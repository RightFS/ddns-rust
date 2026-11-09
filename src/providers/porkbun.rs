//! Porkbun v3: https://porkbun.com/llms/dns and https://porkbun.com/llms/domain.
//! Checked against ddns-go/dns/porkbun.go, but never uses its RRset-wide edit.
//! Parent must disable redirects. No production endpoint override.
//! Account domain pagination proves ownership before exact-domain DNS retrieval.
//! Retrieve returns all editable records, excluding SOA/default NS, and does not
//! echo the zone name or document pagination. No disable/routing-line controls.
//! Account TTL minimum is not exposed (typically 600); lower TTLs are refused.
#![allow(clippy::result_large_err)]
use super::common::{self, Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
const ENDPOINT: &str = "https://api.porkbun.com/api/json/v3";
const DOMAIN_PAGE_SIZE: usize = 1000;
const MAX_DOMAIN_PAGES: usize = 10;
// Not Debug: both credentials are secrets.
pub struct Porkbun {
    api: Api,
    id: String,
    key: String,
    #[cfg(test)]
    endpoint: String,
}
impl Porkbun {
    pub fn new(
        client: reqwest::Client,
        id: String,
        key: String,
        _options: &BTreeMap<String, String>,
    ) -> Self {
        Self {
            api: Api::new(client, vec![id.clone(), key.clone()]),
            id,
            key,
            #[cfg(test)]
            endpoint: ENDPOINT.into(),
        }
    }
    fn invalid(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage, code, message,
            "Verify the exact Porkbun domain, API access and account TTL limits. Inspect any uncertain write before retrying; no automatic write retry occurs.", reply)
    }
    fn validate_spec(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.id.trim().is_empty() || self.key.trim().is_empty() {
            return Err(self.invalid(
                "validation",
                "MissingCredentials",
                "Porkbun requires both apikey and secretapikey.",
                None,
            ));
        }
        if !hostname(&spec.domain)
            || !spec.domain.contains('.')
            || (spec.subdomain != "@" && !hostname(&spec.subdomain))
        {
            return Err(self.invalid(
                "validation",
                "InvalidZoneName",
                "Use an exact ASCII/punycode account domain and a plain subdomain (or @).",
                None,
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.invalid(
                "validation",
                "UnsupportedRecordType",
                "Porkbun DDNS supports only A and AAAA.",
                None,
            ));
        }
        if !matches!(spec.record_line.as_str(), "默认" | "default") || !spec.options.is_empty() {
            return Err(self.invalid(
                "validation",
                "UnsupportedOptions",
                "Porkbun has no routing-line or record-option controls; use the default line.",
                None,
            ));
        }
        if !(600..=604800).contains(&spec.ttl) {
            return Err(self.invalid("validation", "UnsupportedTTL", "Porkbun TTL must be 600..604800 here; the account minimum is not exposed and may be higher.", None));
        }
        Ok(())
    }
    async fn call(
        &self,
        stage: &str,
        path: &str,
        mut body: Value,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        body["apikey"] = json!(self.id);
        body["secretapikey"] = json!(self.key);
        #[cfg(test)]
        let endpoint = &self.endpoint;
        #[cfg(not(test))]
        let endpoint = ENDPOINT;
        let reply = self
            .api
            .send(
                stage,
                self.api
                    .client
                    .post(format!("{endpoint}{path}"))
                    .json(&body),
                write,
            )
            .await?;
        if reply.body.get("status").and_then(Value::as_str) == Some("ERROR") {
            let code = scalar(reply.body.get("code")).unwrap_or_else(|| "PorkbunApiError".into());
            let mut message = reply
                .body
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Porkbun reported ERROR without a message.")
                .to_owned();
            // Preserve structured source, never serialize the raw body.
            if let Some(source) = reply.body.get("source").and_then(Value::as_str) {
                message.push_str(" Source: ");
                message.push_str(source);
            }
            return Err(self.invalid(stage, &code, &message, Some(&reply)));
        }
        self.api.check_http(stage, &reply)?;
        if reply.body.get("status").and_then(Value::as_str) != Some("SUCCESS") {
            return Err(self.invalid(
                stage,
                "InvalidEnvelope",
                "Porkbun response lacks an explicit status SUCCESS.",
                Some(&reply),
            ));
        }
        if write {
            if reply
                .body
                .get("dryRun")
                .is_some_and(|v| v != &Value::Bool(false))
            {
                return Err(self.invalid(
                    stage,
                    "InvalidWriteAcknowledgement",
                    "Porkbun returned a dry-run preview instead of a write acknowledgement.",
                    Some(&reply),
                ));
            }
            if let Some(warnings) = reply.body.get("warnings") {
                let warnings = warnings.as_array().ok_or_else(|| {
                    self.invalid(
                        stage,
                        "InvalidEnvelope",
                        "Porkbun returned malformed write warnings; inspect the record.",
                        Some(&reply),
                    )
                })?;
                if !warnings.is_empty() {
                    let details = warnings
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("; ");
                    return Err(self.invalid(stage, "WriteWarning", &format!("Porkbun accepted the write with warnings; it may not change authoritative DNS. Inspect before retrying. {details}"), Some(&reply)));
                }
            }
        }
        Ok(reply)
    }
    async fn verify_domain(&self, spec: &Spec) -> Result<(), ProviderError> {
        let mut seen = HashSet::new();
        let mut matched = false;
        for page in 0..MAX_DOMAIN_PAGES {
            let reply = self
                .call(
                    "ownership",
                    "/domain/listAll",
                    json!({"start":page * DOMAIN_PAGE_SIZE}),
                    false,
                )
                .await?;
            let domains = reply
                .body
                .get("domains")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    self.invalid(
                        "ownership",
                        "MalformedDomainList",
                        "Porkbun domain list is missing the domains array.",
                        Some(&reply),
                    )
                })?;
            if domains.len() > DOMAIN_PAGE_SIZE
                || reply
                    .body
                    .get("count")
                    .is_some_and(|v| v.as_u64() != Some(domains.len() as u64))
            {
                return Err(self.invalid(
                    "ownership",
                    "IncompleteDomainList",
                    "Porkbun domain pagination count is inconsistent.",
                    Some(&reply),
                ));
            }
            for domain in domains {
                let name = domain
                    .get("domain")
                    .and_then(Value::as_str)
                    .filter(|s| hostname(s))
                    .ok_or_else(|| {
                        self.invalid(
                            "ownership",
                            "MalformedDomainList",
                            "Porkbun returned an invalid domain name.",
                            Some(&reply),
                        )
                    })?;
                if !seen.insert(name.to_ascii_lowercase()) {
                    return Err(self.invalid(
                        "ownership",
                        "UnstableDomainList",
                        "Repeated domains across Porkbun pages; ownership verification stopped.",
                        Some(&reply),
                    ));
                }
                if name.eq_ignore_ascii_case(&spec.domain) {
                    if domain.get("apiAccess").is_some_and(|v| {
                        v.as_str() != Some("1")
                            && v.as_str() != Some("yes")
                            && v != &Value::Bool(true)
                    }) {
                        return Err(self.invalid(
                            "ownership",
                            "DomainApiDisabled",
                            "The exact domain has API access disabled or unrecognized.",
                            Some(&reply),
                        ));
                    }
                    matched = true;
                }
            }
            if domains.len() < DOMAIN_PAGE_SIZE {
                return if matched {
                    Ok(())
                } else {
                    Err(self.invalid(
                        "ownership",
                        "DomainNotFound",
                        "The exact configured domain is not in the authenticated Porkbun account.",
                        Some(&reply),
                    ))
                };
            }
        }
        Err(self.invalid(
            "ownership",
            "DomainPageLimit",
            "Domain pagination did not finish within 10 pages; ownership verification stopped.",
            None,
        ))
    }
    fn record(&self, spec: &Spec, raw: &Value, reply: &HttpReply) -> Result<Record, ProviderError> {
        let bad = || {
            self.invalid(
                "list",
                "MalformedRecord",
                "Porkbun returned incomplete or invalid record fields; selection stopped.",
                Some(reply),
            )
        };
        let id = decimal_id(raw.get("id")).ok_or_else(bad)?;
        let name = raw
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(bad)?
            .to_owned();
        let bare = name.trim_end_matches('.');
        if !bare.eq_ignore_ascii_case(&spec.domain)
            && !bare
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", spec.domain.to_ascii_lowercase()))
        {
            return Err(self.invalid(
                "list",
                "RecordZoneMismatch",
                "Porkbun returned a record outside the exact configured domain.",
                Some(reply),
            ));
        }
        let record_type = raw
            .get("type")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(bad)?
            .to_owned();
        let value = raw
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(bad)?
            .to_owned();
        let ttl = scalar(raw.get("ttl"))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .ok_or_else(bad)?;
        // No enabled field is documented. If introduced, honor boolean false,
        // and fail closed on unknown encoding instead of silently enabling.
        let enabled = match raw.get("enabled") {
            None => true,
            Some(Value::Bool(v)) => *v,
            Some(_) => return Err(bad()),
        };
        Ok(Record {
            id,
            name,
            record_type,
            value,
            ttl,
            line: String::new(),
            enabled,
            extra: Value::Null,
        })
    }
}
impl Adapter for Porkbun {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Fqdn
    }
    fn validate_selection(
        &self,
        spec: &Spec,
        _record: Option<&Record>,
    ) -> Result<(), ProviderError> {
        self.validate_spec(spec)
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        self.validate_spec(spec)?;
        self.verify_domain(spec).await?;
        let reply = self
            .call(
                "list",
                &format!("/dns/retrieve/{}", spec.domain),
                json!({}),
                false,
            )
            .await?;
        // Official retrieve is complete/unpaginated; unknown pagination fails closed.
        if [
            "pagination",
            "next",
            "nextPage",
            "next_page",
            "cursor",
            "hasMore",
            "has_more",
            "truncated",
            "total",
            "totalCount",
            "total_count",
            "page",
            "pages",
        ]
        .iter()
        .any(|key| reply.body.get(*key).is_some())
        {
            return Err(self.invalid("list", "IncompleteRecordList", "Unexpected Porkbun DNS pagination/truncation metadata; complete selection cannot be proven.", Some(&reply)));
        }
        let raw = reply
            .body
            .get("records")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                self.invalid(
                    "list",
                    "MalformedRecordList",
                    "Porkbun response is missing the records array.",
                    Some(&reply),
                )
            })?;
        if raw.len() > 10000
            || reply
                .body
                .get("count")
                .is_some_and(|v| v.as_u64() != Some(raw.len() as u64))
        {
            return Err(self.invalid(
                "list",
                "IncompleteRecordList",
                "Porkbun DNS list exceeds limits or has an inconsistent count.",
                Some(&reply),
            ));
        }
        let records = raw
            .iter()
            .map(|r| self.record(spec, r, &reply))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(List {
            records,
            request_id: reply.request_id,
        })
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate_spec(spec)?;
        let name = if spec.subdomain == "@" {
            ""
        } else {
            &spec.subdomain
        };
        let reply = self
            .call(
                "create",
                &format!("/dns/create/{}", spec.domain),
                json!({"name":name,"type":spec.record_type,"content":ip,"ttl":spec.ttl}),
                true,
            )
            .await?;
        let record_id = decimal_id(reply.body.get("id")).ok_or_else(|| self.invalid("create", "InvalidWriteAcknowledgement", "Porkbun did not acknowledge the official new record id; inspect the uncertain write.", Some(&reply)))?;
        Ok(Mutation {
            record_id,
            request_id: reply.request_id,
        })
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.validate_spec(spec)?;
        if decimal_id(Some(&json!(record.id))).is_none()
            || !record.enabled
            || !self.name_format().matches(&record.name, spec)
            || record.record_type != spec.record_type
        {
            return Err(self.invalid(
                "update",
                "InvalidSelectedRecord",
                "Porkbun update requires an enabled record with its actual numeric ID.",
                None,
            ));
        }
        // Official edit-by-ID preserves omitted name/type/prio/notes. This is
        // deliberate: never move records, change their type, or edit the RRset.
        let reply = self
            .call(
                "update",
                &format!("/dns/edit/{}/{}", spec.domain, record.id),
                json!({"content":ip,"ttl":spec.ttl}),
                true,
            )
            .await?;
        if let Some(id) = reply.body.get("id")
            && decimal_id(Some(id)).as_deref() != Some(record.id.as_str())
        {
            return Err(self.invalid("update", "UnexpectedRecordId", "Porkbun acknowledged a different or invalid record ID; inspect the uncertain write.", Some(&reply)));
        }
        // Official BasicResponse has status but no ID; explicit SUCCESS is
        // sufficient to acknowledge the requested ID for this endpoint only.
        Ok(Mutation {
            record_id: record.id.clone(),
            request_id: reply.request_id,
        })
    }
}
fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => n.as_u64().map(|n| n.to_string()),
        _ => None,
    }
}
fn decimal_id(value: Option<&Value>) -> Option<String> {
    scalar(value).filter(|s| {
        common::valid_id(s)
            && s.bytes().all(|b| b.is_ascii_digit())
            && s.parse::<u64>().is_ok_and(|n| n > 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::State,
        http::{StatusCode, Uri},
        routing::post,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    type Captures = Arc<Mutex<Vec<(String, Value)>>>;
    #[derive(Clone)]
    struct MockState {
        replies: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
        captures: Captures,
    }
    struct Mock {
        provider: Porkbun,
        captures: Captures,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(
        State(state): State<MockState>,
        uri: Uri,
        axum::Json(body): axum::Json<Value>,
    ) -> (StatusCode, String) {
        state.captures.lock().unwrap().push((uri.to_string(), body));
        state.replies.lock().unwrap().pop_front().unwrap_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"status\":\"ERROR\",\"message\":\"Unexpected request\"}".into(),
        ))
    }
    async fn mock_raw(replies: Vec<(StatusCode, String)>) -> Mock {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            replies: Arc::new(Mutex::new(replies.into())),
            captures: captures.clone(),
        };
        let app = Router::new()
            .route("/{*path}", post(handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut provider = Porkbun::new(
            client,
            "test-api-secret".into(),
            "test-key-secret".into(),
            &BTreeMap::new(),
        );
        provider.endpoint = endpoint;
        Mock {
            provider,
            captures,
            task,
        }
    }
    async fn mock(replies: Vec<Value>) -> Mock {
        mock_raw(
            replies
                .into_iter()
                .map(|v| (StatusCode::OK, v.to_string()))
                .collect(),
        )
        .await
    }
    fn spec() -> Spec {
        Spec {
            domain: "example.com".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "默认".into(),
            ttl: 600,
            record_id: None,
            create_if_missing: false,
            options: BTreeMap::new(),
        }
    }
    fn owned() -> Value {
        json!({"status":"SUCCESS","domains":[{"domain":"example.com","apiAccess":"1"}],"count":1})
    }
    fn raw_record(id: &str, name: &str) -> Value {
        json!({"id":id,"name":name,"type":"A","content":"1.1.1.1","ttl":"600","notes":"keep notes","prio":"0"})
    }
    fn records(raw: Vec<Value>) -> Value {
        json!({"status":"SUCCESS","records":raw,"requestId":"read-42"})
    }
    fn assert_credentials(captures: &[(String, Value)]) {
        for (uri, body) in captures {
            assert!(!uri.contains('?'));
            assert!(!uri.contains("secret"));
            assert_eq!(body["apikey"], "test-api-secret");
            assert_eq!(body["secretapikey"], "test-key-secret");
        }
    }
    #[tokio::test]
    async fn full_list_uses_exact_domain_and_string_ids() {
        let m = mock(vec![
            owned(),
            records(vec![
                raw_record("123", "home.example.com"),
                raw_record("124", "*.example.com"),
            ]),
        ])
        .await;
        let list = m.provider.list(&spec()).await.unwrap();
        assert_eq!(list.records.len(), 2);
        assert_eq!(list.records[0].id, "123");
        assert_eq!(list.records[0].name, "home.example.com");
        assert!(list.records[0].enabled);
        assert_eq!(list.request_id.as_deref(), Some("read-42"));
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls[1].0, "/dns/retrieve/example.com");
        assert_credentials(&calls);
    }
    #[tokio::test]
    async fn create_payload_and_numeric_official_ack() {
        let m = mock(vec![
            owned(),
            records(vec![]),
            json!({"status":"SUCCESS","id":456,"requestId":"write-42"}),
        ])
        .await;
        let mut s = spec();
        s.create_if_missing = true;
        let result = common::reconcile(&m.provider, &s, "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(result.status, "created");
        assert_eq!(result.record_id.as_deref(), Some("456"));
        let calls = m.captures.lock().unwrap();
        assert_credentials(&calls);
        assert_eq!(calls[2].0, "/dns/create/example.com");
        assert_eq!(
            calls[2].1,
            json!({"apikey":"test-api-secret","secretapikey":"test-key-secret","name":"home","type":"A","content":"8.8.8.8","ttl":600})
        );
    }
    #[tokio::test]
    async fn apex_create_uses_blank_name() {
        let m = mock(vec![json!({"status":"SUCCESS","id":"457"})]).await;
        let mut s = spec();
        s.subdomain = "@".into();
        m.provider.create(&s, "8.8.8.8").await.unwrap();
        assert_eq!(m.captures.lock().unwrap()[0].1["name"], "");
    }
    #[tokio::test]
    async fn update_selected_id_only_preserves_omitted_fields() {
        let m = mock(vec![
            owned(),
            records(vec![
                raw_record("123", "Home.Example.COM."),
                raw_record("124", "home.example.com"),
                raw_record("125", "*.example.com"),
            ]),
            json!({"status":"SUCCESS"}),
        ])
        .await;
        let mut s = spec();
        s.record_id = Some("123".into());
        let result = common::reconcile(&m.provider, &s, "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(result.record_id.as_deref(), Some("123"));
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_credentials(&calls);
        assert_eq!(calls[2].0, "/dns/edit/example.com/123");
        assert_eq!(
            calls[2].1,
            json!({"apikey":"test-api-secret","secretapikey":"test-key-secret","content":"8.8.8.8","ttl":600})
        );
        for field in ["name", "type", "prio", "notes"] {
            assert!(calls[2].1.get(field).is_none());
        }
    }
    #[tokio::test]
    async fn error_200_preserves_code_source_id_and_redacts_both_secrets() {
        let m = mock(vec![json!({"status":"ERROR","code":"AUTH_FAILED","message":"Bad test-api-secret and test-key-secret","source":"dns-backend","requestId":"err-42","rawBody":"do not disclose"})]).await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "AUTH_FAILED");
        assert_eq!(e.http_status, Some(200));
        assert_eq!(e.request_id.as_deref(), Some("err-42"));
        assert!(e.message.contains("dns-backend"));
        assert!(!e.message.contains("test-api-secret"));
        assert!(!e.message.contains("test-key-secret"));
        assert!(!e.message.contains("do not disclose"));
    }
    #[tokio::test]
    async fn ownership_requires_exact_domain_not_parent_or_child() {
        let m = mock(vec![json!({"status":"SUCCESS","domains":[{"domain":"child.example.com"},{"domain":"example.net"}]})]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "DomainNotFound"
        );
        assert_eq!(m.captures.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn ownership_disabled_api_stops_before_dns_read() {
        let m = mock(vec![
            json!({"status":"SUCCESS","domains":[{"domain":"example.com","apiAccess":"0"}]}),
        ])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "DomainApiDisabled"
        );
        assert_eq!(m.captures.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn domain_pagination_reads_to_completion() {
        let first: Vec<_> = (0..1000)
            .map(|i| json!({"domain":format!("d{i}.net")}))
            .collect();
        let m = mock(vec![
            json!({"status":"SUCCESS","count":1000,"domains":first}),
            owned(),
            records(vec![]),
        ])
        .await;
        m.provider.list(&spec()).await.unwrap();
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1["start"], 0);
        assert_eq!(calls[1].1["start"], 1000);
    }
    #[tokio::test]
    async fn inconsistent_domain_count_is_rejected() {
        let m = mock(vec![
            json!({"status":"SUCCESS","count":2,"domains":[{"domain":"example.com"}]}),
        ])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "IncompleteDomainList"
        );
    }
    #[tokio::test]
    async fn unexpected_dns_pagination_rejects_partial_list() {
        let m = mock(vec![
            owned(),
            json!({"status":"SUCCESS","records":[],"pagination":{"next":2}}),
        ])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "IncompleteRecordList"
        );
    }
    #[tokio::test]
    async fn malformed_json_uses_common_sanitized_error() {
        let m = mock_raw(vec![(
            StatusCode::OK,
            "{test-api-secret test-key-secret".into(),
        )])
        .await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "MalformedResponse");
        assert!(!e.message.contains("test-api-secret"));
        assert!(!e.message.contains("test-key-secret"));
    }
    #[tokio::test]
    async fn wrong_zone_and_missing_fields_are_rejected() {
        let m = mock(vec![
            owned(),
            records(vec![raw_record("123", "home.other.com")]),
        ])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "RecordZoneMismatch"
        );
        let mut r = raw_record("123", "home.example.com");
        r.as_object_mut().unwrap().remove("ttl");
        let m = mock(vec![owned(), records(vec![r])]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "MalformedRecord"
        );
    }
    #[tokio::test]
    async fn create_requires_official_field_and_valid_id() {
        for ack in [
            json!({"status":"SUCCESS"}),
            json!({"status":"SUCCESS","recordId":123}),
            json!({"status":"SUCCESS","id":0}),
            json!({"status":"SUCCESS","id":1.5}),
        ] {
            let m = mock(vec![ack]).await;
            assert_eq!(
                m.provider
                    .create(&spec(), "8.8.8.8")
                    .await
                    .unwrap_err()
                    .code,
                "InvalidWriteAcknowledgement"
            );
        }
    }
    #[tokio::test]
    async fn edit_requires_success_and_rejects_contradictory_ack() {
        for (ack, code) in [
            (json!({"message":"ok"}), "InvalidEnvelope"),
            (
                json!({"status":"ERROR","code":"NO_RECORD","message":"gone"}),
                "NO_RECORD",
            ),
            (json!({"status":"SUCCESS","id":124}), "UnexpectedRecordId"),
        ] {
            let m = mock(vec![
                owned(),
                records(vec![raw_record("123", "home.example.com")]),
                ack,
            ])
            .await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
        }
    }
    #[tokio::test]
    async fn common_dry_run_never_creates_or_updates() {
        for existing in [true, false] {
            let raw = if existing {
                vec![raw_record("123", "home.example.com")]
            } else {
                vec![]
            };
            let m = mock(vec![owned(), records(raw)]).await;
            let mut s = spec();
            s.create_if_missing = true;
            let result = common::reconcile(&m.provider, &s, "8.8.8.8", true)
                .await
                .unwrap();
            assert_eq!(
                result.status,
                if existing {
                    "would_update"
                } else {
                    "would_create"
                }
            );
            assert_eq!(m.captures.lock().unwrap().len(), 2);
        }
    }
    #[tokio::test]
    async fn common_disabled_and_ambiguous_fail_without_writes() {
        let mut disabled = raw_record("123", "home.example.com");
        disabled["enabled"] = json!(false);
        for (raw, code) in [
            (vec![disabled], "RecordDisabled"),
            (
                vec![
                    raw_record("123", "home.example.com"),
                    raw_record("124", "home.example.com"),
                ],
                "AmbiguousRecords",
            ),
        ] {
            let m = mock(vec![owned(), records(raw)]).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(m.captures.lock().unwrap().len(), 2);
        }
    }
    #[tokio::test]
    async fn authoritative_dns_warning_is_not_false_success() {
        let m = mock(vec![json!({"status":"SUCCESS","id":123,"warnings":["Not delegated to our nameservers test-key-secret"]})]).await;
        let e = m.provider.create(&spec(), "8.8.8.8").await.unwrap_err();
        assert_eq!(e.code, "WriteWarning");
        assert!(!e.message.contains("test-key-secret"));
        assert!(!e.retryable);
    }
    #[tokio::test]
    async fn capability_limits_are_checked_before_any_request() {
        let m = mock(vec![]).await;
        let mut s = spec();
        s.ttl = 300;
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedTTL"
        );
        s.ttl = 600;
        s.record_line = "telecom".into();
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        assert!(m.captures.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn fqdn_short_owner_never_matches_dotted_relative_target() {
        for explicit in [false, true] {
            for (ip, dry) in [("1.1.1.1", false), ("8.8.8.8", true), ("8.8.8.8", false)] {
                let m = mock(vec![
                    owned(),
                    records(vec![raw_record("123", "home.example.com")]),
                ])
                .await;
                let mut s = spec();
                s.subdomain = "home.example.com".into();
                if explicit {
                    s.record_id = Some("123".into());
                    s.create_if_missing = true;
                }
                assert_eq!(
                    common::reconcile(&m.provider, &s, ip, dry)
                        .await
                        .unwrap_err()
                        .code,
                    if explicit {
                        "RecordIdMismatch"
                    } else {
                        "RecordNotFound"
                    }
                );
                let calls = m.captures.lock().unwrap();
                assert_eq!(calls.len(), 2);
                assert!(
                    calls
                        .iter()
                        .all(|r| !r.0.contains("/dns/edit/") && !r.0.contains("/dns/create/"))
                );
            }
        }
    }
    #[tokio::test]
    async fn fqdn_suffix_collision_updates_only_double_qualified_owner() {
        let m = mock(vec![
            owned(),
            records(vec![
                raw_record("123", "home.example.com"),
                raw_record("124", "home.example.com.example.com."),
            ]),
            json!({"status":"SUCCESS"}),
        ])
        .await;
        let mut s = spec();
        s.subdomain = "home.example.com".into();
        let out = common::reconcile(&m.provider, &s, "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(out.record_id.as_deref(), Some("124"));
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].0, "/dns/edit/example.com/124");
        assert!(calls[2].1.get("name").is_none());
    }
}
