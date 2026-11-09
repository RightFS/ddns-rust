//! DNS.LA current official API: https://www.dns.la/docs/ApiDoc.
//! JS-only CRUD tabs are embedded markdown in the official Nuxt bundle
//! https://www.dns.la/_nuxt/B_J6rdMU.js (inspected 2026-11-09). Unlike legacy
//! ddns-go, current schemas use domainId and lower-case JSON field names.
//! GET /api/domain proves exact-zone access; recordList retrieves ALL records
//! with domainId, omitting optional filters, and exhausts total-based pagination.
//! Routing line codes are supported; the API's empty default line is normalized
//! to the configured default alias so common selection never treats it as wildcard.
//! Actual disable/system flags and TTL are required, never synthesized. PUT
//! explicitly preserves lineId/groupId/weight; disable is not a PUT parameter,
//! and disabled records are never updated. URL/MX-only fields do not apply to
//! this A/AAAA adapter. PUT's documented acknowledgement is code=200,data=null.
//! The parent must construct the shared client with redirects disabled.
#![allow(clippy::result_large_err)]
use super::common::{self, Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

const ENDPOINT: &str = "https://api.dns.la";
const PAGE_SIZE: usize = 100;
const RECORD_LIMIT: usize = 10000;

// Deliberately not Debug: APIID, APISecret and the encoded token are secrets.
pub struct Dnsla {
    api: Api,
    id: String,
    key: String,
    options_valid: bool,
    #[cfg(test)]
    endpoint: String,
}
impl Dnsla {
    pub fn new(
        client: reqwest::Client,
        id: String,
        key: String,
        options: &BTreeMap<String, String>,
    ) -> Self {
        let token = STANDARD.encode(format!("{id}:{key}"));
        Self {
            api: Api::new(client, vec![id.clone(), key.clone(), token]),
            id,
            key,
            options_valid: options.is_empty(),
            #[cfg(test)]
            endpoint: ENDPOINT.into(),
        }
    }
    fn error(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage, code, message,
            "Check the exact DNS.LA zone, account permissions and documented response fields. Inspect an uncertain write before retrying; writes are never automatically retried.", reply)
    }
    fn schema(&self, stage: &str, field: &str, expected: &str, reply: &HttpReply) -> ProviderError {
        self.error(stage, "MalformedResponse", &format!("DNS.LA response field {field} is missing or invalid; expected {expected}. Safe selection/mutation stopped; no default value was substituted."), Some(reply))
    }
    fn validate_spec(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.id.is_empty()
            || self.id.contains(':')
            || self.key.is_empty()
            || self.id.chars().any(char::is_control)
            || self.key.chars().any(char::is_control)
        {
            return Err(self.error("validation", "InvalidCredentials", "DNS.LA requires a nonempty APIID (without colon) and APISecret, without control characters.", None));
        }
        if !self.options_valid || !spec.options.is_empty() {
            return Err(self.error(
                "validation",
                "UnsupportedOptions",
                "DNS.LA has no adapter-specific options or production endpoint override.",
                None,
            ));
        }
        if !hostname(&spec.domain)
            || !spec.domain.contains('.')
            || (spec.subdomain != "@" && !hostname(&spec.subdomain))
        {
            return Err(self.error(
                "validation",
                "InvalidZoneName",
                "Use the exact ASCII/punycode zone and a plain relative host (or @).",
                None,
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "DNS.LA DDNS supports only A and AAAA.",
                None,
            ));
        }
        if !(1..=u32::MAX as u64).contains(&spec.ttl) {
            return Err(self.error("validation", "UnsupportedTTL", "DNS.LA documents TTL 1..4294967295; account minimums are also enforced by the API.", None));
        }
        if spec.record_line.trim().is_empty()
            || spec.record_line.len() > 128
            || spec.record_line.chars().any(char::is_control)
        {
            return Err(self.error(
                "validation",
                "InvalidRecordLine",
                "Use default/默认 for the default line, or the exact DNS.LA lineCode.",
                None,
            ));
        }
        Ok(())
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        #[cfg(test)]
        let endpoint = &self.endpoint;
        #[cfg(not(test))]
        let endpoint = ENDPOINT;
        self.api
            .client
            .request(method, format!("{endpoint}{path}"))
            .basic_auth(&self.id, Some(&self.key))
    }
    async fn call(
        &self,
        stage: &str,
        request: reqwest::RequestBuilder,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let reply = self.api.send(stage, request, write).await?;
        // Preserve actual business codes even on HTTP 200 (or HTTP failure).
        if let Some(code) = reply.body.get("code").and_then(Value::as_i64)
            && code != 200
        {
            let msg = reply
                .body
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("DNS.LA returned a business error without a string msg.");
            return Err(self.error(stage, &code.to_string(), msg, Some(&reply)));
        }
        self.api.check_http(stage, &reply)?;
        if reply.body.get("code").and_then(Value::as_i64) != Some(200) {
            return Err(self.schema(stage, "code", "integer business success code 200", &reply));
        }
        if reply.body.get("msg").and_then(Value::as_str).is_none()
            || reply.body.get("data").is_none()
        {
            return Err(self.schema(
                stage,
                "msg/data",
                "a string msg and explicit data member",
                &reply,
            ));
        }
        Ok(reply)
    }
    async fn zone(&self, spec: &Spec) -> Result<String, ProviderError> {
        let reply = self
            .call(
                "ownership",
                self.request(reqwest::Method::GET, "/api/domain")
                    .query(&[("domain", &spec.domain)]),
                false,
            )
            .await?;
        let data = &reply.body["data"];
        let id = identifier(data.get("id")).ok_or_else(|| {
            self.schema(
                "ownership",
                "data.id",
                "nonzero string zone identifier",
                &reply,
            )
        })?;
        let domain = data.get("domain").and_then(Value::as_str).ok_or_else(|| {
            self.schema(
                "ownership",
                "data.domain",
                "exact punycode zone name",
                &reply,
            )
        })?;
        if !domain
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&spec.domain)
        {
            return Err(self.error(
                "ownership",
                "ZoneMismatch",
                "DNS.LA returned a different zone than the exact configured domain.",
                Some(&reply),
            ));
        }
        if data.get("state").and_then(Value::as_u64) != Some(1) {
            return Err(self.error("ownership", "ZoneNotActive", "DNS.LA zone state is not documented normal state 1; paused/unknown zones are refused.", Some(&reply)));
        }
        for field in ["quoteDomainId", "quoteDomain"] {
            let value = data.get(field).and_then(Value::as_str).ok_or_else(|| {
                self.schema(
                    "ownership",
                    &format!("data.{field}"),
                    "string (empty for a non-referenced zone)",
                    &reply,
                )
            })?;
            if !value.is_empty() {
                return Err(self.error("ownership", "ReferencedZone", "DNS.LA zone uses another zone's records (quoteDomain); its own record writes would not take effect.", Some(&reply)));
            }
        }
        Ok(id)
    }
    fn record(
        &self,
        spec: &Spec,
        raw: &Value,
        zone_id: &str,
        index: usize,
        reply: &HttpReply,
    ) -> Result<Record, ProviderError> {
        let field_error = |field: &str, expected: &str| {
            self.schema(
                "list",
                &format!("data.results[{index}].{field}"),
                expected,
                reply,
            )
        };
        let id = identifier(raw.get("id"))
            .ok_or_else(|| field_error("id", "nonzero string identifier"))?;
        if raw.get("domainId").and_then(Value::as_str) != Some(zone_id) {
            return Err(self.error("list", "RecordZoneMismatch", "DNS.LA returned a record with missing/different domainId; exact-zone selection stopped.", Some(reply)));
        }
        let name = raw
            .get("host")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| field_error("host", "nonempty punycode relative host"))?
            .to_owned();
        let numeric_type = raw
            .get("type")
            .and_then(Value::as_u64)
            .filter(|t| *t > 0)
            .ok_or_else(|| field_error("type", "positive integer DNS type"))?;
        let record_type = match numeric_type {
            1 => "A".into(),
            28 => "AAAA".into(),
            n => format!("TYPE{n}"),
        };
        let value = raw
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| field_error("data", "string record data"))?
            .to_owned();
        let ttl = raw
            .get("ttl")
            .and_then(Value::as_u64)
            .filter(|n| (1..=u32::MAX as u64).contains(n))
            .ok_or_else(|| field_error("ttl", "actual integer TTL 1..4294967295"))?;
        let disable = raw
            .get("disable")
            .and_then(Value::as_bool)
            .ok_or_else(|| field_error("disable", "documented boolean pause state"))?;
        let line_id = raw
            .get("lineId")
            .and_then(Value::as_str)
            .ok_or_else(|| field_error("lineId", "string line identifier (empty for default)"))?;
        let line_code = raw
            .get("lineCode")
            .and_then(Value::as_str)
            .ok_or_else(|| field_error("lineCode", "string line code (empty for default)"))?;
        if line_id.is_empty() != line_code.is_empty()
            || (!line_id.is_empty() && !common::valid_id(line_id))
        {
            return Err(field_error(
                "lineId/lineCode",
                "consistent default or valid non-default routing metadata",
            ));
        }
        let line = if line_code.is_empty() {
            if spec.record_line == "default" {
                "default"
            } else {
                "默认"
            }
        } else {
            line_code
        };
        Ok(Record {
            id,
            name,
            record_type,
            value,
            ttl,
            line: line.into(),
            enabled: !disable,
            extra: raw.clone(),
        })
    }
    fn validate_record(&self, spec: &Spec, record: Option<&Record>) -> Result<(), ProviderError> {
        self.validate_spec(spec)?;
        let Some(record) = record else {
            if !matches!(spec.record_line.as_str(), "default" | "默认") {
                return Err(self.error("selection", "UnsupportedCreateLine", "Creating a routed line requires lineId resolution; this adapter only creates default-line records. Select an existing routed record by exact lineCode or explicit ID.", None));
            }
            return Ok(());
        };
        if spec.record_id.is_none()
            && !(record.line == spec.record_line
                || (record.line.is_empty()
                    && matches!(spec.record_line.as_str(), "default" | "默认")))
        {
            return Err(self.error("selection", "RecordLineMismatch", "Selected DNS.LA record lineCode does not match the configured routing line; no line changes are performed.", None));
        }
        let raw = &record.extra;
        if ["status", "enabled"]
            .iter()
            .any(|field| raw.get(*field).is_some())
        {
            return Err(self.error("selection", "UnknownRecordState", "DNS.LA returned an undocumented status/enabled field; only documented boolean disable is understood. Inspect the schema before mutation.", None));
        }
        if raw.get("system").and_then(Value::as_bool) != Some(false) {
            return Err(self.error("selection", "SystemRecord", "DNS.LA selected record has missing/true system state; system records are not editable DDNS targets.", None));
        }
        let group = raw.get("groupId").and_then(Value::as_str);
        let line = raw.get("lineId").and_then(Value::as_str);
        let weight = raw.get("weight").and_then(Value::as_u64);
        if group.is_none_or(|s| !s.is_empty() && !common::valid_id(s))
            || line.is_none_or(|s| !s.is_empty() && !common::valid_id(s))
            || weight.is_none_or(|n| !(1..=10).contains(&n))
        {
            return Err(self.error("selection", "UnsafeRecordMetadata", "Selected DNS.LA record requires actual string groupId/lineId and integer weight 1..10 to preserve routing, grouping and load balancing; missing/invalid fields are not defaulted.", None));
        }
        Ok(())
    }
}
impl Adapter for Dnsla {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Relative
    }
    fn validate_selection(
        &self,
        spec: &Spec,
        record: Option<&Record>,
    ) -> Result<(), ProviderError> {
        self.validate_record(spec, record)
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        self.validate_spec(spec)?;
        let zone_id = self.zone(spec).await?;
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        let mut request_id = None;
        for page in 1..=RECORD_LIMIT / PAGE_SIZE {
            // Omit host/type/line/disable/system filters: explicit mismatched IDs
            // must be visible, and disabled records count toward ambiguity.
            let reply = self
                .call(
                    "list",
                    self.request(reqwest::Method::GET, "/api/recordList")
                        .query(&[
                            ("domainId", zone_id.clone()),
                            ("pageIndex", page.to_string()),
                            ("pageSize", PAGE_SIZE.to_string()),
                        ]),
                    false,
                )
                .await?;
            let page_total = reply
                .body
                .pointer("/data/total")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    self.schema("list", "data.total", "nonnegative integer total", &reply)
                })?;
            let results = reply
                .body
                .pointer("/data/results")
                .and_then(Value::as_array)
                .ok_or_else(|| self.schema("list", "data.results", "array of records", &reply))?;
            if page_total > RECORD_LIMIT as u64 {
                return Err(self.error(
                    "list",
                    "RecordLimit",
                    "DNS.LA returned more than 10,000 zone records; exhaustive selection stopped.",
                    Some(&reply),
                ));
            }
            if total.is_some_and(|previous| previous != page_total)
                || results.len() > PAGE_SIZE
                || records.len() + results.len() > page_total as usize
                || results.len()
                    != PAGE_SIZE.min((page_total as usize).saturating_sub(records.len()))
            {
                return Err(self.error("list", "UnstableRecordList", "DNS.LA pagination total changed or page size/count is inconsistent; incomplete selection is refused.", Some(&reply)));
            }
            total = Some(page_total);
            for (index, raw) in results.iter().enumerate() {
                let record = self.record(spec, raw, &zone_id, index, &reply)?;
                if !ids.insert(record.id.clone()) {
                    return Err(self.error("list", "UnstableRecordList", "DNS.LA repeated a record ID within/across pages; exhaustive selection cannot be proven.", Some(&reply)));
                }
                records.push(record);
            }
            if reply.request_id.is_some() {
                request_id = reply.request_id.clone();
            }
            if records.len() == page_total as usize {
                return Ok(List {
                    records,
                    request_id,
                });
            }
        }
        Err(self.error(
            "list",
            "IncompleteRecordList",
            "DNS.LA pagination did not finish within the safety limit; no mutation was attempted.",
            None,
        ))
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate_record(spec, None)?;
        let zone_id = self.zone(spec).await?;
        let body = json!({"domainId":zone_id,"host":spec.subdomain,"type":dns_type(spec),"data":ip,"ttl":spec.ttl,"groupId":"","lineId":"","weight":1});
        let reply = self
            .call(
                "create",
                self.request(reqwest::Method::POST, "/api/record")
                    .json(&body),
                true,
            )
            .await?;
        let record_id = identifier(reply.body.pointer("/data/id")).ok_or_else(|| self.error("create", "InvalidWriteAcknowledgement", "DNS.LA did not return the documented data.id for the created record; inspect the uncertain write.", Some(&reply)))?;
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
        self.validate_record(spec, Some(record))?;
        if !record.enabled
            || identifier(Some(&json!(record.id))).is_none()
            || !record.name.eq_ignore_ascii_case(&spec.subdomain)
            || record.record_type != spec.record_type
        {
            return Err(self.error("update", "InvalidSelectedRecord", "DNS.LA update requires the actual enabled ID and matching host/type; unrelated records are never repurposed.", None));
        }
        let body = json!({"id":record.id,"host":record.name,"type":dns_type(spec),"data":ip,"ttl":spec.ttl,
            "groupId":record.extra["groupId"],"lineId":record.extra["lineId"],"weight":record.extra["weight"]});
        let reply = self
            .call(
                "update",
                self.request(reqwest::Method::PUT, "/api/record")
                    .json(&body),
                true,
            )
            .await?;
        // The current official PUT returns explicit null, not a record ID.
        // Accept an older ID acknowledgement only when it equals this exact ID.
        match &reply.body["data"] {
            Value::Null => {},
            data if identifier(data.get("id")).as_deref() == Some(record.id.as_str()) => {},
            _ => return Err(self.error("update", "InvalidWriteAcknowledgement", "DNS.LA update data is neither the documented null nor an acknowledgement of the selected ID; inspect the uncertain write.", Some(&reply))),
        }
        Ok(Mutation {
            record_id: record.id.clone(),
            request_id: reply.request_id,
        })
    }
}
fn dns_type(spec: &Spec) -> u64 {
    if spec.record_type == "AAAA" { 28 } else { 1 }
}
fn identifier(value: Option<&Value>) -> Option<String> {
    value?
        .as_str()
        .filter(|s| common::valid_id(s))
        .map(str::to_owned)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, Method, StatusCode, Uri},
        routing::any,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    #[derive(Clone, Debug)]
    struct Capture {
        method: Method,
        uri: String,
        headers: HeaderMap,
        body: Value,
    }
    type Captures = Arc<Mutex<Vec<Capture>>>;
    #[derive(Clone)]
    struct MockState {
        replies: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
        captures: Captures,
    }
    struct Mock {
        provider: Dnsla,
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
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, String) {
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        state.captures.lock().unwrap().push(Capture {
            method,
            uri: uri.to_string(),
            headers,
            body,
        });
        state.replies.lock().unwrap().pop_front().unwrap_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"code":500,"msg":"Unexpected request","data":null}).to_string(),
        ))
    }
    async fn mock_raw(replies: Vec<(StatusCode, String)>) -> Mock {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            replies: Arc::new(Mutex::new(replies.into())),
            captures: captures.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/{*path}", any(handler))
            .with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let mut provider = Dnsla::new(
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
        json!({"code":200,"msg":"","data":{"id":"85371689655342080","domain":"Example.COM.","state":1,"nsState":1,"quoteDomain":"","quoteDomainId":""}})
    }
    fn raw_record(id: &str, host: &str) -> Value {
        json!({"id":id,"domainId":"85371689655342080","host":host,"type":1,"data":"1.1.1.1","ttl":600,
            "lineId":"","lineCode":"","lineName":"","groupId":"","weight":1,"preference":1,"domaint":false,"system":false,"disable":false})
    }
    fn page(total: usize, records: Vec<Value>) -> Value {
        json!({"code":200,"msg":"","data":{"total":total,"results":records},"requestId":"read-42"})
    }
    fn null_ack() -> Value {
        json!({"code":200,"msg":"","data":null,"requestId":"write-42"})
    }
    fn assert_auth(calls: &[Capture]) {
        let token = STANDARD.encode("test-api-secret:test-key-secret");
        for call in calls {
            assert_eq!(
                call.headers["authorization"].to_str().unwrap(),
                format!("Basic {token}")
            );
            assert!(!call.uri.contains("secret"));
            assert!(!call.uri.contains(&token));
            assert!(!call.body.to_string().contains("test-api-secret"));
            assert!(!call.body.to_string().contains("test-key-secret"));
        }
    }
    #[tokio::test]
    async fn official_all_zone_list_and_actual_ttl_and_auth() {
        let mut r = raw_record("85394988049110016", "home");
        r["ttl"] = json!(300);
        let mut ns = raw_record("85394988049110017", "@");
        ns["type"] = json!(2);
        ns["system"] = json!(true);
        let m = mock(vec![owned(), page(2, vec![r, ns])]).await;
        let result = m.provider.list(&spec()).await.unwrap();
        assert_eq!(result.records[0].ttl, 300);
        assert_eq!(result.records[0].id, "85394988049110016");
        assert_eq!(result.records[1].record_type, "TYPE2");
        assert_eq!(result.request_id.as_deref(), Some("read-42"));
        let calls = m.captures.lock().unwrap();
        assert_auth(&calls);
        assert_eq!(calls[0].method, Method::GET);
        assert_eq!(calls[0].uri, "/api/domain?domain=example.com");
        assert_eq!(
            calls[1].uri,
            "/api/recordList?domainId=85371689655342080&pageIndex=1&pageSize=100"
        );
    }
    #[tokio::test]
    async fn pagination_exhausts_more_than_old_999_records() {
        let mut replies = vec![owned()];
        for page_index in 0usize..11 {
            let begin = page_index * 100;
            let end = (begin + 100).min(1001);
            replies.push(page(
                1001,
                (begin..end)
                    .map(|i| raw_record(&format!("id-{i}"), "home"))
                    .collect(),
            ));
        }
        let m = mock(replies).await;
        assert_eq!(m.provider.list(&spec()).await.unwrap().records.len(), 1001);
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls.len(), 12);
        assert!(calls[11].uri.contains("pageIndex=11&pageSize=100"));
        assert_auth(&calls);
    }
    #[tokio::test]
    async fn pagination_rejects_repeat_ids() {
        let first = (0..100)
            .map(|i| raw_record(&format!("id-{i}"), "home"))
            .collect();
        let m = mock(vec![
            owned(),
            page(101, first),
            page(101, vec![raw_record("id-0", "home")]),
        ])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "UnstableRecordList"
        );
    }
    #[tokio::test]
    async fn pagination_rejects_changed_totals_short_pages_and_oversized_totals() {
        let first: Vec<_> = (0..100)
            .map(|i| raw_record(&format!("id-{i}"), "home"))
            .collect();
        let m = mock(vec![
            owned(),
            page(101, first),
            page(
                102,
                vec![raw_record("id-100", "home"), raw_record("id-101", "home")],
            ),
        ])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "UnstableRecordList"
        );
        for (total, records, code) in [
            (2, vec![raw_record("id-1", "home")], "UnstableRecordList"),
            (1, vec![], "UnstableRecordList"),
            (0, vec![raw_record("id-1", "home")], "UnstableRecordList"),
            (10001, vec![], "RecordLimit"),
        ] {
            let m = mock(vec![owned(), page(total, records)]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
        }
    }
    #[tokio::test]
    async fn business_error_preserves_code_http_id_and_redacts_encoded_token() {
        let token = STANDARD.encode("test-api-secret:test-key-secret");
        let m = mock(vec![json!({"code":603,"msg":format!("Denied test-api-secret test-key-secret {token}; zone access not granted"),"data":null,"requestId":"err-42"})]).await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "603");
        assert_eq!(e.http_status, Some(200));
        assert_eq!(e.request_id.as_deref(), Some("err-42"));
        assert!(!e.message.contains("test-api-secret"));
        assert!(!e.message.contains("test-key-secret"));
        assert!(!e.message.contains(&token));
        assert!(e.message.contains("zone access not granted"));
        assert!(!e.retryable);
    }
    #[tokio::test]
    async fn http_401_and_malformed_json_are_not_success() {
        let m = mock_raw(vec![(
            StatusCode::UNAUTHORIZED,
            json!({"msg":"denied","data":null}).to_string(),
        )])
        .await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "Http401");
        assert_eq!(e.http_status, Some(401));
        let m = mock_raw(vec![(StatusCode::OK, "test-api-secret malformed".into())]).await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "MalformedResponse");
        assert!(!e.message.contains("test-api-secret"));
    }
    #[tokio::test]
    async fn exact_zone_echo_paused_and_referenced_zones_fail_before_listing() {
        for (field, value, code) in [
            ("domain", json!("child.example.com."), "ZoneMismatch"),
            ("state", json!(2), "ZoneNotActive"),
            ("quoteDomain", json!("other.com."), "ReferencedZone"),
            ("quoteDomainId", json!("other-id"), "ReferencedZone"),
        ] {
            let mut zone = owned();
            zone["data"][field] = value;
            let m = mock(vec![zone]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            assert_eq!(m.captures.lock().unwrap().len(), 1);
        }
    }
    #[tokio::test]
    async fn missing_ttl_disable_or_line_schema_has_field_specific_errors() {
        for field in [
            "ttl", "disable", "lineId", "lineCode", "type", "host", "data", "id",
        ] {
            let mut r = raw_record("record-1", "home");
            r.as_object_mut().unwrap().remove(field);
            let m = mock(vec![owned(), page(1, vec![r])]).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "MalformedResponse");
            assert!(e.message.contains(field));
            assert!(e.message.contains("no default"));
        }
        let mut r = raw_record("record-1", "home");
        r["ttl"] = json!("600");
        let m = mock(vec![owned(), page(1, vec![r])]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "MalformedResponse"
        );
    }
    #[tokio::test]
    async fn record_zone_id_mismatch_is_refused() {
        let mut r = raw_record("record-1", "home");
        r["domainId"] = json!("wrong-zone");
        let m = mock(vec![owned(), page(1, vec![r])]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "RecordZoneMismatch"
        );
    }
    #[tokio::test]
    async fn create_current_official_payload_and_string_ack() {
        let m = mock(vec![
            owned(),
            page(0, vec![]),
            owned(),
            json!({"code":200,"msg":"","data":{"id":"85369994254488576"},"requestId":"write-42"}),
        ])
        .await;
        let mut s = spec();
        s.create_if_missing = true;
        let outcome = common::reconcile(&m.provider, &s, "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(outcome.status, "created");
        assert_eq!(outcome.record_id.as_deref(), Some("85369994254488576"));
        let calls = m.captures.lock().unwrap();
        assert_auth(&calls);
        assert_eq!(calls[3].method, Method::POST);
        assert_eq!(calls[3].uri, "/api/record");
        assert_eq!(
            calls[3].body,
            json!({"domainId":"85371689655342080","host":"home","type":1,"data":"8.8.8.8","ttl":600,"groupId":"","lineId":"","weight":1})
        );
    }
    #[tokio::test]
    async fn apex_aaaa_creation_uses_at_and_type_28() {
        let m = mock(vec![
            owned(),
            json!({"code":200,"msg":"","data":{"id":"new-id"}}),
        ])
        .await;
        let mut s = spec();
        s.subdomain = "@".into();
        s.record_type = "AAAA".into();
        m.provider.create(&s, "2001:db8::1").await.unwrap();
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls[1].body["host"], "@");
        assert_eq!(calls[1].body["type"], 28);
    }
    #[tokio::test]
    async fn update_preserves_actual_line_group_weight_and_host_and_null_ack() {
        let mut r = raw_record("record-1", "Home");
        r["lineId"] = json!("84613316902921216");
        r["lineCode"] = json!("tele");
        r["lineName"] = json!("电信");
        r["groupId"] = json!("group-123");
        r["weight"] = json!(7);
        let m = mock(vec![owned(), page(1, vec![r]), null_ack()]).await;
        let mut s = spec();
        s.record_id = Some("record-1".into()); // ID overrides line selection, not metadata.
        let outcome = common::reconcile(&m.provider, &s, "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(outcome.status, "updated");
        assert_eq!(outcome.record_id.as_deref(), Some("record-1"));
        assert_eq!(outcome.request_id.as_deref(), Some("write-42"));
        let calls = m.captures.lock().unwrap();
        assert_auth(&calls);
        assert_eq!(calls[2].method, Method::PUT);
        assert_eq!(
            calls[2].body,
            json!({"id":"record-1","host":"Home","type":1,"data":"8.8.8.8","ttl":600,"groupId":"group-123","lineId":"84613316902921216","weight":7})
        );
        for field in [
            "disable",
            "system",
            "domainId",
            "preference",
            "dominant",
            "domaint",
        ] {
            assert!(calls[2].body.get(field).is_none());
        }
    }
    #[tokio::test]
    async fn exact_line_code_selects_routed_record_without_repurposing_default() {
        let mut routed = raw_record("routed-1", "home");
        routed["lineId"] = json!("line-1");
        routed["lineCode"] = json!("tele");
        let m = mock(vec![
            owned(),
            page(2, vec![raw_record("default-1", "home"), routed.clone()]),
            null_ack(),
        ])
        .await;
        let mut s = spec();
        s.record_line = "tele".into();
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap()
                .record_id
                .as_deref(),
            Some("routed-1")
        );
        for alias in ["默认", "default"] {
            let m = mock(vec![
                owned(),
                page(2, vec![raw_record("default-1", "home"), routed.clone()]),
                null_ack(),
            ])
            .await;
            let mut default_spec = spec();
            default_spec.record_line = alias.into();
            assert_eq!(
                common::reconcile(&m.provider, &default_spec, "8.8.8.8", false)
                    .await
                    .unwrap()
                    .record_id
                    .as_deref(),
                Some("default-1")
            );
        }
        let m = mock(vec![
            owned(),
            page(1, vec![raw_record("default-1", "home")]),
        ])
        .await;
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", true)
                .await
                .unwrap_err()
                .code,
            "UnsupportedCreateLine"
        );
    }
    #[tokio::test]
    async fn common_dry_run_noop_and_ttl_only_change_never_write() {
        for existing in [true, false] {
            let records = if existing {
                vec![raw_record("record-1", "home")]
            } else {
                vec![]
            };
            let m = mock(vec![owned(), page(records.len(), records)]).await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap()
                    .status,
                if existing {
                    "would_update"
                } else {
                    "would_create"
                }
            );
            assert_eq!(m.captures.lock().unwrap().len(), 2);
        }
        let m = mock(vec![owned(), page(1, vec![raw_record("record-1", "home")])]).await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "1.1.1.1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert_eq!(m.captures.lock().unwrap().len(), 2);
        let m = mock(vec![owned(), page(1, vec![raw_record("record-1", "home")])]).await;
        let mut s = spec();
        s.ttl = 300;
        assert_eq!(
            common::reconcile(&m.provider, &s, "1.1.1.1", true)
                .await
                .unwrap()
                .status,
            "would_update"
        );
    }
    #[tokio::test]
    async fn disabled_ambiguous_and_missing_explicit_id_never_write() {
        let mut disabled = raw_record("record-1", "home");
        disabled["disable"] = json!(true);
        for (records, code) in [
            (vec![disabled], "RecordDisabled"),
            (
                vec![
                    raw_record("record-1", "home"),
                    raw_record("record-2", "home"),
                ],
                "AmbiguousRecords",
            ),
        ] {
            let m = mock(vec![owned(), page(records.len(), records)]).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(m.captures.lock().unwrap().len(), 2);
        }
        let m = mock(vec![owned(), page(1, vec![raw_record("record-1", "home")])]).await;
        let mut s = spec();
        s.record_id = Some("missing".into());
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordIdNotFound"
        );
    }
    #[tokio::test]
    async fn explicit_id_host_and_type_mismatch_are_visible_in_all_zone_list() {
        for (field, value) in [("host", json!("other")), ("type", json!(28))] {
            let mut r = raw_record("record-1", "home");
            r[field] = value;
            let m = mock(vec![owned(), page(1, vec![r])]).await;
            let mut s = spec();
            s.record_id = Some("record-1".into());
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "RecordIdMismatch"
            );
            assert_eq!(m.captures.lock().unwrap().len(), 2);
        }
    }
    #[tokio::test]
    async fn unsupported_metadata_rejected_even_in_dry_run() {
        for (field, value, code) in [
            ("weight", Value::Null, "UnsafeRecordMetadata"),
            ("groupId", Value::Null, "UnsafeRecordMetadata"),
            ("system", json!(true), "SystemRecord"),
            ("status", json!("disabled"), "UnknownRecordState"),
        ] {
            let mut r = raw_record("record-1", "home");
            r[field] = value;
            let m = mock(vec![owned(), page(1, vec![r])]).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(m.captures.lock().unwrap().len(), 2);
        }
        let m = mock(vec![owned(), page(0, vec![])]).await;
        let mut s = spec();
        s.record_line = "tele".into();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", true)
                .await
                .unwrap_err()
                .code,
            "UnsupportedCreateLine"
        );
    }
    #[tokio::test]
    async fn create_ack_requires_official_nonzero_string_id() {
        for data in [
            Value::Null,
            json!({}),
            json!({"id":0}),
            json!({"id":"0"}),
            json!({"id":""}),
            json!({"recordId":"record-1"}),
        ] {
            let m = mock(vec![owned(), json!({"code":200,"msg":"","data":data})]).await;
            let e = m.provider.create(&spec(), "8.8.8.8").await.unwrap_err();
            assert_eq!(e.code, "InvalidWriteAcknowledgement");
            assert!(!e.retryable);
        }
    }
    #[tokio::test]
    async fn update_requires_explicit_business_ack_and_rejects_contradictions() {
        for (ack, code) in [
            (
                json!({"code":200,"msg":"","data":{"id":"wrong-id"}}),
                "InvalidWriteAcknowledgement",
            ),
            (
                json!({"code":200,"msg":"","data":{}}),
                "InvalidWriteAcknowledgement",
            ),
            (json!({"code":200,"msg":""}), "MalformedResponse"),
            (
                json!({"code":601,"msg":"record disappeared","data":null}),
                "601",
            ),
        ] {
            let m = mock(vec![
                owned(),
                page(1, vec![raw_record("record-1", "home")]),
                ack,
            ])
            .await;
            let e = common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, code);
            assert!(!e.retryable);
        }
        let m = mock_raw(vec![
            (StatusCode::OK, owned().to_string()),
            (
                StatusCode::OK,
                page(1, vec![raw_record("record-1", "home")]).to_string(),
            ),
            (StatusCode::NO_CONTENT, String::new()),
        ])
        .await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "MalformedResponse"
        );
    }
    #[tokio::test]
    async fn malformed_total_and_missing_envelope_fail_closed() {
        for reply in [
            json!({"code":200,"msg":"","data":{"results":[]}}),
            json!({"code":200,"msg":"","data":{"total":-1,"results":[]}}),
            json!({"code":200,"msg":"","data":{"total":"0","results":[]}}),
        ] {
            let m = mock(vec![owned(), reply]).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "MalformedResponse"
            );
        }
        let m = mock(vec![json!({"msg":"ok","data":null})]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "MalformedResponse"
        );
    }
    #[tokio::test]
    async fn production_endpoint_and_invalid_options_cannot_be_overridden() {
        assert_eq!(ENDPOINT, "https://api.dns.la");
        let m = mock(vec![]).await;
        let mut s = spec();
        s.options
            .insert("endpoint".into(), "http://attacker".into());
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        assert!(m.captures.lock().unwrap().is_empty());
        let mut options = BTreeMap::new();
        options.insert("endpoint".into(), "http://attacker".into());
        let p = Dnsla::new(reqwest::Client::new(), "id".into(), "key".into(), &options);
        assert_eq!(
            p.validate_selection(&spec(), None).unwrap_err().code,
            "UnsupportedOptions"
        );
    }
}
