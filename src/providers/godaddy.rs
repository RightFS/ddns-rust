//! GoDaddy single-value A/AAAA RRsets; never whole-zone PUT.
//! Contract: https://developer.godaddy.com/openapi/domains-v1.json
//! https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-get
//! https://developer.godaddy.com/en/docs/references/rest/domains/v1/record-replace-type-name
//! Shared client must disable redirects. No documented CAS: exclusive writer required.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use reqwest::{Method, RequestBuilder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::IpAddr};
const ENDPOINT: &str = "https://api.godaddy.com/v1";
const HINT: &str = "Verify the exact account-owned ACTIVE GoDaddy domain and production classic API key/secret. Current eligibility requires at least one domain or a qualifying plan; credentials alone do not grant access. Legacy sso-key is deprecated for Domains. Use a dedicated single-IP A/AAAA RRset and an exclusive writer: no conditional write/CAS is documented, so a race after the final read remains possible. 404 can mean invisible resource, never permission to create. For 429 wait for Retry-After. Inspect uncertain writes before retrying; no automatic API retries occur.";
// Deliberately not Debug: credentials must not be exposed.
pub struct Godaddy {
    api: Api,
    id: String,
    key: String,
    #[cfg(test)]
    endpoint: String,
}
impl Godaddy {
    pub fn new(
        client: reqwest::Client,
        id: String,
        key: String,
        _options: &BTreeMap<String, String>,
    ) -> Self {
        Self {
            api: Api::new(
                client,
                vec![
                    format!("sso-key {id}:{key}"),
                    format!("{id}:{key}"),
                    id.clone(),
                    key.clone(),
                ],
            ),
            id,
            key,
            #[cfg(test)]
            endpoint: ENDPOINT.into(),
        }
    }
    fn endpoint(&self) -> &str {
        #[cfg(test)]
        {
            &self.endpoint
        }
        #[cfg(not(test))]
        {
            ENDPOINT
        }
    }
    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let request = self
            .api
            .client
            .request(method, format!("{}{path}", self.endpoint()))
            .header(reqwest::header::ACCEPT, "application/json");
        match reqwest::header::HeaderValue::from_str(&format!("sso-key {}:{}", self.id, self.key)) {
            Ok(mut value) => {
                value.set_sensitive(true);
                request.header(reqwest::header::AUTHORIZATION, value)
            }
            Err(_) => request.header(reqwest::header::AUTHORIZATION, "\n"),
        }
    }
    fn error(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage, code, message, HINT, reply)
    }
    fn validate_spec(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.id.trim().is_empty() || self.key.trim().is_empty() {
            return Err(self.error(
                "validation",
                "MissingCredentials",
                "GoDaddy requires a nonempty classic API key and secret.",
                None,
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Only A and AAAA are supported.",
                None,
            ));
        }
        if !hostname(&spec.domain)
            || !spec.domain.contains('.')
            || (spec.subdomain != "@" && !hostname(&spec.subdomain))
            || spec.fqdn().len() > 253
        {
            return Err(self.error(
                "validation",
                "InvalidDnsName",
                "Use exact ASCII/punycode zone and relative host or @; URL syntax is forbidden.",
                None,
            ));
        }
        // Current official v1 schema says integer-positive, not a600-second floor.
        if !(1..=604800).contains(&spec.ttl) {
            return Err(self.error(
                "validation",
                "UnsupportedTTL",
                "TTL must be positive and within shared604800-second bound; never clamped.",
                None,
            ));
        }
        if !spec.options.is_empty() {
            return Err(self.error(
                "validation",
                "UnsupportedRecordOptions",
                "GoDaddy has no supported record options.",
                None,
            ));
        }
        Ok(())
    }
    fn validate_ip(&self, spec: &Spec, ip: &str) -> Result<String, ProviderError> {
        self.validate_spec(spec)?;
        let ip = ip.parse::<IpAddr>().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be a plain IP address.",
                None,
            )
        })?;
        if ip.is_ipv4() != (spec.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "Desired IP family does not match RRset type.",
                None,
            ));
        }
        Ok(ip.to_string())
    }
    fn check(&self, stage: &str, reply: &HttpReply) -> Result<(), ProviderError> {
        if !(200..300).contains(&reply.status)
            || reply.body.get("code").is_some()
            || reply.body.get("fields").is_some()
        {
            let fallback = format!("Http{}", reply.status);
            let code = reply.body["code"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or(&fallback);
            return Err(self.error(
                stage,
                code,
                &format!("GoDaddy API error: {}", self.error_details(&reply.body)),
                Some(reply),
            ));
        }
        Ok(())
    }
    fn error_details(&self, body: &Value) -> String {
        let mut out = Vec::new();
        for key in ["code", "message"] {
            if let Some(text) = body[key].as_str() {
                out.push(format!("{key}: {}", self.api.safe(text)));
            }
        }
        if let Some(fields) = body["fields"].as_array() {
            for field in fields.iter().take(16) {
                for key in ["path", "pathRelated", "code", "message"] {
                    if let Some(text) = field[key].as_str() {
                        out.push(format!("field.{key}: {}", self.api.safe(text)));
                    }
                }
            }
        }
        if out.is_empty() {
            "No recognized error details; raw response omitted.".into()
        } else {
            out.join("; ")
        }
    }
    async fn domain(&self, spec: &Spec) -> Result<(), ProviderError> {
        self.validate_spec(spec)?;
        let stage = "GodaddyGetDomain";
        let reply = self
            .api
            .send(
                stage,
                self.request(
                    Method::GET,
                    &format!("/domains/{}", spec.domain.to_ascii_lowercase()),
                ),
                false,
            )
            .await?;
        self.check(stage, &reply)?;
        // v1 is account-scoped with Authorization alone. Never X-Shopper-Id.
        // 203 is partial success and does not verify the zone safely.
        if reply.status != 200
            || !reply.body["domain"]
                .as_str()
                .is_some_and(|d| d.eq_ignore_ascii_case(&spec.domain))
        {
            return Err(self.error(
                stage,
                "DomainMismatch",
                "API did not fully confirm exact account-owned domain; no empty zone fallback.",
                Some(&reply),
            ));
        }
        if reply.body["status"].as_str() != Some("ACTIVE")
            || reply.body["holdRegistrar"] == Value::Bool(true)
        {
            return Err(self.error(
                stage,
                "DomainNotActive",
                "Domain is not confirmed ACTIVE or is on registrar hold.",
                Some(&reply),
            ));
        }
        Ok(())
    }
    fn path(&self, spec: &Spec) -> String {
        format!(
            "/domains/{}/records/{}/{}",
            spec.domain.to_ascii_lowercase(),
            spec.record_type,
            spec.subdomain.to_ascii_lowercase()
        )
    }
    async fn page(&self, spec: &Spec, offset: usize) -> Result<HttpReply, ProviderError> {
        let stage = "GodaddyGetRRset";
        let reply = self
            .api
            .send(
                stage,
                self.request(Method::GET, &self.path(spec))
                    .query(&[("offset", offset), ("limit", 2)]),
                false,
            )
            .await?;
        // Official404 means nonexistent path OR invisible resource. No documented
        // record-only notfound code: never map404 to an empty array.
        self.check(stage, &reply)?;
        if reply.status != 200
            || !reply.body.is_array()
            || reply.headers.contains_key(reqwest::header::LINK)
        {
            return Err(self.error(
                stage,
                "InvalidRRsetList",
                "Expected offset-paginated DNS array; unexpected status, shape or Link header.",
                Some(&reply),
            ));
        }
        Ok(reply)
    }
    async fn read_rrset(&self, spec: &Spec) -> Result<List, ProviderError> {
        let first = self.page(spec, 0).await?;
        let values = first.body.as_array().expect("page checked array");
        if values.len() > 1 {
            return Err(self.error("selection", "UnsafeRRsetValues", "Target RRset contains multiple values; replacement could erase other DNS values, even with explicit synthetic ID.", Some(&first)));
        }
        let Some(value) = values.first() else {
            return Ok(List {
                records: vec![],
                request_id: first.request_id,
            });
        };
        let record = self.record(spec, value, Some(&first))?;
        // offset/limit ARE documented on filtered GET. Confirm exhaustion even
        // if server caps requested limit at one. Never return a partial RRset.
        let tail = self.page(spec, 1).await?;
        if !tail.body.as_array().expect("page checked array").is_empty() {
            return Err(self.error(
                "selection",
                "UnsafeRRsetValues",
                "More values exist on next page or pagination is unstable; no partial selection.",
                Some(&tail),
            ));
        }
        Ok(List {
            records: vec![record],
            request_id: first.request_id,
        })
    }
    fn record(
        &self,
        spec: &Spec,
        value: &Value,
        reply: Option<&HttpReply>,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error(
                "selection",
                "InvalidRRset",
                "Single RRset entry lacks valid name/type/data/TTL metadata.",
                reply,
            )
        };
        let name = value["name"].as_str().ok_or_else(bad)?;
        if !name.eq_ignore_ascii_case(&spec.subdomain)
            || value["type"].as_str() != Some(&spec.record_type)
        {
            return Err(self.error(
                "selection",
                "RRsetMismatch",
                "Filtered response returned another relative host or type.",
                reply,
            ));
        }
        let ip = value["data"]
            .as_str()
            .and_then(|d| d.parse::<IpAddr>().ok())
            .filter(|ip| ip.is_ipv4() == (spec.record_type == "A"))
            .ok_or_else(bad)?;
        let ttl = value["ttl"]
            .as_u64()
            .filter(|ttl| *ttl > 0)
            .ok_or_else(bad)?;
        // Writable qualifiers apply only to MX/SRV. Refuse unexpected A/AAAA
        // values rather than replay or silently discard metadata.
        for field in ["priority", "port", "protocol", "service", "weight"] {
            if value.get(field).is_some() {
                return Err(self.error(
                    "selection",
                    "UnsupportedRecordMetadata",
                    "A/AAAA contains MX/SRV-only metadata; refuse lossy replacement.",
                    reply,
                ));
            }
        }
        Ok(Record {
            id: rrset_id(&spec.record_type, &spec.subdomain),
            name: spec.fqdn(),
            record_type: spec.record_type.clone(),
            value: ip.to_string(),
            ttl,
            line: String::new(),
            enabled: true,
            extra: value.clone(),
        })
    }
    fn selection(&self, spec: &Spec, record: &Record) -> Result<(), ProviderError> {
        let verified = self.record(spec, &record.extra, None)?;
        if record.id != verified.id
            || !record.name.eq_ignore_ascii_case(&verified.name)
            || record.record_type != verified.record_type
            || record.value != verified.value
            || record.ttl != verified.ttl
            || !record.enabled
            || !record.line.is_empty()
        {
            return Err(self.error(
                "selection",
                "RRsetMismatch",
                "Selected synthetic ID or metadata contradicts configured target.",
                None,
            ));
        }
        Ok(())
    }
    async fn put(&self, spec: &Spec, ip: &str, stage: &str) -> Result<Mutation, ProviderError> {
        // DNSRecordCreateTypeName excludes name/type: fixed by path.
        // data/ttl are the only writable metadata applicable to A/AAAA.
        let reply = self
            .api
            .send(
                stage,
                self.request(Method::PUT, &self.path(spec))
                    .json(&json!([{"data": ip, "ttl": spec.ttl}])),
                true,
            )
            .await?;
        self.check(stage, &reply)?;
        // Official prose says204; schema's200 listing is inconsistent. Do not
        // invent JSON acknowledgement. Shared Api maps empty204 to Null.
        if reply.status != 204 || !reply.body.is_null() {
            return Err(self.error(stage, "InvalidWriteAcknowledgement", "Expected documented204 No Content; write outcome uncertain. Inspect before retrying.", Some(&reply)));
        }
        Ok(Mutation {
            record_id: rrset_id(&spec.record_type, &spec.subdomain),
            request_id: reply.request_id,
        })
    }
}
impl Adapter for Godaddy {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Fqdn
    }
    fn validate_selection(
        &self,
        spec: &Spec,
        record: Option<&Record>,
    ) -> Result<(), ProviderError> {
        self.validate_spec(spec)?;
        if let Some(record) = record {
            self.selection(spec, record)?;
        }
        Ok(())
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        self.domain(spec).await?;
        self.read_rrset(spec).await
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.validate_ip(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error(
                "create",
                "CreationNotAllowed",
                "Creation requires create_if_missing=true and no explicit record_id.",
                None,
            ));
        }
        self.domain(spec).await?;
        if !self.read_rrset(spec).await?.records.is_empty() {
            return Err(self.error(
                "create",
                "RRsetChanged",
                "RRset appeared; PUT upsert would replace it, so creation stopped.",
                None,
            ));
        }
        self.put(spec, &ip, "GodaddyCreateRRset").await
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let ip = self.validate_ip(spec, ip)?;
        self.selection(spec, record)?;
        self.domain(spec).await?;
        let fresh = self.read_rrset(spec).await?;
        if !fresh.records.first().is_some_and(|r| {
            r.id == record.id
                && r.extra == record.extra
                && r.value == record.value
                && r.ttl == record.ttl
        }) {
            return Err(self.error(
                "update",
                "RRsetChanged",
                "RRset vanished or changed after selection; no write attempted.",
                None,
            ));
        }
        self.put(spec, &ip, "GodaddyUpdateRRset").await
    }
}
fn hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn rrset_id(kind: &str, host: &str) -> String {
    // Same namespace-separated encoding as deSEC. Apex is empty host.
    let host = if host == "@" {
        String::new()
    } else {
        host.to_ascii_lowercase()
    };
    let id = if host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        format!("{kind}.{host}")
    } else {
        format!("{kind}._{}", hex::encode(host.as_bytes()))
    };
    if id.len() <= 128 {
        id
    } else {
        format!("{kind}..{}", hex::encode(Sha256::digest(id.as_bytes())))
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::reconcile;
    use super::*;
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::{Request, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::any,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    #[derive(Clone)]
    struct Seen {
        method: Method,
        uri: String,
        auth: Option<String>,
        body: Value,
    }
    struct Data {
        replies: VecDeque<(u16, Value)>,
        seen: Vec<Seen>,
    }
    struct Mock {
        endpoint: String,
        data: Arc<Mutex<Data>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(State(data): State<Arc<Mutex<Data>>>, request: Request<Body>) -> Response {
        let (p, b) = request.into_parts();
        let bytes = to_bytes(b, 1048576).await.unwrap();
        let seen = Seen {
            method: p.method,
            uri: p.uri.to_string(),
            auth: p
                .headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().into()),
            body: if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        };
        let (status, body) = {
            let mut d = data.lock().unwrap();
            d.seen.push(seen);
            d.replies
                .pop_front()
                .unwrap_or((500, json!({"code":"UNEXPECTED_REQUEST"})))
        };
        if status == 204 {
            StatusCode::NO_CONTENT.into_response()
        } else {
            (StatusCode::from_u16(status).unwrap(), Json(body)).into_response()
        }
    }
    impl Mock {
        async fn new(replies: Vec<(u16, Value)>) -> Self {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/v1", l.local_addr().unwrap());
            let data = Arc::new(Mutex::new(Data {
                replies: replies.into(),
                seen: vec![],
            }));
            let app = Router::new()
                .route("/{*path}", any(handler))
                .with_state(data.clone());
            let task = tokio::spawn(async move {
                axum::serve(l, app).await.unwrap();
            });
            Self {
                endpoint,
                data,
                task,
            }
        }
        fn adapter(&self) -> Godaddy {
            let c = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let mut g = Godaddy::new(c, "test-id".into(), "test-key".into(), &BTreeMap::new());
            g.endpoint = self.endpoint.clone();
            g
        }
        fn seen(&self) -> Vec<Seen> {
            self.data.lock().unwrap().seen.clone()
        }
        fn done(&self) {
            assert!(self.data.lock().unwrap().replies.is_empty());
        }
        fn no_write(&self) {
            assert!(self.seen().iter().all(|q| q.method == Method::GET));
            self.done();
        }
    }
    fn zone() -> (u16, Value) {
        (
            200,
            json!({"domain":"example.com","status":"ACTIVE","holdRegistrar":false}),
        )
    }
    fn empty() -> (u16, Value) {
        (200, json!([]))
    }
    fn item(ip: &str) -> Value {
        json!({"name":"home","type":"A","data":ip,"ttl":600})
    }
    fn one(ip: &str) -> (u16, Value) {
        (200, json!([item(ip)]))
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
    #[tokio::test]
    async fn auth_and_filtered_pagination() {
        let m = Mock::new(vec![zone(), one("1.1.1.1"), empty()]).await;
        assert_eq!(
            m.adapter().list(&spec()).await.unwrap().records[0].id,
            "A.home"
        );
        let q = m.seen();
        assert_eq!(q[0].uri, "/v1/domains/example.com");
        assert_eq!(
            q[1].uri,
            "/v1/domains/example.com/records/A/home?offset=0&limit=2"
        );
        assert_eq!(
            q[2].uri,
            "/v1/domains/example.com/records/A/home?offset=1&limit=2"
        );
        assert!(
            q.iter()
                .all(|q| q.auth.as_deref() == Some("sso-key test-id:test-key"))
        );
        m.no_write();
    }
    #[test]
    fn sensitive_header_fixed_endpoint_and_redaction() {
        let mut o = BTreeMap::new();
        o.insert("endpoint".into(), "http://evil.invalid".into());
        let g = Godaddy::new(
            reqwest::Client::new(),
            "test-id".into(),
            "test-key".into(),
            &o,
        );
        let q = g
            .request(Method::GET, "/domains/example.com")
            .build()
            .unwrap();
        assert!(q.headers()[reqwest::header::AUTHORIZATION].is_sensitive());
        assert_eq!(
            q.url().as_str(),
            "https://api.godaddy.com/v1/domains/example.com"
        );
        assert!(
            !g.api
                .safe("sso-key test-id:test-key test-id test-key")
                .contains("test-")
        );
    }
    #[tokio::test]
    async fn allowlisted_error_fields_sanitized() {
        let m=Mock::new(vec![(403,json!({"code":"DENIED","message":"test-id:test-key","fields":[{"path":"data","message":"test-key","value":"raw-value"}],"headers":"raw-header","body":"raw-body"}))]).await;
        let e = m.adapter().list(&spec()).await.unwrap_err();
        let text = format!("{e:?}");
        for s in ["test-id", "test-key", "raw-value", "raw-header", "raw-body"] {
            assert!(!text.contains(s));
        }
        assert!(e.message.contains("field.path: data"));
        assert!(e.message.contains("REDACTED"));
        m.no_write();
    }
    #[tokio::test]
    async fn failed_zone_never_empty() {
        let m = Mock::new(vec![(404, json!({"code":"NOT_FOUND"}))]).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert!(reconcile(&m.adapter(), &s, "8.8.8.8", false).await.is_err());
        assert_eq!(m.seen().len(), 1);
        m.no_write();
    }
    #[tokio::test]
    async fn wrong_zone_status_partial_and_hold() {
        for (status, body) in [
            (200, json!({"domain":"other.com","status":"ACTIVE"})),
            (200, json!({"domain":"example.com","status":"PENDING_DNS"})),
            (203, json!({"domain":"example.com","status":"ACTIVE"})),
            (
                200,
                json!({"domain":"example.com","status":"ACTIVE","holdRegistrar":true}),
            ),
        ] {
            let m = Mock::new(vec![(status, body)]).await;
            assert!(m.adapter().list(&spec()).await.is_err());
            assert_eq!(m.seen().len(), 1);
            m.no_write();
        }
    }
    #[tokio::test]
    async fn target_404_permission_business_errors_never_empty_or_retried() {
        for status in [200, 401, 403, 404, 429, 500] {
            let m = Mock::new(vec![
                zone(),
                (status, json!({"code":"DENIED","message":"No access"})),
            ])
            .await;
            let mut s = spec();
            s.create_if_missing = true;
            let e = reconcile(&m.adapter(), &s, "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "DENIED");
            assert!(!e.retryable);
            assert_eq!(m.seen().len(), 2);
            m.no_write();
        }
    }
    #[tokio::test]
    async fn multivalue_even_dry_run_explicit_id() {
        for dry in [false, true] {
            let m = Mock::new(vec![
                zone(),
                (200, json!([item("1.1.1.1"), item("2.2.2.2")])),
            ])
            .await;
            let mut s = spec();
            s.record_id = Some("A.home".into());
            assert_eq!(
                reconcile(&m.adapter(), &s, "8.8.8.8", dry)
                    .await
                    .unwrap_err()
                    .code,
                "UnsafeRRsetValues"
            );
            m.no_write();
        }
    }
    #[tokio::test]
    async fn capped_page_cannot_hide_second_value() {
        let m = Mock::new(vec![zone(), one("1.1.1.1"), one("2.2.2.2")]).await;
        assert_eq!(
            m.adapter().list(&spec()).await.unwrap_err().code,
            "UnsafeRRsetValues"
        );
        m.no_write();
    }
    #[tokio::test]
    async fn shared_dryrun_and_noop() {
        for (ip, status) in [("8.8.8.8", "would_update"), ("1.1.1.1", "unchanged")] {
            let m = Mock::new(vec![zone(), one("1.1.1.1"), empty()]).await;
            assert_eq!(
                reconcile(&m.adapter(), &spec(), ip, true)
                    .await
                    .unwrap()
                    .status,
                status
            );
            m.no_write();
        }
        let m = Mock::new(vec![zone(), empty()]).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.adapter(), &s, "8.8.8.8", true)
                .await
                .unwrap()
                .status,
            "would_create"
        );
        m.no_write();
    }
    #[tokio::test]
    async fn update_reread_scoped_put_and_204() {
        let m = Mock::new(vec![
            zone(),
            one("1.1.1.1"),
            empty(),
            zone(),
            one("1.1.1.1"),
            empty(),
            (204, Value::Null),
        ])
        .await;
        let o = reconcile(&m.adapter(), &spec(), "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(o.status, "updated");
        assert_eq!(o.record_id.as_deref(), Some("A.home"));
        let q = m.seen();
        assert_eq!(q.len(), 7);
        assert_eq!(q[6].method, Method::PUT);
        assert_eq!(q[6].uri, "/v1/domains/example.com/records/A/home");
        assert_eq!(q[6].body, json!([{"data":"8.8.8.8","ttl":600}]));
        m.done();
    }
    #[tokio::test]
    async fn stale_value_ttl_metadata_or_deleted() {
        let mut ttl = item("1.1.1.1");
        ttl["ttl"] = json!(601);
        let mut meta = item("1.1.1.1");
        meta["changedAt"] = json!("now");
        for fresh in [
            one("2.2.2.2"),
            (200, json!([ttl])),
            (200, json!([meta])),
            empty(),
        ] {
            let nonempty = !fresh.1.as_array().unwrap().is_empty();
            let mut q = vec![zone(), one("1.1.1.1"), empty(), zone(), fresh];
            if nonempty {
                q.push(empty());
            }
            let m = Mock::new(q).await;
            assert_eq!(
                reconcile(&m.adapter(), &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "RRsetChanged"
            );
            m.no_write();
        }
    }
    #[tokio::test]
    async fn added_value_before_write() {
        let m = Mock::new(vec![
            zone(),
            one("1.1.1.1"),
            empty(),
            zone(),
            (200, json!([item("1.1.1.1"), item("2.2.2.2")])),
        ])
        .await;
        assert_eq!(
            reconcile(&m.adapter(), &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "UnsafeRRsetValues"
        );
        m.no_write();
    }
    #[tokio::test]
    async fn optin_create_acknowledges_204() {
        let m = Mock::new(vec![zone(), empty(), zone(), empty(), (204, Value::Null)]).await;
        let mut s = spec();
        s.create_if_missing = true;
        let o = reconcile(&m.adapter(), &s, "8.8.8.8", false).await.unwrap();
        assert_eq!(o.status, "created");
        assert_eq!(o.record_id.as_deref(), Some("A.home"));
        assert_eq!(m.seen()[4].body, json!([{"data":"8.8.8.8","ttl":600}]));
        m.done();
    }
    #[tokio::test]
    async fn create_race_prevents_replacement() {
        let m = Mock::new(vec![zone(), empty(), zone(), one("2.2.2.2"), empty()]).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.adapter(), &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RRsetChanged"
        );
        m.no_write();
    }
    #[tokio::test]
    async fn creation_disabled_and_explicit_missing_id() {
        let m = Mock::new(vec![zone(), empty()]).await;
        assert_eq!(
            reconcile(&m.adapter(), &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordNotFound"
        );
        m.no_write();
        let m = Mock::new(vec![zone(), empty()]).await;
        let mut s = spec();
        s.record_id = Some("A.home".into());
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.adapter(), &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordIdNotFound"
        );
        m.no_write();
        let m = Mock::new(vec![]).await;
        assert_eq!(
            m.adapter()
                .create(&spec(), "8.8.8.8")
                .await
                .unwrap_err()
                .code,
            "CreationNotAllowed"
        );
        m.no_write();
    }
    #[tokio::test]
    async fn malformed_target_ip_and_writable_metadata() {
        let mut extra = item("1.1.1.1");
        extra["priority"] = json!(0);
        for b in [
            json!({"records":[]}),
            json!([{"name":"other","type":"A","data":"1.1.1.1","ttl":600}]),
            json!([{"name":"home","type":"AAAA","data":"::1","ttl":600}]),
            json!([item("bad-ip")]),
            json!([extra]),
        ] {
            let m = Mock::new(vec![zone(), (200, b)]).await;
            assert!(m.adapter().list(&spec()).await.is_err());
            assert_eq!(m.seen().len(), 2);
            m.no_write();
        }
    }
    #[tokio::test]
    async fn write_errors_and_unexpected_ack_no_retry() {
        for (status, b, code) in [
            (200, json!({}), "InvalidWriteAcknowledgement"),
            (200, json!({"code":"DENIED"}), "DENIED"),
            (500, json!({"code":"SERVER_ERROR"}), "SERVER_ERROR"),
        ] {
            let m = Mock::new(vec![zone(), empty(), zone(), empty(), (status, b)]).await;
            let mut s = spec();
            s.create_if_missing = true;
            let e = reconcile(&m.adapter(), &s, "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, code);
            assert!(!e.retryable);
            assert_eq!(m.seen().len(), 5);
            m.done();
        }
    }
    #[tokio::test]
    async fn ipv6_apex_ttl_not_clamped() {
        let m = Mock::new(vec![zone(), empty(), zone(), empty(), (204, Value::Null)]).await;
        let mut s = spec();
        s.subdomain = "@".into();
        s.record_type = "AAAA".into();
        s.ttl = 60;
        s.create_if_missing = true;
        let o = reconcile(&m.adapter(), &s, "2001:db8::1", false)
            .await
            .unwrap();
        assert_eq!(o.record_id.as_deref(), Some("AAAA."));
        assert_eq!(m.seen()[4].uri, "/v1/domains/example.com/records/AAAA/@");
        assert_eq!(m.seen()[4].body, json!([{"data":"2001:db8::1","ttl":60}]));
        m.done();
    }
    #[test]
    fn bounded_collision_safe_ids() {
        use super::super::common::valid_id;
        assert_eq!(rrset_id("A", "HOME"), "A.home");
        assert_eq!(rrset_id("A", "@"), "A.");
        assert_ne!(rrset_id("A", "_a"), rrset_id("A", "a"));
        let long = format!("{}.{}.{}", "a".repeat(60), "b".repeat(60), "c".repeat(60));
        assert!(valid_id(&rrset_id("AAAA", &long)));
        assert_ne!(rrset_id("A", &long), rrset_id("AAAA", &long));
    }
}
