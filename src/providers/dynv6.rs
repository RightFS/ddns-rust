//! dynv6 REST API v2, never the write-only Update/DynDNS API.
//! https://dynv6.com/docs/apis
//! https://github.com/dynv6/api-spec/blob/master/api/openapi.yml
//! https://github.com/dynv6/api-spec/blob/master/api/models/record.yml
//! The official REST model has no readable/writable TTL: explicit opt-in to
//! provider-managed TTL is required. Record.ttl=0 marks TTL unavailable,
//! not an actual DNS TTL. manages_ttl=false prevents TTL-only mutations.
//! Only literal child A/AAAA records; zone-primary/apex changes can affect
//! inherited records and IPv6 prefixes, so all zone mutations are refused.
//! Caller must disable redirects. No CAS is documented: use one writer.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
const ENDPOINT: &str = "https://dynv6.com/api/v2";
const HINT: &str = "Use a dynv6 HTTP REST token with access to the exact zone, and literal child A/AAAA records. Apex/zone updates and inherited/MAC/prefix records are refused. REST does not expose TTL; explicitly opt into provider-managed TTL. No conditional write/CAS is documented; use an exclusive writer. Inspect uncertain writes before retrying; no automatic write retries occur.";
pub struct Dynv6 {
    api: Api,
    token: String,
    options: BTreeMap<String, String>,
    #[cfg(test)]
    endpoint: String,
}
impl Dynv6 {
    pub fn new(client: reqwest::Client, token: String, options: &BTreeMap<String, String>) -> Self {
        Self {
            api: Api::new(client, vec![format!("Bearer {token}"), token.clone()]),
            token,
            options: options.clone(),
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
    fn error(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage, code, message, HINT, reply)
    }
    fn validate(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.token.trim().is_empty()
            || self
                .token
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(self.error(
                "credentials",
                "InvalidCredentials",
                "A nonempty plain dynv6 HTTP token is required.",
                None,
            ));
        }
        if !hostname(&spec.domain)
            || !spec.domain.contains('.')
            || !hostname(&spec.subdomain)
            || spec.fqdn().len() > 253
        {
            let code = if spec.subdomain == "@" {
                "UnsupportedApex"
            } else {
                "InvalidDnsName"
            };
            return Err(self.error("validation",code,"Use an exact ASCII/punycode zone and plain relative child host. Apex zone-primary mutations are refused because they can affect dependent records.",None));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Only literal A and AAAA child records are supported.",
                None,
            ));
        }
        if !spec.options.is_empty()
            || !matches!(spec.record_line.as_str(), "默认" | "default")
            || self.options.keys().any(|k| k != "ttl_mode")
        {
            return Err(self.error("validation","UnsupportedOptions","Only provider ttl_mode=provider_default is supported; no record options, routing or endpoint overrides.",None));
        }
        if self.options.get("ttl_mode").map(String::as_str) != Some("provider_default") {
            return Err(self.error("validation","UnsupportedTTL","dynv6 REST does not expose TTL. Set provider ttl_mode=provider_default to acknowledge that configured TTL cannot be enforced or read.",None));
        }
        if spec.ttl == 0 || spec.ttl > 604800 {
            return Err(self.error("validation","InvalidTTL","Configuration TTL must remain within the application 1..604800 bound, but provider_default mode does not enforce it on dynv6.",None));
        }
        if spec
            .record_id
            .as_ref()
            .is_some_and(|s| id(&json!(s)).as_deref() != Some(s.as_str()))
        {
            return Err(self.error(
                "validation",
                "InvalidRecordId",
                "Use a canonical positive int64 decimal record ID.",
                None,
            ));
        }
        Ok(())
    }
    fn desired(&self, spec: &Spec, ip: &str) -> Result<String, ProviderError> {
        self.validate(spec)?;
        let ip = ip.parse::<IpAddr>().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be a literal IP address.",
                None,
            )
        })?;
        if ip.is_ipv4() != (spec.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "Desired IP family does not match A/AAAA.",
                None,
            ));
        }
        Ok(ip.to_string())
    }
    async fn call(
        &self,
        stage: &str,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<HttpReply, ProviderError> {
        let write = method != Method::GET;
        let mut request = self
            .api
            .client
            .request(method, format!("{}{path}", self.endpoint()))
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let reply = self.api.send(stage, request, write).await?;
        if !(200..300).contains(&reply.status) || reply.body.get("error").is_some() {
            let source = reply.body.get("error").unwrap_or(&reply.body);
            let fallback = if reply.status == 200 {
                "Dynv6ApiError".into()
            } else {
                format!("Http{}", reply.status)
            };
            let code = source
                .get("name")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or(&fallback);
            let mut details = Vec::new();
            if let Some(text) = source.get("message").and_then(Value::as_str) {
                details.push(self.api.safe(text));
            }
            if let Some(fields) = source.get("fields").and_then(Value::as_array) {
                for field in fields.iter().take(16) {
                    let name = field
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified");
                    let message = field
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("no recognized field detail");
                    details.push(format!(
                        "field {}: {}",
                        self.api.safe(name),
                        self.api.safe(message)
                    ));
                }
            }
            if let Some(text) = source.as_str() {
                details.push(self.api.safe(text));
            }
            if details.is_empty() {
                details.push("No recognized error detail; raw response omitted.".into());
            }
            return Err(self.error(
                stage,
                code,
                &format!("dynv6 REST error: {}", details.join("; ")),
                Some(&reply),
            ));
        }
        if reply.status != 200 {
            return Err(self.error(
                stage,
                "InvalidEnvelope",
                "Expected documented HTTP200 acknowledgement; inspect uncertain writes.",
                Some(&reply),
            ));
        }
        Ok(reply)
    }
    fn zone_value(
        &self,
        spec: &Spec,
        raw: &Value,
        reply: &HttpReply,
        expected: Option<&str>,
    ) -> Result<String, ProviderError> {
        let zone = id(&raw["id"]).ok_or_else(|| {
            self.error(
                "zone",
                "InvalidZone",
                "Zone lacks a valid positive int64 ID.",
                Some(reply),
            )
        })?;
        if !raw["name"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(&spec.domain))
            || expected.is_some_and(|s| s != zone)
        {
            return Err(self.error("zone","ZoneMismatch","Zone read does not confirm exact authenticated domain/ID; suffix fallback is refused.",Some(reply)));
        }
        for field in ["disabled", "enabled"] {
            if let Some(value) = raw.get(field) {
                let active = match (field, value) {
                    ("disabled", Value::Bool(v)) => !*v,
                    ("enabled", Value::Bool(v)) => *v,
                    _ => false,
                };
                if !active {
                    return Err(self.error(
                        "zone",
                        "ZoneDisabled",
                        "Zone is disabled or has unrecognized activity metadata.",
                        Some(reply),
                    ));
                }
            }
        }
        Ok(zone)
    }
    async fn zone(&self, spec: &Spec) -> Result<String, ProviderError> {
        self.validate(spec)?;
        let reply = self
            .call(
                "zone",
                Method::GET,
                &format!("/zones/by-name/{}", spec.domain.to_ascii_lowercase()),
                None,
            )
            .await?;
        let zone = self.zone_value(spec, &reply.body, &reply, None)?;
        let by_id = self
            .call("zone", Method::GET, &format!("/zones/{zone}"), None)
            .await?;
        self.zone_value(spec, &by_id.body, &by_id, Some(&zone))
    }
    fn record(
        &self,
        spec: &Spec,
        zone: &str,
        raw: &Value,
        stage: &str,
        reply: Option<&HttpReply>,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error(
                stage,
                "MalformedRecord",
                "Record lacks valid ID, zoneID, relative name, type or data; selection stopped.",
                reply,
            )
        };
        let record_id = id(&raw["id"]).ok_or_else(bad)?;
        if id(&raw["zoneID"]).as_deref() != Some(zone) {
            return Err(self.error(
                stage,
                "RecordZoneMismatch",
                "Returned record belongs to another zone.",
                reply,
            ));
        }
        let host = raw["name"]
            .as_str()
            .filter(|s| record_host(s))
            .ok_or_else(bad)?;
        let kind = raw["type"]
            .as_str()
            .filter(|s| {
                matches!(
                    *s,
                    "A" | "AAAA" | "CAA" | "CNAME" | "MX" | "SPF" | "SRV" | "TXT"
                )
            })
            .ok_or_else(bad)?;
        let data = raw["data"].as_str().ok_or_else(bad)?;
        let name = if matches!(host, "" | "@") {
            spec.domain.clone()
        } else {
            format!("{host}.{}", spec.domain)
        };
        if name.len() > 253 {
            return Err(bad());
        }
        let enabled = match raw.get("enabled") {
            None => true,
            Some(Value::Bool(v)) => *v,
            _ => return Err(bad()),
        };
        Ok(Record {
            id: record_id,
            name,
            record_type: kind.into(),
            value: data.into(),
            ttl: 0,
            line: String::new(),
            enabled,
            extra: raw.clone(),
        })
    }
    fn selected(&self, spec: &Spec, zone: &str, r: &Record) -> Result<(), ProviderError> {
        let actual = self.record(spec, zone, &r.extra, "selection", None)?;
        if r.id != actual.id
            || r.name != actual.name
            || !r.name.eq_ignore_ascii_case(&spec.fqdn())
            || r.record_type != spec.record_type
            || r.record_type != actual.record_type
            || r.value != actual.value
            || r.ttl != actual.ttl
            || !r.line.is_empty()
            || r.enabled != actual.enabled
            || spec.record_id.as_ref().is_some_and(|id| id != &r.id)
        {
            return Err(self.error(
                "selection",
                "RecordTargetMismatch",
                "Selected record does not match immutable ID/zone/host/type or read metadata.",
                None,
            ));
        }
        if !r.enabled {
            return Err(self.error(
                "selection",
                "RecordDisabled",
                "Selected record is disabled; it will not be enabled or updated.",
                None,
            ));
        }
        let ip=r.value.parse::<IpAddr>().map_err(|_|self.error("selection","ManagedRecord","Selected data is inherited, MAC/EUI-64, suffix/prefix or otherwise not a literal IP; no mutation.",None))?;
        if ip.is_ipv4() != (spec.record_type == "A") {
            return Err(self.error(
                "selection",
                "InvalidRecordValue",
                "Existing literal IP has the wrong family.",
                None,
            ));
        }
        if let Some(expanded) = r.extra.get("expandedData")
            && expanded.as_str().and_then(|s| s.parse::<IpAddr>().ok()) != Some(ip)
        {
            return Err(self.error(
                "selection",
                "ManagedRecord",
                "Expanded data differs from literal data; inherited/dynamic record refused.",
                None,
            ));
        }
        let raw = r.extra.as_object().expect("record checked object");
        for (key, value) in raw {
            match key.as_str() {
                "id"|"zoneID"|"name"|"type"|"data"|"expandedData"=>{},
                "priority"|"port"|"weight"|"flags" if value.as_u64()==Some(0)=>{},
                _=>return Err(self.error("selection","UnsafeRecordSettings","Selected A/AAAA contains undocumented or nondefault type-specific settings; refusal prevents lossy or managed-record changes.",None)),
            }
        }
        Ok(())
    }
    async fn records(&self, spec: &Spec, zone: &str) -> Result<List, ProviderError> {
        let reply = self
            .call("list", Method::GET, &format!("/zones/{zone}/records"), None)
            .await?;
        // Official API returns all records in an unpaginated array. Do not invent
        // page/cursor requests or consider a paginated object an empty zone.
        if [
            "link",
            "content-range",
            "x-next-page",
            "x-page",
            "x-total-count",
            "x-pagination-total",
            "x-has-more",
        ]
        .iter()
        .any(|key| reply.headers.contains_key(*key))
        {
            return Err(self.error(
                "list",
                "IncompleteRecordList",
                "Unexpected pagination/truncation headers; cannot prove complete record selection.",
                Some(&reply),
            ));
        }
        let raw=reply.body.as_array().ok_or_else(||self.error("list","MalformedRecordList","Expected documented complete JSON record array, not a pagination or status envelope.",Some(&reply)))?;
        if raw.len() > 10000 {
            return Err(self.error(
                "list",
                "RecordLimit",
                "More than10000 records; safe selection stopped.",
                Some(&reply),
            ));
        }
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        for value in raw {
            let r = self.record(spec, zone, value, "list", Some(&reply))?;
            if r.name.eq_ignore_ascii_case(&spec.fqdn()) && r.record_type == "CNAME" {
                return Err(self.error("list", "RecordConflict", "A CNAME exists at the configured A/AAAA target; no creation, update or dry-run prediction is safe.", Some(&reply)));
            }
            if !seen.insert(r.id.clone()) {
                return Err(self.error(
                    "list",
                    "UnstableRecordList",
                    "Repeated record IDs returned; selection stopped.",
                    Some(&reply),
                ));
            }
            records.push(r);
        }
        Ok(List {
            records,
            request_id: reply.request_id,
        })
    }
    fn ack(
        &self,
        spec: &Spec,
        zone: &str,
        ip: &str,
        old: Option<&Record>,
        reply: &HttpReply,
        stage: &str,
    ) -> Result<Mutation, ProviderError> {
        let bad = || {
            self.error(stage,"InvalidWriteAcknowledgement","dynv6 did not acknowledge immutable ID/zoneID/host/type and requested literal IP with preserved metadata; result uncertain, inspect before retrying.",Some(reply))
        };
        let r = self
            .record(spec, zone, &reply.body, stage, Some(reply))
            .map_err(|_| bad())?;
        self.selected(spec, zone, &r).map_err(|_| bad())?;
        if r.value.parse::<IpAddr>().ok() != ip.parse::<IpAddr>().ok()
            || old.is_some_and(|old| old.id != r.id)
        {
            return Err(bad());
        }
        if let Some(old) = old {
            let mut before = old.extra.clone();
            let mut after = r.extra.clone();
            for value in [&mut before, &mut after] {
                let map = value.as_object_mut().expect("record object");
                map.remove("data");
                map.remove("expandedData");
            }
            if before != after {
                return Err(bad());
            }
        }
        Ok(Mutation {
            record_id: r.id,
            request_id: reply.request_id.clone(),
        })
    }
}
impl Adapter for Dynv6 {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Fqdn
    }
    fn manages_ttl(&self) -> bool {
        false
    }
    fn validate_selection(&self, spec: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.validate(spec)?;
        if let Some(r) = r {
            let zone = id(&r.extra["zoneID"]).ok_or_else(|| {
                self.error(
                    "selection",
                    "MalformedRecord",
                    "Selected record lacks a zone ID.",
                    None,
                )
            })?;
            self.selected(spec, &zone, r)?;
        }
        Ok(())
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        let zone = self.zone(spec).await?;
        self.records(spec, &zone).await
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.desired(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error(
                "create",
                "CreationNotAllowed",
                "Creation requires explicit opt-in and no explicit record ID.",
                None,
            ));
        }
        let zone = self.zone(spec).await?;
        let list = self.records(spec, &zone).await?;
        if list.records.iter().any(|r| {
            r.name.eq_ignore_ascii_case(&spec.fqdn())
                && (r.record_type == spec.record_type || r.record_type == "CNAME")
        }) {
            return Err(self.error(
                "create",
                "RecordAppeared",
                "Target or CNAME appeared on final complete read; no mutation.",
                None,
            ));
        }
        let body = json!({"name":spec.subdomain,"type":spec.record_type,"data":ip});
        let reply = self
            .call(
                "create",
                Method::POST,
                &format!("/zones/{zone}/records"),
                Some(&body),
            )
            .await?;
        let mutation = self.ack(spec, &zone, &ip, None, &reply, "create")?;
        if list.records.iter().any(|r| r.id == mutation.record_id) {
            return Err(self.error("create", "InvalidWriteAcknowledgement", "Create acknowledgement reused an existing record ID; result uncertain, inspect before retrying.", Some(&reply)));
        }
        Ok(mutation)
    }
    async fn update(&self, spec: &Spec, r: &Record, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.desired(spec, ip)?;
        let zone = self.zone(spec).await?;
        self.selected(spec, &zone, r)?;
        let list = self.records(spec, &zone).await?;
        let matches = list
            .records
            .iter()
            .filter(|candidate| {
                candidate.name.eq_ignore_ascii_case(&spec.fqdn())
                    && candidate.record_type == spec.record_type
            })
            .collect::<Vec<_>>();
        if (spec.record_id.is_none() && matches.len() != 1)
            || !matches
                .iter()
                .any(|candidate| candidate.id == r.id && candidate.extra == r.extra)
        {
            return Err(self.error("preflight", "RecordChanged", "Complete preflight list changed, became ambiguous or lost the selected ID; no mutation attempted.", None));
        }
        let path = format!("/zones/{zone}/records/{}", r.id);
        let fresh = self.call("preflight", Method::GET, &path, None).await?;
        let actual = self.record(spec, &zone, &fresh.body, "preflight", Some(&fresh))?;
        self.selected(spec, &zone, &actual)?;
        if actual.id != r.id || actual.extra != r.extra {
            return Err(self.error(
                "preflight",
                "RecordChanged",
                "Selected record changed since listing; no write attempted.",
                Some(&fresh),
            ));
        }
        // PATCH only data: name/type/zone metadata are immutable, not replayed.
        let reply = self
            .call("update", Method::PATCH, &path, Some(&json!({"data":ip})))
            .await?;
        self.ack(spec, &zone, &ip, Some(r), &reply, "update")
    }
}
fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn record_host(s: &str) -> bool {
    matches!(s, "" | "@")
        || (s.len() <= 253
            && s.split('.').enumerate().all(|(i, s)| {
                (i == 0 && s == "*")
                    || (!s.is_empty()
                        && s.len() <= 63
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
            }))
}
fn id(value: &Value) -> Option<String> {
    let n = match value {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => {
            let n = s.parse::<u64>().ok()?;
            if n.to_string() != *s {
                return None;
            }
            n
        }
        _ => return None,
    };
    (n > 0 && n <= i64::MAX as u64).then(|| n.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::common::reconcile;
    use super::*;
    use axum::{
        Router,
        body::to_bytes,
        extract::{Request, State},
        http::StatusCode,
        response::{IntoResponse, Response},
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
        auth: String,
        content_type: Option<String>,
        body: Value,
    }
    #[derive(Clone)]
    struct MockState {
        replies: Arc<Mutex<VecDeque<(u16, String)>>>,
        calls: Arc<Mutex<Vec<Capture>>>,
    }
    struct Mock {
        provider: Dynv6,
        calls: Arc<Mutex<Vec<Capture>>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(State(state): State<MockState>, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        state.calls.lock().unwrap().push(Capture {
            method: parts.method,
            uri: parts.uri.to_string(),
            auth: parts.headers["authorization"].to_str().unwrap().into(),
            content_type: parts
                .headers
                .get("content-type")
                .map(|v| v.to_str().unwrap().into()),
            body: if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        });
        let (status, body) = state.replies.lock().unwrap().pop_front().unwrap_or((
            500,
            "{\"error\":{\"name\":\"UnexpectedRequest\",\"message\":\"Unexpected request\"}}"
                .into(),
        ));
        let paginated = body.starts_with("MOCK_LINK:");
        let body = body.strip_prefix("MOCK_LINK:").unwrap_or(&body).to_owned();
        let mut response = (
            StatusCode::from_u16(status).unwrap(),
            [("x-request-id", "dyn-trace")],
            body,
        )
            .into_response();
        if paginated {
            response.headers_mut().insert(
                "link",
                "</api/v2/zones/12/records?page=2>; rel=next"
                    .parse()
                    .unwrap(),
            );
        }
        response
    }
    fn options() -> BTreeMap<String, String> {
        BTreeMap::from([("ttl_mode".into(), "provider_default".into())])
    }
    async fn mock_raw(replies: Vec<(u16, String)>) -> Mock {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            replies: Arc::new(Mutex::new(replies.into())),
            calls: calls.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/api/v2", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/{*path}", any(handler))
                    .with_state(state),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let mut provider = Dynv6::new(client, "dyn-token-secret".into(), &options());
        provider.endpoint = endpoint;
        Mock {
            provider,
            calls,
            task,
        }
    }
    async fn mock(replies: Vec<Value>) -> Mock {
        mock_raw(replies.into_iter().map(|v| (200, v.to_string())).collect()).await
    }
    fn spec() -> Spec {
        Spec {
            domain: "example.dynv6.net".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "默认".into(),
            ttl: 600,
            record_id: None,
            create_if_missing: false,
            options: BTreeMap::new(),
        }
    }
    fn zone() -> Value {
        json!({"id":12,"name":"example.dynv6.net","ipv4address":"1.1.1.1","ipv6prefix":"2001:db8::/64","createdAt":"2020-01-01T00:00:00Z"})
    }
    fn raw(id: u64, name: &str, kind: &str, data: &str) -> Value {
        json!({"id":id,"zoneID":12,"name":name,"type":kind,"data":data})
    }
    fn record() -> Value {
        raw(34, "home", "A", "1.1.1.1")
    }
    fn reads(values: Vec<Value>) -> Vec<Value> {
        vec![zone(), zone(), json!(values)]
    }
    fn no_writes(m: &Mock) {
        assert!(
            m.calls
                .lock()
                .unwrap()
                .iter()
                .all(|c| c.method == Method::GET)
        );
    }
    fn credentials(m: &Mock) {
        for call in m.calls.lock().unwrap().iter() {
            assert_eq!(call.auth, "Bearer dyn-token-secret");
            assert!(!call.uri.contains("token"));
            assert!(!call.uri.contains('?'));
            if call.method != Method::GET {
                assert_eq!(call.content_type.as_deref(), Some("application/json"));
                assert!(call.body.get("ttl").is_none());
            } else {
                assert!(call.body.is_null());
            }
        }
    }
    #[tokio::test]
    async fn exact_zone_reads_complete_array_keep_all_records_and_unavailable_ttl() {
        let m = mock(reads(vec![
            record(),
            raw(35, "_acme-challenge", "TXT", "text"),
            raw(36, "*", "AAAA", "2001:db8::1"),
        ]))
        .await;
        let out = m.provider.list(&spec()).await.unwrap();
        assert_eq!(out.records.len(), 3);
        assert_eq!(out.records[0].id, "34");
        assert_eq!(out.records[0].ttl, 0);
        assert_eq!(out.records[0].extra, record());
        assert!(!m.provider.manages_ttl());
        assert_eq!(out.request_id.as_deref(), Some("dyn-trace"));
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls[0].uri, "/api/v2/zones/by-name/example.dynv6.net");
        assert_eq!(calls[1].uri, "/api/v2/zones/12");
        assert_eq!(calls[2].uri, "/api/v2/zones/12/records");
        drop(calls);
        no_writes(&m);
        credentials(&m);
    }
    #[tokio::test]
    async fn noops_ignore_configured_ttl_under_explicit_provider_default() {
        for ttl in [60, 600, 3600, 604800] {
            let m = mock(reads(vec![record()])).await;
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(
                reconcile(&m.provider, &s, "1.1.1.1", false)
                    .await
                    .unwrap()
                    .status,
                "unchanged"
            );
            no_writes(&m);
            assert_eq!(m.calls.lock().unwrap().len(), 3);
        }
    }
    #[tokio::test]
    async fn dry_run_never_creates_or_updates() {
        for (records, create, status) in [
            (vec![], true, "would_create"),
            (vec![record()], false, "would_update"),
        ] {
            let m = mock(reads(records)).await;
            let mut s = spec();
            s.create_if_missing = create;
            assert_eq!(
                reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap()
                    .status,
                status
            );
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn patch_data_only_preserves_metadata_and_identity() {
        let mut old = record();
        for key in ["priority", "port", "weight", "flags"] {
            old[key] = json!(0);
        }
        old["expandedData"] = json!("1.1.1.1");
        let mut ack = old.clone();
        ack["data"] = json!("8.8.8.8");
        ack["expandedData"] = json!("8.8.8.8");
        let mut replies = reads(vec![old.clone()]);
        replies.extend([zone(), zone(), json!([old.clone()]), old, ack]);
        let m = mock(replies).await;
        let mut s = spec();
        s.record_id = Some("34".into());
        let out = reconcile(&m.provider, &s, "8.8.8.8", false).await.unwrap();
        assert_eq!(out.status, "updated");
        assert_eq!(out.record_id.as_deref(), Some("34"));
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls[5].method, Method::GET);
        assert_eq!(calls[5].uri, "/api/v2/zones/12/records");
        assert_eq!(calls[6].method, Method::GET);
        assert_eq!(calls[6].uri, "/api/v2/zones/12/records/34");
        assert_eq!(calls[7].method, Method::PATCH);
        assert_eq!(calls[7].uri, calls[6].uri);
        assert_eq!(calls[7].body, json!({"data":"8.8.8.8"}));
        drop(calls);
        credentials(&m);
    }
    #[tokio::test]
    async fn creates_both_ip_families_after_final_zone_and_record_read() {
        for (kind, ip) in [("A", "8.8.8.8"), ("AAAA", "2001:db8::1")] {
            let mut replies = reads(vec![]);
            replies.extend(reads(vec![]));
            replies.push(raw(55, "home", kind, ip));
            let m = mock(replies).await;
            let mut s = spec();
            s.record_type = kind.into();
            s.create_if_missing = true;
            let out = reconcile(&m.provider, &s, ip, false).await.unwrap();
            assert_eq!(out.status, "created");
            assert_eq!(out.record_id.as_deref(), Some("55"));
            assert_eq!(
                m.calls.lock().unwrap()[6].body,
                json!({"name":"home","type":kind,"data":ip})
            );
            credentials(&m);
        }
    }
    #[tokio::test]
    async fn selection_ambiguity_explicit_ids_and_disabled_are_safe() {
        let mut disabled = record();
        disabled["enabled"] = json!(false);
        for (records, id, code) in [
            (
                vec![record(), raw(35, "home", "A", "2.2.2.2")],
                None,
                "AmbiguousRecords",
            ),
            (vec![record()], Some("99"), "RecordIdNotFound"),
            (
                vec![raw(34, "other", "A", "1.1.1.1")],
                Some("34"),
                "RecordIdMismatch",
            ),
            (vec![disabled], None, "RecordDisabled"),
        ] {
            let m = mock(reads(records)).await;
            let mut s = spec();
            s.record_id = id.map(str::to_owned);
            s.create_if_missing = true;
            assert_eq!(
                reconcile(&m.provider, &s, "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            no_writes(&m);
        }
        let m = mock(reads(vec![record(), raw(35, "home", "A", "2.2.2.2")])).await;
        let mut s = spec();
        s.record_id = Some("35".into());
        assert_eq!(
            reconcile(&m.provider, &s, "8.8.8.8", true)
                .await
                .unwrap()
                .previous_ip
                .as_deref(),
            Some("2.2.2.2")
        );
        no_writes(&m);
    }
    #[tokio::test]
    async fn inherited_mac_expansion_and_unsafe_settings_refused_before_noop() {
        for data in ["", "@", "auto", "aa:bb:cc:dd:ee:ff", "::1234/64"] {
            let m = mock(reads(vec![raw(34, "home", "AAAA", data)])).await;
            let mut s = spec();
            s.record_type = "AAAA".into();
            assert_eq!(
                reconcile(&m.provider, &s, "2001:db8::1", true)
                    .await
                    .unwrap_err()
                    .code,
                "ManagedRecord"
            );
            no_writes(&m);
        }
        for (key, value, code) in [
            ("expandedData", json!("9.9.9.9"), "ManagedRecord"),
            ("expandedData", Value::Null, "ManagedRecord"),
            ("priority", json!(1), "UnsafeRecordSettings"),
            ("port", json!(53), "UnsafeRecordSettings"),
            ("weight", json!(1), "UnsafeRecordSettings"),
            ("flags", json!(128), "UnsafeRecordSettings"),
            ("tag", json!("issue"), "UnsafeRecordSettings"),
            ("enabled", json!(true), "UnsafeRecordSettings"),
            ("routing", json!("geo"), "UnsafeRecordSettings"),
            ("ttl", json!(60), "UnsafeRecordSettings"),
        ] {
            let mut r = record();
            r[key] = value;
            let m = mock(reads(vec![r])).await;
            assert_eq!(
                reconcile(&m.provider, &spec(), "1.1.1.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn explicit_ttl_ack_and_options_checked_before_any_reads() {
        let mut m = mock(vec![]).await;
        m.provider.options = BTreeMap::new();
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "UnsupportedTTL"
        );
        m.provider.options = options();
        m.provider
            .options
            .insert("endpoint".into(), "http://localhost".into());
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        m.provider.options = options();
        m.provider.options.insert("ttl_mode".into(), "60".into());
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "UnsupportedTTL"
        );
        m.provider.options = options();
        let mut s = spec();
        s.options.insert("anything".into(), "x".into());
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        s = spec();
        s.record_line = "geo".into();
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        for host in ["@", "bad/host", "home.", "*", "user@host"] {
            let mut s = spec();
            s.subdomain = host.into();
            assert_eq!(
                m.provider.list(&s).await.unwrap_err().code,
                if host == "@" {
                    "UnsupportedApex"
                } else {
                    "InvalidDnsName"
                }
            );
        }
        for zone in ["dynv6.net.", "http://example.net", "例子.net"] {
            let mut s = spec();
            s.domain = zone.into();
            assert_eq!(
                m.provider.list(&s).await.unwrap_err().code,
                "InvalidDnsName"
            );
        }
        for id in ["0", "01", "-1", "9223372036854775808", "1/2"] {
            let mut s = spec();
            s.record_id = Some(id.into());
            assert_eq!(
                m.provider.list(&s).await.unwrap_err().code,
                "InvalidRecordId"
            );
        }
        assert_eq!(
            m.provider.create(&spec(), "auto").await.unwrap_err().code,
            "InvalidIp"
        );
        assert_eq!(
            m.provider
                .create(&spec(), "2001:db8::1")
                .await
                .unwrap_err()
                .code,
            "IpFamilyMismatch"
        );
        assert!(m.calls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn exact_zone_not_suffix_wrong_id_and_notfound_fail_closed() {
        for (first, second, code) in [
            (json!({"id":12,"name":"dynv6.net"}), None, "ZoneMismatch"),
            (
                zone(),
                Some(json!({"id":13,"name":"example.dynv6.net"})),
                "ZoneMismatch",
            ),
            (
                json!({"id":0,"name":"example.dynv6.net"}),
                None,
                "InvalidZone",
            ),
            (
                json!({"id":12,"name":"example.dynv6.net","disabled":true}),
                None,
                "ZoneDisabled",
            ),
        ] {
            let mut replies = vec![first];
            if let Some(second) = second {
                replies.push(second);
            }
            let m = mock(replies).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            no_writes(&m);
        }
        let m = mock_raw(vec![(
            404,
            json!({"error":{"name":"NotFound","message":"zone not found"}}).to_string(),
        )])
        .await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "NotFound"
        );
        no_writes(&m);
    }
    #[tokio::test]
    async fn list_shapes_duplicates_wrong_zone_and_malformed_unrelated_records_refused() {
        for (value, code) in [
            (json!({"records":[],"nextPage":2}), "MalformedRecordList"),
            (json!([record(), record()]), "UnstableRecordList"),
            (
                json!([{"id":34,"zoneID":13,"name":"home","type":"A","data":"1.1.1.1"}]),
                "RecordZoneMismatch",
            ),
            (
                json!([{"id":35,"zoneID":12,"name":"other","type":"TXT"}]),
                "MalformedRecord",
            ),
        ] {
            let m = mock(vec![zone(), zone(), value]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn stale_preflight_and_create_race_never_write() {
        let mut changed = record();
        changed["data"] = json!("9.9.9.9");
        let mut replies = reads(vec![record()]);
        replies.extend([zone(), zone(), json!([record()]), changed]);
        let m = mock(replies).await;
        assert_eq!(
            reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordChanged"
        );
        no_writes(&m);
        for (r, code) in [
            (record(), "RecordAppeared"),
            (
                raw(35, "home", "CNAME", "target.example.net."),
                "RecordConflict",
            ),
        ] {
            let mut replies = reads(vec![]);
            replies.extend(reads(vec![r]));
            let m = mock(replies).await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                reconcile(&m.provider, &s, "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn cname_conflicts_and_new_ambiguity_stop_before_writes() {
        for dry_run in [false, true] {
            let m = mock(reads(vec![raw(35, "home", "CNAME", "target.example.net.")])).await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                reconcile(&m.provider, &s, "8.8.8.8", dry_run)
                    .await
                    .unwrap_err()
                    .code,
                "RecordConflict"
            );
            no_writes(&m);
        }
        for records in [vec![], vec![record(), raw(35, "home", "A", "2.2.2.2")]] {
            let mut replies = reads(vec![record()]);
            replies.extend(reads(records));
            let m = mock(replies).await;
            assert_eq!(
                reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "RecordChanged"
            );
            no_writes(&m);
            assert_eq!(m.calls.lock().unwrap().len(), 6);
        }
        // An explicit immutable ID still permits distinct same-name siblings.
        let mut replies = reads(vec![record()]);
        replies.extend(reads(vec![record(), raw(35, "home", "A", "2.2.2.2")]));
        replies.extend([record(), raw(34, "home", "A", "8.8.8.8")]);
        let m = mock(replies).await;
        let mut s = spec();
        s.record_id = Some("34".into());
        assert_eq!(
            reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap()
                .record_id
                .as_deref(),
            Some("34")
        );
    }
    #[tokio::test]
    async fn strict_ack_verifies_id_zone_host_type_data_and_metadata() {
        let good = raw(34, "home", "A", "8.8.8.8");
        for (key, value) in [
            ("id", json!(35)),
            ("zoneID", json!(13)),
            ("name", json!("other")),
            ("type", json!("AAAA")),
            ("data", json!("9.9.9.9")),
            ("priority", json!(0)),
            ("expandedData", json!("9.9.9.9")),
        ] {
            let mut ack = good.clone();
            ack[key] = value;
            let mut replies = reads(vec![record()]);
            replies.extend([zone(), zone(), json!([record()]), record(), ack]);
            let m = mock(replies).await;
            let e = reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "InvalidWriteAcknowledgement");
            assert_eq!(e.http_status, Some(200));
            assert_eq!(
                m.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|c| c.method == Method::PATCH)
                    .count(),
                1
            );
        }
        let mut replies = reads(vec![]);
        replies.extend(reads(vec![]));
        replies.push(json!({"id":55}));
        let m = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "InvalidWriteAcknowledgement"
        );
    }
    #[tokio::test]
    async fn sanitized_business_http_validation_errors_and_malformed_responses() {
        for status in [200, 400, 401, 403, 422, 429, 500, 503] {
            let body = json!({"error":{"name":"ValidationError","message":"Rejected dyn-token-secret","fields":[{"name":"data","message":"wrong family"},{"name":"dyn-token-secret","message":"Bearer dyn-token-secret invalid"}]}});
            let m = mock_raw(vec![(status, body.to_string())]).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "ValidationError");
            assert_eq!(e.http_status, Some(status));
            assert_eq!(e.request_id.as_deref(), Some("dyn-trace"));
            assert!(e.message.contains("wrong family"));
            assert!(!e.message.contains("dyn-token-secret"));
            assert!(!e.retryable);
            no_writes(&m);
        }
        let m = mock_raw(vec![(200, "<html>dyn-token-secret</html>".into())]).await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "MalformedResponse");
        assert!(!e.message.contains("dyn-token-secret"));
        let m = mock_raw(vec![(
            302,
            json!({"error":{"message":"redirect refused"}}).to_string(),
        )])
        .await;
        assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, "Http302");
        assert_eq!(m.calls.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn unexpected_pagination_and_reused_create_ids_are_refused() {
        let m = mock_raw(vec![
            (200, zone().to_string()),
            (200, zone().to_string()),
            (200, format!("MOCK_LINK:{}", json!([record()]))),
        ])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "IncompleteRecordList"
        );
        no_writes(&m);
        assert_eq!(m.calls.lock().unwrap().len(), 3);
        let sibling = raw(55, "other", "A", "2.2.2.2");
        let mut replies = reads(vec![sibling.clone()]);
        replies.extend(reads(vec![sibling]));
        replies.push(raw(55, "home", "A", "8.8.8.8"));
        let m = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "InvalidWriteAcknowledgement"
        );
        assert_eq!(
            m.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.method == Method::POST)
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn uncertain_write_failure_is_not_retried() {
        let mut replies = reads(vec![record()])
            .into_iter()
            .map(|v| (200, v.to_string()))
            .collect::<Vec<_>>();
        replies.extend(
            [zone(), zone(), json!([record()]), record()]
                .into_iter()
                .map(|v| (200, v.to_string())),
        );
        replies.push((
            503,
            json!({"error":{"name":"Unavailable","message":"maintenance"}}).to_string(),
        ));
        let m = mock_raw(replies).await;
        let e = reconcile(&m.provider, &spec(), "8.8.8.8", false)
            .await
            .unwrap_err();
        assert_eq!(e.code, "Unavailable");
        assert!(e.message.contains("maintenance"));
        assert!(!e.retryable);
        assert_eq!(m.calls.lock().unwrap().len(), 8);
    }
}
