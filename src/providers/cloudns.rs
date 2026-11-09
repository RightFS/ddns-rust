//! ClouDNS HTTP API: https://www.cloudns.net/wiki/article/41/.
//! Uses official SDK's add-record/record-type and mod-record/record-id,
//! NOT the legacy ddns-go modify-record endpoint. POST forms keep auth off URLs.
//! Only ordinary master zones and static records; GeoDNS/failover refused.
//! No atomic CAS: pre-write reread detects stale selection, use one writer.
#[cfg(test)]
use super::common;
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
const ENDPOINT: &str = "https://api.cloudns.net/dns";
const PAGE_SIZE: usize = 100;
pub struct Cloudns {
    api: Api,
    id: String,
    key: String,
    auth_field: String,
    valid_options: bool,
    #[cfg(test)]
    endpoint: String,
}
impl Cloudns {
    pub fn new(
        client: reqwest::Client,
        id: String,
        key: String,
        options: &BTreeMap<String, String>,
    ) -> Self {
        let auth_field = options
            .get("auth_type")
            .map(String::as_str)
            .unwrap_or("auth-id");
        Self {
            api: Api::new(
                client,
                vec![
                    form_encoded(&id),
                    form_encoded(&key),
                    id.clone(),
                    key.clone(),
                ],
            ),
            id,
            key,
            auth_field: auth_field.into(),
            valid_options: options.keys().all(|k| k == "auth_type")
                && matches!(auth_field, "auth-id" | "sub-auth-id" | "sub-auth-user"),
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
            "Verify the exact ClouDNS master zone, API user/sub-user access and available TTL. No write is retried; inspect uncertain results before retrying.", reply)
    }
    fn validate(&self, spec: &Spec) -> Result<(), ProviderError> {
        if !self.valid_options {
            return Err(self.error("validation", "UnsupportedOptions", "ClouDNS auth_type must be auth-id, sub-auth-id or sub-auth-user; no endpoint override is allowed.", None));
        }
        if self.id.trim().is_empty()
            || self.key.trim().is_empty()
            || (self.auth_field != "sub-auth-user"
                && decimal(Some(&Value::String(self.id.clone()))).is_none())
        {
            return Err(self.error(
                "credentials",
                "InvalidCredentials",
                "ClouDNS requires a positive API user ID (or sub-user name) and API password.",
                None,
            ));
        }
        if !hostname(&spec.domain)
            || !spec.domain.contains('.')
            || (spec.subdomain != "@" && !hostname(&spec.subdomain))
            || !matches!(spec.record_type.as_str(), "A" | "AAAA")
        {
            return Err(self.error(
                "validation",
                "InvalidTarget",
                "Use an exact ASCII/punycode zone, plain host or @, and A/AAAA.",
                None,
            ));
        }
        if !spec.options.is_empty() || !matches!(spec.record_line.as_str(), "默认" | "default") {
            return Err(self.error(
                "validation",
                "UnsupportedOptions",
                "ClouDNS currently supports only static default-location A/AAAA records.",
                None,
            ));
        }
        if spec.ttl == 0 || spec.ttl > 604800 {
            return Err(self.error("validation", "UnsupportedTTL", "TTL must be positive and within the application's 604800-second limit; exact allowed TTLs are read from ClouDNS.", None));
        }
        if spec
            .record_id
            .as_ref()
            .is_some_and(|s| decimal(Some(&Value::String(s.clone()))).is_none())
        {
            return Err(self.error(
                "validation",
                "InvalidRecordId",
                "ClouDNS record IDs must be positive decimal integers.",
                None,
            ));
        }
        Ok(())
    }
    fn ip(&self, spec: &Spec, ip: &str) -> Result<String, ProviderError> {
        self.validate(spec)?;
        let value = ip.parse::<std::net::IpAddr>().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be a plain IP address.",
                None,
            )
        })?;
        if value.is_ipv4() != (spec.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "IP family does not match A/AAAA.",
                None,
            ));
        }
        Ok(value.to_string())
    }
    async fn call(
        &self,
        action: &str,
        spec: &Spec,
        mut params: BTreeMap<String, String>,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        params.insert(self.auth_field.clone(), self.id.clone());
        params.insert("auth-password".into(), self.key.clone());
        params.insert("domain-name".into(), spec.domain.clone());
        #[cfg(test)]
        let endpoint = &self.endpoint;
        #[cfg(not(test))]
        let endpoint = ENDPOINT;
        let reply = self
            .api
            .send(
                action,
                self.api
                    .client
                    .post(format!("{endpoint}/{action}.json"))
                    .form(&params),
                write,
            )
            .await?;
        if let Some(status) = reply.body.get("status").and_then(Value::as_str)
            && !matches!(status, "0" | "1")
            && status != "Success"
        {
            let description = reply
                .body
                .get("statusDescription")
                .and_then(Value::as_str)
                .unwrap_or("ClouDNS returned an unrecognized business status.");
            return Err(self.error(action, "CloudnsApiError", description, Some(&reply)));
        }
        self.api.check_http(action, &reply)?;
        if write && reply.body.get("status").and_then(Value::as_str) != Some("Success") {
            return Err(self.error(
                action,
                "InvalidWriteAcknowledgement",
                "ClouDNS write lacks explicit status Success; inspect the uncertain write.",
                Some(&reply),
            ));
        }
        Ok(reply)
    }
    async fn count(
        &self,
        action: &str,
        spec: &Spec,
        params: BTreeMap<String, String>,
    ) -> Result<usize, ProviderError> {
        let reply = self.call(action, spec, params, false).await?;
        integer(Some(&reply.body))
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n <= 10000)
            .ok_or_else(|| {
                self.error(
                    action,
                    "InvalidCount",
                    "ClouDNS returned an invalid count or exceeded the 10,000-item limit.",
                    Some(&reply),
                )
            })
    }
    async fn verify_zone(&self, spec: &Spec) -> Result<(), ProviderError> {
        let base = params(&[("rows-per-page", "100"), ("search", &spec.domain)]);
        let pages = self.count("get-pages-count", spec, base.clone()).await?;
        if pages > 100 {
            return Err(self.error(
                "ownership",
                "PageLimit",
                "ClouDNS zone discovery exceeded 100 pages.",
                None,
            ));
        }
        let mut seen = HashSet::new();
        let mut matched = false;
        for page in 1..=pages {
            let mut p = base.clone();
            p.insert("page".into(), page.to_string());
            let reply = self.call("list-zones", spec, p, false).await?;
            let rows = reply.body.as_array().ok_or_else(|| {
                self.error(
                    "ownership",
                    "MalformedZoneList",
                    "ClouDNS zone list must be an array.",
                    Some(&reply),
                )
            })?;
            if rows.is_empty()
                || rows.len() > PAGE_SIZE
                || (page < pages && rows.len() != PAGE_SIZE)
            {
                return Err(self.error(
                    "ownership",
                    "IncompleteZoneList",
                    "ClouDNS zone page is incomplete or oversized.",
                    Some(&reply),
                ));
            }
            for row in rows {
                let name = row
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|s| hostname(s))
                    .ok_or_else(|| {
                        self.error(
                            "ownership",
                            "MalformedZone",
                            "Zone name is missing or malformed.",
                            Some(&reply),
                        )
                    })?;
                if !seen.insert(name.to_ascii_lowercase()) {
                    return Err(self.error(
                        "ownership",
                        "UnstableZoneList",
                        "Repeated zones across ClouDNS pages.",
                        Some(&reply),
                    ));
                }
                if name.eq_ignore_ascii_case(&spec.domain) {
                    if row.get("type").and_then(Value::as_str) != Some("master") {
                        return Err(self.error("ownership", "UnsupportedZone", "Only ordinary master zones are supported; slave, parked, cloud and GeoDNS zones are refused.", Some(&reply)));
                    }
                    matched = true;
                }
            }
        }
        if self.count("get-pages-count", spec, base).await? != pages {
            return Err(self.error(
                "ownership",
                "UnstableZoneList",
                "Zone pagination changed during discovery.",
                None,
            ));
        }
        if !matched {
            return Err(self.error(
                "ownership",
                "ZoneNotFound",
                "Exact zone was not found in authenticated ClouDNS discovery.",
                None,
            ));
        }
        let reply = self
            .call("get-zone-info", spec, BTreeMap::new(), false)
            .await?;
        if flag(reply.body.get("status")) != Some(true) {
            return Err(self.error(
                "ownership",
                "ZoneDisabled",
                "ClouDNS zone activity is disabled or cannot be verified from status.",
                Some(&reply),
            ));
        }
        for field in ["name", "domain", "domain-name"] {
            if let Some(name) = reply.body.get(field)
                && name
                    .as_str()
                    .is_none_or(|n| !n.eq_ignore_ascii_case(&spec.domain))
            {
                return Err(self.error(
                    "ownership",
                    "ZoneMismatch",
                    "Zone information contradicts the exact discovered zone.",
                    Some(&reply),
                ));
            }
        }
        if reply
            .body
            .get("type")
            .is_some_and(|v| v.as_str() != Some("master"))
        {
            return Err(self.error(
                "ownership",
                "UnsupportedZone",
                "Zone information is not an ordinary master zone.",
                Some(&reply),
            ));
        }
        let ttl_reply = self
            .call("get-available-ttl", spec, BTreeMap::new(), false)
            .await?;
        // API returns an object mapping seconds to labels (or an array of seconds).
        let allowed = if let Some(map) = ttl_reply.body.as_object() {
            !map.is_empty()
                && map.keys().all(|s| s.parse::<u64>().is_ok_and(|n| n > 0))
                && map.contains_key(&spec.ttl.to_string())
        } else if let Some(rows) = ttl_reply.body.as_array() {
            !rows.is_empty()
                && rows.iter().all(|v| integer(Some(v)).is_some_and(|n| n > 0))
                && rows.iter().any(|v| integer(Some(v)) == Some(spec.ttl))
        } else {
            false
        };
        if !allowed {
            return Err(self.error("validation", "UnsupportedTTL", "Desired TTL is absent from ClouDNS available TTLs or the TTL response is malformed.", Some(&ttl_reply)));
        }
        Ok(())
    }
    fn parse_record(
        &self,
        key: &str,
        raw: &Value,
        reply: &HttpReply,
    ) -> Result<Record, ProviderError> {
        let bad = |field: &str| {
            self.error(
                "records",
                "MalformedRecord",
                &format!("ClouDNS record has a missing, contradictory or malformed {field}."),
                Some(reply),
            )
        };
        let id = decimal(raw.get("id"))
            .filter(|id| id == key)
            .ok_or_else(|| bad("id"))?;
        let host = raw
            .get("host")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("host"))?;
        let name = if host.is_empty() { "@" } else { host };
        let record_type = raw
            .get("type")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| bad("type"))?;
        let value = raw
            .get("record")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("record"))?;
        let ttl = integer(raw.get("ttl"))
            .filter(|n| *n > 0)
            .ok_or_else(|| bad("ttl"))?;
        let enabled = match raw.get("status") {
            None => false,
            Some(v) => flag(Some(v)).ok_or_else(|| bad("status"))?,
        };
        Ok(Record {
            id,
            name: name.into(),
            record_type: record_type.into(),
            value: value.into(),
            ttl,
            line: String::new(),
            enabled,
            extra: raw.clone(),
        })
    }
    fn static_record(&self, record: &Record) -> Result<(), ProviderError> {
        if flag(record.extra.get("status")).is_none() {
            return Err(self.error("selection", "UnknownRecordState", "Selected ClouDNS record lacks a verifiable status flag; it will not be treated as enabled.", None));
        }
        if [
            "geodns-location",
            "geodns-code",
            "geodns-location-code",
            "location",
            "failover",
        ]
        .iter()
        .any(|f| record.extra.get(*f).is_some_and(|v| !inactive(v)))
        {
            return Err(self.error("selection", "ManagedRecord", "GeoDNS and failover-controlled ClouDNS records are refused, including in read-only diagnosis.", None));
        }
        Ok(())
    }
    async fn read_records(&self, spec: &Spec) -> Result<List, ProviderError> {
        let total = self
            .count("get-records-count", spec, BTreeMap::new())
            .await?;
        let pages = total.div_ceil(PAGE_SIZE);
        let base = params(&[("rows-per-page", "100"), ("include-notes", "1")]);
        let count_base = params(&[("rows-per-page", "100")]);
        let announced = self
            .count("get-records-pages-count", spec, count_base.clone())
            .await?;
        if announced != pages && !(total == 0 && announced == 1) {
            return Err(self.error(
                "records",
                "IncompleteRecordList",
                "Record count contradicts ClouDNS page count.",
                None,
            ));
        }
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let mut request_id = None;
        // Even zero-count zones must confirm the empty records response.
        for page in 1..=pages.max(1) {
            let mut p = base.clone();
            p.insert("page".into(), page.to_string());
            let reply = self.call("records", spec, p, false).await?;
            let rows = if reply.body.as_array().is_some_and(Vec::is_empty) {
                None
            } else {
                Some(reply.body.as_object().ok_or_else(|| {
                    self.error(
                        "records",
                        "MalformedRecordList",
                        "ClouDNS records must be an ID-keyed object or an empty array.",
                        Some(&reply),
                    )
                })?)
            };
            let length = rows.map_or(0, |m| m.len());
            let expected = total.saturating_sub((page - 1) * PAGE_SIZE).min(PAGE_SIZE);
            if length != expected {
                return Err(self.error(
                    "records",
                    "IncompleteRecordList",
                    "ClouDNS record page length contradicts the complete count.",
                    Some(&reply),
                ));
            }
            if let Some(rows) = rows {
                for (id, raw) in rows {
                    if !seen.insert(id.clone()) {
                        return Err(self.error(
                            "records",
                            "UnstableRecordList",
                            "Repeated ClouDNS record ID across pages.",
                            Some(&reply),
                        ));
                    }
                    records.push(self.parse_record(id, raw, &reply)?);
                }
            }
            request_id = reply.request_id;
        }
        if self
            .count("get-records-count", spec, BTreeMap::new())
            .await?
            != total
            || self
                .count("get-records-pages-count", spec, count_base)
                .await?
                != announced
        {
            return Err(self.error(
                "records",
                "UnstableRecordList",
                "ClouDNS record totals changed while reading pages.",
                None,
            ));
        }
        Ok(List {
            records,
            request_id,
        })
    }
    fn check_target(&self, spec: &Spec, record: &Record) -> Result<(), ProviderError> {
        self.static_record(record)?;
        if !record.enabled
            || record.record_type != spec.record_type
            || !self.name_format().matches(&record.name, spec)
        {
            return Err(self.error(
                "update",
                "InvalidSelectedRecord",
                "ClouDNS update requires the exact enabled static A/AAAA target.",
                None,
            ));
        }
        Ok(())
    }
}
impl Adapter for Cloudns {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Relative
    }
    fn validate_selection(
        &self,
        spec: &Spec,
        record: Option<&Record>,
    ) -> Result<(), ProviderError> {
        self.validate(spec)?;
        if let Some(record) = record {
            self.static_record(record)?;
        }
        Ok(())
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        self.validate(spec)?;
        self.verify_zone(spec).await?;
        self.read_records(spec).await
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.ip(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error(
                "create",
                "CreationNotAllowed",
                "Creation requires explicit opt-in and no explicit record ID.",
                None,
            ));
        }
        let fresh = self.list(spec).await?;
        if fresh.records.iter().any(|r| {
            self.name_format().matches(&r.name, spec)
                && (r.record_type == spec.record_type
                    || matches!(r.record_type.as_str(), "CNAME" | "ALIAS"))
        }) {
            return Err(self.error("create", "CreateConflict", "A record appeared at the requested host before creation; inspect the zone instead of adding blindly.", None));
        }
        let host = if spec.subdomain == "@" {
            ""
        } else {
            &spec.subdomain
        };
        let reply = self
            .call(
                "add-record",
                spec,
                params(&[
                    ("record-type", &spec.record_type),
                    ("host", host),
                    ("record", &ip),
                    ("ttl", &spec.ttl.to_string()),
                ]),
                true,
            )
            .await?;
        let id = decimal(reply.body.pointer("/data/id")).ok_or_else(|| {
            self.error(
                "add-record",
                "InvalidWriteAcknowledgement",
                "Official ClouDNS data.id is missing or invalid; inspect the uncertain write.",
                Some(&reply),
            )
        })?;
        Ok(Mutation {
            record_id: id,
            request_id: reply.request_id,
        })
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let ip = self.ip(spec, ip)?;
        self.check_target(spec, record)?;
        // Re-read the entire list: also checks metadata, enabled status and ownership.
        let fresh = self.list(spec).await?;
        let r = fresh
            .records
            .iter()
            .find(|r| r.id == record.id)
            .ok_or_else(|| {
                self.error(
                    "update",
                    "StaleRecord",
                    "Selected ClouDNS record disappeared before update.",
                    None,
                )
            })?;
        self.check_target(spec, r)?;
        if r.extra != record.extra {
            return Err(self.error(
                "update",
                "StaleRecord",
                "ClouDNS target changed since selection; no write was made.",
                None,
            ));
        }
        let host = r
            .extra
            .get("host")
            .and_then(Value::as_str)
            .expect("parsed host");
        let reply = self
            .call(
                "mod-record",
                spec,
                params(&[
                    ("record-id", &r.id),
                    ("host", host),
                    ("record", &ip),
                    ("ttl", &spec.ttl.to_string()),
                ]),
                true,
            )
            .await?;
        for ack in [reply.body.get("id"), reply.body.pointer("/data/id")] {
            if let Some(ack) = ack
                && decimal(Some(ack)).as_deref() != Some(&r.id)
            {
                return Err(self.error(
                    "mod-record",
                    "UnexpectedRecordId",
                    "ClouDNS acknowledgement contradicts the requested record ID.",
                    Some(&reply),
                ));
            }
        }
        // mod-record BasicResponse documents status Success without an ID.
        Ok(Mutation {
            record_id: r.id.clone(),
            request_id: reply.request_id,
        })
    }
}
fn form_encoded(value: &str) -> String {
    let mut url = reqwest::Url::parse("https://redaction.invalid/").expect("static URL");
    url.query_pairs_mut().append_pair("value", value);
    url.query()
        .expect("encoded query")
        .strip_prefix("value=")
        .expect("static key")
        .to_owned()
}
fn params(fields: &[(&str, &str)]) -> BTreeMap<String, String> {
    fields
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}
fn integer(v: Option<&Value>) -> Option<u64> {
    match v? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()
        }
        _ => None,
    }
}
fn decimal(v: Option<&Value>) -> Option<String> {
    integer(v).filter(|n| *n > 0).map(|n| n.to_string())
}
fn flag(v: Option<&Value>) -> Option<bool> {
    match v? {
        Value::Bool(b) => Some(*b),
        v => integer(Some(v)).and_then(|n| match n {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }),
    }
}
fn inactive(v: &Value) -> bool {
    v.is_null() || v.as_str() == Some("") || flag(Some(v)) == Some(false)
}
fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::{Form, State},
        http::{StatusCode, Uri},
        routing::post,
    };
    use serde_json::json;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    type Captures = Arc<Mutex<Vec<(String, BTreeMap<String, String>)>>>;
    #[derive(Clone)]
    struct StateData {
        replies: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
        calls: Captures,
    }
    struct Mock {
        provider: Cloudns,
        calls: Captures,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(
        State(s): State<StateData>,
        uri: Uri,
        Form(body): Form<BTreeMap<String, String>>,
    ) -> (StatusCode, String) {
        s.calls.lock().unwrap().push((uri.to_string(), body));
        s.replies.lock().unwrap().pop_front().unwrap_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"status":"Failed","statusDescription":"Unexpected request"}).to_string(),
        ))
    }
    async fn mock_raw(replies: Vec<(StatusCode, String)>) -> Mock {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let state = StateData {
            replies: Arc::new(Mutex::new(replies.into())),
            calls: calls.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/dns", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/{*path}", post(handler))
            .with_state(state);
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut provider = Cloudns::new(
            client,
            "731942".into(),
            "test-password-secret".into(),
            &BTreeMap::new(),
        );
        provider.endpoint = endpoint;
        Mock {
            provider,
            calls,
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
            ttl: 300,
            record_id: None,
            create_if_missing: false,
            options: BTreeMap::new(),
        }
    }
    fn row(id: &str, host: &str) -> Value {
        json!({"id":id,"host":host,"type":"A","record":"1.1.1.1","ttl":"300","status":"1","failover":"0","note":"keep note"})
    }
    fn ownership() -> Vec<Value> {
        vec![
            json!(1),
            json!([{"name":"example.com","type":"master"}]),
            json!(1),
            json!({"name":"example.com","type":"master","status":"1"}),
            json!({"60":"1 minute","300":"5 minutes","3600":"1 hour"}),
        ]
    }
    fn reads(rows: Vec<Value>) -> Vec<Value> {
        let count = rows.len();
        let pages = count.div_ceil(100);
        let mut replies = ownership();
        replies.push(json!(count));
        replies.push(json!(pages));
        if count == 0 {
            replies.push(json!({}));
        }
        for chunk in rows.chunks(100) {
            let mut map = serde_json::Map::new();
            for r in chunk {
                map.insert(r["id"].as_str().unwrap().into(), r.clone());
            }
            replies.push(Value::Object(map));
        }
        replies.push(json!(count));
        replies.push(json!(pages));
        replies
    }
    fn assert_read_only(calls: &[(String, BTreeMap<String, String>)]) {
        assert!(
            calls
                .iter()
                .all(|(u, _)| !u.contains("add-record") && !u.contains("mod-record"))
        );
    }
    #[tokio::test]
    async fn dryrun_noop_update_create_are_read_only() {
        for (rows, ip, status) in [
            (vec![row("101", "home")], "1.1.1.1", "unchanged"),
            (vec![row("101", "home")], "8.8.8.8", "would_update"),
            (vec![], "8.8.8.8", "would_create"),
        ] {
            let m = mock(reads(rows)).await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, ip, true)
                    .await
                    .unwrap()
                    .status,
                status
            );
            let calls = m.calls.lock().unwrap();
            assert_read_only(&calls);
            for (uri, p) in calls.iter() {
                assert!(!uri.contains('?'));
                assert!(!uri.contains("secret"));
                assert_eq!(p["auth-id"], "731942");
                assert_eq!(p["auth-password"], "test-password-secret");
            }
        }
    }
    #[tokio::test]
    async fn update_uses_official_mod_record_and_preserves_settings() {
        let mut replies = reads(vec![row("101", "home")]);
        replies.extend(reads(vec![row("101", "home")]));
        replies.push(json!({"status":"Success"}));
        let m = mock(replies).await;
        let out = common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(out.status, "updated");
        assert_eq!(out.record_id.as_deref(), Some("101"));
        let calls = m.calls.lock().unwrap();
        let (u, p) = calls.last().unwrap();
        assert_eq!(u, "/dns/mod-record.json");
        assert_eq!(p["record-id"], "101");
        assert_eq!(p["host"], "home");
        assert_eq!(p["record"], "8.8.8.8");
        assert_eq!(p.len(), 7);
        assert!(!p.contains_key("status"));
        assert!(!p.contains_key("note"));
        assert!(!p.contains_key("failover"));
    }
    #[tokio::test]
    async fn create_uses_official_record_type_and_data_id() {
        let mut replies = reads(vec![]);
        replies.extend(reads(vec![]));
        replies.push(json!({"status":"Success","data":{"id":102}}));
        let m = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        s.subdomain = "@".into();
        s.record_type = "AAAA".into();
        let out = common::reconcile(&m.provider, &s, "2606:4700:4700::1111", false)
            .await
            .unwrap();
        assert_eq!(out.record_id.as_deref(), Some("102"));
        let calls = m.calls.lock().unwrap();
        let (u, p) = calls.last().unwrap();
        assert_eq!(u, "/dns/add-record.json");
        assert_eq!(p["record-type"], "AAAA");
        assert_eq!(p["host"], "");
        assert!(!p.contains_key("type"));
    }
    #[tokio::test]
    async fn complete_pagination_finds_later_duplicate_target() {
        let mut rows: Vec<_> = (1..=100)
            .map(|i| row(&i.to_string(), &format!("unrelated{i}")))
            .collect();
        rows[0] = row("1", "home");
        rows.push(row("101", "home"));
        let m = mock(reads(rows)).await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "8.8.8.8", true)
                .await
                .unwrap_err()
                .code,
            "AmbiguousRecords"
        );
        let calls = m.calls.lock().unwrap();
        let pages: Vec<_> = calls
            .iter()
            .filter(|(u, _)| u.ends_with("/records.json"))
            .collect();
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[1].1["page"], "2");
        assert_eq!(pages[1].1["include-notes"], "1");
        assert_read_only(&calls);
    }
    #[tokio::test]
    async fn explicit_wrong_missing_disabled_and_ambiguous_never_write() {
        for (rows, id, code) in [
            (
                vec![row("101", "elsewhere")],
                Some("101"),
                "RecordIdMismatch",
            ),
            (vec![row("101", "home")], Some("102"), "RecordIdNotFound"),
            (
                vec![row("101", "home"), row("102", "home")],
                None,
                "AmbiguousRecords",
            ),
            (
                vec![{
                    let mut r = row("101", "home");
                    r["status"] = json!(0);
                    r
                }],
                None,
                "RecordDisabled",
            ),
        ] {
            let m = mock(reads(rows)).await;
            let mut s = spec();
            s.record_id = id.map(str::to_owned);
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_read_only(&m.calls.lock().unwrap());
        }
    }
    #[tokio::test]
    async fn failover_and_geodns_are_not_modified_even_with_explicit_id() {
        for f in ["failover", "geodns-location", "geodns-code"] {
            let mut r = row("101", "home");
            r[f] = json!("7");
            let m = mock(reads(vec![r])).await;
            let mut s = spec();
            s.record_id = Some("101".into());
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap_err()
                    .code,
                "ManagedRecord"
            );
            assert_read_only(&m.calls.lock().unwrap());
        }
    }
    #[tokio::test]
    async fn stale_target_rejects_write() {
        for f in ["record", "ttl", "note", "host", "status", "failover"] {
            let mut r = row("101", "home");
            r[f] = match f {
                "record" => json!("8.8.4.4"),
                "ttl" => json!(3600),
                "host" => json!("other"),
                "status" => json!(0),
                "failover" => json!(1),
                _ => json!("changed"),
            };
            let mut replies = reads(vec![row("101", "home")]);
            replies.extend(reads(vec![r]));
            let m = mock(replies).await;
            assert!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .is_err()
            );
            assert_read_only(&m.calls.lock().unwrap());
        }
    }
    #[tokio::test]
    async fn create_race_never_adds() {
        let mut replies = reads(vec![]);
        replies.extend(reads(vec![row("101", "home")]));
        let m = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "CreateConflict"
        );
        assert_read_only(&m.calls.lock().unwrap());
    }
    #[tokio::test]
    async fn exact_zone_and_zone_types_are_required() {
        for (name, kind, code) in [
            ("other.example.com", "master", "ZoneNotFound"),
            ("example.com", "slave", "UnsupportedZone"),
            ("example.com", "geodns", "UnsupportedZone"),
            ("example.com", "parked", "UnsupportedZone"),
        ] {
            let m = mock(vec![json!(1), json!([{"name":name,"type":kind}]), json!(1)]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            assert_read_only(&m.calls.lock().unwrap());
        }
    }
    #[tokio::test]
    async fn zone_disabled_or_unprovable_refuses_records() {
        for v in [json!(0), json!("unknown"), Value::Null] {
            let mut replies = ownership();
            replies[3]["status"] = v;
            let m = mock(replies).await;
            assert!(m.provider.list(&spec()).await.is_err());
            assert!(
                !m.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(u, _)| u.ends_with("/records.json"))
            );
        }
    }
    #[tokio::test]
    async fn exact_available_ttl_is_checked_during_diagnosis() {
        for allowed in [json!({"3600":"1 hour"}), json!([3600]), json!({"bad":300})] {
            let mut replies = ownership();
            replies[4] = allowed;
            let m = mock(replies).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "UnsupportedTTL"
            );
            assert_read_only(&m.calls.lock().unwrap());
        }
    }
    #[tokio::test]
    async fn malformed_count_short_page_and_changed_count_fail_closed() {
        for (idx, value, code) in [
            (5, json!(1.5), "InvalidCount"),
            (5, json!(10001), "InvalidCount"),
            (6, json!(2), "IncompleteRecordList"),
            (7, json!({}), "IncompleteRecordList"),
            (8, json!(2), "UnstableRecordList"),
        ] {
            let mut replies = reads(vec![row("101", "home")]);
            replies[idx] = value;
            let m = mock(replies).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            assert_read_only(&m.calls.lock().unwrap());
        }
    }
    #[tokio::test]
    async fn repeated_ids_across_pages_fail_closed() {
        let rows: Vec<_> = (1..=101)
            .map(|i| row(&i.to_string(), &format!("h{i}")))
            .collect();
        let mut replies = reads(rows);
        replies[8] = json!({"1":row("1","h1")});
        let m = mock(replies).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "UnstableRecordList"
        );
    }
    #[tokio::test]
    async fn malformed_record_names_exact_fields() {
        for f in ["id", "host", "type", "record", "ttl", "status"] {
            let mut r = row("101", "home");
            r[f] = Value::Null;
            let mut replies = reads(vec![row("101", "home")]);
            replies[7] = json!({"101":r});
            let m = mock(replies).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "MalformedRecord");
            assert!(e.message.contains(f));
        }
    }
    #[tokio::test]
    async fn business_errors_preserve_http_context_without_secrets() {
        for status in [StatusCode::OK, StatusCode::FORBIDDEN] {
            let m=mock_raw(vec![(status,json!({"status":"Failed","statusDescription":"Zone access denied for 731942 test-password-secret","requestId":"read-trace"}).to_string())]).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "CloudnsApiError");
            assert_eq!(e.http_status, Some(status.as_u16()));
            assert_eq!(e.request_id.as_deref(), Some("read-trace"));
            assert!(e.message.contains("Zone access denied"));
            assert!(!e.message.contains("731942"));
            assert!(!e.message.contains("test-password-secret"));
        }
    }
    #[tokio::test]
    async fn write_failure_missing_ack_wrong_id_are_uncertain_not_retried() {
        for ack in [
            json!({"status":"Failed","statusDescription":"Invalid TTL"}),
            json!({}),
            json!({"status":"Success","data":{"id":102}}),
        ] {
            let mut replies = reads(vec![row("101", "home")]);
            replies.extend(reads(vec![row("101", "home")]));
            replies.push(ack);
            let m = mock(replies).await;
            let e = common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err();
            assert!(!e.retryable);
            assert_eq!(
                m.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(u, _)| u.ends_with("/mod-record.json"))
                    .count(),
                1
            );
        }
    }
    #[tokio::test]
    async fn create_ack_requires_official_nonzero_data_id() {
        for ack in [
            json!({"status":"Success"}),
            json!({"status":"Success","id":102}),
            json!({"status":"Success","data":{"id":0}}),
        ] {
            let mut replies = reads(vec![]);
            replies.extend(reads(vec![]));
            replies.push(ack);
            let m = mock(replies).await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "InvalidWriteAcknowledgement"
            );
        }
    }
    #[tokio::test]
    async fn subuser_credentials_use_selected_field_only() {
        for kind in ["sub-auth-id", "sub-auth-user"] {
            let mut m = mock(reads(vec![row("101", "home")])).await;
            m.provider.auth_field = kind.into();
            m.provider.list(&spec()).await.unwrap();
            for (_, p) in m.calls.lock().unwrap().iter() {
                assert!(p.contains_key(kind));
                assert!(!p.contains_key("auth-id"));
            }
        }
    }
    #[tokio::test]
    async fn invalid_target_options_and_endpoint_never_requested() {
        let mut m = mock(vec![]).await;
        for field in [
            "domain",
            "subdomain",
            "record_type",
            "record_line",
            "ttl",
            "record_id",
        ] {
            let mut s = spec();
            match field {
                "domain" => s.domain = "../evil".into(),
                "subdomain" => s.subdomain = "bad/name".into(),
                "record_type" => s.record_type = "TXT".into(),
                "record_line" => s.record_line = "geo".into(),
                "ttl" => s.ttl = 0,
                _ => s.record_id = Some("abc".into()),
            };
            assert!(m.provider.list(&s).await.is_err());
        }
        m.provider.valid_options = false;
        assert!(m.provider.list(&spec()).await.is_err());
        assert!(m.calls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn missing_selected_status_is_not_assumed_active() {
        let mut r = row("101", "home");
        r.as_object_mut().unwrap().remove("status");
        let m = mock(reads(vec![r])).await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "8.8.8.8", true)
                .await
                .unwrap_err()
                .code,
            "UnknownRecordState"
        );
        assert_read_only(&m.calls.lock().unwrap());
    }
    #[tokio::test]
    async fn encoded_password_is_redacted_before_truncation() {
        let key = "password&with space=秘密";
        let encoded = form_encoded(key);
        let client = reqwest::Client::new();
        let p = Cloudns::new(client, "731942".into(), key.into(), &BTreeMap::new());
        let error = p.error(
            "list",
            "CloudnsApiError",
            &format!("Denied auth-password={encoded}"),
            None,
        );
        assert!(!error.message.contains(key));
        assert!(!error.message.contains(&encoded));
    }
    #[tokio::test]
    async fn direct_write_hooks_validate_ip_before_requests() {
        let m = mock(vec![]).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            m.provider
                .create(&s, "2606:4700:4700::1111")
                .await
                .unwrap_err()
                .code,
            "IpFamilyMismatch"
        );
        assert_eq!(
            m.provider.create(&s, "bad-ip").await.unwrap_err().code,
            "InvalidIp"
        );
        assert!(m.calls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn aaaa_creation_can_coexist_with_a() {
        let replies = {
            let mut replies = reads(vec![row("101", "home")]);
            replies.extend(reads(vec![row("101", "home")]));
            replies.push(json!({"status":"Success","data":{"id":102}}));
            replies
        };
        let m = mock(replies).await;
        let mut s = spec();
        s.record_type = "AAAA".into();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "2606:4700:4700::1111", false)
                .await
                .unwrap()
                .status,
            "created"
        );
    }
    #[tokio::test]
    async fn malformed_json_404_and_204_not_empty_success() {
        for (status, body) in [
            (StatusCode::OK, "<html>bad</html>"),
            (StatusCode::NOT_FOUND, "{}"),
            (StatusCode::NO_CONTENT, ""),
        ] {
            let m = mock_raw(vec![(status, body.into())]).await;
            assert!(m.provider.list(&spec()).await.is_err());
            assert_read_only(&m.calls.lock().unwrap());
        }
    }
    #[tokio::test]
    async fn relative_suffix_shadow_never_selects_or_writes_wrong_owner() {
        for explicit in [false, true] {
            for (ip, dry) in [("1.1.1.1", false), ("8.8.8.8", true), ("8.8.8.8", false)] {
                let m = mock(reads(vec![row("101", "home.example.com")])).await;
                let mut s = spec();
                if explicit {
                    s.record_id = Some("101".into());
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
                assert_read_only(&m.calls.lock().unwrap());
            }
        }
    }
    #[tokio::test]
    async fn relative_collision_updates_only_real_id_and_preserves_dotted_host() {
        for host in ["home", "home.example.com", "example.com"] {
            let mut s = spec();
            s.subdomain = host.into();
            let rows = vec![row("101", &s.fqdn()), row("102", host)];
            let mut replies = reads(rows.clone());
            replies.extend(reads(rows));
            replies.push(json!({"status":"Success"}));
            let m = mock(replies).await;
            let out = common::reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap();
            assert_eq!(out.record_id.as_deref(), Some("102"));
            let calls = m.calls.lock().unwrap();
            let writes: Vec<_> = calls
                .iter()
                .filter(|r| r.0.contains("mod-record"))
                .collect();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].1["record-id"], "102");
            assert_eq!(writes[0].1["host"], host);
        }
    }
    #[tokio::test]
    async fn relative_shadow_does_not_cause_false_create_conflict() {
        let rows = vec![row("101", "home.example.com")];
        let mut replies = reads(rows.clone());
        replies.extend(reads(rows));
        replies.push(json!({"status":"Success","data":{"id":102}}));
        let m = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap()
                .status,
            "created"
        );
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls.last().unwrap().1["host"], "home");
    }
}
