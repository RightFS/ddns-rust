//! Rainyun v2 official schemas (empty response schemas):
//! https://s.apifox.cn/a4595cc8-44c5-4678-a2a3-eed7738dab03/api-153559362.md
//! and api-153559361.md, api-175421754.md, api-175427268.md on that site.
//! Actual response fields and TTL choices crosschecked with official clients
//! https://app.rainyun.com/js/6487.1b3a89de.js and
//! https://app.rainyun.com/js/8483.0009fb0b.js (2026-11-09), plus ddns-go.
//! Required provider option domain_id is a numeric domain product ID.
//! Parent must disable redirects. No production endpoint override. Every write
//! gets a full verification read; no automatic write retry. Product-bound,
//! paused and unknown-state targets are refused. No compare-and-swap API exists.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
const ENDPOINT: &str = "https://api.v2.rainyun.com";
const PAGE_SIZE: usize = 100;
const RECORD_LIMIT: usize = 10000;
const TTLS: &[u64] = &[60, 300, 600, 900, 1800, 3600, 7200, 14400, 28800];
const LINES: &[&str] = &["DEFAULT", "LTEL", "LCNC", "LMOB", "LEDU", "LSEO", "LFOR"];
// Deliberately not Debug: token is secret.
pub struct Rainyun {
    api: Api,
    token: String,
    domain_id: String,
    options_valid: bool,
    #[cfg(test)]
    endpoint: String,
}
impl Rainyun {
    pub fn new(client: reqwest::Client, token: String, options: &BTreeMap<String, String>) -> Self {
        Self {
            api: Api::new(client, vec![token.clone()]),
            token,
            domain_id: options.get("domain_id").cloned().unwrap_or_default(),
            options_valid: options.keys().all(|k| k == "domain_id"),
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
            "Verify Rainyun token, numeric domain_id, exact domain, default authoritative nameservers and API schema. Inspect uncertain writes before retrying; no write is automatically retried.", reply)
    }
    fn validate(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.token.is_empty() || !self.token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(self.error(
                "validation",
                "InvalidCredentials",
                "Rainyun requires a nonempty x-api-key token without control characters.",
                None,
            ));
        }
        if !self.options_valid
            || decimal(&json!(self.domain_id)).is_none()
            || !spec.options.is_empty()
        {
            return Err(self.error("validation", "UnsupportedOptions", "Rainyun requires only provider option domain_id (canonical positive decimal integer); record options and endpoint overrides are unsupported.", None));
        }
        if !hostname(&spec.domain)
            || !spec.domain.contains('.')
            || (spec.subdomain != "@" && !hostname(&spec.subdomain))
            || spec.fqdn().len() > 253
        {
            return Err(self.error("validation", "InvalidZoneName", "Use an exact ASCII/punycode domain and relative host (or @), without paths or underscores.", None));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Only A and AAAA are supported.",
                None,
            ));
        }
        if !TTLS.contains(&spec.ttl) {
            return Err(self.error("validation", "UnsupportedTTL", "Rainyun official client supports TTL 60,300,600,900,1800,3600,7200,14400,28800; no TTL is clamped or defaulted (including dry-run).", None));
        }
        if !LINES.contains(&line(&spec.record_line)) {
            return Err(self.error(
                "validation",
                "InvalidRecordLine",
                "Use default/默认/DEFAULT or exact Rainyun line LTEL,LCNC,LMOB,LEDU,LSEO,LFOR.",
                None,
            ));
        }
        Ok(())
    }
    fn request(&self, method: reqwest::Method, suffix: &str) -> reqwest::RequestBuilder {
        #[cfg(test)]
        let endpoint = &self.endpoint;
        #[cfg(not(test))]
        let endpoint = ENDPOINT;
        let mut key =
            reqwest::header::HeaderValue::from_str(&self.token).expect("validated ASCII API key");
        key.set_sensitive(true);
        self.api
            .client
            .request(
                method,
                format!("{endpoint}/product/domain/{}{suffix}", self.domain_id),
            )
            .header("x-api-key", key)
    }
    async fn call(
        &self,
        stage: &str,
        request: reqwest::RequestBuilder,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let reply = self.api.send(stage, request, write).await?;
        if let Some(code) = reply.body.get("code").and_then(Value::as_i64)
            && code != 200
        {
            let msg = reply
                .body
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Rainyun business error without a string message.");
            return Err(self.error(stage, &format!("Rainyun{code}"), msg, Some(&reply)));
        }
        if !(200..300).contains(&reply.status) {
            let message = reply
                .body
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Rainyun returned an unsuccessful HTTP status.");
            return Err(self.error(
                stage,
                &format!("Http{}", reply.status),
                message,
                Some(&reply),
            ));
        }
        if reply.body.get("code").and_then(Value::as_i64) != Some(200)
            || reply.body.get("data").is_none()
        {
            return Err(self.error(
                stage,
                "InvalidEnvelope",
                "Rainyun response requires integer code 200 and explicit data; raw body omitted.",
                Some(&reply),
            ));
        }
        Ok(reply)
    }
    async fn ownership(&self, spec: &Spec) -> Result<(), ProviderError> {
        let reply = self
            .call("ownership", self.request(reqwest::Method::GET, ""), false)
            .await?;
        let detail = &reply.body["data"]["Data"];
        if decimal(&detail["id"]).as_deref() != Some(self.domain_id.as_str())
            || !detail["domain"]
                .as_str()
                .is_some_and(|s| s.trim_end_matches('.').eq_ignore_ascii_case(&spec.domain))
        {
            return Err(self.error("ownership", "ZoneMismatch", "Rainyun data.Data.id/domain is missing or differs from the exact configured product ID/domain.", Some(&reply)));
        }
        if detail["is_default_nameservers"].as_bool() != Some(true) {
            return Err(self.error("ownership", "NonAuthoritativeZone", "Rainyun domain has missing/false default-nameserver state; writes would not necessarily affect authoritative DNS.", Some(&reply)));
        }
        if detail["hold_reason"].as_str() != Some("")
            || detail["status"]
                .as_str()
                .is_none_or(|s| s.is_empty() || s.to_ascii_lowercase().contains("hold"))
            || reply.body["data"]
                .get("west_detail_error")
                .is_some_and(|v| v.as_str() != Some(""))
        {
            return Err(self.error("ownership", "UnsafeDomainState", "Rainyun domain is held, has missing state, or upstream detail retrieval failed; mutation is refused.", Some(&reply)));
        }
        Ok(())
    }
    fn record(&self, spec: &Spec, raw: &Value, reply: &HttpReply) -> Result<Record, ProviderError> {
        let bad = || {
            self.error("list", "MalformedRecord", "Rainyun record requires actual positive record_id, relative host, type/value, TTL and known routing line; missing fields are not defaulted.", Some(reply))
        };
        let id = decimal(&raw["record_id"]).ok_or_else(bad)?;
        let name = raw["host"]
            .as_str()
            .filter(|s| *s == "@" || record_hostname(s))
            .ok_or_else(bad)?
            .to_owned();
        if raw.get("domain").is_some_and(|v| {
            !v.as_str()
                .is_some_and(|s| s.trim_end_matches('.').eq_ignore_ascii_case(&spec.domain))
        }) {
            return Err(self.error(
                "list",
                "RecordZoneMismatch",
                "Rainyun returned a DNS record with a conflicting domain.",
                Some(reply),
            ));
        }
        let record_type = raw["type"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(bad)?
            .to_ascii_uppercase();
        let value = raw["value"].as_str().ok_or_else(bad)?.to_owned();
        let ttl = raw["ttl"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= i32::MAX as u64)
            .ok_or_else(bad)?;
        let actual_line = raw["line"]
            .as_str()
            .filter(|s| LINES.contains(s))
            .ok_or_else(bad)?;
        let normalized = if actual_line == "DEFAULT"
            && matches!(spec.record_line.as_str(), "default" | "默认")
        {
            &spec.record_line
        } else {
            actual_line
        };
        // The official client uses is_pause. Missing state is retained but
        // refused if selected (older ddns-go did not model this field).
        let enabled = raw["is_pause"].as_bool() == Some(false);
        Ok(Record {
            id,
            name,
            record_type,
            value,
            ttl,
            line: normalized.into(),
            enabled,
            extra: raw.clone(),
        })
    }
    fn selection(&self, spec: &Spec, record: Option<&Record>) -> Result<(), ProviderError> {
        self.validate(spec)?;
        let Some(r) = record else {
            if line(&spec.record_line) != "DEFAULT" {
                return Err(self.error("selection", "UnsafeCreateLine", "Rainyun requires a default line before routed lines; adapter only creates DEFAULT records. Select an existing routed record.", None));
            }
            return Ok(());
        };
        if r.extra["is_pause"].as_bool().is_none()
            || ["enabled", "disabled", "disable", "status", "system"]
                .iter()
                .any(|k| r.extra.get(*k).is_some())
        {
            return Err(self.error("selection", "UnknownRecordState", "Selected Rainyun record has missing boolean is_pause or undocumented state/system controls; no state is synthesized or changed.", None));
        }
        if r.extra["level"]
            .as_u64()
            .is_none_or(|n| !(1..=100).contains(&n))
        {
            return Err(self.error(
                "selection",
                "UnsafeRecordMetadata",
                "Selected Rainyun record requires actual level 1..100 to preserve priority.",
                None,
            ));
        }
        if r.extra
            .get("rain_product_id")
            .is_some_and(|v| v.as_u64() != Some(0))
            || r.extra
                .get("rain_product_type")
                .is_some_and(|v| v.as_str() != Some(""))
        {
            return Err(self.error("selection", "ProductBoundRecord", "Rainyun product-linked records are not custom DDNS targets; linkage will not be removed or overwritten.", None));
        }
        if [
            "weight",
            "priority",
            "routing",
            "proxied",
            "health_check",
            "failover",
        ]
        .iter()
        .any(|k| r.extra.get(*k).is_some())
        {
            return Err(self.error("selection", "UnsafeRecordMetadata", "Selected Rainyun record carries unsupported routing/settings fields; their semantics cannot safely be preserved.", None));
        }
        if spec.record_id.is_none() && line(&r.line) != line(&spec.record_line) {
            return Err(self.error(
                "selection",
                "RecordLineMismatch",
                "Selected record line differs; routing is never changed.",
                None,
            ));
        }
        Ok(())
    }
    async fn mutate(
        &self,
        spec: &Spec,
        record: Option<&Record>,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.selection(spec, record)?;
        if record.is_none() && (!spec.create_if_missing || spec.record_id.is_some()) {
            return Err(self.error("create", "UnsafeCreate", "Creation requires create_if_missing=true and no explicit record_id; no fallback creation is allowed.", None));
        }
        let parsed: std::net::IpAddr = ip.parse().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be a plain IP address.",
                None,
            )
        })?;
        if parsed.is_ipv4() != (spec.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "Desired IP does not match record type.",
                None,
            ));
        }
        let stage = if record.is_some() { "update" } else { "create" };
        if let Some(r) = record
            && (!r.enabled
                || !r.name.eq_ignore_ascii_case(&spec.subdomain)
                || r.record_type != spec.record_type
                || decimal(&r.extra["record_id"]).as_deref() != Some(r.id.as_str()))
        {
            return Err(self.error(
                stage,
                "InvalidSelectedRecord",
                "Update requires actual enabled ID and matching host/type.",
                None,
            ));
        }
        let fresh = self.list(spec).await?;
        if let Some(original) = record {
            let unchanged = fresh
                .records
                .iter()
                .find(|r| r.id == original.id)
                .is_some_and(|r| {
                    r.name == original.name
                        && r.record_type == original.record_type
                        && r.value == original.value
                        && r.ttl == original.ttl
                        && r.line == original.line
                        && r.enabled
                        && r.extra == original.extra
                });
            let matching = fresh
                .records
                .iter()
                .filter(|r| {
                    r.name.eq_ignore_ascii_case(&spec.subdomain)
                        && r.record_type == spec.record_type
                        && line(&r.line) == line(&spec.record_line)
                })
                .count();
            if !unchanged || spec.record_id.is_none() && matching != 1 {
                return Err(self.error(stage, "StaleRecord", "Rainyun selected record changed or disappeared during the pre-write full reread; no mutation occurred. Rerun selection.", None));
            }
        } else if fresh.records.iter().any(|r| {
            r.name.eq_ignore_ascii_case(&spec.subdomain)
                && (r.record_type == "CNAME"
                    || r.record_type == spec.record_type
                        && line(&r.line) == line(&spec.record_line))
        }) {
            return Err(self.error(stage, "CreateRace", "Rainyun pre-write full reread found an existing target or conflicting CNAME; creation is refused without fallback update.", None));
        }
        let mut body = if let Some(r) = record {
            json!({"host":r.extra["host"],"type":r.extra["type"],"line":r.extra["line"],"level":r.extra["level"],"record_id":r.id.parse::<u64>().unwrap(),"ttl":spec.ttl,"value":parsed.to_string()})
        } else {
            json!({"host":spec.subdomain,"type":spec.record_type,"line":"DEFAULT","level":10,"record_id":0,"ttl":spec.ttl,"value":parsed.to_string()})
        };
        if let Some(r) = record {
            for field in ["rain_product_id", "rain_product_type"] {
                if let Some(value) = r.extra.get(field) {
                    body[field] = value.clone();
                }
            }
        }
        let reply = self
            .call(
                stage,
                self.request(
                    if record.is_some() {
                        reqwest::Method::PATCH
                    } else {
                        reqwest::Method::POST
                    },
                    "/dns",
                )
                .json(&body),
                true,
            )
            .await?;
        let data = &reply.body["data"];
        // Official response schema is unspecified. Allow null/ID only, still
        // proving final state. Never treat an arbitrary object as success.
        let ack = if data.is_null() {
            None
        } else {
            decimal(data).or_else(|| decimal(&data["record_id"]))
        };
        if !data.is_null() && ack.is_none()
            || record.is_some_and(|r| ack.as_ref().is_some_and(|id| id != &r.id))
            || ["warnings", "dryRun", "errors", "error"]
                .iter()
                .any(|k| reply.body.get(*k).is_some() || data.get(*k).is_some())
            || reply
                .body
                .get("success")
                .is_some_and(|v| v.as_bool() != Some(true))
            || data
                .get("success")
                .is_some_and(|v| v.as_bool() != Some(true))
        {
            return Err(self.error(stage, "InvalidWriteAcknowledgement", "Rainyun write has invalid/conflicting ID or preview/warnings; result uncertain, inspect before retrying.", Some(&reply)));
        }
        let listed = self.list(spec).await.map_err(|e| self.error(stage, "UnverifiedWrite", &format!("Rainyun accepted a write, but full verification failed at {} ({}; HTTP {:?}; trace {:?}): {}. Result uncertain; no retry occurred.", e.stage, e.code, e.http_status, e.request_id, e.message), Some(&reply)))?;
        let candidates: Vec<_> = listed
            .records
            .iter()
            .filter(|r| {
                r.name.eq_ignore_ascii_case(&spec.subdomain)
                    && r.record_type == spec.record_type
                    && line(&r.line) == line(body["line"].as_str().unwrap())
            })
            .collect();
        let selected = if let Some(r) = record {
            candidates.iter().copied().find(|v| v.id == r.id)
        } else if candidates.len() == 1 {
            candidates.first().copied()
        } else {
            None
        };
        let verified = selected.is_some_and(|r| {
            (spec.record_id.is_some() || candidates.len() == 1)
                && self.selection(spec, Some(r)).is_ok()
                && r.enabled
                && r.value.parse::<std::net::IpAddr>().ok() == Some(parsed)
                && r.ttl == spec.ttl
                && r.extra["level"] == body["level"]
                && ack.as_ref().is_none_or(|id| id == &r.id)
        });
        if !verified {
            return Err(self.error(stage, "UnverifiedWrite", "Rainyun accepted a write but the full read did not uniquely confirm the exact enabled ID/host/type/line/IP/TTL/priority; inspect uncertain result before retrying.", Some(&reply)));
        }
        Ok(Mutation {
            record_id: selected.unwrap().id.clone(),
            request_id: reply.request_id.or(listed.request_id),
        })
    }
}
impl Adapter for Rainyun {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Relative
    }
    fn validate_selection(
        &self,
        spec: &Spec,
        record: Option<&Record>,
    ) -> Result<(), ProviderError> {
        self.selection(spec, record)
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        self.validate(spec)?;
        self.ownership(spec).await?;
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        for page in 1..=RECORD_LIMIT / PAGE_SIZE + 1 {
            let reply = self
                .call(
                    "list",
                    self.request(reqwest::Method::GET, "/dns/")
                        .query(&[("limit", PAGE_SIZE), ("page_no", page)]),
                    false,
                )
                .await?;
            let data = &reply.body["data"];
            let count = data["TotalRecords"].as_u64().filter(|n| *n <= RECORD_LIMIT as u64).ok_or_else(|| self.error("list", "IncompletePagination", "Rainyun TotalRecords is missing/invalid or exceeds 10,000; selection stopped.", Some(&reply)))? as usize;
            let page_records = data["Records"].as_array().ok_or_else(|| {
                self.error(
                    "list",
                    "MalformedRecordList",
                    "Rainyun Records array is missing or malformed.",
                    Some(&reply),
                )
            })?;
            if total.is_some_and(|t| t != count)
                || page_records.len() != PAGE_SIZE.min(count.saturating_sub(records.len()))
                || records.len() + page_records.len() > count
                || page_records.is_empty() && records.len() < count
            {
                return Err(self.error("list", "IncompletePagination", "Rainyun pagination changed total, oversized/truncated page, or ended early; no partial selection.", Some(&reply)));
            }
            total = Some(count);
            for raw in page_records {
                let record = self.record(spec, raw, &reply)?;
                if !ids.insert(record.id.clone()) {
                    return Err(self.error(
                        "list",
                        "UnstableRecordList",
                        "Repeated record IDs across Rainyun pages; selection stopped.",
                        Some(&reply),
                    ));
                }
                records.push(record);
            }
            if records.len() == count {
                if records.iter().any(|r| {
                    r.name.eq_ignore_ascii_case(&spec.subdomain) && r.record_type == "CNAME"
                }) {
                    return Err(self.error("selection", "ConflictingCname", "Rainyun target host has a CNAME; A/AAAA creation or updates would conflict. No mutation or dry-run success is allowed.", Some(&reply)));
                }
                return Ok(List {
                    records,
                    request_id: reply.request_id,
                });
            }
        }
        Err(self.error(
            "list",
            "PageLimit",
            "Rainyun pagination failed to finish within the 10,000-record safety limit.",
            None,
        ))
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.mutate(spec, None, ip).await
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.mutate(spec, Some(record), ip).await
    }
}
fn line(s: &str) -> &str {
    if matches!(s, "default" | "默认") {
        "DEFAULT"
    } else {
        s
    }
}
fn decimal(v: &Value) -> Option<String> {
    let id = v
        .as_u64()
        .filter(|n| *n > 0 && *n <= i64::MAX as u64)
        .map(|n| n.to_string())
        .or_else(|| v.as_str().map(str::to_owned))?;
    let n = id.parse::<u64>().ok()?;
    (n > 0 && n <= i64::MAX as u64 && n.to_string() == id).then_some(id)
}
fn record_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').enumerate().all(|(i, l)| {
            (i == 0 && l == "*")
                || (!l.is_empty()
                    && l.len() <= 63
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
        })
}
fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::super::common;
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
    #[derive(Clone)]
    struct Capture {
        method: Method,
        uri: String,
        headers: HeaderMap,
        body: Value,
    }
    type Captures = Arc<Mutex<Vec<Capture>>>;
    #[derive(Clone)]
    struct StateData {
        replies: Arc<Mutex<VecDeque<(StatusCode, String)>>>,
        captures: Captures,
    }
    struct Mock {
        provider: Rainyun,
        captures: Captures,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(
        State(s): State<StateData>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, HeaderMap, String) {
        s.captures.lock().unwrap().push(Capture {
            method,
            uri: uri.to_string(),
            headers,
            body: if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            },
        });
        let (status, body) = s.replies.lock().unwrap().pop_front().unwrap_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"code":500,"message":"Unexpected request","data":null}).to_string(),
        ));
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", "mock-header-trace".parse().unwrap());
        (status, headers, body)
    }
    async fn mock_raw(replies: Vec<(StatusCode, String)>) -> Mock {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let state = StateData {
            replies: Arc::new(Mutex::new(replies.into())),
            captures: captures.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
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
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap();
        let mut provider = Rainyun::new(
            client,
            "test-rainyun-secret".into(),
            &BTreeMap::from([("domain_id".into(), "123".into())]),
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
        json!({"code":200,"message":"","data":{"Data":{"id":123,"domain":"Example.COM.","is_default_nameservers":true,"hold_reason":"","status":"ok"},"west_detail_error":""}})
    }
    fn raw(id: u64, host: &str) -> Value {
        json!({"record_id":id,"host":host,"type":"A","value":"1.1.1.1","line":"DEFAULT","ttl":600,"level":17,"is_pause":false})
    }
    fn page(total: usize, records: Vec<Value>) -> Value {
        json!({"code":200,"message":"","data":{"TotalRecords":total,"Records":records},"requestId":"list-trace"})
    }
    fn ack(data: Value) -> Value {
        json!({"code":200,"message":"","data":data,"requestId":"write-trace"})
    }
    fn assert_reads(m: &Mock) {
        assert!(
            m.captures
                .lock()
                .unwrap()
                .iter()
                .all(|c| c.method == Method::GET)
        );
    }
    #[tokio::test]
    async fn exact_domain_full_list_auth_and_actual_metadata() {
        let mut r = raw(9223372036854775807, "home");
        r["ttl"] = json!(300);
        let m = mock(vec![owned(), page(1, vec![r])]).await;
        let l = m.provider.list(&spec()).await.unwrap();
        assert_eq!(l.records[0].id, "9223372036854775807");
        assert_eq!(l.records[0].ttl, 300);
        assert_eq!(l.records[0].line, "默认");
        assert_eq!(l.request_id.as_deref(), Some("list-trace"));
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls[0].uri, "/product/domain/123");
        assert_eq!(calls[1].uri, "/product/domain/123/dns/?limit=100&page_no=1");
        for c in calls.iter() {
            assert_eq!(c.headers["x-api-key"], "test-rainyun-secret");
            assert!(!c.uri.contains("secret"));
            assert!(!c.body.to_string().contains("secret"));
        }
    }
    #[tokio::test]
    async fn exhausts_1001_records_and_selects_last_page() {
        let mut replies = vec![owned()];
        for start in (0..1001).step_by(100) {
            replies.push(page(
                1001,
                (start..(start + 100).min(1001))
                    .map(|n| raw(n as u64 + 1, if n == 1000 { "home" } else { "unrelated" }))
                    .collect(),
            ));
        }
        let m = mock(replies).await;
        let o = common::reconcile(&m.provider, &spec(), "8.8.8.8", true)
            .await
            .unwrap();
        assert_eq!(o.status, "would_update");
        assert_eq!(o.record_id.as_deref(), Some("1001"));
        assert_eq!(m.captures.lock().unwrap().len(), 12);
        assert_reads(&m);
    }
    #[tokio::test]
    async fn pagination_refuses_duplicates_changing_total_short_missing_and_limit() {
        let first: Vec<_> = (1..=100).map(|n| raw(n, "other")).collect();
        for (last, expected) in [
            (page(101, vec![raw(1, "home")]), "UnstableRecordList"),
            (page(102, vec![raw(101, "home")]), "IncompletePagination"),
            (page(101, vec![]), "IncompletePagination"),
            (
                json!({"code":200,"data":{"Records":[]}}),
                "IncompletePagination",
            ),
            (page(10001, vec![]), "IncompletePagination"),
        ] {
            let m = mock(vec![owned(), page(101, first.clone()), last]).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                expected
            );
            assert_reads(&m);
        }
        let m = mock(vec![owned(), page(0, vec![raw(1, "home")])]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "IncompletePagination"
        );
    }
    #[tokio::test]
    async fn ownership_refuses_wrong_id_domain_nondefault_and_missing_or_hold_state() {
        for (field, value, expected) in [
            ("id", json!(124), "ZoneMismatch"),
            ("domain", json!("other.com"), "ZoneMismatch"),
            ("domain", Value::Null, "ZoneMismatch"),
            (
                "is_default_nameservers",
                json!(false),
                "NonAuthoritativeZone",
            ),
            (
                "is_default_nameservers",
                Value::Null,
                "NonAuthoritativeZone",
            ),
            ("hold_reason", json!("unverified"), "UnsafeDomainState"),
            ("hold_reason", Value::Null, "UnsafeDomainState"),
            ("status", json!("clientHold"), "UnsafeDomainState"),
        ] {
            let mut reply = owned();
            reply["data"]["Data"][field] = value;
            let m = mock(vec![reply]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, expected);
            assert_eq!(m.captures.lock().unwrap().len(), 1);
        }
        let mut r = owned();
        r["data"]["west_detail_error"] = json!("upstream unavailable");
        let m = mock(vec![r]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "UnsafeDomainState"
        );
    }
    #[tokio::test]
    async fn validates_options_ttl_credentials_domain_line_before_dry_run_reads() {
        for ttl in [0, 1, 59, 61, 604800, u64::MAX] {
            let m = mock(vec![]).await;
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap_err()
                    .code,
                "UnsupportedTTL"
            );
            assert!(m.captures.lock().unwrap().is_empty());
        }
        for mutate in 0..6 {
            let mut m = mock(vec![]).await;
            let mut s = spec();
            match mutate {
                0 => m.provider.domain_id = "../123".into(),
                1 => m.provider.options_valid = false,
                2 => s
                    .options
                    .insert("level".into(), "5".into())
                    .map(|_| ())
                    .unwrap_or(()),
                3 => m.provider.token = "\nsecret".into(),
                4 => s.domain = "example.com/path".into(),
                _ => s.record_line = "invented".into(),
            }
            assert!(m.provider.list(&s).await.is_err());
            assert!(m.captures.lock().unwrap().is_empty());
        }
        for ttl in TTLS {
            let m = mock(vec![owned(), page(0, vec![])]).await;
            let mut s = spec();
            s.ttl = *ttl;
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap()
                    .status,
                "would_create"
            );
            assert_reads(&m);
        }
    }
    #[tokio::test]
    async fn refuses_ambiguous_disabled_missing_id_and_unrelated_id() {
        for (records, id, code) in [
            (
                vec![raw(1, "home"), raw(2, "home")],
                None,
                "AmbiguousRecords",
            ),
            (
                vec![{
                    let mut r = raw(1, "home");
                    r["is_pause"] = json!(true);
                    r
                }],
                None,
                "RecordDisabled",
            ),
            (vec![raw(1, "other")], Some("1"), "RecordIdMismatch"),
            (vec![], Some("999"), "RecordIdNotFound"),
        ] {
            let m = mock(vec![owned(), page(records.len(), records)]).await;
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
            assert_reads(&m);
        }
    }
    #[tokio::test]
    async fn refuses_missing_priority_unknown_state_binding_and_invalid_values_even_unchanged() {
        for (field, value, code) in [
            ("level", Value::Null, "UnsafeRecordMetadata"),
            ("level", json!(0), "UnsafeRecordMetadata"),
            ("is_pause", Value::Null, "UnknownRecordState"),
            ("enabled", json!(true), "UnknownRecordState"),
            ("rain_product_id", json!(42), "ProductBoundRecord"),
            ("rain_product_type", json!("rcs"), "ProductBoundRecord"),
            ("value", json!("not-an-ip"), "InvalidRecordValue"),
            ("value", json!("::1"), "InvalidRecordValue"),
        ] {
            let mut r = raw(1, "home");
            r[field] = value;
            let m = mock(vec![owned(), page(1, vec![r])]).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "1.1.1.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_reads(&m);
        }
    }
    #[tokio::test]
    async fn malformed_records_fail_closed_and_do_not_default_fields() {
        for field in ["record_id", "host", "type", "value", "ttl", "line"] {
            let mut r = raw(1, "home");
            r.as_object_mut().unwrap().remove(field);
            let m = mock(vec![owned(), page(1, vec![r])]).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "MalformedRecord"
            );
            assert_reads(&m);
        }
        let mut r = raw(1, "home");
        r["domain"] = json!("evil.com");
        let m = mock(vec![owned(), page(1, vec![r])]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "RecordZoneMismatch"
        );
    }
    #[tokio::test]
    async fn update_preserves_actual_routed_line_level_and_native_id_with_post_read() {
        let mut r = raw(7, "HOME");
        r["line"] = json!("LTEL");
        let mut final_r = r.clone();
        final_r["value"] = json!("8.8.8.8");
        let m = mock(vec![
            owned(),
            page(1, vec![r.clone()]),
            owned(),
            page(1, vec![r]),
            ack(Value::Null),
            owned(),
            page(1, vec![final_r]),
        ])
        .await;
        let mut s = spec();
        s.record_id = Some("7".into());
        let o = common::reconcile(&m.provider, &s, "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(o.status, "updated");
        assert_eq!(o.request_id.as_deref(), Some("write-trace"));
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls.len(), 7);
        assert_eq!(calls[4].method, Method::PATCH);
        assert_eq!(calls[4].uri, "/product/domain/123/dns");
        assert_eq!(
            calls[4].body,
            json!({"host":"HOME","type":"A","line":"LTEL","level":17,"record_id":7,"ttl":600,"value":"8.8.8.8"})
        );
        assert_eq!(calls.iter().filter(|c| c.method != Method::GET).count(), 1);
    }
    #[tokio::test]
    async fn create_ipv6_apex_requires_full_unique_verification() {
        let mut r = raw(9, "@");
        r["type"] = json!("AAAA");
        r["value"] = json!("2001:db8::1");
        r["level"] = json!(10);
        let m = mock(vec![
            owned(),
            page(0, vec![]),
            owned(),
            page(0, vec![]),
            ack(json!(9)),
            owned(),
            page(1, vec![r]),
        ])
        .await;
        let mut s = spec();
        s.subdomain = "@".into();
        s.record_type = "AAAA".into();
        s.create_if_missing = true;
        let o = common::reconcile(&m.provider, &s, "2001:0db8::1", false)
            .await
            .unwrap();
        assert_eq!(o.status, "created");
        assert_eq!(o.record_id.as_deref(), Some("9"));
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls[4].method, Method::POST);
        assert_eq!(calls[4].body["line"], "DEFAULT");
        assert_eq!(calls[4].body["record_id"], 0);
        assert_eq!(calls[4].body["value"], "2001:db8::1");
    }
    #[tokio::test]
    async fn ttl_only_update_and_ipv6_canonical_unchanged() {
        let r = raw(1, "home");
        let mut after = r.clone();
        after["ttl"] = json!(300);
        let m = mock(vec![
            owned(),
            page(1, vec![r.clone()]),
            owned(),
            page(1, vec![r]),
            ack(json!({"record_id":1})),
            owned(),
            page(1, vec![after]),
        ])
        .await;
        let mut s = spec();
        s.ttl = 300;
        assert_eq!(
            common::reconcile(&m.provider, &s, "1.1.1.1", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let mut r = raw(1, "home");
        r["type"] = json!("AAAA");
        r["value"] = json!("2001:0db8::1");
        let m = mock(vec![owned(), page(1, vec![r])]).await;
        let mut s = spec();
        s.record_type = "AAAA".into();
        assert_eq!(
            common::reconcile(&m.provider, &s, "2001:db8::1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert_reads(&m);
    }
    #[tokio::test]
    async fn unsafe_write_ack_and_post_read_drift_are_uncertain_without_retry() {
        for data in [
            json!(0),
            json!(2),
            json!({}),
            json!({"record_id":0}),
            json!(false),
        ] {
            let m = mock(vec![
                owned(),
                page(1, vec![raw(1, "home")]),
                owned(),
                page(1, vec![raw(1, "home")]),
                ack(data),
            ])
            .await;
            let e = common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "InvalidWriteAcknowledgement");
            assert!(!e.retryable);
            assert_eq!(m.captures.lock().unwrap().len(), 5);
        }
        for data in [
            page(1, vec![raw(1, "home")]),
            page(0, vec![]),
            page(2, vec![raw(1, "home"), raw(2, "home")]),
        ] {
            let m = mock(vec![
                owned(),
                page(0, vec![]),
                owned(),
                page(0, vec![]),
                ack(Value::Null),
                owned(),
                data,
            ])
            .await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "UnverifiedWrite"
            );
            assert_eq!(
                m.captures
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|c| c.method == Method::POST)
                    .count(),
                1
            );
        }
    }
    #[tokio::test]
    async fn detailed_http_business_errors_are_sanitized_traceable_and_no_retry() {
        for (status, body, code) in [
            (
                StatusCode::OK,
                json!({"code":400101,"message":"bad key test-rainyun-secret\n detail","data":null,"requestId":"business-trace"}),
                "Rainyun400101",
            ),
            (
                StatusCode::FORBIDDEN,
                json!({"code":401,"message":"denied test-rainyun-secret","data":null}),
                "Rainyun401",
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                json!({"message":"quota exceeded test-rainyun-secret"}),
                "Http429",
            ),
        ] {
            let m = mock_raw(vec![(status, body.to_string())]).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, code);
            assert_eq!(e.http_status, Some(status.as_u16()));
            assert!(e.message.contains("[REDACTED]"));
            assert!(!e.message.contains("test-rainyun-secret"));
            assert!(!e.message.contains('\n'));
            assert!(e.request_id.is_some());
        }
        for body in ["not JSON", "<html>test-rainyun-secret</html>"] {
            let m = mock_raw(vec![(StatusCode::BAD_GATEWAY, body.into())]).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "MalformedResponse");
            assert_eq!(e.http_status, Some(502));
            assert!(!e.message.contains("test-rainyun-secret"));
        }
        let m = mock(vec![json!({"code":200})]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "InvalidEnvelope"
        );
    }
    #[tokio::test]
    async fn preflight_refuses_stale_pause_line_priority_disappearance_and_ambiguity() {
        for (field, value) in [
            ("is_pause", json!(true)),
            ("line", json!("LTEL")),
            ("level", json!(18)),
            ("value", json!("9.9.9.9")),
        ] {
            let original = raw(1, "home");
            let mut changed = original.clone();
            changed[field] = value;
            let m = mock(vec![
                owned(),
                page(1, vec![original]),
                owned(),
                page(1, vec![changed]),
            ])
            .await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "StaleRecord"
            );
            assert_reads(&m);
        }
        for fresh in [
            page(0, vec![]),
            page(2, vec![raw(1, "home"), raw(2, "home")]),
        ] {
            let m = mock(vec![owned(), page(1, vec![raw(1, "home")]), owned(), fresh]).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "StaleRecord"
            );
            assert_reads(&m);
        }
    }
    #[tokio::test]
    async fn direct_create_opt_in_and_preflight_creation_races_are_refused() {
        let m = mock(vec![]).await;
        assert_eq!(
            m.provider
                .create(&spec(), "8.8.8.8")
                .await
                .unwrap_err()
                .code,
            "UnsafeCreate"
        );
        assert!(m.captures.lock().unwrap().is_empty());
        let mut s = spec();
        s.create_if_missing = true;
        s.record_id = Some("1".into());
        assert_eq!(
            m.provider.create(&s, "8.8.8.8").await.unwrap_err().code,
            "UnsafeCreate"
        );
        assert!(m.captures.lock().unwrap().is_empty());
        for kind in ["A", "CNAME"] {
            let mut appeared = raw(1, "home");
            appeared["type"] = json!(kind);
            let m = mock(vec![
                owned(),
                page(0, vec![]),
                owned(),
                page(1, vec![appeared]),
            ])
            .await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                if kind == "CNAME" {
                    "ConflictingCname"
                } else {
                    "CreateRace"
                }
            );
            assert_reads(&m);
        }
    }
    #[tokio::test]
    async fn unrelated_txt_wildcard_hosts_and_neutral_product_metadata_are_preserved() {
        let mut target = raw(1, "home");
        target["record_id"] = json!("1");
        target["rain_product_id"] = json!(0);
        target["rain_product_type"] = json!("");
        let mut after = target.clone();
        after["value"] = json!("8.8.8.8");
        let mut unrelated = raw(2, "_acme-challenge");
        unrelated["type"] = json!("TXT");
        unrelated["value"] = json!("validation");
        let wildcard = raw(3, "*.other");
        let before = page(3, vec![target, unrelated.clone(), wildcard.clone()]);
        let m = mock(vec![
            owned(),
            before.clone(),
            owned(),
            before,
            ack(Value::Null),
            owned(),
            page(3, vec![after, unrelated, wildcard]),
        ])
        .await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls[4].body["record_id"], 1);
        assert_eq!(calls[4].body["rain_product_id"], 0);
        assert_eq!(calls[4].body["rain_product_type"], "");
        let request = m
            .provider
            .request(reqwest::Method::GET, "")
            .build()
            .unwrap();
        assert!(request.headers()["x-api-key"].is_sensitive());
    }
    #[tokio::test]
    async fn dry_run_create_update_default_aliases_and_missing_routed_create() {
        for alias in ["default", "默认", "DEFAULT"] {
            let m = mock(vec![owned(), page(1, vec![raw(1, "home")])]).await;
            let mut s = spec();
            s.record_line = alias.into();
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap()
                    .status,
                "would_update"
            );
            assert_reads(&m);
        }
        let m = mock(vec![owned(), page(0, vec![])]).await;
        let mut s = spec();
        s.record_line = "LTEL".into();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", true)
                .await
                .unwrap_err()
                .code,
            "UnsafeCreateLine"
        );
        assert_reads(&m);
        let m = mock(vec![owned(), page(0, vec![])]).await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordNotFound"
        );
        assert_reads(&m);
    }
}
