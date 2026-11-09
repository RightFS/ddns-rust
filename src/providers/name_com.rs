//! Name.com Core v1 (not deprecated v4).
//! Contracts: https://docs.name.com/api/v1/reference/dns/list-records
//! https://docs.name.com/api/v1/reference/dns/update-record
//! https://docs.name.com/api/v1/reference/domains/get-domain
//! https://docs.name.com/guides/authentication
//! Parent must supply a redirect-disabled client. No production endpoint override.
//! PUT replaces a complete record: preserve host/type/priority; reject unknown
//! settings. Fresh reads reduce races but no conditional write/CAS is documented;
//! use an exclusive writer. Never retry an uncertain write automatically.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
const ENDPOINT: &str = "https://api.name.com/core/v1";
const PAGE_SIZE: u64 = 500;
const MAX_PAGES: u64 = 100;
const HINT: &str = "Verify the exact Name.com account domain and production username/API token (enable API Access with 2FA). Use default routing and dedicated A/AAAA records. TTL minimum is 300 seconds. 404 is not an empty zone. For 429 check X-RateLimit-Reset. Use an exclusive writer: no CAS is documented. Inspect any uncertain write before retrying; no automatic write retries occur.";
// Intentionally not Debug: credentials and encoded Basic authorization are secret.
pub struct NameCom {
    api: Api,
    username: String,
    token: String,
    options: BTreeMap<String, String>,
    #[cfg(test)]
    endpoint: String,
}
impl NameCom {
    pub fn new(
        client: reqwest::Client,
        username: String,
        token: String,
        options: &BTreeMap<String, String>,
    ) -> Self {
        let pair = format!("{username}:{token}");
        let encoded = STANDARD.encode(&pair);
        Self {
            api: Api::new(
                client,
                vec![
                    format!("Basic {encoded}"),
                    encoded,
                    pair,
                    username.clone(),
                    token.clone(),
                ],
            ),
            username,
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
    fn validate_spec(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.username.trim().is_empty()
            || self.token.trim().is_empty()
            || self.username.contains(':')
            || self.username.chars().any(char::is_control)
            || self.token.chars().any(char::is_control)
        {
            return Err(self.error("validation", "InvalidCredentials", "Name.com requires nonempty username and API token; username cannot contain a colon or control characters.", None));
        }
        if !hostname(&spec.domain)
            || !spec.domain.contains('.')
            || (spec.subdomain != "@" && !hostname(&spec.subdomain))
            || spec.fqdn().len() > 253
        {
            return Err(self.error("validation", "InvalidDnsName", "Use an exact ASCII/punycode zone and relative host or @; URL syntax and wildcards are forbidden targets.", None));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Only A and AAAA DDNS records are supported.",
                None,
            ));
        }
        // Official minimum is 300; 604800 is the application's conservative cap,
        // not a claimed provider maximum. Never silently clamp TTL.
        if !(300..=604800).contains(&spec.ttl) {
            return Err(self.error("validation", "UnsupportedTTL", "TTL must be at least the documented Name.com minimum 300 seconds and at most the application safety cap 604800 seconds.", None));
        }
        if !matches!(spec.record_line.as_str(), "默认" | "default")
            || !spec.options.is_empty()
            || !self.options.is_empty()
        {
            return Err(self.error("validation", "UnsupportedOptions", "Name.com supports no adapter/record options or routing-line controls here; use the default line.", None));
        }
        if spec
            .record_id
            .as_ref()
            .is_some_and(|id| decimal_id(&json!(id)).as_deref() != Some(id.as_str()))
        {
            return Err(self.error(
                "validation",
                "InvalidRecordId",
                "Explicit record_id must be a canonical positive int32 decimal ID.",
                None,
            ));
        }
        Ok(())
    }
    fn ip(&self, spec: &Spec, ip: &str) -> Result<String, ProviderError> {
        self.validate_spec(spec)?;
        let value = ip.parse::<IpAddr>().map_err(|_| {
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
                "IP address family does not match A/AAAA.",
                None,
            ));
        }
        Ok(value.to_string())
    }
    async fn call(
        &self,
        stage: &str,
        method: Method,
        path: &str,
        body: Option<&Value>,
        page: Option<u64>,
    ) -> Result<HttpReply, ProviderError> {
        let write = method != Method::GET;
        let mut request = self
            .api
            .client
            .request(method, format!("{}{path}", self.endpoint()))
            .basic_auth(&self.username, Some(&self.token))
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        if let Some(page) = page {
            request = request.query(&[("page", page), ("perPage", PAGE_SIZE)]);
        }
        let reply = self.api.send(stage, request, write).await?;
        // Name.com error schema is message + details; also recognize code/error
        // business envelopes even on HTTP 200. Never serialize an arbitrary body.
        if !(200..300).contains(&reply.status)
            || reply.body.get("message").is_some()
            || reply.body.get("error").is_some()
            || reply.body.get("code").is_some()
        {
            let fallback = if reply.status == 200 {
                "NameComApiError".into()
            } else {
                format!("Http{}", reply.status)
            };
            let code = reply
                .body
                .get("code")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .unwrap_or(&fallback);
            let mut details = Vec::new();
            for key in ["message", "details", "error"] {
                if let Some(text) = reply.body.get(key).and_then(Value::as_str) {
                    details.push(format!("{key}: {}", self.api.safe(text)));
                }
            }
            for key in ["message", "details", "code"] {
                if let Some(text) = reply
                    .body
                    .pointer(&format!("/error/{key}"))
                    .and_then(Value::as_str)
                {
                    details.push(format!("error.{key}: {}", self.api.safe(text)));
                }
            }
            if details.is_empty() {
                details.push("No recognized error detail; raw body omitted.".into());
            }
            if let Some(reset) = reply
                .headers
                .get("x-ratelimit-reset")
                .and_then(|v| v.to_str().ok())
            {
                details.push(format!("X-RateLimit-Reset: {}", self.api.safe(reset)));
            }
            return Err(self.error(
                stage,
                code,
                &format!("Name.com API error: {}", details.join("; ")),
                Some(&reply),
            ));
        }
        if reply.status != 200 || !reply.body.is_object() {
            return Err(self.error(
                stage,
                "InvalidEnvelope",
                "Expected documented HTTP 200 JSON object; inspect any uncertain write.",
                Some(&reply),
            ));
        }
        Ok(reply)
    }
    fn domain_path(&self, spec: &Spec) -> String {
        format!("/domains/{}", spec.domain.to_ascii_lowercase())
    }
    async fn zone(&self, spec: &Spec) -> Result<(), ProviderError> {
        self.validate_spec(spec)?;
        let reply = self
            .call("zone", Method::GET, &self.domain_path(spec), None, None)
            .await?;
        if !reply.body["domainName"]
            .as_str()
            .is_some_and(|d| d.eq_ignore_ascii_case(&spec.domain))
        {
            return Err(self.error("zone", "ZoneMismatch", "GetDomain did not confirm the exact authenticated account domain; no zone fallback.", Some(&reply)));
        }
        if let Some(locks) = reply.body.get("locks") {
            let locks = locks.as_array().ok_or_else(|| {
                self.error(
                    "zone",
                    "MalformedZone",
                    "Domain locks metadata is malformed.",
                    Some(&reply),
                )
            })?;
            for lock in locks {
                let lock = lock.as_str().ok_or_else(|| {
                    self.error(
                        "zone",
                        "MalformedZone",
                        "Domain lock is not a string.",
                        Some(&reply),
                    )
                })?;
                if lock.eq_ignore_ascii_case("clientHold")
                    || lock.eq_ignore_ascii_case("serverHold")
                {
                    return Err(self.error(
                        "zone",
                        "ZoneOnHold",
                        "Domain is on a DNS-disabling registry hold; no mutation permitted.",
                        Some(&reply),
                    ));
                }
            }
        }
        Ok(())
    }
    fn record(
        &self,
        spec: &Spec,
        raw: &Value,
        stage: &str,
        reply: Option<&HttpReply>,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error(stage, "MalformedRecord", "Record lacks a valid positive int32 ID, zone, host, type, answer, TTL or consistent FQDN.", reply)
        };
        let id = decimal_id(&raw["id"]).ok_or_else(bad)?;
        let zone = raw["domainName"].as_str().ok_or_else(bad)?;
        if !zone.eq_ignore_ascii_case(&spec.domain) {
            return Err(self.error(
                stage,
                "RecordZoneMismatch",
                "Record belongs to a different domain; selection stopped.",
                reply,
            ));
        }
        let host = raw["host"].as_str().ok_or_else(bad)?;
        // Zone lists include unrelated wildcard/SRV/TXT hosts. Validate them as
        // DNS labels (including underscore/wildcard), not as writable targets.
        if !record_host(host) {
            return Err(bad());
        }
        let name = if matches!(host, "" | "@") {
            zone.to_owned()
        } else {
            format!("{host}.{zone}")
        };
        if name.len() > 253
            || !raw["fqdn"].as_str().is_some_and(|fqdn| {
                fqdn.strip_suffix('.')
                    .unwrap_or(fqdn)
                    .eq_ignore_ascii_case(&name)
            })
        {
            return Err(bad());
        }
        let kind = raw["type"]
            .as_str()
            .filter(|v| {
                matches!(
                    *v,
                    "A" | "AAAA"
                        | "ANAME"
                        | "CNAME"
                        | "MX"
                        | "NS"
                        | "SRV"
                        | "TXT"
                        | "SOA"
                        | "CAA"
                        | "HTTPS"
                        | "SVCB"
                )
            })
            .ok_or_else(bad)?;
        let answer = raw["answer"].as_str().ok_or_else(bad)?;
        let ttl = raw["ttl"]
            .as_u64()
            .filter(|v| *v >= 300 && *v <= i64::MAX as u64)
            .ok_or_else(bad)?;
        let enabled = match raw.get("enabled") {
            None => true,
            Some(Value::Bool(v)) => *v,
            _ => return Err(bad()),
        };
        Ok(Record {
            id,
            name,
            record_type: kind.into(),
            value: answer.into(),
            ttl,
            line: String::new(),
            enabled,
            extra: raw.clone(),
        })
    }
    fn selection(&self, spec: &Spec, record: &Record) -> Result<(), ProviderError> {
        let verified = self.record(spec, &record.extra, "selection", None)?;
        if record.id != verified.id
            || spec.record_id.as_ref().is_some_and(|id| id != &record.id)
            || !record.name.eq_ignore_ascii_case(&verified.name)
            || !record.name.eq_ignore_ascii_case(&spec.fqdn())
            || record.record_type != spec.record_type
            || record.record_type != verified.record_type
            || record.value != verified.value
            || record.ttl != verified.ttl
            || record.enabled != verified.enabled
            || !record.line.is_empty()
        {
            return Err(self.error(
                "selection",
                "RecordTargetMismatch",
                "Selected record identity or metadata contradicts the immutable configured target.",
                None,
            ));
        }
        if !record.enabled {
            return Err(self.error(
                "selection",
                "RecordDisabled",
                "Selected record is disabled; it will not be enabled or overwritten.",
                None,
            ));
        }
        let raw = record.extra.as_object().expect("record validated object");
        // Full-overwrite PUT cannot safely preserve undocumented settings.
        for key in raw.keys() {
            if !matches!(
                key.as_str(),
                "id" | "domainName" | "fqdn" | "host" | "type" | "answer" | "ttl" | "priority"
            ) {
                return Err(self.error("selection", "UnsafeRecordSettings", "Selected A/AAAA record contains undocumented settings; refuse lossy full replacement.", None));
            }
        }
        if raw.get("priority").is_some_and(|v| v.as_u64() != Some(0)) {
            return Err(self.error("selection", "UnsafeRecordSettings", "Selected A/AAAA has nonzero or malformed MX/SRV priority; refuse unsafe replacement.", None));
        }
        let old = record.value.parse::<IpAddr>().map_err(|_| {
            self.error(
                "selection",
                "InvalidRecordValue",
                "Existing A/AAAA answer is not a plain IP address.",
                None,
            )
        })?;
        if old.is_ipv4() != (record.record_type == "A") {
            return Err(self.error(
                "selection",
                "InvalidRecordValue",
                "Existing answer has incorrect IP family.",
                None,
            ));
        }
        Ok(())
    }
    async fn read_records(&self, spec: &Spec) -> Result<List, ProviderError> {
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        let mut range_base = None;
        let mut last = None;
        let mut request_id = None;
        for page in 1..=MAX_PAGES {
            let reply = self
                .call(
                    "list",
                    Method::GET,
                    &format!("{}/records", self.domain_path(spec)),
                    None,
                    Some(page),
                )
                .await?;
            let bad = || {
                self.error("list", "IncompletePagination", "Record pagination counts/ranges or nextPage/lastPage are missing, inconsistent, truncated or unstable; no partial selection.", Some(&reply))
            };
            if [
                "pagination",
                "next",
                "cursor",
                "hasMore",
                "has_more",
                "truncated",
                "next_page",
                "total",
                "total_count",
            ]
            .iter()
            .any(|key| reply.body.get(*key).is_some())
                || reply.headers.contains_key(reqwest::header::LINK)
            {
                return Err(bad());
            }
            let raw = reply.body["records"].as_array().ok_or_else(bad)?;
            let count = reply.body["totalCount"]
                .as_u64()
                .filter(|n| *n <= 10000)
                .ok_or_else(bad)?;
            if total.is_some_and(|n| n != count) || raw.len() as u64 > PAGE_SIZE {
                return Err(bad());
            }
            total = Some(count);
            let from = reply.body["from"].as_u64().ok_or_else(bad)?;
            let to = reply.body["to"].as_u64().ok_or_else(bad)?;
            // Docs describe starting/ending record numbers but do not define
            // their base. Accept either inclusive zero- or one-based ranges,
            // fixed by the first nonempty page; never accept gaps/base changes.
            if raw.is_empty() {
                if count != 0 || from != 0 || to != 0 {
                    return Err(bad());
                }
            } else {
                let base = *range_base.get_or_insert(from);
                let offset = records.len() as u64;
                let length = raw.len() as u64;
                if base > 1
                    || from != offset + base
                    || to != from + length - 1
                    || offset + length > count
                {
                    return Err(bad());
                }
            }
            for value in raw {
                let record = self.record(spec, value, "list", Some(&reply))?;
                if !ids.insert(record.id.clone()) {
                    return Err(self.error(
                        "list",
                        "UnstableRecordList",
                        "Repeated record ID across pages; selection stopped.",
                        Some(&reply),
                    ));
                }
                records.push(record);
            }
            request_id = reply.request_id.clone().or(request_id);
            let next = match reply.body.get("nextPage") {
                None => 0,
                Some(v) => v.as_u64().ok_or_else(bad)?,
            };
            let final_page = match reply.body.get("lastPage") {
                None => 0,
                Some(v) => v.as_u64().ok_or_else(bad)?,
            };
            if next == 0 {
                if records.len() as u64 != count
                    || (final_page != 0 && final_page != page)
                    || last.is_some_and(|n| n != page)
                {
                    return Err(bad());
                }
                return Ok(List {
                    records,
                    request_id,
                });
            }
            if raw.is_empty()
                || next != page + 1
                || final_page < next
                || final_page > MAX_PAGES
                || last.is_some_and(|n| n != final_page)
                || records.len() as u64 >= count
            {
                return Err(bad());
            }
            last = Some(final_page);
        }
        Err(self.error(
            "list",
            "PaginationLimit",
            "Pagination exceeded the 100-page safety bound; no partial selection.",
            None,
        ))
    }
    fn ack(
        &self,
        spec: &Spec,
        ip: &str,
        record: Option<&Record>,
        reply: &HttpReply,
        stage: &str,
    ) -> Result<Mutation, ProviderError> {
        let bad = || {
            self.error(stage, "InvalidWriteAcknowledgement", "Name.com did not acknowledge the immutable ID/zone/host/type and requested answer/TTL/priority; write result is uncertain, inspect before retrying.", Some(reply))
        };
        let acknowledged = self
            .record(spec, &reply.body, stage, Some(reply))
            .map_err(|_| bad())?;
        if !acknowledged.name.eq_ignore_ascii_case(&spec.fqdn())
            || acknowledged.record_type != spec.record_type
            || acknowledged.value.parse::<IpAddr>().ok() != ip.parse::<IpAddr>().ok()
            || acknowledged.ttl != spec.ttl
            || !acknowledged.enabled
            || record.is_some_and(|r| r.id != acknowledged.id)
        {
            return Err(bad());
        }
        self.selection(spec, &acknowledged).map_err(|_| bad())?;
        if let Some(record) = record {
            if reply.body["host"] != record.extra["host"]
                || reply.body.get("priority") != record.extra.get("priority")
            {
                return Err(bad());
            }
        } else if reply
            .body
            .get("priority")
            .is_some_and(|v| v.as_u64() != Some(0))
        {
            return Err(bad());
        }
        Ok(Mutation {
            record_id: acknowledged.id,
            request_id: reply.request_id.clone(),
        })
    }
}
impl Adapter for NameCom {
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
        self.zone(spec).await?;
        self.read_records(spec).await
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.ip(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error(
                "create",
                "CreationNotAllowed",
                "Creation requires explicit create_if_missing and no record_id.",
                None,
            ));
        }
        self.zone(spec).await?;
        let fresh = self.read_records(spec).await?;
        if fresh.records.iter().any(|r| {
            r.name.eq_ignore_ascii_case(&spec.fqdn())
                && (r.record_type == spec.record_type
                    || matches!(r.record_type.as_str(), "CNAME" | "ANAME"))
        }) {
            return Err(self.error(
                "create",
                "RecordAppeared",
                "Target or alias appeared on the final complete read; creation stopped.",
                None,
            ));
        }
        let host = if spec.subdomain == "@" {
            ""
        } else {
            &spec.subdomain
        };
        let body = json!({"host":host,"type":spec.record_type,"answer":ip,"ttl":spec.ttl});
        let reply = self
            .call(
                "create",
                Method::POST,
                &format!("{}/records", self.domain_path(spec)),
                Some(&body),
                None,
            )
            .await?;
        self.ack(spec, &ip, None, &reply, "create")
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let ip = self.ip(spec, ip)?;
        self.selection(spec, record)?;
        self.zone(spec).await?;
        let path = format!("{}/records/{}", self.domain_path(spec), record.id);
        let fresh = self
            .call("preflight", Method::GET, &path, None, None)
            .await?;
        let actual = self.record(spec, &fresh.body, "preflight", Some(&fresh))?;
        self.selection(spec, &actual)?;
        if actual.id != record.id || actual.extra != record.extra {
            return Err(self.error(
                "preflight",
                "RecordChanged",
                "Selected record changed or vanished after listing; no mutation attempted.",
                Some(&fresh),
            ));
        }
        let mut body = json!({"host":record.extra["host"],"type":record.record_type,"answer":ip,"ttl":spec.ttl});
        if let Some(priority) = record.extra.get("priority") {
            body["priority"] = priority.clone();
        }
        let reply = self
            .call("update", Method::PUT, &path, Some(&body), None)
            .await?;
        self.ack(spec, &ip, Some(record), &reply, "update")
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
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn record_host(s: &str) -> bool {
    matches!(s, "" | "@")
        || (s.len() <= 253
            && s.split('.').enumerate().all(|(i, label)| {
                (i == 0 && label == "*")
                    || (!label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
            }))
}
fn decimal_id(value: &Value) -> Option<String> {
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
    (n > 0 && n <= i32::MAX as u64).then(|| n.to_string())
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
    struct StateData {
        replies: Arc<Mutex<VecDeque<(u16, String)>>>,
        calls: Arc<Mutex<Vec<Capture>>>,
    }
    struct Mock {
        provider: NameCom,
        calls: Arc<Mutex<Vec<Capture>>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(State(state): State<StateData>, request: Request) -> Response {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        state.calls.lock().unwrap().push(Capture {
            method: parts.method,
            uri: parts.uri.to_string(),
            auth: parts.headers["authorization"].to_str().unwrap().into(),
            content_type: parts
                .headers
                .get("content-type")
                .map(|h| h.to_str().unwrap().into()),
            body: if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        });
        let (status, body) = state
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or((500, "{\"message\":\"unexpected request\"}".into()));
        (
            StatusCode::from_u16(status).unwrap(),
            [
                ("x-request-id", "mock-trace"),
                ("x-ratelimit-reset", "1747668270"),
            ],
            body,
        )
            .into_response()
    }
    async fn mock_raw(replies: Vec<(u16, String)>) -> Mock {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let state = StateData {
            replies: Arc::new(Mutex::new(replies.into())),
            calls: calls.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/core/v1", listener.local_addr().unwrap());
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
        let mut provider = NameCom::new(
            client,
            "mock-user-secret".into(),
            "mock-token-secret".into(),
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
        mock_raw(replies.into_iter().map(|v| (200, v.to_string())).collect()).await
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
    fn zone() -> Value {
        json!({"domainName":"example.com","locks":["clientTransferProhibited"]})
    }
    fn raw(id: u64, host: &str, kind: &str, ip: &str, ttl: u64) -> Value {
        let fqdn = if matches!(host, "" | "@") {
            "example.com.".into()
        } else {
            format!("{host}.example.com.")
        };
        json!({"id":id,"domainName":"example.com","host":host,"fqdn":fqdn,"type":kind,"answer":ip,"ttl":ttl})
    }
    fn record() -> Value {
        raw(123, "home", "A", "1.1.1.1", 600)
    }
    fn page(records: Vec<Value>) -> Value {
        let n = records.len();
        json!({"records":records,"totalCount":n,"from":if n == 0 {0} else {1},"to":n})
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
        let expected = format!(
            "Basic {}",
            STANDARD.encode("mock-user-secret:mock-token-secret")
        );
        for c in m.calls.lock().unwrap().iter() {
            assert_eq!(c.auth, expected);
            assert!(!c.uri.contains("secret"));
            if c.method != Method::GET {
                assert_eq!(c.content_type.as_deref(), Some("application/json"));
            } else {
                assert!(c.body.is_null());
            }
        }
    }
    #[tokio::test]
    async fn complete_pagination_keeps_all_types_and_metadata() {
        let mut first =
            json!({"records":[record()],"totalCount":3,"from":1,"to":1,"nextPage":2,"lastPage":3});
        first["records"][0]["priority"] = json!(0);
        let m = mock(vec![zone(), first, json!({"records":[raw(124,"*","TXT","text",600)],"totalCount":3,"from":2,"to":2,"nextPage":3,"lastPage":3}), json!({"records":[raw(125,"_sip._tcp","SRV","1 123 target",600)],"totalCount":3,"from":3,"to":3})]).await;
        let list = m.provider.list(&spec()).await.unwrap();
        assert_eq!(list.records.len(), 3);
        assert_eq!(list.records[0].id, "123");
        assert_eq!(list.records[0].extra["priority"], 0);
        assert_eq!(list.request_id.as_deref(), Some("mock-trace"));
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls[0].uri, "/core/v1/domains/example.com");
        for i in 1..=3 {
            assert_eq!(
                calls[i].uri,
                format!("/core/v1/domains/example.com/records?page={i}&perPage=500")
            );
        }
        drop(calls);
        credentials(&m);
        no_writes(&m);
    }
    #[tokio::test]
    async fn pagination_accepts_zero_or_one_based_ranges_but_not_mixed() {
        for base in [0, 1] {
            let first = json!({"records":[record()],"from":base,"to":base,"totalCount":2,"nextPage":2,"lastPage":2});
            let second = json!({"records":[raw(124,"other","A","2.2.2.2",600)],"from":base+1,"to":base+1,"totalCount":2});
            let m = mock(vec![zone(), first.clone(), second]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap().records.len(), 2);
            no_writes(&m);
            let mixed = json!({"records":[raw(124,"other","A","2.2.2.2",600)],"from":2-base,"to":2-base,"totalCount":2});
            let m = mock(vec![zone(), first, mixed]).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "IncompletePagination"
            );
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn dry_run_create_update_and_noop_never_write() {
        for (values, create, ip, status) in [
            (vec![], true, "8.8.8.8", "would_create"),
            (vec![record()], false, "8.8.8.8", "would_update"),
            (vec![record()], false, "1.1.1.1", "unchanged"),
        ] {
            let m = mock(vec![zone(), page(values)]).await;
            let mut s = spec();
            s.create_if_missing = create;
            assert_eq!(
                reconcile(&m.provider, &s, ip, true).await.unwrap().status,
                status
            );
            no_writes(&m);
            assert_eq!(m.calls.lock().unwrap().len(), 2);
        }
    }
    #[tokio::test]
    async fn update_exact_id_preserves_metadata_full_body() {
        let mut old = record();
        old["priority"] = json!(0);
        let mut ack = old.clone();
        ack["answer"] = json!("8.8.8.8");
        ack["ttl"] = json!(300);
        let m = mock(vec![zone(), page(vec![old.clone()]), zone(), old, ack]).await;
        let mut s = spec();
        s.ttl = 300;
        s.record_id = Some("123".into());
        let out = reconcile(&m.provider, &s, "8.8.8.8", false).await.unwrap();
        assert_eq!(out.status, "updated");
        assert_eq!(out.record_id.as_deref(), Some("123"));
        let calls = m.calls.lock().unwrap();
        assert_eq!(calls[3].method, Method::GET);
        assert_eq!(calls[3].uri, "/core/v1/domains/example.com/records/123");
        assert_eq!(calls[4].method, Method::PUT);
        assert_eq!(calls[4].uri, calls[3].uri);
        assert_eq!(
            calls[4].body,
            json!({"host":"home","type":"A","answer":"8.8.8.8","ttl":300,"priority":0})
        );
        drop(calls);
        credentials(&m);
    }
    #[tokio::test]
    async fn create_apex_and_ipv6_verify_complete_ack() {
        for (host, kind, ip) in [("@", "A", "8.8.8.8"), ("home", "AAAA", "2001:db8::1")] {
            let wire_host = if host == "@" { "" } else { host };
            let m = mock(vec![
                zone(),
                page(vec![]),
                zone(),
                page(vec![]),
                raw(456, wire_host, kind, ip, 600),
            ])
            .await;
            let mut s = spec();
            s.subdomain = host.into();
            s.record_type = kind.into();
            s.create_if_missing = true;
            assert_eq!(
                reconcile(&m.provider, &s, ip, false).await.unwrap().status,
                "created"
            );
            assert_eq!(
                m.calls.lock().unwrap()[4].body,
                json!({"host":wire_host,"type":kind,"answer":ip,"ttl":600})
            );
            credentials(&m);
        }
    }
    #[tokio::test]
    async fn ambiguous_missing_id_mismatch_and_disabled_fail_closed() {
        let mut disabled = record();
        disabled["enabled"] = json!(false);
        for (values, id, code) in [
            (
                vec![record(), raw(124, "home", "A", "2.2.2.2", 600)],
                None,
                "AmbiguousRecords",
            ),
            (vec![record()], Some("999"), "RecordIdNotFound"),
            (
                vec![raw(123, "other", "A", "1.1.1.1", 600)],
                Some("123"),
                "RecordIdMismatch",
            ),
            (vec![disabled], None, "RecordDisabled"),
        ] {
            let m = mock(vec![zone(), page(values)]).await;
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
        // Explicit ID resolves same-host ambiguity without choosing the first.
        let m = mock(vec![
            zone(),
            page(vec![record(), raw(124, "home", "A", "2.2.2.2", 600)]),
        ])
        .await;
        let mut s = spec();
        s.record_id = Some("124".into());
        let out = reconcile(&m.provider, &s, "8.8.8.8", true).await.unwrap();
        assert_eq!(out.previous_ip.as_deref(), Some("2.2.2.2"));
        no_writes(&m);
    }
    #[tokio::test]
    async fn unsafe_settings_are_refused_even_on_noop_and_dry_run() {
        for (key, value) in [
            ("priority", json!(5)),
            ("priority", json!("0")),
            ("enabled", json!(true)),
            ("disabled", json!(false)),
            ("routing", json!("geo")),
            ("notes", json!("preserve me")),
            ("weight", json!(1)),
        ] {
            let mut r = record();
            r[key] = value;
            let m = mock(vec![zone(), page(vec![r])]).await;
            assert_eq!(
                reconcile(&m.provider, &spec(), "1.1.1.1", true)
                    .await
                    .unwrap_err()
                    .code,
                "UnsafeRecordSettings"
            );
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn invalid_config_never_contacts_server() {
        let m = mock(vec![]).await;
        for ttl in [0, 299, 604801, u64::MAX] {
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(
                m.provider.list(&s).await.unwrap_err().code,
                "UnsupportedTTL"
            );
        }
        for name in ["bad/zone", "example.com.", "user@example.com", "例子.com"] {
            let mut s = spec();
            s.domain = name.into();
            assert_eq!(
                m.provider.list(&s).await.unwrap_err().code,
                "InvalidDnsName"
            );
        }
        let mut s = spec();
        s.options
            .insert("endpoint".into(), "http://localhost".into());
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        let mut s = spec();
        s.record_line = "geo".into();
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        for id in ["0", "001", "-1", "2147483648", "a/b"] {
            let mut s = spec();
            s.record_id = Some(id.into());
            assert_eq!(
                m.provider.list(&s).await.unwrap_err().code,
                "InvalidRecordId"
            );
        }
        assert_eq!(
            m.provider.create(&spec(), "not-ip").await.unwrap_err().code,
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
        let mut options = BTreeMap::new();
        options.insert("anything".into(), "x".into());
        let p = NameCom::new(
            reqwest::Client::new(),
            "user".into(),
            "token".into(),
            &options,
        );
        assert_eq!(
            p.validate_spec(&spec()).unwrap_err().code,
            "UnsupportedOptions"
        );
        for (u, t) in [
            ("", "token"),
            ("user", ""),
            ("user:bad", "token"),
            ("user", "token\n"),
        ] {
            let p = NameCom::new(reqwest::Client::new(), u.into(), t.into(), &BTreeMap::new());
            assert_eq!(
                p.validate_spec(&spec()).unwrap_err().code,
                "InvalidCredentials"
            );
        }
    }
    #[tokio::test]
    async fn zone_read_mismatch_hold_and_notfound_never_create() {
        for (value, code) in [
            (json!({"domainName":"elsewhere.com"}), "ZoneMismatch"),
            (json!({}), "ZoneMismatch"),
            (
                json!({"domainName":"example.com","locks":["serverHold"]}),
                "ZoneOnHold",
            ),
            (
                json!({"domainName":"example.com","locks":"bad"}),
                "MalformedZone",
            ),
        ] {
            let m = mock(vec![value]).await;
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
        let m = mock_raw(vec![(
            404,
            json!({"message":"Not Found","details":"domain invisible"}).to_string(),
        )])
        .await;
        let mut s = spec();
        s.create_if_missing = true;
        let e = reconcile(&m.provider, &s, "8.8.8.8", false)
            .await
            .unwrap_err();
        assert_eq!(e.http_status, Some(404));
        assert!(e.message.contains("domain invisible"));
        no_writes(&m);
    }
    #[tokio::test]
    async fn malformed_records_and_wrong_zones_are_not_filtered_away() {
        for (key, value, code) in [
            ("domainName", json!("other.com"), "RecordZoneMismatch"),
            ("fqdn", json!("other.example.com."), "MalformedRecord"),
            ("host", Value::Null, "MalformedRecord"),
            ("id", json!(0), "MalformedRecord"),
            ("id", json!(2147483648u64), "MalformedRecord"),
            ("ttl", json!(299), "MalformedRecord"),
            ("answer", Value::Null, "MalformedRecord"),
        ] {
            let mut r = record();
            r[key] = value;
            let m = mock(vec![zone(), page(vec![r])]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn pagination_missing_truncated_loop_gap_counts_and_duplicate_ids_fail() {
        let valid = page(vec![record()]);
        let mut cases = vec![json!({"records":[]})];
        for (key, value) in [
            ("totalCount", json!(2)),
            ("from", json!(0)),
            ("to", json!(2)),
            ("nextPage", json!(1)),
            ("nextPage", json!("2")),
            ("lastPage", json!(2)),
            ("totalCount", json!(10001)),
            ("truncated", json!(true)),
            ("cursor", json!("next")),
        ] {
            let mut p = valid.clone();
            p[key] = value;
            cases.push(p);
        }
        for p in cases {
            let m = mock(vec![zone(), p]).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "IncompletePagination"
            );
            no_writes(&m);
        }
        let first =
            json!({"records":[record()],"from":1,"to":1,"totalCount":2,"nextPage":2,"lastPage":2});
        for (second, code) in [
            (
                json!({"records":[record()],"from":2,"to":2,"totalCount":2}),
                "UnstableRecordList",
            ),
            (
                json!({"records":[raw(124,"other","A","2.2.2.2",600)],"from":2,"to":2,"totalCount":3}),
                "IncompletePagination",
            ),
            (
                json!({"records":[],"from":0,"to":0,"totalCount":2}),
                "IncompletePagination",
            ),
        ] {
            let m = mock(vec![zone(), first.clone(), second]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn preflight_changed_record_and_create_race_refuse_writes() {
        let mut changed = record();
        changed["answer"] = json!("9.9.9.9");
        let m = mock(vec![zone(), page(vec![record()]), zone(), changed]).await;
        assert_eq!(
            reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordChanged"
        );
        no_writes(&m);
        for r in [
            record(),
            raw(125, "home", "CNAME", "target.example.com", 600),
        ] {
            let m = mock(vec![zone(), page(vec![]), zone(), page(vec![r])]).await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                reconcile(&m.provider, &s, "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "RecordAppeared"
            );
            no_writes(&m);
        }
    }
    #[tokio::test]
    async fn ack_checks_immutable_target_and_mutable_result() {
        let good = raw(123, "home", "A", "8.8.8.8", 600);
        for (key, value) in [
            ("id", json!(124)),
            ("domainName", json!("other.com")),
            ("host", json!("other")),
            ("fqdn", json!("other.example.com.")),
            ("type", json!("AAAA")),
            ("answer", json!("9.9.9.9")),
            ("ttl", json!(300)),
            ("priority", json!(5)),
            ("enabled", json!(true)),
        ] {
            let mut ack = good.clone();
            ack[key] = value;
            let m = mock(vec![zone(), page(vec![record()]), zone(), record(), ack]).await;
            let e = reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "InvalidWriteAcknowledgement");
            assert_eq!(e.http_status, Some(200));
            assert!(!e.retryable);
            assert_eq!(
                m.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|c| c.method == Method::PUT)
                    .count(),
                1
            );
        }
        let m = mock(vec![
            zone(),
            page(vec![]),
            zone(),
            page(vec![]),
            json!({"id":456}),
        ])
        .await;
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
    async fn detailed_http_business_errors_redact_plain_and_encoded_credentials() {
        let encoded = STANDARD.encode("mock-user-secret:mock-token-secret");
        for status in [200, 400, 401, 403, 429, 500, 503] {
            let body = json!({"code":"Denied","message":"Bad mock-token-secret on zone","details":format!("user mock-user-secret Basic {encoded}; field ttl too small")});
            let m = mock_raw(vec![(status, body.to_string())]).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "Denied");
            assert_eq!(e.http_status, Some(status));
            assert_eq!(e.request_id.as_deref(), Some("mock-trace"));
            assert!(e.message.contains("field ttl too small"));
            assert!(e.message.contains("1747668270"));
            assert!(!e.message.contains("mock-token-secret"));
            assert!(!e.message.contains("mock-user-secret"));
            assert!(!e.message.contains(&encoded));
            assert!(!e.retryable);
            no_writes(&m);
        }
        let m = mock_raw(vec![(200, "<html>mock-token-secret</html>".into())]).await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "MalformedResponse");
        assert!(!e.message.contains("mock-token-secret"));
        let m = mock_raw(vec![(302, json!({}).to_string())]).await;
        assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, "Http302");
        assert_eq!(m.calls.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn write_failure_is_not_retried() {
        let m = mock_raw(vec![
            (200, zone().to_string()),
            (200, page(vec![record()]).to_string()),
            (200, zone().to_string()),
            (200, record().to_string()),
            (
                503,
                json!({"message":"maintenance","details":"no automatic retry"}).to_string(),
            ),
        ])
        .await;
        let e = reconcile(&m.provider, &spec(), "8.8.8.8", false)
            .await
            .unwrap_err();
        assert_eq!(e.http_status, Some(503));
        assert!(e.message.contains("maintenance"));
        assert!(!e.retryable);
        assert_eq!(m.calls.lock().unwrap().len(), 5);
    }
}
