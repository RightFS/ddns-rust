//! Native deSEC RRsets. Shared client must disable redirects; production endpoint is fixed.
//! API: https://desec.readthedocs.io/en/latest/dns/rrsets.html
//! Domain TTL: https://desec.readthedocs.io/en/latest/dns/domains.html
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use reqwest::{Method, RequestBuilder, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
const ENDPOINT: &str = "https://desec.io/api/v1";
// Deliberately not Debug: never log credentials.
pub struct Desec {
    api: Api,
    token: String,
    #[cfg(test)]
    endpoint: String,
}
impl Desec {
    pub fn new(
        client: reqwest::Client,
        token: String,
        _options: &BTreeMap<String, String>,
    ) -> Self {
        Self {
            api: Api::new(client, vec![token.clone()]),
            token,
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
        self.authorize(
            self.api
                .client
                .request(method, format!("{}{path}", self.endpoint())),
        )
    }
    fn authorize(&self, request: RequestBuilder) -> RequestBuilder {
        match reqwest::header::HeaderValue::from_str(&format!("Token {}", self.token)) {
            Ok(mut value) => {
                value.set_sensitive(true);
                request.header(reqwest::header::AUTHORIZATION, value)
            }
            // Preserve RequestBuilder's standard invalid-header failure without
            // attaching the malformed token to any diagnostic or debug value.
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
        self.api.error(stage, code, message,
            "Check the exact deSEC hosted domain, token validity and domain/subname/type read/write permissions. A 404 may mean the domain is absent or inaccessible; create zones manually, never by DDNS. For HTTP 429 wait for the rate-limit window (Retry-After if present); check provider availability for 5xx. Inspect uncertain writes before retrying; no automatic write retry occurs.", reply)
    }
    fn validate_spec(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.token.trim().is_empty() {
            return Err(self.error(
                "validation",
                "MissingApiToken",
                "deSEC requires a nonempty API token.",
                None,
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "deSEC DDNS supports only A and AAAA.",
                None,
            ));
        }
        if !hostname(&spec.domain, 191)
            || (spec.subdomain != "@" && !hostname(&spec.subdomain, 178))
            || spec.fqdn().len() > 253
        {
            return Err(self.error("validation", "InvalidDnsName", "Use an exact ASCII/punycode zone (maximum191 characters), relative host (maximum178) or @ for apex; URL syntax is forbidden.", None));
        }
        if !(1..=86400).contains(&spec.ttl) {
            return Err(self.error("validation", "UnsupportedTTL", "deSEC TTL must meet domain.minimum_ttl and not exceed86400 seconds; it is never silently clamped.", None));
        }
        Ok(())
    }
    fn validate_ip(&self, spec: &Spec, ip: &str) -> Result<(), ProviderError> {
        self.validate_spec(spec)?;
        let parsed = ip.parse::<IpAddr>().map_err(|_| {
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
                "Desired IP family does not match RRset type.",
                None,
            ));
        }
        Ok(())
    }
    fn check(&self, stage: &str, reply: &HttpReply, write: bool) -> Result<(), ProviderError> {
        if !(200..300).contains(&reply.status) {
            // Extract only standard DRF details/field errors, never raw response
            // JSON or unknown metadata. Api additionally sanitizes credentials.
            let mut e = self.error(
                stage,
                &format!("Http{}", reply.status),
                &format!(
                    "deSEC HTTP {}: {}",
                    reply.status,
                    error_details(&reply.body)
                ),
                Some(reply),
            );
            e.retryable = !write && (reply.status == 429 || reply.status >= 500);
            return Err(e);
        }
        Ok(())
    }
    async fn domain(&self, spec: &Spec) -> Result<(), ProviderError> {
        self.validate_spec(spec)?;
        let stage = "DesecGetDomain";
        let reply = self
            .api
            .send(
                stage,
                self.request(
                    Method::GET,
                    &format!("/domains/{}/", spec.domain.to_ascii_lowercase()),
                ),
                false,
            )
            .await?;
        self.check(stage, &reply, false)?;
        if reply.status != 200
            || !reply.body["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(&spec.domain))
        {
            return Err(self.error(stage, "DomainMismatch", "deSEC did not confirm the exact configured domain; parent/child domains are not interchangeable.", Some(&reply)));
        }
        let minimum = reply.body["minimum_ttl"]
            .as_u64()
            .filter(|ttl| (1..=86400).contains(ttl))
            .ok_or_else(|| {
                self.error(
                    stage,
                    "InvalidDomain",
                    "Domain response lacks a valid minimum_ttl; TTL safety cannot be verified.",
                    Some(&reply),
                )
            })?;
        if spec.ttl < minimum {
            return Err(self.api.error("validation", "UnsupportedTTL", &format!("deSEC TTL for this domain must be {minimum}..86400 seconds (domain.minimum_ttl); requested {}.", spec.ttl),
                "Set TTL to domain.minimum_ttl or higher. Lower values require a support-approved exception; DDNS never clamps TTL.", Some(&reply)));
        }
        Ok(())
    }
    fn rrset(
        &self,
        spec: &Spec,
        value: &Value,
        reply: &HttpReply,
        stage: &str,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error(
                stage,
                "InvalidRRset",
                "RRset has missing/invalid domain, subname, type, records or TTL.",
                Some(reply),
            )
        };
        let subname = value["subname"]
            .as_str()
            .filter(|name| name.is_empty() || rrset_hostname(name))
            .ok_or_else(bad)?;
        let kind = value["type"]
            .as_str()
            .filter(|kind| {
                !kind.is_empty()
                    && kind.len() <= 16
                    && kind
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            })
            .ok_or_else(bad)?;
        if !value["domain"]
            .as_str()
            .is_some_and(|domain| domain.eq_ignore_ascii_case(&spec.domain))
        {
            return Err(self.error(
                stage,
                "RRsetMismatch",
                "deSEC returned an RRset outside the exact configured domain.",
                Some(reply),
            ));
        }
        let name = if subname.is_empty() {
            spec.domain.clone()
        } else {
            format!("{subname}.{}", spec.domain)
        };
        if name.len() > 253 {
            return Err(bad());
        }
        if let Some(full) = value.get("name")
            && !full.as_str().is_some_and(|full| dns_equal(full, &name))
        {
            return Err(self.error(
                stage,
                "RRsetMismatch",
                "RRset full name contradicts its domain/subname.",
                Some(reply),
            ));
        }
        let values = value["records"]
            .as_array()
            .filter(|v| v.len() <= 4091 && v.iter().all(Value::is_string))
            .ok_or_else(bad)?;
        let ttl = value["ttl"]
            .as_u64()
            .filter(|ttl| (1..=86400).contains(ttl))
            .ok_or_else(bad)?;
        // One common Record per RRset. Never expose an arbitrary first value.
        let ip = if values.len() == 1 && matches!(kind, "A" | "AAAA") {
            values[0]
                .as_str()
                .and_then(|v| v.parse::<IpAddr>().ok())
                .filter(|ip| ip.is_ipv4() == (kind == "A"))
                .map(|ip| ip.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Record {
            id: rrset_id(kind, subname),
            name,
            record_type: kind.into(),
            value: ip,
            ttl,
            line: String::new(),
            enabled: true,
            extra: value.clone(),
        })
    }
    fn selection(&self, spec: &Spec, record: &Record) -> Result<(), ProviderError> {
        if record.id != rrset_id(&spec.record_type, &subname_for(spec))
            || !dns_equal(&record.name, &spec.fqdn())
            || record.record_type != spec.record_type
        {
            return Err(self.error(
                "selection",
                "RRsetMismatch",
                "Selected synthetic RRset ID/name/type does not identify the configured target.",
                None,
            ));
        }
        let values = record.extra["records"].as_array().ok_or_else(|| {
            self.error(
                "selection",
                "InvalidRRset",
                "Selected RRset metadata lacks records.",
                None,
            )
        })?;
        if values.len() != 1 {
            return Err(self.api.error("selection", "UnsafeRRsetValues", "Selected deSEC RRset does not contain exactly one value; replacing it could remove other DNS values.",
                "Use a dedicated single-IP A/AAAA RRset for DDNS. Remove extra values deliberately in deSEC only if intended; record_id selects the entire RRset, not an individual value.", None));
        }
        if !values[0]
            .as_str()
            .and_then(|v| v.parse::<IpAddr>().ok())
            .is_some_and(|ip| {
                ip.is_ipv4() == (spec.record_type == "A") && ip.to_string() == record.value
            })
        {
            return Err(self.error("selection", "InvalidRecordValue", "Single RRset value is not a valid IP of the expected family or contradicts selection metadata.", None));
        }
        if !record.extra["subname"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(&subname_for(spec)))
            || record.extra["type"].as_str() != Some(&spec.record_type)
            || !record.extra["domain"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(&spec.domain))
        {
            return Err(self.error(
                "selection",
                "RRsetMismatch",
                "Selected RRset metadata contradicts target identity.",
                None,
            ));
        }
        Ok(())
    }
    fn mutation(
        &self,
        spec: &Spec,
        ip: &str,
        reply: &HttpReply,
        stage: &str,
        status: u16,
    ) -> Result<Mutation, ProviderError> {
        self.check(stage, reply, true)?;
        if reply.status != status {
            return Err(self.error(stage, "InvalidWriteAcknowledgement", "Unexpected write status (204 means RRset deletion). Result is uncertain; inspect deSEC before retrying.", Some(reply)));
        }
        let record = self.rrset(spec, &reply.body, reply, stage)?;
        if record.id != rrset_id(&spec.record_type, &subname_for(spec))
            || record.extra["records"]
                .as_array()
                .is_none_or(|v| v.len() != 1)
            || record.value
                != ip
                    .parse::<IpAddr>()
                    .map(|ip| ip.to_string())
                    .unwrap_or_default()
            || record.ttl != spec.ttl
        {
            return Err(self.error(stage, "InvalidWriteAcknowledgement", "Returned RRset does not confirm target identity, exactly the desired single IP and TTL. Inspect uncertain write before retrying.", Some(reply)));
        }
        Ok(Mutation {
            record_id: record.id,
            request_id: reply.request_id.clone(),
        })
    }
    fn next_page(
        &self,
        spec: &Spec,
        current: &Url,
        reply: &HttpReply,
    ) -> Result<Option<Url>, ProviderError> {
        let bad = || {
            self.error("DesecListRRsets", "UnsafePagination", "deSEC Link pagination is malformed, duplicated or points outside the fixed domain RRset endpoint; no partial list is returned.", Some(reply))
        };
        let base = Url::parse(&format!(
            "{}/domains/{}/rrsets/",
            self.endpoint(),
            spec.domain.to_ascii_lowercase()
        ))
        .map_err(|_| bad())?;
        let mut next = None;
        for header in reply.headers.get_all(reqwest::header::LINK) {
            let header = header.to_str().map_err(|_| bad())?;
            for link in header.split(',') {
                let (target, params) = link.trim().split_once('>').ok_or_else(bad)?;
                let target = target.strip_prefix('<').ok_or_else(bad)?;
                let relations: Vec<_> = params
                    .split(';')
                    .filter_map(|p| p.trim().strip_prefix("rel="))
                    .collect();
                if relations.len() != 1 {
                    return Err(bad());
                }
                let raw_relation = relations[0];
                if raw_relation.starts_with('"') != raw_relation.ends_with('"') {
                    return Err(bad());
                }
                let relation = raw_relation.trim_matches('"');
                if relation.contains('"') || relation.is_empty() {
                    return Err(bad());
                }
                if !relation.split_whitespace().any(|r| r == "next") {
                    continue;
                }
                if next.is_some() {
                    return Err(bad());
                }
                let url = current.join(target).map_err(|_| bad())?;
                // Auth tokens are attached only AFTER this strict origin/path check.
                // Cursor is opaque; no unrelated or credential-bearing query allowed.
                if url.scheme() != base.scheme()
                    || url.host_str() != base.host_str()
                    || url.port_or_known_default() != base.port_or_known_default()
                    || url.path() != base.path()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.fragment().is_some()
                {
                    return Err(bad());
                }
                let pairs: Vec<_> = url.query_pairs().collect();
                if pairs.len() != 1
                    || pairs[0].0 != "cursor"
                    || pairs[0].1.is_empty()
                    || pairs[0].1.contains(&self.token)
                    || pairs[0].1.chars().any(char::is_control)
                {
                    return Err(bad());
                }
                next = Some(url);
            }
        }
        Ok(next)
    }
}
impl Adapter for Desec {
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
        let stage = "DesecListRRsets";
        let mut url = Url::parse(&format!(
            "{}/domains/{}/rrsets/?cursor=",
            self.endpoint(),
            spec.domain.to_ascii_lowercase()
        ))
        .map_err(|_| {
            self.error(
                stage,
                "InvalidDnsName",
                "Cannot construct safe RRset URL.",
                None,
            )
        })?;
        let mut urls = HashSet::new();
        let mut ids = HashSet::new();
        let mut records = Vec::new();
        for _ in 0..100 {
            if !urls.insert(url.as_str().to_owned()) {
                return Err(self.error(
                    stage,
                    "UnstablePagination",
                    "Pagination repeated a URL; no partial record list is returned.",
                    None,
                ));
            }
            let request = self.authorize(self.api.client.get(url.clone()));
            let reply = self.api.send(stage, request, false).await?;
            self.check(stage, &reply, false)?;
            let values = reply
                .body
                .as_array()
                .filter(|v| v.len() <= 500)
                .ok_or_else(|| {
                    self.error(
                        stage,
                        "InvalidRRsetList",
                        "deSEC paginated RRsets response must be an array of at most500 RRsets.",
                        Some(&reply),
                    )
                })?;
            if reply.status != 200 || records.len() + values.len() > 10000 {
                return Err(self.error(
                    stage,
                    "RecordLimit",
                    "RRset listing exceeded10000 records or returned an unexpected status.",
                    Some(&reply),
                ));
            }
            for value in values {
                let record = self.rrset(spec, value, &reply, stage)?;
                if !ids.insert(record.id.clone()) {
                    return Err(self.error(
                        stage,
                        "UnstablePagination",
                        "deSEC repeated an RRset ID across pages; safe selection stopped.",
                        Some(&reply),
                    ));
                }
                records.push(record);
            }
            match self.next_page(spec, &url, &reply)? {
                Some(next) => url = next,
                None => {
                    return Ok(List {
                        records,
                        request_id: reply.request_id,
                    });
                }
            }
        }
        Err(self.error(
            stage,
            "PaginationLimit",
            "RRset listing exceeded100 pages; no partial list is returned.",
            None,
        ))
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate_ip(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error("create", "CreationNotAllowed", "Creation requires create_if_missing and no explicit record_id; no fallback creation.", None));
        }
        self.domain(spec).await?;
        let stage = "DesecCreateRRset";
        let reply = self.api.send(stage, self.request(Method::POST, &format!("/domains/{}/rrsets/", spec.domain.to_ascii_lowercase()))
            .json(&json!({"subname": subname_for(spec), "type": spec.record_type, "ttl": spec.ttl, "records": [ip]})), true).await?;
        self.mutation(spec, ip, &reply, stage, 201)
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.validate_ip(spec, ip)?;
        self.selection(spec, record)?;
        self.domain(spec).await?;
        let path = format!(
            "/domains/{}/rrsets/{}/{}/",
            spec.domain.to_ascii_lowercase(),
            spec.subdomain.to_ascii_lowercase(),
            spec.record_type
        );
        // Re-read to avoid silently discarding values added after selection. There
        // is no documented conditional write: a single owner is still required.
        let read = self
            .api
            .send("DesecGetRRset", self.request(Method::GET, &path), false)
            .await?;
        self.check("DesecGetRRset", &read, false)?;
        let fresh = self.rrset(spec, &read.body, &read, "DesecGetRRset")?;
        self.selection(spec, &fresh)?;
        if read.status != 200 || fresh.value != record.value || fresh.ttl != record.ttl {
            return Err(self.error(
                "selection",
                "RRsetChanged",
                "RRset changed after selection; no write was attempted.",
                Some(&read),
            ));
        }
        let stage = "DesecUpdateRRset";
        // Only mutable fields: no created/touched/type/subname metadata replay.
        let reply = self
            .api
            .send(
                stage,
                self.request(Method::PATCH, &path)
                    .json(&json!({"records": [ip], "ttl": spec.ttl})),
                true,
            )
            .await?;
        self.mutation(spec, ip, &reply, stage, 200)
    }
}
fn error_details(body: &Value) -> String {
    fn collect(value: &Value, path: &str, depth: usize, out: &mut Vec<String>) {
        if depth > 4 || out.len() >= 16 {
            return;
        }
        match value {
            Value::String(text) => {
                let text: String = text.chars().take(256).collect();
                out.push(if path.is_empty() {
                    text
                } else {
                    format!("{path}: {text}")
                });
            }
            Value::Number(number) if path.ends_with("code") => {
                out.push(format!("{path}: {number}"))
            }
            Value::Array(values) => {
                for (index, value) in values.iter().take(16).enumerate() {
                    collect(value, &format!("{path}[{index}]"), depth + 1, out);
                }
            }
            Value::Object(object) => {
                for key in [
                    "detail",
                    "message",
                    "error",
                    "code",
                    "non_field_errors",
                    "records",
                    "ttl",
                    "domain",
                    "name",
                    "subname",
                    "type",
                ] {
                    if let Some(value) = object.get(key) {
                        let path = if path.is_empty() {
                            key.to_owned()
                        } else {
                            format!("{path}.{key}")
                        };
                        collect(value, &path, depth + 1, out);
                    }
                }
            }
            _ => {}
        }
    }
    let mut details = Vec::new();
    collect(body, "", 0, &mut details);
    if details.is_empty() {
        "Provider returned no recognized error details; raw response omitted.".into()
    } else {
        details.join("; ")
    }
}
fn subname_for(spec: &Spec) -> String {
    if spec.subdomain == "@" {
        String::new()
    } else {
        spec.subdomain.to_ascii_lowercase()
    }
}
fn rrset_id(kind: &str, subname: &str) -> String {
    // Hex encodes wildcard/underscore labels as needed to fit common's safe ID
    // alphabet. Prefixes separate readable, escaped, and hashed namespaces.
    let host = subname.to_ascii_lowercase();
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
fn dns_equal(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}
fn hostname(name: &str, maximum: usize) -> bool {
    !name.is_empty()
        && name.len() <= maximum
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn rrset_hostname(name: &str) -> bool {
    // Full zone reads must support unrelated _service and wildcard RRsets.
    name.len() <= 178
        && name.split('.').enumerate().all(|(index, label)| {
            !label.is_empty()
                && label.len() <= 63
                && (label == "*" && index == 0
                    || label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
        })
}

#[cfg(test)]
mod tests {
    use super::super::common::reconcile;
    use super::*;
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::{Request, State},
        http::{HeaderValue, StatusCode},
        response::{IntoResponse, Response},
        routing::any,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    #[derive(Clone)]
    struct Captured {
        method: Method,
        uri: String,
        auth: Option<String>,
        body: Value,
    }
    struct Reply {
        status: u16,
        body: Value,
        link: Option<String>,
    }
    struct StateData {
        replies: VecDeque<Reply>,
        requests: Vec<Captured>,
    }
    struct Mock {
        endpoint: String,
        state: Arc<Mutex<StateData>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(
        State(state): State<Arc<Mutex<StateData>>>,
        request: Request<Body>,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let captured = Captured {
            method: parts.method,
            uri: parts.uri.to_string(),
            auth: parts
                .headers
                .get("authorization")
                .map(|h| h.to_str().unwrap().into()),
            body: if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        };
        let reply = {
            let mut s = state.lock().unwrap();
            s.requests.push(captured);
            s.replies.pop_front().unwrap_or(Reply {
                status: 500,
                body: json!({"detail":"Unexpected request"}),
                link: None,
            })
        };
        let mut response = if reply.status == 204 {
            StatusCode::NO_CONTENT.into_response()
        } else {
            (
                StatusCode::from_u16(reply.status).unwrap(),
                Json(reply.body),
            )
                .into_response()
        };
        if let Some(link) = reply.link {
            response
                .headers_mut()
                .insert(reqwest::header::LINK, HeaderValue::from_str(&link).unwrap());
        }
        response
    }
    impl Mock {
        async fn new(replies: Vec<Reply>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let state = Arc::new(Mutex::new(StateData {
                replies: replies.into(),
                requests: vec![],
            }));
            let router = Router::new()
                .route("/{*path}", any(handler))
                .with_state(state.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            Self {
                endpoint,
                state,
                task,
            }
        }
        fn adapter(&self) -> Desec {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let mut adapter = Desec::new(client, "secret-test-token".into(), &BTreeMap::new());
            adapter.endpoint = self.endpoint.clone();
            adapter
        }
        fn requests(&self) -> Vec<Captured> {
            self.state.lock().unwrap().requests.clone()
        }
        fn done(&self) {
            assert!(self.state.lock().unwrap().replies.is_empty());
        }
        fn reads_only(&self) {
            assert!(self.requests().iter().all(|r| r.method == Method::GET));
            self.done();
        }
    }
    fn reply(status: u16, body: Value) -> Reply {
        Reply {
            status,
            body,
            link: None,
        }
    }
    fn page(body: Value, link: &str) -> Reply {
        Reply {
            status: 200,
            body,
            link: Some(link.into()),
        }
    }
    fn spec() -> Spec {
        Spec {
            domain: "example.com".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "默认".into(),
            ttl: 3600,
            record_id: None,
            create_if_missing: true,
            options: BTreeMap::new(),
        }
    }
    fn domain(minimum: u64) -> Reply {
        reply(200, json!({"name":"example.com","minimum_ttl":minimum}))
    }
    fn rrset(values: &[&str]) -> Value {
        json!({"domain":"example.com","subname":"home","name":"home.example.com.","type":"A","ttl":3600,"records":values,"created":"keep-created","touched":"keep-touched"})
    }
    fn list(values: &[&str]) -> Reply {
        reply(200, json!([rrset(values)]))
    }
    fn named(host: &str) -> Value {
        let mut v = rrset(&["192.0.2.1"]);
        v["subname"] = json!(host);
        v["name"] = json!(format!("{host}.example.com."));
        v
    }

    #[tokio::test]
    async fn verifies_exact_domain_and_token_auth() {
        let mock = Mock::new(vec![domain(3600), list(&["192.0.2.1"])]).await;
        let records = mock.adapter().list(&spec()).await.unwrap().records;
        assert_eq!(records[0].id, "A.home");
        assert_eq!(records[0].value, "192.0.2.1");
        let requests = mock.requests();
        assert_eq!(requests[0].uri, "/domains/example.com/");
        assert_eq!(requests[1].uri, "/domains/example.com/rrsets/?cursor=");
        for r in requests {
            assert_eq!(r.auth.as_deref(), Some("Token secret-test-token"));
            assert!(!r.uri.contains("secret"));
        }
        mock.reads_only();
    }
    #[tokio::test]
    async fn complete_link_pagination_retains_unrelated_rrsets() {
        let mock = Mock::new(vec![
            domain(3600),
            page(
                json!([rrset(&["192.0.2.1"])]),
                "</domains/example.com/rrsets/?cursor=next>; rel=\"next\"",
            ),
            reply(200, json!([named("other")])),
        ])
        .await;
        let result = mock.adapter().list(&spec()).await.unwrap();
        assert_eq!(result.records.len(), 2);
        assert_eq!(result.records[1].id, "A.other");
        assert_eq!(
            mock.requests()[2].uri,
            "/domains/example.com/rrsets/?cursor=next"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn domain_mismatch_stops_before_records() {
        let mock = Mock::new(vec![reply(
            200,
            json!({"name":"child.example.com","minimum_ttl":3600}),
        )])
        .await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "DomainMismatch"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn domain_permission_failures_preserve_details_without_token() {
        for status in [401, 403, 404] {
            let mock = Mock::new(vec![reply(
                status,
                json!({"detail":"Domain inaccessible secret-test-token"}),
            )])
            .await;
            let e = mock.adapter().list(&spec()).await.unwrap_err();
            assert_eq!(e.code, format!("Http{status}"));
            assert_eq!(e.http_status, Some(status));
            assert!(e.request_id.is_none());
            assert!(e.message.contains("Domain inaccessible"));
            assert!(!e.message.contains("secret-test-token"));
            assert!(e.hint.contains("permissions"));
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn multivalue_is_one_record_no_arbitrary_value_and_no_dryrun_write() {
        let mock = Mock::new(vec![domain(3600), list(&["192.0.2.1", "192.0.2.2"])]).await;
        let records = mock.adapter().list(&spec()).await.unwrap().records;
        assert_eq!(records.len(), 1);
        assert!(records[0].value.is_empty());
        let e = mock
            .adapter()
            .validate_selection(&spec(), Some(&records[0]))
            .unwrap_err();
        assert_eq!(e.code, "UnsafeRRsetValues");
        assert!(e.hint.contains("dedicated"));
        mock.reads_only();
        let mock = Mock::new(vec![domain(3600), list(&["192.0.2.1", "192.0.2.2"])]).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.3", true)
                .await
                .unwrap_err()
                .code,
            "UnsafeRRsetValues"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn ttl_minimum_is_authoritative_and_not_clamped() {
        let mut s = spec();
        s.ttl = 900;
        let mock = Mock::new(vec![domain(900), list(&["192.0.2.1"])]).await;
        mock.adapter().list(&s).await.unwrap();
        mock.reads_only();
        s.ttl = 899;
        let mock = Mock::new(vec![domain(900)]).await;
        assert_eq!(
            mock.adapter().list(&s).await.unwrap_err().code,
            "UnsupportedTTL"
        );
        mock.reads_only();
        s.ttl = 86401;
        let mock = Mock::new(vec![]).await;
        assert_eq!(
            mock.adapter().list(&s).await.unwrap_err().code,
            "UnsupportedTTL"
        );
        assert!(mock.requests().is_empty());
        s.ttl = 86400;
        let mock = Mock::new(vec![domain(86400), reply(200, json!([]))]).await;
        mock.adapter().list(&s).await.unwrap();
        mock.reads_only();
    }
    #[tokio::test]
    async fn missing_domain_minimum_fails_closed() {
        let mock = Mock::new(vec![reply(200, json!({"name":"example.com"}))]).await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "InvalidDomain"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn dryrun_create_update_unchanged_never_write() {
        for (records, ip, status) in [
            (json!([]), "192.0.2.2", "would_create"),
            (json!([rrset(&["192.0.2.1"])]), "192.0.2.2", "would_update"),
            (json!([rrset(&["192.0.2.1"])]), "192.0.2.1", "unchanged"),
        ] {
            let mock = Mock::new(vec![domain(3600), reply(200, records)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), ip, true)
                    .await
                    .unwrap()
                    .status,
                status
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn patch_only_records_and_ttl_preserves_metadata() {
        let mock = Mock::new(vec![
            domain(3600),
            list(&["192.0.2.1"]),
            domain(3600),
            reply(200, rrset(&["192.0.2.1"])),
            reply(200, rrset(&["192.0.2.2"])),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let requests = mock.requests();
        let patch = requests.last().unwrap();
        assert_eq!(patch.method, Method::PATCH);
        assert_eq!(patch.uri, "/domains/example.com/rrsets/home/A/");
        assert_eq!(patch.body, json!({"records":["192.0.2.2"],"ttl":3600}));
        mock.done();
    }
    #[tokio::test]
    async fn prewrite_added_values_and_stale_selection_prevent_patch() {
        for (fresh, code) in [
            (rrset(&["192.0.2.1", "192.0.2.9"]), "UnsafeRRsetValues"),
            (rrset(&["192.0.2.9"]), "RRsetChanged"),
        ] {
            let mock = Mock::new(vec![
                domain(3600),
                list(&["192.0.2.1"]),
                domain(3600),
                reply(200, fresh),
            ])
            .await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn creation_acknowledges_single_value_and_synthetic_id() {
        let mock = Mock::new(vec![
            domain(3600),
            reply(200, json!([])),
            domain(3600),
            reply(201, rrset(&["192.0.2.2"])),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap()
                .record_id
                .as_deref(),
            Some("A.home")
        );
        let r = mock.requests().pop().unwrap();
        assert_eq!(r.method, Method::POST);
        assert_eq!(
            r.body,
            json!({"type":"A","subname":"home","records":["192.0.2.2"],"ttl":3600})
        );
        mock.done();
    }
    #[tokio::test]
    async fn returned_values_ttl_and_identity_must_match() {
        for returned in [
            rrset(&["192.0.2.9"]),
            rrset(&["192.0.2.2", "192.0.2.3"]),
            {
                let mut v = rrset(&["192.0.2.2"]);
                v["ttl"] = json!(7200);
                v
            },
            named("other"),
        ] {
            let mock = Mock::new(vec![domain(3600), reply(201, returned)]).await;
            assert_eq!(
                mock.adapter()
                    .create(&spec(), "192.0.2.2")
                    .await
                    .unwrap_err()
                    .code,
                "InvalidWriteAcknowledgement"
            );
            mock.done();
        }
    }
    #[tokio::test]
    async fn error_arrays_and_429_keep_http_codes_details_without_request_id() {
        let mock=Mock::new(vec![reply(429,json!([{"detail":"Request was throttled","code":"throttled"},{"records":["Try later"]}]))]).await;
        let e = mock.adapter().list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "Http429");
        assert_eq!(e.http_status, Some(429));
        assert!(e.message.contains("throttled") && e.message.contains("Try later"));
        assert!(e.request_id.is_none());
        assert!(e.retryable);
        mock.done();
        let mock = Mock::new(vec![
            domain(3600),
            reply(400, json!([{"records":["Invalid IP"]}])),
        ])
        .await;
        let e = mock
            .adapter()
            .create(&spec(), "192.0.2.2")
            .await
            .unwrap_err();
        assert_eq!(e.code, "Http400");
        assert!(e.message.contains("Invalid IP"));
        assert!(!e.retryable);
        mock.done();
    }
    #[tokio::test]
    async fn apex_create_empty_subname_update_uses_at_path() {
        let mut s = spec();
        s.subdomain = "@".into();
        let mut old = rrset(&["192.0.2.1"]);
        old["subname"] = json!("");
        old["name"] = json!("example.com.");
        let mut new = old.clone();
        new["records"] = json!(["192.0.2.2"]);
        let mock = Mock::new(vec![domain(3600), reply(201, new.clone())]).await;
        assert_eq!(
            mock.adapter()
                .create(&s, "192.0.2.2")
                .await
                .unwrap()
                .record_id,
            "A."
        );
        assert_eq!(mock.requests()[1].body["subname"], json!(""));
        mock.done();
        let mock = Mock::new(vec![
            domain(3600),
            reply(200, json!([old.clone()])),
            domain(3600),
            reply(200, old),
            reply(200, new),
        ])
        .await;
        reconcile(&mock.adapter(), &s, "192.0.2.2", false)
            .await
            .unwrap();
        assert_eq!(mock.requests()[4].uri, "/domains/example.com/rrsets/@/A/");
        mock.done();
    }
    #[tokio::test]
    async fn explicit_wrong_target_is_mismatch_and_missing_id_never_creates() {
        for id in ["A.other", "A.missing"] {
            let mut s = spec();
            s.record_id = Some(id.into());
            let mock = Mock::new(vec![
                domain(3600),
                reply(200, json!([rrset(&["192.0.2.1"]), named("other")])),
            ])
            .await;
            assert_eq!(
                reconcile(&mock.adapter(), &s, "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                if id == "A.other" {
                    "RecordIdMismatch"
                } else {
                    "RecordIdNotFound"
                }
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn zero_values_invalid_ip_or_wrong_family_are_refused() {
        for values in [vec![], vec!["not-an-ip"], vec!["::1"]] {
            let mock = Mock::new(vec![domain(3600), list(&values)]).await;
            assert!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                    .await
                    .is_err()
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn empty_204_is_not_a_successful_update() {
        let mock = Mock::new(vec![
            domain(3600),
            list(&["192.0.2.1"]),
            domain(3600),
            reply(200, rrset(&["192.0.2.1"])),
            reply(204, Value::Null),
        ])
        .await;
        let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(e.code, "InvalidWriteAcknowledgement");
        assert_eq!(e.http_status, Some(204));
        assert!(!e.retryable);
        mock.done();
    }
    #[tokio::test]
    async fn pagination_rejects_token_exfiltration_wrong_paths_and_bad_queries() {
        for target in [
            "https://evil.example/domains/example.com/rrsets/?cursor=x",
            "https://user:pass@desec.io/api/v1/domains/example.com/rrsets/?cursor=x",
            "/domains/other.com/rrsets/?cursor=x",
            "/domains/example.com/rrsets/?cursor=x#fragment",
            "/domains/example.com/rrsets/?cursor=x&token=secret",
            "/domains/example.com/rrsets/?cursor=x&cursor=y",
        ] {
            let mock = Mock::new(vec![
                domain(3600),
                page(
                    json!([rrset(&["192.0.2.1"])]),
                    &format!("<{target}>; rel=\"next\""),
                ),
            ])
            .await;
            assert_eq!(
                mock.adapter().list(&spec()).await.unwrap_err().code,
                "UnsafePagination"
            );
            assert_eq!(mock.requests().len(), 2);
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn duplicate_next_links_and_repeated_cursor_fail_closed() {
        let link = "</domains/example.com/rrsets/?cursor=x>; rel=\"next\"";
        let mock = Mock::new(vec![
            domain(3600),
            page(json!([]), &format!("{link}, {link}")),
        ])
        .await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "UnsafePagination"
        );
        mock.reads_only();
        let mock = Mock::new(vec![
            domain(3600),
            page(json!([rrset(&["192.0.2.1"])]), link),
            page(json!([named("other")]), link),
        ])
        .await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "UnstablePagination"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn repeated_rrset_across_pages_and_later_error_never_return_partial_list() {
        let link = "</domains/example.com/rrsets/?cursor=x>; rel=\"next\"";
        let mock = Mock::new(vec![
            domain(3600),
            page(json!([rrset(&["192.0.2.1"])]), link),
            list(&["192.0.2.1"]),
        ])
        .await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "UnstablePagination"
        );
        mock.reads_only();
        let mock = Mock::new(vec![
            domain(3600),
            page(json!([rrset(&["192.0.2.1"])]), link),
            reply(429, json!({"detail":"Later page throttled"})),
        ])
        .await;
        let e = mock.adapter().list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "Http429");
        assert!(e.message.contains("Later page"));
        mock.reads_only();
    }
    #[tokio::test]
    async fn unrelated_service_wildcard_and_non_ip_rrsets_do_not_block_selection() {
        let mut service = named("_acme-challenge");
        service["type"] = json!("TXT");
        service["records"] = json!(["\"text\""]);
        let mock = Mock::new(vec![
            domain(3600),
            reply(200, json!([service, named("*"), rrset(&["192.0.2.1"])])),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.1", true)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn ipv6_canonical_returned_value_is_accepted() {
        let mut s = spec();
        s.record_type = "AAAA".into();
        let mut v = rrset(&["2001:db8::2"]);
        v["type"] = json!("AAAA");
        let mock = Mock::new(vec![domain(3600), reply(201, v)]).await;
        assert_eq!(
            mock.adapter()
                .create(&s, "2001:0db8:0:0::2")
                .await
                .unwrap()
                .record_id,
            "AAAA.home"
        );
        mock.done();
    }
    #[test]
    fn official_absolute_links_are_valid_but_malformed_relations_are_not() {
        let adapter = Desec::new(
            reqwest::Client::new(),
            "secret-test-token".into(),
            &BTreeMap::new(),
        );
        let current =
            Url::parse("https://desec.io/api/v1/domains/example.com/rrsets/?cursor=").unwrap();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::LINK, HeaderValue::from_static("<https://desec.io/api/v1/domains/example.com/rrsets/?cursor=>; rel=\"first\", <https://desec.io/api/v1/domains/example.com/rrsets/?cursor=opaque%2Bcursor>; rel=\"next\""));
        let mut reply = HttpReply {
            headers,
            body: json!([]),
            status: 200,
            request_id: None,
        };
        assert_eq!(
            adapter
                .next_page(&spec(), &current, &reply)
                .unwrap()
                .unwrap()
                .query(),
            Some("cursor=opaque%2Bcursor")
        );
        for link in [
            "<?cursor=x>; rel=\"next",
            "<?cursor=secret-test-token>; rel=\"next\"",
            "<?cursor=%0A>; rel=\"next\"",
        ] {
            reply
                .headers
                .insert(reqwest::header::LINK, HeaderValue::from_str(link).unwrap());
            assert_eq!(
                adapter
                    .next_page(&spec(), &current, &reply)
                    .unwrap_err()
                    .code,
                "UnsafePagination"
            );
        }
    }
    #[tokio::test]
    async fn creation_optin_and_input_validation_prevent_requests() {
        let mock = Mock::new(vec![]).await;
        let mut s = spec();
        s.create_if_missing = false;
        assert_eq!(
            mock.adapter()
                .create(&s, "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "CreationNotAllowed"
        );
        s.create_if_missing = true;
        s.record_id = Some("A.home".into());
        assert_eq!(
            mock.adapter()
                .create(&s, "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "CreationNotAllowed"
        );
        assert_eq!(
            mock.adapter()
                .create(&spec(), "::1")
                .await
                .unwrap_err()
                .code,
            "IpFamilyMismatch"
        );
        s = spec();
        s.domain = "example.com/escape".into();
        assert_eq!(
            mock.adapter().list(&s).await.unwrap_err().code,
            "InvalidDnsName"
        );
        assert!(mock.requests().is_empty());
        mock.done();
    }
    #[tokio::test]
    async fn errors_exclude_unknown_metadata_and_credentials_but_keep_field_details() {
        let mock = Mock::new(vec![reply(400, json!({
            "detail": "RRset rejected secret-test-token", "code": "invalid",
            "records": ["Expected one valid IP"], "ttl": ["Must exceed domain minimum"],
            "metadata": {"detail": "UNKNOWN-PRIVATE-PAYLOAD", "credential": "OTHER-SECRET"},
            "authorization": "UNRELATED-TOKEN", "request_headers": {"Authorization": "PRIVATE-HEADER"},
            "raw_payload": "PRIVATE-BODY"
        }))]).await;
        let error = mock.adapter().list(&spec()).await.unwrap_err();
        assert!(
            error.message.contains("RRset rejected")
                && error.message.contains("Expected one valid IP")
        );
        assert!(
            error.message.contains("Must exceed domain minimum")
                && error.message.contains("invalid")
        );
        for omitted in [
            "secret-test-token",
            "UNKNOWN-PRIVATE-PAYLOAD",
            "OTHER-SECRET",
            "UNRELATED-TOKEN",
            "PRIVATE-HEADER",
            "PRIVATE-BODY",
            "metadata",
            "request_headers",
        ] {
            assert!(!error.message.contains(omitted));
        }
        assert_eq!(error.http_status, Some(400));
        mock.reads_only();
    }
    #[test]
    fn authorization_is_sensitive_and_malformed_tokens_fail_without_echo() {
        let adapter = Desec::new(
            reqwest::Client::new(),
            "secret-test-token".into(),
            &BTreeMap::new(),
        );
        let request = adapter
            .request(Method::GET, "/domains/example.com/")
            .build()
            .unwrap();
        assert!(request.headers()[reqwest::header::AUTHORIZATION].is_sensitive());
        assert!(!format!("{request:?}").contains("secret-test-token"));
        let adapter = Desec::new(
            reqwest::Client::new(),
            "PRIVATE-MALFORMED\ntoken".into(),
            &BTreeMap::new(),
        );
        let error = adapter
            .request(Method::GET, "/domains/example.com/")
            .build()
            .unwrap_err();
        assert!(!format!("{error:?}").contains("PRIVATE-MALFORMED"));
    }
    #[test]
    fn synthetic_ids_are_stable_safe_distinct_and_bounded() {
        let host = format!("{}.{}.{}", "a".repeat(60), "b".repeat(60), "c".repeat(40));
        let id = rrset_id("AAAA", &host);
        assert!(super::super::common::valid_id(&id));
        assert!(id.len() <= 128);
        assert!(id.starts_with("AAAA.."));
        assert_eq!(id, rrset_id("AAAA", &host.to_ascii_uppercase()));
        assert_ne!(id, rrset_id("A", &host));
        for host in ["", "apex", "*", "_acme-challenge"] {
            assert!(super::super::common::valid_id(&rrset_id("A", host)));
        }
        assert_ne!(rrset_id("A", ""), rrset_id("A", "apex"));
        assert_ne!(
            rrset_id("A", "_acme-challenge"),
            rrset_id("A", "acme-challenge")
        );
    }
}
