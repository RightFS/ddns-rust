//! Vercel DNS, fixed HTTPS host; the supplied client must disable redirects.
//! Verified contracts: https://openapi.vercel.sh
//! https://vercel.com/docs/rest-api/dns/list-existing-dns-records
//! https://vercel.com/docs/rest-api/dns/create-a-dns-record
//! https://vercel.com/docs/rest-api/dns/update-an-existing-dns-record
//! https://vercel.com/docs/rest-api/domains/get-information-for-a-single-domain
//! Current official listing is v5, not upstream's legacy v4. POST acknowledges
//! `uid`; PATCH returns `id` + `recordType` and a separate internal `type`.
// Preserve the application's shared structured ProviderError diagnostic DTO.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec, valid_id};
use crate::provider::ProviderError;
use reqwest::{Method, RequestBuilder};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
const ENDPOINT: &str = "https://api.vercel.com";
const MIN_TTL: u64 = 60;
const API_MAX_TTL: u64 = 2_147_483_647;
// Intersection with application's configuration maximum.
const MAX_TTL: u64 = 604_800;
// Intentionally not Debug: never print credentials.
pub struct Vercel {
    api: Api,
    token: String,
    options: BTreeMap<String, String>,
    #[cfg(test)]
    endpoint: String,
}
impl Vercel {
    pub fn new(client: reqwest::Client, token: String, options: &BTreeMap<String, String>) -> Self {
        Self {
            api: Api::new(client, vec![token.clone()]),
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
    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        // Only locally constructed paths/cursors, never provider links. Scope
        // is teamId only (not slug), and always on the same fixed origin.
        let request = self
            .api
            .client
            .request(method, format!("{}{path}", self.endpoint()));
        let request = if let Some(team) = self.options.get("team_id") {
            request.query(&[("teamId", team)])
        } else {
            request
        };
        match reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.token)) {
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
        self.api.error(stage, code, message,
            "Check the exact verified Vercel DNS zone, token domain permissions and optional team_id (team identifier, not slug). External/delegated DNS and system records require manual management. For 401/403 check token/scope; for 429 wait for rate limits and Retry-After; for 5xx check Vercel availability. Inspect uncertain writes before another attempt; no automatic retry occurs.", reply)
    }
    fn validate_spec(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.token.trim().is_empty() || self.token.chars().any(char::is_control) {
            return Err(self.error(
                "validation",
                "InvalidApiToken",
                "Vercel requires a nonempty token without control characters.",
                None,
            ));
        }
        if self.options.keys().any(|k| k != "team_id")
            || self
                .options
                .get("team_id")
                .is_some_and(|team| !valid_id(team) || team.contains(&self.token))
        {
            return Err(self.error("validation", "UnsupportedOptions", "Only optional team_id is supported; use a plain team identifier, not a slug, endpoint or URL.", None));
        }
        if !spec.options.is_empty() {
            return Err(self.error(
                "validation",
                "UnsupportedRecordOptions",
                "Vercel has no DDNS record options or line concept.",
                None,
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Vercel DDNS supports only A and AAAA; other record types are never converted.",
                None,
            ));
        }
        if !hostname(&spec.domain)
            || !spec.domain.contains('.')
            || (spec.subdomain != "@" && !hostname(&spec.subdomain))
            || spec.fqdn().len() > 253
        {
            return Err(self.error("validation", "InvalidDnsName", "Use an exact ASCII/punycode zone and relative host or @ for apex; URL syntax is forbidden.", None));
        }
        if !(MIN_TTL..=MAX_TTL).contains(&spec.ttl) {
            return Err(self.error("validation", "UnsupportedTTL", "Vercel TTL must be 60..604800 seconds (application maximum; API maximum 2147483647); TTL is never silently clamped.", None));
        }
        if spec.record_id.as_deref().is_some_and(|id| !valid_id(id)) {
            return Err(self.error(
                "validation",
                "InvalidRecordId",
                "record_id must be a plain nonzero string identifier.",
                None,
            ));
        }
        Ok(())
    }
    fn validate_ip(&self, spec: &Spec, ip: &str) -> Result<(), ProviderError> {
        self.validate_spec(spec)?;
        if !ip
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_ipv4() == (spec.record_type == "A"))
        {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "Desired value must be a plain IP address of the configured A/AAAA family.",
                None,
            ));
        }
        Ok(())
    }
    async fn send(
        &self,
        stage: &str,
        request: RequestBuilder,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let reply = self.api.send(stage, request, write).await?;
        self.check(stage, &reply, write)?;
        Ok(reply)
    }
    fn check(&self, stage: &str, reply: &HttpReply, write: bool) -> Result<(), ProviderError> {
        if reply
            .body
            .get("error")
            .is_some_and(|error| !error.is_null())
            || !(200..300).contains(&reply.status)
        {
            let code = reply
                .body
                .pointer("/error/code")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    if !(200..300).contains(&reply.status) {
                        format!("Http{}", reply.status)
                    } else {
                        "ProviderApiError".into()
                    }
                });
            let mut error = self.error(stage, &code, &error_details(&reply.body), Some(reply));
            error.retryable = !write && (reply.status == 429 || reply.status >= 500);
            return Err(error);
        }
        Ok(())
    }
    async fn domain(&self, spec: &Spec) -> Result<HttpReply, ProviderError> {
        self.validate_spec(spec)?;
        let stage = "VercelGetDomain";
        let reply = self
            .send(
                stage,
                self.request(
                    Method::GET,
                    &format!("/v5/domains/{}", spec.domain.to_ascii_lowercase()),
                ),
                false,
            )
            .await?;
        let domain = &reply.body["domain"];
        if !domain["name"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(&spec.domain))
        {
            return Err(self.error(stage, "DomainMismatch", "Vercel did not confirm the exact configured zone; a parent or child domain is not interchangeable.", Some(&reply)));
        }
        if domain["verified"].as_bool() != Some(true) {
            return Err(self.error(
                stage,
                "DomainNotVerified",
                "Exact zone ownership is not verified; DDNS will not verify or create domains.",
                Some(&reply),
            ));
        }
        // Documented serviceType, not guessed NS suffixes, confirms Vercel DNS.
        if domain["serviceType"].as_str() != Some("zeit.world") {
            return Err(self.error(stage, "ExternalDns", "Domain serviceType does not confirm Vercel DNS management (zeit.world); external/na DNS is refused.", Some(&reply)));
        }
        for key in ["readOnly", "readonly", "read_only"] {
            if domain.get(key).is_some_and(|v| v.as_bool() != Some(false)) {
                return Err(self.error(
                    stage,
                    "ReadOnlyDomain",
                    "Domain is marked read-only or returned an invalid read-only flag.",
                    Some(&reply),
                ));
            }
        }
        Ok(reply)
    }
    fn record(&self, value: &Value, reply: &HttpReply) -> Result<Record, ProviderError> {
        let bad = || {
            self.error("VercelListRecords", "InvalidRecord", "DNS record has missing/invalid string ID, name, type, value, creator or TTL; raw record omitted.", Some(reply))
        };
        let id = value["id"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or_else(bad)?;
        let name = value["name"]
            .as_str()
            .filter(|name| record_name(name))
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
        let content = value["value"].as_str().ok_or_else(bad)?;
        value["creator"].as_str().ok_or_else(bad)?;
        // TTL is optional in the official list schema. No guessed default:
        // selected absent TTL fails in the hook before dry-run/no-op success.
        let ttl = match value.get("ttl") {
            None => 0,
            Some(ttl) => ttl
                .as_u64()
                .filter(|ttl| (MIN_TTL..=API_MAX_TTL).contains(ttl))
                .ok_or_else(bad)?,
        };
        if value
            .get("recordType")
            .is_some_and(|v| v.as_str() != Some(kind))
        {
            return Err(bad());
        }
        Ok(Record {
            id: id.into(),
            // Common uses @ for apex; extra preserves actual empty provider name.
            name: if name.is_empty() {
                "@".into()
            } else {
                name.into()
            },
            record_type: kind.into(),
            value: content.into(),
            ttl,
            line: String::new(),
            enabled: true,
            extra: value.clone(),
        })
    }
    fn selection(&self, spec: &Spec, record: &Record) -> Result<(), ProviderError> {
        let fail = |code, message| self.error("selection", code, message, None);
        if !valid_id(&record.id)
            || record.extra["id"].as_str() != Some(&record.id)
            || record.record_type != spec.record_type
            || record.extra["type"].as_str() != Some(&record.record_type)
            || !same_target(&record.name, spec)
            || !record.line.is_empty()
            || !record.extra["name"]
                .as_str()
                .is_some_and(|name| same_target(if name.is_empty() { "@" } else { name }, spec))
        {
            return Err(fail(
                "RecordMismatch",
                "Selected record ID, actual name/type or metadata does not identify the configured target; no type conversion is permitted.",
            ));
        }
        if record.extra["value"].as_str() != Some(&record.value) {
            return Err(fail(
                "RecordMismatch",
                "Selected record value contradicts the original provider metadata.",
            ));
        }
        if !(MIN_TTL..=API_MAX_TTL).contains(&record.ttl)
            || record.extra["ttl"].as_u64() != Some(record.ttl)
        {
            return Err(fail(
                "InvalidRecordTTL",
                "Selected record lacks a documented integer TTL of 60..2147483647; no default TTL is assumed.",
            ));
        }
        if record.extra["creator"]
            .as_str()
            .is_none_or(|v| v.is_empty())
        {
            return Err(fail(
                "InvalidRecordCreator",
                "Selected record lacks creator metadata; system-record safety cannot be established.",
            ));
        }
        // Official Vercel CLI marks creator === system as a default record.
        // Other flags are not assumed present, but fail closed if returned.
        if record.extra["creator"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case("system"))
            || record.extra["recordKind"].as_str() == Some("record-sys")
        {
            return Err(fail(
                "SystemRecord",
                "Selected record is system-managed and must not be changed by DDNS.",
            ));
        }
        for key in [
            "readOnly",
            "readonly",
            "read_only",
            "system",
            "isSystem",
            "systemRecord",
        ] {
            if record
                .extra
                .get(key)
                .is_some_and(|v| v.as_bool() != Some(false))
            {
                return Err(fail(
                    "ReadOnlyRecord",
                    "Selected record is read-only/system-managed or its safety flag is invalid.",
                ));
            }
        }
        Ok(())
    }
    fn acknowledgement(
        &self,
        spec: &Spec,
        ip: &str,
        record: Option<&Record>,
        reply: &HttpReply,
        stage: &str,
    ) -> Result<Mutation, ProviderError> {
        let bad = || {
            self.error(stage, "InvalidWriteAcknowledgement", "Vercel did not acknowledge the documented record identity or returned contradictory properties; result is uncertain. Inspect before retrying.", Some(reply))
        };
        let id = if let Some(record) = record {
            let body = &reply.body;
            let id = body["id"]
                .as_str()
                .filter(|id| valid_id(id))
                .ok_or_else(bad)?;
            if id != record.id
                || body["recordType"].as_str() != Some(&record.record_type)
                || body["type"].as_str() != Some("record")
                || !body["domain"]
                    .as_str()
                    .is_some_and(|domain| domain.eq_ignore_ascii_case(&spec.domain))
                || !body["name"]
                    .as_str()
                    .is_some_and(|name| same_target(if name.is_empty() { "@" } else { name }, spec))
                || !body["value"]
                    .as_str()
                    .and_then(|v| v.parse::<IpAddr>().ok())
                    .is_some_and(|v| Some(v) == ip.parse().ok())
                || body["creator"]
                    .as_str()
                    .is_none_or(|v| v.is_empty() || v.eq_ignore_ascii_case("system"))
                || body
                    .get("ttl")
                    .is_some_and(|ttl| ttl.as_u64() != Some(spec.ttl))
                || body
                    .get("comment")
                    .is_some_and(|comment| Some(comment) != record.extra.get("comment"))
            {
                return Err(bad());
            }
            id
        } else {
            // Create acknowledges uid, not an invented record envelope.
            let id = reply.body["uid"]
                .as_str()
                .filter(|id| valid_id(id))
                .ok_or_else(bad)?;
            if reply.body.get("id").is_some_and(|v| v.as_str() != Some(id)) {
                return Err(bad());
            }
            id
        };
        Ok(Mutation {
            record_id: id.into(),
            request_id: reply.request_id.clone(),
        })
    }
}
impl Adapter for Vercel {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Relative
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
        let domain = self.domain(spec).await?;
        let stage = "VercelListRecords";
        let path = format!("/v5/domains/{}/records", spec.domain.to_ascii_lowercase());
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut cursors = HashSet::new();
        let mut until: Option<u64> = None;
        let mut last_request_id = domain.request_id;
        for _ in 0..100 {
            let mut request = self.request(Method::GET, &path).query(&[("limit", "100")]);
            if let Some(cursor) = until {
                request = request.query(&[("until", cursor.to_string())]);
            }
            let reply = self.send(stage, request, false).await?;
            if reply.request_id.is_some() {
                last_request_id = reply.request_id.clone();
            }
            let page = reply.body["records"].as_array().filter(|page| page.len() <= 100)
                .ok_or_else(|| self.error(stage, "InvalidRecordList", "Vercel records must be an array with at most100 records per page; no partial list is returned.", Some(&reply)))?;
            if records.len() + page.len() > 10_000 {
                return Err(self.error(
                    stage,
                    "RecordLimit",
                    "Listing exceeds10000 records; safe selection stopped.",
                    Some(&reply),
                ));
            }
            for value in page {
                let record = self.record(value, &reply)?;
                if !ids.insert(record.id.clone()) {
                    return Err(self.error(
                        stage,
                        "UnstablePagination",
                        "Record ID repeated within or across pages; no partial list is returned.",
                        Some(&reply),
                    ));
                }
                records.push(record);
            }
            // Explicit completion required even for short pages; length is not
            // proof of completeness. Do not accept legacy unpaginated variants.
            let pagination = reply.body["pagination"].as_object().ok_or_else(|| {
                self.error(
                    stage,
                    "InvalidPagination",
                    "Listing lacks pagination metadata; completion cannot be established safely.",
                    Some(&reply),
                )
            })?;
            if pagination.get("count").and_then(Value::as_u64) != Some(page.len() as u64) {
                return Err(self.error(
                    stage,
                    "InvalidPagination",
                    "Pagination count contradicts the number of returned records.",
                    Some(&reply),
                ));
            }
            match pagination.get("next") {
                Some(Value::Null) => {
                    // Full-zone types also establish alias/delegation safety,
                    // including opt-in creation when there is no A/AAAA match.
                    if records.iter().any(|r| match r.record_type.as_str() {
                        "CNAME" | "ALIAS" => same_target(&r.name, spec),
                        "NS" => delegated(&r.name, spec),
                        _ => false,
                    }) {
                        return Err(self.error("selection", "UnsafeDnsOwner", "Target is delegated by NS or occupied by CNAME/ALIAS; creating or updating an address would violate DNS semantics.", Some(&reply)));
                    }
                    return Ok(List {
                        records,
                        request_id: last_request_id,
                    });
                }
                Some(value) => {
                    // Integer JavaScript milliseconds only; never f64 or URL.
                    let next = value
                        .as_u64()
                        .filter(|v| *v > 0 && *v <= 9_007_199_254_740_991)
                        .ok_or_else(|| {
                            self.error(
                                stage,
                                "InvalidPagination",
                                "Next cursor must be a positive integer JavaScript timestamp.",
                                Some(&reply),
                            )
                        })?;
                    if page.is_empty()
                        || until.is_some_and(|previous| next >= previous)
                        || !cursors.insert(next)
                    {
                        return Err(self.error(stage, "UnstablePagination", "Pagination repeated/increased its timestamp or returned an empty continuing page; no partial list is returned.", Some(&reply)));
                    }
                    until = Some(next);
                }
                None => {
                    return Err(self.error(
                        stage,
                        "InvalidPagination",
                        "Pagination lacks explicit next timestamp or null completion marker.",
                        Some(&reply),
                    ));
                }
            }
        }
        let mut error = self.error(
            stage,
            "PaginationLimit",
            "Listing exceeds100 pages; no partial list is returned.",
            None,
        );
        error.request_id = last_request_id;
        Err(error)
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate_ip(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error("create", "CreationNotAllowed", "Creation requires explicit create_if_missing and no record_id; no fallback creation.", None));
        }
        self.domain(spec).await?;
        let stage = "VercelCreateRecord";
        let name = if spec.subdomain == "@" {
            ""
        } else {
            &spec.subdomain
        };
        let reply = self
            .send(
                stage,
                self.request(
                    Method::POST,
                    &format!("/v2/domains/{}/records", spec.domain.to_ascii_lowercase()),
                )
                .json(&json!({"name":name,"type":spec.record_type,"value":ip,"ttl":spec.ttl})),
                true,
            )
            .await?;
        self.acknowledgement(spec, ip, None, &reply, stage)
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
        let stage = "VercelUpdateRecord";
        let reply = self
            .send(
                stage,
                self.request(Method::PATCH, &format!("/v1/domains/records/{}", record.id))
                    // Optional PATCH fields: never type/name/comment/creator replay.
                    .json(&json!({"value":ip,"ttl":spec.ttl})),
                true,
            )
            .await?;
        self.acknowledgement(spec, ip, Some(record), &reply, stage)
    }
}
fn hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
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
fn record_name(name: &str) -> bool {
    name.is_empty()
        || name == "@"
        || (!name.ends_with("..")
            && name.len() <= 254
            && name
                .trim_end_matches('.')
                .split('.')
                .enumerate()
                .all(|(i, label)| {
                    !label.is_empty()
                        && label.len() <= 63
                        && (label == "*" && i == 0
                            || label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
                }))
}
fn same_target(name: &str, spec: &Spec) -> bool {
    super::common::NameFormat::Relative.matches(name, spec)
}
fn delegated(name: &str, spec: &Spec) -> bool {
    // Vercel names are strictly relative. Only empty/@ define apex NS;
    // even a name equal to or ending in the zone text denotes a child owner.
    if matches!(name, "" | "@") {
        return false;
    }
    let fqdn = format!(
        "{}.{}",
        name.to_ascii_lowercase(),
        spec.domain.to_ascii_lowercase()
    );
    let target = spec.fqdn().to_ascii_lowercase();
    target == fqdn || target.ends_with(&format!(".{fqdn}"))
}
fn error_details(body: &Value) -> String {
    fn collect(value: &Value, path: &str, depth: usize, out: &mut Vec<String>) {
        if depth > 5 || out.len() >= 16 {
            return;
        }
        match value {
            Value::String(text) => out.push(format!("{path}: {text}")),
            Value::Array(values) => {
                for value in values.iter().take(16) {
                    collect(value, path, depth + 1, out);
                }
            }
            Value::Object(object) => {
                for key in [
                    "error", "errors", "code", "message", "detail", "field", "name", "type",
                    "value", "ttl", "teamId", "domain", "recordId",
                ] {
                    if let Some(value) = object.get(key) {
                        collect(value, &format!("{path}.{key}"), depth + 1, out);
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    collect(body, "Vercel", 0, &mut out);
    if out.is_empty() {
        "Vercel returned no recognized error details; raw response omitted.".into()
    } else {
        out.join("; ")
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
        http::{HeaderValue, StatusCode},
        response::{IntoResponse, Response},
        routing::any,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    const TOKEN: &str = "secret-test-token";
    #[derive(Clone, Debug)]
    struct Captured {
        method: Method,
        uri: String,
        auth: Option<String>,
        body: Value,
    }
    struct Reply {
        status: u16,
        body: Value,
        request_id: Option<String>,
        vercel_id: Option<String>,
    }
    struct Data {
        replies: VecDeque<Reply>,
        requests: Vec<Captured>,
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
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let captured = Captured {
            method: parts.method,
            uri: parts.uri.to_string(),
            auth: parts
                .headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().into()),
            body: if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        };
        let reply = {
            let mut d = data.lock().unwrap();
            d.requests.push(captured);
            d.replies.pop_front().unwrap_or_else(|| {
                response(
                    500,
                    json!({"error":{"code":"unexpected_request","message":"Unexpected request"}}),
                )
            })
        };
        let mut result = if reply.status == 204 {
            StatusCode::NO_CONTENT.into_response()
        } else {
            (
                StatusCode::from_u16(reply.status).unwrap(),
                Json(reply.body),
            )
                .into_response()
        };
        if let Some(id) = reply.request_id {
            result
                .headers_mut()
                .insert("x-request-id", HeaderValue::from_str(&id).unwrap());
        }
        if let Some(id) = reply.vercel_id {
            result
                .headers_mut()
                .insert("x-vercel-id", HeaderValue::from_str(&id).unwrap());
        }
        result
    }
    impl Mock {
        async fn new(replies: Vec<Reply>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let data = Arc::new(Mutex::new(Data {
                replies: replies.into(),
                requests: vec![],
            }));
            let app = Router::new()
                .route("/{*path}", any(handler))
                .with_state(data.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                endpoint,
                data,
                task,
            }
        }
        fn adapter(&self) -> Vercel {
            self.with_options(BTreeMap::new())
        }
        fn with_options(&self, options: BTreeMap<String, String>) -> Vercel {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let mut adapter = Vercel::new(client, TOKEN.into(), &options);
            adapter.endpoint = self.endpoint.clone();
            adapter
        }
        fn requests(&self) -> Vec<Captured> {
            self.data.lock().unwrap().requests.clone()
        }
        fn done(&self) {
            assert!(self.data.lock().unwrap().replies.is_empty());
        }
        fn reads_only(&self) {
            assert!(self.requests().iter().all(|r| r.method == Method::GET));
            self.done();
        }
    }
    fn response(status: u16, body: Value) -> Reply {
        Reply {
            status,
            body,
            request_id: Some("request-123".into()),
            vercel_id: None,
        }
    }
    fn domain() -> Reply {
        response(
            200,
            json!({"domain":{"name":"example.com","verified":true,"serviceType":"zeit.world","teamId":"team_test"}}),
        )
    }
    fn row(id: &str, name: &str, kind: &str, value: &str) -> Value {
        json!({"id":id,"name":name,"type":kind,"value":value,"ttl":600,"creator":"usr_test","slug":"preserve-slug","comment":"preserve comment","createdAt":123,"updatedAt":456,"readOnly":false})
    }
    fn address() -> Value {
        row("rec_one", "home", "A", "192.0.2.1")
    }
    fn page(rows: Vec<Value>, next: Value) -> Reply {
        let count = rows.len();
        response(
            200,
            json!({"records":rows,"pagination":{"count":count,"next":next,"prev":null}}),
        )
    }
    fn complete(rows: Vec<Value>) -> Reply {
        page(rows, Value::Null)
    }
    fn patch_ack() -> Value {
        json!({"id":"rec_one","name":"home","recordType":"A","type":"record","domain":"example.com","value":"192.0.2.2","ttl":600,"creator":"usr_test","comment":"preserve comment"})
    }
    fn spec() -> Spec {
        Spec {
            domain: "example.com".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "默认".into(),
            ttl: 600,
            record_id: None,
            create_if_missing: true,
            options: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn exact_zone_team_auth_preserved_across_timestamp_pages() {
        let mock = Mock::new(vec![
            domain(),
            page(vec![address()], json!(1_700_000_000_000_u64)),
            complete(vec![row("rec_two", "other", "AAAA", "2001:db8::1")]),
        ])
        .await;
        let adapter = mock.with_options(BTreeMap::from([("team_id".into(), "team_test".into())]));
        assert_eq!(adapter.list(&spec()).await.unwrap().records.len(), 2);
        let requests = mock.requests();
        assert_eq!(requests[0].uri, "/v5/domains/example.com?teamId=team_test");
        assert_eq!(
            requests[1].uri,
            "/v5/domains/example.com/records?teamId=team_test&limit=100"
        );
        assert_eq!(
            requests[2].uri,
            "/v5/domains/example.com/records?teamId=team_test&limit=100&until=1700000000000"
        );
        for r in requests {
            assert_eq!(r.auth.as_deref(), Some("Bearer secret-test-token"));
            assert!(!r.uri.contains(TOKEN));
            assert!(!r.uri.contains("slug="));
        }
        mock.reads_only();
    }
    #[test]
    fn sensitive_header_fixed_origin_and_only_team_id_option() {
        let adapter = Vercel::new(
            reqwest::Client::new(),
            TOKEN.into(),
            &BTreeMap::from([("team_id".into(), "team_test".into())]),
        );
        let request = adapter
            .request(Method::GET, "/v5/domains/example.com")
            .build()
            .unwrap();
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("api.vercel.com"));
        assert!(request.headers()["authorization"].is_sensitive());
        assert!(!format!("{request:?}").contains(TOKEN));
        for (key, value) in [
            ("endpoint", "https://evil.example"),
            ("slug", "my-team"),
            ("team_id", "team?bad=1"),
            ("team_id", ""),
        ] {
            let a = Vercel::new(
                reqwest::Client::new(),
                TOKEN.into(),
                &BTreeMap::from([(key.into(), value.into())]),
            );
            assert_eq!(
                a.validate_spec(&spec()).unwrap_err().code,
                "UnsupportedOptions"
            );
        }
    }
    #[tokio::test]
    async fn ownership_verification_delegation_and_exact_zone_fail_closed() {
        for (field, value, code) in [
            ("name", json!("parent.example.com"), "DomainMismatch"),
            ("name", json!("com"), "DomainMismatch"),
            ("verified", json!(false), "DomainNotVerified"),
            ("verified", json!("true"), "DomainNotVerified"),
            ("serviceType", json!("external"), "ExternalDns"),
            ("serviceType", json!("na"), "ExternalDns"),
            ("readOnly", json!(true), "ReadOnlyDomain"),
        ] {
            let mut d = domain();
            d.body["domain"][field] = value;
            let mock = Mock::new(vec![d]).await;
            let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                .await
                .unwrap_err();
            assert_eq!(e.code, code);
            assert_eq!(e.request_id.as_deref(), Some("request-123"));
            assert_eq!(mock.requests().len(), 1);
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn all_types_actual_names_comments_and_creator_retained() {
        let rows = vec![
            address(),
            row("txt", "_acme-challenge", "TXT", "verification"),
            row("mx", "", "MX", "mail.example.com"),
            row("ns", "", "NS", "ns.example.net"),
            row("alias", "elsewhere", "ALIAS", "alias.example.net"),
            row("cname", "www", "CNAME", "cname.example.net"),
            row("srv", "_service._tcp", "SRV", "service"),
            row("https", "api", "HTTPS", "https data"),
            row("caa", "", "CAA", "0 issue ca.example"),
            row("wild", "*", "AAAA", "2001:db8::1"),
        ];
        let mock = Mock::new(vec![domain(), complete(rows.clone())]).await;
        let list = mock.adapter().list(&spec()).await.unwrap();
        assert_eq!(list.records.len(), rows.len());
        for (record, original) in list.records.iter().zip(rows) {
            assert_eq!(record.extra, original);
            assert_eq!(record.record_type, original["type"].as_str().unwrap());
            assert!(record.line.is_empty());
        }
        assert_eq!(list.records[1].name, "_acme-challenge");
        assert_eq!(list.records[2].name, "@");
        mock.reads_only();
    }
    #[tokio::test]
    async fn repeated_ids_within_and_across_pages_are_rejected() {
        for pages in [
            vec![complete(vec![address(), address()])],
            vec![
                page(vec![address()], json!(1000)),
                complete(vec![address()]),
            ],
        ] {
            let mut replies = vec![domain()];
            replies.extend(pages);
            let mock = Mock::new(replies).await;
            assert_eq!(
                mock.adapter().list(&spec()).await.unwrap_err().code,
                "UnstablePagination"
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn cursor_repetition_increase_float_string_and_missing_fail() {
        for next in [
            json!(1000),
            json!(1001),
            json!(999.5),
            json!("999"),
            json!("https://evil.example"),
        ] {
            let mock = Mock::new(vec![
                domain(),
                page(vec![address()], json!(1000)),
                page(vec![row("rec_two", "other", "A", "192.0.2.3")], next),
            ])
            .await;
            let e = mock.adapter().list(&spec()).await.unwrap_err();
            assert!(matches!(
                e.code.as_str(),
                "UnstablePagination" | "InvalidPagination"
            ));
            mock.reads_only();
        }
        for body in [
            json!({"records":[]}),
            json!({"records":[],"pagination":{"count":0}}),
            json!({"records":[],"pagination":{"count":1,"next":null}}),
        ] {
            let mock = Mock::new(vec![domain(), response(200, body)]).await;
            assert_eq!(
                mock.adapter().list(&spec()).await.unwrap_err().code,
                "InvalidPagination"
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn empty_continuing_page_is_not_completion() {
        let mock = Mock::new(vec![domain(), page(vec![], json!(1000))]).await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "UnstablePagination"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn ids_are_opaque_strings_and_never_float_converted() {
        for id in [
            json!(9_007_199_254_740_993_u64),
            json!(123.5),
            json!("rec/unsafe"),
            json!("0"),
        ] {
            let mut r = address();
            r["id"] = id;
            let mock = Mock::new(vec![domain(), complete(vec![r])]).await;
            assert_eq!(
                mock.adapter().list(&spec()).await.unwrap_err().code,
                "InvalidRecord"
            );
            mock.reads_only();
        }
        let mut r = address();
        r["id"] = json!("9007199254740993");
        let mock = Mock::new(vec![domain(), complete(vec![r])]).await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap().records[0].id,
            "9007199254740993"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn common_selection_never_first_name_only_or_type_conversion() {
        let rows = vec![
            row("v6", "home", "AAAA", "2001:db8::1"),
            row("wrong_host", "other", "A", "192.0.2.9"),
            address(),
        ];
        let mock = Mock::new(vec![domain(), complete(rows.clone())]).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                .await
                .unwrap()
                .record_id
                .as_deref(),
            Some("rec_one")
        );
        mock.reads_only();
        for id in ["v6", "wrong_host", "missing"] {
            let mock = Mock::new(vec![domain(), complete(rows.clone())]).await;
            let mut s = spec();
            s.record_id = Some(id.into());
            let e = reconcile(&mock.adapter(), &s, "192.0.2.2", true)
                .await
                .unwrap_err();
            assert!(matches!(
                e.code.as_str(),
                "RecordIdMismatch" | "RecordIdNotFound"
            ));
            mock.reads_only();
        }
        let mock = Mock::new(vec![
            domain(),
            complete(vec![address(), row("duplicate", "home", "A", "192.0.2.3")]),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                .await
                .unwrap_err()
                .code,
            "AmbiguousRecords"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn readonly_system_creator_and_malformed_flags_rejected_before_dryrun() {
        for (field, value, code) in [
            ("creator", json!("system"), "SystemRecord"),
            ("creator", json!(""), "InvalidRecordCreator"),
            ("readOnly", json!(true), "ReadOnlyRecord"),
            ("readonly", json!(true), "ReadOnlyRecord"),
            ("isSystem", json!(true), "ReadOnlyRecord"),
            ("system", json!(true), "ReadOnlyRecord"),
            ("readOnly", json!("false"), "ReadOnlyRecord"),
            ("recordKind", json!("record-sys"), "SystemRecord"),
        ] {
            let mut r = address();
            r[field] = value;
            let mock = Mock::new(vec![domain(), complete(vec![r])]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn alias_and_ns_delegation_block_creation_or_update_not_apex_ns() {
        for rows in [
            vec![row("alias", "home", "ALIAS", "alias.example.net")],
            vec![
                address(),
                row("cname", "home", "CNAME", "cname.example.net"),
            ],
            vec![row("ns", "home", "NS", "ns.example.net")],
        ] {
            let mock = Mock::new(vec![domain(), complete(rows)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                    .await
                    .unwrap_err()
                    .code,
                "UnsafeDnsOwner"
            );
            mock.reads_only();
        }
        let mut s = spec();
        s.subdomain = "host.child".into();
        let mock = Mock::new(vec![
            domain(),
            complete(vec![row("ns", "child", "NS", "ns.example.net")]),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &s, "192.0.2.2", true)
                .await
                .unwrap_err()
                .code,
            "UnsafeDnsOwner"
        );
        mock.reads_only();
        let mock = Mock::new(vec![
            domain(),
            complete(vec![address(), row("ns", "", "NS", "ns.example.net")]),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_update"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn desired_ttl_boundaries_validate_before_any_get_or_dryrun() {
        for ttl in [0, 1, 59, 604801, 2_147_483_647, 2_147_483_648, u64::MAX] {
            let mock = Mock::new(vec![]).await;
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(
                reconcile(&mock.adapter(), &s, "192.0.2.2", true)
                    .await
                    .unwrap_err()
                    .code,
                "UnsupportedTTL"
            );
            assert!(mock.requests().is_empty());
            mock.done();
            assert_eq!(
                mock.adapter()
                    .validate_selection(&s, None)
                    .unwrap_err()
                    .code,
                "UnsupportedTTL"
            );
        }
        for ttl in [60, 604800] {
            let mock = Mock::new(vec![domain(), complete(vec![])]).await;
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(
                reconcile(&mock.adapter(), &s, "192.0.2.2", true)
                    .await
                    .unwrap()
                    .status,
                "would_create"
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn selected_missing_ttl_fails_unrelated_missing_ttl_retained() {
        let mut r = address();
        r.as_object_mut().unwrap().remove("ttl");
        let mock = Mock::new(vec![domain(), complete(vec![r.clone()])]).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                .await
                .unwrap_err()
                .code,
            "InvalidRecordTTL"
        );
        mock.reads_only();
        r["name"] = json!("other");
        r["id"] = json!("rec_other_missing_ttl");
        let mock = Mock::new(vec![domain(), complete(vec![address(), r.clone()])]).await;
        let list = mock.adapter().list(&spec()).await.unwrap();
        assert_eq!(list.records[1].ttl, 0);
        assert_eq!(list.records[1].extra, r);
        mock.reads_only();
        for ttl in [
            json!(59),
            json!(2_147_483_648_u64),
            json!(600.5),
            json!("600"),
            Value::Null,
        ] {
            let mut r = address();
            r["ttl"] = ttl;
            let mock = Mock::new(vec![domain(), complete(vec![r])]).await;
            assert_eq!(
                mock.adapter().list(&spec()).await.unwrap_err().code,
                "InvalidRecord"
            );
            mock.reads_only();
        }
        let mut r = address();
        r["ttl"] = json!(2_147_483_647_u64);
        let mock = Mock::new(vec![domain(), complete(vec![r])]).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_update"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn errors_even_http200_preserve_safe_code_fields_and_header_context() {
        for status in [200, 400, 401, 403, 404, 409, 429, 500, 503] {
            let body = json!({"error":{"code":"bad_request","message":format!("Denied {TOKEN}"),"errors":{"ttl":{"message":"TTL too small","code":"invalid_ttl"}},"unknown":{"message":"do-not-print"},"debug":"hidden-debug"}});
            let mock = Mock::new(vec![response(status, body)]).await;
            let e = mock.adapter().list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "bad_request");
            assert_eq!(e.http_status, Some(status));
            assert_eq!(e.request_id.as_deref(), Some("request-123"));
            assert!(e.message.contains("TTL too small"));
            assert!(!e.message.contains(TOKEN));
            assert!(!e.message.contains("do-not-print"));
            assert!(!e.message.contains("hidden-debug"));
            assert!(e.hint.contains("team_id"));
            assert_eq!(mock.requests().len(), 1);
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn vercel_trace_header_with_colons_is_retained() {
        let mut r = response(
            403,
            json!({"error":{"code":"forbidden","message":"No access"}}),
        );
        r.request_id = None;
        r.vercel_id = Some("iad1::trace-123".into());
        let mock = Mock::new(vec![r]).await;
        assert_eq!(
            mock.adapter()
                .list(&spec())
                .await
                .unwrap_err()
                .request_id
                .as_deref(),
            Some("iad1::trace-123")
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn post_real_payload_uid_ack_and_success_statuses() {
        for status in [200, 201] {
            let mock = Mock::new(vec![
                domain(),
                complete(vec![]),
                domain(),
                response(status, json!({"uid":"rec_created"})),
            ])
            .await;
            let a = mock.with_options(BTreeMap::from([("team_id".into(), "team_test".into())]));
            let result = reconcile(&a, &spec(), "192.0.2.2", false).await.unwrap();
            assert_eq!(result.status, "created");
            assert_eq!(result.record_id.as_deref(), Some("rec_created"));
            let requests = mock.requests();
            assert_eq!(requests.len(), 4);
            let write = &requests[3];
            assert_eq!(write.method, Method::POST);
            assert_eq!(
                write.uri,
                "/v2/domains/example.com/records?teamId=team_test"
            );
            assert_eq!(
                write.body,
                json!({"name":"home","type":"A","value":"192.0.2.2","ttl":600})
            );
            mock.done();
        }
    }
    #[tokio::test]
    async fn apex_create_sends_empty_name_and_ipv6_actual_type() {
        let mock = Mock::new(vec![
            domain(),
            complete(vec![]),
            domain(),
            response(201, json!({"uid":"rec_v6"})),
        ])
        .await;
        let mut s = spec();
        s.subdomain = "@".into();
        s.record_type = "AAAA".into();
        assert_eq!(
            reconcile(&mock.adapter(), &s, "2001:db8::2", false)
                .await
                .unwrap()
                .status,
            "created"
        );
        assert_eq!(
            mock.requests()[3].body,
            json!({"name":"","type":"AAAA","value":"2001:db8::2","ttl":600})
        );
        mock.done();
        let mut r = row("rec_apex", "", "AAAA", "2001:db8::2");
        r["ttl"] = json!(600);
        let mock = Mock::new(vec![domain(), complete(vec![r])]).await;
        assert_eq!(
            reconcile(&mock.adapter(), &s, "2001:db8::2", true)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn patch_only_value_ttl_preserves_actual_type_comment_and_metadata() {
        let mock = Mock::new(vec![
            domain(),
            complete(vec![address()]),
            domain(),
            response(200, patch_ack()),
        ])
        .await;
        let a = mock.with_options(BTreeMap::from([("team_id".into(), "team_test".into())]));
        let result = reconcile(&a, &spec(), "192.0.2.2", false).await.unwrap();
        assert_eq!(result.status, "updated");
        let requests = mock.requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[3].method, Method::PATCH);
        assert_eq!(
            requests[3].uri,
            "/v1/domains/records/rec_one?teamId=team_test"
        );
        assert_eq!(requests[3].body, json!({"value":"192.0.2.2","ttl":600}));
        mock.done();
    }
    #[tokio::test]
    async fn patch_model_type_and_dns_record_type_are_not_interchangeable() {
        for (field, value) in [
            ("type", json!("A")),
            ("type", json!("record-sys")),
            ("recordType", json!("AAAA")),
            ("name", json!("other")),
            ("domain", json!("child.example.com")),
            ("id", json!("other_id")),
            ("ttl", json!(601)),
            ("value", json!("192.0.2.3")),
            ("comment", json!("overwritten")),
            ("creator", json!("system")),
        ] {
            let mut ack = patch_ack();
            ack[field] = value;
            let mock = Mock::new(vec![
                domain(),
                complete(vec![address()]),
                domain(),
                response(200, ack),
            ])
            .await;
            let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "InvalidWriteAcknowledgement");
            assert!(!e.retryable);
            assert_eq!(e.request_id.as_deref(), Some("request-123"));
            assert_eq!(
                mock.requests()
                    .iter()
                    .filter(|r| r.method == Method::PATCH)
                    .count(),
                1
            );
            mock.done();
        }
        // Do not reinterpret a PATCH/internal model as the list DNS model.
        let mut r = address();
        r["type"] = json!("record-sys");
        r["recordType"] = json!("A");
        let mock = Mock::new(vec![domain(), complete(vec![r])]).await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "InvalidRecord"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn missing_or_invalid_create_ack_never_succeeds_or_retries() {
        for ack in [
            json!({}),
            json!({"id":"rec_created"}),
            json!({"uid":123}),
            json!({"uid":""}),
            json!({"uid":"rec_created","id":"other"}),
            json!({"record":{"id":"rec_created"}}),
        ] {
            let mock = Mock::new(vec![
                domain(),
                complete(vec![]),
                domain(),
                response(201, ack),
            ])
            .await;
            let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "InvalidWriteAcknowledgement");
            assert!(!e.retryable);
            assert_eq!(
                mock.requests()
                    .iter()
                    .filter(|r| r.method == Method::POST)
                    .count(),
                1
            );
            mock.done();
        }
        let mock = Mock::new(vec![
            domain(),
            complete(vec![]),
            domain(),
            response(204, Value::Null),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "InvalidWriteAcknowledgement"
        );
        mock.done();
    }
    #[tokio::test]
    async fn failed_writes_are_uncertain_and_never_retried() {
        for status in [200, 401, 403, 409, 429, 500] {
            let mock = Mock::new(vec![
                domain(),
                complete(vec![address()]),
                domain(),
                response(
                    status,
                    json!({"error":{"code":"forbidden","message":format!("Failed {TOKEN}")}}),
                ),
            ])
            .await;
            let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "forbidden");
            assert!(!e.retryable);
            assert!(!e.message.contains(TOKEN));
            assert_eq!(e.http_status, Some(status));
            assert_eq!(mock.requests().len(), 4);
            mock.done();
        }
    }
    #[tokio::test]
    async fn common_dryrun_update_create_unchanged_are_get_only() {
        for (rows, ip, status) in [
            (vec![address()], "192.0.2.2", "would_update"),
            (vec![], "192.0.2.2", "would_create"),
            (vec![address()], "192.0.2.1", "unchanged"),
        ] {
            let mock = Mock::new(vec![domain(), complete(rows)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), ip, true)
                    .await
                    .unwrap()
                    .status,
                status
            );
            assert_eq!(mock.requests().len(), 2);
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn creation_requires_common_optin_without_explicit_id() {
        let mut s = spec();
        s.create_if_missing = false;
        let mock = Mock::new(vec![domain(), complete(vec![])]).await;
        assert_eq!(
            reconcile(&mock.adapter(), &s, "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "RecordNotFound"
        );
        mock.reads_only();
        let mock = Mock::new(vec![]).await;
        assert_eq!(
            mock.adapter()
                .create(&s, "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "CreationNotAllowed"
        );
        assert!(mock.requests().is_empty());
        s.create_if_missing = true;
        s.record_id = Some("missing".into());
        assert_eq!(
            mock.adapter()
                .create(&s, "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "CreationNotAllowed"
        );
        mock.done();
    }
    #[tokio::test]
    async fn actual_name_and_type_safety_rejects_malformed_list_models() {
        for (field, value) in [
            ("name", json!("home..")),
            ("name", json!("home/example.com")),
            ("name", json!("https://example.com")),
            ("type", json!("a")),
            ("type", json!("record")),
            ("recordType", json!("AAAA")),
            ("creator", Value::Null),
        ] {
            let mut r = address();
            r[field] = value;
            let mock = Mock::new(vec![domain(), complete(vec![r])]).await;
            assert_eq!(
                mock.adapter().list(&spec()).await.unwrap_err().code,
                "InvalidRecord"
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn direct_hook_refuses_inconsistent_identity_and_readonly_metadata() {
        let mock = Mock::new(vec![domain(), complete(vec![address()])]).await;
        let adapter = mock.adapter();
        let original = adapter.list(&spec()).await.unwrap().records.remove(0);
        for field in ["id", "name", "record_type", "line", "value"] {
            let mut r = original.clone();
            match field {
                "id" => r.id = "other".into(),
                "name" => r.name = "other".into(),
                "record_type" => r.record_type = "AAAA".into(),
                "line" => r.line = "invented-line".into(),
                _ => r.value = "192.0.2.9".into(),
            }
            assert_eq!(
                adapter
                    .validate_selection(&spec(), Some(&r))
                    .unwrap_err()
                    .code,
                "RecordMismatch"
            );
        }
        let mut r = original.clone();
        r.extra["readOnly"] = json!(true);
        assert_eq!(
            adapter
                .update(&spec(), &r, "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "ReadOnlyRecord"
        );
        let mut r = original;
        r.ttl = 0;
        assert_eq!(
            adapter
                .validate_selection(&spec(), Some(&r))
                .unwrap_err()
                .code,
            "InvalidRecordTTL"
        );
        mock.reads_only();
    }
    #[test]
    fn error_sanitization_happens_before_truncation_and_never_raw_json() {
        let token = "credential-long-value";
        let adapter = Vercel::new(reqwest::Client::new(), token.into(), &BTreeMap::new());
        let body = json!({"error":{"code":"bad_request","message":format!("{}{}","x".repeat(250),token),"errors":{"ttl":[{"message":"bad ttl"}]},"requestHeaders":{"Authorization":"do-not-print"},"unknown":"do-not-print"}});
        let reply = HttpReply {
            headers: reqwest::header::HeaderMap::new(),
            body,
            status: 400,
            request_id: Some("request-123".into()),
        };
        let e = adapter
            .check("VercelListRecords", &reply, false)
            .unwrap_err();
        assert!(e.message.contains("[REDACTED]"));
        assert!(!e.message.contains("credential-long"));
        assert!(!e.message.contains("do-not-print"));
        assert!(e.message.contains("bad ttl"));
    }
    #[tokio::test]
    async fn pagination_bound_stops_at100_pages_with_no_partial_list() {
        let mut replies = vec![domain()];
        for i in 0..100 {
            replies.push(page(
                vec![row(&format!("rec_{i}"), "other", "TXT", "data")],
                json!(1000 - i),
            ));
        }
        let mock = Mock::new(replies).await;
        let e = mock.adapter().list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "PaginationLimit");
        assert_eq!(e.request_id.as_deref(), Some("request-123"));
        assert_eq!(mock.requests().len(), 101);
        mock.reads_only();
    }
    #[tokio::test]
    async fn complete10000_records_allowed_but_oversized_page_refused() {
        let mut replies = vec![domain()];
        for i in 0..100 {
            let rows = (0..100)
                .map(|j| row(&format!("rec_{i}_{j}"), "other", "TXT", "data"))
                .collect();
            replies.push(page(
                rows,
                if i == 99 {
                    Value::Null
                } else {
                    json!(1000 - i)
                },
            ));
        }
        let mock = Mock::new(replies).await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap().records.len(),
            10000
        );
        mock.reads_only();
        let rows = (0..101)
            .map(|i| row(&format!("rec_{i}"), "other", "TXT", "data"))
            .collect();
        let mock = Mock::new(vec![domain(), complete(rows)]).await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "InvalidRecordList"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn relative_suffix_shadow_never_selects_or_writes_wrong_owner() {
        for explicit in [false, true] {
            for (ip, dry) in [
                ("192.0.2.1", false),
                ("192.0.2.2", true),
                ("192.0.2.2", false),
            ] {
                let m = Mock::new(vec![
                    domain(),
                    complete(vec![row("shadow", "home.example.com", "A", "192.0.2.1")]),
                ])
                .await;
                let mut s = spec();
                s.create_if_missing = false;
                if explicit {
                    s.record_id = Some("shadow".into());
                    s.create_if_missing = true;
                }
                assert_eq!(
                    reconcile(&m.adapter(), &s, ip, dry).await.unwrap_err().code,
                    if explicit {
                        "RecordIdMismatch"
                    } else {
                        "RecordNotFound"
                    }
                );
                m.reads_only();
            }
        }
    }
    #[tokio::test]
    async fn relative_collision_updates_only_real_id_and_accepts_dotted_ack_name() {
        for host in ["home", "home.example.com", "example.com"] {
            let mut s = spec();
            s.subdomain = host.into();
            let mut ack = patch_ack();
            ack["name"] = json!(host);
            let m = Mock::new(vec![
                domain(),
                complete(vec![
                    row("shadow", &s.fqdn(), "A", "192.0.2.1"),
                    row("rec_one", host, "A", "192.0.2.1"),
                ]),
                domain(),
                response(200, ack),
            ])
            .await;
            let out = reconcile(&m.adapter(), &s, "192.0.2.2", false)
                .await
                .unwrap();
            assert_eq!(out.record_id.as_deref(), Some("rec_one"));
            let writes: Vec<_> = m
                .requests()
                .into_iter()
                .filter(|r| r.method == Method::PATCH)
                .collect();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].uri, "/v1/domains/records/rec_one");
            assert!(writes[0].body.get("name").is_none());
            m.done();
        }
    }
    #[tokio::test]
    async fn dotted_relative_ns_is_child_delegation_not_apex_or_already_fqdn() {
        for owner in ["example.com", "home.example.com"] {
            for host in [owner.to_string(), format!("leaf.{owner}")] {
                for dry in [false, true] {
                    let mut s = spec();
                    s.subdomain = host.clone();
                    let m = Mock::new(vec![
                        domain(),
                        complete(vec![
                            row("ns", owner, "NS", "ns.other.net"),
                            row("rec_one", &host, "A", "192.0.2.1"),
                        ]),
                    ])
                    .await;
                    assert_eq!(
                        reconcile(&m.adapter(), &s, "192.0.2.1", dry)
                            .await
                            .unwrap_err()
                            .code,
                        "UnsafeDnsOwner"
                    );
                    m.reads_only();
                }
            }
        }
        // A literal relative CNAME named like the zone is not apex either.
        let m = Mock::new(vec![
            domain(),
            complete(vec![row("alias", "example.com", "CNAME", "elsewhere.net")]),
        ])
        .await;
        let mut s = spec();
        s.subdomain = "@".into();
        assert_eq!(
            reconcile(&m.adapter(), &s, "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_create"
        );
        m.reads_only();
    }
}
