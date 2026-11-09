//! Cloudflare API-token adapter, fail-closed and without write retries.
//! API: https://developers.cloudflare.com/api/resources/zones/methods/list/
//! PATCH: https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/
//! TTL: https://developers.cloudflare.com/dns/manage-dns-records/reference/ttl/
//! Supply a client with redirects disabled; production endpoints cannot be overridden.

#![allow(clippy::result_large_err)]

use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use reqwest::{Method, RequestBuilder};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};

const ENDPOINT: &str = "https://api.cloudflare.com/client/v4";
const ZONE_PAGE_SIZE: u64 = 50;
const RECORD_PAGE_SIZE: u64 = 100;
const MAX_PAGES: u64 = 100;

// Intentionally not Debug: credentials must never be logged.
pub struct Cloudflare {
    api: Api,
    token: String,
    zone_id: Option<String>,
    #[cfg(test)]
    endpoint: String,
}

struct Zone {
    id: String,
    enterprise: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Pagination {
    per_page: u64,
    total_count: u64,
    total_pages: u64,
}

impl Cloudflare {
    pub fn new(client: reqwest::Client, token: String, options: &BTreeMap<String, String>) -> Self {
        Self {
            api: Api::new(client, vec![token.clone()]),
            token,
            zone_id: options.get("zone_id").cloned(),
            #[cfg(test)]
            endpoint: ENDPOINT.into(),
        }
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        #[cfg(test)]
        let endpoint = &self.endpoint;
        #[cfg(not(test))]
        let endpoint = ENDPOINT;
        self.api
            .client
            .request(method, format!("{endpoint}{path}"))
            .bearer_auth(&self.token)
    }

    fn invalid(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage, code, message,
            "Check the exact hosted zone, token permissions and configuration; no automatic write retry is safe.", reply)
    }

    fn validate_spec(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.token.trim().is_empty() {
            return Err(self.invalid(
                "validation",
                "MissingApiToken",
                "Cloudflare requires a nonempty API token, not a global API key/email pair.",
                None,
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.invalid(
                "validation",
                "UnsupportedRecordType",
                "Cloudflare DDNS only supports A and AAAA records.",
                None,
            ));
        }
        if spec.domain.is_empty() || spec.domain.contains(':') || spec.domain.contains('/') {
            return Err(self.invalid(
                "validation",
                "InvalidZoneName",
                "Set domain to the exact Cloudflare hosted DNS zone name.",
                None,
            ));
        }
        Ok(())
    }

    fn validate_ip(&self, spec: &Spec, ip: &str) -> Result<(), ProviderError> {
        self.validate_spec(spec)?;
        let parsed = ip.parse::<IpAddr>().map_err(|_| {
            self.invalid(
                "validation",
                "InvalidIp",
                "The desired content is not a valid IP address.",
                None,
            )
        })?;
        if !matches!(
            (spec.record_type.as_str(), parsed),
            ("A", IpAddr::V4(_)) | ("AAAA", IpAddr::V6(_))
        ) {
            return Err(self.invalid(
                "validation",
                "IpFamilyMismatch",
                "The desired IP address family does not match the configured A/AAAA record type.",
                None,
            ));
        }
        Ok(())
    }

    fn validate_proxy_ttl(&self, spec: &Spec, proxied: bool) -> Result<(), ProviderError> {
        if proxied && spec.ttl != 1 {
            return Err(self.api.error("validation", "UnsupportedTTL", "Cloudflare proxied records only support automatic TTL (ttl = 1); a custom TTL would be silently ignored.", "Set ttl = 1, or deliberately switch the record to DNS-only in Cloudflare. DDNS does not change an existing record's proxy status.", None));
        }
        Ok(())
    }

    fn validate_ttl(&self, spec: &Spec, zone: &Zone, proxied: bool) -> Result<(), ProviderError> {
        self.validate_proxy_ttl(spec, proxied)?;
        let minimum = if zone.enterprise { 30 } else { 60 };
        if spec.ttl != 1 && !(minimum..=86_400).contains(&spec.ttl) {
            return Err(self.api.error("validation", "UnsupportedTTL", &format!("Cloudflare DNS-only TTL must be 1 (automatic) or {minimum}..86400 seconds for this zone."), "Use ttl = 1 for Auto. TTL values below 60 seconds require a verified Enterprise zone; do not rely on provider coercion.", None));
        }
        Ok(())
    }

    /// Parse the provider envelope before checking HTTP status so API codes and
    /// messages survive 403/429/5xx responses. Api sanitizes all diagnostics.
    fn envelope<'a>(
        &self,
        action: &str,
        reply: &'a HttpReply,
        write: bool,
    ) -> Result<&'a Value, ProviderError> {
        let errors = reply.body.get("errors");
        if let Some(errors) = errors
            && !errors.is_array()
        {
            return Err(self.invalid(
                action,
                "InvalidEnvelope",
                "Cloudflare returned a malformed errors field.",
                Some(reply),
            ));
        }
        let has_errors = errors
            .and_then(Value::as_array)
            .is_some_and(|v| !v.is_empty());
        if reply.body.get("success").and_then(Value::as_bool) == Some(false) || has_errors {
            let mut codes = Vec::new();
            let mut messages = Vec::new();
            if let Some(errors) = errors.and_then(Value::as_array) {
                collect_errors(errors, &mut codes, &mut messages, 0);
            }
            let code = codes
                .first()
                .cloned()
                .unwrap_or_else(|| "CloudflareApiError".into());
            let message = if messages.is_empty() {
                "Cloudflare reported failure without an error message.".into()
            } else {
                messages.join("; ")
            };
            let mut error = self.api.error(action, &code, &message,
                "Verify API-token Zone Read and DNS Read/Edit permissions for this exact zone. Use the Ray ID to investigate the Cloudflare error; writes are never retried automatically.", Some(reply));
            error.retryable = !write && (reply.status == 429 || reply.status >= 500);
            return Err(error);
        }
        if let Err(mut error) = self.api.check_http(action, reply) {
            if write {
                error.retryable = false;
            }
            return Err(error);
        }
        if reply.body.get("success").and_then(Value::as_bool) != Some(true) {
            return Err(self.invalid(
                action,
                "InvalidEnvelope",
                "Cloudflare response is missing an explicit success=true envelope.",
                Some(reply),
            ));
        }
        reply
            .body
            .get("result")
            .filter(|v| !v.is_null())
            .ok_or_else(|| {
                self.invalid(
                    action,
                    "InvalidEnvelope",
                    "Cloudflare success response is missing its result.",
                    Some(reply),
                )
            })
    }

    // Each input independently validates the provider's current page against
    // the request and previous pages; action/reply preserve diagnostic context.
    #[allow(clippy::too_many_arguments)]
    fn pagination(
        &self,
        action: &str,
        reply: &HttpReply,
        page: u64,
        requested: u64,
        count: usize,
        previous: Option<Pagination>,
        received: u64,
    ) -> Result<(Pagination, bool), ProviderError> {
        let info = &reply.body["result_info"];
        let bad = || {
            self.invalid(action, "InvalidPagination", "Cloudflare pagination is missing, inconsistent, truncated or changed between pages; no record can be safely selected.", Some(reply))
        };
        let reported_page = info["page"].as_u64().ok_or_else(bad)?;
        let per_page = info["per_page"].as_u64().ok_or_else(bad)?;
        let reported_count = info["count"].as_u64().ok_or_else(bad)?;
        let total_count = info["total_count"].as_u64().ok_or_else(bad)?;
        let total_pages = info["total_pages"].as_u64().ok_or_else(bad)?;
        if reported_page != page
            || per_page == 0
            || per_page > requested
            || reported_count != count as u64
            || reported_count > per_page
            || total_pages > MAX_PAGES
            || received > total_count
        {
            return Err(bad());
        }
        let expected_pages = total_count.div_ceil(per_page);
        if total_count == 0 {
            if page != 1 || count != 0 || total_pages > 1 {
                return Err(bad());
            }
        } else if total_pages != expected_pages || page > total_pages {
            return Err(bad());
        }
        let pagination = Pagination {
            per_page,
            total_count,
            total_pages,
        };
        if previous.is_some_and(|previous| previous != pagination) {
            return Err(bad());
        }
        let done = total_count == 0 || page == total_pages;
        if done {
            if received != total_count {
                return Err(bad());
            }
        } else if reported_count != per_page || received != page * per_page {
            return Err(bad());
        }
        Ok((pagination, done))
    }

    fn zone_from(
        &self,
        action: &str,
        spec: &Spec,
        value: &Value,
        reply: &HttpReply,
    ) -> Result<Zone, ProviderError> {
        let id = value["id"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or_else(|| {
                self.invalid(
                    action,
                    "InvalidZone",
                    "Cloudflare returned a missing or invalid zone identifier.",
                    Some(reply),
                )
            })?;
        if !value["name"]
            .as_str()
            .is_some_and(|name| dns_equal(name, &spec.domain))
        {
            return Err(self.invalid(action, "ZoneMismatch", "Cloudflare returned a different zone name; domain must be the exact hosted zone, not a parent or child hostname.", Some(reply)));
        }
        if value["status"].as_str() != Some("active") {
            return Err(self.invalid(action, "ZoneInactive", "The Cloudflare zone is not active (or has an unknown status); no records were changed.", Some(reply)));
        }
        // `paused` only disables Cloudflare proxy benefits, not authoritative DNS.
        let enterprise = value["plan"]["legacy_id"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("enterprise"))
            || value["plan"]["name"].as_str().is_some_and(|s| {
                s.eq_ignore_ascii_case("enterprise")
                    || s.to_ascii_lowercase().starts_with("enterprise ")
            });
        Ok(Zone {
            id: id.into(),
            enterprise,
        })
    }

    async fn zone(&self, spec: &Spec) -> Result<Zone, ProviderError> {
        self.validate_spec(spec)?;
        if let Some(id) = &self.zone_id {
            if !valid_id(id) {
                return Err(self.invalid(
                    "validation",
                    "InvalidZoneId",
                    "Cloudflare zone_id is empty, too long or contains unsafe characters.",
                    None,
                ));
            }
            let action = "CloudflareGetZone";
            let reply = self
                .api
                .send(
                    action,
                    self.request(Method::GET, &format!("/zones/{id}")),
                    false,
                )
                .await?;
            let result = self.envelope(action, &reply, false)?;
            let zone = self.zone_from(action, spec, result, &reply)?;
            if zone.id != *id {
                return Err(self.invalid(action, "ZoneMismatch", "Cloudflare returned a different zone ID than the explicitly configured zone_id.", Some(&reply)));
            }
            return Ok(zone);
        }
        let action = "CloudflareListZones";
        let mut pagination = None;
        let mut received = 0;
        let mut seen = HashSet::new();
        let mut zones = Vec::new();
        for page in 1..=MAX_PAGES {
            // No status filter: inactive/duplicate exact zones must not be hidden.
            let reply = self
                .api
                .send(
                    action,
                    self.request(Method::GET, "/zones").query(&[
                        ("name", spec.domain.trim_end_matches('.').to_owned()),
                        ("match", "all".into()),
                        ("page", page.to_string()),
                        ("per_page", ZONE_PAGE_SIZE.to_string()),
                    ]),
                    false,
                )
                .await?;
            let result = self
                .envelope(action, &reply, false)?
                .as_array()
                .ok_or_else(|| {
                    self.invalid(
                        action,
                        "InvalidEnvelope",
                        "Cloudflare zones result must be an array.",
                        Some(&reply),
                    )
                })?;
            received += result.len() as u64;
            let (current, done) = self.pagination(
                action,
                &reply,
                page,
                ZONE_PAGE_SIZE,
                result.len(),
                pagination,
                received,
            )?;
            pagination = Some(current);
            for value in result {
                let zone = self.zone_from(action, spec, value, &reply)?;
                if !seen.insert(zone.id.clone()) {
                    return Err(self.invalid(
                        action,
                        "UnstablePagination",
                        "Cloudflare repeated a zone ID across pages; discovery was stopped.",
                        Some(&reply),
                    ));
                }
                zones.push(zone);
            }
            if done {
                if zones.len() != 1 {
                    return Err(self.invalid(action, if zones.is_empty() { "ZoneNotFound" } else { "AmbiguousZones" }, "Cloudflare must return exactly one active zone with the exact configured domain name.", Some(&reply)));
                }
                return Ok(zones.remove(0));
            }
        }
        Err(self.invalid(
            action,
            "PaginationLimit",
            "Cloudflare zone discovery exceeded its pagination safety limit.",
            None,
        ))
    }

    fn record(&self, value: &Value, reply: &HttpReply) -> Result<Record, ProviderError> {
        let bad = || {
            self.invalid("CloudflareListRecords", "InvalidRecord", "Cloudflare returned a DNS record with missing or invalid ID/name/type/content/TTL; selection was stopped.", Some(reply))
        };
        let id = value["id"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or_else(bad)?;
        let name = value["name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .ok_or_else(bad)?;
        let record_type = value["type"]
            .as_str()
            .filter(|kind| !kind.is_empty())
            .ok_or_else(bad)?;
        let content = value["content"].as_str().ok_or_else(bad)?;
        let ttl = value["ttl"]
            .as_u64()
            .filter(|ttl| *ttl != 0)
            .ok_or_else(bad)?;
        Ok(Record {
            id: id.into(),
            name: name.into(),
            record_type: record_type.into(),
            value: content.into(),
            ttl,
            line: String::new(),
            enabled: true,
            extra: value.clone(),
        })
    }

    fn mutation(
        &self,
        action: &str,
        reply: &HttpReply,
        expected_id: Option<&str>,
    ) -> Result<Mutation, ProviderError> {
        let result = self.envelope(action, reply, true)?;
        let id = result["id"].as_str().filter(|id| valid_id(id)).ok_or_else(|| self.invalid(action, "InvalidWriteResponse", "Cloudflare reported write success without a valid record ID. The write may have committed; inspect DNS before retrying.", Some(reply)))?;
        if expected_id.is_some_and(|expected| expected != id) {
            return Err(self.invalid(action, "RecordIdMismatch", "Cloudflare reported a different record ID after PATCH. The write may have committed; inspect DNS before retrying.", Some(reply)));
        }
        Ok(Mutation {
            record_id: id.into(),
            request_id: reply.request_id.clone(),
        })
    }
}

impl Adapter for Cloudflare {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Fqdn
    }
    fn validate_selection(
        &self,
        spec: &Spec,
        record: Option<&Record>,
    ) -> Result<(), ProviderError> {
        // Common has already selected the record, but has not planned a dry-run,
        // no-op or creation. Existing proxy state always wins over create options.
        let proxied = if let Some(record) = record {
            record.extra.get("proxied").and_then(Value::as_bool).ok_or_else(|| self.invalid(
                "validation", "InvalidRecordMetadata",
                "The selected Cloudflare record is missing its boolean proxied metadata; its TTL constraints cannot be safely verified.", None))?
        } else {
            match spec.options.get("proxied").map(String::as_str) {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => {
                    return Err(self.invalid(
                        "validation",
                        "InvalidProxied",
                        "Cloudflare record option proxied must be exactly 'true' or 'false'.",
                        None,
                    ));
                }
            }
        };
        self.validate_proxy_ttl(spec, proxied)
    }

    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        let zone = self.zone(spec).await?;
        self.validate_ttl(spec, &zone, false)?;
        let action = "CloudflareListRecords";
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let mut pagination = None;
        let mut received = 0;
        for page in 1..=MAX_PAGES {
            let reply = self
                .api
                .send(
                    action,
                    self.request(Method::GET, &format!("/zones/{}/dns_records", zone.id))
                        .query(&[
                            ("page", page.to_string()),
                            ("per_page", RECORD_PAGE_SIZE.to_string()),
                            ("order", "name".into()),
                            ("direction", "asc".into()),
                        ]),
                    false,
                )
                .await?;
            let result = self
                .envelope(action, &reply, false)?
                .as_array()
                .ok_or_else(|| {
                    self.invalid(
                        action,
                        "InvalidEnvelope",
                        "Cloudflare DNS records result must be an array.",
                        Some(&reply),
                    )
                })?;
            received += result.len() as u64;
            let (current, done) = self.pagination(
                action,
                &reply,
                page,
                RECORD_PAGE_SIZE,
                result.len(),
                pagination,
                received,
            )?;
            pagination = Some(current);
            for value in result {
                let record = self.record(value, &reply)?;
                if !seen.insert(record.id.clone()) {
                    return Err(self.invalid(action, "UnstablePagination", "Cloudflare repeated a DNS record ID across pages; safe record selection is impossible.", Some(&reply)));
                }
                records.push(record);
            }
            if done {
                return Ok(List {
                    records,
                    request_id: reply.request_id,
                });
            }
        }
        Err(self.invalid(action, "PaginationLimit", "Cloudflare DNS listing exceeded its 10,000-record pagination safety limit; no record was selected.", None))
    }

    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate_ip(spec, ip)?;
        let proxied = match spec.options.get("proxied").map(String::as_str) {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => {
                return Err(self.invalid(
                    "validation",
                    "InvalidProxied",
                    "Cloudflare record option proxied must be exactly 'true' or 'false'.",
                    None,
                ));
            }
        };
        let zone = self.zone(spec).await?;
        self.validate_ttl(spec, &zone, proxied)?;
        let action = "CloudflareCreateRecord";
        let reply = self.api.send(action, self.request(Method::POST, &format!("/zones/{}/dns_records", zone.id)).json(&json!({
            "type": spec.record_type, "name": spec.fqdn(), "content": ip, "ttl": spec.ttl, "proxied": proxied,
        })), true).await?;
        self.mutation(action, &reply, None)
    }

    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.validate_ip(spec, ip)?;
        if !valid_id(&record.id)
            || !dns_equal(&record.name, &spec.fqdn())
            || record.record_type != spec.record_type
        {
            return Err(self.invalid("validation", "RecordMismatch", "Refusing to PATCH a record with an invalid ID or a different name/type than the configured host.", None));
        }
        let proxied = record.extra.get("proxied").and_then(Value::as_bool).ok_or_else(|| self.invalid("validation", "InvalidRecordMetadata", "The selected Cloudflare record is missing its boolean proxied metadata; its TTL constraints cannot be safely verified.", None))?;
        let zone = self.zone(spec).await?;
        self.validate_ttl(spec, &zone, proxied)?;
        let action = "CloudflareUpdateRecord";
        // PATCH only these two properties. Omitting proxied/comment/tags/settings
        // preserves server metadata, including concurrent unrelated edits. Never PUT.
        let reply = self
            .api
            .send(
                action,
                self.request(
                    Method::PATCH,
                    &format!("/zones/{}/dns_records/{}", zone.id, record.id),
                )
                .json(&json!({"content": ip, "ttl": spec.ttl})),
                true,
            )
            .await?;
        self.mutation(action, &reply, Some(&record.id))
    }
}

fn dns_equal(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn collect_errors(
    errors: &[Value],
    codes: &mut Vec<String>,
    messages: &mut Vec<String>,
    depth: usize,
) {
    for error in errors {
        if codes.len() >= 16 || messages.len() >= 16 || depth > 3 {
            break;
        }
        let code = error.get("code").and_then(|code| {
            code.as_str()
                .map(str::to_owned)
                .or_else(|| code.is_number().then(|| code.to_string()))
        });
        if let Some(code) = &code {
            codes.push(code.clone());
        }
        if let Some(message) = error["message"].as_str() {
            messages.push(match code {
                Some(code) => format!("[{code}] {message}"),
                None => message.into(),
            });
        }
        if let Some(chain) = error["error_chain"].as_array() {
            collect_errors(chain, codes, messages, depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
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
        time::Duration,
    };

    #[derive(Clone, Debug)]
    struct Captured {
        method: Method,
        uri: String,
        authorization: Option<String>,
        global_key: bool,
        global_email: bool,
        body: Value,
    }

    struct MockState {
        replies: VecDeque<(u16, Value)>,
        requests: Vec<Captured>,
    }

    struct Mock {
        endpoint: String,
        state: Arc<Mutex<MockState>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn handler(
        State(state): State<Arc<Mutex<MockState>>>,
        request: Request<Body>,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let captured = Captured {
            method: parts.method,
            uri: parts.uri.to_string(),
            authorization: parts
                .headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().into()),
            global_key: parts.headers.contains_key("x-auth-key"),
            global_email: parts.headers.contains_key("x-auth-email"),
            body: if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        };
        let (status, body) = {
            let mut state = state.lock().unwrap();
            state.requests.push(captured);
            state.replies.pop_front().unwrap_or((500, json!({"success":false,"errors":[{"code":9999,"message":"Unexpected mock request"}]})))
        };
        let mut response = (StatusCode::from_u16(status).unwrap(), Json(body)).into_response();
        response
            .headers_mut()
            .insert("cf-ray", HeaderValue::from_static("ray-test-123-SJC"));
        response
    }

    impl Mock {
        async fn new(replies: Vec<(u16, Value)>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let state = Arc::new(Mutex::new(MockState {
                replies: replies.into(),
                requests: Vec::new(),
            }));
            let app = Router::new()
                .route("/{*path}", any(handler))
                .with_state(state.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                endpoint,
                state,
                task,
            }
        }

        fn adapter(&self, explicit: bool) -> Cloudflare {
            let options = if explicit {
                BTreeMap::from([("zone_id".into(), "zone-1".into())])
            } else {
                BTreeMap::new()
            };
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();
            let mut adapter = Cloudflare::new(client, "token-test".into(), &options);
            adapter.endpoint = self.endpoint.clone();
            adapter
        }

        fn requests(&self) -> Vec<Captured> {
            self.state.lock().unwrap().requests.clone()
        }
        fn assert_done(&self) {
            assert!(
                self.state.lock().unwrap().replies.is_empty(),
                "Not all expected requests were made"
            );
        }
    }

    fn spec() -> Spec {
        Spec {
            domain: "example.com".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "ignored-line".into(),
            ttl: 300,
            record_id: None,
            create_if_missing: true,
            options: BTreeMap::new(),
        }
    }

    fn zone_value() -> Value {
        json!({"id":"zone-1","name":"example.com","status":"active","paused":false,"plan":{"name":"Free","legacy_id":"free"}})
    }

    fn success(value: Value) -> (u16, Value) {
        (200, json!({"success":true,"errors":[],"result":value}))
    }

    fn page(values: Vec<Value>, page: u64, per_page: u64, total_count: u64) -> (u16, Value) {
        (
            200,
            json!({"success":true,"errors":[],"result":values,"result_info":{
                "page":page,"per_page":per_page,"count":values.len(),"total_count":total_count,"total_pages":total_count.div_ceil(per_page),
            }}),
        )
    }

    fn record_value(id: &str) -> Value {
        json!({"id":id,"type":"A","name":"home.example.com","content":"192.0.2.1","ttl":300,
            "proxied":false,"comment":"Keep this comment","tags":["owner:ddns"],"settings":{"ipv4_only":true},"meta":{"auto_added":false}})
    }

    fn record(id: &str, proxied: bool) -> Record {
        let mut extra = record_value(id);
        extra["proxied"] = json!(proxied);
        Record {
            id: id.into(),
            name: "home.example.com".into(),
            record_type: "A".into(),
            value: "192.0.2.1".into(),
            ttl: if proxied { 1 } else { 300 },
            line: String::new(),
            enabled: true,
            extra,
        }
    }

    #[tokio::test]
    async fn exact_zone_discovery_and_complete_record_pagination() {
        let mock = Mock::new(vec![
            page(vec![zone_value()], 1, 50, 1),
            page(vec![record_value("r1"), record_value("r2")], 1, 2, 3),
            page(vec![record_value("r3")], 2, 2, 3),
        ])
        .await;
        let result = mock.adapter(false).list(&spec()).await.unwrap();
        assert_eq!(result.records.len(), 3);
        assert_eq!(result.records[2].id, "r3");
        assert_eq!(result.request_id.as_deref(), Some("ray-test-123-SJC"));
        assert!(
            result
                .records
                .iter()
                .all(|r| r.line.is_empty() && r.enabled)
        );
        let requests = mock.requests();
        assert!(requests[0].uri.contains("name=example.com"));
        assert!(!requests[0].uri.contains("status="));
        assert!(requests[2].uri.contains("page=2"));
        for request in &requests {
            assert_eq!(request.method, Method::GET);
            assert_eq!(request.authorization.as_deref(), Some("Bearer token-test"));
            assert!(!request.global_key && !request.global_email);
        }
        mock.assert_done();
    }

    #[tokio::test]
    async fn explicit_zone_is_fetched_and_verified_before_list() {
        let mock = Mock::new(vec![
            success(zone_value()),
            page(vec![record_value("r1")], 1, 100, 1),
        ])
        .await;
        let result = mock.adapter(true).list(&spec()).await.unwrap();
        assert_eq!(result.records.len(), 1);
        assert_eq!(mock.requests()[0].uri, "/zones/zone-1");
        mock.assert_done();
    }

    #[tokio::test]
    async fn explicit_zone_name_mismatch_prevents_any_dns_request() {
        let mut zone = zone_value();
        zone["name"] = json!("other.example.com");
        let mock = Mock::new(vec![success(zone)]).await;
        let error = mock.adapter(true).list(&spec()).await.err().unwrap();
        assert_eq!(error.code, "ZoneMismatch");
        assert_eq!(mock.requests().len(), 1);
        mock.assert_done();
    }

    #[tokio::test]
    async fn explicit_zone_id_mismatch_is_refused() {
        let mut zone = zone_value();
        zone["id"] = json!("zone-2");
        let mock = Mock::new(vec![success(zone)]).await;
        let error = mock.adapter(true).list(&spec()).await.err().unwrap();
        assert_eq!(error.code, "ZoneMismatch");
        assert_eq!(mock.requests().len(), 1);
        mock.assert_done();
    }

    #[tokio::test]
    async fn inactive_zone_is_refused() {
        let mut zone = zone_value();
        zone["status"] = json!("pending");
        let mock = Mock::new(vec![success(zone)]).await;
        assert_eq!(
            mock.adapter(true).list(&spec()).await.err().unwrap().code,
            "ZoneInactive"
        );
        assert_eq!(mock.requests().len(), 1);
        mock.assert_done();
    }

    #[tokio::test]
    async fn duplicate_exact_zones_are_ambiguous_after_pagination() {
        let mut second = zone_value();
        second["id"] = json!("zone-2");
        let mock = Mock::new(vec![
            page(vec![zone_value()], 1, 1, 2),
            page(vec![second], 2, 1, 2),
        ])
        .await;
        assert_eq!(
            mock.adapter(false).list(&spec()).await.err().unwrap().code,
            "AmbiguousZones"
        );
        assert_eq!(mock.requests().len(), 2);
        mock.assert_done();
    }

    #[tokio::test]
    async fn discovery_requires_exact_not_suffix_zone_name() {
        let mut desired = spec();
        desired.domain = "sub.example.com".into();
        let mock = Mock::new(vec![page(vec![zone_value()], 1, 50, 1)]).await;
        assert_eq!(
            mock.adapter(false).list(&desired).await.err().unwrap().code,
            "ZoneMismatch"
        );
        mock.assert_done();
    }

    #[tokio::test]
    async fn missing_zone_never_creates_a_record() {
        let mock = Mock::new(vec![page(vec![], 1, 50, 0)]).await;
        assert_eq!(
            mock.adapter(false)
                .create(&spec(), "192.0.2.2")
                .await
                .err()
                .unwrap()
                .code,
            "ZoneNotFound"
        );
        assert!(mock.requests().iter().all(|r| r.method == Method::GET));
        mock.assert_done();
    }

    #[tokio::test]
    async fn error_envelope_retains_codes_messages_http_and_ray_without_token() {
        let mock = Mock::new(vec![(403,json!({"success":false,"errors":[{"code":10000,"message":"Authentication failed token-test","error_chain":[{"code":9109,"message":"Missing zone permission"}]}]}))]).await;
        let error = mock.adapter(true).list(&spec()).await.err().unwrap();
        assert_eq!(error.code, "10000");
        assert!(error.message.contains("[9109]"));
        assert!(error.message.contains("Authentication failed"));
        assert!(error.message.contains("Missing zone permission"));
        assert!(!format!("{error:?}").contains("token-test"));
        assert_eq!(error.http_status, Some(403));
        assert_eq!(error.request_id.as_deref(), Some("ray-test-123-SJC"));
        assert!(!error.retryable);
        mock.assert_done();
    }

    #[tokio::test]
    async fn http_200_failure_envelope_is_still_an_error() {
        let mock = Mock::new(vec![(
            200,
            json!({"success":false,"errors":[{"code":7003,"message":"Invalid route"}]}),
        )])
        .await;
        assert_eq!(
            mock.adapter(true).list(&spec()).await.err().unwrap().code,
            "7003"
        );
        mock.assert_done();
    }

    #[tokio::test]
    async fn second_page_error_never_returns_partial_list() {
        let mock = Mock::new(vec![
            success(zone_value()),
            page(vec![record_value("r1")], 1, 1, 2),
            (
                429,
                json!({"success":false,"errors":[{"code":1015,"message":"Rate limited"}]}),
            ),
        ])
        .await;
        let error = mock.adapter(true).list(&spec()).await.err().unwrap();
        assert_eq!(error.code, "1015");
        assert!(error.retryable);
        assert_eq!(mock.requests().len(), 3);
        mock.assert_done();
    }

    #[tokio::test]
    async fn repeated_record_ids_across_pages_are_refused() {
        let mock = Mock::new(vec![
            success(zone_value()),
            page(vec![record_value("r1")], 1, 1, 2),
            page(vec![record_value("r1")], 2, 1, 2),
        ])
        .await;
        assert_eq!(
            mock.adapter(true).list(&spec()).await.err().unwrap().code,
            "UnstablePagination"
        );
        mock.assert_done();
    }

    #[tokio::test]
    async fn incomplete_page_is_refused_instead_of_partial_success() {
        let mock = Mock::new(vec![
            success(zone_value()),
            page(vec![record_value("r1")], 1, 2, 3),
        ])
        .await;
        assert_eq!(
            mock.adapter(true).list(&spec()).await.err().unwrap().code,
            "InvalidPagination"
        );
        assert_eq!(mock.requests().len(), 2);
        mock.assert_done();
    }

    #[tokio::test]
    async fn changed_page_totals_are_refused() {
        let mock = Mock::new(vec![
            success(zone_value()),
            page(vec![record_value("r1")], 1, 1, 2),
            page(vec![record_value("r2")], 2, 1, 3),
        ])
        .await;
        assert_eq!(
            mock.adapter(true).list(&spec()).await.err().unwrap().code,
            "InvalidPagination"
        );
        mock.assert_done();
    }

    #[tokio::test]
    async fn missing_pagination_metadata_is_refused() {
        let mock = Mock::new(vec![
            success(zone_value()),
            success(json!([record_value("r1")])),
        ])
        .await;
        assert_eq!(
            mock.adapter(true).list(&spec()).await.err().unwrap().code,
            "InvalidPagination"
        );
        mock.assert_done();
    }

    #[tokio::test]
    async fn empty_record_list_is_complete_and_read_only() {
        let mock = Mock::new(vec![success(zone_value()), page(vec![], 1, 100, 0)]).await;
        assert!(
            mock.adapter(true)
                .list(&spec())
                .await
                .unwrap()
                .records
                .is_empty()
        );
        assert!(mock.requests().iter().all(|r| r.method == Method::GET));
        mock.assert_done();
    }

    #[tokio::test]
    async fn list_preserves_all_proxy_comment_tags_and_settings_metadata() {
        let original = record_value("r1");
        let mock = Mock::new(vec![
            success(zone_value()),
            page(vec![original.clone()], 1, 100, 1),
        ])
        .await;
        let result = mock.adapter(true).list(&spec()).await.unwrap();
        assert_eq!(result.records[0].extra, original);
        assert_eq!(result.records[0].extra["comment"], "Keep this comment");
        assert_eq!(result.records[0].name, "home.example.com");
        mock.assert_done();
    }

    #[tokio::test]
    async fn create_defaults_to_dns_only_and_sends_exact_body() {
        let mock = Mock::new(vec![
            success(zone_value()),
            success(json!({"id":"created-1"})),
        ])
        .await;
        let result = mock
            .adapter(true)
            .create(&spec(), "192.0.2.2")
            .await
            .unwrap();
        assert_eq!(result.record_id, "created-1");
        assert_eq!(result.request_id.as_deref(), Some("ray-test-123-SJC"));
        let requests = mock.requests();
        assert_eq!(requests[1].method, Method::POST);
        assert_eq!(requests[1].uri, "/zones/zone-1/dns_records");
        assert_eq!(
            requests[1].body,
            json!({"type":"A","name":"home.example.com","content":"192.0.2.2","ttl":300,"proxied":false})
        );
        mock.assert_done();
    }

    #[tokio::test]
    async fn create_supports_explicit_proxy_with_automatic_ttl() {
        let mut desired = spec();
        desired.ttl = 1;
        desired.options.insert("proxied".into(), "true".into());
        let mock = Mock::new(vec![
            success(zone_value()),
            success(json!({"id":"created-1"})),
        ])
        .await;
        mock.adapter(true)
            .create(&desired, "192.0.2.2")
            .await
            .unwrap();
        assert_eq!(mock.requests()[1].body["proxied"], true);
        assert_eq!(mock.requests()[1].body["ttl"], 1);
        mock.assert_done();
    }

    #[tokio::test]
    async fn update_patches_only_content_and_ttl_preserving_metadata() {
        let mut desired = spec();
        desired.ttl = 1;
        desired.options.insert("proxied".into(), "false".into());
        let selected = record("r1", true);
        let before = selected.extra.clone();
        let mock = Mock::new(vec![success(zone_value()), success(json!({"id":"r1"}))]).await;
        let result = mock
            .adapter(true)
            .update(&desired, &selected, "192.0.2.2")
            .await
            .unwrap();
        assert_eq!(result.record_id, "r1");
        let requests = mock.requests();
        assert_eq!(requests[1].method, Method::PATCH);
        assert_eq!(requests[1].uri, "/zones/zone-1/dns_records/r1");
        assert_eq!(requests[1].body, json!({"content":"192.0.2.2","ttl":1}));
        assert_eq!(selected.extra, before);
        mock.assert_done();
    }

    #[tokio::test]
    async fn write_failure_is_not_retried_or_retryable() {
        let mock = Mock::new(vec![success(zone_value()),(503,json!({"success":false,"errors":[{"code":1001,"message":"Temporary upstream error"}]}))]).await;
        let error = mock
            .adapter(true)
            .update(&spec(), &record("r1", false), "192.0.2.2")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, "1001");
        assert!(!error.retryable);
        assert_eq!(mock.requests().len(), 2);
        mock.assert_done();
    }

    #[tokio::test]
    async fn malformed_write_success_does_not_trigger_another_write() {
        let mock = Mock::new(vec![success(zone_value()), success(json!({}))]).await;
        let error = mock
            .adapter(true)
            .create(&spec(), "192.0.2.2")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, "InvalidWriteResponse");
        assert!(!error.retryable);
        assert_eq!(mock.requests().len(), 2);
        mock.assert_done();
    }

    #[tokio::test]
    async fn proxied_custom_ttl_is_rejected_before_post_or_patch() {
        let mut desired = spec();
        desired.options.insert("proxied".into(), "true".into());
        let mock = Mock::new(vec![success(zone_value()), success(zone_value())]).await;
        let adapter = mock.adapter(true);
        assert_eq!(
            adapter
                .create(&desired, "192.0.2.2")
                .await
                .err()
                .unwrap()
                .code,
            "UnsupportedTTL"
        );
        assert_eq!(
            adapter
                .update(&spec(), &record("r1", true), "192.0.2.2")
                .await
                .err()
                .unwrap()
                .code,
            "UnsupportedTTL"
        );
        assert!(mock.requests().iter().all(|r| r.method == Method::GET));
        mock.assert_done();
    }

    #[tokio::test]
    async fn unsupported_dns_only_ttl_is_rejected_on_list_and_write() {
        let mock = Mock::new(vec![success(zone_value()), success(zone_value())]).await;
        let adapter = mock.adapter(true);
        let mut desired = spec();
        desired.ttl = 30;
        assert_eq!(
            adapter.list(&desired).await.err().unwrap().code,
            "UnsupportedTTL"
        );
        desired.ttl = 86_401;
        assert_eq!(
            adapter
                .create(&desired, "192.0.2.2")
                .await
                .err()
                .unwrap()
                .code,
            "UnsupportedTTL"
        );
        assert!(mock.requests().iter().all(|r| r.method == Method::GET));
        mock.assert_done();
    }

    #[tokio::test]
    async fn enterprise_dns_only_ttl_30_is_supported() {
        let mut zone = zone_value();
        zone["plan"]["legacy_id"] = json!("enterprise");
        let mut desired = spec();
        desired.ttl = 30;
        let mock = Mock::new(vec![success(zone), success(json!({"id":"created-1"}))]).await;
        mock.adapter(true)
            .create(&desired, "192.0.2.2")
            .await
            .unwrap();
        assert_eq!(mock.requests()[1].body["ttl"], 30);
        mock.assert_done();
    }

    #[tokio::test]
    async fn invalid_proxy_option_and_ip_family_never_issue_requests() {
        let mock = Mock::new(vec![]).await;
        let adapter = mock.adapter(true);
        let mut desired = spec();
        desired.options.insert("proxied".into(), "yes".into());
        assert_eq!(
            adapter
                .create(&desired, "192.0.2.2")
                .await
                .err()
                .unwrap()
                .code,
            "InvalidProxied"
        );
        assert_eq!(
            adapter
                .create(&spec(), "2001:db8::1")
                .await
                .err()
                .unwrap()
                .code,
            "IpFamilyMismatch"
        );
        assert!(mock.requests().is_empty());
        mock.assert_done();
    }

    #[tokio::test]
    async fn aaaa_creation_uses_full_name_and_ipv6_content() {
        let mut desired = spec();
        desired.record_type = "AAAA".into();
        desired.subdomain = "@".into();
        desired.ttl = 1;
        let mock = Mock::new(vec![
            success(zone_value()),
            success(json!({"id":"created-6"})),
        ])
        .await;
        mock.adapter(true)
            .create(&desired, "2001:db8::1")
            .await
            .unwrap();
        assert_eq!(
            mock.requests()[1].body,
            json!({"type":"AAAA","name":"example.com","content":"2001:db8::1","ttl":1,"proxied":false})
        );
        mock.assert_done();
    }

    #[tokio::test]
    async fn common_dry_run_rejects_existing_proxy_custom_ttl_without_writes() {
        let mut desired = spec();
        desired.ttl = 600;
        // Create-only false cannot override the selected existing proxy state.
        desired.options.insert("proxied".into(), "false".into());
        for current_ttl in [1, 600] {
            let mut current = record_value("r1");
            current["proxied"] = json!(true);
            current["ttl"] = json!(current_ttl);
            let mock = Mock::new(vec![success(zone_value()), page(vec![current], 1, 100, 1)]).await;
            let error =
                super::super::common::reconcile(&mock.adapter(true), &desired, "192.0.2.1", true)
                    .await
                    .err()
                    .unwrap();
            assert_eq!(error.code, "UnsupportedTTL");
            assert!(mock.requests().iter().all(|r| r.method == Method::GET));
            assert_eq!(mock.requests().len(), 2);
            mock.assert_done();
        }
    }

    #[tokio::test]
    async fn common_dry_run_rejects_new_proxy_custom_ttl_without_writes() {
        let mut desired = spec();
        desired.ttl = 600;
        desired.options.insert("proxied".into(), "true".into());
        let mock = Mock::new(vec![success(zone_value()), page(vec![], 1, 100, 0)]).await;
        let error =
            super::super::common::reconcile(&mock.adapter(true), &desired, "192.0.2.2", true)
                .await
                .err()
                .unwrap();
        assert_eq!(error.code, "UnsupportedTTL");
        assert!(mock.requests().iter().all(|r| r.method == Method::GET));
        assert_eq!(mock.requests().len(), 2);
        mock.assert_done();
    }

    #[tokio::test]
    async fn common_dry_run_existing_proxy_auto_ttl_allows_update_and_noop() {
        let mut desired = spec();
        desired.ttl = 1;
        for (ip, expected) in [("192.0.2.1", "unchanged"), ("192.0.2.2", "would_update")] {
            let mut current = record_value("r1");
            current["proxied"] = json!(true);
            current["ttl"] = json!(1);
            let mock = Mock::new(vec![success(zone_value()), page(vec![current], 1, 100, 1)]).await;
            let outcome = super::super::common::reconcile(&mock.adapter(true), &desired, ip, true)
                .await
                .unwrap();
            assert_eq!(outcome.status, expected);
            assert!(mock.requests().iter().all(|r| r.method == Method::GET));
            assert_eq!(mock.requests().len(), 2);
            mock.assert_done();
        }
    }

    #[tokio::test]
    async fn common_dry_run_new_proxy_auto_ttl_allows_creation_without_writes() {
        let mut desired = spec();
        desired.ttl = 1;
        desired.options.insert("proxied".into(), "true".into());
        let mock = Mock::new(vec![success(zone_value()), page(vec![], 1, 100, 0)]).await;
        let outcome =
            super::super::common::reconcile(&mock.adapter(true), &desired, "192.0.2.2", true)
                .await
                .unwrap();
        assert_eq!(outcome.status, "would_create");
        assert!(mock.requests().iter().all(|r| r.method == Method::GET));
        assert_eq!(mock.requests().len(), 2);
        mock.assert_done();
    }

    #[tokio::test]
    async fn unrelated_record_or_unsafe_identifier_cannot_be_patched() {
        let mock = Mock::new(vec![]).await;
        let adapter = mock.adapter(true);
        let mut selected = record("r1", false);
        selected.name = "other.example.com".into();
        assert_eq!(
            adapter
                .update(&spec(), &selected, "192.0.2.2")
                .await
                .err()
                .unwrap()
                .code,
            "RecordMismatch"
        );
        selected = record("../../other", false);
        assert_eq!(
            adapter
                .update(&spec(), &selected, "192.0.2.2")
                .await
                .err()
                .unwrap()
                .code,
            "RecordMismatch"
        );
        assert!(mock.requests().is_empty());
        mock.assert_done();
    }
}
