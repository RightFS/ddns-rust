//! Tencent Cloud DNSPod API 3.0, fail-closed and without write retries.
//! Docs: https://cloud.tencent.com/document/api/1427/56189 (TC3), /56173
//! (DescribeDomain), /56166 (DescribeRecordList), /56157 (ModifyRecord), /56180
//! (CreateRecord). Supply a client with connect/total timeouts and redirects disabled.

// The public diagnostic DTO intentionally owns full error context on a cold path.
#![allow(clippy::result_large_err)]

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, net::IpAddr, time::Duration};

const API_HOST: &str = "dnspod.tencentcloudapi.com";
const ENDPOINT: &str = "https://dnspod.tencentcloudapi.com/";
const CONTENT_TYPE_VALUE: &str = "application/json; charset=utf-8";
const SIGNED_HEADERS: &str = "content-type;host;x-tc-action";
const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 100;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);

// Intentionally no Debug/Serialize: never put credentials in logs or JSON.
pub struct Credentials {
    pub secret_id: String,
    pub secret_key: String,
}

#[derive(Clone, Debug)]
pub struct RecordSpec {
    pub domain: String,
    pub subdomain: String,
    pub record_type: String,
    pub record_line: String,
    pub ttl: u64,
    pub record_id: Option<u64>,
    pub create_if_missing: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct Outcome {
    pub status: String,
    pub previous_ip: Option<String>,
    pub current_ip: String,
    pub record_id: Option<u64>,
    pub request_id: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ProviderError {
    pub stage: String,
    pub code: String,
    pub message: String,
    pub hint: String,
    pub request_id: Option<String>,
    pub http_status: Option<u16>,
    /// Transient read failure; never permission to automatically retry a write.
    pub retryable: bool,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} failed [{}]: {} (HTTP {}; RequestId: {}). Hint: {}",
            self.stage,
            self.code,
            self.message,
            self.http_status
                .map(|v| v.to_string())
                .unwrap_or_else(|| "unavailable".into()),
            self.request_id.as_deref().unwrap_or("unavailable"),
            self.hint
        )
    }
}
impl std::error::Error for ProviderError {}

pub struct Provider {
    client: reqwest::Client,
    credentials: Credentials,
    endpoint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DomainResponse {
    domain_info: DomainInfo,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DomainInfo {
    domain_id: u64,
    domain: String,
    status: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListResponse {
    record_list: Vec<Record>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Record {
    record_id: u64,
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    line: String,
    #[serde(default)]
    line_id: Option<String>,
    value: String,
    status: String,
    #[serde(rename = "TTL")]
    ttl: u64,
    #[serde(default)]
    weight: Option<u64>,
}
struct Reply {
    body: Value,
    request_id: Option<String>,
    http_status: u16,
}

impl Provider {
    pub fn new(client: reqwest::Client, credentials: Credentials) -> Self {
        Self {
            client,
            credentials,
            endpoint: ENDPOINT.into(),
        }
    }

    pub async fn reconcile(
        &self,
        spec: &RecordSpec,
        ip: &str,
        dry_run: bool,
    ) -> Result<Outcome, ProviderError> {
        let desired = self.validate(spec, ip)?;
        let domain_reply = self
            .call("DescribeDomain", json!({"Domain": spec.domain}))
            .await?;
        let domain: DomainResponse = self.decode("DescribeDomain", &domain_reply)?;
        if domain.domain_info.domain_id == 0
            || !domain.domain_info.domain.eq_ignore_ascii_case(&spec.domain)
        {
            return Err(local_error(
                "DescribeDomain",
                "ZoneMismatch",
                "DNSPod returned a different or invalid zone; no records were changed.",
                "Set domain to the exact DNSPod hosted zone, not the full host name; put the host prefix in subdomain.",
                Some(&domain_reply),
            ));
        }
        if !domain.domain_info.status.eq_ignore_ascii_case("enable") {
            return Err(local_error(
                "DescribeDomain",
                "DomainDisabled",
                "The DNSPod zone is paused, disabled, banned, or has an unknown status; no records were changed.",
                "Inspect the zone status in DNSPod and enable or unlock it deliberately before running again.",
                Some(&domain_reply),
            ));
        }
        let domain_id = domain.domain_info.domain_id;
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let mut last_reply = domain_reply;
        // Do not filter by line: an explicit RecordId selects its existing line,
        // which must be preserved rather than moved to the configured default.
        // Never select before completing pagination: another page may be ambiguous.
        for page in 0..MAX_PAGES {
            let reply = self
                .call(
                    "DescribeRecordList",
                    json!({
                        "Domain": spec.domain, "DomainId": domain_id,
                        "SubDomain": spec.subdomain, "RecordType": spec.record_type,
                        "Offset": page * PAGE_SIZE, "Limit": PAGE_SIZE, "ErrorOnEmpty": "no"
                    }),
                )
                .await?;
            let list: ListResponse = self.decode("DescribeRecordList", &reply)?;
            let count = list.record_list.len();
            if count > PAGE_SIZE {
                return Err(local_error(
                    "DescribeRecordList",
                    "InvalidPagination",
                    "DNSPod returned more records than the requested page limit; selection was stopped.",
                    "Inspect the API response using its RequestId; no mutation was attempted.",
                    Some(&reply),
                ));
            }
            for record in list.record_list {
                if record.record_id == 0 || !seen.insert(record.record_id) {
                    return Err(local_error(
                        "DescribeRecordList",
                        "UnstablePagination",
                        "The record list contains an invalid or repeated RecordId; safe selection is impossible.",
                        "Stop concurrent zone changes and run a fresh read; no records were changed.",
                        Some(&reply),
                    ));
                }
                records.push(record);
            }
            last_reply = reply;
            if count < PAGE_SIZE {
                break;
            }
            if page + 1 == MAX_PAGES {
                return Err(local_error(
                    "DescribeRecordList",
                    "PaginationLimit",
                    "The record list exceeded the safety limit of 10,000 records; no record was selected.",
                    "Narrow the configured subdomain/type or reduce the zone size; no mutation was attempted.",
                    Some(&last_reply),
                ));
            }
        }
        let selected = if let Some(id) = spec.record_id {
            let record = records.iter().find(|r| r.record_id == id).ok_or_else(||
                local_error("selection", "RecordIdNotFound", "The explicit RecordId was not found for the configured zone, host, and type; creation is refused even when create_if_missing is true.",
                    "Verify RecordId in DNSPod and correct domain/subdomain/type. A missing explicit ID never falls back to another record or creates a replacement.", Some(&last_reply)))?;
            if !record.name.eq_ignore_ascii_case(&spec.subdomain)
                || record.record_type != spec.record_type
            {
                return Err(local_error(
                    "selection",
                    "RecordIdMismatch",
                    "The explicit RecordId belongs to a different host or record type; no records were changed.",
                    "Correct RecordId or the configured host/type; DDNS never repurposes an unrelated record.",
                    Some(&last_reply),
                ));
            }
            Some(record)
        } else {
            let candidates: Vec<_> = records
                .iter()
                .filter(|r| {
                    r.name.eq_ignore_ascii_case(&spec.subdomain)
                        && r.record_type == spec.record_type
                        && r.line == spec.record_line
                })
                .collect();
            if candidates.len() > 1 {
                return Err(local_error(
                    "selection",
                    "AmbiguousRecords",
                    "Multiple records match the configured host, type, and line; refusing to silently select one.",
                    "Set an explicit record_id from DNSPod, or remove unintended duplicate records. Disabled records also count toward ambiguity.",
                    Some(&last_reply),
                ));
            }
            candidates.first().copied()
        };
        let Some(record) = selected else {
            if !spec.create_if_missing {
                return Err(local_error(
                    "selection",
                    "RecordNotFound",
                    "No record matches the configured host, type, and line, and create_if_missing is false; no record was created.",
                    "Verify the hosted zone, subdomain, record type and exact line name. Create the record manually or explicitly enable create_if_missing.",
                    Some(&last_reply),
                ));
            }
            if dry_run {
                return Ok(outcome(
                    "would_create",
                    None,
                    desired,
                    None,
                    last_reply.request_id,
                ));
            }
            let reply = self
                .call(
                    "CreateRecord",
                    json!({
                        "Domain": spec.domain, "DomainId": domain_id, "SubDomain": spec.subdomain,
                        "RecordType": spec.record_type, "RecordLine": spec.record_line,
                        "Value": desired, "TTL": spec.ttl, "Status": "ENABLE"
                    }),
                )
                .await?;
            let id = self.write_record_id("CreateRecord", &reply)?;
            return Ok(outcome(
                "created",
                None,
                desired,
                Some(id),
                reply.request_id,
            ));
        };
        if !record.status.eq_ignore_ascii_case("enable") {
            return Err(local_error(
                "selection",
                "RecordDisabled",
                "The selected DNSPod record is disabled or has an unknown status; it was skipped and was not enabled, updated, or replaced.",
                "Enable the intended record manually in DNSPod or select a different enabled RecordId; DDNS will not override an intentional pause.",
                Some(&last_reply),
            ));
        }
        if record.line.is_empty() {
            return Err(local_error(
                "selection",
                "InvalidRecordLine",
                "The selected record has no usable line name; no mutation was attempted.",
                "Inspect the selected record's line in DNSPod; the existing line must be preserved.",
                Some(&last_reply),
            ));
        }
        // Validate before exposing values in public Debug/Serialize DTOs.
        let previous = record.value.parse::<IpAddr>().map_err(|_| local_error("selection", "InvalidRecordValue",
            "The selected A/AAAA record does not contain a valid IP address; no records were changed.",
            "Inspect the selected record in DNSPod and correct its value manually.", Some(&last_reply)))?;
        if previous.is_ipv4() != desired.parse::<IpAddr>().expect("validated IP").is_ipv4() {
            return Err(local_error(
                "selection",
                "InvalidRecordValue",
                "The selected record value has the wrong IP family; no records were changed.",
                "Verify that the selected A record contains IPv4 or AAAA contains IPv6.",
                Some(&last_reply),
            ));
        }
        let previous = previous.to_string();
        if previous == desired && record.ttl == spec.ttl {
            return Ok(outcome(
                "unchanged",
                Some(previous),
                desired,
                Some(record.record_id),
                last_reply.request_id,
            ));
        }
        if dry_run {
            return Ok(outcome(
                "would_update",
                Some(previous),
                desired,
                Some(record.record_id),
                last_reply.request_id,
            ));
        }
        let mut body = json!({
            "Domain": spec.domain, "DomainId": domain_id, "SubDomain": record.name,
            "RecordId": record.record_id, "RecordType": record.record_type,
            "RecordLine": record.line, "Value": desired, "TTL": spec.ttl, "Status": "ENABLE"
        });
        if let Some(line_id) = &record.line_id
            && !line_id.is_empty()
        {
            body["RecordLineId"] = json!(line_id);
        }
        // Preserve load-balancing weight as well as the exact selected line.
        if let Some(weight) = record.weight {
            body["Weight"] = json!(weight);
        }
        let reply = self.call("ModifyRecord", body).await?;
        let id = self.write_record_id("ModifyRecord", &reply)?;
        if id != record.record_id {
            return Err(local_error(
                "ModifyRecord",
                "UnexpectedRecordId",
                "DNSPod acknowledged a different RecordId; the write result is uncertain and was not retried.",
                "Inspect the intended record in DNSPod and contact support with RequestId before making another write.",
                Some(&reply),
            ));
        }
        Ok(outcome(
            "updated",
            Some(previous),
            desired,
            Some(id),
            reply.request_id,
        ))
    }

    fn validate(&self, spec: &RecordSpec, ip: &str) -> Result<String, ProviderError> {
        if self.credentials.secret_id.is_empty()
            || self.credentials.secret_key.is_empty()
            || !self
                .credentials
                .secret_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
        {
            return Err(local_error(
                "validation",
                "InvalidCredentials",
                "Tencent Cloud API credentials are missing or the SecretId format is invalid.",
                "Provide a Tencent Cloud SecretId/SecretKey pair (not a legacy DNSPod token); never paste keys into logs.",
                None,
            ));
        }
        if spec.domain.is_empty()
            || spec.subdomain.is_empty()
            || spec.record_line.is_empty()
            || [&spec.domain, &spec.subdomain, &spec.record_line]
                .iter()
                .any(|s| s.trim() != s.as_str() || s.chars().any(char::is_control))
            || spec.domain.contains('/')
            || spec.domain.ends_with('.')
            || !spec.domain.contains('.')
        {
            return Err(local_error(
                "validation",
                "InvalidRecordSpec",
                "The DNSPod hosted zone, subdomain or exact record line is missing or malformed.",
                "Use domain=example.com, subdomain=www (or @ for the apex), and the exact DNSPod line name, such as 默认. Do not supply a URL or trailing dot.",
                None,
            ));
        }
        if !(1..=604800).contains(&spec.ttl) || spec.record_id == Some(0) {
            return Err(local_error(
                "validation",
                "InvalidRecordSpec",
                "TTL must be between 1 and 604800 seconds and any explicit RecordId must be positive.",
                "Choose a TTL allowed by your DNSPod plan; paid/free plans have different minimum TTLs.",
                None,
            ));
        }
        let parsed: IpAddr = ip.parse().map_err(|_| local_error("validation", "InvalidIp", "The desired record value is not an IPv4 or IPv6 address.",
            "Supply a plain IP address without a port, whitespace, URL, or IPv6 zone identifier.", None))?;
        if !matches!(
            (spec.record_type.as_str(), parsed),
            ("A", IpAddr::V4(_)) | ("AAAA", IpAddr::V6(_))
        ) {
            return Err(local_error(
                "validation",
                "IpFamilyMismatch",
                "DDNS supports only A with IPv4 or AAAA with IPv6; the type and desired address do not match.",
                "Set record_type to A or AAAA and use the corresponding IP-family detector.",
                None,
            ));
        }
        Ok(parsed.to_string())
    }

    fn decode<T: serde::de::DeserializeOwned>(
        &self,
        action: &str,
        reply: &Reply,
    ) -> Result<T, ProviderError> {
        serde_json::from_value(reply.body.clone()).map_err(|_| local_error(action, "MalformedResponse",
            "DNSPod returned an incomplete or invalid response; safe reconciliation was stopped.",
            "Check the API service/version and contact Tencent support with RequestId. Raw response contents are deliberately omitted. If this was a write, inspect the record before retrying.", Some(reply)))
    }

    fn write_record_id(&self, action: &str, reply: &Reply) -> Result<u64, ProviderError> {
        reply.body.get("RecordId").and_then(Value::as_u64).filter(|id| *id != 0).ok_or_else(|| local_error(action, "MalformedResponse",
            "DNSPod did not return a valid RecordId after the write; the result is uncertain and was not retried.",
            "Inspect the record in DNSPod using RequestId before attempting another write, especially CreateRecord.", Some(reply)))
    }

    async fn call(&self, action: &str, body: Value) -> Result<Reply, ProviderError> {
        let started = std::time::Instant::now();
        tracing::debug!(
            action,
            write = is_write(action),
            "DNSPod API action started"
        );
        let result =
            match tokio::time::timeout(REQUEST_DEADLINE, self.call_inner(action, body)).await {
                Ok(result) => result,
                Err(_) => {
                    let mut error = transport_error(action, "Timeout", is_write(action), None);
                    error.message.push_str(
                        " Transport detail: the 30-second provider request deadline elapsed.",
                    );
                    Err(error)
                }
            };
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match &result {
            Ok(reply) => tracing::debug!(action, http_status = reply.http_status,
                request_id = ?reply.request_id, elapsed_ms, "DNSPod API action completed"),
            Err(error) => tracing::debug!(action, http_status = ?error.http_status,
                request_id = ?error.request_id, code = %error.code, elapsed_ms,
                "DNSPod API action failed"),
        }
        result
    }

    async fn call_inner(&self, action: &str, body: Value) -> Result<Reply, ProviderError> {
        let write = is_write(action);
        let payload = serde_json::to_vec(&body).map_err(|_| local_error(action, "SerializationFailure", "The API request could not be encoded; no request was sent.",
            "Check the configured record parameters. Request contents are deliberately omitted.", None))?;
        let timestamp = Utc::now().timestamp();
        let auth = authorization(&self.credentials, action, &payload, timestamp)?;
        let mut auth = HeaderValue::from_str(&auth).map_err(|_| {
            local_error(
                action,
                "InvalidCredentials",
                "The authorization header could not be constructed; no request was sent.",
                "Check the SecretId format without logging credentials.",
                None,
            )
        })?;
        auth.set_sensitive(true);
        // Exactly the same serialized bytes are signed and sent; never .json()
        // reserialization, automatic write retries, raw body logs, or error Debug.
        let mut response = self
            .client
            .post(&self.endpoint)
            .header(HOST, API_HOST)
            .header(CONTENT_TYPE, CONTENT_TYPE_VALUE)
            .header(AUTHORIZATION, auth)
            .header("X-TC-Action", action)
            .header("X-TC-Version", "2021-03-23")
            .header("X-TC-Timestamp", timestamp.to_string())
            .header("X-TC-Language", "en-US")
            .body(payload)
            .send()
            .await
            .map_err(|e| {
                self.transport_failure(
                    action,
                    if e.is_timeout() {
                        "Timeout"
                    } else if e.is_connect() {
                        "ConnectionFailure"
                    } else {
                        "TransportFailure"
                    },
                    write,
                    None,
                    e,
                )
            })?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(response_limit_error(action, status));
        }
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            self.transport_failure(
                action,
                if e.is_timeout() {
                    "Timeout"
                } else {
                    "ResponseReadFailure"
                },
                write,
                Some(status),
                e,
            )
        })? {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(response_limit_error(action, status));
            }
            bytes.extend_from_slice(&chunk);
        }
        self.parse_reply(action, status, &bytes)
    }

    fn parse_reply(&self, action: &str, status: u16, bytes: &[u8]) -> Result<Reply, ProviderError> {
        let envelope: Value = serde_json::from_slice(bytes).map_err(|_| ProviderError {
            stage: action.into(), code: if (200..300).contains(&status) { "MalformedResponse".into() } else { format!("Http{status}") },
            message: "The API returned a non-JSON or invalid response; response contents were not exposed.".into(),
            hint: if is_write(action) { "The write result may be uncertain. Inspect DNSPod before retrying; check proxy/TLS/firewall settings.".into() }
                else { "Check proxy/TLS/firewall settings and Tencent service status; no mutation was attempted.".into() },
            request_id: None, http_status: Some(status), retryable: !is_write(action) && (status == 429 || status >= 500),
        })?;
        let body = envelope.get("Response").filter(|v| v.is_object()).ok_or_else(|| ProviderError {
            stage: action.into(), code: "MalformedResponse".into(), message: "DNSPod returned no valid Response envelope; reconciliation stopped.".into(),
            hint: "Verify the DNSPod API endpoint and version. If a write was sent, inspect the record before retrying.".into(),
            request_id: None, http_status: Some(status), retryable: false,
        })?;
        let request_id = body
            .get("RequestId")
            .and_then(Value::as_str)
            .and_then(|v| self.safe_identifier(v));
        // API errors normally use HTTP 200; check the envelope FIRST.
        if let Some(error) = body.get("Error").filter(|e| !e.is_null()) {
            let code = error
                .get("Code")
                .and_then(Value::as_str)
                .and_then(|v| self.safe_identifier(v))
                .unwrap_or_else(|| "ProviderApiError".into());
            let (message, hint, transient) = api_error_details(&code);
            let message = match error.get("Message").and_then(Value::as_str) {
                Some(detail) => format!(
                    "{message} Provider detail: {}",
                    self.sanitize_detail(detail)
                ),
                None => message.into(),
            };
            return Err(ProviderError {
                stage: action.into(),
                code,
                message,
                hint: if is_write(action) {
                    format!(
                        "{hint} This write was not automatically retried; inspect the record before another attempt."
                    )
                } else {
                    hint.into()
                },
                request_id,
                http_status: Some(status),
                retryable: transient && !is_write(action),
            });
        }
        if !(200..300).contains(&status) {
            return Err(ProviderError { stage: action.into(), code: format!("Http{status}"),
                message: "DNSPod returned an unsuccessful HTTP status without an API error envelope.".into(),
                hint: "Check permissions for HTTP 401/403, rate limits for 429, and service status for 5xx. Inspect any write before retrying.".into(),
                request_id, http_status: Some(status), retryable: !is_write(action) && (status == 429 || status >= 500) });
        }
        Ok(Reply {
            body: body.clone(),
            request_id,
            http_status: status,
        })
    }

    fn transport_failure(
        &self,
        action: &str,
        code: &str,
        write: bool,
        status: Option<u16>,
        cause: reqwest::Error,
    ) -> ProviderError {
        let mut error = transport_error(action, code, write, status);
        let cause = cause.without_url();
        let detail = self.sanitize_detail(&error_cause_chain(&cause));
        error.message.push_str(" Transport detail: ");
        error.message.push_str(&detail);
        error
    }

    // Only Error.Message and transport Display/source causes enter here, never
    // response bodies, payloads, headers or Debug representations. Remove log
    // control characters, redact exact credentials, omit token-bearing details,
    // then bound retained UTF-8 text to 2048 bytes.
    fn sanitize_detail(&self, value: &str) -> String {
        let mut text = value.to_string();
        for secret in [&self.credentials.secret_id, &self.credentials.secret_key] {
            if !secret.is_empty() {
                text = text.replace(secret.as_str(), "[REDACTED]");
            }
        }
        text = text.chars().filter(|c| !c.is_control()
            && !matches!(*c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')).collect();
        let lower: String = text
            .to_ascii_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if [
            "authorization",
            "signature=",
            "signature:",
            "credential=",
            "secretkey=",
            "secretkey:",
            "secret_key=",
            "secret_key:",
            "requestbody:",
            "requestheaders:",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
        {
            return "[Sensitive diagnostic detail omitted]".into();
        }
        if text.len() > 2048 {
            let mut end = 2048;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        if text.trim().is_empty() {
            "[No diagnostic detail provided]".into()
        } else {
            text
        }
    }

    fn safe_identifier(&self, value: &str) -> Option<String> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            || [&self.credentials.secret_id, &self.credentials.secret_key]
                .iter()
                .any(|secret| !secret.is_empty() && value.contains(secret.as_str()))
        {
            None
        } else {
            Some(value.into())
        }
    }
}

fn error_cause_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    for _ in 0..8 {
        let Some(cause) = source else {
            break;
        };
        let detail = cause.to_string();
        if parts.last() != Some(&detail) {
            parts.push(detail);
        }
        source = cause.source();
    }
    parts.join("; caused by: ")
}

fn outcome(
    status: &str,
    previous_ip: Option<String>,
    current_ip: String,
    record_id: Option<u64>,
    request_id: Option<String>,
) -> Outcome {
    Outcome {
        status: status.into(),
        previous_ip,
        current_ip,
        record_id,
        request_id,
    }
}
fn is_write(action: &str) -> bool {
    matches!(action, "CreateRecord" | "ModifyRecord")
}
fn local_error(
    stage: &str,
    code: &str,
    message: &str,
    hint: &str,
    reply: Option<&Reply>,
) -> ProviderError {
    ProviderError {
        stage: stage.into(),
        code: code.into(),
        message: message.into(),
        hint: hint.into(),
        request_id: reply.and_then(|r| r.request_id.clone()),
        http_status: reply.map(|r| r.http_status),
        retryable: false,
    }
}
fn transport_error(action: &str, code: &str, write: bool, status: Option<u16>) -> ProviderError {
    ProviderError {
        stage: action.into(),
        code: code.into(),
        message: if write {
            "The API write timed out or failed in transport; whether DNSPod applied it is uncertain. No automatic retry was made.".into()
        } else {
            "The DNSPod read timed out or failed in transport; no mutation was attempted.".into()
        },
        hint: if write {
            "Inspect the record in DNSPod before another write (especially creation). Check network/DNS/TLS, proxy settings, and the client's connect/total timeouts.".into()
        } else {
            "Check network/DNS/TLS, proxy settings, and the client's connect/total timeouts. Retry a fresh read only after connectivity is restored.".into()
        },
        request_id: None,
        http_status: status,
        retryable: !write,
    }
}
fn response_limit_error(action: &str, status: u16) -> ProviderError {
    ProviderError { stage: action.into(), code: "ResponseTooLarge".into(), message: "The API response exceeded the 1 MiB safety limit and was not processed.".into(),
        hint: "Check the API endpoint/proxy and narrow the record query. If this was a write, inspect the record before retrying.".into(),
        request_id: None, http_status: Some(status), retryable: false }
}
fn api_error_details(code: &str) -> (&'static str, &'static str, bool) {
    if code.contains("SignatureExpire") || code.contains("RequestExpired") {
        (
            "Tencent Cloud rejected the request timestamp because the signature expired or the clock is skewed.",
            "Synchronize the system clock with NTP; UTC timestamps must be within five minutes of Tencent Cloud time.",
            false,
        )
    } else if code.contains("SignatureFailure")
        || code.contains("SecretId")
        || code.starts_with("AuthFailure")
    {
        (
            "Tencent Cloud rejected API authentication or TC3 signature verification.",
            "Verify the Tencent Cloud SecretId/SecretKey pair is active (not a DNSPod legacy token), synchronize the clock with NTP, and check that a proxy does not alter signed headers/body.",
            false,
        )
    } else if code.starts_with("UnauthorizedOperation")
        || code.starts_with("OperationDenied")
        || code.contains("NotDomainOwner")
    {
        (
            "The API identity does not have permission to access or modify this DNSPod zone.",
            "Grant least-privilege CAM access to dnspod:DescribeDomain and dnspod:DescribeRecordList plus dnspod:ModifyRecord (and dnspod:CreateRecord only if enabled); verify zone ownership/shared write access and resource scope.",
            false,
        )
    } else if code.contains("DomainNotExists")
        || code.contains("DomainInvalid")
        || code.contains("DomainIdInvalid")
        || code.contains("DomainIsAliaser")
    {
        (
            "The configured DNSPod zone does not exist, is invalid, or is an alias rather than the hosted zone.",
            "Use the exact zone shown in DNSPod (example.com), not a host such as www.example.com; configure the host prefix separately and verify the correct Tencent account.",
            false,
        )
    } else if code.contains("RecordLine") {
        (
            "DNSPod rejected the configured record line.",
            "Use the exact supported line name from DescribeRecordLineList; do not translate 默认 into Default or replace an existing selected line.",
            false,
        )
    } else if code.contains("Ttl") || code.contains("TTL") {
        (
            "DNSPod rejected the requested TTL for this zone's plan.",
            "Choose a TTL between 1 and 604800 seconds and at least the minimum allowed by the DNSPod plan.",
            false,
        )
    } else if code.contains("NoDataOfRecord") || code.contains("RecordIdInvalid") {
        (
            "DNSPod could not find the requested record or record list.",
            "Verify zone, subdomain, type, line and explicit RecordId. No replacement record is silently created; recent creations may need 30 seconds to appear in the index.",
            false,
        )
    } else if code.starts_with("RequestLimitExceeded") || code.contains("FrequencyLimit") {
        (
            "Tencent Cloud throttled this action because its request rate limit was exceeded.",
            "Reduce DDNS frequency and concurrent callers; wait before a fresh read. Never blindly repeat an uncertain write.",
            true,
        )
    } else if code.starts_with("InternalError")
        || code.starts_with("ServiceUnavailable")
        || code.contains("UnknowError")
    {
        (
            "DNSPod reported a transient internal service failure.",
            "Check Tencent Cloud service status and retain RequestId for support; inspect the record before repeating a write.",
            true,
        )
    } else if code.contains("DomainIsLocked")
        || code.contains("DomainIsSpam")
        || code.contains("DomainNotAllowedModify")
    {
        (
            "DNSPod blocked changes because the zone is locked, banned, or not in a modifiable state.",
            "Inspect domain status in the DNSPod console and contact Tencent support if needed; DDNS will not unlock or enable it automatically.",
            false,
        )
    } else {
        (
            "DNSPod rejected this API action; the provider error code and sanitized provider detail identify the failure.",
            "Inspect this action's API documentation and verify zone, record parameters, CAM permissions and account status; contact Tencent support with RequestId.",
            false,
        )
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}
fn authorization(
    credentials: &Credentials,
    action: &str,
    payload: &[u8],
    timestamp: i64,
) -> Result<String, ProviderError> {
    let date = DateTime::<Utc>::from_timestamp(timestamp, 0)
        .ok_or_else(|| {
            local_error(
                "signing",
                "InvalidTimestamp",
                "The system timestamp cannot be represented in UTC; no request was sent.",
                "Correct and synchronize the system clock.",
                None,
            )
        })?
        .format("%Y-%m-%d")
        .to_string();
    let canonical_headers = format!(
        "content-type:{CONTENT_TYPE_VALUE}\nhost:{API_HOST}\nx-tc-action:{}\n",
        action.to_ascii_lowercase()
    );
    let canonical_request = format!(
        "POST\n/\n\n{canonical_headers}\n{SIGNED_HEADERS}\n{}",
        hex::encode(Sha256::digest(payload))
    );
    let scope = format!("{date}/dnspod/tc3_request");
    let to_sign = format!(
        "TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let date_key = hmac_sha256(
        format!("TC3{}", credentials.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let service_key = hmac_sha256(&date_key, b"dnspod");
    let signing_key = hmac_sha256(&service_key, b"tc3_request");
    let signature = hex::encode(hmac_sha256(&signing_key, to_sign.as_bytes()));
    Ok(format!(
        "TC3-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={SIGNED_HEADERS}, Signature={signature}",
        credentials.secret_id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    use tokio::task::JoinHandle;

    fn credentials() -> Credentials {
        Credentials {
            secret_id: "AKIDTestOnly".into(),
            secret_key: "test-secret-not-real".into(),
        }
    }
    fn spec() -> RecordSpec {
        RecordSpec {
            domain: "example.com".into(),
            subdomain: "www".into(),
            record_type: "A".into(),
            record_line: "默认".into(),
            ttl: 600,
            record_id: None,
            create_if_missing: false,
        }
    }
    fn domain() -> Value {
        json!({"Response":{"RequestId":"domain-request", "DomainInfo":{"DomainId":42,"Domain":"example.com","Status":"enable"}}})
    }
    fn record(id: u64) -> Value {
        json!({"RecordId":id,"Name":"www","Type":"A","Line":"默认","LineId":"0","Value":"192.0.2.1","Status":"ENABLE","TTL":600})
    }
    fn list(records: Vec<Value>) -> Value {
        json!({"Response":{"RequestId":"list-request","RecordList":records}})
    }
    fn api_error(code: &str) -> Value {
        json!({"Response":{"RequestId":"error-request","Error":{"Code":code,"Message":"Authorization: test-secret-not-real AKIDTestOnly raw-request-body"}}})
    }
    #[derive(Clone)]
    struct Seen {
        action: String,
        body: Value,
        signature_valid: bool,
    }
    struct Scripted {
        status: StatusCode,
        body: String,
        delay: Duration,
    }
    impl Scripted {
        fn json(body: Value) -> Self {
            Self {
                status: StatusCode::OK,
                body: body.to_string(),
                delay: Duration::ZERO,
            }
        }
    }
    #[derive(Clone)]
    struct MockState {
        queue: Arc<Mutex<VecDeque<Scripted>>>,
        seen: Arc<Mutex<Vec<Seen>>>,
    }
    struct Mock {
        provider: Provider,
        seen: Arc<Mutex<Vec<Seen>>>,
        task: JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Mock {
        async fn new(script: Vec<Value>) -> Self {
            Self::scripted(
                script.into_iter().map(Scripted::json).collect(),
                Duration::from_secs(2),
            )
            .await
        }
        async fn scripted(script: Vec<Scripted>, timeout: Duration) -> Self {
            async fn handler(
                State(state): State<MockState>,
                headers: HeaderMap,
                bytes: Bytes,
            ) -> (StatusCode, String) {
                let action = headers
                    .get("x-tc-action")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let timestamp = headers
                    .get("x-tc-timestamp")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse::<i64>()
                    .unwrap();
                let expected = authorization(&credentials(), &action, &bytes, timestamp).unwrap();
                let valid = headers.get(AUTHORIZATION).unwrap().to_str().unwrap() == expected
                    && headers.get(CONTENT_TYPE).unwrap() == CONTENT_TYPE_VALUE
                    && headers.get(HOST).unwrap() == API_HOST
                    && headers.get("x-tc-version").unwrap() == "2021-03-23";
                state.seen.lock().unwrap().push(Seen {
                    action,
                    body: serde_json::from_slice(&bytes).unwrap(),
                    signature_valid: valid,
                });
                let next = state
                    .queue
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Scripted {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        body: "Unexpected request".into(),
                        delay: Duration::ZERO,
                    });
                if !next.delay.is_zero() {
                    tokio::time::sleep(next.delay).await;
                }
                (next.status, next.body)
            }
            let seen = Arc::new(Mutex::new(Vec::new()));
            let state = MockState {
                queue: Arc::new(Mutex::new(script.into())),
                seen: seen.clone(),
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(
                    listener,
                    Router::new().route("/", post(handler)).with_state(state),
                )
                .await
                .unwrap();
            });
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(timeout)
                .timeout(timeout)
                .build()
                .unwrap();
            let mut provider = Provider::new(client, credentials());
            provider.endpoint = format!("http://{addr}/");
            Self {
                provider,
                seen,
                task,
            }
        }
        fn requests(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
        fn assert_reads_only(&self, expected: usize) {
            let requests = self.requests();
            assert_eq!(requests.len(), expected);
            assert!(
                requests
                    .iter()
                    .all(|r| !is_write(&r.action) && r.signature_valid)
            );
        }
    }

    #[test]
    fn tc3_golden_independently_computed_with_python_stdlib() {
        // Python hashlib/hmac, UTF-8, UTC timestamp, three binary key-derivation
        // rounds, NOT generated by the Rust implementation under test.
        // payload SHA256 a29f72dc6ea1d96e576baa90b7c0dd3446f0d256c59fd3a2b97a9a275ffd2a31
        // canonical SHA256 9f33cd2f0782151bbfd68523724076b1a86aa2be67aa7fce29d2397d2eb7bf6d
        let credentials = Credentials {
            secret_id: "AKIDGolden".into(),
            secret_key: "golden-secret".into(),
        };
        let actual = authorization(
            &credentials,
            "DescribeDomain",
            br#"{"Domain":"example.com"}"#,
            1551113065,
        )
        .unwrap();
        assert_eq!(
            actual,
            "TC3-HMAC-SHA256 Credential=AKIDGolden/2019-02-25/dnspod/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature=c2ce8849cda138bcfa2bd2f94250c111575e5c6be5a10a7888aea1adb9483eaf"
        );
    }

    #[test]
    fn signing_uses_exact_bytes_action_and_utc_date() {
        let c = credentials();
        let a = authorization(
            &c,
            "CreateRecord",
            "{\"RecordLine\":\"默认\"}".as_bytes(),
            1551113065,
        )
        .unwrap();
        let b = authorization(
            &c,
            "CreateRecord",
            "{\"RecordLine\": \"默认\"}".as_bytes(),
            1551113065,
        )
        .unwrap();
        assert_ne!(a, b);
        assert_ne!(
            a,
            authorization(
                &c,
                "ModifyRecord",
                "{\"RecordLine\":\"默认\"}".as_bytes(),
                1551113065
            )
            .unwrap()
        );
        assert!(a.contains("/2019-02-25/dnspod/")); // Already next date in UTC+8.
        assert!(
            authorization(&c, "DescribeDomain", b"{}", 1551139200)
                .unwrap()
                .contains("/2019-02-26/dnspod/")
        );
    }

    #[tokio::test]
    async fn http_200_error_envelope_is_not_success_and_secrets_never_escape() {
        let mock = Mock::new(vec![api_error("UnauthorizedOperation")]).await;
        let error = mock
            .provider
            .reconcile(&spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "UnauthorizedOperation");
        assert_eq!(error.stage, "DescribeDomain");
        assert_eq!(error.http_status, Some(200));
        assert_eq!(error.request_id.as_deref(), Some("error-request"));
        assert!(error.hint.contains("dnspod:ModifyRecord"));
        assert!(!error.retryable);
        let exposed = format!(
            "{error} {error:?} {}",
            serde_json::to_string(&error).unwrap()
        );
        for forbidden in [
            "AKIDTestOnly",
            "test-secret-not-real",
            "Authorization:",
            "raw-request-body",
        ] {
            assert!(!exposed.contains(forbidden));
        }
        assert!(exposed.contains("HTTP 200") && exposed.contains("RequestId: error-request"));
        mock.assert_reads_only(1);
    }

    #[test]
    fn clock_zone_timeout_and_permission_hints_are_actionable() {
        for (code, text) in [
            ("AuthFailure.SignatureExpire", "NTP"),
            ("InvalidParameterValue.DomainNotExists", "host prefix"),
            ("AuthFailure.SignatureFailure", "SecretId/SecretKey"),
            ("OperationDenied.NoPermissionToOperateDomain", "CAM"),
        ] {
            let (_, hint, transient) = api_error_details(code);
            assert!(hint.contains(text));
            assert!(!transient);
        }
        assert!(
            transport_error("ModifyRecord", "Timeout", true, None)
                .hint
                .contains("before another write")
        );
    }

    #[tokio::test]
    async fn dry_run_update_never_writes() {
        let mock = Mock::new(vec![domain(), list(vec![record(1)])]).await;
        let result = mock
            .provider
            .reconcile(&spec(), "192.0.2.2", true)
            .await
            .unwrap();
        assert_eq!(result.status, "would_update");
        assert_eq!(result.previous_ip.as_deref(), Some("192.0.2.1"));
        assert_eq!(result.current_ip, "192.0.2.2");
        assert_eq!(result.record_id, Some(1));
        mock.assert_reads_only(2);
    }

    #[tokio::test]
    async fn dry_run_create_never_writes_and_missing_is_not_silently_created() {
        for create in [false, true] {
            let mock = Mock::new(vec![domain(), list(vec![])]).await;
            let mut spec = spec();
            spec.create_if_missing = create;
            let result = mock.provider.reconcile(&spec, "192.0.2.2", true).await;
            if create {
                let result = result.unwrap();
                assert_eq!(result.status, "would_create");
                assert_eq!(result.record_id, None);
            } else {
                assert_eq!(result.unwrap_err().code, "RecordNotFound");
            }
            mock.assert_reads_only(2);
        }
        let mock = Mock::new(vec![domain(), list(vec![])]).await;
        assert_eq!(
            mock.provider
                .reconcile(&spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "RecordNotFound"
        );
        mock.assert_reads_only(2);
    }

    #[tokio::test]
    async fn ambiguous_records_fail_in_both_modes_even_if_one_disabled() {
        for dry_run in [false, true] {
            let mut disabled = record(2);
            disabled["Status"] = json!("DISABLE");
            let mock = Mock::new(vec![domain(), list(vec![record(1), disabled])]).await;
            let error = mock
                .provider
                .reconcile(&spec(), "192.0.2.2", dry_run)
                .await
                .unwrap_err();
            assert_eq!(error.code, "AmbiguousRecords");
            assert!(error.hint.contains("record_id"));
            mock.assert_reads_only(2);
        }
    }

    #[tokio::test]
    async fn ambiguity_on_later_page_is_not_silently_ignored() {
        let first: Vec<Value> = (1..=PAGE_SIZE as u64)
            .map(|id| {
                let mut r = record(id);
                if id != 1 {
                    r["Line"] = json!("电信");
                }
                r
            })
            .collect();
        let mock = Mock::new(vec![domain(), list(first), list(vec![record(101)])]).await;
        assert_eq!(
            mock.provider
                .reconcile(&spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "AmbiguousRecords"
        );
        mock.assert_reads_only(3);
        assert_eq!(mock.requests()[2].body["Offset"], 100);
        assert_eq!(mock.requests()[1].body["ErrorOnEmpty"], "no");
    }

    #[tokio::test]
    async fn explicit_id_resolves_ambiguity_and_preserves_its_line_weight_and_ttl() {
        let mut chosen = record(2);
        chosen["Line"] = json!("电信");
        chosen["LineId"] = json!("10=0");
        chosen["Weight"] = json!(20);
        let mock = Mock::new(vec![
            domain(),
            list(vec![record(1), chosen]),
            json!({"Response":{"RecordId":2,"RequestId":"write-request"}}),
        ])
        .await;
        let mut spec = spec();
        spec.record_id = Some(2);
        spec.ttl = 120;
        // Same IP, different TTL must still issue ModifyRecord.
        let result = mock
            .provider
            .reconcile(&spec, "192.0.2.1", false)
            .await
            .unwrap();
        assert_eq!(result.status, "updated");
        assert_eq!(result.request_id.as_deref(), Some("write-request"));
        let requests = mock.requests();
        assert_eq!(requests.len(), 3);
        let write = &requests[2];
        assert_eq!(write.action, "ModifyRecord");
        assert!(write.signature_valid);
        assert_eq!(write.body["RecordLine"], "电信");
        assert_eq!(write.body["RecordLineId"], "10=0");
        assert_eq!(write.body["RecordId"], 2);
        assert_eq!(write.body["Weight"], 20);
        assert_eq!(write.body["TTL"], 120);
        assert_eq!(write.body["DomainId"], 42);
        assert_eq!(write.body["SubDomain"], "www");
    }

    #[tokio::test]
    async fn explicit_missing_or_mismatched_id_never_creates() {
        for mismatch in [false, true] {
            let mut r = record(1);
            if mismatch {
                r["Name"] = json!("other");
            }
            let mock = Mock::new(vec![domain(), list(vec![r])]).await;
            let mut spec = spec();
            spec.create_if_missing = true;
            spec.record_id = Some(if mismatch { 1 } else { 99 });
            let error = mock
                .provider
                .reconcile(&spec, "192.0.2.2", false)
                .await
                .unwrap_err();
            assert_eq!(
                error.code,
                if mismatch {
                    "RecordIdMismatch"
                } else {
                    "RecordIdNotFound"
                }
            );
            mock.assert_reads_only(2);
        }
    }

    #[tokio::test]
    async fn disabled_record_is_not_updated_enabled_or_replaced() {
        for dry_run in [false, true] {
            let mut r = record(1);
            r["Status"] = json!("DISABLE");
            let mock = Mock::new(vec![domain(), list(vec![r])]).await;
            let mut spec = spec();
            spec.create_if_missing = true;
            let error = mock
                .provider
                .reconcile(&spec, "192.0.2.1", dry_run)
                .await
                .unwrap_err();
            assert_eq!(error.code, "RecordDisabled");
            assert!(error.message.contains("skipped"));
            mock.assert_reads_only(2);
        }
    }

    #[tokio::test]
    async fn unchanged_ip_and_ttl_do_not_write_and_ipv6_comparison_is_semantic() {
        let mut r = record(1);
        r["Type"] = json!("AAAA");
        r["Value"] = json!("2001:0db8:0000:0000:0000:0000:0000:0001");
        let mock = Mock::new(vec![domain(), list(vec![r])]).await;
        let mut spec = spec();
        spec.record_type = "AAAA".into();
        let result = mock
            .provider
            .reconcile(&spec, "2001:db8::1", false)
            .await
            .unwrap();
        assert_eq!(result.status, "unchanged");
        assert_eq!(result.current_ip, "2001:db8::1");
        mock.assert_reads_only(2);
    }

    #[tokio::test]
    async fn creation_requires_opt_in_and_returns_server_record_id() {
        let mock = Mock::new(vec![
            domain(),
            list(vec![]),
            json!({"Response":{"RecordId":77,"RequestId":"create-request"}}),
        ])
        .await;
        let mut spec = spec();
        spec.create_if_missing = true;
        let result = mock
            .provider
            .reconcile(&spec, "192.0.2.2", false)
            .await
            .unwrap();
        assert_eq!(result.status, "created");
        assert_eq!(result.record_id, Some(77));
        assert_eq!(result.previous_ip, None);
        let requests = mock.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[2].action, "CreateRecord");
        assert!(requests[2].signature_valid);
        assert_eq!(requests[2].body["RecordLine"], "默认");
        assert_eq!(requests[2].body["TTL"], 600);
        assert!(requests[2].body.get("RecordId").is_none());
    }

    #[tokio::test]
    async fn writes_are_not_retried_on_http_200_internal_error() {
        let mock = Mock::new(vec![
            domain(),
            list(vec![record(1)]),
            api_error("InternalError"),
        ])
        .await;
        let error = mock
            .provider
            .reconcile(&spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.stage, "ModifyRecord");
        assert_eq!(error.code, "InternalError");
        assert!(!error.retryable);
        assert_eq!(mock.requests().len(), 3);
        assert!(error.hint.contains("not automatically retried"));
    }

    #[tokio::test]
    async fn malformed_list_and_unstable_pagination_fail_closed() {
        let mut spec = spec();
        spec.create_if_missing = true;
        for response in [
            json!({"Response":{"RequestId":"malformed","RecordList":null}}),
            list(vec![record(1), record(1)]),
        ] {
            let mock = Mock::new(vec![domain(), response]).await;
            let error = mock
                .provider
                .reconcile(&spec, "192.0.2.2", false)
                .await
                .unwrap_err();
            assert!(matches!(
                error.code.as_str(),
                "MalformedResponse" | "UnstablePagination"
            ));
            mock.assert_reads_only(2);
        }
    }

    #[tokio::test]
    async fn malformed_write_acknowledgement_is_uncertain_and_never_retried() {
        for response in [
            json!({"Response":{"RequestId":"write-request"}}),
            json!({"Response":{"RecordId":99,"RequestId":"write-request"}}),
        ] {
            let mock = Mock::new(vec![domain(), list(vec![record(1)]), response]).await;
            let error = mock
                .provider
                .reconcile(&spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert!(!error.retryable);
            assert_eq!(mock.requests().len(), 3);
            assert!(matches!(
                error.code.as_str(),
                "MalformedResponse" | "UnexpectedRecordId"
            ));
        }
    }

    #[tokio::test]
    async fn client_timeout_is_honored_without_raw_transport_errors() {
        let response = Scripted {
            status: StatusCode::OK,
            body: domain().to_string(),
            delay: Duration::from_millis(200),
        };
        let mock = Mock::scripted(vec![response], Duration::from_millis(30)).await;
        let error = mock
            .provider
            .reconcile(&spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "Timeout");
        assert!(error.retryable);
        assert_eq!(error.http_status, None);
        assert!(error.hint.contains("timeouts"));
        assert!(!error.to_string().contains("http://"));
        mock.assert_reads_only(1);
    }

    #[tokio::test]
    async fn response_size_is_bounded() {
        let response = Scripted {
            status: StatusCode::OK,
            body: "x".repeat(MAX_RESPONSE_BYTES + 1),
            delay: Duration::ZERO,
        };
        let mock = Mock::scripted(vec![response], Duration::from_secs(2)).await;
        let error = mock
            .provider
            .reconcile(&spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "ResponseTooLarge");
        assert_eq!(error.http_status, Some(200));
        assert!(!error.retryable);
        mock.assert_reads_only(1);
    }

    #[tokio::test]
    async fn chunked_response_without_content_length_is_also_bounded() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let count = socket.read(&mut request).await.unwrap();
            assert!(count > 0);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let chunk = vec![b'x'; 16384];
            for _ in 0..65 {
                if socket.write_all(b"4000\r\n").await.is_err() {
                    return;
                }
                if socket.write_all(&chunk).await.is_err() {
                    return;
                }
                if socket.write_all(b"\r\n").await.is_err() {
                    return;
                }
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let mut provider = Provider::new(client, credentials());
        provider.endpoint = format!("http://{addr}/");
        let error = provider
            .reconcile(&spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "ResponseTooLarge");
        assert_eq!(error.http_status, Some(200));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn timed_out_write_is_uncertain_not_retryable_and_not_repeated() {
        let delayed = Scripted {
            status: StatusCode::OK,
            body: "{}".into(),
            delay: Duration::from_millis(200),
        };
        let mock = Mock::scripted(
            vec![
                Scripted::json(domain()),
                Scripted::json(list(vec![record(1)])),
                delayed,
            ],
            Duration::from_millis(40),
        )
        .await;
        let error = mock
            .provider
            .reconcile(&spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.stage, "ModifyRecord");
        assert_eq!(error.code, "Timeout");
        assert!(!error.retryable);
        assert!(error.message.contains("uncertain"));
        assert_eq!(mock.requests().len(), 3);
    }

    #[tokio::test]
    async fn unsuccessful_http_status_and_malformed_envelope_are_errors() {
        let mock = Mock::new(vec![]).await;
        for (status, body, code) in [
            (503, b"proxy raw body".as_slice(), "Http503"),
            (200, b"{}".as_slice(), "MalformedResponse"),
            (
                403,
                br#"{"Response":{"RequestId":"http-error"}}"#.as_slice(),
                "Http403",
            ),
        ] {
            let error = mock
                .provider
                .parse_reply("DescribeDomain", status, body)
                .err()
                .unwrap();
            assert_eq!(error.code, code);
            assert_eq!(error.http_status, Some(status));
            assert!(!format!("{error:?}").contains("proxy raw body"));
        }
        let error = mock
            .provider
            .parse_reply("ModifyRecord", 503, b"proxy")
            .err()
            .unwrap();
        assert!(!error.retryable);
    }

    #[tokio::test]
    async fn action_debug_traces_have_status_timing_request_id_but_no_payload_or_auth() {
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(move || Capture(sink.clone()))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let mock = Mock::new(vec![domain(), list(vec![record(1)])]).await;
        mock.provider
            .reconcile(&spec(), "192.0.2.2", true)
            .await
            .unwrap();
        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        for required in [
            "DescribeDomain",
            "DescribeRecordList",
            "action started",
            "action completed",
            "http_status=200",
            "elapsed_ms=",
            "domain-request",
            "list-request",
        ] {
            assert!(logs.contains(required), "missing field {required}");
        }
        for forbidden in [
            "AKIDTestOnly",
            "test-secret-not-real",
            "Authorization",
            "RecordList",
            "192.0.2.2",
            "Payload",
        ] {
            // DescribeRecordList is the public action, not a serialized RecordList.
            if forbidden == "RecordList" {
                assert!(!logs.contains("\"RecordList\""));
            } else {
                assert!(!logs.contains(forbidden));
            }
        }
    }

    #[tokio::test]
    async fn original_meaningful_api_detail_is_retained_with_http_200() {
        let body = json!({"Response":{"RequestId":"detail-request","Error":{
            "Code":"InvalidParameter.CustomMessage", "Message":"TTL 60 is below this zone's minimum of 600 seconds."}}});
        let mock = Mock::new(vec![body]).await;
        let error = mock
            .provider
            .reconcile(&spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.http_status, Some(200));
        assert!(
            error
                .message
                .contains("Provider detail: TTL 60 is below this zone's minimum of 600 seconds.")
        );
        assert_eq!(error.request_id.as_deref(), Some("detail-request"));
    }

    #[tokio::test]
    async fn harmless_provider_detail_survives_exact_credential_redaction() {
        let mock = Mock::new(vec![]).await;
        let body = json!({"Response":{"RequestId":"detail-request","Error":{
            "Code":"UnauthorizedOperation", "Message":"Identity AKIDTestOnly using test-secret-not-real cannot modify this shared read-only zone."}}});
        let error = mock
            .provider
            .parse_reply("ModifyRecord", 200, body.to_string().as_bytes())
            .err()
            .unwrap();
        assert!(
            error
                .message
                .contains("cannot modify this shared read-only zone")
        );
        assert!(error.message.contains("[REDACTED]"));
        let serialized = serde_json::to_string(&error).unwrap();
        assert!(
            !serialized.contains("AKIDTestOnly") && !serialized.contains("test-secret-not-real")
        );
        for detail in [
            "Authorization: Bearer unknown-token",
            "Signature=unknown-signature",
            "SigNaTuRe: token",
            "Credential=unknown-key",
        ] {
            assert_eq!(
                mock.provider.sanitize_detail(detail),
                "[Sensitive diagnostic detail omitted]"
            );
        }
        let bounded = mock.provider.sanitize_detail(&format!(
            "harmless\n\r\u{1b}\u{202e}{}",
            "说明".repeat(1500)
        ));
        assert!(bounded.len() <= 2048);
        assert!(bounded.starts_with("harmless"));
        assert!(!bounded.chars().any(char::is_control) && !bounded.contains('\u{202e}'));
    }

    #[tokio::test]
    async fn dns_and_tls_transport_source_causes_are_retained_without_debug() {
        #[derive(Debug)]
        struct Cause {
            text: &'static str,
            source: Option<Box<Cause>>,
        }
        impl fmt::Display for Cause {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.text)
            }
        }
        impl std::error::Error for Cause {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                self.source
                    .as_deref()
                    .map(|s| s as &(dyn std::error::Error + 'static))
            }
        }
        let mock = Mock::new(vec![]).await;
        for cause in [
            "DNS lookup failed: no such host",
            "TLS certificate validation failed: UnknownIssuer",
        ] {
            let error = Cause {
                text: "error sending request",
                source: Some(Box::new(Cause {
                    text: cause,
                    source: None,
                })),
            };
            let retained = mock.provider.sanitize_detail(&error_cause_chain(&error));
            assert!(retained.contains(cause));
            assert!(retained.contains("caused by:"));
        }
        // A genuine reqwest connector error exercises .without_url() plus its
        // underlying source, rather than only synthetic cause-chain fixtures.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let mut provider = Provider::new(client, credentials());
        provider.endpoint = format!("http://{addr}/");
        let error = provider
            .reconcile(&spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "ConnectionFailure");
        assert!(
            error.message.contains("Transport detail:")
                && error.message.to_lowercase().contains("refused")
        );
        assert!(!error.message.contains("http://"));
    }

    #[tokio::test]
    async fn untrusted_error_code_and_request_id_cannot_echo_credentials() {
        let mock = Mock::new(vec![]).await;
        let body = json!({"Response":{"RequestId":"test-secret-not-real","Error":{"Code":"AKIDTestOnly","Message":"test-secret-not-real"}}});
        let error = mock
            .provider
            .parse_reply("DescribeDomain", 200, body.to_string().as_bytes())
            .err()
            .unwrap();
        assert_eq!(error.request_id, None);
        assert_eq!(error.code, "ProviderApiError");
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("test-secret-not-real")
        );
    }

    #[tokio::test]
    async fn invalid_inputs_and_disabled_or_wrong_zone_never_mutate() {
        let mock = Mock::new(vec![]).await;
        for ip in ["not-an-ip", "2001:db8::1", "192.0.2.2:80", " 192.0.2.2"] {
            assert!(mock.provider.reconcile(&spec(), ip, false).await.is_err());
        }
        let mut invalid = spec();
        invalid.ttl = 0;
        assert!(
            mock.provider
                .reconcile(&invalid, "192.0.2.2", false)
                .await
                .is_err()
        );
        assert!(mock.requests().is_empty());
        for (field, value, code) in [
            ("Status", "pause", "DomainDisabled"),
            ("Domain", "other.com", "ZoneMismatch"),
        ] {
            let mut response = domain();
            response["Response"]["DomainInfo"][field] = json!(value);
            let mock = Mock::new(vec![response]).await;
            assert_eq!(
                mock.provider
                    .reconcile(&spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            mock.assert_reads_only(1);
        }
    }
}
