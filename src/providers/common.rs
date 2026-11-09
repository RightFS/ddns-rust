//! Shared safety policy for DNS adapters. Providers only perform reads/writes;
//! selection, dry-run and idempotency live here so every adapter fails closed.
#![allow(async_fn_in_trait, clippy::result_large_err)]
use crate::provider::ProviderError;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct Spec {
    pub domain: String,
    pub subdomain: String,
    pub record_type: String,
    pub record_line: String,
    pub ttl: u64,
    pub record_id: Option<String>,
    pub create_if_missing: bool,
    pub options: BTreeMap<String, String>,
}
impl Spec {
    pub fn fqdn(&self) -> String {
        if matches!(self.subdomain.as_str(), "" | "@") {
            self.domain.clone()
        } else {
            format!("{}.{}", self.subdomain, self.domain)
        }
    }
}
#[derive(Clone, Debug)]
pub struct Record {
    pub id: String,
    pub name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u64,
    pub line: String,
    pub enabled: bool,
    pub extra: Value,
}
#[derive(Clone, Debug)]
pub struct List {
    pub records: Vec<Record>,
    pub request_id: Option<String>,
}
#[derive(Clone, Debug)]
pub struct Mutation {
    pub record_id: String,
    pub request_id: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    pub status: String,
    pub previous_ip: Option<String>,
    pub current_ip: String,
    pub record_id: Option<String>,
    pub request_id: Option<String>,
}
/// The convention of parsed `Record.name`, not necessarily the API write name.
/// Every adapter must declare it: relative labels must never be guessed to be FQDNs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameFormat {
    Relative,
    Fqdn,
}
impl NameFormat {
    pub fn matches(self, record: &str, spec: &Spec) -> bool {
        match self {
            // Empty and @ are the documented relative apex representations.
            // Dots inside a relative owner are literal labels, never qualification.
            Self::Relative => {
                if matches!(spec.subdomain.as_str(), "" | "@") {
                    matches!(record, "" | "@")
                } else {
                    record.eq_ignore_ascii_case(&spec.subdomain)
                }
            }
            // Exactly one legal DNS root dot may be omitted for comparison.
            Self::Fqdn => record
                .strip_suffix('.')
                .unwrap_or(record)
                .eq_ignore_ascii_case(&spec.fqdn()),
        }
    }
}
pub trait Adapter {
    fn name_format(&self) -> NameFormat;
    /// False only when the provider cannot read/write TTL and configuration
    /// explicitly acknowledges provider-managed TTL. Record.ttl=0 then means
    /// unavailable, never the desired TTL or a guessed provider default.
    fn manages_ttl(&self) -> bool {
        true
    }
    fn validate_selection(
        &self,
        _spec: &Spec,
        _record: Option<&Record>,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError>;
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError>;
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError>;
}
pub fn local_error(
    stage: &str,
    code: &str,
    message: &str,
    hint: &str,
    request_id: Option<String>,
) -> ProviderError {
    ProviderError {
        stage: stage.into(),
        code: code.into(),
        message: message.into(),
        hint: hint.into(),
        request_id,
        http_status: None,
        retryable: false,
    }
}
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && id != "0"
}
pub fn valid_trace_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id.is_ascii()
        && !id
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        && !id.contains("[REDACTED]")
        && !id.contains("Sensitive")
}
pub async fn reconcile<P: Adapter>(
    provider: &P,
    spec: &Spec,
    ip: &str,
    dry_run: bool,
) -> Result<Outcome, ProviderError> {
    let desired: IpAddr = ip.parse().map_err(|_| {
        local_error(
            "validation",
            "InvalidIp",
            "The desired value is not a plain IP address.",
            "Check the IP source.",
            None,
        )
    })?;
    if desired.is_ipv4() != (spec.record_type == "A")
        || !matches!(spec.record_type.as_str(), "A" | "AAAA")
    {
        return Err(local_error(
            "validation",
            "IpFamilyMismatch",
            "IP address family does not match A/AAAA.",
            "Correct the record type or IP source.",
            None,
        ));
    }
    let ip = desired.to_string();
    let list = provider.list(spec).await?;
    let fail = |code: &str, msg: &str, hint: &str| {
        local_error("selection", code, msg, hint, list.request_id.clone())
    };
    if list.records.len() > 10000 {
        return Err(fail(
            "RecordLimit",
            "More than 10,000 records returned; safe selection stopped.",
            "Narrow the zone/host filter.",
        ));
    }
    let mut ids = HashSet::new();
    for r in &list.records {
        if !valid_id(&r.id) || !ids.insert(&r.id) {
            return Err(fail(
                "UnstableRecordList",
                "Invalid or repeated record IDs were returned.",
                "Stop concurrent changes and rerun a fresh read.",
            ));
        }
    }
    let selected = if let Some(id) = &spec.record_id {
        let r = list.records.iter().find(|r| &r.id == id).ok_or_else(|| {
            fail(
                "RecordIdNotFound",
                "Explicit record ID was not found; creation and fallback selection are refused.",
                "Verify the ID, hosted zone and host/type.",
            )
        })?;
        if !provider.name_format().matches(&r.name, spec) || r.record_type != spec.record_type {
            return Err(fail(
                "RecordIdMismatch",
                "Explicit record ID belongs to a different host or type.",
                "Correct the ID or target; unrelated records are never repurposed.",
            ));
        }
        Some(r)
    } else {
        let matches: Vec<_> = list
            .records
            .iter()
            .filter(|r| {
                provider.name_format().matches(&r.name, spec)
                    && r.record_type == spec.record_type
                    && (r.line.is_empty() || r.line == spec.record_line)
            })
            .collect();
        if matches.len() > 1 {
            return Err(fail(
                "AmbiguousRecords",
                "Multiple matching records found; no default first-record selection.",
                "Set an explicit record_id. Disabled records also count toward ambiguity.",
            ));
        }
        matches.first().copied()
    };
    provider
        .validate_selection(spec, selected)
        .map_err(|mut error| {
            if error.request_id.is_none() {
                error.request_id = list.request_id.clone();
            }
            error
        })?;
    let Some(record) = selected else {
        if !spec.create_if_missing {
            return Err(fail(
                "RecordNotFound",
                "Record does not exist and create_if_missing is false.",
                "Check zone/host/type/line or explicitly opt into creation.",
            ));
        }
        if dry_run {
            return Ok(Outcome {
                status: "would_create".into(),
                previous_ip: None,
                current_ip: ip,
                record_id: None,
                request_id: list.request_id,
            });
        }
        let mutation = provider.create(spec, &ip).await?;
        if !valid_id(&mutation.record_id) {
            return Err(local_error(
                "create",
                "InvalidWriteAcknowledgement",
                "Provider did not acknowledge a valid record ID; write result is uncertain.",
                "Inspect the provider before another write; no automatic retry occurred.",
                mutation.request_id,
            ));
        }
        return Ok(Outcome {
            status: "created".into(),
            previous_ip: None,
            current_ip: ip,
            record_id: Some(mutation.record_id),
            request_id: mutation.request_id,
        });
    };
    if !record.enabled {
        return Err(fail(
            "RecordDisabled",
            "Selected record is disabled; it will not be updated or enabled.",
            "Enable the intended record manually or select another enabled record.",
        ));
    }
    let previous: IpAddr = record.value.parse().map_err(|_| {
        fail(
            "InvalidRecordValue",
            "Selected A/AAAA record value is not a valid IP address.",
            "Inspect and correct the record in the provider console.",
        )
    })?;
    if previous.is_ipv4() != desired.is_ipv4() {
        return Err(fail(
            "InvalidRecordValue",
            "Existing record IP family is invalid for its type.",
            "Correct the record manually before enabling DDNS.",
        ));
    }
    let previous = previous.to_string();
    let status = if previous == ip && (!provider.manages_ttl() || record.ttl == spec.ttl) {
        "unchanged"
    } else if dry_run {
        "would_update"
    } else {
        "updated"
    };
    let request_id = if status == "updated" {
        let mutation = provider.update(spec, record, &ip).await?;
        if mutation.record_id != record.id {
            return Err(local_error(
                "update",
                "UnexpectedRecordId",
                "Provider acknowledged a different record ID; result is uncertain.",
                "Inspect the intended record before making another write.",
                mutation.request_id,
            ));
        }
        mutation.request_id
    } else {
        list.request_id
    };
    Ok(Outcome {
        status: status.into(),
        previous_ip: Some(previous),
        current_ip: ip,
        record_id: Some(record.id.clone()),
        request_id,
    })
}

pub struct HttpReply {
    pub headers: reqwest::header::HeaderMap,
    pub body: Value,
    pub status: u16,
    pub request_id: Option<String>,
}
pub struct Api {
    pub client: reqwest::Client,
    secrets: Vec<String>,
}
impl Api {
    pub fn new(client: reqwest::Client, secrets: Vec<String>) -> Self {
        Self { client, secrets }
    }
    pub fn safe(&self, value: &str) -> String {
        let mut text = value.to_owned();
        for secret in &self.secrets {
            if !secret.is_empty() {
                text = text.replace(secret, "[REDACTED]");
            }
        }
        text=text.chars().filter(|c|!c.is_control()&&!matches!(*c,'\u{200b}'..='\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')).collect();
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
            "login_token=",
        ]
        .iter()
        .any(|token| lower.contains(token))
        {
            return "[Sensitive diagnostic detail omitted]".into();
        }
        if text.len() > 2048 {
            let mut end = 2048;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str(" [truncated]");
        }
        text
    }
    pub fn error(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        hint: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        let safe_code = self.safe(code);
        let safe_code = if valid_id(&safe_code) {
            safe_code
        } else {
            "ProviderApiError".into()
        };
        ProviderError {
            stage: stage.into(),
            code: safe_code,
            message: self.safe(message),
            hint: hint.into(),
            request_id: reply.and_then(|r| r.request_id.clone()),
            http_status: reply.map(|r| r.status),
            retryable: false,
        }
    }
    fn parse_failure_message(&self, headers: &reqwest::header::HeaderMap) -> String {
        let base = "Provider returned non-JSON or malformed JSON; raw response body omitted.";
        // Gcore documents this error header. Read only the allowlisted field,
        // sanitize it, and never record arbitrary/raw response headers or body.
        match headers
            .get("error")
            .and_then(|v| v.to_str().ok())
            .map(|s| self.safe(s))
            .filter(|s| !s.trim().is_empty())
        {
            Some(detail) => format!("{base} Provider error detail: {detail}"),
            None => base.into(),
        }
    }
    pub fn check_http(&self, action: &str, reply: &HttpReply) -> Result<(), ProviderError> {
        if (200..300).contains(&reply.status) {
            Ok(())
        } else {
            Err(self.error(action,&format!("Http{}",reply.status),"Provider returned an unsuccessful HTTP status.","Check authentication for 401/403, rate limits for 429 and provider availability for 5xx. Inspect any uncertain write before another attempt.",Some(reply)))
        }
    }
    pub async fn send(
        &self,
        action: &str,
        request: reqwest::RequestBuilder,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let started = std::time::Instant::now();
        tracing::debug!(action, write, "Provider API action started");
        let result=tokio::time::timeout(Duration::from_secs(30),async {
            let mut response=request.send().await.map_err(|e|self.transport(action,e,write,None))?;
            let status=response.status().as_u16();
            let headers=response.headers().clone();
            let header_id=["x-request-id","x-id","cf-ray","x-correlation-id","x-vercel-id","x-nsone-request-id"].iter().find_map(|name|response.headers().get(*name).and_then(|v|v.to_str().ok())).map(|s|self.safe(s)).filter(|s|valid_trace_id(s));
            let mut bytes=Vec::new();
            while let Some(chunk)=response.chunk().await.map_err(|e|self.transport(action,e,write,Some(status)))?{
                if bytes.len()+chunk.len()>1024*1024{return Err(self.error(action,"ResponseTooLarge","API response exceeded 1 MiB and was not processed.","Check the endpoint/proxy. If this was a write, inspect the record before retrying.",Some(&HttpReply{headers:headers.clone(),body:Value::Null,status,request_id:header_id})));}bytes.extend_from_slice(&chunk);
            }
            let body:Value=if status==204 && bytes.is_empty(){Value::Null}else{serde_json::from_slice(&bytes).map_err(|_|self.error(action,"MalformedResponse",&self.parse_failure_message(&headers),"Check endpoint, service availability and proxies. Inspect any write before retrying.",Some(&HttpReply{headers:headers.clone(),body:Value::Null,status,request_id:header_id.clone()})))?};
            let request_id=body.get("RequestId").or_else(||body.get("requestId")).or_else(||body.pointer("/status/request_id")).or_else(||body.pointer("/Response/RequestId")).and_then(Value::as_str).map(|s|self.safe(s)).filter(|s|valid_trace_id(s)).or(header_id);
            Ok(HttpReply{headers,body,status,request_id})
        }).await.unwrap_or_else(|_|Err(self.error(action,"Timeout","Provider request exceeded the 30-second safety deadline.",if write{"Write result is uncertain; inspect the provider before another attempt."}else{"Check network, DNS, TLS and proxy settings."},None)));
        match &result {
            Ok(reply) => {
                tracing::debug!(action,http_status=reply.status,request_id=?reply.request_id,elapsed_ms=started.elapsed().as_millis() as u64,"Provider API action completed")
            }
            Err(error) => {
                tracing::debug!(action,code=%error.code,http_status=?error.http_status,elapsed_ms=started.elapsed().as_millis() as u64,"Provider API action failed")
            }
        };
        result
    }
    fn transport(
        &self,
        action: &str,
        error: reqwest::Error,
        write: bool,
        status: Option<u16>,
    ) -> ProviderError {
        let code = if error.is_timeout() {
            "Timeout"
        } else if error.is_connect() {
            "ConnectionFailure"
        } else {
            "TransportFailure"
        };
        let error = error.without_url();
        let mut chain = error.to_string();
        let mut source = std::error::Error::source(&error);
        for _ in 0..8 {
            let Some(cause) = source else {
                break;
            };
            chain.push_str(" -> ");
            chain.push_str(&cause.to_string());
            source = cause.source();
        }
        let mut e=self.error(action,code,&format!("Provider transport failed. {} Detail: {}",if write{"Write result is uncertain; no automatic retry was made."}else{"No mutation was attempted."},chain),"Check network routing, DNS, TLS certificates and proxy configuration. Inspect an uncertain write before retrying.",None);
        e.http_status = status;
        e.retryable = !write;
        e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Fake {
        records: Vec<Record>,
        format: NameFormat,
        writes: AtomicUsize,
    }
    impl Adapter for Fake {
        fn name_format(&self) -> NameFormat {
            self.format
        }
        async fn list(&self, _: &Spec) -> Result<List, ProviderError> {
            Ok(List {
                records: self.records.clone(),
                request_id: Some("read-id".into()),
            })
        }
        async fn create(&self, _: &Spec, _: &str) -> Result<Mutation, ProviderError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(Mutation {
                record_id: "new-id".into(),
                request_id: Some("write-id".into()),
            })
        }
        async fn update(&self, _: &Spec, r: &Record, _: &str) -> Result<Mutation, ProviderError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(Mutation {
                record_id: r.id.clone(),
                request_id: Some("write-id".into()),
            })
        }
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
    fn record(id: &str) -> Record {
        Record {
            id: id.into(),
            name: "home.example.com".into(),
            record_type: "A".into(),
            value: "1.1.1.1".into(),
            ttl: 600,
            line: String::new(),
            enabled: true,
            extra: Value::Null,
        }
    }
    fn fake(records: Vec<Record>) -> Fake {
        Fake {
            records,
            format: NameFormat::Fqdn,
            writes: AtomicUsize::new(0),
        }
    }
    #[tokio::test]
    async fn dry_run_never_calls_writes() {
        let f = fake(vec![record("abc-id")]);
        assert_eq!(
            reconcile(&f, &spec(), "8.8.8.8", true)
                .await
                .unwrap()
                .status,
            "would_update"
        );
        assert_eq!(f.writes.load(Ordering::SeqCst), 0);
        let f = fake(vec![]);
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&f, &s, "8.8.8.8", true).await.unwrap().status,
            "would_create"
        );
        assert_eq!(f.writes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn refuses_ambiguous_and_disabled_records() {
        let f = fake(vec![record("one"), record("two")]);
        assert_eq!(
            reconcile(&f, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "AmbiguousRecords"
        );
        let mut r = record("one");
        r.enabled = false;
        let f = fake(vec![r]);
        assert_eq!(
            reconcile(&f, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordDisabled"
        );
        assert_eq!(f.writes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn explicit_missing_id_never_falls_back_or_creates() {
        let f = fake(vec![record("one")]);
        let mut s = spec();
        s.record_id = Some("missing".into());
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&f, &s, "8.8.8.8", false).await.unwrap_err().code,
            "RecordIdNotFound"
        );
        assert_eq!(f.writes.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn string_id_update_and_noop() {
        let f = fake(vec![record("cf-opaque-id")]);
        let mut s = spec();
        s.record_id = Some("cf-opaque-id".into());
        assert_eq!(
            reconcile(&f, &s, "1.1.1.1", false).await.unwrap().status,
            "unchanged"
        );
        assert_eq!(
            reconcile(&f, &s, "8.8.8.8", false).await.unwrap().record_id,
            Some("cf-opaque-id".into())
        );
        assert_eq!(f.writes.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn provider_managed_ttl_does_not_cause_ttl_only_writes() {
        struct Managed(Fake);
        impl Adapter for Managed {
            fn name_format(&self) -> NameFormat {
                self.0.name_format()
            }
            fn manages_ttl(&self) -> bool {
                false
            }
            async fn list(&self, s: &Spec) -> Result<List, ProviderError> {
                self.0.list(s).await
            }
            async fn create(&self, s: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
                self.0.create(s, ip).await
            }
            async fn update(
                &self,
                s: &Spec,
                r: &Record,
                ip: &str,
            ) -> Result<Mutation, ProviderError> {
                self.0.update(s, r, ip).await
            }
        }
        let mut r = record("id");
        r.ttl = 0; // Unavailable, not a fabricated observed TTL.
        let p = Managed(fake(vec![r]));
        assert_eq!(
            reconcile(&p, &spec(), "1.1.1.1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert_eq!(p.0.writes.load(Ordering::SeqCst), 0);
        assert_eq!(
            reconcile(&p, &spec(), "8.8.8.8", true)
                .await
                .unwrap()
                .status,
            "would_update"
        );
        assert_eq!(p.0.writes.load(Ordering::SeqCst), 0);
        assert_eq!(
            reconcile(&p, &spec(), "8.8.8.8", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        assert_eq!(p.0.writes.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn non_json_error_header_retains_sanitized_detail_without_raw_body() {
        let api = Api::new(reqwest::Client::new(), vec!["test-secret".into()]);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "error",
            reqwest::header::HeaderValue::from_static("Zone permission denied for test-secret"),
        );
        let message = api.parse_failure_message(&headers);
        assert!(message.contains("Zone permission denied"));
        assert!(message.contains("raw response body omitted"));
        assert!(!message.contains("test-secret"));
        headers.insert(
            "error",
            reqwest::header::HeaderValue::from_static("Authorization: APIKey private"),
        );
        assert!(!api.parse_failure_message(&headers).contains("private"));
    }
    #[test]
    fn diagnostic_trace_ids_are_not_record_paths() {
        assert!(valid_trace_id("iad1::abc-123"));
        assert!(!valid_id("iad1::abc-123"));
        assert!(!valid_trace_id("bad\nheader"));
        assert!(!valid_trace_id("[REDACTED]"));
    }
    #[tokio::test]
    async fn validation_errors_keep_read_request_context() {
        struct Reject(Fake);
        impl Adapter for Reject {
            fn name_format(&self) -> NameFormat {
                self.0.name_format()
            }
            fn validate_selection(
                &self,
                _: &Spec,
                _: Option<&Record>,
            ) -> Result<(), ProviderError> {
                Err(local_error(
                    "validation",
                    "ProviderLimit",
                    "Unsupported provider configuration.",
                    "Fix the setting.",
                    None,
                ))
            }
            async fn list(&self, s: &Spec) -> Result<List, ProviderError> {
                self.0.list(s).await
            }
            async fn create(&self, s: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
                self.0.create(s, ip).await
            }
            async fn update(
                &self,
                s: &Spec,
                r: &Record,
                ip: &str,
            ) -> Result<Mutation, ProviderError> {
                self.0.update(s, r, ip).await
            }
        }
        let p = Reject(fake(vec![record("id")]));
        let error = reconcile(&p, &spec(), "8.8.8.8", true).await.unwrap_err();
        assert_eq!(error.request_id.as_deref(), Some("read-id"));
        assert_eq!(p.0.writes.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn sanitization_retains_detail_without_secrets() {
        let api = Api::new(reqwest::Client::new(), vec!["secret-key".into()]);
        assert_eq!(
            api.safe("Bad credential secret-key in zone"),
            "Bad credential [REDACTED] in zone"
        );
        assert!(api.safe("Authorization: Bearer hidden").contains("omitted"));
    }
    #[test]
    fn owner_formats_are_exact_and_never_inferred_from_dots_or_zone_suffix() {
        let mut s = spec();
        assert!(NameFormat::Relative.matches("HOME", &s));
        assert!(!NameFormat::Relative.matches("home.example.com", &s));
        assert!(!NameFormat::Relative.matches("home.", &s));
        assert!(NameFormat::Fqdn.matches("HOME.EXAMPLE.COM.", &s));
        assert!(!NameFormat::Fqdn.matches("home", &s));
        assert!(!NameFormat::Fqdn.matches("home.example.com..", &s));
        s.subdomain = "home.example.com".into();
        assert!(NameFormat::Relative.matches("home.example.com", &s));
        assert!(!NameFormat::Fqdn.matches("home.example.com", &s));
        assert!(NameFormat::Fqdn.matches("home.example.com.example.com.", &s));
        s.subdomain = "@".into();
        for apex in ["", "@"] {
            assert!(NameFormat::Relative.matches(apex, &s));
        }
        assert!(!NameFormat::Relative.matches("example.com", &s));
        assert!(NameFormat::Fqdn.matches("example.com.", &s));
    }
    #[tokio::test]
    async fn wrong_owner_never_reaches_noop_dryrun_write_or_explicit_id_fallback() {
        for format in [NameFormat::Relative, NameFormat::Fqdn] {
            for explicit in [false, true] {
                for (ip, dry) in [("1.1.1.1", false), ("8.8.8.8", true), ("8.8.8.8", false)] {
                    let mut s = spec();
                    let mut wrong = record("shadow");
                    if format == NameFormat::Fqdn {
                        s.subdomain = "home.example.com".into();
                    }
                    let mut f = fake(vec![wrong.clone()]);
                    f.format = format;
                    if explicit {
                        s.record_id = Some("shadow".into());
                        s.create_if_missing = true;
                        wrong.id = "real".into();
                        wrong.name = match format {
                            NameFormat::Relative => s.subdomain.clone(),
                            NameFormat::Fqdn => s.fqdn(),
                        };
                        f.records.push(wrong);
                    }
                    assert_eq!(
                        reconcile(&f, &s, ip, dry).await.unwrap_err().code,
                        if explicit {
                            "RecordIdMismatch"
                        } else {
                            "RecordNotFound"
                        }
                    );
                    assert_eq!(f.writes.load(Ordering::SeqCst), 0);
                }
            }
        }
    }
    #[tokio::test]
    async fn suffix_collision_does_not_count_as_ambiguity_and_dotted_targets_update() {
        for format in [NameFormat::Relative, NameFormat::Fqdn] {
            for host in ["home", "home.example.com", "example.com", "branch.home"] {
                let mut s = spec();
                s.subdomain = host.into();
                let mut real = record("real");
                real.name = match format {
                    NameFormat::Relative => host.into(),
                    NameFormat::Fqdn => s.fqdn(),
                };
                let mut shadow = real.clone();
                shadow.id = "shadow".into();
                shadow.name = match format {
                    NameFormat::Relative => s.fqdn(),
                    NameFormat::Fqdn => host.into(),
                };
                let mut f = fake(vec![shadow, real]);
                f.format = format;
                let out = reconcile(&f, &s, "8.8.8.8", false).await.unwrap();
                assert_eq!(out.status, "updated");
                assert_eq!(out.record_id.as_deref(), Some("real"));
                assert_eq!(f.writes.load(Ordering::SeqCst), 1);
            }
        }
    }
}
