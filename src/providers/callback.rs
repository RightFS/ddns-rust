//! Independent, unverified JSON POST delivery; deliberately NOT a DNS Adapter.
//!
//! This is not ddns-go's GET/template callback protocol. The receiver must agree
//! to the fixed JSON schema below. A complete HTTP 2xx response acknowledges only
//! HTTP acceptance (including 202 and bodies containing business errors), never
//! DNS success, an observed remote IP, or TTL control. TTL is request metadata.
//! Every real execution dispatches once, even when the IP is unchanged. Delivery
//! IDs are new UUIDs, not stable idempotency keys; receiver idempotency is unknown.
//!
//! Caller MUST supply a TLS-verifying client with redirect Policy::none() and
//! retry::never(). Never automatically retry an uncertain delivery. Endpoint
//! values exist only in server-owned CALLBACK_ environment variables; options
//! cannot contain URLs or credentials. No endpoint/body/transport-chain logging.
#![allow(clippy::result_large_err)]
use super::common::{Outcome, Spec, local_error};
use crate::provider::ProviderError;
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::Serialize;
use std::{collections::BTreeMap, net::IpAddr, time::Duration};
use uuid::Uuid;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);
const HINT: &str = "Callback delivery is unverified: HTTP acceptance is not DNS success; TTL is metadata only. Every real run sends again and receiver idempotency is not guaranteed. Inspect the receiver before repeating an uncertain delivery; no automatic retry occurred.";
const REQUIRED: [(&str, &str); 4] = [
    ("mode", "json_post"),
    ("verification", "unverified"),
    ("delivery", "every_run"),
    ("ttl_mode", "metadata_only"),
];

fn error(stage: &str, code: &str, message: &str) -> ProviderError {
    local_error(stage, code, message, HINT, None)
}

/// Only a scoped, uppercase server environment NAME, never a URL or DDNS_*.
pub fn valid_endpoint_env(name: &str) -> bool {
    (6..=64).contains(&name.len())
        && name.starts_with("CALLBACK_")
        && name.len() > "CALLBACK_".len()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Credential references follow the registry's multi-account namespace policy.
/// This is intentionally broader than the strictly CALLBACK_-scoped endpoint ref.
#[cfg(test)]
pub fn check_token_env(name: &str) -> Result<(), ProviderError> {
    if !(((name.starts_with("CALLBACK_") && name.len() > "CALLBACK_".len())
        || (name.starts_with("DDNS_") && name.len() > "DDNS_".len()))
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
    {
        return Err(error(
            "configuration",
            "InvalidTokenEnv",
            "Callback token_env must be an uppercase server-owned CALLBACK_ or DDNS_ credential reference with a nonempty suffix, at most 128 characters.",
        ));
    }
    Ok(())
}

/// Validate all options BEFORE any environment lookup or IP-source I/O.
#[cfg(test)]
pub fn check_options(options: &BTreeMap<String, String>) -> Result<(), ProviderError> {
    check_options_with_direct(options, false)
}
pub fn check_options_with_direct(
    options: &BTreeMap<String, String>,
    direct: bool,
) -> Result<(), ProviderError> {
    if !options
        .get("endpoint_env")
        .is_some_and(|name| valid_endpoint_env(name))
        && !(direct && options.get("endpoint_env").is_none_or(String::is_empty))
    {
        return Err(error(
            "configuration",
            "InvalidEndpointEnv",
            "endpoint_env must be a 6..64-character CALLBACK_-scoped uppercase server environment name with a nonempty suffix; URLs and arbitrary environment lookups are refused.",
        ));
    }
    if options
        .keys()
        .any(|key| key != "endpoint_env" && !REQUIRED.iter().any(|(required, _)| key == required))
    {
        return Err(error(
            "configuration",
            "UnsupportedOptions",
            "Only endpoint_env, mode, verification, delivery and ttl_mode are supported. No URL, token value, template, TLS or redirect options are accepted.",
        ));
    }
    if REQUIRED
        .iter()
        .any(|(key, value)| options.get(*key).map(String::as_str) != Some(*value))
    {
        return Err(error(
            "configuration",
            "MissingCallbackAcknowledgement",
            "Callback requires mode=json_post, verification=unverified, delivery=every_run and ttl_mode=metadata_only explicitly.",
        ));
    }
    Ok(())
}

/// Preflight checks only local configuration/environment syntax: ZERO network I/O.
/// The actual endpoint value is never included in an error or returned as a string.
#[cfg(test)]
pub fn check_endpoint_ref(options: &BTreeMap<String, String>) -> Result<(), ProviderError> {
    endpoint_from_env(options).map(|_| ())
}

#[cfg(test)]
fn endpoint_from_env(options: &BTreeMap<String, String>) -> Result<Url, ProviderError> {
    endpoint_with_direct(options, None)
}
pub fn endpoint_with_direct(
    options: &BTreeMap<String, String>,
    direct: Option<&str>,
) -> Result<Url, ProviderError> {
    check_options_with_direct(options, direct.is_some())?;
    if let Some(value) = direct {
        return check_endpoint_value(value);
    }
    // The key is present and scoped only after check_options succeeds.
    let value = std::env::var(&options["endpoint_env"]).map_err(|_| {
        error("configuration", "MissingEndpoint", "Set the scoped callback endpoint environment variable on the server; its value is intentionally omitted.")
    })?;
    check_endpoint_value(&value)
}

/// Strict canonical HTTPS URL with an unambiguous ASCII path, no query/auth/etc.
/// Private HTTPS origins are allowed: choosing the server environment is an
/// operator trust decision, not an untrusted Web-configured destination.
pub fn check_endpoint_value(value: &str) -> Result<Url, ProviderError> {
    let invalid = || {
        error(
            "configuration",
            "InvalidEndpoint",
            "Callback endpoint must be a canonical full HTTPS URL with a plain ASCII path, without userinfo, query, fragment, backslash, percent escapes, dot segments or templates. Endpoint values are intentionally omitted.",
        )
    };
    if !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || value.contains(['\\', '?', '#', '%', '{', '}'])
    {
        return Err(invalid());
    }
    let url = Url::parse(value).map_err(|_| invalid())?;
    let host = url.host_str().ok_or_else(invalid)?;
    let ip_host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok();
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
        || (!ip_host && !dns_name(host))
        || value != url.as_str()
    {
        return Err(invalid());
    }
    let path = url.path();
    if !path.starts_with('/')
        || path.contains("//")
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~'))
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
    {
        return Err(invalid());
    }
    Ok(url)
}

fn dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
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

/// Callback has no record selection/create capability. Call before IP-source I/O.
pub fn check_spec(spec: &Spec) -> Result<(), ProviderError> {
    if spec.record_id.is_some() || spec.create_if_missing || !spec.options.is_empty() {
        return Err(error(
            "validation",
            "UnsupportedCallbackSelection",
            "Callback does not select or create DNS records: omit record_id and all record options, and set create_if_missing=false.",
        ));
    }
    if !dns_name(&spec.domain)
        || (!matches!(spec.subdomain.as_str(), "" | "@") && !dns_name(&spec.subdomain))
        || spec.fqdn().len() > 253
    {
        return Err(error(
            "validation",
            "InvalidDnsName",
            "Use an ASCII/punycode domain and a relative child host, empty host or @; do not put a full domain in a relative-host field.",
        ));
    }
    if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
        return Err(error(
            "validation",
            "UnsupportedRecordType",
            "Callback metadata record_type must be A or AAAA.",
        ));
    }
    // record_line is deliberately ignored, never interpreted as DNS selection.
    // ttl is metadata only: no DNS read, write, provider TTL bound, or claim.
    Ok(())
}

// No Debug/Serialize: token and server-owned URL must never enter diagnostics.
pub struct Callback {
    client: Client,
    token: String,
    options: BTreeMap<String, String>,
    endpoint: Result<Url, ProviderError>,
}

#[derive(Serialize)]
struct Payload<'a> {
    domain: String,
    ip: &'a str,
    record_type: &'a str,
    ttl: u64,
    delivery_id: &'a str,
}

impl Callback {
    #[cfg(test)]
    pub fn new(client: Client, token: String, options: &BTreeMap<String, String>) -> Self {
        // All configuration/name validation precedes lookup; no global fallback.
        let endpoint = endpoint_from_env(options);
        Self {
            client,
            token,
            options: options.clone(),
            endpoint,
        }
    }

    pub fn new_with_direct(
        client: Client,
        token: String,
        options: &BTreeMap<String, String>,
        direct: Option<&str>,
    ) -> Self {
        Self {
            client,
            token,
            options: options.clone(),
            endpoint: endpoint_with_direct(options, direct),
        }
    }

    pub async fn execute(
        &self,
        spec: &Spec,
        ip: &str,
        dry_run: bool,
    ) -> Result<Outcome, ProviderError> {
        check_options_with_direct(&self.options, self.endpoint.is_ok())?;
        check_spec(spec)?;
        let endpoint = self.endpoint.as_ref().map_err(Clone::clone)?;
        if self.token.is_empty()
            || self.token.len() > 4096
            || !self.token.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            })
        {
            return Err(error(
                "credentials",
                "InvalidCredentials",
                "A nonempty plain callback Bearer token (at most 4096 bytes) is required; whitespace/control characters are refused.",
            ));
        }
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {}", self.token)).map_err(|_| {
                error(
                    "credentials",
                    "InvalidCredentials",
                    "The callback token is not a valid Bearer credential.",
                )
            })?;
        authorization.set_sensitive(true);
        let desired: IpAddr = ip.parse().map_err(|_| {
            error(
                "validation",
                "InvalidIp",
                "Callback IP must be a plain IP address, not a URL, port or template.",
            )
        })?;
        if desired.is_ipv4() != (spec.record_type == "A") {
            return Err(error(
                "validation",
                "IpFamilyMismatch",
                "IP address family does not match A/AAAA callback metadata.",
            ));
        }
        let ip = desired.to_string();
        if dry_run {
            return Ok(Outcome {
                status: "would_call_unverified".into(),
                previous_ip: None,
                current_ip: ip,
                record_id: None,
                request_id: None,
            });
        }
        let delivery_id = Uuid::new_v4().to_string();
        let payload = Payload {
            domain: spec.fqdn(),
            ip: &ip,
            record_type: &spec.record_type,
            ttl: spec.ttl,
            delivery_id: &delivery_id,
        };
        let request = self
            .client
            .post(endpoint.clone())
            .header(AUTHORIZATION, authorization)
            .timeout(DEADLINE)
            .json(&payload)
            .build()
            .map_err(|_| {
                error(
                    "callback",
                    "InvalidCallbackRequest",
                    "Callback request could not be constructed locally; no request was dispatched.",
                )
            })?;
        let uncertain = |status: Option<u16>| {
            let mut error = error(
                "callback",
                "DeliveryUncertain",
                "Callback dispatch or response completion failed; receiver acceptance and downstream effects are unknown. No automatic retry occurred.",
            );
            error.http_status = status;
            error.request_id = Some(delivery_id.clone());
            error
        };
        let delivery = async {
            let mut response = self
                .client
                .execute(request)
                .await
                .map_err(|_| uncertain(None))?;
            let status = response.status();
            let mut received = 0usize;
            if response
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
            {
                return Err(if status.is_success() {
                    uncertain(Some(status.as_u16()))
                } else {
                    rejected(status.as_u16(), &delivery_id)
                });
            }
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| uncertain(Some(status.as_u16())))?
            {
                received = received.saturating_add(chunk.len());
                if received > MAX_RESPONSE_BYTES {
                    return Err(if status.is_success() {
                        uncertain(Some(status.as_u16()))
                    } else {
                        rejected(status.as_u16(), &delivery_id)
                    });
                }
                // Discard untrusted response; it may echo unknown credentials.
            }
            if !status.is_success() {
                return Err(rejected(status.as_u16(), &delivery_id));
            }
            Ok(Outcome {
                status: "callback_accepted_unverified".into(),
                previous_ip: None,
                current_ip: ip.clone(),
                record_id: None,
                request_id: Some(delivery_id.clone()),
            })
        };
        // Covers dispatch AND full bounded response reading. No raw error escapes.
        tokio::time::timeout(DEADLINE, delivery)
            .await
            .map_err(|_| uncertain(None))?
    }

    #[cfg(test)]
    fn test_endpoint(
        client: Client,
        token: String,
        options: &BTreeMap<String, String>,
        endpoint: String,
    ) -> Self {
        // Private constructor: NO environment lookup. HTTP is localhost-test-only.
        let url = Url::parse(&endpoint).expect("test endpoint");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        assert!(url.username().is_empty() && url.password().is_none());
        assert!(url.query().is_none() && url.fragment().is_none());
        Self {
            client,
            token,
            options: options.clone(),
            endpoint: Ok(url),
        }
    }
}

fn rejected(status: u16, delivery_id: &str) -> ProviderError {
    let mut error = error(
        "callback",
        "CallbackHttpRejected",
        "Callback returned a non-2xx HTTP status; no DNS success is inferred and no automatic retry occurred. Response body and headers are intentionally omitted.",
    );
    error.http_status = Some(status);
    // Only our generated UUID is safe; remote RequestId could echo secrets.
    error.request_id = Some(delivery_id.into());
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    const TOKEN: &str = "test-secret-token+encoded/=";
    #[derive(Clone)]
    struct Captured {
        headers: HeaderMap,
        payload: Value,
    }
    #[derive(Clone)]
    struct StateData {
        calls: Arc<Mutex<Vec<Captured>>>,
        status: StatusCode,
        body: Vec<u8>,
        location: Option<String>,
    }
    struct Mock {
        endpoint: String,
        calls: Arc<Mutex<Vec<Captured>>>,
        task: JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn receive(
        State(state): State<StateData>,
        headers: HeaderMap,
        body: Bytes,
    ) -> impl IntoResponse {
        state.calls.lock().unwrap().push(Captured {
            headers,
            payload: serde_json::from_slice(&body).unwrap(),
        });
        let mut response = (state.status, state.body).into_response();
        // Remote headers are deliberately hostile, even if syntactically legal.
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_static("test-secret-token+encoded/="),
        );
        if let Some(location) = state.location {
            response
                .headers_mut()
                .insert("location", HeaderValue::from_str(&location).unwrap());
        }
        response
    }
    async fn mock(status: StatusCode, body: impl Into<Vec<u8>>, location: Option<String>) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/hook", post(receive))
            .with_state(StateData {
                calls: calls.clone(),
                status,
                body: body.into(),
                location,
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Mock {
            endpoint,
            calls,
            task,
        }
    }
    fn options() -> BTreeMap<String, String> {
        let mut result: BTreeMap<_, _> = REQUIRED
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        result.insert(
            "endpoint_env".into(),
            format!("CALLBACK_TEST_{}", Uuid::new_v4().simple()).to_ascii_uppercase(),
        );
        result
    }
    fn spec() -> Spec {
        Spec {
            domain: "example.com".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "ignored arbitrary line 默认".into(),
            ttl: 600,
            record_id: None,
            create_if_missing: false,
            options: BTreeMap::new(),
        }
    }
    fn client() -> Client {
        Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .unwrap()
    }
    fn callback(mock: &Mock) -> Callback {
        Callback::test_endpoint(client(), TOKEN.into(), &options(), mock.endpoint.clone())
    }
    fn assert_unobserved(outcome: &Outcome, status: &str, ip: &str) {
        assert_eq!(outcome.status, status);
        assert_eq!(outcome.current_ip, ip);
        assert!(outcome.previous_ip.is_none());
        assert!(outcome.record_id.is_none());
    }
    fn assert_sanitized(error: &ProviderError) {
        let diagnostic = format!(
            "{error:?} {error} {}",
            serde_json::to_string(error).unwrap()
        );
        for secret in [
            TOKEN,
            "unknown-receiver-secret",
            "https://private.internal",
            "auth=",
            "test-secret-token%2Bencoded%2F%3D",
            "127.0.0.1",
        ] {
            assert!(
                !diagnostic.contains(secret),
                "diagnostic leaked {secret}: {diagnostic}"
            );
        }
        assert!(!error.retryable);
        assert!(diagnostic.len() < 3000);
        if let Some(id) = &error.request_id {
            assert!(Uuid::parse_str(id).is_ok());
        }
    }

    #[tokio::test]
    async fn dry_run_is_zero_io_and_unverified() {
        let server = mock(StatusCode::OK, "untrusted", None).await;
        let outcome = callback(&server)
            .execute(&spec(), "8.8.8.8", true)
            .await
            .unwrap();
        assert_unobserved(&outcome, "would_call_unverified", "8.8.8.8");
        assert!(outcome.request_id.is_none());
        assert!(server.calls.lock().unwrap().is_empty());
        // Also succeeds against a closed listener: no dispatch or health checks.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
        drop(listener);
        let cb = Callback::test_endpoint(client(), TOKEN.into(), &options(), endpoint);
        assert!(cb.execute(&spec(), "8.8.8.8", true).await.is_ok());
    }

    #[tokio::test]
    async fn every_real_run_sends_same_ip_once_with_new_delivery_uuid() {
        let server = mock(
            StatusCode::ACCEPTED,
            "{\"error\":\"not DNS success\"}",
            None,
        )
        .await;
        let cb = callback(&server);
        let first = cb.execute(&spec(), "8.8.8.8", false).await.unwrap();
        let second = cb.execute(&spec(), "8.8.8.8", false).await.unwrap();
        for outcome in [&first, &second] {
            assert_unobserved(outcome, "callback_accepted_unverified", "8.8.8.8");
            assert!(Uuid::parse_str(outcome.request_id.as_ref().unwrap()).is_ok());
        }
        assert_ne!(first.request_id, second.request_id);
        let calls = server.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for (call, outcome) in calls.iter().zip([&first, &second]) {
            assert_eq!(call.headers[AUTHORIZATION], format!("Bearer {TOKEN}"));
            assert_eq!(call.headers["content-type"], "application/json");
            assert!(!call.headers.contains_key("idempotency-key"));
            assert_eq!(
                call.payload,
                json!({"domain":"home.example.com", "ip":"8.8.8.8", "record_type":"A", "ttl":600, "delivery_id":outcome.request_id})
            );
        }
    }

    #[tokio::test]
    async fn arbitrary_2xx_body_never_becomes_dns_or_business_success() {
        for (status, body) in [
            (
                StatusCode::OK,
                b"{\"error\":\"unknown-receiver-secret\"}".to_vec(),
            ),
            (StatusCode::CREATED, b"<html>not JSON</html>".to_vec()),
            (StatusCode::OK, vec![0xff, 0xfe, 0x00]),
            (StatusCode::NO_CONTENT, Vec::new()),
        ] {
            let server = mock(status, body, None).await;
            let outcome = callback(&server)
                .execute(&spec(), "8.8.8.8", false)
                .await
                .unwrap();
            assert_unobserved(&outcome, "callback_accepted_unverified", "8.8.8.8");
            assert_eq!(server.calls.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn relative_names_ipv6_and_ttl_remain_metadata_only() {
        let server = mock(StatusCode::OK, "", None).await;
        let cb = callback(&server);
        for (host, fqdn) in [
            ("", "example.com"),
            ("@", "example.com"),
            ("nested.example.com", "nested.example.com.example.com"),
        ] {
            let mut desired = spec();
            desired.subdomain = host.into();
            desired.record_type = "AAAA".into();
            desired.ttl = u64::MAX;
            let outcome = cb
                .execute(&desired, "2001:4860:4860:0:0:0:0:8888", false)
                .await
                .unwrap();
            assert_unobserved(
                &outcome,
                "callback_accepted_unverified",
                "2001:4860:4860::8888",
            );
            let calls = server.calls.lock().unwrap();
            assert_eq!(calls.last().unwrap().payload["domain"], fqdn);
            assert_eq!(calls.last().unwrap().payload["ttl"], json!(u64::MAX));
            assert!(calls.last().unwrap().payload.get("record_line").is_none());
        }
    }

    #[tokio::test]
    async fn http_errors_are_not_empty_records_or_success_and_never_echo_body() {
        let hostile = format!(
            "Bearer {TOKEN} https://private.internal/hook?auth=unknown-receiver-secret test-secret-token%2Bencoded%2F%3D"
        );
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let server = mock(status, hostile.clone(), None).await;
            let error = callback(&server)
                .execute(&spec(), "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(error.code, "CallbackHttpRejected");
            assert_eq!(error.http_status, Some(status.as_u16()));
            assert_eq!(server.calls.lock().unwrap().len(), 1);
            assert_sanitized(&error);
        }
    }

    #[tokio::test]
    async fn redirects_fail_closed_and_target_gets_zero_hits() {
        let target = mock(StatusCode::OK, "", None).await;
        for status in [
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::FOUND,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::PERMANENT_REDIRECT,
        ] {
            let server = mock(
                status,
                "redirect secret body",
                Some(target.endpoint.clone()),
            )
            .await;
            let error = callback(&server)
                .execute(&spec(), "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(error.code, "CallbackHttpRejected");
            assert_eq!(error.http_status, Some(status.as_u16()));
            assert_eq!(server.calls.lock().unwrap().len(), 1);
            assert!(target.calls.lock().unwrap().is_empty());
            assert_sanitized(&error);
        }
    }

    #[tokio::test]
    async fn oversize_2xx_is_uncertain_without_retry() {
        let server = mock(StatusCode::OK, vec![b'x'; MAX_RESPONSE_BYTES + 1], None).await;
        let error = callback(&server)
            .execute(&spec(), "8.8.8.8", false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "DeliveryUncertain");
        assert_eq!(error.http_status, Some(200));
        assert_eq!(server.calls.lock().unwrap().len(), 1);
        assert_sanitized(&error);
    }

    async fn raw_server(reply: Vec<u8>) -> (String, JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 8192];
            // reqwest's known-size JSON request fits in one bounded buffer. Read
            // at least all headers, then respond without borrowing external IO.
            let mut filled = 0;
            loop {
                let count = stream.read(&mut request[filled..]).await.unwrap();
                if count == 0 {
                    break;
                }
                filled += count;
                if request[..filled]
                    .windows(4)
                    .any(|bytes| bytes == b"\r\n\r\n")
                {
                    break;
                }
                assert!(filled < request.len());
            }
            let _ = stream.write_all(&reply).await;
            let _ = stream.shutdown().await;
            1
        });
        (endpoint, task)
    }

    #[tokio::test]
    async fn malformed_truncated_and_transport_responses_are_uncertain() {
        for reply in [
            b"not an HTTP response unknown-receiver-secret".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nshort".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nwrong-chunk".to_vec(),
            Vec::new(),
        ] {
            let (endpoint, task) = raw_server(reply).await;
            let cb = Callback::test_endpoint(client(), TOKEN.into(), &options(), endpoint);
            let error = cb.execute(&spec(), "8.8.8.8", false).await.unwrap_err();
            assert_eq!(error.code, "DeliveryUncertain");
            assert_sanitized(&error);
            assert_eq!(task.await.unwrap(), 1);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
        drop(listener);
        let cb = Callback::test_endpoint(client(), TOKEN.into(), &options(), endpoint);
        let error = cb.execute(&spec(), "8.8.8.8", false).await.unwrap_err();
        assert_eq!(error.code, "DeliveryUncertain");
        assert!(error.http_status.is_none());
        assert_sanitized(&error);
    }

    #[tokio::test]
    async fn chunked_oversize_and_exact_limit_are_bounded() {
        for (size, accepted) in [(MAX_RESPONSE_BYTES, true), (MAX_RESPONSE_BYTES + 1, false)] {
            let mut reply =
                format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n")
                    .into_bytes();
            reply.extend(std::iter::repeat_n(b'x', size));
            reply.extend_from_slice(b"\r\n0\r\n\r\n");
            let (endpoint, task) = raw_server(reply).await;
            let cb = Callback::test_endpoint(client(), TOKEN.into(), &options(), endpoint);
            let result = cb.execute(&spec(), "8.8.8.8", false).await;
            if accepted {
                assert_unobserved(&result.unwrap(), "callback_accepted_unverified", "8.8.8.8");
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.code, "DeliveryUncertain");
                assert_eq!(error.http_status, Some(200));
                assert_sanitized(&error);
            }
            assert_eq!(task.await.unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn invalid_credentials_ip_and_selection_are_rejected_locally_even_dry_run() {
        let server = mock(StatusCode::OK, "", None).await;
        let cb = callback(&server);
        for ip in ["8.8.8.8:80", "https://8.8.8.8", " 8.8.8.8", "#{ip}"] {
            assert_eq!(
                cb.execute(&spec(), ip, true).await.unwrap_err().code,
                "InvalidIp"
            );
        }
        assert_eq!(
            cb.execute(&spec(), "2001:4860::8888", true)
                .await
                .unwrap_err()
                .code,
            "IpFamilyMismatch"
        );
        let mut wrong_family = spec();
        wrong_family.record_type = "AAAA".into();
        assert_eq!(
            cb.execute(&wrong_family, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "IpFamilyMismatch"
        );
        for change in 0..3 {
            let mut desired = spec();
            match change {
                0 => desired.record_id = Some("123".into()),
                1 => desired.create_if_missing = true,
                _ => {
                    desired
                        .options
                        .insert("ttl_mode".into(), "metadata_only".into());
                }
            }
            for dry in [true, false] {
                assert_eq!(
                    cb.execute(&desired, "8.8.8.8", dry).await.unwrap_err().code,
                    "UnsupportedCallbackSelection"
                );
            }
        }
        for token in [
            "",
            "Bearer secret",
            "with\ncontrol",
            "with:punctuation",
            "秘密",
        ] {
            let invalid = Callback::test_endpoint(
                client(),
                token.into(),
                &options(),
                server.endpoint.clone(),
            );
            let error = invalid.execute(&spec(), "8.8.8.8", true).await.unwrap_err();
            assert_eq!(error.code, "InvalidCredentials");
            assert_sanitized(&error);
        }
        let invalid = Callback::test_endpoint(
            client(),
            "x".repeat(4097),
            &options(),
            server.endpoint.clone(),
        );
        assert_eq!(
            invalid
                .execute(&spec(), "8.8.8.8", true)
                .await
                .unwrap_err()
                .code,
            "InvalidCredentials"
        );
        assert!(server.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn endpoint_names_and_required_acknowledgements_are_fail_closed() {
        assert!(valid_endpoint_env("CALLBACK_ENDPOINT"));
        assert!(valid_endpoint_env(&format!("CALLBACK_{}", "A".repeat(55))));
        for name in [
            "",
            "CALLBACK_",
            "PATH",
            "DDNS_CALLBACK_ENDPOINT",
            "HIPM_API_ENDPOINT",
            "callback_endpoint",
            "CALLBACK_Mixed",
            "CALLBACK_URL=value",
            "https://example.com/hook",
            "CALLBACK_../PATH",
            &format!("CALLBACK_{}", "A".repeat(56)),
        ] {
            assert!(!valid_endpoint_env(name), "accepted {name}");
            let mut configured = options();
            configured.insert("endpoint_env".into(), name.into());
            assert_eq!(
                check_endpoint_ref(&configured).unwrap_err().code,
                "InvalidEndpointEnv"
            );
            // Constructor validates names before attempting env lookup, too.
            assert_eq!(
                Callback::new(client(), TOKEN.into(), &configured)
                    .endpoint
                    .unwrap_err()
                    .code,
                "InvalidEndpointEnv"
            );
        }
        for (key, _) in REQUIRED {
            let mut configured = options();
            configured.remove(key);
            assert_eq!(
                check_endpoint_ref(&configured).unwrap_err().code,
                "MissingCallbackAcknowledgement"
            );
            configured.insert(key.into(), "wrong".into());
            assert_eq!(
                check_options(&configured).unwrap_err().code,
                "MissingCallbackAcknowledgement"
            );
        }
        for key in [
            "url",
            "endpoint",
            "token",
            "template",
            "method",
            "tls_insecure",
            "redirects",
            "idempotency",
            "ttl_control",
        ] {
            let mut configured = options();
            configured.insert(
                key.into(),
                "https://private.internal/hook?auth=unknown-receiver-secret".into(),
            );
            let error = check_endpoint_ref(&configured).unwrap_err();
            assert_eq!(error.code, "UnsupportedOptions");
            assert_sanitized(&error);
        }
        let missing = options(); // UUID-scoped nonexistent env ref, no global mutation.
        assert!(std::env::var(&missing["endpoint_env"]).is_err());
        assert_eq!(
            check_endpoint_ref(&missing).unwrap_err().code,
            "MissingEndpoint"
        );
        for name in [
            "CALLBACK_TOKEN",
            "CALLBACK_OTHER",
            "DDNS_TOKEN",
            &format!("CALLBACK_{}", "A".repeat(119)),
            &format!("DDNS_{}", "A".repeat(123)),
        ] {
            assert!(check_token_env(name).is_ok(), "rejected {name}");
        }
        for name in [
            "PATH",
            "CALLBACK_",
            "DDNS_",
            "callback_token",
            "DDNS_Mixed",
            "CALLBACK_TOKEN=value",
            TOKEN,
            &format!("CALLBACK_{}", "A".repeat(120)),
        ] {
            assert_eq!(check_token_env(name).unwrap_err().code, "InvalidTokenEnv");
        }
    }

    #[test]
    fn endpoint_https_operator_origins_and_plain_paths_are_valid() {
        for value in [
            "https://example.com/",
            "https://example.com/hooks/ddns-v1.json",
            "https://private.internal:8443/hook",
            "https://localhost/hook",
            "https://10.0.0.1/hook",
            "https://127.0.0.1/hook",
            "https://[::1]:8443/hook",
            "https://[fd00::1]/hooks/v1/~notify_2/",
        ] {
            assert_eq!(check_endpoint_value(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn endpoint_ambiguity_auth_query_templates_and_tls_bypass_are_rejected_safely() {
        for value in [
            "",
            "https://example.com",
            "http://127.0.0.1/hook",
            "ftp://example.com/hook",
            "//example.com/hook",
            "https:example.com/hook",
            "https://user:password@example.com/hook",
            "https://user@example.com/hook",
            "https://@example.com/hook",
            "https://example.com/hook?auth=unknown-receiver-secret",
            "https://example.com/hook?",
            "https://example.com/hook#fragment",
            "https://example.com/hook#",
            "https://example.com\\hook",
            "https://example.com/hook\\path",
            "https://example.com/hooks/../hook",
            "https://example.com/./hook",
            "https://example.com/%2e%2e/hook",
            "https://example.com/%2fhook",
            "https://example.com/hook%20path",
            "https://example.com//hook",
            "https://example.com/#{ip}",
            "https://example.com/{domain}",
            "https://example.com/hook path",
            " https://example.com/hook",
            "https://example.com/hook\n",
            "https://例子.example/hook",
            "https://EXAMPLE.com/hook",
            "https://127.1/hook",
            "https://2130706433/hook",
            "https://example.com:0/hook",
            "https://example.com:443/hook",
            "https://example.com./hook",
            "https://bad_host/hook",
            "https://-bad.example/hook",
        ] {
            let error = check_endpoint_value(value).expect_err(value);
            assert_eq!(error.code, "InvalidEndpoint");
            assert_sanitized(&error);
        }
    }

    #[test]
    fn local_dns_validation_preserves_relative_config_semantics() {
        for host in ["", "@", "home", "nested.example.com"] {
            let mut desired = spec();
            desired.subdomain = host.into();
            assert!(check_spec(&desired).is_ok());
        }
        for host in ["home.", "a..b", "bad host", "-bad", "#{domain}", "*"] {
            let mut desired = spec();
            desired.subdomain = host.into();
            assert_eq!(check_spec(&desired).unwrap_err().code, "InvalidDnsName");
        }
        let mut desired = spec();
        desired.record_type = "TXT".into();
        assert_eq!(
            check_spec(&desired).unwrap_err().code,
            "UnsupportedRecordType"
        );
    }
}
