//! AliDNS RPC API 2015-01-09. Credentials/signatures travel ONLY in a POST
//! form, never a URL; this type intentionally does not implement Debug.
//! References:
//! https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomaininfo
//! https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomainrecords
//! https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-updatedomainrecord
//! See also ddns-go/dns/alidns.go and util/aliyun_signer_util.go.

#![allow(clippy::result_large_err)]

use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::Value;
use sha1::Sha1;
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;

const ENDPOINT: &str = "https://alidns.aliyuncs.com/";
const PAGE_SIZE: u64 = 500;
const MAX_PAGES: u64 = 100;
// RFC3986 unreserved bytes, NOT application/x-www-form-urlencoded's '+' rule.
const RPC_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub struct Alidns {
    api: Api,
    id: String,
    key: String,
    region: String,
    #[cfg(test)]
    endpoint: String,
}

fn encode(value: &str) -> String {
    utf8_percent_encode(value, RPC_ENCODE).to_string()
}

fn canonical(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .filter(|(key, _)| key.as_str() != "Signature")
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn signature(params: &BTreeMap<String, String>, key: &str) -> String {
    let to_sign = format!("POST&%2F&{}", encode(&canonical(params)));
    // HMAC-SHA1 accepts a key of any length; no credentials in panic output.
    let mut mac = Hmac::<Sha1>::new_from_slice(format!("{key}&").as_bytes())
        .expect("HMAC accepts arbitrary key length");
    mac.update(to_sign.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn line(value: &str) -> &str {
    match value {
        "" | "默认" => "default",
        other => other,
    }
}

fn rr(value: &str) -> &str {
    if value.is_empty() { "@" } else { value }
}

fn same_zone(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}

impl Alidns {
    pub fn new(
        client: reqwest::Client,
        id: String,
        key: String,
        options: &BTreeMap<String, String>,
    ) -> Self {
        Self {
            api: Api::new(client, vec![id.clone(), key.clone()]),
            id,
            key,
            region: options
                .get("region")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| "cn-hangzhou".into()),
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

    async fn call(
        &self,
        action: &str,
        mut params: BTreeMap<String, String>,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        params.extend([
            ("AccessKeyId".into(), self.id.clone()),
            ("Action".into(), action.into()),
            ("Format".into(), "JSON".into()),
            ("Version".into(), "2015-01-09".into()),
            ("RegionId".into(), self.region.clone()),
            ("SignatureMethod".into(), "HMAC-SHA1".into()),
            ("SignatureVersion".into(), "1.0".into()),
            ("SignatureNonce".into(), Uuid::new_v4().to_string()),
            (
                "Timestamp".into(),
                Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ),
        ]);
        let signed = signature(&params, &self.key);
        // Use the same RFC3986 serialization for signing and form submission.
        let body = format!("{}&Signature={}", canonical(&params), encode(&signed));
        let request = self
            .api
            .client
            .post(self.endpoint())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body);
        let reply = self.api.send(action, request, write).await?;
        // RPC business errors may arrive with HTTP 200, or with HTTP 4xx.
        // Inspect them BEFORE the generic HTTP check so useful Code/Message survive.
        if let Some(code_value) = reply.body.get("Code") {
            let code = code_value
                .as_str()
                .filter(|v| !v.is_empty())
                .unwrap_or("MalformedErrorResponse");
            let message = reply
                .body
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or("AliDNS returned an error without a Message");
            return Err(self
                .api
                .error(action, code, message, error_hint(code), Some(&reply)));
        }
        self.api.check_http(action, &reply)?;
        if !reply.body.is_object() {
            return Err(self.malformed(action, "Expected an RPC JSON object", &reply));
        }
        Ok(reply)
    }

    fn malformed(&self, action: &str, message: &str, reply: &HttpReply) -> ProviderError {
        self.api.error(action, "MalformedResponse", message,
            "Refusing to select or mutate records from an incomplete provider response; retry the read and inspect RequestId.", Some(reply))
    }

    fn required<'a>(
        &self,
        action: &str,
        value: &'a Value,
        field: &str,
        reply: &HttpReply,
    ) -> Result<&'a str, ProviderError> {
        value
            .get(field)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| self.malformed(action, &format!("Missing or invalid {field}"), reply))
    }

    async fn verify_zone(&self, spec: &Spec) -> Result<(), ProviderError> {
        let action = "DescribeDomainInfo";
        let reply = self
            .call(
                action,
                BTreeMap::from([("DomainName".into(), spec.domain.clone())]),
                false,
            )
            .await?;
        let domain = self.required(action, &reply.body, "DomainName", &reply)?;
        self.required(action, &reply.body, "DomainId", &reply)?;
        if !same_zone(domain, &spec.domain) {
            return Err(self.api.error(action, "ZoneMismatch",
                &format!("Configured zone {} differs from returned zone {}", spec.domain, domain),
                "Set domain to the actual hosted AliDNS zone; do not infer the zone from a public-suffix or first-record match.", Some(&reply)));
        }
        Ok(())
    }

    fn record(
        &self,
        value: &Value,
        spec: &Spec,
        reply: &HttpReply,
    ) -> Result<Record, ProviderError> {
        let action = "DescribeDomainRecords";
        let id = self.required(action, value, "RecordId", reply)?;
        let name = self.required(action, value, "RR", reply)?;
        let record_type = self.required(action, value, "Type", reply)?;
        let address = self.required(action, value, "Value", reply)?;
        let record_line = self.required(action, value, "Line", reply)?;
        let status = self.required(action, value, "Status", reply)?;
        let enabled = if status.eq_ignore_ascii_case("ENABLE") {
            true
        } else if status.eq_ignore_ascii_case("DISABLE") {
            false
        } else {
            return Err(self.malformed(
                action,
                "Unknown record Status (expected ENABLE/DISABLE)",
                reply,
            ));
        };
        let ttl = value
            .get("TTL")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0)
            .ok_or_else(|| self.malformed(action, "Missing or invalid record TTL", reply))?;
        let domain = self.required(action, value, "DomainName", reply)?;
        if !same_zone(domain, &spec.domain) {
            return Err(self.malformed(action, "Record belongs to a different zone", reply));
        }
        // Retain the original JSON for supported payload fields and diagnostics.
        // Do not log it: some providers may echo credentials in response fields.
        Ok(Record {
            id: id.into(),
            name: name.into(),
            record_type: record_type.into(),
            value: address.into(),
            ttl,
            line: line(record_line).into(),
            enabled,
            extra: value.clone(),
        })
    }

    fn mutation(
        &self,
        action: &str,
        reply: HttpReply,
        expected_id: Option<&str>,
    ) -> Result<Mutation, ProviderError> {
        let id = self.required(action, &reply.body, "RecordId", &reply)?;
        if expected_id.is_some_and(|expected| expected != id) {
            return Err(self.malformed(
                action,
                "Mutation returned a different RecordId; verify write outcome before retrying",
                &reply,
            ));
        }
        Ok(Mutation {
            record_id: id.into(),
            request_id: reply.request_id,
        })
    }
}

fn error_hint(code: &str) -> &'static str {
    let lower = code.to_ascii_lowercase();
    if lower.contains("signature") || lower.contains("timestamp") || lower.contains("nonce") {
        "Check AccessKey credentials, UTC system clock/NTP, and RPC signature settings; never log the signed form."
    } else if lower.contains("forbidden")
        || lower.contains("permission")
        || lower.contains("unauthorized")
        || lower.contains("accessdenied")
    {
        "Check RAM alidns:DescribeDomainInfo permission on * and DescribeDomainRecords/AddDomainRecord/UpdateDomainRecord permissions for this zone; verify the account owns it."
    } else if lower.contains("accesskey") {
        "Check that the AccessKeyId is active, the secret matches, and the correct Alibaba Cloud account owns this zone."
    } else if lower.contains("domainnotexist") || lower.contains("invaliddomain") {
        "Verify domain is the actual zone hosted in this AliDNS account, not the full record name."
    } else if lower.contains("throttl") {
        "Reduce request frequency; read operations may be retried, but verify a write's outcome before any manual retry."
    } else if lower.contains("ttl") || lower.contains("line") {
        "Check the zone edition's minimum TTL and supported DNS line codes (default, telecom, unicom, etc.)."
    } else {
        "Inspect the sanitized AliDNS Code, Message, HTTP status and RequestId; check zone ownership, RAM permissions and record parameters."
    }
}

impl Adapter for Alidns {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Relative
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        self.verify_zone(spec).await?;
        let action = "DescribeDomainRecords";
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        let mut page_size = None;
        let mut request_id = None;
        for page in 1..=MAX_PAGES {
            // Return ALL records, not a fuzzy-filtered subset or a default first
            // choice. The shared reconciler performs exact selection/dry-run.
            let reply = self
                .call(
                    action,
                    BTreeMap::from([
                        ("DomainName".into(), spec.domain.clone()),
                        ("PageNumber".into(), page.to_string()),
                        ("PageSize".into(), PAGE_SIZE.to_string()),
                    ]),
                    false,
                )
                .await?;
            let count = reply
                .body
                .get("TotalCount")
                .and_then(Value::as_u64)
                .ok_or_else(|| self.malformed(action, "Missing or invalid TotalCount", &reply))?;
            if count > PAGE_SIZE * MAX_PAGES || total.is_some_and(|n| n != count) {
                return Err(self.malformed(
                    action,
                    "TotalCount changed during pagination or exceeds safe pagination limit",
                    &reply,
                ));
            }
            total = Some(count);
            if reply.body.get("PageNumber").and_then(Value::as_u64) != Some(page) {
                return Err(self.malformed(action, "Missing or unexpected PageNumber", &reply));
            }
            let size = reply
                .body
                .get("PageSize")
                .and_then(Value::as_u64)
                .filter(|v| *v > 0 && *v <= PAGE_SIZE)
                .ok_or_else(|| self.malformed(action, "Missing or invalid PageSize", &reply))?;
            if page_size.is_some_and(|previous| previous != size) {
                return Err(self.malformed(action, "PageSize changed during pagination", &reply));
            }
            page_size = Some(size);
            let items = reply
                .body
                .pointer("/DomainRecords/Record")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    self.malformed(action, "Missing DomainRecords.Record array", &reply)
                })?;
            if items.len() as u64 > size || records.len() as u64 + items.len() as u64 > count {
                return Err(self.malformed(
                    action,
                    "Page length contradicts PageSize or TotalCount",
                    &reply,
                ));
            }
            for item in items {
                let record = self.record(item, spec, &reply)?;
                if !ids.insert(record.id.clone()) {
                    return Err(self.malformed(
                        action,
                        "Duplicate RecordId across pages; refusing incomplete selection",
                        &reply,
                    ));
                }
                records.push(record);
            }
            request_id = reply.request_id.clone().or(request_id);
            if records.len() as u64 == count {
                return Ok(List {
                    records,
                    request_id,
                });
            }
            if items.len() as u64 != size {
                return Err(self.malformed(
                    action,
                    "Truncated page before TotalCount was reached",
                    &reply,
                ));
            }
        }
        Err(self.api.error(action, "PaginationLimit", "Records exceed bounded pagination",
            "Refusing incomplete record selection; inspect zone size and retry only after resolving the limit.", None))
    }

    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let action = "AddDomainRecord";
        let reply = self
            .call(
                action,
                BTreeMap::from([
                    ("DomainName".into(), spec.domain.clone()),
                    ("RR".into(), rr(&spec.subdomain).into()),
                    ("Type".into(), spec.record_type.clone()),
                    ("Value".into(), ip.into()),
                    ("TTL".into(), spec.ttl.to_string()),
                    ("Line".into(), line(&spec.record_line).into()),
                ]),
                true,
            )
            .await?;
        self.mutation(action, reply, None)
    }

    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        if !self.name_format().matches(&record.name, spec) || record.record_type != spec.record_type
        {
            return Err(super::common::local_error(
                "update",
                "RecordIdMismatch",
                "Selected AliDNS record belongs to a different host or type.",
                "Re-read the intended target; unrelated records are never repurposed.",
                None,
            ));
        }
        let action = "UpdateDomainRecord";
        let mut params = BTreeMap::from([
            ("RecordId".into(), record.id.clone()),
            ("RR".into(), record.name.clone()),
            ("Type".into(), record.record_type.clone()),
            ("Value".into(), ip.into()),
            ("TTL".into(), spec.ttl.to_string()),
            ("Line".into(), line(&record.line).into()),
        ]);
        // Priority is a documented UpdateDomainRecord field. Weight is NOT:
        // preserve weight/LbaStatus/Status/Remark/Locked by leaving them alone,
        // never passing undocumented properties or calling separate mutations.
        if record.record_type.eq_ignore_ascii_case("MX") {
            let priority = record.extra.get("Priority").and_then(Value::as_u64)
                .filter(|p| (1..=50).contains(p)).ok_or_else(|| self.api.error(action,
                    "InvalidRecord", "MX record is missing a valid Priority",
                    "Re-read the selected record before updating; refusing to reset its priority.", None))?;
            params.insert("Priority".into(), priority.to_string());
        }
        let reply = self.call(action, params, true).await?;
        self.mutation(action, reply, Some(&record.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode, Uri},
        routing::post,
    };
    use serde_json::json;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[derive(Clone)]
    struct MockState {
        replies: Arc<Mutex<VecDeque<(u16, Value)>>>,
        requests: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    }
    struct Mock {
        provider: Alidns,
        state: MockState,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(
        State(state): State<MockState>,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, axum::Json<Value>) {
        assert_eq!(uri.path(), "/");
        assert!(
            uri.query().is_none(),
            "Credentials must never appear in URL"
        );
        assert_eq!(
            headers[reqwest::header::CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        let body = std::str::from_utf8(&body).unwrap();
        let params: BTreeMap<String, String> = body
            .split('&')
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap();
                (
                    percent_encoding::percent_decode_str(key)
                        .decode_utf8()
                        .unwrap()
                        .into_owned(),
                    percent_encoding::percent_decode_str(value)
                        .decode_utf8()
                        .unwrap()
                        .into_owned(),
                )
            })
            .collect();
        assert_eq!(params["Signature"], signature(&params, "mock-secret"));
        assert_eq!(params["AccessKeyId"], "mock-access-id");
        assert!(Uuid::parse_str(&params["SignatureNonce"]).is_ok());
        assert!(chrono::DateTime::parse_from_rfc3339(&params["Timestamp"]).is_ok());
        state.requests.lock().unwrap().push(params);
        let (status, reply) = state
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request");
        (StatusCode::from_u16(status).unwrap(), axum::Json(reply))
    }
    async fn mock(replies: Vec<(u16, Value)>) -> Mock {
        let state = MockState {
            replies: Arc::new(Mutex::new(replies.into())),
            requests: Arc::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/", post(handler))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let mut provider = Alidns::new(
            client,
            "mock-access-id".into(),
            "mock-secret".into(),
            &BTreeMap::new(),
        );
        provider.endpoint = endpoint;
        Mock {
            provider,
            state,
            task,
        }
    }
    fn spec() -> Spec {
        Spec {
            domain: "example.com".into(),
            subdomain: "www".into(),
            record_type: "A".into(),
            record_line: "默认".into(),
            ttl: 600,
            record_id: None,
            create_if_missing: true,
            options: BTreeMap::new(),
        }
    }
    fn zone() -> (u16, Value) {
        (
            200,
            json!({"DomainName":"example.com", "DomainId":"zone-1", "RequestId":"zone-request"}),
        )
    }
    fn record(id: &str) -> Value {
        json!({"RecordId":id,"RR":"www","Type":"A","Value":"192.0.2.1","TTL":600,
            "Line":"default","Status":"ENABLE","DomainName":"example.com","Weight":37,
            "LbaStatus":true,"Locked":false,"Remark":"keep this remark"})
    }
    fn page(total: u64, number: u64, size: u64, records: Vec<Value>) -> (u16, Value) {
        (
            200,
            json!({"TotalCount":total,"PageNumber":number,"PageSize":size,
            "DomainRecords":{"Record":records},"RequestId":format!("page-{number}")}),
        )
    }
    fn captured(mock: &Mock) -> Vec<BTreeMap<String, String>> {
        mock.state.requests.lock().unwrap().clone()
    }

    #[test]
    fn signing_golden_independently_calculated_with_python_stdlib() {
        // Python urllib.parse.quote(safe='-_.~'), hmac.new(key + b'&',
        // b'POST&%2F&' + quote(canonical), hashlib.sha1), base64.b64encode.
        let params = BTreeMap::from([
            ("AccessKeyId".into(), "testid".into()),
            ("Action".into(), "DescribeDomainRecords".into()),
            ("DomainName".into(), "example.com".into()),
            ("Format".into(), "JSON".into()),
            ("RegionId".into(), "cn-hangzhou".into()),
            ("SignatureMethod".into(), "HMAC-SHA1".into()),
            (
                "SignatureNonce".into(),
                "00000000-0000-4000-8000-000000000000".into(),
            ),
            ("SignatureVersion".into(), "1.0".into()),
            ("Timestamp".into(), "2015-01-09T12:00:00Z".into()),
            ("Version".into(), "2015-01-09".into()),
            ("RRKeyWord".into(), "a +/~*中文".into()),
        ]);
        assert_eq!(
            canonical(&params),
            "AccessKeyId=testid&Action=DescribeDomainRecords&DomainName=example.com&Format=JSON&RRKeyWord=a%20%2B%2F~%2A%E4%B8%AD%E6%96%87&RegionId=cn-hangzhou&SignatureMethod=HMAC-SHA1&SignatureNonce=00000000-0000-4000-8000-000000000000&SignatureVersion=1.0&Timestamp=2015-01-09T12%3A00%3A00Z&Version=2015-01-09"
        );
        assert_eq!(
            signature(&params, "testsecret"),
            "ZfjbeCjc9eaM0me3EylDsVj34n8="
        );
        let mut already_signed = params.clone();
        already_signed.insert("Signature".into(), "ignored".into());
        assert_eq!(
            signature(&params, "testsecret"),
            signature(&already_signed, "testsecret")
        );
    }

    #[test]
    fn rfc3986_encoding_and_line_compatibility() {
        assert_eq!(encode("AZaz09-_.~ +/*%"), "AZaz09-_.~%20%2B%2F%2A%25");
        assert_eq!(line("默认"), "default");
        assert_eq!(line("telecom"), "telecom");
        assert_eq!(rr(""), "@");
    }

    #[tokio::test]
    async fn complete_pagination_keeps_multiple_candidates_and_metadata() {
        let mut disabled = record("2");
        disabled["Status"] = json!("Disable");
        disabled["Line"] = json!("telecom");
        let mock = mock(vec![
            zone(),
            page(3, 1, 2, vec![record("1"), disabled.clone()]),
            page(3, 2, 2, vec![record("3")]),
        ])
        .await;
        let result = mock.provider.list(&spec()).await.unwrap();
        assert_eq!(result.records.len(), 3);
        assert!(!result.records[1].enabled);
        assert_eq!(result.records[1].line, "telecom");
        assert_eq!(result.records[1].extra, disabled);
        assert_eq!(result.request_id.as_deref(), Some("page-2"));
        let requests = captured(&mock);
        assert_eq!(requests[0]["Action"], "DescribeDomainInfo");
        assert_eq!(requests[1]["PageNumber"], "1");
        assert_eq!(requests[2]["PageNumber"], "2");
        assert!(!requests[1].contains_key("RRKeyWord"));
        assert_ne!(requests[1]["SignatureNonce"], requests[2]["SignatureNonce"]);
    }

    #[tokio::test]
    async fn empty_zone_is_valid_only_with_explicit_zero_count_and_array() {
        let mock = mock(vec![zone(), page(0, 1, 500, vec![])]).await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap()
                .records
                .is_empty()
        );
    }

    #[tokio::test]
    async fn actual_zone_mismatch_fails_before_record_read() {
        let mock = mock(vec![(
            200,
            json!({"DomainName":"other.com","DomainId":"zone-2"}),
        )])
        .await;
        let error = mock.provider.list(&spec()).await.unwrap_err();
        assert_eq!(error.code, "ZoneMismatch");
        assert_eq!(captured(&mock).len(), 1);
    }

    #[tokio::test]
    async fn business_error_http_200_preserves_code_request_id_and_redacts_credentials() {
        let mock = mock(vec![(
            200,
            json!({"Code":"Forbidden.RAM","Message":"Denied mock-access-id mock-secret",
            "RequestId":"req-denied"}),
        )])
        .await;
        let error = mock.provider.list(&spec()).await.unwrap_err();
        assert_eq!(error.code, "Forbidden.RAM");
        assert_eq!(error.http_status, Some(200));
        assert!(error.hint.contains("RAM"));
        let serialized = serde_json::to_string(&error).unwrap();
        assert!(!serialized.contains("mock-secret"));
        assert!(!serialized.contains("mock-access-id"));
        assert!(error.request_id.is_some());
    }

    #[tokio::test]
    async fn business_error_http_403_is_not_replaced_by_generic_http_error() {
        let mock = mock(vec![(
            403,
            json!({"Code":"SignatureDoesNotMatch","Message":"bad signing","RequestId":"req-403"}),
        )])
        .await;
        let error = mock.provider.list(&spec()).await.unwrap_err();
        assert_eq!(error.code, "SignatureDoesNotMatch");
        assert_eq!(error.http_status, Some(403));
        assert_eq!(error.request_id.as_deref(), Some("req-403"));
        assert!(error.hint.contains("clock"));
    }

    #[tokio::test]
    async fn missing_total_count_fails_closed() {
        let mut response = page(0, 1, 500, vec![]);
        response.1.as_object_mut().unwrap().remove("TotalCount");
        let mock = mock(vec![zone(), response]).await;
        assert_eq!(
            mock.provider.list(&spec()).await.unwrap_err().code,
            "MalformedResponse"
        );
    }

    #[tokio::test]
    async fn truncated_page_does_not_trigger_create_or_select_first() {
        let mock = mock(vec![zone(), page(3, 1, 2, vec![record("1")])]).await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap_err()
                .message
                .contains("Truncated")
        );
        assert_eq!(captured(&mock).len(), 2);
    }

    #[tokio::test]
    async fn changing_total_count_fails_closed() {
        let mock = mock(vec![
            zone(),
            page(2, 1, 1, vec![record("1")]),
            page(3, 2, 1, vec![record("2")]),
        ])
        .await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap_err()
                .message
                .contains("TotalCount")
        );
    }

    #[tokio::test]
    async fn duplicate_record_ids_across_pages_fail_closed() {
        let mock = mock(vec![
            zone(),
            page(2, 1, 1, vec![record("1")]),
            page(2, 2, 1, vec![record("1")]),
        ])
        .await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap_err()
                .message
                .contains("Duplicate")
        );
    }

    #[tokio::test]
    async fn unknown_status_is_not_treated_as_enabled() {
        let mut item = record("1");
        item["Status"] = json!("unknown");
        let mock = mock(vec![zone(), page(1, 1, 500, vec![item])]).await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap_err()
                .message
                .contains("Status")
        );
    }

    #[tokio::test]
    async fn create_posts_real_parameters_and_default_line_no_secrets_in_url() {
        let mock = mock(vec![(
            200,
            json!({"RecordId":"new-1","RequestId":"create-req"}),
        )])
        .await;
        let mut spec = spec();
        spec.subdomain = "@".into();
        spec.record_type = "AAAA".into();
        let mutation = mock.provider.create(&spec, "2001:db8::1").await.unwrap();
        assert_eq!(mutation.record_id, "new-1");
        let request = &captured(&mock)[0];
        assert_eq!(request["Action"], "AddDomainRecord");
        assert_eq!(request["DomainName"], "example.com");
        assert_eq!(request["RR"], "@");
        assert_eq!(request["Type"], "AAAA");
        assert_eq!(request["Value"], "2001:db8::1");
        assert_eq!(request["TTL"], "600");
        assert_eq!(request["Line"], "default");
        assert_eq!(request["RegionId"], "cn-hangzhou");
    }

    #[tokio::test]
    async fn update_preserves_real_line_weight_status_and_metadata_without_undocumented_fields() {
        let mut item = record("weighted-1");
        item["Line"] = json!("telecom");
        let mock = mock(vec![
            zone(),
            page(1, 1, 500, vec![item.clone()]),
            (
                200,
                json!({"RecordId":"weighted-1","RequestId":"update-req"}),
            ),
        ])
        .await;
        let listed = mock.provider.list(&spec()).await.unwrap();
        let selected = &listed.records[0];
        let mutation = mock
            .provider
            .update(&spec(), selected, "192.0.2.99")
            .await
            .unwrap();
        assert_eq!(mutation.record_id, "weighted-1");
        assert_eq!(selected.extra, item);
        let request = &captured(&mock)[2];
        assert_eq!(request["Line"], "telecom");
        assert_eq!(request["RecordId"], "weighted-1");
        assert_eq!(request["Value"], "192.0.2.99");
        assert_eq!(request["RR"], "www");
        for field in [
            "Weight",
            "LbaStatus",
            "Status",
            "Remark",
            "Locked",
            "DomainName",
            "Priority",
        ] {
            assert!(
                !request.contains_key(field),
                "Do not send undocumented or unrelated property {field}"
            );
        }
        assert_eq!(captured(&mock).len(), 3, "No extra status/weight mutation");
    }

    #[tokio::test]
    async fn mutation_missing_id_is_not_success_and_write_is_not_retried() {
        let mock = mock(vec![(200, json!({"RequestId":"missing-record"}))]).await;
        assert_eq!(
            mock.provider
                .create(&spec(), "192.0.2.99")
                .await
                .unwrap_err()
                .code,
            "MalformedResponse"
        );
        assert_eq!(captured(&mock).len(), 1);
    }

    #[tokio::test]
    async fn configured_region_used_but_endpoint_option_cannot_override_production_host() {
        let mut mock = mock(vec![(200, json!({"RecordId":"new-1"}))]).await;
        // Region is selectable; constructor never accepts an endpoint override.
        let options = BTreeMap::from([
            ("region".into(), "ap-southeast-1".into()),
            ("endpoint".into(), "http://invalid.example/".into()),
        ]);
        let provider = Alidns::new(reqwest::Client::new(), "id".into(), "key".into(), &options);
        assert_eq!(provider.region, "ap-southeast-1");
        assert_eq!(provider.endpoint(), ENDPOINT);
        mock.provider.region = provider.region;
        mock.provider.create(&spec(), "192.0.2.2").await.unwrap();
        assert_eq!(captured(&mock)[0]["RegionId"], "ap-southeast-1");
    }
    #[tokio::test]
    async fn relative_suffix_shadow_never_selects_or_writes_wrong_owner() {
        for explicit in [false, true] {
            for (ip, dry) in [
                ("192.0.2.1", false),
                ("192.0.2.2", true),
                ("192.0.2.2", false),
            ] {
                let mut wrong = record("1");
                wrong["RR"] = json!("home.example.com");
                let m = mock(vec![zone(), page(1, 1, 500, vec![wrong])]).await;
                let mut s = spec();
                s.subdomain = "home".into();
                s.create_if_missing = false;
                s.record_line = "default".into();
                if explicit {
                    s.record_id = Some("1".into());
                    s.create_if_missing = true;
                }
                assert_eq!(
                    super::super::common::reconcile(&m.provider, &s, ip, dry)
                        .await
                        .unwrap_err()
                        .code,
                    if explicit {
                        "RecordIdMismatch"
                    } else {
                        "RecordNotFound"
                    }
                );
                let calls = captured(&m);
                assert_eq!(calls.len(), 2);
                assert!(calls.iter().all(|r| r["Action"].starts_with("Describe")));
            }
        }
    }

    #[tokio::test]
    async fn relative_collision_updates_only_real_id_and_preserves_dotted_rr() {
        for host in ["home", "home.example.com", "example.com"] {
            let mut s = spec();
            s.subdomain = host.into();
            s.record_line = "default".into();
            let mut wrong = record("1");
            wrong["RR"] = json!(s.fqdn());
            let mut real = record("2");
            real["RR"] = json!(host);
            let m = mock(vec![
                zone(),
                page(2, 1, 500, vec![wrong, real]),
                (200, json!({"RecordId":"2"})),
            ])
            .await;
            let out = super::super::common::reconcile(&m.provider, &s, "192.0.2.2", false)
                .await
                .unwrap();
            assert_eq!(out.record_id.as_deref(), Some("2"));
            let calls = captured(&m);
            assert_eq!(calls.len(), 3);
            assert_eq!(calls[2]["RecordId"], "2");
            assert_eq!(calls[2]["RR"], host);
        }
    }
}
