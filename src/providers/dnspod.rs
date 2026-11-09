//! Traditional DNSPod API (main-account DNSPod Token ID/Token, NOT Tencent
//! Cloud SecretId/SecretKey). Fixed HTTPS endpoint; authentication ONLY in POST
//! form data. Clients must have redirects disabled. No Debug/Serialize for secrets.
//! https://docs.dnspod.cn/api/api-public-request/
//! https://docs.dnspod.cn/api/domain-info/
//! https://docs.dnspod.cn/api/record-list/
//! https://docs.dnspod.cn/api/add-record/
//! https://docs.dnspod.cn/api/modify-records/
//! https://docs.dnspod.cn/api/common-return/
#![allow(clippy::result_large_err)]

use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

const ENDPOINT: &str = "https://dnsapi.cn";
const PAGE_SIZE: u64 = 100;
const MAX_RECORDS: u64 = 10_000;
const USER_AGENT: &str = concat!("ddns-rust/", env!("CARGO_PKG_VERSION"));

pub struct Dnspod {
    api: Api,
    token: String,
    #[cfg(test)]
    endpoint: String,
}

// Official responses mix decimal strings and integer JSON values. Reject
// signs, whitespace, floats and nonnumeric strings rather than guessing counts.
fn number(value: &Value) -> Option<u64> {
    if let Some(text) = value.as_str() {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    } else {
        value.as_u64()
    }
}
fn identifier(value: &Value) -> Option<String> {
    number(value).filter(|id| *id > 0).map(|id| id.to_string())
}
fn record_line(value: &str) -> &str {
    if value.is_empty() || value == "default" {
        "默认"
    } else {
        value
    }
}
fn same_zone(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}
fn hint(code: &str) -> &'static str {
    match code {
        "-1" | "-8" => {
            "Use a main-account DNSPod Token ID and Token, not Tencent Cloud SecretId/SecretKey; check token activity and account lockout."
        }
        "-2" => {
            "Reduce API request frequency. Reads may be retried; inspect an uncertain write before any manual retry."
        }
        "-7" | "7" | "8" => {
            "Check that the main account owns this DNSPod zone and the token is authorized; traditional APIs do not accept subaccount Tencent credentials."
        }
        "6" | "13" => {
            "Verify the configured domain is the actual zone in this DNSPod account, not the full record name."
        }
        "-15" | "21" | "83" => {
            "The account or domain is blocked/locked; resolve the lock in the provider console before updating DNS."
        }
        "85" => "Check DNSPod login-region protection and the source IP allowlist.",
        "26" | "27" => {
            "Check record type and DNSPod line/line_id; keep the selected record's existing line."
        }
        "32" => {
            "TTL is outside this domain edition's permitted range (global range 1..604800); inspect the zone's minimum TTL and NS limits."
        }
        "104" | "31" => {
            "Inspect existing records and type conflicts; do not blindly retry a create or select the first matching record."
        }
        "-99" => {
            "DNSPod temporarily disabled this API; retry reads later, and inspect any uncertain write before retrying."
        }
        _ => {
            "Inspect sanitized DNSPod status.code/message, HTTP status and RequestId; verify ownership, token permissions and record parameters."
        }
    }
}

impl Dnspod {
    pub fn new(
        client: reqwest::Client,
        id: String,
        key: String,
        _options: &BTreeMap<String, String>,
    ) -> Self {
        let token = format!("{id},{key}");
        Self {
            api: Api::new(client, vec![token.clone(), key, id]),
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
    async fn call(
        &self,
        action: &str,
        mut params: BTreeMap<String, String>,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        params.extend([
            ("login_token".into(), self.token.clone()),
            ("format".into(), "json".into()),
            ("lang".into(), "en".into()),
            ("error_on_empty".into(), "no".into()),
        ]);
        let request = self
            .api
            .client
            .post(format!("{}/{action}", self.endpoint()))
            .header(reqwest::header::USER_AGENT, USER_AGENT)
            .form(&params);
        let reply = self.api.send(action, request, write).await?;
        if let Some(code) = reply.body.pointer("/status/code").and_then(Value::as_str) {
            if code != "1" {
                let message = reply
                    .body
                    .pointer("/status/message")
                    .and_then(Value::as_str)
                    .unwrap_or("DNSPod returned an error without a status.message");
                let message = if write {
                    format!(
                        "{message}. Write was not acknowledged; inspect the record before retrying."
                    )
                } else {
                    message.to_owned()
                };
                return Err(self
                    .api
                    .error(action, code, &message, hint(code), Some(&reply)));
            }
        } else {
            self.api.check_http(action, &reply)?;
            return Err(self.malformed(action, "Missing string status.code", &reply));
        }
        self.api.check_http(action, &reply)?;
        Ok(reply)
    }
    fn malformed(&self, action: &str, message: &str, reply: &HttpReply) -> ProviderError {
        self.api.error(action, "MalformedResponse", message,
            "Refusing incomplete record selection or an unacknowledged write; re-read the zone and inspect the provider before retrying a mutation.", Some(reply))
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
            .filter(|s| !s.is_empty())
            .ok_or_else(|| self.malformed(action, &format!("Missing or invalid {field}"), reply))
    }
    fn ttl(&self, spec: &Spec) -> Result<(), ProviderError> {
        if !(1..=604800).contains(&spec.ttl) {
            return Err(self.api.error("validation", "InvalidTtl", "DNSPod TTL must be within 1..604800 seconds",
                "Choose a TTL supported by the domain's edition; DNSPod also enforces a per-edition minimum.", None));
        }
        Ok(())
    }
    async fn verify_zone(&self, spec: &Spec) -> Result<String, ProviderError> {
        self.ttl(spec)?;
        let action = "Domain.Info";
        let reply = self
            .call(
                action,
                BTreeMap::from([("domain".into(), spec.domain.clone())]),
                false,
            )
            .await?;
        let domain = reply
            .body
            .get("domain")
            .filter(|d| d.is_object())
            .ok_or_else(|| self.malformed(action, "Missing domain object", &reply))?;
        let id = domain
            .get("id")
            .and_then(identifier)
            .ok_or_else(|| self.malformed(action, "Missing or invalid domain.id", &reply))?;
        let name = self.required(action, domain, "name", &reply)?;
        if !same_zone(name, &spec.domain) {
            return Err(self.api.error(action, "ZoneMismatch", "Returned DNSPod domain differs from the configured zone",
                "Configure the actual hosted zone; do not infer ownership from a first matching record.", Some(&reply)));
        }
        let status = self.required(action, domain, "status", &reply)?;
        if status != "enable" {
            return Err(self.api.error(
                action,
                "DomainDisabled",
                &format!("DNSPod zone status is {status}, not enable"),
                "Resolve paused, locked or blocked domain status in DNSPod before making changes.",
                Some(&reply),
            ));
        }
        // Domain.Info's ttl is the DEFAULT, not the MINIMUM (official docs).
        // Validate its shape, but do not reject a legitimate lower desired TTL.
        domain
            .get("ttl")
            .and_then(number)
            .filter(|ttl| (1..=604800).contains(ttl))
            .ok_or_else(|| {
                self.malformed(action, "Missing or invalid domain default ttl", &reply)
            })?;
        Ok(id)
    }
    fn parse_record(&self, value: &Value, reply: &HttpReply) -> Result<Record, ProviderError> {
        let action = "Record.List";
        let id = value
            .get("id")
            .and_then(identifier)
            .ok_or_else(|| self.malformed(action, "Missing or invalid record id", reply))?;
        let name = self.required(action, value, "name", reply)?.to_owned();
        let record_type = self.required(action, value, "type", reply)?.to_owned();
        let address = value
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| self.malformed(action, "Missing string record value", reply))?
            .to_owned();
        let ttl = value
            .get("ttl")
            .and_then(number)
            .filter(|ttl| *ttl > 0)
            .ok_or_else(|| self.malformed(action, "Missing or invalid record ttl", reply))?;
        let line = self.required(action, value, "line", reply)?.to_owned();
        self.required(action, value, "line_id", reply)?;
        let enabled = match value.get("enabled").and_then(Value::as_str) {
            Some("1") => true,
            Some("0") => false,
            _ => {
                return Err(self.malformed(
                    action,
                    "Unknown enabled status (expected string 0/1)",
                    reply,
                ));
            }
        };
        if let Some(weight) = value.get("weight").filter(|v| !v.is_null()) {
            number(weight)
                .filter(|w| *w <= 100)
                .ok_or_else(|| self.malformed(action, "Invalid record weight", reply))?;
        }
        Ok(Record {
            id,
            name,
            record_type,
            value: address,
            ttl,
            line,
            enabled,
            extra: value.clone(),
        })
    }
    fn mutation(
        &self,
        action: &str,
        reply: HttpReply,
        expected: Option<&str>,
    ) -> Result<Mutation, ProviderError> {
        let id = reply
            .body
            .pointer("/record/id")
            .and_then(identifier)
            .ok_or_else(|| {
                self.malformed(
                    action,
                    "Missing or invalid record.id acknowledgement; write outcome uncertain",
                    &reply,
                )
            })?;
        if expected.is_some_and(|expected| expected != id) {
            return Err(self.malformed(
                action,
                "Acknowledged record.id differs from selected record; write outcome uncertain",
                &reply,
            ));
        }
        Ok(Mutation {
            record_id: id,
            request_id: reply.request_id,
        })
    }
}

impl Adapter for Dnspod {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Relative
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        let domain_id = self.verify_zone(spec).await?;
        let action = "Record.List";
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        for _ in 0..(MAX_RECORDS / PAGE_SIZE) {
            let offset = records.len() as u64;
            let reply = self
                .call(
                    action,
                    BTreeMap::from([
                        ("domain_id".into(), domain_id.clone()),
                        ("offset".into(), offset.to_string()),
                        ("length".into(), PAGE_SIZE.to_string()),
                    ]),
                    false,
                )
                .await?;
            let domain = reply
                .body
                .get("domain")
                .ok_or_else(|| self.malformed(action, "Missing list domain", &reply))?;
            if domain.get("id").and_then(identifier).as_deref() != Some(&domain_id)
                || !same_zone(self.required(action, domain, "name", &reply)?, &spec.domain)
            {
                return Err(self.malformed(
                    action,
                    "Record.List returned a different zone",
                    &reply,
                ));
            }
            let count = reply
                .body
                .pointer("/info/record_total")
                .and_then(number)
                .ok_or_else(|| {
                    self.malformed(action, "Missing or invalid info.record_total", &reply)
                })?;
            if count > MAX_RECORDS || total.is_some_and(|previous| previous != count) {
                return Err(self.malformed(
                    action,
                    "Record total changed or exceeds safe pagination limit",
                    &reply,
                ));
            }
            total = Some(count);
            let returned = reply
                .body
                .pointer("/info/records_num")
                .and_then(number)
                .ok_or_else(|| {
                    self.malformed(action, "Missing or invalid info.records_num", &reply)
                })?;
            let items = reply
                .body
                .get("records")
                .and_then(Value::as_array)
                .ok_or_else(|| self.malformed(action, "Missing records array", &reply))?;
            if returned != items.len() as u64 || returned > PAGE_SIZE || offset + returned > count {
                return Err(self.malformed(
                    action,
                    "records_num contradicts array length or record_total",
                    &reply,
                ));
            }
            for item in items {
                let record = self.parse_record(item, &reply)?;
                if !ids.insert(record.id.clone()) {
                    return Err(self.malformed(
                        action,
                        "Duplicate record id during pagination",
                        &reply,
                    ));
                }
                records.push(record);
            }
            if records.len() as u64 == count {
                return Ok(List {
                    records,
                    request_id: reply.request_id,
                });
            }
            if returned != PAGE_SIZE {
                return Err(self.malformed(
                    action,
                    "Truncated page before record_total was reached",
                    &reply,
                ));
            }
        }
        Err(self.api.error(
            action,
            "PaginationLimit",
            "DNSPod pagination exceeded safe limit",
            "Refusing incomplete selection; inspect the zone size and concurrent changes.",
            None,
        ))
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.ttl(spec)?;
        let action = "Record.Create";
        let mut params = BTreeMap::from([
            ("domain".into(), spec.domain.clone()),
            ("sub_domain".into(), spec.subdomain.clone()),
            ("record_type".into(), spec.record_type.clone()),
            ("record_line".into(), record_line(&spec.record_line).into()),
            ("value".into(), ip.into()),
            ("ttl".into(), spec.ttl.to_string()),
        ]);
        if let Some(id) = spec
            .options
            .get("record_line_id")
            .filter(|id| !id.is_empty())
        {
            params.insert("record_line_id".into(), id.clone());
        }
        self.mutation(action, self.call(action, params, true).await?, None)
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.ttl(spec)?;
        if !self.name_format().matches(&record.name, spec) || record.record_type != spec.record_type
        {
            return Err(super::common::local_error(
                "update",
                "RecordIdMismatch",
                "Selected DNSPod record belongs to a different host or type.",
                "Re-read the intended target; unrelated records are never repurposed.",
                None,
            ));
        }
        let action = "Record.Modify";
        let line_id = record
            .extra
            .get("line_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                self.api.error(
                    action,
                    "InvalidRecord",
                    "Selected record is missing line_id",
                    "Re-read the record; refusing to reset its DNSPod line.",
                    None,
                )
            })?;
        let mut params = BTreeMap::from([
            ("domain".into(), spec.domain.clone()),
            ("record_id".into(), record.id.clone()),
            ("sub_domain".into(), record.name.clone()),
            ("record_type".into(), record.record_type.clone()),
            ("record_line".into(), record.line.clone()),
            ("record_line_id".into(), line_id.into()),
            ("value".into(), ip.into()),
            ("ttl".into(), spec.ttl.to_string()),
            // Record.Modify defaults to enable, so preserve explicitly.
            (
                "status".into(),
                if record.enabled { "enable" } else { "disable" }.into(),
            ),
        ]);
        if let Some(weight) = record.extra.get("weight").filter(|v| !v.is_null()) {
            let weight = number(weight).filter(|w| *w <= 100).ok_or_else(|| {
                self.api.error(
                    action,
                    "InvalidRecord",
                    "Selected record has invalid weight",
                    "Re-read the record before modifying its load balancing.",
                    None,
                )
            })?;
            params.insert("weight".into(), weight.to_string());
        }
        if record.record_type == "MX" {
            let mx = record
                .extra
                .get("mx")
                .and_then(number)
                .filter(|mx| (1..=20).contains(mx))
                .ok_or_else(|| {
                    self.api.error(
                        action,
                        "InvalidRecord",
                        "MX record is missing valid mx priority",
                        "Re-read the record before modifying its MX priority.",
                        None,
                    )
                })?;
            params.insert("mx".into(), mx.to_string());
        }
        self.mutation(
            action,
            self.call(action, params, true).await?,
            Some(&record.id),
        )
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

    type Request = (String, BTreeMap<String, String>);
    #[derive(Clone)]
    struct MockState {
        replies: Arc<Mutex<VecDeque<(u16, Value)>>>,
        requests: Arc<Mutex<Vec<Request>>>,
    }
    struct Mock {
        provider: Dnspod,
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
        assert!(uri.query().is_none(), "No token in request URLs");
        assert_eq!(
            headers[reqwest::header::CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        assert_eq!(headers[reqwest::header::USER_AGENT], USER_AGENT);
        let params = std::str::from_utf8(&body)
            .unwrap()
            .split('&')
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap();
                let decode = |s: &str| {
                    percent_encoding::percent_decode_str(&s.replace('+', " "))
                        .decode_utf8()
                        .unwrap()
                        .into_owned()
                };
                (decode(key), decode(value))
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(params["login_token"], "token-id,token-secret");
        assert_eq!(params["format"], "json");
        assert_eq!(params["lang"], "en");
        assert_eq!(params["error_on_empty"], "no");
        state
            .requests
            .lock()
            .unwrap()
            .push((uri.path().to_owned(), params));
        let (status, reply) = state
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("Unexpected request/retry");
        (StatusCode::from_u16(status).unwrap(), axum::Json(reply))
    }
    async fn mock(replies: Vec<(u16, Value)>) -> Mock {
        let state = MockState {
            replies: Arc::new(Mutex::new(replies.into())),
            requests: Arc::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/{action}", post(handler))
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
        let mut provider = Dnspod::new(
            client,
            "token-id".into(),
            "token-secret".into(),
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
    fn ok(body: Value) -> (u16, Value) {
        let mut body = body;
        body["status"] = json!({"code":"1","message":"Action completed successful"});
        (200, body)
    }
    fn zone() -> (u16, Value) {
        ok(json!({"domain":{"id":"12345","name":"example.com","status":"enable","ttl":"600"}}))
    }
    fn record(id: u64) -> Value {
        json!({"id":id.to_string(),"name":"www","type":"A","ttl":"600","value":"192.0.2.1",
        "line":"电信","line_id":"10=0","enabled":"1","weight":"37","mx":"0","remark":"Keep me","use_aqb":"no"})
    }
    fn page(total: u64, records: Vec<Value>) -> (u16, Value) {
        ok(json!({"domain":{"id":"12345","name":"example.com"},
        "info":{"record_total":total.to_string(),"records_num":records.len().to_string()},"records":records}))
    }
    fn requests(mock: &Mock) -> Vec<Request> {
        mock.state.requests.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn full_zone_pagination_does_not_filter_or_select_first() {
        let first = (1..=100).map(record).collect();
        let mut disabled = record(101);
        disabled["enabled"] = json!("0");
        let mock = mock(vec![
            zone(),
            page(101, first),
            page(101, vec![disabled.clone()]),
        ])
        .await;
        let list = mock.provider.list(&spec()).await.unwrap();
        assert_eq!(list.records.len(), 101);
        assert!(!list.records[100].enabled);
        assert_eq!(list.records[100].extra, disabled);
        let req = requests(&mock);
        assert_eq!(req[0].0, "/Domain.Info");
        assert_eq!(req[1].0, "/Record.List");
        assert_eq!(req[1].1["domain_id"], "12345");
        assert_eq!(req[1].1["offset"], "0");
        assert_eq!(req[2].1["offset"], "100");
        assert_eq!(req[1].1["length"], "100");
        assert!(!req[1].1.contains_key("sub_domain"));
        assert!(!req[1].1.contains_key("record_type"));
    }
    #[tokio::test]
    async fn empty_list_requires_explicit_zero_total_and_array() {
        let mock = mock(vec![zone(), page(0, vec![])]).await;
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
    async fn arbitrary_code_ten_is_not_empty_success() {
        let mock = mock(vec![
            zone(),
            (200, json!({"status":{"code":"10","message":"No data"}})),
        ])
        .await;
        assert_eq!(mock.provider.list(&spec()).await.unwrap_err().code, "10");
    }
    #[tokio::test]
    async fn disabled_zone_fails_before_listing() {
        let mut response = zone();
        response.1["domain"]["status"] = json!("pause");
        let mock = mock(vec![response]).await;
        assert_eq!(
            mock.provider.list(&spec()).await.unwrap_err().code,
            "DomainDisabled"
        );
        assert_eq!(requests(&mock).len(), 1);
    }
    #[tokio::test]
    async fn returned_wrong_zone_is_rejected() {
        let mut response = zone();
        response.1["domain"]["name"] = json!("other.com");
        let mock = mock(vec![response]).await;
        assert_eq!(
            mock.provider.list(&spec()).await.unwrap_err().code,
            "ZoneMismatch"
        );
    }
    #[tokio::test]
    async fn domain_default_ttl_is_not_mistaken_for_minimum() {
        let mock = mock(vec![zone(), page(0, vec![])]).await;
        let mut spec = spec();
        spec.ttl = 60;
        assert!(mock.provider.list(&spec).await.is_ok());
    }
    #[tokio::test]
    async fn negative_business_errors_retain_code_message_and_sanitize_secrets() {
        let mock = mock(vec![(
            403,
            json!({"status":{"code":"-1","message":"Bad token token-id,token-secret"}}),
        )])
        .await;
        let error = mock.provider.list(&spec()).await.unwrap_err();
        assert_eq!(error.code, "-1");
        assert_eq!(error.http_status, Some(403));
        assert!(error.message.contains("Bad token"));
        assert!(error.hint.contains("SecretId"));
        let json = serde_json::to_string(&error).unwrap();
        assert!(!json.contains("token-id"));
        assert!(!json.contains("token-secret"));
    }
    #[tokio::test]
    async fn missing_count_is_not_interpreted_as_zero() {
        let mut response = page(0, vec![]);
        response.1["info"]
            .as_object_mut()
            .unwrap()
            .remove("record_total");
        let mock = mock(vec![zone(), response]).await;
        assert_eq!(
            mock.provider.list(&spec()).await.unwrap_err().code,
            "MalformedResponse"
        );
    }
    #[tokio::test]
    async fn records_num_must_match_actual_array() {
        let mut response = page(1, vec![record(1)]);
        response.1["info"]["records_num"] = json!("0");
        let mock = mock(vec![zone(), response]).await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap_err()
                .message
                .contains("records_num")
        );
    }
    #[tokio::test]
    async fn truncated_first_page_is_rejected() {
        let mock = mock(vec![zone(), page(101, vec![record(1)])]).await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap_err()
                .message
                .contains("Truncated")
        );
    }
    #[tokio::test]
    async fn changed_total_is_rejected() {
        let mock = mock(vec![
            zone(),
            page(101, (1..=100).map(record).collect()),
            page(102, vec![record(101)]),
        ])
        .await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap_err()
                .message
                .contains("total changed")
        );
    }
    #[tokio::test]
    async fn duplicate_ids_fail_closed() {
        let mock = mock(vec![zone(), page(2, vec![record(1), record(1)])]).await;
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
    async fn update_preserves_line_id_weight_and_status_and_accepts_numeric_ack_id() {
        let item = record(16894439);
        let mock = mock(vec![
            zone(),
            page(1, vec![item.clone()]),
            ok(json!({"record":{"id":16894439}})),
        ])
        .await;
        let list = mock.provider.list(&spec()).await.unwrap();
        let result = mock
            .provider
            .update(&spec(), &list.records[0], "192.0.2.99")
            .await
            .unwrap();
        assert_eq!(result.record_id, "16894439");
        assert_eq!(list.records[0].extra, item);
        let req = &requests(&mock)[2];
        assert_eq!(req.0, "/Record.Modify");
        assert_eq!(req.1["record_line"], "电信");
        assert_eq!(req.1["record_line_id"], "10=0");
        assert_eq!(req.1["weight"], "37");
        assert_eq!(req.1["status"], "enable");
        assert_eq!(req.1["value"], "192.0.2.99");
        assert!(!req.1.contains_key("remark"));
        assert!(!req.1.contains_key("use_aqb"));
        assert_eq!(requests(&mock).len(), 3);
    }
    #[tokio::test]
    async fn update_does_not_enable_disabled_record_or_reset_null_weight() {
        let mut item = record(1);
        item["enabled"] = json!("0");
        item["weight"] = Value::Null;
        let mock = mock(vec![
            zone(),
            page(1, vec![item]),
            ok(json!({"record":{"id":"1"}})),
        ])
        .await;
        let list = mock.provider.list(&spec()).await.unwrap();
        mock.provider
            .update(&spec(), &list.records[0], "192.0.2.2")
            .await
            .unwrap();
        let req = &requests(&mock)[2].1;
        assert_eq!(req["status"], "disable");
        assert!(!req.contains_key("weight"));
    }
    #[tokio::test]
    async fn create_uses_real_payload_and_optional_line_id() {
        let mock = mock(vec![ok(json!({"record":{"id":"16894439"}}))]).await;
        let mut spec = spec();
        spec.options.insert("record_line_id".into(), "10=3".into());
        let result = mock.provider.create(&spec, "192.0.2.3").await.unwrap();
        assert_eq!(result.record_id, "16894439");
        let req = &requests(&mock)[0];
        assert_eq!(req.0, "/Record.Create");
        assert_eq!(req.1["record_line"], "默认");
        assert_eq!(req.1["record_line_id"], "10=3");
        assert_eq!(req.1["domain"], "example.com");
        assert_eq!(req.1["sub_domain"], "www");
        assert_eq!(req.1["record_type"], "A");
        assert_eq!(req.1["ttl"], "600");
    }
    #[tokio::test]
    async fn missing_write_ack_is_uncertain_and_not_retried() {
        let mock = mock(vec![ok(json!({"record":{}}))]).await;
        assert_eq!(
            mock.provider
                .create(&spec(), "192.0.2.3")
                .await
                .unwrap_err()
                .code,
            "MalformedResponse"
        );
        assert_eq!(requests(&mock).len(), 1);
    }
    #[tokio::test]
    async fn write_business_failure_preserves_ttl_code_and_is_not_retryable() {
        let mock = mock(vec![(
            200,
            json!({"status":{"code":"32","message":"TTL out of range"}}),
        )])
        .await;
        let error = mock
            .provider
            .create(&spec(), "192.0.2.3")
            .await
            .unwrap_err();
        assert_eq!(error.code, "32");
        assert!(!error.retryable);
        assert!(error.message.contains("TTL out of range"));
        assert!(error.hint.contains("minimum"));
        assert_eq!(requests(&mock).len(), 1);
    }
    #[test]
    fn counts_are_exact_integers_and_constructor_cannot_override_endpoint() {
        assert_eq!(number(&json!("100")), Some(100));
        assert_eq!(number(&json!(100)), Some(100));
        for bad in [
            json!("-1"),
            json!(" 1"),
            json!(1.5),
            json!("x"),
            Value::Null,
        ] {
            assert_eq!(number(&bad), None);
        }
        let options = BTreeMap::from([("endpoint".into(), "http://evil.example".into())]);
        assert_eq!(
            Dnspod::new(reqwest::Client::new(), "id".into(), "key".into(), &options).endpoint(),
            ENDPOINT
        );
    }
    #[tokio::test]
    async fn relative_suffix_shadow_never_selects_or_writes_wrong_owner() {
        for explicit in [false, true] {
            for (ip, dry) in [
                ("192.0.2.1", false),
                ("192.0.2.2", true),
                ("192.0.2.2", false),
            ] {
                let mut wrong = record(1);
                wrong["name"] = json!("home.example.com");
                let m = mock(vec![zone(), page(1, vec![wrong])]).await;
                let mut s = spec();
                s.subdomain = "home".into();
                s.create_if_missing = false;
                s.record_line = "电信".into();
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
                let calls = requests(&m);
                assert_eq!(calls.len(), 2);
                assert!(
                    calls
                        .iter()
                        .all(|r| r.0 == "/Domain.Info" || r.0 == "/Record.List")
                );
            }
        }
    }

    #[tokio::test]
    async fn relative_collision_updates_only_real_id_and_preserves_dotted_rr() {
        for host in ["home", "home.example.com", "example.com"] {
            let mut s = spec();
            s.subdomain = host.into();
            s.record_line = "电信".into();
            let mut wrong = record(1);
            wrong["name"] = json!(s.fqdn());
            let mut real = record(2);
            real["name"] = json!(host);
            let m = mock(vec![
                zone(),
                page(2, vec![wrong, real]),
                ok(json!({"record":{"id":"2"}})),
            ])
            .await;
            let out = super::super::common::reconcile(&m.provider, &s, "192.0.2.2", false)
                .await
                .unwrap();
            assert_eq!(out.record_id.as_deref(), Some("2"));
            let calls = requests(&m);
            assert_eq!(calls.len(), 3);
            assert_eq!(calls[2].1["record_id"], "2");
            assert_eq!(calls[2].1["sub_domain"], host);
        }
    }
}
