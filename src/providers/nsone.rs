//! IBM NS1 Connect native records. Only dedicated static single-answer RRsets.
//! API methods and partial-update model: official ns1-python Records resource:
//! https://raw.githubusercontent.com/ns1/ns1-python/master/ns1/rest/records.py
//! Zones: https://raw.githubusercontent.com/ns1/ns1-python/master/ns1/rest/zones.py
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec, valid_id};
use crate::provider::ProviderError;
use reqwest::{Method, RequestBuilder, header::HeaderValue};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::IpAddr};
const ENDPOINT: &str = "https://api.nsone.net/v1";
// Deliberately no Debug: do not expose API key in diagnostic output.
pub struct Nsone {
    api: Api,
    token: String,
    #[cfg(test)]
    endpoint: String,
}
fn present(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        Some(Value::String(s)) => !s.is_empty(),
        _ => true,
    }
}
fn hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
impl Nsone {
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
        let header = HeaderValue::from_str(&self.token).map(|mut h| {
            h.set_sensitive(true);
            h
        });
        let request = self
            .api
            .client
            .request(method, format!("{}{path}", self.endpoint()));
        match header {
            Ok(h) => request.header("X-NSONE-Key", h),
            Err(_) => request.header("X-NSONE-Key", "\n"),
        }
    }
    fn error(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage,code,message,"Verify the NS1 API key and exact zone/record read/write permissions. Use a primary, unlinked zone and a dedicated static single-answer RRset with one writer. No automatic write retry occurs; inspect uncertain writes before retrying.",reply)
    }
    fn validate_spec(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.token.trim().is_empty() {
            return Err(self.error(
                "validation",
                "MissingApiKey",
                "NS1 requires a nonempty API key.",
                None,
            ));
        }
        if !hostname(&spec.domain)
            || (spec.subdomain != "@" && !hostname(&spec.subdomain))
            || spec.fqdn().len() > 253
            || !matches!(spec.record_type.as_str(), "A" | "AAAA")
            || !(1..=604800).contains(&spec.ttl)
        {
            return Err(self.error("validation","InvalidRecordSpec","Use an exact ASCII/punycode hosted zone, A/AAAA, @ or a relative host and TTL 1..604800. Provider plan limits may be stricter.",None));
        }
        Ok(())
    }
    fn check(&self, stage: &str, reply: &HttpReply, write: bool) -> Result<(), ProviderError> {
        let malformed_error = reply.body.get("error").is_some_and(|v| !v.is_null());
        let message_only = reply.body.get("message").is_some()
            && reply.body.get("zone").is_none()
            && reply.body.get("domain").is_none();
        if !(200..300).contains(&reply.status) || malformed_error || message_only {
            let code = reply
                .body
                .get("code")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("Http{}", reply.status));
            let mut messages = Vec::new();
            for key in ["message", "error", "detail"] {
                if let Some(s) = reply.body.get(key).and_then(Value::as_str) {
                    messages.push(s.to_owned());
                }
            }
            if let Some(errors) = reply.body.get("errors").and_then(Value::as_array) {
                for e in errors.iter().take(16) {
                    if let Some(s) = e
                        .as_str()
                        .or_else(|| e.get("message").and_then(Value::as_str))
                    {
                        messages.push(s.to_owned());
                    }
                }
            }
            if messages.is_empty() {
                messages.push("NS1 returned an unsuccessful or malformed API response; unrecognized response contents omitted.".into());
            }
            let mut e = self.error(stage, &code, &messages.join("; "), Some(reply));
            e.retryable = !write && (reply.status == 429 || reply.status >= 500);
            return Err(e);
        }
        Ok(())
    }
    async fn zone(&self, spec: &Spec) -> Result<String, ProviderError> {
        self.validate_spec(spec)?;
        // records=false requests only exact zone metadata, not a partial record list.
        let reply = self
            .api
            .send(
                "Ns1GetZone",
                self.request(Method::GET, &format!("/zones/{}", spec.domain))
                    .query(&[("records", "false")]),
                false,
            )
            .await?;
        self.check("Ns1GetZone", &reply, false)?;
        if reply.status != 200
            || !reply
                .body
                .get("zone")
                .and_then(Value::as_str)
                .is_some_and(|zone| zone.eq_ignore_ascii_case(&spec.domain))
            || !reply
                .body
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(valid_id)
        {
            return Err(self.error(
                "Ns1GetZone",
                "ZoneMismatch",
                "NS1 did not confirm the exact hosted zone and valid zone ID.",
                Some(&reply),
            ));
        }
        if reply
            .body
            .pointer("/secondary/enabled")
            .and_then(Value::as_bool)
            == Some(true)
        {
            return Err(self.error("validation","SecondaryZone","Secondary zones are transferred from an upstream primary; DDNS will not modify them.",Some(&reply)));
        }
        if present(reply.body.get("link")) || present(reply.body.get("views")) {
            return Err(self.error("validation","LinkedOrSplitHorizonZone","Linked or split-horizon zones need an explicit specialized workflow; default-zone DDNS is refused.",Some(&reply)));
        }
        Ok(reply.body["id"]
            .as_str()
            .expect("zone id validated")
            .to_owned())
    }
    fn path(spec: &Spec) -> String {
        format!(
            "/zones/{}/{}/{}",
            spec.domain,
            spec.fqdn(),
            spec.record_type
        )
    }
    fn record(
        &self,
        spec: &Spec,
        zone_id: &str,
        reply: &HttpReply,
        stage: &str,
    ) -> Result<Record, ProviderError> {
        let b = &reply.body;
        let bad = |field: &str, expected: &str| {
            self.error(stage,"InvalidRecord",&format!("NS1 record field '{field}' is missing, inconsistent or malformed; expected {expected}."),Some(reply))
        };
        if !b
            .get("zone")
            .and_then(Value::as_str)
            .is_some_and(|v| v.eq_ignore_ascii_case(&spec.domain) || v == zone_id)
        {
            return Err(bad("zone", "the confirmed zone name or confirmed zone ID"));
        }
        if b.get("zone_name").is_some_and(|v| {
            !v.is_null()
                && v.as_str()
                    .is_none_or(|name| !name.eq_ignore_ascii_case(&spec.domain))
        }) {
            return Err(bad("zone_name", "the configured zone name when present"));
        }
        if !b
            .get("domain")
            .and_then(Value::as_str)
            .is_some_and(|v| v.trim_end_matches('.').eq_ignore_ascii_case(&spec.fqdn()))
        {
            return Err(bad("domain", "the exact configured FQDN"));
        }
        if b.get("type").and_then(Value::as_str) != Some(spec.record_type.as_str()) {
            return Err(bad("type", "the configured A/AAAA type"));
        }
        let id = b
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .ok_or_else(|| bad("id", "a plain record identifier"))?
            .to_owned();
        let ttl = b
            .get("ttl")
            .and_then(Value::as_u64)
            .filter(|n| (1..=2147483647).contains(n))
            .ok_or_else(|| bad("ttl", "a positive DNS TTL"))?;
        let answers = b
            .get("answers")
            .and_then(Value::as_array)
            .filter(|v| v.len() <= 10000)
            .ok_or_else(|| bad("answers", "a bounded answer array"))?;
        let value = answers
            .first()
            .and_then(|a| a.get("answer"))
            .and_then(Value::as_array)
            .and_then(|v| v.first())
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let enabled = b.pointer("/meta/up").and_then(Value::as_bool) != Some(false)
            && b.pointer("/answers/0/meta/up").and_then(Value::as_bool) != Some(false);
        Ok(Record {
            id,
            name: spec.fqdn(),
            record_type: spec.record_type.clone(),
            value,
            ttl,
            line: String::new(),
            enabled,
            extra: b.clone(),
        })
    }
    fn selection(&self, spec: &Spec, record: &Record) -> Result<(), ProviderError> {
        let bad = |code: &str, msg: &str| self.error("selection", code, msg, None);
        if record.name.trim_end_matches('.') != spec.fqdn()
            || record.record_type != spec.record_type
            || !valid_id(&record.id)
        {
            return Err(bad(
                "RecordIdMismatch",
                "Selected NS1 record does not belong to the configured host/type.",
            ));
        }
        let b = &record.extra;
        let answers = b
            .get("answers")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("InvalidRecord", "Answer metadata is unavailable."))?;
        if answers.len() != 1 {
            return Err(bad(
                "MultiAnswerRRset",
                "NS1 RRset must contain exactly one static answer. Multiple answers will not be discarded; use a dedicated single-IP record.",
            ));
        }
        let answer = &answers[0];
        let values = answer
            .get("answer")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("InvalidRecord", "Malformed NS1 answer."))?;
        if values.len() != 1
            || values[0].as_str().is_none_or(|s| {
                s.parse::<IpAddr>()
                    .ok()
                    .is_none_or(|ip| ip.is_ipv4() != (spec.record_type == "A"))
            })
        {
            return Err(bad(
                "InvalidAnswer",
                "Selected A/AAAA answer must contain one matching-family plain IP address.",
            ));
        }
        if present(b.get("filters")) || present(b.get("regions")) || present(answer.get("region")) {
            return Err(bad(
                "UnsupportedRouting",
                "NS1 filters/regions require specialized traffic-policy handling. DDNS will not rewrite a routed record.",
            ));
        }
        if present(b.get("link")) || present(b.get("feeds")) || present(answer.get("feeds")) {
            return Err(bad(
                "ManagedOrLinkedRecord",
                "Linked records and data-feed managed answers must be updated through their controlling source.",
            ));
        }
        for meta in [b.get("meta"), answer.get("meta")].into_iter().flatten() {
            let fields = meta.as_object().ok_or_else(|| {
                bad(
                    "UnsupportedMetadata",
                    "NS1 metadata must be a static object.",
                )
            })?;
            if fields.values().any(|v| v.is_object() || v.is_array()) {
                return Err(bad(
                    "ManagedMetadata",
                    "Nested metadata may contain data-feed references; use a dedicated static RRset.",
                ));
            }
        }
        if answer.as_object().is_none_or(|m| {
            m.keys()
                .any(|k| !matches!(k.as_str(), "answer" | "meta" | "id" | "region" | "feeds"))
        }) {
            return Err(bad(
                "UnknownAnswerMetadata",
                "Unrecognized answer fields cannot be safely preserved; no write attempted.",
            ));
        }
        if !record.enabled {
            return Err(bad(
                "RecordDisabled",
                "Record/answer metadata marks this record down; DDNS will not re-enable it.",
            ));
        }
        Ok(())
    }
    async fn retrieve(
        &self,
        spec: &Spec,
        zone_id: &str,
    ) -> Result<Option<(Record, HttpReply)>, ProviderError> {
        let reply = self
            .api
            .send(
                "Ns1GetRecord",
                self.request(Method::GET, &Self::path(spec)),
                false,
            )
            .await?;
        // Do not hide 401/403 or arbitrary 404 as 'record absent'. NS1's known
        // missing-record message is distinct from missing/inaccessible zones.
        if reply.status == 404
            && reply
                .body
                .get("message")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case("record not found"))
        {
            return Ok(None);
        }
        self.check("Ns1GetRecord", &reply, false)?;
        if reply.status != 200 {
            return Err(self.error(
                "Ns1GetRecord",
                "UnexpectedStatus",
                "NS1 record retrieval must return HTTP 200.",
                Some(&reply),
            ));
        }
        let record = self.record(spec, zone_id, &reply, "Ns1GetRecord")?;
        Ok(Some((record, reply)))
    }
    fn acknowledgment(
        &self,
        spec: &Spec,
        zone_id: &str,
        ip: &str,
        reply: &HttpReply,
        expected_id: Option<&str>,
    ) -> Result<Mutation, ProviderError> {
        self.check("Ns1WriteRecord", reply, true)?;
        if !matches!(reply.status, 200 | 201) {
            return Err(self.error("Ns1WriteRecord","UncertainAcknowledgement","NS1 did not return a documented record acknowledgement; inspect the write before another attempt.",Some(reply)));
        }
        let record = self.record(spec, zone_id, reply, "Ns1WriteRecord")?;
        self.selection(spec, &record)?;
        if record.value.parse::<IpAddr>().ok() != ip.parse::<IpAddr>().ok()
            || record.ttl != spec.ttl
            || expected_id.is_some_and(|id| id != record.id)
        {
            return Err(self.error("Ns1WriteRecord","UnexpectedAcknowledgement","NS1 acknowledged different record identity, value or TTL; write outcome is uncertain.",Some(reply)));
        }
        Ok(Mutation {
            record_id: record.id,
            request_id: reply.request_id.clone(),
        })
    }
}
impl Adapter for Nsone {
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
        let zone_id = self.zone(spec).await?;
        match self.retrieve(spec, &zone_id).await? {
            Some((record, reply)) => Ok(List {
                records: vec![record],
                request_id: reply.request_id,
            }),
            None => Ok(List {
                records: vec![],
                request_id: None,
            }),
        }
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        if !spec.create_if_missing {
            return Err(self.error(
                "validation",
                "CreationNotEnabled",
                "create_if_missing is false.",
                None,
            ));
        }
        let zone_id = self.zone(spec).await?;
        if self.retrieve(spec, &zone_id).await?.is_some() {
            return Err(self.error(
                "selection",
                "RecordAppeared",
                "RRset appeared after selection; no replacement or write attempted.",
                None,
            ));
        }
        let body = json!({"zone":spec.domain,"domain":spec.fqdn(),"type":spec.record_type,"ttl":spec.ttl,"answers":[{"answer":[ip]}]});
        let reply = self
            .api
            .send(
                "Ns1CreateRecord",
                self.request(Method::PUT, &Self::path(spec)).json(&body),
                true,
            )
            .await?;
        self.acknowledgment(spec, &zone_id, ip, &reply, None)
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.selection(spec, record)?;
        let zone_id = self.zone(spec).await?;
        let (fresh, _) = self.retrieve(spec, &zone_id).await?.ok_or_else(|| {
            self.error(
                "selection",
                "RecordDisappeared",
                "Selected RRset disappeared; no write was attempted.",
                None,
            )
        })?;
        self.selection(spec, &fresh)?;
        if fresh.id != record.id
            || fresh.value != record.value
            || fresh.ttl != record.ttl
            || fresh.extra != record.extra
        {
            return Err(self.error("selection","RecordChanged","NS1 record changed after selection; no write attempted. Use one writer; no atomic conditional update is documented.",None));
        }
        let mut answer = json!({"answer":[ip]});
        if let Some(meta) = fresh.extra.pointer("/answers/0/meta") {
            answer["meta"] = meta.clone();
        }
        // Official SDK update emits only supplied mutable fields; all other
        // record settings are left unchanged. Static answer metadata is copied.
        let body = json!({"zone":spec.domain,"domain":spec.fqdn(),"type":spec.record_type,"ttl":spec.ttl,"answers":[answer]});
        let reply = self
            .api
            .send(
                "Ns1UpdateRecord",
                self.request(Method::POST, &Self::path(spec)).json(&body),
                true,
            )
            .await?;
        self.acknowledgment(spec, &zone_id, ip, &reply, Some(&record.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::{Request, State},
        response::Response,
    };
    use std::sync::{Arc, Mutex};
    struct Mock {
        queue: Mutex<Vec<(u16, Value)>>,
        seen: Mutex<Vec<(String, String, Value, String)>>,
    }
    struct Server {
        url: String,
        state: Arc<Mock>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(State(mock): State<Arc<Mock>>, request: Request) -> Response {
        let method = request.method().to_string();
        let path = request.uri().to_string();
        let key = request
            .headers()
            .get("X-NSONE-Key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
        let data = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        mock.seen.lock().unwrap().push((method, path, data, key));
        let (status, value) = {
            let mut q = mock.queue.lock().unwrap();
            if q.is_empty() {
                (500, json!({"message":"Unexpected mock request"}))
            } else {
                q.remove(0)
            }
        };
        Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .header("X-Request-Id", "ns1-request")
            .body(Body::from(value.to_string()))
            .unwrap()
    }
    async fn server(queue: Vec<(u16, Value)>) -> Server {
        let state = Arc::new(Mock {
            queue: Mutex::new(queue),
            seen: Mutex::new(vec![]),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(handler).with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Server { url, state, task }
    }
    fn provider(s: &Server) -> Nsone {
        let mut p = Nsone::new(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()
                .unwrap(),
            "ns1-test-key".into(),
            &BTreeMap::new(),
        );
        p.endpoint = s.url.clone();
        p
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
        json!({"zone":"example.com","id":"zone-id","secondary":{"enabled":false},"link":null,"views":[]})
    }
    fn record(ip: &str) -> Value {
        json!({"zone":"example.com","domain":"home.example.com","type":"A","id":"record-id","ttl":600,"answers":[{"answer":[ip],"id":"answer-id","meta":{"up":true,"weight":2}}],"meta":{},"filters":[],"regions":{},"feeds":[],"link":null,"local_tags":["keep"]})
    }
    #[tokio::test]
    async fn dry_run_and_unchanged_never_write() {
        for ip in ["1.1.1.1", "8.8.8.8"] {
            let s = server(vec![(200, zone()), (200, record("1.1.1.1"))]).await;
            let result = super::super::common::reconcile(&provider(&s), &spec(), ip, true)
                .await
                .unwrap();
            assert_eq!(
                result.status,
                if ip == "1.1.1.1" {
                    "unchanged"
                } else {
                    "would_update"
                }
            );
            let seen = s.state.seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert!(seen.iter().all(|r| r.0 == "GET"));
            assert_eq!(seen[0].3, "ns1-test-key");
            assert!(seen[0].1.contains("records=false"));
        }
    }
    #[tokio::test]
    async fn multianswer_filters_feeds_regions_are_refused() {
        for kind in ["multi", "filters", "feeds", "regions", "dynamic"] {
            let mut r = record("1.1.1.1");
            match kind {
                "multi" => r["answers"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"answer":["8.8.8.8"]})),
                "filters" => r["filters"] = json!([{"filter":"up"}]),
                "feeds" => r["feeds"] = json!([{"source":"x"}]),
                "regions" => r["regions"] = json!({"us":{}}),
                _ => r["answers"][0]["meta"]["up"] = json!({"feed":"feed-id"}),
            };
            let s = server(vec![(200, zone()), (200, r)]).await;
            assert!(
                super::super::common::reconcile(&provider(&s), &spec(), "8.8.8.8", true)
                    .await
                    .is_err(),
                "{kind}"
            );
            assert_eq!(s.state.seen.lock().unwrap().len(), 2);
        }
    }
    #[tokio::test]
    async fn blocked_zones_never_read_records() {
        for kind in ["secondary", "linked", "views", "mismatch"] {
            let mut z = zone();
            match kind {
                "secondary" => z["secondary"]["enabled"] = json!(true),
                "linked" => z["link"] = json!("other.example"),
                "views" => z["views"] = json!(["private"]),
                _ => z["zone"] = json!("other.example"),
            };
            let s = server(vec![(200, z)]).await;
            assert!(provider(&s).list(&spec()).await.is_err());
            assert_eq!(s.state.seen.lock().unwrap().len(), 1);
        }
    }
    #[tokio::test]
    async fn known_record_absence_is_not_permission_absence() {
        for (status, message, empty) in [
            (404, "record not found", true),
            (404, "zone not found", false),
            (403, "record not found", false),
            (401, "Invalid API key", false),
        ] {
            let s = server(vec![(200, zone()), (status, json!({"message":message}))]).await;
            let result = provider(&s).list(&spec()).await;
            if empty {
                assert!(result.unwrap().records.is_empty());
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[tokio::test]
    async fn missing_id_never_creates() {
        let s = server(vec![(200, zone()), (200, record("1.1.1.1"))]).await;
        let mut c = spec();
        c.record_id = Some("wrong-id".into());
        c.create_if_missing = true;
        assert_eq!(
            super::super::common::reconcile(&provider(&s), &c, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordIdNotFound"
        );
        assert_eq!(s.state.seen.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn create_rechecks_absence_and_acknowledges_id() {
        let missing = json!({"message":"record not found"});
        let s = server(vec![
            (200, zone()),
            (404, missing.clone()),
            (200, zone()),
            (404, missing),
            (201, record("8.8.8.8")),
        ])
        .await;
        let mut c = spec();
        c.create_if_missing = true;
        let result = super::super::common::reconcile(&provider(&s), &c, "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(result.status, "created");
        assert_eq!(result.record_id.as_deref(), Some("record-id"));
        let seen = s.state.seen.lock().unwrap();
        assert_eq!(seen[4].0, "PUT");
        assert_eq!(seen[4].2["answers"][0]["answer"][0], "8.8.8.8");
    }
    #[tokio::test]
    async fn create_race_is_refused() {
        let missing = json!({"message":"record not found"});
        let s = server(vec![
            (200, zone()),
            (404, missing),
            (200, zone()),
            (200, record("1.1.1.1")),
        ])
        .await;
        let mut c = spec();
        c.create_if_missing = true;
        assert_eq!(
            super::super::common::reconcile(&provider(&s), &c, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordAppeared"
        );
        assert!(s.state.seen.lock().unwrap().iter().all(|r| r.0 == "GET"));
    }
    #[tokio::test]
    async fn update_preserves_static_answer_metadata_and_record_settings() {
        let r = record("1.1.1.1");
        let s = server(vec![
            (200, zone()),
            (200, r.clone()),
            (200, zone()),
            (200, r),
            (200, record("8.8.8.8")),
        ])
        .await;
        assert_eq!(
            super::super::common::reconcile(&provider(&s), &spec(), "8.8.8.8", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let seen = s.state.seen.lock().unwrap();
        let body = &seen[4].2;
        assert_eq!(seen[4].0, "POST");
        assert_eq!(body["answers"][0]["meta"], json!({"up":true,"weight":2}));
        assert!(body.get("filters").is_none());
        assert!(body.get("local_tags").is_none());
        assert!(body["answers"][0].get("id").is_none());
    }
    #[tokio::test]
    async fn changed_rrset_is_not_written() {
        let r = record("1.1.1.1");
        let s = server(vec![
            (200, zone()),
            (200, r),
            (200, zone()),
            (200, record("9.9.9.9")),
        ])
        .await;
        assert_eq!(
            super::super::common::reconcile(&provider(&s), &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordChanged"
        );
        assert_eq!(s.state.seen.lock().unwrap().len(), 4);
    }
    #[tokio::test]
    async fn error_details_are_retained_and_key_redacted() {
        let s = server(vec![(
            403,
            json!({"code":"Forbidden","message":"Permission denied for ns1-test-key"}),
        )])
        .await;
        let e = provider(&s).list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "Forbidden");
        assert!(e.message.contains("Permission denied"));
        assert!(!e.message.contains("ns1-test-key"));
        assert_eq!(e.request_id.as_deref(), Some("ns1-request"));
    }
    #[tokio::test]
    async fn disabled_answer_remains_disabled() {
        let mut r = record("1.1.1.1");
        r["answers"][0]["meta"]["up"] = json!(false);
        let s = server(vec![(200, zone()), (200, r)]).await;
        assert!(
            super::super::common::reconcile(&provider(&s), &spec(), "8.8.8.8", false)
                .await
                .is_err()
        );
        assert_eq!(s.state.seen.lock().unwrap().len(), 2);
    }
    #[tokio::test]
    async fn write_ack_mismatch_is_uncertain_and_not_retried() {
        let r = record("1.1.1.1");
        let mut wrong = record("8.8.8.8");
        wrong["id"] = json!("different-id");
        let s = server(vec![
            (200, zone()),
            (200, r.clone()),
            (200, zone()),
            (200, r),
            (200, wrong),
        ])
        .await;
        assert!(
            super::super::common::reconcile(&provider(&s), &spec(), "8.8.8.8", false)
                .await
                .is_err()
        );
        assert_eq!(s.state.seen.lock().unwrap().len(), 5);
    }
    #[tokio::test]
    async fn ipv6_is_compared_semantically() {
        let mut c = spec();
        c.record_type = "AAAA".into();
        let mut r = record("2606:4700:4700:0:0:0:0:1111");
        r["type"] = json!("AAAA");
        let s = server(vec![(200, zone()), (200, r)]).await;
        assert_eq!(
            super::super::common::reconcile(&provider(&s), &c, "2606:4700:4700::1111", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
    }
    #[tokio::test]
    async fn zone_response_identity_must_match_confirmed_proof() {
        for (id, name, valid) in [
            ("zone-id", Some("example.com"), true),
            ("zone-id", None, true),
            ("other-id", Some("example.com"), false),
            ("zone-id", Some("other.example"), false),
        ] {
            let mut r = record("1.1.1.1");
            r["zone"] = json!(id);
            r["zone_name"] = json!(name);
            let s = server(vec![(200, zone()), (200, r)]).await;
            let result = provider(&s).list(&spec()).await;
            assert_eq!(result.is_ok(), valid, "{id} {name:?}");
        }
    }
    #[tokio::test]
    async fn missing_field_diagnostics_name_the_exact_field() {
        let mut r = record("1.1.1.1");
        r.as_object_mut().unwrap().remove("ttl");
        let s = server(vec![(200, zone()), (200, r)]).await;
        let e = provider(&s).list(&spec()).await.unwrap_err();
        assert!(e.message.contains("'ttl'"));
        assert_eq!(e.request_id.as_deref(), Some("ns1-request"));
    }
    #[test]
    fn endpoint_options_and_invalid_names_are_not_used() {
        let mut options = BTreeMap::new();
        options.insert("endpoint".into(), "https://evil.example".into());
        let p = Nsone::new(reqwest::Client::new(), "key".into(), &options);
        assert_eq!(p.endpoint(), ENDPOINT);
        let mut s = spec();
        s.domain = "evil.example/path".into();
        assert!(p.validate_spec(&s).is_err());
    }
}
