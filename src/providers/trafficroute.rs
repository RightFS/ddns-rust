//! Volcengine TrafficRoute public authoritative DNS, NOT Tencent/DNSPod, GTM,
//! PrivateZone, HTTPDNS or recursive PublicDNS. Fixed dns.volcengineapi.com.
//! Official contracts (2018-08-01):
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/update-record
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/query-zone
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/list-records
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/list-record-sets
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/query-record
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/create-record
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/list-lines
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/edit-ions
//! https://docs.volcengine.com/docs/traffic-route-dns-suite/use-volcano-engine-go-sdk
//! Host is explicitly relative (@ apex); FQDN/PQDN are NOT reliable FQDNs.
//! UpdateRecord documents omission preservation for Type/Remark/Weight/TTL.
//! Only singleton A/AAAA, non-weighted RRsets, native standard lines supported.
//! One exclusive writer required: no documented CAS. Never retry a mutation.
//! Supplied client must disable redirects. Test endpoint override is cfg(test) only.
#![allow(clippy::result_large_err)]
use super::common::{
    Adapter, Api, HttpReply, List, Mutation, NameFormat, Record, Spec, valid_id, valid_trace_id,
};
use crate::provider::ProviderError;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
const HOST: &str = "dns.volcengineapi.com";
const ENDPOINT: &str = "https://dns.volcengineapi.com/";
const VERSION: &str = "2018-08-01";
const REGION: &str = "cn-beijing";
const PAGE: usize = 100;
const CAP: usize = 10_000;
const HINT: &str = "Use Volcengine AccessKeyID/SecretAccessKey authorized for DNS ListZones, QueryZone, ListRecords, ListRecordSets, ListLines and QueryRecord on the exact existing public zone; UpdateRecord for writes and optionally CreateRecord. Not Tencent/DNSPod credentials or GTM/PrivateZone APIs. Require an exclusive writer; inspect uncertain/pending writes before a manual retry.";
pub struct TrafficRoute {
    api: Api,
    id: String,
    key: String,
    zid: u64,
    configuration_error: Option<ProviderError>,
    #[cfg(test)]
    endpoint: String,
}
fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().filter(|n| *n <= i64::MAX as u64)
}
pub fn validate_options(options: &BTreeMap<String, String>) -> Result<(), ProviderError> {
    let fail =
        |code, message| super::common::local_error("configuration", code, message, HINT, None);
    if options.get("scope").map(String::as_str) != Some("public_dns") {
        return Err(fail(
            "InvalidScope",
            "Set scope=public_dns explicitly; TrafficRoute GTM, private/recursive/mobile DNS are different products.",
        ));
    }
    if options.get("api_version").map(String::as_str) != Some(VERSION) {
        return Err(fail(
            "InvalidApiVersion",
            "Set api_version=2018-08-01; API version fallback is forbidden.",
        ));
    }
    if options.get("region").map(String::as_str) != Some(REGION) {
        return Err(fail(
            "InvalidRegion",
            "Set region=cn-beijing, the current official DNS SDK signing region; arbitrary regions are unsupported.",
        ));
    }
    if !options.get("zone_id").is_some_and(|s| decimal(s).is_some()) {
        return Err(fail(
            "InvalidZoneId",
            "Explicit positive decimal zone_id (Volcengine ZID) is required.",
        ));
    }
    if options
        .keys()
        .any(|s| !matches!(s.as_str(), "scope" | "api_version" | "region" | "zone_id"))
    {
        return Err(fail(
            "UnsupportedOptions",
            "Unknown provider options, endpoint overrides and traffic controls are unsupported.",
        ));
    }
    Ok(())
}
fn same(a: &str, b: &str) -> bool {
    a.strip_suffix('.')
        .unwrap_or(a)
        .eq_ignore_ascii_case(b.strip_suffix('.').unwrap_or(b))
}
fn dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.is_ascii()
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'*'))
        })
}
fn within(a: &str, b: &str) -> bool {
    same(a, b)
        || a.to_ascii_lowercase()
            .ends_with(&format!(".{}", b.to_ascii_lowercase()))
}
fn line(s: &Spec) -> &str {
    if matches!(s.record_line.as_str(), "" | "默认" | "default") {
        "default"
    } else {
        &s.record_line
    }
}
fn owner(host: &str, domain: &str) -> String {
    if host == "@" {
        domain.into()
    } else {
        format!("{host}.{domain}")
    }
}
fn opaque(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 1024
        && s.is_ascii()
        && !s
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
}
fn hmac(key: &[u8], input: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts all key lengths");
    m.update(input);
    m.finalize().into_bytes().to_vec()
}
// Query values originate from allowlisted actions, version and validated decimal IDs.
// BTreeMap supplies canonical lexicographic order. Sign exactly the bytes sent.
fn authorization(
    id: &str,
    key: &str,
    method: &str,
    query: &str,
    body: &[u8],
    date: &str,
) -> (String, String, Vec<String>) {
    let digest = hex::encode(Sha256::digest(body));
    let headers = format!("host:{HOST}\nx-content-sha256:{digest}\nx-date:{date}\n");
    let signed = "host;x-content-sha256;x-date";
    let canonical = format!("{method}\n/\n{query}\n{headers}\n{signed}\n{digest}");
    let scope = format!("{}/{REGION}/dns/request", &date[..8]);
    let to_sign = format!(
        "HMAC-SHA256\n{date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let kd = hmac(key.as_bytes(), &date.as_bytes()[..8]);
    let kr = hmac(&kd, REGION.as_bytes());
    let ks = hmac(&kr, b"dns");
    let signing = hmac(&ks, b"request");
    let signature = hex::encode(hmac(&signing, to_sign.as_bytes()));
    (
        format!(
            "HMAC-SHA256 Credential={id}/{scope}, SignedHeaders={signed}, Signature={signature}"
        ),
        digest,
        vec![
            signature,
            hex::encode(kd),
            hex::encode(kr),
            hex::encode(ks),
            hex::encode(signing),
        ],
    )
}
impl TrafficRoute {
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
            zid: options.get("zone_id").and_then(|s| decimal(s)).unwrap_or(0),
            configuration_error: validate_options(options).err(),
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
    fn fail(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage, code, message, HINT, reply)
    }
    fn bad(&self, action: &str, message: &str, reply: &HttpReply) -> ProviderError {
        self.fail(action, "MalformedResponse", message, Some(reply))
    }
    fn validate(&self, s: &Spec) -> Result<(), ProviderError> {
        if let Some(e) = &self.configuration_error {
            return Err(e.clone());
        }
        if self.id.is_empty()
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || self.key.is_empty()
        {
            return Err(self.fail(
                "credentials",
                "InvalidCredentials",
                "Missing or invalid Volcengine AccessKeyID/SecretAccessKey.",
                None,
            ));
        }
        if !s.options.is_empty() {
            return Err(self.fail(
                "validation",
                "UnsupportedOptions",
                "Record-level traffic, routing, proxy, backup or health options are unsupported.",
                None,
            ));
        }
        if !matches!(s.record_type.as_str(), "A" | "AAAA")
            || !dns_name(&s.domain)
            || !dns_name(&s.fqdn())
            || s.fqdn().contains('*')
        {
            return Err(self.fail(
                "validation",
                "UnsupportedTarget",
                "Only literal non-wildcard ASCII/punycode A/AAAA names are supported.",
                None,
            ));
        }
        if !(1..=86400).contains(&s.ttl) {
            return Err(self.fail(
                "validation",
                "InvalidTtl",
                "TTL must be 1..86400; the actual zone edition minimum is checked on read.",
                None,
            ));
        }
        if s.record_id
            .as_ref()
            .is_some_and(|id| decimal(id).is_none() || !valid_id(id))
        {
            return Err(self.fail("validation","InvalidRecordId","RecordID must be a stable positive decimal string, not a base64 RecordSetID or compound import ID.",None));
        }
        if !valid_id(line(s)) {
            return Err(self.fail(
                "validation",
                "InvalidLine",
                "Use an exact standard DNS line Value; default aliases are local to TrafficRoute.",
                None,
            ));
        }
        Ok(())
    }
    async fn call(
        &self,
        action: &str,
        params: Value,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        if !matches!(
            action,
            "ListZones"
                | "QueryZone"
                | "ListRecords"
                | "ListRecordSets"
                | "ListLines"
                | "QueryRecord"
                | "CreateRecord"
                | "UpdateRecord"
        ) {
            return Err(self.fail(
                "validation",
                "InvalidAction",
                "Action is outside the public DNS allowlist.",
                None,
            ));
        }
        let mut query = BTreeMap::from([
            ("Action".to_owned(), action.to_owned()),
            ("Version".to_owned(), VERSION.to_owned()),
        ]);
        let body = if write {
            serde_json::to_vec(&params).expect("Value serializes")
        } else {
            for (k, v) in params.as_object().expect("internal object") {
                let v = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => {
                        return Err(self.fail(
                            "validation",
                            "InvalidQuery",
                            "Invalid internal query value.",
                            None,
                        ));
                    }
                };
                if !v
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
                {
                    return Err(self.fail(
                        "validation",
                        "InvalidQuery",
                        "Noncanonical internal query value.",
                        None,
                    ));
                }
                query.insert(k.clone(), v);
            }
            Vec::new()
        };
        let query = query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let (auth, digest, mut secrets) = authorization(
            &self.id,
            &self.key,
            if write { "POST" } else { "GET" },
            &query,
            &body,
            &date,
        );
        secrets.extend([self.id.clone(), self.key.clone(), auth.clone()]);
        let api = Api::new(self.api.client.clone(), secrets);
        let url = format!("{}?{query}", self.endpoint());
        let request = if write {
            api.client
                .post(url)
                .header("content-type", "application/json; charset=utf-8")
                .body(body)
        } else {
            api.client.get(url)
        };
        let request = request
            .header("host", HOST)
            .header("x-date", date)
            .header("x-content-sha256", digest)
            .header("authorization", auth);
        let mut reply = api.send(action, request, write).await?;
        reply.request_id = reply
            .body
            .pointer("/ResponseMetadata/RequestId")
            .and_then(Value::as_str)
            .map(|s| api.safe(s))
            .filter(|s| valid_trace_id(s));
        let meta = reply
            .body
            .get("ResponseMetadata")
            .filter(|v| v.is_object())
            .ok_or_else(|| {
                api.error(
                    action,
                    "MalformedResponse",
                    "Missing ResponseMetadata; any write outcome is uncertain.",
                    HINT,
                    Some(&reply),
                )
            })?;
        if let Some(error) = meta.get("Error") {
            if let (Some(code), Some(message)) = (
                error
                    .get("Code")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty()),
                error.get("Message").and_then(Value::as_str),
            ) {
                return Err(api.error(
                    action,
                    code,
                    &format!(
                        "{message}{}",
                        if write {
                            " Write not acknowledged; no retry occurred."
                        } else {
                            ""
                        }
                    ),
                    HINT,
                    Some(&reply),
                ));
            }
            return Err(api.error(
                action,
                "MalformedResponse",
                "Malformed business error; never interpreted as success.",
                HINT,
                Some(&reply),
            ));
        }
        api.check_http(action, &reply)?;
        if reply.request_id.is_none()
            || meta.get("Action").and_then(Value::as_str) != Some(action)
            || meta.get("Version").and_then(Value::as_str) != Some(VERSION)
            || meta.get("Service").and_then(Value::as_str) != Some("dns")
            || !meta
                .get("Region")
                .and_then(Value::as_str)
                .is_some_and(|r| matches!(r, "cn-beijing" | "cn-north-1"))
            || !reply.body.get("Result").is_some_and(Value::is_object)
        {
            return Err(api.error(action,"MalformedResponse","Missing or mismatched action/version/service/region/RequestId/Result; no success acknowledgement established.",HINT,Some(&reply)));
        }
        Ok(reply)
    }
    async fn pages(
        &self,
        action: &str,
        array: &str,
        count_field: &str,
        id_field: &str,
        mut params: Value,
    ) -> Result<(Vec<Value>, Option<String>), ProviderError> {
        let mut items = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        for page in 1..=CAP / PAGE {
            params["PageNumber"] = json!(page);
            params["PageSize"] = json!(PAGE);
            let reply = self.call(action, params.clone(), false).await?;
            let result = &reply.body["Result"];
            let count = result
                .get(count_field)
                .and_then(Value::as_u64)
                .filter(|n| *n <= CAP as u64)
                .ok_or_else(|| self.bad(action, "Missing explicit bounded total count", &reply))?
                as usize;
            let values = result.get(array).and_then(Value::as_array).ok_or_else(|| {
                self.bad(
                    action,
                    "Missing explicit list array; not assumed empty",
                    &reply,
                )
            })?;
            if total.is_some_and(|n| n != count)
                || values.len() > PAGE
                || items.len() + values.len() > count
                || (action != "ListZones"
                    && (result.get("PageNumber").and_then(Value::as_u64) != Some(page as u64)
                        || result.get("PageSize").and_then(Value::as_u64) != Some(PAGE as u64)))
            {
                return Err(self.bad(
                    action,
                    "Contradictory or changed pagination metadata",
                    &reply,
                ));
            }
            total = Some(count);
            for item in values {
                let id = if action == "ListZones" {
                    item.get(id_field)
                        .and_then(Value::as_u64)
                        .filter(|n| *n > 0 && *n <= i64::MAX as u64)
                        .map(|n| n.to_string())
                } else {
                    item.get(id_field)
                        .and_then(Value::as_str)
                        .filter(|s| opaque(s))
                        .map(str::to_owned)
                }
                .ok_or_else(|| self.bad(action, "Missing stable list identity", &reply))?;
                if !ids.insert(id) {
                    return Err(self.bad(
                        action,
                        "Duplicate identity across full pagination",
                        &reply,
                    ));
                }
                items.push(item.clone());
            }
            if items.len() == count {
                return Ok((items, reply.request_id));
            }
            if values.len() != PAGE {
                return Err(self.bad(
                    action,
                    "Truncated page before explicit total count reached",
                    &reply,
                ));
            }
        }
        Err(self.fail(
            action,
            "PaginationLimit",
            "Complete snapshot exceeds 10,000 item/page cap.",
            None,
        ))
    }
    async fn zone(&self, s: &Spec) -> Result<(), ProviderError> {
        let (zones, trace) = self
            .pages("ListZones", "Zones", "Total", "ZID", json!({}))
            .await?;
        let matches = zones
            .iter()
            .filter(|z| z.get("ZID").and_then(Value::as_u64) == Some(self.zid))
            .collect::<Vec<_>>();
        if matches.len() != 1
            || !matches[0]
                .get("ZoneName")
                .and_then(Value::as_str)
                .is_some_and(|n| same(n, &s.domain))
        {
            let mut e=self.fail("ListZones","ZoneMismatch","Exact ZID/domain not found uniquely in owned account inventory; no zone creation/fallback.",None);
            e.request_id = trace;
            return Err(e);
        }
        let reply = self
            .call("QueryZone", json!({"ZID":self.zid}), false)
            .await?;
        let z = &reply.body["Result"];
        if !z
            .get("ZoneName")
            .and_then(Value::as_str)
            .is_some_and(|n| same(n, &s.domain))
            || z.get("Stage").and_then(Value::as_u64) != Some(0)
            || z.get("IsNSCorrect").and_then(Value::as_bool) != Some(true)
            || z.get("IsSubDomain").and_then(Value::as_bool) != Some(false)
        {
            return Err(self.fail("QueryZone","ZoneUnavailable","Exact public zone must have Stage=0, correct allocated NS and be a main domain; pending recovery, wrong NS and delegated hosted-subdomain modes are refused.",Some(&reply)));
        }
        let (min, levels) = match z.get("TradeCode").and_then(Value::as_str) {
            Some("free_inner") => (600, 5),
            Some("professional_inner") => (300, 20),
            Some("enterprise_inner") => (60, 20),
            Some("ultimate_inner") => (1, 20),
            Some("ultimate_exclusive_inner") => (1, usize::MAX),
            _ => {
                return Err(self.bad(
                    "QueryZone",
                    "Unknown edition; TTL/host limits cannot be proved",
                    &reply,
                ));
            }
        };
        if s.ttl < min
            || (!matches!(s.subdomain.as_str(), "" | "@")
                && s.subdomain.split('.').count() > levels)
        {
            return Err(self.fail("validation","EditionLimit","Desired TTL or host depth is outside the observed zone edition's documented limits.",Some(&reply)));
        }
        Ok(())
    }
    fn parse(&self, raw: Value, s: &Spec) -> Result<Record, ProviderError> {
        let err = || {
            self.fail(
                "ListRecords",
                "MalformedResponse",
                "Incomplete or invalid DNS record identity/Host/Type/Value/TTL/Line/Enable.",
                None,
            )
        };
        let text = |key| raw.get(key).and_then(Value::as_str).ok_or_else(err);
        let id = text("RecordID")?.to_owned();
        let host = text("Host")?.to_owned();
        let kind = text("Type")?.to_owned();
        let value = text("Value")?.to_owned();
        let location = text("Line")?.to_owned();
        if decimal(&id).is_none()
            || !valid_id(&id)
            || !(host == "@" || dns_name(&host))
            || !dns_name(&owner(&host, &s.domain))
            || kind.is_empty()
            || location.is_empty()
        {
            return Err(err());
        }
        let ttl = raw
            .get("TTL")
            .and_then(Value::as_u64)
            .filter(|n| (1..=86400).contains(n))
            .ok_or_else(err)?;
        let enabled = raw.get("Enable").and_then(Value::as_bool).ok_or_else(err)?;
        Ok(Record {
            id,
            name: host,
            record_type: kind,
            value,
            ttl,
            line: if location == line(s) {
                s.record_line.clone()
            } else {
                location
            },
            enabled,
            extra: json!({"record":raw}),
        })
    }
    fn raw_controls(&self, r: &Record) -> Result<(), ProviderError> {
        let raw = &r.extra["record"];
        if raw.as_object().is_none_or(|o| {
            o.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "RecordID"
                        | "FQDN"
                        | "PQDN"
                        | "Host"
                        | "Type"
                        | "TTL"
                        | "Line"
                        | "Value"
                        | "Weight"
                        | "RecordSetID"
                        | "Enable"
                        | "Tags"
                        | "Remark"
                        | "CreatedAt"
                        | "UpdatedAt"
                        | "Operators"
                )
            })
        }) {
            return Err(self.fail(
                "selection",
                "UnsupportedControlFields",
                "Unknown record controls cannot be safely classified before no-op/plan/write.",
                None,
            ));
        }
        // Missing Tags is unknown GTM ownership, not an invented empty field.
        if !raw
            .get("Tags")
            .and_then(Value::as_array)
            .is_some_and(|a| a.is_empty())
        {
            return Err(self.fail("selection","ManagedTraffic","Nonempty or missing Tags (including GTMLock) prevents ordinary DNS-only ownership proof.",None));
        }
        Ok(())
    }
    fn controls(&self, r: &Record) -> Result<(), ProviderError> {
        self.raw_controls(r)?;
        let raw = &r.extra["record"];
        if !raw
            .get("Weight")
            .and_then(Value::as_u64)
            .is_some_and(|w| (1..=100).contains(&w))
        {
            return Err(self.fail(
                "selection",
                "InvalidWeight",
                "Actual positive documented Weight required; never fabricate or enable traffic.",
                None,
            ));
        }
        let set = &r.extra["set"];
        if set.as_object().is_none_or(|o| {
            o.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "ID" | "FQDN" | "PQDN" | "Host" | "Type" | "Line" | "WeightEnabled"
                )
            })
        }) || set.get("WeightEnabled").and_then(Value::as_bool) != Some(false)
        {
            return Err(self.fail("selection","UnsupportedRecordSet","Only observed non-weighted singleton RRsets; unknown routing fields or load balancing refused.",None));
        }
        Ok(())
    }
    async fn target(&self, s: &Spec, id: &str) -> Result<Record, ProviderError> {
        let reply = self
            .call("QueryRecord", json!({"RecordID":id}), false)
            .await?;
        self.parse(reply.body["Result"].clone(), s)
            .map_err(|mut e| {
                e.request_id = reply.request_id.clone();
                e.http_status = Some(reply.status);
                e
            })
    }
    async fn verify(
        &self,
        s: &Spec,
        id: &str,
        ip: &str,
        before: Option<&Record>,
        ack: &HttpReply,
    ) -> Result<Mutation, ProviderError> {
        let uncertain =
            |message: &str| self.fail("verification", "WriteOutcomeUncertain", message, Some(ack));
        let list=self.list(s).await.map_err(|e|uncertain(&format!("Acknowledged write has pending/uncertain post-read: {} [{}] {} (HTTP {:?}, RequestId {:?}); no retry.",e.stage,e.code,e.message,e.http_status,e.request_id)))?;
        let current = list
            .records
            .iter()
            .find(|r| r.id == id)
            .ok_or_else(|| uncertain("Acknowledged ID absent in full post-read; no retry."))?;
        self.validate_selection(s, Some(current))
            .map_err(|e| uncertain(&e.message))?;
        let target = self.target(s, id).await.map_err(|e| {
            uncertain(&format!(
                "Post-write target read failed: {} [{}] {} (HTTP {:?}, RequestId {:?}); no retry.",
                e.stage, e.code, e.message, e.http_status, e.request_id
            ))
        })?;
        if target.extra["record"] != current.extra["record"]
            || !NameFormat::Relative.matches(&current.name, s)
            || current.record_type != s.record_type
            || current.value.parse::<IpAddr>().ok() != ip.parse::<IpAddr>().ok()
            || current.ttl != s.ttl
            || !current.enabled
        {
            return Err(uncertain(
                "Write acknowledged but desired ID/Host/Type/Value/TTL/status or target/full-snapshot consistency is unproved; pending/uncertain, no retry.",
            ));
        }
        if let Some(before) = before {
            let mut prior = before.extra.clone();
            let mut after = current.extra.clone();
            for v in [&mut prior, &mut after] {
                if let Some(o) = v["record"].as_object_mut() {
                    for k in ["Value", "TTL", "UpdatedAt", "Operators"] {
                        o.remove(k);
                    }
                }
            }
            if prior != after {
                return Err(uncertain(
                    "Post-read changed an unmodified control/identity field; no retry.",
                ));
            }
        } else if current.extra["record"]["Line"] != json!(line(s))
            || current.extra["record"]["Weight"] != json!(1)
        {
            return Err(uncertain(
                "Created line/weight differs from explicit ordinary singleton DNS request; no retry.",
            ));
        }
        Ok(Mutation {
            record_id: id.into(),
            request_id: ack.request_id.clone(),
        })
    }
}
impl Adapter for TrafficRoute {
    fn name_format(&self) -> NameFormat {
        NameFormat::Relative
    }
    fn validate_selection(&self, s: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.validate(s)?;
        if let Some(r) = r {
            self.controls(r)?;
            if r.extra["record"].get("Line").and_then(Value::as_str) != Some(line(s)) {
                return Err(self.fail(
                    "selection",
                    "RecordLineMismatch",
                    "Explicit RecordID is not on the exact configured line.",
                    None,
                ));
            }
        }
        Ok(())
    }
    async fn list(&self, s: &Spec) -> Result<List, ProviderError> {
        self.validate(s)?;
        self.zone(s).await?;
        let (lines, trace) = self
            .pages(
                "ListLines",
                "Lines",
                "TotalCount",
                "ID",
                json!({"ZID":self.zid,"Hierarchy":"false"}),
            )
            .await?;
        if lines
            .iter()
            .filter(|l| l.get("Value").and_then(Value::as_str) == Some(line(s)))
            .count()
            != 1
        {
            let mut e=self.fail("ListLines","UnsupportedLine","Exact configured standard line not uniquely available to this ZID/edition; custom lines/group expansion unsupported.",None);
            e.request_id = trace;
            return Err(e);
        }
        let (sets, set_trace) = self
            .pages(
                "ListRecordSets",
                "RecordSets",
                "TotalCount",
                "ID",
                json!({"ZID":self.zid}),
            )
            .await?;
        for set in &sets {
            if !set
                .get("Host")
                .and_then(Value::as_str)
                .is_some_and(|h| h == "@" || dns_name(h))
                || !set
                    .get("Type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| matches!(t, "A" | "AAAA" | "CNAME"))
                || !set
                    .get("Line")
                    .and_then(Value::as_str)
                    .is_some_and(|l| !l.is_empty())
                || set.get("WeightEnabled").and_then(Value::as_bool).is_none()
            {
                let mut e=self.fail("ListRecordSets","MalformedResponse","Incomplete RRset owner/type/line/routing inventory cannot establish target absence.",None);
                e.request_id = set_trace.clone();
                return Err(e);
            }
        }
        let (values, trace) = self
            .pages(
                "ListRecords",
                "Records",
                "TotalCount",
                "RecordID",
                json!({"ZID":self.zid,"SearchOrder":"asc"}),
            )
            .await?;
        let mut records = Vec::new();
        for value in values {
            let mut r = self.parse(value, s).map_err(|mut e| {
                e.request_id = trace.clone();
                e
            })?;
            let name = owner(&r.name, &s.domain);
            if NameFormat::Relative.matches(&r.name, s) {
                self.raw_controls(&r).map_err(|mut e| {
                    e.request_id = trace.clone();
                    e
                })?;
            }
            if (r.record_type == "CNAME"
                && (same(&name, &s.fqdn())
                    || name
                        .strip_prefix("*.")
                        .is_some_and(|n| within(&s.fqdn(), n))))
                || (r.record_type == "NS" && r.name != "@" && within(&s.fqdn(), &name))
            {
                let mut e=self.fail("selection","DnsConflict","CNAME or delegated child NS conflict (including disabled records) blocks plans and writes.",None);
                e.request_id = trace.clone();
                return Err(e);
            }
            if NameFormat::Relative.matches(&r.name, s) && r.record_type == s.record_type {
                let id = r.extra["record"]
                    .get("RecordSetID")
                    .and_then(Value::as_str)
                    .filter(|id| opaque(id))
                    .ok_or_else(|| {
                        self.fail(
                            "selection",
                            "MissingRecordSet",
                            "Target A/AAAA lacks an actual stable RecordSetID.",
                            None,
                        )
                    })?;
                let matching = sets
                    .iter()
                    .filter(|set| set.get("ID").and_then(Value::as_str) == Some(id))
                    .collect::<Vec<_>>();
                if matching.len() != 1
                    || matching[0].get("Host") != r.extra["record"].get("Host")
                    || matching[0].get("Type") != r.extra["record"].get("Type")
                    || matching[0].get("Line") != r.extra["record"].get("Line")
                {
                    let mut e = self.fail(
                        "selection",
                        "RecordSetMismatch",
                        "Target RRset identity not uniquely consistent with full zone snapshot.",
                        None,
                    );
                    e.request_id = set_trace.clone();
                    return Err(e);
                }
                r.extra["set"] = matching[0].clone();
                self.controls(&r).map_err(|mut e| {
                    e.request_id = trace.clone();
                    e
                })?;
            }
            records.push(r);
        }
        let targets = records
            .iter()
            .filter(|r| NameFormat::Relative.matches(&r.name, s) && r.record_type == s.record_type)
            .count();
        let target_sets = sets
            .iter()
            .filter(|set| {
                set.get("Host")
                    .and_then(Value::as_str)
                    .is_some_and(|h| NameFormat::Relative.matches(h, s))
                    && set.get("Type").and_then(Value::as_str) == Some(&s.record_type)
            })
            .count();
        if targets > 1 || target_sets != targets {
            let mut e=self.fail("selection","UnsupportedRecordSet","Only one target record and one corresponding RRset across all lines; multi-record/stranded/complex sets are refused even with explicit ID.",None);
            e.request_id = trace.clone();
            return Err(e);
        }
        if s.create_if_missing
            && records.iter().any(|r| {
                NameFormat::Relative.matches(&r.name, s)
                    && r.record_type == s.record_type
                    && r.extra["record"].get("Line").and_then(Value::as_str) != Some(line(s))
            })
        {
            let mut e=self.fail("selection","CreationRefused","Target exists on another line; absence-based policy extension is refused before planning.",None);
            e.request_id = trace.clone();
            return Err(e);
        }
        Ok(List {
            records,
            request_id: trace,
        })
    }
    async fn create(&self, s: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate(s)?;
        if !ip
            .parse::<IpAddr>()
            .is_ok_and(|v| v.is_ipv4() == (s.record_type == "A"))
        {
            return Err(self.fail(
                "validation",
                "InvalidIp",
                "A/AAAA value must be a single literal IP of matching family.",
                None,
            ));
        }
        if !s.create_if_missing || s.record_id.is_some() {
            return Err(self.fail(
                "create",
                "CreationRefused",
                "Requires explicit create_if_missing=true and no explicit RecordID.",
                None,
            ));
        }
        let list = self.list(s).await?;
        if list
            .records
            .iter()
            .any(|r| NameFormat::Relative.matches(&r.name, s) && r.record_type == s.record_type)
        {
            return Err(self.fail(
                "create",
                "ConcurrentRecord",
                "Fresh full snapshot found target; do not extend an RRset or traffic policy.",
                None,
            ));
        }
        let host = if matches!(s.subdomain.as_str(), "" | "@") {
            "@"
        } else {
            &s.subdomain
        };
        let ack=self.call("CreateRecord",json!({"ZID":self.zid,"Host":host,"Type":s.record_type,"Value":ip,"TTL":s.ttl,"Line":line(s),"Weight":1}),true).await?;
        let id = ack.body["Result"]
            .get("RecordID")
            .and_then(Value::as_str)
            .filter(|id| decimal(id).is_some() && valid_id(id))
            .ok_or_else(|| {
                self.bad(
                    "CreateRecord",
                    "Missing valid RecordID acknowledgement; uncertain, no retry",
                    &ack,
                )
            })?;
        self.verify(s, id, ip, None, &ack).await
    }
    async fn update(&self, s: &Spec, r: &Record, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate(s)?;
        if !ip
            .parse::<IpAddr>()
            .is_ok_and(|v| v.is_ipv4() == (s.record_type == "A"))
        {
            return Err(self.fail(
                "validation",
                "InvalidIp",
                "A/AAAA value must be a single literal IP of matching family.",
                None,
            ));
        }
        let list = self.list(s).await?;
        let current = list.records.iter().find(|v| v.id == r.id).ok_or_else(|| {
            self.fail(
                "update",
                "ConcurrentRecord",
                "Selected ID disappeared; no creation fallback.",
                None,
            )
        })?;
        self.validate_selection(s, Some(current))?;
        if current.extra != r.extra
            || !current.enabled
            || !NameFormat::Relative.matches(&current.name, s)
            || current.record_type != s.record_type
            || s.record_id.as_ref().is_some_and(|id| id != &r.id)
        {
            return Err(self.fail(
                "update",
                "ConcurrentRecord",
                "Fresh identity/status/control snapshot changed; no mutation.",
                None,
            ));
        }
        let target = self.target(s, &r.id).await?;
        if target.extra["record"] != current.extra["record"] {
            return Err(self.fail(
                "update",
                "ConcurrentRecord",
                "Target read disagrees with fresh full snapshot; no mutation.",
                None,
            ));
        }
        // Official UpdateRecord: omitted Type/Remark/Weight do not change.
        // Enable/Tags/RecordSetID are output-only; never echo an unsafe full DTO.
        let ack=self.call("UpdateRecord",json!({"RecordID":r.id,"Host":current.extra["record"]["Host"],"Line":current.extra["record"]["Line"],"Value":ip,"TTL":s.ttl}),true).await?;
        if ack.body["Result"].get("RecordID").and_then(Value::as_str) != Some(&r.id) {
            return Err(self.bad(
                "UpdateRecord",
                "Missing or different RecordID acknowledgement; uncertain, no retry",
                &ack,
            ));
        }
        self.verify(s, &r.id, ip, Some(current), &ack).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::reconcile;
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, Method, StatusCode, Uri},
        routing::get,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    type Request = (String, Value, Method);
    #[derive(Clone)]
    struct Data {
        replies: Arc<Mutex<VecDeque<(u16, Value)>>>,
        requests: Arc<Mutex<Vec<Request>>>,
    }
    struct Mock {
        provider: TrafficRoute,
        data: Data,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    fn options() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("scope".into(), "public_dns".into()),
            ("api_version".into(), VERSION.into()),
            ("region".into(), REGION.into()),
            ("zone_id".into(), "1234".into()),
        ])
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
    async fn handler(
        State(data): State<Data>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        bytes: Bytes,
    ) -> (StatusCode, axum::Json<Value>) {
        assert_eq!(uri.path(), "/");
        assert_eq!(headers["host"], HOST);
        let query = uri.query().unwrap();
        let params = query
            .split('&')
            .map(|p| p.split_once('=').unwrap())
            .collect::<BTreeMap<_, _>>();
        let action = params["Action"].to_string();
        assert_eq!(params["Version"], VERSION);
        let (auth, _, keys) = authorization(
            "AKTestOnly",
            "test-only-secret",
            method.as_str(),
            query,
            &bytes,
            headers["x-date"].to_str().unwrap(),
        );
        assert_eq!(headers["authorization"], auth);
        let payload = if method == Method::POST {
            serde_json::from_slice(&bytes).unwrap()
        } else {
            json!(params)
        };
        data.requests
            .lock()
            .unwrap()
            .push((action.clone(), payload, method));
        let (status, mut value) = data
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected API call/write retry");
        if value == json!("echo-auth") {
            value = json!({"ResponseMetadata":{"RequestId":keys[0],"Error":{"Code":"AuthFailure","Message":format!("Bad signature {} {} test-only-secret AKTestOnly",keys[0],keys[1])}}});
        } else if value.get("ResponseMetadata").is_none() {
            value = json!({"ResponseMetadata":{"RequestId":"trace-test","Action":action,"Version":VERSION,"Service":"dns","Region":REGION},"Result":value});
        }
        (StatusCode::from_u16(status).unwrap(), axum::Json(value))
    }
    async fn mock(replies: Vec<(u16, Value)>) -> Mock {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let data = Data {
            replies: Arc::new(Mutex::new(replies.into())),
            requests: Arc::default(),
        };
        let app = Router::new()
            .route("/", get(handler).post(handler))
            .with_state(data.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut provider = TrafficRoute::new(
            client,
            "AKTestOnly".into(),
            "test-only-secret".into(),
            &options(),
        );
        provider.endpoint = endpoint;
        Mock {
            provider,
            data,
            task,
        }
    }
    fn ok(v: Value) -> (u16, Value) {
        (200, v)
    }
    fn page(array: &str, count: usize, values: Vec<Value>) -> (u16, Value) {
        ok(json!({"PageNumber":1,"PageSize":PAGE,"TotalCount":count,array:values}))
    }
    fn record(id: u64) -> Value {
        json!({"RecordID":id.to_string(),"Host":"home","Type":"A","Value":"192.0.2.1","TTL":600,"Line":"default","Enable":true,"Weight":37,"RecordSetID":"base64-set=","Tags":[],"Remark":"keep me","CreatedAt":"2024-01-01","UpdatedAt":"2024-01-01","Operators":["actor"]})
    }
    fn set() -> Value {
        json!({"ID":"base64-set=","Host":"home","Type":"A","Line":"default","WeightEnabled":false})
    }
    fn zone() -> Value {
        json!({"ZoneName":"example.com","Stage":0,"IsNSCorrect":true,"IsSubDomain":false,"TradeCode":"free_inner","InstanceNo":null,"ExpiredTime":null})
    }
    fn snapshot(records: Vec<Value>) -> Vec<(u16, Value)> {
        let sets = if records
            .iter()
            .any(|r| r["Host"] == "home" && r["Type"] == "A")
        {
            vec![set()]
        } else {
            vec![]
        };
        vec![
            ok(json!({"Total":1,"Zones":[{"ZID":1234,"ZoneName":"example.com"}]})),
            ok(zone()),
            page("Lines", 1, vec![json!({"ID":"1","Value":"default"})]),
            page("RecordSets", sets.len(), sets),
            page("Records", records.len(), records),
        ]
    }
    fn writes(m: &Mock) -> usize {
        m.data
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.2 == Method::POST)
            .count()
    }
    #[test]
    fn independent_python_hmac_golden() {
        let (_, _, keys) = authorization(
            "AKTestOnly",
            "test-only-secret",
            "GET",
            "Action=ListRecords&PageNumber=1&PageSize=100&Version=2018-08-01&ZID=1234",
            b"",
            "20240908T103826Z",
        );
        assert_eq!(
            keys[0],
            "60dd167425602d69a826c0086399cc12d77dff4c2bb53197f1c9c8c0d121dc2a"
        );
        let (auth,_,keys)=authorization("AKTestOnly","test-only-secret","POST","Action=UpdateRecord&Version=2018-08-01",br#"{"Host":"@","Line":"default","RecordID":"3170534137672596377","TTL":600,"Value":"192.0.2.2"}"#,"20240908T103826Z");
        assert_eq!(
            keys[0],
            "e091715caf0d8a0f23504650f7a89cf2971ee01142a7494cd783d945e4d1775f"
        );
        assert!(auth.contains("/20240908/cn-beijing/dns/request"));
        assert!(!auth.contains("TC3"));
    }
    #[tokio::test]
    async fn local_configuration_fails_without_requests() {
        let mut m = mock(vec![]).await;
        for key in ["scope", "api_version", "region", "zone_id"] {
            let mut o = options();
            o.remove(key);
            m.provider.configuration_error = validate_options(&o).err();
            assert!(m.provider.list(&spec()).await.is_err());
        }
        m.provider.configuration_error = None;
        for id in ["0", "001", "-1", "1/2", "base64="] {
            let mut s = spec();
            s.record_id = Some(id.into());
            assert_eq!(
                m.provider.list(&s).await.unwrap_err().code,
                "InvalidRecordId"
            );
        }
        let mut s = spec();
        s.options.insert("HealthCheck".into(), "on".into());
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        assert!(m.data.requests.lock().unwrap().is_empty());
        let mut o = options();
        o.insert("endpoint".into(), "http://localhost".into());
        assert_eq!(validate_options(&o).unwrap_err().code, "UnsupportedOptions");
    }
    #[tokio::test]
    async fn exact_zone_active_ownership_and_edition_required() {
        for (field, value, code) in [
            ("Stage", json!(1), "ZoneUnavailable"),
            ("Stage", json!(2), "ZoneUnavailable"),
            ("Stage", json!(5), "ZoneUnavailable"),
            ("Stage", Value::Null, "ZoneUnavailable"),
            ("IsNSCorrect", json!(false), "ZoneUnavailable"),
            ("IsSubDomain", json!(true), "ZoneUnavailable"),
            ("ZoneName", json!("other.com"), "ZoneUnavailable"),
            ("TradeCode", json!("unknown"), "MalformedResponse"),
        ] {
            let mut replies = snapshot(vec![]);
            replies[1].1[field] = value;
            let m = mock(replies).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            assert_eq!(writes(&m), 0);
        }
        let m = mock(snapshot(vec![])).await;
        let mut s = spec();
        s.ttl = 300;
        assert_eq!(m.provider.list(&s).await.unwrap_err().code, "EditionLimit");
        let mut replies = snapshot(vec![]);
        replies[0].1["Zones"][0]["ZID"] = json!(4321);
        let m = mock(replies).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "ZoneMismatch"
        );
    }
    #[tokio::test]
    async fn full_unfiltered_pagination_and_counts() {
        let mut replies = snapshot(vec![]);
        replies.pop();
        let first = (1..=100)
            .map(|i| {
                let mut r = record(i);
                r["Host"] = json!(format!("other{i}"));
                r
            })
            .collect();
        replies.push(page("Records", 101, first));
        let mut last = record(101);
        last["Host"] = json!("last");
        let mut p = page("Records", 101, vec![last]);
        p.1["PageNumber"] = json!(2);
        replies.push(p);
        let m = mock(replies).await;
        assert_eq!(m.provider.list(&spec()).await.unwrap().records.len(), 101);
        let requests = m.data.requests.lock().unwrap();
        assert_eq!(requests[4].1["PageNumber"], "1");
        assert_eq!(requests[5].1["PageNumber"], "2");
        for key in ["Host", "Line", "Type", "Value", "SearchMode"] {
            assert!(requests[4].1.get(key).is_none());
        }
    }
    #[tokio::test]
    async fn malformed_incomplete_duplicate_and_excessive_pages_fail() {
        for mut result in [
            json!({"Records":[]}),
            json!({"TotalCount":0}),
            json!({"TotalCount":1,"Records":[]}),
            json!({"TotalCount":10001,"Records":[]}),
            json!({"TotalCount":2,"Records":[record(1),record(1)]}),
            json!({"TotalCount":101,"Records":[record(1)]}),
        ] {
            result["PageNumber"] = json!(1);
            result["PageSize"] = json!(PAGE);
            let mut replies = snapshot(vec![]);
            replies[4] = ok(result);
            let m = mock(replies).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "MalformedResponse"
            );
            assert_eq!(writes(&m), 0);
        }
        for mode in ["duplicate", "changed-total", "repeated-page"] {
            let mut replies = snapshot(vec![]);
            replies.pop();
            let first = (1..=100)
                .map(|i| {
                    let mut r = record(i);
                    r["Host"] = json!(format!("other{i}"));
                    r
                })
                .collect();
            replies.push(page("Records", 101, first));
            let mut r = record(if mode == "duplicate" { 1 } else { 101 });
            r["Host"] = json!("other");
            let mut second = page(
                "Records",
                if mode == "changed-total" { 100 } else { 101 },
                vec![r],
            );
            second.1["PageNumber"] = json!(if mode == "repeated-page" { 1 } else { 2 });
            replies.push(second);
            let m = mock(replies).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "MalformedResponse"
            );
            assert_eq!(writes(&m), 0);
        }
        let mut replies = snapshot(vec![]);
        replies[3].1["RecordSets"] = set();
        let m = mock(replies).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "MalformedResponse"
        );
    }
    #[tokio::test]
    async fn exact_relative_owner_and_default_aliases() {
        for name in ["home.example.com", "example.com", "branch.home"] {
            let mut r = record(1);
            r["Host"] = json!(name);
            let m = mock(snapshot(vec![r])).await;
            assert_eq!(
                reconcile(&m.provider, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                "RecordNotFound"
            );
            assert_eq!(writes(&m), 0);
        }
        for alias in ["默认", "default", ""] {
            let m = mock(snapshot(vec![record(1)])).await;
            let mut s = spec();
            s.record_line = alias.into();
            assert_eq!(
                reconcile(&m.provider, &s, "192.0.2.1", true)
                    .await
                    .unwrap()
                    .status,
                "unchanged"
            );
        }
        let m = mock(snapshot(vec![record(1)])).await;
        let mut s = spec();
        s.record_line = "Default".into();
        assert_eq!(
            m.provider.list(&s).await.unwrap_err().code,
            "UnsupportedLine"
        );
    }
    #[tokio::test]
    async fn noop_and_dryrun_are_real_ttl_reads_without_writes() {
        for (ip, ttl, status) in [
            ("192.0.2.1", 600, "unchanged"),
            ("192.0.2.1", 700, "would_update"),
            ("192.0.2.2", 600, "would_update"),
        ] {
            let m = mock(snapshot(vec![record(1)])).await;
            let mut s = spec();
            s.ttl = ttl;
            let result = reconcile(&m.provider, &s, ip, true).await.unwrap();
            assert_eq!(result.status, status);
            assert_eq!(writes(&m), 0);
        }
    }
    #[tokio::test]
    async fn tags_unknown_controls_and_weighted_sets_block_even_noop() {
        for (field, value, code) in [
            ("Tags", json!(["GTMLock"]), "ManagedTraffic"),
            ("Tags", Value::Null, "ManagedTraffic"),
            ("HealthCheck", json!(true), "UnsupportedControlFields"),
            ("Weight", json!(0), "InvalidWeight"),
        ] {
            let mut r = record(1);
            r[field] = value;
            let m = mock(snapshot(vec![r])).await;
            assert_eq!(
                reconcile(&m.provider, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(writes(&m), 0);
        }
        let mut replies = snapshot(vec![record(1)]);
        replies[3].1["RecordSets"][0]["WeightEnabled"] = json!(true);
        let m = mock(replies).await;
        assert_eq!(
            reconcile(&m.provider, &spec(), "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "UnsupportedRecordSet"
        );
    }
    #[tokio::test]
    async fn disabled_conflicts_rrsets_and_explicit_missing_never_write() {
        let mut disabled = record(1);
        disabled["Enable"] = json!(false);
        let m = mock(snapshot(vec![disabled])).await;
        assert_eq!(
            reconcile(&m.provider, &spec(), "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "RecordDisabled"
        );
        for kind in ["CNAME", "NS"] {
            let mut r = record(2);
            r["Type"] = json!(kind);
            r["Enable"] = json!(false);
            let m = mock(snapshot(vec![record(1), r])).await;
            assert_eq!(
                reconcile(&m.provider, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                "DnsConflict"
            );
        }
        let m = mock(snapshot(vec![record(1), record(2)])).await;
        let mut s = spec();
        s.record_id = Some("1".into());
        assert_eq!(
            reconcile(&m.provider, &s, "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "UnsupportedRecordSet"
        );
        let m = mock(snapshot(vec![])).await;
        let mut s = spec();
        s.record_id = Some("1".into());
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.provider, &s, "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "RecordIdNotFound"
        );
        assert_eq!(writes(&m), 0);
    }
    #[tokio::test]
    async fn update_partial_fields_preserves_real_controls_and_verifies() {
        let before = record(1);
        let mut after = before.clone();
        after["Value"] = json!("192.0.2.2");
        after["UpdatedAt"] = json!("2024-02-01");
        after["Operators"] = json!(["new-actor"]);
        let mut replies = snapshot(vec![before.clone()]);
        replies.extend(snapshot(vec![before.clone()]));
        replies.push(ok(before));
        replies.push(ok(json!({"RecordID":"1"})));
        replies.extend(snapshot(vec![after.clone()]));
        replies.push(ok(after));
        let m = mock(replies).await;
        assert_eq!(
            reconcile(&m.provider, &spec(), "192.0.2.2", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        assert_eq!(writes(&m), 1);
        let requests = m.data.requests.lock().unwrap();
        let update = requests.iter().find(|r| r.0 == "UpdateRecord").unwrap();
        assert_eq!(
            update.1,
            json!({"RecordID":"1","Host":"home","Line":"default","Value":"192.0.2.2","TTL":600})
        );
        assert_eq!(requests[10].0, "QueryRecord");
    }
    #[tokio::test]
    async fn create_only_after_fresh_absence_then_postread() {
        let mut after = record(9);
        after["Value"] = json!("192.0.2.2");
        after["Weight"] = json!(1);
        let mut replies = snapshot(vec![]);
        replies.extend(snapshot(vec![]));
        replies.push(ok(json!({"RecordID":"9"})));
        replies.extend(snapshot(vec![after.clone()]));
        replies.push(ok(after));
        let m = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.provider, &s, "192.0.2.2", false)
                .await
                .unwrap()
                .status,
            "created"
        );
        assert_eq!(writes(&m), 1);
        let m = mock(snapshot(vec![])).await;
        assert_eq!(
            reconcile(&m.provider, &s, "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_create"
        );
        assert_eq!(writes(&m), 0);
    }
    #[tokio::test]
    async fn fresh_target_races_never_mutate() {
        for change in ["snapshot", "target"] {
            let before = record(1);
            let mut changed = before.clone();
            changed["Weight"] = json!(38);
            let mut replies = snapshot(vec![before.clone()]);
            if change == "snapshot" {
                replies.extend(snapshot(vec![changed]));
            } else {
                replies.extend(snapshot(vec![before]));
                replies.push(ok(changed));
            }
            let m = mock(replies).await;
            assert_eq!(
                reconcile(&m.provider, &spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                "ConcurrentRecord"
            );
            assert_eq!(writes(&m), 0);
        }
    }
    #[tokio::test]
    async fn strict_ack_and_pending_postread_never_retry() {
        for ack in [json!({}), json!({"RecordID":"2"})] {
            let before = record(1);
            let mut replies = snapshot(vec![before.clone()]);
            replies.extend(snapshot(vec![before.clone()]));
            replies.push(ok(before));
            replies.push(ok(ack));
            let m = mock(replies).await;
            assert_eq!(
                reconcile(&m.provider, &spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                "MalformedResponse"
            );
            assert_eq!(writes(&m), 1);
        }
        let before = record(1);
        let mut replies = snapshot(vec![before.clone()]);
        replies.extend(snapshot(vec![before.clone()]));
        replies.push(ok(before.clone()));
        replies.push(ok(json!({"RecordID":"1"})));
        replies.extend(snapshot(vec![before.clone()]));
        replies.push(ok(before));
        let m = mock(replies).await;
        assert_eq!(
            reconcile(&m.provider, &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "WriteOutcomeUncertain"
        );
        assert_eq!(writes(&m), 1);
    }
    #[tokio::test]
    async fn status_200_business_error_keeps_sanitized_original_context() {
        for status in [200, 403] {
            let m=mock(vec![(status,json!({"ResponseMetadata":{"RequestId":"original-trace","Error":{"Code":"ErrZoneInactive","Message":"zone is inactive test-only-secret AKTestOnly"}}}))]).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "ErrZoneInactive");
            assert_eq!(e.http_status, Some(status));
            assert_eq!(e.request_id.as_deref(), Some("original-trace"));
            assert!(e.message.contains("zone is inactive"));
            assert!(!e.message.contains("test-only-secret"));
            assert!(!e.message.contains("AKTestOnly"));
        }
        let m = mock(vec![ok(json!("echo-auth"))]).await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert!(e.request_id.is_none());
        assert_eq!(e.code, "AuthFailure");
        assert!(e.message.contains("[REDACTED]"));
    }
    #[tokio::test]
    async fn apex_dotted_relative_and_ipv6_are_not_suffix_guessed() {
        for (host, kind, ip) in [
            ("@", "A", "192.0.2.1"),
            ("branch.example.com", "A", "192.0.2.1"),
            ("home", "AAAA", "2001:db8::1"),
        ] {
            let mut r = record(1);
            r["Host"] = json!(host);
            r["Type"] = json!(kind);
            r["Value"] = json!(ip);
            let mut set = set();
            set["Host"] = json!(host);
            set["Type"] = json!(kind);
            let mut replies = snapshot(vec![r]);
            replies[3] = page("RecordSets", 1, vec![set]);
            let m = mock(replies).await;
            let mut s = spec();
            s.subdomain = host.into();
            s.record_type = kind.into();
            assert_eq!(
                reconcile(&m.provider, &s, ip, true).await.unwrap().status,
                "unchanged"
            );
            assert_eq!(writes(&m), 0);
        }
    }
    #[tokio::test]
    async fn create_race_other_line_and_unknown_other_family_controls_refused() {
        let mut replies = snapshot(vec![]);
        replies.extend(snapshot(vec![record(1)]));
        let m = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&m.provider, &s, "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "ConcurrentRecord"
        );
        assert_eq!(writes(&m), 0);
        let mut r = record(1);
        r["Line"] = json!("domestic");
        let mut set = set();
        set["Line"] = json!("domestic");
        let mut replies = snapshot(vec![r]);
        replies[3] = page("RecordSets", 1, vec![set]);
        let m = mock(replies).await;
        assert_eq!(
            reconcile(&m.provider, &s, "192.0.2.2", true)
                .await
                .unwrap_err()
                .code,
            "CreationRefused"
        );
        assert_eq!(writes(&m), 0);
        let mut r = record(1);
        r["Type"] = json!("AAAA");
        r["Value"] = json!("2001:db8::1");
        r["HealthCheck"] = json!({});
        let m = mock(snapshot(vec![r])).await;
        assert_eq!(
            reconcile(&m.provider, &s, "192.0.2.2", true)
                .await
                .unwrap_err()
                .code,
            "UnsupportedControlFields"
        );
        assert_eq!(writes(&m), 0);
    }
    #[tokio::test]
    async fn changed_postwrite_controls_are_uncertain_and_never_retried() {
        let before = record(1);
        let mut after = before.clone();
        after["Value"] = json!("192.0.2.2");
        after["Remark"] = json!("lost note");
        let mut replies = snapshot(vec![before.clone()]);
        replies.extend(snapshot(vec![before.clone()]));
        replies.push(ok(before));
        replies.push(ok(json!({"RecordID":"1"})));
        replies.extend(snapshot(vec![after.clone()]));
        replies.push(ok(after));
        let m = mock(replies).await;
        let e = reconcile(&m.provider, &spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(e.code, "WriteOutcomeUncertain");
        assert_eq!(e.request_id.as_deref(), Some("trace-test"));
        assert_eq!(writes(&m), 1);
        let before = record(1);
        let mut replies = snapshot(vec![before.clone()]);
        replies.extend(snapshot(vec![before.clone()]));
        replies.push(ok(before));
        replies.push(ok(json!({"ResponseMetadata":{"RequestId":"write-trace","Error":{"Code":"ErrParamInvalid","Message":"validation fail: test-only-secret"}}})));
        let m = mock(replies).await;
        let e = reconcile(&m.provider, &spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(e.code, "ErrParamInvalid");
        assert_eq!(e.http_status, Some(200));
        assert_eq!(e.request_id.as_deref(), Some("write-trace"));
        assert!(e.message.contains("validation fail:"));
        assert!(!e.message.contains("test-only-secret"));
        assert_eq!(writes(&m), 1);
    }
    #[tokio::test]
    async fn documented_metadata_regions_only_and_invalid_record_fields_fail() {
        for (field, value) in [
            ("Service", json!("dnspod")),
            ("Version", json!("2021-06-11")),
            ("Action", json!("DescribeDomains")),
            ("Region", json!("other")),
            ("RequestId", json!("")),
        ] {
            let mut metadata = json!({"RequestId":"trace","Action":"ListZones","Version":VERSION,"Service":"dns","Region":REGION});
            metadata[field] = value;
            let m = mock(vec![ok(
                json!({"ResponseMetadata":metadata,"Result":{"Total":0,"Zones":[]}}),
            )])
            .await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "MalformedResponse"
            );
        }
        let metadata = json!({"RequestId":"trace","Action":"ListZones","Version":VERSION,"Service":"dns","Region":"cn-north-1"});
        let m = mock(vec![ok(
            json!({"ResponseMetadata":metadata,"Result":{"Total":0,"Zones":[]}}),
        )])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "ZoneMismatch"
        );
        for field in ["RecordID", "Host", "Type", "Value", "TTL", "Line", "Enable"] {
            let mut r = record(1);
            r.as_object_mut().unwrap().remove(field);
            let m = mock(snapshot(vec![r])).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "MalformedResponse"
            );
            assert_eq!(writes(&m), 0);
        }
        let mut r = record(1);
        r["Value"] = json!("192.0.2.1,192.0.2.2");
        let m = mock(snapshot(vec![r])).await;
        assert_eq!(
            reconcile(&m.provider, &spec(), "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "InvalidRecordValue"
        );
    }
}
