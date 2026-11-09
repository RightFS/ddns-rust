//! Native TEODNS only: NOT acceleration-domain origins or origin groups.
//! Official API version 2022-09-01, service teo, fixed provider-owned HTTPS.
//! https://cloud.tencent.com/document/api/1552/80713 (DescribeZones)
//! https://cloud.tencent.com/document/api/1552/80716 (DescribeDnsRecords)
//! https://cloud.tencent.com/document/api/1552/80720 (CreateDnsRecord: NS/full only)
//! https://cloud.tencent.com/document/api/1552/114252 (ModifyDnsRecords: partial fields)
//! https://github.com/TencentCloud/tencentcloud-sdk-cpp/tree/master/teo/include/tencentcloud/teo/v20220901/model
//! DnsRecord.Status/ZoneId/timestamps are output-only; do not send them back.
//! TTL is genuinely observed and writable (60..86400). No Origin TTL exists here.
//! One writer is required: TEODNS offers no documented conditional mutation.
//! The supplied client MUST disable redirects; no response URL is ever followed.
#![allow(clippy::result_large_err)]

use super::common::{
    Adapter, Api, HttpReply, List, Mutation, Record, Spec, valid_id, valid_trace_id,
};
use crate::provider::ProviderError;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};

const HOST: &str = "teo.tencentcloudapi.com";
const ENDPOINT: &str = "https://teo.tencentcloudapi.com/";
const VERSION: &str = "2022-09-01";
const CONTENT_TYPE: &str = "application/json; charset=utf-8";
const SIGNED_HEADERS: &str = "content-type;host;x-tc-action";
const PAGE_SIZE: usize = 100;
const MAX_ITEMS: usize = 10_000;
const HINT: &str = "Use Tencent Cloud SecretId/SecretKey with teo:DescribeZones, teo:DescribeDnsRecords, teo:DescribeAccelerationDomains and teo:DescribeApplicationProxies read permissions on the exact NS/full zone; add teo:ModifyDnsRecords and optionally teo:CreateDnsRecord for writes. Origin/acceleration control and DNSPod fallback are not supported. Inspect uncertain writes before any manual retry.";

// No Debug/Serialize: keys and derived auth material must never enter DTOs.
pub struct EdgeOne {
    api: Api,
    id: String,
    key: String,
    zone_id: String,
    configuration_error: Option<ProviderError>,
    #[cfg(test)]
    endpoint: String,
}

pub fn validate_options(options: &BTreeMap<String, String>) -> Result<(), ProviderError> {
    let fail =
        |code, message| super::common::local_error("configuration", code, message, HINT, None);
    if options.get("mode").map(String::as_str) != Some("dns") {
        return Err(fail(
            "UnsupportedMode",
            "Set mode=dns explicitly: this adapter updates native TEODNS, not reverse-proxy origins or origin groups.",
        ));
    }
    if options.get("scope").map(String::as_str) != Some("teodns") {
        return Err(fail(
            "InvalidScope",
            "Set scope=teodns explicitly; only ordinary DNS on an existing NS/full site is supported.",
        ));
    }
    if options.get("api_version").map(String::as_str) != Some(VERSION) {
        return Err(fail(
            "InvalidApiVersion",
            "Set api_version=2022-09-01; no automatic API-version fallback is permitted.",
        ));
    }
    if !options
        .get("zone_id")
        .is_some_and(|id| id.starts_with("zone-") && valid_id(id))
    {
        return Err(fail(
            "InvalidZoneId",
            "An explicit native zone_id (zone-...) is required; name-only or first-zone selection is refused.",
        ));
    }
    if options
        .keys()
        .any(|key| !matches!(key.as_str(), "mode" | "scope" | "api_version" | "zone_id"))
    {
        return Err(fail(
            "UnsupportedOptions",
            "Unsupported EdgeOne option: origin/group/endpoint/region overrides are not accepted.",
        ));
    }
    Ok(())
}
fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}
fn within(name: &str, zone: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let zone = zone.trim_end_matches('.').to_ascii_lowercase();
    name == zone || name.ends_with(&format!(".{zone}"))
}
fn domain_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'*'))
        })
}
fn overlaps(name: &str, target: &str) -> bool {
    same_name(name, target)
        || name
            .strip_prefix("*.")
            .is_some_and(|suffix| within(target, suffix))
}
fn line(spec: &Spec) -> &str {
    if matches!(spec.record_line.as_str(), "" | "默认" | "default") {
        "Default"
    } else {
        &spec.record_line
    }
}
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts all key lengths");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
fn authorization(
    id: &str,
    key: &str,
    action: &str,
    payload: &[u8],
    timestamp: i64,
) -> Option<(String, String, Vec<String>)> {
    let date = DateTime::<Utc>::from_timestamp(timestamp, 0)?
        .format("%Y-%m-%d")
        .to_string();
    let headers = format!(
        "content-type:{CONTENT_TYPE}\nhost:{HOST}\nx-tc-action:{}\n",
        action.to_ascii_lowercase()
    );
    let canonical = format!(
        "POST\n/\n\n{headers}\n{SIGNED_HEADERS}\n{}",
        hex::encode(Sha256::digest(payload))
    );
    let scope = format!("{date}/teo/tc3_request");
    let to_sign = format!(
        "TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let date_key = hmac(format!("TC3{key}").as_bytes(), date.as_bytes());
    let service_key = hmac(&date_key, b"teo");
    let signing_key = hmac(&service_key, b"tc3_request");
    let signature = hex::encode(hmac(&signing_key, to_sign.as_bytes()));
    let auth = format!(
        "TC3-HMAC-SHA256 Credential={id}/{scope}, SignedHeaders={SIGNED_HEADERS}, Signature={signature}"
    );
    Some((
        auth,
        signature,
        vec![
            hex::encode(date_key),
            hex::encode(service_key),
            hex::encode(signing_key),
        ],
    ))
}

impl EdgeOne {
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
            zone_id: options.get("zone_id").cloned().unwrap_or_default(),
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
    fn malformed(&self, action: &str, message: &str, reply: &HttpReply) -> ProviderError {
        self.fail(action, "MalformedResponse", message, Some(reply))
    }
    fn text<'a>(
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
            .ok_or_else(|| {
                self.malformed(action, &format!("Missing or invalid string {field}"), reply)
            })
    }
    fn validate(&self, spec: &Spec) -> Result<(), ProviderError> {
        if let Some(error) = &self.configuration_error {
            return Err(error.clone());
        }
        if self.id.is_empty()
            || !self.id.bytes().all(|b| b.is_ascii_alphanumeric())
            || self.key.is_empty()
        {
            return Err(self.fail("credentials", "InvalidCredentials", "Missing or invalid Tencent Cloud SecretId/SecretKey; legacy DNSPod tokens are not accepted.", None));
        }
        if !spec.options.is_empty() {
            return Err(self.fail("validation", "UnsupportedOptions", "Record options are unsupported: use record_id for a native DNS ID and record_line for Location; origin controls are not DNS.", None));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA")
            || !domain_name(&spec.domain)
            || !domain_name(&spec.fqdn())
            || spec.fqdn().contains('*')
        {
            return Err(self.fail("validation", "UnsupportedTarget", "Only a single literal A/AAAA target at an ASCII/punycode non-wildcard DNS name is supported.", None));
        }
        if !(60..=86400).contains(&spec.ttl) {
            return Err(self.fail(
                "validation",
                "InvalidTtl",
                "TEODNS TTL must be within 60..86400 seconds, including dry-run/no-op.",
                None,
            ));
        }
        if spec
            .record_id
            .as_ref()
            .is_some_and(|id| !id.starts_with("record-") || !valid_id(id))
        {
            return Err(self.fail(
                "validation",
                "InvalidRecordId",
                "record_id must be the native TEODNS record-... ID, not an origin group/source ID.",
                None,
            ));
        }
        Ok(())
    }
    fn validate_ip(&self, spec: &Spec, ip: &str) -> Result<(), ProviderError> {
        self.validate(spec)?;
        if !ip
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_ipv4() == (spec.record_type == "A"))
        {
            return Err(self.fail("validation", "InvalidIp", "Target must be a single literal IP of the configured A/AAAA family, without port or protocol.", None));
        }
        Ok(())
    }
    async fn call(
        &self,
        action: &str,
        payload: Value,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let payload = serde_json::to_vec(&payload).expect("JSON Value serialization");
        let timestamp = Utc::now().timestamp();
        let (auth, signature, mut keys) =
            authorization(&self.id, &self.key, action, &payload, timestamp).ok_or_else(|| {
                self.fail(
                    "signing",
                    "InvalidTimestamp",
                    "System timestamp cannot be represented in UTC.",
                    None,
                )
            })?;
        keys.extend([
            self.id.clone(),
            self.key.clone(),
            format!("TC3{}", self.key),
            auth.clone(),
            signature,
        ]);
        // Per-call sanitizer includes the actual generated signature/authorization
        // and derived keys, not just long-term credentials. Same bytes signed/sent.
        let api = Api::new(self.api.client.clone(), keys);
        let request = api
            .client
            .post(self.endpoint())
            .header("host", HOST)
            .header("content-type", CONTENT_TYPE)
            .header("x-tc-action", action)
            .header("x-tc-version", VERSION)
            .header("x-tc-timestamp", timestamp.to_string())
            .header("authorization", auth)
            .body(payload);
        let reply = api.send(action, request, write).await?;
        let response = reply.body.get("Response").filter(|v| v.is_object())
            .ok_or_else(|| api.error(action, "MalformedResponse", "Missing Response object; write acknowledgement unavailable if mutation was attempted.", HINT, Some(&reply)))?;
        if let Some(error) = response.get("Error") {
            let code = error
                .get("Code")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty());
            let message = error.get("Message").and_then(Value::as_str);
            if let (Some(code), Some(message)) = (code, message) {
                return Err(api.error(action, code, &format!("{message}{}", if write { " Write was not acknowledged; outcome may be uncertain, no retry occurred." } else { "" }), HINT, Some(&reply)));
            }
            return Err(api.error(
                action,
                "MalformedResponse",
                "Malformed Response.Error; not interpreted as success.",
                HINT,
                Some(&reply),
            ));
        }
        api.check_http(action, &reply)?;
        if !response
            .get("RequestId")
            .and_then(Value::as_str)
            .is_some_and(|id| valid_trace_id(id) && api.safe(id) == id)
        {
            return Err(api.error(action, "MalformedResponse", "Missing valid Response.RequestId; success/write acknowledgement is not established.", HINT, Some(&reply)));
        }
        Ok(reply)
    }
    async fn pages(
        &self,
        action: &str,
        array: &str,
        id_field: &str,
        mut payload: Value,
    ) -> Result<(Vec<Value>, Option<String>), ProviderError> {
        let mut items = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        for _ in 0..(MAX_ITEMS / PAGE_SIZE) {
            payload["Offset"] = json!(items.len());
            payload["Limit"] = json!(PAGE_SIZE);
            let reply = self.call(action, payload.clone(), false).await?;
            let response = &reply.body["Response"];
            let count = response
                .get("TotalCount")
                .and_then(Value::as_u64)
                .filter(|n| *n <= MAX_ITEMS as u64)
                .ok_or_else(|| {
                    self.malformed(action, "Missing, invalid or excessive TotalCount", &reply)
                })? as usize;
            let page = response
                .get(array)
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    self.malformed(
                        action,
                        "Missing explicit list array (not an empty-list success)",
                        &reply,
                    )
                })?;
            if total.is_some_and(|previous| previous != count)
                || page.len() > PAGE_SIZE
                || items.len() + page.len() > count
            {
                return Err(self.malformed(
                    action,
                    "Changing TotalCount or contradictory page length",
                    &reply,
                ));
            }
            total = Some(count);
            for item in page {
                let id = self.text(action, item, id_field, &reply)?;
                if !ids.insert(id.to_owned()) {
                    return Err(self.malformed(
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
            if page.len() != PAGE_SIZE {
                return Err(self.malformed(
                    action,
                    "Truncated page before TotalCount was reached",
                    &reply,
                ));
            }
        }
        Err(self.fail(
            action,
            "PaginationLimit",
            "Full list exceeded bounded pagination; no selection/mutation permitted.",
            None,
        ))
    }
    async fn zone(&self, spec: &Spec) -> Result<(), ProviderError> {
        let (zones, request_id) = self
            .pages(
                "DescribeZones",
                "Zones",
                "ZoneId",
                json!({"Filters":[{"Name":"zone-id","Values":[self.zone_id],"Fuzzy":false}]}),
            )
            .await?;
        let fail = |code, message| {
            let mut e = self.fail("DescribeZones", code, message, None);
            e.request_id = request_id.clone();
            e
        };
        if zones.len() != 1
            || zones[0].get("ZoneId").and_then(Value::as_str) != Some(&self.zone_id)
            || !zones[0]
                .get("ZoneName")
                .and_then(Value::as_str)
                .is_some_and(|name| same_name(name, &spec.domain))
        {
            return Err(fail(
                "ZoneMismatch",
                "Exact zone_id/domain identity was not uniquely returned; name-only fallback refused.",
            ));
        }
        let zone = &zones[0];
        if zone.get("Type").and_then(Value::as_str) != Some("full") {
            return Err(fail(
                "UnsupportedZoneType",
                "Native TEODNS supports NS/full sites only; CNAME/partial, DNSPod-hosted, Pages and origin-only sites are not ordinary DNS targets.",
            ));
        }
        if zone.get("Status").and_then(Value::as_str) != Some("active")
            || zone.get("ActiveStatus").and_then(Value::as_str) != Some("active")
            || zone.get("LockStatus").and_then(Value::as_str) != Some("enable")
            || zone.get("Paused").and_then(Value::as_bool) != Some(false)
        {
            return Err(fail(
                "ZoneUnavailable",
                "Site must be active, active-display, unpaused and unlocked; pending/moved/deactivated/unknown states fail closed.",
            ));
        }
        Ok(())
    }
    async fn managed(&self, spec: &Spec) -> Result<(), ProviderError> {
        let (domains, request_id) = self
            .pages(
                "DescribeAccelerationDomains",
                "AccelerationDomains",
                "DomainName",
                json!({"ZoneId":self.zone_id}),
            )
            .await?;
        for domain in domains {
            let name = domain
                .get("DomainName")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if domain.get("ZoneId").and_then(Value::as_str) != Some(&self.zone_id)
                || !domain_name(name)
                || !within(name, &spec.domain)
            {
                let mut e = self.fail(
                    "DescribeAccelerationDomains",
                    "ManagedIdentityMismatch",
                    "Acceleration list returned invalid zone/domain identity.",
                    None,
                );
                e.request_id = request_id;
                return Err(e);
            }
            if overlaps(name, &spec.fqdn()) {
                let mut e = self.fail("selection", "ManagedTraffic", "Target overlaps an acceleration domain (including offline/pending/wildcard). Updating its origin is not an ordinary DNS change; refused before dry-run/no-op.", None);
                e.request_id = request_id;
                return Err(e);
            }
        }
        let (proxies, request_id) = self
            .pages(
                "DescribeApplicationProxies",
                "ApplicationProxies",
                "ProxyId",
                json!({"ZoneId":self.zone_id}),
            )
            .await?;
        for proxy in proxies {
            if proxy.get("ZoneId").and_then(Value::as_str) != Some(&self.zone_id)
                || !proxy
                    .get("ProxyId")
                    .and_then(Value::as_str)
                    .is_some_and(valid_id)
            {
                let mut e = self.fail(
                    "DescribeApplicationProxies",
                    "ManagedIdentityMismatch",
                    "Proxy list returned invalid zone/native proxy identity.",
                    None,
                );
                e.request_id = request_id;
                return Err(e);
            }
            match proxy.get("ProxyType").and_then(Value::as_str) {
                Some("instance") => {}
                Some("hostname")
                    if proxy
                        .get("ProxyName")
                        .and_then(Value::as_str)
                        .is_some_and(domain_name) =>
                {
                    if overlaps(proxy["ProxyName"].as_str().unwrap(), &spec.fqdn()) {
                        let mut e = self.fail("selection", "ManagedTraffic", "Target overlaps a four-layer hostname proxy; proxy/source/port controls are unsupported DNS targets.", None);
                        e.request_id = request_id;
                        return Err(e);
                    }
                }
                _ => {
                    let mut e = self.fail(
                        "DescribeApplicationProxies",
                        "UnsupportedManagedTraffic",
                        "Unknown or incomplete proxy type/name prevents safe DNS ownership checks.",
                        None,
                    );
                    e.request_id = request_id;
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    fn parse(&self, value: Value, spec: &Spec) -> Result<Record, ProviderError> {
        let fail = |message| self.fail("DescribeDnsRecords", "MalformedResponse", message, None);
        let text = |field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| fail("Missing required DNS record string field"))
        };
        let id = text("RecordId")?.to_owned();
        let name = text("Name")?.to_owned();
        if !id.starts_with("record-")
            || !valid_id(&id)
            || value.get("ZoneId").and_then(Value::as_str) != Some(&self.zone_id)
            || !domain_name(&name)
            || !within(&name, &spec.domain)
        {
            return Err(fail("Invalid native DNS ID or record zone/name identity"));
        }
        let record_type = text("Type")?.to_owned();
        let address = value
            .get("Content")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("Missing DNS Content"))?
            .to_owned();
        let ttl = value
            .get("TTL")
            .and_then(Value::as_u64)
            .filter(|ttl| (60..=86400).contains(ttl))
            .ok_or_else(|| fail("Missing or invalid observed DNS TTL"))?;
        let location = text("Location")?.to_owned();
        let enabled = match text("Status")? {
            "enable" => true,
            "disable" => false,
            _ => return Err(fail("Unknown DNS status; not assumed enabled")),
        };
        Ok(Record {
            id,
            name,
            record_type,
            value: address,
            ttl,
            line: location,
            enabled,
            extra: value,
        })
    }
    fn controls(&self, record: &Record) -> Result<(), ProviderError> {
        if record.extra.as_object().is_none_or(|object| {
            object.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "ZoneId"
                        | "RecordId"
                        | "Name"
                        | "Type"
                        | "Content"
                        | "Location"
                        | "TTL"
                        | "Weight"
                        | "Priority"
                        | "Status"
                        | "CreatedOn"
                        | "ModifiedOn"
                )
            })
        }) {
            return Err(self.fail("selection", "UnsupportedControlFields", "Unknown DNS/proxy/routing fields on selected record cannot be safely treated as ordinary DNS.", None));
        }
        if !record
            .extra
            .get("Weight")
            .and_then(Value::as_i64)
            .is_some_and(|weight| (-1..=100).contains(&weight))
            || !record
                .extra
                .get("Priority")
                .and_then(Value::as_u64)
                .is_some_and(|priority| priority <= 50)
        {
            return Err(self.fail(
                "selection",
                "InvalidControlFields",
                "Missing or invalid observed Weight/Priority; refusing to guess traffic controls.",
                None,
            ));
        }
        if record.extra["Weight"] == json!(0) {
            return Err(self.fail("selection", "RecordDisabled", "Weight=0 means not resolved even when Status=enable; never enable or update this target.", None));
        }
        Ok(())
    }
    async fn verify_write(
        &self,
        spec: &Spec,
        id: &str,
        ip: &str,
        before: Option<&Record>,
        ack: &HttpReply,
    ) -> Result<Mutation, ProviderError> {
        let uncertain = |detail: &str| {
            self.fail("verification", "WriteOutcomeUncertain", &format!("Write acknowledged but full post-read did not establish the intended record and preserved controls: {detail}. Pending deployment/uncertain state; no writer retry occurred."), Some(ack))
        };
        let list = self.list(spec).await.map_err(|error| {
            uncertain(&format!(
                "{} [{}]: {} (post-read HTTP {}; RequestId {})",
                error.stage,
                error.code,
                error.message,
                error
                    .http_status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "unavailable".into()),
                error.request_id.as_deref().unwrap_or("unavailable")
            ))
        })?;
        let record = list
            .records
            .iter()
            .find(|record| record.id == id)
            .ok_or_else(|| uncertain("native RecordId not present"))?;
        self.validate_selection(spec, Some(record))
            .map_err(|error| uncertain(&error.message))?;
        if spec.record_id.is_none()
            && list
                .records
                .iter()
                .filter(|r| {
                    same_name(&r.name, &spec.fqdn())
                        && r.record_type == spec.record_type
                        && r.line == spec.record_line
                })
                .count()
                != 1
        {
            return Err(uncertain(
                "post-read selection became ambiguous or changed Location",
            ));
        }
        if !same_name(&record.name, &spec.fqdn())
            || record.record_type != spec.record_type
            || record.value.parse::<IpAddr>().ok() != ip.parse::<IpAddr>().ok()
            || record.ttl != spec.ttl
            || !record.enabled
        {
            return Err(uncertain("name/type/content/TTL/status mismatch"));
        }
        if let Some(before) = before {
            for field in [
                "ZoneId",
                "RecordId",
                "Name",
                "Type",
                "Location",
                "Weight",
                "Priority",
                "Status",
                "CreatedOn",
            ] {
                if before.extra.get(field) != record.extra.get(field) {
                    return Err(uncertain("unmodified control/identity field changed"));
                }
            }
        } else if record.extra["Location"] != json!(line(spec))
            || record.extra["Weight"] != json!(-1)
        {
            return Err(uncertain(
                "new record line or weight differs from ordinary DNS creation",
            ));
        }
        Ok(Mutation {
            record_id: id.into(),
            request_id: ack.request_id.clone(),
        })
    }
}
impl Adapter for EdgeOne {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Fqdn
    }
    fn validate_selection(
        &self,
        spec: &Spec,
        record: Option<&Record>,
    ) -> Result<(), ProviderError> {
        self.validate(spec)?;
        if let Some(record) = record {
            self.controls(record)?;
        }
        Ok(())
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        self.validate(spec)?;
        self.zone(spec).await?;
        self.managed(spec).await?;
        let (items, request_id) = self
            .pages(
                "DescribeDnsRecords",
                "DnsRecords",
                "RecordId",
                json!({"ZoneId":self.zone_id}),
            )
            .await?;
        let mut records = Vec::new();
        for item in items {
            let record = self.parse(item, spec).map_err(|mut e| {
                e.request_id = request_id.clone();
                e
            })?;
            if (record.record_type == "CNAME" && overlaps(&record.name, &spec.fqdn()))
                || (record.record_type == "NS"
                    && !same_name(&record.name, &spec.domain)
                    && within(&spec.fqdn(), &record.name))
            {
                let mut e = self.fail("selection", "DnsConflict", "Target conflicts with CNAME or a delegated NS ancestor (disabled records included); refused before dry-run/no-op/create.", None);
                e.request_id = request_id;
                return Err(e);
            }
            // Common policy matches the configured line; default is translated
            // locally, while the exact provider Location remains in extra.
            if record.line == line(spec) {
                let mut record = record;
                record.line = spec.record_line.clone();
                records.push(record);
            } else {
                records.push(record);
            }
        }
        if spec.record_id.is_none()
            && spec.create_if_missing
            && records
                .iter()
                .any(|r| same_name(&r.name, &spec.fqdn()) && r.record_type == spec.record_type)
            && !records.iter().any(|r| {
                same_name(&r.name, &spec.fqdn())
                    && r.record_type == spec.record_type
                    && r.line == spec.record_line
            })
        {
            let mut e = self.fail("selection", "CreationRefused", "Target records exist on another Location; implicit RRset/traffic-policy extension is refused before dry-run.", None);
            e.request_id = request_id;
            return Err(e);
        }
        Ok(List {
            records,
            request_id,
        })
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate_ip(spec, ip)?;
        if spec.record_id.is_some() || !spec.create_if_missing {
            return Err(self.fail(
                "create",
                "CreationRefused",
                "Creation requires create_if_missing=true and no explicit native record_id.",
                None,
            ));
        }
        let fresh = self.list(spec).await?;
        if fresh.records.iter().any(|record| {
            same_name(&record.name, &spec.fqdn()) && record.record_type == spec.record_type
        }) {
            return Err(self.fail("create", "ConcurrentRecord", "A target A/AAAA record exists in the fresh snapshot; creation is refused rather than extending an RRset or traffic policy.", None));
        }
        let ack = self.call("CreateDnsRecord", json!({"ZoneId":self.zone_id,"Name":spec.fqdn(),"Type":spec.record_type,"Content":ip,"Location":line(spec),"TTL":spec.ttl,"Weight":-1}), true).await?;
        let id = ack.body.pointer("/Response/RecordId").and_then(Value::as_str).filter(|id| id.starts_with("record-") && valid_id(id))
            .ok_or_else(|| self.malformed("CreateDnsRecord", "Missing valid RecordId acknowledgement; write outcome uncertain, no retry occurred", &ack))?;
        self.verify_write(spec, id, ip, None, &ack).await
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.validate_ip(spec, ip)?;
        let fresh = self.list(spec).await?;
        let current = fresh
            .records
            .iter()
            .find(|item| item.id == record.id)
            .ok_or_else(|| {
                self.fail(
                    "update",
                    "ConcurrentRecord",
                    "Selected native ID disappeared from fresh full snapshot; no write occurred.",
                    None,
                )
            })?;
        self.validate_selection(spec, Some(current))?;
        if (spec.record_id.is_none()
            && fresh
                .records
                .iter()
                .filter(|r| {
                    same_name(&r.name, &spec.fqdn())
                        && r.record_type == spec.record_type
                        && r.line == spec.record_line
                })
                .count()
                != 1)
            || spec.record_id.as_ref().is_some_and(|id| id != &record.id)
        {
            return Err(self.fail(
                "update",
                "ConcurrentRecord",
                "Fresh selection is ambiguous or explicit ID differs; no write occurred.",
                None,
            ));
        }
        if current.extra != record.extra
            || !current.enabled
            || !same_name(&current.name, &spec.fqdn())
            || current.record_type != spec.record_type
        {
            return Err(self.fail("update", "ConcurrentRecord", "Selected identity/status/settings changed since selection; no write occurred. One writer is required (no conditional API).", None));
        }
        // Official partial-update examples establish omission preservation. Do
        // not reset Location/Weight/Priority; Status and timestamps are output-only.
        let ack = self.call("ModifyDnsRecords", json!({"ZoneId":self.zone_id,"DnsRecords":[{"RecordId":current.id,"Content":ip,"TTL":spec.ttl}]}), true).await?;
        self.verify_write(spec, &record.id, ip, Some(current), &ack)
            .await
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
        http::{HeaderMap, StatusCode, Uri},
        routing::post,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    type Request = (String, Value, HeaderMap);
    #[derive(Clone)]
    struct StateData {
        replies: Arc<Mutex<VecDeque<(u16, Value)>>>,
        requests: Arc<Mutex<Vec<Request>>>,
    }
    struct Mock {
        provider: EdgeOne,
        state: StateData,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(
        State(state): State<StateData>,
        uri: Uri,
        headers: HeaderMap,
        bytes: Bytes,
    ) -> (StatusCode, HeaderMap, axum::Json<Value>) {
        assert_eq!(uri.path(), "/");
        assert!(uri.query().is_none());
        assert_eq!(headers["host"], HOST);
        assert_eq!(headers["content-type"], CONTENT_TYPE);
        assert_eq!(headers["x-tc-version"], VERSION);
        assert!(headers.get("x-tc-region").is_none());
        let action = headers["x-tc-action"].to_str().unwrap().to_owned();
        let timestamp = headers["x-tc-timestamp"].to_str().unwrap().parse().unwrap();
        let (auth, signature, _) = authorization(
            "AKIDTestOnly",
            "test-secret-not-real",
            &action,
            &bytes,
            timestamp,
        )
        .unwrap();
        assert_eq!(headers["authorization"], auth);
        let payload = serde_json::from_slice(&bytes).unwrap();
        state
            .requests
            .lock()
            .unwrap()
            .push((action, payload, headers));
        let (status, mut reply) = state
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("Unexpected request or write retry");
        // Echo the real generated signature without an Authorization label to
        // test per-call redaction, including RequestId and Error.Code fields.
        if reply == json!("echo-signature") {
            reply = json!({"Response":{"RequestId":signature,"Error":{"Code":"AuthFailure.SignatureFailure","Message":format!("Rejected key test-secret-not-real AKIDTestOnly digest {signature}")}}});
        }
        let mut response_headers = HeaderMap::new();
        if let Some(url) = reply.get("Redirect").and_then(Value::as_str) {
            response_headers.insert("location", url.parse().unwrap());
        }
        (
            StatusCode::from_u16(status).unwrap(),
            response_headers,
            axum::Json(reply),
        )
    }
    fn options() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("mode".into(), "dns".into()),
            ("scope".into(), "teodns".into()),
            ("api_version".into(), VERSION.into()),
            ("zone_id".into(), "zone-test".into()),
        ])
    }
    async fn mock(replies: Vec<(u16, Value)>) -> Mock {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let state = StateData {
            replies: Arc::new(Mutex::new(replies.into())),
            requests: Arc::default(),
        };
        let app = Router::new()
            .route("/", post(handler))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let mut provider = EdgeOne::new(
            client,
            "AKIDTestOnly".into(),
            "test-secret-not-real".into(),
            &options(),
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
            ttl: 300,
            record_id: None,
            create_if_missing: false,
            options: BTreeMap::new(),
        }
    }
    fn ok(response: Value) -> (u16, Value) {
        let mut response = response;
        response["RequestId"] = json!("request-test");
        (200, json!({"Response":response}))
    }
    fn page(array: &str, total: usize, records: Vec<Value>) -> (u16, Value) {
        ok(json!({"TotalCount":total,array:records}))
    }
    fn zone() -> (u16, Value) {
        page(
            "Zones",
            1,
            vec![
                json!({"ZoneId":"zone-test","ZoneName":"example.com","Type":"full","Status":"active","ActiveStatus":"active","LockStatus":"enable","Paused":false}),
            ],
        )
    }
    fn record(id: usize) -> Value {
        json!({"ZoneId":"zone-test","RecordId":format!("record-{id}"),"Name":"www.example.com","Type":"A","Content":"192.0.2.1","Location":"Default","TTL":300,"Weight":-1,"Priority":0,"Status":"enable","CreatedOn":"2024-09-18T05:03:46Z","ModifiedOn":"2024-09-18T05:03:46Z"})
    }
    fn snapshot(records: Vec<Value>) -> Vec<(u16, Value)> {
        vec![
            zone(),
            page("AccelerationDomains", 0, vec![]),
            page("ApplicationProxies", 0, vec![]),
            page("DnsRecords", records.len(), records),
        ]
    }
    fn requests(mock: &Mock) -> Vec<Request> {
        mock.state.requests.lock().unwrap().clone()
    }
    fn writes(mock: &Mock) -> usize {
        requests(mock)
            .iter()
            .filter(|r| r.0.starts_with("Modify") || r.0.starts_with("Create"))
            .count()
    }

    #[test]
    fn independent_python_golden_tc3_vector() {
        // Computed independently with Python stdlib hashlib/hmac and UTC date;
        // canonical SHA256 974a99da3c8dfaf76e803cd9292cd4294bccf5e4dde5cd02aeace955b1a0d9be.
        let payload = br#"{"ZoneId":"zone-test","Offset":0,"Limit":100}"#;
        let (auth, signature, _) = authorization(
            "AKIDTestOnly",
            "test-secret-not-real",
            "DescribeDnsRecords",
            payload,
            1551113065,
        )
        .unwrap();
        assert_eq!(
            signature,
            "2ade74fa3602a94c46bc2c32544541668f7cd59e2e1442d7345f65d4811e4e32"
        );
        assert_eq!(
            auth,
            "TC3-HMAC-SHA256 Credential=AKIDTestOnly/2019-02-25/teo/tc3_request, SignedHeaders=content-type;host;x-tc-action, Signature=2ade74fa3602a94c46bc2c32544541668f7cd59e2e1442d7345f65d4811e4e32"
        );
        assert_ne!(
            authorization(
                "AKIDTestOnly",
                "test-secret-not-real",
                "CreateDnsRecord",
                payload,
                1551113065
            )
            .unwrap()
            .1,
            signature
        );
        assert_ne!(
            authorization(
                "AKIDTestOnly",
                "test-secret-not-real",
                "DescribeDnsRecords",
                b"{}",
                1551113065
            )
            .unwrap()
            .1,
            signature
        );
        assert!(authorization("x", "y", "DescribeDnsRecords", b"{}", i64::MAX).is_none());
    }
    #[tokio::test]
    async fn required_configuration_and_origin_options_fail_before_requests() {
        let mut mock = mock(vec![]).await;
        for field in ["mode", "scope", "api_version", "zone_id"] {
            let mut options = options();
            options.remove(field);
            mock.provider.configuration_error = validate_options(&options).err();
            assert!(mock.provider.list(&spec()).await.is_err());
        }
        let mut options = options();
        options.insert("mode".into(), "origin".into());
        assert_eq!(
            validate_options(&options).unwrap_err().code,
            "UnsupportedMode"
        );
        options.insert("mode".into(), "dns".into());
        options.insert("GroupId".into(), "origin-test".into());
        assert_eq!(
            validate_options(&options).unwrap_err().code,
            "UnsupportedOptions"
        );
        assert!(requests(&mock).is_empty());
        assert_eq!(
            EdgeOne::new(reqwest::Client::new(), "id".into(), "key".into(), &options).endpoint(),
            ENDPOINT
        );
    }
    #[tokio::test]
    async fn validates_ttl_record_options_ip_and_native_ids_locally() {
        let mock = mock(vec![]).await;
        for ttl in [0, 59, 86401, u64::MAX] {
            let mut spec = spec();
            spec.ttl = ttl;
            assert_eq!(
                reconcile(&mock.provider, &spec, "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                "InvalidTtl"
            );
        }
        let mut s = spec();
        s.record_id = Some("origin-test".into());
        assert_eq!(
            mock.provider.list(&s).await.unwrap_err().code,
            "InvalidRecordId"
        );
        s.record_id = None;
        s.options.insert("GroupId".into(), "origin-test".into());
        assert_eq!(
            mock.provider.list(&s).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        assert_eq!(
            mock.provider
                .update(
                    &spec(),
                    &mock.provider.parse(record(1), &spec()).unwrap(),
                    "https://192.0.2.1:443"
                )
                .await
                .unwrap_err()
                .code,
            "InvalidIp"
        );
        assert_eq!(writes(&mock), 0);
        assert!(requests(&mock).is_empty());
    }
    #[tokio::test]
    async fn exact_zone_id_domain_full_type_and_status_required() {
        for (field, value, code) in [
            ("ZoneId", json!("zone-other"), "ZoneMismatch"),
            ("ZoneName", json!("other.com"), "ZoneMismatch"),
            ("Type", json!("partial"), "UnsupportedZoneType"),
            ("Type", json!("dnsPodAccess"), "UnsupportedZoneType"),
            ("Status", json!("pending"), "ZoneUnavailable"),
            ("Status", json!("moved"), "ZoneUnavailable"),
            ("ActiveStatus", json!("inactive"), "ZoneUnavailable"),
            ("LockStatus", json!("disable"), "ZoneUnavailable"),
            ("Paused", json!(true), "ZoneUnavailable"),
            ("Paused", Value::Null, "ZoneUnavailable"),
        ] {
            let mut zone = zone();
            zone.1["Response"]["Zones"][0][field] = value;
            let mock = mock(vec![zone]).await;
            assert_eq!(
                reconcile(&mock.provider, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(requests(&mock).len(), 1);
        }
    }
    #[tokio::test]
    async fn full_unfiltered_dns_pagination_preserves_native_fields() {
        let mut replies = snapshot(vec![]);
        replies.pop();
        let first = (1..=100)
            .map(|id| {
                let mut r = record(id);
                r["Name"] = json!(format!("host{id}.example.com"));
                r
            })
            .collect();
        replies.push(page("DnsRecords", 101, first));
        replies.push(page("DnsRecords", 101, vec![record(101)]));
        let mock = mock(replies).await;
        let list = mock.provider.list(&spec()).await.unwrap();
        assert_eq!(list.records.len(), 101);
        assert_eq!(list.records[100].extra, record(101));
        assert_eq!(list.records[100].ttl, 300);
        assert!(mock.provider.manages_ttl());
        let requests = requests(&mock);
        assert_eq!(
            requests[0].1["Filters"],
            json!([{"Name":"zone-id","Values":["zone-test"],"Fuzzy":false}])
        );
        assert_eq!(requests[3].0, "DescribeDnsRecords");
        assert_eq!(requests[3].1["Offset"], 0);
        assert_eq!(requests[4].1["Offset"], 100);
        assert!(requests[3].1.get("Filters").is_none());
    }
    #[tokio::test]
    async fn pagination_missing_counts_arrays_duplicates_and_truncation_fail_closed() {
        for response in [
            json!({"DnsRecords":[]}),
            json!({"TotalCount":0}),
            json!({"TotalCount":1,"DnsRecords":[]}),
            json!({"TotalCount":101,"DnsRecords":[record(1)]}),
            json!({"TotalCount":2,"DnsRecords":[record(1),record(1)]}),
            json!({"TotalCount":"0","DnsRecords":[]}),
            json!({"TotalCount":10001,"DnsRecords":[]}),
        ] {
            let mut replies = snapshot(vec![]);
            replies.pop();
            replies.push(ok(response));
            let mock = mock(replies).await;
            assert_eq!(
                mock.provider.list(&spec()).await.unwrap_err().code,
                "MalformedResponse"
            );
            assert_eq!(writes(&mock), 0);
        }
    }
    #[tokio::test]
    async fn changing_total_rejected_and_other_lists_also_paginated() {
        let mut replies = snapshot(vec![]);
        replies.pop();
        replies.push(page("DnsRecords", 101, (1..=100).map(record).collect()));
        replies.push(page("DnsRecords", 102, vec![record(101)]));
        let mock = mock(replies).await;
        assert_eq!(
            mock.provider.list(&spec()).await.unwrap_err().code,
            "MalformedResponse"
        );
        let unrelated =
            |i| json!({"ZoneId":"zone-test","DomainName":format!("host{i}.example.com")});
        let mock = self::mock(vec![
            zone(),
            page(
                "AccelerationDomains",
                101,
                (0..100).map(unrelated).collect(),
            ),
            page("AccelerationDomains", 101, vec![unrelated(100)]),
            page("ApplicationProxies", 0, vec![]),
            page("DnsRecords", 0, vec![]),
        ])
        .await;
        assert!(
            mock.provider
                .list(&spec())
                .await
                .unwrap()
                .records
                .is_empty()
        );
        assert_eq!(requests(&mock)[2].1["Offset"], 100);
    }
    #[tokio::test]
    async fn acceleration_pending_offline_wildcard_and_four_layer_targets_rejected() {
        for name in ["www.example.com", "*.example.com"] {
            let mock = mock(vec![zone(), page("AccelerationDomains", 1, vec![json!({"ZoneId":"zone-test","DomainName":name,"DomainStatus":"offline","OriginDetail":{"Origin":"192.0.2.1"}})])]).await;
            assert_eq!(
                reconcile(&mock.provider, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                "ManagedTraffic"
            );
            assert_eq!(writes(&mock), 0);
        }
        let mock = mock(vec![zone(), page("AccelerationDomains", 0, vec![]), page("ApplicationProxies", 1, vec![json!({"ZoneId":"zone-test","ProxyId":"proxy-test","ProxyType":"hostname","ProxyName":"www.example.com","Status":"offline","ApplicationProxyRules":[{"Proto":"TCP","Port":["443"],"Origin":["192.0.2.1"]}]})])]).await;
        assert_eq!(
            reconcile(&mock.provider, &spec(), "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "ManagedTraffic"
        );
        assert_eq!(writes(&mock), 0);
    }
    #[tokio::test]
    async fn cname_delegated_ns_disabled_and_duplicate_targets_fail_before_noop() {
        for kind in ["CNAME", "NS"] {
            let mut conflict = record(2);
            conflict["Type"] = json!(kind);
            conflict["Status"] = json!("disable");
            let mock = mock(snapshot(vec![record(1), conflict])).await;
            assert_eq!(
                reconcile(&mock.provider, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                "DnsConflict"
            );
        }
        let mock = mock(snapshot(vec![record(1), record(2)])).await;
        assert_eq!(
            reconcile(&mock.provider, &spec(), "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "AmbiguousRecords"
        );
        let mut disabled = record(1);
        disabled["Status"] = json!("disable");
        let mock = self::mock(snapshot(vec![disabled])).await;
        assert_eq!(
            reconcile(&mock.provider, &spec(), "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "RecordDisabled"
        );
    }
    #[tokio::test]
    async fn unknown_control_zero_weight_invalid_value_and_missing_id_before_noop() {
        for (field, value, code) in [
            ("Proxy", json!(false), "UnsupportedControlFields"),
            ("Weight", json!(0), "RecordDisabled"),
            ("Weight", Value::Null, "InvalidControlFields"),
            ("Content", json!("192.0.2.1:443"), "InvalidRecordValue"),
            ("Content", json!("2001:db8::1"), "InvalidRecordValue"),
        ] {
            let mut record = record(1);
            record[field] = value;
            let mock = mock(snapshot(vec![record])).await;
            assert_eq!(
                reconcile(&mock.provider, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(writes(&mock), 0);
        }
        let mock = mock(snapshot(vec![record(1)])).await;
        let mut s = spec();
        s.record_id = Some("record-missing".into());
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&mock.provider, &s, "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "RecordIdNotFound"
        );
        assert_eq!(writes(&mock), 0);
    }
    #[tokio::test]
    async fn noop_and_dry_run_have_no_writes_and_ttl_only_is_real_update() {
        for (ip, ttl, status) in [
            ("192.0.2.1", 300, "unchanged"),
            ("192.0.2.99", 300, "would_update"),
            ("192.0.2.1", 600, "would_update"),
        ] {
            let mock = mock(snapshot(vec![record(1)])).await;
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(
                reconcile(&mock.provider, &s, ip, true)
                    .await
                    .unwrap()
                    .status,
                status
            );
            assert_eq!(writes(&mock), 0);
        }
    }
    #[tokio::test]
    async fn update_uses_fresh_full_snapshot_partial_patch_and_strict_postread() {
        let mut before = record(1);
        before["Location"] = json!("CN.BJ");
        before["Weight"] = json!(37);
        before["Priority"] = json!(5);
        let mut after = before.clone();
        after["Content"] = json!("192.0.2.99");
        after["TTL"] = json!(600);
        after["ModifiedOn"] = json!("2026-01-01T00:00:00Z");
        let mut replies = snapshot(vec![before.clone()]);
        replies.extend(snapshot(vec![before.clone()]));
        replies.push(ok(json!({})));
        replies.extend(snapshot(vec![after]));
        let mock = mock(replies).await;
        let mut s = spec();
        s.record_id = Some("record-1".into());
        s.ttl = 600;
        assert_eq!(
            reconcile(&mock.provider, &s, "192.0.2.99", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let reqs = requests(&mock);
        assert_eq!(reqs.len(), 13);
        assert_eq!(writes(&mock), 1);
        assert_eq!(reqs[8].0, "ModifyDnsRecords");
        assert_eq!(
            reqs[8].1,
            json!({"ZoneId":"zone-test","DnsRecords":[{"RecordId":"record-1","Content":"192.0.2.99","TTL":600}]})
        );
    }
    #[tokio::test]
    async fn concurrent_snapshot_changes_prevent_write() {
        let mut changed = record(1);
        changed["Weight"] = json!(37);
        let mut replies = snapshot(vec![record(1)]);
        replies.extend(snapshot(vec![changed]));
        let mock = mock(replies).await;
        assert_eq!(
            reconcile(&mock.provider, &spec(), "192.0.2.99", false)
                .await
                .unwrap_err()
                .code,
            "ConcurrentRecord"
        );
        assert_eq!(writes(&mock), 0);
    }
    #[tokio::test]
    async fn new_duplicates_in_fresh_snapshots_are_not_silently_selected() {
        let mut replies = snapshot(vec![record(1)]);
        replies.extend(snapshot(vec![record(1), record(2)]));
        let mock = mock(replies).await;
        assert_eq!(
            reconcile(&mock.provider, &spec(), "192.0.2.99", false)
                .await
                .unwrap_err()
                .code,
            "ConcurrentRecord"
        );
        assert_eq!(writes(&mock), 0);
        let mut after = record(1);
        after["Content"] = json!("192.0.2.99");
        let mut replies = snapshot(vec![record(1)]);
        replies.extend(snapshot(vec![record(1)]));
        replies.push(ok(json!({})));
        replies.extend(snapshot(vec![after, record(2)]));
        let mock = self::mock(replies).await;
        assert_eq!(
            reconcile(&mock.provider, &spec(), "192.0.2.99", false)
                .await
                .unwrap_err()
                .code,
            "WriteOutcomeUncertain"
        );
        assert_eq!(writes(&mock), 1);
    }
    #[tokio::test]
    async fn pending_postread_changed_controls_or_missing_record_are_uncertain_not_success() {
        for after in [
            vec![record(1)],
            vec![],
            vec![{
                let mut r = record(1);
                r["Content"] = json!("192.0.2.99");
                r["Weight"] = json!(37);
                r
            }],
        ] {
            let mut replies = snapshot(vec![record(1)]);
            replies.extend(snapshot(vec![record(1)]));
            replies.push(ok(json!({})));
            replies.extend(snapshot(after));
            let mock = mock(replies).await;
            let err = reconcile(&mock.provider, &spec(), "192.0.2.99", false)
                .await
                .unwrap_err();
            assert_eq!(err.code, "WriteOutcomeUncertain");
            assert_eq!(err.request_id.as_deref(), Some("request-test"));
            assert!(!err.retryable);
            assert_eq!(writes(&mock), 1);
        }
    }
    #[tokio::test]
    async fn native_dns_create_requires_optin_real_ack_and_postread() {
        let mut new = record(9);
        new["Content"] = json!("192.0.2.99");
        let mut replies = snapshot(vec![]);
        replies.extend(snapshot(vec![]));
        replies.push(ok(json!({"RecordId":"record-9"})));
        replies.extend(snapshot(vec![new]));
        let mock = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        let outcome = reconcile(&mock.provider, &s, "192.0.2.99", false)
            .await
            .unwrap();
        assert_eq!(outcome.status, "created");
        assert_eq!(outcome.record_id.as_deref(), Some("record-9"));
        assert_eq!(writes(&mock), 1);
        assert_eq!(
            requests(&mock)[8].1,
            json!({"ZoneId":"zone-test","Name":"www.example.com","Type":"A","Content":"192.0.2.99","Location":"Default","TTL":300,"Weight":-1})
        );
    }
    #[tokio::test]
    async fn no_origin_create_or_rrset_extension_even_dry_run() {
        let mock = mock(vec![]).await;
        assert_eq!(
            mock.provider
                .create(&spec(), "192.0.2.99")
                .await
                .unwrap_err()
                .code,
            "CreationRefused"
        );
        assert!(requests(&mock).is_empty());
        let mut r = record(1);
        r["Location"] = json!("CN.BJ");
        let mock = self::mock(snapshot(vec![r])).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&mock.provider, &s, "192.0.2.99", true)
                .await
                .unwrap_err()
                .code,
            "CreationRefused"
        );
        assert_eq!(writes(&mock), 0);
    }
    #[tokio::test]
    async fn missing_requestid_write_ack_and_business_failure_never_retry() {
        for response in [
            json!({"Response":{}}),
            json!({"Response":{"RequestId":"request-test","Error":null}}),
            json!({"Response":{"RequestId":"request-test","Error":{"Code":"InvalidParameter.TTL","Message":"TTL rejected"}}}),
        ] {
            let mut replies = snapshot(vec![record(1)]);
            replies.extend(snapshot(vec![record(1)]));
            replies.push((403, response));
            let mock = mock(replies).await;
            let error = reconcile(&mock.provider, &spec(), "192.0.2.99", false)
                .await
                .unwrap_err();
            assert!(!error.retryable);
            assert_eq!(writes(&mock), 1);
            assert_eq!(requests(&mock).len(), 9);
        }
        let mut replies = snapshot(vec![]);
        replies.push(ok(json!({})));
        let mock = mock(replies).await;
        let mut s = spec();
        s.create_if_missing = true;
        let error = mock.provider.create(&s, "192.0.2.99").await.unwrap_err();
        assert_eq!(error.code, "MalformedResponse");
        assert!(error.message.contains("uncertain"));
        assert_eq!(writes(&mock), 1);
    }
    #[tokio::test]
    async fn generated_signature_and_keys_sanitized_with_original_business_dto() {
        let mock = mock(vec![(403, json!("echo-signature"))]).await;
        let error = mock.provider.list(&spec()).await.unwrap_err();
        assert_eq!(error.code, "AuthFailure.SignatureFailure");
        assert_eq!(error.http_status, Some(403));
        assert!(error.message.contains("Rejected key"));
        assert!(error.request_id.is_none());
        let req = requests(&mock);
        let auth = req[0].2["authorization"].to_str().unwrap();
        let signature = auth.split("Signature=").nth(1).unwrap();
        let dto = serde_json::to_string(&error).unwrap();
        for secret in ["AKIDTestOnly", "test-secret-not-real", signature, auth] {
            assert!(!dto.contains(secret));
        }
    }
    #[tokio::test]
    async fn malformed_envelope_http_error_and_response_size_are_bounded() {
        for (status, body, code) in [
            (200, json!({}), "MalformedResponse"),
            (
                503,
                json!({"Response":{"RequestId":"request-test"}}),
                "Http503",
            ),
            (
                200,
                json!({"Response":{"RequestId":"request-test","Error":{"Code":"OperationDenied","Message":"x".repeat(10000)}}}),
                "OperationDenied",
            ),
            (
                200,
                json!({"Response":{"RequestId":"request-test","Error":{"Code":"OperationDenied","Message":"x".repeat(1024*1024)}}}),
                "ResponseTooLarge",
            ),
        ] {
            let mock = mock(vec![(status, body)]).await;
            let error = mock.provider.list(&spec()).await.unwrap_err();
            assert_eq!(error.code, code);
            assert!(error.message.len() < 2500);
            assert_eq!(writes(&mock), 0);
        }
    }
    #[tokio::test]
    async fn redirects_never_forward_authentication_and_delegated_ancestors_fail() {
        let mock = mock(vec![(
            307,
            json!({"Redirect":"http://127.0.0.1:1/stolen","Response":{"RequestId":"request-test"}}),
        )])
        .await;
        assert_eq!(
            mock.provider.list(&spec()).await.unwrap_err().code,
            "Http307"
        );
        assert_eq!(requests(&mock).len(), 1);
        let mut delegated = record(2);
        delegated["Type"] = json!("NS");
        delegated["Name"] = json!("child.example.com");
        let mock = self::mock(snapshot(vec![delegated])).await;
        let mut s = spec();
        s.subdomain = "www.child".into();
        assert_eq!(
            reconcile(&mock.provider, &s, "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "DnsConflict"
        );
        assert_eq!(writes(&mock), 0);
        let mut apex = record(2);
        apex["Type"] = json!("NS");
        apex["Name"] = json!("example.com");
        let mock = self::mock(snapshot(vec![record(1), apex])).await;
        assert_eq!(
            reconcile(&mock.provider, &spec(), "192.0.2.1", true)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
    }
    #[tokio::test]
    async fn aaaa_native_record_keeps_literal_family_and_ttl() {
        let mut s = spec();
        s.record_type = "AAAA".into();
        let mut r = record(1);
        r["Type"] = json!("AAAA");
        r["Content"] = json!("2001:db8::1");
        let mock = mock(snapshot(vec![r])).await;
        assert_eq!(
            reconcile(&mock.provider, &s, "2001:db8::1", true)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert_eq!(writes(&mock), 0);
    }
}
