//! Gcore DNS v2: native RRset PUT is a full replacement, not a member update.
//! Sources (OpenAPI version cf9de6156f72, checked 2026-11-09):
//! https://docs.gcore.com/api-reference/dns/rrsets/update-rrset
//! https://docs.gcore.com/api-reference/dns/rrsets/list-of-rrset
//! https://docs.gcore.com/api-reference/dns/zones/get-zone
//! https://docs.gcore.com/dns (plan minimum TTLs: 120 / 30 / 1 seconds).
//! Only singleton static RRsets are writable. Unknown fields fail closed rather
//! than disappearing in PUT. Member IDs are output-only; diagnostics expose a
//! synthetic, stable RRset identity. The caller MUST disable HTTP redirects.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use reqwest::{Method, RequestBuilder};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};

const ENDPOINT: &str = "https://api.gcore.com/dns/v2";
const PAGE_SIZE: usize = 100;
const RECORD_LIMIT: usize = 10000;
// No Debug: credentials must never appear in diagnostics.
pub struct Gcore {
    api: Api,
    token: String,
    plan: String,
    invalid_options: bool,
    #[cfg(test)]
    endpoint: String,
}
impl Gcore {
    pub fn new(client: reqwest::Client, token: String, options: &BTreeMap<String, String>) -> Self {
        Self {
            api: Api::new(client, vec![token.clone()]),
            token,
            plan: options
                .get("plan")
                .cloned()
                .unwrap_or_else(|| "free".into()),
            invalid_options: options.keys().any(|key| key != "plan"),
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
        let request = self
            .api
            .client
            .request(method, format!("{}{path}", self.endpoint()));
        match reqwest::header::HeaderValue::from_str(&format!("APIKey {}", self.token)) {
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
            "Check the exact hosted primary zone, API token and DNS read/write permissions. Use a dedicated enabled single-IP static RRset; record_id identifies an RRset, not a numeric member. Declare your actual plan for TTL validation. For 429 respect Retry-After; for 5xx check provider availability. Inspect uncertain writes before retrying. Gcore has no documented conditional RRset write; use one writer.", reply)
    }
    fn validate(&self, spec: &Spec) -> Result<(), ProviderError> {
        if self.invalid_options || !spec.options.is_empty() {
            return Err(self.error(
                "validation",
                "UnsupportedOptions",
                "Only provider.options.plan is supported; Gcore record options are unsupported.",
                None,
            ));
        }
        if !matches!(spec.record_line.as_str(), "" | "默认" | "default") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordLine",
                "Gcore has no record-line selector; custom routing lines are refused.",
                None,
            ));
        }
        if self.token.trim().is_empty()
            || reqwest::header::HeaderValue::from_str(&format!("APIKey {}", self.token)).is_err()
        {
            return Err(self.error(
                "validation",
                "InvalidApiToken",
                "A nonempty valid API token is required; credential contents omitted.",
                None,
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Gcore DDNS supports only A and AAAA.",
                None,
            ));
        }
        if !hostname(&spec.domain, false)
            || (spec.subdomain != "@" && !hostname(&spec.subdomain, false))
            || spec.fqdn().len() > 253
        {
            return Err(self.error("validation", "InvalidDnsName", "Use an exact ASCII/punycode hosted zone and relative hostname, or @ for apex; no URL syntax.", None));
        }
        let minimum = match self.plan.as_str() {
            "free" => 120, "pro" => 30, "enterprise" => 1,
            _ => return Err(self.error("validation", "InvalidPlan", "Gcore plan must be free, pro or enterprise (actual account plan, not an override of provider policy).", None)),
        };
        if spec.ttl < minimum || spec.ttl > u32::MAX as u64 {
            return Err(self.error("validation", "UnsupportedTTL", &format!("Requested TTL must be at least {minimum} seconds for the declared Gcore plan and fit the documented uint32 schema (maximum 4294967295); never clamped. Account-specific policy is not exposed by the documented API."), None));
        }
        Ok(())
    }
    fn ip(&self, spec: &Spec, ip: &str) -> Result<String, ProviderError> {
        self.validate(spec)?;
        let parsed = ip.parse::<IpAddr>().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be a plain IP address.",
                None,
            )
        })?;
        if parsed.is_ipv4() != (spec.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "Desired IP family does not match target type.",
                None,
            ));
        }
        Ok(parsed.to_string())
    }
    fn check(&self, stage: &str, reply: &HttpReply, write: bool) -> Result<(), ProviderError> {
        let business_error = reply.status == 200
            && !reply.body["name"].is_string()
            && !reply.body["rrsets"].is_array()
            && ["error", "errors", "message", "detail"]
                .iter()
                .any(|k| reply.body.get(k).is_some());
        if reply.status != 200 || business_error {
            let code = if business_error {
                "ProviderApiError".into()
            } else if (200..300).contains(&reply.status) {
                "InvalidWriteAcknowledgement".into()
            } else {
                format!("Http{}", reply.status)
            };
            let mut detail = error_details(&reply.body);
            if let Some(header) = reply.headers.get("error").and_then(|h| h.to_str().ok()) {
                let text: String = header.chars().take(256).collect();
                detail.push_str(&format!(" Provider error header: {}", self.api.safe(&text)));
            }
            if let Some(header) = reply
                .headers
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|h| h.to_str().ok())
            {
                let text: String = header.chars().take(128).collect();
                detail.push_str(&format!(" Retry-After: {}", self.api.safe(&text)));
            }
            let mut e = self.error(
                stage,
                &code,
                &format!("Gcore API rejected the request. {detail}"),
                Some(reply),
            );
            e.retryable = !write && (reply.status == 429 || reply.status >= 500);
            return Err(e);
        }
        Ok(())
    }
    async fn zone(&self, spec: &Spec) -> Result<(), ProviderError> {
        self.validate(spec)?;
        let stage = "GcoreGetZone";
        let reply = self
            .api
            .send(
                stage,
                self.request(
                    Method::GET,
                    &format!("/zones/{}", spec.domain.to_ascii_lowercase()),
                ),
                false,
            )
            .await?;
        self.check(stage, &reply, false)?;
        if !reply.body["name"]
            .as_str()
            .is_some_and(|name| dns_equal(name, &spec.domain))
        {
            return Err(self.error(stage, "ZoneMismatch", "Provider did not confirm the exact hosted zone name; parent and child zones are not interchangeable.", Some(&reply)));
        }
        // enabled has an official default of true. status is merely a string in
        // OpenAPI: do not invent an 'active' enum or require a numeric zone ID.
        if !default_enabled(&reply.body).ok_or_else(|| {
            self.error(
                stage,
                "InvalidZone",
                "Zone enabled flag is malformed.",
                Some(&reply),
            )
        })? {
            return Err(self.error(
                stage,
                "ZoneDisabled",
                "Hosted zone is disabled; it will not be enabled or written by DDNS.",
                Some(&reply),
            ));
        }
        if let Some(meta) = reply.body.get("meta") {
            if !meta.is_object() {
                return Err(self.error(
                    stage,
                    "InvalidZone",
                    "Zone metadata is malformed.",
                    Some(&reply),
                ));
            }
            if meta
                .get("is_secondary")
                .is_some_and(|v| v != &Value::Bool(false))
            {
                return Err(self.error(
                    stage,
                    "SecondaryZone",
                    "AXFR secondary zones are not writable DDNS targets.",
                    Some(&reply),
                ));
            }
        }
        Ok(())
    }
    fn rrset(
        &self,
        spec: &Spec,
        v: &Value,
        reply: &HttpReply,
        stage: &str,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error(stage, "InvalidRRset", "RRset has missing or malformed name, type, TTL, records or settings; response contents omitted.", Some(reply))
        };
        let name = v["name"]
            .as_str()
            .ok_or_else(bad)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let zone = spec.domain.to_ascii_lowercase();
        if !hostname(&name, true) || !(name == zone || name.ends_with(&format!(".{zone}"))) {
            return Err(self.error(
                stage,
                "RRsetMismatch",
                "Listed RRset is outside the exact hosted zone.",
                Some(reply),
            ));
        }
        let kind = v["type"]
            .as_str()
            .filter(|s| {
                !s.is_empty()
                    && s.len() <= 16
                    && s.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            })
            .ok_or_else(bad)?;
        let ttl = v["ttl"]
            .as_u64()
            .filter(|t| *t <= u32::MAX as u64)
            .ok_or_else(bad)?;
        let members = v["resource_records"]
            .as_array()
            .filter(|m| m.len() <= RECORD_LIMIT)
            .ok_or_else(bad)?;
        if v.get("meta").is_some_and(|m| !m.is_object())
            || v.get("pickers").is_some_and(|p| !p.is_array())
        {
            return Err(bad());
        }
        for m in members {
            if !m.is_object()
                || !m["content"].is_array()
                || default_enabled(m).is_none()
                || m.get("meta").is_some_and(|m| !m.is_object())
                || m.get("id").is_some_and(|id| id.as_u64().is_none())
            {
                return Err(bad());
            }
        }
        let value = if members.len() == 1 && matches!(kind, "A" | "AAAA") {
            singleton_ip(&members[0], kind).unwrap_or_default()
        } else {
            String::new()
        };
        let enabled = members.len() == 1 && default_enabled(&members[0]) == Some(true);
        Ok(Record {
            id: rrset_id(kind, &name),
            name,
            record_type: kind.into(),
            value,
            ttl,
            enabled,
            line: String::new(),
            extra: v.clone(),
        })
    }
    fn selection(&self, spec: &Spec, record: &Record) -> Result<(), ProviderError> {
        if record.id != rrset_id(&spec.record_type, &spec.fqdn())
            || spec.record_id.as_ref().is_some_and(|id| id != &record.id)
            || !dns_equal(&record.name, &spec.fqdn())
            || record.record_type != spec.record_type
            || !record.extra["name"]
                .as_str()
                .is_some_and(|n| dns_equal(n, &spec.fqdn()))
            || record.extra["type"].as_str() != Some(spec.record_type.as_str())
            || record.extra["ttl"].as_u64() != Some(record.ttl)
        {
            return Err(self.error("selection", "RRsetMismatch", "Selected synthetic RRset identity/name/type/TTL contradicts the configured target.", None));
        }
        let members = record.extra["resource_records"].as_array().ok_or_else(|| {
            self.error(
                "selection",
                "InvalidRRset",
                "Selected RRset lacks resource records.",
                None,
            )
        })?;
        if members.len() != 1
            || members[0]["content"]
                .as_array()
                .is_none_or(|c| c.len() != 1)
        {
            return Err(self.error("selection", "UnsafeRRsetValues", "PUT replaces the entire RRset. DDNS refuses multiple resource records or multiple content values, including disabled values.", None));
        }
        if record
            .extra
            .get("pickers")
            .is_some_and(|p| p.as_array().is_none_or(|p| !p.is_empty()))
            || record.extra["meta"].get("failover").is_some()
            || record.extra["meta"].get("geodns_link").is_some()
            || record
                .extra
                .get("filter_set_id")
                .is_some_and(|v| v.as_u64() != Some(0))
        {
            return Err(self.error("selection", "DynamicRRset", "Dynamic, healthchecked or CDN-linked RRsets are not safe DDNS targets; no settings are removed.", None));
        }
        if !known_keys(
            &record.extra,
            &[
                "name",
                "type",
                "ttl",
                "resource_records",
                "meta",
                "pickers",
                "filter_set_id",
                "updated_at",
                "warning",
                "warnings",
            ],
        ) || !known_keys(&members[0], &["id", "content", "enabled", "meta"])
            || record.extra.get("meta").is_some_and(|m| !m.is_object())
            || members[0].get("meta").is_some_and(|m| !m.is_object())
        {
            return Err(self.error("selection", "UnknownRRsetSettings", "Undocumented settings cannot be safely preserved by the documented PUT input schema; no write attempted.", None));
        }
        if record.extra.get("meta").is_some_and(|m| !notes_only(m))
            || members[0].get("meta").is_some_and(|m| !notes_only(m))
        {
            return Err(self.error("selection", "UnsafeMetadata", "Static singleton DDNS only permits empty metadata or string notes. Routing, backup and unknown metadata are refused rather than removed.", None));
        }
        if singleton_ip(&members[0], &spec.record_type).as_deref() != Some(&record.value)
            || record.value.is_empty()
        {
            return Err(self.error(
                "selection",
                "InvalidRecordValue",
                "Selected singleton content is not a valid IP of the target family.",
                None,
            ));
        }
        if default_enabled(&members[0]) != Some(record.enabled) || !record.enabled {
            return Err(self.error("selection", "RecordDisabled", "Selected member is disabled or its enabled metadata is inconsistent; DDNS never enables it.", None));
        }
        Ok(())
    }
    fn payload(&self, spec: &Spec, record: Option<&Record>, ip: &str) -> Value {
        let mut body =
            json!({"ttl": spec.ttl, "resource_records": [{"content": [ip], "enabled": true}]});
        if let Some(record) = record {
            // Only documented InputRRSet / InputResourceRecord fields. Native
            // member id, filter_set_id, timestamps and warnings are output-only.
            for key in ["meta", "pickers"] {
                if let Some(v) = record.extra.get(key) {
                    body[key] = v.clone();
                }
            }
            if let Some(v) = record.extra["resource_records"][0].get("meta") {
                body["resource_records"][0]["meta"] = v.clone();
            }
        }
        body
    }
    fn path(spec: &Spec) -> String {
        format!(
            "/zones/{}/{}/{}",
            spec.domain.to_ascii_lowercase(),
            spec.fqdn().to_ascii_lowercase(),
            spec.record_type
        )
    }
    fn acknowledge(
        &self,
        spec: &Spec,
        reply: &HttpReply,
        stage: &str,
        expected: &Value,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.check(stage, reply, true)?;
        // OutputRRSet requires name/type/resource_records, but TTL and settings
        // are optional. Require only documented identity and resource records;
        // a separate GET verifies effective TTL/settings after the write.
        let members = reply.body["resource_records"].as_array();
        let invalid_members = members.is_none_or(|m| {
            m.len() != 1
                || singleton_ip(&m[0], &spec.record_type).as_deref() != Some(ip)
                || default_enabled(&m[0]) != Some(true)
        });
        let optional_contradiction = reply
            .body
            .get("ttl")
            .is_some_and(|t| t.as_u64() != Some(spec.ttl))
            || ["meta", "pickers"].iter().any(|key| {
                reply.body.get(*key).is_some_and(|v| {
                    let default = if *key == "pickers" {
                        json!([])
                    } else {
                        json!({})
                    };
                    v != expected.get(*key).unwrap_or(&default)
                })
            })
            || members.is_some_and(|m| {
                m.len() == 1
                    && m[0].get("meta").is_some_and(|v| {
                        v != expected["resource_records"][0]
                            .get("meta")
                            .unwrap_or(&json!({}))
                    })
            });
        if !reply.body["name"]
            .as_str()
            .is_some_and(|n| dns_equal(n, &spec.fqdn()))
            || reply.body["type"].as_str() != Some(spec.record_type.as_str())
            || invalid_members
            || optional_contradiction
        {
            return Err(self.error(stage, "InvalidWriteAcknowledgement", "Write response does not acknowledge the documented target RRset identity and resource records; inspect uncertain write before retrying.", Some(reply)));
        }
        Ok(Mutation {
            record_id: rrset_id(&spec.record_type, &spec.fqdn()),
            request_id: reply.request_id.clone(),
        })
    }
    async fn write(
        &self,
        spec: &Spec,
        record: Option<&Record>,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let stage = if record.is_some() {
            "GcoreUpdateRRset"
        } else {
            "GcoreCreateRRset"
        };
        let body = self.payload(spec, record, ip);
        let reply = self
            .api
            .send(
                stage,
                self.request(
                    if record.is_some() {
                        Method::PUT
                    } else {
                        Method::POST
                    },
                    &Self::path(spec),
                )
                .json(&body),
                true,
            )
            .await?;
        let mutation = self.acknowledge(spec, &reply, stage, &body, ip)?;
        let read = self.api.send("GcoreVerifyRRset", self.request(Method::GET, &Self::path(spec)), false).await.map_err(|mut e| { e.retryable = false; e.hint = "A write was accepted but verification failed; inspect Gcore before retrying. No automatic write retry occurs.".into(); e })?;
        self.check("GcoreVerifyRRset", &read, true)?;
        let fresh = self.rrset(spec, &read.body, &read, "GcoreVerifyRRset")?;
        self.selection(spec, &fresh).map_err(|e| {
            self.error(
                "GcoreVerifyRRset",
                &e.code,
                &format!("Accepted write could not be safely verified. {}", e.message),
                Some(&read),
            )
        })?;
        let effective = self.payload(spec, Some(&fresh), &fresh.value);
        // Providers may materialize documented defaults for optional empty
        // meta/pickers. Compare meanings without requiring guessed echoes.
        if fresh.value != ip || fresh.ttl != spec.ttl || !settings_equal(&body, &effective) {
            return Err(self.error("GcoreVerifyRRset", "WriteVerificationFailed", "Read-after-write did not confirm desired IP, TTL and preserved settings. Result is uncertain; inspect Gcore before retrying.", Some(&read)));
        }
        Ok(mutation)
    }
}
impl Adapter for Gcore {
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
            self.selection(spec, record)?;
        }
        Ok(())
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        self.zone(spec).await?;
        let stage = "GcoreListRRsets";
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        for _ in 0..100 {
            let offset = records.len();
            let reply = self
                .api
                .send(
                    stage,
                    self.request(
                        Method::GET,
                        &format!("/zones/{}/rrsets", spec.domain.to_ascii_lowercase()),
                    )
                    .query(&[
                        ("limit", PAGE_SIZE.to_string()),
                        ("offset", offset.to_string()),
                        ("order_by", "name".into()),
                        ("order_direction", "asc".into()),
                    ]),
                    false,
                )
                .await?;
            self.check(stage, &reply, false)?;
            let amount = reply.body["total_amount"]
                .as_u64()
                .filter(|n| *n <= RECORD_LIMIT as u64)
                .ok_or_else(|| {
                    self.error(
                        stage,
                        "InvalidPagination",
                        "Missing, negative or excessive total_amount; no partial list returned.",
                        Some(&reply),
                    )
                })? as usize;
            if total.is_some_and(|n| n != amount) {
                return Err(self.error(
                    stage,
                    "UnstablePagination",
                    "total_amount changed during pagination; no partial list returned.",
                    Some(&reply),
                ));
            }
            total = Some(amount);
            let values = reply.body["rrsets"]
                .as_array()
                .filter(|v| v.len() <= PAGE_SIZE)
                .ok_or_else(|| {
                    self.error(
                        stage,
                        "InvalidPagination",
                        "RRsets page is malformed or exceeds requested page size.",
                        Some(&reply),
                    )
                })?;
            if offset + values.len() > amount
                || values.len() != PAGE_SIZE.min(amount.saturating_sub(offset))
            {
                return Err(self.error(
                    stage,
                    "InvalidPagination",
                    "RRsets page contradicts total_amount or makes no progress.",
                    Some(&reply),
                ));
            }
            for v in values {
                let r = self.rrset(spec, v, &reply, stage)?;
                if !ids.insert(r.id.clone()) {
                    return Err(self.error(
                        stage,
                        "UnstablePagination",
                        "Repeated RRset identity across pages; no partial list returned.",
                        Some(&reply),
                    ));
                }
                records.push(r);
            }
            if records.len() == amount {
                let target = spec.fqdn().to_ascii_lowercase();
                let zone = spec.domain.to_ascii_lowercase();
                if records
                    .iter()
                    .any(|r| r.record_type == "CNAME" && dns_equal(&r.name, &target))
                {
                    return Err(self.error(stage, "ConflictingCNAME", "Target owner has a CNAME; A/AAAA creation and dry-run creation are refused.", Some(&reply)));
                }
                if records.iter().any(|r| {
                    r.record_type == "NS"
                        && r.name != zone
                        && (target == r.name || target.ends_with(&format!(".{}", r.name)))
                }) {
                    return Err(self.error(stage, "DelegatedTarget", "Target is at or below an NS-delegated child; configure the exact authoritative child zone.", Some(&reply)));
                }
                return Ok(List {
                    records,
                    request_id: reply.request_id,
                });
            }
        }
        Err(self.error(
            stage,
            "PaginationLimit",
            "More than 100 pages; no partial list returned.",
            None,
        ))
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.ip(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error("create", "CreationNotAllowed", "Creation requires create_if_missing and no explicit record_id; no update fallback.", None));
        }
        // Fresh full authoritative-zone/list verification even when called
        // directly or when a record appeared after reconcile's first list.
        let fresh = self.list(spec).await?;
        if fresh.records.iter().any(|r| {
            dns_equal(&r.name, &spec.fqdn())
                && (r.record_type == spec.record_type || r.record_type == "CNAME")
        }) {
            return Err(self.error("create", "RecordAppeared", "Target RRset or conflicting CNAME exists on the fresh full list; creation refused.", None));
        }
        self.write(spec, None, &ip).await
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let ip = self.ip(spec, ip)?;
        self.selection(spec, record)?;
        self.zone(spec).await?;
        let read = self
            .api
            .send(
                "GcoreGetRRset",
                self.request(Method::GET, &Self::path(spec)),
                false,
            )
            .await?;
        self.check("GcoreGetRRset", &read, false)?;
        let fresh = self.rrset(spec, &read.body, &read, "GcoreGetRRset")?;
        self.selection(spec, &fresh)?;
        // Equality includes every setting, disabled state, IDs and timestamps;
        // no stale snapshot replay into full PUT. Residual TOCTOU needs one writer.
        if fresh.extra != record.extra {
            return Err(self.error(
                "selection",
                "RRsetChanged",
                "RRset or metadata changed after selection; no write attempted.",
                Some(&read),
            ));
        }
        self.write(spec, Some(&fresh), &ip).await
    }
}
fn default_enabled(v: &Value) -> Option<bool> {
    match v.get("enabled") {
        None => Some(true),
        Some(v) => v.as_bool(),
    }
}
fn singleton_ip(v: &Value, kind: &str) -> Option<String> {
    let c = v["content"].as_array()?;
    if c.len() != 1 {
        return None;
    }
    let ip = c[0].as_str()?.parse::<IpAddr>().ok()?;
    (ip.is_ipv4() == (kind == "A")).then(|| ip.to_string())
}
fn known_keys(v: &Value, allowed: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.keys().all(|k| allowed.contains(&k.as_str())))
}
fn dns_equal(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}
fn hostname(name: &str, records: bool) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').enumerate().all(|(i, l)| {
            !l.is_empty()
                && l.len() <= 63
                && (records && i == 0 && l == "*"
                    || !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || b == b'-' || records && b == b'_'
                        }))
        })
}
fn rrset_id(kind: &str, name: &str) -> String {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let id = if name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    {
        format!("{kind}.{name}")
    } else {
        format!("{kind}._{}", hex::encode(name.as_bytes()))
    };
    if id.len() <= 128 {
        id
    } else {
        format!("{kind}..{}", hex::encode(Sha256::digest(id.as_bytes())))
    }
}
fn settings_equal(a: &Value, b: &Value) -> bool {
    let empty = json!({});
    let pickers = json!([]);
    a.get("meta").unwrap_or(&empty) == b.get("meta").unwrap_or(&empty)
        && a.get("pickers").unwrap_or(&pickers) == b.get("pickers").unwrap_or(&pickers)
        && a["resource_records"][0].get("meta").unwrap_or(&empty)
            == b["resource_records"][0].get("meta").unwrap_or(&empty)
        && default_enabled(&a["resource_records"][0]) == default_enabled(&b["resource_records"][0])
}
fn notes_only(v: &Value) -> bool {
    v.as_object().is_some_and(|m| {
        m.iter()
            .all(|(key, value)| key == "notes" && value.is_string())
    })
}
fn error_details(body: &Value) -> String {
    fn collect(v: &Value, depth: usize, out: &mut Vec<String>) {
        if depth > 3 || out.len() >= 12 {
            return;
        }
        match v {
            Value::String(s) => out.push(s.chars().take(256).collect()),
            Value::Array(items) => {
                for item in items.iter().take(12) {
                    collect(item, depth + 1, out);
                }
            }
            Value::Object(map) => {
                for key in ["code", "message", "detail", "details", "error", "errors"] {
                    if let Some(v) = map.get(key) {
                        collect(v, depth + 1, out);
                    }
                }
            }
            Value::Number(n) => out.push(n.to_string()),
            _ => {}
        }
    }
    let mut parts = Vec::new();
    collect(body, 0, &mut parts);
    if parts.is_empty() {
        "No recognized error details; raw provider response omitted.".into()
    } else {
        parts.join("; ")
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
    #[derive(Clone)]
    struct Captured {
        method: Method,
        uri: String,
        auth: Option<String>,
        body: Value,
    }
    struct Reply {
        status: u16,
        body: Value,
        raw: Option<&'static str>,
        trace: Option<&'static str>,
    }
    struct Data {
        replies: VecDeque<Reply>,
        requests: Vec<Captured>,
    }
    struct Mock {
        endpoint: String,
        state: Arc<Mutex<Data>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(State(state): State<Arc<Mutex<Data>>>, request: Request<Body>) -> Response {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let r = Captured {
            method: parts.method,
            uri: parts.uri.to_string(),
            auth: parts
                .headers
                .get("authorization")
                .map(|h| h.to_str().unwrap().into()),
            body: if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        };
        let reply = {
            let mut s = state.lock().unwrap();
            s.requests.push(r);
            s.replies.pop_front().expect("unexpected HTTP request")
        };
        let mut response = if reply.status == 204 {
            StatusCode::NO_CONTENT.into_response()
        } else if let Some(raw) = reply.raw {
            (StatusCode::from_u16(reply.status).unwrap(), raw).into_response()
        } else {
            (
                StatusCode::from_u16(reply.status).unwrap(),
                Json(reply.body),
            )
                .into_response()
        };
        if let Some(id) = reply.trace {
            response
                .headers_mut()
                .insert("x-request-id", HeaderValue::from_static(id));
        }
        response
    }
    impl Mock {
        async fn new(replies: Vec<Reply>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let state = Arc::new(Mutex::new(Data {
                replies: replies.into(),
                requests: vec![],
            }));
            let router = Router::new()
                .route("/{*path}", any(handler))
                .with_state(state.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            Self {
                endpoint,
                state,
                task,
            }
        }
        fn adapter(&self) -> Gcore {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let mut a = Gcore::new(client, "secret-test-token".into(), &BTreeMap::new());
            a.endpoint = self.endpoint.clone();
            a
        }
        fn requests(&self) -> Vec<Captured> {
            self.state.lock().unwrap().requests.clone()
        }
        fn done(&self) {
            assert!(self.state.lock().unwrap().replies.is_empty());
        }
        fn reads_only(&self) {
            assert!(self.requests().iter().all(|r| r.method == Method::GET));
            self.done();
        }
    }
    fn reply(status: u16, body: Value) -> Reply {
        Reply {
            status,
            body,
            raw: None,
            trace: None,
        }
    }
    fn zone() -> Reply {
        reply(200, json!({"name":"example.com","enabled":true}))
    }
    fn spec() -> Spec {
        Spec {
            domain: "example.com".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "默认".into(),
            ttl: 300,
            record_id: None,
            create_if_missing: true,
            options: BTreeMap::new(),
        }
    }
    fn rr(ip: &str) -> Value {
        json!({"name":"home.example.com","type":"A","ttl":300,"resource_records":[{"id":42,"content":[ip],"enabled":true,"meta":{"notes":"keep me"}}],"meta":{"notes":"zone settings"},"pickers":[],"filter_set_id":0,"updated_at":"2026-01-01T00:00:00Z","warnings":[]})
    }
    fn page(values: Vec<Value>, total: usize) -> Reply {
        reply(200, json!({"rrsets":values,"total_amount":total}))
    }
    fn list(v: Value) -> Reply {
        page(vec![v], 1)
    }
    fn other(name: &str) -> Value {
        let mut v = rr("192.0.2.1");
        v["name"] = json!(name);
        v
    }
    fn hundred() -> Vec<Value> {
        (0..100)
            .map(|i| other(&format!("other{i}.example.com")))
            .collect()
    }
    #[tokio::test]
    async fn exact_zone_native_member_stable_id_and_auth() {
        let mock = Mock::new(vec![zone(), list(rr("192.0.2.1"))]).await;
        let r = mock
            .adapter()
            .list(&spec())
            .await
            .unwrap()
            .records
            .remove(0);
        assert_eq!(r.id, "A.home.example.com");
        assert_eq!(r.extra["resource_records"][0]["id"], 42);
        assert_eq!(mock.requests()[0].uri, "/zones/example.com");
        assert_eq!(
            mock.requests()[1].uri,
            "/zones/example.com/rrsets?limit=100&offset=0&order_by=name&order_direction=asc"
        );
        for r in mock.requests() {
            assert_eq!(r.auth.as_deref(), Some("APIKey secret-test-token"));
            assert!(!r.uri.contains("secret"));
        }
        mock.reads_only();
    }
    #[tokio::test]
    async fn documented_enabled_default_no_zone_id_or_status_enum() {
        let mock = Mock::new(vec![
            reply(
                200,
                json!({"name":"EXAMPLE.COM.","status":"not-an-invented-enum"}),
            ),
            page(vec![], 0),
        ])
        .await;
        mock.adapter().list(&spec()).await.unwrap();
        mock.reads_only();
        let mut v = rr("192.0.2.1");
        v["resource_records"][0]
            .as_object_mut()
            .unwrap()
            .remove("enabled");
        let mock = Mock::new(vec![zone(), list(v)]).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.1", true)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn noop_dryrun_update_create_get_only() {
        for (values, ip, status) in [
            (vec![rr("192.0.2.1")], "192.0.2.1", "unchanged"),
            (vec![rr("192.0.2.1")], "192.0.2.2", "would_update"),
            (vec![], "192.0.2.2", "would_create"),
        ] {
            let n = values.len();
            let mock = Mock::new(vec![zone(), page(values, n)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), ip, true)
                    .await
                    .unwrap()
                    .status,
                status
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn update_preserves_writable_metadata_not_output_only_ids() {
        let old = rr("192.0.2.1");
        let mut new = rr("192.0.2.2");
        new["resource_records"][0]["id"] = json!(900);
        let mock = Mock::new(vec![
            zone(),
            list(old.clone()),
            zone(),
            reply(200, old),
            reply(200, new.clone()),
            reply(200, new),
        ])
        .await;
        let out = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
            .await
            .unwrap();
        assert_eq!(out.status, "updated");
        assert_eq!(out.record_id.as_deref(), Some("A.home.example.com"));
        let requests = mock.requests();
        let r = &requests[4];
        assert_eq!(r.method, Method::PUT);
        assert_eq!(r.uri, "/zones/example.com/home.example.com/A");
        assert_eq!(r.body["meta"], rr("192.0.2.1")["meta"]);
        assert_eq!(r.body["pickers"], json!([]));
        assert_eq!(
            r.body["resource_records"][0]["meta"],
            rr("192.0.2.1")["resource_records"][0]["meta"]
        );
        assert!(known_keys(
            &r.body,
            &["ttl", "meta", "pickers", "resource_records"]
        ));
        assert!(r.body["resource_records"][0].get("id").is_none());
        mock.done();
    }
    #[tokio::test]
    async fn create_a_aaaa_apex_post_verified_get_optional_ack_fields() {
        for (kind, host, ip) in [
            ("A", "home", "192.0.2.2"),
            ("AAAA", "home", "2001:0db8:0:0::2"),
            ("A", "@", "192.0.2.2"),
        ] {
            let mut s = spec();
            s.record_type = kind.into();
            s.subdomain = host.into();
            let canonical = ip.parse::<IpAddr>().unwrap().to_string();
            let v = json!({"name":s.fqdn(),"type":kind,"ttl":300,"resource_records":[{"content":[canonical],"enabled":true,"meta":{}}],"meta":{},"pickers":[]});
            let ack =
                json!({"name":s.fqdn(),"type":kind,"resource_records":[{"content":[canonical]}]});
            let mock = Mock::new(vec![
                zone(),
                page(vec![], 0),
                zone(),
                page(vec![], 0),
                reply(200, ack),
                reply(200, v),
            ])
            .await;
            assert_eq!(
                reconcile(&mock.adapter(), &s, ip, false)
                    .await
                    .unwrap()
                    .status,
                "created"
            );
            let requests = mock.requests();
            let r = &requests[4];
            assert_eq!(r.method, Method::POST);
            assert_eq!(r.uri, format!("/zones/example.com/{}/{kind}", s.fqdn()));
            assert_eq!(
                r.body,
                json!({"ttl":300,"resource_records":[{"content":[canonical],"enabled":true}]})
            );
            mock.done();
        }
    }
    #[tokio::test]
    async fn ttl_minima_declared_plans_and_uint32_even_dryrun() {
        for (plan, min) in [("free", 120), ("pro", 30), ("enterprise", 1)] {
            let mock = Mock::new(vec![]).await;
            let mut a = mock.adapter();
            a.plan = plan.into();
            let mut s = spec();
            for ttl in [0, min - 1, u32::MAX as u64 + 1] {
                s.ttl = ttl;
                assert_eq!(
                    reconcile(&a, &s, "192.0.2.1", true).await.unwrap_err().code,
                    "UnsupportedTTL"
                );
            }
            for ttl in [min, u32::MAX as u64] {
                s.ttl = ttl;
                a.validate(&s).unwrap();
            }
            assert!(mock.requests().is_empty());
            mock.done();
        }
        let mock = Mock::new(vec![]).await;
        let mut a = mock.adapter();
        a.plan = "invented".into();
        assert_eq!(a.validate(&spec()).unwrap_err().code, "InvalidPlan");
    }
    #[tokio::test]
    async fn zone_mismatch_disabled_secondary_invalid_flags_refused() {
        for (v, code) in [
            (json!({"name":"parent.com"}), "ZoneMismatch"),
            (
                json!({"name":"example.com","enabled":false}),
                "ZoneDisabled",
            ),
            (
                json!({"name":"example.com","meta":{"is_secondary":true}}),
                "SecondaryZone",
            ),
            (
                json!({"name":"example.com","enabled":"false"}),
                "InvalidZone",
            ),
            (json!({"name":"example.com","meta":null}), "InvalidZone"),
        ] {
            let mock = Mock::new(vec![reply(200, v)]).await;
            assert_eq!(mock.adapter().list(&spec()).await.unwrap_err().code, code);
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn multimember_multicontent_empty_disabled_rejected_even_noop() {
        for (v, code) in [
            (
                {
                    let mut v = rr("192.0.2.1");
                    let second = v["resource_records"][0].clone();
                    v["resource_records"].as_array_mut().unwrap().push(second);
                    v
                },
                "UnsafeRRsetValues",
            ),
            (
                {
                    let mut v = rr("192.0.2.1");
                    v["resource_records"][0]["content"] = json!(["192.0.2.1", "192.0.2.2"]);
                    v
                },
                "UnsafeRRsetValues",
            ),
            (
                {
                    let mut v = rr("192.0.2.1");
                    v["resource_records"] = json!([]);
                    v
                },
                "UnsafeRRsetValues",
            ),
            (
                {
                    let mut v = rr("192.0.2.1");
                    v["resource_records"][0]["enabled"] = json!(false);
                    v
                },
                "RecordDisabled",
            ),
        ] {
            let mock = Mock::new(vec![zone(), list(v)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn dynamic_cdn_healthcheck_unknown_settings_fail_closed() {
        for (key, value, code) in [
            (
                "/pickers",
                json!([{"type":"first_n","limit":1}]),
                "DynamicRRset",
            ),
            ("/filter_set_id", json!(99), "DynamicRRset"),
            (
                "/meta",
                json!({"geodns_link":"cdn.example.com"}),
                "DynamicRRset",
            ),
            (
                "/meta",
                json!({"failover":{"protocol":"TCP"}}),
                "DynamicRRset",
            ),
        ] {
            let mut v = rr("192.0.2.1");
            *v.pointer_mut(key).unwrap() = value;
            let mock = Mock::new(vec![zone(), list(v)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            mock.reads_only();
        }
        for member in [false, true] {
            let mut v = rr("192.0.2.1");
            if member {
                v["resource_records"][0]["new_setting"] = json!(false);
            } else {
                v["new_setting"] = json!(true);
            }
            let mock = Mock::new(vec![zone(), list(v)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                    .await
                    .unwrap_err()
                    .code,
                "UnknownRRsetSettings"
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn complete_offset_pages_target_last_and_unrelated_retained() {
        let mock = Mock::new(vec![
            zone(),
            page(hundred(), 101),
            page(vec![rr("192.0.2.1")], 101),
        ])
        .await;
        let out = mock.adapter().list(&spec()).await.unwrap();
        assert_eq!(out.records.len(), 101);
        assert_eq!(out.records[100].name, "home.example.com");
        assert!(mock.requests()[2].uri.contains("offset=100"));
        mock.reads_only();
    }
    #[tokio::test]
    async fn pagination_duplicates_totals_short_empty_later_fail_no_partial() {
        for (second, code) in [
            (
                page(vec![other("other0.example.com")], 101),
                "UnstablePagination",
            ),
            (page(vec![rr("192.0.2.1")], 102), "UnstablePagination"),
            (page(vec![], 101), "InvalidPagination"),
            (
                reply(429, json!({"message":"later page throttled"})),
                "Http429",
            ),
        ] {
            let mock = Mock::new(vec![zone(), page(hundred(), 101), second]).await;
            assert_eq!(mock.adapter().list(&spec()).await.unwrap_err().code, code);
            mock.reads_only();
        }
        for body in [
            json!({"rrsets":[]}),
            json!({"rrsets":[],"total_amount":-1}),
            json!({"rrsets":[],"total_amount":10001}),
            json!({"rrsets":[rr("192.0.2.1")],"total_amount":0}),
            json!({"rrsets":[rr("192.0.2.1")],"total_amount":101}),
            json!({"rrsets":"wrong","total_amount":1}),
        ] {
            let mock = Mock::new(vec![zone(), reply(200, body)]).await;
            assert_eq!(
                mock.adapter().list(&spec()).await.unwrap_err().code,
                "InvalidPagination"
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn prewrite_value_ttl_id_metadata_timestamp_and_disable_races() {
        for (key, value, code) in [
            ("/ttl", json!(600), "RRsetChanged"),
            ("/resource_records/0/id", json!(43), "RRsetChanged"),
            (
                "/resource_records/0/content",
                json!(["192.0.2.9"]),
                "RRsetChanged",
            ),
            (
                "/resource_records/0/meta/notes",
                json!("changed"),
                "RRsetChanged",
            ),
            ("/meta/notes", json!("changed"), "RRsetChanged"),
            ("/updated_at", json!("2026-01-02T00:00:00Z"), "RRsetChanged"),
            (
                "/resource_records/0/enabled",
                json!(false),
                "RecordDisabled",
            ),
            (
                "/resource_records/0/content",
                json!(["192.0.2.1", "192.0.2.3"]),
                "UnsafeRRsetValues",
            ),
        ] {
            let old = rr("192.0.2.1");
            let mut fresh = old.clone();
            *fresh.pointer_mut(key).unwrap() = value;
            let mock = Mock::new(vec![zone(), list(old), zone(), reply(200, fresh)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn create_fresh_full_list_detects_record_appearance_and_conflicts_dryrun() {
        let mock = Mock::new(vec![
            zone(),
            page(vec![], 0),
            zone(),
            page(hundred(), 101),
            page(vec![rr("192.0.2.9")], 101),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "RecordAppeared"
        );
        mock.reads_only();
        for (kind, code) in [("CNAME", "ConflictingCNAME"), ("NS", "DelegatedTarget")] {
            let mut v = rr("192.0.2.9");
            v["type"] = json!(kind);
            v["resource_records"][0]["content"] = json!(["target.example.net"]);
            let mock = Mock::new(vec![zone(), list(v)]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            mock.reads_only();
        }
        let mock = Mock::new(vec![
            zone(),
            reply(403, json!({"message":"permission denied"})),
        ])
        .await;
        assert_eq!(
            mock.adapter()
                .create(&spec(), "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "Http403"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn explicit_member_id_missing_wrong_rrset_no_fallback() {
        for (id, code) in [
            ("42", "RecordIdNotFound"),
            ("A.other.example.com", "RecordIdMismatch"),
        ] {
            let mut s = spec();
            s.record_id = Some(id.into());
            let mock = Mock::new(vec![
                zone(),
                page(vec![rr("192.0.2.1"), other("other.example.com")], 2),
            ])
            .await;
            assert_eq!(
                reconcile(&mock.adapter(), &s, "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            mock.reads_only();
        }
    }
    #[tokio::test]
    async fn http_business_errors_details_redaction_trace_and_no_write_retry() {
        for status in [200, 400, 401, 403, 404, 409, 429, 500] {
            let mut r = reply(
                status,
                json!({"error":{"code":"Rejected","message":"permission denied secret-test-token"},"metadata":{"message":"UNKNOWN-SECRET"},"authorization":"PRIVATE-HEADER","raw_payload":"PRIVATE-BODY"}),
            );
            r.trace = Some("safe-trace-id");
            let mock = Mock::new(vec![r]).await;
            let e = mock.adapter().list(&spec()).await.unwrap_err();
            assert_eq!(e.http_status, Some(status));
            assert_eq!(e.request_id.as_deref(), Some("safe-trace-id"));
            assert!(e.message.contains("permission denied") && e.message.contains("Rejected"));
            assert_eq!(e.retryable, status == 429 || status >= 500);
            for secret in [
                "secret-test-token",
                "UNKNOWN-SECRET",
                "PRIVATE-HEADER",
                "PRIVATE-BODY",
            ] {
                assert!(!e.message.contains(secret));
            }
            mock.reads_only();
            let mock = Mock::new(vec![
                zone(),
                page(vec![], 0),
                reply(status, json!({"message":"write rejected"})),
            ])
            .await;
            let e = mock
                .adapter()
                .create(&spec(), "192.0.2.2")
                .await
                .unwrap_err();
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
    }
    #[tokio::test]
    async fn malformed_json_wrong_status_identity_content_optional_ack_contradictions() {
        let mut r = reply(200, Value::Null);
        r.raw = Some("PRIVATE secret-test-token not json");
        let mock = Mock::new(vec![r]).await;
        let e = mock.adapter().list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "MalformedResponse");
        assert!(!e.message.contains("PRIVATE"));
        mock.done();
        let ack = json!({"name":"home.example.com","type":"A","resource_records":[{"content":["192.0.2.2"]}]});
        for r in [
            reply(204, Value::Null),
            reply(201, ack.clone()),
            reply(200, json!({})),
            reply(200, other("wrong.example.com")),
            reply(200, {
                let mut v = ack.clone();
                v["resource_records"] = json!([]);
                v
            }),
            reply(200, {
                let mut v = ack.clone();
                v["resource_records"][0]["content"] = json!(["192.0.2.9"]);
                v
            }),
            reply(200, {
                let mut v = ack.clone();
                v["resource_records"][0]["enabled"] = json!(false);
                v
            }),
            reply(200, {
                let mut v = ack.clone();
                v["ttl"] = json!(600);
                v
            }),
            reply(200, {
                let mut v = ack.clone();
                v["meta"] = json!({"new":"unexpected"});
                v
            }),
        ] {
            let mock = Mock::new(vec![zone(), page(vec![], 0), r]).await;
            assert_eq!(
                mock.adapter()
                    .create(&spec(), "192.0.2.2")
                    .await
                    .unwrap_err()
                    .code,
                "InvalidWriteAcknowledgement"
            );
            mock.done();
        }
    }
    #[tokio::test]
    async fn verification_wrong_ip_ttl_missing_ttl_dropped_meta_http_failure() {
        for verified in [
            reply(200, rr("192.0.2.9")),
            reply(200, {
                let mut v = rr("192.0.2.2");
                v["ttl"] = json!(600);
                v
            }),
            reply(200, {
                let mut v = rr("192.0.2.2");
                v.as_object_mut().unwrap().remove("ttl");
                v
            }),
            reply(200, {
                let mut v = rr("192.0.2.2");
                v["meta"] = json!({});
                v
            }),
            reply(429, json!({"message":"verify throttled"})),
        ] {
            let old = rr("192.0.2.1");
            let mock = Mock::new(vec![
                zone(),
                list(old.clone()),
                zone(),
                reply(200, old),
                reply(200, rr("192.0.2.2")),
                verified,
            ])
            .await;
            let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert!(!e.retryable);
            assert_eq!(
                mock.requests()
                    .iter()
                    .filter(|r| r.method == Method::PUT)
                    .count(),
                1
            );
            mock.done();
        }
    }
    #[tokio::test]
    async fn unrelated_wildcard_service_txt_multivalue_do_not_block() {
        let mut txt = other("_acme-challenge.example.com");
        txt["type"] = json!("TXT");
        txt["resource_records"][0]["content"] = json!(["text"]);
        let mut multi = other("other.example.com");
        multi["resource_records"][0]["content"] = json!(["192.0.2.1", "192.0.2.2"]);
        let mock = Mock::new(vec![
            zone(),
            page(vec![txt, multi, other("*.example.com"), rr("192.0.2.1")], 4),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.1", true)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn invalid_names_ips_tokens_options_lines_creation_no_network() {
        let mock = Mock::new(vec![]).await;
        let a = mock.adapter();
        for host in ["../escape", "https://bad", "home?x=1", "home#x", ""] {
            let mut s = spec();
            s.subdomain = host.into();
            assert_eq!(a.list(&s).await.unwrap_err().code, "InvalidDnsName");
        }
        assert_eq!(
            a.create(&spec(), "::1").await.unwrap_err().code,
            "IpFamilyMismatch"
        );
        assert_eq!(
            a.create(&spec(), "bad").await.unwrap_err().code,
            "InvalidIp"
        );
        let mut s = spec();
        s.create_if_missing = false;
        assert_eq!(
            a.create(&s, "192.0.2.2").await.unwrap_err().code,
            "CreationNotAllowed"
        );
        s.create_if_missing = true;
        s.record_id = Some("42".into());
        assert_eq!(
            a.create(&s, "192.0.2.2").await.unwrap_err().code,
            "CreationNotAllowed"
        );
        for token in ["", "secret\nPRIVATE"] {
            let mut a = mock.adapter();
            a.token = token.into();
            assert_eq!(a.list(&spec()).await.unwrap_err().code, "InvalidApiToken");
        }
        let mut s = spec();
        s.options.insert("new".into(), "true".into());
        assert_eq!(a.list(&s).await.unwrap_err().code, "UnsupportedOptions");
        s.options.clear();
        s.record_line = "geo".into();
        assert_eq!(a.list(&s).await.unwrap_err().code, "UnsupportedRecordLine");
        let mut a = mock.adapter();
        a.invalid_options = true;
        assert_eq!(
            a.list(&spec()).await.unwrap_err().code,
            "UnsupportedOptions"
        );
        assert!(mock.requests().is_empty());
        mock.done();
    }
    #[tokio::test]
    async fn notes_only_metadata_preservation_policy_and_direct_id() {
        for key in [
            "asn",
            "continents",
            "countries",
            "latlong",
            "backup",
            "weight",
            "ip",
            "default",
            "unknown",
        ] {
            for member in [true, false] {
                let mut v = rr("192.0.2.1");
                if member {
                    v["resource_records"][0]["meta"][key] = json!(true);
                } else {
                    v["meta"][key] = json!(true);
                }
                let mock = Mock::new(vec![zone(), list(v)]).await;
                assert_eq!(
                    reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                        .await
                        .unwrap_err()
                        .code,
                    "UnsafeMetadata"
                );
                mock.reads_only();
            }
        }
        let mock = Mock::new(vec![zone(), list(rr("192.0.2.1"))]).await;
        let a = mock.adapter();
        let r = a.list(&spec()).await.unwrap().records.remove(0);
        let mut s = spec();
        s.record_id = Some("42".into());
        assert_eq!(
            a.update(&s, &r, "192.0.2.2").await.unwrap_err().code,
            "RRsetMismatch"
        );
        mock.reads_only();
    }
    #[tokio::test]
    async fn ipv6_update_noop_and_ttl_only_update() {
        let mut s = spec();
        s.record_type = "AAAA".into();
        let mut old = rr("2001:db8::1");
        old["type"] = json!("AAAA");
        let mock = Mock::new(vec![zone(), list(old.clone())]).await;
        assert_eq!(
            reconcile(&mock.adapter(), &s, "2001:0db8:0:0::1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        mock.reads_only();
        let mut new = old.clone();
        new["resource_records"][0]["content"] = json!(["2001:db8::2"]);
        let mock = Mock::new(vec![
            zone(),
            list(old.clone()),
            zone(),
            reply(200, old),
            reply(200, new.clone()),
            reply(200, new),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &s, "2001:0db8:0:0::2", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        assert_eq!(
            mock.requests()[4].body["resource_records"][0]["content"],
            json!(["2001:db8::2"])
        );
        mock.done();
        let mut s = spec();
        s.ttl = 600;
        let old = rr("192.0.2.1");
        let mut new = old.clone();
        new["ttl"] = json!(600);
        let mock = Mock::new(vec![
            zone(),
            list(old.clone()),
            zone(),
            reply(200, old),
            reply(200, new.clone()),
            reply(200, new),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &s, "192.0.2.1", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        assert_eq!(mock.requests()[4].body["ttl"], 600);
        mock.done();
    }
    #[tokio::test]
    async fn vanished_or_invalid_target_never_creates_and_verification_context_retained() {
        let mock = Mock::new(vec![
            zone(),
            list(rr("192.0.2.1")),
            zone(),
            reply(404, json!({"message":"target vanished"})),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "Http404"
        );
        mock.reads_only();
        for ip in ["not an IP", "::1"] {
            let mock = Mock::new(vec![zone(), list(rr(ip))]).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                    .await
                    .unwrap_err()
                    .code,
                "InvalidRecordValue"
            );
            mock.reads_only();
        }
        let old = rr("192.0.2.1");
        let mut disabled = rr("192.0.2.2");
        disabled["resource_records"][0]["enabled"] = json!(false);
        let mut verified = reply(200, disabled);
        verified.trace = Some("verify-trace");
        let mock = Mock::new(vec![
            zone(),
            list(old.clone()),
            zone(),
            reply(200, old),
            reply(200, rr("192.0.2.2")),
            verified,
        ])
        .await;
        let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(e.stage, "GcoreVerifyRRset");
        assert_eq!(e.http_status, Some(200));
        assert_eq!(e.request_id.as_deref(), Some("verify-trace"));
        assert!(e.message.contains("Accepted write"));
        assert!(!e.retryable);
        mock.done();
    }
    #[test]
    fn error_headers_retry_after_are_bounded_and_sanitized() {
        let a = Gcore::new(
            reqwest::Client::new(),
            "secret-test-token".into(),
            &BTreeMap::new(),
        );
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "error",
            HeaderValue::from_static("invalid RRset secret-test-token"),
        );
        headers.insert("retry-after", HeaderValue::from_static("120"));
        let r = HttpReply {
            headers,
            body: json!({"message":"rate limited"}),
            status: 429,
            request_id: Some("trace".into()),
        };
        let e = a.check("test", &r, false).unwrap_err();
        assert!(e.message.contains("invalid RRset") && e.message.contains("Retry-After: 120"));
        assert!(!e.message.contains("secret-test-token"));
        assert_eq!(e.request_id.as_deref(), Some("trace"));
    }
    #[test]
    fn ids_safe_stable_case_apex_wildcard_long_fixed_endpoint() {
        assert_eq!(rrset_id("A", "HOME.Example.com."), "A.home.example.com");
        assert_eq!(rrset_id("AAAA", "example.com"), "AAAA.example.com");
        for name in [
            "*.example.com".to_owned(),
            "_service.example.com".to_owned(),
            format!("{}.{}.example.com", "x".repeat(63), "y".repeat(63)),
        ] {
            let id = rrset_id("A", &name);
            assert!(super::super::common::valid_id(&id));
            assert_eq!(id, rrset_id("A", &name));
        }
        let a = Gcore::new(
            reqwest::Client::new(),
            "secret-test-token".into(),
            &BTreeMap::from([("endpoint".into(), "https://evil.example".into())]),
        );
        assert_eq!(a.endpoint(), ENDPOINT);
        assert!(a.invalid_options);
    }
}
