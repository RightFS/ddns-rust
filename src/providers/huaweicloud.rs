//! Huawei DNS v2.1: permanent AK/SK only; client MUST disable redirects/retries.
//! Official references checked 2026-11-09:
//! https://support.huaweicloud.com/api-dns/dns_api_64001.html
//! https://support.huaweicloud.com/api-dns/dns_api_64002.html
//! https://support.huaweicloud.com/api-dns/dns_api_64004.html
//! https://support.huaweicloud.com/api-dns/UpdateRecordSets.html
//! https://github.com/huaweicloud/huaweicloud-sdk-python-v3/blob/master/huaweicloud-sdk-core/huaweicloudsdkcore/signer/signer.py
//! https://github.com/huaweicloud/huaweicloud-sdk-python-v3/blob/master/huaweicloud-sdk-dns/huaweicloudsdkdns/v2/region/dns_region.py
//! TTL schema 1..2147483647; initial rollout conservatively requires >=300
//! (documented default), NOT a claimed account minimum. APIs expose no account
//! minimum TTL. Never clamp. No CAS: use one writer. No API links followed.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use hmac::{Hmac, Mac};
use reqwest::{Method, Url, header::HeaderValue};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
const PAGE: usize = 100;
const MAX: usize = 10000;
const REGIONS: &[&str] = &[
    "cn-east-2",
    "cn-east-3",
    "cn-north-1",
    "cn-north-4",
    "cn-south-1",
    "cn-southwest-2",
    "af-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "sa-brazil-1",
    "la-south-2",
    "la-north-2",
    "na-mexico-1",
    "cn-north-9",
    "cn-north-2",
    "cn-south-2",
    "ap-southeast-4",
    "ae-ad-1",
    "ru-moscow-1",
    "me-east-1",
    "ap-southeast-5",
    "cn-east-5",
    "cn-east-4",
    "tr-west-1",
    "af-north-1",
    "my-kualalumpur-1",
];
// Intentionally no Debug: neither credentials nor signed requests are printable.
pub struct HuaweiCloud {
    api: Api,
    id: String,
    key: String,
    region: String,
    project: String,
    zone_id: Option<String>,
    invalid_options: bool,
    #[cfg(test)]
    endpoint: Option<String>,
}
impl HuaweiCloud {
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
            region: options.get("region").cloned().unwrap_or_default(),
            project: options.get("project_id").cloned().unwrap_or_default(),
            zone_id: options.get("zone_id").cloned(),
            invalid_options: options
                .keys()
                .any(|k| !["region", "project_id", "zone_id"].contains(&k.as_str())),
            #[cfg(test)]
            endpoint: None,
        }
    }
    fn endpoint(&self) -> String {
        #[cfg(test)]
        if let Some(endpoint) = &self.endpoint {
            return endpoint.clone();
        }
        format!("https://dns.{}.myhuaweicloud.com", self.region)
    }
    fn error(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage,code,message,"Check permanent AK/SK, explicit DNS region/IAM project, exact public ACTIVE zone and DNS list/get/create/update permissions. Only dedicated ACTIVE singleton A/AAAA default_view weight-1 RRsets are supported. Respect rate limits (429) and check availability (5xx). A 404 never authorizes fallback creation. Inspect pending/uncertain writes before retrying; no automatic write retry. Use one writer: no documented conditional update.",reply)
    }
    fn zone_option<'a>(&'a self, spec: &'a Spec) -> Result<Option<&'a str>, ProviderError> {
        let record = spec.options.get("zone_id");
        if let (Some(a), Some(b)) = (&self.zone_id, record)
            && a != b
        {
            return Err(self.error(
                "validation",
                "ZoneIdMismatch",
                "Provider and record zone_id disagree; no override/fallback.",
                None,
            ));
        }
        Ok(record.or(self.zone_id.as_ref()).map(String::as_str))
    }
    fn validate(&self, spec: &Spec) -> Result<(), ProviderError> {
        let fail = |code, msg| self.error("validation", code, msg, None);
        if self.invalid_options || spec.options.keys().any(|k| k != "zone_id") {
            return Err(fail(
                "UnsupportedOptions",
                "Provider options region/project_id/zone_id only; record options zone_id only. No endpoint/routing overrides.",
            ));
        }
        if !REGIONS.contains(&self.region.as_str()) {
            return Err(fail(
                "InvalidRegion",
                "Required region must be a plain official DNS SDK allowlisted region; no URLs or suffixes.",
            ));
        }
        if !path_id(&self.project) {
            return Err(fail(
                "InvalidProjectId",
                "Explicit valid regional IAM project_id is required; no IAM discovery/guessing.",
            ));
        }
        if self.id.is_empty()
            || self.id.len() > 256
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || self.key.is_empty()
            || self.key.len() > 512
            || !self.key.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(fail(
                "InvalidCredentials",
                "Nonempty permanent AK/SK required; contents omitted. Temporary tokens unsupported.",
            ));
        }
        if self.zone_option(spec)?.is_some_and(|id| !path_id(id))
            || spec.record_id.as_ref().is_some_and(|id| !path_id(id))
        {
            return Err(fail(
                "InvalidResourceId",
                "Native resource IDs must be safe non-dot string path segments; no URL syntax.",
            ));
        }
        if !matches!(
            spec.record_line.as_str(),
            "" | "默认" | "default" | "default_view"
        ) {
            return Err(fail(
                "UnsupportedRecordLine",
                "Only default_view supported; routing lines refused.",
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(fail("UnsupportedRecordType", "Only A and AAAA supported."));
        }
        if !hostname(&spec.domain, false)
            || (spec.subdomain != "@" && !hostname(&spec.subdomain, false))
            || spec.fqdn().len() > 253
        {
            return Err(fail(
                "InvalidDnsName",
                "Use exact ASCII/punycode hosted zone and relative host or @; no suffix guessing/URL syntax.",
            ));
        }
        if !(300..=2147483647).contains(&spec.ttl) {
            return Err(fail(
                "UnsupportedTTL",
                "Schema TTL is 1..2147483647 seconds; rollout conservatively permits 300..2147483647, not a claimed account minimum. Account minimum is not exposed; no clamping.",
            ));
        }
        Ok(())
    }
    fn ip(&self, spec: &Spec, value: &str) -> Result<String, ProviderError> {
        self.validate(spec)?;
        let ip = value.parse::<IpAddr>().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be plain IP.",
                None,
            )
        })?;
        if ip.is_ipv4() != (spec.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "Desired IP family mismatches A/AAAA.",
                None,
            ));
        }
        Ok(ip.to_string())
    }
    async fn send(
        &self,
        stage: &str,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let mut url = Url::parse(&format!("{}{path}", self.endpoint())).map_err(|_| {
            self.error(
                stage,
                "InvalidEndpoint",
                "Cannot construct provider-owned endpoint.",
                None,
            )
        })?;
        let query = canonical_query(query);
        url.set_query((!query.is_empty()).then_some(query.as_str()));
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().into(),
        };
        let bytes = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| {
                self.error(
                    stage,
                    "InvalidPayload",
                    "Cannot serialize documented payload.",
                    None,
                )
            })?
            .unwrap_or_default();
        let date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let headers = BTreeMap::from([
            ("content-type".into(), "application/json".into()),
            ("host".into(), host),
            ("x-project-id".into(), self.project.clone()),
            ("x-sdk-date".into(), date.clone()),
        ]);
        let (auth, signature) = sign(
            &self.id,
            &self.key,
            method.as_str(),
            path,
            &query,
            &headers,
            &bytes,
            &date,
        );
        // CRITICAL: scoped Api redacts generated Authorization/signature before
        // common::Api can log a malicious provider trace ID or parse an error.
        let api = Api::new(
            self.api.client.clone(),
            vec![
                auth.clone(),
                signature,
                self.id.clone(),
                self.key.clone(),
                "https://".into(),
                "http://".into(),
            ],
        );
        let mut request = api.client.request(method, url);
        for (key, value) in headers {
            request = request.header(
                key,
                HeaderValue::from_str(&value).map_err(|_| {
                    self.error(
                        stage,
                        "InvalidHeaders",
                        "Cannot build signed headers; contents omitted.",
                        None,
                    )
                })?,
            );
        }
        let mut auth = HeaderValue::from_str(&auth).map_err(|_| {
            self.error(
                stage,
                "InvalidCredentials",
                "Cannot build Authorization; contents omitted.",
                None,
            )
        })?;
        auth.set_sensitive(true);
        request = request.header(reqwest::header::AUTHORIZATION, auth);
        if body.is_some() {
            request = request.body(bytes);
        }
        let mut reply = api.send(stage, request, write).await.map_err(|mut error| {
            if error.code == "MalformedResponse" {
                error.message = if write {
                    "Huawei returned non-JSON/malformed JSON; raw body and headers omitted. Write result may be uncertain; inspect before retrying."
                } else {
                    "Huawei returned non-JSON/malformed JSON; raw body and headers omitted."
                }.into();
            }
            error
        })?;
        if reply.request_id.is_none() {
            reply.request_id = reply
                .body
                .get("request_id")
                .and_then(Value::as_str)
                .or_else(|| {
                    reply
                        .headers
                        .get("x-openstack-request-id")
                        .and_then(|v| v.to_str().ok())
                })
                .map(|s| api.safe(s))
                .filter(|s| super::common::valid_trace_id(s) && !s.contains("://"));
        }
        let business =
            reply.body.get("error_code").is_some() || reply.body.get("error_msg").is_some();
        if !(200..300).contains(&reply.status) || business {
            let code = if business {
                reply.body["error_code"]
                    .as_str()
                    .unwrap_or("ProviderApiError")
                    .to_string()
            } else {
                format!("Http{}", reply.status)
            };
            let detail = reply.body["error_msg"]
                .as_str()
                .or_else(|| reply.body["message"].as_str())
                .map(|s| {
                    if s.contains("://") {
                        String::from("Provider URL detail omitted.")
                    } else {
                        api.safe(s)
                    }
                })
                .unwrap_or_else(|| "No recognized business detail; raw response omitted.".into());
            let code = if code.contains("://") {
                "ProviderApiError".into()
            } else {
                code
            };
            let mut e=api.error(stage,&code,&format!("Huawei HTTP {}: {detail}",reply.status),"Check AK/SK, regional project and permissions; respect 429 and check 5xx. Inspect uncertain writes before retrying; no writer retries.",Some(&reply));
            e.retryable = !write && (reply.status == 429 || reply.status >= 500);
            return Err(e);
        }
        if reply.status != if write { 202 } else { 200 } {
            return Err(api.error(
                stage,
                "InvalidAcknowledgement",
                "Unexpected HTTP acknowledgement; write may be uncertain.",
                "Inspect provider before retrying; no automatic retries.",
                Some(&reply),
            ));
        }
        Ok(reply)
    }
    async fn pages(
        &self,
        stage: &str,
        path: &str,
        field: &str,
        mut query: Vec<(String, String)>,
    ) -> Result<(Vec<Value>, Option<String>), ProviderError> {
        query.push(("limit".into(), PAGE.to_string()));
        let mut values = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        for _ in 0..=100 {
            let mut q = query.clone();
            q.push(("offset".into(), values.len().to_string()));
            let reply = self.send(stage, Method::GET, path, &q, None, false).await?;
            let fail = |code, msg| self.error(stage, code, msg, Some(&reply));
            let count = reply.body["metadata"]["total_count"]
                .as_u64()
                .filter(|n| *n <= MAX as u64)
                .ok_or_else(|| {
                    fail(
                        "InvalidPagination",
                        "Missing/excessive total_count; no partial list.",
                    )
                })? as usize;
            if total.is_some_and(|n| n != count) {
                return Err(fail(
                    "UnstablePagination",
                    "total_count changed; no partial list.",
                ));
            }
            total = Some(count);
            let page = reply.body[field]
                .as_array()
                .filter(|a| a.len() <= PAGE)
                .ok_or_else(|| {
                    fail(
                        "InvalidPagination",
                        "Missing/oversized page; no partial list.",
                    )
                })?;
            if values.len() + page.len() > count || (page.is_empty() && values.len() != count) {
                return Err(fail(
                    "InvalidPagination",
                    "Page contradicts total_count or makes no progress.",
                ));
            }
            for v in page {
                let id = v["id"].as_str().filter(|id| path_id(id)).ok_or_else(|| {
                    fail(
                        "InvalidResourceId",
                        "Unsafe or non-string native resource ID.",
                    )
                })?;
                if !ids.insert(id.to_string()) {
                    return Err(fail(
                        "UnstablePagination",
                        "Repeated resource ID; no partial list.",
                    ));
                }
                values.push(v.clone());
            }
            if values.len() == count {
                return Ok((values, reply.request_id));
            }
        }
        Err(self.error(
            stage,
            "PaginationLimit",
            "More than 101 pages; no partial list.",
            None,
        ))
    }
    async fn zone(&self, spec: &Spec) -> Result<String, ProviderError> {
        self.validate(spec)?;
        let id = if let Some(id) = self.zone_option(spec)? {
            id.to_string()
        } else {
            let (zones, _) = self
                .pages(
                    "HuaweiListZones",
                    "/v2/zones",
                    "zones",
                    vec![
                        ("type".into(), "public".into()),
                        (
                            "name".into(),
                            format!("{}.", spec.domain.to_ascii_lowercase()),
                        ),
                        ("search_mode".into(), "equal".into()),
                    ],
                )
                .await?;
            let zones: Vec<_> = zones
                .iter()
                .filter(|v| {
                    v["name"]
                        .as_str()
                        .is_some_and(|n| fqdn(n, true) && dns_equal(n, &spec.domain))
                })
                .collect();
            if zones.len() != 1 {
                return Err(self.error(
                    "HuaweiListZones",
                    if zones.is_empty() {
                        "ZoneNotFound"
                    } else {
                        "AmbiguousZones"
                    },
                    "Exactly one public zone must match full zone name; no suffix fallback.",
                    None,
                ));
            }
            zones[0]["id"].as_str().unwrap().into()
        };
        let reply = self
            .send(
                "HuaweiGetZone",
                Method::GET,
                &format!("/v2/zones/{id}"),
                &[],
                None,
                false,
            )
            .await?;
        let v = &reply.body;
        if v["id"].as_str() != Some(&id)
            || !v["name"]
                .as_str()
                .is_some_and(|n| fqdn(n, true) && dns_equal(n, &spec.domain))
        {
            return Err(self.error(
                "HuaweiGetZone",
                "ZoneMismatch",
                "Zone ID/full name mismatch; no fallback.",
                Some(&reply),
            ));
        }
        if v["zone_type"] != "public" || v["status"] != "ACTIVE" {
            return Err(self.error(
                "HuaweiGetZone",
                "ZoneInactive",
                "Zone must be public and ACTIVE; never enables disabled/frozen/pending zone.",
                Some(&reply),
            ));
        }
        if v["project_id"].as_str() != Some(self.project.as_str()) {
            return Err(self.error(
                "HuaweiGetZone",
                "ProjectMismatch",
                "Zone does not confirm configured IAM project.",
                Some(&reply),
            ));
        }
        if v.get("masters")
            .is_some_and(|m| !m.is_null() && m.as_array().is_none_or(|a| !a.is_empty()))
        {
            return Err(self.error(
                "HuaweiGetZone",
                "SecondaryZone",
                "Master/secondary settings unsupported.",
                Some(&reply),
            ));
        }
        Ok(id)
    }
    fn record(
        &self,
        spec: &Spec,
        zone: &str,
        v: &Value,
        reply: &HttpReply,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error("HuaweiReadRRset","InvalidRRset","RRset missing valid native IDs, FQDN, type, values, TTL or state; raw contents omitted.",Some(reply))
        };
        let id = v["id"].as_str().filter(|s| path_id(s)).ok_or_else(bad)?;
        let name = v["name"]
            .as_str()
            .filter(|n| fqdn(n, true))
            .ok_or_else(bad)?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let domain = spec.domain.to_ascii_lowercase();
        if v["zone_id"].as_str() != Some(zone)
            || !v["zone_name"]
                .as_str()
                .is_some_and(|n| fqdn(n, true) && dns_equal(n, &domain))
            || !(name == domain || name.ends_with(&format!(".{domain}")))
        {
            return Err(self.error(
                "HuaweiReadRRset",
                "RRsetMismatch",
                "RRset outside exact zone ID/name.",
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
            .filter(|n| (1..=2147483647).contains(n))
            .ok_or_else(bad)?;
        let values = v["records"]
            .as_array()
            .filter(|a| a.len() <= MAX && a.iter().all(Value::is_string))
            .ok_or_else(bad)?;
        if !v["status"].is_string() {
            return Err(bad());
        }
        let value = if matches!(kind, "A" | "AAAA") && values.len() == 1 {
            singleton_ip(v, kind).unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Record {
            id: id.into(),
            name,
            record_type: kind.into(),
            value,
            ttl,
            line: String::new(),
            enabled: v["status"] == "ACTIVE",
            extra: v.clone(),
        })
    }
    fn selection(&self, spec: &Spec, r: &Record) -> Result<(), ProviderError> {
        self.validate(spec)?;
        let v = &r.extra;
        if !path_id(&r.id)
            || v["id"].as_str() != Some(r.id.as_str())
            || !dns_equal(&r.name, &spec.fqdn())
            || r.record_type != spec.record_type
            || spec.record_id.as_ref().is_some_and(|id| id != &r.id)
            || !v["name"]
                .as_str()
                .is_some_and(|n| fqdn(n, false) && dns_equal(n, &spec.fqdn()))
            || v["type"].as_str() != Some(spec.record_type.as_str())
            || v["ttl"].as_u64() != Some(r.ttl)
            || !v["zone_id"].as_str().is_some_and(path_id)
            || self
                .zone_option(spec)?
                .is_some_and(|id| v["zone_id"].as_str() != Some(id))
            || !v["zone_name"]
                .as_str()
                .is_some_and(|n| dns_equal(n, &spec.domain))
            || v["project_id"].as_str() != Some(self.project.as_str())
        {
            return Err(self.error(
                "selection",
                "RRsetMismatch",
                "Selected native RRset contradicts identity/project/name/type/TTL.",
                None,
            ));
        }
        if v["status"] != "ACTIVE" || !r.enabled {
            return Err(self.error("selection","RecordInactive","Only ACTIVE records supported; disabled/frozen/pending/error refused even unchanged/dry-run.",None));
        }
        if v["records"].as_array().is_none_or(|a| a.len() != 1) {
            return Err(self.error(
                "selection",
                "UnsafeRRsetValues",
                "PUT replaces all values; exactly one IP required.",
                None,
            ));
        }
        if singleton_ip(v, &spec.record_type).as_deref() != Some(r.value.as_str())
            || r.value.is_empty()
        {
            return Err(self.error(
                "selection",
                "InvalidRecordValue",
                "Singleton is not target-family IP.",
                None,
            ));
        }
        if v["line"] != "default_view"
            || v["weight"].as_u64() != Some(1)
            || v.get("alias_target").is_some_and(|v| !v.is_null())
            || v.get("health_check_id").is_some_and(|v| !v.is_null())
            || v["default"].as_bool() != Some(false)
        {
            return Err(self.error("selection","UnsafeRRsetSettings","Only non-system default_view weight-1 static records without alias/healthcheck; never removes settings.",None));
        }
        if !known_keys(
            v,
            &[
                "id",
                "name",
                "description",
                "type",
                "ttl",
                "records",
                "status",
                "links",
                "zone_id",
                "zone_name",
                "created_at",
                "updated_at",
                "default",
                "project_id",
                "line",
                "weight",
                "health_check_id",
                "alias_target",
                "bundle",
            ],
        ) || v
            .get("description")
            .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| s.chars().count() > 255))
            || v.get("bundle").is_some_and(|v| !v.is_string())
        {
            return Err(self.error(
                "selection",
                "UnknownRRsetSettings",
                "Unknown/malformed settings fail closed, never silently dropped.",
                None,
            ));
        }
        Ok(())
    }
    async fn get(
        &self,
        spec: &Spec,
        zone: &str,
        id: &str,
    ) -> Result<(Record, HttpReply), ProviderError> {
        let reply = self
            .send(
                "HuaweiGetRRset",
                Method::GET,
                &format!("/v2.1/zones/{zone}/recordsets/{id}"),
                &[],
                None,
                false,
            )
            .await?;
        let r = self.record(spec, zone, &reply.body, &reply)?;
        if r.id != id {
            return Err(self.error(
                "HuaweiGetRRset",
                "RRsetMismatch",
                "Detail returned another native ID.",
                Some(&reply),
            ));
        }
        Ok((r, reply))
    }
    fn conflicts(&self, spec: &Spec, records: &[Record]) -> Result<(), ProviderError> {
        let target = spec.fqdn().to_ascii_lowercase();
        let zone = spec.domain.to_ascii_lowercase();
        if records
            .iter()
            .any(|r| r.name == target && matches!(r.record_type.as_str(), "CNAME" | "URL"))
        {
            return Err(self.error(
                "selection",
                "ConflictingCNAME",
                "Target has CNAME/URL redirection; creation and dry-run refused.",
                None,
            ));
        }
        if records.iter().any(|r| {
            r.record_type == "NS"
                && r.name != zone
                && (target == r.name || target.ends_with(&format!(".{}", r.name)))
        }) {
            return Err(self.error(
                "selection",
                "DelegatedTarget",
                "Target at/below delegated NS; configure exact child authoritative zone.",
                None,
            ));
        }
        Ok(())
    }
    async fn snapshot(&self, spec: &Spec) -> Result<(String, List), ProviderError> {
        let zone = self.zone(spec).await?;
        let (values, mut request_id) = self
            .pages(
                "HuaweiListRRsets",
                &format!("/v2.1/zones/{zone}/recordsets"),
                "recordsets",
                vec![],
            )
            .await?;
        let context = HttpReply {
            headers: Default::default(),
            body: Value::Null,
            status: 200,
            request_id: request_id.clone(),
        };
        let mut records: Vec<Record> = values
            .iter()
            .map(|v| self.record(spec, &zone, v, &context))
            .collect::<Result<_, _>>()?;
        self.conflicts(spec, &records)?;
        // List schema omits route/healthcheck/alias fields: hydrate ALL target
        // candidates before common may say unchanged/would_update. No defaults.
        for r in &mut records {
            if (dns_equal(&r.name, &spec.fqdn()) && r.record_type == spec.record_type)
                || spec.record_id.as_ref() == Some(&r.id)
            {
                let (full, reply) = self.get(spec, &zone, &r.id).await?;
                for key in [
                    "id",
                    "name",
                    "type",
                    "ttl",
                    "records",
                    "status",
                    "zone_id",
                    "zone_name",
                    "project_id",
                    "description",
                    "created_at",
                    "updated_at",
                    "default",
                ] {
                    if r.extra
                        .get(key)
                        .is_some_and(|v| full.extra.get(key) != Some(v))
                    {
                        return Err(self.error(
                            "selection",
                            "RRsetChanged",
                            "Detail contradicts full-list snapshot; no stale selection.",
                            Some(&reply),
                        ));
                    }
                }
                *r = full;
                request_id = reply.request_id.or(request_id);
            }
        }
        Ok((
            zone,
            List {
                records,
                request_id,
            },
        ))
    }
    fn payload(&self, spec: &Spec, old: Option<&Record>, ip: &str) -> Value {
        let mut body = json!({"name":format!("{}.",spec.fqdn().to_ascii_lowercase()),"type":spec.record_type,"ttl":spec.ttl,"records":[ip],"weight":1});
        if let Some(r) = old {
            body["name"] = r.extra["name"].clone();
            body["type"] = r.extra["type"].clone();
            body["weight"] = r.extra["weight"].clone();
            if r.extra.get("description").is_some_and(Value::is_string) {
                body["description"] = r.extra["description"].clone();
            }
        } else {
            body["line"] = json!("default_view");
            body["status"] = json!("ENABLE");
        }
        // Update schema has no line/status. ID retains line; never enables.
        body
    }
    async fn write(
        &self,
        spec: &Spec,
        zone: &str,
        old: Option<&Record>,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let stage = if old.is_some() {
            "HuaweiUpdateRRset"
        } else {
            "HuaweiCreateRRset"
        };
        let path = match old {
            Some(r) => format!("/v2.1/zones/{zone}/recordsets/{}", r.id),
            None => format!("/v2.1/zones/{zone}/recordsets"),
        };
        let expected = self.payload(spec, old, ip);
        let reply = self
            .send(
                stage,
                if old.is_some() {
                    Method::PUT
                } else {
                    Method::POST
                },
                &path,
                &[],
                Some(&expected),
                true,
            )
            .await?;
        let ack=self.record(spec,zone,&reply.body,&reply).map_err(|_|self.error(stage,"InvalidWriteAcknowledgement","Accepted write lacks exact documented RRset acknowledgement; inspect uncertain result.",Some(&reply)))?;
        let pending = if old.is_some() {
            "PENDING_UPDATE"
        } else {
            "PENDING_CREATE"
        };
        if !dns_equal(&ack.name, &spec.fqdn())
            || ack.record_type != spec.record_type
            || ack.value != ip
            || ack.ttl != spec.ttl
            || old.is_some_and(|r| r.id != ack.id)
            || ack.extra["status"] != pending
            || ack.extra["project_id"].as_str() != Some(self.project.as_str())
            || ack.extra["line"] != "default_view"
            || ack.extra["weight"] != 1
            || ack
                .extra
                .get("health_check_id")
                .is_some_and(|v| !v.is_null())
            || ack.extra.get("alias_target").is_some_and(|v| !v.is_null())
            || expected
                .get("description")
                .is_some_and(|v| ack.extra.get("description") != Some(v))
        {
            return Err(self.error(stage,"InvalidWriteAcknowledgement","Accepted write did not acknowledge exact ID/IP/TTL/settings/description and expected pending state; uncertain result.",Some(&reply)));
        }
        let mut active_ack = ack.clone();
        active_ack.extra["status"] = json!("ACTIVE");
        active_ack.enabled = true;
        self.selection(spec, &active_ack).map_err(|_| {
            self.error(
                stage,
                "InvalidWriteAcknowledgement",
                "Accepted acknowledgement has unsafe or unknown settings; result uncertain.",
                Some(&reply),
            )
        })?;
        let (fresh,read)=self.get(spec,zone,&ack.id).await.map_err(|mut e|{e.retryable=false;e.hint="Write accepted but readback failed; inspect Huawei before retrying. No writer retries.".into();e})?;
        if fresh.extra["status"] == pending {
            return Err(self.error("HuaweiVerifyRRset","WritePending","Asynchronous write accepted but readback still pending. No success claimed or automatic writer retry; inspect completion.",Some(&read)));
        }
        self.selection(spec, &fresh).map_err(|_| {
            self.error(
                "HuaweiVerifyRRset",
                "WriteVerificationFailed",
                "Write did not become safe ACTIVE singleton; inspect uncertain result.",
                Some(&read),
            )
        })?;
        if fresh.id != ack.id
            || fresh.value != ip
            || fresh.ttl != spec.ttl
            || fresh.extra["name"] != expected["name"]
            || expected
                .get("description")
                .is_some_and(|v| fresh.extra.get("description") != Some(v))
            || (old.is_none()
                && ["description", "bundle", "default", "created_at"]
                    .iter()
                    .any(|key| ack.extra.get(*key) != fresh.extra.get(*key)))
            || old.is_some_and(|r| {
                ["bundle", "default", "created_at", "description"]
                    .iter()
                    .any(|k| r.extra.get(*k) != fresh.extra.get(*k))
            })
        {
            return Err(self.error("HuaweiVerifyRRset","WriteVerificationFailed","Readback mismatches desired IP/TTL/identity/preserved settings; never assume clamping or acceptance.",Some(&read)));
        }
        Ok(Mutation {
            record_id: ack.id,
            request_id: reply.request_id.or(read.request_id),
        })
    }
}
impl Adapter for HuaweiCloud {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Fqdn
    }
    fn validate_selection(&self, spec: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.validate(spec)?;
        if let Some(r) = r {
            self.selection(spec, r)?;
        }
        Ok(())
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        Ok(self.snapshot(spec).await?.1)
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.ip(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error(
                "create",
                "CreationNotAllowed",
                "Explicit create opt-in and no record_id required; missing IDs never fallback.",
                None,
            ));
        }
        let (zone, fresh) = self.snapshot(spec).await?;
        if fresh
            .records
            .iter()
            .any(|r| dns_equal(&r.name, &spec.fqdn()) && r.record_type == spec.record_type)
        {
            return Err(self.error(
                "create",
                "RecordAppeared",
                "Fresh full snapshot confirms target appeared; no POST regardless of route/state.",
                None,
            ));
        }
        // Explicit second full absence read immediately before POST. No filters
        // hiding CNAME/delegations. Still not atomic; one writer is required.
        let (again, fresh) = self.snapshot(spec).await?;
        if zone != again
            || fresh
                .records
                .iter()
                .any(|r| dns_equal(&r.name, &spec.fqdn()) && r.record_type == spec.record_type)
        {
            return Err(self.error(
                "create",
                "RecordAppeared",
                "Target/zone changed during absence recheck; no POST.",
                None,
            ));
        }
        self.write(spec, &zone, None, &ip).await
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let ip = self.ip(spec, ip)?;
        self.selection(spec, record)?;
        let (zone, list) = self.snapshot(spec).await?;
        let fresh = list
            .records
            .iter()
            .find(|r| r.id == record.id)
            .ok_or_else(|| {
                self.error(
                    "selection",
                    "RecordIdNotFound",
                    "Native RRset vanished; no fallback/create.",
                    None,
                )
            })?;
        self.selection(spec, fresh)?;
        if fresh.extra != record.extra {
            return Err(self.error(
                "selection",
                "RRsetChanged",
                "Full metadata changed since selection; no stale PUT.",
                None,
            ));
        }
        let (immediate, reply) = self.get(spec, &zone, &record.id).await?;
        self.selection(spec, &immediate)?;
        if immediate.extra != fresh.extra {
            return Err(self.error(
                "selection",
                "RRsetChanged",
                "Immediate prewrite metadata differs; no PUT.",
                Some(&reply),
            ));
        }
        self.write(spec, &zone, Some(&immediate), &ip).await
    }
}
fn path_id(id: &str) -> bool {
    super::common::valid_id(id) && id != "." && id != ".."
}
fn dns_equal(a: &str, b: &str) -> bool {
    a.strip_suffix('.')
        .unwrap_or(a)
        .eq_ignore_ascii_case(b.strip_suffix('.').unwrap_or(b))
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
fn fqdn(name: &str, records: bool) -> bool {
    name.strip_suffix('.').is_some_and(|n| hostname(n, records))
}
fn singleton_ip(v: &Value, kind: &str) -> Option<String> {
    let a = v["records"].as_array()?;
    if a.len() != 1 {
        return None;
    }
    let ip = a[0].as_str()?.parse::<IpAddr>().ok()?;
    (ip.is_ipv4() == (kind == "A")).then(|| ip.to_string())
}
fn known_keys(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|m| m.keys().all(|k| keys.contains(&k.as_str())))
}
fn escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
fn canonical_query(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", escape(k), escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}
// Keep the official canonical signing inputs explicit for auditability and the
// independent golden vectors; this pure helper performs no I/O or logging.
#[allow(clippy::too_many_arguments)]
fn sign(
    id: &str,
    key: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    date: &str,
) -> (String, String) {
    // Official SDK unquotes path, escapes segments, appends canonical-only '/'.
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();
    let mut uri = decoded.split('/').map(escape).collect::<Vec<_>>().join("/");
    if !uri.ends_with('/') {
        uri.push('/');
    }
    let signed = headers.keys().cloned().collect::<Vec<_>>().join(";");
    let canonical_headers = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect::<String>();
    let canonical = format!(
        "{method}\n{uri}\n{query}\n{canonical_headers}\n{signed}\n{}",
        hex::encode(Sha256::digest(body))
    );
    let string_to_sign = format!(
        "SDK-HMAC-SHA256\n{date}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC allows arbitrary key lengths");
    mac.update(string_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    (
        format!("SDK-HMAC-SHA256 Access={id}, SignedHeaders={signed}, Signature={signature}"),
        signature,
    )
}

#[cfg(test)]
mod tests {
    use super::super::common::reconcile;
    use super::*;
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::State,
        http::{Request, Response, StatusCode},
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    struct Reply {
        status: u16,
        body: Value,
        raw: Option<String>,
        echo: bool,
        headers: Vec<(String, String)>,
    }
    fn reply(status: u16, body: Value) -> Reply {
        Reply {
            status,
            body,
            raw: None,
            echo: false,
            headers: vec![],
        }
    }
    fn zone() -> Value {
        json!({"id":"zone-test","name":"example.com.","zone_type":"public","status":"ACTIVE","project_id":"project-test","masters":[]})
    }
    fn rr(ip: &str) -> Value {
        json!({"id":"rr-test","name":"home.example.com.","description":"keep legal description","zone_id":"zone-test","zone_name":"example.com.","type":"A","ttl":300,"records":[ip],"status":"ACTIVE","default":false,"project_id":"project-test","line":"default_view","weight":1,"health_check_id":null,"alias_target":null,"created_at":"created-stable","updated_at":"updated-stable","links":{"self":"https://untrusted.invalid/do-not-follow"}})
    }
    fn pending(ip: &str, create: bool) -> Value {
        let mut v = rr(ip);
        v["status"] = json!(if create {
            "PENDING_CREATE"
        } else {
            "PENDING_UPDATE"
        });
        v
    }
    fn page(values: Vec<Value>, total: usize) -> Reply {
        reply(
            200,
            json!({"recordsets":values,"metadata":{"total_count":total},"links":{"next":"https://evil.invalid/never-follow"}}),
        )
    }
    fn snap(values: Vec<Value>) -> Vec<Reply> {
        let mut replies = vec![reply(200, zone()), page(values.clone(), values.len())];
        for v in values {
            if v["name"] == "home.example.com." && v["type"] == "A" {
                replies.push(reply(200, v));
            }
        }
        replies
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
    #[derive(Clone)]
    struct Seen {
        method: Method,
        path: String,
        headers: reqwest::header::HeaderMap,
        body: Value,
    }
    struct Server {
        replies: Mutex<VecDeque<Reply>>,
        seen: Mutex<Vec<Seen>>,
    }
    async fn handle(State(state): State<Arc<Server>>, req: Request<Body>) -> Response<Body> {
        let (parts, body) = req.into_parts();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
        let auth = parts
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let sig = auth.split("Signature=").nth(1).unwrap().to_string();
        state.seen.lock().unwrap().push(Seen {
            method: parts.method,
            path: parts.uri.to_string(),
            headers: parts.headers,
            body: if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        });
        let mut r = state
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                reply(
                    500,
                    json!({"error_code":"UnexpectedRequest","error_msg":"Mock exhausted"}),
                )
            });
        if r.echo {
            r.body = json!({"error_code":"DNS.0001","error_msg":format!("Rejected {auth} {sig} secret-test access-test"),"request_id":sig,"request_headers":{"Authorization":auth},"raw_payload":"PRIVATE-UNLISTED-PAYLOAD"});
            r.headers.push(("x-request-id".into(), sig));
        }
        let mut response = Response::builder().status(StatusCode::from_u16(r.status).unwrap());
        for (k, v) in r.headers {
            response = response.header(k, v);
        }
        response
            .body(Body::from(r.raw.unwrap_or_else(|| r.body.to_string())))
            .unwrap()
    }
    struct Mock {
        state: Arc<Server>,
        endpoint: String,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Mock {
        async fn new(replies: Vec<Reply>) -> Self {
            let state = Arc::new(Server {
                replies: Mutex::new(replies.into()),
                seen: Mutex::new(vec![]),
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let app = Router::new().fallback(handle).with_state(state.clone());
            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            Self {
                state,
                endpoint,
                task,
            }
        }
        fn adapter(&self) -> HuaweiCloud {
            let options = BTreeMap::from([
                ("region".into(), "cn-north-4".into()),
                ("project_id".into(), "project-test".into()),
                ("zone_id".into(), "zone-test".into()),
            ]);
            let mut a = HuaweiCloud::new(
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .retry(reqwest::retry::never())
                    .build()
                    .unwrap(),
                "access-test".into(),
                "secret-test".into(),
                &options,
            );
            a.endpoint = Some(self.endpoint.clone());
            a
        }
        fn seen(&self) -> Vec<Seen> {
            self.state.seen.lock().unwrap().clone()
        }
        fn readonly(&self) {
            assert!(self.seen().iter().all(|r| r.method == Method::GET));
        }
        fn consumed(&self) {
            assert!(self.state.replies.lock().unwrap().is_empty());
        }
    }
    #[test]
    fn independent_python_signer_goldens() {
        // Independent Python hashlib/hmac/urllib.parse vectors run 2026-11-09.
        let h = BTreeMap::from([
            ("content-type".into(), "application/json".into()),
            ("host".into(), "dns.cn-north-4.myhuaweicloud.com".into()),
            ("x-project-id".into(), "project-test".into()),
            ("x-sdk-date".into(), "20260102T030405Z".into()),
        ]);
        let q = canonical_query(&[
            ("name".into(), "home.example.com.".into()),
            ("tag".into(), "a b".into()),
            ("tag".into(), "+中文".into()),
            ("empty".into(), "".into()),
            ("tag".into(), "a".into()),
        ]);
        assert_eq!(
            q,
            "empty=&name=home.example.com.&tag=%2B%E4%B8%AD%E6%96%87&tag=a&tag=a%20b"
        );
        let (auth, sig) = sign(
            "access-test",
            "secret-test",
            "GET",
            "/v2.1/zones/zone-test/recordsets",
            &q,
            &h,
            b"",
            "20260102T030405Z",
        );
        assert_eq!(
            sig,
            "8a0690449c33d3a8fa1c28f4ecf1fed5bf975b605d23137e1ff1bf157de09bff"
        );
        assert_eq!(
            auth,
            format!(
                "SDK-HMAC-SHA256 Access=access-test, SignedHeaders=content-type;host;x-project-id;x-sdk-date, Signature={sig}"
            )
        );
        let(_,sig)=sign("access-test","secret-test","PUT","/v2.1/zones/zone-test/recordsets/rr-test","",&h,br#"{"name":"home.example.com.","records":["192.0.2.2"],"ttl":300,"type":"A","weight":1}"#,"20260102T030405Z");
        assert_eq!(
            sig,
            "c59ae3ad65e39027448fd6f36681f9a1c34d4ef253a8596ee82467140a62e146"
        );
        assert_eq!(escape("a +/中文~"), "a%20%2B%2F%E4%B8%AD%E6%96%87~");
        for id in [".", "..", "a/b", "x?y", "x%2F", "https://evil", "", "0"] {
            assert!(!path_id(id));
        }
        assert!(path_id("2c9-native.1"));
    }
    #[tokio::test]
    async fn validates_before_network() {
        let mock = Mock::new(vec![]).await;
        let a = mock.adapter();
        assert!(a.validate(&spec()).is_ok());
        for ttl in [0, 1, 299, 2147483648, u64::MAX] {
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(
                reconcile(&a, &s, "192.0.2.1", true).await.unwrap_err().code,
                "UnsupportedTTL"
            );
        }
        for ttl in [300, 2147483647] {
            let mut s = spec();
            s.ttl = ttl;
            assert!(a.validate(&s).is_ok());
        }
        for id in [".", "..", "a/b", "https://evil.invalid"] {
            let mut s = spec();
            s.record_id = Some(id.into());
            assert_eq!(a.validate(&s).unwrap_err().code, "InvalidResourceId");
        }
        for region in [
            "",
            "CN-NORTH-4",
            "cn-north-4.evil",
            "cn-north-4/",
            "https://dns.cn-north-4.myhuaweicloud.com",
            "unknown-1",
        ] {
            let mut a = mock.adapter();
            a.region = region.into();
            assert_eq!(a.validate(&spec()).unwrap_err().code, "InvalidRegion");
        }
        for name in [
            "example.com.",
            "https://example.com",
            "example..com",
            "x/path",
        ] {
            let mut s = spec();
            s.domain = name.into();
            assert_eq!(a.validate(&s).unwrap_err().code, "InvalidDnsName");
        }
        let mut s = spec();
        s.options.insert("zone_id".into(), "another-zone".into());
        assert_eq!(a.validate(&s).unwrap_err().code, "ZoneIdMismatch");
        let mut a = mock.adapter();
        a.project.clear();
        assert_eq!(a.validate(&spec()).unwrap_err().code, "InvalidProjectId");
        a = mock.adapter();
        a.key.clear();
        assert_eq!(a.validate(&spec()).unwrap_err().code, "InvalidCredentials");
        a = mock.adapter();
        a.invalid_options = true;
        assert_eq!(a.validate(&spec()).unwrap_err().code, "UnsupportedOptions");
        assert!(mock.seen().is_empty());
    }
    #[tokio::test]
    async fn unchanged_dryrun_and_signed_requests() {
        for (ip, dry, status) in [
            ("192.0.2.1", false, "unchanged"),
            ("192.0.2.2", true, "would_update"),
        ] {
            let mock = Mock::new(snap(vec![rr("192.0.2.1")])).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), ip, dry)
                    .await
                    .unwrap()
                    .status,
                status
            );
            mock.readonly();
            mock.consumed();
            let seen = mock.seen();
            assert_eq!(
                seen[1].path,
                "/v2.1/zones/zone-test/recordsets?limit=100&offset=0"
            );
            assert_eq!(seen[2].path, "/v2.1/zones/zone-test/recordsets/rr-test");
            assert!(seen.iter().all(|r| {
                r.headers["x-project-id"] == "project-test"
                    && r.headers.contains_key("x-sdk-date")
                    && r.headers["authorization"]
                        .to_str()
                        .unwrap()
                        .starts_with("SDK-HMAC-SHA256 Access=access-test,")
            }));
        }
        let mock = Mock::new(snap(vec![])).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_create"
        );
        mock.readonly();
        mock.consumed();
        let mock = Mock::new(snap(vec![])).await;
        let mut s = spec();
        s.create_if_missing = false;
        assert!(
            reconcile(&mock.adapter(), &s, "192.0.2.2", true)
                .await
                .is_err()
        );
        mock.readonly();
    }
    #[tokio::test]
    async fn unsafe_settings_before_unchanged_or_dryrun() {
        for (key, value, code) in [
            (
                "records",
                json!(["192.0.2.1", "192.0.2.2"]),
                "UnsafeRRsetValues",
            ),
            ("records", json!([]), "UnsafeRRsetValues"),
            ("records", json!(["::1"]), "InvalidRecordValue"),
            ("line", json!("custom-route"), "UnsafeRRsetSettings"),
            ("weight", json!(0), "UnsafeRRsetSettings"),
            ("weight", json!(2), "UnsafeRRsetSettings"),
            (
                "alias_target",
                json!({"resource_id":"alias"}),
                "UnsafeRRsetSettings",
            ),
            ("health_check_id", json!("health"), "UnsafeRRsetSettings"),
            ("default", json!(true), "UnsafeRRsetSettings"),
            ("routing", json!({"geo":"X"}), "UnknownRRsetSettings"),
            (
                "description",
                json!("x".repeat(256)),
                "UnknownRRsetSettings",
            ),
            ("project_id", json!("other-project"), "RRsetMismatch"),
        ] {
            for dry in [false, true] {
                let mut v = rr("192.0.2.1");
                v[key] = value.clone();
                let mock = Mock::new(snap(vec![v])).await;
                assert_eq!(
                    reconcile(&mock.adapter(), &spec(), "192.0.2.1", dry)
                        .await
                        .unwrap_err()
                        .code,
                    code,
                    "{key}"
                );
                mock.readonly();
            }
        }
        for state in [
            "DISABLE",
            "FREEZE",
            "ERROR",
            "PENDING_CREATE",
            "PENDING_UPDATE",
            "PENDING_DELETE",
        ] {
            let mut v = rr("192.0.2.1");
            v["status"] = json!(state);
            let mock = Mock::new(snap(vec![v])).await;
            assert!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.1", true)
                    .await
                    .is_err()
            );
            mock.readonly();
        }
        for field in ["line", "weight", "default"] {
            let mut v = rr("192.0.2.1");
            v.as_object_mut().unwrap().remove(field);
            let mock = Mock::new(snap(vec![v])).await;
            assert!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.1", true)
                    .await
                    .is_err()
            );
            mock.readonly();
        }
    }
    #[tokio::test]
    async fn exact_zone_state_project_native_ids() {
        for (key, value, code) in [
            ("id", json!("different-zone"), "ZoneMismatch"),
            ("name", json!("parent.example.com."), "ZoneMismatch"),
            ("zone_type", json!("private"), "ZoneInactive"),
            ("status", json!("DISABLE"), "ZoneInactive"),
            ("status", json!("PENDING_UPDATE"), "ZoneInactive"),
            ("project_id", json!("other-project"), "ProjectMismatch"),
            ("masters", json!(["192.0.2.1"]), "SecondaryZone"),
        ] {
            let mut v = zone();
            v[key] = value;
            let mock = Mock::new(vec![reply(200, v)]).await;
            assert_eq!(mock.adapter().list(&spec()).await.unwrap_err().code, code);
            mock.readonly();
        }
        let mock = Mock::new(vec![reply(
            404,
            json!({"error_code":"DNS.404","error_msg":"Zone absent"}),
        )])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "DNS.404"
        );
        assert_eq!(mock.seen().len(), 1);
        mock.readonly();
        for id in [json!(123), json!("."), json!(".."), json!("a/b")] {
            let mut v = rr("192.0.2.1");
            v["id"] = id;
            let mock = Mock::new(vec![reply(200, zone()), page(vec![v], 1)]).await;
            assert_eq!(
                mock.adapter().list(&spec()).await.unwrap_err().code,
                "InvalidResourceId"
            );
            mock.readonly();
        }
        let mock = Mock::new(snap(vec![rr("192.0.2.1")])).await;
        let mut s = spec();
        s.record_id = Some("missing-id".into());
        assert_eq!(
            reconcile(&mock.adapter(), &s, "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "RecordIdNotFound"
        );
        mock.readonly();
        let mut v = rr("192.0.2.1");
        v["name"] = json!("other.example.com.");
        let mock = Mock::new(vec![
            reply(200, zone()),
            page(vec![v.clone()], 1),
            reply(200, v),
        ])
        .await;
        let mut s = spec();
        s.record_id = Some("rr-test".into());
        assert!(
            reconcile(&mock.adapter(), &s, "192.0.2.2", false)
                .await
                .is_err()
        );
        mock.readonly();
    }
    #[tokio::test]
    async fn full_pagination_discovery_never_follows_links() {
        let mut v = rr("192.0.2.5");
        v["id"] = json!("other");
        v["name"] = json!("other.example.com.");
        let mock = Mock::new(vec![
            reply(200, zone()),
            page(vec![v], 2),
            page(vec![rr("192.0.2.1")], 2),
            reply(200, rr("192.0.2.1")),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert!(mock.seen()[2].path.ends_with("offset=1"));
        mock.consumed();
        let mut parent = zone();
        parent["id"] = json!("parent-zone");
        parent["name"] = json!("com.");
        let mut near = zone();
        near["id"] = json!("near-zone");
        near["name"] = json!("evil-example.com.");
        let mut replies = vec![
            reply(
                200,
                json!({"zones":[parent,near],"metadata":{"total_count":3}}),
            ),
            reply(200, json!({"zones":[zone()],"metadata":{"total_count":3}})),
        ];
        replies.extend(snap(vec![]));
        let mock = Mock::new(replies).await;
        let mut a = mock.adapter();
        a.zone_id = None;
        assert!(a.list(&spec()).await.unwrap().records.is_empty());
        assert!(mock.seen()[0].path.contains("search_mode=equal"));
        assert!(mock.seen()[1].path.contains("offset=2"));
        mock.consumed();
        for values in [
            vec![json!({"id":"parent","name":"com."})],
            vec![zone(), json!({"id":"duplicate-zone","name":"EXAMPLE.COM."})],
        ] {
            let mock = Mock::new(vec![reply(
                200,
                json!({"zones":values,"metadata":{"total_count":values.len()}}),
            )])
            .await;
            let mut a = mock.adapter();
            a.zone_id = None;
            assert!(a.list(&spec()).await.is_err());
            mock.readonly();
        }
        for pages in [
            vec![page(vec![], 1)],
            vec![
                page(vec![rr("192.0.2.1")], 2),
                page(vec![rr("192.0.2.1")], 2),
            ],
            vec![page(vec![rr("192.0.2.1")], 2), page(vec![], 3)],
            vec![reply(200, json!({"recordsets":[],"metadata":{}}))],
            vec![page(vec![], 10001)],
        ] {
            let mut replies = vec![reply(200, zone())];
            replies.extend(pages);
            let mock = Mock::new(replies).await;
            assert!(mock.adapter().list(&spec()).await.is_err());
            mock.readonly();
        }
    }
    #[tokio::test]
    async fn cname_delegation_before_would_create() {
        for (name, kind, code) in [
            ("home.example.com.", "CNAME", "ConflictingCNAME"),
            ("home.example.com.", "NS", "DelegatedTarget"),
            ("example.com.", "NS", ""),
        ] {
            let mut v = rr("192.0.2.1");
            v["type"] = json!(kind);
            v["name"] = json!(name);
            v["records"] = json!(["ns.example.net."]);
            let mock = Mock::new(vec![reply(200, zone()), page(vec![v], 1)]).await;
            let result = reconcile(&mock.adapter(), &spec(), "192.0.2.2", true).await;
            if code.is_empty() {
                assert_eq!(result.unwrap().status, "would_create");
            } else {
                assert_eq!(result.unwrap_err().code, code);
            }
            mock.readonly();
        }
        let mut v = rr("192.0.2.1");
        v["type"] = json!("NS");
        v["records"] = json!(["ns.example.net."]);
        let mock = Mock::new(vec![reply(200, zone()), page(vec![v], 1)]).await;
        let mut s = spec();
        s.subdomain = "deep.home".into();
        assert_eq!(
            reconcile(&mock.adapter(), &s, "192.0.2.2", true)
                .await
                .unwrap_err()
                .code,
            "DelegatedTarget"
        );
        mock.readonly();
    }
    fn update_replies(ack: Reply, read: Option<Reply>) -> Vec<Reply> {
        let mut replies = snap(vec![rr("192.0.2.1")]);
        replies.extend(snap(vec![rr("192.0.2.1")]));
        replies.push(reply(200, rr("192.0.2.1")));
        replies.push(ack);
        if let Some(read) = read {
            replies.push(read);
        }
        replies
    }
    #[tokio::test]
    async fn update_payload_and_exact_readback() {
        let mock = Mock::new(update_replies(
            reply(202, pending("192.0.2.2", false)),
            Some(reply(200, rr("192.0.2.2"))),
        ))
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        mock.consumed();
        let seen = mock.seen();
        let writes: Vec<_> = seen.iter().filter(|r| r.method != Method::GET).collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].method, Method::PUT);
        assert_eq!(writes[0].path, "/v2.1/zones/zone-test/recordsets/rr-test");
        assert_eq!(
            writes[0].body,
            json!({"name":"home.example.com.","description":"keep legal description","type":"A","ttl":300,"records":["192.0.2.2"],"weight":1})
        );
        assert_eq!(seen.last().unwrap().method, Method::GET);
    }
    #[tokio::test]
    async fn create_fresh_full_snapshot_second_absence_read() {
        let mut replies = snap(vec![]);
        replies.extend(snap(vec![]));
        replies.extend(snap(vec![]));
        replies.push(reply(202, pending("192.0.2.2", true)));
        replies.push(reply(200, rr("192.0.2.2")));
        let mock = Mock::new(replies).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap()
                .status,
            "created"
        );
        mock.consumed();
        let seen = mock.seen();
        let write = seen.iter().find(|r| r.method == Method::POST).unwrap();
        assert_eq!(
            write.body,
            json!({"name":"home.example.com.","type":"A","ttl":300,"records":["192.0.2.2"],"weight":1,"line":"default_view","status":"ENABLE"})
        );
        assert_eq!(seen.iter().filter(|r| r.method == Method::POST).count(), 1);
        for late in [false, true] {
            let mut replies = snap(vec![]);
            if late {
                replies.extend(snap(vec![]));
            }
            replies.extend(snap(vec![rr("192.0.2.1")]));
            let mock = Mock::new(replies).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                "RecordAppeared"
            );
            mock.readonly();
        }
        let mut v = rr("192.0.2.1");
        v["type"] = json!("CNAME");
        v["records"] = json!(["elsewhere.example.net."]);
        let mut replies = snap(vec![]);
        replies.extend(snap(vec![v]));
        let mock = Mock::new(replies).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "ConflictingCNAME"
        );
        mock.readonly();
    }
    #[tokio::test]
    async fn prewrite_full_metadata_and_immediate_equality() {
        for key in [
            "description",
            "updated_at",
            "bundle",
            "records",
            "weight",
            "line",
            "health_check_id",
        ] {
            let mut v = rr("192.0.2.1");
            v[key] = if key == "records" {
                json!(["192.0.2.9"])
            } else if key == "weight" {
                json!(2)
            } else {
                json!("changed")
            };
            let mut replies = snap(vec![rr("192.0.2.1")]);
            replies.extend(snap(vec![v]));
            let mock = Mock::new(replies).await;
            assert!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                    .await
                    .is_err(),
                "{key}"
            );
            mock.readonly();
        }
        let mut changed = rr("192.0.2.1");
        changed["description"] = json!("changed after full snapshot");
        let mut replies = snap(vec![rr("192.0.2.1")]);
        replies.extend(snap(vec![rr("192.0.2.1")]));
        replies.push(reply(200, changed));
        let mock = Mock::new(replies).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "RRsetChanged"
        );
        mock.readonly();
    }
    #[tokio::test]
    async fn pending_uncertain_mismatches_no_writer_retries() {
        for (key, value) in [
            ("id", json!("wrong-id")),
            ("name", json!("other.example.com.")),
            ("records", json!(["192.0.2.9"])),
            ("ttl", json!(600)),
            ("line", json!("geo")),
            ("description", json!("lost")),
            ("status", json!("ACTIVE")),
            ("routing", json!({"geo":"X"})),
        ] {
            let mut ack = pending("192.0.2.2", false);
            ack[key] = value;
            let mock = Mock::new(update_replies(reply(202, ack), None)).await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                "InvalidWriteAcknowledgement",
                "{key}"
            );
            assert_eq!(
                mock.seen()
                    .iter()
                    .filter(|r| r.method == Method::PUT)
                    .count(),
                1
            );
            mock.consumed();
        }
        for (read, code) in [
            (reply(200, pending("192.0.2.2", false)), "WritePending"),
            (reply(200, rr("192.0.2.9")), "WriteVerificationFailed"),
            (
                reply(
                    404,
                    json!({"error_code":"DNS.404","error_msg":"Not visible"}),
                ),
                "DNS.404",
            ),
        ] {
            let mock = Mock::new(update_replies(
                reply(202, pending("192.0.2.2", false)),
                Some(read),
            ))
            .await;
            let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, code);
            assert!(!e.retryable);
            assert_eq!(
                mock.seen()
                    .iter()
                    .filter(|r| r.method == Method::PUT)
                    .count(),
                1
            );
            mock.consumed();
        }
        for (status, code) in [(200, "InvalidAcknowledgement"), (503, "DNS.Unavailable")] {
            let body = if status == 200 {
                pending("192.0.2.2", false)
            } else {
                json!({"error_code":"DNS.Unavailable","error_msg":"Write uncertain"})
            };
            let mock = Mock::new(update_replies(reply(status, body), None)).await;
            let e = reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, code);
            assert!(!e.retryable);
            assert_eq!(
                mock.seen()
                    .iter()
                    .filter(|r| r.method == Method::PUT)
                    .count(),
                1
            );
        }
    }
    #[tokio::test]
    async fn aaaa_apex_no_name_guessing() {
        let mut s = spec();
        s.record_type = "AAAA".into();
        s.subdomain = "@".into();
        let mut v = rr("192.0.2.1");
        v["type"] = json!("AAAA");
        v["name"] = json!("example.com.");
        v["records"] = json!(["2001:db8:0:0::1"]);
        let mock = Mock::new(vec![
            reply(200, zone()),
            page(vec![v.clone()], 1),
            reply(200, v),
        ])
        .await;
        assert_eq!(
            reconcile(&mock.adapter(), &s, "2001:db8::1", true)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        mock.readonly();
        mock.consumed();
    }
    #[tokio::test]
    async fn bounded_business_errors_safe_request_ids() {
        for status in [200, 400, 401, 403, 404, 409, 429, 500, 503] {
            let mock=Mock::new(vec![reply(status,json!({"error_code":"DNS.0001","error_msg":"Specific permission/TTL failure","request_id":"safe-request-123","unlisted":"PRIVATE-PAYLOAD"}))]).await;
            let e = mock.adapter().list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "DNS.0001");
            assert_eq!(e.http_status, Some(status));
            assert!(e.message.contains("Specific permission/TTL failure"));
            assert_eq!(e.request_id.as_deref(), Some("safe-request-123"));
            assert!(!e.message.contains("PRIVATE-PAYLOAD"));
            assert_eq!(e.retryable, status == 429 || status >= 500);
            mock.readonly();
        }
        let mock=Mock::new(vec![reply(400,json!({"error_code":"DNS.Long","error_msg":"x".repeat(5000),"request_id":"https://evil.invalid/PRIVATE"}))]).await;
        let e = mock.adapter().list(&spec()).await.unwrap_err();
        assert!(e.message.len() < 2200);
        assert!(e.request_id.is_none());
        let mock=Mock::new(vec![reply(400,json!({"error_code":"DNS.URL","error_msg":"Provider https://evil.invalid/PRIVATE body"}))]).await;
        assert!(
            !mock
                .adapter()
                .list(&spec())
                .await
                .unwrap_err()
                .message
                .contains("evil.invalid")
        );
        let mut r = reply(503, Value::Null);
        r.raw = Some("PRIVATE-NONJSON-BODY".into());
        let mock = Mock::new(vec![r]).await;
        let e = mock.adapter().list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "MalformedResponse");
        assert!(!e.message.contains("PRIVATE-NONJSON-BODY"));
        let mut r = reply(400, json!({"error_code":"DNS.Test","error_msg":"bad"}));
        r.headers
            .push(("x-openstack-request-id".into(), "safe-openstack-id".into()));
        let mock = Mock::new(vec![r]).await;
        assert_eq!(
            mock.adapter()
                .list(&spec())
                .await
                .unwrap_err()
                .request_id
                .as_deref(),
            Some("safe-openstack-id")
        );
    }
    #[derive(Clone)]
    struct Trace(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Trace {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Trace {
        type Writer = Trace;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
    #[tokio::test]
    async fn scoped_generated_auth_signature_trace_redaction() {
        // Other API tests dynamically reload the process-wide log filter. Run
        // this positive trace/redaction assertion in an isolated test process;
        // otherwise global callsite interest can change during the local capture.
        const ISOLATED: &str = "DDNS_HUAWEI_TRACE_TEST_ISOLATED";
        if std::env::var_os(ISOLATED).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "providers::huaweicloud::tests::scoped_generated_auth_signature_trace_redaction",
                    "--nocapture",
                ])
                .env(ISOLATED, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated trace/redaction test failed"
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let trace = Trace(Arc::new(Mutex::new(vec![])));
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(trace.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(sub);
        let mut r = reply(403, Value::Null);
        r.echo = true;
        let mock = Mock::new(vec![r]).await;
        let e = mock.adapter().list(&spec()).await.unwrap_err();
        let seen = mock.seen();
        let auth = seen[0].headers["authorization"].to_str().unwrap();
        let sig = auth.split("Signature=").nth(1).unwrap();
        let text = format!(
            "{} {} {:?} {}",
            e.code,
            e.message,
            e.request_id,
            String::from_utf8(trace.0.lock().unwrap().clone()).unwrap()
        );
        for secret in [
            auth,
            sig,
            "access-test",
            "secret-test",
            "PRIVATE-UNLISTED-PAYLOAD",
            "request_headers",
        ] {
            assert!(!text.contains(secret), "secret leaked");
        }
        assert!(e.request_id.is_none());
        assert!(text.contains("HuaweiGetZone"));
    }
    #[tokio::test]
    async fn ipv6_ttl_only_update_and_postwrite_state_failures() {
        let mut s = spec();
        s.record_type = "AAAA".into();
        s.ttl = 600;
        let mut old = rr("192.0.2.1");
        old["type"] = json!("AAAA");
        old["records"] = json!(["2001:db8::1"]);
        let mut ack = old.clone();
        ack["ttl"] = json!(600);
        ack["status"] = json!("PENDING_UPDATE");
        let mut read = ack.clone();
        read["status"] = json!("ACTIVE");
        let replies = vec![
            reply(200, zone()),
            page(vec![old.clone()], 1),
            reply(200, old.clone()),
            reply(200, zone()),
            page(vec![old.clone()], 1),
            reply(200, old.clone()),
            reply(200, old),
            reply(202, ack),
            reply(200, read),
        ];
        let mock = Mock::new(replies).await;
        assert_eq!(
            reconcile(&mock.adapter(), &s, "2001:db8::1", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        assert_eq!(
            mock.seen()
                .iter()
                .find(|r| r.method == Method::PUT)
                .unwrap()
                .body["records"],
            json!(["2001:db8::1"])
        );
        mock.consumed();
        for (key, value) in [
            ("ttl", json!(600)),
            ("line", json!("custom-route")),
            ("health_check_id", json!("health")),
            ("alias_target", json!({"resource_id":"alias"})),
            ("description", json!("lost")),
            ("status", json!("ERROR")),
            ("status", json!("DISABLE")),
            ("default", json!(true)),
            ("bundle", json!("new-reserved-setting")),
        ] {
            let mut read = rr("192.0.2.2");
            read[key] = value;
            let mock = Mock::new(update_replies(
                reply(202, pending("192.0.2.2", false)),
                Some(reply(200, read)),
            ))
            .await;
            assert_eq!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                "WriteVerificationFailed",
                "{key}"
            );
            assert_eq!(
                mock.seen()
                    .iter()
                    .filter(|r| r.method == Method::PUT)
                    .count(),
                1
            );
            mock.consumed();
        }
    }
    #[tokio::test]
    async fn ambiguous_rrsets_and_list_detail_disagreement() {
        let mut another = rr("192.0.2.1");
        another["id"] = json!("another-rrset");
        let mock = Mock::new(snap(vec![rr("192.0.2.1"), another])).await;
        assert_eq!(
            reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                .await
                .unwrap_err()
                .code,
            "AmbiguousRecords"
        );
        mock.readonly();
        for (key, value) in [
            ("name", json!("other.example.com.")),
            ("type", json!("AAAA")),
            ("description", json!("changed")),
            ("records", json!(["192.0.2.9"])),
            ("zone_id", json!("wrong-zone")),
            ("zone_name", json!("wrong.example.com.")),
        ] {
            let mut detail = rr("192.0.2.1");
            detail[key] = value;
            let mock = Mock::new(vec![
                reply(200, zone()),
                page(vec![rr("192.0.2.1")], 1),
                reply(200, detail),
            ])
            .await;
            assert!(
                reconcile(&mock.adapter(), &spec(), "192.0.2.2", true)
                    .await
                    .is_err(),
                "{key}"
            );
            mock.readonly();
        }
    }
    #[tokio::test]
    async fn malformed_oversized_and_transport_responses_are_honest() {
        let mut r = reply(503, Value::Null);
        r.raw = Some("PRIVATE-BODY".into());
        r.headers
            .push(("error".into(), "PRIVATE-NON-HUAWEI-HEADER".into()));
        let mock = Mock::new(vec![r]).await;
        let e = mock.adapter().list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "MalformedResponse");
        assert!(!e.message.contains("PRIVATE"));
        let mut r = reply(200, Value::Null);
        r.raw = Some("x".repeat(1024 * 1024 + 1));
        let mock = Mock::new(vec![r]).await;
        assert_eq!(
            mock.adapter().list(&spec()).await.unwrap_err().code,
            "ResponseTooLarge"
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let mock = Mock::new(vec![]).await;
        let mut a = mock.adapter();
        a.endpoint = Some(endpoint);
        let e = a.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "ConnectionFailure");
        assert!(e.retryable);
        assert!(!e.message.contains("http://"));
    }
    #[tokio::test]
    async fn redirects_never_forward_signed_auth() {
        let target = Mock::new(vec![]).await;
        let mut r = reply(307, json!({"error_msg":"Redirect rejected"}));
        r.headers
            .push(("location".into(), format!("{}/steal", target.endpoint)));
        let mock = Mock::new(vec![r]).await;
        assert!(mock.adapter().list(&spec()).await.is_err());
        assert!(target.seen().is_empty());
        assert_eq!(mock.seen().len(), 1);
    }
}
