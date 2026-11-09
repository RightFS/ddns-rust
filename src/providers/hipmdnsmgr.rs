//! HiPM DnsMgr (now HiDNS), deployment-owned HTTPS API origin + Bearer API token.
//! Official evidence (public docs/source, never production DNS API requests):
//! https://github.com/HiPM-Tech/HiDNS/blob/main/README.md
//! https://github.com/HiPM-Tech/HiDNS/blob/main/docs/api.md
//! https://github.com/HiPM-Tech/HiDNS/blob/main/server/src/routes/domains.ts
//! https://github.com/HiPM-Tech/HiDNS/blob/main/server/src/routes/accounts.ts
//! https://github.com/HiPM-Tech/HiDNS/blob/main/server/src/routes/records.ts
//! https://github.com/HiPM-Tech/HiDNS/blob/main/server/src/lib/dns/providers/hidns/adapter.ts
//! https://github.com/HiPM-Tech/HiDNS/blob/main/server/src/lib/dns/providers/aliyun/adapter.ts
//!
//! There is NO global production endpoint. endpoint_env MUST name a HIPM_-scoped
//! server-owned environment variable; Web options cannot contain a target URL.
//! Its value must be an HTTPS origin (optional /api). TLS verification remains
//! enabled; caller MUST disable redirects. HTTP is supported only by private
//! cfg(test) localhost override. No response-supplied URLs or automatic retries.
//!
//! Only the audited manager account type `aliyun` is supported: its official
//! adapter updates one native RecordId with UpdateDomainRecord, not an RRset.
//! Cloudflare, PowerDNS, nested HiDNS, ESA, EdgeOne and other unaudited mappings
//! are refused before dry-run/noop: the generic manager projection is not proof
//! of preservation of their settings, tags, metadata or whole-RRset siblings.
//! Aliyun's line/TTL are forwarded; status/weight/remark are separate native
//! controls and are preserved by OMITTING them from the update request. This
//! avoids HiDNS's optional separate remark mutation and undocumented Weight
//! update parameter. Creation intentionally uses provider defaults for these
//! optional controls. Unknown record metadata/proxy projections are refused.
//!
//! Token domain lists are bare arrays: unrestricted tokens paginate without
//! total; restricted tokens can return their entire whitelist on every page.
//! Full discovery requires an empty next page; repeated pages fail closed with
//! a hint to configure domain_id (exact authenticated detail/name/account proof).
//! Record reads are unfiltered {total,list}, pageSize=100, bounded at 10,000,
//! with total stability/duplicate IDs/empty next-page protection. POST returns
//! data.id; PUT has no ID acknowledgement, so one strict full readback confirms
//! target ID/value/TTL/line and unchanged sibling/control metadata. No CAS is
//! documented: snapshots detect changes before writes, not races afterwards.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, Api, HttpReply, List, Mutation, Record, Spec, valid_id};
use crate::provider::ProviderError;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};

const HINT: &str = "Use a scoped HiDNS API Bearer token, an enabled aliyun account and an exact manager-local domain. Set endpoint_env to a HIPM_-scoped server environment variable containing the deployment's HTTPS origin; use a TLS reverse proxy for HTTP-only deployments. domain_id avoids uncounted/repeating token-domain discovery. Only audited Aliyun per-record operations are supported. No CAS is documented: use one writer. Inspect uncertain writes before retrying; no automatic write retry occurred.";
const MAX_RECORDS: usize = 10_000;

pub struct HipmDnsMgr {
    api: Api,
    token: String,
    options: BTreeMap<String, String>,
    endpoint: Option<String>,
    #[cfg(test)]
    mock_endpoint: Option<String>,
}
#[derive(Clone)]
struct Snapshot {
    zone: Value,
    account: Value,
    records: Vec<Record>,
    request_id: Option<String>,
}
impl Snapshot {
    fn proof(&self) -> Value {
        let mut rows: Vec<_> = self.records.iter().map(|r| r.extra.clone()).collect();
        rows.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let full = json!({"zone": self.zone, "account": self.account, "records": rows});
        // A bounded digest proves every raw row without O(record_count^2)
        // cloning when the common Record model carries per-record JSON extras.
        json!(hex::encode(Sha256::digest(
            serde_json::to_vec(&full).expect("JSON snapshot")
        )))
    }
}
impl HipmDnsMgr {
    #[cfg(test)]
    pub fn new(client: reqwest::Client, token: String, options: &BTreeMap<String, String>) -> Self {
        Self::new_with_direct(client, token, options, None)
    }
    pub fn new_with_direct(
        client: reqwest::Client,
        token: String,
        options: &BTreeMap<String, String>,
        direct: Option<&str>,
    ) -> Self {
        // Validate the environment name BEFORE lookup. Never read arbitrary
        // process variables chosen by Web configuration, including DDNS_*.
        let endpoint = direct.map(str::to_owned).or_else(|| {
            options
                .get("endpoint_env")
                .filter(|s| endpoint_env(s))
                .and_then(|name| std::env::var(name).ok())
        });
        let mut secrets = vec![
            format!("Bearer {token}"),
            token.clone(),
            utf8_percent_encode(&token, NON_ALPHANUMERIC).to_string(),
        ];
        if let Some(value) = &endpoint {
            // Even diagnostics returned by the manager must not reveal origin.
            secrets.push(value.clone());
            if let Ok(url) = Url::parse(value)
                && let Some(host) = url.host_str()
            {
                secrets.push(host.into());
            }
        }
        Self {
            api: Api::new(client, secrets),
            token,
            options: options.clone(),
            endpoint,
            #[cfg(test)]
            mock_endpoint: None,
        }
    }
    #[cfg(test)]
    fn with_mock_endpoint(mut self, endpoint: String) -> Self {
        let url = Url::parse(&endpoint).expect("localhost mock URL");
        assert_eq!(url.scheme(), "http");
        assert_eq!(url.host_str(), Some("127.0.0.1"));
        self.mock_endpoint = Some(endpoint);
        self
    }
    fn error(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        self.api.error(stage, code, message, HINT, reply)
    }
    fn safe_business_detail(&self, message: &str) -> String {
        // Manager errors can echo UNDERLYING provider credentials, which are
        // not our Bearer token and cannot be safely redacted by exact matching.
        // Omit only credential-shaped value dumps; benign InvalidAccessKeyId
        // error names remain useful diagnostics. Also inspect percent-encoded
        // dumps without ever printing decoded content.
        let decoded_once = percent_encoding::percent_decode_str(message).decode_utf8_lossy();
        let decoded = percent_encoding::percent_decode_str(&decoded_once).decode_utf8_lossy();
        let normalized: String = decoded
            .to_ascii_lowercase()
            .chars()
            .filter(|c| !matches!(c, '\"' | '\'' | '`' | '\\'))
            .collect();
        if [
            "accesskeyid",
            "access_key_id",
            "accesskeysecret",
            "access_key_secret",
            "secretid",
            "secret_id",
            "signature",
            "config",
            "secretkey",
            "secret_key",
            "apikey",
            "api_key",
            "apitoken",
            "api_token",
            "password",
            "token",
        ]
        .iter()
        .any(|field| {
            normalized.match_indices(field).any(|(index, _)| {
                let boundary = index == 0
                    || !normalized.as_bytes()[index - 1].is_ascii_alphanumeric()
                        && normalized.as_bytes()[index - 1] != b'_';
                let suffix = normalized[index + field.len()..].trim_start();
                boundary
                    && (suffix.starts_with([':', '='])
                        || *field == "config" && suffix.starts_with(['{', '[']))
            })
        }) {
            return "[Underlying provider credential/config diagnostic omitted]".into();
        }
        self.api.safe(&decoded)
    }
    fn origin(&self) -> Result<String, ProviderError> {
        #[cfg(test)]
        if let Some(endpoint) = &self.mock_endpoint {
            return Ok(endpoint.clone());
        }
        let value = self.endpoint.as_deref().ok_or_else(|| self.error("configuration", "MissingEndpoint", "Set the validated HIPM_-scoped endpoint environment variable on the server; there is no default/global service origin.", None))?;
        production_origin(value).ok_or_else(|| self.error("configuration", "InvalidEndpoint", "Endpoint environment value must be a plain HTTPS origin, optionally ending in /api, without userinfo, query or fragment. Its value is intentionally omitted.", None))
    }
    fn validate(&self, spec: &Spec) -> Result<(), ProviderError> {
        if !self
            .options
            .get("endpoint_env")
            .is_some_and(|s| endpoint_env(s))
            && !(self.endpoint.is_some()
                && self
                    .options
                    .get("endpoint_env")
                    .is_none_or(String::is_empty))
        {
            return Err(self.error("configuration", "InvalidEndpointEnv", "endpoint_env must be a 6..64-character HIPM_-scoped uppercase environment name; arbitrary environment lookups are refused.", None));
        }
        if self
            .options
            .keys()
            .any(|k| !matches!(k.as_str(), "endpoint_env" | "domain_id"))
            || !spec.options.is_empty()
        {
            return Err(self.error("validation", "UnsupportedOptions", "Only provider endpoint_env and optional domain_id are accepted; no record options, mutable URL, proxy or TTL bypass settings.", None));
        }
        self.origin()?;
        if self.token.is_empty()
            || self.token.len() > 4096
            || self
                .token
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(self.error("credentials", "InvalidCredentials", "A nonempty plain HiDNS API token is required; whitespace/control characters are refused.", None));
        }
        if !dns_name(&spec.domain, false)
            || !spec.domain.contains('.')
            || (spec.subdomain != "@" && !dns_name(&spec.subdomain, false))
            || spec.fqdn().len() > 253
        {
            return Err(self.error(
                "validation",
                "InvalidDnsName",
                "Use an exact ASCII/punycode zone and a plain relative child host or @.",
                None,
            ));
        }
        if !matches!(spec.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Only A/AAAA records are supported.",
                None,
            ));
        }
        if !spec.record_line.is_ascii() || spec.record_line.chars().any(|c| c.is_whitespace()) {
            return Err(self.error("validation", "InvalidRecordLine", "record_line must be an actual ASCII Aliyun line ID such as default, not the display label 默认; routing changes are refused.", None));
        }
        if !(1..=604800).contains(&spec.ttl)
            || spec.record_line.is_empty()
            || spec.record_line.len() > 128
            || spec.record_line.chars().any(|c| c.is_control())
        {
            return Err(self.error("validation", "InvalidSettings", "Use TTL in 1..604800 and a nonempty actual provider line ID (Aliyun default is default).", None));
        }
        if self
            .options
            .get("domain_id")
            .is_some_and(|s| decimal_id(&json!(s)).as_deref() != Some(s))
            || spec.record_id.as_ref().is_some_and(|s| !valid_id(s))
        {
            return Err(self.error("validation", "InvalidId", "domain_id must be canonical positive decimal; record_id must be a plain native record ID.", None));
        }
        Ok(())
    }
    fn desired(&self, spec: &Spec, ip: &str) -> Result<String, ProviderError> {
        self.validate(spec)?;
        let ip: IpAddr = ip.parse().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be a literal IP address.",
                None,
            )
        })?;
        if ip.is_ipv4() != (spec.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "IP family does not match record type.",
                None,
            ));
        }
        Ok(ip.to_string())
    }
    async fn call(
        &self,
        stage: &str,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<HttpReply, ProviderError> {
        let write = method != Method::GET;
        let mut request = self
            .api
            .client
            .request(method, format!("{}/api{path}", self.origin()?))
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let reply = self.api.send(stage, request, write).await?;
        let code = reply.body.get("code").and_then(Value::as_i64);
        if !(200..300).contains(&reply.status) || code.is_some_and(|c| c != 0) {
            let detail = reply
                .body
                .get("msg")
                .and_then(Value::as_str)
                .map(|s| self.safe_business_detail(s))
                .unwrap_or_else(|| "No recognized business detail; raw body omitted.".into());
            let code = code
                .filter(|c| *c != 0)
                .map(|c| format!("HiDNS{c}"))
                .unwrap_or_else(|| format!("Http{}", reply.status));
            return Err(self.error(
                stage,
                &code,
                &format!("HiDNS API failure: {detail}"),
                Some(&reply),
            ));
        }
        if reply.status != 200 || code != Some(0) || !reply.body.is_object() {
            return Err(self.error(stage, "InvalidEnvelope", "Expected official HTTP200 JSON success envelope with numeric code=0; inspect any uncertain write.", Some(&reply)));
        }
        Ok(reply)
    }
    async fn discover_zone(&self, spec: &Spec) -> Result<String, ProviderError> {
        if let Some(id) = self.options.get("domain_id") {
            return Ok(id.clone());
        }
        let mut seen = HashSet::new();
        let mut matches = Vec::new();
        let mut count = 0;
        let mut total = None;
        for page in 1..=102 {
            let reply = self
                .call(
                    "zone_list",
                    Method::GET,
                    &format!(
                        "/domains?page={page}&pageSize=100&include_disabled=true&domain_status=all"
                    ),
                    None,
                )
                .await?;
            let data = &reply.body["data"];
            let (rows, declared) = if let Some(rows) = data.as_array() {
                (rows, None)
            } else {
                (
                    data["list"].as_array().ok_or_else(|| {
                        self.error(
                            "zone_list",
                            "MalformedZoneList",
                            "Expected official array or list/total domain model.",
                            Some(&reply),
                        )
                    })?,
                    Some(data["total"].as_u64().ok_or_else(|| {
                        self.error(
                            "zone_list",
                            "MalformedZoneList",
                            "Paginated domain object lacks a numeric total.",
                            Some(&reply),
                        )
                    })?),
                )
            };
            if rows.len() > 100
                || declared.is_some_and(|n| n > MAX_RECORDS as u64)
                || (page > 1 && total != declared)
            {
                return Err(self.error("zone_list", "UnstablePagination", "Domain page size/total changed or exceeded safety bound; no authoritative selection.", Some(&reply)));
            }
            total = declared;
            if rows.is_empty() {
                if declared.is_some_and(|n| n != count) {
                    return Err(self.error(
                        "zone_list",
                        "IncompleteList",
                        "Empty domain page arrived before declared total was read.",
                        Some(&reply),
                    ));
                }
                return match matches.len() {
                    1 => Ok(matches.remove(0)),
                    0 => Err(self.error(
                        "zone",
                        "ZoneNotFound",
                        "Exact authenticated zone name was not found; suffix matching is refused.",
                        Some(&reply),
                    )),
                    _ => Err(self.error(
                        "zone",
                        "AmbiguousZones",
                        "Multiple manager domains have the exact name; set domain_id explicitly.",
                        Some(&reply),
                    )),
                };
            }
            if declared.is_some_and(|n| count >= n) {
                return Err(self.error(
                    "zone_list",
                    "UnexpectedNextPage",
                    "Provider returned domains beyond declared total.",
                    Some(&reply),
                ));
            }
            for row in rows {
                let id = decimal_id(&row["id"]).ok_or_else(|| {
                    self.error(
                        "zone_list",
                        "MalformedZone",
                        "Domain lacks valid local ID.",
                        Some(&reply),
                    )
                })?;
                if !seen.insert(id.clone()) {
                    return Err(self.error("zone_list", "RepeatedPage", "Domain IDs repeated across pages. Restricted API tokens can repeat their whitelist; configure domain_id for exact authenticated detail proof instead.", Some(&reply)));
                }
                let name = row["name"]
                    .as_str()
                    .filter(|s| dns_name(s, false))
                    .ok_or_else(|| {
                        self.error(
                            "zone_list",
                            "MalformedZone",
                            "Domain lacks a valid documented name.",
                            Some(&reply),
                        )
                    })?;
                if name.eq_ignore_ascii_case(&spec.domain) {
                    matches.push(id);
                }
                count += 1;
            }
            if count > MAX_RECORDS as u64 || declared.is_some_and(|n| count > n) {
                return Err(self.error(
                    "zone_list",
                    "RecordLimit",
                    "Domain count exceeded safety bound or declared total.",
                    Some(&reply),
                ));
            }
        }
        Err(self.error(
            "zone_list",
            "PaginationLimit",
            "Domain discovery never established a complete bounded list; configure domain_id.",
            None,
        ))
    }
    async fn zone(&self, spec: &Spec) -> Result<(Value, Value, Option<String>), ProviderError> {
        self.validate(spec)?;
        let id = self.discover_zone(spec).await?;
        let reply = self
            .call("zone", Method::GET, &format!("/domains/{id}"), None)
            .await?;
        let raw = &reply.body["data"];
        if decimal_id(&raw["id"]).as_deref() != Some(&id)
            || !raw["name"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(&spec.domain))
        {
            return Err(self.error(
                "zone",
                "ZoneMismatch",
                "Authenticated detail did not prove exact requested manager domain ID/name.",
                Some(&reply),
            ));
        }
        if raw.get("enabled").is_some_and(|v| v.as_u64() != Some(1))
            || raw["can_write"].as_bool() != Some(true)
        {
            return Err(self.error("zone", "ZoneDisabledOrReadOnly", "Domain is disabled or does not acknowledge write permission; dry-run/noop are refused too.", Some(&reply)));
        }
        let account_id = decimal_id(&raw["account_id"]).ok_or_else(|| {
            self.error(
                "zone",
                "MalformedZone",
                "Domain lacks documented account_id.",
                Some(&reply),
            )
        })?;
        let third_id = raw["third_id"].as_str().ok_or_else(|| {
            self.error(
                "zone",
                "MalformedZone",
                "Domain lacks documented underlying third_id string.",
                Some(&reply),
            )
        })?;
        let account_reply = self
            .call(
                "account",
                Method::GET,
                &format!("/accounts/{account_id}"),
                None,
            )
            .await?;
        let account = &account_reply.body["data"];
        if decimal_id(&account["id"]).as_deref() != Some(&account_id)
            || account["enabled"].as_bool() != Some(true)
        {
            return Err(self.error("account", "AccountDisabledOrMismatch", "Authenticated account is disabled, lacks active boolean status or differs from domain account_id.", Some(&account_reply)));
        }
        if account["type"].as_str() != Some("aliyun") {
            return Err(self.error("account", "UnsupportedUnderlyingProvider", "Only the audited aliyun manager mapping supports preservation-safe single-record writes. Cloudflare/RRset/nested-manager and other unaudited mappings are refused.", Some(&account_reply)));
        }
        // Never copy config: the official API may return unmasked secrets.
        let account_proof = json!({"id": account_id, "type": "aliyun", "enabled": true});
        let zone_proof = json!({"id": id, "name": spec.domain.to_ascii_lowercase(), "account_id": account_id, "third_id": third_id, "enabled": raw.get("enabled"), "can_write": true});
        Ok((
            zone_proof,
            account_proof,
            account_reply.request_id.or(reply.request_id),
        ))
    }
    fn record(
        &self,
        spec: &Spec,
        raw: &Value,
        reply: Option<&HttpReply>,
        stage: &str,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error(stage, "MalformedRecord", "Record projection lacks documented native ID/name/type/value/TTL/line/status or contains invalid metadata; selection stopped.", reply)
        };
        let obj = raw.as_object().ok_or_else(bad)?;
        if obj.keys().any(|k| {
            !matches!(
                k.as_str(),
                "id" | "name"
                    | "type"
                    | "value"
                    | "line"
                    | "ttl"
                    | "mx"
                    | "weight"
                    | "status"
                    | "proxiable"
                    | "cloudflare"
                    | "remark"
                    | "updated_at"
            )
        }) {
            return Err(self.error(stage, "UnsupportedMetadata", "Unknown manager record metadata cannot be preserved through the audited write model.", reply));
        }
        if ["cloudflare", "proxiable"]
            .iter()
            .any(|k| raw.get(k).is_some_and(|v| !v.is_null()))
        {
            return Err(self.error(stage, "UnsupportedMetadata", "Aliyun records unexpectedly contain proxy/provider-specific projections; preservation cannot be verified.", reply));
        }
        let id = raw["id"].as_str().filter(|s| valid_id(s)).ok_or_else(bad)?;
        let name = raw["name"].as_str().ok_or_else(bad)?;
        let fqdn = record_fqdn(name, spec).ok_or_else(bad)?;
        let kind = raw["type"]
            .as_str()
            .filter(|s| {
                !s.is_empty()
                    && s.len() <= 32
                    && s.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            })
            .ok_or_else(bad)?;
        let value = raw["value"].as_str().ok_or_else(bad)?;
        let ttl = raw["ttl"]
            .as_u64()
            .filter(|n| (1..=2147483647).contains(n))
            .ok_or_else(bad)?;
        let line = raw["line"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(|c| c.is_control()))
            .ok_or_else(bad)?;
        let status = raw["status"].as_u64().filter(|n| *n <= 1).ok_or_else(bad)?;
        for key in ["mx", "weight"] {
            if raw
                .get(key)
                .is_some_and(|v| !v.is_null() && !v.as_u64().is_some_and(|n| n <= 65535))
            {
                return Err(bad());
            }
        }
        for key in ["remark", "updated_at"] {
            if raw.get(key).is_some_and(|v| !v.is_null() && !v.is_string()) {
                return Err(bad());
            }
        }
        Ok(Record {
            id: id.into(),
            name: fqdn,
            record_type: kind.into(),
            value: value.into(),
            ttl,
            line: line.into(),
            enabled: status == 1,
            extra: raw.clone(),
        })
    }
    fn conflicts(&self, spec: &Spec, records: &[Record]) -> Result<(), ProviderError> {
        let target = spec.fqdn().to_ascii_lowercase();
        let wildcard = target
            .split_once('.')
            .map(|(_, suffix)| format!("*.{suffix}"));
        for r in records {
            let host = r.name.to_ascii_lowercase();
            let ancestor = target == host || target.ends_with(&format!(".{host}"));
            if (r.record_type == "CNAME" && (ancestor || wildcard.as_deref() == Some(&host)))
                || (r.record_type == "DNAME" && ancestor)
            {
                return Err(self.error("selection", "CnameConflict", "Target or covering owner has CNAME/DNAME; no dry-run/noop/create/update is permitted.", None));
            }
            if r.record_type == "NS" && host != spec.domain.to_ascii_lowercase() && ancestor {
                return Err(self.error(
                    "selection",
                    "DelegatedNamespace",
                    "Target is at or below a delegated NS owner; parent-zone writes are refused.",
                    None,
                ));
            }
        }
        Ok(())
    }
    async fn snapshot(&self, spec: &Spec) -> Result<Snapshot, ProviderError> {
        let (zone, account, mut request_id) = self.zone(spec).await?;
        let id = zone["id"].as_str().expect("validated zone ID");
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        for page in 1..=102 {
            let reply = self
                .call(
                    "list",
                    Method::GET,
                    &format!("/domains/{id}/records?page={page}&pageSize=100"),
                    None,
                )
                .await?;
            request_id = reply.request_id.clone().or(request_id);
            let data = &reply.body["data"];
            let n = data["total"]
                .as_u64()
                .filter(|n| *n <= MAX_RECORDS as u64)
                .ok_or_else(|| {
                    self.error(
                        "list",
                        "InvalidCount",
                        "Record list lacks bounded numeric total.",
                        Some(&reply),
                    )
                })?;
            if total.is_some_and(|previous| previous != n) {
                return Err(self.error(
                    "list",
                    "UnstablePagination",
                    "Record total changed between pages; no partial list is used.",
                    Some(&reply),
                ));
            }
            total = Some(n);
            let rows = data["list"]
                .as_array()
                .filter(|v| v.len() <= 100)
                .ok_or_else(|| {
                    self.error(
                        "list",
                        "MalformedList",
                        "Expected official list array of at most 100 records.",
                        Some(&reply),
                    )
                })?;
            if rows.is_empty() {
                if records.len() as u64 != n {
                    return Err(self.error(
                        "list",
                        "IncompleteList",
                        "Empty page arrived before declared total; absence was not proved.",
                        Some(&reply),
                    ));
                }
                let (confirmed_zone, confirmed_account, confirmed_request_id) =
                    self.zone(spec).await?;
                if zone != confirmed_zone || account != confirmed_account {
                    return Err(self.error("list", "ConcurrentContextChange", "Manager domain ID/name/account/third_id or active account mapping changed during the complete record read; no snapshot was accepted.", None));
                }
                request_id = confirmed_request_id.or(request_id);
                self.conflicts(spec, &records).map_err(|mut error| {
                    error.request_id = request_id.clone();
                    error
                })?;
                return Ok(Snapshot {
                    zone,
                    account,
                    records,
                    request_id,
                });
            }
            if records.len() as u64 >= n {
                return Err(self.error(
                    "list",
                    "UnexpectedNextPage",
                    "Nonempty next page after total reached; complete-list proof failed.",
                    Some(&reply),
                ));
            }
            for row in rows {
                let record = self.record(spec, row, Some(&reply), "list")?;
                if !ids.insert(record.id.clone()) {
                    return Err(self.error(
                        "list",
                        "RepeatedRecordId",
                        "Repeated native record ID across pages; no first-record selection.",
                        Some(&reply),
                    ));
                }
                records.push(record);
            }
            if records.len() as u64 > n {
                return Err(self.error(
                    "list",
                    "InvalidCount",
                    "Returned more records than declared total.",
                    Some(&reply),
                ));
            }
        }
        Err(self.error(
            "list",
            "PaginationLimit",
            "Record pagination never proved a complete bounded list.",
            None,
        ))
    }
    fn select<'a>(
        &self,
        spec: &Spec,
        snapshot: &'a Snapshot,
    ) -> Result<Option<&'a Record>, ProviderError> {
        let target = spec.fqdn();
        let record = if let Some(id) = &spec.record_id {
            let record = snapshot
                .records
                .iter()
                .find(|r| &r.id == id)
                .ok_or_else(|| {
                    self.error(
                        "selection",
                        "RecordIdNotFound",
                        "Explicit ID missing; fallback and creation refused.",
                        None,
                    )
                })?;
            if !record.name.eq_ignore_ascii_case(&target) || record.record_type != spec.record_type
            {
                return Err(self.error(
                    "selection",
                    "RecordIdMismatch",
                    "Explicit ID has another owner/type; repurposing refused.",
                    None,
                ));
            }
            Some(record)
        } else {
            let matches: Vec<_> = snapshot
                .records
                .iter()
                .filter(|r| {
                    r.name.eq_ignore_ascii_case(&target)
                        && r.record_type == spec.record_type
                        && r.line == spec.record_line
                })
                .collect();
            if matches.len() > 1 {
                return Err(self.error(
                    "selection",
                    "AmbiguousRecords",
                    "Multiple matching records, including disabled records; specify record_id.",
                    None,
                ));
            }
            matches.first().copied()
        };
        self.validate_selection(spec, record)?;
        Ok(record)
    }
    async fn postwrite_snapshot(
        &self,
        spec: &Spec,
        write: &HttpReply,
    ) -> Result<Snapshot, ProviderError> {
        self.snapshot(spec).await.map_err(|mut error| {
            error.stage = "readback".into();
            error.code = "PostWriteReadbackFailed".into();
            error.message = self.api.safe(&format!("Write result is uncertain: full readback failed. No automatic write retry occurred. Detail: {}", error.message));
            error.hint = HINT.into();
            error.retryable = false;
            error.request_id = error.request_id.or_else(|| write.request_id.clone());
            error
        })
    }
    fn update_body(&self, spec: &Spec, record: &Record, ip: &str) -> Value {
        // Manager requires name/type/value; preserve raw native owner spelling.
        // Weight/remark/status are intentionally omitted: separate Aliyun
        // controls, not documented UpdateDomainRecord settings.
        json!({"name": record.extra["name"], "type": record.record_type, "value": ip, "line": record.line, "ttl": spec.ttl})
    }
    fn readback(
        &self,
        before: &Snapshot,
        after: &Snapshot,
        id: &str,
        spec: &Spec,
        ip: &str,
        create: bool,
    ) -> Result<(), ProviderError> {
        let fail = || {
            let mut error = self.error("readback", "WriteReadbackMismatch", "Write result is uncertain: exact native ID/owner/value/TTL/line, preserved controls or full sibling snapshot was not confirmed. No retry occurred.", None);
            error.request_id = after.request_id.clone();
            error
        };
        if before.zone != after.zone
            || before.account != after.account
            || after.records.len() != before.records.len() + usize::from(create)
        {
            return Err(fail());
        }
        let record = after.records.iter().find(|r| r.id == id).ok_or_else(fail)?;
        if !record.name.eq_ignore_ascii_case(&spec.fqdn())
            || record.record_type != spec.record_type
            || record.value.parse::<IpAddr>().ok() != ip.parse::<IpAddr>().ok()
            || record.ttl != spec.ttl
            || record.line != spec.record_line
            || !record.enabled
        {
            return Err(fail());
        }
        for old in &before.records {
            let next = after
                .records
                .iter()
                .find(|r| r.id == old.id)
                .ok_or_else(fail)?;
            if old.id == id && !create {
                let mut expected = old.extra.clone();
                expected["value"] = json!(ip);
                expected["ttl"] = json!(spec.ttl);
                // Timestamp is provider-owned and may change; all real controls
                // and legal optional metadata must remain identical.
                expected
                    .as_object_mut()
                    .expect("record object")
                    .remove("updated_at");
                let mut actual = next.extra.clone();
                actual
                    .as_object_mut()
                    .expect("record object")
                    .remove("updated_at");
                if actual != expected {
                    return Err(fail());
                }
            } else if next.extra != old.extra {
                return Err(fail());
            }
        }
        Ok(())
    }
}
impl Adapter for HipmDnsMgr {
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
            if record.line != spec.record_line {
                return Err(self.error(
                    "selection",
                    "RecordLineMismatch",
                    "Selected native line differs from configured line; line changes are refused.",
                    None,
                ));
            }
            if !record.enabled {
                return Err(self.error("selection", "RecordDisabled", "Selected record is disabled; it will not be updated or enabled, even in dry-run/noop.", None));
            }
            if !record
                .value
                .parse::<IpAddr>()
                .ok()
                .is_some_and(|ip| ip.is_ipv4() == (spec.record_type == "A"))
            {
                return Err(self.error("selection", "InvalidRecordValue", "Selected native A/AAAA value is not a literal IP of the correct family; inspect it before DDNS.", None));
            }
        }
        Ok(())
    }
    async fn list(&self, spec: &Spec) -> Result<List, ProviderError> {
        let snapshot = self.snapshot(spec).await?;
        self.select(spec, &snapshot).map_err(|mut error| {
            error.request_id = snapshot.request_id.clone();
            error
        })?;
        let proof = snapshot.proof();
        let records = snapshot
            .records
            .into_iter()
            .map(|mut record| {
                record.extra = json!({"raw": record.extra, "snapshot": proof});
                record
            })
            .collect();
        Ok(List {
            records,
            request_id: snapshot.request_id,
        })
    }
    async fn create(&self, spec: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.desired(spec, ip)?;
        if !spec.create_if_missing || spec.record_id.is_some() {
            return Err(self.error(
                "create",
                "CreationNotAllowed",
                "Creation requires explicit opt-in and no explicit record_id.",
                None,
            ));
        }
        let before = self.snapshot(spec).await?;
        if self.select(spec, &before)?.is_some() {
            return Err(self.error(
                "create",
                "RecordAppeared",
                "Fresh full read found an existing matching record; duplicate creation refused.",
                None,
            ));
        }
        let stable = self.snapshot(spec).await?;
        if before.proof() != stable.proof() {
            return Err(self.error(
                "create",
                "ConcurrentChange",
                "Full zone/account/record snapshot changed before creation; no write attempted.",
                None,
            ));
        }
        let body = json!({"name": spec.subdomain, "type": spec.record_type, "value": ip, "ttl": spec.ttl, "line": spec.record_line});
        let id = before.zone["id"].as_str().expect("zone ID");
        let reply = self
            .call(
                "create",
                Method::POST,
                &format!("/domains/{id}/records"),
                Some(&body),
            )
            .await?;
        let record_id = reply.body["data"]["id"].as_str().filter(|s| valid_id(s)).ok_or_else(|| self.error("create", "InvalidWriteAcknowledgement", "POST did not acknowledge documented data.id; write result uncertain, no retry.", Some(&reply)))?.to_owned();
        if before.records.iter().any(|r| r.id == record_id) {
            return Err(self.error(
                "create",
                "UnexpectedRecordId",
                "POST acknowledged an already existing native ID; inspect uncertain result.",
                Some(&reply),
            ));
        }
        let after = self.postwrite_snapshot(spec, &reply).await?;
        self.readback(&before, &after, &record_id, spec, &ip, true)?;
        Ok(Mutation {
            record_id,
            request_id: reply.request_id.or(after.request_id),
        })
    }
    async fn update(
        &self,
        spec: &Spec,
        record: &Record,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let ip = self.desired(spec, ip)?;
        self.validate_selection(spec, Some(record))?;
        let raw = &record.extra["raw"];
        let original = self.record(spec, raw, None, "update")?;
        if original.id != record.id
            || original.name != record.name
            || original.record_type != record.record_type
            || original.value != record.value
            || original.ttl != record.ttl
            || original.line != record.line
            || original.enabled != record.enabled
        {
            return Err(self.error(
                "update",
                "InvalidSnapshot",
                "Record does not match its original native read projection.",
                None,
            ));
        }
        let before = self.snapshot(spec).await?;
        if record.extra.get("snapshot") != Some(&before.proof()) {
            return Err(self.error(
                "update",
                "ConcurrentChange",
                "Full zone/account/record snapshot changed since selection; no write attempted.",
                None,
            ));
        }
        let fresh = self
            .select(spec, &before)?
            .filter(|r| r.id == record.id)
            .ok_or_else(|| {
                self.error(
                    "update",
                    "RecordChanged",
                    "Fresh safe selection differs from the original ID.",
                    None,
                )
            })?;
        let body = self.update_body(spec, fresh, &ip);
        let zone = before.zone["id"].as_str().expect("zone ID");
        let reply = self
            .call(
                "update",
                Method::PUT,
                &format!("/domains/{zone}/records/{}", record.id),
                Some(&body),
            )
            .await?;
        // Official PUT has no ID acknowledgement. Do not invent one or claim
        // success on code=0 alone: strict complete readback is required.
        if reply.body.get("data").is_some_and(|v| !v.is_null()) {
            return Err(self.error("update", "InvalidWriteAcknowledgement", "Unexpected PUT acknowledgement data; official update success is empty. Inspect uncertain write.", Some(&reply)));
        }
        let after = self.postwrite_snapshot(spec, &reply).await?;
        self.readback(&before, &after, &record.id, spec, &ip, false)?;
        Ok(Mutation {
            record_id: record.id.clone(),
            request_id: reply.request_id.or(after.request_id),
        })
    }
}
fn endpoint_env(name: &str) -> bool {
    (6..=64).contains(&name.len())
        && name.starts_with("HIPM_")
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}
pub(super) fn production_origin(value: &str) -> Option<String> {
    if value.len() > 2048
        || value.trim() != value
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/" | "/api" | "/api/")
    {
        return None;
    }
    // Explicit-empty userinfo and normalized dot segments also fail closed.
    let rest = value.split_once("://")?.1;
    let authority = rest.split('/').next()?;
    let raw_path = rest.find('/').map(|index| &rest[index..]).unwrap_or("");
    if !matches!(raw_path, "" | "/" | "/api" | "/api/")
        || authority.contains('@')
        || value.contains('\\')
        || value.contains("/../")
        || value.contains("/./")
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}
fn decimal_id(raw: &Value) -> Option<String> {
    let text = raw
        .as_str()
        .map(str::to_owned)
        .or_else(|| raw.as_u64().map(|n| n.to_string()))?;
    let number: u64 = text.parse().ok()?;
    (number > 0 && number <= i64::MAX as u64 && text == number.to_string()).then_some(text)
}
fn dns_name(name: &str, record: bool) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && (record && label == "*"
                    || label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || record && b == b'_'))
        })
}
fn record_fqdn(name: &str, spec: &Spec) -> Option<String> {
    if name == "@" {
        return Some(spec.domain.to_ascii_lowercase());
    }
    // The only audited mapping is Aliyun: its manager adapter exposes the
    // native RR, which is RELATIVE even when it happens to end in the zone's
    // text. Never infer an already-qualified owner from the spelling. Only @
    // is documented as apex; empty/trailing-dot RR values are not aliases.
    if !dns_name(name, true) {
        return None;
    }
    let fqdn = format!(
        "{}.{}",
        name.to_ascii_lowercase(),
        spec.domain.to_ascii_lowercase()
    );
    (fqdn.len() <= 253).then_some(fqdn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::common::reconcile;
    use axum::{
        Router,
        body::Bytes,
        extract::{OriginalUri, State},
        http::{HeaderMap, StatusCode},
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    const TOKEN: &str = "private/HiPM+token?&=%";
    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
        uri: String,
        body: Value,
        authorization: Option<String>,
    }
    struct Scenario {
        records: Vec<Value>,
        zone: Value,
        account: Value,
        seen: Vec<Seen>,
        list_reads: usize,
        change_at: Option<usize>,
        replies: BTreeMap<String, VecDeque<(u16, Value)>>,
        ignore_write: bool,
        change_sibling: bool,
        change_control: bool,
        ack: Option<Value>,
    }
    impl Scenario {
        fn new(records: Vec<Value>) -> Self {
            Self {
                records,
                zone: json!({"id":1,"name":"example.com","account_id":2,"third_id":"native-zone","enabled":1,"can_write":true,"record_count":1}),
                account: json!({"id":2,"type":"aliyun","enabled":true,"config":{"secretKey":"unmasked-native-secret"}}),
                seen: Vec::new(),
                list_reads: 0,
                change_at: None,
                replies: BTreeMap::new(),
                ignore_write: false,
                change_sibling: false,
                change_control: false,
                ack: None,
            }
        }
        fn respond(&mut self, uri: &str, status: u16, body: Value) {
            self.replies
                .entry(uri.into())
                .or_default()
                .push_back((status, body));
        }
        fn writes(&self) -> Vec<&Seen> {
            self.seen.iter().filter(|r| r.method != "GET").collect()
        }
    }
    struct Mock {
        state: Arc<Mutex<Scenario>>,
        task: tokio::task::JoinHandle<()>,
        adapter: HipmDnsMgr,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn mock(scenario: Scenario, discovery: bool) -> Mock {
        async fn serve(
            State(state): State<Arc<Mutex<Scenario>>>,
            method: Method,
            OriginalUri(uri): OriginalUri,
            headers: HeaderMap,
            bytes: Bytes,
        ) -> (StatusCode, axum::Json<Value>) {
            let mut state = state.lock().unwrap();
            let body = if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            };
            let uri_text = uri.to_string();
            state.seen.push(Seen {
                method: method.to_string(),
                uri: uri_text.clone(),
                body: body.clone(),
                authorization: headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
            });
            if let Some(queue) = state.replies.get_mut(&uri_text)
                && let Some((status, reply)) = queue.pop_front()
            {
                return (StatusCode::from_u16(status).unwrap(), axum::Json(reply));
            }
            let url = Url::parse(&format!("http://localhost{uri_text}")).unwrap();
            let page: usize = url
                .query_pairs()
                .find(|(key, _)| key == "page")
                .map(|(_, n)| n.parse().unwrap())
                .unwrap_or(1);
            let path = uri.path();
            let data = match (method.as_str(), path) {
                ("GET", "/api/domains") => {
                    if page == 1 {
                        json!([state.zone.clone()])
                    } else {
                        json!([])
                    }
                }
                ("GET", "/api/domains/1") => state.zone.clone(),
                ("GET", "/api/accounts/2") => state.account.clone(),
                ("GET", "/api/domains/1/records") => {
                    if page == 1 {
                        state.list_reads += 1;
                        if state.change_at == Some(state.list_reads) && !state.records.is_empty() {
                            state.records[0]["remark"] = json!("concurrent metadata change");
                        }
                    }
                    let start = (page - 1) * 100;
                    let rows: Vec<_> = state
                        .records
                        .iter()
                        .skip(start)
                        .take(100)
                        .cloned()
                        .collect();
                    json!({"total": state.records.len(), "list": rows})
                }
                ("POST", "/api/domains/1/records") => {
                    if !state.ignore_write {
                        let mut row = native(
                            "new-id",
                            body["name"].as_str().unwrap(),
                            body["type"].as_str().unwrap(),
                        );
                        row["value"] = body["value"].clone();
                        row["ttl"] = body["ttl"].clone();
                        row["line"] = body["line"].clone();
                        state.records.push(row);
                    }
                    state.ack.clone().unwrap_or_else(|| json!({"id":"new-id"}))
                }
                ("PUT", _) if path.starts_with("/api/domains/1/records/") => {
                    let id = path.rsplit('/').next().unwrap();
                    if !state.ignore_write {
                        let row = state.records.iter_mut().find(|r| r["id"] == id).unwrap();
                        row["value"] = body["value"].clone();
                        row["ttl"] = body["ttl"].clone();
                        row["line"] = body["line"].clone();
                        row["updated_at"] = json!("after-write");
                        if state.change_control {
                            state.records.iter_mut().find(|r| r["id"] == id).unwrap()["weight"] =
                                json!(0);
                        }
                        if state.change_sibling
                            && let Some(row) = state.records.iter_mut().find(|r| r["id"] != id)
                        {
                            row["remark"] = json!("lost sibling metadata");
                        }
                    }
                    state.ack.clone().unwrap_or(Value::Null)
                }
                _ => {
                    return (
                        StatusCode::NOT_FOUND,
                        axum::Json(json!({"code":404,"msg":"unknown mock route"})),
                    );
                }
            };
            (
                StatusCode::OK,
                axum::Json(json!({"code":0,"data":data,"msg":"success"})),
            )
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(scenario));
        let app = Router::new().fallback(serve).with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut options = BTreeMap::from([("endpoint_env".into(), "HIPM_TEST_ENDPOINT".into())]);
        if !discovery {
            options.insert("domain_id".into(), "1".into());
        }
        let adapter = HipmDnsMgr::new(client, TOKEN.into(), &options).with_mock_endpoint(endpoint);
        Mock {
            state,
            task,
            adapter,
        }
    }
    fn spec() -> Spec {
        Spec {
            domain: "example.com".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "default".into(),
            ttl: 600,
            record_id: None,
            create_if_missing: false,
            options: BTreeMap::new(),
        }
    }
    fn native(id: &str, name: &str, kind: &str) -> Value {
        json!({"id":id,"name":name,"type":kind,"value":if kind == "AAAA" { "2001:db8::1" } else { "192.0.2.1" },"line":"default","ttl":600,"mx":0,"weight":37,"status":1,"remark":"preserve notes","updated_at":"before-write","proxiable":null,"cloudflare":null})
    }
    async fn failure(mock: &Mock, spec: &Spec, code: &str) {
        for dry in [true, false] {
            let error = reconcile(&mock.adapter, spec, "192.0.2.1", dry)
                .await
                .unwrap_err();
            assert_eq!(error.code, code, "{error:?}");
            assert!(!error.retryable);
        }
        assert!(mock.state.lock().unwrap().writes().is_empty());
    }
    const PAGE1: &str = "/api/domains/1/records?page=1&pageSize=100";
    const PAGE2: &str = "/api/domains/1/records?page=2&pageSize=100";

    #[test]
    fn production_endpoint_and_env_policy() {
        for name in ["HIPM_API_ENDPOINT", "HIPM_A", "HIPM_1"] {
            assert!(endpoint_env(name));
        }
        for name in [
            "HIPM_",
            "DDNS_ENDPOINT",
            "PATH",
            "HIPM_lower",
            "HIPM_BAD-NAME",
            "HIPM_A\n",
        ] {
            assert!(!endpoint_env(name));
        }
        assert!(!endpoint_env(&format!("HIPM_{}", "A".repeat(60))));
        for origin in [
            "https://dns.example.com",
            "https://dns.example.com/api",
            "https://dns.example.com/api/",
            "https://localhost:3443/",
            "https://127.0.0.1:3443/api",
            "https://[::1]:3443",
        ] {
            assert!(production_origin(origin).is_some(), "{origin}");
        }
        for origin in [
            "http://localhost:3001",
            "https://user:secret@dns.example.com",
            "https://@dns.example.com",
            "https://dns.example.com/api?x=1",
            "https://dns.example.com/#fragment",
            "https://dns.example.com/private",
            "https://dns.example.com/../api",
            "https://dns.example.com/%2e%2e/api",
            "https://dns.example.com/%61pi",
            " https://dns.example.com",
            "https://dns.example.com\\api",
        ] {
            assert!(production_origin(origin).is_none(), "{origin}");
        }
    }
    #[tokio::test]
    async fn invalid_configuration_never_makes_requests() {
        let mock = mock(Scenario::new(vec![]), false).await;
        for option in ["endpoint", "base_url", "ttl_mode"] {
            let mut adapter = HipmDnsMgr::new(
                mock.adapter.api.client.clone(),
                TOKEN.into(),
                &BTreeMap::from([
                    ("endpoint_env".into(), "HIPM_TEST_ENDPOINT".into()),
                    (option.into(), "untrusted-web-url".into()),
                ]),
            );
            adapter.mock_endpoint = mock.adapter.mock_endpoint.clone();
            assert_eq!(
                adapter.list(&spec()).await.unwrap_err().code,
                "UnsupportedOptions"
            );
        }
        for name in ["PATH", "DDNS_ENDPOINT", "HIPM_"] {
            let adapter = HipmDnsMgr::new(
                mock.adapter.api.client.clone(),
                TOKEN.into(),
                &BTreeMap::from([("endpoint_env".into(), name.into())]),
            );
            assert!(adapter.endpoint.is_none());
            assert_eq!(
                adapter.list(&spec()).await.unwrap_err().code,
                "InvalidEndpointEnv"
            );
        }
        let adapter = HipmDnsMgr::new(
            mock.adapter.api.client.clone(),
            TOKEN.into(),
            &BTreeMap::from([(
                "endpoint_env".into(),
                "HIPM_TEST_MISSING_ENDPOINT_29381".into(),
            )]),
        );
        assert_eq!(
            adapter.list(&spec()).await.unwrap_err().code,
            "MissingEndpoint"
        );
        assert!(mock.state.lock().unwrap().seen.is_empty());
    }
    #[tokio::test]
    async fn no_op_dry_run_auth_and_unfiltered_next_page() {
        let mock = mock(Scenario::new(vec![native("native-id", "home", "A")]), false).await;
        assert_eq!(
            reconcile(&mock.adapter, &spec(), "192.0.2.1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert_eq!(
            reconcile(&mock.adapter, &spec(), "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_update"
        );
        let state = mock.state.lock().unwrap();
        assert!(state.writes().is_empty());
        assert!(
            state
                .seen
                .iter()
                .all(|r| r.authorization.as_deref() == Some(&format!("Bearer {TOKEN}")))
        );
        assert!(state.seen.iter().any(|r| r.uri == PAGE2));
        assert!(state.seen.iter().all(|r| !r.uri.contains(TOKEN)
            && !r.uri.contains("subdomain=")
            && !r.uri.contains("type=")
            && !r.uri.contains("status=")));
    }
    #[tokio::test]
    async fn strict_native_id_update_preserves_controls_and_siblings() {
        let mut txt = native("txt-id", "_legal", "TXT");
        txt["value"] = json!("arbitrary legal TXT metadata");
        let mock = mock(
            Scenario::new(vec![native("native-id", "home", "A"), txt.clone()]),
            false,
        )
        .await;
        let outcome = reconcile(&mock.adapter, &spec(), "192.0.2.2", false)
            .await
            .unwrap();
        assert_eq!(outcome.status, "updated");
        assert_eq!(outcome.record_id.as_deref(), Some("native-id"));
        let state = mock.state.lock().unwrap();
        let writes = state.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].method, "PUT");
        assert_eq!(writes[0].uri, "/api/domains/1/records/native-id");
        assert_eq!(
            writes[0].body,
            json!({"name":"home","type":"A","value":"192.0.2.2","line":"default","ttl":600})
        );
        for field in ["weight", "remark", "status", "mx", "cloudflare"] {
            assert!(writes[0].body.get(field).is_none());
        }
        assert_eq!(state.records[0]["weight"], 37);
        assert_eq!(state.records[0]["remark"], "preserve notes");
        assert_eq!(state.records[1], txt);
        assert_eq!(state.list_reads, 3);
    }
    #[tokio::test]
    async fn real_ttl_and_ipv6_are_written_and_read_back() {
        let mock = mock(Scenario::new(vec![native("v6-id", "home", "AAAA")]), false).await;
        let mut spec = spec();
        spec.record_type = "AAAA".into();
        spec.ttl = 300;
        assert!(mock.adapter.manages_ttl());
        assert_eq!(
            reconcile(&mock.adapter, &spec, "2001:0db8::1", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let state = mock.state.lock().unwrap();
        assert_eq!(state.writes()[0].body["ttl"], 300);
        assert_eq!(state.writes()[0].body["value"], "2001:db8::1");
    }
    #[tokio::test]
    async fn disabled_ambiguous_explicit_missing_and_line_are_refused() {
        let mut disabled = native("disabled-id", "home", "A");
        disabled["status"] = json!(0);
        let mock1 = mock(Scenario::new(vec![disabled.clone()]), false).await;
        failure(&mock1, &spec(), "RecordDisabled").await;
        let mock2 = mock(
            Scenario::new(vec![disabled, native("second-id", "home", "A")]),
            false,
        )
        .await;
        failure(&mock2, &spec(), "AmbiguousRecords").await;
        let mock3 = mock(Scenario::new(vec![native("native-id", "home", "A")]), false).await;
        let mut spec = spec();
        spec.record_id = Some("missing-id".into());
        spec.create_if_missing = true;
        failure(&mock3, &spec, "RecordIdNotFound").await;
        spec.record_id = Some("native-id".into());
        spec.record_line = "telecom".into();
        failure(&mock3, &spec, "RecordLineMismatch").await;
    }
    #[tokio::test]
    async fn explicit_native_id_cannot_repurpose_other_target() {
        let mock = mock(
            Scenario::new(vec![native("native-id", "other", "A")]),
            false,
        )
        .await;
        let mut spec = spec();
        spec.record_id = Some("native-id".into());
        failure(&mock, &spec, "RecordIdMismatch").await;
    }
    #[tokio::test]
    async fn cname_dname_and_delegated_ns_are_refused_before_noop() {
        for (name, kind, code) in [
            ("home", "CNAME", "CnameConflict"),
            ("*", "CNAME", "CnameConflict"),
            ("home", "DNAME", "CnameConflict"),
            ("home", "NS", "DelegatedNamespace"),
        ] {
            let mock = mock(
                Scenario::new(vec![
                    native("native-id", "home", "A"),
                    native("conflict-id", name, kind),
                ]),
                false,
            )
            .await;
            failure(&mock, &spec(), code).await;
        }
        let mock = mock(
            Scenario::new(vec![
                native("native-id", "home.branch", "A"),
                native("ns-id", "branch", "NS"),
            ]),
            false,
        )
        .await;
        let mut spec = spec();
        spec.subdomain = "home.branch".into();
        failure(&mock, &spec, "DelegatedNamespace").await;
    }
    #[tokio::test]
    async fn full_pagination_not_first_match_and_last_count_checked() {
        let mut records: Vec<_> = (0..101)
            .map(|n| native(&format!("id-{n}"), &format!("host{n}"), "A"))
            .collect();
        records[100]["name"] = json!("home");
        let mock = mock(Scenario::new(records), false).await;
        assert_eq!(
            reconcile(&mock.adapter, &spec(), "192.0.2.1", true)
                .await
                .unwrap()
                .record_id
                .as_deref(),
            Some("id-100")
        );
        let state = mock.state.lock().unwrap();
        assert!(state.seen.iter().any(|r| r.uri.contains("records?page=3")));
        assert!(state.writes().is_empty());
    }
    #[tokio::test]
    async fn pagination_count_repeated_id_and_next_page_fail_closed() {
        for (rows, total, next_rows, next_total, code) in [
            (
                vec![native("id", "home", "A")],
                2,
                vec![],
                2,
                "IncompleteList",
            ),
            (
                vec![native("id", "home", "A")],
                2,
                vec![native("id", "other", "A")],
                2,
                "RepeatedRecordId",
            ),
            (
                vec![native("id", "home", "A")],
                1,
                vec![native("other", "other", "A")],
                1,
                "UnexpectedNextPage",
            ),
            (
                vec![native("id", "home", "A")],
                2,
                vec![],
                3,
                "UnstablePagination",
            ),
        ] {
            let mut state = Scenario::new(vec![]);
            state.respond(
                PAGE1,
                200,
                json!({"code":0,"data":{"total":total,"list":rows}}),
            );
            state.respond(
                PAGE2,
                200,
                json!({"code":0,"data":{"total":next_total,"list":next_rows}}),
            );
            let mock = mock(state, false).await;
            assert_eq!(
                reconcile(&mock.adapter, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert!(mock.state.lock().unwrap().writes().is_empty());
        }
    }
    #[tokio::test]
    async fn malformed_records_metadata_and_counts_are_refused() {
        for (key, value, code) in [
            ("id", json!("../unsafe"), "MalformedRecord"),
            ("status", json!("1"), "MalformedRecord"),
            ("ttl", json!(0), "MalformedRecord"),
            ("weight", json!(-1), "MalformedRecord"),
            (
                "cloudflare",
                json!({"proxied":false}),
                "UnsupportedMetadata",
            ),
            ("settings", json!({"unknown":true}), "UnsupportedMetadata"),
        ] {
            let mut row = native("id", "home", "A");
            row[key] = value;
            let mock = mock(Scenario::new(vec![row]), false).await;
            failure(&mock, &spec(), code).await;
        }
        for total in [json!(10001), json!(-1), json!("1"), Value::Null] {
            let mut scenario = Scenario::new(vec![]);
            scenario.respond(
                PAGE1,
                200,
                json!({"code":0,"data":{"total":total,"list":[]}}),
            );
            let mock = mock(scenario, false).await;
            assert_eq!(
                mock.adapter.list(&spec()).await.unwrap_err().code,
                "InvalidCount"
            );
        }
    }
    #[tokio::test]
    async fn authenticated_zone_account_and_mapping_proof_required() {
        for (field, value, code) in [
            ("name", json!("other.com"), "ZoneMismatch"),
            ("id", json!(3), "ZoneMismatch"),
            ("enabled", json!(0), "ZoneDisabledOrReadOnly"),
            ("can_write", json!(false), "ZoneDisabledOrReadOnly"),
            ("account_id", json!("../../bad"), "MalformedZone"),
        ] {
            let mut scenario = Scenario::new(vec![]);
            scenario.zone[field] = value;
            let mock = mock(scenario, false).await;
            failure(&mock, &spec(), code).await;
        }
        for (field, value, code) in [
            ("id", json!(3), "AccountDisabledOrMismatch"),
            ("enabled", json!(false), "AccountDisabledOrMismatch"),
            ("enabled", json!(1), "AccountDisabledOrMismatch"),
            ("type", json!("cloudflare"), "UnsupportedUnderlyingProvider"),
            ("type", json!("powerdns"), "UnsupportedUnderlyingProvider"),
            ("type", json!("hidns"), "UnsupportedUnderlyingProvider"),
        ] {
            let mut scenario = Scenario::new(vec![]);
            scenario.account[field] = value;
            let mock = mock(scenario, false).await;
            failure(&mock, &spec(), code).await;
        }
    }
    #[tokio::test]
    async fn discovery_exact_name_full_array_and_repeated_whitelist_protection() {
        let mock1 = mock(Scenario::new(vec![native("id", "home", "A")]), true).await;
        assert_eq!(
            reconcile(&mock1.adapter, &spec(), "192.0.2.1", true)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        let mut scenario = Scenario::new(vec![]);
        let query = "/api/domains?page=2&pageSize=100&include_disabled=true&domain_status=all";
        scenario.respond(query, 200, json!({"code":0,"data":[scenario.zone.clone()]}));
        let mock2 = mock(scenario, true).await;
        assert_eq!(
            mock2.adapter.list(&spec()).await.unwrap_err().code,
            "RepeatedPage"
        );
        assert!(mock2.state.lock().unwrap().writes().is_empty());
    }
    #[tokio::test]
    async fn concurrent_metadata_change_stops_prewrite() {
        let mut scenario = Scenario::new(vec![native("id", "home", "A")]);
        scenario.change_at = Some(2);
        let mock = mock(scenario, false).await;
        assert_eq!(
            reconcile(&mock.adapter, &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "ConcurrentChange"
        );
        assert!(mock.state.lock().unwrap().writes().is_empty());
    }
    #[tokio::test]
    async fn creation_requires_optin_fresh_absence_and_full_readback() {
        let mock1 = mock(Scenario::new(vec![]), false).await;
        assert_eq!(
            reconcile(&mock1.adapter, &spec(), "192.0.2.2", true)
                .await
                .unwrap_err()
                .code,
            "RecordNotFound"
        );
        let mut spec = spec();
        spec.create_if_missing = true;
        assert_eq!(
            reconcile(&mock1.adapter, &spec, "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_create"
        );
        assert!(mock1.state.lock().unwrap().writes().is_empty());
        assert_eq!(
            reconcile(&mock1.adapter, &spec, "192.0.2.2", false)
                .await
                .unwrap()
                .status,
            "created"
        );
        assert_eq!(mock1.state.lock().unwrap().writes().len(), 1);
        let mock2 = mock(Scenario::new(vec![native("id", "home", "A")]), false).await;
        assert_eq!(
            mock2
                .adapter
                .create(&spec, "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "RecordAppeared"
        );
        assert!(mock2.state.lock().unwrap().writes().is_empty());
    }
    #[tokio::test]
    async fn create_snapshot_change_and_invalid_ack_never_retry() {
        let mut scenario = Scenario::new(vec![native("txt", "other", "TXT")]);
        scenario.change_at = Some(2);
        let mock1 = mock(scenario, false).await;
        let mut spec = spec();
        spec.create_if_missing = true;
        assert_eq!(
            mock1
                .adapter
                .create(&spec, "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "ConcurrentChange"
        );
        assert!(mock1.state.lock().unwrap().writes().is_empty());
        for ack in [json!({}), json!({"id":0}), json!({"id":"../unsafe"})] {
            let mut scenario = Scenario::new(vec![]);
            scenario.ack = Some(ack);
            let mock = mock(scenario, false).await;
            assert_eq!(
                mock.adapter
                    .create(&spec, "192.0.2.2")
                    .await
                    .unwrap_err()
                    .code,
                "InvalidWriteAcknowledgement"
            );
            assert_eq!(mock.state.lock().unwrap().writes().len(), 1);
        }
    }
    #[tokio::test]
    async fn ignored_write_changed_controls_or_sibling_are_uncertain_without_retry() {
        for mode in 0..3 {
            let mut scenario = Scenario::new(vec![
                native("id", "home", "A"),
                native("sibling", "other", "TXT"),
            ]);
            match mode {
                0 => scenario.ignore_write = true,
                1 => scenario.change_control = true,
                _ => scenario.change_sibling = true,
            }
            let mock = mock(scenario, false).await;
            let error = reconcile(&mock.adapter, &spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert_eq!(error.code, "WriteReadbackMismatch");
            assert!(!error.retryable);
            assert_eq!(mock.state.lock().unwrap().writes().len(), 1);
        }
    }
    #[tokio::test]
    async fn invalid_update_ack_and_sanitized_business_http_errors() {
        let mut scenario = Scenario::new(vec![native("id", "home", "A")]);
        scenario.ack = Some(json!({"id":"other"}));
        let mock1 = mock(scenario, false).await;
        assert_eq!(
            reconcile(&mock1.adapter, &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "InvalidWriteAcknowledgement"
        );
        assert_eq!(mock1.state.lock().unwrap().writes().len(), 1);
        for status in [200, 400, 401, 403, 429, 500] {
            let mut scenario = Scenario::new(vec![]);
            let encoded = utf8_percent_encode(TOKEN, NON_ALPHANUMERIC).to_string();
            scenario.respond("/api/domains/1", status, json!({"code":403,"msg":format!("Permission denied {TOKEN} encoded {encoded}\n {}", "bounded".repeat(600))}));
            let mock = mock(scenario, false).await;
            let error = mock.adapter.list(&spec()).await.unwrap_err();
            assert_eq!(error.code, "HiDNS403");
            assert_eq!(error.http_status, Some(status));
            assert!(!error.retryable);
            assert!(error.message.contains("Permission denied"));
            assert!(error.message.len() < 2100);
            assert!(!error.message.contains(TOKEN));
            assert!(!error.message.contains(&encoded));
            assert!(!error.message.contains('\n'));
            assert!(mock.state.lock().unwrap().writes().is_empty());
        }
    }
    #[tokio::test]
    async fn redirect_and_non_success_envelopes_are_not_followed() {
        for (status, body, code) in [
            (302, json!({"code":0,"data":{}}), "Http302"),
            (200, json!({"data":{}}), "InvalidEnvelope"),
            (201, json!({"code":0,"data":{}}), "InvalidEnvelope"),
        ] {
            let mut scenario = Scenario::new(vec![]);
            scenario.respond("/api/domains/1", status, body);
            let mock = mock(scenario, false).await;
            assert_eq!(mock.adapter.list(&spec()).await.unwrap_err().code, code);
            assert_eq!(mock.state.lock().unwrap().seen.len(), 1);
        }
    }
    #[tokio::test]
    async fn display_line_bad_credentials_and_native_values_are_local_refusals() {
        let mock1 = mock(Scenario::new(vec![native("id", "home", "A")]), false).await;
        let mut bad_spec = spec();
        bad_spec.record_line = "默认".into();
        assert_eq!(
            mock1.adapter.list(&bad_spec).await.unwrap_err().code,
            "InvalidRecordLine"
        );
        bad_spec.record_line = "default".into();
        bad_spec.ttl = 0;
        assert_eq!(
            mock1.adapter.list(&bad_spec).await.unwrap_err().code,
            "InvalidSettings"
        );
        assert!(mock1.state.lock().unwrap().seen.is_empty());
        let mut adapter = HipmDnsMgr::new(
            mock1.adapter.api.client.clone(),
            "bad token".into(),
            &mock1.adapter.options,
        );
        adapter.mock_endpoint = mock1.adapter.mock_endpoint.clone();
        assert_eq!(
            adapter.list(&spec()).await.unwrap_err().code,
            "InvalidCredentials"
        );
        assert!(mock1.state.lock().unwrap().seen.is_empty());
        for value in ["not-an-ip", "2001:db8::1"] {
            let mut row = native("id", "home", "A");
            row["value"] = json!(value);
            let mock = mock(Scenario::new(vec![row]), false).await;
            failure(&mock, &spec(), "InvalidRecordValue").await;
        }
    }
    #[tokio::test]
    async fn manager_context_cannot_change_during_snapshot() {
        for field in ["account_id", "third_id"] {
            let mut scenario = Scenario::new(vec![native("id", "home", "A")]);
            let initial = scenario.zone.clone();
            let mut changed = initial.clone();
            changed[field] = if field == "account_id" {
                json!(3)
            } else {
                json!("another-native-zone")
            };
            scenario.respond("/api/domains/1", 200, json!({"code":0,"data":initial}));
            scenario.respond("/api/domains/1", 200, json!({"code":0,"data":changed}));
            let mock = mock(scenario, false).await;
            let error = reconcile(&mock.adapter, &spec(), "192.0.2.2", false)
                .await
                .unwrap_err();
            assert!(matches!(
                error.code.as_str(),
                "ConcurrentContextChange" | "HiDNS404"
            ));
            assert!(mock.state.lock().unwrap().writes().is_empty());
        }
    }
    #[tokio::test]
    async fn postwrite_read_error_is_uncertain_nonretryable_and_single_write() {
        let mut scenario = Scenario::new(vec![native("id", "home", "A")]);
        let row = scenario.records[0].clone();
        for _ in 0..2 {
            scenario.respond(
                PAGE1,
                200,
                json!({"code":0,"data":{"total":1,"list":[row.clone()]}}),
            );
        }
        scenario.respond(
            PAGE1,
            500,
            json!({"code":500,"msg":"upstream read temporarily unavailable"}),
        );
        let mock = mock(scenario, false).await;
        let error = reconcile(&mock.adapter, &spec(), "192.0.2.2", false)
            .await
            .unwrap_err();
        assert_eq!(error.code, "PostWriteReadbackFailed");
        assert_eq!(error.stage, "readback");
        assert!(!error.retryable);
        assert_eq!(error.http_status, Some(500));
        assert!(error.message.contains("uncertain"));
        assert!(
            error
                .message
                .contains("upstream read temporarily unavailable")
        );
        assert_eq!(mock.state.lock().unwrap().writes().len(), 1);
    }
    #[tokio::test]
    async fn full_snapshot_digest_is_bounded_and_contains_no_account_secrets() {
        let records: Vec<_> = (0..250)
            .map(|n| native(&format!("id-{n}"), &format!("host{n}"), "TXT"))
            .collect();
        let mock = mock(Scenario::new(records), false).await;
        let list = mock.adapter.list(&spec()).await.unwrap();
        assert_eq!(list.records.len(), 250);
        for row in &list.records {
            assert_eq!(row.extra["snapshot"].as_str().unwrap().len(), 64);
            assert!(!row.extra.to_string().contains("unmasked-native-secret"));
            assert!(row.extra.to_string().len() < 1000);
        }
    }
    #[tokio::test]
    async fn underlying_credentials_echoed_in_business_errors_are_never_exposed() {
        for message in [
            "accessKeyId=unregistered-native-secret",
            "Provider failure accessKeySecret : unregistered-native-secret",
            "{\"SecretId\":\"unregistered-native-secret\"}",
            "signature = unregistered-native-secret",
            "config: {other: unregistered-native-secret}",
            "%22accessKeySecret%22%3A%22unregistered-native-secret%22",
        ] {
            let mut scenario = Scenario::new(vec![]);
            scenario.respond("/api/domains/1", 403, json!({"code":403,"msg":message,"data":{"config":{"secret":"raw-body-native-secret"}}}));
            let mock = mock(scenario, false).await;
            let error = mock.adapter.list(&spec()).await.unwrap_err();
            assert!(!format!("{error:?}").contains("unregistered-native-secret"));
            assert!(!format!("{error:?}").contains("raw-body-native-secret"));
            assert!(error.message.contains("diagnostic omitted"));
            assert!(mock.state.lock().unwrap().writes().is_empty());
        }
        let mock = mock(Scenario::new(vec![]), false).await;
        for benign in [
            "InvalidAccessKeyId.NotFound",
            "InvalidAccessKeyId: key is not valid",
            "AccessKeyId is not valid",
        ] {
            assert_eq!(mock.adapter.safe_business_detail(benign), benign);
        }
        let encoded = utf8_percent_encode(TOKEN, NON_ALPHANUMERIC).to_string();
        assert!(
            !mock
                .adapter
                .safe_business_detail(&format!("Permission denied {encoded}"))
                .contains(TOKEN)
        );
    }
    #[test]
    fn aliyun_wire_rr_is_always_relative_except_documented_apex() {
        assert_eq!(
            record_fqdn("home", &spec()).as_deref(),
            Some("home.example.com")
        );
        assert_eq!(
            record_fqdn("home.example.com", &spec()).as_deref(),
            Some("home.example.com.example.com")
        );
        assert_eq!(
            record_fqdn("example.com", &spec()).as_deref(),
            Some("example.com.example.com")
        );
        assert_eq!(record_fqdn("@", &spec()).as_deref(), Some("example.com"));
        for unsupported in ["", ".", "home.", "home.example.com."] {
            assert!(record_fqdn(unsupported, &spec()).is_none(), "{unsupported}");
        }
    }
    #[tokio::test]
    async fn zone_suffixed_relative_rr_cannot_select_shorter_target() {
        let mock = mock(
            Scenario::new(vec![native("double-owner", "home.example.com", "A")]),
            false,
        )
        .await;
        for dry_run in [true, false] {
            for ip in ["192.0.2.1", "192.0.2.2"] {
                let error = reconcile(&mock.adapter, &spec(), ip, dry_run)
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.code, "RecordNotFound",
                    "must not report unchanged/would_update/updated for the different owner"
                );
            }
        }
        let mut explicit = spec();
        explicit.record_id = Some("double-owner".into());
        for dry_run in [true, false] {
            assert_eq!(
                reconcile(&mock.adapter, &explicit, "192.0.2.2", dry_run)
                    .await
                    .unwrap_err()
                    .code,
                "RecordIdMismatch"
            );
        }
        let state = mock.state.lock().unwrap();
        assert!(state.writes().is_empty());
        assert_eq!(state.records[0]["name"], "home.example.com");
        assert_eq!(state.records[0]["value"], "192.0.2.1");
    }
    #[tokio::test]
    async fn legitimate_double_qualified_owner_keeps_wire_relative_rr_on_update() {
        let mock = mock(
            Scenario::new(vec![native("double-owner", "home.example.com", "A")]),
            false,
        )
        .await;
        let mut target = spec();
        target.subdomain = "home.example.com".into();
        let list = mock.adapter.list(&target).await.unwrap();
        assert_eq!(list.records[0].name, "home.example.com.example.com");
        assert_eq!(list.records[0].extra["raw"]["name"], "home.example.com");
        assert_eq!(
            reconcile(&mock.adapter, &target, "192.0.2.1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert_eq!(
            reconcile(&mock.adapter, &target, "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_update"
        );
        assert!(mock.state.lock().unwrap().writes().is_empty());
        let outcome = reconcile(&mock.adapter, &target, "192.0.2.2", false)
            .await
            .unwrap();
        assert_eq!(outcome.status, "updated");
        assert_eq!(outcome.record_id.as_deref(), Some("double-owner"));
        let state = mock.state.lock().unwrap();
        assert_eq!(state.writes().len(), 1);
        assert_eq!(state.writes()[0].body["name"], "home.example.com");
        assert_eq!(state.records[0]["name"], "home.example.com");
        assert_eq!(state.records[0]["value"], "192.0.2.2");
    }
    #[tokio::test]
    async fn relative_rr_equal_zone_name_is_not_apex() {
        let mock = mock(
            Scenario::new(vec![native("zone-spelled-owner", "example.com", "A")]),
            false,
        )
        .await;
        let mut apex = spec();
        apex.subdomain = "@".into();
        for dry_run in [true, false] {
            for ip in ["192.0.2.1", "192.0.2.2"] {
                assert_eq!(
                    reconcile(&mock.adapter, &apex, ip, dry_run)
                        .await
                        .unwrap_err()
                        .code,
                    "RecordNotFound"
                );
            }
        }
        assert!(mock.state.lock().unwrap().writes().is_empty());
        let mut relative = spec();
        relative.subdomain = "example.com".into();
        assert_eq!(
            reconcile(&mock.adapter, &relative, "192.0.2.2", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let state = mock.state.lock().unwrap();
        assert_eq!(state.writes().len(), 1);
        assert_eq!(state.writes()[0].body["name"], "example.com");
    }
    #[tokio::test]
    async fn forged_update_record_and_direct_invalid_inputs_do_not_write() {
        let mock = mock(Scenario::new(vec![native("id", "home", "A")]), false).await;
        let list = mock.adapter.list(&spec()).await.unwrap();
        let mut forged = list.records[0].clone();
        forged.value = "192.0.2.99".into();
        assert_eq!(
            mock.adapter
                .update(&spec(), &forged, "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "InvalidSnapshot"
        );
        assert_eq!(
            mock.adapter
                .update(&spec(), &list.records[0], "2001:db8::2")
                .await
                .unwrap_err()
                .code,
            "IpFamilyMismatch"
        );
        assert_eq!(
            mock.adapter
                .create(&spec(), "192.0.2.2")
                .await
                .unwrap_err()
                .code,
            "CreationNotAllowed"
        );
        assert!(mock.state.lock().unwrap().writes().is_empty());
        assert!(!format!("{:?}", list.records[0].extra).contains("unmasked-native-secret"));
    }
}
