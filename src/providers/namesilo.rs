//! NameSilo v1 JSON (upstream ddns-go uses XML, but JSON is documented).
//! Official contracts (the current site's API-reference client loads these):
//! https://www.namesilo.com/api-reference
//! https://www.namesilo.com/api-reference/pages?uid=domains/list-domains
//! https://www.namesilo.com/api-reference/pages?uid=domains/get-domain-info
//! https://www.namesilo.com/api-reference/pages?uid=dns/dns-list-records
//! https://www.namesilo.com/api-reference/pages?uid=dns/dns-add-record
//! https://www.namesilo.com/api-reference/pages?uid=dns/dns-update-record
//! https://www.namesilo.com/support/v2/articles/domain-manager/dns-troubleshooting
//! https://www.namesilo.com/support/v2/articles/domain-manager/dns-manager
//! ALL operations MUST use GET; key query authentication is unavoidable. Caller
//! MUST disable redirects. Never expose request URLs; redact raw/form/percent
//! encoded keys. GET mutations are explicitly marked writes, with no retries.
//! Updates rotate native IDs: acknowledgement + full readback prove the new ID,
//! old-ID disappearance and preservation of every unrelated record. Diagnostics
//! use a stable synthetic singleton host/type ID, NOT a fabricated native API ID.
//! Actual native IDs remain in record.extra and are used verbatim for requests.
//! No CAS is documented: fresh snapshots reduce races, but an exclusive writer
//! is required.
//! Basic DNS only: exact account zone, Active, default DNSOWL nameservers, no
//! forwarding, singleton A/AAAA, no unknown selected settings. Premium/custom NS
//! configurations fail closed. API readback is not proof of DNS propagation
//! (provider publishes changes every five minutes). TTL is read and written;
//! special automatically adjusted TTLs 3603/7207 are deliberately disallowed.
#![allow(clippy::result_large_err)]
use super::common::{self, Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
const ENDPOINT: &str = "https://www.namesilo.com/api";
const PAGE_SIZE: u64 = 100;
const HINT: &str = "Verify the exact NameSilo account domain, API key/IP allowlist and Active basic DNS using NS1/2/3.DNSOWL.COM (not forwarding/premium/custom DNS). Use one writer and a dedicated singleton A/AAAA. Updates rotate native API IDs; configured record_id uses the stable namesilo- logical singleton ID from diagnostics, never a native ID. API changes can take five minutes to publish. No CAS or automatic write retries: inspect uncertain writes before trying again. Authentication requires a GET query key; never enable URL/proxy logging.";
// Intentionally not Debug: the key and credential-bearing URLs are secrets.
pub struct Namesilo {
    api: Api,
    token: String,
    options: BTreeMap<String, String>,
    #[cfg(test)]
    endpoint: String,
}
impl Namesilo {
    pub fn new(client: reqwest::Client, token: String, options: &BTreeMap<String, String>) -> Self {
        let mut url = reqwest::Url::parse(ENDPOINT).expect("fixed URL");
        url.query_pairs_mut().append_pair("key", &token);
        let form = url
            .query()
            .unwrap_or("")
            .strip_prefix("key=")
            .unwrap_or("")
            .to_owned();
        let percent =
            percent_encoding::utf8_percent_encode(&token, percent_encoding::NON_ALPHANUMERIC)
                .to_string();
        let mut secrets = vec![token.clone(), form.clone(), percent.clone()];
        for value in [form, percent] {
            let bytes = value.as_bytes();
            let mut lower = String::new();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' && i + 2 < bytes.len() {
                    lower.push('%');
                    lower.push((bytes[i + 1] as char).to_ascii_lowercase());
                    lower.push((bytes[i + 2] as char).to_ascii_lowercase());
                    i += 3;
                } else {
                    lower.push(bytes[i] as char);
                    i += 1;
                }
            }
            secrets.push(lower);
        }
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        Self {
            api: Api::new(client, secrets),
            token,
            options: options.clone(),
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
    fn safe(&self, message: &str) -> String {
        let first = self.api.safe(message);
        let bytes = first.as_bytes();
        let mut normalized = String::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                normalized.push('%');
                normalized.push((bytes[i + 1] as char).to_ascii_uppercase());
                normalized.push((bytes[i + 2] as char).to_ascii_uppercase());
                i += 3;
            } else {
                let ch = first[i..].chars().next().expect("valid character boundary");
                normalized.push(ch);
                i += ch.len_utf8();
            }
        }
        let safe = self.api.safe(&normalized);
        let lower = safe.to_ascii_lowercase();
        if lower.contains("://")
            || lower.contains("%3a%2f%2f")
            || lower.contains("key=")
            || lower.contains("key%3d")
        {
            "Credential-bearing URL diagnostic omitted.".into()
        } else {
            safe
        }
    }
    fn error(
        &self,
        stage: &str,
        code: &str,
        message: &str,
        reply: Option<&HttpReply>,
    ) -> ProviderError {
        let mut e = self
            .api
            .error(stage, code, &self.safe(message), HINT, reply);
        if e.request_id.as_ref().is_some_and(|id| self.safe(id) != *id) {
            e.request_id = None;
        }
        e
    }
    fn validate(&self, s: &Spec) -> Result<(), ProviderError> {
        if self.token.trim().is_empty()
            || self.token.len() > 1024
            || self.token.chars().any(char::is_control)
        {
            return Err(self.error(
                "validation",
                "InvalidCredentials",
                "A nonempty API key without control characters is required.",
                None,
            ));
        }
        if !hostname(&s.domain, false)
            || !s.domain.contains('.')
            || (s.subdomain != "@" && !hostname(&s.subdomain, false))
            || s.fqdn().len() > 253
        {
            return Err(self.error("validation","InvalidDnsName","Use an exact ASCII/punycode domain and relative host or @; no URLs or wildcard targets.",None));
        }
        if !matches!(s.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Only A/AAAA DDNS is supported.",
                None,
            ));
        }
        if !matches!(s.record_line.as_str(), "默认" | "default")
            || !s.options.is_empty()
            || !self.options.is_empty()
        {
            return Err(self.error(
                "validation",
                "UnsupportedOptions",
                "No provider or record options, routing lines or endpoint overrides are supported.",
                None,
            ));
        }
        if !(300..=604800).contains(&s.ttl) || matches!(s.ttl, 3603 | 7207) {
            return Err(self.error("validation","UnsupportedTTL","Application TTL safety range is 300..604800, excluding automatically adjusted NameSilo TTLs 3603/7207; provider may impose additional limits.",None));
        }
        if s.record_id
            .as_ref()
            .is_some_and(|id| !common::valid_id(id) || !id.starts_with("namesilo-"))
        {
            return Err(self.error("validation","InvalidRecordId","record_id must be the namesilo- logical singleton identity from diagnostics, not the rotating native API ID.",None));
        }
        Ok(())
    }
    fn ip(&self, s: &Spec, ip: &str) -> Result<String, ProviderError> {
        self.validate(s)?;
        let p = ip.parse::<IpAddr>().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be a plain IP address.",
                None,
            )
        })?;
        if p.is_ipv4() != (s.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "Desired address family differs from the configured record type.",
                None,
            ));
        }
        Ok(p.to_string())
    }
    async fn send(
        &self,
        stage: &str,
        request: reqwest::RequestBuilder,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        // Unlike generic adapters, query-authenticated transport cannot allow
        // arbitrary provider trace IDs or reqwest source URLs into tracing.
        let started = std::time::Instant::now();
        tracing::debug!(action = stage, write, "NameSilo API action started");
        let result=tokio::time::timeout(std::time::Duration::from_secs(30),async {
            let mut response=request.send().await.map_err(|e|self.transport(stage,e,write,None))?;
            let status=response.status().as_u16();
            let headers=response.headers().clone();
            let request_id=headers.get("x-request-id").and_then(|v|v.to_str().ok()).map(|s|self.safe(s)).filter(|s|common::valid_trace_id(s)&&!s.contains("omitted")&&!s.contains("[REDACTED]"));
            let context=HttpReply{headers:headers.clone(),body:Value::Null,status,request_id:request_id.clone()};
            let mut bytes=Vec::new();
            while let Some(chunk)=response.chunk().await.map_err(|e|self.transport(stage,e,write,Some(status)))? {
                if bytes.len()+chunk.len()>1024*1024 {return Err(self.error(stage,"ResponseTooLarge","NameSilo JSON response exceeded 1 MiB; raw response omitted. Inspect any uncertain write.",Some(&context)));}
                bytes.extend_from_slice(&chunk);
            }
            let body=serde_json::from_slice(&bytes).map_err(|_|self.error(stage,"MalformedResponse","NameSilo returned non-JSON or malformed JSON; raw response omitted. Inspect any uncertain write.",Some(&context)))?;
            Ok(HttpReply{headers,body,status,request_id})
        }).await.unwrap_or_else(|_|Err(self.error(stage,"Timeout",if write {"NameSilo write exceeded the 30-second safety deadline; result uncertain and not retried."} else {"NameSilo read exceeded the 30-second safety deadline."},None)));
        match &result {
            Ok(reply) => {
                tracing::debug!(action=stage,http_status=reply.status,request_id=?reply.request_id,elapsed_ms=started.elapsed().as_millis() as u64,"NameSilo API action completed")
            }
            Err(error) => {
                tracing::debug!(action=stage,code=%error.code,http_status=?error.http_status,elapsed_ms=started.elapsed().as_millis() as u64,"NameSilo API action failed")
            }
        }
        result
    }
    fn transport(
        &self,
        stage: &str,
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
        let mut detail = error.to_string();
        let mut source = std::error::Error::source(&error);
        for _ in 0..8 {
            let Some(cause) = source else {
                break;
            };
            detail.push_str(" -> ");
            detail.push_str(&cause.to_string());
            source = cause.source();
        }
        let mut e = self.error(
            stage,
            code,
            &format!(
                "NameSilo transport failed; {} Detail: {}",
                if write {
                    "write result is uncertain; no automatic retry occurred."
                } else {
                    "no mutation was attempted."
                },
                self.safe(&detail)
            ),
            None,
        );
        e.http_status = status;
        e.retryable = !write;
        e
    }
    async fn call(
        &self,
        stage: &str,
        operation: &str,
        params: Vec<(&str, String)>,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let mut query = vec![
            ("version", "1".to_owned()),
            ("type", "json".to_owned()),
            ("key", self.token.clone()),
        ];
        query.extend(params);
        let reply = self
            .send(
                stage,
                self.api
                    .client
                    .get(format!("{}/{operation}", self.endpoint()))
                    .query(&query)
                    .header(reqwest::header::ACCEPT, "application/json"),
                write,
            )
            .await?;
        let code = number(&reply.body["reply"]["code"]);
        if reply.status != 200 || code.is_some_and(|c| c != 300) {
            let business = code
                .map(|c| format!("NameSilo{c}"))
                .unwrap_or_else(|| format!("Http{}", reply.status));
            let detail = reply.body["reply"]["detail"]
                .as_str()
                .unwrap_or("No recognized business error detail; raw response omitted.");
            let mut e = self.error(
                stage,
                &business,
                &format!("NameSilo rejected the request: {detail}"),
                Some(&reply),
            );
            e.retryable = !write && (reply.status == 429 || reply.status >= 500);
            return Err(e);
        }
        if code != Some(300)
            || unexpected_pagination(&reply.body, &[])
            || !reply.body["reply"].is_object()
            || reply.body["request"]["operation"].as_str() != Some(operation)
            || !reply.body["reply"]["detail"].is_string()
        {
            return Err(self.error(stage,"InvalidEnvelope","Expected operation-matching NameSilo JSON request/reply with explicit code 300 and detail; raw response omitted.",Some(&reply)));
        }
        Ok(reply)
    }
    async fn zone(&self, s: &Spec) -> Result<(), ProviderError> {
        self.validate(s)?;
        let mut total = None;
        let mut seen = HashSet::new();
        let mut matched = false;
        for page in 1..=100 {
            let reply = self
                .call(
                    "ownership",
                    "listDomains",
                    vec![
                        ("pageSize", PAGE_SIZE.to_string()),
                        ("page", page.to_string()),
                    ],
                    false,
                )
                .await?;
            let body = &reply.body["reply"];
            let bad = || {
                self.error("ownership","IncompleteDomainList","Account pagination is missing, repeated, inconsistent or beyond the 10,000-domain limit; no partial ownership proof.",Some(&reply))
            };
            if unexpected_pagination(body, &["pager"])
                || reply.headers.contains_key(reqwest::header::LINK)
            {
                return Err(bad());
            }
            let domains = body["domains"].as_array().ok_or_else(bad)?;
            let count = number(&body["pager"]["total"])
                .filter(|v| *v <= 10000)
                .ok_or_else(bad)?;
            if number(&body["pager"]["page"]) != Some(page)
                || number(&body["pager"]["pageSize"]) != Some(PAGE_SIZE)
                || total.is_some_and(|t| t != count)
            {
                return Err(bad());
            }
            total = Some(count);
            let remaining = count.saturating_sub((page - 1) * PAGE_SIZE);
            if domains.len() as u64 != remaining.min(PAGE_SIZE) {
                return Err(bad());
            }
            for d in domains {
                let name = d["domain"]
                    .as_str()
                    .filter(|n| hostname(n, false))
                    .ok_or_else(bad)?;
                if !seen.insert(name.to_ascii_lowercase()) {
                    return Err(bad());
                }
                matched |= name.eq_ignore_ascii_case(&s.domain);
            }
            if seen.len() as u64 == count {
                break;
            }
            if page == 100 {
                return Err(bad());
            }
        }
        if !matched {
            return Err(self.error("ownership","DomainNotFound","The exact domain was not present in the complete authenticated account domain list; no suffix fallback.",None));
        }
        let reply = self
            .call(
                "zone",
                "getDomainInfo",
                vec![("domain", s.domain.to_ascii_lowercase())],
                false,
            )
            .await?;
        let b = &reply.body["reply"];
        if b["status"].as_str() != Some("Active")
            || b["email_verification_required"].as_str() != Some("No")
        {
            return Err(self.error(
                "zone",
                "ZoneInactive",
                "Domain is not explicitly Active with no outstanding email verification.",
                Some(&reply),
            ));
        }
        if b["traffic_type"].as_str() != Some("Custom DNS")
            || b["forward_url"].as_str() != Some("N/A")
            || b["forward_type"].as_str() != Some("N/A")
        {
            return Err(self.error("zone","UnsafeZoneSettings","Parked/forwarded or unrecognized DNS settings are refused; use dedicated custom records on basic NameSilo DNS.",Some(&reply)));
        }
        let ns = b["nameservers"].as_array().ok_or_else(|| {
            self.error(
                "zone",
                "MalformedNameservers",
                "Domain nameservers are missing or malformed.",
                Some(&reply),
            )
        })?;
        let mut names = HashSet::new();
        let mut positions = HashSet::new();
        for raw in ns {
            let name = raw["nameserver"]
                .as_str()
                .unwrap_or("")
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !matches!(
                name.as_str(),
                "ns1.dnsowl.com" | "ns2.dnsowl.com" | "ns3.dnsowl.com"
            ) || !names.insert(name)
                || !number(&raw["position"])
                    .is_some_and(|p| (1..=3).contains(&p) && positions.insert(p))
            {
                return Err(self.error("zone","ExternalNameservers","Domain does not use the complete documented default NameSilo DNSOWL nameserver set; custom/premium/externally delegated DNS is refused.",Some(&reply)));
            }
        }
        if names.len() != 3 {
            return Err(self.error(
                "zone",
                "ExternalNameservers",
                "All three documented default DNSOWL nameservers must be present.",
                Some(&reply),
            ));
        }
        Ok(())
    }
    fn record(
        &self,
        s: &Spec,
        raw: &Value,
        reply: Option<&HttpReply>,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error("list","MalformedRecord","Record lacks documented native ID, in-zone FQDN, type, scalar value, positive TTL or distance.",reply)
        };
        let id = raw["record_id"]
            .as_str()
            .filter(|id| native_id(id))
            .ok_or_else(bad)?;
        let name = raw["host"]
            .as_str()
            .map(|n| n.trim_end_matches('.'))
            .filter(|n| hostname(n, true))
            .ok_or_else(bad)?;
        if !dns_equal(name, &s.domain)
            && !name
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", s.domain.to_ascii_lowercase()))
        {
            return Err(self.error(
                "list",
                "RecordZoneMismatch",
                "A returned DNS record lies outside the exact account zone.",
                reply,
            ));
        }
        let kind = raw["type"]
            .as_str()
            .filter(|k| {
                matches!(
                    *k,
                    "A" | "AAAA"
                        | "CNAME"
                        | "MX"
                        | "TXT"
                        | "SRV"
                        | "CAA"
                        | "NS"
                        | "SOA"
                        | "ANAME"
                        | "ALIAS"
                        | "HTTPS"
                        | "SVCB"
                )
            })
            .ok_or_else(bad)?;
        let value = raw["value"].as_str().ok_or_else(bad)?;
        let ttl = number(&raw["ttl"]).filter(|t| *t > 0).ok_or_else(bad)?;
        number(&raw["distance"]).ok_or_else(bad)?;
        let enabled = match raw.get("enabled") {
            None => true,
            Some(Value::Bool(v)) => *v,
            _ => return Err(bad()),
        };
        let id = if dns_equal(name, &s.fqdn()) && kind == s.record_type {
            logical_id(s)
        } else {
            format!("native-{id}")
        };
        Ok(Record {
            id,
            name: name.into(),
            record_type: kind.into(),
            value: value.into(),
            ttl,
            line: String::new(),
            enabled,
            extra: raw.clone(),
        })
    }
    fn checks(&self, s: &Spec, records: &[Record]) -> Result<(), ProviderError> {
        let target = s.fqdn();
        for r in records {
            if dns_equal(&r.name, &target)
                && matches!(
                    r.record_type.as_str(),
                    "CNAME" | "ANAME" | "ALIAS" | "HTTPS" | "SVCB"
                )
            {
                return Err(self.error(
                    "selection",
                    "AliasConflict",
                    "Target contains an alias/service binding; neither no-op nor creation is safe.",
                    None,
                ));
            }
            if r.record_type == "NS"
                && !dns_equal(&r.name, &s.domain)
                && (dns_equal(&r.name, &target)
                    || target
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{}", r.name.to_ascii_lowercase())))
            {
                return Err(self.error(
                    "selection",
                    "DelegatedHost",
                    "Target is at or below a child-zone NS delegation.",
                    None,
                ));
            }
        }
        let targets: Vec<_> = records
            .iter()
            .filter(|r| dns_equal(&r.name, &target) && r.record_type == s.record_type)
            .collect();
        if targets.len() > 1 {
            return Err(self.error("selection","UnsafeMultivalue","Only singleton A/AAAA targets are supported, even with an explicit ID; no member or RRset-wide ambiguity.",None));
        }
        let mut unpinned = s.clone();
        unpinned.record_id = None;
        for r in targets {
            self.selection(&unpinned, r)?;
        }
        Ok(())
    }
    fn selection(&self, s: &Spec, r: &Record) -> Result<(), ProviderError> {
        let raw = r.extra.get("record").unwrap_or(&r.extra);
        let verified = self.record(s, raw, None)?;
        if r.id != verified.id
            || !dns_equal(&r.name, &verified.name)
            || !dns_equal(&r.name, &s.fqdn())
            || r.record_type != s.record_type
            || r.record_type != verified.record_type
            || r.value != verified.value
            || r.ttl != verified.ttl
            || r.enabled != verified.enabled
            || !r.line.is_empty()
            || s.record_id.as_ref().is_some_and(|id| *id != r.id)
        {
            return Err(self.error(
                "selection",
                "RecordTargetMismatch",
                "Selected identity/metadata contradicts the immutable configured target.",
                None,
            ));
        }
        if !r.enabled {
            return Err(self.error(
                "selection",
                "RecordDisabled",
                "Disabled records are never enabled or updated.",
                None,
            ));
        }
        if raw.as_object().is_none_or(|o| {
            o.keys().any(|k| {
                !matches!(
                    k.as_str(),
                    "record_id" | "type" | "host" | "value" | "ttl" | "distance"
                )
            })
        }) || number(&raw["distance"]) != Some(0)
        {
            return Err(self.error("selection","UnsafeRecordSettings","Selected A/AAAA contains unknown settings or nonzero distance; refuse a lossy update.",None));
        }
        if !r
            .value
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|ip| ip.is_ipv4() == (s.record_type == "A"))
        {
            return Err(self.error(
                "selection",
                "InvalidRecordValue",
                "Existing A/AAAA value is not a plain address of the correct family.",
                None,
            ));
        }
        Ok(())
    }
    async fn read_records(&self, s: &Spec) -> Result<List, ProviderError> {
        let reply = self
            .call(
                "list",
                "dnsListRecords",
                vec![("domain", s.domain.to_ascii_lowercase())],
                false,
            )
            .await?;
        let b = &reply.body["reply"];
        // Complete/unpaginated contract; an omitted field/object is not absence.
        if unexpected_pagination(b, &[])
            || reply.headers.contains_key(reqwest::header::LINK)
            || b.as_object().is_none_or(|o| {
                o.keys()
                    .any(|k| !matches!(k.as_str(), "code" | "detail" | "resource_record"))
            })
        {
            return Err(self.error("list","IncompleteRecordList","Undocumented pagination/truncation or list settings were returned; no partial selection.",Some(&reply)));
        }
        let raw=b["resource_record"].as_array().ok_or_else(||self.error("list","MalformedRecordList","Complete list must contain the documented resource_record array; an omitted field is not proven absence.",Some(&reply)))?;
        if raw.len() > 100 {
            return Err(self.error("list","RecordLimit","Basic NameSilo DNS documents a 100-record zone limit; no partial or premium-zone selection.",Some(&reply)));
        }
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        for raw in raw {
            let r = self.record(s, raw, Some(&reply))?;
            if !ids.insert(raw["record_id"].as_str().unwrap_or("").to_owned()) {
                return Err(self.error(
                    "list",
                    "UnstableRecordList",
                    "Repeated native record IDs were returned.",
                    Some(&reply),
                ));
            }
            records.push(r);
        }
        self.checks(s, &records)?;
        let snapshot = snapshot(&records);
        for r in &mut records {
            r.extra = json!({"record":r.extra,"snapshot":snapshot});
        }
        Ok(List {
            records,
            request_id: reply.request_id,
        })
    }
    async fn write(
        &self,
        s: &Spec,
        ip: &str,
        old: Option<&Record>,
        before: &List,
    ) -> Result<Mutation, ProviderError> {
        let mut params = vec![
            ("domain", s.domain.to_ascii_lowercase()),
            (
                "rrhost",
                if s.subdomain == "@" {
                    String::new()
                } else {
                    s.subdomain.clone()
                },
            ),
            ("rrvalue", ip.into()),
            ("rrttl", s.ttl.to_string()),
        ];
        let (stage, op) = if let Some(old) = old {
            params.push((
                "rrid",
                old.extra["record"]["record_id"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned(),
            ));
            ("update", "dnsUpdateRecord")
        } else {
            params.push(("rrtype", s.record_type.clone()));
            ("create", "dnsAddRecord")
        };
        let reply = self.call(stage, op, params, true).await?;
        if reply.body["reply"]["detail"].as_str() != Some("success")
            || reply.body["reply"].as_object().is_none_or(|o| {
                o.keys()
                    .any(|k| !matches!(k.as_str(), "code" | "detail" | "record_id"))
            })
        {
            return Err(self.error(stage,"InvalidWriteAcknowledgement","Write returned a warning or undocumented acknowledgement settings; result is uncertain.",Some(&reply)));
        }
        let id=reply.body["reply"]["record_id"].as_str().filter(|id|native_id(id)).ok_or_else(||self.error(stage,"InvalidWriteAcknowledgement","Write returned no valid native string record_id; inspect the uncertain result.",Some(&reply)))?;
        if before
            .records
            .iter()
            .any(|r| r.extra["record"]["record_id"].as_str() == Some(id))
        {
            return Err(self.error(stage,"InvalidWriteAcknowledgement","Create/update must acknowledge a fresh native ID (NameSilo updates rotate IDs); returned ID already existed.",Some(&reply)));
        }
        let mut read_spec = s.clone();
        read_spec.record_id = None;
        let after = self.read_records(&read_spec).await.map_err(|mut e| {
            e.stage = stage.into();
            e.hint = format!("Write accepted but verification failed. {HINT}");
            e.retryable = false;
            e
        })?;
        let found=after.records.iter().find(|r|r.extra["record"]["record_id"].as_str()==Some(id)).ok_or_else(||self.error(stage,"WriteReadbackMismatch","Acknowledged new native ID is missing from complete readback; inspect before retrying.",Some(&reply)))?;
        if !dns_equal(&found.name, &s.fqdn())
            || found.record_type != s.record_type
            || found.value.parse::<IpAddr>().ok() != ip.parse::<IpAddr>().ok()
            || found.ttl != s.ttl
            || !found.enabled
            || number(&found.extra["record"]["distance"]) != Some(0)
        {
            return Err(self.error(stage,"WriteReadbackMismatch","Readback of acknowledged ID differs in target, type, value, TTL or legal metadata.",Some(&reply)));
        }
        let old_id = old.and_then(|r| r.extra["record"]["record_id"].as_str());
        let before_other: Vec<_> = before
            .records
            .iter()
            .filter(|r| r.extra["record"]["record_id"].as_str() != old_id)
            .cloned()
            .collect();
        let after_other: Vec<_> = after
            .records
            .iter()
            .filter(|r| r.extra["record"]["record_id"].as_str() != Some(id))
            .cloned()
            .collect();
        if snapshot(&before_other) != snapshot(&after_other)
            || after.records.len() != before.records.len() + usize::from(old.is_none())
        {
            return Err(self.error(stage,"WriteReadbackMismatch","Old ID did not disappear exactly once, or unrelated records/metadata changed; write result is uncertain.",Some(&reply)));
        }
        Ok(Mutation {
            record_id: logical_id(s),
            request_id: reply.request_id.or(after.request_id),
        })
    }
}
impl Adapter for Namesilo {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Fqdn
    }
    fn validate_selection(&self, s: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.validate(s)?;
        if let Some(r) = r {
            self.selection(s, r)?;
        }
        Ok(())
    }
    async fn list(&self, s: &Spec) -> Result<List, ProviderError> {
        self.zone(s).await?;
        self.read_records(s).await
    }
    async fn create(&self, s: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.ip(s, ip)?;
        if !s.create_if_missing || s.record_id.is_some() {
            return Err(self.error(
                "create",
                "CreationNotAllowed",
                "Creation requires explicit opt-in and no record_id.",
                None,
            ));
        }
        self.zone(s).await?;
        let before = self.read_records(s).await?;
        if before
            .records
            .iter()
            .any(|r| dns_equal(&r.name, &s.fqdn()) && r.record_type == s.record_type)
        {
            return Err(self.error(
                "create",
                "RecordAppeared",
                "Target appeared on the final complete read; creation stopped.",
                None,
            ));
        }
        if before.records.len() >= 100 {
            return Err(self.error(
                "create",
                "RecordLimit",
                "Zone already contains the documented 100-record maximum.",
                None,
            ));
        }
        self.write(s, &ip, None, &before).await
    }
    async fn update(&self, s: &Spec, r: &Record, ip: &str) -> Result<Mutation, ProviderError> {
        let ip = self.ip(s, ip)?;
        self.selection(s, r)?;
        self.zone(s).await?;
        let before = self.read_records(s).await?;
        if r.extra.get("snapshot") != Some(&snapshot(&before.records))
            || !before
                .records
                .iter()
                .any(|fresh| fresh.id == r.id && fresh.extra["record"] == r.extra["record"])
        {
            return Err(self.error(
                "update",
                "StaleRecord",
                "Full zone snapshot changed since selection; no write occurred.",
                None,
            ));
        }
        self.write(s, &ip, Some(r), &before).await
    }
}
fn logical_id(s: &Spec) -> String {
    format!(
        "namesilo-{}",
        hex::encode(Sha256::digest(
            format!("{}\n{}", s.fqdn().to_ascii_lowercase(), s.record_type).as_bytes()
        ))
    )
}
fn native_id(s: &str) -> bool {
    common::valid_id(s)
}
fn number(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| {
        v.as_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
    })
}
fn dns_equal(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}
fn hostname(s: &str, records: bool) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.is_ascii()
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && (records && l == "*"
                    || !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || b == b'-' || records && b == b'_'
                        }))
        })
}
fn unexpected_pagination(b: &Value, allowed: &[&str]) -> bool {
    [
        "pager",
        "pagination",
        "next",
        "nextPage",
        "next_page",
        "cursor",
        "hasMore",
        "has_more",
        "truncated",
        "total",
        "totalCount",
        "total_count",
        "page",
        "pages",
        "count",
        "offset",
        "limit",
    ]
    .iter()
    .any(|k| !allowed.contains(k) && b.get(*k).is_some())
}
fn snapshot(records: &[Record]) -> Value {
    let mut values: Vec<_> = records
        .iter()
        .map(|r| r.extra.get("record").unwrap_or(&r.extra).clone())
        .collect();
    values.sort_by(|a, b| a["record_id"].as_str().cmp(&b["record_id"].as_str()));
    Value::Array(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        extract::{Path, Query, State},
        http::StatusCode,
        response::IntoResponse,
        routing::get,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    #[derive(Clone)]
    struct Step {
        op: &'static str,
        status: u16,
        body: String,
    }
    type CapturedCalls = Arc<Mutex<Vec<(String, BTreeMap<String, String>)>>>;
    #[derive(Clone)]
    struct Mock {
        steps: Arc<Mutex<VecDeque<Step>>>,
        calls: CapturedCalls,
    }
    struct Server {
        state: Mock,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handle(
        State(m): State<Mock>,
        Path(op): Path<String>,
        Query(q): Query<BTreeMap<String, String>>,
    ) -> impl IntoResponse {
        m.calls.lock().unwrap().push((op.clone(), q.clone()));
        assert_eq!(q.get("type").map(String::as_str), Some("json"));
        assert_eq!(q.get("version").map(String::as_str), Some("1"));
        assert_eq!(q.get("key").map(String::as_str), Some("Test+/ Key&?"));
        let step = m
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request / write retry");
        assert_eq!(op, step.op);
        (
            StatusCode::from_u16(step.status).unwrap(),
            [
                ("content-type", "application/json"),
                ("x-request-id", "mock-trace"),
                ("location", "/api/forbidden"),
            ],
            step.body,
        )
    }
    async fn mock(steps: Vec<Step>) -> (Namesilo, Server) {
        let state = Mock {
            steps: Arc::new(Mutex::new(steps.into())),
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/api/{op}", get(handle))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut p = Namesilo::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            "Test+/ Key&?".into(),
            &BTreeMap::new(),
        );
        p.endpoint = format!("http://{address}/api");
        (p, Server { state, task })
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
    fn row(id: &str, host: &str, kind: &str, value: &str) -> Value {
        json!({"record_id":id,"host":host,"type":kind,"value":value,"ttl":"600","distance":"0"})
    }
    fn a() -> Value {
        row("oldOpaque.ID-7", "home.example.com", "A", "1.1.1.1")
    }
    fn step(op: &'static str, fields: Value) -> Step {
        let mut reply = json!({"code":300,"detail":"success"});
        for (k, v) in fields.as_object().unwrap() {
            reply[k] = v.clone();
        }
        Step {
            op,
            status: 200,
            body: json!({"request":{"operation":op,"ip":"127.0.0.1"},"reply":reply}).to_string(),
        }
    }
    fn domains() -> Step {
        step(
            "listDomains",
            json!({"domains":[{"domain":"example.com"}],"pager":{"page":1,"pageSize":"100","total":"1"}}),
        )
    }
    fn zone() -> Step {
        step(
            "getDomainInfo",
            json!({"status":"Active","email_verification_required":"No","traffic_type":"Custom DNS","forward_url":"N/A","forward_type":"N/A","nameservers":[{"nameserver":"NS1.DNSOWL.COM","position":1},{"nameserver":"NS2.DNSOWL.COM","position":2},{"nameserver":"NS3.DNSOWL.COM","position":3}]}),
        )
    }
    fn list(rows: Vec<Value>) -> Step {
        step("dnsListRecords", json!({"resource_record":rows}))
    }
    fn read(rows: Vec<Value>) -> Vec<Step> {
        vec![domains(), zone(), list(rows)]
    }
    fn ack(op: &'static str, id: &str) -> Step {
        step(op, json!({"record_id":id}))
    }
    fn done(server: &Server) {
        assert!(server.state.steps.lock().unwrap().is_empty());
    }
    fn writes(server: &Server) -> usize {
        server
            .state
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(op, _)| matches!(op.as_str(), "dnsAddRecord" | "dnsUpdateRecord"))
            .count()
    }
    fn patch(step: &mut Step, path: &str, value: Value) {
        let mut b: Value = serde_json::from_str(&step.body).unwrap();
        *b.pointer_mut(path).unwrap() = value;
        step.body = b.to_string();
    }

    #[tokio::test]
    async fn readonly_and_noop_do_not_write() {
        for (ip, status) in [("1.1.1.1", "unchanged"), ("8.8.8.8", "would_update")] {
            let (p, m) = mock(read(vec![a()])).await;
            let outcome = common::reconcile(&p, &spec(), ip, true).await.unwrap();
            assert_eq!(outcome.status, status);
            assert_eq!(outcome.record_id, Some(logical_id(&spec())));
            assert_eq!(outcome.request_id.as_deref(), Some("mock-trace"));
            assert_eq!(writes(&m), 0);
            done(&m);
        }
    }
    #[tokio::test]
    async fn absence_requires_optin_and_readonly_is_safe() {
        for allow in [false, true] {
            let (p, m) = mock(read(vec![])).await;
            let mut s = spec();
            s.create_if_missing = allow;
            let result = common::reconcile(&p, &s, "8.8.8.8", true).await;
            if allow {
                assert_eq!(result.unwrap().status, "would_create");
            } else {
                assert_eq!(result.unwrap_err().code, "RecordNotFound");
            }
            assert_eq!(writes(&m), 0);
            done(&m);
        }
    }
    #[tokio::test]
    async fn explicit_missing_identity_does_not_fallback_or_create() {
        let (p, m) = mock(read(vec![a()])).await;
        let mut s = spec();
        s.record_id = Some("namesilo-missing".into());
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&p, &s, "1.1.1.1", true)
                .await
                .unwrap_err()
                .code,
            "RecordIdNotFound"
        );
        assert_eq!(writes(&m), 0);
        done(&m);
    }
    #[tokio::test]
    async fn duplicate_native_ids_are_rejected() {
        let (p, m) = mock(read(vec![
            a(),
            row("oldOpaque.ID-7", "other.example.com", "TXT", "text"),
        ]))
        .await;
        assert_eq!(
            common::reconcile(&p, &spec(), "1.1.1.1", true)
                .await
                .unwrap_err()
                .code,
            "UnstableRecordList"
        );
        assert_eq!(writes(&m), 0);
        done(&m);
    }
    #[tokio::test]
    async fn multivalue_even_pinned_is_rejected_before_noop() {
        let (p, m) = mock(read(vec![
            a(),
            row("another", "home.example.com", "A", "1.1.1.1"),
        ]))
        .await;
        let mut s = spec();
        s.record_id = Some(logical_id(&s));
        assert_eq!(
            common::reconcile(&p, &s, "1.1.1.1", true)
                .await
                .unwrap_err()
                .code,
            "UnsafeMultivalue"
        );
        assert_eq!(writes(&m), 0);
        done(&m);
    }
    #[tokio::test]
    async fn disabled_and_unknown_settings_fail_before_noop() {
        for (key, value, code) in [
            ("enabled", json!(false), "RecordDisabled"),
            ("enabled", json!("no"), "MalformedRecord"),
            ("weight", json!(10), "UnsafeRecordSettings"),
            ("distance", json!("10"), "UnsafeRecordSettings"),
        ] {
            let mut r = a();
            r[key] = value;
            let (p, m) = mock(read(vec![r])).await;
            assert_eq!(
                common::reconcile(&p, &spec(), "1.1.1.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(writes(&m), 0);
            done(&m);
        }
    }
    #[tokio::test]
    async fn aliases_prevent_noop_and_would_create() {
        for existing in [false, true] {
            let mut rows = vec![row(
                "alias",
                "home.example.com",
                "CNAME",
                "target.example.net",
            )];
            if existing {
                rows.push(a());
            }
            let (p, m) = mock(read(rows)).await;
            let mut s = spec();
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&p, &s, "1.1.1.1", true)
                    .await
                    .unwrap_err()
                    .code,
                "AliasConflict"
            );
            assert_eq!(writes(&m), 0);
            done(&m);
        }
    }
    #[tokio::test]
    async fn child_delegation_prevents_creation_and_noop() {
        let (p, m) = mock(read(vec![
            row("delegation", "home.example.com", "NS", "ns.example.net"),
            a(),
        ]))
        .await;
        assert_eq!(
            common::reconcile(&p, &spec(), "1.1.1.1", true)
                .await
                .unwrap_err()
                .code,
            "DelegatedHost"
        );
        assert_eq!(writes(&m), 0);
        done(&m);
    }
    #[tokio::test]
    async fn malformed_and_outside_zone_records_fail_closed() {
        for (key, value, code) in [
            ("record_id", json!(42), "MalformedRecord"),
            ("host", json!("outside.com"), "RecordZoneMismatch"),
            ("ttl", Value::Null, "MalformedRecord"),
            ("value", json!(["1.1.1.1"]), "MalformedRecord"),
            ("value", json!("::1"), "InvalidRecordValue"),
        ] {
            let mut r = a();
            r[key] = value;
            let (p, m) = mock(read(vec![r])).await;
            assert_eq!(
                common::reconcile(&p, &spec(), "1.1.1.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(writes(&m), 0);
            done(&m);
        }
    }
    #[tokio::test]
    async fn list_requires_complete_array_and_no_pagination() {
        for v in [
            json!({"resource_record":null}),
            json!({"resource_record":a()}),
            json!({"resource_record":[],"pager":{"total":1}}),
            json!({"resource_record":[],"truncated":true}),
        ] {
            let (p, m) = mock(vec![domains(), zone(), step("dnsListRecords", v)]).await;
            assert!(
                common::reconcile(&p, &spec(), "1.1.1.1", true)
                    .await
                    .is_err()
            );
            assert_eq!(writes(&m), 0);
            done(&m);
        }
    }
    #[tokio::test]
    async fn account_absence_never_infers_parent_zone() {
        let mut d = domains();
        patch(&mut d, "/reply/domains/0/domain", json!("com"));
        let (p, m) = mock(vec![d]).await;
        assert_eq!(p.list(&spec()).await.unwrap_err().code, "DomainNotFound");
        done(&m);
    }
    #[tokio::test]
    async fn complete_account_pagination_reads_through_match() {
        let mut first: Vec<Value> = (0..100)
            .map(|i| json!({"domain":format!("d{i}.example.net")}))
            .collect();
        first[0] = json!({"domain":"example.com"});
        let d1 = step(
            "listDomains",
            json!({"domains":first,"pager":{"page":1,"pageSize":"100","total":"101"}}),
        );
        let d2 = step(
            "listDomains",
            json!({"domains":[{"domain":"last.example.net"}],"pager":{"page":2,"pageSize":"100","total":"101"}}),
        );
        let (p, m) = mock(vec![d1, d2, zone(), list(vec![a()])]).await;
        p.list(&spec()).await.unwrap();
        let calls = m.state.calls.lock().unwrap();
        assert_eq!(calls[1].1["page"], "2");
        drop(calls);
        done(&m);
    }
    #[tokio::test]
    async fn account_pager_inconsistency_fails_even_when_domain_matches() {
        for (path, value) in [
            ("/reply/pager/total", json!(2)),
            ("/reply/pager/page", json!(2)),
            ("/reply/pager/pageSize", json!(200)),
        ] {
            let mut d = domains();
            patch(&mut d, path, value);
            let (p, m) = mock(vec![d]).await;
            assert_eq!(
                p.list(&spec()).await.unwrap_err().code,
                "IncompleteDomainList"
            );
            done(&m);
        }
    }
    #[tokio::test]
    async fn inactive_external_and_forwarded_zones_fail_before_list() {
        for (path, value, code) in [
            ("/reply/status", json!("Expired"), "ZoneInactive"),
            (
                "/reply/email_verification_required",
                json!("Yes"),
                "ZoneInactive",
            ),
            (
                "/reply/traffic_type",
                json!("Forwarded"),
                "UnsafeZoneSettings",
            ),
            (
                "/reply/nameservers/0/nameserver",
                json!("ns.external.net"),
                "ExternalNameservers",
            ),
        ] {
            let mut z = zone();
            patch(&mut z, path, value);
            let (p, m) = mock(vec![domains(), z]).await;
            assert_eq!(p.list(&spec()).await.unwrap_err().code, code);
            done(&m);
        }
    }
    #[tokio::test]
    async fn creates_with_exact_native_ack_and_readback() {
        let mut steps = read(vec![]);
        steps.extend(read(vec![]));
        steps.push(ack("dnsAddRecord", "newNative"));
        steps.push(list(vec![row(
            "newNative",
            "home.example.com",
            "A",
            "8.8.8.8",
        )]));
        let (p, m) = mock(steps).await;
        let mut s = spec();
        s.create_if_missing = true;
        let out = common::reconcile(&p, &s, "8.8.8.8", false).await.unwrap();
        assert_eq!(out.status, "created");
        assert_eq!(out.record_id, Some(logical_id(&s)));
        assert_eq!(writes(&m), 1);
        let calls = m.state.calls.lock().unwrap();
        let q = &calls[6].1;
        assert_eq!(q["rrtype"], "A");
        assert_eq!(q["rrhost"], "home");
        assert_eq!(q["rrttl"], "600");
        assert!(!q.contains_key("rrid"));
        drop(calls);
        done(&m);
    }
    #[tokio::test]
    async fn pinned_identity_survives_repeated_native_rotation() {
        let unrelated = row("txtOriginal", "other.example.com", "TXT", "preserve me");
        let mut steps = read(vec![a(), unrelated.clone()]);
        steps.extend(read(vec![unrelated.clone(), a()]));
        steps.push(ack("dnsUpdateRecord", "newNative"));
        steps.push(list(vec![
            row("newNative", "home.example.com", "A", "8.8.8.8"),
            unrelated.clone(),
        ]));
        steps.extend(read(vec![
            row("newNative", "home.example.com", "A", "8.8.8.8"),
            unrelated.clone(),
        ]));
        steps.extend(read(vec![
            unrelated.clone(),
            row("newNative", "home.example.com", "A", "8.8.8.8"),
        ]));
        steps.push(ack("dnsUpdateRecord", "nextNative"));
        steps.push(list(vec![
            row("nextNative", "home.example.com", "A", "9.9.9.9"),
            unrelated,
        ]));
        let (p, m) = mock(steps).await;
        let mut s = spec();
        s.record_id = Some(logical_id(&s));
        for ip in ["8.8.8.8", "9.9.9.9"] {
            let out = common::reconcile(&p, &s, ip, false).await.unwrap();
            assert_eq!(out.status, "updated");
            assert_eq!(out.record_id, s.record_id);
        }
        let calls = m.state.calls.lock().unwrap();
        let qs: Vec<_> = calls
            .iter()
            .filter(|(op, _)| op == "dnsUpdateRecord")
            .map(|(_, q)| q)
            .collect();
        assert_eq!(qs[0]["rrid"], "oldOpaque.ID-7");
        assert_eq!(qs[1]["rrid"], "newNative");
        assert!(!qs[0].contains_key("rrtype"));
        drop(calls);
        assert_eq!(writes(&m), 2);
        done(&m);
    }
    #[tokio::test]
    async fn stale_full_snapshot_including_unrelated_metadata_stops_write() {
        let txt = row("txt", "other.example.com", "TXT", "before");
        let mut changed = txt.clone();
        changed["value"] = json!("after");
        let mut steps = read(vec![a(), txt]);
        steps.extend(read(vec![a(), changed]));
        let (p, m) = mock(steps).await;
        assert_eq!(
            common::reconcile(&p, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "StaleRecord"
        );
        assert_eq!(writes(&m), 0);
        done(&m);
    }
    #[tokio::test]
    async fn fresh_absence_prevents_duplicate_create() {
        let mut steps = read(vec![]);
        steps.extend(read(vec![a()]));
        let (p, m) = mock(steps).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&p, &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordAppeared"
        );
        assert_eq!(writes(&m), 0);
        done(&m);
    }
    #[tokio::test]
    async fn reused_or_nonstring_native_ack_never_succeeds_or_retries() {
        for id in [json!("oldOpaque.ID-7"), json!(42), json!("")] {
            let mut steps = read(vec![a()]);
            steps.extend(read(vec![a()]));
            steps.push(step("dnsUpdateRecord", json!({"record_id":id})));
            let (p, m) = mock(steps).await;
            let e = common::reconcile(&p, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err();
            assert_eq!(e.code, "InvalidWriteAcknowledgement");
            assert!(!e.retryable);
            assert_eq!(writes(&m), 1);
            done(&m);
        }
    }
    #[tokio::test]
    async fn wrong_native_readback_identity_value_ttl_or_unrelated_change_rejected() {
        for mode in 0..5 {
            let txt = row("txt", "other.example.com", "TXT", "before");
            let mut new = row("newNative", "home.example.com", "A", "8.8.8.8");
            let mut other = txt.clone();
            match mode {
                0 => new["record_id"] = json!("wrongNative"),
                1 => new["value"] = json!("9.9.9.9"),
                2 => new["ttl"] = json!("300"),
                3 => new["host"] = json!("wrong.example.com"),
                _ => other["value"] = json!("changed"),
            };
            let mut steps = read(vec![a(), txt.clone()]);
            steps.extend(read(vec![a(), txt]));
            steps.push(ack("dnsUpdateRecord", "newNative"));
            steps.push(list(vec![new, other]));
            let (p, m) = mock(steps).await;
            assert_eq!(
                common::reconcile(&p, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "WriteReadbackMismatch"
            );
            assert_eq!(writes(&m), 1);
            done(&m);
        }
    }
    #[tokio::test]
    async fn bounded_sanitized_business_and_http_errors() {
        for status in [200, 403, 429, 503] {
            let step=Step{op:"listDomains",status,body:json!({"reply":{"code":201,"detail":format!("Permission denied Test+/ Key&? Test%2B%2F+Key%26%3F Test%2b%2f+Key%26%3f {}","x".repeat(3000))}}).to_string()};
            let (p, m) = mock(vec![step]).await;
            let e = p.list(&spec()).await.unwrap_err();
            assert_eq!(e.http_status, Some(status));
            assert!(e.message.contains("Permission denied"));
            assert!(!e.message.contains("Test"));
            assert!(e.message.len() < 2300);
            assert_eq!(writes(&m), 0);
            done(&m);
        }
    }
    #[tokio::test]
    async fn mutation_http_failure_is_not_retried() {
        let mut steps = read(vec![a()]);
        steps.extend(read(vec![a()]));
        steps.push(Step {
            op: "dnsUpdateRecord",
            status: 503,
            body: json!({"reply":{"code":201,"detail":"provider unavailable"}}).to_string(),
        });
        let (p, m) = mock(steps).await;
        let e = common::reconcile(&p, &spec(), "8.8.8.8", false)
            .await
            .unwrap_err();
        assert!(!e.retryable);
        assert_eq!(e.http_status, Some(503));
        assert_eq!(writes(&m), 1);
        done(&m);
    }
    #[tokio::test]
    async fn malformed_xml_response_and_redirect_do_not_leak_urls_or_retry() {
        for (status, body) in [
            (200, "<namesilo>secret</namesilo>"),
            (
                302,
                "{\"reply\":{\"code\":201,\"detail\":\"https://evil.example/?key=Test%2B%2F+Key%26%3F\"}}",
            ),
        ] {
            let (p, m) = mock(vec![Step {
                op: "listDomains",
                status,
                body: body.into(),
            }])
            .await;
            let e = p.list(&spec()).await.unwrap_err();
            let msg = format!("{} {:?}", e.message, e.request_id);
            assert!(!msg.contains("https://"));
            assert!(!msg.contains("Test"));
            assert!(!msg.contains("secret"));
            assert_eq!(e.http_status, Some(status));
            assert_eq!(m.state.calls.lock().unwrap().len(), 1);
            done(&m);
        }
    }
    #[tokio::test]
    async fn direct_creation_and_invalid_configuration_fail_locally() {
        let (p, m) = mock(vec![]).await;
        assert_eq!(
            p.create(&spec(), "8.8.8.8").await.unwrap_err().code,
            "CreationNotAllowed"
        );
        for ttl in [299, 3603, 7207, 604801] {
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(p.list(&s).await.unwrap_err().code, "UnsupportedTTL");
        }
        let mut s = spec();
        s.record_id = Some("oldNative".into());
        assert_eq!(p.list(&s).await.unwrap_err().code, "InvalidRecordId");
        let mut s = spec();
        s.options.insert("endpoint".into(), "unsafe".into());
        assert_eq!(p.list(&s).await.unwrap_err().code, "UnsupportedOptions");
        let mut s = spec();
        s.domain = "https://evil.example".into();
        assert_eq!(p.list(&s).await.unwrap_err().code, "InvalidDnsName");
        assert!(m.state.calls.lock().unwrap().is_empty());
        done(&m);
    }
    #[tokio::test]
    async fn ipv6_apex_preserves_family_and_empty_relative_host() {
        let mut s = spec();
        s.subdomain = "@".into();
        s.record_type = "AAAA".into();
        let old = row("v6Old", "example.com", "AAAA", "2001:db8::1");
        let new = row("v6New", "example.com", "AAAA", "2001:db8::2");
        let mut steps = read(vec![old.clone()]);
        steps.extend(read(vec![old]));
        steps.push(ack("dnsUpdateRecord", "v6New"));
        steps.push(list(vec![new]));
        let (p, m) = mock(steps).await;
        assert_eq!(
            common::reconcile(&p, &s, "2001:0db8::2", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let calls = m.state.calls.lock().unwrap();
        assert_eq!(calls[6].1["rrhost"], "");
        assert_eq!(calls[6].1["rrvalue"], "2001:db8::2");
        drop(calls);
        done(&m);
    }
    #[tokio::test]
    async fn oversized_response_is_bounded_without_raw_body() {
        let (p, m) = mock(vec![Step {
            op: "listDomains",
            status: 200,
            body: format!("{{\"secret\":\"{}\"}}", "x".repeat(1024 * 1024)),
        }])
        .await;
        let e = p.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "ResponseTooLarge");
        assert_eq!(e.http_status, Some(200));
        assert!(!e.message.contains("secret"));
        done(&m);
    }
    #[tokio::test]
    async fn wrong_operation_and_missing_success_envelope_fail_closed() {
        for body in [
            json!({"request":{"operation":"wrong"},"reply":{"code":300,"detail":"success"}}),
            json!({"request":{"operation":"listDomains"},"reply":{"detail":"success"}}),
            json!({"request":{"operation":"listDomains"},"reply":{"code":300,"detail":"success"},"truncated":true}),
        ] {
            let (p, m) = mock(vec![Step {
                op: "listDomains",
                status: 200,
                body: body.to_string(),
            }])
            .await;
            assert_eq!(p.list(&spec()).await.unwrap_err().code, "InvalidEnvelope");
            done(&m);
        }
    }
    #[tokio::test]
    async fn warning_ack_is_uncertain_not_automatic_success() {
        let mut steps = read(vec![a()]);
        steps.extend(read(vec![a()]));
        let mut write = ack("dnsUpdateRecord", "newNative");
        patch(&mut write, "/reply/detail", json!("accepted with warning"));
        steps.push(write);
        let (p, m) = mock(steps).await;
        let e = common::reconcile(&p, &spec(), "8.8.8.8", false)
            .await
            .unwrap_err();
        assert_eq!(e.code, "InvalidWriteAcknowledgement");
        assert!(!e.retryable);
        assert_eq!(writes(&m), 1);
        done(&m);
    }
    #[test]
    fn encoded_keys_mixed_escape_case_are_fully_redacted() {
        let p = Namesilo::new(
            reqwest::Client::new(),
            "Test+/ Key&?".into(),
            &BTreeMap::new(),
        );
        for value in [
            "Test+/ Key&?",
            "Test%2B%2f+Key%26%3F",
            "Test%2b%2F%20Key%26%3f",
        ] {
            let text = p.safe(&format!("Permission denied for {value}"));
            assert!(!text.contains("Test"));
            assert!(text.contains("Permission denied"));
        }
    }
    #[test]
    fn logical_ids_are_stable_casefolded_and_type_specific() {
        let s = spec();
        assert_eq!(logical_id(&s).len(), 73);
        assert!(common::valid_id(&logical_id(&s)));
        let mut same = s.clone();
        same.domain = "EXAMPLE.COM".into();
        same.subdomain = "HOME".into();
        assert_eq!(logical_id(&s), logical_id(&same));
        same.record_type = "AAAA".into();
        assert_ne!(logical_id(&s), logical_id(&same));
        let p = Namesilo::new(
            reqwest::Client::new(),
            "Test+/ Key&?".into(),
            &BTreeMap::new(),
        );
        assert!(
            !p.safe("https://evil.example/?key=secret")
                .contains("https://")
        );
    }
}
