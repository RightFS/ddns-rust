//! Baidu BCD DNS contracts checked 2026-11-09:
//! https://cloud.baidu.com/doc/BCD/s/4jwvymhs7
//! https://cloud.baidu.com/doc/BCD/s/dkps0ww42
//! https://github.com/baidubce/bce-sdk-java/tree/master/src/main/java/com/baidubce/services/bcd
//! https://cloud.baidu.com/doc/Reference/s/Njwvz1wot
//! Required provider resource_id is the actual owned domain resourceId.
//! Parent supplies a redirect-disabled client; no production URL override.
//! Edits are per-record, only ttl/rdType/rdata mutable. Unknown selected metadata
//! is refused, not dropped. Empty HTTP 200 is the documented write ack; a full
//! readback establishes its outcome. No CAS: concurrent races remain possible.
//! TTL is the BCD documented 60..3600, not a fabricated account-minimum API;
//! account-specific rejections remain original sanitized business errors.
//! Authority proof is configured provider DNS, not live public DNS delegation.
//! Undocumented nameserver pairs/advanced metadata need a preservation contract.
#![allow(clippy::result_large_err)]
use super::common::{
    Adapter, Api, HttpReply, List, Mutation, Record, Spec, valid_id, valid_trace_id,
};
use crate::provider::ProviderError;
use chrono::Utc;
use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    time::Duration,
};
const ENDPOINT: &str = "https://bcd.baidubce.com";
const PAGE: usize = 100;
const LIMIT: usize = 10000;
const ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
const LINES: &[&str] = &["DEFAULT", "CMNET", "CNC", "EDU", "SEARCH"];
const HINT: &str = "Check BCE AK/SK, exact owned resource_id/domain, active Baidu DNS and documented line/TTL. Inspect uncertain writes manually; no automatic write retry.";
// Intentionally no Debug: credentials/signatures are secret.
pub struct BaiduCloud {
    api: Api,
    id: String,
    key: String,
    resource_id: String,
    options_valid: bool,
    #[cfg(test)]
    endpoint: String,
}
struct Snapshot {
    records: Vec<Record>,
    ownership: Value,
    request_id: Option<String>,
}
fn encode(s: &str) -> String {
    utf8_percent_encode(s, ENCODE).to_string()
}
fn hmac(key: &str, text: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(text.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
fn authorization(
    id: &str,
    key: &str,
    timestamp: &str,
    method: &str,
    path: &str,
    query: &BTreeMap<String, String>,
) -> (String, String, String) {
    let prefix = format!("bce-auth-v1/{id}/{timestamp}/1800");
    let signing_key = hmac(key, &prefix);
    let uri = path.split('/').map(encode).collect::<Vec<_>>().join("/");
    let mut pairs = query
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>();
    pairs.sort();
    let query = pairs.join("&");
    let canonical = format!("{method}\n{uri}\n{query}\nhost:bcd.baidubce.com");
    let signature = hmac(&signing_key, &canonical);
    (format!("{prefix}/host/{signature}"), signature, signing_key)
}
fn line(s: &str) -> &str {
    match s {
        "默认" | "default" => "DEFAULT",
        other => other,
    }
}
fn native_id(v: &Value) -> Option<String> {
    let n = match v {
        Value::String(s) => {
            let n = s.parse::<u64>().ok()?;
            if n.to_string() != *s {
                return None;
            }
            n
        }
        _ => v.as_u64()?,
    };
    (n > 0 && n <= i32::MAX as u64).then(|| n.to_string())
}
fn resource_id(s: &str) -> bool {
    valid_id(s) && !matches!(s, "." | "..")
}
fn hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn record_name(s: &str) -> bool {
    s == "@"
        || s == "*"
        || hostname(s)
        || s.strip_prefix("*.").is_some_and(hostname)
        || (!s.is_empty()
            && s.len() <= 253
            && s.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            }))
}
fn safe_trace(s: &str) -> bool {
    valid_trace_id(s)
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn business_message(api: &Api, s: &str) -> String {
    // Keep bounded original detail, never URLs or credential echoes.
    api.safe(s)
        .split_whitespace()
        .map(|part| {
            if part.to_ascii_lowercase().contains("http://")
                || part.to_ascii_lowercase().contains("https://")
            {
                "[URL omitted]"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}
fn same_ip(a: &str, b: &str) -> bool {
    a.parse::<IpAddr>()
        .ok()
        .zip(b.parse::<IpAddr>().ok())
        .is_some_and(|(a, b)| a == b)
}
impl BaiduCloud {
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
            resource_id: options.get("resource_id").cloned().unwrap_or_default(),
            options_valid: options.keys().all(|k| k == "resource_id"),
            #[cfg(test)]
            endpoint: ENDPOINT.into(),
        }
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
    fn validate(&self, s: &Spec) -> Result<(), ProviderError> {
        if self.id.is_empty()
            || self.id.len() > 256
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || self.key.is_empty()
            || self.key.len() > 1024
            || !self.key.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(self.error(
                "validation",
                "InvalidCredentials",
                "BCE requires nonempty ASCII AK/SK; AK cannot contain signing delimiters.",
                None,
            ));
        }
        if !self.options_valid || !resource_id(&self.resource_id) || !s.options.is_empty() {
            return Err(self.error("validation","UnsupportedOptions","Only required provider resource_id is supported; no record options, min_ttl or endpoint override.",None));
        }
        if !hostname(&s.domain)
            || !s.domain.contains('.')
            || s.domain.len() > 64
            || (s.subdomain != "@" && !hostname(&s.subdomain))
            || s.fqdn().len() > 253
        {
            return Err(self.error("validation","InvalidTarget","Use an exact ASCII/punycode registered domain (maximum 64 bytes) and relative host or @.",None));
        }
        if !matches!(s.record_type.as_str(), "A" | "AAAA")
            || !(60..=3600).contains(&s.ttl)
            || !LINES.contains(&line(&s.record_line))
        {
            return Err(self.error("validation","UnsupportedRecordSettings","Use A/AAAA, documented TTL 60..3600 and DEFAULT/CMNET/CNC/EDU/SEARCH lines; default/默认 aliases mean exact DEFAULT, not wildcard.",None));
        }
        if s.record_id
            .as_ref()
            .is_some_and(|id| native_id(&json!(id)).is_none())
        {
            return Err(self.error("validation","InvalidRecordId","record_id must be a canonical positive decimal BCD ID, not a path, dot segment or zero.",None));
        }
        Ok(())
    }
    // Shared Api.send rejects documented empty200. Local bounded transport uses
    // a per-call Api with auth/signature/derived key registered for sanitization.
    async fn call(
        &self,
        stage: &str,
        path: &str,
        query: BTreeMap<String, String>,
        body: Option<Value>,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let method = if body.is_some() { "POST" } else { "GET" };
        let (auth, sig, derived) = authorization(
            &self.id,
            &self.key,
            &Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            method,
            path,
            &query,
        );
        let api = Api::new(
            self.api.client.clone(),
            vec![
                auth.clone(),
                sig,
                derived,
                self.id.clone(),
                self.key.clone(),
            ],
        );
        #[cfg(test)]
        let endpoint = &self.endpoint;
        #[cfg(not(test))]
        let endpoint = ENDPOINT;
        let mut header = reqwest::header::HeaderValue::from_str(&auth).map_err(|_| {
            api.error(
                stage,
                "InvalidAuthorization",
                "Could not construct BCE authorization.",
                HINT,
                None,
            )
        })?;
        header.set_sensitive(true);
        let mut request = api
            .client
            .request(
                if body.is_some() {
                    reqwest::Method::POST
                } else {
                    reqwest::Method::GET
                },
                format!("{endpoint}{path}"),
            )
            .query(&query)
            .header(reqwest::header::AUTHORIZATION, header);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let transport = |e: reqwest::Error| {
            let code = if e.is_timeout() {
                "Timeout"
            } else if e.is_connect() {
                "ConnectionFailure"
            } else {
                "TransportFailure"
            };
            // Arbitrary proxy/TLS error chains may contain URLs: never expose.
            api.error(
                stage,
                code,
                if write {
                    "BCE transport failed; write result is uncertain; no retry occurred."
                } else {
                    "BCE transport failed; no write was attempted."
                },
                HINT,
                None,
            )
        };
        let result=tokio::time::timeout(Duration::from_secs(30),async {
            let mut response=request.send().await.map_err(transport)?;
            let status=response.status().as_u16();
            let headers=response.headers().clone();
            let request_id=headers.get("x-bce-request-id").and_then(|v|v.to_str().ok()).map(|s|api.safe(s)).filter(|s|safe_trace(s));
            let mut reply=HttpReply {status,headers,body:Value::Null,request_id};
            let mut bytes=Vec::new();
            while let Some(chunk)=response.chunk().await.map_err(transport)? {
                if bytes.len()+chunk.len()>1024*1024 {return Err(api.error(stage,"ResponseTooLarge","BCE response exceeded 1 MiB; raw body omitted.",HINT,Some(&reply)));}
                bytes.extend_from_slice(&chunk);
            }
            if !bytes.is_empty() {
                reply.body=serde_json::from_slice(&bytes).map_err(|_|api.error(stage,"MalformedResponse","BCE returned malformed JSON; raw body omitted; inspect any uncertain write.",HINT,Some(&reply)))?;
            }
            if let Some(id)=reply.body.get("requestId").and_then(Value::as_str).map(|v|api.safe(v)).filter(|v|safe_trace(v)) {reply.request_id=Some(id);}
            if let Some(code)=reply.body.get("code") {
                let code=code.as_str().unwrap_or("BceBusinessError");
                let message=reply.body.get("message").and_then(Value::as_str).unwrap_or("BCE business error without a string message.");
                return Err(api.error(stage,code,&business_message(&api,message),HINT,Some(&reply)));
            }
            if status!=200 {
                let message=reply.body.get("message").and_then(Value::as_str).unwrap_or("BCE returned an unsuccessful or undocumented HTTP status; raw body omitted.");
                return Err(api.error(stage,&format!("Http{status}"),&business_message(&api,message),HINT,Some(&reply)));
            }
            if write {
                if !reply.body.is_null() && !reply.body.as_object().is_some_and(|m|m.is_empty()) {
                    return Err(api.error(stage,"InvalidWriteAcknowledgement","BCD write returned undocumented fields; result is uncertain. HTTP200 empty response is the documented acknowledgement.",HINT,Some(&reply)));
                }
            } else if !reply.body.is_object() {
                return Err(api.error(stage,"InvalidEnvelope","BCD read requires a JSON object; raw response omitted.",HINT,Some(&reply)));
            }
            Ok(reply)
        }).await.unwrap_or_else(|_|Err(api.error(stage,"Timeout","BCE exceeded the 30-second deadline; inspect any uncertain write.",HINT,None)));
        match &result {
            Ok(r) => {
                tracing::debug!(action=stage,http_status=r.status,request_id=?r.request_id,"BCE action completed")
            }
            Err(e) => {
                tracing::debug!(action=stage,code=%e.code,http_status=?e.http_status,"BCE action failed")
            }
        };
        result
    }
    fn page<'a>(
        &self,
        reply: &'a HttpReply,
        page: usize,
        records: bool,
        total: &mut Option<usize>,
        seen: usize,
    ) -> Result<&'a Vec<Value>, ProviderError> {
        let fail = || {
            self.error("list","IncompletePagination","BCD pagination has missing/changed totals, wrong page, truncated results or unsupported continuation links.",Some(reply))
        };
        if [
            "next",
            "nextPage",
            "nextLink",
            "links",
            "marker",
            "isTruncated",
        ]
        .iter()
        .any(|k| reply.body.get(*k).is_some())
        {
            return Err(fail());
        }
        let count = reply.body["totalCount"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n <= LIMIT)
            .ok_or_else(fail)?;
        if total.is_some_and(|n| n != count) {
            return Err(fail());
        }
        *total = Some(count);
        if (records || reply.body.get("pageNo").is_some())
            && reply.body["pageNo"].as_u64() != Some(page as u64)
        {
            return Err(fail());
        }
        if (records || reply.body.get("pageSize").is_some())
            && reply.body["pageSize"].as_u64() != Some(PAGE as u64)
        {
            return Err(fail());
        }
        let rows = reply.body["result"].as_array().ok_or_else(fail)?;
        if rows.len() != PAGE.min(count.saturating_sub(seen)) || seen + rows.len() > count {
            return Err(fail());
        }
        Ok(rows)
    }
    async fn ownership(&self, s: &Spec) -> Result<Value, ProviderError> {
        let mut zones = Vec::new();
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        let mut total = None;
        for p in 1..=LIMIT / PAGE + 1 {
            let reply = self
                .call(
                    "ownership",
                    "/v2/domain",
                    BTreeMap::from([
                        ("pageNo".into(), p.to_string()),
                        ("pageSize".into(), PAGE.to_string()),
                    ]),
                    None,
                    false,
                )
                .await?;
            let rows = self.page(&reply, p, false, &mut total, zones.len())?;
            for z in rows {
                let id = z["resourceId"]
                    .as_str()
                    .filter(|id| resource_id(id))
                    .ok_or_else(|| {
                        self.error(
                            "ownership",
                            "MalformedZone",
                            "Owned domain lacks a valid actual resourceId.",
                            Some(&reply),
                        )
                    })?;
                let name = z["domainName"]
                    .as_str()
                    .filter(|n| hostname(n))
                    .ok_or_else(|| {
                        self.error(
                            "ownership",
                            "MalformedZone",
                            "Owned domain lacks an exact domainName.",
                            Some(&reply),
                        )
                    })?;
                if !ids.insert(id.to_owned()) || !names.insert(name.to_ascii_lowercase()) {
                    return Err(self.error(
                        "ownership",
                        "DuplicateZone",
                        "Duplicate resource IDs/names; ownership is unstable.",
                        Some(&reply),
                    ));
                }
                zones.push(z.clone());
            }
            if rows.is_empty() {
                break;
            }
        }
        let targets: Vec<_> = zones
            .iter()
            .filter(|z| {
                z["domainName"]
                    .as_str()
                    .is_some_and(|n| same_name(n, &s.domain))
                    || z["resourceId"].as_str() == Some(&self.resource_id)
            })
            .collect();
        if targets.len() != 1
            || targets[0]["resourceId"].as_str() != Some(&self.resource_id)
            || !targets[0]["domainName"]
                .as_str()
                .is_some_and(|n| same_name(n, &s.domain))
        {
            return Err(self.error("ownership","ZoneMismatch","Exact resource_id/domain pair was not uniquely present in the complete owned-domain listing.",None));
        }
        let zone = targets[0];
        if zone["expireStatus"].as_str() != Some("NORMAL")
            || zone
                .get("domain")
                .is_some_and(|v| !v.as_str().is_some_and(|n| same_name(n, &s.domain)))
        {
            return Err(self.error(
                "ownership",
                "InactiveZone",
                "Domain is expired, missing expiry state or has conflicting identity.",
                None,
            ));
        }
        let reply = self
            .call(
                "ownership",
                "/v1/domain/detail",
                BTreeMap::from([("domain".into(), s.domain.clone())]),
                None,
                false,
            )
            .await?;
        let d = &reply.body;
        let expiry = d["expireTime"]
            .as_str()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok());
        if !d["domain"]
            .as_str()
            .is_some_and(|n| same_name(n, &s.domain))
            || d["status"].as_str() != Some("RUNNING")
            || expiry.is_none_or(|v| v <= Utc::now())
            || (!matches!(d["verifyStatus"].as_str(), Some("NORMAL"))
                && !d.get("verifyStatus").is_some_and(Value::is_null))
        {
            return Err(self.error("ownership","InactiveZone","Exact domain detail must be RUNNING, unexpired and verified NORMAL (or explicit null for no verification requirement).",Some(&reply)));
        }
        let dns = d["dns"].as_array().and_then(|a| {
            a.iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                })
                .collect::<Option<Vec<_>>>()
        });
        let mut dns = dns.unwrap_or_default();
        dns.sort();
        if dns != ["ns1.bdydns.cn", "ns2.bdydns.cn"]
            && dns != ["ns3.baidudns.xyz", "ns4.baidudns.xyz"]
        {
            return Err(self.error("ownership","NonAuthoritativeZone","Only exact documented Baidu DNS pairs ns1/ns2.bdydns.cn or ns3/ns4.baidudns.xyz are recognized; custom/unknown nameservers are refused.",Some(&reply)));
        }
        if zone.get("dns").is_some_and(|v| {
            let mut z = v
                .as_array()
                .and_then(|a| {
                    a.iter()
                        .map(|v| {
                            v.as_str()
                                .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                        })
                        .collect::<Option<Vec<_>>>()
                })
                .unwrap_or_default();
            z.sort();
            z != dns
        }) {
            return Err(self.error(
                "ownership",
                "ZoneControlChanged",
                "Domain list/detail disagree on actual nameservers.",
                Some(&reply),
            ));
        }
        Ok(
            json!({"resourceId":self.resource_id,"domain":d["domain"],"status":d["status"],"verifyStatus":d["verifyStatus"],"expireTime":d["expireTime"],"dns":dns,"expireStatus":zone["expireStatus"]}),
        )
    }
    fn record(
        &self,
        s: &Spec,
        raw: &Value,
        proof: &Value,
        reply: &HttpReply,
    ) -> Result<Record, ProviderError> {
        let bad = || {
            self.error("list","MalformedRecord","BCD requires actual ID, relative domain, zoneName, rdtype/rdata, TTL, documented view and RUNNING/STOPPED status; none are defaulted.",Some(reply))
        };
        let id = native_id(&raw["recordId"]).ok_or_else(bad)?;
        let name = raw["domain"]
            .as_str()
            .filter(|n| record_name(n))
            .ok_or_else(bad)?
            .to_owned();
        if !raw["zoneName"]
            .as_str()
            .is_some_and(|n| same_name(n, &s.domain))
        {
            return Err(self.error(
                "list",
                "RecordZoneMismatch",
                "Returned record zoneName differs from exact owned domain.",
                Some(reply),
            ));
        }
        let rt = raw["rdtype"]
            .as_str()
            .filter(|t| {
                matches!(
                    *t,
                    "A" | "AAAA" | "CNAME" | "NS" | "TXT" | "MX" | "SOA" | "SRV"
                )
            })
            .ok_or_else(bad)?
            .to_owned();
        let value = raw["rdata"].as_str().ok_or_else(bad)?.to_owned();
        let ttl = raw["ttl"]
            .as_u64()
            .filter(|t| *t > 0 && *t <= i32::MAX as u64)
            .ok_or_else(bad)?;
        let actual = raw["view"]
            .as_str()
            .filter(|v| LINES.contains(v))
            .ok_or_else(bad)?;
        let enabled = match raw["status"].as_str() {
            Some("RUNNING") => true,
            Some("STOPPED") => false,
            _ => return Err(bad()),
        };
        Ok(Record {
            id,
            name,
            record_type: rt,
            value,
            ttl,
            line: if actual == line(&s.record_line) {
                s.record_line.clone()
            } else {
                actual.into()
            },
            enabled,
            extra: json!({"raw":raw,"ownership":proof}),
        })
    }
    fn conflicts(&self, s: &Spec, rows: &[Record]) -> Result<(), ProviderError> {
        for r in rows {
            if r.record_type == "CNAME" && same_name(&r.name, &s.subdomain) {
                return Err(self.error("selection","CnameConflict","Target host has a CNAME on some line; stopped aliases also block selection/create.",None));
            }
            if r.record_type == "NS"
                && r.name != "@"
                && (same_name(&r.name, &s.subdomain)
                    || s.subdomain
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{}", r.name.to_ascii_lowercase())))
            {
                return Err(self.error(
                    "selection",
                    "DelegatedTarget",
                    "Target lies at/below an NS delegation; no mutation is safe.",
                    None,
                ));
            }
        }
        Ok(())
    }
    async fn snapshot(&self, s: &Spec) -> Result<Snapshot, ProviderError> {
        self.validate(s)?;
        let ownership = self.ownership(s).await?;
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        let mut total = None;
        let mut request_id = None;
        for p in 1..=LIMIT / PAGE + 1 {
            let reply = self
                .call(
                    "list",
                    "/v1/domain/resolve/list",
                    BTreeMap::new(),
                    Some(json!({"domain":s.domain,"pageNo":p,"pageSize":PAGE})),
                    false,
                )
                .await?;
            let rows = self.page(&reply, p, true, &mut total, records.len())?;
            request_id = reply.request_id.clone().or(request_id);
            for raw in rows {
                let r = self.record(s, raw, &ownership, &reply)?;
                if !ids.insert(r.id.clone()) {
                    return Err(self.error(
                        "list",
                        "DuplicateRecordId",
                        "Repeated record ID across full BCD pages.",
                        Some(&reply),
                    ));
                }
                records.push(r);
            }
            if rows.is_empty() {
                break;
            }
        }
        self.conflicts(s, &records)?;
        Ok(Snapshot {
            records,
            ownership,
            request_id,
        })
    }
    fn selection(&self, s: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.validate(s)?;
        if let Some(r) = r {
            let raw = &r.extra["raw"];
            if !same_name(&r.name, &s.subdomain)
                || r.record_type != s.record_type
                || raw["view"].as_str() != Some(line(&s.record_line))
                || native_id(&raw["recordId"]).as_deref() != Some(&r.id)
                || !r.enabled
                || raw["status"].as_str() != Some("RUNNING")
                || !(60..=3600).contains(&r.ttl)
                || raw["ttl"].as_u64() != Some(r.ttl)
                || raw["rdata"].as_str() != Some(&r.value)
                || raw["rdtype"].as_str() != Some(&r.record_type)
                || raw["domain"].as_str() != Some(&r.name)
                || !raw["zoneName"]
                    .as_str()
                    .is_some_and(|n| same_name(n, &s.domain))
            {
                return Err(self.error("selection","UnsafeRecordSelection","Selected host/type/id/line/state mismatch; stopped records cannot be enabled or repurposed.",None));
            }
            if !raw.as_object().is_some_and(|m| {
                m.keys().all(|k| {
                    matches!(
                        k.as_str(),
                        "recordId"
                            | "domain"
                            | "view"
                            | "rdtype"
                            | "ttl"
                            | "rdata"
                            | "zoneName"
                            | "status"
                    )
                })
            }) {
                return Err(self.error("selection","UnsupportedRecordMetadata","Selected record has undocumented controls/metadata (including weight/remark); edit preservation contract is insufficient, so it is refused.",None));
            }
        }
        Ok(())
    }
    fn payload(&self, s: &Spec, r: Option<&Record>, ip: &str) -> Value {
        let mut body = json!({"domain":r.map_or(s.subdomain.as_str(),|r|r.name.as_str()),"view":r.map_or(line(&s.record_line),|r|r.extra["raw"]["view"].as_str().expect("validated view")),"rdType":s.record_type,"ttl":s.ttl,"rdata":ip.to_ascii_uppercase(),"zoneName":r.map_or(s.domain.as_str(),|r|r.extra["raw"]["zoneName"].as_str().expect("validated zone"))});
        if let Some(r) = r {
            body["recordId"] = json!(r.id.parse::<u64>().expect("validated numeric ID"));
        }
        body
    }
    fn matching<'a>(&self, s: &Spec, rows: &'a [Record]) -> Vec<&'a Record> {
        rows.iter()
            .filter(|r| {
                same_name(&r.name, &s.subdomain)
                    && r.record_type == s.record_type
                    && r.extra["raw"]["view"].as_str() == Some(line(&s.record_line))
            })
            .collect()
    }
    fn verified(&self, s: &Spec, r: &Record, ip: &str) -> bool {
        self.selection(s, Some(r)).is_ok() && r.ttl == s.ttl && same_ip(&r.value, ip)
    }
    fn unchanged_others(&self, before: &[Record], after: &[Record], target: &str) -> bool {
        let map = |rows: &[Record]| {
            rows.iter()
                .filter(|r| r.id != target)
                .map(|r| (r.id.clone(), r.extra["raw"].clone()))
                .collect::<BTreeMap<_, _>>()
        };
        map(before) == map(after)
    }
    fn uncertain(&self, id: Option<String>) -> ProviderError {
        let mut e=self.error("readback","WriteNotVerified","Full BCD readback did not prove the single-record result and unchanged controls/other records; result is uncertain; no retry occurred.",None);
        e.request_id = id;
        e
    }
}
impl Adapter for BaiduCloud {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Relative
    }
    fn validate_selection(&self, s: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.selection(s, r)
    }
    async fn list(&self, s: &Spec) -> Result<List, ProviderError> {
        let snap = self.snapshot(s).await?;
        Ok(List {
            records: snap.records,
            request_id: snap.request_id,
        })
    }
    async fn create(&self, s: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate(s)?;
        if !s.create_if_missing || s.record_id.is_some() {
            return Err(self.error(
                "create",
                "UnsafeCreate",
                "Create requires explicit opt-in and no explicit record ID.",
                None,
            ));
        }
        let before = self.snapshot(s).await?;
        if !self.matching(s, &before.records).is_empty() {
            return Err(self.error(
                "create",
                "RecordAppeared",
                "Fresh full snapshot no longer proves absence; no create occurred.",
                None,
            ));
        }
        let ack = self
            .call(
                "create",
                "/v1/domain/resolve/add",
                BTreeMap::new(),
                Some(self.payload(s, None, ip)),
                true,
            )
            .await?;
        let after = self
            .snapshot(s)
            .await
            .map_err(|_| self.uncertain(ack.request_id.clone()))?;
        let found = self.matching(s, &after.records);
        if found.len() != 1
            || before.ownership != after.ownership
            || before.records.iter().any(|r| r.id == found[0].id)
            || !self.verified(s, found[0], ip)
            || !self.unchanged_others(&before.records, &after.records, &found[0].id)
        {
            return Err(self.uncertain(ack.request_id));
        }
        Ok(Mutation {
            record_id: found[0].id.clone(),
            request_id: ack.request_id.or(after.request_id),
        })
    }
    async fn update(&self, s: &Spec, r: &Record, ip: &str) -> Result<Mutation, ProviderError> {
        self.selection(s, Some(r))?;
        let before = self.snapshot(s).await?;
        let current = before.records.iter().find(|x| x.id == r.id);
        if !current.is_some_and(|x| x.extra == r.extra)
            || r.extra["ownership"] != before.ownership
            || (s.record_id.is_none() && self.matching(s, &before.records).len() != 1)
        {
            return Err(self.error(
                "update",
                "RecordChanged",
                "Fresh snapshot differs from selected record/zone controls; no update occurred.",
                None,
            ));
        }
        self.selection(s, current)?;
        let ack = self
            .call(
                "update",
                "/v1/domain/resolve/edit",
                BTreeMap::new(),
                Some(self.payload(s, Some(r), ip)),
                true,
            )
            .await?;
        let after = self
            .snapshot(s)
            .await
            .map_err(|_| self.uncertain(ack.request_id.clone()))?;
        let found = after.records.iter().find(|x| x.id == r.id);
        let mut expected = r.extra["raw"].clone();
        expected["ttl"] = json!(s.ttl);
        expected["rdata"] = json!(ip.to_ascii_uppercase());
        let valid = found.is_some_and(|x| {
            let mut raw = x.extra["raw"].clone();
            raw["rdata"] = expected["rdata"].clone();
            self.verified(s, x, ip) && raw == expected
        });
        if !valid
            || before.ownership != after.ownership
            || !self.unchanged_others(&before.records, &after.records, &r.id)
        {
            return Err(self.uncertain(ack.request_id));
        }
        Ok(Mutation {
            record_id: r.id.clone(),
            request_id: ack.request_id.or(after.request_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::reconcile;
    use super::*;
    use axum::{
        Router,
        body::to_bytes,
        extract::{Request, State},
        http::StatusCode,
        response::{IntoResponse, Response},
    };
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    struct Mock {
        rows: Vec<Value>,
        calls: Vec<(String, Value)>,
        writes: usize,
        bad_zone: bool,
        stopped_zone: bool,
        foreign_dns: bool,
        error_status: Option<u16>,
        business_error: bool,
        echo_auth: bool,
        truncate: bool,
        duplicate: bool,
        foreign_link: bool,
        mutate_on_second_snapshot: bool,
        list_starts: usize,
        no_apply: bool,
        bad_ack: bool,
    }
    async fn handler(State(state): State<Arc<Mutex<Mock>>>, request: Request) -> Response {
        let path = request.uri().path().to_owned();
        let query = request.uri().query().unwrap_or("").to_owned();
        let auth = request
            .headers()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(auth.starts_with("bce-auth-v1/test-ak/"));
        let bytes = to_bytes(request.into_body(), 1024 * 1024).await.unwrap();
        let body: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        let mut m = state.lock().unwrap();
        m.calls.push((format!("{path}?{query}"), body.clone()));
        let reply = |status: u16, v: Value| {
            (
                StatusCode::from_u16(status).unwrap(),
                [("x-bce-request-id", "mock-request")],
                axum::Json(v),
            )
                .into_response()
        };
        if m.echo_auth {
            let sig = auth.rsplit('/').next().unwrap();
            return reply(
                403,
                json!({"code":"AccessDenied","message":format!("Denied token {auth} signature {sig} test-ak test-sk"),"requestId":sig}),
            );
        }
        if m.business_error || m.error_status.is_some() {
            return reply(
                m.error_status.unwrap_or(200),
                json!({"code":"AccessDenied","message":"Original policy denied for test-sk","requestId":"safe-business-id"}),
            );
        }
        if path == "/v2/domain" {
            assert!(!query.contains("domain="));
            let page = query
                .split('&')
                .find_map(|p| p.strip_prefix("pageNo="))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let result = if page == 1 {
                vec![
                    json!({"resourceId":if m.bad_zone{"wrong-zone"}else{"zone-1"},"domainName":"example.com","domain":"example.com","expireStatus":"NORMAL"}),
                ]
            } else {
                vec![]
            };
            return reply(200, json!({"totalCount":1,"result":result}));
        }
        if path == "/v1/domain/detail" {
            return reply(
                200,
                json!({"domain":"example.com","status":if m.stopped_zone{"PENDING"}else{"RUNNING"},"verifyStatus":"NORMAL","expireTime":"2099-01-01T00:00:00Z","dns":if m.foreign_dns{vec!["ns1.evil.test","ns2.evil.test"]}else{vec!["ns3.baidudns.xyz","ns4.baidudns.xyz"]}}),
            );
        }
        if path == "/v1/domain/resolve/list" {
            assert!(body.get("pageNum").is_none());
            assert_eq!(body.as_object().unwrap().len(), 3);
            let page = body["pageNo"].as_u64().unwrap() as usize;
            if page == 1 {
                m.list_starts += 1;
                if m.mutate_on_second_snapshot && m.list_starts == 2 {
                    m.rows[0]["rdata"] = json!("192.0.2.99");
                }
            }
            let start = (page - 1) * PAGE;
            let mut rows = m
                .rows
                .iter()
                .skip(start)
                .take(PAGE)
                .cloned()
                .collect::<Vec<_>>();
            if m.truncate && !rows.is_empty() {
                rows.pop();
            }
            if m.duplicate && page == 2 && !rows.is_empty() {
                rows[0] = m.rows[0].clone();
            }
            let mut v =
                json!({"totalCount":m.rows.len(),"pageNo":page,"pageSize":PAGE,"result":rows});
            if m.foreign_link {
                v["nextLink"] = json!("https://evil.test/steal");
            }
            return reply(200, v);
        }
        if matches!(
            path.as_str(),
            "/v1/domain/resolve/edit" | "/v1/domain/resolve/add"
        ) {
            m.writes += 1;
            assert_eq!(body["view"], "DEFAULT");
            if !m.no_apply {
                if path.ends_with("edit") {
                    let r = m
                        .rows
                        .iter_mut()
                        .find(|r| r["recordId"] == body["recordId"])
                        .unwrap();
                    assert_eq!(r["domain"], body["domain"]);
                    assert_eq!(r["view"], body["view"]);
                    assert_eq!(r["zoneName"], body["zoneName"]);
                    r["ttl"] = body["ttl"].clone();
                    r["rdata"] = body["rdata"].clone();
                    r["rdtype"] = body["rdType"].clone();
                } else {
                    m.rows.push(json!({"recordId":950,"domain":body["domain"],"view":body["view"],"zoneName":body["zoneName"],"ttl":body["ttl"],"rdata":body["rdata"],"rdtype":body["rdType"],"status":"RUNNING"}));
                }
            }
            if m.bad_ack {
                return reply(200, json!({"success":true}));
            }
            return (StatusCode::OK, [("x-bce-request-id", "mock-write")], "").into_response();
        }
        panic!("unexpected mock route");
    }
    async fn setup(mock: Mock) -> (BaiduCloud, Arc<Mutex<Mock>>, tokio::task::JoinHandle<()>) {
        let state = Arc::new(Mutex::new(mock));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(handler).with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut adapter = BaiduCloud::new(
            client,
            "test-ak".into(),
            "test-sk".into(),
            &BTreeMap::from([("resource_id".into(), "zone-1".into())]),
        );
        adapter.endpoint = endpoint;
        (adapter, state, task)
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
    fn raw(id: usize) -> Value {
        json!({"recordId":id,"domain":"home","zoneName":"example.com","rdtype":"A","rdata":"192.0.2.1","ttl":600,"view":"DEFAULT","status":"RUNNING"})
    }
    #[test]
    fn independent_python_hmac_golden() {
        // Python stdlib hmac.new(...,hashlib.sha256).hexdigest(); second HMAC
        // uses ASCII HEX derived key (not decoded bytes), as BCE specifies.
        for (method, path, q, want) in [
            (
                "POST",
                "/v1/domain/resolve/edit",
                BTreeMap::new(),
                "29ff62360cf891ec878c9942d63f040973affe67842bae47a1cf4e3183f3538e",
            ),
            (
                "GET",
                "/v1/domain/detail",
                BTreeMap::from([("domain".into(), "example.com".into())]),
                "2f6b7652b18b420e36540d520fe039703374889506a8aa965e471191a756ecf1",
            ),
            (
                "GET",
                "/v2/domain",
                BTreeMap::from([
                    ("pageNo".into(), "2".into()),
                    ("pageSize".into(), "100".into()),
                ]),
                "c77ce540253d30686b02d173eb5df8e298f7aa33fd43b40147df619e9586b6a6",
            ),
        ] {
            let (auth, sig, key) = authorization(
                "test-ak",
                "test-sk",
                "2026-01-02T03:04:05Z",
                method,
                path,
                &q,
            );
            assert_eq!(
                key,
                "ddda74b2bc4620f1bcc3d95b5d1810c0d5af9f92547d3b0e71a6b3667e05b058"
            );
            assert_eq!(sig, want);
            assert_eq!(
                auth,
                format!("bce-auth-v1/test-ak/2026-01-02T03:04:05Z/1800/host/{want}")
            );
        }
        assert_eq!(encode("a b/+~中文"), "a%20b%2F%2B~%E4%B8%AD%E6%96%87");
    }
    #[tokio::test]
    async fn unchanged_dryrun_update_and_empty_ack_readback() {
        let (a, m, t) = setup(Mock {
            rows: vec![raw(950)],
            ..Default::default()
        })
        .await;
        assert_eq!(
            reconcile(&a, &spec(), "192.0.2.1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert_eq!(
            reconcile(&a, &spec(), "192.0.2.2", true)
                .await
                .unwrap()
                .status,
            "would_update"
        );
        assert_eq!(m.lock().unwrap().writes, 0);
        let out = reconcile(&a, &spec(), "192.0.2.2", false).await.unwrap();
        assert_eq!(out.status, "updated");
        assert_eq!(out.record_id.as_deref(), Some("950"));
        assert_eq!(out.request_id.as_deref(), Some("mock-write"));
        assert_eq!(m.lock().unwrap().writes, 1);
        t.abort();
    }
    #[tokio::test]
    async fn create_optin_full_absence_and_ipv6_uppercase() {
        let (a, m, t) = setup(Mock::default()).await;
        let mut s = spec();
        assert_eq!(
            reconcile(&a, &s, "192.0.2.2", true).await.unwrap_err().code,
            "RecordNotFound"
        );
        s.create_if_missing = true;
        s.record_type = "AAAA".into();
        assert_eq!(
            reconcile(&a, &s, "2001:db8::ab", true)
                .await
                .unwrap()
                .status,
            "would_create"
        );
        assert_eq!(m.lock().unwrap().writes, 0);
        assert_eq!(
            reconcile(&a, &s, "2001:db8::ab", false)
                .await
                .unwrap()
                .status,
            "created"
        );
        assert_eq!(m.lock().unwrap().rows[0]["rdata"], "2001:DB8::AB");
        t.abort();
    }
    #[tokio::test]
    async fn unsafe_selection_rejected_even_unchanged_and_dryrun() {
        for (field, value, code) in [
            ("status", json!("STOPPED"), "UnsafeRecordSelection"),
            ("weight", json!(10), "UnsupportedRecordMetadata"),
            ("remark", json!("keep me"), "UnsupportedRecordMetadata"),
        ] {
            let mut r = raw(950);
            r[field] = value;
            let (a, m, t) = setup(Mock {
                rows: vec![r],
                ..Default::default()
            })
            .await;
            for dry in [true, false] {
                assert_eq!(
                    reconcile(&a, &spec(), "192.0.2.1", dry)
                        .await
                        .unwrap_err()
                        .code,
                    code
                );
            }
            assert_eq!(m.lock().unwrap().writes, 0);
            t.abort();
        }
        let (a, m, t) = setup(Mock {
            rows: vec![raw(950), raw(951)],
            ..Default::default()
        })
        .await;
        assert_eq!(
            reconcile(&a, &spec(), "192.0.2.1", true)
                .await
                .unwrap_err()
                .code,
            "AmbiguousRecords"
        );
        let mut s = spec();
        s.record_id = Some("999".into());
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&a, &s, "192.0.2.1", true).await.unwrap_err().code,
            "RecordIdNotFound"
        );
        s.record_id = Some("950".into());
        assert_eq!(
            reconcile(&a, &s, "192.0.2.2", false).await.unwrap().status,
            "updated"
        );
        assert_eq!(m.lock().unwrap().rows[1]["rdata"], "192.0.2.1");
        t.abort();
    }
    #[tokio::test]
    async fn cross_line_cname_and_ancestor_ns_block_every_outcome() {
        for (name, rt, code) in [
            ("home", "CNAME", "CnameConflict"),
            ("home", "NS", "DelegatedTarget"),
        ] {
            let mut r = raw(951);
            r["domain"] = json!(name);
            r["rdtype"] = json!(rt);
            r["view"] = json!("CNC");
            r["status"] = json!("STOPPED");
            let (a, m, t) = setup(Mock {
                rows: vec![raw(950), r],
                ..Default::default()
            })
            .await;
            assert_eq!(
                reconcile(&a, &spec(), "192.0.2.1", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_eq!(m.lock().unwrap().writes, 0);
            t.abort();
        }
        let mut ns = raw(951);
        ns["domain"] = json!("branch");
        ns["rdtype"] = json!("NS");
        let (a, m, t) = setup(Mock {
            rows: vec![ns],
            ..Default::default()
        })
        .await;
        let mut s = spec();
        s.subdomain = "home.branch".into();
        s.create_if_missing = true;
        assert_eq!(
            reconcile(&a, &s, "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "DelegatedTarget"
        );
        assert_eq!(m.lock().unwrap().writes, 0);
        t.abort();
    }
    #[tokio::test]
    async fn full_unfiltered_pages_and_truncation_duplicate_foreign_links() {
        let rows = (1..=101)
            .map(|id| {
                let mut r = raw(id);
                r["domain"] = json!(format!("host{id}"));
                r
            })
            .collect::<Vec<_>>();
        let (a, m, t) = setup(Mock {
            rows: rows.clone(),
            ..Default::default()
        })
        .await;
        assert_eq!(a.list(&spec()).await.unwrap().records.len(), 101);
        assert_eq!(
            m.lock()
                .unwrap()
                .calls
                .iter()
                .filter(|(p, _)| p.starts_with("/v1/domain/resolve/list"))
                .count(),
            3
        );
        t.abort();
        for mode in 0..3 {
            let (a, m, t) = setup(Mock {
                rows: rows.clone(),
                truncate: mode == 0,
                duplicate: mode == 1,
                foreign_link: mode == 2,
                ..Default::default()
            })
            .await;
            assert!(a.list(&spec()).await.is_err());
            assert_eq!(m.lock().unwrap().writes, 0);
            t.abort();
        }
    }
    #[tokio::test]
    async fn exact_owned_active_zone_and_dns_proof() {
        for mode in 0..3 {
            let (a, m, t) = setup(Mock {
                rows: vec![raw(950)],
                bad_zone: mode == 0,
                stopped_zone: mode == 1,
                foreign_dns: mode == 2,
                ..Default::default()
            })
            .await;
            assert!(reconcile(&a, &spec(), "192.0.2.1", true).await.is_err());
            assert_eq!(m.lock().unwrap().writes, 0);
            t.abort();
        }
    }
    #[tokio::test]
    async fn changed_prewrite_and_uncertain_readback_never_retry() {
        let (a, m, t) = setup(Mock {
            rows: vec![raw(950)],
            mutate_on_second_snapshot: true,
            ..Default::default()
        })
        .await;
        assert_eq!(
            reconcile(&a, &spec(), "192.0.2.2", false)
                .await
                .unwrap_err()
                .code,
            "RecordChanged"
        );
        assert_eq!(m.lock().unwrap().writes, 0);
        t.abort();
        for bad_ack in [false, true] {
            let (a, m, t) = setup(Mock {
                rows: vec![raw(950)],
                no_apply: true,
                bad_ack,
                ..Default::default()
            })
            .await;
            assert_eq!(
                reconcile(&a, &spec(), "192.0.2.2", false)
                    .await
                    .unwrap_err()
                    .code,
                if bad_ack {
                    "InvalidWriteAcknowledgement"
                } else {
                    "WriteNotVerified"
                }
            );
            assert_eq!(m.lock().unwrap().writes, 1);
            t.abort();
        }
    }
    #[tokio::test]
    async fn original_business_errors_and_generated_auth_are_sanitized() {
        for status in [200, 403, 429, 500] {
            let (a, _, t) = setup(Mock {
                business_error: true,
                error_status: Some(status),
                ..Default::default()
            })
            .await;
            let e = a.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "AccessDenied");
            assert_eq!(e.http_status, Some(status));
            assert!(e.message.contains("Original policy denied"));
            assert!(!e.message.contains("test-sk"));
            assert_eq!(e.request_id.as_deref(), Some("safe-business-id"));
            assert!(!e.retryable);
            t.abort();
        }
        let (a, _, t) = setup(Mock {
            echo_auth: true,
            ..Default::default()
        })
        .await;
        let e = a.list(&spec()).await.unwrap_err();
        let text = format!("{e:?}");
        assert!(!text.contains("test-ak"));
        assert!(!text.contains("test-sk"));
        assert!(!text.contains("bce-auth-v1/"));
        assert_eq!(e.request_id.as_deref(), Some("mock-request"));
        t.abort();
    }
    #[tokio::test]
    async fn invalid_settings_do_not_make_requests() {
        let (a, m, t) = setup(Mock::default()).await;
        for id in [".", "..", "a/b", "0", "01", "-1"] {
            let mut s = spec();
            s.record_id = Some(id.into());
            assert_eq!(a.list(&s).await.unwrap_err().code, "InvalidRecordId");
        }
        for ttl in [0, 59, 3601] {
            let mut s = spec();
            s.ttl = ttl;
            assert!(a.list(&s).await.is_err());
        }
        for l in ["", "*", "ALL", "default-route"] {
            let mut s = spec();
            s.record_line = l.into();
            assert!(a.list(&s).await.is_err());
        }
        let mut s = spec();
        s.options.insert("min_ttl".into(), "60".into());
        assert_eq!(a.list(&s).await.unwrap_err().code, "UnsupportedOptions");
        assert!(m.lock().unwrap().calls.is_empty());
        t.abort();
    }
}
