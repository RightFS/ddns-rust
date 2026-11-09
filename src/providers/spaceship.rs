//! Spaceship official OpenAPI, inspected 2026-11-09:
//! https://docs.spaceship.dev/#tag/DNS-records/operation/saveRecords
//! https://docs.spaceship.dev/#tag/DNS-records/operation/deleteRecords
//! https://docs.spaceship.dev/#tag/DNS-records/operation/getResourceRecordsList
//! https://docs.spaceship.dev/#tag/Domain-Management/operation/getDomainInfo
//! PUT adds a custom value or changes its TTL, NOT an address replacement.
//! IP updates add-before-delete, verifying complete state between operations.
//! DELETE names only the old value; force is always false. No RRset-wide edits.
//! Only singleton custom A/AAAA RRsets are mutable. Synthetic rrset IDs are
//! SHA256(domain, relative host, type), NOT provider record IDs. Multi-value
//! member IDs are diagnostic only; selecting them explicitly is still refused.
//! No CAS exists: races after the final read remain possible. Partial updates
//! remain additive (both IPs), are reported uncertain, and never auto-retried.
//! Requires domains:read,dnsrecords:read,dnsrecords:write. Domain detail allows
//! only 5 requests/domain/300s; an IP change makes four detail reads. Use >=300s.
//! Parent must disable redirects. No production endpoint override/options.
#![allow(clippy::result_large_err)]
use super::common::{self, Adapter, Api, HttpReply, List, Mutation, Record, Spec};
use crate::provider::ProviderError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
};
const ENDPOINT: &str = "https://spaceship.dev/api/v1";
const PAGE_SIZE: usize = 100; // Request allows 500, response schema maxItems=100.
const LIMIT: usize = 10000;
pub struct Spaceship {
    api: Api,
    id: String,
    key: String,
    options_valid: bool,
    #[cfg(test)]
    endpoint: String,
}
impl Spaceship {
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
            options_valid: options.is_empty(),
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
        self.api.error(stage,code,message,"Check Spaceship API key/secret and domains:read,dnsrecords:read,dnsrecords:write scopes, exact domain/basic nameservers and API schema. Inspect uncertain or partially completed updates before retrying; no write is automatically retried.",reply)
    }
    fn validate(&self, s: &Spec) -> Result<(), ProviderError> {
        if [&self.id, &self.key]
            .iter()
            .any(|v| v.is_empty() || !v.bytes().all(|b| (0x21..=0x7e).contains(&b)))
        {
            return Err(self.error("validation","InvalidCredentials","Spaceship requires an API key and API secret containing printable ASCII without whitespace.",None));
        }
        if !self.options_valid
            || !s.options.is_empty()
            || !matches!(s.record_line.as_str(), "默认" | "default")
        {
            return Err(self.error("validation","UnsupportedOptions","Spaceship has no adapter/record options or routing-line controls; use the default line.",None));
        }
        if !hostname(&s.domain)
            || !s.domain.contains('.')
            || (s.subdomain != "@" && !hostname(&s.subdomain))
            || s.fqdn().len() > 253
        {
            return Err(self.error(
                "validation",
                "InvalidZoneName",
                "Use an exact ASCII/punycode domain and plain relative host (or @).",
                None,
            ));
        }
        if !matches!(s.record_type.as_str(), "A" | "AAAA") {
            return Err(self.error(
                "validation",
                "UnsupportedRecordType",
                "Only A and AAAA are supported.",
                None,
            ));
        }
        if !(60..=3600).contains(&s.ttl) {
            return Err(self.error("validation","UnsupportedTTL","Spaceship documents TTL60..3600 seconds; invalid TTL is refused, also during dry-run.",None));
        }
        Ok(())
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        #[cfg(test)]
        let endpoint = &self.endpoint;
        #[cfg(not(test))]
        let endpoint = ENDPOINT;
        let mut id = reqwest::header::HeaderValue::from_str(&self.id).expect("validated API key");
        id.set_sensitive(true);
        let mut key =
            reqwest::header::HeaderValue::from_str(&self.key).expect("validated API secret");
        key.set_sensitive(true);
        self.api
            .client
            .request(method, format!("{endpoint}{path}"))
            .header("x-api-key", id)
            .header("x-api-secret", key)
    }
    async fn call(
        &self,
        stage: &str,
        request: reqwest::RequestBuilder,
        write: bool,
    ) -> Result<HttpReply, ProviderError> {
        let mut r = self.api.send(stage, request, write).await?;
        if let Some(id) = r
            .headers
            .get("spaceship-operation-id")
            .and_then(|v| v.to_str().ok())
            .map(|v| self.api.safe(v))
            .filter(|v| common::valid_trace_id(v))
        {
            r.request_id = Some(id);
        }
        let business = r
            .headers
            .get("spaceship-error-code")
            .and_then(|v| v.to_str().ok());
        if !(200..300).contains(&r.status) || business.is_some() || r.body.get("detail").is_some() {
            let code = business
                .map(str::to_owned)
                .unwrap_or_else(|| format!("Http{}", r.status));
            let mut message = r
                .body
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("Spaceship returned an API error without string detail.")
                .to_owned();
            if let Some(data) = r.body.get("data").and_then(Value::as_array) {
                for item in data.iter().take(20) {
                    if let (Some(field), Some(detail)) = (
                        item.get("field").and_then(Value::as_str),
                        item.get("details").and_then(Value::as_str),
                    ) {
                        message.push_str(&format!("; {field}: {detail}"));
                    }
                }
            }
            return Err(self.error(stage, &code, &message, Some(&r)));
        }
        if write {
            if r.status != 204
                || !r.body.is_null()
                || r.headers.contains_key("spaceship-async-operationid")
            {
                return Err(self.error(stage,"InvalidWriteAcknowledgement","Spaceship DNS writes require documented synchronous HTTP204 with no content; previews/async/arbitrary success bodies are uncertain.",Some(&r)));
            }
        } else if r.status != 200 {
            return Err(self.error(
                stage,
                "InvalidReadAcknowledgement",
                "Spaceship reads require HTTP200 JSON.",
                Some(&r),
            ));
        }
        Ok(r)
    }
    async fn ownership(&self, s: &Spec) -> Result<(), ProviderError> {
        let r = self
            .call(
                "ownership",
                self.request(reqwest::Method::GET, &format!("/domains/{}", s.domain)),
                false,
            )
            .await?;
        let d = &r.body;
        if !d["name"]
            .as_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(&s.domain))
        {
            return Err(self.error(
                "ownership",
                "ZoneMismatch",
                "Spaceship domain info did not identify the exact configured domain.",
                Some(&r),
            ));
        }
        if d["lifecycleStatus"].as_str() != Some("registered")
            || !matches!(d.get("verificationStatus"), Some(Value::Null))
                && d["verificationStatus"].as_str() != Some("success")
            || d["suspensions"].as_array().is_none_or(|a| !a.is_empty())
        {
            return Err(self.error("ownership","UnsafeDomainState","Spaceship domain must be registered, verified (success or documented null), and have an explicit empty suspensions array.",Some(&r)));
        }
        let epp = d["eppStatuses"].as_array().ok_or_else(|| {
            self.error(
                "ownership",
                "UnknownDomainState",
                "Spaceship domain lacks documented eppStatuses array.",
                Some(&r),
            )
        })?;
        if epp.iter().any(|v| {
            !matches!(
                v.as_str(),
                Some(
                    "clientDeleteProhibited" | "clientRenewProhibited" | "clientTransferProhibited"
                )
            )
        }) {
            return Err(self.error("ownership","UnsafeDomainState","Spaceship domain has hold/update-prohibited or unknown EPP status; mutation is refused.",Some(&r)));
        }
        if d["nameservers"]["provider"].as_str() != Some("basic")
            || d["nameservers"]["hosts"].as_array().is_none_or(|a| {
                !(2..=12).contains(&a.len()) || a.iter().any(|v| !v.as_str().is_some_and(hostname))
            })
        {
            return Err(self.error("ownership","NonAuthoritativeZone","Spaceship basic nameserver provider and actual valid nameserver hosts are required; custom/missing delegation is refused.",Some(&r)));
        }
        Ok(())
    }
    fn selection(&self, s: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.validate(s)?;
        let Some(r) = r else {
            return Ok(());
        };
        if r.extra["members"].as_u64() != Some(1) {
            return Err(self.error("selection","MultiValueRRset","Spaceship adapter only mutates singleton RRsets; selecting a synthetic member ID does not authorize changing other values.",None));
        }
        let raw = &r.extra["raw"];
        if raw["group"]["type"].as_str() != Some("custom")
            || raw["group"].as_object().is_none_or(|o| o.len() != 1)
        {
            return Err(self.error(
                "selection",
                "ManagedRecord",
                "Spaceship product/personalNs/unknown record groups are not custom DDNS targets.",
                None,
            ));
        }
        if raw.as_object().is_none_or(|o| {
            o.keys()
                .any(|k| !matches!(k.as_str(), "type" | "name" | "address" | "ttl" | "group"))
        }) {
            return Err(self.error("selection","UnsafeRecordMetadata","Selected Spaceship A/AAAA contains undocumented state/settings; disabling or routing metadata cannot safely be synthesized or discarded.",None));
        }
        if raw["ttl"].as_u64() != Some(r.ttl) || !(60..=3600).contains(&r.ttl) || !r.enabled {
            return Err(self.error(
                "selection",
                "UnsafeRecordMetadata",
                "Selected Spaceship record lacks actual valid TTL/enabled custom state.",
                None,
            ));
        }
        if r.value
            .parse::<IpAddr>()
            .ok()
            .is_none_or(|ip| ip.is_ipv4() != (r.record_type == "A"))
        {
            return Err(self.error(
                "selection",
                "InvalidRecordValue",
                "Existing Spaceship A/AAAA must have a plain IP of the correct family.",
                None,
            ));
        }
        Ok(())
    }
    async fn snapshot(&self, s: &Spec) -> Result<List, ProviderError> {
        self.validate(s)?;
        self.ownership(s).await?;
        let mut all = Vec::new();
        let mut total = None;
        let mut duplicates = HashSet::new();
        let mut trace = None;
        for skip in (0..=LIMIT).step_by(PAGE_SIZE) {
            let r = self
                .call(
                    "list",
                    self.request(reqwest::Method::GET, &format!("/dns/records/{}", s.domain))
                        .query(&[("take", PAGE_SIZE), ("skip", skip)]),
                    false,
                )
                .await?;
            trace = r.request_id.clone();
            let n = r.body["total"]
                .as_u64()
                .filter(|n| *n <= LIMIT as u64)
                .ok_or_else(|| {
                    self.error(
                        "list",
                        "IncompletePagination",
                        "Spaceship total is missing/invalid or exceeds10000; no partial selection.",
                        Some(&r),
                    )
                })? as usize;
            let items = r.body["items"].as_array().ok_or_else(|| {
                self.error(
                    "list",
                    "MalformedRecordList",
                    "Spaceship items array is missing/invalid.",
                    Some(&r),
                )
            })?;
            if total.is_some_and(|t| t != n)
                || items.len() != PAGE_SIZE.min(n.saturating_sub(all.len()))
                || all.len() + items.len() > n
            {
                return Err(self.error("list","IncompletePagination","Spaceship total changed or a page is short/oversized/truncated; no partial list is selected.",Some(&r)));
            }
            total = Some(n);
            for raw in items {
                if !raw["name"].as_str().is_some_and(record_name)
                    || !raw["type"].as_str().is_some_and(|t| {
                        !t.is_empty()
                            && t.len() <= 5
                            && t.bytes().all(|b| b.is_ascii_alphanumeric())
                    })
                    || raw["group"]["type"].as_str().is_none()
                {
                    return Err(self.error(
                        "list",
                        "MalformedRecord",
                        "Spaceship record requires actual relative name/type/group.",
                        Some(&r),
                    ));
                }
                if !duplicates.insert(raw.to_string()) {
                    return Err(self.error(
                        "list",
                        "UnstableRecordList",
                        "Spaceship returned repeated identical records; pagination stopped.",
                        Some(&r),
                    ));
                }
                all.push(raw.clone());
            }
            if all.len() == n {
                break;
            }
        }
        let mut counts = BTreeMap::new();
        for raw in &all {
            let key = (
                raw["name"].as_str().unwrap().to_ascii_lowercase(),
                raw["type"].as_str().unwrap().to_ascii_uppercase(),
            );
            *counts.entry(key).or_insert(0usize) += 1;
        }
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        for raw in all {
            let name = raw["name"].as_str().unwrap().to_owned();
            let ty = raw["type"].as_str().unwrap().to_ascii_uppercase();
            if name.eq_ignore_ascii_case(&s.subdomain) && matches!(ty.as_str(), "CNAME" | "ALIAS")
                || ty == "NS"
                    && name != "@"
                    && (s.subdomain.eq_ignore_ascii_case(&name)
                        || s.subdomain
                            .to_ascii_lowercase()
                            .ends_with(&format!(".{}", name.to_ascii_lowercase())))
            {
                return Err(self.error("selection","ConflictingOrDelegatedHost","Spaceship target has CNAME/ALIAS or lies beneath a delegated child NS; this zone is not a safe A/AAAA target.",None));
            }
            let members = counts[&(name.to_ascii_lowercase(), ty.clone())];
            let id = identity(
                &s.domain,
                &name,
                &ty,
                if members == 1 { None } else { Some(&raw) },
            );
            if !seen.insert(id.clone()) {
                return Err(self.error(
                    "list",
                    "UnstableRecordList",
                    "Spaceship duplicate semantic member identities were returned.",
                    None,
                ));
            }
            let ttl = raw["ttl"].as_u64().unwrap_or(0); // Missing TTL retained as unknown; selected targets refuse it.
            let value = if matches!(ty.as_str(), "A" | "AAAA") {
                raw["address"]
                    .as_str()
                    .ok_or_else(|| {
                        self.error(
                            "list",
                            "MalformedRecord",
                            "Spaceship A/AAAA lacks string address.",
                            None,
                        )
                    })?
                    .to_owned()
            } else {
                String::new()
            };
            records.push(Record {
                id,
                name,
                record_type: ty,
                value,
                ttl,
                line: String::new(),
                enabled: raw["group"]["type"].as_str() == Some("custom"),
                extra: json!({"raw":raw,"members":members}),
            });
        }
        Ok(List {
            records,
            request_id: trace,
        })
    }
    async fn write(
        &self,
        s: &Spec,
        r: Option<&Record>,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        self.selection(s, r)?;
        if r.is_none() && (!s.create_if_missing || s.record_id.is_some()) {
            return Err(self.error(
                "create",
                "UnsafeCreate",
                "Creation requires explicit create_if_missing=true and no record_id.",
                None,
            ));
        }
        let ip: IpAddr = ip.parse().map_err(|_| {
            self.error(
                "validation",
                "InvalidIp",
                "Desired value must be a plain IP address.",
                None,
            )
        })?;
        if ip.is_ipv4() != (s.record_type == "A") {
            return Err(self.error(
                "validation",
                "IpFamilyMismatch",
                "IP family differs from A/AAAA type.",
                None,
            ));
        }
        let stage = if r.is_some() { "update" } else { "create" };
        let before = self.snapshot(s).await?;
        let matches: Vec<_> = before
            .records
            .iter()
            .filter(|v| v.name.eq_ignore_ascii_case(&s.subdomain) && v.record_type == s.record_type)
            .collect();
        if let Some(r) = r {
            if matches.len() != 1
                || matches[0].id != r.id
                || matches[0].extra != r.extra
                || matches[0].value != r.value
                || !r.name.eq_ignore_ascii_case(&s.subdomain)
                || r.record_type != s.record_type
            {
                return Err(self.error(stage,"StaleRecord","Spaceship complete pre-write reread differs from selected singleton record; no mutation occurred.",None));
            }
            self.selection(s, Some(matches[0]))?;
        } else if !matches.is_empty() {
            return Err(self.error(stage,"CreateRace","Spaceship target appeared in pre-write reread; creation is refused without fallback update.",None));
        }
        let name = r.map(|r| r.name.as_str()).unwrap_or(&s.subdomain);
        let address = r
            .filter(|r| r.value.parse::<IpAddr>().ok() == Some(ip))
            .map(|r| r.value.clone())
            .unwrap_or_else(|| ip.to_string());
        let item = json!({"type":s.record_type,"name":name,"address":address,"ttl":s.ttl});
        let put = self
            .call(
                stage,
                self.request(reqwest::Method::PUT, &format!("/dns/records/{}", s.domain))
                    .json(&json!({"force":false,"items":[item]})),
                true,
            )
            .await?;
        let added = self
            .snapshot(s)
            .await
            .map_err(|e| self.uncertain(stage, "AfterAddReadFailed", &e, &put))?;
        let old_ip = r.and_then(|r| r.value.parse::<IpAddr>().ok());
        let changed = r.is_some() && old_ip != Some(ip);
        let expected = if changed { 2 } else { 1 };
        let targets: Vec<_> = added
            .records
            .iter()
            .filter(|v| v.name.eq_ignore_ascii_case(&s.subdomain) && v.record_type == s.record_type)
            .collect();
        let wanted = targets
            .iter()
            .find(|v| v.value.parse::<IpAddr>().ok() == Some(ip));
        let custom = |v: &Record| {
            v.extra["raw"]["group"] == json!({"type":"custom"})
                && v.extra["raw"].as_object().is_some_and(|o| {
                    o.keys().all(|k| {
                        matches!(k.as_str(), "type" | "name" | "address" | "ttl" | "group")
                    })
                })
        };
        let old_present = !changed
            || targets.iter().any(|v| {
                Some(v.value.parse::<IpAddr>().ok()) == Some(old_ip)
                    && r.is_some_and(|r| v.extra["raw"] == r.extra["raw"])
            });
        let unrelated = |list: &List| -> BTreeMap<String, String> {
            list.records
                .iter()
                .filter(|v| {
                    !v.name.eq_ignore_ascii_case(&s.subdomain) || v.record_type != s.record_type
                })
                .map(|v| (v.id.clone(), v.extra["raw"].to_string()))
                .collect()
        };
        if targets.len() != expected
            || wanted.is_none_or(|v| v.ttl != s.ttl || !custom(v))
            || !old_present
            || targets.iter().any(|v| !custom(v))
            || unrelated(&before) != unrelated(&added)
        {
            return Err(self.error(stage,"UnverifiedAdd","Spaceship accepted PUT but complete reread did not confirm only the intended addition/TTL change with old and unrelated values preserved. No delete occurred; inspect partial state.",Some(&put)));
        }
        let mut trace = put.request_id;
        if changed {
            let old = r.unwrap();
            let delete=self.call("delete",self.request(reqwest::Method::DELETE,&format!("/dns/records/{}",s.domain)).json(&json!([{"type":old.record_type,"name":old.name,"address":old.value}])),true).await.map_err(|mut e| {e.stage=stage.into();e.message=self.api.safe(&format!("Spaceship new IP was added and verified; exact old-value deletion failed: {}. Both IPs may remain; inspect partial state before retrying.",e.message));e.retryable=false;e})?;
            let final_list = self
                .snapshot(s)
                .await
                .map_err(|e| self.uncertain(stage, "AfterDeleteReadFailed", &e, &delete))?;
            let targets: Vec<_> = final_list
                .records
                .iter()
                .filter(|v| {
                    v.name.eq_ignore_ascii_case(&s.subdomain) && v.record_type == s.record_type
                })
                .collect();
            if targets.len() != 1
                || targets[0].value.parse::<IpAddr>().ok() != Some(ip)
                || targets[0].ttl != s.ttl
                || !custom(targets[0])
                || unrelated(&before) != unrelated(&final_list)
            {
                return Err(self.error(stage,"UnverifiedDelete","Spaceship accepted exact old-value DELETE but final singleton/IP/TTL/custom state or unrelated records were not preserved; inspect uncertain result.",Some(&delete)));
            }
            trace = delete.request_id.or(trace);
        }
        Ok(Mutation {
            record_id: identity(&s.domain, &s.subdomain, &s.record_type, None),
            request_id: trace,
        })
    }
    fn uncertain(
        &self,
        stage: &str,
        code: &str,
        e: &ProviderError,
        ack: &HttpReply,
    ) -> ProviderError {
        self.error(stage,code,&format!("Spaceship write accepted but verification failed at {} ({}; HTTP {:?}; trace {:?}): {}. Result uncertain; no retry occurred.",e.stage,e.code,e.http_status,e.request_id,e.message),Some(ack))
    }
}
impl Adapter for Spaceship {
    fn name_format(&self) -> super::common::NameFormat {
        super::common::NameFormat::Relative
    }
    fn validate_selection(&self, s: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.selection(s, r)
    }
    async fn list(&self, s: &Spec) -> Result<List, ProviderError> {
        self.snapshot(s).await
    }
    async fn create(&self, s: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.write(s, None, ip).await
    }
    async fn update(&self, s: &Spec, r: &Record, ip: &str) -> Result<Mutation, ProviderError> {
        self.write(s, Some(r), ip).await
    }
}
fn identity(domain: &str, name: &str, ty: &str, member: Option<&Value>) -> String {
    let material = json!([
        domain.to_ascii_lowercase(),
        name.to_ascii_lowercase(),
        ty.to_ascii_uppercase(),
        member
    ]);
    format!(
        "{}-{}",
        if member.is_some() { "member" } else { "rrset" },
        hex::encode(Sha256::digest(material.to_string().as_bytes()))
    )
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
        || !s.is_empty()
            && s.len() <= 253
            && s.split('.').enumerate().all(|(i, l)| {
                (i == 0 && matches!(l, "*" | "_"))
                    || (!l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().any(|b| b.is_ascii_alphanumeric())
                        && l.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')))
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, Method, StatusCode, Uri},
        routing::any,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    struct Reply {
        status: StatusCode,
        body: String,
        error: Option<String>,
    }
    #[derive(Clone)]
    struct Capture {
        method: Method,
        uri: String,
        headers: HeaderMap,
        body: Value,
    }
    type Captures = Arc<Mutex<Vec<Capture>>>;
    #[derive(Clone)]
    struct StateData {
        replies: Arc<Mutex<VecDeque<Reply>>>,
        captures: Captures,
    }
    struct Mock {
        provider: Spaceship,
        captures: Captures,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(
        State(s): State<StateData>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, HeaderMap, String) {
        s.captures.lock().unwrap().push(Capture {
            method,
            uri: uri.to_string(),
            headers,
            body: if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            },
        });
        let r = s
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| read(json!({"detail":"Unexpected request"})));
        let mut headers = HeaderMap::new();
        headers.insert("spaceship-operation-id", "spaceship-trace".parse().unwrap());
        if let Some(error) = r.error {
            headers.insert("spaceship-error-code", error.parse().unwrap());
        }
        (r.status, headers, r.body)
    }
    async fn mock(replies: Vec<Reply>) -> Mock {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let state = StateData {
            replies: Arc::new(Mutex::new(replies.into())),
            captures: captures.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/{*path}", any(handler))
                    .with_state(state),
            )
            .await
            .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap();
        let mut provider = Spaceship::new(
            client,
            "test-spaceship-id".into(),
            "test-spaceship-secret".into(),
            &BTreeMap::new(),
        );
        provider.endpoint = endpoint;
        Mock {
            provider,
            captures,
            task,
        }
    }
    fn read(v: Value) -> Reply {
        Reply {
            status: StatusCode::OK,
            body: v.to_string(),
            error: None,
        }
    }
    fn ack() -> Reply {
        Reply {
            status: StatusCode::NO_CONTENT,
            body: String::new(),
            error: None,
        }
    }
    fn owned() -> Value {
        json!({"name":"Example.COM","lifecycleStatus":"registered","verificationStatus":"success","eppStatuses":["clientTransferProhibited"],"suspensions":[],"nameservers":{"provider":"basic","hosts":["launch1.spaceship.net","launch2.spaceship.net"]}})
    }
    fn raw(host: &str, ip: &str) -> Value {
        json!({"type":"A","name":host,"address":ip,"ttl":600,"group":{"type":"custom"}})
    }
    fn page(total: usize, items: Vec<Value>) -> Value {
        json!({"total":total,"items":items})
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
    fn assert_reads(m: &Mock) {
        assert!(
            m.captures
                .lock()
                .unwrap()
                .iter()
                .all(|c| c.method == Method::GET)
        );
    }
    fn stable(r: Value) -> Vec<Reply> {
        vec![
            read(owned()),
            read(page(1, vec![r.clone()])),
            read(owned()),
            read(page(1, vec![r])),
        ]
    }
    #[tokio::test]
    async fn complete_domain_record_reads_auth_and_stable_synthetic_id() {
        let r = raw("HOME", "1.1.1.1");
        let m = mock(vec![read(owned()), read(page(1, vec![r.clone()]))]).await;
        let list = m.provider.list(&spec()).await.unwrap();
        assert_eq!(
            list.records[0].id,
            identity("example.com", "home", "A", None)
        );
        assert!(list.records[0].id.starts_with("rrset-"));
        assert_eq!(list.records[0].ttl, 600);
        assert_eq!(list.request_id.as_deref(), Some("spaceship-trace"));
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls[0].uri, "/domains/example.com");
        assert_eq!(calls[1].uri, "/dns/records/example.com?take=100&skip=0");
        for c in calls.iter() {
            assert_eq!(c.headers["x-api-key"], "test-spaceship-id");
            assert_eq!(c.headers["x-api-secret"], "test-spaceship-secret");
            assert!(!c.uri.contains("test-spaceship"));
            assert!(!c.body.to_string().contains("test-spaceship"));
        }
        let req = m
            .provider
            .request(reqwest::Method::GET, "/domains/example.com")
            .build()
            .unwrap();
        assert!(req.headers()["x-api-key"].is_sensitive());
        assert!(req.headers()["x-api-secret"].is_sensitive());
        let mut r2 = r;
        r2["address"] = json!("8.8.8.8");
        assert_eq!(
            identity("Example.COM", "HOME", "a", None),
            list.records[0].id
        );
    }
    #[tokio::test]
    async fn pagination_exhausts_1001_records_and_last_page_selection() {
        let mut replies = vec![read(owned())];
        for start in (0..1001).step_by(100) {
            replies.push(read(page(
                1001,
                (start..(start + 100).min(1001))
                    .map(|n| {
                        let name = if n == 1000 {
                            "home".to_owned()
                        } else {
                            format!("host{n}")
                        };
                        raw(&name, "1.1.1.1")
                    })
                    .collect(),
            )));
        }
        let m = mock(replies).await;
        let o = common::reconcile(&m.provider, &spec(), "8.8.8.8", true)
            .await
            .unwrap();
        assert_eq!(o.status, "would_update");
        assert_eq!(m.captures.lock().unwrap().len(), 12);
        assert_reads(&m);
    }
    #[tokio::test]
    async fn pagination_refuses_repetition_changing_total_and_partial_pages() {
        let first: Vec<_> = (0..100)
            .map(|n| raw(&format!("host{n}"), "1.1.1.1"))
            .collect();
        for (last, code) in [
            (page(101, vec![first[0].clone()]), "UnstableRecordList"),
            (
                page(102, vec![raw("home", "1.1.1.1")]),
                "IncompletePagination",
            ),
            (page(101, vec![]), "IncompletePagination"),
            (page(10001, vec![]), "IncompletePagination"),
            (json!({"items":[]}), "IncompletePagination"),
        ] {
            let m = mock(vec![
                read(owned()),
                read(page(101, first.clone())),
                read(last),
            ])
            .await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            assert_reads(&m);
        }
        let m = mock(vec![
            read(owned()),
            read(page(2, vec![raw("home", "1.1.1.1")])),
        ])
        .await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "IncompletePagination"
        );
    }
    #[tokio::test]
    async fn domain_identity_registration_verification_epp_and_authority_fail_closed() {
        for (field, value, code) in [
            ("name", json!("evil.com"), "ZoneMismatch"),
            ("lifecycleStatus", json!("grace1"), "UnsafeDomainState"),
            (
                "verificationStatus",
                json!("verification"),
                "UnsafeDomainState",
            ),
            (
                "suspensions",
                json!([{"reasonCode":"abuse"}]),
                "UnsafeDomainState",
            ),
            ("eppStatuses", json!(["clientHold"]), "UnsafeDomainState"),
            (
                "eppStatuses",
                json!(["clientUpdateProhibited"]),
                "UnsafeDomainState",
            ),
            ("eppStatuses", Value::Null, "UnknownDomainState"),
            (
                "nameservers",
                json!({"provider":"custom","hosts":["ns1.other.com","ns2.other.com"]}),
                "NonAuthoritativeZone",
            ),
        ] {
            let mut r = owned();
            r[field] = value;
            let m = mock(vec![read(r)]).await;
            assert_eq!(m.provider.list(&spec()).await.unwrap_err().code, code);
            assert_eq!(m.captures.lock().unwrap().len(), 1);
        }
        let mut r = owned();
        r["verificationStatus"] = Value::Null;
        let m = mock(vec![read(r), read(page(0, vec![]))]).await;
        assert!(m.provider.list(&spec()).await.is_ok());
    }
    #[tokio::test]
    async fn local_ttl_options_and_credentials_rejected_before_dry_run_reads() {
        for ttl in [0, 59, 3601, u64::MAX] {
            let m = mock(vec![]).await;
            let mut s = spec();
            s.ttl = ttl;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap_err()
                    .code,
                "UnsupportedTTL"
            );
            assert!(m.captures.lock().unwrap().is_empty());
        }
        for n in 0..6 {
            let mut m = mock(vec![]).await;
            let mut s = spec();
            match n {
                0 => m.provider.id = "".into(),
                1 => m.provider.key = "\nsecret".into(),
                2 => m.provider.options_valid = false,
                3 => {
                    s.options.insert("force".into(), "true".into());
                }
                4 => s.record_line = "routed".into(),
                _ => s.domain = "example.com/path".into(),
            };
            assert!(m.provider.list(&s).await.is_err());
            assert!(m.captures.lock().unwrap().is_empty());
        }
        for ttl in [60, 3600] {
            let m = mock(vec![read(owned()), read(page(0, vec![]))]).await;
            let mut s = spec();
            s.ttl = ttl;
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap()
                    .status,
                "would_create"
            );
            assert_reads(&m);
        }
    }
    #[tokio::test]
    async fn managed_unknown_flags_invalid_values_and_missing_metadata_are_refused() {
        for (field, value, code) in [
            ("group", json!({"type":"product"}), "ManagedRecord"),
            ("group", json!({"type":"personalNs"}), "ManagedRecord"),
            (
                "group",
                json!({"type":"custom","productId":"123"}),
                "ManagedRecord",
            ),
            ("enabled", json!(false), "UnsafeRecordMetadata"),
            ("ttl", Value::Null, "UnsafeRecordMetadata"),
            ("address", json!("not-ip"), "InvalidRecordValue"),
            ("address", json!("::1"), "InvalidRecordValue"),
        ] {
            let mut r = raw("home", "1.1.1.1");
            r[field] = value;
            let m = mock(vec![read(owned()), read(page(1, vec![r]))]).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", true)
                    .await
                    .unwrap_err()
                    .code,
                code
            );
            assert_reads(&m);
        }
        for field in ["name", "type", "group", "address"] {
            let mut r = raw("home", "1.1.1.1");
            r.as_object_mut().unwrap().remove(field);
            let m = mock(vec![read(owned()), read(page(1, vec![r]))]).await;
            assert_eq!(
                m.provider.list(&spec()).await.unwrap_err().code,
                "MalformedRecord"
            );
        }
    }
    #[tokio::test]
    async fn multivalue_ambiguous_and_explicit_member_selection_are_never_mutated() {
        let rows = vec![raw("home", "1.1.1.1"), raw("home", "9.9.9.9")];
        let m = mock(vec![read(owned()), read(page(2, rows.clone()))]).await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "AmbiguousRecords"
        );
        assert_reads(&m);
        let m = mock(vec![read(owned()), read(page(2, rows.clone()))]).await;
        let mut s = spec();
        s.record_id = Some(identity(&s.domain, "home", "A", Some(&rows[0])));
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", true)
                .await
                .unwrap_err()
                .code,
            "MultiValueRRset"
        );
        assert_reads(&m);
        let m = mock(vec![
            read(owned()),
            read(page(1, vec![raw("other", "1.1.1.1")])),
        ])
        .await;
        let mut s = spec();
        s.record_id = Some(identity(&s.domain, "other", "A", None));
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordIdMismatch"
        );
    }
    #[tokio::test]
    async fn cname_alias_and_delegated_child_zone_fail_even_dry_run() {
        for (ty, name) in [
            ("CNAME", "home"),
            ("ALIAS", "home"),
            ("NS", "home"),
            ("NS", "child"),
        ] {
            let mut r = raw(name, "1.1.1.1");
            r["type"] = json!(ty);
            let m = mock(vec![read(owned()), read(page(1, vec![r]))]).await;
            let mut s = spec();
            if name == "child" {
                s.subdomain = "home.child".into();
            }
            s.create_if_missing = true;
            assert_eq!(
                common::reconcile(&m.provider, &s, "8.8.8.8", true)
                    .await
                    .unwrap_err()
                    .code,
                "ConflictingOrDelegatedHost"
            );
            assert_reads(&m);
        }
    }
    #[tokio::test]
    async fn address_update_adds_first_verifies_then_deletes_exact_old_only() {
        let old = raw("home", "1.1.1.1");
        let new = raw("home", "8.8.8.8");
        let mut txt = raw("_acme-challenge", "1.1.1.1");
        txt["type"] = json!("TXT");
        txt.as_object_mut().unwrap().remove("address");
        txt["value"] = json!("do-not-touch");
        let initial = page(2, vec![old.clone(), txt.clone()]);
        let m = mock(vec![
            read(owned()),
            read(initial.clone()),
            read(owned()),
            read(initial),
            ack(),
            read(owned()),
            read(page(3, vec![old, new.clone(), txt.clone()])),
            ack(),
            read(owned()),
            read(page(2, vec![new, txt])),
        ])
        .await;
        let o = common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
            .await
            .unwrap();
        assert_eq!(o.status, "updated");
        assert_eq!(
            o.record_id.as_deref(),
            Some(identity("example.com", "home", "A", None).as_str())
        );
        let c = m.captures.lock().unwrap();
        assert_eq!(c.len(), 10);
        assert_eq!(c[4].method, Method::PUT);
        assert_eq!(
            c[4].body,
            json!({"force":false,"items":[{"type":"A","name":"home","address":"8.8.8.8","ttl":600}]})
        );
        assert_eq!(c[7].method, Method::DELETE);
        assert_eq!(
            c[7].body,
            json!([{"type":"A","name":"home","address":"1.1.1.1"}])
        );
        assert!(!c[7].body.to_string().contains("do-not-touch"));
    }
    #[tokio::test]
    async fn ttl_only_and_ipv6_equivalent_update_do_not_delete() {
        let mut old = raw("@", "2001:0db8::1");
        old["type"] = json!("AAAA");
        let mut after = old.clone();
        after["ttl"] = json!(300);
        let mut replies = stable(old);
        replies.extend([ack(), read(owned()), read(page(1, vec![after]))]);
        let m = mock(replies).await;
        let mut s = spec();
        s.subdomain = "@".into();
        s.record_type = "AAAA".into();
        s.ttl = 300;
        assert_eq!(
            common::reconcile(&m.provider, &s, "2001:db8::1", false)
                .await
                .unwrap()
                .status,
            "updated"
        );
        let c = m.captures.lock().unwrap();
        assert_eq!(c.len(), 7);
        assert_eq!(c[4].body["items"][0]["address"], "2001:0db8::1");
        assert!(!c.iter().any(|v| v.method == Method::DELETE));
    }
    #[tokio::test]
    async fn create_opt_in_apex_ipv6_and_dry_run_no_writes() {
        let m = mock(vec![]).await;
        assert_eq!(
            m.provider
                .create(&spec(), "8.8.8.8")
                .await
                .unwrap_err()
                .code,
            "UnsafeCreate"
        );
        assert!(m.captures.lock().unwrap().is_empty());
        let mut new = raw("@", "2001:db8::1");
        new["type"] = json!("AAAA");
        let m = mock(vec![
            read(owned()),
            read(page(0, vec![])),
            read(owned()),
            read(page(0, vec![])),
            ack(),
            read(owned()),
            read(page(1, vec![new])),
        ])
        .await;
        let mut s = spec();
        s.subdomain = "@".into();
        s.record_type = "AAAA".into();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "2001:db8::1", false)
                .await
                .unwrap()
                .status,
            "created"
        );
        assert_eq!(
            m.captures
                .lock()
                .unwrap()
                .iter()
                .filter(|v| v.method != Method::GET)
                .count(),
            1
        );
        let m = mock(vec![
            read(owned()),
            read(page(1, vec![raw("home", "1.1.1.1")])),
        ])
        .await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "1.1.1.1", false)
                .await
                .unwrap()
                .status,
            "unchanged"
        );
        assert_reads(&m);
        let m = mock(vec![read(owned()), read(page(0, vec![]))]).await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", true)
                .await
                .unwrap()
                .status,
            "would_create"
        );
        assert_reads(&m);
    }
    #[tokio::test]
    async fn preflight_changed_address_group_ttl_or_appeared_target_stops_writes() {
        for (field, value) in [
            ("address", json!("9.9.9.9")),
            ("ttl", json!(300)),
            ("group", json!({"type":"product"})),
        ] {
            let old = raw("home", "1.1.1.1");
            let mut fresh = old.clone();
            fresh[field] = value;
            let m = mock(vec![
                read(owned()),
                read(page(1, vec![old])),
                read(owned()),
                read(page(1, vec![fresh])),
            ])
            .await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "StaleRecord"
            );
            assert_reads(&m);
        }
        let m = mock(vec![
            read(owned()),
            read(page(0, vec![])),
            read(owned()),
            read(page(1, vec![raw("home", "1.1.1.1")])),
        ])
        .await;
        let mut s = spec();
        s.create_if_missing = true;
        assert_eq!(
            common::reconcile(&m.provider, &s, "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "CreateRace"
        );
        assert_reads(&m);
    }
    #[tokio::test]
    async fn unverified_add_never_deletes_or_retries_and_partial_delete_error_is_detailed() {
        for rows in [
            vec![raw("home", "1.1.1.1")],
            vec![raw("home", "8.8.8.8")],
            vec![
                raw("home", "1.1.1.1"),
                raw("home", "8.8.8.8"),
                raw("other", "9.9.9.9"),
            ],
        ] {
            let mut replies = stable(raw("home", "1.1.1.1"));
            replies.extend([ack(), read(owned()), read(page(rows.len(), rows))]);
            let m = mock(replies).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "UnverifiedAdd"
            );
            let c = m.captures.lock().unwrap();
            assert_eq!(c.iter().filter(|v| v.method == Method::PUT).count(), 1);
            assert!(!c.iter().any(|v| v.method == Method::DELETE));
        }
        let mut replies = stable(raw("home", "1.1.1.1"));
        replies.extend([
            ack(),
            read(owned()),
            read(page(
                2,
                vec![raw("home", "1.1.1.1"), raw("home", "8.8.8.8")],
            )),
            Reply {
                status: StatusCode::FORBIDDEN,
                body: json!({"detail":"delete denied test-spaceship-secret"}).to_string(),
                error: Some("business.dns.deleteDenied".into()),
            },
        ]);
        let m = mock(replies).await;
        let e = common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
            .await
            .unwrap_err();
        assert_eq!(e.stage, "update");
        assert_eq!(e.code, "business.dns.deleteDenied");
        assert_eq!(e.http_status, Some(403));
        assert_eq!(e.request_id.as_deref(), Some("spaceship-trace"));
        assert!(e.message.contains("Both IPs may remain"));
        assert!(!e.message.contains("test-spaceship-secret"));
        assert!(!e.retryable);
    }
    #[tokio::test]
    async fn writes_require_204_no_content_and_final_delete_is_verified() {
        for reply in [
            read(json!({"success":true})),
            Reply {
                status: StatusCode::ACCEPTED,
                body: json!({"operationId":"pending"}).to_string(),
                error: None,
            },
        ] {
            let mut replies = stable(raw("home", "1.1.1.1"));
            replies.push(reply);
            let m = mock(replies).await;
            assert_eq!(
                common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "InvalidWriteAcknowledgement"
            );
            assert_eq!(m.captures.lock().unwrap().len(), 5);
        }
        let mut replies = stable(raw("home", "1.1.1.1"));
        replies.extend([
            ack(),
            read(owned()),
            read(page(
                2,
                vec![raw("home", "1.1.1.1"), raw("home", "8.8.8.8")],
            )),
            ack(),
            read(owned()),
            read(page(
                2,
                vec![raw("home", "1.1.1.1"), raw("home", "8.8.8.8")],
            )),
        ]);
        let m = mock(replies).await;
        assert_eq!(
            common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
                .await
                .unwrap_err()
                .code,
            "UnverifiedDelete"
        );
        assert_eq!(
            m.captures
                .lock()
                .unwrap()
                .iter()
                .filter(|v| v.method == Method::DELETE)
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn failed_post_add_verification_is_uncertain_and_read_only_recovery_required() {
        let mut replies = stable(raw("home", "1.1.1.1"));
        replies.extend([
            ack(),
            Reply {
                status: StatusCode::FORBIDDEN,
                body: json!({"detail":"verify denied test-spaceship-secret"}).to_string(),
                error: Some("business.domain.readDenied".into()),
            },
        ]);
        let m = mock(replies).await;
        let e = common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
            .await
            .unwrap_err();
        assert_eq!(e.code, "AfterAddReadFailed");
        assert_eq!(e.stage, "update");
        assert!(e.message.contains("business.domain.readDenied"));
        assert!(e.message.contains("403"));
        assert!(e.message.contains("spaceship-trace"));
        assert!(!e.message.contains("test-spaceship-secret"));
        assert!(!e.retryable);
        let calls = m.captures.lock().unwrap();
        assert_eq!(calls.iter().filter(|v| v.method == Method::PUT).count(), 1);
        assert!(!calls.iter().any(|v| v.method == Method::DELETE));
    }
    #[tokio::test]
    async fn failed_post_delete_read_keeps_uncertain_result_and_never_retries() {
        let mut replies = stable(raw("home", "1.1.1.1"));
        replies.extend([
            ack(),
            read(owned()),
            read(page(
                2,
                vec![raw("home", "1.1.1.1"), raw("home", "8.8.8.8")],
            )),
            ack(),
            Reply {
                status: StatusCode::FORBIDDEN,
                body: json!({"detail":"final read denied test-spaceship-id"}).to_string(),
                error: Some("business.domain.readDenied".into()),
            },
        ]);
        let m = mock(replies).await;
        let e = common::reconcile(&m.provider, &spec(), "8.8.8.8", false)
            .await
            .unwrap_err();
        assert_eq!(e.code, "AfterDeleteReadFailed");
        assert_eq!(e.stage, "update");
        assert!(e.message.contains("business.domain.readDenied"));
        assert!(e.message.contains("403"));
        assert!(!e.message.contains("test-spaceship-id"));
        assert!(!e.retryable);
        let c = m.captures.lock().unwrap();
        assert_eq!(c.iter().filter(|v| v.method == Method::PUT).count(), 1);
        assert_eq!(c.iter().filter(|v| v.method == Method::DELETE).count(), 1);
    }
    #[tokio::test]
    async fn record_host_wildcards_and_unlocked_domain_schema_are_precise() {
        for valid in [
            "@",
            "*",
            "*.child",
            "_acme-challenge",
            "_service._tcp",
            "_.child",
        ] {
            assert!(record_name(valid));
        }
        for invalid in ["ho*me", "child.*", "a..b", "-bad", "bad-", "child/host"] {
            assert!(!record_name(invalid));
        }
        let mut d = owned();
        d["eppStatuses"] = json!([]);
        let m = mock(vec![read(d), read(page(0, vec![]))]).await;
        assert!(m.provider.list(&spec()).await.is_ok());
        let mut d = owned();
        d.as_object_mut().unwrap().remove("verificationStatus");
        let m = mock(vec![read(d)]).await;
        assert_eq!(
            m.provider.list(&spec()).await.unwrap_err().code,
            "UnsafeDomainState"
        );
    }
    #[tokio::test]
    async fn structured_http_and_business_errors_redact_both_keys_and_keep_trace() {
        for status in [
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            let m=mock(vec![Reply{status,body:json!({"detail":"test-spaceship-id invalid\n test-spaceship-secret","data":[{"field":"items[0].ttl","details":"TTL outside bounds"}]}).to_string(),error:Some("business.dns.validationFailed".into())}]).await;
            let e = m.provider.list(&spec()).await.unwrap_err();
            assert_eq!(e.code, "business.dns.validationFailed");
            assert_eq!(e.http_status, Some(status.as_u16()));
            assert_eq!(e.request_id.as_deref(), Some("spaceship-trace"));
            assert!(e.message.contains("items[0].ttl"));
            assert!(e.message.contains("TTL outside bounds"));
            assert!(!e.message.contains("test-spaceship"));
            assert!(!e.message.contains('\n'));
        }
        let m = mock(vec![Reply {
            status: StatusCode::BAD_GATEWAY,
            body: "<html>test-spaceship-secret</html>".into(),
            error: None,
        }])
        .await;
        let e = m.provider.list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "MalformedResponse");
        assert_eq!(e.http_status, Some(502));
        assert!(!e.message.contains("test-spaceship-secret"));
    }
}
