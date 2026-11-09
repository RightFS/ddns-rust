use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::IpAddr,
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub log_level: String,
    pub providers: Vec<ProviderConfig>,
    pub records: Vec<RecordConfig>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub name: String,
    #[serde(default = "default_provider_kind")]
    pub kind: String,
    #[serde(default)]
    pub secret_id_env: String,
    #[serde(default)]
    pub secret_key_env: String,
    #[serde(default)]
    pub token_env: String,
    #[serde(default)]
    pub credentials: BTreeMap<String, String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

pub const CONFIGURED_CREDENTIAL: &str = "__DDNS_CONFIGURED__";

impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("secret_id_env", &self.secret_id_env)
            .field("secret_key_env", &self.secret_key_env)
            .field("token_env", &self.token_env)
            .field("credentials", &self.credentials.keys().collect::<Vec<_>>())
            .field("options", &self.options)
            .finish()
    }
}

impl ProviderConfig {
    pub(crate) fn direct_credential(&self, key: &str) -> Option<&str> {
        self.credentials
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty() && *v != CONFIGURED_CREDENTIAL)
    }
}
fn default_provider_kind() -> String {
    "tencentcloud".into()
}
fn deserialize_record_id<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Id {
        Text(String),
        Number(u64),
    }
    Ok(Option::<Id>::deserialize(deserializer)?.map(|id| match id {
        Id::Text(s) => s,
        Id::Number(n) => n.to_string(),
    }))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordConfig {
    pub name: String,
    pub provider: String,
    pub domain: String,
    pub subdomain: String,
    pub record_type: String,
    pub record_line: String,
    pub ttl: u64,
    #[serde(default, deserialize_with = "deserialize_record_id")]
    pub record_id: Option<String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    pub create_if_missing: bool,
    pub enabled: bool,
    pub ip_source: IpSource,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpSource {
    pub kind: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
}

impl IpSource {
    pub fn interface_regex(&self) -> Result<Option<regex::Regex>, regex::Error> {
        self.regex
            .as_deref()
            .filter(|pattern| !pattern.is_empty())
            .map(regex::Regex::new)
            .transpose()
    }
}

pub fn valid_level(level: &str) -> bool {
    matches!(level, "trace" | "debug" | "info" | "warn" | "error")
}
fn hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
impl Default for Config {
    fn default() -> Self {
        Self {
            interval_secs: 300,
            timeout_secs: 15,
            log_level: "info".into(),
            providers: vec![ProviderConfig {
                name: "tencent".into(),
                kind: default_provider_kind(),
                token_env: String::new(),
                options: BTreeMap::new(),
                credentials: BTreeMap::new(),
                secret_id_env: "TENCENT_SECRET_ID".into(),
                secret_key_env: "TENCENT_SECRET_KEY".into(),
            }],
            records: vec![],
        }
    }
}
// Exact Huawei DNS SDK regions mirrored from the frozen adapter contract.
fn huawei_region(region: &str) -> bool {
    [
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
    ]
    .contains(&region)
}
fn native_path_id(id: &str) -> bool {
    crate::providers::common::valid_id(id) && !matches!(id, "." | "..")
}
impl Config {
    /// Return the public configuration without exposing server-owned secret values.
    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        for provider in &mut redacted.providers {
            for value in provider.credentials.values_mut() {
                if !value.is_empty() {
                    *value = CONFIGURED_CREDENTIAL.into();
                }
            }
        }
        redacted
    }

    /// Resolve masked round-trip values against the same provider identity only.
    pub fn merge_credentials(&mut self, current: &Config) -> Result<(), String> {
        let mut merged = self.clone();
        for provider in &mut merged.providers {
            for (key, value) in &mut provider.credentials {
                if value == CONFIGURED_CREDENTIAL {
                    *value = current.providers.iter()
                        .find(|p| p.name == provider.name && p.kind == provider.kind)
                        .and_then(|p| p.direct_credential(key))
                        .ok_or_else(|| "Cannot preserve a configured credential without a matching provider and existing value".to_owned())?
                        .to_owned();
                }
            }
            provider.credentials.retain(|_, value| !value.is_empty());
        }
        *self = merged;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !(30..=86400).contains(&self.interval_secs) {
            return Err("interval_secs must be between 30 and 86400".into());
        }
        if !(1..=120).contains(&self.timeout_secs) {
            return Err("timeout_secs must be between 1 and 120".into());
        }
        if !valid_level(&self.log_level) {
            return Err("log_level must be trace, debug, info, warn or error".into());
        }
        if self.records.len() > 100 || self.providers.len() > 64 {
            return Err("Maximum 100 records and 64 providers".into());
        }
        let mut providers = HashSet::new();
        for p in &self.providers {
            if p.name.trim().is_empty() || !providers.insert(&p.name) {
                return Err("Provider names must be nonempty and unique".into());
            }
            let descriptor = crate::providers::registry::descriptor(&p.kind)
                .ok_or_else(|| format!("Unknown provider kind: {}", p.kind))?;
            if !descriptor.implemented {
                return Err(format!(
                    "Provider {} is planned but not implemented; no fallback provider will be used",
                    p.kind
                ));
            }
            if descriptor.options.iter().any(|field| {
                field.required
                    && p.options.get(field.key).is_none_or(|v| v.trim().is_empty())
                    && !(matches!(field.key, "endpoint_env" | "client_ip_env")
                        && p.direct_credential(field.key).is_some())
            }) {
                return Err(format!(
                    "Required provider option is missing for {}",
                    p.kind
                ));
            }
            match p.kind.as_str() {
                "namecheap" => crate::providers::namecheap::check_options_with_direct(
                    &p.options,
                    p.direct_credential("client_ip_env").is_some(),
                )
                .map_err(|e| e.message)?,
                "trafficroute" => crate::providers::trafficroute::validate_options(&p.options)
                    .map_err(|e| e.message)?,
                "callback" => crate::providers::callback::check_options_with_direct(
                    &p.options,
                    p.direct_credential("endpoint_env").is_some(),
                )
                .map_err(|e| e.message)?,
                "huaweicloud" => {
                    if !p.options.get("region").is_some_and(|v| huawei_region(v))
                        || !p
                            .options
                            .get("project_id")
                            .is_some_and(|v| native_path_id(v))
                        || p.options.get("zone_id").is_some_and(|v| !native_path_id(v))
                    {
                        return Err("HuaweiCloud requires an official DNS SDK region and safe regional project_id; optional zone_id must be a native non-dot path ID".into());
                    }
                }
                "baiducloud" => {
                    if !p
                        .options
                        .get("resource_id")
                        .is_some_and(|v| native_path_id(v))
                    {
                        return Err(
                            "BaiduCloud requires a safe native registered-domain resource_id"
                                .into(),
                        );
                    }
                }
                "edgeone"
                    if p.options.get("mode").map(String::as_str) != Some("dns")
                        || p.options.get("scope").map(String::as_str) != Some("teodns")
                        || p.options.get("api_version").map(String::as_str)
                            != Some("2022-09-01")
                        || !p.options.get("zone_id").is_some_and(|v| {
                            v.starts_with("zone-") && crate::providers::common::valid_id(v)
                        }) =>
                {
                    return Err("EdgeOne requires mode=dns, scope=teodns, api_version=2022-09-01 and native zone-... zone_id; no origin or endpoint fallback".into());
                }
                _ => {}
            }
            if p.kind == "hipmdnsmgr" {
                if !p
                    .options
                    .get("endpoint_env")
                    .is_some_and(|name| crate::providers::registry::valid_endpoint_env(name))
                    && !(p.options.get("endpoint_env").is_none_or(String::is_empty)
                        && p.direct_credential("endpoint_env").is_some())
                {
                    return Err("HiPM endpoint_env must be a 6..64-character HIPM_-scoped uppercase server environment reference; no DDNS_, arbitrary names or literal URLs".into());
                }
                if p.options.get("domain_id").is_some_and(|id| {
                    id.parse::<i64>()
                        .ok()
                        .is_none_or(|n| n <= 0 || n.to_string() != *id)
                }) {
                    return Err(
                        "HiPM domain_id must be a canonical positive int64 manager ID".into(),
                    );
                }
            }
            if p.kind == "gcore"
                && p.options
                    .get("plan")
                    .is_some_and(|plan| !matches!(plan.as_str(), "free" | "pro" | "enterprise"))
            {
                return Err(
                    "Gcore plan must be free, pro or enterprise (the actual account plan)".into(),
                );
            }
            if p.kind == "dynv6"
                && p.options.get("ttl_mode").map(String::as_str) != Some("provider_default")
            {
                return Err(
                    "dynv6 requires ttl_mode=provider_default; REST cannot read/write TTL".into(),
                );
            }
            if p.kind == "rainyun"
                && p.options.get("domain_id").is_none_or(|id| {
                    id.parse::<u64>().is_err()
                        || id.parse::<u64>().ok() == Some(0)
                        || id.parse::<u64>().ok().map(|n| n.to_string()).as_ref() != Some(id)
                })
            {
                return Err(
                    "Rainyun requires options.domain_id as a canonical positive decimal product ID"
                        .into(),
                );
            }
            if p.kind == "cloudns"
                && p.options.get("auth_type").is_some_and(|s| {
                    !matches!(s.as_str(), "auth-id" | "sub-auth-id" | "sub-auth-user")
                })
            {
                return Err(
                    "ClouDNS auth_type must be auth-id, sub-auth-id or sub-auth-user".into(),
                );
            }
            for (key, value) in [
                ("secret_id_env", &p.secret_id_env),
                ("secret_key_env", &p.secret_key_env),
                ("token_env", &p.token_env),
            ] {
                if let Some(field) = descriptor.credential_fields.iter().find(|f| f.key == key) {
                    if !(value.is_empty() && p.direct_credential(key).is_some())
                        && !crate::providers::registry::valid_env(value, field.env_prefix)
                    {
                        return Err(format!(
                            "{} for {} must reference an environment variable starting with {} or DDNS_ (A-Z, 0-9, _ only)",
                            key, p.kind, field.env_prefix
                        ));
                    }
                } else if !value.is_empty() {
                    return Err(format!("{} is not used by provider {}", key, p.kind));
                }
            }
            for (key, value) in &p.credentials {
                if !descriptor.credential_fields.iter().any(|f| f.key == key)
                    && !(matches!(key.as_str(), "endpoint_env" | "client_ip_env")
                        && descriptor.options.iter().any(|f| f.key == key))
                {
                    return Err(format!("Unsupported direct credential for {}", p.kind));
                }
                if value == CONFIGURED_CREDENTIAL {
                    return Err("Masked credentials must be merged before validation".into());
                }
                if !value.is_empty() {
                    match (p.kind.as_str(), key.as_str()) {
                        ("callback", "endpoint_env") => {
                            crate::providers::callback::check_endpoint_value(value)
                                .map_err(|e| e.message)?;
                        }
                        ("hipmdnsmgr", "endpoint_env") => {
                            crate::providers::check_hipm_endpoint_value(value)
                                .map_err(|e| e.message)?;
                        }
                        ("namecheap", "client_ip_env") => {
                            crate::providers::namecheap::check_client_ip_value(value)
                                .map_err(|e| e.message)?;
                        }
                        _ => {}
                    }
                }
            }
            if p.options
                .keys()
                .any(|key| !descriptor.options.iter().any(|field| field.key == key))
                || p.options
                    .values()
                    .any(|v| v.len() > 256 || v.chars().any(char::is_control))
            {
                return Err(format!("Unsupported or malformed options for {}", p.kind));
            }
            if let Some(zone_id) = p.options.get("zone_id")
                && !crate::providers::common::valid_id(zone_id)
            {
                return Err("zone_id must be a plain provider identifier".into());
            }
            if let Some(team_id) = p.options.get("team_id")
                && (!crate::providers::common::valid_id(team_id)
                    || matches!(team_id.as_str(), "." | ".."))
            {
                return Err("team_id must be a plain Vercel team identifier".into());
            }
            if let Some(region) = p.options.get("region")
                && (region.is_empty()
                    || !region
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
            {
                return Err("region must be a plain region identifier".into());
            }
        }
        let mut names = HashSet::new();
        let mut targets = HashSet::new();
        let mut record_ids = HashSet::new();
        for r in &self.records {
            if r.name.trim().is_empty() || !names.insert(&r.name) {
                return Err("Record names must be nonempty and unique".into());
            }
            if !providers.contains(&r.provider) {
                return Err(format!("Unknown provider for record {}", r.name));
            }
            let empty_namecheap_apex = r.subdomain.is_empty()
                && self
                    .providers
                    .iter()
                    .any(|p| p.name == r.provider && p.kind == "namecheap");
            if !r.domain.contains('.')
                || !hostname(&r.domain)
                || !(r.subdomain == "@" || empty_namecheap_apex || hostname(&r.subdomain))
            {
                return Err(format!(
                    "Invalid zone or subdomain for record {}; use ASCII/punycode and @ for the zone apex",
                    r.name
                ));
            }
            if !matches!(r.record_type.as_str(), "A" | "AAAA") {
                return Err("record_type must be A or AAAA".into());
            }
            let provider = self
                .providers
                .iter()
                .find(|p| p.name == r.provider)
                .expect("provider checked");
            let descriptor =
                crate::providers::registry::descriptor(&provider.kind).expect("provider validated");
            crate::providers::check_record(provider, r).map_err(|e| e.message)?;
            if provider.kind == "trafficroute" {
                let line = match r.record_line.as_str() {
                    "" | "默认" | "default" => "default",
                    other => other,
                };
                if !(1..=86400).contains(&r.ttl)
                    || !native_path_id(line)
                    || r.record_id.as_ref().is_some_and(|id| {
                        id.parse::<i64>()
                            .ok()
                            .is_none_or(|n| n <= 0 || n.to_string() != *id)
                    })
                    || r.domain.len()
                        + if r.subdomain == "@" {
                            0
                        } else {
                            r.subdomain.len() + 1
                        }
                        > 253
                {
                    return Err("TrafficRoute requires TTL 1..86400 (actual account minimum checked by ListLines), exact native line Value and canonical positive int64 RecordID".into());
                }
            }
            if provider.kind == "hipmdnsmgr"
                && (r.record_line.is_empty()
                    || r.record_line.len() > 128
                    || !r.record_line.is_ascii()
                    || r.record_line
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control()))
            {
                return Err("HiPM record_line requires the actual native ASCII Aliyun line code (e.g. default), not 默认; no display-label mapping is guessed".into());
            }
            if provider.kind == "dynv6" {
                if r.subdomain == "@" {
                    return Err("dynv6 REST adapter refuses apex/zone-primary updates; use literal child records".into());
                }
                if let Some(id) = &r.record_id
                    && id
                        .parse::<i64>()
                        .ok()
                        .is_none_or(|n| n <= 0 || n.to_string() != *id)
                {
                    return Err("dynv6 requires a canonical positive int64 record_id".into());
                }
            }
            if matches!(
                provider.kind.as_str(),
                "huaweicloud" | "baiducloud" | "edgeone"
            ) && r.record_line.chars().any(char::is_control)
            {
                return Err("Native DNS record_line must not contain control characters".into());
            }
            match provider.kind.as_str() {
                "huaweicloud" => {
                    if !matches!(r.record_line.as_str(), "默认" | "default" | "default_view")
                        || r.ttl < 300
                    {
                        return Err("HuaweiCloud supports default_view only (default/默认 aliases); rollout TTL minimum is conservatively 300, not an account entitlement claim".into());
                    }
                    if r.record_id.as_ref().is_some_and(|v| !native_path_id(v))
                        || r.options.get("zone_id").is_some_and(|v| !native_path_id(v))
                        || provider
                            .options
                            .get("zone_id")
                            .zip(r.options.get("zone_id"))
                            .is_some_and(|(a, b)| a != b)
                    {
                        return Err("HuaweiCloud requires safe native IDs; provider and record zone_id must agree without override".into());
                    }
                }
                "baiducloud" => {
                    if r.domain.len() > 64
                        || !(60..=3600).contains(&r.ttl)
                        || !matches!(
                            r.record_line.as_str(),
                            "默认" | "default" | "DEFAULT" | "CMNET" | "CNC" | "EDU" | "SEARCH"
                        )
                        || r.record_id.as_ref().is_some_and(|v| {
                            v.parse::<i32>()
                                .ok()
                                .is_none_or(|n| n <= 0 || n.to_string() != *v)
                        })
                    {
                        return Err("BaiduCloud requires an exact registered domain (<=64 bytes), TTL 60..3600, native DEFAULT/CMNET/CNC/EDU/SEARCH line (default/默认 aliases) and canonical positive int32 record_id".into());
                    }
                }
                "edgeone"
                    if !(60..=86400).contains(&r.ttl)
                        || r.record_id.as_ref().is_some_and(|v| {
                            !v.starts_with("record-") || !crate::providers::common::valid_id(v)
                        }) =>
                {
                    return Err("EdgeOne native TEODNS requires TTL 60..86400 and record-... record_id, not origin IDs".into());
                }
                _ => {}
            }
            if matches!(
                provider.kind.as_str(),
                "huaweicloud" | "baiducloud" | "edgeone"
            ) && (r.domain.len()
                + if r.subdomain == "@" {
                    0
                } else {
                    r.subdomain.len() + 1
                }
                > 253)
            {
                return Err("Native DNS target FQDN must be at most 253 bytes".into());
            }
            if r.options.keys().any(|key| {
                !descriptor
                    .record_options
                    .iter()
                    .any(|field| field.key == key)
            }) {
                return Err(format!("Unsupported record option for {}", provider.kind));
            }
            if let Some(proxied) = r.options.get("proxied")
                && !matches!(proxied.as_str(), "true" | "false")
            {
                return Err("proxied must be true or false".into());
            }
            if let Some(id) = &r.record_id {
                if !crate::providers::common::valid_id(id) {
                    return Err(
                        "record_id must be a nonzero plain identifier, at most 128 characters"
                            .into(),
                    );
                }
                if matches!(provider.kind.as_str(), "tencentcloud" | "alidns" | "dnspod")
                    && id.parse::<u64>().ok().is_none_or(|n| n == 0)
                {
                    return Err(format!(
                        "{} requires a positive decimal record_id",
                        provider.kind
                    ));
                }
            }
            if !(1..=604800).contains(&r.ttl)
                || (r.record_line.trim().is_empty()
                    && !matches!(
                        provider.kind.as_str(),
                        "trafficroute" | "callback" | "namecheap"
                    ))
            {
                return Err("TTL must be 1..604800 and record_line nonempty; provider limits may be stricter".into());
            }
            if let Some(id) = &r.record_id
                && !record_ids.insert((&r.provider, r.domain.to_ascii_lowercase(), id))
            {
                return Err(
                    "Duplicate explicit RecordId; configure only one updater per record".into(),
                );
            }
            let target_line = if provider.kind == "trafficroute" {
                match r.record_line.as_str() {
                    "" | "默认" | "default" => "default".into(),
                    other => other.to_owned(),
                }
            } else if provider.kind == "baiducloud" {
                match r.record_line.as_str() {
                    "默认" | "default" => "DEFAULT".into(),
                    other => other.to_owned(),
                }
            } else if provider.kind == "edgeone" {
                match r.record_line.as_str() {
                    "默认" | "default" => "Default".into(),
                    other => other.to_owned(),
                }
            } else if matches!(
                provider.kind.as_str(),
                "tencentcloud" | "alidns" | "dnspod" | "dnsla" | "rainyun" | "hipmdnsmgr"
            ) {
                if r.record_line == "默认" || r.record_line.eq_ignore_ascii_case("default") {
                    "default".to_owned()
                } else {
                    r.record_line.clone()
                }
            } else {
                String::new()
            };
            if !targets.insert((
                &r.provider,
                r.domain.to_ascii_lowercase(),
                if provider.kind == "namecheap" && r.subdomain.is_empty() {
                    "@".into()
                } else {
                    r.subdomain.to_ascii_lowercase()
                },
                &r.record_type,
                target_line,
            )) {
                return Err("Duplicate DNS target; configure only one updater per record".into());
            }
            if r.ip_source.regex.is_some() && r.ip_source.kind != "interface" {
                return Err("IP source regex is only supported for network interfaces".into());
            }
            match r.ip_source.kind.as_str() {
                "static" => {
                    let ip: IpAddr = r
                        .ip_source
                        .value
                        .parse()
                        .map_err(|_| "Invalid static IP address".to_owned())?;
                    if ip.is_ipv4() != (r.record_type == "A") {
                        return Err("Static IP family does not match record type".into());
                    }
                }
                "url" => {
                    let url = reqwest::Url::parse(&r.ip_source.value)
                        .map_err(|_| "Invalid IP source URL".to_owned())?;
                    if url.scheme() != "https"
                        || url.host_str().is_none()
                        || !url.username().is_empty()
                        || url.password().is_some()
                        || url.query().is_some()
                        || url.fragment().is_some()
                    {
                        return Err(
                            "IP source URL must use HTTPS without credentials, query or fragment"
                                .into(),
                        );
                    }
                }
                "interface" => {
                    if r.ip_source.value.trim().is_empty() {
                        return Err("Interface name must not be empty".into());
                    }
                    r.ip_source.interface_regex().map_err(|err| {
                        format!("Invalid interface IP regex for {}: {err}", r.name)
                    })?;
                }
                _ => return Err("IP source kind must be static, url or interface".into()),
            }
        }
        Ok(())
    }
    pub async fn load(path: &Path) -> Result<Self, String> {
        let text = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| format!("Cannot read configuration: {e}"))?;
        let config: Self = toml::from_str(&text).map_err(|e| {
            let position = e
                .span()
                .map(|span| {
                    let prefix = &text[..span.start.min(text.len())];
                    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
                    format!(" at line {line}")
                })
                .unwrap_or_default();
            let category = if e.message().starts_with("unknown field") {
                "unknown field (unsupported configuration key)"
            } else {
                "configuration values are omitted"
            };
            format!("Invalid TOML configuration{position}: {category}")
        })?;
        config.validate()?;
        Ok(config)
    }
    pub async fn save(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file = tempfile::Builder::new()
            .prefix(".ddns-rust-")
            .tempfile_in(parent)
            .map_err(|e| format!("Cannot create temporary config: {e}"))?;
        use std::io::Write;
        let mut file = file;
        file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist(path)
            .map_err(|e| format!("Cannot atomically persist config: {}", e.error))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> RecordConfig {
        RecordConfig {
            name: "home".into(),
            provider: "tencent".into(),
            domain: "example.com".into(),
            subdomain: "home".into(),
            record_type: "A".into(),
            record_line: "默认".into(),
            ttl: 600,
            record_id: None,
            options: BTreeMap::new(),
            create_if_missing: false,
            enabled: true,
            ip_source: IpSource {
                kind: "static".into(),
                value: "1.1.1.1".into(),
                regex: None,
            },
        }
    }
    #[test]
    fn interface_regex_is_optional_and_validated_before_save() {
        let mut c = Config::default();
        c.records.push(record());
        c.records[0].ip_source = toml::from_str("kind = 'interface'\nvalue = 'en0'").unwrap();
        c.validate().unwrap();
        c.records[0].ip_source.regex = Some("^240e:".into());
        c.validate().unwrap();
        let loaded: Config = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        assert_eq!(loaded.records[0].ip_source.regex.as_deref(), Some("^240e:"));
        c.records[0].ip_source.regex = Some("(".into());
        assert!(
            c.validate()
                .unwrap_err()
                .contains("Invalid interface IP regex")
        );
        c.records[0].ip_source.kind = "static".into();
        assert!(
            c.validate()
                .unwrap_err()
                .contains("only supported for network interfaces")
        );
    }

    #[test]
    fn direct_credentials_validate_without_environment_references() {
        let mut c = Config::default();
        let p = &mut c.providers[0];
        p.secret_id_env.clear();
        p.secret_key_env.clear();
        p.credentials = BTreeMap::from([
            ("secret_id_env".into(), "direct-id-sensitive".into()),
            ("secret_key_env".into(), "direct-key-sensitive".into()),
        ]);
        c.validate().unwrap();
        let loaded: Config = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        assert_eq!(loaded.providers[0].credentials, c.providers[0].credentials);
        c.providers[0].secret_key_env = "PATH".into();
        assert!(c.validate().is_err());
        c.providers[0].secret_key_env.clear();
        c.providers[0]
            .credentials
            .insert("secret_key_env".into(), "".into());
        assert!(c.validate().is_err());
        c.providers[0]
            .credentials
            .insert("unsupported".into(), "never-expose-this".into());
        assert!(!c.validate().unwrap_err().contains("never-expose-this"));
    }

    #[test]
    fn masking_and_merge_preserve_only_exact_provider_identity() {
        let mut current = Config::default();
        current.providers[0].credentials = BTreeMap::from([
            ("secret_id_env".into(), "sensitive-direct-id".into()),
            ("secret_key_env".into(), "sensitive-direct-key".into()),
        ]);
        let mut incoming = current.redacted();
        let public = serde_json::to_string(&incoming).unwrap();
        assert!(!public.contains("sensitive-direct"));
        assert!(!format!("{current:?}").contains("sensitive-direct"));
        assert_eq!(
            incoming.providers[0].credentials["secret_id_env"],
            CONFIGURED_CREDENTIAL
        );
        assert!(incoming.validate().is_err());
        incoming.merge_credentials(&current).unwrap();
        assert_eq!(
            incoming.providers[0].credentials,
            current.providers[0].credentials
        );
        for change_kind in [false, true] {
            let mut wrong = current.redacted();
            if change_kind {
                wrong.providers[0].kind = "alidns".into();
            } else {
                wrong.providers[0].name = "renamed".into();
            }
            assert!(wrong.merge_credentials(&current).is_err());
            assert_eq!(
                wrong.providers[0].credentials["secret_id_env"],
                CONFIGURED_CREDENTIAL
            );
        }
        let mut missing = current.redacted();
        missing.providers[0]
            .credentials
            .insert("token_env".into(), CONFIGURED_CREDENTIAL.into());
        assert!(missing.merge_credentials(&current).is_err());
        incoming.providers[0]
            .credentials
            .insert("secret_id_env".into(), "".into());
        incoming.providers[0]
            .credentials
            .insert("secret_key_env".into(), "replacement-key".into());
        incoming.merge_credentials(&current).unwrap();
        assert!(
            !incoming.providers[0]
                .credentials
                .contains_key("secret_id_env")
        );
        assert_eq!(
            incoming.providers[0].credentials["secret_key_env"],
            "replacement-key"
        );
    }

    #[test]
    fn direct_special_options_use_existing_value_and_reference_validation() {
        for (mut c, key, good, bad, invalid_ref) in [
            (
                eighth_config("callback"),
                "endpoint_env",
                "https://private.example/hook",
                "https://private.example/hook?secret=omit",
                "DDNS_ENDPOINT",
            ),
            (
                sixth_config("hipmdnsmgr"),
                "endpoint_env",
                "https://private.example/api",
                "http://private.example/api",
                "DDNS_ENDPOINT",
            ),
            (
                namecheap_config(),
                "client_ip_env",
                "8.8.8.8",
                "127.0.0.1",
                "DDNS_CLIENT_IP",
            ),
        ] {
            c.providers[0].credentials.insert(key.into(), good.into());
            for absent in [false, true] {
                if absent {
                    c.providers[0].options.remove(key);
                } else {
                    c.providers[0].options.insert(key.into(), String::new());
                }
                c.validate().unwrap();
            }
            let public = serde_json::to_string(&c.redacted()).unwrap();
            assert!(!public.contains(good));
            c.providers[0]
                .options
                .insert(key.into(), invalid_ref.into());
            assert!(c.validate().is_err());
            c.providers[0].options.remove(key);
            c.providers[0].credentials.insert(key.into(), bad.into());
            let error = c.validate().unwrap_err();
            assert!(!error.contains(bad));
        }
    }

    #[test]
    fn defaults_valid() {
        Config::default().validate().unwrap();
    }
    #[test]
    fn wrong_family_rejected() {
        let mut c = Config::default();
        let mut r = record();
        r.record_type = "AAAA".into();
        c.records.push(r);
        assert!(c.validate().is_err());
    }
    #[test]
    fn duplicate_target_rejected() {
        let mut c = Config::default();
        let r = record();
        let mut other = r.clone();
        other.name = "other".into();
        c.records = vec![r, other];
        assert!(c.validate().is_err());
    }
    #[test]
    fn arbitrary_environment_rejected() {
        let mut c = Config::default();
        c.providers[0].secret_key_env = "PATH".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn legacy_numeric_record_id_and_missing_kind_are_compatible() {
        let old = serde_json::json!({"interval_secs":300,"timeout_secs":15,"log_level":"info","providers":[{"name":"tencent","secret_id_env":"TENCENT_SECRET_ID","secret_key_env":"TENCENT_SECRET_KEY"}],"records":[{"name":"home","provider":"tencent","domain":"example.com","subdomain":"home","record_type":"A","record_line":"默认","ttl":600,"record_id":123456789,"create_if_missing":false,"enabled":false,"ip_source":{"kind":"static","value":"1.1.1.1"}}]});
        let c: Config = serde_json::from_value(old).unwrap();
        c.validate().unwrap();
        assert_eq!(c.providers[0].kind, "tencentcloud");
        assert_eq!(c.records[0].record_id.as_deref(), Some("123456789"));
    }
    #[test]
    fn cloudflare_accepts_opaque_ids_and_token_only_credentials() {
        let mut c = Config::default();
        c.providers[0] = ProviderConfig {
            name: "cf".into(),
            kind: "cloudflare".into(),
            secret_id_env: String::new(),
            secret_key_env: String::new(),
            token_env: "CLOUDFLARE_API_TOKEN".into(),
            credentials: BTreeMap::new(),
            options: BTreeMap::new(),
        };
        let mut r = record();
        r.provider = "cf".into();
        r.record_id = Some("0123456789abcdef0123456789abcdef".into());
        c.records.push(r);
        c.validate().unwrap();
        c.providers[0].token_env = "CLOUDFLARE_".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn pending_provider_is_never_silently_mapped_to_tencent() {
        let mut c = Config::default();
        c.providers[0].kind = "aliesa".into();
        assert!(c.validate().unwrap_err().contains("not implemented"));
    }
    #[test]
    fn unrelated_provider_options_are_rejected() {
        let mut c = Config::default();
        c.providers[0]
            .options
            .insert("endpoint".into(), "https://evil.example".into());
        assert!(c.validate().is_err());
    }
    #[test]
    fn new_provider_credentials_options_and_roundtrip() {
        for (kind, prefix) in [
            ("name_com", "NAMECOM_"),
            ("cloudns", "CLOUDNS_"),
            ("rainyun", "RAINYUN_"),
        ] {
            let mut c = Config::default();
            let p = &mut c.providers[0];
            p.kind = kind.into();
            p.secret_id_env.clear();
            p.secret_key_env.clear();
            if kind == "rainyun" {
                p.token_env = format!("{prefix}API_TOKEN");
                p.options.insert("domain_id".into(), "123".into());
            } else {
                p.secret_id_env = format!("{prefix}ID");
                p.secret_key_env = format!("{prefix}KEY");
            }
            let mut r = record();
            r.record_id = Some("12345".into());
            r.enabled = false;
            c.records.push(r);
            c.validate().unwrap();
            let text = toml::to_string_pretty(&c).unwrap();
            let loaded: Config = toml::from_str(&text).unwrap();
            loaded.validate().unwrap();
            assert_eq!(loaded.records[0].record_id.as_deref(), Some("12345"));
            if kind == "rainyun" {
                for value in ["", "0", "01", "abc", "../other"] {
                    c.providers[0]
                        .options
                        .insert("domain_id".into(), value.into());
                    assert!(c.validate().is_err());
                }
                c.providers[0].options.clear();
                assert!(c.validate().is_err());
            }
            if kind == "cloudns" {
                for value in ["auth-id", "sub-auth-id", "sub-auth-user"] {
                    c.providers[0]
                        .options
                        .insert("auth_type".into(), value.into());
                    c.validate().unwrap();
                }
                c.providers[0]
                    .options
                    .insert("auth_type".into(), "unknown".into());
                assert!(c.validate().is_err());
            }
        }
    }
    #[test]
    fn fifth_batch_config_requires_explicit_dynv6_ttl_capability() {
        let mut c = Config::default();
        let p = &mut c.providers[0];
        p.kind = "dynv6".into();
        p.secret_id_env.clear();
        p.secret_key_env.clear();
        p.token_env = "DYNV6_TOKEN".into();
        let mut r = record();
        r.subdomain = "home".into();
        r.record_id = Some("123".into());
        r.enabled = false;
        c.records.push(r);
        assert!(c.validate().is_err());
        c.providers[0]
            .options
            .insert("ttl_mode".into(), "provider_default".into());
        c.validate().unwrap();
        let saved: Config = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        saved.validate().unwrap();
        assert_eq!(saved.providers[0].options["ttl_mode"], "provider_default");
        c.providers[0]
            .options
            .insert("ttl_mode".into(), "fixed_60".into());
        assert!(c.validate().is_err());
        c.providers[0]
            .options
            .insert("ttl_mode".into(), "provider_default".into());
        c.records[0].subdomain = "@".into();
        assert!(c.validate().is_err());
        c.records[0].subdomain = "home".into();
        for id in ["01", "abc", "0", "9223372036854775808"] {
            c.records[0].record_id = Some(id.into());
            assert!(c.validate().is_err());
        }
        let p = &mut c.providers[0];
        p.kind = "spaceship".into();
        p.token_env.clear();
        p.options.clear();
        p.secret_id_env = "SPACESHIP_API_KEY".into();
        p.secret_key_env = "SPACESHIP_API_SECRET".into();
        c.records[0].subdomain = "@".into();
        c.records[0].record_id = Some(format!("rrset-{}", "a".repeat(64)));
        c.validate().unwrap();
        let loaded: Config = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        loaded.validate().unwrap();
        assert_eq!(loaded.records[0].record_id, c.records[0].record_id);
        c.providers[0]
            .options
            .insert("endpoint".into(), "https://evil.invalid".into());
        assert!(c.validate().is_err());
    }
    #[test]
    fn line_aliases_cannot_bypass_duplicate_target_guard() {
        let mut c = Config::default();
        c.records.push(record());
        let mut second = record();
        second.name = "second".into();
        second.record_line = "default".into();
        c.records.push(second);
        assert!(c.validate().unwrap_err().contains("Duplicate DNS target"));
        for kind in ["cloudflare", "dynv6", "spaceship", "gcore"] {
            let p = &mut c.providers[0];
            p.kind = kind.into();
            p.secret_id_env.clear();
            p.secret_key_env.clear();
            p.token_env.clear();
            p.options.clear();
            if kind == "spaceship" {
                p.secret_id_env = "SPACESHIP_API_KEY".into();
                p.secret_key_env = "SPACESHIP_API_SECRET".into();
            } else {
                p.token_env = match kind {
                    "cloudflare" => "CLOUDFLARE_TOKEN",
                    "dynv6" => "DYNV6_TOKEN",
                    _ => "GCORE_API_KEY",
                }
                .into();
            }
            if kind == "dynv6" {
                p.options
                    .insert("ttl_mode".into(), "provider_default".into());
            }
            c.records[1].record_line = "another-ignored-line".into();
            assert!(c.validate().unwrap_err().contains("Duplicate DNS target"));
        }
    }
    fn sixth_config(kind: &str) -> Config {
        let mut c = Config::default();
        let p = &mut c.providers[0];
        p.kind = kind.into();
        p.secret_id_env.clear();
        p.secret_key_env.clear();
        p.token_env = if kind == "namesilo" {
            "NAMESILO_KEY"
        } else {
            "HIPM_TOKEN"
        }
        .into();
        if kind == "hipmdnsmgr" {
            p.options
                .insert("endpoint_env".into(), "HIPM_ORIGIN".into());
        }
        let mut r = record();
        r.record_line = "default".into();
        r.enabled = false;
        r.record_id = Some(if kind == "namesilo" {
            format!("namesilo-{}", "a".repeat(64))
        } else {
            "native-123".into()
        });
        c.records.push(r);
        c
    }
    #[test]
    fn sixth_batch_scoped_references_and_id_roundtrip() {
        for kind in ["namesilo", "hipmdnsmgr"] {
            let mut c = sixth_config(kind);
            c.validate().unwrap();
            let loaded: Config = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
            loaded.validate().unwrap();
            assert_eq!(loaded.records[0].record_id, c.records[0].record_id);
            c.providers[0].token_env = "DDNS_SHARED_TOKEN".into();
            c.validate().unwrap();
            for name in ["PATH", "OTHER_TOKEN", "literal-secret"] {
                c.providers[0].token_env = name.into();
                assert!(c.validate().is_err());
            }
        }
    }
    #[test]
    fn hipm_endpoint_options_and_manager_ids_fail_closed() {
        for name in [
            "",
            "PATH",
            "DDNS_ORIGIN",
            "OTHER_ORIGIN",
            "HIPM_",
            "HIPM_lower",
            "http://127.0.0.1",
            "https://private.example",
        ] {
            let mut c = sixth_config("hipmdnsmgr");
            c.providers[0]
                .options
                .insert("endpoint_env".into(), name.into());
            assert!(c.validate().is_err());
        }
        for name in [format!("HIPM_{}", "A".repeat(60)), "HIPM_ORIGIN\n".into()] {
            let mut c = sixth_config("hipmdnsmgr");
            c.providers[0].options.insert("endpoint_env".into(), name);
            assert!(c.validate().is_err());
        }
        let mut c = sixth_config("hipmdnsmgr");
        c.providers[0]
            .options
            .insert("domain_id".into(), i64::MAX.to_string());
        c.validate().unwrap();
        for id in ["", "0", "01", "-1", "+1", "1.0", "9223372036854775808"] {
            c.providers[0].options.insert("domain_id".into(), id.into());
            assert!(c.validate().is_err());
        }
        for kind in ["namesilo", "hipmdnsmgr"] {
            for key in ["endpoint", "url", "insecure", "ttl_mode"] {
                let mut c = sixth_config(kind);
                c.providers[0]
                    .options
                    .insert(key.into(), "https://private.example".into());
                assert!(c.validate().is_err());
            }
        }
        c = sixth_config("hipmdnsmgr");
        c.providers[0].options.clear();
        assert!(c.validate().is_err());
    }
    #[test]
    fn hipm_native_line_and_duplicate_aliases_are_validated_before_io() {
        for line in ["默认", " default", "default ", "def\tault", "def\nault"] {
            let mut c = sixth_config("hipmdnsmgr");
            c.records[0].record_line = line.into();
            assert!(c.validate().is_err());
        }
        let mut c = sixth_config("hipmdnsmgr");
        let mut r = c.records[0].clone();
        r.name = "other".into();
        r.record_id = None;
        r.record_line = "DEFAULT".into();
        c.records.push(r);
        assert!(c.validate().unwrap_err().contains("Duplicate DNS target"));
        c.records[1].record_line = "telecom".into();
        c.validate().unwrap();
        c.records[1].record_id = c.records[0].record_id.clone();
        assert!(
            c.validate()
                .unwrap_err()
                .contains("Duplicate explicit RecordId")
        );
    }
    fn seventh_config(kind: &str) -> Config {
        let mut c = Config::default();
        let p = &mut c.providers[0];
        p.kind = kind.into();
        let prefix = match kind {
            "huaweicloud" => "HUAWEICLOUD_",
            "baiducloud" => "BAIDUCLOUD_",
            _ => "EDGEONE_",
        };
        p.secret_id_env = format!("{prefix}ID");
        p.secret_key_env = format!("{prefix}KEY");
        p.options = match kind {
            "huaweicloud" => BTreeMap::from([
                ("region".into(), "cn-north-4".into()),
                ("project_id".into(), "project-native".into()),
                ("zone_id".into(), "zone-native".into()),
            ]),
            "baiducloud" => BTreeMap::from([("resource_id".into(), "resource-native".into())]),
            _ => BTreeMap::from([
                ("mode".into(), "dns".into()),
                ("scope".into(), "teodns".into()),
                ("api_version".into(), "2022-09-01".into()),
                ("zone_id".into(), "zone-native".into()),
            ]),
        };
        let mut r = record();
        r.subdomain = "home.nested".into();
        r.enabled = false;
        r.record_id = Some(
            match kind {
                "huaweicloud" => "rrset-native",
                "baiducloud" => "2147483647",
                _ => "record-native",
            }
            .into(),
        );
        c.records.push(r);
        c
    }
    #[tokio::test]
    async fn seventh_batch_options_native_ids_and_env_references_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        for kind in ["huaweicloud", "baiducloud", "edgeone"] {
            let mut c = seventh_config(kind);
            c.validate().unwrap();
            let path = dir.path().join(format!("{kind}.toml"));
            c.save(&path).await.unwrap();
            let loaded = Config::load(&path).await.unwrap();
            assert_eq!(loaded.providers[0].options, c.providers[0].options);
            assert_eq!(loaded.records[0].record_id, c.records[0].record_id);
            c.providers[0].secret_id_env = "DDNS_SHARED_ID".into();
            c.providers[0].secret_key_env = "DDNS_SHARED_KEY".into();
            c.validate().unwrap();
            for key in ["endpoint", "region_override", "group", "min_ttl"] {
                let mut bad = c.clone();
                bad.providers[0]
                    .options
                    .insert(key.into(), "untrusted".into());
                assert!(bad.validate().is_err());
            }
            for value in ["PATH", "OTHER_SECRET", "literal-secret", "DDNS_"] {
                let mut bad = c.clone();
                bad.providers[0].secret_key_env = value.into();
                assert!(bad.validate().is_err());
            }
            for key in crate::providers::registry::descriptor(kind)
                .unwrap()
                .options
                .into_iter()
                .filter(|f| f.required)
                .map(|f| f.key)
            {
                let mut bad = c.clone();
                bad.providers[0].options.remove(key);
                assert!(bad.validate().is_err());
            }
        }
    }
    #[test]
    fn seventh_batch_options_ids_lines_and_ttl_fail_before_io() {
        for (kind, key, values) in [
            (
                "huaweicloud",
                "region",
                vec!["cn-fake-1", "cn-north-4.evil", "https://evil"],
            ),
            (
                "huaweicloud",
                "project_id",
                vec![".", "..", "0", "../project", "https://evil"],
            ),
            ("huaweicloud", "zone_id", vec![".", "..", "zone/other"]),
            (
                "baiducloud",
                "resource_id",
                vec![".", "..", "0", "resource/other"],
            ),
            ("edgeone", "mode", vec!["origin", "DNS"]),
            ("edgeone", "scope", vec!["origin", "dns"]),
            ("edgeone", "api_version", vec!["latest", "2020-01-01"]),
            (
                "edgeone",
                "zone_id",
                vec!["origin-native", "zone/other", "../zone-native"],
            ),
        ] {
            for value in values {
                let mut c = seventh_config(kind);
                c.providers[0].options.insert(key.into(), value.into());
                assert!(c.validate().is_err(), "{kind} {key}={value}");
            }
        }
        for (kind, ids, ttls, lines) in [
            (
                "huaweicloud",
                vec![".", "..", "rrset/other"],
                vec![1, 299],
                vec!["DEFAULT", "telecom"],
            ),
            (
                "baiducloud",
                vec!["01", "+1", "0", "2147483648", "record-native"],
                vec![1, 59, 3601],
                vec!["Default", "cmnet", "telecom"],
            ),
            (
                "edgeone",
                vec!["origin-native", "record/other"],
                vec![1, 59, 86401],
                vec!["Default\n", "CN.\0BJ"],
            ),
        ] {
            for id in ids {
                let mut c = seventh_config(kind);
                c.records[0].record_id = Some(id.into());
                assert!(c.validate().is_err());
            }
            for ttl in ttls {
                let mut c = seventh_config(kind);
                c.records[0].ttl = ttl;
                assert!(c.validate().is_err());
            }
            for line in lines {
                let mut c = seventh_config(kind);
                c.records[0].record_line = line.into();
                assert!(c.validate().is_err());
            }
        }
        let mut c = seventh_config("huaweicloud");
        c.records[0]
            .options
            .insert("zone_id".into(), "zone-native".into());
        c.validate().unwrap();
        c.records[0]
            .options
            .insert("zone_id".into(), "zone-other".into());
        assert!(c.validate().is_err());
        c.providers[0].options.remove("zone_id");
        c.validate().unwrap();
        for id in [".", "..", "zone/other"] {
            c.records[0].options.insert("zone_id".into(), id.into());
            assert!(c.validate().is_err());
        }
        for region in ["cn-east-2", "my-kualalumpur-1", "ap-southeast-5"] {
            let mut c = seventh_config("huaweicloud");
            c.providers[0]
                .options
                .insert("region".into(), region.into());
            c.validate().unwrap();
        }
    }
    #[test]
    fn seventh_batch_native_default_aliases_and_routed_identity() {
        for (kind, aliases, routed) in [
            ("huaweicloud", vec!["default", "default_view", "默认"], None),
            (
                "baiducloud",
                vec!["default", "DEFAULT", "默认"],
                Some("CMNET"),
            ),
            ("edgeone", vec!["default", "Default", "默认"], Some("CN.BJ")),
        ] {
            for alias in aliases {
                let mut c = seventh_config(kind);
                let mut other = c.records[0].clone();
                other.name = "second".into();
                other.record_id = None;
                other.record_line = alias.into();
                c.records.push(other);
                assert!(
                    c.validate().unwrap_err().contains("Duplicate DNS target"),
                    "{kind} {alias}"
                );
                if let Some(line) = routed {
                    c.records[1].record_line = line.into();
                    c.validate().unwrap();
                }
            }
        }
        for line in ["DEFAULT", "CMNET", "CNC", "EDU", "SEARCH"] {
            let mut c = seventh_config("baiducloud");
            c.records[0].record_line = line.into();
            c.validate().unwrap();
        }
        for (kind, boundaries) in [
            ("huaweicloud", vec![300, 604800]),
            ("baiducloud", vec![60, 3600]),
            ("edgeone", vec![60, 86400]),
        ] {
            for ttl in boundaries {
                let mut c = seventh_config(kind);
                c.records[0].ttl = ttl;
                c.validate().unwrap();
            }
        }
    }
    #[tokio::test]
    async fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let c = Config::default();
        c.save(&path).await.unwrap();
        assert_eq!(Config::load(&path).await.unwrap().interval_secs, 300);
    }
    fn eighth_config(kind: &str) -> Config {
        let mut c = Config::default();
        let p = &mut c.providers[0];
        p.kind = kind.into();
        p.secret_id_env.clear();
        p.secret_key_env.clear();
        if kind == "trafficroute" {
            p.secret_id_env = "TRAFFICROUTE_AK".into();
            p.secret_key_env = "TRAFFICROUTE_SK".into();
            p.options = [
                ("scope", "public_dns"),
                ("api_version", "2018-08-01"),
                ("region", "cn-beijing"),
                ("zone_id", "123"),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        } else {
            p.token_env = "CALLBACK_ACCOUNT_TOKEN".into();
            p.options = [
                ("endpoint_env", "CALLBACK_ACCOUNT_ENDPOINT"),
                ("mode", "json_post"),
                ("verification", "unverified"),
                ("delivery", "every_run"),
                ("ttl_mode", "metadata_only"),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        }
        c.records.push(record());
        c
    }
    #[test]
    fn eighth_batch_options_and_credential_names_are_strict() {
        for kind in ["trafficroute", "callback"] {
            eighth_config(kind).validate().unwrap();
            let good = eighth_config(kind);
            for key in good.providers[0].options.keys() {
                let mut c = good.clone();
                c.providers[0].options.remove(key);
                assert!(c.validate().is_err());
                let mut c = good.clone();
                c.providers[0].options.insert(key.clone(), "wrong".into());
                assert!(c.validate().is_err());
            }
            let mut c = good.clone();
            c.providers[0]
                .options
                .insert("endpoint".into(), "https://evil.invalid/".into());
            assert!(c.validate().is_err());
        }
        for name in [
            "CALLBACK_",
            "PATH",
            "DDNS_ENDPOINT",
            "CALLBACK_lower",
            "https://evil.invalid/",
        ] {
            let mut c = eighth_config("callback");
            c.providers[0]
                .options
                .insert("endpoint_env".into(), name.into());
            assert!(c.validate().is_err());
        }
        let mut c = eighth_config("callback");
        c.providers[0].token_env = "DDNS_CUSTOM_ACCOUNT".into();
        c.validate().unwrap();
    }
    #[test]
    fn eighth_batch_traffic_native_ids_lines_and_account_ttl_contract() {
        for id in ["1", "9223372036854775807"] {
            let mut c = eighth_config("trafficroute");
            c.records[0].record_id = Some(id.into());
            c.validate().unwrap();
        }
        for id in ["01", "0", "9223372036854775808", "native-id", ".."] {
            let mut c = eighth_config("trafficroute");
            c.records[0].record_id = Some(id.into());
            assert!(c.validate().is_err());
        }
        for ttl in [1, 86400] {
            let mut c = eighth_config("trafficroute");
            c.records[0].ttl = ttl;
            c.validate().unwrap();
        }
        let mut c = eighth_config("trafficroute");
        c.records[0].ttl = 86401;
        assert!(c.validate().is_err());
        for line in ["bad line", "bad/line", "..", "default\n"] {
            let mut c = eighth_config("trafficroute");
            c.records[0].record_line = line.into();
            assert!(c.validate().is_err());
        }
        for alias in ["", "default", "默认"] {
            let mut c = eighth_config("trafficroute");
            let mut r = c.records[0].clone();
            r.name = "second".into();
            r.record_line = alias.into();
            c.records.push(r);
            assert!(c.validate().is_err());
            c.records[1].record_line = "DEFAULT".into();
            c.validate().unwrap();
        }
    }
    #[test]
    fn eighth_batch_callback_no_dns_selection_and_line_ignored_identity() {
        let good = eighth_config("callback");
        let mut c = good.clone();
        c.records[0].record_id = Some("123".into());
        assert!(c.validate().is_err());
        let mut c = good.clone();
        c.records[0].create_if_missing = true;
        assert!(c.validate().is_err());
        let mut c = good.clone();
        c.records[0].options.insert("line".into(), "telecom".into());
        assert!(c.validate().is_err());
        let mut c = good.clone();
        let mut other = c.records[0].clone();
        other.name = "second".into();
        other.record_line = "telecom".into();
        c.records.push(other);
        assert!(c.validate().is_err());
        let mut c = good;
        c.records[0].record_line.clear();
        c.validate().unwrap();
    }
    fn namecheap_config() -> Config {
        let mut c: Config = toml::from_str(include_str!("../examples/namecheap.toml")).unwrap();
        c.records[0].ip_source = IpSource {
            kind: "static".into(),
            value: "1.1.1.1".into(),
            regex: None,
        };
        c
    }
    fn namecheap_id(domain: &str, owner: &str, kind: &str) -> String {
        use sha2::{Digest, Sha256};
        format!(
            "namecheap-{}",
            hex::encode(Sha256::digest(
                format!("{domain}\0{owner}\0{kind}").as_bytes()
            ))
        )
    }
    #[test]
    fn namecheap_local_refs_only_options_and_credentials() {
        let good = namecheap_config();
        good.validate().unwrap(); // No environment lookup even with absent references.
        for key in good.providers[0].options.keys() {
            let mut c = good.clone();
            c.providers[0].options.remove(key);
            assert!(c.validate().is_err(), "missing {key}");
        }
        for (key, value) in [
            ("scope", "basicdns"),
            ("write_mode", "per_record"),
            ("environment", "auto"),
            ("sld", "example.com"),
            ("tld", ".com"),
            ("tld", "toolongfortld"),
            ("client_ip_env", "DDNS_SERVER_IP"),
            ("client_ip_env", "PATH"),
            ("client_ip_env", "1.1.1.1"),
            ("client_ip_env", "NAMECHEAP_"),
            ("client_ip_env", "NAMECHEAP_lower"),
            ("endpoint", "https://evil.invalid/"),
            ("EmailType", "MX"),
        ] {
            let mut c = good.clone();
            c.providers[0].options.insert(key.into(), value.into());
            assert!(c.validate().is_err(), "{key} {value}");
        }
        for name in ["NAMECHEAP_", "PATH", "OTHER_KEY", "literal-password"] {
            let mut c = good.clone();
            c.providers[0].secret_key_env = name.into();
            assert!(c.validate().is_err());
        }
        for prefix in ["NAMECHEAP_ACCOUNT2_", "DDNS_ACCOUNT3_"] {
            let mut c = good.clone();
            c.providers[0].secret_id_env = format!("{prefix}TOKEN");
            c.providers[0].secret_key_env = format!("{prefix}KEY");
            c.validate().unwrap();
        }
        let mut c = good;
        c.providers[0].token_env = "NAMECHEAP_TOKEN".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn namecheap_exact_scope_ids_domain_ttl_lines_and_creation() {
        let good = namecheap_config();
        for owner in ["home", "home.nested", "@", ""] {
            let mut c = good.clone();
            c.records[0].subdomain = owner.into();
            c.records[0].record_id = Some(namecheap_id(
                "example.com",
                if owner.is_empty() { "@" } else { owner },
                "A",
            ));
            c.records[0].create_if_missing = true;
            c.validate().unwrap();
        }
        for id in [
            "123".into(),
            "../123".into(),
            namecheap_id("example.com", "other", "A"),
            namecheap_id("other.com", "home", "A"),
            namecheap_id("example.com", "home", "AAAA"),
        ] {
            let mut c = good.clone();
            c.records[0].record_id = Some(id);
            assert!(c.validate().is_err());
        }
        for line in ["Default", "telecom", " default", "default\n"] {
            let mut c = good.clone();
            c.records[0].record_line = line.into();
            assert!(c.validate().is_err());
        }
        for ttl in [59, 60001] {
            let mut c = good.clone();
            c.records[0].ttl = ttl;
            assert!(c.validate().is_err());
        }
        for domain in ["home.example.com", "example.net"] {
            let mut c = good.clone();
            c.records[0].domain = domain.into();
            assert!(c.validate().is_err());
        }
        let mut c = good.clone();
        c.providers[0].options.insert("tld".into(), "co.uk".into());
        c.records[0].domain = "example.co.uk".into();
        c.validate().unwrap();
        let mut c = good;
        c.records[0].options.insert("proxied".into(), "true".into());
        assert!(c.validate().is_err());
    }
    #[test]
    fn namecheap_default_aliases_and_empty_apex_share_identity() {
        for line in ["", "default", "默认"] {
            let mut c = namecheap_config();
            c.records[0].record_line = line.into();
            c.validate().unwrap();
            let mut r = c.records[0].clone();
            r.name = "duplicate".into();
            r.record_line = "default".into();
            c.records.push(r);
            assert!(c.validate().is_err());
        }
        let mut c = namecheap_config();
        c.records[0].subdomain.clear();
        let mut r = c.records[0].clone();
        r.name = "duplicate".into();
        r.subdomain = "@".into();
        c.records.push(r);
        assert!(c.validate().is_err());
    }
}
