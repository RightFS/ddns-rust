//! First-party Namecheap account API, NOT the Dynamic DNS password endpoint.
//! Narrow plain BasicDNS whole-host replacement. Caller MUST disable redirects
//! and automatic retries. Exclusive writer consent is NOT CAS. See contract note.
#![allow(clippy::result_large_err)]
use super::common::{Adapter, List, Mutation, NameFormat, Record, Spec, local_error};
use crate::provider::ProviderError;
use chrono::{NaiveDate, Utc};
use quick_xml::{
    events::{BytesStart, Event},
    name::ResolveResult,
    reader::NsReader,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
const PROD: &str = "https://api.namecheap.com/xml.response";
const SANDBOX: &str = "https://api.sandbox.namecheap.com/xml.response";
const NS: [&str; 2] = [
    "http://api.namecheap.com/xml.response",
    "https://api.namecheap.com/xml.response",
];
const LIMIT: usize = 1024 * 1024;
const CAP: usize = 800;
const HINT: &str = "BasicDNS plain host scope only. Account API username/key and whitelisted server egress IPv4 differ from DDNS password/target IP. setHosts replaces the entire host array; exclusive writer consent is an assumption, not CAS. EmailType is deliberately omitted to preserve mail routing. Inspect uncertain writes before a manual retry; no automatic mutation retry occurred.";
fn err(stage: &str, code: &str, msg: &str) -> ProviderError {
    local_error(stage, code, msg, HINT, None)
}
fn dns_name(s: &str, underscore: bool) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || (underscore && b == b'_'))
        })
}
fn relative(s: &str) -> bool {
    s == "@" || dns_name(s, true)
}
fn integer(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        None
    } else {
        s.parse().ok()
    }
}
fn boolean(s: &str) -> Option<bool> {
    match s {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}
fn mail_mode(s: &str) -> bool {
    matches!(s, "NONE" | "MX" | "MXE" | "FWD" | "OX" | "GMAIL")
}
fn logical_id(s: &Spec) -> String {
    let host = if matches!(s.subdomain.as_str(), "" | "@") {
        "@"
    } else {
        &s.subdomain
    };
    format!(
        "namecheap-{}",
        hex::encode(Sha256::digest(
            format!(
                "{}\0{}\0{}",
                s.domain.to_ascii_lowercase(),
                host.to_ascii_lowercase(),
                s.record_type
            )
            .as_bytes()
        ))
    )
}
#[cfg(test)]
pub fn check_options(o: &BTreeMap<String, String>) -> Result<(), ProviderError> {
    check_options_with_direct(o, false)
}
pub fn check_options_with_direct(
    o: &BTreeMap<String, String>,
    direct: bool,
) -> Result<(), ProviderError> {
    if o.get("scope").map(String::as_str) != Some("basicdns_plain")
        || o.get("write_mode").map(String::as_str) != Some("exclusive_full_zone")
    {
        return Err(err(
            "configuration",
            "InvalidScope",
            "Explicit scope=basicdns_plain and write_mode=exclusive_full_zone required.",
        ));
    }
    if !matches!(
        o.get("environment").map(String::as_str),
        Some("production" | "sandbox")
    ) {
        return Err(err(
            "configuration",
            "InvalidEnvironment",
            "Select production or sandbox explicitly; no fallback.",
        ));
    }
    if o.keys().any(|k| {
        ![
            "scope",
            "write_mode",
            "environment",
            "sld",
            "tld",
            "client_ip_env",
        ]
        .contains(&k.as_str())
    }) {
        return Err(err(
            "configuration",
            "UnsupportedProviderOptions",
            "Unknown provider option; no endpoint/mailmode override.",
        ));
    }
    let sld = o.get("sld").map(String::as_str).unwrap_or("");
    let tld = o.get("tld").map(String::as_str).unwrap_or("");
    if sld.contains('.')
        || !dns_name(sld, false)
        || sld.len() > 63
        || !dns_name(tld, false)
        || tld.len() > 10
        || format!("{sld}.{tld}").len() > 253
    {
        return Err(err(
            "configuration",
            "InvalidDomainParts",
            "Explicit ASCII/punycode sld and tld required (tld may contain dots, max 10 bytes); no PSL/URL guessing.",
        ));
    }
    let name = o.get("client_ip_env").map(String::as_str).unwrap_or("");
    if !(name.is_empty() && direct)
        && (!(11..=64).contains(&name.len())
            || !name.starts_with("NAMECHEAP_")
            || !name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'))
    {
        return Err(err(
            "configuration",
            "InvalidClientIpEnv",
            "client_ip_env must be a bounded uppercase NAMECHEAP_ server reference, not an IP/URL/arbitrary environment name.",
        ));
    }
    Ok(())
}
pub fn check_credentials(user: &str, key: &str) -> Result<(), ProviderError> {
    if !(1..=64).contains(&user.len())
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        || !(1..=256).contains(&key.len())
        || key.bytes().any(|b| !b.is_ascii_graphic())
    {
        return Err(err(
            "credentials",
            "InvalidCredentials",
            "Require plain bounded Namecheap API username/key without whitespace/control characters.",
        ));
    }
    Ok(())
}
pub fn check_client_ip_value(value: &str) -> Result<String, ProviderError> {
    let ip=value.parse::<Ipv4Addr>().map_err(|_|err("credentials","InvalidClientIp","ClientIp must be a public whitelisted server egress IPv4, not DDNS target/IPv6/URL/CIDR."))?;
    let [a, b, _, _] = ip.octets();
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 192 && b == 0)
    {
        return Err(err(
            "credentials",
            "InvalidClientIp",
            "ClientIp must be public server-owned IPv4; reserved/private ranges refused.",
        ));
    }
    Ok(ip.to_string())
}
fn resolve_client_ip_with_direct(
    o: &BTreeMap<String, String>,
    direct: Option<&str>,
) -> Result<String, ProviderError> {
    check_options_with_direct(o, direct.is_some())?;
    if let Some(value) = direct {
        return check_client_ip_value(value);
    }
    let v=std::env::var(&o["client_ip_env"]).map_err(|_|err("credentials","MissingClientIp","Set and whitelist the configured NAMECHEAP_ server egress IPv4 in the selected environment."))?;
    check_client_ip_value(&v)
}
pub fn check_client_ip_with_direct(
    o: &BTreeMap<String, String>,
    direct: Option<&str>,
) -> Result<(), ProviderError> {
    resolve_client_ip_with_direct(o, direct).map(|_| ())
}
#[cfg(test)]
pub fn check_spec(s: &Spec, o: &BTreeMap<String, String>) -> Result<(), ProviderError> {
    check_spec_with_direct(s, o, false)
}
pub fn check_spec_with_direct(
    s: &Spec,
    o: &BTreeMap<String, String>,
    direct: bool,
) -> Result<(), ProviderError> {
    check_options_with_direct(o, direct)?;
    if !s
        .domain
        .eq_ignore_ascii_case(&format!("{}.{}", o["sld"], o["tld"]))
    {
        return Err(err(
            "validation",
            "DomainMismatch",
            "Record domain must equal configured sld.tld; no zone inference.",
        ));
    }
    if !matches!(s.record_type.as_str(), "A" | "AAAA") || !(60..=60000).contains(&s.ttl) {
        return Err(err(
            "validation",
            "UnsupportedRecordTypeOrTTL",
            "Singleton A/AAAA target with TTL60..60000 required; no clamping.",
        ));
    }
    if !(matches!(s.subdomain.as_str(), "" | "@") || dns_name(&s.subdomain, false))
        || s.fqdn().len() > 253
    {
        return Err(err(
            "validation",
            "InvalidDnsName",
            "Use relative labels or @/empty apex; trailing-dot owners refused rather than qualification guesses.",
        ));
    }
    if !matches!(s.record_line.as_str(), "" | "default" | "默认") || !s.options.is_empty() {
        return Err(err(
            "validation",
            "UnsupportedRecordOptions",
            "No routing line or record options in BasicDNS plain scope.",
        ));
    }
    if s.record_id.as_ref().is_some_and(|id| id != &logical_id(s)) {
        return Err(err(
            "validation",
            "InvalidLogicalRecordId",
            "Only stable namecheap owner/type logical ID allowed; native HostId pinning refused.",
        ));
    }
    Ok(())
}
fn desired(s: &Spec, ip: &str) -> Result<String, ProviderError> {
    ip.parse::<IpAddr>()
        .ok()
        .filter(|v| v.is_ipv4() == (s.record_type == "A"))
        .map(|v| v.to_string())
        .ok_or_else(|| {
            err(
                "validation",
                "InvalidIp",
                "Desired literal IP family is invalid.",
            )
        })
}

// Tree is produced by quick-xml. Never Debug/Serialize: transient getInfo may
// include contact information or DynamicDNSPassword, which is not snapshotted.
struct Node {
    name: String,
    attrs: BTreeMap<String, String>,
    text: String,
    children: Vec<Node>,
}
impl Node {
    fn attr(&self, k: &str) -> Result<&str, ProviderError> {
        self.attrs.get(k).map(String::as_str).ok_or_else(|| {
            err(
                "xml",
                "MalformedResponse",
                "Required XML attribute missing; no default substituted.",
            )
        })
    }
    fn one(&self, k: &str) -> Result<&Node, ProviderError> {
        self.optional(k)?.ok_or_else(|| {
            err(
                "xml",
                "MalformedResponse",
                "Required XML result/container missing; absent inventory is not an empty zone.",
            )
        })
    }
    fn optional(&self, k: &str) -> Result<Option<&Node>, ProviderError> {
        let mut iter = self.children.iter().filter(|n| n.name == k);
        let n = iter.next();
        if iter.next().is_some() {
            return Err(err(
                "xml",
                "MalformedResponse",
                "Duplicate XML singleton/result.",
            ));
        }
        Ok(n)
    }
    fn attrs_only(&self, keys: &[&str]) -> Result<(), ProviderError> {
        if self.attrs.keys().any(|k| !keys.contains(&k.as_str())) {
            return Err(err(
                "xml",
                "UnsupportedXmlSettings",
                "Unknown XML attributes/settings cannot be dropped.",
            ));
        }
        Ok(())
    }
    fn children_only(&self, keys: &[&str]) -> Result<(), ProviderError> {
        if self
            .children
            .iter()
            .any(|n| !keys.contains(&n.name.as_str()))
            || !self.text.trim().is_empty()
        {
            return Err(err(
                "xml",
                "UnsupportedXmlSettings",
                "Unknown XML elements/settings or mixed content refused.",
            ));
        }
        Ok(())
    }
    fn leaf(&self) -> Result<&str, ProviderError> {
        if !self.children.is_empty() {
            return Err(err(
                "xml",
                "MalformedResponse",
                "Expected scalar XML value.",
            ));
        }
        Ok(self.text.trim())
    }
}
fn xml_chars(s: &str) -> bool {
    s.chars().all(|c| {
        matches!(c, '\t' | '\n' | '\r')
            || ('\u{20}'..='\u{d7ff}').contains(&c)
            || ('\u{e000}'..='\u{fffd}').contains(&c)
            || c >= '\u{10000}'
    })
}
fn xml_attrs(
    start: &BytesStart<'_>,
    decoder: quick_xml::encoding::Decoder,
) -> Result<BTreeMap<String, String>, ProviderError> {
    let mut out = BTreeMap::new();
    for (i, a) in start.attributes().with_checks(true).enumerate() {
        if i >= 32 {
            return Err(err("xml", "XmlLimit", "XML attribute count limit."));
        }
        let a = a.map_err(|_| {
            err(
                "xml",
                "MalformedXml",
                "Malformed/duplicate XML attribute; raw body omitted.",
            )
        })?;
        if a.value.as_ref().contains(&b'<') {
            return Err(err(
                "xml",
                "MalformedXml",
                "Literal less-than in XML attribute is invalid.",
            ));
        }
        let k = std::str::from_utf8(a.key.as_ref())
            .map_err(|_| err("xml", "MalformedXml", "Invalid UTF8 attribute."))?;
        let v = a.decode_and_unescape_value(decoder).map_err(|_| {
            err(
                "xml",
                "MalformedXml",
                "Unknown/custom XML entity or malformed attribute.",
            )
        })?;
        if k.len() > 80 || v.len() > 8192 || !xml_chars(&v) {
            return Err(err(
                "xml",
                "XmlLimit",
                "XML attribute bounds/characters exceeded.",
            ));
        }
        if k == "xmlns" || k.starts_with("xmlns:") {
            if !NS.contains(&v.as_ref()) {
                return Err(err(
                    "xml",
                    "XmlNamespace",
                    "Unknown namespace binding; spoofing refused.",
                ));
            }
            continue;
        }
        if k.contains(':')
            || !k
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(err(
                "xml",
                "XmlNamespace",
                "Namespaced/unsupported attribute names refused.",
            ));
        }
        if out.insert(k.into(), v.into_owned()).is_some() {
            return Err(err("xml", "MalformedXml", "Duplicate XML attribute."));
        }
    }
    Ok(out)
}
fn parse_xml(bytes: &[u8]) -> Result<Node, ProviderError> {
    if bytes.len() > LIMIT {
        return Err(err("xml", "ResponseTooLarge", "XML exceeded1MiB."));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        err(
            "xml",
            "MalformedXml",
            "Only UTF8 XML accepted; body omitted.",
        )
    })?;
    if !xml_chars(text) {
        return Err(err("xml", "MalformedXml", "Invalid XML characters."));
    }
    let mut reader = NsReader::from_str(text);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<Node> = vec![];
    let mut root = None;
    let mut declaration = false;
    let mut tokens = 0;
    loop {
        tokens += 1;
        if tokens > 24000 {
            return Err(err("xml", "XmlLimit", "XML token bound exceeded."));
        }
        let decoder = reader.decoder();
        let (namespace, event) = reader
            .read_resolved_event()
            .map_err(|_| err("xml", "MalformedXml", "Malformed XML; raw body omitted."))?;
        let good = match namespace {
            ResolveResult::Bound(n) => NS.iter().any(|v| n.as_ref() == v.as_bytes()),
            _ => false,
        };
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                if !good {
                    return Err(err(
                        "xml",
                        "XmlNamespace",
                        "API element has missing/unknown namespace.",
                    ));
                }
                let name = std::str::from_utf8(start.local_name().as_ref())
                    .map_err(|_| err("xml", "MalformedXml", "Invalid XML element."))?
                    .to_string();
                if name.is_empty()
                    || name.len() > 80
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                {
                    return Err(err("xml", "MalformedXml", "Unsupported element name."));
                }
                let n = Node {
                    name,
                    attrs: xml_attrs(&start, decoder)?,
                    text: String::new(),
                    children: vec![],
                };
                if stack.len() >= 16 || (stack.is_empty() && root.is_some()) {
                    return Err(err(
                        "xml",
                        "XmlLimit",
                        "XML depth/single-root invariant failed.",
                    ));
                }
                if empty {
                    if let Some(p) = stack.last_mut() {
                        p.children.push(n);
                    } else {
                        root = Some(n);
                    }
                } else {
                    stack.push(n);
                }
            }
            Event::End(_) => {
                if !good {
                    return Err(err("xml", "XmlNamespace", "Invalid closing namespace."));
                }
                let n = stack
                    .pop()
                    .ok_or_else(|| err("xml", "MalformedXml", "Unmatched XML close."))?;
                if let Some(p) = stack.last_mut() {
                    p.children.push(n);
                } else if root.replace(n).is_some() {
                    return Err(err("xml", "MalformedXml", "Multiple roots."));
                }
            }
            Event::Text(t) => {
                let decoded = t
                    .decode()
                    .map_err(|_| err("xml", "MalformedXml", "Invalid text encoding."))?;
                if let Some(n) = stack.last_mut() {
                    n.text.push_str(&decoded);
                    if n.text.len() > 8192 {
                        return Err(err("xml", "XmlLimit", "XML scalar too large."));
                    }
                } else if !decoded.trim().is_empty() {
                    return Err(err("xml", "MalformedXml", "Text outside root."));
                }
            }
            Event::GeneralRef(r) => {
                let name = r
                    .decode()
                    .map_err(|_| err("xml", "MalformedXml", "Invalid entity."))?;
                let c = match name.as_ref() {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    _ => r
                        .resolve_char_ref()
                        .map_err(|_| err("xml", "MalformedXml", "Invalid character reference."))?
                        .ok_or_else(|| {
                            err("xml", "MalformedXml", "Unknown/custom entities refused.")
                        })?,
                };
                if !xml_chars(&c.to_string()) {
                    return Err(err("xml", "MalformedXml", "Invalid referenced character."));
                }
                let n = stack
                    .last_mut()
                    .ok_or_else(|| err("xml", "MalformedXml", "Reference outside root."))?;
                n.text.push(c);
                if n.text.len() > 8192 {
                    return Err(err("xml", "XmlLimit", "XML scalar too large."));
                }
            }
            Event::CData(t) => {
                let d = t
                    .decode()
                    .map_err(|_| err("xml", "MalformedXml", "Invalid CDATA encoding."))?;
                let n = stack
                    .last_mut()
                    .ok_or_else(|| err("xml", "MalformedXml", "CDATA outside root."))?;
                n.text.push_str(&d);
                if n.text.len() > 8192 {
                    return Err(err("xml", "XmlLimit", "XML scalar too large."));
                }
            }
            Event::Decl(d) => {
                if declaration
                    || tokens != 1
                    || root.is_some()
                    || !stack.is_empty()
                    || d.version().ok().as_deref() != Some(b"1.0")
                    || d.encoding()
                        .transpose()
                        .map_err(|_| err("xml", "MalformedXml", "Invalid encoding declaration."))?
                        .is_some_and(|v| !v.eq_ignore_ascii_case(b"UTF-8"))
                    || d.standalone()
                        .transpose()
                        .map_err(|_| err("xml", "MalformedXml", "Invalid declaration."))?
                        .is_some_and(|s| s.as_ref() != b"yes" && s.as_ref() != b"no")
                {
                    return Err(err(
                        "xml",
                        "MalformedXml",
                        "Only one XML1.0 UTF8 declaration supported.",
                    ));
                }
                let raw = std::str::from_utf8(d.as_ref())
                    .map_err(|_| err("xml", "MalformedXml", "Invalid declaration."))?;
                let declaration_start = BytesStart::from_content(raw, 3);
                for attribute in declaration_start.attributes().with_checks(true) {
                    let attribute = attribute.map_err(|_| {
                        err(
                            "xml",
                            "MalformedXml",
                            "Malformed/duplicate declaration attribute.",
                        )
                    })?;
                    if ![
                        b"version".as_slice(),
                        b"encoding".as_slice(),
                        b"standalone".as_slice(),
                    ]
                    .contains(&attribute.key.as_ref())
                    {
                        return Err(err("xml", "MalformedXml", "Unknown declaration attribute."));
                    }
                }
                let _ = xml_attrs(&declaration_start, decoder)?;
                declaration = true;
            }
            Event::Eof => {
                if !stack.is_empty() {
                    return Err(err("xml", "MalformedXml", "Truncated document."));
                }
                break;
            }
            Event::DocType(_) | Event::PI(_) | Event::Comment(_) => {
                return Err(err(
                    "xml",
                    "UnsafeXml",
                    "DTD/DOCTYPE/entities, instructions and extensions refused.",
                ));
            }
        }
    }
    root.ok_or_else(|| err("xml", "MalformedXml", "Missing XML document/root."))
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Row {
    native_id: Option<String>,
    name: String,
    kind: String,
    address: String,
    ttl: String,
    mx: String,
    active: bool,
    ddns: bool,
    app: String,
    friendly: String,
}
impl Row {
    fn validate(&self, domain: &str, mode: &str) -> Result<(), ProviderError> {
        if !self.active || self.ddns || !self.app.is_empty() || !self.friendly.is_empty() {
            return Err(err(
                "selection",
                "UnsupportedRecordControls",
                "All zone rows must be explicitly active/nonDDNS and without app/friendly metadata.",
            ));
        }
        if !["A", "AAAA", "TXT", "CNAME", "NS", "MX"].contains(&self.kind.as_str())
            || (self.kind == "MX" && mode != "MX")
        {
            return Err(err(
                "selection",
                "UnsupportedRecordType",
                "Unrepresentable zone type/MX outside MX mailmode; no planning/replacement.",
            ));
        }
        if !relative(&self.name)
            || (self.name != "@" && format!("{}.{}", self.name, domain).len() > 253)
        {
            return Err(err(
                "selection",
                "UnsupportedNativeName",
                "Native @ or relative labels only; trailing-dot/ambiguous qualification refused.",
            ));
        }
        if !integer(&self.ttl)
            .is_some_and(|n| (60..=60000).contains(&n) && n.to_string() == self.ttl)
            || !integer(&self.mx).is_some_and(|n| n <= 255 && n.to_string() == self.mx)
            || (self.kind != "MX" && self.mx != "10")
        {
            return Err(err(
                "selection",
                "UnsupportedRecordTTL",
                "Missing/invalid explicit TTL or MX preference; no defaults/clamps.",
            ));
        }
        if self.address.is_empty()
            || self.address.len() > 2500
            || self.address.chars().any(char::is_control)
        {
            return Err(err(
                "selection",
                "InvalidRecordValue",
                "Unrepresentable native value.",
            ));
        }
        match self.kind.as_str() {
            "A" | "AAAA" => {
                if !self
                    .address
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_ipv4() == (self.kind == "A"))
                {
                    return Err(err(
                        "selection",
                        "InvalidRecordValue",
                        "Invalid native IP family.",
                    ));
                }
            }
            "CNAME" | "NS" | "MX"
                if !dns_name(
                    self.address.strip_suffix('.').unwrap_or(&self.address),
                    false,
                ) =>
            {
                return Err(err(
                    "selection",
                    "InvalidRecordValue",
                    "Unrepresentable DNS target hostname.",
                ));
            }
            _ => {}
        }
        Ok(())
    }
    fn signature(&self) -> String {
        serde_json::to_string(&(
            &self.name,
            &self.kind,
            &self.address,
            &self.ttl,
            &self.mx,
            self.active,
            self.ddns,
            &self.app,
            &self.friendly,
        ))
        .expect("scalar tuple")
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Context {
    domain_id: String,
    domain: String,
    status: String,
    expires: String,
    provider_type: String,
    nameservers: Vec<String>,
    info_mail: String,
    host_count: Option<u64>,
    mode: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    context: Context,
    rows: Vec<Row>,
}
impl Snapshot {
    fn signatures(&self) -> Vec<String> {
        let mut v: Vec<_> = self.rows.iter().map(Row::signature).collect();
        v.sort();
        v
    }
    fn same(&self, other: &Self) -> bool {
        self.context == other.context && self.signatures() == other.signatures()
    }
    fn same_readback(&self, other: &Self, s: &Spec) -> bool {
        let normalized = |snapshot: &Self| {
            let mut rows = snapshot.rows.clone();
            for row in &mut rows {
                if NameFormat::Relative.matches(&row.name, s)
                    && row.kind == s.record_type
                    && let Ok(ip) = row.address.parse::<IpAddr>()
                {
                    row.address = ip.to_string();
                }
            }
            let mut signatures: Vec<_> = rows.iter().map(Row::signature).collect();
            signatures.sort();
            signatures
        };
        self.context == other.context && normalized(self) == normalized(other)
    }
    fn matches(&self, s: &Spec) -> Vec<&Row> {
        self.rows
            .iter()
            .filter(|r| NameFormat::Relative.matches(&r.name, s) && r.kind == s.record_type)
            .collect()
    }
    fn validate(&self, s: &Spec) -> Result<(), ProviderError> {
        if self.rows.len() > CAP
            || !mail_mode(&self.context.mode)
            || self
                .context
                .host_count
                .is_some_and(|n| n != self.rows.len() as u64)
        {
            return Err(err(
                "selection",
                "InvalidInventory",
                "Incomplete/excessive host count or unknown mailmode.",
            ));
        }
        for r in &self.rows {
            r.validate(&s.domain, &self.context.mode)?;
        }
        if self.matches(s).len() > 1 {
            return Err(err(
                "selection",
                "AmbiguousRecords",
                "Target owner/type has multiple records; native pinning cannot make replacement safe.",
            ));
        }
        let target = s.fqdn().to_ascii_lowercase();
        for r in &self.rows {
            let owner = if r.name == "@" {
                s.domain.clone()
            } else {
                format!("{}.{}", r.name, s.domain)
            }
            .to_ascii_lowercase();
            if (r.kind == "CNAME" && owner == target)
                || (r.kind == "NS"
                    && (owner == s.domain.to_ascii_lowercase()
                        || target == owner
                        || target.ends_with(&format!(".{owner}"))))
            {
                return Err(err(
                    "selection",
                    "DnsOwnerConflict",
                    "Target collides with CNAME/delegated NS authority; no planning/write.",
                ));
            }
        }
        Ok(())
    }
}
// Never Debug/Serialize credentials; arbitrary endpoints only under cfg(test).
pub struct Namecheap {
    client: reqwest::Client,
    user: String,
    key: String,
    client_ip: String,
    options: BTreeMap<String, String>,
    configuration_error: Option<ProviderError>,
    #[cfg(test)]
    endpoint: String,
}
impl Namecheap {
    pub fn new_with_direct(
        client: reqwest::Client,
        user: String,
        key: String,
        o: &BTreeMap<String, String>,
        direct: Option<&str>,
    ) -> Self {
        Self::build(
            client,
            user,
            key,
            o,
            resolve_client_ip_with_direct(o, direct),
        )
    }
    fn build(
        client: reqwest::Client,
        user: String,
        key: String,
        o: &BTreeMap<String, String>,
        ip: Result<String, ProviderError>,
    ) -> Self {
        let mut error = check_options_with_direct(o, ip.is_ok())
            .and_then(|_| check_credentials(&user, &key))
            .err();
        let client_ip = match ip {
            Ok(ip) => ip,
            Err(e) => {
                if error.is_none() {
                    error = Some(e);
                }
                String::new()
            }
        };
        Self {
            client,
            user,
            key,
            client_ip,
            options: o.clone(),
            configuration_error: error,
            #[cfg(test)]
            endpoint: if o.get("environment").map(String::as_str) == Some("sandbox") {
                SANDBOX
            } else {
                PROD
            }
            .into(),
        }
    }
    fn endpoint(&self) -> &str {
        #[cfg(test)]
        {
            &self.endpoint
        }
        #[cfg(not(test))]
        {
            if self.options["environment"] == "sandbox" {
                SANDBOX
            } else {
                PROD
            }
        }
    }
    fn validate(&self, s: &Spec) -> Result<(), ProviderError> {
        if let Some(e) = &self.configuration_error {
            return Err(e.clone());
        }
        check_spec_with_direct(s, &self.options, !self.client_ip.is_empty())
    }
    fn safe(&self, text: &str) -> String {
        let lower = text.to_ascii_lowercase();
        if [
            "http://",
            "https://",
            "apiuser=",
            "apikey=",
            "username=",
            "clientip=",
            "authorization",
            "dynamicdnspassword",
        ]
        .iter()
        .any(|v| lower.contains(v))
        {
            return "[Sensitive provider detail omitted]".into();
        }
        let mut variants = vec![];
        for secret in [&self.user, &self.key, &self.client_ip] {
            if secret.is_empty() {
                continue;
            }
            variants.push(secret.clone());
            let encoded =
                percent_encoding::utf8_percent_encode(secret, percent_encoding::NON_ALPHANUMERIC)
                    .to_string();
            let mut u = reqwest::Url::parse(PROD).expect("fixed URL");
            u.query_pairs_mut().append_pair("x", secret);
            let form = u.query().expect("query")[2..].to_string();
            for v in [encoded, form] {
                variants.push(v.clone());
                variants.push(lower_hex(&v));
                for first in [&v, &lower_hex(&v)] {
                    let double = percent_encoding::utf8_percent_encode(
                        first,
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string();
                    variants.push(double.clone());
                    variants.push(lower_hex(&double));
                }
            }
        }
        variants.sort_by_key(|v| std::cmp::Reverse(v.len()));
        let mut out = text.to_string();
        for v in variants {
            out = out.replace(&v, "[REDACTED]");
        }
        out.chars().filter(|c|!c.is_control()&&!matches!(*c,'\u{200b}'..='\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')).take(512).collect()
    }
    fn error(&self, action: &str, code: &str, msg: &str, status: Option<u16>) -> ProviderError {
        let mut e = err(action, code, &self.safe(msg));
        e.http_status = status;
        e
    }
    async fn call(
        &self,
        method: &str,
        mut params: Vec<(String, String)>,
        write: bool,
    ) -> Result<Node, ProviderError> {
        let command = format!("namecheap.{method}");
        params.extend([
            ("ApiUser".into(), self.user.clone()),
            ("ApiKey".into(), self.key.clone()),
            ("UserName".into(), self.user.clone()),
            ("ClientIp".into(), self.client_ip.clone()),
            ("Command".into(), command.clone()),
        ]);
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut response = self
                .client
                .post(self.endpoint())
                .form(&params)
                .header(reqwest::header::ACCEPT, "application/xml")
                .send()
                .await
                .map_err(|_| {
                    self.error(
                        method,
                        "TransportFailure",
                        if write {
                            "Write outcome uncertain; transport details/URL omitted, no retry."
                        } else {
                            "Read transport failed; details/URL omitted, no mutation."
                        },
                        None,
                    )
                })?;
            let status = response.status().as_u16();
            if status != 200 {
                return Err(self.error(
                    method,
                    &format!("Http{status}"),
                    if write {
                        "Unsuccessful HTTP acknowledgement; outcome uncertain."
                    } else {
                        "Unsuccessful API HTTP status; no empty-inventory fallback."
                    },
                    Some(status),
                ));
            }
            if response.headers().contains_key(reqwest::header::LINK)
                || response
                    .headers()
                    .contains_key(reqwest::header::CONTENT_RANGE)
            {
                return Err(self.error(
                    method,
                    "InvalidInventory",
                    "Unexpected paging/truncation header.",
                    Some(status),
                ));
            }
            let mut bytes = vec![];
            while let Some(chunk) = response.chunk().await.map_err(|_| {
                self.error(
                    method,
                    "TransportFailure",
                    "Incomplete response; dispatched write uncertain, raw detail omitted.",
                    Some(status),
                )
            })? {
                if bytes.len() + chunk.len() > LIMIT {
                    return Err(self.error(
                        method,
                        "ResponseTooLarge",
                        "XML exceeded1MiB; no success inferred.",
                        Some(status),
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            let root = parse_xml(&bytes).map_err(|mut e| {
                e.stage = method.into();
                e.http_status = Some(status);
                e
            })?;
            self.envelope(method, &command, root, status)
        })
        .await
        .unwrap_or_else(|_| {
            Err(self.error(
                method,
                "Timeout",
                if write {
                    "Deadline exceeded; write uncertain, no retry."
                } else {
                    "Read deadline exceeded; no mutation."
                },
                None,
            ))
        })
    }
    fn envelope(
        &self,
        method: &str,
        command: &str,
        root: Node,
        status: u16,
    ) -> Result<Node, ProviderError> {
        if root.name != "ApiResponse" {
            return Err(self.error(
                method,
                "MalformedResponse",
                "Expected ApiResponse root.",
                Some(status),
            ));
        }
        root.attrs_only(&["Status"])?;
        root.children_only(&[
            "Errors",
            "Warnings",
            "RequestedCommand",
            "CommandResponse",
            "Server",
            "GMTTimeDifference",
            "ExecutionTime",
        ])?;
        let errors = root.one("Errors")?;
        errors.attrs_only(&[])?;
        errors.children_only(&["Error"])?;
        if !errors.children.is_empty() {
            let mut details = vec![];
            let mut code = "ProviderApiError".to_string();
            for e in errors.children.iter().take(16) {
                e.attrs_only(&["Number"])?;
                let num = e.attr("Number")?;
                if integer(num).is_none() || num.len() > 12 {
                    return Err(self.error(
                        method,
                        "MalformedResponse",
                        "Malformed provider error number.",
                        Some(status),
                    ));
                }
                if details.is_empty() {
                    code = format!("Namecheap{num}");
                }
                details.push(format!("{num}: {}", self.safe(e.leaf()?)));
            }
            return Err(self.error(method, &code, &details.join("; "), Some(status)));
        }
        if root.attr("Status")? != "OK" {
            return Err(self.error(
                method,
                "ProviderApiError",
                "API did not report Status=OK.",
                Some(status),
            ));
        }
        if let Some(w) = root.optional("Warnings")? {
            w.attrs_only(&[])?;
            if !w.children.is_empty() || !w.text.trim().is_empty() {
                return Err(self.error(
                    method,
                    "ProviderWarning",
                    "Warnings prevent accepting completeness/write result.",
                    Some(status),
                ));
            }
        }
        let requested = root.one("RequestedCommand")?;
        requested.attrs_only(&[])?;
        if !requested.leaf()?.eq_ignore_ascii_case(command) {
            return Err(self.error(
                method,
                "CommandMismatch",
                "RequestedCommand mismatch.",
                Some(status),
            ));
        }
        let response = root.one("CommandResponse")?;
        response.attrs_only(&["Type"])?;
        if !response.attr("Type")?.eq_ignore_ascii_case(command) {
            return Err(self.error(
                method,
                "CommandMismatch",
                "CommandResponse Type mismatch.",
                Some(status),
            ));
        }
        let index = root
            .children
            .iter()
            .position(|n| n.name == "CommandResponse")
            .expect("verified");
        let mut children = root.children;
        Ok(children.remove(index))
    }
    fn parts(&self) -> Vec<(String, String)> {
        vec![
            ("SLD".into(), self.options["sld"].clone()),
            ("TLD".into(), self.options["tld"].clone()),
        ]
    }
    async fn snapshot(&self, s: &Spec) -> Result<Snapshot, ProviderError> {
        self.validate(s)?;
        let info = self
            .call(
                "domains.getInfo",
                vec![("DomainName".into(), s.domain.clone())],
                false,
            )
            .await?;
        info.children_only(&["DomainGetInfoResult"])?;
        let r = info.one("DomainGetInfoResult")?;
        r.attrs_only(&[
            "Status",
            "ID",
            "DomainName",
            "OwnerName",
            "IsOwner",
            "IsPremium",
        ])?;
        r.children_only(&[
            "DomainDetails",
            "LockDetails",
            "Whoisguard",
            "PremiumDnsSubscription",
            "DnsDetails",
            "Modificationrights",
        ])?;
        if !r.attr("DomainName")?.eq_ignore_ascii_case(&s.domain)
            || boolean(r.attr("IsOwner")?) != Some(true)
            || !r.attr("OwnerName")?.eq_ignore_ascii_case(&self.user)
            || !matches!(r.attr("Status")?, "Ok" | "OK" | "Locked")
            || !integer(r.attr("ID")?).is_some_and(|n| n > 0)
        {
            return Err(err(
                "domains.getInfo",
                "DomainNotOwned",
                "Exact account-owned nonexpired registered domain not established.",
            ));
        }
        let details = r.one("DomainDetails")?;
        details.attrs_only(&[])?;
        details.children_only(&["CreatedDate", "ExpiredDate", "NumYears"])?;
        let expiry = details.one("ExpiredDate")?.leaf()?;
        let date = NaiveDate::parse_from_str(expiry, "%m/%d/%Y").map_err(|_| {
            err(
                "domains.getInfo",
                "InvalidExpiry",
                "Missing/unrecognized expiry; no default active state.",
            )
        })?;
        if date <= Utc::now().date_naive() {
            return Err(err(
                "domains.getInfo",
                "DomainExpired",
                "Domain expired or expires today.",
            ));
        }
        let premium = r.one("PremiumDnsSubscription")?;
        premium.attrs_only(&[])?;
        premium.children_only(&[
            "UseAutoRenew",
            "SubscriptionId",
            "CreatedDate",
            "ExpirationDate",
            "IsActive",
        ])?;
        if boolean(premium.one("IsActive")?.leaf()?) != Some(false) {
            return Err(err(
                "domains.getInfo",
                "UnsupportedDnsProvider",
                "PremiumDNS active or unknown.",
            ));
        }
        let dns = r.one("DnsDetails")?;
        dns.attrs_only(&[
            "ProviderType",
            "IsUsingOurDNS",
            "HostCount",
            "EmailType",
            "DynamicDNSStatus",
            "IsFailover",
            "DynamicDNSPassword",
        ])?;
        dns.children_only(&["Nameserver", "DynamicDNSPassword"])?;
        if dns.attr("ProviderType")? != "ENOM"
            || boolean(dns.attr("IsUsingOurDNS")?) != Some(true)
            || boolean(dns.attr("DynamicDNSStatus")?) != Some(false)
            || boolean(dns.attr("IsFailover")?) != Some(false)
        {
            return Err(err(
                "domains.getInfo",
                "UnsupportedDnsProvider",
                "Require observed ENOM/BasicDNS, OurDNS and explicit DynamicDNS/failover=false; no invented ProviderType label.",
            ));
        }
        // DynamicDNSPassword is transient, never stored or echoed.
        let count = dns
            .attrs
            .get("HostCount")
            .map(|v| {
                integer(v).filter(|n| *n <= CAP as u64).ok_or_else(|| {
                    err(
                        "domains.getInfo",
                        "InvalidHostCount",
                        "Malformed/excessive HostCount.",
                    )
                })
            })
            .transpose()?;
        let mut nameservers = vec![];
        for n in dns.children.iter().filter(|n| n.name == "Nameserver") {
            n.attrs_only(&[])?;
            nameservers.push(n.leaf()?.to_ascii_lowercase());
        }
        nameservers.sort();
        if nameservers != vec!["dns1.registrar-servers.com", "dns2.registrar-servers.com"] {
            return Err(err(
                "domains.getInfo",
                "UnsupportedDnsProvider",
                "Exact BasicDNS nameservers not confirmed.",
            ));
        }
        let list = self
            .call("domains.dns.getList", self.parts(), false)
            .await?;
        list.children_only(&["DomainDNSGetListResult"])?;
        let dl = list.one("DomainDNSGetListResult")?;
        dl.attrs_only(&["Domain", "IsUsingOurDNS", "IsPremiumDNS", "IsUsingFreeDNS"])?;
        dl.children_only(&["Nameserver"])?;
        if !dl.attr("Domain")?.eq_ignore_ascii_case(&s.domain)
            || boolean(dl.attr("IsUsingOurDNS")?) != Some(true)
            || boolean(dl.attr("IsPremiumDNS")?) != Some(false)
            || boolean(dl.attr("IsUsingFreeDNS")?) != Some(false)
        {
            return Err(err(
                "domains.dns.getList",
                "UnsupportedDnsProvider",
                "DNS list did not independently confirm BasicDNS/nonPremium/nonFree scope.",
            ));
        }
        let mut listns = vec![];
        for n in &dl.children {
            n.attrs_only(&[])?;
            listns.push(n.leaf()?.to_ascii_lowercase());
        }
        listns.sort();
        if listns != nameservers {
            return Err(err(
                "domains.dns.getList",
                "DnsModeChanged",
                "DNS lists disagree.",
            ));
        }
        let hosts = self
            .call("domains.dns.getHosts", self.parts(), false)
            .await?;
        hosts.children_only(&["DomainDNSGetHostsResult"])?;
        let inv = hosts.one("DomainDNSGetHostsResult")?;
        inv.attrs_only(&["Domain", "EmailType", "IsUsingOurDNS"])?;
        inv.children_only(&["host", "Host"])?;
        let mode = inv.attr("EmailType")?;
        if !inv.attr("Domain")?.eq_ignore_ascii_case(&s.domain)
            || boolean(inv.attr("IsUsingOurDNS")?) != Some(true)
            || !mail_mode(mode)
        {
            return Err(err(
                "domains.dns.getHosts",
                "InvalidInventory",
                "Wrong domain/DNS or missing/unknown mailmode.",
            ));
        }
        let info_mail = dns.attr("EmailType")?;
        if info_mail != mode && !(mode == "NONE" && info_mail == "No Email Service") {
            return Err(err(
                "domains.dns.getHosts",
                "MailModeMismatch",
                "DNS information/mailmode inconsistent.",
            ));
        }
        let mut rows = vec![];
        let mut ids = HashSet::new();
        for n in &inv.children {
            if rows.len() == CAP {
                return Err(err(
                    "selection",
                    "RecordLimit",
                    "More than800 hosts; no replacement.",
                ));
            }
            n.attrs_only(&[
                "HostId",
                "Name",
                "Type",
                "Address",
                "MXPref",
                "TTL",
                "AssociatedAppTitle",
                "FriendlyName",
                "IsActive",
                "IsDDNSEnabled",
            ])?;
            n.children_only(&[])?;
            if !n.text.trim().is_empty() {
                return Err(err(
                    "selection",
                    "MalformedResponse",
                    "Host must contain only attributes.",
                ));
            }
            let id = n.attr("HostId")?;
            if !integer(id).is_some_and(|v| v > 0) || !ids.insert(id.to_string()) {
                return Err(err(
                    "selection",
                    "InvalidNativeId",
                    "Invalid/repeated native HostId.",
                ));
            }
            rows.push(Row {
                native_id: Some(id.into()),
                name: n.attr("Name")?.into(),
                kind: n.attr("Type")?.into(),
                address: n.attr("Address")?.into(),
                ttl: n.attr("TTL")?.into(),
                mx: n.attr("MXPref")?.into(),
                active: boolean(n.attr("IsActive")?).ok_or_else(|| {
                    err(
                        "selection",
                        "UnsupportedRecordControls",
                        "Unknown active control; missing does not mean enabled.",
                    )
                })?,
                ddns: boolean(n.attr("IsDDNSEnabled")?).ok_or_else(|| {
                    err(
                        "selection",
                        "UnsupportedRecordControls",
                        "Unknown DDNS control.",
                    )
                })?,
                app: n.attr("AssociatedAppTitle")?.into(),
                friendly: n.attr("FriendlyName")?.into(),
            });
        }
        let snapshot = Snapshot {
            context: Context {
                domain_id: r.attr("ID")?.into(),
                domain: s.domain.to_ascii_lowercase(),
                status: r.attr("Status")?.into(),
                expires: expiry.into(),
                provider_type: dns.attr("ProviderType")?.into(),
                nameservers,
                info_mail: info_mail.into(),
                host_count: count,
                mode: mode.into(),
            },
            rows,
        };
        snapshot.validate(s)?;
        Ok(snapshot)
    }
    fn presentation(&self, s: &Spec, snapshot: &Snapshot, row: &Row) -> Record {
        Record {
            id: logical_id(s),
            name: row.name.clone(),
            record_type: row.kind.clone(),
            value: row.address.clone(),
            ttl: integer(&row.ttl).expect("checked"),
            line: String::new(),
            enabled: true,
            extra: json!({"row":row,"snapshot":snapshot}),
        }
    }
    fn selected_snapshot(&self, s: &Spec, r: &Record) -> Result<Snapshot, ProviderError> {
        self.validate(s)?;
        let snapshot: Snapshot = serde_json::from_value(
            r.extra.get("snapshot").cloned().unwrap_or_default(),
        )
        .map_err(|_| {
            err(
                "selection",
                "InvalidSnapshot",
                "Missing/invalid complete opaque before-snapshot.",
            )
        })?;
        snapshot.validate(s)?;
        let targets = snapshot.matches(s);
        let row = targets.first().ok_or_else(|| {
            err(
                "selection",
                "InvalidSnapshot",
                "Selected target absent from before-snapshot.",
            )
        })?;
        let observed = self.presentation(s, &snapshot, row);
        if r.id != observed.id
            || r.name != observed.name
            || r.record_type != observed.record_type
            || r.value != observed.value
            || r.ttl != observed.ttl
            || r.line != observed.line
            || !r.enabled
            || r.extra != observed.extra
        {
            return Err(err(
                "selection",
                "InvalidSnapshot",
                "Selected ID/metadata contradict complete before-snapshot.",
            ));
        }
        Ok(snapshot)
    }
    async fn replace(
        &self,
        s: &Spec,
        old: &Snapshot,
        mut expected: Snapshot,
        ip: &str,
    ) -> Result<Mutation, ProviderError> {
        let fresh = self.snapshot(s).await?;
        if !old.same(&fresh) {
            return Err(err(
                "write",
                "ConcurrentZoneChange",
                "Whole zone/settings changed between fresh snapshots; stopped.",
            ));
        }
        if expected.rows.len() > CAP {
            return Err(err("write", "RecordLimit", "Creation exceeds800 hosts."));
        }
        let mut params = self.parts();
        for (i, r) in expected.rows.iter().enumerate() {
            let j = i + 1;
            params.extend([
                (format!("HostName{j}"), r.name.clone()),
                (format!("RecordType{j}"), r.kind.clone()),
                (format!("Address{j}"), r.address.clone()),
                (format!("TTL{j}"), r.ttl.clone()),
                (format!("MXPref{j}"), r.mx.clone()),
            ]);
        }
        // Critical: OMIT EmailType to preserve hidden mail routing, never send status,
        // app/friendly/HostId or copy the documentation's unrelated JSON POST example.
        let ack = self.call("domains.dns.setHosts", params, true).await?;
        ack.children_only(&["DomainDNSSetHostsResult"])?;
        let r = ack.one("DomainDNSSetHostsResult")?;
        r.attrs_only(&["Domain", "IsSuccess", "EmailType"])?;
        r.children_only(&["Warnings"])?;
        if !r.attr("Domain")?.eq_ignore_ascii_case(&s.domain)
            || boolean(r.attr("IsSuccess")?) != Some(true)
            || r.attrs
                .get("EmailType")
                .is_some_and(|v| v != &old.context.mode)
            || r.children
                .iter()
                .any(|n| !n.attrs.is_empty() || !n.children.is_empty() || !n.text.trim().is_empty())
        {
            return Err(err(
                "domains.dns.setHosts",
                "UncertainWrite",
                "No complete domain/mailmode/IsSuccess=true acknowledgement; no retry.",
            ));
        }
        let after = self.snapshot(s).await.map_err(|_| {
            err(
                "verification",
                "UncertainWrite",
                "Write dispatched but complete readback failed; inspect before retrying.",
            )
        })?;
        expected.context.host_count = old.context.host_count.map(|_| expected.rows.len() as u64);
        if !expected.same_readback(&after, s)
            || !after.matches(s).first().is_some_and(|r| {
                r.address.parse::<IpAddr>().ok() == ip.parse::<IpAddr>().ok()
                    && integer(&r.ttl) == Some(s.ttl)
            })
        {
            return Err(err(
                "verification",
                "UncertainWrite",
                "Readback differs from full intended records/mailmode/settings; no success/retry.",
            ));
        }
        Ok(Mutation {
            record_id: logical_id(s),
            request_id: None,
        })
    }
}
fn lower_hex(value: &str) -> String {
    let mut b = value.as_bytes().to_vec();
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i] == b'%' {
            b[i + 1] = b[i + 1].to_ascii_lowercase();
            b[i + 2] = b[i + 2].to_ascii_lowercase();
            i += 3;
        } else {
            i += 1;
        }
    }
    String::from_utf8(b).expect("UTF8 kept")
}
impl Adapter for Namecheap {
    fn name_format(&self) -> NameFormat {
        NameFormat::Relative
    }
    fn validate_selection(&self, s: &Spec, r: Option<&Record>) -> Result<(), ProviderError> {
        self.validate(s)?;
        if let Some(r) = r {
            self.selected_snapshot(s, r)?;
        }
        Ok(())
    }
    async fn list(&self, s: &Spec) -> Result<List, ProviderError> {
        let snapshot = self.snapshot(s).await?;
        let records = snapshot
            .matches(s)
            .into_iter()
            .map(|r| self.presentation(s, &snapshot, r))
            .collect();
        Ok(List {
            records,
            request_id: None,
        })
    }
    async fn create(&self, s: &Spec, ip: &str) -> Result<Mutation, ProviderError> {
        self.validate(s)?;
        let ip = desired(s, ip)?;
        if !s.create_if_missing || s.record_id.is_some() {
            return Err(err(
                "create",
                "CreationRefused",
                "Explicit create_if_missing and no record_id required.",
            ));
        }
        let old = self.snapshot(s).await?;
        if !old.matches(s).is_empty() {
            return Err(err(
                "create",
                "ConcurrentZoneChange",
                "Target appeared; no upsert fallback.",
            ));
        }
        let mut expected = old.clone();
        expected.rows.push(Row {
            native_id: None,
            name: if s.subdomain.is_empty() {
                "@".into()
            } else {
                s.subdomain.clone()
            },
            kind: s.record_type.clone(),
            address: ip.clone(),
            ttl: s.ttl.to_string(),
            mx: "10".into(),
            active: true,
            ddns: false,
            app: String::new(),
            friendly: String::new(),
        });
        self.replace(s, &old, expected, &ip).await
    }
    async fn update(&self, s: &Spec, r: &Record, ip: &str) -> Result<Mutation, ProviderError> {
        let source = self.selected_snapshot(s, r)?;
        let ip = desired(s, ip)?;
        let old = self.snapshot(s).await?;
        if !source.same(&old) {
            return Err(err(
                "update",
                "ConcurrentZoneChange",
                "Selected full zone/settings changed; no replacement.",
            ));
        }
        let mut expected = old.clone();
        let row = expected
            .rows
            .iter_mut()
            .find(|r| NameFormat::Relative.matches(&r.name, s) && r.kind == s.record_type)
            .ok_or_else(|| {
                err(
                    "update",
                    "ConcurrentZoneChange",
                    "Target vanished; no create fallback.",
                )
            })?;
        row.address = ip.clone();
        row.ttl = s.ttl.to_string();
        self.replace(s, &old, expected, &ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::reconcile;
    use super::*;
    use axum::{
        Router,
        body::{Body, to_bytes},
        extract::{Request, State},
        http::{StatusCode, header},
        response::{IntoResponse, Response},
        routing::any,
    };
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };
    fn options() -> BTreeMap<String, String> {
        [
            ("scope", "basicdns_plain"),
            ("write_mode", "exclusive_full_zone"),
            ("environment", "production"),
            ("sld", "example"),
            ("tld", "com"),
            ("client_ip_env", "NAMECHEAP_SERVER_IP"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
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
    fn row(id: u64, name: &str, kind: &str, address: &str) -> Row {
        Row {
            native_id: Some(id.to_string()),
            name: name.into(),
            kind: kind.into(),
            address: address.into(),
            ttl: "1800".into(),
            mx: "10".into(),
            active: true,
            ddns: false,
            app: String::new(),
            friendly: String::new(),
        }
    }
    fn esc(v: &str) -> String {
        quick_xml::escape::escape(v).into_owned()
    }
    fn xmlrow(r: &Row) -> String {
        format!(
            "<host HostId=\"{}\" Name=\"{}\" Type=\"{}\" Address=\"{}\" TTL=\"{}\" MXPref=\"{}\" IsActive=\"{}\" IsDDNSEnabled=\"{}\" AssociatedAppTitle=\"{}\" FriendlyName=\"{}\"/>",
            r.native_id.as_deref().unwrap_or("900"),
            esc(&r.name),
            r.kind,
            esc(&r.address),
            r.ttl,
            r.mx,
            r.active,
            r.ddns,
            esc(&r.app),
            esc(&r.friendly)
        )
    }
    fn envelope(method: &str, content: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><ApiResponse Status=\"OK\" xmlns=\"http://api.namecheap.com/xml.response\"><Errors/><Warnings/><RequestedCommand>namecheap.{method}</RequestedCommand><CommandResponse Type=\"namecheap.{method}\">{content}</CommandResponse><Server>fixture</Server><GMTTimeDifference>+0</GMTTimeDifference><ExecutionTime>0.1</ExecutionTime></ApiResponse>"
        )
    }
    fn info(mode: &str, count: Option<usize>) -> String {
        let count = count
            .map(|n| format!(" HostCount=\"{n}\""))
            .unwrap_or_default();
        envelope(
            "domains.getInfo",
            &format!(
                "<DomainGetInfoResult Status=\"Locked\" ID=\"123\" DomainName=\"example.com\" OwnerName=\"test-user\" IsOwner=\"true\" IsPremium=\"false\"><DomainDetails><CreatedDate>01/01/2020</CreatedDate><ExpiredDate>12/31/2037</ExpiredDate><NumYears>1</NumYears></DomainDetails><LockDetails/><Whoisguard Enabled=\"True\"><ID>1</ID></Whoisguard><PremiumDnsSubscription><UseAutoRenew>false</UseAutoRenew><SubscriptionId>-1</SubscriptionId><CreatedDate>0001-01-01T00:00:00</CreatedDate><ExpirationDate>0001-01-01T00:00:00</ExpirationDate><IsActive>false</IsActive></PremiumDnsSubscription><DnsDetails ProviderType=\"ENOM\" IsUsingOurDNS=\"true\"{count} EmailType=\"{mode}\" DynamicDNSStatus=\"false\" IsFailover=\"false\"><Nameserver>dns1.registrar-servers.com</Nameserver><Nameserver>dns2.registrar-servers.com</Nameserver></DnsDetails><Modificationrights All=\"true\"/></DomainGetInfoResult>"
            ),
        )
    }
    fn dnslist() -> String {
        envelope(
            "domains.dns.getList",
            "<DomainDNSGetListResult Domain=\"example.com\" IsUsingOurDNS=\"true\" IsPremiumDNS=\"false\" IsUsingFreeDNS=\"false\"><Nameserver>dns1.registrar-servers.com</Nameserver><Nameserver>dns2.registrar-servers.com</Nameserver></DomainDNSGetListResult>",
        )
    }
    fn hosts(rows: &[Row], mode: &str) -> String {
        envelope(
            "domains.dns.getHosts",
            &format!(
                "<DomainDNSGetHostsResult Domain=\"example.com\" EmailType=\"{mode}\" IsUsingOurDNS=\"true\">{}</DomainDNSGetHostsResult>",
                rows.iter().map(xmlrow).collect::<String>()
            ),
        )
    }
    fn snapshot(rows: &[Row], mode: &str) -> Vec<(u16, String)> {
        vec![
            (200, info(mode, Some(rows.len()))),
            (200, dnslist()),
            (200, hosts(rows, mode)),
        ]
    }
    fn ack() -> (u16, String) {
        (
            200,
            envelope(
                "domains.dns.setHosts",
                "<DomainDNSSetHostsResult Domain=\"example.com\" IsSuccess=\"true\"><Warnings/></DomainDNSSetHostsResult>",
            ),
        )
    }
    #[derive(Clone)]
    struct Seen {
        method: String,
        uri: String,
        content_type: String,
        form: BTreeMap<String, String>,
    }
    struct Data {
        replies: VecDeque<(u16, String)>,
        seen: Vec<Seen>,
    }
    struct Mock {
        url: String,
        data: Arc<Mutex<Data>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn handler(State(data): State<Arc<Mutex<Data>>>, req: Request<Body>) -> Response {
        let (p, b) = req.into_parts();
        let bytes = to_bytes(b, LIMIT * 2).await.unwrap();
        let mut u = reqwest::Url::parse("http://localhost/").unwrap();
        u.set_query(Some(std::str::from_utf8(&bytes).unwrap()));
        let seen = Seen {
            method: p.method.to_string(),
            uri: p.uri.to_string(),
            content_type: p
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .into(),
            form: u
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect(),
        };
        let (status, body) = {
            let mut d = data.lock().unwrap();
            d.seen.push(seen);
            d.replies
                .pop_front()
                .unwrap_or((500, "Unexpected request".into()))
        };
        if status == 307 {
            let mut r = StatusCode::TEMPORARY_REDIRECT.into_response();
            r.headers_mut()
                .insert(header::LOCATION, body.parse().unwrap());
            r
        } else {
            (
                StatusCode::from_u16(status).unwrap(),
                [(header::CONTENT_TYPE, "application/xml")],
                body,
            )
                .into_response()
        }
    }
    impl Mock {
        async fn new(replies: Vec<(u16, String)>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/xml.response", listener.local_addr().unwrap());
            let data = Arc::new(Mutex::new(Data {
                replies: replies.into(),
                seen: vec![],
            }));
            let app = Router::new()
                .route("/xml.response", any(handler))
                .with_state(data.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self { url, data, task }
        }
        fn provider(&self) -> Namecheap {
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .build()
                .unwrap();
            let mut p = Namecheap::build(
                client,
                "test-user".into(),
                "test/key+%=".into(),
                &options(),
                check_client_ip_value("8.8.8.8"),
            );
            p.endpoint = self.url.clone();
            p
        }
        fn seen(&self) -> Vec<Seen> {
            self.data.lock().unwrap().seen.clone()
        }
        fn writes(&self) -> usize {
            self.seen()
                .iter()
                .filter(|r| {
                    r.form
                        .get("Command")
                        .is_some_and(|c| c == "namecheap.domains.dns.setHosts")
                })
                .count()
        }
        fn no_write(&self) {
            assert_eq!(self.writes(), 0);
        }
        fn done(&self) {
            assert!(self.data.lock().unwrap().replies.is_empty());
        }
    }
    fn old() -> Vec<Row> {
        vec![
            row(1, "home", "A", "192.0.2.1"),
            row(2, "_acme-challenge", "TXT", "a & b + % / = \"quoted\""),
            row(3, "www", "CNAME", "external.example."),
            row(4, "child", "NS", "ns.example."),
            row(5, "@", "MX", "mx.example."),
        ]
    }
    fn after(rows: &[Row], ip: &str, ttl: u64) -> Vec<Row> {
        rows.iter()
            .cloned()
            .map(|mut r| {
                r.native_id =
                    Some((integer(r.native_id.as_deref().unwrap()).unwrap() + 100).to_string());
                if r.name == "home" && r.kind == "A" {
                    r.address = ip.into();
                    r.ttl = ttl.to_string();
                }
                r
            })
            .collect()
    }
    #[tokio::test]
    async fn actual_xml_form_roundtrip_preserves_unrelated_mail_and_rotating_ids() {
        let rows = old();
        let changed = after(&rows, "192.0.2.8", 600);
        let mut replies = snapshot(&rows, "MX");
        replies.extend(snapshot(&rows, "MX"));
        replies.extend(snapshot(&after(&rows, "192.0.2.1", 1800), "MX"));
        replies.push(ack());
        replies.extend(snapshot(&changed, "MX"));
        let m = Mock::new(replies).await;
        let result = reconcile(&m.provider(), &spec(), "192.0.2.8", false)
            .await
            .unwrap();
        assert_eq!(result.status, "updated");
        assert_eq!(result.record_id, Some(logical_id(&spec())));
        assert_eq!(m.writes(), 1);
        let seen = m.seen();
        for q in &seen {
            assert_eq!(q.method, "POST");
            assert_eq!(q.uri, "/xml.response");
            assert_eq!(q.content_type, "application/x-www-form-urlencoded");
            assert_eq!(q.form["ApiUser"], "test-user");
            assert_eq!(q.form["UserName"], "test-user");
            assert_eq!(q.form["ApiKey"], "test/key+%=");
            assert_eq!(q.form["ClientIp"], "8.8.8.8");
        }
        let write = seen
            .iter()
            .find(|q| q.form["Command"].ends_with("setHosts"))
            .unwrap();
        assert!(!write.form.contains_key("EmailType"));
        assert_eq!(write.form["SLD"], "example");
        assert_eq!(write.form["TLD"], "com");
        assert_eq!(write.form["Address2"], rows[1].address);
        assert_eq!(write.form["MXPref5"], "10");
        assert_eq!(write.form["TTL5"], "1800");
        assert_eq!(write.form["Address5"], "mx.example.");
        assert_eq!(write.form["HostName1"], "home");
        assert!(write.form.keys().all(|k| !k.starts_with("HostId")
            && !k.starts_with("IsActive")
            && !k.starts_with("Associated")));
        m.done();
    }
    #[tokio::test]
    async fn unchanged_and_dryrun_require_complete_safe_snapshot() {
        for (ip, dry, status) in [
            ("192.0.2.1", false, "unchanged"),
            ("192.0.2.8", true, "would_update"),
        ] {
            let mut s = spec();
            s.ttl = 1800;
            let m = Mock::new(snapshot(&old(), "MX")).await;
            assert_eq!(
                reconcile(&m.provider(), &s, ip, dry).await.unwrap().status,
                status
            );
            m.no_write();
            m.done();
        }
    }
    #[tokio::test]
    async fn hidden_preset_mode_omitted_and_verified() {
        for mode in ["NONE", "FWD", "OX", "GMAIL", "MXE"] {
            let rows = vec![row(1, "home", "A", "192.0.2.1")];
            let changed = after(&rows, "192.0.2.8", 600);
            let mut replies = snapshot(&rows, mode);
            replies.extend(snapshot(&rows, mode));
            replies.extend(snapshot(&rows, mode));
            replies.push(ack());
            replies.extend(snapshot(&changed, mode));
            let m = Mock::new(replies).await;
            assert_eq!(
                reconcile(&m.provider(), &spec(), "192.0.2.8", false)
                    .await
                    .unwrap()
                    .status,
                "updated"
            );
            assert_eq!(m.writes(), 1);
            assert!(m.seen().iter().all(|r| !r.form.contains_key("EmailType")));
            m.done();
        }
    }
    #[tokio::test]
    async fn unsupported_controls_types_values_fail_before_every_plan() {
        let mut variants = vec![];
        for kind in [
            "SRV", "CAA", "ALIAS", "MXE", "URL", "URL301", "FRAME", "BOGUS",
        ] {
            let mut r = old();
            r[1].kind = kind.into();
            variants.push(r);
        }
        for change in 0..7 {
            let mut r = old();
            match change {
                0 => r[1].active = false,
                1 => r[1].ddns = true,
                2 => r[1].app = "FWD".into(),
                3 => r[1].friendly = "friendly".into(),
                4 => r[1].name = "_acme.example.com.".into(),
                5 => r[1].ttl = "0".into(),
                _ => r[1].mx = "256".into(),
            };
            variants.push(r);
        }
        for rows in variants {
            for (ip, dry) in [
                ("192.0.2.1", false),
                ("192.0.2.8", true),
                ("192.0.2.8", false),
            ] {
                let m = Mock::new(snapshot(&rows, "MX")).await;
                assert!(reconcile(&m.provider(), &spec(), ip, dry).await.is_err());
                m.no_write();
                m.done();
            }
        }
    }
    #[tokio::test]
    async fn unsupported_xml_fields_and_missing_control_are_not_enabled_defaults() {
        for change in [
            "missing-active",
            "weight",
            "unknown-child",
            "missing-result",
            "missing-mode",
            "unknown-mode",
            "duplicate-id",
            "wrong-domain",
            "warning",
        ] {
            let mut replies = snapshot(&old(), "MX");
            let body = &mut replies[2].1;
            *body = match change {
                "missing-active" => body.replace(" IsActive=\"true\"", ""),
                "weight" => body.replace("HostId=\"2\"", "HostId=\"2\" Weight=\"1\""),
                "unknown-child" => body.replace(
                    "</DomainDNSGetHostsResult>",
                    "<Truncated>true</Truncated></DomainDNSGetHostsResult>",
                ),
                "missing-result" => envelope("domains.dns.getHosts", ""),
                "missing-mode" => body.replace(" EmailType=\"MX\"", ""),
                "unknown-mode" => body.replace("EmailType=\"MX\"", "EmailType=\"UNKNOWN\""),
                "duplicate-id" => body.replace("HostId=\"2\"", "HostId=\"1\""),
                "wrong-domain" => body.replace("Domain=\"example.com\"", "Domain=\"another.com\""),
                _ => body.replace(
                    "<Warnings/>",
                    "<Warnings><Warning>partial</Warning></Warnings>",
                ),
            };
            let m = Mock::new(replies).await;
            assert!(
                reconcile(&m.provider(), &spec(), "192.0.2.1", true)
                    .await
                    .is_err(),
                "{change}"
            );
            m.no_write();
            m.done();
        }
    }
    #[tokio::test]
    async fn ownership_dns_and_expiry_failclosed() {
        for (a, b) in [
            ("IsOwner=\"true\"", "IsOwner=\"false\""),
            ("ProviderType=\"ENOM\"", "ProviderType=\"FreeDNS\""),
            ("<IsActive>false</IsActive>", "<IsActive>true</IsActive>"),
            ("DynamicDNSStatus=\"false\"", "DynamicDNSStatus=\"true\""),
            ("IsFailover=\"false\"", "IsFailover=\"true\""),
            ("12/31/2037", "01/01/2000"),
            ("dns1.registrar-servers.com", "custom.example.com"),
        ] {
            let m = Mock::new(vec![(200, info("NONE", Some(1)).replace(a, b))]).await;
            assert!(m.provider().list(&spec()).await.is_err());
            m.no_write();
            m.done();
        }
        let m = Mock::new(vec![
            (200, info("NONE", Some(1))),
            (
                200,
                dnslist().replace("IsUsingFreeDNS=\"false\"", "IsUsingFreeDNS=\"true\""),
            ),
        ])
        .await;
        assert!(m.provider().list(&spec()).await.is_err());
        m.no_write();
        m.done();
    }
    #[tokio::test]
    async fn ambiguous_and_cname_delegated_ns_conflicts() {
        for rows in [
            vec![
                row(1, "home", "A", "192.0.2.1"),
                row(2, "HOME", "A", "192.0.2.2"),
            ],
            vec![
                row(1, "home", "A", "192.0.2.1"),
                row(2, "home", "CNAME", "cname.example."),
            ],
            vec![row(1, "home", "NS", "ns.example.")],
            vec![row(1, "@", "NS", "ns.example.")],
        ] {
            for dry in [true, false] {
                let m = Mock::new(snapshot(&rows, "NONE")).await;
                assert!(
                    reconcile(&m.provider(), &spec(), "192.0.2.1", dry)
                        .await
                        .is_err()
                );
                m.no_write();
                m.done();
            }
        }
        let rows = vec![row(1, "child", "NS", "ns.example.")];
        let mut s = spec();
        s.subdomain = "nested.child".into();
        s.create_if_missing = true;
        let m = Mock::new(snapshot(&rows, "NONE")).await;
        assert_eq!(
            reconcile(&m.provider(), &s, "192.0.2.8", true)
                .await
                .unwrap_err()
                .code,
            "DnsOwnerConflict"
        );
        m.no_write();
    }
    #[tokio::test]
    async fn full_array_800_vs801_count_and_absent_count() {
        let mut rows = vec![row(1, "home", "A", "192.0.2.1")];
        for i in 2..=800 {
            rows.push(row(i, &format!("other{i}"), "TXT", "unrelated"));
        }
        let m = Mock::new(snapshot(&rows, "NONE")).await;
        assert_eq!(m.provider().list(&spec()).await.unwrap().records.len(), 1);
        m.no_write();
        m.done();
        for count in [Some(799), Some(801)] {
            let mut replies = snapshot(&rows, "NONE");
            replies[0].1 = info("NONE", count);
            if count == Some(801) {
                replies.truncate(1);
            }
            let m = Mock::new(replies).await;
            assert!(m.provider().list(&spec()).await.is_err());
            m.no_write();
            m.done();
        }
        rows.push(row(801, "too-many", "TXT", "x"));
        let mut replies = snapshot(&rows, "NONE");
        replies[0].1 = info("NONE", None);
        let m = Mock::new(replies).await;
        assert_eq!(
            m.provider().list(&spec()).await.unwrap_err().code,
            "RecordLimit"
        );
        m.no_write();
        m.done();
        let one = vec![row(1, "home", "A", "192.0.2.1")];
        let mut replies = snapshot(&one, "NONE");
        replies[0].1 = info("NONE", None);
        let m = Mock::new(replies).await;
        assert!(m.provider().list(&spec()).await.is_ok());
        m.no_write();
    }
    #[tokio::test]
    async fn create_requires_optin_double_absence_and_verifies_all_records() {
        let mut s = spec();
        let rows = vec![row(1, "unrelated", "TXT", "keep")];
        let m = Mock::new(snapshot(&rows, "OX")).await;
        assert_eq!(
            reconcile(&m.provider(), &s, "192.0.2.8", false)
                .await
                .unwrap_err()
                .code,
            "RecordNotFound"
        );
        m.no_write();
        s.create_if_missing = true;
        let mut changed = rows.clone();
        changed.push(row(900, "home", "A", "192.0.2.8"));
        changed[1].ttl = "600".into();
        let mut replies = snapshot(&rows, "OX");
        replies.extend(snapshot(&rows, "OX"));
        replies.extend(snapshot(&rows, "OX"));
        replies.push(ack());
        replies.extend(snapshot(&changed, "OX"));
        let m = Mock::new(replies).await;
        assert_eq!(
            reconcile(&m.provider(), &s, "192.0.2.8", false)
                .await
                .unwrap()
                .status,
            "created"
        );
        assert_eq!(m.writes(), 1);
        m.done();
    }
    #[tokio::test]
    async fn race_checks_cover_unrelated_rows_mail_and_create() {
        for race in ["unrelated", "mode", "count"] {
            let rows = old();
            let mut replies = snapshot(&rows, "MX");
            let mut changed = rows.clone();
            changed[1].address = "concurrent".into();
            if race == "unrelated" {
                replies.extend(snapshot(&changed, "MX"));
            } else if race == "mode" {
                let mut other = rows.clone();
                other.retain(|r| r.kind != "MX");
                replies.extend(snapshot(&other, "OX"));
            } else {
                let mut other = rows.clone();
                other.push(row(30, "new", "TXT", "new"));
                replies.extend(snapshot(&other, "MX"));
            }
            let m = Mock::new(replies).await;
            assert_eq!(
                reconcile(&m.provider(), &spec(), "192.0.2.8", false)
                    .await
                    .unwrap_err()
                    .code,
                "ConcurrentZoneChange"
            );
            m.no_write();
            m.done();
        }
        let rows = vec![row(1, "other", "TXT", "keep")];
        let mut replies = snapshot(&rows, "NONE");
        replies.extend(snapshot(&rows, "NONE"));
        let mut changed = rows.clone();
        changed.push(row(2, "home", "A", "192.0.2.7"));
        replies.extend(snapshot(&changed, "NONE"));
        let mut s = spec();
        s.create_if_missing = true;
        let m = Mock::new(replies).await;
        assert!(
            reconcile(&m.provider(), &s, "192.0.2.8", false)
                .await
                .is_err()
        );
        m.no_write();
        m.done();
    }
    #[tokio::test]
    async fn uncertain_ack_and_readback_never_retry() {
        for fault in [
            "false",
            "missing",
            "mode",
            "read-error",
            "unrelated",
            "target",
            "ttl",
        ] {
            let rows = old();
            let mut replies = snapshot(&rows, "MX");
            replies.extend(snapshot(&rows, "MX"));
            replies.extend(snapshot(&rows, "MX"));
            if matches!(fault, "false" | "missing" | "mode") {
                let mut a = ack();
                a.1 = match fault {
                    "false" => a.1.replace("IsSuccess=\"true\"", "IsSuccess=\"false\""),
                    "missing" => a.1.replace(" IsSuccess=\"true\"", ""),
                    _ => a.1.replace(
                        "IsSuccess=\"true\"",
                        "IsSuccess=\"true\" EmailType=\"NONE\"",
                    ),
                };
                replies.push(a);
            } else {
                replies.push(ack());
                if fault == "read-error" {
                    replies.push((500, "bad".into()));
                } else {
                    let mut changed = after(&rows, "192.0.2.8", 600);
                    match fault {
                        "unrelated" => changed[1].address = "lost".into(),
                        "target" => changed[0].address = "192.0.2.9".into(),
                        _ => changed[0].ttl = "1800".into(),
                    };
                    replies.extend(snapshot(&changed, "MX"));
                }
            }
            let m = Mock::new(replies).await;
            assert!(
                reconcile(&m.provider(), &spec(), "192.0.2.8", false)
                    .await
                    .is_err(),
                "{fault}"
            );
            assert_eq!(m.writes(), 1);
            m.done();
        }
    }
    #[tokio::test]
    async fn relative_dotted_owners_and_suffix_collision_do_not_guess() {
        for host in ["home.example.com", "branch.home", "example.com"] {
            let mut s = spec();
            s.subdomain = host.into();
            s.ttl = 1800;
            let rows = vec![
                row(1, host, "A", "192.0.2.1"),
                row(2, &format!("{host}.example.com"), "A", "192.0.2.2"),
            ];
            let m = Mock::new(snapshot(&rows, "NONE")).await;
            let out = reconcile(&m.provider(), &s, "192.0.2.1", true)
                .await
                .unwrap();
            assert_eq!(out.status, "unchanged");
            assert_eq!(out.record_id, Some(logical_id(&s)));
            m.no_write();
        }
    }
    #[test]
    fn xml_parser_rejects_unsafe_malformed_duplicate_namespace_and_bounds() {
        let valid = envelope(
            "domains.dns.getHosts",
            "<DomainDNSGetHostsResult Domain=\"example.com\" EmailType=\"NONE\" IsUsingOurDNS=\"true\"/>",
        );
        assert!(parse_xml(format!(" {valid}").as_bytes()).is_err());
        assert!(
            parse_xml(
                valid
                    .replace(
                        "version=\"1.0\"",
                        "version=\"1.0\" xmlns=\"http://api.namecheap.com/xml.response\""
                    )
                    .as_bytes()
            )
            .is_err()
        );
        assert!(
            parse_xml(
                valid
                    .replace("Domain=\"example.com\"", "Domain=\"example<com\"")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(parse_xml(valid.as_bytes()).is_ok());
        assert!(
            parse_xml(
                valid
                    .replace(
                        "http://api.namecheap.com/xml.response",
                        "https://api.namecheap.com/xml.response"
                    )
                    .as_bytes()
            )
            .is_ok()
        );
        for bad in [
            valid.replace(
                "xmlns=\"http://api.namecheap.com/xml.response\"",
                "xmlns=\"urn:evil\"",
            ),
            valid.replace("<Errors/>", "<Errors xmlns=\"\"/>"),
            valid.replace("<Errors/>", "<Errors xmlns=\"urn:evil\"/>"),
            valid.replace("Status=\"OK\"", "Status=\"OK\" Status=\"OK\""),
            valid.replace("<Errors/>", "<Errors>&unknown;</Errors>"),
            valid.replace("<Errors/>", "<Errors>&#0;</Errors>"),
            valid.replace(
                "<Errors/>",
                "<!DOCTYPE x [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><Errors/>",
            ),
            valid.replace("<Errors/>", "<?extension secret?><Errors/>"),
            valid.replace("<Errors/>", "<Errors></Warnings>"),
            valid.replace("</ApiResponse>", ""),
            format!("{valid}{valid}"),
            valid.replace("encoding=\"utf-8\"", "encoding=\"UTF-16\""),
            valid.replace("version=\"1.0\"", "version=\"1.1\""),
        ] {
            assert!(parse_xml(bad.as_bytes()).is_err());
        }
        assert!(parse_xml(&vec![b'x'; LIMIT + 1]).is_err());
        let deep = format!(
            "<ApiResponse xmlns=\"{}\">{}{}{}</ApiResponse>",
            NS[0],
            "<x>".repeat(20),
            "x",
            "</x>".repeat(20)
        );
        assert_eq!(parse_xml(deep.as_bytes()).err().unwrap().code, "XmlLimit");
    }
    #[tokio::test]
    async fn errors_http200_are_sanitized_and_redirects_not_followed() {
        let msg = "test-user test/key+%= test%2Fkey%2B%25%3D test%252Fkey%252B%2525%253D test%252fkey%252b%2525%253d 8.8.8.8 &amp; useful error";
        let body = format!(
            "<ApiResponse xmlns=\"{}\" Status=\"ERROR\"><Errors><Error Number=\"2016166\">{msg}</Error></Errors></ApiResponse>",
            NS[0]
        );
        let m = Mock::new(vec![(200, body)]).await;
        let e = m.provider().list(&spec()).await.unwrap_err();
        assert_eq!(e.code, "Namecheap2016166");
        assert_eq!(e.http_status, Some(200));
        let text = serde_json::to_string(&e).unwrap();
        for secret in [
            "test-user",
            "test/key+%=",
            "test%2Fkey",
            "test%252Fkey",
            "8.8.8.8",
        ] {
            assert!(!text.contains(secret));
        }
        assert!(e.message.contains("useful error"));
        m.no_write();
        m.done();
        let target = Mock::new(vec![]).await;
        let m = Mock::new(vec![(307, target.url.clone())]).await;
        assert_eq!(
            m.provider().list(&spec()).await.unwrap_err().code,
            "Http307"
        );
        assert_eq!(target.seen().len(), 0);
        m.done();
    }
    #[tokio::test]
    async fn ipv6_target_spellings_are_semantic_but_unrelated_addresses_remain_raw() {
        let mut s = spec();
        s.record_type = "AAAA".into();
        let rows = vec![
            row(1, "home", "AAAA", "2001:db8::1"),
            row(
                2,
                "other",
                "AAAA",
                "2001:0DB8:0000:0000:0000:0000:0000:0007",
            ),
            row(3, "same", "TXT", "duplicate"),
            row(4, "same", "TXT", "duplicate"),
        ];
        let mut changed = rows.clone();
        changed[0].native_id = Some("900".into());
        changed[0].address = "2001:0DB8:0000:0000:0000:0000:0000:0008".into();
        changed[0].ttl = "600".into();
        let mut replies = snapshot(&rows, "NONE");
        replies.extend(snapshot(&rows, "NONE"));
        replies.extend(snapshot(&rows, "NONE"));
        replies.push(ack());
        replies.extend(snapshot(&changed, "NONE"));
        let m = Mock::new(replies).await;
        let outcome = reconcile(&m.provider(), &s, "2001:db8::8", false)
            .await
            .unwrap();
        assert_eq!(outcome.status, "updated");
        let write = m
            .seen()
            .into_iter()
            .find(|r| r.form["Command"].ends_with("setHosts"))
            .unwrap();
        assert_eq!(write.form["Address1"], "2001:db8::8");
        assert_eq!(write.form["Address2"], rows[1].address);
        assert_eq!(write.form["Address3"], "duplicate");
        assert_eq!(write.form["Address4"], "duplicate");
        m.done();
        changed[1].address = "2001:db8::7".into();
        let mut replies = snapshot(&rows, "NONE");
        replies.extend(snapshot(&rows, "NONE"));
        replies.extend(snapshot(&rows, "NONE"));
        replies.push(ack());
        replies.extend(snapshot(&changed, "NONE"));
        let m = Mock::new(replies).await;
        assert_eq!(
            reconcile(&m.provider(), &s, "2001:db8::8", false)
                .await
                .unwrap_err()
                .code,
            "UncertainWrite"
        );
        assert_eq!(m.writes(), 1);
        m.done();
    }
    #[tokio::test]
    async fn number_spelling_and_nonmx_preference_are_explicit_subset_restrictions() {
        for (ttl, mx) in [
            ("01800", "10"),
            ("1800", "010"),
            ("1800", "0"),
            ("1800", "20"),
            ("+1800", "10"),
        ] {
            let mut rows = old();
            rows[1].ttl = ttl.into();
            rows[1].mx = mx.into();
            for dry in [true, false] {
                let m = Mock::new(snapshot(&rows, "MX")).await;
                assert_eq!(
                    reconcile(&m.provider(), &spec(), "192.0.2.1", dry)
                        .await
                        .unwrap_err()
                        .code,
                    "UnsupportedRecordTTL"
                );
                m.no_write();
                m.done();
            }
        }
        let mut rows = old();
        rows[4].mx = "255".into();
        let m = Mock::new(snapshot(&rows, "MX")).await;
        assert!(m.provider().list(&spec()).await.is_ok());
        m.no_write();
        m.done();
    }
    #[test]
    fn firstparty_raw_fixture_has_mail_and_presence_controls() {
        // Exact public SDK example shape; no account requests or SDK execution.
        let fixture = r#"<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors/><Warnings/><RequestedCommand>namecheap.domains.dns.gethosts</RequestedCommand><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="domain.net" EmailType="MX" IsUsingOurDNS="true"><host HostId="877748" Name="host33" Type="MX" Address="addr.domain.com." MXPref="10" TTL="1800" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false"/><host HostId="877749" Name="@" Type="CNAME" Address="anotherdomain.com" MXPref="10" TTL="1800" AssociatedAppTitle="" FriendlyName="" IsActive="true" IsDDNSEnabled="false"/></DomainDNSGetHostsResult></CommandResponse><Server>PHX01SBAPIEXT06</Server><GMTTimeDifference>--4:00</GMTTimeDifference><ExecutionTime>0.417</ExecutionTime></ApiResponse>"#;
        let p = Namecheap::build(
            reqwest::Client::new(),
            "test-user".into(),
            "test-key".into(),
            &options(),
            check_client_ip_value("8.8.8.8"),
        );
        let root = parse_xml(fixture.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        let response = p
            .envelope(
                "domains.dns.getHosts",
                "namecheap.domains.dns.getHosts",
                root,
                200,
            )
            .unwrap_or_else(|e| panic!("{e}"));
        let inv = response.one("DomainDNSGetHostsResult").unwrap();
        assert_eq!(inv.attr("EmailType").unwrap(), "MX");
        assert_eq!(inv.children.len(), 2);
        let host = &inv.children[0];
        assert_eq!(host.attr("IsActive").unwrap(), "true");
        assert_eq!(host.attr("IsDDNSEnabled").unwrap(), "false");
        assert_eq!(host.attr("AssociatedAppTitle").unwrap(), "");
        let uppercase = fixture.replace("<host ", "<Host ");
        assert!(parse_xml(uppercase.as_bytes()).is_ok());
    }
    #[tokio::test]
    async fn recognized_info_none_label_and_unknown_mail_labels() {
        let rows = vec![row(1, "home", "A", "192.0.2.1")];
        for (label, allowed) in [
            ("No Email Service", true),
            ("UNKNOWN", false),
            ("MX", false),
        ] {
            let mut replies = snapshot(&rows, "NONE");
            replies[0].1 = replies[0]
                .1
                .replace("EmailType=\"NONE\"", &format!("EmailType=\"{label}\""));
            let m = Mock::new(replies).await;
            assert_eq!(m.provider().list(&spec()).await.is_ok(), allowed);
            m.no_write();
            m.done();
        }
    }
    #[test]
    fn options_credentials_native_ids_and_server_ip_validation() {
        assert!(check_options(&options()).is_ok());
        for (key, value) in [
            ("scope", "dynamic_dns"),
            ("write_mode", "per_record"),
            ("environment", "auto"),
            ("client_ip_env", "PATH"),
            ("client_ip_env", "DDNS_IP"),
            ("client_ip_env", "8.8.8.8"),
            ("sld", "example.com"),
            ("tld", ""),
            ("endpoint", "https://evil.example"),
        ] {
            let mut o = options();
            o.insert(key.into(), value.into());
            assert!(check_options(&o).is_err());
        }
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "240.1.1.1",
            "::1",
            "8.8.8.8/32",
        ] {
            assert!(check_client_ip_value(value).is_err());
        }
        assert!(check_client_ip_value("8.8.8.8").is_ok());
        assert!(check_credentials("test-user", "key").is_ok());
        assert!(check_credentials("bad user", "key").is_err());
        assert!(check_credentials("user", "bad\nkey").is_err());
        let mut s = spec();
        s.record_id = Some("12345".into());
        assert!(check_spec(&s, &options()).is_err());
        s.record_id = Some(logical_id(&s));
        assert!(check_spec(&s, &options()).is_ok());
        s.domain = "other.com".into();
        assert!(check_spec(&s, &options()).is_err());
    }
}
