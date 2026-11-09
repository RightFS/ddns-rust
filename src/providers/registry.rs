//! Provider catalog is the only source of UI choices and configuration validation.
//! An entry with implemented=false is a roadmap item, never an executable fallback.
use serde::Serialize;
#[derive(Clone, Serialize)]
pub struct CredentialField {
    pub key: &'static str,
    pub label: &'static str,
    pub required: bool,
    pub env_prefix: &'static str,
}
#[derive(Clone, Serialize)]
pub struct OptionField {
    pub key: &'static str,
    pub label: &'static str,
    pub required: bool,
}
#[derive(Clone, Serialize)]
pub struct Descriptor {
    pub kind: &'static str,
    pub label: &'static str,
    pub implemented: bool,
    /// False only for independent delivery capabilities, never a DNS read claim.
    pub supports_dns_read: bool,
    pub credential_fields: Vec<CredentialField>,
    pub options: Vec<OptionField>,
    pub record_options: Vec<OptionField>,
}
fn pair(prefix: &'static str) -> Vec<CredentialField> {
    vec![
        CredentialField {
            key: "secret_id_env",
            label: "Credential ID environment variable",
            required: true,
            env_prefix: prefix,
        },
        CredentialField {
            key: "secret_key_env",
            label: "Credential key environment variable",
            required: true,
            env_prefix: prefix,
        },
    ]
}
fn token(prefix: &'static str) -> Vec<CredentialField> {
    vec![CredentialField {
        key: "token_env",
        label: "API token environment variable",
        required: true,
        env_prefix: prefix,
    }]
}
fn option(key: &'static str, label: &'static str) -> OptionField {
    OptionField {
        key,
        label,
        required: false,
    }
}
pub fn catalog() -> Vec<Descriptor> {
    [
        ("tencentcloud", "Tencent Cloud DNSPod"),
        ("cloudflare", "Cloudflare"),
        ("alidns", "Alibaba Cloud DNS"),
        ("dnspod", "DNSPod legacy"),
        ("aliesa", "Alibaba Cloud ESA"),
        ("trafficroute", "Volcengine TrafficRoute"),
        ("dnsla", "DNS.LA"),
        ("huaweicloud", "Huawei Cloud DNS"),
        ("callback", "Custom callback"),
        ("baiducloud", "Baidu Cloud DNS"),
        ("porkbun", "Porkbun"),
        ("godaddy", "GoDaddy"),
        ("namecheap", "Namecheap"),
        ("namesilo", "NameSilo"),
        ("vercel", "Vercel"),
        ("dynadot", "Dynadot"),
        ("dynv6", "dynv6"),
        ("spaceship", "Spaceship"),
        ("nowcn", "Now.cn"),
        ("eranet", "Eranet"),
        ("tnethk", "Tnet.hk"),
        ("gcore", "Gcore"),
        ("edgeone", "Tencent EdgeOne"),
        ("nsone", "NS1"),
        ("name_com", "Name.com"),
        ("rainyun", "Rainyun"),
        ("hipmdnsmgr", "HiPM DNS Manager"),
        ("cloudns", "ClouDNS"),
        ("desec", "deSEC"),
    ]
    .into_iter()
    .map(|(kind, label)| {
        let (implemented, credential_fields, options, record_options) = match kind {
            "tencentcloud" => (true, pair("TENCENT_"), vec![], vec![]),
            "cloudflare" => (
                true,
                token("CLOUDFLARE_"),
                vec![option("zone_id", "Optional exact Zone ID")],
                vec![option(
                    "proxied",
                    "Proxy new record: true / false (existing proxy state is preserved)",
                )],
            ),
            "alidns" => (
                true,
                pair("ALIDNS_"),
                vec![option("region", "Region ID (default cn-hangzhou)")],
                vec![],
            ),
            "godaddy" => (true, pair("GODADDY_"), vec![], vec![]),
            "vercel" => (
                true,
                token("VERCEL_"),
                vec![option("team_id", "Optional Vercel Team ID")],
                vec![],
            ),
            "namecheap" => (
                true, // Author frozen: offline adapter tests and strict lint passed.
                pair("NAMECHEAP_"),
                [
                    ("scope", "Required basicdns_plain (registered active BasicDNS only)"),
                    ("write_mode", "Required exclusive_full_zone (whole host-array replacement acknowledgement)"),
                    ("environment", "Required production or sandbox (no fallback)"),
                    ("sld", "Required explicit domain SLD (no PSL guessing)"),
                    ("tld", "Required explicit domain TLD (e.g. com or co.uk)"),
                    ("client_ip_env", "Required NAMECHEAP_ server egress public IPv4 environment reference"),
                ].into_iter().map(|(key, label)| OptionField { key, label, required: true }).collect(),
                vec![],
            ),
            "name_com" => (true, pair("NAMECOM_"), vec![], vec![]),
            "rainyun" => (
                true,
                token("RAINYUN_"),
                vec![OptionField {
                    key: "domain_id",
                    label: "Rainyun domain product ID",
                    required: true,
                }],
                vec![],
            ),
            "cloudns" => (
                true,
                pair("CLOUDNS_"),
                vec![option(
                    "auth_type",
                    "auth-id (default), sub-auth-id or sub-auth-user",
                )],
                vec![],
            ),
            "dynv6" => (
                true,
                token("DYNV6_"),
                vec![OptionField {
                    key: "ttl_mode",
                    label: "Required provider_default: configured TTL is NOT enforced",
                    required: true,
                }],
                vec![],
            ),
            "spaceship" => (true, pair("SPACESHIP_"), vec![], vec![]),
            "gcore" => (
                true,
                token("GCORE_"),
                vec![option(
                    "plan",
                    "Actual Gcore plan: free (default), pro, enterprise",
                )],
                vec![],
            ),
            "nsone" => (true, token("NS1_"), vec![], vec![]),
            "dnsla" => (true, pair("DNSLA_"), vec![], vec![]),
            "desec" => (true, token("DESEC_"), vec![], vec![]),
            "porkbun" => (true, pair("PORKBUN_"), vec![], vec![]),
            "namesilo" => (true, token("NAMESILO_"), vec![], vec![]),
            "hipmdnsmgr" => (
                true,
                token("HIPM_"),
                vec![
                    OptionField {
                        key: "endpoint_env",
                        label: "Server-owned HIPM_ endpoint environment name (HTTPS only)",
                        required: true,
                    },
                    option("domain_id", "Optional positive int64 manager domain ID"),
                ],
                vec![],
            ),
            "huaweicloud" => (
                true,
                pair("HUAWEICLOUD_"),
                vec![
                    OptionField {
                        key: "region",
                        label: "Required official DNS SDK region (trusted immutable endpoint)",
                        required: true,
                    },
                    OptionField {
                        key: "project_id",
                        label: "Required regional IAM project ID (no discovery)",
                        required: true,
                    },
                    option("zone_id", "Optional exact PUBLIC ACTIVE Zone ID"),
                ],
                vec![option(
                    "zone_id",
                    "Optional Zone ID; must agree with provider Zone ID",
                )],
            ),
            "baiducloud" => (
                true,
                pair("BAIDUCLOUD_"),
                vec![OptionField {
                    key: "resource_id",
                    label: "Required owned registered-domain resourceId",
                    required: true,
                }],
                vec![],
            ),
            "edgeone" => (
                true,
                pair("EDGEONE_"),
                vec![
                    OptionField {
                        key: "mode",
                        label: "Required dns (native DNS, NOT origin)",
                        required: true,
                    },
                    OptionField {
                        key: "scope",
                        label: "Required teodns (NS/full sites only)",
                        required: true,
                    },
                    OptionField {
                        key: "api_version",
                        label: "Required 2022-09-01 (no fallback)",
                        required: true,
                    },
                    OptionField {
                        key: "zone_id",
                        label: "Required native zone-... ID",
                        required: true,
                    },
                ],
                vec![],
            ),
            "trafficroute" => (
                true,
                pair("TRAFFICROUTE_"),
                vec![
                    OptionField {
                        key: "scope",
                        label: "Required public_dns (Volcengine, NOT Tencent)",
                        required: true,
                    },
                    OptionField {
                        key: "api_version",
                        label: "Required 2018-08-01",
                        required: true,
                    },
                    OptionField {
                        key: "region",
                        label: "Required cn-beijing signing region",
                        required: true,
                    },
                    OptionField {
                        key: "zone_id",
                        label: "Required canonical positive int64 ZID",
                        required: true,
                    },
                ],
                vec![],
            ),
            "callback" => (
                true,
                token("CALLBACK_"),
                vec![
                    OptionField {
                        key: "endpoint_env",
                        label: "Server-owned CALLBACK_ HTTPS endpoint reference",
                        required: true,
                    },
                    OptionField {
                        key: "mode",
                        label: "Required json_post (no GET templates)",
                        required: true,
                    },
                    OptionField {
                        key: "verification",
                        label: "Required unverified (NOT DNS success)",
                        required: true,
                    },
                    OptionField {
                        key: "delivery",
                        label: "Required every_run (no idempotency guarantee)",
                        required: true,
                    },
                    OptionField {
                        key: "ttl_mode",
                        label: "Required metadata_only (NOT DNS TTL control)",
                        required: true,
                    },
                ],
                vec![],
            ),
            "dnspod" => (true, pair("DNSPOD_"), vec![], vec![]),
            _ => (false, vec![], vec![], vec![]),
        };
        Descriptor {
            kind,
            label,
            implemented,
            supports_dns_read: implemented && kind != "callback",
            credential_fields,
            options,
            record_options,
        }
    })
    .collect()
}
pub fn descriptor(kind: &str) -> Option<Descriptor> {
    catalog().into_iter().find(|p| p.kind == kind)
}
pub fn valid_endpoint_env(name: &str) -> bool {
    (6..=64).contains(&name.len())
        && name.starts_with("HIPM_")
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}
pub fn valid_env(name: &str, prefix: &str) -> bool {
    ((name.starts_with(prefix) && name.len() > prefix.len())
        || (name.starts_with("DDNS_") && name.len() > 5))
        && name.len() <= 128
        && name
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_has_all_upstream_choices_no_fake_fallback() {
        let list = catalog();
        assert_eq!(list.len(), 29);
        let kinds: std::collections::HashSet<_> = list.iter().map(|p| p.kind).collect();
        assert_eq!(kinds.len(), 29);
        assert_eq!(list.iter().filter(|p| p.implemented).count(), 24);
        for (kind, prefix, required, records) in [
            (
                "namecheap",
                "NAMECHEAP_",
                vec![
                    "scope",
                    "write_mode",
                    "environment",
                    "sld",
                    "tld",
                    "client_ip_env",
                ],
                vec![],
            ),
            (
                "huaweicloud",
                "HUAWEICLOUD_",
                vec!["region", "project_id"],
                vec!["zone_id"],
            ),
            ("baiducloud", "BAIDUCLOUD_", vec!["resource_id"], vec![]),
            (
                "edgeone",
                "EDGEONE_",
                vec!["mode", "scope", "api_version", "zone_id"],
                vec![],
            ),
        ] {
            let d = descriptor(kind).unwrap();
            assert!(d.implemented);
            assert_eq!(d.credential_fields.len(), 2);
            assert!(
                d.credential_fields
                    .iter()
                    .all(|f| f.required && f.env_prefix == prefix)
            );
            assert_eq!(
                d.options
                    .iter()
                    .filter(|f| f.required)
                    .map(|f| f.key)
                    .collect::<Vec<_>>(),
                required
            );
            assert_eq!(
                d.record_options.iter().map(|f| f.key).collect::<Vec<_>>(),
                records
            );
        }
        assert_eq!(
            list.iter()
                .filter(|d| d.implemented && d.supports_dns_read)
                .count(),
            23
        );
        let callback = descriptor("callback").unwrap();
        assert!(!callback.supports_dns_read);
        assert_eq!(callback.credential_fields[0].env_prefix, "CALLBACK_");
        assert!(callback.options.iter().all(|o| o.required));
        assert!(descriptor("trafficroute").unwrap().supports_dns_read);
        assert_eq!(list.iter().filter(|d| !d.implemented).count(), 5);
        assert!(
            list.iter()
                .filter(|d| !d.implemented)
                .all(|d| !d.supports_dns_read)
        );
        assert!(descriptor("unknown").is_none());
    }
    #[test]
    fn environment_references_are_scoped() {
        assert!(valid_env("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_"));
        assert!(valid_env("DDNS_HOME_TOKEN", "CLOUDFLARE_"));
        assert!(!valid_env("PATH", "CLOUDFLARE_"));
        assert!(!valid_env("TENCENT_SECRET_KEY", "CLOUDFLARE_"));
    }
}
