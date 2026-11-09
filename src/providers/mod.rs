// Error DTOs deliberately retain full diagnostic context on a cold path.
#![allow(clippy::result_large_err)]

mod alidns;
#[cfg(test)]
mod availability_tests;
mod baiducloud;
pub(crate) mod callback;
mod cloudflare;
mod cloudns;
pub mod common;
mod desec;
mod dnsla;
mod dnspod;
mod dynv6;
mod edgeone;
mod gcore;
mod godaddy;
mod hipmdnsmgr;
mod huaweicloud;
mod name_com;
pub(crate) mod namecheap;
mod namesilo;
mod nsone;
mod porkbun;
mod rainyun;
pub mod registry;
mod spaceship;
pub(crate) mod trafficroute;
mod vercel;
use crate::{
    config::{ProviderConfig, RecordConfig},
    provider::{self, ProviderError},
};
pub use common::Outcome;

fn resolve_credential(
    config: &ProviderConfig,
    field: &registry::CredentialField,
) -> Result<String, ProviderError> {
    let reference = match field.key {
        "secret_id_env" => &config.secret_id_env,
        "secret_key_env" => &config.secret_key_env,
        "token_env" => &config.token_env,
        _ => unreachable!("registered credential field"),
    };
    if !reference.is_empty() && !registry::valid_env(reference, field.env_prefix) {
        return Err(common::local_error(
            "configuration",
            "InvalidCredentialEnv",
            "Credential environment reference is not valid for the selected provider.",
            "Use the provider namespace or DDNS_ namespace; direct values belong in credentials.",
            None,
        ));
    }
    let value = config
        .direct_credential(field.key)
        .map(str::to_owned)
        .or_else(|| {
            (!reference.is_empty())
                .then(|| std::env::var(reference).ok())
                .flatten()
        });
    value.filter(|v| !v.trim().is_empty()).ok_or_else(|| common::local_error(
        "credentials", "MissingCredentials", "A required credential is not configured for the selected provider.",
        "Configure a direct credential or its compatible server environment reference. Tencent SecretId/Key differs from legacy DNSPod ID/Token; use credentials for the selected API. Credential values are never returned.", None))
}

pub(crate) fn check_hipm_endpoint_value(value: &str) -> Result<(), ProviderError> {
    hipmdnsmgr::production_origin(value).map(|_| ()).ok_or_else(|| common::local_error(
        "configuration", "InvalidEndpoint", "HiPM endpoint must be a plain HTTPS origin, optionally ending in /api, without userinfo, query or fragment. Its value is intentionally omitted.",
        "Configure a verified HTTPS origin; there is no global fallback.", None))
}

fn hipm_endpoint(config: &ProviderConfig) -> Result<String, ProviderError> {
    let name = config
        .options
        .get("endpoint_env")
        .map(String::as_str)
        .unwrap_or("");
    if !name.is_empty() && !registry::valid_endpoint_env(name) {
        return Err(common::local_error(
            "configuration",
            "InvalidEndpointEnv",
            "endpoint_env must name a HIPM_-scoped server environment variable.",
            "Direct values belong in credentials; arbitrary environment lookups are refused.",
            None,
        ));
    }
    let value = config.direct_credential("endpoint_env").map(str::to_owned)
        .or_else(|| (!name.is_empty()).then(|| std::env::var(name).ok()).flatten())
        .ok_or_else(|| common::local_error("configuration", "MissingEndpoint", "HiPM endpoint is not configured.", "Configure a direct endpoint or HIPM_-scoped environment reference. Its value is never returned.", None))?;
    check_hipm_endpoint_value(&value)?;
    Ok(value)
}

pub fn check_credentials(config: &ProviderConfig) -> Result<(), ProviderError> {
    let descriptor = registry::descriptor(&config.kind)
        .filter(|d| d.implemented)
        .ok_or_else(|| {
            common::local_error(
                "configuration",
                "UnsupportedProvider",
                "Provider adapter is unavailable.",
                "No fallback or mutation was attempted.",
                None,
            )
        })?;
    for field in &descriptor.credential_fields {
        resolve_credential(config, field)?;
    }
    if config.kind == "namecheap" {
        let user = resolve_credential(config, &descriptor.credential_fields[0])?;
        let key = resolve_credential(config, &descriptor.credential_fields[1])?;
        namecheap::check_credentials(&user, &key)?;
        namecheap::check_client_ip_with_direct(
            &config.options,
            config.direct_credential("client_ip_env"),
        )?;
    }
    if config.kind == "callback" {
        let token = resolve_credential(config, &descriptor.credential_fields[0])?;
        if token.len() > 4096
            || !token.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            })
        {
            return Err(common::local_error(
                "credentials",
                "InvalidCredentials",
                "Callback requires a plain Bearer token of at most 4096 bytes; whitespace/control characters are refused.",
                "Set a valid callback token; no network request was attempted.",
                None,
            ));
        }
        callback::endpoint_with_direct(&config.options, config.direct_credential("endpoint_env"))?;
    }
    if config.kind == "hipmdnsmgr" {
        hipm_endpoint(config)?;
    }
    Ok(())
}

/// Local record contract checks must run before any IP-source network request.
pub fn check_record(config: &ProviderConfig, record: &RecordConfig) -> Result<(), ProviderError> {
    if config.kind == "namecheap" {
        namecheap::check_spec_with_direct(
            &common::Spec {
                domain: record.domain.clone(),
                subdomain: record.subdomain.clone(),
                record_type: record.record_type.clone(),
                record_line: record.record_line.clone(),
                ttl: record.ttl,
                record_id: record.record_id.clone(),
                create_if_missing: record.create_if_missing,
                options: record.options.clone(),
            },
            &config.options,
            config.direct_credential("client_ip_env").is_some(),
        )?;
    }
    if config.kind == "callback" {
        callback::check_spec(&common::Spec {
            domain: record.domain.clone(),
            subdomain: record.subdomain.clone(),
            record_type: record.record_type.clone(),
            record_line: record.record_line.clone(),
            ttl: record.ttl,
            record_id: record.record_id.clone(),
            create_if_missing: record.create_if_missing,
            options: record.options.clone(),
        })?;
    }
    Ok(())
}

pub async fn reconcile(
    client: reqwest::Client,
    config: &ProviderConfig,
    record: &RecordConfig,
    ip: &str,
    dry_run: bool,
) -> Result<Outcome, ProviderError> {
    let descriptor = registry::descriptor(&config.kind)
        .filter(|d| d.implemented)
        .ok_or_else(|| {
            common::local_error(
                "configuration",
                "UnsupportedProvider",
                "Provider is not implemented; no fallback was selected.",
                "Choose a supported adapter from /api/providers.",
                None,
            )
        })?;
    let mut id = String::new();
    let mut key = String::new();
    let mut token = String::new();
    for field in &descriptor.credential_fields {
        let value = resolve_credential(config, field)?;
        match field.key {
            "secret_id_env" => id = value,
            "secret_key_env" => key = value,
            "token_env" => token = value,
            _ => {}
        }
    }
    if config.kind == "tencentcloud" {
        let record_id = record
            .record_id
            .as_ref()
            .map(|id| id.parse::<u64>())
            .transpose()
            .map_err(|_| {
                common::local_error(
                    "validation",
                    "InvalidRecordId",
                    "Tencent Cloud requires a positive decimal RecordId.",
                    "Correct record_id.",
                    None,
                )
            })?;
        let outcome = provider::Provider::new(
            client,
            provider::Credentials {
                secret_id: id,
                secret_key: key,
            },
        )
        .reconcile(
            &provider::RecordSpec {
                domain: record.domain.clone(),
                subdomain: record.subdomain.clone(),
                record_type: record.record_type.clone(),
                record_line: record.record_line.clone(),
                ttl: record.ttl,
                record_id,
                create_if_missing: record.create_if_missing,
            },
            ip,
            dry_run,
        )
        .await?;
        return Ok(Outcome {
            status: outcome.status,
            previous_ip: outcome.previous_ip,
            current_ip: outcome.current_ip,
            record_id: outcome.record_id.map(|id| id.to_string()),
            request_id: outcome.request_id,
        });
    }
    let mut spec = common::Spec {
        domain: record.domain.clone(),
        subdomain: record.subdomain.clone(),
        record_type: record.record_type.clone(),
        record_line: record.record_line.clone(),
        ttl: record.ttl,
        record_id: record.record_id.clone(),
        create_if_missing: record.create_if_missing,
        options: record.options.clone(),
    };
    match config.kind.as_str() {
        "namecheap" => {
            common::reconcile(
                &namecheap::Namecheap::new_with_direct(
                    client,
                    id,
                    key,
                    &config.options,
                    config.direct_credential("client_ip_env"),
                ),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "trafficroute" => {
            common::reconcile(
                &trafficroute::TrafficRoute::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "callback" => {
            callback::Callback::new_with_direct(
                client,
                token,
                &config.options,
                config.direct_credential("endpoint_env"),
            )
            .execute(&spec, ip, dry_run)
            .await
        }
        "cloudflare" => {
            common::reconcile(
                &cloudflare::Cloudflare::new(client, token, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "alidns" => {
            if spec.record_line == "默认" {
                spec.record_line = "default".into();
            }
            common::reconcile(
                &alidns::Alidns::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "dnspod" => {
            common::reconcile(
                &dnspod::Dnspod::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "porkbun" => {
            common::reconcile(
                &porkbun::Porkbun::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "desec" => {
            common::reconcile(
                &desec::Desec::new(client, token, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "dnsla" => {
            common::reconcile(
                &dnsla::Dnsla::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "godaddy" => {
            common::reconcile(
                &godaddy::Godaddy::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "vercel" => {
            common::reconcile(
                &vercel::Vercel::new(client, token, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "cloudns" => {
            common::reconcile(
                &cloudns::Cloudns::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "rainyun" => {
            common::reconcile(
                &rainyun::Rainyun::new(client, token, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "name_com" => {
            common::reconcile(
                &name_com::NameCom::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "dynv6" => {
            common::reconcile(
                &dynv6::Dynv6::new(client, token, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "spaceship" => {
            common::reconcile(
                &spaceship::Spaceship::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "gcore" => {
            common::reconcile(
                &gcore::Gcore::new(client, token, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "namesilo" => {
            common::reconcile(
                &namesilo::Namesilo::new(client, token, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "hipmdnsmgr" => {
            common::reconcile(
                &hipmdnsmgr::HipmDnsMgr::new_with_direct(
                    client,
                    token,
                    &config.options,
                    Some(&hipm_endpoint(config)?),
                ),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "huaweicloud" => {
            common::reconcile(
                &huaweicloud::HuaweiCloud::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "baiducloud" => {
            common::reconcile(
                &baiducloud::BaiduCloud::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "edgeone" => {
            common::reconcile(
                &edgeone::EdgeOne::new(client, id, key, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        "nsone" => {
            common::reconcile(
                &nsone::Nsone::new(client, token, &config.options),
                &spec,
                ip,
                dry_run,
            )
            .await
        }
        _ => Err(common::local_error(
            "configuration",
            "UnsupportedProvider",
            "Provider adapter is unavailable.",
            "No fallback or mutation was attempted.",
            None,
        )),
    }
}
