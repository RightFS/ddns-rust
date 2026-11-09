use crate::{
    config::{Config, RecordConfig},
    provider::ProviderError,
    providers::Outcome,
};
use chrono::Utc;
use serde::Serialize;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tracing::Instrument;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct RecordResult {
    pub name: String,
    pub status: String,
    pub ip: Option<String>,
    pub outcome: Option<Outcome>,
    pub error: Option<ProviderError>,
}
#[derive(Clone, Debug, Serialize)]
pub struct RunReport {
    pub run_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub dry_run: bool,
    pub results: Vec<RecordResult>,
}
pub fn error(stage: &str, code: &str, message: impl Into<String>, hint: &str) -> ProviderError {
    ProviderError {
        stage: stage.into(),
        code: code.into(),
        message: message.into(),
        hint: hint.into(),
        request_id: None,
        http_status: None,
        retryable: false,
    }
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_private()
                && !v.is_loopback()
                && !v.is_link_local()
                && !v.is_unspecified()
                && !v.is_multicast()
                && !v.is_broadcast()
                && v.octets()[0] != 0
                && v.octets()[0] < 240
                && !(v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1]))
                && !v.is_documentation()
                && !(v.octets()[0] == 192
                    && ((v.octets()[1] == 0 && v.octets()[2] == 0)
                        || (v.octets()[1] == 88 && v.octets()[2] == 99)))
                && !(v.octets()[0] == 198 && matches!(v.octets()[1], 18 | 19))
        }
        IpAddr::V6(v) => {
            (v.segments()[0] & 0xe000) == 0x2000
                && (v.segments()[0] != 0x2001 || v.segments()[1] != 0x0db8)
        }
    }
}
// Diagnostic errors intentionally own complete context; this is not a hot path.
#[allow(clippy::result_large_err)]
pub async fn detect_ip(record: &RecordConfig, timeout: u64) -> Result<String, ProviderError> {
    let family = record.record_type == "A";
    let fail = |code: &str, msg: String| {
        error(
            "ip_detection",
            code,
            msg,
            "Check IP source, network routing and the selected A/AAAA family. Use a static IP to isolate provider issues.",
        )
    };
    let ip = match record.ip_source.kind.as_str() {
        "static" => record.ip_source.value.parse::<IpAddr>().map_err(|_| {
            fail(
                "InvalidIp",
                "Static source did not contain an IP address".into(),
            )
        })?,
        "interface" => {
            let interfaces =
                if_addrs::get_if_addrs().map_err(|e| fail("InterfaceReadFailed", e.to_string()))?;
            let mut candidates: Vec<_> = interfaces
                .into_iter()
                .filter(|i| i.name == record.ip_source.value)
                .map(|i| i.ip())
                .filter(|ip| ip.is_ipv4() == family && public_ip(*ip))
                .collect();
            candidates.sort();
            candidates.dedup();
            if candidates.len() != 1 {
                return Err(fail(
                    "AmbiguousInterfaceIp",
                    format!(
                        "Interface {} has {} public addresses matching {}. Select an explicit static address or HTTPS source instead",
                        record.ip_source.value,
                        candidates.len(),
                        record.record_type
                    ),
                ));
            }
            candidates[0]
        }
        "url" => {
            let local = if family {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout))
                .connect_timeout(Duration::from_secs(timeout.min(10)))
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .local_address(local)
                .build()
                .map_err(|e| fail("HttpClientFailed", e.to_string()))?;
            let start = std::time::Instant::now();
            tracing::debug!(record=%record.name,family=%record.record_type,"Starting IP source request");
            let mut response = client
                .get(&record.ip_source.value)
                .send()
                .await
                .map_err(|e| {
                    fail(
                        if e.is_timeout() {
                            "IpSourceTimeout"
                        } else {
                            "IpSourceNetworkError"
                        },
                        e.without_url().to_string(),
                    )
                })?;
            if !response.status().is_success() {
                let mut e = fail(
                    "IpSourceHttpError",
                    format!("IP source returned HTTP {}", response.status()),
                );
                e.http_status = Some(response.status().as_u16());
                return Err(e);
            }
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| fail("IpSourceBodyError", e.without_url().to_string()))?
            {
                if body.len() + chunk.len() > 1024 {
                    return Err(fail(
                        "IpSourceResponseTooLarge",
                        "IP source must return a plain IP address (maximum 1024 bytes)".into(),
                    ));
                }
                body.extend_from_slice(&chunk);
            }
            let text = std::str::from_utf8(&body).map_err(|_| {
                fail(
                    "InvalidIpResponse",
                    "IP source returned non-UTF8 data".into(),
                )
            })?;
            let ip = text.trim().parse::<IpAddr>().map_err(|_| {
                fail(
                    "InvalidIpResponse",
                    "IP source did not return a plain IPv4 or IPv6 address".into(),
                )
            })?;
            tracing::debug!(record=%record.name,elapsed_ms=start.elapsed().as_millis() as u64,"IP source request completed");
            ip
        }
        _ => return Err(fail("InvalidIpSource", "Unknown IP source kind".into())),
    };
    if ip.is_ipv4() != family {
        return Err(fail(
            "IpFamilyMismatch",
            format!("Detected address does not match {}", record.record_type),
        ));
    }
    if !public_ip(ip) {
        return Err(fail(
            "NonPublicIp",
            "Refusing to publish a non-public, reserved or documentation IP address".into(),
        ));
    }
    Ok(ip.to_string())
}
pub async fn run(config: &Config, dry_run: bool) -> RunReport {
    let mut report = RunReport {
        run_id: Uuid::new_v4().to_string(),
        started_at: Utc::now().to_rfc3339(),
        finished_at: String::new(),
        dry_run,
        results: vec![],
    };
    tracing::info!(run_id=%report.run_id,dry_run,"DDNS run started");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .connect_timeout(Duration::from_secs(config.timeout_secs.min(10)))
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build();
    for record in &config.records {
        if !record.enabled && !dry_run {
            report.results.push(RecordResult {
                name: record.name.clone(),
                status: "disabled".into(),
                ip: None,
                outcome: None,
                error: None,
            });
            continue;
        }
        let mut result = RecordResult {
            name: record.name.clone(),
            status: "failed".into(),
            ip: None,
            outcome: None,
            error: None,
        };
        let step = async {
            let provider_config = config
                .providers
                .iter()
                .find(|p| p.name == record.provider)
                .ok_or_else(|| {
                    error(
                        "configuration",
                        "UnknownProvider",
                        "Record provider does not exist",
                        "Validate the configuration.",
                    )
                })?;
            crate::providers::check_record(provider_config, record)?;
            crate::providers::check_credentials(provider_config)?;
            let ip = detect_ip(record, config.timeout_secs).await?;
            result.ip = Some(ip.clone());
            let client = client
                .as_ref()
                .map_err(|_| {
                    error(
                        "http",
                        "ClientBuildFailed",
                        "Cannot build TLS HTTP client",
                        "Check system TLS configuration.",
                    )
                })?
                .clone();
            crate::providers::reconcile(client, provider_config, record, &ip, dry_run).await
        }
        .instrument(
            tracing::info_span!("record_run",run_id=%report.run_id,record=%record.name,dry_run),
        )
        .await;
        match step {
            Ok(outcome) => {
                result.status = outcome.status.clone();
                tracing::info!(run_id=%report.run_id,record=%record.name,status=%outcome.status,ip=?result.ip,request_id=?outcome.request_id,"Provider action completed");
                result.outcome = Some(outcome);
            }
            Err(e) => {
                tracing::error!(run_id=%report.run_id,record=%record.name,stage=%e.stage,code=%e.code,provider_message=%e.message,hint=%e.hint,request_id=?e.request_id,http_status=?e.http_status,retryable=e.retryable,"Provider action failed");
                result.error = Some(e);
            }
        }
        report.results.push(result);
    }
    report.finished_at = Utc::now().to_rfc3339();
    tracing::info!(run_id=%report.run_id,failed=report.results.iter().filter(|r|r.error.is_some()).count() as u64,"DDNS run finished");
    report
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_private_addresses() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "192.0.2.1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn accept_public_addresses() {
        assert!(public_ip("1.1.1.1".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
