//! Defense-in-depth availability gate, including direct execution bypassing Config.
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot};

#[tokio::test]
async fn unavailable_and_unknown_kinds_fail_at_registry_gate_without_network_fallback() {
    // Contain even a regressed HTTPS fallback at a loopback-only proxy.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = hits.clone();
    let (stop, mut stopped) = oneshot::channel::<()>();
    let proxy = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                accepted = listener.accept() => {
                    let (mut connection, _) = accepted.unwrap();
                    observed.fetch_add(1, Ordering::SeqCst);
                    let _ = connection.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                }
            }
        }
    });
    let client = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://{address}"))
                .unwrap()
                .no_proxy(None),
        )
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_millis(250))
        .build()
        .unwrap();
    let mut kinds: Vec<_> = registry::catalog()
        .into_iter()
        .filter(|descriptor| !descriptor.implemented)
        .map(|descriptor| descriptor.kind.to_string())
        .collect();
    kinds.push("unknown-provider-no-fallback".into());
    kinds.push("namecheap/../../tencentcloud".into());
    let record = RecordConfig {
        name: "unavailable-target".into(),
        provider: "unavailable".into(),
        domain: "example.com".into(),
        subdomain: "home".into(),
        record_type: "A".into(),
        record_line: "default".into(),
        ttl: 600,
        record_id: Some("1".into()),
        options: Default::default(),
        create_if_missing: true,
        enabled: true,
        ip_source: crate::config::IpSource {
            kind: "static".into(),
            value: "1.1.1.1".into(),
        },
    };
    for kind in kinds {
        let mut provider = crate::config::Config::default().providers.remove(0);
        provider.kind = kind;
        // Bypass Config validation deliberately. Registry rejection must take
        // precedence over these invalid refs; no environment is modified and
        // no values are printed. This is not an env-read instrumentation test.
        provider.secret_id_env = "PATH".into();
        provider.secret_key_env = "HOME".into();
        provider.token_env = "PATH".into();
        let error = check_credentials(&provider).unwrap_err();
        assert_eq!(error.code, "UnsupportedProvider");
        for dry_run in [true, false] {
            let error = reconcile(client.clone(), &provider, &record, "1.1.1.1", dry_run)
                .await
                .unwrap_err();
            assert_eq!(error.code, "UnsupportedProvider");
            assert_eq!(error.stage, "configuration");
            assert!(error.http_status.is_none());
        }
    }
    stop.send(()).unwrap();
    proxy.await.unwrap();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "unavailable kind contacted the proxy"
    );
}

#[test]
fn all_implemented_adapters_resolve_direct_credentials_without_env_mutation() {
    for descriptor in registry::catalog().into_iter().filter(|d| d.implemented) {
        let mut config = crate::config::Config::default().providers.remove(0);
        config.kind = descriptor.kind.into();
        config.secret_id_env.clear();
        config.secret_key_env.clear();
        config.token_env.clear();
        for field in &descriptor.credential_fields {
            config
                .credentials
                .insert(field.key.into(), "direct-sensitive-value".into());
            assert_eq!(
                resolve_credential(&config, field).unwrap(),
                "direct-sensitive-value"
            );
        }
        // A supplied compatibility reference is still validated, even with direct values.
        match descriptor.credential_fields[0].key {
            "token_env" => config.token_env = "PATH".into(),
            _ => config.secret_id_env = "PATH".into(),
        }
        let error = resolve_credential(&config, &descriptor.credential_fields[0]).unwrap_err();
        assert_eq!(error.code, "InvalidCredentialEnv");
        assert!(
            !serde_json::to_string(&error)
                .unwrap()
                .contains("direct-sensitive-value")
        );
    }
}

#[tokio::test]
async fn direct_callback_credentials_and_endpoint_support_safe_dry_run() {
    let mut config: crate::config::Config =
        toml::from_str(include_str!("../../examples/callback.toml")).unwrap();
    let provider = &mut config.providers[0];
    provider.token_env.clear();
    provider.options.remove("endpoint_env");
    provider
        .credentials
        .insert("token_env".into(), "private-callback-token".into());
    provider.credentials.insert(
        "endpoint_env".into(),
        "https://private.example/sensitive-hook".into(),
    );
    config.validate().unwrap();
    check_credentials(&config.providers[0]).unwrap();
    let outcome = reconcile(
        reqwest::Client::new(),
        &config.providers[0],
        &config.records[0],
        "8.8.8.8",
        true,
    )
    .await
    .unwrap();
    assert_eq!(outcome.status, "would_call_unverified");
    let result = format!("{outcome:?}");
    assert!(!result.contains("private-callback-token"));
    assert!(!result.contains("private.example"));
}

#[test]
fn direct_endpoint_and_client_ip_preflight_refuses_bad_values_without_exposing_them() {
    for (example, key, good, bad) in [
        (
            include_str!("../../examples/namecheap.toml"),
            "client_ip_env",
            "8.8.8.8",
            "127.0.0.1",
        ),
        (
            include_str!("../../examples/hipmdnsmgr.toml"),
            "endpoint_env",
            "https://private.example/api",
            "https://private.example/api?private=secret",
        ),
        (
            include_str!("../../examples/callback.toml"),
            "endpoint_env",
            "https://private.example/hook",
            "https://private.example/hook?private=secret",
        ),
    ] {
        let mut config: crate::config::Config = toml::from_str(example).unwrap();
        let provider = &mut config.providers[0];
        let descriptor = registry::descriptor(&provider.kind).unwrap();
        provider.secret_id_env.clear();
        provider.secret_key_env.clear();
        provider.token_env.clear();
        provider.options.remove(key);
        for field in descriptor.credential_fields {
            provider
                .credentials
                .insert(field.key.into(), "plain-sensitive-credential".into());
        }
        provider.credentials.insert(key.into(), good.into());
        check_credentials(provider).unwrap();
        check_record(provider, &config.records[0]).unwrap();
        provider.credentials.insert(key.into(), bad.into());
        let error = check_credentials(provider).unwrap_err();
        let serialized = serde_json::to_string(&error).unwrap();
        assert!(!serialized.contains(bad));
        assert!(!serialized.contains("plain-sensitive-credential"));
    }
}
