use std::process::{Command, Output};
fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ddns-rust"))
}
fn run(path: &std::path::Path, args: &[&str]) -> Output {
    binary()
        .arg("--config")
        .arg(path)
        .args(args)
        .env_remove("TENCENT_SECRET_ID")
        .env_remove("TENCENT_SECRET_KEY")
        .env_remove("DDNS_RUST_WEB_TOKEN")
        .output()
        .unwrap()
}
const CONFIG: &str = r#"
interval_secs = 300
timeout_secs = 2
log_level = "debug"
[[providers]]
name = "tencent"
secret_id_env = "TENCENT_SECRET_ID"
secret_key_env = "TENCENT_SECRET_KEY"
[[records]]
name = "first"
provider = "tencent"
domain = "example.com"
subdomain = "home"
record_type = "A"
record_line = "默认"
ttl = 600
create_if_missing = false
enabled = false
[records.ip_source]
kind = "static"
value = "1.1.1.1"
[[records]]
name = "second"
provider = "tencent"
domain = "example.com"
subdomain = "other"
record_type = "A"
record_line = "默认"
ttl = 600
create_if_missing = false
enabled = false
[records.ip_source]
kind = "static"
value = "1.1.1.1"
"#;
#[test]
fn initialization_is_safe_and_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    assert!(run(&path, &["init"]).status.success());
    let before = std::fs::read(&path).unwrap();
    assert!(!run(&path, &["init"]).status.success());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(run(&path, &["check"]).status.success());
}
#[test]
fn diagnose_checks_disabled_records_and_reports_each_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, CONFIG).unwrap();
    let result = run(&path, &["diagnose"]);
    assert_eq!(result.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    let results = report["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    for record in results {
        assert_eq!(record["error"]["code"], "MissingCredentials");
        assert_eq!(record["error"]["stage"], "credentials");
        assert!(
            record["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("SecretId")
        );
    }
    for line in String::from_utf8(result.stderr)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with('{'))
    {
        let log: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(log.get("timestamp").is_some());
        assert!(log.get("fields").is_some());
    }
}
#[test]
fn real_run_skips_disabled_records_without_credentials_or_network() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, CONFIG).unwrap();
    let result = run(&path, &["once"]);
    assert!(result.status.success());
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["dry_run"], false);
    for record in report["results"].as_array().unwrap() {
        assert_eq!(record["status"], "disabled");
    }
}
#[test]
fn web_server_requires_secure_length_token_without_echoing_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, CONFIG).unwrap();
    let result = run(&path, &["serve", "--token", "too-short-secret"]);
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("too-short-secret"));
}
#[test]
fn planned_providers_cannot_be_enabled_by_configuration_or_client_flags() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    for kind in ["aliesa", "dynadot", "nowcn", "eranet", "tnethk"] {
        let disabled = CONFIG.replacen(
            "[[providers]]\n",
            &format!("[[providers]]\nkind = '{kind}'\n"),
            1,
        );
        for config in [
            disabled.clone(),
            disabled.replace("enabled = false", "enabled = true"),
        ] {
            std::fs::write(&path, &config).unwrap();
            for action in ["check", "diagnose", "once"] {
                let result = run(&path, &[action]);
                assert!(
                    !result.status.success(),
                    "{kind}/{action} bypassed availability"
                );
                let stderr = String::from_utf8_lossy(&result.stderr);
                assert!(
                    stderr.contains("not implemented"),
                    "{kind}/{action} failed at wrong gate"
                );
                assert!(stderr.contains("no fallback"));
                assert!(
                    result.stdout.is_empty(),
                    "{kind}/{action} emitted a DNS run report"
                );
                assert_eq!(std::fs::read(&path).unwrap(), config.as_bytes());
            }
        }
        // Implementation is server-owned registry data, not a config flag.
        let forged = disabled.replacen("[[providers]]\n", "[[providers]]\nimplemented = true\n", 1);
        std::fs::write(&path, &forged).unwrap();
        let result = run(&path, &["check"]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("unknown field"));
        assert_eq!(std::fs::read(&path).unwrap(), forged.as_bytes());
    }
}

#[test]
fn unknown_configuration_fields_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!("secret_key = 'do-not-configure-secrets'\n{CONFIG}"),
    )
    .unwrap();
    assert!(!run(&path, &["check"]).status.success());
}

#[test]
fn service_flags_are_documented_but_internal_entry_is_hidden() {
    let result = binary().arg("--help").output().unwrap();
    assert!(result.status.success());
    let help = String::from_utf8_lossy(&result.stdout);
    assert!(help.contains("-s, --service"));
    assert!(help.contains("install") && help.contains("uninstall"));
    assert!(!help.contains("--service-run"));
    // Parsing help must never register a service, even when -s is present.
    assert!(
        binary()
            .args(["serve", "-s", "install", "--help"])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn service_mode_rejects_one_shot_commands_before_touching_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.toml");
    for command in ["init", "check", "diagnose", "once"] {
        for action in ["install", "uninstall"] {
            for args in [
                vec!["-s", action, command],
                vec![command, "--service", action],
            ] {
                let result = run(&path, &args);
                assert!(!result.status.success());
                assert!(
                    String::from_utf8_lossy(&result.stderr).contains("Service mode supports only")
                );
                assert!(!path.exists());
            }
        }
    }
}

#[test]
fn service_mode_rejects_conflicting_flags_and_invalid_listener() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.toml");
    assert!(
        !run(&path, &["-s", "install", "--service-run"])
            .status
            .success()
    );
    let result = run(
        &path,
        &["serve", "-s", "install", "--listen", "127.0.0.1:0"],
    );
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Listen port must be nonzero"));
    assert!(!path.exists());
}

#[test]
fn service_requires_explicit_install_or_uninstall() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.toml");
    for args in [
        vec!["-s"],
        vec!["-s", "remove"],
        vec!["--service", "restart"],
    ] {
        let result = run(&path, &args);
        assert!(!result.status.success());
        assert!(!path.exists());
    }
    // Show help without running uninstall; no host services may be modified by tests.
    let result = run(&path, &["-s", "uninstall", "--help"]);
    assert!(result.status.success());
    assert!(!path.exists());
}

#[cfg(not(windows))]
#[test]
fn internal_windows_service_entry_is_rejected_on_unix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.toml");
    let result = run(&path, &["--service-run"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("internal Windows SCM"));
    assert!(!path.exists());
}
