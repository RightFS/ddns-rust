use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn default_command_starts_with_no_config_account_or_token() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ddns-rust"))
        .arg("--config")
        .arg(&config)
        .env("DDNS_RUST_DEFAULT_LISTEN", address.to_string())
        .env_remove("DDNS_RUST_WEB_TOKEN")
        .env_remove("TENCENT_SECRET_ID")
        .env_remove("TENCENT_SECRET_KEY")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(line) = lines.next_line().await.unwrap() {
            if line.contains("Web server ready") {
                return;
            }
        }
        panic!("server exited before readiness");
    })
    .await
    .unwrap();
    let client = reqwest::Client::new();
    let base = format!("http://{address}");
    assert_eq!(
        client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let status: serde_json::Value = client
        .get(format!("{base}/api/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["initialized"], false);
    assert_eq!(
        client
            .get(format!("{base}/api/config"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let created: toml::Value =
        toml::from_str(&tokio::fs::read_to_string(&config).await.unwrap()).unwrap();
    assert!(created["providers"].as_array().unwrap().is_empty());
    assert!(created["records"].as_array().unwrap().is_empty());
    let setup = client
        .post(format!("{base}/api/auth/setup"))
        .json(&serde_json::json!({"username":"admin","password":"synthetic-initial-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(setup.status(), reqwest::StatusCode::OK);
    let cookie = setup.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let settings: serde_json::Value = client
        .get(format!("{base}/api/settings"))
        .header("cookie", cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settings["active_listen"], address.to_string());
    assert_eq!(settings["listen"], address.to_string());
    assert_eq!(settings["token_configured"], false);
    assert!(config.with_file_name("config.toml.web.toml").exists());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}
