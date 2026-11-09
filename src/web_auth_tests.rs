use crate::*;
use axum::body::{Body, to_bytes};
use tower::ServiceExt;

fn request(
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
    cookie: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
        .unwrap()
}
async fn json(response: Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}
fn app(
    config: Config,
    dir: &std::path::Path,
    settings: web_auth::WebSettings,
    control: LogControl,
) -> App {
    App {
        config: Arc::new(RwLock::new(config)),
        path: Arc::new(dir.join("config.toml")),
        control,
        run_lock: Arc::new(Mutex::new(())),
        last_run: Arc::new(RwLock::new(None)),
        notify: Arc::new(Notify::new()),
        token: Arc::new(String::new()),
        auth_state: Arc::new(Mutex::new(web_auth::AuthState::new(
            settings,
            "127.0.0.1:9876".parse().unwrap(),
            dir.join("config.toml.web.toml"),
        ))),
    }
}
#[tokio::test]
async fn first_run_account_config_settings_and_restart_contract() {
    use tracing_subscriber::prelude::*;
    let logs = logging::Logs(Arc::new(std::sync::Mutex::new(
        std::collections::VecDeque::new(),
    )));
    let (layer, filter) = tracing_subscriber::reload::Layer::new(logging::filter("info"));
    let _subscriber = tracing::Dispatch::new(
        tracing_subscriber::registry()
            .with(layer)
            .with(logs.clone()),
    );
    let control = LogControl { logs, filter };
    let dir = tempfile::tempdir().unwrap();
    let config = load_startup_config(&dir.path().join("config.toml"), true)
        .await
        .unwrap();
    assert!(config.providers.is_empty() && config.records.is_empty());
    let application = app(
        config,
        dir.path(),
        web_auth::WebSettings::default(),
        control.clone(),
    );
    let router = router(application.clone());
    let response = router
        .clone()
        .oneshot(request("GET", "/api/auth/status", None, None))
        .await
        .unwrap();
    assert_eq!(json(response).await["initialized"], false);
    for route in [
        "/api/config",
        "/api/settings",
        "/api/logs",
        "/api/status",
        "/api/interfaces",
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request("GET", route, None, None))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let account = serde_json::json!({"username":"admin","password":"strong-initial-password"});
    let response = router
        .clone()
        .oneshot(request(
            "POST",
            "/api/auth/setup",
            Some(serde_json::json!({"username":"admin","password":"short"})),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = router
        .clone()
        .oneshot(request(
            "POST",
            "/api/auth/setup",
            Some(account.clone()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"));
    let cookie = set_cookie.split(';').next().unwrap();
    let response = router
        .clone()
        .oneshot(request("GET", "/api/interfaces", None, Some(cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let interfaces = json(response).await;
    for interface in interfaces.as_array().unwrap() {
        assert!(!interface["name"].as_str().unwrap().is_empty());
        assert!(
            !interface["ipv4"].as_array().unwrap().is_empty()
                || !interface["ipv6"].as_array().unwrap().is_empty()
        );
        for (key, ipv4) in [("ipv4", true), ("ipv6", false)] {
            let addresses: Vec<std::net::IpAddr> = interface[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|ip| ip.as_str().unwrap().parse().unwrap())
                .collect();
            assert!(addresses.iter().all(|ip| ip.is_ipv4() == ipv4));
            assert!(addresses.windows(2).all(|pair| pair[0] < pair[1]));
        }
    }
    let preview = serde_json::json!({
        "record_type": "AAAA",
        "ip_source": {"kind": "interface", "value": "", "regex": "("}
    });
    let response = router
        .clone()
        .oneshot(request(
            "POST",
            "/api/interfaces/preview",
            Some(preview.clone()),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(request(
            "POST",
            "/api/interfaces/preview",
            Some(preview),
            Some(cookie),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json(response).await["error"], "Invalid IP regex");
    if let Some(name) = interfaces[0]["name"].as_str() {
        let preview = serde_json::json!({
            "record_type": "AAAA",
            "ip_source": {"kind": "interface", "value": name, "regex": "^no-match$"}
        });
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                "/api/interfaces/preview",
                Some(preview),
                Some(cookie),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json(response).await, serde_json::json!([]));
    }
    assert_eq!(
        router
            .clone()
            .oneshot(request(
                "POST",
                "/api/auth/setup",
                Some(account.clone()),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    let response = router
        .clone()
        .oneshot(request("GET", "/api/config", None, Some(cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut config = json(response).await;
    config["providers"] = serde_json::json!([{"name":"web","kind":"cloudflare","credentials":{"token_env":"private-provider-value"},"options":{}}]);
    let response = router
        .clone()
        .oneshot(request("PUT", "/api/config", Some(config), Some(cookie)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let masked = json(response).await;
    assert_eq!(
        masked["providers"][0]["credentials"]["token_env"],
        "__DDNS_CONFIGURED__"
    );
    assert!(!masked.to_string().contains("private-provider-value"));
    let mut preserved = masked.clone();
    preserved["interval_secs"] = serde_json::json!(600);
    assert_eq!(
        router
            .clone()
            .oneshot(request("PUT", "/api/config", Some(preserved), Some(cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        Config::load(&dir.path().join("config.toml"))
            .await
            .unwrap()
            .providers[0]
            .credentials["token_env"],
        "private-provider-value"
    );
    let mut renamed = masked;
    renamed["providers"][0]["name"] = serde_json::json!("renamed");
    assert_eq!(
        router
            .clone()
            .oneshot(request("PUT", "/api/config", Some(renamed), Some(cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut cross_origin = request(
        "PUT",
        "/api/settings",
        Some(serde_json::json!({"listen":"127.0.0.1:9999","username":"admin"})),
        Some(cookie),
    );
    cross_origin
        .headers_mut()
        .insert("host", "127.0.0.1:9876".parse().unwrap());
    cross_origin
        .headers_mut()
        .insert("origin", "https://evil.invalid".parse().unwrap());
    assert_eq!(
        router.clone().oneshot(cross_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let response = router.clone().oneshot(request("PUT", "/api/settings", Some(serde_json::json!({"listen":"127.0.0.1:9999","username":"admin","password":"changed-strong-password","token":"legacy-token-abcdefghijklmnopqrstuvwxyz"})), Some(cookie))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let settings = json(response).await;
    assert_eq!(settings["listen"], "127.0.0.1:9999");
    assert_eq!(settings["active_listen"], "127.0.0.1:9876");
    assert_eq!(settings["token_configured"], true);
    assert!(!settings.to_string().contains("changed-strong-password"));
    assert_eq!(
        router
            .clone()
            .oneshot(request("GET", "/api/config", None, Some(cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        router
            .clone()
            .oneshot(request("POST", "/api/auth/login", Some(account), None))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let persisted = web_auth::WebSettings::load(&dir.path().join("config.toml.web.toml"))
        .await
        .unwrap();
    assert!(persisted.password_hash.starts_with("$argon2id$"));
    assert!(
        web_auth::verify_password(
            persisted.password_hash.clone(),
            "changed-strong-password".into()
        )
        .await
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["config.toml", "config.toml.web.toml"] {
            assert_eq!(
                std::fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    let restarted = crate::router(app(
        Config::load(&dir.path().join("config.toml")).await.unwrap(),
        dir.path(),
        persisted,
        control,
    ));
    let response = restarted
        .clone()
        .oneshot(request(
            "POST",
            "/api/auth/login",
            Some(serde_json::json!({"username":"admin","password":"changed-strong-password"})),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .to_owned();
    let cookie = set_cookie.split(';').next().unwrap();
    assert_eq!(
        restarted
            .clone()
            .oneshot(request("POST", "/api/auth/logout", None, Some(cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        restarted
            .oneshot(request("GET", "/api/config", None, Some(cookie)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn malformed_existing_config_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    tokio::fs::write(&path, "not valid TOML!").await.unwrap();
    assert!(load_startup_config(&path, true).await.is_err());
    assert_eq!(
        tokio::fs::read_to_string(&path).await.unwrap(),
        "not valid TOML!"
    );
    assert!(
        load_startup_config(&dir.path().join("missing.toml"), false)
            .await
            .is_err()
    );
}
#[test]
fn authentication_attempts_are_bounded() {
    let mut state = web_auth::AuthState::new(
        web_auth::WebSettings::default(),
        "127.0.0.1:9876".parse().unwrap(),
        PathBuf::new(),
    );
    for _ in 0..10 {
        assert!(state.allow_attempt());
    }
    assert!(!state.allow_attempt());
    assert!(!state.session_valid(""));
}
