mod config;
mod engine;
mod logging;
mod provider;
mod providers;
mod service;
mod web_auth;
#[cfg(test)]
mod web_auth_tests;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
};
use clap::{Parser, Subcommand};
use config::Config;
use engine::RunReport;
use logging::LogControl;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Notify, RwLock};

#[derive(Parser)]
#[command(
    name = "ddns-rust",
    version,
    about = "Troubleshooting-first multi-provider dynamic DNS"
)]
struct Cli {
    #[arg(long, default_value = "config.toml", global = true)]
    config: PathBuf,
    /// Install/start or stop/uninstall the system service, then exit (administrator required).
    #[arg(
        short = 's',
        long = "service",
        value_enum,
        global = true,
        conflicts_with = "service_run"
    )]
    service: Option<ServiceAction>,
    #[arg(long, hide = true, global = true)]
    service_run: bool,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ServiceAction {
    Install,
    Uninstall,
}
impl Cli {
    fn validate_service_mode(&self) -> Result<(), String> {
        if (self.service.is_some() || self.service_run)
            && self
                .command
                .as_ref()
                .is_some_and(|command| !matches!(command, Command::Serve { .. }))
        {
            return Err("Service mode supports only the default command or serve, not init/check/diagnose/once".into());
        }
        #[cfg(not(windows))]
        if self.service_run {
            return Err("--service-run is an internal Windows SCM entry point".into());
        }
        if self.service.is_some()
            && matches!(&self.command, Some(Command::Serve { listen: Some(address), .. }) if address.port() == 0)
        {
            return Err("Listen port must be nonzero".into());
        }
        Ok(())
    }
}
#[derive(Subcommand)]
enum Command {
    /// Create a safe configuration with no enabled DNS records.
    Init,
    /// Validate local configuration without making network requests.
    Check,
    /// Read-only IP detection and provider diagnostics. Never writes DNS.
    Diagnose,
    /// Run one real reconciliation and exit.
    Once,
    /// Start the web UI and scheduler (default).
    Serve {
        #[arg(long)]
        listen: Option<SocketAddr>,
        #[arg(long, env = "DDNS_RUST_WEB_TOKEN", hide_env_values = true)]
        token: Option<String>,
    },
}
#[derive(Clone)]
struct App {
    config: Arc<RwLock<Config>>,
    path: Arc<PathBuf>,
    control: LogControl,
    run_lock: Arc<Mutex<()>>,
    last_run: Arc<RwLock<Option<RunReport>>>,
    notify: Arc<Notify>,
    token: Arc<String>,
    auth_state: Arc<Mutex<web_auth::AuthState>>,
}
#[derive(Serialize)]
struct ApiError {
    error: String,
}
type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;
fn api_error(status: StatusCode, error: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (
        status,
        Json(ApiError {
            error: error.into(),
        }),
    )
}
async fn auth(State(app): State<App>, request: Request<axum::body::Body>, next: Next) -> Response {
    let supplied = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    let mut state = app.auth_state.lock().await;
    let legacy = if app.token.is_empty() {
        &state.settings.token
    } else {
        &app.token
    };
    let bearer_valid =
        !legacy.is_empty() && supplied.as_bytes().ct_eq(legacy.as_bytes()).unwrap_u8() == 1;
    let valid = bearer_valid
        || state.settings.initialized() && state.session_valid(session_cookie(request.headers()));
    drop(state);
    if !valid {
        return api_error(StatusCode::UNAUTHORIZED, "Login is required").into_response();
    }
    next.run(request).await
}
fn session_cookie(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie| {
            cookie
                .split(';')
                .find_map(|part| part.trim().strip_prefix("ddns_session="))
        })
        .unwrap_or("")
}
async fn same_origin(request: Request<axum::body::Body>, next: Next) -> Response {
    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) && let Some(origin) = request.headers().get("origin")
    {
        let host = request
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let valid = origin
            .to_str()
            .ok()
            .is_some_and(|o| o == format!("http://{host}") || o == format!("https://{host}"));
        if !valid {
            return api_error(
                StatusCode::FORBIDDEN,
                "Cross-origin requests are not allowed",
            )
            .into_response();
        }
    }
    next.run(request).await
}
async fn security_headers(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("cache-control", "no-store".parse().unwrap());
    headers.insert("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'".parse().unwrap());
    response
}
async fn get_config(State(app): State<App>) -> Json<Config> {
    Json(app.config.read().await.redacted())
}
async fn save_config(State(app): State<App>, Json(mut config): Json<Config>) -> ApiResult<Config> {
    let _guard = app.run_lock.try_lock().map_err(|_| {
        api_error(
            StatusCode::CONFLICT,
            "A run is in progress; save configuration after it finishes",
        )
    })?;
    let mut current = app.config.write().await;
    config
        .merge_credentials(&current)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    config
        .validate()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    config
        .save(&app.path)
        .await
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    app.control
        .filter
        .reload(logging::filter(&config.log_level))
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    *current = config.clone();
    app.notify.notify_one();
    tracing::info!("Configuration saved and scheduler reloaded");
    Ok(Json(config.redacted()))
}
#[derive(Serialize)]
struct Status {
    running: bool,
    last_run: Option<RunReport>,
}
async fn status(State(app): State<App>) -> Json<Status> {
    Json(Status {
        running: app.run_lock.try_lock().is_err(),
        last_run: app.last_run.read().await.clone(),
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    dry_run: bool,
}
async fn launch(app: App, dry_run: bool) -> Result<tokio::task::JoinHandle<RunReport>, String> {
    let guard = app
        .run_lock
        .clone()
        .try_lock_owned()
        .map_err(|_| "A run is already in progress".to_owned())?;
    let config = app.config.read().await.clone();
    Ok(tokio::spawn(async move {
        let _guard = guard;
        let report = engine::run(&config, dry_run).await;
        *app.last_run.write().await = Some(report.clone());
        report
    }))
}
async fn run_now(State(app): State<App>, Json(request): Json<RunRequest>) -> ApiResult<RunReport> {
    let handle = launch(app, request.dry_run)
        .await
        .map_err(|e| api_error(StatusCode::CONFLICT, e))?;
    let report = handle.await.map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Run task failed; inspect server logs",
        )
    })?;
    Ok(Json(report))
}
#[derive(Deserialize)]
struct LogQuery {
    level: Option<String>,
    search: Option<String>,
}
async fn logs(
    State(app): State<App>,
    Query(q): Query<LogQuery>,
) -> ApiResult<Vec<logging::LogEntry>> {
    if q.level.as_deref().is_some_and(|l| !config::valid_level(l)) {
        return Err(api_error(StatusCode::BAD_REQUEST, "Invalid log level"));
    }
    Ok(Json(
        app.control
            .logs
            .entries(q.level.as_deref(), q.search.as_deref()),
    ))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Level {
    level: String,
}
async fn set_level(State(app): State<App>, Json(level): Json<Level>) -> ApiResult<Level> {
    if !config::valid_level(&level.level) {
        return Err(api_error(StatusCode::BAD_REQUEST, "Invalid log level"));
    }
    // Serialize file changes; changing verbosity never interrupts an active DNS run.
    let mut config = app.config.write().await;
    let mut updated = config.clone();
    updated.log_level = level.level.clone();
    updated
        .save(&app.path)
        .await
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    app.control
        .filter
        .reload(logging::filter(&level.level))
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    *config = updated;
    tracing::info!(level=%level.level,"Log level changed without restarting");
    Ok(Json(level))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRequest {
    username: String,
    password: String,
}
async fn auth_status(State(app): State<App>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"initialized": app.auth_state.lock().await.settings.initialized()}))
}
fn session_response(username: &str, session: &str) -> Response {
    (
        [(
            "set-cookie",
            format!("ddns_session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"),
        )],
        Json(serde_json::json!({"username":username})),
    )
        .into_response()
}
async fn setup_account(
    State(app): State<App>,
    Json(account): Json<AccountRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let mut state = app.auth_state.lock().await;
    if state.settings.initialized() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Administrator is already initialized; log in instead",
        ));
    }
    web_auth::validate_account(&account.username, &account.password)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    if !state.allow_attempt() {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts; retry in one minute",
        ));
    }
    let mut settings = state.settings.clone();
    settings.username = account.username;
    settings.password_hash = web_auth::hash_password(account.password)
        .await
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    settings
        .save(&state.path)
        .await
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state.settings = settings;
    let session = state.new_session();
    app.notify.notify_one();
    Ok(session_response(&state.settings.username, &session))
}
async fn login_account(
    State(app): State<App>,
    Json(account): Json<AccountRequest>,
) -> Result<Response, (StatusCode, Json<ApiError>)> {
    let mut state = app.auth_state.lock().await;
    if !state.settings.initialized() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Initialize an administrator first",
        ));
    }
    if !state.allow_attempt() {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts; retry in one minute",
        ));
    }
    if account.username.len() > 64 || account.password.len() > 128 {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "Invalid username or password",
        ));
    }
    let verified =
        web_auth::verify_password(state.settings.password_hash.clone(), account.password).await;
    if !verified || account.username != state.settings.username {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "Invalid username or password",
        ));
    }
    let session = state.new_session();
    Ok(session_response(&state.settings.username, &session))
}
async fn logout_account(State(app): State<App>, headers: axum::http::HeaderMap) -> Response {
    app.auth_state.lock().await.logout(session_cookie(&headers));
    (
        [(
            "set-cookie",
            "ddns_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(serde_json::json!({"ok":true})),
    )
        .into_response()
}
fn settings_json(state: &web_auth::AuthState, token: &str) -> serde_json::Value {
    serde_json::json!({"listen":state.settings.listen.to_string(), "active_listen":state.active_listen.to_string(), "username":state.settings.username, "token_configured":!state.settings.token.is_empty() || !token.is_empty()})
}
async fn get_settings(State(app): State<App>) -> Json<serde_json::Value> {
    Json(settings_json(&*app.auth_state.lock().await, &app.token))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsRequest {
    listen: SocketAddr,
    username: String,
    password: Option<String>,
    token: Option<String>,
}
async fn save_settings(
    State(app): State<App>,
    Json(request): Json<SettingsRequest>,
) -> ApiResult<serde_json::Value> {
    if request.listen.port() == 0 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Listen port must be nonzero",
        ));
    }
    web_auth::validate_account(
        &request.username,
        request.password.as_deref().unwrap_or("unchanged-password"),
    )
    .map_err(|e| api_error(StatusCode::BAD_REQUEST, e))?;
    if request.token.as_ref().is_some_and(|t| {
        !t.is_empty() && (t.len() < 24 || t.len() > 512 || t.chars().any(char::is_control))
    }) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Optional bearer token must be 24..512 bytes without control characters",
        ));
    }
    if request.token.is_some() && !app.token.is_empty() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Remove the CLI/environment token override and restart before editing the web token",
        ));
    }
    let mut state = app.auth_state.lock().await;
    if !state.settings.initialized() {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Initialize an administrator first",
        ));
    }
    let invalidate = state.settings.username != request.username
        || request.password.is_some()
        || request.token.is_some();
    let mut settings = state.settings.clone();
    settings.listen = request.listen;
    settings.username = request.username;
    if let Some(password) = request.password {
        settings.password_hash = web_auth::hash_password(password)
            .await
            .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    }
    if let Some(token) = request.token {
        settings.token = token;
    }
    settings
        .save(&state.path)
        .await
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    state.settings = settings;
    if invalidate {
        state.clear_sessions();
    }
    Ok(Json(settings_json(&state, &app.token)))
}
fn router(app: App) -> Router {
    let api = Router::new()
        .route(
            "/providers",
            get(|| async { Json(providers::registry::catalog()) }),
        )
        .route("/config", get(get_config).put(save_config))
        .route("/status", get(status))
        .route("/run", post(run_now))
        .route("/logs", get(logs))
        .route("/log-level", put(set_level))
        .route("/settings", get(get_settings).put(save_settings))
        .layer(middleware::from_fn_with_state(app.clone(), auth));
    Router::new()
        .nest("/api", api)
        .route("/api/auth/status", get(auth_status))
        .route("/api/auth/setup", post(setup_account))
        .route("/api/auth/login", post(login_account))
        .route("/api/auth/logout", post(logout_account))
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({"status":"ok"})) }),
        )
        .layer(DefaultBodyLimit::max(65536))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(same_origin))
        .with_state(app)
}
async fn serve(
    config: Config,
    path: PathBuf,
    control: LogControl,
    listen: Option<SocketAddr>,
    token: Option<String>,
) -> Result<(), String> {
    if token
        .as_ref()
        .is_some_and(|t| t.len() < 24 || t.len() > 512 || t.chars().any(char::is_control))
    {
        return Err("Optional web token must be 24..512 bytes without control characters".into());
    }
    let auth_path = web_auth::WebSettings::path(&path);
    let mut settings = web_auth::WebSettings::load(&auth_path).await?;
    if !auth_path.exists()
        && let Ok(default_listen) = std::env::var("DDNS_RUST_DEFAULT_LISTEN")
    {
        settings.listen = default_listen
            .parse()
            .map_err(|_| "Invalid default listen address".to_owned())?;
    }
    let listen = listen.unwrap_or(settings.listen);
    if listen.port() == 0 {
        return Err("Listen port must be nonzero".into());
    }
    if !auth_path.exists() {
        settings.listen = listen;
    }
    let app = App {
        config: Arc::new(RwLock::new(config)),
        path: Arc::new(path),
        control,
        run_lock: Arc::new(Mutex::new(())),
        last_run: Arc::new(RwLock::new(None)),
        notify: Arc::new(Notify::new()),
        token: Arc::new(token.unwrap_or_default()),
        auth_state: Arc::new(Mutex::new(web_auth::AuthState::new(
            settings, listen, auth_path,
        ))),
    };
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("Cannot bind web server: {e}"))?;
    #[cfg(windows)]
    service::windows::report_running()?;
    if !listen.ip().is_loopback() {
        tracing::warn!(
            "Web server is exposed beyond loopback; use a TLS reverse proxy and firewall. Bearer tokens over plain HTTP are not secure."
        );
    }
    tracing::info!(address=%listen,"Web server ready; scheduled runs begin after one interval");
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let scheduler_app = app.clone();
    let scheduler = tokio::spawn(async move {
        loop {
            let delay = scheduler_app.config.read().await.interval_secs;
            tokio::select! {
                _=shutdown_rx.changed()=>break,
                _=scheduler_app.notify.notified()=>continue,
                _=tokio::time::sleep(std::time::Duration::from_secs(delay))=>{
                    if !scheduler_app.auth_state.lock().await.settings.initialized() && scheduler_app.token.is_empty() { continue; }
                    match launch(scheduler_app.clone(),false).await{
                        Ok(handle)=>{if handle.await.is_err(){tracing::error!("Scheduled run task failed");}},
                        Err(_)=>tracing::debug!("Scheduled run skipped because another run is in progress"),
                    }
                }
            }
        }
    });
    let server_shutdown_tx = shutdown_tx.clone();
    let result = axum::serve(listener, router(app.clone()))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = server_shutdown_tx.send(true);
            tracing::info!("Shutdown requested; waiting for active DNS operations");
        })
        .await
        .map_err(|e| e.to_string());
    let _ = shutdown_tx.send(true);
    let _ = scheduler.await;
    let _guard = app.run_lock.lock().await;
    result
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(windows)]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = service::windows::shutdown_signal() => {},
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn load_startup_config(
    path: &std::path::Path,
    create_missing: bool,
) -> Result<Config, String> {
    match tokio::fs::metadata(path).await {
        Ok(_) => Config::load(path).await,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create_missing => {
            let mut config = Config::default();
            config.providers.clear();
            config.save(path).await?;
            Ok(config)
        }
        Err(e) => Err(format!("Cannot read configuration: {e}")),
    }
}
async fn execute() -> Result<(), String> {
    let cli = Cli::parse();
    cli.validate_service_mode()?;
    if cli.service == Some(ServiceAction::Uninstall) {
        service::uninstall()?;
        println!("Service stopped and uninstalled. Configuration and binary were preserved.");
        return Ok(());
    }
    let command = cli.command.unwrap_or(Command::Serve {
        listen: None,
        token: std::env::var("DDNS_RUST_WEB_TOKEN").ok(),
    });
    if matches!(command, Command::Init) {
        if cli.config.exists() {
            return Err("Configuration already exists; init refuses to overwrite it".into());
        }
        Config::default().save(&cli.config).await?;
        println!(
            "Created safe configuration. No DNS records are enabled. Run serve and open http://127.0.0.1:9876 to create the administrator and configure providers."
        );
        return Ok(());
    }
    let config = load_startup_config(&cli.config, matches!(command, Command::Serve { .. })).await?;
    if cli.service == Some(ServiceAction::Install) {
        let Command::Serve { listen, token } = command else {
            unreachable!()
        };
        if listen.is_some_and(|address| address.port() == 0) {
            return Err("Listen port must be nonzero".into());
        }
        if token.is_some() {
            eprintln!(
                "Service installation does not persist CLI/shell web tokens. Configure Web settings or the service environment instead."
            );
        }
        let spec = service::ServiceSpec::current(&cli.config, listen)?;
        let auth_path = web_auth::WebSettings::path(&spec.config);
        let settings = web_auth::WebSettings::load(&auth_path).await?;
        let address = listen.unwrap_or(settings.listen);
        if address.port() == 0 {
            return Err("Listen port must be nonzero".into());
        }
        // Persist first-run defaults so the service uses this address, not a manager-specific
        // default-listen environment. Without --listen, future Web settings still take effect.
        if !auth_path.exists() {
            settings.save(&auth_path).await?;
        }
        service::install(&spec)?;
        service::wait_for_web(address).await?;
        println!("Service installed and started in the background.");
        println!("Web management: {}", service::web_url(address));
        return Ok(());
    }
    if matches!(command, Command::Check) {
        println!(
            "Configuration is valid ({} records). Credentials and network access are not checked.",
            config.records.len()
        );
        return Ok(());
    }
    let control = logging::init(&config.log_level)?;
    match command {
        Command::Diagnose | Command::Once => {
            let dry_run = matches!(command, Command::Diagnose);
            let report = engine::run(&config, dry_run).await;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
            if report.results.iter().any(|r| r.error.is_some()) {
                return Err("One or more records failed. See the JSON report and structured logs for stage, code, request ID and remediation.".into());
            }
            Ok(())
        }
        Command::Serve { listen, token } => serve(config, cli.config, control, listen, token).await,
        _ => Ok(()),
    }
}
fn run_application() -> Result<(), String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot create async runtime: {e}"))?
        .block_on(execute())
}
fn main() {
    #[cfg(windows)]
    let result = {
        let cli = Cli::parse();
        match cli.validate_service_mode() {
            Err(error) => Err(error),
            Ok(()) if cli.service_run => service::windows::dispatch(),
            Ok(()) => run_application(),
        }
    };
    #[cfg(not(windows))]
    let result = run_application();
    if let Err(e) = result {
        eprintln!("ddns-rust: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod service_cli_tests {
    use super::*;
    #[test]
    fn parses_install_and_uninstall_before_or_after_serve() {
        for (action, expected) in [
            ("install", ServiceAction::Install),
            ("uninstall", ServiceAction::Uninstall),
        ] {
            for args in [
                vec!["ddns-rust", "-s", action],
                vec!["ddns-rust", "serve", "-s", action],
            ] {
                let cli = Cli::try_parse_from(args).unwrap();
                assert!(cli.service == Some(expected));
                assert!(cli.validate_service_mode().is_ok());
            }
        }
        let cli = Cli::try_parse_from([
            "ddns-rust",
            "--config",
            "/nonexistent/config.toml",
            "-s",
            "uninstall",
        ])
        .unwrap();
        assert!(cli.service == Some(ServiceAction::Uninstall));
        assert!(cli.validate_service_mode().is_ok());
    }
}

#[cfg(test)]
mod api_tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt;
    const TOKEN: &str = "test-only-token-0123456789abcdef";
    fn request(
        method: &str,
        path: &str,
        authorized: bool,
        body: Option<serde_json::Value>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if authorized {
            builder = builder.header("authorization", format!("Bearer {TOKEN}"));
        }
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        builder
            .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
            .unwrap()
    }
    async fn json_body(response: Response) -> serde_json::Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
    }
    #[tokio::test]
    async fn hipm_endpoint_preflight_isolated_process_no_outbound() {
        const CHILD: &str = "DDNS_TEST_HIPM_ENDPOINT_CHILD";
        if std::env::var(CHILD).is_err() {
            let unique = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "api_tests::hipm_endpoint_preflight_isolated_process_no_outbound",
                    "--nocapture",
                ])
                .env(CHILD, &unique)
                .env(format!("HIPM_TOKEN_{unique}"), "synthetic-test-token")
                .env(
                    format!("HIPM_INVALID_{unique}"),
                    "http://private-origin.invalid/api",
                )
                .env_remove(format!("HIPM_MISSING_{unique}"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated endpoint API test failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let unique = std::env::var(CHILD).unwrap();
        let mut config = serde_json::to_value(Config::default()).unwrap();
        config["providers"] = serde_json::json!([
            {"name":"missing","kind":"hipmdnsmgr","token_env":format!("HIPM_TOKEN_{unique}"),"options":{"endpoint_env":format!("HIPM_MISSING_{unique}")}},
            {"name":"invalid","kind":"hipmdnsmgr","token_env":format!("HIPM_TOKEN_{unique}"),"options":{"endpoint_env":format!("HIPM_INVALID_{unique}")}}
        ]);
        config["records"] = serde_json::json!([
            {"name":"missing","provider":"missing","domain":"example.com","subdomain":"home","record_type":"A","record_line":"default","ttl":600,"create_if_missing":false,"enabled":false,"ip_source":{"kind":"url","value":"https://no-outbound.invalid"}},
            {"name":"invalid","provider":"invalid","domain":"example.com","subdomain":"home","record_type":"A","record_line":"default","ttl":600,"create_if_missing":false,"enabled":false,"ip_source":{"kind":"static","value":"1.1.1.1"}}
        ]);
        let config: Config = serde_json::from_value(config).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("isolated.toml");
        config.save(&path).await.unwrap();
        let app = App {
            config: Arc::new(RwLock::new(config)),
            path: Arc::new(path),
            control: logging::init("info").unwrap(),
            run_lock: Arc::new(Mutex::new(())),
            last_run: Arc::new(RwLock::new(None)),
            notify: Arc::new(Notify::new()),
            token: Arc::new(TOKEN.into()),
            auth_state: Arc::new(Mutex::new(web_auth::AuthState::new(
                web_auth::WebSettings::default(),
                "127.0.0.1:9876".parse().unwrap(),
                dir.path().join("web.toml"),
            ))),
        };
        let router = router(app);
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                "/api/run",
                true,
                Some(serde_json::json!({"dry_run":true})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let report = json_body(response).await;
        assert_eq!(report["results"][0]["error"]["code"], "MissingEndpoint");
        assert!(report["results"][0]["ip"].is_null());
        assert_eq!(report["results"][1]["error"]["code"], "InvalidEndpoint");
        assert!(!report.to_string().contains("private-origin.invalid"));
        assert!(!report.to_string().contains("synthetic-test-token"));
        let response = router
            .oneshot(request(
                "POST",
                "/api/run",
                true,
                Some(serde_json::json!({"dry_run":false})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        for row in json_body(response).await["results"].as_array().unwrap() {
            assert_eq!(row["status"], "disabled");
        }
    }
    #[tokio::test]
    async fn api_contract_and_safety() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = Config::default();
        config.save(&path).await.unwrap();
        let control = logging::init("info").unwrap();
        let app = App {
            config: Arc::new(RwLock::new(config)),
            path: Arc::new(path.clone()),
            control,
            run_lock: Arc::new(Mutex::new(())),
            last_run: Arc::new(RwLock::new(None)),
            notify: Arc::new(Notify::new()),
            token: Arc::new(TOKEN.into()),
            auth_state: Arc::new(Mutex::new(web_auth::AuthState::new(
                web_auth::WebSettings::default(),
                "127.0.0.1:9876".parse().unwrap(),
                dir.path().join("web.toml"),
            ))),
        };
        let router = router(app.clone());
        for endpoint in ["/api/providers", "/api/config", "/api/status", "/api/logs"] {
            let response = router
                .clone()
                .oneshot(request("GET", endpoint, false, None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        for endpoint in ["/", "/app.js", "/style.css", "/healthz"] {
            assert_eq!(
                router
                    .clone()
                    .oneshot(request("GET", endpoint, false, None))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        let response = router
            .clone()
            .oneshot(request("GET", "/api/config", true, None))
            .await
            .unwrap();
        let configuration = json_body(response).await;
        let response = router
            .clone()
            .oneshot(request("GET", "/api/providers", true, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let catalog = json_body(response).await;
        assert_eq!(
            catalog.as_array().unwrap().len(),
            providers::registry::catalog().len()
        );
        assert!(
            catalog
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["kind"] == "cloudflare" && p["implemented"] == true)
        );
        assert!(configuration.get("providers").is_some());
        let catalog_rows = catalog.as_array().unwrap();
        assert_eq!(
            catalog_rows
                .iter()
                .filter(|p| p["implemented"] == true)
                .count(),
            24
        );
        assert_eq!(
            catalog_rows
                .iter()
                .filter(|p| p["implemented"] == true && p["supports_dns_read"] == true)
                .count(),
            23
        );
        assert_eq!(
            catalog_rows
                .iter()
                .find(|p| p["kind"] == "callback")
                .unwrap()["supports_dns_read"],
            false
        );
        for kind in [
            "name_com",
            "rainyun",
            "cloudns",
            "namesilo",
            "hipmdnsmgr",
            "namecheap",
        ] {
            assert!(
                catalog_rows
                    .iter()
                    .any(|p| p["kind"] == kind && p["implemented"] == true)
            );
        }
        assert!(
            catalog_rows
                .iter()
                .any(|p| p["kind"] == "dynadot" && p["implemented"] == false)
        );
        let hipm = catalog_rows
            .iter()
            .find(|p| p["kind"] == "hipmdnsmgr")
            .unwrap();
        assert_eq!(hipm["credential_fields"][0]["env_prefix"], "HIPM_");
        assert_eq!(hipm["options"][0]["key"], "endpoint_env");
        assert_eq!(hipm["options"][0]["required"], true);
        let silo = catalog_rows
            .iter()
            .find(|p| p["kind"] == "namesilo")
            .unwrap();
        assert_eq!(silo["credential_fields"][0]["env_prefix"], "NAMESILO_");
        assert_eq!(silo["options"], serde_json::json!([]));
        let rainyun = catalog_rows
            .iter()
            .find(|p| p["kind"] == "rainyun")
            .unwrap();
        assert_eq!(rainyun["options"][0]["required"], true);
        assert!(!configuration.to_string().contains(TOKEN));
        assert!(configuration["providers"][0].get("secret_key").is_none());
        let response = router
            .clone()
            .oneshot(request(
                "PUT",
                "/api/log-level",
                true,
                Some(serde_json::json!({"level":"debug"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(Config::load(&path).await.unwrap().log_level, "debug");
        tracing::debug!(test_marker = "dynamic-debug-works", "Runtime debug event");
        let logs = app
            .control
            .logs
            .entries(Some("debug"), Some("dynamic-debug-works"));
        assert_eq!(logs.len(), 1);
        let response = router
            .clone()
            .oneshot(request(
                "PUT",
                "/api/log-level",
                true,
                Some(serde_json::json!({"level":"nonsense"})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let guard = app.run_lock.lock().await;
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                "/api/run",
                true,
                Some(serde_json::json!({"dry_run":true})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let response = router
            .clone()
            .oneshot(request(
                "PUT",
                "/api/config",
                true,
                Some(configuration.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        drop(guard);
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                "/api/run",
                true,
                Some(serde_json::json!({"dry_run":true})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let report = json_body(response).await;
        assert_eq!(report["dry_run"], true);
        assert_eq!(report["results"], serde_json::json!([]));
        let response = router
            .clone()
            .oneshot(request("GET", "/api/status", true, None))
            .await
            .unwrap();
        let status = json_body(response).await;
        assert_eq!(status["running"], false);
        assert_eq!(status["last_run"]["run_id"], report["run_id"]);
        let mut bad = configuration.clone();
        bad["interval_secs"] = serde_json::json!(1);
        let response = router
            .clone()
            .oneshot(request("PUT", "/api/config", true, Some(bad)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(Config::load(&path).await.unwrap().interval_secs, 300);
        let response = router
            .clone()
            .oneshot(request("GET", "/api/logs?level=nonsense", true, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Integration coverage for the new adapters without real credentials or DNS writes.
        let mut batch = configuration.clone();
        batch["providers"] = serde_json::json!([
            {"name":"namecom","kind":"name_com","secret_id_env":"DDNS_ABSENT_BATCH4_USERNAME_7D23","secret_key_env":"DDNS_ABSENT_BATCH4_TOKEN_7D23"},
            {"name":"rain","kind":"rainyun","token_env":"DDNS_ABSENT_BATCH4_RAIN_7D23","options":{"domain_id":"123"}},
            {"name":"cl","kind":"cloudns","secret_id_env":"DDNS_ABSENT_BATCH4_CL_ID_7D23","secret_key_env":"DDNS_ABSENT_BATCH4_CL_KEY_7D23","options":{"auth_type":"sub-auth-id"}}
        ]);
        batch["records"] = serde_json::json!([]);
        for (name, provider) in [
            ("namecom-record", "namecom"),
            ("rain-record", "rain"),
            ("cloudns-record", "cl"),
        ] {
            batch["records"].as_array_mut().unwrap().push(serde_json::json!({"name":name,"provider":provider,"domain":"example.com","subdomain":"home","record_type":"A","record_line":"默认","ttl":600,"record_id":"12345","create_if_missing":false,"enabled":false,"ip_source":{"kind":"static","value":"1.1.1.1"}}));
        }
        let response = router
            .clone()
            .oneshot(request("PUT", "/api/config", true, Some(batch.clone())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let persisted = Config::load(&path).await.unwrap();
        assert_eq!(persisted.providers[1].options["domain_id"], "123");
        assert_eq!(persisted.providers[2].options["auth_type"], "sub-auth-id");
        assert_eq!(persisted.records[0].record_id.as_deref(), Some("12345"));
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                "/api/run",
                true,
                Some(serde_json::json!({"dry_run":true})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let report = json_body(response).await;
        let rows = report["results"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        for row in rows {
            assert_eq!(row["error"]["code"], "MissingCredentials");
        }
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                "/api/run",
                true,
                Some(serde_json::json!({"dry_run":false})),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let report = json_body(response).await;
        for row in report["results"].as_array().unwrap() {
            assert_eq!(row["status"], "disabled");
        }
        let mut bad = batch;
        bad["providers"][1]["options"] = serde_json::json!({});
        let response = router
            .clone()
            .oneshot(request("PUT", "/api/config", true, Some(bad)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            Config::load(&path).await.unwrap().providers[1].options["domain_id"],
            "123"
        );
        let mut fifth = configuration;
        fifth["providers"] = serde_json::json!([
            {"name":"dyn","kind":"dynv6","token_env":"DDNS_ABSENT_DYNV6_47AC","options":{"ttl_mode":"provider_default"}},
            {"name":"space","kind":"spaceship","secret_id_env":"DDNS_ABSENT_SPACE_ID_47AC","secret_key_env":"DDNS_ABSENT_SPACE_KEY_47AC"},
            {"name":"gc","kind":"gcore","token_env":"DDNS_ABSENT_GCORE_47AC","options":{"plan":"free"}}
        ]);
        fifth["records"] = serde_json::json!([]);
        for (provider, id) in [
            ("dyn", "123".to_string()),
            ("space", format!("rrset-{}", "a".repeat(64))),
            ("gc", "A.home.example.com".to_string()),
        ] {
            fifth["records"].as_array_mut().unwrap().push(serde_json::json!({"name":provider,"provider":provider,"domain":"example.com","subdomain":"home","record_type":"A","record_line":"默认","ttl":600,"record_id":id,"create_if_missing":false,"enabled":false,"ip_source":{"kind":"static","value":"1.1.1.1"}}));
        }
        let response = router
            .clone()
            .oneshot(request("PUT", "/api/config", true, Some(fifth.clone())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let saved = Config::load(&path).await.unwrap();
        assert_eq!(saved.providers[0].options["ttl_mode"], "provider_default");
        assert_eq!(saved.providers[2].options["plan"], "free");
        assert_eq!(
            saved.records[1].record_id,
            fifth["records"][1]["record_id"].as_str().map(str::to_owned)
        );
        for dry_run in [true, false] {
            let response = router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/run",
                    true,
                    Some(serde_json::json!({"dry_run":dry_run})),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let report = json_body(response).await;
            let results = report["results"].as_array().unwrap();
            assert_eq!(results.len(), 3);
            for row in results {
                if dry_run {
                    assert_eq!(row["error"]["code"], "MissingCredentials");
                } else {
                    assert_eq!(row["status"], "disabled");
                }
            }
        }
        // UUID-scoped absent references avoid global process-environment mutation.
        let unique = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
        let mut sixth = serde_json::to_value(Config::default()).unwrap();
        sixth["providers"] = serde_json::json!([
            {"name":"silo","kind":"namesilo","token_env":format!("NAMESILO_{unique}")},
            {"name":"hipm","kind":"hipmdnsmgr","token_env":format!("HIPM_TOKEN_{unique}"),"options":{"endpoint_env":format!("HIPM_ORIGIN_{unique}"),"domain_id":"123"}}
        ]);
        sixth["records"] = serde_json::json!([]);
        for (provider, id) in [
            ("silo", format!("namesilo-{}", "a".repeat(64))),
            ("hipm", "native-123".into()),
        ] {
            // HTTPS source would require outbound IO if missing credentials did not fail first.
            sixth["records"].as_array_mut().unwrap().push(serde_json::json!({"name":provider,"provider":provider,"domain":"example.com","subdomain":"home","record_type":"A","record_line":"default","ttl":600,"record_id":id,"create_if_missing":false,"enabled":false,"ip_source":{"kind":"url","value":"https://no-outbound.invalid"}}));
        }
        let response = router
            .clone()
            .oneshot(request("PUT", "/api/config", true, Some(sixth.clone())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let loaded = Config::load(&path).await.unwrap();
        assert_eq!(
            loaded.records[0].record_id,
            sixth["records"][0]["record_id"].as_str().map(str::to_owned)
        );
        assert_eq!(loaded.records[1].record_id.as_deref(), Some("native-123"));
        let response = router
            .clone()
            .oneshot(request("GET", "/api/config", true, None))
            .await
            .unwrap();
        let returned = json_body(response).await;
        assert_eq!(
            returned["providers"][1]["options"]["endpoint_env"],
            sixth["providers"][1]["options"]["endpoint_env"]
        );
        assert!(!returned.to_string().contains("https://private"));
        for dry_run in [true, false] {
            let response = router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/run",
                    true,
                    Some(serde_json::json!({"dry_run":dry_run})),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let report = json_body(response).await;
            assert_eq!(report["results"].as_array().unwrap().len(), 2);
            for row in report["results"].as_array().unwrap() {
                if dry_run {
                    assert_eq!(row["error"]["code"], "MissingCredentials");
                    assert!(row["ip"].is_null());
                } else {
                    assert_eq!(row["status"], "disabled");
                }
            }
        }
        let mut refusals = Vec::new();
        for value in [
            "PATH",
            "DDNS_ORIGIN",
            "OTHER_ORIGIN",
            "HIPM_",
            "https://private.example",
            "http://127.0.0.1",
        ] {
            let mut bad = sixth.clone();
            bad["providers"][1]["options"]["endpoint_env"] = serde_json::json!(value);
            refusals.push(bad);
        }
        for value in ["0", "01", "9223372036854775808"] {
            let mut bad = sixth.clone();
            bad["providers"][1]["options"]["domain_id"] = serde_json::json!(value);
            refusals.push(bad);
        }
        for kind in ["namesilo", "hipmdnsmgr"] {
            let i = usize::from(kind == "hipmdnsmgr");
            let mut bad = sixth.clone();
            bad["providers"][i]["token_env"] = serde_json::json!("PATH");
            refusals.push(bad);
            let mut bad = sixth.clone();
            bad["providers"][i]["options"]["insecure"] = serde_json::json!("true");
            refusals.push(bad);
        }
        let mut bad = sixth.clone();
        bad["records"][1]["record_line"] = serde_json::json!("默认");
        refusals.push(bad);
        let mut bad = sixth.clone();
        let mut dup = bad["records"][1].clone();
        dup["name"] = serde_json::json!("duplicate");
        dup["record_id"] = serde_json::Value::Null;
        dup["record_line"] = serde_json::json!("DEFAULT");
        bad["records"].as_array_mut().unwrap().push(dup);
        refusals.push(bad);
        for bad in refusals {
            let response = router
                .clone()
                .oneshot(request("PUT", "/api/config", true, Some(bad)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                Config::load(&path).await.unwrap().providers[1].options["domain_id"],
                "123"
            );
        }
        let mut seventh = serde_json::to_value(Config::default()).unwrap();
        seventh["providers"] = serde_json::json!([
            {"name":"hw","kind":"huaweicloud","secret_id_env":format!("HUAWEICLOUD_ID_{unique}"),"secret_key_env":format!("HUAWEICLOUD_KEY_{unique}"),"options":{"region":"cn-north-4","project_id":"project-native","zone_id":"zone-native"}},
            {"name":"bcd","kind":"baiducloud","secret_id_env":format!("BAIDUCLOUD_ID_{unique}"),"secret_key_env":format!("BAIDUCLOUD_KEY_{unique}"),"options":{"resource_id":"resource-native"}},
            {"name":"teo","kind":"edgeone","secret_id_env":format!("EDGEONE_ID_{unique}"),"secret_key_env":format!("EDGEONE_KEY_{unique}"),"options":{"mode":"dns","scope":"teodns","api_version":"2022-09-01","zone_id":"zone-native"}}
        ]);
        seventh["records"] = serde_json::json!([]);
        for (provider, id, line, options) in [
            (
                "hw",
                "rrset-native",
                "default_view",
                serde_json::json!({"zone_id":"zone-native"}),
            ),
            ("bcd", "2147483647", "DEFAULT", serde_json::json!({})),
            ("teo", "record-native", "Default", serde_json::json!({})),
        ] {
            seventh["records"].as_array_mut().unwrap().push(serde_json::json!({"name":provider,"provider":provider,"domain":"example.com","subdomain":"home.nested","record_type":"A","record_line":line,"ttl":600,"record_id":id,"options":options,"create_if_missing":false,"enabled":false,"ip_source":{"kind":"static","value":"192.0.2.1"}}));
        }
        assert_eq!(
            router
                .clone()
                .oneshot(request("PUT", "/api/config", true, Some(seventh.clone())))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let saved_seventh = tokio::fs::read(&path).await.unwrap();
        let loaded = Config::load(&path).await.unwrap();
        for i in 0..3 {
            assert_eq!(
                loaded.records[i].record_id.as_deref(),
                seventh["records"][i]["record_id"].as_str()
            );
            assert_eq!(
                serde_json::to_value(&loaded.providers[i].options).unwrap(),
                seventh["providers"][i]["options"]
            );
            assert_eq!(
                serde_json::to_value(&loaded.records[i].options).unwrap(),
                seventh["records"][i]["options"]
            );
        }
        let returned = json_body(
            router
                .clone()
                .oneshot(request("GET", "/api/config", true, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            returned["providers"][2]["options"],
            seventh["providers"][2]["options"]
        );
        for dry_run in [true, false] {
            let response = router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/run",
                    true,
                    Some(serde_json::json!({"dry_run":dry_run})),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let report = json_body(response).await;
            assert_eq!(report["results"].as_array().unwrap().len(), 3);
            for row in report["results"].as_array().unwrap() {
                if dry_run {
                    assert_eq!(row["error"]["code"], "MissingCredentials");
                    assert!(row["ip"].is_null());
                } else {
                    assert_eq!(row["status"], "disabled");
                }
            }
        }
        let mut refusals = Vec::new();
        for (i, key, value) in [
            (0, "region", "cn-fake-1"),
            (0, "project_id", ".."),
            (0, "zone_id", "../zone"),
            (1, "resource_id", ".."),
            (2, "mode", "origin"),
            (2, "scope", "origin"),
            (2, "api_version", "latest"),
            (2, "zone_id", "origin-native"),
        ] {
            let mut bad = seventh.clone();
            bad["providers"][i]["options"][key] = serde_json::json!(value);
            refusals.push(bad);
        }
        for (i, id, ttl, line) in [
            (0, "..", 299, "telecom"),
            (1, "2147483648", 3601, "cmnet"),
            (2, "origin-native", 86401, "Default\n"),
        ] {
            for (key, value) in [
                ("record_id", serde_json::json!(id)),
                ("ttl", serde_json::json!(ttl)),
                ("record_line", serde_json::json!(line)),
            ] {
                let mut bad = seventh.clone();
                bad["records"][i][key] = value;
                refusals.push(bad);
            }
        }
        for i in 0..3 {
            let mut bad = seventh.clone();
            bad["providers"][i]["secret_key_env"] = serde_json::json!("PATH");
            refusals.push(bad);
            let mut bad = seventh.clone();
            bad["providers"][i]["options"]["endpoint"] =
                serde_json::json!("https://untrusted.invalid");
            refusals.push(bad);
            let mut bad = seventh.clone();
            bad["providers"][i]["options"] = serde_json::json!({});
            refusals.push(bad);
            let mut bad = seventh.clone();
            let mut duplicate = bad["records"][i].clone();
            duplicate["name"] = serde_json::json!("duplicate");
            duplicate["record_id"] = serde_json::Value::Null;
            duplicate["record_line"] = serde_json::json!("default");
            bad["records"].as_array_mut().unwrap().push(duplicate);
            refusals.push(bad);
        }
        let mut bad = seventh.clone();
        bad["records"][0]["options"]["zone_id"] = serde_json::json!("zone-other");
        refusals.push(bad);
        for bad in refusals {
            assert_eq!(
                router
                    .clone()
                    .oneshot(request("PUT", "/api/config", true, Some(bad)))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(tokio::fs::read(&path).await.unwrap(), saved_seventh);
        }
        // Restore the fifth batch before checking its original refusal below.
        let response = router
            .clone()
            .oneshot(request("PUT", "/api/config", true, Some(fifth.clone())))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        fifth["providers"][0]["options"] = serde_json::json!({});
        let response = router
            .clone()
            .oneshot(request("PUT", "/api/config", true, Some(fifth)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            Config::load(&path).await.unwrap().providers[0].options["ttl_mode"],
            "provider_default"
        );
    }
    #[tokio::test]
    async fn eighth_batch_callback_preflight_and_persistence_isolated() {
        const CHILD: &str = "DDNS_TEST_BATCH8_CHILD";
        if std::env::var(CHILD).is_err() {
            let u = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "api_tests::eighth_batch_callback_preflight_and_persistence_isolated",
                    "--nocapture",
                ])
                .env(CHILD, &u)
                .env(format!("CALLBACK_TOKEN_{u}"), "synthetic-token")
                .env(format!("CALLBACK_BADTOKEN_{u}"), "invalid token")
                .env(
                    format!("CALLBACK_VALID_{u}"),
                    "https://receiver.invalid/delivery",
                )
                .env(
                    format!("CALLBACK_INVALID_{u}"),
                    "https://secret-host.invalid/delivery?secret=value",
                )
                .env_remove(format!("CALLBACK_MISSING_{u}"))
                .env_remove(format!("CALLBACK_ABSENTTOKEN_{u}"))
                .env_remove(format!("TRAFFICROUTE_AK_{u}"))
                .env_remove(format!("TRAFFICROUTE_SK_{u}"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let u = std::env::var(CHILD).unwrap();
        let mut c = serde_json::to_value(Config::default()).unwrap();
        c["providers"] = serde_json::json!([
            {"name":"traffic","kind":"trafficroute","secret_id_env":format!("TRAFFICROUTE_AK_{u}"),"secret_key_env":format!("TRAFFICROUTE_SK_{u}"),"options":{"scope":"public_dns","api_version":"2018-08-01","region":"cn-beijing","zone_id":"123"}},
            {"name":"callback","kind":"callback","token_env":format!("CALLBACK_TOKEN_{u}"),"options":{"endpoint_env":format!("CALLBACK_VALID_{u}"),"mode":"json_post","verification":"unverified","delivery":"every_run","ttl_mode":"metadata_only"}}
        ]);
        c["records"] = serde_json::json!([
            {"name":"traffic","provider":"traffic","domain":"example.com","subdomain":"home.nested","record_type":"A","record_line":"default","ttl":600,"record_id":"9223372036854775807","options":{},"create_if_missing":false,"enabled":false,"ip_source":{"kind":"static","value":"1.1.1.1"}},
            {"name":"callback","provider":"callback","domain":"example.com","subdomain":"home","record_type":"A","record_line":"ignored","ttl":600,"record_id":null,"options":{},"create_if_missing":false,"enabled":false,"ip_source":{"kind":"static","value":"1.1.1.1"}}
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("batch8.toml");
        let initial = Config::default();
        initial.save(&path).await.unwrap();
        let app = App {
            config: Arc::new(RwLock::new(initial)),
            path: Arc::new(path.clone()),
            control: logging::init("info").unwrap(),
            run_lock: Arc::new(Mutex::new(())),
            last_run: Arc::new(RwLock::new(None)),
            notify: Arc::new(Notify::new()),
            token: Arc::new(TOKEN.into()),
            auth_state: Arc::new(Mutex::new(web_auth::AuthState::new(
                web_auth::WebSettings::default(),
                "127.0.0.1:9876".parse().unwrap(),
                dir.path().join("web.toml"),
            ))),
        };
        let router = router(app.clone());
        assert_eq!(
            router
                .clone()
                .oneshot(request("PUT", "/api/config", true, Some(c.clone())))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let saved = tokio::fs::read(&path).await.unwrap();
        let returned = json_body(
            router
                .clone()
                .oneshot(request("GET", "/api/config", true, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(returned["records"][0]["record_id"], "9223372036854775807");
        assert_eq!(
            returned["providers"][1]["options"],
            c["providers"][1]["options"]
        );
        assert!(!returned.to_string().contains("receiver.invalid"));
        let report = json_body(
            router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/run",
                    true,
                    Some(serde_json::json!({"dry_run":true})),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert!(uuid::Uuid::parse_str(report["run_id"].as_str().unwrap()).is_ok());
        assert_eq!(report["results"][0]["error"]["code"], "MissingCredentials");
        assert_eq!(report["results"][1]["status"], "would_call_unverified");
        assert_eq!(report["results"][1]["ip"], "1.1.1.1");
        assert!(report["results"][1]["outcome"]["record_id"].is_null());
        assert!(report["results"][1]["outcome"]["previous_ip"].is_null());
        assert!(!report.to_string().contains("receiver.invalid"));
        let real = json_body(
            router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/run",
                    true,
                    Some(serde_json::json!({"dry_run":false})),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert!(
            real["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["status"] == "disabled")
        );
        for (key, value) in [
            ("record_id", serde_json::json!("123")),
            ("create_if_missing", serde_json::json!(true)),
            ("options", serde_json::json!({"line":"telecom"})),
        ] {
            let mut bad = c.clone();
            bad["records"][1][key] = value;
            assert_eq!(
                router
                    .clone()
                    .oneshot(request("PUT", "/api/config", true, Some(bad)))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(tokio::fs::read(&path).await.unwrap(), saved);
        }
        for (i, key, value) in [
            (0, "scope", "gtm"),
            (0, "zone_id", "01"),
            (0, "region", "cn-north-1"),
            (1, "mode", "get"),
            (1, "endpoint_env", "DDNS_ENDPOINT"),
            (1, "delivery", "on_change"),
        ] {
            let mut bad = c.clone();
            bad["providers"][i]["options"][key] = serde_json::json!(value);
            assert_eq!(
                router
                    .clone()
                    .oneshot(request("PUT", "/api/config", true, Some(bad)))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(tokio::fs::read(&path).await.unwrap(), saved);
        }
        for (key, value) in [
            ("record_id", serde_json::json!("01")),
            ("record_id", serde_json::json!("native-id")),
            ("record_line", serde_json::json!("bad/line")),
            ("ttl", serde_json::json!(86401)),
            ("options", serde_json::json!({"weight":"2"})),
        ] {
            let mut bad = c.clone();
            bad["records"][0][key] = value;
            assert_eq!(
                router
                    .clone()
                    .oneshot(request("PUT", "/api/config", true, Some(bad)))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(tokio::fs::read(&path).await.unwrap(), saved);
        }
        let mut duplicate = c.clone();
        let mut other = duplicate["records"][1].clone();
        other["name"] = serde_json::json!("duplicate-callback");
        other["record_line"] = serde_json::json!("different-ignored-line");
        duplicate["records"].as_array_mut().unwrap().push(other);
        assert_eq!(
            router
                .clone()
                .oneshot(request("PUT", "/api/config", true, Some(duplicate)))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(tokio::fs::read(&path).await.unwrap(), saved);
        for (endpoint, token, code) in [
            ("MISSING", "TOKEN", "MissingEndpoint"),
            ("INVALID", "TOKEN", "InvalidEndpoint"),
            ("VALID", "BADTOKEN", "InvalidCredentials"),
            ("MISSING", "ABSENTTOKEN", "MissingCredentials"),
        ] {
            let mut local: Config = serde_json::from_value(c.clone()).unwrap();
            local.providers[1]
                .options
                .insert("endpoint_env".into(), format!("CALLBACK_{endpoint}_{u}"));
            local.providers[1].token_env = format!("CALLBACK_{token}_{u}");
            local.records[1].ip_source = crate::config::IpSource {
                kind: "url".into(),
                value: "https://no-outbound.invalid/".into(),
            };
            *app.config.write().await = local;
            let report = json_body(
                router
                    .clone()
                    .oneshot(request(
                        "POST",
                        "/api/run",
                        true,
                        Some(serde_json::json!({"dry_run":true})),
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(report["results"][1]["error"]["code"], code);
            assert!(report["results"][1]["ip"].is_null());
            assert!(!report.to_string().contains("secret-host.invalid"));
            assert!(!report.to_string().contains("invalid token"));
        }
        // Bypass Config only to prove engine itself enforces selection before HTTPS IP I/O.
        let mut invalid: Config = serde_json::from_value(c).unwrap();
        invalid.records[1].create_if_missing = true;
        invalid.records[1].ip_source = crate::config::IpSource {
            kind: "url".into(),
            value: "https://no-outbound.invalid/".into(),
        };
        *app.config.write().await = invalid;
        let report = json_body(
            router
                .oneshot(request(
                    "POST",
                    "/api/run",
                    true,
                    Some(serde_json::json!({"dry_run":true})),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            report["results"][1]["error"]["code"],
            "UnsupportedCallbackSelection"
        );
        assert!(report["results"][1]["ip"].is_null());
    }
    #[tokio::test]
    async fn namecheap_preflight_and_persistence_isolated_no_outbound() {
        const CHILD: &str = "DDNS_TEST_NAMECHEAP_CHILD";
        if std::env::var(CHILD).is_err() {
            let u = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "api_tests::namecheap_preflight_and_persistence_isolated_no_outbound",
                    "--nocapture",
                ])
                .env(CHILD, &u)
                .env(format!("NAMECHEAP_USER_{u}"), "synthetic-user")
                .env(format!("NAMECHEAP_KEY_{u}"), "synthetic-key-never-echo")
                .env(format!("NAMECHEAP_BADUSER_{u}"), "invalid username")
                .env(format!("NAMECHEAP_PRIVATE_{u}"), "10.23.45.67")
                .env(format!("NAMECHEAP_IPV6_{u}"), "2606:4700:4700::1111")
                .env(format!("NAMECHEAP_BADIP_{u}"), "literal-invalid-client-ip")
                .env_remove(format!("NAMECHEAP_MISSING_{u}"))
                .env_remove(format!("NAMECHEAP_ABSENTUSER_{u}"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let u = std::env::var(CHILD).unwrap();
        let mut c: Config = toml::from_str(include_str!("../examples/namecheap.toml")).unwrap();
        c.providers[0].secret_id_env = format!("NAMECHEAP_USER_{u}");
        c.providers[0].secret_key_env = format!("NAMECHEAP_KEY_{u}");
        c.providers[0]
            .options
            .insert("client_ip_env".into(), format!("NAMECHEAP_MISSING_{u}"));
        c.records[0].ip_source = crate::config::IpSource {
            kind: "url".into(),
            value: "https://no-outbound.invalid/".into(),
        };
        use sha2::{Digest, Sha256};
        c.records[0].record_id = Some(format!(
            "namecheap-{}",
            hex::encode(Sha256::digest(b"example.com\0home\0A"))
        ));
        let good = serde_json::to_value(&c).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("namecheap.toml");
        let initial = Config::default();
        initial.save(&path).await.unwrap();
        let app = App {
            config: Arc::new(RwLock::new(initial)),
            path: Arc::new(path.clone()),
            control: logging::init("info").unwrap(),
            run_lock: Arc::new(Mutex::new(())),
            last_run: Arc::new(RwLock::new(None)),
            notify: Arc::new(Notify::new()),
            token: Arc::new(TOKEN.into()),
            auth_state: Arc::new(Mutex::new(web_auth::AuthState::new(
                web_auth::WebSettings::default(),
                "127.0.0.1:9876".parse().unwrap(),
                dir.path().join("web.toml"),
            ))),
        };
        let router = router(app.clone());
        assert_eq!(
            router
                .clone()
                .oneshot(request("PUT", "/api/config", true, Some(good.clone())))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let saved = tokio::fs::read(&path).await.unwrap();
        let loaded = Config::load(&path).await.unwrap();
        assert_eq!(loaded.records[0].record_id, c.records[0].record_id);
        let returned = json_body(
            router
                .clone()
                .oneshot(request("GET", "/api/config", true, None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            returned["providers"][0]["options"],
            good["providers"][0]["options"]
        );
        assert_eq!(
            returned["records"][0]["record_id"],
            good["records"][0]["record_id"]
        );
        assert!(!returned.to_string().contains("synthetic-key-never-echo"));
        let mut invalids = Vec::new();
        for (key, value) in [
            ("sld", "other"),
            ("sld", "example.com"),
            ("tld", "net"),
            ("scope", "basicdns"),
            ("write_mode", "per_record"),
            ("environment", "auto"),
            ("client_ip_env", "DDNS_CLIENT_IP"),
            ("client_ip_env", "PATH"),
            ("client_ip_env", "1.1.1.1"),
            ("endpoint", "https://api.namecheap.com/xml.response"),
        ] {
            let mut bad = good.clone();
            bad["providers"][0]["options"][key] = serde_json::json!(value);
            invalids.push(bad);
        }
        for (key, value) in [
            ("domain", serde_json::json!("home.example.com")),
            ("ttl", serde_json::json!(59)),
            ("ttl", serde_json::json!(60001)),
            ("record_line", serde_json::json!("telecom")),
            ("record_id", serde_json::json!(123)),
            ("record_id", serde_json::json!("../123")),
            (
                "record_id",
                serde_json::json!(format!("namecheap-{}", "a".repeat(64))),
            ),
            ("options", serde_json::json!({"proxied":"true"})),
        ] {
            let mut bad = good.clone();
            bad["records"][0][key] = value;
            invalids.push(bad);
        }
        let mut bad = good.clone();
        bad["providers"][0]["secret_key_env"] = serde_json::json!("PATH");
        invalids.push(bad);
        for bad in invalids {
            assert_eq!(
                router
                    .clone()
                    .oneshot(request("PUT", "/api/config", true, Some(bad)))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(tokio::fs::read(&path).await.unwrap(), saved);
        }
        // Existing Axum schema errors are 422, distinct from semantic validation 400.
        let mut wrong_type = good.clone();
        wrong_type["records"][0]["ttl"] = serde_json::json!("0600");
        assert_eq!(
            router
                .clone()
                .oneshot(request("PUT", "/api/config", true, Some(wrong_type)))
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(tokio::fs::read(&path).await.unwrap(), saved);
        // NEVER supply valid public ClientIp: dry-run would read the fixed vendor DNS API.
        for (user, client_ip, code) in [
            ("ABSENTUSER", "MISSING", "MissingCredentials"),
            ("USER", "MISSING", "MissingClientIp"),
            ("BADUSER", "MISSING", "InvalidCredentials"),
            ("USER", "PRIVATE", "InvalidClientIp"),
            ("USER", "IPV6", "InvalidClientIp"),
            ("USER", "BADIP", "InvalidClientIp"),
        ] {
            let mut local = c.clone();
            local.providers[0].secret_id_env = format!("NAMECHEAP_{user}_{u}");
            local.providers[0]
                .options
                .insert("client_ip_env".into(), format!("NAMECHEAP_{client_ip}_{u}"));
            *app.config.write().await = local;
            let report = json_body(
                router
                    .clone()
                    .oneshot(request(
                        "POST",
                        "/api/run",
                        true,
                        Some(serde_json::json!({"dry_run":true})),
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(report["results"][0]["error"]["code"], code);
            assert!(report["results"][0]["ip"].is_null());
            for secret in [
                "synthetic-key-never-echo",
                "10.23.45.67",
                "2606:4700:4700::1111",
                "literal-invalid-client-ip",
                "invalid username",
            ] {
                assert!(!report.to_string().contains(secret));
            }
        }
        // Engine re-checks scope independently of static Config validation, before IP-source I/O.
        let mut local = c.clone();
        local.records[0].record_line = "telecom".into();
        *app.config.write().await = local;
        let report = json_body(
            router
                .clone()
                .oneshot(request(
                    "POST",
                    "/api/run",
                    true,
                    Some(serde_json::json!({"dry_run":true})),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            report["results"][0]["error"]["code"],
            "UnsupportedRecordOptions"
        );
        assert!(report["results"][0]["ip"].is_null());
        *app.config.write().await = c;
        let real = json_body(
            router
                .oneshot(request(
                    "POST",
                    "/api/run",
                    true,
                    Some(serde_json::json!({"dry_run":false})),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(real["results"][0]["status"], "disabled"); // Skip credentials and network on real disabled runs.
    }
}
