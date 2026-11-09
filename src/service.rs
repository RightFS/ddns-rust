//! Native service registration; never capture credentials from the installing shell.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
#[cfg(windows)]
pub mod windows;

pub struct ServiceSpec {
    pub executable: PathBuf,
    pub config: PathBuf,
    pub working_dir: PathBuf,
    pub listen: Option<SocketAddr>,
}
impl ServiceSpec {
    pub fn current(config: &Path, listen: Option<SocketAddr>) -> Result<Self, String> {
        let config = config
            .canonicalize()
            .map_err(|e| format!("Cannot resolve configuration (run init first): {e}"))?;
        let working_dir = config
            .parent()
            .ok_or("Configuration has no parent directory")?
            .to_path_buf();
        let executable = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let spec = Self {
            executable,
            config,
            working_dir,
            listen,
        };
        for path in [&spec.executable, &spec.config, &spec.working_dir] {
            let text = path.to_str().ok_or("Service paths must be valid UTF-8")?;
            if text.chars().any(char::is_control) {
                return Err("Service paths must not contain control characters".into());
            }
        }
        Ok(spec)
    }
    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn arguments(&self) -> Vec<String> {
        let mut args = vec![
            "--config".into(),
            self.config.to_string_lossy().into_owned(),
            "serve".into(),
        ];
        if let Some(listen) = self.listen {
            args.extend(["--listen".into(), listen.to_string()]);
        }
        args
    }
}
pub fn install(spec: &ServiceSpec) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::install(spec)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        require_root()?;
        install_unix(spec)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = spec;
        Err("Service installation supports Windows, Linux (systemd), and macOS only".into())
    }
}
pub fn uninstall() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::uninstall()
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        require_root()?;
        uninstall_unix()
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err("Service management supports Windows, Linux (systemd), and macOS only".into())
    }
}

pub fn web_url(mut listen: SocketAddr) -> String {
    // Wildcard bind addresses are not browser destinations. Prefer the same IP family.
    if listen.ip().is_unspecified() {
        listen.set_ip(if listen.is_ipv4() {
            std::net::Ipv4Addr::LOCALHOST.into()
        } else {
            std::net::Ipv6Addr::LOCALHOST.into()
        });
    }
    format!("http://{listen}")
}

pub async fn wait_for_web(listen: SocketAddr) -> Result<(), String> {
    let url = format!("{}/healthz", web_url(listen));
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(1))
        .build()
        .map_err(|e| format!("Cannot check service readiness: {e}"))?;
    let ready = async {
        loop {
            if let Ok(response) = client.get(&url).send().await
                && response.status().is_success()
                && let Ok(body) = response.json::<serde_json::Value>().await
                && body["status"] == "ok"
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), ready).await
        .map_err(|_| format!("Service was registered, but Web management did not become ready at {} within 30 seconds. Inspect service logs; registration was retained.", web_url(listen)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_root() -> Result<(), String> {
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| format!("Cannot check administrator privileges: {e}"))?;
    if !uid.status.success() || uid.stdout != b"0\n" {
        return Err("Service management requires root; run the command with sudo".into());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("Cannot execute {program}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_definition(path: &Path, contents: &str) -> Result<(), String> {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().ok_or("Missing service directory")?)
            .map_err(|e| format!("Cannot create service definition: {e}"))?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(|e| e.to_string())?;
    file.write_all(contents.as_bytes())
        .map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist_noclobber(path).map_err(|e| {
        format!(
            "Cannot install {} (existing services are not overwritten): {e}",
            path.display()
        )
    })?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn install_unix(spec: &ServiceSpec) -> Result<(), String> {
    if !Path::new("/run/systemd/system").is_dir() {
        return Err("Linux service installation requires a running systemd system manager".into());
    }
    let path = Path::new("/etc/systemd/system/ddns-rust.service");
    write_definition(path, &systemd_unit(spec))?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", "ddns-rust.service"])?;
    Ok(())
}
#[cfg(target_os = "macos")]
fn install_unix(spec: &ServiceSpec) -> Result<(), String> {
    let loaded = Command::new("launchctl")
        .args(["print", "system/com.ddns-rust"])
        .output()
        .map_err(|e| format!("Cannot execute launchctl: {e}"))?;
    if loaded.status.success() {
        return Err(
            "com.ddns-rust is already registered; bootout the existing service before installing"
                .into(),
        );
    }
    let path = Path::new("/Library/LaunchDaemons/com.ddns-rust.plist");
    write_definition(path, &launchd_plist(spec))?;
    run("launchctl", &["enable", "system/com.ddns-rust"])?;
    run(
        "launchctl",
        &["bootstrap", "system", path.to_str().unwrap()],
    )?;
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_definition(path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("Cannot inspect service definition: {e}")),
        Ok(metadata) if !metadata.is_file() => {
            return Err(
                "Refusing to delete a service definition that is not a regular file".into(),
            );
        }
        Ok(_) => {}
    }
    let intended = path
        .parent()
        .ok_or("Service definition has no parent")?
        .canonicalize()
        .map_err(|e| e.to_string())?
        .join(
            path.file_name()
                .ok_or("Service definition has no filename")?,
        );
    let resolved = path.canonicalize().map_err(|e| e.to_string())?;
    if !path.is_absolute() || resolved != intended {
        return Err("Refusing to delete an unexpected service definition path".into());
    }
    std::fs::remove_file(&resolved).map_err(|e| format!("Cannot remove service definition: {e}"))
}

#[cfg(any(target_os = "linux", test))]
fn uninstall_systemd(
    path: &Path,
    loaded: bool,
    mut command: impl FnMut(&str, &[&str]) -> Result<(), String>,
    mut remove: impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    if loaded {
        // systemctl stop blocks until stopped; never remove registration when stop fails.
        command("systemctl", &["stop", "ddns-rust.service"])?;
        command("systemctl", &["disable", "ddns-rust.service"])?;
    }
    remove(path)?;
    command("systemctl", &["daemon-reload"])?;
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn uninstall_launchd(
    path: &Path,
    loaded: bool,
    mut command: impl FnMut(&str, &[&str]) -> Result<(), String>,
    mut remove: impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    if loaded {
        command("launchctl", &["bootout", "system/com.ddns-rust"])?;
    }
    remove(path)
}

#[cfg(target_os = "linux")]
fn uninstall_unix() -> Result<(), String> {
    if !Path::new("/run/systemd/system").is_dir() {
        return Err("Linux service management requires a running systemd system manager".into());
    }
    let output = Command::new("systemctl")
        .args([
            "show",
            "--property=LoadState",
            "--value",
            "ddns-rust.service",
        ])
        .output()
        .map_err(|e| format!("Cannot execute systemctl: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Cannot query service state: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let loaded = String::from_utf8_lossy(&output.stdout).trim() != "not-found";
    uninstall_systemd(
        Path::new("/etc/systemd/system/ddns-rust.service"),
        loaded,
        run,
        remove_definition,
    )
}

#[cfg(target_os = "macos")]
fn uninstall_unix() -> Result<(), String> {
    let output = Command::new("launchctl")
        .args(["print", "system/com.ddns-rust"])
        .output()
        .map_err(|e| format!("Cannot execute launchctl: {e}"))?;
    // launchctl can report an absent job as ESRCH (3) or service-not-found (113).
    // Permission/connection failures must not trigger deletion.
    if !output.status.success() && !matches!(output.status.code(), Some(3 | 113)) {
        return Err(format!(
            "Cannot query service state: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let pid = launchd_pid(&String::from_utf8_lossy(&output.stdout));
    uninstall_launchd(
        Path::new("/Library/LaunchDaemons/com.ddns-rust.plist"),
        output.status.success(),
        run,
        |path| {
            if let Some(pid) = pid {
                wait_for_launchd_exit(pid)?;
            }
            remove_definition(path)
        },
    )
}

#[cfg(any(target_os = "macos", test))]
fn launchd_pid(description: &str) -> Option<u32> {
    description.lines().find_map(|line| {
        line.trim()
            .strip_prefix("pid = ")?
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid > 1)
    })
}

#[cfg(target_os = "macos")]
fn wait_for_launchd_exit(pid: u32) -> Result<(), String> {
    let start = std::time::Instant::now();
    loop {
        // Signal zero only tests existence; never force-kill a process or process group.
        let output = Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .env("LC_ALL", "C")
            .output()
            .map_err(|e| format!("Cannot check stopped service process: {e}"))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr);
            if detail.contains("No such process") {
                return Ok(());
            }
            return Err(format!(
                "Cannot confirm service process exit: {}",
                detail.trim()
            ));
        }
        if start.elapsed() >= std::time::Duration::from_secs(300) {
            return Err("Service was unloaded, but its process did not exit within 300 seconds; the plist was retained".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(any(target_os = "linux", test))]
fn systemd_quote(text: &str) -> String {
    format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}
#[cfg(any(target_os = "linux", test))]
fn systemd_unit(spec: &ServiceSpec) -> String {
    let command = std::iter::once(spec.executable.to_string_lossy().into_owned())
        .chain(spec.arguments())
        .map(|arg| systemd_quote(&arg))
        .collect::<Vec<_>>()
        .join(" ");
    let dir = systemd_quote(&spec.working_dir.to_string_lossy());
    let env = systemd_quote(&spec.working_dir.join("ddns-rust.env").to_string_lossy());
    format!(
        "[Unit]\nDescription=ddns-rust dynamic DNS\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\nWorkingDirectory={dir}\nEnvironmentFile=-{env}\nExecStart=:{command}\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=300\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}
#[cfg(any(target_os = "macos", test))]
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
#[cfg(any(target_os = "macos", test))]
fn launchd_plist(spec: &ServiceSpec) -> String {
    let args = std::iter::once(spec.executable.to_string_lossy().into_owned())
        .chain(spec.arguments())
        .map(|arg| format!("    <string>{}</string>\n", xml_escape(&arg)))
        .collect::<String>();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>com.ddns-rust</string>\n  <key>ProgramArguments</key><array>\n{args}  </array>\n  <key>WorkingDirectory</key><string>{}</string>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n  <key>ThrottleInterval</key><integer>5</integer>\n  <key>ExitTimeOut</key><integer>300</integer>\n  <key>Umask</key><integer>63</integer>\n  <key>StandardOutPath</key><string>/var/log/ddns-rust.log</string>\n  <key>StandardErrorPath</key><string>/var/log/ddns-rust.log</string>\n</dict></plist>\n",
        xml_escape(&spec.working_dir.to_string_lossy())
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> ServiceSpec {
        ServiceSpec {
            executable: "/opt/DDNS & tools/ddns-rust".into(),
            config: "/etc/ddns/config %$\".toml".into(),
            working_dir: "/etc/ddns".into(),
            listen: Some("127.0.0.1:9876".parse().unwrap()),
        }
    }
    #[test]
    fn systemd_escapes_paths_and_never_reinstalls() {
        let unit = systemd_unit(&spec());
        assert!(unit.contains("config %%$\\\".toml"));
        assert!(unit.contains("ExecStart=:"));
        assert!(unit.contains("\"serve\" \"--listen\" \"127.0.0.1:9876\""));
        assert!(!unit.contains("\"-s\""));
        let env = systemd_quote(&spec().working_dir.join("ddns-rust.env").to_string_lossy());
        assert!(unit.contains(&format!("EnvironmentFile=-{env}")));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }
    #[test]
    fn launchd_escapes_xml_and_keeps_each_argument_separate() {
        let plist = launchd_plist(&spec());
        assert!(plist.contains("<string>/opt/DDNS &amp; tools/ddns-rust</string>"));
        assert!(plist.contains("config %$&quot;.toml</string>"));
        assert!(!plist.contains("<string>-s</string>"));
        assert!(plist.contains("<key>RunAtLoad</key><true/>"));
        let mut reader = quick_xml::Reader::from_str(&plist);
        while !matches!(reader.read_event().unwrap(), quick_xml::events::Event::Eof) {}
    }
    #[test]
    fn default_listener_has_no_override() {
        let mut spec = spec();
        spec.listen = None;
        assert_eq!(spec.arguments().len(), 3);
    }
    #[test]
    fn registration_resolves_paths_and_rejects_missing_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        assert!(ServiceSpec::current(&path, None).is_err());
        std::fs::write(&path, "").unwrap();
        let spec = ServiceSpec::current(&path, None).unwrap();
        assert!(spec.executable.is_absolute());
        assert_eq!(spec.config, path.canonicalize().unwrap());
        assert_eq!(spec.working_dir, dir.path().canonicalize().unwrap());
    }
    #[test]
    fn launchd_pid_is_only_a_positive_service_process() {
        assert_eq!(
            launchd_pid("service = {\n  state = running\n  pid = 4321\n}"),
            Some(4321)
        );
        for text in [
            "pid = -1",
            "pid = 0",
            "pid = 1",
            "pid = malformed",
            "state = waiting",
        ] {
            assert_eq!(launchd_pid(text), None);
        }
    }

    #[test]
    fn browser_urls_handle_ipv4_ipv6_and_wildcard_binds() {
        for (listen, expected) in [
            ("127.0.0.1:9876", "http://127.0.0.1:9876"),
            ("0.0.0.0:1234", "http://127.0.0.1:1234"),
            ("[::]:9876", "http://[::1]:9876"),
            ("[::1]:1234", "http://[::1]:1234"),
            ("192.168.1.2:9876", "http://192.168.1.2:9876"),
        ] {
            assert_eq!(web_url(listen.parse().unwrap()), expected);
        }
    }

    fn simulate_uninstall(
        systemd: bool,
        loaded: bool,
        fail_stop: bool,
    ) -> (Result<(), String>, Vec<String>) {
        let events = std::cell::RefCell::new(Vec::new());
        let command = |_: &str, args: &[&str]| {
            events.borrow_mut().push(args.join(" "));
            if fail_stop && matches!(args[0], "stop" | "bootout") {
                Err("stop failed".into())
            } else {
                Ok(())
            }
        };
        let remove = |_: &Path| {
            events.borrow_mut().push("remove".into());
            Ok(())
        };
        let path = Path::new("/test/service");
        let result = if systemd {
            uninstall_systemd(path, loaded, command, remove)
        } else {
            uninstall_launchd(path, loaded, command, remove)
        };
        (result, events.into_inner())
    }
    #[test]
    fn uninstall_stops_before_removing_registration() {
        let (result, events) = simulate_uninstall(true, true, false);
        assert!(result.is_ok());
        assert_eq!(
            events,
            [
                "stop ddns-rust.service",
                "disable ddns-rust.service",
                "remove",
                "daemon-reload"
            ]
        );
        let (result, events) = simulate_uninstall(false, true, false);
        assert!(result.is_ok());
        assert_eq!(events, ["bootout system/com.ddns-rust", "remove"]);
    }
    #[test]
    fn failed_stop_never_deletes_service_definition() {
        for systemd in [true, false] {
            let (result, events) = simulate_uninstall(systemd, true, true);
            assert!(result.is_err());
            assert_eq!(events.len(), 1);
        }
    }
    #[test]
    fn unloaded_services_can_remove_leftover_definitions() {
        let (result, events) = simulate_uninstall(true, false, false);
        assert!(result.is_ok());
        assert_eq!(events, ["remove", "daemon-reload"]);
        let (result, events) = simulate_uninstall(false, false, false);
        assert!(result.is_ok());
        assert_eq!(events, ["remove"]);
    }
    #[tokio::test]
    async fn waits_for_background_web_health() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/healthz",
            axum::routing::get(|| async { axum::Json(serde_json::json!({"status":"ok"})) }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        wait_for_web(address).await.unwrap();
        server.abort();
        let _ = server.await;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn removal_preserves_config_and_refuses_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let definition = dir.path().join("service");
        let config = dir.path().join("config.toml");
        std::fs::write(&definition, "service").unwrap();
        std::fs::write(&config, "config").unwrap();
        remove_definition(&definition).unwrap();
        remove_definition(&definition).unwrap();
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "config");
        std::os::unix::fs::symlink(&config, &definition).unwrap();
        assert!(remove_definition(&definition).is_err());
        assert!(config.exists());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn service_file_refuses_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("service");
        write_definition(&path, "original").unwrap();
        assert!(write_definition(&path, "replacement").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");
    }
}
