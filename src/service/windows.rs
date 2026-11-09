//! Native Windows service support. SCM launches with machine/service-account environment,
//! not the installing shell's environment; installation deliberately saves no secrets.

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, mpsc},
    time::{Duration, Instant},
};

use tokio::sync::watch;
use windows_service::{
    define_windows_service,
    service::{
        Service, ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl,
        ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const SERVICE_NAME: &str = "ddns-rust";
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: i32 = 1061;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;
const ERROR_SERVICE_EXISTS: i32 = 1073;
const WAIT_HINT: Duration = Duration::from_secs(30);
const START_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(300);
const DELETE_TIMEOUT: Duration = Duration::from_secs(30);
const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(250);

// Unlike Notify::notify_waiters, watch retains a STOP delivered before execute
// installs its shutdown waiter, including when there are currently no receivers.
static SHUTDOWN: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::channel(false).0);
static SERVICE_RESULT: Mutex<Option<Result<(), String>>> = Mutex::new(None);
static SERVICE_FINISHED: Condvar = Condvar::new();
static REPORTER: Mutex<Option<Arc<Mutex<Reporter>>>> = Mutex::new(None);

pub(super) fn install(spec: &super::ServiceSpec) -> Result<(), String> {
    for (label, path) in [
        ("executable", &spec.executable),
        ("configuration", &spec.config),
        ("working directory", &spec.working_dir),
    ] {
        if !path.is_absolute() {
            return Err(format!(
                "Windows service {label} path must be absolute: {}",
                path.display()
            ));
        }
    }
    // Windows SCM cannot configure a cwd. Recover it from --config at startup.
    if spec.config.parent() != Some(spec.working_dir.as_path()) {
        return Err("Windows service working directory must be the configuration's parent".into());
    }
    let manager = ServiceManager::local_computer(
        None::<&OsStr>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| {
        format!("Cannot connect to Windows service manager (run as Administrator): {e}")
    })?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(_) => return Err(existing_service_error()),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {}
        Err(e) => {
            return Err(format!(
                "Cannot check existing Windows service {SERVICE_NAME}: {e}"
            ));
        }
    }
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: spec.executable.clone(),
        // Pass separate OsStrings: windows-service performs native Windows quoting,
        // preserving spaces, Unicode, and trailing backslashes without a shell.
        launch_arguments: launch_arguments(&spec.config, spec.listen),
        dependencies: vec![],
        account_name: None, // LocalSystem; never capture the installer's credentials.
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(|e| match &e {
            windows_service::Error::Winapi(error)
                if error.raw_os_error() == Some(ERROR_SERVICE_EXISTS) =>
            {
                existing_service_error()
            }
            _ => format!("Cannot install Windows service {SERVICE_NAME}: {e}"),
        })?;
    service
        .start::<&OsStr>(&[])
        .map_err(|e| installed_start_error(format!("could not start: {e}")))?;
    // StartService only acknowledges launch. Running is published by the existing
    // readiness callback after configuration loading and listener binding succeed.
    wait_for_service(&service, ServiceGoal::Running, START_TIMEOUT).map_err(installed_start_error)
}

fn installed_start_error(reason: String) -> String {
    format!(
        "Windows service {SERVICE_NAME} was installed for automatic startup, but {reason}. Its registration has been retained. Inspect its configuration and start it with `sc.exe start {SERVICE_NAME}`; do not reinstall over it."
    )
}

/// Remove only the named SCM service; no executable or configuration is needed.
/// Never mark it for deletion until SCM confirms graceful shutdown has completed.
pub(super) fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)
        .map_err(|e| {
            format!("Cannot connect to Windows service manager (run as Administrator): {e}")
        })?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => service,
        Err(e) if is_service_error(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(()),
        // An earlier uninstall may have marked it while another process still
        // holds a handle. Do not claim it is gone until SCM says it is absent.
        Err(e) if is_service_error(&e, ERROR_SERVICE_MARKED_FOR_DELETE) => {
            return wait_for_deletion(&manager);
        }
        Err(e) => {
            return Err(format!(
                "Cannot open Windows service {SERVICE_NAME} for uninstall (run as Administrator): {e}"
            ));
        }
    };
    wait_for_service(&service, ServiceGoal::Stopped, STOP_TIMEOUT).map_err(|e| {
        format!("Cannot uninstall Windows service {SERVICE_NAME}: {e}. It has not been deleted.")
    })?;
    match service.delete() {
        Ok(()) => {}
        Err(e) if is_service_error(&e, ERROR_SERVICE_MARKED_FOR_DELETE) => {}
        Err(e) if is_service_error(&e, ERROR_SERVICE_DOES_NOT_EXIST) => {}
        Err(e) => {
            return Err(format!(
                "Windows service {SERVICE_NAME} is stopped, but cannot be deleted (run as Administrator): {e}"
            ));
        }
    }
    // DeleteService only marks registration; our own handle would prevent removal.
    drop(service);
    wait_for_deletion(&manager)
}

fn is_service_error(error: &windows_service::Error, code: i32) -> bool {
    matches!(error, windows_service::Error::Winapi(e) if e.raw_os_error() == Some(code))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceGoal {
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PollDecision {
    Complete,
    Wait,
    Stop,
    Failed,
    TimedOut,
}

// The wall-clock limit is absolute: checkpoints/wait hints never extend it.
// Keep decisions separate from SCM calls so pending-state races are testable.
fn status_poll_decision(
    state: ServiceState,
    goal: ServiceGoal,
    stop_requested: bool,
    elapsed: Duration,
    timeout: Duration,
) -> PollDecision {
    match (goal, state) {
        (ServiceGoal::Running, ServiceState::Running)
        | (ServiceGoal::Stopped, ServiceState::Stopped) => return PollDecision::Complete,
        (ServiceGoal::Running, ServiceState::StartPending) => {}
        (ServiceGoal::Running, _) => return PollDecision::Failed,
        (ServiceGoal::Stopped, _) => {}
    }
    if elapsed >= timeout {
        return PollDecision::TimedOut;
    }
    match state {
        ServiceState::Running | ServiceState::Paused if !stop_requested => PollDecision::Stop,
        // StartPending does not accept STOP yet; let it reach Running first.
        // StopPending already has a shutdown in flight, so do not send it again.
        _ => PollDecision::Wait,
    }
}

fn wait_for_service(service: &Service, goal: ServiceGoal, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut stop_requested = false;
    loop {
        let status = service
            .query_status()
            .map_err(|e| format!("cannot query Windows service {SERVICE_NAME} status: {e}"))?;
        match status_poll_decision(
            status.current_state,
            goal,
            stop_requested,
            start.elapsed(),
            timeout,
        ) {
            PollDecision::Complete => return Ok(()),
            PollDecision::Failed => {
                return Err(format!(
                    "did not reach {goal:?}: state {:?}, exit code {:?}",
                    status.current_state, status.exit_code
                ));
            }
            PollDecision::TimedOut => {
                return Err(format!(
                    "timed out after {}s waiting for {goal:?}: state {:?}, exit code {:?}, checkpoint {}, wait hint {:?}",
                    timeout.as_secs(),
                    status.current_state,
                    status.exit_code,
                    status.checkpoint,
                    status.wait_hint
                ));
            }
            PollDecision::Stop => match service.stop() {
                Ok(_) => stop_requested = true,
                Err(e) => {
                    // Status can change between query and ControlService. Only
                    // tolerate errors explained by a newly observed pending or
                    // stopped state; all real stop failures preserve registration.
                    let raced = if is_service_error(&e, ERROR_SERVICE_NOT_ACTIVE)
                        || is_service_error(&e, ERROR_SERVICE_CANNOT_ACCEPT_CTRL)
                    {
                        service.query_status().ok().is_some_and(|status| {
                            matches!(
                                status.current_state,
                                ServiceState::Stopped
                                    | ServiceState::StopPending
                                    | ServiceState::StartPending
                            )
                        })
                    } else {
                        false
                    };
                    if !raced {
                        return Err(format!("cannot stop Windows service {SERVICE_NAME}: {e}"));
                    }
                }
            },
            PollDecision::Wait => {}
        }
        std::thread::sleep(STATUS_POLL_INTERVAL.min(timeout.saturating_sub(start.elapsed())));
    }
}

fn wait_for_deletion(manager: &ServiceManager) -> Result<(), String> {
    let start = Instant::now();
    loop {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            // Close every poll handle immediately; do not delay SCM removal.
            Ok(service) => drop(service),
            Err(e) if is_service_error(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(()),
            Err(e) if is_service_error(&e, ERROR_SERVICE_MARKED_FOR_DELETE) => {}
            Err(e) => {
                return Err(format!(
                    "Cannot confirm Windows service {SERVICE_NAME} registration removal: {e}"
                ));
            }
        }
        if start.elapsed() >= DELETE_TIMEOUT {
            return Err(format!(
                "Windows service {SERVICE_NAME} deletion is pending: registration still exists after {}s. Close service-management tools or other open service handles and retry uninstall; a service already marked for deletion may require a restart. No processes were force-killed.",
                DELETE_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(
            STATUS_POLL_INTERVAL.min(DELETE_TIMEOUT.saturating_sub(start.elapsed())),
        );
    }
}

fn existing_service_error() -> String {
    format!(
        "Windows service {SERVICE_NAME} already exists; refusing to overwrite it. Inspect it with `sc.exe qc {SERVICE_NAME}` and explicitly remove it before reinstalling."
    )
}

fn launch_arguments(config: &Path, listen: Option<std::net::SocketAddr>) -> Vec<OsString> {
    let mut args = vec![
        "--config".into(),
        config.as_os_str().to_owned(),
        "serve".into(),
    ];
    if let Some(listen) = listen {
        args.extend(["--listen".into(), listen.to_string().into()]);
    }
    args.push("--service-run".into());
    args
}

/// Connect to SCM on the process's synchronous main thread, before creating Tokio.
/// This is only for the hidden --service-run flag, never the installer (-s).
pub fn dispatch() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("Cannot dispatch Windows service {SERVICE_NAME}: {e}"))?;
    // SCM can unblock as soon as Stopped is published, before service_main has
    // stored its result. Wait for completion instead of losing startup errors.
    let mut result = lock(&SERVICE_RESULT);
    while result.is_none() {
        result = SERVICE_FINISHED
            .wait(result)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    result.take().expect("service_main completion result")
}

/// Called by serve immediately after binding its listener, before serving requests.
/// Foreground execution is a no-op; an early STOP must not be overwritten.
pub fn report_running() -> Result<(), String> {
    let Some(reporter) = lock(&REPORTER).clone() else {
        return Ok(());
    };
    let mut state = lock(&reporter);
    if let Some(error) = &state.error {
        return Err(error.clone());
    }
    if state.status.current_state == ServiceState::StartPending {
        state.status.current_state = ServiceState::Running;
        state.status.controls_accepted =
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN;
        state.status.checkpoint = 0;
        state.status.wait_hint = Duration::ZERO;
        state.publish();
    }
    state.error.clone().map_or(Ok(()), Err)
}

/// Await SCM STOP/SHUTDOWN. The application's shutdown helper also selects Ctrl-C.
pub async fn shutdown_signal() {
    wait_for_shutdown(SHUTDOWN.subscribe()).await;
}

async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    // No panic may unwind through the generated extern "system" callback.
    let result = std::panic::catch_unwind(run_service)
        .unwrap_or_else(|_| Err("Windows service lifecycle panicked".into()));
    *lock(&SERVICE_RESULT) = Some(result);
    SERVICE_FINISHED.notify_one();
}

struct Reporter {
    handle: Option<ServiceStatusHandle>,
    status: ServiceStatus,
    error: Option<String>,
}

impl Reporter {
    fn new() -> Self {
        Self {
            handle: None,
            status: ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::StartPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 1,
                wait_hint: WAIT_HINT,
                process_id: None,
            },
            error: None,
        }
    }

    fn publish(&mut self) {
        if let Some(handle) = self.handle {
            if let Err(error) = handle.set_service_status(self.status.clone()) {
                self.error.get_or_insert_with(|| {
                    format!("Cannot report Windows service status: {error}")
                });
            }
        }
    }

    fn stop_pending(&mut self) {
        if self.status.current_state == ServiceState::Stopped {
            return;
        }
        if self.status.current_state != ServiceState::StopPending {
            self.status.current_state = ServiceState::StopPending;
            self.status.controls_accepted = ServiceControlAccept::empty();
            self.status.checkpoint = 1;
            self.status.wait_hint = WAIT_HINT;
        } else {
            self.status.checkpoint = self.status.checkpoint.saturating_add(1);
        }
        self.publish();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn run_service() -> Result<(), String> {
    let reporter = Arc::new(Mutex::new(Reporter::new()));
    *lock(&REPORTER) = Some(reporter.clone());
    let handler_reporter = reporter.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Serialize status updates so startup cannot overwrite StopPending with Running.
            lock(&handler_reporter).stop_pending();
            SHUTDOWN.send_replace(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => {
            lock(&handler_reporter).publish();
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|e| format!("Cannot register Windows service control handler: {e}"))?;
    {
        let mut state = lock(&reporter);
        state.handle = Some(handle);
        state.publish();
    }
    // Catch application/runtime panics while we still have the status handle and
    // can report SERVICE_SPECIFIC_ERROR rather than falsely reporting success.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let config = config_argument(std::env::args_os().skip(1))?;
        let cwd = config
            .parent()
            .ok_or("Windows service configuration has no parent directory")?;
        std::env::set_current_dir(cwd).map_err(|e| {
            format!(
                "Cannot set Windows service working directory {}: {e}",
                cwd.display()
            )
        })?;
        {
            let state = lock(&reporter);
            if let Some(error) = &state.error {
                return Err(error.clone());
            }
        }
        let (done_tx, done_rx) = mpsc::channel();
        let monitor_reporter = reporter.clone();
        let monitor = std::thread::Builder::new()
            .name("windows-service-status".into())
            .spawn(move || {
                while matches!(
                    done_rx.recv_timeout(Duration::from_secs(5)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    let mut state = lock(&monitor_reporter);
                    match state.status.current_state {
                        ServiceState::StartPending => {
                            state.status.checkpoint = state.status.checkpoint.saturating_add(1);
                            state.publish();
                        }
                        ServiceState::StopPending => {
                            // Graceful drain can outlive one wait hint: do not cancel DNS operations.
                            state.stop_pending();
                        }
                        _ => {}
                    }
                }
            })
            .map_err(|e| format!("Cannot start Windows service status reporter: {e}"))?;
        let application = std::panic::catch_unwind(crate::run_application)
            .unwrap_or_else(|_| Err("Windows service application panicked".into()));
        let _ = done_tx.send(());
        if monitor.join().is_err() {
            return Err("Windows service status reporter panicked".into());
        }
        application
    }))
    .unwrap_or_else(|_| Err("Windows service initialization panicked".into()));
    let mut state = lock(&reporter);
    let result = result.and_then(|()| state.error.clone().map_or(Ok(()), Err));
    state.status.current_state = ServiceState::Stopped;
    state.status.controls_accepted = ServiceControlAccept::empty();
    state.status.exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    state.status.checkpoint = 0;
    state.status.wait_hint = Duration::ZERO;
    state.publish();
    result.and_then(|()| state.error.clone().map_or(Ok(()), Err))
}

fn config_argument(args: impl IntoIterator<Item = OsString>) -> Result<PathBuf, String> {
    let mut args = args.into_iter();
    let mut config = None;
    while let Some(arg) = args.next() {
        if arg == "--config" {
            config = Some(PathBuf::from(
                args.next().ok_or("--config requires a path")?,
            ));
        } else {
            // Split the ASCII prefix without converting a potentially non-Unicode
            // Windows path into a lossy String.
            use std::os::windows::ffi::{OsStrExt, OsStringExt};
            let wide: Vec<u16> = arg.encode_wide().collect();
            let prefix: Vec<u16> = "--config=".encode_utf16().collect();
            if let Some(value) = wide.strip_prefix(prefix.as_slice()) {
                config = Some(PathBuf::from(OsString::from_wide(value)));
            }
        }
    }
    let config = config.ok_or("Windows service requires an explicit absolute --config path")?;
    if !config.is_absolute() {
        return Err("Windows service --config path must be absolute".into());
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_waits_for_readiness_and_reports_terminal_startup_failure() {
        for state in [
            ServiceState::StartPending,
            ServiceState::Running,
            ServiceState::Stopped,
        ] {
            let expected = match state {
                ServiceState::StartPending => PollDecision::Wait,
                ServiceState::Running => PollDecision::Complete,
                _ => PollDecision::Failed,
            };
            assert_eq!(
                status_poll_decision(
                    state,
                    ServiceGoal::Running,
                    false,
                    Duration::ZERO,
                    START_TIMEOUT
                ),
                expected
            );
        }
        for state in [
            ServiceState::StopPending,
            ServiceState::Paused,
            ServiceState::PausePending,
            ServiceState::ContinuePending,
        ] {
            assert_eq!(
                status_poll_decision(
                    state,
                    ServiceGoal::Running,
                    false,
                    Duration::ZERO,
                    START_TIMEOUT
                ),
                PollDecision::Failed
            );
        }
    }

    #[test]
    fn uninstall_waits_for_start_and_stop_pending_without_sending_stop() {
        for state in [
            ServiceState::StartPending,
            ServiceState::StopPending,
            ServiceState::PausePending,
            ServiceState::ContinuePending,
        ] {
            assert_eq!(
                status_poll_decision(
                    state,
                    ServiceGoal::Stopped,
                    false,
                    Duration::ZERO,
                    STOP_TIMEOUT
                ),
                PollDecision::Wait
            );
        }
        for state in [ServiceState::Running, ServiceState::Paused] {
            assert_eq!(
                status_poll_decision(
                    state,
                    ServiceGoal::Stopped,
                    false,
                    Duration::ZERO,
                    STOP_TIMEOUT
                ),
                PollDecision::Stop
            );
            assert_eq!(
                status_poll_decision(
                    state,
                    ServiceGoal::Stopped,
                    true,
                    Duration::ZERO,
                    STOP_TIMEOUT
                ),
                PollDecision::Wait
            );
        }
        assert_eq!(
            status_poll_decision(
                ServiceState::Stopped,
                ServiceGoal::Stopped,
                false,
                Duration::ZERO,
                STOP_TIMEOUT
            ),
            PollDecision::Complete
        );
    }

    #[test]
    fn pending_states_and_stop_requests_obey_absolute_timeout() {
        for elapsed in [STOP_TIMEOUT, STOP_TIMEOUT + Duration::from_secs(1)] {
            for state in [
                ServiceState::StartPending,
                ServiceState::StopPending,
                ServiceState::Running,
                ServiceState::Paused,
            ] {
                for stop_requested in [false, true] {
                    assert_eq!(
                        status_poll_decision(
                            state,
                            ServiceGoal::Stopped,
                            stop_requested,
                            elapsed,
                            STOP_TIMEOUT
                        ),
                        PollDecision::TimedOut
                    );
                }
            }
        }
        assert_eq!(
            status_poll_decision(
                ServiceState::StartPending,
                ServiceGoal::Running,
                false,
                START_TIMEOUT,
                START_TIMEOUT
            ),
            PollDecision::TimedOut
        );
        // A status observed at the boundary already satisfies the goal.
        assert_eq!(
            status_poll_decision(
                ServiceState::Running,
                ServiceGoal::Running,
                false,
                START_TIMEOUT,
                START_TIMEOUT
            ),
            PollDecision::Complete
        );
        assert_eq!(
            status_poll_decision(
                ServiceState::Stopped,
                ServiceGoal::Stopped,
                true,
                STOP_TIMEOUT,
                STOP_TIMEOUT
            ),
            PollDecision::Complete
        );
    }

    #[test]
    fn service_errors_do_not_confuse_absent_marked_delete_or_access_denied() {
        let absent = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(
            ERROR_SERVICE_DOES_NOT_EXIST,
        ));
        let marked = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(
            ERROR_SERVICE_MARKED_FOR_DELETE,
        ));
        let denied = windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5));
        assert!(is_service_error(&absent, ERROR_SERVICE_DOES_NOT_EXIST));
        assert!(!is_service_error(&marked, ERROR_SERVICE_DOES_NOT_EXIST));
        assert!(is_service_error(&marked, ERROR_SERVICE_MARKED_FOR_DELETE));
        assert!(!is_service_error(&denied, ERROR_SERVICE_DOES_NOT_EXIST));
        assert!(!is_service_error(&denied, ERROR_SERVICE_MARKED_FOR_DELETE));
    }

    #[test]
    fn failed_install_explains_that_registration_is_retained() {
        let message = installed_start_error("startup failed".into());
        assert!(message.contains("startup failed"));
        assert!(message.contains("registration has been retained"));
        assert!(message.contains("do not reinstall over it"));
    }

    #[test]
    fn launch_arguments_preserve_paths_without_shell_quoting_or_installer_flag() {
        let config = Path::new(r"C:\Program Files\动态 DNS\config.toml");
        let args = launch_arguments(config, Some("[::1]:3000".parse().unwrap()));
        assert_eq!(
            args,
            vec![
                OsString::from("--config"),
                config.as_os_str().to_owned(),
                "serve".into(),
                "--listen".into(),
                "[::1]:3000".into(),
                "--service-run".into(),
            ]
        );
        assert_eq!(launch_arguments(config, None).len(), 4);
    }

    #[test]
    fn config_argument_accepts_both_clap_forms_and_rejects_relative_paths() {
        let path = r"C:\Program Files\动态 DNS\config.toml";
        assert_eq!(
            config_argument(["--config".into(), path.into(), "serve".into()]).unwrap(),
            PathBuf::from(path)
        );
        assert_eq!(
            config_argument([format!("--config={path}").into(), "serve".into()]).unwrap(),
            PathBuf::from(path)
        );
        assert!(config_argument(["--config".into(), "config.toml".into()]).is_err());
        assert!(config_argument(["--config".into()]).is_err());
        assert!(config_argument(["serve".into()]).is_err());
    }

    #[test]
    fn config_argument_preserves_non_unicode_windows_paths() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let mut wide: Vec<u16> = r"C:\service\".encode_utf16().collect();
        wide.push(0xd800); // An unpaired surrogate is valid in a Windows OsString.
        wide.extend(".toml".encode_utf16());
        let path = OsString::from_wide(&wide);
        let mut argument = OsString::from("--config=");
        argument.push(&path);
        let parsed = config_argument([argument]).unwrap();
        assert_eq!(parsed.as_os_str().encode_wide().collect::<Vec<_>>(), wide);
    }

    #[test]
    fn stop_pending_progress_does_not_overwrite_stopped() {
        let mut reporter = Reporter::new();
        reporter.stop_pending();
        assert_eq!(reporter.status.current_state, ServiceState::StopPending);
        assert!(reporter.status.controls_accepted.is_empty());
        assert_eq!(reporter.status.checkpoint, 1);
        reporter.stop_pending();
        assert_eq!(reporter.status.checkpoint, 2);
        reporter.status.current_state = ServiceState::Stopped;
        reporter.stop_pending();
        assert_eq!(reporter.status.current_state, ServiceState::Stopped);
    }

    #[tokio::test]
    async fn shutdown_is_retained_before_subscription_and_reaches_all_waiters() {
        let (sender, _) = watch::channel(false);
        sender.send_replace(true);
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_shutdown(sender.subscribe()),
        )
        .await
        .unwrap();
        let (sender, receiver) = watch::channel(false);
        let first = tokio::spawn(wait_for_shutdown(receiver));
        let second = tokio::spawn(wait_for_shutdown(sender.subscribe()));
        sender.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), async {
            first.await.unwrap();
            second.await.unwrap();
        })
        .await
        .unwrap();
    }
}
