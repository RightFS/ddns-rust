use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSettings {
    pub listen: SocketAddr,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password_hash: String,
    #[serde(default)]
    pub token: String,
}
impl Default for WebSettings {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9876".parse().unwrap(),
            username: String::new(),
            password_hash: String::new(),
            token: String::new(),
        }
    }
}
impl WebSettings {
    pub fn initialized(&self) -> bool {
        !self.username.is_empty() && !self.password_hash.is_empty()
    }
    pub fn path(config: &Path) -> PathBuf {
        config.with_file_name(format!(
            "{}.web.toml",
            config.file_name().unwrap_or_default().to_string_lossy()
        ))
    }
    pub async fn load(path: &Path) -> Result<Self, String> {
        let text = match tokio::fs::read_to_string(path).await {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("Cannot read web settings: {e}")),
        };
        let settings: Self =
            toml::from_str(&text).map_err(|_| "Invalid web settings file".to_owned())?;
        if settings.username.is_empty() != settings.password_hash.is_empty()
            || settings.initialized() && PasswordHash::new(&settings.password_hash).is_err()
            || !settings.token.is_empty() && settings.token.len() < 24
            || settings.listen.port() == 0
        {
            return Err("Invalid persisted web account or listen address".into());
        }
        Ok(settings)
    }
    pub async fn save(&self, path: &Path) -> Result<(), String> {
        let text =
            toml::to_string_pretty(self).map_err(|_| "Cannot serialize web settings".to_owned())?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut file = tempfile::Builder::new()
            .prefix(".ddns-web-")
            .tempfile_in(parent)
            .map_err(|e| format!("Cannot create web settings: {e}"))?;
        use std::io::Write;
        file.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist(path)
            .map_err(|e| format!("Cannot persist web settings: {}", e.error))?;
        Ok(())
    }
}
pub struct AuthState {
    pub settings: WebSettings,
    pub active_listen: SocketAddr,
    pub path: PathBuf,
    sessions: HashMap<String, Instant>,
    attempts: VecDeque<Instant>,
}
impl AuthState {
    pub fn new(settings: WebSettings, active_listen: SocketAddr, path: PathBuf) -> Self {
        Self {
            settings,
            active_listen,
            path,
            sessions: HashMap::new(),
            attempts: VecDeque::new(),
        }
    }
    pub fn session_valid(&mut self, session: &str) -> bool {
        self.sessions.retain(|_, expiry| *expiry > Instant::now());
        self.sessions.contains_key(session)
    }
    pub fn new_session(&mut self) -> String {
        self.sessions.retain(|_, expiry| *expiry > Instant::now());
        if self.sessions.len() >= 128 {
            self.sessions.clear();
        }
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        self.sessions
            .insert(token.clone(), Instant::now() + Duration::from_secs(86400));
        token
    }
    pub fn logout(&mut self, session: &str) {
        self.sessions.remove(session);
    }
    pub fn clear_sessions(&mut self) {
        self.sessions.clear();
    }
    pub fn allow_attempt(&mut self) -> bool {
        self.attempts
            .retain(|time| time.elapsed() < Duration::from_secs(60));
        if self.attempts.len() >= 10 {
            return false;
        }
        self.attempts.push_back(Instant::now());
        true
    }
}
pub fn validate_account(username: &str, password: &str) -> Result<(), String> {
    if username.trim() != username
        || username.is_empty()
        || username.len() > 64
        || username.chars().any(char::is_control)
    {
        return Err(
            "Username must be 1..64 bytes without surrounding whitespace or control characters"
                .into(),
        );
    }
    if password.len() < 8 || password.len() > 128 {
        return Err("Password must be 8..128 bytes".into());
    }
    Ok(())
}
pub async fn hash_password(password: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
            .map_err(|_| "Cannot generate password salt".to_owned())?;
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| "Cannot hash password".to_owned())
    })
    .await
    .map_err(|_| "Password hashing failed".to_owned())?
}
pub async fn verify_password(hash: String, password: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash).is_ok_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
    })
    .await
    .unwrap_or(false)
}
