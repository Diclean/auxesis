//! API key resolution: macOS Keychain first, environment fallback second.
//!
//! Config files only ever hold a `key_user` reference (the Keychain account).
//! The service is always [`KEYCHAIN_SERVICE`]. For development and tests the
//! environment variable `AUX_KEY_<UPPER_ID>` is used **only when the Keychain
//! has no entry** — an environment variable never overrides a Keychain value.

use thiserror::Error;

/// Keychain service name for every Auxesis secret.
pub const KEYCHAIN_SERVICE: &str = "auxesis";

/// Environment variable prefix for the development fallback.
pub const ENV_PREFIX: &str = "AUX_KEY_";

/// File name of the headless secret store, under the Auxesis home.
pub const ENV_FILE: &str = ".env";

/// Permission bits the `.env` file must not grant to group or others.
const ENV_FILE_DENIED_BITS: u32 = 0o077;

/// A `.env` secret file that group or other users can read or write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileModeWarning {
    /// Path of the offending file.
    pub path: std::path::PathBuf,
    /// The observed permission bits (`mode & 0o777`).
    pub mode: u32,
}

impl EnvFileModeWarning {
    /// The command that fixes the mode.
    pub fn fix(&self) -> String {
        format!("chmod 600 {}", self.path.display())
    }

    /// One line naming the file and the fix.
    ///
    /// Building it only stats the file, so it can never carry a key value.
    pub fn message(&self) -> String {
        format!(
            "{} is accessible to other users (mode {:03o}); run `{}`",
            self.path.display(),
            self.mode,
            self.fix()
        )
    }
}

/// Inspect the mode of a `.env` file without reading its contents.
///
/// `None` means the file is missing, is not a regular file (the loaders
/// report that separately), or is private to its owner. Unlike the store's
/// `keys/` files, a shared `.env` is not refused: a working setup keeps
/// working, but the owner is warned and `aux doctor` reports it.
#[cfg(unix)]
pub fn env_file_mode_warning(path: &std::path::Path) -> Option<EnvFileModeWarning> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mode = meta.permissions().mode() & 0o777;
    (mode & ENV_FILE_DENIED_BITS != 0).then(|| EnvFileModeWarning {
        path: path.to_path_buf(),
        mode,
    })
}

/// Non-Unix platforms carry no POSIX mode bits, so there is nothing to warn about.
#[cfg(not(unix))]
pub fn env_file_mode_warning(_path: &std::path::Path) -> Option<EnvFileModeWarning> {
    None
}

static ENV_FILE_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Log the `.env` mode warning once per process.
///
/// Key resolution loads the file on almost every provider call, so repeating
/// the warning would flood the log. Returns whether this call emitted it.
pub fn warn_env_file_mode_once(path: &std::path::Path) -> bool {
    warn_env_file_mode_once_with(path, &ENV_FILE_WARNED)
}

fn warn_env_file_mode_once_with(
    path: &std::path::Path,
    warned: &std::sync::atomic::AtomicBool,
) -> bool {
    let Some(warning) = env_file_mode_warning(path) else {
        return false;
    };
    if warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return false;
    }
    // auxd installs a tracing subscriber (its launchd log); the CLI does not,
    // so fall back to stderr there. Either way the message names the file and
    // the fix, never a value from it.
    if tracing::enabled!(tracing::Level::WARN) {
        tracing::warn!("{}", warning.message());
    } else {
        eprintln!("warning: {}", warning.message());
    }
    true
}

/// Errors while looking up a secret.
#[derive(Debug, Error)]
pub enum KeyError {
    /// The Keychain could not be queried.
    #[error("keychain lookup failed for account `{account}`: {message}")]
    Keychain {
        /// Keychain account that was queried.
        account: String,
        /// Platform error message.
        message: String,
    },
    /// The headless `.env` file could not be read.
    #[error("env file `{path}`: {message}")]
    File {
        /// Path of the offending file.
        path: String,
        /// Human-readable failure.
        message: String,
    },
}

/// A place secrets can be read from.
///
/// Production uses [`KeychainStore`]; tests inject an in-memory store to
/// verify the resolution order without touching the real Keychain.
pub trait SecretStore: Send + Sync {
    /// Return the secret stored for `(service, account)`, or `None` when the
    /// entry does not exist.
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, KeyError>;
}

/// The macOS Keychain backed store (service `auxesis`).
///
/// Reads go through the `security` CLI (with a hard timeout) instead of the
/// keyring crate: it is the same, prompt-free path `aux secret` uses, and it
/// can never block the daemon on a silent XPC call.
///
/// On non-macOS platforms (Linux CI) this store always reports "no entry", so
/// the `.env` and environment fallbacks keep working.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeychainStore;

impl KeychainStore {
    /// Create a Keychain store.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl SecretStore for KeychainStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, KeyError> {
        let key_err = |message: String| KeyError::Keychain {
            account: account.to_string(),
            message,
        };

        if !kernel_core::keychain::keychain_allowed() {
            // Tests, the sandbox guard or a scratch HOME: report "no entry"
            // without spawning `security` (the `.env` fallback still works).
            return Ok(None);
        }

        let output = kernel_core::keychain::run_security(&[
            "find-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
        ])
        .map_err(key_err)?;

        if output.status.success() {
            let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
            return Ok(if secret.is_empty() {
                None
            } else {
                Some(secret)
            });
        }
        // Exit code 44 is `errSecItemNotFound`: simply no entry.
        if output.status.code() == Some(44) {
            return Ok(None);
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(key_err(format!(
            "`security` failed ({}): {stderr}",
            output.status
        )))
    }
}

#[cfg(not(target_os = "macos"))]
impl SecretStore for KeychainStore {
    fn get(&self, _service: &str, _account: &str) -> Result<Option<String>, KeyError> {
        Ok(None)
    }
}

/// `.env`-style secret store for headless deployments (Linux servers,
/// launchd daemons): `$AUXESIS_HOME/.env`, mode `0600`, never committed.
///
/// Format — the same variable names the process environment would use:
/// ```dotenv
/// AUX_KEY_DEEPSEEK=sk-...
/// ```
#[derive(Debug, Clone, Default)]
pub struct AgentEnvStore {
    vars: std::collections::BTreeMap<String, String>,
}

impl AgentEnvStore {
    /// Default path: `$AUXESIS_HOME/.env`.
    pub fn default_path() -> std::path::PathBuf {
        kernel_core::auxesis_home().join(ENV_FILE)
    }

    /// Load the default file; a missing file yields an empty store.
    pub fn load_default() -> Result<Self, KeyError> {
        Self::load(&Self::default_path())
    }

    /// Load a file; a missing file yields an empty store.
    ///
    /// Refuses non-regular files (FIFOs, devices) and oversized files so a
    /// broken `.env` can never hang or exhaust the daemon (NF4-02).
    pub fn load(path: &std::path::Path) -> Result<Self, KeyError> {
        const MAX_ENV_BYTES: u64 = 1024 * 1024;
        match std::fs::metadata(path) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(KeyError::File {
                        path: path.display().to_string(),
                        message: "not a regular file".to_string(),
                    });
                }
                if meta.len() > MAX_ENV_BYTES {
                    return Err(KeyError::File {
                        path: path.display().to_string(),
                        message: format!("file too large ({} bytes)", meta.len()),
                    });
                }
                let text = std::fs::read_to_string(path).map_err(|err| KeyError::File {
                    path: path.display().to_string(),
                    message: err.to_string(),
                })?;
                // A shared mode does not make the keys unusable, so the file
                // is still loaded; the warning is the fix, not a refusal.
                warn_env_file_mode_once(path);
                Ok(Self {
                    vars: parse_dotenv(&text),
                })
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(KeyError::File {
                path: path.display().to_string(),
                message: err.to_string(),
            }),
        }
    }

    /// Look up a variable, exactly as the process environment would.
    pub fn get_var(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }
}

/// Split one `.env` line into `(key, value)`, matching on the *parsed* key so
/// an `export` prefix and whitespace around `=` are tolerated: blanks and `#`
/// comments yield `None`, as do lines with an empty key or no `=`.
///
/// The value keeps its surrounding whitespace trimmed but its quotes; callers
/// that need the unquoted value strip them.
fn dotenv_entry(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, value.trim()))
}

/// Parse `KEY=value` lines: blanks and `#` comments ignored, optional
/// `export` prefix and surrounding single/double quotes tolerated.
fn parse_dotenv(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut vars = std::collections::BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = dotenv_entry(line) else {
            continue;
        };
        let mut value = value;
        let quoted = value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')));
        if quoted {
            value = &value[1..value.len() - 1];
        }
        vars.insert(key.to_string(), value.to_string());
    }
    vars
}

/// Read `<home>/.env` as raw text, with regular-file + size guards.
///
/// A missing file is `None`; anything unreadable is an error so a write never
/// silently drops the owner's other variables.
fn read_env_text(home: &std::path::Path) -> Result<Option<String>, KeyError> {
    const MAX_ENV_BYTES: u64 = 1024 * 1024;
    let path = home.join(ENV_FILE);
    match std::fs::metadata(&path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(KeyError::File {
                    path: path.display().to_string(),
                    message: "not a regular file".to_string(),
                });
            }
            if meta.len() > MAX_ENV_BYTES {
                return Err(KeyError::File {
                    path: path.display().to_string(),
                    message: format!("file too large ({} bytes)", meta.len()),
                });
            }
            warn_env_file_mode_once(&path);
            std::fs::read_to_string(&path)
                .map(Some)
                .map_err(|err| KeyError::File {
                    path: path.display().to_string(),
                    message: err.to_string(),
                })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(KeyError::File {
            path: path.display().to_string(),
            message: err.to_string(),
        }),
    }
}

/// Upsert `AUX_KEY_<UPPER_ID>=value` in `<home>/.env` (mode `0600`).
///
/// The write is **atomic** (sibling temp file + `renameat` in the verified
/// home directory fd) and never follows a symlink at the `.env` name. Every
/// other variable in the file is preserved; an existing value for this
/// provider id is replaced in place, so a repeated save leaves exactly one
/// line. The value is never logged.
pub fn set_in_env_file(
    home: &std::path::Path,
    provider_id: &str,
    value: &str,
) -> Result<(), KeyError> {
    let name = env_var_name(provider_id);
    set_named_in_env_file(home, &name, value)
}

/// Upsert a specifically named secret in the protected `.env` store. Names
/// are restricted to uppercase environment identifiers; the value is never
/// logged or included in an error.
pub fn set_named_in_env_file(
    home: &std::path::Path,
    name: &str,
    value: &str,
) -> Result<(), KeyError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || value.contains('\n')
        || value.contains('\r')
    {
        return Err(KeyError::File {
            path: home.join(ENV_FILE).display().to_string(),
            message: "invalid secret entry".to_string(),
        });
    }
    // Serialize the whole read-modify-write against every other process
    // (the daemon's API, the CLI `aux secret set`) with the shared
    // `<home>/.config.lock` file lock: without it a writer that read the file
    // before another saved a key would rewrite the stale text and erase that
    // key (security review P2).
    kernel_core::with_config_lock(home, || {
        let mut lines: Vec<String> = read_env_text(home)?
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default();
        // Match on the parsed key, not a raw prefix: a previous value written
        // as `export AUX_KEY_X=...` or `AUX_KEY_X = ...` is replaced too, so
        // exactly one line remains and no old secret stays at rest.
        lines.retain(|line| match dotenv_entry(line) {
            Some((key, _)) => key != name,
            None => true,
        });
        lines.push(format!("{name}={value}"));
        let mut text = lines.join("\n");
        text.push('\n');

        // J-02 write gateway: the `.env` file is written relative to the
        // verified home directory fd, never through the home path string; the
        // atomic temp+rename never leaves a half-written file, and the open
        // refuses a symlink at the file name.
        let handle = kernel_core::SandboxHome::open(home).map_err(|err| KeyError::File {
            path: home.display().to_string(),
            message: format!("opening home: {err}"),
        })?;
        handle
            .write_atomic(std::path::Path::new(ENV_FILE), text.as_bytes(), 0o600)
            .map_err(|err| KeyError::File {
                path: home.join(ENV_FILE).display().to_string(),
                message: format!("writing: {err}"),
            })
    })
    .map_err(|err| KeyError::File {
        path: home.join(ENV_FILE).display().to_string(),
        message: format!("config lock: {err}"),
    })?
}

/// Environment variable name for a provider id: `AUX_KEY_<UPPER_ID>`.
///
/// Every character that is not ASCII alphanumeric becomes `_`, so ids like
/// `my-provider` map to `AUX_KEY_MY_PROVIDER`.
pub fn env_var_name(provider_id: &str) -> String {
    let mut name = String::from(ENV_PREFIX);
    for ch in provider_id.chars() {
        if ch.is_ascii_alphanumeric() {
            name.push(ch.to_ascii_uppercase());
        } else {
            name.push('_');
        }
    }
    name
}

/// Resolve the API key for a provider using the real stores.
///
/// Order: macOS Keychain → `$AUXESIS_HOME/.env` → `AUX_KEY_<UPPER_ID>`
/// process environment. Returns `Ok(None)` when no source has a non-empty
/// secret. The process environment is deliberately **last**: on macOS its
/// exec-time snapshot is readable by any same-uid process for the lifetime
/// of the program (`ps eww`), so exported keys are discouraged.
pub fn resolve_key(provider_id: &str, key_user: Option<&str>) -> Result<Option<String>, KeyError> {
    let keychain = KeychainStore::new();
    let env_file = AgentEnvStore::load_default()?;
    resolve_key_full(&keychain, &env_file, provider_id, key_user, |name| {
        std::env::var(name).ok()
    })
}

/// [`resolve_key`] with injectable stores and environment lookup.
///
/// Order: non-empty Keychain entry → non-empty `.env` entry → non-empty
/// `AUX_KEY_<UPPER_ID>` process environment. Store *errors* propagate instead
/// of silently falling back, so a locked Keychain stays visible. Empty strings
/// count as missing.
pub fn resolve_key_full<F>(
    store: &dyn SecretStore,
    env_file: &AgentEnvStore,
    provider_id: &str,
    key_user: Option<&str>,
    env: F,
) -> Result<Option<String>, KeyError>
where
    F: FnOnce(&str) -> Option<String>,
{
    let account = key_user.filter(|account| !account.trim().is_empty());

    // A Keychain *error* (locked, timeout, ...) must not veto the alternate
    // sources: remember it and surface it only if no source has a key
    // (NF4-05).
    let mut keychain_error: Option<KeyError> = None;
    if let Some(account) = account {
        match store.get(KEYCHAIN_SERVICE, account) {
            Ok(Some(secret)) if !secret.is_empty() => return Ok(Some(secret)),
            Ok(_) => {}
            Err(err) => keychain_error = Some(err),
        }
    }

    let var_name = env_var_name(provider_id);
    if let Some(value) = env_file.get_var(&var_name) {
        if !value.is_empty() {
            return Ok(Some(value.to_string()));
        }
    }

    if let Some(value) = env(&var_name) {
        if !value.is_empty() {
            return Ok(Some(value));
        }
    }

    if let Some(err) = keychain_error {
        return Err(err);
    }
    Ok(None)
}

/// [`resolve_key_full`] without the `.env` fallback (kept for callers that
/// only have a single store, and for the historical tests).
pub fn resolve_key_with<F>(
    store: &dyn SecretStore,
    provider_id: &str,
    key_user: Option<&str>,
    env: F,
) -> Result<Option<String>, KeyError>
where
    F: FnOnce(&str) -> Option<String>,
{
    resolve_key_full(store, &AgentEnvStore::default(), provider_id, key_user, env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeStore {
        secret: Option<String>,
        fail: bool,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl SecretStore for FakeStore {
        fn get(&self, service: &str, account: &str) -> Result<Option<String>, KeyError> {
            self.calls
                .lock()
                .unwrap()
                .push((service.to_string(), account.to_string()));
            if self.fail {
                return Err(KeyError::Keychain {
                    account: account.to_string(),
                    message: "keychain locked".to_string(),
                });
            }
            Ok(self.secret.clone())
        }
    }

    #[test]
    fn env_var_name_uppercases_and_sanitizes() {
        assert_eq!(env_var_name("deepseek"), "AUX_KEY_DEEPSEEK");
        assert_eq!(env_var_name("acme-lfm"), "AUX_KEY_ACME_LFM");
        assert_eq!(env_var_name("openrouter.chat"), "AUX_KEY_OPENROUTER_CHAT");
        assert_eq!(env_var_name("v2"), "AUX_KEY_V2");
    }

    #[test]
    fn keychain_wins_over_environment() {
        let store = FakeStore {
            secret: Some("chain-secret".into()),
            ..FakeStore::default()
        };
        let key = resolve_key_with(&store, "deepseek", Some("deepseek"), |_| {
            Some("env-secret".into())
        })
        .unwrap();
        assert_eq!(key.as_deref(), Some("chain-secret"));
        assert_eq!(
            store.calls.lock().unwrap().as_slice(),
            [("auxesis".to_string(), "deepseek".to_string())]
        );
    }

    #[test]
    fn environment_used_when_keychain_misses() {
        let store = FakeStore::default();
        let key = resolve_key_with(&store, "deepseek", Some("deepseek"), |_| {
            Some("env-secret".into())
        })
        .unwrap();
        assert_eq!(key.as_deref(), Some("env-secret"));
    }

    #[test]
    fn environment_used_when_key_user_is_absent() {
        let store = FakeStore {
            secret: Some("unused".into()),
            ..FakeStore::default()
        };
        let key =
            resolve_key_with(&store, "lmstudio", None, |_| Some("env-secret".into())).unwrap();
        assert_eq!(key.as_deref(), Some("env-secret"));
        assert!(store.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn environment_used_when_keychain_value_is_empty() {
        let store = FakeStore {
            secret: Some(String::new()),
            ..FakeStore::default()
        };
        let key = resolve_key_with(&store, "deepseek", Some("deepseek"), |_| {
            Some("env-secret".into())
        })
        .unwrap();
        assert_eq!(key.as_deref(), Some("env-secret"));
    }

    #[test]
    fn no_key_when_both_sources_miss() {
        let store = FakeStore::default();
        let key = resolve_key_with(&store, "deepseek", Some("deepseek"), |_| None).unwrap();
        assert_eq!(key, None);
    }

    #[test]
    fn empty_environment_value_counts_as_missing() {
        let store = FakeStore::default();
        let key = resolve_key_with(
            &store,
            "deepseek",
            Some("deepseek"),
            |_| Some(String::new()),
        )
        .unwrap();
        assert_eq!(key, None);
    }

    #[test]
    fn keychain_errors_fall_back_when_another_source_has_a_key() {
        let store = FakeStore {
            fail: true,
            ..FakeStore::default()
        };
        let file = AgentEnvStore {
            vars: parse_dotenv("AUX_KEY_DEEPSEEK=file-secret\n"),
        };
        let key = resolve_key_full(&store, &file, "deepseek", Some("deepseek"), |name| {
            Some(format!("env-{name}"))
        })
        .unwrap();
        assert_eq!(key.as_deref(), Some("file-secret"));

        let empty = AgentEnvStore::default();
        let key = resolve_key_full(&store, &empty, "deepseek", Some("deepseek"), |_| {
            Some("env-secret".into())
        })
        .unwrap();
        assert_eq!(key.as_deref(), Some("env-secret"));
    }

    #[test]
    fn keychain_errors_surface_when_no_other_source_has_a_key() {
        let store = FakeStore {
            fail: true,
            ..FakeStore::default()
        };
        let err = resolve_key_full(
            &store,
            &AgentEnvStore::default(),
            "deepseek",
            Some("deepseek"),
            |_| None,
        )
        .unwrap_err();
        assert!(matches!(err, KeyError::Keychain { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn dotenv_refuses_fifo_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join(".env");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo");
        assert!(status.success());
        let err = AgentEnvStore::load(&fifo).unwrap_err();
        assert!(matches!(err, KeyError::File { .. }));

        let big = dir.path().join("big.env");
        std::fs::write(&big, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        let err = AgentEnvStore::load(&big).unwrap_err();
        assert!(matches!(err, KeyError::File { .. }));
    }

    #[test]
    fn environment_name_is_built_from_provider_id_not_key_user() {
        let store = FakeStore::default();
        let requested = Mutex::new(None);
        let key = resolve_key_with(&store, "deepseek", Some("some-other-account"), |name| {
            *requested.lock().unwrap() = Some(name.to_string());
            None
        })
        .unwrap();
        assert_eq!(key, None);
        assert_eq!(
            requested.lock().unwrap().as_deref(),
            Some("AUX_KEY_DEEPSEEK")
        );
        assert_eq!(
            store.calls.lock().unwrap().as_slice(),
            [("auxesis".to_string(), "some-other-account".to_string())]
        );
    }

    #[test]
    fn dotenv_store_parses_lines() {
        let store = AgentEnvStore {
            vars: parse_dotenv(
                "# comment\nAUX_KEY_DEEPSEEK=\"sk-123\"\nexport AUX_KEY_OTHER='v' \n\nBAD LINE\n",
            ),
        };
        assert_eq!(store.get_var("AUX_KEY_DEEPSEEK"), Some("sk-123"));
        assert_eq!(store.get_var("AUX_KEY_OTHER"), Some("v"));
        assert_eq!(store.get_var("MISSING"), None);
    }

    #[test]
    fn dotenv_is_used_when_keychain_and_env_miss() {
        let keychain = FakeStore::default();
        let file = AgentEnvStore {
            vars: parse_dotenv("AUX_KEY_DEEPSEEK=from-file\n"),
        };
        let key =
            resolve_key_full(&keychain, &file, "deepseek", Some("deepseek"), |_| None).unwrap();
        assert_eq!(key.as_deref(), Some("from-file"));
    }

    #[test]
    fn keychain_and_dotenv_win_over_process_env() {
        let file = AgentEnvStore {
            vars: parse_dotenv("AUX_KEY_DEEPSEEK=from-file\n"),
        };

        let keychain = FakeStore {
            secret: Some("chain".into()),
            ..FakeStore::default()
        };
        let key = resolve_key_full(&keychain, &file, "deepseek", Some("deepseek"), |_| {
            Some("env".into())
        })
        .unwrap();
        assert_eq!(key.as_deref(), Some("chain"));

        let keychain = FakeStore::default();
        let key = resolve_key_full(&keychain, &file, "deepseek", Some("deepseek"), |_| {
            Some("env".into())
        })
        .unwrap();
        assert_eq!(
            key.as_deref(),
            Some("from-file"),
            "the .env beats the process env"
        );

        let empty_file = AgentEnvStore::default();
        let key = resolve_key_full(&keychain, &empty_file, "deepseek", Some("deepseek"), |_| {
            Some("env".into())
        })
        .unwrap();
        assert_eq!(
            key.as_deref(),
            Some("env"),
            "process env stays as the last resort"
        );
    }

    #[cfg(unix)]
    #[test]
    fn env_file_mode_warning_names_the_path_and_fix_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ENV_FILE);
        std::fs::write(&path, "AUX_KEY_DEEPSEEK=sk-CANARY-value\n").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(env_file_mode_warning(&path), None);

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let warning = env_file_mode_warning(&path).expect("a 0644 file must warn");
        assert_eq!(warning.mode & 0o777, 0o644);
        let message = warning.message();
        assert!(
            message.contains(&path.display().to_string()),
            "the file must be named: {message}"
        );
        assert!(
            message.contains(&format!("chmod 600 {}", path.display())),
            "the fix must be named: {message}"
        );
        assert!(
            !message.contains("CANARY"),
            "the warning must never carry a value: {message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn env_file_mode_warning_fires_once_per_process() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::AtomicBool;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ENV_FILE);
        std::fs::write(&path, "AUX_KEY_DEEPSEEK=from-file\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let warned = AtomicBool::new(false);
        assert!(
            warn_env_file_mode_once_with(&path, &warned),
            "the first read must warn"
        );
        assert!(
            !warn_env_file_mode_once_with(&path, &warned),
            "the second read must stay quiet"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_shared_dotenv_is_still_loaded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ENV_FILE);
        std::fs::write(&path, "AUX_KEY_DEEPSEEK=from-file\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let store = AgentEnvStore::load(&path).expect("a shared file is still used");
        assert_eq!(store.get_var("AUX_KEY_DEEPSEEK"), Some("from-file"));
    }

    #[test]
    fn dotenv_load_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = AgentEnvStore::load(&dir.path().join(".env")).unwrap();
        assert_eq!(store.get_var("AUX_KEY_X"), None);
    }

    #[test]
    fn set_in_env_file_upserts_preserves_others_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        set_in_env_file(home, "deepseek", "sk-one").unwrap();
        set_in_env_file(home, "openrouter", "sk-two").unwrap();
        set_in_env_file(home, "deepseek", "sk-updated").unwrap();

        let text = std::fs::read_to_string(home.join(ENV_FILE)).unwrap();
        assert!(text.contains("AUX_KEY_DEEPSEEK=sk-updated"), "{text}");
        assert!(text.contains("AUX_KEY_OPENROUTER=sk-two"), "{text}");
        assert_eq!(text.matches("AUX_KEY_DEEPSEEK=").count(), 1, "{text}");

        let store = AgentEnvStore::load(&home.join(ENV_FILE)).unwrap();
        assert_eq!(store.get_var("AUX_KEY_DEEPSEEK"), Some("sk-updated"));
        assert_eq!(store.get_var("AUX_KEY_OPENROUTER"), Some("sk-two"));
    }

    #[test]
    fn set_in_env_file_replaces_exported_and_spaced_lines() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::write(
            home.join(ENV_FILE),
            "export AUX_KEY_DEEPSEEK=old-export-value
AUX_KEY_DEEPSEEK = old-spaced-value
AUX_KEY_OTHER=keep-me
",
        )
        .unwrap();

        set_in_env_file(home, "deepseek", "new-value").unwrap();

        let text = std::fs::read_to_string(home.join(ENV_FILE)).unwrap();
        assert!(text.contains("AUX_KEY_DEEPSEEK=new-value"), "{text}");
        assert!(text.contains("AUX_KEY_OTHER=keep-me"), "{text}");
        assert_eq!(
            text.lines()
                .filter(
                    |line| matches!(dotenv_entry(line), Some((key, _)) if key == "AUX_KEY_DEEPSEEK")
                )
                .count(),
            1,
            "exactly one line must remain: {text}"
        );
        assert!(
            !text.contains("old-export-value"),
            "old secret left: {text}"
        );
        assert!(
            !text.contains("old-spaced-value"),
            "old secret left: {text}"
        );

        let store = AgentEnvStore::load(&home.join(ENV_FILE)).unwrap();
        assert_eq!(store.get_var("AUX_KEY_DEEPSEEK"), Some("new-value"));
        assert_eq!(store.get_var("AUX_KEY_OTHER"), Some("keep-me"));
    }

    #[cfg(unix)]
    #[test]
    fn set_in_env_file_is_private_and_leaves_no_temp() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::write(home.join(ENV_FILE), "AUX_KEY_OLD=keep-me\n").unwrap();
        set_in_env_file(home, "deepseek", "sk").unwrap();

        let mode = std::fs::metadata(home.join(ENV_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the .env must be 0600");
        // No half-written sibling temp survives a successful atomic write.
        let leftovers: Vec<_> = std::fs::read_dir(home)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
        let text = std::fs::read_to_string(home.join(ENV_FILE)).unwrap();
        assert!(text.contains("AUX_KEY_OLD=keep-me"), "{text}");
    }

    /// Security review P2: two writers each doing their own read-modify-write of `.env`
    /// in parallel must not erase each other's keys. Two threads that open
    /// their own lock descriptor are enough to exercise `flock` (the lock is
    /// per open file description, not per process).
    #[test]
    fn concurrent_writers_keep_every_key() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        const WRITERS: usize = 2;
        const PER_WRITER: usize = 200;

        let handles: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let home = home.clone();
                std::thread::spawn(move || {
                    for index in 0..PER_WRITER {
                        let id = format!("p{writer}-{index}");
                        set_in_env_file(&home, &id, &format!("sk-{writer}-{index}"))
                            .expect("the locked .env write must succeed");
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let store = AgentEnvStore::load(&home.join(ENV_FILE)).unwrap();
        for writer in 0..WRITERS {
            for index in 0..PER_WRITER {
                let id = format!("p{writer}-{index}");
                let name = env_var_name(&id);
                let expected = format!("sk-{writer}-{index}");
                assert_eq!(
                    store.get_var(&name),
                    Some(expected.as_str()),
                    "key {name} was lost by a concurrent writer"
                );
            }
        }
        let lines = std::fs::read_to_string(home.join(ENV_FILE))
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("AUX_KEY_"))
            .count();
        assert_eq!(
            lines,
            WRITERS * PER_WRITER,
            "exactly one line per key must remain"
        );
    }
}
