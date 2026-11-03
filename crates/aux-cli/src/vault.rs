//! `aux secret` — secret management. The only sink is `~/.auxesis/.env`
//! (0600, via the verified-home write gateway, recoverable, never
//! committed). Values are read from stdin, so they never appear in shell
//! history or process arguments.
//!
//! There is no Keychain *write* path (P2/KC-01): `security
//! add-generic-password` took the value on the command line and created
//! items readable by any process (`-A`), so `aux secret set` never touches
//! the Keychain. Keychain *reads* exist only for the `check --keychain`
//! probe and are default-deny (`AUXESIS_ALLOW_KEYCHAIN=1` opt-in).

use std::io::BufRead;

/// Keychain service used by Auxesis.
pub const SERVICE: &str = "auxesis";

/// Trim a secret line: drop the trailing newline, reject blank input and any
/// value that still carries a newline or another control character.
///
/// The daemon applies the same rule before it stores a key
/// (`aux_providers::set_named_in_env_file`): a value with an embedded control
/// byte would corrupt the `.env` line or smuggle a second entry, so it is
/// refused here too. The value is never echoed back in the error.
fn parse_secret(raw: &str) -> Option<String> {
    let value = raw.trim_end_matches(['\n', '\r']);
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_string())
    }
}

/// Read a secret value from stdin (shared by the Keychain and `.env` sinks).
pub fn read_from_stdin() -> Result<String, String> {
    let mut raw = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut raw)
        .map_err(|err| format!("reading secret from stdin: {err}"))?;
    parse_secret(&raw).ok_or_else(|| {
        "no secret provided on stdin (blank or containing a control character)".to_string()
    })
}

/// Run `security` with a hard 5-second timeout (NF4-04).
///
/// Every Keychain access goes through [`kernel_core::keychain::run_security`],
/// the single allowlisted spawner: when [`kernel_core::keychain::keychain_allowed`]
/// is false (tests, the sandbox guard, a scratch HOME) it returns an error
/// without touching the owner's Keychain.
#[cfg(target_os = "macos")]
fn run_security(args: &[&str]) -> Result<std::process::Output, String> {
    kernel_core::keychain::run_security(args)
}

/// Read the `.env` file with regular-file + size guards (NF5-02).
fn read_env_file(home: &std::path::Path) -> Result<Option<String>, String> {
    const MAX_ENV_BYTES: u64 = 1024 * 1024;
    let path = home.join(aux_providers::ENV_FILE);
    match std::fs::metadata(&path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(format!("{} is not a regular file", path.display()));
            }
            if meta.len() > MAX_ENV_BYTES {
                return Err(format!("{} is too large", path.display()));
            }
            std::fs::read_to_string(&path)
                .map(Some)
                .map_err(|err| format!("reading {}: {err}", path.display()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("reading {}: {err}", path.display())),
    }
}

/// Upsert `AUX_KEY_<ID>=value` in `<home>/.env` (mode 0600).
///
/// This is the headless source: the same daemon binary can run on a Linux
/// server or a launchd agent with no Keychain available.
pub fn set_in_env_file(
    home: &std::path::Path,
    provider_id: &str,
    value: &str,
) -> Result<(), String> {
    let name = aux_providers::env_var_name(provider_id);

    // Serialize the read-modify-write against the daemon (which writes the
    // same `.env` while saving a provider key) with the shared
    // `<home>/.config.lock` file lock: a CLI write based on a stale read must
    // not erase a key the daemon just saved (security review P2).
    kernel_core::with_config_lock(home, || {
        let mut lines: Vec<String> = read_env_file(home)?
            .map(|text| text.lines().map(str::to_string).collect())
            .unwrap_or_default();
        let prefix = format!("{name}=");
        lines.retain(|line| !line.trim_start().starts_with(&prefix));
        lines.push(format!("{name}={value}"));

        let mut text = lines.join("\n");
        text.push('\n');
        // J-02 write gateway: the `.env` file is written relative to the
        // verified home directory fd, never through the home path string;
        // `O_NOFOLLOW` refuses a symlink at the file name. The write is an
        // atomic replace (temp file + rename): a crash mid-write never leaves
        // a truncated `.env` that loses the other keys (security review P2, #136).
        let handle = kernel_core::SandboxHome::open(home)
            .map_err(|err| format!("opening {}: {err}", home.display()))?;
        handle
            .write_atomic(
                std::path::Path::new(aux_providers::ENV_FILE),
                text.as_bytes(),
                0o600,
            )
            .map_err(|err| {
                format!(
                    "writing {}: {err}",
                    home.join(aux_providers::ENV_FILE).display()
                )
            })
    })
    .map_err(|err| format!("acquiring the configuration lock: {err}"))?
}

/// Whether `AUX_KEY_<ID>` exists in `<home>/.env`.
pub fn env_file_has(home: &std::path::Path, provider_id: &str) -> bool {
    let name = aux_providers::env_var_name(provider_id);
    let prefix = format!("{name}=");
    read_env_file(home)
        .ok()
        .flatten()
        .map(|text| {
            text.lines()
                .any(|line| line.trim_start().starts_with(&prefix))
        })
        .unwrap_or(false)
}

/// Whether a secret exists for `account`. The value is never printed.
pub fn exists(account: &str) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        if !kernel_core::keychain::keychain_allowed() {
            // No Keychain in this context: report "not found" without
            // spawning anything (the `.env`/environment fallbacks still work).
            return Ok(false);
        }
        let output = run_security(&["find-generic-password", "-s", SERVICE, "-a", account])?;
        Ok(output.status.success())
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = account;
        Err("the Keychain is macOS-only; use AUX_KEY_<ID> env vars on this platform".to_string())
    }
}

/// Remove `AUX_KEY_*` variables from this process environment.
///
/// Called after key material has been loaded (Keychain or env), so a child
/// process reading our environment (`ps eww`) can never see it. The
/// implementation lives in `aux-engine` so the daemon shares it too.
pub fn scrub_process_key_env() {
    aux_engine::scrub_process_key_env()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_secret_trims_trailing_newlines() {
        assert_eq!(parse_secret("sk-abc\n").as_deref(), Some("sk-abc"));
        assert_eq!(parse_secret("sk-abc\r\n").as_deref(), Some("sk-abc"));
    }

    #[test]
    fn parse_secret_rejects_blank_input() {
        assert_eq!(parse_secret(""), None);
        assert_eq!(parse_secret("   \n"), None);
    }

    #[test]
    fn parse_secret_keeps_inner_whitespace() {
        assert_eq!(parse_secret("a b c\n").as_deref(), Some("a b c"));
    }

    #[test]
    fn parse_secret_rejects_control_characters() {
        // An embedded newline or carriage return would corrupt the `.env` line.
        assert_eq!(parse_secret("sk-abc\ndef"), None);
        assert_eq!(parse_secret("sk-abc\rdef"), None);
        assert_eq!(parse_secret("sk-\u{7}abc\n"), None);
        assert_eq!(parse_secret("sk-abc\u{1b}[31m\n"), None);
        assert_eq!(parse_secret("sk-\u{7f}abc\n"), None);
        // A plain trailing newline/CRLF is still trimmed, not rejected.
        assert_eq!(parse_secret("sk-abc\n").as_deref(), Some("sk-abc"));
    }

    #[test]
    fn process_key_env_is_scrubbed() {
        std::env::set_var("AUX_KEY_SCRUB_TEST", "canary");
        scrub_process_key_env();
        assert!(std::env::var("AUX_KEY_SCRUB_TEST").is_err());
    }

    #[test]
    fn env_file_upsert_round_trips_and_preserves_others() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();

        set_in_env_file(home, "deepseek", "sk-one").unwrap();
        set_in_env_file(home, "openrouter", "sk-two").unwrap();
        set_in_env_file(home, "deepseek", "sk-updated").unwrap();

        let text = std::fs::read_to_string(home.join(".env")).unwrap();
        assert!(text.contains("AUX_KEY_DEEPSEEK=sk-updated"));
        assert!(text.contains("AUX_KEY_OPENROUTER=sk-two"));
        assert_eq!(text.matches("AUX_KEY_DEEPSEEK=").count(), 1);
        assert!(env_file_has(home, "deepseek"));
        assert!(!env_file_has(home, "missing"));
    }

    #[cfg(unix)]
    #[test]
    fn env_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        set_in_env_file(dir.path(), "deepseek", "sk").unwrap();

        let mode = std::fs::metadata(dir.path().join(".env"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "the .env must be 0600");
    }

    /// Security review P2: the CLI writer (`aux secret set`) and the daemon writer
    /// (`aux_providers::set_in_env_file`, the provider key path) share the
    /// same `<home>/.config.lock`. Two threads that each open their own lock
    /// descriptor exercise `flock` (per open file description, not per
    /// process); a write based on a stale read used to erase the other's key.
    #[test]
    fn cli_and_daemon_writers_share_the_config_lock() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        const PER_WRITER: usize = 200;

        let cli_home = home.clone();
        let cli = std::thread::spawn(move || {
            for index in 0..PER_WRITER {
                let id = format!("cli-{index}");
                set_in_env_file(&cli_home, &id, &format!("v{index}")).unwrap();
            }
        });
        let daemon_home = home.clone();
        let daemon = std::thread::spawn(move || {
            for index in 0..PER_WRITER {
                let id = format!("daemon-{index}");
                aux_providers::set_in_env_file(&daemon_home, &id, &format!("d{index}")).unwrap();
            }
        });
        cli.join().unwrap();
        daemon.join().unwrap();

        let text = std::fs::read_to_string(home.join(".env")).unwrap();
        for index in 0..PER_WRITER {
            assert!(
                text.contains(&format!("AUX_KEY_CLI_{index}=v{index}")),
                "CLI key {index} was erased by a concurrent writer"
            );
            assert!(
                text.contains(&format!("AUX_KEY_DAEMON_{index}=d{index}")),
                "daemon key {index} was erased by a concurrent writer"
            );
        }
        let lines = text
            .lines()
            .filter(|line| line.starts_with("AUX_KEY_"))
            .count();
        assert_eq!(
            lines,
            PER_WRITER * 2,
            "exactly one line per key must remain"
        );
    }
}
