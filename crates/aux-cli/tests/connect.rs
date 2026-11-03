//! `aux connect google` end to end, offline: argument parsing and the
//! `--status` report. No network, no browser, no real `~/.auxesis`.
//!
//! The status line is the one the owner reads: it must name the state and
//! nothing else — never the client id, the client secret or an email address.

// MA4: the Google connect surface exists only with the `google` feature.
#![cfg(feature = "google")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

const CLIENT_ID: &str = "desktop-client-id.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "client-secret-canary";
const EMAIL: &str = "alex@example.test";

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

struct Sandbox {
    _tmp: TempDir,
    user_home: PathBuf,
    aux_home: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let user_home = tmp.path().join("user-home");
        let aux_home = tmp.path().join("auxesis-home");
        for dir in [&user_home, &aux_home] {
            fs::create_dir_all(dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        Self {
            _tmp: tmp,
            user_home,
            aux_home,
        }
    }

    /// Write the two client settings exactly like the setup guide does.
    fn write_credentials(&self, client_id: &str, client_secret: &str) {
        let env_file = self.aux_home.join(".env");
        fs::write(
            &env_file,
            format!(
                "AUXESIS_GOOGLE_CLIENT_ID={client_id}\nAUXESIS_GOOGLE_CLIENT_SECRET={client_secret}\n"
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&env_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// Pretend the consent flow already stored the grant for `client_id`.
    fn write_grant(&self, client_id: &str) {
        let key = aux_google::mac_account_key(client_id);
        fs::write(
            self.aux_home.join(format!("google-auth-{key}.json")),
            b"{\"version\":1}",
        )
        .unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(aux_bin())
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", &self.user_home)
            .env("AUXESIS_HOME", &self.aux_home)
            .env("AUXESIS_SANDBOX", "1")
            .env("AUXESIS_API_PORT", "0")
            .output()
            .expect("run aux")
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn connect_google_status_reports_disconnected_with_exit_failure() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["connect", "google", "--status"]);
    let output_text = text(&output);
    assert!(
        output_text.contains("Google: not connected"),
        "unexpected status line: {output_text}"
    );
    assert!(!output.status.success());
}

#[test]
fn connect_google_status_reports_connected_without_naming_a_secret_or_an_email() {
    let sandbox = Sandbox::new();
    sandbox.write_credentials(CLIENT_ID, CLIENT_SECRET);
    sandbox.write_grant(CLIENT_ID);

    let output = sandbox.run(&["connect", "google", "--status"]);
    let output_text = text(&output);
    assert!(
        output_text.contains("Google: connected"),
        "unexpected status line: {output_text}"
    );
    assert!(output.status.success());

    // The whole point of the flag: the state, and nothing else.
    for canary in [
        CLIENT_ID,
        CLIENT_SECRET,
        EMAIL,
        "apps.googleusercontent.com",
    ] {
        assert!(
            !output_text.contains(canary),
            "status leaked `{canary}`: {output_text}"
        );
    }
}

#[test]
fn connect_google_status_is_honest_when_only_another_client_ids_grant_exists() {
    let sandbox = Sandbox::new();
    sandbox.write_credentials(CLIENT_ID, CLIENT_SECRET);
    sandbox.write_grant("another-client-id.apps.googleusercontent.com");

    let output = sandbox.run(&["connect", "google", "--status"]);
    let output_text = text(&output);
    assert!(
        output_text.contains("Google: not connected"),
        "a grant for a different client must read as disconnected: {output_text}"
    );
    assert!(!output.status.success());
}

#[test]
fn connect_google_argument_parsing_accepts_status_and_disconnect_but_not_both() {
    let sandbox = Sandbox::new();

    let help = sandbox.run(&["connect", "google", "--help"]);
    assert!(help.status.success());
    let help_text = text(&help);
    for flag in ["--status", "--disconnect"] {
        assert!(
            help_text.contains(flag),
            "help must document {flag}: {help_text}"
        );
    }

    let conflict = sandbox.run(&["connect", "google", "--status", "--disconnect"]);
    assert!(
        !conflict.status.success(),
        "the two flags cannot be asked for at once"
    );

    let unknown = sandbox.run(&["connect", "google", "--nope"]);
    assert!(!unknown.status.success());

    let unknown_service = sandbox.run(&["connect", "outlook"]);
    assert!(!unknown_service.status.success());
}

/// The help text names Google only: no host, no port, no internal identifier.
#[test]
fn connect_google_help_never_names_an_internal_route() {
    let sandbox = Sandbox::new();
    let help = sandbox.run(&["connect", "--help"]);
    assert!(help.status.success());
    let help_text = text(&help);
    assert!(help_text.contains("google"), "unexpected help: {help_text}");
    for internal in ["127.0.0.1", "2893", ".env", "client_secret"] {
        assert!(!help_text.contains(internal), "help leaked {internal}");
    }
}

/// `--status` never opens a browser: the run must not reach a network listener
/// even when nothing is configured, and must return promptly.
#[test]
fn connect_google_status_never_starts_a_flow() {
    let sandbox = Sandbox::new();
    let started = std::time::Instant::now();
    let output = sandbox.run(&["connect", "google", "--status"]);
    assert!(!output.status.success());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "status must not wait for a consent flow"
    );
}
