//! End-to-end tests of `aux doctor` in a throwaway Auxesis home.
//!
//! The doctor now also checks the pieces a first run needs (service, AI
//! services, agents), so these tests pin the probe to a dead local port and
//! assert the missing pieces are named with a next step.

use std::net::TcpListener;
use std::process::Stdio;
use tempfile::tempdir;

mod common;
use common::sandbox_command;

fn aux_bin() -> &'static str {
    env!("CARGO_BIN_EXE_aux")
}

/// A local port nothing listens on. Port 1 is privileged and unused in CI; a
/// bind-then-drop port could be taken by a parallel server.
fn dead_port() -> u16 {
    1
}

/// J-02 round 5: hermetic under any harness env — an explicit
/// `AUXESIS_API_PORT` is the sanctioned client form and works with the
/// sandbox guard active (unlike `AUXESIS_API`, which is refused).
fn doctor(home: &std::path::Path, api_port: u16) -> std::process::Output {
    let dir = home.parent().expect("home sits in the temp dir");
    sandbox_command(aux_bin(), dir, home)
        .arg("doctor")
        .env("AUXESIS_LANG", "en")
        .env("AUXESIS_API_PORT", api_port.to_string())
        .output()
        .expect("run aux doctor")
}

/// The doctor line of one named check: `[ok] providers …` or
/// `[fail] providers …`.
fn check_line(stdout: &str, name: &str) -> String {
    stdout
        .lines()
        .map(str::trim)
        .find(|line| {
            line.strip_prefix("[ok] ")
                .or_else(|| line.strip_prefix("[fail] "))
                .and_then(|rest| rest.strip_prefix(name))
                .is_some_and(|rest| rest.starts_with(' '))
        })
        .unwrap_or_else(|| panic!("no `{name}` line in:\n{stdout}"))
        .to_string()
}

/// DOCTOR-PROVIDERS-1: the daemon resolves its brain chain from
/// `providers.toml`, so the doctor must read that file and not the older
/// `config.toml`.
#[test]
fn doctor_reports_the_provider_of_the_file_the_daemon_reads() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("providers.toml"),
        "[[provider]]\nid = \"fake\"\nkind = \"fake\"\nmodels = [\"fake-echo\"]\n",
    )
    .unwrap();

    let stdout = String::from_utf8_lossy(&doctor(&home, 0).stdout).into_owned();
    let line = check_line(&stdout, "providers");
    assert!(
        line.starts_with("[ok] providers"),
        "the provider must be reported as configured:\n{stdout}"
    );
    assert!(
        line.contains("providers.toml"),
        "the doctor must name the file the daemon reads:\n{stdout}"
    );
}

/// DOCTOR-PROVIDERS-1: with no provider file at all the doctor says plainly
/// that no provider is configured, and names the file the daemon reads.
#[test]
fn doctor_says_no_provider_when_no_provider_file_exists() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");

    let stdout = String::from_utf8_lossy(&doctor(&home, 0).stdout).into_owned();
    let line = check_line(&stdout, "providers");
    assert!(
        line.starts_with("[fail] providers"),
        "no provider is configured:\n{stdout}"
    );
    assert!(
        line.contains("no AI service configured"),
        "the missing provider must be named:\n{stdout}"
    );
    assert!(
        line.contains("providers.toml"),
        "the doctor must name the file the daemon reads:\n{stdout}"
    );
}

/// DOCTOR-PROVIDERS-1: with only `config.toml` the doctor says where the
/// entries are and names the file the daemon reads.
#[test]
fn doctor_names_the_providers_file_when_only_config_toml_exists() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        concat!(
            "version = 1\n\n",
            "[[providers]]\nid = \"fake\"\nkind = \"fake\"\n",
            "base_url = \"http://127.0.0.1:9/v1\"\nmodel = \"fake-echo\"\n",
        ),
    )
    .unwrap();

    let stdout = String::from_utf8_lossy(&doctor(&home, 0).stdout).into_owned();
    let line = check_line(&stdout, "providers");
    assert!(
        line.contains("config.toml"),
        "the doctor must say where the entries are:\n{stdout}"
    );
    assert!(
        line.contains("providers.toml"),
        "the doctor must name the file the daemon reads:\n{stdout}"
    );
}

/// DOCTOR-PROVIDERS-1 r1: a `toml` parse error quotes the offending source
/// line, so a key pasted into `providers.toml` must never reach the terminal.
#[test]
fn doctor_never_echoes_a_key_pasted_in_the_provider_file() {
    // Two broken shapes a pasted key can take: a field the schema does not
    // know, and a string that is never closed.
    let broken = [
        concat!(
            "[[provider]]\nid = \"fake\"\nkind = \"fake\"\n",
            "api_key = \"sk-CANARY-1234567890abcdef\"\n",
        ),
        concat!(
            "[[provider]]\nid = \"fake\"\nkind = \"fake\"\n",
            "key = \"sk-CANARY-1234567890abcdef\n",
        ),
    ];
    for content in broken {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("providers.toml"), content).unwrap();

        let output = doctor(&home, 0);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stdout.contains("CANARY") && !stderr.contains("CANARY"),
            "the doctor echoed a key pasted in the file:\n{stdout}{stderr}"
        );
        assert!(
            stdout.contains("could not be read"),
            "the doctor must say the file could not be read:\n{stdout}"
        );
        assert!(
            stdout.contains("providers.toml"),
            "the doctor must name the file:\n{stdout}"
        );
    }
}

#[test]
fn doctor_fails_on_fresh_home_and_names_the_missing_pieces() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");

    let output = doctor(&home, dead_port());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "a fresh home cannot run the app yet:\n{stdout}"
    );
    assert!(
        stdout.contains("[fail]"),
        "expected failing checks:\n{stdout}"
    );
    assert!(
        stdout.contains("service"),
        "the missing service must be named:\n{stdout}"
    );
    assert!(
        stdout.contains("providers"),
        "the missing AI service must be named:\n{stdout}"
    );
    assert!(
        stdout.contains("agents"),
        "the missing agent must be named:\n{stdout}"
    );
    assert!(
        stdout.contains("providers.toml"),
        "the next step must point at the file the daemon reads:\n{stdout}"
    );
    assert!(
        !stdout.contains("all checks passed"),
        "false assurance must be impossible:\n{stdout}"
    );
    assert!(
        home.join("config.toml").exists(),
        "config should be created"
    );
    assert!(home.join("store.db").exists(), "store should be created");
}

#[test]
fn doctor_succeeds_when_service_providers_and_agent_exist() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        r#"
version = 1
default_agent = "scout"

[[providers]]
id = "fake"
kind = "fake"
base_url = "http://127.0.0.1:9/v1"
model = "fake-echo"
"#,
    )
    .unwrap();

    // A TCP listener that stays up for the whole run: the service check passes
    // without running a real auxd. The accept loop is bounded by a deadline so
    // the test can never hang.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let accept = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    drop(stream);
                    return;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }
    });

    let output = doctor(&home, addr.port());
    drop(accept.join());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "everything is configured:\n{stdout}"
    );
    assert!(
        stdout.contains("all checks passed"),
        "unexpected output:\n{stdout}"
    );
    assert!(
        stdout.contains("[ok]"),
        "expected passing checks:\n{stdout}"
    );
}

/// CONFIG-ERR-ECHO-2: a key on a broken line of `config.toml`, in a provider
/// URL or as a provider id never reaches the terminal; the file, line and
/// field stay readable.
#[test]
fn doctor_never_echoes_a_key_from_config_or_provider_urls() {
    let cases = [
        (
            "config.toml",
            "version = 1\napi_key = \"sk-proj-CANARY-7f3k9q\n",
            "config",
            "config.toml, line 2",
        ),
        (
            "providers.toml",
            "[[provider]]\nid = \"p\"\nkind = \"openai\"\nbase_url = \"https://api.example.com/v1?api_key=CANARY1\"\n",
            "providers",
            "https://api.example.com/v1?<redacted>",
        ),
        (
            "providers.toml",
            "[[provider]]\nid = \"p\"\nkind = \"openai\"\nbase_url = \"https://user:CANARY1@api.example.com:99999/v1\"\n",
            "providers",
            "base_url is not a valid URL",
        ),
        (
            "providers.toml",
            "[[provider]]\nid = \"sk-proj-canary-7f3k9q\"\nkind = \"acp\"\n",
            "providers",
            "looks like a key",
        ),
        // CONFIG-ERR-ECHO-2 (review): a percent-encoded key is the same key,
        // encoded once, twice, or in another case.
        (
            "providers.toml",
            "[[provider]]\nid = \"p\"\nkind = \"openai\"\nbase_url = \"http://h.test/%73k-proj-CANARY-7f3k9q\"\n",
            "providers",
            "http://h.test/<redacted>",
        ),
        (
            "providers.toml",
            "[[provider]]\nid = \"p\"\nkind = \"openai\"\nbase_url = \"http://h.test/%2573k-proj-CANARY-7f3k9q\"\n",
            "providers",
            "http://h.test/<redacted>",
        ),
        (
            "providers.toml",
            "[[provider]]\nid = \"p\"\nkind = \"openai\"\nbase_url = \"http://h.test/%53K-PROJ-CANARY-7f3k9q\"\n",
            "providers",
            "http://h.test/<redacted>",
        ),
        // CONFIG-ECHO-DECODE-LOOP: a key percent-encoded four or six times is
        // the same key; the decoder peels every escape layer.
        (
            "providers.toml",
            "[[provider]]\nid = \"p\"\nkind = \"openai\"\nbase_url = \"http://h.test/%25252573k-proj-CANARY-7f3k9q\"\n",
            "providers",
            "http://h.test/<redacted>",
        ),
        (
            "providers.toml",
            "[[provider]]\nid = \"p\"\nkind = \"openai\"\nbase_url = \"http://h.test/%252525252573k-proj-CANARY-7f3k9q\"\n",
            "providers",
            "http://h.test/<redacted>",
        ),
        (
            "config.toml",
            "version = 1\n[[providers]]\nid = \"%25252573k-proj-canary-7f3k9q\"\nkind = \"openai-compat\"\nbase_url = \"https://h.test/v1?x=1\"\nmodel = \"m\"\n",
            "providers",
            "looks like a key",
        ),
    ];
    for (file, content, check, kept) in cases {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(file), content).unwrap();

        let output = doctor(&home, dead_port());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stdout.to_lowercase().contains("canary") && !stderr.to_lowercase().contains("canary"),
            "the doctor echoed a value from {file}:\n{stdout}{stderr}"
        );
        let line = check_line(&stdout, check);
        assert!(line.contains(kept), "expected `{kept}` in:\n{stdout}");
    }
}

/// BRAINCONFIG-DEBUG: the provider line of the doctor names the file and the
/// count, never a value from it: a key pasted as a model id never reaches
/// the terminal.
#[test]
fn doctor_never_echoes_a_key_pasted_as_a_model_id() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join("providers.toml"),
        concat!(
            "[[provider]]\nid = \"p\"\nkind = \"openai\"\n",
            "base_url = \"https://api.example.com/v1\"\n",
            "models = [\"sk-proj-CANARY-7f3k9q\"]\n",
        ),
    )
    .unwrap();

    let output = doctor(&home, dead_port());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.to_lowercase().contains("canary") && !stderr.to_lowercase().contains("canary"),
        "the doctor echoed a model id from the file:\n{stdout}{stderr}"
    );
    let line = check_line(&stdout, "providers");
    assert!(line.contains("providers.toml"), "{stdout}");
}

#[test]
fn doctor_fails_on_broken_config() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("config.toml"), "version = \"nope\"\n").unwrap();

    let output = doctor(&home, dead_port());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "doctor should fail:\n{stdout}");
    assert!(
        stdout.contains("[fail]"),
        "expected a failing check:\n{stdout}"
    );
}

#[test]
fn doctor_fails_on_corrupted_store() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("store.db"), b"not a sqlite database at all").unwrap();

    let output = doctor(&home, dead_port());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "doctor should fail:\n{stdout}");
    assert!(
        stdout.contains("[fail]"),
        "expected a failing check:\n{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn doctor_fails_on_read_only_home() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o500)).unwrap();

    let output = doctor(&home, dead_port());

    // Restore permissions so the tempdir can be cleaned up.
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "doctor should fail:\n{stdout}");
    assert!(
        stdout.contains("[fail]"),
        "expected a failing check:\n{stdout}"
    );
}

/// ENV-MODE-UPDATER-DOC: a `.env` another user can read is still used, but it
/// is a problem: the doctor reports it with the one-line fix and the process
/// warns once. The key value itself never reaches the terminal.
#[cfg(unix)]
#[test]
fn doctor_reports_a_group_readable_env_file_without_printing_the_key() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let env_path = home.join(".env");
    std::fs::write(&env_path, "AUX_KEY_DEEPSEEK=sk-CANARY-8f2a1c\n").unwrap(); // gitleaks:allow
    std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = doctor(&home, dead_port());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let line = check_line(&stdout, "secrets");
    assert!(
        line.starts_with("[fail] secrets"),
        "a shared .env is a problem:\n{stdout}"
    );
    assert!(
        line.contains(&env_path.display().to_string()),
        "the doctor must name the file:\n{stdout}"
    );
    assert!(
        line.contains("chmod 600"),
        "the doctor must name the fix:\n{stdout}"
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.contains("warning:"))
            .count(),
        1,
        "exactly one warning per process:\n{stderr}"
    );
    assert!(
        stderr.contains("chmod 600"),
        "the warning must name the fix:\n{stderr}"
    );
    assert!(
        !stdout.contains("CANARY") && !stderr.contains("CANARY"),
        "a key value reached the output:\n{stdout}{stderr}"
    );
}

/// ENV-MODE-UPDATER-DOC: a `0600` file is the normal case — no warning and a
/// passing check.
#[cfg(unix)]
#[test]
fn doctor_keeps_quiet_for_a_0600_env_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let env_path = home.join(".env");
    std::fs::write(&env_path, "AUX_KEY_DEEPSEEK=sk-CANARY-8f2a1c\n").unwrap(); // gitleaks:allow
    std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let output = doctor(&home, dead_port());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let line = check_line(&stdout, "secrets");
    assert!(
        line.starts_with("[ok] secrets"),
        "a 0600 .env is fine:\n{stdout}"
    );
    assert!(
        !stderr.contains("warning:") && !stdout.contains("accessible to other users"),
        "a 0600 file must not warn:\n{stdout}{stderr}"
    );
    assert!(
        !stdout.contains("CANARY") && !stderr.contains("CANARY"),
        "a key value reached the output:\n{stdout}{stderr}"
    );
}

#[test]
fn doctor_survives_closed_stdout() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");

    let mut child = sandbox_command(aux_bin(), dir.path(), &home)
        .arg("doctor")
        .env("AUXESIS_LANG", "en")
        .env("AUXESIS_API_PORT", dead_port().to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn aux doctor");
    drop(child.stdout.take());

    let status = child.wait().expect("wait for doctor");
    // The exit code reflects the checks; the point here is that the process
    // exits normally instead of panicking on the broken pipe.
    assert!(
        status.code().is_some(),
        "must not panic on a broken pipe: {status:?}"
    );
}

#[test]
fn doctor_gives_no_legacy_hint_now_that_main_is_the_chief() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("config.toml"), "default_dot = \"main\"\n").unwrap();
    let stdout = String::from_utf8_lossy(&doctor(&home, dead_port()).stdout).into_owned();
    let hint = "default agent: main — your default agent is 'main'; set default_agent = \"aux\"";
    assert!(!stdout.contains(hint), "{stdout}");
}
