//! The extension scenarios, end to end on this host.
//!
//! These live as unit tests (not `tests/`) so they can use the crate's regular
//! dependencies to build a signed test catalog and a fixture stdio server.
//! The real `sandbox-exec` checks are `#[ignore]` and macOS-only; the Linux CI
//! gate runs the rest.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use kernel_broker::{
    ApprovalRequest, Approver, ApproverError, AuthorizeRequest, Broker, ExecutionMode,
    MemoryAuditSink, Taint, ToolRegistry,
};
use sha2::{Digest, Sha256};

use super::catalog::{Entry, EntryKind, Run, Sensitivity, Source, SourceType, Transport};
use super::install::{install, load_installed, remove, InstallOptions};
use super::mount::{
    accept, freeze, is_frozen, is_mounted, load_state, mount, mounted_extensions, store_state,
    unmount, ExtensionHost, ExtensionState,
};
use super::session::{session_for, verify_identity, SessionOptions};
use super::{extensions_dir, hex};

const TEST_SEED: [u8; 32] = [13u8; 32];

fn key() -> SigningKey {
    SigningKey::from_bytes(&TEST_SEED)
}

/// A minimal stdio MCP server in POSIX shell. `description` is what the
/// `ping` tool advertises, so a variant changes the pinned identity.
fn fixture_script(description: &str) -> String {
    format!(
        r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*)
      id=${{line#*\"id\":}}; id=${{id%%,*}}
      printf '{{"jsonrpc":"2.0","id":%s,"result":{{"protocolVersion":"2025-11-25","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"fixture","version":"1.0.0"}}}}}}\n' "$id"
      ;;
    *'"method":"tools/list"'*)
      id=${{line#*\"id\":}}; id=${{id%%,*}}
      printf '{{"jsonrpc":"2.0","id":%s,"result":{{"tools":[{{"name":"ping","description":"{description}","inputSchema":{{"type":"object","properties":{{}},"additionalProperties":false}}}},{{"name":"leak","description":"Print a secret","inputSchema":{{"type":"object","properties":{{}},"additionalProperties":false}}}}]}}}}\n' "$id"
      ;;
    *'"method":"tools/call"'*)
      id=${{line#*\"id\":}}; id=${{id%%,*}}
      text="pong"
      case "$line" in *'"name":"leak"'*) text="token=$EXT_DEMO__TOKEN";; esac
      printf '{{"jsonrpc":"2.0","id":%s,"result":{{"content":[{{"type":"text","text":"%s"}}],"isError":false}}}}\n' "$id" "$text"
      ;;
    *) ;;
  esac
done
"#
    )
}

fn fixture_entry(name: &str, script: &[u8], version: &str, sensitivity: Sensitivity) -> Entry {
    Entry {
        name: name.to_owned(),
        kind: EntryKind::Mcp,
        version: version.to_owned(),
        licence: "MIT".to_owned(),
        reviewed: true,
        sensitivity,
        summary_en: "fixture".to_owned(),
        summary_fr: "fixture".to_owned(),
        source: Source {
            kind: SourceType::Binary,
            package: "server".to_owned(),
            sha256: hex(&Sha256::digest(script)),
        },
        run: Run {
            transport: Transport::Stdio,
            command: "server".to_owned(),
            args: Vec::new(),
        },
        tools: vec![
            super::catalog::EntryTool {
                name: "ping".to_owned(),
                description: "Ping the fixture".to_owned(),
                network: Vec::new(),
                secrets: Vec::new(),
                auth: "none".to_owned(),
                fs: Vec::new(),
            },
            super::catalog::EntryTool {
                name: "leak".to_owned(),
                description: "Print a secret".to_owned(),
                network: Vec::new(),
                secrets: vec!["EXT_DEMO__TOKEN".to_owned()],
                auth: "none".to_owned(),
                fs: Vec::new(),
            },
        ],
        oauth: None,
        meta: None,
    }
}

/// Write a signed catalog tree for `entries` and return the public key.
fn signed_catalog(dir: &Path, entries: &[Entry]) -> ed25519_dalek::VerifyingKey {
    std::fs::create_dir_all(dir.join("entries")).unwrap();
    let mut index = String::from("format = 1\ncatalog_version = \"2026.10.09-1\"\n");
    for entry in entries {
        let text = toml::to_string(entry).unwrap();
        std::fs::write(
            dir.join("entries").join(format!("{}.toml", entry.name)),
            &text,
        )
        .unwrap();
        index.push_str(&format!(
            "[[entry]]\nname = \"{}\"\nfile = \"entries/{}.toml\"\nsha256 = \"{}\"\n",
            entry.name,
            entry.name,
            hex(&Sha256::digest(text.as_bytes()))
        ));
    }
    let bytes = index.into_bytes();
    std::fs::write(dir.join("index.toml"), &bytes).unwrap();
    let signature = base64::engine::general_purpose::STANDARD.encode(key().sign(&bytes).to_bytes());
    std::fs::write(dir.join("index.toml.sig"), signature).unwrap();
    key().verifying_key()
}

/// Write the fixture script to a temp file and return (path, bytes).
fn write_script(dir: &Path, name: &str, script: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, script).unwrap();
    path
}

/// Install the fixture entry end to end and return the home/name.
async fn install_fixture(home: &Path, name: &str, script: &str) -> Entry {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "server", script);
    let mut entry = fixture_entry(name, script.as_bytes(), "1.0.0", Sensitivity::Public);
    entry.source.package = path.to_string_lossy().into_owned();
    install(
        home,
        &entry,
        &InstallOptions {
            allow_loopback: true,
            pin: true,
        },
    )
    .await
    .expect("fixture installs");
    entry
}

#[tokio::test]
async fn catalog_refuses_a_tampered_index_and_keeps_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    let entry = fixture_entry("demo", script.as_bytes(), "1.0.0", Sensitivity::Public);
    let key = signed_catalog(dir.path(), &[entry]);
    let home = tempfile::tempdir().unwrap();
    let cache = super::CatalogCache::new(home.path());
    let catalog = super::Catalog::load_dir(dir.path(), &key).unwrap();
    let index_bytes = std::fs::read(dir.path().join("index.toml")).unwrap();
    let signature = std::fs::read_to_string(dir.path().join("index.toml.sig")).unwrap();
    cache.store(&catalog, &index_bytes, &signature).unwrap();
    assert_eq!(cache.cached_version().as_deref(), Some("2026.10.09-1"));
    // A tampered index no longer verifies, and the cache is untouched.
    let mut tampered = index_bytes.clone();
    tampered.push(b'\n');
    assert!(super::verify_index(&tampered, &signature, &key).is_err());
    assert_eq!(cache.cached_version().as_deref(), Some("2026.10.09-1"));
}

#[test]
fn entry_hash_mismatch_and_version_rollback_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    let entry = fixture_entry("demo", script.as_bytes(), "1.0.0", Sensitivity::Public);
    let key = signed_catalog(dir.path(), &[entry]);
    // Corrupt the entry file: its sha256 no longer matches the index line.
    std::fs::write(dir.path().join("entries/demo.toml"), "name = \"demo\"\n").unwrap();
    assert!(super::Catalog::load_dir(dir.path(), &key).is_err());
    // A lower version than the cache is refused.
    let home = tempfile::tempdir().unwrap();
    let cache = super::CatalogCache::new(home.path());
    std::fs::create_dir_all(cache.dir()).unwrap();
    std::fs::write(cache.dir().join("catalog_version"), "2026.10.10-0\n").unwrap();
    assert!(cache.check_monotonic("2026.10.09-9").is_err());
    assert_eq!(cache.cached_version().as_deref(), Some("2026.10.10-0"));
}

#[tokio::test]
async fn sha256_mismatch_refuses_the_install_and_leaves_nothing() {
    let home = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "server", "#!/bin/sh\necho real\n");
    let mut entry = fixture_entry("demo", b"expected-bytes", "1.0.0", Sensitivity::Public);
    entry.source.package = path.to_string_lossy().into_owned();
    assert!(install(
        home.path(),
        &entry,
        &InstallOptions {
            allow_loopback: true,
            pin: false,
        },
    )
    .await
    .is_err());
    assert!(!extensions_dir(home.path()).join("demo@1.0.0").exists());
}

#[tokio::test]
async fn identity_drift_freezes_and_unmounts() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    install_fixture(home.path(), "demo", &script).await;
    mount(home.path(), "demo", "alice").unwrap();
    assert!(is_mounted(home.path(), "demo", "alice"));
    // Swap the installed server for one whose `ping` description changed.
    let installed = load_installed(home.path(), "demo").unwrap();
    std::fs::write(
        installed.dir.join("server"),
        fixture_script("Ping the fixture v2"),
    )
    .unwrap();
    let session = session_for(home.path(), &installed, &SessionOptions::default())
        .await
        .unwrap();
    let drift = verify_identity(home.path(), "demo", &session.tools);
    assert!(drift.is_err());
    session.stop().await;
    assert!(is_frozen(home.path(), "demo"));
    assert!(!is_mounted(home.path(), "demo", "alice"));
    // The owner can re-approve.
    accept(home.path(), "demo").unwrap();
    assert!(!is_frozen(home.path(), "demo"));
}

#[tokio::test]
async fn a_printed_secret_is_scrubbed_from_the_tool_output() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    install_fixture(home.path(), "demo", &script).await;
    let canary = "CANARY-WO13B-SECRET-9f2c1d4a";
    std::fs::write(
        home.path().join(".env"),
        format!("EXT_DEMO__TOKEN={canary}\n"),
    )
    .unwrap();
    let installed = load_installed(home.path(), "demo").unwrap();
    let session = session_for(home.path(), &installed, &SessionOptions::default())
        .await
        .unwrap();
    let value = session
        .call_tool_raw("leak", serde_json::json!({}))
        .await
        .unwrap();
    session.stop().await;
    let rendered = value.to_string();
    assert!(!rendered.contains(canary), "{rendered}");
    assert!(rendered.contains("token="), "{rendered}");
}

#[tokio::test]
async fn remove_leaves_no_file_no_secret_and_no_mount() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    install_fixture(home.path(), "demo", &script).await;
    mount(home.path(), "demo", "alice").unwrap();
    let canary = "CANARY-WO13B-REMOVE-1234";
    std::fs::write(
        home.path().join(".env"),
        format!("KEEP=1\nEXT_DEMO__TOKEN={canary}\n"),
    )
    .unwrap();
    let removed = remove(home.path(), "demo").unwrap();
    assert_eq!(removed, 1);
    assert!(!extensions_dir(home.path()).join("demo@1.0.0").exists());
    assert!(!is_mounted(home.path(), "demo", "alice"));
    assert!(load_state(home.path(), "demo").is_none());
    let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
    assert!(env.contains("KEEP=1"));
    assert!(!env.contains("EXT_DEMO__TOKEN"));
    assert!(!env.contains(canary));
}

#[tokio::test]
async fn a_real_entry_installs_and_its_tool_is_mcp_name_tool_default_ask() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    install_fixture(home.path(), "demo", &script).await;
    mount(home.path(), "demo", "alice").unwrap();
    assert_eq!(mounted_extensions(home.path(), "alice"), vec!["demo"]);

    let host = ExtensionHost::start(home.path()).await;
    let mut registry = ToolRegistry::new();
    let mounted = host.register_for_agent("alice", &mut registry);
    assert_eq!(mounted, 2);

    let wire = kernel_mcp::wire_name("demo", "ping");
    assert_eq!(wire, "mcp__demo__ping");
    assert_eq!(kernel_mcp::display_name("demo", "ping"), "mcp.demo.ping");
    let tool = registry.get(&wire).expect("registered");
    assert!(
        tool.class().requires_explicit_rule,
        "an MCP tool must require an exact-name rule"
    );

    // Broker default: with no rule, the approver is consulted.
    let approver = Arc::new(RecordingApprover::default());
    let broker = Broker::new(
        Arc::new(MemoryAuditSink::new()),
        Vec::new(),
        approver.clone(),
        Arc::new(registry),
    );
    let taint = Taint::Clean;
    let authorization = broker
        .authorize(AuthorizeRequest {
            agent: "alice",
            tool: &wire,
            risk: kernel_broker::Risk::High,
            arguments: serde_json::json!({}),
            taint: &taint,
            read_only: false,
            mode: ExecutionMode::Sandboxed,
            requires_explicit_rule: true,
            skill: None,
            skill_only: false,
        })
        .await
        .unwrap();
    assert!(authorization.is_allowed());
    assert!(approver.asked.load(Ordering::SeqCst), "broker must ask");
    host.stop().await;
}

#[tokio::test]
async fn sensitive_extension_is_mountable_in_private_because_b14_is_covered() {
    let home = tempfile::tempdir().unwrap();
    let mut state = ExtensionState {
        name: "secret-ext".to_owned(),
        version: "1.0.0".to_owned(),
        kind: "mcp".to_owned(),
        frozen: false,
        tools: Default::default(),
        network: Vec::new(),
        secrets: Vec::new(),
        oauth: None,
        artefact: None,
        launch: None,
    };
    state.tools.insert("ping".to_owned(), "00".to_owned());
    store_state(home.path(), &state).unwrap();
    let entry = fixture_entry(
        "secret-ext",
        fixture_script("Ping").as_bytes(),
        "1.0.0",
        Sensitivity::Sensitive,
    );
    assert!(super::mount::may_mount_in_mode(
        &entry,
        kernel_core::privacy::PrivacyMode::Private
    ));
    assert!(super::mount::may_mount_in_mode(
        &entry,
        kernel_core::privacy::PrivacyMode::Open
    ));
    // A frozen extension refuses a mount regardless of mode.
    freeze(home.path(), "secret-ext", "test").unwrap();
    assert!(mount(home.path(), "secret-ext", "alice").is_err());
    let _ = unmount(home.path(), "secret-ext", "alice");
}

/// Write `[privacy] mode` into the home's `config.toml`.
fn set_mode(home: &Path, mode: &str) {
    std::fs::write(
        home.join("config.toml"),
        format!("[privacy]\nmode = \"{mode}\"\n"),
    )
    .unwrap();
}

#[tokio::test]
async fn a_sensitive_extension_is_offered_in_private_mode_too() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "server", &script);
    let mut entry = fixture_entry("demo", script.as_bytes(), "1.0.0", Sensitivity::Sensitive);
    entry.source.package = path.to_string_lossy().into_owned();
    install(
        home.path(),
        &entry,
        &InstallOptions {
            allow_loopback: true,
            pin: true,
        },
    )
    .await
    .unwrap();
    set_mode(home.path(), "open");
    mount(home.path(), "demo", "alice").unwrap();
    let host = ExtensionHost::start(home.path()).await;
    let mut registry = ToolRegistry::new();
    assert_eq!(host.register_for_agent("alice", &mut registry), 2);
    // Private: B14 is covered, so the next turn still offers the tools.
    set_mode(home.path(), "private");
    let mut registry = ToolRegistry::new();
    assert_eq!(host.register_for_agent("alice", &mut registry), 2);
    assert!(registry
        .get(&kernel_mcp::wire_name("demo", "ping"))
        .is_some());
    host.stop().await;
}

#[tokio::test]
async fn reinstall_keeps_a_freeze_until_accept() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    install_fixture(home.path(), "demo", &script).await;
    freeze(home.path(), "demo", "drift").unwrap();
    assert!(is_frozen(home.path(), "demo"));
    // A reinstall re-pins the tools but must not clear the freeze.
    install_fixture(home.path(), "demo", &script).await;
    assert!(
        is_frozen(home.path(), "demo"),
        "reinstall must keep the freeze until `verify --accept`"
    );
    #[cfg(unix)]
    {
        let state = home.path().join("extensions/state/demo.json");
        for kind in ["fifo", "garbage"] {
            std::fs::remove_file(&state).unwrap();
            if kind == "fifo" {
                assert!(std::process::Command::new("mkfifo")
                    .arg(&state)
                    .status()
                    .unwrap()
                    .success());
            } else {
                std::fs::write(&state, b"not json").unwrap();
            }
            assert!(is_frozen(home.path(), "demo"), "{kind}");
            install_fixture(home.path(), "demo", &script).await;
            assert!(is_frozen(home.path(), "demo"), "reinstall over {kind}");
        }
    }
    accept(home.path(), "demo").unwrap();
    assert!(!is_frozen(home.path(), "demo"));
    #[cfg(unix)]
    {
        let state = home.path().join("extensions/state/demo.json");
        std::fs::remove_file(&state).unwrap();
        std::os::unix::fs::symlink(home.path().join("nothing"), &state).unwrap();
        if !kernel_core::sandbox_guard_active() {
            install_fixture(home.path(), "demo", &script).await;
        }
        assert!(is_frozen(home.path(), "demo"), "a link must read frozen");
    }
}

#[tokio::test]
async fn accept_repins_the_current_identity() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    install_fixture(home.path(), "demo", &script).await;
    mount(home.path(), "demo", "alice").unwrap();
    // The owner installs a new build (its own pinned sha256) without re-pinning
    // its tools, so the changed description freezes it on the next start.
    let v2 = fixture_script("Ping the fixture v2");
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "server", &v2);
    let mut entry = fixture_entry("demo", v2.as_bytes(), "1.0.0", Sensitivity::Public);
    entry.source.package = path.to_string_lossy().into_owned();
    install(
        home.path(),
        &entry,
        &InstallOptions {
            allow_loopback: true,
            pin: false,
        },
    )
    .await
    .unwrap();
    let installed = load_installed(home.path(), "demo").unwrap();
    let session = session_for(home.path(), &installed, &SessionOptions::default())
        .await
        .unwrap();
    assert!(verify_identity(home.path(), "demo", &session.tools).is_err());
    session.stop().await;
    assert!(is_frozen(home.path(), "demo"));
    // EXT-ANCHOR-7: the approval binds bytes, not the version name: new bytes
    // at the approved 1.0.0 are refused by a plain `--accept` and by a mount.
    let err = super::session::accept_current(home.path(), "demo", false)
        .await
        .unwrap_err()
        .to_string();
    let named = err.contains("--downgrade-to 1.0.0");
    assert!(err.contains("sha256") && named, "{err}");
    assert!(is_frozen(home.path(), "demo"), "nothing re-pinned");
    let refused = super::mount::require_approval(home.path(), &installed).unwrap_err();
    assert!(refused.to_string().contains("sha256"), "{refused}");
    // `verify --accept` naming the build re-pins the live identity and bytes.
    let accepted = super::session::accept_installed(home.path(), "demo", false, Some("1.0.0"))
        .await
        .unwrap();
    let pin = hex(&Sha256::digest(v2.as_bytes()));
    assert_eq!(accepted.state.artefact, Some(pin));
    assert!(!is_frozen(home.path(), "demo"));
    let rows = super::ledger::payloads(home.path(), super::ledger::VERIFY);
    let flagged = rows.iter().any(|row| row.contains(r#""downgrade":true"#));
    assert!(flagged, "{rows:?}");
    let installed = load_installed(home.path(), "demo").unwrap();
    let session = session_for(home.path(), &installed, &SessionOptions::default())
        .await
        .unwrap();
    assert!(
        verify_identity(home.path(), "demo", &session.tools).is_ok(),
        "the accepted identity must not refreeze on the next start"
    );
    session.stop().await;
}

#[tokio::test]
async fn accept_refuses_a_tampered_binary_and_stays_frozen() {
    let home = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    let path = write_script(scratch.path(), "server", &script);
    let mut entry = fixture_entry("demo", script.as_bytes(), "1.0.0", Sensitivity::Public);
    entry.source.package = path.to_string_lossy().into_owned();
    install(
        home.path(),
        &entry,
        &InstallOptions {
            allow_loopback: true,
            pin: false,
        },
    )
    .await
    .unwrap();
    let installed = load_installed(home.path(), "demo").unwrap();
    let state = ExtensionState {
        name: "demo".to_owned(),
        version: "1.0.0".to_owned(),
        kind: "mcp".to_owned(),
        frozen: true,
        tools: Default::default(),
        network: Vec::new(),
        secrets: Vec::new(),
        oauth: None,
        artefact: None,
        launch: None,
    };
    store_state(home.path(), &state).unwrap();
    // Tamper with the installed bytes: `accept` must re-hash before re-pinning.
    std::fs::write(
        installed.dir.join("server"),
        fixture_script("Ping the fixture v2"),
    )
    .unwrap();
    let err = super::session::accept_current(home.path(), "demo", false)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("sha256 mismatch"), "{err}");
    assert!(
        is_frozen(home.path(), "demo"),
        "a tampered binary must not clear the freeze"
    );
}

// EXT-ANCHOR-6: the approved 2.0.0 entry went corrupt, so 1.0.0 is what would
// run. `--accept` never re-pins it silently: it names both versions and keeps
// the freeze, and only the owner's explicit `--downgrade-to 1.0.0` re-pins it.
#[tokio::test]
async fn accept_refuses_a_silent_downgrade_past_a_corrupt_newer_entry() {
    let home = tempfile::tempdir().unwrap();
    install_fixture(home.path(), "demo", &fixture_script("Ping the fixture")).await;
    let mut state = load_state(home.path(), "demo").unwrap();
    state.version = "2.0.0".to_owned();
    state.frozen = true;
    store_state(home.path(), &state).unwrap();
    let newer = extensions_dir(home.path()).join("demo@2.0.0");
    std::fs::create_dir_all(&newer).unwrap();
    std::fs::write(newer.join("entry.toml"), b"not = [toml").unwrap();
    let accept = |to| super::session::accept_installed(home.path(), "demo", false, to);
    let err = accept(None).await.unwrap_err();
    // EXT-ANCHOR-7: the refusal carries the corrupt newer entries to print.
    let super::session::SessionError::DowngradeRefused { corrupt_newer, .. } = &err else {
        panic!("{err}");
    };
    assert_eq!(corrupt_newer, &["2.0.0"]);
    let err = err.to_string();
    assert!(err.contains("2.0.0") && err.contains("1.0.0"), "{err}");
    assert!(accept(Some("3.0.0")).await.is_err(), "only the running one");
    let kept = load_state(home.path(), "demo").unwrap();
    assert!(kept.frozen && kept.version == "2.0.0", "nothing re-pinned");
    let accepted = accept(Some("1.0.0")).await.unwrap();
    assert_eq!(accepted.state.version, "1.0.0");
    assert_eq!(accepted.corrupt_newer, ["2.0.0"]);
    assert!(!is_frozen(home.path(), "demo"));
}

// EXT-ANCHOR-7: the guard compares the exact version string, never an order
// (`01.0.0` sorts equal to `1.0.0`); a row without an artefact pin is never
// the approved build; a stray `--downgrade-to` on the approved build names
// `--accept` alone.
#[tokio::test]
async fn accept_names_any_build_other_than_the_approved_one() {
    let home = tempfile::tempdir().unwrap();
    install_fixture(home.path(), "demo", &fixture_script("Ping the fixture")).await;
    let accept = |to| super::session::accept_installed(home.path(), "demo", false, to);
    let err = accept(Some("1.0.0")).await.unwrap_err().to_string();
    assert!(err.contains("`aux ext verify demo --accept`"), "{err}");
    assert!(!err.contains("--downgrade-to"), "{err}");
    let pinned = load_state(home.path(), "demo").unwrap();
    for (version, artefact) in [("01.0.0", pinned.artefact.clone()), ("1.0.0", None)] {
        let mut state = pinned.clone();
        (state.version, state.artefact, state.frozen) = (version.to_owned(), artefact, true);
        store_state(home.path(), &state).unwrap();
        let err = accept(None).await.unwrap_err().to_string();
        assert!(err.contains("--downgrade-to 1.0.0"), "{version}: {err}");
        let kept = load_state(home.path(), "demo").unwrap();
        assert!(kept.frozen && kept.version == version, "nothing re-pinned");
    }
    let accepted = accept(Some("1.0.0")).await.unwrap();
    assert_eq!(accepted.state.artefact, pinned.artefact, "pin written back");
    accept(None).await.expect("the approved build re-accepts");
}

#[tokio::test]
async fn remove_deletes_only_this_extensions_secrets() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    install_fixture(home.path(), "demo", &script).await;
    std::fs::write(
        home.path().join(".env"),
        "AUX_KEY_DEEPSEEK=keep\n\
         EXT_DEMO__TOKEN=drop\n",
    )
    .unwrap();
    remove(home.path(), "demo").unwrap();
    let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
    assert!(env.contains("AUX_KEY_DEEPSEEK=keep"));
    assert!(!env.contains("EXT_DEMO__TOKEN"));
}

#[test]
fn remove_never_touches_another_extensions_secret_keys() {
    let home = tempfile::tempdir().unwrap();
    let mut foo = ExtensionState {
        name: "foo".to_owned(),
        version: "1.0.0".to_owned(),
        kind: "mcp".to_owned(),
        frozen: false,
        tools: Default::default(),
        network: Vec::new(),
        // The colliding name is planted in `foo`'s row: the filter must refuse
        // it because it belongs to `foo-bar`.
        secrets: vec!["EXT_FOO__TOKEN".to_owned(), "EXT_FOO_BAR__TOKEN".to_owned()],
        oauth: None,
        artefact: None,
        launch: None,
    };
    foo.tools.insert("ping".to_owned(), "00".to_owned());
    store_state(home.path(), &foo).unwrap();
    let bar = ExtensionState {
        name: "foo-bar".to_owned(),
        version: "1.0.0".to_owned(),
        kind: "mcp".to_owned(),
        frozen: false,
        tools: Default::default(),
        network: Vec::new(),
        secrets: vec!["EXT_FOO_BAR__TOKEN".to_owned()],
        oauth: None,
        artefact: None,
        launch: None,
    };
    store_state(home.path(), &bar).unwrap();
    std::fs::write(
        home.path().join(".env"),
        "EXT_FOO__TOKEN=a\nEXT_FOO_BAR__TOKEN=b\n",
    )
    .unwrap();
    remove(home.path(), "foo").unwrap();
    let env = std::fs::read_to_string(home.path().join(".env")).unwrap();
    assert!(!env.contains("EXT_FOO__TOKEN"), "{env}");
    assert!(env.contains("EXT_FOO_BAR__TOKEN"), "{env}");
}

/// A recording approver: proves the broker consulted it.
#[derive(Default)]
struct RecordingApprover {
    asked: AtomicBool,
}

#[async_trait::async_trait]
impl Approver for RecordingApprover {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        self.asked.store(true, Ordering::SeqCst);
        Ok(true)
    }
}

// ---- Test 5: the egress proxy's allowlist, fully offline -------------------

async fn proxy_reply(allow: Vec<(String, u16)>, target: &str) -> String {
    let proxy = kernel_net::spawn_egress_proxy(allow).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port()))
        .await
        .unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut body = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut body),
    )
    .await;
    proxy.shutdown().await;
    String::from_utf8_lossy(&body).into_owned()
}

#[tokio::test]
async fn proxy_allows_only_the_listed_host_and_port() {
    let allow = vec![("allowed.invalid".to_owned(), 443u16)];
    // The allowlisted host passes authorization; DNS then fails, which is the
    // proof it was not refused by the allowlist.
    let allowed = proxy_reply(allow.clone(), "allowed.invalid:443").await;
    assert!(allowed.contains("dns_failure"), "{allowed}");
    assert!(!allowed.contains("host_not_allowed"), "{allowed}");
    // Another host is refused by the allowlist.
    let other = proxy_reply(allow.clone(), "other.invalid:443").await;
    assert!(other.contains("host_not_allowed"), "{other}");
    // The right host on the wrong port is refused too.
    let wrong_port = proxy_reply(allow, "allowed.invalid:80").await;
    assert!(wrong_port.contains("port_not_allowed"), "{wrong_port}");
}

// ---- Tests 4 and 5: the real macOS sandbox --------------------------------
//
// The seatbelt profile currently aborts every child on macOS 27 (a kernel
// fix is pending), so these stay `#[ignore]`d. Each test runs a **positive
// control** first — `/usr/bin/true` under the same profile must exit 0, and in
// the proxy case a child must reach the allowed loopback port. If the profile
// aborts everything, the control fails and the test cannot pass vacuously.

#[cfg(target_os = "macos")]
fn sandbox_run(profile: &str, program: &str, args: &[&str]) -> std::process::ExitStatus {
    std::process::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(profile)
        .arg(program)
        .args(args)
        .status()
        .expect("run sandbox-exec")
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_with_no_proxy_port_denies_network() {
    let work = tempfile::tempdir().unwrap();
    let spec = kernel_mcp::SandboxSpec {
        install_dir: PathBuf::from("/usr"),
        work_dir: work.path().to_path_buf(),
        runtime_read_paths: vec![PathBuf::from("/usr/bin")],
        proxy_port: None,
    };
    let profile = kernel_mcp::seatbelt_profile(&spec);
    // Positive control: the profile must be able to run a child at all.
    assert!(
        sandbox_run(&profile, "/usr/bin/true", &[]).success(),
        "positive control: the profile must run /usr/bin/true"
    );
    let status = sandbox_run(
        &profile,
        "/usr/bin/nc",
        &["-z", "-w", "2", "1.1.1.1", "443"],
    );
    assert!(!status.success(), "the sandbox must deny the connection");
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_allows_only_the_proxy_port_and_proxy_refuses_other_hosts() {
    let work = tempfile::tempdir().unwrap();
    // A live loopback listener stands in for the egress proxy port.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let port_arg = port.to_string();
    let spec = kernel_mcp::SandboxSpec {
        install_dir: PathBuf::from("/usr"),
        work_dir: work.path().to_path_buf(),
        runtime_read_paths: vec![PathBuf::from("/usr/bin")],
        proxy_port: Some(port),
    };
    let profile = kernel_mcp::seatbelt_profile(&spec);
    // Positive controls: a child runs, and it can reach the allowed port.
    assert!(
        sandbox_run(&profile, "/usr/bin/true", &[]).success(),
        "positive control: the profile must run /usr/bin/true"
    );
    assert!(
        sandbox_run(
            &profile,
            "/usr/bin/nc",
            &["-z", "-w", "2", "127.0.0.1", port_arg.as_str()],
        )
        .success(),
        "positive control: a child must reach the allowed loopback port"
    );
    // Negative: a direct connection off the machine is denied.
    let status = sandbox_run(
        &profile,
        "/usr/bin/nc",
        &["-z", "-w", "2", "1.1.1.1", "443"],
    );
    assert!(
        !status.success(),
        "a direct connection must be denied even when the proxy port is allowed"
    );
}

/// Install `entry` from `script` without re-pinning (an upgrade on disk).
async fn install_unpinned(home: &Path, mut entry: Entry, script: &str) {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "server", script);
    entry.source.package = path.to_string_lossy().into_owned();
    install(
        home,
        &entry,
        &InstallOptions {
            allow_loopback: true,
            pin: false,
        },
    )
    .await
    .expect("upgrade installs");
}

#[tokio::test]
async fn an_upgrade_with_a_wider_network_needs_a_new_yes_before_it_runs() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "server", &script);
    let mut v1 = fixture_entry("demo", script.as_bytes(), "1.0.0", Sensitivity::Public);
    v1.tools[0].network = vec!["a.example:443".to_owned()];
    v1.source.package = path.to_string_lossy().into_owned();
    install(
        home.path(),
        &v1,
        &InstallOptions {
            allow_loopback: true,
            pin: true,
        },
    )
    .await
    .expect("v1 installs and pins");
    mount(home.path(), "demo", "alice").unwrap();
    assert_eq!(
        load_state(home.path(), "demo").unwrap().network,
        vec!["a.example:443"]
    );

    // v2 widens the allowlist; it is installed without a new approval.
    let mut v2 = fixture_entry("demo", script.as_bytes(), "2.0.0", Sensitivity::Public);
    v2.tools[0].network = vec!["a.example:443".to_owned(), "b.example:443".to_owned()];
    install_unpinned(home.path(), v2, &script).await;
    assert_eq!(
        load_installed(home.path(), "demo").unwrap().version,
        "2.0.0"
    );

    let err = mount(home.path(), "demo", "bob").unwrap_err();
    assert!(err.to_string().starts_with("approval_required"), "{err}");
    assert!(!is_mounted(home.path(), "demo", "bob"));
    let Err(err) =
        super::session::discover_session(home.path(), "demo", &SessionOptions::default()).await
    else {
        panic!("an unapproved build must not start");
    };
    assert!(err.to_string().contains("approval_required"), "{err}");
    let host = ExtensionHost::start(home.path()).await;
    assert!(
        host.running().is_empty(),
        "an unapproved upgrade must not be spawned"
    );
    let mut registry = ToolRegistry::new();
    assert_eq!(host.register_for_agent("alice", &mut registry), 0);
    host.stop().await;

    // The owner's yes, naming v2, pins its version and hosts; the next start passes.
    let accept = |to| super::session::accept_installed(home.path(), "demo", false, to);
    assert!(accept(None).await.is_err(), "another build needs its name");
    let state = accept(Some("2.0.0")).await.unwrap().state;
    assert_eq!(state.version, "2.0.0");
    assert_eq!(state.network, vec!["a.example:443", "b.example:443"]);
    mount(home.path(), "demo", "bob").unwrap();
    let host = ExtensionHost::start(home.path()).await;
    assert_eq!(host.running(), vec!["demo"]);
    host.stop().await;

    // v3 keeps the version string of v2 but declares a new secret name; it
    // replaces the v2 tree in place.
    let mut v3 = fixture_entry("demo", script.as_bytes(), "2.0.0", Sensitivity::Public);
    v3.tools[0].network = vec!["a.example:443".to_owned()];
    v3.tools[0].secrets = vec!["EXT_DEMO__EXTRA".to_owned()];
    install_unpinned(home.path(), v3, &script).await;
    let err = mount(home.path(), "demo", "carol").unwrap_err();
    assert!(err.to_string().contains("EXT_DEMO__EXTRA"), "{err}");
    let host = ExtensionHost::start(home.path()).await;
    assert!(
        host.running().is_empty(),
        "a new secret name must not start"
    );
    host.stop().await;
}

async fn assert_starts(home: &Path, want: bool) {
    let host = ExtensionHost::start(home).await;
    let names: Vec<String> = host.running().iter().map(|n| n.to_string()).collect();
    host.stop().await;
    assert_eq!(names.is_empty(), !want, "{names:?}");
}

// EXT-ANCHOR-7 r2: entry.toml sits in the install tree, so the approval binds
// what runs and where, not only the sha256. A kind flip (which skips the
// binary re-hash), a new command or args, or a lowered sensitivity is refused
// at mount and at start; a row without the launch pin waits for `--accept`.
#[tokio::test]
async fn approval_binds_the_launch_fields_of_entry_toml() {
    let home = tempfile::tempdir().unwrap();
    let script = fixture_script("Ping the fixture");
    install_fixture(home.path(), "demo", &script).await;
    mount(home.path(), "demo", "alice").unwrap();
    // (c) the unchanged entry starts.
    assert_starts(home.path(), true).await;
    let installed = load_installed(home.path(), "demo").unwrap();
    let approved = installed.entry.clone();
    let rewrite = |entry: &Entry| {
        std::fs::write(
            installed.dir.join("entry.toml"),
            toml::to_string(entry).unwrap(),
        )
        .unwrap()
    };
    let marker = home.path().join("ran");
    // (a) Binary -> npm with another command and args, same sha256 and version.
    let mut flipped = approved.clone();
    flipped.source.kind = SourceType::Npm;
    flipped.run.command = "sh".to_owned();
    flipped.run.args = vec!["-c".to_owned(), format!("touch '{}'", marker.display())];
    rewrite(&flipped);
    let err = mount(home.path(), "demo", "bob").unwrap_err().to_string();
    for field in ["source.type", "run.command", "run.args"] {
        assert!(err.contains(field), "{err}");
    }
    assert_starts(home.path(), false).await;
    assert!(!marker.exists(), "the swapped command must never run");
    // (b) sensitive -> public.
    let mut sensitive = approved.clone();
    sensitive.sensitivity = Sensitivity::Sensitive;
    rewrite(&sensitive);
    // EXT-ANCHOR-8: a plain `--accept` refuses it; naming the field re-trusts it.
    let err = super::session::accept_current(home.path(), "demo", false).await;
    let err = err.unwrap_err().to_string();
    assert!(err.contains("--accept-launch-change sensitivity"), "{err}");
    let fields = ["sensitivity".to_owned()];
    let pinned = accept_launch(home.path(), &fields).await;
    assert!(pinned.unwrap().state.launch.is_some());
    rewrite(&approved);
    let err = mount(home.path(), "demo", "bob").unwrap_err().to_string();
    assert!(err.contains("changed launch fields: sensitivity"), "{err}");
    assert_starts(home.path(), false).await;
    // (d) a row without the launch pin is refused until `--accept`.
    let mut state = load_state(home.path(), "demo").unwrap();
    state.launch = None;
    store_state(home.path(), &state).unwrap();
    let err = mount(home.path(), "demo", "bob").unwrap_err().to_string();
    assert!(err.contains("no approved launch"), "{err}");
    assert_starts(home.path(), false).await;
    super::session::accept_current(home.path(), "demo", false)
        .await
        .unwrap();
    mount(home.path(), "demo", "bob").unwrap();
    assert_starts(home.path(), true).await;
}

/// `aux ext verify demo --accept --accept-launch-change <fields>`.
async fn accept_launch(
    home: &Path,
    fields: &[String],
) -> Result<super::session::Accepted, super::session::SessionError> {
    let options = super::session::AcceptOptions {
        launch_change: fields,
        ..Default::default()
    };
    super::session::accept_with(home, "demo", &options, |_| {}).await
}

// EXT-ANCHOR-8: `--accept` diffs the launch pin before anything runs. A
// tampered `run.args` is refused by a plain `--accept` (it names the field and
// the flag), by a flag naming other fields, and nothing starts or is pinned;
// only the exact field list re-trusts it, and the pin is saved and shown
// before the child starts. The Ledger row carries both sha256s.
#[tokio::test]
async fn accept_refuses_a_tampered_run_args_and_starts_nothing() {
    let home = tempfile::tempdir().unwrap();
    install_fixture(home.path(), "demo", &fixture_script("Ping the fixture")).await;
    let installed = load_installed(home.path(), "demo").unwrap();
    mount(home.path(), "demo", "alice").unwrap();
    assert_starts(home.path(), true).await;
    let before = load_state(home.path(), "demo").unwrap();
    let mut tampered = installed.entry.clone();
    tampered.run.args = vec!["--evil".to_owned()];
    std::fs::write(
        installed.dir.join("entry.toml"),
        toml::to_string(&tampered).unwrap(),
    )
    .unwrap();
    let err = super::session::accept_current(home.path(), "demo", false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, super::session::SessionError::LaunchChangeRefused(_)),
        "{err}"
    );
    let err = err.to_string();
    assert!(err.contains("(run.args)"), "{err}");
    assert!(err.contains("--accept-launch-change run.args"), "{err}");
    let wrong = accept_launch(home.path(), &["run.command".to_owned()]).await;
    assert!(wrong.unwrap_err().to_string().contains("run.args"));
    let kept = load_state(home.path(), "demo").unwrap();
    assert_eq!(kept.launch, before.launch, "nothing re-pinned");
    assert_starts(home.path(), false).await;
    // The exact field re-trusts it; the pin is on disk when `on_trusted` runs.
    let fields = ["run.args".to_owned()];
    let options = super::session::AcceptOptions {
        launch_change: &fields,
        ..Default::default()
    };
    let mut seen = None;
    let accepted = super::session::accept_with(home.path(), "demo", &options, |state| {
        seen = load_state(home.path(), "demo").map(|row| (row.launch, row.frozen));
        assert_eq!(state.launch.as_ref().unwrap().run.args, tampered.run.args);
    })
    .await
    .unwrap();
    let pinned = super::mount::launch_pin(&tampered);
    assert_eq!(
        seen,
        Some((Some(pinned.clone()), true)),
        "saved before start"
    );
    assert_eq!(accepted.state.launch, Some(pinned));
    assert!(!accepted.state.frozen);
    mount(home.path(), "demo", "alice").unwrap();
    assert_starts(home.path(), true).await;
    let rows = super::ledger::payloads(home.path(), super::ledger::VERIFY);
    let sha = before.artefact.unwrap();
    let row = format!(r#""previous_sha256":"{sha}""#);
    assert!(rows.iter().any(|r| r.contains(&row)), "{rows:?}");
    let row = format!(r#""sha256":"{sha}""#);
    assert!(rows.iter().any(|r| r.contains(&row)), "{rows:?}");
    // A flag on a build with no launch change is refused.
    let again = accept_launch(home.path(), &fields).await.unwrap_err();
    assert!(
        again.to_string().contains("no changed launch field"),
        "{again}"
    );
}
