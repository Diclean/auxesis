//! B3 round 5, F2: in Private mode the `crm-timeline` refresh runs only when
//! every IMAP host is loopback (the brief's rule); any other config stops it
//! before any IMAP socket. The Open path is unchanged.
//!
//! The endpoint below is a plain TCP spy standing in for the mail server: it
//! records every connection it accepts and closes each one at once, so a
//! client that dials fails fast instead of hanging. Private mode must return
//! before that dial; Open mode must still reach the dial exactly as before.
//! Loopback only; people and addresses are fictional.

use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use aux_crm::Crm;
use aux_fakemail::{serve, SimConfig, StoredMail};
use aux_store::{NewParty, PartyKind, Store};
use kernel_core::privacy::{ModeFn, PrivacyMode};

/// The account id the fixture configures; its password comes from the temp
/// home's `.env`, exactly as the mail CLI test does.
const ACCOUNT: &str = "personal";

/// A loopback endpoint that counts connections and closes them at once.
struct SpyImap {
    port: u16,
    connections: Arc<AtomicUsize>,
    accepted: Receiver<()>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SpyImap {
    fn spawn() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the spy endpoint");
        listener
            .set_nonblocking(true)
            .expect("the spy endpoint is nonblocking");
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, accepted) = mpsc::channel();
        let counter = Arc::clone(&connections);
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let _ = tx.send(());
                        // Close at once: the client's handshake fails fast.
                        drop(stream);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            connections,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    /// Wait, bounded, for the first accepted connection. A disconnected
    /// sender means the spy thread has stopped.
    fn wait_for_dial(&self) -> bool {
        matches!(self.accepted.recv_timeout(Duration::from_secs(10)), Ok(()))
    }
}

impl Drop for SpyImap {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// One configured mailbox: its id, IMAP host and port, and an optional pinned
/// certificate (a pinned certificate is refused on a non-loopback host).
struct Account<'a> {
    id: &'a str,
    host: &'a str,
    port: u16,
    ca_file: Option<&'a Path>,
}

fn account<'a>(id: &'a str, host: &'a str, port: u16) -> Account<'a> {
    Account {
        id,
        host,
        port,
        ca_file: None,
    }
}

fn write_config(home: &Path, port: u16, mode: &str) {
    write_accounts(home, mode, &[account(ACCOUNT, "127.0.0.1", port)]);
}

/// Write the config and one `.env` password per account.
fn write_accounts(home: &Path, mode: &str, accounts: &[Account]) {
    let mut config = format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n\n[connectors.mail]\n");
    let mut env = String::new();
    for account in accounts {
        let ca_line = account
            .ca_file
            .map(|path| format!("ca_file = \"{}\"\n", path.display()))
            .unwrap_or_default();
        config.push_str(&format!(
            "[[connectors.mail.accounts]]\n\
             id = \"{id}\"\n\
             email = \"owner@mailsim.test\"\n\
             only_folders = [\"INBOX\"]\n\
             [connectors.mail.accounts.imap]\n\
             host = \"{host}\"\n\
             port = {port}\n\
             security = \"tls\"\n\
             {ca_line}",
            id = account.id,
            host = account.host,
            port = account.port,
        ));
        env.push_str(&format!(
            "AUX_MAIL_{}=secret\n",
            account.id.to_ascii_uppercase()
        ));
    }
    std::fs::write(kernel_core::config_path(home), config).unwrap();
    let path = home.join(".env");
    std::fs::write(&path, env).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// A listener on `0.0.0.0`: not a loopback spelling, yet a connect to it lands
/// here, so a dial of the "remote" host is counted without any DNS.
fn remote_listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn open_home() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    (dir, home)
}

fn open_store(home: &Path) -> Arc<Mutex<Store>> {
    Arc::new(Mutex::new(
        Store::open(&kernel_core::store_path(home)).unwrap(),
    ))
}

/// Start the loopback `aux-fakemail` simulator; returns its IMAP port and CA.
fn start_mailbox(dir: &Path, mailbox: &[StoredMail]) -> (u16, std::path::PathBuf) {
    let sim_dir = dir.join("sim");
    std::fs::create_dir_all(&sim_dir).unwrap();
    std::fs::write(
        sim_dir.join("mailbox.json"),
        serde_json::to_vec(mailbox).unwrap(),
    )
    .unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let server = runtime
            .block_on(serve(SimConfig {
                dir: sim_dir,
                imap_port: 0,
                smtp_port: 0,
            }))
            .unwrap();
        tx.send((server.imap_port, server.ca_file.clone())).unwrap();
        loop {
            std::thread::park();
        }
    });
    rx.recv_timeout(Duration::from_secs(30))
        .expect("the simulator started")
}

/// P1: every IMAP host is loopback, so Private refreshes the timeline and the
/// client's mail lands on her card.
#[test]
fn private_mode_refreshes_the_timeline_from_a_loopback_mailbox() {
    let (dir, home) = open_home();
    let mailbox = vec![StoredMail {
        uid: 1,
        message_id: "<p1@mailsim.test>".to_string(),
        subject: "Fictional kickoff agenda".to_string(),
        from: "Mira Fictive <mira@lumenworks.example>".to_string(),
        to: vec!["Owner <owner@mailsim.test>".to_string()],
        cc: Vec::new(),
        date: "Mon, 6 Oct 2025 09:00:00 +0000".to_string(),
        body: "From: Mira\r\n\r\nbody\r\n".to_string(),
        flags: Vec::new(),
        in_reply_to: None,
        ..StoredMail::default()
    }];
    let (port, ca_file) = start_mailbox(dir.path(), &mailbox);
    write_accounts(
        &home,
        "private",
        &[Account {
            id: ACCOUNT,
            host: "127.0.0.1",
            port,
            ca_file: Some(&ca_file),
        }],
    );
    let store = open_store(&home);
    let party = {
        let guard = store.lock().unwrap();
        Crm::new(&guard)
            .create(NewParty {
                kind: PartyKind::Person,
                display_name: "Mira Fictive".to_string(),
                name_variants: vec!["Mira Fictive".to_string()],
                emails: vec!["mira@lumenworks.example".to_string()],
                phones: Vec::new(),
                addresses: Vec::new(),
                tags: Vec::new(),
                notes: String::new(),
                time_zone: None,
                origin: "owner".to_string(),
            })
            .unwrap()
    };

    let summary = auxd::crm::run_job(&home, &store).expect("private + loopback refreshes");

    assert!(summary.contains("1 mail"), "unexpected summary: {summary}");
    let rows = store
        .lock()
        .unwrap()
        .interactions_for_party(party.id)
        .unwrap();
    assert!(rows.iter().any(|row| row.kind == "mail"), "no mail row");
}

/// P2: one remote account makes the whole refresh refuse, before any socket,
/// even to the loopback account (all-or-nothing, as the brief).
#[test]
fn private_mode_refuses_when_any_mailbox_is_remote_and_dials_none() {
    let (_dir, home) = open_home();
    let spy = SpyImap::spawn();
    let (remote, port) = remote_listener();
    for host in ["imap.example.com", "0.0.0.0"] {
        for accounts in [
            vec![
                account(ACCOUNT, "127.0.0.1", spy.port),
                account("remote", host, port),
            ],
            vec![account("remote", host, port)],
        ] {
            write_accounts(&home, "private", &accounts);
            let refused = auxd::crm::run_job(&home, &open_store(&home)).expect_err("refused");
            assert_eq!(refused, auxd::crm::PRIVATE_REFUSAL);
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(spy.connections(), 0, "the loopback account was dialled");
    assert!(remote.accept().is_err(), "the remote host was dialled");
}

/// P3a: the mode is open for the up-front check and private from the next read
/// on. The remote account gets no password at the last step and is never
/// dialled.
#[test]
fn a_switch_to_private_between_the_check_and_the_dial_opens_no_connection() {
    let (_dir, home) = open_home();
    let (remote, port) = remote_listener();
    write_accounts(&home, "open", &[account("remote", "0.0.0.0", port)]);
    let store = open_store(&home);

    let reads = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reads);
    let mode: ModeFn = Arc::new(move || {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            PrivacyMode::Open
        } else {
            PrivacyMode::Private
        }
    });

    let result = auxd::crm::run_job_with_mode(&home, &store, &mode);

    assert!(result.is_err(), "the refresh cannot succeed: {result:?}");
    assert!(
        reads.load(Ordering::SeqCst) >= 2,
        "the dial gate read the mode"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert!(remote.accept().is_err(), "the remote host was dialled");
}

/// P3b: Private stays, but the config turns remote right after the check
/// reads the mode. The dial uses the host that was checked, never the new one.
#[test]
fn a_config_turning_remote_after_the_check_never_dials_the_remote_host() {
    let (_dir, home) = open_home();
    let spy = SpyImap::spawn();
    let (remote, remote_port) = remote_listener();
    write_config(&home, spy.port, "private");
    let store = open_store(&home);

    let flipped = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&flipped);
    let target = home.clone();
    let mode: ModeFn = Arc::new(move || {
        if !flag.swap(true, Ordering::SeqCst) {
            write_accounts(
                &target,
                "private",
                &[account(ACCOUNT, "0.0.0.0", remote_port)],
            );
        }
        PrivacyMode::Private
    });

    let result = auxd::crm::run_job_with_mode(&home, &store, &mode);

    assert!(result.is_err(), "the spy is not a real IMAP server");
    assert!(flipped.load(Ordering::SeqCst), "the mode was read");
    std::thread::sleep(Duration::from_millis(200));
    assert!(remote.accept().is_err(), "the remote host was dialled");
}

/// P4: a mail config that does not parse is not local: Private refuses.
#[test]
fn private_mode_refuses_an_unparsable_mail_config() {
    let (_dir, home) = open_home();
    let spy = SpyImap::spawn();
    write_config(&home, spy.port, "private");
    let config = std::fs::read_to_string(kernel_core::config_path(&home)).unwrap();
    std::fs::write(
        kernel_core::config_path(&home),
        config.replace("only_folders", "surprise = 1\nonly_folders"),
    )
    .unwrap();
    let store = open_store(&home);

    let refused = auxd::crm::run_job(&home, &store).expect_err("unparsable refuses");

    assert_eq!(refused, auxd::crm::PRIVATE_REFUSAL);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(spy.connections(), 0, "an unparsable config was dialled");
}

/// P6: the kill switch still refuses in both modes, before any socket.
#[test]
fn the_kill_switch_refuses_the_refresh_in_both_modes() {
    let (_dir, home) = open_home();
    let spy = SpyImap::spawn();
    let store = open_store(&home);
    kernel_core::killswitch::engage(&home).unwrap();
    for mode in ["private", "open"] {
        write_config(&home, spy.port, mode);
        let refused = auxd::crm::run_job(&home, &store).expect_err("stopped");
        assert_eq!(refused, "stopped by kill switch", "mode {mode}");
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(spy.connections(), 0, "a stopped refresh dialled");
}

/// P5: Open mode reaches the dial exactly as before; the spy is not a real
/// IMAP server, so the exchange then fails.
#[test]
fn open_mode_still_dials_the_configured_mailbox() {
    let (_dir, home) = open_home();
    let spy = SpyImap::spawn();
    write_config(&home, spy.port, "open");
    let open = auxd::crm::run_job(&home, &open_store(&home));
    assert!(
        spy.connections() >= 1 || spy.wait_for_dial(),
        "open mode must still dial the configured mailbox"
    );
    let open_error = open.expect_err("the spy endpoint is not a real IMAP server");
    assert!(
        !open_error.contains("not available in private mode"),
        "open mode must not take the private branch: {open_error}"
    );
}
