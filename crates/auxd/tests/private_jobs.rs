//! A scheduled agent job in private mode runs exactly like a private
//! chat turn (F1). The real `auxd` binary is spawned in a throwaway home with a
//! loopback OpenAI-compatible provider that records every request body. The
//! prompt carries a fictional contact's name, an e-mail address, an IBAN and a
//! phone number. None may reach the provider raw; the run's summary, kept only
//! in the local store, holds the rehydrated text.
//!
//! Sandbox only: temp home, loopback listener, fictional `*.invalid` data. No
//! Keychain, launchd or real network.

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aux_store::{ContactRecord, Store, RUN_OK};
use kernel_core::{config_path, store_path};

const NAME: &str = "Camille Exemple";
const EMAIL: &str = "camille.exemple@example.invalid";
const IBAN: &str = "FR7630006000011234567890189";
const PHONE: &str = "+33612345678";
const TIMEOUT: Duration = Duration::from_secs(20);

/// A loopback OpenAI-compatible server. It records each request body and
/// answers with every `⟦…⟧` token the request held, so the daemon's local
/// rehydration of the answer can be checked.
struct RecordingProvider {
    uri: String,
    bodies: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    addr: std::net::SocketAddr,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RecordingProvider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_bodies, thread_stop) = (Arc::clone(&bodies), Arc::clone(&stop));
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if thread_stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let body = read_request_body(&mut stream);
                let reply = tokens_of(&body).join(" ");
                thread_bodies.lock().unwrap().push(body);
                let json = serde_json::json!({
                    "choices": [{"message": {"role": "assistant", "content": format!("Noted: {reply}")}}]
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{json}",
                    json.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            uri: format!("http://{addr}"),
            bodies,
            stop,
            addr,
            handle: Some(handle),
        }
    }

    fn bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }
}

impl Drop for RecordingProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The body of one HTTP request: headers up to the blank line, then
/// `content-length` bytes.
fn read_request_body(stream: &mut std::net::TcpStream) -> String {
    let mut data = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let Some(split) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return String::new(),
                Ok(n) => data.extend_from_slice(&chunk[..n]),
            }
            continue;
        };
        let head = String::from_utf8_lossy(&data[..split]).to_ascii_lowercase();
        let length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        while data.len() < split + 4 + length {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => data.extend_from_slice(&chunk[..n]),
            }
        }
        return String::from_utf8_lossy(&data[split + 4..]).into_owned();
    }
}

/// Every distinct `⟦…⟧` token in `text`, in order.
fn tokens_of(text: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('⟦') {
        let Some(len) = rest[start..].find('⟧') else {
            break;
        };
        let end = start + len + '⟧'.len_utf8();
        let token = rest[start..end].to_string();
        if !tokens.contains(&token) {
            tokens.push(token);
        }
        rest = &rest[end..];
    }
    tokens
}

struct Sandbox {
    dir: tempfile::TempDir,
    home: PathBuf,
}

impl Sandbox {
    /// A private home whose only provider is the loopback recorder.
    fn private(provider: &RecordingProvider) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            config_path(&home),
            format!(
                "version = 1\ndefault_agent = \"main\"\n\n[privacy]\nmode = \"private\"\n\n\
                 [[providers]]\nid = \"local\"\nbase_url = \"{}/v1\"\n\
                 model = \"test-model\"\nkind = \"openai-compat\"\n",
                provider.uri
            ),
        )
        .unwrap();
        Self { dir, home }
    }

    fn store(&self) -> Store {
        Store::open(&store_path(&self.home)).unwrap()
    }

    /// Import the fictional contact, as `aux contacts import` would.
    fn import_camille(&self) {
        self.store()
            .replace_source_contacts(
                "file:contacts.vcf",
                &[ContactRecord {
                    source: "file:contacts.vcf".to_string(),
                    display_name: Some(NAME.to_string()),
                    given: vec!["Camille".to_string()],
                    family: vec!["Exemple".to_string()],
                    emails: vec![EMAIL.to_string()],
                    phones: vec![PHONE.to_string()],
                    ..ContactRecord::default()
                }],
            )
            .unwrap();
    }

    /// Create one agent job, due now, then spawn the daemon on it.
    fn run_job(&self, prompt: &str) -> (Child, i64) {
        let job = self
            .store()
            .create_job(
                "main",
                "nightly",
                "every 1h",
                &serde_json::json!({ "kind": "agent", "prompt": prompt }).to_string(),
                Some("2000-01-01 00:00:00"),
            )
            .unwrap();
        let child =
            common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), self.dir.path(), &self.home)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
        (child, job.id)
    }
}

/// The finished run's `(status, summary)`, or `None` after the timeout.
fn wait_for_run(store: &Store, job_id: i64) -> Option<(String, String)> {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if let Some(run) = store
            .runs_for_job(job_id)
            .unwrap()
            .into_iter()
            .find(|run| run.status != aux_store::RUN_RUNNING)
        {
            return Some((run.status, run.summary.unwrap_or_default()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn stop(mut child: Child) -> String {
    let _ = child.kill();
    let _ = child.wait();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    stderr
}

#[test]
fn a_private_job_sends_no_raw_value_and_keeps_the_rehydrated_result_local() {
    let provider = RecordingProvider::start();
    let sandbox = Sandbox::private(&provider);
    sandbox.import_camille();
    let prompt = format!("Draft a note for {NAME} ({EMAIL}, {PHONE}). Refund to {IBAN}.");
    let (child, job_id) = sandbox.run_job(&prompt);

    let finished = wait_for_run(&sandbox.store(), job_id);
    let stderr = stop(child);
    let (status, summary) =
        finished.unwrap_or_else(|| panic!("the private job never finished; stderr: {stderr}"));

    assert_eq!(status, RUN_OK, "a private job runs (F1 covered): {summary}");
    let bodies = provider.bodies();
    assert!(!bodies.is_empty(), "the job sent no provider request");
    for body in &bodies {
        // A name is not a hidden value.
        for raw in [EMAIL, IBAN, PHONE, "6 12 34 56 78"] {
            assert!(
                !body.contains(raw),
                "raw `{raw}` reached the provider: {body}"
            );
        }
    }
    let wire = bodies.join("\n");
    for marker in ["⟦EMAIL_", "⟦PHONE_", "⟦IBAN_"] {
        assert!(wire.contains(marker), "{marker} missing from the wire copy");
    }
    // The provider echoed only tokens: the stored result is the local,
    // rehydrated text, with no token left in it.
    assert!(
        !summary.contains('⟦'),
        "an unresolved token in the result: {summary}"
    );
    assert!(summary.contains(EMAIL), "address not rehydrated: {summary}");
    // A private run stores no title, and its rows hold tokens, never a hidden value
    // (G1, PRIVATE-TRANSCRIPT). Names are not hidden (NAMES-OFF), so NAME is not checked.
    let store = sandbox.store();
    for session in store.list_sessions().unwrap() {
        assert_eq!(session.title, None, "no title in private mode");
        for row in store.list_messages(session.id).unwrap() {
            for raw in [EMAIL, IBAN, PHONE] {
                assert!(!row.content.contains(raw), "a value was stored: {row:?}");
            }
        }
    }
}

/// With no contacts the private gate still runs: pattern values (e-mail, IBAN,
/// phone) are masked and nothing is refused. Needs TOK-1 (a private gate
/// without a name dictionary tokenises instead of refusing).
#[test]
fn a_private_job_with_no_contacts_still_runs_and_masks_pattern_values() {
    let provider = RecordingProvider::start();
    let sandbox = Sandbox::private(&provider);
    let prompt = format!("Write to {EMAIL} or {PHONE}. Refund to {IBAN}.");
    let (child, job_id) = sandbox.run_job(&prompt);

    let finished = wait_for_run(&sandbox.store(), job_id);
    let stderr = stop(child);
    let (status, summary) =
        finished.unwrap_or_else(|| panic!("the private job never finished; stderr: {stderr}"));

    assert_eq!(
        status, RUN_OK,
        "no contacts must not block the job: {summary}"
    );
    let bodies = provider.bodies();
    assert!(!bodies.is_empty(), "the job sent no provider request");
    for body in &bodies {
        for raw in [EMAIL, IBAN, PHONE] {
            assert!(
                !body.contains(raw),
                "raw `{raw}` reached the provider: {body}"
            );
        }
    }
}
