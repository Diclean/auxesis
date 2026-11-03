//! GLM-P1-1 regression (J-02 round 4): after `auxd` verified its home, a
//! same-uid actor renames the home and plants a symlink to a decoy. Every
//! state re-open (kill switch, audit, config, store) must re-verify the
//! identity and fail closed — the decoy must gain **no** `store.db`,
//! `config.toml` or `STOP`.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn wait_for_api_port(child: &mut Child, timeout: Duration) -> Option<u16> {
    let stdout = child.stdout.take()?;
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Some(rest) = line.split("auxd api on http://127.0.0.1:").nth(1) {
                let port = rest
                    .split_whitespace()
                    .next()
                    .and_then(|raw| raw.parse::<u16>().ok());
                let _ = sender.send(port);
                return;
            }
        }
        let _ = sender.send(None);
    });
    receiver.recv_timeout(timeout).ok().flatten()
}

#[test]
fn a_home_swap_after_start_never_redirects_state_writes() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join(".auxesis");
    let mut child = common::sandbox_command(env!("CARGO_BIN_EXE_auxd"), dir.path(), &home)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let port = wait_for_api_port(&mut child, Duration::from_secs(10))
        .expect("auxd must announce its API port");
    let token = std::fs::read_to_string(home.join("api.token")).expect("api.token");

    // The breaker's swap: the verified home is renamed and replaced by a
    // symlink to an empty decoy (never the real home).
    let decoy = dir.path().join("decoy");
    std::fs::create_dir_all(&decoy).unwrap();
    let original = dir.path().join("home.orig");
    std::fs::rename(&home, &original).unwrap();
    std::os::unix::fs::symlink(&decoy, &home).unwrap();
    // Copy the token into the decoy too, so auth can never be the thing that
    // stops the write.
    std::fs::copy(original.join("api.token"), decoy.join("api.token")).unwrap();

    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    let response = common::post(addr, "/v1/stop-all", Some(&token), "{}");
    assert!(
        response.status >= 500,
        "a swapped home must fail closed, got HTTP {} ({})",
        response.status,
        response.body
    );
    assert!(
        !decoy.join("store.db").exists(),
        "the decoy must not gain store.db"
    );
    assert!(
        !decoy.join("config.toml").exists(),
        "the decoy must not gain config.toml"
    );
    assert!(
        !decoy.join("STOP").exists(),
        "the decoy must not gain the kill switch"
    );

    let _ = child.kill();
    let _ = child.wait();
}
