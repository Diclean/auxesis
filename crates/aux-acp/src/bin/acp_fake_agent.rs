//! Test-only fake ACP agent (A0 fixtures).
//!
//! Speaks real JSON-RPC 2.0 over stdio: `initialize`, `session/new`,
//! `session/prompt` with streamed `session/update` notifications, and the
//! client-side requests (`session/request_permission`, `fs/*`,
//! `terminal/*`). Scenarios are selected by the first argument; see
//! `tests/acp_integration.rs`.
//!
//! This binary is only built for tests and the example smoke path; it is not
//! part of the daemon.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::time::Duration;

struct Agent {
    reader: BufReader<std::io::Stdin>,
    out: std::io::Stdout,
    next_id: i64,
    session: String,
    /// Responses to our own requests, keyed by id.
    responses: HashMap<i64, Value>,
}

impl Agent {
    fn send(&mut self, value: &Value) {
        let line = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
        let _ = writeln!(self.out, "{line}");
        let _ = self.out.flush();
    }

    fn respond(&mut self, id: &Value, result: Value) {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
    }

    fn respond_error(&mut self, id: &Value, code: i64, message: &str) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": code, "message": message}
        }));
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    fn update(&mut self, update: Value) {
        self.notify(
            "session/update",
            json!({"sessionId": self.session, "update": update}),
        );
    }

    fn chunk(&mut self, text: &str) {
        self.update(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": text}
        }));
    }

    fn read_frame(&mut self) -> Option<Value> {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) | Err(_) => return None,
                Ok(_) => {}
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            return serde_json::from_str(trimmed).ok();
        }
    }

    /// Send a request and wait for its response, servicing client frames
    /// (cancel notifications, stray responses) meanwhile.
    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        }));
        self.read_response(id)
    }

    /// Wait for the response to `id`, servicing client frames meanwhile.
    fn read_response(&mut self, id: i64) -> Value {
        if let Some(response) = self.responses.remove(&id) {
            return response;
        }
        loop {
            let Some(frame) = self.read_frame() else {
                return json!({"__closed": true});
            };
            if let Some(response_id) = frame.get("id").and_then(Value::as_i64) {
                if response_id == id {
                    return frame;
                }
                self.responses.insert(response_id, frame);
                continue;
            }
            self.handle_client_frame(&frame);
        }
    }

    fn handle_client_frame(&mut self, frame: &Value) {
        match frame.get("method").and_then(Value::as_str) {
            Some("session/cancel") => {}
            Some(other) => {
                if let Some(id) = frame.get("id") {
                    let id = id.clone();
                    self.respond_error(&id, -32601, &format!("unsupported method {other}"));
                }
            }
            None => {}
        }
    }

    fn result_text(&self, response: &Value) -> String {
        if let Some(error) = response.get("error") {
            return format!(
                "error:{}",
                error.get("code").and_then(Value::as_i64).unwrap_or(0)
            );
        }
        let result = response.get("result").cloned().unwrap_or(Value::Null);
        result.to_string()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scenario = args.get(1).cloned().unwrap_or_else(|| "happy".to_string());
    let scenario_arg = args.get(2).cloned();
    if let Err(err) = run(&scenario, scenario_arg.as_deref()) {
        eprintln!("acp-fake-agent: {err}");
        std::process::exit(2);
    }
}

fn run(scenario: &str, arg: Option<&str>) -> Result<(), String> {
    if scenario == "orphan-mid" {
        // Hidden helper: the middle process of the GLM round-2 repro. It
        // forks a grandchild that closes every fd, starts its own session and
        // leaves the workspace, then exits immediately, so the sampler can
        // never see the grandchild under the agent.
        let pidfile = arg.unwrap_or("/nonexistent");
        // python3 is the mainstream grandchild the GLM repro used, and its
        // environment stays readable on macOS (unlike platform binaries).
        let mut command = std::process::Command::new("python3");
        command
            .args(["-c", "import time; time.sleep(300)"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(unix)]
        unsafe {
            use std::os::unix::process::CommandExt;
            command.pre_exec(|| {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let max = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                    limit.rlim_cur.min(4096) as i32
                } else {
                    256
                };
                for fd in 3..max {
                    libc::close(fd);
                }
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::chdir(c"/".as_ptr());
                Ok(())
            });
        }
        if let Ok(child) = command.spawn() {
            use std::io::Write;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(pidfile)
            {
                let _ = writeln!(file, "{}", child.id());
            }
            drop(child);
        }
        std::process::exit(0);
    }
    let mut agent = Agent {
        reader: BufReader::new(std::io::stdin()),
        out: std::io::stdout(),
        next_id: 1,
        session: "sess-1".to_string(),
        responses: HashMap::new(),
    };
    if scenario == "stderr-secret" {
        // A secret-shaped value on stderr: the supervisor must scrub it
        // before storing or logging.
        eprintln!("token=sk-abcdefghijklmnopqrstuvwxyz012345");
    }
    loop {
        let Some(frame) = agent.read_frame() else {
            return Ok(());
        };
        let method = frame.get("method").and_then(Value::as_str);
        let id = frame.get("id").cloned().unwrap_or(Value::Null);
        match method {
            Some("initialize") => agent.respond(
                &id,
                json!({
                    "protocolVersion": 1,
                    "agentCapabilities": {"loadSession": false},
                    "authMethods": [],
                }),
            ),
            Some("session/new") => agent.respond(&id, json!({"sessionId": agent.session.clone()})),
            Some("session/prompt") => {
                let outcome = prompt(&mut agent, scenario, arg, &id, &frame);
                if outcome == PromptFlow::EndTurn {
                    agent.respond(&id, json!({"stopReason": "end_turn"}));
                }
            }
            Some("session/cancel") => {}
            Some(other) if frame.get("id").is_some() => {
                agent.respond_error(&id, -32601, &format!("unsupported method {other}"));
            }
            Some(_) => {}
            None => {}
        }
    }
}

#[derive(PartialEq)]
enum PromptFlow {
    EndTurn,
    /// The scenario already answered the prompt itself.
    Answered,
}

/// Run one prompt scenario. Returns how the main loop should answer it, or
/// answers inside when the scenario manages its own response.
fn prompt(
    agent: &mut Agent,
    scenario: &str,
    arg: Option<&str>,
    id: &Value,
    frame: &Value,
) -> PromptFlow {
    match scenario {
        "echo" => {
            // Answer with the prompt the agent received, so a test can read it back.
            let text = frame
                .pointer("/params/prompt/0/text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            agent.chunk(&format!("echo:{text}"));
            PromptFlow::EndTurn
        }
        "private-probe" => {
            // The arg is a file path in the workspace; the agent notes what the host
            // served it next to that file, then asks permission with the first
            // token it saw and echoes everything back as its answer.
            let note = std::path::PathBuf::from(arg.unwrap_or("/nonexistent"));
            let prompt = frame
                .pointer("/params/prompt/0/text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let read = agent.call(
                "fs/read_text_file",
                json!({"sessionId": agent.session, "path": note}),
            );
            let content = read
                .pointer("/result/content")
                .and_then(Value::as_str)
                .unwrap_or("read-error")
                .to_string();
            // The first token the host showed it, in the prompt or else the file.
            let seen = format!("{prompt}\n{content}");
            let token = seen
                .find('\u{27e6}')
                .and_then(|start| {
                    seen[start..]
                        .find('\u{27e7}')
                        .map(|end| seen[start..start + end + '\u{27e7}'.len_utf8()].to_string())
                })
                .unwrap_or_default();
            let permission = agent.call(
                "session/request_permission",
                json!({
                    "sessionId": agent.session,
                    "toolCall": {"toolCallId": "t1", "title": format!("Share {token}"), "kind": "other",
                                 "rawInput": {"who": token}},
                    "options": [{"optionId": "a1", "kind": "allow_once", "name": "Allow once"},
                                {"optionId": "r1", "kind": "reject_once", "name": "Reject"}]
                }),
            );
            let env = |name: &str| std::env::var(name).unwrap_or_else(|_| "unset".to_string());
            let received = format!(
                "prompt={prompt}\nfile={content}\npermission={permission}\ncwd={}\nnote_env={}\nkey_env={}",
                std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default(),
                env("ACP_PROBE_NOTE"),
                env("ACP_PROBE_API_KEY"),
            );
            let _ = std::fs::write(note.with_extension("received"), &received);
            agent.chunk(&format!("prompt={prompt}\nfile={content}"));
            PromptFlow::EndTurn
        }
        "happy" => {
            agent.chunk("hello ");
            agent.chunk("world");
            agent.update(json!({"sessionUpdate": "usage_update", "used": 42, "size": 1000}));
            PromptFlow::EndTurn
        }
        "tool" => {
            agent.chunk("working");
            agent.update(json!({
                "sessionUpdate": "tool_call",
                "toolCallId": "t1",
                "title": "Run the tests",
                "kind": "execute",
                "status": "pending",
                "rawInput": {"command": "cargo test"}
            }));
            agent.update(json!({
                "sessionUpdate": "tool_call_update",
                "toolCallId": "t1",
                "status": "completed",
                "rawOutput": {"exit": 0}
            }));
            agent.chunk("done");
            PromptFlow::EndTurn
        }
        "plan" => {
            agent.update(json!({
                "sessionUpdate": "plan",
                "entries": [{"content": "step one", "priority": "high", "status": "in_progress"}]
            }));
            agent.chunk("planned");
            PromptFlow::EndTurn
        }
        "permission" => {
            agent.chunk("deciding");
            let response = agent.call(
                "session/request_permission",
                json!({
                    "sessionId": agent.session,
                    "toolCall": {
                        "toolCallId": "t1",
                        "title": "Delete the file",
                        "kind": "edit",
                        "rawInput": {"path": "/tmp/x"}
                    },
                    "options": [
                        {"optionId": "a1", "kind": "allow_once", "name": "Allow once"},
                        {"optionId": "a2", "kind": "allow_always", "name": "Always"},
                        {"optionId": "r1", "kind": "reject_once", "name": "Reject"},
                        {"optionId": "r2", "kind": "reject_always", "name": "Never"}
                    ]
                }),
            );
            let outcome = response
                .get("result")
                .and_then(|result| result.get("outcome"))
                .cloned()
                .unwrap_or(Value::Null);
            agent.chunk(&format!("outcome={}", outcome));
            if outcome.get("outcome").and_then(Value::as_str) == Some("cancelled") {
                agent.respond(id, json!({"stopReason": "cancelled"}));
                return PromptFlow::Answered;
            }
            PromptFlow::EndTurn
        }
        "fs-read" => {
            let path = arg.unwrap_or("/nonexistent");
            let response = agent.call(
                "fs/read_text_file",
                json!({"sessionId": agent.session, "path": path}),
            );
            if let Some(content) = response
                .get("result")
                .and_then(|result| result.get("content"))
                .and_then(Value::as_str)
            {
                agent.chunk(&format!("read={content}"));
            } else {
                agent.chunk(&format!("read-error={}", agent.result_text(&response)));
            }
            PromptFlow::EndTurn
        }
        "fs-write" => {
            let path = arg.unwrap_or("/nonexistent");
            let response = agent.call(
                "fs/write_text_file",
                json!({"sessionId": agent.session, "path": path, "content": "written-by-agent"}),
            );
            if response.get("error").is_some() {
                agent.chunk(&format!("write-error={}", agent.result_text(&response)));
            } else {
                agent.chunk("write=ok");
            }
            PromptFlow::EndTurn
        }
        "fs-write-race" => {
            // security-review 1 F1: the owner's approval window is human-sized, so a
            // hostile agent swaps the approved path for a symlink pointing
            // outside the workspace *after* sending the request.
            let args: Vec<String> = arg
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_default();
            let (Some(path), Some(outside)) = (args.first(), args.get(1)) else {
                agent.chunk("fs-write-race=missing-args");
                return PromptFlow::EndTurn;
            };
            let _ = std::fs::write(path, "original");
            let request_id = agent.next_id;
            agent.next_id += 1;
            agent.send(&json!({
                "jsonrpc": "2.0", "id": request_id, "method": "fs/write_text_file",
                "params": {
                    "sessionId": agent.session,
                    "path": path,
                    "content": "PWNED-BY-AGENT",
                }
            }));
            // Let the client resolve and ask for approval, then swap.
            std::thread::sleep(Duration::from_millis(150));
            let _ = std::fs::remove_file(path);
            if std::os::unix::fs::symlink(outside, path).is_ok() {
                agent.chunk("swap=ok");
            } else {
                agent.chunk("swap=failed");
            }
            let response = agent.read_response(request_id);
            if response.get("error").is_some() {
                agent.chunk("write-error");
            } else {
                agent.chunk("write=ok");
            }
            PromptFlow::EndTurn
        }
        "orphan-envmarker" => {
            // GLM round-2 F2 repro: five mid→grandchild sequences where the
            // grandchild closes every fd, setsid()s and chdir()s out of the
            // workspace while the mid exits immediately. The grandchildren
            // keep the per-turn AUXESIS_ACP_TURN environment marker, which is
            // the reaper's anchor.
            let pidfile = arg.unwrap_or("/nonexistent");
            let self_exe = std::env::current_exe().unwrap_or_default();
            for _ in 0..5 {
                let _ = std::process::Command::new(&self_exe)
                    .arg("orphan-mid")
                    .arg(pidfile)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                std::thread::sleep(Duration::from_millis(20));
            }
            std::thread::sleep(Duration::from_millis(100));
            agent.chunk("orphans-started");
            PromptFlow::EndTurn
        }
        "secret-split" => {
            // security review round-2 P2: the registered canary split across consecutive
            // frames of every agent-originated stream.
            agent.chunk("CANARY_ACP_STREAM_0123");
            agent.chunk("456789abcdef");
            agent.update(json!({
                "sessionUpdate": "agent_thought_chunk",
                "content": {"type": "text", "text": "CANARY_ACP_STREAM_0123"}
            }));
            agent.update(json!({
                "sessionUpdate": "agent_thought_chunk",
                "content": {"type": "text", "text": "456789abcdef"}
            }));
            agent.update(json!({
                "sessionUpdate": "tool_call",
                "toolCallId": "t1",
                "title": "split",
                "rawOutput": "CANARY_ACP_STREAM_0123"
            }));
            agent.update(json!({
                "sessionUpdate": "tool_call_update",
                "toolCallId": "t1",
                "rawOutput": "456789abcdef"
            }));
            agent.update(json!({
                "sessionUpdate": "plan",
                "entries": [{"content": "CANARY_ACP_STREAM_0123", "priority": "high", "status": "in_progress"}]
            }));
            agent.update(json!({
                "sessionUpdate": "plan",
                "entries": [{"content": "456789abcdef", "priority": "high", "status": "in_progress"}]
            }));
            PromptFlow::EndTurn
        }
        "fs-read-len" => {
            // Report only the length: the reply must still arrive when the
            // file's JSON-escaped frame would exceed the outbound cap.
            let path = arg.unwrap_or("/nonexistent");
            let response = agent.call(
                "fs/read_text_file",
                json!({"sessionId": agent.session, "path": path}),
            );
            if let Some(content) = response
                .get("result")
                .and_then(|result| result.get("content"))
                .and_then(Value::as_str)
            {
                agent.chunk(&format!("read-len={}", content.len()));
            } else {
                agent.chunk(&format!("read-error={}", agent.result_text(&response)));
            }
            PromptFlow::EndTurn
        }
        "secret-echo" => {
            // The shared scrubber must redact this before it is stored.
            agent.chunk(&format!(
                "token=sk-abcdefghijklmnopqrstuvwxyz012345 secret={}",
                arg.unwrap_or("none")
            ));
            agent.chunk(" tail");
            // The agent-controlled stopReason must be scrubbed as well.
            agent.respond(
                id,
                json!({"stopReason": format!("end_turn secret={}", arg.unwrap_or("none"))}),
            );
            PromptFlow::Answered
        }
        "orphan-fdcless" => {
            // security-review 1 F2: a grandchild that closes every inherited fd
            // (python `close_fds=True` / node `stdio:'ignore'`), starts its
            // own session, and outlives the agent, which exits immediately.
            let mut command = std::process::Command::new("python3");
            command
                .args(["-c", "import time; time.sleep(300)"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            #[cfg(unix)]
            unsafe {
                use std::os::unix::process::CommandExt;
                command.pre_exec(|| {
                    let mut limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    let max = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                        limit.rlim_cur.min(4096) as i32
                    } else {
                        256
                    };
                    for fd in 3..max {
                        libc::close(fd);
                    }
                    if libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            if let Ok(child) = command.spawn() {
                if let Some(path) = arg {
                    let _ = std::fs::write(path, child.id().to_string());
                }
                drop(child); // Never wait: the grandchild is reparented.
            }
            // Give the grandchild a beat to reparent (`os._exit` follows), so
            // the sweep cannot rely on a still-attached ppid walk.
            std::thread::sleep(Duration::from_millis(200));
            agent.chunk("orphan-started");
            agent.respond(id, json!({"stopReason": "end_turn"}));
            let _ = agent.out.flush();
            // Exit hard, like `os._exit(0)`: no destructors, no reaping.
            std::process::exit(0);
        }
        "terminal" => {
            let response = agent.call(
                "terminal/create",
                json!({"sessionId": agent.session, "command": "echo", "args": ["terminal-ok"]}),
            );
            let terminal_id = response
                .get("result")
                .and_then(|result| result.get("terminalId"))
                .and_then(Value::as_str)
                .unwrap_or("missing")
                .to_string();
            let waited = agent.call(
                "terminal/wait_for_exit",
                json!({"sessionId": agent.session, "terminalId": terminal_id}),
            );
            let output = agent.call(
                "terminal/output",
                json!({"sessionId": agent.session, "terminalId": terminal_id}),
            );
            agent.chunk(&format!(
                "exit={} output={}",
                waited
                    .get("result")
                    .and_then(|result| result.get("exitCode"))
                    .and_then(Value::as_i64)
                    .unwrap_or(-1),
                output
                    .get("result")
                    .and_then(|result| result.get("output"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ));
            PromptFlow::EndTurn
        }
        "terminal-echo" => {
            // Runs `echo <arg>` on the host and reports what the host returned.
            let response = agent.call(
                "terminal/create",
                json!({"sessionId": agent.session, "command": "echo", "args": [arg.unwrap_or("")]}),
            );
            let terminal_id = response
                .pointer("/result/terminalId")
                .and_then(Value::as_str)
                .unwrap_or("missing")
                .to_string();
            agent.call(
                "terminal/wait_for_exit",
                json!({"sessionId": agent.session, "terminalId": terminal_id}),
            );
            let output = agent.call(
                "terminal/output",
                json!({"sessionId": agent.session, "terminalId": terminal_id}),
            );
            let output = output
                .pointer("/result/output")
                .and_then(Value::as_str)
                .unwrap_or("no-output");
            agent.chunk(&format!("output={output}"));
            PromptFlow::EndTurn
        }
        "terminal-cmd" => {
            // Runs the whitespace-separated command in the arg on the host and
            // reports its exit code.
            let mut words = arg.unwrap_or("true").split_whitespace();
            let command = words.next().unwrap_or("true");
            let args: Vec<&str> = words.collect();
            let response = agent.call(
                "terminal/create",
                json!({"sessionId": agent.session, "command": command, "args": args}),
            );
            let terminal_id = response
                .pointer("/result/terminalId")
                .and_then(Value::as_str)
                .unwrap_or("missing")
                .to_string();
            let waited = agent.call(
                "terminal/wait_for_exit",
                json!({"sessionId": agent.session, "terminalId": terminal_id}),
            );
            let code = waited
                .pointer("/result/exitCode")
                .and_then(Value::as_i64)
                .unwrap_or(-1);
            agent.chunk(&format!("exit={code}"));
            PromptFlow::EndTurn
        }
        "terminal-marker" => {
            // security-review round 3: a read-only ACP brain must refuse this and
            // never create the marker.
            let marker = arg.unwrap_or("/nonexistent");
            let response = agent.call(
                "terminal/create",
                json!({"sessionId": agent.session, "command": "touch", "args": [marker]}),
            );
            if response.get("error").is_some() {
                agent.chunk(&format!("terminal-error={}", agent.result_text(&response)));
            } else {
                agent.chunk("terminal-ran");
            }
            PromptFlow::EndTurn
        }
        "terminal-kill" => {
            let response = agent.call(
                "terminal/create",
                json!({"sessionId": agent.session, "command": "sh", "args": ["-c", "sleep 300"]}),
            );
            let terminal_id = response
                .get("result")
                .and_then(|result| result.get("terminalId"))
                .and_then(Value::as_str)
                .unwrap_or("missing")
                .to_string();
            let killed = agent.call(
                "terminal/kill",
                json!({"sessionId": agent.session, "terminalId": terminal_id}),
            );
            agent.chunk(&format!("killed={}", killed.get("error").is_none()));
            PromptFlow::EndTurn
        }
        "spawn-child" => {
            // Spawn a child, record its pid, answer cancel, then exit without
            // reaping it: the client's reaper must kill the orphan.
            let child = std::process::Command::new("sleep").arg("300").spawn().ok();
            if let (Some(child), Some(path)) = (&child, arg) {
                let _ = std::fs::write(path, child.id().to_string());
            }
            agent.chunk("child-started");
            loop {
                let Some(frame) = agent.read_frame() else {
                    return PromptFlow::EndTurn;
                };
                if frame.get("method").and_then(Value::as_str) == Some("session/cancel") {
                    break;
                }
            }
            agent.respond(id, json!({"stopReason": "cancelled"}));
            // Leave the child behind on purpose.
            PromptFlow::EndTurn
        }
        "cancel" => {
            agent.chunk("started");
            loop {
                let Some(frame) = agent.read_frame() else {
                    return PromptFlow::EndTurn;
                };
                if frame.get("method").and_then(Value::as_str) == Some("session/cancel") {
                    break;
                }
            }
            agent.respond(id, json!({"stopReason": "cancelled"}));
            // Stay alive: the client must kill the tree.
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        "hang" => {
            if let Some(path) = arg {
                let child = std::process::Command::new("sleep").arg("300").spawn().ok();
                if let Some(child) = child {
                    let _ = std::fs::write(path, child.id().to_string());
                }
            }
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        "malformed" => {
            // Garbage and an oversized frame, then a normal answer: the
            // client must survive both.
            let _ = writeln!(agent.out, "this is not json");
            let _ = writeln!(agent.out, "{}", "x".repeat(2 * 1024 * 1024));
            let _ = agent.out.flush();
            agent.chunk("survived");
            PromptFlow::EndTurn
        }
        "crash" => {
            std::process::exit(1);
        }
        "env" => {
            let aux_keys = std::env::vars()
                .filter(|(name, _)| name.starts_with("AUX_KEY_"))
                .count();
            let home = std::env::var("HOME").unwrap_or_default();
            let tmpdir = std::env::var("TMPDIR").unwrap_or_default();
            let auxesis = std::env::var("AUXESIS_HOME").unwrap_or_default();
            agent.chunk(&format!(
                "aux_keys={aux_keys} home={home} tmpdir={tmpdir} auxesis_home={auxesis}"
            ));
            PromptFlow::EndTurn
        }
        "probe-read" => {
            let path = arg.unwrap_or("/nonexistent");
            match std::fs::read_to_string(path) {
                Ok(_) => agent.chunk("probe=ok"),
                Err(err) => agent.chunk(&format!("probe=denied ({})", err.kind() as i32)),
            }
            PromptFlow::EndTurn
        }
        "stderr-secret" => {
            agent.chunk("ok");
            PromptFlow::EndTurn
        }
        "slow" => {
            std::thread::sleep(Duration::from_secs(30));
            agent.chunk("late");
            PromptFlow::EndTurn
        }
        other => {
            agent.chunk(&format!("unknown scenario {other}"));
            PromptFlow::EndTurn
        }
    }
}
