//! `aux chat` through a running `auxd`: the turn goes to its chat API
//! (`POST /v1/threads/<agent|id>/messages`), so it gets the app's agent, tools,
//! delegation, approvals and privacy mode. An approval card is never answered
//! from here: a new pending card ends the command with a pointer to the app.

use std::collections::HashSet;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use kernel_core::{auxesis_home, config_path, Config, Lang};
use serde_json::Value;

use super::ChatArgs;

const POLL: Duration = Duration::from_millis(500);
const REQUEST: Duration = Duration::from_secs(5);
/// A backstop only: the daemon's own turn and approval deadlines end a turn first.
const TURN: Duration = Duration::from_secs(6 * 3600);

pub fn choose(lang: Lang, fr: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Fr => fr,
        Lang::En => en,
    }
}

struct Daemon {
    client: reqwest::Client,
    url: String,
    token: String,
}

impl Daemon {
    /// The daemon, when a loopback endpoint, its token and a healthy answer exist;
    /// `Ok(None)` only when this home has no token or nothing listens. A daemon that
    /// answers but refuses this CLI, or a token file we cannot use, is an error:
    /// falling back would run the turn without the daemon's approvals.
    async fn connect(home: &Path) -> Result<Option<Self>, String> {
        let Ok(endpoint) = kernel_core::resolve_client_endpoint(&[]) else {
            return Ok(None);
        };
        // Literal loopback only: `localhost` is a name a resolver could repoint.
        let host = endpoint.host.trim_matches(['[', ']']);
        let loopback = host.parse::<std::net::IpAddr>().is_ok_and(|ip| {
            ip == std::net::Ipv4Addr::LOCALHOST || ip == std::net::Ipv6Addr::LOCALHOST
        });
        if !endpoint.has_endpoint() || !loopback {
            return Ok(None);
        }
        let client = reqwest::Client::builder()
            // A fixed loopback URL: no redirect off it, no proxy to carry the token.
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .build()
            .map_err(|err| format!("no HTTP client: {err}"))?;
        // No token file: this home has no daemon of its own, so chat alone.
        if !home.join("api.token").exists() {
            return Ok(None);
        }
        let token = read_token(home);
        let mut health = client
            .get(format!("{}/v1/health", endpoint.url))
            .timeout(REQUEST);
        if let Some(token) = &token {
            health = health.bearer_auth(token);
        }
        let Ok(health) = health.send().await else {
            return Ok(None);
        };
        let status = health.status();
        match token {
            Some(token) if status.is_success() => Ok(Some(Self {
                client,
                url: endpoint.url,
                token,
            })),
            _ => Err(format!(
                "auxd is running but refused this CLI (HTTP {status}); check ~/.auxesis/api.token (yours, mode 0600)"
            )),
        }
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{path}", self.url);
        self.client
            .get(url)
            .bearer_auth(&self.token)
            .timeout(REQUEST)
    }

    async fn pending(&self) -> HashSet<String> {
        let Ok(response) = self.get("/v1/approvals").send().await else {
            return HashSet::new();
        };
        let body = response.text().await.unwrap_or_default();
        let cards: Value = serde_json::from_str(&body).unwrap_or_default();
        let ids = cards.as_array().into_iter().flatten();
        ids.filter_map(|card| card["id"].as_str().map(str::to_string))
            .collect()
    }

    /// Send one message to `thread`; returns the answer and the thread id. A new
    /// approval card is announced once and the request stays open: it is the
    /// owner's to answer in the app, and a dropped request would retire it.
    async fn send(&self, thread: &str, text: &str) -> Result<(String, String), String> {
        let before = self.pending().await;
        let post = self.post(thread, text);
        tokio::pin!(post);
        let mut tick = tokio::time::interval(POLL);
        let mut announced = false;
        loop {
            tokio::select! {
                reply = &mut post => return reply,
                _ = tick.tick(), if !announced => if !self.pending().await.is_subset(&before) {
                    announced = true;
                    let _ = writeln!(std::io::stderr(), "waiting for your approval in the app");
                },
            }
        }
    }

    /// Start a new chat session for `thread`'s agent; returns its id.
    async fn new_thread(&self, thread: &str) -> Result<String, String> {
        let response = self
            .client
            .post(format!("{}/v1/threads/{thread}/new", self.url))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|err| format!("request to auxd failed: {err}"))?;
        let status = response.status();
        let value: Value =
            serde_json::from_str(&response.text().await.unwrap_or_default()).unwrap_or_default();
        match value["id"].as_i64() {
            Some(id) if status.is_success() => Ok(id.to_string()),
            _ => Err(value["error"]["message"]
                .as_str()
                .map_or_else(|| format!("auxd answered HTTP {status}"), str::to_string)),
        }
    }

    async fn post(&self, thread: &str, text: &str) -> Result<(String, String), String> {
        let response = self
            .client
            .post(format!("{}/v1/threads/{thread}/messages", self.url))
            .bearer_auth(&self.token)
            .header("content-type", "application/json")
            .body(serde_json::json!({ "content": text }).to_string())
            .timeout(TURN)
            .send()
            .await
            .map_err(|err| format!("request to auxd failed: {err}"))?;
        let status = response.status();
        let value: Value =
            serde_json::from_str(&response.text().await.unwrap_or_default()).unwrap_or_default();
        if !status.is_success() {
            let message = value["error"]["message"].as_str();
            return Err(
                message.map_or_else(|| format!("auxd answered HTTP {status}"), str::to_string)
            );
        }
        let messages = value["messages"].as_array().into_iter().flatten().rev();
        let answer = messages
            .filter(|message| message["role"] == "assistant")
            .filter_map(|message| message["content"].as_str())
            .find(|content| !content.trim().is_empty())
            .unwrap_or_default();
        let id = value["thread"]["id"]
            .as_i64()
            .ok_or("auxd sent no thread id")?;
        let answer = kernel_broker::sanitize_external_text(answer, 1024 * 1024);
        Ok((answer, id.to_string()))
    }
}

pub(super) fn is_available() -> bool {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    match runtime.block_on(Daemon::connect(&auxesis_home())) {
        Ok(Some(_)) | Err(_) => true,
        Ok(None) => false,
    }
}

/// `aux chat` through the daemon, or `None` when no daemon listens.
pub fn try_run(args: &ChatArgs) -> Option<ExitCode> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let home = auxesis_home();
    let daemon = match runtime.block_on(Daemon::connect(&home)) {
        Ok(daemon) => daemon?,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "aux chat: {message}");
            return Some(ExitCode::FAILURE);
        }
    };
    Some(match runtime.block_on(chat(&daemon, args, &home)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "aux chat: {message}");
            ExitCode::FAILURE
        }
    })
}

async fn chat(daemon: &Daemon, args: &ChatArgs, home: &Path) -> Result<(), String> {
    // A refusal, never a silent ignore: the daemon keeps its own approvals and brains.
    if args.auto_approve || args.provider.is_some() {
        let flag = if args.auto_approve {
            "--auto-approve"
        } else {
            "--provider"
        };
        let why = "does not exist with auxd: approvals and the brain are set in the app";
        return Err(format!("{flag} {why}"));
    }
    let mut thread = match &args.agent {
        Some(agent) => agent.clone(),
        None => {
            let config = Config::load_or_create(&config_path(home));
            config.map_err(|err| err.to_string())?.default_agent
        }
    };
    if args.new {
        thread = daemon.new_thread(&thread).await?;
    }
    if let Some(message) = &args.message {
        return turn(daemon, &mut thread, message).await;
    }
    loop {
        let _ = write!(std::io::stderr(), "> ");
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
            return Ok(());
        }
        match line.trim() {
            "" => {}
            "exit" | "quit" | ":q" | "/exit" | "/quit" => return Ok(()),
            input => turn(daemon, &mut thread, input).await?,
        }
    }
}

async fn turn(daemon: &Daemon, thread: &mut String, text: &str) -> Result<(), String> {
    let (answer, id) = daemon.send(thread, text).await?;
    *thread = id;
    if !answer.is_empty() {
        let _ = writeln!(std::io::stdout(), "{answer}");
    }
    Ok(())
}

/// Read the daemon token (`<home>/api.token`) without creating it.
fn read_token(home: &Path) -> Option<String> {
    let verified = kernel_core::verified_home_or_verify(home).ok()?;
    token_from(
        verified
            .open_read_existing(Path::new("api.token"), 4096)
            .ok()?,
    )
}

/// The token in an opened file, only when that very descriptor is ours and
/// private: owned by this user, no group or other permission bits.
fn token_from(mut file: std::fs::File) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().ok()?;
    // SAFETY: `getuid` takes no arguments and cannot fail.
    if meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
        return None;
    }
    let mut token = String::new();
    file.read_to_string(&mut token).ok()?;
    let token = token.trim();
    (!token.is_empty() && token.len() <= 256).then(|| token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn token_file(mode: u32) -> (tempfile::TempDir, std::fs::File) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.token");
        std::fs::write(&path, "secret-token\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        (dir, std::fs::File::open(path).unwrap())
    }

    #[test]
    fn only_an_owner_private_token_file_is_read() {
        let (_dir, private) = token_file(0o600);
        assert_eq!(token_from(private).as_deref(), Some("secret-token"));
        for mode in [0o644, 0o640, 0o604] {
            let (_dir, shared) = token_file(mode);
            assert_eq!(token_from(shared), None, "mode {mode:o} was read");
        }
    }
}
