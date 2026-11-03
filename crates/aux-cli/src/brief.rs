//! `aux brief now` — today's brief from the running daemon, or the offline
//! M0 fixture with `--offline`.

use aux_brief::{
    run_once, BriefClock, BriefResult, FakeBriefSource, SystemBriefClock, MAX_SOURCE_READS,
};
use aux_notify::{system_notifier, Notification, Notifier, StopSwitchNotifier};
use aux_store::Store;
use clap::{Args, Subcommand};
use kernel_core::privacy::{admit_call, Destination, PathId};
use kernel_core::{auxesis_home, config_path, ensure_home, Config, Lang};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use crate::notify::current_mode;

#[derive(Debug, Args)]
pub struct BriefArgs {
    #[command(subcommand)]
    action: BriefAction,
}

#[derive(Debug, Subcommand)]
enum BriefAction {
    /// Generate today's brief now (still respects quiet hours and daily idempotency).
    Now(BriefNowArgs),
    /// Say whether today's brief ran, how, and what happened to its delivery.
    /// Never shows brief content.
    Status,
}

#[derive(Debug, Args)]
pub struct BriefNowArgs {
    /// Build the offline fixture brief inside the CLI instead of asking auxd.
    #[arg(long)]
    pub offline: bool,
}

pub fn run(args: BriefArgs) -> ExitCode {
    let lang = configured_lang(&auxesis_home());
    match args.action {
        BriefAction::Now(args) => run_now(args.offline, lang),
        BriefAction::Status => print_result(status_inner(lang)),
    }
}

fn run_now(offline: bool, lang: Lang) -> ExitCode {
    print_result(if offline {
        run_offline_inner()
    } else {
        run_daemon_inner(lang)
    })
}

fn choose(lang: Lang, fr: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Fr => fr,
        Lang::En => en,
    }
}

/// The `[ui].language` of the home's config, or the system language when the
/// file is missing or unreadable. Never creates the config: a read-only
/// command must not write a home.
fn configured_lang(home: &Path) -> Lang {
    let path = config_path(home);
    if !path.is_file() {
        return Lang::from_env();
    }
    Config::load_or_create(&path)
        .map(|config| config.ui.language)
        .unwrap_or_else(|_| Lang::from_env())
}

fn print_result(result: Result<String, Box<dyn std::error::Error>>) -> ExitCode {
    match result {
        Ok(result) => {
            let _ = writeln!(std::io::stdout(), "{result}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "aux brief: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `aux brief status`: one `GET /v1/brief/status` over loopback.
fn status_inner(lang: Lang) -> Result<String, Box<dyn std::error::Error>> {
    let (url, token) = daemon_target(lang)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let body = runtime.block_on(call_daemon(
        reqwest::Method::GET,
        &url,
        "/v1/brief/status",
        &token,
        lang,
    ))?;
    Ok(render_status(&serde_json::from_str(&body)?, lang))
}

/// The fix for a send Messages refused or never answered (as auxd's status).
const AUTOMATION_FIX: &str =
    "Allow Auxesis to control Messages: System Settings → Privacy & Security → Automation";
const AUTOMATION_FIX_FR: &str =
    "Autorise Auxesis à contrôler Messages : Réglages Système → Confidentialité et sécurité → Automatisation";

/// The status as plain lines. Only the known fields are printed, so a reply
/// that ever carried more could not put brief content on the terminal.
fn render_status(value: &serde_json::Value, lang: Lang) -> String {
    let text = |v: &serde_json::Value| v.as_str().unwrap_or("?").to_string();
    let last = &value["last_run"];
    let day = text(&value["day"]);
    let mut lines = vec![if last.is_null() {
        match lang {
            Lang::Fr => format!("Brief du {day} : pas encore lancé."),
            Lang::En => format!("Brief {day}: not run."),
        }
    } else {
        let written = value["status"] == "written";
        match (lang, written) {
            (Lang::Fr, true) => format!("Brief du {day} : écrit."),
            (Lang::Fr, false) => format!("Brief du {day} : tenté, rien d'écrit."),
            (Lang::En, true) => format!("Brief {day}: written."),
            (Lang::En, false) => format!("Brief {day}: attempted, nothing written."),
        }
    }];
    if !last.is_null() {
        let sections: Vec<String> = ["calendar", "weather", "mail"]
            .iter()
            .map(|name| match text(&last["sections"][*name]).as_str() {
                "built" => match lang {
                    Lang::Fr => format!("{name} construit"),
                    Lang::En => format!("{name} built"),
                },
                reason => match lang {
                    Lang::Fr => format!("{name} ignoré ({reason})"),
                    Lang::En => format!("{name} skipped ({reason})"),
                },
            })
            .collect();
        let delivery = &last["delivery"];
        let reason = delivery["reason"].as_str().map(|r| format!(": {r}"));
        let outcome = match text(&delivery["outcome"]).as_str() {
            "notice_sent" => choose(
                lang,
                "avis envoyé (mode privé ; brief complet dans l'app)",
                "notice sent (private mode; full brief in the app)",
            )
            .to_string(),
            "failed" => {
                let not_delivered = choose(lang, "non délivré", "not delivered");
                if delivery["reason"] == "not_delivered" {
                    not_delivered.to_string()
                } else {
                    format!("{not_delivered}{}", reason.unwrap_or_default())
                }
            }
            other => format!("{other}{}", reason.unwrap_or_default()),
        };
        // Only the known causes are named; anything else is not echoed.
        let cause = delivery["cause"].as_str().map(|cause| match cause {
            "timeout" => choose(
                lang,
                "Messages n'a pas répondu à temps",
                "Messages did not answer in time",
            ),
            "not_authorized" => choose(
                lang,
                "macOS n'autorise pas Auxesis à contrôler Messages",
                "macOS does not allow Auxesis to control Messages",
            ),
            "messages_unavailable" => choose(
                lang,
                "Messages n'est pas lancé ou n'a pas de compte iMessage",
                "Messages is not running or has no iMessage account",
            ),
            "paced" => choose(
                lang,
                "retenu par le rythme d'envoi",
                "held by the send pacing",
            ),
            "transport" => choose(
                lang,
                "l'envoi par Messages a échoué",
                "the Messages send failed",
            ),
            _ => choose(lang, "cause inconnue", "unknown cause"),
        });
        let (at, trigger, result) = (
            text(&last["at"]),
            text(&last["trigger"]),
            text(&last["result"]),
        );
        let sections = sections.join("; ");
        match lang {
            Lang::Fr => {
                lines.push(format!("  dernier lancement : {at} ({trigger}) — {result}"));
                lines.push(format!("  sections : {sections}"));
                lines.push(format!("  envoi : {outcome}"));
            }
            Lang::En => {
                lines.push(format!("  last run: {at} ({trigger}) — {result}"));
                lines.push(format!("  sections: {sections}"));
                lines.push(format!("  delivery: {outcome}"));
            }
        }
        if let Some(cause) = cause {
            lines.push(format!("  cause: {cause}"));
        }
        // The fix is chosen here from the closed labels, never echoed.
        let automation = matches!(
            delivery["cause"].as_str(),
            Some("not_authorized" | "timeout")
        );
        if automation || delivery["reason"] == "not_confirmed" {
            lines.push(format!(
                "  {}: {}",
                choose(lang, "correctif", "fix"),
                choose(lang, AUTOMATION_FIX_FR, AUTOMATION_FIX)
            ));
        }
    } else if value["enabled"] == false {
        lines.push(
            choose(
                lang,
                "  la planification est coupée ([brief].enabled = false)",
                "  the schedule is off ([brief].enabled = false)",
            )
            .to_string(),
        );
    }
    let next = value["next_scheduled"]
        .as_str()
        .unwrap_or(choose(lang, "inconnu", "unknown"));
    let time = text(&value["scheduled_time"]);
    lines.push(match lang {
        Lang::Fr => format!("  prochain lancement : {next} (chaque jour à {time})"),
        Lang::En => format!("  next scheduled: {next} (daily {time})"),
    });
    lines.join("\n")
}

/// The loopback endpoint and the daemon token, or `Unreachable`.
pub(crate) fn daemon_target(lang: Lang) -> Result<(String, String), BriefDaemonError> {
    let endpoint = kernel_core::resolve_client_endpoint(&[])
        .map_err(|_| BriefDaemonError::unreachable(lang))?;
    if !endpoint.has_endpoint() {
        return Err(BriefDaemonError::unreachable(lang));
    }
    // The shared resolver also accepts AUXESIS_API for other clients. This
    // command reads the daemon bearer token, so never let that override send
    // it to a remote host.
    if !is_loopback_host(&endpoint.host) {
        return Err(BriefDaemonError::unreachable(lang));
    }
    let Some(token) = read_daemon_token(&auxesis_home()) else {
        return Err(BriefDaemonError::unreachable(lang));
    };
    Ok((endpoint.url, token))
}

/// The daemon path: one `POST /v1/brief/run` over loopback, then the brief
/// text or a one-line status.
fn run_daemon_inner(lang: Lang) -> Result<String, Box<dyn std::error::Error>> {
    let (url, token) = daemon_target(lang)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let body = runtime.block_on(call_daemon(
        reqwest::Method::POST,
        &url,
        "/v1/brief/run",
        &token,
        lang,
    ))?;
    let response: BriefRunJson = serde_json::from_str(&body).map_err(|err| {
        BriefDaemonError::Protocol(match lang {
            Lang::Fr => format!("réponse illisible d'auxd : {err}"),
            Lang::En => format!("unreadable reply from auxd: {err}"),
        })
    })?;
    if response.status == "written" {
        return response.brief.ok_or_else(|| {
            BriefDaemonError::Protocol(
                choose(
                    lang,
                    "auxd a annoncé un brief écrit sans texte",
                    "auxd reported a written brief without text",
                )
                .to_string(),
            )
            .into()
        });
    }
    match outcome_text(lang, &response.status) {
        Some(text) => Ok(text.to_string()),
        None => Err(Box::new(BriefDaemonError::Protocol(match lang {
            Lang::Fr => format!("réponse inattendue d'auxd : statut `{}`", response.status),
            Lang::En => format!("unexpected reply from auxd: status `{}`", response.status),
        }))),
    }
}

/// The one-line text of a `POST /v1/brief/run` status that carries no brief.
fn outcome_text(lang: Lang, status: &str) -> Option<&'static str> {
    Some(match status {
        "already_today" => choose(
            lang,
            "Le brief du jour existe déjà.",
            "Today's brief already exists.",
        ),
        "skipped_quiet_hours" => choose(
            lang,
            "Brief ignoré pendant les heures calmes.",
            "Brief skipped during quiet hours.",
        ),
        "source_unavailable" => choose(
            lang,
            "Brief indisponible : aucune source locale n'est configurée.",
            "Brief unavailable: no local source is configured.",
        ),
        _ => return None,
    })
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let address = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    address
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod endpoint_tests {
    use super::is_loopback_host;

    #[test]
    fn brief_client_accepts_only_loopback_hosts() {
        for host in ["127.0.0.1", "::1", "[::1]", "localhost"] {
            assert!(is_loopback_host(host), "{host} must be loopback");
        }
        for host in ["192.0.2.10", "example.com", "localhost.attacker.test"] {
            assert!(!is_loopback_host(host), "{host} must be refused");
        }
    }
}

/// The JSON body of `POST /v1/brief/run`.
#[derive(Debug, serde::Deserialize)]
struct BriefRunJson {
    status: String,
    #[serde(default)]
    brief: Option<String>,
}

/// Errors of the daemon path that print as `aux brief: {error}`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BriefDaemonError {
    #[error("{0}")]
    Protocol(String),
}

impl BriefDaemonError {
    /// No daemon answers on the loopback endpoint.
    fn unreachable(lang: Lang) -> Self {
        Self::Protocol(
            choose(
                lang,
                "auxd ne tourne pas (lance-le, ou utilise --offline)",
                "auxd is not running (start it, or use --offline)",
            )
            .to_string(),
        )
    }
}

pub(crate) async fn call_daemon(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    lang: Lang,
) -> Result<String, BriefDaemonError> {
    let client = reqwest::Client::builder()
        // The endpoint is a fixed loopback URL: never follow a redirect off it
        // and never let an environment proxy carry the bearer token.
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|err| {
            BriefDaemonError::Protocol(match lang {
                Lang::Fr => format!("client local impossible : {err}"),
                Lang::En => format!("cannot build the local client: {err}"),
            })
        })?;
    let response = client
        .request(method, format!("{base}{path}"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| {
            if err.is_connect() {
                BriefDaemonError::unreachable(lang)
            } else {
                BriefDaemonError::Protocol(match lang {
                    Lang::Fr => format!("requête vers auxd échouée : {err}"),
                    Lang::En => format!("request to auxd failed: {err}"),
                })
            }
        })?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| value["error"]["message"].as_str().map(str::to_string))
            .unwrap_or_else(|| match lang {
                Lang::Fr => format!("auxd a répondu HTTP {status}"),
                Lang::En => format!("auxd answered HTTP {status}"),
            });
        return Err(BriefDaemonError::Protocol(message));
    }
    Ok(body)
}

/// Read the daemon token (`<home>/api.token`) without creating it.
fn read_daemon_token(home: &Path) -> Option<String> {
    use std::io::Read;
    let verified = kernel_core::verified_home_or_verify(home).ok()?;
    let mut file = verified
        .open_read_existing(Path::new("api.token"), 4096)
        .ok()?;
    let mut token = String::new();
    file.read_to_string(&mut token).ok()?;
    let token = token.trim();
    if token.is_empty() || token.len() > 256 {
        return None;
    }
    Some(token.to_string())
}

/// C10: a brief notification leaves the app through the OS. The mode is read
/// live at each notification, and a private home sends none, as the daemon's
/// brief job does.
struct PrivacyGate<'a> {
    inner: &'a dyn Notifier,
    home: &'a Path,
}

impl Notifier for PrivacyGate<'_> {
    fn notify(&self, notification: &Notification) -> Result<(), aux_notify::NotifyError> {
        if admit_call(
            PathId::C10,
            current_mode(self.home),
            Destination::LocalDisplay,
        )
        .is_err()
        {
            return Ok(());
        }
        self.inner.notify(notification)
    }
}

/// The offline fixture path, unchanged from M0: it never reaches the daemon.
fn run_offline_inner() -> Result<String, Box<dyn std::error::Error>> {
    let home = auxesis_home();
    let verified = ensure_home(&home)?;
    let config = Config::load_or_create_verified(&verified)?;
    let store = Store::open_verified(&verified)?;
    // A sandbox command records instead of showing a banner; `system_notifier`
    // decides from the shared sandbox guard.
    let notifier: Arc<dyn Notifier> = Arc::new(StopSwitchNotifier::new(
        system_notifier(kernel_core::sandbox_guard_active()),
        kernel_core::killswitch::stop_path(&home),
    ));
    let gate = PrivacyGate {
        inner: notifier.as_ref(),
        home: &home,
    };
    let result = run_once(
        &store,
        &FakeBriefSource::default(),
        &gate,
        &config,
        SystemBriefClock.now_local(),
        MAX_SOURCE_READS,
        || kernel_core::killswitch::is_stopped(&home),
    )?;
    let lang = config.ui.language;
    Ok(match result {
        BriefResult::Sent { day, message_id } => {
            let mut body = String::new();
            for session in store.list_sessions()? {
                if let Some(message) = store
                    .list_messages(session.id)?
                    .into_iter()
                    .find(|message| message.id == message_id)
                {
                    body = message.content;
                    break;
                }
            }
            match lang {
                Lang::Fr => format!("Brief envoyé pour le {day}.\n\n{body}"),
                Lang::En => format!("Brief sent for {day}.\n\n{body}"),
            }
        }
        BriefResult::AlreadySent { day } => match lang {
            Lang::Fr => format!("Le brief du {day} existe déjà."),
            Lang::En => format!("The brief for {day} already exists."),
        },
        BriefResult::QuietHours { .. } => outcome_text(lang, "skipped_quiet_hours")
            .unwrap_or_default()
            .to_string(),
        BriefResult::BudgetStopped { .. } => {
            choose(lang, "Brief en pause (quota).", "Brief paused (quota).").to_string()
        }
        BriefResult::Stopped => {
            choose(lang, "Brief arrêté par STOP.", "Brief stopped by STOP.").to_string()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aux_notify::{FakeNotifier, Notification};

    #[test]
    fn status_lines_name_the_run_and_never_print_content() {
        let reply = serde_json::json!({
            "day": "2026-10-14", "status": "written", "enabled": true,
            "scheduled_time": "08:00", "next_scheduled": "2026-10-15T08:00:00+02:00",
            "last_run": {
                "at": "2026-10-14T08:00:03+02:00", "trigger": "scheduled", "result": "written",
                "sections": {"calendar": "built", "weather": "no_city", "mail": "built"},
                "delivery": {"outcome": "held", "reason": "quiet_hours"},
                // A reply that ever carried content must not reach the terminal.
                "brief": "Standup with Camille", "subject": "Fictional quote", "to": "+33600000000",
            },
        });
        let out = render_status(&reply, Lang::En);
        assert!(out.contains("written"), "{out}");
        assert!(
            out.contains("2026-10-14T08:00:03+02:00 (scheduled)"),
            "{out}"
        );
        assert!(out.contains("weather skipped (no_city)"), "{out}");
        assert!(out.contains("delivery: held: quiet_hours"), "{out}");
        assert!(
            out.contains("next scheduled: 2026-10-15T08:00:00+02:00"),
            "{out}"
        );
        for secret in ["Camille", "Fictional", "+33600000000"] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
    }

    #[test]
    fn a_failed_send_says_not_delivered_why_and_the_fix() {
        for (cause, plain) in [
            (
                "not_authorized",
                "macOS does not allow Auxesis to control Messages",
            ),
            ("timeout", "Messages did not answer in time"),
        ] {
            let delivery = serde_json::json!({"outcome": "failed", "reason": "not_delivered",
                "cause": cause, "fix": "echoed?"});
            let out = render_status(
                &serde_json::json!({"last_run": {"delivery": delivery}}),
                Lang::En,
            );
            assert!(out.contains("delivery: not delivered\n"), "{out}");
            assert!(out.contains(&format!("cause: {plain}")), "{out}");
            assert!(out.contains(&format!("fix: {AUTOMATION_FIX}")), "{out}");
            assert!(!out.contains("echoed?"), "{out}");
            assert!(!out.contains("sent"), "{out}");
        }
        let delivery = serde_json::json!({"outcome": "failed", "cause": "+33600000000 hello"});
        let out = render_status(
            &serde_json::json!({"last_run": {"delivery": delivery}}),
            Lang::En,
        );
        assert!(
            out.contains("cause: unknown cause") && !out.contains("+336"),
            "{out}"
        );
    }

    #[test]
    fn already_today_and_quiet_hours_speak_the_configured_language() {
        let cases = [
            (
                "already_today",
                "Today's brief already exists.",
                "Le brief du jour existe déjà.",
            ),
            (
                "skipped_quiet_hours",
                "Brief skipped during quiet hours.",
                "Brief ignoré pendant les heures calmes.",
            ),
            (
                "source_unavailable",
                "Brief unavailable: no local source is configured.",
                "Brief indisponible : aucune source locale n'est configurée.",
            ),
        ];
        for (status, en, fr) in cases {
            assert_eq!(outcome_text(Lang::En, status), Some(en), "{status}");
            assert_eq!(outcome_text(Lang::Fr, status), Some(fr), "{status}");
        }
        assert_eq!(outcome_text(Lang::En, "written"), None);
    }

    #[test]
    fn the_config_language_wins_and_a_missing_config_is_not_created() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            config_path(dir.path()),
            "version = 1\n\n[ui]\nlanguage = \"fr\"\n",
        )
        .unwrap();
        assert_eq!(configured_lang(dir.path()), Lang::Fr);
        std::fs::write(
            config_path(dir.path()),
            "version = 1\n\n[ui]\nlanguage = \"en\"\n",
        )
        .unwrap();
        assert_eq!(configured_lang(dir.path()), Lang::En);
        let empty = tempfile::tempdir().unwrap();
        let _ = configured_lang(empty.path());
        assert!(!config_path(empty.path()).exists());
    }

    #[test]
    fn status_lines_speak_french_when_configured() {
        let reply = serde_json::json!({"day": "2026-10-14", "status": "written",
            "scheduled_time": "08:00", "next_scheduled": "2026-10-15T08:00:00+02:00",
            "last_run": {"at": "x", "trigger": "scheduled", "result": "written",
                "sections": {"calendar": "built", "mail": "no_account"},
                "delivery": {"outcome": "notice_sent"}}});
        let out = render_status(&reply, Lang::Fr);
        for part in [
            "Brief du 2026-10-14 : écrit.",
            "calendar construit; weather ignoré (?); mail ignoré (no_account)",
            "envoi : avis envoyé (mode privé",
            "prochain lancement : 2026-10-15T08:00:00+02:00 (chaque jour à 08:00)",
        ] {
            assert!(out.contains(part), "{part} missing: {out}");
        }
    }

    #[test]
    fn a_private_notice_never_reads_as_sent() {
        let delivery = serde_json::json!({"outcome": "notice_sent", "reason": "privacy_mode"});
        let reply = serde_json::json!({"day": "2026-10-14", "status": "written",
            "last_run": {"at": "x", "trigger": "scheduled", "result": "written",
                "sections": {}, "delivery": delivery}});
        let out = render_status(&reply, Lang::En);
        let notice = "delivery: notice sent (private mode; full brief in the app)";
        assert!(out.contains(notice), "{out}");
    }

    fn home_in(mode: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            kernel_core::config_path(dir.path()),
            format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n"),
        )
        .unwrap();
        dir
    }

    #[test]
    fn private_mode_holds_the_brief_notification() {
        // C10: a brief notification leaves the app through the OS, so a private
        // home sends none, as the daemon's brief job does.
        let dir = home_in("private");
        let fake = FakeNotifier::new();
        let gate = PrivacyGate {
            inner: &fake,
            home: dir.path(),
        };
        gate.notify(&Notification::new("Brief", "body")).unwrap();
        assert_eq!(fake.count(), 0);
    }

    #[test]
    fn open_mode_delivers_the_brief_notification() {
        let dir = home_in("open");
        let fake = FakeNotifier::new();
        let gate = PrivacyGate {
            inner: &fake,
            home: dir.path(),
        };
        gate.notify(&Notification::new("Brief", "body")).unwrap();
        assert_eq!(fake.count(), 1);
    }
}
