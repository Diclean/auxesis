//! Live acceptance: the owner's questions against the REAL model.
//!
//! Skips cleanly unless `AUX_HERO_CLOUD_URL`, `AUX_HERO_CLOUD_KEY` and
//! `AUX_HERO_CLOUD_MODEL` are set (optionally `AUX_HERO_CLOUD_DISABLE_THINKING`),
//! so CI stays the same. A loopback recorder sits between the engine's real
//! `OpenAiCompat` adapter and the hosted model, like the hero test, and keeps
//! every request body. The mailbox is the fictional `aux-fakemail` demo set.
//!
//! Two mail questions and three calendar questions, in Open and Private
//! mode: the question reaches the model intact (Private: e-mail, phone and the
//! other hidden values are tokens; names pass as written, and `Aux` is never a
//! person), a mail question calls a mail tool, a calendar question calls the
//! calendar tool and the answer names the fixture event, and the answer shown
//! holds no `⟦`. The calendar is a fictional snapshot written
//! into the sandbox home; the Mac's EventKit calendar is never touched.
//!
//! Run: source a test key file you provide (see CONTRIBUTING.md), then use
//! the sandbox env it gives (`env -i HOME=<tmp> AUXESIS_HOME=<tmp>/.auxesis
//! AUXESIS_SANDBOX=1 AUXESIS_API_PORT=0`), then
//! `cargo test -p auxd --test agent_real -- --nocapture`.

use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::time::Duration;

use aux_engine::{ChatSession, ChatSetup};
use aux_fakemail::{serve, write_demo, SimConfig, StaticCredentials};
use aux_mail::config::{ImapSettings, MailAccount, Security};
use aux_mail::dial::Dialer;
use aux_mail::limits::Limits;
use aux_mail::{MailService, MailToolset};
use aux_providers::{OpenAiCompat, ProviderConfig, ProviderKind};
use aux_store::{Store, StoreHandle};
use auxd::apple_eventkit::{save_snapshot, EventItem, EventKitSnapshot};
use chrono::{Datelike, Duration as Days, Local, NaiveDate};
use kernel_broker::{ApprovalRequest, Approver, ApproverError, ToolRegistry};
use kernel_core::budget::{Budgets, PriceTable};
use kernel_core::privacy::PrivacyMode;
use kernel_core::ContextConfig;
use kernel_privacy::ContactIndex;
use serde_json::Value;
use tempfile::tempdir;

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Approves every card: the mail tools ask once the turn holds mail text.
struct ApproveAll;

#[async_trait::async_trait]
impl Approver for ApproveAll {
    async fn approve(&self, _request: &ApprovalRequest) -> Result<bool, ApproverError> {
        Ok(true)
    }
}

/// The loopback endpoint the adapter calls: records each body and forwards it,
/// with the key, to the hosted model. The adapter itself never holds the key.
#[derive(Clone)]
struct Recorder {
    base_url: String,
    upstream: String,
    key: String,
    bodies: Arc<StdMutex<Vec<String>>>,
    responses: Arc<StdMutex<Vec<String>>>,
    client: reqwest::Client,
}

async fn completions(
    axum::extract::State(state): axum::extract::State<Recorder>,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    state.bodies.lock().unwrap().push(body.clone());
    let url = format!("{}/chat/completions", state.upstream.trim_end_matches('/'));
    let request = state.client.post(url).bearer_auth(&state.key);
    let sent = request
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;
    let Ok(upstream) = sent else {
        return (
            axum::http::StatusCode::BAD_GATEWAY,
            "recorder: upstream down",
        )
            .into_response();
    };
    let status = axum::http::StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let bytes = upstream.bytes().await.unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    state.responses.lock().unwrap().push(text);
    (status, [("content-type", content_type)], bytes.to_vec()).into_response()
}

impl Recorder {
    async fn start(upstream: String, key: String) -> Recorder {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let recorder = Recorder {
            base_url: format!("http://{}/v1", listener.local_addr().unwrap()),
            upstream,
            key,
            bodies: Arc::default(),
            responses: Arc::default(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(300))
                .build()
                .unwrap(),
        };
        let app = axum::Router::new()
            .route("/v1/chat/completions", axum::routing::post(completions))
            .with_state(recorder.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        recorder
    }
}

/// What one live turn left behind: the first user and system text the model
/// got, the tools it called, what it read from them, and the owner's answer.
struct Turn {
    user_text: String,
    system_text: String,
    tools_called: Vec<String>,
    tool_text: String,
    shown: String,
}

/// The hosted brain's URL, key and model, when the env names one.
fn brain() -> Option<(String, String, String)> {
    Some((
        env("AUX_HERO_CLOUD_URL")?,
        env("AUX_HERO_CLOUD_KEY")?,
        env("AUX_HERO_CLOUD_MODEL")?,
    ))
}

const CALENDAR_TOOL: &str = "apple_calendar_list_events";

/// The fictional calendar the three calendar questions are asked of, dated from
/// the clock so "tomorrow" and "Friday" hold on any day.
struct Calendar {
    snapshot: EventKitSnapshot,
    /// "Friday", or "next Friday" when today is one.
    friday: &'static str,
}

/// An event at `hour:00` local on `day`, one hour long.
fn event(day: NaiveDate, hour: u32, title: &str) -> EventItem {
    let at = |hour: u32| {
        day.and_hms_opt(hour, 0, 0)
            .and_then(|naive| naive.and_local_timezone(Local).earliest())
            .expect("a local time that exists")
            .to_rfc3339()
    };
    EventItem {
        id: Some(title.to_lowercase().replace(' ', "-")),
        title: title.to_string(),
        start: at(hour),
        end: at(hour + 1),
        all_day: None,
        calendar: "Work".to_string(),
        location: None,
        attendees: None,
        calendar_id: None,
        recurring: None,
    }
}

fn fixture_calendar() -> Calendar {
    let today = Local::now().date_naive();
    let to_friday = (4 - i64::from(today.weekday().num_days_from_monday())).rem_euclid(7);
    let friday = today + Days::days(if to_friday == 0 { 7 } else { to_friday });
    Calendar {
        snapshot: EventKitSnapshot {
            authorized: true,
            events: vec![
                event(today + Days::days(1), 14, "Northwind launch review"),
                event(friday, 10, "Brightpath contract call"),
                event(
                    friday + Days::days(3),
                    16,
                    "Roadmap sync with Camille Example",
                ),
            ],
            reminders: Vec::new(),
            // Read just now over today and the next 8 days, as the app does.
            captured_at: Some(chrono::Utc::now().to_rfc3339()),
            covers_from: Some((chrono::Utc::now() - chrono::Duration::days(1)).to_rfc3339()),
            covers_to: Some((chrono::Utc::now() + chrono::Duration::days(9)).to_rfc3339()),
            default_calendar_id: None,
            events_truncated: false,
            reminders_truncated: false,
        },
        friday: if to_friday == 0 {
            "next Friday"
        } else {
            "Friday"
        },
    }
}

async fn ask(
    question: &str,
    mode: PrivacyMode,
    home_dir: &std::path::Path,
    calendar: &Calendar,
) -> Turn {
    let (url, key, model) = brain().expect("the caller skips without the cloud env");
    let disable_thinking = env("AUX_HERO_CLOUD_DISABLE_THINKING")
        .is_some_and(|value| matches!(value.trim(), "1" | "true"));
    let recorder = Recorder::start(url, key).await;
    let provider = OpenAiCompat::with_key_and_timeout(
        &ProviderConfig {
            disable_thinking,
            id: "live".to_string(),
            base_url: recorder.base_url.clone(),
            model,
            key_user: None,
            kind: ProviderKind::OpenAiCompat,
        },
        None,
        Duration::from_secs(300),
    )
    .unwrap();

    // The fictional demo mailbox (twelve mails) behind the real IMAP client,
    // over the simulator's TLS with its self-signed CA pinned.
    let sim_dir = tempdir().unwrap();
    write_demo(sim_dir.path(), false).unwrap();
    let sim = serve(SimConfig {
        dir: sim_dir.path().to_path_buf(),
        imap_port: 0,
        smtp_port: 0,
    })
    .await
    .unwrap();
    let account = MailAccount {
        id: "mailsim".to_string(),
        email: "owner@mailsim.test".to_string(),
        imap: ImapSettings {
            host: "127.0.0.1".to_string(),
            port: sim.imap_port,
            security: Security::Tls,
            ca_file: Some(sim.ca_file.to_string_lossy().into_owned()),
            ..ImapSettings::default()
        },
        only_folders: vec!["INBOX".to_string()],
        ..MailAccount::default()
    };
    let service = MailService::new(
        Dialer::new(Duration::from_secs(5)),
        Limits::default(),
        vec![account],
        Arc::new(StaticCredentials::new("mailsim", "demo-password")),
    );
    let toolset = MailToolset::new(Arc::new(service), None);
    let mut registry = ToolRegistry::with_defaults();
    // The fixture calendar: an encrypted snapshot in the sandbox home, read by
    // the daemon's own EventKit tool. The store is minted first for its key.
    std::fs::write(
        kernel_core::config_path(home_dir),
        "version = 1\n\n[privacy]\nmode = \"open\"\n",
    )
    .unwrap();
    Store::open(&kernel_core::store_path(home_dir)).unwrap();
    save_snapshot(home_dir, &calendar.snapshot).unwrap();
    auxd::apple_eventkit::register_tools(home_dir, &mut registry);
    for tool in toolset.tools() {
        if tool.name() != "mail_send" {
            registry.register_native(tool);
        }
    }
    for name in ["mail_list", "mail_search", "mail_thread", "mail_read"] {
        registry.mark_read_only(name);
    }

    // The owner's contacts: the two demo clients.
    let mut contacts = ContactIndex::new();
    contacts.add_from_header("Camille Example", "camille@northwind.example");
    contacts.add_from_header("Jonas Sample", "jonas@brightpath.example");
    let contacts = Arc::new(contacts);

    let store = Arc::new(StdMutex::new(Store::open_in_memory().unwrap()));
    let budgets = Budgets::default();
    let prices = PriceTable::default();
    let mode_fn: kernel_core::privacy::ModeFn = Arc::new(move || mode);
    let mut session = ChatSession::start(ChatSetup {
        mode: mode_fn,
        contacts,
        store: StoreHandle::Shared(Arc::clone(&store)),
        provider: &provider,
        registry: Arc::new(RwLock::new(registry)),
        rules: Vec::new(),
        approver: Arc::new(ApproveAll),
        agent: "aux".to_string(),
        home: home_dir.to_path_buf(),
        skills: Vec::new(),
        budgets: &budgets,
        prices: &prices,
        context: ContextConfig::default(),
        title: None,
        stop: None,
        cancel: None,
        session_id: None,
        events: None,
        run_id: None,
    })
    .unwrap();
    let session_id = session.session().id;
    let outcome = session
        .send(question)
        .await
        .unwrap_or_else(|err| panic!("the live turn failed: {err}"));
    drop(session);
    let bodies: Vec<Value> = recorder
        .bodies
        .lock()
        .unwrap()
        .iter()
        .map(|body| serde_json::from_str(body).unwrap())
        .collect();
    // What the model read from the mail tools, in the last request.
    let tool_text = bodies
        .last()
        .and_then(|body| body["messages"].as_array())
        .into_iter()
        .flatten()
        .filter(|message| message["role"] == "tool")
        .map(|message| message["content"].to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let first = &bodies[0];
    let messages = first["messages"].as_array().cloned().unwrap_or_default();
    let text_of = |message: &Value| match &message["content"] {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let user_text = messages
        .iter()
        .find(|message| message["role"] == "user")
        .map(text_of)
        .unwrap_or_default();
    let system_text = messages
        .iter()
        .filter(|message| message["role"] == "system")
        .map(text_of)
        .collect::<Vec<_>>()
        .join("\n");
    // The call names, from the streamed `data:` lines (or a plain JSON reply).
    let mut tools_called = Vec::new();
    for response in recorder.responses.lock().unwrap().iter() {
        for line in response.lines() {
            let json = line.strip_prefix("data:").unwrap_or(line).trim();
            let Ok(chunk) = serde_json::from_str::<Value>(json) else {
                continue;
            };
            for key in ["delta", "message"] {
                for call in chunk["choices"][0][key]["tool_calls"]
                    .as_array()
                    .into_iter()
                    .flatten()
                {
                    tools_called.extend(call["function"]["name"].as_str().map(str::to_string));
                }
            }
        }
    }
    Turn {
        user_text,
        system_text,
        tools_called,
        tool_text,
        shown: auxd::privacy_wiring::rehydrate_local(session_id, &outcome.text),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_questions_against_the_real_model() {
    if brain().is_none() {
        eprintln!(
            "SKIP agent_real: set AUX_HERO_CLOUD_URL, AUX_HERO_CLOUD_KEY and AUX_HERO_CLOUD_MODEL"
        );
        return;
    }
    // (question, calls a mail tool, names a real contact)
    let questions = [
        ("How many unread mails do I have, Aux?", true, false),
        (
            "What did Jonas Sample write to me about the launch page?",
            true,
            true,
        ),
    ];
    let calendar = fixture_calendar();
    for mode in [PrivacyMode::Open, PrivacyMode::Private] {
        for (question, wants_mail_tool, names_contact) in questions {
            let dir = tempdir().unwrap();
            let turn = ask(question, mode, dir.path(), &calendar).await;
            let first_line = turn.shown.lines().next().unwrap_or("").to_string();
            eprintln!(
                "LIVE {mode:?} | {question} | tools {:?} | {first_line}",
                turn.tools_called
            );
            assert!(
                !turn.shown.contains('⟦'),
                "{mode:?} {question:?}: raw token shown: {}",
                turn.shown
            );
            assert!(
                !turn.system_text.contains("⟦PERSON"),
                "{mode:?}: a person token in the system prompt:\n{}",
                turn.system_text
            );
            if names_contact && mode == PrivacyMode::Private {
                // A name passes as written;
                // the contact's address is still a token.
                assert!(
                    turn.user_text.contains("Jonas Sample") && !turn.user_text.contains('⟦'),
                    "the contact name was not passed as written: {}",
                    turn.user_text
                );
                assert!(
                    turn.user_text
                        .contains("write to me about the launch page?"),
                    "{}",
                    turn.user_text
                );
            } else {
                assert_eq!(
                    turn.user_text, question,
                    "{mode:?}: the question was altered"
                );
            }
            if wants_mail_tool {
                // The tool's own words are not names: `uid`, a subject's first
                // word, `Introduction from …` stay as the mailbox wrote them.
                assert!(
                    turn.tool_text.contains("uid ") || turn.tool_text.contains("subject: "),
                    "{mode:?} {question:?}: no mail text reached the model: {}",
                    turn.tool_text
                );
                assert!(
                    !turn.tool_text.contains("⟧ 12 ·")
                        && !turn.tool_text.contains("⟧ about the delivery window"),
                    "{mode:?} {question:?}: a mail word was tokenised: {}",
                    turn.tool_text
                );
                if mode == PrivacyMode::Private {
                    // A name passes as
                    // written; the address stays hidden.
                    assert!(
                        !turn.tool_text.contains("⟦PERSON"),
                        "{mode:?} {question:?}: a name was tokenised: {}",
                        turn.tool_text
                    );
                    assert!(
                        !turn.tool_text.contains("jonas@brightpath.example"),
                        "{mode:?} {question:?}: a contact address reached the model: {}",
                        turn.tool_text
                    );
                    assert!(
                        turn.tool_text.contains("⟦EMAIL_"),
                        "{mode:?} {question:?}: the contact address was not tokenised: {}",
                        turn.tool_text
                    );
                    if names_contact {
                        assert!(
                            turn.tool_text.contains("Jonas"),
                            "{mode:?} {question:?}: the contact name was not passed as written: {}",
                            turn.tool_text
                        );
                    }
                }
                if question.contains("unread") {
                    // The demo mailbox holds eight unread mails (uids 5-12).
                    assert!(
                        turn.tool_text.contains("unread_count=8"),
                        "{mode:?}: mail_list gave no count: {}",
                        turn.tool_text
                    );
                    let shown = turn.shown.to_lowercase();
                    assert!(
                        shown
                            .split(|c: char| !c.is_alphanumeric())
                            .any(|word| word == "8" || word == "eight"),
                        "{mode:?}: the answer miscounted the unread mail: {}",
                        turn.shown
                    );
                }
                assert!(
                    turn.tools_called
                        .iter()
                        .any(|name| name.starts_with("mail_")),
                    "{mode:?} {question:?}: no mail tool was called: {:?}",
                    turn.tools_called
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn owner_calendar_questions_against_the_real_model() {
    if brain().is_none() {
        eprintln!(
            "SKIP agent_real: set AUX_HERO_CLOUD_URL, AUX_HERO_CLOUD_KEY and AUX_HERO_CLOUD_MODEL"
        );
        return;
    }
    // One clock reading for the whole test: the question text and every
    // snapshot share it, so a midnight crossing cannot split the fixture.
    let calendar = fixture_calendar();
    let friday = calendar.friday;
    // (question, the event title the answer names, the titles of the other
    // fixture events a date question must not name, names a contact)
    let questions = [
        (
            "What's on my calendar tomorrow?".to_string(),
            "Northwind launch review",
            &["Brightpath", "Roadmap sync"][..],
            false,
        ),
        (
            format!("Am I free {friday} at 10?"),
            "Brightpath contract call",
            &["Northwind", "Roadmap sync"][..],
            false,
        ),
        (
            "When is my next meeting with Camille Example?".to_string(),
            "Roadmap sync",
            &[][..],
            true,
        ),
    ];
    for mode in [PrivacyMode::Open, PrivacyMode::Private] {
        for (question, title, others, names_contact) in &questions {
            let dir = tempdir().unwrap();
            let turn = ask(question, mode, dir.path(), &calendar).await;
            let first_line = turn.shown.lines().next().unwrap_or("").to_string();
            eprintln!(
                "LIVE {mode:?} | {question} | tools {:?} | {first_line}",
                turn.tools_called
            );
            assert!(
                !turn.shown.contains('⟦'),
                "{mode:?} {question:?}: raw token shown: {}",
                turn.shown
            );
            assert!(
                turn.tools_called.iter().any(|name| name == CALENDAR_TOOL),
                "{mode:?} {question:?}: the calendar tool was not called: {:?}",
                turn.tools_called
            );
            assert!(
                turn.shown.to_lowercase().contains(&title.to_lowercase()),
                "{mode:?} {question:?}: the answer does not name {title:?}: {}",
                turn.shown
            );
            // The tool hands back the whole snapshot, so the date has to be
            // reasoned by the model: the first block of the answer that names
            // any fixture event names the one asked for and no other. A later
            // "also coming up" note is fine.
            let shown = turn.shown.to_lowercase();
            let first_block = shown
                .split("\n\n")
                .find(|block| {
                    others
                        .iter()
                        .chain([title])
                        .any(|name| block.contains(&name.to_lowercase()))
                })
                .unwrap_or_default();
            for other in others.iter() {
                assert!(
                    !first_block.contains(&other.to_lowercase()),
                    "{mode:?} {question:?}: the answer leads with another event {other:?}: {}",
                    turn.shown
                );
            }
            if mode == PrivacyMode::Private {
                // The name in the event title
                // passes as written and is never a token.
                assert!(
                    !turn.tool_text.contains("⟦PERSON"),
                    "{mode:?} {question:?}: a name was tokenised in the calendar tool output: {}",
                    turn.tool_text
                );
                if *names_contact {
                    assert!(
                        turn.tool_text.contains("Camille Example"),
                        "{mode:?} {question:?}: the contact name was not passed as written: {}",
                        turn.tool_text
                    );
                }
            }
            if *names_contact && mode == PrivacyMode::Private {
                assert!(
                    turn.user_text.contains("Camille Example") && !turn.user_text.contains('⟦'),
                    "the contact name was not passed as written: {}",
                    turn.user_text
                );
            } else {
                assert_eq!(
                    &turn.user_text, question,
                    "{mode:?}: the question was altered"
                );
            }
        }
    }
}
