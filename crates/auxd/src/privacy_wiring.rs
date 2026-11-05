//! Daemon side of private mode (`docs/phase1.md` §2, the path rows).
//!
//! These live here:
//!
//! * [`current_mode`]: the live mode of `home`, read from `config.toml` at
//!   each call. There is no cached copy, so a switch (the Mac app, the CLI,
//!   or a direct edit) is seen by the next check of every choke point. A
//!   config that cannot be read is private, so a broken file fails toward
//!   masking.
//! * [`live_mode_fn`] and [`PrivateStop`]: the handles a long-running turn,
//!   job or channel keeps, so each step re-reads the mode.
//! * [`CHOKE_POINTS`]: where each of the 56 matrix rows is gated. The test
//!   below fails when a [`PathId`] has no entry, so a new path cannot ship
//!   unwired.
//! * The store enumeration test: every table in `sqlite_master` maps to a
//!   row, so a new table cannot ship without a policy.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aux_engine::StopCheck;
use kernel_broker::CancelToken;
use kernel_core::privacy::{ModeFn, PathId, PrivacyMode};

/// How often the background watches (MCP children, ACP turns) re-read the mode.
/// Choke points do not wait for it: they read the mode on every call.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// The global privacy mode of the config under `home`, read now.
///
/// A config that cannot be loaded reads as [`PrivacyMode::Private`].
pub fn current_mode(home: &Path) -> PrivacyMode {
    mode_of(&crate::api::load_config_verified(home))
}

/// Whether `home` is in private mode at this moment.
pub fn private_now(home: &Path) -> bool {
    current_mode(home) == PrivacyMode::Private
}

/// A live mode handle for `home`: every call to it reads the config again.
pub fn live_mode_fn(home: &Path) -> ModeFn {
    let home: PathBuf = home.to_path_buf();
    Arc::new(move || current_mode(&home))
}

/// The live mode of a turn of `agent`: the global mode, tightened by the
/// agent's own default when it has an agent.md (`README.md`, "The two modes").
/// Read at each call, so a switch of either layer is seen by the next check.
pub fn agent_mode_fn(home: &Path, agent: &str) -> ModeFn {
    let home: PathBuf = home.to_path_buf();
    let agent_dir = aux_engine::agent_dir(&home, agent);
    Arc::new(move || {
        aux_runtime::skills::effective_mode(
            current_mode(&home),
            aux_runtime::skills::agent_mode_layer(&agent_dir),
        )
    })
}

/// The caller's mode for a delegated turn, pinned at handoff, and that mode.
/// `caller` is the mode the caller's turn runs under (its tool context), never
/// config; the caller agent's live layers (`own`) only tighten it. Private at
/// handoff stays Private, and a later switch to Private still tightens it.
pub fn handoff_mode_fn(caller: ModeFn, own: ModeFn) -> (PrivacyMode, ModeFn) {
    let live: ModeFn = Arc::new(move || caller().max(own()));
    let at_handoff = live();
    (at_handoff, pinned_mode_fn(at_handoff, live))
}

/// `live`, never looser than `floor`: a Private floor stays Private. A resumed
/// delegation restores its stored handoff mode this way.
pub fn pinned_mode_fn(floor: PrivacyMode, live: ModeFn) -> ModeFn {
    Arc::new(move || match floor {
        PrivacyMode::Private => PrivacyMode::Private,
        PrivacyMode::Open => live(),
    })
}

/// An engine stop check that engages while `home` is private. The engine
/// asks it before each provider round and between tool calls, so a running
/// turn or job stops at its next step boundary.
pub struct PrivateStop {
    mode: ModeFn,
}

impl PrivateStop {
    /// Stop when `home` is private.
    pub fn new(home: &Path) -> Self {
        Self {
            mode: live_mode_fn(home),
        }
    }

    /// Stop when the mode of a turn of `agent` is private: the global mode,
    /// tightened by the agent's own default.
    pub fn for_agent(home: &Path, agent: &str) -> Self {
        Self {
            mode: agent_mode_fn(home, agent),
        }
    }
}

impl StopCheck for PrivateStop {
    fn is_stopped(&self) -> bool {
        (self.mode)() == PrivacyMode::Private
    }
}

/// Cancel an ACP turn as soon as `home` turns private. The agent runs in its own
/// process, so the engine's step check cannot reach it; the turn's cancel token
/// is the way to stop it. Returns when it has cancelled, or is aborted.
pub async fn cancel_when_private(home: PathBuf, token: Arc<CancelToken>) {
    let mut tick = tokio::time::interval(WATCH_INTERVAL);
    loop {
        tick.tick().await;
        if private_now(&home) {
            token.cancel();
            return;
        }
    }
}

/// The mode of an already-loaded config result, with the same fail-closed rule.
pub fn mode_of<E>(loaded: &Result<kernel_core::Config, E>) -> PrivacyMode {
    loaded
        .as_ref()
        .map_or(PrivacyMode::Private, |config| config.privacy.mode)
}

/// Longest reference (bytes between `⟦` and `⟧`) read as a token, as on the
/// chat display: a real token is far shorter.
const MAX_REFERENCE_BYTES: usize = 64;

/// What an unknown reference shows: never the token, never a guess.
const UNKNOWN_REFERENCE: &str = "[name hidden]";

/// Rehydrate `text` for the owner's local screen or store: each `⟦TOKEN⟧` the
/// session's gate minted becomes its value. A token the session did not mint
/// shows [`UNKNOWN_REFERENCE`]; a doubled `⟦⟦` is one literal opener. The values
/// come from the session's in-memory table only, and the result must stay on
/// the Mac: a private agent job keeps it in its local run record (F1).
pub fn rehydrate_local(session_id: i64, text: &str) -> String {
    use aux_runtime::executor::TokenResolver;
    use kernel_privacy::{LinkGuard, PLACEHOLDER_CLOSE as CLOSE, PLACEHOLDER_OPEN as OPEN};

    let tokens = aux_engine::skill_runtime::session_tokens(session_id);
    let tokens = kernel_core::sync::lock_recover(&tokens);
    let mut out = String::with_capacity(text.len());
    let mut links = LinkGuard::default();
    let mut rest = text;
    while let Some(open) = rest.find(OPEN) {
        let plain = &rest[..open];
        links.append_to(&mut out, plain);
        let after = &rest[open + OPEN.len_utf8()..];
        if let Some(escaped) = after.strip_prefix(OPEN) {
            links.append_to(&mut out, "⟦");
            rest = escaped;
            continue;
        }
        // Look for the closer only within the longest reference: model output
        // of a million openers and no closer must not rescan the rest of the
        // text at each opener.
        let mut window = after.len().min(MAX_REFERENCE_BYTES + CLOSE.len_utf8());
        while !after.is_char_boundary(window) {
            window -= 1;
        }
        match after[..window].find(CLOSE) {
            Some(end) if end > 0 && end <= MAX_REFERENCE_BYTES => {
                match tokens.resolve(&after[..end]) {
                    Some(value) => {
                        if !links
                            .append_token_value(
                                &mut out,
                                &after[..end],
                                &value,
                                &after[end + CLOSE.len_utf8()..],
                                true,
                            )
                            .unwrap_or(true)
                        {
                            links.append_to(&mut out, &value);
                        }
                    }
                    None => {
                        links.append_value(&mut out, UNKNOWN_REFERENCE);
                    }
                }
                rest = &after[end + CLOSE.len_utf8()..];
            }
            _ => {
                links.append_to(&mut out, "⟦");
                rest = after;
            }
        }
    }
    links.append_to(&mut out, rest);
    links.finish(&mut out);
    let kept_in_link = links.take_redactions();
    if kept_in_link > 0 {
        tracing::info!(kept_in_link, "link values kept hidden");
    }
    out
}

/// How one path is held in check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choke {
    /// The call is refused before it runs: `admit_call`, or a wrapper such as
    /// `GatedChat` or `GatedText`, sits on the call.
    Gate(&'static str),
    /// The feature is not registered in private mode: `may_mount`, the tool
    /// registry filter, or a start-up filter decides.
    Mount(&'static str),
    /// Nothing reaches this path on main today, so there is nothing to gate.
    /// Each entry names the reason; a new caller must replace it with a gate.
    Absent(&'static str),
    /// A mitigation that applies whatever the mode.
    Mitigation(&'static str),
}

/// The gate for every matrix row. Sites are `crate/module` paths.
pub const CHOKE_POINTS: &[(PathId, Choke)] = &[
    (
        PathId::A1,
        Choke::Gate("aux-engine ChatSession::start: a private turn with no names is refused before any row; the session gate checks names; auxd PrivateStop before each step; aux-providers GatedChat reads the live mode per completion"),
    ),
    (
        PathId::A2,
        Choke::Gate("aux-providers GatedChat::complete reads the live mode per call, on the turn, agent-run and channel providers; the WhatsApp agent runs only behind C1"),
    ),
    (
        PathId::A3,
        Choke::Gate("auxd api/providers.rs: endpoint probe refused before the connect"),
    ),
    (
        PathId::B1,
        Choke::Gate("aux-tools registry: the recall tool is mounted in both modes; gate_dispatch admits each call; the session gate tokenises every recall result in Private (aux-engine ChatSession::issue_outbound) before the provider sees it"),
    ),
    (
        PathId::B2,
        Choke::Gate("aux-tools registry: remember, forget and suggest_memory are mounted in both modes when suggestions are enabled; gate_dispatch admits each call; in Private the engine restores the session tokens in their arguments before the local write, so the store holds real values (D24) and a foreign token is refused; suggestions remain pending until owner review"),
    ),
    (
        PathId::B3,
        Choke::Gate("aux-tools registry: read_file is mounted in both modes; gate_dispatch admits each call; the engine restores the session tokens in the path before it runs; the file is read locally and the session gate tokenises its content (aux-engine ChatSession::issue_outbound) before the provider sees it"),
    ),
    (
        PathId::B4,
        Choke::Gate("aux-tools registry: write_file is mounted in both modes; gate_dispatch admits each call; the engine puts the session tokens back on the Mac before the write, so the file holds real values; the broker still approves from the tokenised arguments"),
    ),
    (
        PathId::B5,
        Choke::Gate("aux-tools registry: shell is mounted in both modes; gate_dispatch admits each call; the engine puts the session tokens back on the Mac before the command runs (sandbox and approvals unchanged); the session gate tokenises the output before the provider sees it"),
    ),
    (
        PathId::B6,
        Choke::Gate("aux-tools registry: http_fetch is mounted in both modes; gate_dispatch admits each call; in Private the url keeps its session tokens, so the request names the token and never the value, and the session gate tokenises the page text before the provider sees it"),
    ),
    (
        PathId::B7,
        Choke::Gate("aux-tools registry: weather forecast and geocode are mounted in both modes; gate_dispatch admits each call; in Private the place keeps its session tokens (aux-runtime tools/weather.rs accepts the token form), so the request names the token and never the value, and the session gate tokenises the answer before the provider sees it"),
    ),
    (
        PathId::B8,
        Choke::Mount("aux-google registry filter: Gmail search, read and list; gate_dispatch per call"),
    ),
    (
        PathId::B9,
        Choke::Mount("aux-google registry filter: Gmail draft; gate_dispatch per call"),
    ),
    (
        PathId::B10,
        Choke::Mount("aux-google registry filter: calendar list and get; gate_dispatch per call"),
    ),
    (
        PathId::B11,
        Choke::Gate("auxd apple_eventkit.rs registry: the EventKit snapshot tools mount in both modes (B11 is Covered since K16c); gate_dispatch admits each call and the session gate tokenises every event/reminder result in Private before the provider sees it"),
    ),
    (
        PathId::B12,
        Choke::Absent("invoices moved out of the app (WO-02, #200): no import route or tool in auxd"),
    ),
    (
        PathId::B13,
        Choke::Gate(
            "aux-mcp McpTool: HTTP servers are an outside service; the arguments keep session tokens (the engine restores none for B13) and the reply passes the session gate; the privacy watch restarts the runtime on open to private; gate_dispatch per call",
        ),
    ),
    (
        PathId::B14,
        Choke::Gate(
            "aux-mcp McpTool: a stdio child is local but most forward to the network, so it is treated as an outside service: the arguments keep session tokens (none restored for B14), the reply passes the session gate; the privacy watch restarts every child on open to private; gate_dispatch per call",
        ),
    ),
    (
        PathId::B15,
        Choke::Absent("hosted connector client removed (WO-01, #204): no route or tool in auxd"),
    ),
    (
        PathId::B16,
        Choke::Absent("external CRM connector deleted (Phase 1 D22): no route or tool in auxd"),
    ),
    (
        PathId::B17,
        Choke::Gate("aux-runtime executor.rs: a skill's Gmail send is skill-only; the owner approves each run and every recipient is checked against the known-contacts directory before the connector runs"),
    ),
    (
        PathId::B18,
        Choke::Gate("aux-runtime executor.rs: a skill's calendar create is skill-only; the owner approves each run and every attendee is checked against the known-contacts directory before the connector runs"),
    ),
    (
        PathId::B19,
        Choke::Gate("auxd api/turn.rs registry: the four mail read tools mount only for an agent that grants one (K16c makes B19 Covered, so Private keeps them mountable); gate_dispatch admits each call and the session gate tokenises every mail result in Private before the provider sees it"),
    ),
    (
        PathId::B20,
        Choke::Gate("auxd skill_executor.rs MailSkillConnector: mail.send is skill-only; the executor filters every to/cc recipient against the known-contacts directory before the connector, and the connector calls admit(PathId::B20) with the live mode once per to and cc recipient before any socket, and any Deny or an empty to list refuses the whole send (a Private AskEachTime is satisfied by the run card; a Deny refuses with a mail.call row)"),
    ),
    (
        PathId::B21,
        Choke::Absent("lands with A2b-t; calendar.create_event bridge tool not wired in auxd yet"),
    ),
    (
        PathId::B22,
        Choke::Gate("auxd api/turn.rs registry: mail_fetch_attachments and mail_draft mount only for a granted agent (K16c makes B22 Covered); gate_dispatch admits each call; bytes go only to the local evidence registry (StoreEvidence) and a draft only to the local encrypted journal; mail_draft never calls the mail transport"),
    ),
    (
        PathId::B23,
        Choke::Gate("auxd api/turn.rs registry: owner_profile is mounted in both modes; gate_dispatch admits each call, it reads only the local store (owner CRM card, owner contacts entry, owner.* facts), and the session gate tokenises the result in Private before the provider sees it; privacy_record_summary (AUX-EGRESS-TOOL) shares the row: a local read of the run receipts that returns counts, fixed class names and configured provider ids only"),
    ),
    (
        PathId::C1,
        Choke::Absent("aux-whatsapp is parked (tag parked-2026-10-12): no WhatsApp transport on main, so no inbound text reaches auxd"),
    ),
    (
        PathId::C2,
        Choke::Absent("aux-whatsapp is parked (tag parked-2026-10-12): no send or approval poll exists on main"),
    ),
    (
        PathId::C3,
        Choke::Absent("aux-whatsapp is parked (tag parked-2026-10-12): no voice controller starts"),
    ),
    (
        PathId::C4,
        Choke::Absent("aux-telegram is parked (tag parked-2026-10-12): no Telegram transport on main"),
    ),
    (
        PathId::C5,
        Choke::Absent("aux-telegram is parked (tag parked-2026-10-12): no Telegram transport on main"),
    ),
    (
        PathId::C6,
        Choke::Gate("auxd skill_executor.rs MailSkillConnector: the SMTP send is the one live caller of the aux-mail transport API and runs only after the B20 gate; the IMAP side is read through the B19 and B22 tools, the local brief, and the local sender lookup (MailSkillConnector::received_senders: INBOX From headers plus To/Cc headers of a Sent folder already inside only_folders, never a body, never sent to a model)"),
    ),
    (
        PathId::C7,
        Choke::Gate("aux-engine ChatSession::start: the event feed carries the gated copy only, and the input is gated before any row; raw text needs G1 and C7 both allowed (private::raw_text_allowed)"),
    ),
    (
        PathId::C8,
        Choke::Absent("Mac app clipboard (Swift, apps/auxesis-mac): reviewed, gate due in Wave 1c"),
    ),
    (
        PathId::C9,
        Choke::Absent("no capture API in the Mac app sources: reviewed, grep test due in Wave 1c"),
    ),
    (
        PathId::C10,
        Choke::Gate("auxd agent_job.rs and brief_job.rs notify: no notification in private mode"),
    ),
    (
        PathId::C11,
        Choke::Gate("auxd gateway/imessage.rs private_notice: the only text the gateway sends in private mode is the PRIVATE_NOTICE constant, built with no parameter and admitted under C11; the turn's answer stays in the channel session"),
    ),
    (
        PathId::C12,
        Choke::Gate("auxd api/private_answers.rs displayable: GET /v1/private/answers admits C12 for the local display in private mode only; the ring is in memory, capped, cleared when the mode is not private, and never stored or logged"),
    ),
    (
        PathId::D1,
        Choke::Gate("auxd api/turn.rs AcpSessionGate: the prompt goes through the session gate (D1 grant) before the agent starts, tokens in private"),
    ),
    (
        PathId::D2,
        Choke::Gate("auxd api/turn.rs AcpSessionGate + aux-acp read_text_file: file content is tokenised under a D2 grant before the agent gets it"),
    ),
    (
        PathId::D3,
        Choke::Gate("auxd api/turn.rs AcpSessionGate + aux-acp terminal_output: output is tokenised under a D3 grant (the daemon turn is read-only, so no terminal runs)"),
    ),
    (
        PathId::D4,
        Choke::Gate("aux-acp request_permission: the agent sends tokens, only the owner's approval card shows values, and the answer is an option id"),
    ),
    (
        PathId::E1,
        Choke::Absent(
            "aux-voice is parked (tag parked-2026-10-12): no speech synthesis on main",
        ),
    ),
    (
        PathId::E2,
        Choke::Absent("aux-voice is parked (tag parked-2026-10-12): no STT controller starts"),
    ),
    (
        PathId::F1,
        Choke::Gate("auxd agent_job.rs run: a job is a chat turn, so it starts the same aux-engine ChatSession as A1 (session gate on every text and tool argument, names read per run, over-limit contacts refused); retain_mountable drops uncovered tools; no title stored (G1); aux-providers GatedChat reads the live mode per completion; ModeChangeStop before each step; the notification is held (C10)"),
    ),
    (
        PathId::F2,
        Choke::Gate("auxd api/brief.rs run_brief_now (F2 gate, fail-closed on an unknown mode) with local_brief.rs: private mode reads the encrypted EventKit snapshot (local, at rest on this Mac) and a loopback IMAP mailbox only; a non-loopback or unparsable mail account is skipped before any socket; no model is called and the notification is counts-only"),
    ),
    (
        PathId::G1,
        Choke::Gate("aux-engine ChatSession::persist: the SQLCipher store keeps a private row as the gated copy the provider saw and the pairs its tokens stand for in session_tokens (PRIVATE-TRANSCRIPT); ChatSession::start reloads that table and keeps those tokens whole when it re-sends the rows; auxd display.rs rehydrates from it for the loopback page only; no title or system row is written in private mode; auxd turn.rs writes no title from the message"),
    ),
    (
        PathId::G2,
        Choke::Gate("auxd main.rs supervise_messages: inbound is dropped while private, so no channel row is written"),
    ),
    (
        PathId::G3,
        Choke::Gate("aux-tools registry: the memory and CRM tools are the only writers and are mounted in both modes; gate_dispatch admits each call; the store is local SQLCipher and only real values are written after the engine restores the session tokens"),
    ),
    (
        PathId::G4,
        Choke::Absent("aux-store: no mail table; the store enumeration test blocks one"),
    ),
    (
        PathId::G5,
        Choke::Gate(
            "auxd api/docs_api.rs and turn.rs: extracted text stays in encrypted SQLCipher; the bounded docs_ingest search/read tool returns excerpts through ChatSession's session Gate and untrusted tool-result taint while Private metadata stays reduced; evidence blobs are sealed at rest and a source scan fails any other raw reader",
        ),
    ),
    (
        PathId::G6,
        Choke::Gate("auxd turn.rs, agent_job.rs, brief_job.rs: no event payload is produced"),
    ),
    (
        PathId::G7,
        Choke::Gate("auxd turn.rs, agent_job.rs, brief_job.rs: no body reaches the log"),
    ),
    (
        PathId::H1,
        Choke::Absent(
            "aux-store: no vector or embedding table; the store enumeration test blocks one",
        ),
    ),
    (
        PathId::I1,
        Choke::Mitigation("aux-tools panic hook: payload-free, installed in main.rs"),
    ),
    (
        PathId::I2,
        Choke::Mitigation("auxd main.rs: disable_core_dumps() at start, whatever the mode"),
    ),
];

/// The table names in `aux-store`, each mapped to the row that covers it.
pub const STORE_TABLES: &[(&str, PathId)] = &[
    ("meta", PathId::G6),
    ("events", PathId::G6),
    ("sessions", PathId::G1),
    ("messages", PathId::G1),
    ("delegations", PathId::G1),
    ("thread_reads", PathId::G1),
    ("jobs", PathId::G1),
    ("runs", PathId::G6),
    ("usage", PathId::G6),
    ("usage_reservations", PathId::G6),
    // What a reconcile recorded for a held reservation it claimed: amounts
    // keyed by the reservation id, no content.
    ("usage_reconciled", PathId::G6),
    ("usage_calls", PathId::G6),
    ("budget_stops", PathId::G6),
    ("workspace_taint", PathId::G6),
    ("session_taint", PathId::G6),
    ("trust_requests", PathId::G6),
    ("channel_sessions", PathId::G2),
    ("channel_messages", PathId::G2),
    ("session_private_data", PathId::G6),
    ("session_tokens", PathId::G1),
    ("mcp_tools", PathId::G6),
    ("memory_items", PathId::G3),
    ("memory_items_fts", PathId::G3),
    ("memory_items_fts_data", PathId::G3),
    ("memory_items_fts_idx", PathId::G3),
    ("memory_items_fts_docsize", PathId::G3),
    ("memory_items_fts_config", PathId::G3),
    ("memory_sources", PathId::G3),
    ("profile_facts", PathId::G3),
    ("memory_episodes", PathId::G3),
    ("memory_notes", PathId::G3),
    ("memory_mirrors", PathId::G3),
    ("memory_suggestions", PathId::G3),
    // Contacts are personal data at rest, under the same row as memory: SQLCipher,
    // never sent to a model, and only the masked names reach the gate.
    ("contacts", PathId::G3),
    // The CRM at rest (`docs/phase1.md` §2): the same storage row as memory and
    // contacts. Real values stay in SQLCipher; every party write refreshes the
    // `crm` contacts source, so only tokens reach the next provider call.
    ("party", PathId::G3),
    ("relationship", PathId::G3),
    ("interaction", PathId::G3),
    ("followup", PathId::G3),
    ("documents", PathId::G5),
    ("proofs", PathId::G5),
    ("corrections", PathId::G5),
    ("evidence_guard", PathId::G5),
    ("evidence_source", PathId::G5),
    ("evidence_erase_tombstones", PathId::G5),
    ("document_text_backfill", PathId::G5),
    // Extracted fields, checks and text for an evidence document (C2b). Same
    // SQLCipher boundary as originals and provenance; OCR text reaches a model
    // only as a bounded excerpt through the session Gate.
    ("document_fields", PathId::G5),
    // A send claim on a stored draft: the draft's event id, a state and two
    // timestamps, no content. Same row as `events`, and erased with it (ON
    // DELETE CASCADE).
    ("mail_draft_claim", PathId::G6),
];

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_core::privacy::{admit, Context, Decision, Destination, REGISTRY};
    use std::sync::Arc;

    #[test]
    fn rehydrate_local_resolves_only_this_sessions_tokens() {
        // Fictional session ids, far from any real one.
        let tokens = aux_engine::skill_runtime::session_tokens(9_100_001);
        kernel_core::sync::lock_recover(&tokens).record(&[
            ("PERSON_0123456789AB".into(), "Camille Exemple".into()),
            (
                "EMAIL_000000000101".into(),
                "fixture.user@example.invalid".into(),
            ),
        ]);

        let text = "Hi ⟦PERSON_0123456789AB⟧, ⟦EMAIL_FFFFFFFFFFFF⟧, ⟦⟦literal; https://evil.invalid/?q=⟦EMAIL_000000000101⟧ prose ⟦EMAIL_000000000101⟧ ⟦open";
        assert_eq!(
            rehydrate_local(9_100_001, text),
            "Hi Camille Exemple, [name hidden], ⟦literal; https://evil.invalid/?q=[hidden] prose fixture.user@example.invalid ⟦open"
        );
        // Another session's table does not know this session's token.
        assert_eq!(
            rehydrate_local(9_100_002, "⟦PERSON_0123456789AB⟧"),
            "[name hidden]"
        );
    }

    #[test]
    fn rehydrate_local_hides_srcset_candidates_and_style_urls() {
        let tokens = aux_engine::skill_runtime::session_tokens(9_100_004);
        kernel_core::sync::lock_recover(&tokens).record(&[(
            "EMAIL_000000000201".into(),
            "fixture.user@example.invalid".into(),
        )]);
        let token = "⟦EMAIL_000000000201⟧";
        let text = format!(
            "<img srcset=\"https://x.invalid/1?q={token} 1x, https://y.invalid/2?q={token} 2x\" style='background:url(https://z.invalid/?q={token})'>"
        );
        assert_eq!(
            rehydrate_local(9_100_004, &text),
            "<img srcset=\"https://x.invalid/1?q=[hidden] 1x, https://y.invalid/2?q=[hidden] 2x\" style='background:url(https://z.invalid/?q=[hidden])'>"
        );
    }

    #[test]
    fn rehydrate_local_hides_tokens_in_bare_host_labels() {
        let tokens = aux_engine::skill_runtime::session_tokens(9_100_005);
        kernel_core::sync::lock_recover(&tokens)
            .record(&[("CARD_000000000004".into(), "0000000000000000".into())]);
        assert_eq!(
            rehydrate_local(9_100_005, "⟦CARD_000000000004⟧.evil.invalid/path"),
            "[hidden].evil.invalid/path"
        );
    }

    #[test]
    fn rehydrate_local_is_linear_on_openers_with_no_closer() {
        // Model output of `⟦x` repeated: 1 MiB and no closer. A rescan of the
        // rest of the text at each opener took 15 s in release; one pass is a
        // few milliseconds. The bound is generous so a debug build passes.
        let text = "⟦x".repeat(1024 * 1024 / 4);
        let started = std::time::Instant::now();
        let shown = rehydrate_local(9_100_003, &text);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(shown, text);
        let tokens = aux_engine::skill_runtime::session_tokens(9_100_003);
        kernel_core::sync::lock_recover(&tokens).record(&[(
            "EMAIL_000000000111".into(),
            "fixture.user@example.invalid".into(),
        )]);
        let url = format!(
            "{}://evil.invalid/{}?q=⟦EMAIL_000000000111⟧",
            "a".repeat(100_000),
            "x".repeat(100_000)
        );
        let started = std::time::Instant::now();
        let shown = rehydrate_local(9_100_003, &url);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(shown.ends_with("q=[hidden]"));
        // A closer past the longest reference is not read as one.
        let far = format!("⟦{}⟧", "x".repeat(MAX_REFERENCE_BYTES + 1));
        assert_eq!(rehydrate_local(9_100_003, &far), far);
    }

    fn choke_for(id: PathId) -> Vec<Choke> {
        CHOKE_POINTS
            .iter()
            .filter(|(path, _)| *path == id)
            .map(|(_, choke)| *choke)
            .collect()
    }

    #[test]
    fn every_path_has_a_choke_point() {
        for id in PathId::ALL {
            assert!(
                !choke_for(*id).is_empty(),
                "path {} has no choke point; add it to CHOKE_POINTS",
                id.as_str()
            );
        }
        assert_eq!(CHOKE_POINTS.len(), PathId::ALL.len(), "one entry per path");
    }

    #[test]
    fn the_absent_rows_are_the_reviewed_set() {
        // Each of these has a reason in CHOKE_POINTS. A new `Absent` row must be
        // reviewed here first.
        const REVIEWED: &[&str] = &[
            "B12", "B15", "B16", "B21", "C1", "C2", "C3", "C4", "C5", "C8", "C9", "E1", "E2", "G4",
            "H1",
        ];
        let absent: Vec<&str> = CHOKE_POINTS
            .iter()
            .filter(|(_, choke)| matches!(choke, Choke::Absent(_)))
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(absent, REVIEWED);
    }

    #[test]
    fn every_disabled_private_row_is_held_by_a_gate_or_a_mount() {
        // A disabled row is held by a gate, a mount, an absence, or a
        // mitigation (I2: core dumps off, with the value paths gated elsewhere).
        for row in REGISTRY {
            if row.private != kernel_core::privacy::Behaviour::Allow {
                let held = choke_for(row.id).iter().any(|choke| {
                    matches!(
                        choke,
                        Choke::Gate(_) | Choke::Mount(_) | Choke::Absent(_) | Choke::Mitigation(_)
                    )
                });
                assert!(held, "disabled path {} has no gate", row.id.as_str());
            }
        }
    }

    #[test]
    fn every_store_table_has_a_privacy_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = aux_store::Store::open(&dir.path().join("store.db")).expect("open store");
        let tables = store.table_names().expect("list tables");
        for table in &tables {
            assert!(
                STORE_TABLES.iter().any(|(name, _)| name == table),
                "store table {table} has no privacy path; add it to STORE_TABLES"
            );
        }
        assert!(
            tables.iter().any(|table| table == "events"),
            "store opened with no events table"
        );
    }

    #[test]
    fn current_mode_reads_the_config_and_fails_closed() {
        let missing = Err::<kernel_core::Config, _>("unreadable");
        assert_eq!(mode_of(&missing), PrivacyMode::Private);
        let mut open = kernel_core::Config::default();
        open.privacy.mode = PrivacyMode::Open;
        assert_eq!(mode_of(&Ok::<_, &str>(open)), PrivacyMode::Open);
    }

    #[test]
    fn private_mode_keeps_voice_unmounted_and_mounts_mcp() {
        // Voice (C3) is not mounted. Both MCP transports are, since the
        // arguments keep session tokens and the reply passes the session gate.
        assert!(!kernel_core::privacy::may_mount(
            PathId::C3,
            PrivacyMode::Private
        ));
        for transport in [
            kernel_mcp::McpTransport::Stdio,
            kernel_mcp::McpTransport::Http,
        ] {
            let path = kernel_mcp::transport_path(transport);
            for mode in [PrivacyMode::Private, PrivacyMode::Open] {
                assert!(kernel_core::privacy::may_mount(path, mode));
            }
        }
    }

    #[test]
    fn a_hosted_chat_call_is_admitted_in_both_modes() {
        // kernel-0.0.2 covers A1 in private mode. A private turn with no contacts
        // is refused later, by the names check in `ChatSession::start`.
        let ctx = Context {
            destination: Destination::Vendor("hosted".to_string()),
        };
        assert!(matches!(
            admit(PathId::A1, PrivacyMode::Private, &ctx),
            Decision::Allow(_)
        ));
        assert!(matches!(
            admit(PathId::A1, PrivacyMode::Open, &ctx),
            Decision::Allow(_)
        ));
    }

    #[test]
    fn the_memory_rows_mount_in_private_because_they_are_covered() {
        // Memory is storage. B1, B2 and G3 are Covered and Allow
        // in Private, so `retain_mountable` keeps the memory tools mounted;
        // the engine's session gate still tokenises every result.
        for id in [PathId::B1, PathId::B2, PathId::G3] {
            assert!(
                kernel_core::privacy::may_mount(id, PrivacyMode::Private),
                "path {} must mount in private mode",
                id.as_str()
            );
        }
    }

    #[test]
    fn the_mail_and_calendar_reads_mount_in_private_because_they_are_covered() {
        // B11, B19 and B22 become Covered and Allow in
        // Private, so `retain_mountable` keeps the EventKit and mail tools
        // mounted; the session gate tokenises every result before the provider.
        for id in [PathId::B11, PathId::B19, PathId::B22] {
            assert!(
                kernel_core::privacy::may_mount(id, PrivacyMode::Private),
                "path {} must mount in private mode",
                id.as_str()
            );
        }
        // The sends next to them stay unusable from a plain conversation.
        for id in [PathId::B20, PathId::B21] {
            assert!(
                !kernel_core::privacy::may_mount(id, PrivacyMode::Private),
                "path {} must not mount in private mode",
                id.as_str()
            );
        }
    }

    /// B20 is not an ungated `Absent` row. It is held by a Gate, and in Private
    /// it is an `AskEachTime` the connector satisfies with
    /// the run card plus the executor's recipient filter.
    #[test]
    fn the_mail_send_row_is_gated() {
        assert!(
            matches!(choke_for(PathId::B20).as_slice(), [Choke::Gate(_)]),
            "B20 must be a Gate, not {:?}",
            choke_for(PathId::B20)
        );
        let ctx = Context {
            destination: Destination::Recipient("camille@exemple.fr".to_string()),
        };
        assert!(
            matches!(
                admit(PathId::B20, PrivacyMode::Private, &ctx),
                Decision::Ask(_)
            ),
            "a Private send asks, and the run card is the answer"
        );
        assert!(
            matches!(
                admit(PathId::B20, PrivacyMode::Open, &ctx),
                Decision::Allow(_)
            ),
            "Open allows the send"
        );
    }

    /// Write `mode` into the config under `home`, the way the owner's switch does.
    fn set_mode(home: &Path, mode: &str) {
        std::fs::write(
            home.join("config.toml"),
            format!("version = 1\n\n[privacy]\nmode = \"{mode}\"\n"),
        )
        .unwrap();
    }

    #[test]
    fn a_handoff_mode_is_never_loosened_after_the_handoff() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let open: ModeFn = Arc::new(|| PrivacyMode::Open);
        // Private at handoff: a later switch to public changes nothing.
        set_mode(home, "private");
        let (at, floor) = handoff_mode_fn(Arc::clone(&open), agent_mode_fn(home, "aux"));
        set_mode(home, "public");
        assert_eq!((at, floor()), (PrivacyMode::Private, PrivacyMode::Private));
        // Public at handoff: a later switch to private still tightens it.
        let (at, floor) = handoff_mode_fn(Arc::clone(&open), agent_mode_fn(home, "aux"));
        assert_eq!((at, floor()), (PrivacyMode::Open, PrivacyMode::Open));
        set_mode(home, "private");
        assert_eq!(floor(), PrivacyMode::Private);
    }

    #[test]
    fn the_live_mode_follows_each_switch_of_the_config() {
        // The public -> private -> public round trip, read by a handle made once.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        set_mode(home, "public");
        let live = live_mode_fn(home);
        assert_eq!(live(), PrivacyMode::Open);

        set_mode(home, "private");
        assert_eq!(live(), PrivacyMode::Private, "the handle sees the switch");

        set_mode(home, "public");
        assert_eq!(live(), PrivacyMode::Open, "and the switch back");
    }

    #[test]
    fn a_missing_config_reads_private_and_a_broken_one_reads_private() {
        // A fresh home has no config yet: the default is private, and so is a
        // config that cannot be parsed.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(current_mode(dir.path()), PrivacyMode::Private);
        std::fs::write(
            dir.path().join("config.toml"),
            "[privacy]\nmode = \"Private\"\n",
        )
        .unwrap();
        assert_eq!(current_mode(dir.path()), PrivacyMode::Private);
    }

    #[test]
    fn the_private_stop_engages_only_while_the_home_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let stop = PrivateStop::new(dir.path());
        set_mode(dir.path(), "public");
        assert!(!stop.is_stopped());
        set_mode(dir.path(), "private");
        assert!(stop.is_stopped());
        set_mode(dir.path(), "public");
        assert!(!stop.is_stopped());
    }

    #[tokio::test]
    async fn an_acp_turn_is_cancelled_once_the_home_turns_private() {
        let dir = tempfile::tempdir().unwrap();
        set_mode(dir.path(), "public");
        let token = kernel_broker::CancelToken::new();
        let watch = tokio::spawn(cancel_when_private(
            dir.path().to_path_buf(),
            Arc::clone(&token),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!token.is_cancelled(), "public: the turn keeps running");

        set_mode(dir.path(), "private");
        tokio::time::timeout(WATCH_INTERVAL * 3, watch)
            .await
            .expect("the watch returns after the switch")
            .unwrap();
        assert!(token.is_cancelled());
    }

    struct Probe {
        path: PathId,
        runs: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl kernel_broker::Tool for Probe {
        fn class(&self) -> kernel_broker::ToolClass {
            kernel_broker::ToolClass::default()
        }
        fn name(&self) -> &str {
            "probe"
        }
        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }
        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &kernel_broker::ToolCtx,
        ) -> Result<kernel_broker::ToolOutput, kernel_broker::ToolError> {
            self.runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(kernel_broker::ToolOutput::ok("ran"))
        }
        fn risk(&self) -> kernel_broker::Risk {
            kernel_broker::Risk::Low
        }
        fn path_id(&self) -> PathId {
            self.path
        }
    }

    #[tokio::test]
    async fn a_mounted_tool_stops_dispatching_when_the_home_turns_private() {
        // The mount was decided in public mode; the dispatch gate reads the config
        // on every call, so the switch lands on the tool that is already mounted.
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        set_mode(home, "public");
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut registry = kernel_broker::ToolRegistry::new();
        registry.register(Box::new(Probe {
            path: PathId::B8,
            runs: Arc::clone(&runs),
        }));
        kernel_broker::gate_dispatch(&mut registry, live_mode_fn(home));
        let ctx = kernel_broker::ToolCtx::new("main", home);

        assert!(
            dispatch(&registry, &ctx).await.is_ok(),
            "public: the tool runs"
        );

        set_mode(home, "private");
        match dispatch(&registry, &ctx).await {
            Err(kernel_broker::ToolError::PrivacyDisabled { path }) => assert_eq!(path, "B8"),
            other => panic!("expected privacy_disabled, got {other:?}"),
        }
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);

        set_mode(home, "public");
        assert!(
            dispatch(&registry, &ctx).await.is_ok(),
            "public again: it runs again"
        );
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// One call to the mounted probe, as the engine makes it.
    async fn dispatch(
        registry: &kernel_broker::ToolRegistry,
        ctx: &kernel_broker::ToolCtx,
    ) -> Result<kernel_broker::ToolOutput, kernel_broker::ToolError> {
        registry
            .get("probe")
            .expect("mounted")
            .run(&serde_json::json!({}), ctx)
            .await
    }
}
