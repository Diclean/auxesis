//! The registry: one row per data path. New rows are added to
//! `docs/phase1.md` §2 with their private and open behaviour. A change to a
//! row is a privacy decision: change the contract first.
//!
//! Where the matrix says "DISABLED for hosted hosts" or "DISABLED except an
//! explicit click", the row is `Disabled`. That is the conservative choice.
//! The finer rule belongs to the destination check in Wave 1b.

use super::path::PathId;
use super::path::PathId::*;
use super::policy::Behaviour::{Allow, AskEachTime, Disabled};
use super::policy::RecipientRule::FilteredRecipients;
use super::policy::Status::{Covered, NotCovered, Partial};
use super::policy::{Behaviour, PathPolicy, Status};

const fn row(
    id: PathId,
    label: &'static str,
    status: Status,
    private: Behaviour,
    open: Behaviour,
    slice: &'static str,
) -> PathPolicy {
    PathPolicy {
        id,
        label,
        status,
        private,
        open,
        slice,
    }
}

/// Every row. `Allow` in private mode only on `Covered` rows (A1, A2, C9,
/// I1, memory rows B1, B2, G3 since K16b, mail and calendar reads B11, B19, B22 since K16c, and gated document excerpts G5 since DOC-READ-1,
/// the morning brief F2 since WO-PRIVBRIEF-1, the daily tools B3 to B7 since TOK-3, the owner profile B23 since ASK-1, the ACP rows D1 to D4 since TOK-6, and the MCP rows B13, B14 since TOK-7, the iMessage fixed notice C11 and held answers C12), which the tests enforce. B15 (absent) and B16 (deleted) are disabled in
/// both modes.
///
/// One row per line, so the table reads like the matrix. rustfmt is off here.
#[rustfmt::skip]
pub static REGISTRY: &[PathPolicy] = &[
    // 2a. Chat providers
    row(A1, "Streaming chat", Covered, Allow, Allow, "2a"),
    row(A2, "Non-streaming chat", Covered, Allow, Allow, "2a"),
    row(A3, "Endpoint probe", Covered, Disabled, Allow, "none"),
    // 2b. Tool results, by tool
    row(B1, "memory recall (storage, D24): results reach a provider only through the session gate", Covered, Allow, Allow, "A5"),
    row(B2, "remember and forget (storage, D24): session tokens rehydrated locally before the write", Covered, Allow, Allow, "A5"),
    row(B3, "read_file: local read; the content reaches a provider only through the session gate", Covered, Allow, Allow, "TOK-3"),
    row(B4, "write_file: local write; session tokens in the arguments are restored on the Mac first", Covered, Allow, Allow, "TOK-3"),
    row(B5, "shell: local run; session tokens in the arguments are restored on the Mac first, the output goes back through the session gate", Covered, Allow, Allow, "TOK-3"),
    row(B6, "http_fetch: the request keeps session tokens in the URL (never the value); the page text reaches a provider only through the session gate", Covered, Allow, Allow, "TOK-3"),
    row(B7, "weather forecast and geocode: the request keeps session tokens in the place (never the value); results reach a provider only through the session gate", Covered, Allow, Allow, "TOK-3"),
    row(B8, "Gmail search, read and list", NotCovered, Disabled, Allow, "4a"),
    row(B9, "Gmail draft", NotCovered, Disabled, Allow, "4b"),
    row(B10, "Calendar list and get", NotCovered, Disabled, Allow, "4a"),
    row(B11, "EventKit read (calendar snapshot): results reach a provider only through the session gate", Covered, Allow, Allow, "MA3"),
    row(B12, "invoice import", NotCovered, Disabled, Allow, "3c"),
    row(B13, "MCP HTTP servers: an outside service; the arguments keep session tokens (never the value); the reply reaches a provider only through the session gate", Covered, Allow, Allow, "TOK-7"),
    row(B14, "MCP stdio children: treated as an outside service, since most forward to the network; the arguments keep session tokens; the reply goes through the session gate", Covered, Allow, Allow, "TOK-7"),
    row(B15, "cloud connector middleman (absent)", NotCovered, Disabled, Disabled, "none"),
    row(B16, "deleted (Zoho, D22)", NotCovered, Disabled, Disabled, "none"),
    row(B17, "Gmail send, out to Google: reachable only from a skill; real values rehydrated locally after approval; recipient policy enforced per value", NotCovered, AskEachTime(FilteredRecipients), Allow, "4b"),
    row(B18, "Calendar create with attendees, out to Google: reachable only from a skill; real values rehydrated locally after approval; recipient policy enforced per value", NotCovered, AskEachTime(FilteredRecipients), Allow, "4a"),
    row(B19, "IMAP read: list, search, thread, read (tool results through the session gate)", Covered, Allow, Allow, "MA3"),
    row(B20, "Mail send over SMTP: reachable only from a skill; real values rehydrated locally after approval; recipient policy enforced per value", NotCovered, AskEachTime(FilteredRecipients), Allow, "A2"),
    row(B21, "EventKit create or update event through the Mac bridge: reachable only from a skill; real values rehydrated locally after approval; recipient policy enforced per value", NotCovered, AskEachTime(FilteredRecipients), Allow, "A2b"),
    row(B22, "IMAP attachment download into the local evidence registry (storage, local only)", Covered, Allow, Allow, "MA3"),
    row(B23, "owner_profile: read of the owner's own details (CRM card, contacts entry, saved facts); results reach a provider only through the session gate", Covered, Allow, Allow, "ASK-1"),
    // 2c. Channels, in and out
    row(C1, "WhatsApp text in", Partial, Disabled, Allow, "3b"),
    row(C2, "WhatsApp text out", NotCovered, Disabled, Allow, "3b"),
    row(C3, "WhatsApp voice", NotCovered, Disabled, Allow, "6a"),
    row(C4, "Telegram in", Partial, Disabled, Allow, "3b"),
    row(C5, "Telegram out", NotCovered, Disabled, Allow, "3b"),
    row(C6, "mail IMAP and SMTP", NotCovered, Disabled, Allow, "6b"),
    row(C7, "chat input and event feed", NotCovered, Disabled, Allow, "3c"),
    row(C8, "Mac clipboard and caches", Partial, Disabled, Allow, "3c"),
    row(C9, "screenshots", Covered, Allow, Allow, "1c"),
    row(C10, "macOS notifications", Partial, Disabled, Allow, "3b"),
    row(C11, "iMessage private-mode notice: one fixed phrase built by the gateway, never session, model or owner text (the answer stays in the app)", Covered, Allow, Allow, "PRIV-IMSG"),
    row(C12, "private answers held in memory and shown to the owner's app over the loopback API (local display only; never stored, logged or sent)", Covered, Allow, Allow, "PRIV-IMSG"),
    // 2d. ACP agents
    row(D1, "ACP prompt (tokenised by the chat session gate)", Covered, Allow, Allow, "2a, 5c"),
    row(D2, "ACP host file read (tokenised before it reaches the agent)", Covered, Allow, Allow, "3c"),
    row(D3, "ACP host terminal output (tokenised before it reaches the agent)", Covered, Allow, Allow, "5c"),
    row(D4, "ACP agent permission params (values shown to the owner only)", Covered, Allow, Allow, "5c"),
    // 2e. Voice
    row(E1, "TTS speak", NotCovered, Disabled, Allow, "6a"),
    row(E2, "STT", NotCovered, Disabled, Allow, "6a"),
    // 2f. Scheduler and agent jobs
    row(F1, "agent jobs (a scheduled run is a chat turn with tools: same session gate, same tool mounting, no stored title)", Covered, Allow, Allow, "2a, then each tool"),
    row(F2, "morning brief (local sources only: EventKit snapshot where B11 serves one, loopback IMAP mail; no model; counts-only notification)", Covered, Allow, Allow, "4a"),
    // 2g. Local stores
    row(G1, "chat history store (SQLCipher, local only; a private row is the tokenised copy the provider saw, its token table is in the same store)", Covered, Allow, Allow, "2c"),
    row(G2, "channel message store", NotCovered, Disabled, Allow, "3b"),
    row(G3, "memory store (SQLCipher, local only)", Covered, Allow, Allow, "A5"),
    row(G4, "mail archive (no table)", Covered, Disabled, Allow, "6b"),
    row(G5, "documents and proofs store (model excerpts pass the session Gate)", Covered, Allow, Allow, "DOC-READ-1"),
    row(G6, "audit log", NotCovered, Disabled, Allow, "5d"),
    row(G7, "app logs", Partial, Disabled, Allow, "5d"),
    // 2h. Embeddings
    row(H1, "embeddings (none on main)", Covered, Disabled, Allow, "3a"),
    // 2i. Crash and panic
    row(I1, "panic messages", Covered, Allow, Allow, "none"),
    row(I2, "OS crash reports and core dumps", NotCovered, Disabled, Allow, "1c"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_matrix_row_has_exactly_one_policy() {
        assert_eq!(REGISTRY.len(), PathId::ALL.len());
        for id in PathId::ALL {
            let rows = REGISTRY.iter().filter(|row| row.id == *id).count();
            assert_eq!(rows, 1, "path {} has {rows} rows", id.as_str());
        }
    }

    #[test]
    fn status_counts_match_the_matrix_footer() {
        // 53 rows after K16b: COVERED 10, PARTIAL 9, NOT COVERED 34. K16 adds
        // B19 to B22, all NOT COVERED; B16 (deleted) stays NOT COVERED. K16b
        // flips the memory rows B1, B2 and G3 to COVERED (D24). K16c flips mail
        // read B19, attachments B22 and calendar read B11: 13 / 9 / 31.
        // WO-PRIVBRIEF-1 flips the morning brief F2: 14 / 9 / 30. TOK-2 flips
        // agent jobs F1 (they run through the chat session gate): 15 / 9 / 29.
        // TOK-3 flips read_file B3, write_file B4, shell B5, http_fetch B6 and
        // weather B7; TOK-6 flips the ACP rows D1 to D4 (the host text passes
        // the session gate): 24 / 6 / 23. ASK-1 adds owner_profile B23 as
        // COVERED: 25 / 6 / 23. TOK-7 flips the MCP rows B13 and B14
        // (arguments keep tokens, replies pass the session gate): 27 / 5 / 22.
        // PRIV-IMSG adds the iMessage fixed notice C11 as COVERED: 28 / 5 / 22. PRIV-IMSG-2 adds C12 as COVERED: 29 / 5 / 22.
        let count = |wanted: Status| REGISTRY.iter().filter(|row| row.status == wanted).count();
        assert_eq!(count(Status::Covered), 31);
        assert_eq!(count(Status::Partial), 5);
        assert_eq!(count(Status::NotCovered), 20);
    }

    #[test]
    fn document_store_text_is_covered_for_session_gated_reads() {
        let row = REGISTRY.iter().find(|row| row.id == G5).unwrap();
        assert_eq!(row.status, Covered);
        assert_eq!(row.private, Allow);
        assert_eq!(row.open, Allow);
    }

    #[test]
    fn mail_and_calendar_reads_are_covered_in_both_modes() {
        // K16c (with MA3): mail read, attachment download into the local
        // registry, and the calendar snapshot. Their results reach a provider
        // only through the session gate, so Private mode allows them.
        for id in [B11, B19, B22] {
            let row = REGISTRY
                .iter()
                .find(|row| row.id == id)
                .expect("every path has a row");
            assert_eq!(row.status, Status::Covered, "path {}", id.as_str());
            assert_eq!(row.private, Allow, "path {}", id.as_str());
            assert_eq!(row.open, Allow, "path {}", id.as_str());
        }
        // The sends next to them stay behind the owner's approval.
        for id in [B20, B21] {
            let row = REGISTRY.iter().find(|row| row.id == id).unwrap();
            assert_eq!(row.status, Status::NotCovered, "path {}", id.as_str());
        }
    }

    #[test]
    fn the_morning_brief_is_covered_because_every_source_is_local() {
        // WO-PRIVBRIEF-1: the brief is deterministic (no model, no prompt, no
        // network client) and stored locally; its notification is counts-only.
        // The sources enforce the rest: the EventKit snapshot (none in private,
        // B11), and mail only from a loopback IMAP host in private mode (auxd
        // local_brief.rs).
        let row = REGISTRY
            .iter()
            .find(|row| row.id == F2)
            .expect("every path has a row");
        assert_eq!(row.status, Status::Covered);
        assert_eq!(row.private, Allow);
        assert_eq!(row.open, Allow);
    }

    #[test]
    fn the_daily_tools_are_covered_in_both_modes() {
        // TOK-3: local tools (read_file, write_file, shell) restore the session
        // tokens on the Mac and answer through the session gate; the web tools
        // (http_fetch, weather) send the masked form and answer through it too.
        for id in [B3, B4, B5, B6, B7, B23] {
            let row = REGISTRY
                .iter()
                .find(|row| row.id == id)
                .expect("every path has a row");
            assert_eq!(row.status, Status::Covered, "path {}", id.as_str());
            assert_eq!(row.private, Allow, "path {}", id.as_str());
            assert_eq!(row.open, Allow, "path {}", id.as_str());
        }
    }

    #[test]
    fn the_mcp_servers_are_covered_in_both_modes() {
        // TOK-7: every MCP server, HTTP or stdio, is an outside service. Its
        // arguments keep the session tokens (nothing is restored) and its reply
        // reaches a provider only through the session gate.
        for id in [B13, B14] {
            let row = REGISTRY
                .iter()
                .find(|row| row.id == id)
                .expect("every path has a row");
            assert_eq!(row.status, Status::Covered, "path {}", id.as_str());
            assert_eq!(row.private, Allow, "path {}", id.as_str());
            assert_eq!(row.open, Allow, "path {}", id.as_str());
        }
    }

    #[test]
    fn agent_jobs_are_covered_because_they_reuse_the_chat_session_gate() {
        // TOK-2: a scheduled run is a chat turn with tools. It runs the engine's
        // ChatSession (session gate on every outbound text and tool argument,
        // local rehydration), mounts the tools a private chat mounts, and
        // stores no title (G1). Private allows it; so does open.
        let row = REGISTRY
            .iter()
            .find(|row| row.id == F1)
            .expect("every path has a row");
        assert_eq!(row.status, Status::Covered);
        assert_eq!(row.private, Allow);
        assert_eq!(row.open, Allow);
    }

    #[test]
    fn memory_rows_are_covered_storage_in_both_modes() {
        // K16b (D24): memory is storage. Private mode allows it because every
        // recalled byte reaches a provider only through the session gate.
        // PRIVATE-TRANSCRIPT: so is the chat history (G1), on the same terms.
        for id in [B1, B2, G3, G1] {
            let row = REGISTRY
                .iter()
                .find(|row| row.id == id)
                .expect("every path has a row");
            assert_eq!(row.status, Status::Covered, "path {}", id.as_str());
            assert_eq!(row.private, Allow, "path {}", id.as_str());
            assert_eq!(row.open, Allow, "path {}", id.as_str());
        }
    }

    #[test]
    fn skill_only_sends_need_owner_approval_in_private_mode() {
        // Private mode: the provider sees only tokens, the executor rehydrates
        // after the owner approves, and the recipient filter applies per value.
        // So the call is neither a plain Allow nor a Deny: it waits for the owner.
        use super::super::gate::{admit, Context, Decision, Destination, Needs};
        use super::super::mode::PrivacyMode;

        let third_party = Context {
            destination: Destination::Recipient("client".to_string()),
        };
        let owner = Context {
            destination: Destination::OwnerSelf,
        };
        for id in [B17, B18, B20, B21] {
            match admit(id, PrivacyMode::Private, &third_party) {
                Decision::Ask(request) => assert_eq!(
                    request.needs,
                    Needs::OwnerApprovalAndRecipientFilter {
                        alias: "client".to_string()
                    },
                    "path {}",
                    id.as_str()
                ),
                other => panic!("path {}: expected Ask, got {other:?}", id.as_str()),
            }
            match admit(id, PrivacyMode::Private, &owner) {
                Decision::Ask(request) => assert_eq!(request.needs, Needs::OwnerApproval),
                other => panic!("path {}: expected Ask, got {other:?}", id.as_str()),
            }
        }
    }

    #[test]
    fn skill_only_sends_are_open_and_ask_in_private() {
        // The rows: private asks the owner per value, open runs as the other
        // outbound rows do.
        let policy = |wanted: PathId| {
            REGISTRY
                .iter()
                .find(|row| row.id == wanted)
                .expect("every path has a row")
        };
        for id in [B17, B18, B20, B21] {
            let row = policy(id);
            assert_eq!(
                row.private,
                AskEachTime(FilteredRecipients),
                "path {}",
                id.as_str()
            );
            assert_eq!(row.open, Allow, "path {}", id.as_str());
        }
    }

    #[test]
    fn private_allow_only_on_covered_rows() {
        // Owner principle: private mode runs only what the kernel covers.
        for row in REGISTRY {
            if row.private == Behaviour::Allow {
                assert_eq!(row.status, Status::Covered, "path {}", row.id.as_str());
            }
        }
    }

    #[test]
    fn only_b15_and_b16_are_disabled_in_open_mode() {
        // B15: "DISABLED, always (cloud middleman, owner decision)".
        // B16 is the deleted Zoho row (D22): disabled in both modes.
        let disabled: Vec<&str> = REGISTRY
            .iter()
            .filter(|row| row.open == Behaviour::Disabled)
            .map(|row| row.id.as_str())
            .collect();
        assert_eq!(disabled, ["B15", "B16"]);
    }

    #[test]
    fn deleted_zoho_row_is_disabled_in_both_modes() {
        // K16: "deleted (Zoho, D22)". No mode may mount or run it.
        let row = REGISTRY
            .iter()
            .find(|row| row.id == B16)
            .expect("every path has a row");
        assert_eq!(row.label, "deleted (Zoho, D22)");
        assert_eq!(row.private, Disabled);
        assert_eq!(row.open, Disabled);
    }
}
