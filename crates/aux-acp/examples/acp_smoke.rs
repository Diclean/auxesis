//! One live ACP turn, for `scripts/acp-smoke.sh` (manual smoke only — never
//! run in CI).
//!
//! ```text
//! cargo run -p aux-acp --example acp-smoke -- "say ok"
//! ```
//!
//! Environment:
//! - `AUX_ACP_COMMAND` (default `opencode`) and `AUX_ACP_ARGS` (default
//!   `acp`, whitespace-separated);
//! - `AUX_ACP_WORKSPACE` (default: a fresh dir under `$TMPDIR`);
//! - `AUX_ACP_VENDOR_DATA` (optional read-only vendor data dir so the CLI's
//!   own login is visible to the child, e.g. `~/.local/share/opencode`).
//!
//! The owner's credentials are never read by this program: the child gets a
//! read-only sandbox view of the vendor data dir and uses its own login.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aux_acp::{
    AcpAgentSpec, AcpBackend, AcpBackendConfig, AcpError, AcpLimits, AcpTurnRequest, AgentBackend,
    TurnHost, TurnObserver, TurnReservation, UsageUpdate,
};
use aux_engine::StdinApprover;
use aux_store::Message;
use kernel_broker::sandbox::ShellSandbox;

struct PrintObserver;

impl TurnObserver for PrintObserver {
    fn message_chunk(&mut self, chunk: &str) {
        use std::io::Write;
        print!("{chunk}");
        let _ = std::io::stdout().flush();
    }
}

/// A host that only prints: the smoke path persists nothing and reserves
/// nothing.
struct PrintingHost;

impl TurnHost for PrintingHost {
    fn reserve_turn(&mut self, cost_cents: u64) -> Result<Option<TurnReservation>, AcpError> {
        eprintln!("[smoke] reserved a fixed {cost_cents} cent estimate (no store)");
        Ok(None)
    }

    fn settle_turn(
        &mut self,
        _reservation: Option<TurnReservation>,
        observed: &UsageUpdate,
    ) -> Result<(), AcpError> {
        eprintln!("[smoke] observed usage (best effort): {observed:?}");
        Ok(())
    }

    fn persist_assistant(&mut self, text: &str, meta: &str) -> Result<Message, AcpError> {
        eprintln!(
            "[smoke] would persist one assistant message ({} bytes) meta={meta}",
            text.len()
        );
        Ok(Message {
            id: 0,
            session_id: 0,
            role: "assistant".to_string(),
            content: text.to_string(),
            created_at: String::new(),
            meta: Some(meta.to_string()),
        })
    }

    fn emit_message(&mut self, _message: &Message) {}

    fn emit_done(&mut self, _message_id: i64) {}

    fn taint_session(&mut self, source: &str) -> Result<(), AcpError> {
        eprintln!("[smoke] conversation marked tainted ({source})");
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let prompt = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "say ok".to_string());
    let command = std::env::var("AUX_ACP_COMMAND").unwrap_or_else(|_| "opencode".to_string());
    let args: Vec<String> = std::env::var("AUX_ACP_ARGS")
        .unwrap_or_else(|_| "acp".to_string())
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let workspace = match std::env::var_os("AUX_ACP_WORKSPACE") {
        Some(path) => PathBuf::from(path),
        None => tempfile::Builder::new()
            .prefix("aux-acp-smoke-")
            .tempdir()?
            .keep(),
    };
    std::fs::create_dir_all(&workspace)?;
    let vendor_data = std::env::var_os("AUX_ACP_VENDOR_DATA").map(PathBuf::from);

    let limits = AcpLimits {
        turn_timeout: Duration::from_secs(120),
        ..AcpLimits::default()
    };
    let mut agent = AcpAgentSpec::new("smoke", command, args);
    agent.vendor_data_dir = vendor_data;

    let backend_config = AcpBackendConfig {
        enabled: true,
        agent_name: "smoke".to_string(),
        agent,
        limits,
        sandbox: ShellSandbox::default(),
        workspace: workspace.clone(),
        sandbox_home: None,
        read_only: false,
    };
    let mut backend = AcpBackend::new(
        backend_config,
        Arc::new(StdinApprover),
        Box::new(PrintingHost),
    );
    eprintln!(
        "[smoke] workspace={} (private HOME/TMPDIR inside it)",
        workspace.display()
    );
    let result = backend
        .run_turn(
            AcpTurnRequest {
                prompt: {
                    let grant = kernel_core::privacy::admit_call(
                        kernel_core::privacy::PathId::C9,
                        kernel_core::privacy::PrivacyMode::Private,
                        kernel_core::privacy::Destination::LocalDisplay,
                    )
                    .expect("C9 is covered in private mode");
                    kernel_privacy::Gate::for_tests(
                        &grant,
                        [0u8; 32],
                        aux_providers::test_gate::names_checked(),
                    )
                    .text(&prompt)
                    .expect("the smoke prompt passes the privacy gate")
                    .0
                },
                cancel: None,
                turns_used: 0,
            },
            &mut PrintObserver,
        )
        .await?;
    eprintln!(
        "\n[smoke] stop_reason={:?} chunks={} tool_calls={} truncated={}",
        result.stop_reason, result.stats.chunks, result.stats.tool_calls, result.stats.truncated
    );
    Ok(())
}
