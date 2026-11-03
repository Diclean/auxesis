//! `aux docs export` (M5-2): ask the daemon to write the receipts of a period
//! to `<out>/auxesis-receipts-<from>-<to>/` (`receipts.csv` + `originals/`). An
//! empty period prints one line and exits 0 without writing anything; an
//! existing empty export folder is reused, a non-empty one is refused.

use std::process::ExitCode;

use clap::Subcommand;

/// The export half of `aux docs`, flattened into `docs::DocsAction`.
#[derive(Debug, Subcommand)]
pub(crate) enum ExportAction {
    /// Export the receipts of a period (optionally of one client) to a CSV
    /// and a folder of the originals, for an accountant.
    ///
    /// An empty period prints one line and exits 0; it writes no CSV and no
    /// folder. The export goes in `<out>/auxesis-receipts-<from>-<to>`: an
    /// existing empty folder is reused, and one that already holds anything is
    /// refused without touching it, so pass a new --out folder.
    Export {
        /// First issue date, YYYY-MM-DD (inclusive).
        #[arg(long)]
        from: String,
        /// Last issue date, YYYY-MM-DD (inclusive).
        #[arg(long)]
        to: String,
        /// Only this client (CRM party id).
        #[arg(long)]
        client: Option<i64>,
        /// An existing folder (absolute path); the export goes in
        /// `auxesis-receipts-<from>-<to>` inside it.
        #[arg(long)]
        out: String,
    },
}

/// Percent-encode one query value.
fn encode(value: &str) -> String {
    let keep = |byte: u8| byte.is_ascii_alphanumeric() || b"-_.~/".contains(&byte);
    let encoded = value.bytes().map(|byte| match keep(byte) {
        true => (byte as char).to_string(),
        false => format!("%{byte:02X}"),
    });
    encoded.collect()
}

/// Run `aux docs export`: one `POST /v1/docs/export` over loopback, with the
/// endpoint and token rules of `aux brief`.
pub(crate) fn run(action: ExportAction) -> ExitCode {
    let ExportAction::Export {
        from,
        to,
        client,
        out,
    } = action;
    let mut path = format!(
        "/v1/docs/export?from={}&to={}&out={}",
        encode(&from),
        encode(&to),
        encode(&out)
    );
    if let Some(client) = client {
        path.push_str(&format!("&client={client}"));
    }
    let lang = kernel_core::Lang::from_env();
    let called = crate::brief::daemon_target(lang).and_then(|(url, token)| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| crate::brief::BriefDaemonError::Protocol(err.to_string()))?;
        runtime.block_on(crate::brief::call_daemon(
            reqwest::Method::POST,
            &url,
            &path,
            &token,
            lang,
        ))
    });
    match called.map(|body| serde_json::from_str::<serde_json::Value>(&body).unwrap_or_default()) {
        Ok(reply) if reply["status"] == "written" => {
            let folder = reply["folder"].as_str().unwrap_or_default();
            println!("Exported {} receipt(s) to {folder}", reply["rows"]);
            if reply["missing"].as_u64().is_some_and(|missing| missing > 0) {
                println!(
                    "{} original(s) were missing; their rows say (missing).",
                    reply["missing"]
                );
            }
            ExitCode::SUCCESS
        }
        Ok(reply) => {
            println!(
                "{}",
                reply["message"].as_str().unwrap_or("nothing to export")
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("aux docs: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn help_documents_the_empty_period_and_existing_folder_rules() {
        let mut cli = crate::Cli::command();
        let docs = cli.find_subcommand_mut("docs").expect("docs command");
        let export = docs.find_subcommand_mut("export").expect("export command");
        let help = export.render_long_help().to_string();
        assert!(help.contains("empty period"), "{help}");
        assert!(help.contains("existing empty folder is reused"), "{help}");
        assert!(help.contains("refused without touching it"), "{help}");
    }
}
