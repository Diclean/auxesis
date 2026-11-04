//! `aux docs`: receipts collected from mail and their client, read from the
//! local `auxd` API; fields only, never a body or a file name.

use std::process::ExitCode;

use clap::{Args, Subcommand};
use serde_json::Value;

/// `aux docs`.
#[derive(Debug, Args)]
pub(crate) struct DocsArgs {
    #[command(subcommand)]
    action: DocsAction,
}

#[derive(Debug, Subcommand)]
enum DocsAction {
    /// List the documents, newest first, with their client and checks.
    List {
        /// Only the documents linked to this client id.
        #[arg(long, conflicts_with = "unlinked")]
        client: Option<i64>,
        /// Only the documents linked to no client.
        #[arg(long)]
        unlinked: bool,
        /// How many documents (default 50, max 500).
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Link a document to a client by hand.
    Link {
        /// The first 8 or more characters of the document hash.
        hash: String,
        /// The client id (`aux crm`).
        party: i64,
    },
    /// Remove the client link of a document.
    Unlink {
        /// The first 8 or more characters of the document hash.
        hash: String,
    },
    #[command(flatten)]
    Export(crate::docs_export::ExportAction),
}

/// Run `aux docs`.
pub(crate) fn run(args: DocsArgs) -> ExitCode {
    let result = match args.action {
        DocsAction::Export(action) => return crate::docs_export::run(action),
        DocsAction::List {
            client,
            unlinked,
            limit,
        } => {
            let client = client.map(|id| format!("&client={id}")).unwrap_or_default();
            let path = format!("/v1/docs?limit={limit}&unlinked={unlinked}{client}");
            call(reqwest::Method::GET, &path).map(|value| render_list(&value))
        }
        DocsAction::Link { hash, party } => link(&hash, &party.to_string()),
        DocsAction::Unlink { hash } => link(&hash, "none"),
    };
    match result {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("aux docs: {err}");
            ExitCode::FAILURE
        }
    }
}

/// `POST /v1/docs/<prefix>/party?party=<id|none>`; the daemon checks the
/// prefix and the client and refuses without writing.
fn link(hash: &str, party: &str) -> Result<String, String> {
    let hash = hash.to_ascii_lowercase();
    if hash.len() < 8 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("a document hash prefix is 8 to 64 hex characters".to_string());
    }
    let value = call(
        reqwest::Method::POST,
        &format!("/v1/docs/{hash}/party?party={party}"),
    )?;
    let full = value["hash"].as_str().unwrap_or(&hash);
    let short = full.get(..12).unwrap_or(full);
    Ok(match value["party_id"].as_i64() {
        Some(id) => format!("Linked {short} to client {id}."),
        None => format!("Unlinked {short}."),
    })
}

/// One loopback call with the daemon token, through the `aux brief` client.
fn call(method: reqwest::Method, path: &str) -> Result<Value, String> {
    let lang = kernel_core::Lang::En;
    let (url, token) = crate::brief::daemon_target(lang).map_err(|err| err.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;
    let body = runtime
        .block_on(crate::brief::call_daemon(method, &url, path, &token, lang))
        .map_err(|err| err.to_string())?;
    serde_json::from_str(&body).map_err(|_| "unreadable reply from auxd".to_string())
}

/// One line per document: hash, kind, date, number, amounts, client, status, checks.
fn render_list(value: &Value) -> String {
    let text = |v: &Value| v.as_str().unwrap_or("-").to_string();
    let mut lines = Vec::new();
    for row in value.as_array().into_iter().flatten() {
        let c = &row["client"];
        let archived = (c["archived"] == true).then_some(" (archived)");
        let archived = archived.unwrap_or_default();
        let client = match c["id"].as_i64() {
            Some(id) => format!("client {id} {}{archived}", text(&c["name"])),
            None => "no client".to_string(),
        };
        let checks: Vec<String> = (row["checks"].as_array().into_iter().flatten())
            .map(|check| format!("{}:{}", text(&check["name"]), text(&check["state"])))
            .collect();
        let [hash, kind, date, number, total, vat, status] = [
            "hash",
            "kind",
            "issued_on",
            "number",
            "total",
            "vat",
            "status",
        ]
        .map(|k| text(&row[k]));
        let checks = checks.join(" ");
        lines.push(format!(
            "{hash}  {kind}  {date}  {number}  {total} (VAT {vat})  {client}  [{status}]  {checks}"
        ));
    }
    if lines.is_empty() {
        return "No documents.".to_string();
    }
    lines.join("\n")
}
