//! The `aux-imessage` helper (G2).
//!
//! A small local binary around the [`aux_imessage`] library. It is the process
//! that would hold Full Disk Access to read `chat.db` once the authenticated
//! local socket lands; today `auxd` uses the same library in-process, so this
//! binary is the operator's read-only inspection tool. Outbound sends are
//! owned by auxd, where they pass through the privacy kernel.

use aux_imessage::config::{load_file, ImessageConfig};
use aux_imessage::cursor::CursorStore;
use aux_imessage::reader::{ChatDbReader, ChatSpec};
use clap::{Parser, Subcommand};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "aux-imessage",
    version,
    about = "Local iMessage helper for Auxesis"
)]
struct Args {
    /// Path to `gateways.toml`; defaults to `$AUXESIS_HOME/gateways.toml`.
    #[arg(long)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print inbound messages newer than the persisted cursor as JSON lines.
    Read {
        /// How many rows to read.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

fn main() -> ExitCode {
    // J-02: the one shared sandbox guard, before anything is read or created.
    // It refuses the real `~/.auxesis` while the sandbox is active and returns
    // the verified home every path below is built from.
    let home_path = match kernel_core::ensure_sandbox_guard(None) {
        Ok(home) => home,
        Err(err) => {
            eprintln!("aux-imessage: {err}");
            return ExitCode::FAILURE;
        }
    };
    let home = match kernel_core::ensure_home(&home_path) {
        Ok(home) => home,
        Err(err) => {
            eprintln!("aux-imessage: {err}");
            return ExitCode::FAILURE;
        }
    };
    let args = Args::parse();
    let path = args
        .config
        .clone()
        .unwrap_or_else(|| home.path().join(aux_imessage::config::GATEWAYS_FILE));
    let config = load_file(&path).imessage;
    if !config.enabled {
        eprintln!("aux-imessage: [imessage] is disabled in {}", path.display());
        return ExitCode::FAILURE;
    }
    if let Err(err) = config.validate() {
        eprintln!("aux-imessage: [imessage] is invalid: {err}");
        return ExitCode::FAILURE;
    }
    match args.command {
        Command::Read { limit } => read(&config, &home, limit),
    }
}

fn read(config: &ImessageConfig, home: &kernel_core::SandboxHome, limit: usize) -> ExitCode {
    let mut out = std::io::stdout();
    match run_read(config, home, limit, &mut out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("aux-imessage: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Print inbound messages newer than the persisted cursor as JSON lines.
///
/// It never writes the shared cursor: only `auxd` (or the future socket
/// server) owns it, so an inspection never consumes a row. A missing cursor
/// starts at the current max ROWID, and a read error propagates instead of
/// silently reading from zero.
fn run_read(
    config: &ImessageConfig,
    home: &kernel_core::SandboxHome,
    limit: usize,
    out: &mut impl Write,
) -> Result<(), String> {
    let spec = ChatSpec::new(config.owner_handles.clone(), config.chat_guid.clone())
        .map_err(|err| err.to_string())?;
    let reader =
        ChatDbReader::open_read_only(&config.chat_db_path()).map_err(|err| err.to_string())?;
    let store = CursorStore::new(home.clone(), config.cursor_file());
    let cursor = match store.load() {
        Ok(Some(cursor)) => cursor,
        Ok(None) => reader.max_rowid().map_err(|err| err.to_string())?,
        Err(err) => return Err(err.to_string()),
    };
    let batch = reader
        .read_since(&spec, cursor, limit)
        .map_err(|err| err.to_string())?;
    for message in &batch.messages {
        let row = serde_json::json!({
            "rowid": message.rowid,
            "sender": message.sender,
            "date": message.date,
            "text": message.text,
        });
        writeln!(out, "{row}").map_err(|err| err.to_string())?;
    }
    // The shared cursor stays untouched: `read` is an inspection only.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    #[test]
    fn standalone_send_command_is_not_exposed() {
        assert!(Args::try_parse_from(["aux-imessage", "send", "--to", "+33600000001"]).is_err());
    }

    fn fake_chat_db(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("chat.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT NOT NULL); \
             CREATE TABLE chat (ROWID INTEGER PRIMARY KEY, guid TEXT NOT NULL); \
             CREATE TABLE message ( \
                 ROWID INTEGER PRIMARY KEY, text TEXT, attributedBody BLOB, handle_id INTEGER, \
                 is_from_me INTEGER DEFAULT 0, is_read INTEGER, date INTEGER, date_read INTEGER); \
             CREATE TABLE chat_message_join (chat_id INTEGER, message_id INTEGER); \
             CREATE TABLE chat_handle_join (chat_id INTEGER, handle_id INTEGER);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO handle (ROWID, id) VALUES (1, ?1)",
            params!["+33600000001"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat (ROWID, guid) VALUES (7, ?1)",
            params!["iMessage;-;+33600000001"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (ROWID, text, handle_id, is_from_me, is_read, date) \
             VALUES (1, 'hello from the owner', 1, 0, 0, 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chat_message_join (chat_id, message_id) VALUES (7, 1)",
            [],
        )
        .unwrap();
        path
    }

    fn config(db: std::path::PathBuf) -> ImessageConfig {
        ImessageConfig {
            enabled: true,
            owner_handles: vec!["+33600000001".to_string()],
            chat_guid: "iMessage;-;+33600000001".to_string(),
            agent_handle: "agent@example.test".to_string(),
            chat_db: Some(db),
            ..ImessageConfig::default()
        }
    }

    #[test]
    fn read_prints_rows_and_never_writes_the_shared_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(fake_chat_db(dir.path()));
        let home = kernel_core::SandboxHome::open(dir.path()).unwrap();
        let store = CursorStore::new(home.clone(), config.cursor_file());
        store.save(0).unwrap();
        let mut out = Vec::new();
        run_read(&config, &home, 20, &mut out).unwrap();
        let printed = String::from_utf8(out).unwrap();
        assert!(printed.contains("hello from the owner"));
        assert_eq!(
            store.load().unwrap(),
            Some(0),
            "read must not advance the shared cursor"
        );
    }

    #[test]
    fn read_propagates_a_cursor_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(fake_chat_db(dir.path()));
        let home = kernel_core::SandboxHome::open(dir.path()).unwrap();
        let store = CursorStore::new(home.clone(), config.cursor_file());
        std::fs::write(store.path(), b"{not json").unwrap();
        let mut out = Vec::new();
        assert!(
            run_read(&config, &home, 20, &mut out).is_err(),
            "a corrupt cursor must propagate, not reset to zero"
        );
    }
}
