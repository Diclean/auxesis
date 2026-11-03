//! Owner-only read-only quarantine inspection.
use clap::{Args, Subcommand};
use std::path::Path;
use std::process::ExitCode;

#[derive(Debug, Args)]
pub struct MemoryArgs {
    #[command(subcommand)]
    pub action: MemoryAction,
}
#[derive(Debug, Subcommand)]
pub enum MemoryAction {
    Quarantine(QuarantineArgs),
}
#[derive(Debug, Args)]
pub struct QuarantineArgs {
    #[command(subcommand)]
    pub action: QuarantineAction,
}
#[derive(Debug, Subcommand)]
pub enum QuarantineAction {
    List {
        #[arg(long, value_name = "AGENT")]
        agent: String,
    },
}

pub fn run(args: MemoryArgs) -> ExitCode {
    let home = kernel_core::auxesis_home();
    let result = match args.action {
        MemoryAction::Quarantine(q) => match q.action {
            QuarantineAction::List { agent } => list(&home, &agent),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("aux memory: {err}");
            ExitCode::FAILURE
        }
    }
}

fn list(home: &Path, agent: &str) -> Result<(), String> {
    if agent.is_empty() || agent.len() > 256 {
        return Err("invalid agent identifier".into());
    }
    let path = kernel_core::store_path(home);
    let conn = aux_store::open_keyed_readonly(&path).map_err(|e| format!("opening store: {e}"))?;
    let mut stmt = conn.prepare("SELECT id,kind,created_at FROM memory_items WHERE agent=?1 AND state='quarantined' ORDER BY created_at DESC,id DESC LIMIT 100").map_err(|e| format!("reading quarantine: {e}"))?;
    let rows = stmt
        .query_map([agent], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| format!("reading quarantine: {e}"))?;
    println!("ID\tKIND\tCREATED (max 100; content omitted)");
    for row in rows {
        let (id, kind, created) = row.map_err(|e| format!("reading quarantine: {e}"))?;
        println!(
            "{id}\t{}\t{}",
            kernel_core::clean_field(&kind),
            kernel_core::clean_field(&created)
        );
    }
    Ok(())
}
