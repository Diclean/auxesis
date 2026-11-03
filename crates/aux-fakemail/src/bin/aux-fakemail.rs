//! `aux-fakemail` — the local simulated mailbox (fictional data only).
//!
//! `aux-fakemail serve --dir <dir>` writes a self-signed certificate, loads a
//! fictional mailbox and serves IMAP + SMTP on loopback until SIGINT/SIGTERM.
//! It prints one line naming the two ports and the CA file.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use aux_fakemail::{serve, write_demo, write_world, SimConfig};

#[derive(Debug, Parser)]
#[command(
    name = "aux-fakemail",
    version,
    about = "Local simulated IMAP/SMTP mailbox for offline Auxesis development"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve the simulated mailbox until SIGINT/SIGTERM.
    Serve(ServeArgs),
    /// Write the daily-use demo mailbox to <dir>/mailbox.json (kept if present).
    Demo(DemoArgs),
}

#[derive(Debug, Args)]
struct DemoArgs {
    /// Directory that holds mailbox.json.
    #[arg(long)]
    dir: PathBuf,
    /// Append a fresh batch of today's mail instead.
    #[arg(long)]
    seed: bool,
    /// Write the rich fictional freelancer world instead of the small demo set.
    #[arg(long)]
    world: bool,
    /// Overwrite an existing mailbox.json (only meaningful with --world).
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Directory for cert.pem, key.pem, mailbox.json and outbox/.
    #[arg(long)]
    dir: PathBuf,
    /// IMAP port; 0 binds an ephemeral port.
    #[arg(long, default_value_t = 0)]
    imap_port: u16,
    /// SMTP port; 0 binds an ephemeral port.
    #[arg(long, default_value_t = 0)]
    smtp_port: u16,
    /// Add one new unread fictional mail to INBOX each UTC day while running.
    #[arg(long)]
    daily_mail: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    // J-02: the one shared sandbox guard, before anything is read or created.
    if let Err(error) = kernel_core::ensure_sandbox_guard(None) {
        eprintln!("aux-fakemail: {error}");
        return ExitCode::FAILURE;
    }
    let Cli { command } = Cli::parse();
    match command {
        Command::Serve(args) => run(args).await,
        Command::Demo(args) => {
            if args.seed && args.world {
                eprintln!("aux-fakemail: --seed and --world are mutually exclusive");
                return ExitCode::FAILURE;
            }
            let result = if args.world {
                write_world(&args.dir, args.force)
            } else {
                write_demo(&args.dir, args.seed)
            };
            match result {
                Ok(count) => {
                    println!("fakemail mailbox: {count} message(s)");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("aux-fakemail: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn run(args: ServeArgs) -> ExitCode {
    let daily_mail = args.daily_mail;
    let pid_file = args.dir.join("pid");
    let server = match serve(SimConfig {
        dir: args.dir,
        imap_port: args.imap_port,
        smtp_port: args.smtp_port,
    })
    .await
    {
        Ok(server) => server,
        Err(error) => {
            eprintln!("aux-fakemail: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "fakemail imap=127.0.0.1:{} smtp=127.0.0.1:{} ca={}",
        server.imap_port,
        server.smtp_port,
        server.ca_file.display()
    );
    // brief-setup.sh matches this pid to the port's listener to know the port is ours.
    let _ = std::fs::write(&pid_file, format!("{}\n", std::process::id()));
    if daily_mail {
        server.drip_daily_mail();
    }
    wait_for_signal().await;
    let _ = std::fs::remove_file(&pid_file);
    ExitCode::SUCCESS
}

/// Resolve on SIGINT or SIGTERM.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
