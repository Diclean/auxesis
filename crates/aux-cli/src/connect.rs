//! `aux connect google` — connect this Mac to Google, ask about it, or
//! disconnect it.
//!
//! The consent flow opens the browser **only** here, when the owner runs the
//! command. `--status` prints one honest line (never a secret, never an email)
//! and touches no network; `--disconnect` revokes the stored authorization and
//! deletes it.

use aux_google::browser::SystemBrowser;
use aux_google::{MacConnection, CONNECT_SCOPES};
use clap::{Args, Subcommand};
use kernel_core::Lang;
use std::io::Write;
use std::process::ExitCode;

#[derive(Debug, Args)]
pub struct ConnectArgs {
    #[command(subcommand)]
    service: ConnectService,
}

#[derive(Debug, Subcommand)]
enum ConnectService {
    /// Connect Auxesis to your Google mail and calendar.
    Google(GoogleArgs),
}

#[derive(Debug, Args, Default)]
pub struct GoogleArgs {
    /// Report whether Google is connected on this Mac; nothing else is printed.
    #[arg(long, conflicts_with = "disconnect")]
    pub status: bool,
    /// Revoke the Google authorization stored on this Mac and delete it.
    #[arg(long)]
    pub disconnect: bool,
}

pub fn run(args: ConnectArgs) -> ExitCode {
    match args.service {
        ConnectService::Google(args) => run_google(args),
    }
}

fn run_google(args: GoogleArgs) -> ExitCode {
    let lang = Lang::from_env();
    let connection = MacConnection::at(kernel_core::auxesis_home());
    if args.status {
        status(&connection, lang)
    } else if args.disconnect {
        disconnect(&connection, lang)
    } else {
        connect(&connection, lang)
    }
}

/// One line, the state only: no token, no address, no client id.
fn status(connection: &MacConnection, lang: Lang) -> ExitCode {
    if connection.connected() {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            choose(lang, "Google : connecté", "Google: connected")
        );
        ExitCode::SUCCESS
    } else {
        let _ = writeln!(
            std::io::stdout(),
            "{}",
            choose(lang, "Google : non connecté", "Google: not connected")
        );
        ExitCode::FAILURE
    }
}

fn connect(connection: &MacConnection, lang: Lang) -> ExitCode {
    let runtime = match runtime() {
        Ok(runtime) => runtime,
        Err(code) => return code,
    };
    match runtime.block_on(connection.connect_with_lang(&SystemBrowser, &CONNECT_SCOPES, lang)) {
        Ok(_) => {
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                choose(
                    lang,
                    "Google : connecté. Tu peux fermer l'onglet de ton navigateur.",
                    "Google: connected. You can close the browser tab."
                )
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(error, lang),
    }
}

fn disconnect(connection: &MacConnection, lang: Lang) -> ExitCode {
    let runtime = match runtime() {
        Ok(runtime) => runtime,
        Err(code) => return code,
    };
    match runtime.block_on(connection.disconnect()) {
        Ok(()) => {
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                choose(
                    lang,
                    "Google : déconnecté. L'autorisation a été retirée de ce Mac.",
                    "Google: disconnected. The authorization was removed from this Mac."
                )
            );
            ExitCode::SUCCESS
        }
        // The local authorization is what this Mac controls: once the grant is
        // gone, the owner is disconnected here whatever Google answered. Say so
        // on stderr rather than claim a revoke that did not happen.
        Err(error) if !connection.connected() => {
            let _ = writeln!(
                std::io::stderr(),
                "aux connect google: {}",
                error.localized_message(lang)
            );
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                choose(lang,
                    "Google : déconnecté de ce Mac. Préviens Google plus tard si tu veux retirer l'accès.",
                    "Google: disconnected from this Mac. Tell Google later if you want the access removed."
                )
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(error, lang),
    }
}

fn choose(lang: Lang, fr: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Fr => fr,
        Lang::En => en,
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            let _ = writeln!(std::io::stderr(), "aux connect: {error}");
            ExitCode::FAILURE
        })
}

fn fail(error: aux_google::AuthError, lang: Lang) -> ExitCode {
    let _ = writeln!(
        std::io::stderr(),
        "aux connect google: {}",
        error.localized_message(lang)
    );
    ExitCode::FAILURE
}
