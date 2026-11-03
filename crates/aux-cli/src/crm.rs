//! `aux crm`: the owner's clients (the CRM contract moved out of this
//! repository, see `docs/README.md`). A mail sender becomes a party only
//! when the owner confirms it here; nothing is promoted on its own.

use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use aux_crm::{Crm, CrmError, Seeded};
use aux_store::Store;
use clap::{Args, Subcommand};

/// `aux crm`.
#[derive(Debug, Args)]
pub(crate) struct CrmArgs {
    #[command(subcommand)]
    action: CrmAction,
}

#[derive(Debug, Subcommand)]
enum CrmAction {
    /// Promote a mail sender you confirm to a party, in one step. The party's origin is
    /// `mail:<account>`, and its name is tokenised in the next private call. Promoting a
    /// sender whose address a party already holds changes nothing.
    AddFromMail {
        /// The mail account id the sender wrote to, from `[connectors.mail.accounts]`.
        account: String,
        /// The sender's e-mail address.
        #[arg(long)]
        email: String,
        /// The sender's name, as the mail shows it. Without it the address is the name.
        #[arg(long, default_value = "")]
        name: String,
        /// Tag the new party `prospect` (a possible new client from the brief).
        #[arg(long)]
        prospect: bool,
    },
    /// Never suggest this sender as a possible new client again.
    IgnoreProspect {
        /// The sender's e-mail address.
        #[arg(long)]
        email: String,
    },
    /// Refresh the local client timeline (B3): attach mail threads and EventKit
    /// events to their parties by exact address match.
    Timeline(TimelineArgs),
}

/// `aux crm timeline`.
#[derive(Debug, Args)]
pub(crate) struct TimelineArgs {
    #[command(subcommand)]
    action: TimelineAction,
}

#[derive(Debug, Subcommand)]
enum TimelineAction {
    /// Attach new mail threads and calendar events to their parties.
    Refresh,
}

/// Run `aux crm`. Output names no one: a party is reported by its id.
pub(crate) fn run(args: CrmArgs) -> ExitCode {
    let home = kernel_core::auxesis_home();
    let result = match args.action {
        CrmAction::AddFromMail {
            account,
            email,
            name,
            prospect,
        } => crate::contacts::open_writable(&home)
            .and_then(|store| add_from_mail(&store, &account, &name, &email, prospect)),
        CrmAction::IgnoreProspect { email } => {
            crate::contacts::open_writable(&home).and_then(|store| {
                Crm::new(&store)
                    .ignore_prospect(&email)
                    .map(|()| "This sender will not be suggested again.".to_string())
                    .map_err(|err| err.to_string())
            })
        }
        CrmAction::Timeline(timeline) => match timeline.action {
            TimelineAction::Refresh => refresh_in(&home),
        },
    };
    match result {
        Ok(text) => {
            println!("{}", text.trim_end());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("aux crm: {}", crate::contacts::printable(&err));
            ExitCode::FAILURE
        }
    }
}

/// Refresh the timeline of `home` and return its one-line summary. The mail
/// collection and the EventKit read live in `auxd::crm`, so the CLI and the
/// daemon's periodic job can never drift.
fn refresh_in(home: &Path) -> Result<String, String> {
    // Private mode (F2): `run_job` alone decides, so the two never disagree.
    let verified = kernel_core::ensure_home(home).map_err(|err| err.to_string())?;
    let store = aux_store::Store::open_verified(&verified).map_err(|err| err.to_string())?;
    let store = Arc::new(Mutex::new(store));
    auxd::crm::run_job(home, &store)
}

/// Promote the sender to a party, or report the party that already holds the address.
/// Errors name no one: a refused address is not echoed back.
fn add_from_mail(
    store: &Store,
    account: &str,
    name: &str,
    email: &str,
    prospect: bool,
) -> Result<String, String> {
    let crm = Crm::new(store);
    let seeded = if prospect {
        crm.add_prospect(account, name, email)
    } else {
        crm.promote_sender(account, name, email)
    }
    .map_err(|err| match err {
        CrmError::InvalidEmail { .. } => "the sender's address is not an e-mail address".into(),
        CrmError::EmptyOrigin => "the mail account id is empty".into(),
        other => other.to_string(),
    })?;
    let id = seeded.party().id;
    Ok(match seeded {
        Seeded::Created(_) => format!(
            "Promoted the sender to party {id} (origin mail:{}).",
            account.trim()
        ),
        Seeded::Updated(_) | Seeded::Unchanged(_) => {
            format!("Party {id} already holds this address: nothing changed.")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store under a fresh temp dir.
    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("store.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn add_from_mail_promotes_once_and_names_no_one() {
        let (_dir, store) = store();
        let address = "jean.fictif@example.invalid";

        let first = add_from_mail(&store, "fictif", "Jean Fictif", address, false).unwrap();
        let id = store.parties().unwrap()[0].id;
        assert_eq!(
            first,
            format!("Promoted the sender to party {id} (origin mail:fictif).")
        );
        assert!(
            !first.contains("Jean") && !first.contains("jean."),
            "{first}"
        );

        let second = add_from_mail(&store, "fictif", "Jean Fictif", address, false).unwrap();
        assert!(second.contains("nothing changed"), "{second}");
        assert_eq!(store.parties().unwrap().len(), 1);
    }

    #[test]
    fn a_refused_address_is_not_echoed_and_stores_nothing() {
        let (_dir, store) = store();
        let err = add_from_mail(
            &store,
            "fictif",
            "Jean Fictif",
            "not-an-address-Jean",
            false,
        )
        .unwrap_err();
        assert_eq!(err, "the sender's address is not an e-mail address");
        assert!(store.parties().unwrap().is_empty());
    }
}
