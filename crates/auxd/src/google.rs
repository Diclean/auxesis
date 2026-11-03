//! Wiring the native Google connector into the daemon.
//!
//! The five read tools (`gmail_search`, `gmail_read_message`,
//! `gmail_list_threads`, `calendar_list_events`, `calendar_get_event`) and the
//! one write tool (`google_gmail_create_draft`, a Gmail draft that is never
//! sent) are registered on the registry the daemon builds for every chat turn
//! — and only while this home holds a Google authorization. The write tool is
//! left consequential, so the broker's default `ask` applies and no draft is
//! created without an explicit owner approval. Nothing here ever opens a
//! browser: connecting is the owner's `aux connect google` command or an
//! explicit click in the app, both of which reach
//! [`aux_google::MacConnection::connect`] with an opener they had to name.

use aux_google::tools::GoogleTools;
use aux_google::MacConnection;
use aux_store::Store;
use kernel_broker::ToolRegistry;
use kernel_core::budget::Budgets;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Register the native Google read tools, the draft write tool and the two
/// skill-only writes when `home` holds a grant.
///
/// Returns how many tools were registered (`0` when this Mac is not connected,
/// or when the client settings needed to refresh are missing). The reads keep
/// their registry marking (read-only, untrusted output, private data); the
/// draft tool is deliberately consequential so it always asks. The skill-only
/// writes are in the registry so the broker's floor applies to them, and the
/// engine never offers them as plain tools.
pub fn register_connected_tools(
    home: &Path,
    store: Arc<Mutex<Store>>,
    budgets: Budgets,
    registry: &mut ToolRegistry,
) -> usize {
    let connection = MacConnection::at(home);
    if !connection.connected() {
        return 0;
    }
    let Ok(client) = connection.client() else {
        return 0;
    };
    let Ok(tools) = GoogleTools::new(Arc::new(client), store, budgets) else {
        return 0;
    };
    let registered = tools.tools().len() + tools.skill_tools().len();
    tools.register_into(registry);
    registered
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_broker::ToolClassExt;
    use std::path::PathBuf;

    const CLIENT_ID: &str = "desktop-client-id.apps.googleusercontent.com";
    const CLIENT_SECRET: &str = "client-secret-canary";

    const READ_TOOLS: [&str; 5] = [
        "gmail_search",
        "gmail_read_message",
        "gmail_list_threads",
        "calendar_list_events",
        "calendar_get_event",
    ];
    const DRAFT_TOOL: &str = "google_gmail_create_draft";

    fn home_with_credentials() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("auxesis-home");
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let env_file = home.join(".env");
        std::fs::write(
            &env_file,
            format!(
                "AUXESIS_GOOGLE_CLIENT_ID={CLIENT_ID}\nAUXESIS_GOOGLE_CLIENT_SECRET={CLIENT_SECRET}\n"
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (directory, home)
    }

    fn store(home: &Path) -> Arc<Mutex<Store>> {
        Arc::new(Mutex::new(
            Store::open(&kernel_core::store_path(home)).unwrap(),
        ))
    }

    #[test]
    fn the_read_and_draft_tools_are_registered_only_when_a_grant_exists() {
        let (_directory, home) = home_with_credentials();
        let mut registry = ToolRegistry::new();
        let registered =
            register_connected_tools(&home, store(&home), Budgets::default(), &mut registry);
        assert_eq!(registered, 0, "no grant means no Google tools");
        for name in READ_TOOLS {
            assert!(!registry.names().contains(&name));
        }
        assert!(!registry.names().contains(&DRAFT_TOOL));

        // The consent flow the CLI or the app would run stores the grant under
        // the client-id key; the daemon only has to notice it.
        let key = aux_google::mac_account_key(CLIENT_ID);
        std::fs::write(
            home.join(format!("google-auth-{key}.json")),
            b"{\"version\":1}",
        )
        .unwrap();

        let mut registry = ToolRegistry::new();
        let registered =
            register_connected_tools(&home, store(&home), Budgets::default(), &mut registry);
        assert_eq!(registered, READ_TOOLS.len() + 3);
        for name in ["google_gmail_send", "google_calendar_create_event"] {
            assert!(
                registry
                    .get(name)
                    .is_some_and(|tool| tool.class().skill_only),
                "{name} must be registered, skill-only, so the floor refuses it"
            );
        }
        for name in READ_TOOLS {
            assert!(
                registry.names().contains(&name),
                "{name} must be registered"
            );
            assert!(registry.is_read_only(name), "{name} must stay read-only");
            assert!(
                registry.is_untrusted_output(name),
                "{name} output must stay untrusted"
            );
        }
        assert!(
            registry.names().contains(&DRAFT_TOOL),
            "the draft write tool must be registered"
        );
        assert!(
            !registry.is_read_only(DRAFT_TOOL),
            "the draft write tool must never be read-only: it has to ask"
        );
        assert!(
            registry
                .get(DRAFT_TOOL)
                .is_some_and(|tool| tool.requires_explicit_rule()),
            "a wildcard allow must not authorize a Gmail draft"
        );
        assert!(
            !registry.is_untrusted_output(DRAFT_TOOL),
            "the draft confirmation carries only opaque ids, so it is trusted"
        );
    }

    #[test]
    fn a_grant_whose_client_settings_are_gone_registers_nothing() {
        let (_directory, home) = home_with_credentials();
        let key = aux_google::mac_account_key(CLIENT_ID);
        std::fs::write(
            home.join(format!("google-auth-{key}.json")),
            b"{\"version\":1}",
        )
        .unwrap();
        std::fs::remove_file(home.join(".env")).unwrap();

        let mut registry = ToolRegistry::new();
        assert_eq!(
            register_connected_tools(&home, store(&home), Budgets::default(), &mut registry),
            0
        );
    }

    #[test]
    fn another_client_ids_grant_is_not_this_daemons_connection() {
        let (_directory, home) = home_with_credentials();
        let key = aux_google::mac_account_key("someone-elses-client-id");
        std::fs::write(
            home.join(format!("google-auth-{key}.json")),
            b"{\"version\":1}",
        )
        .unwrap();

        let mut registry = ToolRegistry::new();
        assert_eq!(
            register_connected_tools(&home, store(&home), Budgets::default(), &mut registry),
            0
        );
    }
}
