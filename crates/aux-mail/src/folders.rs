//! Folder discovery: `LIST`, the EN/FR/DE localisation map, and `INBOX.*`
//! flattening.
//!
//! The map is deliberately small and explicit. It never *opens* a folder; it
//! only proposes the user-facing role (`inbox`, `sent`, …) for a server name so
//! the setup UI can pre-tick the obvious ones. Anything unresolved stays
//! `canonical: None` and is shown as-is — never guessed, because an agent must
//! not wander into a personal folder because it looked like an inbox.

use async_imap::types::{Name, NameAttribute};
use async_imap::Session;
use futures_util::TryStreamExt;

use crate::dial::BoxedStream;
use crate::error::MailError;

/// One folder the server offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// The server-side name, byte-for-byte as `LIST` returned it.
    pub name: String,
    /// The user-facing role when the name is recognised.
    pub canonical: Option<&'static str>,
    /// RFC 6154 role, when the server marks this mailbox as special-use.
    pub special_use: Option<&'static str>,
    /// False for a `\Noselect` parent node, which cannot be `SELECT`ed.
    pub selectable: bool,
}

/// The `(role, aliases)` table: EN + FR + DE, lower-cased.
const ROLES: &[(&str, &[&str])] = &[
    (
        "inbox",
        &[
            "inbox",
            "boîte de réception",
            "boite de reception",
            "posteingang",
        ],
    ),
    (
        "sent",
        &[
            "sent",
            "sent items",
            "sent mail",
            "sent messages",
            "éléments envoyés",
            "elements envoyes",
            "gesendete elemente",
            "gesendet",
        ],
    ),
    ("drafts", &["drafts", "brouillons", "entwürfe", "entwurfe"]),
    (
        "trash",
        &[
            "trash",
            "deleted",
            "deleted items",
            "corbeille",
            "éléments supprimés",
            "papierkorb",
            "gelöschte elemente",
            "geloschte elemente",
        ],
    ),
    ("archive", &["archive", "archives", "archiv"]),
    ("junk", &["junk", "spam", "indésirables", "indesirables"]),
];

/// The role a server folder name maps to, if any.
///
/// Matching is case-insensitive, ignores surrounding quotes, and tries again
/// after an `INBOX.` / `INBOX/` prefix is removed (the `INBOX.*` flattening).
pub fn canonical_name(server_name: &str) -> Option<&'static str> {
    let trimmed = server_name.trim().trim_matches('"');
    let flattened = strip_inbox_prefix(trimmed);
    let lower = flattened.to_ascii_lowercase();
    ROLES
        .iter()
        .find_map(|(role, aliases)| aliases.contains(&lower.as_str()).then_some(*role))
}

/// `INBOX.Sent` / `INBOX/Sent` flatten to `Sent` before the map runs.
fn strip_inbox_prefix(name: &str) -> &str {
    let lower = name.to_ascii_lowercase();
    for separator in ['.', '/'] {
        let prefix = format!("inbox{separator}");
        if lower.starts_with(&prefix) {
            return &name[prefix.len()..];
        }
    }
    name
}

/// Every folder `LIST "" *` returns, mapped.
pub async fn list(session: &mut Session<BoxedStream>) -> Result<Vec<Folder>, MailError> {
    let stream = session
        .list(Some(""), Some("*"))
        .await
        .map_err(|_| MailError::Protocol)?;
    let names: Vec<Name> = stream
        .try_collect()
        .await
        .map_err(|_| MailError::Protocol)?;
    Ok(names.iter().map(folder).collect())
}

fn folder(name: &Name) -> Folder {
    let special_use = name
        .attributes()
        .iter()
        .find_map(|attribute| match attribute {
            NameAttribute::Sent => Some("sent"),
            NameAttribute::Drafts => Some("drafts"),
            NameAttribute::Trash => Some("trash"),
            NameAttribute::Junk => Some("junk"),
            NameAttribute::Archive => Some("archive"),
            _ => None,
        });
    Folder {
        name: name.name().to_string(),
        canonical: special_use.or_else(|| canonical_name(name.name())),
        special_use,
        selectable: !name
            .attributes()
            .iter()
            .any(|attribute| matches!(attribute, NameAttribute::NoSelect)),
    }
}

#[cfg(test)]
mod tests {
    use super::canonical_name;

    #[test]
    fn common_sent_folder_names_are_recognized() {
        assert_eq!(canonical_name("Sent Messages"), Some("sent"));
        assert_eq!(canonical_name("INBOX.Sent Messages"), Some("sent"));
    }
}
