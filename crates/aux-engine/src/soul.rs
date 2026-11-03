//! Agent souls: `~/.auxesis/agents/<agent>/soul.md`.
//!
//! The soul is the agent's system prompt material. It is a plain text file the
//! user can edit; when it is missing, [`load_or_create`] writes a small
//! default. When it exists but cannot be used (unreadable, a directory,
//! invalid UTF-8, empty, oversized, a FIFO/device), the default is used
//! **in memory only**: a corrupt file is never overwritten and never takes
//! the chat down.

use std::path::{Path, PathBuf};

/// Refuse to read soul files larger than this (same guard as the config
/// loader: protects against device files and runaway writes).
pub const MAX_SOUL_BYTES: u64 = 1024 * 1024;

/// Default soul written for an agent that does not have one yet.
///
/// `{agent}` is substituted with the agent's name.
pub const DEFAULT_SOUL: &str = "\
# {agent}

You are {agent}, an Auxesis agent: a personal always-on agent running on this Mac.
Be concise and honest about uncertainty. Use tools when they help, and say
what you are about to do before doing anything consequential: something that
leaves this Mac or that changes what the owner owns. Reading this Mac's own
data, and the local skills that need no approval, need no permission: run them
yourself and report what you found.
";

/// DOCS-ERASED-MARKER: "that PDF" and "the invoice" need one clear antecedent.
/// With several recent documents in play, the Documents agent asks which one
/// instead of reading one and describing the wrong document.
const DOCUMENTS_AMBIGUOUS_DOCUMENT_RULE: &str = "\nWhen the owner says \"that PDF\", \
     \"this invoice\" or \"the document\" and the recent thread does not make one recent \
     document the obvious one, ask ONE short question naming up to three candidate recent \
     documents by file name only. Never guess which document is meant, and never describe a \
     document you did not read.\n";

/// WHO-OWES: a client card holds no invoice data, so "who owes me" is read
/// from the local registry: every invoice, one line each, never the first
/// match. The registry is not the mailbox, so an empty registry never reads as
/// "nobody owes you".
const DOCUMENTS_WHO_OWES_RULE: &str = "\nWhen the owner asks who owes them, who has not \
     paid, or which invoice is unpaid or overdue, search the local registry for invoices \
     (call `docs_ingest` with action \"search\" and the query \"invoice\") and list EVERY \
     invoice it returns, one line each with its number, the client, the amount and the due \
     date. Say when a field is not recorded. A mail mention is evidence, never proof by \
     itself: name it as a mail mention, and when the registry holds none, say the mailbox may \
     still show overdue reminders. Never stop at the first match. The CRM holds no invoice \
     data.\n";

/// WHO-OWES-2 / WHO-OWES-DIRECTION: the demo world's late-payment mails are
/// received from the clients, so they say what the owner owes, not what the
/// clients owe. The mail agent read candidates one by one (the fake search
/// returned the whole folder) and its second client's thread was still unread;
/// this rule makes the search's matches the list and reports the direction the
/// tool computed instead of treating every reminder as a client debt.
const MAIL_WHO_OWES_RULE: &str = "\nWhen the owner asks who owes them, who has not paid, or \
     which invoice is unpaid or overdue, search the mailbox for \"overdue\" first (then \
     \"unpaid\" or \"invoice\" if that finds nothing), in every folder you may read, Sent \
     included, and list EVERY overdue mail, one line each with the sender, the client, the \
     invoice number in the subject and the direction the tool gives it: owed_to_you when the \
     owner sent it, you_owe when it is a reminder the owner received, unknown when the tool \
     cannot tell. Never put a you_owe mail in the list of clients who owe the owner; say \
     plainly when the direction is unknown. Never stop at the first match, never read the \
     whole folder in place of the matches, and never let the newest page be the list. A \
     client card and the CRM hold no invoice data.\n";

/// The default soul for `agent`.
pub fn default_soul(agent: &str) -> String {
    let mut soul = DEFAULT_SOUL.replace("{agent}", agent);
    if agent == "mail" {
        soul.push_str(
            "\nWhen the owner asks to reply, answer, send or write back (\"reply camille \
             ok\", \"answer her\", \"réponds à Lea\"), prepare the reply with `mail_send`: \
             it raises the approval card that is the owner's review. Use `mail_draft` \
             only when the owner explicitly says draft, brouillon, \"write a draft\" or \
             \"don't send\": it saves on this Mac and never sends. Do not read the \
             mailbox first when drafting, and a draft with no recipient is fine. \
             When the owner says \"send it\" about a draft you saved, run the \
             send-draft skill with that draft's id only: the runtime loads the \
             recipient, subject and body it stored, and you never restate them.\n",
        );
        soul.push_str(MAIL_WHO_OWES_RULE);
    }
    if agent == "documents" {
        soul.push_str(DOCUMENTS_AMBIGUOUS_DOCUMENT_RULE);
        soul.push_str(DOCUMENTS_WHO_OWES_RULE);
    }
    soul
}

/// Where the soul of `agent` came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoulStatus {
    /// An existing soul file was read.
    Loaded,
    /// No soul existed: the default was written to disk.
    Created,
    /// The soul file could not be used; the default is used in memory only.
    FellBack {
        /// Why the file could not be used.
        reason: String,
    },
}

/// An agent's soul, ready to be turned into a system prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soul {
    /// Soul text (never empty).
    pub content: String,
    /// Where [`content`](Self::content) came from.
    pub status: SoulStatus,
}

/// Directory holding every agent: `<home>/agents`.
pub fn agents_dir(home: &Path) -> PathBuf {
    home.join("agents")
}

/// Directory of one agent: `<home>/agents/<agent>`.
pub fn agent_dir(home: &Path, agent: &str) -> PathBuf {
    agents_dir(home).join(agent)
}

/// Path of an agent's soul: `<home>/agents/<agent>/soul.md`.
pub fn soul_path(home: &Path, agent: &str) -> PathBuf {
    agent_dir(home, agent).join("soul.md")
}

/// Path of an agent's tool workspace: `<home>/agents/<agent>/workspace`.
pub fn workspace_dir(home: &Path, agent: &str) -> PathBuf {
    agent_dir(home, agent).join("workspace")
}

/// Load the soul of `agent`, creating it with a default when missing.
///
/// Never fails: unreadable or corrupt souls fall back to the default in
/// memory and leave the offending file untouched.
pub fn load_or_create(home: &Path, agent: &str) -> Soul {
    let path = soul_path(home, agent);
    let fallback = |reason: String| Soul {
        content: default_soul(agent),
        status: SoulStatus::FellBack { reason },
    };

    let meta = match std::fs::metadata(&path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let content = default_soul(agent);
            return match write_default(home, agent, &content) {
                Ok(()) => Soul {
                    content,
                    status: SoulStatus::Created,
                },
                Err(err) => fallback(format!("could not create {}: {err}", path.display())),
            };
        }
        Err(err) => return fallback(format!("could not read {}: {err}", path.display())),
    };

    if !meta.is_file() {
        return fallback(format!("{} is not a regular file", path.display()));
    }
    if meta.len() > MAX_SOUL_BYTES {
        return fallback(format!(
            "{} is unexpectedly large ({} bytes)",
            path.display(),
            meta.len()
        ));
    }

    match std::fs::read_to_string(&path) {
        Ok(content) if content.trim().is_empty() => {
            fallback(format!("{} is empty", path.display()))
        }
        Ok(content) => Soul {
            content,
            status: SoulStatus::Loaded,
        },
        Err(err) => fallback(format!("could not read {}: {err}", path.display())),
    }
}

/// Write the default soul through the verified sandbox home handle (J-02
/// write gateway), never following a symlink and never clobbering an existing
/// file.
fn write_default(home: &Path, agent: &str, content: &str) -> std::io::Result<()> {
    let handle = kernel_core::SandboxHome::open(home)?;
    let rel = Path::new("agents").join(agent).join("soul.md");
    if handle.write_new(&rel, content.as_bytes(), 0o600)? {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "soul already exists",
        ))
    }
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn paths_live_under_the_auxesis_home() {
        let home = Path::new("/tmp/aux-home");
        assert_eq!(agents_dir(home), PathBuf::from("/tmp/aux-home/agents"));
        assert_eq!(
            agent_dir(home, "main"),
            PathBuf::from("/tmp/aux-home/agents/main")
        );
        assert_eq!(
            soul_path(home, "main"),
            PathBuf::from("/tmp/aux-home/agents/main/soul.md")
        );
        assert_eq!(
            workspace_dir(home, "main"),
            PathBuf::from("/tmp/aux-home/agents/main/workspace")
        );
    }

    #[test]
    fn missing_soul_is_created_with_the_default() {
        let dir = tempdir().unwrap();
        let soul = load_or_create(dir.path(), "main");

        assert_eq!(soul.status, SoulStatus::Created);
        assert_eq!(soul.content, default_soul("main"));
        let on_disk = std::fs::read_to_string(soul_path(dir.path(), "main")).unwrap();
        assert_eq!(on_disk, soul.content);
        assert!(on_disk.contains("# main"));
    }

    #[test]
    fn existing_soul_is_loaded_verbatim() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "axis");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# my own soul\nbe terse\n").unwrap();

        let soul = load_or_create(dir.path(), "axis");

        assert_eq!(soul.status, SoulStatus::Loaded);
        assert_eq!(soul.content, "# my own soul\nbe terse\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), soul.content);
    }

    #[test]
    fn empty_soul_falls_back_without_overwriting() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "  \n").unwrap();

        let soul = load_or_create(dir.path(), "main");

        assert!(matches!(soul.status, SoulStatus::FellBack { .. }));
        assert_eq!(soul.content, default_soul("main"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "  \n");
    }

    #[test]
    fn corrupt_soul_falls_back_without_overwriting() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let garbage = [0xff, 0xfe, 0x00, 0x42];
        std::fs::write(&path, garbage).unwrap();

        let soul = load_or_create(dir.path(), "main");

        assert!(matches!(soul.status, SoulStatus::FellBack { .. }));
        assert_eq!(soul.content, default_soul("main"));
        assert_eq!(std::fs::read(&path).unwrap(), garbage, "file must be kept");
    }

    #[test]
    fn soul_that_is_a_directory_falls_back() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "main");
        std::fs::create_dir_all(&path).unwrap();

        let soul = load_or_create(dir.path(), "main");

        assert!(matches!(soul.status, SoulStatus::FellBack { .. }));
        assert_eq!(soul.content, default_soul("main"));
        assert!(path.is_dir(), "the directory must be kept");
    }

    #[test]
    fn oversized_soul_falls_back() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![b'#'; (MAX_SOUL_BYTES + 1) as usize]).unwrap();

        let soul = load_or_create(dir.path(), "main");

        assert!(matches!(soul.status, SoulStatus::FellBack { .. }));
        assert_eq!(soul.content, default_soul("main"));
    }

    #[test]
    fn a_soul_exactly_at_the_ceiling_is_still_loaded() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let content = "x".repeat(MAX_SOUL_BYTES as usize);
        std::fs::write(&path, &content).unwrap();

        let soul = load_or_create(dir.path(), "main");

        assert_eq!(soul.status, SoulStatus::Loaded);
        assert_eq!(soul.content, content);
    }

    #[cfg(unix)]
    #[test]
    fn soul_symlinked_to_a_device_falls_back_without_reading() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &path).unwrap();

        let soul = load_or_create(dir.path(), "main");

        assert!(matches!(soul.status, SoulStatus::FellBack { .. }));
        assert_eq!(soul.content, default_soul("main"));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_soul_falls_back_without_hanging() {
        let dir = tempdir().unwrap();
        let path = soul_path(dir.path(), "main");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let soul = load_or_create(dir.path(), "main");

        assert!(matches!(soul.status, SoulStatus::FellBack { .. }));
        assert_eq!(soul.content, default_soul("main"));
    }

    #[cfg(unix)]
    #[test]
    fn created_soul_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();

        load_or_create(dir.path(), "main");

        let mode = std::fs::metadata(soul_path(dir.path(), "main"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "soul must be 0600");
    }

    #[test]
    fn default_soul_mentions_the_agent() {
        let soul = default_soul("axis");
        assert!(soul.contains("# axis"));
        assert!(soul.contains("You are axis"));
    }

    /// REPLY-VS-DRAFT: "reply", "answer", "send" and "write back" prepare the
    /// reply with the carded send; a local draft is only for an explicit draft.
    #[test]
    fn the_mail_soul_sends_a_reply_and_only_drafts_when_asked() {
        let soul = default_soul("mail");
        assert!(
            soul.contains("When the owner asks to reply, answer, send or write back"),
            "a reply must go through mail_send: {soul}"
        );
        assert!(
            soul.contains("prepare the reply with `mail_send`: it raises the approval card"),
            "the send card is the owner's review: {soul}"
        );
        assert!(
            soul.contains("Use `mail_draft` only when the owner explicitly says draft, brouillon"),
            "a local draft is only for an explicit draft: {soul}"
        );
        assert!(
            soul.contains("Do not read the mailbox first when drafting"),
            "drafting still skips the mailbox: {soul}"
        );
        assert!(
            soul.contains("send-draft skill with that draft's id only"),
            "send it must use the stored draft, not model fields: {soul}"
        );
    }

    /// DOCS-ERASED-MARKER: "what's in that pdf" with no clear antecedent asks
    /// which document, naming at most three recent file names. The approval
    /// paragraph in [`DEFAULT_SOUL`] stays byte-identical: this only appends.
    #[test]
    fn the_documents_soul_asks_which_document_when_the_pdf_is_ambiguous() {
        let soul = default_soul("documents");
        assert_eq!(
            soul,
            DEFAULT_SOUL.replace("{agent}", "documents")
                + DOCUMENTS_AMBIGUOUS_DOCUMENT_RULE
                + DOCUMENTS_WHO_OWES_RULE,
            "the unchanged default plus two rules: {soul}"
        );
        assert!(
            soul.contains(concat!(
                "ask ONE short question naming up to three candidate recent documents ",
                "by file name only"
            )),
            "{soul}"
        );
        assert!(!default_soul("main").contains(DOCUMENTS_AMBIGUOUS_DOCUMENT_RULE));
    }

    /// WHO-OWES: "which clients owe me" read the client card, which holds no
    /// invoice data, and named the one client whose timeline mentioned an
    /// invoice. The Documents soul sends the question to the registry and
    /// demands every invoice, not the first match, and never calls an empty
    /// registry proof that nobody owes.
    #[test]
    fn the_documents_soul_lists_every_invoice_for_a_who_owes_question() {
        let soul = default_soul("documents");
        for line in [
            "asks who owes them, who has not paid",
            "list EVERY invoice it returns",
            "one line each with its number, the client, the amount and the due date",
            "A mail mention is evidence, never proof by itself",
            "the mailbox may still show overdue reminders",
            "Never stop at the first match",
            "The CRM holds no invoice data",
        ] {
            assert!(soul.contains(line), "missing {line:?}: {soul}");
        }
        for other in ["mail", "clients", "main"] {
            assert!(
                !default_soul(other).contains(DOCUMENTS_WHO_OWES_RULE),
                "{other} must not carry the Documents rule"
            );
        }
    }

    /// WHO-OWES-2: the two unpaid invoices of the demo world exist only as
    /// mail from the clients. The Mail soul searches for overdue mail and
    /// lists every match, because the search tool's page is not the folder.
    #[test]
    fn the_mail_soul_lists_every_overdue_mail_for_a_who_owes_question() {
        let soul = default_soul("mail");
        for line in [
            "asks who owes them, who has not paid",
            "search the mailbox for \"overdue\" first",
            "in every folder you may read, Sent included",
            "list EVERY overdue mail",
            "the invoice number in the subject",
            "the direction the tool gives it",
            "owed_to_you when the owner sent it",
            "you_owe when it is a reminder the owner received",
            "Never put a you_owe mail in the list of clients who owe the owner",
            "Never stop at the first match",
            "never let the newest page be the list",
            "A client card and the CRM hold no invoice data",
        ] {
            assert!(soul.contains(line), "missing {line:?}: {soul}");
        }
        assert!(
            !soul.contains("strong unpaid signal"),
            "a received reminder is not proof that a client owes the owner: {soul}"
        );
        for other in ["documents", "clients", "main"] {
            assert!(
                !default_soul(other).contains(MAIL_WHO_OWES_RULE),
                "{other} must not carry the Mail rule"
            );
        }
    }
}
