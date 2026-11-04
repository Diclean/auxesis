//! Who owes whom for one mail, decided in code.
//!
//! The same words read opposite ways: a reminder the owner sent is money a
//! client owes the owner, the same reminder received from a supplier is money
//! the owner owes. The envelope renderer labels every row from the folder,
//! the sender and, when the registry has it, the invoice's issuer.

/// The direction of the money one mail is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailDirection {
    /// The owner issued the invoice or sent the reminder: a client owes them.
    OwedToYou,
    /// Someone else issued the invoice: the owner owes them.
    YouOwe,
    /// No fact decides it; say so instead of guessing.
    Unknown,
}

impl MailDirection {
    /// The one word rendered into the tool result.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwedToYou => "owed_to_you",
            Self::YouOwe => "you_owe",
            Self::Unknown => "unknown",
        }
    }
}

/// The local facts that decide the direction of one rendered page.
#[derive(Debug, Clone, Copy)]
pub struct EnvelopeDirection<'a> {
    /// Every address of the owner's configured mailboxes.
    pub owner_addresses: &'a [String],
    /// The account's Sent folder, when its config names one.
    pub sent_folder: Option<&'a str>,
    /// The folder this page was read from (`None` means the inbox).
    pub folder: Option<&'a str>,
}

impl EnvelopeDirection<'_> {
    /// The direction of one row. `registry_issuer_is_owner` is the invoice
    /// registry's verdict for the invoice number in the subject, when it has
    /// one: `Some(true)` the owner issued it, `Some(false)` someone else did.
    pub fn for_row(&self, from: &str, registry_issuer_is_owner: Option<bool>) -> MailDirection {
        mail_direction(
            from,
            self.folder,
            self.owner_addresses,
            self.sent_folder,
            registry_issuer_is_owner,
        )
    }
}

/// Decide one mail's direction from facts, never from its words alone.
///
/// `registry_issuer_is_owner` wins when it is known: the registry names who
/// issued the invoice, whatever folder the mail sits in. Otherwise a mail in
/// Sent, or from one of the owner's addresses, is a reminder the owner sent
/// (`owed_to_you`); a mail from anyone else is a reminder they sent
/// (`you_owe`); an envelope with no usable sender is `unknown`.
pub fn mail_direction(
    from: &str,
    folder: Option<&str>,
    owner_addresses: &[String],
    sent_folder: Option<&str>,
    registry_issuer_is_owner: Option<bool>,
) -> MailDirection {
    match registry_issuer_is_owner {
        Some(true) => return MailDirection::OwedToYou,
        Some(false) => return MailDirection::YouOwe,
        None => {}
    }
    if in_sent(folder, sent_folder) || from_is_owner(from, owner_addresses) {
        return MailDirection::OwedToYou;
    }
    if address_of(from).is_some() {
        return MailDirection::YouOwe;
    }
    MailDirection::Unknown
}

/// True when `folder` is the account's Sent folder (`Sent` by default).
fn in_sent(folder: Option<&str>, sent_folder: Option<&str>) -> bool {
    let Some(folder) = folder else {
        return false;
    };
    folder.eq_ignore_ascii_case(sent_folder.unwrap_or("Sent"))
        || folder.eq_ignore_ascii_case("Sent")
}

/// The bare address of `Name <address>`, or of a bare address.
fn address_of(from: &str) -> Option<&str> {
    let from = from.trim();
    if let Some(start) = from.rfind('<') {
        if let Some(end) = from[start + 1..].find('>') {
            let address = from[start + 1..start + 1 + end].trim();
            return (!address.is_empty()).then_some(address);
        }
    }
    (!from.is_empty() && from.contains('@')).then_some(from)
}

/// True when the sender is one of the owner's own addresses.
fn from_is_owner(from: &str, owner_addresses: &[String]) -> bool {
    let Some(sender) = address_of(from) else {
        return false;
    };
    owner_addresses
        .iter()
        .any(|owner| owner.trim().eq_ignore_ascii_case(sender))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(from: &str, folder: Option<&str>, registry: Option<bool>) -> MailDirection {
        mail_direction(
            from,
            folder,
            &["owner@example.org".to_string()],
            Some("Sent"),
            registry,
        )
    }

    #[test]
    fn a_reminder_the_owner_sent_is_money_a_client_owes_them() {
        for (from, folder) in [
            ("Owner <owner@example.org>", Some("Sent")),
            ("Owner <owner@example.org>", Some("SENT")),
            ("owner@EXAMPLE.org", Some("INBOX")),
            ("Owner <owner@example.org>", None),
        ] {
            assert_eq!(
                dir(from, folder, None),
                MailDirection::OwedToYou,
                "{from} {folder:?}"
            );
        }
    }

    #[test]
    fn a_reminder_received_from_someone_else_is_money_the_owner_owes() {
        assert_eq!(
            dir("Supplier <billing@supplier.example>", Some("INBOX"), None),
            MailDirection::YouOwe
        );
    }

    #[test]
    fn the_registry_issuer_outranks_the_folder_and_the_sender() {
        assert_eq!(
            dir(
                "Supplier <billing@supplier.example>",
                Some("INBOX"),
                Some(true)
            ),
            MailDirection::OwedToYou
        );
        assert_eq!(
            dir("Owner <owner@example.org>", Some("Sent"), Some(false)),
            MailDirection::YouOwe
        );
    }

    #[test]
    fn an_envelope_with_no_sender_is_unknown() {
        assert_eq!(dir("", Some("INBOX"), None), MailDirection::Unknown);
        assert_eq!(dir("Nobody", Some("INBOX"), None), MailDirection::Unknown);
    }
}
