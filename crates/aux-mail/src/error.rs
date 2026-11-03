//! The mail connector's error vocabulary.
//!
//! One typed variant per row of the error table. Every variant maps to
//! a three-part [`UserMessage`] (title, cause, action) in **English and
//! French**. The wording is deliberately jargon-free: the user never sees
//! `NOAUTH`, `A0011` or `535`. Whenever a server is named, its port is named
//! with it, so "which door stayed closed" is always actionable.

use std::fmt;
use std::time::Duration;

/// The languages [`MailError::user_message`] speaks.
///
/// This mirrors `kernel_core::Lang`; the kernel crate is not a dependency of
/// `aux-mail` yet, so the error vocabulary owns its own two-value enum. A later
/// slice can add a `From<kernel_core::Lang>` conversion without touching the
/// call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// English.
    #[default]
    En,
    /// French.
    Fr,
}

/// A user-facing, three-part explanation of a [`MailError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMessage {
    /// One line: what went wrong, in plain words.
    pub title: String,
    /// Why it happened.
    pub cause: String,
    /// What the user can do next.
    pub action: String,
}

/// Everything that can go wrong talking to a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailError {
    /// The host name did not resolve.
    Dns { host: String, port: u16 },
    /// The TCP connection was refused or timed out.
    Connect { host: String, port: u16 },
    /// The TLS handshake failed for a non-certificate reason.
    ///
    /// Carries **no** library text: the rustls error can quote the offending
    /// bytes, so the reason is dropped at the boundary.
    Tls { host: String, port: u16 },
    /// STARTTLS was required but the server did not advertise it.
    NoStartTls { host: String, port: u16 },
    /// A password would have been sent over an unencrypted connection.
    ///
    /// Raised **before** any socket is opened: a login always carries the
    /// password, so an account configured `plain` is refused rather than
    /// leaking it in the clear.
    InsecurePassword { host: String, port: u16 },
    /// The server's certificate was rejected by the production verifier.
    CertRejected { host: String, port: u16 },
    /// `LOGIN` (or `AUTHENTICATE`) was refused.
    ///
    /// Deliberately carries **no** server text: a hostile IMAP server can echo
    /// the `LOGIN` command — the password included — in its `NO`/`BAD` reason,
    /// so the reason is dropped at the boundary instead of being stored.
    Auth,
    /// The server offered no authentication mechanism we can use.
    NoAuthMechanism,
    /// The message was handed to the server (DATA was accepted) and the
    /// connection or its final reply then failed. The server may have accepted
    /// the mail: the caller must not release a send claim as if nothing left.
    Uncertain,
    /// The server refused a folder, usually because it is not on this account.
    FolderUnavailable { name: String, seen: Vec<String> },
    /// SMTP authentication was refused.
    SmtpAuth,
    /// The SMTP server refused to relay for the sender address.
    RelayDenied { from: String },
    /// The SMTP server refused one recipient address.
    RecipientDenied { to: String },
    /// The provider throttled us (`421`, `4xx`).
    RateLimited,
    /// A message exceeded a hard byte bound.
    TooLarge { limit: usize, seen: usize },
    /// A field of the outgoing message is malformed.
    ///
    /// Names the field only: the value (an address, a subject) is never stored,
    /// so an error can never echo the owner's text back into a log.
    InvalidField(&'static str),
    /// The whole operation exceeded its wall-clock budget.
    Timeout { budget: Duration },
    /// The server sent something we could not parse.
    ///
    /// Carries **no** server or library text: a hostile server can echo the
    /// `LOGIN` command — the password included — in a malformed response, and
    /// `imap-proto`/`async-imap` can embed that line in their error text. Every
    /// login-phase failure therefore collapses to the error kind alone.
    Protocol,
    /// A configured value is unsafe or unusable, refused **before** any socket
    /// is opened. Names the field only; e.g. `ca_file` on a non-loopback host.
    Config { field: &'static str },
}

impl MailError {
    /// The three-part message in `lang`. Never empty, never jargon.
    pub fn user_message(&self, lang: Lang) -> UserMessage {
        match lang {
            Lang::En => self.english(),
            Lang::Fr => self.french(),
        }
    }

    /// A stable, value-free classification for the `mail.call` Ledger row.
    pub fn kind(&self) -> &'static str {
        match self {
            MailError::Dns { .. } => "dns",
            MailError::Connect { .. } => "connect",
            MailError::Tls { .. } => "tls",
            MailError::NoStartTls { .. } => "no_starttls",
            MailError::InsecurePassword { .. } => "insecure_password",
            MailError::CertRejected { .. } => "cert_rejected",
            MailError::Auth => "auth",
            MailError::NoAuthMechanism => "no_auth_mechanism",
            MailError::Uncertain => "uncertain",
            MailError::FolderUnavailable { .. } => "folder_unavailable",
            MailError::SmtpAuth => "smtp_auth",
            MailError::RelayDenied { .. } => "relay_denied",
            MailError::RecipientDenied { .. } => "recipient_denied",
            MailError::RateLimited => "rate_limited",
            MailError::TooLarge { .. } => "too_large",
            MailError::Timeout { .. } => "timeout",
            MailError::Protocol => "protocol",
            MailError::InvalidField(_) => "invalid_field",
            MailError::Config { .. } => "config",
        }
    }

    /// The SMTP reply class a failure most likely came from, for the Ledger.
    pub fn reply_class(&self) -> &'static str {
        match self {
            MailError::RateLimited => "4xx",
            MailError::SmtpAuth
            | MailError::RelayDenied { .. }
            | MailError::RecipientDenied { .. }
            | MailError::Auth
            | MailError::NoAuthMechanism => "5xx",
            _ => "none",
        }
    }

    fn english(&self) -> UserMessage {
        match self {
            MailError::Dns { host, port } => um(
                "We can't find that mail server",
                &format!("The name {host} (port {port}) could not be resolved."),
                "Check the address, or type the server name yourself.",
            ),
            MailError::Connect { host, port } => um(
                "The server didn't answer",
                &format!("We reached {host} but the connection to port {port} stayed closed."),
                "Check the port, or try the other encrypted port.",
            ),
            MailError::Tls { host, port } => um(
                "The secure connection failed",
                &format!("The encrypted connection to {host}:{port} failed."),
                "Check the server name and port; do not continue if you do not trust this server.",
            ),
            MailError::NoStartTls { host, port } => um(
                "This server doesn't offer a secure connection on that port",
                &format!("{host} on port {port} does not offer the secure upgrade."),
                "Try the encrypted port (usually 465 for sending).",
            ),
            MailError::InsecurePassword { host, port } => um(
                "We won't send your password without encryption",
                &format!(
                    "The account for {host} (port {port}) is set to an unencrypted connection, \
                     so signing in would send the password in the clear."
                ),
                "Switch the account to the encrypted port (usually 993) and try again.",
            ),
            MailError::CertRejected { host, port } => um(
                "The server's security certificate isn't valid",
                &format!("The certificate for {host}:{port} is not trusted."),
                "Do not continue unless you know this server.",
            ),
            MailError::Auth => um(
                "Wrong user name or password",
                "The server refused the login.",
                "The user name is usually the full email address; an app password may be needed.",
            ),
            MailError::NoAuthMechanism => um(
                "This server wants an authentication method we don't support",
                "The server did not offer a password login we can use.",
                "Check the provider's settings, or use an app password.",
            ),
            MailError::FolderUnavailable { name, seen } => um(
                "This folder isn't available on this account",
                &format!(
                    "The server refused {name}. Folders we did see: {}.",
                    seen_list(seen)
                ),
                "Pick one of the folders we did see.",
            ),
            MailError::SmtpAuth => um(
                "The server refused the password for sending",
                "The login for sending was refused.",
                "Check the sending password; an app password may be needed.",
            ),
            MailError::RelayDenied { from } => um(
                "This server won't send mail for this address",
                &format!("The server refused to relay mail from {from}."),
                "Use the address the provider expects for sending.",
            ),
            MailError::RecipientDenied { to } => um(
                "The server refused one recipient",
                &format!("The server would not accept mail for {to}."),
                "Check the address, or send to a different one.",
            ),
            MailError::RateLimited => um(
                "The provider is throttling us",
                "The server asked us to slow down.",
                "Wait a minute and try again.",
            ),
            MailError::TooLarge { limit, seen } => um(
                "That message is too large",
                &format!("The message is {seen} bytes; the limit is {limit} bytes."),
                "Skip that message, or raise the limit in the mail settings.",
            ),
            MailError::InvalidField(field) => um(
                "Part of that message can't be sent",
                &format!("The message's `{field}` field is not valid."),
                "Check the recipient, subject and body, then try again.",
            ),
            MailError::Config { field } => um(
                "A mail setting can't be used",
                &format!("The `{field}` setting is not valid for this account."),
                "Check the mail settings, then try again.",
            ),
            MailError::Uncertain => um(
                "This mail may have been sent",
                "The server connection failed after the message was handed over.",
                "Check your Sent folder before sending again; to send again, write a new draft.",
            ),
            MailError::Timeout { budget } => um(
                "The mail server took too long",
                &format!("The operation exceeded {} seconds.", budget.as_secs()),
                "Try again, or check the server and your connection.",
            ),
            MailError::Protocol => um(
                "The mail server sent something we couldn't read",
                "The server's reply could not be understood.",
                "Try again; if it keeps happening, the server may not follow the standard.",
            ),
        }
    }

    fn french(&self) -> UserMessage {
        match self {
            MailError::Dns { host, port } => um(
                "Impossible de trouver ce serveur de messagerie",
                &format!("Le nom {host} (port {port}) n'a pas pu être résolu."),
                "Vérifiez l'adresse, ou saisissez le nom du serveur vous-même.",
            ),
            MailError::Connect { host, port } => um(
                "Le serveur n'a pas répondu",
                &format!("Nous avons joint {host} mais la connexion au port {port} est restée fermée."),
                "Vérifiez le port, ou essayez l'autre port chiffré.",
            ),
            MailError::Tls { host, port } => um(
                "La connexion sécurisée a échoué",
                &format!("La connexion chiffrée à {host}:{port} a échoué."),
                "Vérifiez le nom du serveur et le port ; ne continuez pas si vous ne faites pas confiance à ce serveur.",
            ),
            MailError::NoStartTls { host, port } => um(
                "Ce serveur ne propose pas de connexion sécurisée sur ce port",
                &format!("{host} sur le port {port} ne propose pas la mise à niveau sécurisée."),
                "Essayez le port chiffré (souvent 465 pour l'envoi).",
            ),
            MailError::InsecurePassword { host, port } => um(
                "Nous n'enverrons pas votre mot de passe sans chiffrement",
                &format!(
                    "Le compte pour {host} (port {port}) est réglé sur une connexion non \
                     chiffrée : la connexion enverrait le mot de passe en clair."
                ),
                "Passez le compte sur le port chiffré (souvent 993) et réessayez.",
            ),
            MailError::CertRejected { host, port } => um(
                "Le certificat de sécurité du serveur n'est pas valide",
                &format!("Le certificat de {host}:{port} n'est pas approuvé."),
                "Ne continuez que si vous connaissez ce serveur.",
            ),
            MailError::Auth => um(
                "Nom d'utilisateur ou mot de passe incorrect",
                "Le serveur a refusé la connexion.",
                "Le nom d'utilisateur est souvent l'adresse e-mail complète ; un mot de passe d'application peut être nécessaire.",
            ),
            MailError::NoAuthMechanism => um(
                "Ce serveur demande une méthode d'authentification que nous ne prenons pas en charge",
                "Le serveur n'a pas proposé de connexion par mot de passe utilisable.",
                "Vérifiez les réglages du fournisseur, ou utilisez un mot de passe d'application.",
            ),
            MailError::FolderUnavailable { name, seen } => um(
                "Ce dossier n'est pas disponible sur ce compte",
                &format!("Le serveur a refusé {name}. Dossiers vus : {}.", seen_list(seen)),
                "Choisissez l'un des dossiers que nous avons vus.",
            ),
            MailError::SmtpAuth => um(
                "Le serveur a refusé le mot de passe pour l'envoi",
                "La connexion pour l'envoi a été refusée.",
                "Vérifiez le mot de passe d'envoi ; un mot de passe d'application peut être nécessaire.",
            ),
            MailError::RelayDenied { from } => um(
                "Ce serveur n'enverra pas de courrier pour cette adresse",
                &format!("Le serveur a refusé de relayer le courrier depuis {from}."),
                "Utilisez l'adresse attendue par le fournisseur pour l'envoi.",
            ),
            MailError::RecipientDenied { to } => um(
                "Le serveur a refusé un destinataire",
                &format!("Le serveur n'a pas accepté le courrier pour {to}."),
                "Vérifiez l'adresse, ou écrivez à une autre personne.",
            ),
            MailError::RateLimited => um(
                "Le fournisseur nous limite",
                "Le serveur nous demande de ralentir.",
                "Attendez une minute et réessayez.",
            ),
            MailError::TooLarge { limit, seen } => um(
                "Ce message est trop volumineux",
                &format!("Le message fait {seen} octets ; la limite est de {limit} octets."),
                "Ignorez ce message, ou augmentez la limite dans les réglages.",
            ),
            MailError::InvalidField(field) => um(
                "Une partie de ce message ne peut pas être envoyée",
                &format!("Le champ `{field}` du message n'est pas valide."),
                "Vérifiez le destinataire, l'objet et le corps, puis réessayez.",
            ),
            MailError::Config { field } => um(
                "Un réglage de messagerie ne peut pas être utilisé",
                &format!("Le réglage `{field}` n'est pas valide pour ce compte."),
                "Vérifiez les réglages de messagerie, puis réessayez.",
            ),
            MailError::Uncertain => um(
                "Ce mail a peut-être été envoyé",
                "La connexion au serveur a échoué après la remise du message.",
                "Vérifiez votre dossier Éléments envoyés avant de renvoyer ; pour renvoyer, rédigez un nouveau brouillon.",
            ),
            MailError::Timeout { budget } => um(
                "Le serveur de messagerie a mis trop de temps",
                &format!("L'opération a dépassé {} secondes.", budget.as_secs()),
                "Réessayez, ou vérifiez le serveur et votre connexion.",
            ),
            MailError::Protocol => um(
                "Le serveur de messagerie a envoyé une réponse illisible",
                "La réponse du serveur n'a pas pu être comprise.",
                "Réessayez ; si cela persiste, le serveur ne suit peut-être pas le standard.",
            ),
        }
    }
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.user_message(Lang::En).title)
    }
}

impl std::error::Error for MailError {}

fn um(title: &str, cause: &str, action: &str) -> UserMessage {
    UserMessage {
        title: title.to_string(),
        cause: cause.to_string(),
        action: action.to_string(),
    }
}

fn seen_list(seen: &[String]) -> String {
    if seen.is_empty() {
        "none".to_string()
    } else {
        seen.join(", ")
    }
}
