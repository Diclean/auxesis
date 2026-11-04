//! A fixed in-process credential source for tests. Fictional values only.
//!
//! The production source reads `~/.auxesis/.env`; tests must never
//! touch it, so this implements [`Credentials`] over a small map.

use std::collections::HashMap;

use aux_mail::imap_read::Credentials;

/// A credential source with a fixed password per account.
#[derive(Debug, Default)]
pub struct StaticCredentials {
    passwords: HashMap<String, String>,
}

impl StaticCredentials {
    /// One account and its (fictional) password.
    pub fn new(account: &str, password: &str) -> Self {
        let mut passwords = HashMap::new();
        passwords.insert(account.to_string(), password.to_string());
        Self { passwords }
    }

    /// No account has a password.
    pub fn empty() -> Self {
        Self::default()
    }
}

impl Credentials for StaticCredentials {
    fn password(&self, account: &str) -> Option<String> {
        self.passwords.get(account).cloned()
    }
}
