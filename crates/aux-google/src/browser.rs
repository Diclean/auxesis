//! The explicit system-browser opener.
//!
//! [`SystemBrowser`] is deliberately **not** a default anywhere in this crate:
//! a caller must name it, so a browser can only ever open from a command the
//! owner just ran (`aux connect google`) or a button the owner just clicked
//! (the app's « Connecter Google »). Nothing in the daemon's startup path, its
//! scheduler or a tool call can reach it.

use crate::{UrlOpenError, UrlOpener};
use url::Url;

/// Opens an authorization URL with the platform's default browser.
pub struct SystemBrowser;

#[async_trait::async_trait]
impl UrlOpener for SystemBrowser {
    async fn open_url(&self, url: &Url) -> Result<(), UrlOpenError> {
        // Defense in depth: only the fixed https authorization endpoint this
        // crate builds may ever be handed to the OS opener. A file:// or a
        // custom scheme would otherwise become a local execution primitive.
        if url.scheme() != "https" || url.host_str() != Some("accounts.google.com") {
            return Err(UrlOpenError);
        }
        let url = url.as_str().to_string();
        tokio::task::spawn_blocking(move || open_with_system(&url))
            .await
            .map_err(|_| UrlOpenError)?
    }
}

#[cfg(target_os = "macos")]
fn open_with_system(url: &str) -> Result<(), UrlOpenError> {
    launch("/usr/bin/open", url)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_with_system(url: &str) -> Result<(), UrlOpenError> {
    launch("xdg-open", url)
}

#[cfg(not(unix))]
fn open_with_system(_url: &str) -> Result<(), UrlOpenError> {
    Err(UrlOpenError)
}

#[cfg(unix)]
fn launch(command: &str, url: &str) -> Result<(), UrlOpenError> {
    // The URL is passed as one argv entry (never through a shell), so no
    // argument of it can be re-interpreted as a command.
    let status = std::process::Command::new(command)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| UrlOpenError)?;
    if status.success() {
        Ok(())
    } else {
        Err(UrlOpenError)
    }
}
