//! Extensions at daemon startup.
//!
//! The daemon starts one sandboxed session per mounted, unfrozen extension and
//! registers its tools on each agent's turn registry. Discovery and identity
//! verification happen once at startup; a drift freezes the extension and
//! drops it before any tool is offered.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use aux_runtime::extensions::ExtensionHost;

/// The daemon's extension host, shared with the turn runner.
pub type ExtSlot = Arc<RwLock<Arc<ExtensionHost>>>;

/// Start every mounted extension and return the shared slot.
pub async fn start(home: &Path) -> ExtSlot {
    let host = ExtensionHost::start(home).await;
    Arc::new(RwLock::new(Arc::new(host)))
}

/// The current host behind the slot.
pub fn current(slot: &ExtSlot) -> Arc<ExtensionHost> {
    slot.read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// On a switch open → private, stop every extension child and start the
/// host again, so no open-mode state survives; extensions run like any
/// MCP server. A plain private → private tick does nothing.
pub fn spawn_privacy_watch(home: PathBuf, slot: ExtSlot) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(crate::privacy_wiring::WATCH_INTERVAL);
        let mut was_private = crate::privacy_wiring::private_now(&home);
        loop {
            tick.tick().await;
            let private = crate::privacy_wiring::private_now(&home);
            if private && !was_private {
                current(&slot).stop().await;
                let host = Arc::new(ExtensionHost::start(&home).await);
                *slot
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = host;
            }
            was_private = private;
        }
    })
}
