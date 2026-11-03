//! The built-in tools: the implementations the kernel registry dispatches to.
//!
//! The kernel's [`ToolRegistry`] carries each tool's class (trust, risk, skill
//! floor). [`register_builtins`] puts the implementations behind those classes.

use kernel_broker::{ShellSandbox, ToolRegistry};
use kernel_core::WebConfig;

mod memory;
mod owner_profile;
mod read_file;
mod shell;
mod write_file;
// The L1 fetch tools wait for the `l1-fetch` feature (see `crate::fetch`).
#[cfg(feature = "l1-fetch")]
mod http_fetch;
#[cfg(feature = "l1-fetch")]
mod weather;

#[cfg(feature = "l1-fetch")]
pub use http_fetch::HttpFetchTool;
pub use memory::{sync_note_mirror, ForgetTool, MemoryTools, RecallTool, SuggestMemoryTool};
pub use owner_profile::OwnerProfileTool;
pub use read_file::ReadFileTool;
pub use shell::ShellTool;
#[cfg(feature = "l1-fetch")]
pub use weather::{WeatherForecastTool, WeatherGeocodeTool};
pub use write_file::WriteFileTool;

/// Register the built-in tool implementations on `registry`.
///
/// Call it on a registry built with [`ToolRegistry::with_shell_web`], which
/// already holds the classes, so each name lands behind the class the kernel
/// declares for it. `shell` gets `sandbox`; the fetch tools get `web`.
pub fn register_builtins(registry: &mut ToolRegistry, sandbox: ShellSandbox, web: WebConfig) {
    registry.register_native(Box::new(ShellTool::with_sandbox(sandbox)));
    registry.register_native(Box::new(ReadFileTool));
    registry.register_native(Box::new(WriteFileTool));
    #[cfg(feature = "l1-fetch")]
    {
        registry.register_native(Box::new(HttpFetchTool::with_web(web.clone())));
        registry.register_native(Box::new(WeatherForecastTool::with_web(web.clone())));
        registry.register_native(Box::new(WeatherGeocodeTool::with_web(web)));
    }
    #[cfg(not(feature = "l1-fetch"))]
    let _ = web;
}
