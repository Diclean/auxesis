//! Level-1 fetch: readable text from a web page.
//!
//! [`extract_readable`] is pure and always built. [`Fetcher`], the simple path,
//! needs the kernel's pinned HTTP client factory. The kernel keeps that factory
//! crate-private, so the simple path sits behind the `l1-fetch` feature.

mod readability;
#[cfg(feature = "l1-fetch")]
mod simple;

pub use readability::{extract_readable, Readable};
#[cfg(feature = "l1-fetch")]
pub use simple::Fetcher;
