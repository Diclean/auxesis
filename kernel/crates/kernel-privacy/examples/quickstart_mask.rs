//! Quickstart 1: find the sensitive values in a string, replace them with
//! tokens, then put the real values back into the answer. Invented values.
//!
//!     cargo run -p kernel-privacy --example quickstart_mask

use kernel_privacy::{Anonymizer, Registry, UnknownPolicy};

fn main() {
    let text = "Pay GB82 WEST 1234 5698 7654 32 before Friday, \
                mail alice@example.com, key AKIAIOSFODNN7EXAMPLE.";

    // 1. Detect. `without_names()` is what private mode runs: a name stays clear.
    let spans = Registry::new().without_names().analyze(text);

    // 2. Tokenise. One fresh random key per session, and the token map never
    // leaves this machine.
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).expect("random session key");
    let (masked, tokens) = Anonymizer::new(key).anonymize(text, &spans);
    println!("sent to the model: {masked}");

    // 3. The model answers with tokens. The restore runs here, on this machine,
    // from the token map that never left it: the map itself is never printed,
    // only the text that comes back from the API, for the person who asked.
    let reply = Anonymizer::restore(&format!("Done: {masked}"), &tokens, UnknownPolicy::Redact);
    assert!(reply.is_clean(), "unknown tokens: {:?}", reply.unknown);
    println!("shown to you:      {}", reply.text);
    assert_eq!(reply.text, format!("Done: {text}"));
}
