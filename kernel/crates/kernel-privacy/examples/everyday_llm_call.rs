//! Everyday use: mask a prompt for a cloud model through the production gate,
//! send it through a fake call, then put the real values back into the answer.
//! No network, no API key. Invented values.
//!
//!     cargo run -p kernel-privacy --example everyday_llm_call

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{restore, Gate, UnknownPolicy};

fn main() {
    let text = "Hi, this is Alice from ACME. My IBAN is GB82 WEST 1234 5698 7654 32 \
                and my e-mail is alice@example.com. Is the invoice paid?";

    // 1. Ask the kernel for a grant for this path, then mask through the gate.
    //    `A1` is "chat with a hosted model"; Private tokenises what it detects.
    let to_model = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let grant = match admit(PathId::A1, PrivacyMode::Private, &to_model) {
        Decision::Allow(grant) => grant,
        other => panic!("A1 refused: {other:?}"),
    };
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).expect("random session key");
    let mut gate = Gate::for_grant(&grant, key);
    let (safe, _report) = gate.text(text).expect("the gate fails closed on error");
    println!("to the model: {}", safe.as_str());

    // 2. Send it. This closure stands in for the cloud call, so the example
    //    needs no network. The model only ever sees `safe`.
    let fake_model = |prompt: &str| format!("About your invoice: {prompt}");
    let answer = fake_model(safe.as_str());

    // 3. The gate hands out `(token, value)` pairs on this machine. `restore`
    //    puts the values back locally: they never went to the model, and the
    //    restored text is for the person who asked, never for the model.
    let minted = gate.take_minted();
    let restored = restore(&answer, &minted, UnknownPolicy::Keep);
    println!("back to you:  {restored}");

    // Names stay readable; the account and e-mail do not. The round trip is
    // exact for this text, so the person who asked sees their own text again.
    assert!(safe.as_str().contains("Alice from ACME"));
    assert!(!safe.as_str().contains("GB82 WEST"));
    assert!(!safe.as_str().contains("alice@example.com"));
    assert_eq!(restored, format!("About your invoice: {text}"));
}
