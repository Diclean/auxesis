//! Everyday use, command line: read a document from stdin, run it through the
//! production gate in Private mode, and print the masked text. The token pairs
//! are dropped at the end, so this is for paste-only use; restoring needs them
//! and is shown in `everyday_llm_call`.
//!
//!     cargo run -p kernel-privacy --example everyday_mask_stdin < document.txt

use std::io::{self, Read};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::Gate;

fn main() {
    let mut text = String::new();
    io::stdin()
        .read_to_string(&mut text)
        .expect("read stdin as UTF-8");

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
    let (safe, _report) = gate.text(&text).expect("the gate fails closed on error");

    print!("{}", safe.as_str());
}
