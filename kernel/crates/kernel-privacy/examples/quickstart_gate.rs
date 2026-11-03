//! Quickstart 2: the policy path. Ask the kernel whether a path may send text,
//! then handle the only type a sender should accept, `SafeText`. Invented
//! values.
//!
//!     cargo run -p kernel-privacy --example quickstart_gate

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::Gate;

fn main() {
    let text = "Mail alice@example.com, IBAN GB82 WEST 1234 5698 7654 32, \
                key AKIAIOSFODNN7EXAMPLE.";
    let to_model = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };

    for mode in [PrivacyMode::Private, PrivacyMode::Open] {
        // A1 is the "chat with a hosted model" path; other paths can be refused.
        let grant = match admit(PathId::A1, mode, &to_model) {
            Decision::Allow(grant) => grant,
            other => panic!("A1 refused: {other:?}"),
        };
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("random session key");
        let mut gate = Gate::for_grant(&grant, key);
        let (safe, report) = gate.text(text).expect("the gate fails closed on error");
        println!("{mode:?} sent:   {}", safe.as_str());
        println!("{mode:?} report: {report}");

        // Only the gate holds the token -> value pairs: keep them on this machine.
        // They go to the caller's vault, never to a terminal and never to a log:
        // a printed value is a copy you cannot take back. So print the count only.
        let minted = gate.take_minted();
        println!(
            "{mode:?} keep:   {} pair(s) for the vault, values not printed",
            minted.len()
        );
    }
}
