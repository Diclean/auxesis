# Auxesis kernel

**Cloud brains. Local secrets.**

Auxesis lets cloud models reason for you without learning who you are. The
kernel is the part that decides what may leave your Mac: before a prompt leaves,
names, phone numbers, addresses and account numbers are replaced by tokens. The
cloud model never learns who the clients are. Real values come back only on the
machine, after approval, when an action runs.

This repository holds the security-critical Rust crates. The daemon, the CLI,
the macOS app and the tools live in the app repository, which depends on this
one by pinned revision.

## Crates

| Crate | What it holds |
| --- | --- |
| `kernel-core` | Config, modes, `PathId`, `admit()` / `Grant`, `SafeText`, budgets, STOP |
| `kernel-privacy` | Detectors, e-mail layer, contacts index, tokens, encrypted vault, GLiNER (feature `ner-gliner`) |
| `kernel-broker` | Rules, taint, scrubbing, audit event types (the sink is a trait) |
| `kernel-net` | The one HTTP client factory, SSRF guard, DNS pinning, egress inventory |
| `kernel-mcp` | MCP client over stdio and HTTP, sandbox profiles, tool identity pinning |

The evaluation harness `qa/privacy-eval` (a workspace member) scores the
detectors against a fake, labelled corpus. The prompt-injection corpus that the
tests read is not part of this repository.

## Soul rules

These are enforced by code, not by prompts. A change that weakens one is rejected.

| # | Rule |
| --- | --- |
| 1 | The model proposes, the broker decides: ordered rules, last match wins, default `ask`, hardline deny floor. |
| 2 | Silence is no: an approval that is not answered in time is a refusal. |
| 3 | Nothing leaves the machine that the owner did not wire out. |
| 4 | In Private mode the provider only receives tokens; real values are rehydrated locally, after approval. |
| 5 | Unknown means closed: an unregistered path is refused, not tolerated. |
| 6 | Untrusted content cannot act: taint is a ratchet, and tainted conversations always ask for writes. |
| 7 | Every action leaves a replayable trace with the rule that decided it. |
| 8 | There is always a stop: the STOP file, a kill switch and daily budgets. |
| 9 | We attack our own builds: every fix becomes a permanent test, and only breakers close defects. |
| 10 | Rust with rustls only, no `unsafe` in sensitive crates, PolyForm Noncommercial 1.0.0, EN/FR copy, E.164 phone numbers. |

## Build and test

The toolchain is pinned in `rust-toolchain.toml`. Builds run on a build server,
not on a laptop.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts/check-egress.sh
cargo run -p privacy-eval --locked --release
```

`privacy-eval` prints the detection measures for the corpus in
`qa/privacy-eval/cases/`. Publish what it prints; a missed bar is printed as
missed, never rounded.

## Everyday use

These are the three ways people use the kernel day to day. The examples below
use invented values and run offline: the model call is faked, so there is no
network and no API key.

`Registry` and `Anonymizer` are the lower-level parts; the gate adds extra
passes, so use the gate unless you know why not.

### 1. Your app calls a cloud model

**The situation:** your app sends a prompt to a hosted model and shows the
answer.

**What it hides:** the values it detects leave as tokens, including bank
accounts, cards, ID numbers, health terms, API keys, e-mail addresses and phone
numbers. **What it does not hide:** person and company names stay clear by
design; postal addresses and dates of birth are only partly caught — the
measured recall table shows the rates.

```rust
use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{restore, Gate, UnknownPolicy};

let text = "Alice from ACME asks: IBAN GB82 WEST 1234 5698 7654 32, mail alice@example.com.";
let to_model = Context { destination: Destination::Vendor("hosted-model".into()) };
let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &to_model) else {
    panic!("A1 is refused");
};
let mut key = [0u8; 32];
getrandom::getrandom(&mut key).expect("random session key");
let mut gate = Gate::for_grant(&grant, key);
let (safe, _report) = gate.text(text).expect("the gate fails closed");
println!("to the model: {}", safe.as_str());

let fake_model = |prompt: &str| format!("About your invoice: {prompt}");
let answer = fake_model(safe.as_str());
// The gate gives `(token, value)` pairs; `restore` puts them back locally.
let minted = gate.take_minted();
let restored = restore(&answer, &minted, UnknownPolicy::Keep);
println!("back to you: {restored}");
```

`restore` rehydrates the answer on this machine from the pairs the gate hands
out; the values never went to the model. The full program is
[`crates/kernel-privacy/examples/everyday_llm_call.rs`](crates/kernel-privacy/examples/everyday_llm_call.rs);
it runs offline.

### 2. Before you paste a document into a chatbot

**The situation:** you want to ask a chatbot about a document without pasting
the raw values.

**What it hides:** the same classes as above, when it detects them. **What it
does not hide:** person and company names stay clear by design; postal
addresses and dates of birth are only partly caught — the measured recall table
shows the rates.

Until a command-line tool exists (it is planned, not there yet), this example
reads a file and prints the masked text:

```rust
use std::io::{self, Read};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::Gate;

let mut text = String::new();
io::stdin().read_to_string(&mut text).expect("read stdin");
let to_model = Context { destination: Destination::Vendor("hosted-model".into()) };
let Decision::Allow(grant) = admit(PathId::A1, PrivacyMode::Private, &to_model) else {
    panic!("A1 is refused");
};
let mut key = [0u8; 32];
getrandom::getrandom(&mut key).expect("random session key");
let mut gate = Gate::for_grant(&grant, key);
let (safe, _report) = gate.text(&text).expect("the gate fails closed");
print!("{}", safe.as_str());
```

```sh
cargo run -p kernel-privacy --example everyday_mask_stdin < document.txt
```

The token map is thrown away, so this output is for pasting, not for restoring
the chatbot's answer.

### 3. A team that sends customer messages to an AI tool

**The situation:** a support team sends customer messages to a hosted AI tool.
**What it hides:** the kernel sits between the app and the provider. **Open**
mode hides the most sensitive classes — bank accounts, cards, IDs, health
terms, secrets, and any address or labelled date of birth it detects — and
leaves the rest readable with a report. **Private** mode tokenises every value
it detects apart from names, so more of the text becomes tokens you can restore
on the machine. **What it does not hide:** names and company names stay clear
in both modes by design, and postal addresses and dates of birth are only
partly caught — the measured recall table shows the rates. No new code for this
one: it is the same policy path as the quickstart examples.

One honest limit: it is not a legal compliance guarantee. It reduces what
leaves the machine; the measured recall table shows how much it catches.

## Measured recall

Two runs, published as measured. Neither is a guarantee about your text.

### Held-out set (internal)

The kernel keeps an internal held-out set of 250 invented values in 184 carrier
texts, in FR/EN/AF/HU/SL/ZH. It is not in this repository, and fixes must not be
tuned against it. A value counts as hidden only when no 6-character run of it is
readable in the output; a partial mask or a gate refusal is a miss.

| class | n | Private | Open |
| --- | ---: | ---: | ---: |
| IBAN | 40 | 100.00 % | 100.00 % |
| card | 35 | 100.00 % | 100.00 % |
| ID | 70 | 95.71 % | 94.29 % |
| secret | 45 | 93.33 % | 93.33 % |
| health | 60 | 81.67 % | 81.67 % |
| **all** | **250** | **93.20 %** | **92.80 %** |

The Tier C bar is 99.5 %. **It is not met yet**: Private is 93.20 % and Open is
92.80 % on this set. These are measured recall values on invented data, not a
guarantee about other text. Details: [`qa/privacy-eval/RECALL.md`](qa/privacy-eval/RECALL.md).

### Public benchmarks

EXT-BENCH-1 ran the production gate in Private mode over three public PII
corpora on 2026-11-01, Standard detection only, at most 5,000 texts per set.
Recall is per class and per set; `n` is the number of gold values in that set's
sample, and `–` means the set has no scorable label for that class.

| class | Nemotron-PII | Gretel | TAB |
| --- | ---: | ---: | ---: |
| e-mail | 100.0 % (3,218) | 99.8 % (1,300) | – |
| phone | 99.0 % (1,835) | 96.9 % (915) | – |
| IBAN | – | 96.4 % (195) | – |
| card | 99.9 % (769) | 99.2 % (118) | – |
| national ID | 100.0 % (331) | 93.5 % (153) | – |
| passport | – | 89.0 % (136) | – |
| driving licence | 76.6 % (167) | 100.0 % (140) | – |
| tax ID | 100.0 % (90) | – | – |
| secret | 85.0 % (1,672) | 61.5 % (494) | – |
| health | 97.3 % (1,564) | – | – |
| postal address | 72.1 % (920) | 40.8 % (4,304) | 100.0 % (6) |
| date of birth | 97.5 % (1,062) | 69.1 % (230) | 3.4 % (235) |

TAB's 241 scored values are only dates of birth and six street-number addresses,
so its cells say nothing about the other classes.

Known gaps: postal address is the weak class (Gretel 40.8 %, n = 4,304;
Nemotron 72.1 %, n = 920; TAB 100 % is six street-number addresses). Other weak
cells: secret on Gretel 61.5 % (n = 494), date of birth on TAB 3.4 % (n = 235)
and Gretel 69.1 % (n = 230), driving licence on Nemotron 76.6 % (n = 167), and
national ID on Gretel 93.5 % (n = 153). Cards read 99.9 % on Nemotron and 99.2 %
on Gretel; many synthetic cards are Luhn-invalid and Private catches them by
context, so that is not a checksum result. The run predates the compact and
spaced IBAN fix (#475), so IBAN should be re-measured on current code.

The three open-licence corpora:

- [nvidia/Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) —
  CC BY 4.0, NVIDIA Corporation.
- [gretelai/synthetic_pii_finance_multilingual](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) —
  Apache-2.0, Gretel AI.
- [TAB, the Text Anonymisation Benchmark](https://github.com/NorskRegnesentral/text-anonymisation-benchmark) —
  MIT, Norsk Regnesentral.

No dataset row or raw value is in this repository.

## Known gaps

**Postal addresses are only partly detected.** Measured Private recall is 40.8 %
on Gretel (n = 4,304) and 72.1 % on Nemotron (n = 920); the 100 % TAB cell is six
street-number addresses. Treat an address as unprotected unless you have
measured the form you care about.

## Status

Early and owner-first. The kernel has no releases and no stable API yet. Only
`main` is supported; see [SECURITY.md](SECURITY.md) to report a vulnerability.

## Licence

**PolyForm Noncommercial 1.0.0.** Free for noncommercial use. Any commercial
use needs a paid licence from the copyright holder — see
[COMMERCIAL.md](COMMERCIAL.md). The full text is in [LICENSE](LICENSE) and the
notices in [NOTICE](NOTICE).
