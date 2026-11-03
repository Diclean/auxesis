//! K-REGISTRY-PERF: a megabyte of chat log (user and assistant turns, prose
//! mixed with code, JSON, tables, mail and phone lines) is scanned in about a
//! second, linearly. Release only: `--release --test registry_perf -- --ignored`.

use std::time::{Duration, Instant};

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::{Gate, Registry};

const KIB: usize = 1024;

/// A small deterministic generator (xorshift), so the fixture is the same on
/// every machine and needs no download. Every value is invented.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[(self.next() % items.len() as u64) as usize]
    }
}

const FIRST: &[&str] = &["Mara", "Jonas", "Ilse", "Theo", "Nadia", "Pieter", "Lena"];
const LAST: &[&str] = &["Exemple", "Testwood", "Fictive", "Sample", "Demoville"];
const PROSE: &[&str] = &[
    "Could you summarise the thread and tell me what is still open?",
    "Sure, here is what I found in the last three messages.",
    "The meeting moved to Thursday at 10:30, and the agenda is unchanged.",
    "I paid the invoice on 2026-09-14 for 1 250,00 EUR, reference INV-2041.",
    "Please draft a short reply that thanks them and asks for the signed copy.",
    "They want the quote revised: 12 days at 640 EUR a day, net 30.",
    "I could not find a mail about the contract renewal in your inbox.",
];
/// The structured part of a turn. `§F`/`§L` are a given and family name (`§f`
/// and `§l` lower-cased), `§2` two digits, `§4` four, `§x` a hex id, `§n` a
/// number.
const BLOCKS: &[&str] = &[
    "Mail from §F §L <§f.§l§n@example.org>: see you on Monday.",
    "Call §F on +44 20 7946 §4 or +33 6 12 34 §2 §2.",
    "```json\n{\"id\": §n, \"name\": \"§F §L\", \"amount\": §n.§2, \"url\": \"https://example.com/items/§n\"}\n```",
    "| date | client | amount |\n|---|---|---|\n| 2026-10-§2 | §L Ltd | §n EUR |",
    "```rust\nfn total(items: &[u32]) -> u32 { items.iter().sum::<u32>() + §2 }\n```",
    "- step §2: open https://docs.example.net/guide?page=§n&lang=en\n- step §2: run `make test`",
    "IBAN for the refund: GB82 WEST 1234 5698 7654 32, thanks.",
    "Log: 2026-10-21T08:§2:§2Z INFO request id=§x took §n ms",
    "> §F wrote: the parcel §n left Lyon on 21/10 and arrives in 2 days.",
];

/// One chat turn: prose plus one structured block, like a real session log.
fn turn(rng: &mut Rng, index: usize, out: &mut String) {
    let role = if index.is_multiple_of(2) {
        "user"
    } else {
        "assistant"
    };
    out.push_str(&format!("[{role}] turn {index}\n"));
    for _ in 0..=rng.next() % 3 {
        out.push_str(rng.pick(PROSE));
        out.push(' ');
    }
    out.push('\n');
    let (first, last) = (rng.pick(FIRST), rng.pick(LAST));
    let mut parts = rng.pick(BLOCKS).split('§');
    out.push_str(parts.next().unwrap_or_default());
    for part in parts {
        let value = match part.chars().next() {
            Some('F') => first.to_owned(),
            Some('L') => last.to_owned(),
            Some('f') => first.to_lowercase(),
            Some('l') => last.to_lowercase(),
            Some('2') => format!("{:02}", rng.next() % 60),
            Some('4') => format!("{:04}", rng.next() % 10_000),
            Some('x') => format!("{:016x}", rng.next()),
            _ => (rng.next() % 100_000).to_string(),
        };
        out.push_str(&value);
        out.push_str(&part[1..]);
    }
    out.push_str("\n\n");
}

/// The chat-log fixture, cut to `bytes` at a line end.
fn chat_log(bytes: usize) -> String {
    let mut rng = Rng(0x5eed_cafe_f00d_d00d);
    let mut text = String::with_capacity(bytes + 512);
    let mut index = 0;
    while text.len() < bytes {
        turn(&mut rng, index, &mut text);
        index += 1;
    }
    let cut = text[..bytes].rfind('\n').map_or(bytes, |at| at + 1);
    text.truncate(cut);
    text
}

fn gate(mode: PrivacyMode) -> Gate {
    let context = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &context) else {
        panic!("chat is admitted in {mode:?}");
    };
    Gate::for_grant(&grant, [0x44u8; 32])
}

/// The fastest of three runs, so one scheduler hiccup does not fail the bar.
fn best_of_three(text: &str, work: &dyn Fn(&str)) -> Duration {
    (0..3)
        .map(|_| {
            let start = Instant::now();
            work(text);
            start.elapsed()
        })
        .min()
        .expect("three runs")
}

/// A timed arm: label, 1 MiB limit, work.
type Arm<'a> = (&'a str, Duration, &'a dyn Fn(&str));

/// "About a second" on the owner's Mac, with headroom for a busy machine.
const LIMIT: Duration = Duration::from_millis(1500);

/// The acceptance bar: 1 MiB of chat log through the whole registry in about
/// a second, and four times the text costs about four times the time (a
/// quadratic pass costs sixteen; main took 0.76 s, 2.06 s and 6.51 s at 256,
/// 512 and 1024 KiB). Both modes of the gate stay linear too; Private reads
/// the text twice (detection, then the residue scan of its output).
#[test]
#[ignore = "release-mode timing: run with --release --ignored"]
fn a_mebibyte_of_chat_log_is_scanned_in_about_a_second() {
    let quarter = chat_log(256 * KIB);
    let whole = chat_log(1024 * KIB);
    let registry = Registry::new();
    let issue = |mode| move |text: &str| drop(gate(mode).text(text).expect("issued"));
    let arms: [Arm; 3] = [
        ("analyze", LIMIT, &|text| drop(registry.analyze(text))),
        ("gate Open", LIMIT, &issue(PrivacyMode::Open)),
        ("gate Private", 2 * LIMIT, &issue(PrivacyMode::Private)),
    ];
    for (label, limit, work) in arms {
        let (small, large) = (best_of_three(&quarter, work), best_of_three(&whole, work));
        let ratio = large.as_secs_f64() / small.as_secs_f64();
        println!("{label}: 256 KiB {small:?}, 1 MiB {large:?}, ratio {ratio:.2}");
        assert!(
            ratio < 6.0,
            "{label} grows super-linearly: x{ratio:.2} for x4 text"
        );
        assert!(
            large < limit,
            "{label} of 1 MiB took {large:?}, limit {limit:?}"
        );
    }
}
