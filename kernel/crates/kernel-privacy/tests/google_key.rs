//! K-GOOGLE-KEY acceptance: a Google API key (`AIza` and 35 key characters), an
//! OAuth client secret (`GOCSPX-`) and an OAuth access token (`ya29.`) are
//! secrets in both modes, in every form below: bare, after a label, in a URL,
//! glued to words, after a line break or another masked value, in quotes and
//! brackets, with markdown escapes (`\_`, `\-`) inside, and the dotted
//! `ya29.c.` service-account token. Look-alikes gain no mask, and the head is a
//! strict byte superset of main on a seeded differential frozen from origin/main
//! in `data/google_key_main.txt` (`-- --ignored freeze --nocapture`, on main
//! only). Every mask is read with the shared exact reader `data/exact_mask.rs`.
//! Every key is invented and built at runtime from parts.

use std::time::Instant;

use kernel_core::privacy::PrivacyMode;

#[allow(dead_code)]
mod norm1 {
    include!("data/norm1_cases.rs");
}
use norm1::{covered, exact_ranges, issue, MODES};

const FIXTURE: &str = include_str!("data/google_key_main.txt");

/// One mode's record of `input`, read by the shared exact reader:
/// `start-end,` ranges; `!` a refusal; `?` an output that does not read back.
fn exact(mode: PrivacyMode, input: &str) -> String {
    let Some((output, minted)) = issue(mode, input) else {
        return "!".into();
    };
    exact_ranges(mode, input, &output, &minted).map_or("?".into(), |r| {
        r.iter().map(|(s, e)| format!("{s}-{e},")).collect()
    })
}

/// A xorshift64, so the corpus is the same text on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<'a>(&mut self, list: &[&'a str]) -> &'a str {
        list[(self.next() % list.len() as u64) as usize]
    }
}

/// `n` invented key characters, `_` and `-` included, seeded by `seed`.
fn body(seed: u64, n: usize) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    (0..n)
        .map(|_| char::from(alphabet[(rng.next() % 64) as usize]))
        .collect()
}

/// An invented Google API key: `AIza`, then `Sy`, then 33 more characters
/// holding at least one `_` and one `-`.
fn gkey(i: u64) -> String {
    let t = body(i, 31);
    format!("AI{}Sy{}_{}-{}", "za", &t[..10], &t[10..20], &t[20..])
}

/// An invented OAuth client secret: `GOCSPX-` and 28 characters.
fn gocspx(i: u64) -> String {
    format!("GOC{}-{}_{}", "SPX", body(i + 7, 13), body(i + 9, 14))
}

/// An invented OAuth access token, plain (`ya29.a0…`) or service-account
/// (`ya29.c.…`).
fn ya29(i: u64, service: bool) -> String {
    let dot = if service { ".c." } else { "." };
    format!("ya{}{dot}{}-{}", "29", body(i + 3, 40), body(i + 5, 30))
}

/// Markdown escapes: every `_` and `-` written as `\_` and `\-`.
fn escaped(value: &str) -> String {
    value.replace('_', "\\_").replace('-', "\\-")
}

/// What may stand before a key (`¦`-separated): other masked values and breaks.
const BEFORE: &str = "AB 12 34 56\n¦AB 12 34 56 C\n¦AB123456C\n¦AB 12 34 56\r\n¦\
    NI QQ 12 34 56 C\t¦GB82 WEST 1234 5698 7654 32\n¦+44 20 7946 0958\n¦lena.ortiz@example.org\n¦\
    lena.ortiz@example.org¦x\n¦x\r\n¦x\t¦abc¦";

/// The frames a value sits in, `¦`-separated.
const FRAMES: &str = "{}¦key={}¦\"api_key\": \"{}\"¦GOOGLE_API_KEY={}¦\
    https://maps.googleapis.com/maps/api/js?key={}&v=3¦{}def¦({})¦[{}]¦'{}'¦<{}>¦`{}`¦**{}**¦\
    | key | {} |¦Maps key {} works.";

/// `(text, value)`: every byte of `value` (its last occurrence) must be hidden
/// in both modes, and Private must restore the text exactly.
fn positives() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    for before in BEFORE.split('¦') {
        for frame in FRAMES.split('¦') {
            i += 1;
            let values = [
                gkey(i),
                escaped(&gkey(i)),
                gocspx(i),
                escaped(&gocspx(i)),
                ya29(i, false),
                ya29(i, true),
                escaped(&ya29(i, true)),
            ];
            for value in values {
                out.push((format!("{before}{}", frame.replace("{}", &value)), value));
            }
        }
    }
    out.push((
        format!("Authorization: Bearer {}", ya29(1, true)),
        ya29(1, true),
    ));
    out
}

/// Look-alikes: whatever main does with them, the head does byte for byte.
fn negatives() -> Vec<String> {
    let mut out: Vec<String> = [
        "Aizawa met Aizaki in Aizu.",
        "Mr Aizawa's notes, AIZA policy, aiza.",
        "ya29 is a model number; GOCSPX is a word.",
        "Visit ya29. Then leave.",
        "path\\_to\\_file and a\\-b and snake\\_case\\_name",
        "use \\_\\_init\\_\\_ here",
    ]
    .map(String::from)
    .to_vec();
    for i in 0..12 {
        let k = body(100 + i, 40);
        out.push(format!("short AI{}{} key", "za", &k[..34]));
        out.push(format!("long AI{}{} key", "za", &k[..36]));
        out.push(format!("escaped short AI{}\\_{}", "za", &k[..20]));
        out.push(format!("ya{}.c.{} end", "29", &k[..8]));
        out.push(format!("GOC{}-{} end", "SPX", &k[..12]));
        let blob: String = (0..4).map(|j| body(200 + i * 4 + j, 40)).collect();
        out.push(format!("attachment data {blob}== end"));
        out.push(format!("line one\n{}\nline two", &blob[..76]));
    }
    out
}

/// Values of the other classes and prose, `¦`-separated.
const OTHERS: &str = "IBAN FR76 3000 6000 0112 3456 7890 189¦GB82 WEST 1234 5698 7654 32¦\
    card 4111 1111 1111 1111 exp 09/29¦NI number QQ 12 34 56 C¦AB 12 34 56¦AB123456C¦\
    SSN 512-45-8873¦she has type 2 diabetes¦blood type AB-¦lena.ortiz@example.org¦\
    call +44 20 7946 0958¦see https://example.test/login¦Thanks for the update.¦Kind regards,¦\
    Mr Aizawa called.¦use snake\\_case here";

/// The seeded corpus: 1,600 documents of two to five parts (a key in a frame,
/// another class's value, or prose), joined by a break, glue or a sentence end.
fn seeded() -> Vec<String> {
    let mut rng = Rng(0x474F_4F47_4C45_4B45);
    let (frames, others): (Vec<_>, Vec<_>) =
        (FRAMES.split('¦').collect(), OTHERS.split('¦').collect());
    let mut out = Vec::new();
    for i in 0..1_600u64 {
        let mut parts: Vec<String> = Vec::new();
        for _ in 0..2 + rng.next() % 4 {
            let part = match rng.next() % 3 {
                0 => {
                    let value = match rng.next() % 6 {
                        0 | 1 => gkey(i),
                        2 => escaped(&gkey(i)),
                        3 => gocspx(i),
                        4 => ya29(i, rng.next().is_multiple_of(2)),
                        _ => escaped(&ya29(i, true)),
                    };
                    rng.pick(&frames).replace("{}", &value)
                }
                1 => rng.pick(&others).to_string(),
                _ => rng.pick(&["Hello", "Aizawa", "Notes:", "x"]).to_string(),
            };
            if !parts.contains(&part) {
                parts.push(part);
            }
        }
        let joint = rng.pick(&["\n", "\r\n", "\t", " ", "\n\n", ". "]);
        out.push(parts.join(joint));
    }
    out
}

/// An invented Slack bot token (`xoxb-`, two digit runs, 24 characters).
fn xoxb(i: u64) -> String {
    let d = format!(
        "{:020}",
        i.wrapping_mul(0x2545_F491_4F6C_DD1D) % 10u64.pow(19)
    );
    let tail: String = body(i + 11, 80)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(24)
        .collect();
    format!("xo{}-1{}-2{}-{tail}", "xb", &d[..9], &d[10..19])
}

/// An invented GitHub token (`ghp_` and 36 characters).
fn ghp(i: u64) -> String {
    let tail: String = body(i + 13, 120)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(36)
        .collect();
    format!("gh{}_{tail}", "p")
}

/// What is glued before a URL (`¦`-separated): masked values of other classes.
const URL_BEFORE: &str = "IBAN FR76 3000 6000 0112 3456 7890 189¦+44 20 7946 0958¦\
    lena.ortiz@example.org ¦AB 12 34 56 C¦AB123456C¦GB82 WEST 1234 5698 7654 32";

/// What follows the key inside the URL (`¦`-separated): query tails.
const URL_TAILS: &str = "&amp;alt=json¦&alt=json¦&session=7f3a9c1e2b¦&uid=42&amp;v=3¦\
    &amp;session=ab12cd34&amp;uid=99¦/v2/x?alt=json¦#frag¦¦&x=1\u{a0}next¦&x=1\u{3000}after";

/// What follows the URL (`¦`-separated): another masked value, a break or prose.
const URL_AFTER: &str =
    "+44 20 7946 0958¦¦\n¦\r\n¦ next¦.¦lena.ortiz@example.org¦\u{a0}next¦\u{3000}after";

/// K-GOOGLE-KEY round 1: an escaped key inside a URL with a query tail, the URL
/// glued after (or one break after) another masked value. `(text, url start,
/// key start, key end, tail end)`.
fn url_tail_cases(seed: u64, n: usize) -> Vec<(String, usize, usize, usize, usize)> {
    let mut rng = Rng(seed);
    let (before, tails, after): (Vec<_>, Vec<_>, Vec<_>) = (
        URL_BEFORE.split('¦').collect(),
        URL_TAILS.split('¦').collect(),
        URL_AFTER.split('¦').collect(),
    );
    (0..n as u64)
        .map(|i| {
            let key = match rng.next() % 5 {
                0 => gkey(i),
                1 => xoxb(i),
                2 => ghp(i),
                3 => gocspx(i),
                _ => ya29(i, true),
            };
            let key = escaped(&key);
            let head = format!(
                "{}{}https://api.example.test/v1/x?{}=",
                rng.pick(&before),
                rng.pick(&["", "", "\n", "\r\n"]),
                rng.pick(&["key", "access_token", "q=1&amp;token", "q=1&token"]),
            );
            let url = head.rfind("https").expect("url");
            let tail = rng.pick(&tails);
            let text = format!("{head}{key}{tail}{}", rng.pick(&after));
            let end = head.len() + key.len() + tail.len();
            (text, url, head.len(), head.len() + key.len(), end)
        })
        .collect()
}

/// `n` invented ASCII letters and digits, seeded by `seed`.
fn alnum(seed: u64, n: usize) -> String {
    body(seed, n * 4)
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .chain("Q7".chars().cycle())
        .take(n)
        .collect()
}

/// An invented key of one of twelve kinds, built from parts.
fn any_key(kind: u64, i: u64) -> String {
    match kind % 12 {
        0 => gkey(i),
        1 => gocspx(i),
        2 => ya29(i, false),
        3 => ya29(i, true),
        4 => format!("1/{}0{}-{}", "/", body(i + 15, 30), body(i + 17, 20)),
        5 => ghp(i),
        6 => format!(
            "github{}_{}_{}",
            "_pat",
            alnum(i + 19, 22),
            alnum(i + 21, 59)
        ),
        7 => xoxb(i),
        8 => format!("sk{}_{}", "_live", alnum(i + 23, 24)),
        9 => format!("sk-{}-{}", "proj", body(i + 25, 48)),
        10 => format!(
            "ey{}{}.ey{}{}.{}",
            "J",
            body(i + 27, 30),
            "J",
            body(i + 29, 40),
            body(i + 31, 43)
        ),
        _ => format!("glp{}-{}", "at", body(i + 33, 20)),
    }
}

/// `key` in one of twelve written forms: plain, markdown escapes, a line wrap,
/// invisible characters, a JSON-escaped backslash, percent and dot escapes.
fn form(key: &str, f: u64) -> String {
    let mid = key.len() / 2;
    let split = |sep: &str| format!("{}{sep}{}", &key[..mid], &key[mid..]);
    match f % 12 {
        0 => key.to_string(),
        1 => escaped(key),
        2 => key.replace('_', "\\_"),
        3 => key.replace('-', "\\-"),
        4 => escaped(&split("\n")),
        5 => escaped(&split("\r\n")),
        6 => split("\u{200b}"),
        7 => split("\u{ad}"),
        8 => key.replace('_', "\\\\_").replace('-', "\\\\-"),
        9 => key.replace('_', "%5F").replace('-', "%2D"),
        10 => escaped(key).replace('.', "\\."),
        _ => escaped(&split("\u{200b}")),
    }
}

/// Pass A's frames (`¦`-separated).
const A_FRAMES: &str = "{}¦Here is the key {} for you.¦{\"api_key\": \"{}\"}¦api_key: {}¦\
    API_KEY={}¦https://api.example.test/v1?key={}&alt=json¦- {}¦NI AB 12 34 56 C\n{}¦\
    lena.ortiz@example.org {}¦| key | {} |¦token={}";

/// Values that may stand before a URL or a key (`¦`-separated).
const A_BEFORE: &str = "4111 1111 1111 1111¦4111111111111111¦1 85 05 78 006 084 36¦\
    185057800608436¦she has type 2 diabetes¦12 rue de la Paix, 75002 Paris¦\
    10 Downing Street, London SW1A 2AA¦SSN 512-45-8873¦IBAN FR76 3000 6000 0112 3456 7890 189¦\
    lena.ortiz@example.org¦+44 20 7946 0958¦AB 12 34 56 C¦";

/// Prose and values after a key or a URL (`¦`-separated).
const A_AFTER: &str = "¦ then call me¦; see you¦. Thanks¦\tcall +44 20 7946 0958¦\nNext line¦\
    card 4111 1111 1111 1111 exp 09/29¦\r\nKNI number QQ 12 34 56 C¦ \t ¦,then more";

/// Pass A's round-0 grid: twelve kinds in twelve forms in eleven frames.
#[allow(dead_code)]
fn grid_cases() -> Vec<String> {
    let frames: Vec<&str> = A_FRAMES.split('¦').collect();
    let mut out = Vec::new();
    for kind in 0..12 {
        for f in 0..12 {
            for (n, frame) in frames.iter().enumerate() {
                let key = form(&any_key(kind, kind * 131 + f * 11 + n as u64), f);
                out.push(frame.replace("{}", &key));
            }
        }
    }
    out
}

/// Markdown-escaped prose that is no key, and short look-alikes.
#[allow(dead_code)]
fn escaped_prose(seed: u64, n: usize) -> Vec<String> {
    let mut rng = Rng(seed);
    let fixed = "snake\\_case¦cargo test \\-\\-release¦\\_\\_main\\_\\_¦my\\_api\\_key\\_name.txt¦\
        sk\\-learn¦pk\\_test¦C:\\Users\\_temp\\-dir¦[A-Za-z0-9\\_\\-]{35}¦Aizawa\\_san¦\
        AIza\\_short\\-x¦ghp\\_ is the prefix¦**bold\\_text**¦ya29.c.ab\\_cd";
    let mut out: Vec<String> = fixed.split('¦').map(String::from).collect();
    let words = [
        "snake", "case", "my", "api", "key", "AIza", "ya29", "sk", "ghp", "file", "x",
    ];
    while out.len() < n {
        let parts: Vec<&str> = (0..2 + rng.next() % 4).map(|_| rng.pick(&words)).collect();
        let glue = rng.pick(&["\\_", "\\-", "_", "."]);
        out.push(format!("use {} here", parts.join(glue)));
    }
    out
}

/// Seeded mixes: a key in some form and frame, other classes and prose.
fn mixed_cases(seed: u64, n: usize) -> Vec<String> {
    let mut rng = Rng(seed);
    let frames: Vec<&str> = A_FRAMES.split('¦').collect();
    let (before, after): (Vec<&str>, Vec<&str>) =
        (A_BEFORE.split('¦').collect(), A_AFTER.split('¦').collect());
    (0..n as u64)
        .map(|i| {
            let key = form(&any_key(rng.next(), i), rng.next());
            let joint = rng.pick(&["", "\n", "\r\n", "\t", " ", ". "]);
            let frame = rng.pick(&frames).replace("{}", &key);
            format!("{}{joint}{frame}{}", rng.pick(&before), rng.pick(&after))
        })
        .collect()
}

/// Pass A's URL tails: a value glued (or one break) before a URL holding one or
/// two keys in some form, in a wrapper, then prose.
fn url_family(seed: u64, n: usize) -> Vec<String> {
    let mut rng = Rng(seed);
    let (before, after): (Vec<&str>, Vec<&str>) =
        (A_BEFORE.split('¦').collect(), A_AFTER.split('¦').collect());
    let kinds = [5, 8, 9, 10, 7, 0, 1, 3];
    let wraps = [
        "{}",
        "[docs]({})",
        "<{}>",
        "\"{}\"",
        "'{}'",
        "`{}`",
        "see {}",
    ];
    (0..n as u64)
        .map(|i| {
            let mut key = || {
                let k = any_key(kinds[(rng.next() % 8) as usize], i + rng.next() % 97);
                form(&k, [0, 1, 2, 9][(rng.next() % 4) as usize])
            };
            let (a, b) = (key(), key());
            let url = match rng.next() % 6 {
                0 => format!("https://api.example.test/v1/x?key={a}&alt=json"),
                1 => format!("https://api.example.test/v1/x?key={a}&token={b}&alt=json"),
                2 => format!("https://api.example.test/v1/x?key={a}#frag"),
                3 => format!("https://api.example.test/v1/{a}/x?alt=json"),
                4 => format!("https://api.example.test/v1/x?q=1&amp;key={a}&amp;alt=json"),
                _ => format!("https://api.example.test/v1/x?alt=json&key={a}"),
            };
            format!(
                "{}{}{}{}",
                rng.pick(&before),
                rng.pick(&["", "", "\n", "\r\n", " "]),
                rng.pick(&wraps).replace("{}", &url),
                rng.pick(&after)
            )
        })
        .collect()
}

/// Pass B's probes: a value glued before a URL with an IDN, punycode or port
/// host and a multibyte path, keys in seven shapes, then tails and endings with
/// NBSP, U+3000 and other non-ASCII characters.
fn nbsp_family(seed: u64, n: usize) -> Vec<String> {
    let mut rng = Rng(seed);
    let before = [
        "IBAN FR76 3000 6000 0112 3456 7890 189",
        "+44 20 7946 0958",
        "lena.ortiz@example.org",
        "AB 12 34 56 C",
        "",
    ];
    let hosts = [
        "a.example.test:8443",
        "xn--bcher-kva.example",
        "bücher.example",
        "例え.テスト",
    ];
    let paths = ["/", "/café/", "/日本/x/", "/v1/"];
    let tails = "&x=1¦&amp;alt=json¦&x=1\u{a0}next¦&x=1\u{3000}after¦\u{a0}next¦\u{3000}after¦\
        #frag¦/v2/x?alt=json¦&uid=42&amp;v=3¦&session=7f3a9c1e2b¦&x=é¦&q=日本¦&x=1\u{2028}x¦\
        &x=1\u{200b}y¦&x=１¦&x=1\u{a0}\u{a0}y¦&x=a\u{3000}日¦&x=1 \u{a0}b¦";
    let tails: Vec<&str> = tails.split('¦').collect();
    let ends = [
        "",
        "\r\n",
        "\n",
        " end",
        "\u{3000}after\r\n",
        ".",
        "+44 20 7946 0958",
    ];
    (0..n as u64)
        .map(|i| {
            let (a, b) = (any_key(rng.next(), i), any_key(rng.next(), i + 1));
            let key = match rng.next() % 7 {
                0 => escaped(&a),
                1 => a,
                2 => format!("{a}&k2={}", escaped(&b)),
                3 => format!("{}{b}", escaped(&a)),
                4 => ya29(i, true),
                5 => escaped(&ya29(i, true)),
                _ => escaped(&xoxb(i)),
            };
            format!(
                "{}https://{}{}?key={key}{}{}",
                rng.pick(&before),
                rng.pick(&hosts),
                rng.pick(&paths),
                rng.pick(&tails),
                rng.pick(&ends)
            )
        })
        .collect()
}

/// Pass A's round-1 repros: a key only the new rules read lost the run to the
/// end of its line that main's residue round gave it (K-GOOGLE-KEY round 2).
fn line_run_repros() -> Vec<String> {
    let jwt = escaped(&any_key(10, 3));
    let long = alnum(11, 59);
    vec![
        format!(
            "4111 1111 1111 1111https://api.example.test/v1/x?key=ya{}.c.{}-{}.{}_{}&token={}\
             &alt=json then call me",
            "29",
            alnum(1, 40),
            alnum(2, 20),
            alnum(3, 20),
            alnum(4, 8),
            ghp(5)
        ),
        format!(
            "IBAN FR76 3000 6000 0112 3456 7890 189https://api.example.test/v1/x?key={}\
             &token={}&alt=json; see you",
            escaped(&any_key(8, 6)),
            escaped(&any_key(9, 7))
        ),
        format!(
            "NI AB 12 34 56 C\ntoken=xo{}\\-1123456789012\\-223456789\r\n0123\\-{}\t\
             call +44 20 7946 0958",
            "xb",
            alnum(8, 24)
        ),
        format!(
            "API_KEY={}\n{}card 4111 1111 1111 1111 exp 09/29token={}",
            &jwt[..40],
            &jwt[40..],
            ghp(9)
        ),
        format!(
            "token=github\\_pat\\_{}\\_{}\n{}KNI number QQ 12 34 56 C",
            alnum(10, 22),
            &long[..30],
            &long[30..]
        ),
        format!(
            "key=ya{}.c.{}\\-e\r\n{}.{}\\_{} NI number QQ 12 34 56 C",
            "29",
            alnum(12, 40),
            alnum(13, 20),
            alnum(14, 20),
            alnum(15, 8)
        ),
    ]
}

fn inputs() -> Vec<String> {
    let mut out = seeded();
    out.extend(
        url_tail_cases(0x5552_4C54_4149_4C31, 1_200)
            .into_iter()
            .map(|c| c.0),
    );
    out.extend(positives().into_iter().map(|(text, _)| text));
    out.extend(negatives());
    // K-GOOGLE-KEY round 2: pass A's and pass B's families, 1,306 more texts.
    out.extend(line_run_repros());
    out.extend(mixed_cases(0x4D49_5845_4432, 400));
    out.extend(url_family(0x5552_4C46_414D, 450));
    out.extend(nbsp_family(0x4E42_5350_4632, 450));
    out
}

/// `output` with each minted token replaced by its surface.
fn restore(output: &str, minted: &[(String, String)]) -> String {
    let mut restored = output.to_string();
    for (token, surface) in minted {
        restored = restored.replace(&format!("⟦{token}⟧"), surface);
    }
    restored
}

#[test]
fn google_keys_are_hidden_in_both_modes() {
    let mut wrong = Vec::new();
    let all = positives();
    for (text, value) in &all {
        let start = text.rfind(value.as_str()).expect("value in text");
        for mode in MODES {
            let now = exact(mode, text);
            if !covered(&parse(&now), start, start + value.len()) {
                wrong.push(format!("{mode:?} {text:?}: {now}"));
            }
        }
        let (output, minted) = issue(PrivacyMode::Private, text).expect("issued");
        if restore(&output, &minted) != *text {
            wrong.push(format!("restore {text:?} -> {output:?}"));
        }
    }
    assert!(all.len() >= 1_000, "1,000+ positives: {}", all.len());
    let shown: Vec<&String> = wrong.iter().take(40).collect();
    assert!(wrong.is_empty(), "{} wrong:\n{shown:#?}", wrong.len());
}

/// Pass A's repro family: the key is hidden in both modes, and in Private a URL
/// masked up to the key is masked past it to the end of its query tail. Main
/// masks the whole URL as one value; the escaped key's own token must not cut
/// the URL and leave `&amp;alt=json` or `&session=…` in clear.
#[test]
fn escaped_key_keeps_its_url_tail_masked() {
    let mut wrong = Vec::new();
    let cases = url_tail_cases(0x7461_696C_5F72_6570, 400);
    for (text, url, key, key_end, end) in &cases {
        for mode in MODES {
            let now = exact(mode, text);
            let r = parse(&now);
            let head_masked = covered(&r, *url, *key);
            if !covered(&r, *key, *key_end) || (head_masked && !covered(&r, *key_end, *end)) {
                wrong.push(format!("{mode:?} {text:?}: {now}"));
            }
        }
    }
    let shown: Vec<&String> = wrong.iter().take(20).collect();
    assert!(wrong.is_empty(), "{} wrong:\n{shown:#?}", wrong.len());
}

fn parse(record: &str) -> Vec<(usize, usize)> {
    record
        .split(',')
        .filter_map(|r| r.split_once('-'))
        .map(|(s, e)| (s.parse().unwrap(), e.parse().unwrap()))
        .collect()
}

/// The input count and an FNV-1a hash of every input.
fn header(inputs: &[String]) -> String {
    let bytes = inputs.iter().flat_map(|text| text.bytes().chain([0]));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{} {hash}", inputs.len())
}

fn frozen() -> Vec<(String, Vec<String>)> {
    let inputs = inputs();
    let (head, body) = FIXTURE.split_once('\n').expect("fixture header");
    assert_eq!(head, header(&inputs), "inputs changed: refreeze on main");
    let records: Vec<&str> = body.trim().split_terminator(';').map(str::trim).collect();
    assert_eq!(records.len(), inputs.len());
    let split = |r: &str| r.split('|').map(String::from).collect();
    inputs
        .into_iter()
        .zip(records.into_iter().map(split))
        .collect()
}

#[test]
#[ignore = "freezes the main fixture: run on origin/main only"]
fn freeze() {
    let inputs = inputs();
    let each = |text: &String| MODES.map(|mode| exact(mode, text)).join("|");
    let records: Vec<String> = inputs.iter().map(each).collect();
    let lines: Vec<String> = records.chunks(64).map(|c| c.join(";") + ";").collect();
    println!(
        "FIXTURE-BEGIN\n{}\n{}\nFIXTURE-END",
        header(&inputs),
        lines.join("\n")
    );
}

/// A strict byte superset of main in both modes: no byte main masked is clear,
/// no new refusal, every output reads back exactly, and no look-alike changes.
#[test]
fn strict_superset_of_main_in_both_modes() {
    let main = frozen();
    let negatives = negatives();
    let (mut lost, mut refused, mut unaligned, mut grew) = ([0usize; 2], 0, 0, [0usize; 2]);
    let mut lookalikes = 0;
    for (text, records) in &main {
        for (index, mode) in MODES.into_iter().enumerate() {
            let before = records[index].as_str();
            let now = exact(mode, text);
            if now == "?" || before == "?" {
                unaligned += 1;
                eprintln!("unaligned {mode:?} {text:?}: main {before} now {now}");
            } else if now == "!" {
                refused += usize::from(before != "!");
            } else {
                let r = parse(&now);
                let gone = parse(before)
                    .iter()
                    .flat_map(|&(s, e)| s..e)
                    .filter(|&b| !covered(&r, b, b + 1))
                    .count();
                let lookalike = now != before && negatives.contains(text);
                if gone > 0 || lookalike {
                    eprintln!("{mode:?} {text:?}: main {before} now {now}");
                }
                lost[index] += gone;
                grew[index] += usize::from(now != before);
                lookalikes += usize::from(lookalike);
            }
        }
    }
    eprintln!(
        "{} inputs: bytes lost Private/Open {lost:?}; new refusals {refused}; unaligned \
         {unaligned}; texts with new masks Private/Open {grew:?}; look-alikes changed {lookalikes}",
        main.len()
    );
    assert!(main.len() >= 1_600);
    assert_eq!((lost, refused, unaligned, lookalikes), ([0, 0], 0, 0, 0));
}

/// Release only: key-dense text through both gates at 16 KiB, 64 KiB, 256 KiB
/// and 1 MiB, best of three. Bar: each 4x step at most 6x. A debug build skips.
#[test]
#[ignore = "release timing: cargo test --release --test google_key -- --ignored dense --nocapture"]
fn dense_keys_scale_linearly() {
    if cfg!(debug_assertions) {
        return;
    }
    const IBAN: &str = "IBAN FR76 3000 6000 0112 3456 7890 189";
    let many: String = (0..20).map(|i| format!("k={}&a=1&", ghp(i))).collect();
    // `(unit, mode, a part of the unit that must not come out in clear)`. Each
    // part is masked only by the path the unit times: `a=1` and `next` only by
    // `url_tails` (a plain key cuts the residue URL), `call me` and ` x ` only
    // by the run to the end of the line (K-GOOGLE-KEY round 2).
    let units = [
        (
            format!("AB 12 34 56\n{} {}\n", gkey(1), escaped(&gkey(2))),
            None,
        ),
        (
            format!("{}\\_{} ", ya29(3, true), escaped(&gocspx(4))),
            None,
        ),
        (format!("{}.", "a\\_b\\-".repeat(40)), None),
        (
            format!("{IBAN}https://a.example.test/x?{many}\n"),
            Some((MODES[0], "a=1")),
        ),
        (
            format!(
                "{IBAN}https://a.example.test/x?k={}&x=1\u{a0}next\n",
                ghp(30)
            ),
            Some((MODES[0], "next")),
        ),
        (
            format!("{} then call me\n", escaped(&gkey(5))),
            Some((MODES[1], "call me")),
        ),
        (
            format!("{} then call me\n", ya29(6, true)),
            Some((MODES[1], "call me")),
        ),
        (format!("{} x ", escaped(&xoxb(7))), Some((MODES[1], " x "))),
    ];
    for (unit, part) in units {
        if let Some((mode, part)) = part {
            let (output, _) = issue(mode, &unit.repeat(3)).expect("issued");
            assert!(
                unit.contains(part) && !output.contains(part),
                "{mode:?} {output:?}"
            );
        }
        let mut last = 0.0;
        for size in [16_384usize, 65_536, 262_144, 1_048_576] {
            let text = unit.repeat(size / unit.len() + 1);
            let mut best = f64::MAX;
            for _ in 0..3 {
                let start = Instant::now();
                for mode in MODES {
                    let _ = issue(mode, &text);
                }
                best = best.min(start.elapsed().as_secs_f64());
            }
            let ratio = if last == 0.0 { 0.0 } else { best / last };
            eprintln!("{size} bytes: {best:.3}s ratio {ratio:.2}");
            assert!(ratio <= 6.0, "{size} bytes scales {ratio:.2}");
            last = best;
        }
    }
}
