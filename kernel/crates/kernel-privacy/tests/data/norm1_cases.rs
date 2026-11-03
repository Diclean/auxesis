// NORM-1 cases and gate helpers, shared by `norm1_lookalikes.rs` and
// `norm1_superset.rs`. All values are invented: the FR and ES IBANs and the
// 4111… card are the public specimens, the AWS key is the AWS documentation example.

include!("exact_mask.rs");

use kernel_core::privacy::{admit, Context, Decision, Destination, PathId, PrivacyMode};
use kernel_privacy::Gate;

pub const MODES: [PrivacyMode; 2] = [PrivacyMode::Private, PrivacyMode::Open];

/// The gate's output and the `(token, surface)` pairs it minted, or `None` for
/// a refusal.
pub fn issue(mode: PrivacyMode, input: &str) -> Option<(String, Vec<(String, String)>)> {
    let ctx = Context {
        destination: Destination::Vendor("hosted-model".to_string()),
    };
    let Decision::Allow(grant) = admit(PathId::A1, mode, &ctx) else {
        panic!("A1 must be allowed in {mode:?}");
    };
    let mut gate = Gate::for_grant(&grant, [9u8; 32]);
    let output = gate.text(input).ok()?.0.as_str().to_string();
    Some((output, gate.take_minted()))
}

/// The exact byte ranges of `input` a gate in `mode` replaced, or `None` for a
/// refusal.
///
/// The alignment is exact (TEST-FITS-EXACT, `exact_mask.rs`): an output that
/// does not read back onto `input` panics here rather than come back as one
/// reading that hides fewer bytes than the gate masked.
pub fn masked(mode: PrivacyMode, input: &str) -> Option<Vec<(usize, usize)>> {
    let (output, minted) = issue(mode, input)?;
    Some(exact_or_fail(mode, input, &output, &minted))
}

pub fn covered(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    (start..end).all(|byte| ranges.iter().any(|&(s, e)| s <= byte && byte < e))
}

/// `text` with ASCII digits and letters in the full-width block.
pub fn wide(text: &str) -> String {
    let shift = |ch: char| char::from_u32(ch as u32 + 0xFEE0).unwrap();
    text.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { shift(ch) } else { ch })
        .collect()
}

/// `text` in mathematical bold (U+1D400 letters, U+1D7CE digits).
pub fn bold(text: &str) -> String {
    let at = |base: u32, from: char, ch: char| char::from_u32(base + ch as u32 - from as u32);
    text.chars()
        .map(|ch| match ch {
            'A'..='Z' => at(0x1D400, 'A', ch).unwrap(),
            'a'..='z' => at(0x1D41A, 'a', ch).unwrap(),
            '0'..='9' => at(0x1D7CE, '0', ch).unwrap(),
            _ => ch,
        })
        .collect()
}

/// (text, the value inside it, whether Open must remove it too). Open leaves
/// e-mails and phones in clear by design, so only Private covers them.
pub fn repros() -> Vec<(String, String, bool)> {
    let mut out: Vec<(String, String, bool)> = Vec::new();
    let mut add = |frame: &str, value: String, open: bool| {
        out.push((frame.replace("{}", &value), value, open));
    };
    // The work order's repros.
    add("mail {} now", "ali\u{200B}ce@example.org".into(), false);
    add("IBAN {}", wide("FR76 3000 6000 0112 3456 7890 189"), true);
    add("key {} here", "AKIAIOSFOD\u{AD}NN7EXAMPLE".into(), true);
    add("call {} today", "+33 6\u{A0}12\u{2007}34 56 78".into(), false);
    add("card {}", bold("4111 1111 1111 1111"), true);
    add("mail {}", "jean.dupont@gmail.c\u{43E}m".into(), false);
    // Leaks found on main: a Unicode space inside a word or key.
    add("I have {}", "dia\u{A0}betes".into(), true);
    add("I have {}", "diabe\u{202F}tes".into(), true);
    add("key {}", "sk-proj-abcdefgh\u{A0}ijklmnopqrstuvwx".into(), true);
    add("key {}", "sk-proj-abcdefgh\u{2007}ijklmnopqrstuvwx".into(), true);
    add("key {}", "sk-proj-abcdefgh\u{3000}ijklmnopqrstuvwx".into(), true);
    // Cyrillic and Greek look-alikes in a key, a health word, a label, an IBAN.
    add("key {}", "sk-pr\u{43E}j-abcdefghijklmnopqrstuvwx".into(), true);
    add("key {}", "\u{455}k-proj-abcdefghijklmnopqrstuvwx".into(), true);
    add("key {}", "AKI\u{410}IOSFODNN7EXAMPLE".into(), true);
    add("token {}", "ghp_\u{3BF}B3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A7".into(), true);
    add("I have {}", "di\u{430}betes".into(), true);
    add("p\u{430}ssword: {}", "Sunflower2025".into(), true);
    add("IBAN {}", "\u{415}S91 2100 0418 4502 0005 1332".into(), true);
    add("IBAN {}", "\u{415}S91\u{200B}2100\u{A0}0418 4502 0005 1332".into(), true);
    add("mail {}", "ali\u{441}e@ex\u{3B1}mple.org".into(), false);
    // Mathematical letters in a key and a label.
    add("key {}", bold("AKIAIOSFODNN7EXAMPLE"), true);
    add(&format!("{}: {{}}", bold("password")), "Sunflower2025".into(), true);
    out
}

/// Chinese prose with full-width punctuation, digits and spaces, and Cyrillic
/// prose: no value in any line, so nothing may be masked.
pub const ZH_PROSE: &[&str] = &[
    "今天天气很好，我们去公园散步吧！",
    "会议改到下午３点，请准时参加。",
    "注意：本周五（１０月２４日）放假一天。",
    "价格：１２０元／件，库存还有４５件。",
    "他说：“明天见！”然后就走了。",
    "第１章　总则　第２章　细则",
    "请把文件放在３号柜子里，谢谢。",
    "２０２６年１０月，项目进入第二阶段；预算增加１５％。",
    "问题：为什么？答案：因为下雨了。",
    "ＣＰＵ占用率是８５％，内存还剩２ＧＢ。",
    "我们的目标是：质量第一，客户至上。",
    "这本书一共有３００页，我已经读了一半。",
];

pub const CYRILLIC_PROSE: &[&str] = &[
    "Привет, как дела? Это обычный текст о погоде.",
    "Сегодня сосед купил хорошее масло и сыр.",
    "Москва, 2026 год: встреча в офисе на третьем этаже.",
    "Ответ: всё хорошо, спасибо за помощь!",
    "Η ομάδα θα συναντηθεί αύριο το πρωί στο γραφείο.",
];
