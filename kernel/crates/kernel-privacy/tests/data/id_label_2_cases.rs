// ID-LABEL-2 cases: the forms main leaves clear today, each in the frame that
// leaks it. Every value is built at run time from parts by the seeded [`Rng`]
// this file includes, so no complete licence, passport or driving-licence
// number is written out anywhere: the file holds labels, shapes and prose only.
//
// Frames read `{}` as the value. The five families are the work order's: the FR
// `numéro de permis de conduire` label with its variants, a lower-case UK licence
// after `licence`/`license`, a licence grouped over a dash or a line break after
// its label, a spaced CN passport, and a snake_case key with the value in
// parentheses.

include!("id_label_cases.rs");

/// The FR driving licence number: two digits, two letters and five digits, or
/// the old twelve-digit form.
pub fn fr_permis(rng: &mut Rng) -> String {
    if rng.below(2) == 0 {
        let head = rng.digits(2);
        let mid = rng.letters(2);
        let tail = rng.digits(5);
        format!("{head}{mid}{tail}")
    } else {
        rng.digits(12)
    }
}

/// A UK driving licence in the case and the grouping the frame asks for:
/// `lower` writes it all lower case, `dash` groups it 5-6-5 over `-`, `brk`
/// breaks the line after the surname instead.
pub fn uk_grouped(rng: &mut Rng, lower: bool, dash: bool, brk: bool) -> String {
    let code = uk_licence(rng);
    let (surname, rest) = code.split_at(5);
    let (digits, initials) = rest.split_at(6);
    let mut value = match (dash, brk) {
        (true, _) => format!("{surname}-{digits}-{initials}"),
        (_, true) => format!("{surname}\n{digits}-{initials}"),
        _ => format!("{surname} {digits} {initials}"),
    };
    if lower {
        value = value.to_lowercase();
    }
    value
}

/// A CN passport number written spaced: `E` or `EA`, then two groups of four
/// digits (`E 1234 5678`).
pub fn cn_spaced(rng: &mut Rng, two_letters: bool) -> String {
    let extra = if two_letters {
        rng.letters(1)
    } else {
        String::new()
    };
    let first = rng.digits(4);
    let second = rng.digits(4);
    format!("E{extra} {first} {second}")
}

/// A state-shaped licence number for the parenthesised snake_case key: one
/// letter, then groups of two, four, four and two digits.
pub fn paren_licence(rng: &mut Rng) -> String {
    let letter = rng.letters(1);
    let a = rng.digits(2);
    let b = rng.digits(4);
    let c = rng.digits(4);
    let d = rng.digits(2);
    format!("{letter}-{a}-{b}-{c}-{d}")
}

/// A short value glued to a number sign: three or four alphanumerics behind
/// `no`, `NO`, `No` or one of the typographic signs (ID-LABEL-2 round 1, F1).
/// It is short enough that the sign's own two letters decide whether the value
/// reaches the minimum length, which is exactly what main read.
pub fn glued_short(rng: &mut Rng, sign: &str) -> String {
    let n = 3 + rng.below(2);
    let body = match rng.below(3) {
        0 => rng.digits(n),
        1 => rng.mixed(n + 1),
        _ => format!("{}{}", rng.letters(1), rng.digits(n)),
    };
    format!("{sign}{body}")
}

/// A secret value for a `(` after a secret label: six lower-case letters, a
/// dash, six digits and one letter (ID-LABEL-2 round 1, F2).
pub fn secret_paren(rng: &mut Rng) -> String {
    format!(
        "{}-{}{}",
        rng.letters(6).to_lowercase(),
        rng.digits(6),
        rng.letters(1).to_lowercase()
    )
}

/// The signs a short value is glued to: the two ASCII ones main reads as two
/// alphanumerics of the value, and the typographic ones only the fallback reads
/// past (`n°`, `nº`). `Nº` is left out on purpose: its two-letter reading opens
/// the line after the value, so it only ever lands beside a `\n\n`, where the
/// mask that follows lands a byte further out in the head than in main.
pub const GLUED_SIGNS: &[&str] = &["no", "NO", "No", "n°", "N°", "nº"];

/// Frames a short glued value leaks in: ID, health, member and tax labels.
pub const GLUED_FRAMES: &[&str] = &[
    "Tax ID: {}",
    "tax id {}",
    "Steuer-ID {}",
    "TIN: {}",
    "CNI {}",
    "passport: {}",
    "passport no {}",
    "NHS number: {}",
    "medical record number: {}",
    "member ID {} at the health insurer",
    "N° de permis de conduire {}",
];

/// Secret labels and a value in parentheses: `(` is decoration for an ID or a
/// health label only, so behind these it is the first byte of the value, on main
/// and on the head alike.
pub const SECRET_PAREN_FRAMES: &[&str] = &[
    "api_key ({})",
    "api_key\t({})",
    "api_key: ({})",
    "password ({})",
    "password: ({})",
    "secret key ({})",
    "access token ({})",
    "api_key ({})\r\nand the line goes on",
];

/// The label frames of the FR driving licence. Three of the leaks live here:
/// `numero de permis` swallows `numero de permis de conduire` whole and leaves
/// `de conduire` in front of the value, a value may sit with no blank before `:`
/// (`:` is a link, so this one holds), and it may be glued to the `n°` number
/// word.
pub const FR_FRAMES: &[&str] = &[
    "Numéro de permis de conduire : {}",
    "Numéro de permis de conduire:{}",
    "Numéro de permis de conduire :\n{}",
    "numéro de permis de conduire n°{}",
    "numéro de permis de conduire n° {}",
    "N° de permis de conduire : {}",
    "N° de permis n°{}",
    "numéro de permis : {}",
    "N° de permis : {}",
    "numéro de permis n°{}",
    "mon Numéro de Permis de Conduire : {}",
    "NUMERO DE PERMIS DE CONDUIRE : {}",
    "Permis de conduire : {}",
    "Permis de conduire:{}",
];

/// A lower-case UK licence after its `licence`/`license` label.
pub const UK_LOWER_FRAMES: &[&str] = &[
    "licence {}",
    "license {}",
    "licence: {}",
    "license: {}",
    "his licence number is {}.",
    "his license number is {}.",
    "licence number: {}",
    "license number: {}",
    "license_number: {}",
    "licence\n{}",
    "Driving licence {}",
    "driver license {}",
];

/// A licence grouped over a dash or a line break, after its label.
pub const UK_GROUPED_FRAMES: &[&str] = &[
    "licence {}",
    "licence number {}",
    "license: {}",
    "Driving licence {}",
    "driver licence {}",
    "Driving licence\n{}",
    "Driving licence\r\n{}",
    "driver licence number ({})",
    "Driving licence: {}",
];

/// A spaced CN passport number after a passport label, JSON frames included:
/// the acceptance reads the shape a form posts as well as the one it prints.
pub const CN_SPACED_FRAMES: &[&str] = &[
    "护照号：{}",
    "护照号码：{}",
    "护照号: {}",
    "passport no: {}",
    "passport number is {}",
    "a passport of {}",
    "Passport: {}",
    "passport number: {}",
    "{\"passport_number\": \"{}\"}",
    "{\"passportNo\": \"{}\"}",
    "{\"passport\": \"{}\"}",
];

/// A snake_case key and its value in parentheses. The JSON frames are written
/// with real braces: `String::replace` is not `format!`, so `{{` would reach the
/// text as two braces.
pub const SNAKE_FRAMES: &[&str] = &[
    "driver_license_number ({})",
    "driving_license_number ({})",
    "driver_licence_number ({})",
    "{\"driver_license_number\": \"({})\"}",
    "{\"driving_license_number\": \"({})\"}",
    "driver_license_number: ({})",
    "driver license number ({})",
];

/// Every positive of ID-LABEL-2, built from the frames above: `(text, value)`.
pub fn labelled_positives() -> Vec<(String, String)> {
    let mut rng = Rng(SEED ^ 0x2ED1_AB2E);
    let mut out: Vec<(String, String)> = Vec::new();
    let add = |out: &mut Vec<(String, String)>, frame: &str, value: String| {
        out.push((frame.replace("{}", &value), value));
    };
    for frame in FR_FRAMES {
        for _ in 0..2 {
            let value = fr_permis(&mut rng);
            add(&mut out, frame, value);
        }
    }
    for frame in UK_LOWER_FRAMES {
        let value = uk_grouped(&mut rng, true, false, false);
        add(&mut out, frame, value);
    }
    for frame in UK_GROUPED_FRAMES {
        for dash in [true, false] {
            let value = uk_grouped(&mut rng, false, dash, !dash);
            add(&mut out, frame, value);
        }
    }
    for frame in CN_SPACED_FRAMES {
        for _ in 0..2 {
            let value = cn_spaced(&mut rng, false);
            add(&mut out, frame, value);
        }
    }
    for frame in SNAKE_FRAMES {
        for _ in 0..2 {
            let value = paren_licence(&mut rng);
            add(&mut out, frame, value);
        }
    }
    out
}

/// Lookalikes (`LOOKALIKES`): prose that holds a label and no identity, a date
/// or a version under an ID label, a label inside a key or a path, and a value
/// of another class under an ID label. Each keeps exactly the masks main gives
/// it, in both modes.
pub const LOOKALIKES: &[&str] = &[
    // Bare words after the labels.
    "permis de conduire valide",
    "mon permis est valide jusqu'en 2030",
    "licence valid",
    "the licence and the permit are separate",
    "licence fee of 159 pounds",
    "license agreement v2.3",
    "MIT license, version 2.0",
    "open source license: Apache-2.0",
    "the licence number field is empty",
    "licence number is on file",
    "driver licence renewal in October",
    "Numéro de permis de conduire à renouveler",
    "N° de permis : à préciser",
    "numéro de permis de conduire inconnu",
    "driver_license_number is empty",
    "driving licence renewal forms are online",
    "licence_agreement_v2.3",
    "portal/licence-check",
    "certificate_license",
    "Permis de conduire expiré",
    // Dates and versions under ID keys.
    "licence: 2024-10-01",
    "licence: 2024/10/01",
    "licence number: 2024-10-01",
    "the licence was valid from 2024-10-01",
    "version 1.2.3",
    "licence: 1.2.3",
    "licence v2.0",
    "Permis de construire n° PC0751232400017",
    "driver version 535.104.05",
    "the CNIL fined them last year",
    "passport no: to be confirmed",
    // Values of another class: main masks what it masks, and never less.
    "NIR 1 84 12 76 451 089 46",
    "NI number QQ 12 34 56 C",
    "IBAN FR76 3000 6000 0112 3456 7890 189",
    "card 4111 1111 1111 1111 exp 09/29",
    "mail jo.pell@example.org",
    "call +33 6 12 34 56 78",
    "passport_photo_v2.jpg",
    "passport_20240301.pdf",
    "scan_passport_L898902C3.pdf",
    "order_A7K29Q4M1.pdf",
    "Booking reference: EA1234567",
    "Serial: WILLI861205JD9AB",
    "SKU MORGA753116SM9IJ in stock",
    "Product code SMITH802115J99RT",
    "Batch MORGA753116SM9IJ shipped",
    "Ref: PATEL907244AR9CK",
    // Round 1, F1: a short value glued to a sign. Main read the sign's letters
    // as two of the value's alphanumerics, so every one of these keeps exactly
    // main's mask; the head may not count the value alone (`no1234` is five of
    // them, not three).
    "Tax ID: NO1234",
    "Tax ID: no1234",
    "tax id no1234",
    "TIN: no1234",
    "Steuer-ID no1234",
    "CNI no1234",
    "passport: no1234",
    "passport no1234",
    "passport NO123",
    "passport no123",
    "NHS number: no123",
    "NHS number: no12",
    "medical record number: No123",
    "medical record number no123",
    "member ID no123 at the health insurer",
    "Driving Licence No. NO3967",
    "{\"passport_no\": \"no175\"}",
    "permis de conduire n°\tNO2846",
    // Round 1, F2: `(` is decoration for an ID or a health label only. Behind a
    // secret label it is the first byte of the value, so the head keeps main's
    // mask here — `(` included, and `[secret removed]` still a marker.
    "api_key (smith-404135-zt7jh)",
    "api_key (smith\r\n404135-zt7jh",
    "api_key\t(JQA028344)",
    "password (hunter22)",
    "password: (Lantern#2291)",
    "secret key (sk-9f2b-11ac)",
    "access token (eyJhbGciOi.eyJzdWIi.s1n)",
    "api_key ([secret removed])",
    "password ([secret removed])",
    // Round 1: a spaced CN passport is read behind a passport label only, so a
    // tax, a CNI or a licence label does not claim that shape.
    "tax id: E 1234 5678",
    "Tax ID: E 1234 5678",
    "CNI: E 1234 5678",
    "licence number: E 1234 5678",
    "driver licence number: E 1234 5678",
];

/// Separators between the pieces of a differential text, LF and CRLF included.
pub const JOINS: &[&str] = &[
    " ", "\n", "\r\n", "\t", ". ", " | ", ", ", "; ", "\n\n", "\n  ",
];

/// One differential text of ID-LABEL-2: 1 to 4 pieces, each a form this work
/// order adds, a value of another class, or a lookalike; and the byte ranges of
/// the values it holds.
pub fn seeded_text(rng: &mut Rng) -> (String, Vec<(usize, usize)>) {
    let (mut text, mut values) = (String::new(), Vec::new());
    // `read` says the piece holds a value both modes must cover: every form
    // this work order adds, and a short glued value behind a two-letter sign.
    let mut framed = |text: &mut String, frame: &str, value: &str, read: bool| {
        let start = text.len() + frame.find("{}").expect("a frame holds {}");
        text.push_str(&frame.replace("{}", value));
        if read {
            values.push((start, start + value.len()));
        }
    };
    for at in 0..1 + rng.below(4) {
        if at > 0 {
            text.push_str(rng.pick(JOINS));
        }
        match rng.below(11) {
            0 => {
                let value = fr_permis(rng);
                let frame = rng.pick(FR_FRAMES);
                framed(&mut text, frame, &value, true);
            }
            1 => {
                let value = uk_grouped(rng, true, false, false);
                let frame = rng.pick(UK_LOWER_FRAMES);
                framed(&mut text, frame, &value, true);
            }
            2 => {
                let dash = rng.below(2) == 0;
                let value = uk_grouped(rng, false, dash, !dash);
                let frame = rng.pick(UK_GROUPED_FRAMES);
                framed(&mut text, frame, &value, true);
            }
            3 => {
                let two = rng.below(3) == 0;
                let value = cn_spaced(rng, two);
                let frame = rng.pick(CN_SPACED_FRAMES);
                framed(&mut text, frame, &value, true);
            }
            4 => {
                let value = paren_licence(rng);
                let frame = rng.pick(SNAKE_FRAMES);
                framed(&mut text, frame, &value, true);
            }
            5 => {
                // Only a two-letter sign holds a value both modes must cover;
                // `n°1234` is below the minimum length however it is read.
                let sign = rng.pick(GLUED_SIGNS);
                let value = glued_short(rng, sign);
                let frame = rng.pick(GLUED_FRAMES);
                let read = sign.bytes().all(|b| b.is_ascii_alphanumeric());
                framed(&mut text, frame, &value, read);
            }
            6 => {
                let value = secret_paren(rng);
                let frame = rng.pick(SECRET_PAREN_FRAMES);
                framed(&mut text, frame, &value, true);
            }
            7..=8 => text.push_str(rng.pick(OTHERS)),
            _ => text.push_str(rng.pick(LOOKALIKES)),
        }
    }
    (text, values)
}

/// How many seeded texts the differential runs.
pub const SEEDED_TEXTS: usize = 1600;

/// One round-1 regression text: 1 to 3 pieces, each a short value glued to a
/// number sign behind an ID, health, member or tax label (F1), or a secret label
/// whose value is in parentheses (F2).
///
/// The byte ranges it returns are the values both modes must cover: a secret
/// behind a `(` whole, and a value behind a two-letter sign whole, because main
/// read both of those and the head must not leave a byte of them. A value
/// behind a typographic sign is left out — `n°1234` is below the minimum length
/// however it is read, so no mode owes it a mask.
pub fn round1_text(rng: &mut Rng) -> (String, Vec<(usize, usize)>) {
    let (mut text, mut values) = (String::new(), Vec::new());
    for at in 0..1 + rng.below(3) {
        if at > 0 {
            text.push_str(rng.pick(JOINS));
        }
        let (frame, value, read) = if rng.below(2) == 0 {
            (rng.pick(SECRET_PAREN_FRAMES), secret_paren(rng), true)
        } else {
            let sign = rng.pick(GLUED_SIGNS);
            let read = sign.bytes().all(|b| b.is_ascii_alphanumeric());
            (rng.pick(GLUED_FRAMES), glued_short(rng, sign), read)
        };
        let start = text.len() + frame.find("{}").expect("a frame holds {}");
        text.push_str(&frame.replace("{}", &value));
        if read {
            values.push((start, start + value.len()));
        }
    }
    (text, values)
}

/// How many round-1 regression texts the differential runs, 500 by the work
/// order and 600 here: 1 to 3 pieces each, so most of them hold a glued short
/// value, a `(` after a secret label, or both.
pub const ROUND1_TEXTS: usize = 600;
