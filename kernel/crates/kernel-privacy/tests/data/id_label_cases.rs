// ID-LABEL cases: labelled national IDs, driving licences, tax numbers and IDs
// inside file names. Every value is invented: none is copied from a public
// corpus. The FR IBAN and the 4111… card are the public specimens, the AWS key
// is the AWS documentation example.

/// `(text, value)`: an ID after its label, a UK licence by its structure, or an
/// ID inside a file name, in mail, form, chat and file-name shapes. Both modes
/// must hide every byte of the value.
pub const POSITIVES: &[(&str, &str)] = &[
    // FR carte nationale d'identité: 12 digits (old) or 9 alphanumerics (2021+).
    (
        "Bonjour,\nVoici ma CNI : 880692310285, valable jusqu'en 2031.\nCordialement",
        "880692310285",
    ),
    ("Carte nationale d'identité n° X4RTBT9M2", "X4RTBT9M2"),
    ("N° de carte d'identité : 120375501234", "120375501234"),
    ("| CNI | K7RT2PQ94 |", "K7RT2PQ94"),
    ("ma cni c'est X9PL4KR27 je crois", "X9PL4KR27"),
    ("Le numéro de ma carte d'identité est 931204501877.", "931204501877"),
    // FR permis de conduire: 2 digits, 2 letters, 5 digits, or 12 digits.
    ("Permis de conduire : 12AB34567", "12AB34567"),
    (
        "Mon permis de conduire n° 071234567890 expire en 2030.",
        "071234567890",
    ),
    ("N° de permis 19PL60432, catégorie B", "19PL60432"),
    ("- Permis : 07AK31298\n- Catégorie : B", "07AK31298"),
    ("mon permis c'est 22RT40917", "22RT40917"),
    // UK driving licence: checked by its structure, with or without a label.
    ("Driving licence: MORGA753116SM9IJ", "MORGA753116SM9IJ"),
    ("His licence number is MORGA753116SM9IJ.", "MORGA753116SM9IJ"),
    ("Driver number WILLI861205JD9AB please", "WILLI861205JD9AB"),
    ("DVLA said the licence PATEL907244AR9CK is valid.", "PATEL907244AR9CK"),
    ("Licence MA999701160AB9XY renewed", "MA999701160AB9XY"),
    ("licence: SMITH802115J99RT", "SMITH802115J99RT"),
    ("name,licence\nAda Price,PRICE752148AP9QZ\n", "PRICE752148AP9QZ"),
    ("my licence is MORGA 753116 SM9IJ", "MORGA 753116 SM9IJ"),
    ("Hi, it's JONES610089KL9MN on the card", "JONES610089KL9MN"),
    // DE Personalausweis: 9 or 10 alphanumerics.
    ("Personalausweis Nr L01X00T47", "L01X00T47"),
    ("Mein Ausweis-Nr. ist T220001293", "T220001293"),
    ("Personalausweisnummer lautet LZ6311T47", "LZ6311T47"),
    ("Dokumentennummer: CFGH12K47", "CFGH12K47"),
    ("Ausweis Nr.: M7KR1C0T52", "M7KR1C0T52"),
    // CN passport: E or EA + 7–8 digits.
    ("Passport: EA0000125", "EA0000125"),
    ("护照号：E52819034", "E52819034"),
    ("her passport number is EB7712093", "EB7712093"),
    ("Chinese passport no. E37740218 issued in Shanghai", "E37740218"),
    ("a passport of EA4471235 was scanned", "EA4471235"),
    // Tax numbers.
    ("Tax ID: 12-3456789", "12-3456789"),
    ("TIN: 123-45-6789", "123-45-6789"),
    ("The tax ID for Northwind Labs is 78-3456719.", "78-3456719"),
    ("registered with a tax ID of 98-2316704, it files", "98-2316704"),
    ("numéro fiscal : 1234567890123", "1234567890123"),
    ("Votre numéro fiscal est 3023456789012.", "3023456789012"),
    ("SSN 780711-1963 on the file", "780711-1963"),
    ("{\"taxId\": \"47-1029384\"}", "47-1029384"),
    ("<DriverLicenseNumber>R16-7038-651-14</DriverLicenseNumber>", "R16-7038-651-14"),
    ("\"passportNumber\": \"E52819034\",", "E52819034"),
    // IDs inside file names.
    ("scan_passport_L898902C3.pdf", "L898902C3"),
    ("CNI-X4RTBT9M2.jpg", "X4RTBT9M2"),
    ("Attached: permis_071234567890.png", "071234567890"),
    ("passport_12AB34567.pdf", "12AB34567"),
    ("Pièce jointe : CNI_recto_K7RT2PQ94.jpeg", "K7RT2PQ94"),
    ("uploads/2026/ausweis_T220001293.png", "T220001293"),
    ("DE_Personalausweis_LZ6311T47_front.jpg", "LZ6311T47"),
    ("File: driving-licence-PRICE752148AP9QZ.pdf", "PRICE752148AP9QZ"),
    (
        "Hi,\nmy passport scan is attached (passport_E52819034.pdf).\nBest",
        "E52819034",
    ),
    ("![](passeport-20AB71234-verso.PNG)", "20AB71234"),
];

/// Lookalikes: order, invoice and tracking numbers, SKUs and part numbers,
/// flight and booking codes, hashes, software IDs, postcodes and phones, and
/// file names with no ID word or no ID-shaped part. Each keeps exactly the
/// masks main gives it.
pub const NEGATIVES: &[&str] = &[
    "Order #A7K29Q4M1 ships Monday.",
    "Invoice INV-2026-004417 is due on 30 November.",
    "Tracking: 1Z999AA10123456784",
    "SKU MORGA753116SM9IJ in stock",
    "Part number PRT-55120-AB, qty 4",
    "Flight AF1234 departs 07:15, booking ref X4RTBT.",
    "PNR: K7QZ2M",
    "commit 9f86d081884c7d659a2feaea0c55ad015a3bf4f1",
    "sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "The user ID is 8812345 in the logs",
    "session ID a8f9c2d1e4",
    "Postcode SW1A 1AA, London",
    "75008 Paris, France",
    "Call me on +44 20 7946 0958",
    "Tél : 06 12 34 56 78",
    "report_2026-10-23.pdf",
    "IMG_20240301_101500.jpg",
    "passport_photo_v2.jpg",
    "passport-renewal-form.pdf",
    "passport_20240301.pdf",
    "Permis de construire n° PC0751232400017",
    "MIT license, version 2.0",
    "driver version 535.104.05",
    "Driver number 44 won the race",
    "the tax rate of 20.5 % applies",
    "Ausweis bitte am Eingang zeigen.",
    "Product code SMITH802115J99RT",
    "Serial: WILLI861205JD9AB",
    "Ticket ABC-123456 closed",
    "Booking reference: EA1234567",
    "Container MSCU1234565 arrived",
    "ISBN 978-2-07-036822-8",
    "the CNIL fined them last year",
    "uuid 550e8400-e29b-41d4-a716-446655440000",
    "Item ABCDE123456FG7HI",
    "MORGANSTANLEY2024 report",
    "scan_invoice_INV20240012.pdf",
    "build_artifact_L898902C3.zip",
    "order_A7K29Q4M1.pdf",
    "Customer ID C566-840-875",
    "of the 12345 orders",
    "licence fee of 159 pounds",
    "Batch MORGA753116SM9IJ shipped",
    "Ref: PATEL907244AR9CK",
    "passport.pdf and cni.jpg attached",
    "Model number WILLI861205JD9AB",
];

/// Values of other classes mixed into the differential texts.
pub const OTHERS: &[&str] = &[
    "IBAN FR76 3000 6000 0112 3456 7890 189",
    "card 4111 1111 1111 1111 exp 09/29",
    "key AKIAIOSFODNN7EXAMPLE",
    "password: Lantern#2291",
    "MRN: 7730-41925",
    "blood type AB-",
    "she has diabetes",
    "mail jo.pell@example.org",
    "call +33 6 12 34 56 78",
    "phone +44 20 7946 0958",
    "NIR 1 84 12 76 451 089 46",
    "NI number QQ 12 34 56 C",
    "SSN 078-05-1120",
    "order 55210931",
    "the meeting moved to 14:30",
];

/// Label frames: `{}` is the value. One list per value shape.
pub const CNI_FRAMES: &[&str] = &[
    "CNI : {}",
    "N° CNI: {}",
    "Carte nationale d'identité n° {}",
    "carte d'identité : {}",
    "ma cni c'est {}",
    "| CNI | {} |",
    "scan_cni_{}.pdf",
    "CNI-{}.jpg",
];
pub const PERMIS_FRAMES: &[&str] = &[
    "Permis de conduire : {}",
    "permis de conduire n° {}",
    "N° de permis {}",
    "Permis : {}",
    "permis_{}.png",
];
pub const UK_FRAMES: &[&str] = &[
    "Driving licence: {}",
    "licence number {}",
    "Driver number {}",
    "{}",
    "my licence is {}.",
    "driving-licence-{}.pdf",
];
pub const DE_FRAMES: &[&str] = &[
    "Personalausweis Nr {}",
    "Ausweis-Nr. {}",
    "Ausweisnummer: {}",
    "Dokumentennummer: {}",
    "ausweis_{}.heic",
];
pub const CN_FRAMES: &[&str] = &[
    "Passport: {}",
    "护照号：{}",
    "passport number is {}",
    "a passport of {}",
    "scan_passport_{}.pdf",
];
pub const TAX_FRAMES: &[&str] = &[
    "Tax ID: {}",
    "TIN: {}",
    "the tax ID for Acme Ltd is {}",
    "a tax ID of {}",
    "numéro fiscal : {}",
    "\"taxId\": \"{}\"",
];

pub const SEPARATORS: &[&str] = &[" ", "\n", ". ", " | ", ", ", "\n\n", "; "];

/// A small seeded generator (SplitMix64), so the differential is the same on
/// every machine.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn digits(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'0' + self.below(10) as u8))
            .collect()
    }

    fn letters(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from(b'A' + self.below(26) as u8))
            .collect()
    }

    /// `n` capitals and digits, at least three digits and one letter.
    fn mixed(&mut self, n: usize) -> String {
        loop {
            let value: String = (0..n)
                .map(|_| {
                    let pick = self.below(36) as u8;
                    char::from(if pick < 10 { b'0' + pick } else { b'A' + pick - 10 })
                })
                .collect();
            let digits = value.bytes().filter(u8::is_ascii_digit).count();
            if digits >= 3 && digits < n && value.as_bytes()[0].is_ascii_uppercase() {
                return value;
            }
        }
    }
}

/// An invented UK driving licence number with a valid structure: five surname
/// letters (`9` padding), decade, month (`+50` for women), day, year, two
/// initials, a digit and two check letters.
pub fn uk_licence(rng: &mut Rng) -> String {
    let short = rng.below(4);
    let surname = format!("{}{}", rng.letters(5 - short), "9".repeat(short));
    let month = 1 + rng.below(12) + 50 * rng.below(2);
    let day = 1 + rng.below(28);
    format!(
        "{surname}{}{month:02}{day:02}{}{}9{}",
        rng.digits(1),
        rng.digits(1),
        rng.letters(2),
        rng.letters(2)
    )
}

/// One differential text: 1 to 4 pieces, each an ID in a frame, a value of
/// another class, or a negative; and the byte ranges of the IDs it holds.
pub fn differential_text(rng: &mut Rng) -> (String, Vec<(usize, usize)>) {
    let (mut text, mut values) = (String::new(), Vec::new());
    let mut framed = |text: &mut String, frame: &str, value: &str| {
        let start = text.len() + frame.find("{}").expect("a frame holds {}");
        text.push_str(&frame.replace("{}", value));
        values.push((start, start + value.len()));
    };
    for at in 0..1 + rng.below(4) {
        if at > 0 {
            text.push_str(rng.pick(SEPARATORS));
        }
        match rng.below(9) {
            0 => {
                let value = if rng.below(2) == 0 {
                    rng.digits(12)
                } else {
                    rng.mixed(9)
                };
                framed(&mut text, rng.pick(CNI_FRAMES), &value);
            }
            1 => {
                let value = if rng.below(2) == 0 {
                    rng.digits(12)
                } else {
                    format!("{}{}{}", rng.digits(2), rng.letters(2), rng.digits(5))
                };
                framed(&mut text, rng.pick(PERMIS_FRAMES), &value);
            }
            2 => {
                let value = uk_licence(rng);
                framed(&mut text, rng.pick(UK_FRAMES), &value);
            }
            3 => {
                let len = 9 + rng.below(2);
                let value = rng.mixed(len);
                framed(&mut text, rng.pick(DE_FRAMES), &value);
            }
            4 => {
                let value = if rng.below(2) == 0 {
                    format!("E{}", rng.digits(8))
                } else {
                    format!("E{}{}", rng.letters(1), rng.digits(7))
                };
                framed(&mut text, rng.pick(CN_FRAMES), &value);
            }
            5 => {
                let value = match rng.below(3) {
                    0 => format!("{}-{}", rng.digits(2), rng.digits(7)),
                    1 => format!("{}-{}-{}", rng.digits(3), rng.digits(2), rng.digits(4)),
                    _ => rng.digits(13),
                };
                framed(&mut text, rng.pick(TAX_FRAMES), &value);
            }
            6 => text.push_str(rng.pick(OTHERS)),
            _ => text.push_str(rng.pick(NEGATIVES)),
        }
    }
    (text, values)
}

/// How many seeded texts the differential runs.
pub const DIFFERENTIAL_TEXTS: usize = 1600;
pub const SEED: u64 = 0x0049_444C_4142_454C;
