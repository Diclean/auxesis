// LABEL-VALUE-1 cases, shared by `tests/label_value_differential.rs` (frozen-main
// differential) and `tests/label_value.rs` (acceptance).

/// The finish-line repros (FIN-1 health, FIN-2 secrets, FIN-3 IDs): the text
/// and the value that must never be issued in clear.
const REPROS: &[(&str, &str)] = &[
    ("MRN: 00438291", "00438291"),
    ("Patient MRN 448812 was admitted.", "448812"),
    ("Medical record number: 7781-2290", "7781-2290"),
    (
        "Health plan beneficiary number: 948-221-7730",
        "948-221-7730",
    ),
    ("Health plan no. HP4471029", "HP4471029"),
    ("Blood type: O negative", "O negative"),
    ("Blood group: AB+", "AB+"),
    ("Her blood type is A positive.", "A positive"),
    ("Groupe sanguin : O+", "O+"),
    (
        "Cookie: sessionid=9f8e7d6c5b4a3f2e1d0c",
        "9f8e7d6c5b4a3f2e1d0c",
    ),
    (
        "Set-Cookie: user_session=Zx81pQ7rT2mW4nB6; Path=/; HttpOnly",
        "Zx81pQ7rT2mW4nB6",
    ),
    ("user_session=Qm4Lp9Wz2Xr7Tn5V; Path=/", "Qm4Lp9Wz2Xr7Tn5V"),
    ("the password might be G9$rP2zT@qWk", "G9$rP2zT@qWk"),
    ("the password, Sunflower@2025, opens it", "Sunflower@2025"),
    (
        "Our API key, L9dXq7Rv2Tm8Kp4, is in the vault",
        "L9dXq7Rv2Tm8Kp4",
    ),
    ("the pin, 719836, works", "719836"),
    ("I changed my pin to 619036 yesterday", "619036"),
    ("api\\_key: Zq9Lm2Xv8Rt4Wp7N", "Zq9Lm2Xv8Rt4Wp7N"),  // gitleaks:allow
    ("**api\\_key**: Zq9Lm2Xv8Rt4Wp7N", "Zq9Lm2Xv8Rt4Wp7N"),
    ("CNI : 123456789012", "123456789012"),
    ("Carte nationale d'identité : AB12CD34E", "AB12CD34E"),
    ("Permis de conduire : 12AB34567", "12AB34567"),
    ("Driving licence: MORGA753116SM9IJ", "MORGA753116SM9IJ"),
    ("Personalausweis Nr L01X00T47", "L01X00T47"),
    ("Personalausweis-Nr. L01X00T47", "L01X00T47"),
    ("passport_12AB34567.pdf", "12AB34567"),
    ("护照号 EA0000125", "EA0000125"),
    ("| Tax ID | 98-7654321 |", "98-7654321"),
    ("Paspoortnommer: A12345678", "A12345678"),
    ("Útlevélszám: BA1234567", "BA1234567"),
    ("Številka potnega lista: PB1234567", "PB1234567"),
    ("Jelszó: Kalap#2024", "Kalap#2024"),
];

/// Texts that hold a label but no value: no new mask, in either mode.
const TRAPS: &[&str] = &[
    "the password policy is strict",
    "your PIN is required",
    "Tax ID requirements",
    "blood type matters",
    "ID card renewal",
    "API key rotation is due",
    "code review",
    "Your blood type is a factor in transfusions.",
    "The passport office opens at 9.",
    "Medical record numbers are kept for 10 years.",
    "Cookie: chocolate chip",
    "Session 2024 opens on Monday.",
    "the password is incorrect",
];
