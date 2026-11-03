// HEALTH-LABEL cases: labelled health numbers and blood groups. Every value is
// invented; the FR IBAN and the 4111… card are the public specimens, the AWS key
// is the AWS documentation example.

/// `(text, value)`: the value after its label, in mail, form and chat shapes,
/// English and French. Both modes must hide every byte of the value.
pub const POSITIVES: &[(&str, &str)] = &[
    // English, mail.
    (
        "Hi Dr Vale,\nPatient MRN: 7730-41925, follow-up Tuesday.\nThanks",
        "7730-41925",
    ),
    (
        "Dear team, medical record number #A55-90213 is attached.",
        "A55-90213",
    ),
    (
        "Please file the scan under medical record no. 4471-0098-22 today.",
        "4471-0098-22",
    ),
    (
        "She was admitted with a medical record number of 0041177256 yesterday.",
        "0041177256",
    ),
    (
        "Her health plan beneficiary number is 7KL2-QW9-PX41, please check.",
        "7KL2-QW9-PX41",
    ),
    (
        "Valid health plan beneficiary numbers, such as XJ-0091234567, start with two letters.",
        "XJ-0091234567",
    ),
    (
        "The patient's blood type is AB-. Please order two units.",
        "AB-",
    ),
    (
        "Lab note: the sample had a blood type of O+ and no antibodies.",
        "O+",
    ),
    (
        "Your new insurer, Lantern Health, sent your member ID: QHX81402277.",
        "QHX81402277",
    ),
    (
        "The hospital needs your member number 88412-0093 before the visit.",
        "88412-0093",
    ),
    ("Dental plan renewal, subscriber ID DNT-55120-8.", "DNT-55120-8"),
    (
        "The medical record number for this donor is 5520-1183-77, see the scan.",
        "5520-1183-77",
    ),
    (
        "Health plan beneficiary number for the primary member: WQ-7710-2294-31",
        "WQ-7710-2294-31",
    ),
    // English, form.
    (
        "- **Medical Record Number:**\n558830-2741\n- Ward: 4",
        "558830-2741",
    ),
    (
        "Name: Jo Pell\nHealth plan beneficiary number: ZQX-4410-8823-07\nPlan: Silver",
        "ZQX-4410-8823-07",
    ),
    ("Patient ID: PT-882301-C\nRoom: 12", "PT-882301-C"),
    ("NHS number: 943 476 5919", "943 476 5919"),
    ("NHS no. 401 023 2137", "401 023 2137"),
    ("Blood Type: B-\nAllergies: none", "B-"),
    ("Blood group: AB Rh-", "AB Rh-"),
    ("Blood type:\nB positive", "B positive"),
    ("MRN#55120934", "55120934"),
    ("MRN - 6620-1173", "6620-1173"),
    ("Health plan ID: HP-4471-02", "HP-4471-02"),
    (
        "Medical insurance card\nMember ID: 55120934\nGroup: 0042",
        "55120934",
    ),
    // English, chat.
    ("fyi my blood type is O+ lol", "O+"),
    ("btw blood group B Rh+ if they ask", "B Rh+"),
    ("patient id 99-4410-772 is the one for mum", "99-4410-772"),
    ("the clinic asked for my member id 7712009355", "7712009355"),
    ("my blood type is A-, is that rare?", "A-"),
    // French, mail.
    (
        "Bonjour, numéro de dossier médical 8812-55-301 pour le rendez-vous.",
        "8812-55-301",
    ),
    (
        "Madame, son groupe sanguin est B négatif, merci de prévoir.",
        "B négatif",
    ),
    (
        "La mutuelle santé demande votre numéro adhérent, member ID MS-7741-0920.",
        "MS-7741-0920",
    ),
    // French, form.
    (
        "Numéro de dossier médical : DM-2024-77812\nService : cardiologie",
        "DM-2024-77812",
    ),
    ("N° de dossier médical : 77-1203-9", "77-1203-9"),
    ("Groupe sanguin : AB-", "AB-"),
    ("Groupe sanguin : A positif", "A positif"),
    ("Numéro patient : PAT-44120-7", "PAT-44120-7"),
    ("Identifiant patient : IP-90213-4", "IP-90213-4"),
    // French, chat.
    ("groupe sanguin O Rh+ au cas où", "O Rh+"),
    ("mon groupe sanguin c'est A- en fait", "A-"),
];

/// FR social security numbers after their labels: hidden in both modes, and the
/// kind stays the ID's.
pub const FR_SOCIAL: &[(&str, &str)] = &[
    (
        "N° de sécurité sociale : 2 84 12 75 113 052 41",
        "2 84 12 75 113 052 41",
    ),
    (
        "n° de sécurité sociale 1 91 07 13 055 018 72",
        "1 91 07 13 055 018 72",
    ),
    ("Sécurité sociale : 184127645108946", "184127645108946"),
];

/// Lookalikes with no health label, or a member ID by a gym, a shop or a club:
/// no HEALTH span, token or marker in either mode (an ID main already hides
/// stays hidden as an ID).
pub const NEGATIVES: &[&str] = &[
    "She has a type A personality and runs every morning.",
    "Plan A failed, so we moved to Plan B.",
    "Keep an O positive attitude, the demo is tomorrow!",
    "Group B of the tournament plays on Sunday.",
    "Invoice number 20481234 is due on Friday.",
    "Order #55210931 shipped this morning.",
    "Gym member ID: 44120098, valid until June.",
    "Loyalty member ID 7712-0093-55 earns double points.",
    "Your rewards member number is RW-55120-88.",
    "Fitness pass, member ID: FC-88210.",
    "His health is fine; gym member ID 55120934.",
    "Health club member ID 44120098, towel included.",
    "Member ID: 55120934 for the book club.",
    "Member number 88120-44 for the ski association.",
    "What blood type are you?",
    "The blood group study ran in 2024.",
    "Blood type A personalities are a myth.",
    "The record system goes live in November, type A or B.",
    "MRN format is three letters and some digits.",
    "Le groupe B du tournoi joue dimanche.",
    "Plan A ou plan B ? On décide demain.",
    "Numéro de commande : 55210931",
    "Numéro de facture FAC-2026-0042, merci.",
    "Le groupe A passe en premier, le groupe O ensuite.",
    "patient ID requirements changed last week",
    "Our NHS number lookup page is down.",
    "Ticket no. 4471-2290 is open.",
    "The A+ grade students get a prize.",
    "Group AB of the survey answered first.",
    "A positive review from the client came in.",
    "O negative feedback so far, which is great.",
    "Member ID card for the climbing club: GY-4410-22",
    "The blood type of the character is never said.",
    "Plan B: order 4471 more boxes.",
];

/// Values of other classes mixed into the differential texts: `(frame, kind)`.
pub const OTHERS: &[&str] = &[
    "IBAN FR76 3000 6000 0112 3456 7890 189",
    "card 4111 1111 1111 1111 exp 09/29",
    "key AKIAIOSFODNN7EXAMPLE",
    "password: Lantern#2291",
    "mail jo.pell@example.org",
    "call +33 6 12 34 56 78",
    "phone +44 20 7946 0958",
    "NIR 1 84 12 76 451 089 46",
    "SSN 078-05-1120",
    "order 55210931",
    "the meeting moved to 14:30",
    "type A personality",
];

/// Label frames: `{}` is the value.
pub const HEALTH_FRAMES: &[&str] = &[
    "MRN: {}",
    "MRN {}",
    "Patient MRN #{}",
    "medical record number {}",
    "Medical Record Number:\n{}",
    "a medical record number of {}",
    "**Medical Record Number:** {}",
    "health plan beneficiary number {}",
    "Health Plan Beneficiary Number: {}",
    "patient ID: {}",
    "NHS number {}",
    "NHS no. {}",
    "Health plan ID {}",
    "health insurance member ID {}",
    "the clinic asked for member ID {}",
    "numéro de dossier médical : {}",
    "N° de dossier médical {}",
    "numéro patient {}",
];

pub const BLOOD_FRAMES: &[&str] = &[
    "Blood type: {}",
    "blood type {}",
    "a blood type of {}",
    "Blood group: {}",
    "her blood type is {}",
    "Groupe sanguin : {}",
    "groupe sanguin {}",
];

pub const BLOOD_VALUES: &[&str] = &[
    "O+", "O-", "A+", "A-", "B+", "B-", "AB+", "AB-", "O negative", "A positive",
    "B Rh+", "AB Rh-", "O Rh-", "A positif", "B négatif",
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
}

/// An invented record number: digits, letter prefixes, `-` groups.
pub fn record_number(rng: &mut Rng) -> String {
    let digits = |rng: &mut Rng, n: usize| -> String {
        (0..n)
            .map(|_| char::from(b'0' + rng.below(10) as u8))
            .collect()
    };
    let letters = |rng: &mut Rng, n: usize| -> String {
        (0..n)
            .map(|_| char::from(b'A' + rng.below(26) as u8))
            .collect()
    };
    let extra = rng.below(3);
    match rng.below(6) {
        0 => digits(rng, 8 + extra),
        1 => format!("{}-{}", letters(rng, 2 + extra.min(1)), digits(rng, 7)),
        2 => format!("{}-{}-{}", digits(rng, 4), digits(rng, 4), digits(rng, 2)),
        3 => format!("{}-{}", digits(rng, 6), digits(rng, 4)),
        4 => format!("{}{}", letters(rng, 1), digits(rng, 8)),
        _ => format!("{} {} {}", digits(rng, 3), digits(rng, 3), digits(rng, 4)),
    }
}

/// One differential text: 1 to 4 pieces, each a health value in a frame, a
/// value of another class, or a negative; and the byte ranges of the health
/// values it holds.
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
        match rng.below(5) {
            0 | 1 => {
                let value = record_number(rng);
                framed(&mut text, rng.pick(HEALTH_FRAMES), &value);
            }
            2 => {
                let (frame, value) = (rng.pick(BLOOD_FRAMES), rng.pick(BLOOD_VALUES));
                framed(&mut text, frame, value);
            }
            3 => text.push_str(rng.pick(OTHERS)),
            _ => text.push_str(rng.pick(NEGATIVES)),
        }
    }
    (text, values)
}

/// How many seeded texts the differential runs.
pub const DIFFERENTIAL_TEXTS: usize = 1600;
pub const SEED: u64 = 0x4845_414C_5448;
