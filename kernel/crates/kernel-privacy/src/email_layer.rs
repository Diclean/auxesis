//! Email-aware detection layer (slice 1e).
//!
//! [`EmailLayer`] is the post-pass that closes the gap the deterministic
//! recognisers and GLiNER leave on messy e-mail: a bare first name in a
//! greeting, a name inside a `linkedin.example.invalid/in/jules-ferrand` path,
//! an address hidden behind `%40` in an unsubscribe link, a legal footer's
//! company number.
//!
//! It works in three steps:
//!
//! 1. **Decode** — [`DecodedText`] folds HTML entities and the percent escapes
//!    inside URLs, and every detection is mapped back to the original bytes.
//! 2. **Seed** — collect the names the text itself reveals: every `PERSON`
//!    span any recogniser found, every e-mail local part, every display name in
//!    a sender header or a "wrote" line, and every name a greeting, a sign-off
//!    or a `ps:` line names.
//! 3. **Propagate** — mask every other occurrence of each seeded token in the
//!    whole text (Unicode word boundary, case- and diacritic-insensitive),
//!    merging a first name and its surname when only a short separator sits
//!    between them. A stop-list keeps function words and public terms out.
//!
//! It also emits the deterministic company/tax identifiers
//! ([`crate::company_id`]), the whole value of a tracking or unsubscribe query
//! parameter, and a keyword-gated birth date in a flattened table. Finally it
//! drops an organisation or address span from a model when the value is an
//! allow-listed public term, unless the text carries a private signal too.
//!
//! Everything here fails toward masking: a rule that is unsure still masks.

use std::collections::{HashMap, HashSet};

use regex::Regex;

use crate::company_id;
use crate::decode::DecodedText;
use crate::name_lexicon;
use crate::normalize::SharedViews;
use crate::public_terms::{fold, PublicTerms};
use crate::recognizer::Recognizer;
use crate::recognizers::email::EmailRecognizer;
use crate::span::{EntityKind, Span};

/// Score of a name reached by propagation from a seed.
pub const PROPAGATION_SCORE: f32 = 0.6;
/// Score of a name named directly by a greeting, sign-off, header or `ps:`.
pub const RULE_SCORE: f32 = 0.7;

/// The reserved app-config key that turns bare-first-name masking back on.
///
/// Default `false` (owner decision of 2026-10-09). The kernel-privacy switch is
/// [`EmailLayer::with_first_names`] / [`crate::RegistryBuilder::mask_first_names`].
/// The key is parsed by kernel-core as `PrivacyConfig::mask_first_names`; the
/// `[privacy] mask_first_names` contract is pinned by `tests/config_first_names.rs`.
pub const MASK_FIRST_NAMES_CONFIG_KEY: &str = "privacy.mask_first_names";

/// Query parameter names that carry an address or a name in a tracking link.
const TRACKING_KEYS: &[&str] = &[
    "e",
    "email",
    "u",
    "uid",
    "name",
    "recipient",
    "mail",
    "to",
    "nom",
    "naam",
];

/// Greeting words, longest first so a multi-word greeting wins.
///
/// Matching is case-insensitive, so a lower-case greeting works too; the entries
/// below add the colloquial forms of the six corpus languages.
const GREETINGS: &[&str] = &[
    "здравствуйте",
    "здравствуй",
    "добрый день",
    "добрый вечер",
    "السلام عليكم",
    "guten tag",
    "goeie môre",
    "goeie more",
    "bonjour",
    "bonsoir",
    "coucou",
    "salut",
    "hello",
    "hallo",
    "haai",
    "beste",
    "liewe",
    "goeie",
    "geachte",
    "kedves",
    "sziasztok",
    "привет",
    "مرحبا",
    "السلام",
    "عزيزي",
    "عزيزتي",
    "سلام",
    "هلا",
    "واخا",
    "أهلا",
    "helló",
    "szia",
    "liebe",
    "dear",
    "hey",
    "hi",
    "üdv",
    "您好",
    "你好",
    "哈囉",
    "哈罗",
    "嗨",
];

/// Closing words that end a sign-off line, longest first.
///
/// A closing line opens a signature block, so the name below it always stays
/// masked. The list carries the common forms of the six corpus languages plus
/// the German (`Mit freundlichen Grüßen`, `Viele Grüße`, `Liebe Grüße`), Chinese
/// (`此致敬礼`, `此致`, `敬礼`, `祝好`, `顺祝商祺`), Dutch/Afrikaans
/// (`Met vriendelike groete`) and Hungarian (`Üdvözlettel`, `Tisztelettel`)
/// closings, with the ASCII `Gruessen`/`Gruesse`/`Grusse` variants of the
/// German ones.
const CLOSINGS: &[&str] = &[
    "mit freundlichen grüßen",
    "mit freundlichen gruessen",
    "mit freundlichen gruesse",
    "met vriendelike groete",
    "vriendelike groete",
    "herzliche grüße",
    "herzliche gruesse",
    "freundliche grüße",
    "freundliche gruesse",
    "bien cordialement",
    "bien à vous",
    "szívélyes üdvözlettel",
    "с наилучшими пожеланиями",
    "dankie vir die hulp",
    "beste grüße",
    "beste gruesse",
    "viele grüße",
    "viele gruesse",
    "liebe grüße",
    "liebe gruesse",
    "liebe grusse",
    "cordialement",
    "amicalement",
    "kind regards",
    "best regards",
    "thanks a lot",
    "many thanks",
    "üdvözlettel",
    "tisztelettel",
    "с уважением",
    "всего доброго",
    "مع تحياتي",
    "مع التحية",
    "شكرا جزيلا",
    "此致敬礼",
    "顺祝商祺",
    "regards",
    "dankie",
    "groete",
    "bisous",
    "bises",
    "thanks",
    "cheers",
    "此致",
    "敬礼",
    "祝好",
    "تحياتي",
    "شكرا",
    "best",
    "üdv",
];

/// Words that address the reader right before a name (`merci Jules`,
/// `thanks Mila`, `köszi Anna`). A name directly after one of these is in an
/// address position (the thanks check of [`in_vocative_or_address`]). The list
/// is folded (lowercase, marks dropped) because the lookup folds the text.
const ADDRESS_THANKS: &[&str] = &[
    "thank you",
    "thanks",
    "spasibo",
    "bedankt",
    "dankie",
    "koszonom",
    "koszi",
    "merci",
    "danke",
    "谢谢",
    "شكرا",
];

/// Marks that close a greeting or thanks clause: a line end, then the ASCII,
/// Arabic and full-width clause punctuation (see [`closes_address_clause`]).
const CLAUSE_MARKS: &str = "\r\n,!:;.?\u{060C}，！：；。？";

/// Verbs that introduce a quoted reply.
const REPLY_VERBS: &[&str] = &[
    "wrote:",
    "a écrit",
    "geskryf",
    "írta",
    "написал",
    "написала",
    "كتب",
];

/// Sender and recipient header keys, already lowercased and without the colon.
///
/// A name on any of these lines is signature/header context and always stays:
/// `From`, `To`, `Cc`, the French `De`, the Dutch `Van`, the German `Von`, the
/// Russian `От`, the Hungarian `Feladó`, the Arabic `من` and the Chinese
/// `发件人` / `收件人`.
const SENDER_KEYS: &[&str] = &[
    "from",
    "to",
    "cc",
    "de",
    "van",
    "von",
    "от",
    "feladó",
    "felado",
    "من",
    "sender",
    "发件人",
    "收件人",
];

/// Subject header keys, lowercased and without the colon. A name line directly
/// follows one of these in a forwarded or reply body.
const SUBJECT_KEYS: &[&str] = &[
    "subject",
    "objet",
    "betreff",
    "tárgy",
    "targy",
    "тема",
    "onderwerp",
    "الموضوع",
];

/// Verbs that introduce a spoken clause, with whether the speaker is named
/// before the verb (`X said`) or after it (`قال X`), longest first.
const SPEECH_VERBS: &[(&str, bool)] = &[
    ("azt mondta", true),
    ("het gesê", true),
    ("het gese", true),
    ("a dit", true),
    ("сказала", true),
    ("сказал", true),
    ("said", true),
    ("says", true),
    ("قال", false),
];

/// Honorifics and roles that a rule must not seed as a name on their own.
const TITLES: &[&str] = &[
    "dr",
    "mr",
    "mrs",
    "ms",
    "mme",
    "mlle",
    "prof",
    "sir",
    "madame",
    "monsieur",
    "herr",
    "frau",
    "mevrouw",
    "meneer",
    "úr",
    "asszony",
    "г-н",
    "г-жа",
    "سيد",
    "سيدة",
    "دكتور",
];

/// Discourse words that a capitalized opening (`Yes, …`, `Note, …`) would
/// otherwise seed as a name.
const DISCOURSE_WORDS: &[&str] = &[
    "yes",
    "no",
    "ok",
    "okay",
    "well",
    "sure",
    "note",
    "notes",
    "update",
    "updates",
    "news",
    "fyi",
    "btw",
    "important",
    "urgent",
    "reminder",
    "info",
    "all",
    "team",
    "everyone",
    "everybody",
    "folks",
    "guys",
    "colleagues",
    "re",
    "fwd",
    "objet",
    "subject",
    "message",
];

/// Folded words that open or close a mail or name a role or a discourse move;
/// none of them is a name, whatever its case. The phrases are split into words
/// and folded, so `Üdvözlettel`, `С уважением` and `Здравствуйте` are all caught.
static RULE_WORDS: std::sync::LazyLock<HashSet<String>> = std::sync::LazyLock::new(|| {
    GREETINGS
        .iter()
        .chain(CLOSINGS.iter())
        .chain(TITLES.iter())
        .chain(DISCOURSE_WORDS.iter())
        .flat_map(|phrase| phrase.split(|ch: char| !ch.is_alphanumeric()))
        .filter(|word| !word.is_empty())
        .map(fold)
        .collect()
});

/// Courtesy and discourse interjections that a capitalized rule hit would
/// otherwise seed (`Merci, …`, `Спасибо, …`, `Köszönöm, …`). They are not names,
/// whatever their case.
const COURTESY_WORDS: &[&str] = &[
    "merci",
    "amities",
    "amitiés",
    "cordialement",
    "спасибо",
    "пожалуйста",
    "köszönöm",
    "koszonom",
    "kérem",
    "kerem",
    "dankie",
    "asseblief",
    "eerlikwaar",
    "شكرا",
    "عفوا",
    "تحياتي",
    // Discourse adverbs and one-word headers a rule would otherwise name as a
    // person (`fontos`, `важно`, `отправлено`, `elküldve`).
    "fontos",
    "важно",
    "отправлено",
    "elkuldve",
    "elküldve",
    "hier",
    // Discourse and interjection words seen opening a line before a comma.
    "rendben",
    "хорошо",
    "ок",
    "köszi",
    "koszi",
    "szépen",
    "szepen",
    "salam",
    "dringend",
    "chère",
    "chere",
    "cher",
    "честно",
    "говоря",
    "بصراحة",
    "őszintén",
    "oszinten",
    "szólva",
    "szolva",
];

/// Words that open a question or a request, never a vocative: a line that
/// starts with one, then a comma later, is a sentence, not an address
/// (`How many unread mails do I have, and who sent the newest one?`).
///
/// Closed and functional like [`FUNCTION_WORDS`]; it holds no first name
/// (`Will`, `Mark`, `Rose`, `Maxime` still open a vocative).
const QUESTION_OPENERS: &[&str] = &[
    "how",
    "why",
    "can",
    "would",
    "please",
    "show",
    "tell",
    "give",
    "list",
    "check",
    "find",
    "send",
    "open",
    "read",
    "summarise",
    "summarize",
    "comment",
    "pourquoi",
    "combien",
    "quel",
    "quels",
    "quelle",
    "quelles",
    "quand",
    "est-ce",
    "peux-tu",
    "pouvez-vous",
    "peux",
    "pouvez",
    "où",
    "ou",
    "qui",
    "que",
    "quoi",
    "dis-moi",
    "montre-moi",
    "donne-moi",
    "je",
    "j",
    "il",
    "elle",
    "on",
    "nous",
    "vous",
    "il y a",
];

/// Articles, determiners, pronouns, prepositions, conjunctions and auxiliaries
/// of the six corpus languages.
///
/// A rule (`greeting`, `sign-off`, line-initial comma, speech verb, `ps`) never
/// seeds or propagates one of these, whatever its case. The list is closed and
/// functional on purpose: it holds no common noun and no name, so `Will`, `Mark`,
/// `Rose` and `Pierre` still seed when a rule fires on them.
const FUNCTION_WORDS: &[&str] = &[
    // English.
    "the",
    "a",
    "an",
    "this",
    "that",
    "these",
    "those",
    "my",
    "your",
    "our",
    "their",
    "his",
    "her",
    "its",
    "its",
    "some",
    "any",
    "all",
    "every",
    "each",
    "both",
    "another",
    "such",
    "i",
    "you",
    "he",
    "she",
    "it",
    "we",
    "they",
    "me",
    "him",
    "us",
    "them",
    "who",
    "whom",
    "whose",
    "which",
    "what",
    "of",
    "in",
    "on",
    "at",
    "by",
    "for",
    "with",
    "from",
    "to",
    "into",
    "onto",
    "over",
    "under",
    "about",
    "after",
    "before",
    "between",
    "during",
    "without",
    "within",
    "across",
    "through",
    "against",
    "among",
    "along",
    "around",
    "behind",
    "below",
    "beside",
    "beyond",
    "near",
    "off",
    "out",
    "past",
    "since",
    "till",
    "toward",
    "towards",
    "until",
    "up",
    "upon",
    "via",
    "and",
    "or",
    "but",
    "nor",
    "so",
    "yet",
    "if",
    "because",
    "although",
    "though",
    "while",
    "whereas",
    "unless",
    "whether",
    "as",
    "than",
    "when",
    "where",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "am",
    "do",
    "does",
    "did",
    "have",
    "has",
    "had",
    "shall",
    "should",
    "could",
    "might",
    "must",
    "ought",
    // French.
    "le",
    "la",
    "les",
    "un",
    "une",
    "des",
    "du",
    "de",
    "au",
    "aux",
    "ce",
    "cet",
    "cette",
    "ces",
    "mon",
    "ma",
    "mes",
    "ton",
    "ta",
    "tes",
    "son",
    "sa",
    "ses",
    "notre",
    "nos",
    "votre",
    "vos",
    "leur",
    "leurs",
    "chaque",
    "quelques",
    "plusieurs",
    "tout",
    "tous",
    "toute",
    "toutes",
    "aucun",
    "aucune",
    "autre",
    "autres",
    "meme",
    "même",
    "je",
    "tu",
    "il",
    "elle",
    "on",
    "nous",
    "vous",
    "ils",
    "elles",
    "me",
    "te",
    "se",
    "moi",
    "toi",
    "lui",
    "eux",
    "qui",
    "que",
    "quoi",
    "dont",
    "ou",
    "où",
    "y",
    "en",
    "dans",
    "sur",
    "sous",
    "pour",
    "par",
    "avec",
    "sans",
    "chez",
    "entre",
    "vers",
    "contre",
    "depuis",
    "pendant",
    "avant",
    "apres",
    "après",
    "devant",
    "derriere",
    "derrière",
    "pres",
    "près",
    "malgre",
    "malgré",
    "selon",
    "parmi",
    "hors",
    "des",
    "et",
    "mais",
    "donc",
    "or",
    "ni",
    "car",
    "si",
    "comme",
    "quand",
    "lorsque",
    "puisque",
    "parce",
    "afin",
    "pourtant",
    "cependant",
    "toutefois",
    "neanmoins",
    "néanmoins",
    "est",
    "sont",
    "suis",
    "es",
    "etes",
    "êtes",
    "etait",
    "était",
    "etaient",
    "étaient",
    "etre",
    "être",
    "ai",
    "as",
    "avons",
    "avez",
    "ont",
    "avait",
    "avaient",
    "avoir",
    "sera",
    "seront",
    "serait",
    "peut",
    "peuvent",
    "doit",
    "doivent",
    "va",
    "vont",
    "vient",
    "viennent",
    // Afrikaans.
    "die",
    "hierdie",
    "daardie",
    "elkeen",
    "elke",
    "alle",
    "sommige",
    "geen",
    "ander",
    "ek",
    "jy",
    "u",
    "hy",
    "sy",
    "dit",
    "ons",
    "julle",
    "hulle",
    "hom",
    "haar",
    "wie",
    "wat",
    "waar",
    "wanneer",
    "hoe",
    "hoekom",
    "van",
    "vir",
    "met",
    "op",
    "in",
    "aan",
    "by",
    "na",
    "tot",
    "deur",
    "oor",
    "onder",
    "bo",
    "tussen",
    "sonder",
    "teen",
    "langs",
    "om",
    "voor",
    "agter",
    "sedert",
    "en",
    "of",
    "maar",
    "want",
    "omdat",
    "as",
    "terwyl",
    "sodat",
    "totdat",
    "hoewel",
    "tensy",
    "beide",
    "nog",
    "is",
    "was",
    "wees",
    "word",
    "het",
    "gehad",
    "sal",
    "sou",
    "kan",
    "kon",
    "moet",
    "mag",
    "gaan",
    "kom",
    "doen",
    "gedoen",
    // Hungarian.
    "a",
    "az",
    "egy",
    "e",
    "ez",
    "ezek",
    "azok",
    "ezen",
    "azon",
    "minden",
    "mindegyik",
    "valamelyik",
    "semelyik",
    "sajat",
    "saját",
    "mas",
    "más",
    "ilyen",
    "olyan",
    "en",
    "én",
    "te",
    "o",
    "ő",
    "mi",
    "ti",
    "ok",
    "ők",
    "engem",
    "teged",
    "téged",
    "ot",
    "őt",
    "minket",
    "titeket",
    "oket",
    "őket",
    "aki",
    "ami",
    "amely",
    "amelyik",
    "milyen",
    "mekkora",
    "alatt",
    "felett",
    "elott",
    "előtt",
    "utan",
    "után",
    "mellett",
    "kozott",
    "között",
    "mogott",
    "mögött",
    "nelkul",
    "nélkül",
    "altal",
    "által",
    "miatt",
    "szerint",
    "ellen",
    "fele",
    "felé",
    "ota",
    "óta",
    "es",
    "és",
    "vagy",
    "de",
    "hanem",
    "mert",
    "hogy",
    "ha",
    "mint",
    "mig",
    "míg",
    "bar",
    "bár",
    "mivel",
    "ezert",
    "ezért",
    "azert",
    "azért",
    "viszont",
    "tehat",
    "tehát",
    "van",
    "vannak",
    "volt",
    "voltak",
    "lesz",
    "lesznek",
    "lenni",
    "vagyok",
    "vagyunk",
    "vagytok",
    // Russian.
    "в",
    "во",
    "на",
    "с",
    "со",
    "из",
    "от",
    "до",
    "по",
    "за",
    "под",
    "над",
    "при",
    "про",
    "без",
    "для",
    "о",
    "об",
    "обо",
    "к",
    "ко",
    "у",
    "через",
    "между",
    "перед",
    "около",
    "возле",
    "после",
    "и",
    "а",
    "но",
    "или",
    "да",
    "что",
    "чтобы",
    "если",
    "когда",
    "пока",
    "хотя",
    "потому",
    "поэтому",
    "также",
    "тоже",
    "либо",
    "ни",
    "я",
    "ты",
    "он",
    "она",
    "оно",
    "мы",
    "вы",
    "они",
    "меня",
    "тебя",
    "его",
    "ее",
    "её",
    "нас",
    "вас",
    "их",
    "мне",
    "тебе",
    "ему",
    "ей",
    "нам",
    "вам",
    "им",
    "кто",
    "который",
    "которая",
    "которое",
    "которые",
    "был",
    "была",
    "было",
    "были",
    "есть",
    "будет",
    "будут",
    "быть",
    "буду",
    "будешь",
    "будем",
    "будете",
    "имею",
    "имеет",
    "имеют",
    "не",
    "нет",
    "это",
    "этот",
    "эта",
    "эти",
    "ваш",
    "ваша",
    "ваше",
    "ваши",
    "ниже",
    // Arabic.
    "في",
    "من",
    "إلى",
    "الى",
    "على",
    "عن",
    "مع",
    "بين",
    "تحت",
    "فوق",
    "أمام",
    "امام",
    "خلف",
    "بعد",
    "قبل",
    "حتى",
    "حتي",
    "عند",
    "لدى",
    "نحو",
    "عبر",
    "خلال",
    "ضد",
    "بدون",
    "و",
    "أو",
    "او",
    "لكن",
    "لأن",
    "لان",
    "إذا",
    "اذا",
    "كما",
    "بينما",
    "غير",
    "بل",
    "ثم",
    "أنا",
    "انا",
    "أنت",
    "انت",
    "هو",
    "هي",
    "نحن",
    "أنتم",
    "انتم",
    "هم",
    "هن",
    "هذا",
    "هذه",
    "ذلك",
    "تلك",
    "هؤلاء",
    "الذي",
    "التي",
    "الذين",
    "ما",
    "كان",
    "كانت",
    "يكون",
    "تكون",
    "سوف",
    "قد",
    "لقد",
];

/// Header labels of the six corpus languages. A sender or subject header must
/// never seed its own label as a name (`De :`, `Objet :`, `From:`, `Тема:`).
const HEADER_LABELS: &[&str] = &[
    "from",
    "to",
    "cc",
    "cco",
    "bcc",
    "reply-to",
    "sender",
    "subject",
    "date",
    "datum",
    "dátum",
    "elkuldve",
    "elküldve",
    "gestuur",
    "importance",
    "priority",
    "sent",
    "de",
    "a",
    "à",
    "objet",
    "envoye",
    "envoyé",
    "priorite",
    "priorité",
    "van",
    "aan",
    "onderwerp",
    "verzonden",
    "gesendet",
    "felado",
    "feladó",
    "cimzett",
    "címzett",
    "targy",
    "tárgy",
    "от",
    "кому",
    "тема",
    "дата",
    "من",
    "الى",
    "إلى",
    "التاريخ",
    "الموضوع",
];

/// Weekdays and months of the six corpus languages, so a date line or a
/// forwarded header never names one as a person.
const CALENDAR_WORDS: &[&str] = &[
    // English.
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
    // French.
    "lundi",
    "mardi",
    "mercredi",
    "jeudi",
    "vendredi",
    "samedi",
    "dimanche",
    "janvier",
    "fevrier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "aout",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "decembre",
    "décembre",
    // Afrikaans.
    "maandag",
    "dinsdag",
    "woensdag",
    "donderdag",
    "vrydag",
    "saterdag",
    "sondag",
    "januarie",
    "februarie",
    "maart",
    "april",
    "mei",
    "junie",
    "julie",
    "augustus",
    "september",
    "oktober",
    "november",
    "desember",
    // Hungarian.
    "hetfo",
    "hétfő",
    "kedd",
    "szerda",
    "csutortok",
    "csütörtök",
    "pentek",
    "péntek",
    "szombat",
    "vasarnap",
    "vasárnap",
    "januar",
    "január",
    "februar",
    "február",
    "marcius",
    "március",
    "aprilis",
    "április",
    "majus",
    "május",
    "junius",
    "június",
    "julius",
    "július",
    "augusztus",
    "szeptember",
    "oktober",
    "október",
    "november",
    "december",
    // Russian.
    "понедельник",
    "вторник",
    "среда",
    "четверг",
    "пятница",
    "суббота",
    "воскресенье",
    "январь",
    "февраль",
    "март",
    "апрель",
    "май",
    "июнь",
    "июль",
    "август",
    "сентябрь",
    "октябрь",
    "ноябрь",
    "декабрь",
    // Arabic.
    "الإثنين",
    "الاثنين",
    "الثلاثاء",
    "الأربعاء",
    "الاربعاء",
    "الخميس",
    "الجمعة",
    "السبت",
    "الأحد",
    "الاحد",
    "يناير",
    "فبراير",
    "مارس",
    "أبريل",
    "ابريل",
    "مايو",
    "يونيو",
    "يوليو",
    "أغسطس",
    "اغسطس",
    "سبتمبر",
    "أكتوبر",
    "اكتوبر",
    "نوفمبر",
    "ديسمبر",
    // Common short forms a date or "sent" line carries.
    "okt",
    "вт",
    "ср",
];

/// Role mailboxes: a local part that is entirely one of these never seeds a
/// name, and none of their tokens ever propagates.
const ROLE_LOCAL_PARTS: &[&str] = &[
    "contact",
    "info",
    "hr",
    "admin",
    "office",
    "support",
    "sales",
    "hello",
    "hi",
    "team",
    "noreply",
    "no-reply",
    "enquiries",
    "inquiries",
    "billing",
    "accounts",
    "compta",
    "facturation",
    "rh",
    "service",
    "mail",
    "postmaster",
    "webmaster",
    "bureau",
    "accueil",
    "vente",
    "commercial",
    "direction",
    "kontak",
    "inligting",
    "ondersteuning",
    "verkope",
    "rekeninge",
    "navrae",
    "kapcsolat",
    "ertekesites",
    "értékesítés",
    "szamla",
    "számla",
    "ugyfelszolgalat",
    "ügyfélszolgálat",
    "контакт",
    "инфо",
    "поддержка",
    "продажи",
    "почта",
    "اتصال",
    "معلومات",
    "دعم",
    "مبيعات",
    "بريد",
];

/// [`ROLE_LOCAL_PARTS`], folded once so a token that [`fold`] normalised matches
/// its accented or hamzated spelling.
static ROLE_LOCAL_WORDS: std::sync::LazyLock<HashSet<String>> =
    std::sync::LazyLock::new(|| ROLE_LOCAL_PARTS.iter().map(|word| fold(word)).collect());

/// Surname particles of every corpus language (P3, over-masking).
///
/// These join a given name to its family name (`van der Berg`, `Ибн Сина`,
/// `al-Rashid`). As structural words they never propagate alone; they are
/// masked only as part of a strong seed's full sequence. `Mac`/`Mc` behave as
/// prefixes only: they join a following name, never a surname on their own.
const STRUCTURAL_PARTICLES: &[&str] = &[
    "ибн", "бен", "ван", "фон", "ibn", "bin", "bint", "ben", "abu", "al", "el", "van", "von",
    "der", "den", "ter", "du", "des", "da", "di", "del", "della", "dos", "mac", "mc",
];

/// Function words, roles and structural labels that no rule may seed or emit,
/// in any case. [`RULE_WORDS`] is folded into it, so greetings, closings, titles
/// and discourse words are covered too.
static STRUCTURAL_WORDS: std::sync::LazyLock<HashSet<String>> = std::sync::LazyLock::new(|| {
    RULE_WORDS
        .iter()
        .map(String::as_str)
        .chain(FUNCTION_WORDS.iter().copied())
        .chain(HEADER_LABELS.iter().copied())
        .chain(CALENDAR_WORDS.iter().copied())
        .chain(COURTESY_WORDS.iter().copied())
        .chain(STRUCTURAL_PARTICLES.iter().copied())
        .flat_map(|phrase| phrase.split(|ch: char| !ch.is_alphanumeric()))
        .filter(|word| !word.is_empty())
        .map(fold)
        .collect()
});

/// Cue words that a birth date follows, lowercased.
const DOB_CUES: &[&str] = &[
    "né le",
    "nee le",
    "née le",
    "ddn",
    "date of birth",
    "dob",
    "born",
    "gebore",
    "geboren",
    "születési",
    "született",
    "szuletesi",
    "родился",
    "родилась",
    "дата рождения",
    "تاريخ الازدياد",
    "تاريخ الميلاد",
    "مولود",
    "مولودة",
];

/// The layer and its configuration.
#[derive(Clone, Debug)]
pub struct EmailLayer {
    public_terms: PublicTerms,
    /// Whether a bare given name (a single token that is not a known surname
    /// and is not part of a full name) is masked on its own.
    ///
    /// Default `false`: the owner decision of 2026-10-09 ("non, prénom on s'en
    /// fout") keeps bare first names in clear. The app layer's config key is
    /// `[privacy] mask_first_names` (see [`EmailLayer::with_first_names`]).
    mask_first_names: bool,
}

impl EmailLayer {
    /// The layer with the built-in public-term list.
    pub fn new() -> Self {
        Self {
            public_terms: PublicTerms::builtin(),
            mask_first_names: false,
        }
    }

    /// Use a custom public-term allowlist.
    pub fn with_public_terms(mut self, public_terms: PublicTerms) -> Self {
        self.public_terms = public_terms;
        self
    }

    /// Turn bare-first-name masking back on (default `false`).
    ///
    /// The config key reserved for this switch is `[privacy]
    /// mask_first_names = false`. With it off, a lone token is left in clear only
    /// when [`leaves_lone_name_in_clear`] proves it is a bare given name: in the
    /// closed given-name lexicon, not in the surname lexicon, in a vocative or
    /// address position (a greeting or thanks word closing its clause, or a
    /// line-start comma) and outside signature or header context (`P.S.`/`PS`/`NB`
    /// lines included). Every other lone token stays masked; full names (2+
    /// tokens), signature and header names, known surnames, CJK names, names
    /// preceded by an honorific and ALL-CAPS surnames are always masked.
    pub fn with_first_names(mut self, mask_first_names: bool) -> Self {
        self.mask_first_names = mask_first_names;
        self
    }

    /// Whether bare first names are masked.
    pub fn masks_first_names(&self) -> bool {
        self.mask_first_names
    }

    /// The allowlist in force.
    pub fn public_terms(&self) -> &PublicTerms {
        &self.public_terms
    }

    /// Run the layer with no seeds from another recogniser.
    pub fn analyze(&self, text: &str) -> Vec<Span> {
        self.apply(text, Vec::new(), &[])
    }

    /// Add the layer's spans to `candidates` and drop public-term model spans.
    ///
    /// `seeds` must hold every `PERSON` span any mounted recogniser produced,
    /// including those below its threshold: a name the model found is evidence
    /// enough to mask its other occurrences.
    pub fn apply(&self, text: &str, candidates: Vec<Span>, seeds: &[Span]) -> Vec<Span> {
        let decoded = DecodedText::new(text);
        let _views = SharedViews::new(decoded.text());
        // One e-mail scan of the decoded view serves the seeds and propagation.
        let emails = EmailRecognizer::new().analyze(decoded.text());
        let mut names = NameSet::new(&self.public_terms);
        for seed in seeds {
            if seed.kind == EntityKind::Person
                && well_formed(text, seed)
                && self.keep_person_seed(text, seed, &names)
            {
                names.add_seed_text(&text[seed.start..seed.end]);
            }
        }

        let mut added = Vec::new();
        added.extend(self.emails_in_decoded(&decoded, &emails, &mut names));
        added.extend(self.header_spans(&decoded, &mut names));
        added.extend(self.greeting_spans(&decoded, &mut names));
        added.extend(self.signoff_spans(&decoded, &mut names));
        added.extend(self.line_name_spans(&decoded, &mut names));
        added.extend(self.speech_spans(&decoded, &mut names));
        added.extend(self.dob_spans(&decoded));
        added.extend(self.tracking_spans(text));
        added.extend(self.propagate(&decoded, &names, &emails));
        added.extend(company_id::recognize(text));

        let mut all = candidates;
        all.extend(added);
        if !self.mask_first_names {
            all.retain(|span| self.keep_person_span(text, span, &names));
        }
        self.filter_public(text, all)
    }

    /// Whether a `PERSON` seed may seed propagation.
    ///
    /// A single-token model `PERSON` only seeds when it is not a bare given
    /// name; with first names off a bare given name seeds nothing. Every rule
    /// seed, every multi-token model span, every signature/header name, every
    /// known surname and every CJK span always seeds.
    fn keep_person_seed(&self, text: &str, seed: &Span, names: &NameSet<'_>) -> bool {
        if self.mask_first_names {
            return true;
        }
        !self.drops_lone_given_name(text, seed, names)
    }

    /// Whether a `PERSON` candidate survives the bare-first-name rule.
    ///
    /// Only a single-token model span can be dropped: a full name, a rule span
    /// (a header display name is HIGH), a signature/header name, a known surname,
    /// a CJK name or an ALL-CAPS surname always survives.
    fn keep_person_span(&self, text: &str, span: &Span, names: &NameSet<'_>) -> bool {
        if self.mask_first_names || span.kind != EntityKind::Person {
            return true;
        }
        !self.drops_lone_given_name(text, span, names)
    }

    /// Whether a model `PERSON` span is a lone bare given name the default
    /// (first-names-off) policy drops.
    ///
    /// Every condition of [`leaves_lone_name_in_clear`] must hold to drop the
    /// span, including the vocative or address position; any doubt keeps it, so
    /// the rule fails toward masking. The span must additionally be a
    /// single-token `gliner` `PERSON` — a rule span or a name the lexicon does
    /// not know is never dropped this way.
    fn drops_lone_given_name(&self, text: &str, span: &Span, names: &NameSet<'_>) -> bool {
        if span.kind != EntityKind::Person || span.recognizer != "gliner" {
            return false;
        }
        if !well_formed(text, span) || name_token_count(text, span) != 1 {
            return false;
        }
        leaves_lone_name_in_clear(text, span.start, span.end, names)
    }

    /// Detect e-mail addresses on the decoded view and seed their local parts.
    fn emails_in_decoded(
        &self,
        decoded: &DecodedText,
        emails: &[Span],
        names: &mut NameSet<'_>,
    ) -> Vec<Span> {
        let mut spans = Vec::new();
        for span in emails {
            let Some((start, end)) = decoded.source_bounds(span.start, span.end) else {
                continue;
            };
            let value = &decoded.text()[span.start..span.end];
            if let Some((local, _)) = value.split_once('@') {
                names.add_local_part(local);
            }
            spans.push(Span::new(
                EntityKind::Email,
                start,
                end,
                span.score,
                "email_layer",
            ));
        }
        spans
    }

    /// Display names in sender headers and reply lines.
    fn header_spans(&self, decoded: &DecodedText, names: &mut NameSet<'_>) -> Vec<Span> {
        let text = decoded.text();
        let mut spans = Vec::new();
        for (line_start, line_end) in line_ranges(text) {
            let line = &text[line_start..line_end];
            let Some((start, end, tokens)) = display_name(line, names) else {
                continue;
            };
            let value = &text[line_start + start..line_start + end];
            if value.is_empty() {
                continue;
            }
            let raws: Vec<&str> = tokens
                .iter()
                .map(|token| &line[token.start..token.end])
                .collect();
            names.add_strong_phrase(&raws);
            if let Some((orig_start, orig_end)) =
                decoded.source_bounds(line_start + start, line_start + end)
            {
                spans.push(Span::new(
                    EntityKind::Person,
                    orig_start,
                    orig_end,
                    RULE_SCORE,
                    "email_layer_header",
                ));
            }
        }
        spans
    }

    /// Names named directly by a greeting.
    fn greeting_spans(&self, decoded: &DecodedText, names: &mut NameSet<'_>) -> Vec<Span> {
        let text = decoded.text();
        let mut spans = Vec::new();
        for (line_start, line_end) in line_ranges(text) {
            let line = &text[line_start..line_end];
            let offset = strip_quote_prefix(line);
            let body = &line[offset..];
            let Some(greeting_end) = starts_with_greeting(body) else {
                continue;
            };
            let rest = &body[greeting_end..];
            let rest_offset = skip_separators(rest);
            let value = &rest[rest_offset..];
            let picked = pick_rule_tokens(value, names, 2);
            let (Some(first), Some(last_token)) = (picked.first(), picked.last()) else {
                continue;
            };
            // A greeting name is capitalised ("Bonjour Élise") or ends the greeting
            // phrase ("bonjour hugo,"). A lower-case run followed by more words is
            // the sentence ("Bonjour, ceci est un plan"), not a name.
            let capitalised = value[first.start..].starts_with(char::is_uppercase);
            let ends_phrase = value[last_token.end..]
                .trim_start()
                .chars()
                .next()
                .is_none_or(|ch| !ch.is_alphanumeric());
            if !capitalised && !ends_phrase {
                continue;
            }
            let raws: Vec<&str> = picked
                .iter()
                .map(|token| &rest[rest_offset + token.start..rest_offset + token.end])
                .collect();
            names.add_rule_phrase(&raws);
            let begin = line_start + offset + greeting_end + rest_offset + picked[0].start;
            let last =
                line_start + offset + greeting_end + rest_offset + picked.last().unwrap().end;
            if self.allow_lone_rule_span(names, text, begin, last, picked.len()) {
                push_person(decoded, begin, last, "email_layer_greeting", &mut spans);
            }
        }
        spans
    }

    /// The name line right after a closing, and the `ps:` author.
    fn signoff_spans(&self, decoded: &DecodedText, names: &mut NameSet<'_>) -> Vec<Span> {
        let text = decoded.text();
        let lines = line_ranges(text);
        let mut spans = Vec::new();
        for (index, (line_start, line_end)) in lines.iter().enumerate() {
            let line = &text[*line_start..*line_end];
            let stripped = strip_quote_prefix(line);
            let candidate = line[stripped..].trim();
            if candidate.is_empty() {
                continue;
            }
            // `P.S.` / `PS` / `NB` author on the same line. `rest` runs to the end
            // of `line`, so `line.len() - rest.len()` is its exact offset.
            if let Some(rest) = ps_rest(line) {
                let offset = line.len() - rest.len();
                let picked = pick_rule_tokens(rest, names, 2);
                if !picked.is_empty() {
                    let raws: Vec<&str> = picked
                        .iter()
                        .map(|token| &rest[token.start..token.end])
                        .collect();
                    names.add_rule_phrase(&raws);
                    let begin = line_start + offset + picked[0].start;
                    let last = line_start + offset + picked.last().unwrap().end;
                    if self.allow_lone_rule_span(names, text, begin, last, picked.len()) {
                        push_person(decoded, begin, last, "email_layer_ps", &mut spans);
                    }
                }
                continue;
            }
            // A closing line or a `--` separator opens the signature block.
            let separator = matches!(candidate, "--" | "---" | "—" | "––");
            let closing = word_tokens(candidate).len() <= 6 && is_closing(candidate);
            if !closing && !separator {
                continue;
            }
            let Some((next_start, next_end)) = next_signoff_line(&lines, index + 1, text) else {
                continue;
            };
            let raw = &text[next_start..next_end];
            // The name is the part before a title or department that a comma
            // introduces ("Dr. H. Nel, Sonnekus Konsultante").
            let value = trim_signature_prefix(raw)
                .split([',', '\u{060C}'])
                .next()
                .unwrap_or("")
                .trim_end();
            if value.is_empty() {
                continue;
            }
            let tokens = word_tokens(value);
            if tokens.is_empty() || tokens.len() > 4 {
                continue;
            }
            if value.contains('@')
                || value.contains("://")
                || value.chars().any(|ch| ch.is_ascii_digit())
            {
                continue;
            }
            if !tokens.iter().any(|token| names.is_rule_name(token, value)) {
                continue;
            }
            names.add_rule_text(value, 4);
            let Some(offset) = raw.find(value) else {
                continue;
            };
            if self.allow_lone_rule_span(
                names,
                text,
                next_start + offset,
                next_start + offset + value.len(),
                tokens.len(),
            ) {
                push_person(
                    decoded,
                    next_start + offset,
                    next_start + offset + value.len(),
                    "email_layer_signoff",
                    &mut spans,
                );
            }
        }
        spans
    }

    /// A name at the very start of a line, followed by a comma.
    ///
    /// The body of a reply often opens with the addressee's first name right
    /// after the subject or header block (`Théo, peux-tu…`), in any language.
    fn line_name_spans(&self, decoded: &DecodedText, names: &mut NameSet<'_>) -> Vec<Span> {
        let text = decoded.text();
        let mut spans = Vec::new();
        for (line_start, line_end) in line_ranges(text) {
            let line = &text[line_start..line_end];
            let (offset, value) = content_after_prefix(line);
            if value.is_empty() {
                continue;
            }
            // A name may open the line itself, or sit right after a subject
            // header's colon ("Subject: Priya, …").
            let (base, candidate) = match subject_rest(value) {
                Some(rest) => {
                    let trimmed = rest.trim_start();
                    let shift = value.len() - rest.len() + (rest.len() - trimmed.len());
                    (offset + shift, trimmed)
                }
                None => (offset, value),
            };
            // The name is followed by a comma, ASCII or Arabic, optionally after
            // one space; everything before it is the address.
            let Some(comma) = candidate
                .char_indices()
                .find(|(_, ch)| matches!(ch, ',' | '\u{060C}'))
                .map(|(index, _)| index)
            else {
                continue;
            };
            let head = candidate[..comma].trim_end();
            // Code, JSON and markup never open a name line: `{"path":"C:\x", …`
            // or `` `read_file` (risk: low), `` is a value, not a person.
            if head.is_empty() || head.contains(['{', '}', '[', ']', '\\', '`', '=']) {
                continue;
            }
            // A question or a request is not an address.
            if is_question_opening(head) {
                continue;
            }
            let picked = pick_rule_tokens(head, names, 4);
            if picked.is_empty() {
                continue;
            }
            // Latin script: the comma follows the name directly. A line whose
            // first comma sits deep in other words (`uid 12 · Thanks, …`, a
            // date `Thu, 15 Oct`) is a record or a sentence, not an address,
            // unless it opens with a full name (`Owen Calder works at …, `).
            if is_latin_head(head)
                && has_words_beyond_the_name(head, &picked)
                && !opens_with_a_name(head, &picked)
            {
                continue;
            }
            // A capitalized stop word can open a real first name ("Will,"), but
            // not when a second name-shaped word follows it: that is an article
            // phrase ("Le dossier,"), not a person.
            if picked.len() > 1
                && picked
                    .first()
                    .is_some_and(|token| names.is_weak_filtered(&token.folded))
            {
                continue;
            }
            let raws: Vec<&str> = picked
                .iter()
                .map(|token| &head[token.start..token.end])
                .collect();
            names.add_rule_phrase(&raws);
            // An ordinary name line masks just the name tokens. A short chat
            // clause that opens the body (`лол файл от павла опять не пришёл, …`)
            // has no comma-delimited name, so mask the whole clause: it is
            // bounded (<= 12 word tokens), carries no address, header or digit
            // field, and failing toward masking a clause that holds a lowercase
            // personal name beats leaking it. A sentence, an address line or a
            // data row stays on the picked name tokens only.
            let head_tokens = word_tokens(head);
            // Latin script: a vocative is at most three name-shaped words, none
            // a function or question word; a longer head is a sentence
            // (`Can you check my calendar, please?`). Other scripts keep the
            // short-clause rule.
            let plain_clause = head_tokens.len() <= 12
                && (!is_latin_head(head)
                    || (head_tokens.len() <= 3
                        && !head_tokens.iter().any(|token| {
                            FUNCTION_WORDS.contains(&token.folded.as_str())
                                || QUESTION_OPENERS.contains(&token.folded.as_str())
                        })))
                && !head
                    .chars()
                    .any(|ch| matches!(ch, '@' | ':' | '/' | '|' | '\\') || ch.is_ascii_digit());
            let (begin, end) = if plain_clause {
                (line_start + base, line_start + base + head.len())
            } else {
                (
                    line_start + base + picked[0].start,
                    line_start + base + picked.last().unwrap().end,
                )
            };
            let token_count = if plain_clause {
                head_tokens.len()
            } else {
                picked.len()
            };
            if self.allow_lone_rule_span(names, text, begin, end, token_count) {
                push_person(decoded, begin, end, "email_layer_line_name", &mut spans);
            }
        }
        spans
    }

    /// The speaker a speech verb names: `X said`, `X a dit`, `X сказала`,
    /// `X azt mondta`, `X het gesê`, or the verb-first Arabic `قال X`.
    fn speech_spans(&self, decoded: &DecodedText, names: &mut NameSet<'_>) -> Vec<Span> {
        let text = decoded.text();
        let mut spans = Vec::new();
        for (line_start, line_end) in line_ranges(text) {
            let line = &text[line_start..line_end];
            let (lowered, map) = lower_mapped(line);
            if lowered.len() != line.len() {
                // `to_lowercase` changed the line's byte length (an exotic code
                // point): main skips the line, and so does this pass.
                continue;
            }
            for (verb, name_before) in SPEECH_VERBS {
                let Some(at) = lowered.find(*verb) else {
                    continue;
                };
                if !is_token_boundary(&lowered, at, verb.len()) {
                    continue;
                }
                // Equal lengths do not mean equal offsets (`İ` grows, `ẞ`
                // shrinks): slice `line` at the mapped bytes.
                let (Some(from), Some(to)) =
                    (original_at(&map, at), original_at(&map, at + verb.len()))
                else {
                    continue;
                };
                let value = if *name_before {
                    &line[..from]
                } else {
                    &line[to..]
                };
                let tokens = word_tokens(value);
                let ordered: Vec<WordToken> = if *name_before {
                    tokens.into_iter().rev().collect()
                } else {
                    tokens
                };
                // Walk out from the verb: skip a title or an initial, take the
                // name-shaped words, and stop at the first weaker word, so the
                // speaker is the run touching the verb.
                let mut picked: Vec<WordToken> = Vec::new();
                for token in ordered {
                    let folded = token.folded.as_str();
                    if TITLES.contains(&folded) || !NameSet::is_name_like(folded) {
                        continue;
                    }
                    let raw = &value[token.start..token.end];
                    if names.is_rule_name(&token, raw) {
                        picked.push(token);
                        if picked.len() >= 2 {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if *name_before {
                    picked.reverse();
                }
                if picked.is_empty() {
                    continue;
                }
                let raws: Vec<&str> = picked
                    .iter()
                    .map(|token| &value[token.start..token.end])
                    .collect();
                names.add_rule_phrase(&raws);
                let base = if *name_before {
                    line_start
                } else {
                    line_start + to
                };
                let begin = base + picked[0].start;
                let last = base + picked.last().unwrap().end;
                if self.allow_lone_rule_span(names, text, begin, last, picked.len()) {
                    push_person(decoded, begin, last, "email_layer_speech", &mut spans);
                }
            }
        }
        spans
    }

    /// A birth date in a flattened table row, after a cue word.
    fn dob_spans(&self, decoded: &DecodedText) -> Vec<Span> {
        let text = decoded.text();
        let lines = line_ranges(text);
        let mut spans = Vec::new();
        for (index, (line_start, line_end)) in lines.iter().enumerate() {
            let line = &text[*line_start..*line_end];
            let (lowered, map) = lower_mapped(line);
            let Some(end) = DOB_CUES
                .iter()
                .find_map(|cue| lowered.find(cue).map(|at| at + cue.len()))
            else {
                continue;
            };
            // A lowered offset is no `line` offset when lower-casing changes a
            // character's byte length (`İDOBé`): read on from the byte it maps
            // to and, as main did, from the same offset when that is a
            // character boundary of `line` too.
            let mapped = original_at(&map, end);
            let same = (mapped != Some(end) && line.is_char_boundary(end)).then_some(end);
            for cue in mapped.into_iter().chain(same) {
                let found = find_date(&line[cue..], line_start + cue).or_else(|| {
                    let (next_start, next_end) = next_content_line(&lines, index + 1, text)?;
                    find_date(&text[next_start..next_end], next_start)
                });
                if let Some((start, end)) = found {
                    if let Some((orig_start, orig_end)) = decoded.source_bounds(start, end) {
                        spans.push(Span::new(
                            EntityKind::DateOfBirth,
                            orig_start,
                            orig_end,
                            RULE_SCORE,
                            "email_layer_dob",
                        ));
                    }
                }
            }
        }
        spans
    }

    /// Mask the whole value of a tracking or unsubscribe query parameter.
    fn tracking_spans(&self, text: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        for (url_start, url_end) in crate::decode::url_ranges(text) {
            let url = &text[url_start..url_end];
            let Some(question) = url.find('?') else {
                continue;
            };
            let mut offset = question + 1;
            for pair in url[question + 1..].split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    let folded = fold(key.trim());
                    if TRACKING_KEYS.contains(&folded.as_str()) && !value.is_empty() {
                        let value_start = url_start + offset + key.len() + 1;
                        let value_end = value_start + value.len();
                        let decoded = DecodedText::new(&text[value_start..value_end]);
                        let kind = if decoded.text().contains('@') {
                            EntityKind::Email
                        } else {
                            EntityKind::Person
                        };
                        spans.push(Span::new(
                            kind,
                            value_start,
                            value_end,
                            RULE_SCORE,
                            "email_layer_url",
                        ));
                    }
                }
                offset += pair.len() + 1;
            }
        }
        spans
    }

    /// Mask every other occurrence of a seeded name token.
    ///
    /// Three rules, in the order the maintainer fixed them:
    ///
    /// * (c) a token from a strong seed that is not structural always propagates
    ///   (over stop words and public terms); a bare given name alone propagates
    ///   only when [`EmailLayer::with_first_names`] is on;
    /// * (a) a structural token that is part of a strong seed's full sequence is
    ///   masked with it, in any order of given and family name, with an initial
    ///   (`J. De`, `De J.`) or an honorific (`M. De`);
    /// * (b) a structural token from a strong seed is masked alone only in the
    ///   exact spelling the seed used, off a line or sentence start and not
    ///   followed by a lower-case word.
    fn propagate(&self, decoded: &DecodedText, names: &NameSet<'_>, emails: &[Span]) -> Vec<Span> {
        if names.is_empty() {
            return Vec::new();
        }
        let text = decoded.text();
        let tokens = word_tokens(text);
        let mut masked = vec![false; tokens.len()];

        for (index, token) in tokens.iter().enumerate() {
            if names.is_always(&token.folded)
                || (self.mask_first_names && names.is_given(&token.folded))
            {
                masked[index] = true;
            }
        }
        mark_sequences(&tokens, text, &names.sequences, &mut masked);
        mark_honorifics(&tokens, text, names, &mut masked);
        for (index, slot) in masked.iter_mut().enumerate() {
            *slot |= names.is_lone_structural(text, &tokens, index);
        }
        // A token inside an e-mail address is masked as part of that address.
        // It must not join a name phrase that precedes it: the display name and
        // the address stay two regions (and two tokens) even when the address
        // local part repeats the name.
        // Sorted by start, with the running maximum end: one search per token.
        let mut emails: Vec<(usize, usize)> = emails.iter().map(|e| (e.start, e.end)).collect();
        emails.sort_unstable();
        let ends: Vec<usize> = emails
            .iter()
            .scan(0, |reach, &(_, end)| {
                *reach = end.max(*reach);
                Some(*reach)
            })
            .collect();
        for (index, token) in tokens.iter().enumerate() {
            let before = emails.partition_point(|&(start, _)| start < token.end);
            if before > 0 && ends[before - 1] > token.start {
                masked[index] = false;
            }
        }

        let mut matches: Vec<(usize, usize)> = Vec::new();
        for (index, token) in tokens.iter().enumerate() {
            if !masked[index] {
                continue;
            }
            if let Some(last) = matches.last_mut() {
                let gap = &text[last.1..token.start];
                if gap.len() <= 4 && gap.chars().all(is_word_separator) {
                    last.1 = token.end;
                    continue;
                }
            }
            matches.push((token.start, token.end));
        }
        let mut spans = Vec::new();
        for (start, mut end) in matches {
            // A masked initial keeps its dot, so `De J.` masks as written.
            if end < text.len()
                && text[end..].starts_with('.')
                && text[..end]
                    .chars()
                    .rev()
                    .take_while(|ch| ch.is_alphanumeric())
                    .count()
                    == 1
            {
                end += 1;
            }
            if let Some((orig_start, orig_end)) = decoded.source_bounds(start, end) {
                spans.push(Span::new(
                    EntityKind::Person,
                    orig_start,
                    orig_end,
                    PROPAGATION_SCORE,
                    "email_layer_name",
                ));
            }
        }
        spans
    }

    /// Drop a model organisation or address span whose value is a public term.
    fn filter_public(&self, text: &str, spans: Vec<Span>) -> Vec<Span> {
        let private_present = spans.iter().any(|span| is_private_signal(span.kind));
        if private_present {
            return spans;
        }
        spans
            .into_iter()
            .filter(|span| {
                if !matches!(span.kind, EntityKind::Organization | EntityKind::Address) {
                    return true;
                }
                if !well_formed(text, span) {
                    return true;
                }
                !self.public_terms.contains(&text[span.start..span.end])
            })
            .collect()
    }

    /// Whether a rule-detected span may be emitted as a person.
    ///
    /// With bare-first-name masking on, every rule span is kept. With it off, a
    /// span of two or more name tokens is a full name. A lone token is kept
    /// unless [`leaves_lone_name_in_clear`] proves it is a bare given name: a
    /// known given name, not a known surname, in a vocative or address position,
    /// outside signature or header context. A token the lexicons do not know is
    /// **never** dropped here — an unknown rule token stays masked.
    fn allow_lone_rule_span(
        &self,
        names: &NameSet<'_>,
        text: &str,
        start: usize,
        end: usize,
        token_count: usize,
    ) -> bool {
        if self.mask_first_names || token_count >= 2 {
            return true;
        }
        !leaves_lone_name_in_clear(text, start, end, names)
    }
}

impl Default for EmailLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a kind is a private signal that keeps public-term model spans.
fn is_private_signal(kind: EntityKind) -> bool {
    !matches!(
        kind,
        EntityKind::Organization | EntityKind::Address | EntityKind::Url
    )
}

/// Whether a span lies inside `text` on char boundaries.
fn well_formed(text: &str, span: &Span) -> bool {
    span.start < span.end
        && span.end <= text.len()
        && text.is_char_boundary(span.start)
        && text.is_char_boundary(span.end)
}

/// Push a person span mapped back to the original bytes.
fn push_person(
    decoded: &DecodedText,
    start: usize,
    end: usize,
    recognizer: &'static str,
    spans: &mut Vec<Span>,
) {
    if let Some((orig_start, orig_end)) = decoded.source_bounds(start, end) {
        spans.push(Span::new(
            EntityKind::Person,
            orig_start,
            orig_end,
            RULE_SCORE,
            recognizer,
        ));
    }
}

/// The bytes of each line, without the trailing newline.
fn line_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0usize;
    for (index, ch) in text.char_indices() {
        if ch == '\n' {
            ranges.push((start, index));
            start = index + 1;
        }
    }
    if start < text.len() {
        ranges.push((start, text.len()));
    }
    ranges
}

/// The next line that holds something other than quote markers.
fn next_content_line(lines: &[(usize, usize)], from: usize, text: &str) -> Option<(usize, usize)> {
    for (start, end) in lines.iter().skip(from) {
        let line = &text[*start..*end];
        if !line.trim().trim_start_matches(['>', ' ', '\t']).is_empty() {
            return Some((*start, *end));
        }
    }
    None
}

/// The next line of a sign-off block that may name the author.
///
/// Like [`next_content_line`], but it also steps over the emoji-only or
/// title-only lines a closing and its name can have between them
/// (`Mit freundlichen Grüßen` / `😊` / `Mila`), up to a bounded count.
fn next_signoff_line(lines: &[(usize, usize)], from: usize, text: &str) -> Option<(usize, usize)> {
    let mut skipped = 0usize;
    for (start, end) in lines.iter().skip(from) {
        let line = &text[*start..*end];
        let body = line[strip_quote_prefix(line)..].trim();
        if body.is_empty() {
            continue;
        }
        if skipped < 4 && is_signoff_noise(body) {
            skipped += 1;
            continue;
        }
        return Some((*start, *end));
    }
    None
}

/// Whether a non-empty sign-off line is an emoji-only or title-only line rather
/// than the author's name.
fn is_signoff_noise(body: &str) -> bool {
    if !body.chars().any(char::is_alphanumeric) {
        return true;
    }
    let tokens = word_tokens(body);
    !tokens.is_empty()
        && tokens.iter().all(|token| {
            is_honorific(&token.folded) || TITLES.iter().any(|t| fold(t) == token.folded)
        })
}

/// A word token of the decoded text.
struct WordToken {
    start: usize,
    end: usize,
    folded: String,
}

/// Split `text` into Unicode word tokens (a combining mark stays inside its
/// token).
fn word_tokens(text: &str) -> Vec<WordToken> {
    let mut tokens = Vec::new();
    let mut current: Option<usize> = None;
    for (index, ch) in text.char_indices() {
        if ch.is_alphanumeric() || unicode_normalization::char::is_combining_mark(ch) {
            current.get_or_insert(index);
        } else if let Some(start) = current.take() {
            tokens.push(token(text, start, index));
        }
    }
    if let Some(start) = current {
        tokens.push(token(text, start, text.len()));
    }
    tokens
}

/// Build one token.
fn token(text: &str, start: usize, end: usize) -> WordToken {
    WordToken {
        start,
        end,
        folded: fold(&text[start..end]),
    }
}

/// Whether a character may join a first name to its surname.
fn is_word_separator(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '\t' | '\n' | '\r' | '-' | '_' | '.' | '+' | '\'' | '’'
    )
}

/// Whether `start` opens a line or a sentence (so a lone structural token there
/// is an article or a label, never a surname).
///
/// A bullet marker, a dash or a list number opens a line just like `\n`: the
/// P3 over-masking round found a lone structural token after `•`, `-`, `*`, `>`
/// or `1.` / `a)` being masked as if it were a surname.
fn opens_line_or_sentence(text: &str, start: usize) -> bool {
    for ch in text[..start].chars().rev() {
        if ch == '\n' {
            return true;
        }
        if ch.is_whitespace() {
            continue;
        }
        return matches!(ch, '.' | '!' | '?' | ';' | ':' | ')') || is_bullet_marker(ch);
    }
    true
}

/// Whether a character is a bullet or list marker that opens a line.
fn is_bullet_marker(ch: char) -> bool {
    matches!(
        ch,
        '•' | '·' | '◦' | '▪' | '‣' | '⁃' | '–' | '—' | '-' | '*' | '>'
    )
}

/// Whether a raw token is an ALL-CAPS surname (`DUPONT`).
fn is_all_caps_surname(raw: &str) -> bool {
    let letters = raw.chars().filter(|ch| ch.is_alphabetic()).count();
    letters >= 2 && !raw.chars().any(char::is_lowercase)
}

/// How many word tokens a person span holds.
fn name_token_count(text: &str, span: &Span) -> usize {
    if span.start >= span.end
        || span.end > text.len()
        || !text.is_char_boundary(span.start)
        || !text.is_char_boundary(span.end)
    {
        return 0;
    }
    word_tokens(&text[span.start..span.end]).len()
}

/// Whether the last non-initial word before `start` on the same line is an
/// honorific (`Dr. H. Nel` keeps `Nel`).
fn preceded_by_honorific(text: &str, start: usize) -> bool {
    let line_start = text[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let tokens = word_tokens(&text[line_start..start]);
    for token in tokens.iter().rev() {
        if token.folded.chars().count() == 1 {
            continue;
        }
        return is_honorific(&token.folded);
    }
    false
}

/// Whether the byte range `start..end` sits on a signature or header line.
///
/// Signature and header context always keeps a span, whatever its token count:
/// a sender or recipient header (`From`, `To`, `Cc`, `De`, `Van`, `Von`, `От`,
/// `Feladó`, `من`, `发件人`), a reply or speech line (`a écrit`, `wrote:`, `said`),
/// a `Name <email>` display name, or a line inside a signature block (a closing
/// or a `--` separator in the lines above).
fn is_signature_or_header_range(text: &str, start: usize, end: usize) -> bool {
    if start >= end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return false;
    }
    let line_start = text[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let line_end = text[start..]
        .find('\n')
        .map(|at| start + at)
        .unwrap_or(text.len());
    let line = &text[line_start..line_end];
    // A `P.S.` / `PS` / `NB` author is a signature name, whatever the line says.
    if is_ps_or_nb_line(line) {
        return true;
    }
    let body = &line[strip_quote_prefix(line)..];
    let lowered = body.to_lowercase();
    if SENDER_KEYS.iter().any(|key| {
        lowered
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    }) {
        return true;
    }
    if REPLY_VERBS
        .iter()
        .copied()
        .chain(SPEECH_VERBS.iter().map(|(verb, _)| *verb))
        .any(|verb| lowered.contains(verb))
    {
        return true;
    }
    // A `Name <local@domain>` display name: the span is the name before the
    // angle address, even without a header key.
    let before_angle_address = body.find('<').is_some_and(|angle| {
        body[angle..].contains('@') && end <= line_start + strip_quote_prefix(line) + angle
    });
    if before_angle_address {
        return true;
    }
    // A signature block: a closing line or a `--` separator in the lines above.
    // GATE-PERF-1: walk up from this line instead of splitting the whole text,
    // so a text of many short lines costs linear time, not lines × bytes.
    let mut seen = 0usize;
    let mut cursor = line_start;
    while cursor > 0 {
        let line_end_above = cursor - 1;
        let line_start_above = text[..line_end_above].rfind('\n').map_or(0, |at| at + 1);
        cursor = line_start_above;
        let candidate = text[line_start_above..line_end_above].trim();
        if candidate.is_empty() {
            continue;
        }
        seen += 1;
        if seen > 6 {
            break;
        }
        if matches!(candidate, "--" | "---" | "—" | "––")
            || (word_tokens(candidate).len() <= 6 && is_closing(candidate))
            || is_ps_or_nb_line(candidate)
        {
            return true;
        }
    }
    false
}

/// Whether the lone name `start..end` may stay in clear under the default
/// (first-names-off) policy.
///
/// The lexicons alone are not evidence enough. A lone token is left in clear
/// only when **all** of these hold:
///
/// * it is a known given name in the closed lexicon and **not** a known surname
///   (the surname list carries every verified given/surname collision);
/// * it sits in a vocative or address position ([`in_vocative_or_address`]):
///   right after a greeting or a thanks word that closes its clause, or at the
///   start of a line followed by a comma;
/// * it is not on a signature or header line (`From`/`To`/`Cc`, a reply line, a
///   closing block, a `Name <email>` pair, a `P.S.`/`PS`/`NB` author);
/// * it is not ALL-CAPS, not honorific-led, not a surname a strong seed already
///   carries, and not CJK.
///
/// Everywhere else the span is masked, whatever the lexicons say: running text,
/// an NER singleton outside a vocative position, and a rule token the given-name
/// lexicon does not know.
fn leaves_lone_name_in_clear(text: &str, start: usize, end: usize, names: &NameSet<'_>) -> bool {
    if start >= end
        || end > text.len()
        || !text.is_char_boundary(start)
        || !text.is_char_boundary(end)
    {
        return false;
    }
    let raw = &text[start..end];
    if is_cjk_script(raw)
        || is_all_caps_surname(raw)
        || preceded_by_honorific(text, start)
        || is_signature_or_header_range(text, start, end)
    {
        return false;
    }
    let folded = fold(raw);
    if names.is_always(&folded) || name_lexicon::is_surname(&folded) {
        return false;
    }
    name_lexicon::is_given_name(&folded) && in_vocative_or_address(text, start, end)
}

/// Whether `start..end` is a vocative or address position: right after a
/// greeting or a thanks word that closes its clause (`Salut Jules`, `Hi Mila,`,
/// `merci Mila`), or at the start of a line followed by a comma (`Jules, peux-tu`).
///
/// A greeting or thanks word followed by a sentence (`Hi, Mila was called`,
/// `Hello Mila said`) is not an address: the name is the subject of that sentence
/// and stays masked. A `P.S.`, `PS` or `NB` author is a signature line, not a
/// vocative, so it never reaches this check (see [`is_ps_or_nb_line`]).
fn in_vocative_or_address(text: &str, start: usize, end: usize) -> bool {
    let line_start = text[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
    let before = &text[line_start..start];
    let offset = strip_quote_prefix(before);
    let lead = &before[offset..];
    if preceded_by_address_lead(lead) && closes_address_clause(text, end) {
        return true;
    }
    // A name that opens the line and is followed by a comma (`Jules, peux-tu`).
    if lead.trim().is_empty() {
        let after = text[end..].trim_start_matches([' ', '\t']);
        if after.starts_with(',') || after.starts_with('\u{060C}') {
            return true;
        }
    }
    false
}

/// Whether the name ending at `end` closes its greeting or thanks clause: the
/// rest of its line is empty, or it is followed by a clause mark (`,` `!` `:`
/// `;` `.` `?`, or their CJK and Arabic forms). Any other word after the name
/// continues the sentence, so the name is its subject, not its addressee.
fn closes_address_clause(text: &str, end: usize) -> bool {
    let rest = text[end..].trim_start_matches([' ', '\t']);
    rest.chars()
        .next()
        .is_none_or(|ch| CLAUSE_MARKS.contains(ch))
}

/// Whether `line` is a `P.S.`, `PS` or `NB` line: a postscript or note whose
/// author is a signature name, so a name on it always stays masked.
fn is_ps_or_nb_line(line: &str) -> bool {
    ps_marker_end(line).is_some()
}

/// The byte offset in `line` just past its `P.S.` / `PS` / `NB` marker (quote
/// prefix and indent included), or `None`. The marker must end at a word
/// boundary, so `Psychologue` is not a postscript.
fn ps_marker_end(line: &str) -> Option<usize> {
    let indent = strip_quote_prefix(line);
    let lowered = line[indent..].to_lowercase();
    ["p.s.", "p.s", "ps", "nb"]
        .into_iter()
        .find(|marker| {
            lowered
                .strip_prefix(marker)
                .is_some_and(|after| after.chars().next().is_none_or(|ch| !ch.is_alphanumeric()))
        })
        .map(|marker| indent + marker.len())
}

/// Whether `lead` (the text before a name on its line, quote prefix removed) is a
/// greeting or a thanks word followed only by separators.
fn preceded_by_address_lead(lead: &str) -> bool {
    let trimmed = lead.trim_end();
    if trimmed.is_empty() {
        return false;
    }
    if let Some(greeting_end) = starts_with_greeting(trimmed) {
        let after = &trimmed[greeting_end..];
        if after.chars().all(|ch| {
            ch.is_whitespace() || matches!(ch, ',' | ':' | ';' | '.' | '!' | '?' | '-' | '–' | '—')
        }) {
            return true;
        }
    }
    let folded = fold(trimmed);
    if ADDRESS_THANKS
        .iter()
        .filter_map(|thanks| folded.strip_suffix(*thanks))
        .any(|prefix| {
            prefix
                .chars()
                .next_back()
                .is_none_or(|ch| !ch.is_alphanumeric())
        })
    {
        return true;
    }
    false
}

/// Whether `raw` holds a Han, CJK or Hangul character.
///
/// A `PERSON` span in one of these scripts is a full name or a surname the
/// bare-first-name rule cannot read, so it is always kept; so is a single Han
/// character that follows an honorific (`preceded_by_honorific`).
fn is_cjk_script(raw: &str) -> bool {
    raw.chars().any(|ch| {
        matches!(
            ch as u32,
            0x1100..=0x11FF   // Hangul Jamo
                | 0x2E80..=0x2EFF // CJK radicals
                | 0x3000..=0x303F // CJK punctuation
                | 0x3040..=0x30FF // Hiragana / Katakana
                | 0x3130..=0x318F // Hangul compatibility Jamo
                | 0x3400..=0x4DBF // CJK extension A
                | 0x4E00..=0x9FFF // CJK unified ideographs
                | 0xAC00..=0xD7AF // Hangul syllables
                | 0xF900..=0xFAFF // CJK compatibility ideographs
                | 0x20000..=0x2FA1F // CJK extensions B..F
        )
    })
}

/// Whether a folded token is an honorific a name may follow.
fn is_honorific(folded: &str) -> bool {
    folded == "m" || TITLES.iter().any(|title| fold(title) == folded)
}

/// Whether the bytes between two token bounds are only the short separators that
/// join a given name to its surname.
fn joined_by_separator(text: &str, from: usize, to: usize) -> bool {
    from <= to
        && text.is_char_boundary(from)
        && text.is_char_boundary(to)
        && text[from..to].chars().all(is_word_separator)
}

/// Mask an honorific and the seeded name right after it (`M. De`, `Dr Jean`).
fn mark_honorifics(tokens: &[WordToken], text: &str, names: &NameSet<'_>, masked: &mut [bool]) {
    for (index, pair) in tokens.windows(2).enumerate() {
        if !is_honorific(&pair[0].folded) {
            continue;
        }
        let next = &pair[1];
        let named = names.is_always(&next.folded)
            || names.is_given(&next.folded)
            || (names.structural.contains_key(&next.folded)
                && text[next.start..next.end]
                    .chars()
                    .next()
                    .is_some_and(char::is_uppercase));
        if named {
            masked[index] = true;
            masked[index + 1] = true;
        }
    }
}

/// Mask every occurrence of each strong seed's token sequence, in any order.
///
/// A seed token that is structural is only masked in its capitalised surname
/// shape: a lower-case article `de`/`le` belongs to every French mail, and the
/// seed's own sequence (`Jean De`) must not turn it into a name. A
/// non-structural seed token also matches a one-letter initial (`J. De`).
///
/// One pass per length, not per seed (K-REGISTRY-PERF: a pass each was
/// quadratic over a long log). A window token longer than one letter matches
/// only an equal seed token, so a window is compared only with the sequences
/// holding its rarest such token; a window of initials, with the sequences of
/// the same first letters. No other sequence can match it.
fn mark_sequences(tokens: &[WordToken], text: &str, seeds: &[Vec<String>], masked: &mut [bool]) {
    let mut seen: HashSet<&[String]> = HashSet::new();
    let mut lengths: Vec<usize> = Vec::new();
    let mut by_token: HashMap<(usize, &str), Vec<&[String]>> = HashMap::new();
    let mut by_initials: HashMap<Vec<char>, Vec<&[String]>> = HashMap::new();
    for sequence in seeds {
        if sequence.is_empty() || !seen.insert(sequence) {
            continue;
        }
        let length = sequence.len();
        if !lengths.contains(&length) {
            lengths.push(length);
        }
        let mut words: Vec<&str> = sequence.iter().map(String::as_str).collect();
        words.sort_unstable();
        words.dedup();
        for word in words {
            by_token.entry((length, word)).or_default().push(sequence);
        }
        let initials = first_letters(sequence.iter().map(String::as_str));
        by_initials.entry(initials).or_default().push(sequence);
    }
    for length in lengths {
        for (start, window) in tokens.windows(length).enumerate() {
            let rarest = window
                .iter()
                .filter(|token| token.folded.chars().count() != 1)
                .map(|token| by_token.get(&(length, token.folded.as_str())))
                .min_by_key(|found| found.map_or(0, Vec::len));
            let candidates = match rarest {
                Some(found) => found,
                None => by_initials.get(&first_letters(window.iter().map(|t| t.folded.as_str()))),
            };
            let Some(candidates) = candidates else {
                continue;
            };
            if candidates
                .iter()
                .any(|sequence| window_matches_any_order(sequence, window, text))
            {
                for slot in masked.iter_mut().skip(start).take(length) {
                    *slot = true;
                }
            }
        }
    }
}

/// The first letter of each word, sorted: the key two words lists must share
/// for one to match the other through initials.
fn first_letters<'w>(words: impl Iterator<Item = &'w str>) -> Vec<char> {
    let mut letters: Vec<char> = words.filter_map(|word| word.chars().next()).collect();
    letters.sort_unstable();
    letters
}

/// Whether `window` is a permutation of `sequence`, each pair allowed to match
/// with an initial.
fn window_matches_any_order(sequence: &[String], window: &[WordToken], text: &str) -> bool {
    if sequence.len() != window.len() {
        return false;
    }
    fn assign(
        sequence: &[String],
        window: &[WordToken],
        text: &str,
        index: usize,
        used: &mut [bool],
    ) -> bool {
        if index == sequence.len() {
            return true;
        }
        for slot in 0..window.len() {
            if used[slot] || !token_matches(&sequence[index], &window[slot], text) {
                continue;
            }
            used[slot] = true;
            if assign(sequence, window, text, index + 1, used) {
                return true;
            }
            used[slot] = false;
        }
        false
    }
    let mut used = vec![false; window.len()];
    assign(sequence, window, text, 0, &mut used)
}

/// Whether a window token matches one seed token.
fn token_matches(seed: &str, token: &WordToken, text: &str) -> bool {
    if STRUCTURAL_WORDS.contains(seed) {
        return token.folded == seed
            && text[token.start..token.end]
                .chars()
                .next()
                .is_some_and(char::is_uppercase);
    }
    token.folded == seed || initial_matches(seed, &token.folded)
}

/// Whether `folded` is a one-letter initial of the seed word.
fn initial_matches(seed: &str, folded: &str) -> bool {
    let mut seed_chars = seed.chars();
    let mut folded_chars = folded.chars();
    match (seed_chars.next(), folded_chars.next(), folded_chars.next()) {
        (Some(first), Some(only), None) => only == first,
        _ => false,
    }
}

/// The byte offset of the first character that is not a quote marker.
fn strip_quote_prefix(line: &str) -> usize {
    line.char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t' | '>'))
        .map(|(index, _)| index)
        .unwrap_or(line.len())
}

/// Trim quote markers, bullets and surrounding space from a line.
fn trim_signature_prefix(line: &str) -> &str {
    let offset = line
        .char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t' | '>' | '-' | '*' | '•'))
        .map(|(index, _)| index)
        .unwrap_or(line.len());
    line[offset..].trim()
}

/// Skip whitespace and the punctuation that separates a greeting from a name.
fn skip_separators(value: &str) -> usize {
    value
        .char_indices()
        .find(|(_, ch)| {
            !(ch.is_whitespace()
                || matches!(ch, ',' | ':' | ';' | '.' | '!' | '?' | '-' | '–' | '—'))
        })
        .map(|(index, _)| index)
        .unwrap_or(value.len())
}

/// Whether `line` starts with a greeting; returns the byte length of it.
fn starts_with_greeting(line: &str) -> Option<usize> {
    // A lowered length is no `line` length when lower-casing changes a
    // character's (`Hİ` -> `hi̇`): map it back, or there is no greeting.
    let (lowered, map) = lower_mapped(line);
    for greeting in GREETINGS {
        if let Some(after) = lowered.strip_prefix(greeting) {
            if after.chars().next().is_none_or(|ch| !ch.is_alphanumeric()) {
                if let Some(end) = original_at(&map, greeting.len()) {
                    return Some(end);
                }
            }
        }
    }
    None
}

/// Whether `line` starts with a closing word.
fn is_closing(line: &str) -> bool {
    let lowered = line.to_lowercase();
    CLOSINGS.iter().any(|closing| {
        lowered
            .strip_prefix(closing)
            .is_some_and(|after| after.chars().next().is_none_or(|ch| !ch.is_alphanumeric()))
    })
}

/// The author part of a `P.S.` / `PS` / `NB` line, as a slice of `line` that runs
/// to its end, or `None`.
fn ps_rest(line: &str) -> Option<&str> {
    let at = ps_marker_end(line)?;
    let rest = line[at..].trim_start_matches([':', '.', ' ', '\t']);
    (!rest.is_empty()).then_some(rest)
}

/// Whether the picked tokens open with a known given name, or with two
/// capitalized words: a name, not a record or a sentence.
fn opens_with_a_name(head: &str, picked: &[WordToken]) -> bool {
    picked
        .first()
        .is_some_and(|token| name_lexicon::is_given_name(&token.folded))
        || (picked.len() >= 2
            && picked.iter().take(2).all(|token| {
                head[token.start..token.end]
                    .chars()
                    .next()
                    .is_some_and(char::is_uppercase)
            }))
}

/// Whether `head` holds a word that is neither a picked name token, a title,
/// a one-letter initial nor a surname particle.
fn has_words_beyond_the_name(head: &str, picked: &[WordToken]) -> bool {
    word_tokens(head).iter().any(|token| {
        let folded = token.folded.as_str();
        !picked.iter().any(|name| name.start == token.start)
            && !TITLES.iter().any(|title| fold(title) == folded)
            && folded.chars().count() > 1
            && !STRUCTURAL_PARTICLES.contains(&folded)
    })
}

/// Whether a line head is written in a Latin script (it holds an ASCII letter).
fn is_latin_head(head: &str) -> bool {
    head.chars().any(|ch| ch.is_ascii_alphabetic())
}

/// Whether a line head opens like a question or a request (see
/// [`QUESTION_OPENERS`]) or holds a function word after a capitalized opener.
fn is_question_opening(head: &str) -> bool {
    let Some(first) = word_tokens(head).into_iter().next() else {
        return false;
    };
    if !is_latin_head(head) {
        return false;
    }
    QUESTION_OPENERS.contains(&first.folded.as_str())
        || (FUNCTION_WORDS.contains(&first.folded.as_str())
            && !STRUCTURAL_PARTICLES.contains(&first.folded.as_str())
            && word_tokens(head).len() > 1)
}

/// Collect up to `max` name tokens from the front of `value`.
///
/// A rule that names a person (a greeting, a sign-off, a header, a line-initial
/// comma, a speech verb) is strong evidence, so a capitalized stop word or public
/// term is still taken as a name. A lower-case function word ends the run: it
/// would seed a modal verb or an article from every mail.
fn pick_rule_tokens(value: &str, names: &NameSet<'_>, max: usize) -> Vec<WordToken> {
    let mut picked = Vec::new();
    // A surname particle (`van`, `al`, `Mac`) is not a name on its own, but it
    // joins the name that follows; hold it until a name-shaped token confirms
    // the phrase (`van der Berg`).
    let mut pending: Vec<WordToken> = Vec::new();
    for token in word_tokens(value) {
        if picked.len() >= max {
            break;
        }
        let folded = token.folded.as_str();
        if TITLES.iter().any(|title| fold(title) == folded) || !NameSet::is_name_like(folded) {
            // A title or a one-letter initial never seeds on its own, but it
            // does not end the name either ("Dr. H. Nel").
            continue;
        }
        let raw = &value[token.start..token.end];
        if names.is_rule_name(&token, raw) {
            let room = max.saturating_sub(picked.len() + 1);
            for (index, particle) in pending.drain(..).enumerate() {
                if index >= room {
                    break;
                }
                picked.push(particle);
            }
            pending.clear();
            if picked.len() >= max {
                break;
            }
            picked.push(token);
        } else if STRUCTURAL_PARTICLES.contains(&folded) {
            pending.push(token);
        } else {
            break;
        }
    }
    picked
}

/// The first non-prefix character of a line and the trimmed content from there.
fn content_after_prefix(line: &str) -> (usize, &str) {
    let offset = line
        .char_indices()
        .find(|(_, ch)| !matches!(ch, ' ' | '\t' | '>' | '-' | '*' | '•'))
        .map(|(index, _)| index)
        .unwrap_or(line.len());
    (offset, line[offset..].trim())
}

/// Whether `line` (already trimmed) is a subject header.
fn subject_rest(line: &str) -> Option<&str> {
    let lowered = line.to_lowercase();
    let is_subject = SUBJECT_KEYS.iter().any(|key| {
        lowered
            .strip_prefix(*key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    });
    if !is_subject {
        return None;
    }
    let colon = line.find(':')?;
    Some(&line[colon + 1..])
}

/// Whether the byte range `start..start + len` in `text` is a whole word.
fn is_token_boundary(text: &str, start: usize, len: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[start + len..].chars().next();
    let free = |ch: Option<char>| ch.is_none_or(|value| !value.is_alphanumeric());
    free(before) && free(after)
}

/// The display name of a sender header or a reply line: its byte range inside
/// `line` plus the tokens that seed propagation.
///
/// A structural token that lies inside the picked run or directly after it is
/// the surname the seed was cut at ("Jean De", "Jean de la Cruz"), so it seeds
/// too. A structural token before the first picked token is an article or a
/// header label ("De : Le Monde" names "Monde"), so it does not.
fn display_name(line: &str, names: &NameSet<'_>) -> Option<(usize, usize, Vec<WordToken>)> {
    let offset = strip_quote_prefix(line);
    let body = &line[offset..];
    let lowered = body.to_lowercase();
    let is_sender = SENDER_KEYS.iter().any(|key| {
        lowered
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    });
    let is_reply = REPLY_VERBS
        .iter()
        .copied()
        .chain(SPEECH_VERBS.iter().map(|(verb, _)| *verb))
        .any(|verb| lowered.contains(verb));
    if !is_sender && !is_reply {
        return None;
    }
    let mut picked: Vec<WordToken> = Vec::new();
    // The region the picked run lives in, and the shift that maps one of its
    // tokens back to a `body` offset.
    let (region, shift): (&str, usize);
    if let Some(angle) = body.find('<') {
        region = &body[..angle];
        shift = 0;
        for token in word_tokens(region).into_iter().rev() {
            if STRUCTURAL_WORDS.contains(&token.folded) {
                // A header label or an article is not part of the name
                // ("De : Le Monde" names "Monde"); skip it and keep walking.
                continue;
            }
            if picked.len() >= 4 || !names.is_rule_name(&token, body) {
                break;
            }
            picked.push(token);
        }
    } else if is_sender {
        let start = body.find(':').map(|colon| colon + 1).unwrap_or(0);
        // A sender without an angle address can still carry a bracketed
        // `[mailto:…]`: stop the display name before it, so the person span
        // never reaches into the address.
        let value = &body[start..];
        let cut = value
            .char_indices()
            .find(|(_, ch)| matches!(ch, '[' | '<' | '(' | '|'))
            .map(|(index, _)| index)
            .unwrap_or(value.len());
        region = &value[..cut];
        shift = start;
        for mut token in word_tokens(region) {
            if STRUCTURAL_WORDS.contains(&token.folded) {
                continue;
            }
            if picked.len() >= 4 || !names.is_rule_name(&token, value) {
                break;
            }
            token.start += start;
            token.end += start;
            picked.push(token);
        }
    } else {
        return None;
    }
    if picked.is_empty() {
        return None;
    }
    let mut begin = picked.iter().map(|token| token.start).min()?;
    let mut end = picked.iter().map(|token| token.end).max()?;
    // Keep the structural tokens that belong to the run: the interior ones, plus
    // the trailing run a surname may form right before the address.
    let mut seeds: Vec<WordToken> = Vec::new();
    for token in word_tokens(region) {
        if !STRUCTURAL_WORDS.contains(&token.folded) {
            continue;
        }
        let start = token.start + shift;
        let stop = token.end + shift;
        if start < begin || !joined_by_separator(body, end.min(start), start) {
            continue;
        }
        end = end.max(stop);
        seeds.push(WordToken {
            start,
            end: stop,
            folded: token.folded,
        });
    }
    // A leading surname particle joins the name it precedes (`van der Berg`,
    // `Mac Donald`). Walk backwards so `van` is reached after `der` widened the
    // run. Other leading structural tokens are labels, not names.
    for token in word_tokens(region).into_iter().rev() {
        if !STRUCTURAL_WORDS.contains(&token.folded)
            || !STRUCTURAL_PARTICLES.contains(&token.folded.as_str())
        {
            continue;
        }
        let start = token.start + shift;
        let stop = token.end + shift;
        if stop > begin || !joined_by_separator(body, stop, begin) {
            continue;
        }
        begin = start;
        seeds.push(WordToken {
            start,
            end: stop,
            folded: token.folded,
        });
    }
    let mut tokens = picked;
    tokens.extend(seeds);
    // Text order, so the first token of a phrase is the given name even when a
    // leading particle (`van der Berg`) was collected after the surname.
    tokens.sort_by_key(|token| token.start);
    for token in &mut tokens {
        token.start += offset;
        token.end += offset;
    }
    Some((offset + begin, offset + end, tokens))
}

/// `text` lower-cased one character at a time and, per lowered byte, the byte
/// of `text` its character starts at, plus one entry for the end.
/// `to_lowercase` may change a character's byte length (`İ` -> `i̇`, `ẞ` ->
/// `ß`), so a lowered offset must go through [`original_at`].
fn lower_mapped(text: &str) -> (String, Vec<usize>) {
    let mut lowered = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len() + 1);
    for (at, ch) in text.char_indices() {
        for low in ch.to_lowercase() {
            lowered.push(low);
            map.extend(std::iter::repeat_n(at, low.len_utf8()));
        }
    }
    map.push(text.len());
    (lowered, map)
}

/// The byte of the original text a lowered offset `at` stands for, or `None`
/// when `at` falls inside one original character (part of `İ` -> `i̇`).
fn original_at(map: &[usize], at: usize) -> Option<usize> {
    let here = *map.get(at)?;
    (at == 0 || map[at - 1] != here).then_some(here)
}

/// The byte range of the first date in `value`, shifted by `base`.
fn find_date(value: &str, base: usize) -> Option<(usize, usize)> {
    static YEAR_FIRST: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\d{4}\s*[./-]\s*\d{1,2}\s*[./-]\s*\d{1,2}").expect("date regex")
    });
    static YEAR_LAST: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\d{1,2}\s*[./-]\s*\d{1,2}\s*[./-]\s*\d{4}").expect("date regex")
    });
    let found = YEAR_FIRST.find(value).or_else(|| YEAR_LAST.find(value))?;
    Some((base + found.start(), base + found.end()))
}

/// Seeded name tokens plus the stop-list that keeps common words out.
struct NameSet<'a> {
    /// Folded tokens that always propagate: known surnames, ambiguous
    /// single-token seeds and every non-first token of a full name.
    names: HashSet<String>,
    /// Folded tokens that are only a given name in the seeds seen so far: they
    /// propagate alone only when [`EmailLayer::with_first_names`] is on.
    given: HashSet<String>,
    /// Folded structural token -> the exact spelling a strong seed used, so a
    /// lone `De`/`Le` can be compared with the seed's capitalisation.
    structural: HashMap<String, String>,
    /// Folded token sequences of the strong seed phrases (NER person, header
    /// display name, contact local part). Rule (a) masks a re-ordered sequence,
    /// an initial form (`J. De`, `De J.`) or an honorific prefix (`M. De`).
    sequences: Vec<Vec<String>>,
    public: &'a PublicTerms,
}

impl<'a> NameSet<'a> {
    fn new(public: &'a PublicTerms) -> Self {
        Self {
            names: HashSet::new(),
            given: HashSet::new(),
            structural: HashMap::new(),
            sequences: Vec::new(),
            public,
        }
    }

    fn is_empty(&self) -> bool {
        self.names.is_empty() && self.given.is_empty() && self.structural.is_empty()
    }

    /// Whether a folded token always propagates (a surname, or an ambiguous
    /// single-token seed).
    fn is_always(&self, folded: &str) -> bool {
        self.names.contains(folded)
    }

    /// Whether a folded token is only known as a bare given name.
    fn is_given(&self, folded: &str) -> bool {
        self.given.contains(folded)
    }

    /// Whether a folded token has the shape of a name word at all.
    fn is_name_like(folded: &str) -> bool {
        let length = folded.chars().count();
        (2..=40).contains(&length) && folded.chars().any(char::is_alphabetic)
    }

    /// Whether a weaker source must drop this token.
    fn is_weak_filtered(&self, folded: &str) -> bool {
        STOP_WORDS.contains(folded) || self.public.covers_word(folded)
    }

    /// Remember a structural token with the exact spelling the seed used.
    fn remember_structural(&mut self, raw: &str, folded: String) {
        self.structural
            .entry(folded)
            .and_modify(|known| {
                if !known.chars().any(char::is_uppercase) && raw.chars().any(char::is_uppercase) {
                    *known = raw.to_string();
                }
            })
            .or_insert_with(|| raw.to_string());
    }

    /// Add one token that always propagates.
    ///
    /// A seed is the text naming a person itself — a model span, a greeting or
    /// sign-off rule, a header display name, an email local part — so its tokens
    /// propagate even when they collide with a stop word ("Will") or a public
    /// term ("Orange"). Only weaker sources consult the stop and public lists.
    ///
    /// A structural label is never a strong seed on its own: masking every `le`,
    /// `de`, `contact` or `objet` of a mail garbles the text the model reads
    /// without protecting anything. It is kept aside, with the exact spelling the
    /// seed used, because it can still be a surname ("Jean De"): rules (a) and (b)
    /// in [`EmailLayer::propagate`] are what decide when it is masked.
    fn add_strong(&mut self, raw: &str) {
        let folded = fold(raw);
        if !Self::is_name_like(&folded) {
            return;
        }
        if STRUCTURAL_WORDS.contains(&folded) {
            self.remember_structural(raw, folded);
        } else {
            // Seen as a surname anywhere: it must never be suppressed as a
            // bare first name.
            self.given.remove(&folded);
            self.names.insert(folded);
        }
    }

    /// Add one token that is only known as a given name so far.
    ///
    /// An ALL-CAPS token is a surname convention (`DUPONT`), a structural token
    /// is a particle, and a token already seen as a surname anywhere stays in the
    /// always-propagate set; everything else is a bare given name.
    fn add_given(&mut self, raw: &str) {
        let folded = fold(raw);
        if !Self::is_name_like(&folded) {
            return;
        }
        if STRUCTURAL_WORDS.contains(&folded) {
            self.remember_structural(raw, folded);
        } else if is_all_caps_surname(raw) || self.names.contains(&folded) {
            self.names.insert(folded);
        } else {
            self.given.insert(folded);
        }
    }

    /// Add a strong seed phrase.
    ///
    /// The full phrase (2+ tokens) always propagates through [`Self::sequences`].
    /// For the lone-token case, `single_always` decides whether one token is
    /// enough evidence on its own (a model span, a header display name or a
    /// mailbox local part) or only a bare given name (a greeting, a sign-off, a
    /// line-start comma, a speech verb). The first token of a full name is its
    /// given name; every later token is a surname.
    fn add_phrase(&mut self, raw_tokens: &[&str], single_always: bool) {
        let mut sequence: Vec<String> = Vec::new();
        for raw in raw_tokens {
            let folded = fold(raw);
            if Self::is_name_like(&folded) {
                sequence.push(folded);
            }
        }
        if sequence.is_empty() {
            return;
        }
        if sequence.len() == 1 {
            if single_always {
                let raw = raw_tokens
                    .iter()
                    .copied()
                    .find(|raw| Self::is_name_like(&fold(raw)))
                    .expect("sequence has one token");
                self.add_strong(raw);
            } else {
                let raw = raw_tokens
                    .iter()
                    .copied()
                    .find(|raw| Self::is_name_like(&fold(raw)))
                    .expect("sequence has one token");
                self.add_given(raw);
            }
            return;
        }
        self.sequences.push(sequence);
        let mut position = 0usize;
        for raw in raw_tokens {
            if !Self::is_name_like(&fold(raw)) {
                continue;
            }
            if position == 0 {
                self.add_given(raw);
            } else {
                self.add_strong(raw);
            }
            position += 1;
        }
    }

    /// Add every token of a strong seed phrase and remember it as an ordered
    /// sequence. A lone token is strong enough on its own.
    fn add_strong_phrase(&mut self, raw_tokens: &[&str]) {
        self.add_phrase(raw_tokens, true);
    }

    /// Add a rule-detected name phrase. A lone token is only a bare given name.
    fn add_rule_phrase(&mut self, raw_tokens: &[&str]) {
        self.add_phrase(raw_tokens, false);
    }

    /// Add every name-shaped token of a PERSON seed phrase.
    fn add_seed_text(&mut self, value: &str) {
        let tokens = word_tokens(value);
        let raws: Vec<&str> = tokens
            .iter()
            .map(|token| &value[token.start..token.end])
            .collect();
        self.add_strong_phrase(&raws);
    }

    /// Seed the local part of an e-mail address, never a role mailbox.
    ///
    /// A role address (`contact@`, `info@`, `compta@`) names a function, not a
    /// person: it seeds nothing, and none of its tokens ever propagate. In a real
    /// mailbox (`marie.dupont@`, `jules+news@`) the name tokens are seeded and any
    /// role token is dropped. The domain part is never seeded at all.
    fn add_local_part(&mut self, local: &str) {
        if is_role_local_part(local) {
            return;
        }
        let tokens = word_tokens(local);
        let mut raws: Vec<&str> = Vec::new();
        for token in &tokens {
            if ROLE_LOCAL_WORDS.contains(&token.folded) {
                continue;
            }
            raws.push(&local[token.start..token.end]);
        }
        self.add_strong_phrase(&raws);
    }

    /// Add the name-shaped tokens of a rule phrase, strongly.
    fn add_rule_text(&mut self, value: &str, max: usize) {
        let picked = pick_rule_tokens(value, self, max);
        let raws: Vec<&str> = picked
            .iter()
            .map(|token| &value[token.start..token.end])
            .collect();
        self.add_rule_phrase(&raws);
    }

    /// Whether a rule may take a raw token as a name.
    ///
    /// A rule is medium-strength evidence: capitalisation never rescues a
    /// function word or a structural label (`Le`, `De`, `Contact`, `Objet`), but a
    /// capitalised stop word or public term that is a real name (`Will`,
    /// `Orange`) still passes.
    fn is_rule_name(&self, token: &WordToken, raw: &str) -> bool {
        if !Self::is_name_like(&token.folded) {
            return false;
        }
        let folded = token.folded.as_str();
        if STRUCTURAL_WORDS.contains(folded) {
            return false;
        }
        let capitalized = raw.chars().next().is_some_and(char::is_uppercase);
        capitalized || !self.is_weak_filtered(&token.folded)
    }

    /// Rule (b): a structural token from a strong seed, masked alone.
    ///
    /// Only when the seed spelled it exactly so, it does not open a sentence or
    /// a line, and it is not followed by a lower-case word that would make it a
    /// function word. A lone lower-case `de`/`le` never passes the first test, so
    /// an article is never masked by this rule.
    fn is_lone_structural(&self, text: &str, tokens: &[WordToken], index: usize) -> bool {
        let token = &tokens[index];
        let Some(seed) = self.structural.get(&token.folded) else {
            return false;
        };
        let raw = &text[token.start..token.end];
        // Capitalised exactly as in the seed: a lower-case seed spelling (a
        // mailbox local part) never masks a lower-case article either.
        if !raw.chars().next().is_some_and(char::is_uppercase) || raw != seed.as_str() {
            return false;
        }
        if opens_line_or_sentence(text, token.start) {
            return false;
        }
        if let Some(next) = tokens.get(index + 1) {
            if text[next.start..next.end]
                .chars()
                .next()
                .is_some_and(char::is_lowercase)
            {
                return false;
            }
        }
        true
    }
}

/// Whether a local part is a role mailbox, which never names a person.
///
/// The whole local part is compared after folding and after dropping the
/// separators, so `no-reply`, `no.reply`, `noreply` and `info+web@` all match a
/// closed list entry, with the `+tag` sub-address ignored.
fn is_role_local_part(local: &str) -> bool {
    let folded = fold(local);
    let base = folded.split('+').next().unwrap_or(&folded);
    let compact: String = base.chars().filter(|ch| ch.is_alphanumeric()).collect();
    if base.is_empty() {
        return true;
    }
    if ROLE_LOCAL_WORDS.contains(base) || ROLE_LOCAL_WORDS.contains(compact.as_str()) {
        return true;
    }
    let tokens: Vec<&str> = base
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    !tokens.is_empty() && tokens.iter().all(|token| ROLE_LOCAL_WORDS.contains(*token))
}

/// Function words and roles that never propagate as a name.
///
/// Entries are folded once at start-up so a token compared with [`fold`] (which
/// lower-cases and drops marks) matches its accented or hamzated spelling:
/// `إن`, `üdv` and `tárgy` are all caught.
static STOP_WORDS: std::sync::LazyLock<HashSet<String>> =
    std::sync::LazyLock::new(|| STOP_WORDS_LIST.iter().map(|word| fold(word)).collect());

const STOP_WORDS_LIST: &[&str] = &[
    // English.
    "the",
    "and",
    "for",
    "from",
    "with",
    "you",
    "your",
    "yours",
    "we",
    "our",
    "us",
    "me",
    "my",
    "he",
    "she",
    "it",
    "they",
    "them",
    "this",
    "that",
    "these",
    "those",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "on",
    "in",
    "at",
    "by",
    "as",
    "an",
    "or",
    "if",
    "but",
    "not",
    "no",
    "yes",
    "please",
    "thanks",
    "thank",
    "regards",
    "best",
    "kind",
    "hello",
    "hey",
    "dear",
    "here",
    "there",
    "where",
    "when",
    "what",
    "who",
    "whom",
    "how",
    "why",
    "all",
    "any",
    "some",
    "more",
    "most",
    "other",
    "such",
    "only",
    "own",
    "same",
    "so",
    "too",
    "very",
    "can",
    "will",
    "just",
    "should",
    "would",
    "could",
    "may",
    "might",
    "must",
    "have",
    "has",
    "had",
    "do",
    "does",
    "did",
    "done",
    "get",
    "got",
    "team",
    "office",
    "admin",
    "contact",
    "support",
    "info",
    "sales",
    "mail",
    "email",
    "reply",
    "message",
    "sent",
    "subject",
    "bcc",
    "hi",
    "re",
    "fw",
    "fwd",
    "mailto",
    "smtp",
    "www",
    // French.
    "le",
    "la",
    "les",
    "un",
    "une",
    "des",
    "du",
    "et",
    "ou",
    "au",
    "aux",
    "en",
    "dans",
    "sur",
    "sous",
    "pour",
    "par",
    "avec",
    "sans",
    "je",
    "tu",
    "il",
    "elle",
    "on",
    "nous",
    "vous",
    "ils",
    "elles",
    "te",
    "se",
    "mon",
    "ma",
    "mes",
    "ton",
    "ta",
    "tes",
    "son",
    "sa",
    "ses",
    "notre",
    "nos",
    "votre",
    "vos",
    "leur",
    "leurs",
    "ce",
    "cet",
    "cette",
    "ces",
    "qui",
    "que",
    "quoi",
    "dont",
    "est",
    "sont",
    "suis",
    "es",
    "etait",
    "etaient",
    "avoir",
    "ont",
    "avez",
    "faire",
    "fait",
    "plus",
    "moins",
    "tres",
    "bien",
    "tout",
    "tous",
    "toute",
    "toutes",
    "aussi",
    "mais",
    "si",
    "non",
    "oui",
    "merci",
    "cordialement",
    "bonjour",
    "salut",
    "voici",
    "voila",
    "cher",
    "chere",
    "madame",
    "monsieur",
    "bureau",
    "amities",
    // Afrikaans.
    "die",
    "van",
    "vir",
    "met",
    "op",
    "het",
    "ek",
    "jy",
    "hy",
    "sy",
    "ons",
    "julle",
    "hulle",
    "jou",
    "haar",
    "nie",
    "ja",
    "dankie",
    "groete",
    "hallo",
    "beste",
    "liewe",
    "asseblief",
    "hierdie",
    "daardie",
    "wat",
    "wie",
    "waar",
    "wanneer",
    "hoe",
    "hoekom",
    "baie",
    "kan",
    "sal",
    "moet",
    "wees",
    "word",
    "ook",
    "maar",
    "as",
    // Hungarian.
    "az",
    "egy",
    "es",
    "vagy",
    "de",
    "hogy",
    "nem",
    "igen",
    "en",
    "te",
    "o",
    "mi",
    "ti",
    "ok",
    "ez",
    "ezek",
    "azok",
    "van",
    "vannak",
    "volt",
    "lesz",
    "lenni",
    "mint",
    "nagyon",
    "jol",
    "koszonom",
    "udvozlettel",
    "kedves",
    "szia",
    "mert",
    "ha",
    "is",
    "csak",
    "meg",
    "mar",
    "itt",
    "ott",
    "aki",
    "ami",
    "mit",
    "hol",
    "mikor",
    "hogyan",
    "miert",
    "kerem",
    "udv",
    // Arabic.
    "في",
    "من",
    "إلى",
    "على",
    "عن",
    "مع",
    "هذا",
    "هذه",
    "ذلك",
    "التي",
    "الذي",
    "أن",
    "إن",
    "كان",
    "كانت",
    "هو",
    "هي",
    "هم",
    "أنا",
    "نحن",
    "أنت",
    "لا",
    "نعم",
    "شكرا",
    "شكراً",
    "تحياتي",
    "تحية",
    "مرحبا",
    "السلام",
    "عليكم",
    "عزيزي",
    "عزيزتي",
    "إذا",
    "كما",
    "قد",
    "كل",
    "بعض",
    "يا",
    // Russian.
    "и",
    "в",
    "во",
    "не",
    "что",
    "он",
    "на",
    "я",
    "с",
    "со",
    "как",
    "а",
    "то",
    "все",
    "она",
    "так",
    "его",
    "но",
    "да",
    "ты",
    "к",
    "у",
    "же",
    "вы",
    "за",
    "бы",
    "по",
    "только",
    "ее",
    "мне",
    "было",
    "вот",
    "от",
    "меня",
    "еще",
    "нет",
    "о",
    "из",
    "ему",
    "теперь",
    "когда",
    "даже",
    "ну",
    "вдруг",
    "ли",
    "если",
    "уже",
    "или",
    "ни",
    "быть",
    "был",
    "него",
    "до",
    "вас",
    "нибудь",
    "опять",
    "уж",
    "вам",
    "ведь",
    "там",
    "потом",
    "себя",
    "ничего",
    "ей",
    "может",
    "они",
    "тут",
    "где",
    "есть",
    "надо",
    "ней",
    "для",
    "мы",
    "тебя",
    "их",
    "чем",
    "была",
    "сам",
    "чтоб",
    "без",
    "будто",
    "чего",
    "раз",
    "тоже",
    "себе",
    "под",
    "будет",
    "ж",
    "тогда",
    "кто",
    "этот",
    "того",
    "потому",
    "этого",
    "какой",
    "совсем",
    "ним",
    "здесь",
    "этом",
    "один",
    "почти",
    "мой",
    "тем",
    "чтобы",
    "нее",
    "сейчас",
    "были",
    "куда",
    "зачем",
    "всех",
    "никогда",
    "можно",
    "при",
    "наконец",
    "два",
    "об",
    "другой",
    "хоть",
    "после",
    "над",
    "больше",
    "тот",
    "через",
    "эти",
    "нас",
    "про",
    "всего",
    "них",
    "какая",
    "много",
    // Titles and roles.
    "dr",
    "mr",
    "mrs",
    "ms",
    "mme",
    "mlle",
    "ir",
    "prof",
    "ing",
    "dipl",
    "hr",
    "noreply",
    "no-reply",
    "postmaster",
    "webmaster",
    "newsletter",
    "marketing",
    "direction",
    "manager",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// GATE-PERF-1: the signature-block check as it was on main, one split of
    /// the whole text per call. The upward walk must answer exactly the same.
    fn signature_or_header_range_main(text: &str, start: usize, end: usize) -> bool {
        let line_start = text[..start].rfind('\n').map(|at| at + 1).unwrap_or(0);
        let lines = line_ranges(text);
        let mut seen = 0usize;
        for (above_start, above_end) in lines.iter().rev() {
            if *above_start >= line_start {
                continue;
            }
            let candidate = text[*above_start..*above_end].trim();
            if candidate.is_empty() {
                continue;
            }
            seen += 1;
            if seen > 6 {
                break;
            }
            if matches!(candidate, "--" | "---" | "—" | "––")
                || (word_tokens(candidate).len() <= 6 && is_closing(candidate))
                || is_ps_or_nb_line(candidate)
            {
                return true;
            }
        }
        // The line-local checks did not change: run them on the same text.
        let line_end = text[start..].find('\n').map_or(text.len(), |at| start + at);
        let line = &text[line_start..line_end];
        let local = format!("{line}\n");
        let shift = start - line_start;
        is_signature_or_header_range(&local, shift, shift + (end - start))
    }

    #[test]
    fn upward_signature_walk_answers_what_the_whole_text_split_did() {
        let mut texts: Vec<String> = [
            include_str!("../tests/data/secret_2_tables_main.txt"),
            include_str!("../tests/data/secret_2_main.txt"),
            include_str!("../tests/data/health_label_main.txt"),
            include_str!("../tests/data/address_main.txt"),
            include_str!("../tests/data/fin6_main.txt"),
            include_str!("../tests/data/label_value_main.txt"),
        ]
        .iter()
        .map(|text| text.chars().take(24 * 1024).collect())
        .collect();
        texts.push(
            "Hi Mila,\r\nthanks.\r\n\r\nBest regards,\r\n\r\n  \r\nJules\nP.S. Noor\n\
             --\nOwen Calder\n\n\n\na\nb\nc\nd\ne\nf\ng\nLeila, ok\n—\nSam\n\nCheers\nAva, hi"
                .to_string(),
        );
        for (head, unit) in [
            ("", "id,password,note\n"),
            ("", "\nid,password,note\n"),
            ("id,password,city\n", "\nalice,hunter,oslo\n"),
            ("id,password,note\n", "17,\"ordered\nagain\",x\n"),
            ("id,password,note\n", "\nThe meeting moved to Tuesday.\n"),
            ("id,password,note\n", "17,Cherry6!,\n,,\nThanks,\n"),
        ] {
            texts.push(format!("{head}{}", unit.repeat(200)));
        }
        let mut checked = 0usize;
        let mut kept = 0usize;
        for text in &texts {
            for (start, end) in line_ranges(text) {
                // One word at the line start (or the whole line when it is short).
                let word = text[start..end]
                    .find([' ', ',', '\r'])
                    .map_or(end, |at| start + at.max(1));
                if !text.is_char_boundary(word) || word <= start {
                    continue;
                }
                let head = is_signature_or_header_range(text, start, word);
                assert_eq!(
                    head,
                    signature_or_header_range_main(text, start, word),
                    "line {start}..{end}: {:?}",
                    &text[start..end]
                );
                checked += 1;
                kept += usize::from(head);
            }
        }
        assert!(checked > 1_500, "only {checked} lines checked");
        assert!(kept > 5, "the sample keeps only {kept} signature lines");
    }

    use proptest::prelude::*;

    proptest! {
        /// K-REGISTRY-PERF: the indexed pass marks exactly the windows the
        /// old pass, one full scan per sequence, marked.
        #[test]
        fn indexed_sequences_mark_what_one_pass_per_sequence_marked(
            words in prop::collection::vec(prop::sample::select(&WORDS[..]), 0..40),
            seeds in prop::collection::vec(prop::collection::vec(prop::sample::select(&SEED_WORDS[..]), 1..4), 0..8),
        ) {
            let text = words.join(" ");
            let tokens = word_tokens(&text);
            let sequences: Vec<Vec<String>> = seeds
                .iter()
                .map(|seed| seed.iter().map(|word| word.to_string()).collect())
                .collect();
            let mut indexed = vec![false; tokens.len()];
            mark_sequences(&tokens, &text, &sequences, &mut indexed);
            let mut reference = vec![false; tokens.len()];
            for sequence in &sequences {
                for (start, window) in tokens.windows(sequence.len()).enumerate() {
                    if window_matches_any_order(sequence, window, &text) {
                        reference[start..start + sequence.len()].fill(true);
                    }
                }
            }
            prop_assert_eq!(indexed, reference);
        }
    }

    /// Text words: full names, initials, structural particles in both cases.
    const WORDS: [&str; 12] = [
        "Jean", "jean", "J.", "De", "de", "Le", "D", "Dupont", "dupont", "x", "Mara", "M",
    ];
    const SEED_WORDS: [&str; 6] = ["jean", "de", "le", "dupont", "mara", "marc"];

    fn persons(text: &str) -> Vec<String> {
        persons_with(text, false)
    }

    /// The person spans of the layer with the bare-first-name switch set.
    fn persons_with(text: &str, mask_first_names: bool) -> Vec<String> {
        EmailLayer::new()
            .with_first_names(mask_first_names)
            .analyze(text)
            .into_iter()
            .filter(|span| span.kind == EntityKind::Person)
            .map(|span| text[span.start..span.end].to_string())
            .collect()
    }

    #[test]
    fn greeting_names_a_full_name_and_propagates() {
        let text = "Bonjour Hugo Dupont,\n\nle dossier suit. Hugo Dupont repondra.";
        let found = persons(text);
        assert!(found.iter().any(|value| value == "Hugo Dupont"));
        assert!(found.iter().filter(|value| *value == "Hugo Dupont").count() >= 2);
    }

    #[test]
    fn a_bare_greeting_name_is_off_by_default_and_on_with_the_switch() {
        let text = "Bonjour Hugo,\n\nle dossier suit. Hugo repondra.";
        assert!(
            persons(text).iter().all(|value| value != "Hugo"),
            "a bare first name was masked by default"
        );
        let found = persons_with(text, true);
        assert!(found.iter().any(|value| value == "Hugo"));
        assert!(found.iter().filter(|value| *value == "Hugo").count() >= 2);
    }

    #[test]
    fn a_surname_from_a_header_propagates_when_a_bare_greeting_name_follows() {
        // The header names the surname, so a later lone `Dupont` is a known
        // surname and still masks; the bare first name `Hugo` does not.
        let text = "De : Hugo Dupont <hugo.dupont@example.invalid>\n\n\
                    Bonjour Hugo,\n\nLe dossier suit.\n\nDupont confirme.";
        let found = persons(text);
        assert!(found.iter().any(|value| value == "Dupont"), "{found:?}");
        assert!(!found.iter().any(|value| value == "Hugo"), "{found:?}");
    }

    #[test]
    fn a_lone_name_after_an_honorific_is_still_masked() {
        let found = persons("Bonjour Dr Hugo,\n\nle dossier suit.");
        assert!(
            found.iter().any(|value| value.contains("Hugo")),
            "{found:?}"
        );
    }

    #[test]
    fn an_all_caps_surname_is_still_masked() {
        let found = persons("Bonjour DUPONT,\n\nle dossier suit.");
        assert!(found.iter().any(|value| value == "DUPONT"), "{found:?}");
    }

    #[test]
    fn sign_off_names_the_next_line() {
        let text = "Merci pour tout,\n\nCordialement,\nThéo Lambrecht";
        let found = persons(text);
        assert!(found.iter().any(|value| value == "Théo Lambrecht"));
    }

    #[test]
    fn ps_author_name_line_is_masked() {
        assert!(persons("C'est tout.\n\nps: Idriss Benali")
            .iter()
            .any(|value| value == "Idriss Benali"));
        // A lone `ps:` author is a bare first name: off by default, on with the
        // switch.
        assert!(persons_with("C'est tout.\n\nps: Idriss", true)
            .iter()
            .any(|value| value == "Idriss"));
    }

    #[test]
    fn sender_header_seeds_propagation_into_a_signature() {
        let text = "De : Océane Mabille <oceane.mabille@example.invalid>\n\
                    Suivi : https://devis.example.invalid/suivi?ref=1\n\
                    Océane Mabille";
        let found = persons(text);
        assert!(found.iter().any(|value| value == "Océane Mabille"));
        // The surname is seeded too, so it is masked inside the URL and the
        // signature as well.
        assert!(found.iter().any(|value| value.contains("Mabille")));
    }

    #[test]
    fn percent_encoded_email_in_a_tracking_link_is_masked() {
        let text =
            "Shop: https://promo.example.invalid/u?e=freya.halloran%40example.invalid&r=7731";
        let spans = EmailLayer::new().analyze(text);
        let email = spans
            .iter()
            .find(|span| span.kind == EntityKind::Email)
            .expect("email found");
        assert_eq!(
            &text[email.start..email.end],
            "freya.halloran%40example.invalid"
        );
    }

    #[test]
    fn tracking_parameter_value_is_masked_whole() {
        let text = "Click https://x.example.invalid/u?uid=abc123&id=9 now";
        let spans = EmailLayer::new().analyze(text);
        assert!(
            spans
                .iter()
                .any(|span| span.kind == EntityKind::Person
                    && &text[span.start..span.end] == "abc123")
        );
    }

    #[test]
    fn name_inside_a_url_path_propagates() {
        let text = "From: Jules Ferrand <jules.ferrand@example.invalid>\n\
                    https://linkedin.example.invalid/in/jules-ferrand";
        let found = persons(text);
        assert!(found.iter().any(|value| value == "jules-ferrand"));
    }

    #[test]
    fn a_lowercase_first_name_propagates_from_a_greeting_when_the_switch_is_on() {
        let text = "hello hugo,\n\nhugo, can you send it?";
        let found = persons_with(text, true);
        assert!(
            found
                .iter()
                .filter(|value| value.as_str() == "hugo")
                .count()
                >= 2
        );
        assert!(persons(text).iter().all(|value| value != "hugo"));
    }

    #[test]
    fn stop_words_never_propagate() {
        assert!(!persons("Bonjour,\nle dossier")
            .iter()
            .any(|value| value == "le"));
    }

    #[test]
    fn public_terms_are_dropped_from_model_org_spans_without_a_private_signal() {
        let layer = EmailLayer::new().with_public_terms(
            PublicTerms::from_json_str(r#"{"en":["Ministry of Transit"]}"#).expect("json"),
        );
        let span = Span::new(EntityKind::Organization, 4, 23, 0.9, "gliner");
        let kept = layer.apply("The Ministry of Transit meets.", vec![span], &[]);
        assert!(kept.is_empty());
        // A person in the text is a private signal: the org span survives. The
        // person is a full name so the bare-first-name rule keeps it.
        let span = Span::new(EntityKind::Organization, 4, 23, 0.9, "gliner");
        let text = "The Ministry of Transit sees Owen Park.";
        let person = Span::new(EntityKind::Person, 29, 38, 0.9, "gliner");
        assert_eq!(&text[29..38], "Owen Park");
        let kept = layer.apply(text, vec![span, person], &[]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn person_spans_are_never_dropped_by_the_allowlist() {
        let layer = EmailLayer::new()
            .with_public_terms(PublicTerms::from_json_str(r#"{"en":["Dublin"]}"#).expect("json"));
        // A two-token person is a full name and survives the allowlist.
        let span = Span::new(EntityKind::Person, 0, 11, 0.9, "gliner");
        let kept = layer.apply("Dublin North", vec![span], &[]);
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn nbsp_before_a_health_span_is_decoded() {
        let decoded = DecodedText::new("I'm&nbsp;on sick leave");
        assert!(decoded.text().contains("on sick leave"));
    }

    #[test]
    fn dob_in_a_flattened_table_is_found() {
        let text = "Nom\tNé le\tAdresse actuelle\nOcéane Mabille\t12/05/1991\t9 rue X";
        let spans = EmailLayer::new().analyze(text);
        let dob = spans
            .iter()
            .find(|span| span.kind == EntityKind::DateOfBirth)
            .expect("dob");
        assert_eq!(&text[dob.start..dob.end], "12/05/1991");
    }

    #[test]
    fn a_person_seed_beats_stop_words_and_public_terms() {
        let layer = EmailLayer::new().with_first_names(true);
        // "Will" is an English stop word; the seed names it anyway.
        let text = "Will left early. Will was tired.";
        let seed = Span::new(EntityKind::Person, 0, 4, 0.9, "gliner");
        let spans = layer.apply(text, vec![seed], &[seed]);
        assert!(
            spans
                .iter()
                .filter(|span| span.kind == EntityKind::Person)
                .count()
                >= 2,
            "{spans:?}"
        );
        // "Orange" is a built-in public term; as a seeded surname it propagates.
        let text = "Orange called. Orange left a message.";
        let seed = Span::new(EntityKind::Person, 0, 6, 0.9, "gliner");
        let spans = layer.apply(text, vec![seed], &[seed]);
        assert!(
            spans
                .iter()
                .filter(|span| span.kind == EntityKind::Person)
                .count()
                >= 2,
            "{spans:?}"
        );
    }

    #[test]
    fn a_greeting_names_capitalized_stop_words_and_public_terms() {
        for (text, name) in [
            ("Bonjour Will,\n\nWill, tu viens ?", "Will"),
            ("Bonjour Alice Orange,\n\nOrange a confirmé.", "Orange"),
            ("Bonjour Mark,\n\nMark, voici le dossier.", "Mark"),
            ("Bonjour Pierre,\n\npierre, tu viens ?", "pierre"),
        ] {
            let found = persons_with(text, true);
            let folded = name.to_lowercase();
            let hits = found
                .iter()
                .filter(|value| value.to_lowercase().contains(&folded))
                .count();
            assert!(hits >= 2, "{text:?} -> {found:?}");
        }
    }

    #[test]
    fn colloquial_and_lowercase_greetings_name_a_person() {
        for (text, name) in [
            ("szia Bence,\nköszi", "Bence"),
            ("sziasztok Bence,\nköszi", "Bence"),
            ("helló Bence,\nköszi", "Bence"),
            ("привет Борис,\nспасибо", "Борис"),
            ("здравствуй Борис,\nспасибо", "Борис"),
            ("هلا سامي,\nشكرا", "سامي"),
            ("واخا سامي,\nشكرا", "سامي"),
            ("سلام سامي,\nشكرا", "سامي"),
            ("أهلا سامي,\nشكرا", "سامي"),
            ("hallo Pieter,\ndankie", "Pieter"),
            ("haai Pieter,\ndankie", "Pieter"),
            ("goeie môre Pieter,\ndankie", "Pieter"),
            ("bonjour hugo,\nmerci", "hugo"),
            ("hello hugo,\nthanks", "hugo"),
        ] {
            let found = persons_with(text, true);
            assert!(
                found.iter().any(|value| value == name),
                "{text:?} -> {found:?}"
            );
        }
    }

    #[test]
    fn a_line_initial_name_before_a_comma_is_a_person() {
        // The name directly follows the subject line, in any language. A lone
        // first name is off by default and on with the switch.
        let text = "Objet : dossier\n\nThéo, peux-tu confirmer ?\n\nMerci";
        assert!(persons(text).iter().all(|value| value != "Théo"));
        let found = persons_with(text, true);
        assert!(found.iter().any(|value| value == "Théo"), "{found:?}");
        // A greeting or closing word before the comma is not a name.
        assert!(!persons("Bonjour,\n\nCordialement, Hugo")
            .iter()
            .any(|value| value == "Bonjour"));
    }

    #[test]
    fn an_owner_question_before_a_comma_is_not_a_person() {
        // AGENT-REAL-1: the owner's own questions open with a capitalized word
        // and hold a comma. The short-clause rule must not mask the clause.
        for text in [
            "How many unread mails do I have, and who sent the newest one?",
            "Can you check my calendar, please?",
            "What did Lena say, and when?",
            "Do I have any meetings tomorrow, or is the day free?",
            "Which invoices are still unpaid, and for how long?",
            "Is there anything urgent in my inbox, from this week?",
            "Show me the newest mail, then summarise it.",
            "Who wrote to me yesterday, and what did they want?",
            "Quels mails non lus, et de qui ?",
            "Combien de mails non lus ai-je, et qui a envoyé le dernier ?",
            "Peux-tu vérifier mon agenda, s'il te plaît ?",
            "Est-ce que j'ai une réunion demain, ou la journée est libre ?",
            "Où en est la facture, et quand part-elle ?",
            "Je voudrais voir mes rendez-vous, et les mails liés.",
            // The mail tools' own list lines: the first comma is in the date.
            "uid 12 · Thanks, looks good · from: Jonas Sample <jonas@brightpath.example> · date: Thu, 15 Oct 2026 17:54:55 +0000 · unread · 293 B",
            "Question about the delivery window · from: Camille Example <camille@northwind.example> · date: Thu, 15 Oct 2026 16:54:55 +0000 · unread",
            "Introduction from Camille · date: Thu, 15 Oct 2026 14:54:55 +0000 · unread",
        ] {
            for first_names in [false, true] {
                let found = persons_with(text, first_names);
                let masked_whole_clause = found
                    .iter()
                    .any(|value| value.split_whitespace().count() > 3);
                assert!(
                    !masked_whole_clause && found.iter().all(|value| {
                        matches!(
                            value.as_str(),
                            "Lena" | "Jonas" | "Jonas Sample" | "Camille Example" | "Camille"
                        )
                    }),
                    "{text:?} (first_names={first_names}) -> {found:?}"
                );
            }
        }
        // A real vocative still masks.
        let found = persons_with("Camille, can you send the invoice?", true);
        assert!(found.iter().any(|value| value == "Camille"), "{found:?}");
    }

    #[test]
    fn a_speech_verb_names_its_speaker() {
        for (text, name) in [
            ("Alice said the meeting moved.", "Alice"),
            ("Sabine a dit que le dossier suit.", "Sabine"),
            ("Мария сказала правду.", "Мария"),
            ("Bence azt mondta, hogy kész.", "Bence"),
            ("Pieter het gesê dit is klaar.", "Pieter"),
            ("قال سامي إن الأمر جاهز.", "سامي"),
        ] {
            let found = persons_with(text, true);
            assert!(
                found.iter().any(|value| value == name),
                "{text:?} -> {found:?}"
            );
        }
    }

    #[test]
    fn a_header_label_or_article_is_never_seeded_or_propagated() {
        // `De` and `Le` are structural: the display name seeds only `Monde`,
        // and neither label is masked anywhere, whatever its case.
        let text = "De : Le Monde <contact@example.invalid>\n\n\
                    Le dossier suit, Le Monde confirme.";
        let found = persons(text);
        for label in ["De", "Le", "de", "le"] {
            assert!(
                !found.iter().any(|value| value == label),
                "structural label {label:?} masked: {found:?}"
            );
        }
        assert!(found.iter().any(|value| value == "Monde"), "{found:?}");
    }

    #[test]
    fn a_role_mailbox_never_seeds_its_local_part() {
        for (text, role) in [
            ("Write to contact@example.invalid for the file.", "contact"),
            ("Écris à info@example.invalid pour le dossier.", "info"),
            ("Skryf aan admin@example.invalid vir die lêer.", "admin"),
            ("Írj a compta@example.invalid címre.", "compta"),
        ] {
            let found = persons(text);
            assert!(
                !found.iter().any(|value| value.eq_ignore_ascii_case(role)),
                "role mailbox {role:?} masked: {text:?} -> {found:?}"
            );
        }
        // A real mailbox still seeds its name part, but not a role token.
        let found = persons("Écris à marie.info@example.invalid, marie répondra.");
        assert!(found.iter().any(|value| value == "marie"), "{found:?}");
        assert!(!found.iter().any(|value| value == "info"), "{found:?}");
    }

    #[test]
    fn a_structural_surname_from_a_strong_seed_propagates_with_its_sequence() {
        for (surname, email) in [
            ("De", "jean.de@example.invalid"),
            ("Le", "jean.le@example.invalid"),
        ] {
            let text = format!(
                "Jean {surname} <{email}>\n\n\
                 merci Jean {surname}\n\
                 M. {surname} a appelé\n\
                 le dossier de Jean"
            );
            let spans = EmailLayer::new().with_first_names(true).analyze(&text);
            let found: Vec<&str> = spans
                .iter()
                .filter(|span| span.kind == EntityKind::Person)
                .map(|span| &text[span.start..span.end])
                .collect();
            let covers = |needle: &str| found.iter().any(|value| value.contains(needle));
            // (a) the full sequence, in the seed order and with the honorific.
            assert!(covers(&format!("Jean {surname}")), "{surname}: {found:?}");
            assert!(covers(&format!("M. {surname}")), "{surname}: {found:?}");
            // (c) the given name always propagates.
            assert!(found.contains(&"Jean"), "{surname}: {found:?}");
            // (b) the lower-case article is never covered by a person span.
            let last_line = text.rfind('\n').map(|at| at + 1).unwrap_or(0);
            let at = last_line
                + text[last_line..]
                    .find(&surname.to_lowercase())
                    .expect("article");
            assert!(
                !spans.iter().any(|span| span.kind == EntityKind::Person
                    && span.start <= at
                    && span.end > at),
                "{surname}: article covered at {at}: {found:?}"
            );
        }
    }

    #[test]
    fn a_structural_surname_sequence_matches_any_order_and_initials() {
        let text = "Jean De <jean.de@example.invalid>\n\nDe Jean, J. De and De J. were here.";
        let found = persons(text);
        for expected in ["De Jean", "J. De", "De J."] {
            assert!(
                found.iter().any(|value| value == expected),
                "{expected:?} in {found:?}"
            );
        }
    }

    #[test]
    fn a_strong_seed_still_propagates_stop_words_and_public_terms() {
        let text = "Will Orange <will.orange@example.invalid>\n\nWill called. Orange left.";
        let found = persons_with(text, true);
        assert!(found.iter().any(|value| value == "Will"), "{found:?}");
        assert!(found.iter().any(|value| value == "Orange"), "{found:?}");
    }

    #[test]
    fn a_surname_from_a_full_seed_still_propagates_alone_with_first_names_off() {
        let text = "Will Orange <will.orange@example.invalid>\n\nWill called. Orange left.";
        let found = persons(text);
        assert!(!found.iter().any(|value| value == "Will"), "{found:?}");
        assert!(found.iter().any(|value| value == "Orange"), "{found:?}");
    }

    #[test]
    fn bullet_and_list_markers_open_a_line_for_a_lone_structural_token() {
        // A structural token after a bullet is not a surname.
        for text in [
            "• le dossier suit",
            "- de la part de Jean",
            "* van het kantoor",
            "> le message",
            "1. le dossier",
            "a) de la part de Jean",
        ] {
            let found = persons(text);
            for label in ["le", "de", "van"] {
                assert!(
                    !found.iter().any(|value| value.eq_ignore_ascii_case(label)),
                    "bullet line masked {label:?}: {text:?} -> {found:?}"
                );
            }
        }
    }

    #[test]
    fn structural_particles_do_not_propagate_alone() {
        // The particles are structural: a surname particle alone in the text is
        // not a person, but the full name that carries it is.
        let found = persons("van der Berg <van.berg@example.invalid>\n\nvan is here.");
        assert!(
            found.iter().any(|value| value.contains("Berg")),
            "{found:?}"
        );
        assert!(!found.iter().any(|value| value == "van"), "{found:?}");
    }

    /// Whether a lone model `PERSON` span covering `value` survives the layer.
    fn kept_gliner_person(text: &str, value: &str, mask_first_names: bool) -> bool {
        let start = text.find(value).expect("value in text");
        let span = Span::new(
            EntityKind::Person,
            start,
            start + value.len(),
            0.9,
            "gliner",
        );
        let layer = EmailLayer::new().with_first_names(mask_first_names);
        let kept = layer.apply(text, vec![span], &[span]);
        kept.iter().any(|candidate| {
            candidate.kind == EntityKind::Person
                && candidate.start <= start
                && candidate.end >= start + value.len()
        })
    }

    #[test]
    fn signature_and_header_singletons_always_stay() {
        // (P1) A lone name in a signature block or a header line is kept, whatever
        // its token count: the bare-first-name policy only bites outside that
        // context.
        for (text, name) in [
            ("Merci,\n\nCordialement,\nMila", "Mila"),
            ("Merci,\n\nCordialement,\n— Mila", "Mila"),
            ("Merci,\n\nCheers,\nMila", "Mila"),
            ("De : Mila <mila@example.invalid>", "Mila"),
            ("From: Mila <mila@example.invalid>", "Mila"),
            ("To: Mila", "Mila"),
            ("Cc: Mila", "Mila"),
            ("发件人: Mila", "Mila"),
            ("Mila wrote:", "Mila"),
            ("Le 2 oct., Mila a écrit :", "Mila"),
        ] {
            assert!(
                kept_gliner_person(text, name, false),
                "{text:?} dropped a signature/header singleton"
            );
        }
        // The sign-off rule itself keeps the singleton too.
        for (text, name) in [
            ("Merci,\n\nCordialement,\nMila", "Mila"),
            ("Merci,\n\nCordialement,\n— Mila", "Mila"),
            ("Merci,\n\nCheers,\nMila", "Mila"),
        ] {
            let found = persons(text);
            assert!(
                found.iter().any(|value| value.contains(name)),
                "{text:?} -> {found:?}"
            );
        }
    }

    #[test]
    fn a_lone_unknown_model_person_is_kept() {
        // (P1) A lone token that may be a surname, a CJK full name or a
        // Hungarian surname-first name stays masked; only a known bare given
        // name is left in clear by default.
        for (text, name) in [
            ("ask Halloran about it", "Halloran"),
            ("Dupont a appelé", "Dupont"),
            ("Martin viendra", "Martin"),
            ("王小明说", "王小明"),
            ("Nagy Bence jött", "Nagy"),
            ("Bonjour Dupont,", "Dupont"),
        ] {
            assert!(
                kept_gliner_person(text, name, false),
                "{text:?} dropped a possible surname"
            );
            assert!(
                kept_gliner_person(text, name, true),
                "{text:?} not masked with mask_first_names"
            );
        }
    }

    #[test]
    fn a_lone_known_given_name_is_left_in_clear_by_default() {
        // The strict rule leaves a lone given name in clear only in a vocative
        // or address position: after a greeting or a thanks word that closes its
        // clause, or at the start of a line followed by a comma. A `P.S.` author
        // is a signature name and is masked (see the table test below).
        for (text, name) in [
            ("Salut Jules", "Jules"),
            ("Hi Mila,", "Mila"),
            ("Hi Mila!", "Mila"),
            ("Salut Mila\n", "Mila"),
            ("thanks Mila", "Mila"),
            ("merci Jules", "Jules"),
            ("Jules, peux-tu", "Jules"),
        ] {
            assert!(
                !kept_gliner_person(text, name, false),
                "{text:?} masked a bare given name by default"
            );
            assert!(
                kept_gliner_person(text, name, true),
                "{text:?} not masked with mask_first_names"
            );
        }
    }

    #[test]
    fn a_lone_given_name_outside_a_vocative_position_is_masked() {
        // (P1) The lexicon alone is not enough: running text, a signature block,
        // a CJK name and a given/surname collision all stay masked, whatever the
        // given-name lexicon says.
        for (text, name) in [
            ("Grace will send the file", "Grace"),
            ("János hívott", "János"),
            ("Mila hívott", "Mila"),
            ("Jules will send the file", "Jules"),
            ("ask Halloran", "Halloran"),
            ("Dupont a appelé", "Dupont"),
            ("Salut Martin", "Martin"),
            ("Mit freundlichen Grüßen\nMila", "Mila"),
            ("此致敬礼\n小明", "小明"),
            // A greeting or thanks word followed by a sentence makes the name its
            // subject, not its addressee.
            ("Hi, Mila was called in today.", "Mila"),
            ("Hello Mila said it was fine.", "Mila"),
            ("merci Jules pour ton aide", "Jules"),
        ] {
            assert!(
                kept_gliner_person(text, name, false),
                "{text:?} left a lone name in clear outside a vocative position"
            );
            assert!(
                kept_gliner_person(text, name, true),
                "{text:?} not masked with mask_first_names"
            );
        }
    }

    #[test]
    fn greeting_and_postscript_repros_hold_in_both_directions() {
        // (P1, security review round 3) After a greeting the name is vocative only when it
        // closes its clause; a sentence after it makes the name the subject. A
        // `P.S.` / `PS` / `NB` author is a signature name, never a vocative. Each
        // case is checked on the rule path (`persons`) and on a lone NER singleton
        // (`kept_gliner_person`).
        for (text, name, clear) in [
            ("Hi Mila,\n\nle dossier suit.", "Mila", true),
            ("Hi Mila!\n\nle dossier suit.", "Mila", true),
            ("Salut Mila\n", "Mila", true),
            ("Hi, Mila was called in today.", "Mila", false),
            ("Hello Mila said it was fine.", "Mila", false),
            ("Bonjour,\n\nP.S. Mila", "Mila", false),
            ("P.S. Mila", "Mila", false),
            ("PS Mila", "Mila", false),
            ("P.S Mila", "Mila", false),
            ("NB Mila", "Mila", false),
        ] {
            let rule_masked = persons(text).iter().any(|value| value.contains(name));
            assert_eq!(
                rule_masked,
                !clear,
                "{text:?} rule path: {:?}",
                persons(text)
            );
            assert_eq!(
                kept_gliner_person(text, name, false),
                !clear,
                "{text:?} NER singleton path"
            );
            assert!(
                kept_gliner_person(text, name, true),
                "{text:?} not masked with mask_first_names"
            );
        }
    }

    #[test]
    fn a_postscript_word_is_not_a_postscript_marker() {
        // `Psychologue` opens with the letters `ps` but is no marker: the name
        // after it is not a signature author. Only the marker boundary decides.
        assert_eq!(ps_marker_end("Psychologue Mila"), None);
        assert_eq!(ps_marker_end("> P.S. Mila"), Some(6));
        assert_eq!(ps_marker_end("NBA Mila"), None);
    }

    #[test]
    fn a_postscript_author_keeps_its_span_when_the_line_has_trailing_space() {
        // The author span must land on the name itself, even when the line ends
        // in spaces or a carriage return: the offset is taken from the full line.
        let text = "P.S. Mila   \r\nà bientôt";
        let found: Vec<&str> = EmailLayer::new()
            .analyze(text)
            .into_iter()
            .filter(|span| span.kind == EntityKind::Person)
            .map(|span| &text[span.start..span.end])
            .collect();
        assert!(found.contains(&"Mila"), "{found:?}");
    }

    #[test]
    fn unknown_rule_tokens_are_never_dropped() {
        // (P1) A rule-detected token the given-name lexicon does not know is
        // masked, never dropped.
        for (text, name) in [
            ("Salut Zorblath", "Zorblath"),
            ("Bonjour Quillfeather,", "Quillfeather"),
            ("Zorblath, peux-tu?", "Zorblath"),
        ] {
            let found = persons_with(text, false);
            assert!(
                found.iter().any(|value| value == name),
                "{text:?} dropped an unknown rule token: {found:?}"
            );
        }
    }

    #[test]
    fn new_closings_open_a_signature_block() {
        // (P1) The added closings and their variants keep the name below them
        // masked, including across an emoji-only or title-only line.
        for closing in [
            "Mit freundlichen Grüßen",
            "Viele Grüße",
            "Liebe Grüße",
            "此致敬礼",
            "此致",
            "敬礼",
            "祝好",
            "顺祝商祺",
            "Met vriendelike groete",
            "Groete",
            "Üdvözlettel",
            "Tisztelettel",
            "Best regards",
            "Kind regards",
            "Regards",
            "Cordialement",
            "Bien à vous",
            "Bisous",
        ] {
            for text in [
                format!("{closing}\nMila"),
                format!("{closing}\n😊\nMila"),
                format!("Best regards\n{closing}\nMila"),
            ] {
                let found = persons_with(&text, false);
                assert!(
                    found.iter().any(|value| value == "Mila"),
                    "{closing:?} in {text:?} dropped the sign-off name: {found:?}"
                );
                assert!(
                    kept_gliner_person(&text, "Mila", false),
                    "{text:?} dropped the sign-off NER singleton"
                );
            }
        }
        // A title-only line between the closing and the name is stepped over too.
        let found = persons_with("Best regards\nDr.\nMila", false);
        assert!(found.iter().any(|value| value == "Mila"), "{found:?}");
    }

    #[test]
    fn cjk_person_spans_are_always_kept() {
        for (text, name) in [
            ("王小明说", "王小明"),
            ("김민수 왔다", "김민수"),
            ("李 said hello", "李"),
            ("Dr 王 said hello", "王"),
        ] {
            assert!(
                kept_gliner_person(text, name, false),
                "{text:?} dropped a CJK name"
            );
        }
    }
}
