//! K10: Standard-level recognisers for health and Art. 9 terms, bare Chinese
//! mobile numbers and API-key prefixes. Every value below is fictional.

use kernel_privacy::{Anonymizer, EntityKind, Registry};

/// The text as the anonymiser would send it to a provider.
fn masked(text: &str) -> String {
    let spans = Registry::new().analyze(text);
    Anonymizer::new([0x4B; 32]).anonymize(text, &spans).0
}

#[test]
fn health_terms_are_masked_in_every_language() {
    let cases = [
        ("She has cancer and starts chemotherapy.", "cancer"),
        ("Type 2 diabetes was found at the checkup.", "diabetes"),
        ("He tested HIV positive in 2019.", "HIV"),
        (
            "Elle suit une chimiothérapie depuis mars.",
            "chimiothérapie",
        ),
        ("Il vit avec le VIH depuis 2015.", "VIH"),
        ("Hy is al drie jaar met kanker besig.", "kanker"),
        ("Anyám cukorbetegségben szenved.", "cukorbetegségben"),
        ("Oče ima sladkorno bolezen že dvajset let.", "sladkorno"),
        ("Mama je prejela diagnozo raka.", "raka"),
        ("他两年前被确诊为糖尿病。", "糖尿病"),
    ];
    for (text, term) in cases {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn health_terms_match_case_plural_and_accents() {
    for term in [
        "CANCER",
        "Cancers",
        "chimiotherapie",
        "Diabètes",
        "SÉROPOSITIF",
        "KANKERS",
    ] {
        let out = masked(&format!("Dossier : {term} ."));
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn health_terms_must_be_whole_words() {
    for text in [
        "The cancelled flight left at noon.",
        "Rakete za Bohinj.",
        "Rákóczi úti lakás.",
        "Le goût du café est riche.",
    ] {
        assert!(!masked(text).contains("HEALTH_"), "over-masked: {text}");
    }
}

#[test]
fn health_kind_is_the_existing_health_label() {
    let spans = Registry::new().analyze("She has cancer.");
    assert!(
        spans.iter().any(|span| span.kind == EntityKind::Health),
        "no Health span: {spans:?}"
    );
}

#[test]
fn art9_terms_are_masked_under_their_own_label() {
    let cases = [
        ("Il est musulman depuis l'enfance.", "musulman", "RELIGION_"),
        ("She is Jewish and works in finance.", "Jewish", "RELIGION_"),
        (
            "Elle est homosexuelle et vit à Lyon.",
            "homosexuelle",
            "SEXUAL_ORIENTATION_",
        ),
        (
            "He came out as gay at the conference.",
            "gay",
            "SEXUAL_ORIENTATION_",
        ),
        ("Il est syndiqué à la CGT.", "syndiqué", "TRADE_UNION_"),
        (
            "She is a union member at the plant.",
            "union member",
            "TRADE_UNION_",
        ),
        (
            "Données sur l'origine ethnique des salariés.",
            "origine ethnique",
            "ETHNIC_ORIGIN_",
        ),
    ];
    for (text, term, label) in cases {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {term}: {out}");
    }
}

#[test]
fn art9_terms_must_not_mask_a_given_name() {
    let out = masked("Christian Dior opened a store.");
    assert!(!out.contains("RELIGION_"), "over-masked: {out}");
    assert!(!out.contains("SEXUAL_ORIENTATION_"), "over-masked: {out}");
}

#[test]
fn bare_chinese_mobile_numbers_are_masked() {
    for (text, number) in [
        ("Mobile 13800138000.", "13800138000"),
        ("手机 13800138000 请回电", "13800138000"),
        ("tel 15912345678", "15912345678"),
        ("138-0013-8000", "138-0013-8000"),
        ("138 0013 8000", "138 0013 8000"),
        ("139.0013.9000", "139.0013.9000"),
    ] {
        let out = masked(text);
        assert!(!out.contains(number), "{number} left in clear: {out}");
    }
}

#[test]
fn a_chinese_mobile_is_masked_whatever_the_words_around_it() {
    for (text, number) in [
        ("Order contact: 138-1234-5678", "138-1234-5678"),
        ("Eating disorder hotline 138-1234-5678", "138-1234-5678"),
        ("Facture client, tél 138 1234 5678", "138 1234 5678"),
        ("订单联系电话：13812345678", "13812345678"),
        ("In order to reach me: 13812345678", "13812345678"),
        ("At the border call 13812345678", "13812345678"),
    ] {
        let out = masked(text);
        assert!(!out.contains(number), "{number} left in clear: {out}");
    }
}

#[test]
fn a_twelve_digit_run_is_not_a_phone() {
    let spans = Registry::new().analyze("138001380001");
    assert!(
        spans.iter().all(|span| span.kind != EntityKind::Phone),
        "phone in a longer digit run: {spans:?}"
    );
}

#[test]
fn a_bare_and_an_international_chinese_mobile_share_one_token() {
    let mut anonymizer = Anonymizer::new([0x4B; 32]);
    let (bare, _) = anonymizer.token_for(EntityKind::Phone, "13800138000");
    let (international, _) = anonymizer.token_for(EntityKind::Phone, "+86 138 0013 8000");
    assert_eq!(bare, international);
}

/// Fictional key shapes. Each is built from fragments, so the source holds no
/// whole key-shaped literal. The last one has an IBAN-shaped tail (security-review B).
const KEYS: &[&str] = &[
    concat!("sk-proj-", "FAKEKEY0123456789abcdefGHIJKL"),
    concat!("sk-ant-", "api03-FAKEKEY0123456789abcdefGHIJKL"),
    concat!("sk-", "FAKEKEY0123456789abcdefGHIJKL"),
    concat!("ghp_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"),
    concat!("github_pat_", "FAKEKEY0123456789_abcdefGHIJ"),
    concat!("xoxb-", "0000000000-FAKEKEYFAKEKEY"),
    concat!("AKIA", "FAKEFAKEFAKEFAKE"),
    concat!("AIza", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK"),
    concat!("eyJ", "hbGciFAKE.eyJzdWJFAKE.FAKEsig"),
    concat!("sk-proj-", "FR7630006000011234567890189XYZ"),
];

#[test]
fn api_key_prefixes_are_masked_whole() {
    for key in KEYS {
        let out = masked(&format!("key={key} end"));
        assert!(!out.contains(key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {key}: {out}");
        assert!(!out.contains("IBAN_"), "IBAN label on {key}: {out}");
    }
}

#[test]
fn a_short_sk_word_is_not_a_key() {
    for text in ["the sk-learn package", "task-manager-sk-tools"] {
        assert!(!masked(text).contains("SECRET_"), "over-masked: {text}");
    }
}

#[test]
fn a_key_after_han_text_or_an_underscore_is_masked_whole() {
    let anthropic = concat!("sk-ant-", "api03-FAKEKEY0123456789abcdefGHIJKL");
    let aws = concat!("AKIA", "FAKEFAKEFAKEFAKE");
    let cases: [(String, &str); 4] = [
        (format!("我的密钥是{anthropic}"), anthropic),
        (format!("token_{anthropic}"), anthropic),
        (format!("task-{anthropic}"), anthropic),
        (format!("密钥{aws}"), aws),
    ];
    for (text, key) in cases {
        let out = masked(&text);
        assert!(!out.contains(key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
        assert!(!out.contains("IBAN_"), "IBAN label on the tail: {out}");
    }
}

#[test]
fn a_key_wrapped_at_80_columns_is_masked_whole() {
    let key = format!(
        "sk-proj-{}",
        "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz".repeat(3)
    );
    let wrapped = format!("{}\n{}", &key[..80], &key[80..]);
    let out = masked(&format!("config: {wrapped} end"));
    // No 12-character window of the key may survive in clear, on either line.
    for start in (0..key.len() - 12).step_by(4) {
        let window = &key[start..start + 12];
        assert!(!out.contains(window), "{window} left in clear: {out}");
    }
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn a_key_wrapped_after_a_short_prefix_is_masked() {
    let out = masked("token sk-proj-FAKEKEY0123\nFAKEKEY456789abcdefGHIJKL end");
    assert!(!out.contains("FAKEKEY0123"), "first line in clear: {out}");
    assert!(
        !out.contains("FAKEKEY456789abcdefGHIJKL"),
        "tail in clear: {out}"
    );
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn a_secret_wins_over_an_iban_or_a_phone_on_the_same_bytes() {
    for text in [
        "sk-proj-FAKEKEY0123\nFR7630006000011234567890189XYZ",
        "key=sk-proj-FAKEKEY0123456789abcdef13812345678XYZ",
    ] {
        let out = masked(text);
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
        assert!(!out.contains("IBAN_"), "IBAN label on the key: {out}");
        assert!(!out.contains("PHONE_"), "PHONE label on the key: {out}");
    }
}

#[test]
fn stripe_and_other_issuer_keys_are_masked_whole() {
    let keys = [
        concat!("sk_live_", "FAKEKEY0123456789abcdef"),
        concat!("rk_live_", "FAKEKEY0123456789abcdef"),
        concat!("sk_test_", "FAKEKEY0123456789abcdef"),
        concat!("rk_test_", "FAKEKEY0123456789abcdef"),
        concat!("pk_live_", "FAKEKEY0123456789abcdef"),
        concat!("whsec_", "FAKEKEY0123456789abcdef"),
        concat!("hf_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA"),
        concat!("gsk_", "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"),
        concat!("glpat-", "FAKEKEY0123456789abcd"),
        concat!("xapp-", "1-FAKEKEY0123-4567890123-abcdef"),
        concat!("ya29.", "FAKEKEY0123456789abcdefGHIJ"),
    ];
    for key in keys {
        let out = masked(&format!("Authorization: Bearer {key} end"));
        assert!(!out.contains(key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {key}: {out}");
    }
}

#[test]
fn traditional_chinese_health_terms_are_masked() {
    for term in ["憂鬱症", "愛滋病", "腫瘤", "懷孕", "高血壓", "化療", "癲癇"] {
        let out = masked(&format!("他有{term}。"));
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn han_terms_match_across_zero_width_characters_and_spaces() {
    for text in ["他有糖\u{200B}尿病。", "他有糖 尿 病。"] {
        let out = masked(text);
        assert!(
            !out.contains('糖') && !out.contains('尿'),
            "left in clear: {out}"
        );
        assert!(out.contains("HEALTH_"), "no HEALTH token: {out}");
    }
}

#[test]
fn french_feminine_forms_are_masked_like_the_masculine() {
    for (text, term, label) in [
        (
            "Elle est séropositive depuis 2015.",
            "séropositive",
            "HEALTH_",
        ),
        (
            "Elle est dépressive depuis l'hiver.",
            "dépressive",
            "HEALTH_",
        ),
        ("Elle est syndiquée à la CGT.", "syndiquée", "TRADE_UNION_"),
        (
            "Traitement antirétroviral quotidien.",
            "antirétroviral",
            "HEALTH_",
        ),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {term}: {out}");
    }
}

#[test]
fn ambiguous_abbreviations_are_masked_next_to_a_health_cue() {
    for (text, term) in [
        ("She has MS and is in pain.", "MS"),
        ("Il a une SEP diagnostiquée.", "SEP"),
        ("Patient souffrant de TOC.", "TOC"),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn ambiguous_abbreviations_stay_clear_without_a_health_cue() {
    for text in ["Microsoft MS Office update", "Voir le TOC du document."] {
        assert!(!masked(text).contains("HEALTH_"), "over-masked: {text}");
    }
}

#[test]
fn stroke_anxiety_antidepressants_ocd_crohn_herpes_and_drugs_are_masked() {
    for (text, term) in [
        ("He had a stroke last year.", "stroke"),
        ("Il a eu un AVC en mars.", "AVC"),
        ("Anxiety is common in students.", "Anxiety"),
        ("Elle souffre d'anxiété.", "anxiété"),
        ("Il prend un antidépresseur.", "antidépresseur"),
        ("She takes an antidepressant.", "antidepressant"),
        ("OCD affects her daily life.", "OCD"),
        ("Il a la maladie de Crohn.", "Crohn"),
        ("Herpes outbreak on the lip.", "Herpes"),
        ("Elle prend du Prozac.", "Prozac"),
        ("Zoloft prescription renewed.", "Zoloft"),
        ("Hy gebruik 'n antidepressant.", "antidepressant"),
        ("Hy het 'n dwangneurose.", "dwangneurose"),
        ("Egy agyvérzés után.", "agyvérzés"),
        ("Ima anksiozno motnjo.", "anksiozno"),
        ("Ima možganska kap.", "možganska kap"),
        ("Ima Crohnovo bolezen.", "Crohnovo"),
        ("他患过卒中。", "卒中"),
        ("他有焦虑。", "焦虑"),
        ("他在吃抗抑郁药。", "抗抑郁"),
        ("她患有強迫症。", "強迫症"),
        ("他得了克罗恩病。", "克罗恩病"),
        ("他有疱疹。", "疱疹"),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

#[test]
fn compounds_and_case_endings_in_hu_af_and_sl_are_masked() {
    for (text, term) in [
        ("A tüdőrákja miatt kezelik.", "tüdőrákja"),
        ("Prosztatarákban szenved.", "prosztatarákban"),
        ("Az orvos rákja súlyos.", "rákja"),
        ("Ez a ráknak szól.", "ráknak"),
        ("Terhesen dolgozik.", "Terhesen"),
        ("Hy het borskanker.", "borskanker"),
        ("Sy het longkanker.", "longkanker"),
        ("Die suikersiektepasiënt rus.", "suikersiektepasiënt"),
        ("Oče ima diabetesom.", "diabetesom"),
        ("Ima hepatitisom.", "hepatitisom"),
        ("Ima multiplo sklerozo.", "sklerozo"),
        ("Ima možgansko kap.", "možgansko"),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
}

/// Normal prose per language (one sentence per line), with no health content.
const PROSE: [(&str, &str); 3] = [
    ("hu", include_str!("../../../qa/privacy-eval/prose/hu.txt")),
    ("af", include_str!("../../../qa/privacy-eval/prose/af.txt")),
    ("sl", include_str!("../../../qa/privacy-eval/prose/sl.txt")),
];

/// Whether a span comes from the K10 recognisers. The e-mail layer's name
/// heuristic (`email_layer_*`) also tags sentence-initial words in prose; that
/// behaviour predates K10 and is measured apart by the eval harness.
fn k10_span(span: &kernel_privacy::Span) -> bool {
    matches!(span.recognizer, "sensitive_terms" | "secrets")
}

#[test]
fn normal_prose_is_over_masked_in_at_most_one_percent_of_lines() {
    let registry = Registry::new();
    for (lang, prose) in PROSE {
        let lines: Vec<&str> = prose
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(lines.len(), 100, "{lang} corpus is not 100 lines");
        let over: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|line| registry.analyze(line).iter().any(k10_span))
            .collect();
        assert!(
            over.len() * 100 <= lines.len(),
            "{lang}: {} of {} lines over-masked: {over:?}",
            over.len(),
            lines.len()
        );
    }
}

/// The Standard registry on one megabyte of mixed prose, health text and keys.
/// Release timing only: `cargo test --release -- --ignored --nocapture`.
#[test]
#[ignore = "release timing: run with --release --ignored --nocapture"]
fn one_megabyte_of_mixed_text_analyses_in_bounded_time() {
    let unit = "Elle a une consultation le 12 mars, sa tension est normale. Le patient souffre de diabète et prend de l'insuline. Contact: 138-1234-5678, token sk-proj-FAKEKEY0123456789abcdefGHIJKL. Ana je kupila raketo. 他有糖尿病。\n";
    let text = unit.repeat(1_000_000 / unit.len() + 1);
    let registry = Registry::new();
    let started = std::time::Instant::now();
    let spans = registry.analyze(&text);
    let elapsed = started.elapsed();
    eprintln!(
        "PERF analyze {} bytes -> {} spans in {:?}",
        text.len(),
        spans.len(),
        elapsed
    );
    assert!(!spans.is_empty());
    assert!(elapsed < linear_budget(), "one megabyte took {elapsed:?}");
}

#[test]
fn common_words_that_contain_a_short_health_root_are_not_masked() {
    for text in ["Poraka je prišla včeraj.", "Praka je bila v muzeju."] {
        let out = masked(text);
        assert!(!out.contains("HEALTH_"), "over-masked: {text} -> {out}");
    }
}

#[test]
fn a_wrapped_key_longer_than_128_bytes_is_one_token() {
    let key = format!(
        "sk-proj-{}",
        "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz".repeat(3)
    );
    let wrapped = format!("{}\n{}", &key[..80], &key[80..]);
    let spans = Registry::new().analyze(&format!("config: {wrapped} end"));
    let secret = spans
        .iter()
        .filter(|span| span.kind == EntityKind::Secret)
        .count();
    assert_eq!(secret, 1, "one key split into {secret} spans: {spans:?}");
}

/// One megabyte of each input that the wrap join once walked quadratically.
/// Release timing, run in the gate: `cargo test --release -- --ignored`.
#[test]
#[ignore = "release timing: run with --release --ignored"]
fn wrapped_key_inputs_of_one_megabyte_are_linear() {
    let mut task_list = String::new();
    let mut n = 0usize;
    while task_list.len() < 1_000_000 {
        n += 1;
        task_list.push_str(&format!("task-{}\n", n % 10));
    }
    let inputs = [
        ("sk-a lines", "sk-a\n".repeat(200_000)),
        ("AKIA lines", "AKIA\n".repeat(200_000)),
        ("task lines", task_list),
    ];
    let registry = Registry::new();
    for (name, text) in inputs {
        let started = std::time::Instant::now();
        let spans = registry.analyze(&text);
        let elapsed = started.elapsed();
        eprintln!(
            "PERF {name}: {} bytes, {} spans, {elapsed:?}",
            text.len(),
            spans.len()
        );
        assert!(
            elapsed.as_secs_f64() < 2.0,
            "{name}: one megabyte took {elapsed:?}"
        );
    }
}

#[test]
fn a_wrapped_key_with_an_indented_or_quoted_continuation_is_masked() {
    let head = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuv";
    let tail = "wxyzFAKEKEY0123456789TAIL";
    let cases = [
        format!("api_key: sk-proj-{head}\n  {tail} end"),
        format!("> sk-proj-{head}\n> {tail} end"),
        format!("> sk-proj-{head}\n>> {tail} end"),
        format!("sk-proj-{head}\n\"{tail}\" end"),
    ];
    for text in cases {
        let out = masked(&text);
        assert_no_window_in_clear(&out, head);
        assert_no_window_in_clear(&out, tail);
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
    }
}

/// No nine-character window of `key` may survive in clear in `out`: a masked key
/// can still leak its tail through a neighbouring label.
fn assert_no_window_in_clear(out: &str, key: &str) {
    for start in 0..key.len() - 9 {
        let window = &key[start..start + 9];
        assert!(!out.contains(window), "{window} left in clear: {out}");
    }
}

#[test]
fn a_short_first_line_followed_by_an_indented_tail_is_masked() {
    let tail = "FAKEKEY0123456789abcdefGHIJKL";
    let out = masked(&format!("sk-proj-FAKEK\n    {tail} end"));
    assert!(!out.contains("FAKEK\n"), "first line left in clear: {out}");
    assert_no_window_in_clear(&out, tail);
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn private_key_blocks_are_masked_whole() {
    let body = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789ABCDEFGH";
    for kind in [
        "OPENSSH PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
        "PRIVATE KEY",
    ] {
        let begin = format!("-----BEGIN {kind}-----");
        let end = format!("-----END {kind}-----");
        let text = format!("config\n{begin}\n{body}\n{body}\n{end}\nafter");
        let out = masked(&text);
        assert!(!out.contains("BEGIN"), "{kind}: header in clear: {out}");
        assert_no_window_in_clear(&out, body);
        assert!(out.contains("SECRET_"), "{kind}: no SECRET token: {out}");
    }
}

#[test]
fn aws_secret_access_keys_are_masked_by_their_key_name() {
    let value = concat!("FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE", "");
    for text in [
        format!("AWS_SECRET_ACCESS_KEY={value}"),
        format!("aws_secret_access_key = {value}"),
        format!("\"aws_secret_access_key\": \"{value}\""),
        format!("aws_secret_access_key: {value}"),
    ] {
        let out = masked(&text);
        assert!(!out.contains(value), "value left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
    }
}

#[test]
fn age_secret_keys_are_masked() {
    let key = concat!(
        "AGE-SECRET-KEY-1",
        "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN"
    );
    let out = masked(&format!("identity {key} end"));
    assert!(!out.contains("QPZRY9"), "age key in clear: {out}");
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn provider_prefixes_are_masked_whole() {
    let telegram = format!("1234567890:AA{}", "FAKEKEY0123456789abcdefGHIJKLmno");
    let keys = [
        concat!("npm_", "FAKEKEY0123456789abcdefGHIJKLmnopqrst").to_string(),
        concat!("pypi-", "AgEIcHlwaS5vcmcFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE").to_string(),
        concat!(
            "SG.",
            "FAKEKEY0123456789ab.FAKEKEY0123456789abcdefGHIJKLmnop"
        )
        .to_string(),
        concat!(
            "dop_v1_",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .to_string(),
        concat!("r8_", "FAKEKEY0123456789abcdefGHIJKLmnopqrst").to_string(),
        concat!("SK", "0123456789abcdef0123456789abcdef").to_string(),
        telegram,
        concat!("lin_api_", "FAKEKEY0123456789abcdefGHIJKLmnopqrs").to_string(),
        concat!("shpat_", "0123456789abcdef0123456789abcdef").to_string(),
        concat!("sbp_", "0123456789abcdef0123456789abcdef01234567").to_string(),
        concat!("ntn_", "FAKEKEY0123456789abcdefGHIJKLmnopqrst").to_string(),
    ];
    for key in keys {
        let out = masked(&format!("token {key} end"));
        assert!(!out.contains(&key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {key}: {out}");
    }
}

#[test]
fn traditional_taiwan_and_mainland_forms_are_masked_with_their_label() {
    let cases = [
        ("胰島素", "HEALTH_"),
        ("中風", "HEALTH_"),
        ("自閉症", "HEALTH_"),
        ("自殺", "HEALTH_"),
        ("殘疾", "HEALTH_"),
        ("孕婦", "HEALTH_"),
        ("成癮", "HEALTH_"),
        ("自殘", "HEALTH_"),
        ("失智症", "HEALTH_"),
        ("阿茲海默症", "HEALTH_"),
        ("阿爾茲海默症", "HEALTH_"),
        ("猶太人", "RELIGION_"),
        ("伊斯蘭教徒", "RELIGION_"),
        ("錫克教徒", "RELIGION_"),
    ];
    for (term, label) in cases {
        let out = masked(&format!("他是{term}。"));
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {term}: {out}");
    }
}

#[test]
fn the_breaker_terms_are_masked_in_their_languages() {
    let cases = [
        ("Elle est anorexique depuis un an.", "anorexique", "HEALTH_"),
        ("Il est boulimique depuis l'été.", "boulimique", "HEALTH_"),
        ("Il est bipolaire depuis 2010.", "bipolaire", "HEALTH_"),
        ("Elle est déprimée depuis l'hiver.", "déprimée", "HEALTH_"),
        ("Une patiente leucémique.", "leucémique", "HEALTH_"),
        ("Il est insomniaque.", "insomniaque", "HEALTH_"),
        ("Il est obèse.", "obèse", "HEALTH_"),
        ("Il est toxicomane.", "toxicomane", "HEALTH_"),
        ("Elle a subi une IVG en mars.", "IVG", "HEALTH_"),
        ("Il a parlé de son avortement.", "avortement", "HEALTH_"),
        ("Elle a une trisomie 21.", "trisomie", "HEALTH_"),
        ("Il prend du Lexomil le soir.", "Lexomil", "HEALTH_"),
        ("He is bipolar and works nights.", "bipolar", "HEALTH_"),
        ("She felt depressed all week.", "depressed", "HEALTH_"),
        ("The cancerous cells spread.", "cancerous", "HEALTH_"),
        ("She had an abortion in 2019.", "abortion", "HEALTH_"),
        ("A case of syphilis was reported.", "syphilis", "HEALTH_"),
        (
            "A chlamydia test came back positive.",
            "chlamydia",
            "HEALTH_",
        ),
        ("Her lupus flared up in spring.", "lupus", "HEALTH_"),
        ("He has cirrhosis of the liver.", "cirrhosis", "HEALTH_"),
        (
            "She takes sertraline each morning.",
            "sertraline",
            "HEALTH_",
        ),
        ("He switched to fluoxetine.", "fluoxetine", "HEALTH_"),
        ("He takes PrEP for HIV prevention.", "PrEP", "HEALTH_"),
        ("Sy het 'n aborsie gehad.", "aborsie", "HEALTH_"),
        ("A bipoláris zavar kezelése.", "bipoláris", "HEALTH_"),
        ("Szívroham érte tavaly.", "Szívroham", "HEALTH_"),
        ("Oče je imel infarkt.", "infarkt", "HEALTH_"),
        ("Bolnik je imel kap in je v bolnišnici.", "kap", "HEALTH_"),
    ];
    let registry = Registry::new();
    for (text, term, label) in cases {
        let spans = registry.analyze(text);
        let out = Anonymizer::new([0x4B; 32]).anonymize(text, &spans).0;
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {term}: {out}");
    }
}

#[test]
fn hungarian_rak_compounds_and_case_forms_need_the_accent() {
    for (text, term) in [
        ("A méhnyakrák miatt kezelik.", "méhnyakrák"),
        ("A vastagbélrák szűrése pénteken.", "vastagbélrák"),
        ("Rákszűrés lesz pénteken.", "Rákszűrés"),
        ("Rákkutatás folyik az egyetemen.", "Rákkutatás"),
        ("Rákból gyógyult meg.", "Rákból"),
        ("Ráktól fél a családja.", "Ráktól"),
        ("Rákba került a betegség.", "Rákba"),
    ] {
        let out = masked(text);
        assert!(!out.contains(term), "{term} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {term}: {out}");
    }
    for text in [
        "Rak le a dobozt a padlóra.",
        "Az árak emelkedtek a héten.",
        "Rakospalota a kerület neve.",
    ] {
        assert!(!masked(text).contains("HEALTH_"), "over-masked: {text}");
    }
}

/// The reference list: a table of conditions, drugs and Art. 9 categories with
/// their forms in six languages (see its header for the sources).
const REFERENCE: &str = include_str!("../data/sensitive-terms-reference.md");

/// The lexicon the reference list must be a part of.
const LEXICON_ROWS: &str = include_str!("../data/sensitive-terms-v1.tsv");

/// The cue word that makes a sentence a health sentence in each language.
fn reference_cue(lang: &str) -> &'static str {
    match lang {
        "af" => "pasiënt",
        "hu" => "beteg",
        "sl" => "bolnik",
        "zh" => "患者",
        _ => "patient",
    }
}

#[test]
fn every_reference_term_is_a_lexicon_row_and_is_masked_in_its_language() {
    use std::collections::HashSet;
    let registry = Registry::new();
    let rows: HashSet<&str> = LEXICON_ROWS.lines().collect();
    let languages = [
        ("en", 3),
        ("fr", 4),
        ("af", 5),
        ("hu", 6),
        ("sl", 7),
        ("zh", 8),
    ];
    let mut per_language = [0usize; 6];
    let mut drugs = 0usize;
    let check = |category: &str, lang: &str, term: &str| {
        // A Hungarian form with the accent rák is the accent rule in code, not a row.
        if !(lang == "hu" && term.contains("rák")) {
            // A cue-gated form (a `?` row, as for a bare Slovene rak) is a row too.
            let row = format!("{category}\t{lang}\t{term}");
            let gated = format!("{category}\t{lang}\t?{term}");
            assert!(
                rows.contains(row.as_str()) || rows.contains(gated.as_str()),
                "reference row missing from the lexicon: {row}"
            );
        }
        let sentence = format!("{}: {term}.", reference_cue(lang));
        let spans = registry.analyze(&sentence);
        let out = Anonymizer::new([0x4B; 32]).anonymize(&sentence, &spans).0;
        assert!(!out.contains(term), "{term} ({lang}) left in clear: {out}");
        assert!(
            out.contains(&format!("{category}_")),
            "no {category} token for {term} ({lang}): {out}"
        );
    };
    for line in REFERENCE.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        match cells.get(1).and_then(|id| id.chars().next()) {
            Some('C') | Some('A') if cells.len() >= 9 => {
                for (index, (lang, column)) in languages.iter().enumerate() {
                    let term = cells[*column];
                    if term != "—" {
                        per_language[index] += 1;
                        check(cells[2], lang, term);
                    }
                }
            }
            Some('D') if cells.len() >= 4 => {
                drugs += 1;
                check("HEALTH", "xx", cells[3]);
            }
            _ => {}
        }
    }
    for (index, (lang, _)) in languages.iter().enumerate() {
        assert!(
            per_language[index] >= 120,
            "{lang}: only {} reference terms",
            per_language[index]
        );
    }
    assert!(drugs >= 40, "only {drugs} drug names");
}

#[test]
fn a_hyphenated_word_that_starts_with_sk_is_not_a_key() {
    for text in [
        "risk-adjusted-performance-metrics-quarterly-review",
        "task-management-system-for-remote-teams-2025",
    ] {
        let spans = Registry::new().analyze(text);
        assert!(
            spans.iter().all(|span| span.kind != EntityKind::Secret),
            "over-masked as a key: {text}: {spans:?}"
        );
    }
}

#[test]
fn medium_risk_is_not_a_stroke_and_a_stroke_is() {
    assert!(
        !masked("这是中风险等级的项目。").contains("HEALTH_"),
        "中风险 over-masked"
    );
    assert!(
        masked("他患有中风。").contains("HEALTH_"),
        "中风 not masked"
    );
}

#[test]
fn sep_followed_by_a_year_or_a_day_is_a_month() {
    let out = masked("Patient, rendez-vous le 12 SEP 2025.");
    assert!(
        !out.contains("HEALTH_"),
        "SEP 2025 masked as the disease: {out}"
    );
    let out = masked("Patient, réunion le SEP 12.");
    assert!(
        !out.contains("HEALTH_"),
        "SEP 12 masked as the disease: {out}"
    );
}

#[test]
fn han_terms_split_by_a_middle_dot_or_a_hyphen_are_masked() {
    for text in ["他有糖·尿·病。", "他有糖-尿-病。"] {
        let out = masked(text);
        assert!(
            !out.contains('糖') && !out.contains('尿'),
            "left in clear: {out}"
        );
        assert!(out.contains("HEALTH_"), "no HEALTH token: {out}");
    }
}

#[test]
fn keys_with_zero_width_fullwidth_or_dash_variants_are_masked_whole() {
    let tail = "FAKEKEY0123456789abcdefGHIJKL";
    for text in [
        "key sk-proj-FAKEKEY\u{200B}0123456789abcdefGHIJKL end".to_string(),
        format!("key ｓｋ-ant-api03-{tail} end"),
        format!("key sk\u{2010}proj\u{2010}{tail} end"),
    ] {
        let out = masked(&text);
        assert!(!out.contains("FAKEKEY"), "key left in clear: {out}");
        assert!(
            !out.contains("0123456789"),
            "key digits left in clear: {out}"
        );
        assert!(out.contains("SECRET_"), "no SECRET token: {out}");
    }
}

#[test]
fn afrikaans_kaartjies_is_not_varicose_veins() {
    let out = masked("Wys asseblief die kaartjies by die hek.");
    assert!(
        !out.contains("HEALTH_"),
        "kaartjies (tickets) over-masked: {out}"
    );
}

#[test]
fn inflected_forms_of_health_terms_are_masked_hu_sl_and_brand() {
    for (text, form, label) in [
        ("Magas vérnyomással él.", "vérnyomással", "HEALTH_"),
        ("Krónikus fájdalommal küzd.", "fájdalommal", "HEALTH_"),
        ("Ízületi gyulladással jár.", "gyulladással", "HEALTH_"),
        ("Down-szindrómával született.", "szindrómával", "HEALTH_"),
        ("Orvosi igazolást kért.", "igazolást", "HEALTH_"),
        ("Kórházi kezelésen volt.", "kezelésen", "HEALTH_"),
        (
            "Posttraumás stresszzavarral küzd.",
            "stresszzavarral",
            "HEALTH_",
        ),
        ("Szklerózis multiplexszel él.", "multiplexszel", "HEALTH_"),
        ("Etnikai származása miatt.", "származása", "ETHNIC_ORIGIN_"),
        ("Sérvvel operálták.", "Sérvvel", "HEALTH_"),
        ("Köszvénnyel küzd.", "Köszvénnyel", "HEALTH_"),
        ("Mama ima levkemijo.", "levkemijo", "HEALTH_"),
        ("Zaradi hipertenzije je bolna.", "hipertenzije", "HEALTH_"),
        ("Pacient s pljučnico.", "pljučnico", "HEALTH_"),
        ("Ima gripo.", "gripo", "HEALTH_"),
        ("Ima psihoze.", "psihoze", "HEALTH_"),
        ("Ima osteoporozo.", "osteoporozo", "HEALTH_"),
        ("Ima tromboze.", "tromboze", "HEALTH_"),
        ("Ima sepso.", "sepso", "HEALTH_"),
        ("Ima ciroze.", "ciroze", "HEALTH_"),
        ("Ima anemijo.", "anemijo", "HEALTH_"),
        ("Ima razjedo.", "razjedo", "HEALTH_"),
        ("Ima klamidijo.", "klamidijo", "HEALTH_"),
        ("Imel je cerebralno paralizo.", "paralizo", "HEALTH_"),
        ("Ima panične motnje.", "motnje", "HEALTH_"),
        ("Ima kronično bolečino.", "bolečino", "HEALTH_"),
        ("Zaradi raka prostate.", "raka", "HEALTH_"),
        ("Umrl je za rakom.", "rakom", "HEALTH_"),
        ("Vzel je Xanaxot.", "Xanaxot", "HEALTH_"),
        ("Jemlje Truvadát.", "Truvadát", "HEALTH_"),
        ("Vzel je Seroquelt.", "Seroquelt", "HEALTH_"),
        ("Vzel je Prozacom.", "Prozacom", "HEALTH_"),
        ("Vzel je Xanaxa.", "Xanaxa", "HEALTH_"),
    ] {
        let out = masked(text);
        assert!(!out.contains(form), "{form} left in clear: {out}");
        assert!(out.contains(label), "no {label} token for {form}: {out}");
    }
}

#[test]
fn hungarian_rak_with_a_possessive_and_a_case_is_masked() {
    for (text, form) in [
        ("Rákomról beszél.", "Rákomról"),
        ("Rákjával küzd.", "Rákjával"),
        ("Rákommal él.", "Rákommal"),
        ("Rákunkról szól.", "Rákunkról"),
        ("Rákjukat kezelik.", "Rákjukat"),
    ] {
        let out = masked(text);
        assert!(!out.contains(form), "{form} left in clear: {out}");
        assert!(out.contains("HEALTH_"), "no HEALTH token for {form}: {out}");
    }
    let out = masked("A Rákos-patak mellett sétáltunk.");
    assert!(
        !out.contains("HEALTH_"),
        "the stream Rákos-patak over-masked: {out}"
    );
}

/// The Han fold table: a traditional character, its simplified form, and the OpenCC
/// file the pair came from (TS: traditional to simplified, ST: simplified to
/// traditional).
const HAN_FOLD_TABLE: &str = include_str!("../data/han-fold-v1.tsv");

#[test]
fn every_zh_reference_term_in_traditional_is_masked() {
    use std::collections::HashMap;
    let mut simplified_to_traditional: HashMap<char, char> = HashMap::new();
    for line in HAN_FOLD_TABLE.lines().filter(|line| !line.starts_with('#')) {
        let fields: Vec<&str> = line.split('\t').collect();
        if let [traditional, simplified, "ST"] = fields[..] {
            if let (Some(t), Some(s)) = (traditional.chars().next(), simplified.chars().next()) {
                simplified_to_traditional.entry(s).or_insert(t);
            }
        }
    }
    assert!(
        simplified_to_traditional.len() >= 80,
        "the fold table has {} ST pairs",
        simplified_to_traditional.len()
    );
    let to_traditional = |simplified: &str| -> String {
        simplified
            .chars()
            .map(|ch| simplified_to_traditional.get(&ch).copied().unwrap_or(ch))
            .collect()
    };
    for (simplified, traditional) in [
        ("偏头痛", "偏頭痛"),
        ("惊恐障碍", "驚恐障礙"),
        ("创伤后应激障碍", "創傷後應激障礙"),
        ("医疗证明", "醫療證明"),
    ] {
        assert_eq!(to_traditional(simplified), traditional);
    }
    let mut checked = 0;
    for line in REFERENCE.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if cells.len() < 9
            || !matches!(
                cells.get(1).and_then(|id| id.chars().next()),
                Some('C') | Some('A')
            )
        {
            continue;
        }
        let zh = cells[8];
        if zh == "—" {
            continue;
        }
        let traditional = to_traditional(zh);
        let out = masked(&format!("患者: {traditional}。"));
        assert!(
            !out.contains(&traditional),
            "{zh} ({traditional}) left in clear: {out}"
        );
        assert!(
            out.contains(&format!("{}_", cells[2])),
            "no {} token for {traditional}: {out}",
            cells[2]
        );
        checked += 1;
    }
    assert!(checked >= 120, "only {checked} zh reference terms checked");
}

/// A key of `len` bytes built from `fake`, split into lines of `width` bytes.
fn wrap_key(prefix: &str, len: usize, width: usize) -> (String, String) {
    let body: String = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz"
        .chars()
        .cycle()
        .take(len)
        .collect();
    let key = format!("{prefix}{body}");
    let lines: Vec<String> = key
        .as_bytes()
        .chunks(width)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    (key, lines.join("\n"))
}

#[test]
fn a_key_wrapped_at_thirty_columns_over_six_lines_is_masked_whole() {
    let (key, wrapped) = wrap_key("sk-proj-", 172, 30);
    let out = masked(&format!("cfg {wrapped} end"));
    assert_no_window_in_clear(&out, &key);
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
    assert!(
        !out.contains("IBAN_") && !out.contains("PHONE_"),
        "other label on the key: {out}"
    );
}

#[test]
fn a_wrapped_jwt_and_an_sg_key_with_a_dotted_tail_are_masked_whole() {
    let jwt_head = "eyJhbGciOiJIUzI1NiJ9";
    let jwt_tail = ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let out = masked(&format!("token {jwt_head}\n{jwt_tail} end"));
    assert_no_window_in_clear(&out, jwt_head);
    assert_no_window_in_clear(&out, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV");
    let sg = "SG.FAKEKEY0123456789ab";
    let sg_tail = ".FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz";
    let out = masked(&format!("key {sg}\n{sg_tail} end"));
    assert_no_window_in_clear(&out, sg_tail);
    assert!(out.contains("SECRET_"), "no SECRET token: {out}");
}

#[test]
fn a_continuation_with_a_line_prefix_or_trailing_spaces_is_masked() {
    let head = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuv";
    let tail = "wxyzFAKEKEY0123456789TAILTAIL";
    for text in [
        format!("sk-proj-{head}   \n{tail} end"),
        format!("# sk-proj-{head}\n# {tail} end"),
        format!("// sk-proj-{head}\n// {tail} end"),
        format!(" * sk-proj-{head}\n * {tail} end"),
        format!("| sk-proj-{head}\n| {tail} end"),
    ] {
        let out = masked(&text);
        assert_no_window_in_clear(&out, tail);
    }
}

#[test]
fn a_lone_carriage_return_and_the_unicode_line_separators_break_a_key() {
    let tail = "wxyzFAKEKEY0123456789TAILTAIL";
    for sep in ["\r", "\u{2028}", "\u{85}"] {
        let out = masked(&format!("sk-proj-FAKEKEY0123456789abcdef{sep}{tail} end"));
        assert_no_window_in_clear(&out, tail);
    }
}

#[test]
fn a_wrap_longer_than_four_lines_up_to_eight_kilobytes_is_one_key() {
    let (key, wrapped) = wrap_key("sk-proj-", 4800, 400);
    let out = masked(&format!("cfg {wrapped} end"));
    assert_no_window_in_clear(&out, &key[..key.len().min(4000)]);
    assert!(
        !out.contains("IBAN_") && !out.contains("PHONE_"),
        "other label on the key: {out}"
    );
}

#[test]
fn aws_secret_keys_by_name_in_every_format_are_masked() {
    let value = "FAKE-KEY_0123456789/abcdefGHIJKLmnopqrstuvwxyz0123";
    for text in [
        format!("{{\"SecretAccessKey\": \"{value}\"}}"),
        format!("secret_access_key = \"{value}\""),
        format!("AWS_SECRET_KEY={value}"),
        format!("aws_secret_access_key: >\n  {value}\n"),
        format!("aws_secret_access_key = {}\n{}", &value[..20], &value[20..]),
        format!("aws_session_token = {value}"),
    ] {
        let out = masked(&text);
        assert_no_window_in_clear(&out, &value[..20]);
        assert_no_window_in_clear(&out, &value[20..]);
        assert!(out.contains("SECRET_"), "no SECRET token: {text} -> {out}");
    }
}

#[test]
fn issuer_key_shapes_are_masked_whole_and_zoho_is_one_token() {
    let tail = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789";
    for key in [
        format!("GOCSPX-{}", &tail[..28]),
        format!("EAA{tail}"),
        format!("1//0{tail}"),
        format!("xai-{tail}"),
        format!("pplx-{tail}"),
        format!("hvs.{tail}"),
        format!("tskey-api-{}", &tail[..30]),
        format!("glsa_{tail}"),
        format!("sntrys_{tail}"),
        format!("ATATT3x{tail}"),
        format!("sb_secret_{}", &tail[..30]),
        "shpss_0123456789abcdef0123456789abcdef".to_string(),
        "shpca_0123456789abcdef0123456789abcdef".to_string(),
        "glptt-0123456789abcdef0123456789abcdef01234567".to_string(),
        format!("gldt-{}", &tail[..20]),
        "MTIzNDU2Nzg5MDEyMzQ1Njc4.FAKEKE.FAKEKEY0123456789abcdefGHIJKLmnopq".to_string(),
        "ODEyMzQ1Njc4OTAxMjM0NTY3.GFk3jQ.Fk3jQ9xZ2mP7vB4nL8wRFk3jQ9xZ2mP7vB4nL".to_string(),
    ] {
        let out = masked(&format!("token {key} end"));
        assert!(!out.contains(&key), "{key} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {key}: {out}");
    }
    let zoho = "1000.FAKEKEY0123456789.abcdef0123456789";
    let spans = Registry::new().analyze(&format!("token {zoho} end"));
    let secret: Vec<_> = spans
        .iter()
        .filter(|span| span.kind == EntityKind::Secret)
        .collect();
    assert_eq!(secret.len(), 1, "Zoho token is not one SECRET: {spans:?}");
}

#[test]
fn headerless_pem_bodies_and_smart_dashes_and_ppk_are_masked() {
    let body = "FAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP";
    let line_one = format!("MII{}", &body[..61]);
    let line_two = &body[..64];
    let line_three = &body[64 - 64..64];
    let text = format!("config\n{line_one}\n{line_two}\n{line_three}\nend");
    let out = masked(&text);
    assert!(
        !out.contains("MII"),
        "headerless PEM header in clear: {out}"
    );
    assert_no_window_in_clear(&out, line_two);
    let dashes = "\u{2013}\u{2013}\u{2013}\u{2013}\u{2013}BEGIN PRIVATE KEY\u{2013}\u{2013}\u{2013}\u{2013}\u{2013}\n{}\n\u{2014}\u{2014}\u{2014}\u{2014}\u{2014}END PRIVATE KEY\u{2014}\u{2014}\u{2014}\u{2014}\u{2014}";
    let out = masked(&dashes.replace("{}", body));
    assert!(
        !out.contains("BEGIN") && !out.contains("END PRIVATE"),
        "smart-dash PEM in clear: {out}"
    );
    assert_no_window_in_clear(&out, body);
    let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: fake\nPublic-Lines: 2\nAAAAC3NzaC1lZDI1NTE5AAAAIFAKEKEY0123456789abcdefGHIJKLmnopqrs\nPrivate-Lines: 1\nAAAAIFAKEKEY0123456789abcdefGHIJKLmnopqrstuvwxyz0123456789ABCD\nPrivate-MAC: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    let out = masked(ppk);
    assert_no_window_in_clear(&out, "AAAAIFAKEKEY0123456789abcdef");
    assert!(
        !out.contains("Private-MAC: 0123456789"),
        "PuTTY MAC in clear: {out}"
    );
}

#[test]
fn name_assigned_secrets_and_authorization_values_are_masked() {
    for (text, value) in [
        (
            "MISTRAL_API_KEY=FAKEKEY0123456789abcdefGHIJ",
            "FAKEKEY0123456789abcdefGHIJ",
        ),
        (
            "\"client_secret\": \"FAKEKEY0123456789abcdef\"",
            "FAKEKEY0123456789abcdef",
        ),
        ("password: hunter2hunter2", "hunter2hunter2"),
        (
            "Authorization: Bearer FAKEKEY0123456789abcdefGHIJ",
            "FAKEKEY0123456789abcdefGHIJ",
        ),
        (
            "Authorization: Basic RkFLRUtFWTpGQUtFS0VZMDEyMw==",
            "RkFLRUtFWTpGQUtFS0VZMDEyMw==",
        ),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {value}: {out}"
        );
    }
}

#[test]
fn hungarian_hivjak_and_kap_are_not_health_terms() {
    let out = masked("A hívják gomb nem működik.");
    assert!(!out.contains("HEALTH_"), "hívják over-masked as HIV: {out}");
    let out = masked("Bíró Mira kezelést kap; ez bizalmas adat.");
    assert!(
        out.contains("kap"),
        "the Hungarian verb kap over-masked as the Slovene health word: {out}"
    );
}

#[test]
fn cn_resident_id_is_masked_as_national_id() {
    let id = "11010519491231002X";
    let fullwidth = "１１０１０５１９４９１２３１００２Ｘ";
    let grouped_six_eight_four = "110105 19491231 002X";
    let grouped_dashes = "110105-19491231-002X";
    let grouped_six_four_four_four = "110105 1949 1231 002X";
    let legacy = "110105491231002";
    for (text, value) in [
        (id.to_string(), id),
        (format!("身份证号：{id}"), id),
        (format!("身份证号：{fullwidth}"), fullwidth),
        (
            format!("身份证号：{grouped_six_eight_four}"),
            grouped_six_eight_four,
        ),
        (format!("身份证号：{grouped_dashes}"), grouped_dashes),
        (
            format!("身份证号：{grouped_six_four_four_four}"),
            grouped_six_four_four_four,
        ),
        (format!("我的身份证{id}号"), id),
        (format!("身份证号：{legacy}"), legacy),
        // A bad check character is still an ID when a cue sits next to it.
        (
            "身份证号：110105194912310021".to_string(),
            "110105194912310021",
        ),
    ] {
        let out = masked(&text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(
            out.contains("NATIONAL_ID_"),
            "no NATIONAL_ID token for {value}: {out}"
        );
    }
}

#[test]
fn an_order_number_with_a_bad_checksum_and_a_phone_stay_clear() {
    for text in ["Commande 110105194912310021 expédiée.", "Tel 13812345678."] {
        let out = masked(text);
        assert!(
            !out.contains("NATIONAL_ID_"),
            "over-masked as an ID: {text} -> {out}"
        );
    }
}

#[test]
fn gitlab_deploy_and_discord_shapes_stay_clear_below_their_format() {
    // A GitLab deploy token is `gldt-` plus 20 characters: 19 is not one.
    let out = masked("deploy: gldt-Fk3jQ9xZ2mP7vB4nL8w");
    assert!(!out.contains("SECRET_"), "a short gldt- was masked: {out}");
    // A Discord bot token's first field starts with M, N or O (user IDs from
    // 8 or 9 encode to OD or OT); any other first letter is not that shape.
    let out = masked("QWERTY1234567890ABCDEFGH.GFk3jQ.Fk3jQ9xZ2mP7vB4nL8wRFk3jQ9xZ2mP7vB4nL");
    assert!(
        !out.contains("SECRET_"),
        "a non-MNO first field was masked: {out}"
    );
}

#[test]
fn password_keys_in_six_languages_mask_their_value() {
    // A password key takes `:`, `=` or the fullwidth `：` after it, with spaces
    // or tabs around it. A password value needs four characters; a short value
    // is not one.
    for (text, value) in [
        ("mot de passe : Tr0ub4dor&3x", "Tr0ub4dor&3x"),
        ("mot_de_passe=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("motdepasse: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("mdp: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("jelszó: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("jelszo: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("geslo: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("wagwoord: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("密码：Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("密碼=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("口令: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("pwd=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("passwd: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("passphrase = Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("DB_PASS=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("DB_PWD=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("password: hunter2", "hunter2"),
        ("pwd=abcd", "abcd"),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {text}: {out}");
    }
}

#[test]
fn password_words_in_prose_and_short_values_stay_clear() {
    for text in [
        "the password policy requires 12 characters",
        "mot de passe oublié ?",
        "Kérem a jelszó visszaállítását",
        "geslo je pozabljeno",
        "忘记密码了",
        "bypass: Fk3jQ9xZ2m",
        "pwd=abc",
    ] {
        let out = masked(text);
        assert!(
            !out.contains("SECRET_"),
            "over-masked as a secret: {text} -> {out}"
        );
    }
}

#[test]
fn cn_resident_id_cues_include_the_formal_and_short_names() {
    // A bad check character needs a cue: 公民身份号码 (citizen identity number)
    // and 身份号码 (identity number) name the card as 身份证 does.
    for text in [
        "公民身份号码：110105194912310021",
        "身份号码：110105194912310021",
    ] {
        let out = masked(text);
        assert!(
            !out.contains("110105194912310021"),
            "the CN ID left in clear: {text} -> {out}"
        );
        assert!(
            out.contains("NATIONAL_ID_"),
            "no NATIONAL_ID token: {text} -> {out}"
        );
    }
}

#[test]
fn name_assigned_values_mask_for_every_key_shape_and_value_form() {
    // The key is any segment of a name (SECRET_KEY, secretKey, db.password, STRIPE_SECRET),
    // and the value is quoted, a block scalar, or an unquoted run that may hold `:`, `=`, `;`, `,`.
    for (text, value) in [
        ("password: Pass:w0rd99", "Pass:w0rd99"),
        ("DB_PASSWORD=Summer=2024", "Summer=2024"),
        (
            "password: \"correct horse battery staple\"",
            "correct horse battery staple",
        ),
        ("DB_PASSWORD=\"Fk3j;Q9xZ2mA\"", "Fk3j;Q9xZ2mA"),
        ("password: \"Fk3j,Q9xZ2mAA\"", "Fk3j,Q9xZ2mAA"),
        ("password = Fk3j;Q9xZ2m", "Fk3j;Q9xZ2m"),
        ("password: |\n  Fk3jQ9xZ2mAA", "Fk3jQ9xZ2mAA"),
        ("token: >-\n  Fk3jQ9xZ2mP7vB4nX", "Fk3jQ9xZ2mP7vB4nX"),
        (
            "SECRET_KEY=django-insecure-Fk3jQ9xZ2m",
            "django-insecure-Fk3jQ9xZ2m",
        ),
        (
            "\"secretKey\": \"Fk3jQ9xZ2mP7vB4nX8cV\"",
            "Fk3jQ9xZ2mP7vB4nX8cV",
        ),
        ("SECRET_KEY_BASE=9f8e7d6c5b4a3210", "9f8e7d6c5b4a3210"),
        ("PRIVATE_KEY=Fk3jQ9xZ2mP7vB4n", "Fk3jQ9xZ2mP7vB4n"),
        ("ENCRYPTION_KEY=Fk3jQ9xZ2mP7vB4n", "Fk3jQ9xZ2mP7vB4n"),
        ("MASTER_KEY=Fk3jQ9xZ2mP7vB4n", "Fk3jQ9xZ2mP7vB4n"),
        (
            "APP_KEY=base64:Fk3jQ9xZ2mP7vB4n=",
            "base64:Fk3jQ9xZ2mP7vB4n=",
        ),
        ("STRIPE_SECRET=Fk3jQ9xZ2mP7vB4n", "Fk3jQ9xZ2mP7vB4n"),
        ("db.password=Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("mdp: Fk3jQ9xZ2m", "Fk3jQ9xZ2m"),
        ("password: hunter2", "hunter2"),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {text:?}: {out}"
        );
    }
    // The key stays in clear: only the value is the secret.
    let out = masked("{\"password\": \"Fk3jQ9xZ2mAA\"}");
    assert!(
        out.contains("\"password\""),
        "the JSON key was masked: {out}"
    );
}

#[test]
fn a_natural_language_key_masks_the_rest_of_its_line_as_an_accepted_over_mask() {
    for text in [
        "The password: never share it with anyone.",
        "Le mot de passe : changez-le tous les mois.",
        "A jelszó: legalább nyolc karakter legyen.",
        "Geslo: vsaj osem znakov.",
        "Die wagwoord: moet sterk wees.",
    ] {
        let out = masked(text);
        assert!(
            out.contains("SECRET_"),
            "a natural-language key is an accepted over-mask, so it masks: {text} -> {out}"
        );
    }
}

#[test]
fn a_dsn_password_masks_as_secret_for_every_host_and_user_form() {
    for (text, value) in [
        (
            "DATABASE_URL=postgres://admin:S3cr3tPassw0rd@localhost:5432/app",
            "S3cr3tPassw0rd",
        ),
        ("redis://:R3disPassw0rd@redis:6379/0", "R3disPassw0rd"),
        ("mysql://app:Fk3jQ9xZ2mP7@10.0.0.5:3306/db", "Fk3jQ9xZ2mP7"),
        (
            "https://svc:Fk3jQ9xZ2mP7@api.example.invalid/v1",
            "Fk3jQ9xZ2mP7",
        ),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(out.contains("SECRET_"), "no SECRET token for {text}: {out}");
        assert!(
            !out.contains("EMAIL_"),
            "the DSN was read as an e-mail: {out}"
        );
    }
}

#[test]
fn r6_name_forms_mask_the_rest_of_the_line_in_every_shape() {
    // Each key is a secret-class name; the value is the rest of its line, whatever
    // the separator or the quoting.
    for (text, value) in [
        ("MAIL_PASSWORD=my mail pass 2024", "my mail pass 2024"),
        (
            "password = correct horse battery staple",
            "correct horse battery staple",
        ),
        ("spring.datasource.password=Hunter2 xyz", "Hunter2 xyz"),
        ("password: P@ss w0rd 2024", "P@ss w0rd 2024"),
        ("DB_PASSWORD: hunter rabbit", "hunter rabbit"),
        (
            "Wifi password: sunshine see you at 8",
            "sunshine see you at 8",
        ),
        ("The guest password: letmein, thanks!", "letmein, thanks!"),
        ("password: &dbpw Hunter2xyz", "&dbpw Hunter2xyz"),
        ("password: !!str Hunter2xyz", "!!str Hunter2xyz"),
        ("password=it's-a-long-secret", "it's-a-long-secret"),
        ("password=Hun'ter2xyz", "Hun'ter2xyz"),
        ("password=Hunter\"2xyzABC", "Hunter\"2xyzABC"),
        ("password=<Hunter2xyz>", "Hunter2xyz"),
        ("password={Hunter2xyz}", "Hunter2xyz"),
        ("password: 'it''s Hunter2xyz'", "Hunter2xyz"),
        ("const token = `Fk3jQ9xZ2mP7vB4n`;", "Fk3jQ9xZ2mP7vB4n"),
        ("password = r\"Hunter2xyz\"", "Hunter2xyz"),
        ("password := \"Hunter2xyz\"", "Hunter2xyz"),
        ("'password' => 'Hunter2xyz'", "Hunter2xyz"),
        ("- name: DB_PASSWORD\n  value: Hunter2xyz", "Hunter2xyz"),
        ("<password>Hunter2xyz</password>", "Hunter2xyz"),
        ("--password Hunter2xyz", "Hunter2xyz"),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {text:?}: {out}"
        );
    }
}

#[test]
fn a_k8s_secret_name_keeps_its_name_and_masks_its_value() {
    let out = masked("- name: DB_PASSWORD\n  value: Hunter2xyz");
    assert!(
        out.contains("DB_PASSWORD"),
        "the k8s env name was masked: {out}"
    );
    assert!(
        !out.contains("Hunter2xyz"),
        "the k8s value left in clear: {out}"
    );
}

#[test]
fn a_quoted_command_line_secret_with_spaces_is_masked_whole() {
    // A CLI value that opens with a quote runs to its matching closing quote.
    for (text, value) in [
        (
            "psql --password \"correct horse battery\" -h db",
            "correct horse battery",
        ),
        (
            "x --api-key 'FAKEkey 0123 4567' --verbose",
            "FAKEkey 0123 4567",
        ),
    ] {
        let out = masked(text);
        // Each word of the value, so a partial mask is caught too.
        for word in value.split_whitespace() {
            assert!(!out.contains(word), "{word} left in clear: {out}");
        }
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {text:?}: {out}"
        );
    }
}

#[test]
fn an_unquoted_value_stops_before_the_next_assignment_or_ampersand() {
    // The value ends at `&`, or at a blank followed by another `key=`, `key:`, `-e`
    // or `--flag`; a value with no such blank takes the whole line.
    // K-SECRET-TAIL-4 over-mask: a one-line value now runs to the line end,
    // so the next assignment is masked too; only the secret is pinned.
    let out = masked("password=Fk3jQ9xZ2m user=alice");
    assert!(
        !out.contains("Fk3jQ9xZ2m"),
        "the password left in clear: {out}"
    );
    let out = masked("token=FAKEtok12345&p0=v0");
    assert!(
        !out.contains("FAKEtok12345"),
        "the token left in clear: {out}"
    );
}

#[test]
fn an_ampersand_inside_a_password_masks_the_whole_value() {
    // `&` ends a value only before a query parameter (`&name=`). In a password it is
    // a character: the whole value is the secret, every piece of it.
    for (text, value) in [
        ("DB_PASSWORD=Xk9&mP2q!z", "Xk9&mP2q!z"),
        ("export DB_PASSWORD=Pa&ss&w0rd", "Pa&ss&w0rd"),
        ("spring.datasource.password=Rt5&wQ8zLm2N", "Rt5&wQ8zLm2N"),
        ("password: x8&Lq2PmZ7vR9tK3", "x8&Lq2PmZ7vR9tK3"),
        ("DB_PASSWORD=Kx7mQ2&pL9vR4tZ8", "Kx7mQ2&pL9vR4tZ8"),
        ("password: Tr0ub4dor&3", "Tr0ub4dor&3"),
    ] {
        let out = masked(text);
        assert!(!out.contains(value), "{value} left in clear: {out}");
        for piece in value.split('&').filter(|piece| piece.len() >= 3) {
            assert!(!out.contains(piece), "{piece} left in clear: {out}");
        }
        assert!(
            out.contains("SECRET_"),
            "no SECRET token for {text:?}: {out}"
        );
    }
}

#[test]
fn base64_padding_after_a_blank_stays_inside_the_value() {
    // A word followed by `==` is base64 padding, not the next assignment.
    for (text, padded) in [
        (
            "AUTH_TOKEN=Basic dXNlcjpwYXNzd29yZA==",
            "dXNlcjpwYXNzd29yZA",
        ),
        ("secret: Bearer FAKEtok3nAbc==", "FAKEtok3nAbc"),
    ] {
        let out = masked(text);
        assert!(!out.contains(padded), "{padded} left in clear: {out}");
        assert!(!out.contains("=="), "the padding left in clear: {out}");
    }
}

#[test]
fn a_quoted_value_spanning_lines_masks_through_its_closing_quote() {
    let out = masked("password=\"line one\nline two secret\"");
    for word in ["line", "one", "two"] {
        assert!(!out.contains(word), "{word} left in clear: {out}");
    }
}

#[test]
fn an_unclosed_cli_quote_masks_the_rest_of_the_line() {
    let out = masked("psql --password \"correct horse battery -h db");
    for word in ["correct", "horse", "battery"] {
        assert!(!out.contains(word), "{word} left in clear: {out}");
    }
}

/// The linear-time bar: 10 s in release; the debug profile is slower, so it
/// gets 30 s. What is checked does not change (see secret_recall_1.rs).
fn linear_budget() -> std::time::Duration {
    if cfg!(debug_assertions) {
        std::time::Duration::from_secs(30)
    } else {
        std::time::Duration::from_secs(10)
    }
}
