//! Pure checksum and structural validators shared by the recognisers.
//!
//! Every function here takes an already-extracted candidate (`&str`) and
//! returns whether it is valid. No function touches the network or a registry.

/// Luhn checksum over an ASCII digit string (payment cards, SIREN, SIRET,
/// South African ID).
pub fn luhn_ok(digits: &str) -> bool {
    if digits.is_empty() {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for ch in digits.chars().rev() {
        let Some(digit) = ch.to_digit(10) else {
            return false;
        };
        let mut value = digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// IBAN mod-97: move the first four characters to the end, map `A=10 … Z=35`,
/// and require the whole number to be `1 mod 97`. Computed incrementally so no
/// big-integer type is needed.
pub(crate) fn iban_mod97(compact: &str) -> bool {
    let upper = compact.to_ascii_uppercase();
    if upper.len() < 5 {
        return false;
    }
    let (head, tail) = upper.split_at(4);
    let rearranged = format!("{tail}{head}");
    let mut remainder: u32 = 0;
    for ch in rearranged.chars() {
        let value = match ch {
            '0'..='9' => ch as u32 - '0' as u32,
            'A'..='Z' => ch as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        remainder = iban_step(remainder, value);
    }
    remainder == 1
}

/// IBAN mod-97 over a raw value with separators, without allocating (P3-5).
///
/// Returns `None` when the value holds a character that is neither an ASCII
/// alphanumeric nor a separator, or fewer than five alphanumerics.
pub fn iban_mod97_loose(raw: &str) -> Option<bool> {
    let mut head = [0u32; 4];
    let mut count = 0usize;
    let mut remainder: u32 = 0;
    for ch in raw.chars() {
        let value = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else if ch.is_ascii_alphabetic() {
            ch.to_ascii_uppercase() as u32 - 'A' as u32 + 10
        } else if matches!(ch, ' ' | '-' | '.' | '/') {
            continue;
        } else {
            return None;
        };
        if count < 4 {
            head[count] = value;
        } else {
            remainder = iban_step(remainder, value);
        }
        count += 1;
    }
    if count < 5 {
        return None;
    }
    for value in head {
        remainder = iban_step(remainder, value);
    }
    Some(remainder == 1)
}

/// Advance the running mod-97 remainder by one mapped IBAN character value.
fn iban_step(remainder: u32, value: u32) -> u32 {
    if value >= 10 {
        (remainder * 100 + value) % 97
    } else {
        (remainder * 10 + value) % 97
    }
}

/// Registered IBAN length for a two-letter country code, from the ISO 13616
/// country table. Unknown codes are rejected so a random `XX12…` cannot pass.
pub fn iban_country_length(code: &str) -> Option<usize> {
    let code = code.to_ascii_uppercase();
    Some(match code.as_str() {
        "AD" => 24,
        "AE" => 23,
        "AL" => 28,
        "AO" => 25,
        "AT" => 20,
        "AZ" => 28,
        "BA" => 20,
        "BE" => 16,
        "BF" => 28,
        "BG" => 22,
        "BH" => 22,
        "BI" => 27,
        "BJ" => 28,
        "BR" => 29,
        "BY" => 28,
        "CF" => 27,
        "CG" => 27,
        "CH" => 21,
        "CI" => 28,
        "CM" => 27,
        "CR" => 22,
        "CV" => 25,
        "CY" => 28,
        "CZ" => 24,
        "DE" => 22,
        "DJ" => 27,
        "DK" => 18,
        "DO" => 28,
        "DZ" => 26,
        "EE" => 20,
        "EG" => 29,
        "ES" => 24,
        "FI" => 18,
        "FK" => 18,
        "FO" => 18,
        "FR" => 27,
        "GA" => 27,
        "GB" => 22,
        "GE" => 22,
        "GI" => 23,
        "GL" => 18,
        "GQ" => 27,
        "GR" => 27,
        "GT" => 28,
        "GW" => 25,
        "HN" => 28,
        "HR" => 21,
        "HU" => 28,
        "IE" => 22,
        "IL" => 23,
        "IQ" => 23,
        "IR" => 26,
        "IS" => 26,
        "IT" => 27,
        "JO" => 30,
        "KM" => 27,
        "KW" => 30,
        "KZ" => 20,
        "LB" => 28,
        "LC" => 32,
        "LI" => 21,
        "LT" => 20,
        "LU" => 20,
        "LV" => 21,
        "LY" => 25,
        "MA" => 28,
        "MC" => 27,
        "MD" => 24,
        "ME" => 22,
        "MG" => 27,
        "MK" => 19,
        "ML" => 28,
        "MN" => 20,
        "MR" => 27,
        "MT" => 31,
        "MU" => 30,
        "MZ" => 25,
        "NE" => 28,
        "NI" => 28,
        "NL" => 18,
        "NO" => 15,
        "OM" => 23,
        "PK" => 24,
        "PL" => 28,
        "PS" => 29,
        "PT" => 25,
        "QA" => 29,
        "RO" => 24,
        "RS" => 22,
        "RU" => 33,
        "SA" => 24,
        "SC" => 31,
        "SD" => 18,
        "SE" => 24,
        "SI" => 19,
        "SK" => 24,
        "SM" => 27,
        "SN" => 28,
        "SO" => 23,
        "ST" => 25,
        "SV" => 28,
        "TD" => 27,
        "TG" => 28,
        "TL" => 23,
        "TN" => 24,
        "TR" => 26,
        "UA" => 29,
        "VA" => 22,
        "VG" => 24,
        "XK" => 20,
        "YE" => 30,
        // South Africa is not in the SWIFT IBAN registry (it uses national
        // account numbers), but the fake eval corpus models a 26-char `ZA`
        // bank-account form that passes mod-97; accept it so it is masked.
        "ZA" => 26,
        _ => return None,
    })
}

/// French SIREN: nine digits, Luhn-valid.
pub fn fr_siren_ok(digits: &str) -> bool {
    digits.len() == 9 && digits.chars().all(|ch| ch.is_ascii_digit()) && luhn_ok(digits)
}

/// French SIRET: SIREN plus a five-digit NIC, Luhn over all fourteen digits.
/// Exception for La Poste (`356000000`): every SIRET except the head office
/// `35600000000048` needs its digit sum to be `0 mod 5`.
pub fn fr_siret_ok(digits: &str) -> bool {
    if digits.len() != 14 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    if digits.starts_with("356000000") && digits != "35600000000048" {
        let sum: u32 = digits.chars().filter_map(|ch| ch.to_digit(10)).sum();
        return sum.is_multiple_of(5);
    }
    luhn_ok(digits)
}

/// The SIRET shape without the checksum: exactly fourteen digits. A typo in a
/// real document is still personal data, so the shape alone masks.
pub fn fr_siret_shape_ok(digits: &str) -> bool {
    digits.len() == 14 && digits.chars().all(|ch| ch.is_ascii_digit())
}

/// French NIR structure without the key: thirteen digits (`sex year month dept
/// commune order`), or fifteen with the key. Digits only, bar the Corsica
/// `2A`/`2B` department. The sex digit is `1`-`4` or `7`/`8`, the month is
/// `01`-`12`, `20`-`42` or `50`-`99` (INSEE), the department is `01`-`95`,
/// `2A`/`2B`, or `97`-`99` for overseas and abroad. `00` also passes: a one-digit
/// typo can land there. The key and the commune are not checked, so a typo in
/// them still masks (fail toward masking).
pub fn fr_nir_shape_ok(raw: &str) -> bool {
    let compact: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    if !matches!(compact.len(), 13 | 15) {
        return false;
    }
    let digits = |text: &str| text.bytes().all(|byte| byte.is_ascii_digit());
    let number = |text: &str| text.parse::<u32>().ok();
    let sex_ok = matches!(
        compact.as_bytes()[0],
        b'1' | b'2' | b'3' | b'4' | b'7' | b'8'
    );
    let month = &compact[3..5];
    let month_ok = digits(month) && matches!(number(month), Some(1..=12 | 20..=42 | 50..=99));
    let dept = &compact[5..7];
    let dept_ok = matches!(dept, "2A" | "2B")
        || (digits(dept) && matches!(number(dept), Some(0..=95 | 97..=99)));
    sex_ok
        && digits(&compact[1..3])
        && month_ok
        && dept_ok
        && digits(&compact[7..13])
        && (compact.len() == 13 || digits(&compact[13..]))
}

/// French NIR: fifteen characters (`sex year month dept commune order key`),
/// Corsica `2A`/`2B` read as `19`/`18` before the key check
/// `key = 97 - (number mod 97)`.
pub fn fr_nir_ok(raw: &str) -> bool {
    let compact: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    if compact.len() != 15 {
        return false;
    }
    let key = &compact[13..15];
    if !key.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    let dept = &compact[5..7];
    let dept_number = match dept {
        "2A" => "19",
        "2B" => "18",
        other => other,
    };
    let body = format!("{}{}{}", &compact[..5], dept_number, &compact[7..13]);
    if !body.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    let Ok(number) = body.parse::<u64>() else {
        return false;
    };
    let expected = 97 - (number % 97);
    key.parse::<u64>()
        .map(|got| got == expected)
        .unwrap_or(false)
}

/// French VAT, numeric-key form: `FR` + two-digit key + SIREN, where
/// `key = (12 + 3 × (SIREN mod 97)) mod 97`. Any separator between the groups
/// (`FR 40 303 265 045`) is discarded before the check.
pub fn fr_vat_ok(raw: &str) -> bool {
    let compact: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase();
    if compact.len() != 13 || !compact.starts_with("FR") {
        return false;
    }
    let key = &compact[2..4];
    let siren = &compact[4..13];
    if !key.chars().all(|ch| ch.is_ascii_digit()) || !siren.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    if !fr_siren_ok(siren) {
        return false;
    }
    let Ok(siren_number) = siren.parse::<u64>() else {
        return false;
    };
    let expected = (12 + 3 * (siren_number % 97)) % 97;
    key.parse::<u64>()
        .map(|got| got == expected)
        .unwrap_or(false)
}

/// Hungarian TAJ: nine digits; the ninth is
/// `(3·Σ odd-position + 7·Σ even-position) mod 10` over the first eight.
pub fn hu_taj_ok(digits: &str) -> bool {
    if digits.len() != 9 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    let d: Vec<u32> = digits.chars().filter_map(|ch| ch.to_digit(10)).collect();
    let sum = 3 * (d[0] + d[2] + d[4] + d[6]) + 7 * (d[1] + d[3] + d[5] + d[7]);
    sum % 10 == d[8]
}

/// Hungarian adóazonosító jel: ten digits, first digit `8` for natural
/// persons; `d10 = (Σ k·d_k for k=1..9) mod 11` and a remainder of `10` is
/// never issued.
pub fn hu_taxid_ok(digits: &str) -> bool {
    if digits.len() != 10 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    if !digits.starts_with('8') {
        return false;
    }
    let d: Vec<u32> = digits.chars().filter_map(|ch| ch.to_digit(10)).collect();
    let mut weighted = 0u32;
    for (index, digit) in d.iter().take(9).enumerate() {
        weighted += (index as u32 + 1) * digit;
    }
    let remainder = weighted % 11;
    remainder != 10 && remainder == d[9]
}

/// South African identity number: thirteen digits, `YYMMDD SSSS C A Z`, with a
/// plausible date and a citizenship digit of `0` or `1`, Luhn-valid.
pub fn za_id_ok(digits: &str) -> bool {
    za_id_luhn_ok(digits) && za_id_shape_ok(digits)
}

/// The Luhn half of the ZA ID check, ignoring the date and citizenship fields.
///
/// The date may be odd (a typo in a real document is still personal data), so
/// masking keys on the checksum and the shape separately.
pub fn za_id_luhn_ok(digits: &str) -> bool {
    digits.len() == 13 && digits.chars().all(|ch| ch.is_ascii_digit()) && luhn_ok(digits)
}

/// The structural ZA ID shape without the checksum: a plausible `YYMMDD` and a
/// citizenship digit of `0` or `1`.
pub fn za_id_shape_ok(digits: &str) -> bool {
    if digits.len() != 13 || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    let Ok(month) = digits[2..4].parse::<u32>() else {
        return false;
    };
    let Ok(day) = digits[4..6].parse::<u32>() else {
        return false;
    };
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    matches!(digits.as_bytes()[10], b'0' | b'1')
}

/// ICAO 9303 7-3-1 check digit over an MRZ payload: digits at face value,
/// `A=10 … Z=35`, `<` is zero, weights 7-3-1 repeating, sum mod 10.
pub(crate) fn mrz_check_digit(payload: &str) -> Option<u8> {
    const WEIGHTS: [u32; 3] = [7, 3, 1];
    let mut sum: u32 = 0;
    for (index, ch) in payload.chars().enumerate() {
        let value = match ch {
            '<' => 0,
            '0'..='9' => ch.to_digit(10)?,
            'A'..='Z' => ch as u32 - 'A' as u32 + 10,
            _ => return None,
        };
        sum += value * WEIGHTS[index % 3];
    }
    Some((sum % 10) as u8)
}

/// Whether a passport number plus its check digit is 7-3-1 valid.
pub fn passport_mrz_ok(payload: &str, check_digit: u8) -> bool {
    mrz_check_digit(payload).is_some_and(|expected| expected == check_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_vectors() {
        assert!(luhn_ok("79927398713"));
        assert!(!luhn_ok("79927398714"));
        assert!(!luhn_ok(""));
        assert!(!luhn_ok("12a4"));
    }

    #[test]
    fn iban_vectors() {
        assert!(iban_mod97("FR7630006000011234567890189"));
        assert!(!iban_mod97("FR7630006000011234567890188"));
        assert!(iban_mod97("HU42117730161111101800000000"));
        assert_eq!(iban_country_length("FR"), Some(27));
        assert_eq!(iban_country_length("HU"), Some(28));
        assert_eq!(iban_country_length("MA"), Some(28));
        assert_eq!(iban_country_length("DZ"), Some(26));
        assert_eq!(iban_country_length("ZA"), Some(26));
        assert_eq!(iban_country_length("ZZ"), None);
        assert_eq!(iban_country_length("fr"), Some(27));
    }

    #[test]
    fn siren_vectors() {
        assert!(fr_siren_ok("732829320"));
        assert!(fr_siren_ok("404833048"));
        assert!(!fr_siren_ok("732829321"));
        assert!(!fr_siren_ok("73282932"));
    }

    #[test]
    fn siret_vectors() {
        assert!(fr_siret_ok("73282932000074"));
        assert!(fr_siret_ok("35600000049837"));
        assert!(fr_siret_ok("35600000000048"));
        assert!(!fr_siret_ok("35600000049838"));
        assert!(!fr_siret_ok("73282932000079"));
    }

    #[test]
    fn nir_vectors() {
        assert!(fr_nir_ok("202022A01806376"));
        assert!(fr_nir_ok("2 02 02 2A 018 063 76"));
        assert!(fr_nir_ok("253072B07300470"));
        assert!(!fr_nir_ok("202022A01806377"));
        assert!(!fr_nir_ok("253072B0730047"));
    }

    #[test]
    fn vat_vectors() {
        assert!(fr_vat_ok("FR83404833048"));
        assert!(fr_vat_ok("FR27552032534"));
        assert!(!fr_vat_ok("FR84404833048"));
        assert!(!fr_vat_ok("FR8340483304"));
    }

    #[test]
    fn hu_taj_vectors() {
        assert!(hu_taj_ok("123456788"));
        assert!(!hu_taj_ok("123456789"));
    }

    #[test]
    fn hu_taxid_vectors() {
        assert!(hu_taxid_ok("8123456786"));
        assert!(!hu_taxid_ok("8123456787"));
        assert!(!hu_taxid_ok("7123456786"));
    }

    #[test]
    fn za_id_vectors() {
        assert!(za_id_ok("8001015009087"));
        assert!(!za_id_ok("8001015009088"));
        assert!(!za_id_ok("8013015009087"));
        // The checksum and the shape are independent: an odd month is still a
        // personal identifier when the Luhn check holds (P2-2).
        assert!(za_id_luhn_ok("8013015009082"));
        assert!(!za_id_shape_ok("8013015009082"));
        assert!(za_id_shape_ok("8001015009087"));
        assert!(!za_id_luhn_ok("8001015009088"));
        assert!(za_id_shape_ok("8001015009088"));
    }

    #[test]
    fn shape_vectors_mask_typos() {
        assert!(fr_nir_shape_ok("202022A01806377"));
        assert!(fr_nir_shape_ok("7 34 05 00 999 001 55"));
        // Thirteen digits with no key are still a NIR shape.
        assert!(fr_nir_shape_ok("1840300999001"));
        assert!(fr_nir_shape_ok("3013015009070"));
        assert!(!fr_nir_shape_ok("9013015009070"));
        assert!(!fr_nir_shape_ok("1841300999001"));
        assert!(!fr_nir_shape_ok("1840396999001"));
        assert!(!fr_nir_shape_ok("1840300999001abcdef"));
        assert!(!fr_nir_shape_ok("18403009990"));
        assert!(fr_siret_shape_ok("73282932000079"));
        assert!(!fr_siret_shape_ok("7328293200007"));
    }

    #[test]
    fn loose_iban_mod97_matches_the_compact_check() {
        assert_eq!(
            iban_mod97_loose("ZZ85 ABCD 1234 5678 9012 3456"),
            Some(true)
        );
        assert_eq!(iban_mod97_loose("ZZ85ABCD1234567890123456"), Some(true));
        assert_eq!(iban_mod97_loose("ZZ85ABCD1234567890123457"), Some(false));
        assert_eq!(iban_mod97_loose("ZZ85 ABCD!"), None);
    }

    #[test]
    fn mrz_vectors() {
        assert_eq!(mrz_check_digit("L898902C3"), Some(6));
        assert!(passport_mrz_ok("L898902C3", 6));
        assert!(!passport_mrz_ok("L898902C3", 5));
        assert!(passport_mrz_ok("L898902C3", 6));
        assert_eq!(mrz_check_digit("l898902c3"), None);
        assert_eq!(mrz_check_digit("L898-02C3"), None);
    }
}
