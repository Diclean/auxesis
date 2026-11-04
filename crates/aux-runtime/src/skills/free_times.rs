//! The owner's free times, computed by the runtime before a card.
//!
//! A skill whose body names [`MARKER`] has its `mail.send` body's marker
//! replaced with the owner's free windows: 09:00–18:00 in the owner's zone,
//! Monday to Friday, the next [`WORKING_DAYS`] working days after today, each
//! window at least the skill's `duration` long. Busy events (all-day ones too)
//! are subtracted by instant, so a DST change, an overlap or an event across
//! midnight needs no special case. A mail that might state a time of the
//! model's own is refused: only the runtime writes times.

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;

/// The body marker the runtime replaces with the free windows.
pub const MARKER: &str = "{free_times}";
/// The local calendar read the runtime makes (never offered to the model).
pub const CALENDAR_READ: &str = "calendar.list_events";
/// How many working days are searched, starting tomorrow.
pub const WORKING_DAYS: usize = 5;

/// One free window in the owner's zone.
pub type Window = (DateTime<Tz>, DateTime<Tz>);

/// The free windows of at least `length` in the [`WORKING_DAYS`] working days
/// after `now`'s local date, outside every `busy` interval.
pub fn free_windows(
    busy: &[(DateTime<Utc>, DateTime<Utc>)],
    now: DateTime<Utc>,
    zone: Tz,
    length: Duration,
) -> Vec<Window> {
    let at = |day: NaiveDate, hour| {
        let wall = day.and_time(NaiveTime::from_hms_opt(hour, 0, 0)?);
        Some(zone.from_local_datetime(&wall).earliest()?.to_utc())
    };
    let mut windows = Vec::new();
    for day in working_days(now, zone) {
        let (Some(open), Some(close)) = (at(day, 9), at(day, 18)) else {
            continue;
        };
        let mut blocks: Vec<_> = busy
            .iter()
            .filter(|(start, end)| *start < close && *end > open)
            .map(|(start, end)| ((*start).max(open), (*end).min(close)))
            .collect();
        blocks.sort();
        let mut cursor = open;
        for (start, end) in blocks.into_iter().chain([(close, close)]) {
            if start - cursor >= length {
                windows.push((cursor.with_timezone(&zone), start.with_timezone(&zone)));
            }
            cursor = cursor.max(end);
        }
    }
    windows
}

/// The windows as mail lines in the owner's zone; with none, one line says so.
pub fn render(windows: &[Window], zone: Tz) -> String {
    if windows.is_empty() {
        return format!("I have no free time in the next {WORKING_DAYS} working days ({zone}).");
    }
    let line = |(start, end): &Window| {
        let (day, from, to) = (
            start.format("%a %-d %b"),
            start.format("%H:%M"),
            end.format("%H:%M"),
        );
        format!("- {day}, {from}–{to} ({zone})")
    };
    windows.iter().map(line).collect::<Vec<_>>().join("\n")
}

/// The longest slot a skill may ask for.
const MAX_MINUTES: u32 = 8 * 60;

/// A skill `duration` (`30m`, `1h`, `1h30m`, `PT1H30M`) as 5 minutes to 8
/// hours; anything else, however long or odd, is an error and never a panic.
pub fn parse_length(text: &str) -> Result<Duration, String> {
    let bad = || "the duration must be 5 minutes to 8 hours, such as 30m or 1h".to_string();
    let text = text.trim().to_ascii_lowercase();
    let mut rest = text.strip_prefix("pt").unwrap_or(&text);
    let mut minutes = 0;
    for (unit, scale) in [('h', 60), ('m', 1)] {
        let Some((count, after)) = rest.split_once(unit) else {
            continue;
        };
        // At most three ASCII digits: no sign, no overflow, no Unicode digit.
        if !(1..=3).contains(&count.len()) || !count.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        minutes += count.parse::<u32>().map_err(|_| bad())? * scale;
        rest = after;
    }
    match rest.is_empty() && (5..=MAX_MINUTES).contains(&minutes) {
        true => Ok(Duration::minutes(minutes.into())),
        false => Err(bad()),
    }
}

/// The days searched: the [`WORKING_DAYS`] weekdays after `now`'s local date.
fn working_days(now: DateTime<Utc>, zone: Tz) -> impl Iterator<Item = NaiveDate> {
    let days = now.with_timezone(&zone).date_naive().iter_days().skip(1);
    days.filter(|day| !matches!(day.weekday(), Weekday::Sat | Weekday::Sun))
        .take(WORKING_DAYS)
}

/// The whole local days [`free_windows`] searches, as the calendar read's
/// `{from, to}`: from tomorrow's midnight to the midnight after the last day.
pub fn search_span(now: DateTime<Utc>, zone: Tz) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let midnight = |day: NaiveDate| {
        let wall = day.and_time(NaiveTime::MIN);
        Some(zone.from_local_datetime(&wall).earliest()?.to_utc())
    };
    let mut days = working_days(now, zone);
    let first = days.next()?;
    let last = days.last().unwrap_or(first);
    Some((midnight(first)?, midnight(last.succ_opt()?)?))
}

/// The `mail.send` fields the time check skips: recipients, whose addresses
/// the recipient policy owns.
const RECIPIENT_FIELDS: [&str; 2] = ["to", "cc"];

/// Fill `mail` (the `mail.send` arguments): its body's one [`MARKER`] becomes
/// `lines` (appended when the model left it out). Refused when a marker is
/// anywhere but the body, the body has two, or any text but the marker states a
/// time (see [`states_time`]): only the runtime writes times.
pub fn fill_mail(mail: &mut serde_json::Value, lines: &str) -> Result<(), String> {
    let map = mail.as_object_mut().ok_or("the mail is not an object")?;
    for (field, value) in map.iter() {
        if RECIPIENT_FIELDS.contains(&field.as_str()) {
            continue;
        }
        let text = value.as_str().ok_or("a mail field is not text")?;
        let marks = text.matches(MARKER).count();
        if marks > usize::from(field == "body") {
            return Err(format!("write {MARKER} once, in the body only"));
        }
        if states_time(&text.replace(MARKER, " ")) {
            return Err(format!(
                "the mail states a time of its own: write {MARKER} where the times go"
            ));
        }
    }
    let body = map.get("body").and_then(|b| b.as_str()).unwrap_or_default();
    let body = match body.contains(MARKER) {
        true => body.replacen(MARKER, lines, 1),
        false => format!("{}\n\n{lines}", body.trim_end()),
    };
    map.insert("body".to_string(), body.into());
    Ok(())
}

/// The only words an ASCII number may stand before: `30 minutes`, `30-minute`,
/// `1 hour`. `h` is not one: `9h` and `14 h 30` are clock times in French.
const DURATION_UNITS: [&str; 6] = ["minute", "minutes", "min", "mins", "hour", "hours"];
/// Words before a duration that make it a time: `in 2 hours`.
const RELATIVE: [&str; 3] = ["in", "dans", "within"];
/// Words that name a time of day with no digit at all.
const TIME_WORDS: [&str; 7] = [
    "noon", "midnight", "midday", "midi", "minuit", "oclock", "pm",
];
/// Hours as words, a time when next to [`HOUR_CUES`]: `at two`, `two am`.
const NUMBER_WORDS: [&str; 23] = [
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
    "twelve", "une", "deux", "trois", "quatre", "cinq", "sept", "huit", "neuf", "dix", "onze",
    "douze",
];
const HOUR_CUES: [&str; 13] = [
    "at", "à", "vers", "past", "to", "till", "until", "am", "pm", "oclock", "h", "heure", "heures",
];

/// Fail closed: true when `text` might state a time. Any non-ASCII digit, any
/// ASCII number that is not a duration (see [`DURATION_UNITS`]), a time word
/// (`noon`, `midi`, `pm`, `p.m.`, `o'clock`) or an hour word next to a cue
/// (`at two`, `two am`). `morning` and `afternoon` are fine.
fn states_time(text: &str) -> bool {
    if text
        .chars()
        .any(|ch| ch.is_numeric() && !ch.is_ascii_digit())
    {
        return true;
    }
    // `a.m.` → `am.`, `o'clock` → `oclock`: drop a dot or apostrophe in a word.
    let raw: Vec<char> = text.to_lowercase().chars().collect();
    let letter = |k: usize| raw.get(k).is_some_and(|ch| ch.is_alphabetic());
    let c: Vec<char> = (0..raw.len())
        .filter(|&k| !(".'’".contains(raw[k]) && k > 0 && letter(k - 1) && letter(k + 1)))
        .map(|k| raw[k])
        .collect();
    let mut words: Vec<(usize, usize)> = Vec::new();
    for (k, ch) in c.iter().enumerate() {
        match words.last_mut() {
            Some((_, end)) if *end == k && ch.is_alphanumeric() => *end = k + 1,
            _ if ch.is_alphanumeric() => words.push((k, k + 1)),
            _ => {}
        }
    }
    let word = |i: usize| -> String {
        words
            .get(i)
            .map_or(String::new(), |&(s, e)| c[s..e].iter().collect())
    };
    (0..words.len()).any(|i| {
        let (here, before, after) = (word(i), word(i.wrapping_sub(1)), word(i + 1));
        if here.chars().any(|ch| ch.is_ascii_digit()) {
            let gap: String = words
                .get(i + 1)
                .map_or(String::new(), |&(s, _)| c[words[i].1..s].iter().collect());
            let duration = here.chars().all(|ch| ch.is_ascii_digit())
                && DURATION_UNITS.contains(&after.as_str())
                && (gap == " " || gap == "-")
                && !RELATIVE.contains(&before.as_str());
            return !duration;
        }
        TIME_WORDS.contains(&here.as_str())
            || (NUMBER_WORDS.contains(&here.as_str())
                && (HOUR_CUES.contains(&before.as_str()) || HOUR_CUES.contains(&after.as_str())))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARIS: Tz = chrono_tz::Europe::Paris;

    /// `"23T10:00+02"` as an instant in October 2026.
    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_str(&format!("2026-10-{text}:00"), "%Y-%m-%dT%H:%M%:z")
            .unwrap()
            .to_utc()
    }

    fn walls(windows: &[Window]) -> Vec<String> {
        let wall = |(s, e): &Window| format!("{} {}", s.format("%d %H:%M%:z"), e.format("%H:%M"));
        windows.iter().map(wall).collect()
    }

    /// Thu 22 Oct 2026 in Paris: the five days are Fri 23 (CEST, +02) and
    /// Mon 26 – Thu 29 (CET, +01, after the change on Sunday 25 Oct).
    #[test]
    fn free_windows_follow_wall_time_busy_events_and_the_week() {
        let busy = [
            (at("23T10:00+02"), at("23T11:00+02")), // Fri: two overlapping meetings,
            (at("23T10:30+02"), at("23T11:30+02")), // then a 20-minute gap
            (at("23T11:50+02"), at("23T18:00+02")),
            (at("26T00:00+01"), at("27T00:00+01")), // Mon: all day
            (at("27T17:00+01"), at("28T10:00+01")), // Tue to Wed, across midnight
            (at("29T08:00+01"), at("29T19:00+01")), // Thu: longer than the day
        ];
        let now = at("22T15:00+02");
        let windows = free_windows(&busy, now, PARIS, Duration::minutes(30));
        let expected = [
            "23 09:00+02:00 10:00",
            "27 09:00+01:00 17:00",
            "28 10:00+01:00 18:00",
        ];
        assert_eq!(walls(&windows), expected);
        assert_eq!(free_windows(&busy, now, PARIS, Duration::hours(2)).len(), 2);
        // A fully busy week proposes nothing, and says so without a time.
        let week = [(at("22T00:00+00"), at("31T00:00+00"))];
        let none = render(
            &free_windows(&week, now, PARIS, Duration::minutes(30)),
            PARIS,
        );
        assert!(
            none.starts_with("I have no free time") && !none.contains(':'),
            "{none}"
        );
        assert_eq!(
            render(&windows[..1], PARIS),
            "- Fri 23 Oct, 09:00–10:00 (Europe/Paris)"
        );
    }

    #[test]
    fn durations_parse_in_both_forms_and_are_bounded() {
        for (text, minutes) in [
            ("30m", 30),
            ("1h", 60),
            ("1h30m", 90),
            ("PT1H30M", 90),
            ("PT45M", 45),
            ("PT2H", 120),
            ("8h", 480),
        ] {
            assert_eq!(parse_length(text), Ok(Duration::minutes(minutes)), "{text}");
        }
        let refused = concat!(
            "|0m|1m|9h|10h|P1D|PT|soon|h|m|-1h|+30m|1h30|30m1h|1.5h|307445734561825861h|",
            "999h999m|18446744073709551616m|٣٠m|３０m|1ｈ|30 m|𝟑𝟎m",
        );
        for text in refused.split('|') {
            assert!(parse_length(text).is_err(), "{text}");
        }
    }

    proptest::proptest! {
        /// No input panics, and every accepted one is 5 minutes to 8 hours.
        #[test]
        fn any_duration_text_is_bounded_or_refused(text in "(PT)?[0-9]{0,24}[hH]?[0-9]{0,24}[mM]?|\\PC{0,24}") {
            if let Ok(length) = parse_length(&text) {
                proptest::prop_assert!((5..=480).contains(&length.num_minutes()));
            }
        }
    }

    fn mail(subject: &str, body: &str) -> serde_json::Value {
        serde_json::json!({ "to": ["c3@exemple.fr"], "subject": subject, "body": body })
    }

    #[test]
    fn the_marker_is_replaced_and_any_time_of_the_model_s_is_refused() {
        let lines = "- Mon 26 Oct, 09:00–12:30 (Europe/Paris)";
        let mut sent = mail("Re: Quote", "Hello,\nI am free:\n{free_times}\nBest");
        fill_mail(&mut sent, lines).unwrap();
        assert_eq!(sent["body"], format!("Hello,\nI am free:\n{lines}\nBest"));
        let mut sent = mail("Quote", "Hello.\n");
        fill_mail(&mut sent, lines).unwrap();
        assert_eq!(sent["body"], format!("Hello.\n\n{lines}"));
        let invented = concat!(
            "How about 14:00?|say 9h30|at 3 pm|at 10am|at 9.15|I am free at 9h.|14 h 30|",
            "9 h|noon|at midday|midi|minuit|９:３０|١٤:٣٠|٩:٣٠|１４:００|2026-10-26T140000Z|",
            "20261021T1400|T14|09.30|9:30|2pm|2 p.m.|at two|two a.m.|half past three|",
            "three o’clock|in 2 hours|Call +33 6 12 34 56|the Q3 quote|1.5 hours",
        );
        for text in invented.split('|') {
            assert!(
                fill_mail(&mut mail("Hi", &format!("{text} {MARKER}")), lines).is_err(),
                "{text}"
            );
            assert!(
                fill_mail(&mut mail(&format!("Meet {text}"), MARKER), lines).is_err(),
                "{text}"
            );
        }
        let fine = concat!(
            "a 30-minute call|30 minutes|1 hour|an hour|I am free|a morning slot|",
            "the afternoon|Re: Quote",
        );
        for fine in fine.split('|') {
            assert!(
                fill_mail(&mut mail(fine, &format!("{fine}\n{MARKER}")), lines).is_ok(),
                "{fine}"
            );
        }
        // The marker belongs once, in the body: none in the subject, no second.
        for (subject, body) in [
            ("Times {free_times}", MARKER),
            ("Hi", "{free_times}\n{free_times}"),
        ] {
            assert!(
                fill_mail(&mut mail(subject, body), lines).is_err(),
                "{subject} {body}"
            );
        }
        let mut account = mail("Hi", MARKER);
        account["account"] = "at noon".into();
        assert!(fill_mail(&mut account, lines).is_err());
    }

    /// The calendar read asks for exactly these UTC bounds
    /// (whole Budapest days, across the Oct 25 DST end); the daemon checks
    /// them against the copy's own `covers_from..covers_to`, never a guess.
    #[test]
    fn the_search_span_is_whole_local_days_in_utc() {
        let zone: Tz = "Europe/Budapest".parse().unwrap();
        let at = |text: &str| {
            zone.from_local_datetime(
                &chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S").unwrap(),
            )
            .unwrap()
            .to_utc()
        };
        let utc = |text: &str| DateTime::parse_from_rfc3339(text).unwrap().to_utc();
        for (now, from, to) in [
            (
                "2026-10-19 23:59:59",
                "2026-10-19T22:00:00Z",
                "2026-10-26T23:00:00Z",
            ),
            (
                "2026-10-20 00:00:01",
                "2026-10-20T22:00:00Z",
                "2026-10-27T23:00:00Z",
            ),
            (
                "2026-10-22 14:00:00",
                "2026-10-22T22:00:00Z",
                "2026-10-29T23:00:00Z",
            ),
        ] {
            assert_eq!(
                search_span(at(now), zone),
                Some((utc(from), utc(to))),
                "{now}"
            );
        }
    }
}
