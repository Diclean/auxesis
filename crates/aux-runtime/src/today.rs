//! The date the model is told at the start of each turn: today's weekday and
//! date, the local UTC offset, and the ranges the owner means by "this week".
//! Date and offset only: no place, no clock time, nothing about the owner.

use chrono::{DateTime, Datelike, Duration, FixedOffset, Local, NaiveDate, TimeZone};

/// The sentence for `now`, read in its own offset: the weekday, the date and
/// the offset (`+02:00`). Two shapes are avoided, both measured through the
/// tokenising gate: a dashed `2026-10-11` (a phone-like run) and a weekday before
/// a comma (read as a name, so `Today` itself is masked). The line depends only
/// on the instant it is given.
pub fn today_line(now: DateTime<FixedOffset>) -> String {
    format!(
        "Today is {} {}. Local time zone offset {}.",
        now.format("%A"),
        now.format("%-d %B %Y"),
        now.format("%:z")
    )
}

/// The line for the wall clock now, in the local offset.
pub fn today_line_now() -> String {
    today_line(Local::now().fixed_offset())
}

/// A mail `Date:` header as the owner's wall clock in `zone`, with the offset
/// that applied on that date: `Thu, 15 Oct 2026 14:59 (local time, UTC+02:00)`.
/// The offset is the zone's rule at that instant, not today's, so a summer
/// mail read in winter still shows its summer offset. `None` when `raw` is not
/// an RFC 2822 date: the caller keeps the header as written.
///
/// The model used to get the sender's raw header (`… 12:59:00 +0000`) and
/// converted it itself, with only today's offset, so one mail read at
/// 14:59, 15:59 or 16:59 from run to run.
///
/// What the model learns is the owner's own offset on that date, which is the
/// only new fact; nothing about the sender or the mail is added. A header with
/// text after the date (`… +0000 TAIL`) is not a date: `None`, so the caller
/// keeps the whole header, sanitised like any other.
pub fn mail_time_in<Z: TimeZone>(raw: &str, zone: &Z) -> Option<String>
where
    Z::Offset: std::fmt::Display,
{
    let sent = DateTime::parse_from_rfc2822(raw.trim()).ok()?;
    let local = sent.with_timezone(zone);
    Some(format!(
        "{} (local time, UTC{})",
        local.format("%a, %-d %b %Y %H:%M"),
        local.format("%:z")
    ))
}

/// [`mail_time_in`] in a named IANA zone (`Europe/Paris`); `None` when the
/// name is unknown or `raw` is not a date.
pub fn mail_time_in_named(raw: &str, zone: &str) -> Option<String> {
    mail_time_in(raw, &zone.parse::<chrono_tz::Tz>().ok()?)
}

/// [`mail_time_in`] in the owner's system zone (the IANA name when the Mac
/// names one, else the system's local rules), and `raw` unchanged when it is
/// not a date.
pub fn mail_time_local(raw: &str) -> String {
    crate::skills::event_time::owner_time_zone()
        .and_then(|name| mail_time_in_named(raw, &name))
        .or_else(|| mail_time_in(raw, &Local))
        .unwrap_or_else(|| raw.to_string())
}

/// The date context the model gets at the start of every turn: today's line,
/// then the three ranges the owner means by "this week", "the next seven days"
/// and "next week".
///
/// The model used to pick the week range itself. On a Sunday
/// 25 October it answered "what do I have this week?" with the days of
/// Monday 26 October to Sunday 1 November and called them this week. The
/// ranges are computed here, from the local date, so the model only reads them
/// and never guesses one.
///
/// "This week" runs from today to the Sunday of the current week (a week runs
/// Monday to Sunday), so on a Sunday it is today alone and "next week" is the
/// Monday to Sunday that follows.
pub fn date_context(now: DateTime<FixedOffset>) -> String {
    let today = now.date_naive();
    let week_end = today + Duration::days((6 - today.weekday().num_days_from_monday()) as i64);
    format!(
        "{today_line}\n\
         This week (from today to the end of the week): {rest}.\n\
         Next seven days: {seven}.\n\
         Next week: {next}.",
        today_line = today_line(now),
        rest = span(today, week_end),
        seven = span(today, today + Duration::days(6)),
        next = span(week_end + Duration::days(1), week_end + Duration::days(7)),
    )
}

/// The date context for the wall clock now, in the local offset.
pub fn date_context_now() -> String {
    date_context(Local::now().fixed_offset())
}

/// One range as the model reads it: "Wednesday 28 October 2026 to Sunday 1
/// November 2026", or the single day when the range is one day long.
fn span(from: NaiveDate, to: NaiveDate) -> String {
    if from == to {
        return from.format("%A %-d %B %Y").to_string();
    }
    format!(
        "{from} to {to}",
        from = from.format("%A %-d %B %Y"),
        to = to.format("%A %-d %B %Y")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line depends only on the instant it is given, so a fixed instant
    /// keeps the test independent of the wall clock.
    #[test]
    fn the_line_names_the_weekday_date_and_offset_of_the_instant() {
        let east = FixedOffset::east_opt(2 * 3600).unwrap();
        let morning = east.with_ymd_and_hms(2026, 10, 11, 9, 30, 0).unwrap();
        assert_eq!(
            today_line(morning),
            "Today is Sunday 11 October 2026. Local time zone offset +02:00."
        );
        let west = FixedOffset::west_opt(5 * 3600).unwrap();
        let late = west.with_ymd_and_hms(2026, 10, 10, 23, 30, 0).unwrap();
        assert_eq!(
            today_line(late),
            "Today is Saturday 10 October 2026. Local time zone offset -05:00."
        );
    }

    /// Date and offset only: no clock time and no place name.
    #[test]
    fn the_line_carries_no_clock_time_or_place() {
        let instant = FixedOffset::east_opt(3600)
            .unwrap()
            .with_ymd_and_hms(2026, 10, 11, 9, 30, 0)
            .unwrap();
        let line = today_line(instant);
        assert!(!line.contains("09:30"), "{line}");
        assert!(!line.contains('/'), "a zone name is not offered: {line}");
    }

    /// The mail from 15 October was shown at 14:59, 15:59 and 16:59 on
    /// different runs: the model got `12:59 +0000` and only today's offset.
    /// The time now comes converted with the offset of that date (CEST), also
    /// when it is read in November (CET).
    #[test]
    fn a_mail_time_carries_the_offset_of_its_own_date() {
        let paris = chrono_tz::Europe::Paris;
        let summer = mail_time_in("Thu, 15 Oct 2026 12:59:00 +0000", &paris);
        assert_eq!(
            summer.as_deref(),
            Some("Thu, 15 Oct 2026 14:59 (local time, UTC+02:00)")
        );
        let winter = mail_time_in("Sat, 7 Nov 2026 12:59:00 +0000", &paris);
        assert_eq!(
            winter.as_deref(),
            Some("Sat, 7 Nov 2026 13:59 (local time, UTC+01:00)")
        );
        // The sender's own offset is converted, not trusted as the owner's.
        let sent = mail_time_in("Thu, 15 Oct 2026 08:59:00 -0400", &paris);
        assert_eq!(
            sent.as_deref(),
            Some("Thu, 15 Oct 2026 14:59 (local time, UTC+02:00)")
        );
    }

    /// A header that is not a date is kept as written, never guessed.
    #[test]
    fn a_header_that_is_not_a_date_is_kept() {
        assert_eq!(
            mail_time_in("yesterday-ish", &chrono_tz::Europe::Paris),
            None
        );
        assert_eq!(mail_time_local("yesterday-ish"), "yesterday-ish");
        let local = mail_time_local("Thu, 15 Oct 2026 12:59:00 +0000");
        assert!(local.contains("(local time, UTC"), "{local}");
    }

    /// The offset changes at the transition instant, 01:00 UTC on 25 October
    /// 2026: 00:30 UTC is still summer time, 01:30 UTC is winter time.
    #[test]
    fn the_offset_changes_at_the_dst_transition_instant() {
        let paris = chrono_tz::Europe::Paris;
        assert_eq!(
            mail_time_in("Sun, 25 Oct 2026 00:30:00 +0000", &paris).as_deref(),
            Some("Sun, 25 Oct 2026 02:30 (local time, UTC+02:00)")
        );
        assert_eq!(
            mail_time_in("Sun, 25 Oct 2026 01:30:00 +0000", &paris).as_deref(),
            Some("Sun, 25 Oct 2026 02:30 (local time, UTC+01:00)")
        );
    }

    /// A date far ahead still converts, with the rule of its own year.
    #[test]
    fn a_far_date_is_converted_with_its_own_offset() {
        assert_eq!(
            mail_time_in_named("Thu, 16 Jul 2099 12:00:00 +0000", "Europe/Paris").as_deref(),
            Some("Thu, 16 Jul 2099 14:00 (local time, UTC+02:00)")
        );
        assert_eq!(
            mail_time_in_named("Thu, 17 Dec 2099 12:00:00 +0000", "Europe/Paris").as_deref(),
            Some("Thu, 17 Dec 2099 13:00 (local time, UTC+01:00)")
        );
    }

    /// A zone name the database does not know falls back to the system's
    /// local rules, never to the raw header.
    #[test]
    fn an_unknown_zone_falls_back_to_the_system_local_rules() {
        let raw = "Thu, 15 Oct 2026 12:59:00 +0000";
        assert_eq!(mail_time_in_named(raw, "Not/AZone"), None);
        let _zone = crate::skills::event_time::TestZone::set("Not/AZone");
        assert_eq!(
            Some(mail_time_local(raw)),
            mail_time_in(raw, &Local),
            "the Local branch, whatever the host zone"
        );
    }

    /// Text after a valid date is not dropped: the header is kept whole.
    #[test]
    fn text_after_a_valid_date_keeps_the_whole_header() {
        let raw = "Thu, 15 Oct 2026 12:59:00 +0000 TAIL";
        assert_eq!(mail_time_in_named(raw, "Europe/Paris"), None);
        assert_eq!(mail_time_local(raw), raw);
    }

    /// A Paris instant on a given day. Paris is CET (+01:00) at midday on
    /// 25 October 2026: the summer time ended that morning at 03:00.
    fn paris(year: i32, month: u32, day: u32) -> DateTime<FixedOffset> {
        chrono_tz::Europe::Paris
            .with_ymd_and_hms(year, month, day, 12, 0, 0)
            .single()
            .expect("a Paris instant")
            .fixed_offset()
    }

    /// The owner asked "what do I have this week?" on Sunday
    /// 25 October 2026 and got the days of the next week, called this week.
    /// The context names the weekday and the ranges, so the model reads them
    /// instead of choosing one.
    #[test]
    fn the_date_context_names_the_weekday_and_the_ranges_of_a_sunday() {
        let context = date_context(paris(2026, 10, 25));
        assert!(
            context.contains("Today is Sunday 25 October 2026."),
            "{context}"
        );
        assert!(
            context
                .contains("This week (from today to the end of the week): Sunday 25 October 2026."),
            "{context}"
        );
        assert!(
            context
                .contains("Next seven days: Sunday 25 October 2026 to Saturday 31 October 2026."),
            "{context}"
        );
        assert!(
            context.contains("Next week: Monday 26 October 2026 to Sunday 1 November 2026."),
            "{context}"
        );
    }

    /// A week runs Monday to Sunday: on a Wednesday the rest of the week ends
    /// on the Sunday of the same week, and next week is the Monday after.
    #[test]
    fn the_date_context_ends_the_week_on_sunday() {
        let context = date_context(paris(2026, 10, 28));
        assert!(
            context.contains("Today is Wednesday 28 October 2026."),
            "{context}"
        );
        assert!(
            context.contains(
                "This week (from today to the end of the week): Wednesday 28 October 2026 to Sunday 1 November 2026."
            ),
            "{context}"
        );
        assert!(
            context.contains("Next week: Monday 2 November 2026 to Sunday 8 November 2026."),
            "{context}"
        );
    }

    /// The context names no clock time and no place, like the line it extends.
    #[test]
    fn the_date_context_carries_no_clock_time_or_place() {
        let context = date_context(paris(2026, 10, 25));
        assert!(!context.contains("12:00"), "{context}");
        assert!(
            !context.contains('/'),
            "a zone name is not offered: {context}"
        );
    }
}
