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

/// [`mail_time_in`] in the owner's system zone (the IANA name when the Mac
/// names one, else the system's local rules), and `raw` unchanged when it is
/// not a date.
pub fn mail_time_local(raw: &str) -> String {
    let named = crate::skills::event_time::owner_time_zone()
        .and_then(|name| name.parse::<chrono_tz::Tz>().ok());
    let shown = match named {
        Some(zone) => mail_time_in(raw, &zone),
        None => mail_time_in(raw, &Local),
    };
    shown.unwrap_or_else(|| raw.to_string())
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
