//! The date the model is told at the start of each turn: today's weekday and
//! date, the local UTC offset, and the ranges the owner means by "this week".
//! Date and offset only: no place, no clock time, nothing about the owner.

use chrono::{DateTime, Datelike, Duration, FixedOffset, Local, NaiveDate};

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

/// The date context the model gets at the start of every turn: today's line,
/// then the three ranges the owner means by "this week", "the next seven days"
/// and "next week".
///
/// CAL-THIS-WEEK: the model used to pick the week range itself. On a Sunday
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
    use chrono::{FixedOffset, TimeZone};

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

    /// A Paris instant on a given day. Paris is CET (+01:00) at midday on
    /// 25 October 2026: the summer time ended that morning at 03:00.
    fn paris(year: i32, month: u32, day: u32) -> DateTime<FixedOffset> {
        chrono_tz::Europe::Paris
            .with_ymd_and_hms(year, month, day, 12, 0, 0)
            .single()
            .expect("a Paris instant")
            .fixed_offset()
    }

    /// CAL-THIS-WEEK: the owner asked "what do I have this week?" on Sunday
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
