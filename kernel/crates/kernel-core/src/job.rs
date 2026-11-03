//! Job schedules for the M2 scheduler.
//!
//! Schedule v1 supports two forms:
//!
//! - `every <N>m` / `every <N>h` — a fixed interval counted from the last
//!   run; if the daemon was asleep for several intervals, the missed
//!   occurrences collapse into a single catch-up run.
//! - `daily <HH:MM>` — a local wall-clock time, once a day.
//!
//! [`Schedule::next_after`] is generic over the timezone so tests can pin a
//! fixed offset; [`Schedule::next_after_utc`] resolves daily schedules
//! against the machine's local timezone (DST gaps move to the first real
//! instant, ambiguous times pick the earliest).

use chrono::{DateTime, Duration, Local, LocalResult, NaiveTime, TimeZone, Utc};
use thiserror::Error;

/// A parsed job schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schedule {
    /// Fire every `period`, measured in absolute time.
    Interval {
        /// Positive interval between two runs.
        period: Duration,
    },
    /// Fire once a day at a local wall-clock `time`.
    Daily {
        /// Local wall-clock time of day.
        time: NaiveTime,
    },
}

/// Errors returned when parsing a schedule.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    /// The schedule string was empty or whitespace only.
    #[error("schedule is empty")]
    Empty,
    /// The schedule is not one of the supported v1 forms.
    #[error("unsupported schedule {0:?}: expected \"every 15m\" or \"daily 08:30\"")]
    Unsupported(String),
    /// The interval part of an `every …` schedule is malformed.
    #[error("invalid interval {0:?}: expected `every <n>m` or `every <n>h` with n >= 1")]
    InvalidInterval(String),
    /// The time part of a `daily …` schedule is malformed.
    #[error("invalid daily time {0:?}: expected `daily HH:MM` (24-hour, local time)")]
    InvalidDailyTime(String),
}

impl Schedule {
    /// Parse `every <n>m`, `every <n>h` or `daily <HH:MM>`.
    ///
    /// Input is whitespace-trimmed and case-insensitive. Only `m` and `h`
    /// units are accepted in v1 (one minute is the finest granularity), so
    /// a valid schedule can never spin faster than the scheduler tick.
    pub fn parse(raw: &str) -> Result<Self, ScheduleError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ScheduleError::Empty);
        }
        let mut parts = trimmed.split_whitespace();
        let kind = parts.next().unwrap_or_default().to_ascii_lowercase();
        let rest: Vec<&str> = parts.collect();
        match (kind.as_str(), rest.as_slice()) {
            ("every", [interval]) => parse_interval(interval),
            ("daily", [time]) => parse_daily(time),
            _ => Err(ScheduleError::Unsupported(trimmed.to_string())),
        }
    }

    /// Next occurrence strictly after `after`, in `after`'s timezone.
    pub fn next_after<Tz: TimeZone>(&self, after: DateTime<Tz>) -> DateTime<Tz> {
        match self {
            Schedule::Interval { period } => after + *period,
            Schedule::Daily { time } => next_daily(after, *time),
        }
    }

    /// Next occurrence strictly after `after`, resolving daily schedules in
    /// the machine's local timezone.
    pub fn next_after_utc(&self, after: DateTime<Utc>) -> DateTime<Utc> {
        self.next_after(after.with_timezone(&Local)).to_utc()
    }
}

fn parse_interval(raw: &str) -> Result<Schedule, ScheduleError> {
    let lowered = raw.to_ascii_lowercase();
    let (digits, unit) = if let Some(digits) = lowered.strip_suffix('m') {
        (digits, 'm')
    } else if let Some(digits) = lowered.strip_suffix('h') {
        (digits, 'h')
    } else {
        return Err(ScheduleError::InvalidInterval(raw.to_string()));
    };
    let count: i64 = digits
        .parse()
        .map_err(|_| ScheduleError::InvalidInterval(raw.to_string()))?;
    if count < 1 {
        return Err(ScheduleError::InvalidInterval(raw.to_string()));
    }
    let period = match unit {
        'm' => Duration::try_minutes(count),
        'h' => Duration::try_hours(count),
        _ => None,
    }
    .ok_or_else(|| ScheduleError::InvalidInterval(raw.to_string()))?;
    Ok(Schedule::Interval { period })
}

fn parse_daily(raw: &str) -> Result<Schedule, ScheduleError> {
    let time = NaiveTime::parse_from_str(raw, "%H:%M")
        .map_err(|_| ScheduleError::InvalidDailyTime(raw.to_string()))?;
    Ok(Schedule::Daily { time })
}

/// Strictly-next local wall-clock `time` after `after`.
fn next_daily<Tz: TimeZone>(after: DateTime<Tz>, time: NaiveTime) -> DateTime<Tz> {
    let timezone = after.timezone();
    let wall = after.naive_local();

    let mut date = wall.date();
    let mut candidate = date.and_time(time);
    if candidate <= wall {
        match date.succ_opt() {
            Some(next) => {
                date = next;
                candidate = date.and_time(time);
            }
            // Unreachable for real calendars; keep the function total.
            None => return after + Duration::days(1),
        }
    }

    // Resolve the wall-clock candidate against the zone, always returning a
    // strictly future instant:
    // - a spring-forward gap (`None`) walks forward to the first instant
    //   that exists;
    // - a fall-back overlap (`Ambiguous`) picks the earliest occurrence
    //   still after `after` — on the second pass through the repeated hour,
    //   the first occurrence is in the past, so the later one wins.
    let mut probe = candidate;
    for _ in 0..96 {
        match timezone.from_local_datetime(&probe) {
            LocalResult::Single(instant) if instant > after => return instant,
            LocalResult::Single(_) => probe += Duration::minutes(15),
            LocalResult::Ambiguous(earliest, latest) => {
                if earliest > after {
                    return earliest;
                }
                if latest > after {
                    return latest;
                }
                probe += Duration::minutes(15);
            }
            LocalResult::None => probe += Duration::minutes(15),
        }
    }
    after + Duration::days(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{FixedOffset, NaiveDate};

    /// A timezone-pinned instant, so the assertions are machine-independent.
    fn at(
        offset_seconds: i32,
        y: i32,
        m: u32,
        d: u32,
        hh: u32,
        mm: u32,
        ss: u32,
    ) -> DateTime<FixedOffset> {
        FixedOffset::east_opt(offset_seconds)
            .unwrap()
            .with_ymd_and_hms(y, m, d, hh, mm, ss)
            .unwrap()
    }

    fn daily(hh: u32, mm: u32) -> Schedule {
        Schedule::Daily {
            time: NaiveTime::from_hms_opt(hh, mm, 0).unwrap(),
        }
    }

    // ---- parsing ----

    #[test]
    fn parses_interval_minutes() {
        assert_eq!(
            Schedule::parse("every 15m").unwrap(),
            Schedule::Interval {
                period: Duration::minutes(15)
            }
        );
    }

    #[test]
    fn parses_interval_hours() {
        assert_eq!(
            Schedule::parse("every 2h").unwrap(),
            Schedule::Interval {
                period: Duration::hours(2)
            }
        );
    }

    #[test]
    fn parse_trims_and_ignores_case() {
        assert_eq!(
            Schedule::parse("  Every 15M  ").unwrap(),
            Schedule::Interval {
                period: Duration::minutes(15)
            }
        );
        assert_eq!(Schedule::parse("DAILY 08:30").unwrap(), daily(8, 30));
    }

    #[test]
    fn parses_single_digit_hour() {
        assert_eq!(Schedule::parse("daily 8:30").unwrap(), daily(8, 30));
    }

    #[test]
    fn rejects_malformed_schedules() {
        for raw in [
            "",
            "   ",
            "every",
            "every m",
            "every 15",
            "every 15s",
            "every 15d",
            "every 0m",
            "every 0h",
            "every -5m",
            "every 99999999999999999999m",
            "daily",
            "daily 8h",
            "daily 25:00",
            "daily 12:60",
            "daily 08:30:00",
            "weekly 08:30",
        ] {
            assert!(
                Schedule::parse(raw).is_err(),
                "{raw:?} should not parse as a v1 schedule"
            );
        }
    }

    // ---- interval occurrences ----

    #[test]
    fn interval_advances_by_exactly_one_period() {
        let start = at(2 * 3600, 2026, 10, 3, 8, 0, 0);
        assert_eq!(
            Schedule::parse("every 15m").unwrap().next_after(start),
            at(2 * 3600, 2026, 10, 3, 8, 15, 0)
        );
    }

    #[test]
    fn interval_is_absolute_time_not_wall_clock() {
        // Intervals count real elapsed time, so an offset change does not
        // shift them.
        let start = at(3600, 2026, 10, 25, 1, 30, 0);
        assert_eq!(
            Schedule::parse("every 2h").unwrap().next_after(start),
            at(3600, 2026, 10, 25, 3, 30, 0)
        );
    }

    #[test]
    fn interval_repeats_forever() {
        let schedule = Schedule::parse("every 15m").unwrap();
        let mut cursor = at(0, 2026, 10, 3, 23, 50, 0);
        for expected in [(2026, 10, 4, 0, 5), (2026, 10, 4, 0, 20)] {
            cursor = schedule.next_after(cursor);
            assert_eq!(
                cursor,
                at(0, expected.0, expected.1, expected.2, expected.3, expected.4, 0)
            );
        }
    }

    // ---- daily occurrences ----

    #[test]
    fn daily_stays_on_the_same_day_when_the_time_is_ahead() {
        let schedule = daily(8, 30);
        let start = at(2 * 3600, 2026, 10, 3, 7, 59, 59);
        assert_eq!(
            schedule.next_after(start),
            at(2 * 3600, 2026, 10, 3, 8, 30, 0)
        );
    }

    #[test]
    fn daily_rolls_to_the_next_day_once_due() {
        let schedule = daily(8, 30);
        for start in [
            at(2 * 3600, 2026, 10, 3, 8, 30, 0),   // exactly due: next day
            at(2 * 3600, 2026, 10, 3, 8, 30, 1),   // just past
            at(2 * 3600, 2026, 10, 3, 23, 59, 59), // end of day
        ] {
            assert_eq!(
                schedule.next_after(start),
                at(2 * 3600, 2026, 10, 4, 8, 30, 0),
                "start {start}"
            );
        }
    }

    #[test]
    fn daily_is_wall_clock_in_its_own_zone() {
        let schedule = daily(8, 30);
        // 23:00 in +05:30 is still before 08:30 there, but the *next*
        // instant must be 08:30 wall clock in that same zone.
        let start = at(5 * 3600 + 1800, 2026, 10, 3, 7, 0, 0);
        assert_eq!(
            schedule.next_after(start),
            at(5 * 3600 + 1800, 2026, 10, 3, 8, 30, 0)
        );
    }

    #[test]
    fn daily_crosses_month_and_year_boundaries() {
        let schedule = daily(8, 30);
        let start = at(0, 2026, 12, 31, 9, 0, 0);
        assert_eq!(schedule.next_after(start), at(0, 2027, 1, 1, 8, 30, 0));
    }

    // ---- DST (Europe/Paris, the project's local zone) ----

    #[test]
    fn daily_moves_to_the_first_real_instant_in_a_spring_forward_gap() {
        use chrono_tz::Europe::Paris;
        // 2026-03-29: 02:00 CET jumps to 03:00 CEST, so 02:30 does not exist.
        let schedule = daily(2, 30);
        let before = Paris
            .with_ymd_and_hms(2026, 3, 29, 1, 0, 0)
            .single()
            .unwrap();

        let next = schedule.next_after(before);
        assert_eq!(
            next,
            Paris
                .with_ymd_and_hms(2026, 3, 29, 3, 0, 0)
                .single()
                .unwrap(),
            "the missed wall time runs at the first instant that exists"
        );
    }

    #[test]
    fn daily_in_a_fall_back_overlap_is_always_strictly_after() {
        use chrono_tz::Europe::Paris;
        // 2026-10-25: 03:00 CEST falls back to 02:00 CET, so 02:30 happens
        // twice: 00:30 UTC (CEST) then 01:30 UTC (CET).
        let schedule = daily(2, 30);
        let first_pass = Paris
            .with_ymd_and_hms(2026, 10, 25, 2, 0, 0)
            .earliest()
            .unwrap();

        let next = schedule.next_after(first_pass);
        assert_eq!(
            next,
            Paris
                .with_ymd_and_hms(2026, 10, 25, 2, 30, 0)
                .earliest()
                .unwrap(),
            "before the first 02:30, the earliest occurrence is next"
        );

        // 02:15 CET is the *second* pass through the repeated hour: the
        // first 02:30 is already in the past, so the second one must win —
        // never an instant before `after`, or the job would be overdue
        // forever.
        let second_pass = Paris
            .with_ymd_and_hms(2026, 10, 25, 2, 15, 0)
            .latest()
            .unwrap();
        let next = schedule.next_after(second_pass);
        assert!(next > second_pass);
        assert_eq!(
            next,
            Paris
                .with_ymd_and_hms(2026, 10, 25, 2, 30, 0)
                .latest()
                .unwrap(),
            "after the first occurrence, the repeated wall time wins"
        );

        // Once both passes are behind us, the next run is tomorrow.
        let after_both = Paris
            .with_ymd_and_hms(2026, 10, 25, 2, 45, 0)
            .latest()
            .unwrap();
        let next = schedule.next_after(after_both);
        assert!(next > after_both);
        assert_eq!(next.date_naive().to_string(), "2026-10-26");
    }

    #[test]
    fn interval_next_after_is_always_in_the_future() {
        use chrono_tz::Europe::Paris;
        let schedule = Schedule::parse("every 15m").unwrap();
        for (y, m, d, hh, mm) in [
            (2026, 3, 29, 1, 50),  // before the spring-forward gap
            (2026, 3, 29, 3, 5),   // just after it
            (2026, 10, 25, 2, 50), // inside the fall-back overlap
        ] {
            let after = Paris
                .with_ymd_and_hms(y, m, d, hh, mm, 0)
                .single()
                .or_else(|| Paris.with_ymd_and_hms(y, m, d, hh, mm, 0).earliest())
                .unwrap();
            assert!(schedule.next_after(after) > after);
        }
    }

    #[test]
    fn next_after_utc_resolves_daily_in_local_time() {
        let now_local = Local
            .with_ymd_and_hms(2026, 10, 3, 7, 0, 0)
            .single()
            .expect("07:00 local exists on a normal day");
        let next = daily(8, 30).next_after_utc(now_local.to_utc());
        let next_local = next.with_timezone(&Local);

        assert!(next > now_local.to_utc());
        assert_eq!(
            next_local.date_naive(),
            NaiveDate::from_ymd_opt(2026, 10, 3).unwrap()
        );
        assert_eq!(
            next_local.time(),
            NaiveTime::from_hms_opt(8, 30, 0).unwrap()
        );
    }
}
