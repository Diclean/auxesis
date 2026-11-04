//! Is a scheduled job healthy? The rule is pure: `now` is passed in, and a
//! due run that left no receipt is a problem, not silence.

use aux_store::{Run, RUN_FAILED, RUN_INTERRUPTED, RUN_OK, RUN_RUNNING};
use chrono::{DateTime, Duration, Local, NaiveDateTime, TimeZone, Utc};

use crate::api::jobs::RoutineSchedule;

const MIN_GRACE_MINUTES: i64 = 15;

/// A job's health, as the API exposes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// The last due run left a done receipt.
    Ok,
    /// A due run is more than the grace window past its time with no receipt.
    Late,
    /// The last run failed, or the last two runs had to be retried.
    Failing,
    /// It never ran yet and is not due.
    Unknown,
}

impl HealthState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Late => "late",
            Self::Failing => "failing",
            Self::Unknown => "unknown",
        }
    }
}

/// A state plus the short plain reason shown for Late and Failing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobHealth {
    /// The state.
    pub state: HealthState,
    /// `None` unless the state is Late or Failing.
    pub reason: Option<String>,
}

impl JobHealth {
    fn new(state: HealthState, reason: Option<String>) -> Self {
        Self { state, reason }
    }
    fn late(reason: String) -> Self {
        Self::new(HealthState::Late, Some(reason))
    }
    fn failing(reason: String) -> Self {
        Self::new(HealthState::Failing, Some(reason))
    }
}

/// Assess one job. Production passes [`Utc::now`]. An unparseable schedule is
/// `Unknown`; a paused job or a paused/stopped agent is never `Late`.
pub fn assess(
    now: DateTime<Utc>,
    schedule: &str,
    created_at: &str,
    next_run_at: Option<&str>,
    paused: bool,
    runs: &[Run],
) -> JobHealth {
    assess_in(now, schedule, created_at, next_run_at, paused, runs, Local)
}

fn assess_in<Tz: TimeZone + Copy>(
    now: DateTime<Utc>,
    schedule: &str,
    created_at: &str,
    next_run_at: Option<&str>,
    paused: bool,
    runs: &[Run],
    tz: Tz,
) -> JobHealth
where
    Tz::Offset: std::fmt::Display,
{
    let Ok(schedule) = RoutineSchedule::parse(schedule) else {
        return JobHealth::new(HealthState::Unknown, None);
    };
    let Some(created) = parse_at(created_at) else {
        return JobHealth::new(HealthState::Unknown, None);
    };
    let next = next_run_at.and_then(parse_at);
    let Some(last) = runs.last() else {
        if paused {
            return JobHealth::new(HealthState::Unknown, None);
        }
        let due = match next {
            Some(next) if next >= created => next,
            // Created after its slot: the first real slot is still ahead.
            Some(_) => return JobHealth::new(HealthState::Unknown, None),
            // Due immediately; creation is the due time.
            None => created,
        };
        if now <= due {
            return JobHealth::new(HealthState::Unknown, None);
        }
        return if now > due + grace_window(&schedule, due, tz) {
            JobHealth::late(format!("did not run at {}", clock(due, tz)))
        } else {
            JobHealth::new(HealthState::Unknown, None)
        };
    };
    if last.status == RUN_FAILED {
        let at = last
            .finished_at
            .as_deref()
            .and_then(parse_at)
            .unwrap_or(now);
        return JobHealth::failing(format!("failed at {}", clock(at, tz)));
    }
    if runs.len() >= 2
        && runs
            .iter()
            .rev()
            .take(2)
            .all(|run| run.status == RUN_INTERRUPTED)
    {
        return JobHealth::failing("the last two runs were interrupted".to_string());
    }
    if paused {
        return JobHealth::new(HealthState::Ok, None);
    }
    let Some(started) = parse_at(&last.started_at) else {
        return JobHealth::new(HealthState::Unknown, None);
    };
    if last.status == RUN_RUNNING {
        // A run in flight past the grace window is a hang.
        return if now > started + grace_window(&schedule, started, tz) {
            JobHealth::late(format!(
                "started at {} and has not finished",
                clock(started, tz)
            ))
        } else {
            JobHealth::new(HealthState::Ok, None)
        };
    }
    if last.status != RUN_OK && last.status != RUN_INTERRUPTED {
        return JobHealth::failing(format!("failed at {}", clock(now, tz)));
    }
    // Pause/resume moves the next occurrence forward on purpose, so a resumed
    // job is not late for the slots it skipped while paused.
    let due = next.unwrap_or(started).max(started);
    if now > due + grace_window(&schedule, started, tz) {
        return JobHealth::late(format!("did not run at {}", clock(due, tz)));
    }
    JobHealth::new(HealthState::Ok, None)
}

/// `max(15 min, 10% of the period)`. A DST day gives a 23 h or 25 h period,
/// so the window grows with the wall-clock gap.
fn grace_window<Tz: TimeZone + Copy>(
    schedule: &RoutineSchedule,
    at: DateTime<Utc>,
    tz: Tz,
) -> Duration {
    let period = schedule.next_after_run_in(at, at, tz) - at;
    Duration::milliseconds(period.num_milliseconds() / 10).max(Duration::minutes(MIN_GRACE_MINUTES))
}

fn parse_at(raw: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|at| at.and_utc())
}

fn clock<Tz: TimeZone>(at: DateTime<Utc>, tz: Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    at.with_timezone(&tz).format("%H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(raw: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(raw).unwrap().to_utc()
    }

    fn run(started: &str, finished: Option<&str>, status: &str) -> Run {
        Run {
            id: 1,
            job_id: 1,
            started_at: started.to_string(),
            finished_at: finished.map(str::to_string),
            status: status.to_string(),
            summary: None,
        }
    }

    fn done(started: &str) -> Run {
        run(started, Some(started), RUN_OK)
    }

    fn h(now: &str, next: Option<&str>, paused: bool, runs: &[Run]) -> JobHealth {
        assess_in(
            at(now),
            "every 15m",
            "2026-10-01 08:00:00",
            next,
            paused,
            runs,
            Utc,
        )
    }

    #[test]
    fn states_and_the_grace_boundary() {
        let runs = [done("2026-10-03 08:00:00")];
        let next = Some("2026-10-03 08:15:00");
        let state = |now| h(now, next, false, &runs).state;
        assert_eq!(state("2026-10-03T08:10:00Z"), HealthState::Ok);
        assert_eq!(state("2026-10-03T08:30:00Z"), HealthState::Ok);
        let late = h("2026-10-03T08:30:01Z", next, false, &runs);
        assert_eq!(late.state, HealthState::Late);
        assert_eq!(late.reason.as_deref(), Some("did not run at 08:15"));
        let never = |now| h(now, next, false, &[]).state;
        assert_eq!(never("2026-10-03T08:10:00Z"), HealthState::Unknown);
        assert_eq!(never("2026-10-03T08:30:01Z"), HealthState::Late);
    }

    #[test]
    fn failing_retries_a_hang_and_a_pause() {
        let failed = [run(
            "2026-10-03 08:00:00",
            Some("2026-10-03 08:01:00"),
            RUN_FAILED,
        )];
        let state = h(
            "2026-10-03T08:10:00Z",
            Some("2026-10-03 08:15:00"),
            false,
            &failed,
        );
        assert_eq!(state.state, HealthState::Failing);
        assert_eq!(state.reason.as_deref(), Some("failed at 08:01"));
        let retried = [
            run(
                "2026-10-03 07:45:00",
                Some("2026-10-03 07:46:00"),
                RUN_INTERRUPTED,
            ),
            run(
                "2026-10-03 08:00:00",
                Some("2026-10-03 08:01:00"),
                RUN_INTERRUPTED,
            ),
        ];
        let state = h(
            "2026-10-03T08:10:00Z",
            Some("2026-10-03 08:15:00"),
            false,
            &retried,
        );
        assert_eq!(state.state, HealthState::Failing);
        let running = [run("2026-10-03 08:00:00", None, RUN_RUNNING)];
        let hung = h(
            "2026-10-03T08:16:00Z",
            Some("2026-10-03 08:10:00"),
            false,
            &running,
        );
        assert_eq!(hung.state, HealthState::Late);
        assert_eq!(
            hung.reason.as_deref(),
            Some("started at 08:00 and has not finished")
        );
        let paused = h(
            "2026-10-03T10:00:00Z",
            Some("2026-10-03 08:15:00"),
            true,
            &[done("2026-10-03 08:00:00")],
        );
        assert_eq!(paused.state, HealthState::Ok);
    }

    #[test]
    fn a_dst_day_changes_the_grace_window() {
        // Fall-back day in Paris: 08:00 local is 25 h after the last one.
        let runs = [done("2026-10-24 06:00:00")];
        let state = |now: &str| {
            assess_in(
                at(now),
                "0 8 * * *",
                "2026-10-20 00:00:00",
                Some("2026-10-25 07:00:00"),
                false,
                &runs,
                chrono_tz::Europe::Paris,
            )
        };
        assert_eq!(state("2026-10-25T09:24:00Z").state, HealthState::Ok);
        assert_eq!(state("2026-10-25T09:40:00Z").state, HealthState::Late);
    }
}
