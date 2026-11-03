//! Scheduled jobs and the runs they produce.
//!
//! A job is recurring work with a schedule; every time the scheduler
//! claims a due job it opens a run that records how the job ended.

use super::*;

impl Store {
    // ---- jobs ----

    /// Create a job and return the stored row.
    ///
    /// `next_run_at` is computed by the caller (schedule parsing lives in
    /// `aux-core`); pass `None` to make the job due immediately, which the
    /// scheduler then reschedules after the first run. New jobs are enabled.
    pub fn create_job(
        &self,
        agent: &str,
        name: &str,
        schedule: &str,
        payload: &str,
        next_run_at: Option<&str>,
    ) -> Result<Job, StoreError> {
        self.conn.execute(
            "INSERT INTO jobs(agent, name, schedule, payload, next_run_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![agent, name, schedule, payload, next_run_at],
        )?;
        self.job(self.conn.last_insert_rowid())
    }

    /// Fetch one job by id, or `None` when it does not exist.
    pub fn job_by_id(&self, id: i64) -> Result<Option<Job>, StoreError> {
        let job = self
            .conn
            .query_row("SELECT id, agent, name, schedule, payload, enabled, created_at, last_run_at, next_run_at FROM jobs WHERE id = ?1", [id], row_to_job)
            .optional()?;
        Ok(job)
    }

    /// List all jobs, oldest first.
    pub fn list_jobs(&self) -> Result<Vec<Job>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent, name, schedule, payload, enabled, created_at, last_run_at, next_run_at
             FROM jobs
             ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], row_to_job)?;
        let jobs = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(jobs)
    }

    /// Replace every mutable field of a job (not the id or `created_at`).
    pub fn update_job(&self, job: &Job) -> Result<Job, StoreError> {
        let changed = self.conn.execute(
            "UPDATE jobs
             SET agent = ?2, name = ?3, schedule = ?4, payload = ?5, enabled = ?6,
                 last_run_at = ?7, next_run_at = ?8
             WHERE id = ?1",
            rusqlite::params![
                job.id,
                job.agent,
                job.name,
                job.schedule,
                job.payload,
                job.enabled,
                job.last_run_at,
                job.next_run_at,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::JobNotFound { id: job.id });
        }
        self.job(job.id)
    }

    /// Enable or disable a job. Returns `false` when the id is unknown.
    pub fn set_job_enabled(&self, id: i64, enabled: bool) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE jobs SET enabled = ?2 WHERE id = ?1",
            rusqlite::params![id, enabled],
        )?;
        Ok(changed > 0)
    }

    /// Replace one job's payload only (a watcher's state), leaving its claim
    /// lease and flags alone. Returns `false` when the id is unknown.
    pub fn set_job_payload(&self, id: i64, payload: &str) -> Result<bool, StoreError> {
        let sql = "UPDATE jobs SET payload = ?2 WHERE id = ?1";
        Ok(self.conn.execute(sql, rusqlite::params![id, payload])? > 0)
    }

    /// Delete a job and, via `ON DELETE CASCADE`, its runs.
    ///
    /// Returns `true` when a job was deleted and `false` when `id` did not
    /// exist, so callers can tell a missing job apart from an empty one.
    pub fn delete_job(&self, id: i64) -> Result<bool, StoreError> {
        let deleted = self.conn.execute("DELETE FROM jobs WHERE id = ?1", [id])?;
        Ok(deleted > 0)
    }

    /// Jobs that are due and **claimable** at `now`: enabled, with a
    /// `next_run_at` in the past or no `next_run_at` at all ("due
    /// immediately"), and no `running` run in flight. Ordered by due time
    /// (never-scheduled jobs first), then id.
    pub fn due_jobs(&self, now: &str) -> Result<Vec<Job>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, agent, name, schedule, payload, enabled, created_at, last_run_at, next_run_at
             FROM jobs
             WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?1)
               AND NOT EXISTS (
                   SELECT 1 FROM runs
                   WHERE runs.job_id = jobs.id AND runs.status = ?2
               )
             ORDER BY next_run_at IS NOT NULL, next_run_at, id",
        )?;
        let rows = stmt.query_map([now, RUN_RUNNING], row_to_job)?;
        let jobs = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(jobs)
    }

    /// Atomically claim the jobs due at `now` and reserve them until
    /// `lease_until` by moving their `next_run_at` forward.
    ///
    /// The claim runs in an `IMMEDIATE` transaction, so concurrent claimants
    /// (two daemons on the same store) can never both take the same job. If
    /// the process crashes while a run is in flight, the lease expires and
    /// the job becomes due again — never lost, never double-claimed while
    /// the lease holds. Claimed rows come back with `next_run_at` already
    /// set to `lease_until`.
    ///
    /// A job with a live `running` run is never claimed, even when its lease
    /// has been outrun (clock jump, missed renewal, machine sleep): the run
    /// itself is the last line of defence, not the lease. Crash recovery is
    /// unaffected — daemon startup marks leftover `running` runs
    /// `interrupted`, and an `interrupted` run is re-claimable.
    pub fn claim_due_jobs(&mut self, now: &str, lease_until: &str) -> Result<Vec<Job>, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut claimed = {
            let mut stmt = tx.prepare(
                "SELECT id, agent, name, schedule, payload, enabled, created_at, last_run_at, next_run_at
                 FROM jobs
                 WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?1)
                   AND NOT EXISTS (
                       SELECT 1 FROM runs
                       WHERE runs.job_id = jobs.id AND runs.status = ?2
                   )
                 ORDER BY next_run_at IS NOT NULL, next_run_at, id
                 LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                rusqlite::params![now, RUN_RUNNING, CLAIM_BATCH_LIMIT],
                row_to_job,
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for job in &claimed {
            tx.execute(
                "UPDATE jobs SET next_run_at = ?2 WHERE id = ?1",
                rusqlite::params![job.id, lease_until],
            )?;
        }
        tx.commit()?;
        for job in &mut claimed {
            job.next_run_at = Some(lease_until.to_string());
        }
        Ok(claimed)
    }

    /// Set the last/next run timestamps of a job after a run finished.
    /// Returns `false` when the id is unknown.
    pub fn reschedule_job(
        &self,
        id: i64,
        last_run_at: Option<&str>,
        next_run_at: Option<&str>,
    ) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE jobs SET last_run_at = ?2, next_run_at = ?3 WHERE id = ?1",
            rusqlite::params![id, last_run_at, next_run_at],
        )?;
        Ok(changed > 0)
    }

    /// Push a running job's claim lease forward without touching its
    /// `last_run_at`. Used while a long run is still executing, so the job
    /// never becomes claimable behind the live run. Returns `false` when the
    /// id is unknown.
    pub fn renew_lease(&self, id: i64, lease_until: &str) -> Result<bool, StoreError> {
        let changed = self.conn.execute(
            "UPDATE jobs SET next_run_at = ?2 WHERE id = ?1",
            rusqlite::params![id, lease_until],
        )?;
        Ok(changed > 0)
    }

    // ---- runs ----

    /// Record the start of a run. The run stays `running` until
    /// [`Store::finish_run`] is called.
    pub fn start_run(&self, job_id: i64, started_at: &str) -> Result<Run, StoreError> {
        self.conn.execute(
            "INSERT INTO runs(job_id, started_at, status) VALUES (?1, ?2, ?3)",
            rusqlite::params![job_id, started_at, RUN_RUNNING],
        )?;
        self.run(self.conn.last_insert_rowid())
    }

    /// Close a run with its final status and summary.
    pub fn finish_run(
        &self,
        run_id: i64,
        finished_at: &str,
        status: &str,
        summary: Option<&str>,
    ) -> Result<Run, StoreError> {
        let changed = self.conn.execute(
            "UPDATE runs SET finished_at = ?2, status = ?3, summary = ?4 WHERE id = ?1",
            rusqlite::params![run_id, finished_at, status, summary],
        )?;
        if changed == 0 {
            return Err(StoreError::RunNotFound { id: run_id });
        }
        self.run(run_id)
    }

    /// Runs of a job in execution order.
    pub fn runs_for_job(&self, job_id: i64) -> Result<Vec<Run>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, job_id, started_at, finished_at, status, summary
             FROM runs
             WHERE job_id = ?1
             ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([job_id], row_to_run)?;
        let runs = rows.collect::<Result<Vec<_>, _>>()?;
        Ok(runs)
    }

    /// Mark every `running` run as `interrupted` (called once on daemon
    /// startup: a run left `running` can only mean the process died).
    pub fn interrupt_running_runs(&self, finished_at: &str) -> Result<usize, StoreError> {
        let changed = self.conn.execute(
            "UPDATE runs
             SET status = ?3, finished_at = ?1,
                 summary = COALESCE(summary, 'interrupted by daemon restart')
             WHERE status = ?2",
            rusqlite::params![finished_at, RUN_RUNNING, RUN_INTERRUPTED],
        )?;
        Ok(changed)
    }

    /// Fetch one job by id (fails when missing).
    fn job(&self, id: i64) -> Result<Job, StoreError> {
        let job = self.conn.query_row(
            "SELECT id, agent, name, schedule, payload, enabled, created_at, last_run_at, next_run_at
             FROM jobs WHERE id = ?1",
            [id],
            row_to_job,
        )?;
        Ok(job)
    }

    /// Fetch one run by id (fails when missing).
    fn run(&self, id: i64) -> Result<Run, StoreError> {
        let run = self.conn.query_row(
            "SELECT id, job_id, started_at, finished_at, status, summary FROM runs WHERE id = ?1",
            [id],
            row_to_run,
        )?;
        Ok(run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ---- jobs ----

    #[test]
    fn create_job_round_trips_its_fields() {
        let store = Store::open_in_memory().unwrap();
        let job = store
            .create_job(
                "axis",
                "morning digest",
                "daily 08:30",
                r#"{"kind":"digest"}"#,
                Some("2026-10-04 06:30:00"),
            )
            .unwrap();

        assert!(job.id > 0);
        assert_eq!(job.agent, "axis");
        assert_eq!(job.name, "morning digest");
        assert_eq!(job.schedule, "daily 08:30");
        assert_eq!(job.payload, r#"{"kind":"digest"}"#);
        assert!(job.enabled);
        assert!(!job.created_at.is_empty());
        assert_eq!(job.last_run_at, None);
        assert_eq!(job.next_run_at.as_deref(), Some("2026-10-04 06:30:00"));
        assert_eq!(store.job_by_id(job.id).unwrap(), Some(job.clone()));
        assert_eq!(store.list_jobs().unwrap(), vec![job]);
    }

    #[test]
    fn create_job_without_schedule_is_due_immediately() {
        let store = Store::open_in_memory().unwrap();
        let job = store
            .create_job("main", "kick", "every 15m", "{}", None)
            .unwrap();
        assert_eq!(job.next_run_at, None);
        assert_eq!(store.due_jobs("2026-10-03 08:00:00").unwrap(), vec![job]);
    }

    #[test]
    fn list_jobs_is_oldest_first() {
        let store = Store::open_in_memory().unwrap();
        let first = store
            .create_job("main", "one", "every 15m", "{}", None)
            .unwrap();
        let second = store
            .create_job("main", "two", "every 15m", "{}", None)
            .unwrap();
        assert_eq!(
            store.list_jobs().unwrap(),
            vec![first.clone(), second.clone()]
        );
        assert_eq!(store.job_by_id(999).unwrap(), None);
    }

    #[test]
    fn update_job_replaces_mutable_fields() {
        let store = Store::open_in_memory().unwrap();
        let mut job = store
            .create_job("main", "old", "every 15m", "{}", None)
            .unwrap();

        job.agent = "axis".to_string();
        job.name = "new".to_string();
        job.schedule = "daily 09:00".to_string();
        job.payload = r#"{"v":2}"#.to_string();
        job.enabled = false;
        job.last_run_at = Some("2026-10-03 08:00:00".to_string());
        job.next_run_at = Some("2026-10-04 07:00:00".to_string());
        let updated = store.update_job(&job).unwrap();

        assert_eq!(updated, job);
        assert_eq!(store.job_by_id(job.id).unwrap(), Some(job));
    }

    #[test]
    fn update_missing_job_is_reported() {
        let store = Store::open_in_memory().unwrap();
        let ghost = Job {
            id: 4242,
            agent: "main".into(),
            name: "ghost".into(),
            schedule: "every 15m".into(),
            payload: "{}".into(),
            enabled: true,
            created_at: "2026-01-01 00:00:00".into(),
            last_run_at: None,
            next_run_at: None,
        };
        assert!(matches!(
            store.update_job(&ghost).unwrap_err(),
            StoreError::JobNotFound { id: 4242 }
        ));
    }

    #[test]
    fn set_job_enabled_toggles_and_reports_missing_ids() {
        let store = Store::open_in_memory().unwrap();
        let job = store
            .create_job("main", "pause me", "every 15m", "{}", None)
            .unwrap();

        assert!(store.set_job_enabled(job.id, false).unwrap());
        assert!(!store.job_by_id(job.id).unwrap().unwrap().enabled);
        assert!(store.set_job_enabled(job.id, true).unwrap());
        assert!(store.job_by_id(job.id).unwrap().unwrap().enabled);
        assert!(!store.set_job_enabled(999, false).unwrap());
    }

    #[test]
    fn delete_job_cascades_to_its_runs_only() {
        let store = Store::open_in_memory().unwrap();
        let doomed = store
            .create_job("main", "doomed", "every 15m", "{}", None)
            .unwrap();
        let kept = store
            .create_job("main", "kept", "every 15m", "{}", None)
            .unwrap();
        store.start_run(doomed.id, "2026-10-03 08:00:00").unwrap();
        store.start_run(doomed.id, "2026-10-03 08:15:00").unwrap();
        store.start_run(kept.id, "2026-10-03 08:00:00").unwrap();

        assert!(store.delete_job(doomed.id).unwrap());
        assert!(store.runs_for_job(doomed.id).unwrap().is_empty());
        assert_eq!(store.runs_for_job(kept.id).unwrap().len(), 1);
        assert_eq!(store.list_jobs().unwrap(), vec![kept]);
        assert!(!store.delete_job(doomed.id).unwrap());
    }

    #[test]
    fn due_jobs_respects_enabled_and_due_time() {
        let store = Store::open_in_memory().unwrap();
        let past = store
            .create_job(
                "main",
                "past",
                "every 15m",
                "{}",
                Some("2026-10-03 07:00:00"),
            )
            .unwrap();
        let future = store
            .create_job(
                "main",
                "future",
                "every 15m",
                "{}",
                Some("2026-10-03 09:00:00"),
            )
            .unwrap();
        let paused = store
            .create_job(
                "main",
                "paused",
                "every 15m",
                "{}",
                Some("2026-10-03 07:00:00"),
            )
            .unwrap();
        store.set_job_enabled(paused.id, false).unwrap();

        // Exactly-at-due counts; one second before does not.
        assert_eq!(store.due_jobs("2026-10-03 06:59:59").unwrap(), vec![]);
        assert_eq!(
            store.due_jobs("2026-10-03 07:00:00").unwrap(),
            vec![past.clone()]
        );
        // Both scheduled jobs are in the past by noon, in due-time order.
        assert_eq!(
            store.due_jobs("2026-10-03 12:00:00").unwrap(),
            vec![past, future]
        );
    }

    #[test]
    fn due_jobs_orders_by_due_time_then_id() {
        let store = Store::open_in_memory().unwrap();
        let later = store
            .create_job(
                "main",
                "later",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let earlier = store
            .create_job(
                "main",
                "earlier",
                "every 15m",
                "{}",
                Some("2026-10-03 07:00:00"),
            )
            .unwrap();
        let now = store
            .create_job("main", "now", "every 15m", "{}", None)
            .unwrap();

        let due = store.due_jobs("2026-10-03 08:30:00").unwrap();
        assert_eq!(due, vec![now, earlier, later]);
    }

    #[test]
    fn claim_due_jobs_moves_next_run_to_the_lease() {
        let mut store = Store::open_in_memory().unwrap();
        let job = store
            .create_job(
                "main",
                "tick",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        let not_due = store
            .create_job(
                "main",
                "later",
                "every 15m",
                "{}",
                Some("2026-10-03 09:00:00"),
            )
            .unwrap();

        let claimed = store
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, job.id);
        assert_eq!(
            claimed[0].next_run_at.as_deref(),
            Some("2026-10-03 08:10:00")
        );

        // The claim is persisted, so a second claimant at the same instant
        // sees nothing.
        assert!(store
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:10:00")
        );
        assert_eq!(
            store
                .job_by_id(not_due.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 09:00:00")
        );
    }

    #[test]
    fn claim_due_jobs_is_bounded_by_the_batch_limit() {
        // F-17: a store with many due jobs must not fan out one engine turn
        // per row in a single tick.
        let mut store = Store::open_in_memory().unwrap();
        for index in 0..(CLAIM_BATCH_LIMIT + 8) {
            store
                .create_job(
                    "main",
                    &format!("job{index}"),
                    "every 15m",
                    "{}",
                    Some("2026-10-03 08:00:00"),
                )
                .unwrap();
        }
        let first = store
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap();
        assert_eq!(first.len() as i64, CLAIM_BATCH_LIMIT);
        // The claimed rows were leased forward, so the next tick gets the
        // remainder instead of starving.
        let second = store
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap();
        assert_eq!(second.len(), 8);
        assert!(store
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_live_running_run_blocks_a_re_claim_even_with_a_backdated_lease() {
        // NEW-A2: the lease alone must not be the last line of defence. If a
        // clock jump (or a missed renewal) back-dates `next_run_at` while run
        // #1 is still `running`, the next claim must not start run #2.
        let mut store = Store::open_in_memory().unwrap();
        let job = store
            .create_job(
                "main",
                "slow",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();

        let claimed = store
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap();
        assert_eq!(claimed.len(), 1);
        let run = store.start_run(job.id, "2026-10-03 08:00:00").unwrap();
        assert_eq!(run.status, RUN_RUNNING);

        // Models the back-dated lease from the report: due again while live.
        store.renew_lease(job.id, "2026-10-03 07:59:00").unwrap();
        assert!(
            store
                .claim_due_jobs("2026-10-03 08:05:00", "2026-10-03 08:15:00")
                .unwrap()
                .is_empty(),
            "a live run must never be re-claimed"
        );
        assert!(
            store.due_jobs("2026-10-03 08:05:00").unwrap().is_empty(),
            "`due` must mean `claimable`"
        );
        assert_eq!(store.runs_for_job(job.id).unwrap().len(), 1);

        // Crash recovery semantics stay: startup marks the run interrupted…
        assert_eq!(
            store.interrupt_running_runs("2026-10-03 08:06:00").unwrap(),
            1
        );
        // …and an interrupted run is re-claimable.
        let reclaimed = store
            .claim_due_jobs("2026-10-03 08:06:00", "2026-10-03 08:16:00")
            .unwrap();
        assert_eq!(reclaimed.len(), 1);
        assert_eq!(
            store.runs_for_job(job.id).unwrap().len(),
            1,
            "claiming does not create a run by itself"
        );

        // A finished run blocks nothing (only `running` does).
        let second = store.start_run(job.id, "2026-10-03 08:06:00").unwrap();
        store
            .finish_run(second.id, "2026-10-03 08:06:01", RUN_OK, None)
            .unwrap();
        store.renew_lease(job.id, "2026-10-03 07:59:00").unwrap();
        assert_eq!(
            store
                .claim_due_jobs("2026-10-03 08:07:00", "2026-10-03 08:17:00")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.runs_for_job(job.id).unwrap().len(), 2);
    }

    #[test]
    fn a_claim_is_visible_to_other_connections() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let mut first = Store::open(&path).unwrap();
        let mut second = Store::open(&path).unwrap();
        let job = first
            .create_job(
                "main",
                "shared",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();

        let claimed = first
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap();
        assert_eq!(claimed.len(), 1);

        // A second connection (a CLI, another daemon) sees the lease and
        // cannot claim the same job again.
        assert!(second.due_jobs("2026-10-03 08:00:00").unwrap().is_empty());
        assert!(second
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap()
            .is_empty());
        assert_eq!(
            second
                .job_by_id(job.id)
                .unwrap()
                .unwrap()
                .next_run_at
                .as_deref(),
            Some("2026-10-03 08:10:00")
        );
    }

    #[test]
    fn expired_lease_makes_a_job_due_again() {
        let mut store = Store::open_in_memory().unwrap();
        let job = store
            .create_job(
                "main",
                "crashy",
                "every 15m",
                "{}",
                Some("2026-10-03 08:00:00"),
            )
            .unwrap();
        store
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap();

        // Simulates a daemon that died mid-run: nothing is due while the
        // lease holds, then the job comes back.
        assert!(store.due_jobs("2026-10-03 08:09:59").unwrap().is_empty());
        assert_eq!(
            store.due_jobs("2026-10-03 08:10:00").unwrap(),
            vec![store.job_by_id(job.id).unwrap().unwrap()]
        );
    }

    #[test]
    fn disabled_jobs_are_never_claimed() {
        let mut store = Store::open_in_memory().unwrap();
        let job = store
            .create_job(
                "main",
                "paused",
                "every 15m",
                "{}",
                Some("2026-10-03 07:00:00"),
            )
            .unwrap();
        store.set_job_enabled(job.id, false).unwrap();

        assert!(store
            .claim_due_jobs("2026-10-03 08:00:00", "2026-10-03 08:10:00")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reschedule_job_sets_timestamps_and_reports_missing_ids() {
        let store = Store::open_in_memory().unwrap();
        let job = store
            .create_job("main", "j", "every 15m", "{}", None)
            .unwrap();

        assert!(store
            .reschedule_job(
                job.id,
                Some("2026-10-03 08:00:00"),
                Some("2026-10-03 08:15:00")
            )
            .unwrap());
        let stored = store.job_by_id(job.id).unwrap().unwrap();
        assert_eq!(stored.last_run_at.as_deref(), Some("2026-10-03 08:00:00"));
        assert_eq!(stored.next_run_at.as_deref(), Some("2026-10-03 08:15:00"));

        // Pausing a job clears its next occurrence.
        assert!(store.reschedule_job(job.id, None, None).unwrap());
        let stored = store.job_by_id(job.id).unwrap().unwrap();
        assert_eq!(stored.last_run_at, None);
        assert_eq!(stored.next_run_at, None);

        assert!(!store.reschedule_job(999, None, None).unwrap());
    }

    // ---- runs ----

    #[test]
    fn runs_round_trip_through_start_and_finish() {
        let store = Store::open_in_memory().unwrap();
        let job = store
            .create_job("main", "j", "every 15m", "{}", None)
            .unwrap();

        let running = store.start_run(job.id, "2026-10-03 08:00:00").unwrap();
        assert_eq!(running.status, RUN_RUNNING);
        assert_eq!(running.started_at, "2026-10-03 08:00:00");
        assert_eq!(running.finished_at, None);
        assert_eq!(running.summary, None);

        let finished = store
            .finish_run(running.id, "2026-10-03 08:00:03", RUN_OK, Some("all good"))
            .unwrap();
        assert_eq!(finished.status, RUN_OK);
        assert_eq!(finished.finished_at.as_deref(), Some("2026-10-03 08:00:03"));
        assert_eq!(finished.summary.as_deref(), Some("all good"));
        assert_eq!(store.runs_for_job(job.id).unwrap(), vec![finished]);
    }

    #[test]
    fn runs_are_listed_in_execution_order_and_scoped_to_their_job() {
        let store = Store::open_in_memory().unwrap();
        let first = store
            .create_job("main", "first", "every 15m", "{}", None)
            .unwrap();
        let second = store
            .create_job("main", "second", "every 15m", "{}", None)
            .unwrap();

        let first_a = store.start_run(first.id, "2026-10-03 08:00:00").unwrap();
        let second_a = store.start_run(second.id, "2026-10-03 08:05:00").unwrap();
        let first_b = store.start_run(first.id, "2026-10-03 08:15:00").unwrap();

        assert_eq!(
            store.runs_for_job(first.id).unwrap(),
            vec![first_a, first_b]
        );
        assert_eq!(store.runs_for_job(second.id).unwrap(), vec![second_a]);
        assert!(store.runs_for_job(999).unwrap().is_empty());
    }

    #[test]
    fn start_run_requires_an_existing_job() {
        let store = Store::open_in_memory().unwrap();
        let error = store.start_run(4242, "2026-10-03 08:00:00").unwrap_err();
        assert!(matches!(error, StoreError::Sqlite(_)));
    }

    #[test]
    fn finish_missing_run_is_reported() {
        let store = Store::open_in_memory().unwrap();
        let error = store
            .finish_run(4242, "2026-10-03 08:00:00", RUN_OK, None)
            .unwrap_err();
        assert!(matches!(error, StoreError::RunNotFound { id: 4242 }));
    }

    #[test]
    fn interrupt_running_runs_marks_only_running_runs() {
        let store = Store::open_in_memory().unwrap();
        let job = store
            .create_job("main", "j", "every 15m", "{}", None)
            .unwrap();
        let interrupted = store.start_run(job.id, "2026-10-03 08:00:00").unwrap();
        let done = store
            .start_run(job.id, "2026-10-03 08:01:00")
            .map(|run| {
                store
                    .finish_run(run.id, "2026-10-03 08:01:01", RUN_OK, Some("done"))
                    .unwrap()
            })
            .unwrap();

        assert_eq!(
            store.interrupt_running_runs("2026-10-03 09:00:00").unwrap(),
            1
        );

        let runs = store.runs_for_job(job.id).unwrap();
        assert_eq!(runs[0].id, interrupted.id);
        assert_eq!(runs[0].status, RUN_INTERRUPTED);
        assert_eq!(runs[0].finished_at.as_deref(), Some("2026-10-03 09:00:00"));
        assert!(runs[0].summary.as_deref().unwrap().contains("restart"));
        // An already finished run is untouched.
        assert_eq!(runs[1], done);
        // Idempotent: a second startup finds nothing to interrupt.
        assert_eq!(
            store.interrupt_running_runs("2026-10-03 10:00:00").unwrap(),
            0
        );
    }

    #[test]
    fn jobs_and_runs_persist_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");
        let (job_id, run_id) = {
            let store = Store::open(&path).unwrap();
            let job = store
                .create_job(
                    "main",
                    "persisted",
                    "daily 08:30",
                    r#"{"k":"v"}"#,
                    Some("2026-10-04 06:30:00"),
                )
                .unwrap();
            let run = store
                .start_run(job.id, "2026-10-03 08:00:00")
                .map(|run| {
                    store
                        .finish_run(run.id, "2026-10-03 08:00:02", RUN_FAILED, Some("boom"))
                        .unwrap()
                })
                .unwrap();
            (job.id, run.id)
        };

        let store = Store::open(&path).unwrap();
        let job = store.job_by_id(job_id).unwrap().unwrap();
        assert_eq!(job.name, "persisted");
        assert_eq!(job.schedule, "daily 08:30");
        assert_eq!(job.payload, r#"{"k":"v"}"#);
        assert_eq!(job.next_run_at.as_deref(), Some("2026-10-04 06:30:00"));

        let runs = store.runs_for_job(job_id).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].id, run_id);
        assert_eq!(runs[0].status, RUN_FAILED);
        assert_eq!(runs[0].summary.as_deref(), Some("boom"));
    }
}
