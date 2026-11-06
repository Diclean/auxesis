//! Load an agent's runtime skills at agent start.
//!
//! The loader writes every `skill.load_error` row through the store's
//! `AuditSink`, deduplicated per `(agent, file hash)` so a broken skill is
//! logged once, not on every turn. The parsed skills are not yet wired into
//! the turn.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use aux_store::{Store, StoreHandle};
use kernel_broker::{AuditError, AuditSink};
use serde_json::Value;

/// Load `home/agents/<agent>`'s definition and skills, logging every load error
/// through the shared store's `AuditSink`, once per `(agent, file hash)`.
pub fn load_agent_skills(home: &Path, agent: &str, store: &Arc<Mutex<Store>>) {
    let agent_dir = aux_engine::agent_dir(home, agent);
    let Some(inner) = aux_engine::gated_audit_sink(&StoreHandle::Shared(Arc::clone(store))) else {
        return;
    };
    let sink = DedupSink { inner };
    let loaded = match aux_runtime::skills::load_agent(&agent_dir) {
        Ok(loaded) => loaded,
        Err(err) => {
            let skill_name = Path::new(&err.file)
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or(&err.file)
                .to_string();
            let payload = serde_json::json!({
                "agent": agent,
                "skill_name": skill_name,
                "skill_version": serde_json::Value::Null,
                "skill_hash": serde_json::Value::Null,
                "run_id": serde_json::Value::Null,
                "file": err.file,
                "reason": err.reason,
            });
            let _ = sink.log_event("skill.load_error", &payload);
            return;
        }
    };
    let _ = aux_runtime::skills::load_skills(&agent_dir, &loaded, Some(&sink));
}

/// A sink that forwards each `skill.load_error` only once per
/// `(agent, skill_hash)`, falling back to the file when there is no hash.
struct DedupSink {
    inner: Arc<dyn AuditSink>,
}

impl AuditSink for DedupSink {
    fn log_event(&self, kind: &str, payload: &Value) -> Result<i64, AuditError> {
        if kind == "skill.load_error" {
            let agent = payload
                .get("agent")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let key = payload
                .get("skill_hash")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    format!(
                        "file:{}",
                        payload
                            .get("file")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                    )
                });
            let mut logged = kernel_core::sync::lock_recover(logged_errors());
            if !logged.insert((agent.to_string(), key)) {
                return Ok(0);
            }
        }
        self.inner.log_event(kind, payload)
    }
}

fn logged_errors() -> &'static Mutex<HashSet<(String, String)>> {
    static LOGGED: OnceLock<Mutex<HashSet<(String, String)>>> = OnceLock::new();
    LOGGED.get_or_init(|| Mutex::new(HashSet::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn broken_agent(home: &Path, content: &str) {
        let agent_dir = home.join("agents").join("assistant");
        fs::create_dir_all(agent_dir.join("skills")).unwrap();
        fs::write(agent_dir.join("agent.md"), "---\nname: assistant\n---\n").unwrap();
        fs::write(agent_dir.join("skills").join("bad.md"), content).unwrap();
    }

    #[test]
    fn load_errors_reach_the_store_sink_once_per_file_hash() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        broken_agent(
            home,
            "---\nname: bad\nversion: 3\ntools: [google.gmail.archive]\napproval: each_run\n---\n",
        );
        let store = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));

        // A turn loads the same broken file: the row is written once.
        load_agent_skills(home, "assistant", &store);
        load_agent_skills(home, "assistant", &store);
        let guard = kernel_core::sync::lock_recover(&store);
        assert_eq!(guard.event_count("skill.load_error").unwrap(), 1);
        let payload = &guard.event_payloads("skill.load_error").unwrap()[0];
        assert!(payload.contains("\"skill_name\":\"bad\""), "{payload}");
        assert!(payload.contains("\"skill_version\":3"), "{payload}");
        assert!(payload.contains("unknown tool"), "{payload}");
        assert!(payload.contains("\"run_id\":null"), "{payload}");
        drop(guard);

        // Editing the file changes its hash, so the new error is logged.
        fs::write(
            home.join("agents/assistant/skills/bad.md"),
            "---\nname: bad\nversion: 4\ntools: [google.gmail.archive]\napproval: each_run\n---\n",
        )
        .unwrap();
        load_agent_skills(home, "assistant", &store);
        let guard = kernel_core::sync::lock_recover(&store);
        assert_eq!(guard.event_count("skill.load_error").unwrap(), 2);
    }
}
