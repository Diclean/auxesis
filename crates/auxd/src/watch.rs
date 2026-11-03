//! WATCH-1: "tell me when…" watchers: routines with a `{"kind":"watch","url",
//! "condition","stop_after_hit","last_hash"}` payload. The chief's `watch` tool
//! adds, lists and cancels them through the `POST /v1/jobs` checks; a run is
//! `AgentJobRunner::run` (fetch, skip the model while the hash is unchanged,
//! notify once on a hit).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aux_store::{Job, Store};
use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
use kernel_core::privacy::PathId;
use kernel_net::{EgressContext, FetchEgress, WebBudget};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::jobs::{create_routine, delete_routine};

/// Payload `kind` of a watcher job.
pub const KIND: &str = "watch";

const MAX_CONDITION_BYTES: usize = 500;

/// Texts a watcher that stays armed may send per local calendar day.
pub const MAX_TEXTS_PER_DAY: u32 = 3;

/// The payload of a watcher job; `last_hash` and the daily tally are its only
/// mutable state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchSpec {
    pub url: String,
    pub condition: String,
    pub stop_after_hit: bool,
    pub last_hash: Option<String>,
    /// Local day (`YYYY-MM-DD`) the counts below belong to.
    #[serde(default)]
    pub sent_day: Option<String>,
    /// Notifications sent on `sent_day`.
    #[serde(default)]
    pub sent: u32,
    /// Hits on `sent_day` past the daily cap, not sent.
    #[serde(default)]
    pub skipped: u32,
}

impl WatchSpec {
    /// The watcher in `job`'s payload, or `None` for any other job.
    pub fn of(job: &Job) -> Option<Self> {
        let value: Value = serde_json::from_str(&job.payload).ok()?;
        (value["kind"] == KIND).then(|| serde_json::from_value(value).ok())?
    }

    /// Start `day`'s tally if it is a new day; returns the hits skipped on
    /// earlier days, to be told once with the next notification.
    pub fn roll_day(&mut self, day: &str) -> u32 {
        if self.sent_day.as_deref() == Some(day) {
            return 0;
        }
        self.sent_day = Some(day.to_string());
        self.sent = 0;
        std::mem::take(&mut self.skipped)
    }

    /// The payload JSON stored on the job row.
    pub fn payload(&self) -> String {
        let mut value = json!(self);
        value["kind"] = json!(KIND);
        value.to_string()
    }
}

/// FNV-1a over the page text with whitespace collapsed: stable across Rust
/// versions, so a stored hash never changes meaning under a toolchain bump.
pub fn text_hash(text: &str) -> String {
    let bytes = text
        .split_whitespace()
        .flat_map(|word| word.bytes().chain(*b" "));
    let hash = bytes.fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("{hash:016x}")
}

/// The egress authority of a scheduled fetch of `url`: approved for the
/// origin the owner approved at `add` and for no other, so a redirect to
/// another origin (or port) is refused before any request. The context is
/// clean on purpose: the turn that carried private data was gated when the
/// watcher was created, and a run has no turn. A fresh budget per run.
pub fn scheduled_egress(url: &str) -> Option<FetchEgress> {
    let url = reqwest::Url::parse(url).ok()?;
    let host = url.host_str()?.trim_matches(['[', ']']);
    let origin = format!("{}://{host}:{}", url.scheme(), url.port_or_known_default()?);
    Some(FetchEgress {
        context: EgressContext::default(),
        seen_origins: Arc::default(),
        approved_origins: Arc::new([origin].into()),
        budget: Arc::new(Mutex::new(WebBudget::new())),
        refused_hops: Arc::default(),
        received_response: Arc::default(),
        received_origins: Arc::default(),
    })
}

/// The chief's `watch` tool: `add`, `list` or `cancel` a watcher.
pub struct WatchTool {
    home: PathBuf,
    store: Arc<Mutex<Store>>,
}

impl WatchTool {
    pub fn new(home: PathBuf, store: Arc<Mutex<Store>>) -> Self {
        Self { home, store }
    }
}

#[async_trait]
impl Tool for WatchTool {
    fn path_id(&self) -> PathId {
        // A local write in the job table, like the CRM tools.
        PathId::G3
    }

    fn name(&self) -> &str {
        "watch"
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "description": "Watch a web page and message the owner once when a condition is met. `add` (default) needs url, condition in plain words and interval (`every 30m`, `daily 08:30`; at least 5 minutes); stop_after_hit defaults to true. `list` shows the watchers; `cancel` needs an id.",
            "properties": {
                "action": {"type": "string", "enum": ["add", "list", "cancel"]},
                "url": {"type": "string", "maxLength": 2048},
                "condition": {"type": "string", "maxLength": MAX_CONDITION_BYTES},
                "interval": {"type": "string", "maxLength": 64},
                "stop_after_hit": {"type": "boolean"},
                "id": {"type": "integer", "minimum": 1}
            },
            "additionalProperties": false
        })
    }

    async fn run(&self, args: &Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let bad = |message: &str| ToolError::invalid_args("watch", message);
        let text = |key: &str| args[key].as_str().map(|text| text.trim().to_string());
        let refused = |message: String| Ok(ToolOutput::error(message));
        let store = kernel_core::sync::lock_recover(&self.store);
        match args["action"].as_str().unwrap_or("add") {
            "list" => {
                let jobs = store.list_jobs().unwrap_or_default();
                let rows = jobs.iter().filter_map(|job| {
                    let on = if job.enabled { "on" } else { "off" };
                    Some(format!(
                        "#{} ({on}): {}",
                        job.id,
                        WatchSpec::of(job)?.condition
                    ))
                });
                Ok(ToolOutput::ok(rows.collect::<Vec<_>>().join("\n")))
            }
            "cancel" => {
                let id = args["id"]
                    .as_i64()
                    .ok_or_else(|| bad("cancel needs an id"))?;
                let job = store.job_by_id(id).ok().flatten();
                match job.filter(|job| WatchSpec::of(job).is_some()) {
                    Some(_) => match delete_routine(&store, id) {
                        Ok(_) => Ok(ToolOutput::ok(format!("watcher {id} cancelled"))),
                        Err(err) => refused(err.message),
                    },
                    None => refused("no such watcher".into()),
                }
            }
            "add" => {
                let (Some(url), Some(condition), Some(interval)) =
                    (text("url"), text("condition"), text("interval"))
                else {
                    return Err(bad("add needs url, condition and interval"));
                };
                if !(url.starts_with("https://") || url.starts_with("http://")) || url.len() > 2048
                {
                    return Err(bad("url must be an absolute http:// or https:// address"));
                }
                // A token this session never minted (private mode) is refused:
                // a watcher stores real values.
                if format!("{url}{condition}").contains(['⟦', '⟧'])
                    || condition.is_empty()
                    || condition.len() > MAX_CONDITION_BYTES
                {
                    return Err(bad("condition must be 1-500 bytes without ⟦…⟧ references"));
                }
                let label: String = condition
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(60)
                    .collect();
                let name = format!("watch: {label}");
                let stop_after_hit = args["stop_after_hit"].as_bool().unwrap_or(true);
                let spec = WatchSpec {
                    url,
                    condition,
                    stop_after_hit,
                    last_hash: None,
                    sent_day: None,
                    sent: 0,
                    skipped: 0,
                };
                let payload = spec.payload();
                match create_routine(&self.home, &store, &ctx.agent, &name, &interval, &payload) {
                    Ok(job) => Ok(ToolOutput::ok(
                        json!({"id": job.id, "name": job.name}).to_string(),
                    )),
                    Err(err) => refused(err.message),
                }
            }
            _ => Err(bad("action must be add, list or cancel")),
        }
    }

    fn risk(&self) -> Risk {
        Risk::Medium
    }

    fn class(&self) -> ToolClass {
        // A local write whose `url` is the address the scheduler will fetch
        // from then on. Declared like `http_fetch`, so `add` clears the
        // engine's web egress layer first (URL gate, deny list, the
        // sensitive-turn ask) and the argument screen reads url and
        // condition; `list` and `cancel` carry no url and pass through.
        ToolClass {
            performs_web_egress: true,
            egress_url_argument: true,
            arguments_leave_machine: true,
            ..ToolClass::default()
        }
    }
}
