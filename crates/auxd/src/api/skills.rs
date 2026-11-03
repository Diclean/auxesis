//! Local skill discovery and owner-only runtime skill imports.
use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;

use super::{error, ApiState};

/// `GET /v1/skills` — names, descriptions, byte sizes and validation status.
pub async fn list(State(state): State<Arc<ApiState>>) -> Response {
    match tokio::task::spawn_blocking(move || aux_engine::skills::list(&state.home)).await {
        Ok(skills) => Json(skills).into_response(),
        Err(_) => error::error_response(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "skills_unavailable",
            "skills could not be listed",
            None,
        ),
    }
}

use aux_runtime::skills::{
    skill::parse_skill,
    tool_map::{self, ToolKind},
    LoadedSkill,
};
use axum::extract::{Path as RoutePath, Query};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};

// Serialise preview, import and approval, including the check before replacement.
static IMPORT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Deserialize)]
pub struct Target {
    agent: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    filename: String,
    text: String,
    agent: Option<String>,
}
#[derive(Deserialize)]
pub struct Approve {
    agent: Option<String>,
    hash: String,
}

fn validate_segment(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 40
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("name must contain 1 to 40 lowercase letters, digits or hyphens".into());
    }
    Ok(())
}
fn pending(agent: &str, name: &str) -> PathBuf {
    PathBuf::from("skill-imports/pending")
        .join(agent)
        .join(format!("{name}.md"))
}
fn parsed(home: &Path, agent: &str, name: &str, bytes: &[u8]) -> Result<LoadedSkill, String> {
    aux_engine::validate_agent(agent).map_err(|e| e.to_string())?;
    validate_segment(name)?;
    let dir = aux_engine::agent_dir(home, agent);
    if !crate::agent::exists(home, agent) {
        return Err("unknown agent".into());
    }
    let definition = aux_runtime::skills::load_agent(&dir).map_err(|e| e.to_string())?;
    let skill =
        parse_skill(bytes, &format!("{name}.md"), name, &definition).map_err(|e| e.reason)?;
    for tool in &skill.tools {
        if matches!(
            tool_map::lookup(tool).map(|info| info.kind),
            Some(ToolKind::Extension) | None
        ) {
            return Err(format!("unknown or unsupported extension tool `{tool}`"));
        }
    }
    let existing = aux_runtime::skills::load_skills(&dir, &definition, None);
    if skill.command.as_ref().is_some_and(|command| {
        existing
            .skills
            .iter()
            .any(|s| s.name != name && s.command.as_ref() == Some(command))
    }) {
        return Err("command is already used by another skill".into());
    }
    Ok(skill)
}
fn preview(agent: &str, skill: &LoadedSkill, bytes: &[u8]) -> Value {
    let mut read = Vec::new();
    let mut write = Vec::new();
    let mut contact = Vec::new();
    for tool in &skill.tools {
        // Write tools may also look up existing records or read attachments.
        read.push(tool.clone());
        if tool_map::lookup(tool).is_some_and(|info| !info.is_read_only()) {
            write.push(tool.clone());
        }
        let service = if tool.starts_with("google.") {
            Some("Google account services")
        } else if tool.starts_with("mail.") || tool == "docs.ingest" {
            Some("configured mail server and mail recipients")
        } else if tool.starts_with("calendar.") || tool.starts_with("reminders.") {
            Some("configured calendar or reminders accounts")
        } else {
            None
        };
        if let Some(service) = service.filter(|service| !contact.contains(service)) {
            contact.push(service);
        }
    }
    json!({"agent":agent,"name":skill.name,"description":skill.body.lines().find(|line| !line.trim().is_empty()).unwrap_or(""),
        "text":std::str::from_utf8(bytes).unwrap_or(""),"tools":skill.tools,"read":read,"write":write,
        "contact":contact,"model":"the agent's configured model may be contacted", "hash":skill.hash,"status":"pending"})
}
fn read_pending(home: &Path, agent: &str, name: &str) -> Result<(Vec<u8>, LoadedSkill), String> {
    aux_engine::validate_agent(agent).map_err(|e| e.to_string())?;
    validate_segment(name)?;
    let gateway = kernel_core::verified_home_or_verify(home).map_err(|_| "home unavailable")?;
    let mut file = gateway
        .open_read_existing(&pending(agent, name), aux_runtime::skills::MAX_SKILL_BYTES)
        .map_err(|_| "pending skill not found or unreadable")?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(aux_runtime::skills::MAX_SKILL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read pending skill")?;
    if bytes.len() as u64 > aux_runtime::skills::MAX_SKILL_BYTES {
        return Err("skill exceeds 64 KiB".into());
    }
    let skill = parsed(home, agent, name, &bytes)?;
    Ok((bytes, skill))
}
fn result(result: Result<Value, String>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(reason) => {
            error::error_response(StatusCode::BAD_REQUEST, "invalid_skill", &reason, None)
        }
    }
}
async fn blocking(f: impl FnOnce() -> Result<Value, String> + Send + 'static) -> Response {
    match tokio::task::spawn_blocking(f).await {
        Ok(value) => result(value),
        Err(_) => result(Err("skill operation failed".into())),
    }
}

pub async fn import(State(state): State<Arc<ApiState>>, Json(request): Json<Import>) -> Response {
    blocking(move || {
        let _guard = IMPORT_LOCK
            .lock()
            .map_err(|_| "skill operation unavailable")?;
        let agent = request
            .agent
            .unwrap_or_else(|| crate::agent::default_chat_agent(&state.home));
        let name = request
            .filename
            .strip_suffix(".md")
            .ok_or("provide a .md file name")?;
        validate_segment(name)?;
        let bytes = request.text.as_bytes();
        if bytes.len() as u64 > aux_runtime::skills::MAX_SKILL_BYTES {
            return Err("skill exceeds 64 KiB".into());
        }
        let skill = parsed(&state.home, &agent, name, bytes)?;
        let gateway =
            kernel_core::verified_home_or_verify(&state.home).map_err(|_| "home unavailable")?;
        let rel = pending(&agent, name);
        gateway
            .create_dir_all(rel.parent().ok_or("invalid pending path")?)
            .map_err(|_| "cannot create pending area")?;
        gateway
            .write_atomic(&rel, bytes, 0o600)
            .map_err(|_| "cannot store pending skill")?;
        Ok(preview(&agent, &skill, bytes))
    })
    .await
}

pub async fn show_pending(
    State(state): State<Arc<ApiState>>,
    RoutePath(name): RoutePath<String>,
    Query(target): Query<Target>,
) -> Response {
    blocking(move || {
        let _guard = IMPORT_LOCK
            .lock()
            .map_err(|_| "skill operation unavailable")?;
        let agent = target
            .agent
            .unwrap_or_else(|| crate::agent::default_chat_agent(&state.home));
        let (bytes, skill) = read_pending(&state.home, &agent, &name)?;
        Ok(preview(&agent, &skill, &bytes))
    })
    .await
}

pub async fn approve(
    State(state): State<Arc<ApiState>>,
    RoutePath(name): RoutePath<String>,
    Json(request): Json<Approve>,
) -> Response {
    blocking(move || {
        let _guard = IMPORT_LOCK
            .lock()
            .map_err(|_| "skill operation unavailable")?;
        let agent = request
            .agent
            .unwrap_or_else(|| crate::agent::default_chat_agent(&state.home));
        let (bytes, skill) = read_pending(&state.home, &agent, &name)?;
        if request.hash != skill.hash {
            return Err("pending skill changed; review it again before approving".into());
        }
        let gateway =
            kernel_core::verified_home_or_verify(&state.home).map_err(|_| "home unavailable")?;
        let dir = PathBuf::from("agents").join(&agent).join("skills");
        gateway
            .create_dir_all(&dir)
            .map_err(|_| "cannot create active skill area")?;
        gateway
            .write_atomic(&dir.join(format!("{name}.md")), &bytes, 0o600)
            .map_err(|_| "cannot activate skill")?;
        gateway
            .remove_file(&pending(&agent, &name))
            .map_err(|_| "skill is active but pending entry could not be removed")?;
        Ok(json!({"name":name,"agent":agent,"status":"active","hash":skill.hash}))
    })
    .await
}
