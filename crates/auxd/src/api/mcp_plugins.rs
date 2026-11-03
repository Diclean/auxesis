//! Safe management API for configured MCP servers.
use super::{error, ApiState};
use axum::{
    body::Bytes,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

const CATALOG: &str = include_str!("../../../../catalog/mcp-servers.toml");
const PACKS: &str = include_str!("../../../../catalog/mcp-packs.toml");

/// The compiled catalog, or — in a `test-util` build only — the absolute
/// fixture path in `AUXESIS_MCP_CATALOG`. A release daemon has no such seam.
fn catalog_text() -> std::borrow::Cow<'static, str> {
    #[cfg(feature = "test-util")]
    if let Some(path) = std::env::var("AUXESIS_MCP_CATALOG")
        .ok()
        .filter(|path| Path::new(path).is_absolute())
    {
        if let Ok(text) = std::fs::read_to_string(path) {
            return text.into();
        }
    }
    CATALOG.into()
}

fn parsed_catalog() -> Option<CatalogFile> {
    toml::from_str(&catalog_text()).ok()
}

#[derive(Debug, Deserialize, Serialize)]
struct CatalogFile {
    /// Stale half of the HTTP pin; bumped whenever any entry changes.
    catalog_version: String,
    server: Vec<CatalogEntry>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct CatalogEntry {
    id: String,
    name: String,
    region: String,
    category: String,
    status: String,
    tier: String,
    auth: String,
    access: String,
    #[serde(default = "default_catalog_class")]
    data_class: String,
    transport: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    repo_url: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    /// Published release; absent means the entry is display-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    /// SHA-256 of the exact binary at `command`; re-checked at spawn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    /// Curated `stdio` command; required for the entry to be installable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command: Option<String>,
    /// Curated `stdio` args paired with `command`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
    /// Applied at install; the confirmation binding locks it at spawn too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions: Option<CatalogPermissions>,
    /// Derived: this entry's pin identity, so an approval can bind to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    catalog_hash: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogPermissions {
    /// The tool-identity set the entry publishes.
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    network: bool,
    /// Env **names** (values come from the protected `.env` only).
    #[serde(default)]
    env: Vec<String>,
}
fn default_catalog_class() -> String {
    "sensitive".to_owned()
}
#[derive(Serialize)]
struct CatalogResponse {
    catalog_version: String,
    servers: Vec<CatalogEntry>,
}
pub(super) async fn catalog() -> Response {
    let Some(parsed) = parsed_catalog() else {
        return internal("catalog_invalid");
    };
    let servers = parsed
        .server
        .into_iter()
        .filter(|e| e.tier == "recommended" || e.tier == "candidate")
        .map(|mut entry| {
            entry.catalog_hash = Some(catalog_entry_hash(&entry));
            entry
        })
        .collect();
    Json(CatalogResponse {
        catalog_version: parsed.catalog_version,
        servers,
    })
    .into_response()
}

/// A stable identity for one catalog entry, over every authored field.
///
/// HTTP has no binary to checksum, so this hash plus `catalog_version` is the
/// pin an approval can bind to.
fn catalog_entry_hash(entry: &CatalogEntry) -> String {
    blake3::hash(serde_json::to_string(entry).unwrap_or_default().as_bytes())
        .to_hex()
        .to_string()
}

/// The complete `stdio` pin an entry must publish to be installable.
struct StdioPin<'a> {
    sha256: &'a str,
    command: &'a str,
    args: &'a [String],
    permissions: &'a CatalogPermissions,
}

/// A `stdio` entry installs only from a complete pin (version, artefact
/// SHA-256, absolute command, args, permissions); anything less is display-only.
fn stdio_pin(entry: &CatalogEntry) -> Option<StdioPin<'_>> {
    if entry.transport != "stdio" || entry.version.as_deref().is_none_or(str::is_empty) {
        return None;
    }
    Some(StdioPin {
        sha256: entry.sha256.as_deref().filter(|s| s.len() == 64)?,
        command: entry
            .command
            .as_deref()
            .filter(|c| Path::new(c).is_absolute())?,
        args: &entry.args,
        permissions: entry.permissions.as_ref()?,
    })
}

#[derive(Debug, Deserialize, Serialize)]
struct PackFile {
    pack: Vec<PackEntry>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
struct PackEntry {
    id: String,
    title_en: String,
    title_fr: String,
    description_en: String,
    description_fr: String,
    servers: Vec<String>,
}
#[derive(Serialize)]
struct PackView {
    id: String,
    title_en: String,
    title_fr: String,
    description_en: String,
    description_fr: String,
    server_count: usize,
    key_required: Vec<String>,
}
pub(super) async fn packs() -> Response {
    let (Ok(packs), Some(catalog)) = (toml::from_str::<PackFile>(PACKS), parsed_catalog()) else {
        return internal("catalog_invalid");
    };
    Json(serde_json::json!({"packs": packs.pack.into_iter().map(|p| {
        // Item 13: a pack never lists a catalog entry whose endpoint is
        // `unverified`; the count and the key hint follow the visible set.
        let visible: Vec<&CatalogEntry> = p.servers.iter().filter_map(|id| {
            catalog.server.iter().find(|e| &e.id == id && catalog_endpoint_usable(e))
        }).collect();
        let key_required: Vec<String> = visible.iter().filter(|e| e.auth != "none").map(|e| e.id.clone()).collect();
        PackView { id:p.id, title_en:p.title_en, title_fr:p.title_fr, description_en:p.description_en, description_fr:p.description_fr, server_count: visible.len(), key_required }
    }).collect::<Vec<_>>() })).into_response()
}

/// Whether a catalog entry's endpoint is verified enough to appear in a pack.
///
/// `endpoint = "unverified"` is the explicit unknown; such an entry is never
/// offered by a pack (item 13).
fn catalog_endpoint_usable(entry: &CatalogEntry) -> bool {
    entry.endpoint.as_deref() != Some("unverified")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackEnableRequest {
    #[serde(default = "default_agent")]
    agent: String,
}
fn default_agent() -> String {
    "main".into()
}
pub(super) async fn enable_pack(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath(pack_id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if body.len() > 1024 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let req: PackEnableRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if !crate::agent::exists(&state.home, &req.agent) {
        return fail(StatusCode::BAD_REQUEST, "agent_not_found");
    }
    let Ok(packs) = toml::from_str::<PackFile>(PACKS) else {
        return internal("catalog_invalid");
    };
    let Some(pack) = packs.pack.into_iter().find(|p| p.id == pack_id) else {
        return fail(StatusCode::NOT_FOUND, "pack_not_found");
    };
    let Some(catalog) = parsed_catalog() else {
        return internal("catalog_invalid");
    };
    let eligible: Vec<_> = pack
        .servers
        .iter()
        .filter_map(|id| {
            catalog
                .server
                .iter()
                .find(|e| {
                    &e.id == id
                        && e.auth == "none"
                        && e.access == "read-only"
                        && e.data_class == "public"
                        && e.transport == "http"
                        && e.endpoint.is_some()
                        && catalog_endpoint_usable(e)
                        && (e.tier == "recommended" || e.tier == "candidate")
                })
                .cloned()
        })
        .collect();
    let prior_config = match read_config(&state.home) {
        Ok(config) => config,
        Err(_) => return internal("mcp_config_invalid"),
    };
    let prior_ids: std::collections::BTreeSet<String> =
        prior_config.server.iter().map(|s| s.id.clone()).collect();
    let prior_enabled: std::collections::BTreeMap<String, bool> = prior_config
        .server
        .iter()
        .map(|s| (s.id.clone(), s.enabled))
        .collect();
    let omitted: Vec<String> = pack
        .servers
        .iter()
        .filter(|id| !eligible.iter().any(|e| &e.id == *id))
        .cloned()
        .collect();
    let to_add = eligible.clone();
    if eligible.is_empty() {
        return fail(StatusCode::BAD_REQUEST, "pack_no_eligible_servers");
    }
    // A pack enable is itself the owner's approval for the curated read-only
    // entries it names; the binding is still keyed by the daemon token.
    let approval_secret = state.token.confirmation_key().to_vec();
    // Review P2: an existing server is only approved when every tool it would
    // mount is one the pack curates as read-only. Discovery before this call
    // is the only trusted source for that set: an unstarted or failed server
    // has none, so a non-empty allowlist can never be proven in-pack and stays
    // pending for the normal install preview.
    let runtime_before = state.mcp.read().unwrap_or_else(|p| p.into_inner()).clone();
    let curated: std::collections::BTreeMap<String, Vec<String>> = eligible
        .iter()
        .map(|entry| {
            (
                entry.id.clone(),
                read_only_tool_names(&runtime_before.descriptors_for(&entry.id)),
            )
        })
        .collect();
    let added = mutate(&state, move |config| {
        for entry in &to_add {
            if let Some(existing) = config.server.iter_mut().find(|s| s.id == entry.id) {
                if !pack_server_matches(existing, entry) {
                    return Err("pack_server_mismatch");
                }
                existing.enabled = true;
                let curated = curated.get(&entry.id).map(Vec::as_slice).unwrap_or(&[]);
                let allowlist_within_pack = existing
                    .agents
                    .values()
                    .flat_map(|tools| tools.iter())
                    .all(|tool| curated.contains(tool));
                if !allowlist_within_pack {
                    // The pack never blesses an allowlist it does not fully
                    // cover, and it also revokes an older approval that covered
                    // more: the server stays `needs_approval` for the owner's
                    // normal install preview. Never a weaker check.
                    existing.approval = None;
                    continue;
                }
                let Some((hash, _pin)) = approval_hash(existing, &approval_secret) else {
                    return Err("approval_unavailable");
                };
                existing.approval = Some(hash);
                continue;
            }
            let mut server = kernel_mcp::McpServerConfig {
                id: entry.id.clone(),
                catalog_id: Some(entry.id.clone()),
                data_class: if entry.data_class == "public" {
                    kernel_mcp::McpDataClass::Public
                } else {
                    kernel_mcp::McpDataClass::Sensitive
                },
                stdio_confirmed: false,
                stdio_confirmation: None,
                approval: None,
                network: false,
                transport: kernel_mcp::McpTransport::Http,
                url: entry.endpoint.clone(),
                command: None,
                args: vec![],
                env: vec![],
                enabled: true,
                agents: Default::default(),
            };
            let Some((hash, _pin)) = approval_hash(&server, &approval_secret) else {
                return Err("approval_unavailable");
            };
            server.approval = Some(hash);
            config.server.push(server);
        }
        Ok(())
    })
    .await;
    if added.status() != StatusCode::OK {
        return added;
    }
    let runtime = state.mcp.read().unwrap_or_else(|p| p.into_inner()).clone();
    let new_ids: std::collections::BTreeSet<String> = eligible
        .iter()
        .map(|e| e.id.clone())
        .filter(|id| !prior_ids.contains(id))
        .collect();
    let mut enabled_tools = 0usize;
    for entry in eligible {
        let names = read_only_tool_names(&runtime.descriptors_for(&entry.id));
        if !names.is_empty() {
            if prior_ids.contains(&entry.id) {
                let existing_tools = prior_config
                    .server
                    .iter()
                    .find(|s| s.id == entry.id)
                    .and_then(|s| s.agents.get(&req.agent));
                enabled_tools += count_pack_tools(&names, existing_tools.map(Vec::as_slice));
                continue;
            }
            enabled_tools += names.len();
            let id = entry.id.clone();
            let agent = req.agent.clone();
            let secret = state.token.confirmation_key().to_vec();
            let response = mutate(&state, move |c| {
                if let Some(s) = c.server.iter_mut().find(|s| s.id == id) {
                    s.agents.insert(agent, names);
                    let Some((hash, _pin)) = approval_hash(s, &secret) else {
                        return Err("approval_unavailable");
                    };
                    s.approval = Some(hash);
                }
                Ok(())
            })
            .await;
            if response.status() != StatusCode::OK {
                return response;
            }
        }
    }
    if enabled_tools == 0 {
        let _ = mutate(&state, move |config| {
            config.server.retain(|server| !new_ids.contains(&server.id));
            for server in &mut config.server {
                if let Some(enabled) = prior_enabled.get(&server.id) {
                    server.enabled = *enabled;
                }
            }
            Ok(())
        })
        .await;
        return fail(StatusCode::BAD_REQUEST, "pack_no_tools_enabled");
    }
    Json(serde_json::json!({"ok":true,"omitted":omitted,"agent":req.agent})).into_response()
}

/// Perform a bounded, read-only MCP handshake and tool discovery. No config or
/// runtime state is changed by this endpoint.
pub(super) async fn test_server(
    State(state): State<std::sync::Arc<ApiState>>,
    body: Bytes,
) -> Response {
    if body.len() > 4096 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestRequest {
        url: String,
    }
    let req: TestRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    // Local checks first: nothing reaches the network for a value that is
    // malformed, secret-looking, plain http, or not a bare public https URL.
    if req.url.len() > kernel_mcp::MAX_MCP_URL_BYTES {
        return fail(StatusCode::BAD_REQUEST, "endpoint_refused");
    }
    if has_secret(&req.url) {
        return secret_config_error();
    }
    let parsed = match reqwest::Url::parse(&req.url) {
        Ok(url) => url,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_url"),
    };
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return fail(StatusCode::BAD_REQUEST, "endpoint_refused");
    }
    let Ok(config) = crate::api::load_config_verified(&state.home) else {
        return fail(StatusCode::SERVICE_UNAVAILABLE, "web_policy_unavailable");
    };
    let gate = kernel_net::WebGate::new(config.web);
    if gate.check(&req.url).is_err() {
        return fail(StatusCode::BAD_REQUEST, "endpoint_refused");
    }
    // Loopback, private, link-local, CGNAT/tailnet and multicast answers are all
    // refused by the shared SSRF guard, on literals and on every DNS answer.
    if kernel_net::check_public_url(&parsed).await.is_err() {
        return fail(StatusCode::BAD_REQUEST, "endpoint_not_public");
    }
    let result = async {
        let transport = pinned_test_transport(&req.url).await.map_err(|_| ())?;
        let client = kernel_mcp::client(
            std::sync::Arc::new(transport),
            kernel_mcp::ServerInfo::default(),
        );
        let info = tokio::time::timeout(Duration::from_secs(12), client.initialize())
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        let page = tokio::time::timeout(Duration::from_secs(18), client.list_tools(None))
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
        Ok::<_, ()>((info, page.tools))
    }
    .await;
    match result {
        Ok((info, tools)) => {
            #[derive(Serialize)]
            struct TestTool {
                name: String,
                risk: &'static str,
            }
            #[derive(Serialize)]
            struct TestResponse {
                name: String,
                tools: Vec<TestTool>,
                digest: String,
            }
            let name = kernel_mcp::sanitize_untrusted(&info.name, 256);
            let digest = mcp_test_digest(
                &req.url,
                &tools.iter().map(|t| t.name.to_string()).collect::<Vec<_>>(),
            );
            Json(TestResponse {
                name,
                digest,
                tools: tools
                    .into_iter()
                    .map(|tool| TestTool {
                        name: kernel_mcp::sanitize_untrusted(&tool.name, 128),
                        risk: "high",
                    })
                    .collect(),
            })
            .into_response()
        }
        Err(()) => fail(StatusCode::BAD_GATEWAY, "connection_test_failed"),
    }
}

/// Build the pinned, SSRF-checked transport `test_server` uses (item 11).
///
/// Kept in one place so a test can prove the checked constructor is the one
/// wired in: `HttpTransport::new` would accept a private host, `new_checked`
/// resolves and refuses it before any connection.
async fn pinned_test_transport(url: &str) -> Result<kernel_mcp::HttpTransport, ()> {
    kernel_mcp::HttpTransport::new_checked(
        url,
        reqwest::header::HeaderMap::new(),
        kernel_mcp::Limits::default(),
    )
    .await
    .map_err(|_| ())
}

/// Parse common Claude Desktop/Cursor snippets without persisting anything.
pub(super) async fn import_servers(
    State(state): State<std::sync::Arc<ApiState>>,
    body: Bytes,
) -> Response {
    if body.len() > 64 * 1024 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let value: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_import"),
    };
    fn depth(value: &serde_json::Value, level: usize) -> bool {
        if level > 32 {
            return false;
        }
        match value {
            serde_json::Value::Array(a) => a.iter().all(|v| depth(v, level + 1)),
            serde_json::Value::Object(o) => o.values().all(|v| depth(v, level + 1)),
            _ => true,
        }
    }
    if !depth(&value, 0) {
        return fail(StatusCode::BAD_REQUEST, "import_too_deep");
    }
    let Some(servers) = value
        .get("mcpServers")
        .and_then(serde_json::Value::as_object)
    else {
        return fail(StatusCode::BAD_REQUEST, "invalid_import");
    };
    if servers.len() > 32 {
        return fail(StatusCode::BAD_REQUEST, "too_many_servers");
    }
    #[derive(Serialize)]
    struct Preview {
        id: String,
        transport: &'static str,
        url: Option<String>,
        command: Option<String>,
        args: Vec<String>,
        env: Vec<String>,
        enabled: bool,
        data_class: String,
        stdio_confirmed: bool,
    }
    let Ok(config) = crate::api::load_config_verified(&state.home) else {
        return fail(StatusCode::SERVICE_UNAVAILABLE, "web_policy_unavailable");
    };
    let gate = kernel_net::WebGate::new(config.web);
    let mut previews = Vec::new();
    for (id, item) in servers {
        if !valid_import_id(id) {
            return fail(StatusCode::BAD_REQUEST, "invalid_server_id");
        }
        if let Some(url) = item.get("url").and_then(serde_json::Value::as_str) {
            if has_secret(url) {
                return secret_config_error();
            }
            if gate.check(url).is_err() {
                return fail(StatusCode::BAD_REQUEST, "endpoint_refused");
            }
            previews.push(Preview {
                id: id.clone(),
                transport: "http",
                url: Some(url.to_owned()),
                command: None,
                args: vec![],
                env: vec![],
                enabled: false,
                data_class: item
                    .get("data_class")
                    .and_then(serde_json::Value::as_str)
                    .filter(|v| *v == "public")
                    .unwrap_or("sensitive")
                    .to_owned(),
                stdio_confirmed: false,
            });
            continue;
        }
        let Some(command) = item.get("command").and_then(serde_json::Value::as_str) else {
            return fail(StatusCode::BAD_REQUEST, "invalid_server");
        };
        let args = match item.get("args").and_then(serde_json::Value::as_array) {
            Some(a) if a.len() <= 128 => a
                .iter()
                .map(|v| {
                    v.as_str()
                        .filter(|s| s.len() <= 4096)
                        .map(str::to_owned)
                        .ok_or(())
                })
                .collect::<Result<Vec<_>, _>>(),
            None => Ok(vec![]),
            _ => Err(()),
        };
        let Ok(args) = args else {
            return fail(StatusCode::BAD_REQUEST, "invalid_server");
        };
        if has_secret(command) || args.iter().any(|a| has_secret(a)) {
            return secret_config_error();
        }
        // Item 2: a wrapper or shell `argv[0]` is refused outright, before the
        // command is ever resolved or stored. No warning-only path.
        if kernel_mcp::wrapper_launcher_label(command).is_some() {
            return fail(StatusCode::BAD_REQUEST, "wrapper_launcher");
        }
        if args.iter().any(|a| shell_syntax(a)) {
            return fail(StatusCode::BAD_REQUEST, "command_refused");
        }
        // An import never sets the confirmation flag: the owner confirms the
        // resolved command through the confirm endpoint.
        let resolved = if Path::new(command).is_absolute() {
            command.to_owned()
        } else {
            if !matches!(command, "npx" | "uvx" | "pipx" | "bunx" | "docker") {
                return fail(StatusCode::BAD_REQUEST, "command_refused");
            }
            if command == "docker" && args.first().map(String::as_str) != Some("run") {
                return fail(StatusCode::BAD_REQUEST, "command_refused");
            }
            let found = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
                .iter()
                .map(|dir| Path::new(dir).join(command))
                .find(|p| p.is_file());
            let Some(path) = found else {
                return fail(StatusCode::BAD_REQUEST, "command_not_found");
            };
            path.to_string_lossy().into_owned()
        };
        if let Err(refusal) = kernel_mcp::evaluate_stdio_policy(id, &resolved, &args, false) {
            return fail(StatusCode::BAD_REQUEST, refusal_static_code(refusal.label));
        }
        let env_obj = item.get("env").and_then(serde_json::Value::as_object);
        let mut env = Vec::new();
        if let Some(values) = env_obj {
            for key in values.keys() {
                if !valid_import_env(key) {
                    return fail(StatusCode::BAD_REQUEST, "invalid_env_name");
                }
                env.push(key.clone());
            }
        }
        previews.push(Preview {
            id: id.clone(),
            transport: "stdio",
            url: None,
            command: Some(resolved),
            args,
            env,
            enabled: false,
            data_class: item
                .get("data_class")
                .and_then(serde_json::Value::as_str)
                .filter(|v| *v == "public")
                .unwrap_or("sensitive")
                .to_owned(),
            stdio_confirmed: false,
        });
    }
    #[derive(Serialize)]
    struct ImportResponse {
        servers: Vec<Preview>,
        /// Stable warning **codes**, exactly like the confirmation preview: the
        /// Mac app translates them, the daemon never ships English copy.
        warnings: Vec<&'static str>,
    }
    let dropped_headers = servers
        .values()
        .any(|server| server.get("headers").is_some());
    let warnings = import_warnings(dropped_headers);
    Json(ImportResponse {
        servers: previews,
        warnings,
    })
    .into_response()
}
fn valid_import_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn valid_import_env(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && kernel_mcp::stdio::env_key_declared(name)
}
fn shell_syntax(value: &str) -> bool {
    value.contains(';')
        || value.contains("&&")
        || value.contains('|')
        || value.contains("$(")
        || value == "sh"
        || value == "bash"
        || value == "-c"
}
#[derive(Serialize)]
struct ServerList {
    servers: Vec<ServerView>,
}
#[derive(Serialize)]
struct ServerView {
    id: String,
    enabled: bool,
    state: String,
    reason: Option<&'static str>,
    transport: String,
    auth: String,
    data_class: String,
    high_risk: Option<&'static str>,
    tools: Vec<ToolView>,
    agents: std::collections::BTreeMap<String, Vec<String>>,
}
#[derive(Serialize)]
struct ToolView {
    name: String,
    risk: String,
}
pub(super) async fn servers(State(state): State<std::sync::Arc<ApiState>>) -> Response {
    let config = match read_config(&state.home) {
        Ok(v) => v,
        Err(_) => return internal("mcp_config_invalid"),
    };
    let runtime = state.mcp.read().unwrap_or_else(|p| p.into_inner()).clone();
    let mut views: Vec<ServerView> = config
        .server
        .iter()
        .map(|server| {
            let status = runtime.statuses().iter().find(|s| s.id == server.id);
            // Installed from a complete pin, still off: the add verified the
            // SHA-256, and the approve binds it before any spawn.
            let pinned = server.transport == kernel_mcp::McpTransport::Stdio
                && catalog_match(server) == CatalogMatch::Exact;
            let state = if pinned && !server.enabled {
                "pinned".to_owned()
            } else {
                status
                    .map(|s| s.state.as_str())
                    .unwrap_or(if server.enabled { "error" } else { "disabled" })
                    .to_owned()
            };
            let descriptors = runtime.descriptors_for(&server.id);
            let tools = descriptors
                .iter()
                .map(|d| ToolView {
                    name: d.remote_name.clone(),
                    risk: d.risk().to_string(),
                })
                .collect();
            let auth = catalog_entry(server.catalog_id.as_deref())
                .map(|e| e.auth)
                .unwrap_or_else(|| {
                    if server.env.is_empty() {
                        "none".into()
                    } else {
                        "key-required".into()
                    }
                });
            ServerView {
                id: server.id.clone(),
                enabled: server.enabled,
                state,
                reason: status.and_then(|s| s.reason),
                transport: server.transport.as_str().to_owned(),
                auth,
                data_class: match server.data_class {
                    kernel_mcp::McpDataClass::Public => "public",
                    kernel_mcp::McpDataClass::Sensitive => "sensitive",
                }
                .to_owned(),
                high_risk: (server.transport == kernel_mcp::McpTransport::Stdio)
                    .then(|| {
                        server
                            .command
                            .as_deref()
                            .and_then(|c| kernel_mcp::stdio_risk_label(c, &server.args))
                    })
                    .flatten(),
                tools,
                agents: server.agents.clone(),
            }
        })
        .collect();
    // Item 6: entries that failed to deserialize are listed as quarantined so
    // the GET returns 200 with a reason instead of dropping every server.
    for quarantined in &config.quarantined {
        views.push(ServerView {
            id: quarantined.id.clone(),
            enabled: false,
            state: "quarantined".to_owned(),
            reason: Some(quarantined.reason),
            transport: quarantined
                .transport
                .map(|transport| transport.as_str().to_owned())
                .unwrap_or_else(|| "unknown".to_owned()),
            auth: "none".to_owned(),
            data_class: "sensitive".to_owned(),
            high_risk: None,
            tools: Vec::new(),
            agents: std::collections::BTreeMap::new(),
        });
    }
    Json(ServerList { servers: views }).into_response()
}
fn catalog_entry(id: Option<&str>) -> Option<CatalogEntry> {
    parsed_catalog()?
        .server
        .into_iter()
        .find(|e| Some(e.id.as_str()) == id && (e.tier == "recommended" || e.tier == "candidate"))
}
fn pack_server_matches(server: &kernel_mcp::McpServerConfig, entry: &CatalogEntry) -> bool {
    // Every install-relevant field must be the catalogue's, not an override:
    // a pack only ever enables the curated read-only launch it names.
    server.catalog_id.as_deref() == Some(entry.id.as_str())
        && server.transport == kernel_mcp::McpTransport::Http
        && server.url.as_deref() == entry.endpoint.as_deref()
        && server.command.is_none()
        && server.args.is_empty()
        && server.env.is_empty()
        && !server.network
        && server.data_class == kernel_mcp::McpDataClass::Public
}

/// The curated read-only tools of one server: discovered low-risk tools the
/// server itself tags read-only and does not tag as mutating. The pack may
/// approve nothing outside this set.
fn read_only_tool_names(descriptors: &[&kernel_mcp::McpToolDescriptor]) -> Vec<String> {
    descriptors
        .iter()
        .filter(|descriptor| {
            descriptor.risk() == kernel_broker::Risk::Low
                && descriptor.tags.contains(&kernel_mcp::McpTag::ReadOnlyHint)
                && !descriptor.tags.iter().any(|tag| {
                    matches!(
                        tag,
                        kernel_mcp::McpTag::CreateHint
                            | kernel_mcp::McpTag::UpdateHint
                            | kernel_mcp::McpTag::DestructiveHint
                    )
                })
        })
        .map(|descriptor| descriptor.remote_name.clone())
        .collect()
}
fn count_pack_tools(names: &[String], existing_allowlist: Option<&[String]>) -> usize {
    match existing_allowlist {
        Some(allowed) => names.iter().filter(|name| allowed.contains(name)).count(),
        None => 0,
    }
}
fn is_catalog_id(id: &str) -> bool {
    parsed_catalog().is_some_and(|catalog| catalog.server.iter().any(|entry| entry.id == id))
}

/// How a config entry's `catalog_id` relates to the curated catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatalogMatch {
    /// Exact match: the http endpoint or the published `stdio` launch. A
    /// curated server needs no per-server confirmation.
    Exact,
    /// The catalog entry exists but publishes no full `stdio` pin (or an
    /// endpoint left `unverified`).
    Unverifiable,
    /// The entry names a catalog id whose transport, endpoint or launch differs.
    Mismatch,
    /// No catalog entry carries that id.
    Unknown,
}

/// Match one configured server against its claimed catalog entry.
pub(crate) fn catalog_match(server: &kernel_mcp::McpServerConfig) -> CatalogMatch {
    let Some(id) = server.catalog_id.as_deref() else {
        return CatalogMatch::Unknown;
    };
    let Some(catalog) = parsed_catalog() else {
        return CatalogMatch::Unknown;
    };
    let Some(entry) = catalog.server.iter().find(|entry| entry.id == id) else {
        return CatalogMatch::Unknown;
    };
    if entry.transport != server.transport.as_str() {
        return CatalogMatch::Mismatch;
    }
    match server.transport {
        kernel_mcp::McpTransport::Http => {
            let endpoint = entry
                .endpoint
                .as_deref()
                .filter(|value| *value != "unverified" && value.starts_with("https://"));
            match endpoint {
                Some(endpoint) if Some(endpoint) == server.url.as_deref() => CatalogMatch::Exact,
                _ => CatalogMatch::Mismatch,
            }
        }
        // Item 7: a `stdio` server that claims a catalog id must match the
        // entry's command and args, and the entry must carry a full pin. The
        // kernel's confirmation binding, minted at install, locks the rest of
        // the launch (env names, network, data class, binary SHA-256) and is
        // re-checked at spawn, so a hand-widened config never spawns.
        kernel_mcp::McpTransport::Stdio => match stdio_pin(entry) {
            Some(pin)
                if Some(pin.command) == server.command.as_deref()
                    && pin.args == server.args.as_slice() =>
            {
                CatalogMatch::Exact
            }
            Some(_) => CatalogMatch::Mismatch,
            None => CatalogMatch::Unverifiable,
        },
    }
}

/// The daemon's per-server policy: quarantine or allow, before any transport.
///
/// Order matters: a hard refusal (item 2) or a catalog mismatch (item 7) wins;
/// then an uncurated `stdio` server needs the owner's confirmation (item 1) and
/// is reported `needs_confirmation`; finally the M6-2 install approval gates
/// every enabled server. `secret` is the daemon's API token: a confirmation or
/// approval is only honoured when it was minted with that token, so a
/// hand-edited config file cannot forge one. When the token cannot be read
/// (`None`) nothing is confirmed (item 5, fail closed).
pub(crate) fn server_policy_refusal(
    server: &kernel_mcp::McpServerConfig,
    secret: Option<&[u8]>,
) -> Option<kernel_mcp::McpServerRefusal> {
    if let Err(refusal) = server.check() {
        return Some(kernel_mcp::McpServerRefusal::quarantined(refusal.label));
    }
    if let Some(_catalog_id) = server.catalog_id.as_deref() {
        match catalog_match(server) {
            CatalogMatch::Exact => {}
            CatalogMatch::Mismatch => {
                return Some(kernel_mcp::McpServerRefusal::quarantined(
                    "catalog_mismatch",
                ))
            }
            CatalogMatch::Unknown => {
                return Some(kernel_mcp::McpServerRefusal::quarantined(
                    "unknown_catalog_id",
                ))
            }
            CatalogMatch::Unverifiable => {
                return Some(kernel_mcp::McpServerRefusal::quarantined(
                    "catalog_stdio_unverifiable",
                ))
            }
        }
    } else if server.transport == kernel_mcp::McpTransport::Stdio
        && !secret.is_some_and(|secret| server.stdio_is_confirmed_with(secret))
    {
        // The old stdio gate stays first: an unconfirmed server reports
        // `needs_confirmation`, as it did before M6-2. A stored confirmation
        // that no longer matches (the digest hardening invalidated every
        // pre-r1 record) is reported as `needs_approval`: the one-approval path
        // re-mints both records. Both states refuse to spawn (fail closed).
        if server.stdio_confirmation.is_some() {
            return Some(kernel_mcp::McpServerRefusal::needs_approval(
                "approval_required",
            ));
        }
        return Some(kernel_mcp::McpServerRefusal::needs_confirmation(
            "stdio_confirmation_required",
        ));
    }
    if server.is_install_approved(secret, catalog_pin(server).as_deref()) {
        None
    } else {
        Some(kernel_mcp::McpServerRefusal::needs_approval(
            "approval_required",
        ))
    }
}

/// The preview shown before a stdio server is confirmed: the exact resolved
/// command, its args, the declared env **names**, the network flag, the data
/// class, the SHA-256 of the binary and the hash the confirmation is bound to.
#[derive(Serialize)]
struct ConfirmationPreview {
    id: String,
    command: String,
    args: Vec<String>,
    env: Vec<String>,
    network: bool,
    data_class: String,
    binary_hash: String,
    high_risk: Option<&'static str>,
    /// Item 2 (downgraded P3): always set for a **non-catalog** stdio server,
    /// whatever `high_risk` says, so a missing heuristic warning is never
    /// reassuring. Stable code the Mac app translates.
    unverified_program: Option<&'static str>,
    hash: String,
    warning: &'static str,
}

/// A stable warning **code**, not a sentence: the Mac app translates it into
/// the system language (EN/FR). The daemon never ships English copy.
const CONFIRMATION_WARNING_CODE: &str = "mcp_stdio_confirmation";
/// The generic warning every non-catalog stdio server carries (item 2).
const UNVERIFIED_PROGRAM_WARNING_CODE: &str = "stdio_unverified_program";
/// M6-2: the install preview is an approval, not a connection test.
const APPROVAL_WARNING_CODE: &str = "mcp_install_approval";

/// One tool in the install preview. `risk`/`access` are derived from the
/// curated catalog when there is one; an uncatalogued server is always high
/// risk because its own annotations are untrusted.
#[derive(Serialize)]
struct ApprovalTool {
    name: String,
    risk: &'static str,
    access: &'static str,
}

/// What the owner sees before one approval: what the server can call, where it
/// can connect, which env **names** it needs, its data class and catalog pin.
#[derive(Serialize)]
struct ApprovalPreview {
    id: String,
    transport: String,
    enabled: bool,
    network: bool,
    env: Vec<String>,
    data_class: String,
    endpoint: Option<String>,
    command: Option<String>,
    args: Vec<String>,
    tools: Vec<ApprovalTool>,
    catalog_version: Option<String>,
    catalog_pin: Option<String>,
    hash: String,
    warning: &'static str,
}

/// The daemon's approval digest for one configured server, or `None` when the
/// token is unavailable (fail closed).
fn approval_hash(
    server: &kernel_mcp::McpServerConfig,
    secret: &[u8],
) -> Option<(String, Option<String>)> {
    let pin = catalog_pin(server);
    let hash = server.approval_binding(secret, pin.as_deref())?;
    Some((hash, pin))
}

/// The curated catalog hash for a server's claimed entry, if it has one.
pub(crate) fn catalog_pin(server: &kernel_mcp::McpServerConfig) -> Option<String> {
    catalog_entry(server.catalog_id.as_deref()).map(|entry| catalog_entry_hash(&entry))
}

/// The install preview for one configured server.
fn approval_preview(
    server: &kernel_mcp::McpServerConfig,
    secret: &[u8],
) -> Option<ApprovalPreview> {
    let (hash, catalog_pin) = approval_hash(server, secret)?;
    let entry = catalog_entry(server.catalog_id.as_deref());
    let (risk, access) = match entry.as_ref().map(|entry| entry.access.as_str()) {
        Some("read-only") => ("low", "read"),
        _ => ("high", "write"),
    };
    let names: std::collections::BTreeSet<String> = server
        .agents
        .values()
        .flat_map(|tools| tools.iter().cloned())
        .collect();
    Some(ApprovalPreview {
        id: server.id.clone(),
        transport: server.transport.as_str().to_owned(),
        enabled: server.enabled,
        network: server.network,
        env: server.env.clone(),
        data_class: match server.data_class {
            kernel_mcp::McpDataClass::Public => "public",
            kernel_mcp::McpDataClass::Sensitive => "sensitive",
        }
        .to_owned(),
        endpoint: server.url.clone(),
        command: server.command.clone(),
        args: server.args.clone(),
        tools: names
            .into_iter()
            .map(|name| ApprovalTool { name, risk, access })
            .collect(),
        catalog_version: entry
            .as_ref()
            .and_then(|_| parsed_catalog().map(|catalog| catalog.catalog_version)),
        catalog_pin,
        hash,
        warning: APPROVAL_WARNING_CODE,
    })
}

/// `GET /v1/mcp/servers/{id}/approval`: the same preview `POST /servers`
/// returns, for a server already in `mcp.toml` (a hand-edited entry migrates
/// by approving this preview once).
pub(super) async fn server_approval(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let config = match read_config(&state.home) {
        Ok(v) => v,
        Err(_) => return internal("mcp_config_invalid"),
    };
    let Some(server) = config.server.iter().find(|server| server.id == id) else {
        return fail(StatusCode::NOT_FOUND, "server_not_found");
    };
    match approval_preview(server, state.token.confirmation_key()) {
        Some(preview) => Json(preview).into_response(),
        None => internal("confirmation_unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveRequest {
    hash: String,
    #[serde(default = "default_agent")]
    agent: String,
}

/// `POST /v1/mcp/servers/{id}/approve`: the one owner action that enables a
/// server, its agent allowlist and the `mcp.approve` ledger row.
///
/// The supplied hash must equal the current preview binding; a config edit
/// between preview and approve returns `409 stale_confirmation`. A repeat with
/// the same hash is a no-op, so it cannot start a second child.
pub(super) async fn approve_server(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if body.len() > 4096 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let req: ApproveRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if !valid_agent_name(&req.agent) {
        return fail(StatusCode::BAD_REQUEST, "invalid_agent");
    }
    if !crate::agent::exists(&state.home, &req.agent) {
        return fail(StatusCode::BAD_REQUEST, "agent_not_found");
    }
    let ledger_id = id.clone();
    let ledger_agent = req.agent.clone();
    let ledger_hash = req.hash.clone();
    let secret = state.token.confirmation_key().to_vec();
    // Review P3: the audit row is written inside the same commit path, before
    // `mcp.toml` is rewritten and before `mutate` starts the runtime. A store
    // that cannot record the approval fails the call (500 `ledger_failed`) and
    // leaves the server disabled.
    mutate_audited(
        &state,
        Some((
            aux_runtime::extensions::ledger::MCP_APPROVE,
            serde_json::json!({
                "server": ledger_id,
                "agent": ledger_agent,
                "binding": ledger_hash,
            }),
        )),
        move |config| {
            let Some(server) = config.server.iter_mut().find(|server| server.id == id) else {
                return Err("server_not_found");
            };
            let Some((binding, _pin)) = approval_hash(server, &secret) else {
                return Err("approval_unavailable");
            };
            if binding != req.hash {
                // Distinct from the legacy confirm's 400: an approve replay after
                // a config edit is a 409 `stale_confirmation` (mapped below).
                return Err("stale_approval");
            }
            // M6-2: a catalog stdio binary can be swapped between the preview and
            // this call. Re-run the catalog checks and bind the PUBLISHED sha —
            // never a fresh read — so the kernel's spawn-time re-hash only passes
            // for exactly the curated file.
            let mut confirmation = None;
            if server.transport == kernel_mcp::McpTransport::Stdio {
                if let Some(entry) = catalog_entry(server.catalog_id.as_deref()) {
                    if catalog_match(server) != CatalogMatch::Exact {
                        return Err("catalog_mismatch");
                    }
                    let Some(pin) = stdio_pin(&entry) else {
                        return Err("catalog_stdio_unverifiable");
                    };
                    if catalog_binary_is_mutable(Path::new(pin.command)) {
                        return Err("binary_path_mutable");
                    }
                    if !kernel_mcp::binary_sha256(Path::new(pin.command))
                        .eq_ignore_ascii_case(pin.sha256)
                    {
                        return Err("checksum_mismatch");
                    }
                    confirmation = server.confirmation_binding_for_sha(&secret, pin.sha256);
                } else {
                    confirmation = server.confirmation_binding(&secret);
                }
                if confirmation.is_none() {
                    return Err("approval_unavailable");
                }
            }
            // Idempotent by construction: the same binding rewrites the same
            // fields, and `mutate` sees an unchanged config and starts no child
            // — so a replay writes no second ledger row either.
            server.enabled = true;
            server.approval = Some(binding);
            if let Some(hash) = confirmation {
                server.stdio_confirmed = true;
                server.stdio_confirmation = Some(hash);
            }
            Ok(())
        },
    )
    .await
}

fn valid_agent_name(agent: &str) -> bool {
    (1..=64).contains(&agent.len())
        && agent
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

pub(super) async fn confirmation_preview(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let config = match read_config(&state.home) {
        Ok(v) => v,
        Err(_) => return internal("mcp_config_invalid"),
    };
    let Some(server) = config.server.iter().find(|server| server.id == id) else {
        return fail(StatusCode::NOT_FOUND, "server_not_found");
    };
    if server.transport != kernel_mcp::McpTransport::Stdio {
        return fail(StatusCode::BAD_REQUEST, "not_stdio");
    }
    // Review P2: a catalog stdio entry has exactly one install path,
    // `POST .../approve`, which re-runs the published-SHA checks and binds the
    // verified checksum. The legacy route must not preview a re-read file.
    if server.catalog_id.is_some() {
        return fail(StatusCode::CONFLICT, "use_approve");
    }
    let Some(command) = server.command.clone() else {
        return fail(StatusCode::BAD_REQUEST, "invalid_server");
    };
    let high_risk = kernel_mcp::stdio_risk_label(&command, &server.args);
    let Some(hash) = server.confirmation_binding(state.token.confirmation_key()) else {
        return internal("confirmation_unavailable");
    };
    let binary_hash = kernel_mcp::binary_sha256(Path::new(&command));
    Json(ConfirmationPreview {
        id: server.id.clone(),
        command,
        args: server.args.clone(),
        env: server.env.clone(),
        network: server.network,
        data_class: match server.data_class {
            kernel_mcp::McpDataClass::Public => "public",
            kernel_mcp::McpDataClass::Sensitive => "sensitive",
        }
        .to_owned(),
        binary_hash,
        high_risk,
        unverified_program: server
            .catalog_id
            .is_none()
            .then_some(UNVERIFIED_PROGRAM_WARNING_CODE),
        hash,
        warning: CONFIRMATION_WARNING_CODE,
    })
    .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmRequest {
    hash: String,
}

/// The only writer of `stdio_confirmed` / `stdio_confirmation`.
///
/// The supplied hash must equal the hash of the server's current launch, so a
/// client cannot confirm one command and have another run.
pub(super) async fn confirm_server(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if body.len() > 4096 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let req: ConfirmRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let secret = state.token.confirmation_key().to_vec();
    mutate(&state, move |config| {
        let Some(server) = config.server.iter_mut().find(|server| server.id == id) else {
            return Err("server_not_found");
        };
        if server.transport != kernel_mcp::McpTransport::Stdio {
            return Err("not_stdio");
        }
        // Review P2: never confirm a catalog stdio entry from whatever bytes
        // currently sit at `command`. `/approve` re-checks `binary_path_mutable`
        // and the published SHA, and binds that SHA; re-reading the file here
        // would let a swapped catalog binary be confirmed as if curated.
        if server.catalog_id.is_some() {
            return Err("use_approve");
        }
        let Some(hash) = server.confirmation_binding(&secret) else {
            return Err("invalid_server");
        };
        if hash != req.hash {
            return Err("stale_confirmation");
        }
        server.stdio_confirmed = true;
        server.stdio_confirmation = Some(hash);
        // The legacy confirm is also the owner's approval of this preview:
        // record it so an enabled server is not left `needs_approval`.
        if let Some((approval, _pin)) = approval_hash(server, &secret) {
            server.approval = Some(approval);
        }
        Ok(())
    })
    .await
}

/// Clear a confirmation (used when the owner edits or disables the server).
pub(super) async fn revoke_confirmation(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    mutate(&state, move |config| {
        let Some(server) = config.server.iter_mut().find(|server| server.id == id) else {
            return Err("server_not_found");
        };
        server.stdio_confirmed = false;
        server.stdio_confirmation = None;
        Ok(())
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AddRequest {
    id: String,
    #[serde(default)]
    catalog_id: Option<String>,
    #[serde(default)]
    transport: Option<kernel_mcp::McpTransport>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    data_class: kernel_mcp::McpDataClass,
    #[serde(default)]
    network: bool,
    /// Accepted for backwards compatibility and **ignored**: only the confirm
    /// or approve endpoint sets `stdio_confirmed`, bound to the launch hash.
    #[serde(default)]
    #[allow(dead_code)]
    stdio_confirmed: bool,
    #[serde(default)]
    test_digest: Option<String>,
    /// Agent the one-approval install is staged for (default `main`). The
    /// preview hash binds this allowlist; `approve` must name the same agent.
    #[serde(default = "default_agent")]
    agent: String,
    /// Tools the owner is approving for a non-catalog server. A stdio server
    /// cannot be discovered before approval, so its set is declared here; an
    /// HTTP server uses the tools the connection test discovered.
    #[serde(default)]
    tools: Vec<String>,
}

#[derive(Serialize)]
struct AddResponse {
    ok: bool,
    #[serde(flatten)]
    preview: ApprovalPreview,
}

fn valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}
pub(super) async fn add_server(
    State(state): State<std::sync::Arc<ApiState>>,
    body: Bytes,
) -> Response {
    if body.len() > 16 * 1024 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let req: AddRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let config_id = req.catalog_id.clone();
    let data_class = req.data_class;
    let agent = req.agent.clone();
    if !valid_agent_name(&agent) {
        return fail(StatusCode::BAD_REQUEST, "invalid_agent");
    }
    if req.tools.len() > 256 || req.tools.iter().any(|name| !valid_tool_name(name)) {
        return fail(StatusCode::BAD_REQUEST, "invalid_tools");
    }
    let requested_tools = req.tools.clone();
    let mut server = if let Some(cid) = req.catalog_id {
        let Some(entry) = catalog_entry(Some(&cid)) else {
            return fail(StatusCode::BAD_REQUEST, "unknown_catalog_entry");
        };
        let entry_class = if entry.data_class == "public" {
            kernel_mcp::McpDataClass::Public
        } else {
            kernel_mcp::McpDataClass::Sensitive
        };
        if entry.transport == "http" {
            let url = entry.endpoint.filter(|_| entry.transport == "http");
            let Some(url) = url else {
                return fail(StatusCode::BAD_REQUEST, "catalog_transport_unavailable");
            };
            kernel_mcp::McpServerConfig {
                id: req.id,
                catalog_id: Some(cid),
                data_class: entry_class,
                stdio_confirmed: false,
                stdio_confirmation: None,
                approval: None,
                network: false,
                transport: kernel_mcp::McpTransport::Http,
                url: Some(url),
                command: None,
                args: vec![],
                env: vec![],
                enabled: false,
                agents: Default::default(),
            }
        } else if let Some(pin) = stdio_pin(&entry) {
            // Installed from the pin only: request overrides are refused.
            let overrides = req.url.is_some()
                || req
                    .command
                    .as_deref()
                    .is_some_and(|c| Some(c) != entry.command.as_deref())
                || (!req.args.is_empty() && req.args != entry.args)
                || req
                    .transport
                    .is_some_and(|t| t != kernel_mcp::McpTransport::Stdio)
                || (!req.env.is_empty() && req.env != pin.permissions.env);
            if overrides {
                return fail(StatusCode::BAD_REQUEST, "catalog_mismatch");
            }
            if let Err(refusal) = kernel_mcp::evaluate_stdio_policy(
                &req.id,
                pin.command,
                pin.args,
                pin.permissions.network,
            ) {
                return fail(StatusCode::BAD_REQUEST, refusal_static_code(refusal.label));
            }
            // Verify the artefact before any write: a mismatch writes no
            // `mcp.toml` and starts no child.
            if catalog_binary_is_mutable(Path::new(pin.command)) {
                return fail(StatusCode::BAD_REQUEST, "binary_path_mutable");
            }
            if !kernel_mcp::binary_sha256(Path::new(pin.command)).eq_ignore_ascii_case(pin.sha256) {
                return fail(StatusCode::BAD_REQUEST, "checksum_mismatch");
            }
            kernel_mcp::McpServerConfig {
                id: req.id,
                catalog_id: Some(cid),
                data_class: entry_class,
                // Never from the request; the approve binds the catalog pin.
                stdio_confirmed: false,
                stdio_confirmation: None,
                approval: None,
                network: pin.permissions.network,
                transport: kernel_mcp::McpTransport::Stdio,
                url: None,
                command: Some(pin.command.to_owned()),
                args: pin.args.to_vec(),
                env: pin.permissions.env.clone(),
                enabled: false,
                agents: Default::default(),
            }
        } else {
            return fail(StatusCode::BAD_REQUEST, "catalog_transport_unavailable");
        }
    } else {
        kernel_mcp::McpServerConfig {
            id: req.id,
            catalog_id: None,
            data_class,
            // Never from the request: only the confirm endpoint sets these.
            stdio_confirmed: false,
            stdio_confirmation: None,
            approval: None,
            network: req.network,
            transport: req.transport.unwrap_or(kernel_mcp::McpTransport::Http),
            url: req.url,
            command: req.command,
            args: req.args,
            env: req.env,
            enabled: false,
            agents: Default::default(),
        }
    };
    if server.id.is_empty()
        || server.id.len() > 32
        || !server
            .id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return fail(StatusCode::BAD_REQUEST, "invalid_server_id");
    }
    if server
        .env
        .iter()
        .any(|name| !kernel_mcp::stdio::env_key_declared(name))
    {
        return fail(StatusCode::BAD_REQUEST, "invalid_env_name");
    }
    if config_id.is_none() && is_catalog_id(&server.id) {
        return fail(StatusCode::BAD_REQUEST, "catalog_id_reserved");
    }
    if config_id.is_none() && server.transport == kernel_mcp::McpTransport::Stdio {
        // Only the hard refusals are errors here. A shell/wrapper/runner class
        // is stored as a high-risk, needs-confirmation server: the security
        // boundary is the owner's confirmation below, not this denylist.
        let command = server.command.as_deref().unwrap_or("");
        if let Err(refusal) =
            kernel_mcp::evaluate_stdio_policy(&server.id, command, &server.args, server.network)
        {
            return fail(StatusCode::BAD_REQUEST, refusal_static_code(refusal.label));
        }
    }
    if let Ok(config) = read_config(&state.home) {
        if config.server.iter().any(|s| s.id == server.id) {
            return fail(StatusCode::CONFLICT, "server_exists");
        }
        // Item 1 (keep): a quarantined entry already owns this id. Refuse
        // rather than creating a twin the owner could never promote or delete
        // unambiguously. The owner deletes or fixes the quarantined entry first.
        if config.quarantined.iter().any(|entry| entry.id == server.id) {
            return fail(StatusCode::CONFLICT, "id_taken_by_quarantined_entry");
        }
    }
    if config_id.is_none() && server.transport == kernel_mcp::McpTransport::Http {
        let Some(url) = server.url.as_deref() else {
            return fail(StatusCode::BAD_REQUEST, "invalid_server");
        };
        if has_secret(url) {
            return secret_config_error();
        }
        let digest = req.test_digest.as_deref();
        let Some(digest) = digest else {
            return fail(StatusCode::BAD_REQUEST, "connection_test_required");
        };
        let test_body = serde_json::to_vec(&serde_json::json!({"url": url})).unwrap_or_default();
        let tested =
            test_server(State(std::sync::Arc::clone(&state)), Bytes::from(test_body)).await;
        if tested.status() != StatusCode::OK {
            return fail(StatusCode::BAD_GATEWAY, "connection_test_failed");
        }
        let tested_body = match axum::body::to_bytes(tested.into_body(), 64 * 1024).await {
            Ok(bytes) => bytes,
            Err(_) => return internal("connection_test_failed"),
        };
        let tested_json = serde_json::from_slice::<serde_json::Value>(&tested_body).ok();
        let current_digest = tested_json.as_ref().and_then(|v| {
            v.get("digest")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
        if current_digest.as_deref() != Some(digest) {
            return fail(StatusCode::CONFLICT, "stale_test_result");
        }
        let discovered: Vec<String> = tested_json
            .as_ref()
            .and_then(|v| v.get("tools"))
            .and_then(serde_json::Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
                    .filter(|name| valid_tool_name(name))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if !discovered.is_empty() {
            server.agents.insert(agent.clone(), discovered);
        }
        let Some(url) = server
            .url
            .as_deref()
            .and_then(|u| reqwest::Url::parse(u).ok())
        else {
            return fail(StatusCode::BAD_REQUEST, "invalid_url");
        };
        if kernel_net::check_public_url(&url).await.is_err() {
            return fail(StatusCode::BAD_REQUEST, "endpoint_refused");
        }
    }
    // Stage the allowlist the approval will enable. A catalog entry publishes
    // its tools; an uncatalogued stdio server declares them (it cannot be
    // discovered before the one approval starts it); an HTTP connection test
    // already produced them above.
    if let Some(entry) = catalog_entry(server.catalog_id.as_deref()) {
        if let Some(permissions) = entry.permissions {
            if !permissions.tools.is_empty() {
                server.agents.insert(agent.clone(), permissions.tools);
            }
        }
    } else if !requested_tools.is_empty() {
        server
            .agents
            .entry(agent.clone())
            .or_insert(requested_tools);
    }
    let Some(preview) = approval_preview(&server, state.token.confirmation_key()) else {
        return internal("confirmation_unavailable");
    };
    let response = mutate(&state, move |config| {
        if config.server.iter().any(|s| s.id == server.id) {
            return Err("server_exists");
        }
        // Item 1 (keep): the same check again, now under the write lock, so a
        // quarantined entry written between the pre-check and here still wins.
        if config.quarantined.iter().any(|entry| entry.id == server.id) {
            return Err("id_taken_by_quarantined_entry");
        }
        config.server.push(server);
        Ok(())
    })
    .await;
    if response.status() != StatusCode::OK {
        return response;
    }
    Json(AddResponse { ok: true, preview }).into_response()
}

/// Map a static refusal label to the API's error code (they are identical;
/// this keeps the code explicit at the boundary).
fn refusal_static_code(label: &'static str) -> &'static str {
    match label {
        "command_refused" => "command_refused",
        "secret_in_config" => "secret_in_config_use_env",
        other => other,
    }
}

fn mcp_test_digest(url: &str, tools: &[String]) -> String {
    let names = tools.join("\n");
    blake3::hash(format!("{url}\n{names}").as_bytes())
        .to_hex()
        .to_string()
}

/// Secret-looking values are refused in arguments, URLs and commands; see
/// [`kernel_mcp::looks_like_secret`] (the same rule config validation applies).
fn has_secret(value: &str) -> bool {
    kernel_mcp::looks_like_secret(value)
}
/// Stable warning code for an import that dropped HTTP headers (item 6).
///
/// A code, never a sentence: the Mac app owns the EN/FR copy, exactly as with
/// [`CONFIRMATION_WARNING_CODE`].
const IMPORT_HEADERS_WARNING_CODE: &str = "mcp_import_headers_dropped";

fn import_warnings(dropped_headers: bool) -> Vec<&'static str> {
    if dropped_headers {
        vec![IMPORT_HEADERS_WARNING_CODE]
    } else {
        vec![]
    }
}
fn secret_config_error() -> Response {
    error::error_response(StatusCode::BAD_REQUEST, "secret_in_config_use_env", "Secrets belong in ~/.auxesis/.env, not in MCP arguments or URLs. For a stdio server, list the variable name in env.", None)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnableRequest {
    enabled: bool,
}
pub(super) async fn set_server(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
    body: Bytes,
) -> Response {
    if body.len() > 1024 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let req: EnableRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    mutate(&state, move |c| {
        let Some(s) = c.server.iter_mut().find(|s| s.id == id) else {
            return Err("server_not_found");
        };
        s.enabled = req.enabled;
        Ok(())
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolsRequest {
    tools: Vec<String>,
}
pub(super) async fn set_agent_tools(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath((id, agent)): AxumPath<(String, String)>,
    body: Bytes,
) -> Response {
    if body.len() > 16 * 1024 {
        return fail(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
    }
    let req: ToolsRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return fail(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let runtime = state.mcp.read().unwrap_or_else(|p| p.into_inner()).clone();
    let discovered: std::collections::BTreeSet<String> = runtime
        .descriptors_for(&id)
        .iter()
        .map(|d| d.remote_name.clone())
        .collect();
    if req.tools.iter().any(|n| !discovered.contains(n)) {
        return fail(StatusCode::BAD_REQUEST, "tool_not_discovered");
    }
    mutate(&state, move |c| {
        let Some(s) = c.server.iter_mut().find(|s| s.id == id) else {
            return Err("server_not_found");
        };
        if req.tools.is_empty() {
            s.agents.remove(&agent);
        } else {
            s.agents.insert(agent, req.tools);
        }
        // The allowlist is part of the approval digest: an edit leaves the
        // server `needs_approval` until the owner approves the new preview.
        // M6-3 adds the permission-growth card on top.
        Ok(())
    })
    .await
}
pub(super) async fn delete_server(
    State(state): State<std::sync::Arc<ApiState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    mutate(&state, move |c| {
        let n = c.server.len();
        c.server.retain(|s| s.id != id);
        if n == c.server.len() {
            Err("server_not_found")
        } else {
            Ok(())
        }
    })
    .await
}
fn read_config(home: &Path) -> Result<kernel_mcp::McpConfig, ()> {
    kernel_mcp::McpConfig::load_from_path(&home.join("mcp.toml")).map_err(|_| ())
}
async fn mutate(
    state: &std::sync::Arc<ApiState>,
    edit: impl FnOnce(&mut kernel_mcp::McpConfig) -> Result<(), &'static str> + Send + 'static,
) -> Response {
    mutate_audited(state, None, edit).await
}

/// One MCP mutation, with an optional audit row written **before** the config
/// write and therefore before any child starts.
///
/// Review P3: the `mcp.approve` row used to be written after the enable and a
/// failure was only warned about, so a crash (or a store that could not open)
/// left an enabled, spawned server with no ledger row. Now the row is part of
/// the commit path: if the store cannot open or log, nothing is written,
/// nothing is enabled or started, and the caller gets 500 `ledger_failed`. The
/// reverse window (row written, file write then fails) over-records an approval
/// that did not take effect, which is the fail-closed direction.
async fn mutate_audited(
    state: &std::sync::Arc<ApiState>,
    audit: Option<(&'static str, serde_json::Value)>,
    edit: impl FnOnce(&mut kernel_mcp::McpConfig) -> Result<(), &'static str> + Send + 'static,
) -> Response {
    // Keep all MCP mutations ordered through discovery and installation. The
    // discovery path has its own hard timeout, so this lock has a finite hold.
    let _mutation = state.mcp_mutation.lock().await;
    let home = state.home.clone();
    let lock = std::sync::Arc::clone(&state.config_write);
    let generation = std::sync::Arc::clone(&state.mcp_generation);
    let db_path = state.db_path.clone();
    match tokio::task::spawn_blocking(move || {
        let _guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        kernel_core::with_config_lock(&home, || -> Result<u64, &'static str> {
            let mut config = read_config(&home).map_err(|_| "mcp_config_invalid")?;
            let before = config.clone();
            edit(&mut config)?;
            // An idempotent approve (or a repeated enable) writes nothing and
            // replaces no runtime, so it can never start a second child.
            if config == before {
                return Ok(0);
            }
            // Structural only: a single invalid or unconfirmed server is
            // quarantined by the runtime, never a whole-file write failure.
            config.validate_structural().map_err(|_| "invalid_server")?;
            // Item 7: a re-parse of the retained source that fails is refused
            // rather than silently replacing the owner's file from scratch.
            let text = config.to_toml_string().map_err(|_| "mcp_config_invalid")?;
            let gateway = kernel_core::SandboxHome::open(&home).map_err(|_| "write_failed")?;
            // The audit row is the last fallible step before the commit: no
            // row, no write, no enable, no start.
            if let Some((kind, row)) = audit.as_ref() {
                let store = aux_store::Store::open(&db_path).map_err(|_| "ledger_failed")?;
                aux_runtime::extensions::ledger::log_with(&store, kind, row)
                    .map_err(|_| "ledger_failed")?;
            }
            gateway
                .write_atomic(Path::new("mcp.toml"), text.as_bytes(), 0o600)
                .map_err(|_| "write_failed")?;
            Ok(generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1)
        })
        .map_err(|_| "write_failed")?
    })
    .await
    {
        Ok(Ok(0)) => Json(Ack { ok: true }).into_response(),
        Ok(Ok(written_generation)) => {
            let config = crate::api::load_config_verified(&state.home).unwrap_or_default();
            let sandbox = aux_engine::shell_sandbox(&config.shell);
            let runtime = crate::mcp::start(&state.home, &config.web, &sandbox).await;
            if state
                .mcp_generation
                .load(std::sync::atomic::Ordering::SeqCst)
                == written_generation
            {
                let old = {
                    let mut current = state.mcp.write().unwrap_or_else(|p| p.into_inner());
                    std::mem::replace(&mut *current, runtime)
                };
                drop(old);
            } else {
                drop(runtime);
            }
            Json(Ack { ok: true }).into_response()
        }
        Ok(Err("approval_unavailable")) => internal("approval_unavailable"),
        Ok(Err("stale_approval")) => fail(StatusCode::CONFLICT, "stale_confirmation"),
        Ok(Err("ledger_failed")) => internal("ledger_failed"),
        Ok(Err(code)) => fail(
            if code == "server_not_found" {
                StatusCode::NOT_FOUND
            } else if matches!(
                code,
                "server_exists" | "id_taken_by_quarantined_entry" | "use_approve"
            ) {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            },
            code,
        ),
        Err(_) => internal("write_failed"),
    }
}
fn fail(status: StatusCode, code: &'static str) -> Response {
    let message = match code {
        "pack_server_mismatch" => "An existing server with this ID does not match the selected catalog transport or endpoint. Restore the catalog settings or remove that server first.",
        // Item 1 (keep): never silently create a twin of an unusable entry.
        "id_taken_by_quarantined_entry" => "An entry with this ID is already in mcp.toml but could not be loaded, so it is quarantined. Delete that entry or fix it first, then add this server.",
        // Review P2: catalog servers have one install path: the approval.
        "use_approve" => "This server comes from the catalog. Approve its install preview instead: POST /v1/mcp/servers/{id}/approve.",
        "ledger_failed" => "The approval could not be recorded in the audit log, so nothing was enabled. Check the store and retry.",
        other => other,
    };
    error::error_response(status, code, message, None)
}
fn internal(code: &'static str) -> Response {
    fail(StatusCode::INTERNAL_SERVER_ERROR, code)
}
#[derive(Serialize)]
struct Ack {
    ok: bool,
}

/// A catalog binary another user could replace: a symlink anywhere we can see,
/// or a file / parent directory writable by group or others. Unreadable paths
/// count as mutable (fail closed).
fn catalog_binary_is_mutable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return true;
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.permissions().mode() & 0o022 != 0 {
        return true;
    }
    match path.parent().map(std::fs::metadata) {
        Some(Ok(dir)) => dir.permissions().mode() & 0o022 != 0,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_filters_avoid_and_keeps_required_review_fields() {
        let parsed: CatalogFile = toml::from_str(CATALOG).unwrap();
        let visible: Vec<_> = parsed
            .server
            .into_iter()
            .filter(|e| e.tier == "recommended" || e.tier == "candidate")
            .collect();
        assert!(!visible.is_empty());
        assert!(visible.iter().all(|e| e.tier != "avoid"));
        assert!(visible
            .iter()
            .all(|e| !e.id.is_empty() && !e.region.is_empty() && !e.access.is_empty()));
    }

    #[test]
    fn packs_are_bundled_and_contain_only_public_servers() {
        let packs: PackFile = toml::from_str(PACKS).unwrap();
        let catalog: CatalogFile = toml::from_str(CATALOG).unwrap();
        assert_eq!(packs.pack.len(), 7);
        for pack in packs.pack {
            for id in pack.servers {
                if let Some(server) = catalog.server.iter().find(|s| s.id == id) {
                    assert_eq!(server.data_class, "public");
                }
            }
        }
    }

    #[test]
    fn catalog_data_class_pins_the_exact_id_to_class_mapping() {
        // Source of truth: the data class of every entry in
        // `catalog/mcp-servers.toml` (the gate: `scripts/check-mcp-catalog.sh`).
        // This pins every ID -> class pair, not only the counts, so
        // a reclassification cannot pass silently.
        const EXPECTED: &[(&str, &str)] = &[
            ("abby-mcp", "sensitive"),
            ("arxiv-mcp-server", "public"),
            ("atlassian-rovo-mcp", "sensitive"),
            ("au-weather-mcp", "public"),
            ("brave-search-mcp", "public"),
            ("brevo-mcp", "sensitive"),
            ("brreg-mcp", "sensitive"),
            ("check-vat-vies-mcp", "sensitive"),
            ("companies-house-mcp", "sensitive"),
            ("crossref-mcp-server", "public"),
            ("datagouv-mcp", "public"),
            ("datos-gob-es-mcp", "public"),
            ("db-timetable-mcp", "public"),
            ("deepl-mcp-server", "sensitive"),
            ("docusign-mcp", "sensitive"),
            ("ecb-fx-rates-mcp", "public"),
            ("ecb-mcp", "public"),
            ("esankhyiki-mcp", "public"),
            ("exa-mcp", "public"),
            ("france-travail-mcp", "public"),
            ("frankfurter-mcp", "public"),
            ("gbif-mcp-server", "public"),
            ("github-mcp-server", "sensitive"),
            ("google-ads-mcp", "sensitive"),
            ("google-calendar-mcp", "sensitive"),
            ("google-data-commons-agent-toolkit", "public"),
            ("google-developer-knowledge-mcp", "public"),
            ("google-gmail-mcp", "sensitive"),
            ("google-maps-grounding-lite", "public"),
            ("google-people-mcp", "sensitive"),
            ("gsa-cms-blue-button-sandbox-mcp", "sensitive"),
            ("gsa-cms-data-json-mcp", "public"),
            ("gsa-fema-nfhl-mcp", "public"),
            ("gsa-ncbi-eutils-mcp", "public"),
            ("gsa-nih-clinicaltrials-mcp", "public"),
            ("gsa-nih-icite-mcp", "public"),
            ("gsa-nist-nvd-mcp", "public"),
            ("gsa-nsf-awards-mcp", "public"),
            ("gsa-per-diem-mcp", "public"),
            ("gsa-regulations-gov-mcp", "sensitive"),
            ("gsa-usgs-national-map-mcp", "public"),
            ("hal-mcp", "public"),
            ("idfm-paris-transit-mcp", "public"),
            ("justicelibre", "sensitive"),
            ("kiwi-flights-mcp", "public"),
            ("linear-mcp", "sensitive"),
            ("mapbox-mcp-docs", "public"),
            ("mapbox-mcp-server", "public"),
            ("mcp-belgium", "sensitive"),
            ("mcp-eu-finance", "public"),
            ("mcp-eu-sparql", "sensitive"),
            ("mcp-insee-entreprises", "sensitive"),
            ("mcp-magistrat-civil", "sensitive"),
            ("met-norway-mcp", "public"),
            ("microsoft-learn-mcp", "public"),
            ("microsoft-work-iq-calendar", "sensitive"),
            ("microsoft-work-iq-mail", "sensitive"),
            ("microsoft-work-iq-onedrive", "sensitive"),
            ("microsoft-work-iq-sharepoint", "sensitive"),
            ("microsoft-work-iq-teams", "sensitive"),
            ("nasa-earthdata-cmr-mcp", "public"),
            ("nl-eli-mcp", "public"),
            ("notion-mcp", "sensitive"),
            ("openalex-mcp-server", "public"),
            ("openstreetmap-mcp", "public"),
            ("paypal-mcp", "sensitive"),
            ("pennylane-mcp", "sensitive"),
            ("pubmed-mcp-server", "public"),
            ("qonto-mcp", "sensitive"),
            ("ris-mcp-ts", "sensitive"),
            ("semantic-scholar-mcp-jackkuo", "public"),
            ("shine-facture-mcp", "sensitive"),
            ("shopify-dev-mcp", "public"),
            ("slack-mcp", "sensitive"),
            ("stripe-mcp", "sensitive"),
            ("tavily-mcp", "public"),
            ("todoist-mcp", "sensitive"),
            ("tomtom-maps-mcp", "public"),
            ("transitland-mcp", "public"),
            ("uniprot-mcp-server", "public"),
            ("vatnode-mcp", "sensitive"),
            ("wikidata-mcp-server", "public"),
            ("wikipedia-mcp-rudra", "public"),
            ("world-bank-data-mcp", "public"),
            ("worldbank-data360-mcp", "public"),
            ("xero-mcp-server", "sensitive"),
        ];
        let catalog: CatalogFile = toml::from_str(CATALOG).unwrap();
        let mut actual: Vec<(String, String)> = catalog
            .server
            .iter()
            .map(|entry| (entry.id.clone(), entry.data_class.clone()))
            .collect();
        actual.sort();
        assert_eq!(
            actual,
            EXPECTED
                .iter()
                .map(|(id, class)| ((*id).to_owned(), (*class).to_owned()))
                .collect::<Vec<_>>()
        );
        let public = actual.iter().filter(|(_, c)| c == "public").count();
        let sensitive = actual.len() - public;
        assert_eq!((actual.len(), public, sensitive), (86, 49, 37));
    }

    #[test]
    fn config_roundtrip_has_no_secret_values_and_disabled_by_default() {
        let mut config = kernel_mcp::McpConfig::default();
        config.server.push(kernel_mcp::McpServerConfig {
            id: "sample".into(),
            catalog_id: Some("datagouv-mcp".into()),
            data_class: kernel_mcp::McpDataClass::Sensitive,
            stdio_confirmed: false,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: kernel_mcp::McpTransport::Http,
            url: Some("https://example.invalid/mcp".into()),
            command: None,
            args: vec![],
            env: vec!["SAMPLE_TOKEN".into()],
            enabled: false,
            agents: Default::default(),
        });
        config.validate().unwrap();
        let encoded = toml::to_string(&config).unwrap();
        assert!(encoded.contains("SAMPLE_TOKEN"));
        assert!(!encoded.contains("secret-value"));
        assert!(!config.server[0].enabled);
    }

    #[test]
    fn import_policy_rejects_shell_and_reserved_secret_names() {
        assert!(shell_syntax("sh"));
        assert!(shell_syntax("bash"));
        assert!(shell_syntax("anything;whoami"));
        assert!(shell_syntax("$(touch x)"));
        assert!(valid_import_env("GITHUB_TOKEN"));
        assert!(valid_import_env("SERVICE_TOKEN"));
        assert!(!valid_import_env("AUXESIS_HOME"));
        assert!(!valid_import_id("Bad_ID"));
        assert!(valid_import_id("safe-id"));
        assert!(!valid_import_env("PATH"));
        assert!(!valid_import_env("DYLD_INSERT_LIBRARIES"));
        assert!(!valid_import_env("LD_PRELOAD"));
        assert!(!valid_import_env("NODE_OPTIONS"));
        assert!(!valid_import_env("BASH_ENV"));
        assert!(has_secret("https://example.test/?token=sk-123"));
        assert!(!has_secret("https://example.test/public"));
        assert!(has_secret("--api-key"));
        assert!(has_secret("sk-abcdefgh1234"));
        // Ordinary words that contain "sk-" are not keys.
        assert!(!has_secret("https://example.test/task-list"));
        assert!(!has_secret("https://example.test/desk-top"));
    }

    #[test]
    fn pack_activation_requires_catalog_identity_and_matching_endpoint_without_touching_allowlists()
    {
        let entry = catalog_entry(Some("datagouv-mcp")).unwrap();
        let mut server = kernel_mcp::McpServerConfig {
            id: entry.id.clone(),
            catalog_id: Some(entry.id.clone()),
            data_class: kernel_mcp::McpDataClass::Public,
            stdio_confirmed: false,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: kernel_mcp::McpTransport::Http,
            url: entry.endpoint.clone(),
            command: None,
            args: vec![],
            env: vec![],
            enabled: false,
            agents: std::collections::BTreeMap::from([("main".into(), vec!["kept".into()])]),
        };
        assert!(pack_server_matches(&server, &entry));
        server.catalog_id = None;
        assert!(!pack_server_matches(&server, &entry));
        server.catalog_id = Some(entry.id.clone());
        server.url = Some("https://attacker.invalid/mcp".into());
        assert!(!pack_server_matches(&server, &entry));
        server.url = entry.endpoint.clone();
        server.data_class = kernel_mcp::McpDataClass::Sensitive;
        assert!(!pack_server_matches(&server, &entry));
        server.data_class = kernel_mcp::McpDataClass::Public;
        server.command = Some("/bin/echo".into());
        assert!(!pack_server_matches(&server, &entry));
        server.command = None;
        assert!(pack_server_matches(&server, &entry));
        // Review P2: no install-relevant override may ride along with a pack.
        server.args = vec!["--write".into()];
        assert!(!pack_server_matches(&server, &entry));
        server.args.clear();
        server.env = vec!["SOME_KEY".into()];
        assert!(!pack_server_matches(&server, &entry));
        server.env.clear();
        server.network = true;
        assert!(!pack_server_matches(&server, &entry));
        server.network = false;
        assert!(pack_server_matches(&server, &entry));
        assert_eq!(server.agents["main"], vec!["kept"]);
        assert_eq!(
            count_pack_tools(&["kept".into(), "removed".into()], Some(&["kept".into()])),
            1
        );
        assert_eq!(count_pack_tools(&["kept".into()], Some(&[])), 0);
    }

    #[test]
    fn generic_catalog_id_cannot_shadow_catalog_identity() {
        assert!(is_catalog_id("github-mcp-server"));
        assert!(is_catalog_id("datagouv-mcp"));
        assert!(!is_catalog_id("my-custom-server"));
    }

    #[test]
    fn test_digest_changes_with_tool_discovery_and_endpoint() {
        let first = mcp_test_digest("https://example.test/mcp", &["read".into()]);
        assert_eq!(
            first,
            mcp_test_digest("https://example.test/mcp", &["read".into()])
        );
        assert_ne!(
            first,
            mcp_test_digest("https://example.test/mcp", &["write".into()])
        );
        assert_ne!(
            first,
            mcp_test_digest("https://other.test/mcp", &["read".into()])
        );
    }

    #[test]
    fn import_warns_when_headers_were_dropped() {
        let warnings = import_warnings(true);
        assert_eq!(warnings, vec![IMPORT_HEADERS_WARNING_CODE]);
        // Item 6: a stable code, never a sentence the daemon would have to
        // translate or that could leak a value.
        assert!(!warnings[0].contains(' '), "the warning must be a code");
        assert!(!warnings[0].contains("${"));
        assert!(import_warnings(false).is_empty());
    }

    #[tokio::test]
    async fn mcp_test_refuses_private_and_tailnet_address_literals() {
        for url in [
            "http://127.0.0.1/mcp",
            "https://10.0.0.2/mcp",
            "https://169.254.169.254/mcp",
            "https://100.64.0.1/mcp",
            "https://100.80.0.1/mcp",
        ] {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(
                kernel_net::check_public_url(&parsed).await.is_err(),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn test_server_uses_the_pinned_checked_transport() {
        // Item 11: `test_server` must use `new_checked`, which refuses a
        // private host. `HttpTransport::new` alone would accept it.
        assert!(
            pinned_test_transport("http://127.0.0.1:9/mcp")
                .await
                .is_err(),
            "the pinned transport must refuse a loopback literal"
        );
    }

    #[test]
    fn packs_exclude_catalog_entries_with_an_unverified_endpoint() {
        // Item 13: the stdio INSEE entry has endpoint = "unverified".
        let unverified = catalog_entry(Some("mcp-insee-entreprises")).unwrap();
        assert_eq!(unverified.endpoint.as_deref(), Some("unverified"));
        assert!(!catalog_endpoint_usable(&unverified));
        let verified = catalog_entry(Some("datagouv-mcp")).unwrap();
        assert!(catalog_endpoint_usable(&verified));
    }

    #[test]
    fn confirmation_preview_sends_a_warning_code_and_the_high_risk_key() {
        // Item 6 (GLM): the daemon ships a code, never an English sentence, and
        // the JSON key Swift maps is `high_risk`.
        assert_eq!(CONFIRMATION_WARNING_CODE, "mcp_stdio_confirmation");
        assert!(
            !CONFIRMATION_WARNING_CODE.contains(' '),
            "the warning must be a stable code, not copy"
        );
        // Item 2: the generic non-catalog warning is its own stable code, and
        // it is set whatever the heuristic `high_risk` says.
        assert_eq!(UNVERIFIED_PROGRAM_WARNING_CODE, "stdio_unverified_program");
        assert!(!UNVERIFIED_PROGRAM_WARNING_CODE.contains(' '));
        for high_risk in [None, Some("shell_launcher")] {
            let preview = ConfirmationPreview {
                id: "sample".to_owned(),
                command: "/usr/local/bin/tool".to_owned(),
                args: vec!["--stdio".to_owned()],
                env: vec![],
                network: false,
                data_class: "sensitive".to_owned(),
                binary_hash: "unavailable".to_owned(),
                high_risk,
                unverified_program: Some(UNVERIFIED_PROGRAM_WARNING_CODE),
                hash: "hash".to_owned(),
                warning: CONFIRMATION_WARNING_CODE,
            };
            let json = serde_json::to_value(&preview).unwrap();
            assert_eq!(json["high_risk"], serde_json::json!(high_risk));
            assert_eq!(json["warning"], CONFIRMATION_WARNING_CODE);
            assert_eq!(json["unverified_program"], UNVERIFIED_PROGRAM_WARNING_CODE);
        }
    }

    #[test]
    fn a_quarantined_entry_survives_the_api_rewrite_verbatim() {
        // Item 1: the rewrite path the confirm/revoke endpoints use must keep
        // an unusable entry byte-for-byte, never drop it.
        let bad = "[[server]]\nid = \"bad\"\ntransport = \"carrier-pigeon\"\n";
        let text = format!(
            "[[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n\n{bad}"
        );
        let mut config = kernel_mcp::McpConfig::parse("mcp.toml", &text).unwrap();
        config.server[0].stdio_confirmed = true;
        config.server[0].stdio_confirmation = Some("hash".to_owned());
        let written = config.to_toml_string().unwrap();
        assert!(written.contains(bad));
        config.server[0].stdio_confirmed = false;
        config.server[0].stdio_confirmation = None;
        let written = config.to_toml_string().unwrap();
        assert!(written.contains(bad));
    }
}
