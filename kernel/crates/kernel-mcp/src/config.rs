//! User-configured MCP servers (`~/.auxesis/mcp.toml`).
//!
//! The file is the only place a person names an MCP server; nothing is
//! activated by default. An absent file means "no servers"; a present but
//! invalid file is a clear error the caller can log while it keeps running
//! without MCP (the daemon must never fail to boot because one server line is
//! wrong).
//!
//! # Bounds
//!
//! Every field is bounded (server count, argument count/length, agent and tool
//! name counts, total file size) and unknown keys are **refused** rather than
//! ignored, so a typo cannot silently change what is launched. A `stdio`
//! command must be an absolute path (never resolved through `PATH`, never a
//! shell string) and an `http` URL must be `https`, except on loopback where
//! the offline test server needs plain `http`.
//!
//! # Secrets
//!
//! `env` names variables only. Values live in `~/.auxesis/.env` and are read by
//! the caller at launch; nothing in this module resolves or stores them, and no
//! value can appear in this file.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value as EditValue};

/// Refuse to read an `mcp.toml` larger than this (runaway write, device file).
pub const MAX_MCP_CONFIG_BYTES: u64 = 256 * 1024;
/// Most servers the file may declare.
pub const MAX_MCP_SERVERS: usize = 32;
/// Most agents one server may name.
pub const MAX_MCP_AGENTS: usize = 64;
/// Most tool names one agent may list for one server.
pub const MAX_MCP_AGENT_TOOLS: usize = 256;
/// Hard cap on one `stdio` argument, in bytes.
pub const MAX_MCP_ARG_BYTES: usize = 4096;
/// Hard cap on an `http` URL, in bytes.
pub const MAX_MCP_URL_BYTES: usize = 2048;
/// Hard cap on an `env` variable name, in bytes.
pub const MAX_MCP_ENV_NAME_BYTES: usize = 64;

/// Transport one configured server speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpTransport {
    /// Streamable HTTP endpoint.
    Http,
    /// Local child process speaking newline-delimited JSON-RPC.
    Stdio,
}

/// Privacy classification of an MCP server's source data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum McpDataClass {
    Public,
    #[default]
    Sensitive,
}

impl McpTransport {
    /// Lowercase config label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Stdio => "stdio",
        }
    }
}

/// One `[[server]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerConfig {
    /// User-chosen id, `[a-z0-9-]{1,32}` and unique in the file.
    pub id: String,
    /// Optional reference to `catalog/mcp-servers.toml`; informational.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_id: Option<String>,
    /// Missing legacy values are conservatively treated as sensitive.
    #[serde(default)]
    pub data_class: McpDataClass,
    /// Explicit owner confirmation for package-runner or other gated launchers.
    ///
    /// A hand-edited `true` is **not** enough on its own: the flag is only
    /// honoured together with [`McpServerConfig::stdio_confirmation`], a hash
    /// of `(canonical command, args, env names)` written by the daemon's
    /// confirm endpoint. Any change to those three invalidates it.
    #[serde(default)]
    pub stdio_confirmed: bool,
    /// Hash binding the confirmation to one exact launch
    /// (`canonical command path, args, env names`). `None` means the server has
    /// never been confirmed by the daemon, whatever `stdio_confirmed` says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio_confirmation: Option<String>,
    /// M6-2: the owner's approval of the whole install preview, keyed by the
    /// daemon token. `None` means never approved; an enabled server without a
    /// matching record never starts (one-approval install).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    /// Whether the server needs network access. A sandboxed stdio child gets
    /// sockets only when this is set; the default denies all sockets.
    #[serde(default)]
    pub network: bool,
    /// Transport to use.
    pub transport: McpTransport,
    /// `http`: endpoint URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `stdio`: absolute path to the executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// `stdio`: arguments passed verbatim (never through a shell).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Environment variable **names** read from `~/.auxesis/.env` and injected
    /// at launch (stdio). Names only; no value is ever stored here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    /// Whether the daemon starts this server. Nothing is enabled by default.
    #[serde(default)]
    pub enabled: bool,
    /// `[server.agents]`: agent -> the remote tool names that agent may see. An agent
    /// with no entry sees nothing from this server. Read from the legacy
    /// `[server.dots]` table too.
    #[serde(
        default,
        skip_serializing_if = "std::collections::BTreeMap::is_empty",
        alias = "dots"
    )]
    pub agents: std::collections::BTreeMap<String, Vec<String>>,
}

/// One `[[server]]` entry that could not even be deserialized.
///
/// It is kept apart from the valid servers so one bad entry never drops the
/// rest of the file (item 6). `id` is best-effort (the raw `id` when the entry
/// is a table carrying one) and `reason` is a stable, content-free label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedServer {
    /// Best-effort id, or `"<entry>"` when the entry carried none.
    pub id: String,
    /// Transport when the entry named a valid one.
    pub transport: Option<McpTransport>,
    /// Stable, content-free quarantine label.
    pub reason: &'static str,
    /// Best-effort TOML rendering of the entry, for display and diagnostics.
    ///
    /// Rewrites no longer use this: the whole document is parsed with
    /// `toml_edit` and edited in place, so the entry (and every comment around
    /// it) is preserved verbatim by construction. This stays for callers that
    /// want to show the owner what was rejected.
    pub raw: String,
}

/// The whole `mcp.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpConfig {
    /// Every declared server, in file order.
    #[serde(default)]
    pub server: Vec<McpServerConfig>,
    /// Entries that failed to deserialize, kept so the API/UI can report them.
    ///
    /// Never serialized back on its own: the source document already holds
    /// them, and a rewrite leaves every quarantined entry untouched in place.
    #[serde(skip)]
    pub quarantined: Vec<QuarantinedServer>,
    /// The exact text this configuration was parsed from.
    ///
    /// Keep it so a rewrite (confirm, revoke, enable, delete, add) can edit the
    /// parsed `toml_edit` document in place: comments, formatting, ordering and
    /// quarantined entries survive byte-for-byte. Empty for a configuration
    /// built in memory, which then serializes from scratch.
    #[serde(skip)]
    source: String,
}

/// The keys a `[[server]]` entry may carry (mirrors `McpServerConfig`).
const SERVER_ENTRY_KEYS: &[&str] = &[
    "id",
    "catalog_id",
    "data_class",
    "stdio_confirmed",
    "stdio_confirmation",
    "approval",
    "network",
    "transport",
    "url",
    "command",
    "args",
    "env",
    "enabled",
    "agents",
    // Legacy spelling of `agents`, still accepted on read.
    "dots",
];

impl McpConfig {
    /// Parse `text`, naming `source` in any error.
    ///
    /// The document is parsed once with `toml_edit` (the exact text is kept for
    /// later in-place rewrites). The top-level structure is then checked; each
    /// `server` entry is deserialized **on its own**, so an unknown transport,
    /// an unknown key, a missing transport or a bad `data_class` quarantines
    /// only that entry and every other server still loads (item 6). A
    /// whole-file syntax error is still an error.
    ///
    /// Unknown top-level keys are refused. A duplicate id quarantines **every**
    /// entry that carries it (item 6): when one of them is already invalid, the
    /// good twin is quarantined too, so deleting it can never promote the
    /// hidden duplicate; both stay quarantined until the owner fixes the file.
    pub fn parse(source: &str, text: &str) -> Result<Self, McpConfigError> {
        if text.len() as u64 > MAX_MCP_CONFIG_BYTES {
            return Err(McpConfigError::TooLarge {
                path: source.to_owned(),
                size: text.len() as u64,
            });
        }
        let document = text
            .parse::<DocumentMut>()
            .map_err(|err| McpConfigError::Parse {
                path: source.to_owned(),
                message: kernel_core::describe_toml_error("", text, err.span(), err.message()),
            })?;
        // An unknown key is never quoted: it came from the file.
        if document.as_table().iter().any(|(key, _)| key != "server") {
            return Err(invalid(
                "unknown top-level key (only [[server]] is allowed)",
            ));
        }
        let entries = document_server_entries(&document)?;
        let mut config = Self {
            source: text.to_owned(),
            ..Self::default()
        };
        // Best-effort id of every entry, so a duplicated id (whether or not one
        // twin is otherwise valid) quarantines all of them as `duplicate_id`.
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for entry in &entries {
            if let Some(id) = entry_id(&entry.value) {
                *counts.entry(id).or_insert(0) += 1;
            }
        }
        for (index, entry) in entries.iter().enumerate() {
            let id = entry_id(&entry.value);
            let transport = entry_transport(&entry.value);
            let duplicated = id
                .as_deref()
                .is_some_and(|id| counts.get(id).copied().unwrap_or(0) > 1);
            let outcome = if duplicated {
                Err("duplicate_id")
            } else {
                validate_server_entry(&entry.value)
            };
            match outcome {
                Ok(server) => config.server.push(server),
                Err(reason) => config.quarantined.push(QuarantinedServer {
                    id: id.unwrap_or_else(|| format!("<entry {}>", index + 1)),
                    transport,
                    reason,
                    raw: entry.raw.clone(),
                }),
            }
        }
        if config.server.len() > MAX_MCP_SERVERS {
            for server in config.server.split_off(MAX_MCP_SERVERS) {
                let raw = format!("[[server]]\n{}", server_to_table(&server));
                config.quarantined.push(QuarantinedServer {
                    id: server.id,
                    transport: Some(server.transport),
                    reason: "too_many_servers",
                    raw,
                });
            }
        }
        Ok(config)
    }

    /// Build a configuration from an in-memory server list (no source text).
    ///
    /// A rewrite then serializes from scratch; a parsed configuration instead
    /// edits its source document in place.
    pub fn from_servers(server: Vec<McpServerConfig>) -> Self {
        Self {
            server,
            ..Self::default()
        }
    }

    /// Read `path`, validating it. A missing file is an empty configuration.
    pub fn load_from_path(path: &Path) -> Result<Self, McpConfigError> {
        match std::fs::metadata(path) {
            Ok(meta) => {
                if !meta.is_file() {
                    return Err(McpConfigError::NotRegularFile {
                        path: path.display().to_string(),
                    });
                }
                if meta.len() > MAX_MCP_CONFIG_BYTES {
                    return Err(McpConfigError::TooLarge {
                        path: path.display().to_string(),
                        size: meta.len(),
                    });
                }
                let text = std::fs::read_to_string(path)?;
                Self::parse(&path.display().to_string(), &text)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(McpConfigError::Io(err)),
        }
    }

    /// Enabled servers, in file order.
    pub fn enabled_servers(&self) -> impl Iterator<Item = &McpServerConfig> {
        self.server.iter().filter(|server| server.enabled)
    }

    /// The server with `id`, if declared.
    pub fn server(&self, id: &str) -> Option<&McpServerConfig> {
        self.server.iter().find(|server| server.id == id)
    }

    /// Whether the configuration declares nothing.
    pub fn is_empty(&self) -> bool {
        self.server.is_empty() && self.quarantined.is_empty()
    }

    /// Whole-file structural checks: server count and unique ids.
    ///
    /// A single invalid or unconfirmed server is **not** a whole-file error:
    /// it is quarantined one by one (see [`McpServerConfig::check`] and the
    /// runtime's `NeedsConfirmation`/`Quarantined` states), so every other
    /// server still loads.
    pub fn validate_structural(&self) -> Result<(), McpConfigError> {
        if self.server.len() > MAX_MCP_SERVERS {
            return Err(invalid(format!(
                "too many servers ({} > {MAX_MCP_SERVERS})",
                self.server.len()
            )));
        }
        let mut seen = BTreeSet::new();
        for server in &self.server {
            if !seen.insert(server.id.as_str()) {
                return Err(invalid(format!(
                    "duplicate server id {}",
                    shown(&server.id, "<id>")
                )));
            }
        }
        Ok(())
    }

    /// Strict validation of every server (structural checks included).
    ///
    /// Kept for callers that want one clear error; the runtime instead walks
    /// the servers and quarantines each failure in isolation.
    pub fn validate(&self) -> Result<(), McpConfigError> {
        self.validate_structural()?;
        for server in &self.server {
            server.check().map_err(|refusal| McpConfigError::Invalid {
                reason: refusal.detail,
            })?;
        }
        Ok(())
    }

    /// Serialize the configuration for writing, preserving the source document.
    ///
    /// The document parsed at load time is edited **in place** with
    /// `toml_edit`: only the tables that changed are touched, so every comment,
    /// blank line, key order, `[[ server ]]` spelling and quarantined entry
    /// stays byte-for-byte. A configuration assembled in memory (`source`
    /// empty) is written from scratch instead.
    ///
    /// Item 7: the retained source parsed once already, so a re-parse failure
    /// is a bug rather than a normal case — the rewrite is **refused** instead
    /// of silently replacing the owner's file with a from-scratch document.
    pub fn to_toml_string(&self) -> Result<String, McpConfigError> {
        let mut document: DocumentMut = if self.source.is_empty() {
            DocumentMut::new()
        } else {
            self.source
                .parse::<DocumentMut>()
                .map_err(|err| McpConfigError::Parse {
                    path: "<retained source>".to_owned(),
                    message: kernel_core::describe_toml_error(
                        "",
                        &self.source,
                        err.span(),
                        err.message(),
                    ),
                })?
        };
        edit_server_entries(&mut document, &self.server, &self.quarantined);
        Ok(document.to_string())
    }
}

/// One `server` entry recovered from the parsed document.
struct DocumentEntry {
    /// The entry as a plain `toml::Value`, for the per-entry deserialization.
    value: toml::Value,
    /// Best-effort TOML rendering, for `QuarantinedServer::raw`.
    raw: String,
}

/// Every `server` entry of the document, in file order.
///
/// Both the documented `[[server]]` array of tables and the inline
/// `server = [ { ... } ]` form are accepted; anything else is a whole-file
/// error (as before).
fn document_server_entries(document: &DocumentMut) -> Result<Vec<DocumentEntry>, McpConfigError> {
    let Some(item) = document.as_table().get("server") else {
        return Ok(Vec::new());
    };
    match item {
        Item::ArrayOfTables(array) => Ok(array
            .iter()
            .map(|table| DocumentEntry {
                value: table_to_value(table),
                raw: format!("[[server]]\n{table}"),
            })
            .collect()),
        Item::Value(EditValue::Array(entries)) => Ok(entries
            .iter()
            .map(|value| DocumentEntry {
                value: edit_value_to_value(value),
                raw: value.to_string(),
            })
            .collect()),
        _ => Err(invalid("`server` must be an array of tables")),
    }
}

/// The best-effort `id` of one parsed entry, when it carries a string one.
fn entry_id(entry: &toml::Value) -> Option<String> {
    entry
        .get("id")
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
}

/// The best-effort transport of one parsed entry, when it names a valid one.
fn entry_transport(entry: &toml::Value) -> Option<McpTransport> {
    match entry.get("transport").and_then(toml::Value::as_str) {
        Some("http") => Some(McpTransport::Http),
        Some("stdio") => Some(McpTransport::Stdio),
        _ => None,
    }
}

/// Validate one `[[server]]` entry on its own, without the duplicate rule.
///
/// The entry is inspected as a `toml::Value` first so a precise, content-free
/// label names the failure; only then is it deserialized.
fn validate_server_entry(item: &toml::Value) -> Result<McpServerConfig, &'static str> {
    let Some(table) = item.as_table() else {
        return Err("invalid_server");
    };
    for key in table.keys() {
        if !SERVER_ENTRY_KEYS.contains(&key.as_str()) {
            return Err("unknown_key");
        }
    }
    match table.get("transport").and_then(toml::Value::as_str) {
        Some("http") | Some("stdio") => {}
        Some(_) => return Err("invalid_transport"),
        None => return Err("missing_transport"),
    }
    if table
        .get("data_class")
        .is_some_and(|class| !matches!(class.as_str(), Some("public") | Some("sensitive")))
    {
        return Err("invalid_data_class");
    }
    item.clone()
        .try_into::<McpServerConfig>()
        .map_err(|_| "invalid_server")
}

/// Render one `toml_edit` table (or every value under it) as a plain
/// `toml::Value`, so the shared per-entry deserialization applies unchanged.
fn table_to_value(table: &Table) -> toml::Value {
    let mut map = toml::map::Map::new();
    for (key, item) in table.iter() {
        if let Some(value) = item_to_value(item) {
            map.insert(key.to_owned(), value);
        }
    }
    toml::Value::Table(map)
}

/// Render one `toml_edit` value as a plain `toml::Value`.
fn edit_value_to_value(value: &EditValue) -> toml::Value {
    match value {
        EditValue::String(string) => toml::Value::String(string.value().clone()),
        EditValue::Integer(integer) => toml::Value::Integer(*integer.value()),
        EditValue::Float(float) => toml::Value::Float(*float.value()),
        EditValue::Boolean(boolean) => toml::Value::Boolean(*boolean.value()),
        // A datetime never appears in a server entry; keep it as a string so an
        // unparsable field is refused rather than silently accepted.
        EditValue::Datetime(datetime) => toml::Value::String(datetime.value().to_string()),
        EditValue::Array(array) => {
            toml::Value::Array(array.iter().map(edit_value_to_value).collect())
        }
        EditValue::InlineTable(table) => toml::Value::Table(inline_table_to_map(table)),
    }
}

/// Render one `toml_edit` item as a plain `toml::Value`, when it has one.
fn item_to_value(item: &Item) -> Option<toml::Value> {
    match item {
        Item::None => None,
        Item::Value(value) => Some(edit_value_to_value(value)),
        Item::Table(table) => Some(table_to_value(table)),
        Item::ArrayOfTables(array) => Some(toml::Value::Array(
            array.iter().map(table_to_value).collect(),
        )),
    }
}

/// Render one inline table as a plain `toml::Value` map.
fn inline_table_to_map(table: &InlineTable) -> toml::map::Map<String, toml::Value> {
    let mut map = toml::map::Map::new();
    for (key, value) in table.iter() {
        map.insert(key.to_owned(), edit_value_to_value(value));
    }
    map
}

/// Edit the document's `server` entries to match `servers`, in place.
///
/// Only the entries that changed are touched. An entry is left exactly as it
/// was when its id is in `quarantined` (the owner must still see and fix it) or
/// when it matches an in-memory server; an id that is neither present nor
/// quarantined was deleted. New servers are appended.
fn edit_server_entries(
    document: &mut DocumentMut,
    servers: &[McpServerConfig],
    quarantined: &[QuarantinedServer],
) {
    let keep: BTreeSet<&str> = quarantined.iter().map(|entry| entry.id.as_str()).collect();
    match document.as_table_mut().get_mut("server") {
        Some(Item::ArrayOfTables(array)) => edit_array_of_tables(array, servers, &keep),
        Some(Item::Value(EditValue::Array(array))) => {
            edit_inline_array(array, servers, &keep);
        }
        _ => {
            if !servers.is_empty() {
                let mut array = ArrayOfTables::new();
                for server in servers {
                    array.push(server_to_table(server));
                }
                document
                    .as_table_mut()
                    .insert("server", Item::ArrayOfTables(array));
            }
        }
    }
}

/// Whether one parsed document entry must be left untouched by a rewrite.
fn entry_kept(
    server: &McpServerConfig,
    servers: &[McpServerConfig],
    keep: &BTreeSet<&str>,
) -> bool {
    servers.iter().any(|candidate| candidate.id == server.id) || keep.contains(server.id.as_str())
}

/// Edit a `[[server]]` array of tables in place.
fn edit_array_of_tables(
    array: &mut ArrayOfTables,
    servers: &[McpServerConfig],
    keep: &BTreeSet<&str>,
) {
    let mut existing: Vec<(usize, McpServerConfig)> = Vec::new();
    for (index, table) in array.iter().enumerate() {
        let Ok(server) = validate_server_entry(&table_to_value(table)) else {
            continue;
        };
        existing.push((index, server));
    }
    for (index, current) in &existing {
        let Some(desired) = servers.iter().find(|server| server.id == current.id) else {
            continue;
        };
        if desired == current {
            continue;
        }
        let Some(table) = array.get_mut(*index) else {
            continue;
        };
        sync_server_fields(table, current, desired);
    }
    let mut removals: Vec<usize> = existing
        .iter()
        .filter(|(_, server)| !entry_kept(server, servers, keep))
        .map(|(index, _)| *index)
        .collect();
    removals.sort_unstable_by(|a, b| b.cmp(a));
    for index in removals {
        if index < array.len() {
            array.remove(index);
        }
    }
    for server in servers {
        if !existing.iter().any(|(_, current)| current.id == server.id) {
            array.push(server_to_table(server));
        }
    }
}

/// Edit an inline `server = [ ... ]` array in place.
fn edit_inline_array(array: &mut Array, servers: &[McpServerConfig], keep: &BTreeSet<&str>) {
    let mut existing: Vec<(usize, McpServerConfig)> = Vec::new();
    for (index, value) in array.iter().enumerate() {
        let Some(table) = value.as_inline_table() else {
            continue;
        };
        let Ok(server) = validate_server_entry(&toml::Value::Table(inline_table_to_map(table)))
        else {
            continue;
        };
        existing.push((index, server));
    }
    for (index, current) in &existing {
        let Some(desired) = servers.iter().find(|server| server.id == current.id) else {
            continue;
        };
        if desired == current {
            continue;
        }
        let Some(EditValue::InlineTable(inline)) = array.get_mut(*index) else {
            continue;
        };
        let mut table = inline.clone().into_table();
        sync_server_fields(&mut table, current, desired);
        *inline = table.into_inline_table();
    }
    let mut removals: Vec<usize> = existing
        .iter()
        .filter(|(_, server)| !entry_kept(server, servers, keep))
        .map(|(index, _)| *index)
        .collect();
    removals.sort_unstable_by(|a, b| b.cmp(a));
    for index in removals {
        if index < array.len() {
            array.remove(index);
        }
    }
    for server in servers {
        if !existing.iter().any(|(_, current)| current.id == server.id) {
            array.push(EditValue::InlineTable(
                server_to_table(server).into_inline_table(),
            ));
        }
    }
}

/// Update only the fields of `table` that differ between `current` and
/// `desired`, so comments and key order elsewhere in the entry survive.
fn sync_server_fields(table: &mut Table, current: &McpServerConfig, desired: &McpServerConfig) {
    if current.catalog_id != desired.catalog_id {
        set_optional_string(table, "catalog_id", desired.catalog_id.as_deref());
    }
    if current.data_class != desired.data_class {
        table.insert(
            "data_class",
            toml_edit::value(match desired.data_class {
                McpDataClass::Public => "public".to_owned(),
                McpDataClass::Sensitive => "sensitive".to_owned(),
            }),
        );
    }
    if current.stdio_confirmed != desired.stdio_confirmed {
        table.insert("stdio_confirmed", toml_edit::value(desired.stdio_confirmed));
    }
    if current.stdio_confirmation != desired.stdio_confirmation {
        set_optional_string(
            table,
            "stdio_confirmation",
            desired.stdio_confirmation.as_deref(),
        );
    }
    if current.approval != desired.approval {
        set_optional_string(table, "approval", desired.approval.as_deref());
    }
    if current.network != desired.network {
        table.insert("network", toml_edit::value(desired.network));
    }
    if current.transport != desired.transport {
        table.insert(
            "transport",
            toml_edit::value(desired.transport.as_str().to_owned()),
        );
    }
    if current.url != desired.url {
        set_optional_string(table, "url", desired.url.as_deref());
    }
    if current.command != desired.command {
        set_optional_string(table, "command", desired.command.as_deref());
    }
    if current.args != desired.args {
        table.insert("args", toml_edit::value(string_array(&desired.args)));
    }
    if current.env != desired.env {
        table.insert("env", toml_edit::value(string_array(&desired.env)));
    }
    if current.enabled != desired.enabled {
        table.insert("enabled", toml_edit::value(desired.enabled));
    }
    if current.agents != desired.agents {
        // Both spellings in one table is a duplicate field, so the legacy key goes.
        table.remove("dots");
        if desired.agents.is_empty() {
            table.remove("agents");
        } else {
            table.insert("agents", toml_edit::value(agents_table(&desired.agents)));
        }
    }
}

/// Set or remove an optional string field.
fn set_optional_string(table: &mut Table, key: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            table.insert(key, toml_edit::value(value.to_owned()));
        }
        None => {
            table.remove(key);
        }
    }
}

/// Build the `toml_edit` array for one string list.
fn string_array(values: &[String]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(value.clone());
    }
    array
}

/// Build the `toml_edit` inline table for one `agents` map.
fn agents_table(agents: &std::collections::BTreeMap<String, Vec<String>>) -> InlineTable {
    let mut table = InlineTable::new();
    for (agent, tools) in agents {
        table.insert(agent.clone(), EditValue::Array(string_array(tools)));
    }
    table
}

/// Build the full `toml_edit` table for a server added to a rewrite.
fn server_to_table(server: &McpServerConfig) -> Table {
    let mut table = Table::new();
    table.insert("id", toml_edit::value(server.id.clone()));
    if let Some(catalog_id) = &server.catalog_id {
        table.insert("catalog_id", toml_edit::value(catalog_id.clone()));
    }
    table.insert(
        "data_class",
        toml_edit::value(match server.data_class {
            McpDataClass::Public => "public".to_owned(),
            McpDataClass::Sensitive => "sensitive".to_owned(),
        }),
    );
    table.insert("stdio_confirmed", toml_edit::value(server.stdio_confirmed));
    if let Some(confirmation) = &server.stdio_confirmation {
        table.insert("stdio_confirmation", toml_edit::value(confirmation.clone()));
    }
    if let Some(approval) = &server.approval {
        table.insert("approval", toml_edit::value(approval.clone()));
    }
    table.insert("network", toml_edit::value(server.network));
    table.insert(
        "transport",
        toml_edit::value(server.transport.as_str().to_owned()),
    );
    if let Some(url) = &server.url {
        table.insert("url", toml_edit::value(url.clone()));
    }
    if let Some(command) = &server.command {
        table.insert("command", toml_edit::value(command.clone()));
    }
    if !server.args.is_empty() {
        table.insert("args", toml_edit::value(string_array(&server.args)));
    }
    if !server.env.is_empty() {
        table.insert("env", toml_edit::value(string_array(&server.env)));
    }
    table.insert("enabled", toml_edit::value(server.enabled));
    if !server.agents.is_empty() {
        table.insert("agents", toml_edit::value(agents_table(&server.agents)));
    }
    table
}

/// Why one `[[server]]` entry is unusable, with a stable static label.
///
/// The label is content-free and is what the API and UI show as a quarantine
/// reason; `detail` is a human-readable, secret-free explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerRefusal {
    /// Stable, content-free category (`catalog_mismatch`, `command_refused`, ...).
    pub label: &'static str,
    /// Human-readable, secret-free explanation.
    pub detail: String,
}

fn refuse(label: &'static str, detail: impl Into<String>) -> ServerRefusal {
    ServerRefusal {
        label,
        detail: detail.into(),
    }
}

impl McpServerConfig {
    /// Validate this one entry, returning a static-label refusal.
    ///
    /// This is the per-server rule set; the caller quarantines only this
    /// server on failure.
    pub fn check(&self) -> Result<StdioPolicy, ServerRefusal> {
        if !valid_id(&self.id) {
            return Err(refuse(
                "invalid_server_id",
                "server id must match [a-z0-9-]{1,32}",
            ));
        }
        let server = shown(&self.id, "<id>");
        if self.env.len() > crate::stdio::MAX_ENV_ENTRIES {
            return Err(refuse(
                "invalid_env_name",
                format!("server {server} declares too many env names"),
            ));
        }
        for name in &self.env {
            validate_env_name(&self.id, name)?;
        }
        let policy = match self.transport {
            McpTransport::Http => {
                if self.command.is_some() || !self.args.is_empty() {
                    return Err(refuse(
                        "invalid_server",
                        format!("server {server} is http and must not set command/args"),
                    ));
                }
                let url = self.url.as_deref().ok_or_else(|| {
                    refuse(
                        "invalid_server",
                        format!("server {server} is http and needs a url"),
                    )
                })?;
                validate_http_url(&self.id, url)?;
                StdioPolicy::default()
            }
            McpTransport::Stdio => {
                if self.url.is_some() {
                    return Err(refuse(
                        "invalid_server",
                        format!("server {server} is stdio and must not set url"),
                    ));
                }
                let command = self.command.as_deref().ok_or_else(|| {
                    refuse(
                        "invalid_server",
                        format!("server {server} is stdio and needs an absolute command"),
                    )
                })?;
                evaluate_stdio_policy(&self.id, command, &self.args, self.network)?
            }
        };
        if self.agents.len() > MAX_MCP_AGENTS {
            return Err(refuse(
                "invalid_tools",
                format!("server {server} names too many agents"),
            ));
        }
        for (agent, tools) in &self.agents {
            if !valid_agent(agent) {
                return Err(refuse(
                    "invalid_tools",
                    format!("server {server} names an invalid agent"),
                ));
            }
            if tools.len() > MAX_MCP_AGENT_TOOLS {
                return Err(refuse(
                    "invalid_tools",
                    format!(
                        "server {server} lists too many tools for agent {}",
                        shown(agent, "<agent>")
                    ),
                ));
            }
            for tool in tools {
                // The remote name is the argument to `tools/call`: it is
                // refused, never rewritten.
                if !crate::naming::valid_wire_component(tool) || tool.len() > 48 {
                    return Err(refuse(
                        "invalid_tools",
                        format!(
                            "server {server} lists an unusable tool name for agent {}",
                            shown(agent, "<agent>")
                        ),
                    ));
                }
            }
        }
        Ok(policy)
    }

    /// The confirmation binding for this launch, keyed by a daemon-held secret.
    ///
    /// Covers the **whole launch spec** (item 4): canonical command path, args
    /// verbatim, sorted env names, `network`, `data_class`, transport and the
    /// SHA-256 of the binary at the canonical path. No secret → no binding
    /// (fail closed, item 5): there is no unkeyed/plain-hash acceptance.
    pub fn confirmation_binding(&self, secret: &[u8]) -> Option<String> {
        confirmation_digest(secret, self, None)
    }

    /// The same binding, but over a binary SHA-256 the caller already
    /// verified (a catalog pin) instead of re-reading the file. Re-reading
    /// would let a file swapped between the check and the binding get the
    /// swapped binary approved; with the published hash bound in, the spawn
    /// re-check (which hashes the file it is about to run) only passes for
    /// exactly the catalog's binary.
    pub fn confirmation_binding_for_sha(&self, secret: &[u8], sha256: &str) -> Option<String> {
        confirmation_digest(secret, self, Some(sha256))
    }

    /// Whether the owner's confirmation is present **and** still matches this
    /// exact launch under `secret`.
    ///
    /// The daemon passes its API token, so a config file edited by hand (or an
    /// imported snippet) cannot mint a confirmation: it would have to know the
    /// token. A bare `stdio_confirmed = true` is never enough. An empty secret
    /// (the daemon token could not be read) confirms nothing.
    pub fn stdio_is_confirmed_with(&self, secret: &[u8]) -> bool {
        // A missing stored hash is never a confirmation, so `None == None`
        // cannot pass. An empty secret yields `None` from the binding, so it
        // can never match a stored hash either.
        let Some(stored) = self.stdio_confirmation.as_deref() else {
            return false;
        };
        self.stdio_confirmed && self.confirmation_binding(secret).as_deref() == Some(stored)
    }

    /// The M6-2 install approval for this exact preview under `secret`.
    ///
    /// `catalog_pin` is the curated `catalog_hash` for a catalog entry; a
    /// catalog server without a pin gets no binding (fail closed). Like the
    /// confirmation, an empty secret yields `None`.
    ///
    /// A non-catalog `stdio` server's digest includes the SHA-256 of the
    /// program file **as it is now**. A caller that already previewed the file
    /// passes the previewed hash to [`Self::approval_binding_for_sha`] instead,
    /// so a swap between preview and approve cannot be accepted by re-reading
    /// the swapped file.
    pub fn approval_binding(&self, secret: &[u8], catalog_pin: Option<&str>) -> Option<String> {
        approval_digest(secret, self, catalog_pin, None)
    }

    /// The same approval binding, but over a binary SHA-256 the caller already
    /// previewed, instead of re-reading the file.
    ///
    /// Only a non-catalog `stdio` server carries the hash: a catalog entry's
    /// pin covers its published SHA, and an `http` server has no program.
    pub fn approval_binding_for_sha(
        &self,
        secret: &[u8],
        catalog_pin: Option<&str>,
        sha256: &str,
    ) -> Option<String> {
        approval_digest(secret, self, catalog_pin, Some(sha256))
    }

    /// Whether the owner approved **this** install: a keyed digest over the
    /// id, catalog id and pin, transport, endpoint or launch, data class,
    /// network, every agent→tool allowlist and (for a non-catalog stdio
    /// server) the program's SHA-256. A hand-edited `enabled = true` never
    /// passes; the lifecycle fields are deliberately not hashed, so the same
    /// hash the preview returned is still valid for the approve call.
    pub fn is_approved_with(&self, secret: &[u8], catalog_pin: Option<&str>) -> bool {
        let Some(stored) = self.approval.as_deref() else {
            return false;
        };
        self.approval_binding(secret, catalog_pin).as_deref() == Some(stored)
    }

    /// Whether this enabled server carries a valid M6-2 install approval.
    ///
    /// This is the one approval predicate: the daemon passes the curated
    /// catalog pin for a catalog entry, and a caller without the catalog (the
    /// CLI) passes `None`, which fails closed for a catalog server.
    ///
    /// A pre-M6-2 `stdio` server whose old launch confirmation still matches
    /// and which has no approval record is grandfathered: its confirmation was
    /// the install approval of its day. A bad or changed approval record never
    /// falls back to the old gate.
    pub fn is_install_approved(&self, secret: Option<&[u8]>, catalog_pin: Option<&str>) -> bool {
        let Some(secret) = secret else {
            return false;
        };
        if self.is_approved_with(secret, catalog_pin) {
            return true;
        }
        self.approval.is_none()
            && self.transport == McpTransport::Stdio
            && self.catalog_id.is_none()
            && self.stdio_is_confirmed_with(secret)
    }
}

/// Bind one install approval to one exact server preview and a daemon secret.
///
/// Covers every install-relevant field, never the mutable lifecycle fields
/// (`enabled`, `approval`, `stdio_confirmed`): the preview hash must stay the
/// same before and after the approve write. `catalog_pin` is required for a
/// catalog server, so a lost or unverifiable entry invalidates the approval.
/// A non-catalog `stdio` server also binds the program's SHA-256: `binary_sha`
/// is the hash the caller previewed, or `None` to read the file now.
fn approval_digest(
    secret: &[u8],
    server: &McpServerConfig,
    catalog_pin: Option<&str>,
    binary_sha: Option<&str>,
) -> Option<String> {
    if secret.is_empty() {
        return None;
    }
    let pin = match (server.catalog_id.as_deref(), catalog_pin) {
        (Some(_), Some(pin)) => pin,
        (Some(_), None) => return None,
        (None, _) => "",
    };
    let mut hasher = blake3::Hasher::new_keyed(blake3::hash(secret).as_bytes());
    // v2: every field carries a tag and a length/count, so no two shapes can
    // serialise to the same byte stream (v1 joined args then env with no
    // boundary, so `args=["X"], env=[]` and `args=[], env=["X"]` collided).
    hasher.update(b"mcp-approval-v2\0");
    hash_field(&mut hasher, b"id:", &server.id);
    hash_field(
        &mut hasher,
        b"catalog:",
        server.catalog_id.as_deref().unwrap_or(""),
    );
    hash_field(&mut hasher, b"pin:", pin);
    hash_field(&mut hasher, b"transport:", server.transport.as_str());
    hash_field(&mut hasher, b"url:", server.url.as_deref().unwrap_or(""));
    hash_field(
        &mut hasher,
        b"command:",
        server.command.as_deref().unwrap_or(""),
    );
    hash_count(&mut hasher, b"args:", server.args.len());
    for arg in &server.args {
        hash_field(&mut hasher, b"arg:", arg);
    }
    let mut names: Vec<&str> = server.env.iter().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    hash_count(&mut hasher, b"env:", names.len());
    for name in names {
        hash_field(&mut hasher, b"env-name:", name);
    }
    hash_flag(&mut hasher, b"network:", server.network);
    hash_field(
        &mut hasher,
        b"class:",
        match server.data_class {
            McpDataClass::Public => "public",
            McpDataClass::Sensitive => "sensitive",
        },
    );
    hash_count(&mut hasher, b"agents:", server.agents.len());
    for (agent, tools) in &server.agents {
        hash_field(&mut hasher, b"agent:", agent);
        hash_count(&mut hasher, b"agent-tools:", tools.len());
        for tool in tools {
            hash_field(&mut hasher, b"tool:", tool);
        }
    }
    // Only a non-catalog stdio install names a program file: a catalog entry's
    // pin already covers its published SHA, and an http server has none. The
    // preview passes the hash it showed; a caller with no previewed hash reads
    // the file now, so a swap changes the digest and refuses the old approval.
    if server.transport == McpTransport::Stdio && server.catalog_id.is_none() {
        let sha = match binary_sha {
            Some(sha) => sha.to_ascii_lowercase(),
            None => binary_sha256(
                server
                    .command
                    .as_deref()
                    .map(Path::new)
                    .unwrap_or_else(|| Path::new("")),
            ),
        };
        hash_field(&mut hasher, b"binary-sha256:", &sha);
    }
    Some(hasher.finalize().to_hex().to_string())
}

/// Bind one confirmation to one exact launch **and** to a daemon-held secret.
///
/// The command is canonicalised (symlinks resolved) where the path exists, so
/// a symlink retargeted after confirmation changes the digest and invalidates
/// it. Arguments are hashed verbatim, in order; env names are sorted and
/// deduplicated; the agent→tool allowlist is hashed sorted (item 7), so widening
/// an agent's tools invalidates the confirmation too. A non-empty `secret` keys
/// the digest, so the value cannot be reproduced from the config file alone.
/// The binary's SHA-256 is recomputed here, so a swapped binary invalidates the
/// confirmation at spawn time too.
fn confirmation_digest(
    secret: &[u8],
    server: &McpServerConfig,
    verified_sha: Option<&str>,
) -> Option<String> {
    if secret.is_empty() {
        // Item 5: no daemon key, no confirmation — never fall back to an
        // unkeyed digest a hand edit could reproduce.
        return None;
    }
    let command = server.command.as_deref()?;
    let canonical = std::fs::canonicalize(command)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| command.to_owned());
    let mut hasher = blake3::Hasher::new_keyed(blake3::hash(secret).as_bytes());
    // v2: tagged, length-prefixed and counted, exactly like the approval
    // digest, so an args/env swap (or a tool moving between agents) invalidates
    // the confirmation instead of reusing the old bytes.
    hasher.update(b"mcp-confirmation-v2\0");
    hash_field(&mut hasher, b"command:", &canonical);
    hash_count(&mut hasher, b"args:", server.args.len());
    for arg in &server.args {
        hash_field(&mut hasher, b"arg:", arg);
    }
    let mut names: Vec<&str> = server.env.iter().map(String::as_str).collect();
    names.sort_unstable();
    names.dedup();
    hash_count(&mut hasher, b"env:", names.len());
    for name in names {
        hash_field(&mut hasher, b"env-name:", name);
    }
    hash_flag(&mut hasher, b"network:", server.network);
    hash_field(
        &mut hasher,
        b"class:",
        match server.data_class {
            McpDataClass::Public => "public",
            McpDataClass::Sensitive => "sensitive",
        },
    );
    hash_field(&mut hasher, b"transport:", server.transport.as_str());
    // Item 7: the per-agent tools allowlist is part of the confirmed launch. A
    // `BTreeMap` iterates in key order, so the digest is deterministic.
    hash_count(&mut hasher, b"agents:", server.agents.len());
    for (agent, tools) in &server.agents {
        hash_field(&mut hasher, b"agent:", agent);
        hash_count(&mut hasher, b"agent-tools:", tools.len());
        for tool in tools {
            hash_field(&mut hasher, b"tool:", tool);
        }
    }
    let sha = match verified_sha {
        Some(sha) => sha.to_ascii_lowercase(),
        None => binary_sha256(Path::new(&canonical)),
    };
    hash_field(&mut hasher, b"sha256:", &sha);
    Some(hasher.finalize().to_hex().to_string())
}

/// Feed one tagged, length-prefixed field into a digest.
///
/// The tag names the field and the length makes the encoding prefix-free, so a
/// value can never be read as another field's tag, as an item of another list,
/// or as the next field.
fn hash_field(hasher: &mut blake3::Hasher, tag: &[u8], value: &str) {
    hasher.update(tag);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

/// Feed one tagged list count into a digest, before the tagged items.
fn hash_count(hasher: &mut blake3::Hasher, tag: &[u8], count: usize) {
    hasher.update(tag);
    hasher.update(&(count as u64).to_le_bytes());
}

/// Feed one tagged boolean into a digest.
fn hash_flag(hasher: &mut blake3::Hasher, tag: &[u8], value: bool) {
    hasher.update(tag);
    hasher.update(&[u8::from(value)]);
}

/// SHA-256 of the file at `path`, streamed so a large binary is never held in
/// memory. An unreadable path hashes to a fixed marker so a missing binary can
/// still be confirmed (and then fails at spawn with its own reason).
pub fn binary_sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return "unavailable".to_owned();
    };
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(_) => return "unavailable".to_owned(),
        }
    }
    let mut hex = String::with_capacity(64);
    for byte in digest.finalize() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Why an `mcp.toml` could not be used.
#[derive(Debug, thiserror::Error)]
pub enum McpConfigError {
    /// Reading the file failed.
    #[error("reading MCP configuration: {0}")]
    Io(#[from] std::io::Error),
    /// The path exists but is not a regular file.
    #[error("MCP configuration {path} is not a regular file")]
    NotRegularFile {
        /// Offending path.
        path: String,
    },
    /// The file is larger than [`MAX_MCP_CONFIG_BYTES`].
    #[error("MCP configuration {path} is unexpectedly large ({size} bytes)")]
    TooLarge {
        /// Offending path.
        path: String,
        /// Observed size.
        size: u64,
    },
    /// The TOML does not parse (unknown keys included).
    ///
    /// The message is [`kernel_core::describe_toml_error`]: a line/column and
    /// a syntax description, never the offending text.
    #[error("parsing MCP configuration at {path}: {message}")]
    Parse {
        /// Offending path or source label.
        path: String,
        /// Parser-rendered syntax error.
        message: String,
    },
    /// The TOML parsed but names something unusable.
    #[error("invalid MCP configuration: {reason}")]
    Invalid {
        /// Human-readable, secret-free reason.
        reason: String,
    },
}

fn invalid(reason: impl Into<String>) -> McpConfigError {
    McpConfigError::Invalid {
        reason: reason.into(),
    }
}

/// A server id or agent name as a refusal may show it: debug-quoted, or
/// `placeholder` when [`looks_like_secret`] reads it as a credential (a key
/// pasted as the id is still a valid slug).
///
/// A percent-encoded key is the same key, so a decoded copy is read too:
/// `%73k-…` and `%2573k-…` are hidden just like `sk-…` is, and so is every
/// deeper layer (`%25252573k-…`).
fn shown(value: &str, placeholder: &str) -> String {
    if looks_like_secret(value) || looks_like_secret_decoded(value) {
        placeholder.to_string()
    } else {
        format!("{value:?}")
    }
}

/// Whether `value` reads as a credential in a percent-decoded copy of it.
/// Bytes that are not valid UTF-8 cannot be shown safely, so they count as a
/// credential too.
fn looks_like_secret_decoded(value: &str) -> bool {
    // The detector has read the value once already: that read is charged to
    // the budget too.
    decoded_copy_is_secret_shaped(value, value.len(), looks_like_secret)
}

/// How many percent-escape layers are peeled before a value is taken at face
/// value: `%73k-…`, `%2573k-…` and `%252573k-…` are one key.
const MAX_DECODE_ROUNDS: usize = 16;

/// The work budget of one value: every byte the detector or the decoder
/// reads is charged, so the whole check stays within 16 × the length of the
/// input and never exceeds 4 MiB.
const MAX_REDACT_WORK: usize = 4 * 1024 * 1024;

/// Whether a percent-decoded copy of `value` reads as a credential.
///
/// The decoder peels one escape layer per round and `secret_shaped` is called
/// with every copy as it is produced: only the current copy is ever kept, so
/// a value that nests its escapes deeply cannot pile up into a pile of
/// copies.
///
/// The work is bounded twice over: at most [`MAX_DECODE_ROUNDS`] rounds, and
/// at most [`MAX_REDACT_WORK`] bytes of work across the whole check — every
/// byte the detector and the decoder read is charged, so the bytes decoded
/// stay within 16 × the length of the input and the total never exceeds
/// 4 MiB. A value that is still changing when the budget or the round cap
/// runs out cannot be shown safely: it counts as secret-shaped.
fn decoded_copy_is_secret_shaped(
    value: &str,
    mut spent: usize,
    secret_shaped: impl Fn(&str) -> bool,
) -> bool {
    let budget = value.len().saturating_mul(16).min(MAX_REDACT_WORK);
    let mut current = value.to_string();
    for _ in 0..MAX_DECODE_ROUNDS {
        // A round that does not fit the budget is never started.
        if spent.saturating_add(current.len()) > budget {
            return true;
        }
        spent = spent.saturating_add(current.len());
        let next = match String::from_utf8(percent_decode_bytes(&current)) {
            Ok(next) => next,
            // Bytes that are not valid UTF-8 cannot be shown safely.
            Err(_) => return true,
        };
        if next == current {
            // The text stopped changing: there is no deeper copy to read.
            return false;
        }
        // The detector reads the copy too: its bytes are charged as well.
        if spent.saturating_add(next.len()) > budget {
            return true;
        }
        spent = spent.saturating_add(next.len());
        if secret_shaped(&next) {
            return true;
        }
        current = next;
    }
    // The round cap ran out while the text was still changing.
    true
}

/// `[a-z0-9-]{1,32}`.
fn valid_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// An agent name accepted by the daemon: short, ASCII, no path characters.
fn valid_agent(agent: &str) -> bool {
    (1..=64).contains(&agent.len())
        && agent
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// A shell-style env name, bounded and never an Auxesis-reserved key.
fn validate_env_name(server: &str, name: &str) -> Result<(), ServerRefusal> {
    let server = shown(server, "<id>");
    if name.len() > MAX_MCP_ENV_NAME_BYTES || !crate::stdio::env_key_declared(name) {
        return Err(refuse(
            "invalid_env_name",
            format!("server {server} declares an invalid or reserved env name"),
        ));
    }
    Ok(())
}

/// `https`, or plain `http` on loopback only.
fn validate_http_url(server: &str, url: &str) -> Result<(), ServerRefusal> {
    let server = shown(server, "<id>");
    if url.len() > MAX_MCP_URL_BYTES {
        return Err(refuse(
            "invalid_url",
            format!("server {server} has an over-long url"),
        ));
    }
    if looks_like_secret(url) {
        return Err(refuse(
            "secret_in_config",
            format!(
                "server {server} url carries a secret-looking value; keep secrets in ~/.auxesis/.env"
            ),
        ));
    }
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| refuse("invalid_url", format!("server {server} has an invalid url")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(refuse(
            "secret_in_config",
            format!("server {server} must not embed credentials in its url"),
        ));
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(parsed.host_str()) => Ok(()),
        _ => Err(refuse(
            "endpoint_insecure",
            format!(
                "server {server} must use https (http is allowed only for 127.0.0.1/localhost)"
            ),
        )),
    }
}

/// Extra, non-binding classification for one stdio launch.
///
/// The denylist below is **warning text only**: the security boundary is the
/// mandatory per-server confirmation (plus the hard container refusals in
/// [`evaluate_stdio_policy`]). A launcher classified here is shown as
/// "high risk" to the owner; it is never silently allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StdioPolicy {
    /// Stable, content-free warning label, `None` for an ordinary binary.
    pub high_risk: Option<&'static str>,
}

impl StdioPolicy {
    /// Whether the launcher class is flagged as high risk.
    pub fn is_high_risk(&self) -> bool {
        self.high_risk.is_some()
    }
}

/// Shells and script engines that evaluate arbitrary text: high-risk warning.
///
/// Item 3 keeps `osascript` and `awk` here (warning only, still confirmed).
/// The shells that cannot be reduced to one allowlisted `execve` shape moved
/// to [`WRAPPER_LAUNCHERS`] and are refused outright.
const EVAL_LAUNCHERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "osascript",
    "awk",
    "gawk",
    "deno",
    "bun",
];
/// Interpreters: a script file is ordinary, but an eval flag is high-risk.
const INTERPRETERS: &[&str] = &[
    "node", "nodejs", "python", "ruby", "perl", "php", "lua", "tclsh", "rscript", "r", "julia",
    "nu", "octave", "raku", "swift",
];
/// Package runners that download and execute code: high-risk warning.
const PACKAGE_RUNNERS: &[&str] = &[
    "npx", "npm", "pnpm", "yarn", "bunx", "uvx", "uv", "pipx", "pip", "corepack",
];
/// Wrapper and shell launchers **refused outright** (items 2-3).
///
/// Each one either re-executes another program (`env`, `nice`, `timeout`,
/// `nohup`, `sudo`, `doas`, `su`, `xargs`, `stdbuf`, `taskset`, `chrt`,
/// `caffeinate`, `arch`, `script`, `exec`, `command`, `sandbox-exec`, `open`)
/// or evaluates arbitrary text (the POSIX and PowerShell shells plus
/// `busybox`). None can be reduced to the one pinned, secret-free `execve` the
/// stdio transport needs, so there is deliberately **no** warning-only path
/// for them: `argv[0]` naming any of these is refused with the stable code
/// `wrapper_launcher`. `osascript`, `awk` and `python -m` stay warning-only
/// (`high_risk`) — the denylist is defence in depth, never the boundary.
const WRAPPER_LAUNCHERS: &[&str] = &[
    "env",
    "nice",
    "timeout",
    "nohup",
    "sudo",
    "doas",
    "su",
    "xargs",
    "stdbuf",
    "taskset",
    "chrt",
    "caffeinate",
    "arch",
    "script",
    "time",
    "exec",
    "command",
    "sandbox-exec",
    "open",
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "pwsh",
    "powershell",
    "busybox",
];
/// Whole tokens that identify a container CLI (item 4).
///
/// Matched as `-`/`_`/`.`-separated parts of the lowercased basename, never as
/// substrings: `dockerize`/`mydockerhelper` are ordinary binaries, while
/// `podman-remote-static-linux_amd64` still resolves to `podman`. `buildah`,
/// `ctr`, Apple's `container` and `orbctl` go through the same `run` allowlist
/// as docker, and are refused when their shape differs.
const CONTAINER_CLI_TOKENS: &[&str] = &[
    "docker",
    "podman",
    "nerdctl",
    "buildah",
    "ctr",
    "container",
    "orbctl",
    "orb",
];
/// The whole token naming a compose launcher refused outright (item 4): a
/// `compose` file is a whole program that can mount, escalate and pull.
const CONTAINER_COMPOSE_TOKEN: &str = "compose";
/// Whole tokens naming a VM manager refused outright (item 4): none of them
/// can be reduced to the one allowlisted `run` shape.
const CONTAINER_VM_TOKENS: &[&str] = &["lima", "limactl", "colima", "finch"];

/// Basename of `command`, lowercased, with trailing version digits removed so
/// `python3.12` and `node18` are classified as `python` and `node`.
fn launcher_name(command: &str) -> String {
    let base = Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
        .to_owned()
}

/// Whether one argument switches an interpreter into eval mode: `--eval`,
/// `--print`, `--execute`/`--module` (with or without `=`) or a short option
/// cluster that carries `c`, `e`, `p`, `E`, `m` or `r` (`-c`, `-Bc`, `-pe`,
/// `-ne`, `-E`, `-r`, `-m`). Item 3 keeps this a **warning only**: `python -m`
/// is high-risk, never a hard refusal.
fn is_eval_flag(arg: &str) -> bool {
    if arg.starts_with("--") {
        let name = arg.split('=').next().unwrap_or(arg);
        return matches!(
            name,
            "--eval" | "--print" | "--execute" | "--exec" | "--import" | "--module"
        );
    }
    arg.len() > 1
        && arg.starts_with('-')
        && arg[1..]
            .chars()
            .any(|c| matches!(c, 'c' | 'e' | 'p' | 'E' | 'm' | 'r'))
}

/// Split a long flag into its name and an inline `=value`, if any.
fn long_flag(arg: &str) -> Option<(&str, Option<&str>)> {
    if !arg.starts_with("--") {
        return None;
    }
    match arg.split_once('=') {
        Some((name, value)) => Some((name, Some(value))),
        None => Some((arg, None)),
    }
}

/// Classify one stdio launch, as warning text only.
pub fn stdio_risk_label(command: &str, args: &[String]) -> Option<&'static str> {
    // Classify the path as written and as it resolves, so a symlink named
    // `helper` that points at `/bin/sh` is still a shell.
    let mut names = vec![launcher_name(command)];
    if let Ok(real) = std::fs::canonicalize(command) {
        names.push(launcher_name(&real.to_string_lossy()));
    }
    let is = |list: &[&str]| names.iter().any(|name| list.contains(&name.as_str()));
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let has = |needle: &str| argv.contains(&needle);
    let contains = |needle: &str| argv.iter().any(|arg| arg.contains(needle));
    if is(EVAL_LAUNCHERS) {
        return Some("shell_launcher");
    }
    if names
        .iter()
        .any(|name| name.contains("npx") || name.contains("npm") || name.contains("uvx"))
        || is(PACKAGE_RUNNERS)
    {
        return Some("package_runner");
    }
    if names.iter().any(|name| name == "ssh") && contains("ProxyCommand") {
        return Some("ssh_proxycommand");
    }
    if names.iter().any(|name| name == "find") && (has("-exec") || has("-execdir")) {
        return Some("find_exec");
    }
    if names.iter().any(|name| name == "git")
        && has("-c")
        && (contains("core.fsmonitor") || contains("core.hooksPath") || contains("core.pager"))
    {
        return Some("git_config_override");
    }
    if is(WRAPPER_LAUNCHERS) {
        return Some("wrapper_launcher");
    }
    if is(INTERPRETERS) && argv.iter().any(|arg| is_eval_flag(arg)) {
        return Some("interpreter_eval");
    }
    if names_carry_token(&names, CONTAINER_CLI_TOKENS) {
        return Some("container_cli");
    }
    None
}

/// Every name `command` can be known by: as written and as it resolves.
fn launcher_names(command: &str) -> Vec<String> {
    let mut names = vec![launcher_name(command)];
    if let Ok(real) = std::fs::canonicalize(command) {
        names.push(launcher_name(&real.to_string_lossy()));
    }
    names
}

/// Whether any of `names` carries one of `tokens` as a whole `-`/`_`/`.`
/// separated part (item 4).
///
/// `launcher_name` already lowercases the basename, so the comparison is
/// case-insensitive. Whole-token matching, never substring: `dockerize`,
/// `mydockerhelper`, `composer` and `climate-mcp` are ordinary binaries while
/// `podman-remote-static-linux_amd64`, `docker-compose-v2` and `Docker-Real`
/// still classify as before.
fn names_carry_token(names: &[String], tokens: &[&str]) -> bool {
    names.iter().any(|name| {
        name.split(['-', '_', '.'])
            .any(|part| tokens.contains(&part))
    })
}

/// Whether `command` names a wrapper or shell launcher refused outright
/// (items 2-3), as written or after symlink resolution.
pub fn wrapper_launcher_label(command: &str) -> Option<&'static str> {
    let names = launcher_names(command);
    names
        .iter()
        .any(|name| WRAPPER_LAUNCHERS.contains(&name.as_str()))
        .then_some("wrapper_launcher")
}

/// Whether `command` names a container CLI, as written or resolved.
///
/// Matched by whole token (item 4), so `podman-remote-static-linux_amd64`, a
/// `docker-real` shim or a case variant all go through the same `run`
/// allowlist, while a substring such as `dockerize` does not.
fn is_container_launcher(command: &str) -> bool {
    names_carry_token(&launcher_names(command), CONTAINER_CLI_TOKENS)
}

/// Whether `command` is a compose/Van Damme wrapper refused outright.
///
/// A basename carrying the whole token `compose` (`docker-compose`, a
/// `*-compose` shim) and the VM managers `lima`/`limactl`, `colima` and `finch`
/// are refused whatever their arguments: none of them can be reduced to the
/// allowlisted one-`run` shape.
fn is_refused_container_wrapper(command: &str) -> Option<&'static str> {
    let names = launcher_names(command);
    if names_carry_token(&names, &[CONTAINER_COMPOSE_TOKEN]) {
        return Some("container_compose");
    }
    if names_carry_token(&names, CONTAINER_VM_TOKENS) {
        return Some("container_vm_tool");
    }
    None
}

/// Whether `value` is a plain environment-variable NAME (no `=`, no value).
fn is_container_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MCP_ENV_NAME_BYTES
        && !value.contains('=')
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
        })
}

/// Whether `value` is a container name (bounded, no option look-alike).
fn is_container_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Whether `value` is a `--pull` policy the allowlist accepts.
fn is_container_pull(value: &str) -> bool {
    value.eq_ignore_ascii_case("never") || value.eq_ignore_ascii_case("missing")
}

/// One parsed `run` shape: the network mode the container would use, if any.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ContainerRun {
    /// `--network` value, lowercase (`none` or `bridge`), when present.
    network: Option<String>,
}

/// The whole allowlist for a container CLI (items 1-3).
///
/// Only this shape is accepted:
///
/// `<cli> run [--rm] [-i] [-t] [--init] [--read-only]
///  [--network=none|bridge] [-e NAME]... [--name X]
///  [--pull=never|missing] IMAGE [ARGS...]`
///
/// Every other flag before IMAGE is refused with a stable reason, which
/// subsumes every mount (`-v`, `--mount`, `--volumes-from`), capability
/// (`--cap-add`), device, namespace (`--ipc`, `--uts`, `--userns`, `--pid`),
/// `--privileged`, `--security-opt`, `-u` and the container socket. `-e`
/// takes env NAMES only: `NAME=value` and `--env-file` are refused. Clustered
/// short flags are expanded before checking and case does not matter.
fn container_run_shape(args: &[String]) -> Result<ContainerRun, &'static str> {
    let Some(first) = args.first() else {
        return Err("container_subcommand");
    };
    if !first.eq_ignore_ascii_case("run") {
        return Err("container_subcommand");
    }
    let mut run = ContainerRun::default();
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if !arg.starts_with('-') {
            // IMAGE, then its own args: accepted verbatim.
            return Ok(run);
        }
        if arg == "--" {
            return Err("container_flag");
        }
        if let Some((name, inline)) = long_flag(arg) {
            let name = name.to_ascii_lowercase();
            match name.as_str() {
                "--rm" | "--init" | "--read-only" => {
                    if inline.is_some() {
                        return Err("container_flag");
                    }
                    index += 1;
                }
                "--network" => {
                    let value = inline
                        .map(str::to_owned)
                        .or_else(|| args.get(index + 1).cloned());
                    let Some(value) = value else {
                        return Err("container_network");
                    };
                    if !value.eq_ignore_ascii_case("none") && !value.eq_ignore_ascii_case("bridge")
                    {
                        return Err("container_network");
                    }
                    run.network = Some(value.to_ascii_lowercase());
                    index += if inline.is_some() { 1 } else { 2 };
                }
                "--env" => {
                    let value = inline
                        .map(str::to_owned)
                        .or_else(|| args.get(index + 1).cloned());
                    if !value.as_deref().is_some_and(is_container_env_name) {
                        return Err("container_env_value");
                    }
                    index += if inline.is_some() { 1 } else { 2 };
                }
                "--name" => {
                    let value = inline
                        .map(str::to_owned)
                        .or_else(|| args.get(index + 1).cloned());
                    if !value.as_deref().is_some_and(is_container_name) {
                        return Err("container_name");
                    }
                    index += if inline.is_some() { 1 } else { 2 };
                }
                "--pull" => {
                    let value = inline
                        .map(str::to_owned)
                        .or_else(|| args.get(index + 1).cloned());
                    if !value.as_deref().is_some_and(is_container_pull) {
                        return Err("container_pull");
                    }
                    index += if inline.is_some() { 1 } else { 2 };
                }
                _ => return Err("container_flag"),
            }
            continue;
        }
        // A clustered/attached short flag: expand one character at a time.
        let body = &arg[1..];
        let mut chars = body.chars();
        let mut short_ok = true;
        let mut consumed_value = false;
        while let Some(flag) = chars.next() {
            match flag.to_ascii_lowercase() {
                'i' | 't' => {}
                'e' => {
                    let rest: String = chars.collect();
                    let value = if rest.is_empty() {
                        consumed_value = true;
                        args.get(index + 1).cloned().unwrap_or_default()
                    } else {
                        rest.strip_prefix('=').unwrap_or(&rest).to_owned()
                    };
                    if !is_container_env_name(&value) {
                        return Err("container_env_value");
                    }
                    break;
                }
                _ => {
                    short_ok = false;
                    break;
                }
            }
        }
        if !short_ok {
            return Err("container_flag");
        }
        index += if consumed_value { 2 } else { 1 };
    }
    Err("container_image_missing")
}

/// Refuse a container launch the policy does not allow (items 1-4).
///
/// `network` is the server's declared network flag. A container server with
/// `network = false` **must** carry `--network=none`: an absent flag (which
/// would default to bridge) and `--network=bridge` are both refused, because
/// otherwise the declared `network = false` would not actually constrain the
/// container. Documented choice: refuse rather than rewrite the argv, so the
/// confirmed launch spec stays exactly what the owner reviewed.
fn container_policy_refusal(command: &str, args: &[String], network: bool) -> Option<&'static str> {
    if let Some(label) = is_refused_container_wrapper(command) {
        return Some(label);
    }
    if !is_container_launcher(command) {
        return None;
    }
    if args
        .first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case(CONTAINER_COMPOSE_TOKEN))
    {
        return Some("container_compose");
    }
    match container_run_shape(args) {
        Err(label) => Some(label),
        Ok(run) => {
            if network {
                return None;
            }
            match run.network.as_deref() {
                Some("none") => None,
                _ => Some("container_network"),
            }
        }
    }
}

/// Percent-decode `value` before the secret checks (item 5), so an encoded
/// separator cannot hide a `token%3Dabc` / `key%3Avalue` pair. An invalid or
/// truncated escape is left exactly as written; the bytes are decoded raw, so
/// a valid UTF-8 sequence round-trips and anything else is lossily replaced.
fn percent_decoded(value: &str) -> String {
    String::from_utf8_lossy(&percent_decode_bytes(value)).into_owned()
}

/// The bytes of `value` after one percent-decoding round: every valid `%XX`
/// escape replaced by its byte. An invalid or truncated escape is left
/// exactly as written.
fn percent_decode_bytes(value: &str) -> Vec<u8> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                out.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// Whether a value looks like a credential: a known token prefix, a
/// `token=`/`api-key`/`password` style flag or query parameter, a JWT, an AWS
/// key id, or userinfo embedded in a URL. Such values belong in
/// `~/.auxesis/.env`, never in an argument, URL or config file.
///
/// The value is percent-decoded first (item 5): `token%3Dabc` is the same
/// request as `token=abc`, so it must be refused too.
pub fn looks_like_secret(value: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "--api-key",
        "--api_key",
        "--apikey",
        "--access-token",
        "--access_token",
        "--auth-token",
        "--auth_token",
        "--token",
        "--private-key",
        "--private_key",
        "--password",
        "--passwd",
        "--client-secret",
        "--client_secret",
        "--secret",
        "?token=",
        "&token=",
        "token=",
        "api_key=",
        "api-key=",
        "apikey=",
        "?secret=",
        "&secret=",
        "secret=",
        "?access_key=",
        "&access_key=",
        "access_key=",
        "x-api-key",
        "authorization: bearer",
        "authorization:bearer",
        "access_token=",
        "password=",
        "passwd=",
        "ghp_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "sk_live_",
        "sk_test_",
        "bearer ",
    ];
    let value = &percent_decoded(value);
    let lower = value.to_ascii_lowercase();
    if NEEDLES.iter().any(|needle| lower.contains(needle)) {
        return true;
    }
    // `?key=` / `&key=` / a leading `key=`, so `monkey=` is not a false hit.
    let key_needle = lower.starts_with("key=")
        || lower.contains("?key=")
        || lower.contains("&key=")
        || lower.contains("?apikey=")
        || lower.contains("&apikey=");
    if key_needle {
        return true;
    }
    // `sk-…` keys: a word-initial `sk-` followed by a plausible key body, so
    // ordinary words such as `task-list` or `desk-top` do not trip the check.
    let sk = lower.match_indices("sk-").any(|(index, _)| {
        let word_start = index == 0 || !lower.as_bytes()[index - 1].is_ascii_alphanumeric();
        let body = lower.as_bytes()[index + 3..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_' || **b == b'-')
            .count();
        word_start && body >= 8
    });
    if sk {
        return true;
    }
    // AWS access-key id: `AKIA` + 16 uppercase alphanumerics. Every occurrence
    // is checked, so a decoy prefix cannot hide a real key later in the string.
    if value.match_indices("AKIA").any(|(index, _)| {
        value[index + 4..]
            .bytes()
            .take_while(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            .count()
            >= 16
    }) {
        return true;
    }
    // JWT: a word-initial `eyJ` header, two `.`-separated segments, long enough.
    if lower.match_indices("eyj").any(|(index, _)| {
        let word_start = index == 0 || !lower.as_bytes()[index - 1].is_ascii_alphanumeric();
        word_start && value[index..].len() >= 24 && value[index..].matches('.').count() >= 2
    }) {
        return true;
    }
    has_userinfo(value) || structured_secret_pair(value)
}

/// Whether `key` names a secret: the key is normalised (`-`/`.` folded to `_`,
/// case ignored) and then matched **part by part** (item 5), so `API-KEY`,
/// `api_key` and `X-Api-Key` all count while `monkey`, `--author=` and
/// `tokenizer` do not.
///
/// A needle matches only when it is one whole `_`-separated part of the key,
/// or the entire key. That is what keeps `author` from tripping `auth` and
/// `tokenizer` from tripping `token`; `api_key`/`access_key`/`private_key`
/// still match through their `key` part.
fn key_looks_like_secret(key: &str) -> bool {
    const KEY_NEEDLES: &[&str] = &[
        "token", "apikey", "password", "passwd", "secret", "auth", "key", "bearer",
    ];
    let normalized = key
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase()
        .replace(['-', '.'], "_");
    normalized
        .split('_')
        .any(|part| !part.is_empty() && KEY_NEEDLES.contains(&part))
}

/// Whether `value` carries a structured `key<sep>value` pair whose key names a
/// secret (item 5): JSON `"key":"value"`, `key: value`, `key=value` and
/// `key:value`. A non-empty value is enough to refuse.
fn structured_secret_pair(value: &str) -> bool {
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b':' && *byte != b'=' {
            continue;
        }
        // Walk back over the key, skipping spaces and a closing quote.
        let mut end = index;
        while end > 0 && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        if end > 0 && matches!(bytes[end - 1], b'"' | b'\'') {
            end -= 1;
        }
        let mut start = end;
        while start > 0
            && (bytes[start - 1].is_ascii_alphanumeric()
                || matches!(bytes[start - 1], b'_' | b'-' | b'.'))
        {
            start -= 1;
        }
        if start == end || !key_looks_like_secret(&value[start..end]) {
            continue;
        }
        // Walk forward over the value, skipping spaces and an opening quote.
        let mut value_start = index + 1;
        while value_start < bytes.len() && matches!(bytes[value_start], b' ' | b'\t') {
            value_start += 1;
        }
        if value_start < bytes.len() && matches!(bytes[value_start], b'"' | b'\'') {
            value_start += 1;
        }
        if value_start < bytes.len()
            && !matches!(bytes[value_start], b'"' | b'\'' | b']' | b'}' | b',')
        {
            return true;
        }
    }
    false
}

/// Whether a value embeds `user:password@host` userinfo.
fn has_userinfo(value: &str) -> bool {
    let authority = match value.find("://") {
        Some(scheme) => &value[scheme + 3..],
        None => {
            // A bare `user:pass@host` argument.
            let Some(at) = value.find('@') else {
                return false;
            };
            let before = &value[..at];
            return !before.contains('/') && before.contains(':') && !before.contains(' ');
        }
    };
    let end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    let userinfo_host = &authority[..end];
    let Some(at) = userinfo_host.find('@') else {
        return false;
    };
    userinfo_host[..at].contains(':')
}

/// The one stdio launch policy, shared by config validation, the add API and
/// import: an absolute command, a refusal of wrapper/shell launchers, bounded
/// NUL-free arguments, secret-looking arguments, and the container hard
/// refusals.
///
/// `network` is the server's declared network flag; a container server that
/// declares `network = false` must carry `--network=none` (item 4).
///
/// A wrapper or shell as `argv[0]` is refused outright with `wrapper_launcher`
/// (item 2) — no warning-only path. The remaining launcher classes
/// (interpreter eval, package runner, container) are reported as `high_risk`
/// warning text and **still require the owner's per-server confirmation** —
/// the denylist is not the boundary.
pub fn evaluate_stdio_policy(
    server: &str,
    command: &str,
    args: &[String],
    network: bool,
) -> Result<StdioPolicy, ServerRefusal> {
    let server = shown(server, "<id>");
    if command.is_empty() || command.contains('\0') || !Path::new(command).is_absolute() {
        return Err(refuse(
            "command_refused",
            format!("server {server} stdio command must be an absolute path"),
        ));
    }
    if command.len() > MAX_MCP_ARG_BYTES {
        return Err(refuse(
            "command_refused",
            format!("server {server} stdio command is too long"),
        ));
    }
    if let Some(label) = wrapper_launcher_label(command) {
        return Err(refuse(
            label,
            format!("server {server} uses a wrapper or shell launcher, which is refused"),
        ));
    }
    if args.len() > crate::stdio::MAX_ARGS {
        return Err(refuse(
            "command_refused",
            format!("server {server} declares too many stdio arguments"),
        ));
    }
    for (index, arg) in args.iter().enumerate() {
        if arg.contains('\0') || arg.len() > MAX_MCP_ARG_BYTES {
            return Err(refuse(
                "command_refused",
                format!("server {server} declares an unusable stdio argument"),
            ));
        }
        if looks_like_secret(arg) {
            return Err(refuse(
                "secret_in_config",
                format!(
                    "server {server} has a secret-looking argument; keep secrets in ~/.auxesis/.env and list the variable name in env"
                ),
            ));
        }
        if secret_pair_refused(args, index) {
            return Err(refuse(
                "secret_in_config",
                format!(
                    "server {server} has a secret-looking flag value; keep secrets in ~/.auxesis/.env and list the variable name in env"
                ),
            ));
        }
    }
    let high_risk = stdio_risk_label(command, args);
    if let Some(label) = container_policy_refusal(command, args, network) {
        return Err(refuse(
            label,
            format!("server {server} container launch is not allowed ({label})"),
        ));
    }
    Ok(StdioPolicy { high_risk })
}

/// Whether a value looks like a secret for the split flag forms: a known token
/// prefix, or at least 12 characters mixing letters and digits.
fn value_is_secret_like(value: &str) -> bool {
    if looks_like_secret(value) {
        return true;
    }
    let has_letter = value.bytes().any(|byte| byte.is_ascii_alphabetic());
    let has_digit = value.bytes().any(|byte| byte.is_ascii_digit());
    value.len() >= 12 && has_letter && has_digit
}

/// Whether the value of a `--key`/`-k` flag is secret-looking.
///
/// Item 6: an all-letters value of 12 characters or more is a plausible
/// passphrase even without a digit, so it is refused alongside the mixed
/// letter/digit form.
fn key_value_refused(value: &str) -> bool {
    if value_is_secret_like(value) {
        return true;
    }
    value.len() >= 12 && value.bytes().all(|byte| byte.is_ascii_alphabetic())
}

/// Whether the flag at `args[index]` takes a **secret value** in the next token
/// or inline, including the split spellings (items 5/10): `--access-token`,
/// `--auth-token`, `--api_key`/`--api-key`, `--private-key`, `--token`,
/// `--password`, `--client-secret`, `--secret`, `--key`/`-k`, `-u user:pass`,
/// `X-API-Key:` and `Authorization: Bearer` across two tokens, plus the
/// attached `-k<value>` form.
fn secret_pair_refused(args: &[String], index: usize) -> bool {
    let arg = args[index].as_str();
    // Attached short form: `-k0123456789ab` / `-k=0123456789ab`.
    if let Some(rest) = arg.strip_prefix("-k") {
        if !arg.starts_with("--") {
            let value = rest.strip_prefix('=').unwrap_or(rest);
            if !value.is_empty() && key_value_refused(value) {
                return true;
            }
        }
    }
    let (name, inline) = long_flag(arg)
        .map(|(name, value)| (name.to_ascii_lowercase(), value.map(str::to_owned)))
        .unwrap_or_else(|| (arg.to_ascii_lowercase(), None));
    let next = args.get(index + 1).map(String::as_str);
    let next_lower = next.map(str::to_ascii_lowercase);
    let value = inline.as_deref().or(next);
    match name.as_str() {
        // `-K` lowercases to `-k`, so one arm covers both.
        "-k" | "--key" => value.is_some_and(key_value_refused),
        "--client-secret" | "--secret" => value.is_some_and(|value| !value.is_empty()),
        "--access-token" | "--auth-token" | "--api-key" | "--api_key" | "--apikey"
        | "--private-key" | "--token" | "--password" | "--passwd" => {
            value.is_some_and(value_is_secret_like)
        }
        "-u" | "--user" => value.is_some_and(|value| value.contains(':')),
        "-h" | "--header" => value.is_some_and(|value| {
            let lower = value.to_ascii_lowercase();
            (lower.contains("authorization:") || lower.contains("x-api-key"))
                && (lower.contains("bearer") || lower.contains("x-api-key"))
        }),
        _ => {
            let next_is_value = next_lower
                .as_deref()
                .is_some_and(|value| !value.is_empty() && !value.starts_with('-'));
            let auth_then_bearer = (name.ends_with("authorization:") || name == "authorization:")
                && next_lower
                    .as_deref()
                    .is_some_and(|value| value.starts_with("bearer"));
            let api_key_then_value =
                (name.ends_with("x-api-key:") || name == "x-api-key:") && next_is_value;
            auth_then_bearer || api_key_then_value
        }
    }
}

/// Whether a URL host is loopback (plain `http` allowed there only).
pub fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(
        host,
        Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    fn docker(argv: &[&str]) -> Result<StdioPolicy, ServerRefusal> {
        evaluate_stdio_policy("docker", "/usr/local/bin/docker", &args(argv), true)
    }

    fn docker_without_network(argv: &[&str]) -> Result<StdioPolicy, ServerRefusal> {
        evaluate_stdio_policy("docker", "/usr/local/bin/docker", &args(argv), false)
    }

    #[test]
    fn an_unknown_key_is_refused_without_quoting_it() {
        let err = McpConfig::parse("mcp.toml", "sk-abc = 1\n").unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        assert!(!shown.contains("abc") && !debug.contains("abc"), "{debug}");
        assert!(shown.contains("unknown top-level key"), "{shown}");
    }

    #[test]
    fn a_refusal_never_quotes_a_secret_shaped_id_or_agent() {
        // CONFIG-ERR-ECHO-2: a slug-valid key as the server id or agent name,
        // and an id that fails the slug check.
        let (id, stdio) = ("sk-proj-canary-7f3k9q", "transport = \"stdio\"\ncommand");
        let agents = |agent: &str| {
            format!("id = \"x\"\n{stdio} = \"/bin/x\"\nagents = {{ {agent} = [\"a b\"] }}")
        };
        for (body, kept) in [
            (
                format!("id = \"{id}\"\ntransport = \"http\""),
                "server <id> is http",
            ),
            (
                format!("id = \"{id}\"\ntransport = \"http\"\nurl = \"http://h.test\""),
                "server <id> must use https",
            ),
            (
                format!("id = \"{id}\"\n{stdio} = \"relative\""),
                "server <id> stdio command",
            ),
            (
                "id = \"Sk-CANARY-7f3k9q\"\ntransport = \"http\"".into(),
                "server id must match",
            ),
            (
                agents(id),
                "server \"x\" lists an unusable tool name for agent <agent>",
            ),
            (
                agents("\"sk CANARY\""),
                "server \"x\" names an invalid agent",
            ),
        ] {
            let text = format!("[[server]]\n{body}\n");
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let refusal = config.server[0].check().unwrap_err();
            let err = config.validate().unwrap_err();
            let (shown, debug) = (err.to_string(), format!("{err:?}{refusal:?}"));
            assert!(!debug.to_lowercase().contains("canary"), "{debug}");
            assert!(shown.contains(kept), "{shown}");
        }
        let text = format!("[[server]]\nid = \"{id}\"\ntransport = \"http\"\n");
        let mut twins = McpConfig::parse("mcp.toml", &text).unwrap();
        twins.server.push(twins.server[0].clone());
        let err = twins.validate_structural().unwrap_err().to_string();
        assert!(err.contains("duplicate server id <id>"), "{err}");
    }

    #[test]
    fn a_refusal_never_quotes_a_percent_encoded_id_or_agent() {
        // CONFIG-ERR-ECHO-2 (review): `%73k-…` is the same key as `sk-…`, and
        // so are `%2573k-…` (encoded twice) and `%53K-…` (the same bytes,
        // another case). None of them may reach a refusal.
        for id in [
            "sk-proj-canary-7f3k9q",
            "%73k-proj-canary-7f3k9q",
            "%2573k-proj-canary-7f3k9q",
            "%53K-PROJ-canary-7f3k9q",
        ] {
            let text = format!("[[server]]\nid = \"{id}\"\ntransport = \"http\"\n");
            let mut twins = McpConfig::parse("mcp.toml", &text).unwrap();
            twins.server.push(twins.server[0].clone());
            let err = twins.validate_structural().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            assert!(err.contains("duplicate server id <id>"), "{err}");
            // The same id in a refusal that names the server.
            let text = format!(
                "[[server]]\nid = \"{id}\"\ntransport = \"http\"\nurl = \"http://h.test\"\n"
            );
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let err = config.validate().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            // The agent name is the same key.
            let text = format!(
                "[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = \"/bin/x\"\nagents = {{ \"{id}\" = [\"a b\"] }}\n"
            );
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let err = config.validate().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
        }
    }

    #[test]
    fn a_refusal_never_quotes_a_key_hidden_however_many_times_it_is_encoded() {
        // CONFIG-ECHO-DECODE-LOOP: `%25252573k-…` is the same key as `sk-…`,
        // four escape layers deep, and `%252525252573k-…` six layers deep. The
        // decoder peels every layer, so neither reaches a refusal.
        for id in [
            "%25252573k-proj-canary-7f3k9q",
            "%252525252573k-proj-canary-7f3k9q",
        ] {
            let text = format!("[[server]]\nid = \"{id}\"\ntransport = \"http\"\n");
            let mut twins = McpConfig::parse("mcp.toml", &text).unwrap();
            twins.server.push(twins.server[0].clone());
            let err = twins.validate_structural().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            assert!(err.contains("duplicate server id <id>"), "{err}");
            // The same id in a refusal that names the server.
            let text = format!(
                "[[server]]\nid = \"{id}\"\ntransport = \"http\"\nurl = \"http://h.test\"\n"
            );
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let err = config.validate().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
            // The agent name is the same key.
            let text = format!(
                "[[server]]\nid = \"x\"\ntransport = \"stdio\"\ncommand = \"/bin/x\"\nagents = {{ \"{id}\" = [\"a b\"] }}\n"
            );
            let config = McpConfig::parse("mcp.toml", &text).unwrap();
            let err = config.validate().unwrap_err().to_string();
            assert!(!err.to_lowercase().contains("canary"), "{err}");
        }
    }

    #[test]
    fn a_megabyte_of_nested_escapes_is_hidden_and_the_work_stays_bounded() {
        // CONFIG-ECHO-DECODE-LOOP (review): a value that nests its escapes
        // deeply must not make the decoder work without bound. The decoder
        // stops at its budget while the text is still changing, so the value
        // is hidden — and it stops fast.
        let canary = format!("%25{}73k-proj-canary-7f3k9q", "25".repeat(98));
        let value = format!("{canary}{}", "x".repeat(1_000_000 - canary.len()));
        let started = std::time::Instant::now();
        let shown = shown(&value, "<id>");
        let elapsed = started.elapsed();
        assert_eq!(shown, "<id>", "{shown}");
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the decoder took {elapsed:?} on a megabyte"
        );
    }

    #[test]
    fn a_parse_error_names_the_line_and_never_quotes_it() {
        let text = "[[server]]\nid = \"x\"\ntoken = \"sk-CANARY-1234567890abcdef\n";
        let err = McpConfig::parse("mcp.toml", text).unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        assert!(
            !shown.contains("CANARY") && !debug.contains("CANARY"),
            "{debug}"
        );
        assert!(shown.contains("mcp.toml: line 3"), "{shown}");
    }

    #[test]
    fn legacy_server_defaults_sensitive_and_plain_binary_is_allowed_but_high_risk_free() {
        let parsed = McpConfig::parse("test", "[[server]]\nid = \"legacy\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n").unwrap();
        assert_eq!(parsed.server[0].data_class, McpDataClass::Sensitive);
        let policy = evaluate_stdio_policy(
            "plain",
            "/usr/local/bin/ripgrep",
            &args(&["--stdio"]),
            false,
        )
        .unwrap();
        assert!(!policy.is_high_risk());
    }

    #[test]
    fn confirmation_covers_the_whole_launch_and_needs_the_daemon_key() {
        let server = McpServerConfig {
            id: "plain".into(),
            catalog_id: None,
            data_class: McpDataClass::Sensitive,
            stdio_confirmed: true,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: McpTransport::Stdio,
            url: None,
            command: Some("/usr/local/bin/ripgrep".into()),
            args: args(&["--stdio"]),
            env: vec![],
            enabled: true,
            agents: Default::default(),
        };
        let secret = b"daemon-token";
        // Item 5: without the daemon key there is no binding at all, so a bare
        // bool or a plain hash is never confirmation.
        assert!(server.confirmation_binding(b"").is_none());
        assert!(!server.stdio_is_confirmed_with(b""));
        let mut hand_edited = server.clone();
        hand_edited.stdio_confirmation = Some("any-plain-value".into());
        assert!(!hand_edited.stdio_is_confirmed_with(b""));
        assert!(
            !server.stdio_is_confirmed_with(secret),
            "no hash stored yet"
        );

        // Item 4: every field of the launch spec is covered.
        let mut confirmed = server.clone();
        confirmed.stdio_confirmation = server.confirmation_binding(secret);
        assert!(confirmed.stdio_is_confirmed_with(secret));
        let mutators: [fn(&mut McpServerConfig); 7] = [
            |s| s.args = args(&["--stdio", "--quiet"]),
            |s| s.env = vec!["DATAGOUV_KEY".into()],
            |s| s.command = Some("/usr/local/bin/other".into()),
            |s| s.network = true,
            |s| s.data_class = McpDataClass::Public,
            |s| s.transport = McpTransport::Http,
            // Item 7: widening an agent's tools invalidates the confirmation.
            |s| {
                s.agents.insert("main".into(), vec!["tool".into()]);
            },
        ];
        for mutate in mutators {
            let mut changed = confirmed.clone();
            mutate(&mut changed);
            assert!(
                !changed.stdio_is_confirmed_with(secret),
                "a changed launch spec must invalidate the confirmation"
            );
        }

        // Item 4: a swapped binary invalidates the confirmation.
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("server");
        std::fs::write(&bin, b"one").unwrap();
        let mut file_server = server.clone();
        file_server.command = Some(bin.to_string_lossy().into_owned());
        let mut file_confirmed = file_server.clone();
        file_confirmed.stdio_confirmation = file_server.confirmation_binding(secret);
        assert!(file_confirmed.stdio_is_confirmed_with(secret));
        std::fs::write(&bin, b"two").unwrap();
        assert!(
            !file_confirmed.stdio_is_confirmed_with(secret),
            "a binary swapped after confirmation must be refused at spawn"
        );

        // A binding built from a verified (catalog) checksum equals the
        // file-read binding when the file matches, and a swap after the
        // check is still refused at spawn.
        std::fs::write(&bin, b"pinned").unwrap();
        let pinned_sha = binary_sha256(&bin);
        assert_eq!(
            file_server.confirmation_binding_for_sha(secret, &pinned_sha.to_ascii_uppercase()),
            file_server.confirmation_binding(secret)
        );
        let mut sha_confirmed = file_server.clone();
        sha_confirmed.stdio_confirmation =
            file_server.confirmation_binding_for_sha(secret, &pinned_sha);
        assert!(sha_confirmed.stdio_is_confirmed_with(secret));
        std::fs::write(&bin, b"replacement").unwrap();
        assert!(
            !sha_confirmed.stdio_is_confirmed_with(secret),
            "a binary swapped after the catalog check must be refused at spawn"
        );
    }

    #[test]
    fn approval_and_confirmation_digests_separate_args_from_env() {
        // Review P2: `args=["X"], env=[]` and `args=[], env=["X"]` must not
        // collide. The env name is a legal declared name, so without the fix a
        // hand edit moves a `.env` value into the child's argv (or the reverse)
        // while the old approval still validates.
        let mut server = McpServerConfig {
            id: "plain".into(),
            catalog_id: None,
            data_class: McpDataClass::Sensitive,
            stdio_confirmed: false,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: McpTransport::Stdio,
            url: None,
            command: Some("/bin/echo".into()),
            args: vec!["X".into()],
            env: vec![],
            enabled: false,
            agents: Default::default(),
        };
        let secret = b"daemon-token";
        let mut moved = server.clone();
        moved.args = vec![];
        moved.env = vec!["X".into()];
        assert_ne!(
            server.approval_binding(secret, None),
            moved.approval_binding(secret, None),
            "moving an item between args and env must change the approval digest"
        );
        assert_ne!(
            server.confirmation_binding(secret),
            moved.confirmation_binding(secret),
            "moving an item between args and env must change the confirmation digest"
        );
        // The same lists in the same field still bind identically.
        assert_eq!(
            server.approval_binding(secret, None),
            server.clone().approval_binding(secret, None)
        );
        // A tool cannot be moved between agents without changing the digest.
        server.agents.insert("main".into(), vec!["read".into()]);
        server.agents.insert("aux".into(), vec!["write".into()]);
        let mut same_tools_one_agent = server.clone();
        same_tools_one_agent.agents.clear();
        same_tools_one_agent
            .agents
            .insert("main".into(), vec!["read".into(), "write".into()]);
        assert_ne!(
            server.approval_binding(secret, None),
            same_tools_one_agent.approval_binding(secret, None)
        );
    }

    #[test]
    fn wrapper_and_shell_launchers_are_refused_outright() {
        // Item 2: the whole list is a hard refusal with one stable code, and
        // there is no warning-only path.
        for command in [
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
            "/bin/fish",
            "/bin/dash",
            "/bin/ksh",
            "/usr/bin/env",
            "/usr/bin/nice",
            "/usr/bin/timeout",
            "/usr/bin/nohup",
            "/usr/bin/sudo",
            "/usr/bin/doas",
            "/usr/bin/su",
            "/usr/bin/xargs",
            "/usr/bin/stdbuf",
            "/usr/bin/taskset",
            "/usr/bin/chrt",
            "/usr/bin/caffeinate",
            "/usr/bin/arch",
        ] {
            let refusal = evaluate_stdio_policy("bad", command, &args(&["server"]), false)
                .expect_err(&format!("{command} must be refused"));
            assert_eq!(refusal.label, "wrapper_launcher", "{command}");
        }
        // A symlink to a shell is refused too.
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("helper");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        assert_eq!(
            evaluate_stdio_policy("bad", &link.to_string_lossy(), &args(&["x"]), false)
                .unwrap_err()
                .label,
            "wrapper_launcher"
        );
        // The classes that were never in the wrapper list keep their warning.
        for command in ["/usr/bin/osascript", "/usr/bin/awk"] {
            let policy = evaluate_stdio_policy("bad", command, &args(&["server"]), false).unwrap();
            assert!(policy.is_high_risk(), "{command} must stay high risk");
        }
        // Item 3: the shell-like launchers moved to the hard refusal, so a
        // missing `high_risk` for one of them can never be reassuring.
        for command in [
            "/bin/csh",
            "/bin/tcsh",
            "/usr/local/bin/pwsh",
            "/usr/local/bin/powershell",
            "/usr/bin/busybox",
            "/usr/bin/script",
            "/usr/bin/time",
            "/usr/bin/exec",
            "/usr/bin/command",
            "/usr/bin/sandbox-exec",
            "/usr/bin/open",
        ] {
            let refusal = evaluate_stdio_policy("bad", command, &args(&["server"]), false)
                .expect_err(&format!("{command} must be refused"));
            assert_eq!(refusal.label, "wrapper_launcher", "{command}");
        }
        // `python -m` stays warning-only with `high_risk` (item 3).
        let policy = evaluate_stdio_policy(
            "warn",
            "/usr/bin/python3",
            &args(&["-m", "http.server"]),
            false,
        )
        .unwrap();
        assert_eq!(policy.high_risk, Some("interpreter_eval"));
        for command in [
            "/opt/homebrew/bin/npx",
            "/usr/local/bin/uvx",
            "/usr/local/bin/pipx",
        ] {
            let policy =
                evaluate_stdio_policy("runner", command, &args(&["run", "pkg"]), false).unwrap();
            assert_eq!(policy.high_risk, Some("package_runner"), "{command}");
        }
    }

    #[test]
    fn eval_flags_on_interpreters_are_flagged_including_clusters_long_forms_and_bypasses() {
        for (command, argv) in [
            ("/opt/homebrew/bin/node", vec!["-e", "1"]),
            ("/opt/homebrew/bin/node", vec!["-pe", "1"]),
            ("/opt/homebrew/bin/node", vec!["--eval=1"]),
            ("/opt/homebrew/bin/node", vec!["--print", "1"]),
            (
                "/opt/homebrew/bin/node",
                vec!["--import=data:text/javascript,1"],
            ),
            ("/usr/bin/python3.12", vec!["-Bc", "print(1)"]),
            ("/usr/bin/python3", vec!["-c", "print(1)"]),
            ("/usr/bin/perl", vec!["-e", "print 1"]),
            ("/usr/bin/ruby", vec!["-ne", "1"]),
            ("/usr/bin/Rscript", vec!["-e", "1"]),
            ("/opt/julia/bin/julia", vec!["-e", "1"]),
            ("/usr/local/bin/nu", vec!["-c", "1"]),
        ] {
            let policy = evaluate_stdio_policy("bad", command, &args(&argv), false).unwrap();
            assert_eq!(
                policy.high_risk,
                Some("interpreter_eval"),
                "{command} {argv:?}"
            );
        }
        // A script file is not an eval flag; a plain binary keeps its flags.
        assert!(
            !evaluate_stdio_policy("ok", "/usr/bin/python3.12", &args(&["server.py"]), false)
                .unwrap()
                .is_high_risk()
        );
        assert!(!evaluate_stdio_policy(
            "ok",
            "/usr/local/bin/rg",
            &args(&["-e", "pattern"]),
            false
        )
        .unwrap()
        .is_high_risk());
    }

    #[test]
    fn dangerous_launcher_bypasses_are_flagged_as_high_risk() {
        for (command, argv, label) in [
            (
                "/usr/bin/ssh",
                vec!["-o", "ProxyCommand=sh -c id", "host"],
                "ssh_proxycommand",
            ),
            ("/usr/bin/find", vec![".", "-exec", "id", ";"], "find_exec"),
            (
                "/usr/bin/git",
                vec!["-c", "core.fsmonitor=id", "status"],
                "git_config_override",
            ),
            (
                "/usr/local/bin/npx-cli.js",
                vec!["--yes", "pkg"],
                "package_runner",
            ),
        ] {
            let policy = evaluate_stdio_policy("bad", command, &args(&argv), false).unwrap();
            assert_eq!(policy.high_risk, Some(label), "{command} {argv:?}");
        }
    }

    #[test]
    fn container_run_allowlist_accepts_only_the_documented_shape() {
        for argv in [
            vec!["run", "img"],
            vec!["run", "--rm", "-i", "-t", "--init", "--read-only", "img"],
            vec!["RUN", "--RM", "-IT", "img"],
            vec!["run", "--network=none", "img"],
            vec!["run", "--network", "bridge", "img"],
            vec!["run", "-e", "DATAGOUV_KEY", "img"],
            vec!["run", "--env=DATAGOUV_KEY", "img"],
            vec!["run", "--env", "DATAGOUV_KEY", "--name", "x", "img"],
            vec!["run", "--pull=never", "--pull", "missing", "img"],
            // Clustered short flags, attached `-eNAME`, and image args.
            vec!["run", "-it", "img", "sh", "-c", "id"],
            vec!["run", "-eDATAGOUV_KEY", "img"],
        ] {
            assert!(docker(&argv).is_ok(), "{argv:?} must be allowed");
        }
    }

    #[test]
    fn container_run_allowlist_refuses_every_other_flag_and_mount() {
        for (argv, label) in [
            (vec!["build", "."], "container_subcommand"),
            (vec!["-v"], "container_subcommand"),
            (vec!["run"], "container_image_missing"),
            (vec!["run", "--privileged", "img"], "container_flag"),
            (vec!["run", "--privileged=true", "img"], "container_flag"),
            (vec!["run", "--cap-add=ALL", "img"], "container_flag"),
            (
                vec!["run", "--cap-add", "CAP_SYS_ADMIN", "img"],
                "container_flag",
            ),
            (vec!["run", "--ipc=host", "img"], "container_flag"),
            (vec!["run", "--pid=host", "img"], "container_flag"),
            (vec!["run", "--uts=host", "img"], "container_flag"),
            (vec!["run", "--userns=host", "img"], "container_flag"),
            (vec!["run", "--device", "/dev/sda", "img"], "container_flag"),
            (
                vec!["run", "--security-opt=seccomp=unconfined", "img"],
                "container_flag",
            ),
            (vec!["run", "--net=host", "img"], "container_flag"),
            (vec!["run", "--network=host", "img"], "container_network"),
            (vec!["run", "--network", "host", "img"], "container_network"),
            (
                vec!["run", "-v", "./nope/../../Users/x:/h", "img"],
                "container_flag",
            ),
            (vec!["run", "-v", "/USERS/x:/h", "img"], "container_flag"),
            (
                vec![
                    "run",
                    "-v",
                    "/run/podman/podman.sock:/run/podman/podman.sock",
                    "img",
                ],
                "container_flag",
            ),
            (
                vec!["run", "--volume=/Users/fake:/data", "img"],
                "container_flag",
            ),
            (
                vec![
                    "run",
                    "--mount",
                    "type=bind,source=/Users/fake,target=/data",
                    "img",
                ],
                "container_flag",
            ),
            (
                vec!["run", "--volumes-from", "other", "img"],
                "container_flag",
            ),
            (vec!["run", "-itv", "/Users/x:/h", "img"], "container_flag"),
            (vec!["run", "-v/Users/fake:/data", "img"], "container_flag"),
            (vec!["run", "-u", "root", "img"], "container_flag"),
            (vec!["run", "--user", "root", "img"], "container_flag"),
            // The env *name* is what the container allowlist checks; a name
            // that does not look credential-like keeps the container label.
            (
                vec!["run", "-e", "DATAGOUV_CONFIG=value", "img"],
                "container_env_value",
            ),
            (
                vec!["run", "--env=DATAGOUV_CONFIG=value", "img"],
                "container_env_value",
            ),
            // Item 5: `key` is a whole `_`-separated part, so a `..._KEY=value`
            // env pair is a secret first — the stronger, earlier refusal wins.
            (
                vec!["run", "-e", "DATAGOUV_KEY=secret", "img"],
                "secret_in_config",
            ),
            (
                vec!["run", "--env=DATAGOUV_KEY=secret", "img"],
                "secret_in_config",
            ),
            (
                vec!["run", "--env-file=/tmp/fake.env", "img"],
                "container_flag",
            ),
        ] {
            let refusal = docker(&argv).expect_err(&format!("{argv:?} must be refused"));
            assert_eq!(refusal.label, label, "{argv:?}");
        }
        // `nerdctl -v` is not a `run` shape; a podman socket mount is refused.
        let nerdctl = evaluate_stdio_policy("n", "/usr/local/bin/nerdctl", &args(&["-v"]), false)
            .unwrap_err();
        assert_eq!(nerdctl.label, "container_subcommand");
        let podman = evaluate_stdio_policy(
            "p",
            "/usr/local/bin/podman",
            &args(&["run", "-v", "/run/podman/podman.sock:/sock", "img"]),
            false,
        )
        .unwrap_err();
        assert_eq!(podman.label, "container_flag");
    }

    #[test]
    fn compose_and_vm_container_launchers_are_refused_outright() {
        let wrappers: [(&str, Vec<&str>); 12] = [
            ("/usr/local/bin/docker-compose", vec!["up"]),
            ("/usr/local/bin/docker", vec!["compose", "up"]),
            ("/usr/local/bin/lima", vec!["start"]),
            ("/usr/local/bin/limactl", vec!["start", "default"]),
            ("/usr/local/bin/colima", vec!["start"]),
            ("/usr/local/bin/finch", vec!["run", "img"]),
            ("/usr/local/bin/nerdctl", vec!["compose", "up"]),
            ("/opt/homebrew/bin/my-compose-shim", vec!["up"]),
            // Item 3: substring matching, so a renamed/static build is caught.
            ("/usr/local/bin/docker-compose-v2", vec!["up"]),
            ("/usr/local/bin/lima-static-linux_amd64", vec!["start"]),
            ("/usr/local/bin/colima-x86_64", vec!["start"]),
            ("/usr/local/bin/finch-static", vec!["run", "img"]),
        ];
        for (command, base) in wrappers {
            for extra in [
                vec!["-v", "/:/h"],
                vec!["--privileged"],
                vec!["--privileged=true"],
            ] {
                let mut full: Vec<String> = base.iter().map(|arg| (*arg).to_owned()).collect();
                full.extend(extra.iter().map(|arg| (*arg).to_owned()));
                let refusal = evaluate_stdio_policy("x", command, &full, false)
                    .expect_err(&format!("{command} {full:?} must be refused"));
                assert!(
                    matches!(refusal.label, "container_compose" | "container_vm_tool"),
                    "{command} {full:?} -> {}",
                    refusal.label
                );
            }
        }
        // `compose up` through a runnable container CLI is refused too.
        for command in [
            "/usr/local/bin/docker",
            "/usr/local/bin/nerdctl",
            "/usr/local/bin/podman",
        ] {
            for extra in [vec!["-v", "/:/h"], vec!["--privileged"]] {
                let mut full: Vec<String> = vec!["compose".to_owned(), "up".to_owned()];
                full.extend(extra.iter().map(|arg| (*arg).to_owned()));
                let refusal = evaluate_stdio_policy("x", command, &full, false)
                    .expect_err("a compose subcommand must be refused");
                assert_eq!(refusal.label, "container_compose", "{command} {full:?}");
            }
        }
        // Item 3: a container CLI is matched by substring, so a renamed or
        // static build (`podman-remote-static-linux_amd64`) still goes through
        // the same allowlist — and its disallowed flags are still refused.
        assert!(evaluate_stdio_policy(
            "p",
            "/usr/local/bin/podman-remote",
            &args(&["run", "--network=none", "img"]),
            false
        )
        .is_ok());
        assert!(evaluate_stdio_policy(
            "p",
            "/usr/local/bin/podman-remote-static-linux_amd64",
            &args(&["run", "--network=none", "img"]),
            false
        )
        .is_ok());
        assert_eq!(
            evaluate_stdio_policy(
                "p",
                "/opt/homebrew/bin/nerdctl-static-linux_amd64",
                &args(&["run", "--privileged", "img"]),
                false
            )
            .unwrap_err()
            .label,
            "container_flag"
        );
        // A Docker-shaped basename is still a container CLI, case-insensitively.
        assert_eq!(
            evaluate_stdio_policy(
                "p",
                "/usr/local/bin/Docker-Real",
                &args(&["run", "-v", "/:/h", "img"]),
                false
            )
            .unwrap_err()
            .label,
            "container_flag"
        );
    }

    #[test]
    fn container_tokens_match_whole_parts_not_substrings() {
        // Item 4: `climate-mcp`, `composer`, `dockerize` and `mydockerhelper`
        // are NOT container CLIs, so they get neither a container refusal nor
        // a `container_cli` label (substring matching used to flag all four).
        for command in [
            "/usr/local/bin/climate-mcp",
            "/usr/local/bin/composer",
            "/usr/local/bin/dockerize",
            "/usr/local/bin/mydockerhelper",
        ] {
            let policy = evaluate_stdio_policy("ok", command, &args(&["--version"]), false)
                .unwrap_or_else(|refusal| panic!("{command} -> {}", refusal.label));
            assert_ne!(policy.high_risk, Some("container_cli"), "{command}");
        }
        // The whole-token forms still behave exactly as before.
        assert_eq!(
            evaluate_stdio_policy(
                "p",
                "/usr/local/bin/docker-compose",
                &args(&["config"]),
                false
            )
            .unwrap_err()
            .label,
            "container_compose"
        );
        assert_eq!(
            evaluate_stdio_policy("p", "/usr/local/bin/lima", &args(&["start"]), false)
                .unwrap_err()
                .label,
            "container_vm_tool"
        );
        assert!(evaluate_stdio_policy(
            "p",
            "/usr/local/bin/podman-remote-static-linux_amd64",
            &args(&["run", "--network=none", "img"]),
            false
        )
        .is_ok());
        // Item 4: buildah, ctr, Apple's `container` and orbctl go through the
        // same `run` allowlist (`orbctl` accepted in shape, refused otherwise).
        for command in [
            "/usr/local/bin/buildah",
            "/usr/bin/ctr",
            "/usr/local/bin/container",
            "/usr/local/bin/orbctl",
        ] {
            assert!(
                evaluate_stdio_policy(
                    "c",
                    command,
                    &args(&["run", "--network=none", "img"]),
                    false
                )
                .is_ok(),
                "{command} must go through the allowlist"
            );
            assert_eq!(
                evaluate_stdio_policy("c", command, &args(&["run", "--privileged", "img"]), false)
                    .unwrap_err()
                    .label,
                "container_flag",
                "{command} must be refused when its shape differs"
            );
        }
        // Apple `container run -v /:/host` is refused on the mount flag.
        assert_eq!(
            evaluate_stdio_policy(
                "c",
                "/usr/local/bin/container",
                &args(&["run", "-v", "/:/host", "img"]),
                false
            )
            .unwrap_err()
            .label,
            "container_flag"
        );
    }

    #[test]
    fn container_with_network_false_must_carry_network_none() {
        for argv in [
            vec!["run", "img"],
            vec!["run", "--rm", "img"],
            vec!["run", "--network", "bridge", "img"],
            vec!["run", "--network=bridge", "img"],
        ] {
            let refusal = docker_without_network(&argv)
                .expect_err(&format!("{argv:?} must be refused without --network=none"));
            assert_eq!(refusal.label, "container_network", "{argv:?}");
        }
        assert!(docker_without_network(&["run", "--network=none", "img"]).is_ok());
        // `network = true` accepts either mode; the declared flag is honoured.
        assert!(docker(&["run", "--network=bridge", "img"]).is_ok());
        assert!(evaluate_stdio_policy(
            "d",
            "/usr/local/bin/docker",
            &args(&["run", "--network=none", "img"]),
            true
        )
        .is_ok());
    }

    #[test]
    fn quarantined_entry_survives_a_confirm_or_revoke_rewrite_verbatim() {
        let bad = "[[server]]\nid = \"bad\"\ntransport = \"carrier-pigeon\"\n";
        let text = format!(
            "[[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n\n{bad}"
        );
        let mut config = McpConfig::parse("mcp.toml", &text).unwrap();
        assert_eq!(config.server.len(), 1);
        assert_eq!(config.quarantined.len(), 1);
        assert!(config.quarantined[0].raw.contains("id = \"bad\""));

        // Simulate the confirm endpoint's edit, then a revoke.
        config.server[0].stdio_confirmed = true;
        config.server[0].stdio_confirmation = Some("hash".to_owned());
        let confirmed = config.to_toml_string().unwrap();
        assert!(
            confirmed.contains(bad),
            "the quarantined entry must survive a confirm rewrite: {confirmed:?}"
        );
        assert_eq!(confirmed.matches("[[server]]").count(), 2);

        config.server[0].stdio_confirmed = false;
        config.server[0].stdio_confirmation = None;
        let revoked = config.to_toml_string().unwrap();
        assert!(
            revoked.contains(bad),
            "the quarantined entry must survive a revoke rewrite: {revoked:?}"
        );

        // The rewrite still round-trips: the bad entry stays quarantined.
        let reparsed = McpConfig::parse("mcp.toml", &revoked).unwrap();
        assert_eq!(reparsed.server.len(), 1);
        assert_eq!(reparsed.quarantined.len(), 1);
        assert_eq!(reparsed.quarantined[0].id, "bad");
        assert_eq!(reparsed.quarantined[0].reason, "invalid_transport");

        // An inline non-table element is preserved by the document rewrite too
        // (never dropped, never turned into a second `server = ...` key).
        let odd = McpConfig::parse("t", "server = [\"nope\"]\n").unwrap();
        assert_eq!(odd.quarantined.len(), 1);
        assert_eq!(odd.quarantined[0].reason, "invalid_server");
        let written = odd.to_toml_string().unwrap();
        assert!(written.contains("nope"));
        assert!(!written.contains("server = []"));
    }

    #[test]
    fn a_symlink_to_a_shell_is_refused_like_the_shell() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("helper");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        let path = link.to_string_lossy().into_owned();
        assert_eq!(
            evaluate_stdio_policy("link", &path, &args(&["x"]), false)
                .unwrap_err()
                .label,
            "wrapper_launcher"
        );
    }

    #[test]
    fn secret_looking_arguments_and_urls_are_refused() {
        for value in [
            "--api-key",
            "--api_key",
            "--access-token",
            "--auth-token",
            "--private-key",
            "--token=abc",
            "--apikey=abc",
            "--password=hunter2",
            "--access-token=abcdefgh1234", // gitleaks:allow
            "--auth-token=abcdefgh1234",   // gitleaks:allow
            "--api_key=abcdefgh1234",      // gitleaks:allow
            "--private-key=abcdefgh1234",  // gitleaks:allow
            "https://example.test/mcp?token=abc",
            "https://example.test/mcp?apikey=abc",
            "https://example.test/mcp?key=abc",
            "sk-abcdefgh1234",
            "sk_live_abcdefgh1234", // gitleaks:allow
            "AKIAIOSFODNN7EXAMPLE",
            // Item 6: a decoy `AKIA` prefix must not hide a later real key.
            "AKIANOTENOUGH AKIAIOSFODNN7EXAMPLE",
            "xoxb-short",
            "xoxp-short",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
            "https://user:password@example.test/mcp",
            "user:password@example.test",
            // Item 5: structured key/value pairs, all four spellings.
            r#"{"token":"abc"}"#,
            r#"{"api_key": "abc"}"#,
            "api_key: abc",
            "api_key:abc",
            "client_secret=abc",
            "--flag=token:abc",
            "auth=1",
            "X-Bearer:abc",
        ] {
            assert!(looks_like_secret(value), "{value} must look secret");
        }
        for value in [
            "task-list",
            "desk-top",
            "https://example.test/mcp",
            "monkey=banana",
            "AKIANOTENOUGH",
            // An ordinary structured pair whose key is not secret-looking.
            r#"{"note":"hello"}"#,
            "name: value",
            // Item 5: `auth`/`token`/`key` match whole `_`/`-`-separated parts
            // only, so these are not false positives.
            "--author=Jane Doe",
            "tokenizer=gpt2",
            "keynote=1",
            "hockey-stick=1",
        ] {
            assert!(!looks_like_secret(value), "{value} must not look secret");
        }
        // Item 5: an encoded separator is decoded before the check, so
        // `token%3Dabc` is the same request as `token=abc`.
        for value in [
            "token%3Dabc",
            "api_key%3Aabc",
            "%22token%22%3A%22abc%22",
            "https://example.test/mcp%3Ftoken%3Dabc",
        ] {
            assert!(
                looks_like_secret(value),
                "{value} must look secret after percent-decoding"
            );
        }
        assert!(!looks_like_secret("percent%2Fonly"));
        assert!(
            evaluate_stdio_policy("s", "/usr/local/bin/tool", &args(&["--token=abc"]), false)
                .is_err()
        );
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["-k", "0123456789abcdef"]),
            false
        )
        .is_err());
        let parsed = McpConfig::parse(
            "t",
            "[[server]]\nid = \"a\"\ntransport = \"http\"\nurl = \"https://example.test/mcp?token=abc\"\n",
        )
        .unwrap();
        assert!(parsed.server[0].check().is_err());
    }

    #[test]
    fn secret_parameter_names_cover_split_args_and_the_lowered_key_threshold() {
        for value in [
            "--client-secret",
            "--client-secret=abc",
            "--secret=abc",
            "--access-token=abcdefgh1234", // gitleaks:allow
            "--auth-token=abcdefgh1234",   // gitleaks:allow
            "--api_key=abcdefgh1234",      // gitleaks:allow
            "--private-key=abcdefgh1234",  // gitleaks:allow
            "https://example.test/mcp?secret=abc",
            "https://example.test/mcp?access_key=abc",
            "X-API-Key: abc",
            "Authorization: Bearer abc",
            "authorization:bearer abc",
        ] {
            assert!(looks_like_secret(value), "{value} must look secret");
        }
        for argv in [
            vec!["--client-secret="],
            vec!["--client-secret", "abc"],
            vec!["--secret", "abc"],
            vec!["-u", "user:pass"],
            vec!["--user", "user:pass"],
            vec!["-H", "X-API-Key: abc"],
            vec!["Authorization:", "Bearer", "abc"],
            // Item 10: the `--key` value threshold is lowered to 12 characters.
            vec!["--key", "0123456789ab"], // gitleaks:allow
            vec!["-k", "0123456789ab"],
            // Item 6: a letters-only value of 12+ characters is a plausible
            // passphrase even without a digit.
            vec!["--key", "abcdefghijkl"],
            vec!["-k", "abcdefghijkl"],
            // Item 5: a structured JSON/colon pair inside one argument.
            vec![r#"{"token":"abc"}"#],
            vec!["api_key:abc"],
            // Item 5: the split spellings all take a secret value.
            vec!["--access-token", "abcdefgh1234"], // gitleaks:allow
            vec!["--auth-token", "abcdefgh1234"],   // gitleaks:allow
            vec!["--api_key", "abcdefgh1234"],      // gitleaks:allow
            vec!["--api-key", "abcdefgh1234"],      // gitleaks:allow
            vec!["--private-key", "abcdefgh1234"],  // gitleaks:allow
            vec!["--password", "abcdefgh1234"],     // gitleaks:allow
            vec!["--token", "abcdefgh1234"],        // gitleaks:allow
            vec!["--access-token", "ghp_abcdefghijklmnop"],
            // Attached `-k<value>` / `-k=<value>`, letters-only included.
            vec!["-kabcdefgh1234"],
            vec!["-k=abcdefgh1234"],
            vec!["-kghp_abcdefghijklmnop"],
            vec!["-kabcdefghijkl"],
            vec!["-k=abcdefghijkl"],
        ] {
            assert!(
                evaluate_stdio_policy("s", "/usr/local/bin/tool", &args(&argv), false).is_err(),
                "{argv:?} must be refused"
            );
        }
        // A short, non-secret value is still allowed.
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["--key", "0123456789"]),
            false
        )
        .is_ok());
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["-k", "0123456789"]),
            false
        )
        .is_ok());
        // A short letters-only value and a long digits-only value stay allowed.
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["--key", "abcdef"]),
            false
        )
        .is_ok());
        assert!(evaluate_stdio_policy(
            "s",
            "/usr/local/bin/tool",
            &args(&["--key", "0123456789012"]),
            false
        )
        .is_ok());
        assert!(evaluate_stdio_policy("s", "/usr/local/bin/tool", &args(&["-u"]), false).is_ok());
    }

    #[test]
    fn declared_env_names_exclude_loader_start_up_and_home_controls() {
        for name in [
            "PATH",
            "HOME",
            "SHELL",
            "TMPDIR",
            "NODE_OPTIONS",
            "BASH_ENV",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "PYTHONPATH",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "LUA_INIT",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_ASKPASS",
            "RUSTC_WRAPPER",
            "GCONV_PATH",
            "PYTHONBREAKPOINT",
            "PYTHONUSERBASE",
            "AUXESIS_API_PORT",
            "AUX_KEY_X",
            // Container-CLI steering names (items 3/4), denied by prefix.
            "DOCKER_HOST",
            "DOCKER_CONFIG",
            "DOCKER_IMAGE",
            "DOCKER_CONTEXT",
            "DOCKER_CERT_PATH",
            "DOCKER_TLS_VERIFY",
            "CONTAINER_HOST",
            "CONTAINER_CONNECTION",
            "CONTAINERS_CONF",
            "CONTAINERD_ADDRESS",
            "PODMAN_HOST",
            "BUILDKIT_HOST",
            "REGISTRY_AUTH_FILE",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_COUNT",
            "NERDCTL_ADDRESS",
            "NERDCTL_NAMESPACE",
            "XDG_CONFIG_HOME",
        ] {
            assert!(!crate::stdio::env_key_declared(name), "{name}");
        }
        // Item 4: the comparison folds case, so a lowercase spelling of a
        // denied name or prefix is refused exactly like the uppercase one.
        for name in [
            "docker_host",
            "Docker_Host",
            "podman_host",
            "xdg_cache_home",
            "shell",
            "tmpdir",
            "ld_preload",
            "dyld_insert_libraries",
            "rustc_wrapper",
            "jdk_java_options",
            "gconv_path",
            "pythonbreakpoint",
            "git_ssh",
            "git_config_system",
            "containerd_address",
        ] {
            assert!(!crate::stdio::env_key_declared(name), "{name}");
        }
        assert!(crate::stdio::env_key_declared("DATAGOUV_KEY"));
        assert!(crate::stdio::env_key_declared("DOCKERFILE_CONTENT"));
        let parsed = McpConfig::parse(
            "t",
            "[[server]]\nid = \"b\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\nenv = [\"NODE_OPTIONS\"]\n",
        )
        .unwrap();
        assert!(parsed.server[0].check().is_err());
        let parsed = McpConfig::parse(
            "t",
            "[[server]]\nid = \"c\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\nenv = [\"DOCKER_HOST\"]\n",
        )
        .unwrap();
        assert!(parsed.server[0].check().is_err());
    }

    #[test]
    fn per_server_failures_do_not_drop_the_whole_config() {
        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"bad\"\ntransport = \"stdio\"\ncommand = \"relative\"\n\n\
             [[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n",
        )
        .unwrap();
        assert_eq!(config.server.len(), 2);
        assert!(config.server[0].check().is_err());
        assert_eq!(
            config.server[0].check().unwrap_err().label,
            "command_refused"
        );
        assert!(config.server[1].check().is_ok());
    }

    #[test]
    fn unknown_transport_entry_is_quarantined_next_to_good_entries() {
        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"bad\"\ntransport = \"carrier-pigeon\"\n\n\
             [[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n",
        )
        .unwrap();
        assert_eq!(config.server.len(), 1, "the good entry must survive");
        assert_eq!(config.server[0].id, "good");
        assert!(config.server[0].check().is_ok());
        assert_eq!(config.quarantined.len(), 1);
        assert_eq!(config.quarantined[0].id, "bad");
        assert_eq!(config.quarantined[0].reason, "invalid_transport");
        assert!(!config.is_empty());

        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"typo\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\nnetworkk = true\n\n\
             [[server]]\nid = \"good\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n",
        )
        .unwrap();
        assert_eq!(config.server.len(), 1);
        assert_eq!(config.quarantined.len(), 1);
        assert_eq!(config.quarantined[0].reason, "unknown_key");

        let config = McpConfig::parse(
            "t",
            "[[server]]\nid = \"no-transport\"\n\n\
             [[server]]\nid = \"bad-class\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\ndata_class = \"secret\"\n",
        )
        .unwrap();
        assert!(config.server.is_empty());
        assert_eq!(config.quarantined.len(), 2);
        assert_eq!(config.quarantined[0].reason, "missing_transport");
        assert_eq!(config.quarantined[1].reason, "invalid_data_class");
    }

    fn added_server(id: &str) -> McpServerConfig {
        McpServerConfig {
            id: id.to_owned(),
            catalog_id: None,
            data_class: McpDataClass::Sensitive,
            stdio_confirmed: false,
            stdio_confirmation: None,
            approval: None,
            network: false,
            transport: McpTransport::Http,
            url: Some("https://added.invalid/mcp".to_owned()),
            command: None,
            args: vec![],
            env: vec![],
            enabled: false,
            agents: Default::default(),
        }
    }

    #[test]
    fn a_crlf_file_is_parsed_and_rewritten_without_corruption() {
        let text = "# c\r\n[[server]]\r\nid = \"good\"\r\ntransport = \"http\"\r\n\
                    url = \"https://example.test/mcp\"\r\n\r\n[[server]]\r\n\
                    id = \"bad\"\r\ntransport = \"carrier-pigeon\"\r\n";
        let mut config = McpConfig::parse("mcp.toml", text).unwrap();
        assert_eq!(config.server.len(), 1);
        assert_eq!(config.quarantined.len(), 1);
        config.server[0].enabled = true;
        let written = config.to_toml_string().unwrap();
        assert!(written.contains("# c"));
        assert!(written.contains("transport = \"carrier-pigeon\""));
        let reparsed = McpConfig::parse("mcp.toml", &written).unwrap();
        assert_eq!(reparsed.server.len(), 1);
        assert_eq!(reparsed.quarantined.len(), 1);
        assert_eq!(reparsed.quarantined[0].id, "bad");
        // A CRLF file is normalised to LF on the first rewrite, but rewriting
        // the result again is a byte-for-byte no-op: nothing drifts.
        assert_eq!(reparsed.to_toml_string().unwrap(), written);
    }

    #[test]
    fn a_retained_source_that_no_longer_parses_refuses_the_rewrite() {
        // Item 7: the retained source parsed once already, so a re-parse
        // failure must refuse the write, never silently fall back to a
        // from-scratch document that would drop the owner's file.
        let mut config = McpConfig::parse(
            "mcp.toml",
            "[[server]]\nid = \"a\"\ntransport = \"http\"\nurl = \"https://example.test/mcp\"\n",
        )
        .unwrap();
        assert!(config.to_toml_string().is_ok());
        config.source = "[[server]]\nid = ".to_owned();
        assert!(matches!(
            config.to_toml_string(),
            Err(McpConfigError::Parse { .. })
        ));
    }

    #[test]
    fn a_spaced_server_header_is_parsed_and_rewritten_without_losing_the_entry() {
        let text = "[[ server ]]\nid = \"good\"\ntransport = \"http\"\n\
                    url = \"https://example.test/mcp\"\n\n\
                    [[ server ]]\nid = \"bad\"\ntransport = \"carrier-pigeon\"\n";
        let mut config = McpConfig::parse("mcp.toml", text).unwrap();
        assert_eq!(config.server.len(), 1, "the spaced header is a real entry");
        assert_eq!(config.quarantined.len(), 1);
        config.server[0].enabled = true;
        let written = config.to_toml_string().unwrap();
        // `toml_edit` may normalise the spaced header spelling, but the entry
        // and the quarantined block must survive intact.
        assert!(
            written.contains("[[server]]") || written.contains("[[ server ]]"),
            "the header must still be an array-of-tables header: {written:?}"
        );
        assert!(written.contains("id = \"good\""));
        assert!(written.contains("id = \"bad\""));
        assert!(written.contains("transport = \"carrier-pigeon\""));
        let reparsed = McpConfig::parse("mcp.toml", &written).unwrap();
        assert_eq!(reparsed.server.len(), 1);
        assert_eq!(reparsed.quarantined.len(), 1);
        assert_eq!(reparsed.quarantined[0].reason, "invalid_transport");
    }

    #[test]
    fn a_multiline_string_containing_a_server_header_is_not_a_second_entry() {
        let text = "[[server]]\nid = \"good\"\ntransport = \"stdio\"\n\
                    command = \"/usr/local/bin/tool\"\nargs = [\"\"\"\n[[server]]\nnot an entry\n\"\"\"]\n";
        let mut config = McpConfig::parse("mcp.toml", text).unwrap();
        assert_eq!(config.server.len(), 1, "the string is data, not a header");
        assert!(config.quarantined.is_empty());
        config.server[0].enabled = true;
        let written = config.to_toml_string().unwrap();
        assert_eq!(
            written.matches("[[server]]").count(),
            2,
            "one real header plus the string body: {written:?}"
        );
        let reparsed = McpConfig::parse("mcp.toml", &written).unwrap();
        assert_eq!(reparsed.server.len(), 1);
    }

    #[test]
    fn five_api_cycles_leave_every_untouched_entry_byte_identical() {
        let bad_one = "# keep me\n[[server]]\nid = \"bad-one\"\ntransport = \"carrier-pigeon\"\n";
        let bad_two = "[[server]]\nid = \"bad-two\"\ntransport = \"http\"\n\
                       url = \"http://10.0.0.1/mcp\"\nnetworkk = true\n";
        let stable = "# stable comment\n[[server]]\nid = \"stable\"\ntransport = \"http\"\n\
                      url = \"https://stable.test/mcp\"\n";
        let text = format!(
            "# header comment\n\n[[server]]\nid = \"keep\"\ntransport = \"http\"\n\
             url = \"https://example.test/mcp\"\nenabled = true\n\n\
             [[server]]\nid = \"remove-me\"\ntransport = \"http\"\n\
             url = \"https://two.test/mcp\"\n\n{stable}\n{bad_one}\n{bad_two}"
        );
        let untouched = [bad_one, bad_two, "# header comment\n", stable];
        let mut config = McpConfig::parse("mcp.toml", &text).unwrap();
        assert_eq!(config.server.len(), 3);
        assert_eq!(config.quarantined.len(), 2);

        for cycle in 0..5 {
            match cycle {
                0 => config.server[0].enabled = false,
                1 => {
                    config.server[0].stdio_confirmed = true;
                    config.server[0].stdio_confirmation = Some("binding".to_owned());
                }
                2 => {
                    config.server[0].stdio_confirmed = false;
                    config.server[0].stdio_confirmation = None;
                }
                3 => config.server.retain(|server| server.id != "remove-me"),
                _ => config.server.push(added_server(&format!("added-{cycle}"))),
            }
            let written = config.to_toml_string().unwrap();
            for marker in untouched {
                assert!(
                    written.contains(marker),
                    "cycle {cycle} changed an untouched entry {marker:?}: {written:?}"
                );
            }
            config = McpConfig::parse("mcp.toml", &written).unwrap();
        }
        assert_eq!(config.quarantined.len(), 2);
        assert_eq!(config.quarantined[0].id, "bad-one");
        assert_eq!(config.quarantined[0].reason, "invalid_transport");
        assert_eq!(config.quarantined[1].id, "bad-two");
        assert_eq!(config.quarantined[1].reason, "unknown_key");
        assert!(config.server.iter().any(|server| server.id == "added-4"));
        assert!(config.server.iter().any(|server| server.id == "stable"));
        assert!(!config.server.iter().any(|server| server.id == "remove-me"));
    }

    #[test]
    fn a_duplicate_id_quarantines_both_twins_and_delete_cannot_promote_one() {
        for text in [
            // Good + bad duplicate.
            "[[server]]\nid = \"x\"\ntransport = \"http\"\nurl = \"https://a.invalid/mcp\"\n\n\
             [[server]]\nid = \"x\"\ntransport = \"carrier-pigeon\"\n",
            // Two good duplicates.
            "[[server]]\nid = \"x\"\ntransport = \"http\"\nurl = \"https://a.invalid/mcp\"\n\n\
             [[server]]\nid = \"x\"\ntransport = \"http\"\nurl = \"https://b.invalid/mcp\"\n",
        ] {
            let mut config = McpConfig::parse("mcp.toml", text).unwrap();
            assert!(config.server.is_empty(), "both twins must be quarantined");
            assert_eq!(config.quarantined.len(), 2);
            assert!(config
                .quarantined
                .iter()
                .all(|entry| entry.reason == "duplicate_id"));
            // Deleting the "good" one is a no-op: it never became a server, so
            // the hidden duplicate cannot be promoted.
            config.server.retain(|server| server.id != "x");
            let written = config.to_toml_string().unwrap();
            let reparsed = McpConfig::parse("mcp.toml", &written).unwrap();
            assert_eq!(
                reparsed.quarantined.len(),
                2,
                "both twins stay quarantined until the owner fixes the file"
            );
            assert!(reparsed.server.is_empty());
        }
    }
}
