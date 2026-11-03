//! The [`Tool`] contract shared by every tool implementation.

use crate::ToolError;
use async_trait::async_trait;
use kernel_net::FetchEgress;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How dangerous running a tool is.
///
/// Risk is informational: it is surfaced in approval prompts and written to
/// the audit trail. The [`crate::Broker`] makes the actual decision; risk
/// never bypasses or grants permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// Reads or observes; no side effects.
    Low,
    /// Mutates local state but is recoverable.
    Medium,
    /// Can run anything: processes, network, destructive writes.
    High,
}

impl Risk {
    /// Lowercase label used in audit records and prompts.
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

impl std::fmt::Display for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a tool returns to the caller.
///
/// A tool that ran but failed (for example a shell command exiting non-zero)
/// returns `Ok` with [`is_error`](Self::is_error) set, so the model can read
/// the output and react. [`ToolError`] is reserved for calls that could not
/// run at all (bad arguments, I/O failure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    /// Text handed back to the model as the tool result.
    pub content: String,
    /// True when the tool ran but the outcome is a failure.
    pub is_error: bool,
}

impl ToolOutput {
    /// A successful result.
    pub fn ok(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_error: false,
        }
    }

    /// A result the model should treat as a failure.
    pub fn error(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_error: true,
        }
    }
}

/// Everything a tool needs from the caller besides its arguments.
#[derive(Debug, Clone)]
pub struct ToolCtx {
    /// Agent that requested the call. Used by permission rules and auditing.
    pub agent: String,
    /// Base directory for relative paths and the shell's working directory.
    ///
    /// File tools are confined to this directory: paths that resolve outside
    /// it (absolute paths, `..` traversal, symlinks pointing away) are
    /// rejected.
    pub workspace: PathBuf,
    /// The turn's cooperative cancellation token, when the caller has one.
    ///
    /// A tool that may outlive a dropped future (the `shell` tool's process
    /// tree) observes it to run its own cleanup. `None` for callers that are
    /// not cancellable (CLI jobs, tests).
    pub cancel: Option<Arc<crate::CancelToken>>,
    /// The web egress authority the engine packed for this call (`http_fetch`
    /// only, when the engine's own egress layer decided it). When it is set,
    /// the fetcher re-runs the mode/sensitive-turn ask rule on every redirect
    /// destination and reserves each hop from the shared budget. `None` for
    /// every other tool and for plain test callers.
    pub egress: Option<FetchEgress>,
    /// Stable identity of the current run, when this tool call belongs to a
    /// daemon receipt. Tools that meter work can stamp their usage rows with
    /// this id so overlapping runs remain separate.
    pub run_id: Option<String>,
    /// Whether the current conversation contains untrusted content.
    pub tainted: bool,
    /// The privacy grant this call was admitted under, when a gate minted one.
    ///
    /// `privacy_wiring::gate_dispatch` admits every call with the live mode and
    /// attaches the grant here. A tool that egresses (an MCP server, a
    /// connector) builds its `SafeText`/`SafeValue` from it; a call with no
    /// grant must fail closed rather than send raw text.
    pub grant: Option<Arc<kernel_core::privacy::Grant>>,
    /// The tokens (`KIND_<hex>`, no delimiters) the conversation's session has
    /// minted so far. A private-mode tool that sends the model's arguments out
    /// keeps these and treats any other token-shaped text as ordinary text.
    /// `None` (no session) keeps nothing.
    pub session_tokens: Option<Arc<std::collections::BTreeSet<String>>>,
    /// The mode the calling turn runs under: a tool that starts another turn
    /// (`delegate`) takes its floor from here. `None` reads as private.
    turn_mode: Option<TurnMode>,
}

#[derive(Clone)]
struct TurnMode(kernel_core::privacy::ModeFn);

impl std::fmt::Debug for TurnMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never call the handle here: it may read config.
        f.write_str("TurnMode(..)")
    }
}

impl ToolCtx {
    /// Build a context for `agent` rooted at `workspace`.
    pub fn new(agent: impl Into<String>, workspace: impl Into<PathBuf>) -> Self {
        Self {
            agent: agent.into(),
            workspace: workspace.into(),
            cancel: None,
            egress: None,
            run_id: None,
            tainted: false,
            grant: None,
            session_tokens: None,
            turn_mode: None,
        }
    }

    /// Attach the calling turn's effective mode (builder style).
    pub fn with_turn_mode(mut self, mode: kernel_core::privacy::ModeFn) -> Self {
        self.turn_mode = Some(TurnMode(mode));
        self
    }

    /// The calling turn's effective mode; private when no turn attached one.
    pub fn turn_mode(&self) -> kernel_core::privacy::ModeFn {
        match &self.turn_mode {
            Some(TurnMode(mode)) => Arc::clone(mode),
            None => Arc::new(|| kernel_core::privacy::PrivacyMode::Private),
        }
    }

    /// Attach the privacy grant this call was admitted under (builder style).
    pub fn with_grant(mut self, grant: kernel_core::privacy::Grant) -> Self {
        self.grant = Some(Arc::new(grant));
        self
    }

    /// Attach the tokens the session has minted (builder style).
    pub fn with_session_tokens(mut self, tokens: std::collections::BTreeSet<String>) -> Self {
        self.session_tokens = Some(Arc::new(tokens));
        self
    }

    /// The privacy grant for this call, when a gate minted one.
    pub fn grant(&self) -> Option<&kernel_core::privacy::Grant> {
        self.grant.as_deref()
    }

    /// Attach the turn's cancellation token (builder style).
    pub fn with_cancel(mut self, cancel: Option<Arc<crate::CancelToken>>) -> Self {
        self.cancel = cancel;
        self
    }

    /// Attach the per-fetch web egress authority (builder style).
    pub fn with_egress(mut self, egress: FetchEgress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Attach the current receipt identity (builder style).
    pub fn with_run_id(mut self, run_id: Option<String>) -> Self {
        self.run_id = run_id;
        self
    }

    /// Attach the engine's current conversation taint for provenance-aware tools.
    pub fn with_tainted(mut self, tainted: bool) -> Self {
        self.tainted = tainted;
        self
    }

    /// Resolve `path` **inside** the workspace and refuse escapes.
    ///
    /// Relative paths join the workspace. Absolute paths are accepted only
    /// when they land inside it. The result is lexically normalized (no `.`
    /// or `..` components remain) and checked against the canonicalized
    /// workspace, so symlinks that point outside are rejected too.
    pub fn resolve(&self, path: &str) -> Result<PathBuf, ToolError> {
        use std::path::Component;

        let candidate = if Path::new(path).is_absolute() {
            PathBuf::from(path)
        } else {
            self.workspace.join(path)
        };

        // 1. Lexical normalization: collapse `.` and `..` in one pass. Any
        //    `..` that pops past the root is an escape.
        let mut normalized = PathBuf::new();
        for component in candidate.components() {
            match component {
                Component::Prefix(_) | Component::RootDir | Component::CurDir => {
                    normalized.push(component.as_os_str());
                }
                Component::ParentDir => {
                    if !normalized.pop() {
                        return Err(outside());
                    }
                }
                Component::Normal(name) => normalized.push(name),
            }
        }

        // 2. The normalized path must stay under the workspace lexically…
        if !normalized.starts_with(&self.workspace) {
            return Err(outside());
        }

        // 3. …and under the canonical workspace once symlinks are followed.
        let workspace_real = self.workspace.canonicalize()?;
        let target_real = real_target(&normalized)?;
        if !target_real.starts_with(&workspace_real) {
            return Err(outside());
        }

        Ok(normalized)
    }
}

fn outside() -> ToolError {
    ToolError::OutsideWorkspace {}
}

/// Canonicalize `path`, or the closest existing ancestor plus the remainder
/// (for paths that do not exist yet).
fn real_target(path: &Path) -> Result<PathBuf, std::io::Error> {
    match path.canonicalize() {
        Ok(real) => Ok(real),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => {
                Ok(real_target(parent)?.join(path.file_name().unwrap_or_default()))
            }
            _ => Err(err),
        },
        Err(err) => Err(err),
    }
}

/// Every defaulted class knob of a [`Tool`], in one value.
///
/// The knobs are read before a call (by the broker, the registry and the
/// engine's egress layer), never during it. Grouping them in one struct is the
/// forward-all seal: a wrapper implements [`Tool::class`] by forwarding the
/// inner tool's value, so a knob added here is forwarded by construction and
/// can never be silently dropped by a wrapper that only lists the knobs it
/// knew about. [`Tool::class`] has no default, so every wrapper must answer it.
///
/// A tool that wants the conservative defaults writes
/// `fn class(&self) -> ToolClass { ToolClass::default() }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolClass {
    /// See [`Tool::requires_explicit_rule`].
    pub requires_explicit_rule: bool,
    /// See [`Tool::risk_is_corroborated`].
    pub risk_is_corroborated: bool,
    /// See [`Tool::output_trust`].
    pub output_trust: crate::Trust,
    /// See [`Tool::execution_mode`].
    pub execution_mode: crate::ExecutionMode,
    /// See [`Tool::returns_private_data`].
    pub returns_private_data: bool,
    /// See [`Tool::performs_web_egress`].
    pub performs_web_egress: bool,
    /// See [`Tool::egress_url_argument`].
    pub egress_url_argument: bool,
    /// See [`Tool::arguments_leave_machine`].
    pub arguments_leave_machine: bool,
    /// See [`Tool::skill_only`].
    pub skill_only: bool,
}

impl Default for ToolClass {
    /// The conservative answer for a tool that declares nothing: untrusted
    /// output, sandboxed, private data, no wildcard allow, not skill-only.
    fn default() -> Self {
        Self {
            requires_explicit_rule: false,
            risk_is_corroborated: true,
            output_trust: crate::Trust::Untrusted,
            execution_mode: crate::ExecutionMode::Sandboxed,
            returns_private_data: true,
            performs_web_egress: false,
            egress_url_argument: false,
            arguments_leave_machine: false,
            skill_only: false,
        }
    }
}

/// A callable tool.
///
/// Implementations must be cheaply shareable (`Send + Sync`) because the chat
/// loop holds them behind a registry. `run` is async through `async-trait` so
/// the trait stays object-safe (`dyn Tool`).
#[async_trait]
pub trait Tool: Send + Sync {
    /// Stable name the model uses to call the tool.
    fn name(&self) -> &str;

    /// JSON schema of the arguments object, ready to send to a provider.
    fn schema(&self) -> serde_json::Value;

    /// Validate `args` and execute the tool.
    async fn run(&self, args: &serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError>;

    /// Risk classification of this tool.
    fn risk(&self) -> Risk;

    /// The privacy path this tool runs on (`docs/phase1.md` §2).
    ///
    /// Required, with no default: a new tool does not compile until it names
    /// its row. The registry drops the tool in private mode when that row is
    /// not allowed (see `privacy_wiring::retain_mountable`).
    fn path_id(&self) -> kernel_core::privacy::PathId;

    /// Every defaulted class knob, in one value ([`ToolClass`]).
    ///
    /// Required, with no default: a wrapper must forward this, so a knob added
    /// to [`ToolClass`] reaches every wrapper without a new method to remember.
    fn class(&self) -> ToolClass;

    /// Fixed destination hosts used by an egress tool when its arguments do
    /// not contain a `url`. Hosts are bare DNS names; the engine builds a
    /// synthetic HTTPS root URL to run the same shape, deny-domain, mode,
    /// private-data and budget checks it applies to URL-based fetches. The
    /// returned list may depend on the arguments, but it must describe every
    /// host the call can contact. An egress tool with neither a URL argument
    /// nor declared hosts is refused before it runs.
    fn egress_hosts(&self, _arguments: &serde_json::Value) -> &'static [&'static str] {
        &[]
    }

    /// The exact text a declared-host call sends off the machine (for example a
    /// place name or coordinates), validated the way the tool validates it. The
    /// engine shows it on the approval card and stores its SHA-256 in the
    /// `web.fetch` row. `None` when nothing beyond the declared hosts leaves.
    fn egress_query(&self, _arguments: &serde_json::Value) -> Option<String> {
        None
    }
}

/// The sealed extension trait every [`Tool`] gets: one accessor per
/// [`ToolClass`] knob, each reading [`Tool::class`].
///
/// The trait is **sealed** and blanket-implemented for every
/// `T: Tool + ?Sized`, so a tool cannot answer an accessor on its own: the
/// only way to change what `skill_only()`, `output_trust()` or any other knob
/// says is to change [`Tool::class`]. That is what makes a wrapper's single
/// `class()` forward total — a wrapper cannot silently drop the skill floor
/// (or any other knob) by overriding one accessor with a default answer.
///
/// A `Tool` implementation cannot add its own `skill_only`:
///
/// ```compile_fail
/// use async_trait::async_trait;
/// use kernel_broker::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
/// use serde_json::Value;
///
/// struct Sneaky;
///
/// #[async_trait]
/// impl Tool for Sneaky {
///     fn name(&self) -> &str {
///         "sneaky"
///     }
///     fn schema(&self) -> Value {
///         serde_json::json!({"type": "object"})
///     }
///     async fn run(&self, _args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
///         Ok(ToolOutput::ok(""))
///     }
///     fn risk(&self) -> Risk {
///         Risk::Low
///     }
///     fn path_id(&self) -> kernel_core::privacy::PathId {
///         kernel_core::privacy::PathId::B5
///     }
///     fn class(&self) -> ToolClass {
///         ToolClass {
///             skill_only: true,
///             ..ToolClass::default()
///         }
///     }
///     // E0407: `skill_only` is not a member of `Tool`; the sealed accessor
///     // reads `class()` and cannot be overridden with `false`.
///     fn skill_only(&self) -> bool {
///         false
///     }
/// }
/// ```
pub trait ToolClassExt: sealed::Sealed + Tool {
    /// Whether a wildcard `allow` rule must not authorize this tool. When
    /// true, only a rule naming this exact tool may allow it automatically.
    fn requires_explicit_rule(&self) -> bool {
        self.class().requires_explicit_rule
    }

    /// Whether this risk classification comes from local policy. Native
    /// tools are corroborated by their implementation; server-provided MCP
    /// classifications must opt in through a local classifier.
    fn risk_is_corroborated(&self) -> bool {
        self.class().risk_is_corroborated && !self.name().starts_with("mcp__")
    }

    /// Trust level of this tool's output.
    ///
    /// Deny-by-default: a tool is trusted only when it **explicitly** declares
    /// [`Trust::Trusted`] in its [`Tool::class`]. A tool that can reach outside
    /// (fetch, connector, mail) or execute arbitrary code (`shell`) returns
    /// content the owner did not author, so its default is
    /// [`Trust::Untrusted`]: its output taints the conversation and forces
    /// approval for consequential calls. A new tool fails closed until someone
    /// classifies it. Pure local deterministic tools (`read_file` of a trusted
    /// path, `write_file` result text) declare `Trusted`.
    fn output_trust(&self) -> crate::Trust {
        self.class().output_trust
    }

    /// How this tool will execute, for the broker's unsandboxed bar.
    ///
    /// `Sandboxed` for every tool that has no sandbox escape hatch; the
    /// `shell` tool derives it from its [`ShellSandbox`] profile: `Unsandboxed`
    /// exactly when [`launch`] would run without a sandbox, `Networked` when
    /// the sandbox has every socket open (`[shell] network = true`). Both
    /// force an ask. The default is the conservative answer for tools that do
    /// not run commands at all; the registry still fails closed for names it
    /// cannot resolve ([`crate::ToolRegistry::execution_mode`]).
    ///
    /// [`ShellSandbox`]: crate::ShellSandbox
    /// [`launch`]: crate::sandbox::launch
    fn execution_mode(&self) -> crate::ExecutionMode {
        self.class().execution_mode
    }

    /// True when this tool returns workspace file content (or other owner
    /// private data) to the model, so reading it must flip the conversation's
    /// `carries_private_data` egress rule for the rest of the conversation.
    ///
    /// The read itself stays card-free — this class changes only the egress
    /// rule — and the flag is **conversation-scoped** by design: unlike the
    /// workspace-level taint mark, a private read in one conversation does not
    /// make a sibling conversation private. Default `true` (fail toward
    /// masking): a new or undeclared tool counts as
    /// private until it declares itself public with `false`. MCP, connector,
    /// `http_fetch` (a signed or tokenised URL can return owner content) and
    /// memory-recall adapters declare `true`; `read_file` declares `true`;
    /// public tools (weather) and ack-only writes declare `false` explicitly.
    fn returns_private_data(&self) -> bool {
        self.class().returns_private_data
    }

    /// True when this tool performs web egress, so the engine's egress layer
    /// must run the deterministic URL-shape/deny gate and the mode/sensitive-
    /// turn ask rule **before** the tool runs.
    ///
    /// `http_fetch` declares it; a future connector fetch tool must too, or it
    /// would bypass the gate. Default `false`: the engine never assumes a tool
    /// fetches from its name.
    fn performs_web_egress(&self) -> bool {
        self.class().performs_web_egress
    }

    /// True when the egress destination is the `url` argument. Such a tool
    /// checks its own `url` and refuses a missing or non-string one as invalid
    /// arguments before any socket opens, so the engine leaves that call to the
    /// tool instead of refusing it as an undeclared egress tool.
    fn egress_url_argument(&self) -> bool {
        self.class().egress_url_argument
    }

    /// True when the call hands its arguments to a third party (an MCP
    /// server). The engine screens such arguments for a high-confidence
    /// identifier ([`crate::argument_screen`]) and, in a conversation that
    /// already carries private data, asks before the call even under an exact
    /// allow rule, the way an unseen web host is held. Default `false`: a
    /// native tool's arguments stay on the machine unless it declares otherwise.
    fn arguments_leave_machine(&self) -> bool {
        self.class().arguments_leave_machine
    }

    /// True when this tool may run only inside a skill.
    ///
    /// The broker receives the skill context as an `Option<SkillRef>`. A
    /// skill-only tool requested with `None` is
    /// [`crate::Authorization::Denied`] with the reason `"skill-only tool"`,
    /// **before** any approver is consulted; requested with `Some`, the
    /// minimum action is `ask` — a hardline floor no `allow` rule can lift.
    /// Default `false`: a tool is not skill-only until it declares so.
    fn skill_only(&self) -> bool {
        self.class().skill_only
    }
}

impl<T: Tool + ?Sized> ToolClassExt for T {}

/// The seal: [`ToolClassExt`] is implemented for exactly the types that
/// implement [`Tool`], so no downstream crate can write an accessor of its own
/// that disagrees with [`Tool::class`].
mod sealed {
    pub trait Sealed {}

    impl<T: ?Sized + crate::Tool> Sealed for T {}
}

/// A tool whose advertised text the application fixed at compile time.
///
/// Only a native tool can be registered with [`ToolRegistry::register_native`].
/// Its three metadata methods return `'static` text, so the system prompt
/// trusts that text without a scan. Nothing built at runtime satisfies the
/// bound: a `String` field, a config value or a server's declaration cannot
/// be borrowed for `'static` without an explicit leak. A tool whose text is
/// built at runtime (MCP, plugins) implements only [`Tool`] and registers
/// through [`ToolRegistry::register`], which gates its text before the model
/// sees it.
///
/// A native tool with static metadata registers and runs as usual:
///
/// ```
/// use async_trait::async_trait;
/// use kernel_broker::{NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, ToolRegistry};
/// use serde_json::{json, Value};
/// use std::sync::LazyLock;
///
/// struct Greeter;
///
/// #[async_trait]
/// impl Tool for Greeter {
///     fn path_id(&self) -> kernel_core::privacy::PathId {
///         kernel_core::privacy::PathId::B5
///     }
///
///     fn class(&self) -> ToolClass {
///         ToolClass::default()
///     }
///
///     fn name(&self) -> &str {
///         self.native_name()
///     }
///
///     fn schema(&self) -> Value {
///         self.native_schema().clone()
///     }
///
///     async fn run(&self, _args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
///         Ok(ToolOutput::ok("hello"))
///     }
///
///     fn risk(&self) -> Risk {
///         Risk::Low
///     }
/// }
///
/// impl NativeTool for Greeter {
///     fn native_name(&self) -> &'static str {
///         "greet"
///     }
///
///     fn native_description(&self) -> &'static str {
///         "Say hello."
///     }
///
///     fn native_schema(&self) -> &'static Value {
///         static SCHEMA: LazyLock<Value> = LazyLock::new(|| json!({"type": "object"}));
///         LazyLock::force(&SCHEMA)
///     }
/// }
///
/// let mut registry = ToolRegistry::new();
/// registry.register_native(Box::new(Greeter));
/// assert!(registry.get("greet").is_some());
/// ```
///
/// Text built at runtime cannot become native metadata: the name below is a
/// `String` owned by the tool, so it cannot be returned as `&'static str`.
///
/// ```compile_fail
/// use async_trait::async_trait;
/// use kernel_broker::{NativeTool, Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput};
/// use serde_json::Value;
/// use std::sync::LazyLock;
///
/// struct Runtime {
///     name: String,
/// }
///
/// #[async_trait]
/// impl Tool for Runtime {
///     fn path_id(&self) -> kernel_core::privacy::PathId {
///         kernel_core::privacy::PathId::B5
///     }
///
///     fn class(&self) -> ToolClass {
///         ToolClass::default()
///     }
///
///     fn name(&self) -> &str {
///         &self.name
///     }
///
///     fn schema(&self) -> Value {
///         Value::Null
///     }
///
///     async fn run(&self, _args: &Value, _ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
///         Ok(ToolOutput::ok(""))
///     }
///
///     fn risk(&self) -> Risk {
///         Risk::Low
///     }
/// }
///
/// impl NativeTool for Runtime {
///     fn native_name(&self) -> &'static str {
///         &self.name
///     }
///
///     fn native_description(&self) -> &'static str {
///         "A declared tool."
///     }
///
///     fn native_schema(&self) -> &'static Value {
///         static SCHEMA: LazyLock<Value> = LazyLock::new(|| Value::Null);
///         LazyLock::force(&SCHEMA)
///     }
/// }
/// ```
pub trait NativeTool: Tool {
    /// The name the model calls the tool by. Must equal [`Tool::name`]; a
    /// mismatch registers the tool on the gated path instead.
    fn native_name(&self) -> &'static str;

    /// The description the model reads, fixed for the process lifetime.
    fn native_description(&self) -> &'static str;

    /// The JSON schema of the arguments, built once for the process lifetime.
    fn native_schema(&self) -> &'static serde_json::Value;
}

/// The metadata of a native tool, as the registry keeps it.
#[derive(Debug, Clone, Copy)]
pub struct NativeDecl {
    /// The tool name.
    pub name: &'static str,
    /// The description the model reads.
    pub description: &'static str,
    /// The argument schema.
    pub schema: &'static serde_json::Value,
}

/// How the registry knows a tool's advertised text. Decided by the
/// registration path, never by the tool's name.
#[derive(Debug, Clone, Copy)]
pub enum Declaration {
    /// Application text fixed at compile time: trusted, not scanned.
    Native(NativeDecl),
    /// Text built at runtime (a server, a plugin): always gated.
    Dynamic,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_joins_relative_paths_onto_the_workspace() {
        let dir = tempdir().unwrap();
        let ctx = ToolCtx::new("main", dir.path());
        assert_eq!(
            ctx.resolve("notes/todo.md").unwrap(),
            dir.path().join("notes/todo.md")
        );
    }

    #[test]
    fn resolve_allows_absolute_paths_inside_the_workspace() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("note.txt");
        std::fs::write(&file, "hi").unwrap();

        let ctx = ToolCtx::new("main", dir.path());
        assert_eq!(ctx.resolve(file.to_str().unwrap()).unwrap(), file);
    }

    #[test]
    fn resolve_rejects_absolute_paths_outside_the_workspace() {
        let dir = tempdir().unwrap();
        let ctx = ToolCtx::new("main", dir.path());
        let err = ctx.resolve("/etc/hosts").unwrap_err();
        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[test]
    fn resolve_rejects_parent_traversal() {
        let dir = tempdir().unwrap();
        let ctx = ToolCtx::new("main", dir.path());
        let err = ctx.resolve("../escape.txt").unwrap_err();
        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[test]
    fn resolve_rejects_ghost_prefix_traversal() {
        // Regression for M1-injection-reverify NEW-01: a non-existent first
        // component must not smuggle `..` past the check.
        let dir = tempdir().unwrap();
        let ctx = ToolCtx::new("main", dir.path());
        let err = ctx.resolve("newghost/../../../../config.toml").unwrap_err();
        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[test]
    fn resolve_normalizes_inner_parents() {
        let dir = tempdir().unwrap();
        let ctx = ToolCtx::new("main", dir.path());
        assert_eq!(
            ctx.resolve("a/../b.txt").unwrap(),
            dir.path().join("b.txt"),
            "inner `..` collapses without escaping"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_rejects_symlink_escapes() {
        let dir = tempdir().unwrap();
        std::os::unix::fs::symlink("/etc", dir.path().join("link")).unwrap();

        let ctx = ToolCtx::new("main", dir.path());
        let err = ctx.resolve("link/hosts").unwrap_err();
        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[test]
    fn output_helpers_set_the_error_flag() {
        assert_eq!(
            ToolOutput::ok("fine"),
            ToolOutput {
                content: "fine".to_string(),
                is_error: false
            }
        );
        assert!(ToolOutput::error("boom").is_error);
    }

    #[test]
    fn risk_labels_are_lowercase() {
        assert_eq!(Risk::Low.as_str(), "low");
        assert_eq!(Risk::Medium.to_string(), "medium");
        assert_eq!(Risk::High.to_string(), "high");
        assert_eq!(
            serde_json::to_value(Risk::High).unwrap(),
            serde_json::json!("high")
        );
        assert_eq!(
            serde_json::from_value::<Risk>(serde_json::json!("medium")).unwrap(),
            Risk::Medium
        );
    }
}
