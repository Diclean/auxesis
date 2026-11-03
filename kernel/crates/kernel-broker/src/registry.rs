//! Name-based lookup for the tools the chat loop can call.

use crate::{
    Declaration, ExecutionMode, NativeDecl, NativeTool, ShellSandbox, SkillOnlyLookup, Tool,
    ToolClassExt,
};
use kernel_core::WebConfig;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

/// Connector tool names whose output is untrusted by convention.
///
/// `mcp__` is the MCP wire prefix, `mail_` the native mailbox
/// tools: both consume outside content. The name is trimmed and
/// ASCII-lowercased first, so casing, stray whitespace and zero-width
/// modifiers cannot smuggle a connector past the hook. This is the first
/// line of defence for a newly registered connector;
/// [`ToolRegistry::register`] and [`ToolRegistry::mark_untrusted_output`]
/// are the explicit sets, and everything unclassified fails closed anyway.
fn untrusted_name_hook(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    name.starts_with("mcp__") || name.starts_with("mail_")
}

/// Tool names whose output is **private owner data**: mail, calendar, memory
/// and notes. Reading one marks the conversation `carries_private_data`, and
/// after that an unseen web host asks (WEB-01). The reads themselves stay
/// silent: they only change the egress rules.
///
/// This name hook is only a backstop for a connector whose output is private
/// by convention. The **class** flag is [`Tool::returns_private_data`], which
/// the tool itself declares (and which the registry consults in
/// [`ToolRegistry::is_private_data`]); `read_file`, the Google and EventKit
/// reads use that flag, and the EventKit tools are also listed explicitly by
/// [`ToolRegistry::mark_private_data`] at registration. The `apple_*` prefixes
/// are the EventKit tool names; a bare `calendar_` prefix never matched them.
fn private_data_name_hook(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    [
        "mail_",
        "calendar_",
        "apple_calendar_",
        "apple_reminders_",
        "memory_",
        "notes_",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

/// One registered tool and the declaration its advertised text came with.
struct Entry {
    tool: Box<dyn Tool>,
    declaration: Declaration,
}

/// Registered tools, keyed by [`Tool::name`].
///
/// Lookup is deterministic (BTreeMap order), which keeps provider tool lists
/// and tests stable.
///
/// The registry also carries the **class** of each tool, which decides what
/// its output does to the conversation:
///
/// - **Output trust is deny-by-default.** A tool is trusted only when it
///   explicitly declares [`Tool::output_trust`] as trusted. Shells, fetchers,
///   connectors, mail tools, and any name nobody classified produce
///   untrusted output that taints the conversation.
/// - **Read-only is an explicit class.** Only tools marked with
///   [`ToolRegistry::mark_read_only`] keep their rule while the conversation
///   is tainted; [`Risk`](crate::Risk) is informational and never grants the
///   exemption (a side-effecting tool that under-reports its risk still
///   asks).
///
/// Both classifications fail closed: unclassified names are untrusted and
/// consequential.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, Entry>,
    untrusted_outputs: BTreeSet<String>,
    read_only: BTreeSet<String>,
    /// Tools whose output is private owner data (mail, calendar, memory,
    /// notes). Reading one flips the conversation's egress rule. The explicit
    /// set is a manual override; the tool's own
    /// [`Tool::returns_private_data`] flag is the class declaration.
    private_data: BTreeSet<String>,
    /// Tools kept out of what the model is offered (see
    /// [`ToolRegistry::mark_unoffered`]).
    unoffered: BTreeSet<String>,
    /// The sandbox profile the registry built `shell` with, when created
    /// through [`ToolRegistry::with_shell`]. Metadata only: the tool itself
    /// owns the profile it runs with.
    shell_sandbox: Option<ShellSandbox>,
    /// The `[web]` section the registry built `http_fetch` with. Metadata for
    /// the engine's egress policy; the tool itself holds its own gate.
    web: WebConfig,
}

impl ToolRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry containing the default tool set (M1 files + shell, M2 web).
    ///
    /// `shell` and `http_fetch` are explicitly untrusted: their results are
    /// whatever the outside world produced. `read_file`/`write_file` declare
    /// themselves trusted in their own implementations; `read_file` is the
    /// one read-only tool, so it keeps its configured rule while a
    /// conversation is tainted (taint applies at the workspace level in the
    /// engine, not per file). `read_file` also declares
    /// [`Tool::returns_private_data`], so a workspace file read flips the
    /// conversation's egress rule; `http_fetch` declares
    /// [`Tool::performs_web_egress`], so the engine gates it (and any future
    /// fetch tool) by class.
    ///
    /// The shell runs with [`ShellSandbox::default`]: sandboxed, no network,
    /// fail closed. Production runners build the registry from the loaded
    /// config instead (the app's engine's `registry_from_config`); this constructor
    /// is the safe default for tests and callers without a config.
    pub fn with_defaults() -> Self {
        Self::with_shell(ShellSandbox::default())
    }

    /// Like [`ToolRegistry::with_defaults`], with `shell` built from an
    /// explicit sandbox profile (the `[shell]` config section).
    ///
    /// The profile is passed through untouched, so the fail-closed rules stay
    /// in the tool: an unsandboxed run is only reachable with the double
    /// opt-in (`sandbox = false` + `allow_unsandboxed = true`, or an
    /// unavailable sandbox plus `allow_unsandboxed = true`), and `shell` stays
    /// in the untrusted-output class, so every run write-ahead taints the
    /// conversation and the workspace.
    pub fn with_shell(sandbox: ShellSandbox) -> Self {
        Self::with_shell_web(sandbox, WebConfig::default())
    }

    /// Like [`ToolRegistry::with_shell`], with `http_fetch` built from the
    /// `[web]` config section. This is the production entry point: the web
    /// gate must be the configured one, never the default.
    pub fn with_shell_web(sandbox: ShellSandbox, web: WebConfig) -> Self {
        let mut registry = Self::new();
        // The built-in tool implementations live in the app runtime; the
        // kernel registry ships the classes and metadata the engine reads.
        registry.mark_untrusted_output("http_fetch");
        registry.mark_untrusted_output("shell");
        registry.mark_read_only("read_file");
        registry.shell_sandbox = Some(sandbox);
        registry.web = web;
        registry
    }

    /// The `[web]` settings `http_fetch` was built with.
    pub fn web_config(&self) -> &WebConfig {
        &self.web
    }

    /// The sandbox profile `shell` was built with, when this registry was
    /// created through [`ToolRegistry::with_shell`] (and therefore
    /// [`ToolRegistry::with_defaults`]). `None` for an empty registry or one
    /// assembled tool by tool.
    pub fn shell_sandbox(&self) -> Option<&ShellSandbox> {
        self.shell_sandbox.as_ref()
    }

    /// Add a tool whose advertised text is built at runtime (an MCP server's
    /// declaration, a plugin). The prompt gates its name, description and
    /// schema before the model sees them. Returns any previous tool
    /// registered under the same name.
    pub fn register(&mut self, tool: Box<dyn Tool>) -> Option<Box<dyn Tool>> {
        self.insert(tool, Declaration::Dynamic)
    }

    /// Add an application-authored tool whose name, description and schema are
    /// `'static`. The prompt trusts that text without a scan. Returns any
    /// previous tool registered under the same name.
    ///
    /// The declared name must equal [`Tool::name`]. A tool that disagrees with
    /// itself is registered on the gated path instead, so it never advertises
    /// text it did not declare.
    pub fn register_native(&mut self, tool: Box<dyn NativeTool>) -> Option<Box<dyn Tool>> {
        let decl = NativeDecl {
            name: tool.native_name(),
            description: tool.native_description(),
            schema: tool.native_schema(),
        };
        let declaration = if tool.name() == decl.name {
            Declaration::Native(decl)
        } else {
            Declaration::Dynamic
        };
        self.insert(tool, declaration)
    }

    fn insert(&mut self, tool: Box<dyn Tool>, declaration: Declaration) -> Option<Box<dyn Tool>> {
        let name = tool.name().to_string();
        if untrusted_name_hook(&name) {
            self.untrusted_outputs.insert(name.clone());
        }
        if private_data_name_hook(&name) {
            self.private_data.insert(name.clone());
        }
        self.tools
            .insert(name, Entry { tool, declaration })
            .map(|previous| previous.tool)
    }

    /// Replace every registered tool through `f`, keeping each tool's name
    /// and both classification sets. The wrapped tool must keep its original
    /// [`Tool::name`]; a rename would silently drop the classification (the
    /// map is keyed by name).
    ///
    /// Used to wrap the whole set with an output filter (WA-MSG-0 scrubs
    /// tool results before persistence) without re-deriving the deny-by-
    /// default trust classes.
    pub fn map_tools(&mut self, mut f: impl FnMut(Box<dyn Tool>) -> Box<dyn Tool>) {
        let tools = std::mem::take(&mut self.tools);
        for (name, entry) in tools {
            let tool = f(entry.tool);
            self.tools.insert(
                name,
                Entry {
                    tool,
                    declaration: entry.declaration,
                },
            );
        }
    }

    /// Keep only the tools `keep` accepts, and return the names it dropped.
    ///
    /// The class sets are left alone: they are keyed by name, so a dropped
    /// name matches nothing. Used by the privacy gate to drop tools that are
    /// not allowed in the current mode before the model sees them.
    pub fn retain(&mut self, mut keep: impl FnMut(&dyn Tool) -> bool) -> Vec<String> {
        let mut dropped = Vec::new();
        self.tools.retain(|name, entry| {
            let kept = keep(entry.tool.as_ref());
            if !kept {
                dropped.push(name.clone());
            }
            kept
        });
        dropped
    }

    /// Owning version of [`ToolRegistry::map_tools`], for callers that build
    /// a registry and immediately wrap it.
    pub fn into_mapped(mut self, f: impl FnMut(Box<dyn Tool>) -> Box<dyn Tool>) -> ToolRegistry {
        self.map_tools(f);
        self
    }

    /// Mark `name` as a tool whose output must taint the conversation.
    pub fn mark_untrusted_output(&mut self, name: impl Into<String>) {
        self.untrusted_outputs.insert(name.into());
    }

    /// Mark `name` as read-only by construction: it observes local state and
    /// produces no side effects beyond its own result. Only this explicit
    /// class keeps an `allow` rule while the conversation is tainted; unknown
    /// names are consequential (fail closed).
    pub fn mark_read_only(&mut self, name: impl Into<String>) {
        self.read_only.insert(name.into());
    }

    /// Mark `name` as a tool whose output is private owner data (mail,
    /// calendar, memory, notes). Reading one flips the conversation's egress
    /// rule: after it, an unseen web host asks instead of running silently.
    pub fn mark_private_data(&mut self, name: impl Into<String>) {
        self.private_data.insert(name.into());
    }

    /// Keep `name` registered but out of what the model is offered: the broker
    /// refuses every call of it for this agent. A call still reaches the
    /// broker, which refuses it and records the decision.
    pub fn mark_unoffered(&mut self, name: impl Into<String>) {
        self.unoffered.insert(name.into());
    }

    /// True when `name` is kept out of what the model is offered.
    pub fn is_unoffered(&self, name: &str) -> bool {
        self.unoffered.contains(name)
    }

    /// True when `name`'s output is private owner data. The explicit set, the
    /// mail/calendar/memory/notes name hook, and the tool's own
    /// [`Tool::returns_private_data`] class flag all count; an unregistered or
    /// differently-named tool is not private data (the egress rule stays a
    /// deliberate, named class). Class-based so `read_file` — and any future
    /// file-content tool — is caught without a name prefix.
    pub fn is_private_data(&self, name: &str) -> bool {
        if self.private_data.contains(name) || private_data_name_hook(name) {
            return true;
        }
        self.get(name)
            .is_some_and(|tool| tool.returns_private_data())
    }

    /// True when content produced by `name` must be treated as untrusted.
    ///
    /// Deny-by-default: the explicit untrusted set and the connector name
    /// hook win; a registered tool is otherwise trusted only when it
    /// **explicitly** declares [`crate::Trust::Trusted`]. Anything else —
    /// including a name that is not registered at all — is untrusted, so a
    /// new tool cannot leak outside content into the conversation by simply
    /// existing.
    pub fn is_untrusted_output(&self, name: &str) -> bool {
        if self.untrusted_outputs.contains(name) || untrusted_name_hook(name) {
            return true;
        }
        match self.get(name) {
            Some(tool) => tool.output_trust().is_untrusted(),
            // Unknown provenance: fail closed.
            None => true,
        }
    }

    /// True when `name` is an explicitly declared read-only tool. Unknown
    /// names are consequential (fail closed).
    pub fn is_read_only(&self, name: &str) -> bool {
        self.read_only.contains(name)
    }

    /// Names of the registered tools that declare [`Tool::skill_only`], sorted.
    ///
    /// A **snapshot**, for display and audit. The broker's hardline skill floor
    /// does not use it: [`crate::Broker::new`] takes a live
    /// [`crate::SkillOnlyLookup`], and `ToolRegistry` implements it by reading
    /// the class of the tool registered at authorization time, so a tool
    /// registered after the broker was built is covered.
    pub fn skill_only_tools(&self) -> Vec<String> {
        self.tools
            .iter()
            .filter(|(_, entry)| entry.tool.skill_only())
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// How the tool `name` will execute, for the broker's execution-mode bar.
    ///
    /// A registered tool reports its own mode (`shell` derives it from the
    /// `[shell]` profile it was built with; everything else is `Sandboxed`).
    /// **Fail closed:** a name the registry cannot resolve is
    /// [`ExecutionMode::Unsandboxed`], so an unclassified call can never be
    /// auto-run by an `allow` rule. The engine passes this to
    /// [`Broker::authorize`], which raises every unsandboxed or
    /// network-enabled call to an ask on the first call, before any taint mark
    /// exists.
    pub fn execution_mode(&self, name: &str) -> ExecutionMode {
        match self.get(name) {
            Some(tool) => tool.execution_mode(),
            None => ExecutionMode::Unsandboxed,
        }
    }

    /// Look up a tool by name.
    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|entry| entry.tool.as_ref())
    }

    /// Iterate over every registered tool, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Tool> {
        self.tools.values().map(|entry| entry.tool.as_ref())
    }

    /// Iterate over every registered tool with its declaration, sorted by name.
    pub fn iter_declared(&self) -> impl Iterator<Item = (&dyn Tool, Declaration)> {
        self.tools
            .values()
            .map(|entry| (entry.tool.as_ref(), entry.declaration))
    }

    /// Registered names, sorted.
    pub fn names(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }

    /// Number of registered tools.
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// True when no tool is registered.
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

impl std::fmt::Debug for ToolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolRegistry")
            .field("tools", &self.names())
            .finish()
    }
}

/// The live skill floor of a registry: the class of the tool registered under
/// `tool` **at the moment the broker asks**, never a set copied at build time.
impl SkillOnlyLookup for ToolRegistry {
    fn is_skill_only(&self, tool: &str) -> bool {
        self.get(tool).is_some_and(|tool| tool.skill_only())
    }
}

/// The live skill floor of a **shared** registry.
///
/// [`ToolRegistry::register`] takes `&mut self`, so a broker built from an
/// `Arc<ToolRegistry>` can only ever see the tools registered before it. Hold
/// the registry in an `Arc<RwLock<ToolRegistry>>` and hand that to
/// [`crate::Broker::new`]: the read happens at authorization time, so a tool
/// registered after the broker was built is still covered.
///
/// A poisoned lock **raises** the floor instead of lowering it: an unreadable
/// registry answers `true`, so the call is denied without a skill context (or
/// held to an ask inside one). Fail closed.
impl SkillOnlyLookup for RwLock<ToolRegistry> {
    fn is_skill_only(&self, tool: &str) -> bool {
        match self.read() {
            Ok(registry) => registry.is_skill_only(tool),
            Err(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeTool, Risk, ToolClass, ToolCtx, ToolError, ToolOutput, Trust};
    use async_trait::async_trait;

    struct Dummy(&'static str);

    #[async_trait]
    impl Tool for Dummy {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            self.0
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok(self.0))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn class(&self) -> ToolClass {
            ToolClass::default()
        }
    }

    #[test]
    fn defaults_carry_the_safe_shell_profile() {
        let registry = ToolRegistry::with_defaults();
        let sandbox = registry.shell_sandbox().expect("defaults build shell");
        assert!(sandbox.enabled, "sandbox on by default");
        assert!(!sandbox.network, "network off by default");
        assert!(!sandbox.allow_unsandboxed, "fail closed by default");
        // The wired registry keeps the WS-C classes: shell output is
        // untrusted (and consequential), read_file is the only read-only tool.
        assert!(registry.is_untrusted_output("shell"));
        assert!(!registry.is_read_only("shell"));
    }

    #[test]
    fn with_shell_passes_the_profile_through() {
        // Config wiring regression (WSD-P2-07): the profile handed to the
        // registry is exactly the one the shell runs with.
        let profile = ShellSandbox::new(false, true, true);
        let registry = ToolRegistry::with_shell(profile.clone());
        assert_eq!(registry.shell_sandbox(), Some(&profile));
        assert!(registry.is_untrusted_output("shell"));
    }

    #[test]
    fn an_unknown_tool_name_fails_closed_to_unsandboxed() {
        let registry = ToolRegistry::new();
        assert_eq!(
            registry.execution_mode("never_heard_of_it"),
            ExecutionMode::Unsandboxed
        );
    }

    #[test]
    fn unknown_names_are_none() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Dummy("known")));
        assert!(registry.get("rm_rf").is_none());
        assert!(registry.get("known").is_some());
        assert!(!registry.is_empty());
        assert!(ToolRegistry::new().is_empty());
    }

    #[test]
    fn registering_twice_replaces() {
        let mut registry = ToolRegistry::new();
        assert!(registry.register(Box::new(Dummy("one"))).is_none());

        let replaced = registry.register(Box::new(Dummy("one")));
        assert!(replaced.is_some());
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get("one").unwrap().name(), "one");
    }

    #[test]
    fn iter_yields_every_tool_sorted() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Dummy("beta")));
        registry.register(Box::new(Dummy("alpha")));
        let names: Vec<_> = registry.iter().map(Tool::name).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn debug_lists_names() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Dummy("alpha")));
        registry.register(Box::new(Dummy("beta")));
        let rendered = format!("{registry:?}");
        assert!(rendered.contains("alpha"));
        assert!(rendered.contains("beta"));
    }

    struct UntrustedDummy;

    #[async_trait]
    impl Tool for UntrustedDummy {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            "custom_reader"
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok("outside content"))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                output_trust: Trust::Untrusted,
                ..ToolClass::default()
            }
        }
    }

    #[test]
    fn untrusted_output_names_are_explicit_and_extensible() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(TrustedDummy("read_file")));
        registry.register(Box::new(TrustedDummy("write_file")));
        registry.mark_untrusted_output("http_fetch");
        registry.mark_untrusted_output("shell");
        assert!(registry.is_untrusted_output("http_fetch"));
        assert!(registry.is_untrusted_output("shell"));
        assert!(!registry.is_untrusted_output("read_file"));
        assert!(!registry.is_untrusted_output("write_file"));
        let mut registry = ToolRegistry::new();
        registry.mark_untrusted_output("custom_reader");
        assert!(registry.is_untrusted_output("custom_reader"));
        registry.register(Box::new(Dummy("mcp__fakeserv__gmail_send")));
        registry.register(Box::new(Dummy("mail_send")));
        assert!(registry.is_untrusted_output("mcp__fakeserv__gmail_send"));
        assert!(registry.is_untrusted_output("mail_send"));
        registry.register(Box::new(UntrustedDummy));
        assert!(registry.is_untrusted_output("custom_reader"));
    }

    #[test]
    fn unclassified_tool_output_fails_closed() {
        // A registered tool that never declares its trust is untrusted…
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Dummy("mystery_tool")));
        assert!(registry.is_untrusted_output("mystery_tool"));
        // …and so is a name nobody classified or even registered.
        assert!(registry.is_untrusted_output("never_heard_of_it"));
        let registry = ToolRegistry::with_defaults();
        assert!(registry.is_untrusted_output("unknown_tool"));
    }

    struct TrustedDummy(&'static str);

    #[async_trait]
    impl Tool for TrustedDummy {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            self.0
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok(self.0))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                output_trust: Trust::Trusted,
                // Declared public, so the name-hook tests below stay meaningful.
                returns_private_data: false,
                ..ToolClass::default()
            }
        }
    }

    #[test]
    fn the_connector_name_hook_normalizes_case_and_whitespace() {
        // A future connector that declares itself trusted must not slip past
        // the name hook: casing and stray whitespace are normalized before
        // the prefix check.
        for name in [
            "MCP__fakeserv__gmail",
            "Mail_Read",
            " mail_read",
            "MAIL_READ",
            "mail_read\u{200b}",
        ] {
            let mut registry = ToolRegistry::new();
            registry.register(Box::new(TrustedDummy(name)));
            assert!(registry.is_untrusted_output(name), "{name:?}");
        }
        // An ordinary trusted name is unaffected.
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(TrustedDummy("read_notes")));
        assert!(!registry.is_untrusted_output("read_notes"));
    }

    #[test]
    fn only_explicitly_declared_read_only_tools_are_exempt() {
        let registry = ToolRegistry::with_defaults();
        assert!(registry.is_read_only("read_file"));
        for name in ["write_file", "shell", "http_fetch", "unclassified"] {
            assert!(!registry.is_read_only(name), "{name}");
        }

        let mut registry = ToolRegistry::new();
        registry.mark_read_only("custom_reader");
        assert!(registry.is_read_only("custom_reader"));
        assert!(!registry.is_read_only("custom_writer"));
    }

    #[test]
    fn private_data_class_is_named_and_testable() {
        // The class is class-based: a tool that declares the flag is private
        // data even without a name prefix.
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(PrivateDummy("workspace_bytes")));
        assert!(registry.is_private_data("workspace_bytes"));
        // The hook recognizes the future mail/calendar/memory/notes tools,
        // case- and whitespace-insensitively.
        for name in [
            "mail_read",
            "Mail_List",
            " calendar_read",
            "memory_search",
            "notes_read",
            "apple_calendar_list_events",
            "apple_reminders_list",
        ] {
            let mut registry = ToolRegistry::new();
            registry.register(Box::new(TrustedDummy(name)));
            assert!(registry.is_private_data(name), "{name:?}");
        }
        // An explicit marker works too, and an unrelated name stays out.
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(TrustedDummy("inbox_peek")));
        assert!(!registry.is_private_data("inbox_peek"));
        registry.mark_private_data("inbox_peek");
        assert!(registry.is_private_data("inbox_peek"));
        assert!(!registry.is_private_data("read_file"));
    }

    #[test]
    fn an_undeclared_tool_counts_as_private_data() {
        // Fail toward masking: a tool that never declares
        // the class is private, so its result flips the egress rule.
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Dummy("brand_new_tool")));
        assert!(registry.is_private_data("brand_new_tool"));
    }

    /// A tool that declares the private-data class flag.
    struct PrivateDummy(&'static str);

    #[async_trait]
    impl Tool for PrivateDummy {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            self.0
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok("private"))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                output_trust: Trust::Trusted,
                returns_private_data: true,
                ..ToolClass::default()
            }
        }
    }

    #[test]
    fn the_private_data_class_is_a_tool_flag_not_only_a_name_prefix() {
        // A name with no private prefix is still private once its tool
        // declares the class flag — the engine hook is class-based.
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(PrivateDummy("workspace_bytes")));
        assert!(registry.is_private_data("workspace_bytes"));
        // The class travels with the tool, not the name: replacing the tool
        // drops the class, as class-based means.
        registry.register(Box::new(TrustedDummy("workspace_bytes")));
        assert!(!registry.is_private_data("workspace_bytes"));
        // An unregistered name is never private data.
        assert!(!registry.is_private_data("never_heard_of_it"));
    }

    #[test]
    fn the_registry_carries_the_web_section_for_the_engine() {
        // The default registry carries the documented defaults…
        let registry = ToolRegistry::with_defaults();
        assert_eq!(registry.web_config(), &WebConfig::default());

        // …and the production constructor passes the configured section
        // through, so the engine's egress policy and the tool's own gate agree.
        let web = WebConfig {
            mode: kernel_core::WebMode::AlwaysAsk,
            deny_domains: vec!["bad.example".to_string()],
            ..WebConfig::default()
        };
        let registry = ToolRegistry::with_shell_web(ShellSandbox::default(), web.clone());
        assert_eq!(registry.web_config(), &web);
    }

    /// A native tool with a fixed name, description and schema.
    struct Declared {
        name: &'static str,
        declared_name: &'static str,
    }

    #[async_trait]
    impl Tool for Declared {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }
        fn name(&self) -> &str {
            self.name
        }

        fn schema(&self) -> serde_json::Value {
            self.native_schema().clone()
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok(""))
        }

        fn risk(&self) -> Risk {
            Risk::Low
        }

        fn class(&self) -> ToolClass {
            ToolClass::default()
        }
    }

    impl NativeTool for Declared {
        fn native_name(&self) -> &'static str {
            self.declared_name
        }

        fn native_description(&self) -> &'static str {
            "A declared tool."
        }

        fn native_schema(&self) -> &'static serde_json::Value {
            static SCHEMA: std::sync::LazyLock<serde_json::Value> =
                std::sync::LazyLock::new(|| serde_json::json!({"type": "object"}));
            std::sync::LazyLock::force(&SCHEMA)
        }
    }

    #[test]
    fn a_native_registration_keeps_its_declaration() {
        let mut registry = ToolRegistry::new();
        registry.register_native(Box::new(Declared {
            name: "declared",
            declared_name: "declared",
        }));
        registry.register(Box::new(Dummy("runtime")));

        let declarations: Vec<(&str, bool)> = registry
            .iter_declared()
            .map(|(tool, declaration)| (tool.name(), matches!(declaration, Declaration::Native(_))))
            .collect();
        assert_eq!(declarations, vec![("declared", true), ("runtime", false)]);
    }

    #[test]
    fn a_native_tool_whose_name_disagrees_with_its_declaration_is_dynamic() {
        let mut registry = ToolRegistry::new();
        registry.register_native(Box::new(Declared {
            name: "other",
            declared_name: "declared",
        }));

        let (_, declaration) = registry.iter_declared().next().unwrap();
        assert!(matches!(declaration, Declaration::Dynamic));
        assert!(registry.get("other").is_some());
        assert!(registry.get("declared").is_none());
    }

    #[test]
    fn map_tools_keeps_each_declaration() {
        let mut registry = ToolRegistry::new();
        registry.register_native(Box::new(Declared {
            name: "declared",
            declared_name: "declared",
        }));
        registry.map_tools(|tool| tool);

        let (_, declaration) = registry.iter_declared().next().unwrap();
        assert!(matches!(declaration, Declaration::Native(_)));
    }

    /// A tool whose class declares the skill floor.
    struct Classed(&'static str);

    #[async_trait]
    impl Tool for Classed {
        fn path_id(&self) -> kernel_core::privacy::PathId {
            kernel_core::privacy::PathId::B5
        }

        fn name(&self) -> &str {
            self.0
        }

        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }

        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok(self.0))
        }

        fn risk(&self) -> Risk {
            Risk::High
        }

        fn class(&self) -> ToolClass {
            ToolClass {
                skill_only: true,
                ..ToolClass::default()
            }
        }
    }

    #[test]
    fn the_skill_floor_is_read_live_from_the_registry() {
        // Seal P2-2(d): the registry answers the broker's `SkillOnlyLookup` at
        // authorization time, so a tool registered after the broker was built
        // is covered — and an unregistered name is never skill-only.
        let registry = ToolRegistry::new();
        assert!(!SkillOnlyLookup::is_skill_only(&registry, "gmail_send"));
        assert!(!SkillOnlyLookup::is_skill_only(&registry, "not_registered"));

        let shared = RwLock::new(ToolRegistry::new());
        assert!(!SkillOnlyLookup::is_skill_only(&shared, "gmail_send"));
        shared
            .write()
            .unwrap()
            .register(Box::new(Classed("gmail_send")));
        assert!(SkillOnlyLookup::is_skill_only(&shared, "gmail_send"));
        assert!(!SkillOnlyLookup::is_skill_only(&shared, "other"));
    }
}
