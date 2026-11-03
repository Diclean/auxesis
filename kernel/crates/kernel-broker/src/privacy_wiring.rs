//! Mount-time privacy gate for tools.
//!
//! The daemon calls [`retain_mountable`] on the turn's registry after every
//! source has registered its tools. Tool specs and dispatch both read that
//! registry, so a dropped tool is neither offered to the model nor callable.
//!
//! Mounting is decided once per registry, so a tool mounted in open mode
//! would keep running after a switch to private. [`gate_dispatch`] closes that
//! gap: every tool asks the gate again, with the live mode, at each call.

use std::sync::Arc;

use crate::{Risk, Tool, ToolClass, ToolCtx, ToolError, ToolOutput, ToolRegistry};
use async_trait::async_trait;
use kernel_core::privacy::{admit_call, may_mount, Destination, ModeFn, PathId, PrivacyMode};

/// Drop every tool whose path is not allowed in `mode`. Returns the dropped
/// names, sorted, so the caller can log them.
pub fn retain_mountable(registry: &mut ToolRegistry, mode: PrivacyMode) -> Vec<String> {
    registry.retain(|tool| may_mount(tool.path_id(), mode))
}

/// Wrap every tool in `registry` so that each call is admitted against the
/// mode `live` returns at that moment. A call in a refused path returns
/// [`ToolError::PrivacyDisabled`] and never reaches the tool.
///
/// Everything except `run` is forwarded unchanged, so the engine's taint,
/// egress and approval decisions see the same tool.
pub fn gate_dispatch(registry: &mut ToolRegistry, live: ModeFn) {
    registry.map_tools(|tool| {
        Box::new(LiveGated {
            inner: tool,
            live: Arc::clone(&live),
        })
    });
}

/// A tool whose calls ask the privacy gate with the live mode.
struct LiveGated {
    inner: Box<dyn Tool>,
    live: ModeFn,
}

#[async_trait]
impl Tool for LiveGated {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn schema(&self) -> serde_json::Value {
        self.inner.schema()
    }

    async fn run(&self, args: &serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        // The grant lives for this call only; it is never stored on the tool.
        // It travels in the context so an egressing tool (an MCP server) can
        // build its `SafeValue` from it instead of sending raw arguments.
        let grant = admit_call(self.path_id(), (self.live)(), Destination::LocalDisplay).map_err(
            |refused| ToolError::PrivacyDisabled {
                path: refused.path.as_str(),
            },
        )?;
        let ctx = ctx.clone().with_grant(grant);
        self.inner.run(args, &ctx).await
    }

    fn risk(&self) -> Risk {
        self.inner.risk()
    }

    fn path_id(&self) -> PathId {
        self.inner.path_id()
    }

    /// One forward for every class knob, present and future: the wrapper never
    /// lists them, so a knob added to [`ToolClass`] cannot be dropped here.
    fn class(&self) -> ToolClass {
        self.inner.class()
    }

    fn egress_hosts(&self, arguments: &serde_json::Value) -> &'static [&'static str] {
        self.inner.egress_hosts(arguments)
    }

    fn egress_query(&self, arguments: &serde_json::Value) -> Option<String> {
        self.inner.egress_query(arguments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExecutionMode, Risk, Tool, ToolClass, ToolClassExt, ToolCtx, ToolError, ToolOutput, Trust,
    };
    use async_trait::async_trait;
    use kernel_core::privacy::PathId;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Row(&'static str, PathId);

    #[async_trait]
    impl Tool for Row {
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
            Ok(ToolOutput::ok("ok"))
        }
        fn risk(&self) -> Risk {
            Risk::Low
        }
        fn path_id(&self) -> PathId {
            self.1
        }
        fn class(&self) -> ToolClass {
            ToolClass::default()
        }
    }

    #[test]
    fn private_mode_drops_only_uncovered_tools_and_keeps_local_shell() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Row("shell", PathId::B5)));
        registry.register(Box::new(Row("gmail_search", PathId::B8)));
        registry.register(Box::new(Row("screen", PathId::C9)));

        let dropped = retain_mountable(&mut registry, PrivacyMode::Private);
        assert_eq!(dropped, ["gmail_search"]);
        assert_eq!(registry.names(), ["screen", "shell"]);
    }

    /// A live mode the test flips between calls, as a config switch would.
    fn switch() -> (Arc<AtomicBool>, ModeFn) {
        let private = Arc::new(AtomicBool::new(false));
        let reader = Arc::clone(&private);
        let live: ModeFn = Arc::new(move || {
            if reader.load(Ordering::SeqCst) {
                PrivacyMode::Private
            } else {
                PrivacyMode::Open
            }
        });
        (private, live)
    }

    #[tokio::test]
    async fn a_mounted_local_tool_keeps_running_after_switch_to_private() {
        let (private, live) = switch();
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Row("shell", PathId::B5)));
        registry.register(Box::new(Row("screen", PathId::C9)));
        gate_dispatch(&mut registry, live);
        let ctx = ToolCtx::new("main", std::env::temp_dir());
        let args = serde_json::json!({});

        let shell = registry.get("shell").expect("mounted").run(&args, &ctx);
        assert!(shell.await.is_ok(), "open mode runs the mounted tool");

        private.store(true, Ordering::SeqCst);
        let private_call = registry
            .get("shell")
            .expect("still mounted")
            .run(&args, &ctx);
        assert!(
            private_call.await.is_ok(),
            "a covered local tool runs in private"
        );
        // A covered row keeps running in private mode.
        let screen = registry.get("screen").expect("mounted").run(&args, &ctx);
        assert!(screen.await.is_ok());

        private.store(false, Ordering::SeqCst);
        let back = registry.get("shell").expect("mounted").run(&args, &ctx);
        assert!(back.await.is_ok(), "open again: the tool runs again");
    }

    /// Every class knob, each set away from its default, in one explicit
    /// literal: a knob added to [`ToolClass`] breaks this test's build until it
    /// is listed here and asserted below. That is the forward-all guard.
    fn probe_class() -> ToolClass {
        ToolClass {
            requires_explicit_rule: true,
            risk_is_corroborated: false,
            output_trust: Trust::Trusted,
            execution_mode: ExecutionMode::Unsandboxed,
            returns_private_data: false,
            performs_web_egress: true,
            egress_url_argument: true,
            arguments_leave_machine: true,
            skill_only: true,
        }
    }

    struct Classed;

    #[async_trait]
    impl Tool for Classed {
        fn path_id(&self) -> PathId {
            PathId::B5
        }
        fn class(&self) -> ToolClass {
            probe_class()
        }
        fn name(&self) -> &str {
            "classed"
        }
        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }
        async fn run(
            &self,
            _args: &serde_json::Value,
            _ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            Ok(ToolOutput::ok("ok"))
        }
        fn risk(&self) -> Risk {
            Risk::Low
        }
        fn egress_hosts(&self, _arguments: &serde_json::Value) -> &'static [&'static str] {
            &["probe.example"]
        }
        fn egress_query(&self, _arguments: &serde_json::Value) -> Option<String> {
            Some("probe".to_string())
        }
    }

    #[test]
    fn gating_forwards_every_tool_class_knob() {
        let (_private, live) = switch();
        let gated = LiveGated {
            inner: Box::new(Classed),
            live,
        };
        let args = serde_json::json!({});
        // One forward carries every knob, present and future.
        assert_eq!(gated.class(), probe_class());
        // Each accessor reads its own knob, never a default.
        assert!(gated.requires_explicit_rule());
        assert!(!gated.risk_is_corroborated());
        assert_eq!(gated.output_trust(), Trust::Trusted);
        assert_eq!(gated.execution_mode(), ExecutionMode::Unsandboxed);
        assert!(!gated.returns_private_data());
        assert!(gated.performs_web_egress());
        assert!(gated.egress_url_argument());
        assert!(gated.arguments_leave_machine());
        assert!(gated.skill_only());
        // The two argument-dependent egress methods are forwarded too.
        assert_eq!(gated.egress_hosts(&args), &["probe.example"]);
        assert_eq!(gated.egress_query(&args), Some("probe".to_string()));
    }

    #[test]
    fn gating_keeps_a_skill_only_tool_skill_only() {
        // Seal P3-1: the class accessors are sealed, so a wrapper forwards the
        // whole class through `class()` and cannot answer `skill_only()` with
        // its own value. `Classed` declares `skill_only: true`; after
        // `gate_dispatch` the mounted tool must still report it, or the
        // broker's hardline floor would be lost on the way to the engine.
        let (_private, live) = switch();
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Classed));
        gate_dispatch(&mut registry, live);
        let gated = registry.get("classed").expect("mounted");
        assert!(
            gated.skill_only(),
            "the skill floor must survive gate_dispatch"
        );
        assert_eq!(registry.skill_only_tools(), ["classed"]);
    }

    /// Records whether the gate attached a grant to the call context.
    struct GrantSeen(Arc<AtomicBool>);

    #[async_trait]
    impl Tool for GrantSeen {
        fn name(&self) -> &str {
            "grant_seen"
        }
        fn schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object"})
        }
        async fn run(
            &self,
            _args: &serde_json::Value,
            ctx: &ToolCtx,
        ) -> Result<ToolOutput, ToolError> {
            self.0.store(ctx.grant().is_some(), Ordering::SeqCst);
            Ok(ToolOutput::ok("ok"))
        }
        fn risk(&self) -> Risk {
            Risk::Low
        }
        fn path_id(&self) -> PathId {
            PathId::C9
        }
        fn class(&self) -> ToolClass {
            ToolClass::default()
        }
    }

    #[tokio::test]
    async fn the_gate_attaches_the_grant_to_the_call_context() {
        let (_private, live) = switch();
        let seen = Arc::new(AtomicBool::new(false));
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(GrantSeen(Arc::clone(&seen))));
        gate_dispatch(&mut registry, live);
        let ctx = ToolCtx::new("main", std::env::temp_dir());
        let args = serde_json::json!({});
        assert!(registry
            .get("grant_seen")
            .expect("mounted")
            .run(&args, &ctx)
            .await
            .is_ok());
        assert!(seen.load(Ordering::SeqCst), "the grant must reach the tool");
        assert!(ctx.grant().is_none(), "the caller's context is unchanged");
    }

    #[test]
    fn gating_keeps_the_names_and_metadata_the_engine_reads() {
        let (_private, live) = switch();
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Row("shell", PathId::B5)));
        gate_dispatch(&mut registry, live);
        assert_eq!(registry.names(), ["shell"]);
        assert_eq!(registry.get("shell").unwrap().path_id(), PathId::B5);
    }

    #[test]
    fn open_mode_keeps_every_tool_the_registry_allows_openly() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(Row("shell", PathId::B5)));
        registry.register(Box::new(Row("gmail_search", PathId::B8)));
        assert!(retain_mountable(&mut registry, PrivacyMode::Open).is_empty());
        assert_eq!(registry.names(), ["gmail_search", "shell"]);
    }
}
