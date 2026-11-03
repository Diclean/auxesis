//! The model capability catalog: `catalog/models.toml`.
//!
//! The catalog is generated **offline** by `scripts/import-models.py` from the
//! vendored `catalog/models.dev.json`; the app never fetches models.dev at
//! runtime (`docs/providers.md` §4). One row per model carries the `tools`
//! capability the skill gate reads. A model that is not in the catalog is
//! treated as `tools = false` until the owner adds it.

use serde::{Deserialize, Serialize};

/// The catalog bundled with the binary. The build fails if it is malformed.
pub const BUNDLED_CATALOG: &str = include_str!("../../../catalog/models.toml");

/// One `[[model]]` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRow {
    /// Provider id the model belongs to (`anthropic`, `deepseek`, …).
    pub provider: String,
    /// Model id, as it travels on the wire.
    pub id: String,
    /// The model can call tools.
    #[serde(default)]
    pub tools: bool,
    /// Informational in Phase 1.
    #[serde(default)]
    pub structured_output: bool,
    /// Context window in tokens, when the upstream reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<u64>,
    /// Maximum output tokens, when the upstream reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<u64>,
    /// Input price in USD per million tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_usd_mtok: Option<f64>,
    /// Output price in USD per million tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_usd_mtok: Option<f64>,
}

/// The parsed `catalog/models.toml`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CatalogFile {
    /// `[[model]]` rows.
    #[serde(default, rename = "model")]
    pub models: Vec<ModelRow>,
}

/// A read-only capability catalog.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    rows: Vec<ModelRow>,
}

impl Catalog {
    /// Parse a catalog document.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        let file: CatalogFile = toml::from_str(text)
            .map_err(|err| kernel_core::redact_toml_error(&err, "models.toml", text))?;
        Ok(Self { rows: file.models })
    }

    /// The catalog compiled into the binary.
    pub fn bundled() -> Self {
        Self::parse(BUNDLED_CATALOG).expect("catalog/models.toml is generated and valid")
    }

    /// The row for `(provider, id)`, if the catalog has one.
    pub fn get(&self, provider: &str, id: &str) -> Option<&ModelRow> {
        self.rows
            .iter()
            .find(|row| row.provider == provider && row.id == id)
    }

    /// Whether `(provider, id)` may call tools. A model missing from the
    /// catalog is `tools = false`.
    pub fn has_tools(&self, provider: &str, id: &str) -> bool {
        self.get(provider, id).map(|row| row.tools).unwrap_or(false)
    }

    /// The label the brain picker shows next to a model: `chat only` when it
    /// cannot use tools, empty otherwise.
    pub fn capability_label(&self, provider: &str, id: &str) -> &'static str {
        if self.has_tools(provider, id) {
            ""
        } else {
            ChatOnly::LABEL
        }
    }

    /// Every row.
    pub fn rows(&self) -> &[ModelRow] {
        &self.rows
    }
}

/// A refusal because the resolved model cannot use tools but the skill needs
/// them (`docs/providers.md` §4). The label is `chat only`; the gate runs
/// before any request is made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{model} cannot use tools; pick another brain for this skill")]
pub struct ChatOnly {
    /// The model that was refused.
    pub model: String,
}

impl ChatOnly {
    /// The label shown by the brain picker and carried by the refusal.
    pub const LABEL: &'static str = "chat only";
}

/// Gate one resolved brain for a skill: a skill with any tool needs
/// `tools = true`, otherwise the skill refuses to start with `chat only`.
pub fn gate_skill_tools(
    catalog: &Catalog,
    provider: &str,
    model: &str,
    needs_tools: bool,
) -> Result<(), ChatOnly> {
    if needs_tools && !catalog.has_tools(provider, model) {
        return Err(ChatOnly {
            model: model.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[model]]
provider = "anthropic"
id = "claude-opus-5-5"
tools = true
structured_output = true
context = 1000000
output = 128000
input_usd_mtok = 4.0
output_usd_mtok = 20.0

[[model]]
provider = "deepseek"
id = "deepseek-chat"
tools = true

[[model]]
provider = "ollama-cloud"
id = "granite3.3:2b"
tools = false
"#;

    #[test]
    fn a_parse_error_names_the_file_and_line_never_the_text() {
        let text = "[[model]]\nprovider = \"x\"\nid = \"sk-CANARY-1234567890abcdef\n";
        let err = Catalog::parse(text).unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        assert!(
            !shown.contains("CANARY") && !debug.contains("CANARY"),
            "{debug}"
        );
        assert!(shown.contains("models.toml, line 3"), "{shown}");
    }

    #[test]
    fn parses_rows_and_reads_the_tools_capability() {
        let catalog = Catalog::parse(SAMPLE).unwrap();
        assert_eq!(catalog.rows().len(), 3);
        assert!(catalog.has_tools("anthropic", "claude-opus-5-5"));
        assert!(catalog.has_tools("deepseek", "deepseek-chat"));
        assert!(!catalog.has_tools("ollama-cloud", "granite3.3:2b"));
    }

    #[test]
    fn a_model_missing_from_the_catalog_has_no_tools() {
        let catalog = Catalog::parse(SAMPLE).unwrap();
        assert!(!catalog.has_tools("anthropic", "not-listed"));
        assert_eq!(
            catalog.capability_label("anthropic", "not-listed"),
            ChatOnly::LABEL
        );
        assert_eq!(catalog.capability_label("anthropic", "claude-opus-5-5"), "");
    }

    #[test]
    fn the_bundled_catalog_parses_and_seeds_the_phase_1_models() {
        let catalog = Catalog::bundled();
        for (provider, id) in [
            ("anthropic", "claude-opus-5-5"),
            ("anthropic", "claude-sonnet-5-5"),
            ("anthropic", "claude-haiku-5-5"),
            ("deepseek", "deepseek-chat"),
        ] {
            assert!(
                catalog.get(provider, id).is_some(),
                "the catalog must seed {provider}/{id}"
            );
        }
    }

    #[test]
    fn a_skill_with_tools_is_refused_on_a_tools_less_brain() {
        let catalog = Catalog::parse(SAMPLE).unwrap();
        let refusal =
            gate_skill_tools(&catalog, "ollama-cloud", "granite3.3:2b", true).unwrap_err();
        assert_eq!(refusal.model, "granite3.3:2b");
        assert_eq!(
            refusal.to_string(),
            "granite3.3:2b cannot use tools; pick another brain for this skill"
        );
        assert_eq!(ChatOnly::LABEL, "chat only");

        // A skill with no tools runs on the same brain.
        assert!(gate_skill_tools(&catalog, "ollama-cloud", "granite3.3:2b", false).is_ok());
        assert!(gate_skill_tools(&catalog, "anthropic", "claude-opus-5-5", true).is_ok());
    }
}
