//! P2 acceptance: `~/.auxesis/mcp.toml` parsing and validation.
//!
//! Offline and self-contained: no server is contacted, no secret is read.

use kernel_mcp::{McpConfig, McpConfigError, McpTransport};

const VALID: &str = r#"
[[server]]
id = "datagouv"
catalog_id = "datagouv-mcp"
transport = "http"
url = "https://mcp.data.gouv.fr/mcp"
env = ["DATAGOUV_KEY"]
enabled = true
[server.agents]
main = ["search_datasets", "get_dataset"]

[[server]]
id = "local-tools"
transport = "stdio"
command = "/usr/local/bin/local-mcp"
args = ["--stdio", "--quiet"]
enabled = false
"#;

#[test]
fn a_valid_file_exposes_only_what_it_declares() {
    let config = McpConfig::parse("mcp.toml", VALID).expect("valid config");
    assert_eq!(config.server.len(), 2);
    assert_eq!(config.enabled_servers().count(), 1);

    let datagouv = config.server("datagouv").expect("datagouv present");
    assert_eq!(datagouv.transport, McpTransport::Http);
    assert_eq!(
        datagouv.url.as_deref(),
        Some("https://mcp.data.gouv.fr/mcp")
    );
    assert_eq!(datagouv.env, vec!["DATAGOUV_KEY".to_string()]);
    let names = datagouv.agents.get("main").expect("main listed");
    assert_eq!(
        names,
        &["search_datasets".to_string(), "get_dataset".to_string()]
    );
    assert!(config.server("nope").is_none());
}

#[test]
fn an_absent_file_is_an_empty_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let config = McpConfig::load_from_path(&dir.path().join("mcp.toml")).expect("missing is empty");
    assert!(config.is_empty());
    assert_eq!(config.enabled_servers().count(), 0);
}

#[test]
fn an_unknown_field_quarantines_only_its_entry() {
    let text = r#"
[[server]]
id = "x"
transport = "http"
url = "https://example.invalid/mcp"
enabled = true
surprise = "nope"

[[server]]
id = "good"
transport = "http"
url = "https://example.invalid/mcp"
"#;
    let config = McpConfig::parse("mcp.toml", text).unwrap();
    assert_eq!(config.server.len(), 1);
    assert_eq!(config.server[0].id, "good");
    assert_eq!(config.quarantined.len(), 1);
    assert_eq!(config.quarantined[0].id, "x");
    assert_eq!(config.quarantined[0].reason, "unknown_key");
}

#[test]
fn a_top_level_unknown_key_is_refused() {
    let err = McpConfig::parse("mcp.toml", "[servers]\nfoo = 1\n").unwrap_err();
    assert!(matches!(err, McpConfigError::Invalid { .. }), "{err}");
}

#[test]
fn plain_http_is_refused_off_loopback_but_allowed_on_it() {
    let base = |url: &str| {
        format!("[[server]]\nid = \"x\"\ntransport = \"http\"\nurl = \"{url}\"\nenabled = true\n")
    };
    let refused = McpConfig::parse("mcp.toml", &base("http://mcp.data.gouv.fr/mcp")).unwrap();
    assert!(refused.server[0].check().is_err());
    assert!(
        McpConfig::parse("mcp.toml", &base("http://127.0.0.1:8080/mcp"))
            .unwrap()
            .server[0]
            .check()
            .is_ok()
    );
    assert!(
        McpConfig::parse("mcp.toml", &base("http://localhost:8080/mcp"))
            .unwrap()
            .server[0]
            .check()
            .is_ok()
    );
    assert!(
        McpConfig::parse("mcp.toml", &base("https://mcp.data.gouv.fr/mcp"))
            .unwrap()
            .server[0]
            .check()
            .is_ok()
    );
}

#[test]
fn per_server_failures_are_quarantinable_not_whole_file_errors() {
    // A relative stdio command, an http server with a command, a malformed id
    // and a reserved env name are refused one by one, never as a whole file.
    let text = r#"
[[server]]
id = "x"
transport = "stdio"
command = "npx"
enabled = true
"#;
    let config = McpConfig::parse("mcp.toml", text).unwrap();
    assert!(config.server[0].check().is_err());

    let text = r#"
[[server]]
id = "x"
transport = "http"
url = "https://example.invalid/mcp"
command = "/bin/true"
enabled = true
"#;
    let config = McpConfig::parse("mcp.toml", text).unwrap();
    assert_eq!(
        config.server[0].check().unwrap_err().label,
        "invalid_server"
    );
}

#[test]
fn malformed_ids_are_per_server_and_duplicates_are_quarantined() {
    for id in ["UPPER", "with space", "", "a/b"] {
        let text = format!(
            "[[server]]\nid = \"{id}\"\ntransport = \"http\"\nurl = \"https://e.invalid/mcp\"\n"
        );
        let config = McpConfig::parse("mcp.toml", &text).unwrap();
        assert!(
            config.server[0].check().is_err(),
            "id {id:?} must be quarantined"
        );
    }
    // Item 6: a duplicate is quarantined one by one, never a whole-file error.
    let duplicate = r#"
[[server]]
id = "x"
transport = "http"
url = "https://a.invalid/mcp"

[[server]]
id = "x"
transport = "http"
url = "https://b.invalid/mcp"
"#;
    let config = McpConfig::parse("mcp.toml", duplicate).unwrap();
    // Item 6: a duplicated id quarantines **both** entries as `duplicate_id`,
    // so deleting one can never promote the hidden duplicate.
    assert!(config.server.is_empty());
    assert_eq!(config.quarantined.len(), 2);
    assert!(config
        .quarantined
        .iter()
        .all(|entry| entry.reason == "duplicate_id"));
}

#[test]
fn reserved_auxesis_env_names_are_per_server_refusals() {
    let text = |name: &str| {
        format!(
            "[[server]]\nid = \"x\"\ntransport = \"http\"\n\
             url = \"https://e.invalid/mcp\"\nenv = [\"{name}\"]\n"
        )
    };
    assert!(McpConfig::parse("mcp.toml", &text("DATAGOUV_KEY"))
        .unwrap()
        .server[0]
        .check()
        .is_ok());
    assert!(McpConfig::parse("mcp.toml", &text("AUX_KEY_OPENAI"))
        .unwrap()
        .server[0]
        .check()
        .is_err());
    assert!(McpConfig::parse("mcp.toml", &text("AUXESIS_HOME"))
        .unwrap()
        .server[0]
        .check()
        .is_err());
    assert!(
        McpConfig::parse("mcp.toml", &text("1BAD")).unwrap().server[0]
            .check()
            .is_err()
    );
}

#[test]
fn an_oversize_file_is_refused_before_parsing() {
    let text = "x".repeat(kernel_mcp::MAX_MCP_CONFIG_BYTES as usize + 1);
    let err = McpConfig::parse("mcp.toml", &text).unwrap_err();
    assert!(matches!(err, McpConfigError::TooLarge { .. }), "{err}");
}

#[test]
fn legacy_dots_table_still_loads_as_agents_and_rewrites_cleanly() {
    // Configs written before the rename say `[server.dots]`; they must still load.
    let legacy = r#"
[[server]]
id = "datagouv"
transport = "http"
url = "https://mcp.data.gouv.fr/mcp"
enabled = true
[server.dots]
main = ["search_datasets"]
"#;
    let mut config = McpConfig::parse("mcp.toml", legacy).unwrap();
    let server = config.server("datagouv").expect("datagouv present");
    assert_eq!(
        server.agents.get("main"),
        Some(&vec!["search_datasets".to_string()])
    );

    // A rewrite that changes the map must not leave both spellings in one table.
    let server = config
        .server
        .iter_mut()
        .find(|server| server.id == "datagouv")
        .unwrap();
    server.agents.insert("axis".to_owned(), Vec::new());
    let rewritten = config.to_toml_string().unwrap();
    assert!(!rewritten.contains("dots"), "{rewritten}");
    assert!(McpConfig::parse("mcp.toml", &rewritten).is_ok());
}
