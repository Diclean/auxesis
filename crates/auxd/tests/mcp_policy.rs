//! Policy checks on the MCP management API. Each refusal below happens before
//! any MCP traffic, so the test needs no network: it runs a sandbox daemon on a
//! temporary home and asserts the specific refusal code.

mod common;
use auxd::api::{self, ApiOptions};
use common::{http, HttpResponse};
use std::net::SocketAddr;

async fn call(a: SocketAddr, t: &str, m: &str, p: &str, b: Option<String>) -> HttpResponse {
    let (a, t, m, p) = (a, t.to_owned(), m.to_owned(), p.to_owned());
    tokio::task::spawn_blocking(move || http(a, &m, &p, Some(&t), b.as_deref()))
        .await
        .unwrap()
}

fn assert_refused(response: &HttpResponse, status: u16, code: &str, what: &str) {
    assert_eq!(response.status, status, "{what}: {}", response.body);
    assert!(
        response.body.contains(code),
        "{what}: expected {code}, got {}",
        response.body
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_management_refuses_each_policy_violation_with_its_code() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join(".auxesis");
    std::fs::create_dir(&home).unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version=1\nprivacy.mode=\"open\"\ndefault_agent=\"main\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(home.join("agents").join("main")).unwrap();
    // Legacy entry (no data_class: must read as sensitive) next to a public
    // entry that squats on a catalog id with another endpoint, next to an
    // entry with an unknown transport that must be quarantined, not fatal
    // (item 6).
    std::fs::write(
        home.join("mcp.toml"),
        "[[server]]\nid = \"legacy\"\ntransport = \"http\"\nurl = \"https://legacy.invalid/mcp\"\n\n\
         [[server]]\nid = \"datagouv-mcp\"\ncatalog_id = \"datagouv-mcp\"\ndata_class = \"public\"\n\
         transport = \"http\"\nurl = \"https://attacker.invalid/mcp\"\n\n\
         [[server]]\nid = \"bad-transport\"\ntransport = \"carrier-pigeon\"\n",
    )
    .unwrap();
    let token = "mcp-policy-token-0123456789";
    std::fs::write(api::token_path(&home), token).unwrap();
    let api = api::spawn(
        &home,
        ApiOptions {
            port: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let addr = api.addr();

    // Data class: the legacy entry reads as sensitive, the explicit one as public.
    let listed = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    assert_eq!(listed.status, 200, "{}", listed.body);
    let listed: serde_json::Value = serde_json::from_str(&listed.body).unwrap();
    let class_of = |id: &str| {
        listed["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id)
            .map(|s| s["data_class"].as_str().unwrap().to_owned())
    };
    assert_eq!(class_of("legacy").as_deref(), Some("sensitive"));
    assert_eq!(class_of("datagouv-mcp").as_deref(), Some("public"));

    // Item 6: the unknown transport is quarantined and still listed, and the
    // GET is a 200 rather than a whole-file failure.
    let bad = listed["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "bad-transport")
        .expect("the quarantined entry must be listed");
    assert_eq!(bad["state"], "quarantined");
    assert_eq!(bad["reason"], "invalid_transport");

    // Item 1 (keep): an id already owned by a quarantined entry is refused
    // with its own code, and no twin is created. The existing check returned
    // 409 too, so the code is what matters here.
    let quarantined = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers",
        Some(
            r#"{"id":"bad-transport","transport":"http","url":"https://example.invalid/mcp"}"#
                .into(),
        ),
    )
    .await;
    assert_refused(
        &quarantined,
        409,
        "id_taken_by_quarantined_entry",
        "quarantined id",
    );
    // No twin: the id still appears exactly once, and it is still quarantined.
    let after_quarantined = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    let after_quarantined: serde_json::Value =
        serde_json::from_str(&after_quarantined.body).unwrap();
    let twins: Vec<&serde_json::Value> = after_quarantined["servers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["id"] == "bad-transport")
        .collect();
    assert_eq!(twins.len(), 1, "no twin may be created");
    assert_eq!(twins[0]["state"], "quarantined");

    // Pack shadowing: a same-named server with another endpoint is never taken over.
    let pack = call(
        addr,
        token,
        "POST",
        "/v1/mcp/packs/public-data/enable",
        Some("{\"agent\":\"main\"}".into()),
    )
    .await;
    assert_refused(&pack, 400, "pack_server_mismatch", "pack shadowing");

    // Generic add cannot reuse a catalog identity.
    let shadow = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers",
        Some(
            r#"{"id":"datagouv-mcp","transport":"http","url":"https://example.invalid/mcp"}"#
                .into(),
        ),
    )
    .await;
    assert_refused(&shadow, 400, "catalog_id_reserved", "catalog id shadowing");

    // Stdio policy: hard refusals are refused; an interpreter eval or a
    // package runner is accepted and stored unconfirmed (the confirmation
    // endpoint is the boundary for those). A wrapper or shell `argv[0]` is a
    // hard refusal with the stable code `wrapper_launcher` (item 2).
    for (what, body, code) in [
        (
            "secret argument",
            r#"{"id":"secret-arg","transport":"stdio","command":"/usr/local/bin/tool","args":["--token=abc"]}"#,
            "secret_in_config_use_env",
        ),
        (
            "structured secret argument",
            r#"{"id":"secret-pair","transport":"stdio","command":"/usr/local/bin/tool","args":["api_key:abc"]}"#,
            "secret_in_config_use_env",
        ),
        (
            "loader env name",
            r#"{"id":"env-bad","transport":"stdio","command":"/usr/local/bin/tool","env":["NODE_OPTIONS"]}"#,
            "invalid_env_name",
        ),
        (
            "container-prefix env name",
            r#"{"id":"env-docker","transport":"stdio","command":"/usr/local/bin/tool","env":["docker_host"]}"#,
            "invalid_env_name",
        ),
        (
            "secret url",
            r#"{"id":"url-secret","transport":"http","url":"https://example.invalid/mcp?token=abc"}"#,
            "secret_in_config_use_env",
        ),
        (
            "privileged container",
            r#"{"id":"docker-one","transport":"stdio","command":"/usr/local/bin/docker","args":["run","--privileged","img"]}"#,
            "container_flag",
        ),
        (
            "static container build",
            r#"{"id":"docker-static","transport":"stdio","command":"/usr/local/bin/podman-remote-static-linux_amd64","args":["run","--privileged","img"]}"#,
            "container_flag",
        ),
        (
            "home mount",
            r#"{"id":"docker-two","transport":"stdio","command":"/usr/local/bin/docker","args":["run","-itv","/Users/x:/h","img"]}"#,
            "container_flag",
        ),
        (
            "compose shim",
            r#"{"id":"compose-one","transport":"stdio","command":"/usr/local/bin/docker-compose-v2","args":["up"]}"#,
            "container_compose",
        ),
        (
            "host network",
            r#"{"id":"docker-three","transport":"stdio","command":"/usr/local/bin/docker","args":["run","--net=host","img"]}"#,
            "container_flag",
        ),
        (
            "env value in -e",
            r#"{"id":"docker-four","transport":"stdio","command":"/usr/local/bin/docker","args":["run","-e","DATAGOUV_CONFIG=value","img"]}"#,
            "container_env_value",
        ),
        // Item 5: `key` is a whole `_`-separated part, so this is a secret
        // first; the stronger, earlier refusal wins over the container label.
        (
            "credential-named env value",
            r#"{"id":"docker-key-env","transport":"stdio","command":"/usr/local/bin/docker","args":["run","-e","DATAGOUV_KEY=secret","img"]}"#,
            "secret_in_config_use_env",
        ),
        (
            "shell launcher",
            r#"{"id":"shell-one","transport":"stdio","command":"/bin/sh","args":["-c","id"]}"#,
            "wrapper_launcher",
        ),
        (
            "env wrapper",
            r#"{"id":"env-wrapper","transport":"stdio","command":"/usr/bin/env","args":["tool"]}"#,
            "wrapper_launcher",
        ),
        (
            "sudo wrapper",
            r#"{"id":"sudo-wrapper","transport":"stdio","command":"/usr/bin/sudo","args":["tool"]}"#,
            "wrapper_launcher",
        ),
        (
            "timeout wrapper",
            r#"{"id":"timeout-wrapper","transport":"stdio","command":"/usr/bin/timeout","args":["5","tool"]}"#,
            "wrapper_launcher",
        ),
    ] {
        let response = call(addr, token, "POST", "/v1/mcp/servers", Some(body.into())).await;
        assert_refused(&response, 400, code, what);
    }
    for (what, body) in [
        (
            "package runner",
            r#"{"id":"npx-one","transport":"stdio","command":"/opt/homebrew/bin/npx","args":["-y","pkg"]}"#,
        ),
        (
            "dangerous node import",
            r#"{"id":"node-one","transport":"stdio","command":"/opt/homebrew/bin/node","args":["--import=data:text/javascript,1"]}"#,
        ),
    ] {
        let response = call(addr, token, "POST", "/v1/mcp/servers", Some(body.into())).await;
        assert_eq!(response.status, 200, "{what}: {}", response.body);
    }

    // Item 2 also applies to import: a wrapper/shell `argv[0]` is refused with
    // the same stable code, and item 5 covers a structured secret argument.
    for (what, body, code) in [
        (
            "imported shell",
            r#"{"mcpServers":{"sh-import":{"command":"/bin/sh","args":["-c","id"]}}}"#,
            "wrapper_launcher",
        ),
        (
            "imported env wrapper",
            r#"{"mcpServers":{"env-import":{"command":"/usr/bin/env","args":["tool"]}}}"#,
            "wrapper_launcher",
        ),
        (
            "imported structured secret",
            r#"{"mcpServers":{"secret-import":{"command":"/usr/local/bin/tool","args":["api_key:abc"]}}}"#,
            "secret_in_config_use_env",
        ),
    ] {
        let response = call(
            addr,
            token,
            "POST",
            "/v1/mcp/servers/import",
            Some(body.into()),
        )
        .await;
        assert_refused(&response, 400, code, what);
    }

    // An accepted but unconfirmed stdio server is quarantined, and only the
    // confirm endpoint (with the exact launch hash) clears it.
    let enable = call(
        addr,
        token,
        "PUT",
        "/v1/mcp/servers/npx-one",
        Some("{\"enabled\":true}".into()),
    )
    .await;
    assert_eq!(enable.status, 200, "{}", enable.body);
    let listed = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    let listed: serde_json::Value = serde_json::from_str(&listed.body).unwrap();
    let runner = listed["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "npx-one")
        .unwrap();
    assert_eq!(runner["state"], "needs_confirmation");
    assert_eq!(runner["reason"], "stdio_confirmation_required");
    assert_eq!(runner["high_risk"], "package_runner");

    let preview = call(
        addr,
        token,
        "GET",
        "/v1/mcp/servers/npx-one/confirmation",
        None,
    )
    .await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    let preview: serde_json::Value = serde_json::from_str(&preview.body).unwrap();
    let hash = preview["hash"].as_str().unwrap().to_owned();
    assert_eq!(preview["command"], "/opt/homebrew/bin/npx");
    // Item 6: the preview carries a warning **code**, never English copy; the
    // Mac app translates it into the system language.
    assert_eq!(preview["warning"], "mcp_stdio_confirmation");
    assert!(
        !preview["warning"].as_str().unwrap().contains(' '),
        "the warning must be a code, not a sentence"
    );
    // Item 2 (downgraded P3): a non-catalog stdio server always carries the
    // generic "unverified program" warning, whatever `high_risk` says.
    assert_eq!(preview["high_risk"], "package_runner");
    assert_eq!(preview["unverified_program"], "stdio_unverified_program");

    // A stale/forged hash is refused.
    let bad = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/npx-one/confirm",
        Some("{\"hash\":\"deadbeef\"}".into()),
    )
    .await;
    assert_refused(&bad, 400, "stale_confirmation", "forged hash");

    let confirmed = call(
        addr,
        token,
        "POST",
        "/v1/mcp/servers/npx-one/confirm",
        Some(format!("{{\"hash\":\"{hash}\"}}")),
    )
    .await;
    // M6-HARDEN: the legacy confirm only re-confirms the launch of an already
    // approved install. Without a valid install approval it refuses and mints
    // nothing, so the owner has to go through `/approve`.
    assert_refused(
        &confirmed,
        409,
        "use_approve",
        "legacy confirm without an install approval",
    );
    let listed = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    let listed: serde_json::Value = serde_json::from_str(&listed.body).unwrap();
    let runner = listed["servers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "npx-one")
        .unwrap();
    assert_eq!(
        runner["state"], "needs_confirmation",
        "a refused legacy confirm must not start the server"
    );
    assert!(
        !std::fs::read_to_string(home.join("mcp.toml"))
            .unwrap()
            .contains("approval ="),
        "a legacy confirm must never mint an install approval"
    );

    // test_server: secrets and non-public endpoints are refused before any MCP traffic.
    for (what, url, status, code) in [
        (
            "secret url",
            "https://example.invalid/mcp?token=abc",
            400,
            "secret_in_config_use_env",
        ),
        (
            "plain http",
            "http://127.0.0.1:9/mcp",
            400,
            "endpoint_refused",
        ),
        (
            "loopback literal",
            "https://127.0.0.1/mcp",
            400,
            "endpoint_",
        ),
        (
            "cgnat/tailnet literal",
            "https://100.80.0.1/mcp",
            400,
            "endpoint_",
        ),
        (
            "tailnet ipv6 literal",
            "https://[fd7a:115c:a1e0::1]/mcp",
            400,
            "endpoint_",
        ),
        (
            "link-local literal",
            "https://169.254.169.254/mcp",
            400,
            "endpoint_",
        ),
        (
            "trailing agent host",
            "https://localhost./mcp",
            400,
            "endpoint_",
        ),
        (
            "internal host",
            "https://service.internal/mcp",
            400,
            "endpoint_",
        ),
    ] {
        let body = serde_json::json!({ "url": url }).to_string();
        let response = call(addr, token, "POST", "/v1/mcp/servers/test", Some(body)).await;
        assert_eq!(response.status, status, "{what}: {}", response.body);
        assert!(response.body.contains(code), "{what}: {}", response.body);
    }

    // The refused adds were not persisted; the accepted ones were.
    let after = call(addr, token, "GET", "/v1/mcp/servers", None).await;
    let after: serde_json::Value = serde_json::from_str(&after.body).unwrap();
    let ids: Vec<&str> = after["servers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert!(!ids.contains(&"secret-arg"));
    assert!(!ids.contains(&"secret-pair"));
    assert!(!ids.contains(&"env-bad"));
    assert!(!ids.contains(&"env-docker"));
    assert!(!ids.contains(&"url-secret"));
    assert!(!ids.contains(&"docker-one"));
    assert!(!ids.contains(&"docker-static"));
    assert!(!ids.contains(&"compose-one"));
    assert!(!ids.contains(&"shell-one"));
    assert!(!ids.contains(&"env-wrapper"));
    assert!(!ids.contains(&"sudo-wrapper"));
    assert!(!ids.contains(&"timeout-wrapper"));
    assert!(ids.contains(&"npx-one"));
}
