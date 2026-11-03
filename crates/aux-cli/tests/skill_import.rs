//! The owner CLI transfers file contents to the sandboxed daemon for review.
mod common;

use auxd::api::{self, ApiOptions};
use std::os::unix::fs::PermissionsExt;

#[test]
fn cli_import_and_approve_review_the_same_content() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join("agents/mail")).unwrap();
    std::fs::write(
        home.join("agents/mail/agent.md"),
        "---\nname: mail\nbrain: cloud\ndefault_mode: open\ntools: [mail.read]\n---\nAssistant.\n",
    )
    .unwrap();
    std::fs::write(
        home.join("config.toml"),
        "version = 1\ndefault_agent = \"mail\"\n",
    )
    .unwrap();
    let token = api::token_path(&home);
    std::fs::write(
        &token,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let handle = runtime.block_on(async {
        api::spawn(
            &home,
            ApiOptions {
                port: 0,
                ..ApiOptions::default()
            },
        )
        .unwrap()
    });
    let path = std::fs::canonicalize(dir.path()).unwrap().join("parcel.md");
    let content = "---\nname: parcel\nversion: 1\ntools: [mail.read]\ntrigger:\n  manual: true\napproval: each_action\n---\nRead a fictional parcel.\n";
    std::fs::write(&path, content).unwrap();
    let aux = |args: &[&str]| {
        common::sandbox_command(env!("CARGO_BIN_EXE_aux"), dir.path(), &home)
            .env("AUXESIS_API_PORT", handle.addr().port().to_string())
            .args(args)
            .output()
            .unwrap()
    };
    let imported = aux(&["skill", "--agent", "mail", "import", path.to_str().unwrap()]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    assert!(String::from_utf8_lossy(&imported.stdout).contains(content));
    assert!(!home.join("agents/mail/skills/parcel.md").exists());
    assert_eq!(
        std::fs::read_to_string(home.join("skill-imports/pending/mail/parcel.md")).unwrap(),
        content
    );
    let approved = aux(&["skill", "--agent", "mail", "approve", "parcel"]);
    assert!(
        approved.status.success(),
        "{}",
        String::from_utf8_lossy(&approved.stderr)
    );
    assert!(String::from_utf8_lossy(&approved.stdout).contains(content));
    assert_eq!(
        std::fs::read_to_string(home.join("agents/mail/skills/parcel.md")).unwrap(),
        content
    );
}
