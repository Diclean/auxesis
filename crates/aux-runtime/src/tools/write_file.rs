//! `write_file` — write a text file inside the agent workspace. Medium risk: it
//! mutates local state but is recoverable.

use async_trait::async_trait;
use kernel_broker::ToolClass;
use kernel_broker::{NativeTool, Risk, Tool, ToolCtx, ToolError, ToolOutput, Trust};
use serde::Deserialize;
use std::path::Path;

/// Writes (or overwrites) a UTF-8 text file, creating parent directories.
#[derive(Debug, Default)]
pub struct WriteFileTool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteFileArgs {
    path: String,
    content: String,
}

impl NativeTool for WriteFileTool {
    fn native_name(&self) -> &'static str {
        "write_file"
    }

    fn native_description(&self) -> &'static str {
        "Write a UTF-8 text file inside the workspace, creating parent directories. Overwrites an existing file."
    }

    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File to write, inside the workspace. Relative paths resolve against the workspace."
                    },
                    "content": {
                        "type": "string",
                        "description": "Full text to write; overwrites an existing file."
                    }
                },
                "required": ["path", "content"],
                "additionalProperties": false
            })
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

/// Whether `path` lands in Git metadata under `workspace` (TOK-3b).
///
/// The check is case-folded, since APFS is case-insensitive by default and
/// `.GIT/config` is `.git/config` there. It runs on the lexical path and on
/// the closest existing ancestor once resolved, so a symlinked parent that
/// aliases `.git` is caught too.
fn touches_git_metadata(path: &Path, workspace: &Path) -> bool {
    fn names_git(path: &Path) -> bool {
        path.components().any(|component| {
            component
                .as_os_str()
                .to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
        })
    }
    let below = |path: &Path, root: &Path| path.strip_prefix(root).map(names_git).unwrap_or(false);
    if below(path, workspace) {
        return true;
    }
    let Ok(root) = workspace.canonicalize() else {
        return true;
    };
    path.ancestors()
        .find_map(|ancestor| ancestor.canonicalize().ok())
        .is_none_or(|real| below(&real, &root))
}

/// Checks where an opened descriptor really is; fails closed when the
/// platform cannot say.
fn opened_outside_git_metadata(file: &std::fs::File, workspace: &Path) -> Result<(), String> {
    let real = fd_real_path(file).map_err(|err| format!("cannot verify the opened file: {err}"))?;
    if touches_git_metadata(&real, workspace) {
        return Err("refusing to write Git metadata".to_string());
    }
    Ok(())
}

/// The real path an open descriptor points at (macOS `F_GETPATH`; Linux
/// `/proc/self/fd`).
#[cfg(target_os = "macos")]
fn fd_real_path(file: &std::fs::File) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::io::AsRawFd;

    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes, NUL-terminated, into
    // a buffer of exactly that size; the descriptor is owned by `file`.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    Ok(std::path::PathBuf::from(
        String::from_utf8_lossy(&buffer[..end]).into_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn fd_real_path(file: &std::fs::File) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::io::AsRawFd;

    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn fd_real_path(_file: &std::fs::File) -> std::io::Result<std::path::PathBuf> {
    Err(std::io::Error::other(
        "descriptor path verification is unavailable on this platform",
    ))
}

#[async_trait]
impl Tool for WriteFileTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B4
    }
    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: WriteFileArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;

        let path = ctx.resolve(&args.path)?;
        if touches_git_metadata(&path, &ctx.workspace) {
            return Err(ToolError::UnsafePath {
                path: args.path.clone(),
                reason: "refusing to write Git metadata".to_string(),
            });
        }
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(ToolError::UnsafePath {
                    path: args.path.clone(),
                    reason: "refusing to write through a symlink".to_string(),
                });
            }
            if !meta.is_file() {
                // FIFOs and devices block forever on open/write (NF3-03).
                return Err(ToolError::UnsafePath {
                    path: args.path.clone(),
                    reason: "target exists and is not a regular file".to_string(),
                });
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    return Err(ToolError::UnsafePath {
                        path: args.path.clone(),
                        reason: format!("hard-linked target (nlink={})", meta.nlink()),
                    });
                }
            }
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        // Open WITHOUT truncating first: validate the opened descriptor
        // (fstat) before touching a single byte (NEW3-02).
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)?
        };
        #[cfg(not(unix))]
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&path)?;

        let mut file = file;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(ToolError::UnsafePath {
                path: args.path.clone(),
                reason: "target is not a regular file".to_string(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() > 1 {
                return Err(ToolError::UnsafePath {
                    path: args.path.clone(),
                    reason: format!("hard-linked target (nlink={})", meta.nlink()),
                });
            }
        }
        // A parent can be swapped for a symlink between the checks above and
        // `open` (O_NOFOLLOW guards only the last component), so the opened
        // descriptor itself must not sit in Git metadata (TOK-3b).
        // Nothing is removed on refusal: under a race the file may be a real
        // Git file, and one this call created is empty and not executable,
        // so Git never runs it. The sandboxed shell cannot rename anything
        // into or out of `.git`, so the descriptor cannot move there later.
        if let Err(reason) = opened_outside_git_metadata(&file, &ctx.workspace) {
            return Err(ToolError::UnsafePath {
                path: args.path.clone(),
                reason,
            });
        }
        file.set_len(0)?;

        use std::io::Write;
        file.write_all(args.content.as_bytes())?;

        Ok(ToolOutput::ok(format!(
            "wrote {} bytes to {}",
            args.content.len(),
            path.display()
        )))
    }

    fn risk(&self) -> Risk {
        Risk::Medium
    }

    fn class(&self) -> ToolClass {
        ToolClass {
            returns_private_data: // The result is a write acknowledgement, not file content.
        false,
            output_trust: Trust::Trusted,
            ..ToolClass::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn ctx(dir: &std::path::Path) -> ToolCtx {
        ToolCtx::new("test", dir)
    }

    #[tokio::test]
    async fn writes_a_new_file() {
        let dir = tempdir().unwrap();
        let out = WriteFileTool
            .run(
                &json!({"path": "hello.txt", "content": "hi there"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap();

        assert!(!out.is_error);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("hello.txt")).unwrap(),
            "hi there"
        );
        assert!(
            out.content.contains("hello.txt"),
            "content: {}",
            out.content
        );
    }

    #[tokio::test]
    async fn refuses_git_metadata_writes() {
        let dir = tempdir().unwrap();
        let config = dir.path().join(".git/config");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "sentinel = true\n").unwrap();

        let err = WriteFileTool
            .run(
                &json!({"path": ".git/config", "content": "restored private value"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::UnsafePath { .. }));
        assert_eq!(
            std::fs::read_to_string(config).unwrap(),
            "sentinel = true\n"
        );
    }

    #[tokio::test]
    async fn refuses_git_metadata_writes_by_case_or_symlinked_parent() {
        let dir = tempdir().unwrap();
        let config = dir.path().join(".git/config");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "sentinel = true\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join(".git"), dir.path().join("meta")).unwrap();

        for path in [
            ".GIT/config",
            ".Git/hooks/pre-commit",
            "meta/config",
            "meta/hooks/pre-commit",
        ] {
            let err = WriteFileTool
                .run(
                    &json!({"path": path, "content": "restored private value"}),
                    &ctx(dir.path()),
                )
                .await
                .unwrap_err();
            assert!(
                matches!(err, ToolError::UnsafePath { .. }),
                "{path}: {err:?}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(config).unwrap(),
            "sentinel = true\n"
        );
        assert!(!dir.path().join(".git/hooks").exists());
    }

    #[test]
    fn a_descriptor_that_landed_in_git_metadata_is_refused() {
        // The race: the path checks passed, then a parent became a symlink
        // into `.git` before `open`. The descriptor check still catches it.
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
        std::os::unix::fs::symlink(dir.path().join(".git"), dir.path().join("notes")).unwrap();
        let swapped = std::fs::File::create(dir.path().join("notes/hooks/pre-commit")).unwrap();
        assert!(opened_outside_git_metadata(&swapped, dir.path()).is_err());

        let plain = std::fs::File::create(dir.path().join("plain.md")).unwrap();
        assert!(opened_outside_git_metadata(&plain, dir.path()).is_ok());
    }

    #[tokio::test]
    async fn creates_missing_parent_directories() {
        let dir = tempdir().unwrap();
        WriteFileTool
            .run(
                &json!({"path": "deep/nested/note.md", "content": "ok"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.path().join("deep/nested/note.md")).unwrap(),
            "ok"
        );
    }

    #[tokio::test]
    async fn overwrites_an_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("note.txt");
        std::fs::write(&path, "old").unwrap();

        WriteFileTool
            .run(
                &json!({"path": path.to_str().unwrap(), "content": "new"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[tokio::test]
    async fn outside_absolute_paths_are_rejected() {
        let dir = tempdir().unwrap();
        let err = WriteFileTool
            .run(
                &json!({"path": "/tmp/auxesis-escape.txt", "content": "nope"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[tokio::test]
    async fn parent_traversal_is_rejected() {
        let dir = tempdir().unwrap();
        let err = WriteFileTool
            .run(
                &json!({"path": "../escape.txt", "content": "nope"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_directory_escapes_are_rejected() {
        let dir = tempdir().unwrap();
        std::os::unix::fs::symlink("/tmp", dir.path().join("link")).unwrap();

        let err = WriteFileTool
            .run(
                &json!({"path": "link/auxesis-escape.txt", "content": "nope"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[tokio::test]
    async fn ghost_prefix_traversal_is_rejected() {
        // Regression for M1-injection-reverify NEW-01: a non-existent first
        // component must not smuggle `..` past the check.
        let dir = tempdir().unwrap();
        let err = WriteFileTool
            .run(
                &json!({"path": "newghost/../../../../config.toml", "content": "pwned"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dangling_symlink_targets_are_rejected() {
        // Regression for M1-injection-reverify NEW-02 / M1-AP NF-01.
        let dir = tempdir().unwrap();
        let lure = dir.path().join("lure-target.txt");
        std::os::unix::fs::symlink(&lure, dir.path().join("ghost")).unwrap();

        let err = WriteFileTool
            .run(
                &json!({"path": "ghost", "content": "pwned"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::UnsafePath { .. }));
        assert!(!lure.exists(), "the dangling target must not be created");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_linked_targets_are_rejected() {
        // Regression for M1-AP NF-02: a hard link to the policy file must not
        // let an agent rewrite it through the workspace.
        let outside = tempdir().unwrap();
        let victim = outside.path().join("config.toml");
        std::fs::write(&victim, "sentinel = true\n").unwrap();

        let dir = tempdir().unwrap();
        std::fs::hard_link(&victim, dir.path().join("policy-link")).unwrap();

        let err = WriteFileTool
            .run(
                &json!({"path": "policy-link", "content": "pwned"}),
                &ctx(dir.path()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::UnsafePath { .. }));
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "sentinel = true\n"
        );
    }

    #[tokio::test]
    async fn cannot_rewrite_files_outside_the_workspace() {
        // The M1-AP-01 scenario: an agent must never rewrite the broker's own
        // config or the audit store, which live outside its workspace.
        let home = tempdir().unwrap();
        let workspace = home.path().join("agents/main/workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(home.path().join("config.toml"), "sentinel = true\n").unwrap();
        std::fs::write(home.path().join("store.db"), "sentinel").unwrap();

        for path in [
            home.path().join("config.toml"),
            home.path().join("store.db"),
        ] {
            let err = WriteFileTool
                .run(
                    &json!({"path": path.to_str().unwrap(), "content": "pwned"}),
                    &ctx(&workspace),
                )
                .await
                .unwrap_err();
            assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
        }

        assert_eq!(
            std::fs::read_to_string(home.path().join("config.toml")).unwrap(),
            "sentinel = true\n"
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join("store.db")).unwrap(),
            "sentinel"
        );
    }

    #[tokio::test]
    async fn a_tool_can_never_rewrite_an_agent_personality_file() {
        // The personality (`soul.md`) is the owner's trusted text: it sits
        // next to the workspace, never inside it, so no agent tool may write
        // it. Both the relative escape and the absolute path must be refused.
        let home = tempdir().unwrap();
        let workspace = home.path().join("agents/main/workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let soul = home.path().join("agents/main/soul.md");
        std::fs::write(&soul, "sentinel soul\n").unwrap();

        for path in ["../soul.md", soul.to_str().unwrap()] {
            let err = WriteFileTool
                .run(&json!({"path": path, "content": "pwned"}), &ctx(&workspace))
                .await
                .unwrap_err();
            assert!(matches!(err, ToolError::OutsideWorkspace { .. }), "{path}");
        }
        assert_eq!(std::fs::read_to_string(&soul).unwrap(), "sentinel soul\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_targets_are_rejected_without_hanging() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let err = WriteFileTool
            .run(&json!({"path": "pipe", "content": "x"}), &ctx(dir.path()))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::UnsafePath { .. }));
    }

    #[tokio::test]
    async fn missing_content_is_rejected() {
        let dir = tempdir().unwrap();
        let err = WriteFileTool
            .run(&json!({"path": "note.txt"}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::InvalidArgs { ref tool, .. } if tool == "write_file"));
    }

    #[tokio::test]
    async fn non_string_content_is_rejected() {
        let dir = tempdir().unwrap();
        let err = WriteFileTool
            .run(
                &json!({"path": "note.txt", "content": 12}),
                &ctx(dir.path()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::InvalidArgs { .. }));
    }

    #[test]
    fn metadata_is_medium_risk() {
        assert_eq!(WriteFileTool.name(), "write_file");
        assert_eq!(WriteFileTool.risk(), Risk::Medium);

        let schema = WriteFileTool.schema();
        assert_eq!(schema["properties"]["content"]["type"], "string");
        assert_eq!(schema["required"][0], "path");
        assert_eq!(schema["required"][1], "content");
        assert_eq!(schema["additionalProperties"], false);
    }
}
