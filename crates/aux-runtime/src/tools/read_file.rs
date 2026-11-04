//! `read_file` — read a text file inside the agent workspace. Low risk: it only
//! observes, and it never leaves the workspace.

use async_trait::async_trait;
use kernel_broker::ToolClass;
use kernel_broker::{NativeTool, Risk, Tool, ToolCtx, ToolError, ToolOutput, Trust};
use serde::Deserialize;
use std::io::ErrorKind;

/// Largest file `read_file` will hand to the model.
pub const MAX_READ_BYTES: u64 = 1024 * 1024;

/// Reads a UTF-8 text file into the tool result.
#[derive(Debug, Default)]
pub struct ReadFileTool;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadFileArgs {
    path: String,
}

impl NativeTool for ReadFileTool {
    fn native_name(&self) -> &'static str {
        "read_file"
    }

    fn native_description(&self) -> &'static str {
        "Read a UTF-8 text file inside the workspace."
    }

    fn native_schema(&self) -> &'static serde_json::Value {
        static SCHEMA: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File to read, inside the workspace. Relative paths resolve against the workspace."
                    }
                },
                "required": ["path"],
                "additionalProperties": false
            })
        });
        std::sync::LazyLock::force(&SCHEMA)
    }
}

#[async_trait]
impl Tool for ReadFileTool {
    fn path_id(&self) -> kernel_core::privacy::PathId {
        kernel_core::privacy::PathId::B3
    }
    fn name(&self) -> &str {
        self.native_name()
    }

    fn schema(&self) -> serde_json::Value {
        self.native_schema().clone()
    }

    async fn run(&self, args: &serde_json::Value, ctx: &ToolCtx) -> Result<ToolOutput, ToolError> {
        let args: ReadFileArgs = serde_json::from_value(args.clone())
            .map_err(|err| ToolError::invalid_args(self.name(), err))?;

        let path = ctx.resolve(&args.path)?;

        // Cheap pre-check so a FIFO/device can never block the open below.
        let pre = tokio::fs::metadata(&path).await?;
        if !pre.is_file() {
            return Err(ToolError::Io(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("not a regular file: {}", path.display()),
            )));
        }

        // Atomic open: O_NOFOLLOW refuses a final-component symlink even if
        // it appeared after the path checks; O_NONBLOCK makes a raced-in FIFO
        // fail instead of hanging; the fstat below validates the opened file
        // itself, not the path.
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)?
        };
        #[cfg(not(unix))]
        let file = std::fs::File::open(&path)?;

        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(ToolError::Io(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("not a regular file: {}", path.display()),
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() > 1 {
                return Err(ToolError::UnsafePath {
                    path: args.path.clone(),
                    reason: format!(
                        "hard-linked file (nlink={}): content may live outside the workspace",
                        meta.nlink()
                    ),
                });
            }
        }
        if meta.len() > MAX_READ_BYTES {
            return Err(ToolError::Io(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "file too large: {} bytes (max {MAX_READ_BYTES})",
                    meta.len()
                ),
            )));
        }

        use std::io::Read;
        let mut file = file;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(ToolOutput::ok(content))
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn ctx(dir: &std::path::Path) -> ToolCtx {
        ToolCtx::new("test", dir)
    }

    #[tokio::test]
    async fn reads_an_absolute_file_inside_the_workspace() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("note.txt");
        std::fs::write(&path, "hello auxesis").unwrap();

        let out = ReadFileTool
            .run(&json!({"path": path.to_str().unwrap()}), &ctx(dir.path()))
            .await
            .unwrap();

        assert!(!out.is_error);
        assert_eq!(out.content, "hello auxesis");
    }

    #[tokio::test]
    async fn resolves_relative_paths_against_the_workspace() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join("notes")).unwrap();
        std::fs::write(dir.path().join("notes/todo.md"), "- ship slice C").unwrap();

        let out = ReadFileTool
            .run(&json!({"path": "notes/todo.md"}), &ctx(dir.path()))
            .await
            .unwrap();

        assert_eq!(out.content, "- ship slice C");
    }

    #[tokio::test]
    async fn absolute_paths_outside_the_workspace_are_rejected() {
        let dir = tempdir().unwrap();
        let err = ReadFileTool
            .run(&json!({"path": "/etc/hosts"}), &ctx(dir.path()))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[tokio::test]
    async fn parent_traversal_is_rejected() {
        let dir = tempdir().unwrap();
        let err = ReadFileTool
            .run(&json!({"path": "../escape.txt"}), &ctx(dir.path()))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[tokio::test]
    async fn missing_file_is_an_io_error() {
        let dir = tempdir().unwrap();
        let err = ReadFileTool
            .run(&json!({"path": "nope.txt"}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::Io(ref e) if e.kind() == std::io::ErrorKind::NotFound));
    }

    #[tokio::test]
    async fn non_utf8_file_is_an_io_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bin.dat");
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();

        let err = ReadFileTool
            .run(&json!({"path": path.to_str().unwrap()}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidData));
    }

    #[tokio::test]
    async fn oversized_files_are_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("big.txt");
        std::fs::write(&path, vec![b'x'; (MAX_READ_BYTES + 1) as usize]).unwrap();

        let err = ReadFileTool
            .run(&json!({"path": "big.txt"}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(
            matches!(err, ToolError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput)
        );
        assert!(err.to_string().contains("too large"), "{err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifos_are_rejected_without_hanging() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo");
        assert!(status.success());

        let err = ReadFileTool
            .run(&json!({"path": "pipe"}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(
            matches!(err, ToolError::Io(ref e) if e.kind() == std::io::ErrorKind::InvalidInput)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escapes_are_rejected() {
        let dir = tempdir().unwrap();
        std::os::unix::fs::symlink("/etc", dir.path().join("link")).unwrap();

        let err = ReadFileTool
            .run(&json!({"path": "link/hosts"}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::OutsideWorkspace { .. }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_links_are_rejected() {
        let outside = tempdir().unwrap();
        let secret = outside.path().join("outside.txt");
        std::fs::write(&secret, "CANARY").unwrap();

        let dir = tempdir().unwrap();
        std::fs::hard_link(&secret, dir.path().join("inside.txt")).unwrap();

        let err = ReadFileTool
            .run(&json!({"path": "inside.txt"}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::UnsafePath { .. }));
    }

    #[tokio::test]
    async fn missing_path_is_rejected() {
        let dir = tempdir().unwrap();
        let err = ReadFileTool
            .run(&json!({}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::InvalidArgs { ref tool, .. } if tool == "read_file"));
    }

    #[tokio::test]
    async fn non_string_path_is_rejected() {
        let dir = tempdir().unwrap();
        let err = ReadFileTool
            .run(&json!({"path": ["a", "b"]}), &ctx(dir.path()))
            .await
            .unwrap_err();

        assert!(matches!(err, ToolError::InvalidArgs { .. }));
    }

    #[test]
    fn metadata_is_low_risk() {
        assert_eq!(ReadFileTool.name(), "read_file");
        assert_eq!(ReadFileTool.risk(), Risk::Low);

        let schema = ReadFileTool.schema();
        assert_eq!(schema["properties"]["path"]["type"], "string");
        assert_eq!(schema["required"][0], "path");
        assert_eq!(schema["additionalProperties"], false);
    }
}
