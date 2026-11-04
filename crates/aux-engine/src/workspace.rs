//! Workspace-level taint.
//!
//! Dispatching an untrusted-class tool in a workspace marks the whole
//! workspace `untrusted-touched` *before* the call runs, so no write can land
//! outside an observation window. The mark is sticky and workspace-level:
//! every conversation there — new, resumed or job-triggered — starts
//! tainted, whether or not it reads a file the call wrote. Only the owner
//! clears it, and since fix round 4 that clear needs an **owner-presence
//! proof**: `aux workspace trust` first sends a one-time code through the
//! owner's local notification channel, and only the owner typing it at a
//! hidden prompt (`--code -` reads stdin; `--code <code>` is a warned legacy
//! form) or the API's `code` field consumes the
//! request and clears the mark (see [`crate::trust`]). A tool that can run
//! the CLI or reach the API with the owner token cannot read the
//! notification, cannot find the code in any store/audit/log output, and
//! cannot guess it past the rate limit, 120 s expiry, 3-attempt cap and
//! single-use consumption.
//!
//! This replaces the round-1 per-file snapshot ledger: coarse on purpose, it
//! cannot be raced by a background process writing after a snapshot, by a
//! same-size rewrite with a restored mtime, or by a turn that is cancelled
//! before the snapshot is diffed.
//!
//! # Scope
//!
//! The mark is keyed to *this* workspace. An unsandboxed `shell` can write
//! into a sibling agent's workspace (or anywhere else on the machine) without
//! marking it, so the guarantee is "untrusted content cannot reach an
//! unapproved write *through this workspace*", not "through any agent". WS-D's
//! sandbox is what bounds an untrusted shell's blast radius; the same limit
//! covers `sqlite3 store.db 'DELETE FROM workspace_taint'` and reading the
//! macOS notification store directly. WS-C is only complete together with
//! WS-D — this module deliberately does not guess at per-tool filesystem
//! capabilities.

use std::path::{Path, PathBuf};

/// Canonical store key of `workspace`.
///
/// Taint marks are keyed by the canonical real path so one workspace maps to
/// one mark through symlinks. A path that cannot be canonicalized (usually
/// because it does not exist yet) falls back to its literal form.
pub fn workspace_key(workspace: &Path) -> String {
    std::fs::canonicalize(workspace)
        .unwrap_or_else(|_| workspace.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

/// Resolve an owner-supplied workspace path to its canonical store key.
///
/// Only an existing directory under `<home>/agents` qualifies: taint marks are
/// keyed by the agent workspace layout, and an owner action that does not name
/// one is refused rather than guessed at.
pub fn resolve_agent_workspace(home: &Path, raw: &str) -> Result<String, WorkspacePathError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(WorkspacePathError::Empty);
    }
    let canonical =
        PathBuf::from(raw)
            .canonicalize()
            .map_err(|_| WorkspacePathError::Unresolvable {
                path: raw.to_string(),
            })?;
    if !canonical.is_dir() {
        return Err(WorkspacePathError::NotADirectory {
            path: raw.to_string(),
        });
    }
    let agents = home
        .canonicalize()
        .map_err(|_| WorkspacePathError::Unresolvable {
            path: home.display().to_string(),
        })?
        .join("agents");
    if !canonical.starts_with(&agents) {
        return Err(WorkspacePathError::OutsideAgents {
            path: raw.to_string(),
        });
    }
    Ok(canonical.to_string_lossy().into_owned())
}

/// Why an owner-supplied path is not an agent workspace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkspacePathError {
    /// The path was empty.
    #[error("workspace path is empty")]
    Empty,
    /// The path does not exist or cannot be resolved.
    #[error("workspace path `{path}` does not exist")]
    Unresolvable {
        /// The offending path, as supplied.
        path: String,
    },
    /// The path exists but is not a directory.
    #[error("workspace path `{path}` is not a directory")]
    NotADirectory {
        /// The offending path, as supplied.
        path: String,
    },
    /// The path is not an agent workspace under this Auxesis home.
    #[error("`{path}` is not an agent workspace under this Auxesis home")]
    OutsideAgents {
        /// The offending path, as supplied.
        path: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn the_key_follows_symlinks_to_the_real_workspace() {
        let dir = tempdir().unwrap();
        let workspace = dir.path().join("agents/main/workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let alias = dir.path().join("alias");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&workspace, &alias).unwrap();
        #[cfg(not(unix))]
        std::fs::create_dir_all(&alias).unwrap();

        let real = workspace.canonicalize().unwrap();
        assert_eq!(workspace_key(&alias), real.to_string_lossy());
        assert_eq!(workspace_key(&workspace), real.to_string_lossy());
    }

    #[test]
    fn resolve_accepts_only_existing_directories_under_agents() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let workspace = home.join("agents/main/workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let key = workspace
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();

        assert_eq!(
            resolve_agent_workspace(&home, workspace.to_str().unwrap()).unwrap(),
            key
        );
        // Trailing whitespace is trimmed.
        assert_eq!(
            resolve_agent_workspace(&home, &format!("  {}  ", workspace.display())).unwrap(),
            key
        );

        assert_eq!(
            resolve_agent_workspace(&home, "   ").unwrap_err(),
            WorkspacePathError::Empty
        );
        assert!(matches!(
            resolve_agent_workspace(&home, home.join("agents/missing").to_str().unwrap()),
            Err(WorkspacePathError::Unresolvable { .. })
        ));
        let file = home.join("agents/main/soul.md");
        std::fs::write(&file, "soul").unwrap();
        assert!(matches!(
            resolve_agent_workspace(&home, file.to_str().unwrap()),
            Err(WorkspacePathError::NotADirectory { .. })
        ));
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        assert!(matches!(
            resolve_agent_workspace(&home, elsewhere.to_str().unwrap()),
            Err(WorkspacePathError::OutsideAgents { .. })
        ));
    }
}
