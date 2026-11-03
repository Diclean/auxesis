//! One-time move of the pre-WO-07 `dots/` folder to `agents/`.
//!
//! Runs at daemon and CLI startup, before anything creates `agents/`. The move
//! is one same-filesystem `rename`, so it is atomic. When both folders exist,
//! nothing is merged or moved: the caller refuses to start and names both.

use std::path::{Path, PathBuf};

/// Result of [`migrate_legacy_agents_dir`] when a move happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentsDirMoved {
    /// The old `dots/` folder that was renamed.
    pub from: PathBuf,
    /// The new `agents/` folder it became.
    pub to: PathBuf,
}

/// Rename `<home>/dots` to `<home>/agents` when only the old folder exists.
///
/// `Ok(None)` when there is nothing to do (neither folder, or `agents/` already
/// present with no `dots/`). `Err` with a bilingual message when both exist.
pub fn migrate_legacy_agents_dir(home: &Path) -> Result<Option<AgentsDirMoved>, String> {
    let legacy = home.join("dots");
    let current = home.join("agents");
    if !legacy.is_dir() {
        return Ok(None);
    }
    if current.exists() {
        return Err(format!(
            "two agent folders exist, so nothing was moved: {} and {}. \
             Move the old one aside by hand, then start again. / \
             deux dossiers d'agents existent, rien n'a été déplacé : {} et {}. \
             Mettez l'ancien de côté à la main, puis relancez.",
            legacy.display(),
            current.display(),
            legacy.display(),
            current.display()
        ));
    }
    match std::fs::rename(&legacy, &current) {
        Ok(()) => Ok(Some(AgentsDirMoved {
            from: legacy,
            to: current,
        })),
        // Another process (daemon and CLI starting together) may have moved it
        // between our check and the rename: that is the same good outcome.
        Err(_) if !legacy.exists() && current.is_dir() => Ok(None),
        Err(err) => Err(format!(
            "could not rename {} to {}: {err} / impossible de renommer {} en {} : {err}",
            legacy.display(),
            current.display(),
            legacy.display(),
            current.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neither_folder_is_a_no_op() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(migrate_legacy_agents_dir(home.path()), Ok(None));
        assert!(!home.path().join("agents").exists());
        assert!(!home.path().join("dots").exists());
    }

    #[test]
    fn only_dots_is_renamed_atomically_and_keeps_its_contents() {
        let home = tempfile::tempdir().unwrap();
        let legacy = home.path().join("dots/main");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("soul.md"), "kept").unwrap();

        let moved = migrate_legacy_agents_dir(home.path()).unwrap().unwrap();
        assert_eq!(moved.from, home.path().join("dots"));
        assert_eq!(moved.to, home.path().join("agents"));
        assert!(!home.path().join("dots").exists());
        assert_eq!(
            std::fs::read_to_string(home.path().join("agents/main/soul.md")).unwrap(),
            "kept"
        );
    }

    #[test]
    fn both_folders_are_refused_without_merging_and_name_both_paths() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("dots/old")).unwrap();
        std::fs::create_dir_all(home.path().join("agents/new")).unwrap();

        let err = migrate_legacy_agents_dir(home.path()).unwrap_err();
        assert!(
            err.contains(&home.path().join("dots").display().to_string()),
            "{err}"
        );
        assert!(
            err.contains(&home.path().join("agents").display().to_string()),
            "{err}"
        );
        assert!(err.contains("nothing was moved"), "{err}");
        assert!(err.contains("rien n'a été déplacé"), "{err}");
        // Nothing merged: both trees are untouched.
        assert!(home.path().join("dots/old").is_dir());
        assert!(home.path().join("agents/new").is_dir());
        assert!(!home.path().join("agents/old").exists());
    }

    #[test]
    fn agents_alone_is_a_no_op() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("agents/main")).unwrap();
        assert_eq!(migrate_legacy_agents_dir(home.path()), Ok(None));
    }
}
