//! Owner-authored, instruction-only skills stored below the Auxesis home.
//!
//! A skill is exactly one bounded `SKILL.md` file. Other entries are ignored
//! and reported; they are never opened or executed.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Maximum bytes in one `SKILL.md`.
pub const MAX_SKILL_BYTES: u64 = 64 * 1024;
/// Maximum combined bytes injected into one agent.
pub const MAX_ACTIVE_SKILLS_BYTES: usize = 256 * 1024;
/// Maximum accepted skill-name length.
pub const MAX_SKILL_NAME_LEN: usize = 48;

/// A discovered skill and its validation status.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SkillInfo {
    pub name: String,
    pub description: Option<String>,
    pub size: u64,
    pub status: SkillStatus,
}

/// Why a discovered skill is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SkillStatus {
    Valid { warning: Option<String> },
    Ignored { reason: String },
}

/// Content eligible for prompt injection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSkill {
    pub name: String,
    pub content: String,
}

/// Validate a single path-segment skill name.
pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_SKILL_NAME_LEN {
        return Err(format!(
            "name must contain 1 to {MAX_SKILL_NAME_LEN} characters"
        ));
    }
    if !name.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
    }) {
        return Err("name may contain only lowercase letters, digits, - and _".into());
    }
    Ok(())
}

fn skills_dir(home: &Path) -> PathBuf {
    home.join("skills")
}

/// List skills within `home/skills`. No files except each direct
/// `SKILL.md` are read.
pub fn list(home: &Path) -> Vec<SkillInfo> {
    let Ok(gateway) = kernel_core::verified_home_or_verify(home) else {
        return Vec::new();
    };
    let Ok(root) = gateway.real_path().map(|home| skills_dir(&home)) else {
        return Vec::new();
    };
    let Ok(root_meta) = fs::symlink_metadata(&root) else {
        return Vec::new();
    };
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut skills = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if validate_name(&name).is_err() {
            continue;
        }
        let path = entry.path();
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                skills.push(ignored(name, 0, "skill directory is a symbolic link"));
                continue;
            }
            Ok(meta) if meta.is_dir() => {}
            _ => continue,
        }
        let mut extras = false;
        let Ok(children) = fs::read_dir(&path) else {
            continue;
        };
        for child in children.flatten() {
            if child.file_name() != "SKILL.md" {
                extras = true;
            }
        }
        let skill_path = path.join("SKILL.md");
        match fs::symlink_metadata(&skill_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                skills.push(ignored(name, 0, "SKILL.md is a symbolic link"));
                continue;
            }
            Ok(meta) if meta.is_file() => {}
            _ => {
                skills.push(ignored(
                    name,
                    0,
                    "SKILL.md is missing or is not a regular file",
                ));
                continue;
            }
        };
        let rel = Path::new("skills").join(&name).join("SKILL.md");
        let bytes = match read_bounded(&gateway, &rel) {
            Ok(bytes) => bytes,
            Err(ReadSkillError::TooLarge) => {
                skills.push(ignored(
                    name,
                    MAX_SKILL_BYTES + 1,
                    "SKILL.md exceeds 64 KiB",
                ));
                continue;
            }
            Err(ReadSkillError::Read) => {
                skills.push(ignored(name, 0, "SKILL.md could not be read"));
                continue;
            }
        };
        let size = bytes.len() as u64;
        let Ok(content) = String::from_utf8(bytes) else {
            skills.push(ignored(name, size, "SKILL.md is not UTF-8"));
            continue;
        };
        let description = description(&content);
        skills.push(SkillInfo {
            name,
            description,
            size,
            status: SkillStatus::Valid {
                warning: extras.then(|| "other files are present and ignored".into()),
            },
        });
    }
    skills.sort_by(|a, b| a.name.cmp(&b.name));
    skills
}

fn ignored(name: String, size: u64, reason: &str) -> SkillInfo {
    SkillInfo {
        name,
        description: None,
        size,
        status: SkillStatus::Ignored {
            reason: reason.into(),
        },
    }
}

fn description(content: &str) -> Option<String> {
    let mut lines = content.lines();
    if lines.next()?.trim() != "---" {
        return None;
    }
    for line in lines {
        if line.trim() == "---" {
            break;
        }
        if let Some(value) = line.strip_prefix("description:") {
            let value = value.trim().trim_matches(['"', '\'']);
            return (!value.is_empty()).then(|| value.to_string());
        }
    }
    None
}

/// Load selected skills, refusing unknown/ignored names and enforcing the
/// aggregate injection bound.
pub fn load_active(home: &Path, names: &[String]) -> Result<Vec<ActiveSkill>, String> {
    load_active_after_discovery(home, names, || {})
}

fn load_active_after_discovery(
    home: &Path,
    names: &[String],
    after_discovery: impl FnOnce(),
) -> Result<Vec<ActiveSkill>, String> {
    let discovered = list(home);
    after_discovery();
    let gateway = kernel_core::verified_home_or_verify(home)
        .map_err(|_| "skills could not be read".to_string())?;
    let mut total = 0usize;
    let mut active = Vec::new();
    for name in names {
        validate_name(name)?;
        let info = discovered
            .iter()
            .find(|skill| skill.name == *name)
            .ok_or_else(|| format!("unknown skill `{name}`"))?;
        if let SkillStatus::Ignored { reason } = &info.status {
            return Err(format!("skill `{name}` is unavailable: {reason}"));
        }
        let path = Path::new("skills").join(name).join("SKILL.md");
        let bytes = read_bounded(&gateway, &path).map_err(|err| match err {
            ReadSkillError::TooLarge => format!("skill `{name}` exceeds 64 KiB"),
            ReadSkillError::Read => format!("skill `{name}` could not be read"),
        })?;
        total = total.saturating_add(bytes.len());
        if total > MAX_ACTIVE_SKILLS_BYTES {
            return Err("active skills exceed 256 KiB".into());
        }
        let content =
            String::from_utf8(bytes).map_err(|_| format!("skill `{name}` is not UTF-8"))?;
        active.push(ActiveSkill {
            name: name.clone(),
            content,
        });
    }
    Ok(active)
}

enum ReadSkillError {
    TooLarge,
    Read,
}

/// Open without following a final symlink and read at most the configured
/// maximum plus one byte, so metadata races cannot cause an unbounded read.
fn read_bounded(gateway: &kernel_core::SandboxHome, rel: &Path) -> Result<Vec<u8>, ReadSkillError> {
    let file = gateway.open_read(rel, MAX_SKILL_BYTES).map_err(|err| {
        if err.kind() == std::io::ErrorKind::InvalidData {
            ReadSkillError::TooLarge
        } else {
            ReadSkillError::Read
        }
    })?;
    let mut bytes = Vec::with_capacity(MAX_SKILL_BYTES as usize);
    file.take(MAX_SKILL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReadSkillError::Read)?;
    if bytes.len() as u64 > MAX_SKILL_BYTES {
        return Err(ReadSkillError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn names_and_active_size_are_bounded() {
        assert!(validate_name("../x").is_err());
        assert!(validate_name("Good").is_err());
        assert!(validate_name(&"a".repeat(MAX_SKILL_NAME_LEN + 1)).is_err());
        let home = tempdir().unwrap();
        let skill = home.path().join("skills/big");
        fs::create_dir_all(&skill).unwrap();
        fs::write(
            skill.join("SKILL.md"),
            vec![b'x'; MAX_SKILL_BYTES as usize + 1],
        )
        .unwrap();
        assert!(matches!(
            list(home.path())[0].status,
            SkillStatus::Ignored { .. }
        ));
        assert!(load_active(home.path(), &["big".into()]).is_err());
    }

    #[test]
    fn combined_active_size_is_bounded_and_only_selected_content_is_loaded() {
        let home = tempdir().unwrap();
        let root = home.path().join("skills");
        let names: Vec<String> = (0..5).map(|n| format!("skill{n}")).collect();
        for name in &names {
            let dir = root.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("SKILL.md"), vec![b'x'; 60 * 1024]).unwrap();
        }
        assert!(load_active(home.path(), &names).is_err());
        let active = load_active(home.path(), &names[..1]).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, "skill0");
    }

    #[test]
    fn combined_active_size_uses_bytes_read_after_discovery() {
        let home = tempdir().unwrap();
        let root = home.path().join("skills");
        let names: Vec<String> = (0..5).map(|n| format!("skill{n}")).collect();
        for name in &names {
            let dir = root.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("SKILL.md"), vec![b'x'; 50 * 1024]).unwrap();
        }

        let result = load_active_after_discovery(home.path(), &names, || {
            for name in &names {
                fs::write(root.join(name).join("SKILL.md"), vec![b'x'; 60 * 1024]).unwrap();
            }
        });
        assert_eq!(result.unwrap_err(), "active skills exceed 256 KiB");
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused_and_extra_files_reported_without_reading() {
        use std::os::unix::fs::symlink;
        let home = tempdir().unwrap();
        // The application verifies its home at startup, before the owner can
        // add skills; reuse that held handle so individual skill links can be
        // reported as ignored without weakening the startup symlink scan.
        kernel_core::ensure_home(home.path()).unwrap();
        let root = home.path().join("skills");
        fs::create_dir_all(root.join("linked")).unwrap();
        fs::write(root.join("linked/SKILL.md"), "ok").unwrap();
        symlink(root.join("linked"), root.join("alias")).unwrap();
        fs::create_dir(root.join("file-link")).unwrap();
        symlink(
            root.join("linked/SKILL.md"),
            root.join("file-link/SKILL.md"),
        )
        .unwrap();
        fs::create_dir(root.join("with-extra")).unwrap();
        fs::write(root.join("with-extra/SKILL.md"), "safe").unwrap();
        fs::write(root.join("with-extra/run.sh"), "not read").unwrap();
        let skills = list(home.path());
        assert!(matches!(
            skills.iter().find(|s| s.name == "alias").unwrap().status,
            SkillStatus::Ignored { .. }
        ));
        assert!(matches!(
            skills
                .iter()
                .find(|s| s.name == "file-link")
                .unwrap()
                .status,
            SkillStatus::Ignored { .. }
        ));
        let with_extra = skills.iter().find(|s| s.name == "with-extra").unwrap();
        assert!(matches!(
            with_extra.status,
            SkillStatus::Valid { warning: Some(_) }
        ));
        assert!(load_active(home.path(), &["with-extra".into()]).is_ok());
    }
}
