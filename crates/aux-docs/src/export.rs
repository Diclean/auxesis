//! The accountant export (M5-2): the receipts of a period, optionally of one
//! client, as `receipts.csv` plus a folder of the originals.
//!
//! Every write goes through the fd-verified [`kernel_core::SandboxHome`]
//! gateway rooted at the owner's chosen folder: no symlink is followed and
//! nothing that exists is overwritten. The CSV holds extracted fields and check
//! names only, never a body or OCR text; amounts come from integer minor units.
//! Nothing here calls a model or logs a file name or value.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use aux_store::{ExportDocument, Store, StoreError};

use crate::extract::{Check, CheckState};

/// The most rows one export writes; a longer period is refused.
pub const MAX_EXPORT_ROWS: usize = 5000;
const MAX_NAME_BYTES: usize = 120;

/// What the owner asked for: issue dates `YYYY-MM-DD` (inclusive), an optional
/// CRM party, and an existing absolute directory that is not a symlink.
#[derive(Debug, Clone, Copy)]
pub struct ExportRequest<'a> {
    pub from: &'a str,
    pub to: &'a str,
    pub client: Option<i64>,
    pub out: &'a Path,
}

/// `Empty` creates no folder; `Written` counts rows and missing originals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportOutcome {
    Empty {
        message: String,
    },
    Written {
        folder: PathBuf,
        rows: usize,
        missing: usize,
    },
}

/// Why an export did not run: a refused request, an existing folder, or a failure.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("{0}")]
    Refused(String),
    #[error("{} already exists and is not empty; choose a new --out folder; nothing was overwritten", .0.display())]
    Exists(PathBuf),
    #[error("the export failed: {0}")]
    Failed(String),
}

impl From<StoreError> for ExportError {
    fn from(err: StoreError) -> Self {
        Self::Failed(err.to_string())
    }
}

fn refused(message: impl Into<String>) -> ExportError {
    ExportError::Refused(message.into())
}

fn date(value: &str) -> Result<&str, ExportError> {
    let canonical = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map(|day| day.format("%Y-%m-%d").to_string());
    match canonical {
        Ok(canonical) if canonical == value => Ok(value),
        _ => Err(refused("dates must be YYYY-MM-DD")),
    }
}

/// Export the receipts `request` asks for, from `store` and the blobs in `home`.
pub fn export_receipts(
    store: &Store,
    home: &Path,
    request: &ExportRequest<'_>,
) -> Result<ExportOutcome, ExportError> {
    let (from, to) = (date(request.from)?, date(request.to)?);
    if from > to {
        return Err(refused("the start date is after the end date"));
    }
    if let Some(id) = request.client {
        store
            .party(id)?
            .ok_or_else(|| refused(format!("no client with id {id}")))?;
    }
    let out = checked_out(request.out, home)?;
    let documents = store.export_documents(from, to, request.client, MAX_EXPORT_ROWS + 1)?;
    if documents.len() > MAX_EXPORT_ROWS {
        return Err(refused(format!(
            "more than {MAX_EXPORT_ROWS} receipts in this period; export a shorter period"
        )));
    }
    if documents.is_empty() {
        let message = format!("No documents between {from} and {to}; nothing exported.");
        return Ok(ExportOutcome::Empty { message });
    }
    let name = PathBuf::from(format!("auxesis-receipts-{from}-{to}"));
    let failed = |err: std::io::Error| ExportError::Failed(err.to_string());
    let gateway = kernel_core::SandboxHome::open_existing(&out).map_err(failed)?;
    if !gateway.create_dir(&name).map_err(failed)? {
        check_reusable_folder(&out.join(&name))?;
    }
    if !gateway
        .create_dir(&name.join("originals"))
        .map_err(failed)?
    {
        return Err(ExportError::Exists(out.join(&name)));
    }

    let clients: HashMap<i64, String> = (store.parties()?.into_iter())
        .map(|party| (party.id, party.display_name))
        .collect();
    let (mut taken, mut missing) = (HashSet::new(), 0);
    let mut csv = String::from("date,number,issuer,client,currency,total,vat,checks,file\r\n");
    for doc in &documents {
        let client = doc.party_id.and_then(|id| clients.get(&id));
        let file = match crate::evidence::read_blob(home, &doc.content_hash) {
            Ok(bytes) => {
                let file = format!("originals/{}", unique_name(&mut taken, doc));
                if !gateway
                    .write_new(&name.join(&file), &bytes, 0o600)
                    .map_err(failed)?
                {
                    return Err(ExportError::Failed("an original already exists".into()));
                }
                file
            }
            Err(_) => {
                missing += 1;
                "(missing)".to_string()
            }
        };
        let text = |value: Option<&str>| text_cell(value.unwrap_or_default());
        let cells = [
            doc.issued_on.clone(),
            text(doc.number.as_deref()),
            text(doc.issuer.as_deref()),
            text(client.map(String::as_str)),
            text(doc.currency.as_deref()),
            doc.total_minor.map(amount).unwrap_or_default(),
            doc.vat_minor.map(amount).unwrap_or_default(),
            text_cell(&checks(&doc.checks_json)),
            text_cell(&file),
        ];
        csv.push_str(&(cells.join(",") + "\r\n"));
    }
    let csv_path = name.join("receipts.csv");
    gateway
        .write_new(&csv_path, csv.as_bytes(), 0o600)
        .map_err(failed)?;
    let (folder, rows) = (out.join(&name), documents.len());
    Ok(ExportOutcome::Written {
        folder,
        rows,
        missing,
    })
}

/// An export folder that already exists is reused only when it is a plain
/// (never a link) empty directory; anything inside it is the owner's and is
/// refused before the first write.
fn check_reusable_folder(folder: &Path) -> Result<(), ExportError> {
    let failed = |err: std::io::Error| ExportError::Failed(err.to_string());
    let meta = std::fs::symlink_metadata(folder).map_err(failed)?;
    if !meta.is_dir() {
        return Err(refused(format!(
            "{} exists and is not a plain folder; choose a new --out folder; nothing was overwritten",
            folder.display()
        )));
    }
    if std::fs::read_dir(folder).map_err(failed)?.next().is_some() {
        return Err(ExportError::Exists(folder.to_path_buf()));
    }
    Ok(())
}

/// `out` must be absolute, an existing directory, not a symlink, and outside
/// the Auxesis home.
fn checked_out(out: &Path, home: &Path) -> Result<PathBuf, ExportError> {
    let meta = std::fs::symlink_metadata(out).ok();
    if !out.is_absolute() || !meta.is_some_and(|meta| meta.is_dir()) {
        return Err(refused(
            "the output folder must be an existing absolute directory, not a link",
        ));
    }
    let real = out.canonicalize().map_err(|err| refused(err.to_string()))?;
    if home.canonicalize().is_ok_and(|home| real.starts_with(home)) {
        return Err(refused(
            "the output folder must be outside the Auxesis home",
        ));
    }
    Ok(real)
}

/// Integer minor units as an exact `.`-decimal string.
fn amount(minor: i64) -> String {
    let (sign, abs) = (if minor < 0 { "-" } else { "" }, minor.unsigned_abs());
    format!("{sign}{}.{:02}", abs / 100, abs % 100)
}

/// The check names grouped by state: `passed: totals, vat; failed: duplicate`.
fn checks(json: &str) -> String {
    let checks: Vec<Check> = serde_json::from_str(json).unwrap_or_default();
    let names = |state| {
        let named = checks.iter().filter(|check| check.state == state);
        named
            .map(|check| check.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let groups = [
        (CheckState::Pass, "passed"),
        (CheckState::Fail, "failed"),
        (CheckState::Unknown, "unknown"),
    ];
    let groups = groups.map(|(state, label)| (label, names(state)));
    let lines = groups.iter().filter(|(_, names)| !names.is_empty());
    lines
        .map(|(label, names)| format!("{label}: {names}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// One text cell: a leading apostrophe defuses a spreadsheet formula, then
/// RFC 4180 quoting. Dates and amounts are built here and need neither.
fn text_cell(value: &str) -> String {
    let mut cell = value.to_string();
    if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        cell.insert(0, '\'');
    }
    if cell.contains([',', '"', '\r', '\n']) {
        cell = format!("\"{}\"", cell.replace('"', "\"\""));
    }
    cell
}

/// `<date>_<number-or-shorthash>.<ext>`: ASCII letters, digits, `-` and `_`
/// only, at most 120 bytes, `-2`, `-3` on a case-insensitive collision.
fn unique_name(taken: &mut HashSet<String>, doc: &ExportDocument) -> String {
    let safe = |value: &str| -> String {
        let keep = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        value
            .chars()
            .map(|c| if keep(c) { c } else { '-' })
            .collect()
    };
    let id = (doc.number.as_deref().map(safe))
        .filter(|number| number.chars().any(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| doc.content_hash.chars().take(12).collect());
    let from_name = (doc
        .original_name
        .as_deref()
        .and_then(|name| name.rsplit_once('.')))
    .map(|(_, ext)| ext.to_ascii_lowercase())
    .filter(|ext| (1..=5).contains(&ext.len()) && ext.chars().all(|c| c.is_ascii_alphanumeric()));
    let ext = from_name.unwrap_or_else(|| {
        let ext = match doc.mime_type.as_str() {
            "application/pdf" => "pdf",
            "application/xml" | "text/xml" => "xml",
            "image/jpeg" => "jpg",
            "image/png" => "png",
            _ => "bin",
        };
        ext.to_string()
    });
    let stem: String = format!("{}_{id}", safe(&doc.issued_on))
        .chars()
        .take(MAX_NAME_BYTES - ext.len() - 7)
        .collect();
    let mut name = format!("{stem}.{ext}");
    for n in 2.. {
        if taken.insert(name.to_ascii_lowercase()) {
            break;
        }
        name = format!("{stem}-{n}.{ext}");
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_exact_and_names_bounded_and_unique() {
        assert_eq!([amount(5), amount(-1250)], ["0.05", "-12.50"]);
        assert_eq!(amount(i64::MIN), "-92233720368547758.08");
        assert_eq!(text_cell("\rx"), "\"'\rx\"");
        let number = Some("x".repeat(500));
        let doc = ExportDocument {
            mime_type: "application/pdf".into(),
            number,
            ..Default::default()
        };
        let mut taken = HashSet::new();
        let (first, second) = (unique_name(&mut taken, &doc), unique_name(&mut taken, &doc));
        assert!(
            first.len() <= MAX_NAME_BYTES && first.ends_with("x.pdf"),
            "{first}"
        );
        assert!(
            second.len() <= MAX_NAME_BYTES && second.ends_with("x-2.pdf"),
            "{second}"
        );
    }
}
