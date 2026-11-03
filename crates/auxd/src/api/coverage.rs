//! `GET /v1/privacy/coverage`: one row per
//! [`PathId::ALL`] entry, joined with the kernel registry (label, status,
//! private-mode behaviour) and the daemon's choke point for that path.
//!
//! Read only. A path with no registry row or no choke point is reported as
//! `missed`, so a gap shows in the app instead of disappearing.

use axum::response::{IntoResponse, Response};
use axum::Json;
use kernel_core::privacy::{Behaviour, PathId, Status, REGISTRY};
use serde::Serialize;

use crate::privacy_wiring::{Choke, CHOKE_POINTS};

/// One coverage row.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CoverageRow {
    /// Matrix row id, e.g. `"B5"`.
    pub id: &'static str,
    /// Short name of the path, from the kernel registry.
    pub label: &'static str,
    /// `covered`, `partial` or `missed`.
    pub state: &'static str,
    /// What private mode does with the path: `allow`, `ask` or `off`.
    pub private: &'static str,
    /// How the daemon holds it: `gate`, `mount`, `absent`, `mitigation`, or
    /// `none` when no choke point is listed.
    pub choke: &'static str,
}

/// The `/v1/privacy/coverage` payload.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CoverageResponse {
    /// Every path, in matrix order.
    pub paths: Vec<CoverageRow>,
    /// Rows whose state is `covered`.
    pub covered: usize,
    /// Rows whose state is `missed`.
    pub missed: usize,
}

/// Builds the payload from [`PathId::ALL`]; pure, so it is tested directly.
pub fn coverage() -> CoverageResponse {
    let paths: Vec<CoverageRow> = PathId::ALL.iter().map(|id| row(*id)).collect();
    let covered = paths.iter().filter(|row| row.state == "covered").count();
    let missed = paths.iter().filter(|row| row.state == "missed").count();
    CoverageResponse {
        paths,
        covered,
        missed,
    }
}

fn row(id: PathId) -> CoverageRow {
    let policy = REGISTRY.iter().find(|policy| policy.id == id);
    let choke = CHOKE_POINTS
        .iter()
        .find(|(path, _)| *path == id)
        .map(|(_, choke)| match choke {
            Choke::Gate(_) => "gate",
            Choke::Mount(_) => "mount",
            Choke::Absent(_) => "absent",
            Choke::Mitigation(_) => "mitigation",
        })
        .unwrap_or("none");
    let Some(policy) = policy else {
        return CoverageRow {
            id: id.as_str(),
            label: "",
            state: "missed",
            private: "off",
            choke,
        };
    };
    let state = match policy.status {
        _ if choke == "none" => "missed",
        Status::Covered => "covered",
        Status::Partial => "partial",
        Status::NotCovered => "missed",
    };
    let private = match policy.private {
        Behaviour::Allow => "allow",
        Behaviour::AskEachTime(_) => "ask",
        Behaviour::Disabled => "off",
    };
    CoverageRow {
        id: id.as_str(),
        label: policy.label,
        state,
        private,
        choke,
    }
}

/// `GET /v1/privacy/coverage`.
pub async fn show() -> Response {
    Json(coverage()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_row_per_path_in_matrix_order() {
        let response = coverage();
        let ids: Vec<&str> = response.paths.iter().map(|row| row.id).collect();
        let expected: Vec<&str> = PathId::ALL.iter().map(|id| id.as_str()).collect();
        assert_eq!(ids, expected);
        assert_eq!(
            response.covered
                + response.missed
                + response
                    .paths
                    .iter()
                    .filter(|row| row.state == "partial")
                    .count(),
            PathId::ALL.len()
        );
    }

    #[test]
    fn every_row_has_a_label_and_a_choke_point() {
        for row in coverage().paths {
            assert!(!row.label.is_empty(), "{} has no label", row.id);
            assert_ne!(row.choke, "none", "{} has no choke point", row.id);
        }
    }

    #[test]
    fn states_follow_the_registry() {
        let response = coverage();
        let a1 = response.paths.iter().find(|row| row.id == "A1").unwrap();
        assert_eq!((a1.state, a1.private), ("covered", "allow"));
        let b8 = response.paths.iter().find(|row| row.id == "B8").unwrap();
        assert_eq!((b8.state, b8.private), ("missed", "off"));
    }
}
