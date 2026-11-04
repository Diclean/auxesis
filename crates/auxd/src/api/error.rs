//! Uniform JSON error bodies for the local API.
//!
//! Every failure — auth, limits, unknown routes, internal errors — answers
//! with `{"error":{"code":…,"message":…}}` so the app can switch on `code`
//! instead of parsing prose. Messages are short, single-line and sanitized;
//! `detail` is only attached for actionable upstream failures and is scrubbed
//! of the Auxesis home path and key-shaped strings before it leaves the
//! process.

use std::path::Path;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// Hard cap on an error `detail` (bytes, after sanitizing).
const DETAIL_MAX_BYTES: usize = 512;

/// Word budget for the one-line message.
#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// Build a JSON error response.
pub fn error_response(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    hint: Option<&'static str>,
) -> Response {
    json_error(status, code, message.into(), hint, None)
}

/// Build a JSON error response with a sanitized upstream detail.
pub fn error_response_with_detail(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    detail: String,
) -> Response {
    json_error(status, code, message.into(), None, Some(detail))
}

fn json_error(
    status: StatusCode,
    code: &'static str,
    message: String,
    hint: Option<&'static str>,
    detail: Option<String>,
) -> Response {
    let body = ErrorEnvelope {
        error: ErrorDetail {
            code,
            message,
            hint,
            detail,
        },
    };
    (status, Json(body)).into_response()
}

/// `501` for features that this API version does not ship yet.
pub fn not_implemented(feature: &'static str) -> Response {
    error_response(
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
        format!("{feature} is not available in this version"),
        Some("planned for a later milestone (auxd local API v1)"),
    )
}

/// `404` for an unknown route.
pub async fn not_found() -> Response {
    error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "no such API route",
        None,
    )
}

/// `405` for a known route with an unsupported method.
pub async fn method_not_allowed() -> Response {
    error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "this method is not supported on this route",
        None,
    )
}

/// Scrub an upstream error string before it is echoed to a client.
///
/// Shared with the CLI and the app: [`kernel_broker::sanitize_error_detail`]
/// strips control/invisible characters, replaces the Auxesis home path with
/// `<home>`, redacts every documented **plain-text** secret shape, collapses
/// to one line and caps the result. Encoded (base64/hex/line-split) values
/// are outside a pattern redactor's reach and must never be claimed.
pub fn sanitize_detail(home: &Path, text: &str) -> String {
    kernel_broker::sanitize_error_detail(home, text, DETAIL_MAX_BYTES)
}

/// Scrub one tool-visible preview string (arguments, result).
///
/// Same transformations as [`sanitize_detail`] minus the one-line collapse:
/// a preview may legitimately span lines (a command, a diff).
pub fn scrub_preview(home: &Path, text: &str, max_bytes: usize) -> String {
    kernel_broker::scrub_external_preview(home, text, max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod redaction_canaries {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/redaction_canaries.rs"
        ));
    }

    #[test]
    fn shared_secret_redaction_canaries_are_scrubbed_in_previews() {
        redaction_canaries::assert_no_canaries(|text| {
            scrub_preview(Path::new("/tmp/auxesis-canary-home"), text, usize::MAX)
        });
    }
    use axum::body::to_bytes;

    async fn body_of(response: Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn error_bodies_have_a_stable_shape() {
        let response = error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid bearer token",
            None,
        );
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let value = body_of(response).await;
        assert_eq!(value["error"]["code"], "unauthorized");
        assert_eq!(value["error"]["message"], "missing or invalid bearer token");
        assert!(value["error"].get("hint").is_none());
        assert!(value["error"].get("detail").is_none());
    }

    #[tokio::test]
    async fn not_implemented_carries_a_hint() {
        let value = body_of(not_implemented("approvals")).await;
        assert_eq!(value["error"]["code"], "not_implemented");
        assert!(value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("approvals"));
        assert!(value["error"]["hint"].is_string());
    }

    #[test]
    fn a_registered_known_secret_is_scrubbed_without_a_name_on_the_error_surface() {
        // The daemon registers the secrets it resolves; an API
        // error body quoting one of them must redact it even when no
        // credential name or vendor prefix sits next to it.
        let secret = format!("CANARY_KNOWN_{}", "7f3a9c2e1b5d");
        assert!(kernel_broker::scrub::register_known_secret(&secret));
        let raw = format!("provider said: the value {secret} is invalid");
        let home = Path::new("/Users/secret/.auxesis");
        let detail = sanitize_detail(home, &raw);
        assert!(!detail.contains(&secret), "{detail}");
        let preview = scrub_preview(home, &raw, 4096);
        assert!(!preview.contains(&secret), "{preview}");
    }

    #[test]
    fn every_canary_is_scrubbed_from_error_details_and_previews() {
        // Error bodies and previews are the shared entry points every other
        // surface funnels through; the whole canary corpus must die here.
        let home = Path::new("/Users/secret/.auxesis");
        for (raw, secret) in crate::api::canary::all_canaries() {
            let detail = sanitize_detail(home, &raw);
            assert!(
                !detail.contains(&secret),
                "detail leaked {secret:?}: {detail:?}"
            );
            let preview = scrub_preview(home, &raw, 64 * 1024);
            assert!(
                !preview.contains(&secret),
                "preview leaked {secret:?}: {preview:?}"
            );
        }
    }

    #[test]
    fn detail_sanitizing_scrubs_paths_controls_and_key_shapes() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = "boom at /Users/secret/.auxesis/store.db\u{1b}[31m \
                   AUX_KEY_DEEPSEEK=sk-live-abcdef12345 and sk-ant-9xyz\nsecond line"; // gitleaks:allow
        let clean = sanitize_detail(home, raw);
        assert!(!clean.contains("/Users/secret/.auxesis"), "{clean}");
        assert!(clean.contains("<home>/store.db"), "{clean}");
        assert!(!clean.contains("sk-live-abcdef12345"), "{clean}");
        assert!(!clean.contains("sk-ant-9xyz"), "{clean}");
        assert!(clean.contains("sk-<redacted>"), "{clean}");
        assert!(clean.contains("AUX_KEY_DEEPSEEK=<redacted>"), "{clean}");
        assert!(!clean.contains('\u{1b}'), "control characters must be gone");
        assert!(!clean.contains('\n'), "details are single-line");
    }

    #[test]
    fn detail_is_capped_by_characters() {
        let dir = tempfile::tempdir().unwrap();
        let clean = sanitize_detail(dir.path(), &"x".repeat(10_000));
        assert!(clean.chars().count() <= DETAIL_MAX_BYTES);
    }

    #[test]
    fn scrub_preview_keeps_lines_but_hides_paths_and_keys() {
        let home = Path::new("/Users/secret/.auxesis");
        let raw = format!(
            "line one\ncd {}/agents/main\nline two\nAUX_KEY_FAKE=sk-live-abcdef12345 and tail\nline four",  // gitleaks:allow
            home.display()
        );
        let clean = scrub_preview(home, &raw, 4096);
        assert!(clean.contains("line one\n"), "lines are preserved");
        assert!(!clean.contains("/Users/secret/.auxesis"), "{clean}");
        assert!(clean.contains("<home>/agents/main"), "{clean}");
        assert!(!clean.contains("sk-live-abcdef12345"), "{clean}");
        assert!(clean.contains("AUX_KEY_FAKE=<redacted>"), "{clean}");

        let capped = scrub_preview(Path::new("/nope"), &"x".repeat(10_000), 128);
        assert!(capped.len() <= 128 + 64, "capped: {}", capped.len());
    }
}
