//! Graceful-degrade parser for the server-side analysis response.
//!
//! The server envelope is versioned but the CLI does NOT pin to a
//! schema version — it deserializes known fields and ignores
//! unknown ones. This mirrors Stripe's client discipline (design
//! doc §14 Q7): new server-side fields never crash an older CLI.
//!
//! What the server returns today (see api/services/analysis_visibility.py
//! `shape_analysis_result` + api/routers/analysis.py `_analysis_response`):
//!
//! ```jsonc
//! {
//!   "scan_id": "uuid",
//!   "device_name": "TP-Link Archer C7",
//!   "analyzed_at": "2026-08-21T18:03:41Z",
//!   "preview": true,
//!   "findings": [
//!     { "label": "…", "value": "…", "detail": "…", "source": "…",
//!       "severity": "…", "cve_id": "CVE-…", "cvss_score": 7.5, ... }
//!   ],
//!   "findings_total": 12,
//!   "findings_visible": 8,
//!   "findings_hidden": 4,
//!   "findings_hidden_by_severity": { "high": 2, "medium": 2 },
//!   "findings_cve_revealed": true,
//!   "cve_details_locked": false,
//!   "attack_recommendations": [...],
//!   "upgrade_reasons": ["save_report", "reveal_all_findings", ...],
//!   "ai_report": "..."   // present on paid tiers only
//! }
//! ```

use serde::Deserialize;

/// Full server response. `#[serde(default)]` on the container +
/// `Option<T>`-fields for anything optional keeps unknown/new
/// fields from breaking parsing. Any field the server drops or
/// renames stays `None` and the CLI degrades gracefully.
#[derive(Deserialize, Debug, Default)]
#[serde(default)]
pub struct ApiScanResponse {
    pub scan_id: Option<String>,
    pub device_name: Option<String>,
    pub analyzed_at: Option<String>,
    pub preview: Option<bool>,
    pub findings: Vec<ApiFinding>,
    pub findings_total: Option<u32>,
    pub findings_visible: Option<u32>,
    pub findings_hidden: Option<u32>,
    pub findings_cve_revealed: Option<bool>,
    pub cve_details_locked: Option<bool>,
    pub attack_recommendations: Vec<serde_json::Value>,
    pub upgrade_reasons: Vec<String>,
    pub ai_report: Option<String>,
    /// Anything we didn't model. Kept so JSON output can passthrough
    /// the whole server body without lossy re-serialization.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Server-side finding shape.
///
/// **Canonical field names match the FastAPI response body** (see
/// `api/services/analysis_visibility.py::finding_model_to_dict`):
/// `title`, `description`, `severity`, `cve_id`, `cvss_score`,
/// `is_exploitable`, `line_index`, `evidence`, `remediation`.
///
/// The client-side detector library uses different names (`label`,
/// `value`, `detail`, `source`) — those older names are accepted as
/// serde aliases so the CLI can consume either shape without a code
/// change if the server ever ships both (e.g. a `/v2/analysis/scan`
/// with a different envelope, or a self-hosted mirror still on old
/// schema).
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(default)]
pub struct ApiFinding {
    /// Server: `title`. Client-lib fallback: `label`.
    #[serde(alias = "label")]
    pub title: Option<String>,
    /// Server: `description`. Client-lib fallback: `value`.
    #[serde(alias = "value")]
    pub description: Option<String>,
    /// Server: `evidence`. Client-lib fallback: `detail`.
    #[serde(alias = "detail")]
    pub evidence: Option<String>,
    /// Server: `remediation` (fix recommendation).
    pub remediation: Option<String>,
    /// Server: `line_index` (0-based index into the raw log where the
    /// finding was detected). Useful for jumping-to-line in a viewer.
    pub line_index: Option<u32>,
    /// Client-lib had `source` (the raw log line that matched); server
    /// doesn't emit this field. Kept as an Option so old fixtures parse.
    pub source: Option<String>,
    pub severity: Option<String>,
    pub cve_id: Option<String>,
    pub cvss_score: Option<f32>,
    pub is_exploitable: Option<bool>,
    /// Server-only enrichment fields we haven't modeled explicitly.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl ApiFinding {
    /// Best-effort display label, preferring the server's `title`.
    pub fn display_title(&self) -> &str {
        self.title.as_deref().unwrap_or("(finding)")
    }
    /// Best-effort display body, preferring the server's `description`.
    pub fn display_body(&self) -> &str {
        self.description.as_deref().unwrap_or("")
    }
    /// Best-effort supplementary line (evidence or remediation).
    pub fn display_detail(&self) -> Option<&str> {
        self.evidence.as_deref().or(self.remediation.as_deref())
    }
}

/// Server error body. FastAPI's default: `{"detail": "..."}`.
#[derive(Deserialize, Debug)]
pub struct ApiError {
    pub detail: Option<String>,
}

/// Parse a server response body. Callers give us the HTTP status
/// + raw body bytes; we sort them into a Result.
pub fn parse_scan_response(status: u16, body: &str) -> Result<ApiScanResponse, ApiFailure> {
    if (200..300).contains(&status) {
        serde_json::from_str(body).map_err(|e| ApiFailure::Malformed {
            status,
            snippet: body.chars().take(200).collect(),
            error: e.to_string(),
        })
    } else {
        let detail = serde_json::from_str::<ApiError>(body)
            .ok()
            .and_then(|e| e.detail);
        Err(ApiFailure::HttpStatus { status, detail })
    }
}

/// Structured API failures. Distinct variants let the caller render
/// each with a specific message (rate-limit points at pricing, auth
/// failures point at where to get a key, etc.).
#[derive(Debug)]
pub enum ApiFailure {
    /// The response wasn't parseable JSON. Includes a snippet of the
    /// body for the user to see so they can debug what came back.
    Malformed {
        status: u16,
        snippet: String,
        error: String,
    },
    /// The server returned a non-2xx status. Preserves the server's
    /// FastAPI-shaped `detail` string when present.
    HttpStatus { status: u16, detail: Option<String> },
}

impl std::fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiFailure::Malformed { status, error, .. } => {
                write!(
                    f,
                    "server returned HTTP {status} but body was not valid JSON: {error}"
                )
            }
            ApiFailure::HttpStatus { status, detail } => match detail {
                Some(d) => write!(f, "server returned HTTP {status}: {d}"),
                None => write!(f, "server returned HTTP {status}"),
            },
        }
    }
}

impl std::error::Error for ApiFailure {}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_success() {
        let body = r#"{"scan_id":"abc","findings":[]}"#;
        let r = parse_scan_response(200, body).unwrap();
        assert_eq!(r.scan_id.as_deref(), Some("abc"));
        assert!(r.findings.is_empty());
    }

    #[test]
    fn parses_full_success_and_preserves_extra_fields() {
        let body = r#"{
            "scan_id":"abc",
            "device_name":"Archer C7",
            "preview":true,
            "findings":[{"label":"Bootloader","value":"U-Boot","cve_id":"CVE-2023-1234","cvss_score":7.5,"unknown_future_field":42}],
            "findings_total":3,
            "findings_visible":1,
            "findings_hidden":2,
            "upgrade_reasons":["save_report"],
            "brand_new_server_field":"never seen this before"
        }"#;
        let r = parse_scan_response(200, body).unwrap();
        assert_eq!(r.findings.len(), 1);
        let f = &r.findings[0];
        // Server "label" alias → title on ApiFinding (backward-compat with
        // old fixtures that used the client-lib shape).
        assert_eq!(f.title.as_deref(), Some("Bootloader"));
        assert_eq!(f.cve_id.as_deref(), Some("CVE-2023-1234"));
        assert_eq!(f.cvss_score, Some(7.5));
        // Unknown finding-level field stayed in extra.
        assert!(f.extra.contains_key("unknown_future_field"));
        // Unknown top-level field stayed in extra.
        assert!(r.extra.contains_key("brand_new_server_field"));
        assert_eq!(r.findings_hidden, Some(2));
        assert_eq!(r.upgrade_reasons, vec!["save_report".to_string()]);
    }

    #[test]
    fn error_body_captured() {
        let body = r#"{"detail":"Anonymous preview limit reached."}"#;
        let err = parse_scan_response(429, body).unwrap_err();
        match err {
            ApiFailure::HttpStatus { status, detail } => {
                assert_eq!(status, 429);
                assert_eq!(detail.as_deref(), Some("Anonymous preview limit reached."));
            }
            _ => panic!("expected HttpStatus"),
        }
    }

    #[test]
    fn error_body_without_detail_is_ok() {
        let err = parse_scan_response(500, r#"{"error":"oops"}"#).unwrap_err();
        match err {
            ApiFailure::HttpStatus { status, detail } => {
                assert_eq!(status, 500);
                assert_eq!(detail, None);
            }
            _ => panic!("expected HttpStatus"),
        }
    }

    #[test]
    fn malformed_2xx_body_flagged() {
        let err = parse_scan_response(200, "not json at all").unwrap_err();
        match err {
            ApiFailure::Malformed {
                status, snippet, ..
            } => {
                assert_eq!(status, 200);
                assert!(snippet.contains("not json"));
            }
            _ => panic!("expected Malformed"),
        }
    }

    #[test]
    fn missing_findings_field_defaults_to_empty() {
        // Server-side schema regression / earlier version returned
        // just {scan_id} — we don't want to crash.
        let r = parse_scan_response(200, r#"{"scan_id":"x"}"#).unwrap();
        assert_eq!(r.scan_id.as_deref(), Some("x"));
        assert!(r.findings.is_empty());
        assert!(r.upgrade_reasons.is_empty());
    }

    #[test]
    fn display_hides_snippet() {
        // Rendered message should be short + user-facing, not the raw body.
        let e = ApiFailure::HttpStatus {
            status: 401,
            detail: Some("Not authenticated".into()),
        };
        assert_eq!(e.to_string(), "server returned HTTP 401: Not authenticated");
    }
}
