//! Renderers for server-side scan responses.
//!
//! Two output surfaces:
//!
//! * `write_text_response` — human-readable terminal output for
//!   `bootintel scan --api` and Ctrl-A f in analyze mode. Groups
//!   findings, calls out CVE IDs, notes hidden findings + why.
//! * `write_json_response` — machine-consumable output. Passthrough
//!   of the entire server body so downstream tools can reach any
//!   field we haven't modeled (via ApiScanResponse::extra) and
//!   `analysis_source: "server"` is a top-level flag they can dispatch on.

use anyhow::Result;
use serde_json::json;
use std::io::Write;

use super::response::ApiScanResponse;
use crate::analyze::render::sanitize_for_term;

/// Text output for a server response. Style-matches the existing
/// client-side text output (label-column + value + optional detail
/// on a wrapped line) so a user who runs `bootintel scan foo.log`
/// then `bootintel scan --api foo.log` doesn't see two different
/// UIs.
pub fn write_text_response<W: Write>(out: &mut W, resp: &ApiScanResponse) -> Result<()> {
    let device = resp.device_name.as_deref().unwrap_or("Unknown Device");
    let preview = resp.preview.unwrap_or(false);
    let mode = if preview {
        "preview (anonymous)"
    } else {
        "full (authenticated)"
    };
    writeln!(out, "  server analysis — {device} — {mode}")?;
    writeln!(out)?;

    if resp.findings.is_empty() {
        writeln!(out, "  no findings returned by server")?;
    } else {
        for f in &resp.findings {
            // Server-shape field names (title/description/evidence);
            // ApiFinding accessors handle the "(finding)"/"" fallbacks
            // when the server ships a partial record. Sanitize each
            // field against ANSI-escape injection from untrusted content.
            let title = sanitize_for_term(f.display_title());
            let body = sanitize_for_term(f.display_body());
            // Prefix with severity glyph when available so critical
            // findings jump off the page.
            let glyph = match f.severity.as_deref() {
                Some(s) if s.eq_ignore_ascii_case("critical") => "⚠ ",
                Some(s) if s.eq_ignore_ascii_case("high") => "! ",
                _ => "● ",
            };
            writeln!(out, "  {glyph}{title:<24}  {body}")?;
            if let Some(d) = f.display_detail() {
                let d = sanitize_for_term(d);
                writeln!(out, "  {:<26}    {d}", "")?;
            }
            // CVE row when the server surfaced one.
            if let Some(cve) = &f.cve_id {
                let cve = sanitize_for_term(cve);
                match f.cvss_score {
                    Some(score) => writeln!(out, "  {:<26}    {cve} (CVSS {score:.1})", "")?,
                    None => writeln!(out, "  {:<26}    {cve}", "")?,
                }
            }
        }
    }
    writeln!(out)?;

    // Summary stats when the server sent them.
    if let (Some(vis), Some(hid)) = (resp.findings_visible, resp.findings_hidden) {
        let total = resp.findings_total.unwrap_or(vis + hid);
        writeln!(out, "  {total} findings — {vis} shown, {hid} hidden")?;
        if hid > 0 {
            writeln!(
                out,
                "    (hidden findings require a paid plan — see bootintel.com/pricing)"
            )?;
        }
    } else if let Some(total) = resp.findings_total {
        writeln!(out, "  {total} findings")?;
    }

    // AI report is a big string when present; pass it through
    // verbatim so heuristic-formatting doesn't mangle whatever the
    // server chose.
    if let Some(ai) = &resp.ai_report {
        writeln!(out)?;
        writeln!(out, "  AI-generated summary")?;
        writeln!(out, "  {}", "-".repeat(60))?;
        for line in ai.lines() {
            writeln!(out, "  {line}")?;
        }
    }

    if resp.cve_details_locked.unwrap_or(false) {
        writeln!(out)?;
        writeln!(out, "  CVE details are locked on this plan.")?;
        writeln!(
            out,
            "    Upgrade at bootintel.com/pricing to see CVSS scores,"
        )?;
        writeln!(
            out,
            "    exploit availability, and affected-version details."
        )?;
    }

    Ok(())
}

/// JSON output for a server response. Passes the whole server body
/// through under a top-level `server` key + adds `analysis_source:
/// "server"` and `bootintel_version` so downstream consumers can
/// dispatch on schema origin cleanly.
///
/// We deliberately re-serialize from the parsed struct (rather than
/// echoing the raw bytes back) so unknown fields surface via the
/// `#[serde(flatten)] extra` map — the round-trip preserves them.
pub fn write_json_response<W: Write>(out: &mut W, resp: &ApiScanResponse) -> Result<()> {
    let envelope = json!({
        "bootintel_version": env!("CARGO_PKG_VERSION"),
        "analysis_source": "server",
        "server": server_value(resp),
    });
    serde_json::to_writer_pretty(&mut *out, &envelope)?;
    writeln!(out)?;
    Ok(())
}

fn server_value(resp: &ApiScanResponse) -> serde_json::Value {
    // Re-serialize via serde_json::to_value so #[serde(flatten)]
    // works both ways and we don't drop any unknown-future-field
    // data the server sent.
    serde_json::to_value(SerializableResponse::from(resp)).unwrap_or(serde_json::Value::Null)
}

fn slice_is_empty<T>(s: &&[T]) -> bool {
    s.is_empty()
}

// Serialize back to JSON. Symmetric with the ApiScanResponse deserializer.
#[derive(serde::Serialize)]
struct SerializableResponse<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    analyzed_at: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<bool>,
    findings: Vec<SerializableFinding<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings_visible: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings_hidden: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    findings_cve_revealed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cve_details_locked: Option<bool>,
    #[serde(skip_serializing_if = "slice_is_empty")]
    attack_recommendations: &'a [serde_json::Value],
    #[serde(skip_serializing_if = "slice_is_empty")]
    upgrade_reasons: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_report: Option<&'a str>,
    #[serde(flatten)]
    extra: &'a std::collections::BTreeMap<String, serde_json::Value>,
}

impl<'a> From<&'a ApiScanResponse> for SerializableResponse<'a> {
    fn from(r: &'a ApiScanResponse) -> Self {
        Self {
            scan_id: r.scan_id.as_deref(),
            device_name: r.device_name.as_deref(),
            analyzed_at: r.analyzed_at.as_deref(),
            preview: r.preview,
            findings: r.findings.iter().map(SerializableFinding::from).collect(),
            findings_total: r.findings_total,
            findings_visible: r.findings_visible,
            findings_hidden: r.findings_hidden,
            findings_cve_revealed: r.findings_cve_revealed,
            cve_details_locked: r.cve_details_locked,
            attack_recommendations: &r.attack_recommendations,
            upgrade_reasons: &r.upgrade_reasons,
            ai_report: r.ai_report.as_deref(),
            extra: &r.extra,
        }
    }
}

#[derive(serde::Serialize)]
struct SerializableFinding<'a> {
    // Field names match the server response shape (title / description
    // / evidence / remediation / line_index). JSON output round-trips
    // the server body cleanly.
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line_index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cve_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cvss_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_exploitable: Option<bool>,
    #[serde(flatten)]
    extra: &'a std::collections::BTreeMap<String, serde_json::Value>,
}

impl<'a> From<&'a super::response::ApiFinding> for SerializableFinding<'a> {
    fn from(f: &'a super::response::ApiFinding) -> Self {
        Self {
            title: f.title.as_deref(),
            description: f.description.as_deref(),
            evidence: f.evidence.as_deref(),
            remediation: f.remediation.as_deref(),
            line_index: f.line_index,
            source: f.source.as_deref(),
            severity: f.severity.as_deref(),
            cve_id: f.cve_id.as_deref(),
            cvss_score: f.cvss_score,
            is_exploitable: f.is_exploitable,
            extra: &f.extra,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::response::{ApiFinding, ApiScanResponse};

    fn sample() -> ApiScanResponse {
        ApiScanResponse {
            scan_id: Some("s1".into()),
            device_name: Some("Archer C7".into()),
            preview: Some(false),
            findings: vec![
                ApiFinding {
                    title: Some("Bootloader".into()),
                    description: Some("U-Boot 2020.10".into()),
                    ..Default::default()
                },
                ApiFinding {
                    title: Some("Autoboot interruptable".into()),
                    description: Some("Hit any key to stop autoboot".into()),
                    severity: Some("critical".into()),
                    cve_id: Some("CVE-2023-12345".into()),
                    cvss_score: Some(7.5),
                    ..Default::default()
                },
            ],
            findings_total: Some(4),
            findings_visible: Some(2),
            findings_hidden: Some(2),
            ..Default::default()
        }
    }

    #[test]
    fn text_output_includes_cve_row() {
        let mut buf = Vec::new();
        write_text_response(&mut buf, &sample()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("U-Boot 2020.10"));
        assert!(s.contains("CVE-2023-12345"));
        assert!(s.contains("CVSS 7.5"));
    }

    #[test]
    fn text_output_notes_hidden_findings() {
        let mut buf = Vec::new();
        write_text_response(&mut buf, &sample()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("4 findings"));
        assert!(s.contains("2 shown"));
        assert!(s.contains("2 hidden"));
        assert!(s.contains("bootintel.com/pricing"));
    }

    #[test]
    fn text_output_shows_locked_notice() {
        let mut r = sample();
        r.cve_details_locked = Some(true);
        let mut buf = Vec::new();
        write_text_response(&mut buf, &r).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("locked"));
    }

    #[test]
    fn text_output_shows_ai_report_when_present() {
        let mut r = sample();
        r.ai_report = Some("summary line 1\nsummary line 2".into());
        let mut buf = Vec::new();
        write_text_response(&mut buf, &r).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("AI-generated summary"));
        assert!(s.contains("summary line 1"));
        assert!(s.contains("summary line 2"));
    }

    #[test]
    fn json_output_flags_analysis_source_server() {
        let mut buf = Vec::new();
        write_json_response(&mut buf, &sample()).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["analysis_source"], "server");
        assert_eq!(v["server"]["device_name"], "Archer C7");
        assert_eq!(v["server"]["findings"][1]["cve_id"], "CVE-2023-12345");
    }

    #[test]
    fn json_output_preserves_unknown_server_fields() {
        let mut r = sample();
        r.extra.insert(
            "brand_new_field".to_string(),
            serde_json::json!({"nested": true}),
        );
        let mut buf = Vec::new();
        write_json_response(&mut buf, &r).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(std::str::from_utf8(&buf).unwrap()).unwrap();
        assert_eq!(v["server"]["brand_new_field"]["nested"], true);
    }

    #[test]
    fn preview_mode_labels_correctly() {
        let mut r = sample();
        r.preview = Some(true);
        let mut buf = Vec::new();
        write_text_response(&mut buf, &r).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("preview (anonymous)"));
    }
}
