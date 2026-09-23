//! Output-format serializers: json / text / sarif / junit.
//!
//! Every format carries a stable top-level `analysis_source` field
//! ("client" for offline scans, "server" when the server response is
//! rendered via `--api`). Downstream consumers can dispatch on it
//! to know which schema they're getting.

use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;
use std::io::Write;

use bootintel_detectors::{Finding, CRITICAL_LABELS};

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum Format {
    Json,
    Text,
    Sarif,
    Junit,
    /// RFC 4180 CSV. Header + one row per finding. Meant for
    /// pandas / spreadsheet ingestion (and `bootintel batch` where
    /// the caller wants all rows across all files in one file).
    Csv,
    /// Self-contained HTML report — one page, inlined styles, no
    /// JS. Portable "share the finding set with the vendor" artifact.
    Html,
    /// GitHub-flavored markdown. Meant for pasting into a
    /// GITHUB_STEP_SUMMARY, a PR comment, or a Slack message.
    /// Summary line + table + critical-exposure callout; no HTML
    /// tags, no images. Aliased as `markdown` for clarity.
    #[value(alias = "markdown")]
    Md,
}

/// Serializable mirror of the detector library's Finding.
/// Field-for-field with the browser tool's Finding type so JSON
/// output round-trips against the browser detector library.
#[derive(Serialize)]
struct FindingOut<'a> {
    label: &'a str,
    value: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
    /// 1-based line of `source` in the analyzed log. Additive field —
    /// omitted when unknown, so consumers written against the older
    /// shape are unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    line_number: Option<usize>,
}

impl<'a> From<&'a Finding> for FindingOut<'a> {
    fn from(f: &'a Finding) -> Self {
        Self {
            label: &f.label,
            value: &f.value,
            detail: f.detail.as_deref(),
            source: f.source.as_deref(),
            line_number: f.line_number,
        }
    }
}

/// Did this scan actually inspect something, and did it recognize
/// anything? Mirrors the legacy Node analyzer's field of the same name
/// and pairs with the exit ladder in `cmd::scan` (2 = empty input,
/// 3 = unrecognized).
///
/// Consumers that only ever looked at `findings` keep working; this is
/// an added key, and it exists so that "zero findings" can be
/// distinguished from "clean" without inferring it from an array
/// length.
fn analysis_status(findings: &[Finding]) -> &'static str {
    if findings.is_empty() {
        "unrecognized"
    } else {
        "matched"
    }
}

#[derive(Serialize)]
struct Envelope<'a> {
    bootintel_version: &'a str,
    analysis_source: &'a str,
    detector_count: usize,
    findings: Vec<FindingOut<'a>>,
    /// Added field — see `analysis_status`.
    analysis_status: &'a str,
}

/// Whether the `text` format should emit ANSI colour escapes.
/// Callers compute this once (respecting `NO_COLOR`, `--no-color`,
/// and stdout-is-tty) and hand it in so we don't have to re-check
/// on every finding. Other formats ignore it — machine-readable
/// output must never carry ANSI.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ColorMode {
    On,
    Off,
}

/// Resolve ANSI-color mode from the standard three-source precedence:
///   1. Explicit `--no-color` flag (or equivalent) forces Off.
///   2. `NO_COLOR=<nonempty>` env var forces Off (per no-color.org spec).
///   3. Falls back to `stream.is_terminal()` — On iff writing to a TTY.
///
/// Extracted here so every subcommand agrees on the same rules — pre-
/// factoring, six subcommands each had a slightly different local copy
/// (some checked `.is_empty()`, some used `is_none_or`, one returned
/// bare `bool` instead of `ColorMode`).
///
/// Takes `&impl IsTerminal` so callers can pass either a real
/// `io::Stdout` or a mock in tests. `IsTerminal` is a sealed trait —
/// see `resolve_color_mode_from_tty` for the test-friendly variant.
pub fn resolve_color_mode(no_color_flag: bool, stream: &impl std::io::IsTerminal) -> ColorMode {
    resolve_color_mode_from_tty(no_color_flag, stream.is_terminal())
}

/// Same precedence as `resolve_color_mode` but takes a pre-resolved
/// `is_tty` bool instead of a stream. Sole reason: `std::io::IsTerminal`
/// is sealed, so a MockTty for unit tests would need to wrap a real
/// FD. Splitting the query lets the tests exercise the pure decision
/// logic directly.
/// Mask a secret by keeping only its last `keep` chars, prefixed
/// with `"..."`. Values shorter than `2 * keep` are fully masked
/// (returned as `"***"`) — printing "ok...bad4" for a 7-char key
/// would leak most of the entropy.
///
/// Used by `config list`, `config set`'s stderr echo, and
/// `whoami`'s api-key-last4 display. Single implementation so a
/// masking-policy change (e.g. "always mask fully in --quiet mode")
/// lands in one place.
///
/// Uses `char_indices` to slice on a UTF-8 boundary — the naive
/// `.chars().rev().take(k).collect::<Vec<_>>()` version scanned the
/// string twice and allocated a Vec per call.
pub fn mask_tail(s: &str, keep: usize) -> String {
    let s = s.trim();
    // Guard against 0 keep (would return ellipsis of full string) +
    // ensure entropy floor: require the tail to be at most half the
    // total so we're never leaking > 50% of a short key.
    if keep == 0 || s.chars().count() < keep.saturating_mul(2) {
        return "***".to_string();
    }
    // Walk from the end backwards `keep` steps to find the byte offset
    // of the (keep)th-from-last char. char_indices() gives (byte_pos, ch),
    // so nth(keep-1) from the reverse gives us the boundary we want.
    let start_byte = s
        .char_indices()
        .rev()
        .nth(keep - 1)
        .map(|(i, _)| i)
        .unwrap_or(0);
    format!("...{}", &s[start_byte..])
}

pub fn resolve_color_mode_from_tty(no_color_flag: bool, is_tty: bool) -> ColorMode {
    if no_color_flag {
        return ColorMode::Off;
    }
    if std::env::var("NO_COLOR")
        .ok()
        .is_some_and(|v| !v.is_empty())
    {
        return ColorMode::Off;
    }
    if is_tty {
        ColorMode::On
    } else {
        ColorMode::Off
    }
}

/// Render `findings` in `format`.
///
/// `source_uri` identifies the analyzed input — the path as the user
/// gave it, or `stdin` for a pipe. SARIF needs it to point its
/// `artifactLocation` at a file that actually exists in the caller's
/// workspace; the other formats ignore it.
pub fn write<W: Write>(
    out: &mut W,
    findings: &[Finding],
    format: Format,
    raw_log: &str,
    color: ColorMode,
    source_uri: &str,
) -> Result<()> {
    match format {
        Format::Json => write_json(out, findings),
        Format::Text => write_text(out, findings, color),
        Format::Sarif => write_sarif(out, findings, raw_log, source_uri),
        Format::Junit => write_junit(out, findings),
        Format::Csv => write_csv(out, findings, None),
        Format::Html => write_html(out, findings),
        Format::Md => write_md(out, findings),
    }
}

/// GitHub-flavored markdown. Meant for paste into GITHUB_STEP_SUMMARY /
/// a PR body / a Slack message. Public so `batch` can aggregate a
/// corpus into one markdown block.
pub fn write_md<W: Write>(out: &mut W, findings: &[Finding]) -> Result<()> {
    let count = findings.len();
    let critical_count = findings
        .iter()
        .filter(|f| CRITICAL_LABELS.contains(&f.label.as_str()))
        .count();
    let version = env!("CARGO_PKG_VERSION");

    writeln!(out, "# bootintel scan report")?;
    writeln!(out)?;
    if count == 0 {
        writeln!(
            out,
            "No findings — client-side detectors did not match this log."
        )?;
        writeln!(out)?;
        writeln!(out, "<sub>Generated by bootintel-cli {version}. For CVE matches + exploit paths, use `scan --api` or visit [bootintel.com](https://bootintel.com/).</sub>")?;
        return Ok(());
    }
    if critical_count > 0 {
        writeln!(
            out,
            "> ⚠️ **{critical_count} critical exposure{}** identified — see the ⚠ rows below.",
            if critical_count == 1 { "" } else { "s" }
        )?;
        writeln!(out)?;
    }
    writeln!(
        out,
        "**{count} finding{} total**",
        if count == 1 { "" } else { "s" }
    )?;
    writeln!(out)?;
    writeln!(out, "| | Detector | Value | Detail |")?;
    writeln!(out, "|---|---|---|---|")?;
    for f in findings {
        let is_critical = CRITICAL_LABELS.contains(&f.label.as_str());
        let glyph = if is_critical { "⚠" } else { "•" };
        let label = md_escape(&f.label);
        let value = md_escape(&f.value);
        let detail = f.detail.as_deref().map(md_escape).unwrap_or_default();
        writeln!(out, "| {glyph} | **{label}** | `{value}` | {detail} |")?;
    }
    writeln!(out)?;
    writeln!(out, "<sub>Generated by bootintel-cli {version} — client-side detectors only. For CVE matches + exploit paths, use `scan --api` or visit [bootintel.com](https://bootintel.com/).</sub>")?;
    Ok(())
}

/// Escape the four glyphs that would break a GFM table cell: pipe
/// (splits the column), backtick (opens/closes code span awkwardly),
/// backslash (escape swallower), and newline (breaks the row). Keeps
/// values readable — no over-escaping.
fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '`' => out.push_str("\\`"),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Self-contained HTML — one page, inlined styles, no JS, no external
/// fonts. "Share this with the vendor" artifact. Public so batch can
/// aggregate a single HTML across a corpus.
pub fn write_html<W: Write>(out: &mut W, findings: &[Finding]) -> Result<()> {
    let count = findings.len();
    let critical_count = findings
        .iter()
        .filter(|f| CRITICAL_LABELS.contains(&f.label.as_str()))
        .count();
    let version = env!("CARGO_PKG_VERSION");

    let rows: String = findings.iter().map(|f| {
        let is_critical = CRITICAL_LABELS.contains(&f.label.as_str());
        let row_class = if is_critical { " class=\"critical\"" } else { "" };
        let badge = if is_critical { " <span class=\"badge critical\">critical</span>" } else { "" };
        let detail_html = f.detail.as_deref().map(|d|
            format!("<div class=\"detail\">{}</div>", html_escape(d))).unwrap_or_default();
        let source_html = f.source.as_deref().map(|s|
            format!("<div class=\"source\">{}</div>", html_escape(s))).unwrap_or_default();
        format!(
            "<tr{row_class}><td class=\"label\">{}{badge}</td><td>{}{detail_html}{source_html}</td></tr>",
            html_escape(&f.label),
            html_escape(&f.value),
        )
    }).collect::<Vec<_>>().join("\n      ");

    writeln!(
        out,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>bootintel scan report</title>
  <style>
    body {{ font: 14px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
    h1 {{ margin: 0 0 .25rem; font-size: 1.4rem; }}
    .subtitle {{ color: #666; font-size: .9rem; margin-bottom: 1.5rem; }}
    .summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
    .summary .card {{ flex: 1; border: 1px solid #e0e0e0; border-radius: 6px; padding: 1rem; }}
    .summary .n {{ font-size: 1.6rem; font-weight: 600; }}
    .summary .label {{ color: #666; font-size: .85rem; }}
    .summary .critical .n {{ color: #c62828; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: .5rem .75rem; border-bottom: 1px solid #eee; vertical-align: top; }}
    th {{ background: #fafafa; font-size: .85rem; text-transform: uppercase; letter-spacing: .05em; color: #555; }}
    tr.critical {{ background: #fff5f5; }}
    td.label {{ font-weight: 600; white-space: nowrap; }}
    .detail {{ color: #666; font-size: .9rem; margin-top: .25rem; }}
    .source {{ color: #999; font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-size: .82rem; margin-top: .25rem; word-break: break-all; }}
    .badge {{ display: inline-block; padding: 1px 6px; margin-left: .35rem; border-radius: 3px; font-size: .7rem; font-weight: 500; text-transform: uppercase; }}
    .badge.critical {{ background: #c62828; color: #fff; }}
    footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #eee; color: #999; font-size: .8rem; }}
    footer a {{ color: #4fc3f7; }}
  </style>
</head>
<body>
  <h1>bootintel scan report</h1>
  <div class="subtitle">Generated by bootintel-cli {version} — client-side detectors only.</div>
  <div class="summary">
    <div class="card"><div class="n">{count}</div><div class="label">findings</div></div>
    <div class="card{}"><div class="n">{critical_count}</div><div class="label">critical exposures</div></div>
  </div>
  <table>
    <thead><tr><th>Label</th><th>Value / detail</th></tr></thead>
    <tbody>
      {rows}
    </tbody>
  </table>
  <footer>
    Report format: <code>scan --format html</code>. For CVE matching + exploit paths, use <code>scan --api</code> or visit <a href="https://bootintel.com/">bootintel.com</a>.
  </footer>
</body>
</html>"#,
        if critical_count > 0 { " critical" } else { "" }
    )?;
    Ok(())
}

/// Escape a string for interpolation into an HTML attribute or text
/// node. Public so batch / diff / cve report writers can reuse a
/// single, audited implementation instead of open-coding their own.
pub fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Public so `bootintel batch` can stream multiple files into a single
/// CSV output without re-emitting the header per file. Pass
/// `source_hint = Some(path)` to get an extra leading "source" column
/// that identifies which log a row came from.
pub fn write_csv<W: Write>(
    out: &mut W,
    findings: &[Finding],
    source_hint: Option<&str>,
) -> Result<()> {
    // Header emitted here — callers that want to stream multiple
    // files should use `write_csv_rows` instead (skips the header).
    write_csv_header(out, source_hint.is_some())?;
    write_csv_rows(out, findings, source_hint)?;
    Ok(())
}

pub fn write_csv_header<W: Write>(out: &mut W, with_source: bool) -> Result<()> {
    if with_source {
        writeln!(out, "source,label,value,detail,source_line")?;
    } else {
        writeln!(out, "label,value,detail,source_line")?;
    }
    Ok(())
}

pub fn write_csv_rows<W: Write>(
    out: &mut W,
    findings: &[Finding],
    source_hint: Option<&str>,
) -> Result<()> {
    for f in findings {
        if let Some(src) = source_hint {
            write!(out, "{},", csv_escape(src))?;
        }
        writeln!(
            out,
            "{},{},{},{}",
            csv_escape(&f.label),
            csv_escape(&f.value),
            csv_escape(f.detail.as_deref().unwrap_or("")),
            csv_escape(f.source.as_deref().unwrap_or(""))
        )?;
    }
    Ok(())
}

/// RFC 4180 field escape: wrap in double quotes if the field contains
/// a comma, quote, or newline; double any embedded quotes.
fn csv_escape(s: &str) -> String {
    if s.chars()
        .any(|c| c == ',' || c == '"' || c == '\n' || c == '\r')
    {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

fn write_json<W: Write>(out: &mut W, findings: &[Finding]) -> Result<()> {
    let env = Envelope {
        bootintel_version: env!("CARGO_PKG_VERSION"),
        analysis_source: "client",
        detector_count: bootintel_detectors::detector_labels().len(),
        findings: findings.iter().map(FindingOut::from).collect(),
        analysis_status: analysis_status(findings),
    };
    serde_json::to_writer_pretty(&mut *out, &env)?;
    writeln!(out)?;
    Ok(())
}

/// ANSI SGR codes. Bare consts (vs a colour crate dep) keep binary
/// size flat — this is the third place we've drawn a line at not
/// pulling a crate in for something a few escape strings can do.
const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD_RED: &str = "\x1b[1;31m";
const ANSI_BOLD_CYAN: &str = "\x1b[1;36m";
const ANSI_DIM: &str = "\x1b[2m";

fn wrap(s: &str, code: &str, on: bool) -> String {
    if on {
        format!("{code}{s}{ANSI_RESET}")
    } else {
        s.to_string()
    }
}

fn write_text<W: Write>(out: &mut W, findings: &[Finding], color: ColorMode) -> Result<()> {
    use crate::analyze::render::sanitize_for_term;
    let color_on = color == ColorMode::On;
    if findings.is_empty() {
        writeln!(out, "no findings")?;
        return Ok(());
    }
    for f in findings {
        // Sanitize label/value/detail against ANSI-escape injection
        // via crafted boot log content flowing through detector fields.
        let label = sanitize_for_term(&f.label);
        let value = sanitize_for_term(&f.value);
        let is_critical = CRITICAL_LABELS.contains(&f.label.as_str());
        // Compute visible length before wrapping so `:<24` alignment
        // still lines up when ANSI escapes are present (escapes have
        // zero display width but Rust's formatter counts bytes).
        let pad = 24usize.saturating_sub(label.chars().count());
        let styled_label = if is_critical {
            wrap(&label, ANSI_BOLD_RED, color_on)
        } else {
            wrap(&label, ANSI_BOLD_CYAN, color_on)
        };
        writeln!(out, "  {styled_label}{:pad$}  {value}", "")?;
        if let Some(d) = &f.detail {
            let d = sanitize_for_term(d);
            let styled_detail = wrap(&d, ANSI_DIM, color_on);
            writeln!(out, "  {:<24}    {styled_detail}", "")?;
        }
    }
    write_text_summary(findings.len());
    Ok(())
}

/// The trailing count + "here is what the paid tier adds" block.
///
/// Goes to **stderr**, unconditionally, and not at all under `-q`.
///
/// It used to go to stdout and ignore `-q` entirely, which meant
/// `bootintel scan --format text > report.txt` shipped a three-line
/// advertisement inside a customer's report, and `-q` — whose own help
/// text promises it "suppresses banners + status hints" — did nothing.
/// stdout carries findings; commentary about them belongs on stderr
/// with every other status hint in this CLI.
fn write_text_summary(count: usize) {
    if crate::verbose::is_quiet() {
        return;
    }
    eprintln!();
    eprintln!("  {count} findings identified locally (client-side detectors only).");
    eprintln!("  For CVE matches + exploit paths + AI report:");
    eprintln!("    bootintel scan --api <log>            (with BOOTINTEL_API_KEY set)");
    eprintln!("    bootintel scan --api --preview <log>  (anonymous free preview — 3/day per IP)");
    eprintln!("    bootintel share <log>                 (share via URL, log embedded, no upload)");
}

// ── SARIF v2.1.0 ─────────────────────────────────────────────────────
//
// Small hand-rolled builder — SARIF is verbose but our subset is
// tractable. Enough to satisfy GitHub Code Scanning ingestion.

/// Turn the input's identity into a SARIF `artifactLocation.uri`.
///
/// This used to be the constant `"boot.log"`, which quietly broke the
/// flagship CI integration: GitHub's SARIF upload attaches each result
/// to the file named here, so every annotation pointed at a path that
/// is not in the repository and landed nowhere.
///
/// SARIF wants a URI relative to the run's root when it can be one, so:
/// an absolute path under the workspace (`$GITHUB_WORKSPACE`, else the
/// current directory) is emitted relative to it; anything else is
/// emitted as given. `stdin` passes through unchanged — there is no
/// file to annotate, and a consumer can see that plainly.
fn sarif_artifact_uri(source_uri: &str) -> String {
    if source_uri == "stdin" || source_uri == "-" {
        return "stdin".to_string();
    }
    let path = std::path::Path::new(source_uri);
    let root = std::env::var_os("GITHUB_WORKSPACE")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::current_dir().ok());
    if let Some(root) = root {
        // Compare canonicalized forms so `./log.txt`, `log.txt` and a
        // symlinked workspace all resolve the same way, but emit the
        // *uncanonicalized* relative path so it matches what is
        // actually checked in.
        if let (Ok(abs_path), Ok(abs_root)) = (path.canonicalize(), root.canonicalize()) {
            if let Ok(rel) = abs_path.strip_prefix(&abs_root) {
                // SARIF URIs use forward slashes on every platform.
                return rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
            }
        }
    }
    source_uri.to_string()
}

fn write_sarif<W: Write>(
    out: &mut W,
    findings: &[Finding],
    raw_log: &str,
    source_uri: &str,
) -> Result<()> {
    let ver = env!("CARGO_PKG_VERSION");
    let artifact_uri = sarif_artifact_uri(source_uri);
    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = if CRITICAL_LABELS.contains(&f.label.as_str()) {
                "warning"
            } else {
                "note"
            };
            let mut msg = format!("{}: {}", f.label, f.value);
            if let Some(d) = &f.detail {
                msg.push_str(&format!(" ({d})"));
            }
            // Prefer the line number the detector library recorded;
            // fall back to locating the evidence text for findings
            // rehydrated from an older archived envelope.
            let line_index = f
                .line_number
                .map(|n| n as i64)
                .or_else(|| {
                    f.source
                        .as_ref()
                        .and_then(|s| raw_log.lines().position(|line| line.contains(s)))
                        .map(|i| i as i64 + 1)
                })
                .unwrap_or(1);
            serde_json::json!({
                "ruleId": f.label,
                "level": level,
                "message": { "text": msg },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": artifact_uri },
                        "region": { "startLine": line_index }
                    }
                }]
            })
        })
        .collect();

    let rules: Vec<serde_json::Value> = bootintel_detectors::detector_labels()
        .iter()
        .map(|label| {
            serde_json::json!({
                "id": label,
                "name": label,
                "shortDescription": { "text": *label },
                "fullDescription": { "text": *label },
                "defaultConfiguration": {
                    "level": if CRITICAL_LABELS.contains(label) { "warning" } else { "note" }
                }
            })
        })
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "bootintel",
                    "informationUri": "https://bootintel.com",
                    "version": ver,
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });
    serde_json::to_writer_pretty(&mut *out, &sarif)?;
    writeln!(out)?;
    Ok(())
}

// ── JUnit XML ────────────────────────────────────────────────────────
//
// Minimal single-testsuite XML that CI systems (Jenkins, GitLab,
// generic junit-report consumers) parse cleanly. Each detector
// becomes a testcase; critical-exposure findings become failures.

fn write_junit<W: Write>(out: &mut W, findings: &[Finding]) -> Result<()> {
    let total = bootintel_detectors::detector_labels().len();
    let matched = findings.len();
    let failures = findings
        .iter()
        .filter(|f| CRITICAL_LABELS.contains(&f.label.as_str()))
        .count();

    writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writeln!(
        out,
        r#"<testsuite name="bootintel" tests="{}" failures="{}" errors="0" skipped="{}">"#,
        total,
        failures,
        total.saturating_sub(matched)
    )?;
    for label in bootintel_detectors::detector_labels() {
        let matched = findings.iter().find(|f| f.label == label);
        write!(
            out,
            r#"  <testcase classname="bootintel.detector" name="{}""#,
            xml_escape(label)
        )?;
        match matched {
            None => {
                // Not matched — skip (i.e., didn't fire on this log).
                writeln!(out, r#"><skipped message="not matched" /></testcase>"#)?;
            }
            Some(f) if CRITICAL_LABELS.contains(&label) => {
                writeln!(out, r#">"#)?;
                writeln!(
                    out,
                    r#"    <failure message="{}">{}</failure>"#,
                    xml_escape(&f.value),
                    xml_escape(f.detail.as_deref().unwrap_or(""))
                )?;
                writeln!(out, r#"  </testcase>"#)?;
            }
            Some(f) => {
                writeln!(
                    out,
                    r#" ><system-out>{}</system-out></testcase>"#,
                    xml_escape(&f.value)
                )?;
            }
        }
    }
    writeln!(out, "</testsuite>")?;
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn f(label: &str, value: &str) -> Finding {
        Finding {
            label: label.into(),
            value: value.into(),
            detail: None,
            source: None,
            line_number: None,
        }
    }

    #[test]
    fn md_no_findings_emits_header_and_no_table() {
        let mut out = Vec::new();
        write_md(&mut out, &[]).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("# bootintel scan report"));
        assert!(s.contains("No findings"));
        assert!(!s.contains("| Detector |"), "no table when no findings");
    }

    #[test]
    fn md_emits_table_row_per_finding() {
        let findings = vec![f("Bootloader", "U-Boot 2020.10"), f("Kernel", "Linux 6.6")];
        let mut out = Vec::new();
        write_md(&mut out, &findings).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("**2 findings total**"));
        assert!(s.contains("| **Bootloader** | `U-Boot 2020.10` |"));
        assert!(s.contains("| **Kernel** | `Linux 6.6` |"));
    }

    #[test]
    fn md_flags_critical_findings_with_glyph_and_callout() {
        let findings = vec![
            f("Bootloader", "U-Boot"),
            f("Autoboot interruptable", "Yes (3s timeout)"),
        ];
        let mut out = Vec::new();
        write_md(&mut out, &findings).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("1 critical exposure"), "callout for 1 critical");
        // Critical row uses ⚠, non-critical uses •.
        let critical_line = s.lines().find(|l| l.contains("Autoboot")).unwrap();
        assert!(critical_line.starts_with("| ⚠ |"), "got: {critical_line}");
        let bootloader_line = s.lines().find(|l| l.contains("Bootloader")).unwrap();
        assert!(
            bootloader_line.starts_with("| • |"),
            "got: {bootloader_line}"
        );
    }

    #[test]
    fn md_escape_handles_pipe_and_backtick_and_backslash() {
        assert_eq!(md_escape("a|b"), "a\\|b");
        assert_eq!(md_escape("`foo`"), "\\`foo\\`");
        assert_eq!(md_escape("c:\\path"), "c:\\\\path");
        // Newlines collapse to space so a table row stays on one line.
        assert_eq!(md_escape("line1\nline2"), "line1 line2");
    }

    // The tests below mutate NO_COLOR. Serialize via the shared
    // process-wide env_lock() so this test module can't race with
    // config/history/api-endpoints tests that also touch env vars.
    fn scoped_no_color<T>(v: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _g = crate::test_util::env_lock();
        let saved = std::env::var("NO_COLOR").ok();
        match v {
            Some(x) => std::env::set_var("NO_COLOR", x),
            None => std::env::remove_var("NO_COLOR"),
        }
        let out = f();
        match saved {
            Some(x) => std::env::set_var("NO_COLOR", x),
            None => std::env::remove_var("NO_COLOR"),
        }
        out
    }

    #[test]
    fn mask_tail_keeps_last_n_when_long_enough() {
        // Entropy-floor rule: len >= 2 * keep, so keep=4 needs >= 8 chars.
        assert_eq!(mask_tail("bik_abcdef1234", 4), "...1234");
        assert_eq!(mask_tail("supersecret_9999", 4), "...9999");
    }

    #[test]
    fn mask_tail_scrubs_short_input_fully() {
        assert_eq!(mask_tail("shrt", 4), "***");
        assert_eq!(mask_tail("1234567", 4), "***", "7 chars < 2*4 = fully mask");
        assert_eq!(mask_tail("", 4), "***");
    }

    #[test]
    fn mask_tail_handles_utf8_boundaries() {
        // Multi-byte chars must not corrupt the slice — the byte offset
        // has to land on a UTF-8 boundary.
        let s = "prefix🔑🔑🔑🔑emoji";
        // Above is 17 chars total (well over 2*4=8). Keep the last 4
        // chars = "moji" — 4 ASCII bytes.
        assert_eq!(mask_tail(s, 4), "...moji");
    }

    #[test]
    fn mask_tail_zero_keep_returns_scrub() {
        assert_eq!(mask_tail("anything", 0), "***");
    }

    #[test]
    fn color_flag_beats_env_beats_tty() {
        scoped_no_color(None, || {
            // --no-color wins even with a TTY.
            assert_eq!(
                resolve_color_mode_from_tty(true, true),
                ColorMode::Off,
                "explicit --no-color must force off"
            );
        });
        scoped_no_color(Some("1"), || {
            // NO_COLOR wins over TTY when flag isn't set.
            assert_eq!(
                resolve_color_mode_from_tty(false, true),
                ColorMode::Off,
                "NO_COLOR=1 must force off"
            );
        });
        scoped_no_color(Some(""), || {
            // Empty NO_COLOR does NOT count per the spec.
            assert_eq!(
                resolve_color_mode_from_tty(false, true),
                ColorMode::On,
                "empty NO_COLOR must NOT disable color"
            );
        });
        scoped_no_color(None, || {
            assert_eq!(
                resolve_color_mode_from_tty(false, false),
                ColorMode::Off,
                "non-TTY defaults to off"
            );
            assert_eq!(
                resolve_color_mode_from_tty(false, true),
                ColorMode::On,
                "TTY defaults to on"
            );
        });
    }

    #[test]
    fn md_singular_plural_agree() {
        let mut out = Vec::new();
        write_md(&mut out, &[f("A", "1")]).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("**1 finding total**"), "singular: {s}");
    }
}
