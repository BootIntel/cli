//! `bootintel view <scan.json>` — re-render an existing scan JSON
//! envelope in any output format. Point of the command: you
//! archived `bootintel scan --format json > report.json`, now you
//! want to look at it as text (or HTML, or CSV) without re-running
//! the detectors against the original log (which you might not
//! have anymore).
//!
//! Accepts either:
//!   - a plain scan envelope: `{"findings":[...], ...}`
//!   - a `bootintel export` bundle: `{"log":{...}, "findings":[...], ...}`
//!
//! Detects the shape by looking for the top-level keys.

use anyhow::{Context, Result};
use bootintel_detectors::Finding;
use clap::Args as ClapArgs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use crate::output::{self, Format};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON file to re-render (or `-` for stdin).
    #[arg(value_name = "SCAN_JSON")]
    file: PathBuf,

    /// Output format. text/html/csv/sarif/junit round-trip cleanly;
    /// `--format json` is a no-op passthrough.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Suppress ANSI colour.
    #[arg(long)]
    no_color: bool,
}

pub fn run(args: Args) -> Result<()> {
    let text = read_input(&args.file)?;
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing {} as JSON", args.file.display()))?;

    let findings = extract_findings(&parsed).ok_or_else(|| {
        anyhow::anyhow!(
            "no findings array in the input JSON.\n  \
             Expected shape: `bootintel scan --format json` envelope or `bootintel export` bundle."
        )
    })?;

    let stdout = io::stdout();
    let color = crate::output::resolve_color_mode(args.no_color, &stdout);

    let mut out = stdout.lock();
    // Passthrough for --format json — the input already IS the shape,
    // just re-serialize in case the caller wants pretty vs compact.
    if matches!(args.format, Format::Json) {
        serde_json::to_writer_pretty(&mut out, &parsed)?;
        writeln!(out)?;
    } else {
        // For non-JSON we don't have the raw log (the input might
        // be an export bundle that has it, but the scan envelope
        // doesn't). Pass an empty string — only SARIF's line-index
        // heuristic uses it and gracefully degrades to line 1 when
        // it can't find the source string.
        let raw_hint = extract_raw_log(&parsed).unwrap_or_default();
        output::write(&mut out, &findings, args.format, &raw_hint, color)?;
    }
    let _ = out.flush();
    Ok(())
}

fn read_input(p: &std::path::Path) -> Result<String> {
    if p == std::path::Path::new("-") {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading stdin")?;
        Ok(buf)
    } else {
        std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))
    }
}

fn extract_findings(v: &serde_json::Value) -> Option<Vec<Finding>> {
    let arr = v.get("findings")?.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let label = item.get("label").and_then(|s| s.as_str())?.to_string();
        // Accept both "value" (client envelope) and "detail" fields.
        let value = item
            .get("value")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let detail = item
            .get("detail")
            .and_then(|s| s.as_str())
            .map(String::from);
        let source = item
            .get("source")
            .and_then(|s| s.as_str())
            .map(String::from);
        out.push(Finding {
            label,
            value,
            detail,
            source,
        });
    }
    Some(out)
}

fn extract_raw_log(v: &serde_json::Value) -> Option<String> {
    // `bootintel export` bundles put the raw log at .log.content
    v.get("log")
        .and_then(|l| l.get("content"))
        .and_then(|c| c.as_str())
        .map(String::from)
}
