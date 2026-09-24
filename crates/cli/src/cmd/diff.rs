//! `bootintel diff <log_a> <log_b>` — compare the finding sets from
//! two boot logs. Real workflow: after a firmware bump, capture the
//! old and new device's boot logs, run diff to see which exposures
//! appeared, disappeared, or changed. Also useful in CI: gate a PR
//! by running scan on before + after and diffing.
//!
//! Output shape (text, default):
//!
//! ```text
//!   +  new  finding_only_in_b
//!   -  gone finding_only_in_a
//!   =  same finding_present_in_both  (only shown with --show-same)
//! ```
//!
//! Exit codes:
//!
//! ```text
//!   0  identical finding sets (or all diffs allowed by --gate)
//!   1  differences present (default; useful for CI --gate flows)
//!   2  I/O or parse error
//! ```

use anyhow::{Context, Result};
use bootintel_detectors::{analyze, Finding};
use clap::Args as ClapArgs;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::output::{html_escape, ColorMode};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// First (baseline / "before") log file.
    #[arg(value_name = "LOG_A")]
    log_a: PathBuf,

    /// Second ("after") log file.
    #[arg(value_name = "LOG_B")]
    log_b: PathBuf,

    /// Also print findings that appear in both logs (same on both
    /// sides). Off by default so the diff view stays focused on
    /// what changed.
    #[arg(long)]
    show_same: bool,

    /// Emit machine-readable JSON instead of the human-oriented
    /// text diff. Same schema regardless of --show-same.
    #[arg(long, conflicts_with = "html")]
    json: bool,

    /// Emit a self-contained HTML report — one page, inlined styles,
    /// no JS. Portable "share this diff with the vendor" artifact.
    /// Sections for added / removed / same (same section respects
    /// --show-same).
    #[arg(long, conflicts_with = "json")]
    html: bool,

    /// Exit 0 even when finding sets differ. Useful when you're
    /// running diff purely for the output, not as a gate.
    #[arg(long)]
    no_gate: bool,

    /// Suppress ANSI colour (auto-off on non-TTY / $NO_COLOR).
    #[arg(long)]
    no_color: bool,
}

pub fn run(args: Args) -> Result<()> {
    let log_a = std::fs::read_to_string(&args.log_a)
        .with_context(|| format!("reading {}", args.log_a.display()))?;
    let log_b = std::fs::read_to_string(&args.log_b)
        .with_context(|| format!("reading {}", args.log_b.display()))?;

    let findings_a = analyze(&log_a);
    let findings_b = analyze(&log_b);

    // Group each side by (label, value) so two logs that produce the
    // same "Bootloader: U-Boot 2020.10" collapse to a single "same"
    // rather than showing as an add + delete. detail is included in
    // the key so a value change (e.g. version) surfaces as a diff.
    let map_a: BTreeMap<Key, &Finding> = findings_a.iter().map(|f| (Key::from(f), f)).collect();
    let map_b: BTreeMap<Key, &Finding> = findings_b.iter().map(|f| (Key::from(f), f)).collect();

    let mut added: Vec<&Finding> = Vec::new();
    let mut removed: Vec<&Finding> = Vec::new();
    let mut same: Vec<&Finding> = Vec::new();
    for (k, f) in &map_b {
        if map_a.contains_key(k) {
            same.push(f);
        } else {
            added.push(f);
        }
    }
    for (k, f) in &map_a {
        if !map_b.contains_key(k) {
            removed.push(f);
        }
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();

    if args.json {
        write_json(&mut out, &added, &removed, &same, &args.log_a, &args.log_b)?;
    } else if args.html {
        write_html(
            &mut out,
            &added,
            &removed,
            &same,
            args.show_same,
            &args.log_a,
            &args.log_b,
        )?;
    } else {
        let color = crate::output::resolve_color_mode(args.no_color, &io::stdout());
        write_text(&mut out, &added, &removed, &same, args.show_same, color)?;
    }
    let _ = out.flush();

    // Gate: any non-empty diff = exit 1 unless --no-gate.
    let differs = !added.is_empty() || !removed.is_empty();
    if differs && !args.no_gate {
        std::process::exit(1);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    label: String,
    value: String,
    detail: String,
}

impl From<&Finding> for Key {
    fn from(f: &Finding) -> Self {
        Self {
            label: f.label.clone(),
            value: f.value.clone(),
            detail: f.detail.clone().unwrap_or_default(),
        }
    }
}

fn write_text<W: Write>(
    out: &mut W,
    added: &[&Finding],
    removed: &[&Finding],
    same: &[&Finding],
    show_same: bool,
    color: ColorMode,
) -> Result<()> {
    // Zero-diff shortcut so CI output stays clean when logs match.
    if added.is_empty() && removed.is_empty() {
        writeln!(out, "identical finding sets ({} finding(s))", same.len())?;
        if show_same {
            for f in same {
                write_row(out, '=', f, color)?;
            }
        }
        return Ok(());
    }
    writeln!(
        out,
        "diff: {} added, {} removed, {} same",
        added.len(),
        removed.len(),
        same.len()
    )?;
    writeln!(out)?;
    for f in removed {
        write_row(out, '-', f, color)?;
    }
    for f in added {
        write_row(out, '+', f, color)?;
    }
    if show_same {
        for f in same {
            write_row(out, '=', f, color)?;
        }
    }
    Ok(())
}

fn write_row<W: Write>(out: &mut W, mark: char, f: &Finding, color: ColorMode) -> Result<()> {
    let color_on = color == ColorMode::On;
    let (open, close) = if color_on {
        match mark {
            '+' => ("\x1b[1;32m", "\x1b[0m"), // bold green
            '-' => ("\x1b[1;31m", "\x1b[0m"), // bold red
            _ => ("\x1b[2m", "\x1b[0m"),      // dim for same
        }
    } else {
        ("", "")
    };
    writeln!(out, "  {open}{mark} {}: {}{close}", f.label, f.value)?;
    if let Some(d) = &f.detail {
        writeln!(out, "      {open}{d}{close}")?;
    }
    Ok(())
}

fn write_json<W: Write>(
    out: &mut W,
    added: &[&Finding],
    removed: &[&Finding],
    same: &[&Finding],
    log_a: &std::path::Path,
    log_b: &std::path::Path,
) -> Result<()> {
    let body = serde_json::json!({
        "bootintel_version": env!("CARGO_PKG_VERSION"),
        "analysis_source": "client",
        "log_a": log_a.display().to_string(),
        "log_b": log_b.display().to_string(),
        "counts": { "added": added.len(), "removed": removed.len(), "same": same.len() },
        "added":   added.iter().map(|f| finding_json(f)).collect::<Vec<_>>(),
        "removed": removed.iter().map(|f| finding_json(f)).collect::<Vec<_>>(),
        "same":    same.iter().map(|f| finding_json(f)).collect::<Vec<_>>(),
    });
    serde_json::to_writer_pretty(&mut *out, &body)?;
    writeln!(out)?;
    Ok(())
}

fn finding_json(f: &Finding) -> serde_json::Value {
    serde_json::json!({
        "label": f.label,
        "value": f.value,
        "detail": f.detail,
        "source": f.source,
    })
}

fn write_html<W: Write>(
    out: &mut W,
    added: &[&Finding],
    removed: &[&Finding],
    same: &[&Finding],
    show_same: bool,
    log_a: &std::path::Path,
    log_b: &std::path::Path,
) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let row = |mark: &str, f: &Finding| -> String {
        let (row_class, badge) = match mark {
            "+" => (
                " class=\"added\"",
                "<span class=\"badge added\">+ added</span>",
            ),
            "-" => (
                " class=\"removed\"",
                "<span class=\"badge removed\">− removed</span>",
            ),
            _ => (
                " class=\"same\"",
                "<span class=\"badge same\">= same</span>",
            ),
        };
        let detail_html = f
            .detail
            .as_deref()
            .map(|d| format!("<div class=\"detail\">{}</div>", html_escape(d)))
            .unwrap_or_default();
        format!(
            "<tr{row_class}><td class=\"mark\">{badge}</td><td class=\"label\">{}</td><td>{}{detail_html}</td></tr>",
            html_escape(&f.label), html_escape(&f.value),
        )
    };
    let mut rows = String::new();
    for f in removed {
        rows.push_str(&row("-", f));
        rows.push('\n');
    }
    for f in added {
        rows.push_str(&row("+", f));
        rows.push('\n');
    }
    if show_same {
        for f in same {
            rows.push_str(&row("=", f));
            rows.push('\n');
        }
    }
    let identical = added.is_empty() && removed.is_empty();
    let summary = if identical {
        format!(
            "identical finding sets ({} finding{})",
            same.len(),
            if same.len() == 1 { "" } else { "s" }
        )
    } else {
        format!(
            "{} added, {} removed, {} same",
            added.len(),
            removed.len(),
            same.len()
        )
    };
    writeln!(
        out,
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>bootintel diff report</title>
<style>
body {{ font: 14px -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 1000px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
h1 {{ margin: 0 0 .25rem; font-size: 1.4rem; }}
.subtitle {{ color: #666; font-size: .9rem; margin-bottom: 1rem; }}
.summary {{ font-weight: 600; margin-bottom: 1.5rem; padding: .5rem .75rem; background: #f7f7f7; border-radius: 4px; }}
.paths {{ font-family: ui-monospace, 'SF Mono', Menlo, monospace; font-size: .82rem; color: #666; margin-bottom: 1.5rem; word-break: break-all; }}
.paths span.a::before {{ content: "− "; color: #c62828; }}
.paths span.b::before {{ content: "+ "; color: #2e7d32; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #f0f0f0; vertical-align: top; font-size: .9rem; }}
tr.added {{ background: #f0fff4; }}
tr.removed {{ background: #fff5f5; }}
tr.same {{ background: transparent; color: #666; }}
td.mark {{ width: 6.5rem; }}
td.label {{ font-weight: 600; white-space: nowrap; }}
.badge {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: .7rem; font-weight: 500; }}
.badge.added   {{ background: #2e7d32; color: #fff; }}
.badge.removed {{ background: #c62828; color: #fff; }}
.badge.same    {{ background: #ddd;    color: #333; }}
.detail {{ color: #666; font-size: .85rem; margin-top: .25rem; }}
footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #eee; color: #999; font-size: .8rem; }}
</style></head><body>
<h1>bootintel diff report</h1>
<div class="subtitle">Generated by bootintel-cli {version} · client-side detectors</div>
<div class="paths">
  <div><span class="a">{}</span></div>
  <div><span class="b">{}</span></div>
</div>
<div class="summary">{summary}</div>
<table><tbody>
{rows}</tbody></table>
<footer>Report format: <code>diff --html</code>. Same-side rows only shown with <code>--show-same</code>.</footer>
</body></html>"#,
        html_escape(&log_a.display().to_string()),
        html_escape(&log_b.display().to_string()),
    )?;
    Ok(())
}
