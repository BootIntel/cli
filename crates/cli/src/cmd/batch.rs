//! `bootintel batch <dir>` — run scan on every log file in a
//! directory and aggregate the result.
//!
//! Real workflow: after fleet-testing, you've got 20 boot-log
//! captures in `~/captures/2026-08-24-*.txt`. Batch runs client-side
//! detectors on each, prints a per-file summary + a rollup by label
//! (how many devices had a `Telnet exposure`, how many had `Autoboot
//! interruptable`, etc.).
//!
//! Output shape: text by default (human-readable table + rollup),
//! json/csv/sarif/junit for machine consumers. CSV is especially
//! useful — batch streams one row per finding across all files with
//! a leading `source` column, so `bootintel batch ... --format csv |
//! pandas` gets a fleet-wide dashboard in one line.

use anyhow::{Context, Result};
use bootintel_detectors::{analyze, CRITICAL_LABELS};
use clap::Args as ClapArgs;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::output::{self, html_escape, ColorMode, Format};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Directory to scan. Walked non-recursively unless --recursive.
    #[arg(value_name = "DIR")]
    dir: PathBuf,

    /// Walk into subdirectories. Off by default so a `.` batch
    /// doesn't accidentally scan `node_modules/` or `.git/`.
    #[arg(long)]
    recursive: bool,

    /// Comma-separated file extensions to include. Default: txt,log.
    /// Case-insensitive.
    #[arg(long, value_name = "EXT[,EXT...]", default_value = "txt,log")]
    ext: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Exit non-zero if any file has a critical-exposure finding
    /// (same set as `scan --gate-critical`). Per-file scan failures
    /// (unreadable file, permission denied) always exit non-zero
    /// regardless of this flag.
    #[arg(long)]
    gate_critical: bool,

    /// Suppress ANSI colour in the text format.
    #[arg(long)]
    no_color: bool,

    /// Run only these detectors — see `bootintel scan --help` for
    /// the label list + normalization rules.
    #[arg(long, value_name = "LIST")]
    only: Option<String>,

    /// Skip these detectors (applied after --only).
    #[arg(long, value_name = "LIST")]
    skip: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let want_exts: Vec<String> = args
        .ext
        .split(',')
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    if want_exts.is_empty() {
        anyhow::bail!("--ext is empty; pass at least one extension (default: txt,log)");
    }

    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(&args.dir, args.recursive, &want_exts, &mut files)?;
    files.sort();

    let stdout = io::stdout();
    let color = crate::output::resolve_color_mode(args.no_color, &stdout);
    let mut out = stdout.lock();

    // Scan up front — we need all findings before we can render text
    // rollups or JSON envelopes. Batches on small (<1MB) logs are
    // fast enough that eager scan is fine; for very large logs the
    // caller can shell-loop `bootintel scan` instead.
    let scanned: Vec<Scanned> = files
        .iter()
        .map(|p| Scanned::from_file(p, &args.only, &args.skip))
        .collect();

    let mut critical_hit = false;
    for s in &scanned {
        if let ScanOutcome::Ok(findings) = &s.outcome {
            if findings
                .iter()
                .any(|f| CRITICAL_LABELS.contains(&f.label.as_str()))
            {
                critical_hit = true;
            }
        }
    }

    match args.format {
        Format::Text => write_text_report(&mut out, &scanned, color)?,
        Format::Json => write_json_report(&mut out, &scanned)?,
        Format::Csv => write_csv_report(&mut out, &scanned)?,
        Format::Html => write_html_report(&mut out, &scanned)?,
        Format::Md => write_md_report(&mut out, &scanned)?,
        Format::Sarif | Format::Junit => {
            anyhow::bail!(
                "--format {:?} isn't supported for batch (produces one report per file).\n  \
                 Loop `bootintel scan --format {:?}` over the files instead, or use --format json/csv/text/html/md.",
                args.format, args.format
            );
        }
    }
    let _ = out.flush();

    // Non-zero exit if any file failed to read or (with --gate-critical) if any critical fired.
    let any_error = scanned
        .iter()
        .any(|s| matches!(s.outcome, ScanOutcome::Err(_)));
    if any_error {
        std::process::exit(2);
    }
    if args.gate_critical && critical_hit {
        std::process::exit(1);
    }
    Ok(())
}

struct Scanned {
    path: PathBuf,
    outcome: ScanOutcome,
}

enum ScanOutcome {
    Ok(Vec<bootintel_detectors::Finding>),
    Err(String),
}

impl Scanned {
    fn from_file(p: &std::path::Path, only: &Option<String>, skip: &Option<String>) -> Self {
        match std::fs::read_to_string(p) {
            Ok(text) => {
                let findings = crate::detector_filter::filter(analyze(&text), only, skip);
                Self {
                    path: p.to_path_buf(),
                    outcome: ScanOutcome::Ok(findings),
                }
            }
            Err(e) => Self {
                path: p.to_path_buf(),
                outcome: ScanOutcome::Err(e.to_string()),
            },
        }
    }
}

fn collect_files(
    dir: &std::path::Path,
    recursive: bool,
    exts: &[String],
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let read =
        std::fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
    for entry in read {
        let entry = entry.with_context(|| format!("iterating {}", dir.display()))?;
        let path = entry.path();
        let ft = entry
            .file_type()
            .with_context(|| format!("stat {}", path.display()))?;
        if ft.is_dir() {
            if recursive {
                collect_files(&path, true, exts, out)?;
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let ext_ok = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .map(|e| exts.iter().any(|w| w == &e))
            .unwrap_or(false);
        if ext_ok {
            out.push(path);
        }
    }
    Ok(())
}

fn write_text_report<W: Write>(out: &mut W, scanned: &[Scanned], color: ColorMode) -> Result<()> {
    let color_on = color == ColorMode::On;
    let (dim_open, dim_close) = if color_on {
        ("\x1b[2m", "\x1b[0m")
    } else {
        ("", "")
    };
    let (bold_open, bold_close) = if color_on {
        ("\x1b[1m", "\x1b[0m")
    } else {
        ("", "")
    };
    let (red_open, red_close) = if color_on {
        ("\x1b[1;31m", "\x1b[0m")
    } else {
        ("", "")
    };

    writeln!(
        out,
        "{bold_open}bootintel batch — {} file(s){bold_close}",
        scanned.len()
    )?;
    writeln!(out)?;

    let mut ok_count = 0;
    let mut err_count = 0;
    let mut rollup: BTreeMap<&str, usize> = BTreeMap::new();

    for s in scanned {
        match &s.outcome {
            ScanOutcome::Ok(findings) => {
                ok_count += 1;
                let critical = findings
                    .iter()
                    .any(|f| CRITICAL_LABELS.contains(&f.label.as_str()));
                let marker = if critical {
                    format!("{red_open}!{red_close}")
                } else {
                    " ".into()
                };
                writeln!(
                    out,
                    "  {marker} {} — {} finding(s)",
                    s.path.display(),
                    findings.len()
                )?;
                for f in findings {
                    *rollup.entry(f.label.as_str()).or_insert(0) += 1;
                    writeln!(out, "      {dim_open}·{dim_close} {}: {}", f.label, f.value)?;
                }
            }
            ScanOutcome::Err(e) => {
                err_count += 1;
                writeln!(out, "  {red_open}✗{red_close} {} — {e}", s.path.display())?;
            }
        }
    }
    writeln!(out)?;
    writeln!(
        out,
        "{bold_open}rollup{bold_close} (by finding label, across all files):"
    )?;
    if rollup.is_empty() {
        writeln!(out, "  (no findings)")?;
    } else {
        for (label, count) in &rollup {
            let marker = if CRITICAL_LABELS.contains(label) {
                format!("{red_open}!{red_close}")
            } else {
                " ".into()
            };
            writeln!(out, "  {marker} {count:4}  {label}")?;
        }
    }
    writeln!(out)?;
    writeln!(out, "{bold_open}summary{bold_close}: {ok_count} scanned, {err_count} failed, {} unique findings", rollup.len())?;
    Ok(())
}

fn write_json_report<W: Write>(out: &mut W, scanned: &[Scanned]) -> Result<()> {
    let files: Vec<serde_json::Value> = scanned
        .iter()
        .map(|s| match &s.outcome {
            ScanOutcome::Ok(findings) => serde_json::json!({
                "path": s.path.display().to_string(),
                "findings": findings.iter().map(|f| serde_json::json!({
                    "label": f.label, "value": f.value,
                    "detail": f.detail, "source": f.source,
                })).collect::<Vec<_>>(),
            }),
            ScanOutcome::Err(e) => serde_json::json!({
                "path": s.path.display().to_string(),
                "error": e,
            }),
        })
        .collect();
    let mut rollup: BTreeMap<String, usize> = BTreeMap::new();
    for s in scanned {
        if let ScanOutcome::Ok(findings) = &s.outcome {
            for f in findings {
                *rollup.entry(f.label.clone()).or_insert(0) += 1;
            }
        }
    }
    let body = serde_json::json!({
        "bootintel_version": env!("CARGO_PKG_VERSION"),
        "analysis_source": "client",
        "file_count": scanned.len(),
        "files": files,
        "rollup": rollup,
    });
    serde_json::to_writer_pretty(&mut *out, &body)?;
    writeln!(out)?;
    Ok(())
}

fn write_html_report<W: Write>(out: &mut W, scanned: &[Scanned]) -> Result<()> {
    // For batch we build a single HTML with one section per file so
    // recipients can Ctrl-F across the whole corpus. Reuse the
    // per-file styling by rendering the whole page ourselves rather
    // than concatenating output::write_html once per file (which
    // would repeat <html><head><body> per file).
    let file_count = scanned.len();
    let ok_files = scanned
        .iter()
        .filter(|s| matches!(s.outcome, ScanOutcome::Ok(_)))
        .count();
    let total_findings: usize = scanned
        .iter()
        .map(|s| match &s.outcome {
            ScanOutcome::Ok(f) => f.len(),
            _ => 0,
        })
        .sum();
    let critical_count: usize = scanned
        .iter()
        .map(|s| match &s.outcome {
            ScanOutcome::Ok(f) => f
                .iter()
                .filter(|f| CRITICAL_LABELS.contains(&f.label.as_str()))
                .count(),
            _ => 0,
        })
        .sum();
    let version = env!("CARGO_PKG_VERSION");

    let sections: String = scanned.iter().map(|s| {
        let path = s.path.display().to_string();
        match &s.outcome {
            ScanOutcome::Ok(findings) => {
                let rows: String = findings.iter().map(|f| {
                    let is_crit = CRITICAL_LABELS.contains(&f.label.as_str());
                    let cls = if is_crit { " class=\"critical\"" } else { "" };
                    let badge = if is_crit { " <span class=\"badge critical\">critical</span>" } else { "" };
                    format!(
                        "<tr{cls}><td class=\"label\">{}{badge}</td><td>{}</td></tr>",
                        html_escape(&f.label), html_escape(&f.value)
                    )
                }).collect::<Vec<_>>().join("");
                format!(
                    "<h2>{}</h2><div class=\"count\">{} finding(s)</div><table><tbody>{}</tbody></table>",
                    html_escape(&path), findings.len(), rows
                )
            }
            ScanOutcome::Err(e) => format!(
                "<h2 class=\"failed\">{}</h2><div class=\"error\">scan failed: {}</div>",
                html_escape(&path), html_escape(e)
            ),
        }
    }).collect::<Vec<_>>().join("\n");

    writeln!(
        out,
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>bootintel batch report</title>
<style>
body {{ font: 14px -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 1000px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
h1 {{ margin: 0 0 .25rem; }}
h2 {{ margin: 2rem 0 .25rem; font-size: 1rem; word-break: break-all; }}
h2.failed {{ color: #c62828; }}
.count {{ color: #666; font-size: .85rem; margin-bottom: .5rem; }}
.summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
.summary .card {{ flex: 1; border: 1px solid #e0e0e0; border-radius: 6px; padding: 1rem; }}
.summary .n {{ font-size: 1.6rem; font-weight: 600; }}
.summary .critical .n {{ color: #c62828; }}
.summary .label {{ color: #666; font-size: .85rem; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; }}
th, td {{ text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #f0f0f0; vertical-align: top; font-size: .9rem; }}
tr.critical {{ background: #fff5f5; }}
td.label {{ font-weight: 600; white-space: nowrap; }}
.badge {{ display: inline-block; padding: 1px 6px; margin-left: .35rem; border-radius: 3px; font-size: .7rem; font-weight: 500; text-transform: uppercase; }}
.badge.critical {{ background: #c62828; color: #fff; }}
.error {{ color: #c62828; font-size: .85rem; }}
footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #eee; color: #999; font-size: .8rem; }}
</style></head><body>
<h1>bootintel batch report</h1>
<div class="summary">
  <div class="card"><div class="n">{file_count}</div><div class="label">files scanned</div></div>
  <div class="card"><div class="n">{ok_files}</div><div class="label">ok</div></div>
  <div class="card"><div class="n">{total_findings}</div><div class="label">total findings</div></div>
  <div class="card critical"><div class="n">{critical_count}</div><div class="label">critical exposures</div></div>
</div>
{sections}
<footer>Generated by bootintel-cli {version} · <code>batch --format html</code></footer>
</body></html>"#
    )?;
    Ok(())
}

fn write_csv_report<W: Write>(out: &mut W, scanned: &[Scanned]) -> Result<()> {
    output::write_csv_header(out, true)?;
    for s in scanned {
        if let ScanOutcome::Ok(findings) = &s.outcome {
            let src = s.path.display().to_string();
            output::write_csv_rows(out, findings, Some(&src))?;
        }
        // Scan errors are intentionally skipped from CSV — pandas
        // consumers don't want a text error snuggled into a numeric
        // row. Errors show in the text/json reports.
    }
    Ok(())
}

/// One `# bootintel batch report` header, then a per-file section
/// with the same table shape as `scan --format md`. Meant for a
/// single markdown blob that CI can paste into GITHUB_STEP_SUMMARY
/// (one summary covering N devices), or a security engineer can
/// paste into an incident-tracking ticket.
fn write_md_report<W: Write>(out: &mut W, scanned: &[Scanned]) -> Result<()> {
    let total_files = scanned.len();
    let total_findings: usize = scanned
        .iter()
        .filter_map(|s| match &s.outcome {
            ScanOutcome::Ok(f) => Some(f.len()),
            _ => None,
        })
        .sum();
    let error_files = scanned
        .iter()
        .filter(|s| matches!(s.outcome, ScanOutcome::Err(_)))
        .count();

    writeln!(out, "# bootintel batch report")?;
    writeln!(out)?;
    writeln!(
        out,
        "**{total_files} file{}, {total_findings} finding{} total**{}",
        if total_files == 1 { "" } else { "s" },
        if total_findings == 1 { "" } else { "s" },
        if error_files > 0 {
            format!(" — {error_files} file(s) errored")
        } else {
            String::new()
        }
    )?;
    writeln!(out)?;

    for s in scanned {
        writeln!(out, "## `{}`", s.path.display())?;
        writeln!(out)?;
        match &s.outcome {
            ScanOutcome::Ok(findings) if findings.is_empty() => {
                writeln!(out, "No findings.")?;
                writeln!(out)?;
            }
            ScanOutcome::Ok(findings) => {
                output::write_md(out, findings)?;
                writeln!(out)?;
            }
            ScanOutcome::Err(e) => {
                writeln!(out, "> ❌ Error: {e}")?;
                writeln!(out)?;
            }
        }
    }
    Ok(())
}
