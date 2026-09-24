//! `bootintel cve <ID>` — look up a CVE in the local feed data.
//!
//! Prints the entry for the requested CVE from a local copy of the
//! embedded-CVE feed (the same data the cron rewrites every 4h and
//! that the `/feed/embedded-cves.*` routes serve), or lists every
//! entry if no ID is given.
//!
//! The point isn't to replace `nvd` — it's to make the "which of my
//! covered targets got a fresh CVE this week" data usable without a
//! browser. Lookups read the LOCAL file, never the network, so the
//! command works offline / air-gapped once the data is on disk.
//!
//! # Where the feed lives
//!
//! In the platform state dir — `~/.local/state/bootintel/` on Linux,
//! `~/Library/Application Support/bootintel/` on macOS,
//! `%LOCALAPPDATA%\bootintel\` on Windows — populated by
//! `bootintel cve --refresh`.
//!
//! This used to resolve `./data/embedded-cves-feed.json` relative to
//! the working directory, which meant the command worked only when run
//! from inside a checkout of the source repo and failed everywhere an
//! installed binary actually runs — while its own help implied the
//! feed shipped with the binary. The repo-relative paths are still
//! tried, last, so working in a checkout keeps behaving as before.

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::PathBuf;

use crate::output::html_escape;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// CVE ID to look up (e.g. CVE-2026-74884). Case-insensitive.
    /// Omit to list every entry in the current feed.
    #[arg(value_name = "ID")]
    id: Option<String>,

    /// Feed file to read. Defaults to $BOOTINTEL_CVE_FEED, then the
    /// cached copy in the platform state dir (see `--refresh`), then
    /// ./data/embedded-cves-feed.json for in-repo use. Handy for
    /// pointing at a copy pulled from an air-gapped mirror.
    #[arg(long, value_name = "PATH")]
    feed: Option<PathBuf>,

    /// Download the current feed from bootintel.com into the platform
    /// state dir, then continue with the lookup. The feed is a moving
    /// 72h window, so refresh before trusting an absence. Needs
    /// network; everything else in this subcommand is offline.
    #[arg(long)]
    refresh: bool,

    /// Filter by severity floor (CRITICAL, HIGH, MEDIUM). Only
    /// meaningful in list mode (no ID given).
    #[arg(long, value_name = "LEVEL")]
    min_severity: Option<String>,

    /// Filter by target label (case-insensitive substring). Only
    /// meaningful in list mode.
    #[arg(long, value_name = "SUBSTR")]
    target: Option<String>,

    /// JSON output. Single entry (when ID given) or array (list mode).
    #[arg(long, conflicts_with = "html")]
    json: bool,

    /// Self-contained HTML output — one page, inlined styles, no JS.
    /// Portable "share this CVE feed slice with the team" artifact.
    /// Renders a single-entry detail view when an ID is given, or a
    /// filterable table when in list mode.
    #[arg(long, conflicts_with = "json")]
    html: bool,

    /// Suppress ANSI colour.
    #[arg(long)]
    no_color: bool,
}

// ── Feed schema (mirror of what scripts/cve-alert-bot.py writes) ─
#[derive(Debug, Deserialize, Serialize)]
struct FeedFile {
    generated_at: String,
    window_hours: u32,
    severity_floor: String,
    count: usize,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct Entry {
    id: String,
    severity: String,
    cvss_score: Option<f32>,
    target_label: String,
    target_url: String,
    description: String,
    published: Option<String>,
    modified: Option<String>,
    nvd_url: String,
    posted_to_bluesky: Option<bool>,
}

/// Public URL the feed is published at. Returns the same JSON the
/// `--feed` file holds.
const FEED_URL: &str = "https://bootintel.com/feed/embedded-cves.json";

/// Where a refreshed feed is cached. Same state dir `history` uses.
pub fn cached_feed_path() -> Option<PathBuf> {
    let root = dirs::state_dir().or_else(dirs::data_local_dir)?;
    Some(root.join("bootintel").join("embedded-cves-feed.json"))
}

/// Fetch the feed and write it to the cache path. Returns the path.
fn refresh_feed() -> Result<PathBuf> {
    let path = cached_feed_path()
        .context("no platform state dir resolvable, so there is nowhere to cache the feed; use --feed PATH instead")?;
    crate::vinfo!("fetching {FEED_URL}");
    let body = ureq::get(FEED_URL)
        .call()
        .with_context(|| format!("fetching {FEED_URL}"))?
        .into_string()
        .context("reading feed response body")?;

    // Parse before writing so a captive-portal HTML page or a
    // truncated transfer can't replace a good cached copy with junk.
    let parsed: FeedFile =
        serde_json::from_str(&body).context("the feed URL did not return a valid feed document")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, &body).with_context(|| format!("writing {}", path.display()))?;
    if !crate::verbose::is_quiet() {
        eprintln!(
            "[bootintel] feed refreshed — {} entries, generated {}, cached at {}",
            parsed.count,
            parsed.generated_at,
            path.display()
        );
    }
    Ok(path)
}

pub fn run(args: Args) -> Result<()> {
    let path = if args.refresh {
        refresh_feed()?
    } else {
        resolve_feed_path(&args.feed)?
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading feed {}", path.display()))?;
    let feed: FeedFile =
        serde_json::from_str(&text).with_context(|| format!("parsing feed {}", path.display()))?;

    let stdout = io::stdout();
    let color_on =
        crate::output::resolve_color_mode(args.no_color, &stdout) == crate::output::ColorMode::On;

    let mut out = stdout.lock();

    match &args.id {
        Some(id) => {
            let up = id.to_ascii_uppercase();
            match feed.entries.iter().find(|e| e.id.eq_ignore_ascii_case(&up)) {
                Some(e) => {
                    if args.json {
                        serde_json::to_writer_pretty(&mut out, e)?;
                        writeln!(out)?;
                    } else if args.html {
                        write_entry_html(&mut out, e, &feed)?;
                    } else {
                        print_entry(&mut out, e, color_on)?;
                    }
                }
                None => {
                    bail!(
                        "CVE {up} not in feed ({}) — the feed only carries entries in the last {}h window that match a covered target.\n  Try `bootintel cve` with no ID to list what's currently in.",
                        path.display(), feed.window_hours
                    );
                }
            }
        }
        None => {
            let severity_floor = args.min_severity.as_deref().map(|s| s.to_ascii_uppercase());
            let target_filter = args.target.as_deref().map(|s| s.to_ascii_lowercase());
            let filtered: Vec<&Entry> = feed
                .entries
                .iter()
                .filter(|e| severity_passes(&e.severity, severity_floor.as_deref()))
                .filter(|e| target_passes(&e.target_label, target_filter.as_deref()))
                .collect();
            if args.json {
                serde_json::to_writer_pretty(&mut out, &filtered)?;
                writeln!(out)?;
            } else if args.html {
                write_list_html(&mut out, &filtered, &feed)?;
            } else {
                writeln!(
                    out,
                    "feed: {} entries, generated {} (window {}h, severity floor {})",
                    filtered.len(),
                    feed.generated_at,
                    feed.window_hours,
                    feed.severity_floor
                )?;
                writeln!(out)?;
                for e in filtered {
                    print_entry_summary(&mut out, e, color_on)?;
                }
            }
        }
    }
    let _ = out.flush();
    Ok(())
}

fn resolve_feed_path(explicit: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.clone());
    }
    if let Ok(env) = std::env::var("BOOTINTEL_CVE_FEED") {
        return Ok(PathBuf::from(env));
    }
    // The cached copy written by `--refresh`. This is the path that
    // makes the command work for an installed binary, from any cwd.
    if let Some(p) = cached_feed_path() {
        if p.is_file() {
            return Ok(p);
        }
    }
    // Repo-relative fallbacks, last: convenient when hacking on the
    // source tree or running the container image, but never the thing
    // an installed binary should depend on.
    for candidate in [
        "data/embedded-cves-feed.json",
        "/data/embedded-cves-feed.json",
    ] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Ok(p);
        }
    }
    let cached = cached_feed_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<no platform state dir>".to_string());
    bail!(
        "no CVE feed on disk yet.\n  \
         Download it:\n    bootintel cve --refresh\n  \
         That caches {FEED_URL} at {cached}.\n  \
         Already have a copy (air-gapped mirror, CI artifact)? Point at it:\n    \
         bootintel cve --feed /path/to/embedded-cves-feed.json\n  \
         Or set $BOOTINTEL_CVE_FEED to the same path."
    );
}

/// Severity rank: lower number = more severe. Passes when the entry's
/// severity is at or above the requested floor. Unknown severities
/// sort as least-severe so they don't accidentally pass a strict floor.
fn severity_passes(entry_sev: &str, floor: Option<&str>) -> bool {
    let Some(floor) = floor else {
        return true;
    };
    let rank = |s: &str| match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 5,
    };
    rank(entry_sev) <= rank(floor)
}

fn target_passes(entry_target: &str, filter: Option<&str>) -> bool {
    match filter {
        Some(f) => entry_target.to_ascii_lowercase().contains(f),
        None => true,
    }
}

fn print_entry<W: Write>(out: &mut W, e: &Entry, color_on: bool) -> Result<()> {
    let sev_style = severity_color(&e.severity, color_on);
    writeln!(out, "{}{}{}", sev_style.0, e.id, sev_style.1)?;
    writeln!(
        out,
        "  severity  {}{}{}{}",
        sev_style.0,
        e.severity,
        sev_style.1,
        e.cvss_score
            .map(|s| format!(" (CVSS {s})"))
            .unwrap_or_default()
    )?;
    writeln!(out, "  target    {} → {}", e.target_label, e.target_url)?;
    if let Some(p) = &e.published {
        writeln!(out, "  published {p}")?;
    }
    if let Some(m) = &e.modified {
        writeln!(out, "  modified  {m}")?;
    }
    writeln!(out, "  nvd       {}", e.nvd_url)?;
    writeln!(
        out,
        "  bluesky   {}",
        if e.posted_to_bluesky.unwrap_or(false) {
            "posted"
        } else {
            "not posted"
        }
    )?;
    writeln!(out)?;
    writeln!(out, "  {}", e.description)?;
    Ok(())
}

fn print_entry_summary<W: Write>(out: &mut W, e: &Entry, color_on: bool) -> Result<()> {
    let (open, close) = severity_color(&e.severity, color_on);
    writeln!(
        out,
        "  {open}{:8} {}{close}  {:12} {}",
        e.severity,
        e.id,
        e.target_label,
        e.description.chars().take(80).collect::<String>()
    )?;
    Ok(())
}

fn write_entry_html<W: Write>(out: &mut W, e: &Entry, feed: &FeedFile) -> Result<()> {
    let cvss = e
        .cvss_score
        .map(|s| format!(" (CVSS {s:.1})"))
        .unwrap_or_default();
    let bluesky = e.posted_to_bluesky.unwrap_or(false);
    writeln!(
        out,
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{id} — bootintel CVE feed</title>
<style>
body {{ font: 15px -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 780px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
h1 {{ margin: 0 0 .25rem; font-family: ui-monospace, 'SF Mono', Menlo, monospace; }}
.meta {{ color: #666; font-size: .9rem; margin-bottom: 1.5rem; }}
.sev {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: .8rem; text-transform: uppercase; margin-right: .5rem; }}
.sev.CRITICAL {{ background: #c62828; color: #fff; }}
.sev.HIGH {{ background: #ef6c00; color: #fff; }}
.sev.MEDIUM {{ background: #f9a825; color: #fff; }}
.sev.LOW {{ background: #6c757d; color: #fff; }}
dl {{ display: grid; grid-template-columns: 8rem 1fr; gap: .5rem 1rem; margin: 1rem 0; }}
dt {{ color: #666; font-size: .85rem; text-transform: uppercase; letter-spacing: .05em; }}
dd {{ margin: 0; word-break: break-word; }}
.desc {{ background: #f7f7f7; padding: 1rem; border-radius: 4px; border-left: 3px solid #4fc3f7; }}
footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #eee; color: #999; font-size: .8rem; }}
</style></head><body>
<h1>{id}</h1>
<div class="meta"><span class="sev {sev}">{sev}</span>{cvss} · matched target: <a href="{target_url}">{target_label}</a></div>
<dl>
  <dt>NVD</dt>       <dd><a href="{nvd_url}">{nvd_url}</a></dd>
  <dt>Published</dt> <dd>{published}</dd>
  <dt>Modified</dt>  <dd>{modified}</dd>
  <dt>Bluesky</dt>   <dd>{bluesky_state}</dd>
</dl>
<h2>Description</h2>
<div class="desc">{description}</div>
<footer>bootintel-cli {version} · pulled from {feed_generated} feed (window {feed_window}h, severity floor {feed_floor})</footer>
</body></html>"#,
        id = html_escape(&e.id),
        sev = e.severity,
        target_url = html_escape(&e.target_url),
        target_label = html_escape(&e.target_label),
        nvd_url = html_escape(&e.nvd_url),
        published = html_escape(e.published.as_deref().unwrap_or("—")),
        modified = html_escape(e.modified.as_deref().unwrap_or("—")),
        bluesky_state = if bluesky { "posted" } else { "not posted" },
        description = html_escape(&e.description),
        version = env!("CARGO_PKG_VERSION"),
        feed_generated = html_escape(&feed.generated_at),
        feed_window = feed.window_hours,
        feed_floor = html_escape(&feed.severity_floor),
    )?;
    Ok(())
}

fn write_list_html<W: Write>(out: &mut W, entries: &[&Entry], feed: &FeedFile) -> Result<()> {
    let rows: String = entries.iter().map(|e| {
        let cvss = e.cvss_score.map(|s| format!(" ({s:.1})")).unwrap_or_default();
        format!(
            "<tr><td><span class=\"sev {sev}\">{sev}</span>{cvss}</td><td><a href=\"{nvd}\">{id}</a></td><td>{tgt}</td><td>{desc}</td></tr>",
            sev = e.severity,
            cvss = cvss,
            nvd = html_escape(&e.nvd_url),
            id = html_escape(&e.id),
            tgt = html_escape(&e.target_label),
            desc = html_escape(&e.description.chars().take(140).collect::<String>()),
        )
    }).collect::<Vec<_>>().join("\n");
    writeln!(
        out,
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>bootintel CVE feed ({count} entries)</title>
<style>
body {{ font: 14px -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
h1 {{ margin: 0 0 .25rem; }}
.meta {{ color: #666; font-size: .9rem; margin-bottom: 1.5rem; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #eee; vertical-align: top; font-size: .9rem; }}
th {{ background: #fafafa; font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; color: #555; }}
.sev {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-weight: 600; font-size: .72rem; text-transform: uppercase; color: #fff; }}
.sev.CRITICAL {{ background: #c62828; }}
.sev.HIGH {{ background: #ef6c00; }}
.sev.MEDIUM {{ background: #f9a825; }}
.sev.LOW {{ background: #6c757d; }}
footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #eee; color: #999; font-size: .8rem; }}
</style></head><body>
<h1>bootintel CVE feed — {count} entries</h1>
<div class="meta">generated {gen} · window {win}h · severity floor {floor} · bootintel-cli {ver}</div>
<table>
  <thead><tr><th>Severity</th><th>CVE</th><th>Target</th><th>Description</th></tr></thead>
  <tbody>
{rows}
  </tbody>
</table>
<footer>Pulled from local feed file. Full stream at <a href="https://bootintel.com/feed/embedded-cves">https://bootintel.com/feed/embedded-cves</a>.</footer>
</body></html>"#,
        count = entries.len(),
        gen = html_escape(&feed.generated_at),
        win = feed.window_hours,
        floor = html_escape(&feed.severity_floor),
        ver = env!("CARGO_PKG_VERSION"),
    )?;
    Ok(())
}

fn severity_color(sev: &str, color_on: bool) -> (&'static str, &'static str) {
    if !color_on {
        return ("", "");
    }
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => ("\x1b[1;31m", "\x1b[0m"), // bold red
        "HIGH" => ("\x1b[1;33m", "\x1b[0m"),     // bold yellow
        "MEDIUM" => ("\x1b[33m", "\x1b[0m"),     // yellow
        _ => ("", ""),
    }
}
