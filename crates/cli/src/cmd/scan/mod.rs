//! `bootintel scan <file>` — analyze a saved boot log.
//!
//! Two modes:
//!
//! * Default (client-side, offline): reads a file, runs the local
//!   detector library, prints JSON/text/SARIF/JUnit. Also supports
//!   `-` for stdin and `--gate-critical` for CI gating on exposure.
//!
//! * `--api` (server-side, online): POSTs the log to bootintel.com
//!   for CVE matching + exploit paths + optional AI summary. Two
//!   auth paths:
//!   * `--api` alone → needs `BOOTINTEL_API_KEY` env var (Pro tier).
//!   * `--api --preview` → anonymous, 3/day per IP (free).
//!
//! Rate-limit UX: 429 surfaces as a friendly message + non-zero
//! exit. Never silently falls back to client-side output (that
//! would produce confusing results — the user asked for full
//! analysis, got the client subset, has no idea why).
//!
//! # Module layout
//!
//! Split into four files after crossing 700 LOC:
//!
//!   * `mod.rs` (this file) — `Args`, `pub fn run`, `read_input`,
//!     `record_history`. The offline-mode fast path lives inline in
//!     `run` since it's the simple case.
//!   * `api.rs` — `--api` server-side path (`run_api`,
//!     `render_api_error`, `exit_code_for`).
//!   * `baseline.rs` — `--baseline` drift diff.
//!   * `context.rs` — `--context N` grep-C excerpts + UTF-8-safe
//!     `adjust_char_boundary` helper.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::io::{self, Read};
use std::path::PathBuf;

use bootintel_detectors::{analyze, CRITICAL_LABELS};

use crate::output::{self, Format};

mod api;
mod baseline;
mod context;

/// Environment variable the CLI reads for the authenticated `--api`
/// path. In-memory only — never persisted to a config file. The
/// resolution chain itself lives in `crate::config::resolve_api_key`.
///
/// `pub(super)` so the split-out `api` module can reference the same
/// literal in error-message text without redefining it.
pub(super) const API_KEY_ENV: &str = "BOOTINTEL_API_KEY";

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to a boot log file, or `-` for stdin.
    #[arg(value_name = "FILE")]
    file: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Json)]
    pub(super) format: Format,

    /// Exit non-zero if any critical-exposure detector fires
    /// (Autoboot interruptable, Telnet exposure). For CI gating.
    #[arg(long)]
    pub(super) gate_critical: bool,

    /// Read log from stdin regardless of `<FILE>` value. Convenience.
    #[arg(long)]
    stdin: bool,

    /// Post the log to bootintel.com for full CVE matching + exploit
    /// paths + (paid tiers) AI summary. Requires BOOTINTEL_API_KEY
    /// unless combined with --preview.
    #[arg(long)]
    api: bool,

    /// With --api: use the anonymous /preview endpoint instead of
    /// the authenticated /scan endpoint. Free but rate-limited to
    /// 3 scans per IP per day. No API key needed.
    #[arg(long)]
    pub(super) preview: bool,

    /// Override the API base URL. Defaults to <https://bootintel.com>
    /// (or $BOOTINTEL_API_BASE). Useful for self-hosted deployments
    /// and for pointing the CLI at a local mock in tests.
    #[arg(long, value_name = "URL")]
    pub(super) api_base: Option<String>,

    /// Device name hint sent to the server (labels the response).
    /// Ignored in client-side mode.
    #[arg(long, value_name = "NAME")]
    pub(super) device_name: Option<String>,

    /// Suppress ANSI colour in the `text` format. Colour is otherwise
    /// auto-detected: on when stdout is a TTY and $NO_COLOR is unset,
    /// off when the output is piped (so `bootintel scan foo | jq` and
    /// `bootintel scan foo > out.txt` never end up with escape codes
    /// in the captured bytes). $NO_COLOR alone also disables — this
    /// flag is the explicit escape hatch.
    #[arg(long)]
    no_color: bool,

    /// Run only these detectors — comma-separated labels
    /// (case-insensitive; spaces / hyphens / underscores ignored).
    /// Example: --only bootloader,kernel,init-system
    /// See `bootintel detectors` for the full list.
    #[arg(long, value_name = "LIST")]
    pub(super) only: Option<String>,

    /// Skip these detectors — comma-separated, same normalization
    /// as --only. Applied AFTER --only, so `--only bootloader,kernel
    /// --skip kernel` yields just Bootloader.
    #[arg(long, value_name = "LIST")]
    pub(super) skip: Option<String>,

    /// Show N chars of surrounding log context per finding (`grep -C`-
    /// shape). Only takes effect for `--format text` output. Useful
    /// for debugging false positives — a finding surfaces "here's
    /// what the detector actually matched against". 0 disables.
    #[arg(long, default_value_t = 0, value_name = "N")]
    context: usize,

    /// Compare the current scan's findings against a saved baseline
    /// (an earlier `scan --format json` or `export` JSON). Exit 1
    /// if anything changed — the CI regression pattern: check the
    /// baseline into the repo, run `scan --baseline` on PRs.
    /// Reports what was added / removed / changed on stderr.
    #[arg(long, value_name = "JSON")]
    baseline: Option<PathBuf>,

    /// Assert a property of the finding set. Exit 1 on any failed
    /// assertion. Repeatable. Grammar (per --gate):
    ///   Label            → must be present (any value)
    ///   !Label           → must NOT be present
    ///   Label=value      → present + exact string match
    ///   Label~=regex     → present + regex match
    /// Labels are case-insensitive (spaces / hyphens / underscores
    /// ignored). Values compare byte-for-byte.
    /// Example:
    ///   --gate 'Bootloader=U-Boot 2020.10'
    ///   --gate 'Kernel~=Linux 6\\.6\\.'
    ///   --gate '!Telnet exposure'
    #[arg(long, value_name = "EXPR", action = clap::ArgAction::Append)]
    gate: Vec<String>,
}

// Detectors whose findings count as "critical" for --gate-critical
// are defined in `bootintel_detectors::CRITICAL_LABELS` — the single
// source of truth used across scan, batch, output, analyze, and tui.

pub fn run(args: Args) -> Result<()> {
    let raw = read_input(&args)?;

    if args.api {
        return api::run_api(&args, &raw);
    }

    let findings = crate::detector_filter::filter(analyze(&raw), &args.only, &args.skip);
    let stdout = io::stdout();
    let color = output::resolve_color_mode(args.no_color, &stdout);
    let mut out = stdout.lock();
    output::write(&mut out, &findings, args.format, &raw, color)?;
    if args.context > 0 && matches!(args.format, Format::Text) {
        context::write_context_blocks(&mut out, &findings, &raw, args.context, color)?;
    }

    // Pre-compute the values we'll write to history, so the per-exit
    // branches below can call record_history(...) inline. Best-effort:
    // record_history swallows all errors.
    let critical_count = findings
        .iter()
        .filter(|f| CRITICAL_LABELS.contains(&f.label.as_str()))
        .count() as u32;

    use std::io::Write as _;
    if args.gate_critical {
        let hit = findings
            .iter()
            .any(|f| CRITICAL_LABELS.contains(&f.label.as_str()));
        if hit {
            let _ = out.flush();
            record_history(&args, findings.len() as u32, critical_count, 1);
            std::process::exit(1);
        }
    }
    if !args.gate.is_empty() {
        let _ = out.flush();
        let pass = crate::gate::evaluate(&findings, &args.gate)?;
        if !pass {
            record_history(&args, findings.len() as u32, critical_count, 1);
            std::process::exit(1);
        }
    }
    if let Some(baseline_path) = &args.baseline {
        let _ = out.flush();
        let drift = baseline::compare_to_baseline(&findings, baseline_path)?;
        if drift {
            record_history(&args, findings.len() as u32, critical_count, 1);
            std::process::exit(1);
        }
    }
    record_history(&args, findings.len() as u32, critical_count, 0);
    Ok(())
}

/// Append one history line for this scan. Best-effort — a locked file
/// / read-only mount / disabled-via-env case never bubbles up to the
/// caller (see `crate::history::append_entry`).
///
/// `pub(super)` so `api::run_api` can share the same shape.
pub(super) fn record_history(args: &Args, findings: u32, critical: u32, exit_code: i32) {
    // Skip cheaply if disabled — don't even canonicalize the path.
    if crate::history::is_disabled() {
        return;
    }
    // stdin scans don't have a meaningful path to record; use "-".
    let path = if args.file == "-" || args.stdin {
        "-".to_string()
    } else {
        // Absolute path so history entries are meaningful across cwd
        // changes. Fall back to the raw arg if canonicalize fails
        // (e.g. the file was deleted between scan + write).
        std::fs::canonicalize(&args.file)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| args.file.clone())
    };
    crate::history::append_entry(&crate::history::Entry {
        ts: crate::history::now_utc_rfc3339(),
        cmd: Some("scan".into()),
        path,
        format: format!("{:?}", args.format).to_lowercase(),
        findings,
        critical,
        exit_code,
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
    });
}

fn read_input(args: &Args) -> Result<String> {
    if args.stdin || args.file == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading log from stdin")?;
        return Ok(buf);
    }
    // Skip a pre-flight exists() check — that would misreport a
    // permission-denied file as "not found" (TOCTOU) and swallow
    // the real error. Let read_to_string surface the accurate
    // io::Error, then translate the common kinds into an actionable
    // hint instead of the bare libc-style "No such file or directory".
    let path = PathBuf::from(&args.file);
    std::fs::read_to_string(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => anyhow::anyhow!(
            "no such file: {}\n  Check the path, or pipe from stdin: bootintel scan - < path/to/log.txt",
            args.file
        ),
        std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
            "permission denied reading {}\n  Check file permissions (`ls -l {}`), or run with elevated privileges only if the file legitimately needs them.",
            args.file, args.file
        ),
        _ => {
            // Detect "is a directory" via raw_os_error since
            // ErrorKind::IsADirectory needs Rust 1.83 and our MSRV is
            // 1.80. EISDIR = 21 on Linux/macOS. Falls through to a
            // context-wrapped generic error on other kinds/platforms.
            #[cfg(unix)]
            if e.raw_os_error() == Some(21) {
                return anyhow::anyhow!(
                    "{} is a directory, not a file\n  bootintel scan expects a single boot log. Point at one .txt / .log file, or shell-loop the dir.",
                    args.file
                );
            }
            anyhow::Error::from(e).context(format!("reading {}", args.file))
        }
    })
}
