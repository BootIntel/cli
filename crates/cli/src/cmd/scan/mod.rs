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

use anyhow::Result;
use clap::Args as ClapArgs;
use std::io;
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

/// Exit code for input that could not be inspected at all: an empty
/// file, an empty pipe, whitespace only. **Never 0** — a CI job whose
/// UART never came up, whose adapter fell out, or whose artifact path
/// was wrong must not report green. See `EXIT_UNRECOGNIZED`.
pub(super) const EXIT_EMPTY_INPUT: i32 = 2;

/// Exit code for input that had content but matched no detector.
/// Distinct from 2 so a caller can tell "nothing to look at" from
/// "looked, recognized nothing" — the second usually means the capture
/// started too late, or the baud was wrong and the bytes are garbage.
pub(super) const EXIT_UNRECOGNIZED: i32 = 3;

pub fn run(args: Args) -> Result<()> {
    let log = read_input(&args)?;
    log.report_replacements();
    let raw = log.text;

    // An empty capture is not a passing scan.
    //
    // Previously `scan --gate-critical` on a 0-byte file printed an
    // empty finding list and exited 0, so every CI gate downstream went
    // green on a capture that never happened. The legacy Node analyzer
    // has always exited 2 here, and its README warns in as many words
    // never to treat an empty capture as a successful gate. Checked
    // before the --api branch as well: there is no point posting
    // nothing to the server either.
    if raw.trim().is_empty() {
        eprintln!(
            "bootintel: empty capture; no inspection performed ({})\n  \
             Nothing was analyzed, so this is not a passing scan.\n  \
             Check that the serial capture actually ran, that the adapter is still \
             attached, and that the path is the one your capture step wrote.",
            log.source_label
        );
        record_history(&args, 0, 0, EXIT_EMPTY_INPUT);
        std::process::exit(EXIT_EMPTY_INPUT);
    }

    if args.api {
        return api::run_api(&args, &raw);
    }

    let findings = crate::detector_filter::filter(analyze(&raw), &args.only, &args.skip);
    let stdout = io::stdout();
    let color = output::resolve_color_mode(args.no_color, &stdout);
    let mut out = stdout.lock();
    output::write(
        &mut out,
        &findings,
        args.format,
        &raw,
        color,
        &log.source_label,
    )?;
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

    // Non-empty input, but no detector recognized anything. Same
    // reasoning as the empty case: report it rather than calling it a
    // clean bill of health. Ordered ahead of the gate checks to match
    // the Node analyzer's ladder; with zero findings neither
    // --gate-critical nor a positive --gate assertion can fire anyway.
    if findings.is_empty() {
        let _ = out.flush();
        eprintln!(
            "bootintel: no recognized evidence in {}; this is not a successful inspection\n  \
             The capture has content but matched none of the {} detectors. Common causes: \
             the capture started after the boot banner scrolled past, or the baud rate \
             was wrong and the bytes are noise.",
            log.source_label,
            bootintel_detectors::detector_labels().len()
        );
        record_history(&args, 0, 0, EXIT_UNRECOGNIZED);
        std::process::exit(EXIT_UNRECOGNIZED);
    }

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

/// How to name this scan's input in output that has to identify it
/// (SARIF's `artifactLocation`, the empty/unrecognized messages).
/// `stdin` for a pipe, the path as the user typed it otherwise.
pub(super) fn source_label(args: &Args) -> String {
    if args.stdin || args.file == "-" {
        "stdin".to_string()
    } else {
        args.file.clone()
    }
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

fn read_input(args: &Args) -> Result<crate::input::LoadedLog> {
    if args.stdin || args.file == "-" {
        return crate::input::read_stdin();
    }
    // Skip a pre-flight exists() check — that would misreport a
    // permission-denied file as "not found" (TOCTOU) and swallow
    // the real error. Let read_to_string surface the accurate
    // io::Error, then translate the common kinds into an actionable
    // hint instead of the bare libc-style "No such file or directory".
    let path = PathBuf::from(&args.file);
    // Bytes, not `read_to_string`: a UART capture is frequently not
    // valid UTF-8 and rejecting it outright loses a perfectly
    // analyzable log. See `crate::input`.
    crate::input::read_file(&path).map_err(|e| match e.kind() {
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
