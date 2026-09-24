//! `scan --api` — server-side path. POSTs the log to bootintel.com
//! (or the configured `--api-base`) for CVE matching + exploit paths
//! + AI summary. Falls back to `--api --preview` for anonymous,
//!   rate-limited free use.
//!
//! Split from mod.rs so the auth flow, error taxonomy, and
//! sysexits-mapping are testable in isolation from the offline path.

use anyhow::{bail, Result};
use bootintel_detectors::{analyze, CRITICAL_LABELS};
use std::io::{self, Write};

use crate::api::client::{ScanClient, ScanError};
use crate::api::render::{write_json_response, write_text_response};
use crate::output::{self, Format};

use super::{record_history, Args, API_KEY_ENV};

pub(super) fn run_api(args: &Args, raw: &str) -> Result<()> {
    // Precedence for both api_base + api_key: CLI flag > env > config
    // file > built-in default. See `crate::config::resolve_api_base`
    // + `resolve_api_key` for the canonical impl.
    let base = crate::config::resolve_api_base(args.api_base.as_deref());
    let api_key = crate::config::resolve_api_key();

    if !args.preview && api_key.is_none() {
        bail!(
            "--api requires ${API_KEY_ENV} to be set (or use --api --preview for the free anonymous quota — 3/day per IP).\n  Get a key at https://bootintel.com/settings/api-keys"
        );
    }
    if args.preview && api_key.is_some() {
        // Not fatal, just wasteful — using the anon endpoint while
        // holding a real key means you're not getting the full
        // analysis your subscription is paying for.
        eprintln!(
            "warning: --preview ignores ${API_KEY_ENV} and uses the anonymous quota. Drop --preview to run the full authenticated scan."
        );
    }

    // Plaintext-transport guard — centralized in api::endpoints so
    // scan/analyze/whoami share one policy. `sending_credential` gates
    // the bail-vs-warn branch.
    let sending_credential = !args.preview && api_key.is_some();
    crate::api::endpoints::require_safe_transport(&base, sending_credential)?;

    let client = ScanClient::new(&base);
    let device = args.device_name.as_deref();
    // Server-side scan can take ~5-15s (CVE match + AI summary).
    // Spinner drops silently when stderr isn't a TTY so CI logs stay
    // clean. Dropped after the call returns; RAII clears the line.
    let _sp = crate::spinner::Spinner::start(if args.preview {
        "bootintel: scanning (preview)…"
    } else {
        "bootintel: scanning…"
    });
    let result = if args.preview {
        client.preview_scan(raw, device)
    } else {
        // Safe: unwrap()-guarded by the bail! above.
        client.authed_scan(raw, device, api_key.as_deref().unwrap())
    };
    drop(_sp);

    let resp = match result {
        Ok(r) => r,
        Err(err) => return render_api_error(err, args.preview),
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    match args.format {
        Format::Json => write_json_response(&mut out, &resp)?,
        Format::Text => write_text_response(&mut out, &resp)?,
        // SARIF + JUnit consumers are typically CI systems that
        // already dispatch on the identification-only client-side
        // schema. Rather than invent a new server-side SARIF shape,
        // fall back to running the detector library on the same log
        // and emit the client format. The API call still happened
        // (so the server-side event log fires) — the human just
        // gets the CI-friendly format.
        Format::Sarif | Format::Junit | Format::Csv | Format::Html | Format::Md => {
            // Same --only/--skip applies when we fall through to the
            // client-side detectors for CI-friendly formats.
            let findings = crate::detector_filter::filter(analyze(raw), &args.only, &args.skip);
            // SARIF/JUnit/CSV/HTML are always machine-readable —
            // never colour. Server-side has no schema for these
            // formats, so we fall back to client-side detectors
            // (the API call still fires, so the server-side event
            // log still records the request — the human just gets
            // the CI-friendly bytes).
            output::write(
                &mut out,
                &findings,
                args.format,
                raw,
                output::ColorMode::Off,
                &super::source_label(args),
            )?;
        }
    }

    // gate-critical honors the server's findings on --api. Match on
    // the finding's severity when the server sets it, otherwise fall
    // back to matching the title against CRITICAL_LABELS (which are
    // labels emitted by the client-side detector library).
    let critical_count = resp
        .findings
        .iter()
        .filter(|f| {
            f.severity
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("critical"))
                || f.title
                    .as_deref()
                    .is_some_and(|t| CRITICAL_LABELS.contains(&t))
        })
        .count() as u32;

    if args.gate_critical && critical_count > 0 {
        let _ = out.flush();
        record_history(args, resp.findings.len() as u32, critical_count, 1);
        std::process::exit(1);
    }
    record_history(args, resp.findings.len() as u32, critical_count, 0);
    Ok(())
}

/// Human-friendly renderer for API failures. Each variant gets
/// a specific message + non-zero exit. Never a silent fallback
/// to client-side output.
pub(super) fn render_api_error(err: ScanError, preview: bool) -> Result<()> {
    let stderr = io::stderr();
    let mut e = stderr.lock();
    match &err {
        ScanError::RateLimited {
            detail,
            retry_after_seconds,
        } => {
            writeln!(e, "bootintel: server-side quota reached.")?;
            if let Some(d) = detail {
                writeln!(e, "  {d}")?;
            }
            if let Some(s) = retry_after_seconds {
                // Clamp the header value to sane bounds so a
                // misconfigured server can't tell us to wait 400,000
                // years. Cap display at 24h; anything larger becomes
                // "tomorrow-ish".
                let secs = (*s).min(24 * 60 * 60);
                let mins = secs.div_ceil(60);
                if secs >= 24 * 60 * 60 {
                    writeln!(e, "  Quota resets within the next 24 hours.")?;
                } else if mins >= 60 {
                    let hrs = mins / 60;
                    writeln!(e, "  Quota resets in ~{hrs} hour(s).")?;
                } else {
                    writeln!(e, "  Quota resets in ~{mins} minute(s).")?;
                }
            }
            writeln!(e)?;
            if preview {
                writeln!(
                    e,
                    "  The anonymous preview quota is 3 scans per IP per day."
                )?;
                writeln!(e, "  For unlimited scans, create an account and set")?;
                writeln!(e, "  {API_KEY_ENV} to your API key.")?;
            } else {
                writeln!(e, "  Your account's daily quota is exhausted.")?;
                writeln!(e, "  Higher-tier plans include larger daily budgets.")?;
            }
            writeln!(e, "  See https://bootintel.com/pricing")?;
        }
        ScanError::Unauthorized { detail } => {
            writeln!(e, "bootintel: authentication failed.")?;
            if let Some(d) = detail {
                writeln!(e, "  {d}")?;
            }
            writeln!(e)?;
            writeln!(e, "  Check that {API_KEY_ENV} is set to a valid key.")?;
            writeln!(e, "  Manage keys: https://bootintel.com/settings/api-keys")?;
        }
        ScanError::BadRequest { detail } => {
            writeln!(e, "bootintel: server rejected the request.")?;
            if let Some(d) = detail {
                writeln!(e, "  {d}")?;
            }
        }
        ScanError::ServerError { status, detail } => {
            writeln!(e, "bootintel: server error (HTTP {status}).")?;
            if let Some(d) = detail {
                writeln!(e, "  {d}")?;
            }
            writeln!(e, "  Please try again in a moment.")?;
        }
        ScanError::Network(msg) => {
            writeln!(e, "bootintel: could not reach the server.")?;
            writeln!(e, "  {msg}")?;
            writeln!(e)?;
            writeln!(e, "  Client-side scan still works offline:")?;
            writeln!(e, "    bootintel scan <log>    # no --api")?;
        }
        ScanError::Malformed {
            status,
            snippet,
            error,
        } => {
            writeln!(
                e,
                "bootintel: server returned HTTP {status} but the body was not parseable JSON."
            )?;
            writeln!(e, "  parse error: {error}")?;
            writeln!(e, "  first 200 bytes: {snippet}")?;
            writeln!(e)?;
            writeln!(e, "  This is a bug — please file at")?;
            writeln!(
                e,
                "  https://github.com/bootintel/cli/issues with the snippet + parse error above."
            )?;
        }
        ScanError::Other { status, detail } => {
            writeln!(e, "bootintel: unexpected HTTP {status}.")?;
            if let Some(d) = detail {
                writeln!(e, "  {d}")?;
            }
            writeln!(e)?;
            writeln!(
                e,
                "  Not a status the CLI recognises. If this reproduces, please file at"
            )?;
            writeln!(
                e,
                "  https://github.com/bootintel/cli/issues with the status + detail above."
            )?;
        }
    }
    // Non-zero exit — see design doc §14 Q8.
    std::process::exit(exit_code_for(&err));
}

pub(super) fn exit_code_for(err: &ScanError) -> i32 {
    // Sysexits-style codes. Not a standard, but conventional
    // enough that scripts can dispatch on them.
    match err {
        ScanError::RateLimited { .. } => 75,  // EX_TEMPFAIL
        ScanError::Unauthorized { .. } => 77, // EX_NOPERM
        ScanError::BadRequest { .. } => 65,   // EX_DATAERR
        ScanError::ServerError { .. } => 76,  // EX_PROTOCOL
        ScanError::Network(_) => 69,          // EX_UNAVAILABLE
        ScanError::Malformed { .. } => 76,    // EX_PROTOCOL
        ScanError::Other { .. } => 1,
    }
}
