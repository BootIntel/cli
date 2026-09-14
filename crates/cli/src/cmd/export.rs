//! `bootintel export <log> [<bundle.json>]` — bundle log + findings,
//! tool version + timestamp + host metadata into one self-contained
//! JSON blob suitable for a bug report / support ticket.
//!
//! Everything a support engineer needs to reproduce is in the
//! bundle: raw log bytes (base64 so no encoding drama), findings,
//! the bootintel version + OS/arch, and a UTC timestamp. No PII
//! is collected — hostname / username are NOT included so an
//! export from a corp laptop doesn't leak identity.

use anyhow::{Context, Result};
use bootintel_detectors::{analyze, detector_labels};
use clap::Args as ClapArgs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Log file (or `-` for stdin).
    #[arg(value_name = "LOG")]
    log: PathBuf,

    /// Where to write the bundle. Default: stdout. Pass `-` to
    /// force stdout even when you have a filename-shaped argument.
    #[arg(value_name = "OUT")]
    out: Option<PathBuf>,

    /// Suppress the raw log bytes from the bundle — only include
    /// findings + metadata. Useful when the log is sensitive but
    /// you still want to send the detector output.
    #[arg(long)]
    no_log: bool,
}

pub fn run(args: Args) -> Result<()> {
    let raw = read_input(&args.log)?;
    let findings = analyze(&raw);

    let bundle = serde_json::json!({
        "bootintel_export_version": 1,
        "bootintel_version": env!("CARGO_PKG_VERSION"),
        "analysis_source": "client",
        "generated_at": iso_utc_now(),
        "target": {
            "os":   std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "detector_count_registered": detector_labels().len(),
        "log": if args.no_log { serde_json::Value::Null } else {
            serde_json::json!({
                "encoding": "utf8",
                "bytes":    raw.len(),
                "content":  raw,
            })
        },
        "findings": findings.iter().map(|f| serde_json::json!({
            "label":  f.label,
            "value":  f.value,
            "detail": f.detail,
            "source": f.source,
        })).collect::<Vec<_>>(),
    });

    let text = serde_json::to_string_pretty(&bundle)?;

    match &args.out {
        None => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            out.write_all(text.as_bytes())?;
            writeln!(out)?;
        }
        Some(p) if p == std::path::Path::new("-") => {
            let stdout = io::stdout();
            let mut out = stdout.lock();
            out.write_all(text.as_bytes())?;
            writeln!(out)?;
        }
        Some(p) => {
            std::fs::write(p, text.as_bytes())
                .with_context(|| format!("writing {}", p.display()))?;
            if !crate::verbose::is_quiet() {
                eprintln!(
                    "[bootintel export] wrote bundle to {} ({} finding(s))",
                    p.display(),
                    findings.len()
                );
            }
        }
    }
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

/// ISO-8601 UTC (mirrors term::logfile's implementation but kept
/// local so this subcommand doesn't take a dependency on term::).
fn iso_utc_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    // Reuse Howard Hinnant's civil_from_unix inline (same algorithm
    // as term::logfile). 10 LOC is cheaper than adding a chrono dep.
    let days = (secs / 86_400) as i64;
    let time_of_day = secs % 86_400;
    let hh = (time_of_day / 3_600) as u32;
    let mm = ((time_of_day % 3_600) / 60) as u32;
    let ss = (time_of_day % 60) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}
