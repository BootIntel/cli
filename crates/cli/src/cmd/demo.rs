//! `bootintel demo` — run scan on the built-in SAMPLE log so a new
//! user (or an eval / talk audience) can see what the tool does
//! without hunting for a real boot log.
//!
//! SAMPLE lives in `bootintel_detectors::SAMPLE` — a MIPS OpenWrt
//! Archer C7 boot log that fires 5+ detectors including the two
//! critical ones (Autoboot interruptable, Telnet exposure), so the
//! demo output actually shows the interesting cases.

use anyhow::Result;
use bootintel_detectors::{analyze, SAMPLE};
use clap::Args as ClapArgs;
use std::io::{self, Write};

use crate::output::{self, Format};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Output format. Defaults to text (colourful when TTY, clean
    /// when piped). Same options as `scan`.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Print the SAMPLE log itself before the findings. Useful for
    /// screencasts where the audience should see the raw input.
    #[arg(long)]
    show_log: bool,

    /// Suppress ANSI colour.
    #[arg(long)]
    no_color: bool,
}

pub fn run(args: Args) -> Result<()> {
    let findings = analyze(SAMPLE);
    let stdout = io::stdout();
    let color = crate::output::resolve_color_mode(args.no_color, &stdout);

    let mut out = stdout.lock();
    if args.show_log {
        writeln!(out, "── SAMPLE boot log ({} bytes) ──", SAMPLE.len())?;
        writeln!(out, "{SAMPLE}")?;
        writeln!(out, "── findings ──")?;
    }
    // The built-in sample has no on-disk path; name it as such
    // so SARIF from `demo` never claims a real repository file.
    output::write(
        &mut out,
        &findings,
        args.format,
        SAMPLE,
        color,
        "bootintel-sample-log",
    )?;
    if !args.show_log && matches!(args.format, Format::Text) && !crate::verbose::is_quiet() {
        writeln!(out)?;
        writeln!(
            out,
            "  (this was `bootintel demo` — the SAMPLE log is a MIPS OpenWrt Archer C7 capture)"
        )?;
        writeln!(
            out,
            "  next: run against a log of your own — `bootintel scan path/to/log.txt`"
        )?;
    }
    let _ = out.flush();
    Ok(())
}
