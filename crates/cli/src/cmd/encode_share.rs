//! `bootintel encode-share <log>` — emit a shareable bootintel.com
//! fingerprint URL for a local log file. Same lz-string compression
//! the existing `share` subcommand uses; this variant is stdout-only
//! (no clipboard) so it composes cleanly in scripts.
//!
//! Round-trips with `bootintel decode-share <url>` which reverses the
//! encoding so CI can embed a log in a URL, hand it to another
//! system, and have that system recover the original bytes.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

const SHARE_BASE: &str = "https://bootintel.com/tools/fingerprint";

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Log file (or `-` for stdin).
    #[arg(value_name = "LOG")]
    log: PathBuf,

    /// Print only the compressed `z=` fragment, not the full URL.
    /// Handy for embedding in a script that builds its own URL.
    #[arg(long)]
    raw: bool,
}

pub fn run(args: Args) -> Result<()> {
    let text = read_input(&args.log)?;
    let compressed = lz_str::compress_to_encoded_uri_component(&text);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if args.raw {
        writeln!(out, "{compressed}")?;
    } else {
        writeln!(out, "{SHARE_BASE}?z={compressed}")?;
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
