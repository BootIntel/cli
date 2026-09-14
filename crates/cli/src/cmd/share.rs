//! `bootintel share <file>` — print a shareable bootintel.com URL.
//!
//! Mirrors the browser tool's Share affordance. Uses lz-string
//! `compressToEncodedURIComponent` so the URL is decompressible by
//! the JS side and vice-versa. Zero server round-trip: the URL
//! carries the compressed log itself.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::io::{self, Read};
use std::path::PathBuf;

// Match the browser share-report caps:
//   * MAX_INPUT_BYTES_FOR_SHARE = 200_000 — cap the input so a
//     pathological log doesn't blow up the URL.
const MAX_INPUT_BYTES: usize = 200_000;
const BASE_URL: &str = "https://bootintel.com";

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to a boot log file, or `-` for stdin.
    #[arg(value_name = "FILE")]
    file: String,

    /// Emit only the URL, no wrapping text (for scripting).
    #[arg(long)]
    quiet: bool,
}

pub fn run(args: Args) -> Result<()> {
    let raw = read_input(&args.file)?;
    let (trimmed, truncated) = if raw.len() > MAX_INPUT_BYTES {
        // Slice at a valid char boundary — logs are ASCII in practice
        // but we're defensive against pathological inputs.
        let mut end = MAX_INPUT_BYTES;
        while !raw.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        (&raw[..end], true)
    } else {
        (raw.as_str(), false)
    };

    let compressed = lz_str::compress_to_encoded_uri_component(trimmed);
    let url = format!("{BASE_URL}/tools/fingerprint?z={compressed}");

    if args.quiet {
        println!("{url}");
    } else {
        println!("{url}");
        eprintln!();
        eprintln!("  compressed bytes: {}", compressed.len());
        if truncated {
            eprintln!(
                "  note: input was longer than {} bytes; truncated before share-encoding.",
                MAX_INPUT_BYTES
            );
        }
        eprintln!("  the log itself is in the URL — nothing was uploaded.");
    }
    Ok(())
}

fn read_input(file: &str) -> Result<String> {
    if file == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("reading log from stdin")?;
        return Ok(buf);
    }
    // Let read_to_string surface the accurate io::Error (permission-
    // denied vs not-found) instead of a pre-flight exists() check
    // that would misreport permission errors as "not found".
    let path = PathBuf::from(file);
    std::fs::read_to_string(&path).with_context(|| format!("reading {file}"))
}
