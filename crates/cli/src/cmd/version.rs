//! `bootintel version` — version + build metadata.

use anyhow::Result;
use clap::Args as ClapArgs;

use bootintel_detectors::detector_labels;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Machine-readable JSON output. For CI / packaging scripts
    /// that need to parse the version + feature set.
    #[arg(long)]
    json: bool,
}

pub fn run(args: Args) -> Result<()> {
    let labels = detector_labels();
    // Build feature list. `mut` is silenced for the `--no-default-features`
    // build where neither `clipboard` nor `tui` are enabled — otherwise
    // `mut v` is never actually mutated and `-D warnings` fails CI.
    #[allow(clippy::vec_init_then_push, unused_mut)]
    let features: Vec<&str> = {
        let mut v: Vec<&str> = Vec::new();
        #[cfg(feature = "clipboard")]
        v.push("clipboard");
        #[cfg(feature = "tui")]
        v.push("tui");
        v
    };

    if args.json {
        let body = serde_json::json!({
            "bootintel_version": env!("CARGO_PKG_VERSION"),
            "target": {
                "os":   std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            },
            "features":  features,
            "detectors": {
                "count":  labels.len(),
                "labels": labels,
            },
            "homepage": "https://bootintel.com",
            "license":  "Apache-2.0",
        });
        println!("{}", serde_json::to_string_pretty(&body)?);
        return Ok(());
    }

    println!("bootintel {}", env!("CARGO_PKG_VERSION"));
    println!(
        "  client-side detectors: {} ({})",
        labels.len(),
        labels.join(", ")
    );
    // Include arch so a Rosetta / QEMU / x86_64-binary-on-aarch64-host
    // mismatch is visible at a glance.
    println!(
        "  target: {}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    // Feature flags baked into this build. Users can `--tui` only when
    // the tui feature was compiled in; --api works either way.
    if features.is_empty() {
        println!("  features: (none)");
    } else {
        println!("  features: {}", features.join(", "));
    }
    println!("  homepage: https://bootintel.com");
    println!("  license: Apache-2.0");
    Ok(())
}
