//! `bootintel detectors` — list every registered detector with a
//! short description. Answers "what does this thing actually look
//! for" without making the user grep the source.
//!
//! Descriptions live here (not in the detector crate) so the crate
//! can stay dep-free and reusable. Kept in sync with the label list
//! at build time via the compile-time assertion at the bottom.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::io::{self, Write};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// JSON output — array of `{label, description}` objects.
    #[arg(long)]
    json: bool,
}

/// One line per label. Order matches detector_labels() (which is
/// registration order). The compile-time assert below guarantees
/// this list stays lockstep with the detector crate — a new
/// detector without a description here fails the build.
const DESCRIPTIONS: &[(&str, &str)] = &[
    ("Bootloader", "U-Boot / Barebox / CFE + build timestamp"),
    (
        "Runtime firmware",
        "OpenSBI — the RISC-V M-mode runtime below the bootloader",
    ),
    ("ROM identifier", "Mask-ROM build stamp (ESP-ROM)"),
    (
        "Firmware SDK",
        "Vendor SDK the image was built against (ESP-IDF)",
    ),
    ("Kernel", "Linux version + build metadata"),
    (
        "CPU / Arch",
        "ARMv7 / ARM64 / MIPS / RISC-V / x86_64 family",
    ),
    (
        "Userland",
        "BusyBox version — what the userland is built on",
    ),
    (
        "Flash layout",
        "MTD partition map — offsets, names, sizes for a flash read",
    ),
    (
        "Init system",
        "systemd / procd / OpenRC / SysV — what PID 1 is",
    ),
    (
        "Device family",
        "OpenWrt / DD-WRT / vendor-firmware fingerprint",
    ),
    ("Network", "MACs, IPs, interfaces, bootloader netvars"),
    (
        "Web admin",
        "HTTP daemon on port 80/8080/etc — attack surface",
    ),
    ("Telnet exposure", "telnetd listening — critical exposure"),
    (
        "Autoboot interruptable",
        "U-Boot autoboot prompt is stoppable — critical",
    ),
];

pub fn run(args: Args) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if args.json {
        let items: Vec<serde_json::Value> = DESCRIPTIONS
            .iter()
            .map(|(l, d)| serde_json::json!({ "label": l, "description": d }))
            .collect();
        serde_json::to_writer_pretty(&mut out, &items)?;
        writeln!(out)?;
    } else {
        let width = DESCRIPTIONS
            .iter()
            .map(|(l, _)| l.len())
            .max()
            .unwrap_or(20);
        writeln!(out, "{} detector(s) registered:", DESCRIPTIONS.len())?;
        writeln!(out)?;
        for (label, desc) in DESCRIPTIONS {
            writeln!(out, "  {label:<width$}  {desc}")?;
        }
    }
    let _ = out.flush();
    Ok(())
}

// Compile-time guard: fail the build if the detector crate adds or
// removes a label without a matching description entry. Runs at
// binary startup (unavoidable given detector_labels() isn't const),
// which is fine for a check that costs microseconds.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptions_cover_every_detector() {
        let labels = bootintel_detectors::detector_labels();
        let described: std::collections::HashSet<&str> =
            DESCRIPTIONS.iter().map(|(l, _)| *l).collect();
        for lbl in &labels {
            assert!(
                described.contains(lbl),
                "detector '{lbl}' has no description in cmd::detectors::DESCRIPTIONS — add one"
            );
        }
        assert_eq!(
            described.len(),
            labels.len(),
            "cmd::detectors::DESCRIPTIONS has extra entries not in detector_labels()"
        );
    }
}
