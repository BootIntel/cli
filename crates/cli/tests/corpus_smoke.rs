//! Workspace-level integration tests: run every detector against
//! every sample in the public corpus and assert that specific
//! high-signal detectors fire where expected.
//!
//! Skips gracefully if run outside the repo (e.g. someone
//! `cargo install`ed the CLI and is running tests against their
//! local checkout of just this crate). Guard: the samples path is
//! taken relative to CARGO_MANIFEST_DIR; if it doesn't exist, tests
//! print a note and no-op.

use std::path::PathBuf;

use bootintel_detectors::analyze;

fn samples_dir() -> Option<PathBuf> {
    // crates/cli → ../../samples (in-repo corpus)
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest.parent()?.parent()?.join("samples");
    if candidate.is_dir() {
        Some(candidate)
    } else {
        None
    }
}

fn read_sample(name: &str) -> Option<String> {
    let dir = samples_dir()?;
    let path = dir.join(name);
    std::fs::read_to_string(&path).ok()
}

fn expect_label(sample: &str, label: &str, expected_value_contains: &str) {
    let Some(log) = read_sample(sample) else {
        eprintln!("[skip] {sample} not in this checkout — test is a no-op");
        return;
    };
    let findings = analyze(&log);
    let f = findings
        .iter()
        .find(|f| f.label == label)
        .unwrap_or_else(|| {
            panic!(
                "{sample}: {label} detector did not fire. All findings: {:?}",
                findings
            )
        });
    assert!(
        f.value.contains(expected_value_contains),
        "{sample}: {label}: expected value to contain {expected_value_contains:?}, got {:?}",
        f.value
    );
}

// ── Golden fixtures: each sample has known-canonical findings ────────
// (Extended over time as new samples land in the corpus.)

#[test]
fn qualcomm_ipq8074_boot_hits_bootloader_kernel_and_arch() {
    // Note: Device family matches OpenWrt first (higher precedence in
    // the detector chain — the Qualcomm log has OpenWrt strings via
    // the ath11k firmware paths). Qualcomm-specific identification
    // is a server-side responsibility in the hybrid model.
    expect_label("bootintel-4.txt", "Bootloader", "U-Boot 2016.01");
    expect_label("bootintel-4.txt", "Kernel", "Linux 6.6.37");
    expect_label("bootintel-4.txt", "CPU / Arch", "ARM64");
    expect_label("bootintel-4.txt", "Device family", "OpenWrt");
}

#[test]
fn allwinner_h618_hits_bootloader_kernel_and_family() {
    // Kernel banner in this log doesn't include the literal `aarch64`
    // (Manjaro build tag stops at `MANJARO-ARM`), so the CPU/Arch
    // detector correctly returns nothing.
    expect_label("bootintel-16.txt", "Bootloader", "U-Boot");
    expect_label("bootintel-16.txt", "Kernel", "Linux");
    expect_label("bootintel-16.txt", "Init system", "systemd");
    expect_label("bootintel-16.txt", "Device family", "Allwinner sunxi");
}

#[test]
fn tp_link_archer_c2_hits_uboot_1_1_3() {
    expect_label("bootintel-12.txt", "Bootloader", "U-Boot 1.1.3");
}

#[test]
fn asus_rt_ac51u_hits_uboot_1_1_3() {
    expect_label("bootintel-25.txt", "Bootloader", "U-Boot 1.1.3");
    expect_label("bootintel-25.txt", "Device family", "OpenWrt");
}

#[test]
fn ti_am62a7_hits_uboot_and_arm64() {
    expect_label("bootintel-27.txt", "Bootloader", "U-Boot");
    expect_label("bootintel-27.txt", "CPU / Arch", "ARM64");
    expect_label("bootintel-27.txt", "Kernel", "Linux 6.1.46");
}

#[test]
fn riscv_vf2_hits_opensbi_and_riscv() {
    expect_label("bootintel-6.txt", "Bootloader", "U-Boot");
    // OpenSBI is the M-mode runtime; U-Boot proper is what shows up
    // last as the "Bootloader" finding (highest-precedence bootloader
    // regex hit). The RISC-V arch tag is what confirms the platform.
    expect_label("bootintel-6.txt", "CPU / Arch", "RISC-V");
}

#[test]
fn autoboot_interruptable_detection_on_flagged_samples() {
    // Only prompts with countdown >= 1 count as interruptable —
    // countdown=0 means the window has already closed and the
    // exposure detector correctly ignores it. Sample 5 has :3,
    // sample 4 has :2, sample 14 has :1.
    expect_label("bootintel-5.txt", "Autoboot interruptable", "Yes");
    expect_label("bootintel-4.txt", "Autoboot interruptable", "Yes");
    expect_label("bootintel-14.txt", "Autoboot interruptable", "Yes");
}

#[test]
fn autoboot_countdown_zero_not_flagged() {
    // Countdown=0 means the window closed. Not an exposure. Sample
    // 16 (OrangePi Zero3) hits this shape.
    let Some(log) = read_sample("bootintel-16.txt") else {
        eprintln!("[skip] bootintel-16.txt not in this checkout — test is a no-op");
        return;
    };
    let findings = analyze(&log);
    assert!(
        findings.iter().all(|f| f.label != "Autoboot interruptable"),
        "bootintel-16.txt has countdown=0 which should not flag as interruptable"
    );
}

// ── Regression guard: no accidental false positives on empty ─────────

#[test]
fn empty_log_produces_no_findings() {
    let findings = analyze("");
    assert!(findings.is_empty());
}

#[test]
fn nonsense_log_produces_no_findings() {
    let findings = analyze("random\ntext\nwith\nno\nboot\ncontent");
    assert!(findings.is_empty());
}
