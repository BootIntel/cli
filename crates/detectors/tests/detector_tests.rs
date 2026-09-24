//! Per-detector unit tests. Each entry in `bootintel_detectors::analyze`
//! must have at least one positive test (a log fragment that matches)
//! and at least one negative test (a fragment that doesn't).
//!
//! Test fixtures live inline as `&str` literals rather than in files
//! so the tests are self-contained and don't drift from the code.
//! Real-corpus fixtures are exercised in the workspace-level
//! `tests/corpus_smoke.rs` (uses the samples in `samples/`).

use bootintel_detectors::{analyze, Finding, SAMPLE};

fn find(log: &str, label: &str) -> Option<Finding> {
    analyze(log).into_iter().find(|f| f.label == label)
}

// ── SAMPLE (baseline: MIPS OpenWrt on TP-Link Archer C7 v5) ──────────

#[test]
fn sample_matches_expected_8_labels() {
    // SAMPLE trips 8 detectors — Telnet is the only critical detector
    // not in the fixture (it's negative-tested in
    // telnet_absent_on_clean_log). If this count changes, either SAMPLE
    // was edited or a detector regressed.
    let findings = analyze(SAMPLE);
    let labels: Vec<&str> = findings.iter().map(|f| f.label.as_str()).collect();
    assert_eq!(
        labels,
        vec![
            "Bootloader",
            "Kernel",
            "CPU / Arch",
            "Init system",
            "Device family",
            "Network",
            "Web admin",
            "Autoboot interruptable",
        ],
        "SAMPLE should trip exactly these 8 detectors (Telnet is not in SAMPLE)"
    );
}

#[test]
fn sample_bootloader_is_uboot_2020_10() {
    let f = find(SAMPLE, "Bootloader").expect("SAMPLE must trip Bootloader");
    assert_eq!(f.value, "U-Boot 2020.10");
    assert!(f.source.as_ref().unwrap().contains("U-Boot 2020.10"));
}

// ── 1. Bootloader ────────────────────────────────────────────────────

#[test]
fn bootloader_uboot() {
    let log = "U-Boot 2016.01 (Jul 25 2022 - 17:08:05 +0800)\n";
    let f = find(log, "Bootloader").unwrap();
    assert_eq!(f.value, "U-Boot 2016.01");
    assert_eq!(f.detail.unwrap(), "Jul 25 2022 - 17:08:05 +0800");
}

#[test]
fn bootloader_coreboot() {
    let log = "coreboot-4.15\nBooting…\n";
    let f = find(log, "Bootloader").unwrap();
    assert_eq!(f.value, "coreboot 4.15");
}

#[test]
fn bootloader_opensbi() {
    let log = "OpenSBI v1.4\nBoot HART ID              : 1\n";
    let f = find(log, "Bootloader").unwrap();
    assert_eq!(f.value, "OpenSBI 1.4");
}

#[test]
fn bootloader_esp_rom() {
    let log = "rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)\n";
    let f = find(log, "Bootloader").unwrap();
    assert_eq!(f.value, "Espressif ROM bootloader");
    assert_eq!(f.detail.unwrap(), "ESP8266/ESP32");
}

#[test]
fn bootloader_none_on_gibberish() {
    let log = "some random log content with no bootloader banner\n";
    assert!(find(log, "Bootloader").is_none());
}

// ── 2. Kernel ────────────────────────────────────────────────────────

#[test]
fn kernel_linux() {
    let log = "[    0.000000] Linux version 5.15.137 (builder@host) (gcc-11.2.0) #0 SMP Tue Nov 14 19:23:42 2023\n";
    let f = find(log, "Kernel").unwrap();
    assert_eq!(f.value, "Linux 5.15.137");
    assert!(f.detail.unwrap().starts_with("gcc-11.2.0"));
}

#[test]
fn kernel_freertos() {
    let log = "FreeRTOS Kernel V10.4.3 starting on core 0\n";
    let f = find(log, "Kernel").unwrap();
    assert_eq!(f.value, "FreeRTOS 10.4.3");
}

#[test]
fn kernel_zephyr() {
    let log = "*** Booting Zephyr OS build v3.5.0-2547-g1234567 ***\n";
    let f = find(log, "Kernel").unwrap();
    assert_eq!(f.value, "Zephyr v3.5.0-2547-g1234567");
}

// ── 3. CPU / Arch ────────────────────────────────────────────────────

#[test]
fn cpu_mips() {
    let log = "CPU0 revision is: 00019374 (MIPS 74Kc)\n";
    let f = find(log, "CPU / Arch").unwrap();
    assert_eq!(f.value, "MIPS 74Kc");
}

#[test]
fn cpu_arm64() {
    let log = "Booting Linux on physical CPU 0x0000000000 aarch64\n";
    let f = find(log, "CPU / Arch").unwrap();
    assert_eq!(f.value, "ARM64 (aarch64)");
}

#[test]
fn cpu_riscv_from_hart() {
    let log = "hart 1: running\n";
    let f = find(log, "CPU / Arch").unwrap();
    assert_eq!(f.value, "RISC-V");
}

// ── 4. Init system ───────────────────────────────────────────────────

#[test]
fn init_procd() {
    let log = "[    3.789012] procd: - init -\n";
    let f = find(log, "Init system").unwrap();
    assert_eq!(f.value, "procd");
    assert_eq!(f.detail.unwrap(), "OpenWrt-family");
}

#[test]
fn init_systemd() {
    let log = "systemd[1]: Starting some.service\n";
    let f = find(log, "Init system").unwrap();
    assert_eq!(f.value, "systemd");
}

#[test]
fn init_busybox() {
    let log = "BusyBox v1.35.0 (2022-03-01) built-in shell (ash)\n";
    let f = find(log, "Init system").unwrap();
    assert_eq!(f.value, "BusyBox init");
}

// ── 5. Device family ─────────────────────────────────────────────────

#[test]
fn family_openwrt() {
    let log = "OpenWrt 22.03.5, r20134-5f15225c1e (2023-01-01)\n";
    let f = find(log, "Device family").unwrap();
    assert_eq!(f.value, "OpenWrt");
}

#[test]
fn family_raspberry_pi() {
    let log = "bcm2711 Raspberry Pi 4 Model B Rev 1.4\n";
    let f = find(log, "Device family").unwrap();
    assert_eq!(f.value, "Raspberry Pi family");
}

#[test]
fn family_qualcomm() {
    let log = "IPQ8074 SoC init\n";
    let f = find(log, "Device family").unwrap();
    assert_eq!(f.value, "Qualcomm IPQ");
}

// ── 6. Network ───────────────────────────────────────────────────────

#[test]
fn network_dhcp() {
    let log = "[    5.012345] DHCP client bound to address 192.168.1.42\n";
    let f = find(log, "Network").unwrap();
    assert_eq!(f.value, "DHCP client active");
    assert_eq!(f.detail.unwrap(), "Lease: 192.168.1.42");
}

#[test]
fn network_dnsmasq() {
    let log = "[    4.456789] dnsmasq[1236]: started, version 2.86 cachesize 150\n";
    let f = find(log, "Network").unwrap();
    assert_eq!(f.value, "dnsmasq 2.86 active");
}

// ── 7. Web admin ─────────────────────────────────────────────────────

#[test]
fn web_uhttpd() {
    let log = "[    4.345678] uhttpd[1235]: Listening on 0.0.0.0:80 0.0.0.0:443\n";
    let f = find(log, "Web admin").unwrap();
    assert_eq!(f.value, "uhttpd active");
    assert!(f.detail.unwrap().starts_with("Listen: 0.0.0.0:80"));
}

#[test]
fn web_nginx() {
    let log = "Server: nginx/1.20.1\n";
    let f = find(log, "Web admin").unwrap();
    assert_eq!(f.value, "nginx 1.20.1");
}

// ── 8. Telnet exposure ───────────────────────────────────────────────

#[test]
fn telnet_started() {
    let log = "telnetd[123]: listening on port 23\n";
    let f = find(log, "Telnet exposure").unwrap();
    assert_eq!(f.value, "Telnet service started");
    assert_eq!(f.detail.unwrap(), "Clear-text, review immediately");
}

#[test]
fn telnet_absent_on_clean_log() {
    let log = "just some kernel messages\nDHCP client bound to address 10.0.0.1\n";
    assert!(find(log, "Telnet exposure").is_none());
}

// ── 9. Autoboot interruptable ────────────────────────────────────────

#[test]
fn autoboot_3_second_countdown() {
    let log = "Hit any key to stop autoboot:  3\n";
    let f = find(log, "Autoboot interruptable").unwrap();
    assert_eq!(f.value, "Yes");
    assert!(f.source.unwrap().contains("Hit any key"));
}

#[test]
fn autoboot_0_second_not_flagged() {
    // Countdown reached zero — not interruptable in the exposure sense.
    let log = "Hit any key to stop autoboot:  0\n";
    assert!(find(log, "Autoboot interruptable").is_none());
}

// ── Labels stability check ──────────────────────────────────────────

#[test]
fn detector_labels_stable() {
    // Guards against renames or reorderings that would break the
    // TS/Rust sync-check script.
    let labels = bootintel_detectors::detector_labels();
    assert_eq!(
        labels,
        vec![
            "Bootloader",
            "Kernel",
            "CPU / Arch",
            "Init system",
            "Device family",
            "Network",
            "Web admin",
            "Telnet exposure",
            "Autoboot interruptable",
        ]
    );
}

// ── Line-prefix normalization (regression) ───────────────────────────
//
// The line-anchored detectors (`(?m)^U-Boot`, `(?m)^coreboot-`,
// `(?m)^GRUB`, `(?m)^procd:`) used to be defeated by anything at all in
// front of the anchor. A plain `U-Boot 2020.10` line was detected; the
// same line behind a terminal timestamp, an ISO-8601 timestamp, or an
// ANSI colour escape produced NO findings and exit 0, while the Kernel,
// CPU and Autoboot detectors — which are not anchored — handled all
// four.
//
// The ISO-8601 case is self-inflicted: `bootintel analyze
// --log-timestamps` prefixes every line with exactly that, so the
// tool's own capture mode broke its own `scan`.
//
// One fixture per prefix shape, all four asserted to produce the same
// finding as the bare line.

/// The bare line every prefixed variant below must still match.
const UBOOT_LINE: &str = "U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)";

fn uboot_value(log: &str) -> Option<String> {
    find(log, "Bootloader").map(|f| f.value)
}

#[test]
fn bootloader_matches_bare_line() {
    assert_eq!(uboot_value(UBOOT_LINE).as_deref(), Some("U-Boot 2020.10"));
}

#[test]
fn bootloader_survives_bracketed_clock_prefix() {
    let log = format!("[12:34:56.789] {UBOOT_LINE}");
    assert_eq!(uboot_value(&log).as_deref(), Some("U-Boot 2020.10"));
}

#[test]
fn bootloader_survives_iso8601_prefix() {
    // Exactly what `bootintel analyze --log-timestamps` writes.
    let log = format!("[2026-09-23T10:00:00.000Z] {UBOOT_LINE}");
    assert_eq!(uboot_value(&log).as_deref(), Some("U-Boot 2020.10"));
}

#[test]
fn bootloader_survives_ansi_colour_prefix() {
    let log = format!("\x1b[32m{UBOOT_LINE}\x1b[0m");
    assert_eq!(uboot_value(&log).as_deref(), Some("U-Boot 2020.10"));
}

#[test]
fn bootloader_survives_kernel_printk_prefix() {
    let log = format!("[    0.000000] {UBOOT_LINE}");
    assert_eq!(uboot_value(&log).as_deref(), Some("U-Boot 2020.10"));
}

#[test]
fn bootloader_survives_stacked_prefixes() {
    // `--log-timestamps` over a Linux console stacks two prefixes.
    let log = format!("[2026-09-23T10:00:00.000Z] [    0.000000] {UBOOT_LINE}");
    assert_eq!(uboot_value(&log).as_deref(), Some("U-Boot 2020.10"));
}

#[test]
fn bootloader_survives_ansi_and_timestamp_together() {
    let log = format!("\x1b[1;33m[12:34:56] \x1b[0m{UBOOT_LINE}");
    assert_eq!(uboot_value(&log).as_deref(), Some("U-Boot 2020.10"));
}

#[test]
fn evidence_keeps_the_original_prefixed_line() {
    // Normalization is for matching only. What we show back to the
    // user must be what their capture actually contained, otherwise
    // they cannot find it again in the log.
    let log = format!("noise\n[2026-09-23T10:00:00.000Z] {UBOOT_LINE}\nmore noise");
    let f = find(&log, "Bootloader").expect("Bootloader should fire");
    assert_eq!(
        f.source.as_deref(),
        Some(format!("[2026-09-23T10:00:00.000Z] {UBOOT_LINE}").as_str())
    );
    assert_eq!(f.line_number, Some(2), "line number must be 1-based");
}

#[test]
fn coreboot_and_grub_anchors_also_normalized() {
    let coreboot = find("[12:34:56] coreboot-4.19 Tue Jan 1", "Bootloader");
    assert_eq!(coreboot.map(|f| f.value).as_deref(), Some("coreboot 4.19"));

    let grub = find("[2026-09-23T10:00:00.000Z] GRUB version 2.06", "Bootloader");
    assert_eq!(grub.map(|f| f.value).as_deref(), Some("GRUB 2.06"));
}

#[test]
fn init_system_anchor_also_normalized() {
    // `(?m)^procd:` is anchored too.
    let f = find("[    3.123456] procd: - early -", "Init system");
    assert!(
        f.is_some(),
        "procd should be detected behind a printk prefix"
    );
}

#[test]
fn unanchored_detectors_are_unaffected_by_normalization() {
    // Regression guard the other way: the detectors that already
    // handled prefixes must keep working, and must not start matching
    // things they shouldn't because of the stripping.
    let log = "[    0.000000] Linux version 5.15.137 (builder@buildhost) (gcc 11.2.0) #0 SMP";
    assert!(find(log, "Kernel").is_some());
}

#[test]
fn a_bracketed_non_timestamp_is_not_stripped() {
    // Only timestamp-shaped brackets come off. A line that genuinely
    // begins with some other bracketed tag keeps it, so evidence and
    // matching stay honest.
    let log = "[vendor-tag] U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)";
    assert!(
        uboot_value(log).is_none(),
        "a non-timestamp bracket must not be stripped by the timestamp rule"
    );
}

#[test]
fn bare_cr_line_endings_are_split() {
    // Some bootloaders emit CR-only line endings. `str::lines()` does
    // not split on those, which would leave the whole capture as one
    // line and defeat every anchored detector.
    let log = format!("boot start\r{UBOOT_LINE}\rdone");
    assert_eq!(uboot_value(&log).as_deref(), Some("U-Boot 2020.10"));
}
