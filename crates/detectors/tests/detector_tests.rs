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
