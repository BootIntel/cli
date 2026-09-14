//! Client-side boot-log detectors for BootIntel.
//!
//! Mirrors the 9-detector streaming subset of the browser detector
//! library at bootintel.com/tools/fingerprint. Kept pure (no I/O, no
//! async, no serde) so this crate can be reused in other contexts —
//! a future WASM build for the browser tool, a plugin for third-party
//! firmware-analysis tooling, etc.
//!
//! Sync discipline: each detector below is a one-for-one port of a
//! browser detector entry. When adding, removing, or renaming a
//! detector, keep both sources aligned.
//!
//! Regex flavor: only features supported by both JavaScript regex
//! and Rust `regex` are used (no lookaround, no backreferences). If
//! a future detector needs lookaround, pull in `fancy-regex` for
//! just that detector — do not switch the whole library.

use regex::Regex;
use std::sync::LazyLock;

/// A single detector's output.
///
/// Matches the browser tool's `Finding` type field-for-field so JSON
/// output can be diffed against the browser tool's output byte-for-byte
/// on the same input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub label: String,
    pub value: String,
    pub detail: Option<String>,
    pub source: Option<String>,
}

impl Finding {
    fn new(label: &str, value: impl Into<String>) -> Self {
        Self {
            label: label.to_string(),
            value: value.into(),
            detail: None,
            source: None,
        }
    }
    fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
    fn source(mut self, s: impl Into<String>) -> Self {
        self.source = Some(s.into());
        self
    }
}

/// Analyze a boot log against every detector; return findings in
/// detector-registration order. Detectors that don't match are
/// silently dropped.
pub fn analyze(log: &str) -> Vec<Finding> {
    ALL_DETECTORS.iter().filter_map(|d| (d.run)(log)).collect()
}

/// Return the labels of every registered detector, in order. Used by
/// the sync-check script + `bootintel version`.
pub fn detector_labels() -> Vec<&'static str> {
    ALL_DETECTORS.iter().map(|d| d.label).collect()
}

/// A canned MIPS OpenWrt boot log used by tests and by `--sample`
/// on the CLI. Byte-for-byte identical to the SAMPLE constant in the
/// browser detector library so browser + CLI output can be diffed
/// against each other.
pub const SAMPLE: &str = "U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)
Model: TP-Link Archer C7 v5
DRAM:  128 MiB
NAND:  ONFI device found
Hit any key to stop autoboot:  3
[    0.000000] Linux version 5.15.137 (builder@buildhost) (mips-openwrt-linux-musl-gcc (OpenWrt GCC 11.2.0 r19685-512e76967f), GNU ld (GNU Binutils) 2.37) #0 SMP Tue Nov 14 19:23:42 2023
[    0.000000] CPU0 revision is: 00019374 (MIPS 74Kc)
[    0.000000] Determined physical RAM map:
[    0.000000]  memory: 08000000 @ 00000000 (usable)
[    1.234567] mtd: device 0 (boot)
[    2.456789] eth0: PHY found at 0x00 (Atheros AR8327)
[    3.123456] procd: - early -
[    3.789012] procd: - init -
[    4.012345] hotplug2: Bootup detected
[    4.234567] dropbear[1234]: Not backgrounding
[    4.345678] uhttpd[1235]: Listening on 0.0.0.0:80 0.0.0.0:443
[    4.456789] dnsmasq[1236]: started, version 2.86 cachesize 150
[    5.012345] DHCP client bound to address 192.168.1.42";

/// Labels that mark a finding as a **critical exposure** — surfaced
/// in scan text output, batch rollups, HTML/SARIF/JUnit rendering,
/// `--gate-critical`, and the TUI's critical highlight. Kept as one
/// list here so scan + batch + output + tui + analyze all agree on
/// what "critical" means without drifting.
pub const CRITICAL_LABELS: &[&str] = &["Autoboot interruptable", "Telnet exposure"];

// ── Detector registry ────────────────────────────────────────────────
//
// Each entry mirrors a browser detector object. Preserve order + labels
// so JSON output stays comparable between browser + CLI.

struct Detector {
    label: &'static str,
    run: fn(&str) -> Option<Finding>,
}

static ALL_DETECTORS: &[Detector] = &[
    Detector {
        label: "Bootloader",
        run: run_bootloader,
    },
    Detector {
        label: "Kernel",
        run: run_kernel,
    },
    Detector {
        label: "CPU / Arch",
        run: run_cpu_arch,
    },
    Detector {
        label: "Init system",
        run: run_init_system,
    },
    Detector {
        label: "Device family",
        run: run_device_family,
    },
    Detector {
        label: "Network",
        run: run_network,
    },
    Detector {
        label: "Web admin",
        run: run_web_admin,
    },
    Detector {
        label: "Telnet exposure",
        run: run_telnet_exposure,
    },
    Detector {
        label: "Autoboot interruptable",
        run: run_autoboot_interruptable,
    },
];

// ── 1. Bootloader ────────────────────────────────────────────────────

// U-Boot line pattern. Multiline `(?m)` so `^` matches the start of
// any line, not just the whole log. Captures the version + build tag.
static RE_UBOOT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^U-Boot\s+(\S+(?:[-+][\w.+\-]+)?)\s+\(([^)]+)\)").unwrap());
static RE_COREBOOT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^coreboot-([\w.\-]+)").unwrap());
static RE_GRUB: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^GRUB\s+(?:version\s+)?([\d.]+)").unwrap());
static RE_OPENSBI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)OpenSBI\s+v?([\d.]+)").unwrap());
static RE_ESP_ROM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(rst:0x1\s+\(POWERON_RESET\)|esp_image:|chip is)").unwrap());

fn run_bootloader(log: &str) -> Option<Finding> {
    if let Some(m) = RE_UBOOT.captures(log) {
        let ver = m.get(1)?.as_str();
        let build = m.get(2)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(
            Finding::new("Bootloader", format!("U-Boot {ver}"))
                .detail(build)
                .source(source),
        );
    }
    if let Some(m) = RE_COREBOOT.captures(log) {
        let ver = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Bootloader", format!("coreboot {ver}")).source(source));
    }
    if let Some(m) = RE_GRUB.captures(log) {
        let ver = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Bootloader", format!("GRUB {ver}")).source(source));
    }
    if let Some(m) = RE_OPENSBI.captures(log) {
        let ver = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Bootloader", format!("OpenSBI {ver}")).source(source));
    }
    if let Some(m) = RE_ESP_ROM.captures(log) {
        let source = m.get(0)?.as_str();
        return Some(
            Finding::new("Bootloader", "Espressif ROM bootloader")
                .detail("ESP8266/ESP32")
                .source(source),
        );
    }
    None
}

// ── 2. Kernel ────────────────────────────────────────────────────────

static RE_LINUX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Linux version\s+(\S+)\s+\([^)]+\)\s+\(([^)]+)\)").unwrap());
static RE_DARWIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Darwin Kernel Version\s+([^:]+):").unwrap());
static RE_FREERTOS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)FreeRTOS\s+(?:Kernel\s+)?V?([\d.]+)").unwrap());
static RE_ZEPHYR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\*\*\*\s+Booting Zephyr OS build\s+([\w.\-]+)").unwrap());

fn run_kernel(log: &str) -> Option<Finding> {
    if let Some(m) = RE_LINUX.captures(log) {
        let ver = m.get(1)?.as_str();
        let toolchain = m.get(2)?.as_str();
        let source_full = m.get(0)?.as_str();
        // Match the TS slicing: detail truncated at 80, source at 200.
        let detail: String = toolchain.chars().take(80).collect();
        let source: String = source_full.chars().take(200).collect();
        return Some(
            Finding::new("Kernel", format!("Linux {ver}"))
                .detail(detail)
                .source(source),
        );
    }
    if let Some(m) = RE_DARWIN.captures(log) {
        let ver = m.get(1)?.as_str().trim();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Kernel", format!("Darwin {ver}")).source(source));
    }
    if let Some(m) = RE_FREERTOS.captures(log) {
        let ver = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Kernel", format!("FreeRTOS {ver}")).source(source));
    }
    if let Some(m) = RE_ZEPHYR.captures(log) {
        let ver = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Kernel", format!("Zephyr {ver}")).source(source));
    }
    None
}

// ── 3. CPU / Arch ────────────────────────────────────────────────────

static RE_MIPS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)CPU\s*\d?\s+revision is:\s+\w+\s+\((MIPS\s+[\w\-]+)\)").unwrap()
});
static RE_ARM64: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)Booting Linux on physical CPU.*aarch64|Linux version.*aarch64").unwrap()
});
static RE_ARMV7: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)CPU:\s+ARMv7|Linux version.*\barmv7l\b").unwrap());
static RE_RISCV: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Linux version.*riscv|hart\s+\d+:\s+running").unwrap());
static RE_X86: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Linux version.*x86_64").unwrap());
static RE_XTENSA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(xtensa|esp32|esp8266)").unwrap());

fn run_cpu_arch(log: &str) -> Option<Finding> {
    if let Some(m) = RE_MIPS.captures(log) {
        return Some(Finding::new("CPU / Arch", m.get(1)?.as_str().to_string()));
    }
    if RE_ARM64.is_match(log) {
        return Some(Finding::new("CPU / Arch", "ARM64 (aarch64)"));
    }
    if RE_ARMV7.is_match(log) {
        return Some(Finding::new("CPU / Arch", "ARMv7 (32-bit)"));
    }
    if RE_RISCV.is_match(log) {
        return Some(Finding::new("CPU / Arch", "RISC-V"));
    }
    if RE_X86.is_match(log) {
        return Some(Finding::new("CPU / Arch", "x86_64"));
    }
    if RE_XTENSA.is_match(log) {
        return Some(Finding::new("CPU / Arch", "Xtensa (ESP)"));
    }
    None
}

// ── 4. Init system ───────────────────────────────────────────────────

static RE_PROCD_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^procd:").unwrap());
static RE_PROCD_INIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"procd:\s+-\s+init").unwrap());
static RE_SYSTEMD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)systemd\[1\]:|Welcome to \w+ Linux").unwrap());
static RE_SYSV: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)INIT:\s+version\s+([\d.]+)").unwrap());
static RE_BUSYBOX_INIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"BusyBox v[\d.]+\s+\([^)]+\)\s+built-in shell").unwrap());
static RE_RUNIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"runit:|runit-init").unwrap());

fn run_init_system(log: &str) -> Option<Finding> {
    if RE_PROCD_START.is_match(log) || RE_PROCD_INIT.is_match(log) {
        return Some(Finding::new("Init system", "procd").detail("OpenWrt-family"));
    }
    if RE_SYSTEMD.is_match(log) {
        return Some(Finding::new("Init system", "systemd"));
    }
    if let Some(m) = RE_SYSV.captures(log) {
        let ver = m.get(1)?.as_str();
        return Some(Finding::new("Init system", format!("SysV init {ver}")));
    }
    if RE_BUSYBOX_INIT.is_match(log) {
        return Some(Finding::new("Init system", "BusyBox init"));
    }
    if RE_RUNIT.is_match(log) {
        return Some(Finding::new("Init system", "runit"));
    }
    None
}

// ── 5. Device family ─────────────────────────────────────────────────

static RE_OPENWRT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)openwrt").unwrap());
static RE_OPENWRT_GCC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)OpenWrt GCC[^)]*\d{4}-\w+").unwrap());
static RE_OPENWRT_R: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)OpenWrt\s+(r\d+[\-\w]+)").unwrap());
static RE_RPI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Raspberry\s*Pi|bcm27\d{2}|bcm28\d{2}").unwrap());
static RE_BUILDROOT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)buildroot|br-\d{4}").unwrap());
static RE_YOCTO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)yocto|poky-\w+").unwrap());
static RE_ESP_FAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(esp32|esp8266|esp_image)").unwrap());
static RE_MEDIATEK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Mediatek|MT76\d{2}|MT79\d{2}").unwrap());
static RE_QUALCOMM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Qualcomm|IPQ\d{4}").unwrap());
static RE_ALLWINNER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(Allwinner|sunxi|H\d{1,3}\s+SoC)").unwrap());

fn run_device_family(log: &str) -> Option<Finding> {
    if RE_OPENWRT.is_match(log) {
        // Prefer the GCC-tag line, fall back to the release marker.
        let detail = RE_OPENWRT_GCC
            .find(log)
            .or_else(|| RE_OPENWRT_R.find(log))
            .map(|m| m.as_str().chars().take(80).collect::<String>());
        let mut f = Finding::new("Device family", "OpenWrt");
        if let Some(d) = detail {
            f = f.detail(d);
        }
        return Some(f);
    }
    if RE_RPI.is_match(log) {
        return Some(Finding::new("Device family", "Raspberry Pi family"));
    }
    if RE_BUILDROOT.is_match(log) {
        return Some(Finding::new("Device family", "Buildroot"));
    }
    if RE_YOCTO.is_match(log) {
        return Some(Finding::new("Device family", "Yocto / Poky"));
    }
    if RE_ESP_FAM.is_match(log) {
        return Some(Finding::new("Device family", "Espressif (ESP)"));
    }
    if RE_MEDIATEK.is_match(log) {
        return Some(Finding::new("Device family", "MediaTek SoC"));
    }
    if RE_QUALCOMM.is_match(log) {
        return Some(Finding::new("Device family", "Qualcomm IPQ"));
    }
    if RE_ALLWINNER.is_match(log) {
        return Some(Finding::new("Device family", "Allwinner sunxi"));
    }
    None
}

// ── 6. Network ───────────────────────────────────────────────────────

static RE_DHCP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)DHCP\s+(?:client\s+)?bound to address\s+([\d.]+)").unwrap());
static RE_DNSMASQ: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)dnsmasq\[\d+\]:\s+started,\s+version\s+([\d.]+)").unwrap());
static RE_DROPBEAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)dropbear\[\d+\]").unwrap());

fn run_network(log: &str) -> Option<Finding> {
    if let Some(m) = RE_DHCP.captures(log) {
        let ip = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(
            Finding::new("Network", "DHCP client active")
                .detail(format!("Lease: {ip}"))
                .source(source),
        );
    }
    if let Some(m) = RE_DNSMASQ.captures(log) {
        let ver = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Network", format!("dnsmasq {ver} active")).source(source));
    }
    if let Some(m) = RE_DROPBEAR.find(log) {
        return Some(Finding::new("Network", "Dropbear SSH started").source(m.as_str()));
    }
    None
}

// ── 7. Web admin ─────────────────────────────────────────────────────

static RE_UHTTPD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)uhttpd\[\d+\]:\s+Listening on\s+([\d.:]+)").unwrap());
static RE_LIGHTTPD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)lighttpd/([\d.]+)").unwrap());
static RE_NGINX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)nginx/([\d.]+)").unwrap());

fn run_web_admin(log: &str) -> Option<Finding> {
    if let Some(m) = RE_UHTTPD.captures(log) {
        let listen = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(
            Finding::new("Web admin", "uhttpd active")
                .detail(format!("Listen: {listen}"))
                .source(source),
        );
    }
    if let Some(m) = RE_LIGHTTPD.captures(log) {
        let ver = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Web admin", format!("lighttpd {ver}")).source(source));
    }
    if let Some(m) = RE_NGINX.captures(log) {
        let ver = m.get(1)?.as_str();
        let source = m.get(0)?.as_str();
        return Some(Finding::new("Web admin", format!("nginx {ver}")).source(source));
    }
    None
}

// ── 8. Telnet exposure ───────────────────────────────────────────────

static RE_TELNET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)telnetd?\[\d+\]?[^\n]*?(?:listening|started|on\s+\d)").unwrap()
});

fn run_telnet_exposure(log: &str) -> Option<Finding> {
    if let Some(m) = RE_TELNET.find(log) {
        return Some(
            Finding::new("Telnet exposure", "Telnet service started")
                .detail("Clear-text, review immediately")
                .source(m.as_str()),
        );
    }
    None
}

// ── 9. Autoboot interruptable ────────────────────────────────────────

static RE_AUTOBOOT_ANY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Hit any key to stop autoboot:\s*[1-9]").unwrap());
static RE_AUTOBOOT_CAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Hit any key to stop autoboot:\s*\d+").unwrap());

fn run_autoboot_interruptable(log: &str) -> Option<Finding> {
    if RE_AUTOBOOT_ANY.is_match(log) {
        // Second regex is broader (matches 0 too) so we can capture the
        // actual matched source line — matches the TS behavior which
        // does the same two-step.
        if let Some(m) = RE_AUTOBOOT_CAP.find(log) {
            return Some(
                Finding::new("Autoboot interruptable", "Yes")
                    .detail("U-Boot will accept any key during the countdown")
                    .source(m.as_str()),
            );
        }
    }
    None
}
