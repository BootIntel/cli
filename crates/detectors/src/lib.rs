//! Client-side boot-log detectors for BootIntel.
//!
//! Mirrors the 14-detector browser detector library at
//! bootintel.com/tools/fingerprint. Kept pure (no I/O, no
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
    /// 1-based line number of `source` within the analyzed log.
    /// Populated by `analyze()`; `None` when the evidence could not be
    /// located (or when a `Finding` is constructed by hand, e.g. from
    /// an archived JSON envelope). Additive — existing consumers that
    /// don't know about it are unaffected.
    pub line_number: Option<usize>,
}

impl Finding {
    fn new(label: &str, value: impl Into<String>) -> Self {
        Self {
            label: label.to_string(),
            value: value.into(),
            detail: None,
            source: None,
            line_number: None,
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
///
/// # Line normalization
///
/// Several detectors are line-anchored (`(?m)^U-Boot`, `(?m)^GRUB`,
/// `(?m)^coreboot-`, `(?m)^procd:`). Real captures very often carry a
/// per-line prefix that defeats a bare `^`:
///
///   * `[12:34:56.789] ` — minicom / picocom / tio timestamping
///   * `[2026-09-23T10:00:00.000Z] ` — **our own** `--log-timestamps`
///   * `[    0.000000] ` — kernel printk timestamps
///   * `\x1b[32m` — ANSI colour from a colourising bootloader
///
/// Before `--log-timestamps` existed this was merely common; now the
/// tool's own capture mode breaks its own `scan`, which is why the
/// normalization lives here rather than being pushed onto callers.
///
/// So: split into lines, strip ANSI CSI sequences and any run of
/// leading bracketed timestamps, and run the detectors over the
/// normalized text. Evidence is then mapped back to the **original**
/// (unmodified) line, so `source` always shows the user what their
/// capture actually contained, prefix and all.
///
/// Ported from the browser `analyze()` so both implementations agree
/// on what a "line" is and what gets stripped.
///
/// Two exceptions, mirroring the browser: the policy observations
/// (`Telnet exposure`, `Autoboot interruptable`) run against the
/// **original** lines. Normalizing is a presentation choice for the
/// inventory detectors; a policy rule should see exactly what the
/// capture contained.
pub fn analyze(log: &str) -> Vec<Finding> {
    let original = split_lines(log);
    let normalized_owned: Vec<String> = original.iter().map(|l| normalize_line(l)).collect();
    let normalized: Vec<&str> = normalized_owned.iter().map(String::as_str).collect();
    let norm_log = normalized.join("\n");
    let orig_log = original.join("\n");
    ALL_DETECTORS
        .iter()
        .filter_map(|d| {
            let (joined, lines) = if ORIGINAL_INPUT_LABELS.contains(&d.label) {
                (&orig_log, &original)
            } else {
                (&norm_log, &normalized)
            };
            let finding = (d.run)(joined)?;
            Some(attach_evidence(d, finding, &original, lines))
        })
        .collect()
}

/// Detectors that read the user's original lines instead of the
/// normalized ones. Same two labels the browser exempts.
const ORIGINAL_INPUT_LABELS: &[&str] = &["Telnet exposure", "Autoboot interruptable"];

/// Split on any of CRLF / LF / CR. `str::lines()` only handles LF and
/// CRLF; a bare-CR stream (some bootloaders emit CR-only line endings)
/// would otherwise arrive as one giant line and defeat every
/// line-anchored detector.
fn split_lines(log: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = log.as_bytes();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                out.push(&log[start..i]);
                i += 1;
                start = i;
            }
            b'\r' => {
                out.push(&log[start..i]);
                // CRLF counts as one terminator.
                i += if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                    2
                } else {
                    1
                };
                start = i;
            }
            _ => i += 1,
        }
    }
    out.push(&log[start..]);
    out
}

/// ANSI CSI escape sequence: ESC `[` params intermediates final.
/// Same character classes as the Node analyzer's
/// `/\x1b\[[0-?]*[ -/]*[@-~]/g`.
static RE_ANSI_CSI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]").unwrap());

/// One leading bracketed timestamp. Three accepted shapes, matching
/// the Node analyzer:
///   * `[12:34:56]` / `[12:34:56.789]`     — wall-clock terminal logger
///   * `[2026-09-23T10:00:00.000Z]`        — ISO-8601 (our --log-timestamps)
///   * `[    0.000000]`                    — kernel printk seconds
static RE_LEADING_TS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*\[(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\s*\d+\.\d+)\]\s*",
    )
    .unwrap()
});

/// Strip ANSI CSI sequences and leading bracketed timestamps from one
/// line. The timestamp strip loops: `bootintel analyze --log-timestamps`
/// over a Linux console produces *two* stacked prefixes
/// (`[2026-…Z] [    0.000000] Linux version …`), and the Node
/// analyzer's single-shot strip would leave the second one in place.
fn normalize_line(line: &str) -> String {
    let mut s = RE_ANSI_CSI.replace_all(line, "").into_owned();
    // Bounded loop — a pathological line of nothing but bracketed
    // timestamps must not spin forever.
    for _ in 0..8 {
        match RE_LEADING_TS.find(&s) {
            Some(m) if m.end() > 0 => {
                s = s[m.end()..].to_string();
            }
            _ => break,
        }
    }
    s
}

/// Point a finding's `source` at the original, unmodified line that
/// produced it, and record that line's 1-based number.
///
/// `source` and `line_number` are **derived**, never set by the
/// detector: the detector is re-run against each line on its own and
/// the first line that reproduces the same `value` + `detail` is the
/// originating evidence. Byte-for-byte the browser's algorithm, which
/// matters for two reasons:
///
///   * a detector that set its own `source` from a whole-log match
///     could point at text that is not on any single line, breaking
///     the "source is the original line" contract the CSV/JSON
///     consumers rely on;
///   * an **aggregate** detector (`Flash layout`, whose `value` counts
///     partitions across many lines) cannot be reproduced from one
///     line, so no line matches and the finding correctly ends up with
///     no `source` / `line_number` — the evidence is the whole table.
///
/// When no line reproduces the finding, whatever `source` the detector
/// itself recorded is left in place (also the browser's behavior: it
/// spreads the located evidence over the finding only when found).
fn attach_evidence(d: &Detector, mut f: Finding, original: &[&str], lines: &[&str]) -> Finding {
    if let Some(i) = lines
        .iter()
        .position(|line| (d.run)(line).is_some_and(|c| c.value == f.value && c.detail == f.detail))
    {
        f.source = Some(original[i].to_string());
        f.line_number = Some(i + 1);
    }
    f
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
        label: "Runtime firmware",
        run: run_runtime_firmware,
    },
    Detector {
        label: "ROM identifier",
        run: run_rom_identifier,
    },
    Detector {
        label: "Firmware SDK",
        run: run_firmware_sdk,
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
        label: "Userland",
        run: run_userland,
    },
    Detector {
        label: "Flash layout",
        run: run_flash_layout,
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

// ── 2. Runtime firmware ──────────────────────────────────────────────
//
// OpenSBI is the RISC-V M-mode runtime that hands off to U-Boot, not a
// bootloader — a RISC-V board reports both, and folding OpenSBI into
// `Bootloader` (as this crate used to) both mislabeled it and hid
// whichever of the two lost the precedence race.

static RE_OPENSBI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*OpenSBI\s+v?(\d+(?:\.\d+)+(?:[-+][A-Za-z0-9_.+\-]+)?)").unwrap()
});

fn run_runtime_firmware(log: &str) -> Option<Finding> {
    let m = RE_OPENSBI.captures(log)?;
    let ver = m.get(1)?.as_str();
    Some(Finding::new("Runtime firmware", format!("OpenSBI {ver}")))
}

// ── 3. ROM identifier ────────────────────────────────────────────────
//
// The mask-ROM build stamp an ESP prints before anything else
// (`ESP-ROM:esp32s3-20210327`). It identifies the silicon revision's
// ROM image, which is what a ROM-level exploit is written against —
// separate from the `Bootloader` finding the same log also produces.

static RE_ESP_ROM_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*ESP-ROM:([A-Za-z0-9._+\-]+)").unwrap());

fn run_rom_identifier(log: &str) -> Option<Finding> {
    let m = RE_ESP_ROM_ID.captures(log)?;
    let id = m.get(1)?.as_str();
    Some(Finding::new(
        "ROM identifier",
        format!("Espressif ROM {id}"),
    ))
}

// ── 4. Firmware SDK ──────────────────────────────────────────────────
//
// ESP-IDF version out of the 2nd-stage bootloader banner. The SDK
// version is the CVE-relevant identifier on an ESP target — the ROM
// stamp above rarely moves, the SDK does.

static RE_ESP_IDF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bboot: ESP-IDF\s+([A-Za-z0-9._+\-]+)\s+2nd stage bootloader\b").unwrap()
});

fn run_firmware_sdk(log: &str) -> Option<Finding> {
    let m = RE_ESP_IDF.captures(log)?;
    let ver = m.get(1)?.as_str();
    Some(Finding::new("Firmware SDK", format!("ESP-IDF {ver}")))
}

// ── 5. Kernel ────────────────────────────────────────────────────────

// The build-metadata parentheses are optional: plenty of vendor kernels
// print `Linux version 3.0.15-ts-armv7l` and stop. `[ \t]` rather than
// `\s` so the match cannot run past the end of the banner line.
static RE_LINUX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Linux version[ \t]+(\S+)(?:[ \t]+\([^\r\n)]+\)[ \t]+\(([^\r\n)]+)\))?").unwrap()
});
static RE_DARWIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Darwin Kernel Version\s+([^:]+):").unwrap());
static RE_FREERTOS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)FreeRTOS\s+(?:Kernel\s+)?V?([\d.]+)").unwrap());
static RE_ZEPHYR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\*\*\*\s+Booting Zephyr OS build\s+([\w.\-]+)").unwrap());

fn run_kernel(log: &str) -> Option<Finding> {
    if let Some(m) = RE_LINUX.captures(log) {
        let ver = m.get(1)?.as_str();
        let source_full = m.get(0)?.as_str();
        // Match the browser slicing: detail truncated at 80, source at 200.
        let source: String = source_full.chars().take(200).collect();
        let mut f = Finding::new("Kernel", format!("Linux {ver}")).source(source);
        if let Some(toolchain) = m.get(2) {
            f = f.detail(toolchain.as_str().chars().take(80).collect::<String>());
        }
        return Some(f);
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

// ── 6. CPU / Arch ────────────────────────────────────────────────────

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
// Only the literal architecture name. `esp32` / `esp8266` are a device
// family, not a CPU, and are reported as such by `Device family` —
// matching them here made the CLI claim an arch the browser did not.
static RE_XTENSA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bxtensa\b").unwrap());

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

// ── 7. Userland ──────────────────────────────────────────────────────
//
// BusyBox prints its version on 7 of the 31 public corpus captures and
// this crate reported it zero times, so the offline story was missing
// the most common userland component in the category.

static RE_BUSYBOX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)BusyBox\s+v?(\d[\d.]*)").unwrap());

fn run_userland(log: &str) -> Option<Finding> {
    let m = RE_BUSYBOX.captures(log)?;
    let ver = m.get(1)?.as_str();
    Some(Finding::new("Userland", format!("BusyBox {ver}")))
}

// ── 8. Flash layout ──────────────────────────────────────────────────
//
// The partition map is what a flash-clip read needs, and it appears in
// roughly half the corpus. Offsets come straight from the kernel's own
// MTD registration lines.
//
// The one **aggregate** detector: it folds many lines into a single
// finding whose `value` counts partitions, so no single line reproduces
// it and `attach_evidence` leaves it without a `source` / `line_number`.

static RE_MTD_PART: LazyLock<Regex> = LazyLock::new(|| {
    // Character class spelled out rather than `\w` so it means the same
    // set as the browser's `[\w/.-]` (ASCII) instead of Rust's
    // Unicode-aware `\w`.
    Regex::new(r#"(?i)0x0*([0-9a-f]+)-0x0*([0-9a-f]+)\s*:\s*"([A-Za-z0-9_/.\-]+)""#).unwrap()
});

fn run_flash_layout(log: &str) -> Option<Finding> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut named: Vec<String> = Vec::new();
    for m in RE_MTD_PART.captures_iter(log) {
        let (Some(start), Some(end), Some(name)) = (m.get(1), m.get(2), m.get(3)) else {
            continue;
        };
        // A capture can print the partition table more than once (a
        // reset loop, or two flash devices registering). Key on the
        // exact offsets so the same region is listed once rather than
        // inflating the count — bootintel-9.txt reports 14 partitions
        // without this for a device that has 7.
        if !seen.insert(format!(
            "{}-{}-{}",
            start.as_str(),
            end.as_str(),
            name.as_str()
        )) {
            continue;
        }
        let size = hex_to_f64(end.as_str()) - hex_to_f64(start.as_str());
        named.push(format!("{} ({})", name.as_str(), human_size(size)));
    }
    if named.is_empty() {
        return None;
    }
    let plural = if named.len() == 1 { "" } else { "s" };
    Some(
        Finding::new("Flash layout", format!("{} partition{plural}", named.len()))
            .detail(named.join(", ")),
    )
}

/// `parseInt(hex, 16)` in f64, so a hostile line with a 40-digit offset
/// widens to infinity the way the browser does instead of overflowing.
fn hex_to_f64(hex: &str) -> f64 {
    hex.chars().fold(0.0, |acc, c| {
        acc * 16.0 + f64::from(c.to_digit(16).unwrap_or(0))
    })
}

/// Render a partition size the way the browser does: whole kibibytes,
/// or mebibytes with one decimal place when it isn't a whole MiB.
///
/// The decimal is computed in integer tenths rather than with `{:.1}`
/// because the two languages break ties differently: JavaScript's
/// `toFixed` rounds a tie away from zero (1.25 → "1.3") while Rust's
/// formatter rounds to even (1.25 → "1.2"). Partition tables hit exact
/// ties routinely — any whole 1.25 MiB region does it, e.g. the 1280 KiB
/// `kernel` partition in sample bootintel-12.txt — so the naive version
/// diverges from the browser on real corpus logs.
fn human_size(size: f64) -> String {
    let kb = (size / 1024.0).round();
    // `-0.0` would print as "-0"; the browser prints "0".
    let kb = if kb == 0.0 { 0.0 } else { kb };
    if kb < 1024.0 {
        return format!("{kb}K");
    }
    let whole = kb as i128;
    if whole % 1024 == 0 {
        return format!("{}M", whole / 1024);
    }
    // round((kb / 1024) * 10) with ties away from zero, in integers.
    // Falls back to the formatter only for absurd offsets (a hostile
    // 40-hex-digit line) where the integer math would overflow.
    match whole
        .checked_mul(20)
        .and_then(|v| v.checked_add(1024))
        .map(|v| v / 2048)
    {
        Some(tenths) => format!("{}.{}M", tenths / 10, tenths % 10),
        None => format!("{:.1}M", kb / 1024.0),
    }
}

// ── 9. Init system ───────────────────────────────────────────────────

static RE_PROCD_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^procd:").unwrap());
static RE_PROCD_INIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"procd:\s+-\s+init").unwrap());
static RE_SYSTEMD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)systemd\[1\]:").unwrap());
static RE_SYSV: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)INIT:\s+version\s+([\d.]+)").unwrap());
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
    if RE_RUNIT.is_match(log) {
        return Some(Finding::new("Init system", "runit"));
    }
    None
}

// ── 10. Device family ─────────────────────────────────────────────────

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

// ── 11. Network ───────────────────────────────────────────────────────

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

// ── 12. Web admin ─────────────────────────────────────────────────────

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

// ── 13. Telnet exposure ───────────────────────────────────────────────

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

// ── 14. Autoboot interruptable ────────────────────────────────────────

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
