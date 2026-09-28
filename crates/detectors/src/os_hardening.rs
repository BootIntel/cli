//! Kernel hardening posture, read from what the kernel announced at boot.
//!
//! A port of `api/analysis_engine/detectors/os_hardening.py`, kept in step by
//! the shared expectation in `tests/fixtures/boot_chain/expect.txt`.
//!
//! The boot log states plainly which protections are active: mandatory access
//! control, memory initialisation, kernel address randomisation. A practitioner
//! reads `mem auto-init: stack:off, heap alloc:off, heap free:off` and knows
//! immediately that a whole class of uninitialised-memory bugs stays exploitable
//! on this device; `grep` hands that back one line at a time with no indication
//! which of the three mattered.
//!
//! # The trap this module is built around
//!
//! `selinux=0` means opposite things depending on the line it sits on:
//!
//! ```text
//! cmdline: console=ttyS3 ... selinux=0 scandelay root=/2   (bootintel-1)
//! Unknown command line parameters: ... selinux=0           (bootintel-6)
//! ```
//!
//! The first is SELinux switched off. The second is the kernel reporting it did
//! not recognise the parameter, which means SELinux is not compiled in at all: a
//! different and worse fact. Reporting the second as "disabled by boot
//! parameter" would describe a device that does not exist while understating the
//! real finding, so the unknown-parameter line is parsed first and anything
//! listed there is treated as not applied.
//!
//! # What this does not do
//!
//! It records facts and raises no findings, because the Rust and browser
//! detector sets are pinned to the same 14 labels and a fifteenth would break
//! that parity. The engine raises the findings; both sides share the facts.
//!
//! Absence is never evidence: a capture that never mentions KASLR is not a
//! capture proving it off, and nothing here reports it as such.

use std::sync::LazyLock;

use regex::Regex;

// Character-for-character from the engine module, for the same reason as the
// boot-chain patterns: reasoning about whether two hand-written tokenisers agree
// is more expensive than keeping them identical.
//
// Unanchored on purpose. The same kernel line arrives with a `[    0.000000]`
// prefix on one device and a `Feb 25 13:51:14 host kernel:` syslog prefix on
// three others; anchoring it silently misses those.
static RE_MEM_AUTO_INIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)mem auto-init:\s*stack:(\S+?),\s*heap alloc:(\S+?),\s*heap free:(\S+?)\s*$")
        .unwrap()
});

// `KASLR disabled due to lack of seed` is the embedded failure mode: the kernel
// supports randomisation and the bootloader handed it no entropy, so it is off
// on a device whose vendor believes it is on.
static RE_KASLR_OFF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bKASLR disabled(?:\s+due to\s+(.+?))?\s*$").unwrap());
static RE_KASLR_ON: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bKASLR enabled\b").unwrap());

static RE_LSM_LIST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bLSM:\s*initializing\s+lsm=(\S+)").unwrap());
static RE_APPARMOR_OFF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)AppArmor:\s*AppArmor disabled by boot time parameter").unwrap()
});
static RE_SELINUX_STATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)SELinux:\s*(Initializing|Permissive|Enforcing|Disabled at runtime)").unwrap()
});
static RE_UNKNOWN_PARAMS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Unknown command line parameters:\s*(.+?)\s*$").unwrap());
static RE_CMDLINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:Kernel command line|cmdline|bootargs)\s*[:=]").unwrap());
static RE_SELINUX_OFF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bselinux=0\b").unwrap());

/// Modules that provide mandatory access control, as opposed to the ones every
/// kernel has. `capability` is always present and enforces nothing of the kind.
const MAC_MODULES: &[&str] = &["selinux", "apparmor", "smack", "tomoyo"];

/// `mem auto-init: stack:off, heap alloc:off, heap free:off`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MemAutoInit {
    pub stack: String,
    pub heap_alloc: String,
    pub heap_free: String,
}

/// What the kernel said about its own hardening.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OsHardening {
    pub mem_auto_init: Option<MemAutoInit>,
    /// `enabled` or `disabled`.
    pub kaslr: Option<String>,
    pub kaslr_reason: Option<String>,
    /// The active security modules, as the kernel listed them.
    pub lsm: Vec<String>,
    /// The subset of `lsm` that actually provides mandatory access control.
    pub mac_modules: Vec<String>,
    /// `disabled_by_parameter`, `not_supported`, or a runtime state.
    pub selinux: Option<String>,
    pub apparmor: Option<String>,
    /// Parameters the kernel listed as unrecognised, and therefore did not apply.
    pub ignored_kernel_parameters: Option<String>,
}

impl OsHardening {
    /// True when the capture said nothing about any of this.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Read the kernel's hardening report.
pub fn parse(log: &str) -> OsHardening {
    let mut h = OsHardening::default();
    for raw in log.lines() {
        let line = raw.trim_end_matches(['\r', '\n']);

        // First, because it changes what a later `selinux=0` means.
        if let Some(caps) = RE_UNKNOWN_PARAMS.captures(line) {
            let ignored = caps[1].to_string();
            if h.ignored_kernel_parameters.is_none() {
                h.ignored_kernel_parameters = Some(clip(&ignored, 300));
            }
            if RE_SELINUX_OFF.is_match(&ignored) && h.selinux.is_none() {
                h.selinux = Some("not_supported".to_string());
            }
            continue;
        }

        if let Some(caps) = RE_MEM_AUTO_INIT.captures(line) {
            if h.mem_auto_init.is_none() {
                h.mem_auto_init = Some(MemAutoInit {
                    stack: caps[1].trim().to_string(),
                    heap_alloc: caps[2].trim().to_string(),
                    heap_free: caps[3].trim().to_string(),
                });
                continue;
            }
        }

        if let Some(caps) = RE_KASLR_OFF.captures(line) {
            if h.kaslr.is_none() {
                h.kaslr = Some("disabled".to_string());
                let reason = caps.get(1).map(|m| m.as_str().trim()).unwrap_or_default();
                if !reason.is_empty() {
                    h.kaslr_reason = Some(clip(reason, 120));
                }
                continue;
            }
        }

        if RE_KASLR_ON.is_match(line) && h.kaslr.is_none() {
            h.kaslr = Some("enabled".to_string());
            continue;
        }

        if let Some(caps) = RE_LSM_LIST.captures(line) {
            if h.lsm.is_empty() {
                h.lsm = caps[1]
                    .split(',')
                    .map(|x| x.trim().to_ascii_lowercase())
                    .filter(|x| !x.is_empty())
                    .collect();
                let mut mac: Vec<String> = h
                    .lsm
                    .iter()
                    .filter(|m| MAC_MODULES.contains(&m.as_str()))
                    .cloned()
                    .collect();
                mac.sort();
                mac.dedup();
                h.mac_modules = mac;
                continue;
            }
        }

        if RE_APPARMOR_OFF.is_match(line) && h.apparmor.is_none() {
            h.apparmor = Some("disabled_by_parameter".to_string());
            continue;
        }

        if let Some(caps) = RE_SELINUX_STATE.captures(line) {
            if h.selinux.is_none() {
                h.selinux = Some(caps[1].to_ascii_lowercase());
                continue;
            }
        }

        // A `selinux=0` the kernel DID recognise, on a real command line.
        if RE_CMDLINE.is_match(line) && RE_SELINUX_OFF.is_match(line) && h.selinux.is_none() {
            h.selinux = Some("disabled_by_parameter".to_string());
        }
    }
    h
}
