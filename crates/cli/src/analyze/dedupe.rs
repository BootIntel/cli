//! Finding-dedupe set.
//!
//! Every detector run against the accumulated log returns ALL matching
//! findings (the detector library is stateless — no delta-tracking).
//! Without a dedupe layer, every re-run would re-print the same
//! bootloader / kernel / SoC lines the reader already saw. Match
//! the browser tool's convention: each finding surfaces exactly
//! once, when its evidence first appears.
//!
//! Key: the triple `(label, value, source)`. Same triple = same
//! finding. Detail is deliberately NOT part of the key because
//! detail sometimes changes slightly across re-runs (e.g. the
//! Linux kernel detector's toolchain-string tail can grow as more
//! of the banner arrives) without meaning "new finding."

use std::collections::HashSet;

use bootintel_detectors::Finding;

/// Filter a full list of findings down to only the ones we haven't
/// emitted before. Mutates internal seen-set. Returns a `Vec<&Finding>`
/// so callers don't have to clone Findings just to display them.
#[derive(Default)]
pub struct Dedupe {
    seen: HashSet<(String, String, Option<String>)>,
}

impl Dedupe {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a full findings list; return references to the ones that
    /// are new (in the order they appear). Findings already seen are
    /// dropped silently.
    pub fn new_findings<'a>(&mut self, findings: &'a [Finding]) -> Vec<&'a Finding> {
        let mut out = Vec::new();
        for f in findings {
            let key = (f.label.clone(), f.value.clone(), f.source.clone());
            if self.seen.insert(key) {
                out.push(f);
            }
        }
        out
    }

    /// Called by the Ctrl-A c hotkey: forget every previously-seen
    /// finding so a fresh scan re-emits everything currently in the
    /// log buffer.
    pub fn reset(&mut self) {
        self.seen.clear();
    }

    /// Snapshot of how many distinct findings we've emitted this
    /// session. Exposed for tests and for a future TUI mode's
    /// findings-counter widget; the current loop tracks the same
    /// info via `AnalyzeState::findings_snapshot().len()`.
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.seen.len()
    }
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn f(label: &str, value: &str) -> Finding {
        Finding {
            label: label.to_string(),
            value: value.to_string(),
            detail: None,
            source: None,
        }
    }

    fn f_src(label: &str, value: &str, source: &str) -> Finding {
        Finding {
            label: label.to_string(),
            value: value.to_string(),
            detail: None,
            source: Some(source.to_string()),
        }
    }

    #[test]
    fn first_run_emits_all() {
        let mut d = Dedupe::new();
        let findings = vec![f("Bootloader", "U-Boot 2020.10"), f("Kernel", "Linux 5.15")];
        let new = d.new_findings(&findings);
        assert_eq!(new.len(), 2);
        assert_eq!(d.count(), 2);
    }

    #[test]
    fn identical_second_run_emits_nothing() {
        let mut d = Dedupe::new();
        let findings = vec![f("Bootloader", "U-Boot 2020.10")];
        assert_eq!(d.new_findings(&findings).len(), 1);
        assert_eq!(d.new_findings(&findings).len(), 0);
        assert_eq!(d.count(), 1);
    }

    #[test]
    fn new_finding_in_later_run_emits() {
        // Simulates the stream growing: first run sees only the
        // bootloader banner; second run also has the kernel banner.
        let mut d = Dedupe::new();
        let first = vec![f("Bootloader", "U-Boot 2020.10")];
        assert_eq!(d.new_findings(&first).len(), 1);
        let second = vec![f("Bootloader", "U-Boot 2020.10"), f("Kernel", "Linux 5.15")];
        let new = d.new_findings(&second);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].label, "Kernel");
    }

    #[test]
    fn different_source_line_treated_as_different_finding() {
        // Same label + value but different source line = different
        // finding. E.g. two DHCP lines with different lease IPs.
        let mut d = Dedupe::new();
        let a = vec![f_src(
            "Bootloader",
            "U-Boot 2020.10",
            "U-Boot 2020.10 (Sep 17 2023)",
        )];
        let b = vec![f_src(
            "Bootloader",
            "U-Boot 2020.10",
            "U-Boot 2020.10 (Oct 05 2023)",
        )];
        assert_eq!(d.new_findings(&a).len(), 1);
        assert_eq!(d.new_findings(&b).len(), 1);
        assert_eq!(d.count(), 2);
    }

    #[test]
    fn detail_changes_do_not_trigger_re_emission() {
        // Detail is not part of the dedupe key. E.g. Linux kernel's
        // detail (toolchain string tail) grows as the banner
        // buffers more; we don't want to re-emit for that.
        let mut d = Dedupe::new();
        let a = vec![Finding {
            label: "Kernel".to_string(),
            value: "Linux 5.15".to_string(),
            detail: Some("gcc-11.2.0".to_string()),
            source: Some("Linux version 5.15…".to_string()),
        }];
        let b = vec![Finding {
            label: "Kernel".to_string(),
            value: "Linux 5.15".to_string(),
            detail: Some("gcc-11.2.0 (OpenWrt GCC 11.2.0)".to_string()),
            source: Some("Linux version 5.15…".to_string()),
        }];
        assert_eq!(d.new_findings(&a).len(), 1);
        assert_eq!(d.new_findings(&b).len(), 0);
    }

    #[test]
    fn reset_re_emits_everything() {
        let mut d = Dedupe::new();
        let findings = vec![f("Bootloader", "U-Boot 2020.10")];
        assert_eq!(d.new_findings(&findings).len(), 1);
        d.reset();
        assert_eq!(d.count(), 0);
        assert_eq!(d.new_findings(&findings).len(), 1);
    }
}
