//! Shared mutable state the analyze loop owns.
//!
//! Not thread-safe by construction — the term-loop main thread owns
//! this struct and calls into it synchronously. Serial-reader and
//! keyboard-reader threads communicate via the existing mpsc
//! channel; only the main thread ever mutates AnalyzeState.

use std::path::PathBuf;

use bootintel_detectors::{analyze as run_detectors, Finding};

use super::dedupe::Dedupe;
use super::pacer::Pacer;

pub struct AnalyzeState {
    /// Accumulated log so far. Capped so a runaway device that emits
    /// hundreds of MiB doesn't OOM the terminal.
    log: String,
    /// Findings we've emitted this session. Also feeds save-summary.
    all_findings: Vec<Finding>,
    dedupe: Dedupe,
    pacer: Pacer,
    /// Whether inline `[bootintel]` lines are being printed. Toggled
    /// by Ctrl-A l. When false, detectors still run + dedupe still
    /// updates, so a subsequent toggle-on doesn't re-flood.
    pub live_display: bool,
    /// Reference to the log file, if any, so Ctrl-A s can save the
    /// findings summary alongside it (default: `<log>.findings.json`).
    log_file_hint: Option<PathBuf>,
}

const MAX_LOG_BYTES: usize = 4 * 1024 * 1024; // 4 MiB soft cap

impl AnalyzeState {
    pub fn new(log_file_hint: Option<PathBuf>) -> Self {
        Self {
            log: String::new(),
            all_findings: Vec::new(),
            dedupe: Dedupe::new(),
            pacer: Pacer::default_settings(),
            live_display: true,
            log_file_hint,
        }
    }

    /// Feed newly-arrived serial bytes into the analyzer. Returns
    /// `Some(new_findings)` if the pacer decided to re-run and there
    /// are new findings to display; None if no re-run happened or
    /// no new findings surfaced.
    pub fn feed(&mut self, chunk: &[u8]) -> Option<Vec<Finding>> {
        self.push_bytes(chunk);
        if !self.pacer.observe(chunk) {
            return None;
        }
        self.rerun()
    }

    /// Called on the main loop's idle tick so quiet lines still get
    /// their detectors run once the pacer's time threshold elapses.
    pub fn maybe_tick(&mut self) -> Option<Vec<Finding>> {
        if !self.pacer.tick() {
            return None;
        }
        self.rerun()
    }

    /// Ctrl-A c: forget everything and re-scan from the current log
    /// buffer. Returns the findings the re-scan surfaces (all of them,
    /// since dedupe is fresh).
    pub fn reset_and_rescan(&mut self) -> Vec<Finding> {
        self.dedupe.reset();
        self.all_findings.clear();
        let findings = run_detectors(&self.log);
        self.all_findings = findings.clone();
        // Mark them as seen so the next observation cycle doesn't
        // re-emit them.
        for f in &findings {
            self.dedupe.new_findings(std::slice::from_ref(f));
        }
        findings
    }

    /// All findings surfaced so far, in emission order. Feeds
    /// Ctrl-A s save-summary and Ctrl-A u share URL generation.
    pub fn findings_snapshot(&self) -> &[Finding] {
        &self.all_findings
    }

    /// Read-only accessor to the accumulated log — used by Ctrl-A u
    /// to build a share URL from the captured bytes.
    pub fn log_so_far(&self) -> &str {
        &self.log
    }

    pub fn captured_bytes(&self) -> usize {
        self.log.len()
    }

    /// Suggested path for the save-summary file. If the user gave a
    /// --log-file, we sit the .findings.json alongside it.
    /// Otherwise fall back to `bootintel-findings.json` in the CWD.
    pub fn default_summary_path(&self) -> PathBuf {
        match &self.log_file_hint {
            Some(p) => {
                let mut path: PathBuf = p.clone();
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "boot".to_string());
                path.set_file_name(format!("{stem}.findings.json"));
                path
            }
            None => PathBuf::from("bootintel-findings.json"),
        }
    }

    fn push_bytes(&mut self, chunk: &[u8]) {
        // Decode lossy so an incomplete UTF-8 sequence at a chunk
        // boundary doesn't panic. Real boot logs are ASCII; the
        // lossy path only matters for corrupted bytes from a noisy
        // serial line.
        let s = String::from_utf8_lossy(chunk);
        self.log.push_str(&s);
        // Cap: keep the tail. Detector matches are anchored on
        // specific banner phrases that appear early in a boot; if
        // we ever hit the cap we're on a device that's been chatty
        // for a long time and the identity findings have long been
        // emitted. Trimming from the front is a compromise: some
        // detectors that only look at recent lines (autoboot
        // prompt, dnsmasq startup) may re-fire on the trimmed tail,
        // but the dedupe layer handles that.
        if self.log.len() > MAX_LOG_BYTES {
            let drop = self.log.len() - MAX_LOG_BYTES;
            // Find a valid UTF-8 boundary at or past `drop`.
            let mut cut = drop;
            while cut < self.log.len() && !self.log.is_char_boundary(cut) {
                cut += 1;
            }
            self.log.drain(..cut);
        }
    }

    fn rerun(&mut self) -> Option<Vec<Finding>> {
        let findings = run_detectors(&self.log);
        let new: Vec<Finding> = self
            .dedupe
            .new_findings(&findings)
            .into_iter()
            .cloned()
            .collect();
        if new.is_empty() {
            return None;
        }
        self.all_findings.extend(new.iter().cloned());
        Some(new)
    }
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn feed_returns_findings_after_pacer_fires() {
        let mut s = AnalyzeState::new(None);
        // Force a fast pacer so the test doesn't need to sleep for 500ms.
        s.pacer = Pacer::new(1, Duration::from_secs(60));
        let bytes = b"U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)\nModel: TP-Link Archer C7 v5\n";
        let out = s
            .feed(bytes)
            .expect("should surface findings once pacer fires");
        assert!(!out.is_empty());
        assert!(out.iter().any(|f| f.label == "Bootloader"));
    }

    #[test]
    fn dedupe_prevents_second_emission() {
        let mut s = AnalyzeState::new(None);
        s.pacer = Pacer::new(1, Duration::from_secs(60));
        let bytes = b"U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)\n";
        assert!(s.feed(bytes).is_some());
        // Feed again — same bytes. Even though pacer fires (new bytes
        // arrived), dedupe should filter it out.
        assert!(s.feed(bytes).is_none());
    }

    #[test]
    fn reset_and_rescan_re_emits_from_current_log() {
        let mut s = AnalyzeState::new(None);
        s.pacer = Pacer::new(1, Duration::from_secs(60));
        s.feed(b"U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)\n");
        assert_eq!(s.findings_snapshot().len(), 1);
        let refreshed = s.reset_and_rescan();
        assert_eq!(refreshed.len(), 1);
        assert_eq!(refreshed[0].label, "Bootloader");
    }

    #[test]
    fn log_cap_trims_front_but_keeps_recent_bytes() {
        let mut s = AnalyzeState::new(None);
        s.pacer = Pacer::new(9999, Duration::from_secs(60));
        // Push more than the cap.
        s.feed(&vec![b'.'; MAX_LOG_BYTES + 8192]);
        assert!(s.captured_bytes() <= MAX_LOG_BYTES);
        assert!(s.captured_bytes() > MAX_LOG_BYTES - 8192);
    }

    #[test]
    fn default_summary_path_sits_next_to_log_file() {
        let hint = PathBuf::from("/tmp/boot-2026-08-21.log");
        let s = AnalyzeState::new(Some(hint));
        assert_eq!(
            s.default_summary_path(),
            PathBuf::from("/tmp/boot-2026-08-21.findings.json")
        );
    }

    #[test]
    fn default_summary_path_fallback_when_no_log_file() {
        let s = AnalyzeState::new(None);
        assert_eq!(
            s.default_summary_path(),
            PathBuf::from("bootintel-findings.json")
        );
    }
}
