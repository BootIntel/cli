//! Pacer: decides when to re-run the detector chain.
//!
//! Design constraint (design doc §5.1): "every N new lines OR every
//! 500ms whichever comes first — tuned to be imperceptible but not
//! per-byte." Running detectors on every incoming byte would burn
//! CPU on high-baud lines; running on a plain timer would delay
//! findings on quiet lines that emit one banner and then wait.
//!
//! The full re-run of all 14 detectors against a 40 KiB log takes
//! <5ms on modern hardware, so the pacer's job is really about
//! amortizing display flicker + not blocking the serial reader,
//! not about compute cost.
//!
//! Pure. No I/O, no clock beyond what the caller passes in.

use std::time::{Duration, Instant};

pub struct Pacer {
    /// How many new bytes have arrived since the last re-run trigger.
    bytes_since_run: usize,
    /// How many new lines (LF bytes) have arrived since last re-run.
    lines_since_run: usize,
    /// When the last re-run fired.
    last_run: Instant,
    /// Config: run when we accumulate this many new lines.
    lines_threshold: usize,
    /// Config: run when this much time has passed since last run
    /// (and we have at least one new byte).
    time_threshold: Duration,
}

impl Pacer {
    pub fn new(lines_threshold: usize, time_threshold: Duration) -> Self {
        Self {
            bytes_since_run: 0,
            lines_since_run: 0,
            last_run: Instant::now(),
            lines_threshold,
            time_threshold,
        }
    }

    /// Default: 5 lines OR 500ms.
    pub fn default_settings() -> Self {
        Self::new(5, Duration::from_millis(500))
    }

    /// Feed a chunk of newly-arrived serial bytes. Returns true if
    /// the pacer thinks it's time to re-run the detector chain
    /// (and resets its counters). The caller is expected to actually
    /// perform the re-run — the pacer just says yes/no.
    pub fn observe(&mut self, chunk: &[u8]) -> bool {
        if chunk.is_empty() {
            return false;
        }
        self.bytes_since_run += chunk.len();
        self.lines_since_run += chunk.iter().filter(|b| **b == b'\n').count();
        self.check_and_maybe_fire()
    }

    /// Called by the main loop on its idle tick so quiet lines
    /// eventually flush their (small) pending bytes even without
    /// a newline.
    pub fn tick(&mut self) -> bool {
        self.check_and_maybe_fire()
    }

    fn check_and_maybe_fire(&mut self) -> bool {
        if self.bytes_since_run == 0 {
            // Nothing new — nothing to re-run.
            return false;
        }
        let time_elapsed = self.last_run.elapsed();
        let lines_reached = self.lines_since_run >= self.lines_threshold;
        let time_reached = time_elapsed >= self.time_threshold;
        if lines_reached || time_reached {
            self.bytes_since_run = 0;
            self.lines_since_run = 0;
            self.last_run = Instant::now();
            return true;
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn empty_chunk_never_fires() {
        let mut p = Pacer::default_settings();
        assert!(!p.observe(b""));
    }

    #[test]
    fn fires_on_line_threshold() {
        let mut p = Pacer::new(3, Duration::from_secs(60));
        assert!(!p.observe(b"line-1\n"));
        assert!(!p.observe(b"line-2\n"));
        assert!(p.observe(b"line-3\n"), "third line should trigger fire");
    }

    #[test]
    fn does_not_fire_without_new_bytes_even_after_time() {
        let mut p = Pacer::new(1000, Duration::from_millis(10));
        sleep(Duration::from_millis(30));
        // Time threshold reached but no bytes seen — must not fire.
        assert!(!p.tick());
    }

    #[test]
    fn fires_on_time_threshold_when_below_line_threshold() {
        let mut p = Pacer::new(1000, Duration::from_millis(10));
        assert!(!p.observe(b"partial "));
        sleep(Duration::from_millis(15));
        assert!(
            p.tick(),
            "time-based fire should trigger even without a newline"
        );
    }

    #[test]
    fn resets_counters_after_firing() {
        let mut p = Pacer::new(1, Duration::from_secs(60));
        assert!(p.observe(b"one\n"));
        // Should not immediately fire again — counters were reset.
        assert!(!p.observe(b"partial"));
        assert!(p.observe(b"partial\n"));
    }

    #[test]
    fn tick_flushes_partial_bytes_once_time_elapses() {
        let mut p = Pacer::new(1000, Duration::from_millis(5));
        p.observe(b"partial-no-newline");
        // Immediately, time hasn't elapsed:
        assert!(!p.tick());
        sleep(Duration::from_millis(10));
        assert!(p.tick());
    }
}
