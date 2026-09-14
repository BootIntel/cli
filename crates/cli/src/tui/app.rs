//! Owned TUI state.
//!
//! The main loop feeds serial bytes + keystrokes in; the renderer
//! reads out. State transitions are pure — testable without a
//! terminal.

use std::time::{Duration, Instant};

use bootintel_detectors::Finding;

use crate::analyze::state::AnalyzeState;
use crate::api::response::ApiScanResponse;
use crate::term::hotkey::EscapePrefix;
use crate::term::run::ApiConfig;

/// Cap the on-screen serial buffer to a few thousand lines. Anything
/// older is scrolled out. AnalyzeState still owns the full log for
/// detector re-runs; this is display-only.
const SERIAL_DISPLAY_LINE_CAP: usize = 5_000;

/// Cap the hex-mode raw-byte ring. 64 KiB = 4096 hex lines. Enough
/// to scroll back through a full boot phase; small enough to keep
/// re-rendering cheap.
const HEX_RING_CAP: usize = 64 * 1024;

/// Ctrl-A f status. Drives the server pane's rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiStatus {
    /// Never submitted this session.
    Idle,
    /// POST in flight. Server pane shows a "submitting..." line.
    /// Contains the timestamp so a stuck request can be shown as
    /// elapsed time.
    InFlight { started: Instant },
    /// Last submission returned OK. The full response body is in
    /// `App::api_result`.
    Ok { at: Instant },
    /// Last submission failed. Error message is in `App::api_error`.
    Err { at: Instant },
}

/// Which pane the user last acted on. Currently informational only —
/// keyboard focus is always on the hotkey state machine — but the
/// renderer highlights the active pane so users know where they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Serial,
    Findings,
    Server,
}

pub struct App {
    // ── Serial + analysis ────────────────────────────────────────
    /// Recent serial bytes as decoded lines for display. Front is
    /// oldest.
    serial_lines: Vec<String>,
    /// Partial line buffer — bytes since the last '\n', not yet
    /// promoted to `serial_lines`.
    partial: String,
    /// Byte counter across the whole session (never trimmed).
    pub total_bytes: usize,
    pub analyzer: AnalyzeState,

    // ── Server integration ───────────────────────────────────────
    pub api_config: Option<ApiConfig>,
    pub api_status: ApiStatus,
    pub api_result: Option<ApiScanResponse>,
    pub api_error: Option<String>,

    // ── Connection metadata (for the title bar) ──────────────────
    pub port_name: String,
    pub baud: u32,
    pub connected_at: Instant,

    /// Active hotkey escape prefix. Shown in the status bar so users
    /// never have to guess what `q`, `f`, etc. actually mean.
    pub escape_prefix: EscapePrefix,

    // ── UI state ─────────────────────────────────────────────────
    pub focused_pane: Pane,
    /// Scroll offset from the bottom of the serial buffer. 0 = pinned
    /// to newest (autoscroll on new bytes); >0 = user scrolled up.
    pub serial_scroll: usize,
    pub should_quit: bool,
    /// Set by handlers to surface a transient bottom-bar message
    /// (e.g. "clipboard unavailable" — 4s TTL by default, or
    /// "tmux prefix collision" — 30s TTL for startup warnings the
    /// user really shouldn't miss). The third tuple element is the
    /// per-message TTL so warnings can linger longer than status pings.
    pub status_message: Option<(String, Instant, Duration)>,

    /// Tracked DTR/RTS line state so Ctrl-A d / Ctrl-A r toggle
    /// idempotently without querying the port (which not all
    /// backends support). Initial state is `true` — ports open with
    /// both modem-control lines asserted on the backends we ship.
    pub dtr_state: bool,
    pub rts_state: bool,
    /// Line-ending conversion applied to bytes on TX. Runtime-cycled
    /// via Ctrl-A n through {LF, CR, CRLF}. Startup default is
    /// Passthrough (byte-identical to what crossterm produced for
    /// Enter).
    pub newline_mode: crate::term::newline::NewlineMode,
    /// RX line-ending mapping applied to bytes received from the
    /// port BEFORE they hit `feed_bytes` (so the pane + analyzer
    /// both see the normalized stream). Runtime-cycled via
    /// Ctrl-A m through {None, CrToLf, StripCr}. Startup default
    /// is None; seeded from opts.rx_newline_mode in tui::run::run.
    pub rx_newline_mode: crate::term::newline::RxNewlineMode,

    /// Hex-dump display mode. When true the serial pane renders a
    /// hex+ASCII view of `hex_bytes` (bounded ring) instead of the
    /// decoded text buffer. Toggled by Ctrl-A x.
    pub hex_mode: bool,
    /// Ring buffer of raw RX bytes for hex display. Front is oldest,
    /// capped at HEX_RING_CAP; bytes older than the cap are dropped.
    /// Populated on every `feed_bytes`, whether hex_mode is on or not,
    /// so toggling the mode shows recent history immediately (not just
    /// bytes received *after* the toggle).
    hex_bytes: std::collections::VecDeque<u8>,

    /// Active input prompt (paste-file path, change-baud value, …).
    /// When Some, keystrokes are routed to the prompt buffer instead
    /// of the serial port. Renderer draws a bottom-line input row when
    /// this is Some.
    pub input_prompt: Option<InputPrompt>,
}

/// Bottom-line input modal state. Small enough to keep inline in App;
/// separate type so the renderer can pattern-match on the intent to
/// customize the prompt label.
#[derive(Debug, Clone)]
pub struct InputPrompt {
    pub intent: InputIntent,
    /// User-visible label ("paste file: ", "new baud: ", …).
    pub label: String,
    /// Current keystroke buffer. Grows on char, shrinks on backspace,
    /// consumed by the run-loop on Enter.
    pub buffer: String,
}

/// What to do with the buffer when the user hits Enter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputIntent {
    /// Path to a file whose bytes should be shoved down the serial TX.
    PasteFile,
    /// New baud rate for the open port (decimal integer).
    ChangeBaud,
}

/// Default TTL for a status message. Handlers can pass a longer
/// duration to `set_status_message_with_ttl` for startup warnings
/// that need to stick around longer than a normal hotkey ack.
pub const STATUS_MESSAGE_TTL: Duration = Duration::from_secs(4);

/// TTL for startup warnings (tmux prefix collision, etc). Long enough
/// for the user to read + act on, short enough to not clutter the
/// status bar forever once they've moved on.
pub const STARTUP_WARNING_TTL: Duration = Duration::from_secs(30);

impl App {
    pub fn new(
        port_name: String,
        baud: u32,
        analyzer: AnalyzeState,
        api_config: Option<ApiConfig>,
        escape_prefix: EscapePrefix,
    ) -> Self {
        Self {
            serial_lines: Vec::new(),
            partial: String::new(),
            total_bytes: 0,
            analyzer,
            api_config,
            api_status: ApiStatus::Idle,
            api_result: None,
            api_error: None,
            port_name,
            baud,
            connected_at: Instant::now(),
            escape_prefix,
            focused_pane: Pane::Serial,
            serial_scroll: 0,
            should_quit: false,
            status_message: None,
            dtr_state: true,
            rts_state: true,
            newline_mode: crate::term::newline::NewlineMode::Passthrough,
            rx_newline_mode: crate::term::newline::RxNewlineMode::None,
            hex_mode: false,
            hex_bytes: std::collections::VecDeque::with_capacity(HEX_RING_CAP),
            input_prompt: None,
        }
    }

    /// Feed serial bytes: decode lossy UTF-8, split on newlines, cap
    /// the display buffer, and pass through to the detector layer.
    /// Returns any new findings surfaced by the analyzer (for the
    /// caller to show as a transient toast if it wants — currently
    /// unused since the findings pane redraws every tick anyway).
    pub fn feed_bytes(&mut self, chunk: &[u8]) -> Option<Vec<Finding>> {
        self.total_bytes += chunk.len();
        // Feed the hex ring regardless of current mode — toggling into
        // hex mode should immediately show recent history, not a blank
        // pane that only fills as new bytes arrive.
        self.hex_bytes.extend(chunk.iter().copied());
        while self.hex_bytes.len() > HEX_RING_CAP {
            self.hex_bytes.pop_front();
        }
        let s = String::from_utf8_lossy(chunk);
        for ch in s.chars() {
            match ch {
                '\n' => {
                    let mut line = std::mem::take(&mut self.partial);
                    // Strip a trailing \r if the device does CRLF.
                    if line.ends_with('\r') {
                        line.pop();
                    }
                    self.serial_lines.push(line);
                }
                '\r' => {
                    // Bare CR (e.g. progress bars): keep it in the
                    // partial line so ratatui shows the last write;
                    // don't split.
                    self.partial.push(ch);
                }
                other => self.partial.push(other),
            }
        }
        // Cap the display buffer.
        if self.serial_lines.len() > SERIAL_DISPLAY_LINE_CAP {
            let drop = self.serial_lines.len() - SERIAL_DISPLAY_LINE_CAP;
            self.serial_lines.drain(..drop);
        }
        self.analyzer.feed(chunk)
    }

    /// Snapshot of the current display buffer (oldest → newest),
    /// with the partial line as the final entry if non-empty.
    pub fn serial_display(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self.serial_lines.iter().map(|s| s.as_str()).collect();
        if !self.partial.is_empty() {
            out.push(&self.partial);
        }
        out
    }

    /// User pressed PgUp / Up-arrow. Scrolls the serial pane up.
    /// Bounded by buffer size.
    pub fn scroll_serial_up(&mut self, by: usize) {
        let max = self.serial_display().len();
        self.serial_scroll = self.serial_scroll.saturating_add(by).min(max);
    }

    /// User pressed PgDn / Down-arrow. Scrolls toward newest (0 =
    /// pinned to bottom, autoscrolls on new data).
    pub fn scroll_serial_down(&mut self, by: usize) {
        self.serial_scroll = self.serial_scroll.saturating_sub(by);
    }

    /// Pin the serial pane to the bottom (End key).
    pub fn scroll_serial_to_bottom(&mut self) {
        self.serial_scroll = 0;
    }

    /// Set a transient status message with the default 4s TTL.
    /// Use for hotkey acks + confirmations.
    pub fn set_status_message(&mut self, msg: impl Into<String>) {
        self.set_status_message_with_ttl(msg, STATUS_MESSAGE_TTL);
    }

    /// Set a status message with a custom TTL. Use STARTUP_WARNING_TTL
    /// for things the user really shouldn't miss (tmux prefix collision,
    /// clipboard-unavailable-on-headless, etc.).
    pub fn set_status_message_with_ttl(&mut self, msg: impl Into<String>, ttl: Duration) {
        self.status_message = Some((msg.into(), Instant::now(), ttl));
    }

    /// Clear the status message if it has aged out. Called by the
    /// main loop's tick.
    pub fn tick_status_message(&mut self) {
        if let Some((_, at, ttl)) = &self.status_message {
            if at.elapsed() >= *ttl {
                self.status_message = None;
            }
        }
    }

    /// Set the api_status to InFlight. Called just before the POST.
    pub fn mark_api_in_flight(&mut self) {
        self.api_status = ApiStatus::InFlight {
            started: Instant::now(),
        };
    }

    /// Called after the POST returns.
    pub fn mark_api_ok(&mut self, resp: ApiScanResponse) {
        self.api_status = ApiStatus::Ok { at: Instant::now() };
        self.api_result = Some(resp);
        self.api_error = None;
    }

    pub fn mark_api_err(&mut self, msg: impl Into<String>) {
        self.api_status = ApiStatus::Err { at: Instant::now() };
        self.api_error = Some(msg.into());
    }

    /// Toggle hex display mode. Returns the new state so the caller
    /// can build an ack status message without re-reading the field.
    pub fn toggle_hex_mode(&mut self) -> bool {
        self.hex_mode = !self.hex_mode;
        // Pin to bottom on mode change so we don't inherit a scroll
        // offset that made sense for the other buffer's line count.
        self.serial_scroll = 0;
        self.hex_mode
    }

    /// Snapshot of the hex ring rendered as one `hexdump -C` line per
    /// 16 bytes. Offsets are absolute (based on session-wide byte
    /// count minus the current ring length) so long streams get
    /// monotonic addresses even after the ring wraps.
    pub fn hex_display(&self) -> Vec<String> {
        let bytes: Vec<u8> = self.hex_bytes.iter().copied().collect();
        let base_offset = self.total_bytes.saturating_sub(bytes.len()) as u64;
        let mut out = Vec::with_capacity(bytes.len() / 16 + 1);
        for (i, chunk) in bytes.chunks(16).enumerate() {
            let off = base_offset + (i as u64) * 16;
            let mut line = String::with_capacity(80);
            use std::fmt::Write;
            let _ = write!(line, "{off:08x}  ");
            for (j, b) in chunk.iter().enumerate() {
                let _ = write!(line, "{b:02x} ");
                if j == 7 {
                    line.push(' ');
                }
            }
            for j in chunk.len()..16 {
                line.push_str("   ");
                if j == 7 {
                    line.push(' ');
                }
            }
            line.push_str(" |");
            for b in chunk {
                let c = if (0x20..0x7f).contains(b) {
                    *b as char
                } else {
                    '.'
                };
                line.push(c);
            }
            line.push('|');
            out.push(line);
        }
        out
    }

    /// Open a bottom-line input prompt. The renderer draws a labelled
    /// input row; keystrokes are routed here by run.rs until Enter (
    /// consumed by `take_input_prompt`) or Esc (cleared).
    pub fn open_input_prompt(&mut self, intent: InputIntent, label: impl Into<String>) {
        self.input_prompt = Some(InputPrompt {
            intent,
            label: label.into(),
            buffer: String::new(),
        });
    }

    /// Consume the current prompt's buffer + intent (called on Enter).
    /// Clears the prompt state so the pane returns to normal.
    pub fn take_input_prompt(&mut self) -> Option<InputPrompt> {
        self.input_prompt.take()
    }

    /// Drop the prompt without submitting (Esc / Ctrl-C).
    pub fn cancel_input_prompt(&mut self) {
        self.input_prompt = None;
    }
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn base_app() -> App {
        App::new(
            "/dev/ttyUSB0".to_string(),
            115200,
            AnalyzeState::new(None),
            None,
            EscapePrefix::DEFAULT,
        )
    }

    #[test]
    fn feed_bytes_splits_on_newlines() {
        let mut a = base_app();
        a.feed_bytes(b"line one\nline two\n");
        let disp = a.serial_display();
        assert_eq!(disp.len(), 2);
        assert_eq!(disp[0], "line one");
        assert_eq!(disp[1], "line two");
        assert_eq!(a.total_bytes, 18);
    }

    #[test]
    fn feed_bytes_strips_crlf() {
        let mut a = base_app();
        a.feed_bytes(b"windows-style\r\nunix-style\n");
        let disp = a.serial_display();
        assert_eq!(disp.len(), 2);
        assert_eq!(disp[0], "windows-style");
        assert_eq!(disp[1], "unix-style");
    }

    #[test]
    fn feed_bytes_keeps_partial_line() {
        let mut a = base_app();
        a.feed_bytes(b"complete\npartial without newline");
        let disp = a.serial_display();
        assert_eq!(disp.len(), 2);
        assert_eq!(disp[0], "complete");
        assert_eq!(disp[1], "partial without newline");
    }

    #[test]
    fn partial_line_promoted_when_newline_arrives() {
        let mut a = base_app();
        a.feed_bytes(b"partial ");
        a.feed_bytes(b"continued\n");
        let disp = a.serial_display();
        assert_eq!(disp.len(), 1);
        assert_eq!(disp[0], "partial continued");
    }

    #[test]
    fn feed_bytes_triggers_detector_findings_after_pacer_fires() {
        let mut a = base_app();
        // Feed enough lines to trip the pacer (default 5 lines OR
        // 500ms). Bootloader banner is in the first line. Collect
        // whatever any of the calls returns — we don't care which
        // specific call is the one that fires, just that findings
        // surface eventually and the Bootloader label is among them.
        let mut all: Vec<bootintel_detectors::Finding> = Vec::new();
        for line in [
            b"U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)\n".as_slice(),
            b"filler line two\n",
            b"filler line three\n",
            b"filler line four\n",
            b"filler line five\n",
            b"filler line six\n",
        ] {
            if let Some(found) = a.feed_bytes(line) {
                all.extend(found);
            }
        }
        assert!(!all.is_empty(), "pacer should fire during 6 feeds");
        assert!(all.iter().any(|f| f.label == "Bootloader"));
    }

    #[test]
    fn buffer_cap_trims_oldest_lines() {
        let mut a = base_app();
        for i in 0..(SERIAL_DISPLAY_LINE_CAP + 100) {
            let line = format!("line {i}\n");
            a.feed_bytes(line.as_bytes());
        }
        let disp = a.serial_display();
        // Cap is applied so buffer never grows past cap.
        assert!(disp.len() <= SERIAL_DISPLAY_LINE_CAP);
        // Last line should be the newest (i.e. still in buffer).
        assert!(disp
            .last()
            .unwrap()
            .contains(&format!("{}", SERIAL_DISPLAY_LINE_CAP + 99)));
    }

    #[test]
    fn scroll_up_bounded_by_buffer_size() {
        let mut a = base_app();
        a.feed_bytes(b"a\nb\nc\n");
        assert_eq!(a.serial_scroll, 0);
        a.scroll_serial_up(10);
        assert!(a.serial_scroll <= 3, "scroll clamped to buffer length");
    }

    #[test]
    fn scroll_down_saturates_at_zero() {
        let mut a = base_app();
        a.feed_bytes(b"a\nb\n");
        a.scroll_serial_down(5);
        assert_eq!(a.serial_scroll, 0);
    }

    #[test]
    fn scroll_to_bottom_resets() {
        let mut a = base_app();
        a.feed_bytes(b"a\nb\nc\n");
        a.scroll_serial_up(2);
        assert_eq!(a.serial_scroll, 2);
        a.scroll_serial_to_bottom();
        assert_eq!(a.serial_scroll, 0);
    }

    #[test]
    fn api_status_lifecycle_transitions() {
        let mut a = base_app();
        assert_eq!(a.api_status, ApiStatus::Idle);
        a.mark_api_in_flight();
        assert!(matches!(a.api_status, ApiStatus::InFlight { .. }));
        a.mark_api_err("net down");
        assert!(matches!(a.api_status, ApiStatus::Err { .. }));
        assert_eq!(a.api_error.as_deref(), Some("net down"));
    }

    #[test]
    fn toggle_hex_mode_flips_and_pins_bottom() {
        let mut a = base_app();
        a.feed_bytes(b"first\nsecond\n");
        a.scroll_serial_up(1);
        assert_eq!(a.serial_scroll, 1);
        assert!(!a.hex_mode);
        assert!(a.toggle_hex_mode());
        assert!(a.hex_mode);
        // Scroll offset resets so we don't inherit a text-buffer scroll
        // that would land us in the middle of a differently-sized
        // hex buffer.
        assert_eq!(a.serial_scroll, 0);
        assert!(!a.toggle_hex_mode());
        assert!(!a.hex_mode);
    }

    #[test]
    fn hex_display_formats_bytes_with_offset_and_ascii() {
        let mut a = base_app();
        // 20 bytes → two hex lines (16 + 4).
        a.feed_bytes(b"hello world!!!\r\n\x00\x01\x02\x03");
        let lines = a.hex_display();
        assert_eq!(lines.len(), 2);
        // First line: offset 00000000, "hello world!!!\r\n" in ASCII.
        assert!(lines[0].starts_with("00000000  "), "got: {}", lines[0]);
        assert!(
            lines[0].ends_with("|hello world!!!..|"),
            "got: {}",
            lines[0]
        );
        // Second line: 4 bytes, offset 00000010, padded with spaces.
        assert!(lines[1].starts_with("00000010  "), "got: {}", lines[1]);
        assert!(lines[1].ends_with("|....|"), "got: {}", lines[1]);
    }

    #[test]
    fn hex_ring_caps_at_max_but_offset_stays_absolute() {
        let mut a = base_app();
        // Feed enough bytes to blow past the cap.
        let big = vec![0x41u8; super::HEX_RING_CAP + 32];
        a.feed_bytes(&big);
        let lines = a.hex_display();
        // Ring only kept HEX_RING_CAP bytes.
        assert_eq!(lines.len(), super::HEX_RING_CAP / 16);
        // But offset accounts for the dropped 32 bytes at the front.
        assert!(
            lines[0].starts_with(&format!("{:08x}  ", 32)),
            "got: {}",
            lines[0]
        );
    }

    #[test]
    fn input_prompt_lifecycle() {
        let mut a = base_app();
        assert!(a.input_prompt.is_none());
        a.open_input_prompt(InputIntent::PasteFile, "path: ");
        let p = a.input_prompt.as_mut().unwrap();
        assert_eq!(p.intent, InputIntent::PasteFile);
        p.buffer.push_str("/tmp/foo");
        // take_input_prompt consumes + clears.
        let taken = a.take_input_prompt().unwrap();
        assert_eq!(taken.buffer, "/tmp/foo");
        assert!(a.input_prompt.is_none());
    }

    #[test]
    fn cancel_input_prompt_clears_without_consuming() {
        let mut a = base_app();
        a.open_input_prompt(InputIntent::ChangeBaud, "baud: ");
        assert!(a.input_prompt.is_some());
        a.cancel_input_prompt();
        assert!(a.input_prompt.is_none());
    }

    #[test]
    fn status_message_ttl_clears() {
        let mut a = base_app();
        a.set_status_message("hello");
        assert!(a.status_message.is_some());
        // Force the timestamp older than TTL.
        if let Some((s, _, ttl)) = a.status_message.take() {
            a.status_message = Some((
                s,
                Instant::now() - STATUS_MESSAGE_TTL - Duration::from_secs(1),
                ttl,
            ));
        }
        a.tick_status_message();
        assert!(a.status_message.is_none());
    }
}
