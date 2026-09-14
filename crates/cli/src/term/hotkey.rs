//! Ctrl-A hotkey state machine.
//!
//! Same convention as picocom / tio / minicom: an escape prefix (default
//! Ctrl-A) puts the terminal into command mode; the next keystroke is
//! interpreted as a command. The escape prefix followed by itself sends
//! the literal control byte to the serial port (so a Ctrl-A key on the
//! remote shell can be typed as Ctrl-A Ctrl-A).
//!
//! The escape prefix is configurable via `--escape` on the CLI (accepts
//! `ctrl-a` through `ctrl-z`) so users inside a tmux/screen session that
//! also uses Ctrl-A as its prefix can pick a different key. Same
//! discipline as picocom (`--escape`) and tio (`--map`).
//!
//! Pure — no I/O, no terminal state, no serial. Feeds directly by
//! taking `KeyEvent` in and returning `Action` out. Testable without
//! any of the surrounding machinery.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A user-selectable escape prefix. Currently limited to Ctrl+letter
/// (ASCII a-z) because that's what fits the "control byte" model that
/// serial terminals expect. Extending to Alt/Meta or non-letter Ctrl
/// combos would require more thought about how to display them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscapePrefix {
    /// The lowercase ASCII letter, e.g. 'a' for Ctrl-A.
    letter: char,
}

impl EscapePrefix {
    /// Default: Ctrl-A, matches picocom / tio / screen convention.
    pub const DEFAULT: EscapePrefix = EscapePrefix { letter: 'a' };

    /// Parse from a user string. Accepts `ctrl-a`, `ctrl-b`, `^a`,
    /// `C-a`, `a`, etc. Case-insensitive.
    pub fn parse(s: &str) -> Result<EscapePrefix, String> {
        let cleaned = s.trim().to_ascii_lowercase();
        let letter = if let Some(rest) = cleaned.strip_prefix("ctrl-") {
            rest
        } else if let Some(rest) = cleaned.strip_prefix("c-") {
            rest
        } else if let Some(rest) = cleaned.strip_prefix('^') {
            rest
        } else {
            cleaned.as_str()
        };
        if letter.len() != 1 {
            return Err(format!(
                "escape prefix '{s}' must be a single Ctrl+letter (e.g. ctrl-a, ctrl-b, C-e, ^t)"
            ));
        }
        let c = letter.chars().next().unwrap();
        if !c.is_ascii_lowercase() {
            return Err(format!(
                "escape prefix letter must be ASCII a-z; got '{c}' from '{s}'"
            ));
        }
        Ok(EscapePrefix { letter: c })
    }

    /// Human-readable display, e.g. "Ctrl-A" / "Ctrl-T".
    pub fn display(&self) -> String {
        format!("Ctrl-{}", self.letter.to_ascii_uppercase())
    }

    /// Raw control byte the prefix maps to (Ctrl-A = 0x01, Ctrl-B = 0x02, ...).
    pub fn control_byte(&self) -> u8 {
        (self.letter as u8) - b'a' + 1
    }

    /// Match a KeyEvent against this prefix. Handles both encodings the
    /// terminal may emit: `KeyCode::Char('a') + CONTROL` or the raw
    /// `KeyCode::Char('\x01')` for Ctrl-A, etc.
    pub fn matches(&self, k: &KeyEvent) -> bool {
        let raw = self.control_byte() as char;
        matches!(
            (k.code, k.modifiers),
            (KeyCode::Char(c), m)
                if m.contains(KeyModifiers::CONTROL)
                    && c.to_ascii_lowercase() == self.letter
        ) || matches!(k.code, KeyCode::Char(c) if c == raw)
    }
}

/// What the terminal loop should do with the current keystroke.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// No output — swallowed the keystroke (e.g. the escape prefix
    /// waiting for the next key).
    Nothing,
    /// Forward these raw bytes to the serial port.
    PassThrough(Vec<u8>),
    /// The user requested quit (`prefix` q).
    Quit,
    /// The user pressed `prefix` ? — main loop should print the help
    /// panel to stdout (not to the serial port).
    ShowHelp,
    /// `prefix` l — toggle live-analysis display on/off. Analyze mode
    /// only; term mode treats it as UnknownCommand.
    ToggleLiveAnalysis,
    /// `prefix` c — clear findings buffer and re-scan the log so far.
    /// Analyze mode only.
    ClearFindings,
    /// `prefix` s — save findings summary to a file. Analyze mode only.
    SaveFindings,
    /// `prefix` u — copy a bootintel.com share URL for the log-so-far
    /// to the clipboard (or print if clipboard unavailable). Analyze
    /// mode only.
    CopyShareUrl,
    /// `prefix` f — full server-side analysis: POST the log-so-far to
    /// bootintel.com/api/analysis/scan (or /preview if no API key),
    /// render the response inline. Analyze mode only.
    FullAnalysis,
    /// `prefix` b — send a serial BREAK signal. Standard picocom/minicom
    /// key. Used to interrupt U-Boot autoboot on some SoCs, drop Linux
    /// into sysrq, or wake a device that's misbehaving. Held for ~250ms.
    SendBreak,
    /// `prefix` x — toggle heX display mode. When on, RX bytes render
    /// as a hexdump (offset + hex bytes + ASCII gutter) instead of raw
    /// characters. Handy when a device streams binary or the terminal
    /// keeps mangling non-printable bytes.
    ToggleHexMode,
    /// `prefix` d — toggle DTR (Data Terminal Ready). Cheap way to
    /// assert/deassert the DTR line without hardware. Common ESP32
    /// bootloader-mode entry, generic device-reset workflows.
    ToggleDtr,
    /// `prefix` r — toggle RTS (Request To Send). Same pattern as
    /// DTR but on the other modem-control line — ESP32 reset uses
    /// DTR+RTS together; a soft-reset via UART typically drives both.
    ToggleRts,
    /// `prefix` p — paste (send) a text file to serial with pacing.
    /// Prompts for a path, then streams the bytes through with a
    /// small inter-line delay so a U-Boot / kernel shell receiver
    /// doesn't lose input to a buffer overrun. Standard minicom
    /// "send ASCII file" workflow.
    SendFile,
    /// `prefix` e — toggle local echo mid-session. Matches picocom's
    /// runtime toggle for --local-echo — some devices echo the
    /// keystroke back, some don't, and it's often the wrong default
    /// until the user tries typing.
    ToggleLocalEcho,
    /// `prefix` n — cycle line-ending mode: LF → CRLF → CR → LF.
    /// Rewrites bytes sent to serial when the user hits Enter (or
    /// pastes a file). Devices differ: U-Boot wants CR, most Linux
    /// login prompts want LF, some legacy modems want CRLF. Cycling
    /// beats forcing a startup flag when the device turns out wrong.
    CycleNewlineMode,
    /// `prefix` a — adjust (change) the serial baud rate mid-session.
    /// Prompts for the new rate. Real workflow: U-Boot boots at 115200,
    /// then the kernel comes up at a different speed dictated by the
    /// DTB's console= line. Currently that means quit + reconnect;
    /// with this hotkey it's one keystroke.
    ChangeBaud,
    /// `prefix` i — dump current session info to stderr: port, baud,
    /// DTR/RTS state, hex mode, local echo, newline mode, log file.
    /// The plain `term` mode has no persistent status bar (unlike
    /// `analyze --tui`); this hotkey substitutes for one on demand.
    ShowInfo,
    /// `prefix` k — cycle Backspace key mode: DEL (0x7f) ↔ BS (0x08).
    /// Some devices (older U-Boot, some ROM monitors) want BS; most
    /// modern Linux prompts want DEL. crossterm's default depends on
    /// the host terminal — this lets you flip when it turns out wrong.
    CycleBackspaceMode,
    /// `prefix` m — cycle RX line-ending mapping: None → CrToLf →
    /// StripCr → None. Some devices emit bare CR (0x0d) after each
    /// line, which makes the terminal overwrite the same row. Mapping
    /// CR→LF (or stripping CR when the device sends CRLF) fixes that.
    CycleRxNewlineMode,
    /// `prefix` h — hangup: close the serial port, wait ~500ms, and
    /// reopen with the same settings. Useful when a USB-serial adapter
    /// gets confused (device unplugged and re-plugged, adapter went
    /// through a power cycle, etc.) — no more quit-and-restart dance.
    Hangup,
    /// The user pressed the prefix followed by an unrecognized key.
    /// Main loop can print a hint like "unknown `prefix` command: 'x'".
    /// Carries the offending character so the loop can quote it.
    UnknownCommand(char),
}

/// Which byte the Backspace key sends. Some devices (older U-Boot,
/// certain ROM monitors) treat DEL as invalid input and only accept
/// BS; most modern Linux prompts accept DEL. crossterm's default is
/// to emit DEL, matching most terminals — but "matches most" isn't
/// "matches yours". Runtime-cycled via Ctrl-A k.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum BackspaceMode {
    /// 0x7f — matches most modern terminals + Linux prompts.
    Del,
    /// 0x08 — matches older U-Boot, some ROM monitors.
    Bs,
}

impl BackspaceMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Del => "DEL (0x7f)",
            Self::Bs => "BS (0x08)",
        }
    }
    pub fn byte(self) -> u8 {
        match self {
            Self::Del => 0x7f,
            Self::Bs => 0x08,
        }
    }
    pub fn cycle(self) -> Self {
        match self {
            Self::Del => Self::Bs,
            Self::Bs => Self::Del,
        }
    }
}

/// State machine for interpreting prefixed commands. Holds the active
/// escape prefix so the loop doesn't have to plumb it into every call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State {
    stage: Stage,
    prefix: EscapePrefix,
    /// Runtime-mutable backspace mode. Cycled via Ctrl-A k. Startup
    /// default is DEL to match `bootintel term`'s v0.1.x behavior.
    backspace_mode: BackspaceMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Idle,
    WaitingForCommand,
}

impl Default for State {
    fn default() -> Self {
        Self::new(EscapePrefix::DEFAULT)
    }
}

impl State {
    pub fn new(prefix: EscapePrefix) -> Self {
        Self {
            stage: Stage::Idle,
            prefix,
            backspace_mode: BackspaceMode::Del,
        }
    }

    /// Flip the Backspace key mode. Returns the new mode so the loop
    /// can surface it in a status message.
    pub fn cycle_backspace_mode(&mut self) -> BackspaceMode {
        self.backspace_mode = self.backspace_mode.cycle();
        self.backspace_mode
    }

    pub fn backspace_mode(&self) -> BackspaceMode {
        self.backspace_mode
    }

    pub fn prefix(&self) -> EscapePrefix {
        self.prefix
    }

    /// Handle one keystroke; return the appropriate Action and
    /// advance internal state. Called from the terminal loop on
    /// every KeyEvent from the crossterm reader thread.
    pub fn handle(&mut self, key: KeyEvent) -> Action {
        match self.stage {
            Stage::Idle => self.handle_idle(key),
            Stage::WaitingForCommand => self.handle_waiting(key),
        }
    }

    fn handle_idle(&mut self, key: KeyEvent) -> Action {
        // Escape prefix: swallow, enter command state.
        if self.prefix.matches(&key) {
            self.stage = Stage::WaitingForCommand;
            return Action::Nothing;
        }
        // Backspace is state-dependent — the user picks DEL or BS via
        // Ctrl-A k depending on what the device expects. Handle it
        // BEFORE encode_key so the shared encoder stays pure.
        if matches!(key.code, KeyCode::Backspace) {
            return Action::PassThrough(vec![self.backspace_mode.byte()]);
        }
        // Everything else: encode + forward to serial.
        match encode_key(&key) {
            Some(bytes) => Action::PassThrough(bytes),
            None => Action::Nothing,
        }
    }

    fn handle_waiting(&mut self, key: KeyEvent) -> Action {
        // Prefix again: send the literal prefix control byte to serial.
        if self.prefix.matches(&key) {
            self.stage = Stage::Idle;
            return Action::PassThrough(vec![self.prefix.control_byte()]);
        }
        let cmd = key_to_command_char(&key);
        self.stage = Stage::Idle;
        match cmd {
            Some('q') => Action::Quit,
            Some('?') => Action::ShowHelp,
            Some('l') => Action::ToggleLiveAnalysis,
            Some('c') => Action::ClearFindings,
            Some('s') => Action::SaveFindings,
            Some('u') => Action::CopyShareUrl,
            Some('f') => Action::FullAnalysis,
            Some('b') => Action::SendBreak,
            Some('x') => Action::ToggleHexMode,
            Some('d') => Action::ToggleDtr,
            Some('r') => Action::ToggleRts,
            Some('p') => Action::SendFile,
            Some('e') => Action::ToggleLocalEcho,
            Some('n') => Action::CycleNewlineMode,
            Some('a') => Action::ChangeBaud,
            Some('i') => Action::ShowInfo,
            Some('k') => Action::CycleBackspaceMode,
            Some('m') => Action::CycleRxNewlineMode,
            Some('h') => Action::Hangup,
            Some(c) => Action::UnknownCommand(c),
            None => Action::UnknownCommand('\0'),
        }
    }
}

fn key_to_command_char(k: &KeyEvent) -> Option<char> {
    match k.code {
        KeyCode::Char(c) => Some(c.to_ascii_lowercase()),
        _ => None,
    }
}

/// Encode a KeyEvent into the byte sequence that would arrive on
/// the serial port if the user were typing directly into a
/// picocom-shaped terminal. Handles the common cases (printable
/// chars, Enter, Backspace, Tab, arrow keys as ANSI escape
/// sequences, control chars via Ctrl+letter). Returns None for
/// key events that don't map to serial output (e.g. F-keys we
/// don't intercept — silently dropped).
pub fn encode_key(k: &KeyEvent) -> Option<Vec<u8>> {
    match k.code {
        KeyCode::Char(c) => {
            // Ctrl+letter → the corresponding control byte.
            if k.modifiers.contains(KeyModifiers::CONTROL) {
                let cc = c.to_ascii_lowercase();
                if cc.is_ascii_lowercase() {
                    let byte = (cc as u8) - b'a' + 1;
                    return Some(vec![byte]);
                }
                // Other control combos are terminal-specific; drop them.
                return None;
            }
            let mut buf = [0u8; 4];
            let s = c.encode_utf8(&mut buf);
            Some(s.as_bytes().to_vec())
        }
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Up => Some(vec![0x1b, b'[', b'A']),
        KeyCode::Down => Some(vec![0x1b, b'[', b'B']),
        KeyCode::Right => Some(vec![0x1b, b'[', b'C']),
        KeyCode::Left => Some(vec![0x1b, b'[', b'D']),
        KeyCode::Home => Some(vec![0x1b, b'[', b'H']),
        KeyCode::End => Some(vec![0x1b, b'[', b'F']),
        KeyCode::PageUp => Some(vec![0x1b, b'[', b'5', b'~']),
        KeyCode::PageDown => Some(vec![0x1b, b'[', b'6', b'~']),
        KeyCode::Delete => Some(vec![0x1b, b'[', b'3', b'~']),
        // F-keys, media keys, etc. — not forwarded. picocom does the
        // same by default. Can add later behind a flag if there's demand.
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn key_ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    // ── EscapePrefix parsing ───────────────────────────────────────

    #[test]
    fn escape_prefix_default_is_ctrl_a() {
        assert_eq!(EscapePrefix::DEFAULT.letter, 'a');
        assert_eq!(EscapePrefix::DEFAULT.display(), "Ctrl-A");
        assert_eq!(EscapePrefix::DEFAULT.control_byte(), 0x01);
    }

    #[test]
    fn escape_prefix_parse_various_forms() {
        for s in ["ctrl-a", "CTRL-A", "Ctrl-a", "c-a", "C-a", "^a", "a", "A"] {
            let p = EscapePrefix::parse(s).unwrap_or_else(|e| panic!("failed to parse '{s}': {e}"));
            assert_eq!(p.letter, 'a', "input '{s}' didn't yield 'a'");
        }
        // Different letter
        assert_eq!(EscapePrefix::parse("ctrl-t").unwrap().letter, 't');
        assert_eq!(EscapePrefix::parse("^b").unwrap().letter, 'b');
    }

    #[test]
    fn escape_prefix_parse_rejects_bad_input() {
        assert!(EscapePrefix::parse("ctrl-").is_err());
        assert!(EscapePrefix::parse("abc").is_err());
        assert!(EscapePrefix::parse("").is_err());
        assert!(EscapePrefix::parse("1").is_err());
        assert!(EscapePrefix::parse("!").is_err());
    }

    #[test]
    fn escape_prefix_matches_ctrl_letter() {
        let p = EscapePrefix::DEFAULT;
        assert!(p.matches(&key_ctrl('a')));
        assert!(p.matches(&key_ctrl('A'))); // shift+ctrl+a
        assert!(p.matches(&key(KeyCode::Char('\x01')))); // raw SOH
        assert!(!p.matches(&key_ctrl('b')));
        assert!(!p.matches(&key(KeyCode::Char('a')))); // no ctrl modifier
    }

    #[test]
    fn escape_prefix_ctrl_t_matches_correctly() {
        let p = EscapePrefix::parse("ctrl-t").unwrap();
        assert!(p.matches(&key_ctrl('t')));
        assert!(p.matches(&key(KeyCode::Char('\x14')))); // Ctrl-T = 0x14
        assert!(!p.matches(&key_ctrl('a'))); // NOT Ctrl-A anymore
        assert_eq!(p.control_byte(), 0x14);
    }

    // ── Basic pass-through ─────────────────────────────────────────

    #[test]
    fn idle_forwards_printable_chars() {
        let mut s = State::default();
        assert_eq!(
            s.handle(key(KeyCode::Char('h'))),
            Action::PassThrough(vec![b'h'])
        );
        assert_eq!(
            s.handle(key(KeyCode::Char('i'))),
            Action::PassThrough(vec![b'i'])
        );
    }

    #[test]
    fn idle_forwards_enter_as_cr() {
        let mut s = State::default();
        assert_eq!(
            s.handle(key(KeyCode::Enter)),
            Action::PassThrough(vec![b'\r'])
        );
    }

    #[test]
    fn idle_forwards_arrow_as_ansi_escape() {
        let mut s = State::default();
        assert_eq!(
            s.handle(key(KeyCode::Up)),
            Action::PassThrough(vec![0x1b, b'[', b'A'])
        );
    }

    #[test]
    fn idle_forwards_ctrl_letter_as_control_byte() {
        let mut s = State::default();
        assert_eq!(s.handle(key_ctrl('c')), Action::PassThrough(vec![0x03]));
        assert_eq!(s.handle(key_ctrl('l')), Action::PassThrough(vec![0x0c]));
    }

    // ── Ctrl-A escape prefix ───────────────────────────────────────

    #[test]
    fn ctrl_a_enters_command_state_and_swallows() {
        let mut s = State::default();
        assert_eq!(s.handle(key_ctrl('a')), Action::Nothing);
        assert_eq!(s.stage, Stage::WaitingForCommand);
    }

    #[test]
    fn ctrl_a_then_q_quits() {
        let mut s = State::default();
        assert_eq!(s.handle(key_ctrl('a')), Action::Nothing);
        assert_eq!(s.handle(key(KeyCode::Char('q'))), Action::Quit);
        assert_eq!(s.stage, Stage::Idle);
    }

    #[test]
    fn ctrl_a_then_question_shows_help() {
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(s.handle(key(KeyCode::Char('?'))), Action::ShowHelp);
    }

    #[test]
    fn ctrl_a_then_ctrl_a_sends_literal_soh() {
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(
            s.handle(key_ctrl('a')),
            Action::PassThrough(vec![0x01]),
            "Ctrl-A Ctrl-A must send SOH (0x01) to serial"
        );
        assert_eq!(s.stage, Stage::Idle);
    }

    #[test]
    fn ctrl_a_then_unknown_command_reports_it() {
        // 'z' is deliberately unclaimed — most letters are wired to
        // real hotkeys now (q ? l c s u f b x d r) so pick a letter
        // unlikely to be added soon.
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(
            s.handle(key(KeyCode::Char('z'))),
            Action::UnknownCommand('z')
        );
        assert_eq!(s.stage, Stage::Idle);
    }

    #[test]
    fn minicom_parity_hotkeys() {
        // All Ctrl-A letters that fall in the "minicom parity" bucket.
        // Grouped so future refactors that renumber letters have a
        // single fix-up site.
        for (letter, want) in [
            ('b', Action::SendBreak),
            ('x', Action::ToggleHexMode),
            ('d', Action::ToggleDtr),
            ('r', Action::ToggleRts),
            ('p', Action::SendFile),
            ('e', Action::ToggleLocalEcho),
            ('n', Action::CycleNewlineMode),
            ('a', Action::ChangeBaud),
            ('i', Action::ShowInfo),
            ('k', Action::CycleBackspaceMode),
            ('m', Action::CycleRxNewlineMode),
            ('h', Action::Hangup),
        ] {
            let mut s = State::default();
            s.handle(key_ctrl('a'));
            assert_eq!(
                s.handle(key(KeyCode::Char(letter))),
                want,
                "Ctrl-A {letter}"
            );
        }
    }

    #[test]
    fn ctrl_a_l_toggles_live_analysis() {
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(
            s.handle(key(KeyCode::Char('l'))),
            Action::ToggleLiveAnalysis
        );
    }

    #[test]
    fn ctrl_a_c_clears_findings() {
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(s.handle(key(KeyCode::Char('c'))), Action::ClearFindings);
    }

    #[test]
    fn ctrl_a_s_saves_findings() {
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(s.handle(key(KeyCode::Char('s'))), Action::SaveFindings);
    }

    #[test]
    fn ctrl_a_u_copies_share_url() {
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(s.handle(key(KeyCode::Char('u'))), Action::CopyShareUrl);
    }

    #[test]
    fn ctrl_a_f_triggers_full_analysis() {
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(s.handle(key(KeyCode::Char('f'))), Action::FullAnalysis);
    }

    #[test]
    fn ctrl_a_then_uppercase_q_still_quits() {
        let mut s = State::default();
        s.handle(key_ctrl('a'));
        assert_eq!(s.handle(key(KeyCode::Char('Q'))), Action::Quit);
    }

    #[test]
    fn raw_soh_char_also_triggers_escape() {
        let mut s = State::default();
        assert_eq!(s.handle(key(KeyCode::Char('\x01'))), Action::Nothing);
        assert_eq!(s.stage, Stage::WaitingForCommand);
    }

    // ── Alternate prefix (--escape ctrl-t) ─────────────────────────

    #[test]
    fn ctrl_t_prefix_swallows_ctrl_t_and_ignores_ctrl_a() {
        let mut s = State::new(EscapePrefix::parse("ctrl-t").unwrap());
        // Ctrl-A is now a regular pass-through (SOH byte to serial).
        assert_eq!(s.handle(key_ctrl('a')), Action::PassThrough(vec![0x01]));
        // Ctrl-T is the new prefix.
        assert_eq!(s.handle(key_ctrl('t')), Action::Nothing);
        assert_eq!(s.stage, Stage::WaitingForCommand);
        // Ctrl-T q quits.
        assert_eq!(s.handle(key(KeyCode::Char('q'))), Action::Quit);
    }

    #[test]
    fn ctrl_t_prefix_double_press_sends_literal_0x14() {
        let mut s = State::new(EscapePrefix::parse("ctrl-t").unwrap());
        s.handle(key_ctrl('t'));
        assert_eq!(
            s.handle(key_ctrl('t')),
            Action::PassThrough(vec![0x14]),
            "Ctrl-T Ctrl-T must send Ctrl-T byte (0x14) to serial"
        );
    }
}
