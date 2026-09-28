//! Interrupting autoboot, and pulling the environment once the prompt lands.
//!
//! # Why this is not "watch for the countdown, then send a key"
//!
//! That is the obvious design and it does not work. U-Boot's autoboot delay is
//! a loop around `tstc()`, and the shortest useful configuration is
//! `bootdelay=0`, where the check happens **once**. Boards in the field are
//! routinely built that way, and plenty of others leave a window of a few
//! milliseconds. By the time "Hit any key to stop autoboot" has crossed the
//! wire, been read by this process, and been recognised, the window is gone:
//! at 115200 baud a single character is already ~87us of wire time, and the
//! read is scheduled by the OS, not by us.
//!
//! What works is that the byte is already in the UART's receive register when
//! the board looks. A serial port buffers, so a character sent before the check
//! is still waiting at the check. So this hammers from the instant the port
//! opens, continuously, and asks the operator to power-cycle AFTER that starts.
//! There is nothing to detect and nothing to react to, which is the point:
//! reaction is exactly the thing that is too slow.
//!
//! `--reset-line` closes the loop entirely by pulsing DTR or RTS, so the reset
//! instant is ours rather than a human's. That needs an adapter wired to the
//! board's reset, which many are not, so it is opt-in.
//!
//! # The split
//!
//! Two things with completely different requirements:
//!
//!   * The hammer must be FAST, so it is a thread that writes one byte string
//!     on a timer and holds no logic at all (`run.rs`).
//!   * Deciding when to stop hammering, and what to type, must be CORRECT, and
//!     happens at human timescales once a prompt exists. That is this module:
//!     a state machine over the received bytes with no clock of its own and no
//!     I/O, so the interesting cases are unit tests rather than a board on a
//!     bench.
//!
//! # Safety on someone else's hardware
//!
//! A consultant runs this against a client's only sample of a device.
//!
//!   * The hammer NEVER sends CR or LF. Its bytes accumulate in U-Boot's line
//!     buffer, and a newline would execute whatever they spell. This is
//!     enforced when the key is parsed, and asserted in the tests.
//!   * The default key is a space, which is a no-op at a U-Boot prompt.
//!   * The default commands are read-only: `printenv`, `bdinfo`, `mtdparts`.
//!   * Every byte this module sends is announced, so a session transcript shows
//!     what the tool typed as distinct from what the board said.

use std::time::{Duration, Instant};

use regex::Regex;
use std::sync::LazyLock;

/// A prompt, seen live. This is NOT the pattern the engine uses on a saved
/// capture, and the difference is deliberate.
///
/// A saved capture is read line by line, and a prompt line there is terminated
/// because whatever was typed next ended it. Live, a prompt is the one thing
/// that arrives WITHOUT a newline: the board prints `=> ` and waits. So the
/// subject here is the unterminated tail of the stream, and the shapes worth
/// accepting are wider, because the vendor-rebranded `RTL8672 # ` that the
/// engine's stricter `=>` pattern skips is a prompt an operator can absolutely
/// type into.
static RE_PROMPT_TAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(?:=>|([\w][\w.@:/~()\-]{0,31}?)\s*(?:=>|[>#]))\s*$").unwrap()
});

static RE_ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]").unwrap());

/// Markers that the bootloader has handed off. After one of these, a `#`
/// prompt is a Linux root shell, not U-Boot, and typing `printenv` into it
/// would produce a shell's environment and a confident, wrong verdict.
const HANDOFF: &[&str] = &[
    "Starting kernel",
    "Booting Linux",
    "Uncompressing Linux",
    "Linux version",
    "Booting kernel",
    "starting pid ",
    "init started",
];

/// Markers that a fresh bootloader cycle has begun, which clears the handoff
/// latch: the operator power-cycled and we are back before the handoff.
const BOOTLOADER_BANNER: &[&str] = &[
    "U-Boot 1",
    "U-Boot 2",
    "U-Boot SPL",
    "Hit any key",
    "autoboot",
    "reset",
    "CPU:",
    "DRAM:",
];

/// What the caller should do next. Every side effect is one of these, so the
/// state machine itself touches nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Begin (or resume) hammering the interrupt key.
    StartHammer,
    /// Stop hammering. Always emitted before anything is typed, so the tool's
    /// commands cannot interleave with the hammer's bytes.
    StopHammer,
    /// Pulse the configured reset line.
    PulseReset,
    /// Write these bytes to the port verbatim.
    Send(Vec<u8>),
    /// Tell the operator something, on its own line.
    Note(String),
    /// Every command ran. The caller prints the verdict and hands the terminal
    /// back to the user.
    Done,
    /// The window was not caught, or the prompt could not be held. Carries an
    /// operator-facing explanation. Never silent, and never mistaken for
    /// success.
    GaveUp(String),
}

/// How the interrupter behaves. Defaults are the ones that work on an unknown
/// board with no information about it.
#[derive(Debug, Clone)]
pub struct Config {
    /// Bytes hammered during the window. Guaranteed CR/LF-free by
    /// [`parse_key`].
    pub key: Vec<u8>,
    /// Gap between hammer writes. The hammer's job is to have a byte waiting
    /// in the receiver, not to flood, so this is a floor on wire use rather
    /// than a race to be won.
    pub interval: Duration,
    /// Total time to keep trying before reporting the window missed. Spans a
    /// power cycle the operator performs by hand, and several if the board is
    /// in a boot loop.
    pub timeout: Duration,
    /// Commands to run once the prompt is held. Read-only by default.
    pub commands: Vec<String>,
    /// How long the line must be quiet before typing. A board mid-transfer
    /// prints a progress line that can look like a prompt; it will not stay
    /// quiet, and a real prompt will.
    pub settle: Duration,
    /// How long to wait for the prompt to come back after typing. On expiry
    /// the hammer is re-armed rather than the attempt abandoned, because the
    /// usual cause is a false prompt or a board that reset under us.
    pub prompt_wait: Duration,
    /// Pulse a reset line at the start.
    pub reset_line: ResetLine,
    /// How long the reset line is held before releasing it.
    pub reset_hold: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResetLine {
    #[default]
    None,
    Dtr,
    Rts,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key: vec![b' '],
            interval: Duration::from_millis(5),
            timeout: Duration::from_secs(45),
            commands: vec![
                "printenv".to_string(),
                "bdinfo".to_string(),
                "mtdparts".to_string(),
            ],
            settle: Duration::from_millis(300),
            prompt_wait: Duration::from_secs(5),
            reset_line: ResetLine::None,
            reset_hold: Duration::from_millis(250),
        }
    }
}

/// Parse a `--interrupt-key` spec into bytes, refusing anything containing a
/// newline.
///
/// The refusal is the point. A hammered CR executes whatever the other
/// hammered bytes spell, on a board that is not ours.
pub fn parse_key(spec: &str) -> Result<Vec<u8>, String> {
    let bytes = match spec.to_ascii_lowercase().as_str() {
        "space" | "" => vec![b' '],
        "esc" | "escape" => vec![0x1b],
        "ctrl-c" | "ctrl_c" | "^c" => vec![0x03],
        "tab" => vec![b'\t'],
        _ => {
            if let Some(hex) = spec.strip_prefix("0x").or_else(|| spec.strip_prefix("0X")) {
                if hex.is_empty()
                    || hex.len() % 2 != 0
                    || !hex.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(format!(
                        "{spec:?} is not a byte string; use an even number of hex digits, e.g. 0x1b"
                    ));
                }
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("validated hex"))
                    .collect()
            } else {
                spec.as_bytes().to_vec()
            }
        }
    };
    if bytes.iter().any(|b| *b == b'\r' || *b == b'\n') {
        return Err(
            "the interrupt key cannot contain CR or LF. It is sent repeatedly and its bytes \
             accumulate in U-Boot's line buffer, so a newline would execute whatever they \
             spell on the board. Send a bare key (space, esc) and let bootintel type the \
             commands."
                .to_string(),
        );
    }
    if bytes.is_empty() {
        return Err("the interrupt key cannot be empty".to_string());
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Hammering, waiting for a prompt to appear.
    Hammering,
    /// A prompt tail is present; waiting for the line to go quiet.
    Settling {
        last_byte: Instant,
    },
    /// A bare CR was sent to flush the hammered bytes; waiting for the prompt
    /// it should print in response.
    Confirming {
        sent: Instant,
    },
    /// `commands[index]` was sent; waiting for the prompt that follows it.
    Running {
        index: usize,
        sent: Instant,
    },
    Finished,
}

pub struct Interrupter {
    cfg: Config,
    phase: Phase,
    started: Instant,
    /// The unterminated tail of the current line, ANSI stripped. Reset on
    /// every send so a prompt we have already acted on cannot match again.
    tail: String,
    /// True once the bootloader has handed off, cleared by a fresh banner.
    /// While set, a `#` prompt is treated as a Linux shell and ignored.
    past_bootloader: bool,
    /// So the Linux-prompt explanation is given once rather than per chunk.
    warned_past_bootloader: bool,
    armed: bool,
}

impl Interrupter {
    pub fn new(cfg: Config, now: Instant) -> Self {
        Self {
            cfg,
            phase: Phase::Hammering,
            started: now,
            tail: String::new(),
            past_bootloader: false,
            warned_past_bootloader: false,
            armed: false,
        }
    }

    /// True once the sequence is over, either way.
    pub fn is_finished(&self) -> bool {
        self.phase == Phase::Finished
    }

    /// The opening moves: start hammering before anything else happens, and
    /// tell the operator what to do with the window that opens.
    pub fn begin(&mut self) -> Vec<Action> {
        self.armed = true;
        let mut out = vec![Action::StartHammer];
        if self.cfg.reset_line != ResetLine::None {
            // Say what is about to happen BEFORE it happens. Driving the line
            // can fail (a USB adapter that does not expose it, a pty), and
            // reading that failure before reading the intent is confusing.
            out.push(Action::Note(format!(
                "hammering {} and pulsing {} to reset the board",
                describe(&self.cfg.key),
                match self.cfg.reset_line {
                    ResetLine::Dtr => "DTR",
                    ResetLine::Rts => "RTS",
                    ResetLine::None => unreachable!(),
                }
            )));
            out.push(Action::PulseReset);
        } else {
            out.push(Action::Note(format!(
                "hammering {} now: POWER-CYCLE THE BOARD. The key has to be waiting in the \
                 UART before U-Boot looks, so this only works if the reset happens after \
                 this line.",
                describe(&self.cfg.key)
            )));
        }
        out
    }

    /// Feed received bytes (empty on an idle tick) and get the next actions.
    pub fn poll(&mut self, now: Instant, rx: &[u8]) -> Vec<Action> {
        if self.phase == Phase::Finished {
            return Vec::new();
        }
        let mut out = Vec::new();
        if !rx.is_empty() {
            self.absorb(rx);
        }

        // The overall deadline applies in every phase but the last: a board
        // that hands us a prompt and then reboots forever should still stop.
        if now.duration_since(self.started) > self.cfg.timeout {
            self.phase = Phase::Finished;
            out.push(Action::StopHammer);
            out.push(Action::GaveUp(self.missed_explanation()));
            return out;
        }

        loop {
            let before = self.phase.clone();
            match self.phase.clone() {
                Phase::Hammering => {
                    if self.prompt_visible() {
                        if self.past_bootloader {
                            if !self.warned_past_bootloader {
                                self.warned_past_bootloader = true;
                                out.push(Action::Note(
                                    "a prompt appeared after the kernel handoff, so it is a \
                                     Linux shell, not U-Boot. Still hammering for the next \
                                     boot: power-cycle again."
                                        .to_string(),
                                ));
                            }
                        } else {
                            out.push(Action::StopHammer);
                            out.push(Action::Note(format!(
                                "prompt reached: {:?}. Autoboot was interrupted.",
                                self.tail.trim()
                            )));
                            self.phase = Phase::Settling { last_byte: now };
                        }
                    }
                }
                Phase::Settling { last_byte } => {
                    if !rx.is_empty() {
                        self.phase = Phase::Settling { last_byte: now };
                    } else if now.duration_since(last_byte) >= self.cfg.settle {
                        // A bare CR. It flushes the hammered bytes (spaces are
                        // a no-op line) and makes the board print a fresh
                        // prompt, which is the confirmation that we are really
                        // at one and not looking at a progress line that
                        // happened to end in `#`.
                        out.push(self.send(b"\r".to_vec()));
                        self.phase = Phase::Confirming { sent: now };
                    }
                }
                Phase::Confirming { sent } => {
                    if self.prompt_visible() && !self.past_bootloader {
                        out.extend(self.start_command(0, now));
                    } else if now.duration_since(sent) > self.cfg.prompt_wait {
                        // Not a prompt after all, or the board reset under us.
                        // Re-arm rather than abandon: a false positive should
                        // cost one round trip, not the session.
                        out.push(Action::Note(
                            "no prompt came back, so that was not one. Re-arming.".to_string(),
                        ));
                        out.push(Action::StartHammer);
                        self.phase = Phase::Hammering;
                    }
                }
                Phase::Running { index, sent } => {
                    if self.prompt_visible() && !self.past_bootloader {
                        let next = index + 1;
                        if next < self.cfg.commands.len() {
                            out.extend(self.start_command(next, now));
                        } else {
                            self.phase = Phase::Finished;
                            out.push(Action::Note(
                                "environment captured. The prompt is yours; the verdict is \
                                 below."
                                    .to_string(),
                            ));
                            out.push(Action::Done);
                        }
                    } else if now.duration_since(sent) > self.cfg.prompt_wait {
                        out.push(Action::Note(format!(
                            "no prompt after {:?}; the board may have reset. Re-arming.",
                            self.cfg.commands[index]
                        )));
                        out.push(Action::StartHammer);
                        self.phase = Phase::Hammering;
                    }
                }
                Phase::Finished => {}
            }
            // Phases can advance more than once per poll (settle expiring and
            // the prompt already being visible, say), so run until stable.
            if self.phase == before {
                break;
            }
        }
        out
    }

    fn start_command(&mut self, index: usize, now: Instant) -> Vec<Action> {
        let cmd = self.cfg.commands[index].clone();
        let mut out = vec![Action::Note(format!("typing `{cmd}`"))];
        out.push(self.send(format!("{cmd}\r").into_bytes()));
        self.phase = Phase::Running { index, sent: now };
        out
    }

    /// Emit a send and clear the tail, so the prompt that prompted this send
    /// cannot immediately satisfy the wait for the NEXT one.
    fn send(&mut self, bytes: Vec<u8>) -> Action {
        debug_assert!(
            !bytes.is_empty(),
            "an empty send would clear the tail for nothing"
        );
        self.tail.clear();
        Action::Send(bytes)
    }

    /// Track the unterminated tail and the two latches, without keeping the
    /// whole session: the analyzer already has that.
    fn absorb(&mut self, rx: &[u8]) {
        let text = String::from_utf8_lossy(rx);
        for chunk in text.split_inclusive(['\n', '\r']) {
            if chunk.ends_with('\n') || chunk.ends_with('\r') {
                let line = format!("{}{}", self.tail, chunk);
                self.note_markers(&line);
                self.tail.clear();
            } else {
                self.tail.push_str(chunk);
                // A prompt is short. Anything longer is output that has not
                // ended yet, and letting it grow unbounded would turn a chatty
                // board into a memory leak.
                if self.tail.len() > 512 {
                    let keep = self.tail.len() - 256;
                    self.tail = self.tail.split_off(keep);
                }
                let tail = self.tail.clone();
                self.note_markers(&tail);
            }
        }
    }

    fn note_markers(&mut self, line: &str) {
        if HANDOFF.iter().any(|m| line.contains(m)) {
            self.past_bootloader = true;
        } else if BOOTLOADER_BANNER.iter().any(|m| line.contains(m)) {
            // A new cycle: whatever we concluded about the last one no longer
            // applies.
            self.past_bootloader = false;
            self.warned_past_bootloader = false;
        }
    }

    fn prompt_visible(&self) -> bool {
        is_prompt_tail(&self.tail)
    }

    fn missed_explanation(&self) -> String {
        format!(
            "autoboot was not interrupted within {}s, so nothing was assessed.\n  \
             The usual causes, in order: the board was not reset while this was hammering \
             (the key must already be in the UART when U-Boot looks); the console is on a \
             different UART than {:?} suggests; the baud rate is wrong, so the board saw \
             noise rather than the key; or the build needs a specific key \
             (CONFIG_AUTOBOOT_KEYED), which --interrupt-key can send.",
            self.cfg.timeout.as_secs(),
            describe(&self.cfg.key),
        )
    }
}

/// Does this unterminated tail look like a prompt waiting for input?
pub fn is_prompt_tail(tail: &str) -> bool {
    let clean = RE_ANSI.replace_all(tail, "");
    let clean = clean.trim_start_matches(['\r', '\n']);
    if clean.len() > 64 {
        return false;
    }
    match RE_PROMPT_TAIL.captures(clean) {
        None => false,
        Some(caps) => match caps.get(1) {
            // The bare `=>` form: unambiguous.
            None => true,
            // A named prompt. `Loading: #` is a TFTP progress line, not a
            // board called "Loading:", and a label ending in a colon is the
            // cheap way to tell them apart. A real false positive here costs
            // one round trip, since the prompt has to come back to be
            // believed.
            Some(name) => !name.as_str().ends_with(':'),
        },
    }
}

fn describe(key: &[u8]) -> String {
    match key {
        [b' '] => "space".to_string(),
        [0x1b] => "ESC".to_string(),
        [0x03] => "Ctrl-C".to_string(),
        other => match std::str::from_utf8(other) {
            Ok(s) if s.chars().all(|c| c.is_ascii_graphic()) => format!("{s:?}"),
            _ => other
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            settle: Duration::from_millis(100),
            prompt_wait: Duration::from_millis(500),
            timeout: Duration::from_secs(10),
            commands: vec!["printenv".into(), "bdinfo".into()],
            ..Config::default()
        }
    }

    fn sends(actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_bare_uboot_prompt_is_recognised() {
        for tail in [
            "=> ",
            "=>",
            "  => ",
            "U-Boot> ",
            "uboot# ",
            "RTL8672 # ",
            "board=> ",
        ] {
            assert!(is_prompt_tail(tail), "{tail:?} should be a prompt");
        }
    }

    /// The false positive that actually happens. U-Boot prints one `#` per
    /// block during a TFTP or flash transfer, so mid-transfer the unterminated
    /// tail is `Loading: #`.
    #[test]
    fn a_transfer_progress_line_is_not_a_prompt() {
        for tail in [
            "Loading: #",
            "Loading: ####",
            "Loading: #################",
            "## Booting kernel from Legacy Image at 82000000 ...",
            "Uncompressing Linux... ",
            "Hit any key to stop autoboot:  2",
            "bootcmd=bootm 0x82000000",
        ] {
            assert!(!is_prompt_tail(tail), "{tail:?} should not be a prompt");
        }
    }

    #[test]
    fn escape_sequences_do_not_hide_a_prompt() {
        assert!(is_prompt_tail("\x1b[0m=> "));
        assert!(is_prompt_tail("\x1b[1;32mRTL8672 # \x1b[0m"));
    }

    #[test]
    fn a_long_tail_is_output_not_a_prompt() {
        let long = format!("{}# ", "x".repeat(80));
        assert!(!is_prompt_tail(&long));
    }

    /// The safety property. A hammered CR executes whatever the other hammered
    /// bytes spell, on hardware that is not ours.
    #[test]
    fn a_key_containing_a_newline_is_refused() {
        for spec in ["\r", "\n", "a\rb", "0x0d", "0x200a"] {
            let err = parse_key(spec).expect_err("should refuse");
            assert!(err.contains("CR or LF"), "{spec:?}: {err}");
        }
    }

    #[test]
    fn key_specs_parse_to_the_documented_bytes() {
        assert_eq!(parse_key("space").unwrap(), b" ");
        assert_eq!(parse_key("esc").unwrap(), vec![0x1b]);
        assert_eq!(parse_key("ctrl-c").unwrap(), vec![0x03]);
        assert_eq!(parse_key("0x1b").unwrap(), vec![0x1b]);
        assert_eq!(parse_key("stop").unwrap(), b"stop");
        assert!(parse_key("0xZZ").is_err());
        assert!(parse_key("0x1").is_err());
    }

    #[test]
    fn hammering_starts_before_anything_is_observed() {
        // The whole design rests on this: the key has to be on its way before
        // the board is looked at, so StartHammer is the first action and it
        // does not depend on having seen any bytes.
        let t0 = Instant::now();
        let mut it = Interrupter::new(cfg(), t0);
        let first = it.begin();
        assert_eq!(first[0], Action::StartHammer);
        assert!(matches!(first[1], Action::Note(_)));
        assert!(sends(&first).is_empty(), "nothing is typed before a prompt");
    }

    #[test]
    fn the_happy_path_runs_every_command_in_order() {
        let t0 = Instant::now();
        let mut it = Interrupter::new(cfg(), t0);
        it.begin();

        // Autoboot interrupted: a prompt with no newline after it.
        let a = it.poll(t0, b"Hit any key to stop autoboot:  2\r\n=> ");
        assert!(a.contains(&Action::StopHammer), "{a:?}");
        assert!(
            sends(&a).is_empty(),
            "nothing typed until the line is quiet"
        );

        // Quiet for the settle window: a bare CR to flush the hammered spaces
        // and make the board prove it is at a prompt.
        let a = it.poll(t0 + Duration::from_millis(150), b"");
        assert_eq!(sends(&a), vec!["\r"]);

        // The board prints a fresh prompt, so the first command goes out.
        let a = it.poll(t0 + Duration::from_millis(160), b"\r\n=> ");
        assert_eq!(sends(&a), vec!["printenv\r"]);

        // printenv output, then the prompt again.
        let a = it.poll(
            t0 + Duration::from_millis(200),
            b"bootdelay=2\r\nEnvironment size: 90/65532 bytes\r\n=> ",
        );
        assert_eq!(sends(&a), vec!["bdinfo\r"]);

        let a = it.poll(
            t0 + Duration::from_millis(300),
            b"arch_number = 0x00000c\r\n=> ",
        );
        assert!(a.contains(&Action::Done), "{a:?}");
        assert!(it.is_finished());
        assert!(it.poll(t0 + Duration::from_millis(400), b"=> ").is_empty());
    }

    /// Without clearing the tail on every send, one visible prompt would
    /// satisfy the wait for all of them and the whole command list would go
    /// out in a single burst, interleaved with the board's replies.
    #[test]
    fn a_stale_prompt_does_not_advance_the_next_command() {
        let t0 = Instant::now();
        let mut it = Interrupter::new(cfg(), t0);
        it.begin();
        it.poll(t0, b"=> ");
        it.poll(t0 + Duration::from_millis(150), b"");
        let a = it.poll(t0 + Duration::from_millis(160), b"\r\n=> ");
        assert_eq!(sends(&a), vec!["printenv\r"]);
        // No new bytes: the prompt we just used must not count again.
        let a = it.poll(t0 + Duration::from_millis(170), b"");
        assert!(sends(&a).is_empty(), "{a:?}");
    }

    /// A `#` prompt after the kernel has started is a root shell. Typing
    /// `printenv` into it yields a shell environment and a confident, wrong
    /// verdict about the boot chain.
    #[test]
    fn a_linux_prompt_is_not_mistaken_for_u_boot() {
        let t0 = Instant::now();
        let mut it = Interrupter::new(cfg(), t0);
        it.begin();
        let a = it.poll(t0, b"Starting kernel ...\r\n\r\nLinux version 5.10\r\n");
        assert!(sends(&a).is_empty());
        // A bare `# ` is not accepted as a prompt at all, which is the first
        // line of defence. This is the shape that gets past that: a
        // distro prompt with a hostname in it.
        assert!(
            !is_prompt_tail("# "),
            "a bare hash is too ambiguous to act on"
        );
        let a = it.poll(
            t0 + Duration::from_millis(10),
            b"BusyBox v1.35\r\nroot@openwrt:/# ",
        );
        assert!(sends(&a).is_empty(), "typed into a Linux shell: {a:?}");
        assert!(!a.contains(&Action::StopHammer), "stopped hammering: {a:?}");
        assert!(
            matches!(a.first(), Some(Action::Note(n)) if n.contains("Linux shell")),
            "{a:?}"
        );

        // The operator power-cycles. A fresh bootloader banner clears the
        // latch, and the next prompt is taken.
        let a = it.poll(
            t0 + Duration::from_millis(20),
            b"\r\nU-Boot 2020.10\r\nDRAM:  128 MiB\r\n=> ",
        );
        assert!(a.contains(&Action::StopHammer), "{a:?}");
    }

    /// A prompt that does not answer should cost one round trip, not the
    /// attempt: the usual cause is a board that reset under us, or a watchdog,
    /// and the window can still be caught on the next cycle. Giving up on the
    /// first disappointment would make this useless on exactly the flaky
    /// hardware it is for.
    #[test]
    fn a_prompt_that_does_not_answer_re_arms_rather_than_giving_up() {
        let t0 = Instant::now();
        let mut it = Interrupter::new(cfg(), t0);
        it.begin();
        it.poll(t0, b"=> ");
        let a = it.poll(t0 + Duration::from_millis(150), b"");
        assert_eq!(sends(&a), vec!["\r"]);
        // Silence: the board went away between the prompt and the CR.
        let a = it.poll(t0 + Duration::from_millis(800), b"");
        assert!(a.contains(&Action::StartHammer), "{a:?}");
        assert!(
            !a.iter().any(|x| matches!(x, Action::GaveUp(_))),
            "gave up on one false positive: {a:?}"
        );
    }

    #[test]
    fn the_window_being_missed_is_reported_not_swallowed() {
        let t0 = Instant::now();
        let mut it = Interrupter::new(cfg(), t0);
        it.begin();
        let a = it.poll(t0 + Duration::from_secs(11), b"");
        assert!(a.contains(&Action::StopHammer), "{a:?}");
        let reason = a
            .iter()
            .find_map(|x| match x {
                Action::GaveUp(r) => Some(r.clone()),
                _ => None,
            })
            .expect("a reason");
        // The message has to be usable by someone standing at a bench with a
        // board that did not stop.
        for expected in [
            "not reset",
            "baud",
            "CONFIG_AUTOBOOT_KEYED",
            "different UART",
        ] {
            assert!(reason.contains(expected), "missing {expected:?}: {reason}");
        }
        assert!(it.is_finished());
    }

    #[test]
    fn a_reset_line_is_pulsed_before_the_board_is_looked_at() {
        let t0 = Instant::now();
        let mut it = Interrupter::new(
            Config {
                reset_line: ResetLine::Dtr,
                ..cfg()
            },
            t0,
        );
        let a = it.begin();
        assert_eq!(a[0], Action::StartHammer, "hammer first, then reset: {a:?}");
        // The explanation comes before the action, so a failure to drive the
        // line reads as a failure of something already announced.
        let note = a
            .iter()
            .position(|x| matches!(x, Action::Note(_)))
            .expect("a note");
        let pulse = a
            .iter()
            .position(|x| *x == Action::PulseReset)
            .expect("the pulse");
        assert!(note < pulse, "{a:?}");
    }
}

/// A simulated board, and the clock, so the timing claim in this module's
/// header is a test rather than an assertion.
///
/// The thing being modelled is the case that makes the obvious design wrong: a
/// board whose autoboot check runs exactly ONCE, `check_at` after reset. Before
/// that instant the board is emitting boot output; at that instant it looks at
/// its receiver; after it, the board is either at a prompt or gone into the
/// kernel, with nothing an operator can do about it.
#[cfg(test)]
mod sim {
    use super::*;

    pub struct OneShotBoard {
        /// When the single `tstc()` happens, measured from reset.
        pub check_at: Duration,
        /// Bytes the tool has sent that the board has not consumed yet. This is
        /// the UART receive buffer, and it is the whole reason a key sent
        /// EARLIER than the check still counts AT the check.
        pending: Vec<u8>,
        checked: bool,
        stopped: bool,
        /// The line being typed at the prompt.
        line: String,
        pub commands_seen: Vec<String>,
    }

    impl OneShotBoard {
        pub fn new(check_at: Duration) -> Self {
            Self {
                check_at,
                pending: Vec::new(),
                checked: false,
                stopped: false,
                line: String::new(),
                commands_seen: Vec::new(),
            }
        }

        pub fn recv(&mut self, bytes: &[u8]) {
            self.pending.extend_from_slice(bytes);
        }

        /// Advance the board to `t` and return whatever it emitted.
        pub fn tick(&mut self, t: Duration) -> Vec<u8> {
            if !self.checked && t >= self.check_at {
                self.checked = true;
                // U-Boot prints the countdown and looks at the receiver in the
                // same breath. A tool that waits to SEE this line and then
                // sends a key is sending it after this moment has passed.
                let mut out = b"Hit any key to stop autoboot:  0\r\n".to_vec();
                self.stopped = !self.pending.is_empty();
                self.pending.clear();
                if self.stopped {
                    out.extend_from_slice(b"=> ");
                } else {
                    out.extend_from_slice(b"Starting kernel ...\r\n");
                }
                return out;
            }
            if !self.stopped {
                return Vec::new();
            }
            // At the prompt: accumulate typed bytes, act on CR.
            let mut out = Vec::new();
            let pending = std::mem::take(&mut self.pending);
            for b in pending {
                if b == b'\r' || b == b'\n' {
                    let cmd = self.line.trim().to_string();
                    self.line.clear();
                    out.extend_from_slice(b"\r\n");
                    if !cmd.is_empty() {
                        self.commands_seen.push(cmd.clone());
                    }
                    match cmd.as_str() {
                        "" => {}
                        "printenv" => out.extend_from_slice(
                            b"bootdelay=0\r\nbootcmd=bootm 0x82000000\r\n\
                              Environment size: 48/65532 bytes\r\n",
                        ),
                        other => out
                            .extend_from_slice(format!("Unknown command '{other}'\r\n").as_bytes()),
                    }
                    out.extend_from_slice(b"=> ");
                } else {
                    self.line.push(b as char);
                }
            }
            out
        }
    }

    pub struct Outcome {
        pub done: bool,
        pub gave_up: Option<String>,
        pub commands: Vec<String>,
        /// When the hammer was first armed, or None if it never was.
        pub armed_at: Option<Duration>,
    }

    /// Run the interrupter against a board for three simulated seconds, one
    /// millisecond at a time. `arm_on_banner` models the WRONG design: instead
    /// of hammering from the start, wait until the countdown has been seen.
    pub fn run(board: &mut OneShotBoard, cfg: Config, arm_on_banner: bool) -> Outcome {
        let base = Instant::now();
        let mut it = Interrupter::new(cfg.clone(), base);
        let mut armed = false;
        let mut armed_at = None;
        let mut done = false;
        let mut gave_up = None;
        let mut hammer_due = Duration::ZERO;

        let apply = |actions: Vec<Action>,
                     board: &mut OneShotBoard,
                     armed: &mut bool,
                     armed_at: &mut Option<Duration>,
                     done: &mut bool,
                     gave_up: &mut Option<String>,
                     t: Duration| {
            for a in actions {
                match a {
                    Action::StartHammer => {
                        if !*armed {
                            *armed = true;
                            if armed_at.is_none() {
                                *armed_at = Some(t);
                            }
                        }
                    }
                    Action::StopHammer => *armed = false,
                    Action::Send(bytes) => board.recv(&bytes),
                    Action::Done => *done = true,
                    Action::GaveUp(r) => *gave_up = Some(r),
                    Action::Note(_) | Action::PulseReset => {}
                }
            }
        };

        let opening = it.begin();
        if arm_on_banner {
            // The reactive design: discard the instruction to start hammering
            // and wait for evidence instead.
            let filtered: Vec<Action> = opening
                .into_iter()
                .filter(|a| *a != Action::StartHammer)
                .collect();
            apply(
                filtered,
                board,
                &mut armed,
                &mut armed_at,
                &mut done,
                &mut gave_up,
                Duration::ZERO,
            );
        } else {
            apply(
                opening,
                board,
                &mut armed,
                &mut armed_at,
                &mut done,
                &mut gave_up,
                Duration::ZERO,
            );
        }

        for ms in 0..3000u64 {
            let t = Duration::from_millis(ms);
            if armed && t >= hammer_due {
                board.recv(&cfg.key);
                hammer_due = t + cfg.interval;
            }
            let rx = board.tick(t);
            if arm_on_banner && !armed && String::from_utf8_lossy(&rx).contains("Hit any key") {
                // Seen it. Start hammering now, which is the point: "now" is
                // already too late.
                armed = true;
                armed_at = Some(t);
            }
            let actions = it.poll(base + t, &rx);
            apply(
                actions,
                board,
                &mut armed,
                &mut armed_at,
                &mut done,
                &mut gave_up,
                t,
            );
            if done || gave_up.is_some() {
                break;
            }
        }
        Outcome {
            done,
            gave_up,
            commands: board.commands_seen.clone(),
            armed_at,
        }
    }
}

#[cfg(test)]
mod timing_tests {
    use super::sim::{self, OneShotBoard};
    use super::*;

    fn cfg() -> Config {
        Config {
            settle: Duration::from_millis(20),
            prompt_wait: Duration::from_millis(500),
            timeout: Duration::from_secs(2),
            commands: vec!["printenv".into()],
            interval: Duration::from_millis(5),
            ..Config::default()
        }
    }

    /// The claim this whole design rests on: hammering from the start catches a
    /// window that is one check wide, wherever in the boot that check lands.
    #[test]
    fn hammering_from_the_start_catches_a_single_check() {
        for ms in [1u64, 2, 7, 13, 60, 250, 900] {
            let mut board = OneShotBoard::new(Duration::from_millis(ms));
            let out = sim::run(&mut board, cfg(), false);
            assert!(
                out.done,
                "missed a check at {ms}ms: gave up with {:?}",
                out.gave_up
            );
            assert_eq!(out.commands, vec!["printenv"], "at {ms}ms");
            assert_eq!(out.armed_at, Some(Duration::ZERO), "at {ms}ms");
        }
    }

    /// The contrast, and the reason the hammer does not wait for evidence.
    /// This asserts the physics of the simulated board rather than this
    /// module's logic: by the time the countdown has crossed the wire, the
    /// board has already looked at its receiver and found it empty.
    #[test]
    fn waiting_to_see_the_countdown_misses_the_window() {
        let mut board = OneShotBoard::new(Duration::from_millis(7));
        let out = sim::run(&mut board, cfg(), true);
        assert!(!out.done, "a reactive key somehow caught a one-shot check");
        assert!(out.gave_up.is_some(), "it should report the miss, not hang");
        assert!(out.commands.is_empty(), "nothing should have been typed");
    }

    /// A board that boots straight past with no interruptible window at all
    /// has to be reported, not quietly tolerated.
    #[test]
    fn a_board_that_never_stops_is_reported() {
        let mut board = OneShotBoard::new(Duration::from_secs(30));
        let out = sim::run(&mut board, cfg(), false);
        assert!(!out.done);
        assert!(out.gave_up.expect("a reason").contains("not interrupted"));
    }
}
