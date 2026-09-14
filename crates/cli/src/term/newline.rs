//! Line-ending conversion applied to bytes going TO the serial port.
//!
//! Devices differ: U-Boot expects a bare CR (0x0D), most Linux
//! login/shell prompts want a bare LF (0x0A), some legacy modems
//! and boot ROMs want CRLF. Rather than force the user to guess at
//! startup, we cycle between the three modes at runtime via
//! Ctrl-A n; startup can pin one via --newline cr|lf|crlf.
//!
//! `Passthrough` is the default — send whatever byte the crossterm
//! layer decoded from the Enter key (LF on Unix, CR on Windows).
//! That matches picocom's default behavior and avoids surprising
//! anyone who's happy with the current stream.

use clap::ValueEnum;

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum NewlineMode {
    /// Send whatever byte crossterm produced for Enter (LF on Unix).
    /// Same as `bootintel term` v0.1.x — no rewriting.
    Passthrough,
    /// Rewrite every 0x0D / 0x0A / 0x0D0A in outbound bytes to a
    /// bare LF (0x0A). Matches most modern Linux prompts.
    Lf,
    /// Rewrite to a bare CR (0x0D). U-Boot + a lot of embedded ROMs.
    Cr,
    /// Rewrite to CR+LF (0x0D 0x0A). Legacy modems, some Windows
    /// serial device drivers, DOS-era ROM monitors.
    Crlf,
}

impl NewlineMode {
    /// Human-readable label for the status line ("LF", "CR", "CRLF",
    /// "passthrough"). Kept short so it fits `[bootintel] newline: X`.
    pub fn label(self) -> &'static str {
        match self {
            NewlineMode::Passthrough => "passthrough",
            NewlineMode::Lf => "LF",
            NewlineMode::Cr => "CR",
            NewlineMode::Crlf => "CRLF",
        }
    }

    /// Next mode in the Ctrl-A n rotation. Passthrough is only
    /// startable via the CLI flag — the runtime cycle stays inside
    /// {LF, CR, CRLF} so a mis-toggle can never take you to the
    /// "who knows what byte" default in the middle of typing.
    pub fn next_in_cycle(self) -> Self {
        match self {
            NewlineMode::Passthrough | NewlineMode::Lf => NewlineMode::Crlf,
            NewlineMode::Crlf => NewlineMode::Cr,
            NewlineMode::Cr => NewlineMode::Lf,
        }
    }

    /// Rewrite `bytes` according to this mode: collapse any of
    /// {CR, LF, CRLF} sequences to the configured line ending.
    /// A raw stream with no line endings passes through unchanged
    /// regardless of mode. Passthrough is always a memcpy.
    pub fn rewrite(self, bytes: &[u8]) -> Vec<u8> {
        if matches!(self, NewlineMode::Passthrough) {
            return bytes.to_vec();
        }
        let replacement: &[u8] = match self {
            NewlineMode::Lf => b"\n",
            NewlineMode::Cr => b"\r",
            NewlineMode::Crlf => b"\r\n",
            NewlineMode::Passthrough => unreachable!(),
        };
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                out.extend_from_slice(replacement);
                i += 2;
            } else if b == b'\r' || b == b'\n' {
                out.extend_from_slice(replacement);
                i += 1;
            } else {
                out.push(b);
                i += 1;
            }
        }
        out
    }
}

/// Line-ending mapping applied to RX bytes (device → terminal) before
/// display + log. Solves the "device sends bare CR after every line
/// so the terminal keeps overwriting the same row" problem, and the
/// inverse: "device sends CRLF, terminal renders a double blank line".
#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum RxNewlineMode {
    /// Passthrough — display exactly what came off the wire. Default.
    None,
    /// Rewrite bare CR to LF. If the device sends CRLF, leave it alone
    /// (only bare CR gets the treatment). Makes bare-CR devices readable.
    CrToLf,
    /// Drop CR entirely. Turns CRLF → LF and bare CR → nothing. Useful
    /// when the terminal already inserts LFs and CR is visual noise.
    StripCr,
}

impl RxNewlineMode {
    pub fn label(self) -> &'static str {
        match self {
            RxNewlineMode::None => "none",
            RxNewlineMode::CrToLf => "CR→LF",
            RxNewlineMode::StripCr => "strip-CR",
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            RxNewlineMode::None => RxNewlineMode::CrToLf,
            RxNewlineMode::CrToLf => RxNewlineMode::StripCr,
            RxNewlineMode::StripCr => RxNewlineMode::None,
        }
    }

    /// Apply the mapping. `None` is a zero-copy identity (we still
    /// allocate a Vec so the caller's downstream code stays simple).
    /// Byte-oriented — safe on arbitrary chunk splits (a bare CR at
    /// the end of one chunk followed by LF at the start of the next
    /// gets treated as CRLF only if the caller reassembles first;
    /// otherwise as a bare CR + a bare LF, which for CrToLf still
    /// produces LF+LF = one blank line, a mild but not fatal artifact).
    pub fn rewrite(self, bytes: &[u8]) -> Vec<u8> {
        if matches!(self, RxNewlineMode::None) {
            return bytes.to_vec();
        }
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            match self {
                RxNewlineMode::CrToLf => {
                    if b == b'\r' {
                        // CRLF stays CRLF; bare CR becomes LF.
                        if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                            out.extend_from_slice(b"\r\n");
                            i += 2;
                            continue;
                        }
                        out.push(b'\n');
                    } else {
                        out.push(b);
                    }
                }
                RxNewlineMode::StripCr => {
                    if b != b'\r' {
                        out.push(b);
                    }
                }
                RxNewlineMode::None => unreachable!(),
            }
            i += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_is_identity() {
        let b = b"hello\r\nworld\n";
        assert_eq!(NewlineMode::Passthrough.rewrite(b), b.to_vec());
    }

    #[test]
    fn lf_normalizes_all_endings() {
        assert_eq!(
            NewlineMode::Lf.rewrite(b"a\r\nb\rc\n"),
            b"a\nb\nc\n".to_vec()
        );
    }

    #[test]
    fn cr_normalizes_all_endings() {
        assert_eq!(
            NewlineMode::Cr.rewrite(b"a\r\nb\rc\n"),
            b"a\rb\rc\r".to_vec()
        );
    }

    #[test]
    fn crlf_normalizes_all_endings() {
        // CRLF stays as CRLF; bare CR expands to CRLF; bare LF
        // expands to CRLF. No accidental CRCRLF from double-processing.
        assert_eq!(
            NewlineMode::Crlf.rewrite(b"a\r\nb\rc\n"),
            b"a\r\nb\r\nc\r\n".to_vec()
        );
    }

    #[test]
    fn no_endings_passes_regardless_of_mode() {
        for mode in [NewlineMode::Lf, NewlineMode::Cr, NewlineMode::Crlf] {
            assert_eq!(
                mode.rewrite(b"binary\x00\xff\x01"),
                b"binary\x00\xff\x01".to_vec()
            );
        }
    }

    #[test]
    fn rx_none_is_identity() {
        assert_eq!(
            RxNewlineMode::None.rewrite(b"a\rb\r\nc\n"),
            b"a\rb\r\nc\n".to_vec()
        );
    }

    #[test]
    fn rx_cr_to_lf_preserves_crlf_but_maps_bare_cr() {
        // Bare CR → LF; CRLF stays CRLF; bare LF untouched.
        assert_eq!(
            RxNewlineMode::CrToLf.rewrite(b"a\rb\r\nc\n"),
            b"a\nb\r\nc\n".to_vec()
        );
    }

    #[test]
    fn rx_strip_cr_drops_all_cr_bytes() {
        assert_eq!(
            RxNewlineMode::StripCr.rewrite(b"a\rb\r\nc\n"),
            b"ab\nc\n".to_vec()
        );
    }

    #[test]
    fn rx_cycle_visits_all_modes() {
        let m0 = RxNewlineMode::None;
        let m1 = m0.cycle();
        let m2 = m1.cycle();
        let m3 = m2.cycle();
        assert_eq!(m1, RxNewlineMode::CrToLf);
        assert_eq!(m2, RxNewlineMode::StripCr);
        assert_eq!(m3, RxNewlineMode::None);
    }

    #[test]
    fn cycle_stays_out_of_passthrough() {
        // Cycling from passthrough must land on a real mode (the
        // safety property so the user never mid-toggles to a
        // "who-knows-what-byte" state).
        assert!(!matches!(
            NewlineMode::Passthrough.next_in_cycle(),
            NewlineMode::Passthrough
        ));
        assert!(!matches!(
            NewlineMode::Lf.next_in_cycle(),
            NewlineMode::Passthrough
        ));
        assert!(!matches!(
            NewlineMode::Cr.next_in_cycle(),
            NewlineMode::Passthrough
        ));
        assert!(!matches!(
            NewlineMode::Crlf.next_in_cycle(),
            NewlineMode::Passthrough
        ));
    }
}
