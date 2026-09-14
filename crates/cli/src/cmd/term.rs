//! `bootintel term <port>` — interactive UART terminal.
//!
//! Picocom-shaped: raw bytes stream to stdout, keystrokes stream to
//! serial. Ctrl-A prefixes a small command set (quit, help). Optional
//! log file captures raw serial bytes in parallel.
//!
//! For live detector analysis + server-side `--api` integration on
//! the interactive stream, see the `analyze` subcommand instead.

use anyhow::{bail, Result};
use clap::Args as ClapArgs;
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::path::PathBuf;

use crate::term::hotkey::EscapePrefix;
use crate::term::logfile::LogFileMode;
use crate::term::run::{run_session, validate_port_hint, TermOptions};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Serial port device (e.g. /dev/ttyUSB0 on Linux, /dev/tty.usbserial-* on macOS, COM3 on Windows).
    #[arg(value_name = "PORT")]
    port: String,

    /// Baud rate. Reads $BOOTINTEL_BAUD when unset.
    #[arg(long, default_value_t = 115200, env = "BOOTINTEL_BAUD")]
    baud: u32,

    /// Data bits (5, 6, 7, 8).
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u8).range(5..=8))]
    data_bits: u8,

    /// Parity (none, odd, even).
    #[arg(long, default_value = "none", value_parser = ["none", "odd", "even"])]
    parity: String,

    /// Stop bits (1 or 2).
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=2))]
    stop_bits: u8,

    /// Flow control (none, software, hardware).
    #[arg(long, default_value = "none", value_parser = ["none", "software", "hardware"])]
    flow_control: String,

    /// Write raw serial bytes to this file in parallel with the terminal.
    /// If the file exists, bootintel refuses to open it — use --log-append
    /// to keep the existing content or --log-overwrite to discard it.
    /// Reads $BOOTINTEL_LOG_FILE when unset.
    #[arg(long, value_name = "PATH", env = "BOOTINTEL_LOG_FILE")]
    log_file: Option<PathBuf>,

    /// If the log file exists, append instead of erroring out.
    #[arg(long, conflicts_with = "log_overwrite")]
    log_append: bool,

    /// If the log file exists, truncate + start fresh. Opt-in destructive.
    #[arg(long)]
    log_overwrite: bool,

    /// Prefix each captured line with an ISO-8601 UTC timestamp
    /// (`[2026-08-24T09:12:03.487Z] ...`). Off by default so a
    /// straight capture is byte-identical to what the device
    /// emitted; opt-in when correlating events across devices or
    /// annotating a boot trace for a bug report.
    /// Reads $BOOTINTEL_LOG_TIMESTAMPS (any value = on) when unset.
    #[arg(long, env = "BOOTINTEL_LOG_TIMESTAMPS")]
    log_timestamps: bool,

    /// Echo typed keystrokes to stdout locally (default: off — most
    /// devices echo back through the serial port, so local echo
    /// causes double-display). Runtime-toggle mid-session with Ctrl-A e.
    #[arg(long)]
    local_echo: bool,

    /// Line-ending conversion applied to bytes sent to the serial port
    /// when Enter is pressed (or when Ctrl-A p pastes a file).
    /// Default `passthrough` = whatever crossterm decoded from Enter.
    /// Devices differ: U-Boot wants `cr`, most Linux prompts want `lf`,
    /// legacy modems want `crlf`. Cycle mid-session with Ctrl-A n.
    #[arg(long, value_enum, default_value_t = crate::term::newline::NewlineMode::Passthrough)]
    newline: crate::term::newline::NewlineMode,

    /// Line-ending mapping applied to bytes RECEIVED from the port
    /// before display (and analyzer). Fixes devices that emit bare
    /// CR after every line (terminal overwrites the same row). Log
    /// file always stores raw bytes regardless. Cycle with Ctrl-A m.
    #[arg(long, value_enum, default_value_t = crate::term::newline::RxNewlineMode::None)]
    rx_newline: crate::term::newline::RxNewlineMode,

    /// Byte sent when the Backspace key is pressed. Most modern
    /// prompts want `del` (0x7f); older U-Boot / some ROM monitors
    /// want `bs` (0x08). Cycle mid-session with Ctrl-A k if wrong.
    #[arg(long, value_enum, default_value_t = crate::term::hotkey::BackspaceMode::Del)]
    backspace: crate::term::hotkey::BackspaceMode,

    /// Bind a function key to a byte string, e.g. `--macro F1=help\r`.
    /// Repeatable: `--macro F1=printenv\r --macro F2=reset\r`.
    /// Escape sequences: `\r \n \t \0 \\ \xHH`. CLI-supplied macros
    /// override the same key in --macros-file. Cycles through the TX
    /// newline mode same as typed keystrokes.
    #[arg(long, value_name = "Fn=VALUE", action = clap::ArgAction::Append)]
    macro_: Vec<String>,

    /// Read macro bindings from this file (one `Fn=value` per line,
    /// blank lines + `#` comments allowed). Default:
    /// $XDG_CONFIG_HOME/bootintel/macros (Unix) or
    /// %APPDATA%\bootintel\macros (Windows) if it exists; unset
    /// otherwise. Set to /dev/null (or an empty file) to disable.
    #[arg(long, value_name = "PATH")]
    macros_file: Option<std::path::PathBuf>,

    /// Hotkey escape prefix. Default: ctrl-a. Change if you're inside
    /// a tmux/screen session whose prefix also is Ctrl-A — otherwise
    /// the prefix gets eaten before bootintel sees it. Same convention
    /// as picocom --escape. Accepts: ctrl-a..ctrl-z, c-a..c-z, ^a..^z.
    /// Reads $BOOTINTEL_ESCAPE when unset.
    #[arg(
        long,
        value_name = "KEY",
        default_value = "ctrl-a",
        env = "BOOTINTEL_ESCAPE"
    )]
    escape: String,
}

pub fn run(args: Args) -> Result<()> {
    validate_port_hint(&args.port)?;
    if (args.log_append || args.log_overwrite) && args.log_file.is_none() {
        bail!(
            "--log-append / --log-overwrite require --log-file to pick a target path.\n  example: bootintel term /dev/ttyUSB0 --log-file capture.log --log-append"
        );
    }
    let log_mode = if args.log_append {
        LogFileMode::Append
    } else if args.log_overwrite {
        LogFileMode::Overwrite
    } else {
        LogFileMode::Refuse
    };
    let escape_prefix =
        EscapePrefix::parse(&args.escape).map_err(|e| anyhow::anyhow!("--escape: {e}"))?;
    let opts = TermOptions {
        port_name: args.port,
        baud: args.baud,
        data_bits: match args.data_bits {
            5 => DataBits::Five,
            6 => DataBits::Six,
            7 => DataBits::Seven,
            _ => DataBits::Eight,
        },
        parity: match args.parity.as_str() {
            "odd" => Parity::Odd,
            "even" => Parity::Even,
            _ => Parity::None,
        },
        stop_bits: if args.stop_bits == 2 {
            StopBits::Two
        } else {
            StopBits::One
        },
        flow_control: match args.flow_control.as_str() {
            "software" => FlowControl::Software,
            "hardware" => FlowControl::Hardware,
            _ => FlowControl::None,
        },
        log_file: args.log_file,
        log_mode,
        log_timestamps: args.log_timestamps,
        local_echo: args.local_echo,
        newline_mode: args.newline,
        rx_newline_mode: args.rx_newline,
        backspace_mode: args.backspace,
        macros: build_macros(&args.macros_file, &args.macro_)?,
        // Term mode never runs the analyzer. Users who want live
        // analysis should use `bootintel analyze` instead.
        analyzer: None,
        // Nor does it wire the api. Ctrl-A f prints a hint pointing
        // at `bootintel analyze --api` if the user tries anyway.
        api: None,
        escape_prefix,
    };
    run_session(opts)
}

/// Merge macro bindings from --macros-file (or the default config
/// path if the flag was omitted) with any --macro CLI overrides.
/// Shared with `cmd::analyze` so both entrypoints get identical
/// resolution semantics.
pub(crate) fn build_macros(
    file_arg: &Option<std::path::PathBuf>,
    cli_specs: &[String],
) -> Result<crate::term::macros::MacroTable> {
    let effective = file_arg
        .clone()
        .or_else(crate::term::macros::default_config_path);
    crate::term::macros::build(effective.as_deref(), cli_specs)
        .map_err(|e| anyhow::anyhow!("--macro/--macros-file: {e}"))
}
