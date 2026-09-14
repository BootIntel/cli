//! `bootintel analyze <port>` — interactive UART terminal with
//! live client-side detector analysis layered on top.
//!
//! Same serial-connection knobs as `bootintel term`; adds live
//! `[bootintel]` finding lines interleaved with the raw serial stream
//! and the four extra Ctrl-A hotkeys (l/c/s/u). Ctrl-A f triggers
//! full server-side analysis when --api / --api --preview is passed.

use anyhow::{bail, Result};
use clap::Args as ClapArgs;
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::path::PathBuf;

use crate::analyze::state::AnalyzeState;
use crate::term::hotkey::EscapePrefix;
use crate::term::logfile::LogFileMode;
use crate::term::run::{run_session, validate_port_hint, ApiConfig, TermOptions};

/// See cmd/scan.rs — same env var name for consistency.
const API_KEY_ENV: &str = "BOOTINTEL_API_KEY";

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

    /// Prefix each captured line with an ISO-8601 UTC timestamp.
    /// Off by default so the capture is byte-identical to the raw
    /// serial stream; opt-in for boot-trace annotation + cross-device
    /// correlation. Reads $BOOTINTEL_LOG_TIMESTAMPS when unset.
    #[arg(long, env = "BOOTINTEL_LOG_TIMESTAMPS")]
    log_timestamps: bool,

    /// Echo typed keystrokes to stdout locally (default: off).
    /// Runtime-toggle mid-session with Ctrl-A e.
    #[arg(long)]
    local_echo: bool,

    /// Line-ending conversion applied to bytes sent to the serial port.
    /// Default `passthrough`; see `bootintel term --help` for guidance.
    /// Runtime-cycle with Ctrl-A n.
    #[arg(long, value_enum, default_value_t = crate::term::newline::NewlineMode::Passthrough)]
    newline: crate::term::newline::NewlineMode,

    /// RX line-ending map (device → terminal). Default `none`.
    /// Runtime-cycle with Ctrl-A m.
    #[arg(long, value_enum, default_value_t = crate::term::newline::RxNewlineMode::None)]
    rx_newline: crate::term::newline::RxNewlineMode,

    /// Byte sent for Backspace. Default `del`. Cycle with Ctrl-A k.
    #[arg(long, value_enum, default_value_t = crate::term::hotkey::BackspaceMode::Del)]
    backspace: crate::term::hotkey::BackspaceMode,

    /// Bind a function key to a byte string, e.g. `--macro F1=help\r`.
    /// Repeatable. See `bootintel term --help` for full escape syntax.
    #[arg(long, value_name = "Fn=VALUE", action = clap::ArgAction::Append)]
    macro_: Vec<String>,

    /// Macro-bindings config file. Defaults to
    /// $XDG_CONFIG_HOME/bootintel/macros if it exists.
    #[arg(long, value_name = "PATH")]
    macros_file: Option<std::path::PathBuf>,

    /// Start with the live-analysis display suppressed. Detectors
    /// still run; findings accumulate silently until Ctrl-A l
    /// toggles the display back on. Useful when you want a clean
    /// terminal for a moment and plan to save findings via Ctrl-A s
    /// afterwards.
    #[arg(long)]
    no_live_display: bool,

    /// Arm Ctrl-A f for full server-side analysis (CVE matching +
    /// exploit paths + optional AI summary). Requires BOOTINTEL_API_KEY
    /// unless combined with --preview.
    #[arg(long)]
    api: bool,

    /// With --api: use the anonymous /preview endpoint. Free but
    /// rate-limited to 3 scans per IP per day.
    #[arg(long)]
    preview: bool,

    /// Override the API base URL. Defaults to <https://bootintel.com>
    /// (or $BOOTINTEL_API_BASE).
    #[arg(long, value_name = "URL")]
    api_base: Option<String>,

    /// Device name hint sent with each Ctrl-A f POST.
    #[arg(long, value_name = "NAME")]
    device_name: Option<String>,

    /// Render a ratatui split-screen dashboard instead of the
    /// picocom-shaped inline output. Requires the `tui` feature
    /// (enabled via `cargo build --features tui` or on
    /// pre-built binaries that ship with it). Same Ctrl-A hotkeys;
    /// PgUp / PgDn / Home / End scroll the serial pane.
    #[arg(long)]
    tui: bool,

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

    // Fail early if --tui was requested but the feature is off.
    // Better UX than "unknown flag" or a silent fallback.
    if args.tui {
        #[cfg(not(feature = "tui"))]
        bail!(
            "--tui requires this binary to be built with the `tui` feature. Rebuild with `cargo install --features tui` or use a release binary that includes it."
        );
    }

    if (args.log_append || args.log_overwrite) && args.log_file.is_none() {
        bail!(
            "--log-append / --log-overwrite require --log-file to pick a target path.\n  example: bootintel analyze /dev/ttyUSB0 --log-file capture.log --log-append"
        );
    }
    let log_mode = if args.log_append {
        LogFileMode::Append
    } else if args.log_overwrite {
        LogFileMode::Overwrite
    } else {
        LogFileMode::Refuse
    };

    let mut analyzer = AnalyzeState::new(args.log_file.clone());
    if args.no_live_display {
        analyzer.live_display = false;
    }

    let api = build_api_config(&args)?;
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
        macros: super::term::build_macros(&args.macros_file, &args.macro_)?,
        analyzer: Some(analyzer),
        api,
        escape_prefix,
    };

    // Snapshot the port name before ownership moves into `opts` so
    // we can record it in the history entry regardless of which run()
    // path we go down.
    let history_path = opts.port_name.clone();
    let history_format = if args.tui { "tui" } else { "term" };

    #[cfg(feature = "tui")]
    let result = if args.tui {
        crate::tui::run::run_session(opts)
    } else {
        run_session(opts)
    };
    #[cfg(not(feature = "tui"))]
    let result = run_session(opts);

    // Best-effort history append on session end. `analyze` is
    // interactive so `findings` isn't easily surfaced back to this
    // frame — leave it at 0 (the "did I run analyze on this port
    // and when" audit trail is the real value here).
    if !crate::history::is_disabled() {
        let exit_code = if result.is_ok() { 0 } else { 1 };
        crate::history::append_entry(&crate::history::Entry {
            ts: crate::history::now_utc_rfc3339(),
            cmd: Some("analyze".into()),
            path: history_path,
            format: history_format.to_string(),
            findings: 0,
            critical: 0,
            exit_code,
            cli_version: env!("CARGO_PKG_VERSION").to_string(),
        });
    }
    result
}

/// Build the ApiConfig from CLI flags + env. None when --api wasn't
/// requested. Errors early on illegal combos so the user finds out
/// before starting a terminal session (rather than mid-session on
/// the first Ctrl-A f).
fn build_api_config(args: &Args) -> Result<Option<ApiConfig>> {
    if !args.api {
        return Ok(None);
    }
    // Precedence: CLI flag > env var > config file > built-in default.
    // Centralized in crate::config so all subcommands agree.
    let base_url = crate::config::resolve_api_base(args.api_base.as_deref());
    let api_key = crate::config::resolve_api_key();
    if !args.preview && api_key.is_none() {
        bail!(
            "--api requires ${API_KEY_ENV} to be set (or use --api --preview for the free anonymous quota — 3/day per IP).\n  Get a key at https://bootintel.com/settings/api-keys"
        );
    }
    // Same plaintext-transport policy as `scan` — shared helper in
    // api::endpoints so a policy tweak is one-file.
    let sending_credential = !args.preview && api_key.is_some();
    crate::api::endpoints::require_safe_transport(&base_url, sending_credential)?;
    Ok(Some(ApiConfig {
        base_url,
        api_key,
        preview: args.preview,
        device_name: args.device_name.clone(),
    }))
}
