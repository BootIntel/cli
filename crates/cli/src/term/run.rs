//! Main terminal loop: connect a serial port, put the terminal in
//! raw mode, spawn two background threads (serial reader + keyboard
//! reader), drain both into one mpsc channel from the main thread.
//!
//! Deliberately synchronous — no tokio. std::thread + a single
//! std::sync::mpsc channel with a variant enum is simpler + smaller
//! than a runtime. The `--api` integration uses a blocking HTTP
//! client, so no async runtime is needed anywhere in the loop.

use anyhow::{bail, Context, Result};
use crossterm::event::{self, Event};
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use std::io::{stdout, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use super::hotkey::{Action, BackspaceMode, EscapePrefix, State as HotkeyState};
use super::logfile::{LogFile, LogFileMode};
use super::macros::MacroTable;
use super::newline::{NewlineMode, RxNewlineMode};
use super::raw_mode::RawModeGuard;
use crate::analyze::render::{print_finding_inline, print_intro, write_summary};
use crate::analyze::state::AnalyzeState;
use crate::api::client::ScanClient;
use crate::api::render::write_text_response;

/// Server-integration config for `bootintel analyze`. When Some,
/// Ctrl-A f POSTs the log-so-far to bootintel.com for full CVE
/// matching + exploit paths + (paid tiers) AI summary. When None,
/// Ctrl-A f prints "server integration disabled; pass --api".
#[derive(Clone)]
pub struct ApiConfig {
    pub base_url: String,
    /// None + `preview: true` = anonymous /preview endpoint.
    /// Some(key)                = authenticated /scan endpoint.
    pub api_key: Option<String>,
    pub preview: bool,
    pub device_name: Option<String>,
}

/// Options for opening the port and running the loop.
pub struct TermOptions {
    pub port_name: String,
    pub baud: u32,
    pub data_bits: DataBits,
    pub parity: Parity,
    pub stop_bits: StopBits,
    pub flow_control: FlowControl,
    pub log_file: Option<std::path::PathBuf>,
    pub log_mode: LogFileMode,
    /// Prefix each captured line with an ISO-8601 UTC timestamp.
    /// Only meaningful when `log_file` is Some. Off by default so a
    /// straight `--log-file` capture stays byte-identical to what
    /// the device emitted (useful for replaying into a fresh
    /// bootintel scan).
    pub log_timestamps: bool,
    pub local_echo: bool,
    /// Line-ending conversion applied to bytes sent to the serial
    /// port. Defaults to Passthrough (no rewriting). Runtime-cycled
    /// via Ctrl-A n through {LF, CR, CRLF}.
    pub newline_mode: NewlineMode,
    /// Line-ending conversion applied to bytes received from the
    /// serial port. Defaults to None. Runtime-cycled via Ctrl-A m
    /// through {None, CrToLf, StripCr}.
    pub rx_newline_mode: RxNewlineMode,
    /// Byte sent when the user hits Backspace. Defaults to DEL.
    /// Runtime-cycled via Ctrl-A k.
    pub backspace_mode: BackspaceMode,
    /// F1..F12 macros — pressing a bound function key sends the
    /// configured byte string to serial (through the current TX
    /// newline transform, same as typed keystrokes). Empty table is
    /// fine; unbound function keys fall through to normal encoding.
    pub macros: MacroTable,
    /// When Some, layer live client-side analysis on top of the term
    /// loop. Serial bytes get fed into the analyzer; detector matches
    /// surface as `[bootintel] ●` inline lines. The four extra
    /// Ctrl-A hotkeys (l/c/s/u) also become active. This is what
    /// separates `bootintel term` (analyzer=None) from `bootintel
    /// analyze` (analyzer=Some).
    pub analyzer: Option<AnalyzeState>,
    /// When Some (analyze mode only), Ctrl-A f is armed for full
    /// server-side analysis. None disables the hotkey with a hint.
    pub api: Option<ApiConfig>,
    /// Escape prefix for the hotkey state machine. Defaults to Ctrl-A.
    /// Users nested inside a tmux/screen session that also binds
    /// Ctrl-A can pass --escape ctrl-t (or whatever) to avoid the
    /// prefix collision.
    pub escape_prefix: EscapePrefix,
}

/// One event on the main-thread channel. Both background threads
/// push into the same mpsc::Sender (cloned) so the main thread
/// drains them in arrival order.
enum Ev {
    SerialBytes(Vec<u8>),
    /// A crossterm event (keystroke). We forward the whole thing so
    /// the hotkey state machine sees modifiers etc.
    KeyPress(event::KeyEvent),
    /// The serial-read thread hit a fatal error and exited. Payload
    /// is a short description for the disconnect banner.
    SerialDisconnected(String),
}

pub fn run_session(mut opts: TermOptions) -> Result<()> {
    // Open serial. Short read timeout so the reader thread can
    // check the shutdown flag between reads without blocking
    // forever on a quiet line.
    let mut port = open_serial_with_hints(
        &opts.port_name,
        opts.baud,
        opts.data_bits,
        opts.parity,
        opts.stop_bits,
        opts.flow_control,
    )?;

    // Log-file writer (optional).
    let mut log = if let Some(p) = &opts.log_file {
        Some(LogFile::create(p, opts.log_mode)?.with_timestamps(opts.log_timestamps))
    } else {
        None
    };

    // Print connection banner BEFORE entering raw mode so it lines up
    // with the shell prompt properly.
    print_banner(&opts);

    // Enter raw mode. Held for the life of the loop; dropped on any
    // exit path (success, error, panic) via RAII.
    let mut _raw = RawModeGuard::enter().context("entering terminal raw mode")?;

    // Channel that both background threads push into. Main thread
    // reads. 64-slot bounded channel — a slow terminal getting behind
    // the serial rate will apply backpressure to the serial reader
    // via .send() blocking, which is the correct behavior (no
    // unbounded memory growth).
    let (tx, rx) = mpsc::sync_channel::<Ev>(64);

    // Shared shutdown flag so both threads can exit cleanly when the
    // main thread decides we're done. The reader-shutdown flag is
    // separate so Ctrl-A h (hangup) can bounce the reader thread
    // without also killing the keyboard reader.
    let shutdown = Arc::new(AtomicBool::new(false));
    let reader_shutdown = Arc::new(AtomicBool::new(false));

    // Serial-read thread. Owns a clone of the port. We can't easily
    // clone SerialPort so we use try_clone() which the crate
    // supports on all backends. Extracted so Ctrl-A h can respawn
    // after reopening the port.
    let read_port = port
        .try_clone()
        .context("cloning serial port for reader thread")?;
    let mut serial_thread = spawn_reader_thread(read_port, tx.clone(), reader_shutdown.clone());

    // Keyboard-read thread. crossterm::event::poll lets us check the
    // shutdown flag periodically without blocking forever on stdin.
    let kb_tx = tx.clone();
    let kb_shutdown = shutdown.clone();
    let keyboard_thread = thread::spawn(move || {
        loop {
            if kb_shutdown.load(Ordering::Relaxed) {
                return;
            }
            match event::poll(Duration::from_millis(100)) {
                Ok(true) => match event::read() {
                    Ok(Event::Key(k)) => {
                        // Only KeyEventKind::Press events are meaningful
                        // for a serial forwarder. Releases + Repeats
                        // would double-send bytes on Windows terminals.
                        if k.kind == event::KeyEventKind::Press
                            && kb_tx.send(Ev::KeyPress(k)).is_err()
                        {
                            return;
                        }
                    }
                    Ok(_other) => {
                        // Resize / paste / mouse events — no meaning here.
                    }
                    Err(_) => return,
                },
                Ok(false) => continue,
                Err(_) => return,
            }
        }
    });

    // Main loop.
    let mut hotkey = HotkeyState::new(opts.escape_prefix);
    // Backspace mode lives on the hotkey state (it affects encoding)
    // so seed from opts here instead of leaving the default.
    if opts.backspace_mode != BackspaceMode::Del {
        hotkey.cycle_backspace_mode();
    }
    let mut out = stdout().lock();
    // Colorize only when writing to a real TTY. Under a pipe (e.g.
    // capturing with tee) the ANSI escape sequences would clutter
    // the log; strip them in that case.
    let use_color = std::io::stdout().is_terminal();
    let analyze_mode = opts.analyzer.is_some();

    // Runtime hotkey state that lives across events:
    //   - hex_mode: Ctrl-A x toggles a hexdump renderer for RX bytes.
    //   - dtr_state / rts_state: track our last-set value so a toggle
    //     flips the level rather than requiring the user to know the
    //     current line state. Start Some(true) — the port opens with
    //     both lines asserted on all backends we support.
    //   - hex_offset: running byte counter used by the hexdump so
    //     offsets are stable across serial-read chunks.
    let mut hex_mode = false;
    let mut dtr_state = true;
    let mut rts_state = true;
    let mut hex_offset: u64 = 0;
    // Runtime-mutable copies of the two TermOptions fields that Ctrl-A
    // e / Ctrl-A n let the user flip mid-session. Shadowing keeps
    // opts.local_echo / opts.newline_mode as the startup defaults for
    // any diagnostic that wants "what did we start with".
    let mut local_echo = opts.local_echo;
    let mut newline_mode = opts.newline_mode;
    let mut rx_newline_mode = opts.rx_newline_mode;
    // Current baud tracked separately from opts so Ctrl-A a can
    // update it. opts.baud stays as the startup value for --info.
    let mut current_baud = opts.baud;

    if analyze_mode {
        let _ = write!(out, "\r\n");
        let _ = print_intro(&mut out);
        let _ = write!(out, "\r\n");
        let _ = out.flush();
    }

    let exit_reason = loop {
        // Bounded recv — poll every 100ms so the analyze mode's pacer
        // can time-flush partial-line findings even on a quiet line.
        let ev_opt = match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(e) => Some(e),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break "both background threads disconnected".to_string();
            }
        };

        // Idle tick: give the analyzer a chance to flush partial
        // pending bytes past its time threshold.
        if ev_opt.is_none() {
            if let Some(analyzer) = &mut opts.analyzer {
                if let Some(new) = analyzer.maybe_tick() {
                    if analyzer.live_display {
                        for f in &new {
                            let _ = print_finding_inline(&mut out, f, use_color);
                        }
                    }
                }
            }
            continue;
        }
        let ev = ev_opt.unwrap();
        match ev {
            Ev::SerialBytes(bytes) => {
                // Apply RX newline mapping once so display + analyzer
                // both see the same normalized stream. Log file stores
                // the RAW bytes (pre-mapping) so post-capture replays
                // preserve exactly what the device emitted.
                let display_bytes = rx_newline_mode.rewrite(&bytes);
                // Display: hexdump when the user asked for it, raw
                // characters otherwise. Log file always stores raw
                // bytes regardless of display mode so post-capture
                // analysis + share URLs see the actual device output,
                // not a hex-rendered transform of it.
                let disp_ok = if hex_mode {
                    render_hexdump(&mut out, &display_bytes, &mut hex_offset).is_ok()
                } else {
                    out.write_all(&display_bytes).is_ok()
                };
                if !disp_ok {
                    break "stdout closed".to_string();
                }
                let _ = out.flush();
                if let Some(l) = &mut log {
                    l.write_bytes(&bytes);
                }
                // Feed the analyzer (if any) AFTER stdout so the
                // ordering user-sees-serial → user-sees-finding is
                // consistent — the finding relates to bytes that just
                // scrolled by.
                if let Some(analyzer) = &mut opts.analyzer {
                    if let Some(new) = analyzer.feed(&bytes) {
                        if analyzer.live_display {
                            for f in &new {
                                let _ = print_finding_inline(&mut out, f, use_color);
                            }
                        }
                    }
                }
            }
            Ev::KeyPress(k) => {
                // Function-key macros take precedence over normal
                // key encoding: pressing F1 when it's bound sends the
                // macro's bytes, not the F1 escape sequence. Runs
                // through newline conversion so the wire byte matches
                // what typed keystrokes would produce. Unbound
                // function keys and non-function keys fall through
                // to the hotkey state machine.
                if let Some(bytes) = opts.macros.lookup(&k) {
                    let to_send = newline_mode.rewrite(bytes);
                    if local_echo {
                        let _ = out.write_all(&to_send);
                        let _ = out.flush();
                    }
                    if let Err(e) = port.write_all(&to_send) {
                        _raw.restore();
                        eprintln!("\r\n[bootintel] serial write failed (macro): {e}");
                        break "serial write failed".to_string();
                    }
                    continue;
                }
                let action = hotkey.handle(k);
                match action {
                    Action::Nothing => {}
                    Action::PassThrough(bytes) => {
                        // Newline conversion happens once, here, so
                        // BOTH local echo AND the serial send see the
                        // same rewritten bytes (otherwise the echo
                        // would show one line ending while the device
                        // received a different one).
                        let to_send = newline_mode.rewrite(&bytes);
                        if local_echo {
                            let _ = out.write_all(&to_send);
                            let _ = out.flush();
                        }
                        if let Err(e) = port.write_all(&to_send) {
                            // Serial write failed — probably disconnect.
                            _raw.restore();
                            eprintln!("\r\n[bootintel] serial write failed: {e}");
                            break "serial write failed".to_string();
                        }
                    }
                    Action::Quit => {
                        break format!("user quit ({} q)", hotkey.prefix().display());
                    }
                    Action::ShowHelp => {
                        _raw.restore();
                        print_help(analyze_mode, hotkey.prefix());
                        // Re-enter raw mode to keep the session going.
                        _raw = RawModeGuard::enter().unwrap_or_else(|_| {
                            eprintln!("[bootintel] warning: could not re-enter raw mode");
                            RawModeGuard::enter().unwrap_or_else(|_| panic!("unrecoverable"))
                        });
                    }
                    Action::ToggleLiveAnalysis => {
                        if let Some(analyzer) = &mut opts.analyzer {
                            analyzer.live_display = !analyzer.live_display;
                            let state = if analyzer.live_display { "on" } else { "off" };
                            let _ =
                                write!(out, "\r\n[bootintel] live analysis display: {state}\r\n");
                            let _ = out.flush();
                        } else {
                            let _ = write!(
                                out,
                                "\r\n[bootintel] {} l is analyze-mode only (this session is `bootintel term`)\r\n", hotkey.prefix().display()
                            );
                            let _ = out.flush();
                        }
                    }
                    Action::ClearFindings => {
                        if let Some(analyzer) = &mut opts.analyzer {
                            let refreshed = analyzer.reset_and_rescan();
                            let _ = write!(
                                out,
                                "\r\n[bootintel] findings cleared and re-scanned — {} finding(s) currently in log\r\n",
                                refreshed.len()
                            );
                            if analyzer.live_display {
                                for f in &refreshed {
                                    let _ = print_finding_inline(&mut out, f, use_color);
                                }
                            }
                            let _ = out.flush();
                        } else {
                            let _ = write!(
                                out,
                                "\r\n[bootintel] {} c is analyze-mode only\r\n",
                                hotkey.prefix().display()
                            );
                            let _ = out.flush();
                        }
                    }
                    Action::SaveFindings => {
                        if let Some(analyzer) = &mut opts.analyzer {
                            let path = analyzer.default_summary_path();
                            let findings = analyzer.findings_snapshot().to_vec();
                            let captured = analyzer.captured_bytes();
                            let version = env!("CARGO_PKG_VERSION");
                            match std::fs::File::create(&path) {
                                Ok(mut f) => {
                                    match write_summary(
                                        &mut f,
                                        version,
                                        captured,
                                        bootintel_detectors::detector_labels().len(),
                                        &findings,
                                    ) {
                                        Ok(()) => {
                                            let _ = write!(
                                                out,
                                                "\r\n[bootintel] saved {} finding(s) to {} ({} log bytes captured)\r\n",
                                                findings.len(),
                                                path.display(),
                                                captured
                                            );
                                        }
                                        Err(e) => {
                                            let _ =
                                                write!(out, "\r\n[bootintel] save failed: {e}\r\n");
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = write!(
                                        out,
                                        "\r\n[bootintel] could not create {}: {e}\r\n",
                                        path.display()
                                    );
                                }
                            }
                            let _ = out.flush();
                        } else {
                            let _ = write!(
                                out,
                                "\r\n[bootintel] {} s is analyze-mode only\r\n",
                                hotkey.prefix().display()
                            );
                            let _ = out.flush();
                        }
                    }
                    Action::CopyShareUrl => {
                        if let Some(analyzer) = &opts.analyzer {
                            let log_so_far = analyzer.log_so_far();
                            // Reuse the same lz-string compression the
                            // share subcommand uses. Duplicating the
                            // one-liner rather than pulling share.rs
                            // in to keep the coupling narrow.
                            let compressed = lz_str::compress_to_encoded_uri_component(log_so_far);
                            let url =
                                format!("https://bootintel.com/tools/fingerprint?z={compressed}");
                            match copy_to_clipboard(&url) {
                                Ok(()) => {
                                    let _ = write!(
                                        out,
                                        "\r\n[bootintel] share URL copied to clipboard ({} chars)\r\n",
                                        url.len()
                                    );
                                }
                                Err(reason) => {
                                    let _ = write!(
                                        out,
                                        "\r\n[bootintel] clipboard unavailable ({reason}); URL:\r\n{url}\r\n"
                                    );
                                }
                            }
                            let _ = out.flush();
                        } else {
                            let _ = write!(
                                out,
                                "\r\n[bootintel] {} u is analyze-mode only\r\n",
                                hotkey.prefix().display()
                            );
                            let _ = out.flush();
                        }
                    }
                    Action::FullAnalysis => {
                        // POST the log-so-far to bootintel.com for
                        // full CVE match + exploit paths. Synchronous
                        // — the terminal pauses for the round-trip.
                        // Restore cooked mode so the rendered report
                        // prints normally + so any error line is
                        // legible; re-enter raw when done.
                        if let (Some(analyzer), Some(api)) = (&opts.analyzer, &opts.api) {
                            let log_so_far = analyzer.log_so_far().to_string();
                            _raw.restore();
                            eprintln!();
                            eprintln!(
                                "[bootintel] submitting {} bytes to bootintel.com{}...",
                                log_so_far.len(),
                                if api.preview {
                                    " (anonymous preview)"
                                } else {
                                    " (authenticated)"
                                }
                            );
                            let client = ScanClient::new(&api.base_url);
                            let device = api.device_name.as_deref();
                            let result = if api.preview || api.api_key.is_none() {
                                client.preview_scan(&log_so_far, device)
                            } else {
                                client.authed_scan(
                                    &log_so_far,
                                    device,
                                    api.api_key.as_deref().unwrap(),
                                )
                            };
                            match result {
                                Ok(resp) => {
                                    let mut stderr = std::io::stderr();
                                    let _ = writeln!(stderr);
                                    let _ = write_text_response(&mut stderr, &resp);
                                    let _ = writeln!(stderr);
                                }
                                Err(e) => {
                                    eprintln!();
                                    eprintln!("[bootintel] full-analysis failed: {e}");
                                    if let Some(hint) = e.hint() {
                                        eprintln!("  {hint}");
                                    }
                                    eprintln!("  (client-side detector output continues to work)");
                                    eprintln!();
                                }
                            }
                            _raw = RawModeGuard::enter().unwrap_or_else(|_| {
                                eprintln!("[bootintel] warning: could not re-enter raw mode");
                                RawModeGuard::enter().unwrap_or_else(|_| panic!("unrecoverable"))
                            });
                        } else if opts.analyzer.is_none() {
                            let _ = write!(
                                out,
                                "\r\n[bootintel] {} f is analyze-mode only\r\n",
                                hotkey.prefix().display()
                            );
                            let _ = out.flush();
                        } else {
                            let _ = write!(
                                out,
                                "\r\n[bootintel] {} f needs --api (or --api --preview); server integration is off in this session\r\n", hotkey.prefix().display()
                            );
                            let _ = out.flush();
                        }
                    }
                    Action::SendBreak => {
                        // Assert BREAK for ~250ms, then release. Enough
                        // to interrupt U-Boot autoboot on every SoC the
                        // sample corpus covers; short enough not to
                        // disturb an active shell more than necessary.
                        match port.set_break() {
                            Ok(()) => {
                                thread::sleep(Duration::from_millis(250));
                                let _ = port.clear_break();
                                let _ = write!(out, "\r\n[bootintel] BREAK sent (250ms)\r\n");
                            }
                            Err(e) => {
                                let _ = write!(out, "\r\n[bootintel] BREAK failed: {e}\r\n");
                            }
                        }
                        let _ = out.flush();
                    }
                    Action::ToggleHexMode => {
                        hex_mode = !hex_mode;
                        // Reset the byte counter each time hex mode is
                        // re-entered so the offset column starts at 0.
                        if hex_mode {
                            hex_offset = 0;
                        }
                        let state = if hex_mode { "on" } else { "off" };
                        let _ = write!(
                            out,
                            "\r\n[bootintel] hex display mode: {state} (log file still stores raw bytes)\r\n"
                        );
                        let _ = out.flush();
                    }
                    Action::ToggleDtr => {
                        dtr_state = !dtr_state;
                        match port.write_data_terminal_ready(dtr_state) {
                            Ok(()) => {
                                let level = if dtr_state {
                                    "asserted (high)"
                                } else {
                                    "deasserted (low)"
                                };
                                let _ = write!(out, "\r\n[bootintel] DTR: {level}\r\n");
                            }
                            Err(e) => {
                                // Revert the tracked state so the next
                                // toggle tries the direction the user
                                // actually asked for.
                                dtr_state = !dtr_state;
                                let _ = write!(out, "\r\n[bootintel] DTR toggle failed: {e}\r\n");
                            }
                        }
                        let _ = out.flush();
                    }
                    Action::ToggleRts => {
                        rts_state = !rts_state;
                        match port.write_request_to_send(rts_state) {
                            Ok(()) => {
                                let level = if rts_state {
                                    "asserted (high)"
                                } else {
                                    "deasserted (low)"
                                };
                                let _ = write!(out, "\r\n[bootintel] RTS: {level}\r\n");
                            }
                            Err(e) => {
                                rts_state = !rts_state;
                                let _ = write!(out, "\r\n[bootintel] RTS toggle failed: {e}\r\n");
                            }
                        }
                        let _ = out.flush();
                    }
                    Action::SendFile => {
                        // Prompt for path in cooked mode, then stream
                        // the file with per-line pacing so a U-Boot /
                        // kernel-shell receiver doesn't lose input to
                        // a buffer overrun. Errors reported inline;
                        // the terminal session continues either way.
                        _raw.restore();
                        eprintln!();
                        eprintln!("[bootintel] paste (send file) — enter path, empty to cancel:");
                        eprint!("[bootintel] path: ");
                        let _ = std::io::stderr().flush();
                        let mut path_line = String::new();
                        let path_read = std::io::stdin().read_line(&mut path_line);
                        let path = path_line.trim();
                        match (path_read, path.is_empty()) {
                            (Err(e), _) => {
                                eprintln!("[bootintel] paste cancelled ({e})");
                            }
                            (_, true) => {
                                eprintln!("[bootintel] paste cancelled");
                            }
                            (Ok(_), false) => {
                                match std::fs::read(path) {
                                    Ok(contents) => {
                                        eprintln!(
                                            "[bootintel] sending {} bytes from {path}...",
                                            contents.len()
                                        );
                                        let sent =
                                            send_file_paced(port.as_mut(), &contents, newline_mode);
                                        match sent {
                                            Ok(n) => {
                                                eprintln!(
                                                    "[bootintel] paste complete ({n} bytes sent)"
                                                );
                                            }
                                            Err(e) => {
                                                eprintln!("[bootintel] paste failed after partial send: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[bootintel] could not read {path}: {e}");
                                    }
                                }
                            }
                        }
                        _raw = RawModeGuard::enter().unwrap_or_else(|_| {
                            eprintln!("[bootintel] warning: could not re-enter raw mode");
                            RawModeGuard::enter().unwrap_or_else(|_| panic!("unrecoverable"))
                        });
                    }
                    Action::ToggleLocalEcho => {
                        local_echo = !local_echo;
                        let state = if local_echo { "on" } else { "off" };
                        let _ = write!(out, "\r\n[bootintel] local echo: {state}\r\n");
                        let _ = out.flush();
                    }
                    Action::CycleNewlineMode => {
                        newline_mode = newline_mode.next_in_cycle();
                        let _ = write!(
                            out,
                            "\r\n[bootintel] newline mode (on send): {}\r\n",
                            newline_mode.label()
                        );
                        let _ = out.flush();
                    }
                    Action::ChangeBaud => {
                        _raw.restore();
                        eprintln!();
                        eprint!("[bootintel] new baud rate (current: {current_baud}, empty to cancel): ");
                        let _ = std::io::stderr().flush();
                        let mut input = String::new();
                        match std::io::stdin().read_line(&mut input) {
                            Ok(_) => {
                                let trimmed = input.trim();
                                if trimmed.is_empty() {
                                    eprintln!("[bootintel] baud change cancelled");
                                } else {
                                    match trimmed.parse::<u32>() {
                                        Ok(rate) if rate > 0 => match port.set_baud_rate(rate) {
                                            Ok(()) => {
                                                current_baud = rate;
                                                eprintln!("[bootintel] baud rate now {rate}");
                                            }
                                            Err(e) => {
                                                eprintln!("[bootintel] set_baud_rate failed: {e}");
                                            }
                                        },
                                        _ => eprintln!(
                                            "[bootintel] not a valid baud rate: {trimmed}"
                                        ),
                                    }
                                }
                            }
                            Err(e) => eprintln!("[bootintel] baud change cancelled ({e})"),
                        }
                        _raw = RawModeGuard::enter().unwrap_or_else(|_| {
                            eprintln!("[bootintel] warning: could not re-enter raw mode");
                            RawModeGuard::enter().unwrap_or_else(|_| panic!("unrecoverable"))
                        });
                    }
                    Action::ShowInfo => {
                        let _ = write!(out, "\r\n[bootintel] session info:\r\n");
                        let _ = write!(out, "  port         {}\r\n", opts.port_name);
                        let _ = write!(out, "  baud         {current_baud}\r\n");
                        let _ = write!(
                            out,
                            "  macros       {}\r\n",
                            if opts.macros.is_empty() {
                                "<none>".to_string()
                            } else {
                                let names: Vec<String> = opts
                                    .macros
                                    .entries()
                                    .iter()
                                    .map(|(k, _)| format!("F{k}"))
                                    .collect();
                                names.join(", ")
                            }
                        );
                        let _ = write!(
                            out,
                            "  DTR          {}    RTS  {}\r\n",
                            if dtr_state { "asserted" } else { "deasserted" },
                            if rts_state { "asserted" } else { "deasserted" }
                        );
                        let _ = write!(
                            out,
                            "  local echo   {}    hex mode   {}\r\n",
                            if local_echo { "on" } else { "off" },
                            if hex_mode { "on" } else { "off" }
                        );
                        let _ = write!(
                            out,
                            "  TX newline   {}    RX newline {}\r\n",
                            newline_mode.label(),
                            rx_newline_mode.label()
                        );
                        let _ = write!(
                            out,
                            "  backspace    {}\r\n",
                            hotkey.backspace_mode().label()
                        );
                        match &opts.log_file {
                            Some(p) => {
                                let _ = write!(
                                    out,
                                    "  log file     {} (timestamps: {})\r\n",
                                    p.display(),
                                    if opts.log_timestamps { "on" } else { "off" }
                                );
                            }
                            None => {
                                let _ = write!(out, "  log file     <none>\r\n");
                            }
                        }
                        let _ = out.flush();
                    }
                    Action::CycleBackspaceMode => {
                        let new_mode = hotkey.cycle_backspace_mode();
                        let _ = write!(
                            out,
                            "\r\n[bootintel] backspace key sends: {}\r\n",
                            new_mode.label()
                        );
                        let _ = out.flush();
                    }
                    Action::CycleRxNewlineMode => {
                        rx_newline_mode = rx_newline_mode.cycle();
                        let _ = write!(
                            out,
                            "\r\n[bootintel] RX newline mapping: {}\r\n",
                            rx_newline_mode.label()
                        );
                        let _ = out.flush();
                    }
                    Action::Hangup => {
                        // Close + reopen the serial port. Fixes USB
                        // adapters that got confused (device replugged,
                        // brief adapter reset) without a full quit.
                        // Preserves current baud + modem-control state
                        // + all runtime toggles.
                        let _ = write!(
                            out,
                            "\r\n[bootintel] hangup: closing port, reopening in 500ms...\r\n"
                        );
                        let _ = out.flush();
                        // 1. Stop the reader thread (drops its port clone).
                        reader_shutdown.store(true, Ordering::Relaxed);
                        let old = std::mem::replace(&mut serial_thread, thread::spawn(|| {}));
                        let _ = old.join();
                        // 2. Give the device 500ms to notice the fd
                        // going quiet before we try to reopen. Old
                        // main-thread port stays open during this; the
                        // fd fully closes when we assign the new one.
                        std::thread::sleep(Duration::from_millis(500));
                        // 3. Reopen. On failure, fall back to resuming
                        // with the old port so a temporary reopen
                        // failure doesn't kill the whole session.
                        match open_serial_with_hints(
                            &opts.port_name,
                            current_baud,
                            opts.data_bits,
                            opts.parity,
                            opts.stop_bits,
                            opts.flow_control,
                        ) {
                            Ok(new_port) => {
                                port = new_port; // old port drops → fd closes
                                let _ = port.write_data_terminal_ready(dtr_state);
                                let _ = port.write_request_to_send(rts_state);
                                let _ = write!(
                                    out,
                                    "[bootintel] hangup: reopened at {current_baud} baud\r\n"
                                );
                            }
                            Err(e) => {
                                let _ = write!(out, "[bootintel] hangup: reopen failed: {e}\r\n[bootintel] resuming with existing port\r\n");
                            }
                        }
                        // 4. Restart the reader (against whichever port
                        // we ended up with — new or old-fallback).
                        reader_shutdown.store(false, Ordering::Relaxed);
                        match port.try_clone() {
                            Ok(rp) => {
                                serial_thread =
                                    spawn_reader_thread(rp, tx.clone(), reader_shutdown.clone());
                            }
                            Err(e) => {
                                let _ =
                                    write!(out, "[bootintel] hangup: reader clone failed: {e}\r\n");
                                break "reader clone failed after hangup".to_string();
                            }
                        }
                        let _ = out.flush();
                    }
                    Action::UnknownCommand(c) => {
                        let _ = write!(
                            out,
                            "\r\n[bootintel] unknown {0} command: '{c}' ({0} ? for help)\r\n",
                            hotkey.prefix().display()
                        );
                        let _ = out.flush();
                    }
                }
            }
            Ev::SerialDisconnected(msg) => {
                _raw.restore();
                eprintln!("\r\n[bootintel] serial disconnected: {msg}");
                break "serial disconnected".to_string();
            }
        }
    };

    // Signal both background threads to exit + wait for them.
    shutdown.store(true, Ordering::Relaxed);
    reader_shutdown.store(true, Ordering::Relaxed);
    drop(tx); // drop the main's sender so any pending send() in threads returns Err
    let _ = serial_thread.join();
    let _ = keyboard_thread.join();

    // Restore terminal (Drop would do this too, but be explicit so the
    // exit banner prints in cooked mode).
    _raw.restore();
    eprintln!("[bootintel] session ended — {exit_reason}");

    if let Some(mut l) = log {
        l.flush();
    }
    Ok(())
}

fn print_banner(opts: &TermOptions) {
    let parity = match opts.parity {
        Parity::None => "N",
        Parity::Odd => "O",
        Parity::Even => "E",
    };
    let data = match opts.data_bits {
        DataBits::Five => "5",
        DataBits::Six => "6",
        DataBits::Seven => "7",
        DataBits::Eight => "8",
    };
    let stop = match opts.stop_bits {
        StopBits::One => "1",
        StopBits::Two => "2",
    };
    let flow = match opts.flow_control {
        FlowControl::None => "none",
        FlowControl::Software => "software (XON/XOFF)",
        FlowControl::Hardware => "hardware (RTS/CTS)",
    };
    eprintln!(
        "[bootintel] connected {} @ {} {}{}{}, flow control: {}",
        opts.port_name, opts.baud, data, parity, stop, flow
    );
    if let Some(p) = &opts.log_file {
        let mode = match opts.log_mode {
            LogFileMode::Refuse => "new file",
            LogFileMode::Append => "append",
            LogFileMode::Overwrite => "overwrite",
        };
        eprintln!("[bootintel] logging to {} ({mode})", p.display());
    }
    let px = opts.escape_prefix.display();
    eprintln!("[bootintel] press {px} ? for help, {px} q to quit");
    // Warn if we detect a nested tmux/screen session AND the user is
    // on the default Ctrl-A prefix — those tools eat Ctrl-A. Point
    // them at --escape to remap.
    if opts.escape_prefix == EscapePrefix::DEFAULT {
        let in_tmux = std::env::var("TMUX").is_ok();
        let in_screen = std::env::var("STY").is_ok();
        if in_tmux || in_screen {
            let host = if in_tmux { "tmux" } else { "screen" };
            eprintln!(
                "[bootintel] warning: you appear to be inside a {host} session. If Ctrl-A is your {host} prefix, hotkeys won't reach bootintel."
            );
            eprintln!(
                "[bootintel]   fix: re-run with `--escape ctrl-t` (or another Ctrl+letter that {host} doesn't use)."
            );
        }
    }
    eprintln!();
}

fn print_help(analyze_mode: bool, prefix: EscapePrefix) {
    // Printed in cooked mode (RawModeGuard::restore called first).
    let px = prefix.display();
    eprintln!();
    if analyze_mode {
        eprintln!("bootintel analyze — hotkeys (escape prefix: {px})");
    } else {
        eprintln!("bootintel term — hotkeys (escape prefix: {px})");
    }
    eprintln!("  {px} q       quit");
    eprintln!("  {px} ?       show this help");
    eprintln!(
        "  {px} {px}    send a literal {px} (0x{:02x}) byte to serial",
        prefix.control_byte()
    );
    eprintln!();
    eprintln!("  {px} b       send serial BREAK (~250ms) — interrupts U-Boot autoboot, drops Linux to sysrq");
    eprintln!(
        "  {px} x       toggle hex display mode (hexdump RX bytes on/off; log file stays raw)"
    );
    eprintln!("  {px} d       toggle DTR line (ESP32 boot mode, generic device reset)");
    eprintln!("  {px} r       toggle RTS line (paired with DTR for reset workflows)");
    eprintln!(
        "  {px} p       paste (send file) with per-line pacing — good for U-Boot env imports"
    );
    eprintln!("  {px} e       toggle local echo (whether typed keys also render locally)");
    eprintln!("  {px} n       cycle TX newline mode: LF → CRLF → CR → LF");
    eprintln!("  {px} m       cycle RX newline map: none → CR→LF → strip-CR → none");
    eprintln!("  {px} a       adjust (change) baud rate mid-session");
    eprintln!("  {px} k       cycle Backspace key: DEL (0x7f) ↔ BS (0x08)");
    eprintln!("  {px} i       show current session info (port, baud, DTR/RTS, modes, log file)");
    eprintln!("  {px} h       hangup: close + reopen the serial port (USB reconnect helper)");
    if analyze_mode {
        eprintln!();
        eprintln!("  {px} l       toggle live analysis display on/off");
        eprintln!("  {px} c       clear findings buffer + re-scan from current log");
        eprintln!("  {px} s       save findings summary to file (JSON)");
        eprintln!("  {px} u       copy share URL for log-so-far (clipboard or stderr)");
        eprintln!("  {px} f       full server-side analysis (needs --api or --api --preview)");
    } else {
        eprintln!();
        eprintln!("  live analysis (findings inline as detectors fire) — use `bootintel analyze`");
    }
    eprintln!();
    eprintln!(
        "  Change the prefix with --escape (e.g. `--escape ctrl-t`) if you're in tmux/screen."
    );
    eprintln!();
}

/// Spawn the serial-reader background thread. Extracted so the
/// Ctrl-A h hangup path can respawn after closing and reopening the
/// port. Owns its own clone of the port and its own AtomicBool
/// "reader shutdown" flag; caller is responsible for joining before
/// dropping the port to avoid a use-after-close read.
fn spawn_reader_thread(
    mut read_port: Box<dyn SerialPort>,
    tx: mpsc::SyncSender<Ev>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            match read_port.read(&mut buf) {
                Ok(0) => continue,
                Ok(n) => {
                    if tx.send(Ev::SerialBytes(buf[..n].to_vec())).is_err() {
                        // Main thread hung up; we're done.
                        return;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    // No data in the 100ms window — normal.
                    continue;
                }
                Err(e) => {
                    let _ = tx.send(Ev::SerialDisconnected(e.to_string()));
                    return;
                }
            }
        }
    })
}

/// Stream a file's bytes to the serial port with per-line pacing
/// so a slow receiver (U-Boot shell, Linux getty at low baud) doesn't
/// drop input to a buffer overrun. Newline conversion is applied on
/// the way out so `Ctrl-A n` and this command agree on line endings.
/// Returns number of bytes actually sent to the wire (post-rewrite),
/// or the first write error encountered.
fn send_file_paced(
    port: &mut dyn SerialPort,
    bytes: &[u8],
    newline: NewlineMode,
) -> std::io::Result<usize> {
    let payload = newline.rewrite(bytes);
    let mut sent = 0usize;
    // Split on \n so we can pause between "lines" — the natural point
    // where a serial receiver would otherwise fall behind. \n includes
    // the byte in the chunk so line boundaries preserve the newline.
    let mut start = 0usize;
    while start < payload.len() {
        let end = match payload[start..].iter().position(|&b| b == b'\n') {
            Some(idx) => start + idx + 1,
            None => payload.len(),
        };
        let chunk = &payload[start..end];
        port.write_all(chunk)?;
        port.flush()?;
        sent += chunk.len();
        start = end;
        // 20ms/line pause — empirically enough to keep a 115200-baud
        // U-Boot shell from dropping bytes in the middle of a long
        // paste, low enough that a 100-line env import takes ~2s.
        if start < payload.len() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    Ok(sent)
}

/// Hexdump renderer for --hex display mode. Standard `hexdump -C`
/// layout: 8-hex-digit offset, 16 space-separated hex bytes, then
/// the same 16 bytes as ASCII (non-printable as '.'). Emits one line
/// per 16 bytes; partial trailing lines get padded so the ASCII
/// gutter stays aligned. `offset` is a running counter across calls
/// so long RX streams get monotonic offsets, not a fresh 0 per chunk.
fn render_hexdump<W: Write>(w: &mut W, bytes: &[u8], offset: &mut u64) -> std::io::Result<()> {
    for chunk in bytes.chunks(16) {
        write!(w, "\r{:08x}  ", *offset)?;
        for (i, b) in chunk.iter().enumerate() {
            write!(w, "{:02x} ", b)?;
            if i == 7 {
                write!(w, " ")?;
            }
        }
        // Pad hex column so the ASCII gutter aligns on partial lines.
        for i in chunk.len()..16 {
            write!(w, "   ")?;
            if i == 7 {
                write!(w, " ")?;
            }
        }
        write!(w, " |")?;
        for b in chunk {
            let c = if (0x20..0x7f).contains(b) {
                *b as char
            } else {
                '.'
            };
            write!(w, "{c}")?;
        }
        writeln!(w, "|\r")?;
        *offset += chunk.len() as u64;
    }
    Ok(())
}

/// Attempt to copy `text` to the system clipboard. Returns `Err` with
/// a short reason if the clipboard subsystem is unavailable
/// (headless CI, missing X/Wayland/Cocoa/WinAPI backend, etc.); the
/// caller falls back to printing the URL to stderr in that case.
fn copy_to_clipboard(text: &str) -> std::result::Result<(), String> {
    #[cfg(feature = "clipboard")]
    {
        use arboard::Clipboard;
        Clipboard::new()
            .map_err(|e| format!("init: {e}"))?
            .set_text(text.to_string())
            .map_err(|e| format!("set: {e}"))
    }
    #[cfg(not(feature = "clipboard"))]
    {
        let _ = text;
        Err("built without --features clipboard".to_string())
    }
}

// Handy for validating that the reader-thread ownership model works
// under cargo check without a real serial device.
#[allow(dead_code)]
fn _serial_port_traits_are_sane<P: SerialPort>(_p: P) {}

/// Open a serial port with actionable error messages + exclusive-mode
/// lock on Unix (TIOCEXCL). Common-case errors that trip up first-time
/// users get specific remediation hints.
///
/// Exclusive mode: on Unix, we ask the kernel to refuse further opens
/// by other processes while ours is open. Prevents two `bootintel term`
/// (or bootintel + picocom, etc.) sessions from silently corrupting
/// each other's stream. Windows: no equivalent; serial ports there are
/// exclusive by default via the CreateFile semantics.
pub fn open_serial_with_hints(
    port_name: &str,
    baud: u32,
    data_bits: DataBits,
    parity: Parity,
    stop_bits: StopBits,
    flow_control: FlowControl,
) -> Result<Box<dyn SerialPort>> {
    let builder = serialport::new(port_name, baud)
        .data_bits(data_bits)
        .parity(parity)
        .stop_bits(stop_bits)
        .flow_control(flow_control)
        .timeout(Duration::from_millis(100));

    #[cfg(unix)]
    {
        match builder.open_native() {
            Ok(mut port) => {
                // Best-effort exclusive lock. Some USB-serial drivers
                // (e.g. certain macOS FTDI builds) return NotSupported;
                // that's fine — we lose the guarantee but proceed.
                if let Err(e) = port.set_exclusive(true) {
                    eprintln!("[bootintel] note: could not set exclusive mode on {port_name}: {e}. Concurrent access from another serial tool may corrupt the stream.");
                }
                Ok(Box::new(port))
            }
            Err(e) => Err(explain_serial_error(port_name, e)),
        }
    }
    #[cfg(not(unix))]
    {
        builder
            .open()
            .map_err(|e| explain_serial_error(port_name, e))
    }
}

/// Convert a raw serialport::Error into an anyhow::Error with a
/// user-actionable hint depending on the error kind.
fn explain_serial_error(port_name: &str, err: serialport::Error) -> anyhow::Error {
    use serialport::ErrorKind;
    // The io::ErrorKind on Unix is inside err.io_kind()? No —
    // serialport::Error has a `kind()` returning ErrorKind. Match on it.
    match err.kind() {
        ErrorKind::NoDevice => anyhow::anyhow!(
            "no such serial device: {port_name}\n\n  Run `bootintel ports` to list what's available on this machine.\n  On Linux the device name is typically /dev/ttyUSB0 or /dev/ttyACM0."
        ),
        ErrorKind::Io(io_kind) => match io_kind {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "serial device not found: {port_name}\n\n  Run `bootintel ports` to list what's here.\n  If your USB-serial adapter was just plugged in, wait a second and try again."
            ),
            std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                "permission denied opening {port_name}\n\n  On Linux you typically need to be in the `dialout` group (or `uucp` on Arch/RHEL):\n    sudo usermod -aG dialout $USER\n  Then log out and back in for the group to take effect.\n  On macOS you may need to grant your terminal Full Disk Access."
            ),
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::ResourceBusy => anyhow::anyhow!(
                "serial port already in use: {port_name}\n\n  Another process has the port open. Find and stop it:\n    lsof {port_name}    # Linux/macOS: shows who owns the fd\n    fuser {port_name}   # Linux alternative\n  Common culprits: an already-running picocom / screen / minicom / tio / another bootintel session."
            ),
            _ => anyhow::Error::from(err).context(format!("opening serial port {port_name}")),
        },
        _ => anyhow::Error::from(err).context(format!("opening serial port {port_name}")),
    }
}

/// Bail helpfully if the port name doesn't look plausible on this
/// platform. Deliberately permissive: catches the common typo case
/// (`bootintel term ttyUSB0` — no /dev/) but accepts anything that
/// looks like a real device path. Virtual PTYs (`/dev/pts/*`),
/// weird symlinks, Docker forwarders, and similar unusual-but-
/// legitimate paths all pass through. The authoritative check is
/// the actual open() call below.
pub fn validate_port_hint(name: &str) -> Result<()> {
    #[cfg(unix)]
    {
        if !name.starts_with('/') {
            bail!(
                "port name '{name}' doesn't look like a device path (expected an absolute path like /dev/ttyUSB0); run `bootintel ports` to list what's here"
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Windows COM ports are the canonical form; also accept a
        // \\.\COM<N> long-form (needed for COM10+).
        let up = name.to_uppercase();
        if !up.starts_with("COM") && !up.starts_with(r"\\.\COM") {
            bail!(
                "port name '{name}' doesn't look like a Windows serial device (expected COM3, COM4, or \\\\.\\COM10 for double-digit COMs); run `bootintel ports` to list what's here"
            );
        }
    }
    Ok(())
}
