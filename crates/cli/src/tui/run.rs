//! TUI main loop.
//!
//! Structurally identical to term::run: open serial, spawn a serial
//! reader thread + a keyboard reader thread pushing into a bounded
//! mpsc channel, main thread drains. Difference is what the main
//! thread does with the events — instead of writing raw bytes to
//! stdout, it feeds the App state and asks ratatui to redraw.

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use serialport::SerialPort;
use std::io::{stdout, Stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::app::{App, InputIntent, InputPrompt, Pane};
use super::render;
use crate::analyze::state::AnalyzeState;
use crate::api::client::ScanClient;
use crate::term::hotkey::{Action, EscapePrefix, State as HotkeyState};
use crate::term::run::{open_serial_with_hints, validate_port_hint, TermOptions};

/// Approx how often we redraw if nothing else has happened. Ratatui
/// diffs against its previous frame so this is cheap — a redraw with
/// no changes moves no bytes.
const TICK: Duration = Duration::from_millis(80);

enum Ev {
    SerialBytes(Vec<u8>),
    KeyPress(KeyEvent),
    SerialDisconnected(String),
}

/// Entry point. Takes the same TermOptions as term::run — the caller
/// (cmd/analyze.rs) builds one and hands it here when --tui is set.
pub fn run_session(opts: TermOptions) -> Result<()> {
    validate_port_hint(&opts.port_name)?;

    let mut port = serialport::new(&opts.port_name, opts.baud)
        .data_bits(opts.data_bits)
        .parity(opts.parity)
        .stop_bits(opts.stop_bits)
        .flow_control(opts.flow_control)
        .timeout(Duration::from_millis(100))
        .open()
        .with_context(|| format!("opening serial port {}", opts.port_name))?;

    // App state. The analyzer inside TermOptions is Some in the
    // analyze subcommand path; if a caller ever passes None (term
    // mode + --tui), we still work by making our own AnalyzeState.
    let analyzer = opts
        .analyzer
        .unwrap_or_else(|| AnalyzeState::new(opts.log_file.clone()));
    let mut app = App::new(
        opts.port_name.clone(),
        opts.baud,
        analyzer,
        opts.api,
        opts.escape_prefix,
    );
    // Seed the TUI's runtime newline mode from the startup flag so
    // --newline lf/cr/crlf applies immediately without needing the
    // user to hit Ctrl-A n first.
    app.newline_mode = opts.newline_mode;
    app.rx_newline_mode = opts.rx_newline_mode;

    // Warn about tmux/screen prefix collision in the status bar.
    // The banner-mode print goes to stderr before raw mode is entered;
    // in TUI mode the alt-screen switch immediately covers it. Surface
    // the warning in the status bar with a long TTL (30s) so the user
    // sees it clearly + has time to act on it.
    if opts.escape_prefix == EscapePrefix::DEFAULT {
        let in_tmux = std::env::var("TMUX").is_ok();
        let in_screen = std::env::var("STY").is_ok();
        if in_tmux || in_screen {
            let host = if in_tmux { "tmux" } else { "screen" };
            app.set_status_message_with_ttl(
                format!(
                    "warning: inside {host} — if Ctrl-A is your {host} prefix, hotkeys won't reach bootintel. Re-launch with --escape ctrl-t (or another Ctrl+letter)."
                ),
                super::app::STARTUP_WARNING_TTL,
            );
        }
    }

    // Enter ratatui / alternate-screen mode.
    let mut terminal = enter_tui().context("entering TUI raw + alt-screen mode")?;

    let (tx, rx) = mpsc::sync_channel::<Ev>(64);
    let shutdown = Arc::new(AtomicBool::new(false));
    // Separate flag for the serial reader so Ctrl-A h can bounce
    // just that thread (drop + reopen the port) without also killing
    // the keyboard thread. Same policy as term::run.
    let reader_shutdown = Arc::new(AtomicBool::new(false));

    let read_port = port
        .try_clone()
        .context("cloning serial port for reader thread")?;
    let mut serial_thread = spawn_serial_reader(read_port, tx.clone(), reader_shutdown.clone());

    // Keyboard reader thread.
    let kb_tx = tx.clone();
    let kb_shutdown = shutdown.clone();
    let keyboard_thread = thread::spawn(move || loop {
        if kb_shutdown.load(Ordering::Relaxed) {
            return;
        }
        match event::poll(Duration::from_millis(100)) {
            Ok(true) => {
                if let Ok(Event::Key(k)) = event::read() {
                    if k.kind == KeyEventKind::Press && kb_tx.send(Ev::KeyPress(k)).is_err() {
                        return;
                    }
                }
            }
            Ok(false) => continue,
            Err(_) => return,
        }
    });

    let mut hotkey = HotkeyState::new(app.escape_prefix);
    let mut last_draw = Instant::now();
    let exit_reason = loop {
        // Initial draw so the user sees the UI immediately (before
        // any events).
        if last_draw.elapsed() >= TICK {
            terminal.draw(|f| render::draw(f, &app))?;
            last_draw = Instant::now();
        }

        let ev = match rx.recv_timeout(TICK) {
            Ok(e) => e,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                app.tick_status_message();
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break "both background threads disconnected".to_string();
            }
        };

        match ev {
            Ev::SerialBytes(bytes) => {
                // Apply RX newline mapping before feeding the pane +
                // analyzer — same policy as plain analyze/watch, so a
                // device that sends bare CR after every line renders
                // as one-line-per-message here too.
                let mapped = app.rx_newline_mode.rewrite(&bytes);
                app.feed_bytes(&mapped);
            }
            Ev::KeyPress(k) => {
                // Input-prompt mode swallows keystrokes: nothing goes
                // to the serial port until Enter (submit) or Esc/Ctrl-C
                // (cancel). Handled BEFORE scroll / macro / hotkey so
                // the user can't accidentally trigger anything else
                // while composing a path or a baud rate.
                if app.input_prompt.is_some() {
                    handle_prompt_key(&mut app, &k, &mut port);
                    continue;
                }
                // Scroll keys are handled OUTSIDE the hotkey state
                // machine so they don't consume Ctrl-A prefix state.
                if is_scroll_key(&k) {
                    handle_scroll(&mut app, &k);
                    continue;
                }
                // F-key macros take precedence over the hotkey state
                // machine (same policy as plain term). Runs through
                // the TUI's newline transform so consistent with
                // typed keystrokes.
                if let Some(bytes) = opts.macros.lookup(&k) {
                    let to_send = app.newline_mode.rewrite(bytes);
                    if let Err(e) = port.write_all(&to_send) {
                        eprintln!("serial write failed (macro): {e}");
                        break "serial write failed".to_string();
                    }
                    continue;
                }
                let action = hotkey.handle(k);
                match action {
                    Action::Nothing => {}
                    Action::PassThrough(bytes) => {
                        // Apply the app's current newline mode on the
                        // way out so Ctrl-A n takes effect in the TUI
                        // too (defaults to Passthrough — no-op).
                        let to_send = app.newline_mode.rewrite(&bytes);
                        if let Err(e) = port.write_all(&to_send) {
                            eprintln!("serial write failed: {e}");
                            break "serial write failed".to_string();
                        }
                    }
                    Action::Quit => break format!("user quit ({} q)", app.escape_prefix.display()),
                    Action::ShowHelp => {
                        let px = app.escape_prefix.display();
                        app.set_status_message(format!("{px}: q=quit f=full-scan l=pause c=clear s=save u=share x=hex p=paste a=baud h=hangup m=rx-nl ?=this"));
                    }
                    Action::ToggleLiveAnalysis => {
                        app.analyzer.live_display = !app.analyzer.live_display;
                        let state = if app.analyzer.live_display {
                            "on"
                        } else {
                            "off"
                        };
                        app.set_status_message(format!("live analysis display: {state}"));
                    }
                    Action::ClearFindings => {
                        let refreshed = app.analyzer.reset_and_rescan();
                        app.set_status_message(format!(
                            "findings cleared and re-scanned — {} finding(s) currently in log",
                            refreshed.len()
                        ));
                    }
                    Action::SaveFindings => save_findings(&mut app),
                    Action::CopyShareUrl => copy_share_url(&mut app),
                    Action::FullAnalysis => {
                        run_full_analysis(&mut app, &mut terminal)?;
                    }
                    Action::SendBreak => match port.set_break() {
                        Ok(()) => {
                            std::thread::sleep(std::time::Duration::from_millis(250));
                            let _ = port.clear_break();
                            app.set_status_message("BREAK sent (250ms)".to_string());
                        }
                        Err(e) => {
                            app.set_status_message(format!("BREAK failed: {e}"));
                        }
                    },
                    Action::ToggleDtr => {
                        // Track DTR state on the app so a toggle is idempotent.
                        // Default assumption is "asserted" (matches port open state).
                        app.dtr_state = !app.dtr_state;
                        match port.write_data_terminal_ready(app.dtr_state) {
                            Ok(()) => {
                                let level = if app.dtr_state {
                                    "asserted"
                                } else {
                                    "deasserted"
                                };
                                app.set_status_message(format!("DTR: {level}"));
                            }
                            Err(e) => {
                                app.dtr_state = !app.dtr_state;
                                app.set_status_message(format!("DTR toggle failed: {e}"));
                            }
                        }
                    }
                    Action::ToggleRts => {
                        app.rts_state = !app.rts_state;
                        match port.write_request_to_send(app.rts_state) {
                            Ok(()) => {
                                let level = if app.rts_state {
                                    "asserted"
                                } else {
                                    "deasserted"
                                };
                                app.set_status_message(format!("RTS: {level}"));
                            }
                            Err(e) => {
                                app.rts_state = !app.rts_state;
                                app.set_status_message(format!("RTS toggle failed: {e}"));
                            }
                        }
                    }
                    Action::ToggleHexMode => {
                        let on = app.toggle_hex_mode();
                        app.set_status_message(format!(
                            "hex display: {}",
                            if on { "on" } else { "off" }
                        ));
                    }
                    Action::SendFile => {
                        app.open_input_prompt(
                            InputIntent::PasteFile,
                            "paste file (Enter=send, Esc=cancel): ",
                        );
                    }
                    Action::ToggleLocalEcho => {
                        // TUI doesn't render TX bytes back to the pane
                        // today (bytes go straight to the port); local
                        // echo is a plain-terminal concept. Surface a
                        // note so the hotkey isn't silently a no-op.
                        app.set_status_message(
                            "local echo isn't meaningful in --tui (typed keys go straight to serial)".to_string()
                        );
                    }
                    Action::CycleNewlineMode => {
                        app.newline_mode = app.newline_mode.next_in_cycle();
                        app.set_status_message(format!(
                            "newline mode (on send): {}",
                            app.newline_mode.label()
                        ));
                    }
                    Action::ChangeBaud => {
                        app.open_input_prompt(
                            InputIntent::ChangeBaud,
                            format!("new baud (current: {}, Enter=set, Esc=cancel): ", app.baud),
                        );
                    }
                    Action::ShowInfo => {
                        app.set_status_message(format!(
                            "port={} baud={} DTR={} RTS={} newline(TX)={}",
                            app.port_name,
                            app.baud,
                            if app.dtr_state { "H" } else { "L" },
                            if app.rts_state { "H" } else { "L" },
                            app.newline_mode.label()
                        ));
                    }
                    Action::CycleBackspaceMode => {
                        let m = hotkey.cycle_backspace_mode();
                        app.set_status_message(format!("backspace: {}", m.label()));
                    }
                    Action::CycleRxNewlineMode => {
                        app.rx_newline_mode = app.rx_newline_mode.cycle();
                        app.set_status_message(format!(
                            "RX newline map: {}",
                            app.rx_newline_mode.label()
                        ));
                    }
                    Action::Hangup => {
                        // Close + reopen the port. Fixes a wedged
                        // USB-serial adapter without a full session
                        // quit. Preserves the current baud + all
                        // runtime toggles + the analyzer's captured
                        // bytes (only the fd churns).
                        app.set_status_message("hangup: closing port, reopening in 500ms...");
                        terminal.draw(|f| render::draw(f, &app))?;
                        // 1. Stop the current reader (drops its port clone).
                        reader_shutdown.store(true, Ordering::Relaxed);
                        let old = std::mem::replace(&mut serial_thread, thread::spawn(|| {}));
                        let _ = old.join();
                        // 2. Give the device 500ms to notice the fd
                        // going quiet before we try to reopen.
                        std::thread::sleep(Duration::from_millis(500));
                        // 3. Reopen at the app's current baud (may
                        // differ from opts.baud if the user has hit
                        // Ctrl-A a since startup).
                        match open_serial_with_hints(
                            &opts.port_name,
                            app.baud,
                            opts.data_bits,
                            opts.parity,
                            opts.stop_bits,
                            opts.flow_control,
                        ) {
                            Ok(new_port) => {
                                port = new_port; // old port drops → fd closes
                                let _ = port.write_data_terminal_ready(app.dtr_state);
                                let _ = port.write_request_to_send(app.rts_state);
                                app.set_status_message(format!(
                                    "hangup: reopened at {} baud",
                                    app.baud
                                ));
                            }
                            Err(e) => {
                                app.set_status_message(format!(
                                    "hangup: reopen failed: {e} — resuming with existing port"
                                ));
                            }
                        }
                        // 4. Restart the reader against whichever
                        // port we ended up with.
                        reader_shutdown.store(false, Ordering::Relaxed);
                        match port.try_clone() {
                            Ok(rp) => {
                                serial_thread =
                                    spawn_serial_reader(rp, tx.clone(), reader_shutdown.clone());
                            }
                            Err(e) => {
                                app.set_status_message(format!("hangup: reader clone failed: {e}"));
                                break "reader clone failed after hangup".to_string();
                            }
                        }
                    }
                    Action::UnknownCommand(c) => {
                        let px = app.escape_prefix.display();
                        app.set_status_message(format!(
                            "unknown {px} command: '{c}' ({px} ? for help)"
                        ));
                    }
                }
            }
            Ev::SerialDisconnected(msg) => {
                app.set_status_message(format!("serial disconnected: {msg}"));
                // Give the user a beat to read the message before we tear down.
                terminal.draw(|f| render::draw(f, &app))?;
                thread::sleep(Duration::from_secs(2));
                break "serial disconnected".to_string();
            }
        }

        if app.should_quit {
            break "app requested quit".to_string();
        }
    };

    // Signal + join background threads.
    shutdown.store(true, Ordering::Relaxed);
    reader_shutdown.store(true, Ordering::Relaxed);
    drop(tx);
    let _ = serial_thread.join();
    let _ = keyboard_thread.join();

    leave_tui(&mut terminal)?;
    eprintln!("[bootintel] session ended — {exit_reason}");
    Ok(())
}

fn enter_tui() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout());
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn leave_tui(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    // Ensure the shell prompt lands cleanly.
    let _ = stdout().flush();
    Ok(())
}

fn is_scroll_key(k: &KeyEvent) -> bool {
    use crossterm::event::KeyCode;
    matches!(
        k.code,
        KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home | KeyCode::End
    )
}

fn handle_scroll(app: &mut App, k: &KeyEvent) {
    use crossterm::event::KeyCode;
    match k.code {
        KeyCode::PageUp => app.scroll_serial_up(10),
        KeyCode::PageDown => app.scroll_serial_down(10),
        KeyCode::Home => app.scroll_serial_up(usize::MAX),
        KeyCode::End => app.scroll_serial_to_bottom(),
        _ => {}
    }
    // Focus the serial pane when the user scrolls it.
    app.focused_pane = Pane::Serial;
}

fn save_findings(app: &mut App) {
    let path = app.analyzer.default_summary_path();
    let findings = app.analyzer.findings_snapshot().to_vec();
    let captured = app.analyzer.captured_bytes();
    let version = env!("CARGO_PKG_VERSION");
    match std::fs::File::create(&path) {
        Ok(mut f) => match crate::analyze::render::write_summary(
            &mut f,
            version,
            captured,
            bootintel_detectors::detector_labels().len(),
            &findings,
        ) {
            Ok(()) => app.set_status_message(format!(
                "saved {} finding(s) to {} ({} log bytes)",
                findings.len(),
                path.display(),
                captured
            )),
            Err(e) => app.set_status_message(format!("save failed: {e}")),
        },
        Err(e) => app.set_status_message(format!("could not create {}: {e}", path.display())),
    }
}

fn copy_share_url(app: &mut App) {
    let log_so_far = app.analyzer.log_so_far();
    let compressed = lz_str::compress_to_encoded_uri_component(log_so_far);
    let url = format!("https://bootintel.com/tools/fingerprint?z={compressed}");
    match copy_to_clipboard(&url) {
        Ok(()) => app.set_status_message(format!(
            "share URL copied to clipboard ({} chars)",
            url.len()
        )),
        Err(reason) => {
            app.set_status_message(format!("clipboard unavailable ({reason}) — url: {url}"))
        }
    }
}

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

fn run_full_analysis(
    app: &mut App,
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
) -> Result<()> {
    if app.api_config.is_none() {
        let px = app.escape_prefix.display();
        app.set_status_message(format!(
            "{px} f needs --api (or --api --preview); server integration is off in this session"
        ));
        return Ok(());
    }
    // Mark in-flight + draw once so the user sees the "submitting"
    // state before we block on the HTTP call.
    app.mark_api_in_flight();
    terminal.draw(|f| render::draw(f, app))?;

    let cfg = app.api_config.clone().unwrap();
    let log_so_far = app.analyzer.log_so_far().to_string();
    let client = ScanClient::new(&cfg.base_url);
    let device = cfg.device_name.as_deref();
    let result = if cfg.preview || cfg.api_key.is_none() {
        client.preview_scan(&log_so_far, device)
    } else {
        client.authed_scan(&log_so_far, device, cfg.api_key.as_deref().unwrap())
    };
    match result {
        Ok(resp) => {
            let visible = resp.findings_visible.unwrap_or(resp.findings.len() as u32);
            let hidden = resp.findings_hidden.unwrap_or(0);
            app.mark_api_ok(resp);
            app.set_status_message(format!("server ok — {visible} visible, {hidden} hidden"));
        }
        Err(e) => {
            let msg = e.to_string();
            app.mark_api_err(msg.clone());
            app.set_status_message(format!("server failed: {msg}"));
        }
    }
    Ok(())
}

// Reference so a `bootintel term --tui` future path could grow into
// this loop the same way — kept until we know we don't want it.
#[allow(dead_code)]
fn _serial_traits<P: SerialPort>(_p: P) {}

/// Spawn a reader thread that owns `port` and pushes SerialBytes /
/// SerialDisconnected events until `shutdown` flips to true. Extracted
/// so Ctrl-A h can bounce a fresh reader against a reopened port
/// without also killing the keyboard thread.
fn spawn_serial_reader(
    mut port: Box<dyn SerialPort>,
    tx: mpsc::SyncSender<Ev>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            match port.read(&mut buf) {
                Ok(0) => continue,
                Ok(n) => {
                    if tx.send(Ev::SerialBytes(buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(e) => {
                    // If shutdown was requested (hangup), swallow the
                    // read error — the fd going away is expected. The
                    // main thread will spawn a new reader against the
                    // reopened port.
                    if !shutdown.load(Ordering::Relaxed) {
                        let _ = tx.send(Ev::SerialDisconnected(e.to_string()));
                    }
                    return;
                }
            }
        }
    })
}

/// Handle a keystroke while an input prompt is active. Enter submits
/// (dispatches by intent); Esc / Ctrl-C cancels; Backspace erases;
/// printable chars append to the buffer. Everything else is ignored
/// so the user can't accidentally scroll / quit / trigger a hotkey
/// mid-input.
fn handle_prompt_key(app: &mut App, k: &KeyEvent, port: &mut Box<dyn SerialPort>) {
    match k.code {
        KeyCode::Enter => {
            if let Some(prompt) = app.take_input_prompt() {
                submit_prompt(app, prompt, port);
            }
        }
        KeyCode::Esc => {
            app.cancel_input_prompt();
            app.set_status_message("cancelled");
        }
        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
            app.cancel_input_prompt();
            app.set_status_message("cancelled");
        }
        KeyCode::Backspace => {
            if let Some(prompt) = app.input_prompt.as_mut() {
                prompt.buffer.pop();
            }
        }
        KeyCode::Char(c) => {
            if let Some(prompt) = app.input_prompt.as_mut() {
                prompt.buffer.push(c);
            }
        }
        _ => {}
    }
}

/// Dispatch a submitted prompt buffer by intent.
fn submit_prompt(app: &mut App, prompt: InputPrompt, port: &mut Box<dyn SerialPort>) {
    let trimmed = prompt.buffer.trim();
    if trimmed.is_empty() {
        app.set_status_message("cancelled (empty input)");
        return;
    }
    match prompt.intent {
        InputIntent::PasteFile => paste_file(app, port, trimmed),
        InputIntent::ChangeBaud => change_baud(app, port, trimmed),
    }
}

/// Read `path` and stream its bytes to the serial port with per-line
/// pacing (20ms/line). Same policy as the plain-terminal paste path —
/// enough headroom for U-Boot / low-baud getty receivers.
fn paste_file(app: &mut App, port: &mut Box<dyn SerialPort>, path: &str) {
    let contents = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            app.set_status_message(format!("paste failed: could not read {path}: {e}"));
            return;
        }
    };
    let payload = app.newline_mode.rewrite(&contents);
    let mut sent = 0usize;
    let mut start = 0usize;
    while start < payload.len() {
        let end = match payload[start..].iter().position(|&b| b == b'\n') {
            Some(idx) => start + idx + 1,
            None => payload.len(),
        };
        let chunk = &payload[start..end];
        if let Err(e) = port.write_all(chunk) {
            app.set_status_message(format!("paste failed after {sent} bytes: {e}"));
            return;
        }
        let _ = port.flush();
        sent += chunk.len();
        start = end;
        if start < payload.len() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    app.set_status_message(format!("paste complete: {sent} bytes from {path}"));
}

/// Parse a baud rate + apply it to the open port. Preserves the port
/// (no reopen — set_baud_rate mutates in place on all supported
/// backends).
fn change_baud(app: &mut App, port: &mut Box<dyn SerialPort>, input: &str) {
    let rate: u32 = match input.parse() {
        Ok(n) if n > 0 => n,
        _ => {
            app.set_status_message(format!("not a valid baud rate: {input}"));
            return;
        }
    };
    match port.set_baud_rate(rate) {
        Ok(()) => {
            app.baud = rate;
            app.set_status_message(format!("baud rate now {rate}"));
        }
        Err(e) => app.set_status_message(format!("set_baud_rate failed: {e}")),
    }
}
