//! Ratatui draw function.
//!
//! Pure — takes a `&App` snapshot + a `Frame`; produces widgets.
//! No state mutation, no I/O other than the frame itself. Called
//! from the main loop on every event and on every ~50ms tick.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use bootintel_detectors::Finding;

use super::app::{ApiStatus, App, InputPrompt, Pane};
use crate::analyze::render::sanitize_for_term;
use crate::api::response::ApiFinding;
use bootintel_detectors::CRITICAL_LABELS;

pub fn draw(f: &mut Frame, app: &App) {
    let has_prompt = app.input_prompt.is_some();
    let mut constraints: Vec<Constraint> = vec![
        Constraint::Length(1), // title bar
        Constraint::Min(0),    // main
    ];
    if has_prompt {
        constraints.push(Constraint::Length(1)); // input row
    }
    constraints.push(Constraint::Length(1)); // status bar
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(f.area());

    render_title_bar(f, outer[0], app);
    render_main(f, outer[1], app);
    if let Some(prompt) = &app.input_prompt {
        render_input_row(f, outer[2], prompt);
        render_status_bar(f, outer[3], app);
    } else {
        render_status_bar(f, outer[2], app);
    }
}

fn render_input_row(f: &mut Frame, area: Rect, prompt: &InputPrompt) {
    // Render as a single line: "<label><buffer>_" where _ marks the
    // insertion point. Reverse-video attribute so it visually distinct
    // from the status bar (which is also reversed — but the cursor
    // glyph + colon make the intent obvious).
    let text = format!("{}{}_", prompt.label, prompt.buffer);
    let p = Paragraph::new(text).style(Style::default().fg(ratatui::style::Color::Yellow));
    f.render_widget(p, area);
}

fn render_title_bar(f: &mut Frame, area: Rect, app: &App) {
    let elapsed = app.connected_at.elapsed();
    let mins = elapsed.as_secs() / 60;
    let secs = elapsed.as_secs() % 60;
    let bytes = format_bytes(app.total_bytes);
    let findings = app.analyzer.findings_snapshot().len();
    let title = format!(
        " bootintel analyze  {}  @ {}  ── {mins}:{secs:02}  ── {bytes}  ── {findings} findings ",
        app.port_name, app.baud
    );
    let p = Paragraph::new(title).style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(p, area);
}

fn render_main(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);
    render_serial_pane(f, cols[0], app);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(cols[1]);
    render_findings_pane(f, right[0], app);
    render_server_pane(f, right[1], app);
}

fn render_serial_pane(f: &mut Frame, area: Rect, app: &App) {
    let border_style = if app.focused_pane == Pane::Serial {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let mode_tag = if app.hex_mode { " [hex]" } else { "" };
    let title = if app.serial_scroll == 0 {
        format!(" serial{mode_tag} ")
    } else {
        format!(
            " serial{mode_tag}  (scroll: {} up from bottom) ",
            app.serial_scroll
        )
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // In hex mode we render the raw-bytes ring as one hexdump line
    // per 16 bytes. In text mode we render decoded lines. Both use
    // the same last-N-minus-scroll windowing.
    let hex_lines: Vec<String>;
    let text_lines: Vec<&str>;
    let lines: &[&str] = if app.hex_mode {
        hex_lines = app.hex_display();
        text_lines = hex_lines.iter().map(|s| s.as_str()).collect();
        &text_lines
    } else {
        text_lines = app.serial_display();
        &text_lines
    };
    let height = inner.height as usize;
    let total = lines.len();
    let end = total.saturating_sub(app.serial_scroll);
    let start = end.saturating_sub(height);
    let visible: Vec<Line> = lines[start..end]
        .iter()
        .map(|l| Line::from(l.to_string()))
        .collect();
    let p = Paragraph::new(visible).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

fn render_findings_pane(f: &mut Frame, area: Rect, app: &App) {
    let border_style = if app.focused_pane == Pane::Findings {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(format!(
            " findings (client) — {} ",
            app.analyzer.findings_snapshot().len()
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let items: Vec<ListItem> = app
        .analyzer
        .findings_snapshot()
        .iter()
        .map(finding_to_list_item)
        .collect();
    let list = List::new(items);
    f.render_widget(list, inner);
}

fn finding_to_list_item(f: &Finding) -> ListItem<'_> {
    let is_critical = CRITICAL_LABELS.contains(&f.label.as_str());
    let (glyph, style) = if is_critical {
        ("⚠", Style::default().fg(ratatui::style::Color::Yellow))
    } else {
        ("●", Style::default().fg(ratatui::style::Color::Green))
    };
    // Sanitize against ANSI-escape injection from hostile boot logs
    // that flow through detector fields into the render path.
    let label = sanitize_for_term(&f.label);
    let value = sanitize_for_term(&f.value);
    let spans = vec![
        Span::styled(format!("{glyph} "), style),
        Span::styled(
            format!("{label:<20}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::raw(value),
    ];
    ListItem::new(Line::from(spans))
}

fn render_server_pane(f: &mut Frame, area: Rect, app: &App) {
    let border_style = if app.focused_pane == Pane::Server {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default()
    };
    let title = server_pane_title(app);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = server_pane_body(app);
    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

fn server_pane_title(app: &App) -> String {
    match &app.api_status {
        ApiStatus::Idle => " server — idle ".into(),
        ApiStatus::InFlight { started } => {
            let s = started.elapsed().as_secs();
            format!(" server — submitting ({s}s) ")
        }
        ApiStatus::Ok { at } => {
            let ago = at.elapsed().as_secs();
            format!(" server — ok ({ago}s ago) ")
        }
        ApiStatus::Err { at } => {
            let ago = at.elapsed().as_secs();
            format!(" server — error ({ago}s ago) ")
        }
    }
}

fn server_pane_body(app: &App) -> Vec<Line<'static>> {
    match (&app.api_status, &app.api_config) {
        (ApiStatus::Idle, None) => vec![
            Line::from("server integration is off"),
            Line::from(""),
            Line::from("re-launch with:"),
            Line::from(Span::styled(
                "  bootintel analyze --api --preview <port>",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from("  (free anonymous quota — 3/day per IP)"),
            Line::from(""),
            Line::from("or with an API key:"),
            Line::from(Span::styled(
                "  export BOOTINTEL_API_KEY=bik_...",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "  bootintel analyze --api --tui <port>",
                Style::default().add_modifier(Modifier::BOLD),
            )),
        ],
        (ApiStatus::Idle, Some(_)) => vec![
            Line::from(format!(
                "press  {} f  to submit the log so far",
                app.escape_prefix.display()
            )),
            Line::from("to bootintel.com for full CVE matching + exploit paths."),
        ],
        (ApiStatus::InFlight { .. }, _) => vec![
            Line::from("submitting to bootintel.com..."),
            Line::from(""),
            Line::from("(the terminal is paused until the server responds)"),
        ],
        (ApiStatus::Ok { .. }, _) => render_server_ok(app),
        (ApiStatus::Err { .. }, _) => vec![
            Line::from(Span::styled(
                app.api_error
                    .clone()
                    .unwrap_or_else(|| "unknown error".into()),
                Style::default().fg(ratatui::style::Color::Red),
            )),
            Line::from(""),
            Line::from(format!("press {} f to retry", app.escape_prefix.display())),
        ],
    }
}

fn render_server_ok(app: &App) -> Vec<Line<'static>> {
    let resp = match &app.api_result {
        Some(r) => r,
        None => return vec![Line::from("(server ok but no body captured)")],
    };
    let mut out: Vec<Line> = Vec::new();

    if let Some(dev) = &resp.device_name {
        out.push(Line::from(vec![
            Span::styled("device: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(dev.clone()),
        ]));
    }
    if let (Some(vis), Some(hid)) = (resp.findings_visible, resp.findings_hidden) {
        let total = resp.findings_total.unwrap_or(vis + hid);
        out.push(Line::from(format!(
            "{total} findings — {vis} shown, {hid} hidden"
        )));
    }
    out.push(Line::from(""));
    for f in &resp.findings {
        out.push(server_finding_line(f));
    }
    if resp.cve_details_locked.unwrap_or(false) {
        out.push(Line::from(""));
        out.push(Line::from(Span::styled(
            "CVE details locked on this plan — see bootintel.com/pricing",
            Style::default().fg(ratatui::style::Color::Yellow),
        )));
    }
    out
}

fn server_finding_line(f: &ApiFinding) -> Line<'static> {
    let label = sanitize_for_term(f.display_title());
    let value = sanitize_for_term(f.display_body());
    let mut spans = vec![
        Span::styled("● ", Style::default().fg(ratatui::style::Color::Green)),
        Span::styled(
            format!("{label:<18}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::raw(value),
    ];
    if let Some(cve) = &f.cve_id {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            cve.clone(),
            Style::default().fg(ratatui::style::Color::Red),
        ));
        if let Some(score) = f.cvss_score {
            spans.push(Span::raw(format!(" (CVSS {score:.1})")));
        }
    }
    Line::from(spans)
}

fn render_status_bar(f: &mut Frame, area: Rect, app: &App) {
    // Spell out the prefix on every hotkey so users don't think
    // `q` alone quits — they need <prefix> q.
    let px = app.escape_prefix.display();
    let base = format!(
        " {px} ?=help · {px} q=quit · {px} f=full-scan · {px} l=pause · {px} c=clear · {px} s=save · {px} u=share · PgUp/PgDn=scroll "
    );
    let content = if let Some((msg, _, _)) = &app.status_message {
        format!(" [bootintel] {msg} ")
    } else {
        base
    };
    let p = Paragraph::new(content).style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(p, area);
}

fn format_bytes(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f32 / 1024.0)
    } else {
        format!("{:.1} MiB", n as f32 / (1024.0 * 1024.0))
    }
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_scales() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn server_pane_title_reflects_status() {
        use crate::analyze::state::AnalyzeState;
        use crate::term::hotkey::EscapePrefix;
        let mut a = App::new(
            "/dev/x".into(),
            115200,
            AnalyzeState::new(None),
            None,
            EscapePrefix::DEFAULT,
        );
        assert!(server_pane_title(&a).contains("idle"));
        a.mark_api_in_flight();
        assert!(server_pane_title(&a).contains("submitting"));
        a.mark_api_err("boom");
        assert!(server_pane_title(&a).contains("error"));
    }
}
