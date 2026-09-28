//! `bootintel verdict <file>` — what the U-Boot environment permits.
//!
//! Every other command here reads a boot log, which is a record of what the
//! firmware chose to print. This reads what an operator pulled OUT of a board
//! after interrupting autoboot: a `printenv` dump. The difference is the whole
//! reason for taking the prompt. A boot log can say autoboot looks
//! interruptible; the environment says exactly what happens when you interrupt
//! it, and whether you can change what boots.
//!
//! It runs entirely offline, unlike `scan --api`, and that is deliberate. A
//! U-Boot environment is the most sensitive thing in a capture — `ipaddr`,
//! `serverip`, `ethaddr`, TFTP hosts, a client's internal addressing — so
//! requiring an upload to learn what it permits would put this out of reach of
//! exactly the people it is for. The rules live in
//! `bootintel_detectors::boot_chain` and are pinned against the server
//! implementation by `crates/detectors/tests/boot_chain.rs`.
//!
//! Absence is never reported as good news: U-Boot prints only what is set, so
//! a missing `bootdelay` is `unknown`, not `hardened`.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::io::Write;

use bootintel_detectors::boot_chain::{self, UbootSession, Verdict};

use crate::analyze::render::sanitize_for_term;
use crate::output::{self, ColorMode};

/// Nothing to inspect: an empty file, an empty pipe, whitespace only. The same
/// code `scan` uses, for the same reason — a capture that never happened must
/// not report green.
const EXIT_EMPTY_INPUT: i32 = 2;

/// Content, but no interactive session in it, so there is no environment to
/// assess. Distinct from an empty capture, and non-zero because "I could not
/// answer" must never look like "nothing is wrong".
const EXIT_NO_SESSION: i32 = 3;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to a capture containing a U-Boot session, or `-` for stdin.
    #[arg(value_name = "FILE")]
    file: String,

    /// Read the capture from stdin regardless of `<FILE>`.
    #[arg(long)]
    stdin: bool,

    /// Machine-readable output. Keys match the server's analysis response
    /// (`uboot_shell`, `uboot_env`, `boot_chain_verdict`), so a consumer can
    /// move between this and `scan --api` without remapping anything.
    #[arg(long)]
    json: bool,

    /// Exit non-zero if any verdict is `exposed`. For CI gating a build's
    /// shipped environment: `bootintel verdict capture.log --gate-exposed`.
    #[arg(long)]
    gate_exposed: bool,

    /// Suppress ANSI colour. Colour is otherwise on only when stdout is a TTY
    /// and $NO_COLOR is unset.
    #[arg(long)]
    no_color: bool,
}

pub fn run(args: Args) -> Result<()> {
    let log = if args.stdin || args.file == "-" {
        crate::input::read_stdin()?
    } else {
        let path = std::path::PathBuf::from(&args.file);
        crate::input::read_file(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "no such file: {}\n  Check the path, or pipe from stdin: \
                 bootintel verdict - < path/to/capture.log",
                args.file
            ),
            _ => anyhow::Error::from(e).context(format!("reading {}", args.file)),
        })?
    };
    log.report_replacements();

    if log.text.trim().is_empty() {
        eprintln!(
            "bootintel: empty capture; nothing to assess ({})\n  \
             Check that the capture actually ran and that the path is the one it wrote.",
            log.source_label
        );
        std::process::exit(EXIT_EMPTY_INPUT);
    }

    let (session, verdicts) = boot_chain::assess(&log.text);

    let stdout = std::io::stdout();
    let color = output::resolve_color_mode(args.no_color, &stdout);
    let mut out = stdout.lock();

    if args.json {
        let payload = json(&log.source_label, &session, &verdicts);
        if let Err(e) = serde_json::to_writer_pretty(&mut out, &payload)
            .map_err(anyhow::Error::from)
            .and_then(|()| writeln!(out).map_err(anyhow::Error::from))
        {
            // A reader that has seen enough is not a failure, and must not
            // become the verdict either. Same rule as `scan`.
            if !crate::is_broken_pipe(&e) {
                return Err(e);
            }
        }
    } else if let Err(e) = write_text(&mut out, &log.source_label, &session, &verdicts, color) {
        if !crate::is_broken_pipe(&e) {
            return Err(e);
        }
    }

    // No session means no answer, which is not the same as a good answer.
    if !session.reached {
        let _ = out.flush();
        eprintln!(
            "bootintel: no U-Boot session found in {}; nothing was assessed\n  \
             This command reads a `printenv` dump taken at the prompt, not a boot log. \
             Capture one with `bootintel term`, interrupt autoboot, run `printenv`, and \
             save the session. `bootintel scan` is the command for a plain boot log.",
            log.source_label
        );
        std::process::exit(EXIT_NO_SESSION);
    }

    if args.gate_exposed {
        let exposed: Vec<&Verdict> = verdicts.iter().filter(|v| v.state == "exposed").collect();
        if !exposed.is_empty() {
            let _ = out.flush();
            eprintln!(
                "bootintel: {} exposed {} in {}",
                exposed.len(),
                if exposed.len() == 1 {
                    "verdict"
                } else {
                    "verdicts"
                },
                log.source_label
            );
            for v in exposed {
                eprintln!("  {} — {}", v.title, v.evidence);
            }
            std::process::exit(1);
        }
    }
    Ok(())
}

fn json(source: &str, session: &UbootSession, verdicts: &[Verdict]) -> serde_json::Value {
    let mut shell = serde_json::Map::new();
    shell.insert("reached".into(), session.reached.into());
    shell.insert("evidence".into(), session.evidence.clone().into());
    if let (Some(used), Some(total)) = (session.env_used_bytes, session.env_total_bytes) {
        shell.insert("env_used_bytes".into(), used.into());
        shell.insert("env_total_bytes".into(), total.into());
    }
    serde_json::json!({
        "source": source,
        "uboot_shell": shell,
        "uboot_env": session.env.iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::from(v.clone())))
            .collect::<serde_json::Map<String, serde_json::Value>>(),
        "boot_chain_verdict": verdicts.iter().map(|v| serde_json::json!({
            "title": v.title,
            "state": v.state,
            "detail": v.detail,
            "evidence": v.evidence,
            "severity": v.severity,
            "remediation": v.remediation,
        })).collect::<Vec<_>>(),
    })
}

/// Colour by what the reader has to do about it, not by severity name.
fn state_code(state: &str) -> &'static str {
    match state {
        "exposed" => output::ANSI_BOLD_RED,
        "confirmed" => output::ANSI_BOLD_CYAN,
        _ => output::ANSI_DIM,
    }
}

pub(crate) fn write_text<W: Write>(
    out: &mut W,
    source: &str,
    session: &UbootSession,
    verdicts: &[Verdict],
    color: ColorMode,
) -> Result<()> {
    let on = color == ColorMode::On;
    if !session.reached {
        writeln!(out, "no U-Boot session in {source}")?;
        return Ok(());
    }
    // Everything below is device-controlled text, so it is sanitized before it
    // reaches a terminal: a crafted environment value could otherwise inject
    // escape sequences into a consultant's session.
    writeln!(
        out,
        "  {} in {source}",
        output::wrap("U-Boot session", output::ANSI_BOLD_CYAN, on)
    )?;
    writeln!(
        out,
        "    evidence  {}",
        sanitize_for_term(&session.evidence)
    )?;
    let size = match (session.env_used_bytes, session.env_total_bytes) {
        (Some(used), Some(total)) => format!(", environment {used}/{total} bytes"),
        _ => String::new(),
    };
    writeln!(
        out,
        "    {} variable{}{size}",
        session.env.len(),
        if session.env.len() == 1 { "" } else { "s" }
    )?;
    writeln!(out)?;

    for v in verdicts {
        // Pad on the visible width: ANSI escapes have zero display width but
        // Rust's formatter counts bytes, so `{:9}` on a wrapped string would
        // knock every column out of line.
        let pad = 9usize.saturating_sub(v.state.chars().count());
        writeln!(
            out,
            "  {}{:pad$}  {}",
            output::wrap(&v.state, state_code(&v.state), on),
            "",
            output::wrap(&sanitize_for_term(&v.title), output::ANSI_BOLD_CYAN, on)
        )?;
        writeln!(out, "      {}", sanitize_for_term(&v.detail))?;
        writeln!(
            out,
            "      {} {}",
            output::wrap("read from", output::ANSI_DIM, on),
            sanitize_for_term(&v.evidence)
        )?;
        if let Some(fix) = &v.remediation {
            writeln!(
                out,
                "      {} {}",
                output::wrap("fix", output::ANSI_DIM, on),
                sanitize_for_term(fix)
            )?;
        }
        writeln!(out)?;
    }
    Ok(())
}
