//! `bootintel init` — bootstrap the per-user config directory.
//!
//! Creates:
//!   $XDG_CONFIG_HOME/bootintel/  (or %APPDATA%\bootintel\ on Windows)
//!     macros    — commented stub with a few example bindings
//!
//! Also prints one-liner hints for wiring shell completions into the
//! user's rc file (per detected shell). Deliberately doesn't touch
//! any rc file directly — an installer that appends to .zshrc without
//! asking is a common way to lose user trust.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Overwrite existing files. Default: refuse and leave your
    /// config alone. Use --force if you're sure.
    #[arg(long)]
    force: bool,

    /// Config directory. Defaults to $XDG_CONFIG_HOME/bootintel
    /// (Unix) / %APPDATA%\bootintel (Windows).
    #[arg(long, value_name = "DIR")]
    config_dir: Option<PathBuf>,
}

const MACROS_STUB: &str = "\
# bootintel function-key macros — pressed during `term` / `analyze`, sent to serial.
#
# Syntax: Fn=value
#   Fn is F1..F12 (case-insensitive)
#   value supports \\r \\n \\t \\0 \\\\ \\xHH escapes
#
# Runs through the TX newline mode (`--newline` / Ctrl-A n) so an
# F1=printenv\\r matches what typing 'printenv' + Enter would send.
#
# Uncomment / edit / add. `--macro F1=...` on the CLI wins over any
# same-key binding here.

# F1=printenv\\r
# F2=setenv autostart no\\r
# F5=reset\\r
# F10=version\\r
";

pub fn run(args: Args) -> Result<()> {
    let stdout = io::stdout();
    let color_on = crate::output::resolve_color_mode(false, &stdout) == crate::output::ColorMode::On;
    let (bold_open, bold_close) = if color_on {
        ("\x1b[1m", "\x1b[0m")
    } else {
        ("", "")
    };
    let (green_open, green_close) = if color_on {
        ("\x1b[32m", "\x1b[0m")
    } else {
        ("", "")
    };
    let (dim_open, dim_close) = if color_on {
        ("\x1b[2m", "\x1b[0m")
    } else {
        ("", "")
    };

    // If the user passed --config-dir, honor it verbatim as a
    // directory. Otherwise derive it from the default MACROS FILE
    // path (parent) so the two commands agree on where to look.
    let dir = match args.config_dir {
        Some(explicit) => explicit,
        None => crate::term::macros::default_config_path()
            .and_then(|p| p.parent().map(|par| par.to_path_buf()))
            .ok_or_else(|| anyhow::anyhow!(
                "couldn't determine a config directory (no $XDG_CONFIG_HOME, $HOME, or %APPDATA%). Pass --config-dir DIR explicitly."
            ))?,
    };

    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let mut out = stdout.lock();
    writeln!(
        out,
        "{bold_open}bootintel init{bold_close} → {}",
        dir.display()
    )?;
    writeln!(out)?;

    // ── macros stub ─────────────────────────────────────────────
    let macros_path = dir.join("macros");
    let macros_action = write_or_skip(&macros_path, MACROS_STUB, args.force)?;
    match macros_action {
        WriteAction::Created => writeln!(
            out,
            "  {green_open}✓ created{green_close}   {}",
            macros_path.display()
        )?,
        WriteAction::Overwritten => writeln!(
            out,
            "  {green_open}✓ replaced{green_close}  {}  (--force)",
            macros_path.display()
        )?,
        WriteAction::Skipped => writeln!(
            out,
            "  {dim_open}·  exists{dim_close}     {}  (use --force to replace)",
            macros_path.display()
        )?,
    }
    writeln!(out)?;

    // ── shell-completion install hints ─────────────────────────
    let shell = detected_shell();
    writeln!(
        out,
        "{bold_open}shell completions{bold_close} (skip if you already have them):"
    )?;
    match shell.as_deref() {
        Some("bash") => {
            writeln!(out, "  {dim_open}# bash — append to ~/.bashrc:{dim_close}")?;
            writeln!(out, "  eval \"$(bootintel completions bash)\"")?;
        }
        Some("zsh") => {
            writeln!(
                out,
                "  {dim_open}# zsh — install into your fpath:{dim_close}"
            )?;
            writeln!(
                out,
                "  bootintel completions zsh > \"${{fpath[1]}}/_bootintel\""
            )?;
        }
        Some("fish") => {
            writeln!(
                out,
                "  {dim_open}# fish — install into your completions dir:{dim_close}"
            )?;
            writeln!(
                out,
                "  bootintel completions fish > ~/.config/fish/completions/bootintel.fish"
            )?;
        }
        _ => {
            writeln!(out, "  {dim_open}# pick your shell:{dim_close}")?;
            writeln!(
                out,
                "  bootintel completions bash | zsh | fish | elvish | powershell"
            )?;
        }
    }
    writeln!(out)?;

    writeln!(out, "{bold_open}next{bold_close}:")?;
    writeln!(out, "  bootintel demo         # see what a scan looks like")?;
    writeln!(
        out,
        "  bootintel doctor       # env sanity-check (serial devices, dialout, tmux)"
    )?;
    writeln!(
        out,
        "  bootintel ports        # list serial devices attached to this machine"
    )?;

    let _ = out.flush();
    Ok(())
}

enum WriteAction {
    Created,
    Overwritten,
    Skipped,
}

fn write_or_skip(path: &std::path::Path, contents: &str, force: bool) -> Result<WriteAction> {
    if path.exists() && !force {
        return Ok(WriteAction::Skipped);
    }
    let action = if path.exists() {
        WriteAction::Overwritten
    } else {
        WriteAction::Created
    };
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(action)
}

fn detected_shell() -> Option<String> {
    // Prefer $SHELL basename since it's what the user's login shell
    // actually is. Fall back to nothing rather than guessing.
    let shell_path = std::env::var("SHELL").ok()?;
    std::path::Path::new(&shell_path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string())
}
