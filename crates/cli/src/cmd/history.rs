//! `bootintel history` — inspect the append-only scan-history log.
//!
//! Output shapes:
//!   * (default)   → last 20 entries as a text table (newest first)
//!   * --limit N   → override the 20-entry default
//!   * --json      → dump full JSONL to stdout (for grep / jq consumers)
//!   * --path      → print the history file path (whether or not it exists)
//!   * --clear     → truncate the history file (prompt unless --yes)
//!
//! History writes are opt-out via `BOOTINTEL_NO_HISTORY=1` or
//! `no_history = true` in the config file. See `crate::history` for
//! append semantics + rotation.

use anyhow::{bail, Result};
use clap::Args as ClapArgs;
use std::io::{self, IsTerminal, Write};

use crate::history::{self, display_shorten};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Number of entries to show (default: 20).
    #[arg(long, default_value_t = 20)]
    limit: usize,

    /// Dump the raw JSONL from the history file to stdout — the
    /// jq / grep composition path.
    #[arg(long, conflicts_with_all = ["path", "clear"])]
    json: bool,

    /// Print the history file path.
    #[arg(long, conflicts_with_all = ["json", "clear"])]
    path: bool,

    /// Truncate the history file (deletes the file + the `.1`
    /// rotated sibling). Prompts for confirmation unless --yes.
    #[arg(long, conflicts_with_all = ["json", "path"])]
    clear: bool,

    /// Skip the --clear confirmation prompt.
    #[arg(long)]
    yes: bool,
}

pub fn run(args: Args) -> Result<()> {
    if args.path {
        return run_path();
    }
    if args.json {
        return run_json();
    }
    if args.clear {
        return run_clear(args.yes);
    }
    run_table(args.limit)
}

fn run_path() -> Result<()> {
    match history::history_path() {
        Some(p) => {
            println!("{}", p.display());
            Ok(())
        }
        None => bail!("no platform state dir resolvable"),
    }
}

fn run_json() -> Result<()> {
    let path = history::history_path().ok_or_else(|| anyhow::anyhow!("no state dir"))?;
    if !path.exists() {
        return Ok(());
    }
    // Stream file → stdout unchanged. We don't parse / re-serialize
    // because a jq consumer wants the exact bytes we wrote, and
    // stripping malformed lines silently would hide corruption from
    // whoever's debugging.
    let mut f = std::fs::File::open(&path)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // std::io::copy uses its own internal buffer + honors sendfile /
    // splice on Linux when both sides are files. Replaces an 8KB
    // manual read/write loop.
    std::io::copy(&mut f, &mut out)?;
    Ok(())
}

fn run_clear(yes: bool) -> Result<()> {
    let path = history::history_path().ok_or_else(|| anyhow::anyhow!("no state dir"))?;
    if !path.exists() {
        eprintln!("nothing to clear ({} does not exist)", path.display());
        return Ok(());
    }
    if !yes {
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            // Non-interactive callers must pass --yes explicitly.
            // Refuse to clear based on a piped y — someone left
            // `yes | bootintel history --clear` running in a script.
            bail!("refusing to clear without --yes when stdin isn't a terminal (safety guard)");
        }
        eprint!("clear {} ? [y/N] ", path.display());
        io::stderr().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !matches!(input.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("aborted");
            return Ok(());
        }
    }
    history::clear()?;
    eprintln!("cleared {}", path.display());
    Ok(())
}

fn run_table(limit: usize) -> Result<()> {
    let entries = history::read_last(limit)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();

    if entries.is_empty() {
        writeln!(
            out,
            "no history yet — run `bootintel scan <log>` to record one"
        )?;
        return Ok(());
    }

    // Header. Kept space-aligned rather than tab-separated so the
    // human view is scannable. jq consumers use --json.
    writeln!(
        out,
        "{:<20}  {:<8}  {:<40}  {:>4}  {:>4}  {:>4}",
        "TIMESTAMP", "CMD", "PATH", "FIND", "CRIT", "EXIT"
    )?;
    for e in &entries {
        // Truncate the path column at 40 chars from the right so the
        // meaningful basename is always visible even for deeply-nested
        // paths.
        let path = display_shorten(&e.path);
        let path_trim = if path.len() > 40 {
            format!("...{}", &path[path.len() - 37..])
        } else {
            path
        };
        writeln!(
            out,
            "{:<20}  {:<8}  {:<40}  {:>4}  {:>4}  {:>4}",
            e.ts,
            e.cmd.as_deref().unwrap_or("scan"),
            path_trim,
            e.findings,
            e.critical,
            e.exit_code
        )?;
    }
    Ok(())
}
