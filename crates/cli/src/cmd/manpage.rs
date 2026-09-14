//! `bootintel manpage [--out-dir DIR]` — emit troff man pages.
//!
//! Without --out-dir, writes the top-level `bootintel.1` to stdout
//! (useful for `bootintel manpage | man -l -`). With --out-dir,
//! writes `bootintel.1` + one page per subcommand into the given
//! directory — the layout Homebrew / dpkg / rpm packagers expect.
//!
//! Delegates the formatting to clap_mangen so subcommand + flag docs
//! stay in sync with clap-derive automatically.

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, CommandFactory};
use clap_mangen::Man;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::Cli;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// If set, write one file per subcommand into this directory.
    /// If unset, emit the top-level `bootintel.1` to stdout.
    #[arg(long, value_name = "DIR")]
    out_dir: Option<PathBuf>,
}

pub fn run(args: Args) -> Result<()> {
    let cmd = Cli::command();
    match args.out_dir {
        None => {
            let mut out = io::stdout().lock();
            Man::new(cmd).render(&mut out)?;
            let _ = out.flush();
        }
        Some(dir) => {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            write_pages(&cmd, &dir, None)?;
        }
    }
    Ok(())
}

/// Recursively write `<bin>.1`, `<bin>-<sub>.1`, `<bin>-<sub>-<subsub>.1`
/// per clap subcommand — the naming convention `apropos` + `man`
/// expect for hierarchical CLIs.
fn write_pages(cmd: &clap::Command, dir: &std::path::Path, parent: Option<&str>) -> Result<()> {
    let name = cmd.get_name().to_string();
    let full = match parent {
        Some(p) => format!("{p}-{name}"),
        None => name.clone(),
    };
    let path = dir.join(format!("{full}.1"));
    let mut f =
        std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
    Man::new(cmd.clone()).render(&mut f)?;
    eprintln!("wrote {}", path.display());
    for sub in cmd.get_subcommands() {
        write_pages(sub, dir, Some(&full))?;
    }
    Ok(())
}
