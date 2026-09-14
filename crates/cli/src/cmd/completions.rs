//! `bootintel completions <shell>` — emit a shell-completion script.
//!
//! Delegates to clap_complete. Usage per shell:
//!
//!   bash:       eval "$(bootintel completions bash)"
//!   zsh:        bootintel completions zsh   > ~/.zsh_completions/_bootintel
//!   fish:       bootintel completions fish  > ~/.config/fish/completions/bootintel.fish
//!   elvish:     bootintel completions elvish > ~/.elvish/lib/bootintel.elv
//!   powershell: bootintel completions powershell > $PROFILE/bootintel.ps1
//!
//! Deliberately doesn't wire dynamic per-port completion (that needs
//! a runtime shim + serialport crate exposure inside the shell): the
//! static script covers subcommand names, flag names, and value-enum
//! choices, which is where the ergonomics win actually lives.

use anyhow::Result;
use clap::{Args as ClapArgs, CommandFactory, ValueEnum};
use clap_complete::{generate, Shell};

use crate::Cli;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Which shell's completion script to emit on stdout.
    #[arg(value_enum)]
    shell: ShellChoice,
}

/// Local mirror of clap_complete::Shell so we own the value-enum
/// derivation without leaking the enum type into every clap doc line.
/// PowerShell carries an alias because the default kebab-case
/// serialization ("power-shell") is not what any real user types.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum ShellChoice {
    Bash,
    Zsh,
    Fish,
    Elvish,
    #[value(alias = "powershell", alias = "pwsh")]
    PowerShell,
}

impl From<ShellChoice> for Shell {
    fn from(s: ShellChoice) -> Self {
        match s {
            ShellChoice::Bash => Shell::Bash,
            ShellChoice::Zsh => Shell::Zsh,
            ShellChoice::Fish => Shell::Fish,
            ShellChoice::Elvish => Shell::Elvish,
            ShellChoice::PowerShell => Shell::PowerShell,
        }
    }
}

pub fn run(args: Args) -> Result<()> {
    let mut cmd = Cli::command();
    let bin = cmd.get_name().to_string();
    generate(
        Shell::from(args.shell),
        &mut cmd,
        bin,
        &mut std::io::stdout(),
    );
    Ok(())
}
