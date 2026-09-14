//! bootintel — interactive UART capture + streaming boot-log analysis.
//!
//! Subcommands: `scan`, `share`, `ports`, `version`, `term`, `analyze`.
//! Client-side identification runs offline; server-side full-CVE
//! analysis is opt-in via `--api`.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod analyze;
mod api;
mod cmd;
mod config;
mod detector_filter;
mod gate;
mod history;
mod output;
mod spinner;
mod term;
#[cfg(feature = "tui")]
mod tui;
mod verbose;

#[cfg(test)]
mod test_util;

/// Exit code the CLI returns when its stdout is closed by a downstream
/// consumer (e.g. `bootintel scan foo.log | head -20`). Matches the
/// convention every real Unix filter uses — 141 = 128 + SIGPIPE(13).
const EXIT_SIGPIPE: i32 = 141;

#[derive(Parser)]
#[command(
    name = "bootintel",
    version,
    about = "Boot log capture, identification, and analysis.",
    long_about = "bootintel captures serial-console boot logs over UART and identifies bootloader / kernel / SoC / exposure signs. \
                  Free client-side scan runs offline; server-side CVE matching + exploit paths are available via bootintel.com's paid API.",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Verbose output. Repeat for more detail: `-v` prints info,
    /// `-vv` also prints debug (request/response bodies for --api,
    /// detector timing). Emitted on stderr with a `[v]` / `[vv]`
    /// prefix so it never contaminates stdout (JSON/SARIF consumers
    /// keep parsing cleanly).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Quiet mode — suppress banners + status hints. Errors still
    /// surface (on stderr, exit-non-zero). For scripts + CI that
    /// want only the primary stdout payload.
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze a saved boot log file (or stdin with `-`).
    Scan(cmd::scan::Args),
    /// Interactive UART terminal (picocom-shaped). Ctrl-A ? for help.
    Term(cmd::term::Args),
    /// Interactive UART terminal + live client-side detector analysis.
    /// Findings surface as `[bootintel] ●` inline lines as detectors match.
    Analyze(cmd::analyze::Args),
    /// Print a shareable bootintel.com URL for a local boot log.
    Share(cmd::share::Args),
    /// List serial ports available on this machine.
    Ports(cmd::ports::Args),
    /// Scan every log file in a directory and print a per-file +
    /// rollup report. Text / JSON / CSV output. Non-recursive by
    /// default; --recursive walks into subdirs.
    Batch(cmd::batch::Args),
    /// Compare finding sets from two boot logs. Useful for firmware
    /// regression testing (before/after) and CI PR-gating.
    Diff(cmd::diff::Args),
    /// Tail a growing log file and live-analyze new bytes. Same
    /// pipeline as `analyze` but sourced from a file, not a serial
    /// port. Reopens on rotate/truncate.
    Watch(cmd::watch::Args),
    /// Look up a CVE in the local embedded-cves feed (populated
    /// every 4h by the cve-alert-bot). Falls back to listing all
    /// entries when no ID is given.
    Cve(cmd::cve::Args),
    /// Measure detector-library performance on a single log
    /// (median + p95 + throughput). Cheap perf-regression guard.
    Bench(cmd::bench::Args),
    /// Pump a saved log into a serial port with baud-derived pacing.
    /// Reproduces customer captures, feeds demos, exercises analyzer
    /// streaming paths.
    Replay(cmd::replay::Args),
    /// Emit troff man pages (bootintel.1 + per-subcommand pages) to
    /// stdout or --out-dir. Homebrew / dpkg / rpm packagers expect
    /// this layout.
    Manpage(cmd::manpage::Args),
    /// List every registered detector + a one-line description.
    /// First-run curiosity, doc lookup without grepping source.
    Detectors(cmd::detectors::Args),
    /// Emit a JSON Schema (2020-12) for `scan --format json` output.
    /// Lets third-party CI tools validate + typegen against a stable
    /// shape.
    Schema(cmd::schema::Args),
    /// Compress a log into a shareable bootintel.com fingerprint URL
    /// (stdout-only variant of `share`; composes cleanly in scripts).
    EncodeShare(cmd::encode_share::Args),
    /// Decompress a bootintel.com fingerprint URL back to the
    /// original log bytes. Round-trips `encode-share` / browser
    /// share links.
    DecodeShare(cmd::decode_share::Args),
    /// Bundle log + findings + tool metadata into one JSON blob for
    /// bug reports / support tickets. No PII is collected — output
    /// only carries what a support engineer needs to reproduce.
    Export(cmd::export::Args),
    /// Re-render an archived `scan --format json` (or `export`
    /// bundle) in any output format. Handy when you kept the JSON
    /// but not the original log.
    View(cmd::view::Args),
    /// Run scan on the built-in SAMPLE log — zero-arg "show me what
    /// this tool does" for demos + evaluation sessions.
    Demo(cmd::demo::Args),
    /// Bootstrap the per-user config dir ($XDG_CONFIG_HOME/bootintel
    /// or %APPDATA%\bootintel) with a macros stub + shell-completion
    /// install hints. Idempotent; --force overwrites.
    Init(cmd::init::Args),
    /// Sanity-check the environment: serial devices, dialout group,
    /// $TERM, tmux/screen prefix collision, $BOOTINTEL_API_* env.
    Doctor(cmd::doctor::Args),
    /// Emit a shell-completion script for bash/zsh/fish/elvish/powershell.
    Completions(cmd::completions::Args),
    /// Inspect + edit the per-user config file (api_base, api_key,
    /// default_format, no_history). Subcommands: path / list / get /
    /// set / edit. Precedence at runtime is: CLI flag > env var >
    /// config file > built-in default.
    Config(cmd::config::Args),
    /// Verify the current API key without running a scan. Prints the
    /// key's identity (email + tier + today's quota) or exits with
    /// a sysexits-style code (77 = unauthorized, 69 = network error).
    Whoami(cmd::whoami::Args),
    /// Inspect the append-only scan-history log (`~/.local/state/
    /// bootintel/history.jsonl` on Linux). Prints the last N entries
    /// as a table by default; --json for raw JSONL; --clear to wipe.
    /// Writes are opt-out via `BOOTINTEL_NO_HISTORY=1` or the
    /// `no_history` config key.
    History(cmd::history::Args),
    /// Print version, detector count, and build metadata.
    /// `--json` for machine-readable output.
    Version(cmd::version::Args),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    verbose::set_level(cli.verbose);
    verbose::set_quiet(cli.quiet);
    let result = match cli.command {
        Cmd::Scan(args) => cmd::scan::run(args),
        Cmd::Term(args) => cmd::term::run(args),
        Cmd::Analyze(args) => cmd::analyze::run(args),
        Cmd::Share(args) => cmd::share::run(args),
        Cmd::Ports(args) => cmd::ports::run(args),
        Cmd::Batch(args) => cmd::batch::run(args),
        Cmd::Diff(args) => cmd::diff::run(args),
        Cmd::Watch(args) => cmd::watch::run(args),
        Cmd::Cve(args) => cmd::cve::run(args),
        Cmd::Bench(args) => cmd::bench::run(args),
        Cmd::Replay(args) => cmd::replay::run(args),
        Cmd::Manpage(args) => cmd::manpage::run(args),
        Cmd::Detectors(args) => cmd::detectors::run(args),
        Cmd::Schema(args) => cmd::schema::run(args),
        Cmd::EncodeShare(args) => cmd::encode_share::run(args),
        Cmd::DecodeShare(args) => cmd::decode_share::run(args),
        Cmd::Export(args) => cmd::export::run(args),
        Cmd::View(args) => cmd::view::run(args),
        Cmd::Demo(args) => cmd::demo::run(args),
        Cmd::Init(args) => cmd::init::run(args),
        Cmd::Doctor(args) => cmd::doctor::run(args),
        Cmd::Completions(args) => cmd::completions::run(args),
        Cmd::Config(args) => cmd::config::run(args),
        Cmd::Whoami(args) => cmd::whoami::run(args),
        Cmd::History(args) => cmd::history::run(args),
        Cmd::Version(args) => cmd::version::run(args),
    };

    // Graceful handling of a downstream consumer closing stdout mid-
    // write (e.g. `bootintel scan foo.log | head -20`). Without this
    // we'd panic on the underlying Broken-pipe io error, which is
    // ugly + wrong for a Unix filter. Exit 141 per convention.
    if let Err(err) = &result {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::BrokenPipe {
                std::process::exit(EXIT_SIGPIPE);
            }
        }
    }
    result
}
