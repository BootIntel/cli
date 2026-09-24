//! `bootintel watch <path>` — tail a growing log file + live-analyze
//! new bytes. Same pipeline as `bootintel analyze` but sourced from
//! a file instead of a serial port, so it works for:
//!   - a picocom / minicom capture that another process is appending
//!   - `bootintel term ... --log-file capture.log` in one window,
//!     watch in another (view without stealing the serial port)
//!   - CI log tailing (systemd unit output that grows during a run)
//!
//! Streaming semantics: opens the file, seeks to end (or --from-start),
//! then polls (default 200ms) for new bytes. On truncate/rotate
//! (inode changes) reopens and starts over. Ctrl-C to quit.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::Duration;

use crate::analyze::state::AnalyzeState;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the log file to watch.
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Start from the beginning of the file instead of the end.
    /// Useful when the file already has content you want scanned.
    #[arg(long)]
    from_start: bool,

    /// Poll interval in milliseconds. Lower = snappier response,
    /// higher CPU. Default 200ms matches picocom's serial read
    /// cadence — good balance.
    #[arg(long, default_value_t = 200, value_name = "MS")]
    poll_ms: u64,

    /// Quit after the first N findings surface. Handy for CI
    /// gating: `bootintel watch foo.log --exit-after 1 --exit-code 1`
    /// exits non-zero the moment a critical detector fires.
    #[arg(long, value_name = "N")]
    exit_after: Option<usize>,

    /// Exit code when --exit-after threshold is met. Ignored
    /// otherwise. Default 0 so ad-hoc uses don't accidentally
    /// scream in CI.
    #[arg(long, default_value_t = 0, value_name = "CODE")]
    exit_code: i32,

    /// Suppress the running-count status line.
    #[arg(long)]
    quiet: bool,

    /// Suppress ANSI colour.
    #[arg(long)]
    no_color: bool,

    /// Run only these detectors — see `bootintel scan --help`.
    #[arg(long, value_name = "LIST")]
    only: Option<String>,

    /// Skip these detectors (applied after --only).
    #[arg(long, value_name = "LIST")]
    skip: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let stdout = io::stdout();
    let color_on =
        crate::output::resolve_color_mode(args.no_color, &stdout) == crate::output::ColorMode::On;

    // Track inode so we can detect log rotation (a fresh file appears
    // at the same path with a different inode). On non-Unix, `dev`
    // + `len` is a reasonable proxy — a smaller len than we've read
    // signals truncation, which is the same recovery action.
    let mut ident =
        FileIdent::of(&args.path).with_context(|| format!("stat {}", args.path.display()))?;
    let mut file =
        File::open(&args.path).with_context(|| format!("opening {}", args.path.display()))?;
    if !args.from_start {
        let _ = file.seek(SeekFrom::End(0));
    }

    let mut buf = [0u8; 8192];
    // Reuse the same AnalyzeState the term+tui loops use so the
    // "streaming dedup" logic (feed(chunk) → Option<Vec<Finding>>
    // of only *newly*-fired findings) stays consistent across all
    // three streaming paths.
    let mut analyzer = AnalyzeState::new(None);
    let mut findings_seen = 0usize;
    let mut last_reported = 0usize;

    if !args.quiet && !crate::verbose::is_quiet() {
        eprintln!("[bootintel watch] {} (Ctrl-C to quit)", args.path.display());
    }

    loop {
        // Detect rotation/truncate. If the file identity changed OR
        // the file is now shorter than our read position, reopen it
        // from the beginning — someone rotated / truncated / recreated.
        if let Ok(now) = FileIdent::of(&args.path) {
            let cur_pos = file.stream_position().unwrap_or(0);
            let rotated = now != ident;
            let truncated = now.len < cur_pos;
            if rotated || truncated {
                if !args.quiet && !crate::verbose::is_quiet() {
                    let cause = if rotated { "rotation" } else { "truncate" };
                    eprintln!("[bootintel watch] {cause} detected — reopening from start");
                }
                ident = now;
                file = File::open(&args.path).ok().unwrap_or(file);
            }
        }

        match file.read(&mut buf) {
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(args.poll_ms));
                continue;
            }
            Ok(n) => {
                let chunk = &buf[..n];
                // feed() returns None when the chunk was consumed
                // but no new findings; Some(vec) when detectors
                // fired. Apply --only/--skip on the streaming batch
                // — the terminal only ever sees findings that pass
                // the filter, and --exit-after counts filtered-in
                // hits (which is the intuitive semantics).
                let new_all = analyzer.feed(chunk).unwrap_or_default();
                let new = crate::detector_filter::filter(new_all, &args.only, &args.skip);
                for f in &new {
                    print_finding(&mut stdout.lock(), f, color_on)?;
                    findings_seen += 1;
                    if let Some(limit) = args.exit_after {
                        if findings_seen >= limit {
                            if !args.quiet && !crate::verbose::is_quiet() {
                                eprintln!(
                                    "[bootintel watch] exit-after limit ({limit}) reached; exit {}",
                                    args.exit_code
                                );
                            }
                            std::process::exit(args.exit_code);
                        }
                    }
                }
                if !args.quiet && findings_seen != last_reported {
                    last_reported = findings_seen;
                }
            }
            Err(e) => {
                anyhow::bail!("read {}: {e}", args.path.display());
            }
        }
    }
}

fn print_finding<W: Write>(
    out: &mut W,
    f: &bootintel_detectors::Finding,
    color_on: bool,
) -> Result<()> {
    let (open, close) = if color_on {
        ("\x1b[1;36m", "\x1b[0m")
    } else {
        ("", "")
    };
    writeln!(out, "{open}[watch] {}{close}: {}", f.label, f.value)?;
    if let Some(d) = &f.detail {
        writeln!(out, "         {d}")?;
    }
    let _ = out.flush();
    Ok(())
}

/// Cheap file-identity token for rotation detection. On Unix uses
/// (dev, ino, len). On non-Unix falls back to len alone (loses
/// rotation detection but keeps truncate detection).
#[derive(Debug, PartialEq, Eq)]
struct FileIdent {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    len: u64,
}

impl FileIdent {
    fn of(path: &std::path::Path) -> io::Result<Self> {
        let m = std::fs::metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                dev: m.dev(),
                ino: m.ino(),
                len: m.len(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { len: m.len() })
        }
    }
}
