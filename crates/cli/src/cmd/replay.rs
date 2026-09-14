//! `bootintel replay <log> <port>` — pump a saved boot log into a
//! serial port with pacing.
//!
//! Use cases:
//!   - Reproduce a customer bug: pipe their capture into a socat PTY
//!     so `bootintel analyze $PTY` reproduces what they see.
//!   - Feed a "device" for a demo — pair with `bootintel term` on
//!     the other end of a socat PTY.
//!   - Analyzer regression test: pipe a corpus log through a live
//!     analyze session at wire speed to exercise the streaming path.
//!
//! Pacing modes: --baud emits at a byte rate matching real UART
//! (e.g. 115200 baud ≈ 11520 bytes/sec, one byte every ~87µs).
//! --rate lets you dial a bytes-per-second directly. --instant
//! blasts the whole file with no pacing (useful for cheap tests).

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::term::run::open_serial_with_hints;
use serialport::{DataBits, FlowControl, Parity, StopBits};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Log file to replay, or `-` for stdin.
    #[arg(value_name = "LOG")]
    log: PathBuf,

    /// Serial port to write to (device path on Unix, COMn on Windows).
    /// Point at a socat PTY endpoint if you don't have real hardware.
    #[arg(value_name = "PORT")]
    port: String,

    /// Baud rate — used both to open the port AND to pace the byte
    /// stream (real UART speed = baud / ~10). Override the pacing
    /// with --rate or --instant.
    #[arg(long, default_value_t = 115200)]
    baud: u32,

    /// Explicit bytes-per-second pacing. Overrides the baud-derived
    /// rate. Useful for testing "what if the device is slow" or
    /// "what if the device blasts data".
    #[arg(long, value_name = "BPS")]
    rate: Option<u32>,

    /// Skip pacing entirely — dump the whole file as fast as the
    /// kernel will accept it. Handy for quick smoke tests.
    #[arg(long)]
    instant: bool,

    /// Repeat the file N times. 0 = loop forever (Ctrl-C to stop).
    /// Defaults to 1 (single-pass).
    #[arg(long, default_value_t = 1, value_name = "N")]
    repeat: u32,

    /// Suppress the per-chunk status output.
    #[arg(long)]
    quiet: bool,
}

pub fn run(args: Args) -> Result<()> {
    let bytes = read_log(&args.log)?;
    if bytes.is_empty() {
        bail!("nothing to replay: {} is empty", args.log.display());
    }

    let mut port = open_serial_with_hints(
        &args.port,
        args.baud,
        DataBits::Eight,
        Parity::None,
        StopBits::One,
        FlowControl::None,
    )?;

    // Pacing model: pick target bytes/sec.
    let bytes_per_sec: Option<u32> = if args.instant {
        None
    } else if let Some(r) = args.rate {
        Some(r)
    } else {
        // UART frame ≈ start + 8 data + stop = 10 bits/byte.
        Some(args.baud / 10)
    };

    if !args.quiet && !crate::verbose::is_quiet() {
        let pace = bytes_per_sec
            .map(|r| format!("{r} B/s"))
            .unwrap_or_else(|| "instant".into());
        eprintln!(
            "[bootintel replay] {} → {} @ {} baud, pacing = {}, repeat = {}",
            args.log.display(),
            args.port,
            args.baud,
            pace,
            if args.repeat == 0 {
                "forever".into()
            } else {
                args.repeat.to_string()
            },
        );
    }

    // Chunk size: aim for ~10ms of bytes-per-chunk when paced (small
    // enough that Ctrl-C interrupts fast, large enough to keep write
    // syscall count reasonable). Uncapped for --instant.
    let chunk_size = match bytes_per_sec {
        Some(bps) if bps > 0 => ((bps as usize) / 100).max(64),
        _ => 8192,
    };

    let start = Instant::now();
    let mut total: u64 = 0;
    let mut iter = 0u32;
    loop {
        iter += 1;
        if !replay_once(port.as_mut(), &bytes, chunk_size, bytes_per_sec, &mut total)? {
            break; // write failure or Ctrl-C signal (via broken pipe)
        }
        if args.repeat != 0 && iter >= args.repeat {
            break;
        }
    }
    if !args.quiet && !crate::verbose::is_quiet() {
        let secs = start.elapsed().as_secs_f64();
        eprintln!(
            "[bootintel replay] done — {} bytes in {:.2}s ({:.1} B/s effective)",
            total,
            secs,
            if secs > 0.0 { total as f64 / secs } else { 0.0 },
        );
    }
    Ok(())
}

fn replay_once(
    port: &mut dyn serialport::SerialPort,
    bytes: &[u8],
    chunk_size: usize,
    bytes_per_sec: Option<u32>,
    total: &mut u64,
) -> Result<bool> {
    let start_of_iter = Instant::now();
    let mut written: usize = 0;
    for chunk in bytes.chunks(chunk_size) {
        if let Err(e) = port.write_all(chunk) {
            eprintln!("[bootintel replay] write failed: {e}");
            return Ok(false);
        }
        written += chunk.len();
        *total += chunk.len() as u64;
        if let Some(bps) = bytes_per_sec {
            // Sleep until the moving-average matches target rate.
            let want_secs = written as f64 / bps as f64;
            let elapsed = start_of_iter.elapsed().as_secs_f64();
            let deficit = want_secs - elapsed;
            if deficit > 0.0 {
                std::thread::sleep(Duration::from_secs_f64(deficit));
            }
        }
    }
    let _ = port.flush();
    Ok(true)
}

fn read_log(p: &std::path::Path) -> Result<Vec<u8>> {
    if p == std::path::Path::new("-") {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).context("reading stdin")?;
        Ok(buf)
    } else {
        std::fs::read(p).with_context(|| format!("reading {}", p.display()))
    }
}
