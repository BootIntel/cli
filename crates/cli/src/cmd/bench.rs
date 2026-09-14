//! `bootintel bench <log>` — measure detector-library performance
//! against a single boot log.
//!
//! Reports wall-clock median + p95 + throughput. Not intended for
//! rigorous benchmarking (that's cargo-criterion territory) — the
//! point is a cheap "did I just slow a detector down 100x" check
//! after touching the detector library, and a "how long does scan
//! actually take on my monster capture?" answer for users.
//!
//! Default 10 iterations with a warmup — enough signal to catch a
//! big regression, fast enough that CI can afford to run it.

use anyhow::{Context, Result};
use bootintel_detectors::analyze;
use clap::Args as ClapArgs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Log file (or `-` for stdin) to bench against.
    #[arg(value_name = "LOG")]
    log: PathBuf,

    /// Number of measured iterations. 10 is a good balance between
    /// signal-to-noise + wall-clock cost for a big capture.
    #[arg(long, default_value_t = 10, value_name = "N")]
    iterations: usize,

    /// Warmup iterations that don't count toward the timing. Helps
    /// stabilize things like page-cache effects on the input file.
    #[arg(long, default_value_t = 2, value_name = "N")]
    warmup: usize,

    /// Machine-readable JSON output. Includes every iteration time
    /// so a caller can compute their own percentiles.
    #[arg(long)]
    json: bool,
}

pub fn run(args: Args) -> Result<()> {
    let bytes = read_log(&args.log)?;
    let bytes_len = bytes.len();
    let text = String::from_utf8_lossy(&bytes).into_owned();

    // Warmup — untimed.
    for _ in 0..args.warmup {
        let _ = analyze(&text);
    }

    // Timed passes.
    let mut samples: Vec<Duration> = Vec::with_capacity(args.iterations);
    for _ in 0..args.iterations {
        let t0 = Instant::now();
        let _ = analyze(&text);
        samples.push(t0.elapsed());
    }

    // Sort a clone to compute median + p95 without mutating the
    // original iteration order (JSON output preserves it).
    let mut sorted = samples.clone();
    sorted.sort();
    let median = sorted[sorted.len() / 2];
    let p95_idx = ((sorted.len() as f64) * 0.95).ceil() as usize - 1;
    let p95 = sorted[p95_idx.min(sorted.len() - 1)];
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let sum: Duration = sorted.iter().sum();
    let mean = sum / sorted.len() as u32;

    let stdout = io::stdout();
    let mut out = stdout.lock();
    if args.json {
        let body = serde_json::json!({
            "bootintel_version": env!("CARGO_PKG_VERSION"),
            "log": args.log.display().to_string(),
            "log_bytes": bytes_len,
            "iterations": args.iterations,
            "warmup": args.warmup,
            "samples_ns": samples.iter().map(|d| d.as_nanos() as u64).collect::<Vec<_>>(),
            "median_ns": median.as_nanos() as u64,
            "p95_ns":    p95.as_nanos() as u64,
            "min_ns":    min.as_nanos() as u64,
            "max_ns":    max.as_nanos() as u64,
            "mean_ns":   mean.as_nanos() as u64,
            "throughput_mb_per_s": mb_per_second(bytes_len, median),
        });
        serde_json::to_writer_pretty(&mut out, &body)?;
        writeln!(out)?;
    } else {
        writeln!(
            out,
            "bootintel bench — {} bytes, {} iteration(s) (+{} warmup)",
            bytes_len, args.iterations, args.warmup
        )?;
        writeln!(out)?;
        writeln!(out, "  median   {}", fmt_dur(median))?;
        writeln!(out, "  p95      {}", fmt_dur(p95))?;
        writeln!(out, "  min      {}", fmt_dur(min))?;
        writeln!(out, "  max      {}", fmt_dur(max))?;
        writeln!(out, "  mean     {}", fmt_dur(mean))?;
        writeln!(out)?;
        writeln!(
            out,
            "  throughput  {:.1} MB/s (median)",
            mb_per_second(bytes_len, median)
        )?;
    }
    let _ = out.flush();
    Ok(())
}

fn read_log(p: &std::path::Path) -> Result<Vec<u8>> {
    if p == std::path::Path::new("-") {
        let mut buf = Vec::new();
        io::Read::read_to_end(&mut io::stdin(), &mut buf).context("reading stdin")?;
        Ok(buf)
    } else {
        std::fs::read(p).with_context(|| format!("reading {}", p.display()))
    }
}

fn fmt_dur(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{:.1}µs", (ns as f64) / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2}ms", (ns as f64) / 1_000_000.0)
    } else {
        format!("{:.2}s", (ns as f64) / 1_000_000_000.0)
    }
}

fn mb_per_second(bytes: usize, dur: Duration) -> f64 {
    let secs = dur.as_secs_f64();
    if secs == 0.0 {
        return 0.0;
    }
    (bytes as f64 / 1_048_576.0) / secs
}
