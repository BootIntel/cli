//! `scan --context N` — `grep -C`-style excerpt printer for findings
//! that carry a `source` field. Only meaningful for `--format text`;
//! other formats already include context in their own shape (JSON
//! keeps the source field, HTML shows it inline).

use anyhow::Result;
use bootintel_detectors::Finding;
use std::io::Write;

use crate::output;

/// Print a `grep -C N`-style context block for each finding that
/// has a `source` field.
pub(super) fn write_context_blocks<W: Write>(
    out: &mut W,
    findings: &[Finding],
    raw: &str,
    context: usize,
    color: output::ColorMode,
) -> Result<()> {
    let color_on = color == output::ColorMode::On;
    let (dim_open, dim_close) = if color_on {
        ("\x1b[2m", "\x1b[0m")
    } else {
        ("", "")
    };
    let (hi_open, hi_close) = if color_on {
        ("\x1b[1;33m", "\x1b[0m")
    } else {
        ("", "")
    };
    let mut wrote_header = false;
    for f in findings {
        let Some(src) = f.source.as_deref() else {
            continue;
        };
        let Some(pos) = raw.find(src) else {
            continue;
        };
        if !wrote_header {
            writeln!(out)?;
            writeln!(out, "  {dim_open}── context ──{dim_close}")?;
            wrote_header = true;
        }
        let start = pos.saturating_sub(context);
        let end = (pos + src.len() + context).min(raw.len());
        // Extend to char boundaries so slicing UTF-8 doesn't panic.
        let start = adjust_char_boundary(raw, start);
        let end = adjust_char_boundary(raw, end);
        let before = &raw[start..pos];
        let matched = src;
        let after = &raw[pos + src.len()..end];
        writeln!(out)?;
        writeln!(out, "  {dim_open}[{}]{dim_close}", f.label)?;
        // Preserve newlines in the excerpt so multi-line context is
        // readable; indent each line by 4 spaces.
        for line in format!("{before}{hi_open}{matched}{hi_close}{after}").lines() {
            writeln!(out, "    {line}")?;
        }
    }
    Ok(())
}

/// Walk backward from `i` until it lands on a char boundary in `s`.
/// Guards `str::split_at` against slicing mid-codepoint on non-ASCII
/// logs (uncommon in boot logs but not impossible).
///
/// Exposed at `pub(super)` so other scan sub-modules (and, via
/// re-export, history's future path-shortener) can share it.
pub(super) fn adjust_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}
