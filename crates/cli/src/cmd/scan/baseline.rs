//! `scan --baseline <json>` — diff current findings against a saved
//! baseline JSON (either a `scan --format json` envelope or an
//! `export` bundle). Powers the CI regression-drift pattern: commit a
//! baseline into the repo, run `scan --baseline` on PRs.

use anyhow::{Context, Result};
use bootintel_detectors::Finding;
use std::path::Path;

/// Load a baseline JSON, diff `current` against it, and print a
/// per-drift summary to stderr. Returns true if there IS drift (the
/// caller then exits non-zero). No-drift returns false + prints a
/// quiet "no drift" line (skipped in --quiet mode).
pub(super) fn compare_to_baseline(current: &[Finding], path: &Path) -> Result<bool> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading baseline {}", path.display()))?;
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing baseline {} as JSON", path.display()))?;
    let baseline_findings = extract_findings_from_json(&parsed).ok_or_else(|| {
        anyhow::anyhow!(
            "baseline {} has no findings array — expected `scan --format json` or `export` shape",
            path.display()
        )
    })?;

    // Group both sides by (label, value, detail) — mirrors `bootintel
    // diff`. A change in value or detail counts as removed+added.
    use std::collections::BTreeSet;
    let key = |f: &Finding| {
        (
            f.label.clone(),
            f.value.clone(),
            f.detail.clone().unwrap_or_default(),
        )
    };
    let cur_set: BTreeSet<_> = current.iter().map(key).collect();
    let base_set: BTreeSet<_> = baseline_findings.iter().map(key).collect();

    let added: Vec<_> = cur_set.difference(&base_set).collect();
    let removed: Vec<_> = base_set.difference(&cur_set).collect();

    if added.is_empty() && removed.is_empty() {
        if !crate::verbose::is_quiet() {
            eprintln!(
                "[bootintel] baseline: no drift ({} finding(s) match {})",
                current.len(),
                path.display()
            );
        }
        return Ok(false);
    }
    eprintln!("[bootintel] baseline drift vs {}:", path.display());
    for (label, value, _) in &removed {
        eprintln!("  - {label}: {value}");
    }
    for (label, value, _) in &added {
        eprintln!("  + {label}: {value}");
    }
    eprintln!(
        "[bootintel] {} added, {} removed",
        added.len(),
        removed.len()
    );
    Ok(true)
}

/// Extract the `findings[]` array from a scan envelope or export
/// bundle. Returns None if the JSON doesn't have the expected shape
/// (caller emits a friendly error).
pub(super) fn extract_findings_from_json(v: &serde_json::Value) -> Option<Vec<Finding>> {
    let arr = v.get("findings")?.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let label = item.get("label").and_then(|s| s.as_str())?.to_string();
        let value = item
            .get("value")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let detail = item
            .get("detail")
            .and_then(|s| s.as_str())
            .map(String::from);
        let source = item
            .get("source")
            .and_then(|s| s.as_str())
            .map(String::from);
        out.push(Finding {
            label,
            value,
            detail,
            source,
        });
    }
    Some(out)
}
