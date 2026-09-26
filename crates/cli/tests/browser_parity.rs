//! Corpus parity against the browser detector library.
//!
//! The browser library (`frontend/src/lib/detectors.ts` in the website
//! repo) is the source of truth for the detector set: it is what the web
//! tool and the legacy Node analyzer both run, and JSON output is meant
//! to be comparable between implementations. This test proves the Rust
//! crate agrees with it on the whole public corpus rather than trusting
//! that two hand-maintained copies of 14 regex sets stayed in step.
//!
//! How it runs the browser side: `tests/browser_detectors.mjs` transpiles
//! the TypeScript in-process and evaluates it in a `vm` context, the same
//! way the website repo's own `cli/test-parity.mjs` does, then prints
//! every finding as JSON. No network, no build step.
//!
//! Skips (loudly) when the pieces aren't here — `node` missing, or the
//! website checkout not on this machine — because the crate is published
//! and `cargo test` has to pass for someone who only has this repo. Set
//! `BOOTINTEL_REQUIRE_PARITY=1` to turn those skips into failures (CI on
//! a machine that does have both). Point `BOOTINTEL_BROWSER_DETECTORS` at
//! `detectors.ts` if your checkout lives somewhere unusual.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use bootintel_detectors::analyze;

/// One finding reduced to the fields both implementations promise to
/// agree on. `source` / `line_number` are derived from the log and are
/// asserted separately (`evidence_is_the_original_line`).
#[derive(Debug, PartialEq, Eq)]
struct Row {
    label: String,
    value: String,
    detail: Option<String>,
}

fn repo_root() -> Option<PathBuf> {
    // crates/cli → ../..
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Some(manifest.parent()?.parent()?.to_path_buf())
}

fn samples_dir() -> Option<PathBuf> {
    let dir = repo_root()?.join("samples");
    dir.is_dir().then_some(dir)
}

/// Locate the browser detector library: explicit env var first, then the
/// usual places a website checkout sits relative to this repo.
fn browser_detectors() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BOOTINTEL_BROWSER_DETECTORS") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let rel = Path::new("frontend/src/lib/detectors.ts");
    let mut candidates = vec![PathBuf::from("/opt/bootintel.com").join(rel)];
    if let Some(root) = repo_root() {
        if let Some(parent) = root.parent() {
            candidates.push(parent.join("bootintel.com").join(rel));
            candidates.push(parent.join("bootintel").join(rel));
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

fn have_node() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// `[skip]` unless the caller demanded the real thing.
fn skip(why: &str) {
    assert!(
        std::env::var_os("BOOTINTEL_REQUIRE_PARITY").is_none(),
        "BOOTINTEL_REQUIRE_PARITY is set but {why}"
    );
    eprintln!("[skip] browser parity: {why}");
}

/// Split a log the way `analyze()` does — on CRLF, LF **or** bare CR.
fn split_lines(log: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = log;
    while let Some(i) = rest.find(['\n', '\r']) {
        out.push(&rest[..i]);
        let skip = if rest[i..].starts_with("\r\n") { 2 } else { 1 };
        rest = &rest[i + skip..];
    }
    out.push(rest);
    out
}

/// Both shapes of every corpus log: as captured, and with a terminal
/// timestamp in front of every line.
#[derive(Debug, PartialEq, Eq)]
struct Variants {
    raw: Vec<Row>,
    prefixed: Vec<Row>,
}

/// Run the browser library over `samples/` and return its findings.
fn browser_findings() -> Option<BTreeMap<String, Variants>> {
    let Some(samples) = samples_dir() else {
        skip("samples/ is not in this checkout");
        return None;
    };
    let Some(detectors) = browser_detectors() else {
        skip("detectors.ts not found — set BOOTINTEL_BROWSER_DETECTORS to the website checkout");
        return None;
    };
    if !have_node() {
        skip("node is not on PATH");
        return None;
    }
    let harness = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("browser_detectors.mjs");
    let out = Command::new("node")
        .arg(&harness)
        .arg(&detectors)
        .arg(&samples)
        .output()
        .expect("failed to spawn node");
    assert!(
        out.status.success(),
        "browser harness failed ({}):\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("browser harness did not print JSON");
    let rows = |v: &serde_json::Value| -> Vec<Row> {
        v.as_array()
            .expect("each variant maps to an array of findings")
            .iter()
            .map(|r| Row {
                label: r["label"].as_str().expect("label is a string").to_string(),
                value: r["value"].as_str().expect("value is a string").to_string(),
                detail: r["detail"].as_str().map(str::to_string),
            })
            .collect()
    };
    let mut findings = BTreeMap::new();
    for (file, variants) in parsed.as_object().expect("harness must print an object") {
        findings.insert(
            file.clone(),
            Variants {
                raw: rows(&variants["raw"]),
                prefixed: rows(&variants["prefixed"]),
            },
        );
    }
    Some(findings)
}

fn rust_findings(log: &str) -> Vec<Row> {
    analyze(log)
        .into_iter()
        .map(|f| Row {
            label: f.label,
            value: f.value,
            detail: f.detail,
        })
        .collect()
}

#[test]
fn every_corpus_log_matches_the_browser_implementation() {
    let Some(expected) = browser_findings() else {
        return;
    };
    let samples = samples_dir().expect("samples/ exists if the harness ran");
    assert!(
        expected.len() >= 31,
        "expected the full public corpus, saw {} logs",
        expected.len()
    );
    for (file, want) in &expected {
        let log = std::fs::read_to_string(samples.join(file)).expect("corpus log is readable");
        assert_eq!(
            rust_findings(&log),
            want.raw,
            "{file}: CLI findings differ from the browser implementation"
        );
        // Same log behind a terminal timestamp. Normalization is where the
        // two implementations could agree on a bare log and still disagree
        // on a real capture — and the browser deliberately exempts the two
        // policy detectors from it, so that exemption is under test here.
        let prefixed = split_lines(&log)
            .iter()
            .map(|l| format!("[12:34:56.123] {l}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            rust_findings(&prefixed),
            want.prefixed,
            "{file}: CLI findings differ from the browser implementation on a timestamped capture"
        );
    }
}

/// The evidence contract: whatever `source` a finding carries has to be
/// the original input line at `line_number`, verbatim — prefix, ANSI and
/// all. `cli/test-parity.mjs` asserts the same thing on the browser side.
#[test]
fn evidence_is_the_original_line() {
    let Some(samples) = samples_dir() else {
        eprintln!("[skip] samples/ is not in this checkout");
        return;
    };
    let mut checked = 0;
    for entry in std::fs::read_dir(&samples).expect("samples/ is readable") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().is_none_or(|e| e != "txt") {
            continue;
        }
        let log = std::fs::read_to_string(&path).expect("corpus log is readable");
        let lines = split_lines(&log);
        for f in analyze(&log) {
            let (Some(source), Some(n)) = (f.source.as_deref(), f.line_number) else {
                // An aggregate finding (Flash layout) has no single
                // originating line, and that is the contract.
                assert_eq!(
                    f.line_number,
                    None,
                    "{}: {} has a line number but no source",
                    path.display(),
                    f.label
                );
                continue;
            };
            assert_eq!(
                lines[n - 1],
                source,
                "{}: {} points at line {n} but that is not what the log says",
                path.display(),
                f.label
            );
            checked += 1;
        }
    }
    assert!(
        checked > 50,
        "expected real evidence to check, saw {checked}"
    );
}
