//! Regression tests for correctness defects found by exercising the
//! real v0.3.1 release binary against socat PTY pairs.
//!
//! These drive the compiled binary rather than calling library
//! functions, because every one of these bugs was invisible from
//! inside the library: the exit code, the stdout/stderr split and the
//! process's UTF-8 handling are all properties of the binary.
//!
//! Item numbering matches the defect report.
//!
//! Item 1 (`--log-file` writing 0 bytes until the clean quit path) is
//! covered by unit tests in `src/term/logfile.rs`, which is where the
//! mid-session-flush property can be asserted without a serial device.
//! Item 3 (line-anchored detectors) is covered in
//! `crates/detectors/tests/detector_tests.rs`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_bootintel");

/// A scratch dir unique to this test binary, cleaned between runs.
fn tmpdir() -> PathBuf {
    let base = std::env::var("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let dir = base.join("bootintel-cli-regressions");
    std::fs::create_dir_all(&dir).expect("creating scratch dir");
    dir
}

fn write_file(name: &str, bytes: &[u8]) -> PathBuf {
    let path = tmpdir().join(name);
    let mut f = std::fs::File::create(&path).expect("creating fixture");
    f.write_all(bytes).expect("writing fixture");
    f.sync_all().ok();
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        // History writes are a side effect we don't want in tests, and
        // the first-write disclosure would add stderr noise.
        .env("BOOTINTEL_NO_HISTORY", "1")
        .output()
        .expect("running bootintel")
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A log fragment that trips two detectors, one of them critical.
const GOOD_LOG: &str = "U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)\n\
                        Hit any key to stop autoboot:  3\n";

// ── Item 2: an empty capture must not pass a gate ────────────────────
//
// `scan --gate-critical` on a 0-byte file printed an empty finding
// list and exited 0, so a CI job whose UART never came up, whose
// adapter fell out, or whose artifact path was wrong reported green.

#[test]
fn empty_file_exits_2_not_0() {
    let path = write_file("empty.log", b"");
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        code(&out),
        2,
        "empty capture must exit 2, got {}\nstderr: {}",
        code(&out),
        stderr(&out)
    );
}

#[test]
fn empty_file_does_not_pass_gate_critical() {
    let path = write_file("empty-gate.log", b"");
    let out = run(&[
        "scan",
        path.to_str().unwrap(),
        "--gate-critical",
        "--format",
        "json",
    ]);
    assert_ne!(
        code(&out),
        0,
        "an empty capture reported a PASSING critical gate — this is the \
         exact failure that reports a broken CI job as green"
    );
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("empty capture"),
        "expected an explanation on stderr, got: {}",
        stderr(&out)
    );
}

#[test]
fn whitespace_only_capture_is_also_empty() {
    let path = write_file("blank.log", b"\n\n   \t\r\n  \n");
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
}

#[test]
fn empty_stdin_exits_2() {
    let mut child = Command::new(BIN)
        .args(["scan", "-", "--format", "json"])
        .env("BOOTINTEL_NO_HISTORY", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning");
    drop(child.stdin.take()); // EOF immediately
    let out = child.wait_with_output().expect("waiting");
    assert_eq!(code(&out), 2, "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("stdin"), "{}", stderr(&out));
}

#[test]
fn unrecognized_but_non_empty_exits_3() {
    let path = write_file("noise.log", b"this capture contains nothing we know\n");
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        code(&out),
        3,
        "non-empty-but-unrecognized must exit 3, got {}\nstderr: {}",
        code(&out),
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("\"analysis_status\": \"unrecognized\""),
        "envelope should carry analysis_status, got: {}",
        stdout(&out)
    );
}

#[test]
fn a_real_capture_still_exits_0_and_reports_matched() {
    let path = write_file("good.log", GOOD_LOG.as_bytes());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("\"analysis_status\": \"matched\""),
        "got: {}",
        stdout(&out)
    );
}

#[test]
fn gate_critical_still_fails_with_1_on_a_real_finding() {
    // The new ladder must not swallow the code the gate already had.
    let path = write_file("critical.log", GOOD_LOG.as_bytes());
    let out = run(&["scan", path.to_str().unwrap(), "--gate-critical"]);
    assert_eq!(code(&out), 1, "stderr: {}", stderr(&out));
}

#[test]
fn existing_envelope_keys_are_unchanged() {
    // The fix adds keys; it must not rename or drop any.
    let path = write_file("envelope.log", GOOD_LOG.as_bytes());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    for key in [
        "bootintel_version",
        "analysis_source",
        "detector_count",
        "findings",
    ] {
        assert!(v.get(key).is_some(), "envelope lost the `{key}` key");
    }
    let first = &v["findings"][0];
    for key in ["label", "value"] {
        assert!(first.get(key).is_some(), "finding lost the `{key}` key");
    }
}

// ── Item 4: a non-UTF-8 byte must not be a hard error ────────────────
//
// A capture containing \xff\xfe\x80\x81\xc0\xc1 failed with "stream did
// not contain valid UTF-8" and exit 1, while the legacy Node analyzer
// read the same file and returned findings. This is the normal shape of
// a real UART capture — bytes before the baud locks, framing errors, a
// binary splash — and `--log-file` writes raw bytes, so `analyze
// --log-file` followed by `scan` could fail on the tool's own output.

/// The SME's fixture: a valid log with a run of invalid bytes in it.
fn non_utf8_log() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)\n");
    v.extend_from_slice(b"\xff\xfe\x80\x81\xc0\xc1\n");
    v.extend_from_slice(b"Hit any key to stop autoboot:  3\n");
    v
}

#[test]
fn non_utf8_capture_is_analyzed_not_rejected() {
    let path = write_file("binary.log", &non_utf8_log());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        code(&out),
        0,
        "a capture with invalid UTF-8 was rejected\nstderr: {}",
        stderr(&out)
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let findings = v["findings"].as_array().expect("findings array");
    assert_eq!(
        findings.len(),
        2,
        "expected both detectors to fire, got {}",
        stdout(&out)
    );
}

#[test]
fn non_utf8_preserves_line_numbers() {
    // The whole point of counting bytes rather than reflowing: the
    // autoboot line is line 3 of the file and must be reported as line
    // 3, with the replaced bytes on line 2 not merging the lines.
    let path = write_file("binary-lines.log", &non_utf8_log());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    let autoboot = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "Autoboot interruptable")
        .expect("autoboot finding");
    assert_eq!(
        autoboot["line_number"],
        3,
        "line number shifted by the UTF-8 replacement: {}",
        stdout(&out)
    );
}

#[test]
fn non_utf8_replacement_count_is_reported_under_v() {
    let path = write_file("binary-verbose.log", &non_utf8_log());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json", "-v"]);
    let err = stderr(&out);
    assert!(
        err.contains("6 byte(s)") && err.contains("U+FFFD"),
        "expected -v to report how many bytes were replaced, got: {err}"
    );
}

#[test]
fn non_utf8_note_is_silent_without_v() {
    let path = write_file("binary-quiet.log", &non_utf8_log());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    assert!(
        !stderr(&out).contains("U+FFFD"),
        "the replacement note should be -v only, got: {}",
        stderr(&out)
    );
}

#[test]
fn non_utf8_over_stdin_is_also_accepted() {
    let mut child = Command::new(BIN)
        .args(["scan", "-", "--format", "json"])
        .env("BOOTINTEL_NO_HISTORY", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&non_utf8_log())
        .expect("writing stdin");
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("waiting");
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
}

#[test]
fn a_capture_that_is_entirely_binary_exits_3_not_1() {
    // Garbage in, but it is not *empty* garbage — so it is 3
    // ("looked, recognized nothing"), never a hard read error.
    let path = write_file("all-binary.log", &[0xff, 0xfe, 0x80, 0x81, 0xc0, 0xc1]);
    let out = run(&["scan", path.to_str().unwrap(), "--format", "json"]);
    assert_eq!(code(&out), 3, "stderr: {}", stderr(&out));
}

// ── Item 5: SIGPIPE must be one silent outcome, not three ────────────
//
// `bootintel batch … --format json | head -2` gave exit 1 plus
// "Error: Broken pipe (os error 32)" when output exceeded the 64K pipe
// buffer, while smaller outputs raced between 141 and 0.
// `bootintel manpage | head` is a packager's first command.

/// Run `<bin> <args> | head -<n>` under bash and return bootintel's
/// OWN exit status plus whatever it wrote to stderr.
fn piped_through_head(args: &str, head_lines: u32) -> Option<(i32, String)> {
    let script = format!(
        "{BIN} {args} 2>/tmp/bootintel-pipe-stderr.$$ | head -{head_lines} >/dev/null; \
         rc=${{PIPESTATUS[0]}}; cat /tmp/bootintel-pipe-stderr.$$; \
         rm -f /tmp/bootintel-pipe-stderr.$$; exit $rc"
    );
    let out = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .env("BOOTINTEL_NO_HISTORY", "1")
        .output()
        .ok()?;
    Some((code(&out), stdout(&out)))
}

#[cfg(unix)]
#[test]
fn manpage_piped_to_head_is_silently_successful_every_time() {
    // Six runs: the old behaviour raced, so a single run could pass by
    // luck. Every run must give the same answer.
    for attempt in 1..=6 {
        let Some((rc, err)) = piped_through_head("manpage", 1) else {
            eprintln!("[skip] bash unavailable");
            return;
        };
        assert_eq!(
            rc, 0,
            "attempt {attempt}: expected a silent success, got exit {rc}. stderr: {err}"
        );
        assert!(
            !err.contains("Broken pipe"),
            "attempt {attempt}: leaked a broken-pipe error to stderr: {err}"
        );
    }
}

#[cfg(unix)]
#[test]
fn large_json_piped_to_head_is_silently_successful_every_time() {
    // Exercises the serde_json write path, whose error does not
    // downcast to io::Error and so escaped the previous handling.
    let samples = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("samples"));
    let Some(samples) = samples.filter(|p| p.is_dir()) else {
        eprintln!("[skip] samples/ not in this checkout");
        return;
    };
    let args = format!("batch {} --format json", samples.display());
    for attempt in 1..=6 {
        let Some((rc, err)) = piped_through_head(&args, 2) else {
            eprintln!("[skip] bash unavailable");
            return;
        };
        assert_eq!(
            rc, 0,
            "attempt {attempt}: expected a silent success, got exit {rc}. stderr: {err}"
        );
        assert!(
            !err.contains("Broken pipe"),
            "attempt {attempt}: leaked a broken-pipe error: {err}"
        );
    }
}

#[cfg(unix)]
#[test]
fn sarif_piped_to_head_is_silently_successful() {
    let path = write_file("pipe-sarif.log", GOOD_LOG.as_bytes());
    let args = format!("scan {} --format sarif", path.display());
    let Some((rc, err)) = piped_through_head(&args, 1) else {
        eprintln!("[skip] bash unavailable");
        return;
    };
    assert_eq!(rc, 0, "exit {rc}, stderr: {err}");
    assert!(!err.contains("Broken pipe"), "{err}");
}

// ── Item 6: SARIF must name the real input file ──────────────────────
//
// Every result carried artifactLocation.uri = "boot.log" regardless of
// the actual input, so GitHub's SARIF upload attached findings to a
// file that is not in the repository and the annotations landed
// nowhere.

fn sarif_uris(out: &Output) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(&stdout(out)).expect("valid SARIF JSON");
    v["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .iter()
        .map(|r| r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].clone())
        .map(|u| u.as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn sarif_uri_is_not_the_hardcoded_boot_log() {
    let path = write_file("my-device-capture.log", GOOD_LOG.as_bytes());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "sarif"]);
    let uris = sarif_uris(&out);
    assert!(!uris.is_empty(), "expected results in the SARIF");
    for uri in &uris {
        assert_ne!(
            uri, "boot.log",
            "SARIF still hardcodes boot.log; CI annotations will land nowhere"
        );
        assert!(
            uri.contains("my-device-capture.log"),
            "SARIF uri should name the real input, got {uri}"
        );
    }
}

#[test]
fn sarif_uri_is_relative_to_the_working_directory() {
    // GitHub matches the uri against paths in the repository, so an
    // input inside the workspace must be emitted relative to it.
    let dir = tmpdir();
    let name = "relative-capture.log";
    write_file(name, GOOD_LOG.as_bytes());
    let out = Command::new(BIN)
        .args(["scan", name, "--format", "sarif"])
        .current_dir(&dir)
        .env("BOOTINTEL_NO_HISTORY", "1")
        // Make sure a real CI env var doesn't steer the test.
        .env_remove("GITHUB_WORKSPACE")
        .output()
        .expect("running bootintel");
    for uri in sarif_uris(&out) {
        assert_eq!(
            uri,
            name,
            "expected a workspace-relative uri, got {uri} (stderr: {})",
            stderr(&out)
        );
    }
}

#[test]
fn sarif_uri_honours_github_workspace() {
    let dir = tmpdir();
    let name = "workspace-capture.log";
    let path = write_file(name, GOOD_LOG.as_bytes());
    let out = Command::new(BIN)
        .args(["scan", path.to_str().unwrap(), "--format", "sarif"])
        .env("BOOTINTEL_NO_HISTORY", "1")
        .env("GITHUB_WORKSPACE", &dir)
        .output()
        .expect("running bootintel");
    for uri in sarif_uris(&out) {
        assert_eq!(uri, name, "stderr: {}", stderr(&out));
    }
}

#[test]
fn sarif_uri_for_piped_input_is_stdin() {
    let mut child = Command::new(BIN)
        .args(["scan", "-", "--format", "sarif"])
        .env("BOOTINTEL_NO_HISTORY", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawning");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(GOOD_LOG.as_bytes())
        .expect("writing stdin");
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("waiting");
    for uri in sarif_uris(&out) {
        assert_eq!(uri, "stdin", "stderr: {}", stderr(&out));
    }
}

#[test]
fn sarif_start_line_points_at_the_evidence() {
    let log = "boot noise\nmore noise\nU-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)\n";
    let path = write_file("sarif-lines.log", log.as_bytes());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "sarif"]);
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid SARIF");
    let line =
        &v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"];
    assert_eq!(line, 3, "SARIF startLine should be the evidence line");
}

// ── Item 7: -q must quiet, and the upsell belongs on stderr ──────────

#[test]
fn text_output_on_stdout_carries_no_upsell() {
    let path = write_file("upsell.log", GOOD_LOG.as_bytes());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "text"]);
    assert!(
        !stdout(&out).contains("--api"),
        "the upsell is still on stdout; `scan --format text > report.txt` would \
         ship marketing inside a customer's report:\n{}",
        stdout(&out)
    );
    assert!(
        stderr(&out).contains("--api"),
        "the upsell should still be shown, on stderr: {}",
        stderr(&out)
    );
}

#[test]
fn quiet_suppresses_the_summary_block_entirely() {
    let path = write_file("upsell-quiet.log", GOOD_LOG.as_bytes());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "text", "-q"]);
    assert!(!stdout(&out).contains("--api"), "{}", stdout(&out));
    assert!(
        !stderr(&out).contains("--api"),
        "-q must suppress the summary block, got: {}",
        stderr(&out)
    );
}

#[test]
fn quiet_still_prints_the_findings_themselves() {
    let path = write_file("quiet-findings.log", GOOD_LOG.as_bytes());
    let out = run(&["scan", path.to_str().unwrap(), "--format", "text", "-q"]);
    assert!(
        stdout(&out).contains("U-Boot 2020.10"),
        "-q suppressed the actual output: {}",
        stdout(&out)
    );
}

// ── Item 9: diagnose a non-serial path correctly ─────────────────────

#[cfg(unix)]
#[test]
fn analyze_on_a_regular_file_says_so_instead_of_blaming_permissions() {
    let path = write_file("not-a-tty.log", GOOD_LOG.as_bytes());
    let out = run(&["analyze", path.to_str().unwrap()]);
    let err = stderr(&out);
    assert!(
        err.contains("not a serial device"),
        "expected a correct diagnosis, got: {err}"
    );
    assert!(
        !err.contains("dialout"),
        "still advising a dialout-group change for a readable regular file: {err}"
    );
    assert!(
        err.contains("bootintel scan"),
        "should point at the subcommand that does want a file: {err}"
    );
}
