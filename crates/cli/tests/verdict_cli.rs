//! `bootintel verdict` driven as a process.
//!
//! The library-level rules are pinned against the server implementation in
//! `crates/detectors/tests/boot_chain.rs`. What only the binary can show is the
//! part a CI job depends on: which exit code means what, and that a capture
//! that could not be assessed never looks like a clean one.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_bootintel");

/// A session with nothing exposed: autoboot cannot be interrupted, images are
/// verified, no netboot path, and no bootcmd to rewrite.
const HARDENED: &str =
    "=> printenv\nbootdelay=-1\nverify=yes\nEnvironment size: 20/65532 bytes\n=>\n";

/// The same board with the defaults a vendor actually ships.
const EXPOSED: &str = "=> printenv\nbootdelay=3\nbootcmd=bootm 0x82000000\nverify=no\n\
                       ipaddr=10.0.0.5\nserverip=10.0.0.1\nEnvironment size: 90/65532 bytes\n=>\n";

/// A plain boot log: no session, but plenty of `KEY=value` noise that a
/// careless parser would turn into an environment.
const PLAIN: &str = "U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)\n\
                     Hit any key to stop autoboot:  2\n\
                     [    0.000000] Kernel command line: console=ttyS0\n\
                     CONFIG_FOO=bar\nbootcmd=this is not really an environment\n";

fn fixture(name: &str, body: &str) -> PathBuf {
    let dir = std::env::var("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("bootintel-verdict");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join(name);
    std::fs::write(&path, body).expect("writing fixture");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("BOOTINTEL_NO_HISTORY", "1")
        .env("NO_COLOR", "1")
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

#[test]
fn a_hardened_environment_passes_the_gate() {
    let path = fixture("hardened.log", HARDENED);
    let out = run(&["verdict", path.to_str().unwrap(), "--gate-exposed"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("hardened"), "{text}");
    assert!(!text.contains("exposed"), "{text}");
}

#[test]
fn an_exposed_environment_fails_the_gate_and_names_why() {
    let path = fixture("exposed.log", EXPOSED);
    let out = run(&["verdict", path.to_str().unwrap(), "--gate-exposed"]);
    assert_eq!(code(&out), 1, "stdout: {}", stdout(&out));
    let err = stderr(&out);
    // A CI log is often the only thing anyone reads, so the failure has to
    // carry the variable it was read from, not just a count.
    assert!(err.contains("Autoboot delay"), "{err}");
    assert!(err.contains("bootdelay=3"), "{err}");
}

/// The case this whole command exists to get right. A boot log with no session
/// cannot be assessed, and "I could not answer" must not be reported as "there
/// is nothing wrong": a CI gate that goes green on it is worse than no gate.
#[test]
fn a_log_with_no_session_is_not_a_pass() {
    let path = fixture("plain.log", PLAIN);
    let out = run(&["verdict", path.to_str().unwrap(), "--gate-exposed"]);
    assert_eq!(code(&out), 3, "stdout: {}", stdout(&out));
    let err = stderr(&out);
    assert!(err.contains("no U-Boot session"), "{err}");
    // And it points at the command that does handle a plain boot log.
    assert!(err.contains("bootintel scan"), "{err}");
}

#[test]
fn an_empty_capture_is_not_a_pass() {
    let path = fixture("empty.log", "   \n\n");
    let out = run(&["verdict", path.to_str().unwrap()]);
    assert_eq!(code(&out), 2, "stdout: {}", stdout(&out));
    assert!(stderr(&out).contains("empty capture"), "{}", stderr(&out));
}

#[test]
fn json_keys_match_the_server_response() {
    // A consumer should be able to move between this and `scan --api` without
    // remapping, so the key names are part of the contract.
    let path = fixture("json.log", EXPOSED);
    let out = run(&["verdict", path.to_str().unwrap(), "--json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(v["uboot_shell"]["reached"], true);
    assert_eq!(v["uboot_shell"]["env_total_bytes"], 65532);
    assert_eq!(v["uboot_env"]["verify"], "no");
    let verdicts = v["boot_chain_verdict"].as_array().expect("an array");
    assert!(!verdicts.is_empty());
    for entry in verdicts {
        for key in ["title", "state", "detail", "evidence", "severity"] {
            assert!(entry[key].is_string(), "{key} missing from {entry}");
        }
        // remediation is nullable, not absent: a consumer indexing it should
        // get null rather than a KeyError-shaped surprise.
        assert!(entry.get("remediation").is_some(), "{entry}");
    }
}

#[test]
fn a_session_can_arrive_on_stdin() {
    let mut child = Command::new(BIN)
        .args(["verdict", "-", "--json"])
        .env("BOOTINTEL_NO_HISTORY", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning bootintel");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(EXPOSED.as_bytes())
        .expect("writing capture");
    let out = child.wait_with_output().expect("waiting");
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(v["source"], "stdin");
    assert_eq!(v["uboot_env"]["bootdelay"], "3");
}

/// Device-controlled text must not reach a terminal unescaped: a crafted
/// environment value is an ANSI-injection vector into a consultant's session.
#[test]
fn a_crafted_environment_value_cannot_inject_escapes() {
    let nasty = "=> printenv\nbootdelay=1\nbootargs=x\x1b[2J\x1b[31mowned\n\
                 Environment size: 40/65532 bytes\n";
    let path = fixture("escapes.log", nasty);
    let out = run(&["verdict", path.to_str().unwrap()]);
    let text = stdout(&out);
    assert!(
        !text.contains('\x1b'),
        "raw escape survived into stdout: {text:?}"
    );
    assert!(
        text.contains("owned"),
        "the value itself should still be shown: {text}"
    );
}
