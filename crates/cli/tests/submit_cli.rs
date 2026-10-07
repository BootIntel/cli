//! `bootintel submit` against a mock server.
//!
//! Drives the compiled binary, because every property worth asserting here is
//! a property of the process: the exit code, which requests it makes in what
//! order, and whether an artifact reaches disk byte-for-byte.
//!
//! The behaviours under test and why each one earns a test:
//!
//!   * Device REUSE. `POST /devices/` will happily create a second device with
//!     the same name, so a nightly CI job without the lookup would add a
//!     device a day and nothing server-side would complain. The test asserts
//!     no device is created when one already matches.
//!   * Byte fidelity. The evidence pack and PDF are binary. Routing them
//!     through a String would corrupt them silently, and a corrupt PDF still
//!     looks like a file on disk, so the test ships bytes that are not valid
//!     UTF-8 and compares them exactly.
//!   * Exit codes. A CI step's only signal. 403 has to be 77 (EX_NOPERM) and
//!     not a generic failure, because the plan/quota case is the one a user
//!     has to act on.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_bootintel");

const SCAN_ID: &str = "11111111-2222-3333-4444-555555555555";
const DEVICE_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

fn tmpdir() -> PathBuf {
    let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".into());
    let dir = PathBuf::from(base).join("submit_cli");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Named rather than inlined: clippy flags the bare
/// `Arc<dyn Fn(&str, &str) -> Vec<u8> + Send + Sync>` as a very complex type,
/// and the in-crate mock in src/api/client.rs already uses an alias for the
/// same shape.
type Responder = Arc<dyn Fn(&str, &str) -> Vec<u8> + Send + Sync>;

struct Mock {
    base: String,
    seen: Arc<Mutex<Vec<String>>>,
}

/// Serve `max_conns` requests, recording "METHOD PATH" for each.
fn spawn_mock<F>(responder: F, max_conns: usize) -> Mock
where
    F: Fn(&str, &str) -> Vec<u8> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let addr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_w = seen.clone();
    let responder = Arc::new(responder);
    let served = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming().take(max_conns).flatten() {
            let r = responder.clone();
            let s = seen_w.clone();
            served.fetch_add(1, Ordering::SeqCst);
            let _ = handle(stream, r, s);
        }
    });
    thread::sleep(Duration::from_millis(80));
    Mock {
        base: format!("http://{addr}"),
        seen,
    }
}

fn handle(stream: TcpStream, responder: Responder, seen: Arc<Mutex<Vec<String>>>) -> Option<()> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut content_length = 0usize;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let t = h.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some((k, v)) = t.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).ok()?;
    }
    seen.lock().unwrap().push(format!("{method} {path}"));
    let resp = responder(&method, &path);
    let mut stream = stream;
    stream.write_all(&resp).ok()?;
    stream.flush().ok()
}

fn http(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A log file unique to the calling test.
///
/// Every test used to write the same `boot.log`. Rust runs tests in parallel
/// threads, and `fs::write` truncates before it writes, so one test's spawned
/// process could read the file in the instant another test had emptied it. The
/// failure was `boot.log is empty; nothing to submit` in CI while the suite
/// passed locally -- the shape of a race that reddens a build intermittently
/// rather than once, which is the kind that survives.
fn log_file(tag: &str) -> PathBuf {
    let p = tmpdir().join(format!("{tag}.log"));
    std::fs::write(&p, "U-Boot 2016.01\nLinux version 4.4.60\n").unwrap();
    p
}

fn run(tag: &str, base: &str, extra: &[&str]) -> std::process::Output {
    let log = log_file(tag);
    let mut cmd = Command::new(BIN);
    cmd.arg("submit")
        .arg(&log)
        .arg("--api-base")
        .arg(base)
        .env("BOOTINTEL_API_KEY", "bik_test_key")
        // The mock serves FastAPI-direct paths, with no /api prefix.
        .env("BOOTINTEL_API_PATH_PREFIX", "/");
    for a in extra {
        cmd.arg(a);
    }
    cmd.output().expect("running bootintel submit")
}

#[test]
fn an_existing_device_with_the_same_name_is_reused() {
    let mock = spawn_mock(
        |method, path| match (method, path) {
            ("GET", "/devices/") => http(
                200,
                "application/json",
                format!(r#"[{{"id":"{DEVICE_ID}","name":"lab-router"}}]"#).as_bytes(),
            ),
            ("POST", "/scans/") => http(
                201,
                "application/json",
                format!(r#"{{"id":"{SCAN_ID}"}}"#).as_bytes(),
            ),
            _ => http(404, "application/json", br#"{"detail":"unexpected"}"#),
        },
        4,
    );
    let out = run("reuse", &mock.base, &["--device-name", "lab-router"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen = mock.seen.lock().unwrap().clone();
    assert!(
        !seen.iter().any(|r| r == "POST /devices/"),
        "a device was created despite one matching by name: {seen:?}"
    );
    assert!(seen.iter().any(|r| r == "POST /scans/"), "{seen:?}");
}

#[test]
fn a_device_is_created_when_none_matches() {
    let mock = spawn_mock(
        |method, path| match (method, path) {
            ("GET", "/devices/") => http(200, "application/json", b"[]"),
            ("POST", "/devices/") => http(
                201,
                "application/json",
                format!(r#"{{"id":"{DEVICE_ID}","name":"new-board"}}"#).as_bytes(),
            ),
            ("POST", "/scans/") => http(
                201,
                "application/json",
                format!(r#"{{"id":"{SCAN_ID}"}}"#).as_bytes(),
            ),
            _ => http(404, "application/json", br#"{"detail":"unexpected"}"#),
        },
        5,
    );
    let out = run("create", &mock.base, &["--device-name", "new-board"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seen = mock.seen.lock().unwrap().clone();
    assert!(seen.iter().any(|r| r == "POST /devices/"), "{seen:?}");
}

#[test]
fn a_binary_artifact_reaches_disk_byte_for_byte() {
    // Deliberately not valid UTF-8: a PDF or zip is not, and a String
    // round-trip would mangle it into replacement characters.
    const RAW: &[u8] = &[
        0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, 0xff, 0xfe, 0x00, 0x80,
    ];
    let dest = tmpdir().join("out.pdf");
    let _ = std::fs::remove_file(&dest);
    let mock = spawn_mock(
        move |method, path| match (method, path) {
            ("GET", "/devices/") => http(200, "application/json", b"[]"),
            ("POST", "/devices/") => http(
                201,
                "application/json",
                format!(r#"{{"id":"{DEVICE_ID}","name":"b"}}"#).as_bytes(),
            ),
            ("POST", "/scans/") => http(
                201,
                "application/json",
                format!(r#"{{"id":"{SCAN_ID}"}}"#).as_bytes(),
            ),
            ("GET", p) if p.ends_with("/report.pdf") => http(200, "application/pdf", RAW),
            _ => http(404, "application/json", br#"{"detail":"unexpected"}"#),
        },
        6,
    );
    let out = run("binary", &mock.base, &["--pdf", dest.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let got = std::fs::read(&dest).expect("artifact written");
    assert_eq!(got, RAW, "the PDF was altered on the way to disk");
}

#[test]
fn a_403_exits_77_and_surfaces_the_servers_reason() {
    let mock = spawn_mock(
        |_method, _path| {
            http(
                403,
                "application/json",
                br#"{"detail":"API access requires Pro plan or higher."}"#,
            )
        },
        3,
    );
    let out = run(
        "forbidden",
        &mock.base,
        &["--sbom", tmpdir().join("x.json").to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(77), "403 must map to EX_NOPERM");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Pro plan or higher"),
        "the server's own reason must be shown, got: {err}"
    );
}

#[test]
fn the_quota_notice_is_not_printed_when_the_run_fails_before_the_spend() {
    // It used to print at the top of the run, so a 403 from the device lookup
    // was preceded by a claim about a charge that never happened.
    let mock = spawn_mock(
        |_method, _path| http(403, "application/json", br#"{"detail":"nope"}"#),
        3,
    );
    let out = run(
        "noquota",
        &mock.base,
        &["--sbom", tmpdir().join("y.json").to_str().unwrap()],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("monthly quota"),
        "claimed a quota spend that did not happen: {err}"
    );
}

#[test]
fn json_mode_emits_parseable_stdout() {
    let dest = tmpdir().join("sbom.json");
    let mock = spawn_mock(
        |method, path| match (method, path) {
            ("GET", "/devices/") => http(200, "application/json", b"[]"),
            ("POST", "/devices/") => http(
                201,
                "application/json",
                format!(r#"{{"id":"{DEVICE_ID}","name":"j"}}"#).as_bytes(),
            ),
            ("POST", "/scans/") => http(
                201,
                "application/json",
                format!(r#"{{"id":"{SCAN_ID}"}}"#).as_bytes(),
            ),
            ("GET", p) if p.ends_with("/sbom.json") => http(
                200,
                "application/vnd.cyclonedx+json",
                br#"{"bomFormat":"CycloneDX"}"#,
            ),
            _ => http(404, "application/json", br#"{"detail":"unexpected"}"#),
        },
        6,
    );
    let out = run(
        "jsonmode",
        &mock.base,
        &["--sbom", dest.to_str().unwrap(), "--json"],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout must be valid JSON");
    assert_eq!(parsed["scan_id"], SCAN_ID);
    assert_eq!(parsed["artifacts"][0]["kind"], "sbom");
}

#[test]
fn plaintext_non_loopback_is_refused_before_any_request() {
    let out = run(
        "plaintext",
        "http://example.invalid",
        &["--sbom", tmpdir().join("z.json").to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(77));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("plaintext"), "got: {err}");
}
