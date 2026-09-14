//! `bootintel whoami` — verify an API key without running a scan.
//!
//! Two-stage approach because the server may or may not have a
//! dedicated /me endpoint:
//!   1. Try `GET /api/whoami`. If it returns 200 we parse the body
//!      (best-effort — `email`, `tier`, `quota_used`, `quota_total`).
//!   2. If /whoami 404s (endpoint not shipped yet), fall through to a
//!      minimal `--preview`-shape scan with a 1-byte payload and infer
//!      identity from the response envelope's `plan_tier` (or absence).
//!
//! Exit codes (sysexits.h-style so shell scripts + CI can dispatch):
//!   0  — authenticated (or --preview succeeded)
//!  65  — EX_DATAERR — 400 bad request from the server
//!  69  — EX_UNAVAILABLE — network / connectivity failure
//!  77  — EX_NOPERM — 401/403 unauthorized (key invalid / expired)
//!
//! The command deliberately never prints the full API key — the
//! human-readable "authenticated" line masks all but the last 4 chars
//! (same convention as `bootintel config list`).

use anyhow::Result;
use clap::Args as ClapArgs;
use serde::Deserialize;
use std::io::{self, Write};
use std::time::Duration;


/// sysexits.h EX_NOPERM.
const EX_NOPERM: i32 = 77;
/// sysexits.h EX_UNAVAILABLE.
const EX_UNAVAILABLE: i32 = 69;
/// sysexits.h EX_DATAERR.
const EX_DATAERR: i32 = 65;

/// Test-friendly timeout so a hung mock server doesn't stall a test
/// run. Production callers get the real ureq default (30s) via the
/// standard `ScanClient::new`.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Override the API base URL. Defaults to <https://bootintel.com>
    /// (or $BOOTINTEL_API_BASE, or config file's api_base).
    #[arg(long, value_name = "URL")]
    api_base: Option<String>,

    /// JSON output. Same info as the human output, in a shape
    /// `jq` can consume. Missing fields serialize as null.
    #[arg(long)]
    json: bool,
}

/// Envelope of resolved identity info returned by both the /whoami
/// path and the fallback preview probe. Kept in one shape so the
/// output renderer doesn't have to branch on the discovery mechanism.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Identity {
    pub api_base: String,
    pub api_key_last4: Option<String>,
    pub status: &'static str,
    pub email: Option<String>,
    pub tier: Option<String>,
    pub quota_used: Option<u64>,
    pub quota_total: Option<u64>,
    /// Seconds until the rate-limit window resets, if the fallback
    /// probe hit a 429 with a `Retry-After` header. `None` when the
    /// request wasn't throttled (or when the server sent no header).
    /// Emitted as `rate_limited_retry_secs` in JSON output.
    #[serde(
        rename = "rate_limited_retry_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub rate_limited: Option<u64>,
}

/// Shape of the /api/whoami response (if the server ships one).
/// All fields optional so a partial response doesn't crash the client.
#[derive(Deserialize, Debug, Default)]
#[serde(default)]
struct WhoamiResponse {
    email: Option<String>,
    tier: Option<String>,
    /// Some servers return the tier as `plan_tier`; accept both.
    plan_tier: Option<String>,
    quota_used: Option<u64>,
    quota_total: Option<u64>,
}

pub fn run(args: Args) -> Result<()> {
    // Precedence: CLI flag > env > config file > built-in default.
    // Centralized in crate::config for all subcommands.
    let base = crate::config::resolve_api_base(args.api_base.as_deref());
    let api_key = crate::config::resolve_api_key();

    let key = match api_key {
        Some(k) => k,
        None => {
            eprintln!(
                "no API key found — set $BOOTINTEL_API_KEY, or `bootintel config set api_key bik_...`\n  Get a key at https://bootintel.com/settings/api-keys"
            );
            std::process::exit(EX_NOPERM);
        }
    };

    // Plaintext-transport guard: same shared helper as scan / analyze.
    // whoami always sends the credential, so a public http:// is a bail
    // (never just a warning). Translate the anyhow::Err to EX_NOPERM.
    if let Err(e) = crate::api::endpoints::require_safe_transport(&base, true) {
        eprintln!("{e}");
        std::process::exit(EX_NOPERM);
    }

    let identity = match probe(&base, &key, DEFAULT_TIMEOUT) {
        Ok(id) => id,
        Err(ProbeError::Unauthorized) => {
            eprintln!("unauthorized — API key rejected by {base}");
            eprintln!(
                "  regenerate at https://bootintel.com/settings/api-keys or check $BOOTINTEL_API_KEY"
            );
            std::process::exit(EX_NOPERM);
        }
        Err(ProbeError::BadRequest(msg)) => {
            eprintln!("bad request from {base}: {msg}");
            std::process::exit(EX_DATAERR);
        }
        Err(ProbeError::Network(msg)) => {
            eprintln!("network error contacting {base}: {msg}");
            std::process::exit(EX_UNAVAILABLE);
        }
    };

    render(&identity, args.json)
}

/// Errors specific to the whoami probe. Deliberately narrower than
/// the general `ScanError` — whoami only cares about auth + network
/// buckets; anything else collapses to Network / BadRequest.
#[derive(Debug)]
enum ProbeError {
    Unauthorized,
    BadRequest(String),
    Network(String),
}

/// Run the discovery flow: try /whoami first, fall back to a preview
/// probe if the endpoint doesn't exist. Returns a fully-populated
/// `Identity` on success or a classified `ProbeError` on any failure.
fn probe(base: &str, api_key: &str, timeout: Duration) -> Result<Identity, ProbeError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .user_agent(&user_agent())
        .build();

    let whoami_url = format!("{}/api/whoami", base.trim_end_matches('/'));
    crate::vinfo!("whoami: GET {whoami_url}");
    let resp = agent
        .get(&whoami_url)
        .set("X-API-Key", api_key)
        .set("Accept", "application/json")
        .call();

    match resp {
        Ok(r) if r.status() == 200 => {
            let text = r
                .into_string()
                .map_err(|e| ProbeError::Network(e.to_string()))?;
            crate::vdebug!("whoami: body ({} bytes): {text}", text.len());
            let parsed: WhoamiResponse = serde_json::from_str(&text).unwrap_or_default();
            Ok(build_identity(base, api_key, "authenticated", parsed))
        }
        Ok(r) => {
            // 2xx-but-not-200 or 3xx redirect somewhere — treat as
            // "endpoint doesn't exist" and fall back to the preview
            // probe path.
            let status = r.status();
            crate::vinfo!("whoami: /whoami returned {status}, trying preview fallback");
            probe_via_preview(base, api_key, timeout)
        }
        Err(ureq::Error::Status(404, _)) | Err(ureq::Error::Status(405, _)) => {
            // 404 = endpoint not shipped; 405 = wrong method (server
            // has a route but doesn't accept GET). Fall through to
            // the preview probe either way.
            crate::vinfo!("whoami: /whoami endpoint not present, trying preview fallback");
            probe_via_preview(base, api_key, timeout)
        }
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => {
            Err(ProbeError::Unauthorized)
        }
        Err(ureq::Error::Status(400, r)) => {
            let text = r.into_string().unwrap_or_default();
            Err(ProbeError::BadRequest(text))
        }
        Err(ureq::Error::Status(status, _)) => {
            // Any other 4xx/5xx — try the preview fallback rather
            // than give up. If the /whoami route isn't served but
            // /preview is, the user still gets a useful answer.
            crate::vinfo!("whoami: /whoami returned unexpected {status}, trying preview fallback");
            probe_via_preview(base, api_key, timeout)
        }
        Err(ureq::Error::Transport(t)) => Err(ProbeError::Network(t.to_string())),
    }
}

/// Fallback probe: send a minimal authed scan with a 1-byte payload
/// and read the response envelope. We're not looking for findings —
/// just "did the server accept our key?".
fn probe_via_preview(base: &str, api_key: &str, timeout: Duration) -> Result<Identity, ProbeError> {
    // Manual POST — bypass ScanClient's retry loop so whoami fails fast.
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .user_agent(&user_agent())
        .build();
    let url = format!("{}/api/analysis/scan", base.trim_end_matches('/'));
    crate::vinfo!("whoami: POST {url} (fallback probe)");
    let body = serde_json::json!({ "raw_log": "\n" });
    let resp = agent
        .post(&url)
        .set("X-API-Key", api_key)
        .set("Accept", "application/json")
        .send_json(body);

    match resp {
        Ok(r) if (200..300).contains(&r.status()) => {
            let text = r
                .into_string()
                .map_err(|e| ProbeError::Network(e.to_string()))?;
            crate::vdebug!("whoami fallback: body ({} bytes): {text}", text.len());
            // Best-effort: pluck plan_tier / tier from the envelope.
            // We don't require any specific field to succeed — a 200
            // is already "key valid".
            let v: serde_json::Value =
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
            let tier = v
                .get("plan_tier")
                .or_else(|| v.get("tier"))
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());
            let email = v
                .get("email")
                .and_then(|e| e.as_str())
                .map(|s| s.to_string());
            let quota_used = v.get("quota_used").and_then(|n| n.as_u64());
            let quota_total = v.get("quota_total").and_then(|n| n.as_u64());
            Ok(build_identity(
                base,
                api_key,
                "authenticated",
                WhoamiResponse {
                    email,
                    tier: tier.clone(),
                    plan_tier: tier,
                    quota_used,
                    quota_total,
                },
            ))
        }
        Ok(r) => {
            // 3xx would be odd from a JSON API; treat as network-ish.
            Err(ProbeError::Network(format!(
                "unexpected status {} from {url}",
                r.status()
            )))
        }
        Err(ureq::Error::Status(429, r)) => {
            // Rate-limited BUT the auth clearly worked (else it'd
            // be 401). Report as authenticated + note the throttle in
            // the typed `rate_limited` field. The status literal stays
            // "authenticated (rate-limited)" so text-mode consumers
            // don't have to parse a new field.
            let retry = r.header("Retry-After").and_then(|v| v.parse::<u64>().ok());
            let mut id = build_identity(
                base,
                api_key,
                "authenticated (rate-limited)",
                WhoamiResponse::default(),
            );
            id.rate_limited = retry;
            Ok(id)
        }
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => {
            Err(ProbeError::Unauthorized)
        }
        Err(ureq::Error::Status(400, r)) => {
            let text = r.into_string().unwrap_or_default();
            Err(ProbeError::BadRequest(text))
        }
        Err(ureq::Error::Status(status, _)) => {
            Err(ProbeError::Network(format!("HTTP {status} from {url}")))
        }
        Err(ureq::Error::Transport(t)) => Err(ProbeError::Network(t.to_string())),
    }
}

fn build_identity(base: &str, api_key: &str, status: &'static str, w: WhoamiResponse) -> Identity {
    Identity {
        api_base: base.to_string(),
        api_key_last4: last4(api_key),
        status,
        email: w.email,
        tier: w.tier.or(w.plan_tier),
        quota_used: w.quota_used,
        quota_total: w.quota_total,
        rate_limited: None,
    }
}

/// User-Agent matches the main scan client so server-side analytics
/// can distinguish whoami traffic from real scans (endpoint alone
/// isn't a reliable filter — the fallback path posts to /analysis/scan).
fn user_agent() -> String {
    format!(
        "bootintel-cli/{} whoami ({} {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Return the last 4 chars of `s` as an owned String, or None if
/// there aren't 4 chars. Used for `Identity::api_key_last4` — a
/// structured field where the caller renders the ellipsis prefix
/// itself (e.g. "bik_...{last4}"). Distinct from
/// `crate::output::mask_tail` which returns "..." + tail as one
/// display-ready string.
///
/// UTF-8-safe via char_indices — the original hand-written
/// .chars().rev().take(4).collect::<Vec<_>>().into_iter().rev()
/// idiom worked but did two passes and allocated a Vec per call.
fn last4(s: &str) -> Option<String> {
    let trimmed = s.trim();
    // Iterate char_indices from the back; take the 4th-from-last byte
    // offset. If fewer than 4 chars exist, nth returns None → None.
    let start_byte = trimmed.char_indices().rev().nth(3).map(|(i, _)| i)?;
    Some(trimmed[start_byte..].to_string())
}

fn render(id: &Identity, as_json: bool) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if as_json {
        // Machine-readable path. `?` field for "unknown" would break
        // strict JSON parsers, so use JSON `null` (serde default for
        // Option::None).
        serde_json::to_writer_pretty(&mut out, id)?;
        writeln!(out)?;
        return Ok(());
    }
    writeln!(out, "bootintel-cli whoami")?;
    writeln!(out, "  api base: {}", id.api_base)?;
    writeln!(
        out,
        "  api key:  bik_...{}",
        id.api_key_last4.as_deref().unwrap_or("????")
    )?;
    writeln!(out, "  status:   {}", id.status)?;
    if let Some(secs) = id.rate_limited {
        writeln!(out, "  retry:    {secs}s")?;
    }
    writeln!(out, "  email:    {}", or_unknown(&id.email))?;
    writeln!(out, "  tier:     {}", or_unknown(&id.tier))?;
    match (id.quota_used, id.quota_total) {
        (Some(u), Some(t)) => writeln!(out, "  quota:    {u}/{t} today")?,
        _ => writeln!(out, "  quota:    unknown")?,
    }
    Ok(())
}

fn or_unknown(s: &Option<String>) -> &str {
    s.as_deref().unwrap_or("unknown")
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    // Reuse the tiny TcpListener-based mock server pattern from the
    // api::client tests — no extra deps, deterministic teardown.
    use std::io::{BufRead, BufReader, Read, Write as IoWrite};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;

    type Responder = Arc<dyn Fn(&str, &str) -> Vec<u8> + Send + Sync + 'static>;

    fn spawn_mock<F>(f: F, max: usize) -> String
    where
        F: Fn(&str, &str) -> Vec<u8> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let r: Responder = Arc::new(f);
        thread::spawn(move || {
            for s in listener.incoming().take(max).flatten() {
                let rc = r.clone();
                let _ = handle(s, rc);
            }
        });
        thread::sleep(Duration::from_millis(50));
        format!("http://{addr}")
    }

    fn handle(stream: TcpStream, r: Responder) -> Option<()> {
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).ok()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                if k.trim().eq_ignore_ascii_case("Content-Length") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
        }
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            let _ = reader.read_exact(&mut body);
        }
        let response = r(&method, &path);
        let mut stream = stream;
        stream.write_all(&response).ok()?;
        stream.flush().ok()
    }

    fn ok(body: &str) -> Vec<u8> {
        let mut o = Vec::new();
        write!(
            o,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        ).unwrap();
        o
    }

    fn status(code: u16, body: &str) -> Vec<u8> {
        let mut o = Vec::new();
        write!(
            o,
            "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        ).unwrap();
        o
    }

    #[test]
    fn whoami_endpoint_populates_identity() {
        let base = spawn_mock(
            |method, path| {
                assert_eq!(method, "GET");
                assert_eq!(path, "/api/whoami");
                ok(
                    r#"{"email":"z@bootintel.com","tier":"Researcher","quota_used":3,"quota_total":50}"#,
                )
            },
            1,
        );
        let id = probe(&base, "bik_test_1234", Duration::from_millis(500)).unwrap();
        assert_eq!(id.status, "authenticated");
        assert_eq!(id.email.as_deref(), Some("z@bootintel.com"));
        assert_eq!(id.tier.as_deref(), Some("Researcher"));
        assert_eq!(id.quota_used, Some(3));
        assert_eq!(id.quota_total, Some(50));
        assert_eq!(id.api_key_last4.as_deref(), Some("1234"));
    }

    #[test]
    fn missing_whoami_endpoint_falls_back_to_preview_probe() {
        // Server responds 404 on /api/whoami, 200 on /api/analysis/scan.
        // Serves two connections; ureq closes each after one request.
        let base = spawn_mock(
            |_method, path| {
                if path == "/api/whoami" {
                    status(404, r#"{"detail":"not found"}"#)
                } else if path == "/api/analysis/scan" {
                    ok(r#"{"scan_id":"z","findings":[],"plan_tier":"Pro"}"#)
                } else {
                    status(500, r#"{"detail":"???"}"#)
                }
            },
            4,
        );
        let id = probe(&base, "bik_test_ABCD", Duration::from_millis(500)).unwrap();
        assert_eq!(id.status, "authenticated");
        assert_eq!(id.tier.as_deref(), Some("Pro"));
        assert_eq!(id.api_key_last4.as_deref(), Some("ABCD"));
    }

    #[test]
    fn unauthorized_maps_to_probe_error() {
        let base = spawn_mock(
            |_method, _path| status(401, r#"{"detail":"invalid key"}"#),
            2,
        );
        let err = probe(&base, "bad", Duration::from_millis(500)).unwrap_err();
        assert!(matches!(err, ProbeError::Unauthorized), "got: {err:?}");
    }

    #[test]
    fn network_failure_maps_to_network_error() {
        // Bind + drop a port so the connect fails deterministically.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let err = probe(&format!("http://{addr}"), "k", Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, ProbeError::Network(_)), "got: {err:?}");
    }

    #[test]
    fn rate_limited_surfaces_in_typed_field() {
        // 404 on /whoami then 429 on preview probe — the fallback path
        // must populate `rate_limited` with the Retry-After seconds and
        // leave `tier` alone.
        fn status_with_header(code: u16, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
            let mut o = Vec::new();
            write!(o, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\n").unwrap();
            for (k, v) in headers {
                write!(o, "{k}: {v}\r\n").unwrap();
            }
            write!(
                o,
                "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            o
        }
        let base = spawn_mock(
            |_method, path| {
                if path == "/api/whoami" {
                    status(404, r#"{"detail":"not found"}"#)
                } else {
                    status_with_header(
                        429,
                        &[("Retry-After", "42")],
                        r#"{"detail":"slow down"}"#,
                    )
                }
            },
            4,
        );
        let id = probe(&base, "bik_test_xyz9", Duration::from_millis(500)).unwrap();
        assert_eq!(id.status, "authenticated (rate-limited)");
        assert_eq!(id.rate_limited, Some(42));
        assert!(id.tier.is_none(), "tier must NOT be hijacked with retry-in-Ns");
    }

    #[test]
    fn last4_masks_correctly() {
        assert_eq!(last4("bik_supersecret_1234"), Some("1234".to_string()));
        assert_eq!(last4("abcd"), Some("abcd".to_string()));
        assert_eq!(last4("abc"), None);
    }

    #[test]
    fn identity_serializes_stable_json_shape() {
        let id = Identity {
            api_base: "https://bootintel.com".into(),
            api_key_last4: Some("beef".into()),
            status: "authenticated",
            email: Some("z@example.com".into()),
            tier: Some("Researcher".into()),
            quota_used: Some(1),
            quota_total: Some(50),
            rate_limited: None,
        };
        let s = serde_json::to_string(&id).unwrap();
        assert!(s.contains("\"api_key_last4\":\"beef\""));
        assert!(s.contains("\"status\":\"authenticated\""));
        assert!(s.contains("\"quota_total\":50"));
    }
}
