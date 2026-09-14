//! Sync HTTP client for the bootintel.com analysis API.
//!
//! Two entrypoints: `preview_scan` (anonymous) and `authed_scan`
//! (needs an API key). Both take the raw log bytes and an optional
//! device-name hint; both return a fully-parsed `ApiScanResponse`
//! on success or a specific `ScanError` variant on failure.
//!
//! `AuthMode` centralises which endpoint + which headers to use so
//! the caller doesn't have to know the routing detail.

use serde::Serialize;
use std::time::Duration;

use super::endpoints::{preview_url, scan_url};
use super::response::{parse_scan_response, ApiFailure, ApiScanResponse};

/// Default read/connect timeout. Server-side analysis (CVE match +
/// AI summarisation) can take up to ~15s on a big log; give it
/// headroom. Overridable via `ScanClient::with_timeout` for tests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Retry schedule for transient failures (network + 5xx). Tuned to
/// paper over a single lost packet or a brief server restart without
/// making the caller wait long enough to reach for Ctrl-C. Total
/// worst-case retry delay: 2.6s. 4xx and Malformed are NOT retried
/// (they're deterministic — retrying wastes time and quota).
const RETRY_BACKOFF_MS: &[u64] = &[100, 500, 2000];

/// User-Agent sent with every request. Server-side analytics can
/// filter CLI traffic vs browser traffic on this string.
fn user_agent() -> String {
    format!(
        "bootintel-cli/{} ({} {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

pub struct ScanClient {
    agent: ureq::Agent,
    base_url: String,
}

impl ScanClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(DEFAULT_TIMEOUT)
            .timeout_read(DEFAULT_TIMEOUT)
            .user_agent(&user_agent())
            .build();
        Self {
            agent,
            base_url: base_url.into(),
        }
    }

    /// Test-friendly constructor: shorter timeout so a hung mock
    /// server fails a test in seconds, not half a minute.
    #[cfg(test)]
    pub fn with_timeout(base_url: impl Into<String>, timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .user_agent(&user_agent())
            .build();
        Self {
            agent,
            base_url: base_url.into(),
        }
    }

    /// Anonymous /api/analysis/preview call. 3/day per IP limit.
    /// Falls into `ScanError::RateLimited` when the server returns
    /// 429 so the caller can render the pricing-upgrade message.
    pub fn preview_scan(
        &self,
        log: &str,
        device_name: Option<&str>,
    ) -> Result<ApiScanResponse, ScanError> {
        let url = preview_url(&self.base_url);
        let body = ScanRequestBody {
            raw_log: log,
            device_name,
        };
        self.post_and_parse(&url, &body, None)
    }

    /// Authenticated /api/analysis/scan call. `api_key` is sent in
    /// the `X-API-Key` header (the server also accepts Bearer; we
    /// pick X-API-Key so the value never lands in web-server access
    /// logs that mask only the Authorization header).
    pub fn authed_scan(
        &self,
        log: &str,
        device_name: Option<&str>,
        api_key: &str,
    ) -> Result<ApiScanResponse, ScanError> {
        let url = scan_url(&self.base_url);
        let body = ScanRequestBody {
            raw_log: log,
            device_name,
        };
        self.post_and_parse(&url, &body, Some(api_key))
    }

    fn post_and_parse(
        &self,
        url: &str,
        body: &ScanRequestBody,
        api_key: Option<&str>,
    ) -> Result<ApiScanResponse, ScanError> {
        // First attempt + up to RETRY_BACKOFF_MS.len() retries. Total
        // attempt count is fixed and small so a broken server or an
        // offline network fails fast enough that the user's Ctrl-C
        // reflex still wins.
        let mut last_err: Option<ScanError> = None;
        for (attempt, wait_ms) in std::iter::once(0)
            .chain(RETRY_BACKOFF_MS.iter().copied())
            .enumerate()
        {
            if wait_ms > 0 {
                crate::vinfo!(
                    "retrying POST {url} in {wait_ms}ms (attempt {})",
                    attempt + 1
                );
                std::thread::sleep(Duration::from_millis(wait_ms));
            } else {
                crate::vinfo!(
                    "POST {url} ({} bytes, key={})",
                    body.raw_log.len(),
                    if api_key.is_some() { "yes" } else { "no" }
                );
            }
            match self.attempt_post(url, body, api_key) {
                Ok(resp) => {
                    crate::vinfo!("POST {url} succeeded ({} findings)", resp.findings.len());
                    return Ok(resp);
                }
                Err(err) => {
                    crate::vinfo!("POST {url} failed: {err}");
                    if !is_retryable(&err) || attempt == RETRY_BACKOFF_MS.len() {
                        return Err(err);
                    }
                    // Keep the last error so if all retries exhaust
                    // (unlikely since we return above on the final
                    // iteration) we still surface something.
                    last_err = Some(err);
                }
            }
        }
        // Unreachable: the loop always returns on the last iteration.
        // Guard with the captured error just in case.
        Err(last_err.unwrap_or(ScanError::Network("retry loop exhausted".into())))
    }

    fn attempt_post(
        &self,
        url: &str,
        body: &ScanRequestBody,
        api_key: Option<&str>,
    ) -> Result<ApiScanResponse, ScanError> {
        let mut req = self.agent.post(url).set("Accept", "application/json");
        if let Some(key) = api_key {
            req = req.set("X-API-Key", key);
        }
        let call = req.send_json(body);
        match call {
            Ok(resp) => {
                let status = resp.status();
                let text = resp
                    .into_string()
                    .map_err(|e| ScanError::Network(e.to_string()))?;
                crate::vdebug!("HTTP {status} body ({} bytes): {}", text.len(), text);
                parse_scan_response(status, &text).map_err(ScanError::from)
            }
            Err(ureq::Error::Status(status, resp)) => {
                let retry_after = resp
                    .header("Retry-After")
                    .and_then(|v| v.parse::<u64>().ok());
                let text = resp.into_string().unwrap_or_default();
                crate::vdebug!("HTTP {status} error body ({} bytes): {}", text.len(), text);
                let parsed = parse_scan_response(status, &text);
                let base = match parsed {
                    Err(e) => e,
                    Ok(_) => {
                        // Server returned an error status with a
                        // shaped success body somehow — treat the
                        // status as authoritative.
                        ApiFailure::HttpStatus {
                            status,
                            detail: None,
                        }
                    }
                };
                Err(ScanError::classify(base, retry_after))
            }
            Err(ureq::Error::Transport(t)) => Err(ScanError::Network(t.to_string())),
        }
    }
}

/// Decide whether a failure is worth retrying. Yes for genuinely
/// transient conditions (network glitch, 5xx). No for anything the
/// server has already made an authoritative decision about (auth,
/// bad request, quota, malformed body) — retrying just wastes
/// wall-clock time and, for 429, further eats the caller's quota.
fn is_retryable(err: &ScanError) -> bool {
    matches!(err, ScanError::Network(_) | ScanError::ServerError { .. })
}

#[derive(Serialize)]
struct ScanRequestBody<'a> {
    raw_log: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<&'a str>,
}

/// Typed API failures the caller can dispatch on. Keeping these
/// distinct (rather than one giant string) lets the scan-command
/// renderer show a specific, actionable message per case.
#[derive(Debug)]
pub enum ScanError {
    /// 429 Too Many Requests. `retry_after_seconds` is parsed from
    /// the Retry-After header when present.
    RateLimited {
        detail: Option<String>,
        retry_after_seconds: Option<u64>,
    },
    /// 401 or 403 — missing/invalid/expired API key.
    Unauthorized { detail: Option<String> },
    /// 400 — request body too large or malformed.
    BadRequest { detail: Option<String> },
    /// 5xx — server-side problem.
    ServerError { status: u16, detail: Option<String> },
    /// Any other non-2xx status not covered above.
    Other { status: u16, detail: Option<String> },
    /// TCP / TLS / DNS / socket-level failure.
    Network(String),
    /// 2xx status but response body was not parseable as JSON.
    /// Includes a snippet so the user can debug.
    Malformed {
        status: u16,
        snippet: String,
        error: String,
    },
}

impl ScanError {
    fn classify(f: ApiFailure, retry_after_seconds: Option<u64>) -> Self {
        match f {
            ApiFailure::HttpStatus {
                status: 429,
                detail,
            } => ScanError::RateLimited {
                detail,
                retry_after_seconds,
            },
            ApiFailure::HttpStatus { status, detail } if status == 401 || status == 403 => {
                ScanError::Unauthorized { detail }
            }
            ApiFailure::HttpStatus {
                status: 400,
                detail,
            } => ScanError::BadRequest { detail },
            ApiFailure::HttpStatus { status, detail } if (500..600).contains(&status) => {
                ScanError::ServerError { status, detail }
            }
            ApiFailure::HttpStatus { status, detail } => ScanError::Other { status, detail },
            ApiFailure::Malformed {
                status,
                snippet,
                error,
            } => ScanError::Malformed {
                status,
                snippet,
                error,
            },
        }
    }

    /// A short, actionable next step for this error, or None if the
    /// Display body already tells the user everything useful. Meant
    /// to be appended on a new line by callers that render errors
    /// compactly (e.g. the `analyze` mode's Ctrl-A f handler that
    /// only has one line of prose before falling back to the live
    /// client-side detector output).
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            ScanError::RateLimited { .. } => Some(
                "quota exhausted — see https://bootintel.com/pricing, or fall back to client-side `bootintel scan` (no --api)",
            ),
            ScanError::Unauthorized { .. } => Some(
                "check $BOOTINTEL_API_KEY, or regenerate at https://bootintel.com/settings/api-keys",
            ),
            ScanError::BadRequest { .. } => Some(
                "common causes: log > 256KB (server limit), or the file isn't a boot log",
            ),
            ScanError::ServerError { .. } => Some(
                "may be transient — retry in a moment; check https://bootintel.com/status if it persists",
            ),
            ScanError::Network(_) => Some(
                "check network + $BOOTINTEL_API_BASE (if set); client-side `bootintel scan` works offline",
            ),
            ScanError::Malformed { .. } => Some(
                "this is a bug — please file at https://github.com/bootintel/cli/issues",
            ),
            ScanError::Other { .. } => None,
        }
    }
}

impl From<ApiFailure> for ScanError {
    fn from(f: ApiFailure) -> Self {
        Self::classify(f, None)
    }
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::RateLimited {
                detail,
                retry_after_seconds,
            } => {
                let base = detail
                    .clone()
                    .unwrap_or_else(|| "rate limit reached".into());
                match retry_after_seconds {
                    Some(s) => write!(f, "{base} (retry after {s}s)"),
                    None => write!(f, "{base}"),
                }
            }
            ScanError::Unauthorized { detail } => match detail {
                Some(d) => write!(f, "unauthorized: {d}"),
                None => write!(f, "unauthorized (missing or invalid API key)"),
            },
            ScanError::BadRequest { detail } => match detail {
                Some(d) => write!(f, "bad request: {d}"),
                None => write!(f, "bad request"),
            },
            ScanError::ServerError { status, detail } => match detail {
                Some(d) => write!(f, "server error {status}: {d}"),
                None => write!(f, "server error {status}"),
            },
            ScanError::Other { status, detail } => match detail {
                Some(d) => write!(f, "HTTP {status}: {d}"),
                None => write!(f, "HTTP {status}"),
            },
            ScanError::Network(s) => write!(f, "network error: {s}"),
            ScanError::Malformed { status, error, .. } => {
                write!(f, "unparseable response (HTTP {status}): {error}")
            }
        }
    }
}

impl std::error::Error for ScanError {}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod mock_server {
    //! Tiny std::net::TcpListener-based HTTP/1.1 mock. No extra
    //! deps — we speak just enough HTTP to serve one request per
    //! connection and return canned bytes.
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    pub type Responder =
        Arc<dyn Fn(&str, &str, &[(String, String)], &str) -> Vec<u8> + Send + Sync + 'static>;

    pub fn spawn<F>(responder: F, max_conns: usize) -> String
    where
        F: Fn(&str, &str, &[(String, String)], &str) -> Vec<u8> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let addr = listener.local_addr().unwrap();
        let responder: Responder = Arc::new(responder);
        thread::spawn(move || {
            for s in listener.incoming().take(max_conns).flatten() {
                let r = responder.clone();
                let _ = handle(s, r);
            }
        });
        thread::sleep(Duration::from_millis(50));
        format!("http://{addr}")
    }

    fn handle(stream: TcpStream, responder: Responder) -> Option<()> {
        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).ok()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();

        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                break;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                let k = k.trim().to_string();
                let v = v.trim().to_string();
                if k.eq_ignore_ascii_case("Content-Length") {
                    content_length = v.parse().unwrap_or(0);
                }
                headers.push((k, v));
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body).ok()?;
        }
        let body_str = std::str::from_utf8(&body).unwrap_or("");
        let response = responder(&method, &path, &headers, body_str);
        let mut stream = stream;
        stream.write_all(&response).ok()?;
        stream.flush().ok()
    }

    pub fn ok(body: &str) -> Vec<u8> {
        let mut out = Vec::new();
        write!(
            out,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        out
    }

    pub fn err(status: u16, body: &str, extra: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        write!(out, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", body.len()).unwrap();
        for (k, v) in extra {
            write!(out, "{k}: {v}\r\n").unwrap();
        }
        write!(out, "\r\n{body}").unwrap();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_contains_version_and_platform() {
        let ua = user_agent();
        assert!(ua.starts_with("bootintel-cli/"));
        assert!(ua.contains(std::env::consts::OS));
        assert!(ua.contains(std::env::consts::ARCH));
    }

    #[test]
    fn classify_maps_status_families() {
        let e429 = ApiFailure::HttpStatus {
            status: 429,
            detail: Some("nope".into()),
        };
        match ScanError::classify(e429, Some(3600)) {
            ScanError::RateLimited {
                retry_after_seconds: Some(3600),
                ..
            } => {}
            other => panic!("wrong variant: {other:?}"),
        }
        let e401 = ApiFailure::HttpStatus {
            status: 401,
            detail: None,
        };
        matches!(
            ScanError::classify(e401, None),
            ScanError::Unauthorized { .. }
        );
        let e500 = ApiFailure::HttpStatus {
            status: 502,
            detail: None,
        };
        matches!(
            ScanError::classify(e500, None),
            ScanError::ServerError { status: 502, .. }
        );
        let e400 = ApiFailure::HttpStatus {
            status: 400,
            detail: None,
        };
        matches!(
            ScanError::classify(e400, None),
            ScanError::BadRequest { .. }
        );
        let e418 = ApiFailure::HttpStatus {
            status: 418,
            detail: None,
        };
        matches!(
            ScanError::classify(e418, None),
            ScanError::Other { status: 418, .. }
        );
    }

    // ── Real-socket round-trips against a mock HTTP server ─────────

    use super::mock_server;

    #[test]
    fn preview_scan_round_trip_over_real_socket() {
        let body = r#"{
            "scan_id":"abc",
            "device_name":"Test Device",
            "preview":true,
            "findings":[{"label":"Bootloader","value":"U-Boot 2020.10"}],
            "findings_total":1
        }"#;
        let base = mock_server::spawn(
            move |method, path, _h, _body| {
                assert_eq!(method, "POST");
                assert_eq!(path, "/api/analysis/preview");
                mock_server::ok(body)
            },
            1,
        );
        let client = ScanClient::new(&base);
        let resp = client
            .preview_scan("boot log bytes", Some("Test Device"))
            .unwrap();
        assert_eq!(resp.scan_id.as_deref(), Some("abc"));
        assert_eq!(resp.findings.len(), 1);
        // "label" is a serde alias for the server's canonical "title" field.
        assert_eq!(resp.findings[0].title.as_deref(), Some("Bootloader"));
    }

    #[test]
    fn authed_scan_sends_api_key_header_and_body() {
        let body = r#"{"scan_id":"z","findings":[]}"#;
        let base = mock_server::spawn(
            move |_m, path, headers, req_body| {
                assert_eq!(path, "/api/analysis/scan");
                let has_key = headers
                    .iter()
                    .any(|(k, v)| k.eq_ignore_ascii_case("x-api-key") && v == "bik_test_1234");
                assert!(has_key, "X-API-Key header missing: {headers:?}");
                assert!(
                    req_body.contains("U-Boot"),
                    "body missing log content: {req_body}"
                );
                mock_server::ok(body)
            },
            1,
        );
        let client = ScanClient::new(&base);
        let resp = client
            .authed_scan("U-Boot 2020.10", None, "bik_test_1234")
            .unwrap();
        assert_eq!(resp.scan_id.as_deref(), Some("z"));
    }

    #[test]
    fn user_agent_header_is_sent() {
        let base = mock_server::spawn(
            move |_m, _p, headers, _b| {
                let ua = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                assert!(ua.starts_with("bootintel-cli/"), "UA was: {ua}");
                mock_server::ok(r#"{"scan_id":"x","findings":[]}"#)
            },
            1,
        );
        let client = ScanClient::new(&base);
        let _ = client.preview_scan("x", None);
    }

    #[test]
    fn rate_limit_surfaces_with_retry_after() {
        let base = mock_server::spawn(
            move |_m, _p, _h, _b| {
                mock_server::err(
                    429,
                    r#"{"detail":"Anonymous preview limit reached."}"#,
                    &[("Retry-After", "3600")],
                )
            },
            1,
        );
        let client = ScanClient::new(&base);
        let err = client.preview_scan("x", None).unwrap_err();
        match err {
            ScanError::RateLimited {
                detail,
                retry_after_seconds,
            } => {
                assert_eq!(retry_after_seconds, Some(3600));
                assert!(detail.as_deref().unwrap_or("").contains("limit reached"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn unauthorized_maps_to_unauthorized_variant() {
        let base = mock_server::spawn(
            move |_m, _p, _h, _b| mock_server::err(401, r#"{"detail":"Not authenticated"}"#, &[]),
            1,
        );
        let client = ScanClient::new(&base);
        let err = client.authed_scan("x", None, "bad_key").unwrap_err();
        assert!(matches!(err, ScanError::Unauthorized { .. }));
    }

    #[test]
    fn server_error_maps_to_server_error() {
        // 5xx are retried (see RETRY_BACKOFF_MS) so serve one socket
        // per attempt (initial + 3 retries = 4 total).
        let base = mock_server::spawn(
            move |_m, _p, _h, _b| mock_server::err(503, r#"{"detail":"Redis unavailable"}"#, &[]),
            4,
        );
        let client = ScanClient::new(&base);
        let err = client.preview_scan("x", None).unwrap_err();
        match err {
            ScanError::ServerError {
                status: 503,
                detail,
            } => {
                assert!(detail.as_deref().unwrap_or("").contains("Redis"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn network_failure_maps_to_network() {
        use std::net::TcpListener;
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = ScanClient::with_timeout(format!("http://{addr}"), Duration::from_millis(500));
        let err = client.preview_scan("x", None).unwrap_err();
        assert!(matches!(err, ScanError::Network(_)), "got: {err:?}");
    }

    #[test]
    fn malformed_2xx_body_flagged() {
        let base = mock_server::spawn(
            move |_m, _p, _h, _b| mock_server::ok("not json at all — server had a stroke"),
            1,
        );
        let client = ScanClient::new(&base);
        let err = client.preview_scan("x", None).unwrap_err();
        match err {
            ScanError::Malformed {
                status: 200,
                snippet,
                ..
            } => {
                assert!(snippet.contains("not json"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn retry_recovers_from_transient_5xx() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        // First two calls return 503; third returns 200. Verifies the
        // retry loop actually walks the backoff schedule and returns
        // the eventual success rather than the first transient error.
        let base = mock_server::spawn(
            move |_m, _p, _h, _b| {
                let n = calls2.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    mock_server::err(503, r#"{"detail":"transient"}"#, &[])
                } else {
                    mock_server::ok(r#"{"scan_id":"ok","findings":[]}"#)
                }
            },
            3,
        );
        let client = ScanClient::new(&base);
        let resp = client.preview_scan("x", None).unwrap();
        assert_eq!(resp.scan_id.as_deref(), Some("ok"));
        assert_eq!(calls.load(Ordering::SeqCst), 3, "should retry twice");
    }

    #[test]
    fn retry_does_not_kick_in_for_4xx() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        // 401 is a deterministic auth failure — retrying wastes time
        // and never changes the outcome, so we must NOT retry.
        let base = mock_server::spawn(
            move |_m, _p, _h, _b| {
                calls2.fetch_add(1, Ordering::SeqCst);
                mock_server::err(401, r#"{"detail":"nope"}"#, &[])
            },
            3,
        );
        let client = ScanClient::new(&base);
        let err = client.authed_scan("x", None, "bad").unwrap_err();
        assert!(matches!(err, ScanError::Unauthorized { .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "4xx must not be retried");
    }

    #[test]
    fn retry_does_not_kick_in_for_429() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        // 429 with Retry-After means "come back in N seconds"; the
        // retry loop's ~2.6s window would still burn quota without
        // giving the reset window a chance to elapse.
        let base = mock_server::spawn(
            move |_m, _p, _h, _b| {
                calls2.fetch_add(1, Ordering::SeqCst);
                mock_server::err(429, r#"{"detail":"quota"}"#, &[("Retry-After", "60")])
            },
            3,
        );
        let client = ScanClient::new(&base);
        let err = client.preview_scan("x", None).unwrap_err();
        assert!(matches!(err, ScanError::RateLimited { .. }));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "429 must not be retried");
    }

    #[test]
    fn unknown_server_fields_do_not_break_parse() {
        let body = r#"{
            "scan_id":"a",
            "findings":[{"label":"Bootloader","value":"U-Boot","brand_new_finding_field":"lorem"}],
            "brand_new_top_level_field":{"nested":true}
        }"#;
        let base = mock_server::spawn(move |_m, _p, _h, _b| mock_server::ok(body), 1);
        let client = ScanClient::new(&base);
        let resp = client.preview_scan("x", None).unwrap();
        assert_eq!(resp.findings.len(), 1);
        assert!(resp.extra.contains_key("brand_new_top_level_field"));
        assert!(resp.findings[0]
            .extra
            .contains_key("brand_new_finding_field"));
    }
}
