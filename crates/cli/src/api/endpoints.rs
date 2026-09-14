//! URL builders for the bootintel.com API endpoints.
//!
//! Isolated from the client so tests can point at a local mock
//! (`http://127.0.0.1:NNNN`) without touching the real host.
//!
//! Path shape: production bootintel.com serves the analysis endpoints
//! under `/api/analysis/<verb>` (nginx adds the `/api` prefix in front
//! of the FastAPI routes). Self-hosted deployments that expose the
//! FastAPI directly without a proxy have the endpoints at
//! `/analysis/<verb>` — set `BOOTINTEL_API_PATH_PREFIX=/` (or empty)
//! for that shape. Default matches production.

/// Default API base URL. Overridable per-invocation via `--api-base`.
pub const DEFAULT_API_BASE: &str = "https://bootintel.com";

/// Default path prefix in front of the analysis routes. Overridable
/// via `BOOTINTEL_API_PATH_PREFIX` env var. Empty string / "/" both
/// mean "no prefix" (FastAPI-direct).
pub const DEFAULT_PATH_PREFIX: &str = "/api";
const PATH_PREFIX_ENV: &str = "BOOTINTEL_API_PATH_PREFIX";

fn path_prefix() -> String {
    match std::env::var(PATH_PREFIX_ENV).ok() {
        Some(s) if s.is_empty() || s == "/" => String::new(),
        Some(s) => format!("/{}", s.trim_matches('/')),
        None => DEFAULT_PATH_PREFIX.to_string(),
    }
}

pub fn preview_url(base: &str) -> String {
    format!(
        "{}{}/analysis/preview",
        base.trim_end_matches('/'),
        path_prefix()
    )
}

pub fn scan_url(base: &str) -> String {
    format!(
        "{}{}/analysis/scan",
        base.trim_end_matches('/'),
        path_prefix()
    )
}

/// Result of `check_plaintext_base`. Callers use this to decide whether
/// to abort (auth path) or emit a warning (preview path).
#[derive(Debug, PartialEq, Eq)]
pub enum PlaintextCheck {
    /// Base is https:// (or a loopback http://, e.g. developer's local
    /// mock server). Safe to send credentials over.
    Ok,
    /// Base is http:// pointing at a non-loopback host. Sending an API
    /// key over this exposes the credential to any on-path observer.
    UnsafePlaintext,
}

/// Classify a resolved `--api-base` URL for plaintext-transport risk.
///
/// `http://` is treated as unsafe unless the host component is a loopback
/// address (`127.0.0.1`, `::1`, or literal `localhost`). Anything else
/// — including a lack of scheme — is treated as unsafe by the caller
/// (fail closed).
pub fn check_plaintext_base(base: &str) -> PlaintextCheck {
    // Lowercased scheme check keeps HTTP:// / HttPS:// consistent with
    // curl / browsers (URL schemes are case-insensitive per RFC 3986).
    let lower = base.trim().to_ascii_lowercase();
    if lower.starts_with("https://") {
        return PlaintextCheck::Ok;
    }
    if let Some(rest) = lower.strip_prefix("http://") {
        // Extract host component. If it's a bracketed IPv6 literal
        // ([::1]:8000/…), take everything between the brackets and
        // ignore any ':' inside; otherwise stop at the first '/',
        // ':', '?', or '#'.
        let host: &str = if let Some(inner) = rest.strip_prefix('[') {
            inner.split(']').next().unwrap_or("")
        } else {
            let end = rest.find(['/', ':', '?', '#']).unwrap_or(rest.len());
            &rest[..end]
        };
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return PlaintextCheck::Ok;
        }
        return PlaintextCheck::UnsafePlaintext;
    }
    // No scheme or an unrecognized one — fail closed.
    PlaintextCheck::UnsafePlaintext
}

/// Enforce the plaintext-transport policy for a resolved `--api-base`.
///
/// Behavior:
///   * https:// or loopback http:// → Ok (no warning, no bail)
///   * public http:// **and** we're about to send a credential →
///     bail with an actionable error (Result::Err)
///   * public http:// **without** a credential (preview mode, no key) →
///     emit a stderr warning and return Ok
///
/// Extracted so scan/analyze/… don't each open-code the same 8-line
/// branch. Centralizing it also means a future policy tweak (e.g.
/// allow-listing extra "safe" schemes) lands in one place.
pub fn require_safe_transport(base: &str, sending_credential: bool) -> anyhow::Result<()> {
    if check_plaintext_base(base) == PlaintextCheck::Ok {
        return Ok(());
    }
    if sending_credential {
        anyhow::bail!(
            "refusing to send API key over plaintext http:// (base: {base}). Use https:// or a loopback address."
        );
    }
    eprintln!(
        "warning: --api-base is http:// ({base}); traffic is unencrypted. Use https:// for anything but a local mock."
    );
    Ok(())
}

#[cfg(test)]
mod plaintext_tests {
    use super::*;

    #[test]
    fn https_is_safe() {
        assert_eq!(
            check_plaintext_base("https://bootintel.com"),
            PlaintextCheck::Ok
        );
        assert_eq!(
            check_plaintext_base("HTTPS://Bootintel.com/"),
            PlaintextCheck::Ok
        );
    }

    #[test]
    fn http_loopback_is_safe() {
        assert_eq!(
            check_plaintext_base("http://127.0.0.1:8000"),
            PlaintextCheck::Ok
        );
        assert_eq!(
            check_plaintext_base("http://localhost:8080/foo"),
            PlaintextCheck::Ok
        );
        assert_eq!(
            check_plaintext_base("http://[::1]:8000"),
            PlaintextCheck::Ok
        );
    }

    #[test]
    fn http_public_is_unsafe() {
        assert_eq!(
            check_plaintext_base("http://staging.example.com"),
            PlaintextCheck::UnsafePlaintext
        );
        assert_eq!(
            check_plaintext_base("http://10.0.0.5:9000/api"),
            PlaintextCheck::UnsafePlaintext
        );
    }

    #[test]
    fn require_safe_transport_ok_on_https() {
        assert!(require_safe_transport("https://bootintel.com", true).is_ok());
        assert!(require_safe_transport("https://bootintel.com", false).is_ok());
    }

    #[test]
    fn require_safe_transport_bails_on_plaintext_with_credential() {
        let e = require_safe_transport("http://staging.example.com", true).unwrap_err();
        let s = e.to_string();
        assert!(s.contains("plaintext"), "got: {s}");
    }

    #[test]
    fn require_safe_transport_warns_on_plaintext_without_credential() {
        // Preview / no key: still Ok (warning goes to stderr, not checked).
        assert!(require_safe_transport("http://staging.example.com", false).is_ok());
    }

    #[test]
    fn missing_scheme_is_unsafe() {
        // A caller that types `bootintel.com` (no scheme) is asking
        // for trouble. Fail closed rather than guess https.
        assert_eq!(
            check_plaintext_base("bootintel.com"),
            PlaintextCheck::UnsafePlaintext
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::env_lock;

    // Serialize env-var mutations across tests via the shared
    // process-wide env_lock() so this test module can't race with
    // config/history/output tests that also touch env vars.
    fn with_prefix<F: FnOnce()>(prefix: Option<&str>, f: F) {
        let _g = env_lock();
        let saved = std::env::var(PATH_PREFIX_ENV).ok();
        match prefix {
            Some(v) => std::env::set_var(PATH_PREFIX_ENV, v),
            None => std::env::remove_var(PATH_PREFIX_ENV),
        }
        f();
        match saved {
            Some(v) => std::env::set_var(PATH_PREFIX_ENV, v),
            None => std::env::remove_var(PATH_PREFIX_ENV),
        }
    }

    #[test]
    fn default_prefix_matches_production() {
        with_prefix(None, || {
            assert_eq!(
                preview_url("https://bootintel.com"),
                "https://bootintel.com/api/analysis/preview"
            );
            assert_eq!(
                scan_url("https://bootintel.com/"),
                "https://bootintel.com/api/analysis/scan"
            );
        });
    }

    #[test]
    fn empty_prefix_env_drops_the_api_prefix() {
        with_prefix(Some(""), || {
            assert_eq!(
                preview_url("http://127.0.0.1:8000"),
                "http://127.0.0.1:8000/analysis/preview"
            );
        });
        with_prefix(Some("/"), || {
            assert_eq!(
                preview_url("http://127.0.0.1:8000"),
                "http://127.0.0.1:8000/analysis/preview"
            );
        });
    }

    #[test]
    fn custom_prefix_is_respected() {
        with_prefix(Some("v2"), || {
            assert_eq!(
                preview_url("https://staging.example.com"),
                "https://staging.example.com/v2/analysis/preview"
            );
        });
        with_prefix(Some("/v2/"), || {
            assert_eq!(
                scan_url("https://staging.example.com"),
                "https://staging.example.com/v2/analysis/scan"
            );
        });
    }
}
