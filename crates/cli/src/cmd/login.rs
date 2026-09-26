//! `bootintel login` — browser-approved terminal login.
//!
//! Replaces `export BOOTINTEL_API_KEY=...`. That worked, but it made the
//! user paste a long-lived credential by hand, and the README had to teach
//! `read -s` so it stayed out of shell history and `ps auxe`.
//!
//! There is a second, less obvious reason this exists. The server gates
//! `x-api-key` auth at the Pro plan, because "API access" there means CI and
//! scripting. Applying that to interactive terminal use would have put the
//! applicability lookup, the one path usable on a client device under an NDA,
//! out of reach of the entry paid tier that the target segment actually buys.
//! A `bic_` terminal token resolves ahead of the API-key gate server-side, so
//! programmatic access stays Pro while `bootintel login` starts at Researcher.
//!
//! Shape is RFC 8628. We print a link with the code already in it so the
//! normal path is one click, and print the code separately so the user can
//! check it against what the browser shows. That comparison is the only thing
//! standing between this flow and a malicious local process getting its own
//! login approved, so the wording asks for it explicitly.
//!
//! Exit codes follow the sysexits convention used by `whoami`:
//!   0  — authorized, token saved
//!  69  — EX_UNAVAILABLE — network failure
//!  73  — EX_CANTCREAT — authorized but the token could not be persisted
//!  77  — EX_NOPERM — the request expired or was refused

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serde::Deserialize;
use std::io::{self, Write};
use std::time::{Duration, Instant};

const EX_UNAVAILABLE: i32 = 69;
const EX_CANTCREAT: i32 = 73;
const EX_NOPERM: i32 = 77;

/// Floor on the server-suggested poll interval. Stops a bad `interval`
/// turning the CLI into a hot loop against the auth endpoint.
const MIN_POLL_SECONDS: u64 = 2;
// Enforced at compile time rather than in a test: lowering this below 2
// would hammer the auth endpoint, and a runtime assertion on a constant is
// something clippy rightly rejects.
const _: () = assert!(MIN_POLL_SECONDS >= 2);
/// Ceiling on total wait, independent of the server's `expires_in`, so a
/// forgotten terminal does not poll indefinitely.
const MAX_WAIT: Duration = Duration::from_secs(15 * 60);
/// Transient poll failures tolerated before giving up. A long poll outliving
/// keep-alive is normal; a network that is actually gone is not.
const MAX_TRANSIENT_RETRIES: u32 = 20;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Override the API base URL (or $BOOTINTEL_API_BASE, or the
    /// config file's api_base).
    #[arg(long)]
    pub api_base: Option<String>,

    /// Label shown on the approval page, e.g. the machine name.
    #[arg(long)]
    pub label: Option<String>,

    /// Print the URL instead of trying to open a browser.
    #[arg(long)]
    pub no_browser: bool,

    /// Print the token instead of saving it to the config file.
    /// For throwaway shells and CI debugging; prefer the default.
    #[arg(long)]
    pub print_token: bool,
}

#[derive(Deserialize)]
struct StartResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    #[serde(default)]
    interval: u64,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct ErrBody {
    #[serde(default)]
    detail: Option<String>,
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout_read(Duration::from_secs(30))
        .build()
}

fn detail_of(resp: ureq::Response, fallback: &str) -> String {
    resp.into_json::<ErrBody>()
        .ok()
        .and_then(|b| b.detail)
        .unwrap_or_else(|| fallback.to_string())
}

pub fn run(args: Args) -> Result<()> {
    let base = crate::config::resolve_api_base(args.api_base.as_deref());
    let code = login(&args, &base)?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn login(args: &Args, api_base: &str) -> Result<i32> {
    let start_url = crate::api::endpoints::device_start_url(api_base);
    let token_url = crate::api::endpoints::device_token_url(api_base);
    let http = agent();

    let body = ureq::json!({ "label": args.label });
    let start: StartResponse = match http.post(&start_url).send_json(body) {
        Ok(r) => r
            .into_json()
            .context("malformed response from the login endpoint")?,
        Err(ureq::Error::Status(code, resp)) => {
            eprintln!(
                "bootintel: could not start a login ({}): {}",
                code,
                detail_of(resp, "unexpected server response")
            );
            return Ok(EX_UNAVAILABLE);
        }
        Err(ureq::Error::Transport(t)) => {
            eprintln!("bootintel: could not reach {}: {}", api_base, t);
            eprintln!(
                "       Local analysis needs no account: `bootintel scan <log>` works offline."
            );
            return Ok(EX_UNAVAILABLE);
        }
    };

    let link = start
        .verification_uri_complete
        .clone()
        .unwrap_or_else(|| start.verification_uri.clone());

    println!("Approve this terminal at:\n  {link}\n");
    println!("Your code is  {}", start.user_code);
    println!("Check it matches the code the page shows before approving.\n");
    if start.expires_in > 0 {
        println!("The code expires in {} minutes.", start.expires_in / 60);
    }
    io::stdout().flush().ok();

    if !args.no_browser {
        // Best effort. A headless box or an SSH session has no browser and
        // that is fine: the link is already printed above.
        let _ = open_in_browser(&link);
    }

    let interval = Duration::from_secs(start.interval.max(MIN_POLL_SECONDS));
    let began = Instant::now();
    let mut transient: u32 = 0;
    println!("Waiting for approval...");

    loop {
        if began.elapsed() > MAX_WAIT {
            eprintln!("bootintel: gave up waiting. Run `bootintel login` again.");
            return Ok(EX_NOPERM);
        }
        std::thread::sleep(interval);

        let payload = ureq::json!({ "device_code": start.device_code });
        match http.post(&token_url).send_json(payload) {
            Ok(r) => {
                let parsed: TokenResponse = r
                    .into_json()
                    .context("malformed response while collecting the token")?;
                if parsed.status == "authorization_pending" {
                    continue;
                }
                let token = match parsed.token {
                    Some(t) if !t.is_empty() => t,
                    _ => {
                        eprintln!(
                            "bootintel: server reported '{}' with no token.",
                            parsed.status
                        );
                        return Ok(EX_NOPERM);
                    }
                };
                return finish(token, parsed.expires_at, args.print_token);
            }
            Err(ureq::Error::Status(code, resp)) => {
                let detail = detail_of(resp, "login failed");
                // 410 expired, 409 already used, 404 unknown. None are
                // retryable, so say which and stop rather than spinning.
                eprintln!("bootintel: {detail} ({code})");
                return Ok(EX_NOPERM);
            }
            Err(ureq::Error::Transport(t)) => {
                // A reset mid-wait is routine, not a problem: a long poll
                // outlives keep-alive and the connection gets recycled.
                // Observed on the very first live run of this command, where
                // the retry worked and the warning was the only thing that
                // looked wrong. So it is retried silently and only surfaced
                // under -v, where someone is actually debugging.
                transient += 1;
                crate::vinfo!("login poll retry {transient}: {t}");
                if transient > MAX_TRANSIENT_RETRIES {
                    eprintln!("bootintel: lost contact with {api_base} while waiting ({t}).");
                    return Ok(EX_UNAVAILABLE);
                }
                continue;
            }
        }
    }
}

fn finish(token: String, expires_at: Option<String>, print_only: bool) -> Result<i32> {
    if print_only {
        println!("{token}");
        return Ok(0);
    }
    match crate::config::set_key("api_key", &token) {
        Ok(path) => {
            let tail = token
                .chars()
                .rev()
                .take(4)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>();
            println!("Signed in. Token ...{tail} saved to {}", path.display());
            if let Some(exp) = expires_at {
                println!("It expires {exp}. Run `bootintel login` again after that.");
            }
            println!("Revoke it any time from your account page.");
            Ok(0)
        }
        Err(e) => {
            // Authorized but unsaved. Hand the token over rather than
            // stranding the user with a consumed, uncollectable login.
            eprintln!("bootintel: signed in, but could not write the config file: {e:#}");
            eprintln!("       Set it for this shell instead:");
            eprintln!("         export BOOTINTEL_API_KEY={token}");
            Ok(EX_CANTCREAT)
        }
    }
}

#[cfg(target_os = "macos")]
fn open_in_browser(url: &str) -> std::io::Result<()> {
    std::process::Command::new("open")
        .arg(url)
        .status()
        .map(|_| ())
}

#[cfg(target_os = "windows")]
fn open_in_browser(url: &str) -> std::io::Result<()> {
    std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .status()
        .map(|_| ())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_in_browser(url: &str) -> std::io::Result<()> {
    std::process::Command::new("xdg-open")
        .arg(url)
        .status()
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the interval computation in `login`. A server sending
    /// `interval: 0`, or omitting it, must not produce a hot loop against
    /// the auth endpoint.
    fn effective_interval(server_suggested: u64) -> Duration {
        Duration::from_secs(server_suggested.max(MIN_POLL_SECONDS))
    }

    #[test]
    fn poll_interval_has_a_floor() {
        assert_eq!(effective_interval(0), Duration::from_secs(MIN_POLL_SECONDS));
        assert_eq!(effective_interval(1), Duration::from_secs(MIN_POLL_SECONDS));
        assert_eq!(effective_interval(5), Duration::from_secs(5));
    }

    #[test]
    fn exit_codes_are_distinct_and_sysexits_shaped() {
        let codes = [EX_UNAVAILABLE, EX_CANTCREAT, EX_NOPERM];
        assert_eq!(
            codes.len(),
            codes.iter().collect::<std::collections::HashSet<_>>().len()
        );
        assert!(codes.iter().all(|c| (64..=78).contains(c)));
    }

    #[test]
    fn a_pending_status_is_not_treated_as_a_token() {
        let body: TokenResponse =
            serde_json::from_str(r#"{"status":"authorization_pending","interval":5}"#).unwrap();
        assert_eq!(body.status, "authorization_pending");
        assert!(body.token.is_none());
    }

    #[test]
    fn the_complete_link_is_preferred_but_optional() {
        let with: StartResponse = serde_json::from_str(
            r#"{"device_code":"d","user_code":"AAAA-BBBB","verification_uri":"https://x/auth/device","verification_uri_complete":"https://x/auth/device?code=AAAA-BBBB","interval":5,"expires_in":600}"#,
        ).unwrap();
        assert!(with.verification_uri_complete.unwrap().contains("code="));
        let without: StartResponse = serde_json::from_str(
            r#"{"device_code":"d","user_code":"AAAA-BBBB","verification_uri":"https://x/auth/device"}"#,
        ).unwrap();
        assert!(without.verification_uri_complete.is_none());
        assert_eq!(
            without.interval, 0,
            "absent interval falls back to the floor"
        );
    }
}
