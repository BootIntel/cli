//! U-Boot interactive session: environment, and the boot-chain verdict.
//!
//! A port of `api/analysis_engine/detectors/uboot_env.py` and
//! `_build_boot_chain_verdict` in `engine.py`. It runs LOCALLY on purpose.
//!
//! Applicability lookup stays server-side because the curated CVE ruleset is
//! the asset that compounds. This is the opposite case: "bootdelay above zero
//! means the prompt is reachable" is domain knowledge any practitioner
//! already has, so shipping it costs nothing, and a U-Boot environment is the
//! single most sensitive thing in a capture (ipaddr, serverip, ethaddr, TFTP
//! hosts, a client's internal addressing). Requiring an upload to learn what
//! the environment permits would put this out of reach of exactly the people
//! it is for.
//!
//! Two implementations of the same rules can drift, which is the problem the
//! detector-parity work just fixed. `tests/boot_chain_parity.rs` pins this one
//! against a shared expectation file that the Python side asserts against too.
//!
//! NOT a detector. Adding a label would break the 14-detector parity with the
//! browser library, so this is a separate entry point.

use std::collections::BTreeMap;

/// One decision about the boot chain, with the variable it was read from.
///
/// A consultant has to defend the answer in a client report rather than quote
/// a tool, so `evidence` is not optional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub title: String,
    /// `exposed`, `hardened`, `confirmed`, or `unknown`. Never a bare boolean:
    /// U-Boot only prints what is set, so absence is unknown, not good news.
    pub state: String,
    pub detail: String,
    pub evidence: String,
    pub severity: String,
    pub remediation: Option<String>,
}

/// What a capture proves about an interactive U-Boot session.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UbootSession {
    pub reached: bool,
    pub evidence: String,
    /// BTreeMap so ordering is deterministic, which the parity test needs.
    pub env: BTreeMap<String, String>,
    pub env_used_bytes: Option<u64>,
    pub env_total_bytes: Option<u64>,
}

use std::sync::LazyLock;

use regex::Regex;

// The three patterns below are character-for-character the ones in
// `api/analysis_engine/detectors/uboot_env.py`. Keeping them literally
// identical is cheaper than reasoning about whether two hand-written
// tokenisers agree.
//
// U-Boot's prompt. `=>` is the default; vendors commonly rebrand it.
static RE_PROMPT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(?:=>|u-?boot\s*[>#]|[\w.-]+\s*=>)\s*(\S.*)?$").unwrap());

// The definitive marker that a printenv dump just happened: U-Boot prints
// this as the last line of `printenv`.
static RE_ENV_SIZE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*Environment size:\s*(\d+)\s*/\s*(\d+)\s*bytes").unwrap());

// An environment entry. U-Boot allows almost anything in a value, including
// spaces and semicolons, so the key is what must be constrained.
static RE_ENV_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([A-Za-z_][A-Za-z0-9_.]{0,63})=(.*)$").unwrap());

/// Truncate to `max` CHARACTERS, mirroring Python's `s[:max]`.
///
/// `String::truncate` counts bytes and panics mid-codepoint, and a capture is
/// arbitrary bytes off a serial line, so this is not hypothetical.
fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Parse a capture for an interactive session. Conservative by construction:
/// `KEY=value` lines are everywhere in a boot log (kernel command line, vendor
/// config dumps), so variables are only committed once the capture proves it
/// holds a real dump, and only inside a block delimited by U-Boot's own
/// markers.
///
/// `bdinfo` and `mtdparts` parsing is deliberately not ported: nothing in the
/// verdict reads them, and an unused second implementation is pure drift risk.
pub fn parse_session(log: &str) -> UbootSession {
    let mut s = UbootSession::default();
    let mut in_env_dump = false;
    // Buffered against the chance an `Environment size:` line is coming.
    // Bounded, and discarded the moment the run of KEY=value lines breaks, so
    // ordinary log noise cannot accumulate into a fake environment: a real
    // dump is one contiguous block.
    let mut candidates: Vec<(String, String)> = Vec::new();
    let mut continuations = 0usize;

    fn note(s: &mut UbootSession, line: &str) {
        if !s.reached {
            s.reached = true;
            s.evidence = clip(line.trim(), 200);
        }
    }

    for raw in log.lines() {
        let line = raw.trim_end_matches(['\r', '\n']);

        // The prompt itself. Also the boundary that closes an env dump:
        // anything after a fresh prompt is a new command's output.
        if let Some(caps) = RE_PROMPT.captures(line) {
            note(&mut s, line);
            let typed = caps
                .get(1)
                .map(|m| m.as_str().trim().to_ascii_lowercase())
                .unwrap_or_default();
            in_env_dump = ["printenv", "print", "env print"]
                .iter()
                .any(|p| typed.starts_with(p));
            continue;
        }

        if let Some(caps) = RE_ENV_SIZE.captures(line) {
            // The retroactive case, and the common one. U-Boot prints this
            // line LAST, so a capture that starts mid-session, or whose prompt
            // line was eaten, still proves the block just above was an
            // environment.
            note(&mut s, line);
            s.env_used_bytes = caps[1].parse().ok();
            s.env_total_bytes = caps[2].parse().ok();
            in_env_dump = false;
            for (k, val) in candidates.drain(..) {
                s.env.entry(k).or_insert(val);
            }
            continuations = 0;
            continue;
        }

        if let Some(caps) = RE_ENV_LINE.captures(line) {
            let key = caps[1].to_string();
            let value = clip(caps[2].trim(), 1024);
            if in_env_dump {
                // First write wins: U-Boot prints each variable once, and a
                // later identical-looking line is more likely log noise than
                // a redefine.
                s.env.entry(key).or_insert(value);
            } else {
                continuations = 0;
                if candidates.len() < 256 {
                    candidates.push((key, value));
                }
            }
            continue;
        }

        if line.trim().is_empty() {
            continue;
        }

        // A long U-Boot value wraps in a terminal capture, so the continuation
        // has no `KEY=`. Treating it as a boundary discarded whole
        // environments. Append instead, bounded: a couple of wrapped lines is
        // normal, a long run means the dump ended and this is ordinary output.
        if !candidates.is_empty() && continuations < 3 {
            continuations += 1;
            let last = candidates.last_mut().expect("checked non-empty");
            last.1 = clip(&(last.1.clone() + line.trim()), 1024);
            continue;
        }
        candidates.clear();
        continuations = 0;
    }
    s
}

fn v(
    out: &mut Vec<Verdict>,
    title: &str,
    state: &str,
    detail: &str,
    evidence: &str,
    severity: &str,
    remediation: Option<&str>,
) {
    out.push(Verdict {
        title: title.to_string(),
        state: state.to_string(),
        detail: detail.to_string(),
        evidence: evidence.to_string(),
        severity: severity.to_string(),
        remediation: remediation.map(str::to_string),
    });
}

/// Turn a pulled environment into decisions, not observations.
///
/// The boot log can say autoboot looks interruptible. The environment says
/// what happens when you interrupt it, and whether you can change what boots.
pub fn verdict(s: &UbootSession) -> Vec<Verdict> {
    let mut out = Vec::new();
    if !s.reached {
        return out;
    }

    v(
        &mut out,
        "U-Boot shell reached",
        "confirmed",
        "An operator interrupted autoboot and got a command prompt. Everything below \
       was read from the device, not inferred from its boot output.",
        if s.evidence.is_empty() {
            "U-Boot prompt"
        } else {
            &s.evidence
        },
        "high",
        Some(
            "Set bootdelay=-1 and build with CONFIG_AUTOBOOT_KEYED so the prompt needs a password.",
        ),
    );

    if s.env.is_empty() {
        v(
            &mut out,
            "Environment not captured",
            "unknown",
            "The shell was reached but no printenv output was captured, so the boot \
           chain below could not be assessed. Run `printenv` at the prompt.",
            &s.evidence,
            "info",
            None,
        );
        return out;
    }

    match s.env.get("bootdelay") {
        Some(raw) => {
            let ev = format!("bootdelay={raw}");
            match raw.trim().parse::<i64>() {
                Err(_) => v(
                    &mut out,
                    "Autoboot delay",
                    "unknown",
                    &format!("bootdelay is not a number: {raw:?}."),
                    &ev,
                    "info",
                    None,
                ),
                Ok(d) if d < 0 => v(
                    &mut out,
                    "Autoboot delay",
                    "hardened",
                    "bootdelay is negative, so autoboot cannot be interrupted by a keypress. \
                     The prompt was still reached, so something else allowed it.",
                    &ev,
                    "medium",
                    None,
                ),
                Ok(0) => v(
                    &mut out,
                    "Autoboot delay",
                    "hardened",
                    "bootdelay is 0: no interrupt window. The prompt was still reached, so \
                     something else allowed it.",
                    &ev,
                    "medium",
                    None,
                ),
                Ok(d) => v(
                    &mut out,
                    "Autoboot delay",
                    "exposed",
                    &format!(
                        "bootdelay is {d}s, so anyone with console access gets {d}s to \
                              take the prompt on every boot."
                    ),
                    &ev,
                    "high",
                    Some("Set bootdelay=-1 and require a password (CONFIG_AUTOBOOT_KEYED)."),
                ),
            }
        }
        None => v(
            &mut out,
            "Autoboot delay",
            "unknown",
            "bootdelay is not set in the environment, so the built-in default applies \
             and cannot be read from here.",
            "bootdelay absent",
            "info",
            None,
        ),
    }

    if let Some(cmd) = s.env.get("bootcmd") {
        let short: String = cmd.chars().take(160).collect();
        v(
            &mut out,
            "Boot command",
            "exposed",
            "bootcmd is readable and, with the prompt reachable, settable. Whoever holds \
           the console decides what the device boots.",
            &format!("bootcmd={short}"),
            "high",
            Some(
                "Lock the environment (CONFIG_ENV_IS_NOWHERE or a signed env) and require a \
                password at the prompt.",
            ),
        );
        let verify_set = s.env.contains_key("verify");
        let boots_image = ["bootm", "bootz", "booti"].iter().any(|t| cmd.contains(t));
        if boots_image && !verify_set && !cmd.contains("verify") {
            v(
                &mut out,
                "Image verification",
                "unknown",
                "bootcmd boots an image without a visible verification step. That is not \
               proof verification is absent: a FIT signature check can be implicit in \
               the image. Confirm with the boot output of an actual `bootm`.",
                &format!("bootcmd={short}"),
                "info",
                None,
            );
        }
    }

    if let Some(val) = s.env.get("verify") {
        if matches!(
            val.trim().to_ascii_lowercase().as_str(),
            "n" | "no" | "0" | "false"
        ) {
            v(
                &mut out,
                "Image verification",
                "exposed",
                "verify is disabled, so U-Boot will not check image checksums before booting.",
                &format!("verify={val}"),
                "high",
                Some("Set verify=yes, and prefer signed FIT images over checksums."),
            );
        }
    }

    if s.env.contains_key("ipaddr") && s.env.contains_key("serverip") {
        let parts: Vec<String> = ["ethaddr", "gatewayip", "ipaddr", "netmask", "serverip"]
            .iter()
            .filter_map(|k| s.env.get(*k).map(|val| format!("{k}={val}")))
            .collect();
        v(
            &mut out,
            "Network boot path",
            "exposed",
            "ipaddr and serverip are both set, so the bootloader is pre-configured to \
           fetch over the network. That is a route in as much as a recovery route out.",
            &parts.join(", "),
            "medium",
            Some("Clear ipaddr/serverip on production images unless netboot is required."),
        );
    }

    if let Some(args) = s.env.get("bootargs") {
        let short: String = args.chars().take(160).collect();
        let ev = format!("bootargs={short}");
        let debug = [
            ("init=/bin/sh", "a root shell as init"),
            ("init=/bin/bash", "a root shell as init"),
            ("single", "single-user mode"),
            ("rdinit=/bin/sh", "a root shell as rdinit"),
        ]
        .iter()
        .find(|(tok, _)| args.contains(tok))
        .map(|(_, what)| *what);
        match debug {
            Some(what) => v(
                &mut out,
                "Boot arguments",
                "exposed",
                &format!("bootargs already requests {what}."),
                &ev,
                "high",
                Some("Remove debug boot arguments from production images."),
            ),
            None => v(
                &mut out,
                "Boot arguments",
                "confirmed",
                "bootargs is readable and settable from the prompt, which is how a root \
                 shell is usually obtained on a board like this.",
                &ev,
                "medium",
                Some("Lock the environment so bootargs cannot be rewritten at the console."),
            ),
        }
    }

    if let (Some(used), Some(total)) = (s.env_used_bytes, s.env_total_bytes) {
        if total > 0 {
            v(
                &mut out,
                "Environment storage",
                "confirmed",
                &format!(
                    "The environment occupies {used} of {total} bytes of writable storage, so \
                        `saveenv` can persist a change across reboots."
                ),
                &format!("Environment size: {used}/{total} bytes"),
                "medium",
                Some("Build with a read-only or signed environment for production."),
            );
        }
    }
    out
}

/// Convenience: parse and decide in one call.
pub fn assess(log: &str) -> (UbootSession, Vec<Verdict>) {
    let s = parse_session(log);
    let verdicts = verdict(&s);
    (s, verdicts)
}
