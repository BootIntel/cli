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

// The integrity patterns, character-for-character from
// `api/analysis_engine/detectors/boot_integrity.py`, for the same reason as the
// session patterns above.
static RE_CHECKSUM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*Verifying Checksum\s*\.\.\.\s*(.*)$").unwrap());
static RE_FIT_HASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*Verifying Hash Integrity\s*\.\.\.\s*(.*)$").unwrap());
// Deliberately NOT `## Checking (hash|sign)`. U-Boot's ordinary FIT output is
// `## Checking hash(es) for FIT Image at ...`, so that pattern reported a
// verified SIGNATURE on every device using unsigned FIT hashes, which is the
// common case. No corpus log prints the line, which is why the bug survived
// review on the engine side.
static RE_FIT_SIG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)Verifying Signature\b").unwrap());
// An algorithm entry that means a signature rather than a digest. U-Boot prints
// `sha256,rsa2048:dev+ OK` when a signature node was checked.
static RE_SIG_ALGO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:rsa\d*|ecdsa\d*|pkcs1)").unwrap());
// Anchored to the whole line: a substring match on "Bad Magic Number" also
// catches `fsck.ext2: Bad magic number in super-block`, which is a filesystem
// complaint and produced a false high-severity finding on the engine side.
static RE_BAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(Bad Data Hash|Bad Header Checksum|Bad Magic Number|Bad Data CRC)\.?\s*$")
        .unwrap()
});
static RE_BAD_SIG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)signature check failed|Verifying Hash Integrity\s*\.\.\.\s*error").unwrap()
});
static RE_HAB_OFF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)hab fuse not enabled").unwrap());
static RE_HAB_ON: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)hab fuse (?:is )?enabled").unwrap());
static RE_UBIFS_UNAUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)UBIFS\s*\(([^)]*)\):\s*Mounting in unauthenticated mode").unwrap()
});
static RE_ENV_CRC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)bad CRC, using default environment").unwrap());
static RE_OK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bOK\b").unwrap());
static RE_ALGO_SPLIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[+,\s]+").unwrap());

/// What the bootloader actually DID about verifying the image it booted, as
/// opposed to what the environment says it is configured to do.
///
/// The distinction this type exists to preserve: a checksum is not a signature.
/// `Verifying Checksum ... OK` proves the image was not corrupt. Anyone who can
/// write the image can recompute the CRC, so it stops bit-rot, not an attacker.
/// Only a signature establishes that the image came from the signer, and on
/// i.MX none of it is enforced while the HAB fuse is unblown.
///
/// Unlike the engine, this does not raise findings for any of it: the Rust and
/// browser detector sets are pinned to the same 14 labels, and a fifteenth would
/// break that parity. The facts and the verdicts are what the two
/// implementations share.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BootIntegrity {
    /// `uimage_crc` or `fit_hash`.
    pub image_check: Option<String>,
    pub image_check_evidence: Option<String>,
    /// `passed`, `failed`, or `not_captured` when the check began but the
    /// capture lost its result. "The check ran" is a different claim from "the
    /// check passed".
    pub image_check_result: Option<String>,
    pub image_hash_algorithms: Vec<String>,
    pub image_signature_checked: bool,
    pub image_signature_evidence: Option<String>,
    pub image_check_failed: Option<String>,
    /// `not_enabled` or `enabled`.
    pub hab_fuse: Option<String>,
    pub hab_evidence: Option<String>,
    pub ubifs_unauthenticated: Option<String>,
    pub env_crc_failed: Option<String>,
}

/// First observation wins, so a later repeat cannot overwrite the evidence line
/// that justified the original claim. Mirrors the engine's `setdefault`.
fn keep_first(slot: &mut Option<String>, value: &str) {
    if slot.is_none() {
        *slot = Some(value.to_string());
    }
}

/// Read the verification a bootloader reported performing.
pub fn parse_integrity(log: &str) -> BootIntegrity {
    let mut bi = BootIntegrity::default();
    for raw in log.lines() {
        let line = raw.trim_end_matches(['\r', '\n']);
        let s = clip(line.trim(), 200);

        if let Some(caps) = RE_CHECKSUM.captures(line) {
            let result = caps[1].trim();
            keep_first(&mut bi.image_check, "uimage_crc");
            keep_first(&mut bi.image_check_evidence, &s);
            keep_first(
                &mut bi.image_check_result,
                if RE_OK.is_match(result) {
                    "passed"
                } else if result.is_empty() {
                    "not_captured"
                } else {
                    "failed"
                },
            );
            continue;
        }

        if let Some(caps) = RE_FIT_HASH.captures(line) {
            let tail = caps[1].trim();
            let algos: Vec<String> = RE_ALGO_SPLIT
                .split(tail)
                .filter(|a| !a.is_empty() && !RE_OK.is_match(a))
                .map(str::to_string)
                .collect();
            keep_first(&mut bi.image_check, "fit_hash");
            keep_first(&mut bi.image_check_evidence, &s);
            keep_first(
                &mut bi.image_check_result,
                if RE_OK.is_match(tail) {
                    "passed"
                } else {
                    "failed"
                },
            );
            if !algos.is_empty() {
                if bi.image_hash_algorithms.is_empty() {
                    bi.image_hash_algorithms = algos.clone();
                }
                if algos.iter().any(|a| RE_SIG_ALGO.is_match(a)) {
                    bi.image_signature_checked = true;
                    keep_first(&mut bi.image_signature_evidence, &s);
                }
            }
            continue;
        }

        if RE_FIT_SIG.is_match(line) {
            bi.image_signature_checked = true;
            keep_first(&mut bi.image_signature_evidence, &s);
            continue;
        }

        if RE_BAD.is_match(line) || RE_BAD_SIG.is_match(line) {
            keep_first(&mut bi.image_check_failed, &s);
            continue;
        }

        if RE_HAB_OFF.is_match(line) {
            keep_first(&mut bi.hab_fuse, "not_enabled");
            keep_first(&mut bi.hab_evidence, &s);
            continue;
        }
        if RE_HAB_ON.is_match(line) {
            keep_first(&mut bi.hab_fuse, "enabled");
            keep_first(&mut bi.hab_evidence, &s);
            continue;
        }

        if RE_ENV_CRC.is_match(line) {
            keep_first(&mut bi.env_crc_failed, &s);
            continue;
        }

        if let Some(caps) = RE_UBIFS_UNAUTH.captures(line) {
            keep_first(&mut bi.ubifs_unauthenticated, caps[1].trim());
        }
    }
    bi
}

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
pub fn verdict(s: &UbootSession, bi: &BootIntegrity) -> Vec<Verdict> {
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

    // Image verification, preferring what was observed over what was configured.
    //
    // One entry, never two. An earlier version emitted a speculative "unknown"
    // alongside an explicit verify=no and produced two contradictory verdicts
    // for one question; the same trap is here in a new form, because a capture
    // can carry BOTH verify=no and an observed checksum pass. Rather than
    // silently picking a winner, the entry reports the observation and names the
    // conflict.
    //
    // Read before the environment because none of it depends on a printenv
    // having been captured: bootintel-7 reaches a prompt, never dumps the
    // environment, and still reports `hab fuse not enabled`.
    let verify_off = matches!(
        s.env
            .get("verify")
            .map(|x| x.trim().to_ascii_lowercase())
            .as_deref(),
        Some("n") | Some("no") | Some("0") | Some("false")
    );
    let conflict = if verify_off {
        " The environment says verify=no, yet the bootloader still reported a check, so either \
         this capture predates that setting or a different boot path ran."
    } else {
        ""
    };
    let observed = bi.image_check.as_deref();
    let result = bi.image_check_result.as_deref();
    if bi.image_signature_checked {
        v(
            &mut out,
            "Image verification",
            "hardened",
            &format!(
                "A signature was checked before boot, which establishes that the image is the \
                    one the signer produced, not merely an uncorrupted one.{conflict}"
            ),
            bi.image_signature_evidence
                .as_deref()
                .unwrap_or("signature check observed"),
            "medium",
            Some(
                "Confirm the verifying key lives somewhere an attacker with flash write access \
                cannot replace it.",
            ),
        );
    } else if observed.is_some() && result == Some("passed") {
        let mechanism = if observed == Some("fit_hash") {
            let algos = if bi.image_hash_algorithms.is_empty() {
                "unspecified".to_string()
            } else {
                bi.image_hash_algorithms.join(", ")
            };
            format!("a FIT hash ({algos})")
        } else {
            "a legacy uImage CRC".to_string()
        };
        v(
            &mut out,
            "Image verification",
            "confirmed",
            &format!(
                "The bootloader checked the image before booting it, using {mechanism}, and \
                    the check passed. That proves the image was not corrupt. It is not a \
                    signature: anyone who can write the image can recompute the checksum, so this \
                    stops bit-rot rather than an attacker.{conflict}"
            ),
            bi.image_check_evidence.as_deref().unwrap_or(""),
            "medium",
            Some(
                "Move to signed FIT images (CONFIG_FIT_SIGNATURE) so a deliberate modification is \
                detected and not just a corrupt one.",
            ),
        );
    } else if observed.is_some() && result == Some("not_captured") {
        v(
            &mut out,
            "Image verification",
            "unknown",
            &format!(
                "The bootloader began an image check but its result is not in the capture, so \
                    whether it passed is unknown.{conflict}"
            ),
            bi.image_check_evidence.as_deref().unwrap_or(""),
            "info",
            None,
        );
    } else if verify_off {
        v(
            &mut out,
            "Image verification",
            "exposed",
            "verify is disabled, so U-Boot will not check image checksums before booting.",
            &format!(
                "verify={}",
                s.env.get("verify").map(String::as_str).unwrap_or("")
            ),
            "high",
            Some("Set verify=yes, and prefer signed FIT images over checksums."),
        );
    }

    // The anchor. On i.MX none of the above is enforced while the fuse is unblown.
    if bi.hab_fuse.as_deref() == Some("not_enabled") {
        v(
            &mut out,
            "Secure boot anchor",
            "exposed",
            "The SoC reports the HAB fuse is not enabled, so the boot ROM will run an unsigned \
           image. Whatever the bootloader does about checksums afterwards is advisory: the chain \
           has no anchor.",
            bi.hab_evidence.as_deref().unwrap_or("hab fuse not enabled"),
            "high",
            Some(
                "Blow the HAB fuse and close the device only after a signed image is confirmed to \
                boot, since the operation is irreversible.",
            ),
        );
    }

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
        // Only speculate when the capture contains no observation at all. The
        // whole point of reading the boot output is to stop guessing here.
        if boots_image && !verify_set && !cmd.contains("verify") && observed.is_none() {
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
/// Everything one capture establishes about the boot chain.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub session: UbootSession,
    pub integrity: BootIntegrity,
    pub verdicts: Vec<Verdict>,
}

/// Parse and decide in one call.
///
/// This replaced a `(UbootSession, Vec<Verdict>)` tuple when integrity reading
/// landed: a breaking change to a published crate, which under the policy at the
/// top of CHANGELOG.md moves the minor version pre-1.0. The alternative was a
/// second name for the same operation, and two entry points differing only in
/// how much they tell you is worse for whoever reads this next.
pub fn assess(log: &str) -> Assessment {
    let session = parse_session(log);
    let integrity = parse_integrity(log);
    let verdicts = verdict(&session, &integrity);
    Assessment {
        session,
        integrity,
        verdicts,
    }
}
