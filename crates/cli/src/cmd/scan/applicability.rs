//! `scan --applicability` — CVE applicability without sending the boot log.
//!
//! A consultant cannot upload a client's boot log. That is a contract matter
//! rather than a preference, and it is the single objection that keeps
//! BootIntel out of the segment it fits best. Shipping the curated ruleset
//! down to the client instead would hand over the one asset that compounds.
//!
//! So neither travels. The detectors run locally, exactly as they do for a
//! plain `scan`, and only the component inventory goes up: product names and
//! version strings. The server answers the expensive question, which is
//! applicability, not identification.
//!
//! What CANNOT be transmitted by this path, structurally rather than by
//! policy: hostnames, internal addressing, MACs, serials, keys, kernel
//! command lines, partition labels, anything a boot log carries beyond a
//! version number. The payload is built from a fixed map of three detector
//! labels to three product names, and every value is re-validated before it
//! leaves. `--dry-run` prints the exact bytes so a consultant can show a
//! client what leaves the machine; that is a headline capability here, not a
//! debugging aid.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

use super::Args;
use bootintel_detectors::Finding;

/// sysexits.h EX_UNAVAILABLE.
const EX_UNAVAILABLE: i32 = 69;
/// sysexits.h EX_NOPERM.
const EX_NOPERM: i32 = 77;
/// sysexits.h EX_DATAERR.
const EX_DATAERR: i32 = 65;

/// Mirrors the server's limits so a malformed payload fails here, instantly
/// and locally, instead of after a round trip. Server rejects with 422 on any
/// of these; if it ever does, that is a bug in this mapping, not user error.
const MAX_INVENTORY_ITEMS: usize = 64;
const MAX_COMPONENT_NAME: usize = 80;
const MAX_COMPONENT_VERSION: usize = 40;

/// The only detector labels that yield a component the catalog can match, and
/// the exact `name` the server expects for each. Translation is required: the
/// server matches on lowercase product names, and sending "Bootloader" or
/// "U-Boot 2020.10" returns nothing while looking like a server fault.
///
/// Every other detector is deliberately absent. CPU architecture, init
/// system, device family, flash layout, ROM identifier, firmware SDK, runtime
/// firmware and the two exposure detectors are not CVE-tracked products, and
/// inventing entries for them would only produce noise.
const LABEL_TO_PRODUCT: &[(&str, &str)] = &[
    ("Bootloader", "u-boot"),
    ("Kernel", "linux"),
    ("Userland", "busybox"),
];

#[derive(Serialize, Debug, PartialEq, Eq)]
pub(super) struct Component {
    pub name: String,
    pub version: String,
}

#[derive(Serialize)]
struct Request<'a> {
    inventory: &'a [Component],
}

#[derive(Deserialize)]
struct Response {
    #[serde(default)]
    inventory: Vec<ResponseComponent>,
    #[serde(default)]
    findings: Vec<Verdict>,
    #[serde(default)]
    log_received: Option<bool>,
}

#[derive(Deserialize)]
struct ResponseComponent {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    cve_count: Option<u32>,
}

#[derive(Deserialize)]
struct Verdict {
    #[serde(default)]
    cve_id: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    match_basis: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    remediation: Option<String>,
}

#[derive(Deserialize)]
struct ErrBody {
    #[serde(default)]
    detail: Option<String>,
}

/// Split a detector value like "U-Boot 2020.10" into its version part.
///
/// Takes the LAST whitespace-separated token, because product names contain
/// spaces ("Espressif ROM bootloader") while versions do not.
fn version_of(value: &str) -> Option<&str> {
    let tok = value.split_whitespace().next_back()?;
    // A version has to start with a digit to be range-matched. The server
    // enforces the same rule, deliberately: a component whose version was
    // never observed cannot be matched, and guessing is the bug that used to
    // paint unversioned services green.
    tok.chars().next().filter(char::is_ascii_digit).map(|_| tok)
}

/// Build the payload from local findings. Pure, so the test suite can assert
/// exactly what would be transmitted for any capture.
pub(super) fn build_inventory(findings: &[Finding]) -> Vec<Component> {
    let mut out: Vec<Component> = Vec::new();
    for finding in findings {
        let Some((_, product)) = LABEL_TO_PRODUCT.iter().find(|(l, _)| *l == finding.label) else {
            continue;
        };
        let Some(version) = version_of(&finding.value) else {
            continue;
        };
        if version.len() > MAX_COMPONENT_VERSION || product.len() > MAX_COMPONENT_NAME {
            continue;
        }
        // Nothing multi-line can reach the wire. Belt and braces: the
        // detectors are per-line already, but this is the guarantee the
        // feature is sold on, so it is checked where it is claimed.
        if version.contains(['\n', '\r', '\t']) {
            continue;
        }
        let candidate = Component {
            name: (*product).to_string(),
            version: version.to_string(),
        };
        if !out.contains(&candidate) {
            out.push(candidate);
        }
        if out.len() >= MAX_INVENTORY_ITEMS {
            break;
        }
    }
    out
}

pub(super) fn run(args: &Args, findings: &[Finding]) -> Result<()> {
    let inventory = build_inventory(findings);

    if inventory.is_empty() {
        eprintln!(
            "bootintel: no version-bearing component was identified, so there is nothing to \
             ask about.\n  \
             Applicability needs a product AND a version. This capture yielded neither for \
             U-Boot, Linux or BusyBox.\n  \
             `bootintel scan` still shows everything identified locally."
        );
        std::process::exit(EX_DATAERR);
    }

    let body = Request {
        inventory: &inventory,
    };

    if args.dry_run {
        // The point of the feature, not a debug switch: this is what a
        // consultant shows a client to prove what leaves the machine.
        let json = serde_json::to_string_pretty(&body).context("serializing the inventory")?;
        let mut out = io::stdout().lock();
        writeln!(out, "{json}")?;
        writeln!(
            out,
            "\n{} component(s) would be sent to {}. The boot log would not.",
            inventory.len(),
            crate::config::resolve_api_base(args.api_base.as_deref())
        )?;
        return Ok(());
    }

    let base = crate::config::resolve_api_base(args.api_base.as_deref());
    let key = crate::config::resolve_api_key().unwrap_or_default();
    if key.is_empty() {
        eprintln!(
            "bootintel: applicability needs an account.\n  \
             Run `bootintel login` to sign in from this terminal.\n  \
             Local identification stays free: `bootintel scan` needs no account at all."
        );
        std::process::exit(EX_NOPERM);
    }

    let url = crate::api::endpoints::applicability_url(&base);
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(15))
        .timeout_read(std::time::Duration::from_secs(120))
        .build();

    let parsed: Response = match agent
        .post(&url)
        .set("X-API-Key", &key)
        .send_json(serde_json::to_value(&body).context("serializing the inventory")?)
    {
        Ok(r) => r
            .into_json()
            .context("malformed response from the server")?,
        Err(ureq::Error::Status(403, resp)) => {
            let detail = detail_of(resp, "your plan does not include applicability lookup");
            eprintln!("bootintel: {detail}");
            eprintln!("       Local identification stays free: `bootintel scan` needs no account.");
            std::process::exit(EX_NOPERM);
        }
        Err(ureq::Error::Status(401, _)) => {
            eprintln!("bootintel: not signed in, or the terminal login expired.");
            eprintln!("       Run `bootintel login` again.");
            std::process::exit(EX_NOPERM);
        }
        Err(ureq::Error::Status(422, resp)) => {
            // This should be unreachable: the same rules are enforced above,
            // before anything is sent. Say so, because it is a bug here.
            let detail = detail_of(resp, "the server rejected the inventory");
            eprintln!("bootintel: the server rejected a payload this client should have caught.");
            eprintln!("       {detail}");
            eprintln!("       That is a bug in bootintel, not in your capture. Please report it");
            eprintln!("       with the output of `--applicability --dry-run`.");
            std::process::exit(EX_DATAERR);
        }
        Err(ureq::Error::Status(code, resp)) => {
            eprintln!(
                "bootintel: applicability lookup failed ({code}): {}",
                detail_of(resp, "unexpected server response")
            );
            std::process::exit(EX_UNAVAILABLE);
        }
        Err(ureq::Error::Transport(t)) => {
            eprintln!("bootintel: could not reach {base}: {t}");
            eprintln!("       `bootintel scan` still works offline.");
            std::process::exit(EX_UNAVAILABLE);
        }
    };

    render(args, &inventory, &parsed)
}

fn detail_of(resp: ureq::Response, fallback: &str) -> String {
    resp.into_json::<ErrBody>()
        .ok()
        .and_then(|b| b.detail)
        .unwrap_or_else(|| fallback.to_string())
}

fn render(args: &Args, sent: &[Component], resp: &Response) -> Result<()> {
    let mut out = io::stdout().lock();

    if matches!(args.format, super::Format::Json) {
        // Echo what was sent alongside what came back. The auditability of
        // the answer is the product, so the request is part of the record.
        let doc = serde_json::json!({
            "sent_inventory": sent,
            "log_received": resp.log_received.unwrap_or(false),
            "components": resp.inventory.iter().map(|c| serde_json::json!({
                "name": c.name, "version": c.version,
                "status": c.status, "cve_count": c.cve_count,
            })).collect::<Vec<_>>(),
            "findings": resp.findings.iter().map(|f| serde_json::json!({
                "cve_id": f.cve_id, "severity": f.severity,
                "match_basis": f.match_basis, "evidence": f.evidence,
                "remediation": f.remediation,
            })).collect::<Vec<_>>(),
        });
        writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)?;
        return Ok(());
    }

    writeln!(
        out,
        "  Sent {} component(s). The boot log stayed here.",
        sent.len()
    )?;
    for c in sent {
        writeln!(out, "    {} {}", c.name, c.version)?;
    }
    writeln!(out)?;

    for c in &resp.inventory {
        let status = c.status.as_deref().unwrap_or("unknown");
        let count = c.cve_count.unwrap_or(0);
        writeln!(
            out,
            "  {:<16} {:<12} {:<10} {} advisory match(es)",
            c.name, c.version, status, count
        )?;
    }

    if resp.findings.is_empty() {
        writeln!(out, "\n  No applicable advisories in checked coverage.")?;
        writeln!(
            out,
            "  That is not proof the device is unaffected: it means nothing matched"
        )?;
        writeln!(
            out,
            "  the versions observed, within the catalog's coverage."
        )?;
        return Ok(());
    }

    writeln!(
        out,
        "\n  {} applicable advisory match(es):",
        resp.findings.len()
    )?;
    for f in &resp.findings {
        let id = f.cve_id.as_deref().unwrap_or("(no id)");
        let sev = f.severity.as_deref().unwrap_or("unrated");
        let basis = f.match_basis.as_deref().unwrap_or("unspecified");
        writeln!(out, "    {id}  {sev}  [{basis}]")?;
        if let Some(ev) = &f.evidence {
            writeln!(out, "        {ev}")?;
        }
    }
    // Every verdict carries the range it matched and the basis it matched on,
    // because a consultant has to be able to defend the answer, not just
    // quote it.
    writeln!(
        out,
        "\n  match_basis says HOW each one matched. bounded_range and"
    )?;
    writeln!(
        out,
        "  exact_version are anchored; series_upper_bound follows the kernel's"
    )?;
    writeln!(out, "  own convention for a stable series.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(label: &str, value: &str) -> Finding {
        Finding {
            label: label.to_string(),
            value: value.to_string(),
            detail: None,
            source: None,
            line_number: None,
        }
    }

    #[test]
    fn the_three_matchable_components_translate_to_server_names() {
        let got = build_inventory(&[
            f("Bootloader", "U-Boot 2020.10"),
            f("Kernel", "Linux 5.4.100"),
            f("Userland", "BusyBox 1.19.4"),
        ]);
        assert_eq!(
            got,
            vec![
                Component {
                    name: "u-boot".into(),
                    version: "2020.10".into()
                },
                Component {
                    name: "linux".into(),
                    version: "5.4.100".into()
                },
                Component {
                    name: "busybox".into(),
                    version: "1.19.4".into()
                },
            ]
        );
    }

    #[test]
    fn detectors_that_are_not_cve_tracked_products_are_omitted() {
        let got = build_inventory(&[
            f("CPU / Arch", "ARMv7 (32-bit)"),
            f("Init system", "procd"),
            f("Device family", "OpenWrt"),
            f("Flash layout", "7 partitions"),
            f("Runtime firmware", "OpenSBI 1.0"),
            f("ROM identifier", "Espressif ROM esp32-20160718"),
            f("Telnet exposure", "telnetd running"),
        ]);
        assert!(got.is_empty(), "invented entries would be noise: {got:?}");
    }

    #[test]
    fn a_component_with_no_observed_version_is_omitted() {
        // The server rejects these, and rightly: an unversioned component
        // cannot be range-matched.
        for value in ["U-Boot", "U-Boot detected", "BusyBox unknown"] {
            assert!(
                build_inventory(&[f("Bootloader", value), f("Userland", value)]).is_empty(),
                "{value:?} should not produce an inventory entry"
            );
        }
    }

    #[test]
    fn nothing_from_a_boot_log_beyond_a_version_can_reach_the_payload() {
        // The shape that actually leaks: a kernel command line carrying a
        // serial number and the bootloader unlock state.
        let hostile = "Linux 2.6.36 androidboot.serialno=180080072ea00922 \
                       androidboot.vbmeta.device_state=unlocked";
        let got = build_inventory(&[f("Kernel", hostile)]);
        let json = serde_json::to_string(&got).unwrap();
        for leak in [
            "serialno",
            "180080072ea00922",
            "device_state",
            "unlocked",
            "androidboot",
        ] {
            assert!(!json.contains(leak), "{leak} reached the payload: {json}");
        }
    }

    #[test]
    fn a_multi_line_value_is_refused() {
        let got = build_inventory(&[f("Kernel", "Linux 2.6.36\nU-Boot 1.1.3")]);
        let json = serde_json::to_string(&got).unwrap();
        assert!(
            !json.contains("U-Boot"),
            "a second component leaked through a newline: {json}"
        );
    }

    #[test]
    fn duplicates_are_collapsed() {
        let got = build_inventory(&[f("Kernel", "Linux 5.4.100"), f("Kernel", "Linux 5.4.100")]);
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn every_emitted_name_is_one_the_server_accepts() {
        // Server-side software_terms for these three, lowercase.
        let accepted = ["u-boot", "linux", "busybox"];
        let got = build_inventory(&[
            f("Bootloader", "U-Boot 2020.10"),
            f("Kernel", "Linux 5.4.100"),
            f("Userland", "BusyBox 1.19.4"),
        ]);
        for c in &got {
            assert!(
                accepted.contains(&c.name.as_str()),
                "{} is not a server product name",
                c.name
            );
            assert!(c.version.chars().next().unwrap().is_ascii_digit());
            assert!(c.name.len() <= MAX_COMPONENT_NAME && c.version.len() <= MAX_COMPONENT_VERSION);
        }
    }

    #[test]
    fn the_payload_has_no_field_a_log_could_occupy() {
        let got = build_inventory(&[f("Kernel", "Linux 5.4.100")]);
        let v = serde_json::to_value(Request { inventory: &got }).unwrap();
        assert_eq!(
            v.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["inventory"]
        );
        let item = &v["inventory"][0];
        let mut keys: Vec<_> = item.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["name", "version"],
            "a new field here is a new way to smuggle a log"
        );
    }

    #[test]
    fn the_inventory_is_bounded() {
        let many: Vec<Finding> = (0..200)
            .map(|i| f("Kernel", &format!("Linux 5.4.{i}")))
            .collect();
        assert!(build_inventory(&many).len() <= MAX_INVENTORY_ITEMS);
    }
}
