//! `bootintel submit <log>` — save a scan to your account and download the
//! server-side artifacts: CycloneDX SBOM, evidence pack, PDF and JSON report.
//!
//! Why this is a separate command from `scan --api`.
//!
//! `scan --api` posts to `/analysis/scan`, which the server documents as
//! "stateless inline log analysis without device_id/database persistence". It
//! returns a freshly minted uuid as its `scan_id`, naming no row, so there is
//! nothing on the server to export. Artifacts are built from a real
//! ScanSession, which only `POST /scans/` creates.
//!
//! That distinction has a price attached, which is the reason this is opt-in
//! rather than a flag on `scan`: a saved scan consumes the account's monthly
//! quota (5/month on Free, 15 on Researcher, unlimited above). The command
//! says what it is about to spend before it spends it.
//!
//! The plan requirement is PRO, not Researcher, and the two gates are easy to
//! conflate. The export endpoints are gated at Researcher, but
//! get_current_user refuses any X-API-Key request below Pro with "API access
//! requires Pro plan or higher", so a Researcher can download these artifacts
//! from the dashboard and not from here. Quoting the endpoint's own gate would
//! have told a Researcher this command works for them.
//!
//! Device handling reuses an existing device with the same name instead of
//! creating one per invocation. Without that, a nightly CI job would add a
//! device a day and the fleet view would become useless; the server is happy
//! to hold duplicates, so nothing else would have complained.
//!
//! Exit codes follow the rest of the CLI (sysexits.h):
//!   0  — scan saved, every requested artifact written
//!  65  — EX_DATAERR     — server rejected the request (400/413/422)
//!  69  — EX_UNAVAILABLE — network failure
//!  77  — EX_NOPERM      — 401 (no/invalid key) or 403 (plan or quota)

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::api::endpoints::{
    check_plaintext_base, devices_url, scan_artifact_url, scans_url, PlaintextCheck,
};

const EX_DATAERR: i32 = 65;
const EX_UNAVAILABLE: i32 = 69;
const EX_NOPERM: i32 = 77;

/// Generous: a PDF or evidence pack for a long log takes the server real time
/// to build, and this is a one-shot CI step rather than an interactive command.
const TIMEOUT: Duration = Duration::from_secs(120);

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Log file (or `-` for stdin).
    #[arg(value_name = "LOG")]
    log: PathBuf,

    /// Device to attach the scan to, by name. Reused if it already exists,
    /// created otherwise. Defaults to the log's file name.
    #[arg(long, value_name = "NAME")]
    device_name: Option<String>,

    /// Attach to this exact device id, skipping name lookup and creation.
    #[arg(long, value_name = "UUID", conflicts_with = "device_name")]
    device_id: Option<String>,

    /// Write the CycloneDX 1.6 SBOM here.
    #[arg(long, value_name = "PATH")]
    sbom: Option<PathBuf>,

    /// Write the evidence pack (zip) here.
    #[arg(long, value_name = "PATH")]
    evidence: Option<PathBuf>,

    /// Write the PDF report here.
    #[arg(long, value_name = "PATH")]
    pdf: Option<PathBuf>,

    /// Write the JSON report here.
    #[arg(long, value_name = "PATH")]
    json_report: Option<PathBuf>,

    /// Do not persist the raw log server-side; keep findings and artifacts
    /// only. The SBOM and reports are still produced.
    #[arg(long)]
    no_store_log: bool,

    /// Override the API base URL. Defaults to <https://bootintel.com>
    /// (or $BOOTINTEL_API_BASE, or the config file's api_base).
    #[arg(long, value_name = "URL")]
    api_base: Option<String>,

    /// Machine-readable result on stdout instead of the human summary.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Deserialize)]
struct DeviceRow {
    id: String,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ScanRow {
    id: String,
}

/// One requested artifact: the server path and where to put it.
struct Artifact<'a> {
    flag: &'static str,
    route: &'static str,
    dest: &'a Path,
    binary: bool,
}

pub fn run(args: Args) -> Result<()> {
    let base = crate::config::resolve_api_base(args.api_base.as_deref());

    // Same rule as the rest of the authenticated surface: an API key must not
    // cross a plaintext hop. Loopback is exempt so a local mock still works.
    if check_plaintext_base(&base) == PlaintextCheck::UnsafePlaintext {
        eprintln!("refusing to send an API key over plaintext http:// to {base}");
        eprintln!("use https://, or point --api-base at a loopback address for local testing.");
        std::process::exit(EX_NOPERM);
    }

    let key = match crate::config::resolve_api_key() {
        Some(k) if !k.trim().is_empty() => k,
        _ => {
            eprintln!("no API key configured. Run `bootintel login`, or set BOOTINTEL_API_KEY.");
            eprintln!(
                "a saved scan needs a Pro account: `bootintel scan` works offline without one."
            );
            std::process::exit(EX_NOPERM);
        }
    };

    let raw = read_input(&args.log)?;
    if raw.trim().is_empty() {
        bail!("{} is empty; nothing to submit", args.log.display());
    }

    let wanted = requested_artifacts(&args);
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(TIMEOUT)
        .timeout_read(TIMEOUT)
        .build();

    let device_id = resolve_device(&agent, &base, &key, &args)?;

    // Announced immediately before the spend, not at the top of the run.
    // Printing it earlier meant a 403 from the device lookup was preceded by
    // "this uses one scan from your monthly quota", which was a claim about a
    // charge that never happened. Suppressed under --json, where stdout is
    // being parsed and stderr noise is still noise.
    if !args.json {
        eprintln!("saving a scan to {base} (this uses one scan from your monthly quota)");
    }
    let scan_id = create_scan(&agent, &base, &key, &raw, &device_id, args.no_store_log)?;

    let mut written: Vec<(&'static str, String)> = Vec::new();
    for artifact in &wanted {
        let url = scan_artifact_url(&base, &scan_id, artifact.route);
        crate::vinfo!("GET {url}");
        let bytes = fetch_artifact(&agent, &url, &key, artifact)?;
        write_out(artifact.dest, &bytes)
            .with_context(|| format!("writing {}", artifact.dest.display()))?;
        written.push((artifact.flag, artifact.dest.display().to_string()));
    }

    if args.json {
        let obj = serde_json::json!({
            "scan_id": scan_id,
            "device_id": device_id,
            "artifacts": written.iter().map(|(k, v)| serde_json::json!({"kind": k, "path": v}))
                .collect::<Vec<_>>(),
        });
        let mut out = io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &obj)?;
        writeln!(out)?;
    } else {
        println!("saved scan {scan_id}");
        for (kind, path) in &written {
            println!("  {kind:<9} {path}");
        }
        if written.is_empty() {
            println!(
                "  (no artifacts requested; pass --sbom / --evidence / --pdf / --json-report)"
            );
        }
        println!("  dashboard {}/dashboard", base.trim_end_matches('/'));
    }
    Ok(())
}

fn requested_artifacts(args: &Args) -> Vec<Artifact<'_>> {
    let mut v = Vec::new();
    if let Some(p) = args.sbom.as_deref() {
        v.push(Artifact {
            flag: "sbom",
            route: "sbom.json",
            dest: p,
            binary: false,
        });
    }
    if let Some(p) = args.json_report.as_deref() {
        v.push(Artifact {
            flag: "json",
            route: "report.json",
            dest: p,
            binary: false,
        });
    }
    if let Some(p) = args.evidence.as_deref() {
        v.push(Artifact {
            flag: "evidence",
            route: "evidence.zip",
            dest: p,
            binary: true,
        });
    }
    if let Some(p) = args.pdf.as_deref() {
        v.push(Artifact {
            flag: "pdf",
            route: "report.pdf",
            dest: p,
            binary: true,
        });
    }
    v
}

/// An existing device with this name, or a new one.
///
/// Reuse is the point. `POST /devices/` happily creates a second device with
/// the same name, so a CI job without this would add one per run.
fn resolve_device(agent: &ureq::Agent, base: &str, key: &str, args: &Args) -> Result<String> {
    if let Some(id) = args.device_id.as_deref() {
        return Ok(id.to_string());
    }
    let name = args
        .device_name
        .clone()
        .unwrap_or_else(|| default_device_name(&args.log));

    let list_url = devices_url(base);
    crate::vinfo!("GET {list_url}");
    match agent
        .get(&list_url)
        .set("X-API-Key", key)
        .set("Accept", "application/json")
        .call()
    {
        Ok(resp) => {
            let rows: Vec<DeviceRow> = resp.into_json().unwrap_or_default();
            if let Some(hit) = rows
                .iter()
                .find(|d| d.name.as_deref().map(str::trim) == Some(name.trim()))
            {
                crate::vinfo!("reusing device {} ({name})", hit.id);
                return Ok(hit.id.clone());
            }
        }
        Err(err) => return Err(api_exit("listing devices", err)),
    }

    let create_url = devices_url(base);
    crate::vinfo!("POST {create_url} (creating device {name})");
    let body = serde_json::json!({ "name": name });
    match agent
        .post(&create_url)
        .set("X-API-Key", key)
        .set("Accept", "application/json")
        .send_json(body)
    {
        Ok(resp) => {
            let row: DeviceRow = resp.into_json().context("parsing created device")?;
            Ok(row.id)
        }
        Err(err) => Err(api_exit("creating a device", err)),
    }
}

fn create_scan(
    agent: &ureq::Agent,
    base: &str,
    key: &str,
    raw_log: &str,
    device_id: &str,
    no_store_log: bool,
) -> Result<String> {
    let url = scans_url(base);
    crate::vinfo!("POST {url} ({} bytes)", raw_log.len());
    let body = serde_json::json!({
        "device_id": device_id,
        "raw_log": raw_log,
        "store_raw_log": !no_store_log,
    });
    match agent
        .post(&url)
        .set("X-API-Key", key)
        .set("Accept", "application/json")
        .send_json(body)
    {
        // POST /scans/ runs the analysis inline and returns a completed scan,
        // so there is nothing to poll for before fetching artifacts.
        Ok(resp) => {
            let row: ScanRow = resp.into_json().context("parsing created scan")?;
            Ok(row.id)
        }
        Err(err) => Err(api_exit("saving the scan", err)),
    }
}

fn fetch_artifact(
    agent: &ureq::Agent,
    url: &str,
    key: &str,
    artifact: &Artifact<'_>,
) -> Result<Vec<u8>> {
    match agent.get(url).set("X-API-Key", key).call() {
        Ok(resp) => {
            let mut buf = Vec::new();
            resp.into_reader()
                .read_to_end(&mut buf)
                .context("reading artifact body")?;
            if !artifact.binary && buf.is_empty() {
                bail!("server returned an empty {} artifact", artifact.flag);
            }
            Ok(buf)
        }
        Err(err) => Err(api_exit(
            &format!("fetching the {} artifact", artifact.flag),
            err,
        )),
    }
}

/// Turn a ureq failure into an exit, with the server's own reason.
///
/// Exits rather than returning, because the status IS the outcome and every
/// caller here would do the same thing. 403 carries the two cases a user most
/// needs told apart: the plan does not include exports, or the monthly scan
/// ceiling is reached. The server states which in `detail`, so that is printed
/// verbatim instead of being guessed at.
fn api_exit(what: &str, err: ureq::Error) -> anyhow::Error {
    match err {
        ureq::Error::Status(status, resp) => {
            let detail = resp
                .into_json::<serde_json::Value>()
                .ok()
                .and_then(|v| v.get("detail").and_then(|d| d.as_str()).map(str::to_string));
            eprintln!(
                "{what} failed: HTTP {status}{}",
                detail.map(|d| format!(" - {d}")).unwrap_or_default()
            );
            let code = match status {
                401 | 403 => EX_NOPERM,
                400 | 413 | 422 => EX_DATAERR,
                _ => EX_UNAVAILABLE,
            };
            std::process::exit(code);
        }
        ureq::Error::Transport(t) => {
            eprintln!("{what} failed: {t}");
            std::process::exit(EX_UNAVAILABLE);
        }
    }
}

/// `boot-2026-10-07.log` -> `boot-2026-10-07`. Stdin has no name to borrow.
fn default_device_name(log: &Path) -> String {
    if log.as_os_str() == "-" {
        return "bootintel-cli".to_string();
    }
    log.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "bootintel-cli".to_string())
}

fn write_out(dest: &Path, bytes: &[u8]) -> Result<()> {
    if dest.as_os_str() == "-" {
        io::stdout().lock().write_all(bytes)?;
        return Ok(());
    }
    std::fs::write(dest, bytes)?;
    Ok(())
}

fn read_input(path: &Path) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        return Ok(s);
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_name_defaults_to_the_log_stem() {
        assert_eq!(default_device_name(Path::new("/tmp/boot-9.log")), "boot-9");
        assert_eq!(default_device_name(Path::new("-")), "bootintel-cli");
    }

    #[test]
    fn artifacts_are_only_requested_when_a_path_is_given() {
        let args = Args {
            log: PathBuf::from("x.log"),
            device_name: None,
            device_id: None,
            sbom: Some(PathBuf::from("s.json")),
            evidence: None,
            pdf: None,
            json_report: None,
            no_store_log: false,
            api_base: None,
            json: false,
        };
        let got = requested_artifacts(&args);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].route, "sbom.json");
        assert!(
            !got[0].binary,
            "the SBOM is text and must not be flagged binary"
        );
    }

    #[test]
    fn binary_artifacts_are_marked_as_such() {
        let args = Args {
            log: PathBuf::from("x.log"),
            device_name: None,
            device_id: None,
            sbom: None,
            evidence: Some(PathBuf::from("e.zip")),
            pdf: Some(PathBuf::from("r.pdf")),
            json_report: None,
            no_store_log: false,
            api_base: None,
            json: false,
        };
        for a in requested_artifacts(&args) {
            assert!(a.binary, "{} must be written as bytes", a.flag);
        }
    }
}
