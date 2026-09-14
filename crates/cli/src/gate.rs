//! `--gate 'EXPR'` DSL — assert properties of the finding set for
//! CI regression gating.
//!
//! Grammar (each --gate takes one expression, flag is repeatable):
//!
//!   Label            → must be present (any value)
//!   !Label           → must NOT be present
//!   Label=value      → present + exact string match on value
//!   Label~=regex     → present + regex match on value
//!
//! Labels are matched case-insensitively with the same whitespace-
//! insensitive normalization as `--only`/`--skip`. Values compare
//! byte-for-byte (no normalization) since the whole point is
//! catching a change from "U-Boot 2020.10" → "U-Boot 2021.04".
//!
//! Exit semantics for the caller:
//!   Ok(true)   → all gates pass; caller returns 0
//!   Ok(false)  → at least one gate failed; caller exits 1
//!   Err(...)   → gate expression didn't parse; caller exits 2

use anyhow::{bail, Result};
use bootintel_detectors::Finding;
use regex::Regex;

#[derive(Debug)]
enum GateExpr {
    Present(String),             // Label
    Absent(String),              // !Label
    ValueEquals(String, String), // Label=value
    ValueMatches(String, Regex), // Label~=regex
}

pub fn evaluate(findings: &[Finding], specs: &[String]) -> Result<bool> {
    if specs.is_empty() {
        return Ok(true);
    }
    let mut all_pass = true;
    for raw in specs {
        let expr = parse_gate(raw)?;
        let (pass, why) = check(&expr, findings);
        if !pass {
            eprintln!("[bootintel] gate failed: {raw}  ({why})");
            all_pass = false;
        }
    }
    Ok(all_pass)
}

fn parse_gate(raw: &str) -> Result<GateExpr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("empty --gate expression");
    }
    // Absence: `!Label`
    if let Some(label) = trimmed.strip_prefix('!') {
        let l = label.trim().to_string();
        if l.is_empty() {
            bail!("--gate '!' with no label");
        }
        return Ok(GateExpr::Absent(l));
    }
    // Regex: `Label~=regex` — check ~= before = so it wins.
    if let Some(idx) = trimmed.find("~=") {
        let label = trimmed[..idx].trim().to_string();
        let rex_src = trimmed[idx + 2..].trim();
        if label.is_empty() {
            bail!("--gate '~=' with no label");
        }
        let rex = Regex::new(rex_src)
            .map_err(|e| anyhow::anyhow!("--gate regex '{rex_src}' didn't parse: {e}"))?;
        return Ok(GateExpr::ValueMatches(label, rex));
    }
    // Exact match: `Label=value`
    if let Some(idx) = trimmed.find('=') {
        let label = trimmed[..idx].trim().to_string();
        let value = trimmed[idx + 1..].to_string(); // preserve leading whitespace in value
        if label.is_empty() {
            bail!("--gate '=' with no label");
        }
        return Ok(GateExpr::ValueEquals(label, value));
    }
    // Presence: bare label
    Ok(GateExpr::Present(trimmed.to_string()))
}

fn check(expr: &GateExpr, findings: &[Finding]) -> (bool, String) {
    match expr {
        GateExpr::Present(label) => {
            let found = findings.iter().any(|f| label_matches(&f.label, label));
            (
                found,
                if found {
                    String::new()
                } else {
                    format!("no finding with label matching '{label}'")
                },
            )
        }
        GateExpr::Absent(label) => {
            let found = findings.iter().any(|f| label_matches(&f.label, label));
            (
                !found,
                if !found {
                    String::new()
                } else {
                    format!("finding with label '{label}' was present (asserted absent)")
                },
            )
        }
        GateExpr::ValueEquals(label, want) => {
            match findings.iter().find(|f| label_matches(&f.label, label)) {
                None => (false, format!("no finding with label '{label}'")),
                Some(f) if &f.value == want => (true, String::new()),
                Some(f) => (
                    false,
                    format!("'{label}' value = '{}' (wanted exact '{}')", f.value, want),
                ),
            }
        }
        GateExpr::ValueMatches(label, rex) => {
            match findings.iter().find(|f| label_matches(&f.label, label)) {
                None => (false, format!("no finding with label '{label}'")),
                Some(f) if rex.is_match(&f.value) => (true, String::new()),
                Some(f) => (
                    false,
                    format!(
                        "'{label}' value = '{}' (wanted regex '{}')",
                        f.value,
                        rex.as_str()
                    ),
                ),
            }
        }
    }
}

/// Label comparison — reuses the same normalization as
/// detector_filter: lowercase, strip spaces/hyphens/underscores/
/// slashes/tabs. So "Init system", "init-system", "init_system",
/// "InitSystem" are equivalent.
fn label_matches(finding_label: &str, gate_label: &str) -> bool {
    norm(finding_label) == norm(gate_label)
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_' | '/' | '\t'))
        .flat_map(|c| c.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(label: &str, value: &str) -> Finding {
        Finding {
            label: label.into(),
            value: value.into(),
            detail: None,
            source: None,
        }
    }

    #[test]
    fn presence_pass_and_fail() {
        let fs = vec![mk("Bootloader", "U-Boot 2020.10")];
        assert!(evaluate(&fs, &["Bootloader".into()]).unwrap());
        assert!(!evaluate(&fs, &["Kernel".into()]).unwrap());
    }

    #[test]
    fn absence_pass_and_fail() {
        let fs = vec![mk("Bootloader", "U-Boot")];
        assert!(evaluate(&fs, &["!Kernel".into()]).unwrap());
        assert!(!evaluate(&fs, &["!Bootloader".into()]).unwrap());
    }

    #[test]
    fn exact_value_match() {
        let fs = vec![mk("Bootloader", "U-Boot 2020.10")];
        assert!(evaluate(&fs, &["Bootloader=U-Boot 2020.10".into()]).unwrap());
        assert!(!evaluate(&fs, &["Bootloader=U-Boot 2021.04".into()]).unwrap());
    }

    #[test]
    fn regex_value_match() {
        let fs = vec![mk("Kernel", "Linux 6.6.37")];
        assert!(evaluate(&fs, &["Kernel~=Linux 6\\.".into()]).unwrap());
        assert!(!evaluate(&fs, &["Kernel~=Linux 5\\.".into()]).unwrap());
    }

    #[test]
    fn label_normalization_across_all_gate_kinds() {
        let fs = vec![mk("Init system", "procd")];
        assert!(evaluate(&fs, &["init-system".into()]).unwrap());
        assert!(evaluate(&fs, &["init_system=procd".into()]).unwrap());
        assert!(evaluate(&fs, &["INITSYSTEM~=proc".into()]).unwrap());
        assert!(!evaluate(&fs, &["!init-system".into()]).unwrap());
    }

    #[test]
    fn parse_errors_carry_context() {
        assert!(evaluate(&[], &["".into()]).is_err());
        assert!(evaluate(&[], &["!".into()]).is_err());
        assert!(evaluate(&[], &["Label~=(unclosed".into()]).is_err());
    }
}
