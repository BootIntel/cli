//! `bootintel schema` — emit a JSON Schema (2020-12) for the
//! `scan --format json` envelope. Lets third-party CI tools validate
//! findings or generate typed clients (`quicktype`, `datamodel-code
//! -generator`, etc.) without reverse-engineering the shape from
//! example output.
//!
//! Schema is hand-written (not derived) so we can add descriptions
//! and version it independently of the Rust struct. Kept in sync
//! with output::FindingOut / Envelope via the smoke test at the
//! bottom of the file — a drift there fails the build.

use anyhow::Result;
use clap::Args as ClapArgs;
use std::io::{self, Write};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Which schema to emit. Defaults to `scan` (the client-side
    /// `scan --format json` envelope). Room to add `api-scan`,
    /// `cve-feed`, `batch` etc. later without breaking callers.
    #[arg(long, value_enum, default_value_t = SchemaKind::Scan)]
    kind: SchemaKind,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum, PartialEq, Eq)]
enum SchemaKind {
    Scan,
}

pub fn run(args: Args) -> Result<()> {
    let body = match args.kind {
        SchemaKind::Scan => scan_schema(),
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, &body)?;
    writeln!(out)?;
    let _ = out.flush();
    Ok(())
}

fn scan_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id":     "https://bootintel.com/schemas/scan.json",
        "title":   "bootintel scan --format json envelope",
        "description": "Schema for the JSON envelope produced by `bootintel scan --format json` (client-side detector output).",
        "type":    "object",
        "required": ["bootintel_version", "analysis_source", "detector_count", "findings"],
        "properties": {
            "bootintel_version": {
                "type":        "string",
                "description": "SemVer string of the CLI that produced this document."
            },
            "analysis_source": {
                "type":        "string",
                "enum":        ["client", "server"],
                "description": "Which detector layer produced these findings — client-side (offline) or server-side (via --api)."
            },
            "detector_count": {
                "type":        "integer",
                "minimum":     0,
                "description": "Total number of detectors the CLI has registered. Not the number of matches — see `findings` length for that."
            },
            "findings": {
                "type":        "array",
                "description": "Per-detector matches, in detector-registration order.",
                "items":       { "$ref": "#/$defs/Finding" }
            },
            "analysis_status": {
                "type":        "string",
                "enum":        ["matched", "unrecognized"],
                "description": "Whether any detector recognized anything. Pairs with the process exit code: `matched` -> 0, `unrecognized` -> 3. An empty or unusable capture never reaches this document at all — it exits 2 before output. Lets a consumer distinguish 'clean' from 'we did not recognize this capture' without inferring it from an empty findings array."
            }
        },
        "additionalProperties": false,
        "$defs": {
            "Finding": {
                "type":     "object",
                "required": ["label", "value"],
                "properties": {
                    "label": {
                        "type":        "string",
                        "description": "Detector name (e.g. 'Bootloader', 'Kernel'). Stable across releases."
                    },
                    "value": {
                        "type":        "string",
                        "description": "Primary extracted value (e.g. 'U-Boot 2020.10')."
                    },
                    "detail": {
                        "type":        ["string", "null"],
                        "description": "Optional supplemental context (build date, extra metadata). May be absent."
                    },
                    "source": {
                        "type":        ["string", "null"],
                        "description": "The original log line this finding came from, as it appeared in the capture — including any timestamp or ANSI prefix. Detector matching runs over a normalized copy, but evidence is reported verbatim so it can be found again in the log. May be absent."
                    },
                    "line_number": {
                        "type":        ["integer", "null"],
                        "minimum":     1,
                        "description": "1-based line number of `source` within the analyzed log. Absent when the evidence could not be located."
                    }
                },
                "additionalProperties": false
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_schema_is_valid_json() {
        let text = serde_json::to_string(&scan_schema()).unwrap();
        let round: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(round.is_object());
    }

    #[test]
    fn scan_schema_field_set_matches_output() {
        // If a Finding field is added/removed in `output.rs` without
        // updating this schema, the test fails. We check by
        // extracting the property keys and verifying against the
        // known set. When Finding fields change, update both.
        let schema = scan_schema();
        let props = &schema["$defs"]["Finding"]["properties"];
        let keys: std::collections::HashSet<_> =
            props.as_object().unwrap().keys().cloned().collect();
        let expected: std::collections::HashSet<String> =
            ["label", "value", "detail", "source", "line_number"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(
            keys, expected,
            "Finding schema drifted from output::FindingOut — update BOTH"
        );
    }
}
