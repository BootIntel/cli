//! `bootintel mcp` — expose the offline analysis to an MCP client over stdio.
//!
//! # Why this exists, and why it is local
//!
//! The reasoning half of reading a boot log is exactly what a model is good at:
//! given a component inventory, a boot-chain verdict and a kernel posture, what
//! should be looked at first. The reading half is what this binary already does.
//!
//! Running that as an MCP server on the operator's own machine keeps the one
//! property the rest of this tool is built around: nothing leaves. The model
//! that does the reasoning is the operator's own, under whatever agreement they
//! already work under, and BootIntel supplies tools rather than a destination
//! for a client's capture. A hosted version would have to receive the log,
//! which is the thing an NDA-bound consultancy cannot do.
//!
//! # Read-only, deliberately
//!
//! Every tool here reads. None of them opens a serial port, writes to a device,
//! or reaches the network. An agent that can type at a U-Boot prompt on a
//! client's only sample of a device is a different product with a different
//! risk, and `--interrupt-autoboot` already exists for a human who wants that,
//! with the safety rails that come with it. If that ever moves here, the
//! allowlist belongs in this process where the bytes are written, not in a
//! prompt: a model can be argued into anything, a refusal in code cannot.
//!
//! # Transport
//!
//! JSON-RPC 2.0 over stdin/stdout, one message per line, which is what MCP's
//! stdio transport is. No dependency is needed for that beyond serde_json,
//! which is already here.

use anyhow::Result;
use clap::Args as ClapArgs;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

/// Protocol revisions this server knows how to speak. The client's requested
/// version is echoed when it is one of these, because a client that asked for a
/// version and got a different one has to guess what changed.
const SUPPORTED_PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_PROTOCOL: &str = "2024-11-05";

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Print the tool definitions as JSON and exit, without serving. Useful for
    /// checking what an MCP client will see without wiring one up.
    #[arg(long)]
    pub list_tools: bool,
}

pub fn run(args: Args) -> Result<()> {
    if args.list_tools {
        let out = std::io::stdout();
        let mut w = out.lock();
        serde_json::to_writer_pretty(&mut w, &json!({ "tools": tool_definitions() }))?;
        writeln!(w)?;
        return Ok(());
    }
    serve(std::io::stdin().lock(), std::io::stdout().lock())
}

/// The message loop. Split from `run` so the tests drive it with ordinary
/// readers and writers instead of a subprocess.
pub fn serve<R: BufRead, W: Write>(reader: R, mut writer: W) -> Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => handle(&request),
            // A parse error still needs an id field, and there is none to read,
            // so this is the one case where null is correct per JSON-RPC.
            Err(e) => Some(error_response(
                Value::Null,
                -32700,
                &format!("parse error: {e}"),
            )),
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut writer, &response)?;
            writeln!(writer)?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// `None` means the message was a notification, which by JSON-RPC takes no
/// reply. Answering one is a protocol error a client may or may not tolerate.
fn handle(request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(json!({}));

    match method {
        "initialize" => {
            let asked = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_PROTOCOL);
            let version = if SUPPORTED_PROTOCOLS.contains(&asked) {
                asked
            } else {
                DEFAULT_PROTOCOL
            };
            Some(result_response(
                id?,
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": {
                        "name": "bootintel",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "instructions":
                        "Reads serial boot logs offline. Nothing is uploaded and no tool here \
                         writes to a device. Give scan_log or boot_chain_verdict the CONTENTS of \
                         a capture; they do not read files themselves, so the caller decides what \
                         is disclosed.",
                }),
            ))
        }
        // Notifications: no id, no reply.
        m if m.starts_with("notifications/") => None,
        "tools/list" => Some(result_response(id?, json!({ "tools": tool_definitions() }))),
        "tools/call" => {
            let id = id?;
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            match call_tool(name, &arguments) {
                Ok(text) => Some(result_response(
                    id,
                    json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
                )),
                // A tool failure is a RESULT with isError, not a protocol error:
                // the call was well formed and the model should see why it
                // failed rather than the client treating it as a transport
                // fault.
                Err(message) => Some(result_response(
                    id,
                    json!({ "content": [{ "type": "text", "text": message }], "isError": true }),
                )),
            }
        }
        "ping" => Some(result_response(id?, json!({}))),
        _ => Some(error_response(
            id.unwrap_or(Value::Null),
            -32601,
            &format!("unknown method: {method}"),
        )),
    }
}

fn result_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// The capture is passed as text rather than a path on purpose: the caller
/// decides what is disclosed, and a tool that reads arbitrary files is a
/// different trust question from one that reads what it was handed.
fn log_argument(arguments: &Value) -> Result<String, String> {
    match arguments.get("log").and_then(Value::as_str) {
        Some(log) if !log.trim().is_empty() => Ok(log.to_string()),
        Some(_) => Err("the `log` argument is empty; pass the contents of a boot capture".into()),
        None => {
            Err("missing the `log` argument, which takes the contents of a boot capture".into())
        }
    }
}

fn call_tool(name: &str, arguments: &Value) -> Result<String, String> {
    match name {
        "scan_log" => {
            let log = log_argument(arguments)?;
            let findings = bootintel_detectors::analyze(&log);
            let rows: Vec<Value> = findings
                .iter()
                .map(|f| {
                    json!({
                        "label": f.label,
                        "value": f.value,
                        "detail": f.detail,
                        "evidence": f.source,
                        "line_number": f.line_number,
                        "critical": bootintel_detectors::CRITICAL_LABELS.contains(&f.label.as_str()),
                    })
                })
                .collect();
            Ok(serde_json::to_string_pretty(&json!({
                "findings": rows,
                "finding_count": rows.len(),
                // Said explicitly because an empty list is ambiguous: a capture
                // that matched nothing is not a device with nothing wrong.
                "note": if rows.is_empty() {
                    "No detector matched. That means this capture was not recognised, not that \
                     the device is clean: the capture may have started after the boot banner, or \
                     the baud rate may have been wrong."
                } else {
                    "Findings are what the detectors recognised in this capture. Absence of a \
                     finding is not evidence of absence on the device."
                },
            }))
            .map_err(|e| e.to_string())?)
        }
        "boot_chain_verdict" => {
            let log = log_argument(arguments)?;
            let a = bootintel_detectors::boot_chain::assess(&log);
            let hardening = bootintel_detectors::os_hardening::parse(&log);
            let verdicts: Vec<Value> = a
                .verdicts
                .iter()
                .map(|v| {
                    json!({
                        "title": v.title,
                        "state": v.state,
                        "severity": v.severity,
                        "detail": v.detail,
                        "read_from": v.evidence,
                        "remediation": v.remediation,
                    })
                })
                .collect();
            Ok(serde_json::to_string_pretty(&json!({
                "session_reached": a.session.reached,
                "environment_variables": a.session.env.len(),
                "verdicts": verdicts,
                "image_check": a.integrity.image_check,
                "image_check_result": a.integrity.image_check_result,
                "hab_fuse": a.integrity.hab_fuse,
                "kaslr": hardening.kaslr,
                "kaslr_reason": hardening.kaslr_reason,
                "lsm": hardening.lsm,
                "mandatory_access_control": hardening.mac_modules,
                "note":
                    "Every verdict names the value it was read from. A protection this capture \
                     does not mention is unknown, not absent: U-Boot prints only what is set, so \
                     absence is never reported as hardened.",
            }))
            .map_err(|e| e.to_string())?)
        }
        "list_detectors" => Ok(serde_json::to_string_pretty(&json!({
            "detectors": bootintel_detectors::detector_labels(),
            "critical": bootintel_detectors::CRITICAL_LABELS,
        }))
        .map_err(|e| e.to_string())?),
        "sample_log" => Ok(bootintel_detectors::SAMPLE.to_string()),
        other => Err(format!(
            "unknown tool: {other}. Call tools/list for what this server offers."
        )),
    }
}

fn log_schema(purpose: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "log": { "type": "string", "description": purpose }
        },
        "required": ["log"],
    })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "scan_log",
            "description":
                "Identify the bootloader, kernel, SoC, init system and exposure signs in a serial \
                 boot log. Runs entirely locally; nothing is uploaded. Absence of a finding means \
                 the capture did not show it, not that the device lacks it.",
            "inputSchema": log_schema("The contents of a serial boot capture."),
        }),
        json!({
            "name": "boot_chain_verdict",
            "description":
                "Assess what the boot chain permits, from a capture containing a U-Boot session \
                 (a `printenv` dump taken at the prompt) and/or a kernel boot. Reports whether \
                 autoboot is interruptible, whether images are verified, whether a netboot path \
                 is configured, and the kernel's hardening posture. Every entry names the value \
                 it was read from.",
            "inputSchema": log_schema(
                "The contents of a capture. A `printenv` dump taken at the U-Boot prompt gives \
                 the fullest answer; a plain boot log still yields the kernel posture."),
        }),
        json!({
            "name": "list_detectors",
            "description": "List every detector this build recognises, and which count as critical exposures.",
            "inputSchema": { "type": "object", "properties": {} },
        }),
        json!({
            "name": "sample_log",
            "description":
                "Return a short example boot log, for trying the other tools without a device to hand.",
            "inputSchema": { "type": "object", "properties": {} },
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    /// Drive the server with a script of messages and collect the replies.
    fn exchange(messages: &[&str]) -> Vec<Value> {
        let input = messages.join("\n") + "\n";
        let mut output: Vec<u8> = Vec::new();
        serve(BufReader::new(input.as_bytes()), &mut output).expect("server loop");
        String::from_utf8(output)
            .expect("utf8")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each reply is one JSON object per line"))
            .collect()
    }

    fn call(tool: &str, arguments: Value) -> Value {
        let msg = json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        });
        exchange(&[&msg.to_string()]).remove(0)
    }

    fn call_text(tool: &str, arguments: Value) -> String {
        call(tool, arguments)["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn initialize_echoes_a_version_the_client_asked_for() {
        for asked in SUPPORTED_PROTOCOLS {
            let msg = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                             "params":{"protocolVersion": asked}});
            let reply = exchange(&[&msg.to_string()]).remove(0);
            assert_eq!(reply["result"]["protocolVersion"], **asked);
        }
    }

    #[test]
    fn an_unknown_protocol_version_falls_back_rather_than_failing() {
        let msg = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
                         "params":{"protocolVersion":"1999-01-01"}});
        let reply = exchange(&[&msg.to_string()]).remove(0);
        assert_eq!(reply["result"]["protocolVersion"], DEFAULT_PROTOCOL);
    }

    /// JSON-RPC notifications take no reply. Sending one anyway is a protocol
    /// error that some clients tolerate and others do not, which makes it the
    /// kind of bug that works on the machine it was written on.
    #[test]
    fn a_notification_gets_no_reply() {
        let replies = exchange(&[
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}"#,
        ]);
        assert!(replies.is_empty(), "replied to a notification: {replies:?}");
    }

    #[test]
    fn the_tool_set_is_read_only() {
        // The guard that matters. Every tool here reads; none opens a serial
        // port or writes to a device. An agent able to type at a U-Boot prompt
        // on a client's only sample is a different product with a different
        // risk, so adding one has to be a deliberate edit to this list rather
        // than something that arrives unnoticed.
        let names: Vec<String> = tool_definitions()
            .iter()
            .map(|t| t["name"].as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "scan_log",
                "boot_chain_verdict",
                "list_detectors",
                "sample_log"
            ],
        );
        let blob = serde_json::to_string(&tool_definitions()).unwrap();
        for forbidden in ["write", "send", "port", "interrupt", "flash", "erase"] {
            assert!(
                !blob
                    .to_lowercase()
                    .contains(&format!("\"name\":\"{forbidden}")),
                "a tool named for a write operation appeared: {forbidden}"
            );
        }
    }

    #[test]
    fn every_tool_declares_a_schema() {
        for tool in tool_definitions() {
            assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
            assert!(
                tool["description"].as_str().unwrap_or_default().len() > 40,
                "{tool}"
            );
        }
    }

    /// A tool failure is a result carrying isError, not a transport error. The
    /// call was well formed; the model needs to see why it failed rather than
    /// the client treating it as a broken connection.
    #[test]
    fn a_missing_argument_is_a_tool_error_not_a_protocol_error() {
        let reply = call("scan_log", json!({}));
        assert!(
            reply.get("error").is_none(),
            "returned a protocol error: {reply}"
        );
        assert_eq!(reply["result"]["isError"], true);
        assert!(reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .contains("log"));
    }

    #[test]
    fn an_unknown_method_is_a_protocol_error() {
        let reply = exchange(&[r#"{"jsonrpc":"2.0","id":4,"method":"does/not/exist"}"#]).remove(0);
        assert_eq!(reply["error"]["code"], -32601);
    }

    #[test]
    fn malformed_input_does_not_kill_the_session() {
        let replies = exchange(&["{not json", r#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#]);
        assert_eq!(replies[0]["error"]["code"], -32700);
        // The session survives: a client that sends one bad line should not
        // have to reconnect.
        assert_eq!(replies[1]["id"], 5);
    }

    #[test]
    fn scan_log_reports_what_it_recognised() {
        let text = call_text("scan_log", json!({ "log": bootintel_detectors::SAMPLE }));
        let body: Value = serde_json::from_str(&text).unwrap();
        assert!(body["finding_count"].as_u64().unwrap_or(0) > 0, "{text}");
    }

    /// The honesty property has to survive the trip through a model. An empty
    /// finding list read without this note is a clean bill of health, which is
    /// the opposite of what it means.
    #[test]
    fn an_empty_result_says_what_empty_means() {
        let text = call_text("scan_log", json!({ "log": "nothing recognisable here\n" }));
        assert!(text.contains("not that the device is clean"), "{text}");
    }

    #[test]
    fn the_verdict_carries_the_value_it_was_read_from() {
        let text = call_text(
            "boot_chain_verdict",
            json!({
                "log": "hab fuse not enabled\n=> printenv\nbootdelay=3\nverify=no\n\
                        Environment size: 40/65532 bytes\n",
            }),
        );
        let body: Value = serde_json::from_str(&text).unwrap();
        let anchor = body["verdicts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["title"] == "Secure boot anchor")
            .expect("the anchor verdict");
        assert_eq!(anchor["read_from"], "hab fuse not enabled");
        assert!(body["note"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown, not absent"));
    }

    #[test]
    fn a_log_with_nothing_in_it_yields_no_verdicts() {
        let text = call_text(
            "boot_chain_verdict",
            json!({ "log": "Booting from flash...\n" }),
        );
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["session_reached"], false);
        assert!(body["verdicts"].as_array().unwrap().is_empty());
    }
}
