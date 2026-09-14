# bootintel-detectors

Client-side boot-log detectors for BootIntel. Mirrors the streaming-identification subset of the browser detector library at bootintel.com/tools/fingerprint.

**Scope:** identification only — bootloader / kernel / CPU / init / device family / network / web admin / telnet / autoboot exposure. CVE matching, exploit paths, and PDF reports run server-side via BootIntel's API and are NOT in this crate.

## Usage

```rust
use bootintel_detectors::analyze;

let log = std::fs::read_to_string("boot.log").unwrap();
for finding in analyze(&log) {
    println!("{}: {}", finding.label, finding.value);
}
```

## Sync discipline

Nine detectors, each mirroring one entry in the upstream browser detector library. Keep label sets aligned when adding a new detector so JSON output round-trips between browser + CLI.

Regex patterns are copied verbatim from the browser source where the flavor allows. All 9 use only features supported by both JavaScript regex and Rust `regex` (no lookaround, no backreferences).

## License

Apache-2.0.
