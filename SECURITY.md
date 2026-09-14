# Security Policy

`bootintel-cli` is a security tool that runs on engineer laptops and CI runners and parses attacker-controlled input (arbitrary boot logs). We take vulnerabilities in the CLI seriously and appreciate coordinated disclosure.

## Reporting a vulnerability

**Email:** hello@bootintel.com — subject line `[SECURITY] cli: <short summary>`.

Please include:
- Affected version(s) (`bootintel version` output).
- Reproduction steps or a minimal proof-of-concept.
- What the impact is (arbitrary file write, RCE, credential leak, DoS, etc.).
- Whether the issue also affects the browser tool at bootintel.com/tools/fingerprint or the server-side scan API.
- Your name / handle for the CHANGELOG credit line (or "anonymous" if you'd rather stay unattributed).

We'll acknowledge receipt within **3 business days** and aim to ship a fix within **30 days** for critical / high-severity issues, and **90 days** for medium / low. If a fix will take longer, we'll tell you why and give a revised timeline.

**Please do not open a public GitHub issue for a security report.** GitHub Security Advisories are also acceptable if you prefer that channel — file at https://github.com/bootintel/cli/security/advisories/new.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | ✅ security fixes actively backported |
| 0.2.x   | ⚠️ critical fixes only until 2026-11-30 |
| < 0.2.0 | ❌ upgrade to 0.3.x |

We maintain security fixes for the latest MINOR release only. 0.2.x is in a 90-day "critical fixes only" grace window that ends 2026-11-30.

## Threat model + trust boundary

Understanding what we consider "in scope" avoids surprises on both sides:

**In scope:**
- Arbitrary boot-log content is treated as **untrusted** input. Vulnerabilities that let a crafted boot log:
  - Execute arbitrary code or shell commands,
  - Trigger a panic that leaves the terminal in raw mode / with modem-control lines held,
  - Write files outside `--log-file` / `--out-dir` (path traversal, symlink race),
  - Smuggle terminal-control sequences (ANSI escapes, `\r`, cursor moves) into rendered output,
  - Cause unbounded memory allocation (decompression bomb, regex DoS — though Rust `regex` is guaranteed linear so this shouldn't happen by construction).
- Serial-port handling races (multiple opens, DTR/RTS state, `TIOCEXCL` bypass on Unix).
- HTTP client bugs: TLS being silently disabled, response parsing panics, credential-in-URL leaks, cache-poisoning of `--api` responses.
- Compressed share URL round-trip (`share` + `decode-share`) — decompression bombs, malformed input crashes.
- File writes with default overwrite behavior that could destroy user data (`--log-file`, `export`, `init`).

**Out of scope:**
- Server-side scan endpoints (`bootintel.com/api/scan`) — file server-side vulns as normal at that surface.
- Content of `--api` server responses (subject to server-side rate limiting + tier gating — a report saying "the server sent findings that aren't accurate" is a product-quality bug, not a CLI vuln).
- Denial-of-service that requires local execution (e.g. `bootintel replay < /dev/random` — you already have the shell).
- User-supplied API key handling if the key comes from `--api-key` on the command line (visible in `ps auxww`) — use `BOOTINTEL_API_KEY` env var if this matters to you.
- Third-party dependencies with known CVEs where the vulnerable path is not reachable from this CLI. (For third-party issues that IS reachable, please still report — we'll upgrade the dep.)

## Credit

Fixes credit reporters in the CHANGELOG unless you ask us not to. We also list contributors in `CONTRIBUTORS.md`.

## Encrypted channel

If your report contains sensitive PoC material and you'd prefer GPG-encrypted email, ask at hello@bootintel.com and we'll send the public key.
