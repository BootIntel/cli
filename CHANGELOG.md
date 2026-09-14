# Changelog

All notable changes to bootintel-cli are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the policy documented in the design doc §14 Q6:

- **MAJOR** — any CLI flag renamed or removed; any output-format schema change; any exit-code policy change.
- **MINOR** — new detector; new subcommand; new flag; new output format.
- **PATCH** — bug fix; internal refactor; docs; no user-visible behavior change.

## [Unreleased]

_No unreleased changes since 0.3.1._

## [0.3.1] — 2026-08-30 — security-hygiene + refactor + dep bumps

Patch release. No user-facing feature changes — this is the pre-public-flip cleanup batch identified by the SME review of 0.3.0. Every 0.3.0 workflow keeps working with identical semantics; the code is smaller, safer, and easier to review.

### Security
- Config file (`~/.config/bootintel/config.toml` and platform equivalents) is now created + written with mode 0600 on Unix, and its parent dir with 0700. Prior to this change the file inherited the process umask (typically 0644), leaving the plaintext `api_key` field readable by any local account. Windows inherits its user-only ACL from `%APPDATA%\bootintel\` — verified + documented.
- History file (`~/.local/state/bootintel/history.jsonl` and platform equivalents) opens with an explicit `.mode(0o600)` + `O_CLOEXEC` on Unix (owner-only from creation, no race window between `open(create)` and a later chmod). Parent dir also 0700. Protects the scanned-path list from local snooping.
- `bootintel config set api_key bik_...` now masks the api_key value on its stderr echo (`...abcd` instead of the full key). The value still lives in `argv` / shell history — an interactive-prompt path (rpassword-style) is a follow-up feature.

### Fixed
- `bootintel whoami` no longer stuffs the 429 retry-after seconds into the `tier` display field with an in-code comment that self-flagged the hijack as a "hack". Added a typed `Identity::rate_limited: Option<u64>` field; text output emits `retry: Ns`, JSON emits `rate_limited_retry_secs`. Also deleted a `let client = ScanClient::new(...); let _ = client;` dead binding in the same function whose two comments contradicted each other about whether the client was in use.
- Detector-tests comment/assertion contradiction: `sample_matches_expected_9_labels` said "trip every detector except… actually all 9 fire" while the assertion listed 8 labels. Renamed to `sample_matches_expected_8_labels` with a comment matching reality (Telnet isn't in SAMPLE and is negative-tested separately).
- README + `.github/actions/bootintel-scan/action.yml` GH-Action pin examples bumped from `cli-v0.2.0` / `cli-v0.1.0` to `cli-v0.3.0` (they'd gone stale after the 0.3.0 tag shipped).
- `SECURITY.md` supported-versions table refreshed for 0.3.x: `0.3.x` is now the actively-supported line, `0.2.x` drops to "critical fixes only until 2026-11-30", and the "Once 0.3.x ships…" future-tense paragraph is replaced with the concrete end date.
- `cargo doc --features tui --no-deps` now exits clean, zero warnings. Fixed 26 rustdoc warnings: bare URLs → `<angle-brackets>`, 20 unclosed `<prefix>` HTML-lookalike tags in `term::hotkey::Action` doc comments → backticked \`prefix\`, unclosed `<port>` tag in `term/mod.rs`, unresolved `[bootintel]` intra-doc link in `analyze.rs`.
- `cargo audit`: 0 advisories (was 2 open unsoundness advisories in `lru 0.12.5`, pulled transitively by `ratatui 0.29`). Cleared by the ratatui 0.30 → lru 0.18.3 bump.

### Changed
- Extracted `output::resolve_color_mode(no_color_flag, stream)` (and the pure-decision variant `resolve_color_mode_from_tty(no_color_flag, is_tty)`). Was duplicated across 6 subcommands (`scan`, `batch`, `diff`, `watch`, `init`, `cve`, `demo`, `view`) with slight variations — some checked `.is_empty()`, some used `is_none_or`, `watch` returned bare `bool` instead of `ColorMode`. Single implementation now.
- Extracted `crate::config::resolve_api_base(cli_flag)` + `crate::config::resolve_api_key()` + `crate::api::endpoints::require_safe_transport(base, sending_credential)`. Deletes the 40-line CLI-flag > env > config > default resolution + plaintext-transport branch that was duplicated across `scan`, `analyze`, and `whoami`.
- Unified `mask_secret` (config.rs) and `last4` (whoami.rs) into `crate::output::mask_tail(s, keep)` — one UTF-8-safe `char_indices()`-based implementation instead of two `.chars().rev().take(N).collect::<Vec<_>>().into_iter().rev()` double-reverse-with-alloc idioms.
- Replaced stringly-typed config-key dispatch with `enum ConfigKey { ApiBase, ApiKey, DefaultFormat, NoHistory }` + `impl { as_str, from_str }` + `pub const ALL_KEYS`. Adding a fifth key is now one enum variant + one arm each in `get_effective`, `apply`, and `from_str` — all in `config.rs`, no cross-file edits. Match exhaustiveness means the compiler yells if a new variant is missed.
- Added `deny.toml` at the repo root. Enforces: SPDX license allowlist (Apache-2.0 / MIT / BSD-2/3 / ISC / Unicode-3.0 / 0BSD / BSL-1.0 / Unlicense / MPL-2.0 / Zlib / CDLA-Permissive-2.0 / Apache-2.0 WITH LLVM-exception); crates.io-only source; wildcard-deny with an explicit workspace-path allow; duplicate-crate skiplist for the legitimately-multi-versioned syn/hashbrown/thiserror/windows-* branches. Wired into CI's existing `audit` job as `cargo deny check` — blocking on failure.
- Split `crates/cli/src/cmd/scan.rs` (699 LOC, five concerns) into `scan/{mod,api,baseline,context}.rs` (max 279 LOC). Preserved via `git mv` so `git log --follow` still tracks the old file. Import path from `main.rs` unchanged.
- Renamed `cmd::term::run_cmd` → `run` and `cmd::analyze::run_cmd` → `run` (every other cmd module already exported `pub fn run`); renamed the lower-level session-entry functions `term::run::run` → `run_session` and `tui::run::run` → `run_session` (removes the module-vs-function name clash).
- `Config::no_history: Option<bool>` → `bool` with `#[serde(default)]`. A boolean has no meaningful "unset" state, and the 3-arm `Some(true) / Some(false) / None` match in `effective_no_history` collapses to 2.
- Miscellaneous readability: mid-file `use crate::output::html_escape as html_esc` imports in `batch.rs` / `cve.rs` / `diff.rs` moved to top-of-file (alias dropped, callsites use `html_escape` directly); `history::run_json`'s 8KB manual read/write loop replaced with `std::io::copy`; `history::display_shorten` uses `dirs::home_dir()` instead of `$HOME` env var (works on Windows now).
- Every env-touching test now grabs a single process-wide `crate::test_util::env_lock()` mutex. Pre-fix, `config.rs` had its own private lock and every other module raced. Prevents intermittent parallel-test failures on busy CI runners.

### Dependencies
- `ratatui` 0.29 → 0.30 (cascade: upgraded transitive `lru` from 0.12.5 to 0.18.3, clearing 2 open unsoundness advisories).
- `crossterm` 0.28 → 0.29 (matched to ratatui 0.30's expected crossterm major).
- `dirs` 5 → 6.
- `clap_mangen` 0.2 → 0.3.
- `serialport` 4.9 → 4.10.
- `clap` `env` feature enabled explicitly (became stricter in the clap 4.5 → 4.6 range picked up transitively by the above).
- Added `libc` as a Unix-only direct dep (was already transitive) for `O_CLOEXEC` on the history file.

## [0.3.0] — 2026-08-29 — config file + Windows installer + whoami + history

Follow-up release adding four opt-in UX conveniences requested by early users. No breaking changes; every 0.2.0 workflow keeps working. All new features are additive.

### Added — per-user config file (`bootintel config`)
- New TOML config file at the platform-native XDG-shaped path (`$XDG_CONFIG_HOME/bootintel/config.toml` on Linux, `~/Library/Application Support/bootintel/config.toml` on macOS, `%APPDATA%\bootintel\config.toml` on Windows).
- Supported keys: `api_base`, `api_key`, `default_format`, `no_history`.
- Precedence: CLI flag > env var > config file > built-in default. Standard order — matches git config, aws-cli, ripgrep.
- New subcommand `bootintel config path | list | get | set | edit`. `set` writes atomically (`.tmp` + rename), refuses to write through symlinks, and `edit` picks `$EDITOR` → `$VISUAL` → nano / vi / notepad. `list` masks `api_key` to just the last 4 chars.
- Config reads are graceful-degrade: a missing / unreadable / malformed file resolves to defaults with a `-vv` debug line, never bails.

### Added — Windows PowerShell installer
- New `packaging/scripts/install.ps1` mirroring `install.sh` feature-for-feature. One-liner: `iwr -useb https://raw.githubusercontent.com/bootintel/cli/main/packaging/scripts/install.ps1 | iex`.
- Detects arch (AMD64 supported; ARM64 errors with a `cargo install` hint), resolves latest version from the GH API (or `$env:BOOTINTEL_VERSION`), downloads + SHA256-verifies the .zip, extracts `bootintel.exe` to `$env:USERPROFILE\.local\bin` (overridable via `$env:BOOTINTEL_INSTALL_DIR`), and prints a `setx PATH` line when the dir isn't on PATH.
- Idempotent (refuses to overwrite unless `-Force` / `$env:BOOTINTEL_FORCE=1`). Supports offline installs via `$env:BOOTINTEL_TARBALL` (same env-var shape as install.sh). `-WhatIf` dry-runs the install step.
- Syntax-verified against PowerShell 7.6 with `[System.Management.Automation.Language.Parser]::ParseFile`.

### Added — `bootintel whoami`
- Verify the current API key without running a scan (previously users had to `bootintel scan foo.log --api` to check auth, which posted the whole log).
- Two-stage discovery: tries `GET /api/whoami` first, falls back to a minimal 1-byte authed `/api/analysis/scan` if the /whoami endpoint isn't shipped.
- Prints identity: api base + masked key + status + email + tier + today's quota. `--json` for machine-readable output. Missing fields render as `unknown` / `null` (never fabricated).
- Sysexits-style exit codes for CI dispatch: 0 authenticated, 65 EX_DATAERR, 69 EX_UNAVAILABLE, 77 EX_NOPERM. Respects the plaintext-transport guard (refuses to send the key over `http://` unless loopback).

### Added — `bootintel history`
- Append-only JSONL log of every `bootintel scan` / `bootintel analyze` invocation. Storage at `$XDG_STATE_HOME/bootintel/history.jsonl` (Linux; macOS + Windows use `~/Library/Application Support` / `%LOCALAPPDATA%` respectively).
- Entry fields: `ts`, `cmd`, `path`, `format`, `findings`, `critical`, `exit_code`, `cli_version`. Flat shape — jq + grep are both first-class consumers.
- New subcommand `bootintel history`:
  - default → last 20 entries as a text table (newest first)
  - `--limit N` → override the default
  - `--json` → dump raw JSONL to stdout
  - `--path` → print the history file path
  - `--clear` → truncate (prompts for confirmation unless `--yes`; refuses to auto-clear when stdin isn't a TTY)
- Best-effort writes — a locked file / read-only mount / disabled-via-env case never blocks a scan.
- 10 MiB rotation cap (single-generation `.1` sibling) so a CI loop can't silently fill the user's disk.
- Opt-out honors both `BOOTINTEL_NO_HISTORY=1` env and `no_history = true` in the config file. Both surfaced in `bootintel doctor` output.

### Changed
- `bootintel scan --api` and `bootintel analyze --api` now consult the config file for `api_base` / `api_key` after checking env vars, matching the documented precedence chain.
- `bootintel doctor` gained a `scan history` check reporting where writes go (or that they're opted out).
- README's Install section grew the Windows one-liner and documents the `BOOTINTEL_NO_HISTORY` env var.
- Homebrew formula version bumped to `0.3.0` — SHAs are stale until the release cut refreshes them.

## [0.2.0] — 2026-08-26 — first tagged release

The aspirational 0.1.0 CHANGELOG entry below was never tagged. 0.2.0 is the first real ship — everything below plus the additions listed here. If you were pointing at anything called "0.1.0," everything you thought you had is present in 0.2.0.

### Added — new subcommands (15)
- `bootintel batch <dir>` — recurse a directory, one report + a rollup across all files. `--format text|json|csv|html|md`.
- `bootintel diff <before> <after>` — compare two scans' finding sets. `--format text|json|md|html`; exit non-zero on drift.
- `bootintel watch <file>` — tail-and-analyze a growing log; reopens on truncate/rotate.
- `bootintel cve <CVE-ID>` — look up a CVE in the embedded feed (populated every 4h by the cve-alert-bot). `--format text|json|md|html`.
- `bootintel bench <log>` — median + p95 + throughput for the detector pipeline on one log. Cheap perf-regression guard.
- `bootintel replay <log> <port>` — pump a saved log into a serial port with baud-derived pacing. Reproduces customer captures, exercises analyzer streaming.
- `bootintel manpage --out-dir DIR` — emit troff man pages for every subcommand (Homebrew / dpkg / rpm packagers expect this layout).
- `bootintel detectors` — list every registered detector + a one-line description.
- `bootintel schema` — emit JSON Schema (2020-12) for `scan --format json`. Third-party CI can validate + typegen against it.
- `bootintel encode-share <log>` / `bootintel decode-share <URL>` — stdout-only round-trip for the fingerprint URL compressor. Composes cleanly in shell.
- `bootintel export <log> <out>` — bundle log + findings + tool metadata into one JSON for support tickets. No PII collected.
- `bootintel view <bundle-or-json>` — re-render an archived JSON in any output format. Handy when the log is gone.
- `bootintel demo` — run scan on the built-in SAMPLE log. Zero-arg "show me what this does."
- `bootintel init` — bootstrap the per-user config dir with a macros stub + shell-completion install hints.
- `bootintel doctor` — sanity-check the environment: serial devices, dialout group, `$TERM`, tmux/screen prefix collision, `$BOOTINTEL_API_*`. Exit 0 if all-required checks pass.
- `bootintel completions <shell>` — bash / zsh / fish / powershell / elvish completion scripts. `powershell` + `pwsh` both accepted as aliases (kebab-case default was a UX regression).

### Added — new output formats
- `--format html` (scan / batch / diff / cve / view) — self-contained single-page report, inlined CSS, no JS, no external fonts. Portable "share with the vendor" artifact.
- `--format csv` (scan / batch) — RFC 4180, header + one row per finding. Pandas + spreadsheet consumers.
- `--format md` (scan / batch) — GitHub-flavored markdown with the critical-exposure callout + table + version footer. Meant for GITHUB_STEP_SUMMARY, PR bodies, Slack. Aliased as `markdown`.

### Added — scan flags
- `--only LIST` / `--skip LIST` — filter detectors by comma-separated label list, applied together.
- `--gate 'EXPR'` (repeatable) — assert properties of the finding set with a small DSL: `Label`, `!Label`, `Label=value`, `Label~=regex`. Exit 1 on any failed assertion.
- `--baseline PATH.json` — diff against a saved baseline; exit 1 on drift. The CI regression pattern: check the baseline into the repo, run on PRs.
- `--context N` — show N chars of surrounding log per finding (`grep -C`-shape). Only affects `--format text`.
- `-v` / `-vv` / `--verbose` — global verbose stderr with `[v]` / `[vv]` prefix; never contaminates stdout.
- `-q` / `--quiet` — suppress banners + status hints. Errors still fire on stderr.
- `--no-color` (plus `NO_COLOR` env respect + TTY detection) — deterministic no-ANSI output for pipes / CI.

### Added — --tui hotkey parity (finish-work for 5 stubs)
- `Ctrl-A x` — hex display mode (raw-byte ring, hexdump -C layout, offsets stay absolute as the ring wraps).
- `Ctrl-A p` — paste file (bottom-line input modal → 20ms/line paced write with the current TX-newline transform).
- `Ctrl-A a` — change baud (same modal → `set_baud_rate` in place; hangup + reopen preserve the new baud).
- `Ctrl-A h` — hangup (reader-thread bounce: signal shutdown, drop port, sleep 500ms, reopen, spawn fresh reader; fd churn only, analyzer state preserved).
- `Ctrl-A m` — RX newline mapping (None / CrToLf / StripCr; applied before feed_bytes so pane + analyzer both see the normalized stream).

### Added — minicom / picocom feature parity
- `Ctrl-A b` — BREAK signal (250ms).
- `Ctrl-A d` / `Ctrl-A r` — toggle DTR / RTS (tracks state so a toggle is idempotent).
- `Ctrl-A i` — port + baud + modem-control + newline-mode info line.
- `Ctrl-A t` — session-relative timestamp toggle on inline RX display.
- `Ctrl-A e` — local echo toggle (plain-term only; no-op in --tui with a status note).
- `Ctrl-A n` — cycle TX newline mode: Passthrough / LF / CR / CRLF.
- F1–F12 macros — configurable via `$XDG_CONFIG_HOME/bootintel/macros.toml` (or overridable per-run with `--macros`). Sent through the current TX newline transform.
- `--escape ctrl-t` (or any Ctrl+letter) — remap the hotkey prefix when Ctrl-A collides with tmux/screen. Auto-detects `$TMUX` / `$STY` and prints a hint if the default would be intercepted. All hotkey help strings + the TUI status bar spell the active prefix.
- `--backspace del` / `--backspace bs` — encode Backspace as either DEL (0x7f, minicom default) or BS (0x08, some legacy consoles).

### Added — dashboard + config
- `bootintel init --config-dir DIR` honors the explicit dir verbatim (previously wrongly took `.parent()` on it, treating an explicit user input as a file path).
- `bootintel version --json` — machine-readable version, target, features, detector list.

### Fixed since 0.1.0
- **Serial errors are now actionable**: permission-denied on `/dev/ttyUSB0` prints the `dialout`-group remediation on Linux and Full Disk Access hint on macOS. `AddrInUse` / `ResourceBusy` points at `lsof` / `fuser`. Not-found points at `bootintel ports`.
- **Serial exclusive lock (`TIOCEXCL`)** on Unix so concurrent `bootintel term` / picocom / screen sessions on the same port can't silently corrupt each other's stream.
- **`--log-file` refuses to overwrite by default**. Existing behavior (silent overwrite) was a captured-boot-session destroyer. Opt in via `--log-append` or `--log-overwrite` explicitly.
- **429 rate-limit wording no longer hardcodes tier names or prices**; points at `bootintel.com/pricing` neutrally so tier renames don't require a CLI release.
- **ANSI-escape sanitization** on all rendered detector fields (label / value / detail / CVE) across `analyze` inline output, `--tui`, `scan --format text`, and `scan --api` output. Prevents a hostile boot log from smuggling terminal-injection sequences through the render path.
- **`path.exists()` TOCTOU removed** from `scan` and `share`: permission-denied on the input file no longer misreports as "not found."
- **`ureq` TLS features locked in explicitly** (`default-features = false, features = ["json", "tls", "gzip"]`) so a future refactor can't accidentally strip HTTPS by adding `default-features = false` for a different reason.
- **PowerShell completion accepts `powershell` + `pwsh`** — clap's default kebab-case rendering was `power-shell`, which no user types.
- **--api retry with jittered exponential backoff** — 5xx no longer fails on the first hop; retries 4×, then surfaces a real error.

### Added — distribution infrastructure
- `.github/workflows/cli-release.yml` — 5-platform release workflow (linux/macos/windows × x86_64/aarch64), workflow_dispatch only, produces a GH Release draft. Optional `publish_docker` input for the multi-arch image.
- `Dockerfile` — multi-stage build (rust:1.90-bookworm → distroless-cc, final ~42 MiB). Publishes to `ghcr.io/zenofex/bootintel`.
- `packaging/scripts/install.sh` — POSIX shell installer (`curl … | sh`) that detects OS/arch, downloads from GH Releases, verifies SHA256. `BOOTINTEL_TARBALL=…` env for offline / air-gapped install.
- `flake.nix` — reproducible Nix build (`nix build .`, `nix run .#`).
- `packaging/homebrew/bootintel.rb` — Homebrew formula (SHA256 values populated post-release from the workflow's SHA256SUMS artifact).
- `.github/actions/bootintel-scan/action.yml` — reusable GH Action wrapping the native binary via install.sh.

### Fixed — Docker builder Rust bump
- Pinned to `rust:1.90-bookworm` (was 1.83, but transitive deps via ratatui + darling required 1.88+).

## [0.1.0] — 2026-08-21 — pre-tag scaffolding (never released)

Initial release. All six subcommands live; five branch-based milestones (M1-M5) shipped over 2026-08-19 → 2026-08-21.

### Added

- `bootintel scan <file>` — analyze a saved boot log. `--format json|text|sarif|junit`, `--gate-critical`, stdin via `-`. Nine detectors: Bootloader, Kernel, Model, CPU, Family, Init, Web, Network, Autoboot interruptable / Telnet exposure (critical).
- `bootintel scan --api` / `--api --preview` — POST log to bootintel.com for full CVE matching + exploit paths + (paid tiers) AI summary. Sysexits-style exit codes for CI dispatch (75 rate-limited, 77 unauthorized, 76 protocol, 69 network, 65 bad-request).
- `bootintel share <file>` — print bootintel.com URL with log embedded via lz-string. No upload.
- `bootintel ports` — list serial ports on this machine with USB VID/PID + product info.
- `bootintel version` — version, detector count, build metadata.
- `bootintel term <port>` — interactive picocom-shaped UART terminal. Baud/data-bits/parity/stop-bits/flow-control. `--log-file` captures raw bytes in parallel. Ctrl-A q to quit, Ctrl-A ? for help.
- `bootintel analyze <port>` — term + streaming client-side detector analysis. Findings surface as inline `[bootintel] ●` lines. Ctrl-A hotkeys: `l` toggle live display, `c` clear+re-scan, `s` save findings JSON, `u` copy share URL, `f` full server-side analysis (M4).
- `bootintel analyze --tui` — split-screen ratatui dashboard alternative to inline output. PgUp/PgDn/Home/End scroll the serial pane. Feature-flagged (`--features tui`).

### Compatibility

- JSON output envelope: `{bootintel_version, analysis_source, detector_count, findings}`. Downstream consumers reading `.findings[]` can rely on the array shape across releases.
- Response schema from `--api` is graceful-degrade: unknown server fields are preserved via a passthrough `extra` map, so a server-side schema addition never crashes an older CLI.

### Not yet in 0.1.0

- Auto-update (`bootintel update`) — deliberately skipped for supply-chain reasons. Distribution via package managers is the update mechanism.
- Telemetry — off by default. Opt-in path not yet wired.
- PDF report download subcommand — server-side endpoint exists but no client-side wrapper yet.
- Windows support — the Rust code compiles for Windows and the release workflow builds it, but install.sh doesn't handle Windows yet (`.ps1` installer is a follow-up).

[Unreleased]: https://github.com/bootintel/cli/compare/cli-v0.3.1...HEAD
[0.3.1]: https://github.com/bootintel/cli/releases/tag/cli-v0.3.1
[0.3.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.3.0
[0.2.0]: https://github.com/bootintel/cli/releases/tag/cli-v0.2.0
[0.1.0]: https://github.com/bootintel/cli/blob/cli-v0.2.0/CHANGELOG.md#010--2026-08-21--pre-tag-scaffolding-never-released
