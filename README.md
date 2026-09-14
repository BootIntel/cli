# bootintel — Rust CLI

Interactive UART capture + streaming boot-log analysis tool in one static Rust binary. Hybrid client/server split: identification runs client-side (offline, no account), full CVE matching + exploit paths + PDF reports run server-side via bootintel.com's API (paid tiers).

Subcommands include `scan`, `share`, `ports`, `version`, `term`, `analyze`, plus 15+ others (`batch`, `diff`, `watch`, `cve`, `bench`, `replay`, `manpage`, `detectors`, `schema`, `export`, `view`, `demo`, `init`, `doctor`, `completions`).

## Install

```
# One-liner (Linux + macOS, x86_64 + aarch64):
curl -sSfL https://raw.githubusercontent.com/bootintel/cli/main/packaging/scripts/install.sh | sh

# Windows (PowerShell, x86_64):
iwr -useb https://raw.githubusercontent.com/bootintel/cli/main/packaging/scripts/install.ps1 | iex

# Docker:
docker run --rm -i ghcr.io/bootintel/cli:latest scan - < boot.log

# Nix flake (in-repo):
nix run github:bootintel/cli -- version

# Cargo (from source):
cargo install --path crates/cli --features tui
```

**GitHub Actions** (reusable composite action):

```yaml
- uses: bootintel/cli/.github/actions/bootintel-scan@cli-v0.3.0
  with:
    log-file: artifacts/boot.log
    format: sarif
    output-file: bootintel.sarif
    gate-critical: true
    version: 0.3.0   # pin the binary too
```

Pin to a release tag (`@cli-v0.3.0`) or a commit SHA — **never `@main`** (a compromised `main` would execute arbitrary shell in every consumer's pipeline).

**Homebrew:** the formula template lives at `packaging/homebrew/bootintel.rb`. A public `bootintel/homebrew-tap` for `brew install bootintel` is planned.

**Windows:** the one-liner above downloads + SHA256-verifies the latest release, extracts `bootintel.exe` into `$env:USERPROFILE\.local\bin`, and prints a `setx PATH` line if that dir isn't already on your PATH. Override with `$env:BOOTINTEL_VERSION` / `$env:BOOTINTEL_INSTALL_DIR`, or use `$env:BOOTINTEL_TARBALL` for offline installs. Currently x86_64 only — ARM64 users need `cargo install --path crates/cli --features tui`.

## Quick start (from source)

```
cargo build --release
./target/release/bootintel version
./target/release/bootintel demo                          # embedded sample, no files needed
./target/release/bootintel scan ./samples/bootintel-4.txt --format text
./target/release/bootintel share ./samples/bootintel-4.txt
./target/release/bootintel ports
```

## Subcommands

| Subcommand | What it does |
| --- | --- |
| `bootintel scan <file>` | Analyze a saved boot log. Supports `--format json\|text\|sarif\|junit` and `--gate-critical` for CI gating on autoboot / telnet exposure. `-` reads from stdin. `--api` POSTs to bootintel.com for full CVE + exploit paths (needs `BOOTINTEL_API_KEY`); `--api --preview` uses the anonymous free quota (3/day per IP, no key). `--api-base` overrides the endpoint. |
| `bootintel share <file>` | Print a bootintel.com share URL with the log embedded via lz-string compression. Nothing is uploaded — the log lives in the URL itself. |
| `bootintel ports` | List serial ports on this machine with USB VID/PID + product info when known. |
| `bootintel version` | Version, detector count, build metadata. |
| `bootintel term <port>` | Interactive picocom-shaped UART terminal. `--baud` / `--data-bits` / `--parity` / `--stop-bits` / `--flow-control` for serial config. `--log-file <path>` captures raw bytes in parallel. Ctrl-A q to quit, Ctrl-A ? for help, Ctrl-A Ctrl-A to send literal 0x01. |
| `bootintel analyze <port>` | Term + streaming client-side detector analysis. Findings surface as `[bootintel] ● Bootloader: U-Boot 2020.10` inline lines interleaved with the raw serial stream. All `term` flags plus `--no-live-display` to suppress inline output. Extra Ctrl-A hotkeys: `l` toggle live display, `c` clear + re-scan, `s` save findings JSON, `u` copy share URL to clipboard, `f` full server-side analysis when armed with `--api` / `--api --preview`. `--tui` renders a split-screen ratatui dashboard instead of the inline picocom-shaped output; PgUp/PgDn/Home/End scroll the serial pane (needs the `tui` build feature). |

### Interactive smoke test (needs a real terminal)

For a fully interactive shakedown without physical hardware, use a socat virtual PTY pair:

```
# terminal A:
socat -d -d pty,raw,echo=0 pty,raw,echo=0
# note the two /dev/pts/N paths in socat's output

# terminal B (the "device" side — types into the terminal):
echo "U-Boot 2020.10 (Sep 17 2023 - 11:38:21 +0000)" > /dev/pts/N1

# terminal C (the "engineer" side — runs bootintel):
bootintel term /dev/pts/N2 --log-file boot.log
```

Interactive hotkeys are unit-tested in the `hotkey` module (15 tests covering Ctrl-A q, Ctrl-A ?, Ctrl-A Ctrl-A, Ctrl-A l/c/s/u/f, unknown commands, printable / arrow / Ctrl-letter passthrough).

## Server-side integration

Client-side scan is always free and offline. Server-side integration (paid) layers full CVE matching, exploit paths, and (paid tiers) an AI-generated summary on top.

```
# free anonymous preview — 3/day per IP, no account:
bootintel scan --api --preview boot.log

# authenticated full analysis — needs an API key:
export BOOTINTEL_API_KEY=bik_...
bootintel scan --api boot.log

# self-hosted / staging (also honors $BOOTINTEL_API_BASE):
bootintel scan --api --preview --api-base https://staging.bootintel.com boot.log
```

### Environment variables

| Variable | Effect |
| --- | --- |
| `BOOTINTEL_API_KEY` | Sent as `X-API-Key` on `--api` (non-preview) requests. Read in-memory only — never persisted. To keep the key out of shell history + `ps auxe`, use `read -s BOOTINTEL_API_KEY && export BOOTINTEL_API_KEY`. |
| `BOOTINTEL_API_BASE` | Override the API base URL (equivalent to `--api-base`). Useful for self-hosted BootIntel deployments and for pointing at a staging environment. |
| `BOOTINTEL_NO_HISTORY` | Set to `1` to disable the `bootintel history` write-log. Also settable persistently via `bootintel config set no_history true`. |

In `bootintel analyze`, Ctrl-A f triggers the same POST against the log-so-far and prints the server response inline. Passing `--api` / `--api --preview` on the analyze subcommand arms the hotkey; without it, Ctrl-A f prints a hint.

Rate-limit UX: `HTTP 429` is never a silent fallback to client-side. The CLI prints a specific message (retry-after seconds when the server sends `Retry-After`) and exits non-zero (75, EX_TEMPFAIL). Other errors likewise map to sysexits-style codes so CI can dispatch:

| Exit | Meaning | Trigger |
| --- | --- | --- |
| 0   | OK | success |
| 1   | gate-critical failure | `--gate-critical` and a critical finding fired |
| 65  | EX_DATAERR | server rejected the request body (log too large) |
| 69  | EX_UNAVAILABLE | network / DNS / TLS failure |
| 75  | EX_TEMPFAIL | rate-limited (429) |
| 76  | EX_PROTOCOL | server 5xx or malformed response body |
| 77  | EX_NOPERM | 401/403 auth failure |

Response schema is auto-follow with graceful degrade (Stripe-style): unknown fields are preserved via a passthrough map so a server-side schema addition never crashes an older CLI. See `api/response.rs` for the parser.

## TUI dashboard

`bootintel analyze --tui <port>` swaps the picocom-shaped inline output for a split-screen ratatui dashboard:

```
┌ bootintel analyze /dev/ttyUSB0 @ 115200 ── 2:14 ── 3.2 KiB ── 5 findings ─────┐
│                                     │  findings (client) — 5                   │
│  serial stream                      │  ● Bootloader     U-Boot 2020.10         │
│  (autoscroll, PgUp to hold)         │  ● Kernel         Linux 5.15             │
│                                     │  ⚠ Autoboot       Hit any key to stop…   │
│  U-Boot 2020.10 (Sep 17 …)          ├──────────────────────────────────────────┤
│  Model: TP-Link Archer C7           │  server — ok (12s ago)                   │
│  autoboot enabled, 3s               │  device: Archer C7                       │
│  ...                                │  5 findings — 3 shown, 2 hidden          │
│                                     │  ● Bootloader   U-Boot 2020.10           │
│                                     │  ● Autoboot     …  CVE-2023-1234 (CVSS…) │
└─ ? help  ·  q quit  ·  f full-scan  ·  l pause  ·  c clear  ·  PgUp/PgDn ─────┘
```

Ctrl-A hotkeys work identically to inline mode. Extra keys: PgUp/PgDn scroll the serial pane, Home jumps to oldest, End pins back to newest. Feature-flagged so headless CI builds stay small — enable with `cargo build --features tui`. When the feature is off, `--tui` fails with a specific rebuild hint (never a silent fallback to inline mode).

Binary cost: 149 KiB when the feature is on (2.87 MiB no-tui → 2.96 MiB with-tui). ratatui uses the crossterm backend the CLI already links, so no extra terminal deps.

## Distribution

Build infrastructure is shipped. To cut a release:

1. Bump `crates/cli/Cargo.toml` version (also affects `bootintel-detectors` via workspace inheritance).
2. Update `CHANGELOG.md` — move `[Unreleased]` items into a new `[X.Y.Z]` section.
3. Merge to `main` (or run from a branch — the workflow accepts any ref).
4. Actions → cli-release → Run workflow → enter the version (e.g. `0.1.0`), leave `dry_run` off, tick `publish_docker` if you also want the ghcr image.
5. Wait ~15 minutes. Actions produces a DRAFT release with 5 tarballs + SHA256SUMS.
6. Review the artifacts, then publish the draft manually. Nothing is public until you hit "Publish release".
7. Once published, populate `packaging/homebrew/bootintel.rb` SHA256 values + create `Zenofex/homebrew-bootintel` tap.

Files:

```
CHANGELOG.md                      # Keep-a-Changelog, semver-disciplined
Dockerfile                        # multi-stage rust-bookworm → distroless-cc
flake.nix                         # reproducible Nix build + devshell
packaging/
├── homebrew/bootintel.rb         # formula template (no public tap yet)
├── scripts/install.sh            # POSIX shell installer (Linux + macOS)
└── scripts/install.ps1           # PowerShell installer (Windows)

.github/
├── workflows/cli-release.yml     # 5-platform matrix, workflow_dispatch only
└── actions/bootintel-scan/action.yml # reusable composite action
```

Distribution scope deliberately excludes: no auto-update (attack surface), no telemetry (off by default), no winget submission, no apt repo. Those are follow-ups based on demand.

## Workspace layout

```
Cargo.toml                       # workspace manifest
crates/
├── detectors/                   # pure client-side detector library
│   ├── src/lib.rs               # 9 detectors
│   └── tests/detector_tests.rs  # unit tests
└── cli/                         # the `bootintel` binary
    ├── src/
    │   ├── main.rs              # clap arg parsing + subcommand dispatch
    │   ├── cmd/                 # one module per subcommand
    │   │   ├── scan.rs
    │   │   ├── share.rs
    │   │   ├── ports.rs
    │   │   └── version.rs
    │   └── output.rs            # json / text / sarif / junit formatters
    └── tests/
        ├── corpus_smoke.rs      # golden-fixture assertions against the sample corpus
        └── share_roundtrip.rs   # lz-string round-trip tests
```

### term/ module

```
crates/cli/src/term/
├── mod.rs      — module glue
├── hotkey.rs   — Ctrl-A escape state machine (pure, unit-tested)
├── raw_mode.rs — RAII guard that restores terminal on drop even under panic
├── logfile.rs  — BufWriter for --log-file, error-tolerant on disk-full
└── run.rs      — main terminal loop (2 background threads + mpsc), takes optional analyzer
```

### analyze/ module

```
crates/cli/src/analyze/
├── mod.rs      — module glue
├── dedupe.rs   — finding dedupe set keyed on (label, value, source)
├── pacer.rs    — re-run scheduler: 5 new lines OR 500ms, whichever first
├── render.rs   — [bootintel] inline printer + save-summary JSON writer
└── state.rs    — owns log buffer + dedupe + pacer; feed() / maybe_tick() / reset_and_rescan()
```

`bootintel analyze` is `bootintel term` plus an `Option<AnalyzeState>` in `TermOptions`. When present, the shared term loop feeds serial bytes into the analyzer after writing them to stdout; new findings surface as inline `[bootintel] ●` lines. When absent (the term-mode case), the loop skips those steps entirely. One loop, two subcommands.

### api/ module

```
crates/cli/src/api/
├── mod.rs        — module glue
├── endpoints.rs  — URL builders + DEFAULT_API_BASE
├── client.rs     — ureq sync client + typed ScanError classification
├── response.rs   — graceful-degrade parser: known fields modeled, unknown fields flow into `extra`
└── render.rs     — text + JSON output for server responses; JSON round-trips unknown fields
```

The Ctrl-A f hotkey path in analyze mode reuses the same `ScanClient` — one HTTP client for both `scan --api` and analyze-mode full analysis. When Ctrl-A f fires, the term loop restores cooked mode, POSTs synchronously, renders the response, then re-enters raw mode. The user sees a `submitting X bytes to bootintel.com...` line so the pause is explained.

### tui/ module (feature-gated)

```
crates/cli/src/tui/
├── mod.rs      — module glue (only compiled when --features tui)
├── app.rs      — App state (serial buffer, findings, scroll, api status)
├── render.rs   — pure draw(&mut Frame, &App): title + serial pane + findings pane + server pane + status bar
└── run.rs      — mpsc loop identical in shape to term/run.rs; feeds App instead of writing bytes to stdout, redraws on every event or ~80ms tick
```

The tui loop reuses `AnalyzeState` + `ScanClient` + `ApiConfig` unchanged. When `--tui` fires, cmd/analyze.rs constructs the same `TermOptions` it would for inline mode and hands it to `tui::run::run` instead of `term::run::run`. One state, two renderers.

## Output stability

`bootintel scan --format json <file>` produces a stable envelope:

```json
{ "bootintel_version": "...", "analysis_source": "client", "detector_count": N, "findings": [...] }
```

Downstream consumers reading `.findings[]` can rely on the array shape across releases. The envelope grows additively (new top-level fields never break parsing).

SARIF v2.1.0 and JUnit XML outputs conform to their respective specs and validate against GitHub Code Scanning and standard `junit-report` consumers.

`--gate-critical` returns exit 0 (no critical exposures) or 1 (at least one — currently `Autoboot interruptable` or `Telnet exposure`).

## Detector sync discipline

Nine detectors live at `crates/detectors/src/lib.rs` and mirror the browser detector library at bootintel.com/tools/fingerprint. When adding a detector, keep the label set aligned between the two so JSON output round-trips cleanly.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the build loop, coding standards, and PR workflow. Adding a detector? [Contributing → Adding a detector](CONTRIBUTING.md#adding-a-detector). Adding a subcommand? [Contributing → Adding a subcommand](CONTRIBUTING.md#adding-a-subcommand).

## Security

Security issues go to hello@bootintel.com — please don't file them as public GitHub issues. Full disclosure policy + threat model in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
