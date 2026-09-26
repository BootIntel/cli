# Contributing to bootintel-cli

Thanks for considering a contribution! This document covers how to build, test, and land changes.

## Table of contents

- [Quick loop](#quick-loop)
- [Repository layout](#repository-layout)
- [Development environment](#development-environment)
- [Filing issues](#filing-issues)
- [Pull request workflow](#pull-request-workflow)
- [Coding standards](#coding-standards)
- [Testing](#testing)
- [Commit messages](#commit-messages)
- [Adding a detector](#adding-a-detector)
- [Adding a subcommand](#adding-a-subcommand)
- [License of contributions](#license-of-contributions)

## Quick loop

```bash
git clone https://github.com/bootintel/cli.git
cd cli
cargo build --release --features tui
cargo test --features tui
./target/release/bootintel demo             # runs against the embedded sample
```

If you see 0 warnings and `test result: ok`, you're set up.

## Repository layout

```
crates/detectors/    # pure regex detector library, no I/O, one dep (regex)
crates/cli/          # the `bootintel` binary — clap CLI, subcommands, TUI, HTTP client
samples/             # 31 boot-log samples used by the corpus_smoke test suite
packaging/           # install.sh, Homebrew formula, Docker (via /Dockerfile), Nix (/flake.nix)
.github/workflows/   # CI, release, action-selftest
.github/actions/     # reusable GH Action wrapper (bootintel-scan)
```

## Development environment

- **Rust:** MSRV is declared in `Cargo.toml` (`workspace.package.rust-version`). CI builds against it to make sure the pin is honest. `rustup toolchain install <that-version>` if you don't have it already.
- **Linux only:** `libudev-dev` for the `serialport` crate. `sudo apt-get install libudev-dev` on Debian/Ubuntu.
- **Optional:** `docker` for the container build, `nix` for the flake, a serial adapter or `socat` PTY pair for interactive `term` / `analyze` testing.

## Filing issues

Search existing issues before opening a new one. Include:

- `bootintel version` output (or the exact commit if you're on `main`).
- Your OS + terminal + shell.
- A minimal reproduction. For scan-related bugs, a boot log excerpt (or link to one of the samples in `samples/`).
- What you expected vs. what happened.

Security issues go to hello@bootintel.com — see [SECURITY.md](SECURITY.md).

## Pull request workflow

1. Fork the repo (or if you have write access, branch directly).
2. Create a topic branch: `git checkout -b fix-thing` or `feat-thing`.
3. Make focused commits — one logical change per commit, not "wip" / "more" / "typo".
4. Run the checks locally:
   ```
   cargo fmt --all --check
   cargo clippy --features tui --all-targets -- -D warnings
   cargo test --features tui
   ```
5. Push + open a PR against `main`.
6. CI runs the same checks plus builds on Linux / macOS / Windows plus MSRV. If CI is red, fix and push — don't force-push mid-review unless you're rebasing on a request.

We aim to respond to PRs within a week. If a PR sits waiting on us for more than that, ping in the PR thread — sometimes life happens.

### What we look for in review

- Code that stays consistent with the rest of the file (naming, imports, error handling).
- New behavior is tested. New detectors get positive + negative unit tests. New CLI flags get an integration test in `crates/cli/tests/`.
- No new panics on untrusted input — see [SECURITY.md](SECURITY.md) for the trust boundary.
- Docstrings on public items explain *why* the thing exists, not just *what* it does.
- No unrelated changes bundled in ("while I was here..." refactors go in separate PRs).

## Coding standards

- **Formatting:** `cargo fmt --all`. No opinionated overrides; the tree uses defaults.
- **Linting:** `cargo clippy -- -D warnings` on default features and `--features tui`. New clippy warnings block CI.
- **Error handling:** `anyhow` at the top level of subcommand entry points; `thiserror` for typed errors in libraries. Wrap errors with actionable context (`.with_context(|| format!("opening {}", path.display()))`) — CI logs and bug reports thank you.
- **Panics:** avoid `unwrap()` / `expect()` in production paths unless a preceding check makes the invariant true. Comments on any surviving `unwrap()` should explain why it's infallible.
- **`unsafe`:** currently zero in the workspace. If you need `unsafe`, discuss in an issue first — we'd rather add a safe helper crate than embed unsafe blocks.
- **Dependencies:** each new dep needs a rationale. Small std-only implementations are preferred over pulling a crate for one line.

## Testing

- Unit tests live alongside the code (`#[cfg(test)] mod tests`).
- Integration tests live in `crates/*/tests/*.rs`.
- Test discipline: deterministic (no wall-clock waits, no filesystem-dependent paths beyond `TempDir`), fast (<10s for the full suite), self-contained (no network unless via a hand-rolled localhost mock — see `crates/cli/src/api/client.rs` tests for the pattern).
- Run everything before pushing:
  ```
  cargo test --features tui
  cargo test --no-default-features    # feature-flag hygiene
  ```

## Commit messages

Loose convention, not strict:

```
component: short summary of the change (<= 65 chars)

Longer explanation of *why* this change is being made. What broke,
what the fix is, what edge cases were considered. Aim for someone
running `git blame` in six months to understand the intent without
having to dig through the PR thread.

Fixes: #123 (if applicable)
```

Component names loosely mirror the tree — `cli`, `detectors`, `tui`, `api`, `docs`, `ci`, `packaging`.

## Adding a detector

New detectors live in `crates/detectors/src/lib.rs`, but the browser detector library at bootintel.com/tools/fingerprint is the source of truth for the set — it is what the web tool and the legacy Node analyzer run. Add the detector there first, then port it here.

1. Add the regex as a `static LazyLock<Regex>`.
2. Add a `fn run_thing(&str) -> Option<Finding>` that runs the regex and returns a `Finding`. Do not set `source` from anything but the matched text, and never set `line_number` — `analyze()` derives both by re-running the detector per line, so a hand-set `source` breaks the original-evidence contract.
3. Wire it into `ALL_DETECTORS` at the same position its browser counterpart occupies. Order and labels are part of the output contract.
4. Add a description to `cmd::detectors::DESCRIPTIONS` (a missing one fails a test) and update `detector_labels_stable`.
5. Add unit tests: at least one positive case and one negative-case log excerpt that shouldn't match.
6. Run `cargo test -p bootintel --test browser_parity` against a checkout of the website repo (`BOOTINTEL_BROWSER_DETECTORS=/path/to/frontend/src/lib/detectors.ts`, `BOOTINTEL_REQUIRE_PARITY=1` so it cannot silently skip). It runs the browser library over all 31 corpus logs and diffs the findings against this crate's.

## Adding a subcommand

New subcommands live in `crates/cli/src/cmd/<name>.rs`.

1. Create the file. Copy the shape of a simple existing subcommand (e.g. `demo.rs` or `detectors.rs`).
2. Register it in `crates/cli/src/main.rs`:
   ```rust
   mod cmd { pub mod newthing; }
   #[derive(Subcommand)] enum Cmd {
       // ...
       Newthing(cmd::newthing::Args),
   }
   ```
3. Add integration tests in `crates/cli/tests/`.
4. Update the README subcommand table.
5. Update `CHANGELOG.md` under `## [Unreleased] / ### Added`.

## License of contributions

By submitting a pull request, you agree that your contribution is licensed under [Apache-2.0](LICENSE) (the same license as this project). No CLA to sign.
