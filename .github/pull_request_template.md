<!--
Thanks for the PR! A few reminders (delete this comment before submitting):

  * Please open an issue first for anything larger than a fix — saves you from writing code we might redirect.
  * Security fixes: coordinate via SECURITY.md, don't disclose in the PR body until fix has landed.
  * Rebase on latest main before opening.
-->

## Summary

<!-- What does this PR do? Keep it to 1-3 sentences. -->

## Why

<!-- What problem does it solve? Link to the issue if there is one: "Fixes #123" -->

## What changed

<!-- Bullet the concrete changes. Reviewers scan this. -->

-
-

## How I tested

<!--
Concrete commands. Examples:

  cargo test --features tui       # 199 passed / 0 failed
  cargo test --no-default-features
  cargo clippy --features tui --all-targets -- -D warnings
  ./target/release/bootintel scan samples/bootintel-4.txt --format json | jq '.findings | length'
  # For interactive changes: socat PTY smoke, tmux session recording, etc.
-->

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --features tui --all-targets -- -D warnings` passes
- [ ] `cargo test --features tui` passes (and `--no-default-features` for feature-flag hygiene)
- [ ] New behavior has tests
- [ ] CHANGELOG.md updated under `## [Unreleased]` if user-visible
- [ ] Docs updated (README subcommand table, per-crate READMEs) if user-visible
- [ ] No unrelated changes bundled in
- [ ] I've read [CONTRIBUTING.md](CONTRIBUTING.md)
