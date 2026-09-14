//! Ratatui TUI.
//!
//! Split-screen dashboard alternative to the inline output.
//! Same backing state (AnalyzeState) — different renderer.
//!
//! Three panes:
//!
//! ```text
//! ┌ bootintel analyze /dev/ttyUSB0 @ 115200 ── 2:14 ── 3.2 KiB ── 5 findings ─┐
//! │                                     │  findings (client)                   │
//! │  serial stream                      │  ● Bootloader     U-Boot 2020.10     │
//! │  (autoscroll)                       │  ⚠ Autoboot       Hit any key…       │
//! │                                     │                                      │
//! │  U-Boot 2020.10 (Sep 17 …)          ├──────────────────────────────────────┤
//! │  Model: TP-Link Archer C7           │  server (Ctrl-A f)                   │
//! │  autoboot enabled, 3s               │  press Ctrl-A f to submit            │
//! │  ...                                │  ...                                 │
//! │                                     │                                      │
//! └─ ?: help  q: quit  f: full-scan  l: pause  c: clear ────────────────────────┘
//! ```
//!
//! Enabled behind `--features tui` and dispatched by `--tui` on the
//! analyze subcommand. When the feature is off, the flag rejects
//! with a build-hint message and analyze runs the classic inline mode.

pub mod app;
pub mod render;
pub mod run;
