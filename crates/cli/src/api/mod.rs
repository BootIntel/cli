//! bootintel.com API integration.
//!
//! Two endpoints:
//!
//! * `POST /api/analysis/preview` — anonymous, IP-rate-limited (3/day).
//!   Free-tier CVE preview without an account. `--api --preview`.
//! * `POST /api/analysis/scan` — authenticated via `X-API-Key` or
//!   `Bearer` header. Full CVE matching + exploit paths + AI report
//!   subject to the caller's plan. `--api` with `BOOTINTEL_API_KEY`.
//!
//! Design notes:
//!
//! * Sync HTTP (ureq). No tokio in the CLI.
//! * Response parser is graceful-degrade: known fields deserialized,
//!   unknown ones ignored, so a server-side schema forward-addition
//!   never crashes an older client (Stripe-style).
//! * Rate-limit 429 surfaces as a specific error variant with the
//!   Retry-After header preserved for the CLI to display. Never a
//!   silent fallback to client-only output.

pub mod client;
pub mod endpoints;
pub mod render;
pub mod response;
