//! Test-only utilities shared across modules.
//!
//! **Why it exists:** Cargo runs tests in parallel by default, and
//! the process's env is shared. Modules that mutate env vars in
//! their tests (config.rs, history.rs, api/endpoints.rs,
//! output.rs, cmd/config.rs, cmd/whoami.rs) MUST serialize those
//! tests against each other or one test's `set_var("BOOTINTEL_*", ...)`
//! races with another test's `remove_var` and one of them fails
//! non-deterministically.
//!
//! Pre-P2-10 posture: config.rs had its own private `env_lock()`;
//! every other test module set env vars unlocked. On a busy CI runner
//! this surfaced as intermittent test failures we'd been re-running
//! away. Post-P2-10: every env-touching test grabs `env_lock()` from
//! this module, so there's exactly one process-wide mutex.

/// Global mutex guarding env-var mutations across all test modules.
///
/// Usage in a test:
/// ```ignore
/// #[test]
/// fn something_that_touches_env() {
///     let _g = crate::test_util::env_lock();
///     std::env::set_var("BOOTINTEL_FOO", "1");
///     // … rest of test …
/// }
/// ```
///
/// The guard's lifetime bounds the critical section — the lock
/// releases when `_g` drops at end-of-scope. Poisoned locks are
/// recovered via `into_inner()` so a panic in one test doesn't
/// permanently break the mutex for later tests.
pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
