//! History log — append-only JSONL of recent scan invocations.
//!
//! Path (platform-native):
//!   * Linux:   `$XDG_STATE_HOME/bootintel/history.jsonl`
//!     (defaults to `~/.local/state/bootintel/history.jsonl`)
//!   * macOS:   `~/Library/Application Support/bootintel/history.jsonl`
//!     (state + application support are conflated on macOS)
//!   * Windows: `%LOCALAPPDATA%\bootintel\history.jsonl`
//!
//! Entry shape (one JSON object per line):
//!
//! ```json
//! {"ts":"2026-08-29T15:04:05Z","path":"/home/z/boot.log","format":"text",
//!  "findings":8,"critical":1,"exit_code":0,"cli_version":"0.3.0"}
//! ```
//!
//! **Best-effort writes**: `append_entry` never returns an error to
//! the caller. A locked file, a full disk, a read-only mount — none
//! of those must block a `scan`. Failures surface as `-vv` debug lines.
//!
//! Cap enforcement: when the file crosses 10 MiB, rotate to `.1`
//! (single generation) and truncate. A perfectly-behaved daily-use
//! account would take years to hit this — the cap exists to keep a
//! script-driven CI loop from silently filling the user's disk.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

const HISTORY_FILENAME: &str = "history.jsonl";
const APP_DIR: &str = "bootintel";

/// Rotation threshold. 10 MiB holds ~50k typical entries — even a
/// nightly-CI account won't hit this in a decade.
const MAX_BYTES: u64 = 10 * 1024 * 1024;

/// One line in the history log. Kept flat (no nested objects) so
/// `grep` + `jq` are both first-class consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// RFC 3339 UTC timestamp (server-log-friendly). Written with
    /// second granularity — sub-second isn't useful for a "what did
    /// I scan last week" audit.
    pub ts: String,
    /// The command name (`scan`, `analyze`, etc). Distinguishes
    /// entries per subcommand for jq filtering.
    #[serde(default)]
    pub cmd: Option<String>,
    /// Path to the log file scanned. Kept as an absolute path so
    /// history is meaningful even when the user's cwd changed.
    pub path: String,
    /// Output format (`text`, `json`, `sarif`, etc.).
    pub format: String,
    /// Finding count from the analyzer.
    pub findings: u32,
    /// Count of findings that fell into `CRITICAL_LABELS`.
    pub critical: u32,
    /// Exit code the process returned (or would have returned).
    pub exit_code: i32,
    /// CLI version (env!("CARGO_PKG_VERSION")).
    pub cli_version: String,
}

/// Resolve the history file path. Uses `dirs::state_dir()` on Linux
/// (falls back to `data_local_dir()` on macOS/Windows where "state"
/// isn't a separate concept). Returns `None` on the very rare
/// platform with neither.
pub fn history_path() -> Option<PathBuf> {
    // dirs::state_dir() returns Some(~/.local/state) on Linux, None
    // on macOS + Windows. Fall through to data_local_dir() there,
    // which points at Application Support / %LOCALAPPDATA%.
    let root = dirs::state_dir().or_else(dirs::data_local_dir)?;
    Some(root.join(APP_DIR).join(HISTORY_FILENAME))
}

/// Append one entry to the history log. Never returns an error to
/// the caller — the whole point of history is that it MUST NOT
/// break a scan. All failures are debug-traced via `vdebug!` and
/// swallowed.
///
/// Also enforces the size cap: if the current file crosses
/// `MAX_BYTES`, rotate to `history.jsonl.1` (single-generation
/// rotate — older `.1` is overwritten) and start a fresh file.
pub fn append_entry(entry: &Entry) {
    if let Err(e) = try_append(entry) {
        crate::vdebug!("history: append failed (ignored): {e}");
    }
}

/// Public predicate that mirrors the module's "should we write?"
/// logic. Callers use this before spending CPU on Entry construction
/// when they know the answer is no (env var opt-out is the common
/// short-circuit).
pub fn is_disabled() -> bool {
    let cfg = crate::config::load_config();
    let (v, _src) = crate::config::effective_no_history(&cfg);
    v
}

fn try_append(entry: &Entry) -> Result<()> {
    if is_disabled() {
        crate::vdebug!("history: writes disabled (BOOTINTEL_NO_HISTORY / no_history=true)");
        return Ok(());
    }
    let path = history_path().context("no platform state dir resolvable")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        // Owner-only on Unix; on Windows the parent inherits the
        // user-only ACL from %LOCALAPPDATA%.
        crate::config::restrict_dir_perms(parent)?;
    }

    // Rotate if the file is over the cap. Check BEFORE opening for
    // append — we want to rotate to `.1` while the current file is
    // still complete, not after we've slapped one more line onto it.
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() >= MAX_BYTES {
            let rotated = path.with_extension("jsonl.1");
            // rename() overwrites the .1 if it exists — single-
            // generation rotate is enough for this use case.
            let _ = std::fs::rename(&path, &rotated);
            crate::vdebug!(
                "history: rotated {} -> {}",
                path.display(),
                rotated.display()
            );
        }
    }

    let mut line = serde_json::to_string(entry).context("serializing entry")?;
    line.push('\n');
    let file_existed = path.exists();
    let mut file = open_history_for_append(&path)?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("writing to {}", path.display()))?;
    // If we just created the file, tighten perms. Doing it once (only
    // on creation) avoids a spurious chmod on every append.
    if !file_existed {
        crate::config::restrict_file_perms(&path)?;
    }
    Ok(())
}

/// Open the history file for append. On Unix we use `.mode(0o600)`
/// via OpenOptionsExt so the file is created owner-only from the
/// start — closing the race between `open(create)` and a later chmod.
/// `O_CLOEXEC` also gets set so child processes never inherit the fd.
#[cfg(unix)]
fn open_history_for_append(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

#[cfg(not(unix))]
fn open_history_for_append(path: &std::path::Path) -> Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// Read the last N entries in reverse-chronological order (newest
/// first). Malformed lines are skipped with a `-vv` debug trace —
/// we never let a corrupted line block the readable ones.
pub fn read_last(n: usize) -> Result<Vec<Entry>> {
    let path = history_path().context("no platform state dir resolvable")?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut out: Vec<Entry> = Vec::new();
    // Iterate lines, keeping only the last N. Reverse at the end
    // to get newest-first. A ring-buffer would be more memory-efficient
    // for enormous files but the cap keeps files under 10 MiB — a
    // full parse is cheap.
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Entry>(line) {
            Ok(e) => out.push(e),
            Err(e) => crate::vdebug!("history: skipping malformed line {} ({e})", i + 1),
        }
    }
    let start = out.len().saturating_sub(n);
    let mut tail: Vec<Entry> = out.split_off(start);
    tail.reverse();
    Ok(tail)
}

/// Truncate the history file. Also removes the rotated `.1` sibling
/// so `history --clear` is fully idempotent.
pub fn clear() -> Result<()> {
    let path = history_path().context("no platform state dir resolvable")?;
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    let rotated = path.with_extension("jsonl.1");
    if rotated.exists() {
        std::fs::remove_file(&rotated)
            .with_context(|| format!("removing {}", rotated.display()))?;
    }
    Ok(())
}

/// RFC 3339 UTC "now". Kept in this module so callers building an
/// Entry don't have to guess the correct format. Uses only stdlib —
/// SystemTime → Unix seconds → hand-rolled Gregorian conversion.
/// Adding `chrono` for this alone would be overkill.
pub fn now_utc_rfc3339() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_utc_secs(d.as_secs())
}

/// Format a Unix epoch second count as `YYYY-MM-DDTHH:MM:SSZ`.
/// Deliberately pure so it's testable without touching the clock.
/// Handles dates from 1970 to well past 2100 correctly (the CLI
/// won't outlive Y2100 concerns; also `u64::MAX` seconds is 500 billion
/// years so we're not risking overflow).
pub fn format_utc_secs(mut secs: u64) -> String {
    let ss = (secs % 60) as u32;
    secs /= 60;
    let mm = (secs % 60) as u32;
    secs /= 60;
    let hh = (secs % 24) as u32;
    let mut days = secs / 24;

    // Days since 1970-01-01 (Thursday). Walk years + months.
    let mut year: u32 = 1970;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let months = [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month: u32 = 0;
    while month < 12 {
        let mut dm = months[month as usize];
        if month == 1 && is_leap(year) {
            dm = 29;
        }
        if days < dm {
            break;
        }
        days -= dm;
        month += 1;
    }
    let day = (days as u32) + 1;
    format!(
        "{year:04}-{:02}-{:02}T{hh:02}:{mm:02}:{ss:02}Z",
        month + 1,
        day
    )
}

fn is_leap(y: u32) -> bool {
    // Standard Gregorian rule: leap if div-by-4 unless div-by-100
    // and not div-by-400. Written with is_multiple_of so clippy on
    // MSRV 1.90+ stops complaining about the manual form.
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Shorten a path for tabular display: `$HOME/foo` → `~/foo`,
/// otherwise show the basename. Never touches disk (pure string op).
///
/// Uses `dirs::home_dir()` rather than `$HOME` directly so the
/// shortening also works on Windows (where the equivalent is
/// `%USERPROFILE%`, not `$HOME`). Falls back to the basename when
/// the path doesn't lie under home.
pub fn display_shorten(p: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if let Some(rest) = p.strip_prefix(home_str.as_ref()) {
            return format!("~{rest}");
        }
    }
    // Fall back to basename.
    std::path::Path::new(p)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::env_lock;

    #[test]
    fn format_utc_secs_matches_known_dates() {
        // 2026-08-29T15:04:05Z = 1788015845 (verified against `date -u -d`).
        assert_eq!(format_utc_secs(1788015845), "2026-08-29T15:04:05Z");
        // Unix epoch.
        assert_eq!(format_utc_secs(0), "1970-01-01T00:00:00Z");
        // Leap-year boundary: 2024-02-29T00:00:00Z = 1709164800.
        assert_eq!(format_utc_secs(1709164800), "2024-02-29T00:00:00Z");
        // Post-2000 leap-year day: 2000-02-29T12:00:00Z = 951825600.
        assert_eq!(format_utc_secs(951825600), "2000-02-29T12:00:00Z");
    }

    #[test]
    fn leap_year_rule() {
        assert!(is_leap(2000));
        assert!(is_leap(2024));
        assert!(!is_leap(2100));
        assert!(!is_leap(1900));
        assert!(!is_leap(2023));
    }

    #[test]
    fn display_shorten_uses_home_prefix() {
        let _g = env_lock();
        std::env::set_var("HOME", "/home/z");
        assert_eq!(display_shorten("/home/z/boot.log"), "~/boot.log");
        assert_eq!(display_shorten("/etc/hosts"), "hosts");
        assert_eq!(display_shorten("/"), "/");
    }

    #[test]
    fn entry_serializes_flat_jsonl_shape() {
        let e = Entry {
            ts: "2026-08-29T15:04:05Z".into(),
            cmd: Some("scan".into()),
            path: "/tmp/boot.log".into(),
            format: "json".into(),
            findings: 8,
            critical: 1,
            exit_code: 0,
            cli_version: "0.3.0".into(),
        };
        let s = serde_json::to_string(&e).unwrap();
        // Must be one line, no nested objects.
        assert!(!s.contains('\n'));
        assert!(s.contains("\"findings\":8"));
        assert!(s.contains("\"critical\":1"));
    }

    #[test]
    fn read_last_roundtrip_via_temp_state() {
        let _g = env_lock();
        // Redirect state to a temp dir by tweaking XDG_STATE_HOME
        // (dirs::state_dir consults it directly).
        let td = std::env::temp_dir().join(format!("bi-hist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        std::fs::create_dir_all(&td).unwrap();
        let saved = std::env::var("XDG_STATE_HOME").ok();
        std::env::set_var("XDG_STATE_HOME", &td);
        // Make sure no_history isn't set anywhere in the env.
        std::env::remove_var("BOOTINTEL_NO_HISTORY");

        for i in 0..5 {
            append_entry(&Entry {
                ts: format!("2026-08-29T00:00:0{i}Z"),
                cmd: Some("scan".into()),
                path: format!("/tmp/log-{i}.txt"),
                format: "text".into(),
                findings: i as u32,
                critical: 0,
                exit_code: 0,
                cli_version: "0.3.0".into(),
            });
        }
        let last = read_last(3).unwrap();
        assert_eq!(last.len(), 3);
        // Newest-first: index 4 comes first.
        assert_eq!(last[0].findings, 4);
        assert_eq!(last[1].findings, 3);
        assert_eq!(last[2].findings, 2);

        // Clear + read = empty.
        clear().unwrap();
        assert_eq!(read_last(10).unwrap().len(), 0);

        // Restore env.
        match saved {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        let _ = std::fs::remove_dir_all(&td);
    }

    #[test]
    fn env_opt_out_makes_append_noop() {
        let _g = env_lock();
        let td = std::env::temp_dir().join(format!("bi-hist-off-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        std::fs::create_dir_all(&td).unwrap();
        let saved_state = std::env::var("XDG_STATE_HOME").ok();
        let saved_off = std::env::var("BOOTINTEL_NO_HISTORY").ok();
        std::env::set_var("XDG_STATE_HOME", &td);
        std::env::set_var("BOOTINTEL_NO_HISTORY", "1");

        append_entry(&Entry {
            ts: "2026-08-29T00:00:00Z".into(),
            cmd: Some("scan".into()),
            path: "/tmp/x".into(),
            format: "text".into(),
            findings: 0,
            critical: 0,
            exit_code: 0,
            cli_version: "0.3.0".into(),
        });
        // File must not exist.
        assert!(!history_path().unwrap().exists());

        match saved_state {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        match saved_off {
            Some(v) => std::env::set_var("BOOTINTEL_NO_HISTORY", v),
            None => std::env::remove_var("BOOTINTEL_NO_HISTORY"),
        }
        let _ = std::fs::remove_dir_all(&td);
    }

    #[cfg(unix)]
    #[test]
    fn history_file_and_dir_are_owner_only() {
        let _g = env_lock();
        use std::os::unix::fs::PermissionsExt;
        let td = std::env::temp_dir().join(format!("bi-hist-perms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        std::fs::create_dir_all(&td).unwrap();
        let saved = std::env::var("XDG_STATE_HOME").ok();
        std::env::set_var("XDG_STATE_HOME", &td);
        std::env::remove_var("BOOTINTEL_NO_HISTORY");

        append_entry(&Entry {
            ts: "2026-08-29T00:00:00Z".into(),
            cmd: Some("scan".into()),
            path: "/tmp/perm".into(),
            format: "text".into(),
            findings: 0,
            critical: 0,
            exit_code: 0,
            cli_version: "0.3.0".into(),
        });

        let path = history_path().unwrap();
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "history file should be 0600");
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "history dir should be 0700");

        match saved {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        let _ = std::fs::remove_dir_all(&td);
    }

    #[test]
    fn rotation_triggers_at_cap() {
        let _g = env_lock();
        // Simulate a file above the cap by pre-writing 10 MiB of
        // pad bytes, then confirming the next append rotates to `.1`.
        let td = std::env::temp_dir().join(format!("bi-hist-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&td);
        std::fs::create_dir_all(&td).unwrap();
        let saved = std::env::var("XDG_STATE_HOME").ok();
        std::env::set_var("XDG_STATE_HOME", &td);
        std::env::remove_var("BOOTINTEL_NO_HISTORY");

        let path = history_path().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Pre-fill 11 MiB so we're comfortably over the cap.
        std::fs::write(&path, vec![b'{'; 11 * 1024 * 1024]).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > MAX_BYTES);

        append_entry(&Entry {
            ts: "2026-08-29T00:00:00Z".into(),
            cmd: Some("scan".into()),
            path: "/tmp/y".into(),
            format: "text".into(),
            findings: 0,
            critical: 0,
            exit_code: 0,
            cli_version: "0.3.0".into(),
        });

        // After rotate: `.1` sibling exists, main file has exactly
        // one line.
        let rotated = path.with_extension("jsonl.1");
        assert!(rotated.exists(), "rotated .1 file missing");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1);

        match saved {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        let _ = std::fs::remove_dir_all(&td);
    }
}
