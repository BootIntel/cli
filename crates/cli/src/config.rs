//! Per-user config file support.
//!
//! Location (platform-native, from the `dirs` crate):
//!   * Linux:   `$XDG_CONFIG_HOME/bootintel/config.toml`
//!     (defaults to `~/.config/bootintel/config.toml`)
//!   * macOS:   `~/Library/Application Support/bootintel/config.toml`
//!   * Windows: `%APPDATA%\bootintel\config.toml`
//!
//! Shape (all keys optional):
//!
//! ```toml
//! api_base       = "https://bootintel.com"
//! api_key        = "bik_..."
//! default_format = "text"
//! no_history     = false
//! ```
//!
//! Precedence for values read at runtime: **CLI flag > env var >
//! config file > built-in default**. This is the standard Unix
//! order (git config, aws-cli, ripgrep, etc.).
//!
//! **All reads are graceful-degrade**: missing file, unreadable
//! file, or malformed TOML → empty `Config` (all `None`) + a
//! `-vv` debug line. Never bail. A busted config file must never
//! block a `bootintel scan`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Directory-name segment we use under the platform config root.
const APP_DIR: &str = "bootintel";
/// Filename inside that directory. Kept as a `.toml` so editors
/// pick up syntax highlighting.
const CONFIG_FILENAME: &str = "config.toml";

/// The four keys we currently support in the config file. Kept
/// minimal for v0.3.x — adding more later is easy, removing them
/// isn't. `no_history` (new in 0.3.0 for the history feature) is
/// included here so all persistent CLI settings live in one file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// API base URL. Overridden by `$BOOTINTEL_API_BASE` and
    /// `--api-base`. Defaults to `https://bootintel.com` when unset.
    pub api_base: Option<String>,
    /// API key. Overridden by `$BOOTINTEL_API_KEY`. No CLI flag —
    /// keys aren't accepted on argv for shell-history reasons.
    pub api_key: Option<String>,
    /// Default output format for `scan` / `batch` / `view`. Any
    /// `--format` flag on the command line takes precedence.
    pub default_format: Option<String>,
    /// If true, `scan` / `analyze` skip appending to the history
    /// file. Env var `BOOTINTEL_NO_HISTORY=1` has the same effect.
    /// Kept as plain `bool` (not `Option<bool>`) since a boolean
    /// has no meaningful "unset" state — false and missing behave
    /// identically. `#[serde(default)]` makes missing-key → false.
    #[serde(default)]
    pub no_history: bool,
}

/// Resolve the config file path. Uses `dirs::config_dir()` which
/// gives the platform-appropriate root; we append `bootintel/config.toml`.
///
/// Returns `None` on the rare platform where no config dir is
/// resolvable (e.g. a headless account with $HOME unset). Callers
/// treat `None` as "config file feature unavailable" — they don't
/// synthesise a path or fail hard.
pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(APP_DIR).join(CONFIG_FILENAME))
}

/// Load the config from disk. Never returns an error — a missing,
/// unreadable, or malformed config file resolves to `Config::default()`
/// with a `-vv` debug trace so the user can diagnose with `-vv`.
///
/// This is the entrypoint called from `scan` / `analyze` / anywhere
/// else that needs to consult the config for a defaulted value.
pub fn load_config() -> Config {
    let path = match config_path() {
        Some(p) => p,
        None => {
            crate::vdebug!("config: no platform config dir resolvable, using defaults");
            return Config::default();
        }
    };
    if !path.exists() {
        crate::vdebug!("config: {} does not exist, using defaults", path.display());
        return Config::default();
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            crate::vdebug!("config: unable to read {}: {e}", path.display());
            return Config::default();
        }
    };
    match toml::from_str::<Config>(&text) {
        Ok(cfg) => {
            crate::vdebug!(
                "config: loaded {} bytes from {}",
                text.len(),
                path.display()
            );
            cfg
        }
        Err(e) => {
            crate::vdebug!("config: malformed TOML at {}: {e}", path.display());
            Config::default()
        }
    }
}

/// Origin of an effective config value. Used by `bootintel config
/// list` to show WHERE each value came from, so users don't have
/// to guess whether their env var or their file is being consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Environment variable (e.g. $BOOTINTEL_API_KEY).
    Env,
    /// From `config.toml`.
    File,
    /// Built-in default when nothing else set it.
    Default,
    /// No effective value (key unset in all sources; no default).
    Unset,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Env => "env",
            Source::File => "file",
            Source::Default => "default",
            Source::Unset => "unset",
        }
    }
}

/// Envelope of "here is the current value + where it came from" for
/// a single config key. Used by `config list` + `config get`.
#[derive(Debug, Clone)]
pub struct Effective {
    pub value: Option<String>,
    pub source: Source,
}

/// Resolve `api_base` following the precedence chain.
///
/// Precedence: `$BOOTINTEL_API_BASE` env > config file > built-in
/// default (`https://bootintel.com`). Never consults CLI flags —
/// callers layer their own flag on top of the returned value.
pub fn effective_api_base(cfg: &Config) -> Effective {
    if let Ok(v) = std::env::var("BOOTINTEL_API_BASE") {
        if !v.is_empty() {
            return Effective {
                value: Some(v),
                source: Source::Env,
            };
        }
    }
    if let Some(v) = cfg.api_base.as_ref().filter(|s| !s.is_empty()) {
        return Effective {
            value: Some(v.clone()),
            source: Source::File,
        };
    }
    Effective {
        value: Some(crate::api::endpoints::DEFAULT_API_BASE.to_string()),
        source: Source::Default,
    }
}

/// Resolve `api_key`. Same shape as `effective_api_base` but no
/// built-in default (there is no such thing as a default API key).
pub fn effective_api_key(cfg: &Config) -> Effective {
    if let Ok(v) = std::env::var("BOOTINTEL_API_KEY") {
        if !v.is_empty() {
            return Effective {
                value: Some(v),
                source: Source::Env,
            };
        }
    }
    if let Some(v) = cfg.api_key.as_ref().filter(|s| !s.is_empty()) {
        return Effective {
            value: Some(v.clone()),
            source: Source::File,
        };
    }
    Effective {
        value: None,
        source: Source::Unset,
    }
}

/// Resolve `default_format`. No env var; config-file only.
pub fn effective_default_format(cfg: &Config) -> Effective {
    if let Some(v) = cfg.default_format.as_ref().filter(|s| !s.is_empty()) {
        return Effective {
            value: Some(v.clone()),
            source: Source::File,
        };
    }
    Effective {
        value: None,
        source: Source::Unset,
    }
}

/// Resolve the `no_history` boolean. Env var `BOOTINTEL_NO_HISTORY=1`
/// wins; config `no_history = true` is the fallback. Any other env
/// value ("0", "false", empty, unset) means "consult the file".
pub fn effective_no_history(cfg: &Config) -> (bool, Source) {
    match std::env::var("BOOTINTEL_NO_HISTORY").ok().as_deref() {
        Some("1") | Some("true") | Some("yes") => return (true, Source::Env),
        _ => {}
    }
    // With `no_history: bool` (post-P2-9 unification), we can't tell
    // "explicitly set to false" from "unset" — both are false. Report
    // Source::File when true, Source::Default when false. In practice
    // the callsites don't care about that distinction: `config list`
    // shows a value + source, and false-from-file vs false-from-default
    // behave identically at runtime.
    if cfg.no_history {
        (true, Source::File)
    } else {
        (false, Source::Default)
    }
}

/// Set a key on the config + persist to disk. Creates the config
/// directory if missing. Writes atomically (`.tmp` + rename) so a
/// crash during write can't leave a truncated file.
///
/// Refuses to write to a symlink — a symlinked config file is a
/// classic TOCTOU attack surface, and we don't have a use case for
/// it, so we fail closed with a clear error.
pub fn set_key(key: &str, value: &str) -> Result<PathBuf> {
    let path =
        config_path().context("no platform config dir resolvable (unset $HOME / $APPDATA?)")?;
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to write through symlink at {} (delete it first if intentional)",
                path.display()
            );
        }
    }
    let mut cfg = if path.exists() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str::<Config>(&text).unwrap_or_default()
    } else {
        Config::default()
    };
    apply_key(&mut cfg, key, value)?;
    let text = toml::to_string_pretty(&cfg).context("serializing config")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        restrict_dir_perms(parent)?;
    }
    write_atomic(&path, text.as_bytes())?;
    restrict_file_perms(&path)?;
    Ok(path)
}

/// Tighten permissions on a config-adjacent directory so only the
/// owner can list / traverse it. On Unix, sets mode to `0o700`. On
/// Windows the parent under `%APPDATA%` already inherits a user-only
/// ACL by default; we no-op there and rely on that.
pub(crate) fn restrict_dir_perms(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .with_context(|| format!("chmod 0700 {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Tighten permissions on a config-adjacent file so only the owner
/// can read/write it. On Unix, sets mode to `0o600`. On Windows the
/// file inherits ACL from `%APPDATA%\bootintel\` which by default is
/// user-only; we no-op there and rely on that inheritance.
pub(crate) fn restrict_file_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Get a single effective value by ConfigKey.
pub fn get_effective(cfg: &Config, key: ConfigKey) -> Effective {
    match key {
        ConfigKey::ApiBase => effective_api_base(cfg),
        ConfigKey::ApiKey => effective_api_key(cfg),
        ConfigKey::DefaultFormat => effective_default_format(cfg),
        ConfigKey::NoHistory => {
            let (v, src) = effective_no_history(cfg);
            Effective {
                value: Some(v.to_string()),
                source: src,
            }
        }
    }
}

/// Get a single effective value by key name (string). Convenience
/// wrapper around ConfigKey::from_str + get_effective for the CLI-arg
/// path; produces a friendly error listing the valid keys.
pub fn get_key(cfg: &Config, key: &str) -> Result<Effective> {
    let k = ConfigKey::from_str(key).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown config key '{}' — valid: api_base, api_key, default_format, no_history",
            key
        )
    })?;
    Ok(get_effective(cfg, k))
}

/// Typed enum for every config key. Adding a new key is a single
/// variant + a single match arm below — before this refactor, the
/// four keys were spelled out as string literals in three places
/// (`run_list`, `get_key`, `apply_key`) and additions had to be
/// mirrored across all three (a whole class of "forgot to add it to
/// list" bugs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKey {
    ApiBase,
    ApiKey,
    DefaultFormat,
    NoHistory,
}

impl ConfigKey {
    /// String form as used in the config file + on the CLI. Kept
    /// snake_case to match the on-disk TOML shape.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfigKey::ApiBase => "api_base",
            ConfigKey::ApiKey => "api_key",
            ConfigKey::DefaultFormat => "default_format",
            ConfigKey::NoHistory => "no_history",
        }
    }

    /// Parse a user-supplied key string. Returns None for unknown
    /// keys so the caller can attach its own context to the error
    /// (usually "valid keys are …").
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim() {
            "api_base" => Some(ConfigKey::ApiBase),
            "api_key" => Some(ConfigKey::ApiKey),
            "default_format" => Some(ConfigKey::DefaultFormat),
            "no_history" => Some(ConfigKey::NoHistory),
            _ => None,
        }
    }
}

/// Every ConfigKey, in the order `config list` should print them.
/// Callers iterate via ALL_KEYS.iter().copied() rather than typing
/// the four variants inline.
pub const ALL_KEYS: &[ConfigKey] = &[
    ConfigKey::ApiBase,
    ConfigKey::ApiKey,
    ConfigKey::DefaultFormat,
    ConfigKey::NoHistory,
];

/// Resolve the effective `api_base` URL for a subcommand, layering:
///   CLI flag > `$BOOTINTEL_API_BASE` env > config file > built-in default.
///
/// Extracted so scan/analyze/whoami/etc. don't each open-code the
/// same three-source chain. Callers pass `cli_flag = args.api_base.as_deref()`.
pub fn resolve_api_base(cli_flag: Option<&str>) -> String {
    if let Some(v) = cli_flag {
        if !v.is_empty() {
            return v.to_string();
        }
    }
    let cfg = load_config();
    // effective_api_base handles the env-var + config-file layers and
    // falls back to DEFAULT_API_BASE when both are unset, so the
    // returned Effective always has Some(value).
    effective_api_base(&cfg)
        .value
        .unwrap_or_else(|| crate::api::endpoints::DEFAULT_API_BASE.to_string())
}

/// Resolve the effective API key (env > config file). No CLI-flag
/// layer — keys are never accepted on argv (would leak in ps auxww +
/// shell history). Returns `None` when unset everywhere.
pub fn resolve_api_key() -> Option<String> {
    let cfg = load_config();
    effective_api_key(&cfg).value.filter(|k| !k.is_empty())
}

fn apply_key(cfg: &mut Config, key: &str, value: &str) -> Result<()> {
    let k = ConfigKey::from_str(key).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown config key '{}' — valid: api_base, api_key, default_format, no_history",
            key
        )
    })?;
    apply(cfg, k, value)
}

/// Typed setter — mutates `cfg` in place. Called by both `apply_key`
/// (string dispatch) and any future typed callsite. Value parsing
/// (bool for no_history) lives here so the two entry points share it.
fn apply(cfg: &mut Config, key: ConfigKey, value: &str) -> Result<()> {
    match key {
        ConfigKey::ApiBase => cfg.api_base = Some(value.to_string()),
        ConfigKey::ApiKey => cfg.api_key = Some(value.to_string()),
        ConfigKey::DefaultFormat => cfg.default_format = Some(value.to_string()),
        ConfigKey::NoHistory => {
            cfg.no_history = parse_bool(value).with_context(|| {
                format!("no_history must be a boolean (true/false), got: {value}")
            })?;
        }
    }
    Ok(())
}

fn parse_bool(s: &str) -> Result<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => bail!("not a boolean: {other}"),
    }
}

/// Atomic write: dump bytes to `<path>.tmp` then rename over
/// `<path>`. Rename is atomic on every filesystem the CLI ships
/// on — even a mid-write crash leaves the previous config intact.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    // Restrict the temp file before rename so there's never a window
    // where world-readable bytes containing api_key sit on disk.
    restrict_file_perms(&tmp)?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // Tests that touch env vars run serially — Cargo runs test fns
    // in parallel by default, and the process's env is shared. The
    // canonical mutex lives in `crate::test_util::env_lock` so every
    // env-touching module (config, history, api/endpoints, output,
    // cmd/config, cmd/whoami) grabs the SAME lock.
    use crate::test_util::env_lock;

    fn clear_env() {
        std::env::remove_var("BOOTINTEL_API_KEY");
        std::env::remove_var("BOOTINTEL_API_BASE");
        std::env::remove_var("BOOTINTEL_NO_HISTORY");
    }

    #[test]
    fn env_beats_file_for_api_base() {
        let _g = env_lock();
        clear_env();
        std::env::set_var("BOOTINTEL_API_BASE", "https://env.example.com");
        let cfg = Config {
            api_base: Some("https://file.example.com".into()),
            ..Default::default()
        };
        let e = effective_api_base(&cfg);
        assert_eq!(e.value.as_deref(), Some("https://env.example.com"));
        assert_eq!(e.source, Source::Env);
        clear_env();
    }

    #[test]
    fn file_beats_default_for_api_base() {
        let _g = env_lock();
        clear_env();
        let cfg = Config {
            api_base: Some("https://file.example.com".into()),
            ..Default::default()
        };
        let e = effective_api_base(&cfg);
        assert_eq!(e.value.as_deref(), Some("https://file.example.com"));
        assert_eq!(e.source, Source::File);
    }

    #[test]
    fn default_when_nothing_set() {
        let _g = env_lock();
        clear_env();
        let cfg = Config::default();
        let e = effective_api_base(&cfg);
        assert_eq!(e.source, Source::Default);
        assert!(e.value.as_deref().unwrap().starts_with("https://"));
    }

    #[test]
    fn api_key_env_over_file() {
        let _g = env_lock();
        clear_env();
        std::env::set_var("BOOTINTEL_API_KEY", "bik_env");
        let cfg = Config {
            api_key: Some("bik_file".into()),
            ..Default::default()
        };
        let e = effective_api_key(&cfg);
        assert_eq!(e.value.as_deref(), Some("bik_env"));
        assert_eq!(e.source, Source::Env);
        clear_env();
    }

    #[test]
    fn api_key_unset_when_absent() {
        let _g = env_lock();
        clear_env();
        let cfg = Config::default();
        let e = effective_api_key(&cfg);
        assert_eq!(e.source, Source::Unset);
        assert!(e.value.is_none());
    }

    #[test]
    fn no_history_env_wins() {
        let _g = env_lock();
        clear_env();
        std::env::set_var("BOOTINTEL_NO_HISTORY", "1");
        let cfg = Config {
            no_history: false,
            ..Default::default()
        };
        let (v, src) = effective_no_history(&cfg);
        assert!(v);
        assert_eq!(src, Source::Env);
        clear_env();
    }

    #[test]
    fn no_history_file_true() {
        let _g = env_lock();
        clear_env();
        let cfg = Config {
            no_history: true,
            ..Default::default()
        };
        let (v, src) = effective_no_history(&cfg);
        assert!(v);
        assert_eq!(src, Source::File);
    }

    #[test]
    fn no_history_default_false() {
        let _g = env_lock();
        clear_env();
        let cfg = Config::default();
        let (v, src) = effective_no_history(&cfg);
        assert!(!v);
        assert_eq!(src, Source::Default);
    }

    #[test]
    fn set_roundtrip_via_atomic_write() {
        // We can't easily point set_key at a temp dir without
        // plumbing an override path, so exercise the pieces
        // directly: apply_key mutates Config, write_atomic +
        // toml (de)serialize roundtrip preserves values.
        let tmp =
            std::env::temp_dir().join(format!("bootintel-cfg-test-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut cfg = Config::default();
        apply_key(&mut cfg, "api_base", "https://custom.example").unwrap();
        apply_key(&mut cfg, "default_format", "text").unwrap();
        apply_key(&mut cfg, "no_history", "true").unwrap();
        let text = toml::to_string_pretty(&cfg).unwrap();
        write_atomic(&tmp, text.as_bytes()).unwrap();

        let back = std::fs::read_to_string(&tmp).unwrap();
        let parsed: Config = toml::from_str(&back).unwrap();
        assert_eq!(parsed.api_base.as_deref(), Some("https://custom.example"));
        assert_eq!(parsed.default_format.as_deref(), Some("text"));
        assert!(parsed.no_history);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn apply_key_rejects_unknown() {
        let mut cfg = Config::default();
        let err = apply_key(&mut cfg, "gibberish", "x").unwrap_err();
        assert!(err.to_string().contains("unknown config key"));
    }

    #[test]
    fn apply_key_bool_parsing() {
        let mut cfg = Config::default();
        apply_key(&mut cfg, "no_history", "1").unwrap();
        assert!(cfg.no_history);
        apply_key(&mut cfg, "no_history", "off").unwrap();
        assert!(!cfg.no_history);
        assert!(apply_key(&mut cfg, "no_history", "sometimes").is_err());
    }

    #[test]
    fn malformed_toml_falls_back_to_default() {
        // load_config never bails — this is a critical property.
        // Exercise the parse-error branch by round-tripping through
        // a temp file we can guarantee is malformed.
        let text = "this is not valid toml at all == = = = = = 🙃";
        let parsed: Result<Config, _> = toml::from_str(text);
        assert!(parsed.is_err(), "sanity: malformed input must fail parse");
        // load_config's own graceful path is exercised in an integration
        // test — here we just verify the parser bit.
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_sets_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp =
            std::env::temp_dir().join(format!("bootintel-perms-test-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        write_atomic(&tmp, b"api_base = \"https://x\"\n").unwrap();
        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config file should be owner-only");
        let _ = std::fs::remove_file(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn restrict_dir_perms_sets_0700_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("bootintel-perms-dir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        restrict_dir_perms(&tmp).unwrap();
        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "config dir should be owner-only");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn config_path_is_stable_shape() {
        // Just verify the path ends in the expected suffix on
        // whatever platform tests are running on. We don't assert
        // the platform-specific prefix because CI containers can
        // have unusual $HOME / $XDG values.
        if let Some(p) = config_path() {
            assert!(p.ends_with("bootintel/config.toml") || p.ends_with("bootintel\\config.toml"));
        }
    }
}
