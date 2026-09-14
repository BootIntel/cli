//! `bootintel config` — inspect + edit the per-user config file.
//!
//! Subcommands:
//!   * `path`           — print the config file path (always, whether or not it exists)
//!   * `list`           — print all effective values + the source they came from
//!   * `get <key>`      — print one effective value
//!   * `set <key> <val>`— persist a value to the config file
//!   * `edit`           — open the file in $EDITOR (falls back to $VISUAL, then vi/nano/notepad)
//!
//! The command intentionally doesn't accept the `--api-base` /
//! `--api-key` flags — this exists to make defaults sticky, not to
//! transiently override.

use anyhow::{bail, Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use std::io::{self, Write};
use std::process::Command;

use crate::config::{
    config_path, get_effective, get_key, load_config, set_key, ConfigKey, Source, ALL_KEYS,
};

#[derive(ClapArgs, Debug)]
pub struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug)]
enum Action {
    /// Print the config file path.
    Path,
    /// Print all effective values and the source each one came from.
    List,
    /// Print a single effective value.
    Get {
        /// One of: api_base, api_key, default_format, no_history.
        key: String,
    },
    /// Persist a value to the config file.
    Set {
        /// One of: api_base, api_key, default_format, no_history.
        key: String,
        /// New value. Booleans accept true/false/1/0/yes/no/on/off.
        value: String,
    },
    /// Open the config file in $EDITOR (creates it first if missing).
    Edit,
}

pub fn run(args: Args) -> Result<()> {
    match args.action {
        Action::Path => run_path(),
        Action::List => run_list(),
        Action::Get { key } => run_get(&key),
        Action::Set { key, value } => run_set(&key, &value),
        Action::Edit => run_edit(),
    }
}

fn run_path() -> Result<()> {
    match config_path() {
        Some(p) => {
            println!("{}", p.display());
            Ok(())
        }
        None => bail!("no platform config dir resolvable (unset $HOME / $APPDATA?)"),
    }
}

fn run_list() -> Result<()> {
    let cfg = load_config();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    // Print the path first so the user always knows where the file
    // lives even if it doesn't exist yet.
    if let Some(p) = config_path() {
        writeln!(out, "# {}", p.display())?;
    }
    writeln!(out)?;

    for key in ALL_KEYS {
        let e = get_effective(&cfg, *key);
        let key_str = key.as_str();
        // API keys are secrets — mask everything past the last 4 chars
        // even when the caller runs `config list` with a valid stdout,
        // so shoulder-surfers + accidental screenshots don't leak the
        // key. `config get api_key` prints the full value on demand.
        let shown = match (*key, &e.value) {
            (ConfigKey::ApiKey, Some(v)) => Some(mask_secret(v)),
            (_, other) => other.clone(),
        };
        match shown {
            Some(v) => writeln!(out, "{key_str:<16} = {v:<40}   [{}]", e.source.label())?,
            None => writeln!(
                out,
                "{key_str:<16} = {:<40}   [{}]",
                "(unset)",
                e.source.label()
            )?,
        }
    }
    Ok(())
}

fn run_get(key: &str) -> Result<()> {
    let cfg = load_config();
    let e = get_key(&cfg, key)?;
    match e.value {
        Some(v) => {
            println!("{v}");
            Ok(())
        }
        None => {
            // "unset" is a legitimate state, not an error. Print
            // nothing + exit 0 so shell composition works:
            //   BOOTINTEL_API_KEY="$(bootintel config get api_key)"
            // ...leaves the env var empty rather than aborting the shell.
            if matches!(e.source, Source::Unset) {
                Ok(())
            } else {
                bail!("no value for {key}")
            }
        }
    }
}

/// Persist `key = value` to the config file and echo the result on
/// stderr so the user has visible confirmation.
///
/// For `api_key`, the echoed value is masked (`...abcd`) — the full
/// value still exists on disk (0600) and in the caller's shell history
/// via `argv`. A future feature should offer an interactive-prompt
/// path (read via `rpassword`) so the key never touches argv; that's
/// out of scope for this security-hygiene release.
fn run_set(key: &str, value: &str) -> Result<()> {
    let path = set_key(key, value)?;
    // Mask the echo for api_key. Route through ConfigKey::from_str
    // so a future rename (e.g. api_key → api_token) can't skew this
    // check away from the actual keyed field.
    let shown = if matches!(ConfigKey::from_str(key), Some(ConfigKey::ApiKey)) {
        mask_secret(value)
    } else {
        value.to_string()
    };
    eprintln!("wrote {} = {} to {}", key, shown, path.display());
    Ok(())
}

fn run_edit() -> Result<()> {
    let path =
        config_path().context("no platform config dir resolvable (unset $HOME / $APPDATA?)")?;
    if !path.exists() {
        // Create an empty file first so the editor doesn't error out
        // on a nonexistent target + so the parent dir exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
            crate::config::restrict_dir_perms(parent)?;
        }
        std::fs::write(
            &path,
            "# bootintel config file — see `bootintel config list`\n",
        )
        .with_context(|| format!("creating {}", path.display()))?;
        // Even the stub gets 0600 — the user might paste an api_key
        // in during their editor session, so tighten now not later.
        crate::config::restrict_file_perms(&path)?;
    }
    let editor = pick_editor();
    let status = Command::new(&editor)
        .arg(&path)
        .status()
        .with_context(|| format!("spawning editor: {editor}"))?;
    if !status.success() {
        bail!("editor exited non-zero ({status})");
    }
    Ok(())
}

/// Editor discovery: $EDITOR → $VISUAL → platform-native fallback.
/// Order matches git's own convention.
fn pick_editor() -> String {
    if let Ok(v) = std::env::var("EDITOR") {
        if !v.is_empty() {
            return v;
        }
    }
    if let Ok(v) = std::env::var("VISUAL") {
        if !v.is_empty() {
            return v;
        }
    }
    if cfg!(windows) {
        "notepad".to_string()
    } else {
        // Prefer nano over vi as the "beginner-safe" fallback —
        // vi's modal editor is a well-documented usability
        // pitfall for users who didn't opt in.
        for candidate in &["nano", "vi", "vim"] {
            if which(candidate).is_some() {
                return (*candidate).to_string();
            }
        }
        "vi".to_string()
    }
}

fn which(name: &str) -> Option<std::path::PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_env) {
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Thin wrapper over the canonical `output::mask_tail` — keeps the
/// existing "keep the last 4 chars" convention for the config-list
/// display of api_key without forcing callers to remember the arg.
fn mask_secret(s: &str) -> String {
    crate::output::mask_tail(s, 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_hides_long_secret_tail() {
        assert_eq!(mask_secret("bik_abcdef1234"), "...1234");
    }

    #[test]
    fn mask_scrubs_short_secret() {
        assert_eq!(mask_secret("shrt"), "***");
    }

    /// The stderr echo emitted by `run_set` must never contain the
    /// full api_key. We build the exact echo string the way `run_set`
    /// does and assert on it.
    #[test]
    fn set_echo_masks_api_key() {
        let key = "api_key";
        let value = "bik_supersecretvaluezzz1234";
        let shown = if key.trim() == "api_key" {
            mask_secret(value)
        } else {
            value.to_string()
        };
        let echo = format!("wrote {} = {} to /fake/path", key, shown);
        assert!(echo.contains("1234"), "should keep last 4 for hint");
        assert!(!echo.contains("supersecret"), "must not leak middle");
        assert!(!echo.contains(value), "must not contain full value");
    }

    /// Non-secret values still print fully — regression guard so we
    /// don't over-mask fields like `api_base` or `default_format`.
    #[test]
    fn set_echo_shows_non_secret_full() {
        let key = "api_base";
        let value = "https://custom.example.com";
        let shown = if key.trim() == "api_key" {
            mask_secret(value)
        } else {
            value.to_string()
        };
        assert_eq!(shown, value);
    }

    #[test]
    fn pick_editor_respects_env() {
        let _g = crate::test_util::env_lock();
        // We can't rely on the ambient env (CI may set / unset any
        // of these). Just verify the algorithm on a scoped setter.
        let saved_editor = std::env::var("EDITOR").ok();
        let saved_visual = std::env::var("VISUAL").ok();
        std::env::set_var("EDITOR", "my-custom-editor");
        assert_eq!(pick_editor(), "my-custom-editor");
        std::env::remove_var("EDITOR");
        std::env::set_var("VISUAL", "my-visual");
        assert_eq!(pick_editor(), "my-visual");
        // Restore
        match saved_editor {
            Some(v) => std::env::set_var("EDITOR", v),
            None => std::env::remove_var("EDITOR"),
        }
        match saved_visual {
            Some(v) => std::env::set_var("VISUAL", v),
            None => std::env::remove_var("VISUAL"),
        }
    }
}
