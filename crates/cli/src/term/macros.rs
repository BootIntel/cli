//! Function-key macros: bind F1..F12 to a byte string that's sent
//! to the serial port when the key is pressed.
//!
//! Two sources merged into a single MacroTable at startup:
//!   1. `~/.config/bootintel/macros` (or the OS-appropriate config
//!      dir) — one `Fn=value` line per macro, optional `#` comments.
//!   2. `--macro Fn=value` repeatable CLI flag — overrides the file.
//!
//! Values support the standard escape sequences you'd type in a
//! shell single-quoted string: `\r`, `\n`, `\t`, `\0`, `\\`, `\xHH`.
//! Anything else after a backslash is a parse error rather than a
//! silent literal — matches sh strict mode + spares the user from
//! debugging "why did my `\a` not do the thing".
//!
//! Runtime: a KeyEvent for a function key is checked against the
//! table BEFORE the hotkey state machine sees it, so macros pre-empt
//! the normal encode-key path. Miss → normal encoding continues.

use crossterm::event::{KeyCode, KeyEvent};
use std::collections::HashMap;
use std::path::PathBuf;

/// Function-key numeric index (1..=12).
type FKey = u8;

#[derive(Debug, Default, Clone)]
pub struct MacroTable {
    map: HashMap<FKey, Vec<u8>>,
}

impl MacroTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Insert (or replace) the macro for a given function key.
    pub fn insert(&mut self, k: FKey, value: Vec<u8>) {
        self.map.insert(k, value);
    }

    /// Return the bytes bound to this KeyEvent, or None if the key
    /// isn't a function key or isn't bound.
    pub fn lookup(&self, k: &KeyEvent) -> Option<&[u8]> {
        match k.code {
            KeyCode::F(n) if (1..=12).contains(&n) => self.map.get(&n).map(|v| v.as_slice()),
            _ => None,
        }
    }

    /// List bindings sorted by function key for a --help-style dump.
    pub fn entries(&self) -> Vec<(FKey, &[u8])> {
        let mut v: Vec<_> = self
            .map
            .iter()
            .map(|(k, val)| (*k, val.as_slice()))
            .collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }
}

/// Parse a `Fn=value` spec into (function key number, decoded bytes).
/// Case-insensitive on the `F`; `f3` and `F3` both work.
pub fn parse_spec(spec: &str) -> Result<(FKey, Vec<u8>), String> {
    let (key_part, val_part) = spec
        .split_once('=')
        .ok_or_else(|| format!("macro spec must be Fn=value (got: {spec})"))?;
    let k = parse_fkey_name(key_part)
        .ok_or_else(|| format!("not a function key: '{key_part}' (want F1..F12)"))?;
    let bytes =
        decode_escapes(val_part).map_err(|e| format!("bad escape in macro F{k} value: {e}"))?;
    Ok((k, bytes))
}

fn parse_fkey_name(s: &str) -> Option<FKey> {
    let trimmed = s.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let (head, rest) = trimmed.split_at(1);
    if !head.eq_ignore_ascii_case("F") {
        return None;
    }
    let n: u8 = rest.parse().ok()?;
    if (1..=12).contains(&n) {
        Some(n)
    } else {
        None
    }
}

/// Decode shell-style escape sequences into raw bytes.
///
/// Recognized:
///   \r \n \t \0 \\ \" \'
///   \xHH  (two hex digits)
///
/// Everything else after a backslash is an error. Bare bytes pass
/// through unchanged (UTF-8 in → UTF-8 out).
fn decode_escapes(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let esc = chars
            .next()
            .ok_or_else(|| "trailing backslash".to_string())?;
        let byte: u8 = match esc {
            'r' => b'\r',
            'n' => b'\n',
            't' => b'\t',
            '0' => 0,
            '\\' => b'\\',
            '"' => b'"',
            '\'' => b'\'',
            'x' => {
                let h1 = chars
                    .next()
                    .ok_or_else(|| "\\x needs two hex digits".to_string())?;
                let h2 = chars
                    .next()
                    .ok_or_else(|| "\\x needs two hex digits".to_string())?;
                let hi = h1
                    .to_digit(16)
                    .ok_or_else(|| format!("\\x: '{h1}' isn't hex"))?;
                let lo = h2
                    .to_digit(16)
                    .ok_or_else(|| format!("\\x: '{h2}' isn't hex"))?;
                (hi * 16 + lo) as u8
            }
            other => return Err(format!("unknown escape '\\{other}'")),
        };
        out.push(byte);
    }
    Ok(out)
}

/// Resolve the config file path. Follows XDG (`$XDG_CONFIG_HOME` then
/// `$HOME/.config`) on Unix; on Windows uses `%APPDATA%\bootintel`.
/// Returns None if we can't figure out a reasonable path.
pub fn default_config_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("bootintel").join("macros"))
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("APPDATA").map(PathBuf::from)?;
        Some(base.join("bootintel").join("macros"))
    }
}

/// Parse a config file. Lines starting with `#` (or blank) are
/// ignored; every other line must be a valid `Fn=value` spec.
/// Errors carry the line number so users can find the typo.
pub fn parse_config_file(text: &str) -> Result<MacroTable, String> {
    let mut table = MacroTable::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, bytes) = parse_spec(line).map_err(|e| format!("line {}: {e}", i + 1))?;
        table.insert(k, bytes);
    }
    Ok(table)
}

/// Compose a fresh table from (optional) config file path + CLI specs.
/// CLI overrides file. Missing file is not an error (returns empty +
/// applies CLI); malformed file IS an error.
pub fn build(
    config_path: Option<&std::path::Path>,
    cli_specs: &[String],
) -> Result<MacroTable, String> {
    let mut table = match config_path {
        Some(p) if p.is_file() => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| format!("reading macro config {}: {e}", p.display()))?;
            parse_config_file(&text)?
        }
        _ => MacroTable::new(),
    };
    for spec in cli_specs {
        let (k, bytes) = parse_spec(spec)?;
        table.insert(k, bytes);
    }
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyModifiers};

    #[test]
    fn parse_basic_spec() {
        let (k, b) = parse_spec("F1=help\\r").unwrap();
        assert_eq!(k, 1);
        assert_eq!(b, b"help\r".to_vec());
    }

    #[test]
    fn parse_case_insensitive_fkey() {
        let (k, _) = parse_spec("f7=hi").unwrap();
        assert_eq!(k, 7);
    }

    #[test]
    fn parse_rejects_out_of_range_fkey() {
        assert!(parse_spec("F13=nope").is_err());
        assert!(parse_spec("F0=nope").is_err());
    }

    #[test]
    fn parse_rejects_missing_equals() {
        assert!(parse_spec("F1help").is_err());
    }

    #[test]
    fn decode_all_supported_escapes() {
        let b = decode_escapes(r"\r\n\t\0\\\x1b\x7f").unwrap();
        assert_eq!(b, vec![b'\r', b'\n', b'\t', 0, b'\\', 0x1b, 0x7f]);
    }

    #[test]
    fn decode_rejects_unknown_escape() {
        assert!(decode_escapes(r"\a").is_err());
    }

    #[test]
    fn decode_rejects_trailing_backslash() {
        assert!(decode_escapes(r"foo\").is_err());
    }

    #[test]
    fn decode_rejects_short_hex() {
        assert!(decode_escapes(r"\x1").is_err());
        assert!(decode_escapes(r"\x").is_err());
        assert!(decode_escapes(r"\xZZ").is_err());
    }

    #[test]
    fn lookup_matches_fn_only_when_bound() {
        let mut t = MacroTable::new();
        t.insert(1, b"go\r".to_vec());
        let f1 = KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE);
        let f2 = KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE);
        let a = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        assert_eq!(t.lookup(&f1), Some(&b"go\r"[..]));
        assert_eq!(t.lookup(&f2), None);
        assert_eq!(t.lookup(&a), None);
    }

    #[test]
    fn config_file_parse_comments_blank_lines() {
        let text = r#"
# u-boot shortcuts
F1=printenv\r

# reset with pause
F5=reset\r
"#;
        let t = parse_config_file(text).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t.entries()[0], (1, &b"printenv\r"[..]));
        assert_eq!(t.entries()[1], (5, &b"reset\r"[..]));
    }

    #[test]
    fn config_file_error_carries_line_number() {
        let text = "F1=ok\r\nF13=bad";
        let err = parse_config_file(text).unwrap_err();
        assert!(err.starts_with("line 2:"), "got: {err}");
    }

    #[test]
    fn build_cli_overrides_file() {
        // Write a temp config file with F1=foo + F2=only-file, then
        // override F1 via CLI. F2 stays as the file value. Line
        // terminators (\n or \r\n) are stripped by str::lines() so
        // the parsed value is just the bytes before the newline.
        let dir = std::env::temp_dir();
        let path = dir.join("bootintel-macros-test.txt");
        std::fs::write(&path, "F1=foo\nF2=only-file\n").unwrap();
        let table = build(Some(&path), &["F1=bar".to_string()]).unwrap();
        assert_eq!(
            table.entries().iter().find(|(k, _)| *k == 1).unwrap().1,
            &b"bar"[..]
        );
        assert_eq!(
            table.entries().iter().find(|(k, _)| *k == 2).unwrap().1,
            &b"only-file"[..]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn build_missing_file_is_ok() {
        let table = build(
            Some(std::path::Path::new("/nonexistent/bootintel/macros")),
            &["F3=hi".to_string()],
        )
        .unwrap();
        assert_eq!(table.len(), 1);
    }
}
