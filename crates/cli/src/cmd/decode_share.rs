//! `bootintel decode-share <url>` — reverse the lz-string compression
//! of a bootintel.com fingerprint URL back to the original boot log.
//!
//! Accepts three input shapes so the caller doesn't have to pre-clean:
//!   - Full URL: `https://bootintel.com/tools/fingerprint?z=<COMPRESSED>`
//!   - Query fragment: `?z=<COMPRESSED>`
//!   - Raw compressed: `<COMPRESSED>`
//!
//! Also accepts `-` to read the URL from stdin (paste-friendly).

use anyhow::{bail, Context, Result};
use clap::Args as ClapArgs;
use std::io::{self, Read, Write};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// URL / fragment / compressed value, or `-` to read from stdin.
    #[arg(value_name = "URL")]
    url: String,
}

pub fn run(args: Args) -> Result<()> {
    let input = if args.url == "-" {
        let mut s = String::new();
        io::stdin()
            .read_to_string(&mut s)
            .context("reading stdin")?;
        s.trim().to_string()
    } else {
        args.url.clone()
    };

    let compressed = extract_z_value(&input)?;
    let decoded_u16 = lz_str::decompress_from_encoded_uri_component(&compressed)
        .ok_or_else(|| anyhow::anyhow!(
            "decompression failed — the `z=` value doesn't look like an lz-string-compressed payload.\n  \
             Check the URL was copied intact (no truncation, no double URL-encoding)."
        ))?;
    check_decoded_size(&decoded_u16)?;

    // lz-string operates on u16 codepoints; the source log is UTF-8
    // text, so re-encode. String::from_utf16_lossy trades U+FFFD for
    // any invalid pair — matches the browser tool's behavior.
    let text = String::from_utf16_lossy(&decoded_u16);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(text.as_bytes())?;
    if !text.ends_with('\n') {
        writeln!(out)?;
    }
    let _ = out.flush();
    Ok(())
}

/// Cap on the size of the decompressed payload, in UTF-16 code units.
/// A well-behaved boot log is well under 200 KiB (the browser-side
/// share cap in `MAX_INPUT_BYTES_FOR_SHARE`); 4 Mi code units (~8 MiB
/// worst-case UTF-16 buffer) is 20× headroom while still catching a
/// crafted lz-string payload that would decompress to hundreds of
/// megabytes of RAM ("decompression bomb").
const MAX_DECODED_UTF16_LEN: usize = 4 * 1024 * 1024;

fn check_decoded_size(decoded: &[u16]) -> Result<()> {
    if decoded.len() > MAX_DECODED_UTF16_LEN {
        bail!(
            "decoded payload is {} code units, exceeds the {MAX_DECODED_UTF16_LEN}-code-unit cap; \
             refusing (possible decompression bomb). Real boot logs are well under 200 KiB.",
            decoded.len()
        );
    }
    Ok(())
}

/// Pull the `z=` value out of whatever the user pasted. Tolerant of
/// full URLs, bare query strings, and raw compressed values.
fn extract_z_value(input: &str) -> Result<String> {
    // If it contains `z=`, take everything after (up to the next `&`
    // or end-of-string). Otherwise assume the caller passed the raw
    // compressed value.
    if let Some(idx) = input.find("z=") {
        let after = &input[idx + 2..];
        let end = after.find('&').unwrap_or(after.len());
        let val = &after[..end];
        if val.is_empty() {
            bail!("found `z=` but the value was empty");
        }
        return Ok(val.to_string());
    }
    // Bare compressed value — lz-string encoded output uses only
    // [A-Za-z0-9+/=_-] chars. If the input has whitespace or looks
    // like a URL scheme, that's probably an accident.
    let trimmed = input.trim();
    if trimmed.is_empty() {
        bail!("empty input");
    }
    if trimmed.contains("://") && !trimmed.contains("z=") {
        bail!(
            "input looks like a URL but has no `z=` parameter.\n  \
             Expected a bootintel.com share URL, or the raw compressed value."
        );
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_full_url() {
        let u = "https://bootintel.com/tools/fingerprint?z=ABC123";
        assert_eq!(extract_z_value(u).unwrap(), "ABC123");
    }

    #[test]
    fn extract_from_query_fragment() {
        assert_eq!(extract_z_value("?z=ABC123").unwrap(), "ABC123");
        assert_eq!(extract_z_value("z=ABC123").unwrap(), "ABC123");
    }

    #[test]
    fn extract_stops_at_ampersand() {
        assert_eq!(
            extract_z_value("https://x.com/y?z=ABC&other=1").unwrap(),
            "ABC"
        );
    }

    #[test]
    fn extract_raw_compressed() {
        assert_eq!(extract_z_value("BASE64ISHDATA").unwrap(), "BASE64ISHDATA");
    }

    #[test]
    fn extract_rejects_url_without_z() {
        let err = extract_z_value("https://example.com/notabootintelurl").unwrap_err();
        assert!(err.to_string().contains("z="), "got: {err}");
    }

    #[test]
    fn round_trip_matches_original() {
        let original = "U-Boot 2020.10\nModel: TP-Link Archer C7 v5\n";
        let encoded = lz_str::compress_to_encoded_uri_component(original);
        let decoded_u16 = lz_str::decompress_from_encoded_uri_component(&encoded).unwrap();
        let decoded = String::from_utf16_lossy(&decoded_u16);
        assert_eq!(decoded, original);
    }

    #[test]
    fn size_cap_accepts_realistic_boot_log() {
        // A ~200 KiB code-unit buffer is well under the cap and models
        // the browser share limit for a fully-loaded boot log.
        let realistic: Vec<u16> = vec![b'A' as u16; 200 * 1024];
        assert!(check_decoded_size(&realistic).is_ok());
    }

    #[test]
    fn size_cap_rejects_oversize_payload() {
        // One code unit past the cap should hard-fail.
        let bomb: Vec<u16> = vec![0; MAX_DECODED_UTF16_LEN + 1];
        let err = check_decoded_size(&bomb).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("decompression bomb"), "got: {msg}");
        assert!(msg.contains("refusing"), "got: {msg}");
    }
}
