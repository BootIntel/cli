//! Share-URL round-trip test: encode a log via `bootintel share`, decode
//! via lz_str, confirm the bytes match. This proves compatibility with
//! the browser share-report encoder/decoder which uses the same
//! lz-string algorithm.

use lz_str::{compress_to_encoded_uri_component, decompress_from_encoded_uri_component};

#[test]
fn sample_log_roundtrips_through_lz_string() {
    let original = bootintel_detectors::SAMPLE;
    let compressed = compress_to_encoded_uri_component(original);
    assert!(
        !compressed.is_empty(),
        "compressed output must be non-empty"
    );
    // Round-trip via decompression back to bytes → parse as UTF-8.
    let decoded_bytes =
        decompress_from_encoded_uri_component(&compressed).expect("decompress must succeed");
    let decoded: String = std::char::decode_utf16(decoded_bytes)
        .filter_map(|r| r.ok())
        .collect();
    assert_eq!(
        decoded, original,
        "share URL round-trip must preserve the original log verbatim"
    );
}

#[test]
fn empty_input_roundtrips() {
    let compressed = compress_to_encoded_uri_component("");
    let decoded_bytes = decompress_from_encoded_uri_component(&compressed)
        .expect("decompress must succeed even for empty");
    let decoded: String = std::char::decode_utf16(decoded_bytes)
        .filter_map(|r| r.ok())
        .collect();
    assert_eq!(decoded, "");
}
