//! Lenient Base64 decoding shared by every layer of the envelope.
//!
//! Providers emit standard and URL-safe alphabets, with or without padding, and v2ray-style
//! subscriptions are often wrapped at 76 columns; Android's `Base64.DEFAULT` decoder accepts all
//! of these, so a strict decoder would reject bodies the vendor client imports.

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;

const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Decode standard or URL-safe Base64, padded or not, ignoring ASCII whitespace.
pub(crate) fn decode_lenient(s: &str) -> Option<Vec<u8>> {
    let normalized: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    LENIENT.decode(normalized).ok()
}

/// Whether `s` consists only of Base64 alphabet characters (either alphabet) and whitespace.
pub(crate) fn is_base64_text(s: &str) -> bool {
    let mut any = false;
    for c in s.chars() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if !(c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '=')) {
            return false;
        }
        any = true;
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    #[test]
    fn accepts_every_alphabet_and_padding_variant() {
        let data = b"\xfb\xff\xfe subscription?";
        for engine in [&STANDARD, &URL_SAFE, &STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
            let enc = engine.encode(data);
            assert_eq!(decode_lenient(&enc).as_deref(), Some(&data[..]), "{enc}");
        }
    }

    #[test]
    fn ignores_line_wrapping() {
        let data = vec![b'x'; 200];
        let enc = STANDARD.encode(&data);
        let wrapped: Vec<&str> = enc
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        assert_eq!(decode_lenient(&wrapped.join("\r\n")), Some(data));
    }

    #[test]
    fn rejects_non_alphabet() {
        assert_eq!(decode_lenient("vless://a@b:1"), None);
        assert!(!is_base64_text("vless://a@b:1"));
        assert!(!is_base64_text("  \n"));
    }
}
