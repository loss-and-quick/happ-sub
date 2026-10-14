//! Incy URL obfuscation (`incy://crypt1/`).
//!
//! INCY (`llc.itdev.incy`) hides a subscription URL behind a deeplink so that chat
//! scanners, moderation bots and screenshots do not expose the raw endpoint:
//!
//! ```text
//! incy://crypt1/<base64url( iv[12] || ciphertext || tag[16] )>
//! ```
//!
//! Parameters, measured from the 3.7.0 client (`llc.itdev.incy`, versionCode 370):
//! * Cipher: AES-256-GCM, 128-bit tag, no additional authenticated data
//! * IV/Nonce: 12 random bytes, one per link, used verbatim
//! * Plaintext: compact JSON with sorted keys, `{"n":<name>,"url":<url>,"v":1}`; the
//!   reader requires `url` and treats `n` as an optional display name
//!
//! # Key derivation
//!
//! ```text
//! K1 = SHA-256("incy" || "deep" || "crypt1" || "v2026.06" || A[1024:1056] || B[2048:2080])
//! ```
//!
//! `A` and `B` are the 4 KiB assets the client ships as `res/raw/incy_assets_a.bin` and
//! `res/raw/incy_assets_b.bin`. There is no secret input and no stretching, so `K1` is a
//! published constant; the same derivation appears in the vendor's own MIT reference
//! implementation [`INCY-DEV/incy-link-encoder`](https://github.com/INCY-DEV/incy-link-encoder).
//! The `builtin-incy-keys` feature embeds the two assets (provenance in [`crate::keys`]).
//!
//! # Scope
//!
//! This is obfuscation, not secrecy, exactly as the vendor states. The client is also an
//! encoder — its share and QR export path mints links with the same key — so
//! [`encrypt_link`] is provided for fixtures and tests, and a fresh IV must be used for
//! every plaintext that is not a test vector.

use crate::b64::decode_lenient;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

/// The only deep-link prefix this crate understands.
pub const PREFIX: &str = "incy://crypt1/";

/// Salt fragments concatenated ahead of the keymat windows by the key derivation.
pub const SALT_PARTS: [&str; 4] = ["incy", "deep", "crypt1", "v2026.06"];

/// Offset of the key window inside `incy_assets_a.bin`.
pub const KEYMAT_A_OFFSET: usize = 1024;

/// Offset of the key window inside `incy_assets_b.bin` (the client reuses the ML Kit
/// constant `Barcode.FORMAT_PDF417`, whose value is 2048).
pub const KEYMAT_B_OFFSET: usize = 2048;

/// Length of each keymat window, in bytes.
pub const KEYMAT_LEN: usize = 32;

/// Length of the AES-GCM nonce, in bytes.
pub const IV_LEN: usize = 12;

/// Length of the AES-GCM authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

/// Shortest accepted wire: nonce, tag and at least one ciphertext byte.
pub const MIN_WIRE_LEN: usize = IV_LEN + TAG_LEN + 1;

/// `SHA-256(K1)` of the shipped keymat, asserted by every reference implementation.
pub const EXPECTED_FINGERPRINT: &str =
    "b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c";

/// `SHA-256` of the two embedded keymat assets, pinned so a resync cannot drift silently.
pub const KEYMAT_A_SHA256: &str =
    "29047e8cbf382932a491608ae9202e3efe447f2739f81dca25b37019dc24d8f7";
/// `SHA-256` of the second embedded keymat asset.
pub const KEYMAT_B_SHA256: &str =
    "0cc7e650c25b10bd53587f01424bc901810ba6ea43af4dac49a3e7d9c5ac10ec";

/// The key pair shipped by INCY clients, ready for [`decrypt_link`].
///
/// Enable the `builtin-incy-keys` feature to embed it.
#[cfg(feature = "builtin-incy-keys")]
pub fn builtin_key() -> &'static [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let keymat: serde_json::Value = serde_json::from_str(crate::keys::INCY_KEYMAT_JSON)
            .expect("embedded incy-keymat.json is valid");
        let field = |name: &str| -> String {
            keymat
                .get(name)
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("embedded incy-keymat.json has no {name}"))
                .to_string()
        };
        let (a, b) = (
            decode_lenient(&field("keymat_a_b64")).expect("embedded keymat_a is base64"),
            decode_lenient(&field("keymat_b_b64")).expect("embedded keymat_b is base64"),
        );
        let key = derive_key(&a, &b).expect("embedded keymat is long enough");
        assert_eq!(
            hex_digest(&key),
            EXPECTED_FINGERPRINT,
            "embedded incy keymat does not derive the documented K1"
        );
        key
    })
}

/// The URL and optional display name carried by one `incy://crypt1/` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncyLink {
    /// The subscription URL, byte-identical to what the client encrypted. It may carry a
    /// `#remarks` suffix, because the client's own export path appends one before encoding.
    pub url: String,
    /// Provider name for the import sheet, absent when the plaintext had no non-empty `n`.
    pub name: Option<String>,
}

/// Errors during `incy://crypt1/` handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncyCryptError {
    /// The link does not start with `incy://crypt1/`.
    UnknownScheme(String),
    /// The payload was empty or not Base64 in either alphabet.
    Base64(String),
    /// The decoded wire is shorter than [`MIN_WIRE_LEN`].
    TooShort(usize),
    /// The keymat asset is too small for its key window.
    KeymatOutOfBounds {
        /// Which asset was short (`"a"` or `"b"`).
        which: char,
        /// Offset the key window starts at.
        offset: usize,
        /// The asset's length in bytes.
        len: usize,
    },
    /// AES-256-GCM authentication failed: wrong key or corrupted payload.
    AesGcmAuth,
    /// The plaintext was not UTF-8 JSON, or had no non-empty `url`.
    Plaintext(String),
}

impl std::fmt::Display for IncyCryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IncyCryptError::UnknownScheme(s) => write!(f, "unrecognized incy link: {s}"),
            IncyCryptError::Base64(m) => write!(f, "base64 decode error: {m}"),
            IncyCryptError::TooShort(len) => {
                write!(
                    f,
                    "decoded payload is {len} bytes, minimum is {MIN_WIRE_LEN}"
                )
            }
            IncyCryptError::KeymatOutOfBounds { which, offset, len } => write!(
                f,
                "keymat {which} is {len} bytes, needs {KEYMAT_LEN} at offset {offset}"
            ),
            IncyCryptError::AesGcmAuth => write!(f, "AES-256-GCM authentication failed"),
            IncyCryptError::Plaintext(m) => write!(f, "invalid incy plaintext: {m}"),
        }
    }
}

impl std::error::Error for IncyCryptError {}

/// Whether `link` looks like an `incy://crypt1/` deeplink (case-insensitive).
pub fn is_incy_link(link: &str) -> bool {
    strip_prefix(link.trim()).is_some()
}

fn strip_prefix(link: &str) -> Option<&str> {
    let (head, tail) = link.split_at_checked(PREFIX.len())?;
    head.eq_ignore_ascii_case(PREFIX).then_some(tail)
}

/// Derive `K1` from the two keymat assets.
///
/// The windows are bounds-checked, so a truncated asset is an error rather than a panic.
pub fn derive_key(keymat_a: &[u8], keymat_b: &[u8]) -> Result<[u8; 32], IncyCryptError> {
    let a = key_window(keymat_a, 'a', KEYMAT_A_OFFSET)?;
    let b = key_window(keymat_b, 'b', KEYMAT_B_OFFSET)?;

    let mut hasher = Sha256::new();
    for part in SALT_PARTS {
        hasher.update(part.as_bytes());
    }
    hasher.update(a);
    hasher.update(b);

    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

/// One key window of a keymat asset, bounds-checked so a short asset is an error, not a panic.
fn key_window(bytes: &[u8], which: char, offset: usize) -> Result<&[u8], IncyCryptError> {
    bytes
        .get(offset..offset + KEYMAT_LEN)
        .ok_or(IncyCryptError::KeymatOutOfBounds {
            which,
            offset,
            len: bytes.len(),
        })
}

/// The `SHA-256` of `key`, lower-case hex; the value to compare against
/// [`EXPECTED_FINGERPRINT`].
pub fn fingerprint(key: &[u8; 32]) -> String {
    hex_digest(key)
}

/// Decrypt a full `incy://crypt1/<payload>` link.
pub fn decrypt_link(link: &str, key: &[u8; 32]) -> Result<IncyLink, IncyCryptError> {
    let link = link.trim();
    let payload = strip_prefix(link)
        .ok_or_else(|| IncyCryptError::UnknownScheme(link.to_string()))?
        .trim_matches('/');
    decrypt_payload(payload, key)
}

/// Decrypt the payload of an `incy://crypt1/` link, without the scheme prefix.
///
/// The client is deliberately tolerant here, and so is this: path segments are joined,
/// newlines are stripped, and either Base64 alphabet is accepted with or without padding.
pub fn decrypt_payload(payload: &str, key: &[u8; 32]) -> Result<IncyLink, IncyCryptError> {
    let wire = decode_lenient(payload)
        .ok_or_else(|| IncyCryptError::Base64(format!("{} chars", payload.len())))?;
    if wire.len() < MIN_WIRE_LEN {
        return Err(IncyCryptError::TooShort(wire.len()));
    }

    let nonce = *Nonce::from_slice(&wire[..IV_LEN]);
    let cipher = Aes256Gcm::new_from_slice(key).expect("32 bytes is a valid AES-256-GCM key");
    let plaintext = cipher
        .decrypt(&nonce, &wire[IV_LEN..])
        .map_err(|_| IncyCryptError::AesGcmAuth)?;

    parse_plaintext(&plaintext)
}

/// Build the `incy://crypt1/` link for `url` and an optional `name` under `iv`.
///
/// The IV is a parameter so that tests and fixture builders are deterministic; production
/// callers must draw a fresh 12 bytes per link, as the client does with `SecureRandom`.
/// The plaintext uses sorted keys, matching every reference implementation byte for byte.
pub fn encrypt_link(url: &str, name: Option<&str>, key: &[u8; 32], iv: [u8; IV_LEN]) -> String {
    let mut fields: Vec<(&str, String)> = vec![("url", json_string(url))];
    if let Some(name) = name.filter(|n| !n.is_empty()) {
        fields.push(("n", json_string(name)));
    }
    fields.push(("v", "1".to_string()));
    fields.sort_by_key(|(k, _)| *k);
    let plaintext = format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(k, v)| format!("{}:{}", json_string(k), v))
            .collect::<Vec<_>>()
            .join(",")
    );

    let cipher = Aes256Gcm::new_from_slice(key).expect("32 bytes is a valid AES-256-GCM key");
    let sealed = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
        .expect("AES-256-GCM encryption cannot fail");

    let mut wire = Vec::with_capacity(IV_LEN + sealed.len());
    wire.extend_from_slice(&iv);
    wire.extend_from_slice(&sealed);
    format!("{PREFIX}{}", url_safe_no_pad(&wire))
}

fn parse_plaintext(plaintext: &[u8]) -> Result<IncyLink, IncyCryptError> {
    let value: serde_json::Value = serde_json::from_slice(plaintext)
        .map_err(|e| IncyCryptError::Plaintext(format!("not JSON: {e}")))?;

    let url = value
        .get("url")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| IncyCryptError::Plaintext("no non-empty url field".into()))?
        .to_string();

    let name = value
        .get("n")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Ok(IncyLink { url, name })
}

/// JSON string escaping matching the client's hand-rolled builder: quotes, backslash and
/// C0 controls only, which is what the vendor's encoder emits for provider names.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn url_safe_no_pad(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hex_digest(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic stand-in for the shipped keymat: any 4 KiB pair whose windows are known.
    fn test_keymat() -> (Vec<u8>, Vec<u8>) {
        let mut a = vec![0x11u8; 4096];
        let mut b = vec![0x22u8; 4096];
        a[KEYMAT_A_OFFSET..KEYMAT_A_OFFSET + KEYMAT_LEN].copy_from_slice(&[0xa5; KEYMAT_LEN]);
        b[KEYMAT_B_OFFSET..KEYMAT_B_OFFSET + KEYMAT_LEN].copy_from_slice(&[0x5a; KEYMAT_LEN]);
        (a, b)
    }

    #[test]
    fn derive_key_matches_the_documented_computation() {
        let (a, b) = test_keymat();
        let key = derive_key(&a, &b).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"incydeepcrypt1v2026.06");
        hasher.update([0xa5u8; KEYMAT_LEN]);
        hasher.update([0x5au8; KEYMAT_LEN]);
        let expected = hasher.finalize();

        assert_eq!(key.as_slice(), expected.as_slice());
        assert_ne!(hex_digest(&key), EXPECTED_FINGERPRINT);
        assert_eq!(hex_digest(&key), fingerprint(&key));
    }

    #[test]
    fn derive_key_reports_short_assets_instead_of_panicking() {
        let (a, b) = test_keymat();
        assert_eq!(
            derive_key(&a[..10], &b),
            Err(IncyCryptError::KeymatOutOfBounds {
                which: 'a',
                offset: KEYMAT_A_OFFSET,
                len: 10
            })
        );
        assert_eq!(
            derive_key(&a, &b[..KEYMAT_B_OFFSET]),
            Err(IncyCryptError::KeymatOutOfBounds {
                which: 'b',
                offset: KEYMAT_B_OFFSET,
                len: 2048
            })
        );
    }

    #[test]
    fn round_trip_keeps_url_and_name() {
        let (a, b) = test_keymat();
        let key = derive_key(&a, &b).unwrap();
        let iv = [0x0au8; IV_LEN];

        for (url, name) in [
            ("https://example.com/sub", None),
            ("https://example.com/sub#Remarks", Some("Probe Provider")),
            ("https://example.com/ü", Some("Имя")),
        ] {
            let link = encrypt_link(url, name, &key, iv);
            assert!(link.starts_with(PREFIX));
            assert_eq!(
                decrypt_link(&link, &key).unwrap(),
                IncyLink {
                    url: url.to_string(),
                    name: name.map(str::to_string),
                }
            );
        }
    }

    #[test]
    fn an_absent_or_empty_name_is_reported_as_none() {
        let (a, b) = test_keymat();
        let key = derive_key(&a, &b).unwrap();
        let link = encrypt_link("https://example.com/x", Some(""), &key, [0u8; IV_LEN]);
        assert_eq!(decrypt_link(&link, &key).unwrap().name, None);
    }

    #[test]
    fn plaintext_keys_are_sorted() {
        let (a, b) = test_keymat();
        let key = derive_key(&a, &b).unwrap();
        let link = encrypt_link("https://example.com/x", Some("N"), &key, [0u8; IV_LEN]);

        let wire = decode_lenient(&link[PREFIX.len()..]).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&wire[..IV_LEN]), &wire[IV_LEN..])
            .unwrap();
        assert_eq!(
            String::from_utf8(plaintext).unwrap(),
            r#"{"n":"N","url":"https://example.com/x","v":1}"#
        );
    }

    #[test]
    fn transport_tolerance_matches_the_client() {
        let (a, b) = test_keymat();
        let key = derive_key(&a, &b).unwrap();
        let link = encrypt_link("https://example.com/x", None, &key, [0u8; IV_LEN]);
        let payload = &link[PREFIX.len()..];

        // Upper-case scheme, a trailing slash and wrapped, standard-alphabet base64.
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let standard = STANDARD.encode(decode_lenient(payload).unwrap());
        let wrapped = standard
            .as_bytes()
            .chunks(40)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        let sloppy = format!("{}/", link.replace(PREFIX, "INCY://CRYPT1/"));

        for candidate in [
            link.clone(),
            sloppy,
            format!("{PREFIX}{payload}/"),
            format!("{PREFIX}{wrapped}"),
        ] {
            assert_eq!(
                decrypt_link(&candidate, &key).unwrap().url,
                "https://example.com/x",
                "{candidate}"
            );
        }
    }

    #[test]
    fn rejects_malformed_input_with_typed_errors() {
        let (a, b) = test_keymat();
        let key = derive_key(&a, &b).unwrap();

        assert!(matches!(
            decrypt_link("happ://crypt5/abc", &key),
            Err(IncyCryptError::UnknownScheme(_))
        ));
        assert!(matches!(
            decrypt_link(PREFIX, &key),
            Err(IncyCryptError::TooShort(0))
        ));
        assert!(matches!(
            decrypt_payload("not base64 !!", &key),
            Err(IncyCryptError::Base64(_))
        ));

        let short = format!("{PREFIX}{}", url_safe_no_pad(&[0u8; MIN_WIRE_LEN - 1]));
        assert_eq!(
            decrypt_link(&short, &key),
            Err(IncyCryptError::TooShort(MIN_WIRE_LEN - 1))
        );

        let link = encrypt_link("https://example.com/x", None, &key, [0u8; IV_LEN]);
        let mut tampered = link.clone().into_bytes();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        let tampered = String::from_utf8(tampered).unwrap();
        assert_eq!(
            decrypt_link(&tampered, &key),
            Err(IncyCryptError::AesGcmAuth)
        );

        assert_eq!(
            decrypt_link(&link, &[0x00; 32]),
            Err(IncyCryptError::AesGcmAuth)
        );
    }

    #[test]
    fn plaintext_without_a_url_is_rejected() {
        let (a, b) = test_keymat();
        let key = derive_key(&a, &b).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();

        for plaintext in [r#"{"v":1}"#, r#"{"url":""}"#, r#"{"url":7}"#, "not json"] {
            let sealed = cipher.encrypt(Nonce::from_slice(&[0u8; IV_LEN]), plaintext.as_bytes());
            let mut wire = vec![0u8; IV_LEN];
            wire.extend_from_slice(&sealed.unwrap());
            let link = format!("{PREFIX}{}", url_safe_no_pad(&wire));
            assert!(
                matches!(decrypt_link(&link, &key), Err(IncyCryptError::Plaintext(_))),
                "{plaintext}"
            );
        }
    }

    #[test]
    fn is_incy_link_is_case_insensitive_and_never_panics_on_short_input() {
        assert!(is_incy_link("incy://crypt1/AAAA"));
        assert!(is_incy_link("  INCY://CRYPT1/AAAA  "));
        assert!(!is_incy_link("incy://crypt2/AAAA"));
        assert!(!is_incy_link("incy:/"));
        assert!(!is_incy_link(""));
        assert!(!is_incy_link("é".repeat(20).as_str()));
    }
}
