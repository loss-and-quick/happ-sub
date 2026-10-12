//! Subscription body decryption (AES-128-GCM, 90 built-in keys).
//!
//! A Happ provider hides subscription contents by encrypting the body with
//! AES-128-GCM using one of 90 built-in keys selected by the `?key=keyNN` URL query
//! parameter. The GCM authentication tag is returned in the `Encrypt-Tag` header.
//!
//! Parameters (fixed by upstream specification):
//! * Cipher: AES-128-GCM, 128-bit tag (16 bytes)
//! * IV/Nonce: 12 ASCII bytes `b"kkkkkkkkkkkk"` (constant across all requests)
//! * Key: Full 16-byte key entry string verbatim (e.g. `b"key02:+]%4ij#P\"/"`)
//!
//! # Security Warning
//! The fixed IV (`kkkkkkkkkkkk`) is a cryptographic protocol flaw of the upstream vendor.
//! This implementation exists strictly for client-side subscription import compatibility
//! and must **never** be used for serving subscriptions.

use crate::b64::decode_lenient;
use crate::keys::{KeyTable, ALL_TABLES};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Key, Nonce};

/// The fixed 12-byte GCM initialization vector used by Happ.
pub const NONCE: &[u8; 12] = b"kkkkkkkkkkkk";

/// Source of key tables for body decryption.
#[derive(Debug, Clone, Copy)]
pub enum BodyKeySource<'a> {
    /// Caller pins a specific known key table generation.
    Pinned(&'a KeyTable),
    /// Automatic try-all from newest to oldest, using GCM authentication as discriminator.
    Auto {
        /// Candidate tables, iterated in order.
        tables: &'a [&'a KeyTable],
    },
}

impl<'a> Default for BodyKeySource<'a> {
    fn default() -> Self {
        BodyKeySource::Auto { tables: ALL_TABLES }
    }
}

/// Successful body decryption outcome recording which table authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted<'a> {
    /// Identifier of the table that authenticated the payload (e.g. `"gen1-4.3.0..4.7.1"`).
    pub table_id: &'a str,
    /// Key ID used (e.g. `"key02"`).
    pub key_id: String,
    /// Decrypted plaintext bytes.
    pub plaintext: Vec<u8>,
}

/// Errors occurring during subscription body decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyCryptError {
    /// The specified `key_id` was not found in the key table.
    UnknownKeyId(String),
    /// The `Encrypt-Tag` header value was malformed or not exactly 16 bytes.
    WrongTag(String),
    /// Base64 decoding failed for ciphertext or tag.
    Base64(String),
    /// AES-GCM authentication failed (wrong key or corrupted ciphertext/tag).
    AesGcmAuth,
    /// None of the candidate key tables authenticated the payload.
    NoTableAuthenticated,
}

impl std::fmt::Display for BodyCryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyCryptError::UnknownKeyId(id) => write!(f, "unknown key ID {id:?}"),
            BodyCryptError::WrongTag(msg) => write!(f, "invalid Encrypt-Tag: {msg}"),
            BodyCryptError::Base64(what) => write!(f, "base64 decode failed for {what}"),
            BodyCryptError::AesGcmAuth => write!(f, "AES-GCM authentication failed"),
            BodyCryptError::NoTableAuthenticated => {
                write!(f, "none of the candidate key tables authenticated the body")
            }
        }
    }
}

impl std::error::Error for BodyCryptError {}

/// Decrypt an encrypted subscription body with the specified key source.
pub fn decrypt_body<'a>(
    src: BodyKeySource<'a>,
    key_id: &str,
    body_b64: &str,
    tag_b64: &str,
) -> Result<Decrypted<'a>, BodyCryptError> {
    match src {
        BodyKeySource::Pinned(table) => {
            let plain = decrypt_with_table(table, key_id, body_b64, tag_b64)?;
            Ok(Decrypted {
                table_id: table.id,
                key_id: key_id.to_string(),
                plaintext: plain,
            })
        }
        BodyKeySource::Auto { tables } => {
            if tables.is_empty() {
                return Err(BodyCryptError::NoTableAuthenticated);
            }
            // Tag and body Base64 errors are invariant across tables: validate once.
            let tag_bytes = decode_tag(tag_b64)?;
            let ct_bytes = decode_body(body_b64)?;

            let mut key_known = false;
            for table in tables {
                if let Some(key_bytes) = table.get(key_id) {
                    key_known = true;
                    if let Ok(plain) = decrypt_raw(key_bytes, &ct_bytes, &tag_bytes) {
                        return Ok(Decrypted {
                            table_id: table.id,
                            key_id: key_id.to_string(),
                            plaintext: plain,
                        });
                    }
                }
            }
            if key_known {
                Err(BodyCryptError::AesGcmAuth)
            } else {
                Err(BodyCryptError::UnknownKeyId(key_id.to_string()))
            }
        }
    }
}

/// Decrypt using a specific key table.
pub fn decrypt_with_table(
    table: &KeyTable,
    key_id: &str,
    body_b64: &str,
    tag_b64: &str,
) -> Result<Vec<u8>, BodyCryptError> {
    let key = table
        .get(key_id)
        .ok_or_else(|| BodyCryptError::UnknownKeyId(key_id.to_string()))?;
    let tag = decode_tag(tag_b64)?;
    let ct = decode_body(body_b64)?;
    decrypt_raw(key, &ct, &tag)
}

fn decode_body(body_b64: &str) -> Result<Vec<u8>, BodyCryptError> {
    decode_lenient(body_b64).ok_or_else(|| BodyCryptError::Base64("body".into()))
}

fn decode_tag(tag_b64: &str) -> Result<Vec<u8>, BodyCryptError> {
    let tag = decode_lenient(tag_b64)
        .ok_or_else(|| BodyCryptError::WrongTag("base64 decode failed".into()))?;
    if tag.len() != 16 {
        return Err(BodyCryptError::WrongTag(format!(
            "tag must be 16 bytes, got {}",
            tag.len()
        )));
    }
    Ok(tag)
}

fn decrypt_raw(key: &[u8; 16], ct: &[u8], tag: &[u8]) -> Result<Vec<u8>, BodyCryptError> {
    let mut input = Vec::with_capacity(ct.len() + tag.len());
    input.extend_from_slice(ct);
    input.extend_from_slice(tag);

    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(NONCE);
    cipher
        .decrypt(nonce, input.as_ref())
        .map_err(|_| BodyCryptError::AesGcmAuth)
}

/// Encrypt a payload the way a Happ provider does, returning `(body_b64, tag_b64)`.
///
/// Exposed under the `test-vectors` feature so downstream crates can build fixtures. Never use
/// it to serve subscriptions: the fixed nonce lets anyone forge bodies under the same key.
#[cfg(any(test, feature = "test-vectors"))]
pub fn encrypt_with_table(
    table: &KeyTable,
    key_id: &str,
    plaintext: &[u8],
) -> Result<(String, String), BodyCryptError> {
    let key = table
        .get(key_id)
        .ok_or_else(|| BodyCryptError::UnknownKeyId(key_id.to_string()))?;
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(NONCE);
    let output = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| BodyCryptError::AesGcmAuth)?;
    let split = output.len() - 16;
    let (ct, tag) = output.split_at(split);
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    Ok((STANDARD.encode(ct), STANDARD.encode(tag)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::DEFAULT_TABLE;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    #[test]
    fn auto_source_reports_unknown_key_id() {
        let (body_b64, tag_b64) = encrypt_with_table(DEFAULT_TABLE, "key01", b"hello").unwrap();
        assert_eq!(
            decrypt_body(BodyKeySource::default(), "key99", &body_b64, &tag_b64),
            Err(BodyCryptError::UnknownKeyId("key99".into()))
        );
    }

    #[test]
    fn line_wrapped_body_decrypts() {
        let plain = vec![b'v'; 300];
        let (body_b64, tag_b64) = encrypt_with_table(DEFAULT_TABLE, "key07", &plain).unwrap();
        let wrapped = body_b64
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let res = decrypt_body(BodyKeySource::default(), "key07", &wrapped, &tag_b64).unwrap();
        assert_eq!(res.plaintext, plain);
    }

    const DOC_KEY02: &[u8; 16] = b"key02:+]%4ij#P\"/";

    #[test]
    fn all_90_keys_present_and_16_bytes() {
        assert_eq!(DEFAULT_TABLE.entries.len(), 90);
        for (id, key) in DEFAULT_TABLE.entries {
            assert_eq!(key.len(), 16, "key {id} must be 16 bytes");
        }
    }

    #[test]
    fn keyids_are_key01_through_key90() {
        for (i, (id, _)) in DEFAULT_TABLE.entries.iter().enumerate() {
            let expected = format!("key{:02}", i + 1);
            assert_eq!(*id, expected.as_str());
        }
    }

    #[test]
    fn key02_matches_vendor_documentation() {
        assert_eq!(DEFAULT_TABLE.get("key02").unwrap(), DOC_KEY02);
    }

    #[test]
    fn round_trip_sample_keys() {
        for id in [
            "key01", "key02", "key05", "key30", "key45", "key60", "key90",
        ] {
            let sample = b"#profile-title: test\nvless://uuid@host:443#srv\n";
            let (body_b64, tag_b64) = encrypt_with_table(DEFAULT_TABLE, id, sample).unwrap();
            let res = decrypt_body(
                BodyKeySource::Pinned(DEFAULT_TABLE),
                id,
                &body_b64,
                &tag_b64,
            )
            .unwrap();
            assert_eq!(res.plaintext, sample);
            assert_eq!(res.table_id, DEFAULT_TABLE.id);
            assert_eq!(res.key_id, id);
        }
    }

    #[test]
    fn round_trip_all_90_keys() {
        let sample = b"vless://a@b:1#node1\n";
        for (id, _) in DEFAULT_TABLE.entries {
            let (body_b64, tag_b64) = encrypt_with_table(DEFAULT_TABLE, id, sample).unwrap();
            let res = decrypt_body(BodyKeySource::default(), id, &body_b64, &tag_b64).unwrap();
            assert_eq!(res.plaintext, sample);
        }
    }

    #[test]
    fn wrong_tag_rejected_distinctly() {
        let (body_b64, tag_b64) = encrypt_with_table(DEFAULT_TABLE, "key02", b"hello").unwrap();
        // Malformed tag length
        assert!(matches!(
            decrypt_body(BodyKeySource::default(), "key02", &body_b64, "AAAA"),
            Err(BodyCryptError::WrongTag(_))
        ));
        // Tampered tag (same length, invalid signature)
        let mut raw_tag = STANDARD.decode(&tag_b64).unwrap();
        raw_tag[0] ^= 0x01;
        let bad_tag = STANDARD.encode(raw_tag);
        assert!(matches!(
            decrypt_body(BodyKeySource::default(), "key02", &body_b64, &bad_tag),
            Err(BodyCryptError::AesGcmAuth)
        ));
    }

    #[test]
    fn wrong_key_rejected_distinctly() {
        // Unknown key ID
        assert!(matches!(
            decrypt_body(BodyKeySource::default(), "key99", "AAA=", "AAAA"),
            Err(BodyCryptError::WrongTag(_))
        ));
        let (body_b64, tag_b64) = encrypt_with_table(DEFAULT_TABLE, "key01", b"hello").unwrap();
        assert!(matches!(
            decrypt_body(
                BodyKeySource::Pinned(DEFAULT_TABLE),
                "key99",
                &body_b64,
                &tag_b64
            ),
            Err(BodyCryptError::UnknownKeyId(_))
        ));
        // Decrypting with wrong key in table fails authentication
        assert!(matches!(
            decrypt_body(
                BodyKeySource::Pinned(DEFAULT_TABLE),
                "key02",
                &body_b64,
                &tag_b64
            ),
            Err(BodyCryptError::AesGcmAuth)
        ));
    }
}
