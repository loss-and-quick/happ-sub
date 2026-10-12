//! Happ URL-hiding decryption (`happ://crypt/` … `happ://crypt5/`).
//!
//! Providers (and `crypto.happ.su`) wrap the destination subscription URL so that
//! users cannot see or share the raw endpoint. The client transparently unwraps it.
//!
//! # Schemes
//! * `happ://crypt/`: chunked RSA-1024 PKCS#1 v1.5 (`pkcs1_0`)
//! * `happ://crypt2/`: chunked RSA-4096 PKCS#1 v1.5 (`pkcs1_1`)
//! * `happ://crypt3/`: chunked RSA-4096 PKCS#1 v1.5 (`pkcs1_2`)
//! * `happ://crypt4/`: chunked RSA-4096 PKCS#1 v1.5 (`pkcs1_3`)
//! * `happ://crypt5/`: hybrid ChaCha20-Poly1305 + RSA-4096 (marker-addressed)
//!
//! # Keys
//! Every scheme needs an RSA private key. The `builtin-url-keys` feature provides the keys
//! known to decrypt vendor-issued links as `builtin_keyring()` (provenance in [`crate::keys`]);
//! any other [`Keyring`] implementation, such as a [`MemoryKeyring`] loaded by the caller,
//! works the same way.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use std::collections::HashMap;
use std::path::Path;

/// Source of the RSA private keys used for URL decryption.
pub trait Keyring: Send + Sync {
    /// Return the 4096-bit RSA private key matching a 8-character `crypt5` marker (e.g. `"vdfzfoff"`).
    fn get_crypt5_key(&self, marker: &str) -> Option<&RsaPrivateKey>;
    /// Return the RSA private key for chunked RSA modes `crypt1`..`crypt4` (ordinals `0`..=`3`).
    fn get_ordinal_key(&self, ordinal: u8) -> Option<&RsaPrivateKey>;
}

/// An in-memory store of RSA private keys.
#[derive(Default)]
pub struct MemoryKeyring {
    crypt5_keys: HashMap<String, RsaPrivateKey>,
    ordinal_keys: HashMap<u8, RsaPrivateKey>,
}

/// Summary of key coverage in a [`MemoryKeyring`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringCoverage {
    /// List of 8-character `crypt5` markers present.
    pub crypt5_markers: Vec<String>,
    /// List of chunked RSA ordinals present (`0` for `crypt/`, `1`..=`3` for `crypt2`..`crypt4`).
    pub ordinals: Vec<u8>,
}

impl MemoryKeyring {
    /// Create an empty keyring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a 4096-bit RSA private key for a `crypt5` marker.
    pub fn insert_crypt5(&mut self, marker: &str, key: RsaPrivateKey) {
        self.crypt5_keys.insert(marker.to_string(), key);
    }

    /// Add an RSA private key for a chunked RSA ordinal (`0`..=`3`).
    pub fn insert_ordinal(&mut self, ordinal: u8, key: RsaPrivateKey) {
        self.ordinal_keys.insert(ordinal, key);
    }

    /// Load a keyring from a JSON map of `"{ \"marker\": \"base64(DER)\", ... }"`.
    pub fn from_json_str(json_str: &str) -> Result<Self, UrlCryptError> {
        let map: HashMap<String, String> = serde_json::from_str(json_str)
            .map_err(|e| UrlCryptError::InvalidKeyring(format!("invalid JSON: {e}")))?;

        let mut keyring = Self::new();
        for (k, v) in map {
            let der = b64(&v)?;
            let priv_key = RsaPrivateKey::from_pkcs1_der(&der)
                .or_else(|_| RsaPrivateKey::from_pkcs8_der(&der))
                .map_err(|e| {
                    UrlCryptError::InvalidKeyring(format!("failed to parse RSA DER for {k}: {e}"))
                })?;

            if let Some(ord_str) = k.strip_prefix("pkcs1_") {
                if let Ok(ord) = ord_str.parse::<u8>() {
                    keyring.insert_ordinal(ord, priv_key);
                    continue;
                }
            }
            keyring.insert_crypt5(&k, priv_key);
        }
        Ok(keyring)
    }

    /// Load a keyring from a JSON file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, UrlCryptError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| UrlCryptError::InvalidKeyring(format!("read file failed: {e}")))?;
        Self::from_json_str(&content)
    }

    /// Report covered markers and ordinals.
    pub fn coverage(&self) -> KeyringCoverage {
        let mut crypt5_markers: Vec<String> = self.crypt5_keys.keys().cloned().collect();
        crypt5_markers.sort();
        let mut ordinals: Vec<u8> = self.ordinal_keys.keys().copied().collect();
        ordinals.sort();
        KeyringCoverage {
            crypt5_markers,
            ordinals,
        }
    }
}

impl Keyring for MemoryKeyring {
    fn get_crypt5_key(&self, marker: &str) -> Option<&RsaPrivateKey> {
        self.crypt5_keys.get(marker)
    }

    fn get_ordinal_key(&self, ordinal: u8) -> Option<&RsaPrivateKey> {
        self.ordinal_keys.get(&ordinal)
    }
}

/// The embedded `crypt` … `crypt5` keys, parsed on first use.
///
/// Infallible because the key data is a compile-time constant that the crate's tests parse in
/// full, so a parse failure here would be a build defect rather than a runtime condition.
#[cfg(feature = "builtin-url-keys")]
pub fn builtin_keyring() -> &'static MemoryKeyring {
    static KEYRING: std::sync::OnceLock<MemoryKeyring> = std::sync::OnceLock::new();
    KEYRING.get_or_init(|| {
        MemoryKeyring::from_json_str(crate::keys::URL_KEYS_JSON)
            .expect("embedded url-keys.json is valid")
    })
}

/// Errors during URL decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlCryptError {
    /// The link scheme is unrecognized.
    UnknownScheme(String),
    /// A required key was not found in the supplied keyring.
    MissingKey(String),
    /// Keyring content was malformed.
    InvalidKeyring(String),
    /// Ciphertext or wire framing was corrupt.
    InvalidFormat(String),
    /// RSA decryption error.
    Rsa(String),
    /// ChaCha20-Poly1305 authentication failed.
    ChaCha,
    /// Base64 decoding failed.
    Base64(String),
    /// Decrypted plaintext is not valid UTF-8.
    Utf8,
}

impl std::fmt::Display for UrlCryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UrlCryptError::UnknownScheme(s) => write!(f, "unrecognized crypt scheme: {s}"),
            UrlCryptError::MissingKey(k) => write!(f, "keyring does not contain key {k:?}"),
            UrlCryptError::InvalidKeyring(m) => write!(f, "invalid keyring: {m}"),
            UrlCryptError::InvalidFormat(m) => write!(f, "invalid wire format: {m}"),
            UrlCryptError::Rsa(m) => write!(f, "RSA decryption error: {m}"),
            UrlCryptError::ChaCha => write!(f, "ChaCha20-Poly1305 authentication failed"),
            UrlCryptError::Base64(m) => write!(f, "base64 decode error: {m}"),
            UrlCryptError::Utf8 => write!(f, "decrypted URL is not valid UTF-8"),
        }
    }
}

impl std::error::Error for UrlCryptError {}

/// Dispatch a `happ://crypt*` URI and decrypt it to the underlying destination URL.
pub fn decrypt_url(link: &str, keyring: &dyn Keyring) -> Result<String, UrlCryptError> {
    let link = link.trim();
    let lower = link.to_ascii_lowercase();

    if lower.starts_with("happ://crypt5/") {
        let orig_payload = &link["happ://crypt5/".len()..];
        return decrypt_crypt5(orig_payload, keyring);
    }
    for (prefix, ord) in [
        ("happ://crypt4/", 3u8),
        ("happ://crypt3/", 2u8),
        ("happ://crypt2/", 1u8),
        ("happ://crypt/", 0u8),
    ] {
        if lower.starts_with(prefix) {
            let orig_payload = &link[prefix.len()..];
            return decrypt_crypt1to4(ord, orig_payload, keyring);
        }
    }

    Err(UrlCryptError::UnknownScheme(link.to_string()))
}

/// Decrypt chunked RSA schemes `happ://crypt/` … `happ://crypt4/`.
pub fn decrypt_crypt1to4(
    ordinal: u8,
    payload_b64: &str,
    keyring: &dyn Keyring,
) -> Result<String, UrlCryptError> {
    let priv_key = keyring
        .get_ordinal_key(ordinal)
        .ok_or_else(|| UrlCryptError::MissingKey(format!("pkcs1_{ordinal}")))?;

    let cipher = b64(payload_b64)?;
    let key_size = priv_key.size();
    if cipher.is_empty() || cipher.len() % key_size != 0 {
        return Err(UrlCryptError::InvalidFormat(format!(
            "payload length {} is not a multiple of RSA modulus {}",
            cipher.len(),
            key_size
        )));
    }

    let mut plain = Vec::with_capacity(cipher.len());
    for chunk in cipher.chunks(key_size) {
        let dec = priv_key
            .decrypt(Pkcs1v15Encrypt, chunk)
            .map_err(|e| UrlCryptError::Rsa(e.to_string()))?;
        plain.extend(dec);
    }
    String::from_utf8(plain).map_err(|_| UrlCryptError::Utf8)
}

/// Decrypt a `happ://crypt5/` payload.
pub fn decrypt_crypt5(payload: &str, keyring: &dyn Keyring) -> Result<String, UrlCryptError> {
    let payload = payload.trim();
    if payload.is_empty() {
        return Err(UrlCryptError::InvalidFormat("empty crypt5 payload".into()));
    }

    let swapped = swap_block_halves(payload.as_bytes());
    if swapped.len() < 8 {
        return Err(UrlCryptError::InvalidFormat(
            "crypt5 payload too short".into(),
        ));
    }

    let mut marker_buf = [0u8; 8];
    marker_buf[..4].copy_from_slice(&swapped[..4]);
    marker_buf[4..].copy_from_slice(&swapped[swapped.len() - 4..]);
    let marker = std::str::from_utf8(&marker_buf)
        .map_err(|_| UrlCryptError::InvalidFormat("marker is not valid ASCII".into()))?;

    let priv_key = keyring
        .get_crypt5_key(marker)
        .ok_or_else(|| UrlCryptError::MissingKey(marker.to_string()))?;

    let body = &swapped[4..swapped.len() - 4];
    if body.len() < 13 {
        return Err(UrlCryptError::InvalidFormat("crypt5 body too short".into()));
    }

    // Salted links put a non-digit filler at body[12] where unsalted ones start seg_len.
    let prefer_salted = body.len() > 22 && !body[12].is_ascii_digit();

    // Report the error of the layout the heuristic preferred; the fallback is a guess.
    decrypt_crypt5_body(body, priv_key, prefer_salted)
        .or_else(|e| decrypt_crypt5_body(body, priv_key, !prefer_salted).map_err(|_| e))
}

fn decrypt_crypt5_body(
    body: &[u8],
    priv_key: &RsaPrivateKey,
    salted: bool,
) -> Result<String, UrlCryptError> {
    let nonce = &body[0..12];

    let (salt, pos): (&[u8], usize) = if salted {
        if body.len() < 22 {
            return Err(UrlCryptError::InvalidFormat(
                "body too short for salted mode".into(),
            ));
        }
        (&body[14..22], 22)
    } else {
        (&[], 12)
    };

    let mut p = pos;
    while p < body.len() && body[p].is_ascii_digit() {
        p += 1;
    }
    if p == pos {
        return Err(UrlCryptError::InvalidFormat(
            "missing seg_len digits".into(),
        ));
    }

    let seg_len_str = std::str::from_utf8(&body[pos..p])
        .map_err(|_| UrlCryptError::InvalidFormat("seg_len is not UTF-8".into()))?;
    let seg_len: usize = seg_len_str
        .parse()
        .map_err(|_| UrlCryptError::InvalidFormat("invalid seg_len integer".into()))?;

    let packed = &body[p..];
    if seg_len >= packed.len() {
        return Err(UrlCryptError::InvalidFormat("segment truncated".into()));
    }

    let enc_url = std::str::from_utf8(&packed[1..1 + seg_len])
        .map_err(|_| UrlCryptError::InvalidFormat("enc_url is not ASCII".into()))?;
    let enc_skey = std::str::from_utf8(&packed[1 + seg_len..])
        .map_err(|_| UrlCryptError::InvalidFormat("enc_skey is not ASCII".into()))?;

    let raw_skey_ct = b64(enc_skey)?;
    let raw_skey_pt = priv_key
        .decrypt(Pkcs1v15Encrypt, &raw_skey_ct)
        .map_err(|e| UrlCryptError::Rsa(e.to_string()))?;

    let swapped_skey = swap_adjacent(&raw_skey_pt);
    let skey_b64 = std::str::from_utf8(&swapped_skey)
        .map_err(|_| UrlCryptError::InvalidFormat("RSA plain is not ASCII base64".into()))?;
    let session_key = b64(skey_b64)?;
    if session_key.len() != 32 {
        return Err(UrlCryptError::InvalidFormat(format!(
            "session key length is {}, expected 32",
            session_key.len()
        )));
    }

    let mut chacha_key = session_key;
    if !salt.is_empty() {
        for i in 0..32 {
            chacha_key[i] ^= salt[i % salt.len()];
        }
    }

    let cipher =
        ChaCha20Poly1305::new_from_slice(&chacha_key).map_err(|_| UrlCryptError::ChaCha)?;
    let ct = b64(enc_url)?;
    let nonce_arr = *Nonce::from_slice(nonce);
    let intermediate = cipher
        .decrypt(&nonce_arr, ct.as_ref())
        .map_err(|_| UrlCryptError::ChaCha)?;

    // The ChaCha plaintext is pair-swapped Base64 of the URL, the same wrapping as the
    // session key; swapping after decoding instead fails on every vendor-generated sample.
    let swapped_inner = swap_adjacent(&intermediate);
    let inner_b64 = std::str::from_utf8(&swapped_inner)
        .map_err(|_| UrlCryptError::InvalidFormat("inner payload is not ASCII".into()))?;
    String::from_utf8(b64(inner_b64)?).map_err(|_| UrlCryptError::Utf8)
}

/// Swaps adjacent byte pairs: `ABCD` -> `BADC`.
pub fn swap_adjacent(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let limit = out.len() - (out.len() % 2);
    for i in (0..limit).step_by(2) {
        out.swap(i, i + 1);
    }
    out
}

/// Swaps 2-byte halves in each 4-byte block: `ABCD` -> `CDAB`.
pub fn swap_block_halves(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let limit = out.len() - (out.len() % 4);
    for i in (0..limit).step_by(4) {
        let (a, b, c, d) = (out[i], out[i + 1], out[i + 2], out[i + 3]);
        out[i] = c;
        out[i + 1] = d;
        out[i + 2] = a;
        out[i + 3] = b;
    }
    out
}

fn b64(s: &str) -> Result<Vec<u8>, UrlCryptError> {
    crate::b64::decode_lenient(s).ok_or_else(|| UrlCryptError::Base64(format!("{} chars", s.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::RsaPublicKey;
    use std::sync::OnceLock;

    /// One throwaway key for every test: RSA generation is slow in debug builds.
    fn test_key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap())
    }

    /// Build a `happ://crypt5/` link with the layout `decrypt_crypt5` reads, which the
    /// vendor-sample integration test confirms against vendor-generated links.
    fn encode_crypt5(
        url: &str,
        marker: &str,
        key: &RsaPublicKey,
        salt: Option<&[u8; 8]>,
    ) -> String {
        let mut rng = rand::thread_rng();
        let session_key: [u8; 32] = rand::random();
        let nonce = b"N0nceN0nceN0";

        let mut chacha_key = session_key;
        if let Some(salt) = salt {
            for (i, b) in chacha_key.iter_mut().enumerate() {
                *b ^= salt[i % 8];
            }
        }
        let inner = swap_adjacent(STANDARD.encode(url).as_bytes());
        let ct = ChaCha20Poly1305::new_from_slice(&chacha_key)
            .unwrap()
            .encrypt(Nonce::from_slice(nonce), inner.as_ref())
            .unwrap();
        let enc_url = STANDARD.encode(ct);
        let rsa_plain = swap_adjacent(STANDARD.encode(session_key).as_bytes());
        let enc_skey = STANDARD.encode(key.encrypt(&mut rng, Pkcs1v15Encrypt, &rsa_plain).unwrap());

        let mut body = nonce.to_vec();
        if let Some(salt) = salt {
            body.extend_from_slice(b"xy");
            body.extend_from_slice(salt);
        }
        body.extend_from_slice(enc_url.len().to_string().as_bytes());
        body.push(b'Q');
        body.extend_from_slice(enc_url.as_bytes());
        body.extend_from_slice(enc_skey.as_bytes());

        let mut framed = marker.as_bytes()[..4].to_vec();
        framed.extend_from_slice(&body);
        framed.extend_from_slice(&marker.as_bytes()[4..]);
        let payload = String::from_utf8(swap_block_halves(&framed)).unwrap();
        format!("happ://crypt5/{payload}")
    }

    fn keyring() -> MemoryKeyring {
        let mut kr = MemoryKeyring::new();
        kr.insert_crypt5("testmark", test_key().clone());
        for ord in 0..=3 {
            kr.insert_ordinal(ord, test_key().clone());
        }
        kr
    }

    #[test]
    fn crypt5_round_trip_salted_and_unsalted() {
        let kr = keyring();
        let public = test_key().to_public_key();
        for url in [
            "https://example.com/a",
            "https://example.com/odd-length?x=1",
        ] {
            for salt in [Some(b"S4ltS4lt"), None] {
                let link = encode_crypt5(url, "testmark", &public, salt);
                assert_eq!(decrypt_url(&link, &kr).unwrap(), url, "salt={salt:?}");
            }
        }
    }

    #[test]
    fn crypt5_unknown_marker_is_missing_key() {
        let link = encode_crypt5(
            "https://example.com/",
            "othermrk",
            &test_key().to_public_key(),
            None,
        );
        assert_eq!(
            decrypt_url(&link, &keyring()),
            Err(UrlCryptError::MissingKey("othermrk".into()))
        );
    }

    #[test]
    fn crypt5_huge_seg_len_does_not_panic() {
        let body = format!("N0nceN0nceN0{}Qabc", usize::MAX);
        let framed = format!("test{body}mark");
        let payload = String::from_utf8(swap_block_halves(framed.as_bytes())).unwrap();
        let kr = keyring();
        assert!(decrypt_crypt5(&payload, &kr).is_err());
    }

    #[test]
    fn crypt1_to_4_round_trip() {
        let kr = keyring();
        let public = test_key().to_public_key();
        // Longer than one 1024-bit PKCS#1 v1.5 block (117 bytes) to exercise chunking.
        let url = format!("https://example.com/{}", "p".repeat(150));
        for (ord, prefix) in [
            "happ://crypt/",
            "happ://crypt2/",
            "happ://crypt3/",
            "happ://crypt4/",
        ]
        .into_iter()
        .enumerate()
        {
            let mut ct = Vec::new();
            for chunk in url.as_bytes().chunks(public.size() - 11) {
                ct.extend(
                    public
                        .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, chunk)
                        .unwrap(),
                );
            }
            let link = format!("{prefix}{}", STANDARD.encode(ct));
            assert_eq!(decrypt_url(&link, &kr).unwrap(), url, "ordinal {ord}");
        }
    }

    #[test]
    fn keyring_json_routes_ordinals_and_markers() {
        let der = test_key().to_pkcs1_der().unwrap();
        let der_b64 = STANDARD.encode(der.as_bytes());
        let json = format!(r#"{{"pkcs1_2": "{der_b64}", "abcdefgh": "{der_b64}"}}"#);
        let kr = MemoryKeyring::from_json_str(&json).unwrap();
        assert_eq!(
            kr.coverage(),
            KeyringCoverage {
                crypt5_markers: vec!["abcdefgh".into()],
                ordinals: vec![2],
            }
        );
    }

    #[test]
    fn swaps_are_involutions() {
        let data = b"ABCDEFGHI";
        assert_eq!(swap_adjacent(data), b"BADCFEHGI");
        assert_eq!(swap_block_halves(data), b"CDABGHEFI");
        assert_eq!(swap_adjacent(&swap_adjacent(data)), data);
        assert_eq!(swap_block_halves(&swap_block_halves(data)), data);
    }

    #[cfg(feature = "builtin-url-keys")]
    #[test]
    fn builtin_keyring_matches_pinned_upstream_file() {
        use sha2::{Digest, Sha256};

        let digest = Sha256::digest(crate::keys::URL_KEYS_JSON.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "dd8639af27ccb4f04c0251f7a08756b5dfbcf5a3e4620d864095ec6d6e815282"
        );

        let entries: HashMap<String, String> =
            serde_json::from_str(crate::keys::URL_KEYS_JSON).unwrap();
        let coverage = builtin_keyring().coverage();
        assert_eq!(coverage.crypt5_markers.len(), 36);
        assert_eq!(coverage.ordinals, [0, 1, 2, 3]);
        assert_eq!(
            coverage.crypt5_markers.len() + coverage.ordinals.len(),
            entries.len()
        );

        let kr = builtin_keyring();
        assert_eq!(kr.get_ordinal_key(0).unwrap().size(), 128);
        for ord in 1..=3 {
            assert_eq!(kr.get_ordinal_key(ord).unwrap().size(), 512);
        }
        for marker in &coverage.crypt5_markers {
            assert_eq!(marker.len(), 8);
            assert_eq!(kr.get_crypt5_key(marker).unwrap().size(), 512, "{marker}");
        }
    }
}
