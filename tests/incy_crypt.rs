//! `incy://crypt1/` against the shipped fixtures.
//!
//! The samples are the vendor's own pinned cross-platform vector plus four payloads generated
//! from the documented key derivation. They are shared with `happ-key-extractor`
//! (`tests/data/incy/incy-crypt1-samples.json`) and the research documentation
//! (`docs/fixtures/incy-crypt1-samples.json` in happ-research-backup), so a divergence between
//! the Rust and Python implementations shows up as a failing test on one side.
//!
//! Every sample is encrypted under K1, so this file needs the embedded keymat. The other way to
//! use the module — a caller holding its own key, without `builtin-incy-keys` — is covered by
//! `incy_caller_key.rs`.

#![cfg(all(feature = "incy-crypt", feature = "builtin-incy-keys"))]

use happ_sub::incy_crypt::{
    builtin_key, decrypt_link, derive_key, encrypt_link, fingerprint, is_incy_link, IncyCryptError,
    IncyLink, EXPECTED_FINGERPRINT, IV_LEN, KEYMAT_A_SHA256, KEYMAT_B_SHA256, PREFIX,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/incy-crypt1-samples.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The keymat blobs as shipped, read back through the same code path a resync would use.
fn embedded_keymat() -> (Vec<u8>, Vec<u8>) {
    let json: Value = serde_json::from_str(include_str!("../src/keys/incy-keymat.json")).unwrap();
    let decode = |name: &str| {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let text = json[name].as_str().unwrap();
        STANDARD
            .decode(text)
            .or_else(|_| {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                URL_SAFE_NO_PAD.decode(text)
            })
            .unwrap()
    };
    (decode("keymat_a_b64"), decode("keymat_b_b64"))
}

#[test]
fn embedded_keymat_matches_the_pinned_digests() {
    let (a, b) = embedded_keymat();
    assert_eq!(a.len(), 4096, "keymat_a must be the full 4 KiB asset");
    assert_eq!(b.len(), 4096, "keymat_b must be the full 4 KiB asset");
    assert_eq!(hex(&Sha256::digest(&a)), KEYMAT_A_SHA256);
    assert_eq!(hex(&Sha256::digest(&b)), KEYMAT_B_SHA256);
}

#[test]
fn builtin_key_is_the_documented_k1() {
    let key = builtin_key();
    assert_eq!(
        fingerprint(key),
        EXPECTED_FINGERPRINT,
        "embedded keymat must derive the K1 every reference implementation pins"
    );
    assert_eq!(
        hex(key),
        "f6d40ea0c8a8899d7c682d09ba0d4165dfe2b3dd45e6bb3e25cb233cf00c2462"
    );
    assert_eq!(
        derive_key(&embedded_keymat().0, &embedded_keymat().1).unwrap(),
        *key
    );
}

#[test]
fn every_fixture_decrypts_to_its_recorded_url() {
    let samples = fixture();
    let key = builtin_key();
    let list = samples["samples"].as_array().unwrap();
    assert_eq!(list.len(), 5);

    for sample in list {
        let note = sample["note"].as_str().unwrap();
        let link = sample["link"].as_str().unwrap();
        assert!(is_incy_link(link), "{note}");

        let decrypted = decrypt_link(link, key).unwrap_or_else(|e| panic!("{note}: {e}"));
        let plaintext: Value = serde_json::from_str(sample["plaintext"].as_str().unwrap()).unwrap();
        assert_eq!(decrypted.url, plaintext["url"].as_str().unwrap(), "{note}");
        assert_eq!(
            decrypted.name,
            plaintext["n"].as_str().map(str::to_string),
            "{note}"
        );
    }
}

#[test]
fn the_pinned_vendor_vector_matches() {
    let samples = fixture();
    let vector = &samples["samples"][0];
    assert_eq!(
        vector["plaintext"],
        r#"{"url":"https://sub.example.com/test-vector","v":1}"#
    );
    assert_eq!(
        decrypt_link(vector["link"].as_str().unwrap(), builtin_key())
            .unwrap()
            .url,
        "https://sub.example.com/test-vector"
    );
}

#[test]
fn generated_links_survive_the_round_trip() {
    let key = builtin_key();
    let iv = [0x11u8; IV_LEN];
    for (url, name) in [
        ("https://example.com/sub?token=abc123", None),
        (
            "https://example.org/v2ray/sub/9f8e7d#Remarks",
            Some("Probe Provider"),
        ),
    ] {
        let link = encrypt_link(url, name, key, iv);
        assert!(link.starts_with(PREFIX));
        assert_eq!(
            decrypt_link(&link, key).unwrap(),
            IncyLink {
                url: url.to_string(),
                name: name.map(str::to_string),
            }
        );
    }
}

#[test]
fn a_foreign_key_never_yields_a_url() {
    let samples = fixture();
    let link = samples["samples"][0]["link"].as_str().unwrap();
    assert_eq!(
        decrypt_link(link, &[0u8; 32]),
        Err(IncyCryptError::AesGcmAuth)
    );
}
