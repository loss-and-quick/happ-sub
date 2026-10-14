//! `incy://crypt1/` for a caller that holds its own key, without `builtin-incy-keys`.
//!
//! The scheme does not require the embedded keymat: `derive_key` turns any two 4 KiB blobs into
//! the K1 the client uses. That is the mode a caller has when it obtained the key some other way,
//! and it is what this file exercises, with synthetic keymat so nothing vendor-derived is needed.

#![cfg(feature = "incy-crypt")]

use happ_sub::incy_crypt::{
    decrypt_link, derive_key, encrypt_link, fingerprint, is_incy_link, IncyCryptError, IncyLink,
    IV_LEN, KEYMAT_A_OFFSET, KEYMAT_B_OFFSET, KEYMAT_LEN, PREFIX,
};

const KEYMAT_LEN_ASSET: usize = 4096;

fn keymat(seed: u8) -> Vec<u8> {
    (0..KEYMAT_LEN_ASSET)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn synthetic_key() -> [u8; 32] {
    [0u8; 32]
}

fn derived(a: u8, b: u8) -> [u8; 32] {
    derive_key(&keymat(a), &keymat(b)).unwrap()
}

#[test]
fn any_two_blobs_of_the_right_size_derive_a_key() {
    let a = keymat(1);
    let b = keymat(2);
    assert_eq!(derive_key(&a, &b).unwrap(), derived(1, 2));

    // The two assets are interchangeable, and different assets give different keys.
    assert_ne!(derived(1, 2), derived(3, 4));

    // The window is bounds-checked: a short asset is an error, not a panic. Key A is read at
    // KEYMAT_A_OFFSET..+KEYMAT_LEN, key B at KEYMAT_B_OFFSET..+KEYMAT_LEN.
    let short_a = KEYMAT_A_OFFSET + KEYMAT_LEN - 1;
    assert!(matches!(
        derive_key(&vec![0u8; short_a], &b),
        Err(IncyCryptError::KeymatOutOfBounds { which: 'a', offset, len }) if offset
            == KEYMAT_A_OFFSET
            && len == short_a
    ));
    let short_b = KEYMAT_B_OFFSET + KEYMAT_LEN - 1;
    assert!(matches!(
        derive_key(&a, &vec![0u8; short_b]),
        Err(IncyCryptError::KeymatOutOfBounds { which: 'b', offset, len }) if offset
            == KEYMAT_B_OFFSET
            && len == short_b
    ));
    assert!(matches!(
        derive_key(&[], &b),
        Err(IncyCryptError::KeymatOutOfBounds { which: 'a', .. })
    ));
}

#[test]
fn links_round_trip_under_a_key_the_caller_derived() {
    let key = &derived(7, 8);
    let iv = [0x5au8; IV_LEN];
    for (url, name) in [
        ("https://example.com/sub", None),
        ("https://example.net/sub#Name With Spaces", Some("Profile")),
        ("https://example.org/x?a=1&b=2# remarks ", None),
    ] {
        let link = encrypt_link(url, name, key, iv);
        assert!(link.starts_with(PREFIX), "{link}");
        assert!(is_incy_link(&link));
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
fn the_iv_and_tag_are_not_accepted_from_another_key() {
    let key = &derived(7, 8);
    let link = encrypt_link("https://example.com/sub", None, key, [0x5au8; IV_LEN]);

    // A different key must fail the tag, not yield a URL.
    assert_eq!(
        decrypt_link(&link, &derived(9, 10)),
        Err(IncyCryptError::AesGcmAuth)
    );
    // So must a mutated IV.
    let mut tampered = link.clone();
    tampered.replace_range(PREFIX.len()..PREFIX.len() + 2, "AA");
    assert_eq!(
        decrypt_link(&tampered, key),
        Err(IncyCryptError::AesGcmAuth)
    );
    // And the all-zero key.
    assert_eq!(
        decrypt_link(&link, &synthetic_key()),
        Err(IncyCryptError::AesGcmAuth)
    );
}

#[test]
fn malformed_links_are_rejected_before_any_decryption() {
    let key = &derived(7, 8);
    for foreign in [
        "happ://crypt1/AAAA",
        "https://example.com",
        "incy://crypt2/AAAA",
        "incy://crypt1",
    ] {
        assert!(
            matches!(
                decrypt_link(foreign, key),
                Err(IncyCryptError::UnknownScheme(link)) if link == foreign
            ),
            "{foreign}"
        );
    }
    assert!(matches!(
        decrypt_link("incy://crypt1/***", key),
        Err(IncyCryptError::Base64(_))
    ));
    assert!(matches!(
        decrypt_link("incy://crypt1/AAAA", key),
        Err(IncyCryptError::TooShort(3))
    ));
    assert!(!is_incy_link("incy://crypt1"));
    assert!(is_incy_link("incy://crypt1/AAAA"));
}

#[test]
fn the_derived_key_is_identifiable_by_its_fingerprint() {
    // A caller can pin the key it derived: the fingerprint is the value the vendor package pins
    // for its own keymat, and a different keymat gives a different one.
    assert_eq!(fingerprint(&derived(7, 8)).len(), 64);
    assert_eq!(fingerprint(&derived(7, 8)), fingerprint(&derived(7, 8)));
    assert_ne!(fingerprint(&derived(7, 8)), fingerprint(&derived(9, 10)));
    assert_eq!(
        fingerprint(&derived(7, 8)),
        fingerprint(&derived(7, 8)).to_lowercase()
    );
}
