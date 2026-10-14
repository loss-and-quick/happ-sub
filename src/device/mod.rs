//! Device identity Happ reports on subscription fetches: `X-HWID` (its SSAID) and `User-Agent`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

mod signers;

pub use crate::happ_request::{user_agent, user_agent_for_os};
pub use crate::release::{
    HAPP_API_VERSION, HAPP_DESKTOP_BUNDLE_ID_LINUX, HAPP_DESKTOP_UA_BUILD_STAMP,
    HAPP_DESKTOP_UA_SUFFIX, HAPP_DESKTOP_VERSION, HAPP_UA_BUILD_STAMP, HAPP_UA_SUFFIX,
    HAPP_VERSION, HAPP_VERSION_CODE,
};
pub use crate::signers::{SigScheme, SignerSet};
pub use signers::HAPP_SIGNERS;

/// Happ's Android package name.
pub const HAPP_PACKAGE: &str = "su.happ.proxyutility";

/// Namespace UUID Happ desktop uses to derive a fallback HWID from hardware identifiers.
///
/// Equal to `ccd6ac7d-ac5f-4106-bb40-066448b49e90` (`0x2f9160`).
pub const HAPP_DESKTOP_HWID_NAMESPACE: [u8; 16] = [
    0xcc, 0xd6, 0xac, 0x7d, 0xac, 0x5f, 0x41, 0x06, 0xbb, 0x40, 0x06, 0x64, 0x48, 0xb4, 0x9e, 0x90,
];

/// Checks whether a system hardware identifier is valid.
///
/// Observed in Happ desktop (`0x2f5920`), which trims whitespace and rejects strings that are
/// empty or contain only `'0'` and `'-'` characters (such as all-zero UUIDs).
pub fn is_valid_sys_hwid(s: &str) -> bool {
    let trimmed = s.trim();
    !trimmed.is_empty() && trimmed.bytes().any(|b| b != b'0' && b != b'-')
}

/// Returns true if an identifier string is a known dummy/bogus hardware serial or UUID.
///
/// Observed in Happ desktop (`0x3b48e0`), which filters out OEM placeholder strings, default
/// sequences, and dummy serial numbers before generating the fallback identifier.
pub fn is_bogus_machine_id(id: &str) -> bool {
    let s = id.trim().to_ascii_lowercase();
    matches!(
        s.as_str(),
        "" | "1234567890"
            | "0123456789"
            | "o.e.m"
            | "o.e.m."
            | "oem"
            | "default string"
            | "serial number"
            | "not specified"
            | "not applicable"
            | "none"
            | "null"
            | "00020003000400050006000700080009"
    )
}

/// Derives a UUIDv5 fallback hardware identifier from a sequence of machine identifier strings.
///
/// Happ desktop joins valid machine IDs with `\n` and generates an RFC 4122 UUIDv5 under
/// namespace `ccd6ac7d-ac5f-4106-bb40-066448b49e90`. The output is formatted without braces in
/// lower-case hex.
pub fn desktop_fallback_hwid(machine_ids: &[&str]) -> String {
    let valid_ids: Vec<&str> = machine_ids
        .iter()
        .copied()
        .map(str::trim)
        .filter(|s| is_valid_sys_hwid(s) && !is_bogus_machine_id(s))
        .collect();

    let joined = valid_ids.join("\n");
    uuid_v5(&HAPP_DESKTOP_HWID_NAMESPACE, joined.as_bytes())
}

/// Generates an RFC 4122 UUIDv5 (lowercase 36-char string without braces).
pub fn uuid_v5(namespace: &[u8; 16], name: &[u8]) -> String {
    let mut data = Vec::with_capacity(16 + name.len());
    data.extend_from_slice(namespace);
    data.extend_from_slice(name);
    let digest = sha1(&data);

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&digest[..16]);
    // Version 5 (0b0101) in high nibble of octet 6
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x50;
    // Variant 1 (0b10) in high 2 bits of octet 8
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
        uuid_bytes[4], uuid_bytes[5],
        uuid_bytes[6], uuid_bytes[7],
        uuid_bytes[8], uuid_bytes[9],
        uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
    )
}

/// Self-contained RFC 3174 SHA-1 implementation used for UUIDv5 generation.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = [
        0x6745_2301u32,
        0xEFCD_AB89u32,
        0x98BA_DCFEu32,
        0x1032_5476u32,
        0xC3D2_E1F0u32,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() + 8) % 64 != 0 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, b) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &item) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(item);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

/// Errors from [`ssaid`] and [`decode_user_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceError {
    /// The stored key is not an even-length hex string.
    InvalidKeyHex,
    /// The key is not 16 or 32 bytes; carries the length found.
    InvalidKeyLength(usize),
    /// The signer set holds no certificate.
    NoCertificates,
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceError::InvalidKeyHex => write!(f, "user key is not an even-length hex string"),
            DeviceError::InvalidKeyLength(n) => {
                write!(f, "user key is {n} bytes, expected 16 or 32")
            }
            DeviceError::NoCertificates => write!(f, "signer set has no certificate"),
        }
    }
}

impl std::error::Error for DeviceError {}

/// The ANDROID_ID (SSAID) Android 8+ gives an app for one user key and signer set.
pub fn ssaid(user_key: &[u8], signers: &SignerSet) -> Result<String, DeviceError> {
    // AOSP SettingsProvider.generateSsaidLocked: HMAC-SHA256 over each certificate prefixed with
    // its big-endian 32-bit length, lower-case hex, first 16 characters.
    check_key_len(user_key.len())?;
    if signers.certs.is_empty() {
        return Err(DeviceError::NoCertificates);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(user_key).expect("HMAC accepts any key length");
    for cert in signers.certs {
        mac.update(&(cert.len() as u32).to_be_bytes());
        mac.update(cert);
    }
    let digest = mac.finalize().into_bytes();
    Ok(digest[..8].iter().map(|b| format!("{b:02x}")).collect())
}

/// Decodes the `userkey` stored in `settings_ssaid.xml` (hex, 16 or 32 bytes).
pub fn decode_user_key(hex: &str) -> Result<Vec<u8>, DeviceError> {
    let hex = hex.trim().as_bytes();
    if hex.len() % 2 != 0 {
        return Err(DeviceError::InvalidKeyHex);
    }
    let key = hex
        .chunks_exact(2)
        .map(|pair| {
            let digit = |c: u8| (c as char).to_digit(16).ok_or(DeviceError::InvalidKeyHex);
            Ok(((digit(pair[0])? << 4) | digit(pair[1])?) as u8)
        })
        .collect::<Result<Vec<u8>, _>>()?;
    check_key_len(key.len())?;
    Ok(key)
}

fn check_key_len(len: usize) -> Result<(), DeviceError> {
    // Android O development builds generated 16-byte keys; current ones generate 32.
    match len {
        16 | 32 => Ok(()),
        n => Err(DeviceError::InvalidKeyLength(n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn test_key(len: u8) -> Vec<u8> {
        (0..len).collect()
    }

    #[test]
    fn ssaid_matches_vector() {
        // Expected values computed independently with `openssl dgst -sha256 -mac HMAC`.
        assert_eq!(
            ssaid(&test_key(32), &HAPP_SIGNERS).unwrap(),
            "013b86e99e8dce53"
        );
        assert_eq!(
            ssaid(&test_key(16), &HAPP_SIGNERS).unwrap(),
            "fe3093ae240d87fd"
        );
    }

    #[test]
    fn ssaid_length_prefixes_every_cert_in_order() {
        let two = SignerSet {
            scheme: SigScheme::V3,
            certs: &[b"first" as &[u8], b"second!"],
            apk_version: "test",
        };
        assert_eq!(ssaid(&test_key(32), &two).unwrap(), "c25fff3c5500ee56");
        let swapped = SignerSet {
            certs: &[b"second!" as &[u8], b"first"],
            ..two
        };
        assert_ne!(ssaid(&test_key(32), &swapped).unwrap(), "c25fff3c5500ee56");
    }

    #[test]
    fn ssaid_rejects_bad_key_len() {
        for len in [0, 15, 24, 33] {
            assert_eq!(
                ssaid(&test_key(len), &HAPP_SIGNERS),
                Err(DeviceError::InvalidKeyLength(len as usize))
            );
        }
        let empty = SignerSet {
            certs: &[],
            ..HAPP_SIGNERS
        };
        assert_eq!(
            ssaid(&test_key(32), &empty),
            Err(DeviceError::NoCertificates)
        );
    }

    #[test]
    fn decode_user_key_accepts_stored_hex() {
        let upper = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
        assert_eq!(decode_user_key(upper).unwrap(), test_key(32));
        assert_eq!(
            decode_user_key(&upper[..32].to_ascii_lowercase()).unwrap(),
            test_key(16)
        );
        assert_eq!(decode_user_key("ABC"), Err(DeviceError::InvalidKeyHex));
        assert_eq!(decode_user_key("ZZ"), Err(DeviceError::InvalidKeyHex));
        assert_eq!(decode_user_key("+1"), Err(DeviceError::InvalidKeyHex));
        assert_eq!(
            decode_user_key("0011"),
            Err(DeviceError::InvalidKeyLength(2))
        );
    }

    #[test]
    fn signers_digest_pinned() {
        assert_eq!(HAPP_SIGNERS.scheme, SigScheme::V2);
        assert_eq!(HAPP_SIGNERS.apk_version, HAPP_VERSION);
        assert_eq!(HAPP_SIGNERS.certs.len(), 1);
        let cert = HAPP_SIGNERS.certs[0];
        assert_eq!(cert.len(), 782);
        let digest: String = sha2::Sha256::digest(cert)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "397e98abed03c5f263ffaf4e8a1043b2a59f538b99e75cf152fa05a7e8007d8d"
        );
    }

    #[test]
    fn sha1_matches_standard_vectors() {
        let hex = |data: &[u8]| {
            sha1(data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn uuid_v5_matches_rfc4122_vector() {
        let dns_ns: [u8; 16] = [
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ];
        assert_eq!(
            uuid_v5(&dns_ns, b"python.org"),
            "886313e1-3b8a-5372-9b90-0c9aee199e5d"
        );
    }

    #[test]
    fn valid_sys_hwid_checks() {
        assert!(!is_valid_sys_hwid(""));
        assert!(!is_valid_sys_hwid("   "));
        assert!(!is_valid_sys_hwid("00000000-0000-0000-0000-000000000000"));
        assert!(!is_valid_sys_hwid("0000"));
        assert!(!is_valid_sys_hwid("---"));
        assert!(is_valid_sys_hwid("0123456789abcdef"));
        assert!(is_valid_sys_hwid(
            "  c0000000-0000-0000-0000-000000000000  "
        ));
    }

    #[test]
    fn bogus_machine_id_checks() {
        assert!(is_bogus_machine_id("1234567890"));
        assert!(is_bogus_machine_id("  Default String  "));
        assert!(is_bogus_machine_id("o.e.m"));
        assert!(is_bogus_machine_id("OEM"));
        assert!(is_bogus_machine_id("none"));
        assert!(!is_bogus_machine_id("a1b2c3d4e5f6"));
    }

    #[test]
    fn desktop_fallback_hwid_filters_bogus_and_produces_deterministic_uuid() {
        let raw = [
            "  1234567890  ",
            "valid-machine-1",
            "Default String",
            "valid-machine-2",
        ];
        let id1 = desktop_fallback_hwid(&raw);
        let id2 = desktop_fallback_hwid(&["valid-machine-1", "valid-machine-2"]);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 36);
        assert_eq!(&id1[14..15], "5"); // version 5
        let variant = id1.as_bytes()[19];
        assert!(matches!(variant, b'8' | b'9' | b'a' | b'b')); // variant 1
    }
}
