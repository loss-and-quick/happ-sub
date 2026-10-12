use happ_sub::meta::RiskClass;
use happ_sub::{
    parse, BodyEncryption, DecryptFailure, Error, Input, Parsed, Payload, RoutingAction,
    StoredState,
};
use std::fs;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(name: &str) -> String {
    fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn header_lines(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("HTTP/"))
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn load_fixture_headers() -> Vec<(String, String)> {
    header_lines(&fixture("fixture-headers.txt"))
}

fn input<'a>(url: &'a str, headers: &'a [(String, String)], body: &'a [u8]) -> Input<'a> {
    Input {
        url,
        headers,
        body,
        stored: None,
        limits: None,
    }
}

fn links(parsed: &Parsed) -> &[String] {
    match &parsed.payload {
        Payload::Links(l) => l,
        other => panic!("expected Payload::Links, got {other:?}"),
    }
}

fn scheme_counts(links: &[String]) -> (usize, usize, usize) {
    let count = |scheme: &str| links.iter().filter(|l| l.starts_with(scheme)).count();
    (count("vless://"), count("hysteria2://"), count("ss://"))
}

fn single_profile(parsed: &Parsed) -> &happ_sub::RoutingProfile {
    match parsed.routing.as_slice() {
        [RoutingAction::OnAdd(p)] => p,
        other => panic!("expected one onadd profile, got {other:?}"),
    }
}

#[test]
fn provider_fixture_parses() {
    let headers = load_fixture_headers();
    let body = fixture("fixture-body.b64.txt");

    let parsed = parse(&input(
        "https://example.com/api/v1/client/subscribe?token=secret",
        &headers,
        body.as_bytes(),
    ))
    .expect("parse provider fixture");

    let links = links(&parsed);
    let decoded_text = fixture("fixture-body-decoded.txt");
    let decoded: Vec<&str> = decoded_text.lines().collect();
    assert_eq!(links, decoded.as_slice());
    assert_eq!(scheme_counts(links), (27, 4, 3));

    let meta = &parsed.meta;
    assert_eq!(meta.profile_title(), Some("Example VPN 🗽"));
    assert_eq!(meta.profile_update_interval(), Some(1));
    let user_info = meta.user_info().expect("subscription-userinfo parsed");
    assert_eq!(
        (
            user_info.upload,
            user_info.download,
            user_info.total,
            user_info.expire
        ),
        (0, 0, 0, 1796256000)
    );
    assert_eq!(meta.support_url(), Some("https://example.org/support"));
    assert_eq!(
        meta.profile_web_page_url(),
        Some("https://example.org/start")
    );
    assert!(meta.announce().expect("announce").contains("ByPass"));

    // Transport headers in the capture must not leak into the metadata.
    for noise in [
        "server",
        "set-cookie",
        "content-type",
        "content-length",
        "date",
        "content-security-policy",
    ] {
        assert!(!meta.contains_key(noise), "{noise} leaked into MetaMap");
    }

    let routing = single_profile(&parsed);
    assert_eq!(routing.name, "EXAMPLE-ROUTING");
    assert!(routing.direct_sites.is_empty());
    assert!(routing.direct_ip.is_empty());

    assert_eq!(parsed.body_encryption, BodyEncryption::None);
    assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
}

#[test]
fn meta_dual_transport_and_refresh_merge() {
    let headers = vec![
        ("profile-title".to_string(), "Header Title".to_string()),
        ("profile-update-interval".to_string(), "2".to_string()),
        (
            "support-url".to_string(),
            "https://t.me/header_support".to_string(),
        ),
    ];
    let body = b"#profile-title: Body Overridden Title\n#fallback-url: https://fallback.example.com\nvless://uuid@host:443#srv1\n";

    let parsed = parse(&input("https://example.com/sub", &headers, body)).unwrap();
    assert_eq!(parsed.meta.profile_title(), Some("Body Overridden Title"));
    assert_eq!(parsed.meta.profile_update_interval(), Some(2));
    assert_eq!(
        parsed.meta.support_url(),
        Some("https://t.me/header_support")
    );
    assert_eq!(
        parsed.meta.fallback_url(),
        Some("https://fallback.example.com")
    );

    let proposed = parsed.meta.proposed_changes();
    let class_of = |key: &str| proposed.iter().find(|p| p.key == key).unwrap().risk_class;
    assert_eq!(class_of("fallback-url"), RiskClass::TrustBoundary);
    assert_eq!(class_of("profile-title"), RiskClass::Display);

    let mut old_meta = happ_sub::MetaMap::new();
    old_meta.insert("profile-title", "Old Stored Title");
    old_meta.insert("announce", "Old banner");
    old_meta.insert("sub-info-text", "Sticky info");

    let refreshed = parse(&Input {
        stored: Some(StoredState {
            encrypted: false,
            meta: Some(&old_meta),
        }),
        ..input("https://example.com/sub", &headers, body)
    })
    .unwrap();
    assert_eq!(
        refreshed.meta.profile_title(),
        Some("Body Overridden Title")
    );
    assert_eq!(refreshed.meta.announce(), None, "absent keys are dropped");
    assert_eq!(refreshed.meta.sub_info_text(), Some("Sticky info"));
}

#[test]
fn invalid_routing_header_is_a_warning() {
    let headers = vec![(
        "routing".to_string(),
        "happ://routing/add/not-json".to_string(),
    )];
    let parsed = parse(&input(
        "https://example.com/sub",
        &headers,
        b"vless://a@b:1",
    ))
    .unwrap();
    assert!(parsed.routing.is_empty());
    assert!(matches!(
        parsed.warnings.as_slice(),
        [happ_sub::Warning::InvalidRouting(_)]
    ));
}

#[test]
fn routing_off_is_reported_from_header_and_body() {
    let headers = vec![("routing".to_string(), "happ://routing/off".to_string())];
    let parsed = parse(&input(
        "https://example.com/sub",
        &headers,
        b"happ://routing/off\nvless://a@b:1",
    ))
    .unwrap();
    assert_eq!(parsed.routing, [RoutingAction::Off, RoutingAction::Off]);
    assert_eq!(links(&parsed), ["vless://a@b:1"]);
    assert!(parsed.warnings.is_empty());
}

mod body_encryption {
    use super::*;

    const PLAIN: &[u8] = b"vless://a@b:1#plain\n";

    fn tag(v: &str) -> Vec<(String, String)> {
        vec![("Encrypt-Tag".to_string(), v.to_string())]
    }

    fn stored_encrypted() -> Option<StoredState<'static>> {
        Some(StoredState {
            encrypted: true,
            meta: None,
        })
    }

    #[test]
    fn stored_encrypted_without_tag_is_plaintext() {
        let parsed = parse(&Input {
            stored: stored_encrypted(),
            ..input("https://example.com/sub?key=key02", &[], PLAIN)
        })
        .unwrap();
        assert_eq!(parsed.body_encryption, BodyEncryption::None);
        assert_eq!(links(&parsed), ["vless://a@b:1#plain"]);
    }

    #[test]
    fn empty_tag_is_no_encryption() {
        let headers = tag("  ");
        let parsed = parse(&input("https://example.com/sub?key=key02", &headers, PLAIN)).unwrap();
        assert_eq!(parsed.body_encryption, BodyEncryption::None);
    }

    #[test]
    fn tag_without_key_param_is_not_attempted() {
        let headers = tag("AAAAAAAAAAAAAAAAAAAAAA==");
        let parsed = parse(&input("https://example.com/sub", &headers, PLAIN)).unwrap();
        assert_eq!(parsed.body_encryption, BodyEncryption::None);
        assert_eq!(links(&parsed).len(), 1);
    }

    #[test]
    fn stored_encrypted_without_key_param_fails() {
        let headers = tag("AAAAAAAAAAAAAAAAAAAAAA==");
        let err = parse(&Input {
            stored: stored_encrypted(),
            ..input("https://example.com/sub", &headers, PLAIN)
        })
        .unwrap_err();
        assert_eq!(
            err,
            Error::Decrypt {
                key_id: None,
                reason: DecryptFailure::MissingKeyParam,
            }
        );
    }

    /// Every case Happ turns into an empty body and a wiped server list.
    #[cfg(feature = "body-crypt")]
    #[test]
    fn failed_decryption_is_an_error_not_plaintext() {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes128Gcm, Key, Nonce};
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use happ_sub::body_crypt::{BodyCryptError, NONCE};
        use happ_sub::keys::DEFAULT_TABLE;

        let key = DEFAULT_TABLE.get("key02").unwrap();
        let sealed = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key))
            .encrypt(Nonce::from_slice(NONCE), PLAIN)
            .unwrap();
        let (ct, good_tag) = sealed.split_at(sealed.len() - 16);
        let (ct, good_tag) = (STANDARD.encode(ct), STANDARD.encode(good_tag));
        let mut raw_tag = STANDARD.decode(&good_tag).unwrap();
        raw_tag[0] ^= 1;
        let corrupt_tag = STANDARD.encode(raw_tag);
        let b64_plain = STANDARD.encode(PLAIN);

        let cases: [(&str, &str, &[u8], BodyCryptError); 6] = [
            (
                "key02",
                "AAAA",
                PLAIN,
                BodyCryptError::WrongTag("tag must be 16 bytes, got 3".into()),
            ),
            (
                "key02",
                &good_tag,
                PLAIN,
                BodyCryptError::Base64("body".into()),
            ),
            (
                "key02",
                &good_tag,
                b64_plain.as_bytes(),
                BodyCryptError::AesGcmAuth,
            ),
            (
                "key02",
                &corrupt_tag,
                ct.as_bytes(),
                BodyCryptError::AesGcmAuth,
            ),
            (
                "key03",
                &good_tag,
                ct.as_bytes(),
                BodyCryptError::AesGcmAuth,
            ),
            (
                "key99",
                &good_tag,
                ct.as_bytes(),
                BodyCryptError::UnknownKeyId("key99".into()),
            ),
        ];
        for (key, t, body, expected) in cases {
            let url = format!("https://example.com/sub?key={key}");
            let headers = tag(t);
            for stored in [None, stored_encrypted()] {
                let err = parse(&Input {
                    stored,
                    ..input(&url, &headers, body)
                })
                .unwrap_err();
                assert_eq!(
                    err,
                    Error::Decrypt {
                        key_id: Some(key.into()),
                        reason: DecryptFailure::Crypt(expected.clone()),
                    },
                    "{key} {t}"
                );
            }
        }

        let headers = tag(&good_tag);
        let ok = parse(&input(
            "https://example.com/sub?key=key02",
            &headers,
            ct.as_bytes(),
        ))
        .unwrap();
        assert_eq!(links(&ok), ["vless://a@b:1#plain"]);
    }

    #[cfg(not(feature = "body-crypt"))]
    #[test]
    fn without_body_crypt_signalled_body_fails() {
        let headers = tag("AAAAAAAAAAAAAAAAAAAAAA==");
        let err = parse(&input("https://example.com/sub?key=key02", &headers, PLAIN)).unwrap_err();
        assert_eq!(
            err,
            Error::Decrypt {
                key_id: Some("key02".into()),
                reason: DecryptFailure::CryptDisabled,
            }
        );
    }
}

/// Redacted responses of one live provider, fetched on 2026-10-12 with different User-Agents.
mod live_2026_10_12 {
    use super::*;

    const URL: &str = "https://example.org/sub/token";

    fn response(name: &str) -> (Vec<(String, String)>, Vec<u8>) {
        let raw = fixture(&format!("live-2026-10-12/{name}"));
        let (head, body) = raw
            .split_once("\r\n\r\n")
            .or_else(|| raw.split_once("\n\n"))
            .unwrap_or_else(|| panic!("{name}: no header/body separator"));
        (header_lines(head), body.as_bytes().to_vec())
    }

    fn parse_response(name: &str) -> Result<Parsed, Error> {
        let (headers, body) = response(name);
        parse(&input(URL, &headers, &body))
    }

    const DISPLAY_KEYS: [&str; 5] = [
        "announce",
        "profile-title",
        "profile-web-page-url",
        "subscription-userinfo",
        "support-url",
    ];

    fn assert_common_meta(parsed: &Parsed, with_routing: bool) {
        let changes = parsed.meta.proposed_changes();
        let mut expected: Vec<(&str, RiskClass)> = DISPLAY_KEYS
            .iter()
            .map(|k| (*k, RiskClass::Display))
            .chain([("profile-update-interval", RiskClass::Schedule)])
            .collect();
        if with_routing {
            expected.push(("routing", RiskClass::TrustBoundary));
        }
        expected.sort();
        let got: Vec<(&str, RiskClass)> = changes
            .iter()
            .map(|c| (c.key.as_str(), c.risk_class))
            .collect();
        assert_eq!(got, expected);
        assert_eq!(parsed.meta.profile_title(), Some("Example VPN 🗽"));
        assert_eq!(parsed.body_encryption, BodyEncryption::None);
    }

    #[test]
    fn happ_user_agent_gets_base64_list_and_routing_header() {
        let parsed = parse_response("01-happ-full.http").unwrap();
        let links = links(&parsed);
        assert_eq!(links.len(), 33);
        assert_eq!(scheme_counts(links), (26, 4, 3));
        // The provider sends a bare IPv6 host; the crate passes the link through unchanged.
        assert!(links.iter().any(|l| l.contains("@2001:db8::4:8443?")));
        assert_common_meta(&parsed, true);
        assert_eq!(single_profile(&parsed).name, "EXAMPLE-ROUTING");
        assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
    }

    #[test]
    fn other_user_agent_gets_no_routing_header() {
        let parsed = parse_response("03-v2rayng.http").unwrap();
        assert_eq!(scheme_counts(links(&parsed)), (26, 4, 3));
        assert_common_meta(&parsed, false);
        assert!(parsed.routing.is_empty());
    }

    #[test]
    fn refresh_without_routing_header_drops_routing_key() {
        let first = parse_response("01-happ-full.http").unwrap();
        let (headers, body) = response("03-v2rayng.http");
        let refreshed = parse(&Input {
            stored: Some(StoredState {
                encrypted: false,
                meta: Some(&first.meta),
            }),
            ..input(URL, &headers, &body)
        })
        .unwrap();
        assert!(first.meta.routing().is_some());
        assert_eq!(refreshed.meta.routing(), None);
    }

    #[test]
    fn sing_box_user_agent_gets_sing_box_json() {
        let parsed = parse_response("07-sing-box.http").unwrap();
        let Payload::SingBoxJson(config) = &parsed.payload else {
            panic!("expected SingBoxJson, got {:?}", parsed.payload);
        };
        assert_eq!(config["outbounds"].as_array().unwrap().len(), 32);
        assert_common_meta(&parsed, false);
    }

    #[test]
    fn clash_user_agent_yaml_is_unknown_content() {
        assert_eq!(
            parse_response("05-clash-verge.http").unwrap_err(),
            Error::UnknownContentType
        );
    }
}

/// Links produced by the vendor's public generator, decrypted with the embedded keys.
#[cfg(feature = "builtin-url-keys")]
mod crypt5_vendor_samples {
    use super::*;
    use happ_sub::url_crypt::{builtin_keyring, decrypt_url};
    use serde_json::Value;

    #[test]
    fn vendor_generated_links_decrypt() {
        let keyring = builtin_keyring();
        let samples: Vec<Value> = serde_json::from_str(&fixture("crypt5-samples.json")).unwrap();
        assert_eq!(samples.len(), 5);
        for sample in samples {
            let id = sample["id"].as_str().unwrap();
            let link = sample["encrypted_link"].as_str().unwrap();
            let expected = sample["expected_url"].as_str().unwrap();
            let got = decrypt_url(link, keyring).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(got, expected, "{id}");
        }
    }
}
