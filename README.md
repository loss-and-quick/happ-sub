# happ-sub

A zero-I/O Rust library for importing Happ-compatible (`su.happ.proxyutility`) subscriptions. Given the subscription URL, response headers and body that the caller fetched, it decrypts the body if needed, extracts meta directives and routing profiles, detects the payload form, merges metadata, and classifies every provider directive by risk so the caller can decide what to apply. It also parses `happ://` deeplinks and decrypts `happ://crypt*` URLs, with embedded keys or a caller-supplied keyring, and unwraps INCY's `incy://crypt1/` URL obfuscation ([docs/11](docs/11-incy-url-obfuscation.md)). It also builds the subscription request Happ would send: its headers in wire order, `User-Agent`, timeout and retry rules, from device facts and user overrides the caller supplies. With the `device` feature it computes the HWID Happ sends, its SSAID. It is written for [Kasumi Proxy](https://github.com/loss-and-quick/Kasumi-Proxy) and usable by any client.

## Features

| Feature | Default | Adds |
|---|---|---|
| `body-crypt` | yes | AES-128-GCM body decryption with the built-in key table (`aes-gcm`) |
| `url-crypt` | no | `happ://crypt/` … `happ://crypt5/` decryption with a caller-supplied keyring (`chacha20poly1305`, `rsa`) |
| `builtin-url-keys` | no | Enables `url-crypt` and embeds the RSA keys as `url_crypt::builtin_keyring()` (about 125 KB) |
| `incy-crypt` | no | `incy://crypt1/` decryption and link generation under a 32-byte key the caller supplies (`aes-gcm`, `sha2`) |
| `builtin-incy-keys` | no | Enables `incy-crypt` and embeds the Incy keymat assets as `incy_crypt::builtin_key()` (about 11 KB) |
| `happ-request` | no | `happ_request::build`: the request Happ sends — headers in wire order, `User-Agent`, timeout, retry, cookie jar |
| `incy-request` | no | `incy_request::build_request`: the request Incy sends — its `User-Agent`, `x-` headers and device id (`sha2`) |
| `incy-signers` | no | `incy_signers::INCY_PACKAGE` and `INCY_SIGNERS`: Incy's package name and signing certificates |
| `test-vectors` | no | Enables `body-crypt` and exposes `body_crypt::encrypt_with_table`, for producing encrypted samples in tests |
| `device` | no | `device::ssaid`: the SSAID Happ sends as `X-HWID`, from a caller-supplied user key and the embedded Happ signing certificate (`hmac`, `sha2`, `happ-request`) |

## Scope

In scope: body form detection, the meta directive protocol, body decryption, URL decryption, routing profiles, deeplinks and the request headers Happ sends. With `incy-crypt` and `incy-request`, the same two jobs for the INCY client, whose formats are a subset of Happ's plus its own URL obfuscation ([docs/12](docs/12-incy-client.md)).

Not in scope:

- Share-link parsing (`vless://`, `vmess://`, `ss://`, …). Links are returned verbatim for the caller's own parser.
- Networking and file I/O. The caller fetches and passes `(url, headers, body)`.
- Policy. The crate classifies directives; it applies none of them.

## Usage

```rust
use happ_sub::{parse, BodyEncryption, Input, Payload};

fn main() -> Result<(), happ_sub::Error> {
    let headers = vec![(
        "profile-title".to_string(),
        "base64:RXhhbXBsZSBWUE4g8J+MkA==".to_string(),
    )];
    let input = Input {
        url: "https://provider.example/sub/abc",
        headers: &headers,
        body: b"vless://uuid@host.example:443?security=reality#node-1\n",
        stored: None,
        limits: None,
    };

    let parsed = parse(&input)?;
    assert_eq!(parsed.meta.profile_title(), Some("Example VPN 🌐"));
    assert_eq!(parsed.body_encryption, BodyEncryption::None);

    match parsed.payload {
        Payload::Links(links) => println!("{} links", links.len()),
        Payload::XrayJson(_) => println!("custom Xray config"),
        Payload::SingBoxJson(_) => println!("sing-box config"),
        Payload::JsonArray(items) => println!("{} JSON servers", items.len()),
    }
    for change in parsed.meta.proposed_changes() {
        println!("{} = {} ({:?})", change.key, change.value, change.risk_class);
    }
    for warning in &parsed.warnings {
        eprintln!("skipped: {warning:?}");
    }
    Ok(())
}
```

## Import and refresh

On import, pass the URL as the user gave it. Its fragment (`#name?key=value&…`) carries meta directives, and `parse` merges the response over them ([docs/03](docs/03-meta-protocol.md#url-fragment)). Fetch and store `meta::fetch_url(url)`, which is the URL without the fragment, as Happ does. On refresh, pass the stored map and say how the refresh started: `MergeMode::Full` for one the user started, which drops absent keys except the sticky ones, and `MergeMode::Partial` for a background update, which keeps them ([docs/03](docs/03-meta-protocol.md#precedence-and-refresh-merge)).

```rust
use happ_sub::{parse, Input, MergeMode, MetaMap, StoredState};

fn refresh(
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    stored: &MetaMap,
) -> Result<MetaMap, happ_sub::Error> {
    let parsed = parse(&Input {
        url,
        headers,
        body,
        stored: Some(StoredState {
            encrypted: false,
            meta: Some(stored),
            merge: MergeMode::Full,
        }),
        limits: None,
    })?;
    Ok(parsed.meta)
}
```

## Building the request

`happ_request::build` returns the request Happ would send: its headers in Happ's order and spelling, the per-attempt timeout, the retry rules and whether to keep a cookie jar. The caller supplies the device facts, the HWID, the user's per-subscription overrides, the current time, the subscription's merged metadata and the user's consent to `TrustBoundary` keys; the crate applies Happ's precedence ([docs/07](docs/07-fetch-and-update.md#request)). It lives behind the `happ-request` feature, so this example is compiled by the feature-gated doctest on `happ_request` rather than here.

```rust,ignore
use std::time::{SystemTime, UNIX_EPOCH};

use happ_sub::happ_request::{self, ClientOs, DeviceInfo, Identity, RetryCause};
use happ_sub::MetaMap;

let identity = Identity {
    // The SSAID (`device::ssaid`) or any identifier the client chooses; `None` sends no X-HWID.
    hwid: Some("0123456789abcdef".into()),
    device: DeviceInfo {
        os: ClientOs::Android,
        os_version: "16".into(),
        model: "Pixel 9".into(),
        locale: "en-US".into(),
    },
    // `user_agent_override`, `send_hwid_override`, `hwid_in_cookie_override`: the user's settings.
    ..Identity::default()
};
let stored: Option<&MetaMap> = None; // the merged meta from the last fetch; none on import
let accepted = ["change-user-agent"]; // TrustBoundary keys the user accepted
let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

let profile = happ_request::build(&identity, stored, now, |key| accepted.contains(&key));
assert_eq!(profile.headers[0], ("Connection".into(), "close".into()));
assert_eq!(profile.headers[1].0, "User-agent");
assert!(profile.headers[1].1.starts_with(&format!("Happ/{}/Android/", happ_sub::HAPP_VERSION)));
assert_eq!(profile.timeout.as_secs(), 7);

// Send `profile.headers` in order and let the client add Host and Accept-Encoding. If the
// call fails, retry once with the headers and resolver mode for the failure.
let retry = profile.retry(RetryCause::TimeoutOrIo);
assert!(retry.ipv4_only);
```

`HAPP_VERSION` and `HAPP_VERSION_CODE` name the Happ release the crate follows. They and the other release constants live in [`src/release.rs`](src/release.rs), generated by happ-key-extractor.

## Risk classes

Every meta key maps to a `RiskClass` (`meta::classify_key`). The full per-key table is in [docs/03-meta-protocol.md](docs/03-meta-protocol.md#key-reference).

| `RiskClass` | Keys | Suggested handling |
|---|---|---|
| `Display` | `profile-title`, `announce`, `subscription-userinfo`, `support-url`, `profile-web-page-url`, `sub-info-*`, `sub-expire`, `sub-expire-button-link` | Apply automatically |
| `Schedule` | `profile-update-interval` (1..=730 h), `subscription-request-timeout` (5..=15 s), `subscription-auto-update-open-enable`, `notification-subs-expire`, `subscription-sort-type`, `subscriptions-sort-type`, `subscriptions-collapse`, `subscriptions-expand-now`, `subscription-pin`, `subscription-ping-onopen-enabled` | Apply automatically, clamped |
| `TunnelBehaviour` | `mux-*`, `fragment`, `fragmentation-*`, `noises-*`, `sniffing-enable`, `preferred-ip-type`, `proxy-ping-*`, `ping-type` | Show, or apply on opt-in |
| `TrustBoundary` | `new-url`, `new-domain`, `fallback-url`, `host`, `insecure`, `change-user-agent`, `manual-block-user-agent`, `user-agent-geo-files`, `check-url-via-proxy`, `routing`, `routing-enable`, `per-app-proxy-*`, `exclude-routes*`, `dont-use-filter`, `dns-from-json-enable`, `local-dns-enable`, `resolve-address`, `server-address-resolve-*`, `inbound-http-enable`, `http-auth-*`, `socks-auth-*`, `xray-tun-*`, `block-bind-to-tunnel-enable`, `app-auto-start`, `subscription-autoconnect*`, `hide-settings` | Require per-subscription consent |
| `DeviceIdentity` | `providerid`, `installid`, `hwidlink`, `subscription-send-hwid-enabled`, `subscription-always-hwid-enable`, `subscription-hwid-in-cookie-enable` | Ignore by default |
| `Ignored` | `ping-result`, `reset` and unknown keys | Ignore |

## Deliberate differences from Happ

The crate follows Happ 4.7.1 as observed on a device, except where Happ loses data or imports something that cannot work ([docs/10](docs/10-verification.md#corrections)):

| Input | Happ 4.7.1 | `parse` |
|---|---|---|
| Body decryption fails (wrong or unknown key, corrupt tag, plaintext sent with a tag) | Imports an empty body: servers wiped, success shown | `Err(Error::Decrypt { key_id, reason })`, so the caller keeps its servers |
| sing-box JSON body | Imported as an Xray custom config that cannot run | `Payload::SingBoxJson` |
| URL-safe whole-body Base64 | Mis-decoded into one broken server | Decoded correctly |
| JSON object or array element without `outbounds` | Imported as a custom config | `InvalidServer` / `InvalidJsonArray` |
| Line that is not `<scheme>://…` | Skipped silently | Skipped, reported as `Warning::SkippedLine` |
| Malformed `<scheme>://…` link | Imported as a broken server | Passed through for the caller's link parser |
| Empty `200` body | Success with zero servers | `Err(Error::EmptyBody)` |
| URL fragment segment without `=` (`#?a=1&b`) | Rejects the whole import | Fragment directives ignored, `Warning::InvalidFragment` |
| `sub-info-text: 0` on an import without a fragment | Stored as the text `0` | Dropped, as on every later merge |

`happ_request::build` follows Happ's request with these differences ([docs/07](docs/07-fetch-and-update.md#device-identifiers)):

| Input | Happ 4.7.1 | `happ_request::build` |
|---|---|---|
| `subscription-always-hwid-enable`, `subscription-hwid-in-cookie-enable`, `manual-block-user-agent` | Lock the user's switch or User-Agent field | The user's override wins; the lock is reported in `RequestProfile::locks` |
| `subscription-send-hwid-enabled`, `subscription-always-hwid-enable`, `change-user-agent` dropped by a later full refresh | Their effect stays in the subscription's settings | The effect ends with the key; persist it as a user override to keep it |
| A header value with characters OkHttp rejects (non-ASCII, line breaks) | The fetch fails | The characters are dropped |
| `insecure` | Applied only to an `EXTRA` subscription | Never applied |

## Key material

- The 90 body keys are interoperability constants, shipped in [`src/keys/gen1.rs`](src/keys/gen1.rs). `key02` is the test key published in the vendor's provider documentation.
- The `builtin-url-keys` feature embeds the `crypt` … `crypt5` RSA private keys, needed to decrypt vendor-issued links client-side. They are `crypt5_keys.json` from [KernelEditor/HappDecrypt](https://github.com/KernelEditor/HappDecrypt) at commit `8d0b97b1875446abb16a0d1b62492a404e766860`, shipped unmodified as [`src/keys/url-keys.json`](src/keys/url-keys.json). Without the feature, `url-crypt` works with any caller-supplied `Keyring`.
- The `device` feature embeds Happ 4.7.1's signing certificate, public data present in every copy of the APK, as [`src/device/signers.rs`](src/device/signers.rs), generated by happ-key-extractor. The per-user key the SSAID also needs is never embedded; the caller reads it from the device ([docs/08](docs/08-device-binding.md#ssaid-derivation)).
- The `builtin-incy-keys` feature embeds the two 4 KiB assets behind INCY's `incy://crypt1/` scheme, as [`src/keys/incy-keymat.json`](src/keys/incy-keymat.json). They are byte-identical to `assets/*.bin` in [INCY-DEV/incy-link-encoder](https://github.com/INCY-DEV/incy-link-encoder) (MIT), which derives the same key from them; the key itself is computed at run time by `incy_crypt::derive_key` and checked against the fingerprint that package pins. Without the feature, `incy-crypt` works with any 32-byte key the caller holds ([docs/11](docs/11-incy-url-obfuscation.md)).
- The `incy-signers` feature embeds Incy 3.7.0's signing certificate — public data in every copy of the APK — as [`src/incy_signers.rs`](src/incy_signers.rs), extracted from the release APK. It identifies the app; it is not an input to its device id, which comes from `android_id` rather than from the certificate ([docs/12](docs/12-incy-client.md#signing-certificates)).
- The body scheme uses a fixed IV. It is implemented for client-side import only and must not be used to serve subscriptions.

## Documentation

The wire formats are specified in [docs/](docs/README.md), with the evidence for each claim:

1. [Overview](docs/01-overview.md)
2. [Subscription body](docs/02-subscription-body.md)
3. [Meta directive protocol](docs/03-meta-protocol.md)
4. [Body encryption](docs/04-body-encryption.md)
5. [URL encryption](docs/05-url-encryption.md)
6. [Deeplinks and routing](docs/06-deeplinks-and-routing.md)
7. [Fetch and update](docs/07-fetch-and-update.md)
8. [Device binding and vendor services](docs/08-device-binding.md)
9. [Implementation guide](docs/09-implementation-guide.md)
10. [Verification ledger](docs/10-verification.md)
11. [Incy URL obfuscation](docs/11-incy-url-obfuscation.md)
12. [The Incy client](docs/12-incy-client.md)

## Development

With Nix, `nix develop` provides the pinned toolchain (`rust-toolchain.toml`); `nix flake check` runs the packaged checks. Without Nix, use rustup with the same toolchain.

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --no-default-features
cargo test --all-features
```

CI runs the same commands plus `nix flake check`. The `crypt5` vendor samples in [`tests/fixtures/`](tests/fixtures/) are decrypted with the embedded keys whenever `builtin-url-keys` is enabled.

## License

Licensed under either of MIT or Apache-2.0, at your option.
