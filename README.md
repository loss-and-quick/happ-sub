# happ-sub

A zero-I/O Rust library for importing Happ-compatible (`su.happ.proxyutility`) subscriptions. Given the subscription URL, response headers and body that the caller fetched, it decrypts the body if needed, extracts meta directives and routing profiles, detects the payload form, merges metadata, and classifies every provider directive by risk so the caller can decide what to apply. It also parses `happ://` deeplinks and decrypts `happ://crypt*` URLs, with embedded keys or a caller-supplied keyring. It is written for [Kasumi Proxy](https://github.com/loss-and-quick/Kasumi-Proxy) and usable by any client.

## Features

| Feature | Default | Adds |
|---|---|---|
| `body-crypt` | yes | AES-128-GCM body decryption with the built-in key table (`aes-gcm`) |
| `url-crypt` | no | `happ://crypt/` … `happ://crypt5/` decryption with a caller-supplied keyring (`chacha20poly1305`, `rsa`) |
| `builtin-url-keys` | no | Enables `url-crypt` and embeds the RSA keys as `url_crypt::builtin_keyring()` (about 125 KB) |
| `test-vectors` | no | Enables `body-crypt` and exposes `body_crypt::encrypt_with_table`, for producing encrypted samples in tests |

## Scope

In scope: body form detection, the meta directive protocol, body decryption, URL decryption, routing profiles and deeplinks.

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

## Key material

- The 90 body keys are interoperability constants, shipped in [`src/keys/gen1.rs`](src/keys/gen1.rs). `key02` is the test key published in the vendor's provider documentation.
- The `builtin-url-keys` feature embeds the `crypt` … `crypt5` RSA private keys, needed to decrypt vendor-issued links client-side. They are `crypt5_keys.json` from [KernelEditor/HappDecrypt](https://github.com/KernelEditor/HappDecrypt) at commit `8d0b97b1875446abb16a0d1b62492a404e766860`, shipped unmodified as [`src/keys/url-keys.json`](src/keys/url-keys.json). Without the feature, `url-crypt` works with any caller-supplied `Keyring`.
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
