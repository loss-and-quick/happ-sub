# Overview

Happ (`su.happ.proxyutility`, Google Play id `com.happproxy`) is a closed-source Xray-based proxy client for Android, Android TV, iOS and macOS. Its subscription format extends the common v2rayN/v2rayNG convention (a Base64 or plain list of share links) with a metadata directive protocol, an encrypted body variant, encrypted subscription URLs, and pushed routing profiles. These documents describe those wire formats so that other clients can import Happ-compatible subscriptions, and record how each fact was established so the research can be rechecked or extended.

The reference build is Happ 4.7.1 for Android (versionCode 1703, minSdk 24, targetSdk 37; `AndroidManifest.xml`).

## Lineage

Happ is a closed-source derivative of [v2rayNG](https://github.com/2dust/v2rayNG), which is licensed under GPL-3.0. The vendor publishes no source code: [`Happ-proxy/happ-android`](https://github.com/Happ-proxy/happ-android) holds only a README, a `release` JSON and APK binaries. The v2rayNG ancestry is visible in the decompiled 4.7.1 APK, which keeps v2rayNG's class names for the data model and the updater: `SubscriptionItem`, `ServerConfig`, `VmessQRCode`, `MetaParams`, `EConfigType`, and the WorkManager worker `service/SubscriptionUpdater$UpdateTask`. On top of that base Happ rewrote the UI in Jetpack Compose and added the metadata protocol, both encryption layers, HWID-based device binding, routing profiles and the `happ://` deeplinks.

Components of the 4.7.1 APK:

| Component | Role |
|---|---|
| Kotlin + Jetpack Compose | UI and all subscription logic |
| `libgojni.so`, `libcore.so` | Xray-core built with gomobile |
| `libhev-socks5-tunnel.so` | TUN to SOCKS bridge |
| `liberror-code.so` (arm64, bionic) | Native string table and crypto helpers used by both encryption layers; the JNI entry is `jniGetErrorMessageFromCode(int)` |
| MMKV | Key-value persistence |
| Sentry | Crash reporting SDK, bundled with auto-init off ([08](08-device-binding.md#vendor-services)) |

## How the facts were established

Every claim carries one of four tags:

| Tag | Meaning |
|---|---|
| **VERIFIED** | Confirmed by the decompiled code or native disassembly **and** by live provider traffic, Happ's observed behaviour on a device, a vendor test vector, or a decryption of real data. |
| **DOCUMENTED** | Stated in the vendor's provider documentation at [happ.su/main/dev-docs](https://www.happ.su/main/dev-docs), not seen in live traffic. |
| **INFERRED** | Read from the decompiled code only; no live sample and no vendor statement. |
| **UNKNOWN** | Could not be settled statically or empirically. |

Sources behind the tags:

- **Decompiled code.** The 4.7.1 APK was decompiled with jadx (with and without resource resolution) and apktool. R8 renamed most classes into the default package with two- or three-letter names. A citation such as `kz1.java:171` means line 171 of the decompiled default-package class `kz1`; `dto/SubscriptionItem.java` and `dto/enums/…` are kept classes under `su/happ/proxyutility/`. Obfuscated classes were identified by their surviving `toString()` output (for example `vl7` prints `SubscriptionProperties(…)`). User-visible strings are cited by their resource name (`parsing_error_invalid_server`).
- **Native code.** `liberror-code.so` was disassembled for offsets and executed under an arm64 Android emulator to dump its string table ([04](04-body-encryption.md#how-the-keys-were-extracted)).
- **Vendor documentation.** The provider pages at happ.su, in English and Russian; the Russian pages are fuller.
- **Live material.** One real provider's responses, captured once earlier and again on 2026-10-12 with 15 `User-Agent` and URL variants (redacted; names replaced by `Example VPN` / `EXAMPLE-ROUTING`), and five `happ://crypt5/` links from the vendor's public generator at `crypto.happ.su`. They are in [`tests/fixtures/`](../tests/fixtures/).
- **Happ on a device.** Happ 4.7.1 on a rooted Android phone, fed scripted responses by a mock subscription server, with its stored state decrypted after every step (2026-10-12). Facts settled this way are marked "on-device mock".
- **Other APK versions.** 3.20.4 through 4.7.0 were collected to measure key stability ([04](04-body-encryption.md#key-stability-across-versions)).

The ledger of all checks, including the ones that overturned earlier claims, is in [10](10-verification.md).

## Two independent encryption layers

A Happ subscription can be hidden at two points, and the two are unrelated (**VERIFIED**: `SubscriptionItem.encryptedUrl` at `dto/SubscriptionItem.java:24` and `SubscriptionItem.encrypted` at `:18` are separate fields with separate code paths):

| | URL encryption | Body encryption |
|---|---|---|
| Hides | the subscription URL from the user | the response body from observers and the user |
| Wire form | `happ://crypt/` … `happ://crypt5/` deeplink | plain HTTPS URL with `?key=keyNN`, `Encrypt-Tag` response header |
| Primitives | RSA PKCS#1 v1.5; crypt5 adds ChaCha20-Poly1305 | AES-128-GCM with a fixed IV |
| Key material | RSA private keys inside `liberror-code.so`; embedded in this crate with the `builtin-url-keys` feature | 90 symmetric keys assembled at runtime; shipped in `src/keys/gen1.rs` |
| Applied | before the fetch (`e53.java:221`) | after the fetch (`e53.java:44`) |

An encrypted URL may lead to a plaintext body, and a plain URL may return an encrypted body.

```
happ://crypt5/<payload>
        │  URL decryption (05)
        ▼
https://provider.example/sub/abc?key=key02
        │  HTTP GET (07)
        ▼
headers: meta directives (03), Encrypt-Tag
body:    Base64 ciphertext
        │  body decryption (04)
        ▼
#profile-title: …         ← body meta directives (03)
happ://routing/onadd/…    ← routing profile (06)
vless://…                 ← payload (02)
```

## Terminology

| Term | Meaning |
|---|---|
| Subscription | A provider URL that returns a set of proxy servers plus metadata; stored as `SubscriptionItem` under a `subId`. |
| Meta directive | A provider setting delivered as an HTTP response header or a `#key: value` body line, parsed into `MetaParams`. See [03](03-meta-protocol.md). |
| Key ID | `key01` … `key90`, chosen by the `?key=` query parameter of the subscription URL; selects the body AES key. See [04](04-body-encryption.md). |
| Marker | 8-character token inside a `crypt5` payload that selects one of 36 RSA private keys. See [05](05-url-encryption.md). |
| HWID | Device identifier Happ sends in `X-HWID`; on Android the `ANDROID_ID`. See [08](08-device-binding.md). |
| Provider ID, Install ID | Vendor-backend identifiers for providers and per-device activations. See [08](08-device-binding.md). |
| DNSTT | DNS TXT tunnel the client uses to reach the vendor's licensing backend when HTTPS is blocked. See [08](08-device-binding.md). |
| Deeplink | A `happ://` URI (`dto/enums/EDeeplinkType.java`). See [06](06-deeplinks-and-routing.md). |
| Routing profile | Base64 JSON rule set delivered by `happ://routing/add/` or `happ://routing/onadd/`. See [06](06-deeplinks-and-routing.md). |
| Custom config | A JSON configuration (object with `outbounds`) delivered as the body; Happ imports it as `EConfigType.CUSTOM` and runs it with Xray. See [02](02-subscription-body.md). |

## Confidence and open questions

Whole-body Base64 subscriptions with meta headers are **VERIFIED** against one live provider, and `crypt5` against five generator links. Body encryption is **VERIFIED** through the vendor's `key02` test vector, the extracted keys and Happ 4.7.1 decrypting a mock server's bodies on a device ([04](04-body-encryption.md)). The on-device probe also settled the default request, the refresh merge, failure handling and routing delivery, and overturned several earlier inferences ([10](10-verification.md#corrections)). Platform coverage beyond Android is **DOCUMENTED** only; the wire formats are assumed identical across platforms.
