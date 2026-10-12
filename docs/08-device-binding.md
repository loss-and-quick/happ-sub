# Device binding and vendor services

Happ ties subscriptions to devices and talks to the vendor's own backend for licensing, device limits, crash reporting and cloud sync. None of this is part of the subscription format a provider serves, and a third-party client should implement none of it. This document records what the client does so that the related meta keys can be understood, and explains why the crate classifies them as `DeviceIdentity` and recommends ignoring them.

## Hardware identifier (HWID)

On Android the HWID is the platform's `ANDROID_ID`, a 16-character hex string per device and user profile (**VERIFIED**: `uk8.j(context)` at `uk8.java:529` reads `Settings.Secure` `android_id`; [HWID links](https://www.happ.su/main/dev-docs/hwid-links) describes the identifier).

It is sent on subscription fetches as `X-HWID`, together with `X-Device-OS` (`Android` or `AndroidTV`), `X-Ver-OS` and `X-Device-model` (`uj7.java:57`). Happ sends all four by default, on the first import and on every refresh, and the per-subscription "send HWID" switch is on by default (**VERIFIED**, on-device mock, 2026-10-12: `X-HWID` was 16 lowercase hex characters equal to the HWID Happ displays). Three meta keys control this:

| Key | Effect |
|---|---|
| `subscription-send-hwid-enabled` | Send `X-HWID` on subscription fetches (Happ's default is to send it) |
| `subscription-always-hwid-enable` | Send the identifiers on every request |
| `subscription-hwid-in-cookie-enable` | Also put the HWID in a cookie (the fetcher installs a `CookieJar` for this) |

## Local check: `hwidlink`

A provider can bind a subscription to one device by adding `hwidlink=<hwid>` to the subscription URL:

```
https://vpn.example.com/sub/user123?hwidlink=4a1b2c3d4e5f6789
```

On import `hq4.p()` compares the value with the local `ANDROID_ID` (`hq4.java:447`). On mismatch Happ keeps the `SubscriptionItem` but disables its import and deletes its servers, and the UI shows "Access to subscription is restricted" (`restricted_access`). The check is entirely client-side: the provider never sees it, and a client that ignores the parameter bypasses it (**INFERRED** from `hq4`; **DOCUMENTED** in [HWID links](https://www.happ.su/main/dev-docs/hwid-links)).

## Remote checks (`TypeCheck`)

For providers registered with the vendor, Happ verifies the subscription against the vendor's backend over one of three transports, `TypeCheck { FILE, DNSTT, REST }` (`dto/enums/TypeCheck.java`). The result is `SubscriptionRestrictedStatus { import, providerId, status }` (`dto/SubscriptionRestrictedStatus.java`). All of this is **INFERRED** from the code.

The provider "extra check" (`eq0`, `xp0`) also sets `SubscriptionItem.status`. Only a subscription whose status is `EXTRA` gets `fallback-url`, `new-url`, `new-domain`, `host`, `insecure`, `resolve-address` and `fragment` applied ([07](07-fetch-and-update.md#alternative-fetch-targets)), and the boolean `reset`, read only from the subscription URL fragment, is consumed on this path ([03](03-meta-protocol.md#precedence-and-refresh-merge)). What makes a subscription `EXTRA` is **UNKNOWN**.

### REST

`bo.java` sends `GET https://time-ntp.com/v1install?id=<installId>` (alternative host `ntp2-sync.com`; the service is also known as `check.happ-proxy.com`) with the headers:

```
X-HWID, X-Ver-OS, X-Bundle-ID: su.happ.proxyutility, X-Device-model,
X-Device-OS: Android | AndroidTV, X-API-Version: 1.0, X-App-Version: 4.7.1,
X-Sub-Expire, X-Domain-Hash, X-Provider-ID, X-Credential
```

`X-Credential` is an HS256 JWT with the claims `hwid`, `iss = su.happ.proxyutility`, `sub` (one of `install`, `remotepush`, `provider`, `sendtv`, `report`, `stdnsttv`) and `iat`. The signing key is assembled at runtime from obfuscated string constants and a native string (`bo.java:43-80`); it was not recovered.

### DNSTT

When HTTPS to the REST hosts is blocked, the same request goes through a DNS TXT tunnel (`fq1.java`, `lq1.java`, `sq1.java`):

- Domains: `t.polend.org`, `t.pullse.org`, `t.itine.org`, `ads.pullse.org`, `cloud.itine.org` (`fq1.java:47`).
- Request: a `RequestEnvelope` (`util/dnsttv/dto/RequestEnvelope.java`: device OS, API and app version, route, subscription expiry, OS version, HWID as hex, bundle ID, device model, domain hash as hex, `pids`, `iid`, `tid`), Base64-chunked into the TXT query name.
- Reply: length-prefixed segments followed by an 8-byte HMAC-SHA256 tag and a 16-byte nonce echo. The HMAC key is the 32 bytes hex-decoded (`uk8.r`) from `c33b18ca2035aa44330a757316ab0f92aa18572a284543af2388950e62fadb4f` (`fq1.java:46`).
- Probe messages `v1/probe-out` and `v1/probe-in` (`lq1.java:32-35`).

### FILE

`bo.k(File)` uploads a multipart zip to `time-ntp.com/v1report`.

## Provider and install IDs

| Key | Wire forms | What the client does |
|---|---|---|
| `providerid` | URL query `#?providerid=…`, body `#providerid …`, or header `providerid:` | A daily `GET …/provider?id={ProviderID}` with the HWID, domain hash and OS, unlocking provider-only settings (**DOCUMENTED**: [Provider ID](https://www.happ.su/main/dev-docs/provider-id)) |
| `installid` | Meta key | "Limited links": the subscription domain is stored server-side as SHA-256. On import the app computes `HashedDomain = hex(SHA-256(authority))`, where `authority` is the URL text between `://` and the next `/` (`host:port` when the URL has a port), or the `host` meta value when one is set (`uk8.q`, `uk8.java:670`; **VERIFIED**, on-device mock, against a URL with a port) and calls `…/install?id={domain_hash}&installid={InstallID}`; over the device limit the subscription is restricted (**DOCUMENTED**: [Limited links](https://www.happ.su/main/dev-docs/limited-links)) |

Result codes, `AdditionalInfoCode` (`dto/AdditionalInfoCodeKt.java`):

| Code | Cause | UI string |
|---|---|---|
| 100 | Device clock differs from the server by more than 24 h | `restricted_access` |
| 106 | Tariff limit reached | `restricted_access` |
| 112, 122 | Domain hash not found | `restricted_access` |
| 121, 124 | Limited-link install code invalid or not found | `restricted_access` |
| 125 | Install limit reached | `restricted_access_mf` |

## Domain hash registry

`assets/data.result` is an encrypted, zstd-compressed JSON registry. Its decryption with the native `kz1.c` key `CHku5|fRC77gcp0,` and IV `vrbculqfahmw` is in [04](04-body-encryption.md#the-second-native-key-kz1c-and-assetsdataresult) (**VERIFIED**: the tag authenticates and the result parses).

- Contents: 390 groups mapping to 1339 SHA-256 hex digests of subscription domains (1256 distinct).
- Meaning: `sha256("happ.su")` is in group `SEVACODE` and `sha256("crypto.happ.su")` in `TMsupp01`, so the registry maps subscription-domain hashes to provider codes. It feeds `SubscriptionItem.hashedDomain` and `CheckSubscriptionExtraResult(hashedDomain, extraResult, typeCheck)`.
- Lifecycle (`j52.java`, `p52.java`, `nu.java`): the bundled copy is used only within 30 days (`2592000000` ms) of the build time `1791210317680`; a downloaded copy in `filesDir` is refreshed when older than 24 h (`86400000` ms), written to `data.result.tmp` and renamed.

## Vendor services

Endpoints and identifiers found in the 4.7.1 client:

| Service | Details | Code |
|---|---|---|
| Sentry crash reporting | DSN `https://dc4747c4eb1f380d72dd79917ed695c7@o312638.ingest.us.sentry.io/4507922783731712` (US region, organisation `o312638`); the manifest sets `io.sentry.auto-init=false` and the client initialises it manually | `e96.java:154` |
| Licensing REST gate | `time-ntp.com`, `ntp2-sync.com` (`/v1install`, `/provider`, `/v1report`) | `bo.java` |
| DNSTT tunnel | `t.polend.org`, `t.pullse.org`, `t.itine.org`, `ads.pullse.org`, `cloud.itine.org` | `fq1.java:47` |
| Send to device | `POST https://api.apple-cloudkit.com/database/1/iCloud.su.ffg.happ/development/public/records/lookup?ckAPIToken=109c641156b4e2deaad787fb678b36fe2e8c0060e13bd48e42f795e8f75c8500` with a fixed `recordName`, then `GET` of the returned download URL and import. Data leaving: the record name and the HWID headers. The container `iCloud.su.ffg.happ` matches the APK signer (FlyFrog LLC). | `d03.java:39`, `nu.java:799` |
| Daily statistics | A daily REST check with the hard-coded `providerId=I8AmwFEw` and `installId=438188ae27605b83f6ba5c5aee91993ce6bf7031c489999c97150b95417a9856`; the backend is chosen by `gn` (`NTP2_SYNC` or `TIME_NTP`) | `xd4.java:53`, `xd4.java:73` |
| TV mode | `https://tv.happ.su/` | |
| Domain fallback list | `cdn.jsdelivr.net` / `raw.githubusercontent.com` copies of `Happ-proxy/app_domain` ([07](07-fetch-and-update.md#alternative-fetch-targets)) | `jg7.java:23` |
| App update check | `https://cdn.jsdelivr.net/gh/Happ-proxy/happ-android@main/release`, the same file on `raw.githubusercontent.com`, and `https://pastebin.com/raw/vc3ficrq` | |

Observed on the device during the on-device probe, from logcat, Happ's own logs and `/proc/net` snapshots (on-device mock, 2026-10-12; short connections may have been missed):

- `api.apple-cloudkit.com` at every start: Happ logs "iCloud file download result", then "Happ file failed" and "Fallback to assets"; the vendor domain list then appears in `SETTING.pref_blacklist`.
- Push-token registration at every start ("send token with providerid:0 success:false"); Firebase Messaging and Installations state is present.
- Sentry: the SDK is bundled and keeps a session cache, with auto-init off in the manifest.
- GitHub (an address in `185.199.108.0/22`) for the geo files of every routing profile ([06](06-deeplinks-and-routing.md#what-happ-does-with-a-delivered-profile)).

## What a third-party client controls

| Aspect | Client side | Provider side |
|---|---|---|
| HWID | A client can send any value, a random one, or the same one on several devices. | The panel records the `X-HWID` values it receives. |
| Header suppression | A client can omit `X-HWID` entirely. | The panel decides whether to reject requests without it or without `installid`. |
| `hwidlink` | A client can ignore it; the check is purely local. | The panel never sees the check. |
| Concurrent use | None. | Enforced by the proxy nodes, which can limit concurrent sessions per credential. |

This is why the crate classifies `providerid`, `installid`, `hwidlink`, `subscription-send-hwid-enabled`, `subscription-always-hwid-enable` and `subscription-hwid-in-cookie-enable` as `DeviceIdentity` and recommends ignoring them: they either feed a vendor backend a third-party client has no business contacting, or implement a lock that only works in a client that chooses to enforce it. Sending a device identifier should be an explicit per-subscription user choice for providers that require it.

## Confidence and open questions

The HWID source and `hwidlink` handling are **VERIFIED** (code and vendor documentation). The REST, DNSTT and FILE transports, the vendor endpoints and the result codes are **INFERRED** from the code; `providerid` and `installid` flows are also **DOCUMENTED**. The registry is **VERIFIED** by decryption. Default sending of the device identifiers, the domain hash input and the vendor hosts Happ contacts at start are **VERIFIED** on a device; the research itself contacted no vendor endpoint. A live provider served the same content with and without device identifiers (live probe, 2026-10-12).

Open questions:

- The JWT signing key is **UNKNOWN**: it is assembled at runtime and was not traced.
- Which providers are registered for remote checks, and how often the registry changes, is **UNKNOWN**.
- What sets a subscription's status to `EXTRA` is **UNKNOWN**.
