# Fetch and update

The crate performs no I/O. This document describes the request a Happ-compatible client sends, how it reacts to the response, and how it schedules refreshes. In Happ the fetch is `uj7.d(url, subId, proxy, headers, …)`, which calls the OkHttp wrapper `e52.a(request, insecure, timeout, proxy, dns, …)`. Facts marked "on-device mock" were observed on Happ 4.7.1 against a mock server on 2026-10-12, facts marked "live probe" on one live provider the same day ([10](10-verification.md#live-probes-2026-10-12)); the rest is **INFERRED** from the classes named.

## Request

A plain HTTP/1.1 `GET` of the subscription URL. Happ sends these headers in this order on the first import and on every refresh (**VERIFIED**, on-device mock, 2026-10-12; `e52.java:208`, `uj7.java:57`):

```http
Connection: close
User-agent: Happ/4.7.1/Android/17912103176801703650
X-Device-Locale: ru
X-HWID: <16 lowercase hex characters>
X-Device-OS: Android
X-Ver-OS: 16
X-Device-model: <Build.MODEL>
Host: <host>:<port>
Accept-Encoding: gzip
```

| Header | Value |
|---|---|
| `User-agent` | Spelled exactly so. Built by `wb8.S("Android")` as `"Happ/4.7.1/" + os + "/" + "1791210317680" + "1703" + d + "50"`, where `1791210317680` is a millisecond timestamp (2026-10-05 14:25:17 UTC), `1703` the version code, and `d` is `6` on an even UTC day of the month and `5` on an odd one. Replaced by the `change-user-agent` key or a per-subscription user setting (`vl7.i`). |
| `X-Device-Locale` | UI language tag, e.g. `en`, `ru` |
| `X-HWID`, `X-Device-OS`, `X-Ver-OS`, `X-Device-model` | Sent by default: the `ANDROID_ID`, `Android` or `AndroidTV`, the Android release, `Build.MODEL`. The per-subscription "send HWID" switch is on by default. See [below](#device-identifiers). |
| `Authorization` | `Basic <base64(user:pass)>` when the URL has userinfo (`https://user:pass@host/…`; `e52.java:205`, not exercised on device) |
| `Cookie` | Not on the first request. Cookies set by any response are kept in a persistent jar keyed by host and sent on every later request to that host, including other paths and other subscriptions (on-device mock). |

The live provider gated its response format on the `User-Agent` and added the `routing` header only for values starting with `Happ` ([below](#provider-behaviour-observed-live)). A client that wants Happ's responses has to send a `Happ/…` `User-Agent`; the full default above is not needed.

### Fetch controls

| Control | Behaviour | Source key | Code |
|---|---|---|---|
| Timeout | 5 to 15 seconds, default 7. A hanging server got two requests 7 s apart, the original and one retry, and the stored servers were kept (on-device mock) | `subscription-request-timeout` or user setting | `uj7.java:64` |
| TLS verification | Trust-all `X509TrustManager` and a permissive hostname verifier when `insecure` is true | `insecure` | `e52.java:44-50` |
| Host header | Overridden | `host` | not traced |
| Name resolution | Custom DNS for the subscription host | `resolve-address`, `server-address-resolve-*` | `s60.java` |
| Path | Through the running tunnel instead of direct | `check-url-via-proxy` | `e52.a` → `xf2.o().e().a(…)` |

All of these are `TrustBoundary` keys except the timeout ([03](03-meta-protocol.md#risk-classes)). `fragment`, `host`, `insecure` and `resolve-address` are read through `SubscriptionItem.E()`, `H()`, `L()` and `T()`, which return nothing unless the subscription's status is `EXTRA` ([below](#alternative-fetch-targets)); for an ordinary subscription they are stored but inert.

## Device identifiers

By default Happ identifies the device to the provider with `X-HWID` (the Android `ANDROID_ID`) plus `X-Device-OS`, `X-Ver-OS` and `X-Device-model` (**VERIFIED**, on-device mock). The meta keys `subscription-send-hwid-enabled`, `subscription-always-hwid-enable` and `subscription-hwid-in-cookie-enable` control this, `hwidlink` binds a subscription to one device, and `providerid` / `installid` tie it to the vendor's licensing backend. All of these are described, with code references, in [08](08-device-binding.md).

The crate classifies all of these keys as `DeviceIdentity`. A third-party client should not send device identifiers by default. If a provider requires them, sending them should be an explicit per-subscription user choice. The live provider served the same content with and without (fake) identifiers and sent no device-limit headers (live probe).

## Response

- A non-2xx status is a failed update; status codes map through the enum `gy2` (400 … 504). A `500` left the stored servers in place without a message (on-device mock).
- `Content-Disposition` is ignored: neither `filename="…"` nor `filename*=UTF-8''…` set the title, which fell back to the URL host (**VERIFIED**, on-device mock; no handler exists in the decompiled code). Earlier drafts claimed otherwise.
- gzip content encoding is decoded by OkHttp before processing.
- Meta headers, `Encrypt-Tag` and the body are then processed as in [03](03-meta-protocol.md), [04](04-body-encryption.md) and [02](02-subscription-body.md).
- The import returns `ImportSubResult(networkResponse, isSubUpdateRequired, errorStatusCode)` (`domain/sub/ImportSubResult.java`); `isSubUpdateRequired` decides whether the server list is replaced or merged.

## Provider behaviour observed live

One live provider on 2026-10-12 (**VERIFIED**, live probe; details and fixtures in [02](02-subscription-body.md#live-provider-behaviour)):

- The body format follows the `User-Agent`: Clash YAML for Clash and mihomo, a sing-box configuration for sing-box and Hiddify, a whole-body Base64 link list for everything else.
- The `routing` header is sent only to `User-Agent`s starting with `Happ`.
- The link order, REALITY `sni` and `sid` change on every request, at a constant `content-length`.
- `?key=key01` and `?key=key02` changed nothing: no `Encrypt-Tag`, plaintext body.
- Fake `X-HWID` and device headers changed nothing; requests without them were served too.
- No body directives and no `Content-Disposition`; meta keys arrive as headers only. `profile-update-interval` is `1`.

## Alternative fetch targets

Three keys would make the client fetch from somewhere other than the URL the user added. All three are `TrustBoundary`. A third-party client should ask the user before applying them and should reject private, loopback and non-HTTPS targets (the crate provides `meta::validate_url_safety` for this check).

| Key | Effect in Happ for an `EXTRA` subscription | Code |
|---|---|---|
| `new-url` | Replaces the stored subscription URL permanently and clears the stored encrypted-URL flags | `qy4.a()` |
| `new-domain` | Replaces the host (authority) of the stored URL, or `metaParams.host` when set; path and query are kept | `ky4.a()` |
| `fallback-url` | Fetched when the primary fetch fails, with the message "Primary update failed. Using fallback URL" (`dialog_subscription_update_msg_fallback`) | `SubscriptionItem.D()`, `uj7`, `e52` |

For an ordinary subscription Happ 4.7.1 applies none of them (**VERIFIED**, on-device mock): with `fallback-url` stored, a primary fetch returning `500` or hanging produced no request to the fallback; `new-url` and `new-domain` left the URL unchanged over two refreshes each. `SubscriptionItem.D()` returns nothing, and `qy4` / `ky4` return early, unless the subscription's status is `EXTRA` (`SubscriptionItem.c()` / `b0()`); Happ's import log prints "Should handle extra params: false". The status is set by the provider extra-check path (`SubscriptionItem.u0`, from `eq0` / `xp0`; [08](08-device-binding.md#remote-checks-typecheck)). What triggers `EXTRA`, and the exact behaviour once it is set, is **UNKNOWN**; the table above is **INFERRED** for that case.

Besides the provider's `fallback-url`, Happ has its own domain fallback list (`jg7.java:23`), fetched from `https://cdn.jsdelivr.net/gh/Happ-proxy/app_domain@main/list.json` or the same file on `raw.githubusercontent.com`. At the time of the research it held 13 domains: `hpdata.link`, `happhost.com.`, `happroxy.ru`, `rdata.click`, `subdata.link`, `appsub.link`, `hpdata.click`, `sub-page-terckpfo2q-ww.a.run.app`, `sub.maxg.ch`, `sub.happhost.com`, `1vpn.world`, `hpkey.com`, `happvpn.com`. On the device the list is stored in the `SETTING` store as `pref_blacklist` (on-device mock). It belongs to the vendor's own infrastructure and a third-party client should not use it.

## Applying servers

Share links carry no stable server identity. Happ gives every imported server a random internal `GuId` (`hq4.e`), not a hash of the link, so a refresh produces new IDs. The selected server survives through the `SELECTED_SERVER` and `REMOVED_SERVER` stores, which match the previous selection by connection parameters after a re-import (`hq4.java:112-135`). `SubscriptionSettingsState(rejectDuplicates=…)` drops duplicate servers within one subscription (`hn7.java`). A client that wants the same behaviour should match the previously selected server by its connection parameters, not by position, ID or full URI: providers randomise the order and per-request parameters such as the REALITY `sni` and `sid` ([above](#provider-behaviour-observed-live)).

When `hide-settings` is true, or the URL was encrypted, Happ hides server details from the user and shows the subscription as a single entry (`gs.java:146`).

## Persistence

Happ keeps all of its state in MMKV under `files/mmkv/`; `databases/` is empty (**VERIFIED**, on-device mock):

| Store | Contents |
|---|---|
| `MAIN` | `HAPP_CONFIGS` (JSON array of `GuId`s), `SELECTED_SERVER`, `REMOVED_SERVER` |
| `SERVER_CONFIG` | One `ServerConfig` JSON per `GuId`; a `CUSTOM` server keeps its configuration in `fullConfig` |
| `SUB` | One `SubscriptionItem` JSON per `subId`; the merged metadata is serialised as `headerMetaParams` |
| `SUB_PROPERTIES` | Per subscription, `{"autoUpdate":{"isEnabled","isBlocked","updateInterval"}}` |
| `SUB_ROUTING_ENABLED` | Per subscription, the routing switch as an 8-byte little-endian `0` or `1` |
| `SETTING` | App settings, including `routing_profile_list`, `pref_blacklist` (the vendor domain list) and `WorkDomainsInStorage` (38 public DNS resolver addresses) |
| `SERVER_RAW`, `SERVER_AFF` | Empty in the test |

The stores use MMKV's encrypted mode with a per-install key that is itself encrypted under an AndroidKeyStore key; how the stores were decrypted is in [10](10-verification.md#method-happ-on-a-device-against-a-mock-server).

`SubscriptionItem` has 28 fields, recovered from its Kotlin `@Metadata` (**VERIFIED** against `dto/SubscriptionItem.java` and the stored JSON):

```kotlin
data class SubscriptionItem(
    val url: String,
    val originUrl: String,
    val hwidLink: HWID?,
    val encryptedUrl: Boolean,
    val encryptedUrlMode: EncryptedUrlMode?,
    val enabled: Boolean,
    val _hideSettings: Boolean,
    val encrypted: Boolean,
    val addedTime: Long,
    val lastUpdated: Long,
    val autoUpdate: Boolean,
    val isExpand: Boolean,
    val installId: InstallId?,
    val `import`: Boolean,
    val importTryAdd: Boolean,
    val extraCheckTimestampMs: Long,
    val extraCheckFailureTimestampMs: Long,
    val status: SubscriptionItem.Status,      // BASIC | EXTRA
    val typeCheck: TypeCheck,                 // FILE | DNSTT | REST
    val metaParams: MetaParams?,
    val remarks: String,
    val manualEnterTitle: String?,
    val manualSendHwidInCookie: Boolean,
    val providerId: ProviderId?,
    val hashedDomain: HashedDomain?,
    val firstRun: Boolean,
    val lastCheckUpdate: Long,
    val resetHandled: Boolean,
)
```

`remarks` holds the title (`profile-title`, truncated to 25 characters, or the URL host). `hashedDomain` is the SHA-256 of the URL authority as written, `host:port` when the URL has a port ([08](08-device-binding.md#provider-and-install-ids)).

A third-party client needs a subset of this per subscription: the current URL (after migrations), the URL originally added, whether the body was encrypted, whether the URL was given in encrypted form, the merged meta map ([03](03-meta-protocol.md#precedence-and-refresh-merge)), the time of the last successful update, and any user-set title.

## Scheduling

Background updates run in the WorkManager `CoroutineWorker` `SubscriptionUpdater$UpdateTask`, scheduled by `eo7`:

- `profile-update-interval` is in **hours**, 1 to 730. Happ schedules one `OneTimeWorkRequest` per subscription, named by the `subId`, with `initial_delay` and `interval_duration` both set to the interval in hours (`eo7.java:110`; **VERIFIED**, on-device mock, read from WorkManager's `workdb`). Without the key no job is scheduled.
- A provider interval locks the user's interval field (`SUB_PROPERTIES.autoUpdate.isBlocked: true`). When a refresh drops the key from the metadata ([03](03-meta-protocol.md#precedence-and-refresh-merge)), `isBlocked` is removed but the saved interval and the scheduled job stay (on-device mock).
- Deleting a subscription usually cancels its job; one job stayed enqueued after its subscription was deleted (on-device mock).
- When the task runs, a subscription is due if `workRunCount × 1 h + lastCheckUpdate ≥ now`, so the effective interval grows over consecutive runs that change nothing, and a real update resets it (**INFERRED**).
- With `subscription-auto-update-open-enable`, subscriptions whose interval has elapsed are refreshed when the app opens.
- `ExpireReminderTask` is a periodic 24-hour job (`expire_reminder`) created on first launch (on-device mock). With `notification-subs-expire`, it notifies the user 3 days before the `expire` time from `subscription-userinfo` (`EXPIRE_REMINDER_TIME = 259200000` ms, `dto/SubscriptionItem.java:36`).
- Updates show a foreground notification on channel `subscription_update_channel` with a Close action; `SubscriptionUpdaterReceiver` cancels the work on `CANCEL_NOTIFICATION`.

## Update errors

| Condition | Happ message | Resource |
|---|---|---|
| TLS certificate rejected | "Certificate verification failed" | `certificate` |
| Connection failed | "Connection error" | `connection_error` |
| Timeout | "Connection timed out" | `time_out` |
| Fallback URL used | "Primary update failed. Using fallback URL" | `dialog_subscription_update_msg_fallback` |
| Provider or device restriction (for example `hwidlink` mismatch) | "Access to subscription is restricted" | `restricted_access` |
| Device limit reached | "Multi-device access limit exceeded" | `restricted_access_mf` |
| Subscription URL malformed | "Subscription link is not correct" | `last_updated_link_not_correct` |
| Any other failure | "Update failed" | `last_updated_fail` |

The messages are **VERIFIED** against the 4.7.1 English string resources. Body parsing errors are listed in [02](02-subscription-body.md#rejections); a failed body decryption is reported as a success ([04](04-body-encryption.md#when-a-body-is-decrypted)).

## Confidence and open questions

Request headers, the default `User-Agent`, the cookie jar, the timeout and retry, the inert alternative fetch targets, `Content-Disposition`, persistence and the job scheduling are **VERIFIED** on Happ 4.7.1 against a mock server; provider format switching is **VERIFIED** on one live provider. The due-time formula, the `EXTRA` behaviour and the error mapping are **INFERRED** from the code; the meta keys involved are **DOCUMENTED**.

Open questions:

- What sets a subscription's status to `EXTRA`, and how `fallback-url`, `new-url`, `new-domain`, `host`, `insecure`, `resolve-address` and `fragment` behave then, is **UNKNOWN**.
- How the schedule behaves after repeated failed updates is **UNKNOWN**; the due-time formula is read from `UpdateTask`.
