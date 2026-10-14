# Verification ledger

How each load-bearing claim in these documents was established, which earlier claims were overturned, and what is still open. Tags are defined in [01](01-overview.md#how-the-facts-were-established). Code references are to the decompiled Happ 4.7.1 APK.

## Claims and evidence

| Claim | Primary evidence | Corroboration | Status |
|---|---|---|---|
| Body cipher is AES-128-GCM | `kz1.java:176` | [Encrypting subscription content](https://www.happ.su/main/dev-docs/encrypting-subscription-content); Happ decrypts a `key02` body on device | **VERIFIED** |
| Fixed IV `kkkkkkkkkkkk` | `kz1.java:171` | Vendor test vector; on device | **VERIFIED** |
| The whole `keyNN:…` string is the AES key | `kz1.java:170` | Vendor `key02` value is 16 bytes including the prefix | **VERIFIED** |
| The 90 body keys | Native table dump + seed decryption + PNG decoding ([04](04-body-encryption.md#how-the-keys-were-extracted)) | Five independent checks, below | **VERIFIED** |
| Body keys unchanged in 4.3.0 to 4.7.1 | Extractor run on 4.3.0, 4.5.0, 4.7.1 | Steganographic PNGs byte-identical from 4.3.0 on | **VERIFIED** |
| Decrypt trigger: tag plus `?key=` or stored flag | `e53.java:44`, `:85` | On device ([below](#live-probes-2026-10-12)) | **VERIFIED** |
| A failed decryption yields an empty body | `kz1.b()` returns `""` on any exception | On device: servers wiped, success shown | **VERIFIED** |
| Whole-body Base64, one level | `j43.smali` | Live provider body; on device (standard, unpadded, wrapped) | **VERIFIED** |
| JSON array and single JSON import as `CUSTOM` | `b71.java`, `ut2.java` | On device; [Routing](https://www.happ.su/main/dev-docs/routing) | **VERIFIED** |
| A JSON object or array element without `outbounds` is accepted | On device | none | **VERIFIED** |
| 91 meta keys plus the `base64:` prefix and four `subscription-userinfo` field names | 96 string constants in `MetaParams` | Vendor key list (90 keys; `reset` is undocumented) | **VERIFIED** |
| Every key except `hwidlink` and `reset` is header-deliverable | `lw2.java:13` reads 89 keys | 7 keys seen as headers on a live provider; on device | **VERIFIED** |
| Body directive overrides header | `pc6.a(headerMeta, bodyMeta)` | On device | **VERIFIED** |
| Refresh drops absent keys except a sticky set (`isFull`) | `MetaParams.Companion.c` / `d` | On device | **VERIFIED** |
| The fetch after an import keeps absent keys (`isFull = false`) | `MainActivity.T` → `P(…, false, …)` | On device ([below](#url-fragment-and-merge-modes-2026-10-12)) | **VERIFIED** |
| Background updates keep absent keys | `SubscriptionUpdater$UpdateTask`, `g92.n` / `g92.o` pass `isFull = false` to `vk7.b` | none | **INFERRED** |
| A response without meta leaves stored meta untouched | `e53.b`: merge skipped when the parsed `MetaParams` is empty | On device | **VERIFIED** |
| A body `0` clears one of seven sticky keys; a header `0` does not | `MetaParams.Companion.a`, `e`; `pc6.a` takes `ResetInfo` from the body | On device | **VERIFIED** |
| `sub-info-text` / `sub-info-button-text` equal to `0` are cleared | `MetaParams.Companion.c` | On device (`sub-info-text`, header and body) | **VERIFIED** |
| URL fragment directives: grammar, import-only, fragment not sent | `hq4.p`, `if7.b`, `if7.c`, `MetaParams.Companion.a(List, true)` | On device | **VERIFIED** |
| `profile-update-interval` in hours, 1 to 730 | `vl7.java:11` (`new pb3(1, 730, 1)`) | [App management](https://www.happ.su/main/dev-docs/app-management); on device | **VERIFIED** |
| `routing` header carries a routing deeplink | Live provider (Happ User-Agents only) | `lw2`, `ng6`; on device | **VERIFIED** |
| Default User-Agent and request headers | `wb8.S`, `e52.java:208` | Captured on device | **VERIFIED** |
| The "send HWID" switch gates all four device headers; `subscription-always-hwid-enable` forces it on and locks it | `uj7.java:57`, `rl7`, `mr` case 8, `cd.java:200` | Default (on) captured on device | **INFERRED** |
| `subscription-hwid-in-cookie-enable` replaces `X-HWID` with `Cookie: <hwid>` | `so1`, `SubscriptionItem.U()` | none | **INFERRED** |
| One retry after a thrown call: without `Connection: close` after a reset, IPv4-only resolution after a timeout or other I/O error | `b52.q`, `s60.lookup` | Two requests 7 s apart against a hanging server, on device | **INFERRED** (retry count **VERIFIED**) |
| A `subscription-request-timeout` outside 5..15 is ignored, not clamped | `MetaParams.java:644`, `pq.b` | none | **INFERRED** |
| `crypt5` block half-swap and marker position | Third-party decoder, `liberror-code.so:0x183024` | 5 of 5 generator links decrypt | **VERIFIED** |
| `crypt5` field sizes | Measured on the 5 links | `0x20`/`0x8`/`0x10` steps in the native ChaCha path | **VERIFIED** |
| `crypt5` step 5 is `base64_decode(swap_adjacent(inner))` | 5 of 5 links decrypt only in this order | Length arithmetic of `seg_len` | **VERIFIED** |
| URL RSA key set is genuine | 5 of 5 links decrypt | Vendor [Crypto link](https://www.happ.su/main/dev-docs/crypto-link) public key equals `pkcs1_2` over the full modulus | **VERIFIED** |
| `incy://crypt1/` is AES-256-GCM over `base64url(iv[12] ‖ ct ‖ tag[16])` with a sorted-JSON `{n,url,v}` plaintext | INCY 3.7.0 decoder and encoder (`wf/f.java`, `ig/d2.o`, decompiled with jadx 1.5.6) | Vendor [Deep links](https://docs.incy.cc/deep-links/) page; the vendor's pinned cross-platform vector | **VERIFIED** |
| `incy://crypt1/` key `K1 = SHA-256("incy"‖"deep"‖"crypt1"‖"v2026.06"‖A[1024:1056]‖B[2048:2080])` | Key windows and salt assembly in the client's `wf/f.b`; obfuscated salt part decodes to `crypt1`, second offset is `Barcode.FORMAT_PDF417` = 2048 | Assets byte-identical to `INCY-DEV/incy-link-encoder` (MIT); fingerprint `b6bf7084…` pinned in its JS, Python, PHP and Go ports | **VERIFIED** |
| HWID is `ANDROID_ID`, sent by default | `uk8.java:529`, `uj7.java:57` | [HWID links](https://www.happ.su/main/dev-docs/hwid-links); captured on device | **VERIFIED** |
| HWID is Happ's SSAID: HMAC-SHA256 under the per-user key over `len_be32(cert) ‖ cert` of the highest scheme's certificates, first 16 hex characters | AOSP `SettingsProvider.generateSsaidLocked`, `generateUserKeyLocked`, `getLengthPrefix` | Computed from the device's per-user key and Happ's v2 certificate; equal to the `X-HWID` Happ sent in all 81 requests of two on-device probe sessions | **VERIFIED** |
| `hwidlink` is checked locally | `hq4.java:447` | Vendor HWID docs | **VERIFIED** |
| Sentry SDK bundled with auto-init off | `e96.java:154`, manifest | Sentry session cache on device | **VERIFIED** |
| Domain hash registry | `assets/data.result` decrypts and parses | `j52.java`, `kz1.c` | **VERIFIED** |
| `SubscriptionItem` has 28 fields | Kotlin `@Metadata` | `dto/SubscriptionItem.java`; stored JSON on device | **VERIFIED** |

## Five confirmations of the body keys

1. **Vendor test key.** The vendor documentation publishes `key02:+]%4ij#P"/`; the extracted `key02` matches byte for byte.
2. **Shape.** 90 entries, each 16 bytes, named `key01` … `key90`, distinct, each prefixed by its own ID. The `kz1.c` key and IV are 16 and 12 bytes, as predicted from the code before extraction.
3. **Anti-tamper blob.** Decrypting it with the replicated primitive yields `g+Uz1USttQp3T0c146yMV1OLJDI=`, which is `83e533d544adb50a774f4735e3ac8c57538b2432`, the SHA-1 that `apksigner verify --print-certs` reports for the release signing certificate.
4. **Round trip.** Encrypting with extracted keys and decrypting through the replicated `kz1.b` returns the input (7 of 7 sampled keys by hand; all 90 in the crate's tests).
5. **Shipped asset.** `assets/data.result` decrypts with the native `kz1.c` key and IV, the GCM tag authenticates, and the plaintext decompresses with zstd to 94,784 bytes of JSON.

The Unicorn-based re-extractor runs the same five checks as gates; the fifth check of that tool compares `key02` with the vendor documentation and reports a mismatch as a warning, since it would mean a legitimate rotation.

## `crypt5` round trips

Five links were generated on 2026-10-12 from `https://crypto.happ.su/api-v2.php` with neutral `https://example.com/…` targets. All five decrypt to the expected URL, with no error, using the crate's implementation and the embedded key set; the crate's integration test `crypt5_vendor_samples::vendor_generated_links_decrypt` repeats this on every run with `builtin-url-keys`. The links confirm the 4-byte half-swap, the 8-character marker, the 12-byte nonce, the 8-byte salt, the two random filler fields and a single 512-byte RSA block. All five use marker `vdfzfoff`.

## `incy://crypt1/` derivation

The INCY key material is the easiest thing in either client to check, because three independent copies of it exist: the APK's `res/raw/incy_assets_{a,b}.bin`, the vendor's MIT reference package, and a third-party decryptor. All three agree byte for byte, and the derived key's fingerprint is the one the vendor asserts in all four of its reference ports. `tests/incy_crypt.rs` pins both asset digests, the key and the fingerprint, and decrypts the vendor's pinned vector plus four generated payloads; `happ-key-extractor` decrypts the same fixture file, so the two implementations cannot drift apart unnoticed ([11](11-incy-url-obfuscation.md)).

## Live probes 2026-10-12

Two probes on 2026-10-12 tested the static findings against real behaviour. Claims they settled are tagged **VERIFIED** in the other documents with the method named (live probe or on-device mock).

### Method: live provider probe

One live Happ-compatible subscription was fetched 15 times within eight minutes, at least 3 seconds apart, over a direct connection, each time with a different `User-Agent` (Happ full and short forms, v2rayNG, v2rayN, Clash Verge, mihomo, sing-box, Hiddify, Streisand, curl, a desktop browser, none) or URL variant (`?key=key01`, `?key=key02`, fake device-identifier headers). The full responses were saved, then redacted for publication: credentials, keys, short IDs and passwords replaced by random values of the same shape, hosts by `node-NN.example.org`, `*.sni.example.com`, `*.example.net`, `192.0.2.18` and `2001:db8::4`, and the provider's brand by `Example VPN` / `EXAMPLE-ROUTING`, with bodies re-encoded in their original form and `content-length` recomputed. A scan against every original secret found no leftovers. Four redacted responses are in [`tests/fixtures/live-2026-10-12/`](../tests/fixtures/live-2026-10-12/) ([09](09-implementation-guide.md#fixtures)).

### Method: Happ on a device against a mock server

Happ 4.7.1 (versionCode 1703) ran on a rooted Android 16 phone; its VPN was never started. A small HTTP server on the workstation served one scenario per path (`/s/<scenario>`), switched between response variants through a control endpoint, and logged every request with its headers in wire order. `adb reverse` exposed it on the phone's loopback, which Happ accepted over plain HTTP. Subscriptions were added with `am start -a android.intent.action.VIEW -d 'happ://add/http://127.0.0.1:<port>/s/<scenario>'` and refreshed or deleted through the UI.

The outcome of each step was read from Happ's own state rather than from the screen alone. Happ keeps all state in MMKV under `files/mmkv/` ([07](07-fetch-and-update.md#persistence)) in MMKV's encrypted mode: AES-128-CFB128 with the first 16 bytes of a per-install key string as the key and bytes 12 to 28 of `<store>.crc` as the IV; the file holds a `u32` length and the ciphertext, and the plaintext is a varint size header followed by repeated `varint keyLen, key, varint valLen, value` records, the last record for a key winning. The key string is 12 random bytes from `o41.H()` in Base64 (16 characters), stored encrypted under an AndroidKeyStore key in shared preferences under misleading names, so it cannot be read from disk. It was recovered from the running process instead: dump the readable heap regions through `/proc/<pid>/mem` as root, collect every 16-character Base64 token, and trial-decrypt the first 64 bytes of the `SETTING` store with each; exactly one token produced a valid record layout. State was snapshotted (`/data/data/su.happ.proxyutility`) and decoded after every step, together with Happ's own subscription import log, WorkManager's `no_backup/androidx.work.workdb`, logcat and `/proc/net` socket tables.

### Claims against observation

| Doc | Claim before the probes | Observation | Verdict |
|---|---|---|---|
| 07 | Build component of the default `User-Agent` unknown | `Happ/4.7.1/Android/1791210317680` + `1703` + `6` (even UTC day) or `5` (odd) + `50`, header spelled `User-agent` | Resolved |
| 07 | Default request headers | Confirmed, plus `Accept-Encoding: gzip`; exact order recorded | Confirmed |
| 07 | Cookie jar | Confirmed; persistent, keyed by host, shared across subscriptions | Confirmed |
| 07, 08 | `X-HWID` is `ANDROID_ID`, sent by default | 16 lowercase hex characters, equal to the HWID Happ displays; sent by default | Confirmed |
| 03 | `base64:` values decoded | Decoded and stored | Confirmed |
| 03 | `profile-title` capped at 25 characters | Truncated to 25 when stored | Confirmed |
| 03 | Body directive overrides header | Body won for every conflicting key; header-only and body-only keys kept | Confirmed |
| 03 | Refresh keeps keys absent from the new response | Most keys dropped; a sticky set kept | Contradicted |
| 03 | `ResetInfo` wire format | Body `0` clears; header `0` ignored; `sub-info-text` `0` clears from any transport (second session) | Resolved |
| 03 | Which update paths keep absent keys | Import fetch keeps them; refresh button drops them (second session) | Resolved |
| 03 | URL fragment merged over stored meta on import | Fragment becomes the initial meta; the first response is merged over it without dropping (second session) | Confirmed |
| 02 | `#key: value`, space optional | `#key:value` accepted | Confirmed |
| 02 | Handling of other `#` lines unknown | `# comment` and `#Not-A-Key value` dropped silently | Resolved |
| 02 | Whole-body Base64 accepts the URL-safe alphabet | Happ mis-decodes it: one broken server, the rest lost; standard, unpadded and 76-column wrapped bodies import | Contradicted |
| 02 | JSON array and object import as `CUSTOM` | Confirmed; names from `remarks` | Confirmed |
| 02 | JSON without `outbounds` rejected | Object accepted as `CUSTOM`; array with one bad element imports both | Contradicted |
| 02 | Invalid link line fails the import | Non-link line skipped silently; malformed `vless://` imported as a broken server (`port: -1`) | Contradicted |
| 02 | Empty body rejected | Success, zero servers, `lastUpdated: -1` | Contradicted |
| 02 | No link at all is "Unknown content type" | Confirmed; servers removed, subscription kept | Confirmed |
| 04 | AES-128-GCM, `key02`, fixed IV, `Encrypt-Tag` | Decrypted end to end, body directives applied, stored flag set | Confirmed |
| 04 | Decrypt trigger | Tag without `?key=` on a fresh subscription is ignored; stored flag plus `?key=` triggers | Confirmed |
| 04 | Failed decryption falls back to the plaintext body | Empty body instead: servers wiped, success shown | Contradicted |
| 04 | Stored as encrypted without `?key=`: key unknown | Code: key ID `""`, decryption throws, empty body (not reproducible on device) | Resolved by code |
| 06 | `onadd` activates, `add` stays inactive | Both selected and enabled on a subscription without a previous profile | Contradicted |
| 06 | Routing via header and body | Both work; header value kept in meta, body lines not | Confirmed |
| 06 | `happ://routing/off` in a body | Line removed, no profile, that subscription's routing switched off | Resolved |
| 02 | `serverDescription` fragment | Stored in `ServerConfig.meta.serverDescription`, not displayed | Confirmed |
| 02 | `pcs`, `pcn`/`vcn` | `pinnedPeerCertSha256` and `verifyPeerCertByName`, with `security=tls` only | Confirmed |
| 02 | `fm` grammar | Recognised as `finalmask`; a `{"fragment":…}` payload became `{}` | Open |
| 07 | `fallback-url` used when the primary fetch fails | Ignored for an ordinary subscription | Contradicted |
| 07 | `new-url` and `new-domain` applied silently | Ignored for an ordinary subscription | Contradicted |
| 07 | `Content-Disposition` supplies the title | Ignored | Contradicted |
| 07 | Timeout 7 s | 7 s, then one retry | Confirmed |
| 07 | One-time WorkManager job per subscription, in hours | Confirmed; no job without the key | Confirmed |
| 07 | `SubscriptionItem` persisted in MMKV | Confirmed; merged meta stored as `headerMetaParams` | Confirmed |
| 08 | `HashedDomain = sha256(domain)` | `sha256("<host>:<port>")` for a URL with a port | Corrected |
| 07 | Vendor domain fallback list | Stored in `SETTING.pref_blacklist` | Confirmed |

The live provider probe added: format switching by `User-Agent`, the `routing` header only for `User-Agent`s starting with `Happ`, per-request randomisation of the link list, a bare IPv6 VLESS host, Hysteria2 `xray-extra-params`, no device-identifier enforcement, no body encryption with `?key=` and no body directives ([02](02-subscription-body.md#live-provider-behaviour), [07](07-fetch-and-update.md#provider-behaviour-observed-live)).

### URL fragment and merge modes (2026-10-12)

Method: on-device mock 2026-10-12, a second session with the same phone and Happ 4.7.1 build, reinstalled for the run and uninstalled afterwards. The method is the one [above](#method-happ-on-a-device-against-a-mock-server), with three changes. The MMKV key of the new install was found by dumping the Java heap within a second of a cold start, before the decrypted key string was collected, and trying every 16-character window. Each import used its own path, with the directives in the `happ://add/` link's fragment. Refreshes were the subscription's refresh button, tapped only while Happ was the resumed activity. The decompiled code was read from the same APK with jadx (`if7.b`, `if7.c`, `hq4.p`, `qk7.e`, `e53.b`, `pc6.a`, `MetaParams.Companion.a` / `c` / `d` / `e`, `MetaParams.j1`, `MainActivity.T` / `l0`, `vk7.b` and its callers).

| Step | Observation |
|---|---|
| Import with `#Name?profile-title=…&support-url=…&announce=…&sub-info-text=…&fallback-url=…`, response without meta | Request line `GET /f/fa1`, no fragment; stored `url` without the fragment, `originUrl` with it; all five keys stored |
| Same, response with only an `announce` header | Fragment keys kept next to the header's (`isFull = false`); `subscription-userinfo=base64:…` decoded |
| Fragment, header and body all set `profile-title`; header and fragment set `support-url` | Body title, header `support-url`, fragment-only `announce` kept |
| `%20`, `%3A%2F%2F`, `+`, `base64:…==`, `p?a=b&c=d` in values | Not percent-decoded; `support-url` with `%3A` rejected; `+` kept; padded Base64 decoded; value cut at the second `=`, `c=d` ignored |
| `…&bogus` | Import failed, "Unknown content type", no request, no subscription |
| Repeated and mixed-case keys, padded with spaces, unknown key | Last value wins, keys case-insensitive, keys and values trimmed, unknown key ignored |
| `#name#?profile-title=…` | Stored URL kept `#name`, no directives applied |
| `reset=1` | Stored `reset: true`, `resetHandled: false`; nothing else for an ordinary subscription |
| `happ://add/` of an existing URL again | Same subscription ID; metadata replaced by the new fragment's (none) and the response stored as on import, not merged |
| Refresh button, body `#fallback-url: 0` and `#sub-info-text: 0`, no other keys | `fallback-url` and `sub-info-text` removed; non-sticky `announce`, `support-url` dropped |
| Refresh button, headers `fallback-url: 0` and `sub-info-text: 0` | `fallback-url` kept, `sub-info-text` removed; `support-url`, `subscription-userinfo` dropped |
| Refresh button, response without any meta | Stored metadata unchanged, `lastUpdated` advanced |
| App restart with `subscription-auto-update-open-enable: true` | No request: the on-open update only refreshes subscriptions whose interval has elapsed ([07](07-fetch-and-update.md#scheduling)) |

## Corrections

Earlier drafts of this research made the claims below; each was checked and corrected.

| Earlier claim | Correction | How it was checked |
|---|---|---|
| `crypt5` step 5 is `swap_adjacent(base64_decode(inner))` | It is `base64_decode(swap_adjacent(inner))`; the encoder computes `swap_adjacent(base64(url))` | The swap-then-decode order is the only one that decrypts the 5 generator links |
| `body[12:14]` of a `crypt5` body is a mode tag, and the byte after `seg_len` is a fixed separator | Both are random filler and are never read | They differ between the 5 links; decoding ignores them |
| The salted `crypt5` layout is a rare variant | It is the current format | 5 of 5 links are salted |
| 91 meta parameters | 91 keys including the undocumented `reset`; `base64:` is a value prefix | `MetaParams` has 96 string constants: 91 keys, `base64:` and the four `subscription-userinfo` field names |
| `fallback-url` is safe to apply automatically | It is `TrustBoundary`, like `new-url` and `new-domain` | It points the client at a provider-chosen fetch target |
| `bs0` and `ea4` are share-link parsers | They are ISO 639 / ISO 15924 language tables | `ea4.java:1025` maps `"ssh"` to `"Arab"` |
| The URL RSA private keys are in no public material | A third-party repository publishes them | Vendor public key matches `pkcs1_2`; 5 links decrypt |
| Fixtures under `docs/fixtures/` | They live in [`tests/fixtures/`](../tests/fixtures/) | Repository layout |
| Refresh merge: a key absent from the new response keeps its stored value | Absent keys are dropped except `installid`, `sub-info-*`, `sub-expire`, `sub-expire-button-link` and seven keys a provider can clear with `0` | On-device refresh with keys omitted; `MetaParams.Companion.d` |
| A failed body decryption falls back to the plaintext body | Happ uses an empty body and wipes the servers; the crate returns `Error::Decrypt` | On device, five failure cases; `kz1.b()` returns `""` |
| `routing/add` stores the profile inactive, `onadd` activates it | Both selected and enabled the profile on device | On device, header and body, both actions |
| `fallback-url` is fetched when the primary fetch fails; `new-url` / `new-domain` migrate the URL | All three are inert unless the subscription status is `EXTRA` | On device: primary returning 500 and hanging, two refreshes with each key; `SubscriptionItem.D()`, `qy4`, `ky4` |
| `Content-Disposition` supplies the title | Ignored; the title falls back to the URL host | On device, `filename` and `filename*` forms |
| An empty body is rejected with "The clipboard is empty" | Imported as success with zero servers; the message belongs to the clipboard path | On device, `200` with 0 bytes |
| Whole-body Base64 accepts the URL-safe alphabet like Android's decoder | Happ mis-decodes it; the crate's acceptance is a deliberate superset | On device |
| A JSON object or array element without `outbounds` is rejected | Happ accepts it as `CUSTOM`; the crate's rejection is a deliberate restriction | On device |
| An invalid link line yields `parsing_error_invalid_server` | Non-link lines are skipped silently; malformed links import as broken servers | On device |
| `HashedDomain = hex(SHA-256(domain))` | SHA-256 of the URL authority as written (`host:port` when the URL has a port), or of the `host` meta value when set | `hashedDomain` of a stored subscription on device; `uk8.q` |
| Sending `0` for one of seven sticky keys clears it; other sticky keys cannot be cleared | Only a body directive clears them: a header `0` is ignored because `pc6.a` takes `ResetInfo` from the body. `sub-info-text` and `sub-info-button-text` are also cleared by `0` or an empty value, from any transport | On-device refreshes with header and body `0`; `MetaParams.j1`, `MetaParams.Companion.c` |
| Every refresh drops keys the response omits | Only refreshes with `isFull` (refresh button, "update all"); the fetch after an import keeps them, and a response with no meta changes nothing | On device; `MainActivity.T`, `e53.b` |
| The crate does not parse the URL fragment | `meta::parse_fragment`; `parse` merges the response over the fragment on import | `hq4.p`, `if7.b`; on device |
| `subscription-hwid-in-cookie-enable` also puts the HWID in a cookie | It replaces the `X-HWID` header with `Cookie: <hwid>`, a bare value with no cookie name | `so1`, which `uj7.d` passes to the fetcher |
| `subscription-always-hwid-enable` sends the identifiers on every request | It turns the "send HWID" switch on and disables it in the UI; the switch gates all four device headers on every fetch anyway | `mr` case 8, `cd.java:200`, `uj7.java:57` |
| `manual-block-user-agent` blocks the fetch if a custom User-Agent is rejected | It clears the user's custom User-Agent and locks the field | `mr` case 9, `ul7` |

## Open items

| Item | Status |
|---|---|
| What sets a subscription's status to `EXTRA` (`SubscriptionItem.u0`, from `eq0` / `xp0`), and how `fallback-url`, `new-url`, `new-domain`, `host`, `insecure`, `resolve-address` and `fragment` behave once it is set | **UNKNOWN** |
| `reset`: code broadcasts a re-import from `originUrl` without `reset=1`; only on the extra-check path | **INFERRED**; stored but inert for an ordinary subscription |
| Partial merge of the WorkManager job, `g92` batch update and `p71` update | **INFERRED** from `vk7.b` callers; only the import fetch was observed |
| Edit-URL path (`qk7.e`) merging a fragment with `isFull = true` | **INFERRED**; not exercised |
| `fm` (`FinalMaskBean`) grammar | **UNKNOWN**; the key is recognised as `finalmask` |
| Behaviour of the update schedule after failed updates | **UNKNOWN**; the due-time formula is **INFERRED** |
| `crypt` … `crypt4` links from the vendor | **UNKNOWN**; the generator emits only `crypt5` |
| `crypt5` markers other than `vdfzfoff` in live links | **UNKNOWN**; all 36 keys are embedded |
| An encrypted body served by a real provider | **UNKNOWN**; the live provider ignored `?key=`; encryption is verified on device against a mock server |
| Byte-exact export→import round trip per scheme | **UNKNOWN**; irrelevant for an importer |
| URL private keys extracted by this research's own pipeline | Not done; the third-party set is pinned by commit and SHA-256 |
| Body key rotation after 4.7.1 | **UNKNOWN**; re-run the extractor on new releases |
| `X-Device-OS` and User-Agent of Happ for Windows, Linux, macOS and iOS | **UNKNOWN**; `request::ClientOs` uses inferred strings for them |
| Effect of the HWID switches and the retry shapes on a device | **INFERRED** from the code; only the defaults and the retry count were observed |
