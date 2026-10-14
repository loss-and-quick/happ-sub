# The Incy client

INCY (`llc.itdev.incy`, Android 3.7.0 / versionCode 370) is a separate client, not a Happ fork.
Its subscription body is a subset of Happ's, its URL obfuscation is its own
([11](11-incy-url-obfuscation.md)), and its request profile differs enough to deserve its own
module: `incy_crypt` for the deeplink, `incy_request` for the fetch.

Everything below is **VERIFIED** against the decompiled 3.7.0 APK unless marked otherwise. Class
names are R8 output and are cited by shape.

## Request headers

`incy_request::build_request` returns the header list in the order the client adds them
(`ag/z.java:67-85`):

| Header | Value | When |
|---|---|---|
| `User-Agent` | `INCY/<versionName>/android Dalvik/<java.vm.version>` | always |
| `Accept` | `*/*` | always |
| `Accept-Language` | `Locale.getDefault().toLanguageTag()` | always |
| `x-hwid` | the device id, see below | only when an id exists |
| `x-device-os` | `Android` | only when an id exists |
| `x-ver-os` | `Build.VERSION.RELEASE` | only when an id exists |
| `x-device-model` | `Build.MANUFACTURER + " " + Build.MODEL` | only when an id exists |
| `x-app-version` | `versionName` | always |
| `x-device-locale` | `Locale.getDefault().toString()` | always |
| `x-client` | `INCY` | always |

Two differences from Happ that matter to a server:

- **No provider-controlled User-Agent.** Happ has `change-user-agent` and
  `manual-block-user-agent`; Incy has neither. The override is a local per-subscription setting,
  and an empty override falls back to the default (`ag/z.java:145-155`).
- **A different device identity.** Happ sends an SSAID derived from its signing certificate;
  Incy sends a value hashed from `android_id` and the build fingerprints.

Other User-Agents in the same APK, none of them subscription fetches: `InCy/1.0` for the
auto-routing profile, `datatransport/3.3.0 android/` for the geo-asset downloader, and
`incy-android` for a secondary download path.

## Device id (`x-hwid`)

`incy_request::derive_hwid` reproduces the client's algorithm (`sg/e.java:78-140`):

1. a stored value of 36 characters containing `-` is returned unchanged — this is the fast path
   that keeps the id stable across runs;
2. otherwise a seed is taken from storage, or derived once:
   - `android_id` missing, empty, or equal to the emulator sentinel `9774d56d682e549c` → a random
     UUID without dashes;
   - `android_id` with fewer than four non-`0` characters → a random UUID without dashes;
   - otherwise `SHA-256(android_id | MANUFACTURER | MODEL | BRAND | DEVICE | PRODUCT | BOARD | HARDWARE)`,
     lower-case hex;
3. the id is the first 32 characters of `SHA-256("afcy_hwidS" ‖ seed)` in **upper-case** hex,
   grouped `8-4-4-4-12`.

The `"afcy_hwidS"` prefix is XOR-obfuscated in the client as `{35,21,77,36,64,11,63,94,8,70}`
against the same 16-byte table it uses for the crypt1 salt. The two hex cases are not a typo: the
seed is formatted `%02x` and the id `%02X`.

**INFERRED**: this was read from the code, not observed on a device, so it carries no test vector.
A caller that has seen a real Incy id should pass it in `RequestOptions::hwid` instead of deriving
one.

## Subscription body

Incy accepts the Happ body forms — a Base64 blob or newline-separated links, a JSON array of Xray
configs, one Xray config object, raw WireGuard/AmneziaWG `.conf` — plus its own extras, and reads
these directives:

| Source | Keys |
|---|---|
| Body `#key: value` | `#announce:`, `#profile-title:`, `#support-url:`, `#profile-web-page-url:`, `#announce-url:`, `#hide-check:`, `#profile-update-interval:`, `://routing/…`, `://autorouting/…` |
| Response headers | `routing` (both cases), `subscription-userinfo` |

Two things it does **not** have: no encrypted-body mode (the `Encrypt-Tag` / `?key=keyNN` scheme
of [04](04-body-encryption.md) is Happ-only, and there is no key table), and no vendor licensing
service — `hwid` here is a device fingerprint, not a licence check.

A body directive that Incy does not know is passed through as content, so a provider can mix Incy
and Happ directives in one response; the routing directives are deliberately schemeless
(`://routing/onadd/{base64}`) for that reason.

## Verification

`src/incy_request.rs` pins the header names, their order and the conditions under which the
`x-hwid` block appears, the User-Agent formats and override precedence, and the shape of a derived
id. Fidelity of the id itself is unproven — see the note above. The research project's
`probes/incy/` keeps the decompiled excerpts this document was written from.
