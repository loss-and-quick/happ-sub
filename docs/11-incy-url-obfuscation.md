# Incy URL obfuscation (`incy://crypt1/`)

INCY (`llc.itdev.incy`, Android 3.7.0 / versionCode 370) can hand out the subscription URL wrapped in a deeplink, so a chat log, a screenshot or a moderation bot does not show the endpoint. It is the same idea as [`happ://crypt*`](05-url-encryption.md), with a symmetric cipher instead of RSA. The vendor states plainly that this is obfuscation, not secrecy: the key ships in every client and in their MIT reference package.

`incy_crypt` implements it; nothing else in the crate knows the scheme.

## Parameters

| Parameter | Value | Evidence |
|---|---|---|
| Prefix | `incy://crypt1/`, matched case-insensitively on the URI host `crypt1` | Decoder in `wf/f.java` (`llc.itdev.incy`, classes3.dex); no other `cryptN` exists in 3.7.0 |
| Cipher | AES-256-GCM (`AES/GCM/NoPadding`), 128-bit tag | `Cipher.getInstance("AES/GCM/NoPadding")`, `GCMParameterSpec(128, iv)` |
| IV | 12 random bytes per link, used verbatim | `wire[0:12]`; the client's own encoder draws them from `SecureRandom` |
| Associated data | None | the client passes `null` |
| Wire | `base64url( iv ‖ ciphertext ‖ tag )`, unpadded | `Base64.URL_SAFE \| NO_WRAP \| NO_PADDING` on the read path, `Base64.encodeToString(…, 11)` on the write path |
| Plaintext | Compact JSON with **sorted** keys: `{"n":<name>,"url":<url>,"v":1}` | hand-rolled `StringBuilder` in the client's encoder; `JSONObject.optString("url")` / `optString("n")` on the read path |
| `url` | Required, non-empty. May carry a `#remarks` suffix | the client's share path encodes `url + "#" + remarks` |
| `n` | Optional display name; empty is treated as absent | `optString` returning `""` is mapped to absent |
| `v` | Written as `1`, never read | no read path inspects it |

```
wire      = base64url_decode(payload)
iv        = wire[0:12]
plaintext = AES_256_GCM_Decrypt(K1, iv, wire[12:])
url       = json["url"]
name      = json["n"]
```

All rows are **VERIFIED**: decompiled 3.7.0 code, the vendor's own pinned cross-platform test vector, and an independent third-party decryptor agree ([ledger](10-verification.md)).

## Key derivation

```
K1 = SHA-256("incy" ‖ "deep" ‖ "crypt1" ‖ "v2026.06" ‖ A[1024:1056] ‖ B[2048:2080])
```

`A` and `B` are the two 4 KiB assets the client ships as `res/raw/incy_assets_a.bin` and `res/raw/incy_assets_b.bin`. There is no secret input and no stretching, so the key is a published constant:

```text
K1          = f6d40ea0c8a8899d7c682d09ba0d4165dfe2b3dd45e6bb3e25cb233cf00c2462
SHA-256(K1) = b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c
```

Two details worth knowing when reading the client: the third salt part is not a literal but `int[]{41,9,87,45,107,82}` XOR a 16-byte table, which decodes to `crypt1`; and the second offset appears as `Barcode.FORMAT_PDF417`, an unrelated ML Kit constant whose value is 2048 (**VERIFIED**).

The assets are byte-identical in the INCY APK and in [`INCY-DEV/incy-link-encoder`](https://github.com/INCY-DEV/incy-link-encoder) (MIT), which pins the fingerprint above in its JS, Python, PHP and Go ports. `builtin-incy-keys` embeds them as [`src/keys/incy-keymat.json`](../src/keys/incy-keymat.json); `derive_key` recomputes `K1` from whatever blobs the caller passes, and `builtin_key()` refuses a keymat that does not reproduce the documented fingerprint.

## What the client tolerates

The decoder is more forgiving than the encoder, and `incy_crypt` is too:

| Input | Result |
|---|---|
| Empty path segments, i.e. a payload split across `/` | Segments are joined by the client's `Uri.getPathSegments()`; `decrypt_payload` takes the payload as given |
| `\r` or `\n` inside the payload | Stripped (`b64::decode_lenient` ignores ASCII whitespace) |
| Standard-Base64 `+` and `/` instead of `-` and `_` | Accepted (`Base64.decode(s, 0)` fallback; the crate's lenient decoder) |
| Missing `=` padding | Accepted |
| Decoded wire shorter than 29 bytes (`12 + 16 + 1`) | Rejected: `IncyCryptError::TooShort` |
| Tampered ciphertext or a foreign key | Rejected: `IncyCryptError::AesGcmAuth` |
| Plaintext that is not JSON, or has no non-empty `url` | Rejected: `IncyCryptError::Plaintext` |

Sorted plaintext keys are **not** required for decryption — GCM authenticates whatever the sender
produced. Sorting only makes links byte-identical across generators.

## Generating links

The client is also an encoder: `ig/d2.o` builds the share and QR string for a subscription flagged
as URL-hidden by calling the same AES-GCM path. `encrypt_link` does the same, with the IV as an
explicit parameter so tests and fixture builders are deterministic. Production callers must draw a
fresh 12 bytes per link; the vendor's own API labels its deterministic helper test-only.

## Scope

`crypt2` does not exist in 3.7.0. The vendor promises that a rotation would add `crypt2/` with new
key material and keep `crypt1/` working forever, so a client should dispatch on a table of schemes
rather than a single prefix — this crate exposes one function per scheme instead.

The INCY client also speaks the Happ-compatible subscription body (Base64 blob or link list, JSON
array or single Xray config, `#key: value` directives including `#profile-title:` and
`subscription-userinfo`, and the schemeless `://routing/onadd/{base64}` directive). It has **no**
encrypted-body mode: the `Encrypt-Tag` / `?key=` scheme of [04](04-body-encryption.md) is Happ-only.

## Verification

Fixtures: [`tests/fixtures/incy-crypt1-samples.json`](../tests/fixtures/incy-crypt1-samples.json) —
the vendor's pinned vector plus four generated cases. `happ-key-extractor` decrypts the same file
(`python -m happ_keys incy verify-fixtures`), so the Rust and Python implementations cannot drift
apart unnoticed; the research copy of the evidence is in `happ-research-backup/docs/11-incy-crypt1.md`.
