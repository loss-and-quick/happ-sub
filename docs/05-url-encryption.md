# URL encryption (`happ://crypt*`)

Providers can hand out the subscription URL in encrypted form so the user cannot read or share it directly (`SubscriptionItem.encryptedUrl`, `dto/SubscriptionItem.java:24`). The client decrypts the deeplink and fetches the resulting URL. The vendor describes the feature in [Crypto link](https://www.happ.su/main/dev-docs/crypto-link) and runs a public generator at `https://crypto.happ.su/` (page title "URL Encryption v3"; API `POST https://crypto.happ.su/api-v2.php` with `{"url": …}` returns `{"encrypted_link": "happ://crypt5/…"}`).

**Key material.** All schemes use RSA private keys held inside the vendor's client, obfuscated in `liberror-code.so`; this research did not extract them itself. URL decryption is behind the non-default `url-crypt` feature and takes any `url_crypt::Keyring`. The `builtin-url-keys` feature adds `url_crypt::builtin_keyring()`, which embeds `crypt5_keys.json` from [KernelEditor/HappDecrypt](https://github.com/KernelEditor/HappDecrypt) at commit `8d0b97b1875446abb16a0d1b62492a404e766860` (36 `crypt5` markers and the four `crypt` … `crypt4` keys) as [`src/keys/url-keys.json`](../src/keys/url-keys.json). The set is corroborated twice: the RSA public key published in the vendor's Crypto link page equals the public half of `pkcs1_2` over the full 4096-bit modulus, and the five generator links decrypt with it ([Confidence](#confidence-and-open-questions)). Measured key sizes: 39 keys of 4096 bits (the 36 markers and `pkcs1_1` … `pkcs1_3`) and `pkcs1_0` of 1024 bits. A caller can instead load its own keys with `MemoryKeyring::from_json_str` / `from_file`, from a JSON object of the same shape: key name to Base64 DER in PKCS#1 or PKCS#8 form, where key names are `pkcs1_0` … `pkcs1_3` for `crypt` … `crypt4` and the 8-character marker for `crypt5`.

## Dispatch in the client

The deeplink prefix maps to `EncryptedUrlMode` (`jz1.java`) and is decrypted by `uy4.E(url, EncryptedUrlMode)` (`uy4.java:184`) inside the fetcher, before the request is made (`e53.java:221-225`). The RSA work is done by the native library, addressed by key ordinal 0 to 3 or by marker (**INFERRED**). A hard-coded 4096-bit RSA public key used on the crypt path is in `q61.java:31`.

| Prefix | `EncryptedUrlMode` | Scheme | Key |
|---|---|---|---|
| `happ://crypt/` | `RSA_1024` | Chunked RSA-1024, PKCS#1 v1.5 | `pkcs1_0` |
| `happ://crypt2/` | `RSA_4096` | Chunked RSA-4096, PKCS#1 v1.5 | `pkcs1_1` |
| `happ://crypt3/` | `RSA_4096_2` | Chunked RSA-4096, PKCS#1 v1.5 | `pkcs1_2` |
| `happ://crypt4/` | `RSA_4096_3` | Chunked RSA-4096, PKCS#1 v1.5 | `pkcs1_3` |
| `happ://crypt5/` | `CRYPTO_5` | ChaCha20-Poly1305 with an RSA-4096 encrypted session key | selected by marker |

`uy4.E` also contains a debug shortcut at `uy4.java:191`: the payload `LDhKyuZYdvtoxZ` skips decryption and returns `https://yandex.ru/<device fingerprint>`. It is not part of the format; a third-party client must not reproduce it.

## `crypt` … `crypt4`

1. Base64-decode the payload (the crate accepts the standard and URL-safe alphabets, with or without padding).
2. Split the bytes into blocks of the modulus size: 128 bytes for RSA-1024 (at most 117 plaintext bytes per block), 512 bytes for RSA-4096 (at most 501). The length must be a multiple of the block size.
3. Decrypt each block with RSA PKCS#1 v1.5 and concatenate the results.
4. The result is the UTF-8 subscription URL.

These steps are **INFERRED** from the mode enum and the key sizes; no vendor-issued `crypt` … `crypt4` link was available.

## `crypt5`

```
happ://crypt5/<payload>
```

The payload is ASCII (Base64 alphabet plus decimal digits and filler characters). Every step below is **VERIFIED** against five links from the vendor generator ([`tests/fixtures/crypt5-samples.json`](../tests/fixtures/crypt5-samples.json)).

### Step 1: block half-swap

For each complete 4-byte block `ABCD` of the payload, swap the 2-byte halves to get `CDAB`. Trailing bytes (length mod 4) stay in place. Call the result `s`. No multiple-of-4 alignment of the payload is required.

### Step 2: marker

```
marker = s[0..4] ++ s[len-4..len]     // 8 ASCII characters, selects the RSA key
body   = s[4..len-4]
```

### Step 3: body layout

Salted layout (all five samples):

| Offset | Length | Field |
|---|---|---|
| 0 | 12 | `nonce`, ASCII, used verbatim as the ChaCha20-Poly1305 nonce |
| 12 | 2 | filler, random, never read |
| 14 | 8 | `salt`, ASCII |
| 22 | variable | `seg_len`, decimal ASCII digits, no delimiter |
| after digits | 1 | filler, random, never read |
| next | `seg_len` | `enc_url`, Base64 |
| rest | to end | `enc_skey`, Base64 |

The two filler fields vary between samples and no decoder reads them. An earlier review of the third-party decoder took them for a mode tag and a fixed separator; both readings were wrong.

Unsalted layout: there is no filler or salt; `seg_len` starts at offset 12. A decoder can tell the layouts apart by `body[12]`: an ASCII digit means unsalted. The unsalted layout is legacy and was not seen in current links. The crate tries the layout this check suggests first and then the other one.

### Step 4: session key

```
rsa_plain   = RSA_PKCS1v15_Decrypt(key[marker], base64_decode(enc_skey))   // 512-byte block → 44 ASCII bytes
session_key = base64_decode(swap_adjacent(rsa_plain))                      // 32 bytes
chacha_key[i] = session_key[i] XOR salt[i mod 8]     for i in 0..32        // salted layout only
```

`swap_adjacent` swaps each pair of bytes (`ABCD` → `BADC`); a trailing odd byte stays in place. It is its own inverse.

The session key travels inside RSA as its 44-character Base64 text rather than as 32 raw bytes. The native path passes everything through string-oriented JNI helpers (`jniGetErrorMessageFromString2`), so every value stays ASCII. PKCS#1 v1.5 needs at least 55 bytes of modulus for a 44-byte payload, and a 4096-bit key carries up to 501.

### Step 5: URL

```
inner = ChaCha20_Poly1305_Decrypt(chacha_key, nonce, base64_decode(enc_url))   // ciphertext || 16-byte tag
url   = utf8(base64_decode(swap_adjacent(inner)))
```

The ChaCha20-Poly1305 plaintext is pair-swapped Base64 of the URL, the same wrapping as the session key; the encoder computes `inner = swap_adjacent(base64(url))`. Swapping after Base64 decoding instead fails on every vendor sample. The lengths check out against the samples: a 52-byte URL gives a 72-character `inner`, an 88-byte ciphertext and `seg_len` 120; a 39-byte URL gives 52, 68 and 92.

### Measured sizes

Identical in all five samples:

| Field | Size |
|---|---|
| `enc_skey` | 684 Base64 characters = 512 bytes, one RSA-4096 block, never chunked |
| RSA plaintext | 44 ASCII characters |
| Session key | 32 bytes |
| Salt | 8 bytes |
| Nonce | 12 bytes |
| Poly1305 tag | 16 bytes, at the end of the decoded `enc_url` |

The native ChaCha path at `liberror-code.so:0x183024` steps and compares in `0x20` (32-byte key), `0x8` (8-byte salt) and `0x10` (16-byte tag) units, which matches the measurements. It also calls `rand@plt` twice, so the same routine generates links as well as decrypting them; the format is symmetric and a client could emit `crypt5` links itself.

## Confidence and open questions

Five `crypt5` links produced by the vendor's public link generator on 2026-10-12, all with neutral `https://example.com/…` targets ([`tests/fixtures/crypt5-samples.json`](../tests/fixtures/crypt5-samples.json)), decrypt to their expected URLs with the crate's implementation and the embedded keys; the integration tests check this whenever `builtin-url-keys` is enabled. The samples confirm the block half-swap, marker position, nonce, salted layout, single RSA block and the order of `swap_adjacent` and Base64 in step 5. An earlier draft of this research described step 5 as `swap_adjacent(base64_decode(inner))`; checked against the five samples, that order is wrong ([10](10-verification.md#corrections)).

Open questions:

- `crypt` … `crypt4` were not observed recently; the public generator emits only `crypt5`. The embedded keys parse and chunked decryption round-trips with a test key, but no vendor-issued `crypt` … `crypt4` link was checked.
- All live `crypt5` samples used one marker (`vdfzfoff`). The other 35 embedded markers were not observed in the wild; links already issued and provider-side tooling may use any of them.
- The unsalted `crypt5` layout was not observed in recent samples (current links are salted).
- The URL private keys come from the third-party key set, not from this research's own extraction pipeline; they are pinned by commit and SHA-256 and re-verified by the crate's tests.
