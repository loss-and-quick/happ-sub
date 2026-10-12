# Body encryption

A provider can encrypt the subscription body with AES-128-GCM. The key is one of 90 fixed keys, selected by the `key` query parameter of the subscription URL; the GCM tag travels in a response header. The scheme is **DOCUMENTED** in [Encrypting subscription content](https://www.happ.su/main/dev-docs/encrypting-subscription-content) and implemented in `kz1.b()`, called from `e53.a()`.

## Parameters

| Parameter | Value | Evidence |
|---|---|---|
| Cipher | AES-128-GCM (`AES/GCM/NoPadding`), 128-bit tag | `kz1.java:176`; vendor docs |
| Key | The full 16-byte ASCII entry string, e.g. `key02:+]%4ij#P"/` for `key02` (the `keyNN:` prefix is part of the key) | `kz1.java:170`, `new SecretKeySpec(key.getBytes(), "AES")`; vendor test key |
| IV | Fixed 12 bytes: ASCII `kkkkkkkkkkkk` | `kz1.java:171`; vendor docs |
| Associated data | None | `kz1.b()` |
| Tag | 16 bytes, standard Base64 in the `Encrypt-Tag` response header (name matched case-insensitively) | `kz1.java:175`; vendor docs write `encrypt-tag` |
| Body | Standard Base64 of the ciphertext, without the tag | `kz1.java:177` appends the tag before `doFinal` (`qt.t0(cipher, tag)`) |
| Plaintext | UTF-8 subscription body, processed as in [02](02-subscription-body.md) | `kz1.java:182` |

All rows are **VERIFIED**: code, vendor documentation and the `key02` test vector agree, and the replication decrypts real data (see [Five confirmations](#five-confirmations-of-the-key-table)).

```
ct        = base64_decode(response_body)
tag       = base64_decode(header["Encrypt-Tag"])     // 16 bytes
key       = ascii_bytes(table[key_id])                // 16 bytes
plaintext = AES_128_GCM_Decrypt(key, iv = b"kkkkkkkkkkkk", ct || tag)
```

## Key selection

The subscription URL carries the key ID: `https://provider.example/sub/abc?key=key02`. Key IDs are `key01` … `key90`. Happ reads the `key` query parameter (`e53.java:73`) and picks the entry whose `entry.split(":")[0]` equals it, so any ID in the table is valid (**VERIFIED**). The table is in [`src/keys/gen1.rs`](../src/keys/gen1.rs); the documentation does not repeat it.

The crate groups keys into generations because keys are not versioned on the wire. Generation 1 is the table measured unchanged in Happ 4.3.0 through 4.7.1 ([below](#key-stability-across-versions)). With `BodyKeySource::Auto` the crate tries each known generation and uses GCM authentication to tell which one matched; `BodyKeySource::Pinned` uses one table.

## When a body is decrypted

Happ attempts decryption when the `Encrypt-Tag` header is present and non-empty **and** either the URL has a `key` parameter or the subscription was previously stored as encrypted (`SubscriptionItem.encrypted`). Otherwise the body is used as is (`e53.java:44`, `e53.java:85`; **VERIFIED**, on-device mock, 2026-10-12). After a successful decryption Happ sets the stored flag.

| Case | Happ 4.7.1 | `parse` |
|---|---|---|
| No tag (also when stored as encrypted) | Body used as is | `BodyEncryption::None` |
| Tag, no `?key=`, not stored as encrypted | Body used as is; an encrypted body then fails with "Unknown content type" | `BodyEncryption::None` |
| Tag and `?key=`, decryption succeeds | Decrypted body imported, body directives applied | `BodyEncryption::Decrypted { key_id, table_id }` |
| Tag and `?key=`, decryption fails: unknown key ID, wrong key, corrupt tag, plaintext sent with a tag | **Empty body**: the server list is wiped and the update reported as successful | `Err(Error::Decrypt { key_id, reason: DecryptFailure::Crypt(_) })` |
| Tag, stored as encrypted, no `?key=` | Key ID `""` matches no entry, decryption throws, empty body | `Err(Error::Decrypt { key_id: None, reason: DecryptFailure::MissingKeyParam })` |

The empty body comes from `kz1.b()`, which catches every exception and returns `""`; `e53.a()` hands that string to the importer instead of the original body (**VERIFIED**, on-device mock, 2026-10-12: wrong key `key03`, unknown key `key99`, corrupt tag, and plaintext with a tag on a subscription stored as encrypted). The last row is read from the code only (**INFERRED**): `new-url` is inert for an ordinary subscription ([07](07-fetch-and-update.md#alternative-fetch-targets)), so a stored-encrypted subscription could not lose its `key` parameter on the device.

The crate fails loudly instead of wiping the subscription: a caller that keeps its previous server list on error gets the safe outcome. A build without the `body-crypt` feature returns `DecryptFailure::CryptDisabled` for every attempt.

## How the keys are stored in the client

`strings` on the APK finds none of the 90 keys. They are assembled at startup from three layers (**VERIFIED**: each layer was reproduced and the result passes the checks below):

| Layer | Where | Contributes |
|---|---|---|
| 1. Native string table | `liberror-code.so`, JNI `jniGetErrorMessageFromCode(int)`: a 1058-case jump table at `0x18c5a0` whose strings are XOR-decrypted at runtime, using TLS, `pthread_once` and the heap; ids 0 and 1 return `No such error code`, the table ends at 1059 | Ciphertexts, keys and tags for layer 2 |
| 2. Encrypted seeds | `kz1.<clinit>`, `kz1.java:30-52` | 90 entries `AES-GCM-Decrypt(S1[i], key = S2[i], tag = S3[i])`, where S1, S2 and S3 are layer-1 strings for three hard-coded 90-element id lists; each yields `keyNN:xxxxx` (11 characters) |
| 3. PNG steganography | `HappApplication.onCreate` → `kz1.a(i, R.drawable.ic_*)` | 90 Material-lookalike icons (`ic_bolt_24dp.png`, …), each hiding 5 ASCII characters in the low 2 bits of the green and blue channels, framed as `!encoded!<len>!`; appended to layer 2 |

Final entry = 11 + 5 = 16 bytes = `keyNN:` + 10 characters.

### Anti-tamper check

`HappApplication.onCreate` first decrypts a hard-coded blob with the same `kz1.b` primitive:

```
uWM0lcVs0849kTwk?AqHnQy35aOM/ZtgUip+BrTHHLnSYBNwQAX0y2g==?os8iL1DE8Dee/5roJ+ZzsQ==
```

Split on `?` it is key, ciphertext and tag. It decrypts to `g+Uz1USttQp3T0c146yMV1OLJDI=`, i.e. the 20-byte SHA-1 `83e533d544adb50a774f4735e3ac8c57538b2432`. `apksigner verify --print-certs` on the release APK prints the same value as `Signer #1 certificate SHA-1 digest` (signer `C=US, ST=Delaware, L=WILMINGTON, O=FlyFrog LLC`, certificate SHA-256 `397e98abed03c5f263ffaf4e8a1043b2a59f538b99e75cf152fa05a7e8007d8d`). The check is therefore `base64(SHA-1(signing certificate))`. On mismatch, as in a repacked APK, `kz1.e()` overwrites all 90 entries with random UUIDs and decryption silently breaks. Debug builds randomise the keys the same way.

### How the keys were extracted

Static extraction of layer 1 is impractical, so the native table was executed:

1. **Layer 3.** Decode the 90 drawables with Pillow, replicating `kz1.a`: read the two low bits of the green and blue channels until the `!encoded!<len>!` frame ends. 90 of 90 decode.
2. **Layer 1.** `liberror-code.so` is arm64/bionic and cannot be loaded by an x86_64 `app_process`; calling it from a translated arm64 process crashes on the fake `JNIEnv`. The exported function ends in a tail call to `JNIEnv->NewStringUTF`, so four instructions at `0x18e0dc` are patched to return the raw `char *`:

   ```
   18e0dc: ldr x8, [x19]          ->  mov x0, x1
   18e0e0: ldr x2, [x8, #0x538]   ->  nop
   18e0e4: mov x0, x19            ->  nop
   18e0f0: br  x2                 ->  ret
   ```

   The patched function is `const char *f(void *, void *, int)` and runs under the emulator's `ndk_translation` (API 34 `google_apis` x86_64 image, NDK r28). Ids 0 to 1100 were dumped with no crash.
3. **Layer 2 and assembly.** Decrypt the seeds with the dumped strings using a byte-exact replication of `kz1.b`, append the layer-3 strings, and emit the table.

A second, Unicorn-based extractor later reproduced the same table byte for byte without an emulator, with the five checks below as automated gates.

### The second native key: `kz1.c` and `assets/data.result`

`kz1.c` builds a separate AES-128-GCM key as `jniGetErrorMessageFromCode(35) + "|fRC77gcp0,"` = `CHku5|fRC77gcp0,` (16 bytes) with IV `jniGetErrorMessageFromCode(1059)` = `vrbculqfahmw` (12 bytes). The lengths were predicted from the code before extraction. It decrypts the bundled asset `assets/data.result` (48,331 bytes; `j52.java`):

```
head = file[0:12], tail = file[-12:]        // ASCII
tag  = base64_decode(head + tail)           // 16 bytes
ct   = file[12:-12]                         // 48,307 bytes
pt   = AES_128_GCM_Decrypt(key = "CHku5|fRC77gcp0,", iv = "vrbculqfahmw", ct || tag)
data = zstd_decompress(pt)                  // pt starts 28 b5 2f fd; data is 94,784 bytes of JSON
```

What the registry contains and how the client uses it is in [08](08-device-binding.md#domain-hash-registry).

## Five confirmations of the key table

Each check is independent of the others:

1. **Vendor test key.** The vendor documentation publishes `key02:+]%4ij#P"/` for provider testing; the extracted `key02` is identical byte for byte.
2. **Shape.** All 90 entries are exactly 16 bytes, named `key01` … `key90`, distinct, with `entry.split(":")[0]` equal to the ID. The two `kz1.c` values are exactly 16 and 12 bytes.
3. **Anti-tamper blob.** It decrypts with the replicated primitive to the APK signing certificate's SHA-1 ([above](#anti-tamper-check)). This was the first proof that the replication is byte-exact.
4. **Round trip.** Bodies encrypted with extracted keys decrypt back through the replicated `kz1.b` (7 of 7 sampled keys); the crate's tests repeat this for all 90.
5. **Shipped data.** `assets/data.result` decrypts with the native `kz1.c` values and decompresses to valid JSON. This is real production data, not a self-made round trip.

## Key stability across versions

APKs from 3.20.4 to 4.7.1 were compared. `liberror-code.so` exists in five distinct builds across that range, but the steganographic PNG set is byte-identical from 4.3.0 onward and differs before it. Running the extractor on 4.3.0, 4.5.0 and 4.7.1 produced identical 90-key tables, all five checks passing (the patch offset is `0x18e0dc` in 4.5.0 and 4.7.1, `0x18e3ec` in 4.3.0). 3.26.3 uses an older native code layout that the extractor rejects, so whether older releases share the table is **UNKNOWN**. The crate's generation 1 (`gen1-4.3.0..4.7.1`) is this measured range.

## Test vector

The vendor's provider documentation publishes `key02` for testing (**DOCUMENTED**):

- URL: `https://vpn.example.com/sub/demo?key=key02`
- Key: `key02:+]%4ij#P"/`
- IV: `kkkkkkkkkkkk`

Provider side:

1. Encrypt the plaintext body with AES-128-GCM under that key and IV.
2. Split the output into ciphertext and the trailing 16-byte tag.
3. Send `Encrypt-Tag: <Base64(tag)>` and the body `<Base64(ciphertext)>`.

The crate's `test-vectors` feature exposes `body_crypt::encrypt_with_table` for producing such samples in tests.

## Security properties

The IV is the same for every key, request and subscriber. Under GCM, nonce reuse with the same key leaks the XOR of plaintexts and allows tag forgery, and all 90 keys are public. The scheme hides content from casual inspection only. Implement it for importing subscriptions; never use it to serve new ones.

## Confidence and open questions

The cipher, IV, header, key format and the 90 keys are **VERIFIED** as described above. The trigger and the failure handling are **VERIFIED** against Happ 4.7.1 on a device with a mock server that encrypted bodies under `key02` ([10](10-verification.md#live-probes-2026-10-12)). The live provider ignored `?key=key01` and `?key=key02` and sent plaintext without `Encrypt-Tag`, so no body encrypted by a real provider was checked.

Open questions:

- Whether future releases replace the key table is **UNKNOWN**. The vendor documentation still publishes the same `key02`; re-running the extractor on a new APK detects a change, and a new table would be added as a new generation.
