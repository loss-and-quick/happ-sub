# Happ subscription format

A specification of the wire formats used by Happ-compatible (`su.happ.proxyutility`) subscriptions, written to make other clients interoperable and to keep the underlying research reusable. The reference client is Happ 4.7.1 for Android, a closed-source derivative of the GPL-3.0 v2rayNG. Every claim is tagged **VERIFIED**, **DOCUMENTED**, **INFERRED** or **UNKNOWN** and cites the decompiled code, the native library, the vendor documentation, the live sample or the on-device observation it rests on ([01](01-overview.md#how-the-facts-were-established)). Where this crate implements a step, the documents name the module; the rest is for callers.

| Document | Contents |
|---|---|
| [01 Overview](01-overview.md) | Lineage, evidence tags and sources, the two encryption layers, end-to-end flow, terminology |
| [02 Subscription body](02-subscription-body.md) | Detection cascade, payload forms, share-link grammars per parser class, rejections, observed provider behaviour |
| [03 Meta directive protocol](03-meta-protocol.md) | Header and body transports, `base64:` prefix, precedence, refresh merge, value formats, all 91 keys with `RiskClass` |
| [04 Body encryption](04-body-encryption.md) | AES-128-GCM parameters, `Encrypt-Tag`, `?key=keyNN`, when decryption is attempted and what a failure does, how the keys are stored and were extracted, the five confirmations, version stability, `key02` test vector |
| [05 URL encryption](05-url-encryption.md) | `happ://crypt/` … `happ://crypt5/` dispatch and wire layout, measured sizes, embedded RSA keys and their provenance |
| [06 Deeplinks and routing](06-deeplinks-and-routing.md) | `happ://` actions, routing profile delivery, what Happ does with a profile, JSON schema |
| [07 Fetch and update](07-fetch-and-update.md) | Request headers and the default `User-Agent`, timeouts, observed provider behaviour, `new-url` / `new-domain` / `fallback-url`, persistence, scheduling, update errors |
| [08 Device binding and vendor services](08-device-binding.md) | HWID and its SSAID derivation, `hwidlink`, REST / DNSTT / FILE licensing checks, `providerid` / `installid`, the domain-hash registry, vendor endpoints, and what a client controls |
| [09 Implementation guide](09-implementation-guide.md) | Import pipeline, crate/caller split, policy, fixtures |
| [10 Verification ledger](10-verification.md) | Evidence per claim, the five key confirmations, `crypt5` round trips, the `incy://crypt1/` derivation, the 2026-10-12 live provider and on-device probes with their methods, corrections to earlier drafts, open items |
| [11 Incy URL obfuscation](11-incy-url-obfuscation.md) | `incy://crypt1/`: AES-256-GCM wire layout, sorted-JSON plaintext, the keymat key derivation, the client's leniency, link generation |

Redacted live samples are under [`tests/fixtures/`](../tests/fixtures/). The body key table is in [`src/keys/gen1.rs`](../src/keys/gen1.rs), the URL RSA keys are in [`src/keys/url-keys.json`](../src/keys/url-keys.json) and the Incy keymat is in [`src/keys/incy-keymat.json`](../src/keys/incy-keymat.json).

Not covered: Xray configuration semantics, provider panels, and the internals of the vendor's backend beyond what the client sends to it.
