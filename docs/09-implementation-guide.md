# Implementation guide

An end-to-end import pipeline for a Happ-compatible client, and how the work splits between this crate and the caller. Each step names the document that specifies it and carries the evidence for it.

## Division of work

| Step | Who |
|---|---|
| Deeplink parsing, `crypt*` URL decryption | crate (`deeplink`; `url_crypt` with `builtin_keyring()` or a caller-supplied keyring) |
| Request headers in Happ's order, User-Agent, timeout, retry rules | crate (`request::build`), from the device facts, HWID, overrides and consent the caller supplies |
| HTTP transport, cookie jar, TLS, DNS | caller, following the `RequestProfile` |
| Device facts (OS, OS version, model, locale), the HWID and its default, per-subscription overrides | caller |
| Happ's SSAID, the HWID Happ sends | crate (`device`, from a caller-supplied user key); whether to send it is the caller's policy |
| Body decryption, directive extraction, payload detection, routing decoding, meta merge | crate (`parse`) |
| Share-link parsing | caller |
| Deciding which meta keys to apply | caller, using `RiskClass` |
| Persistence and scheduling | caller |

## Pipeline

```
IngestSubscription(input, stored) -> Result<Import, Error>

1. Resolve the URL
   s = trim(input)
   if s starts with "happ://crypt"          → url = DecryptUrl(s)              // 05
   else if s starts with "happ://add/"      → url = s without "happ://add/"
   else if s starts with "happ://routing/"  → return ImportRouting(s)          // 06
   else                                     → url = s
   fragment_meta = directives after "#…?" of url, on import only               // 03
   store and fetch url without its fragment

2. Fetch                                                                       // 07
   profile = request::build(identity, stored.meta, now, consent)
       identity: device facts, HWID (or none), the user's overrides for this subscription
       consent:  whether the user accepted change-user-agent / manual-block-user-agent
   GET url with profile.headers in order; the client adds Host and Accept-Encoding
   timeout = profile.timeout per attempt; one retry per profile.retry(cause) if the call fails
   cookie jar per host, shared by all subscriptions
   providers pick the body format and the routing header by the User-Agent
   non-2xx → Err(Network)

3. Decrypt the body                                                            // 04
   tag    = header "Encrypt-Tag" (case-insensitive), if non-empty
   key_id = query parameter "key" of url
   if tag and (key_id or stored.encrypted):
       body = AesGcmDecrypt(table[key_id], iv = "kkkkkkkkkkkk", b64(body) || b64(tag))
              on any failure, or no key_id: Err(Decrypt)        // Happ imports an empty body
   else:
       body unchanged

4. Split directives and detect the payload                                     // 02
   body_meta, routing_lines, rest = extract "#key: value" and "happ://routing/" lines
   if rest is one Base64 line decoding to UTF-8 containing "://":
       rest = decoded; extract directives and routing lines from it as well
   '[' → JsonArray
   '{' → SingBoxJson if every outbound has "type" and none "protocol", else XrayJson
   else → Links (one per non-empty line)

5. Merge metadata                                                              // 03
   response_meta = header_meta, then body_meta overwrites
   on import:  meta = fragment_meta, then response_meta overwrites; absent keys kept
   on refresh: meta = response_meta + keys of stored.meta it lacks (sticky keys only
               on a user-started refresh, all keys on a background update)
   a body "0" clears fallback-url, host, insecure, …; no meta at all keeps stored.meta

6. Routing                                                                     // 06
   actions = routing_lines ++ meta["routing"], each add / onadd / off; undecodable ones are skipped with a warning
   add and onadd both activate the profile in Happ; off turns routing off for this subscription

7. Policy
   for (key, value) in meta: apply according to classify_key(key)             // 03
   new-url / new-domain / fallback-url / routing: only with user consent

8. Persist and schedule                                                        // 07
   keep the user's selected server by matching connection parameters, not the full link
   interval = meta["profile-update-interval"] clamped to 1..730 hours, else client default
```

Step 3 deliberately departs from Happ, which turns every failed decryption into an empty body, wipes the subscription's servers and reports success. `parse` returns `Error::Decrypt` with the key ID and a typed `DecryptFailure` instead; a client that keeps the previous server list on any error then does the safe thing. The other deliberate differences are listed in the [README](../README.md#deliberate-differences-from-happ).

## Policy by `RiskClass`

See [03](03-meta-protocol.md#risk-classes) for the classes and the per-key assignment. In short:

- Apply `Display` and `Schedule` keys automatically; clamp `Schedule` values to their ranges.
- Show `TunnelBehaviour` changes, or apply them only after the user opts in.
- Require per-subscription consent for every `TrustBoundary` key. Show the old and new value (`meta::changes`), and for `new-url`, `new-domain` and `fallback-url` the target host. Happ 4.7.1 itself ignores those three for an ordinary subscription ([07](07-fetch-and-update.md#alternative-fetch-targets)).
- Ignore `DeviceIdentity` and `Ignored` keys by default. The exception is the three `subscription-*-hwid-*` switches, which `request::build` applies: they only withhold, force or move the device headers Happ sends by default, and the user's overrides win over them. `change-user-agent` and `manual-block-user-agent` reach the request only through the consent predicate.

## Things not to implement

Happ also talks to vendor services for licensing, device limits, crash reporting and cloud sync: the `time-ntp.com` REST gate, the DNSTT tunnel, Sentry, CloudKit `send_to_device`, the daily statistics check and the domain-hash registry ([08](08-device-binding.md)). None of that is part of the subscription format, and a third-party client should not contact those services or enforce `hwidlink`. Whether it sends device identifiers is its own policy ([07](07-fetch-and-update.md#device-identifiers)).

## Fixtures

The fixtures under [`tests/fixtures/`](../tests/fixtures/) hold redacted live material. The integration tests in `tests/integration_tests.rs` parse all of them.

| File | Contents |
|---|---|
| [`fixture-headers.txt`](../tests/fixtures/fixture-headers.txt), [`fixture-body.b64.txt`](../tests/fixtures/fixture-body.b64.txt), [`fixture-body-decoded.txt`](../tests/fixtures/fixture-body-decoded.txt) | An earlier capture of a provider response: headers with meta keys and a `routing` header, the whole-body Base64 body (34 links) and its decoded link list |
| [`live-2026-10-12/01-happ-full.http`](../tests/fixtures/live-2026-10-12/01-happ-full.http) | Full response to `User-Agent: Happ/4.7.1/Android/1703`: seven meta headers including `routing`, Base64 list of 33 links (26 VLESS, 4 Hysteria2, 3 Shadowsocks) |
| [`live-2026-10-12/03-v2rayng.http`](../tests/fixtures/live-2026-10-12/03-v2rayng.http) | Response to `User-Agent: v2rayNG/1.10.16`: the same list, no `routing` header |
| [`live-2026-10-12/05-clash-verge.http`](../tests/fixtures/live-2026-10-12/05-clash-verge.http) | Response to `User-Agent: clash-verge/v2.3.1`: Clash YAML, which the crate rejects as `UnknownContentType` |
| [`live-2026-10-12/07-sing-box.http`](../tests/fixtures/live-2026-10-12/07-sing-box.http) | Response to `User-Agent: sing-box 1.12.0`: a sing-box configuration with 32 outbounds, `Payload::SingBoxJson` |
| [`crypt5-samples.json`](../tests/fixtures/crypt5-samples.json) | `crypt5` links produced by the vendor's public generator with their expected URLs, decrypted with the embedded keys when `builtin-url-keys` is enabled |

The `.http` files are the raw responses with CRLF line endings: status line, headers, an empty line and the body. How they were captured and redacted is in [10](10-verification.md#method-live-provider-probe). The fixtures are not part of the published crate.
