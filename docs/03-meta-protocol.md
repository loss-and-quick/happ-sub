# Meta directive protocol

Providers configure the client through 91 meta keys: the 90 in the vendor documentation and the undocumented `reset`. A key is delivered as an HTTP response header, as a `#key: value` line in the body, or in the fragment of the subscription URL. Values may carry a `base64:` prefix.

`MetaParams` (`dto/MetaParams.java`) defines 96 string constants: the 91 keys, the value prefix `base64:` (`PREFIX_BASE_64`, `MetaParams.java:51`) and the four `subscription-userinfo` field names. Earlier drafts of this research counted the prefix as a 91st parameter and missed `reset`.

## Transports

1. **Response headers.** Header names are matched case-insensitively. Every key except `hwidlink` and `reset` can be sent as a header (**VERIFIED**: `lw2.java:13` reads exactly 89 keys from the response headers; seven of them arrive as headers from a live provider). A response also carries ordinary HTTP headers (`content-type`, `date`, …); they are not meta keys and a client should ignore them. The crate keeps only headers named in `meta::KNOWN_KEYS`, except `hwidlink` and `reset`, and drops the rest.
2. **Body lines.** `#<key>: <value>` or `#<key>:<value>` on its own line, anywhere in the body (see [02](02-subscription-body.md#detection-cascade); `MetaParams.Companion.a(List, false)`; **VERIFIED**, on-device mock, 2026-10-12; **DOCUMENTED** in [App management](https://www.happ.su/main/dev-docs/app-management)). Directive lines are removed before the payload is parsed. Body directives are kept whatever the key; an unknown key is classified `Ignored`.
3. **URL fragment.** `https://…/sub#?key=value&key=value` is parsed with the same routine (`if7.b`, `MetaParams.Companion.a(List, true)`) and merged over the stored metadata when the subscription is imported (`qk7.java:119`) (**INFERRED**). `reset` is read only here. The crate does not parse URL fragments.

`hwidlink` is not a header either; it is a query parameter of the subscription URL, checked locally against the device identifier ([08](08-device-binding.md#local-check-hwidlink)).

## Value encoding

- **`base64:` prefix.** If a value starts with `base64:`, the remaining text is standard Base64 of UTF-8 text. Example: `profile-title: base64:RXhhbXBsZSBWUE4g8J+MkA==` decodes to `Example VPN 🌐`. Non-ASCII titles are normally sent this way, since header values are effectively ASCII. If decoding fails, the crate keeps the raw value. (**VERIFIED**: `PREFIX_BASE_64` handling in `MetaParams`; `profile-title` and `announce` arrive with the prefix from a live provider, and Happ stores them decoded, on-device mock, 2026-10-12.)
- **Booleans.** `true` or `1` is enabled, `false` or `0` is disabled (**DOCUMENTED**: [App management](https://www.happ.su/main/dev-docs/app-management); `MetaParams.Companion.f`).
- **Length caps.** `profile-title` is truncated to 25 characters when stored (**VERIFIED**, on-device mock, 2026-10-12: a 41-character title). `sub-info-button-text` is documented with 25 characters and `sub-info-text` with 200. The crate stores values untruncated.
- **Untrusted text.** Values are provider-controlled. The crate strips Unicode bidirectional control characters and carriage returns from every value.

## Specific value formats

| Key | Format |
|---|---|
| `profile-update-interval` | Integer **hours**, 1 to 730. Values below 1 are treated as 1; minutes and fractions are invalid. **VERIFIED**: `vl7.java:11` declares the range as `new pb3(1, 730, 1)`, the vendor docs state hours, a live provider sends `1`, and Happ shows `12` as a 12-hour auto-update and locks the user's interval field (on-device mock, 2026-10-12). |
| `subscription-request-timeout` | Integer seconds, 5 to 15. Happ's default is 7, and a value outside the range or not an integer also becomes 7. **INFERRED**: `uj7.java:64` (default), `MetaParams.Companion.a`; the 7 s default is consistent with the on-device fetch timing ([07](07-fetch-and-update.md#fetch-controls)). The crate's `subscription_request_timeout()` clamps instead. |
| `subscription-userinfo` | `upload=<bytes>; download=<bytes>; total=<bytes>; expire=<unix seconds>`. `total=0` means unmetered, `expire=0` means no expiry. Example: `upload=0; download=2153701362; total=107374182400; expire=1796256000`. **VERIFIED**: parsed into `dto/SubscriptionUserInfo.java`, **DOCUMENTED** in [App management](https://www.happ.su/main/dev-docs/app-management), present in the live fixture; Happ displays `(upload + download) / total` and the expiry date (on-device mock, 2026-10-12). |
| `routing` | A `happ://routing/add/…`, `happ://routing/onadd/…` or `happ://routing/off` deeplink ([06](06-deeplinks-and-routing.md)). |
| `sub-info-color` | `red`, `blue` or `green`. Stored as `RED` / `BLUE` / `GREEN`. Happ 4.7.1 stores `sub-info-text`, `sub-info-color` and `sub-info-button-*` but does not display them on the main screen (on-device mock, 2026-10-12). |

## Precedence and refresh merge

Within one response, a body directive overrides a header with the same key, and keys present in only one transport are all kept (**VERIFIED**: `pc6.a(headerMeta, bodyMeta)`; on-device mock, 2026-10-12):

```
response_meta = headers, then body directives overwrite on key conflict
```

On refresh, Happ builds the stored metadata anew from the response (`MetaParams.Companion.c(new, old, isFull)`, which calls `d(new, isFull, old, getter, dropIfAbsent)` per key). A key in the new response replaces the stored value. A key absent from the new response is **dropped**, except for the sticky keys below, which keep their stored value (**VERIFIED**, on-device mock, 2026-10-12: a refresh that omitted `announce`, `support-url`, `profile-web-page-url`, `subscription-userinfo`, `profile-update-interval`, `fragmentation-enable`, `fragmentation-packets`, `ping-type` and `hide-settings` removed them all, while `sub-info-text`, `sub-info-color`, `fallback-url`, `sub-expire` and `sub-expire-button-link` survived):

```
stored_meta' = response_meta
               + { k: stored_meta[k] for k in STICKY if k not in response_meta }
```

| Sticky key | Can the provider clear it? |
|---|---|
| `installid`, `sub-info-color`, `sub-info-text`, `sub-info-button-text`, `sub-info-button-link`, `sub-expire`, `sub-expire-button-link` | No; only replaced |
| `fragment`, `resolve-address`, `host`, `insecure`, `providerid`, `notification-subs-expire`, `fallback-url` | Yes: sending the key with the value `0` sets its flag in `ResetInfo` and the merge (`MetaParams.Companion.e`) then drops it (**INFERRED**: `MetaParams.Companion.a`; not observed) |

`meta::refresh_merge` implements this with `meta::REFRESH_STICKY_KEYS`. It does not implement the `0` reset: the crate keeps `0` as an ordinary value, which a caller reads as "disabled" for the boolean keys.

The drop only happens when `isFull` is set; with it clear, `d()` keeps every absent key. Every refresh observed on the device dropped keys; which code paths clear the flag was not traced. Dropping a key from the metadata does not undo every effect: after `profile-update-interval` was dropped, the interval saved in the subscription's properties and the scheduled WorkManager job stayed ([07](07-fetch-and-update.md#scheduling)).

`reset` is a separate boolean read only from the URL fragment ([Transports](#transports)) and consumed by the provider extra-check path (`eq0`, `id7`; [08](08-device-binding.md)). What it resets is **UNKNOWN**; the crate classifies it `Ignored`.

## Risk classes

The crate assigns every key a `RiskClass` (`meta::classify_key`). The class is advice for the caller's policy; the crate applies nothing itself.

| `RiskClass` | Meaning | Suggested handling |
|---|---|---|
| `Display` | Labels, banners, quota, provider links | Apply automatically. |
| `Schedule` | Update interval, fetch timeout, list presentation | Apply automatically, clamped to the documented ranges. |
| `TunnelBehaviour` | Mux, fragmentation, noise, sniffing, ping settings | Apply with a visible indication, or let the user opt in. |
| `TrustBoundary` | Changes where the client fetches from, how it routes or resolves, what it exposes locally, or what the user can see | Require explicit per-subscription consent. |
| `DeviceIdentity` | Device binding and provider identification | Ignore by default ([08](08-device-binding.md)). |
| `Ignored` | `ping-result`, `reset` and any unknown key | Ignore. |

`fallback-url`, `new-url` and `new-domain` are `TrustBoundary` because each one points the client at a different, provider-chosen fetch target. An earlier draft of this research put `fallback-url` in the safe tier; that was wrong for the same reason. Happ 4.7.1 itself applies none of the three to an ordinary subscription ([07](07-fetch-and-update.md#alternative-fetch-targets)), so ignoring them loses nothing a Happ user would get.

## Key reference

Transport: **H** = response header (`lw2.java:13`), **B** = body directive. Every key can also travel in the URL fragment ([Transports](#transports)). The table lists all 91 keys; `base64:` is a value prefix, not a key. Keys and transports are **VERIFIED** against `MetaParams` and `lw2`; meanings are **DOCUMENTED** in [App management](https://www.happ.su/main/dev-docs/app-management) except where the confidence section says otherwise. The `RiskClass` column is the crate's classification, not Happ's.

| Key | Type | Transport | Meaning | `RiskClass` |
|---|---|---|---|---|
| `announce` | string | H, B | Provider announcement banner text | `Display` |
| `app-auto-start` | bool | H, B | Launch proxy application on system boot | `TrustBoundary` |
| `block-bind-to-tunnel-enable` | bool | H, B | Prevent tunnel socket loopback binding | `TrustBoundary` |
| `change-user-agent` | string | H, B | Override User-Agent for subscription requests | `TrustBoundary` |
| `check-url-via-proxy` | bool | H, B | Fetch the subscription through the running proxy | `TrustBoundary` |
| `dns-from-json-enable` | bool | H, B | Inherit DNS configuration from Xray JSON | `TrustBoundary` |
| `dont-use-filter` | bool | H, B | Disable client-side country/node filtering | `TrustBoundary` |
| `exclude-routes` | string | H, B | Comma-delimited CIDRs/domains to bypass | `TrustBoundary` |
| `exclude-routes-set` | bool | H, B | Toggle bypass route application | `TrustBoundary` |
| `fallback-url` | string | H, B | Secondary URL fetched if primary fails | `TrustBoundary` |
| `fragment` | string | H, B | TLS fragmentation: `len,interval,packets` | `TunnelBehaviour` |
| `fragmentation-advanced-param` | string | H, B | Base64-encoded advanced fragmentation settings | `TunnelBehaviour` |
| `fragmentation-delay` | int | H, B | Packet fragmentation delay (ms) | `TunnelBehaviour` |
| `fragmentation-enable` | bool | H, B | Enable TCP/TLS packet fragmentation | `TunnelBehaviour` |
| `fragmentation-interval` | string | H, B | Fragmentation interval range | `TunnelBehaviour` |
| `fragmentation-length` | string | H, B | Fragmentation chunk length range | `TunnelBehaviour` |
| `fragmentation-maxsplit` | int | H, B | Maximum packet split count | `TunnelBehaviour` |
| `fragmentation-packets` | string | H, B | Packets subject to fragmentation | `TunnelBehaviour` |
| `fragmentation-type` | string | H, B | Fragmentation algorithm type | `TunnelBehaviour` |
| `hide-settings` | bool | H, B | Hide node connection details from user | `TrustBoundary` |
| `host` | string | H, B | Override the Host header on subscription fetch | `TrustBoundary` |
| `http-auth-mode` | enum | H, B | Inbound HTTP proxy auth mode (`auto,manual,disable`) | `TrustBoundary` |
| `http-auth-password` | string | H, B | Inbound HTTP proxy password | `TrustBoundary` |
| `http-auth-user` | string | H, B | Inbound HTTP proxy username | `TrustBoundary` |
| `hwidlink` | string | URL query | Device identifier the subscription is bound to | `DeviceIdentity` |
| `inbound-http-enable` | bool | H, B | Enable local HTTP inbound proxy | `TrustBoundary` |
| `insecure` | bool | H, B | Disable TLS certificate checks on fetch | `TrustBoundary` |
| `installid` | string | H, B | Installation identifier for per-device activation limits | `DeviceIdentity` |
| `local-dns-enable` | bool | H, B | Enable local system DNS resolution | `TrustBoundary` |
| `manual-block-user-agent` | bool | H, B | Block fetch if custom User-Agent rejected | `TrustBoundary` |
| `mux-enable` | bool | H, B | Enable TCP/UDP multiplexing (Mux.Cool) | `TunnelBehaviour` |
| `mux-quic` | bool | H, B | Enable QUIC multiplexing transport | `TunnelBehaviour` |
| `mux-tcp-connections` | int | H, B | Max concurrent Mux TCP connections | `TunnelBehaviour` |
| `mux-xudp-connections` | int | H, B | Max concurrent Mux XUDP connections | `TunnelBehaviour` |
| `new-domain` | string | H, B | Migrate subscription domain/authority | `TrustBoundary` |
| `new-url` | string | H, B | Replace subscription URL permanently | `TrustBoundary` |
| `noises-delay` | string | H, B | Noise packet delay | `TunnelBehaviour` |
| `noises-enable` | bool | H, B | Enable traffic noise padding | `TunnelBehaviour` |
| `noises-packet` | string | H, B | Noise packet size specification | `TunnelBehaviour` |
| `noises-packet-type` | string | H, B | Noise packet structure type | `TunnelBehaviour` |
| `noises-rand` | string | H, B | Random noise mode | `TunnelBehaviour` |
| `noises-rand-range` | string | H, B | Random noise packet size range | `TunnelBehaviour` |
| `notification-subs-expire` | bool | H, B | Trigger OS notifications prior to expiry | `Schedule` |
| `per-app-proxy-list` | string | H, B | Comma-delimited list of package IDs | `TrustBoundary` |
| `per-app-proxy-list-invert` | bool | H, B | Invert app list (bypass vs route) | `TrustBoundary` |
| `per-app-proxy-list-set` | bool | H, B | Force overwrite local per-app proxy list | `TrustBoundary` |
| `per-app-proxy-mode` | enum | H, B | Per-app mode (`include`, `exclude`, `all`) | `TrustBoundary` |
| `ping-result` | string | H, B | Seed server ping measurements | `Ignored` |
| `ping-type` | enum | H, B | Ping mechanism (`tcp`, `icmp`, `http`) | `TunnelBehaviour` |
| `preferred-ip-type` | enum | H, B | Preferred IP version (`ipv4`, `ipv6`, `auto`) | `TunnelBehaviour` |
| `profile-title` | string | H, B | User-visible subscription title (max 25 chars) | `Display` |
| `profile-update-interval` | int | H, B | Auto-update interval in hours (1..730) | `Schedule` |
| `profile-web-page-url` | string | H, B | Provider management web dashboard URL | `Display` |
| `providerid` | string | H, B | 8-character provider identifier | `DeviceIdentity` |
| `proxy-ping-mode` | enum | H, B | Latency measurement strategy | `TunnelBehaviour` |
| `proxy-ping-timeout` | int | H, B | Ping probe timeout (seconds) | `TunnelBehaviour` |
| `reset` | bool | URL fragment | Read by the provider extra-check path; effect unknown ([above](#precedence-and-refresh-merge)) | `Ignored` |
| `resolve-address` | string | H, B | Custom DNS server for endpoint resolution | `TrustBoundary` |
| `server-address-resolve-dns-domain` | string | H, B | Domain for DNS-over-HTTPS endpoint lookup | `TrustBoundary` |
| `server-address-resolve-dns-ip` | string | H, B | IP address of DoH endpoint | `TrustBoundary` |
| `server-address-resolve-enable` | bool | H, B | Enable custom DNS server resolution | `TrustBoundary` |
| `routing` | string | H, B | Embedded routing deeplink or JSON payload | `TrustBoundary` |
| `routing-enable` | bool | H, B | Force-enable routing profile on import | `TrustBoundary` |
| `sniffing-enable` | bool | H, B | Enable inbound protocol/domain sniffing | `TunnelBehaviour` |
| `socks-auth-mode` | enum | H, B | Inbound SOCKS proxy authentication mode | `TrustBoundary` |
| `socks-auth-password` | string | H, B | Inbound SOCKS proxy password | `TrustBoundary` |
| `socks-auth-user` | string | H, B | Inbound SOCKS proxy username | `TrustBoundary` |
| `subscriptions-collapse` | bool | H, B | Collapse subscription group in UI list | `Schedule` |
| `subscriptions-expand-now` | bool | H, B | Expand subscription group in UI list | `Schedule` |
| `subscriptions-sort-type` | enum | H, B | Sort order for server list in UI | `Schedule` |
| `subscription-always-hwid-enable` | bool | H, B | Force HWID sending on every request | `DeviceIdentity` |
| `subscription-autoconnect` | bool | H, B | Connect automatically after a refresh | `TrustBoundary` |
| `subscription-autoconnect-type` | enum | H, B | Target node selection for autoconnect | `TrustBoundary` |
| `subscription-auto-update-open-enable` | bool | H, B | Trigger refresh when application opens | `Schedule` |
| `subscription-hwid-in-cookie-enable` | bool | H, B | Transmit HWID inside HTTP Cookie header | `DeviceIdentity` |
| `subscription-pin` | bool | H, B | Pin subscription to top of UI list | `Schedule` |
| `subscription-ping-onopen-enabled` | bool | H, B | Probe server latency on app launch | `Schedule` |
| `subscription-request-timeout` | int | H, B | HTTP fetch timeout in seconds (5..15) | `Schedule` |
| `subscription-send-hwid-enabled` | bool | H, B | Transmit `X-HWID` HTTP header | `DeviceIdentity` |
| `subscription-sort-type` | enum | H, B | Server sorting configuration | `Schedule` |
| `subscription-userinfo` | string | H, B | Traffic quota and expiry, see below | `Display` |
| `sub-expire` | bool | H, B | Flag indicating subscription is expired | `Display` |
| `sub-expire-button-link` | string | H, B | Renewal URL for expired subscription | `Display` |
| `sub-info-button-link` | string | H, B | Action link for subscription detail button | `Display` |
| `sub-info-button-text` | string | H, B | Label for subscription detail button (max 25) | `Display` |
| `sub-info-color` | enum | H, B | UI badge color: `red`, `blue`, `green` | `Display` |
| `sub-info-text` | string | H, B | Informational banner text (max 200 chars) | `Display` |
| `support-url` | string | H, B | Provider technical support contact URL | `Display` |
| `user-agent-geo-files` | string | H, B | Custom User-Agent for routing geofile downloads | `TrustBoundary` |
| `xray-tun-enable` | bool | H, B | Force Xray TUN device capture | `TrustBoundary` |
| `xray-tun-mtu` | int | H, B | MTU size for TUN interface | `TrustBoundary` |

## Confidence and open questions

All keys except `ping-result` and `reset` are **DOCUMENTED**. `profile-title` with `base64:`, `profile-update-interval`, `support-url`, `profile-web-page-url`, `subscription-userinfo`, `announce` and `routing` are **VERIFIED** as headers on a live provider; the provider sent the same six keys to every client and added `routing` only for `User-Agent`s starting with `Happ` (live probe, 2026-10-12). Body directives, body-over-header precedence and the refresh merge are **VERIFIED** against Happ 4.7.1 with a mock server (on-device mock, 2026-10-12); no live provider sent body directives.

Open questions:

- `ResetInfo`: the value `0` clears seven sticky keys according to the code; this was not observed.
- What `reset` does in the extra-check path is **UNKNOWN**.
- Which update paths run the refresh merge without dropping absent keys is **UNKNOWN**.
- The meaning of `ping-result` is **UNKNOWN**: it is in `lw2`, but not documented and not observed.
- Exact value grammars of the `fragmentation-*`, `noises-*` and `per-app-proxy-*` keys are **DOCUMENTED** only and were not checked against live samples.
