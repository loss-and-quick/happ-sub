# Subscription body

This document covers the plaintext body, after any body decryption ([04](04-body-encryption.md)). The body importer is `j43.a(…)`, reached from `g92.h()` and `e53.b()`.

## Detection cascade

```
body text (UTF-8)
  │
  ├─ 1. extract `#key: value` directive lines and `happ://routing/` lines
  │
  ├─ 2. remaining text is Base64 that decodes to UTF-8 containing "://"?
  │        yes → decode once, then repeat step 1 on the decoded text
  │
  ├─ 3. first non-whitespace character
  │        '[' → JSON array of server configurations
  │        '{' → single JSON configuration (custom config)
  │
  └─ 4. otherwise → newline-separated share links, one per non-empty line
```

1. **Directives.** A line of the form `#<key>: <value>` (the space after `:` is optional) is a meta directive ([03](03-meta-protocol.md)) and is removed from the body. Happ's grammar is `^#([a-z0-9-]+)\s*:\s*(.*)$` (`MetaParams.Companion.a(List, boolean)`, merged in `pc6.java`). Any other line starting with `#`, such as `# servers below` or `#Not-A-Key value`, is dropped silently by Happ and by the crate (**VERIFIED**, on-device mock, 2026-10-12). A line starting with `happ://routing/` is a routing deeplink ([06](06-deeplinks-and-routing.md)) and is also removed (**VERIFIED**, on-device mock: handed to `ng6.s()` / `ut2.h()` instead of the link parser); one that fails to decode is reported as `Warning::InvalidRouting` instead of failing the import.
2. **Whole-body Base64.** If what remains is Base64 whose decoding is UTF-8 text containing `://`, the decoded text replaces the body. Only one level is unwrapped (**VERIFIED**: the batch → Base64-decode → batch → single-config sequence in `j43.smali`; the live fixtures, each a single padded Base64 line). Happ imports standard Base64 padded, unpadded and wrapped at 76 columns, but mis-decodes the URL-safe alphabet: the first `-` ends up inside a garbage server name and the remaining links are lost, while the import is reported as successful (**VERIFIED**, on-device mock, 2026-10-12). The crate decodes both alphabets, with or without padding and line wrapping, as a deliberate superset: a provider emitting URL-safe Base64 meant a link list, not one broken server. Directives and routing lines inside the decoded text are extracted the same way as in step 1. This is the v2rayN-style form.
3. **JSON.** A body starting with `[` is an array of server configurations (`CustomConfigImportResult(isArray=true)`, `b71.java`); a body starting with `{` is one configuration. Happ imports each configuration as an `EConfigType.CUSTOM` server named after its `remarks` and passes it to Xray as is (`ut2.a()`; **VERIFIED**, on-device mock, 2026-10-12; the JSON form is **DOCUMENTED** in [Routing](https://www.happ.su/main/dev-docs/routing)). Happ accepts a JSON object without an `outbounds` array, and an array in which some elements have none, importing every element (**VERIFIED**, on-device mock). The crate is stricter on purpose: a configuration without `outbounds` cannot route traffic, so it rejects such an object with `InvalidServer` and such an array with `InvalidJsonArray`. Routing restrictions for JSON bodies are in [06](06-deeplinks-and-routing.md#json-subscriptions).
4. **Links.** Lines are split on `\n` or `\r\n` and trimmed; empty lines are skipped. Each line is a share link `<scheme>://…`, dispatched by `startsWith("<scheme>://")` over `EConfigType` (**VERIFIED**: `dto/enums/EConfigType.java`; live provider and on-device mock). Happ skips a line that is not a link silently, and imports a malformed link such as `vless://not-a-valid@@link` as a broken server with port `-1`, without an error (**VERIFIED**, on-device mock, 2026-10-12). The crate skips a line without a `<scheme>://` prefix and reports it as `Warning::SkippedLine`, and passes every `<scheme>://` line through verbatim, so a malformed link reaches the caller's link parser. A body in which no line is a link is "Unknown content type" in both: Happ then removes the subscription's servers but keeps the subscription (**VERIFIED**, on-device mock).

### JSON flavour

The crate returns a single JSON object as `Payload::XrayJson` or `Payload::SingBoxJson`. Xray names the kind of an outbound `protocol`; sing-box names it `type`. The object is `SingBoxJson` when its `outbounds` array is non-empty and every element has `type` and no `protocol`; otherwise, including an empty or mixed array, it is `XrayJson`, which is how Happ reads every JSON configuration. Live providers serve full sing-box configurations to sing-box and Hiddify clients ([below](#live-provider-behaviour)); Happ would import one as an Xray custom config that cannot run. The crate differs on purpose so a client with both cores can run it. A JSON array is always `Payload::JsonArray` of Xray configurations: arrays are Happ's own convention and no provider was seen serving sing-box configurations that way.

The crate returns the result as `Payload::JsonArray`, `Payload::XrayJson`, `Payload::SingBoxJson` or `Payload::Links`. Links are passed through verbatim. Skipped items are listed in `Parsed::warnings`.

## Share links

The crate does not parse share links; the caller does. Happ has one parser class per `EConfigType`; each class's `g(ServerConfig)` method is the matching exporter (**INFERRED**, all rows):

| Scheme | Parser | Forms | Notes |
|---|---|---|---|
| `vmess://` | `mx6` | `vmess://<base64 VmessQRCode JSON>` (`mx6.java:23`); `vmess://<net>[+tls]:<uuid>@<host>:<port>?<query>#<name>` (`mx6.java:54`) | JSON fields: `add`, `port`, `id`, `aid`, `net`, `type`, `host`, `path`, `tls`, `sni`, `alpn`, `fp`, `scy`, `ps`, `pcs`, `pcn`, `vcn`, `fragment`, `noises`, `advancedFragment`, `serverDescription`, `security`. Happ always exports the Base64 JSON form. |
| `vless://` | `lx6` | `vless://<uuid>@<host>:<port>?<query>#<name>` (`lx6.java:18`) | Query keys `encryption` (default `none`), `flow` (dropped when `encryption=none`), `security` (default `tls`), `sni`, `alpn`, `fp`, `pbk`, `sid`, `spx`, `pqv`, `pcs`, `pcn`/`vcn`, `ech`, `type`, `headerType`, `path`, `host`, `serviceName`, `authority`, `mtu`, `fm`. |
| `trojan://` | `kx6` | `trojan://<password>@<host>:<port>?<query>#<name>` (`kx6.java:16`) | Same query keys as VLESS; `security` defaults to `tls`. |
| `ss://` | `ix6` | SIP002 `ss://<method>:<password>@<host>:<port>?<query>#<name>` (`ix6.java:22`); legacy `ss://<base64(method:password)>@<host>:<port>#<name>` (`ix6.java:45`) | Query keys `plugin`, `obfs`, `obfs-host`, `path`, `tls`, `pcs`, `pcn`, `vcn`, `fm`. Exported as SIP002. |
| `socks://` | `jx6` | `socks://[<user>:<password>@]<host>:<port>#<name>` (`jx6.java:14`) | Userinfo may be Base64. |
| `hysteria2://`, `hy2://` | `hx6` | `hysteria2://<auth>@<host>:<port>?<query>#<name>` (`hx6.java:19`) | Query keys `uit`, `mport`, `mportHopInt`, `security`, `sni`, `pcs`, `pcn`/`vcn`, `obfs-password`. `xray-extra-params` is ignored ([below](#live-provider-behaviour)). |
| `wireguard://` | `nx6` | `wireguard://<private key>@<host>:<port>?<query>#<name>` (`nx6.java:21`) | Query keys `address` (default `172.16.0.2/32`), `publickey`, `presharedkey`, `mtu` (default `1420`), `reserved` (default `0,0,0`). |

Happ-specific additions on top of the common grammars:

- `pcs=<64 hex>` becomes `tlsSettings.pinnedPeerCertSha256`, and `pcn` or `vcn` becomes `tlsSettings.verifyPeerCertByName`. Both apply only with `security=tls`; with `security=none` they are dropped (**VERIFIED**, on-device mock, 2026-10-12).
- `fm` is recognised and written to `streamSettings.finalmask`. Its payload is URL-encoded `FinalMaskBean` JSON with extra fragmentation and noise settings; a `{"fragment":…}` payload that did not match the bean became `{}` (on-device mock, 2026-10-12). The grammar is **UNKNOWN**.
- The `#<name>` fragment may carry `?serverDescription=<base64>` after the display name. The decoded text is stored in `ServerConfig.meta.serverDescription` and not shown in the server list; the rest of the fragment, URL-decoded, is the display name, and anything after a following `&` is ignored (**VERIFIED**, on-device mock, 2026-10-12; `gx6.h` / `gx6.i`, regex `.*#.+serverDescription=([^&,#]+)&?` in `q56.java`).

The decompiled classes `bs0` and `ea4` look like parsers for `ssa://`, `ssh://` and similar schemes but are not: they are ISO 639 / ISO 15924 language tables (`ea4.java:1025` maps `"ssh"` → `"Arab"`). Happ has exactly the seven schemes above plus `CUSTOM`.

## Live provider behaviour

One live provider was fetched with 15 `User-Agent` and URL variants on 2026-10-12 ([10](10-verification.md#method-live-provider-probe)). Redacted responses are in [`tests/fixtures/live-2026-10-12/`](../tests/fixtures/live-2026-10-12/). All facts below are **VERIFIED** (live probe, 2026-10-12) for that provider; other panels may differ.

- **Format by `User-Agent`.** Clash and mihomo clients got Clash YAML (`text/yaml`), sing-box and Hiddify got a full sing-box configuration (`application/json`), every other client, including Happ, v2rayNG, v2rayN, Streisand, curl, a browser and an empty `User-Agent`, got a whole-body Base64 link list (`text/plain`). No variant produced Xray JSON. Happ cannot import YAML; neither can the crate (`UnknownContentType`). The YAML and sing-box forms lacked four servers present in the link list: the three Shadowsocks links and the IPv6 VLESS server.
- **Randomisation.** Every request returned the links in a different order, and on 24 of 26 VLESS links the REALITY `sni` (a random label under a fixed domain) and `sid` (drawn from a pool) changed, while hosts, ports, keys and UUIDs stayed. A client that identifies servers by their full URI sees a new set on every refresh; match servers by host, port and credentials instead ([07](07-fetch-and-update.md#applying-servers)).
- **Bare IPv6 host.** One VLESS link has the form `vless://<uuid>@2001:db8::4:8443?…`, with no brackets around the IPv6 address; the port is what follows the last `:`. The crate passes it through; the caller's VLESS parser has to accept it.
- **`xray-extra-params`.** Hysteria2 links carry `xray-extra-params=<base64 JSON>`, for example `{"finalmask":{"quicParams":{"debug":false,"congestion":"bbr"}},"fingerprint":"firefox"}`. Happ's `hx6` ignores the parameter.
- **Shadowsocks.** SIP002 with unpadded Base64 userinfo.
- **Absent features.** No body directives, no `happ://routing/` body lines, no `serverDescription`, no `pcs`/`pcn`/`vcn`/`fm`, no keys outside `meta::KNOWN_KEYS`.

## Rejections

| Condition | Happ 4.7.1 | Crate |
|---|---|---|
| Empty body (`200`, 0 bytes) | Success with zero servers, `lastUpdated: -1` (**VERIFIED**, on-device mock). "The clipboard is empty" (`parsing_error_empty_clipboard`) is the clipboard import path | `Error::EmptyBody`: an empty answer is more likely a provider fault than an intentionally empty subscription |
| A line that is not a link | Skipped silently | Skipped, `Warning::SkippedLine` |
| A malformed `<scheme>://` link | Imported as a broken server | Passed through in `Payload::Links` |
| A JSON object without `outbounds` | Imported as `CUSTOM` | `Error::InvalidServer` |
| A JSON array element without `outbounds` | All elements imported | `Error::InvalidJsonArray` |
| A JSON object or array that does not parse | "Configuration %s is not valid" (`parsing_error_invalid_server`) / "Array of JSON configurations is not valid" (`parsing_error_invalid_array_json_server`) (**INFERRED**) | `Error::InvalidServer` / `Error::InvalidJsonArray` |
| Routing payload is corrupt | "Wrong data for import routing profile" (`parsing_error_invalid_routing`) (**INFERRED**) | `Error::InvalidRouting` from `deeplink::parse_deeplink`; inside a subscription `Warning::InvalidRouting` and the profile is skipped |
| No line is a share link, or the body matches no form | "Unknown content type" (`parsing_error_invalid_unknown_content_type`); servers removed, subscription kept (**VERIFIED**, on-device mock) | `Error::UnknownContentType` |

The messages are the English string resources of 4.7.1 (**VERIFIED** against `res/values/strings.xml`).

## Confidence and open questions

The whole-body Base64 form with a plain link list is **VERIFIED** on a live provider and on a device. Directive lines, routing lines, JSON arrays, single JSON configurations, `serverDescription` and `pcs`/`pcn`/`vcn` are **VERIFIED** against Happ 4.7.1 with a mock server; no live provider sent any of them. The other per-scheme grammars are **INFERRED**.

Open questions:

- The `fm` (`FinalMaskBean`) grammar is **UNKNOWN**.
- Whether every exported link re-imports byte for byte is **UNKNOWN**. The parsers are asymmetric (lenient import, canonical export), which does not matter for an importer.
