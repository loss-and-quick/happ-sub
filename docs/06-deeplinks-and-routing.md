# Deeplinks and routing profiles

## `happ://` deeplinks

Happ accepts `happ://` URIs from the system (links, QR codes, clipboard) and, for routing, from subscription headers and bodies. Android intent filters route the scheme to `DeeplinkInterceptorActivity` (`AndroidManifest.xml`); `qc1.b` matches the text after `happ://` against the prefixes of `EDeeplinkType` (`dto/enums/EDeeplinkType.java`) with `startsWith`, and when several match it picks the `_without_ui` one (**INFERRED**). The crate parses them with `deeplink::parse_deeplink` into a `Deeplink` value.

| URI | Action | `Deeplink` variant |
|---|---|---|
| `happ://add/<url>` | Import `<url>` as a subscription or server | `Add` |
| `happ://routing/add/<base64 JSON>` | Add a routing profile ([below](#add-and-onadd)) | `Routing(Add)` |
| `happ://routing/onadd/<base64 JSON>` | Add a routing profile and activate it | `Routing(OnAdd)` |
| `happ://routing/off` | Turn routing off (all traffic through the proxy) | `Routing(Off)` |
| `happ://crypt/<payload>` … `happ://crypt5/<payload>` | Decrypt the URL ([05](05-url-encryption.md)) and import it | `Crypt { version: 1..=5 }` |
| `happ://send_to_device/<id>` | Fetch a configuration pushed from another device through the vendor's cloud service | `SendToDevice` |
| `happ://toggle`, `happ://connect`, `happ://disconnect` | Tunnel control | `Toggle`, `Connect`, `Disconnect` |
| `happ://toggle_without_ui`, `happ://connect_without_ui`, `happ://disconnect_without_ui` | Same, without bringing up the UI | same, `without_ui: true` |
| `happ://open`, `happ://close` | Open or close the UI | `Open`, `Close` |
| `happ://open_without_ui`, `happ://close_without_ui` | Same, without bringing up the UI | same, `without_ui: true` |

`EDeeplinkType` defines exactly these prefixes (**VERIFIED** against the string constants of `EDeeplinkType` in 4.7.1).

`send_to_device` looks up a record in Apple CloudKit and imports the URL it returns (`d03.java:39`, [08](08-device-binding.md#vendor-services)); it depends on the vendor's backend and is not interoperable; a third-party client should treat it as unsupported. Tunnel-control deeplinks can be triggered by any app or web page, so a client should confirm them or restrict where they are accepted.

Happ reports a malformed deeplink as "The subscription URL is not valid" (`parsing_error_invalid_deeplink`) and an unknown action as "Unknown deepLink action" (`parsing_error_unknown_deeplink`) (crate: `Error::InvalidDeeplink`, `Error::UnknownDeeplink`).

## Routing profile delivery

A routing profile reaches the client in one of three ways:

1. The `routing` response header, whose value is a routing deeplink (**VERIFIED**: live provider, read through `lw2`; on-device mock, 2026-10-12):
   ```http
   routing: happ://routing/onadd/eyJOYW1lIjoiRVhBTVBMRS1ST1VUSU5HIiwiRGlyZWN0U2l0ZXMiOltdLCJEaXJlY3RJcCI6W119
   ```
   The live provider sent this header only to `User-Agent`s starting with `Happ`; `Happ/4.7.1` alone was enough (live probe, 2026-10-12).
2. A body line with the same deeplink. It is removed from the body before link parsing and handed to `ng6.s()` ([02](02-subscription-body.md); **VERIFIED**, on-device mock).
3. A deeplink opened by the user.

Happ keeps the header value in the subscription's metadata, so it follows the refresh merge ([03](03-meta-protocol.md#precedence-and-refresh-merge)); body routing lines are not stored in the metadata (on-device mock).

`parse` returns every routing deeplink of a response in `Parsed::routing` as a `RoutingAction`, body lines first in body order, then the header: `Add` and `OnAdd` carry the decoded profile, and `Off` is reported too. A header or body deeplink that fails to decode becomes `Warning::InvalidRouting` and the rest of the subscription still imports.

The payload above decodes to:

```json
{"Name":"EXAMPLE-ROUTING","DirectSites":[],"DirectIp":[]}
```

The `routing` key is `TrustBoundary` in the crate's classification ([03](03-meta-protocol.md#risk-classes)).

### What Happ does with a delivered profile

Observed on Happ 4.7.1 (**VERIFIED**, on-device mock, 2026-10-12):

- **Per subscription.** A routing profile is bound to the subscription that delivered it (`subId`). Each subscription has its own routing switch (`SUB_ROUTING_ENABLED`) and a user setting to ignore routing imports from it.
- **Defaults.** Fields the profile omits get Happ's defaults: DoH remote DNS, Happ's `DnsHosts`, `RouteOrder: BLOCK_DIRECT_PROXY`, and the Loyalsoldier `geoip.dat` / `geosite.dat` download URLs on GitHub.
- **Geo files.** Every imported profile triggered a 15.8 MB geo-file download from GitHub, even when it carried no geo rules.
- **`happ://routing/off`** in a body: the line is removed, no profile is created, the rest of the body (one server in the test) imports normally, and that subscription's routing switch is turned off and greyed out; other subscriptions are unaffected.

### `add` and `onadd`

The vendor documentation says `onadd` activates the profile immediately and `add` stores it inactive until its geo files are downloaded (**DOCUMENTED** in [Routing](https://www.happ.su/main/dev-docs/routing)). On the device, `add` and `onadd`, delivered in a header or a body line, all produced the same result on a subscription without a previous profile: the profile was selected (`isSelected: true`) and the subscription's routing was enabled. No difference was observable. The crate keeps the two apart (`RoutingAction::Add` / `RoutingAction::OnAdd`) because they differ on the wire; a client that follows Happ treats both as "add and activate".

## Routing profile JSON

The payload is standard Base64 of a UTF-8 JSON object. Field names are PascalCase (**DOCUMENTED** in [Routing](https://www.happ.su/main/dev-docs/routing); the vendor's own generator, [`Happ-proxy/routing_generator`](https://github.com/Happ-proxy/routing_generator), emits the same fields). `Name` is required by the crate's decoder (`routing::RoutingProfile`); every other field is optional.

| Field | Type | Meaning |
|---|---|---|
| `Name` | string | Profile name |
| `GlobalProxy` | bool | Ignore the rules and send everything through the proxy |
| `RemoteDNSType` | string | Remote DNS protocol: `tcp`, `udp`, `doh`, `dot` |
| `RemoteDNSDomain` | string | Remote DNS server name or URL |
| `RemoteDNSIP` | string | Remote DNS server IP |
| `DomesticDNSType` | string | Direct DNS protocol |
| `DomesticDNSDomain` | string | Direct DNS server name or URL |
| `DomesticDNSIP` | string | Direct DNS server IP |
| `Geoipurl` | string | URL of a `geoip.dat` to download |
| `Geositeurl` | string | URL of a `geosite.dat` to download |
| `LastUpdated` | integer | Modification timestamp (seconds or milliseconds) |
| `DnsHosts` | object | Static `{"domain": "ip"}` overrides |
| `DirectSites` | string[] | Domain rules sent direct |
| `DirectIp` | string[] | IP/CIDR rules sent direct |
| `ProxySites` | string[] | Domain rules sent through the proxy |
| `ProxyIp` | string[] | IP/CIDR rules sent through the proxy |
| `BlockSites` | string[] | Domain rules blocked |
| `BlockIp` | string[] | IP/CIDR rules blocked |
| `DomainStrategy` | string | Xray `domainStrategy`: `AsIs`, `IPIfNonMatch`, `IPOnDemand` |
| `FakeDNS` | bool | Enable FakeDNS |

Rule strings use Xray routing syntax (`geosite:…`, `geoip:…`, `domain:…`, CIDRs). Happ downloads geo files from `Geoipurl` / `Geositeurl` at most once every 7 days.

## JSON subscriptions

When the body is a JSON array or a full Xray configuration ([02](02-subscription-body.md)), the configuration carries its own routing. Happ then allows at most one routing profile, does not let the user switch between profiles, and locks editing of geo rules, to avoid conflicting with the routing inside the configuration (**DOCUMENTED** in [Routing](https://www.happ.su/main/dev-docs/routing); the lock is the string resource `routing_profile_json_restrict_geo_edit`).

## Confidence and open questions

The `routing` header with an `onadd` deeplink is **VERIFIED** on a live provider. Header and body delivery, `add`, `onadd` and `off`, per-subscription binding and the defaults for omitted fields are **VERIFIED** against Happ 4.7.1 with a mock server. The JSON schema, the 7-day geo-file interval and the JSON-subscription restrictions are **DOCUMENTED**. The deeplink prefixes are **VERIFIED** against `EDeeplinkType`; the dispatch is **INFERRED** from `qc1`. Profiles that use most schema fields were not observed live.

Open questions:

- Whether `add` and `onadd` differ on a subscription that already has an active profile is **UNKNOWN**.
- Whether `LastUpdated` is in seconds or milliseconds is **UNKNOWN**.
