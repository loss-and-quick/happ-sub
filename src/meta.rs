//! Subscription metadata protocol: dual transport, key classification, merge rules.
//!
//! Happ delivers subscription configuration via two simultaneous transports (a third, the
//! subscription URL fragment, is left to the caller):
//! 1. HTTP response headers (case-insensitive names)
//! 2. Subscription body directives (`#key: value`)
//!
//! When both carry a key, **the body directive wins**. Values may be raw strings or Base64
//! prefixed with `base64:`.
//!
//! # Policy Model
//! Provider directives can reconfigure the client's network boundaries, so this module never
//! applies them: it classifies every key into a [`RiskClass`] tier and exports
//! [`ProposedChange`] descriptors for the caller's UI or policy engine.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;

/// Risk classification tier for metadata directives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    /// Safe display elements: labels, announcements, user quotas, web pages.
    Display,
    /// Client operational schedules: update intervals and timeouts with bounds clamping.
    Schedule,
    /// Transport shaping parameters: mux, fragmentation, noises, sniffing.
    TunnelBehaviour,
    /// Critical security/routing boundaries: alternative URLs, routing profiles, per-app proxying.
    ///
    /// Requires explicit per-subscription user consent.
    TrustBoundary,
    /// Hardware/installation telemetry tokens: ignored by default for user privacy.
    DeviceIdentity,
    /// Diagnostic measurements, vendor telemetry knobs and unknown keys: safely ignored.
    Ignored,
}

/// Every metadata key Happ recognises, with its risk tier.
///
/// This table is the single source for both [`classify_key`] and the header filter in
/// [`parse_headers`].
pub const KNOWN_KEYS: &[(&str, RiskClass)] = &[
    ("profile-title", RiskClass::Display),
    ("announce", RiskClass::Display),
    ("subscription-userinfo", RiskClass::Display),
    ("support-url", RiskClass::Display),
    ("profile-web-page-url", RiskClass::Display),
    ("sub-info-button-link", RiskClass::Display),
    ("sub-info-button-text", RiskClass::Display),
    ("sub-info-color", RiskClass::Display),
    ("sub-info-text", RiskClass::Display),
    ("sub-expire", RiskClass::Display),
    ("sub-expire-button-link", RiskClass::Display),
    ("profile-update-interval", RiskClass::Schedule),
    ("subscription-request-timeout", RiskClass::Schedule),
    ("subscription-auto-update-open-enable", RiskClass::Schedule),
    ("notification-subs-expire", RiskClass::Schedule),
    ("subscriptions-sort-type", RiskClass::Schedule),
    ("subscription-sort-type", RiskClass::Schedule),
    ("subscriptions-collapse", RiskClass::Schedule),
    ("subscriptions-expand-now", RiskClass::Schedule),
    ("subscription-pin", RiskClass::Schedule),
    ("subscription-ping-onopen-enabled", RiskClass::Schedule),
    ("fallback-url", RiskClass::TrustBoundary),
    ("new-url", RiskClass::TrustBoundary),
    ("new-domain", RiskClass::TrustBoundary),
    ("change-user-agent", RiskClass::TrustBoundary),
    ("manual-block-user-agent", RiskClass::TrustBoundary),
    ("insecure", RiskClass::TrustBoundary),
    ("routing-enable", RiskClass::TrustBoundary),
    ("routing", RiskClass::TrustBoundary),
    ("per-app-proxy-list", RiskClass::TrustBoundary),
    ("per-app-proxy-list-invert", RiskClass::TrustBoundary),
    ("per-app-proxy-list-set", RiskClass::TrustBoundary),
    ("per-app-proxy-mode", RiskClass::TrustBoundary),
    ("exclude-routes", RiskClass::TrustBoundary),
    ("exclude-routes-set", RiskClass::TrustBoundary),
    ("dns-from-json-enable", RiskClass::TrustBoundary),
    ("local-dns-enable", RiskClass::TrustBoundary),
    ("resolve-address", RiskClass::TrustBoundary),
    (
        "server-address-resolve-dns-domain",
        RiskClass::TrustBoundary,
    ),
    ("server-address-resolve-dns-ip", RiskClass::TrustBoundary),
    ("server-address-resolve-enable", RiskClass::TrustBoundary),
    ("inbound-http-enable", RiskClass::TrustBoundary),
    ("http-auth-mode", RiskClass::TrustBoundary),
    ("http-auth-password", RiskClass::TrustBoundary),
    ("http-auth-user", RiskClass::TrustBoundary),
    ("socks-auth-mode", RiskClass::TrustBoundary),
    ("socks-auth-password", RiskClass::TrustBoundary),
    ("socks-auth-user", RiskClass::TrustBoundary),
    ("xray-tun-enable", RiskClass::TrustBoundary),
    ("xray-tun-mtu", RiskClass::TrustBoundary),
    ("app-auto-start", RiskClass::TrustBoundary),
    ("subscription-autoconnect", RiskClass::TrustBoundary),
    ("subscription-autoconnect-type", RiskClass::TrustBoundary),
    ("hide-settings", RiskClass::TrustBoundary),
    ("check-url-via-proxy", RiskClass::TrustBoundary),
    ("block-bind-to-tunnel-enable", RiskClass::TrustBoundary),
    ("host", RiskClass::TrustBoundary),
    ("dont-use-filter", RiskClass::TrustBoundary),
    ("user-agent-geo-files", RiskClass::TrustBoundary),
    ("mux-enable", RiskClass::TunnelBehaviour),
    ("mux-quic", RiskClass::TunnelBehaviour),
    ("mux-tcp-connections", RiskClass::TunnelBehaviour),
    ("mux-xudp-connections", RiskClass::TunnelBehaviour),
    ("fragment", RiskClass::TunnelBehaviour),
    ("fragmentation-advanced-param", RiskClass::TunnelBehaviour),
    ("fragmentation-delay", RiskClass::TunnelBehaviour),
    ("fragmentation-enable", RiskClass::TunnelBehaviour),
    ("fragmentation-interval", RiskClass::TunnelBehaviour),
    ("fragmentation-length", RiskClass::TunnelBehaviour),
    ("fragmentation-maxsplit", RiskClass::TunnelBehaviour),
    ("fragmentation-packets", RiskClass::TunnelBehaviour),
    ("fragmentation-type", RiskClass::TunnelBehaviour),
    ("noises-delay", RiskClass::TunnelBehaviour),
    ("noises-enable", RiskClass::TunnelBehaviour),
    ("noises-packet", RiskClass::TunnelBehaviour),
    ("noises-packet-type", RiskClass::TunnelBehaviour),
    ("noises-rand", RiskClass::TunnelBehaviour),
    ("noises-rand-range", RiskClass::TunnelBehaviour),
    ("sniffing-enable", RiskClass::TunnelBehaviour),
    ("preferred-ip-type", RiskClass::TunnelBehaviour),
    ("proxy-ping-mode", RiskClass::TunnelBehaviour),
    ("proxy-ping-timeout", RiskClass::TunnelBehaviour),
    ("ping-type", RiskClass::TunnelBehaviour),
    ("providerid", RiskClass::DeviceIdentity),
    ("installid", RiskClass::DeviceIdentity),
    // Travels as a subscription URL query parameter, never as a header.
    ("hwidlink", RiskClass::DeviceIdentity),
    ("subscription-send-hwid-enabled", RiskClass::DeviceIdentity),
    ("subscription-always-hwid-enable", RiskClass::DeviceIdentity),
    (
        "subscription-hwid-in-cookie-enable",
        RiskClass::DeviceIdentity,
    ),
    ("ping-result", RiskClass::Ignored),
    // Read only from the subscription URL fragment, by Happ's provider extra-check path.
    ("reset", RiskClass::Ignored),
];

/// Keys that travel in the subscription URL and that Happ never reads from a header.
const URL_ONLY_KEYS: [&str; 2] = ["hwidlink", "reset"];

/// Keys Happ keeps across a refresh when the new response omits them; every other key is
/// dropped (`MetaParams.Companion.c`).
pub const REFRESH_STICKY_KEYS: &[&str] = &[
    "installid",
    "sub-info-color",
    "sub-info-text",
    "sub-info-button-text",
    "sub-info-button-link",
    "sub-expire",
    "sub-expire-button-link",
    // Happ clears these when the provider sends the value `0`; the crate keeps `0` as a value.
    "fragment",
    "resolve-address",
    "host",
    "insecure",
    "providerid",
    "notification-subs-expire",
    "fallback-url",
];

/// A classified parameter change proposed by the subscription provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedChange {
    /// Normalized metadata parameter key (e.g. `"profile-title"`).
    pub key: String,
    /// Normalized parameter value with `base64:` prefix decoded.
    pub value: String,
    /// Security classification for policy gating.
    pub risk_class: RiskClass,
}

/// Resource and input bounds for subscription parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Maximum allowable raw body byte length.
    pub max_body_bytes: usize,
    /// Maximum allowable base64-decoded body byte length.
    pub max_decoded_bytes: usize,
    /// Maximum line count in a subscription payload.
    pub max_lines: usize,
    /// Maximum number of distinct metadata keys accepted per transport (headers, body).
    pub max_meta_keys: usize,
    /// Maximum length of an individual metadata value string.
    pub max_meta_value_len: usize,
    /// Maximum length of a `happ://routing/` deeplink, including its Base64 JSON payload.
    pub max_routing_json_bytes: usize,
    /// Maximum elements in a JSON server array.
    pub max_json_array_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 10 * 1024 * 1024,
            max_decoded_bytes: 10 * 1024 * 1024,
            max_lines: 50_000,
            max_meta_keys: 256,
            max_meta_value_len: 16_384,
            max_routing_json_bytes: 2 * 1024 * 1024,
            max_json_array_len: 10_000,
        }
    }
}

/// Structured subscription quota and expiration information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UserInfo {
    /// Bytes uploaded in current billing period.
    pub upload: u64,
    /// Bytes downloaded in current billing period.
    pub download: u64,
    /// Total quota allocation in bytes (0 if unmetered).
    pub total: u64,
    /// Expiration timestamp in seconds since UNIX epoch.
    pub expire: u64,
}

impl UserInfo {
    /// Parse `key=value` tokens separated by `;` or whitespace (`upload=0; download=0; ...`).
    ///
    /// Whitespace around `=` is tolerated (`upload = 1`).
    pub fn parse(s: &str) -> Option<Self> {
        let mut compact = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c.is_whitespace() {
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
                if chars.peek() == Some(&'=') || compact.ends_with('=') {
                    continue;
                }
            }
            compact.push(c);
        }

        let mut info = UserInfo::default();
        let mut found_any = false;
        for part in compact.split(|c: char| c == ';' || c.is_whitespace()) {
            let Some((k, v)) = part.split_once('=') else {
                continue;
            };
            let Ok(num) = v.parse::<u64>() else {
                continue;
            };
            let slot = match k.to_ascii_lowercase().as_str() {
                "upload" => &mut info.upload,
                "download" => &mut info.download,
                "total" => &mut info.total,
                "expire" => &mut info.expire,
                _ => continue,
            };
            *slot = num;
            found_any = true;
        }
        found_any.then_some(info)
    }
}

/// Normalizes text from untrusted subscription providers.
///
/// Strips unicode bidirectional override codepoints (which can visually mask URLs)
/// and carriage returns.
pub fn normalize_untrusted_text(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\r'
            )
        })
        .collect()
}

/// Validates whether an Android application package identifier follows reverse-DNS grammar.
pub fn validate_package_name(pkg: &str) -> bool {
    if pkg.is_empty() || pkg.len() > 128 {
        return false;
    }
    let parts: Vec<&str> = pkg.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().all(|part| {
        let mut chars = part.chars();
        match chars.next() {
            Some(first) if first.is_ascii_alphabetic() || first == '_' => {
                chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
            }
            _ => false,
        }
    })
}

/// Checks whether a provider-supplied URL is safe to contact: http(s) only, and no loopback,
/// private, link-local, CGNAT, multicast or unspecified literal address as the host.
///
/// Hostnames are not resolved, so this cannot catch DNS rebinding; re-check the resolved address.
pub fn validate_url_safety(url_str: &str, require_https: bool) -> Result<(), &'static str> {
    let (scheme, rest) = url_str
        .split_once("://")
        .ok_or("URL scheme must be http or https")?;
    match scheme.to_ascii_lowercase().as_str() {
        "https" => {}
        "http" if !require_https => {}
        _ if require_https => return Err("URL scheme must be https"),
        _ => return Err("URL scheme must be http or https"),
    }

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // WHATWG parsers end the authority at a backslash while RFC 3986 parsers do not, so the
    // two disagree on which side of an `@` is the host.
    if authority.contains('\\') {
        return Err("backslash in URL authority");
    }
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);

    if let Some(bracketed) = host_port.strip_prefix('[') {
        let (inner, after) = bracketed.split_once(']').ok_or("unterminated IPv6 host")?;
        check_port(after)?;
        let ip: Ipv6Addr = inner.parse().map_err(|_| "invalid IPv6 host")?;
        return check_ipv6(ip);
    }
    let (host, port_part) = host_port
        .find(':')
        .map_or((host_port, ""), |i| host_port.split_at(i));
    check_port(port_part)?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();

    if host.is_empty() {
        return Err("missing host");
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Err("localhost targets are rejected");
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return check_ipv4(ip);
    }
    // inet_aton accepts `127.1`, `0x7f.0.0.1` and `2130706433`; refuse every all-numeric host
    // that is not a canonical dotted quad rather than reimplementing those forms.
    if host.split('.').all(|label| match label.strip_prefix("0x") {
        Some(hex) => hex.chars().all(|c| c.is_ascii_hexdigit()),
        None => !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()),
    }) {
        return Err("non-canonical numeric host is rejected");
    }
    Ok(())
}

fn check_port(after_host: &str) -> Result<(), &'static str> {
    match after_host.strip_prefix(':') {
        None if after_host.is_empty() => Ok(()),
        Some(p) if p.is_empty() || p.parse::<u16>().is_ok() => Ok(()),
        _ => Err("invalid port"),
    }
}

fn check_ipv4(ip: Ipv4Addr) -> Result<(), &'static str> {
    let [a, b, ..] = ip.octets();
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || a >= 240
    {
        return Err("private, loopback or reserved IPv4 targets are rejected");
    }
    Ok(())
}

fn check_ipv6(ip: Ipv6Addr) -> Result<(), &'static str> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return check_ipv4(v4);
    }
    let first = ip.segments()[0];
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
    {
        return Err("private, loopback or reserved IPv6 targets are rejected");
    }
    Ok(())
}

/// Container for subscription metadata with case-insensitive key lookup.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MetaMap {
    entries: BTreeMap<String, String>,
}

impl MetaMap {
    /// Create an empty metadata map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a key-value pair, decoding any `base64:` prefix and normalizing the key.
    pub fn insert(&mut self, key: &str, raw_value: &str) {
        let key_norm = key.trim().to_ascii_lowercase();
        let clean_value = normalize_untrusted_text(&decode_value(raw_value));
        self.entries.insert(key_norm, clean_value);
    }

    /// Retrieve a metadata value by key name (case-insensitive).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .get(&key.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    /// Check if a key is present.
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(&key.to_ascii_lowercase())
    }

    /// Return the number of metadata directives stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the metadata map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all stored `(key, value)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Produce classified [`ProposedChange`] descriptors for all stored directives.
    pub fn proposed_changes(&self) -> Vec<ProposedChange> {
        self.entries
            .iter()
            .map(|(k, v)| ProposedChange {
                key: k.clone(),
                value: v.clone(),
                risk_class: classify_key(k),
            })
            .collect()
    }

    /// Collect directives matching a specific risk classification.
    pub fn by_risk(&self, risk: RiskClass) -> Vec<(&str, &str)> {
        self.iter()
            .filter(|(k, _)| classify_key(k) == risk)
            .collect()
    }

    /// Overlay already-normalized entries from `other`; its values win.
    pub(crate) fn overlay(&mut self, other: &MetaMap) {
        for (k, v) in &other.entries {
            self.entries.insert(k.clone(), v.clone());
        }
    }

    // ── Typed accessors ────────────────────────────────────────────────

    /// Subscription display title (`profile-title`); Happ truncates it to 25 characters.
    pub fn profile_title(&self) -> Option<&str> {
        self.get("profile-title")
    }

    /// Auto-update interval in hours (`profile-update-interval`), clamped to 1..=730.
    pub fn profile_update_interval(&self) -> Option<u32> {
        self.get("profile-update-interval")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .map(|h| h.clamp(1, 730))
    }

    /// Quota and billing information (`subscription-userinfo`).
    pub fn user_info(&self) -> Option<UserInfo> {
        self.get("subscription-userinfo").and_then(UserInfo::parse)
    }

    /// Provider technical support link (`support-url`).
    pub fn support_url(&self) -> Option<&str> {
        self.get("support-url")
    }

    /// Provider management web dashboard URL (`profile-web-page-url`).
    pub fn profile_web_page_url(&self) -> Option<&str> {
        self.get("profile-web-page-url")
    }

    /// Provider bulletin banner text (`announce`).
    pub fn announce(&self) -> Option<&str> {
        self.get("announce")
    }

    /// Routing profile deeplink (`routing`).
    pub fn routing(&self) -> Option<&str> {
        self.get("routing")
    }

    /// HTTP request fetch timeout in seconds (`subscription-request-timeout`), clamped 5..=15.
    pub fn subscription_request_timeout(&self) -> Option<u32> {
        self.get("subscription-request-timeout")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .map(|s| s.clamp(5, 15))
    }

    /// Secondary failover URL (`fallback-url`). Classified as [`RiskClass::TrustBoundary`].
    pub fn fallback_url(&self) -> Option<&str> {
        self.get("fallback-url")
    }

    /// Migration URL replacement (`new-url`). Classified as [`RiskClass::TrustBoundary`].
    pub fn new_url(&self) -> Option<&str> {
        self.get("new-url")
    }

    /// Migration domain replacement (`new-domain`). Classified as [`RiskClass::TrustBoundary`].
    pub fn new_domain(&self) -> Option<&str> {
        self.get("new-domain")
    }

    /// Informational detail banner text (`sub-info-text`).
    pub fn sub_info_text(&self) -> Option<&str> {
        self.get("sub-info-text")
    }

    /// Informational detail button label (`sub-info-button-text`).
    pub fn sub_info_button_text(&self) -> Option<&str> {
        self.get("sub-info-button-text")
    }

    /// Informational detail button link (`sub-info-button-link`).
    pub fn sub_info_button_link(&self) -> Option<&str> {
        self.get("sub-info-button-link")
    }

    /// Subscription expiration flag (`sub-expire`).
    pub fn sub_expire(&self) -> Option<bool> {
        self.get("sub-expire").map(parse_bool)
    }

    /// Expired subscription renewal URL (`sub-expire-button-link`).
    pub fn sub_expire_button_link(&self) -> Option<&str> {
        self.get("sub-expire-button-link")
    }
}

fn parse_bool(s: &str) -> bool {
    let s = s.trim();
    s.eq_ignore_ascii_case("true") || s == "1"
}

/// Decodes a value with an optional `base64:` prefix; undecodable values are kept verbatim.
pub fn decode_value(raw: &str) -> String {
    let raw = raw.trim();
    raw.strip_prefix("base64:")
        .and_then(crate::b64::decode_lenient)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_else(|| raw.to_string())
}

/// Assigns a parameter key to its security risk classification tier.
///
/// Keys absent from [`KNOWN_KEYS`] are [`RiskClass::Ignored`].
pub fn classify_key(key: &str) -> RiskClass {
    KNOWN_KEYS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map_or(RiskClass::Ignored, |(_, class)| *class)
}

/// Whether `key` is a recognised metadata key (case-insensitive).
pub fn is_known_key(key: &str) -> bool {
    KNOWN_KEYS.iter().any(|(k, _)| k.eq_ignore_ascii_case(key))
}

/// Extract metadata from HTTP response headers.
///
/// Only [`KNOWN_KEYS`] are taken, so ordinary headers (`content-type`, `set-cookie`, …) never
/// reach the map. `hwidlink` and `reset` are excluded because they travel in the URL.
pub fn parse_headers(headers: &[(String, String)], limits: &Limits) -> Result<MetaMap, Error> {
    let mut map = MetaMap::new();
    for (k, v) in headers {
        let k = k.trim();
        if !is_known_key(k) || URL_ONLY_KEYS.iter().any(|u| k.eq_ignore_ascii_case(u)) {
            continue;
        }
        check_meta_limits(&map, k, v, limits)?;
        map.insert(k, v);
    }
    Ok(map)
}

/// Enforce [`Limits::max_meta_keys`] and [`Limits::max_meta_value_len`] before inserting.
pub(crate) fn check_meta_limits(
    map: &MetaMap,
    key: &str,
    value: &str,
    limits: &Limits,
) -> Result<(), Error> {
    if !map.contains_key(key) && map.len() >= limits.max_meta_keys {
        return Err(Error::LimitExceeded(format!(
            "more than {} metadata keys",
            limits.max_meta_keys
        )));
    }
    if value.len() > limits.max_meta_value_len {
        return Err(Error::LimitExceeded(format!(
            "metadata value for {key:?} exceeds {} bytes",
            limits.max_meta_value_len
        )));
    }
    Ok(())
}

/// Merge body directives over response headers; body values win.
pub fn merge_body_over_headers(headers: &MetaMap, body: &MetaMap) -> MetaMap {
    let mut merged = headers.clone();
    merged.overlay(body);
    merged
}

/// Merge newly fetched metadata over previously stored metadata across a subscription refresh.
///
/// The new response replaces the stored map; only [`REFRESH_STICKY_KEYS`] it omits keep their
/// stored values.
pub fn refresh_merge(old: &MetaMap, incoming: &MetaMap) -> MetaMap {
    let mut merged = incoming.clone();
    for key in REFRESH_STICKY_KEYS {
        if let Some(v) = old.entries.get(*key) {
            merged
                .entries
                .entry(key.to_string())
                .or_insert_with(|| v.clone());
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn base64_prefix_decoding() {
        assert_eq!(
            decode_value("base64:RXhhbXBsZSBWUE4g8J+XvQ=="),
            "Example VPN 🗽"
        );
        // URL-safe and unpadded forms are accepted like the vendor client does.
        assert_eq!(
            decode_value("base64:RXhhbXBsZSBWUE4g8J-XvQ"),
            "Example VPN 🗽"
        );
        assert_eq!(decode_value("base64:!!"), "base64:!!");
    }

    #[test]
    fn known_keys_table_is_unique_and_complete() {
        let mut seen = std::collections::HashSet::new();
        for (k, _) in KNOWN_KEYS {
            assert!(seen.insert(*k), "duplicate key {k}");
            assert_eq!(*k, k.to_ascii_lowercase());
        }
        assert_eq!(KNOWN_KEYS.len(), 91);
        for k in REFRESH_STICKY_KEYS.iter().chain(&URL_ONLY_KEYS) {
            assert!(is_known_key(k), "{k}");
        }
    }

    #[test]
    fn body_precedence_over_headers() {
        let mut headers = MetaMap::new();
        headers.insert("profile-title", "Header Title");
        headers.insert("support-url", "https://t.me/support");

        let mut body = MetaMap::new();
        body.insert("profile-title", "Body Title");

        let merged = merge_body_over_headers(&headers, &body);
        assert_eq!(merged.profile_title(), Some("Body Title"));
        assert_eq!(merged.support_url(), Some("https://t.me/support"));
    }

    #[test]
    fn merge_does_not_decode_twice() {
        // A value that decodes to text which itself starts with `base64:` must stay as decoded once.
        let mut body = MetaMap::new();
        body.insert("announce", "base64:YmFzZTY0OlpXTm8=");
        let merged = merge_body_over_headers(&MetaMap::new(), &body);
        assert_eq!(merged.announce(), Some("base64:ZWNo"));
    }

    #[test]
    fn refresh_merge_drops_absent_keys_except_sticky_ones() {
        let mut old = MetaMap::new();
        for (k, v) in [
            ("profile-title", "Old Title"),
            ("announce", "old banner"),
            ("support-url", "https://example.org/old"),
            ("profile-update-interval", "5"),
            ("hide-settings", "true"),
            ("x-unknown", "1"),
            ("sub-info-text", "kept"),
            ("sub-expire", "true"),
            ("fallback-url", "https://example.org/fallback"),
        ] {
            old.insert(k, v);
        }
        let mut incoming = MetaMap::new();
        incoming.insert("profile-title", "New Title");
        incoming.insert("sub-expire", "false");

        let merged = refresh_merge(&old, &incoming);
        let keys: Vec<(&str, &str)> = merged.iter().collect();
        assert_eq!(
            keys,
            [
                ("fallback-url", "https://example.org/fallback"),
                ("profile-title", "New Title"),
                ("sub-expire", "false"),
                ("sub-info-text", "kept"),
            ]
        );
    }

    #[test]
    fn reset_is_not_a_header() {
        let headers = h(&[("reset", "1"), ("profile-title", "x")]);
        let map = parse_headers(&headers, &Limits::default()).unwrap();
        assert!(!map.contains_key("reset"));
        assert_eq!(classify_key("reset"), RiskClass::Ignored);
    }

    #[test]
    fn userinfo_token_parsing() {
        let s = "upload=1024; download=2048; total=107374182400; expire=1796256000";
        let info = UserInfo::parse(s).unwrap();
        assert_eq!(info.upload, 1024);
        assert_eq!(info.download, 2048);
        assert_eq!(info.total, 107374182400);
        assert_eq!(info.expire, 1796256000);
    }

    #[test]
    fn userinfo_tolerates_spaces_around_equals() {
        let info = UserInfo::parse("upload = 1; download =2;total= 3 expire=4").unwrap();
        assert_eq!(
            info,
            UserInfo {
                upload: 1,
                download: 2,
                total: 3,
                expire: 4
            }
        );
        let spaced = UserInfo::parse("upload=5 download=6").unwrap();
        assert_eq!((spaced.upload, spaced.download), (5, 6));
        assert_eq!(UserInfo::parse("nothing here"), None);
    }

    #[test]
    fn classification_tiers() {
        assert_eq!(classify_key("fallback-url"), RiskClass::TrustBoundary);
        assert_eq!(classify_key("New-URL"), RiskClass::TrustBoundary);
        assert_eq!(classify_key("profile-title"), RiskClass::Display);
        assert_eq!(classify_key("profile-update-interval"), RiskClass::Schedule);
        assert_eq!(classify_key("ping-result"), RiskClass::Ignored);
        assert_eq!(classify_key("content-type"), RiskClass::Ignored);
    }

    #[test]
    fn headers_keep_only_known_keys() {
        let headers = h(&[
            ("Content-Type", "text/plain"),
            ("set-cookie", "session=<REDACTED>"),
            ("date", "Mon, 12 Oct 2026 10:32:28 GMT"),
            ("server", "example-edge"),
            ("Profile-Title", "Example"),
            ("hwidlink", "abc"),
            ("ping-result", "12"),
        ]);
        let map = parse_headers(&headers, &Limits::default()).unwrap();
        let keys: Vec<&str> = map.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["ping-result", "profile-title"]);
    }

    #[test]
    fn headers_enforce_value_limit() {
        let limits = Limits {
            max_meta_value_len: 8,
            ..Limits::default()
        };
        let headers = h(&[("announce", "far too long for the limit")]);
        assert!(matches!(
            parse_headers(&headers, &limits),
            Err(Error::LimitExceeded(_))
        ));
        // Unknown headers are dropped before the limit is applied.
        let noise = h(&[("set-cookie", "far too long for the limit")]);
        assert!(parse_headers(&noise, &limits).unwrap().is_empty());
    }

    #[test]
    fn headers_enforce_key_limit() {
        let limits = Limits {
            max_meta_keys: 1,
            ..Limits::default()
        };
        let headers = h(&[("profile-title", "a"), ("announce", "b")]);
        assert!(matches!(
            parse_headers(&headers, &limits),
            Err(Error::LimitExceeded(_))
        ));
    }

    #[test]
    fn text_normalization_strips_bidi() {
        let malicious = "Example \u{202E}txt.exe\u{202C} VPN";
        assert_eq!(normalize_untrusted_text(malicious), "Example txt.exe VPN");
    }

    #[test]
    fn url_safety_accepts_public_targets() {
        for url in [
            "https://example.com/test",
            "https://example.com:8443/x?y#z",
            "https://user:pw@example.com/",
            "https://93.184.215.14/",
            "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]:443/",
            "http://example.org",
        ] {
            let require_https = url.starts_with("https");
            assert_eq!(validate_url_safety(url, require_https), Ok(()), "{url}");
        }
    }

    #[test]
    fn url_safety_rejects_internal_targets() {
        for url in [
            "http://example.com",
            "ftp://example.com",
            "https://127.0.0.1/test",
            "https://localhost/test",
            "https://api.localhost./",
            "https://192.168.1.1/test",
            "https://10.0.0.1/",
            "https://172.16.5.4/",
            "https://169.254.169.254/latest/meta-data",
            "https://0.0.0.0/",
            "https://0.1.2.3/",
            "https://100.64.0.1/",
            "https://224.0.0.1/",
            "https://255.255.255.255/",
            "https://x@127.0.0.1/",
            "https://example.com@10.0.0.1:443/",
            "https://example.com\\@127.0.0.1/",
            "https://[::1]/",
            "https://[::]/",
            "https://[fc00::1]/",
            "https://[fd12:3456::1]:8443/",
            "https://[fe80::1]/",
            "https://[ff02::1]/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:192.168.0.1]/",
            "https://127.1/",
            "https://2130706433/",
            "https://0x7f.0.0.1/",
            "https:///path",
            "https://[::1/",
            "https://example.com:http/",
        ] {
            assert!(validate_url_safety(url, true).is_err(), "{url}");
        }
    }

    #[test]
    fn url_safety_link_local_checks_second_octet() {
        // 169.x.254.y is public; only 169.254.0.0/16 is link-local.
        assert_eq!(validate_url_safety("https://169.1.254.1/", true), Ok(()));
        assert!(validate_url_safety("https://169.254.1.1/", true).is_err());
    }
}
