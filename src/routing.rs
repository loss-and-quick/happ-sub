//! Dynamic routing profile parsing (`happ://routing/{add,onadd,off}`).
//!
//! Happ supports push-delivered routing rules configuring direct, proxied, and blocked
//! domains and IP CIDRs. Profiles arrive via `happ://routing/` deeplinks in headers or bodies.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::Error;

/// Dynamic routing profile payload decoded from JSON.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RoutingProfile {
    /// Human-readable profile title (e.g. `"EXAMPLE-ROUTING"`).
    pub name: String,
    /// Whether to route all traffic globally via proxy.
    #[serde(default)]
    pub global_proxy: Option<bool>,
    /// Protocol for remote DNS lookup (`tcp`, `udp`, `doh`, `dot`).
    #[serde(default)]
    pub remote_dns_type: Option<String>,
    /// Hostname or endpoint for remote DNS.
    #[serde(default)]
    pub remote_dns_domain: Option<String>,
    /// Fallback IP address for remote DNS server.
    #[serde(default)]
    pub remote_dns_ip: Option<String>,
    /// Protocol for direct/domestic DNS lookup.
    #[serde(default)]
    pub domestic_dns_type: Option<String>,
    /// Hostname or endpoint for domestic DNS.
    #[serde(default)]
    pub domestic_dns_domain: Option<String>,
    /// Fallback IP address for domestic DNS server.
    #[serde(default)]
    pub domestic_dns_ip: Option<String>,
    /// Custom URL for fetching updated geoip database.
    #[serde(default)]
    pub geoipurl: Option<String>,
    /// Custom URL for fetching updated geosite database.
    #[serde(default)]
    pub geositeurl: Option<String>,
    /// Timestamp of profile creation or update.
    #[serde(default)]
    pub last_updated: Option<i64>,
    /// Static domain-to-IP overrides.
    #[serde(default)]
    pub dns_hosts: Option<HashMap<String, String>>,
    /// Domain patterns routed directly (bypassing proxy).
    #[serde(default)]
    pub direct_sites: Vec<String>,
    /// IP CIDR ranges routed directly (bypassing proxy).
    #[serde(default)]
    pub direct_ip: Vec<String>,
    /// Domain patterns forced through proxy tunnel.
    #[serde(default)]
    pub proxy_sites: Vec<String>,
    /// IP CIDR ranges forced through proxy tunnel.
    #[serde(default)]
    pub proxy_ip: Vec<String>,
    /// Domain patterns blocked / blackholed.
    #[serde(default)]
    pub block_sites: Vec<String>,
    /// IP CIDR ranges blocked / blackholed.
    #[serde(default)]
    pub block_ip: Vec<String>,
    /// Domain resolution strategy (`AsIs`, `IPIfNonMatch`, `IPOnDemand`).
    #[serde(default)]
    pub domain_strategy: Option<String>,
    /// Enable local fake DNS allocation for outbound connections.
    #[serde(default)]
    pub fake_dns: Option<bool>,
}

/// Action specified by a `happ://routing/` deeplink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingAction {
    /// `happ://routing/add/<base64>`: documented as adding without activating, but Happ 4.7.1
    /// selected and enabled it like `onadd` on a subscription without a previous profile.
    Add(RoutingProfile),
    /// `happ://routing/onadd/<base64>`: add the profile and activate it.
    OnAdd(RoutingProfile),
    /// `happ://routing/off`: turn routing off for the subscription that delivered it.
    Off,
}

impl RoutingAction {
    /// The delivered profile, unless this is [`RoutingAction::Off`].
    pub fn profile(&self) -> Option<&RoutingProfile> {
        match self {
            RoutingAction::Add(p) | RoutingAction::OnAdd(p) => Some(p),
            RoutingAction::Off => None,
        }
    }
}

/// Parse a `happ://routing/` deeplink URL into a [`RoutingAction`].
///
/// Failures are [`Error::InvalidRouting`].
pub fn parse_routing_url(url: &str) -> Result<RoutingAction, Error> {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if lower.trim_end_matches('/') == "happ://routing/off" {
        return Ok(RoutingAction::Off);
    }
    if lower.starts_with("happ://routing/onadd/") {
        let profile = parse_routing_b64(&url["happ://routing/onadd/".len()..])?;
        return Ok(RoutingAction::OnAdd(profile));
    }
    if lower.starts_with("happ://routing/add/") {
        let profile = parse_routing_b64(&url["happ://routing/add/".len()..])?;
        return Ok(RoutingAction::Add(profile));
    }
    Err(Error::InvalidRouting(format!(
        "unrecognized routing deeplink: {url}"
    )))
}

/// Decodes Base64-encoded routing JSON into a [`RoutingProfile`].
pub fn parse_routing_b64(b64_str: &str) -> Result<RoutingProfile, Error> {
    let clean = b64_str.trim().trim_end_matches('/');
    let bytes = crate::b64::decode_lenient(clean)
        .ok_or_else(|| Error::InvalidRouting("payload is not Base64".into()))?;
    serde_json::from_slice(&bytes).map_err(|e| Error::InvalidRouting(format!("payload JSON: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_onadd_routing() {
        let url = "happ://routing/onadd/eyJOYW1lIjoiRVhBTVBMRS1ST1VUSU5HIiwiRGlyZWN0U2l0ZXMiOltdLCJEaXJlY3RJcCI6W119";
        let action = parse_routing_url(url).unwrap();
        match action {
            RoutingAction::OnAdd(profile) => {
                assert_eq!(profile.name, "EXAMPLE-ROUTING");
                assert!(profile.direct_sites.is_empty());
                assert!(profile.direct_ip.is_empty());
            }
            _ => panic!("expected OnAdd"),
        }
    }

    #[test]
    fn parse_routing_off() {
        let url = "happ://routing/off";
        assert_eq!(parse_routing_url(url).unwrap(), RoutingAction::Off);
    }

    #[test]
    fn routing_errors_are_typed() {
        assert!(matches!(
            parse_routing_url("happ://routing/add/!!!"),
            Err(Error::InvalidRouting(_))
        ));
        assert!(matches!(
            parse_routing_url("happ://routing/frobnicate"),
            Err(Error::InvalidRouting(_))
        ));
    }
}
