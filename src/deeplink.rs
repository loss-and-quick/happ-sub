//! Action parsing for `happ://` deeplinks (`EDeeplinkType`).
//!
//! Happ intercepts `happ://` URLs via Android intent filters and dispatches actions
//! according to fixed prefix tokens.

use crate::routing::{parse_routing_url, RoutingAction};
use crate::Error;

/// Parsed `happ://` deeplink action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deeplink {
    /// Import subscription or configuration from a remote URL (`happ://add/<URL>`).
    Add(String),
    /// Routing profile manipulation (`happ://routing/{add,onadd,off}`).
    Routing(Box<RoutingAction>),
    /// Pushed CloudKit device synchronization record (`happ://send_to_device/<id>`).
    SendToDevice(String),
    /// Encrypted URL import with schema version (`1`..=`5`) and raw payload string.
    Crypt {
        /// Crypt scheme version (1 for `crypt/`, 2 for `crypt2/`, etc.).
        version: u8,
        /// Obfuscated URL payload.
        payload: String,
    },
    /// Toggle VPN connection state.
    Toggle {
        /// Whether UI interaction is suppressed.
        without_ui: bool,
    },
    /// Start VPN tunnel.
    Connect {
        /// Whether UI interaction is suppressed.
        without_ui: bool,
    },
    /// Stop VPN tunnel.
    Disconnect {
        /// Whether UI interaction is suppressed.
        without_ui: bool,
    },
    /// Open client user interface.
    Open {
        /// Whether UI interaction is suppressed.
        without_ui: bool,
    },
    /// Close client user interface.
    Close {
        /// Whether UI interaction is suppressed.
        without_ui: bool,
    },
}

/// Prefixes are matched case-insensitively; the payload keeps its original case.
const CRYPT_PREFIXES: [(&str, u8); 5] = [
    ("crypt5/", 5),
    ("crypt4/", 4),
    ("crypt3/", 3),
    ("crypt2/", 2),
    ("crypt/", 1),
];

/// Parse a `happ://` URI into a [`Deeplink`].
///
/// Errors are [`Error::InvalidDeeplink`] for a non-`happ://` URI, [`Error::UnknownDeeplink`] for
/// an unrecognised action and [`Error::InvalidRouting`] for a bad routing payload.
pub fn parse_deeplink(uri: &str) -> Result<Deeplink, Error> {
    let uri = uri.trim();
    let rest = match uri.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("happ://") => &uri[7..],
        _ => {
            return Err(Error::InvalidDeeplink(format!(
                "URI does not use happ:// scheme: {uri}"
            )))
        }
    };
    let lower = rest.to_ascii_lowercase();

    if lower.starts_with("routing/") {
        return Ok(Deeplink::Routing(Box::new(parse_routing_url(uri)?)));
    }
    if lower.starts_with("add/") {
        return Ok(Deeplink::Add(rest["add/".len()..].to_string()));
    }
    if lower.starts_with("send_to_device/") {
        return Ok(Deeplink::SendToDevice(
            rest["send_to_device/".len()..].to_string(),
        ));
    }
    for (prefix, version) in CRYPT_PREFIXES {
        if lower.starts_with(prefix) {
            return Ok(Deeplink::Crypt {
                version,
                payload: rest[prefix.len()..].to_string(),
            });
        }
    }

    match lower.trim_end_matches('/') {
        "toggle" => Ok(Deeplink::Toggle { without_ui: false }),
        "toggle_without_ui" => Ok(Deeplink::Toggle { without_ui: true }),
        "connect" => Ok(Deeplink::Connect { without_ui: false }),
        "connect_without_ui" => Ok(Deeplink::Connect { without_ui: true }),
        "disconnect" => Ok(Deeplink::Disconnect { without_ui: false }),
        "disconnect_without_ui" => Ok(Deeplink::Disconnect { without_ui: true }),
        "open" => Ok(Deeplink::Open { without_ui: false }),
        "open_without_ui" => Ok(Deeplink::Open { without_ui: true }),
        "close" => Ok(Deeplink::Close { without_ui: false }),
        "close_without_ui" => Ok(Deeplink::Close { without_ui: true }),
        _ => Err(Error::UnknownDeeplink(uri.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_deeplink_actions() {
        assert_eq!(
            parse_deeplink("happ://add/https://example.com/sub").unwrap(),
            Deeplink::Add("https://example.com/sub".into())
        );
        assert_eq!(
            parse_deeplink("happ://crypt5/abcd").unwrap(),
            Deeplink::Crypt {
                version: 5,
                payload: "abcd".into()
            }
        );
        assert_eq!(
            parse_deeplink("HAPP://Crypt/AbCd").unwrap(),
            Deeplink::Crypt {
                version: 1,
                payload: "AbCd".into()
            }
        );
        assert_eq!(
            parse_deeplink("happ://toggle").unwrap(),
            Deeplink::Toggle { without_ui: false }
        );
        assert_eq!(
            parse_deeplink("happ://connect_without_ui").unwrap(),
            Deeplink::Connect { without_ui: true }
        );
        assert_eq!(
            parse_deeplink("happ://routing/off").unwrap(),
            Deeplink::Routing(Box::new(RoutingAction::Off))
        );
    }

    #[test]
    fn open_and_close_have_without_ui_variants() {
        for (uri, expected) in [
            ("happ://open", Deeplink::Open { without_ui: false }),
            (
                "happ://open_without_ui",
                Deeplink::Open { without_ui: true },
            ),
            ("happ://close/", Deeplink::Close { without_ui: false }),
            (
                "HAPP://Close_Without_UI",
                Deeplink::Close { without_ui: true },
            ),
        ] {
            assert_eq!(parse_deeplink(uri).unwrap(), expected, "{uri}");
        }
    }

    #[test]
    fn deeplink_errors_are_typed() {
        assert!(matches!(
            parse_deeplink("https://example.com"),
            Err(Error::InvalidDeeplink(_))
        ));
        assert!(matches!(
            parse_deeplink("happ://frobnicate"),
            Err(Error::UnknownDeeplink(_))
        ));
        assert!(matches!(
            parse_deeplink("happ://routing/add/!!!"),
            Err(Error::InvalidRouting(_))
        ));
    }
}
