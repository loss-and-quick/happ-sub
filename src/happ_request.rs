//! The subscription request Happ sends: headers in wire order, timeout, retry and cookie jar.
//!
//! The caller supplies platform facts ([`DeviceInfo`]), the HWID, the user's overrides, the clock,
//! the subscription's merged metadata and its consent to `TrustBoundary` keys; [`build`] applies
//! Happ's precedence between them. `Host`, `Accept-Encoding` and the `Authorization` header Happ
//! derives from URL userinfo are left to the HTTP client.
//!
//! ```
//! use std::time::{SystemTime, UNIX_EPOCH};
//!
//! use happ_sub::happ_request::{self, ClientOs, DeviceInfo, Identity};
//! use happ_sub::MetaMap;
//!
//! let identity = Identity {
//!     // The SSAID (`device::ssaid`) or any identifier the client chooses; `None` sends no X-HWID.
//!     hwid: Some("0123456789abcdef".into()),
//!     device: DeviceInfo {
//!         os: ClientOs::Android,
//!         os_version: "16".into(),
//!         model: "Pixel 9".into(),
//!         locale: "en-US".into(),
//!     },
//!     ..Identity::default()
//! };
//! let stored: Option<&MetaMap> = None; // the merged meta from the last fetch; none on import
//! let accepted = ["change-user-agent"]; // TrustBoundary keys the user accepted
//! let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
//!
//! let profile = happ_request::build(&identity, stored, now, |key| accepted.contains(&key));
//! assert_eq!(profile.headers[0], ("Connection".into(), "close".into()));
//! assert_eq!(profile.headers[1].0, "User-agent");
//! assert!(profile.headers[1].1.starts_with(&format!("Happ/{}/Android/", happ_sub::HAPP_VERSION)));
//! assert_eq!(profile.timeout.as_secs(), 7);
//! ```

use std::time::Duration;

use crate::meta::{parse_bool, MetaMap};
use crate::release::{
    HAPP_API_VERSION, HAPP_DESKTOP_BUNDLE_ID_LINUX, HAPP_DESKTOP_UA_BUILD_STAMP,
    HAPP_DESKTOP_UA_SUFFIX, HAPP_DESKTOP_VERSION, HAPP_UA_BUILD_STAMP, HAPP_UA_SUFFIX,
    HAPP_VERSION, HAPP_VERSION_CODE,
};

/// Fetch timeout Happ uses when the subscription sets none.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(7);

/// Operating system reported in `X-Device-OS` and the User-Agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ClientOs {
    /// `Android`, observed on a device.
    #[default]
    Android,
    /// `AndroidTV`, from Happ's Android code for TV devices.
    AndroidTv,
    /// `Windows`; inferred, no desktop Happ build was examined.
    Windows,
    /// `Linux`; verified from desktop Happ build (`Happ.linux.x64.deb` 4.5.4-333).
    Linux,
    /// `macOS`; inferred, no desktop Happ build was examined.
    MacOs,
    /// `iOS`; inferred, no iOS Happ build was examined.
    Ios,
    /// Any other string, sent as given.
    Other(String),
}

impl ClientOs {
    /// The string sent for this OS.
    pub fn as_str(&self) -> &str {
        match self {
            ClientOs::Android => "Android",
            ClientOs::AndroidTv => "AndroidTV",
            ClientOs::Windows => "Windows",
            ClientOs::Linux => "Linux",
            ClientOs::MacOs => "macOS",
            ClientOs::Ios => "iOS",
            ClientOs::Other(s) => s,
        }
    }
}

/// Facts about the device the request comes from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceInfo {
    /// Operating system.
    pub os: ClientOs,
    /// OS release sent as `X-Ver-OS` (on Android `Build.VERSION.RELEASE`, e.g. `16`).
    pub os_version: String,
    /// Device model sent as `X-Device-model` (on Android `Build.MODEL`).
    pub model: String,
    /// UI locale; only its language subtag is sent (`ru-RU` and `ru_RU.UTF-8` send `ru`).
    pub locale: String,
}

pub use crate::desktop::DesktopFacts;

/// Translates raw desktop telemetry into Happ's Qt-style [`DeviceInfo`].
pub fn desktop_device(facts: &DesktopFacts<'_>) -> DeviceInfo {
    let os_version = crate::desktop::qt_product(facts.os_release_id, facts.os_release_version);
    let arch = crate::desktop::qt_cpu_architecture(facts.cpu_arch);
    let model = if !facts.hostname.is_empty() && !arch.is_empty() {
        format!("{}_{}", facts.hostname, arch)
    } else if !facts.hostname.is_empty() {
        facts.hostname.to_string()
    } else {
        arch.to_string()
    };
    let locale = crate::desktop::qt_locale_name(facts.posix_locale);
    let os = if facts.os.eq_ignore_ascii_case("linux") {
        ClientOs::Linux
    } else if facts.os.eq_ignore_ascii_case("windows") {
        ClientOs::Windows
    } else {
        ClientOs::Other(facts.os.to_string())
    };
    DeviceInfo {
        os,
        os_version,
        model,
        locale,
    }
}

/// Happ desktop HWID rule: returns `Some(machine_id)` when valid per [`crate::device::is_valid_sys_hwid`],
/// or `None` if absent or bogus (signaling the caller to use a stored random fallback).
pub fn desktop_hwid(machine_id: Option<&str>) -> Option<String> {
    let id = machine_id?.trim();
    if crate::device::is_valid_sys_hwid(id) {
        Some(id.to_string())
    } else {
        None
    }
}

/// The device, its HWID and the user's per-subscription overrides.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    /// Value for `X-HWID`; `None` omits that header but keeps the other device headers.
    pub hwid: Option<String>,
    /// Device facts.
    pub device: DeviceInfo,
    /// User-Agent the user set; wins over the provider's and the default.
    pub user_agent_override: Option<String>,
    /// The user's "send HWID" switch; wins over the provider's keys.
    pub send_hwid_override: Option<bool>,
    /// The user's "HWID in cookie" switch; wins over the provider's key.
    pub hwid_in_cookie_override: Option<bool>,
}

/// Settings the provider locks in Happ's UI; the user's overrides still win in [`build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Locks {
    /// `manual-block-user-agent`, consented: Happ clears the user's User-Agent and locks it.
    pub user_agent: bool,
    /// `subscription-always-hwid-enable`: Happ turns sending on and locks the switch.
    pub send_hwid: bool,
    /// `subscription-hwid-in-cookie-enable` is set: Happ locks the cookie switch to it.
    pub hwid_in_cookie: bool,
}

/// How to fetch a subscription the way Happ does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestProfile {
    /// Request headers in Happ's wire order and spelling.
    pub headers: Vec<(String, String)>,
    /// Limit per attempt on the whole call, from connecting to the last body byte.
    pub timeout: Duration,
    /// Retries after a failed attempt; [`RequestProfile::retry`] says how.
    pub retries: u8,
    /// Keep a persistent cookie jar keyed by host and shared by all subscriptions.
    pub use_cookie_jar: bool,
    /// Settings the provider locks.
    pub locks: Locks,
}

/// How the first attempt failed, which decides how Happ retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryCause {
    /// The peer reset the connection.
    ConnectionReset,
    /// A timeout or another I/O error, TLS failures included.
    TimeoutOrIo,
}

/// The single retry Happ makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retry {
    /// Headers for the retry.
    pub headers: Vec<(String, String)>,
    /// Resolve the host to IPv4 addresses only.
    pub ipv4_only: bool,
}

impl RequestProfile {
    /// The retry Happ makes after `cause`; a response with any status is not retried.
    pub fn retry(&self, cause: RetryCause) -> Retry {
        // `b52`: a reset is retried without `Connection: close`; any other IOException through a
        // resolver that keeps only IPv4 addresses.
        match cause {
            RetryCause::ConnectionReset => Retry {
                headers: self
                    .headers
                    .iter()
                    .filter(|(name, _)| !name.eq_ignore_ascii_case("connection"))
                    .cloned()
                    .collect(),
                ipv4_only: false,
            },
            RetryCause::TimeoutOrIo => Retry {
                headers: self.headers.clone(),
                ipv4_only: true,
            },
        }
    }
}

/// Happ's default User-Agent for an OS string (`Android`, `AndroidTV`, `Linux`) on a day of the month.
///
/// For `Linux`, uses the desktop template (`Happ/4.5.4/Linux/2610141140[5|6]85`).
/// For Android and other OS strings, uses the mobile template (`Happ/4.7.1/...`).
pub fn user_agent(os: &str, day_of_month: u32) -> String {
    if os.eq_ignore_ascii_case("linux") {
        // Happ desktop (observed in `Happ.linux.x64.deb`, `0x2f8440`):
        // Flips between '5' (odd days) and '6' (even days).
        let parity = if day_of_month % 2 != 0 { '5' } else { '6' };
        format!(
            "Happ/{HAPP_DESKTOP_VERSION}/Linux/{HAPP_DESKTOP_UA_BUILD_STAMP}{parity}{HAPP_DESKTOP_UA_SUFFIX}"
        )
    } else {
        // `wb8.S`: the digit after the version code flips between even and odd UTC days.
        let parity = if day_of_month % 2 == 0 { '6' } else { '5' };
        format!(
            "Happ/{HAPP_VERSION}/{os}/{HAPP_UA_BUILD_STAMP}{HAPP_VERSION_CODE}{parity}{HAPP_UA_SUFFIX}"
        )
    }
}

/// Happ's default User-Agent for an OS string and Unix timestamp in seconds.
///
/// On Linux, the day parity is computed in UTC+3 (MSK), as observed in the desktop binary.
/// On Android, the day parity is computed in UTC.
pub fn user_agent_for_os(os: &str, unix_secs: u64) -> String {
    let os = header_value(os);
    if os.eq_ignore_ascii_case("linux") {
        // Desktop Happ adds 10800 seconds (UTC+3) to current UTC time.
        let dt = unix_secs.saturating_add(10_800);
        user_agent("Linux", utc_day_of_month(dt))
    } else {
        user_agent(&os, utc_day_of_month(unix_secs))
    }
}

/// Builds the request Happ would send at `unix_secs`, given the subscription's merged metadata
/// (`None` on the first import) and whether the user consents to a `TrustBoundary` key.
pub fn build(
    identity: &Identity,
    meta: Option<&MetaMap>,
    unix_secs: u64,
    consent: impl Fn(&str) -> bool,
) -> RequestProfile {
    let get = |key: &str| meta.and_then(|m| m.get(key));
    let flag = |key: &str| get(key).map(parse_bool);
    let consented = |key: &str| get(key).filter(|_| consent(key));

    let os = header_value(identity.device.os.as_str());
    // `e52.c` falls back to the default for a blank value (`vl7.i`).
    let ua = [
        identity.user_agent_override.as_deref(),
        consented("change-user-agent"),
    ]
    .into_iter()
    .flatten()
    .map(header_value)
    .find(|ua| !ua.is_empty())
    .unwrap_or_else(|| user_agent_for_os(&os, unix_secs));

    // `mr` case 8: `always` forces sending on, whatever `send-hwid-enabled` says.
    let always_hwid = flag("subscription-always-hwid-enable") == Some(true);
    let send_hwid = identity
        .send_hwid_override
        .unwrap_or_else(|| always_hwid || flag("subscription-send-hwid-enabled").unwrap_or(true));
    let cookie_flag = flag("subscription-hwid-in-cookie-enable");
    let hwid_in_cookie = identity
        .hwid_in_cookie_override
        .or(cookie_flag)
        .unwrap_or(false);
    let hwid = identity
        .hwid
        .as_deref()
        .map(header_value)
        .filter(|h| !h.is_empty());

    let is_linux =
        matches!(identity.device.os, ClientOs::Linux) || os.eq_ignore_ascii_case("linux");

    let mut headers = vec![
        ("Connection".to_string(), "close".to_string()),
        ("User-agent".to_string(), ua),
        (
            "X-Device-Locale".to_string(),
            if is_linux {
                header_value(&identity.device.locale)
            } else {
                language(&identity.device.locale)
            },
        ),
    ];
    // `uj7.d`: the "send HWID" switch gates all four device headers, not only `X-HWID`.
    if send_hwid {
        if let Some(hwid) = hwid.as_ref().filter(|_| !hwid_in_cookie) {
            headers.push(("X-HWID".to_string(), hwid.clone()));
        }
        headers.push(("X-Device-OS".to_string(), os));
        headers.push((
            "X-Ver-OS".to_string(),
            header_value(&identity.device.os_version),
        ));
        headers.push((
            "X-Device-model".to_string(),
            header_value(&identity.device.model),
        ));
        if is_linux {
            headers.push((
                "X-Bundle-ID".to_string(),
                HAPP_DESKTOP_BUNDLE_ID_LINUX.to_string(),
            ));
            headers.push(("X-API-Version".to_string(), HAPP_API_VERSION.to_string()));
            headers.push((
                "X-App-Version".to_string(),
                HAPP_DESKTOP_VERSION.to_string(),
            ));
        }
        // `so1`: the HWID moves to a nameless cookie appended after the other headers.
        if let Some(hwid) = hwid.filter(|_| hwid_in_cookie) {
            headers.push(("Cookie".to_string(), hwid));
        }
    }

    // `MetaParams.Companion.a` drops a value outside 5..=15 instead of clamping it.
    let timeout = get("subscription-request-timeout")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|secs| (5..=15).contains(secs))
        .map_or(DEFAULT_TIMEOUT, Duration::from_secs);

    RequestProfile {
        headers,
        timeout,
        retries: 1,
        use_cookie_jar: true,
        locks: Locks {
            user_agent: consented("manual-block-user-agent").is_some_and(parse_bool),
            send_hwid: always_hwid,
            hwid_in_cookie: cookie_flag.is_some(),
        },
    }
}

/// Keeps the characters OkHttp accepts in a header value, then trims.
fn header_value(s: &str) -> String {
    // OkHttp throws on anything else, which fails Happ's whole fetch.
    let kept: String = s
        .chars()
        .filter(|&c| c == '\t' || (' '..='~').contains(&c))
        .collect();
    kept.trim().to_string()
}

/// The lower-case language subtag of a locale, as Java's `Locale.getLanguage()` returns it.
fn language(locale: &str) -> String {
    let subtag = locale
        .trim()
        .split(['-', '_', '.', '@'])
        .next()
        .unwrap_or("");
    header_value(subtag).to_ascii_lowercase()
}

fn utc_day_of_month(unix_secs: u64) -> u32 {
    // Howard Hinnant's `civil_from_days`, for days since 1970-01-01.
    let z = (unix_secs / 86_400) as i64 + 719_468;
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    (doy - (153 * mp + 2) / 5 + 1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const HWID: &str = "0123456789abcdef";
    // 2026-10-12 and 2026-10-13, 00:00:00 UTC.
    const EVEN_DAY: u64 = 1_791_763_200;
    const ODD_DAY: u64 = EVEN_DAY + 86_400;

    fn default_ua(os: &str, parity: char) -> String {
        format!(
            "Happ/{HAPP_VERSION}/{os}/{HAPP_UA_BUILD_STAMP}{HAPP_VERSION_CODE}{parity}{HAPP_UA_SUFFIX}"
        )
    }

    fn phone() -> Identity {
        Identity {
            hwid: Some(HWID.into()),
            device: DeviceInfo {
                os: ClientOs::Android,
                os_version: "16".into(),
                model: "motorola edge 70".into(),
                locale: "ru-RU".into(),
            },
            ..Identity::default()
        }
    }

    fn meta(pairs: &[(&str, &str)]) -> MetaMap {
        let mut m = MetaMap::new();
        for (k, v) in pairs {
            m.insert(k, v);
        }
        m
    }

    fn header<'p>(p: &'p RequestProfile, name: &str) -> Option<&'p str> {
        p.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn names(p: &RequestProfile) -> Vec<&str> {
        p.headers.iter().map(|(n, _)| n.as_str()).collect()
    }

    fn yes(_: &str) -> bool {
        true
    }

    fn no(_: &str) -> bool {
        false
    }

    #[test]
    fn default_request_matches_capture() {
        let p = build(&phone(), None, EVEN_DAY, no);
        let expected = [
            ("Connection", "close".to_string()),
            ("User-agent", default_ua("Android", '6')),
            ("X-Device-Locale", "ru".to_string()),
            ("X-HWID", HWID.to_string()),
            ("X-Device-OS", "Android".to_string()),
            ("X-Ver-OS", "16".to_string()),
            ("X-Device-model", "motorola edge 70".to_string()),
        ]
        .map(|(n, v)| (n.to_string(), v));
        assert_eq!(p.headers, expected);
        assert_eq!(p.timeout, Duration::from_secs(7));
        assert_eq!(p.retries, 1);
        assert!(p.use_cookie_jar);
        assert_eq!(p.locks, Locks::default());
    }

    #[test]
    fn user_agent_day_parity() {
        let even = user_agent("Android", 12);
        let odd = user_agent("Android", 13);
        assert_eq!(even, default_ua("Android", '6'));
        assert_eq!(odd, default_ua("Android", '5'));
        assert!(even.starts_with(&format!("Happ/{HAPP_VERSION}/Android/")));
        let parity_at = even.len() - HAPP_UA_SUFFIX.len() - 1;
        assert_eq!(&even[parity_at..parity_at + 1], "6");
        assert_eq!(&odd[parity_at..parity_at + 1], "5");
        assert_eq!(
            header(&build(&phone(), None, ODD_DAY, no), "User-agent"),
            Some(odd.as_str())
        );
    }

    #[test]
    fn day_of_month_from_unix_time() {
        assert_eq!(utc_day_of_month(0), 1);
        assert_eq!(utc_day_of_month(EVEN_DAY), 12);
        assert_eq!(utc_day_of_month(EVEN_DAY - 1), 11);
        assert_eq!(utc_day_of_month(1_709_164_800), 29); // 2024-02-29
        assert_eq!(utc_day_of_month(1_709_251_200), 1); // 2024-03-01
        assert_eq!(utc_day_of_month(4_102_358_400), 31); // 2099-12-31
    }

    #[test]
    fn android_tv_reports_its_os() {
        let mut id = phone();
        id.device.os = ClientOs::AndroidTv;
        let p = build(&id, None, EVEN_DAY, no);
        assert_eq!(header(&p, "X-Device-OS"), Some("AndroidTV"));
        assert_eq!(
            header(&p, "User-agent"),
            Some(default_ua("AndroidTV", '6').as_str())
        );
    }

    #[test]
    fn change_user_agent_needs_consent() {
        let m = meta(&[("change-user-agent", "Provider/1.0")]);
        let without = build(&phone(), Some(&m), EVEN_DAY, no);
        assert_eq!(
            header(&without, "User-agent"),
            Some(default_ua("Android", '6').as_str())
        );
        let with = build(&phone(), Some(&m), EVEN_DAY, |k| k == "change-user-agent");
        assert_eq!(header(&with, "User-agent"), Some("Provider/1.0"));
    }

    #[test]
    fn user_agent_override_wins_and_blank_falls_through() {
        let m = meta(&[("change-user-agent", "Provider/1.0")]);
        let mut id = phone();
        id.user_agent_override = Some(" Mine/2.0 ".into());
        let p = build(&id, Some(&m), EVEN_DAY, yes);
        assert_eq!(header(&p, "User-agent"), Some("Mine/2.0"));

        id.user_agent_override = Some("  ".into());
        let p = build(&id, Some(&m), EVEN_DAY, yes);
        assert_eq!(header(&p, "User-agent"), Some("Provider/1.0"));
        let p = build(&id, None, EVEN_DAY, yes);
        assert_eq!(
            header(&p, "User-agent"),
            Some(default_ua("Android", '6').as_str())
        );
    }

    #[test]
    fn send_hwid_disabled_drops_all_device_headers() {
        let m = meta(&[("subscription-send-hwid-enabled", "false")]);
        let p = build(&phone(), Some(&m), EVEN_DAY, no);
        assert_eq!(names(&p), ["Connection", "User-agent", "X-Device-Locale"]);

        let mut id = phone();
        id.send_hwid_override = Some(true);
        let p = build(&id, Some(&m), EVEN_DAY, no);
        assert_eq!(header(&p, "X-HWID"), Some(HWID));

        let mut id = phone();
        id.send_hwid_override = Some(false);
        let p = build(&id, None, EVEN_DAY, no);
        assert_eq!(p.headers.len(), 3);
    }

    #[test]
    fn always_hwid_forces_sending_and_locks() {
        let m = meta(&[
            ("subscription-send-hwid-enabled", "0"),
            ("subscription-always-hwid-enable", "true"),
        ]);
        let p = build(&phone(), Some(&m), EVEN_DAY, no);
        assert_eq!(header(&p, "X-HWID"), Some(HWID));
        assert!(p.locks.send_hwid);

        let mut id = phone();
        id.send_hwid_override = Some(false);
        let p = build(&id, Some(&m), EVEN_DAY, no);
        assert_eq!(header(&p, "X-HWID"), None);
        assert!(p.locks.send_hwid);

        let off = meta(&[("subscription-always-hwid-enable", "false")]);
        assert!(!build(&phone(), Some(&off), EVEN_DAY, no).locks.send_hwid);
    }

    #[test]
    fn hwid_in_cookie_replaces_header_with_trailing_cookie() {
        let m = meta(&[("subscription-hwid-in-cookie-enable", "1")]);
        let p = build(&phone(), Some(&m), EVEN_DAY, no);
        assert_eq!(
            names(&p),
            [
                "Connection",
                "User-agent",
                "X-Device-Locale",
                "X-Device-OS",
                "X-Ver-OS",
                "X-Device-model",
                "Cookie",
            ]
        );
        assert_eq!(header(&p, "Cookie"), Some(HWID));
        assert!(p.locks.hwid_in_cookie);

        let mut id = phone();
        id.hwid_in_cookie_override = Some(false);
        let p = build(&id, Some(&m), EVEN_DAY, no);
        assert_eq!(header(&p, "X-HWID"), Some(HWID));
        assert_eq!(header(&p, "Cookie"), None);

        let mut id = phone();
        id.hwid_in_cookie_override = Some(true);
        id.send_hwid_override = Some(false);
        let p = build(&id, None, EVEN_DAY, no);
        assert_eq!(header(&p, "Cookie"), None);
        assert!(!p.locks.hwid_in_cookie);
    }

    #[test]
    fn missing_hwid_keeps_other_device_headers() {
        let mut id = phone();
        id.hwid = None;
        id.hwid_in_cookie_override = Some(true);
        let p = build(&id, None, EVEN_DAY, no);
        assert_eq!(header(&p, "X-HWID"), None);
        assert_eq!(header(&p, "Cookie"), None);
        assert_eq!(header(&p, "X-Device-OS"), Some("Android"));
        assert_eq!(header(&p, "X-Device-model"), Some("motorola edge 70"));
    }

    #[test]
    fn timeout_outside_range_is_ignored() {
        for (value, secs) in [("5", 5), ("10", 10), ("15", 15), (" 12 ", 12)] {
            let m = meta(&[("subscription-request-timeout", value)]);
            let p = build(&phone(), Some(&m), EVEN_DAY, no);
            assert_eq!(p.timeout, Duration::from_secs(secs), "{value}");
        }
        for value in ["4", "16", "0", "-7", "ten", ""] {
            let m = meta(&[("subscription-request-timeout", value)]);
            let p = build(&phone(), Some(&m), EVEN_DAY, no);
            assert_eq!(p.timeout, DEFAULT_TIMEOUT, "{value}");
        }
    }

    #[test]
    fn manual_block_user_agent_lock_needs_consent() {
        let m = meta(&[("manual-block-user-agent", "true")]);
        assert!(!build(&phone(), Some(&m), EVEN_DAY, no).locks.user_agent);
        assert!(build(&phone(), Some(&m), EVEN_DAY, yes).locks.user_agent);
        let mut id = phone();
        id.user_agent_override = Some("Mine/2.0".into());
        let p = build(&id, Some(&m), EVEN_DAY, yes);
        assert_eq!(header(&p, "User-agent"), Some("Mine/2.0"));
    }

    #[test]
    fn retry_follows_failure_cause() {
        let p = build(&phone(), None, EVEN_DAY, no);
        let reset = p.retry(RetryCause::ConnectionReset);
        assert!(!reset.ipv4_only);
        assert_eq!(reset.headers, p.headers[1..]);
        let timeout = p.retry(RetryCause::TimeoutOrIo);
        assert!(timeout.ipv4_only);
        assert_eq!(timeout.headers, p.headers);
    }

    #[test]
    fn header_values_are_sanitized() {
        let mut id = phone();
        id.device.model = " Pixel\n9 \u{2122} ".into();
        id.device.locale = "en_US.UTF-8".into();
        id.device.os = ClientOs::Other("Haiku\r\n".into());
        id.user_agent_override = Some("\u{0430}\u{0431}".into());
        let p = build(&id, None, EVEN_DAY, no);
        assert_eq!(header(&p, "X-Device-model"), Some("Pixel9"));
        assert_eq!(header(&p, "X-Device-Locale"), Some("en"));
        assert_eq!(header(&p, "X-Device-OS"), Some("Haiku"));
        assert_eq!(
            header(&p, "User-agent"),
            Some(default_ua("Haiku", '6').as_str())
        );
        for (_, v) in &p.headers {
            assert!(v.chars().all(|c| c == '\t' || (' '..='~').contains(&c)));
        }
    }

    #[test]
    fn os_strings() {
        let all = [
            (ClientOs::Android, "Android"),
            (ClientOs::AndroidTv, "AndroidTV"),
            (ClientOs::Windows, "Windows"),
            (ClientOs::Linux, "Linux"),
            (ClientOs::MacOs, "macOS"),
            (ClientOs::Ios, "iOS"),
            (ClientOs::Other("Haiku".into()), "Haiku"),
        ];
        for (os, s) in all {
            assert_eq!(os.as_str(), s);
        }
    }

    #[test]
    fn desktop_linux_user_agent_format() {
        assert_eq!(user_agent("Linux", 14), "Happ/4.5.4/Linux/2610141140685");
        assert_eq!(user_agent("Linux", 15), "Happ/4.5.4/Linux/2610141140585");
        assert_eq!(user_agent("linux", 1), "Happ/4.5.4/Linux/2610141140585");
        assert_eq!(user_agent("LINUX", 2), "Happ/4.5.4/Linux/2610141140685");
    }

    #[test]
    fn desktop_linux_user_agent_timezone_boundary() {
        // 2026-10-14 20:59:00 UTC is 23:59:00 MSK (UTC+3) -> day 14 (even -> '6')
        // 2026-10-14 00:00:00 UTC = 1791936000
        // 20:59:00 = 75540s -> 1791936000 + 75540 = 1792011540
        let t1 = 1_792_011_540;
        assert_eq!(
            user_agent_for_os("Linux", t1),
            "Happ/4.5.4/Linux/2610141140685"
        );

        // 2026-10-14 21:01:00 UTC is 00:01:00 MSK (UTC+3) on 2026-10-15 -> day 15 (odd -> '5')
        // 21:01:00 = 75660s -> 1791936000 + 75660 = 1792011660
        let t2 = 1_792_011_660;
        assert_eq!(
            user_agent_for_os("Linux", t2),
            "Happ/4.5.4/Linux/2610141140585"
        );
    }

    #[test]
    fn desktop_linux_headers_in_build() {
        let identity = Identity {
            hwid: Some("0123456789abcdef".into()),
            device: DeviceInfo {
                os: ClientOs::Linux,
                os_version: "ubuntu_24.04".into(),
                model: "workstation_x86_64".into(),
                locale: "ru_RU.UTF-8".into(),
            },
            ..Identity::default()
        };
        // EVEN_DAY (2026-10-14 12:00:00 UTC): in MSK it is 15:00:00 on day 14 -> even -> '6'
        let p = build(&identity, None, EVEN_DAY, no);
        assert_eq!(
            names(&p),
            [
                "Connection",
                "User-agent",
                "X-Device-Locale",
                "X-HWID",
                "X-Device-OS",
                "X-Ver-OS",
                "X-Device-model",
                "X-Bundle-ID",
                "X-API-Version",
                "X-App-Version",
            ]
        );
        assert_eq!(
            header(&p, "User-agent"),
            Some("Happ/4.5.4/Linux/2610141140685")
        );
        assert_eq!(header(&p, "X-Device-Locale"), Some("ru_RU.UTF-8"));
        assert_eq!(header(&p, "X-HWID"), Some("0123456789abcdef"));
        assert_eq!(header(&p, "X-Device-OS"), Some("Linux"));
        assert_eq!(header(&p, "X-Ver-OS"), Some("ubuntu_24.04"));
        assert_eq!(header(&p, "X-Device-model"), Some("workstation_x86_64"));
        assert_eq!(header(&p, "X-Bundle-ID"), Some("su.happ.desktop.linux"));
        assert_eq!(header(&p, "X-API-Version"), Some("1.0"));
        assert_eq!(header(&p, "X-App-Version"), Some("4.5.4"));
    }

    #[test]
    fn desktop_linux_disabled_hwid_drops_device_headers() {
        let identity = Identity {
            hwid: Some("0123456789abcdef".into()),
            device: DeviceInfo {
                os: ClientOs::Linux,
                os_version: "ubuntu_24.04".into(),
                model: "workstation_x86_64".into(),
                locale: "ru_RU.UTF-8".into(),
            },
            send_hwid_override: Some(false),
            ..Identity::default()
        };
        let p = build(&identity, None, EVEN_DAY, no);
        assert_eq!(names(&p), ["Connection", "User-agent", "X-Device-Locale"]);
    }

    #[test]
    fn desktop_device_translation() {
        let raw = DesktopFacts {
            os: "Linux",
            os_release_id: "nixos",
            os_release_version: "26.05",
            kernel_release: "6.12.18",
            hostname: "mybox",
            cpu_arch: "x86_64",
            username: "user",
            machine_id: Some("0123456789abcdef"),
            posix_locale: "ru_RU.UTF-8",
            language_tag: "ru-RU",
        };
        let device = desktop_device(&raw);
        assert_eq!(device.os, ClientOs::Linux);
        assert_eq!(device.os_version, "nixos_26.05");
        assert_eq!(device.model, "mybox_x86_64");
        assert_eq!(device.locale, "ru_RU");
    }

    #[test]
    fn desktop_hwid_validation() {
        assert_eq!(
            desktop_hwid(Some("0123456789abcdef")),
            Some("0123456789abcdef".to_string())
        );
        assert_eq!(desktop_hwid(Some("")), None);
        assert_eq!(
            desktop_hwid(Some("00000000-0000-0000-0000-000000000000")),
            None
        );
        assert_eq!(desktop_hwid(None), None);
    }
}
