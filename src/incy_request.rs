//! The subscription request INCY sends (`incy://` clients, Android 3.7.0).
//!
//! Where Happ reports itself with a version-stamped `Happ/…` User-Agent and a device identity
//! derived from the APK's signing certificate, INCY sends a small, fixed set of `x-` headers and
//! a User-Agent built from the app version and the VM version string:
//!
//! ```text
//! INCY/<versionName>/android Dalvik/<java.vm.version or "2.1.0">
//! ```
//!
//! ```text
//! User-Agent: INCY/3.7.0/android Dalvik/2.1.0
//! Accept: */*
//! Accept-Language: <Locale.getDefault().toLanguageTag()>
//! x-hwid: <device id>            ┐
//! x-device-os: Android           │ only when a device id exists
//! x-ver-os: <VERSION.RELEASE>    │
//! x-device-model: <M> <MODEL>    ┘
//! x-app-version: <versionName>
//! x-device-locale: <Locale.getDefault()>
//! x-client: INCY
//! ```
//!
//! Unlike Happ there is no `change-user-agent` directive: the override is a local per-subscription
//! setting, and an empty override falls back to the default.
//!
//! # Device id
//!
//! INCY's `x-hwid` is **not** an SSAID. [`derive_hwid`] reproduces the client's algorithm: a stored
//! value is reused as is, otherwise a seed is derived once from `android_id` and the build
//! fingerprints, and the id itself is the uppercase-hex head of `SHA-256("afcy_hwidS" ‖ seed)`
//! grouped as `8-4-4-4-12`. The emulator's sentinel `android_id` is rejected in favour of a
//! random seed. Read from decompiled code only (**INFERRED**): a caller that has observed a real
//! device should pass its id in [`RequestOptions::hwid`] rather than derive one.
//!
//! # Scope
//!
//! Zero I/O: the caller supplies the URL, the `android.os.Build` values, the locale and the
//! device id, and receives the header list in wire order. No policy is applied here.
//!
//! ```
//! use happ_sub::incy_request::{build_request, DeviceFacts, RequestOptions};
//!
//! let facts = DeviceFacts {
//!     android_id: Some("9774d56d682e549c8871f0e5a1b2c3d4"),
//!     manufacturer: "Google",
//!     model: "Pixel 8",
//!     brand: "google",
//!     device: "husky",
//!     product: "husky",
//!     board: "husky",
//!     hardware: "husky",
//!     os_version: "16",
//!     locale: "ru_RU",
//!     language_tag: "ru-RU",
//! };
//! let options = RequestOptions {
//!     app_version: "3.7.0",
//!     vm_version: None,
//!     user_agent: None,
//!     hwid: None,
//! };
//!
//! let request = build_request("https://example.com/sub", &options, &facts, Some("HWID"));
//! assert_eq!(request.user_agent, "INCY/3.7.0/android Dalvik/2.1.0");
//! assert_eq!(request.headers[0].0, "User-Agent");
//! assert!(request.headers.iter().any(|(name, value)| name == "x-hwid" && value == "HWID"));
//! assert_eq!(request.headers.last().unwrap().1, "INCY");
//!
//! // Without a device id the whole x-hwid block disappears, as in the client.
//! let anonymous = build_request("https://example.com/sub", &options, &facts, None);
//! assert!(!anonymous.headers.iter().any(|(name, _)| name.starts_with("x-hwid")));
//! ```

use sha2::{Digest, Sha256};

/// Value of the `x-client` header.
pub const CLIENT: &str = "INCY";

/// Prefix mixed into the device-id digest; XOR-obfuscated in the client as
/// `{35,21,77,36,64,11,63,94,8,70}` against the same table its salt uses.
pub const HWID_PREFIX: &str = "afcy_hwidS";

/// `android_id` every Android emulator reports; treated as absent.
pub const EMULATOR_ANDROID_ID: &str = "9774d56d682e549c";

/// `java.vm.version` substitute when the property is absent.
pub const DEFAULT_VM_VERSION: &str = "2.1.0";

/// Hex characters of the digest kept, before the `8-4-4-4-12` grouping.
pub const HWID_HEX_LEN: usize = 32;

/// How many non-`0` characters `android_id` must have for its hash to be used as the seed.
pub const MIN_NON_ZERO_CHARS: usize = 4;

/// The device values the client reads from the platform; the caller supplies every one of them.
#[derive(Debug, Clone, Copy)]
pub struct DeviceFacts<'a> {
    /// `Settings.Secure.getString("android_id")`, if it could be read.
    pub android_id: Option<&'a str>,
    /// `Build.MANUFACTURER`.
    pub manufacturer: &'a str,
    /// `Build.MODEL`.
    pub model: &'a str,
    /// `Build.BRAND`.
    pub brand: &'a str,
    /// `Build.DEVICE`.
    pub device: &'a str,
    /// `Build.PRODUCT`.
    pub product: &'a str,
    /// `Build.BOARD`.
    pub board: &'a str,
    /// `Build.HARDWARE`.
    pub hardware: &'a str,
    /// `Build.VERSION.RELEASE`.
    pub os_version: &'a str,
    /// `Locale.getDefault().toString()`, for example `en_US`.
    pub locale: &'a str,
    /// `Locale.getDefault().toLanguageTag()`, for example `en-US`.
    pub language_tag: &'a str,
}

impl Default for DeviceFacts<'_> {
    fn default() -> Self {
        Self {
            android_id: None,
            manufacturer: "",
            model: "",
            brand: "",
            device: "",
            product: "",
            board: "",
            hardware: "",
            os_version: "",
            locale: "en_US",
            language_tag: "en-US",
        }
    }
}

/// What the caller knows about the request beyond the device values.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestOptions<'a> {
    /// `versionName` from the package manager; also the `x-app-version` header.
    pub app_version: &'a str,
    /// `System.getProperty("java.vm.version")`; `None` yields [`DEFAULT_VM_VERSION`].
    pub vm_version: Option<&'a str>,
    /// Per-subscription User-Agent override. Empty or absent means the default.
    pub user_agent: Option<&'a str>,
    /// A device id the caller already has. `None` omits the `x-hwid` header block.
    pub hwid: Option<&'a str>,
}

/// A subscription request, ready to hand to an HTTP client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncyRequest {
    /// The subscription URL.
    pub url: String,
    /// The `User-Agent` the header list carries, so a caller can log what was sent.
    pub user_agent: String,
    /// Headers in the order the client adds them.
    pub headers: Vec<(String, String)>,
}

/// Build the default User-Agent: `INCY/<versionName>/android Dalvik/<vm version>`.
pub fn user_agent(app_version: &str, vm_version: Option<&str>) -> String {
    let vm = vm_version
        .filter(|v| !v.is_empty())
        .unwrap_or(DEFAULT_VM_VERSION);
    format!("INCY/{app_version}/android Dalvik/{vm}")
}

/// The User-Agent to send: the caller's override when it is non-empty, the default otherwise.
pub fn resolve_user_agent(options: &RequestOptions<'_>) -> String {
    match options.user_agent {
        Some(override_ua) if !override_ua.is_empty() => override_ua.to_string(),
        _ => user_agent(options.app_version, options.vm_version),
    }
}

/// Reproduce INCY's device id.
///
/// `stored` is the value the client kept from a previous run: a 36-character id is returned
/// unchanged, anything else is treated as a seed to hash. `fallback_seed` is what the client
/// generates when `android_id` is missing, is the emulator sentinel, or has too few non-zero
/// characters — a random UUID without dashes.
///
/// **INFERRED**: read from the client, not observed on a device.
pub fn derive_hwid(stored: Option<&str>, facts: &DeviceFacts<'_>, fallback_seed: &str) -> String {
    if let Some(id) = stored {
        if id.len() == 36 && id.contains('-') {
            return id.to_string();
        }
    }

    let seed = match usable_seed(stored) {
        Some(seed) => seed,
        None => seed_from_device(facts, fallback_seed),
    };

    let digest = hex(
        &Sha256::digest(format!("{HWID_PREFIX}{seed}").as_bytes()),
        true,
    );
    group_uuid(&digest[..HWID_HEX_LEN])
}

fn usable_seed(stored: Option<&str>) -> Option<String> {
    stored.filter(|s| !s.is_empty()).map(str::to_string)
}

/// The client's one-time seed: the hash of `android_id` and the build fingerprints, or a random
/// UUID when `android_id` cannot be used.
fn seed_from_device(facts: &DeviceFacts<'_>, fallback_seed: &str) -> String {
    let Some(android_id) = facts.android_id else {
        return fallback_seed.to_string();
    };
    if android_id.is_empty() || android_id == EMULATOR_ANDROID_ID {
        return fallback_seed.to_string();
    }
    if android_id.chars().filter(|c| *c != '0').count() < MIN_NON_ZERO_CHARS {
        return fallback_seed.to_string();
    }

    let material = [
        android_id,
        facts.manufacturer,
        facts.model,
        facts.brand,
        facts.device,
        facts.product,
        facts.board,
        facts.hardware,
    ]
    .join("|");
    hex(&Sha256::digest(material.as_bytes()), false)
}

/// Build the header list in the client's order.
pub fn build_headers(
    options: &RequestOptions<'_>,
    facts: &DeviceFacts<'_>,
    hwid: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers = vec![
        ("User-Agent".to_string(), resolve_user_agent(options)),
        ("Accept".to_string(), "*/*".to_string()),
        (
            "Accept-Language".to_string(),
            facts.language_tag.to_string(),
        ),
    ];

    if let Some(hwid) = hwid {
        headers.push(("x-hwid".to_string(), hwid.to_string()));
        headers.push(("x-device-os".to_string(), "Android".to_string()));
        headers.push(("x-ver-os".to_string(), facts.os_version.to_string()));
        headers.push((
            "x-device-model".to_string(),
            format!("{} {}", facts.manufacturer, facts.model)
                .trim()
                .to_string(),
        ));
    }

    headers.push(("x-app-version".to_string(), options.app_version.to_string()));
    headers.push(("x-device-locale".to_string(), facts.locale.to_string()));
    headers.push(("x-client".to_string(), CLIENT.to_string()));
    headers
}

/// Build the whole request for one subscription URL.
pub fn build_request(
    url: &str,
    options: &RequestOptions<'_>,
    facts: &DeviceFacts<'_>,
    hwid: Option<&str>,
) -> IncyRequest {
    IncyRequest {
        url: url.to_string(),
        user_agent: resolve_user_agent(options),
        headers: build_headers(options, facts, hwid),
    }
}

/// Lower- or upper-case hex of a digest; the client formats the seed in lower case and the id in
/// upper case.
fn hex(digest: &[u8], upper: bool) -> String {
    digest
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

/// Group 32 hex characters as `8-4-4-4-12`.
fn group_uuid(hex: &str) -> String {
    let groups = [8usize, 4, 4, 4, 12];
    let mut out = String::with_capacity(36);
    let mut pos = 0;
    for (index, len) in groups.iter().enumerate() {
        if index > 0 {
            out.push('-');
        }
        out.push_str(&hex[pos..pos + len]);
        pos += len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> DeviceFacts<'static> {
        DeviceFacts {
            android_id: Some("9774d56d682e549c8871f0e5a1b2c3d4"),
            manufacturer: "Google",
            model: "Pixel 8",
            brand: "google",
            device: "husky",
            product: "husky",
            board: "husky",
            hardware: "husky",
            os_version: "16",
            locale: "ru_RU",
            language_tag: "ru-RU",
        }
    }

    fn options() -> RequestOptions<'static> {
        RequestOptions {
            app_version: "3.7.0",
            vm_version: Some("2.1.0"),
            user_agent: None,
            hwid: None,
        }
    }

    /// The id the documented digest produces for `seed`, spelled out independently of the
    /// production helpers so a change in either one shows up here.
    fn hwid_for_seed(seed: &str) -> String {
        let digest = Sha256::digest(format!("afcy_hwidS{seed}").as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02X}")).collect();
        [
            &hex[0..8],
            &hex[8..12],
            &hex[12..16],
            &hex[16..20],
            &hex[20..32],
        ]
        .join("-")
    }

    #[test]
    fn default_user_agent_uses_the_vm_version_or_the_fallback() {
        assert_eq!(
            user_agent("3.7.0", Some("2.1.0")),
            "INCY/3.7.0/android Dalvik/2.1.0"
        );
        assert_eq!(user_agent("3.7.0", None), "INCY/3.7.0/android Dalvik/2.1.0");
        assert_eq!(
            user_agent("3.7.0", Some("")),
            "INCY/3.7.0/android Dalvik/2.1.0"
        );
    }

    #[test]
    fn an_override_wins_and_an_empty_one_falls_back() {
        let mut opts = options();
        assert_eq!(resolve_user_agent(&opts), "INCY/3.7.0/android Dalvik/2.1.0");

        opts.user_agent = Some("MyBrowser/1.0");
        assert_eq!(resolve_user_agent(&opts), "MyBrowser/1.0");

        opts.user_agent = Some("");
        assert_eq!(resolve_user_agent(&opts), "INCY/3.7.0/android Dalvik/2.1.0");
    }

    #[test]
    fn headers_are_emitted_in_the_clients_order() {
        let request = build_request(
            "https://example.com/sub",
            &options(),
            &facts(),
            Some("HWID-1"),
        );
        let names: Vec<&str> = request
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();

        assert_eq!(
            names,
            [
                "User-Agent",
                "Accept",
                "Accept-Language",
                "x-hwid",
                "x-device-os",
                "x-ver-os",
                "x-device-model",
                "x-app-version",
                "x-device-locale",
                "x-client",
            ]
        );
        assert_eq!(request.headers[0].1, "INCY/3.7.0/android Dalvik/2.1.0");
        assert_eq!(request.headers[2].1, "ru-RU");
        assert_eq!(request.headers[6].1, "Google Pixel 8");
        assert_eq!(request.headers[7].1, "3.7.0");
        assert_eq!(request.headers[8].1, "ru_RU");
        assert_eq!(request.headers[9].1, CLIENT);
        assert_eq!(request.url, "https://example.com/sub");
    }

    #[test]
    fn without_a_device_id_the_x_hwid_block_is_omitted() {
        let request = build_request("https://example.com/sub", &options(), &facts(), None);
        let names: Vec<&str> = request
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();

        assert_eq!(
            names,
            [
                "User-Agent",
                "Accept",
                "Accept-Language",
                "x-app-version",
                "x-device-locale",
                "x-client",
            ]
        );
        assert!(!request
            .headers
            .iter()
            .any(|(name, _)| name.starts_with("x-hwid")));
    }

    #[test]
    fn hwid_is_uppercase_hex_grouped_as_a_uuid() {
        let hwid = derive_hwid(None, &facts(), "0f1e2d3c4b5a69788796a5b4c3d2e1f0");

        assert_eq!(hwid.len(), 36);
        assert_eq!(
            hwid.chars().filter(|c| *c == '-').count(),
            4,
            "{hwid}: four groups"
        );
        assert_eq!(&hwid[8..9], "-");
        assert_eq!(&hwid[13..14], "-");
        assert_eq!(&hwid[18..19], "-");
        assert_eq!(&hwid[23..24], "-");
        assert!(
            hwid.chars()
                .all(|c| c == '-' || c.is_ascii_digit() || ('A'..='F').contains(&c)),
            "{hwid}: uppercase hex only"
        );
    }

    #[test]
    fn hwid_matches_the_documented_digest() {
        let seed = seed_from_device(&facts(), "unused");
        assert_eq!(
            derive_hwid(None, &facts(), "unused"),
            hwid_for_seed(&seed),
            "the id is the upper-case hex head of SHA-256(prefix + seed)"
        );
    }

    #[test]
    fn an_unusable_android_id_falls_back_to_the_supplied_seed() {
        let fallback = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
        let expected = derive_hwid(Some(fallback), &facts(), fallback);

        let mut facts = facts();
        facts.android_id = None;
        assert_eq!(derive_hwid(None, &facts, fallback), expected);

        facts.android_id = Some(EMULATOR_ANDROID_ID);
        assert_eq!(derive_hwid(None, &facts, fallback), expected);

        facts.android_id = Some("");
        assert_eq!(derive_hwid(None, &facts, fallback), expected);

        // Fewer than four non-zero characters: the client distrusts the value.
        facts.android_id = Some("0000");
        assert_eq!(derive_hwid(None, &facts, fallback), expected);
    }

    #[test]
    fn a_stored_uuid_is_returned_unchanged_and_other_stored_values_are_seeds() {
        let stored = "3f7a1c9e-4b2d-4e6f-8a1b-9c0d2e3f4a5b";
        assert_eq!(derive_hwid(Some(stored), &facts(), "unused"), stored);

        // The client keeps the id and the seed in separate storage: a stored seed of any other
        // shape is hashed as is, which is exactly what a fresh derivation produces.
        let device_seed = seed_from_device(&facts(), "unused");
        assert_eq!(
            derive_hwid(Some(&device_seed), &facts(), "unused"),
            hwid_for_seed(&device_seed)
        );
        assert_eq!(
            derive_hwid(None, &facts(), "unused"),
            hwid_for_seed(&device_seed)
        );
    }
}
