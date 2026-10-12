//! Zero-I/O Rust library for Happ-compatible (`su.happ.proxyutility`) subscription handling.
//!
//! * Body form detection (Base64 wrapping, JSON array, Xray or sing-box JSON, newline-delimited
//!   links)
//! * Metadata protocol (URL fragment, headers and `#key: value` directives, precedence, refresh
//!   merge)
//! * Subscription body decryption (AES-128-GCM with versioned key tables)
//! * URL unhiding (`happ://crypt/` … `happ://crypt5/`) with embedded (`builtin-url-keys`) or
//!   caller-supplied RSA keys
//! * Routing profiles (`happ://routing/`) and deeplink action dispatch
//!
//! # Scope Boundary
//! This crate owns **only** the Happ envelope. It performs no I/O, does not parse proxy share
//! links (`vmess://`, `vless://`, …) and enforces no policy: remote-control directives are
//! classified into risk tiers for the caller to gate.

#![deny(missing_docs)]

mod b64;
pub mod body;
#[cfg(feature = "body-crypt")]
pub mod body_crypt;
pub mod deeplink;
pub mod keys;
pub mod meta;
pub mod routing;
#[cfg(feature = "url-crypt")]
pub mod url_crypt;

pub use body::Payload;
pub use meta::{Limits, MergeMode, MetaDelta, MetaMap, ProposedChange, RiskClass, UserInfo};
pub use routing::{RoutingAction, RoutingProfile};

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// Input package supplied by caller for subscription ingestion.
#[derive(Debug, Clone)]
pub struct Input<'a> {
    /// Subscription URL: `?key=` selects the body key; on import the fragment carries directives.
    pub url: &'a str,
    /// Raw HTTP response headers as `(name, value)` pairs.
    pub headers: &'a [(String, String)],
    /// Raw HTTP response body bytes.
    pub body: &'a [u8],
    /// Previously persisted subscription state, if this is an auto-refresh operation.
    pub stored: Option<StoredState<'a>>,
    /// Resource bounds; `None` uses [`Limits::default`].
    pub limits: Option<Limits>,
}

/// Historical subscription state used for refresh merges and persistence flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoredState<'a> {
    /// Whether previous fetches established that this subscription uses body encryption.
    pub encrypted: bool,
    /// Previously active metadata map for refresh merge fallback.
    pub meta: Option<&'a MetaMap>,
    /// How stored keys the response omits are treated; see [`MergeMode`].
    pub merge: MergeMode,
}

/// How the response body was treated with respect to body encryption.
///
/// Happ attempts decryption only when the `Encrypt-Tag` header is non-empty **and** the URL has
/// `?key=` or the subscription was stored as encrypted. Otherwise the body is parsed as is and
/// this is `None`, even when a tag was sent. An attempt that fails is [`Error::Decrypt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyEncryption {
    /// No decryption was attempted; the body was parsed as is.
    None,
    /// The body was decrypted.
    Decrypted {
        /// Key ID from `?key=` (e.g. `"key02"`).
        key_id: String,
        /// Key table that authenticated the body (e.g. `"gen1-4.3.0..4.7.1"`).
        table_id: &'static str,
    },
}

/// Why an attempted body decryption failed ([`Error::Decrypt`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecryptFailure {
    /// Stored as encrypted but the URL has no `?key=`: Happ looks up an empty key ID, which
    /// never exists.
    MissingKeyParam,
    /// The crate was built without the `body-crypt` feature.
    CryptDisabled,
    /// Unknown key ID, malformed tag or Base64, or failed authentication.
    #[cfg(feature = "body-crypt")]
    Crypt(body_crypt::BodyCryptError),
}

impl std::fmt::Display for DecryptFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptFailure::MissingKeyParam => write!(f, "the URL has no `key` parameter"),
            DecryptFailure::CryptDisabled => write!(f, "built without the body-crypt feature"),
            #[cfg(feature = "body-crypt")]
            DecryptFailure::Crypt(e) => e.fmt(f),
        }
    }
}

/// A recoverable problem: the offending item was skipped and parsing continued.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// A routing deeplink (body line or `routing` header) could not be decoded.
    InvalidRouting(String),
    /// A body line that is neither a share link, a directive nor a comment.
    SkippedLine(String),
    /// A URL fragment segment without `=`; Happ rejects the import, the crate skips its directives.
    InvalidFragment(String),
}

/// Successfully decoded subscription package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// Top-level payload structure (proxy links, Xray or sing-box JSON).
    pub payload: Payload,
    /// Merged and normalized metadata map.
    pub meta: MetaMap,
    /// Routing deeplinks in delivery order: body lines first, then the `routing` header.
    pub routing: Vec<RoutingAction>,
    /// How body encryption was handled.
    pub body_encryption: BodyEncryption,
    /// Items skipped while parsing.
    pub warnings: Vec<Warning>,
}

/// Errors returned by Happ envelope parsing.
///
/// Variants mirror the vendor client's import error strings where one exists.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Nothing is left after directives are removed; Happ imports this as zero servers.
    EmptyBody,
    /// Server JSON structure is invalid (`parsing_error_invalid_server`).
    InvalidServer(String),
    /// JSON array contains invalid element schemas (`parsing_error_invalid_array_json_server`).
    InvalidJsonArray(String),
    /// Routing profile payload is corrupt or invalid (`parsing_error_invalid_routing`).
    InvalidRouting(String),
    /// Payload structure could not be identified (`parsing_error_invalid_unknown_content_type`).
    UnknownContentType,
    /// Deeplink syntax is malformed (`parsing_error_invalid_deeplink`).
    InvalidDeeplink(String),
    /// Deeplink action prefix is unrecognized (`parsing_error_unknown_deeplink`).
    UnknownDeeplink(String),
    /// Input exceeded configured resource bounds.
    LimitExceeded(String),
    /// Byte stream is not valid UTF-8.
    Utf8(String),
    /// A URL fragment directive segment has no `=` ([`meta::parse_fragment`]).
    InvalidFragment(String),
    /// The body was signalled as encrypted and could not be decrypted.
    ///
    /// Happ instead imports an empty body and wipes the server list; failing lets the caller
    /// keep the previous servers.
    Decrypt {
        /// Key ID from `?key=`; `None` when the URL has none.
        key_id: Option<String>,
        /// What went wrong.
        reason: DecryptFailure,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EmptyBody => write!(f, "the subscription body is empty"),
            Error::InvalidServer(s) => write!(f, "configuration is not valid: {s}"),
            Error::InvalidJsonArray(s) => {
                write!(f, "array of JSON configurations is not valid: {s}")
            }
            Error::InvalidRouting(s) => write!(f, "wrong data for routing profile: {s}"),
            Error::UnknownContentType => write!(f, "unknown content type"),
            Error::InvalidDeeplink(s) => write!(f, "deeplink is not valid: {s}"),
            Error::UnknownDeeplink(s) => write!(f, "unknown deeplink action: {s}"),
            Error::LimitExceeded(s) => write!(f, "resource limit exceeded: {s}"),
            Error::Utf8(e) => write!(f, "UTF-8 error: {e}"),
            Error::InvalidFragment(s) => write!(f, "URL fragment directive without `=`: {s:?}"),
            Error::Decrypt { key_id, reason } => match key_id {
                Some(id) => write!(f, "body decryption with {id} failed: {reason}"),
                None => write!(f, "body decryption failed: {reason}"),
            },
        }
    }
}

impl std::error::Error for Error {}

/// Ingest and parse a Happ-compatible subscription envelope.
pub fn parse(input: &Input) -> Result<Parsed, Error> {
    let limits = input.limits.clone().unwrap_or_default();
    let header_meta = meta::parse_headers(input.headers, &limits)?;

    let (body_bytes, body_encryption) = decrypt_if_signalled(input)?;
    let body_str =
        std::str::from_utf8(body_bytes.as_ref()).map_err(|e| Error::Utf8(e.to_string()))?;

    let detected = body::detect_body(body_str, &limits)?;
    let mut routing = detected.routing;
    let mut warnings = detected.warnings;

    if let Some(link) = header_meta.routing() {
        body::push_routing(link, &limits, &mut routing, &mut warnings);
    }

    let response_meta = meta::merge_body_over_headers(&header_meta, &detected.meta);
    let meta = match input.stored {
        Some(StoredState {
            meta: Some(old),
            merge,
            ..
        }) => meta::refresh_merge(old, &response_meta, merge),
        // Happ reads the fragment only on import, then stores the URL without it.
        _ => {
            let fragment_meta = match meta::parse_fragment(input.url, &limits) {
                Ok(m) => m,
                Err(Error::InvalidFragment(segment)) => {
                    warnings.push(Warning::InvalidFragment(segment));
                    MetaMap::new()
                }
                Err(e) => return Err(e),
            };
            meta::refresh_merge(&fragment_meta, &response_meta, MergeMode::Partial)
        }
    };

    Ok(Parsed {
        payload: detected.payload,
        meta,
        routing,
        body_encryption,
        warnings,
    })
}

fn decrypt_if_signalled<'a>(
    input: &Input<'a>,
) -> Result<(std::borrow::Cow<'a, [u8]>, BodyEncryption), Error> {
    use std::borrow::Cow;

    let tag = input
        .headers
        .iter()
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("encrypt-tag"))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty());
    let key_id = extract_query_param(input.url, "key");
    let stored_encrypted = input.stored.is_some_and(|s| s.encrypted);

    let Some(tag) = tag.filter(|_| key_id.is_some() || stored_encrypted) else {
        return Ok((Cow::Borrowed(input.body), BodyEncryption::None));
    };
    let fail = |reason| Error::Decrypt {
        key_id: key_id.map(str::to_string),
        reason,
    };
    let Some(key_id) = key_id else {
        return Err(fail(DecryptFailure::MissingKeyParam));
    };

    #[cfg(feature = "body-crypt")]
    {
        use body_crypt::{decrypt_body, BodyCryptError, BodyKeySource};

        let body = std::str::from_utf8(input.body).map_err(|_| {
            fail(DecryptFailure::Crypt(BodyCryptError::Base64(
                "body is not ASCII".into(),
            )))
        })?;
        let d = decrypt_body(BodyKeySource::default(), key_id, body, tag)
            .map_err(|e| fail(DecryptFailure::Crypt(e)))?;
        Ok((
            Cow::Owned(d.plaintext),
            BodyEncryption::Decrypted {
                key_id: d.key_id,
                table_id: d.table_id,
            },
        ))
    }
    #[cfg(not(feature = "body-crypt"))]
    {
        let _ = (tag, key_id);
        Err(fail(DecryptFailure::CryptDisabled))
    }
}

/// First value of `target_key` in the URL query; an empty value counts as absent.
fn extract_query_param<'u>(url: &'u str, target_key: &str) -> Option<&'u str> {
    let url = url.split_once('#').map_or(url, |(u, _)| u);
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| k.eq_ignore_ascii_case(target_key))
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_param_extraction() {
        assert_eq!(
            extract_query_param("https://x/s?a=1&key=key02#f", "key"),
            Some("key02")
        );
        assert_eq!(extract_query_param("https://x/s?key=", "key"), None);
        assert_eq!(extract_query_param("https://x/s#?key=key02", "key"), None);
        assert_eq!(extract_query_param("https://x/s", "key"), None);
        assert_eq!(
            extract_query_param("https://x/s?a=1#n?key=key03&profile-title=T", "key"),
            None
        );
        assert_eq!(
            extract_query_param("https://x/s?key=key02#n?key=key03", "key"),
            Some("key02")
        );
    }

    #[cfg(feature = "body-crypt")]
    #[test]
    fn encrypted_body_is_decrypted() {
        use crate::body_crypt::encrypt_with_table;
        use crate::keys::DEFAULT_TABLE;

        let (body_b64, tag_b64) = encrypt_with_table(
            DEFAULT_TABLE,
            "key02",
            b"#profile-title: Secret\nvless://a@b:1#x\n",
        )
        .unwrap();
        let headers = [("Encrypt-Tag".to_string(), tag_b64)];
        let parsed = parse(&Input {
            url: "https://example.com/sub?key=key02",
            headers: &headers,
            body: body_b64.as_bytes(),
            stored: None,
            limits: None,
        })
        .unwrap();
        assert_eq!(
            parsed.body_encryption,
            BodyEncryption::Decrypted {
                key_id: "key02".into(),
                table_id: DEFAULT_TABLE.id,
            }
        );
        assert_eq!(parsed.meta.profile_title(), Some("Secret"));
        assert_eq!(
            parsed.payload,
            Payload::Links(vec!["vless://a@b:1#x".into()])
        );
    }
}
