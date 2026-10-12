//! Subscription body form detection.
//!
//! Decrypted subscription text goes through a four-step cascade:
//! 1. Remove `#key: value` directives, other `#` comment lines and `happ://routing/` lines.
//! 2. If the rest is Base64 (possibly line-wrapped) that decodes to text containing `://`,
//!    unwrap it once and repeat step 1 on the decoded text.
//! 3. `[` → [`Payload::JsonArray`]; `{` → [`Payload::XrayJson`] or [`Payload::SingBoxJson`].
//! 4. Otherwise newline-separated share links → [`Payload::Links`].

use serde_json::Value;

use crate::meta::{check_meta_limits, Limits, MetaMap};
use crate::routing::{parse_routing_url, RoutingAction};
use crate::{Error, Warning};

/// Subscription payload container.
///
/// Links are kept verbatim: share-link parsing belongs to the caller, whose parsers already
/// cover every scheme it supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Newline-separated proxy URI links (`vless://`, `vmess://`, `ss://`, `hysteria2://`, etc.).
    Links(Vec<String>),
    /// Single Xray JSON configuration with an `outbounds` array (`CUSTOM` profile).
    XrayJson(Value),
    /// Single sing-box configuration: every outbound has `type` and none has `protocol`.
    ///
    /// Happ would import it as an Xray `CUSTOM` config that cannot run; a client with a
    /// sing-box core can run it as is.
    SingBoxJson(Value),
    /// JSON array of Xray configurations, each with an `outbounds` array.
    ///
    /// Elements are not checked for the sing-box shape: no client serves arrays of sing-box
    /// configurations.
    JsonArray(Vec<Value>),
}

/// Result of [`detect_body`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedBody {
    /// Detected payload.
    pub payload: Payload,
    /// `#key: value` directives found in the body.
    pub meta: MetaMap,
    /// `happ://routing/` lines in body order.
    pub routing: Vec<RoutingAction>,
    /// Lines that were skipped instead of failing the whole body.
    pub warnings: Vec<Warning>,
}

#[derive(Default)]
struct Extracted {
    meta: MetaMap,
    routing: Vec<RoutingAction>,
    warnings: Vec<Warning>,
}

/// Detect the payload structure of a subscription body string.
pub fn detect_body(raw_text: &str, limits: &Limits) -> Result<DetectedBody, Error> {
    if raw_text.len() > limits.max_body_bytes {
        return Err(Error::LimitExceeded(format!(
            "body size {} exceeds limit of {} bytes",
            raw_text.len(),
            limits.max_body_bytes
        )));
    }

    let mut ex = Extracted::default();
    let mut text = extract_directives_and_routing(raw_text, limits, &mut ex)?;

    if let Some(decoded) = unwrap_base64(&text, limits)? {
        text = extract_directives_and_routing(&decoded, limits, &mut ex)?;
    }

    let text = text.trim();
    if text.is_empty() {
        return Err(Error::EmptyBody);
    }

    let payload = if text.starts_with('[') {
        parse_json_array(text, limits)?
    } else if text.starts_with('{') {
        let val: Value =
            serde_json::from_str(text).map_err(|e| Error::InvalidServer(e.to_string()))?;
        if !has_outbounds(&val) {
            return Err(Error::InvalidServer(
                "JSON object has no `outbounds` array".into(),
            ));
        }
        if is_sing_box(&val) {
            Payload::SingBoxJson(val)
        } else {
            Payload::XrayJson(val)
        }
    } else {
        parse_links(text, limits, &mut ex.warnings)?
    };

    Ok(DetectedBody {
        payload,
        meta: ex.meta,
        routing: ex.routing,
        warnings: ex.warnings,
    })
}

fn has_outbounds(val: &Value) -> bool {
    val.get("outbounds").is_some_and(Value::is_array)
}

/// Xray names an outbound's kind `protocol`, sing-box names it `type`. Empty or mixed arrays
/// stay Xray, which is how Happ reads every JSON config.
fn is_sing_box(val: &Value) -> bool {
    let Some(outbounds) = val.get("outbounds").and_then(Value::as_array) else {
        return false;
    };
    !outbounds.is_empty()
        && outbounds
            .iter()
            .all(|o| o.get("type").is_some() && o.get("protocol").is_none())
}

fn parse_json_array(text: &str, limits: &Limits) -> Result<Payload, Error> {
    let val: Value =
        serde_json::from_str(text).map_err(|e| Error::InvalidJsonArray(e.to_string()))?;
    let Value::Array(arr) = val else {
        return Err(Error::InvalidJsonArray("expected JSON array".into()));
    };
    if arr.len() > limits.max_json_array_len {
        return Err(Error::LimitExceeded(format!(
            "JSON array length {} exceeds limit of {}",
            arr.len(),
            limits.max_json_array_len
        )));
    }
    if let Some(i) = arr.iter().position(|v| !has_outbounds(v)) {
        return Err(Error::InvalidJsonArray(format!(
            "element {i} has no `outbounds` array"
        )));
    }
    Ok(Payload::JsonArray(arr))
}

fn parse_links(text: &str, limits: &Limits, warnings: &mut Vec<Warning>) -> Result<Payload, Error> {
    let line_count = text.lines().count();
    if line_count > limits.max_lines {
        return Err(Error::LimitExceeded(format!(
            "line count {line_count} exceeds limit of {}",
            limits.max_lines
        )));
    }

    let mut links = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if has_scheme(line) {
            links.push(line.to_string());
        } else {
            warnings.push(Warning::SkippedLine(line.to_string()));
        }
    }
    if links.is_empty() {
        return Err(Error::UnknownContentType);
    }
    Ok(Payload::Links(links))
}

/// `<scheme>://` with an RFC 3986 scheme name.
fn has_scheme(line: &str) -> bool {
    let Some((scheme, _)) = line.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Whole-body Base64 (step 2): only taken when the decoded text looks like a link list.
fn unwrap_base64(text: &str, limits: &Limits) -> Result<Option<String>, Error> {
    if !crate::b64::is_base64_text(text) {
        return Ok(None);
    }
    let Some(bytes) = crate::b64::decode_lenient(text) else {
        return Ok(None);
    };
    if bytes.len() > limits.max_decoded_bytes {
        return Err(Error::LimitExceeded(
            "decoded body exceeds size limit".into(),
        ));
    }
    Ok(String::from_utf8(bytes).ok().filter(|s| s.contains("://")))
}

/// Step 1: strip directives, comments and routing lines; return the remaining text.
fn extract_directives_and_routing(
    text: &str,
    limits: &Limits,
    ex: &mut Extracted,
) -> Result<String, Error> {
    let mut remaining = String::with_capacity(text.len());
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('#') {
            if let Some((k, v)) = parse_directive(rest) {
                check_meta_limits(&ex.meta, k, v, limits)?;
                ex.meta.insert(k, v);
            }
            continue;
        }
        if is_routing_line(trimmed) {
            push_routing(trimmed, limits, &mut ex.routing, &mut ex.warnings);
            continue;
        }
        remaining.push_str(trimmed);
        remaining.push('\n');
    }
    Ok(remaining)
}

/// Happ's directive grammar is `^#([a-z0-9-]+)\s*:\s*(.*)$`; `rest` follows the `#`.
fn parse_directive(rest: &str) -> Option<(&str, &str)> {
    let key_len = rest
        .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
        .unwrap_or(rest.len());
    if key_len == 0 {
        return None;
    }
    let (key, after) = rest.split_at(key_len);
    let value = after.trim_start().strip_prefix(':')?;
    Some((key, value.trim()))
}

fn is_routing_line(line: &str) -> bool {
    line.get(..15)
        .is_some_and(|p| p.eq_ignore_ascii_case("happ://routing/"))
}

/// Decode a routing deeplink; failures become warnings so one bad profile cannot drop the
/// whole subscription.
pub(crate) fn push_routing(
    link: &str,
    limits: &Limits,
    routing: &mut Vec<RoutingAction>,
    warnings: &mut Vec<Warning>,
) {
    if link.len() > limits.max_routing_json_bytes {
        warnings.push(Warning::InvalidRouting(format!(
            "routing deeplink exceeds {} bytes",
            limits.max_routing_json_bytes
        )));
        return;
    }
    match parse_routing_url(link) {
        Ok(action) => routing.push(action),
        Err(e) => warnings.push(Warning::InvalidRouting(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    use base64::Engine;

    fn detect(body: &str) -> Result<DetectedBody, Error> {
        detect_body(body, &Limits::default())
    }

    fn links(d: &DetectedBody) -> &[String] {
        match &d.payload {
            Payload::Links(l) => l,
            other => panic!("expected Payload::Links, got {other:?}"),
        }
    }

    const ROUTING_ADD: &str =
        "happ://routing/add/eyJOYW1lIjoiRVhBTVBMRS1ST1VUSU5HIiwiRGlyZWN0U2l0ZXMiOltdLCJEaXJlY3RJcCI6W119";

    #[test]
    fn parse_newline_separated_links() {
        let d = detect(
            "#profile-title: My Sub\nvless://uuid@host:443#srv1\nvless://uuid@host:443#srv2\n",
        )
        .unwrap();
        assert_eq!(d.meta.profile_title(), Some("My Sub"));
        assert!(d.routing.is_empty());
        assert_eq!(links(&d).len(), 2);
        assert!(d.warnings.is_empty());
    }

    #[test]
    fn parse_whole_body_base64() {
        let encoded = STANDARD.encode("vless://a@b:1#srv1\nvless://c@d:2#srv2");
        assert_eq!(links(&detect(&encoded).unwrap()).len(), 2);
    }

    #[test]
    fn whole_body_base64_url_safe_and_unpadded() {
        // Plaintext chosen so the encoding contains `-`/`_` and needs padding.
        let plain = "vless://a@b:1#\u{fb}\u{ff}?>\nvless://c@d:2#x";
        for enc in [URL_SAFE_NO_PAD.encode(plain), STANDARD_NO_PAD.encode(plain)] {
            let d = detect(&enc).unwrap_or_else(|e| panic!("{enc}: {e}"));
            assert_eq!(links(&d).len(), 2, "{enc}");
        }
        assert!(URL_SAFE_NO_PAD.encode(plain).contains(['-', '_']));
    }

    #[test]
    fn whole_body_base64_wrapped_at_76_columns() {
        let plain: String = (0..10)
            .map(|i| format!("vless://uuid-{i}@node-{i}.example.org:443#n{i}\n"))
            .collect();
        let enc = STANDARD.encode(&plain);
        let wrapped = enc
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        assert!(wrapped.lines().count() > 1);
        assert_eq!(links(&detect(&wrapped).unwrap()).len(), 10);
    }

    #[test]
    fn base64_body_directives_and_routing_are_extracted() {
        let inner = format!("#profile-title: Inner\n{ROUTING_ADD}\nvless://a@b:1#x\n");
        let d = detect(&format!("#announce: hi\n{}", STANDARD.encode(inner))).unwrap();
        assert_eq!(d.meta.profile_title(), Some("Inner"));
        assert_eq!(d.meta.announce(), Some("hi"));
        assert_eq!(d.routing.len(), 1);
        assert_eq!(links(&d), ["vless://a@b:1#x"]);
    }

    #[test]
    fn bad_lines_are_skipped_with_warnings() {
        let d = detect("vless://a@b:1#ok\nnot a link\n://no-scheme\ntrojan://p@h:443#ok2").unwrap();
        assert_eq!(links(&d), ["vless://a@b:1#ok", "trojan://p@h:443#ok2"]);
        assert_eq!(
            d.warnings,
            [
                Warning::SkippedLine("not a link".into()),
                Warning::SkippedLine("://no-scheme".into()),
            ]
        );
    }

    #[test]
    fn malformed_links_reach_the_caller() {
        let d = detect("vless://not-a-valid@@link\nvless://a@2001:db8::4:8443?x=1#v6").unwrap();
        assert_eq!(
            links(&d),
            [
                "vless://not-a-valid@@link",
                "vless://a@2001:db8::4:8443?x=1#v6"
            ]
        );
        assert!(d.warnings.is_empty());
    }

    #[test]
    fn only_bad_lines_is_unknown_content() {
        assert_eq!(
            detect("hello\nworld").unwrap_err(),
            Error::UnknownContentType
        );
    }

    #[test]
    fn comment_lines_are_not_links_or_directives() {
        let d = detect("# servers below\n#Profile-Title: upper\n#: x\nvless://a@b:1#x").unwrap();
        assert!(d.meta.is_empty());
        assert_eq!(links(&d), ["vless://a@b:1#x"]);
        assert!(d.warnings.is_empty());
    }

    #[test]
    fn directive_grammar() {
        assert_eq!(
            parse_directive("profile-title:x"),
            Some(("profile-title", "x"))
        );
        assert_eq!(parse_directive("a1  :  v w "), Some(("a1", "v w")));
        assert_eq!(parse_directive(" profile-title: x"), None);
        assert_eq!(parse_directive("Profile: x"), None);
        assert_eq!(parse_directive("profile_title: x"), None);
        assert_eq!(parse_directive("profile-title x"), None);
    }

    #[test]
    fn unknown_body_keys_are_kept() {
        let d = detect("#x-vendor-knob: 1\nvless://a@b:1").unwrap();
        assert_eq!(d.meta.get("x-vendor-knob"), Some("1"));
    }

    #[test]
    fn body_meta_limits() {
        let limits = Limits {
            max_meta_keys: 1,
            ..Limits::default()
        };
        assert!(matches!(
            detect_body("#a: 1\n#b: 2\nvless://a@b:1", &limits),
            Err(Error::LimitExceeded(_))
        ));
        // Repeating a key does not count twice.
        assert!(detect_body("#a: 1\n#a: 2\nvless://a@b:1", &limits).is_ok());
    }

    #[test]
    fn invalid_routing_line_is_a_warning() {
        let d = detect(&format!(
            "happ://routing/add/!!!\n{ROUTING_ADD}\nvless://a@b:1"
        ))
        .unwrap();
        assert_eq!(d.routing.len(), 1);
        assert!(matches!(
            d.warnings.as_slice(),
            [Warning::InvalidRouting(_)]
        ));
    }

    #[test]
    fn oversized_routing_line_is_a_warning() {
        let limits = Limits {
            max_routing_json_bytes: 32,
            ..Limits::default()
        };
        let d = detect_body(&format!("{ROUTING_ADD}\nvless://a@b:1"), &limits).unwrap();
        assert!(d.routing.is_empty());
        assert!(matches!(
            d.warnings.as_slice(),
            [Warning::InvalidRouting(_)]
        ));
    }

    #[test]
    fn parse_json_array() {
        let d = detect(r#"[{"outbounds": []}, {"outbounds": []}]"#).unwrap();
        assert!(matches!(d.payload, Payload::JsonArray(ref a) if a.len() == 2));
    }

    #[test]
    fn json_array_elements_need_outbounds() {
        assert!(matches!(
            detect(r#"[{"outbounds": []}, {"remarks": "x"}]"#),
            Err(Error::InvalidJsonArray(_))
        ));
    }

    #[test]
    fn json_object_needs_outbounds_array() {
        assert!(matches!(
            detect(r#"{"outbounds": [{"protocol": "freedom"}]}"#)
                .unwrap()
                .payload,
            Payload::XrayJson(_)
        ));
        for bad in [r#"{"remarks": "x"}"#, r#"{"outbounds": {}}"#] {
            assert!(matches!(detect(bad), Err(Error::InvalidServer(_))), "{bad}");
        }
    }

    #[test]
    fn sing_box_config_is_not_xray() {
        let sing_box = r#"{"outbounds": [{"type": "vless", "tag": "a"}, {"type": "direct"}]}"#;
        assert!(matches!(
            detect(sing_box).unwrap().payload,
            Payload::SingBoxJson(_)
        ));
        for xray in [
            r#"{"outbounds": []}"#,
            r#"{"outbounds": [{"protocol": "vless", "type": "x"}]}"#,
            r#"{"outbounds": [{"type": "vless"}, {"protocol": "freedom"}]}"#,
            r#"{"outbounds": [{"type": "vless"}, {"tag": "untyped"}]}"#,
        ] {
            assert!(
                matches!(detect(xray).unwrap().payload, Payload::XrayJson(_)),
                "{xray}"
            );
        }
    }

    #[test]
    fn routing_off_line_is_surfaced() {
        let d = detect(&format!("happ://routing/off\n{ROUTING_ADD}\nvless://a@b:1")).unwrap();
        assert!(matches!(
            d.routing.as_slice(),
            [RoutingAction::Off, RoutingAction::Add(_)]
        ));
        assert_eq!(links(&d), ["vless://a@b:1"]);
        assert!(d.warnings.is_empty());
    }

    #[test]
    fn parse_empty_body_rejected() {
        assert_eq!(detect("   ").unwrap_err(), Error::EmptyBody);
        assert_eq!(detect("#profile-title: x\n").unwrap_err(), Error::EmptyBody);
    }
}
