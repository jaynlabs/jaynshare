//! The account-intent token of `x-jaynshare-account`: `pin.<reference64>` or
//! `pref.<reference64>`, the reference
//! in canonical unpadded base64url. Resolution against the pool is the
//! exchange's.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{HeaderMap, HeaderName};

pub const X_JAYNSHARE_ACCOUNT: HeaderName = HeaderName::from_static("x-jaynshare-account");

/// The decoded reference is at most this long.
const MAX_REFERENCE_BYTES: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    /// This account or nobody.
    Pin(String),
    /// This account first while it is eligible.
    Preference(String),
}

impl Intent {
    pub fn reference(&self) -> &str {
        match self {
            Intent::Pin(r) | Intent::Preference(r) => r,
        }
    }

    pub fn is_pin(&self) -> bool {
        matches!(self, Intent::Pin(_))
    }
}

/// The token for a reference. Every byte of it is
/// URL-unreserved — the discriminator, the dot and unpadded base64url — so it
/// reaches a proxy byte-identical whether or not the caller percent-decodes
/// the proxy URL's user information first.
pub fn encode_token(pin: bool, reference: &str) -> String {
    let discriminator = if pin { "pin" } else { "pref" };
    format!(
        "{discriminator}.{}",
        URL_SAFE_NO_PAD.encode(reference.as_bytes())
    )
}

/// At most one field, no comma-joined value, no surrounding whitespace,
/// nothing outside the token grammar. `Ok(None)` is absence.
pub fn parse(headers: &HeaderMap) -> Result<Option<Intent>, String> {
    let mut values = headers.get_all(X_JAYNSHARE_ACCOUNT).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err("x-jaynshare-account appears more than once".into());
    }
    let token = value
        .to_str()
        .map_err(|_| "x-jaynshare-account is not visible ASCII".to_string())?;
    parse_token(token).map(Some)
}

pub fn parse_token(token: &str) -> Result<Intent, String> {
    if token.is_empty() || token.trim() != token || token.contains(',') {
        return Err("x-jaynshare-account carries whitespace, a comma or nothing".into());
    }
    let (encoded, pin) = if let Some(rest) = token.strip_prefix("pin.") {
        (rest, true)
    } else if let Some(rest) = token.strip_prefix("pref.") {
        (rest, false)
    } else {
        return Err("x-jaynshare-account must start with pin. or pref.".into());
    };
    let reference = decode_reference(encoded)?;
    Ok(if pin {
        Intent::Pin(reference)
    } else {
        Intent::Preference(reference)
    })
}

/// Canonical unpadded base64url of a non-empty UTF-8 reference of at most
/// 1,024 bytes with no NUL, CR, LF or other ASCII control character.
fn decode_reference(encoded: &str) -> Result<String, String> {
    let malformed =
        |what: &str| format!("x-jaynshare-account reference is not canonical base64url: {what}");
    if encoded.is_empty() {
        return Err(malformed("empty"));
    }
    if !encoded
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(malformed("a character outside the base64url alphabet"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| malformed("undecodable"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(malformed("non-canonical encoding"));
    }
    if bytes.len() > MAX_REFERENCE_BYTES {
        return Err("x-jaynshare-account reference exceeds 1024 bytes".into());
    }
    let reference = String::from_utf8(bytes)
        .map_err(|_| "x-jaynshare-account reference is not UTF-8".to_string())?;
    if reference.is_empty() || reference.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("x-jaynshare-account reference is empty or carries a control character".into());
    }
    Ok(reference)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    /// The allowed character set: letters, digits, `-`, `.`, `_`, `~`. The product never
    /// has to check it — [`encode_token`] cannot leave the set — so the
    /// checker is the assertion's, not the proxy's.
    fn is_unreserved(token: &str) -> bool {
        token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    }

    fn with(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(X_JAYNSHARE_ACCOUNT, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn round_trips_unicode_references_in_both_forms() {
        let token = encode_token(true, "Zoë (Acme)");
        assert_eq!(
            parse(&with(&[&token])).unwrap(),
            Some(Intent::Pin("Zoë (Acme)".into()))
        );
        let token = encode_token(false, "a@x.io");
        assert_eq!(
            parse(&with(&[&token])).unwrap(),
            Some(Intent::Preference("a@x.io".into()))
        );
        assert_eq!(parse(&HeaderMap::new()).unwrap(), None);
    }

    /// Whatever the reference, the generated token is unreserved and
    /// parses back to the reference it named.
    #[test]
    fn generation_never_leaves_the_unreserved_set() {
        for reference in [
            "Alpha Desk",
            "a@x.io",
            "Zoë (Acme)",
            "plus+slash/and=pad",
            "~tilde-dot.under_score",
            "日本語",
            &"x".repeat(1024),
        ] {
            for pin in [true, false] {
                let token = encode_token(pin, reference);
                assert!(
                    is_unreserved(&token),
                    "token {token:?} for {reference:?} leaves the unreserved set"
                );
                let parsed = parse_token(&token).expect("the generated token parses");
                assert_eq!(parsed.reference(), reference);
                assert_eq!(parsed.is_pin(), pin);
            }
        }
    }

    /// A token carrying anything outside that set is not one: a caller that
    /// percent-encoded the user information gets its token refused rather
    /// than silently resolved.
    #[test]
    fn a_percent_encoded_token_is_not_a_token() {
        let token = encode_token(true, "Alpha Desk");
        let encoded = token.replace('.', "%2E");
        assert!(!is_unreserved(&encoded));
        assert!(parse_token(&encoded).is_err());
    }

    #[test]
    fn duplicates_commas_padding_and_controls_are_malformed() {
        let ok = encode_token(true, "a");
        assert!(parse(&with(&[&ok, &ok])).is_err());
        assert!(parse_token(&format!("{ok},{ok}")).is_err());
        assert!(parse_token(&format!(" {ok}")).is_err());
        assert!(parse_token("pin.YQ==").is_err());
        assert!(
            parse_token("pin.YR").is_err(),
            "non-canonical trailing bits"
        );
        assert!(parse_token("pin.").is_err());
        assert!(parse_token("nope.YQ").is_err());
        assert!(parse_token(&encode_token(true, "a\nb")).is_err());
        assert!(parse_token(&encode_token(true, &"x".repeat(1025))).is_err());
        assert!(parse_token(&encode_token(true, &"x".repeat(1024))).is_ok());
    }
}
