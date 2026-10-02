//! The invite: one pasteable string that lets a machine join a pool. It names
//! the server, the identity the server must present, the key its client is
//! signed with, and the one-time claim: `jsi1_` and the base64url of a JSON
//! object (`v`, `base_url`, `identity`, `signing_key`, `client_id`, `code`).

use base64::Engine as _;
use serde::{Deserialize, Serialize};

const PREFIX: &str = "jsi1_";
const VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub base_url: String,
    /// The server identity pin; `None` for a server on an operator
    /// certificate, which the system trust store checks instead.
    pub identity: Option<String>,
    /// The minisign public key the server's client kit is signed with.
    pub signing_key: String,
    pub client_id: String,
    pub code: String,
}

#[derive(Serialize, Deserialize)]
struct Token {
    v: u64,
    #[serde(flatten)]
    invite: Invite,
}

impl Invite {
    pub fn encode(&self) -> String {
        let token = Token {
            v: VERSION,
            invite: self.clone(),
        };
        let json = serde_json::to_vec(&token).expect("an invite serialises");
        format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        )
    }

    /// The invite `text` spells, its members checked; the base URL's scheme
    /// is the joining machine's to judge.
    pub fn decode(text: &str) -> Result<Invite, String> {
        let body = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or_else(|| format!("an invite starts with {PREFIX}"))?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| "the invite is damaged: copy it again, whole".to_string())?;
        let value: serde_json::Value = serde_json::from_slice(&json)
            .map_err(|_| "the invite is damaged: copy it again, whole".to_string())?;
        if value["v"] != VERSION {
            return Err(format!(
                "the invite is version {}; this jaynshare reads version {VERSION}",
                value["v"]
            ));
        }
        let token: Token =
            serde_json::from_value(value).map_err(|e| format!("the invite is incomplete: {e}"))?;
        token.invite.check()?;
        Ok(token.invite)
    }

    fn check(&self) -> Result<(), String> {
        let origin: http::Uri = self
            .base_url
            .parse()
            .map_err(|_| format!("the invite's server {:?} is not a URL", self.base_url))?;
        if !matches!(origin.scheme_str(), Some("http" | "https")) || origin.host().is_none() {
            return Err(format!(
                "the invite's server {:?} is not an http(s) origin",
                self.base_url
            ));
        }
        if let Some(pin) = &self.identity
            && !crate::identity::is_pin(pin)
        {
            return Err(format!("the invite's server identity {pin:?} is not a pin"));
        }
        self.signing_key()?;
        crate::registry::Registry::validate_id(&self.client_id)?;
        if self.code.is_empty() {
            return Err("the invite carries no code".into());
        }
        Ok(())
    }

    pub fn signing_key(&self) -> Result<crate::bundle::PinnedKey, String> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.signing_key)
            .map_err(|_| "the invite's signing key is not base64".to_string())
            .and_then(crate::bundle::PinnedKey::from_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn invite() -> Invite {
        let mut key = b"Ed".to_vec();
        key.extend([7u8; 40]);
        Invite {
            base_url: "https://100.64.0.1:8443".into(),
            identity: Some(PIN.into()),
            signing_key: base64::engine::general_purpose::STANDARD.encode(key),
            client_id: "alice".into(),
            code: "jse2_code".into(),
        }
    }

    fn token(value: serde_json::Value) -> String {
        format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        )
    }

    #[test]
    fn an_invite_reads_back_as_written() {
        let text = invite().encode();
        assert!(text.starts_with("jsi1_"), "{text}");
        assert!(
            text[PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "pasteable as one word: {text}"
        );
        assert_eq!(Invite::decode(&format!("  {text}\n")), Ok(invite()));
    }

    #[test]
    fn a_server_without_a_pin_reads_back_as_none() {
        let unpinned = Invite {
            identity: None,
            ..invite()
        };
        assert_eq!(Invite::decode(&unpinned.encode()), Ok(unpinned));
    }

    #[test]
    fn a_damaged_or_foreign_invite_is_refused() {
        let text = invite().encode();
        assert!(Invite::decode(&text[..text.len() - 4]).is_err());
        assert!(Invite::decode(&text.replace("jsi1_", "jsi2_")).is_err());
        let mut later = serde_json::to_value(invite()).expect("value");
        later["v"] = 2.into();
        let refused = Invite::decode(&token(later)).expect_err("a later version");
        assert!(refused.contains("version 2"), "{refused}");
    }

    #[test]
    fn every_member_is_checked() {
        let cases: [(&str, serde_json::Value); 4] = [
            ("base_url", "ftp://host".into()),
            ("identity", "sha256/short".into()),
            ("signing_key", "RWQ=".into()),
            ("client_id", "Not An Id".into()),
        ];
        for (member, bad) in cases {
            let mut value = serde_json::to_value(invite()).expect("value");
            value["v"] = VERSION.into();
            value[member] = bad;
            assert!(Invite::decode(&token(value)).is_err(), "{member}");
        }
    }
}
