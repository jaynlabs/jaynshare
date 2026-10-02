//! The server identity: one long-lived key in the state directory, a
//! self-signed certificate on it for the base-URL listener, and the pin
//! clients check instead of a name or a CA — `sha256/` and the base64 of the
//! key's SubjectPublicKeyInfo digest. Moving the listener to another address
//! never changes the pin.

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::{CertificateError, DigitallySignedStruct, OtherError, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

/// The key's file name in the state directory.
pub const KEY_FILE: &str = "server-identity-key.pem";

const PIN_PREFIX: &str = "sha256/";

pub struct Identity {
    key: KeyPair,
    pin: String,
}

impl Identity {
    /// The key in `state_dir`, generated on first start. A key that exists
    /// but cannot be used is an error, never a regeneration: a new key would
    /// strand every client that pinned the old one.
    pub fn load_or_generate(state_dir: &Path) -> Result<Identity, String> {
        let path = state_dir.join(KEY_FILE);
        if path.exists() {
            let identity = Self::load(state_dir)?;
            tracing::info!(event = "identity_loaded", pin = %identity.pin, "using the server identity already in the state directory");
            return Ok(identity);
        }
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("identity key generation: {e}"))?;
        crate::state::write_private_atomic(&path, key.serialize_pem().as_bytes())
            .map_err(|e| format!("{}: cannot write: {e}", path.display()))?;
        let identity = Self::from_key(key);
        tracing::info!(event = "identity_generated", pin = %identity.pin, "generated the server identity; clients pin it");
        Ok(identity)
    }

    /// The key already in `state_dir`.
    pub fn load(state_dir: &Path) -> Result<Identity, String> {
        let path = state_dir.join(KEY_FILE);
        crate::state::check_private(&path)?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: cannot read: {e}", path.display()))?;
        let key = KeyPair::from_pem(&text)
            .map_err(|e| format!("{}: not a private key: {e}", path.display()))?;
        Ok(Self::from_key(key))
    }

    fn from_key(key: KeyPair) -> Identity {
        let pin = pin_of_spki(&key.public_key_der());
        Identity { key, pin }
    }

    pub fn pin(&self) -> &str {
        &self.pin
    }

    /// A self-signed certificate on the key, made at each start: a client
    /// checks only the pin, so the names and dates carry nothing.
    pub fn certificate(&self) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Jaynshare server identity");
        let certificate = params
            .self_signed(&self.key)
            .map_err(|e| format!("identity certificate: {e}"))?;
        let key = PrivateKeyDer::Pkcs8(self.key.serialize_der().into());
        Ok((certificate.der().clone(), key))
    }
}

fn pin_of_spki(spki: &[u8]) -> String {
    let digest = Sha256::digest(spki);
    format!(
        "{PIN_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// The pin of the key a certificate carries.
pub fn pin_of_certificate(der: &[u8]) -> Result<String, String> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| format!("not an X.509 certificate: {e}"))?;
    Ok(pin_of_spki(certificate.public_key().raw))
}

/// `sha256/` and the base64 of 32 bytes.
pub fn is_pin(text: &str) -> bool {
    text.strip_prefix(PIN_PREFIX)
        .and_then(|digest| {
            base64::engine::general_purpose::STANDARD
                .decode(digest)
                .ok()
        })
        .is_some_and(|digest| digest.len() == 32)
}

/// The client's check of a pinned server: the certificate carries the pinned
/// key and the handshake is signed with it. Names, dates and issuers are not
/// checked; the pin replaces them.
#[derive(Debug)]
pub struct PinnedVerifier {
    pin: String,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    pub fn new(pin: &str, algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self {
            pin: pin.to_string(),
            algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = pin_of_certificate(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if presented == self.pin {
            return Ok(ServerCertVerified::assertion());
        }
        let mismatch: Box<dyn std::error::Error + Send + Sync> = format!(
            "the server's identity {presented} is not the pinned {}",
            self.pin
        )
        .into();
        Err(rustls::Error::InvalidCertificate(CertificateError::Other(
            OtherError(Arc::from(mismatch)),
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("jaynshare-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    #[test]
    fn the_key_survives_a_restart_and_the_certificate_carries_its_pin() {
        let dir = scratch();
        let first = Identity::load_or_generate(&dir).expect("generated");
        let second = Identity::load_or_generate(&dir).expect("loaded");
        assert_eq!(first.pin(), second.pin());
        assert!(is_pin(first.pin()), "{}", first.pin());
        let (certificate, _) = second.certificate().expect("certificate");
        assert_eq!(
            pin_of_certificate(&certificate).expect("parses"),
            first.pin()
        );
    }

    #[test]
    fn an_unusable_key_is_refused_not_replaced() {
        let dir = scratch();
        crate::state::write_private_atomic(&dir.join(KEY_FILE), b"not a key").expect("planted");
        let e = Identity::load_or_generate(&dir).err().expect("refused");
        assert!(e.contains(KEY_FILE), "{e}");
        assert_eq!(
            std::fs::read(dir.join(KEY_FILE)).expect("kept"),
            b"not a key"
        );
    }

    #[test]
    fn a_pin_is_a_sha256_digest() {
        assert!(!is_pin("sha256/abc"));
        assert!(!is_pin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(is_pin(
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ));
    }
}
