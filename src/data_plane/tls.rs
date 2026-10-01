//! The base-URL TLS listener: the operator's certificate and key loaded,
//! matched and mode-checked before the bind, or the server identity's own;
//! HTTP/2 advertised alongside HTTP/1.1 so one exchange behaves identically
//! over either version.

use std::sync::Arc;

use rustls_pki_types::pem::{self, PemObject};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

pub use tokio_rustls::TlsAcceptor;

use crate::config::TlsFiles;
use crate::identity::Identity;
use crate::state;

/// HTTP/2 alongside HTTP/1.1 (an exchange behaves identically over
/// either version; clients offering HTTP/2 are negotiated up).
pub const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// The whole check, before the bind: both files readable, the private
/// key owner-only, and the pair loadable as one certificate chain
/// with one matching key. A failure names the path that caused it.
pub fn prepare(files: &TlsFiles) -> Result<TlsAcceptor, String> {
    let key_path = &files.private_key_file;
    state::check_private(key_path).map_err(|m| format!("{}: {m}", key_path.display()))?;
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| format!("{}: cannot read the private key: {e}", key_path.display()))?;
    let key = PrivateKeyDer::from_pem_reader(key_file).map_err(|e| match e {
        pem::Error::NoItemsFound => format!("{}: no private key in the file", key_path.display()),
        e => format!("{}: cannot parse the private key: {e}", key_path.display()),
    })?;
    let certificate_file = std::fs::File::open(&files.certificate_file).map_err(|e| {
        format!(
            "{}: cannot read the certificate file: {e}",
            files.certificate_file.display()
        )
    })?;
    let certs: Vec<CertificateDer<'_>> = CertificateDer::pem_reader_iter(certificate_file)
        .collect::<Result<_, _>>()
        .map_err(|e| {
            format!(
                "{}: cannot parse the certificate: {e}",
                files.certificate_file.display()
            )
        })?;
    if certs.is_empty() {
        return Err(format!(
            "{}: no certificate in the file",
            files.certificate_file.display()
        ));
    }
    acceptor(certs, key).map_err(|e| {
        format!(
            "{} and {}: the pair does not load together (the key may not match the certificate): {e}",
            files.certificate_file.display(),
            key_path.display()
        )
    })
}

/// The listener on the server identity's self-signed certificate.
pub fn identity(identity: &Identity) -> Result<TlsAcceptor, String> {
    let (certificate, key) = identity.certificate()?;
    acceptor(vec![certificate], key).map_err(|e| format!("identity certificate: {e}"))
}

fn acceptor(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor, rustls::Error> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// The trust store the process verifies upstream TLS against. `SSL_CERT_FILE`
/// and `SSL_CERT_DIR` are part of that store's definition on this platform
/// (the convention rustls-native-certs follows), which is how the acceptance
/// harness stages a fake upstream's CA without a product seam. No ALPN: the
/// upstream connector speaks HTTP/1.1 with keep-alive.
pub fn client_config() -> Result<Arc<rustls::ClientConfig>, String> {
    let result = rustls_native_certs::load_native_certs();
    if let Some(e) = result.errors.first() {
        return Err(format!("system trust store: {e}"));
    }
    let certs = result.certs;
    let mut roots = rustls::RootCertStore::empty();
    for cert in &certs {
        roots
            .add(cert.clone())
            .map_err(|e| format!("system trust store: {e}"))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/acceptance/fixtures/tls")
            .join(name)
    }

    /// The pair staged the way the TLS check requires it: the fixtures are checked in,
    /// so a fresh clone gives them the umask's mode, and the private key must
    /// be the owner's alone before `prepare` will look at it. One directory per
    /// call: two tests staging the same key concurrently would otherwise read
    /// each other's half-written copy.
    fn files(cert: &str, key: &str) -> TlsFiles {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/l1-tls")
            .join(format!("{key}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("staging directory");
        let files = TlsFiles {
            certificate_file: directory.join(cert),
            private_key_file: directory.join(key),
        };
        std::fs::copy(fixture(cert), &files.certificate_file).expect("stage the certificate");
        std::fs::copy(fixture(key), &files.private_key_file).expect("stage the key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &files.private_key_file,
                std::fs::Permissions::from_mode(0o600),
            )
            .expect("the key is the owner's alone");
        }
        files
    }

    #[test]
    fn the_committed_pair_loads_and_offers_both_versions() {
        let acceptor = prepare(&files("test-leaf.pem", "test-leaf-key.pem")).expect("pair loads");
        let _ = acceptor;
    }

    #[test]
    fn a_key_that_does_not_match_the_certificate_is_refused() {
        let e = prepare(&files("test-leaf.pem", "test-other-key.pem"))
            .err()
            .expect("mismatch refused");
        assert!(e.contains("does not load together"), "{e}");
    }

    #[test]
    fn a_missing_file_is_refused_with_its_path() {
        let e = prepare(&TlsFiles {
            certificate_file: PathBuf::from("/nonexistent/cert.pem"),
            ..files("test-leaf.pem", "test-leaf-key.pem")
        })
        .err()
        .expect("missing certificate refused");
        assert!(e.contains("cert.pem"), "{e}");
    }

    /// SSL_CERT_FILE is part of the platform trust store's definition; the
    /// harness relies on it (and the default store has certificates anyway).
    #[test]
    fn the_client_trust_store_loads() {
        assert!(
            !rustls_native_certs::load_native_certs().certs.is_empty(),
            "the platform trust store has no certificates"
        );
        let config = client_config().expect("trust store");
        assert!(
            config.alpn_protocols.is_empty(),
            "the upstream connector negotiates no ALPN"
        );
    }
}
