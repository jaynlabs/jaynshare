//! The MITM CA and its three files.
//!
//! The CA key pair exists only inside [`Ca::generate`]'s frame: the CA
//! certificate is written for the clients to import, the leaf is signed, and
//! the CA private key is dropped without ever reaching a file — nothing on
//! disk can sign a new certificate. The only writers of the three files are
//! first-start generation and [`Ca::rotate`]; the start-time check never
//! regenerates over unusable material, it refuses.
//!
//! Wiring contract: the server calls [`Ca::load_or_generate`] once at start
//! when `mitm.enabled` (a `Result<Ca, _>` failure is the `unusable` state),
//! [`Ca::warn_expiry`] at start and once a day, and [`Ca::rotate`] from the
//! rotate verb/route. This module logs the CA's own lines; it
//! owns no route and no verb.

use base64::Engine as _;
use std::fs;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::{Pem, parse_x509_pem};

/// The three fixed names, relative to the state directory.
pub const CA_CERT_FILE: &str = "mitm-ca.pem";
pub const LEAF_CERT_FILE: &str = "mitm-leaf.pem";
pub const LEAF_KEY_FILE: &str = "mitm-leaf-key.pem";

/// The whole intercept set, one port; the leaf carries every name and the
/// listener intercepts exactly these.
pub const INTERCEPT_NAMES: [&str; 2] = ["api.anthropic.com", "probe.jaynshare.invalid"];

/// Both certificates, valid from one hour before generation until
/// 730 days after it. Not configurable.
const BACKDATING: Duration = Duration::hours(1);
const VALIDITY: Duration = Duration::days(730);
/// The `expiring` state and its warning start 30 days out.
const EXPIRY_WARNING: Duration = Duration::days(30);

/// The states `status` shows for the CA; `unusable` is what a
/// failed [`Ca::load_or_generate`] means and is the wiring's to report.
pub const STATE_OK: &str = "ok";
pub const STATE_EXPIRING: &str = "expiring";
pub const STATE_UNUSABLE: &str = "unusable";

/// The loaded trust material: the CA for the bundle and the fingerprint,
/// the leaf pair for the TLS resolver of an intercepted tunnel.
pub struct Ca {
    ca_certificate: CertificateDer<'static>,
    leaf_certificate: CertificateDer<'static>,
    leaf_key: PrivateKeyDer<'static>,
    not_after: OffsetDateTime,
}

impl Ca {
    /// Generate CA and leaf in memory, write the three files (certificates
    /// `0644`, leaf key `0600` on POSIX), drop the CA key.
    pub fn generate(state_dir: &Path, now: OffsetDateTime) -> Result<Ca, String> {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("CA key generation: {e}"))?;
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Jaynshare local CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        // X.509 carries whole seconds; the value the surfaces report is the
        // certificate's, before and after a restart.
        let not_before = (now - BACKDATING)
            .replace_nanosecond(0)
            .expect("zero is in range");
        let not_after = (now + VALIDITY)
            .replace_nanosecond(0)
            .expect("zero is in range");
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        let ca_certificate = ca_params
            .self_signed(&ca_key)
            .map_err(|e| format!("CA certificate generation: {e}"))?;

        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("leaf key generation: {e}"))?;
        let mut leaf_params = CertificateParams::new(
            INTERCEPT_NAMES
                .iter()
                .map(|n| (*n).to_owned())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| format!("leaf parameters: {e}"))?;
        // `new` leaves rcgen's placeholder subject; name the leaf for what it is.
        leaf_params.distinguished_name = DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Jaynshare intercept leaf");
        // The standard chain check: RFC 5280 links a certificate to its
        // issuer's key by the Authority Key Identifier, and strict verifiers
        // (Python 3.13+'s default context) refuse a leaf without one.
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        let leaf_certificate = leaf_params
            .signed_by(&leaf_key, &ca_certificate, &ca_key)
            .map_err(|e| format!("leaf certificate generation: {e}"))?;

        // On Windows the ACL distinction (certificates Everyone-readable,
        // leaf key private) lands with the Windows client work; the POSIX
        // modes are written here.
        write_file(
            &state_dir.join(CA_CERT_FILE),
            ca_certificate.pem().as_bytes(),
            0o644,
        )?;
        write_file(
            &state_dir.join(LEAF_CERT_FILE),
            leaf_certificate.pem().as_bytes(),
            0o644,
        )?;
        write_file(
            &state_dir.join(LEAF_KEY_FILE),
            leaf_key.serialize_pem().as_bytes(),
            0o600,
        )?;
        // `ca_key` dies here: no file holds it, nothing on disk can sign.

        Ok(Ca {
            ca_certificate: ca_certificate.der().clone(),
            leaf_certificate: leaf_certificate.der().clone(),
            leaf_key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            not_after,
        })
    }

    /// The start-time check: all three files absent → generate and
    /// log that clients must import the new CA; all present, chain valid,
    /// leaf covering the intercept set, not expired → use them; anything
    /// else → an error naming the file and the rotate verb, never a
    /// regeneration.
    pub fn load_or_generate(state_dir: &Path, now: OffsetDateTime) -> Result<Ca, String> {
        let ca_path = state_dir.join(CA_CERT_FILE);
        let leaf_path = state_dir.join(LEAF_CERT_FILE);
        let key_path = state_dir.join(LEAF_KEY_FILE);
        if !ca_path.exists() && !leaf_path.exists() && !key_path.exists() {
            let ca = Self::generate(state_dir, now)?;
            tracing::info!(
                event = "ca_generated",
                fingerprint = %ca.fingerprint(),
                "generated a new CA; clients must import it before their first MITM launch"
            );
            return Ok(ca);
        }
        let ca = Self::load(&ca_path, &leaf_path, &key_path, now)?;
        tracing::info!(
            event = "ca_loaded",
            fingerprint = %ca.fingerprint(),
            "using the CA already in the state directory"
        );
        Ok(ca)
    }

    /// Regenerate all three files and replace them
    /// atomically; log one line carrying the old and the new fingerprint.
    pub fn rotate(state_dir: &Path, now: OffsetDateTime) -> Result<Ca, String> {
        let old = fs::read(state_dir.join(CA_CERT_FILE))
            .ok()
            .and_then(|bytes| parse_pem(&bytes).ok())
            .map(|pem| fingerprint(&pem.contents))
            .unwrap_or_else(|| "unavailable".into());
        let ca = Self::generate(state_dir, now)?;
        tracing::info!(
            event = "ca_rotated",
            old_fingerprint = %old,
            new_fingerprint = %ca.fingerprint(),
            "rotated the CA; every enrolled client needs the CA-update bundle before its next MITM launch"
        );
        Ok(ca)
    }

    fn load(
        ca_path: &Path,
        leaf_path: &Path,
        key_path: &Path,
        now: OffsetDateTime,
    ) -> Result<Ca, String> {
        let name = |p: &Path| {
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("trust material")
                .to_owned()
        };
        let ca_bytes = fs::read(ca_path).map_err(|e| unusable(&name(ca_path), e.to_string()))?;
        let leaf_bytes =
            fs::read(leaf_path).map_err(|e| unusable(&name(leaf_path), e.to_string()))?;
        let key_bytes = fs::read(key_path).map_err(|e| unusable(&name(key_path), e.to_string()))?;

        let pem_ca = parse_pem(&ca_bytes).map_err(|e| unusable(&name(ca_path), e))?;
        let pem_leaf = parse_pem(&leaf_bytes).map_err(|e| unusable(&name(leaf_path), e))?;
        let ca = pem_ca
            .parse_x509()
            .map_err(|e| unusable(&name(ca_path), format!("not a certificate: {e}")))?;
        let leaf = pem_leaf
            .parse_x509()
            .map_err(|e| unusable(&name(leaf_path), format!("not a certificate: {e}")))?;
        if !ca.is_ca() {
            return Err(unusable(
                &name(ca_path),
                "the certificate is not a CA".into(),
            ));
        }
        leaf.verify_signature(Some(ca.public_key()))
            .map_err(|e| unusable(&name(leaf_path), format!("not signed by the CA: {e}")))?;
        let sans: Vec<String> = leaf
            .extensions()
            .iter()
            .filter_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .flat_map(|san| san.general_names.iter())
            .filter_map(|gn| match gn {
                GeneralName::DNSName(d) => Some((*d).to_owned()),
                _ => None,
            })
            .collect();
        for expected in INTERCEPT_NAMES {
            if !sans.iter().any(|got| got.eq_ignore_ascii_case(expected)) {
                return Err(unusable(
                    &name(leaf_path),
                    format!("the leaf does not cover {expected}"),
                ));
            }
        }
        for (what, validity) in [
            (name(ca_path), ca.validity()),
            (name(leaf_path), leaf.validity()),
        ] {
            if validity.not_after.to_datetime() < now {
                return Err(unusable(&what, "the certificate has expired".into()));
            }
            if validity.not_before.to_datetime() > now {
                return Err(unusable(&what, "the certificate is not yet valid".into()));
            }
        }
        let leaf_key = PrivateKeyDer::from_pem_slice(&key_bytes).map_err(|e| {
            unusable(
                &name(key_path),
                format!("cannot parse the private key: {e}"),
            )
        })?;
        Ok(Ca {
            ca_certificate: CertificateDer::from(pem_ca.contents.clone()),
            leaf_certificate: CertificateDer::from(pem_leaf.contents.clone()),
            leaf_key,
            not_after: leaf.validity().not_after.to_datetime(),
        })
    }

    /// SHA-256 of the DER-encoded CA certificate, colon-separated
    /// upper-case hex pairs.
    pub fn fingerprint(&self) -> String {
        fingerprint(self.ca_certificate.as_ref())
    }

    /// The CA certificate as PEM — what a client imports and
    /// what a claim answers. It holds no secret.
    pub fn certificate_pem(&self) -> String {
        let body = base64::engine::general_purpose::STANDARD.encode(self.ca_certificate.as_ref());
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// The leaf presented on intercepted tunnels.
    pub fn leaf_certificate(&self) -> &CertificateDer<'static> {
        &self.leaf_certificate
    }

    /// The leaf's private key, owner-only on disk.
    pub fn leaf_key(&self) -> &PrivateKeyDer<'static> {
        &self.leaf_key
    }

    /// The CA's (and the leaf's) expiry.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// `ok`, or `expiring` from 30 days out.
    pub fn expiry_state(&self, now: OffsetDateTime) -> &'static str {
        if self.not_after - now <= EXPIRY_WARNING {
            STATE_EXPIRING
        } else {
            STATE_OK
        }
    }

    /// The expiry warning, at start and once a day.
    pub fn warn_expiry(&self, now: OffsetDateTime) {
        if self.expiry_state(now) == STATE_EXPIRING {
            tracing::warn!(
                event = "ca_expiring",
                not_after = %crate::timestamp::rfc3339(self.not_after),
                "the CA certificate expires within 30 days; run `jaynshare ca rotate` and hand every client the CA-update bundle"
            );
        }
    }
}

fn unusable(file: &str, cause: String) -> String {
    format!(
        "{file}: {cause}; the CA trust material is unusable — run `jaynshare ca rotate` to regenerate it"
    )
}

/// The decoded DER of a PEM file's first object.
fn parse_pem(pem_bytes: &[u8]) -> Result<Pem, String> {
    let (_, pem): (_, Pem) = parse_x509_pem(pem_bytes).map_err(|e| format!("not PEM: {e}"))?;
    Ok(pem)
}

/// The fingerprint rendering.
pub fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let hex: Vec<String> = digest.iter().map(|b| format!("{b:02X}")).collect();
    hex.join(":")
}

/// One file: a same-directory temporary, fsync, rename.
fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("mitm.pem");
    let tmp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode; // Windows inherits the directory's ACL
        fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("{}: cannot write: {e}", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PublicKeyData as _;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("jns-ca-{name}-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).expect("temp state dir");
        dir
    }

    fn read(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(name)).expect("the generated file")
    }

    /// The parsed certificate of a generated file; the buffer stays alive
    /// beside the certificate.
    macro_rules! parsed {
        ($dir:expr, $name:expr, $pem:ident, $cert:ident) => {
            let $pem = read(&$dir, $name);
            let (_, $pem) = parse_x509_pem($pem.as_bytes()).expect("PEM");
            let $cert = $pem.parse_x509().expect("certificate");
        };
    }

    #[test]
    fn generation_writes_exactly_three_files_and_drops_the_ca_key() {
        let dir = temp_dir("generate");
        Ca::generate(&dir, OffsetDateTime::now_utc()).expect("generate");
        let mut names: Vec<String> = fs::read_dir(&dir)
            .expect("state dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["mitm-ca.pem", "mitm-leaf-key.pem", "mitm-leaf.pem"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |name: &str| {
                fs::metadata(dir.join(name))
                    .expect("meta")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(CA_CERT_FILE), 0o644);
            assert_eq!(mode(LEAF_CERT_FILE), 0o644);
            assert_eq!(mode(LEAF_KEY_FILE), 0o600);
        }
        // The only private key on disk is the leaf's, and its public key is
        // not the CA's: no file can sign a new certificate.
        assert!(!read(&dir, CA_CERT_FILE).contains("PRIVATE KEY"));
        assert!(!read(&dir, LEAF_CERT_FILE).contains("PRIVATE KEY"));
        let leaf_pair = KeyPair::from_pkcs8_pem_and_sign_algo(
            &read(&dir, LEAF_KEY_FILE),
            &PKCS_ECDSA_P256_SHA256,
        )
        .expect("leaf key parses");
        parsed!(dir, CA_CERT_FILE, ca_pem, ca);
        assert_ne!(
            leaf_pair.der_bytes(),
            ca.tbs_certificate.subject_pki.subject_public_key.as_ref(),
            "the leaf key is not the CA key"
        );
    }

    /// The expiry a fresh CA reports is its certificate's, so a
    /// restart that loads the files reports the same instant.
    #[test]
    fn a_generated_ca_reports_the_expiry_its_files_load_with() {
        let dir = temp_dir("expiry");
        let now = OffsetDateTime::now_utc()
            .replace_nanosecond(123_456_789)
            .expect("in range");
        let generated = Ca::generate(&dir, now).expect("generate");
        let loaded = Ca::load_or_generate(&dir, now).expect("load");
        assert_eq!(generated.not_after(), loaded.not_after());
        assert_eq!(generated.not_after().nanosecond(), 0);
    }

    #[test]
    fn the_leaf_carries_the_intercept_set_and_both_certificates_the_specified_validity() {
        let dir = temp_dir("validity");
        let now = OffsetDateTime::now_utc();
        Ca::generate(&dir, now).expect("generate");
        parsed!(dir, CA_CERT_FILE, ca_pem, ca);
        parsed!(dir, LEAF_CERT_FILE, leaf_pem, leaf);
        assert!(ca.is_ca(), "the CA carries the basic constraint");
        assert!(!leaf.is_ca(), "the leaf is not a CA");
        leaf.verify_signature(Some(ca.public_key()))
            .expect("the leaf verifies against the CA");
        let sans: Vec<String> = leaf
            .extensions()
            .iter()
            .filter_map(|e| match e.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => Some(san),
                _ => None,
            })
            .flat_map(|san| san.general_names.iter())
            .filter_map(|gn| match gn {
                GeneralName::DNSName(d) => Some((*d).to_owned()),
                _ => None,
            })
            .collect();
        assert_eq!(sans.len(), INTERCEPT_NAMES.len(), "exactly the set");
        for name in INTERCEPT_NAMES {
            assert!(sans.iter().any(|got| got.eq_ignore_ascii_case(name)));
        }
        for cert in [&ca, &leaf] {
            let validity = cert.validity();
            let span = validity.not_after.to_datetime() - validity.not_before.to_datetime();
            assert_eq!(span.whole_days(), VALIDITY.whole_days(), "730 days");
            assert!(
                validity.not_before.to_datetime() <= now - Duration::hours(1),
                "valid from an hour before generation, so at least an hour in the past"
            );
        }
    }

    #[test]
    fn the_start_check_accepts_the_files_it_wrote() {
        let dir = temp_dir("load-ok");
        let generated = Ca::generate(&dir, OffsetDateTime::now_utc()).expect("generate");
        let loaded =
            Ca::load_or_generate(&dir, OffsetDateTime::now_utc()).expect("the check accepts");
        assert_eq!(generated.fingerprint(), loaded.fingerprint());
        assert!(loaded.fingerprint().contains(':'));
    }

    #[test]
    fn the_start_check_never_regenerates_and_names_the_file_and_the_verb() {
        let now = OffsetDateTime::now_utc();
        let missing_leaf_key = temp_dir("missing-key");
        Ca::generate(&missing_leaf_key, now).expect("generate");
        fs::remove_file(missing_leaf_key.join(LEAF_KEY_FILE)).expect("delete the leaf key");
        let error = Ca::load_or_generate(&missing_leaf_key, now)
            .err()
            .expect("refuses");
        assert!(error.contains(LEAF_KEY_FILE), "names the file: {error}");
        assert!(error.contains("ca rotate"), "names the verb: {error}");
        assert_eq!(
            fs::read_dir(&missing_leaf_key).unwrap().count(),
            2,
            "no regeneration"
        );

        let corrupt = temp_dir("corrupt-ca");
        Ca::generate(&corrupt, now).expect("generate");
        fs::write(corrupt.join(CA_CERT_FILE), "not a certificate").expect("corrupt");
        let error = Ca::load_or_generate(&corrupt, now).err().expect("refuses");
        assert!(error.contains(CA_CERT_FILE), "names the file: {error}");

        let missing_ca = temp_dir("missing-ca");
        Ca::generate(&missing_ca, now).expect("generate");
        fs::remove_file(missing_ca.join(CA_CERT_FILE)).expect("delete the CA cert");
        let error = Ca::load_or_generate(&missing_ca, now)
            .err()
            .expect("refuses");
        assert!(error.contains(CA_CERT_FILE), "names the file: {error}");
    }

    #[test]
    fn the_start_check_rejects_a_foreign_leaf_and_an_expired_ca() {
        let now = OffsetDateTime::now_utc();
        let foreign = temp_dir("foreign-leaf");
        Ca::generate(&foreign, now).expect("generate");
        let other_dir = temp_dir("other-ca");
        Ca::generate(&other_dir, now).expect("generate");
        fs::write(
            foreign.join(LEAF_CERT_FILE),
            read(&other_dir, LEAF_CERT_FILE),
        )
        .expect("swap in the foreign leaf");
        let error = Ca::load_or_generate(&foreign, now).err().expect("refuses");
        assert!(error.contains(LEAF_CERT_FILE), "names the file: {error}");

        let expired = temp_dir("expired");
        Ca::generate(&expired, now).expect("generate");
        let error = Ca::load_or_generate(&expired, now + VALIDITY)
            .err()
            .expect("an expired CA is unusable");
        assert!(error.contains("expired"), "names the cause: {error}");
    }

    #[test]
    fn rotation_replaces_every_file_and_moves_the_fingerprint() {
        let dir = temp_dir("rotate");
        let now = OffsetDateTime::now_utc();
        let before = Ca::generate(&dir, now).expect("generate");
        let old = fs::read_to_string(dir.join(CA_CERT_FILE)).expect("old CA cert");
        let after = Ca::rotate(&dir, now).expect("rotate");
        assert_ne!(
            before.fingerprint(),
            after.fingerprint(),
            "the fingerprint moved"
        );
        assert_ne!(
            old,
            fs::read_to_string(dir.join(CA_CERT_FILE)).expect("new CA cert"),
            "the file was replaced"
        );
        let loaded = Ca::load_or_generate(&dir, now).expect("the new material loads");
        assert_eq!(loaded.fingerprint(), after.fingerprint());
    }

    #[test]
    fn the_fingerprint_is_colon_separated_upper_case_hex_pairs() {
        // SHA-256 of the four bytes deadbeef.
        let fingerprint = fingerprint(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            fingerprint,
            "5F:78:C3:32:74:E4:3F:A9:DE:56:59:26:5C:1D:91:7E:25:C0:37:22:DC:B0:B8:D2:7D:B8:D5:FE:AA:81:39:53"
        );
    }

    #[test]
    fn the_expiry_state_turns_expiring_thirty_days_out() {
        let dir = temp_dir("expiry-state");
        let now = OffsetDateTime::now_utc();
        let ca = Ca::generate(&dir, now).expect("generate");
        assert_eq!(ca.expiry_state(now), STATE_OK);
        assert_eq!(
            ca.expiry_state(now + VALIDITY - EXPIRY_WARNING),
            STATE_EXPIRING
        );
        assert_eq!(
            ca.expiry_state(now + VALIDITY - EXPIRY_WARNING - Duration::minutes(1)),
            STATE_OK
        );
        assert_eq!(
            ca.expiry_state(now + VALIDITY - Duration::days(1)),
            STATE_EXPIRING
        );
    }
}
