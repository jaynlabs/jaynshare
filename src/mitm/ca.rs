//! The MITM CA and its files.
//!
//! The CA key pair exists only inside [`Ca::mint`]'s frame: the CA
//! certificate is written for the clients to import, the leaf is signed, and
//! the CA private key is dropped without ever reaching a file — nothing on
//! disk can sign a new certificate. The start-time check never regenerates
//! over unusable material, it refuses.
//!
//! A staged rotation writes the next CA beside the current one. The proxy
//! keeps presenting the current one until the switch, so clients fetch the
//! next one while both work.

use base64::Engine as _;
use std::fs;
use std::path::Path;
use std::sync::Arc;

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

use crate::mitm::probe::PROBE_HOST;
use crate::provider::anthropic;

/// The three fixed names, relative to the state directory.
pub const CA_CERT_FILE: &str = "mitm-ca.pem";
pub const LEAF_CERT_FILE: &str = "mitm-leaf.pem";
pub const LEAF_KEY_FILE: &str = "mitm-leaf-key.pem";
/// A staged rotation's CA certificate, leaf and leaf key, in one file so it
/// is written whole.
pub const NEXT_FILE: &str = "mitm-ca-next.pem";

/// The whole intercept set, one port; the leaf carries every name and the
/// listener intercepts exactly these.
pub const INTERCEPT_NAMES: [&str; 2] = [anthropic::API_HOST, PROBE_HOST];

/// Both certificates, valid from one hour before generation until
/// 730 days after it. Not configurable.
const BACKDATING: Duration = Duration::hours(1);
const VALIDITY: Duration = Duration::days(730);
/// The `expiring` state and its warning start 30 days out.
const EXPIRY_WARNING: Duration = Duration::days(30);
/// How long a staged CA waits before the proxy presents it.
pub const OVERLAP: Duration = Duration::days(7);

/// The states `status` shows for the CA; `unusable` is what a
/// failed [`Authorities::load`] means and is the wiring's to report.
pub const STATE_OK: &str = "ok";
pub const STATE_EXPIRING: &str = "expiring";
pub const STATE_UNUSABLE: &str = "unusable";

/// The loaded trust material: the CA for the bundle and the fingerprint,
/// the leaf pair for the TLS resolver of an intercepted tunnel.
pub struct Ca {
    ca_certificate: CertificateDer<'static>,
    leaf_certificate: CertificateDer<'static>,
    leaf_key: PrivateKeyDer<'static>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl Ca {
    /// Generate CA and leaf, write the three files (certificates `0644`,
    /// leaf key `0600` on POSIX).
    pub fn generate(state_dir: &Path, now: OffsetDateTime) -> Result<Ca, String> {
        let ca = Self::mint(now)?;
        ca.write_current(state_dir)?;
        Ok(ca)
    }

    /// Generate the next CA into [`NEXT_FILE`] (`0600`), the current one
    /// untouched.
    pub fn stage(state_dir: &Path, now: OffsetDateTime) -> Result<Ca, String> {
        let next = Self::mint(now)?;
        let text = [
            next.certificate_pem(),
            pem("CERTIFICATE", next.leaf_certificate.as_ref()),
            next.leaf_key_pem()?,
        ]
        .concat();
        write_file(&state_dir.join(NEXT_FILE), text.as_bytes(), 0o600)?;
        tracing::info!(
            event = "ca_staged",
            fingerprint = %next.fingerprint(),
            "staged the next CA; clients fetch it on their next launch"
        );
        Ok(next)
    }

    /// The staged CA, `None` without one.
    pub fn load_next(state_dir: &Path, now: OffsetDateTime) -> Result<Option<Ca>, String> {
        let bytes = match fs::read(state_dir.join(NEXT_FILE)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(unusable(NEXT_FILE, e.to_string())),
        };
        let unusable_next = |cause: String| unusable(NEXT_FILE, cause);
        let (rest, pem_ca) =
            parse_x509_pem(&bytes).map_err(|e| unusable_next(format!("no CA certificate: {e}")))?;
        let (rest, pem_leaf) =
            parse_x509_pem(rest).map_err(|e| unusable_next(format!("no leaf: {e}")))?;
        Self::check([NEXT_FILE; 3], &pem_ca, &pem_leaf, rest, now).map(Some)
    }

    /// CA and leaf in memory; the CA key is dropped on return.
    fn mint(now: OffsetDateTime) -> Result<Ca, String> {
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

        Ok(Ca {
            ca_certificate: ca_certificate.der().clone(),
            leaf_certificate: leaf_certificate.der().clone(),
            leaf_key: PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
            not_before,
            not_after,
        })
    }

    /// The three current files. On Windows they inherit the directory's
    /// ACL; the POSIX modes are written here.
    fn write_current(&self, state_dir: &Path) -> Result<(), String> {
        write_file(
            &state_dir.join(CA_CERT_FILE),
            self.certificate_pem().as_bytes(),
            0o644,
        )?;
        write_file(
            &state_dir.join(LEAF_CERT_FILE),
            pem("CERTIFICATE", self.leaf_certificate.as_ref()).as_bytes(),
            0o644,
        )?;
        write_file(
            &state_dir.join(LEAF_KEY_FILE),
            self.leaf_key_pem()?.as_bytes(),
            0o600,
        )
    }

    fn leaf_key_pem(&self) -> Result<String, String> {
        match &self.leaf_key {
            PrivateKeyDer::Pkcs8(key) => Ok(pem("PRIVATE KEY", key.secret_pkcs8_der())),
            PrivateKeyDer::Sec1(key) => Ok(pem("EC PRIVATE KEY", key.secret_sec1_der())),
            PrivateKeyDer::Pkcs1(key) => Ok(pem("RSA PRIVATE KEY", key.secret_pkcs1_der())),
            _ => Err("the leaf key has an unknown encoding".into()),
        }
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
        let ca = Self::load(state_dir, now)?;
        tracing::info!(
            event = "ca_loaded",
            fingerprint = %ca.fingerprint(),
            "using the CA already in the state directory"
        );
        Ok(ca)
    }

    /// Replace the current CA at once, dropping any staged one first so it
    /// can never take over later; log the old and the new fingerprint.
    pub fn rotate(state_dir: &Path, now: OffsetDateTime) -> Result<Ca, String> {
        let old = fs::read(state_dir.join(CA_CERT_FILE))
            .ok()
            .and_then(|bytes| parse_pem(&bytes).ok())
            .map(|pem| fingerprint(&pem.contents))
            .unwrap_or_else(|| "unavailable".into());
        remove_next(state_dir)?;
        let ca = Self::generate(state_dir, now)?;
        tracing::info!(
            event = "ca_rotated",
            old_fingerprint = %old,
            new_fingerprint = %ca.fingerprint(),
            "rotated the CA now; clients fetch it on their next launch, and running Claude Code sessions need a restart"
        );
        Ok(ca)
    }

    /// The current files, never generated.
    fn load(state_dir: &Path, now: OffsetDateTime) -> Result<Ca, String> {
        let read =
            |name: &str| fs::read(state_dir.join(name)).map_err(|e| unusable(name, e.to_string()));
        let ca_bytes = read(CA_CERT_FILE)?;
        let leaf_bytes = read(LEAF_CERT_FILE)?;
        let key_bytes = read(LEAF_KEY_FILE)?;
        let pem_ca = parse_pem(&ca_bytes).map_err(|e| unusable(CA_CERT_FILE, e))?;
        let pem_leaf = parse_pem(&leaf_bytes).map_err(|e| unusable(LEAF_CERT_FILE, e))?;
        Self::check(
            [CA_CERT_FILE, LEAF_CERT_FILE, LEAF_KEY_FILE],
            &pem_ca,
            &pem_leaf,
            &key_bytes,
            now,
        )
    }

    /// Chain valid, leaf covering the intercept set, both in their validity;
    /// an error names the file (`names`: CA, leaf, key) at fault.
    fn check(
        names: [&str; 3],
        pem_ca: &Pem,
        pem_leaf: &Pem,
        key_bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<Ca, String> {
        let [ca_name, leaf_name, key_name] = names;
        let ca = pem_ca
            .parse_x509()
            .map_err(|e| unusable(ca_name, format!("not a certificate: {e}")))?;
        let leaf = pem_leaf
            .parse_x509()
            .map_err(|e| unusable(leaf_name, format!("not a certificate: {e}")))?;
        if !ca.is_ca() {
            return Err(unusable(ca_name, "the certificate is not a CA".into()));
        }
        leaf.verify_signature(Some(ca.public_key()))
            .map_err(|e| unusable(leaf_name, format!("not signed by the CA: {e}")))?;
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
                    leaf_name,
                    format!("the leaf does not cover {expected}"),
                ));
            }
        }
        for (what, validity) in [(ca_name, ca.validity()), (leaf_name, leaf.validity())] {
            if validity.not_after.to_datetime() < now {
                return Err(unusable(what, "the certificate has expired".into()));
            }
            if validity.not_before.to_datetime() > now {
                return Err(unusable(what, "the certificate is not yet valid".into()));
            }
        }
        let leaf_key = PrivateKeyDer::from_pem_slice(key_bytes)
            .map_err(|e| unusable(key_name, format!("cannot parse the private key: {e}")))?;
        Ok(Ca {
            ca_certificate: CertificateDer::from(pem_ca.contents.clone()),
            leaf_certificate: CertificateDer::from(pem_leaf.contents.clone()),
            leaf_key,
            not_before: ca.validity().not_before.to_datetime(),
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
        pem("CERTIFICATE", self.ca_certificate.as_ref())
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

    /// When this CA was generated.
    fn issued_at(&self) -> OffsetDateTime {
        self.not_before + BACKDATING
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
                "the CA certificate expires within 30 days; run `jaynshare ca rotate`, and clients follow on their next launch"
            );
        }
    }
}

/// The CA the proxy presents and, during a staged rotation, the next one.
#[derive(Clone, Default)]
pub struct Authorities {
    pub current: Option<Arc<Ca>>,
    pub next: Option<Arc<Ca>>,
}

impl Authorities {
    /// The start-time check. A staged CA takes over first when it is due or
    /// the current one is unusable; without one, the current CA is loaded,
    /// or generated when none exists. `Err` is the `unusable` state.
    pub fn load(state_dir: &Path, now: OffsetDateTime) -> Result<Authorities, String> {
        let next = Ca::load_next(state_dir, now).unwrap_or_else(|e| {
            tracing::error!(event = "ca_next_unusable", error = %e, "the staged CA is ignored");
            None
        });
        let Some(next) = next else {
            let current = Ca::load_or_generate(state_dir, now)?;
            return Ok(Authorities {
                current: Some(Arc::new(current)),
                next: None,
            });
        };
        let current = Ca::load(state_dir, now)
            .inspect_err(
                |e| tracing::error!(event = "ca_unusable", error = %e, "the staged CA takes over"),
            )
            .ok();
        let mut authorities = Authorities {
            current: current.map(Arc::new),
            next: Some(Arc::new(next)),
        };
        if authorities.due(now) {
            authorities.promote(state_dir)?;
        }
        Ok(authorities)
    }

    /// When the next CA takes over: [`OVERLAP`] after it was staged, when
    /// the current one expires if sooner, at once without a current one.
    pub fn switch_at(&self) -> Option<OffsetDateTime> {
        let next = self.next.as_ref()?;
        Some(match &self.current {
            Some(current) => (next.issued_at() + OVERLAP).min(current.not_after()),
            None => next.issued_at(),
        })
    }

    pub fn due(&self, now: OffsetDateTime) -> bool {
        self.switch_at().is_some_and(|at| at <= now)
    }

    /// The next CA becomes the current one, on disk first.
    pub fn promote(&mut self, state_dir: &Path) -> Result<(), String> {
        let Some(next) = self.next.clone() else {
            return Ok(());
        };
        next.write_current(state_dir)?;
        // A file left behind is promoted again, to the same CA, at the next start.
        if let Err(e) = remove_next(state_dir) {
            tracing::warn!(event = "ca_next_left", error = %e, "the staged file remains");
        }
        tracing::info!(
            event = "ca_switched",
            old_fingerprint = %self.current.as_ref().map_or_else(|| "unavailable".into(), |ca| ca.fingerprint()),
            new_fingerprint = %next.fingerprint(),
            "the proxy now presents the staged CA"
        );
        self.current = Some(next);
        self.next = None;
        Ok(())
    }
}

/// The staged CA takes over when it is due; a failed switch is retried.
pub async fn switch_when_due(server: Arc<crate::server::Server>) {
    let state_dir = server.state_dir();
    loop {
        let wait = {
            let mut authorities = server.mitm_authorities();
            let now = OffsetDateTime::now_utc();
            if authorities.due(now)
                && let Err(e) = authorities.promote(&state_dir)
            {
                tracing::error!(event = "ca_switch_failed", error = %e, "the staged CA could not take over");
            }
            authorities
                .switch_at()
                .map_or(Duration::HOUR, |at| at - now)
                .clamp(Duration::MINUTE, Duration::HOUR)
        };
        tokio::time::sleep(wait.unsigned_abs()).await;
    }
}

fn remove_next(state_dir: &Path) -> Result<(), String> {
    match fs::remove_file(state_dir.join(NEXT_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("{NEXT_FILE}: cannot remove: {e}"))
        }
        _ => Ok(()),
    }
}

/// `der` as one PEM block.
fn pem(label: &str, der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
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

    #[test]
    fn every_intercepted_name_but_the_probe_s_is_a_provider_s() {
        for name in INTERCEPT_NAMES {
            assert_eq!(
                crate::provider::Provider::for_intercepted_host(name).is_some(),
                name != PROBE_HOST,
                "{name}"
            );
        }
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
    fn staging_writes_only_the_next_file_and_it_loads_back() {
        let dir = temp_dir("stage");
        let now = OffsetDateTime::now_utc();
        let current = Ca::generate(&dir, now).expect("generate");
        let presented = read(&dir, CA_CERT_FILE);
        let staged = Ca::stage(&dir, now).expect("stage");
        assert_eq!(read(&dir, CA_CERT_FILE), presented, "the current CA stays");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(NEXT_FILE))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the staged file holds a key");
        }
        let loaded = Ca::load_next(&dir, now).expect("loads").expect("staged");
        assert_eq!(loaded.fingerprint(), staged.fingerprint());
        assert_ne!(loaded.fingerprint(), current.fingerprint());
        assert_eq!(loaded.leaf_certificate(), staged.leaf_certificate());
    }

    #[test]
    fn the_staged_ca_switches_after_the_overlap_or_when_the_current_one_expires() {
        let dir = temp_dir("switch-at");
        let now = OffsetDateTime::now_utc();
        let current = Arc::new(Ca::generate(&dir, now).expect("generate"));
        let next = Arc::new(Ca::stage(&dir, now).expect("stage"));
        let staged = Authorities {
            current: Some(current),
            next: Some(Arc::clone(&next)),
        };
        let at = staged.switch_at().expect("a CA is staged");
        assert!(at <= now + OVERLAP && at > now + OVERLAP - Duration::seconds(1));
        assert!(!staged.due(at - Duration::seconds(1)));
        assert!(staged.due(at));

        let expiring = Arc::new(
            Ca::generate(
                &temp_dir("switch-at-expiring"),
                now - VALIDITY + Duration::days(2),
            )
            .expect("generate"),
        );
        let before_expiry = Authorities {
            current: Some(Arc::clone(&expiring)),
            next: Some(Arc::clone(&next)),
        };
        assert_eq!(before_expiry.switch_at(), Some(expiring.not_after()));

        let without_current = Authorities {
            current: None,
            next: Some(next),
        };
        assert!(without_current.due(now));
        assert_eq!(Authorities::default().switch_at(), None);
    }

    #[test]
    fn a_due_ca_takes_over_at_start_and_its_file_goes() {
        let dir = temp_dir("switch-at-start");
        let now = OffsetDateTime::now_utc();
        let current = Ca::generate(&dir, now).expect("generate");
        let staged = Ca::stage(&dir, now).expect("stage");
        let pending = Authorities::load(&dir, now).expect("load");
        let fingerprint = |ca: &Option<Arc<Ca>>| ca.as_ref().map(|ca| ca.fingerprint());
        assert_eq!(fingerprint(&pending.current), Some(current.fingerprint()));
        assert_eq!(fingerprint(&pending.next), Some(staged.fingerprint()));

        let switched = Authorities::load(&dir, now + OVERLAP).expect("load");
        assert_eq!(fingerprint(&switched.current), Some(staged.fingerprint()));
        assert!(switched.next.is_none());
        assert!(!dir.join(NEXT_FILE).exists());
        let reloaded = Ca::load_or_generate(&dir, now + OVERLAP).expect("load");
        assert_eq!(reloaded.fingerprint(), staged.fingerprint());
    }

    #[test]
    fn a_staged_ca_replaces_an_unusable_current_one_at_start() {
        let dir = temp_dir("switch-unusable");
        let now = OffsetDateTime::now_utc();
        Ca::generate(&dir, now).expect("generate");
        let staged = Ca::stage(&dir, now).expect("stage");
        fs::remove_file(dir.join(LEAF_KEY_FILE)).expect("break the current CA");
        let authorities = Authorities::load(&dir, now).expect("the staged CA takes over");
        let current = authorities.current.expect("a current CA");
        assert_eq!(current.fingerprint(), staged.fingerprint());
        assert!(authorities.next.is_none());
    }

    #[test]
    fn rotating_now_drops_the_staged_ca() {
        let dir = temp_dir("rotate-drops-staged");
        let now = OffsetDateTime::now_utc();
        Ca::generate(&dir, now).expect("generate");
        Ca::stage(&dir, now).expect("stage");
        let rotated = Ca::rotate(&dir, now).expect("rotate");
        assert!(!dir.join(NEXT_FILE).exists());
        let later = Authorities::load(&dir, now + OVERLAP).expect("load");
        let current = later.current.expect("a current CA");
        assert_eq!(current.fingerprint(), rotated.fingerprint());
        assert!(later.next.is_none());
    }

    #[test]
    fn an_unusable_staged_file_is_ignored_and_named() {
        let dir = temp_dir("staged-unusable");
        let now = OffsetDateTime::now_utc();
        let current = Ca::generate(&dir, now).expect("generate");
        fs::write(dir.join(NEXT_FILE), "not a certificate").expect("corrupt");
        let error = Ca::load_next(&dir, now).err().expect("refuses");
        assert!(error.contains(NEXT_FILE), "names the file: {error}");
        let authorities = Authorities::load(&dir, now).expect("the current CA serves");
        assert!(authorities.next.is_none());
        let loaded = authorities.current.expect("a current CA");
        assert_eq!(loaded.fingerprint(), current.fingerprint());
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
