//! Certificate authority trusted by the phone, with one leaf certificate per intercepted host.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::crypto::ring::sign;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// A certificate authority that caches issued certificates by hostname. Its `Debug` output
/// omits keys, while satisfying rustls's trait requirement.
#[derive(Debug)]
pub struct CertificateAuthority {
    cert: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertificateAuthority {
    pub fn generate() -> Result<Self> {
        let mut params = CertificateParams::new(vec![])?;
        params
            .distinguished_name
            .push(DnType::CommonName, "capture-proxy CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Self::load(cert.der(), &key.serialize_der())
    }

    /// Restores a certificate authority from [`Self::cert_der`] and [`Self::key_der`].
    pub fn load(cert: &[u8], key: &[u8]) -> Result<Self> {
        let cert = CertificateDer::from(cert.to_vec());
        let key = KeyPair::try_from(&PrivateKeyDer::Pkcs8(key.into()))?;
        Ok(Self {
            issuer: Issuer::from_ca_cert_der(&cert, key)?,
            cert,
            leaves: Mutex::default(),
        })
    }

    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert
    }

    /// The CA key in PKCS#8 DER.
    #[must_use]
    pub fn key_der(&self) -> Vec<u8> {
        self.issuer.key().serialize_der()
    }

    /// The CA certificate in PEM format for installation on the phone.
    #[must_use]
    pub fn pem(&self) -> String {
        use base64::Engine;

        let encoded = STANDARD.encode(&self.cert);
        let lines: Vec<_> = encoded
            .as_bytes()
            .chunks(64)
            .map(String::from_utf8_lossy)
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        )
    }

    /// Returns the certificate for `host`, issuing it on first use.
    fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let mut leaves = self.leaves.lock().expect("the leaf cache lock");
        if let Some(leaf) = leaves.get(host) {
            return Ok(Arc::clone(leaf));
        }
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        let cert = params.signed_by(&key, &self.issuer)?;
        let signing = sign::any_supported_type(&PrivateKeyDer::Pkcs8(key.serialize_der().into()))?;
        let leaf = Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing));
        leaves.insert(host.to_owned(), Arc::clone(&leaf));
        Ok(leaf)
    }
}

impl ResolvesServerCert for CertificateAuthority {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name()?.to_lowercase();
        self.leaf(&host)
            .inspect_err(|error| eprintln!("issuing a leaf for {host}: {error:#}"))
            .ok()
    }
}
