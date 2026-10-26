//! Disk storage for the proxy's certificate authority and session logs.

use std::path::Path;

use anyhow::{Context, Result, bail};
use cfsolve::capture::{CA_HOST, CA_PATH, CertificateAuthority};
use sha2::Sha256;

/// Loads the certificate authority from `directory`, creating one if needed. Writes its PEM
/// copy on every call so it is ready to install.
pub fn certificate_authority(directory: &Path) -> Result<CertificateAuthority> {
    create_dir(directory)?;
    let cert_path = directory.join("ca-cert.der");
    let key_path = directory.join("ca-key.der");
    let ca = match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            eprintln!("loading the CA from {}", directory.display());
            CertificateAuthority::load(&read(&cert_path)?, &read(&key_path)?)
                .with_context(|| format!("loading the CA from {}", directory.display()))?
        }
        (false, false) => {
            eprintln!("generating a fresh CA in {}", directory.display());
            let ca = CertificateAuthority::generate()?;
            write(&cert_path, ca.cert_der())?;
            write(&key_path, &ca.key_der())?;
            ca
        }
        // Keep the existing certificate because a phone may already trust it.
        _ => bail!(
            "{} holds only half of a CA: restore ca-cert.der and ca-key.der, or remove both",
            directory.display()
        ),
    };
    write(&directory.join("ca-cert.pem"), ca.pem().as_bytes())?;
    Ok(ca)
}

pub fn print_trust_instructions(ca: &CertificateAuthority) {
    use sha2::Digest;

    let digest = Sha256::digest(ca.cert_der());
    let hex_bytes: Vec<String> = digest.iter().map(|byte| format!("{byte:02X}")).collect();
    eprintln!("CA SHA-256 fingerprint:\n{}", hex_bytes.join(":"));
    eprintln!("Install this CA on the phone (as PEM):\n{}", ca.pem());
    eprintln!("Proxy clients can also download it at http://{CA_HOST}{CA_PATH} through the proxy");
}

pub fn create_dir(directory: &Path) -> Result<()> {
    std::fs::create_dir_all(directory).with_context(|| format!("creating {}", directory.display()))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn write(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ca_is_generated_once_and_never_half_replaced() {
        let directory =
            std::env::temp_dir().join(format!("capture-proxy-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let generated = certificate_authority(&directory).unwrap();
        assert!(directory.join("ca-cert.pem").is_file());
        let loaded = certificate_authority(&directory).unwrap();
        assert_eq!(loaded.cert_der(), generated.cert_der());
        std::fs::remove_file(directory.join("ca-key.der")).unwrap();
        let error = format!("{:#}", certificate_authority(&directory).err().unwrap());
        assert!(error.contains("holds only half of a CA"), "{error}");
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
