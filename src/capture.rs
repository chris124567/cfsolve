//! Captures decrypted challenge payloads and transport details from browsers the solver cannot
//! drive, such as iOS Safari.
//!
//! Each challenge POST encrypts a seed under an RSA modulus in the iframe script. The proxy swaps
//! in its own modulus and rewraps the browser's seed under the original before forwarding it.
//! [`Recording`] reads capture logs; [`fill_profile`] uses them to fill a device profile.

mod ca;
mod head;
mod profile;
mod proxy;
mod recorded;
mod rsa;
mod sessions;
mod traffic;
mod upstream;

pub use ca::CertificateAuthority;
pub use profile::fill as fill_profile;
pub use proxy::{CA_HOST, CA_PATH, CHALLENGE_HOST, CaptureProxy, Config};
pub use recorded::{CapturedSession, Recording};
pub use upstream::{Credentials, UpstreamProxy};
