//! Captures decrypted challenge payloads and transport details from browsers the solver cannot
//! drive, such as iOS Safari, or a desktop browser an application drives itself.
//!
//! Each challenge POST encrypts a seed under an RSA modulus in the iframe script. A [`Recorder`]
//! swaps in its own modulus and rewraps the browser's seed under the original before it is
//! forwarded. The capture proxy records through one; so can any other interception of the
//! browser's traffic, such as the DevTools protocol's `Fetch` domain. [`Recording`] holds or reads
//! capture logs; [`fill_profile`] uses them to fill a device profile.

#[cfg(feature = "internals")]
mod ca;
#[cfg(feature = "internals")]
mod head;
mod profile;
#[cfg(feature = "internals")]
mod proxy;
mod recorded;
mod recorder;
mod rsa;
mod sessions;
mod traffic;
#[cfg(feature = "internals")]
mod upstream;

#[cfg(feature = "internals")]
pub use ca::CertificateAuthority;
pub use profile::fill as fill_profile;
#[cfg(feature = "internals")]
pub use proxy::{CA_HOST, CA_PATH, CaptureProxy, Config};
pub use recorded::{CapturedSession, Recording};
pub use recorder::{CHALLENGE_HOST, ChallengePost, Posted, Recorder, RewrittenIframe};
pub use traffic::SentHeaders;
#[cfg(feature = "internals")]
pub use upstream::{Credentials, UpstreamProxy};
