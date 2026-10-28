//! Reference probe strings and names used by recognizers and stored answers.
//!
//! Builds randomize fields, states, and options; [`super::vocabulary`] translates session names
//! to this reference. This module declares all reference names used by the crate. Tests check
//! them against their probe families so regenerating `reference.json` exposes stale
//! declarations.

use std::sync::LazyLock;

use serde::Deserialize;
use sha2::Sha256;

/// The reference build: each probe's collection strings, in program order.
#[derive(Deserialize)]
pub(crate) struct Reference {
    pub probes: Vec<Vec<String>>,
    /// Reference-text identifier used by stored answers.
    #[serde(skip)]
    pub digest: String,
}

/// The embedded reference build, parsed once.
pub(crate) static REFERENCE: LazyLock<Reference> = LazyLock::new(|| {
    use sha2::Digest;

    let text = include_str!("reference.json");
    let mut reference: Reference =
        serde_json::from_str(text).expect("the embedded reference is valid JSON");
    reference.digest = format!("{:x}", Sha256::digest(text))[..16].to_owned();
    reference
});

/// The challenge option (`_cf_chl_opt`) naming the platform segment of a probe's request path.
pub(crate) const PLATFORM_OPTION: &str = "fDDOx7";
/// The option holding the session's ray, which the worker fetch requests.
pub(crate) const RAY_OPTION: &str = "fMrax7";
/// The option holding the nonce the worker fetch requests.
pub(crate) const NONCE_OPTION: &str = "rziaC7";

/// Shared result field used by clock and private-token probes.
pub(crate) const SHARED_RESULT: &str = "Qaeu2";

/// What the clock probe reports when its worker fails.
pub(crate) const CLOCK_FALLBACK: &str = "FBnL2";

pub(crate) const DATES_TODAY: &str = "LKWB0";
pub(crate) const DATES_OFFSET: &str = "kCaP5";
pub(crate) const DATES_ZONE: &str = "vFsge3";

pub(crate) const DOM_MUTATION_RESULT: &str = "yocl1";

// Environment and environment-audit names with session-specific replay patches.

/// The environment probe's `document.referrer`.
pub(crate) const ENVIRONMENT_REFERRER: &str = "IEoo6";
/// The audit's groups of readers, by the value they read.
pub(crate) const ENVIRONMENT_AUDIT_GROUPS: &str = "Mrvi5";
/// The audit's measured values.
pub(crate) const ENVIRONMENT_AUDIT_VALUES: &str = "gVIOJ1";
/// Navigation decoded size minus a Server-Timing duration.
pub(crate) const ENVIRONMENT_AUDIT_REDUCTION: &str = "CUFA2";
/// Navigation decoded size.
pub(crate) const ENVIRONMENT_AUDIT_DECODED: &str = "qYdP1";
/// Navigation encoded size.
pub(crate) const ENVIRONMENT_AUDIT_ENCODED: &str = "qivJU1";
/// Whether the probe's frame supports touch events.
pub(crate) const ENVIRONMENT_AUDIT_TOUCH: &str = "EuKni3";
/// The probe frame's `isSecureContext` value.
pub(crate) const ENVIRONMENT_AUDIT_SECURE: &str = "CvjRv6";
/// The value of `Notification.permission`.
pub(crate) const ENVIRONMENT_AUDIT_PERMISSION: &str = "VJeMl3";

pub(crate) const ERROR_MESSAGE_LENGTH_RESULT: &str = "tbCpm1";

pub(crate) const IMAGE_WIDTH: &str = "HOfsc5";
pub(crate) const IMAGE_HEIGHT: &str = "CfxW8";
pub(crate) const IMAGE_EFFECTIVE_TYPE: &str = "JZpKs0";
pub(crate) const IMAGE_ONLINE: &str = "WnDqR8";
pub(crate) const IMAGE_COMPLETE: &str = "eCvhB6";
pub(crate) const IMAGE_NATURAL_WIDTH: &str = "tZqBF5";
pub(crate) const IMAGE_TIMESTAMP: &str = "TRPPv6";
/// What the probe reports as both dimensions when the image fails to load.
pub(crate) const IMAGE_LOAD_ERROR: &str = "jThV9";
/// Dimension values reported before the image load finishes.
pub(crate) const IMAGE_PENDING: &str = "YyBlg5";
/// The key the probe's worker replies with when its deadline passes.
pub(crate) const IMAGE_WORKER_TIMEOUT: &str = "uIVWw9";
/// A name the probe shares with the other probes that await a promise.
pub(crate) const IMAGE_AWAITING: &str = "BQsv4";

pub(crate) const MEDIA_STATE: &str = "cHOXt5";
pub(crate) const MEDIA_CODECS: &str = "jmcNk6";
pub(crate) const MEDIA_CANDIDATES: &str = "CGqF5";
pub(crate) const MEDIA_SDP: &str = "XmGk2";
pub(crate) const MEDIA_SUPPORT: &str = "nOyvn6";
pub(crate) const MEDIA_ICE_STATE: &str = "THSa3";
pub(crate) const MEDIA_UNAVAILABLE: &str = "tGDM7";
pub(crate) const MEDIA_CANDIDATE: &str = "IujZl5";
pub(crate) const MEDIA_CANDIDATE_TIME: &str = "ujwxq5";
pub(crate) const MEDIA_DATA_CHANNEL: &str = "DGSE1";
pub(crate) const MEDIA_REUSED: &str = "fylY5";
pub(crate) const MEDIA_PRIOR_COUNT: &str = "xwFV8";
pub(crate) const MEDIA_FIRST_CANDIDATE: &str = "lgnB3";
pub(crate) const MEDIA_ELAPSED: &str = "EufTm2";
pub(crate) const MEDIA_CHANNEL_ERROR: &str = "TYVmT3";
pub(crate) const MEDIA_SEED_OFFER_ERROR: &str = "wnGKN3";
pub(crate) const MEDIA_SEED_GATHER_ERROR: &str = "RczL3";

/// Recognition recovers the network information probe's output names from the probe itself.
#[cfg(test)]
pub(crate) const NETWORK_INFORMATION_OUTPUTS: [&str; 6] =
    ["yrECR4", "RAgG0", "PLgV4", "ofXXp7", "OyWi8", "DLxCG4"];

pub(crate) const PARENT_INFO_REFERRER: &str = "TntMf7";
pub(crate) const PARENT_INFO_MISSING: &str = "OwMo9";
pub(crate) const PARENT_INFO_REASONS: &str = "mXVtS4";
pub(crate) const PARENT_INFO_VISIBILITY: &str = "zSEUs9";
/// The output the embedding page's `pad` property is copied to.
pub(crate) const PARENT_INFO_PAD: &str = "xNWk9";
/// Pairs of output fields and parent-info properties copied directly.
pub(crate) const PARENT_INFO_DIRECT: [(&str, &str); 16] = [
    ("Phksv2", "vDuh"),
    ("Rsffu5", "vDie"),
    ("CQoR0", "xp"),
    ("mkXM4", "wp"),
    ("ruEU0", "pfp"),
    ("dkJa8", "sL"),
    ("RjDt7", "ssL"),
    ("Uiqbe2", "mL"),
    ("rQKmV0", "t"),
    ("Bfav1", "tL"),
    ("mTKb7", "lH"),
    ("JpisX5", "sR"),
    ("VQgE2", "ii"),
    ("CPzGA2", "ffp"),
    ("HQKw3", "pac"),
    (PARENT_INFO_PAD, "pad"),
];
/// Pairs of output fields and parent-info properties copied with an empty-string fallback for
/// falsy values.
pub(crate) const PARENT_INFO_FALLBACK: [(&str, &str); 4] = [
    ("mFggz8", "vDmt"),
    ("XZjP7", "vDhp"),
    ("iFsu6", "vDmd"),
    ("ZRfV0", "vDa"),
];

pub(crate) const PRIVATE_TOKEN_ELAPSED: &str = "msMJz1";
pub(crate) const PRIVATE_TOKEN_ERROR: &str = "AYvz5";
pub(crate) const PRIVATE_TOKEN_TOKEN: &str = "tiZRS0";
pub(crate) const PRIVATE_TOKEN_TIMESTAMP: &str = "xDpHl7";
/// The error the probe reports when its worker reaches its deadline.
pub(crate) const PRIVATE_TOKEN_TIMEOUT_ERROR: &str = "EgIt8";
/// The flag every reply of the probe's worker sets.
pub(crate) const PRIVATE_TOKEN_WORKER_REPLIED: &str = "KQxI9";
/// The reply field holding the worker fetch error.
pub(crate) const PRIVATE_TOKEN_WORKER_ERROR: &str = "mGLF5";

pub(crate) const WORKER_FETCH_STATUS: &str = "NChzJ9";
pub(crate) const WORKER_FETCH_TOKEN: &str = "npLu3";

pub(crate) const WORKER_NAVIGATOR_INDICATOR: &str = "IOca9";
pub(crate) const WORKER_NAVIGATOR_RESULT: &str = "DIEq4";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage2::registry::Kind;

    #[test]
    fn every_name_is_in_its_familys_reference_probes() {
        let mut names = vec![
            (Kind::ClockResolution, SHARED_RESULT),
            (Kind::ClockResolution, CLOCK_FALLBACK),
            (Kind::DateParsingOffsets, DATES_TODAY),
            (Kind::DateParsingOffsets, DATES_OFFSET),
            (Kind::DateParsingOffsets, DATES_ZONE),
            (Kind::DomMutation, DOM_MUTATION_RESULT),
            (Kind::Environment, ENVIRONMENT_REFERRER),
            (Kind::EnvironmentAudit, ENVIRONMENT_AUDIT_GROUPS),
            (Kind::EnvironmentAudit, ENVIRONMENT_AUDIT_VALUES),
            (Kind::EnvironmentAudit, ENVIRONMENT_AUDIT_REDUCTION),
            (Kind::EnvironmentAudit, ENVIRONMENT_AUDIT_DECODED),
            (Kind::EnvironmentAudit, ENVIRONMENT_AUDIT_ENCODED),
            (Kind::EnvironmentAudit, ENVIRONMENT_AUDIT_TOUCH),
            (Kind::EnvironmentAudit, ENVIRONMENT_AUDIT_SECURE),
            (Kind::EnvironmentAudit, ENVIRONMENT_AUDIT_PERMISSION),
            (Kind::ErrorMessageLength, ERROR_MESSAGE_LENGTH_RESULT),
            (Kind::Image, PLATFORM_OPTION),
            (Kind::Image, IMAGE_WIDTH),
            (Kind::Image, IMAGE_HEIGHT),
            (Kind::Image, IMAGE_EFFECTIVE_TYPE),
            (Kind::Image, IMAGE_ONLINE),
            (Kind::Image, IMAGE_COMPLETE),
            (Kind::Image, IMAGE_NATURAL_WIDTH),
            (Kind::Image, IMAGE_TIMESTAMP),
            (Kind::Image, IMAGE_LOAD_ERROR),
            (Kind::Image, IMAGE_PENDING),
            (Kind::Image, IMAGE_WORKER_TIMEOUT),
            (Kind::Image, IMAGE_AWAITING),
            (Kind::Media, MEDIA_STATE),
            (Kind::Media, MEDIA_CODECS),
            (Kind::Media, MEDIA_CANDIDATES),
            (Kind::Media, MEDIA_SDP),
            (Kind::Media, MEDIA_SUPPORT),
            (Kind::Media, MEDIA_ICE_STATE),
            (Kind::Media, MEDIA_UNAVAILABLE),
            (Kind::Media, MEDIA_CANDIDATE),
            (Kind::Media, MEDIA_CANDIDATE_TIME),
            (Kind::Media, MEDIA_DATA_CHANNEL),
            (Kind::Media, MEDIA_REUSED),
            (Kind::Media, MEDIA_PRIOR_COUNT),
            (Kind::Media, MEDIA_FIRST_CANDIDATE),
            (Kind::Media, MEDIA_ELAPSED),
            (Kind::Media, MEDIA_CHANNEL_ERROR),
            (Kind::Media, MEDIA_SEED_OFFER_ERROR),
            (Kind::Media, MEDIA_SEED_GATHER_ERROR),
            (Kind::ParentInfo, PARENT_INFO_REFERRER),
            (Kind::ParentInfo, PARENT_INFO_MISSING),
            (Kind::ParentInfo, PARENT_INFO_REASONS),
            (Kind::ParentInfo, PARENT_INFO_VISIBILITY),
            (Kind::PrivateToken, PLATFORM_OPTION),
            (Kind::PrivateToken, SHARED_RESULT),
            (Kind::PrivateToken, PRIVATE_TOKEN_ELAPSED),
            (Kind::PrivateToken, PRIVATE_TOKEN_ERROR),
            (Kind::PrivateToken, PRIVATE_TOKEN_TOKEN),
            (Kind::PrivateToken, PRIVATE_TOKEN_TIMESTAMP),
            (Kind::PrivateToken, PRIVATE_TOKEN_TIMEOUT_ERROR),
            (Kind::PrivateToken, PRIVATE_TOKEN_WORKER_REPLIED),
            (Kind::PrivateToken, PRIVATE_TOKEN_WORKER_ERROR),
            (Kind::WorkerFetch, PLATFORM_OPTION),
            (Kind::WorkerFetch, RAY_OPTION),
            (Kind::WorkerFetch, NONCE_OPTION),
            (Kind::WorkerFetch, WORKER_FETCH_STATUS),
            (Kind::WorkerFetch, WORKER_FETCH_TOKEN),
            (Kind::WorkerNavigator, WORKER_NAVIGATOR_INDICATOR),
            (Kind::WorkerNavigator, WORKER_NAVIGATOR_RESULT),
        ];
        names.extend(NETWORK_INFORMATION_OUTPUTS.map(|name| (Kind::NetworkInformation, name)));
        let copied = PARENT_INFO_DIRECT.into_iter().chain(PARENT_INFO_FALLBACK);
        names.extend(copied.map(|(name, _)| (Kind::ParentInfo, name)));
        for (kind, name) in names {
            for &reference in kind.references() {
                assert!(
                    REFERENCE.probes[reference - 1]
                        .iter()
                        .any(|text| text == name),
                    "reference probe {reference} ({kind}) has no {name}: update the name to the \
                     reference build's"
                );
            }
        }
    }
}
