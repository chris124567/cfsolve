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
pub(crate) const PLATFORM_OPTION: &str = "_bf13c229f4183e5bc0863f59";
/// The option holding the session's ray, which the worker fetch requests.
pub(crate) const RAY_OPTION: &str = "_eed828ce4503e7f7475d133c";
/// The option holding the nonce the worker fetch requests.
pub(crate) const NONCE_OPTION: &str = "_b05ae5510fcfc51f5ef65860";

/// Shared result field used by clock and private-token probes.
pub(crate) const SHARED_RESULT: &str = "_4f8eb26a0f0e8f1cde83205b";

/// What the clock probe reports when its worker fails.
pub(crate) const CLOCK_FALLBACK: &str = "_c69152d69f01e1841d56d1f8";

pub(crate) const DATES_TODAY: &str = "_02fc3d87fc5fb56d0eff03c7";
pub(crate) const DATES_OFFSET: &str = "_faf306f9f99ed3dce219494d";
pub(crate) const DATES_ZONE: &str = "_00b5777cf2b60a45d1d0b872";

pub(crate) const DOM_MUTATION_RESULT: &str = "_b6fdb2d1104e34bd19027e67";

// Environment and environment-audit names with session-specific replay patches.

/// The environment probe's `document.referrer`.
pub(crate) const ENVIRONMENT_REFERRER: &str = "_d92c36c516f3960a1720f1a3";
/// The audit's groups of readers, by the value they read.
pub(crate) const ENVIRONMENT_AUDIT_GROUPS: &str = "_97b56437f4f055c018023578";
/// The audit's measured values.
pub(crate) const ENVIRONMENT_AUDIT_VALUES: &str = "_2d1e29e89715c35b8d8e1927";
/// Navigation decoded size minus a Server-Timing duration.
pub(crate) const ENVIRONMENT_AUDIT_REDUCTION: &str = "_205e69c5e2dbe2ee9c21fe98";
/// Navigation decoded size.
pub(crate) const ENVIRONMENT_AUDIT_DECODED: &str = "_8469255e1c5cb0d4752b6929";
/// Navigation encoded size.
pub(crate) const ENVIRONMENT_AUDIT_ENCODED: &str = "_85ebe15fe783c98fe7e4bed3";
/// Whether the probe's frame supports touch events.
pub(crate) const ENVIRONMENT_AUDIT_TOUCH: &str = "_c1ec04fca99016a50b19dc3b";
/// The probe frame's `isSecureContext` value.
pub(crate) const ENVIRONMENT_AUDIT_SECURE: &str = "_830ebee3a538ccca14314ae3";
/// The value of `Notification.permission`.
pub(crate) const ENVIRONMENT_AUDIT_PERMISSION: &str = "_5db7449633ee9844a05cd4d1";

/// The isolation probe's results for blocked evaluation and cross-origin history writes.
pub(crate) const ISOLATION_FAILURE_FIELDS: [&str; 2] =
    ["_cbea69cc75848034ce0989bf", "_574ffb5982e23ad01867497c"];
pub(crate) const STYLESHEETS_TEXT: &str = "_cba4128a59ca994d6b27ce03";
pub(crate) const STYLESHEETS_HASH: &str = "_834fbaa6a8bf091fdca82035";

pub(crate) const ERROR_MESSAGE_LENGTH_RESULT: &str = "_9965ce2e48f2fcde9b48a5ed";

pub(crate) const IMAGE_WIDTH: &str = "_649c29b5a891b13039f9a0ba";
pub(crate) const IMAGE_HEIGHT: &str = "_1b8a6e7c70da2950e81f0f54";
pub(crate) const IMAGE_EFFECTIVE_TYPE: &str = "_5930e40e97b074bf625978b2";
pub(crate) const IMAGE_ONLINE: &str = "_bceebfedb12b49ea0e29ea48";
pub(crate) const IMAGE_COMPLETE: &str = "_aa9305b32ef2858c5c1250cd";
pub(crate) const IMAGE_NATURAL_WIDTH: &str = "_fced4ca944afed284f7499e1";
pub(crate) const IMAGE_TIMESTAMP: &str = "_2062942b21d57db68286e7c0";
/// What the probe reports as both dimensions when the image fails to load.
pub(crate) const IMAGE_LOAD_ERROR: &str = "_7f2f9bbc902256aec1b764cd";
/// Dimension values reported before the image load finishes.
pub(crate) const IMAGE_PENDING: &str = "_df4785fdfca109a9f0592a9f";
/// The key the probe's worker replies with when its deadline passes.
pub(crate) const IMAGE_WORKER_TIMEOUT: &str = "_b2467a5a08275e8d86927c48";
/// A name the probe shares with the other probes that await a promise.
pub(crate) const IMAGE_AWAITING: &str = "_0a73a3a4a92c73005733d26a";

pub(crate) const MEDIA_STATE: &str = "_56e7c363edf4482d2a652039";
pub(crate) const MEDIA_CODECS: &str = "_da6b6baf45bcd89bee78c361";
pub(crate) const MEDIA_CANDIDATES: &str = "_3876a4914983c02ab62380d7";
pub(crate) const MEDIA_SDP: &str = "_bf827711f1af5e3877b04536";
pub(crate) const MEDIA_SUPPORT: &str = "_9f106978463140319e091736";
pub(crate) const MEDIA_ICE_STATE: &str = "_0551c794bd86a1c60abe95a0";
pub(crate) const MEDIA_UNAVAILABLE: &str = "_c658c1c6899af57ec6c39c2e";
pub(crate) const MEDIA_CANDIDATE: &str = "_e79bddbb1ba20cdb230fff3d";
pub(crate) const MEDIA_CANDIDATE_TIME: &str = "_c1ebce96d91a7cff088c8f77";
pub(crate) const MEDIA_DATA_CHANNEL: &str = "_b784bcb4bd9d5da3adc79aa0";
pub(crate) const MEDIA_REUSED: &str = "_b6b9dbcd14fe11f6c765ca3c";
pub(crate) const MEDIA_PRIOR_COUNT: &str = "_f6579beb0695ae421f105a89";
pub(crate) const MEDIA_FIRST_CANDIDATE: &str = "_2cbbff49f6edc186c6692e8e";
pub(crate) const MEDIA_ELAPSED: &str = "_03c985885a4a85a179027a60";
pub(crate) const MEDIA_CHANNEL_ERROR: &str = "_200177ecf732d1c3cd29cb5c";
pub(crate) const MEDIA_SEED_OFFER_ERROR: &str = "_3cf67a623238585caf0b8128";
pub(crate) const MEDIA_SEED_GATHER_ERROR: &str = "_c0c335f78959467ef4c758c6";

/// Recognition recovers the network information probe's output names from the probe itself.
#[cfg(test)]
pub(crate) const NETWORK_INFORMATION_OUTPUTS: [&str; 6] = [
    "_fbc335568884e8039f111ddc",
    "_7fb7983b147a359ae1605761",
    "_8916475b09ac849d4b33b4eb",
    "_5ad8840411cfcba6a07a8f90",
    "_f53bae0a78ed600a46b3a07a",
    "_43f08fae15abd0265e7f71e9",
];

pub(crate) const PRIVATE_TOKEN_ELAPSED: &str = "_8db99c6a16533752bb1bbed2";
pub(crate) const PRIVATE_TOKEN_ERROR: &str = "_28023293e58744bd41fbf35c";
pub(crate) const PRIVATE_TOKEN_TOKEN: &str = "_07fa7e9ab60f9de64248e36c";
pub(crate) const PRIVATE_TOKEN_TIMESTAMP: &str = "_95f5893bd1c7feb85a3c2768";
/// The error the probe reports when its worker reaches its deadline.
pub(crate) const PRIVATE_TOKEN_TIMEOUT_ERROR: &str = "_b4788c77fdc4276b724c5cfe";
/// The flag every reply of the probe's worker sets.
pub(crate) const PRIVATE_TOKEN_WORKER_REPLIED: &str = "_9050e5ce306b2a8a9468aa2f";
/// The reply field holding the worker fetch error.
pub(crate) const PRIVATE_TOKEN_WORKER_ERROR: &str = "_3749b38b2e2d5390d14e6e8b";

pub(crate) const WORKER_FETCH_STATUS: &str = "_c6ca4de2162f12143f06c7e0";
pub(crate) const WORKER_FETCH_TOKEN: &str = "_c8171b29101f2dfc039b3e28";

pub(crate) const WORKER_NAVIGATOR_INDICATOR: &str = "_6221c83a1c236170f75c7a93";
pub(crate) const WORKER_NAVIGATOR_RESULT: &str = "_b882c66155596222560e6f1b";

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
            (Kind::Stylesheets, STYLESHEETS_TEXT),
            (Kind::Stylesheets, STYLESHEETS_HASH),
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
