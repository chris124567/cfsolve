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
pub(crate) const PLATFORM_OPTION: &str = "_e30715545c342d2c7172508f";
/// The option holding the session's ray, which the worker fetch requests.
pub(crate) const RAY_OPTION: &str = "_b57b772c6cbf614381ea1c9b";
/// The option holding the nonce the worker fetch requests.
pub(crate) const NONCE_OPTION: &str = "_5f03e51a908e7c7f4a90a1ca";

/// Shared result field used by clock and private-token probes.
pub(crate) const SHARED_RESULT: &str = "_62845f21bd76642fe7607006";

/// What the clock probe reports when its worker fails.
pub(crate) const CLOCK_FALLBACK: &str = "_7de8bfec8afbfc6c0a7f7228";

pub(crate) const DATES_TODAY: &str = "_8462a594ae41b7c8900438ca";
pub(crate) const DATES_OFFSET: &str = "_daa71e2bf5d4de20599870b8";
pub(crate) const DATES_ZONE: &str = "_606c6ae129decf99cc72f7bd";

pub(crate) const DOM_MUTATION_RESULT: &str = "_ab16b242260d08ce77aaf2d7";

// Environment and environment-audit names with session-specific replay patches.

/// The environment probe's `document.referrer`.
pub(crate) const ENVIRONMENT_REFERRER: &str = "_6adf411141c3ede7490c3a87";
/// The audit's groups of readers, by the value they read.
pub(crate) const ENVIRONMENT_AUDIT_GROUPS: &str = "_498acb3af906a5f1ad524b55";
/// The audit's measured values.
pub(crate) const ENVIRONMENT_AUDIT_VALUES: &str = "_58775d9322eb1c51ea1c9de3";
/// Navigation decoded size minus a Server-Timing duration.
pub(crate) const ENVIRONMENT_AUDIT_REDUCTION: &str = "_fc47349735427db7e5f565e1";
/// Navigation decoded size.
pub(crate) const ENVIRONMENT_AUDIT_DECODED: &str = "_d1e50e6ff9e2ba34399058f3";
/// Navigation encoded size.
pub(crate) const ENVIRONMENT_AUDIT_ENCODED: &str = "_ea7ac764fd2860c697cbf813";
/// Whether the probe's frame supports touch events.
pub(crate) const ENVIRONMENT_AUDIT_TOUCH: &str = "_9cd866a3511f517879f4516b";
/// The probe frame's `isSecureContext` value.
pub(crate) const ENVIRONMENT_AUDIT_SECURE: &str = "_05547ddcb67150366764f887";
/// The value of `Notification.permission`.
pub(crate) const ENVIRONMENT_AUDIT_PERMISSION: &str = "_ae82ebb109ab253d3f05a980";

/// The isolation probe's results for blocked evaluation and cross-origin history writes.
pub(crate) const ISOLATION_FAILURE_FIELDS: [&str; 2] =
    ["_0d933758da8afefe31570be9", "_f25bb13aa3dd8a386af7c1dc"];
pub(crate) const STYLESHEETS_TEXT: &str = "_fc71c1abadf551a615b367db";
pub(crate) const STYLESHEETS_HASH: &str = "_137a63be904787b00109cacd";

pub(crate) const ERROR_MESSAGE_LENGTH_RESULT: &str = "_81fab77ed2f23f790181a6f7";

pub(crate) const IMAGE_WIDTH: &str = "_78a72dd3637eb6fb0b4f86d4";
pub(crate) const IMAGE_HEIGHT: &str = "_5daa91bb069e46e542190bad";
pub(crate) const IMAGE_EFFECTIVE_TYPE: &str = "_2d11906e809fc8fd8574d281";
pub(crate) const IMAGE_ONLINE: &str = "_c744ece5552965265043fa60";
pub(crate) const IMAGE_COMPLETE: &str = "_8d310517c48e7b458e12ef89";
pub(crate) const IMAGE_NATURAL_WIDTH: &str = "_8cd60bdd4935672b05587476";
pub(crate) const IMAGE_TIMESTAMP: &str = "_12b0e3e0814b017bd235bc6e";
/// What the probe reports as both dimensions when the image fails to load.
pub(crate) const IMAGE_LOAD_ERROR: &str = "_df3d3a69189f46fae9de3d46";
/// Dimension values reported before the image load finishes.
pub(crate) const IMAGE_PENDING: &str = "_951054c8356dc7089dd99299";
/// The key the probe's worker replies with when its deadline passes.
pub(crate) const IMAGE_WORKER_TIMEOUT: &str = "_f91aefe3a5aa9c6bd7b610d8";
/// A name the probe shares with the other probes that await a promise.
pub(crate) const IMAGE_AWAITING: &str = "_68b6422aa18fedc6d9fa7dc3";

pub(crate) const MEDIA_STATE: &str = "_f7da15e7ffdacb47a0cdfdf0";
pub(crate) const MEDIA_CODECS: &str = "_138e30bf2198594f2ded2588";
pub(crate) const MEDIA_CANDIDATES: &str = "_47d0c4f028335a349928a882";
pub(crate) const MEDIA_SDP: &str = "_c07cc41874125a9add025bfd";
pub(crate) const MEDIA_SUPPORT: &str = "_3354f14d23df4b2a88c3fa44";
pub(crate) const MEDIA_ICE_STATE: &str = "_f6d472be910ab1d7322bbadf";
pub(crate) const MEDIA_UNAVAILABLE: &str = "_53a4bc8e7faec89e93d6b000";
pub(crate) const MEDIA_CANDIDATE: &str = "_f6e0345d8c29ab2055f72609";
pub(crate) const MEDIA_CANDIDATE_TIME: &str = "_b77ac88bc96e1b8f478fee4a";
pub(crate) const MEDIA_DATA_CHANNEL: &str = "_538af0a1cfc635f286a37a76";
pub(crate) const MEDIA_REUSED: &str = "_c72defce69f0c94b1c40b17a";
pub(crate) const MEDIA_PRIOR_COUNT: &str = "_ba31acd3ba1c651c58268d2c";
pub(crate) const MEDIA_FIRST_CANDIDATE: &str = "_cd80a8ef68163ad6ce4c080e";
pub(crate) const MEDIA_ELAPSED: &str = "_fa5971a527a24b1a95854b8c";
pub(crate) const MEDIA_CHANNEL_ERROR: &str = "_5074ccd3d62b20984013a86b";
pub(crate) const MEDIA_SEED_OFFER_ERROR: &str = "_53089dcf29654deafd766592";
pub(crate) const MEDIA_SEED_GATHER_ERROR: &str = "_c781a8c6e10f1962d6344856";

/// Recognition recovers the network information probe's output names from the probe itself.
#[cfg(test)]
pub(crate) const NETWORK_INFORMATION_OUTPUTS: [&str; 6] = [
    "_916465939c983b0e34932f10",
    "_ee17ddb325bc2672e4632345",
    "_089f27b0144047a027148655",
    "_120472427ce39965f7989ab9",
    "_7fa3fbe4ce55c442d8ce5ffb",
    "_a19915adb31d352013e44e49",
];

pub(crate) const PRIVATE_TOKEN_ELAPSED: &str = "_c2752bbd593e00cd0a557236";
pub(crate) const PRIVATE_TOKEN_ERROR: &str = "_788b80e93e6f07f8df3a191f";
pub(crate) const PRIVATE_TOKEN_TOKEN: &str = "_ce8d4c2947640b9eeab9edf5";
pub(crate) const PRIVATE_TOKEN_TIMESTAMP: &str = "_b9520771bad17798d15b6a4d";
/// The error the probe reports when its worker reaches its deadline.
pub(crate) const PRIVATE_TOKEN_TIMEOUT_ERROR: &str = "_5f147af36bc5c883dfb4a8f0";
/// The flag every reply of the probe's worker sets.
pub(crate) const PRIVATE_TOKEN_WORKER_REPLIED: &str = "_bd7744733cde9138e62e7c05";
/// The reply field holding the worker fetch error.
pub(crate) const PRIVATE_TOKEN_WORKER_ERROR: &str = "_755032ac06c14e942209534c";

pub(crate) const WORKER_FETCH_STATUS: &str = "_34ede69a56e30699295d3fe7";
pub(crate) const WORKER_FETCH_TOKEN: &str = "_04b7567131213446f02e16b1";

pub(crate) const WORKER_NAVIGATOR_INDICATOR: &str = "_4151217be1606ceeefdfdccb";
pub(crate) const WORKER_NAVIGATOR_RESULT: &str = "_bc44d64454a4d30a2e2a50ea";

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
