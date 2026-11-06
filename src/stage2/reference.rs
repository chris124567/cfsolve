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
pub(crate) const PLATFORM_OPTION: &str = "_61e7550cb6b4bdd13e5e6cdf";
/// The option holding the session's ray, which the worker fetch requests.
pub(crate) const RAY_OPTION: &str = "_6917f47d281ba54bc5956244";
/// The option holding the nonce the worker fetch requests.
pub(crate) const NONCE_OPTION: &str = "_ca0ac6bf4c619f1f6d77467e";

/// Shared result field used by clock and private-token probes.
pub(crate) const SHARED_RESULT: &str = "_6e834e0d80e79f99f3e3c621";

/// What the clock probe reports when its worker fails.
pub(crate) const CLOCK_FALLBACK: &str = "_71ba78019b7f9643f2d8676c";

pub(crate) const DATES_TODAY: &str = "_a614b792240c7239c3b90a0f";
pub(crate) const DATES_OFFSET: &str = "_19d2e214590e0ed54474b83f";
pub(crate) const DATES_ZONE: &str = "_6642b9bf508a9a8a56fc75a6";

pub(crate) const DOM_MUTATION_RESULT: &str = "_38d7dd4de03b4319c02bcd23";

// Environment and environment-audit names with session-specific replay patches.

/// The environment probe's `document.referrer`.
pub(crate) const ENVIRONMENT_REFERRER: &str = "_918d40e1589474fa234a7dfb";
/// The audit's groups of readers, by the value they read.
pub(crate) const ENVIRONMENT_AUDIT_GROUPS: &str = "_ab03e54c0eaeabaaa88a79af";
/// The audit's measured values.
pub(crate) const ENVIRONMENT_AUDIT_VALUES: &str = "_0fd3fb16d62a09a96c3011c0";
/// Navigation decoded size minus a Server-Timing duration.
pub(crate) const ENVIRONMENT_AUDIT_REDUCTION: &str = "_a7dc0e2158b3f79371af65eb";
/// Navigation decoded size.
pub(crate) const ENVIRONMENT_AUDIT_DECODED: &str = "_a7f1b9185bc330b1a3102acc";
/// Navigation encoded size.
pub(crate) const ENVIRONMENT_AUDIT_ENCODED: &str = "_0b5e100d843fbc660d3ae2e8";
/// Whether the probe's frame supports touch events.
pub(crate) const ENVIRONMENT_AUDIT_TOUCH: &str = "_40f087c21d8a2e447e2016d2";
/// The probe frame's `isSecureContext` value.
pub(crate) const ENVIRONMENT_AUDIT_SECURE: &str = "_a09c662213172dfdf7fe11cd";
/// The value of `Notification.permission`.
pub(crate) const ENVIRONMENT_AUDIT_PERMISSION: &str = "_f1e2967f23abbbf676f8a3a9";

/// The isolation probe's results for blocked evaluation and cross-origin history writes.
pub(crate) const ISOLATION_FAILURE_FIELDS: [&str; 2] =
    ["_4dab37431407f6aa72aa262d", "_7ca4f44cb8e7aaf5802217d5"];
pub(crate) const STYLESHEETS_TEXT: &str = "_2da798f52f05c8e2a3575e52";
pub(crate) const STYLESHEETS_HASH: &str = "_3d4d40ff2e985151f19ad154";

pub(crate) const ERROR_MESSAGE_LENGTH_RESULT: &str = "_0d4993e111c0f8ff7cb86b23";

pub(crate) const IMAGE_WIDTH: &str = "_c937904afdbf6a962a495698";
pub(crate) const IMAGE_HEIGHT: &str = "_73085dbd94bdf2f4a55ea8d4";
pub(crate) const IMAGE_EFFECTIVE_TYPE: &str = "_bd02f25dbe60a1cd3392f2a1";
pub(crate) const IMAGE_ONLINE: &str = "_1284c12e9b3dc9629a99b60e";
pub(crate) const IMAGE_COMPLETE: &str = "_899febc1aed6643cb3bdd449";
pub(crate) const IMAGE_NATURAL_WIDTH: &str = "_869abd1318296f606f53f835";
pub(crate) const IMAGE_TIMESTAMP: &str = "_52ffb507df01acf3dec37475";
/// What the probe reports as both dimensions when the image fails to load.
pub(crate) const IMAGE_LOAD_ERROR: &str = "_0d9880b397052efc378cd26b";
/// Dimension values reported before the image load finishes.
pub(crate) const IMAGE_PENDING: &str = "_976c7c9cab404c1b8b94b9f4";
/// The key the probe's worker replies with when its deadline passes.
pub(crate) const IMAGE_WORKER_TIMEOUT: &str = "_5e5d151d1f58f76e7c42c1d6";
/// A name the probe shares with the other probes that await a promise.
pub(crate) const IMAGE_AWAITING: &str = "_043b45997a2670daf27b7021";

pub(crate) const MEDIA_STATE: &str = "_da7bc3a155dca43d5b49f1fa";
pub(crate) const MEDIA_CODECS: &str = "_4213e832a7feb534313b4f39";
pub(crate) const MEDIA_CANDIDATES: &str = "_e63a20d14646da909acd55f9";
pub(crate) const MEDIA_SDP: &str = "_8de55a1f52d181e06ccbbe8b";
pub(crate) const MEDIA_SUPPORT: &str = "_d702e8115f0b764649363d3d";
pub(crate) const MEDIA_ICE_STATE: &str = "_c3a7b9dd369b66837d9e7f98";
pub(crate) const MEDIA_UNAVAILABLE: &str = "_9797a3d5bb0f64080d0d214c";
pub(crate) const MEDIA_CANDIDATE: &str = "_ae22777f7d3d713e841feca5";
pub(crate) const MEDIA_CANDIDATE_TIME: &str = "_ca5e7a972d36bf952fbf09c5";
pub(crate) const MEDIA_DATA_CHANNEL: &str = "_4b86eecf1feba1c6b48c4292";
pub(crate) const MEDIA_REUSED: &str = "_fb480f4b21b6c9b3d1d979a4";
pub(crate) const MEDIA_PRIOR_COUNT: &str = "_a443a02c5d78d387b779d0b3";
pub(crate) const MEDIA_FIRST_CANDIDATE: &str = "_a3e7026918f5e4d34d5865ac";
pub(crate) const MEDIA_ELAPSED: &str = "_b2327e7a4a9eb807909c1741";
pub(crate) const MEDIA_CHANNEL_ERROR: &str = "_64a8b5f81817b0e33dd1751b";
pub(crate) const MEDIA_SEED_OFFER_ERROR: &str = "_f6d7e9eeabea462322f299fa";
pub(crate) const MEDIA_SEED_GATHER_ERROR: &str = "_183cd094666f8d499a59c133";

/// Recognition recovers the network information probe's output names from the probe itself.
#[cfg(test)]
pub(crate) const NETWORK_INFORMATION_OUTPUTS: [&str; 6] = [
    "_6e966490231e673457e97a79",
    "_e56b5c0ff1f6c80af985ffa7",
    "_e2911f4822a370d64b43df18",
    "_9b899864a6fdfdc9e455943b",
    "_1a2b017fe7e3665eae6f45e2",
    "_6755e905972745530aa44b2b",
];

pub(crate) const PARENT_INFO_REFERRER: &str = "_31a6173d1692e77e5a1005d5";
pub(crate) const PARENT_INFO_MISSING: &str = "_10450802c4fb954516e0c07b";
pub(crate) const PARENT_INFO_REASONS: &str = "_cd7d13df270697c8781d261c";
pub(crate) const PARENT_INFO_VISIBILITY: &str = "_4172551fe148377bcda1f7b5";
/// The widget wrapper's `top|right` on the embedding page, from `getBoundingClientRect()`.
pub(crate) const PARENT_INFO_WIDGET_POSITION: &str = "_5ef82acb130f4537ed9aac35";
/// The output the embedding page's `pad` property is copied to.
pub(crate) const PARENT_INFO_PAD: &str = "_e5caf599351485e860642415";
/// Pairs of output fields and parent-info properties copied directly.
pub(crate) const PARENT_INFO_DIRECT: [(&str, &str); 16] = [
    ("_6e1dc8b6953acf52c04a8602", "vDuh"),
    ("_4f08666db7270b9f907f663c", "vDie"),
    ("_c8cb367a7b94d575149530e3", "xp"),
    (PARENT_INFO_WIDGET_POSITION, "wp"),
    ("_62193c48d482daf2700a995c", "pfp"),
    ("_1c113a764991c259adfcf85b", "sL"),
    ("_3da484dbed1006c654fac96e", "ssL"),
    ("_c74be140015d9b0e3d256c48", "mL"),
    ("_d6f250eb3d24cd44d78bab61", "t"),
    ("_1d5d7b99f35d507b3a08a437", "tL"),
    ("_af146df9ca80117c88f514dd", "lH"),
    ("_cf3a9d328d85b9c7f2ae9457", "sR"),
    ("_4c7024270fd2a920c7ce5503", "ii"),
    ("_e4689550ed6807ca8acfeff4", "ffp"),
    ("_fd302ee89388067a1cfa51d9", "pac"),
    (PARENT_INFO_PAD, "pad"),
];
/// Pairs of output fields and parent-info properties copied with an empty-string fallback for
/// falsy values.
pub(crate) const PARENT_INFO_FALLBACK: [(&str, &str); 4] = [
    ("_3bce4851046c22ddb9da2a5b", "vDmt"),
    ("_70346a8995cdbf5b1cd02bc7", "vDhp"),
    ("_d9c1b344a652122a42aa8fdf", "vDmd"),
    ("_1b4e766af5a14e457b0a4459", "vDa"),
];

pub(crate) const PRIVATE_TOKEN_ELAPSED: &str = "_3a403a5bfbe5ad79fcb6d7fa";
pub(crate) const PRIVATE_TOKEN_ERROR: &str = "_11fe3c7cf759c9e85c056175";
pub(crate) const PRIVATE_TOKEN_TOKEN: &str = "_8c0a7d305ce60d56c7e050e0";
pub(crate) const PRIVATE_TOKEN_TIMESTAMP: &str = "_c323fa9d32f21c57738f2d52";
/// The error the probe reports when its worker reaches its deadline.
pub(crate) const PRIVATE_TOKEN_TIMEOUT_ERROR: &str = "_86c0f719c753efd2add5a423";
/// The flag every reply of the probe's worker sets.
pub(crate) const PRIVATE_TOKEN_WORKER_REPLIED: &str = "_502dfebb48ad4577f94b398b";
/// The reply field holding the worker fetch error.
pub(crate) const PRIVATE_TOKEN_WORKER_ERROR: &str = "_1bd19da8fe35caf76f114593";

pub(crate) const WORKER_FETCH_STATUS: &str = "_450ac63dd9d56cfdc07a45a6";
pub(crate) const WORKER_FETCH_TOKEN: &str = "_6c33957a5fcf43fae4182402";

pub(crate) const WORKER_NAVIGATOR_INDICATOR: &str = "_85ce50de34c865aae5312e53";
pub(crate) const WORKER_NAVIGATOR_RESULT: &str = "_f436ec62fa333f0b9cd2d3a4";

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
