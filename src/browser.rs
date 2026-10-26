//! Describes the browser used by a session. Profiles and stored answers are validated before
//! any network requests.
//!
//! Fingerprint files use JSON and ignore unknown keys. The engine, transport, request headers,
//! page and orchestrator timelines, resource timing, interaction, probe timings, and navigator
//! are required. Errors identify missing fields. The `browser` page layout section uses
//! defaults when absent, but rejects invalid values, including `null`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, mem};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use wreq::header::USER_AGENT;

use crate::challenge::state::Intervals;
use crate::embedding_page::extra_params::Timeline;
use crate::embedding_page::page::Layout;
use crate::engine::Engine;
use crate::error::Error;
use crate::fingerprint::{self, Transport, TransportSection};
use crate::js::{JsObject, JsValue, Window};
use crate::resource_timing::Reporting;
use crate::stage2::interaction::native::Viewport;
use crate::stage2::payload::Document;
use crate::stage2::registry::Facts;
use crate::stage2::replay::Answers;

/// A validated profile shared by solves. Each solve starts a fresh browser session.
pub struct Browser {
    pub(crate) transport: Transport,
    pub(crate) page: Page,
    pub(crate) solve: Solve,
}

/// Browser settings needed by the page that contains the widget.
pub(crate) struct Page {
    pub layout: Layout,
    pub timeline: Timeline,
    pub intervals: Intervals,
    pub orchestrator_pacing: OrchestratorPacing,
    /// Resource timing for fetches whose total duration is the only measurement available.
    pub resource_timing: Reporting,
}

/// Timing settings from the fingerprint's `orchestrator` section. Required even for ordinary
/// pages, since the response determines whether a challenge is needed. Durations must be
/// nonnegative.
#[derive(Deserialize)]
pub(crate) struct OrchestratorPacing {
    /// Startup timestamp intervals (`URVD0`), time to payload construction (`shUar7`), and time
    /// to sending (`mHsm4`).
    pub intervals: Intervals,
    /// Time from widget-program arrival to record creation.
    pub program_startup_ms: u32,
    /// Delay from iframe completion to widget callback settlement.
    pub callback_ms: u32,
}

/// Settings and stored answers for programs returned by the server.
pub(crate) struct Solve {
    pub profile: Profile,
    /// Worker `navigator.hardwareConcurrency`, also reported by the click and proof programs.
    pub hardware_concurrency: f64,
    pub answers: Option<Answers>,
    /// Separate stored answers for widgets on Cloudflare challenge pages, if needed.
    pub challenge_page_answers: Option<Answers>,
    pub viewport: Viewport,
}

/// Browser behavior from the fingerprint's `second` section. Durations must be nonnegative.
#[derive(Deserialize)]
pub(crate) struct Profile {
    /// Probe measurements. This section is required but may be empty. Navigator values combine
    /// stored capabilities, the transport user agent, and explicit profile overrides.
    pub facts: Facts,
    pub document: Document,
    pub image: ImageProbe,
    /// Window globals the iframe holds when the payload is sent.
    #[serde(default)]
    pub window: Window,
    /// Duration of each kind of probe, in milliseconds.
    #[serde(default)]
    pub durations: BTreeMap<String, u32>,
    /// Delay between receiving the program and starting its first probe.
    pub startup_ms: u32,
    /// Time the program allows pending work to finish before sending a response.
    pub pending_ms: u32,
}

/// Navigator values read by the image probe. Connection data must match the network information
/// probe.
#[derive(Deserialize)]
pub(crate) struct ImageProbe {
    /// `navigator.connection.effectiveType`.
    pub effective_type: String,
    /// `navigator.onLine`.
    pub online: bool,
}

/// Fingerprint settings loaded for a solve.
#[derive(Deserialize)]
struct Fingerprint {
    engine: Engine,
    transport: TransportSection,
    #[serde(default)]
    browser: Layout,
    timeline: Timeline,
    intervals: Intervals,
    orchestrator: OrchestratorPacing,
    resource_timing: Reporting,
    interaction: Viewport,
    second: Profile,
    /// Stored answer files, relative to the fingerprint file.
    answers: Option<PathBuf>,
    challenge_page_answers: Option<PathBuf>,
}

impl Browser {
    /// Loads the fingerprint at `path` and the stored answers it names, relative to its directory.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, Error> {
        let load = || {
            let path = path.as_ref();
            let fingerprint: Fingerprint = fingerprint::read(path)?;
            let directory = path.parent().unwrap_or(Path::new(""));
            let answers = stored_answers(directory, fingerprint.answers.as_deref())?;
            let challenge_page_answers =
                stored_answers(directory, fingerprint.challenge_page_answers.as_deref())?;
            Self::configure(fingerprint, answers, challenge_page_answers)
        };
        load().map_err(Error::Config)
    }

    /// Uses a parsed fingerprint and the supplied answers instead of loading the answer files
    /// named by the fingerprint.
    pub fn try_new(
        fingerprint: Value,
        answers: Option<Answers>,
        challenge_page_answers: Option<Answers>,
    ) -> Result<Self, Error> {
        let load = || {
            for answers in answers.iter().chain(&challenge_page_answers) {
                answers.check()?;
            }
            let fingerprint: Fingerprint =
                serde_json::from_value(fingerprint).context("reading the fingerprint")?;
            Self::configure(fingerprint, answers, challenge_page_answers)
        };
        load().map_err(Error::Config)
    }

    fn configure(
        fingerprint: Fingerprint,
        answers: Option<Answers>,
        challenge_page_answers: Option<Answers>,
    ) -> Result<Self> {
        let transport = Transport::try_new(fingerprint.engine, fingerprint.transport)?;
        let page = Page {
            layout: fingerprint.browser,
            timeline: fingerprint.timeline,
            intervals: fingerprint.intervals,
            orchestrator_pacing: fingerprint.orchestrator,
            resource_timing: fingerprint.resource_timing,
        };
        let mut profile = fingerprint.second;
        let facts = &mut profile.facts;
        // The image and network information probes must report the same connection.
        if let Some(effective_type) = facts
            .connection
            .as_ref()
            .and_then(|connection| connection.get("effectiveType"))
        {
            ensure!(
                effective_type.as_str() == Some(profile.image.effective_type.as_str()),
                "fingerprint `second.image.effective_type` disagrees with `second.facts.connection.effectiveType`"
            );
        }
        facts.navigator = navigator(
            answers.as_ref().map(|answers| &answers.navigator),
            mem::take(&mut facts.navigator),
            transport
                .headers
                .get(USER_AGENT)
                .and_then(|value| value.to_str().ok()),
        );
        let hardware_concurrency = facts
            .navigator
            .get("hardwareConcurrency")
            .and_then(JsValue::as_f64)
            .context(
                "the navigator has no numeric `hardwareConcurrency`: give it in the stored answers or `second.facts.navigator`",
            )?;
        Ok(Self {
            transport,
            page,
            solve: Solve {
                profile,
                hardware_concurrency,
                answers,
                challenge_page_answers,
                viewport: fingerprint.interaction,
            },
        })
    }
}

/// Builds the worker navigator from the stored one, then applies the HTTP user agent and explicit
/// profile properties. Partial overrides preserve the other stored capabilities.
fn navigator(stored: Option<&JsObject>, overrides: JsObject, user_agent: Option<&str>) -> JsObject {
    let mut navigator = stored.cloned().unwrap_or_default();
    if let Some(user_agent) = user_agent {
        navigator.insert("userAgent".into(), JsValue::from(user_agent));
    }
    navigator.extend(overrides);
    navigator
}

/// Loads stored answers from `path`, relative to the fingerprint's `directory`.
fn stored_answers(directory: &Path, path: Option<&Path>) -> Result<Option<Answers>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let path = directory.join(path);
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let answers: Answers = serde_json::from_slice(&bytes)
        .with_context(|| format!("reading stored answers {}", path.display()))?;
    answers.check()?;
    Ok(Some(answers))
}

#[cfg(test)]
impl Browser {
    /// Loads the tracked iOS Safari profile for tests.
    pub(crate) fn safari() -> &'static Self {
        static SAFARI: std::sync::OnceLock<Browser> = std::sync::OnceLock::new();
        SAFARI.get_or_init(|| {
            let profile = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/safari-26-ios.json");
            Self::read(profile).expect("the tracked iOS Safari profile loads")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::{self, json};

    #[test]
    fn partial_navigator_override_preserves_stored_capabilities() {
        let stored: JsObject = js::from_value(json!({
            "hardwareConcurrency": 4, "userAgent": "captured", "deviceMemory": 16,
            "languages": ["en-US", "en"], "platform": "Linux x86_64"
        }))
        .unwrap();
        let overrides = JsObject::from_iter([("hardwareConcurrency".into(), JsValue::from(8))]);
        let complete = navigator(Some(&stored), overrides, Some("current HTTP user agent"));
        assert_eq!(
            JsValue::Object(complete),
            json!({
                "hardwareConcurrency": 8, "userAgent": "current HTTP user agent",
                "deviceMemory": 16, "languages": ["en-US", "en"], "platform": "Linux x86_64"
            })
        );
        let explicit = JsObject::from_iter([("userAgent".into(), JsValue::from("explicit"))]);
        assert_eq!(
            navigator(Some(&stored), explicit, Some("header"))["userAgent"],
            "explicit"
        );
    }

    /// A complete fingerprint, using the tracked iOS Safari 26 profile's requests, timelines,
    /// resource timing, interaction and worker costs.
    fn complete() -> Value {
        let tracked: Value = serde_json::from_str(include_str!("../profiles/safari-26-ios.json"))
            .expect("the tracked profile is JSON");
        let mut fingerprint = serde_json::json!({
            "engine": "webkit",
            "transport": {"profile": "safari_ios_26.2", "platform": "ios"},
            "orchestrator": {
                "intervals": {"initialise": 6, "handoff": 0, "collect": 92, "send": 195},
                "program_startup_ms": 15, "callback_ms": 30},
            "second": {"facts": {"navigator": {"hardwareConcurrency": 4},
                    "connection": {"effectiveType": "4g"}},
                "document": {"shadow_root": "{}"},
                "image": {"effective_type": "4g", "online": true},
                "durations": {"image": 5}, "startup_ms": 400, "pending_ms": 15}
        });
        fingerprint["transport"]["requests"] = tracked["transport"]["requests"].clone();
        for section in ["timeline", "intervals", "resource_timing", "interaction"] {
            fingerprint[section] = tracked[section].clone();
        }
        for costs in ["proof_worker", "benchmark_worker"] {
            fingerprint["second"]["facts"][costs] = tracked["second"]["facts"][costs].clone();
        }
        fingerprint
    }

    /// Browser facts have no defaults. Missing or invalid facts are reported before any
    /// network requests.
    #[test]
    fn missing_or_invalid_browser_facts_are_named() {
        for (pointer, value, expected) in [
            ("/engine", None, "missing field `engine`"),
            (
                "/engine",
                Some(Value::from("gecko")),
                "unknown variant `gecko`",
            ),
            ("/transport/profile", None, "missing field `profile`"),
            ("/transport/platform", None, "missing field `platform`"),
            ("/transport/requests", None, "missing field `requests`"),
            (
                "/transport/requests/headers",
                None,
                "missing field `headers`",
            ),
            (
                "/transport/requests/headers/image",
                None,
                "no order for `image` requests",
            ),
            (
                "/transport/requests/headers/iframe",
                Some(serde_json::json!(["user-agent", "sec-fetch-dest"])),
                "nothing gives `sec-fetch-dest` a value",
            ),
            ("/orchestrator", None, "missing field `orchestrator`"),
            (
                "/orchestrator/callback_ms",
                None,
                "missing field `callback_ms`",
            ),
            ("/orchestrator/intervals/send", None, "missing field `send`"),
            (
                "/orchestrator/callback_ms",
                Some(Value::from(-1)),
                "invalid value: integer `-1`",
            ),
            (
                "/orchestrator/intervals/collect",
                Some(Value::from(-1)),
                "invalid value: integer `-1`",
            ),
            ("/timeline", None, "missing field `timeline`"),
            ("/intervals", None, "missing field `intervals`"),
            ("/resource_timing", None, "missing field `resource_timing`"),
            ("/interaction", None, "missing field `interaction`"),
            (
                "/interaction/ready_delay_ms",
                None,
                "missing field `ready_delay_ms`",
            ),
            ("/second", None, "missing field `second`"),
            (
                "/second/facts/proof_worker",
                None,
                "missing field `proof_worker`",
            ),
            (
                "/second/facts/benchmark_worker",
                None,
                "missing field `benchmark_worker`",
            ),
            ("/second/image", None, "missing field `image`"),
            ("/second/image/online", None, "missing field `online`"),
            (
                "/second/durations/image",
                Some(Value::from(-5)),
                "invalid value: integer `-5`",
            ),
            (
                "/second/facts/navigator/hardwareConcurrency",
                None,
                "the navigator has no numeric `hardwareConcurrency`",
            ),
            (
                "/second/facts/navigator/hardwareConcurrency",
                Some(Value::from("4")),
                "the navigator has no numeric `hardwareConcurrency`",
            ),
            (
                "/second/facts/connection/effectiveType",
                Some(Value::from("3g")),
                "disagrees",
            ),
        ] {
            let mut fingerprint = complete();
            match value {
                Some(value) => *fingerprint.pointer_mut(pointer).unwrap() = value,
                None => {
                    let (parent, key) = pointer.rsplit_once('/').unwrap();
                    let parent = fingerprint.pointer_mut(parent).unwrap();
                    parent.as_object_mut().unwrap().remove(key).unwrap();
                }
            }
            let error = Browser::try_new(fingerprint, None, None)
                .err()
                .unwrap_or_else(|| panic!("{pointer} was accepted"));
            let error = format!("{error:#}");
            assert!(error.contains(expected), "{pointer}: {error}");
        }
    }

    #[test]
    fn a_complete_fingerprint_resolves_its_facts() {
        let browser = Browser::try_new(complete(), None, None).unwrap();
        let (page, solve) = (&browser.page, &browser.solve);
        assert_eq!(page.orchestrator_pacing.intervals.send, 195);
        assert_eq!(page.orchestrator_pacing.program_startup_ms, 15);
        assert_eq!(page.orchestrator_pacing.callback_ms, 30);
        assert_eq!(solve.profile.durations["image"], 5);
        assert_eq!(solve.profile.startup_ms, 400);
        assert_eq!(solve.hardware_concurrency, 4.0);
        assert_eq!(solve.profile.image.effective_type, "4g");
        assert!(solve.profile.image.online);
        assert!(solve.answers.is_none());
    }

    #[test]
    fn tracked_profiles_load_with_their_answers() {
        let profiles = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
        for entry in fs::read_dir(profiles).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let browser = Browser::read(&path)
                .unwrap_or_else(|error| panic!("{}: {error:#}", path.display()));
            assert!(
                browser.solve.answers.is_some(),
                "{} names no stored answers",
                path.display()
            );
        }
    }
}
