//! Replays stored browser probe answers into current sessions.
//!
//! Device profiles store fields under reference-build names ([`super::vocabulary`]). They
//! preserve the browser's write order and identify fields written after the timestamps. Replay
//! translates names for the current session and updates session-dependent values.
//!
//! Classification across 28 captures, including 12 benchmarks, determines each [`Treatment`].
//! Device facts are retained. [`Session`] refreshes iframe URLs and `document.lastModified`,
//! plus trace membership and navigation sizes in the environment audit. Live requests, fresh
//! WebRTC state, benchmark results, and stacks are computed separately.

use std::collections::BTreeMap;
use std::mem;
use std::ops::Range;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::analysis;
use super::probes::worker_navigator;
use super::records::{ArrangedFields, Probe, ProbePlan};
use super::reference::{
    ENVIRONMENT_AUDIT_DECODED, ENVIRONMENT_AUDIT_ENCODED, ENVIRONMENT_AUDIT_GROUPS,
    ENVIRONMENT_AUDIT_REDUCTION, ENVIRONMENT_AUDIT_VALUES, ENVIRONMENT_REFERRER, REFERENCE,
    WORKER_NAVIGATOR_RESULT,
};
use super::registry::{AUDIT_PROBE, Kind, Operation, Treatment};
use super::trace::Trace;
use super::vocabulary::Vocabulary;
use crate::http::ResponseMetrics;
use crate::js::{JsObject, JsValue, Options, Payload, json};
use crate::script::Source;

/// One device's stored answers.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Answers {
    /// The digest of the reference build the names belong to.
    pub reference: String,
    /// Stored probe answers indexed by one-based reference probe number.
    pub probes: BTreeMap<usize, Stored>,
    /// The worker navigator, by API property.
    pub navigator: JsObject,
}

/// One probe's stored record, without its envelope.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Stored {
    /// How long the probe took, in milliseconds.
    pub duration: Option<i64>,
    /// The fields in the order the browser wrote them.
    pub fields: JsObject,
    /// The fields the browser wrote after the record's clock marks, from callbacks that outlived
    /// the probe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub late: Vec<String>,
}

impl Answers {
    /// Builds stored answers from a captured iframe script, probe program, and second payload.
    pub fn capture(source: &Source, program: &[u8], payload: &Payload) -> Result<Self> {
        let analysis = analysis::analyze(source, program)?;
        let plan = analysis.plan();
        let vocabulary = plan.vocabulary();
        let envelope = &plan.record_fields;
        let envelope_names = envelope.names();
        let is_envelope = |name: &String| envelope_names.contains(&name.as_str());
        let mut answers = Self {
            reference: REFERENCE.digest.clone(),
            ..Self::default()
        };
        for probe in plan.probes() {
            let position = probe.position();
            let mut fields = payload
                .get(&probe.index.to_string())
                .and_then(JsValue::as_object)
                .with_context(|| format!("the payload has no record for probe {}", probe.index))?
                .clone();
            let Some(operation) = &probe.operation else {
                continue;
            };
            let duration = fields
                .get(&envelope.completion.duration)
                .and_then(JsValue::as_i64);
            // The clock marks are written when the probe finishes; callbacks that outlive it
            // write after them.
            let marks = fields
                .get_index_of(&envelope.completion.started)
                .unwrap_or(fields.len());
            let late: Vec<String> = fields
                .keys()
                .skip(marks)
                .filter(|name| !is_envelope(name))
                .map(|name| vocabulary.to_reference(position, name).to_owned())
                .collect();
            fields.retain(|name, _| !is_envelope(name));
            let session_name = |name| vocabulary.to_session(position, name);
            if let Operation::WorkerNavigator(worker_navigator::Fields { properties }) = operation
                && let Some(values) = fields
                    .get(session_name(WORKER_NAVIGATOR_RESULT))
                    .and_then(JsValue::as_object)
            {
                for (output, property) in properties {
                    if let Some(value) = values.get(session_name(output)) {
                        answers.navigator.insert(property.clone(), value.clone());
                    }
                }
            }
            if operation.kind().treatment() == Treatment::Computed {
                continue;
            }
            // Only paired probes have field names that can be mapped across builds.
            let Some(partner) = vocabulary.partner(position) else {
                continue;
            };
            vocabulary.rewrite_to_reference(position, &mut fields);
            // Replay refreshes an audit's navigation sizes and trace by reference name.
            if operation.family() == Kind::EnvironmentAudit {
                ensure!(
                    fields.contains_key(ENVIRONMENT_AUDIT_GROUPS)
                        && fields.contains_key(ENVIRONMENT_AUDIT_VALUES),
                    "probe {} is an environment audit whose groups and values lack their \
                     reference names",
                    probe.index
                );
            }
            let stored = Stored {
                duration,
                fields,
                late,
            };
            answers.probes.insert(partner, stored);
        }
        Ok(answers)
    }

    /// Checks that stored answer names belong to the embedded reference build.
    pub fn check(&self) -> Result<()> {
        ensure!(
            self.reference == REFERENCE.digest,
            "the stored answers name reference build {}, not the embedded {}",
            self.reference,
            REFERENCE.digest
        );
        Ok(())
    }
}

/// Stored answers matched to one session's probes.
pub struct Replay<'answers> {
    answers: &'answers Answers,
    vocabulary: &'answers Vocabulary,
}

impl<'answers> Replay<'answers> {
    /// Matches `answers` to `plan`'s probes using the plan's vocabulary.
    #[must_use]
    pub fn new(answers: &'answers Answers, plan: &'answers ProbePlan) -> Self {
        Self {
            answers,
            vocabulary: plan.vocabulary(),
        }
    }

    /// Finds environment-audit groups that report window dimensions and position.
    #[must_use]
    pub fn audit_groups<'r>(
        &self,
        plan: &ProbePlan,
        records: &'r JsObject,
    ) -> Option<&'r JsObject> {
        let position = (0..plan.probes().len())
            .find(|&position| self.vocabulary.partner(position) == Some(AUDIT_PROBE))?;
        let groups = self
            .vocabulary
            .to_session(position, ENVIRONMENT_AUDIT_GROUPS);
        records
            .get(&plan.probes()[position].index.to_string())?
            .get(groups)?
            .as_object()
    }

    #[must_use]
    pub fn duration(&self, probe: &Probe) -> Option<i64> {
        let partner = self.vocabulary.partner(probe.position())?;
        self.answers.probes.get(&partner)?.duration
    }

    /// Renames a stored record for `probe` and updates session-dependent values. Preserves
    /// field order and which fields were written before or after the timestamps.
    pub fn answer(&self, probe: &Probe, session: &Session<'_>) -> Result<ArrangedFields> {
        let position = probe.position();
        let missing = || {
            let candidate = match self.vocabulary.candidate(position) {
                Some(candidate) => format!(
                    "reference probe {} ({:.2})",
                    candidate.reference, candidate.similarity
                ),
                None => "none".to_owned(),
            };
            format!(
                "no stored answer for probe {} ({}); its strongest candidate is {candidate}",
                probe.index,
                probe
                    .operation
                    .as_ref()
                    .map_or("unrecognized", |operation| operation.family().as_str())
            )
        };
        let partner = self.vocabulary.partner(position).with_context(missing)?;
        let stored = self.answers.probes.get(&partner).with_context(missing)?;
        let mut fields = stored.fields.clone();
        session.patch(probe, &mut fields)?;
        let mut arranged = ArrangedFields::split(fields, &stored.late);
        for fields in [&mut arranged.early, &mut arranged.late] {
            self.vocabulary.rewrite_to_session(position, fields);
        }
        Ok(arranged)
    }
}

/// Current-session values needed to refresh stored records.
pub struct Session<'session> {
    /// The iframe's URL, which records report as the referrer, base URI and stack locations.
    pub iframe_url: &'session str,
    /// `document.lastModified`, as the browser formats it.
    pub modified: String,
    /// Iframe `document.referrer`, set by the embedding page's policy or empty when absent.
    pub referrer: &'session str,
    /// The iframe's navigation, which the environment audit measures.
    pub navigation: &'session ResponseMetrics,
    /// The challenge options, one of which names the Server-Timing metric the audit reads.
    pub options: &'session Options,
    /// The helpers that keep the iframe's session trace, which the audit classifies.
    pub trace: Option<Trace>,
    /// The returned program's own trace frame.
    pub controller: Option<&'session str>,
}

impl Session<'_> {
    /// Patches a stored record while it still uses reference names: document identity, the
    /// referrer, and the environment audit's trace membership and navigation measurements.
    fn patch(&self, probe: &Probe, fields: &mut JsObject) -> Result<()> {
        for value in fields.values_mut() {
            refresh_transplant(value, self.iframe_url, &self.modified);
        }
        if let Some(referrer) = fields.get_mut(ENVIRONMENT_REFERRER) {
            *referrer = json!(self.referrer);
        }
        if let Some(groups) = fields
            .get_mut(ENVIRONMENT_AUDIT_GROUPS)
            .and_then(JsValue::as_object_mut)
        {
            let trace = self
                .trace
                .as_ref()
                .context("the environment audit needs the iframe's trace")?;
            refresh_trace(trace, groups, &probe.features, self.controller)?;
        }
        if let Some(values) = fields
            .get_mut(ENVIRONMENT_AUDIT_VALUES)
            .and_then(JsValue::as_object_mut)
        {
            let navigation = self.navigation;
            for (name, value) in [
                (ENVIRONMENT_AUDIT_DECODED, json!(navigation.decoded_bytes)),
                (ENVIRONMENT_AUDIT_ENCODED, json!(navigation.encoded_bytes)),
                (ENVIRONMENT_AUDIT_REDUCTION, self.reduction(probe)),
            ] {
                values.insert(name.to_owned(), value);
            }
        }
        Ok(())
    }

    /// The audit's decoded-body size minus the selected Server-Timing duration, when positive.
    fn reduction(&self, probe: &Probe) -> JsValue {
        let metric = timing_option(&probe.features, self.options)
            .and_then(|option| self.options.get(option)?.as_str());
        let timing = &self.navigation.server_timing;
        match metric.and_then(|metric| timing.iter().find(|(name, _)| name == metric)) {
            Some((_, duration)) if *duration > 0.0 => {
                json!(self.navigation.decoded_bytes as f64 - duration)
            }
            _ => JsValue::Null,
        }
    }
}

/// Finds the option naming the audit's Server-Timing metric: the first option name after
/// `decodedBodySize` in the probe's strings, which some builds precede with `_cf_chl_opt`.
fn timing_option<'f>(features: &'f [String], options: &Options) -> Option<&'f str> {
    let decoded = features.iter().position(|text| text == "decodedBodySize")?;
    features[decoded..]
        .iter()
        .map(String::as_str)
        .find(|text| options.contains_key(*text))
}

/// Stored challenge iframe URLs: the platform root, a route segment such as `b` or `g`, and the
/// iframe path.
const IFRAME_PLATFORM: &str = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/";
const IFRAME_PATH: &str = "/turnstile/f/av0/rch/";

/// Finds the first stored iframe URL in `text`, regardless of route. The URL ends at a
/// delimiter or at the `:line:column` suffix of a stack location.
fn find_iframe_url(text: &str) -> Option<Range<usize>> {
    let start = text
        .match_indices(IFRAME_PLATFORM)
        .map(|(start, _)| start)
        .find(|&start| {
            let route = &text[start + IFRAME_PLATFORM.len()..];
            let length = route
                .find(|character: char| !character.is_ascii_alphanumeric())
                .unwrap_or(route.len());
            length > 0 && route[length..].starts_with(IFRAME_PATH)
        })?;
    let url = &text[start..];
    let length = url
        .char_indices()
        .find(|&(offset, character)| {
            matches!(character, '"' | ' ' | '\n' | '\r' | '\t' | '\\' | ')' | '|')
                || character == ':'
                    && url[offset + 1..].starts_with(|next: char| next.is_ascii_digit())
        })
        .map_or(url.len(), |(offset, _)| offset);
    Some(start..start + length)
}

/// A `document.lastModified` timestamp, as the browser formats it.
fn is_document_date(text: &str) -> bool {
    text.len() == 19
        && text.bytes().enumerate().all(|(at, byte)| match at {
            2 | 5 => byte == b'/',
            10 => byte == b' ',
            13 | 16 => byte == b':',
            _ => byte.is_ascii_digit(),
        })
}

/// Replaces stored iframe URLs and `document.lastModified` timestamps with this session's. A
/// URL without a query, as JavaScriptCore's stack locations give it, stays without one.
fn refresh_string(text: &mut String, iframe_url: &str, modified: &str) {
    if is_document_date(text) {
        *text = modified.to_owned();
        return;
    }
    let without_query = iframe_url
        .split_once('?')
        .map_or(iframe_url, |(url, _)| url);
    let mut searched = 0;
    while let Some(found) = find_iframe_url(&text[searched..]) {
        let url = searched + found.start..searched + found.end;
        let session_url = if text[url.clone()].contains('?') {
            iframe_url
        } else {
            without_query
        };
        searched = url.start + session_url.len();
        text.replace_range(url, session_url);
    }
}

/// Moves the trace global to the audit group matching this session's trace frames. Uses the
/// recovered controller frame as the second root, or the iframe callback frame if none was
/// recovered.
fn refresh_trace(
    trace: &Trace,
    groups: &mut JsObject,
    features: &[String],
    controller: Option<&str>,
) -> Result<()> {
    let member = JsValue::String(format!("o.{}", trace.global));
    let traced =
        |names: &JsValue| matches!(names, JsValue::Array(names) if names.contains(&member));
    if !groups.values().any(traced) {
        return Ok(());
    }
    let entered = features
        .windows(2)
        .find(|pair| pair[1] == trace.replace)
        .map(|pair| pair[0].as_str())
        .context("environment audit has no session trace entry")?;
    let second = controller.unwrap_or(&trace.returned_root);
    let key = format!("{},{},{}", trace.initial_root, second, entered);
    for (old_key, mut names) in mem::take(groups) {
        let members = names
            .as_array_mut()
            .context("environment audit group is not an array")?;
        let has_trace = members.contains(&member);
        members.retain(|name| *name != member);
        if !has_trace || !members.is_empty() {
            group(groups, old_key).append(members);
        }
        if has_trace {
            group(groups, key.clone()).push(member.clone());
        }
    }
    Ok(())
}

/// Returns the audit group named by `key`, creating an empty group if absent.
fn group(groups: &mut JsObject, key: String) -> &mut Vec<JsValue> {
    groups
        .entry(key)
        .or_insert_with(|| JsValue::Array(Vec::new()))
        .as_array_mut()
        .expect("the groups being rebuilt are all arrays")
}

/// Refreshes document identity in stored values and classification keys. Merges members when
/// refreshed keys coincide. Preserves other recorded browser facts.
fn refresh_transplant(value: &mut JsValue, iframe_url: &str, modified: &str) {
    match value {
        JsValue::String(text) => refresh_string(text, iframe_url, modified),
        JsValue::Array(items) => {
            for item in items {
                refresh_transplant(item, iframe_url, modified);
            }
        }
        JsValue::Object(map) => {
            for (mut key, mut value) in mem::take(map) {
                refresh_string(&mut key, iframe_url, modified);
                refresh_transplant(&mut value, iframe_url, modified);
                if let Some(JsValue::Array(members)) = map.get_mut(&key)
                    && let JsValue::Array(incoming) = value
                {
                    for member in incoming {
                        if !members.contains(&member) {
                            members.push(member);
                        }
                    }
                } else {
                    map.insert(key, value);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js;

    #[test]
    fn the_trace_moves_alone_into_this_sessions_group() {
        let trace = Trace {
            global: "trace".into(),
            replace: "replaceTrace".into(),
            push: None,
            initial_root: "fresh-root".into(),
            returned_root: "fresh-response".into(),
        };
        let refreshed = |features: &[String], controller: Option<&str>| {
            let mut groups: JsObject = js::from_value(json!({
                "old-root,old-response,old-probe": ["o.trace", "other"], "T": ["enabled"],
                "empty": []
            }))
            .unwrap();
            refresh_trace(&trace, &mut groups, features, controller)?;
            anyhow::Ok(js::stringify_object(&groups))
        };
        let features = ["fresh-probe".to_owned(), "replaceTrace".to_owned()];
        assert_eq!(
            refreshed(&features, None).unwrap(),
            r#"{"old-root,old-response,old-probe":["other"],"fresh-root,fresh-response,fresh-probe":["o.trace"],"T":["enabled"],"empty":[]}"#
        );
        // A controller frame the returned program pushed takes the iframe callback frame's place
        // as the second root.
        assert_eq!(
            refreshed(&features, Some("controller-frame")).unwrap(),
            r#"{"old-root,old-response,old-probe":["other"],"fresh-root,controller-frame,fresh-probe":["o.trace"],"T":["enabled"],"empty":[]}"#
        );
        assert!(refreshed(&[], None).is_err());
    }

    const CURRENT: &str = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/av0/rch/y3vzw/0x4AAAAAAB8gDxRzm2UASWbL/light/fbE/new/normal?lang=auto";
    const STALE: &str = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/turnstile/f/av0/rch/qvihw/0x4AAAAAAB8gDxRzm2UASWbL/light/fbE/new/normal?lang=auto";

    #[test]
    fn recorded_transplants_carry_this_session_identity() {
        let (stale_without_query, _) = STALE.split_once('?').unwrap();
        let (current_without_query, _) = CURRENT.split_once('?').unwrap();
        let mut fields = json!({
            "referrer": STALE,
            "stack": format!("Error\n    at y1.XL ({STALE}:1:78859)"),
            // iOS Safari's stack locations leave out the query.
            "webkit_stack": format!("VB@{stale_without_query}:1:130348"),
            "modified": "10/07/2026 19:40:31",
            // A plain value is untouched.
            "cookie": "s",
            // Replace a stored iframe URL even if it used a different route.
            "other_route": format!("ho@{}:2:20683", STALE.replace("/h/g/", "/h/b/")),
            "nested": [format!("seen at {STALE}")],
            "groups": {STALE: ["d.referrer"], "10/07/2026 19:40:31": ["d.lastModified"]},
            // Cookie groups describe the property's type, even for an empty string.
            "audit": {"s": ["d.cookie"]},
        });
        refresh_transplant(&mut fields, CURRENT, "10/10/2026 18:32:24");
        assert_eq!(
            fields,
            json!({
                "referrer": CURRENT,
                "stack": format!("Error\n    at y1.XL ({CURRENT}:1:78859)"),
                "webkit_stack": format!("VB@{current_without_query}:1:130348"),
                "modified": "10/10/2026 18:32:24",
                "cookie": "s",
                "other_route": format!("ho@{CURRENT}:2:20683"),
                "nested": [format!("seen at {CURRENT}")],
                "groups": {CURRENT: ["d.referrer"], "10/10/2026 18:32:24": ["d.lastModified"]},
                "audit": {"s": ["d.cookie"]},
            })
        );
        assert!(is_document_date("10/07/2026 19:40:31"));
        assert!(!is_document_date("10/07/2026"));
        assert!(!is_document_date("1791671529"));
    }

    #[test]
    fn the_timing_option_is_the_first_option_after_the_decoded_size() {
        let options = Options::from_iter([
            ("aSeky4".to_owned(), json!("frrs4qtc")),
            ("JWud0".to_owned(), json!(1)),
        ]);
        let option = |texts: &str| {
            let features: Vec<String> = texts.split(' ').map(str::to_owned).collect();
            timing_option(&features, &options).map(str::to_owned)
        };
        // Builds read it with and without naming `_cf_chl_opt` first.
        let current = "JWud0 decodedBodySize encodedBodySize aSeky4 serverTiming";
        assert_eq!(option(current).as_deref(), Some("aSeky4"));
        let named = "decodedBodySize _cf_chl_opt aSeky4 JWud0";
        assert_eq!(option(named).as_deref(), Some("aSeky4"));
        assert_eq!(option("aSeky4 serverTiming"), None);
    }
}
