//! Fills device profiles from proxy recordings.
//!
//! `traffic.json` provides the user agent, client hints, and header order for each request type.
//! Session payloads provide probe durations, startup and pending times, benchmark speeds, media
//! observations, first-payload intervals, and loader timestamps. Most values use the median across
//! sessions. Loader timestamps come from a single session chosen by median send time, so they
//! remain consistent. Challenge-page sessions also place the widget on Cloudflare's page, the
//! network information probe reports `navigator.connection`, and the second payload publishes the
//! browser's shadow-root report.
//!
//! Values that captures cannot provide stay unchanged: engine, TLS and HTTP/2 settings, request
//! priorities, the viewport and site widget layout, interaction, resource timing phases,
//! orchestrator pacing, and navigator properties. `build_profile` writes the stored answers.

mod headers;

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;
use url::Url;

use self::headers::Headers;
use super::CHALLENGE_HOST;
use super::recorded::{CapturedSession, Recording};
use crate::challenge::merge::OptionSource;
use crate::challenge::payload::Field;
use crate::challenge::program::PreparedSession;
use crate::challenge::state::{Intervals, ScriptState};
use crate::embedding_page::extra_params::{ElapsedTimes, Timeline};
use crate::http::{HeaderOrder, RequestKind};
use crate::js::{self, JsObject, JsValue, Payload};
use crate::script::Source;
use crate::stage2::analysis;
use crate::stage2::benchmark::WorkerCosts;
use crate::stage2::probes::ice;
use crate::stage2::probes::media::Measurement;
use crate::stage2::reference::PARENT_INFO_WIDGET_POSITION;
use crate::stage2::registry::{Kind, Operation};

/// Updates measured profile values from `recordings`. Returns notes about the sources used and data
/// skipped. Other profile values stay unchanged.
pub fn fill(profile: &mut Value, recordings: &[Recording]) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    for recording in recordings {
        for skipped in &recording.skipped {
            notes.push(format!("{}: left out {skipped}", recording.label));
        }
    }
    let requests = recordings
        .iter()
        .flat_map(|recording| &recording.traffic.requests);
    fill_headers(profile, Headers::observe(requests), &mut notes)?;
    let script_fetch = section(profile, "/timeline/script_fetch")?
        .as_f64()
        .context("the profile's timeline has no script_fetch")?;
    let sessions: Vec<(&Recording, &String, &CapturedSession)> = recordings
        .iter()
        .flat_map(|recording| {
            let sessions = recording.sessions.iter();
            sessions.map(move |(name, session)| (recording, name, session))
        })
        .collect();
    let mut reported = Reported {
        script_fetch,
        ..Reported::default()
    };
    // Each session's reading is seconds of deobfuscation and analysis, so sessions are read side
    // by side, then taken in order.
    for ((recording, name, _), (read, problems)) in
        sessions.iter().zip(read_all(script_fetch, &sessions)?)
    {
        reported.absorb(read);
        for problem in problems {
            notes.push(format!("{}/{name}: {problem:#}", recording.label));
        }
    }
    reported.fill(profile, &mut notes)?;
    Ok(notes)
}

/// Reads each of `sessions` on a thread of its own (with a main thread's stack: deobfuscation
/// recurses as deep as the scripts nest), as many at once as the machine runs in parallel.
fn read_all(
    script_fetch: f64,
    sessions: &[(&Recording, &String, &CapturedSession)],
) -> Result<Vec<(Reported, Vec<anyhow::Error>)>> {
    const STACK_SIZE: usize = 8 << 20;
    let parallel = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut read = Vec::with_capacity(sessions.len());
    for batch in sessions.chunks(parallel) {
        std::thread::scope(|scope| {
            let threads: Vec<_> = batch
                .iter()
                .map(|&(recording, _, session)| {
                    std::thread::Builder::new()
                        .name("profile-session".into())
                        .stack_size(STACK_SIZE)
                        .spawn_scoped(scope, move || {
                            let mut reported = Reported {
                                script_fetch,
                                ..Reported::default()
                            };
                            let problems = reported.read(recording, session);
                            (reported, problems)
                        })
                })
                .collect::<std::io::Result<_>>()?;
            for thread in threads {
                read.push(thread.join().expect("reading a session panicked"));
            }
            anyhow::Ok(())
        })?;
    }
    Ok(read)
}

/// Updates header orders and browser identity headers for the request types found in the traffic.
fn fill_headers(profile: &mut Value, headers: Headers, notes: &mut Vec<String>) -> Result<()> {
    let own = section(profile, "/transport/headers")?
        .as_object_mut()
        .context("the profile's transport headers are not an object")?;
    let sent = headers.identity.len();
    for (name, value) in headers.identity {
        // Preserve the spelling of headers already in the profile.
        let existing = own
            .keys()
            .find(|key| key.eq_ignore_ascii_case(&name))
            .cloned();
        own.insert(existing.unwrap_or(name), Value::String(value));
    }
    notes.push(format!(
        "transport.headers: the user agent and client hints, {sent} headers from traffic.json"
    ));
    let orders = section(profile, "/transport/requests/headers")?
        .as_object_mut()
        .context("the profile's header orders are not an object")?;
    let observed = &headers.orders;
    for (kind, order) in observed {
        orders.insert(kind.to_string(), serde_json::to_value(order)?);
    }
    // Use one header order if the browser sends the same order before and after a script redirect.
    if let Some(redirect) = observed.get(&RequestKind::ScriptRedirect)
        && observed.get(&RequestKind::Script) == Some(redirect)
    {
        orders.remove(&RequestKind::ScriptRedirect.to_string());
    }
    serde_json::from_value::<HeaderOrder>(Value::Object(orders.clone()))
        .context("the derived header orders are not valid")?;
    let kept: Vec<&str> = orders
        .keys()
        .filter(|kind| !observed.keys().any(|seen| seen.to_string() == **kind))
        .map(String::as_str)
        .collect();
    let kept = if kept.is_empty() {
        "none".to_owned()
    } else {
        kept.join(", ")
    };
    notes.push(format!(
        "transport.requests.headers: {} kinds from traffic.json; kept the profile's {kept}",
        observed.len(),
    ));
    Ok(())
}

/// Measurements collected from session payloads for use in a profile.
#[derive(Default)]
struct Reported {
    /// Loader fetch time from the profile; payloads do not report it.
    script_fetch: f64,
    /// Probe durations by family.
    durations: BTreeMap<&'static str, Vec<i64>>,
    startup_ms: Vec<i64>,
    pending_ms: Vec<i64>,
    benchmark: Vec<WorkerCosts>,
    /// The first session's media observations.
    media: Option<Measurement>,
    intervals: Vec<Intervals>,
    /// Loader timestamps from ordinary sites. Challenge pages load the loader late, so the solver
    /// uses the timestamps from ordinary sites.
    timelines: Vec<Timeline>,
    /// The widget wrapper's top and right edges on Cloudflare's challenge page.
    placements: Vec<(f64, f64)>,
    /// `navigator.connection`'s properties, as each session's network information probe read
    /// them. Browsers without the API report none.
    connections: Vec<JsObject>,
    /// The report of attaching a shadow root to the body, which the second payload publishes.
    shadow_roots: Vec<String>,
}

impl Reported {
    /// Adds a later session's measurements to these. The first session's media observations
    /// stay.
    fn absorb(&mut self, later: Reported) {
        for (family, durations) in later.durations {
            self.durations.entry(family).or_default().extend(durations);
        }
        self.startup_ms.extend(later.startup_ms);
        self.pending_ms.extend(later.pending_ms);
        self.benchmark.extend(later.benchmark);
        self.media = self.media.take().or(later.media);
        self.intervals.extend(later.intervals);
        self.timelines.extend(later.timelines);
        self.placements.extend(later.placements);
        self.connections.extend(later.connections);
        self.shadow_roots.extend(later.shadow_roots);
    }

    /// Collects measurements from `session` and returns notes about data it could not read.
    fn read(&mut self, recording: &Recording, session: &CapturedSession) -> Vec<anyhow::Error> {
        let source = match session.source() {
            Ok(source) => source,
            Err(error) => return vec![error.context("deobfuscating the iframe script")],
        };
        let mut problems = Vec::new();
        let first = session.first_payload();
        let embedding = first.and_then(|first| self.read_first(&source, first, &mut problems));
        let on_challenge_page = embedding.unwrap_or_else(|error| {
            problems.push(error.context("reading the first payload"));
            false
        });
        let read = self.read_records(
            recording,
            session,
            &source,
            on_challenge_page,
            &mut problems,
        );
        if let Err(error) = read {
            problems.push(error.context("reading the probe records"));
        }
        problems
    }

    /// Collects first-payload intervals and the loader timestamps passed from the site to the
    /// iframe. Returns whether the widget is on a challenge page.
    fn read_first(
        &mut self,
        source: &Source,
        payload: &Payload,
        problems: &mut Vec<anyhow::Error>,
    ) -> Result<bool> {
        // Extraction only needs an iframe URL with the same origin as the POSTs.
        let iframe = Url::parse(&format!("https://{CHALLENGE_HOST}/"))?;
        let prepared = PreparedSession::try_new(source, &iframe)?;
        let mapping = prepared.mapping()?;
        let state = prepared.state()?;
        let fields = &prepared.program().payload_fields;
        match state.intervals(fields, mapping.merged(), payload) {
            Ok(intervals) => self.intervals.push(intervals),
            Err(error) => problems.push(error.context("reading the first payload")),
        }
        let mut message = JsObject::new();
        let mut implicit_render = None;
        for entry in &mapping.0 {
            let Some(value) = reported(payload, fields, &state, &entry.option) else {
                continue;
            };
            match &entry.source {
                OptionSource::Message(key) => {
                    message.insert(key.clone(), value.clone());
                }
                // The loader samples its own stack as it renders the page's widgets.
                OptionSource::Samples(_) => {
                    let sample = value.as_array().and_then(|samples| samples.first());
                    implicit_render = sample.and_then(|sample| sample.get("t")?.as_i64());
                }
                _ => {}
            }
        }
        // The orchestrator passes its page data only to widgets on challenge pages.
        if message.get("chlPageData").is_some_and(js::truthy) {
            return Ok(true);
        }
        let times: ElapsedTimes = js::from_value(JsValue::Object(message))
            .context("the first payload lacks the loader's elapsed times")?;
        let implicit_render =
            implicit_render.context("the first payload lacks the loader's stack sample")?;
        let timeline = Timeline::from_times(&times, implicit_render, self.script_fetch);
        self.timelines.push(timeline);
        Ok(false)
    }

    /// Collects probe durations, benchmark speeds, the first media connection, the widget's
    /// placement on a challenge page, the network information, and probe times relative to the
    /// POSTs.
    fn read_records(
        &mut self,
        recording: &Recording,
        session: &CapturedSession,
        source: &Source,
        on_challenge_page: bool,
        problems: &mut Vec<anyhow::Error>,
    ) -> Result<()> {
        let program = session.program()?;
        let payload = session.probe_payload()?;
        let analysis = analysis::analyze(source, &program)?;
        let plan = analysis.plan();
        let envelope = &plan.record_fields;
        let completion = &envelope.completion;
        // The one published field only a browser computes.
        let shadow_root = plan
            .payload
            .published
            .iter()
            .find(|(_, value)| value.is_none());
        match shadow_root.and_then(|(field, _)| payload.get(field)?.as_str()) {
            Some(report) => self.shadow_roots.push(report.to_owned()),
            None => problems.push(anyhow::anyhow!(
                "the second payload publishes no shadow-root report"
            )),
        }
        let (mut first_started, mut last_finished) = (i64::MAX, i64::MIN);
        for probe in plan.probes() {
            let record = payload
                .get(&probe.index.to_string())
                .and_then(JsValue::as_object)
                .with_context(|| format!("the payload has no record for probe {}", probe.index))?;
            let mark = |name: &str| record.get(name).and_then(JsValue::as_i64);
            let (Some(started), Some(finished)) =
                (mark(&completion.started), mark(&completion.finished))
            else {
                bail!("probe {}'s record has no clock marks", probe.index);
            };
            first_started = first_started.min(started);
            last_finished = last_finished.max(finished);
            let Some(operation) = &probe.operation else {
                continue;
            };
            match operation {
                Operation::Benchmark { fields } => match fields.costs(record) {
                    Ok(costs) => self.benchmark.push(costs),
                    Err(error) => problems.push(error.context("reading the benchmark")),
                },
                Operation::Media { fields } if self.media.is_none() => {
                    let names = envelope.names();
                    let mut observed = record.clone();
                    observed.retain(|name, _| !names.contains(&name.as_str()));
                    plan.vocabulary()
                        .rewrite_to_reference(probe.position(), &mut observed);
                    match fields.observed(&observed, started) {
                        Ok(media) => self.media = Some(host_candidates_only(media)),
                        Err(error) => problems.push(error.context("reading the media probe")),
                    }
                }
                // A site's widget is placed by the site's own page, which the profile does not
                // describe.
                Operation::ParentInfo {} if on_challenge_page => {
                    let mut observed = record.clone();
                    plan.vocabulary()
                        .rewrite_to_reference(probe.position(), &mut observed);
                    match placement(&observed) {
                        Ok(placement) => self.placements.push(placement),
                        Err(error) => problems.push(error.context("reading the widget placement")),
                    }
                }
                Operation::NetworkInformation(fields) => {
                    let mut observed = record.clone();
                    plan.vocabulary()
                        .rewrite_to_reference(probe.position(), &mut observed);
                    let connection = fields.properties.iter().filter_map(|(field, property)| {
                        Some((property.clone(), observed.get(field)?.clone()))
                    });
                    self.connections.push(connection.collect());
                }
                _ => {}
            }
            // The solver measures its own benchmark's duration.
            let family = operation.family();
            if family != Kind::Benchmark
                && let Some(duration) = mark(&completion.duration)
            {
                self.durations
                    .entry(family.as_str())
                    .or_default()
                    .push(duration);
            }
        }
        let posts = recording.post_times(session)?;
        self.startup_ms
            .push(first_started - posts.first_answered_ms);
        // The schedule reserves a millisecond after each probe.
        self.pending_ms
            .push(posts.second_sent_ms - last_finished - 1);
        Ok(())
    }

    fn fill(mut self, profile: &mut Value, notes: &mut Vec<String>) -> Result<()> {
        self.fill_placement(profile, notes)?;
        self.fill_connection(profile, notes)?;
        self.fill_shadow_root(profile, notes)?;
        let mut filled = |pointer: &str, value: Option<Value>, source: &str| -> Result<()> {
            let name = pointer.trim_start_matches('/').replace('/', ".");
            match value {
                Some(value) => {
                    *section(profile, pointer)? = value;
                    notes.push(format!("{name}: {source}"));
                }
                None => notes.push(format!(
                    "{name}: kept the profile's; no session reported it"
                )),
            }
            Ok(())
        };
        let sessions = |count: usize| format!("medians of {count} sessions");

        let durations: BTreeMap<&str, u32> = self
            .durations
            .into_iter()
            .filter_map(|(family, durations)| Some((family, unsigned(median(durations)?))))
            .collect();
        let count = self.startup_ms.len();
        let durations = (!durations.is_empty()).then_some(durations);
        filled("/second/durations", json(durations)?, &sessions(count))?;
        for (pointer, values) in [
            ("/second/startup_ms", self.startup_ms),
            ("/second/pending_ms", self.pending_ms),
        ] {
            filled(
                pointer,
                json(median(values).map(unsigned))?,
                &sessions(count),
            )?;
        }

        let benchmarks = self.benchmark.len();
        let benchmark = self.benchmark.into_iter().reduce(|mut all, costs| {
            all.compile_ms.extend(costs.compile_ms);
            for (speeds, more) in all
                .kernel_ms_per_million
                .iter_mut()
                .zip(costs.kernel_ms_per_million)
            {
                speeds.extend(more);
            }
            all
        });
        let source = format!("every round of {benchmarks} sessions");
        filled("/second/facts/benchmark_worker", json(benchmark)?, &source)?;
        let source = "the first session's, its addresses replaced";
        filled("/second/facts/media", json(self.media)?, source)?;

        let intervals = median_intervals(&self.intervals);
        filled(
            "/intervals",
            json(intervals)?,
            &sessions(self.intervals.len()),
        )?;

        // Use one session to keep timestamps consistent. Choose the session with the median loader
        // send time.
        let count = self.timelines.len();
        self.timelines.sort_by_key(|timeline| timeline.sent);
        let source = format!(
            "the median of {count} site widget sessions by send time; script_fetch kept, as no \
             payload reports it"
        );
        filled("/timeline", json(self.timelines.get(count / 2))?, &source)
    }
}

impl Reported {
    /// Places the widget on challenge pages at the median edges the sessions report. Cloudflare's
    /// page centres its content in the viewport, so the left edge mirrors the right one in the
    /// profile's `browser.inner_width`.
    fn fill_placement(&self, profile: &mut Value, notes: &mut Vec<String>) -> Result<()> {
        if self.placements.is_empty() {
            notes.push(
                "browser.challenge_page: kept the profile's; no challenge page session placed it"
                    .into(),
            );
            return Ok(());
        }
        let inner_width = section(profile, "/browser/inner_width")?
            .as_f64()
            .context("the profile's browser.inner_width, which places the widget's left edge, is not a number")?;
        let top = median_f64(self.placements.iter().map(|(top, _)| *top).collect());
        let right = median_f64(self.placements.iter().map(|(_, right)| *right).collect());
        let (Some(top), Some(right)) = (top, right) else {
            unreachable!("placements is not empty");
        };
        let placement =
            serde_json::json!({"top": top, "left": inner_width - right, "right": right});
        *section(profile, "/browser")?
            .as_object_mut()
            .context("the profile's browser section is not an object")?
            .entry("challenge_page")
            .or_insert(Value::Null) = placement;
        notes.push(format!(
            "browser.challenge_page: medians of {} challenge page sessions; left mirrors right in \
             browser.inner_width",
            self.placements.len()
        ));
        Ok(())
    }

    /// Sets the shadow-root report the second payload publishes to the one seen most often.
    fn fill_shadow_root(&self, profile: &mut Value, notes: &mut Vec<String>) -> Result<()> {
        if self.shadow_roots.is_empty() {
            notes.push(
                "second.document.shadow_root: kept the profile's; no session published one".into(),
            );
            return Ok(());
        }
        let report = most_common(self.shadow_roots.iter().collect());
        *section(profile, "/second/document/shadow_root")? = Value::String(report.clone());
        notes.push(format!(
            "second.document.shadow_root: the most common of {} sessions",
            self.shadow_roots.len()
        ));
        Ok(())
    }

    /// Sets `navigator.connection` to each property's median (numbers) or most common value, and
    /// the image probe's effective type to match it.
    fn fill_connection(&self, profile: &mut Value, notes: &mut Vec<String>) -> Result<()> {
        let mut values: BTreeMap<&str, Vec<&JsValue>> = BTreeMap::new();
        for connection in &self.connections {
            // A property the browser lacks reads `null`, whether or not the profile names it.
            let present = connection.iter().filter(|(_, value)| !value.is_null());
            for (property, value) in present {
                values.entry(property).or_default().push(value);
            }
        }
        if values.is_empty() {
            notes.push(
                "second.facts.connection: kept the profile's; no session reported one".into(),
            );
            return Ok(());
        }
        let mut connection = serde_json::Map::new();
        for (property, observed) in values {
            let numbers: Option<Vec<f64>> = observed.iter().map(|value| value.as_f64()).collect();
            let value = match numbers {
                Some(numbers) => serde_json::json!(median_f64(numbers)),
                None => serde_json::to_value(most_common(observed))?,
            };
            connection.insert(property.to_owned(), value);
        }
        let effective_type = connection.get("effectiveType").cloned();
        section(profile, "/second/facts")?
            .as_object_mut()
            .context("the profile's second.facts is not an object")?
            .insert("connection".into(), Value::Object(connection));
        notes.push(format!(
            "second.facts.connection: medians or most common values of {} sessions",
            self.connections.len()
        ));
        if let Some(effective_type) = effective_type {
            *section(profile, "/second/image/effective_type")? = effective_type;
            notes.push("second.image.effective_type: the connection's".into());
        }
        Ok(())
    }
}

/// Reads the widget wrapper's `top|right` from a parent-info record in reference names.
fn placement(record: &JsObject) -> Result<(f64, f64)> {
    let position = record
        .get(PARENT_INFO_WIDGET_POSITION)
        .and_then(JsValue::as_str)
        .context("the record has no widget position")?;
    let (top, right) = position
        .split_once('|')
        .with_context(|| format!("the widget position {position:?} is not top|right"))?;
    let edge = |text: &str| {
        text.parse::<f64>()
            .with_context(|| format!("the widget position {position:?} has a non-numeric edge"))
    };
    Ok((edge(top)?, edge(right)?))
}

/// Returns the median, choosing the upper middle value for an even count.
fn median_f64(mut values: Vec<f64>) -> Option<f64> {
    values.sort_unstable_by(f64::total_cmp);
    values.get(values.len() / 2).copied()
}

/// Returns the value seen most often, the first seen among equals.
fn most_common<T: PartialEq>(values: Vec<&T>) -> &T {
    let mut counts: Vec<(&T, usize)> = Vec::new();
    for value in values {
        match counts.iter_mut().find(|(seen, _)| *seen == value) {
            Some((_, count)) => *count += 1,
            None => counts.push((value, 1)),
        }
    }
    let best = counts
        .iter()
        .map(|(_, count)| *count)
        .max()
        .expect("a property has values");
    counts
        .into_iter()
        .find(|(_, count)| *count == best)
        .expect("the best count is seen")
        .0
}

/// Returns the median of each interval across sessions.
fn median_intervals(sessions: &[Intervals]) -> Option<Intervals> {
    let column = |interval: fn(&Intervals) -> i64| median(sessions.iter().map(interval).collect());
    Some(Intervals {
        initialise: column(|intervals| intervals.initialise)?,
        handoff: column(|intervals| intervals.handoff)?,
        collect: column(|intervals| intervals.collect)?,
        send: column(|intervals| intervals.send)?,
    })
}

/// Reads the value reported for `option`, either from its template field or directly from a
/// forwarded option.
fn reported<'payload>(
    payload: &'payload Payload,
    fields: &[Field],
    state: &ScriptState,
    option: &str,
) -> Option<&'payload JsValue> {
    match fields
        .iter()
        .find(|field| field.option(state) == Some(option))
    {
        Some(field) => payload.get(&field.name),
        None if state.forwarded.iter().any(|key| key == option) => payload.get(option),
        None => None,
    }
}

/// Keeps only host candidates, which name the capture machine by mDNS name, so shared profiles do
/// not reveal its public address. [`crate::stage2::probes::ice::refresh`] reports only these.
fn host_candidates_only(mut media: Measurement) -> Measurement {
    if let Measurement::Observed { snapshot, .. } = &mut media {
        let candidates = &mut snapshot.connection.published_candidates;
        candidates.retain(|candidate| candidate.candidate.as_str().is_some_and(ice::is_host));
    }
    media
}

/// Returns the profile value at the JSON `pointer`. Panics if the path does not exist.
fn section<'profile>(profile: &'profile mut Value, pointer: &str) -> Result<&'profile mut Value> {
    profile
        .pointer_mut(pointer)
        .with_context(|| format!("the profile has no {pointer}"))
}

fn json(value: Option<impl Serialize>) -> Result<Option<Value>> {
    Ok(value.map(serde_json::to_value).transpose()?)
}

/// Returns the median, choosing the upper middle value for an even count.
fn median(mut values: Vec<i64>) -> Option<i64> {
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}

/// Converts a duration to the profile format. Negative durations caused by clock differences become
/// zero.
fn unsigned(duration: i64) -> u32 {
    u32::try_from(duration.max(0)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::json;

    fn base() -> Value {
        serde_json::json!({
            "browser": {"inner_width": 1919, "inner_height": 992},
            "second": {"facts": {}, "image": {"effective_type": "", "online": true},
                "document": {"shadow_root": "{}"}},
        })
    }

    #[test]
    fn places_the_widget_at_the_median_edges_centred_in_the_viewport() {
        let reported = Reported {
            placements: vec![(304.0, 1407.5), (300.0, 1407.5), (310.0, 1400.0)],
            ..Reported::default()
        };
        let (mut profile, mut notes) = (base(), Vec::new());
        reported.fill_placement(&mut profile, &mut notes).unwrap();
        assert_eq!(
            profile["browser"]["challenge_page"],
            serde_json::json!({"top": 304.0, "left": 511.5, "right": 1407.5})
        );
        assert_eq!(
            placement(&JsObject::from_iter([(
                PARENT_INFO_WIDGET_POSITION.to_owned(),
                json!("378|359")
            )]))
            .unwrap(),
            (378.0, 359.0)
        );
        assert!(placement(&JsObject::new()).is_err());
    }

    #[test]
    fn learns_the_connection_and_matches_the_image_probe_to_it() {
        let session = |downlink: f64, rtt: f64| {
            js::from_value::<JsObject>(json!({"downlink": downlink, "downlinkMax": null,
                "effectiveType": "4g", "rtt": rtt, "saveData": false, "type": null}))
            .unwrap()
        };
        let reported = Reported {
            connections: vec![session(1.75, 100.0), session(1.45, 0.0), session(1.6, 0.0)],
            ..Reported::default()
        };
        let (mut profile, mut notes) = (base(), Vec::new());
        reported.fill_connection(&mut profile, &mut notes).unwrap();
        assert_eq!(
            profile["second"]["facts"]["connection"],
            serde_json::json!({"downlink": 1.6, "effectiveType": "4g", "rtt": 0.0, "saveData": false})
        );
        assert_eq!(profile["second"]["image"]["effective_type"], "4g");

        // Safari has no `navigator.connection`: its sessions leave the profile as it was.
        let safari = Reported {
            connections: vec![JsObject::new()],
            ..Reported::default()
        };
        let mut unchanged = base();
        safari.fill_connection(&mut unchanged, &mut notes).unwrap();
        assert_eq!(unchanged, base());
    }

    #[test]
    fn takes_the_shadow_root_report_seen_most_often() {
        let chrome = r#"[null,"closed","<body></body>","",4,4,37,"function attachShadow() { [native code] }"]"#;
        let reported = Reported {
            shadow_roots: vec![chrome.into(), "odd".into(), chrome.into()],
            ..Reported::default()
        };
        let (mut profile, mut notes) = (base(), Vec::new());
        reported.fill_shadow_root(&mut profile, &mut notes).unwrap();
        assert_eq!(profile["second"]["document"]["shadow_root"], chrome);
    }
}
