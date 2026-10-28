//! Fills device profiles from proxy recordings.
//!
//! `traffic.json` provides the user agent, client hints, and header order for each request type.
//! Session payloads provide probe durations, startup and pending times, benchmark speeds, media
//! observations, first-payload intervals, and loader timestamps. Most values use the median across
//! sessions. Loader timestamps come from a single session chosen by median send time, so they
//! remain consistent.
//!
//! Values that captures cannot provide stay unchanged: engine, TLS and HTTP/2 settings, request
//! priorities, page layout, interaction, resource timing phases, orchestrator pacing, and navigator
//! properties. `build_profile` writes the stored answers.

mod headers;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
use crate::stage2::probes::media::Measurement;
use crate::stage2::registry::{Kind, Operation};

/// Updates measured profile values from `recordings`. Returns notes about the sources used and data
/// skipped. Other profile values stay unchanged.
pub fn fill(profile: &mut Value, recordings: &[Recording]) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    for recording in recordings {
        let dir = recording.dir.display();
        for skipped in &recording.skipped {
            notes.push(format!("{dir}: left out {skipped}"));
        }
    }
    let requests = recordings
        .iter()
        .flat_map(|recording| &recording.traffic.requests);
    fill_headers(profile, Headers::observe(requests), &mut notes)?;
    let script_fetch = section(profile, "/timeline/script_fetch")?
        .as_f64()
        .context("the profile's timeline has no script_fetch")?;
    let mut reported = Reported {
        script_fetch,
        ..Reported::default()
    };
    for recording in recordings {
        for (name, session) in &recording.sessions {
            let path = recording.dir.join(name);
            for problem in reported.read(recording, session) {
                notes.push(format!("{}: {problem:#}", path.display()));
            }
        }
    }
    reported.fill(profile, &mut notes)?;
    Ok(notes)
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
}

impl Reported {
    /// Collects measurements from `session` and returns notes about data it could not read.
    fn read(&mut self, recording: &Recording, session: &CapturedSession) -> Vec<anyhow::Error> {
        let source = match session.source() {
            Ok(source) => source,
            Err(error) => return vec![error.context("deobfuscating the iframe script")],
        };
        let mut problems = Vec::new();
        let first = session.first_payload();
        if let Err(error) = first.and_then(|first| self.read_first(&source, first, &mut problems)) {
            problems.push(error.context("reading the first payload"));
        }
        if let Err(error) = self.read_records(recording, session, &source, &mut problems) {
            problems.push(error.context("reading the probe records"));
        }
        problems
    }

    /// Collects first-payload intervals and the loader timestamps passed from the site to the
    /// iframe.
    fn read_first(
        &mut self,
        source: &Source,
        payload: &Payload,
        problems: &mut Vec<anyhow::Error>,
    ) -> Result<()> {
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
            return Ok(());
        }
        let times: ElapsedTimes = js::from_value(JsValue::Object(message))
            .context("the first payload lacks the loader's elapsed times")?;
        let implicit_render =
            implicit_render.context("the first payload lacks the loader's stack sample")?;
        let timeline = Timeline::from_times(&times, implicit_render, self.script_fetch);
        self.timelines.push(timeline);
        Ok(())
    }

    /// Collects probe durations, benchmark speeds, the first media connection, and probe times
    /// relative to the POSTs.
    fn read_records(
        &mut self,
        recording: &Recording,
        session: &CapturedSession,
        source: &Source,
        problems: &mut Vec<anyhow::Error>,
    ) -> Result<()> {
        let program = session.program()?;
        let payload = session.probe_payload()?;
        let analysis = analysis::analyze(source, &program)?;
        let plan = analysis.plan();
        let envelope = &plan.record_fields;
        let completion = &envelope.completion;
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
                        Ok(media) => self.media = Some(without_addresses(media)),
                        Err(error) => problems.push(error.context("reading the media probe")),
                    }
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

/// Replaces recorded IP addresses with documentation addresses so shared profiles do not reveal the
/// capture network. These addresses are never sent: [`crate::stage2::probes::ice::refresh`]
/// generates new names for host candidates.
fn without_addresses(mut media: Measurement) -> Measurement {
    if let Measurement::Observed { snapshot, .. } = &mut media {
        for candidate in &mut snapshot.connection.published_candidates {
            let Some(line) = candidate.candidate.as_str() else {
                continue;
            };
            let tokens = line.split(' ').map(|token| match token.parse::<IpAddr>() {
                Ok(address) if address.is_unspecified() => token.to_owned(),
                Ok(IpAddr::V4(_)) => Ipv4Addr::new(192, 0, 2, 1).to_string(),
                Ok(IpAddr::V6(_)) => Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).to_string(),
                Err(_) => token.to_owned(),
            });
            candidate.candidate = JsValue::String(tokens.collect::<Vec<String>>().join(" "));
        }
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
