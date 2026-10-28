//! Answers the probes from stored device facts or current observations, and builds the probe
//! payload with record timestamps scheduled to finish just before it is sent.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use chrono::Local;
use tokio::{task, time};
use url::Url;
use wreq::ws::message::Message;

use super::channel::Submission;
use super::timing::{self, Schedule, Timer};
use super::widget::{Embedding, WidgetSession};
use crate::browser::{Profile, Solve};
use crate::challenge::payload;
use crate::engine::Engine;
use crate::http::{self, FetchOptions};
use crate::js::{self, JsObject, JsValue, Options, Payload, Window, json};
use crate::performance_clock::{self, PerformanceClock};
use crate::resource_timing::LoadTiming;
use crate::stage2::call_stack;
use crate::stage2::payload::State;
use crate::stage2::probes::{
    clock, host_reachability, ice, image, performance, private_token, websocket_echo, worker_fetch,
};
use crate::stage2::records::{Probe, ProbePlan};
use crate::stage2::registry::{Facts, Kind, Observed, Operation, Treatment};
use crate::stage2::replay::{self, Replay};
use crate::stage2::trace::Trace;

/// Timeout for host reachability fetches. Browsers report these hosts as unreachable within
/// milliseconds.
const REACHABILITY_TIMEOUT: Duration = Duration::from_secs(5);

/// A probe kind's duration when nothing else gives one.
const DEFAULT_DURATION_MS: i64 = 2;

/// The probe payload and session state needed by the later interaction stage.
pub(crate) struct ProbeSubmission {
    pub payload: Submission,
    pub options: Options,
    pub window: Window,
    /// The window position and decorations the environment audit reported.
    pub geometry: BTreeMap<String, f64>,
}

/// Answers the first response's probe plan using `solve` facts. Schedules sending no earlier
/// than a browser could finish all probes.
pub(crate) async fn prepare(session: &WidgetSession<'_>, solve: &Solve) -> Result<ProbeSubmission> {
    let (merged, profile) = (&session.merged, &solve.profile);
    let answers = solve.answers.as_ref();
    // Reuse widget answers on challenge pages when no separate answers are configured.
    let answers = match session.embedding {
        Embedding::Site => answers,
        Embedding::ChallengePage => solve.challenge_page_answers.as_ref().or(answers),
    };
    let engine = session.client.engine();
    let plan = session.analysis.plan();
    let mut options = session.request.options.clone();
    let (mut observed, fetches) = observe(session, plan, &options, profile).await?;
    observed.page_signals = Some(merged.page_signals.clone());
    // Resource timings now include the first POST and probe requests.
    if let Some(timing) = &merged.state.timing {
        let mut resources = merged.resources.clone();
        let origin = merged.time_origin_ms;
        resources.push(timing.entry(&session.first_post, origin));
        resources.extend(fetches.iter().map(|fetch| timing.entry(fetch, origin)));
        options.insert(timing.option.clone(), JsValue::Array(resources));
    }
    // The sender logged the first POST after sending it.
    if let Some(log) = &merged.state.post_log {
        log.record(&mut options, &session.first_post, merged.time_origin_ms)?;
    }
    // Build window values from installed globals, values read by the first payload, then
    // profile overrides.
    let mut window = merged.window.clone();
    window.extend(merged.globals.clone());
    if let Some(log) = &merged.selector_log {
        window.insert(log.clone(), json!(plan.selector_log(&options)));
    }
    window.extend(profile.window.clone());

    let replay = answers.map(|answers| Replay::new(answers, plan));
    let pending_ms = i64::from(profile.pending_ms);
    let schedule = timing::schedule(
        &durations(plan, &profile.durations, &observed, replay.as_ref()),
        profile.startup_ms.into(),
        pending_ms,
        session.arrived_ms,
        performance_clock::epoch_ms(),
    );
    if let Some((probe, Operation::PerformanceEntries { fields })) =
        plan.operation(Kind::PerformanceEntries)
    {
        observed.performance = Some(performance::Measurement::observed(
            plan,
            probe.index,
            &session.fetched.navigation,
            &session.first_post,
            &fetches,
            &fields.mark_name(session.request.ray()?),
            schedule.marks[probe.position()].start,
            engine,
        ));
    }
    let stored = replay::Session {
        iframe_url: session.fetched.iframe.url.as_str(),
        modified: Local::now().format("%m/%d/%Y %H:%M:%S").to_string(),
        referrer: session.fetched.referrer.as_deref().unwrap_or_default(),
        navigation: &session.fetched.iframe.navigation,
        options: &options,
        trace: Trace::recover(&session.fetched.source),
        controller: plan.controller_trace.as_deref(),
    };
    let records = records(
        plan,
        &profile.facts,
        &observed,
        replay.as_ref(),
        &stored,
        &schedule,
        engine,
    )?;
    let mut plaintext = plan.assemble(
        &State {
            environment: merged.environment(&options, &window),
            input: &merged.first,
        },
        records,
        &profile.document,
        pending_ms,
    )?;
    ensure!(
        plaintext.len() > plan.probes().len(),
        "the assembled payload holds nothing besides records"
    );
    payload::append_send_time_at(&mut plaintext, &merged.state, &options, schedule.send_at);
    let geometry = window_geometry(plan, replay.as_ref(), &plaintext);
    Ok(ProbeSubmission {
        payload: Submission {
            plaintext,
            send_at: schedule.send_at,
        },
        options,
        window,
        geometry,
    })
}

/// Collects native measurements, and the requests the iframe's resource timing lists. Runs
/// requests and stack recovery concurrently.
async fn observe(
    session: &WidgetSession<'_>,
    plan: &ProbePlan,
    options: &Options,
    profile: &Profile,
) -> Result<(Observed, Vec<LoadTiming>)> {
    let mut observed = Observed::default();
    let requests = requests(session, plan, options, profile, &mut observed);
    let stack = probe_stack(session, plan);
    let (fetches, stack) = tokio::try_join!(requests, stack)?;
    observed.stack = stack;
    let facts = &profile.facts;
    let resolution = session.clock_resolution();
    if let Some((probe, Operation::Benchmark { fields })) = plan.operation(Kind::Benchmark) {
        let measured = fields
            .measure(&facts.benchmark_worker, resolution)
            .with_context(|| format!("running probe {}'s benchmark", probe.index))?;
        observed.benchmark = Some(measured);
    }
    if let (Some((probe, _)), Some(previous)) = (plan.operation(Kind::Media), &facts.media) {
        let media = ice::refresh(previous.clone())
            .with_context(|| format!("refreshing probe {}'s media", probe.index))?;
        session.sink.json("media-measurement.json", &media)?;
        observed.media = Some(media);
    }
    // The worker compares 5000 consecutive clock-reading pairs. Chrome's call overhead usually
    // crosses a 100 µs boundary; faster native reads may miss all boundaries. Retry until a
    // pair crosses one.
    if plan.operation(Kind::ClockResolution).is_some() {
        let worker = PerformanceClock::started_now(resolution);
        let readings = (0..20)
            .map(|_| worker.back_to_back(clock::PAIRS))
            .find(|pairs| pairs.iter().any(|[before, after]| before < after))
            .unwrap_or_else(|| worker.back_to_back(clock::PAIRS));
        observed.clock = Some(readings);
    }
    Ok((observed, fetches))
}

/// Runs the WebSocket echo exchange. After opening, sends `String(performance.now())` and sends a
/// new reading after each echo. Closes the socket when enough echoes return or the timeout expires.
async fn echo_websocket(
    session: &WidgetSession<'_>,
    fields: &websocket_echo::Fields,
    options: &Options,
) -> Result<websocket_echo::Measurement> {
    use websocket_echo::{ECHOES, End, Measurement};

    let (client, iframe) = (session.client, &session.fetched.iframe);
    let url = fields.url(options, &iframe.url)?;
    let clock = PerformanceClock::from_epoch_origin(
        session.merged.time_origin_ms,
        session.clock_resolution(),
    );
    let started_ms = performance_clock::epoch_ms();
    let deadline = time::Instant::now() + Duration::from_millis(websocket_echo::TIMEOUT_MS);
    let constructed = clock.now();
    let mut measured = Measurement {
        end: End::TimedOut,
        sent: 0,
        received: 0,
        opened_ms: None,
        round_trips: Vec::new(),
        elapsed_ms: 0,
    };
    let mut socket = None;
    let exchange = async {
        let Ok(opened) = http::open_websocket(client, iframe, &url).await else {
            return End::Failed;
        };
        measured.opened_ms = Some(clock.now() - constructed);
        let socket = socket.insert(opened);
        while measured.sent < ECHOES {
            measured.sent += 1;
            let reading = js::string(Some(&json!(clock.now())));
            if socket.send(Message::text(reading)).await.is_err() {
                return End::Failed;
            }
            // Ping and pong frames do not trigger `message` events. Binary data converts to `NaN`.
            let echoed = loop {
                match socket.recv().await {
                    Some(Ok(Message::Text(text))) => break js::string_number(text.as_str()),
                    Some(Ok(Message::Binary(_))) => break f64::NAN,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => return End::Closed,
                    Some(Err(_)) => return End::Failed,
                }
            };
            measured.received += 1;
            if echoed.is_finite() {
                measured.round_trips.push(clock.now() - echoed);
            }
        }
        End::Echoed
    };
    measured.end = time::timeout_at(deadline, exchange)
        .await
        .unwrap_or(End::TimedOut);
    measured.elapsed_ms = performance_clock::epoch_ms() - started_ms;
    if let Some(mut socket) = socket {
        // Ignore close errors because the result has already been recorded.
        let _ = socket.send(Message::Close(None)).await;
    }
    Ok(measured)
}

/// Rebuilds the stack probe result using the session script and engine's stack format. The VM
/// executes closures within its dispatch loop, so neither engine shows additional VM call levels.
async fn probe_stack(session: &WidgetSession<'_>, plan: &ProbePlan) -> Result<Option<String>> {
    let Some((probe, Operation::Stack { fields })) = plan.operation(Kind::Stack) else {
        return Ok(None);
    };
    let calls = fields.calls.with_context(|| {
        format!(
            "probe {}'s calls leading to `new Error()` have an unrecognized shape",
            probe.index
        )
    })?;
    let fetched = &session.fetched;
    let javascript = fetched.javascript.clone();
    let cases = fetched.cases.clone();
    let origin = fetched.script_position()?;
    let engine = session.client.engine();
    let stack = task::spawn_blocking(move || {
        let geometry = call_stack::recover_probe(&javascript, &cases, calls)?;
        anyhow::Ok(geometry.format(&origin, engine))
    })
    .await
    .context("the stack recovery thread failed")?
    .with_context(|| format!("rebuilding probe {}'s stack", probe.index))?;
    Ok(Some(stack))
}

/// Chooses probe durations from completed work, `configured` profile values, stored answers, or
/// defaults, in that order.
fn durations(
    plan: &ProbePlan,
    configured: &BTreeMap<String, u32>,
    observed: &Observed,
    replay: Option<&Replay<'_>>,
) -> Vec<i64> {
    let duration = |probe: &Probe| {
        if let Some(family) = probe.operation.as_ref().map(Operation::family) {
            if let Some(measured) = observed.duration_ms(family) {
                return measured;
            }
            if let Some(&recorded) = configured.get(family.as_str()) {
                return i64::from(recorded);
            }
        }
        let stored = replay.and_then(|replay| replay.duration(probe));
        stored.unwrap_or(DEFAULT_DURATION_MS)
    };
    plan.probes().iter().map(duration).collect()
}

/// Makes probe requests as the iframe would and returns the loads included in resource timing.
async fn requests(
    session: &WidgetSession<'_>,
    plan: &ProbePlan,
    options: &Options,
    profile: &Profile,
    observed: &mut Observed,
) -> Result<Vec<LoadTiming>> {
    let (client, iframe) = (session.client, &session.fetched.iframe);
    let mut fetches = Vec::new();
    for probe in plan.probes() {
        match &probe.operation {
            Some(Operation::PrivateToken { fields }) => {
                let url = fields.url(options, &probe.input, &iframe.url)?;
                let started_ms = performance_clock::epoch_ms();
                // The worker calls `r.text()` before posting results. Treat body-read failures
                // like fetch failures because both reject the promise chain.
                let fetched = http::fetch_from_worker(client, iframe, &url, FetchOptions::NoCache);
                let outcome = async {
                    let response = fetched.await?;
                    let status = response.status();
                    anyhow::Ok(private_token::WorkerOutcome::Response {
                        ok: status.is_success(),
                        status: status.as_u16(),
                        text: response.text().await?,
                    })
                }
                .await
                .unwrap_or_else(|error| private_token::WorkerOutcome::Rejected {
                    worker_error: error.to_string(),
                });
                observed.private_token = Some(private_token::Measurement {
                    outcome,
                    started_ms,
                    finished_ms: performance_clock::epoch_ms(),
                });
            }
            Some(Operation::WorkerFetch { .. }) if profile.facts.worker_fetch_rejected => {
                observed.worker_fetch = Some(worker_fetch::Measurement::Rejected);
            }
            Some(Operation::HostReachability { fields }) => {
                // CORS rejects a response that does not allow the iframe's origin.
                let origin = iframe.url.origin().ascii_serialization();
                let mut outcomes = Vec::new();
                for url in &fields.urls {
                    let url = Url::parse(url).context("parsing a host reachability URL")?;
                    let timer = Timer::start();
                    let options = FetchOptions::NoStoreWithoutCredentials;
                    let fetched = http::fetch_from_worker(client, iframe, &url, options);
                    outcomes.push(match time::timeout(REACHABILITY_TIMEOUT, fetched).await {
                        Ok(Ok(response))
                            if response
                                .headers()
                                .get("access-control-allow-origin")
                                .and_then(|allowed| allowed.to_str().ok())
                                .is_some_and(|allowed| allowed == "*" || allowed == origin) =>
                        {
                            host_reachability::Outcome::Answered {
                                elapsed_ms: timer.elapsed_ms() as i64,
                            }
                        }
                        _ => host_reachability::Outcome::Rejected,
                    });
                }
                observed.host_reachability = Some(outcomes);
            }
            Some(Operation::WebSocketEcho { fields }) => {
                observed.websocket_echo = Some(echo_websocket(session, fields, options).await?);
            }
            Some(Operation::WorkerFetch { fields }) => {
                let url = fields.url(options)?;
                let options = FetchOptions::NoStoreWithoutCredentials;
                let fetched = http::fetch_from_worker(client, iframe, &url, options).await;
                observed.worker_fetch = Some(match fetched {
                    Ok(response) => worker_fetch::Measurement::Response {
                        status: response.status().as_u16(),
                        headers: http::text_headers(response.headers())
                            .map(|(name, value)| (name.to_owned(), value))
                            .collect(),
                    },
                    Err(_) => worker_fetch::Measurement::Rejected,
                });
            }
            Some(Operation::Image { fields }) => {
                let url = fields.url(options, &probe.input, &iframe.url)?;
                let timer = Timer::start();
                let response = http::fetch_image(client, iframe, &url).await?;
                let waiting_ms = timer.elapsed_ms();
                let ok = response.status().is_success();
                let (body, network) = http::read_encoded(response)
                    .await
                    .context("reading a challenge image")?;
                fetches.push(timer.phased(url.as_str(), waiting_ms, network.encoded_bytes));
                observed.image = Some(image::Measurement::loaded(
                    ok.then_some(&body[..]),
                    &profile.image.effective_type,
                    profile.image.online,
                ));
            }
            _ => {}
        }
    }
    Ok(fetches)
}

/// Builds probe records with scheduled timestamps. Stored answers use `stored` and preserve the
/// browser's field order. Current measurements use the write order recovered from the program.
fn records(
    plan: &ProbePlan,
    facts: &Facts,
    observed: &Observed,
    replay: Option<&Replay<'_>>,
    stored: &replay::Session<'_>,
    schedule: &Schedule,
    engine: Engine,
) -> Result<JsObject> {
    let record = |probe: &Probe| {
        let operation = probe
            .operation
            .as_ref()
            .with_context(|| format!("probe {} matches no known collector", probe.index))?;
        match operation.kind().treatment() {
            Treatment::Replayed => replay
                .context("the fingerprint names no stored answers")?
                .answer(probe, stored),
            Treatment::Computed => {
                let mut fields = operation.collect(facts, observed, engine)?;
                plan.vocabulary()
                    .rewrite_to_session(probe.position(), &mut fields);
                Ok(probe.writes.arrange(fields))
            }
        }
    };
    let mut clock = schedule
        .marks
        .iter()
        .flat_map(|marks| [marks.start, marks.end]);
    plan.collect_records_with(
        |probe| {
            let family = probe
                .operation
                .as_ref()
                .map_or("unknown", |operation| operation.family().as_str());
            record(probe).with_context(|| format!("answering probe {} ({family})", probe.index))
        },
        || {
            clock
                .next()
                .expect("the schedule has one pair of marks per probe")
        },
    )
}

/// Window dimensions and position already reported by the environment audit.
fn window_geometry(
    plan: &ProbePlan,
    replay: Option<&Replay<'_>>,
    payload: &Payload,
) -> BTreeMap<String, f64> {
    let groups = replay
        .and_then(|replay| replay.audit_groups(plan, payload))
        .into_iter()
        .flatten();
    let mut geometry = BTreeMap::new();
    for (value, names) in groups {
        let (Ok(value), Some(names)) = (value.parse::<f64>(), names.as_array()) else {
            continue;
        };
        if !value.is_finite() {
            continue;
        }
        for name in ["outerWidth", "outerHeight", "screenX", "screenY"] {
            if names.iter().any(|item| item.as_str() == Some(name)) {
                geometry.insert(name.into(), value);
            }
        }
    }
    geometry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_duration_overrides_the_default_for_its_family() {
        let plan: ProbePlan = js::from_value(json!({
            "record_fields":{"counter":"counter", "token":"token", "input":"input",
                "status":"status", "message":"message", "started":"started",
                "finished":"finished", "duration":"duration"},
            "payload":{"template":{"fields":{}}, "published":[], "footer":{}, "pending":null},
            "probes": [
                {"index":1, "token":"t", "input":null, "operation":{"kind":"empty"}, "features":[]},
                {"index":2, "token":"t", "input":null, "operation":null, "features":[]},
            ],
        }))
        .unwrap();
        let observed = Observed::default();
        let mut configured = BTreeMap::new();
        assert_eq!(durations(&plan, &configured, &observed, None), [2, 2]);
        configured.insert("empty".into(), 7);
        assert_eq!(durations(&plan, &configured, &observed, None), [7, 2]);
    }
}
