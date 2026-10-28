//! Processes checkbox interaction using the profile's checkbox bounds, the iframe's recovered
//! queries, and input measurements, then builds its payload.

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::{task, time};

use super::channel::Submission;
use super::initial::Merged;
use super::probes::ProbeSubmission;
use super::timing;
use super::widget::WidgetSession;
use crate::browser::Solve;
use crate::challenge::payload as challenge_payload;
use crate::js::{JsObject, JsValue};
use crate::performance_clock::{self, PerformanceClock};
use crate::resource_timing::LoadTiming;
use crate::stage2::call_stack;
use crate::stage2::interaction::native::{self, Viewport};
use crate::stage2::interaction::{Plan, checkbox};
use crate::stage2::payload::{Document, Expression, Scope};

/// An observed input event used by the interaction tally and diagnostics.
#[derive(Serialize)]
pub(crate) struct InputEvent {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub time_stamp: f64,
    pub client_x: f64,
    pub client_y: f64,
}

/// Interaction record fields, timestamps, and the input events that produced them.
pub(crate) struct InteractionResult {
    pub fields: JsObject,
    /// Timestamp recorded before UI initialization and copied to the final record envelope.
    pub started_ms: i64,
    pub finished_ms: i64,
    pub input_events: Vec<InputEvent>,
    /// The selectors the checkbox UI queried, which the iframe's query log records.
    pub queried: Vec<String>,
}

/// Contents of `interaction-measurement.json`.
#[derive(Serialize)]
struct Diagnostic<'click> {
    #[serde(flatten)]
    native: &'click native::Measurement,
    input_events: &'click [InputEvent],
    setup_ms: i64,
    ready_ms: i64,
    epoch_ms: i64,
    performance_ms: f64,
    hardware_concurrency: f64,
}

/// Clicks the checkbox and runs the proof.
pub(crate) async fn collect(
    session: &WidgetSession<'_>,
    plan: &Plan,
    submission: &ProbeSubmission,
    solve: &Solve,
    viewport: &Viewport,
) -> Result<InteractionResult> {
    let (fetched, sink) = (&session.fetched, session.sink);
    let options = &submission.options;
    let hardware_concurrency = solve.hardware_concurrency;
    // Recover queries and callback frames before interaction starts. Parsing after the click
    // would delay the proof timer.
    let queried = checkbox::queries(&fetched.source, options)?;
    let script_position = fetched.script_position()?;
    let geometry = call_stack::recover(
        &fetched.javascript,
        &fetched.cases,
        plan.diagnostics.construct,
        plan.diagnostics.callback_arity,
    )?;
    let engine = session.client.engine();
    let stack = geometry.format(&script_position, engine);
    let clock = PerformanceClock::from_epoch_origin(
        fetched.navigation.started_ms,
        session.clock_resolution(),
    );

    let setup_ms = performance_clock::epoch_ms();
    let mut observed = native::measure(viewport, &fetched.iframe.html, clock.now(), engine);
    let ready_ms = performance_clock::epoch_ms();
    let (client_x, client_y) = observed.click_point()?;
    let delay = Duration::from_millis(viewport.ready_delay_ms);
    let mut input_events = if viewport.touch {
        tap(&clock, delay, (client_x, client_y)).await
    } else {
        move_pointer(&clock, delay, (client_x, client_y)).await
    };
    let click_ms = performance_clock::epoch_ms();
    let clicked_performance_ms = clock.now();
    input_events.push(InputEvent {
        kind: "click",
        time_stamp: clicked_performance_ms,
        client_x,
        client_y,
    });
    observed.stamp(clicked_performance_ms)?;
    sink.json(
        "interaction-measurement.json",
        &Diagnostic {
            native: &observed,
            input_events: &input_events,
            setup_ms,
            ready_ms,
            epoch_ms: click_ms,
            performance_ms: clicked_performance_ms,
            hardware_concurrency,
        },
    )?;

    // The record's fields in the order the UI writes them: its setup, then the click with its
    // diagnostics and the UI audit, then the proof's start.
    let mut fields = plan.initialization.collect(setup_ms, ready_ms);
    fields.insert(
        plan.click.output.clone(),
        plan.click.collect(&observed.sources)?,
    );
    // Initialization sets the console flag to false; the click overwrites it
    // with the marker returned by the getter observation.
    fields.extend(plan.diagnostics.collect(stack));
    fields.insert(plan.ui.output.clone(), plan.ui.collect(&observed.ui));
    let launch_ms = click_ms + plan.click_delay_ms as i64;
    // Proof hashing consumes its full time budget. Run it on a blocking thread with copies
    // prepared before the timer fires.
    let (proof, proof_options, costs) = (
        plan.proof.clone(),
        options.clone(),
        solve.profile.facts.proof_worker.clone(),
    );
    timing::sleep_until(launch_ms).await;
    let launch_ms = performance_clock::epoch_ms();
    fields.insert(
        plan.initialization.proof_started.clone(),
        JsValue::from(launch_ms),
    );
    let began = clock.now();
    let search = task::spawn_blocking(move || {
        proof.search(&proof_options, launch_ms, hardware_concurrency, &costs)
    })
    .await
    .context("the proof thread failed")??;
    let elapsed = clock.now() - began;
    let finished_ms = performance_clock::epoch_ms();
    fields.extend(
        plan.proof_fields
            .finish(&search.answer, search.workers, elapsed, finished_ms),
    );
    Ok(InteractionResult {
        fields,
        started_ms: setup_ms,
        finished_ms,
        input_events,
        queried,
    })
}

/// How long a tapping finger rests on the screen.
const TAP_REST: Duration = Duration::from_millis(100);

/// Moves a mouse pointer from the iframe corner to `target` over `delay`, as the pointer and
/// mouse movement events report it.
async fn move_pointer(
    clock: &PerformanceClock,
    delay: Duration,
    (target_x, target_y): (f64, f64),
) -> Vec<InputEvent> {
    let mut input_events = vec![InputEvent {
        kind: "pointerover",
        time_stamp: clock.now(),
        client_x: 0.0,
        client_y: 0.0,
    }];
    let move_started = Instant::now();
    let mut previous = (0.0, 0.0);
    loop {
        let elapsed = move_started.elapsed();
        let progress = if delay.is_zero() {
            1.0
        } else {
            (elapsed.as_secs_f64() / delay.as_secs_f64()).min(1.0)
        };
        let client_x = (target_x * progress).trunc();
        let client_y = (target_y * progress).trunc();
        if (client_x, client_y) != previous {
            let time_stamp = clock.now();
            for kind in ["pointermove", "mousemove"] {
                input_events.push(InputEvent {
                    kind,
                    time_stamp,
                    client_x,
                    client_y,
                });
            }
            previous = (client_x, client_y);
        }
        if progress >= 1.0 {
            break;
        }
        time::sleep((delay - elapsed).min(Duration::from_millis(16))).await;
    }
    input_events
}

/// Taps `target` after `delay`. The finger triggers pointer-over and touch-start events. On
/// release, the browser emulates a mouse moving to the target before clicking, as observed in
/// iOS Safari input tallies.
async fn tap(
    clock: &PerformanceClock,
    delay: Duration,
    (client_x, client_y): (f64, f64),
) -> Vec<InputEvent> {
    let event = |kind, time_stamp| InputEvent {
        kind,
        time_stamp,
        client_x,
        client_y,
    };
    let rest = TAP_REST.min(delay);
    time::sleep(delay - rest).await;
    let landed = clock.now();
    time::sleep(rest).await;
    vec![
        event("pointerover", landed),
        event("touchstart", landed),
        event("mousemove", clock.now()),
    ]
}

/// Builds the interaction payload: the probe payload with the interaction record, updated input
/// counters, and refreshed fields the checkbox program publishes.
pub(crate) fn payload(
    plan: &Plan,
    merged: &Merged,
    submission: ProbeSubmission,
    result: InteractionResult,
    probe_post: &LoadTiming,
    document: &Document,
) -> Result<Submission> {
    let input = submission.payload.plaintext;
    let (mut options, mut window) = (submission.options, submission.window);
    // The probe POST is the iframe's latest load.
    if let Some(timing) = &merged.state.timing {
        options
            .get_mut(&timing.option)
            .and_then(JsValue::as_array_mut)
            .context("interaction has no resource timing list")?
            .push(timing.entry(probe_post, merged.time_origin_ms));
    }
    if let Some(log) = &merged.state.post_log {
        log.record(&mut options, probe_post, merged.time_origin_ms)?;
    }
    let mut payload =
        plan.append_record(&input, result.fields, result.started_ms, result.finished_ms)?;
    let counters = merged.state.counter_events()?;
    let kinds: Vec<&str> = result.input_events.iter().map(|event| event.kind).collect();
    counters.record(&mut window, &kinds)?;
    if let Some(log) = &merged.selector_log
        && let Some(selectors) = window.get_mut(log).and_then(JsValue::as_array_mut)
    {
        selectors.extend(result.queried.into_iter().map(JsValue::String));
    }
    // JavaScript payloads reference the window tally. Rust maps own their values, so copy tally
    // changes into the payload.
    for (field, expression) in &plan.payload.template.fields {
        if let Expression::Read { scope, path } = expression
            && *scope == Scope::Window
            && path.as_slice() == [counters.global.as_str()]
        {
            payload.insert(field.clone(), window[&counters.global].clone());
        }
    }
    let environment = merged.environment(&options, &window);
    let mut plaintext = plan.finish_payload(payload, environment, document)?;
    let send_at = performance_clock::epoch_ms();
    challenge_payload::append_send_time_at(&mut plaintext, &merged.state, &options, send_at);
    Ok(Submission { plaintext, send_at })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::performance_clock::Resolution;

    /// Checks that an iPhone tap counts each of these events once and records no pointer
    /// movement.
    #[tokio::test]
    async fn a_tap_lands_and_lifts_where_it_clicks() {
        let clock = PerformanceClock::started_now(Resolution::WebKitMillisecond);
        let events = tap(&clock, Duration::ZERO, (107.0, 32.0)).await;
        let kinds: Vec<&str> = events.iter().map(|event| event.kind).collect();
        assert_eq!(kinds, ["pointerover", "touchstart", "mousemove"]);
        assert!(
            events
                .iter()
                .all(|event| (event.client_x, event.client_y) == (107.0, 32.0))
        );
    }
}
