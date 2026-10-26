//! Session load measurements and probe record scheduling.
//!
//! Keeps three time representations separate: epoch milliseconds for records and options,
//! [`Instant`] durations for resource timing, and the iframe's performance clock for input and
//! proof (see [`crate::performance_clock`]).

use std::time::{Duration, Instant};

use tokio::time;

use crate::performance_clock;
use crate::resource_timing::LoadTiming;

/// An active load, with an epoch start time and an [`Instant`] for its duration.
pub(crate) struct Timer {
    started: Instant,
    started_ms: i64,
}

impl Timer {
    #[must_use]
    pub(crate) fn start() -> Self {
        Self {
            started: Instant::now(),
            started_ms: performance_clock::epoch_ms(),
        }
    }

    #[must_use]
    pub(crate) fn elapsed_ms(&self) -> f64 {
        self.started.elapsed().as_secs_f64() * 1000.0
    }

    /// Timing for a request with `waiting_ms` before its response and `body_bytes` so far.
    #[must_use]
    pub(crate) fn phased(&self, url: &str, waiting_ms: f64, body_bytes: u64) -> LoadTiming {
        let duration_ms = self.elapsed_ms();
        LoadTiming {
            url: url.to_owned(),
            started_ms: self.started_ms,
            duration_ms,
            waiting_ms,
            receiving_ms: duration_ms - waiting_ms,
            body_bytes,
        }
    }

    /// Timing for a completed load measured only by its total duration.
    #[must_use]
    pub(crate) fn overall(&self, url: &str, body_bytes: u64) -> LoadTiming {
        LoadTiming {
            waiting_ms: 0.0,
            receiving_ms: 0.0,
            ..self.phased(url, 0.0, body_bytes)
        }
    }
}

/// Waits until `at_ms` in epoch milliseconds, returning immediately if that time has passed.
pub(crate) async fn sleep_until(at_ms: i64) {
    let wait = at_ms - performance_clock::epoch_ms();
    if wait > 0 {
        time::sleep(Duration::from_millis(wait as u64)).await;
    }
}

/// One probe's record marks, in epoch milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProbeMarks {
    pub start: i64,
    pub end: i64,
}

/// When the probes' payload is sent, and each probe's marks.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Schedule {
    /// One entry per probe, in order.
    pub marks: Vec<ProbeMarks>,
    pub send_at: i64,
}

/// Schedules probes at least `startup_ms` after `arrived_ms`. Reserves one millisecond after
/// each probe, then `pending_ms` before sending. The send time is no earlier than `now_ms`.
/// Programs without probes wait only for startup. Uses signed durations to match record
/// timestamp differences.
pub(crate) fn schedule(
    durations: &[i64],
    startup_ms: i64,
    pending_ms: i64,
    arrived_ms: i64,
    now_ms: i64,
) -> Schedule {
    let span: i64 = durations.iter().map(|duration| duration + 1).sum();
    let busy = if durations.is_empty() {
        startup_ms
    } else {
        startup_ms + span + pending_ms
    };
    let send_at = now_ms.max(arrived_ms + busy);
    let mut start = send_at - pending_ms - span;
    let mut marks = Vec::with_capacity(durations.len());
    for &duration in durations {
        let end = start + duration;
        marks.push(ProbeMarks { start, end });
        start = end + 1;
    }
    Schedule { marks, send_at }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_end_pending_ms_before_a_send_no_sooner_than_a_browser_could() {
        let schedule = schedule(&[3, 5], 400, 15, 1_000, 1_100);
        assert_eq!(
            schedule.send_at, 1_425,
            "400 ms startup, then 3 + 1 and 5 + 1 ms of probes, then 15 ms pending: a browser \
             could send 425 ms after the program arrived"
        );
        assert_eq!(
            schedule.marks,
            [
                ProbeMarks {
                    start: 1_400,
                    end: 1_403
                },
                ProbeMarks {
                    start: 1_404,
                    end: 1_409
                },
            ],
            "the last probe's next mark is exactly `pending_ms` before sending"
        );

        let late = super::schedule(&[3, 5], 400, 15, 1_000, 2_000);
        assert_eq!(late.send_at, 2_000);
        assert_eq!(
            late.marks[0].start, 1_975,
            "a late send moves every mark with it"
        );
    }

    #[test]
    fn a_program_without_probes_waits_for_its_startup_alone() {
        let schedule = schedule(&[], 400, 15, 1_000, 1_100);
        assert_eq!(
            schedule,
            Schedule {
                marks: Vec::new(),
                send_at: 1_400
            }
        );
    }

    #[test]
    fn signed_durations_are_kept() {
        let schedule = schedule(&[-2, 4], 0, 0, 0, 0);
        assert_eq!(schedule.marks[0].end - schedule.marks[0].start, -2);
    }
}
