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

/// Probe marks laid out as the probes run: in order, one millisecond apart. A probe lasts its
/// planned duration, or until the work it waits for, such as a request, ends.
pub(crate) struct Timeline {
    /// When the next probe starts, in epoch milliseconds.
    pub next_start: i64,
    marks: Vec<ProbeMarks>,
}

impl Timeline {
    #[must_use]
    pub(crate) fn starting(next_start: i64) -> Self {
        Self {
            next_start,
            marks: Vec::new(),
        }
    }

    /// Ends the next probe `planned_ms` after it starts, or at `finished_ms` if its work ended
    /// later.
    pub(crate) fn finish(&mut self, planned_ms: i64, finished_ms: Option<i64>) {
        let start = self.next_start;
        let planned_end = start + planned_ms;
        let end = finished_ms.map_or(planned_end, |finished| finished.max(planned_end));
        self.marks.push(ProbeMarks { start, end });
        self.next_start = end + 1;
    }

    /// Sends `pending_ms` after the last probe's next mark. Programs without probes send when
    /// they start.
    #[must_use]
    pub(crate) fn schedule(self, pending_ms: i64) -> Schedule {
        let pending_ms = if self.marks.is_empty() { 0 } else { pending_ms };
        Schedule {
            marks: self.marks,
            send_at: self.next_start + pending_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_run_in_order_and_last_until_their_requests_end() {
        let mut timeline = Timeline::starting(1_400);
        timeline.finish(3, None);
        // The request took longer than planned.
        timeline.finish(5, Some(1_430));
        // The request ended before the planned duration ran out.
        timeline.finish(10, Some(1_433));
        let schedule = timeline.schedule(15);
        assert_eq!(
            schedule.marks,
            [
                ProbeMarks {
                    start: 1_400,
                    end: 1_403
                },
                ProbeMarks {
                    start: 1_404,
                    end: 1_430
                },
                ProbeMarks {
                    start: 1_431,
                    end: 1_441
                },
            ]
        );
        assert_eq!(
            schedule.send_at, 1_457,
            "the last probe's next mark is exactly `pending_ms` before sending"
        );
        assert_eq!(Timeline::starting(900).schedule(15).send_at, 900);
    }

    #[test]
    fn signed_durations_are_kept() {
        let mut timeline = Timeline::starting(0);
        timeline.finish(-2, None);
        assert_eq!(
            timeline.schedule(0).marks,
            [ProbeMarks { start: 0, end: -2 }]
        );
    }
}
