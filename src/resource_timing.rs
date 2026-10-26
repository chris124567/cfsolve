//! Reports resource timing for this client's loads using browser rules. Uses measured phases
//! where available and fingerprint estimates when only a total duration was measured.

use serde::Deserialize;

/// Estimated header bytes added to the encoded body size for transfer size.
const ASSUMED_HEADER_BYTES: u64 = 300;
/// The protocol this client fetches over, which resource timing reports as `nextHopProtocol`.
pub(crate) const NEXT_HOP_PROTOCOL: &str = "h2";

/// The fractions of a fetch's duration a browser reports as waiting for the first byte
/// (`request`) and receiving the body (`response`), for fetches this client times only as a
/// whole.
#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct Phases {
    pub request: f64,
    pub response: f64,
}

/// Settings from the fingerprint's `resource_timing` section. Estimate fetch phases when this
/// client measures only total duration.
#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct Reporting {
    /// The phases of a script, image or POST.
    pub phases: Phases,
    /// The phases of a document navigation.
    pub navigation: Phases,
    /// Whether a cross-origin script that allows timing also reports its sizes.
    pub sizes_exposed: bool,
}

/// One fetch, as the browser's resource timing would report it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ResourceMeasurement {
    /// Total fetch duration, in milliseconds.
    pub duration: f64,
    /// `responseStart - requestStart`.
    pub request: f64,
    /// `responseEnd - responseStart`.
    pub response: f64,
    pub transfer_size: u64,
    pub body_size: u64,
}

impl ResourceMeasurement {
    /// Estimates the `phases` and header overhead from the measured duration and body size.
    #[must_use]
    pub(crate) fn estimated(duration: f64, body_size: u64, phases: Phases) -> Self {
        Self {
            duration,
            request: duration * phases.request,
            response: duration * phases.response,
            transfer_size: body_size + ASSUMED_HEADER_BYTES,
            body_size,
        }
    }

    /// Builds a restricted entry for a cross-origin fetch without `Timing-Allow-Origin`.
    /// Request and response start times are zero, so the reported response interval runs from
    /// zero to `end`. Omits sizes.
    #[must_use]
    pub(crate) fn restricted(duration: f64, end: f64) -> Self {
        Self {
            duration,
            request: 0.0,
            response: end,
            transfer_size: 0,
            body_size: 0,
        }
    }
}

/// A load the session made, timed as resource timing reports it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LoadTiming {
    pub url: String,
    /// When it was sent, in epoch milliseconds.
    pub started_ms: i64,
    pub duration_ms: f64,
    pub waiting_ms: f64,
    pub receiving_ms: f64,
    pub body_bytes: u64,
}

impl LoadTiming {
    #[must_use]
    pub(crate) fn ended_ms(&self) -> f64 {
        self.started_ms as f64 + self.duration_ms
    }

    /// Returns timing for this load using its measured phases.
    #[must_use]
    pub(crate) fn measurement(&self) -> ResourceMeasurement {
        ResourceMeasurement {
            duration: self.duration_ms,
            request: self.waiting_ms,
            response: self.receiving_ms,
            transfer_size: self.body_bytes + ASSUMED_HEADER_BYTES,
            body_size: self.body_bytes,
        }
    }
}
