//! Measures WebSocket round trips to the challenge platform. Some builds from 2026-10-27 onward
//! include this probe; the reference build has no matching probe.
//!
//! Connects to `wss://<iframe host>/cdn-cgi/challenge-platform/h/<platform>/w`, using a platform
//! option and a 500 ms timeout. After opening, sends `String(performance.now())`. For each echo,
//! records the current clock minus the echoed value, then sends a new reading. Stops after six
//! echoes.
//!
//! The record contains status, sent and received counts, opening time, round-trip times, and total
//! duration.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use url::{Position, Url};

use crate::js::{self, JsObject, Options, json};
use crate::stage2::analysis::recognize::ProbeView;

/// Number of echoes required to complete the probe.
pub(crate) const ECHOES: usize = 6;

/// Echo timeout in milliseconds.
pub(crate) const TIMEOUT_MS: u64 = 500;

/// Connection options and result field names for this session.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    /// The `_cf_chl_opt` option holding the platform path segment.
    pub platform: String,
    pub status: String,
    pub sent: String,
    pub received: String,
    /// Time taken to open the socket; empty if it never opened.
    pub opened: String,
    pub round_trips: String,
    pub elapsed: String,
    pub statuses: Statuses,
}

/// The probe's status strings.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Statuses {
    /// Every echo returned.
    pub complete: String,
    /// The exchange ended before all echoes returned.
    pub incomplete: String,
    pub timed_out: String,
    pub failed_before_open: String,
    pub failed_after_open: String,
    /// The server closed the socket before all echoes returned.
    pub closed: String,
}

/// Reason the exchange ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// All messages were sent and the final echo was handled.
    Echoed,
    TimedOut,
    Failed,
    Closed,
}

/// Measurements from one WebSocket exchange.
#[derive(Clone, Debug, PartialEq)]
pub struct Measurement {
    pub end: End,
    pub sent: usize,
    pub received: usize,
    /// Time from socket construction to `open`, measured with `performance.now()`. Absent if the
    /// socket never opened.
    pub opened_ms: Option<f64>,
    /// Round-trip time for each echo: current `performance.now()` minus the echoed reading.
    pub round_trips: Vec<f64>,
    /// Probe duration measured with `Date.now()`.
    pub elapsed_ms: i64,
}

impl Fields {
    /// Builds the socket URL using the host from `iframe`.
    pub fn url(&self, options: &Options, iframe: &Url) -> Result<Url> {
        let host = &iframe[Position::BeforeHost..Position::AfterPort];
        let platform = js::string(options.get(self.platform.as_str()));
        Ok(Url::parse(&format!(
            "wss://{host}/cdn-cgi/challenge-platform/h/{platform}/w"
        ))?)
    }

    /// Builds the record in the same field order as the probe.
    #[must_use]
    pub fn collect(&self, measured: &Measurement) -> JsObject {
        let statuses = &self.statuses;
        let status = match measured.end {
            End::Echoed if measured.round_trips.len() >= ECHOES => &statuses.complete,
            End::Echoed => &statuses.incomplete,
            End::TimedOut => &statuses.timed_out,
            End::Failed if measured.opened_ms.is_some() => &statuses.failed_after_open,
            End::Failed => &statuses.failed_before_open,
            End::Closed => &statuses.closed,
        };
        // `Math.round` rounds halves up.
        let opened = measured
            .opened_ms
            .map(|opened| js::string(Some(&json!((opened + 0.5).floor()))))
            .unwrap_or_default();
        let round_trips = json!(measured.round_trips).stringify().unwrap_or_default();
        JsObject::from_iter([
            (self.status.clone(), json!(status)),
            (self.sent.clone(), json!(measured.sent.to_string())),
            (self.received.clone(), json!(measured.received.to_string())),
            (self.opened.clone(), json!(opened)),
            (self.round_trips.clone(), json!(round_trips)),
            (self.elapsed.clone(), json!(measured.elapsed_ms.to_string())),
        ])
    }
}

/// Recognizes the probe by its socket handlers. Field and status names appear in a consistent order
/// around these handlers:
///
/// - The final summary lists status, sent count, received count, opening time, and error code
///   before `length`. Complete and incomplete status strings follow it.
/// - Round-trip times precede `JSON.stringify`; duration precedes `String(Date.now() - start)`.
/// - Timeout status precedes `String(Math.round(..))`, which records opening time.
/// - The error handler tests opening time against `""`, then selects the status for failure after
///   or before opening. The close status follows.
/// - The platform option precedes the URL suffix `/w`.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let strings = probe.session_features;
    let markers = ["WebSocket", "onopen", "onmessage", "onclose", "isFinite"];
    if !markers
        .iter()
        .all(|marker| strings.iter().any(|text| text == marker))
    {
        return None;
    }
    let find = |sequence: &[&str]| {
        strings
            .windows(sequence.len())
            .position(|window| window.iter().zip(sequence).all(|(text, want)| text == want))
    };
    let before = |sequence: &[&str]| strings.get(find(sequence)?.checked_sub(1)?).cloned();

    let length = find(&["length"])?;
    let [status, sent, received, opened, _error] = strings.get(length.checked_sub(5)?..length)?
    else {
        return None;
    };
    let [complete, incomplete] = strings.get(length + 1..length + 3)? else {
        return None;
    };
    let finite = find(&["isFinite"])?;
    let compared = finite + strings[finite..].iter().position(String::is_empty)?;
    let [failed_after_open, failed_before_open, closed] =
        strings.get(compared + 1..compared + 4)?
    else {
        return None;
    };
    let fields = Fields {
        platform: before(&["/w"])?,
        status: status.clone(),
        sent: sent.clone(),
        received: received.clone(),
        opened: opened.clone(),
        round_trips: before(&["JSON", "stringify"])?,
        elapsed: before(&["String", "Date", "now"])?,
        statuses: Statuses {
            complete: complete.clone(),
            incomplete: incomplete.clone(),
            timed_out: before(&["String", "Math", "round"])?,
            failed_before_open: failed_before_open.clone(),
            failed_after_open: failed_after_open.clone(),
            closed: closed.clone(),
        },
    };
    // Require every record field to be written by the probe.
    let written = [
        &fields.status,
        &fields.sent,
        &fields.received,
        &fields.opened,
        &fields.round_trips,
        &fields.elapsed,
    ];
    written
        .iter()
        .all(|name| probe.writes.fields.contains(name))
        .then_some(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> Fields {
        Fields {
            platform: "ppebL7".into(),
            status: "ppmO1".into(),
            sent: "IGrKf5".into(),
            received: "JPvF0".into(),
            opened: "IcEa5".into(),
            round_trips: "UDMx6".into(),
            elapsed: "RvpHD0".into(),
            statuses: Statuses {
                complete: "OCCOO7".into(),
                incomplete: "DptU5".into(),
                timed_out: "ZUzk4".into(),
                failed_before_open: "WKjg8".into(),
                failed_after_open: "TBGV5".into(),
                closed: "lbCk7".into(),
            },
        }
    }

    /// Captured c787ce48cf6b record with an opening time rounded up from 101.5 ms.
    #[test]
    fn records_a_complete_exchange_as_the_browser_did() {
        let round_trips = vec![
            11.189999997615814,
            11.449999995529652,
            11.759999997913837,
            9.370000004768372,
            11.850000001490116,
            10.859999999403954,
        ];
        let measured = Measurement {
            end: End::Echoed,
            sent: 6,
            received: 6,
            opened_ms: Some(101.5),
            round_trips,
            elapsed_ms: 173,
        };
        assert_eq!(
            js::stringify_object(&fields().collect(&measured)),
            r#"{"ppmO1":"OCCOO7","IGrKf5":"6","JPvF0":"6","IcEa5":"102","UDMx6":"[11.189999997615814,11.449999995529652,11.759999997913837,9.370000004768372,11.850000001490116,10.859999999403954]","RvpHD0":"173"}"#
        );
    }

    #[test]
    fn a_socket_that_never_opened_reports_no_opening() {
        let measured = Measurement {
            end: End::Failed,
            sent: 0,
            received: 0,
            opened_ms: None,
            round_trips: Vec::new(),
            elapsed_ms: 40,
        };
        assert_eq!(
            js::stringify_object(&fields().collect(&measured)),
            r#"{"ppmO1":"WKjg8","IGrKf5":"0","JPvF0":"0","IcEa5":"","UDMx6":"[]","RvpHD0":"40"}"#
        );
    }
}
