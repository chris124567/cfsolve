//! Regression tests for a challenge-page session.

use wreq::StatusCode;

use crate::Error;
use crate::challenge::reduced_timing::{Measure, ResourceTiming};
use crate::js::json;
use crate::resource_timing::{LoadTiming, Phases};
use crate::session::{Stage, challenge_page};

/// A load measured only as a whole.
fn fetch(url: &str, started_ms: i64, duration_ms: f64) -> LoadTiming {
    LoadTiming {
        url: url.into(),
        started_ms,
        duration_ms,
        waiting_ms: 0.0,
        receiving_ms: 0.0,
        body_bytes: 100,
    }
}

/// Checks both resource timing snapshots: unfinished and finished navigation, intervening
/// loads, first POST, repeated icon, and iframe with only its end time exposed.
#[test]
fn the_pages_resource_timing_lists_both_of_the_widget_programs_reads() {
    let timing = ResourceTiming {
        option: "timing".into(),
        fields: vec![
            ("n".into(), Measure::Name),
            ("d".into(), Measure::Duration),
            ("r".into(), Measure::Response),
            ("b".into(), Measure::Body),
        ],
    };
    let navigation = fetch("https://page/", 1_000, 50.0);
    let loads = [
        fetch("https://page/orchestrate.js", 1_060, 20.0),
        fetch("https://loader/api.js", 1_300, 40.0),
        fetch("https://page/favicon.ico", 1_090, 10.0),
    ];
    let post = fetch("https://page/flow", 1_100, 30.0);
    let iframe = fetch("https://challenges/iframe", 1_400, 25.0);
    let phases = Phases {
        request: 0.5,
        response: 0.25,
    };
    let entries =
        challenge_page::page_resource_timing(&timing, phases, &navigation, &loads, &post, &iframe);
    assert_eq!(
        entries,
        [
            // Still loading.
            json!({"n": "https://page/", "d": 0, "r": 12, "b": 100}),
            json!({"n": "https://page/orchestrate.js", "d": 20, "r": 5, "b": 100}),
            json!({"n": "https://loader/api.js", "d": 40, "r": 10, "b": 100}),
            json!({"n": "https://page/favicon.ico", "d": 10, "r": 2, "b": 100}),
            // Finished once the last load (the loader, at 1340) ended.
            json!({"n": "https://page/", "d": 340, "r": 12, "b": 100}),
            json!({"n": "https://page/flow", "d": 30, "r": 0, "b": 100}),
            json!({"n": "https://page/favicon.ico", "d": 10, "r": 2, "b": 100}),
            // The cross-origin iframe shows only its end, from the navigation.
            json!({"n": "https://challenges/iframe", "d": 25, "r": 425, "b": 0}),
        ]
    );
}

/// Whether a clearance form response refuses the answers, as a caller sees it.
fn refused(status: StatusCode, challenged: bool, clearance: Option<&str>) -> bool {
    let error = challenge_page::accept_clearance(status, challenged, clearance.map(str::to_owned))
        .expect_err("the response should not pass");
    matches!(
        Error::classify(error),
        Error::Rejected {
            stage: Stage::Clearance,
            ..
        }
    )
}

/// A `cf_clearance` cookie is a pass whatever the status of the page behind the challenge,
/// such as a waiting room's HTTP 429. Another challenge page, or an error status without the
/// cookie, is a refusal. A success without the cookie is a failure the solver can't explain.
#[test]
fn the_clearance_form_passes_when_it_sets_the_cookie_whatever_the_pages_status() {
    for status in [
        StatusCode::OK,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::NOT_FOUND,
    ] {
        let clearance = challenge_page::accept_clearance(status, false, Some("token".into()));
        assert_eq!(clearance.unwrap(), "token", "HTTP {status}");
    }
    assert!(refused(StatusCode::OK, true, Some("token")));
    assert!(refused(StatusCode::FORBIDDEN, true, Some("token")));
    assert!(refused(StatusCode::TOO_MANY_REQUESTS, false, None));
    assert!(!refused(StatusCode::OK, false, None));
}
