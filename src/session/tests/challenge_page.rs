//! Regression tests for a challenge-page session.

use crate::challenge::reduced_timing::{Measure, ResourceTiming};
use crate::js::json;
use crate::resource_timing::{LoadTiming, Phases};
use crate::session::challenge_page;

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
