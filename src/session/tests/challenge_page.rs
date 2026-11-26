//! Regression tests for a challenge-page session.

use std::path::Path;
use std::{env, fs};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use url::Url;
use wreq::StatusCode;

use crate::Error;
use crate::challenge::codec;
use crate::challenge::orchestrator::ChallengePage;
use crate::challenge::reduced_timing::{Measure, ResourceTiming};
use crate::engine::Engine;
use crate::js::json;
use crate::resource_timing::{LoadTiming, Phases};
use crate::script::Source;
use crate::session::{Stage, challenge_page};
use crate::stage2::call_stack;
use crate::stage2::challenge_page::WidgetProgram;

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

/// Rebuilds the loader's render stack from a challenge-page capture named by
/// `CFSOLVE_CHALLENGE_CAPTURE` and compares it with the stack the browser reported. The
/// directory holds `page-url.txt`, `page.html`, `orchestrator.js`, the orchestrator's first
/// `orchestrator-response.txt`, `loader-url.txt` (the loader URL its stack names), `api.js`,
/// `engine.txt` (`chromium` or `webkit`), and, optionally, the browser's `render-stack.txt`.
#[test]
fn rebuilds_the_render_stack_of_a_capture() {
    let Some(dir) = env::var_os("CFSOLVE_CHALLENGE_CAPTURE") else {
        return;
    };
    let dir = Path::new(&dir);
    let read = |name: &str| {
        fs::read_to_string(dir.join(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
    };
    let page_url = Url::parse(read("page-url.txt").trim()).unwrap();
    let challenge = ChallengePage::parse(&read("page.html"), &page_url)
        .unwrap()
        .expect("the page is a challenge page");
    let ray = challenge
        .orchestrator
        .query_pairs()
        .find(|(key, _)| key == "ray")
        .map(|(_, ray)| ray.into_owned())
        .expect("the orchestrator URL names the ray");
    let javascript = challenge.javascript(&read("orchestrator.js"));
    let (deobfuscated, cases) = call_stack::deobfuscate_with_cases(javascript.clone()).unwrap();
    let source = Source::try_new(&deobfuscated.text).unwrap();
    let text =
        codec::decode_response(read("orchestrator-response.txt").trim().as_bytes(), &ray).unwrap();
    let program = STANDARD.decode(text).unwrap();
    let widget = WidgetProgram::recover(&source.disassemble(&program).unwrap()).unwrap();
    let engine = match read("engine.txt").trim() {
        "chromium" => Engine::Chromium,
        "webkit" => Engine::WebKit,
        other => panic!("unknown engine {other}"),
    };
    let loader_url = Url::parse(read("loader-url.txt").trim()).unwrap();
    let sample = challenge_page::render_sample(
        &read("api.js"),
        &loader_url,
        &challenge,
        &javascript,
        &cases,
        &widget,
        engine,
    )
    .unwrap();
    // Without the browser's stack, check only that recovery succeeds.
    if let Ok(expected) = fs::read_to_string(dir.join("render-stack.txt")) {
        assert_eq!(sample.stack, expected.trim_end_matches('\n'));
    }
}
