//! Snapshot every stage2 analysis a saved session directory supports, for
//! comparing analysis output before and after a change.
//! Usage: stage2_snapshot <session-directory>
//!
//! The directory is one the challenge CLI writes: `iframe.js`,
//! `iframe.deobfuscated.js`, `response.decoded.txt` and, when present,
//! `second-response.decoded.txt`, `third-response.decoded.txt` and
//! `options.json`. Each analysis's error is recorded in
//! place of its result, so a regression in one does not hide the others.

use std::path::Path;
use std::{env, fs};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::challenge::program::PreparedSession;
use cfsolve::js::Options;
use cfsolve::script::Source;
use cfsolve::stage2::analysis::{self, ProgramOutcome};
use cfsolve::stage2::registry::{Kind, Operation};
use cfsolve::stage2::{call_stack, interaction};
use serde::Serialize;
use serde_json::{Map, Value, json};
use url::Url;

fn main() -> Result<()> {
    let directory = env::args().nth(1).context("supply a session directory")?;
    let directory = Path::new(&directory);
    let read = |name: &str| fs::read_to_string(directory.join(name));
    let program = |name: &str| -> Result<Option<Vec<u8>>> {
        read(name)
            .ok()
            .map(|text| Ok(STANDARD.decode(text.trim())?))
            .transpose()
    };
    let source = read("iframe.deobfuscated.js")?;
    let original = read("iframe.js")?;
    let mut snapshot = Map::new();

    let prepared = Source::try_new(&source)?;
    // The click stack reads the dispatch cases off the original's own
    // deobfuscation, as the CLI does when it fetches the iframe.
    let (_, cases) = call_stack::deobfuscate_with_cases(original.clone())?;
    let loops = call_stack::dispatch_summary(&original, &cases);
    snapshot.insert("dispatch_loops".into(), record(loops));
    let analysis = program("response.decoded.txt")?
        .context("no first response")
        .and_then(|program| analysis::analyze(&prepared, &program));
    // The stack probe's frames, which the CLI rebuilds for Chromium.
    if let Ok(analysis) = &analysis
        && let Some((_, Operation::Stack { fields })) = analysis.plan().operation(Kind::Stack)
    {
        let frames = fields
            .calls
            .context("the stack probe's calls have an unrecognized shape")
            .and_then(|calls| call_stack::recover_probe(&original, &cases, calls))
            .map(|geometry| {
                json!({
                    "frames": geometry.frames,
                    "jsc_frames": geometry.jsc_frames,
                    "reflected": geometry.reflected,
                })
            });
        snapshot.insert("probe_frames".into(), record(frames));
    }
    let analysis = analysis.and_then(|analysis| Ok(serde_json::to_value(analysis.artifact())?));
    snapshot.insert("analysis".into(), record(analysis));
    // The iframe's URL only places the POST, which this ignores.
    let base = Url::parse("https://challenges.cloudflare.com/")?;
    let session = PreparedSession::try_new(&prepared, &base);
    // The first payload's fields and the options the script marks with `Date.now()`, which
    // its timestamp differences need.
    let first_payload = match &session {
        Ok(session) => session.state().map(|state| {
            let marks: Vec<String> = state.marks.into_iter().map(|mark| mark.option).collect();
            json!({
                "marks": marks,
                "fields": session.program().encoder_json().payload_fields,
                "timing": state.timing.map(|timing| timing.option),
                "post_log": state.post_log.map(|log| log.option),
                "forwarded": state.forwarded,
            })
        }),
        Err(error) => Err(anyhow::anyhow!("{error:#}")),
    };
    snapshot.insert("first_payload".into(), record(first_payload));
    let installed = session.map(|session| {
        let installed = session.into_program().installed;
        json!({"options": installed.options, "window": installed.window})
    });
    snapshot.insert("installed".into(), record(installed));
    for name in ["response", "second-response", "third-response"] {
        if let Some(program) = program(&format!("{name}.decoded.txt"))? {
            let outcome = prepared
                .disassemble(&program)
                .map(|listing| ProgramOutcome::of(&listing).to_string());
            snapshot.insert(format!("{name}-outcome"), record(outcome));
        }
    }
    if let Some(program) = program("second-response.decoded.txt")? {
        let checkbox_program = prepared
            .disassemble(&program)
            .and_then(|listing| interaction::recover(&listing));
        if let Ok(plan) = &checkbox_program {
            let diagnostics = &plan.diagnostics;
            let frames = call_stack::recover(
                &original,
                &cases,
                diagnostics.construct,
                diagnostics.callback_arity,
            );
            snapshot.insert("callback_frames".into(), record(frames));
            if let Ok(options) = read("options.json") {
                let queries = serde_json::from_str::<Options>(&options)
                    .map_err(anyhow::Error::from)
                    .and_then(|options| interaction::checkbox::queries(&prepared, &options));
                snapshot.insert("checkbox_queries".into(), record(queries));
            }
        }
        snapshot.insert("interaction".into(), record(checkbox_program));
    }
    println!("{}", serde_json::to_string_pretty(&snapshot)?);
    Ok(())
}

/// `result` as JSON, or its error in its place.
fn record(result: Result<impl Serialize>) -> Value {
    result
        .and_then(|value| Ok(serde_json::to_value(value)?))
        .unwrap_or_else(|error| json!({"error": format!("{error:#}")}))
}
