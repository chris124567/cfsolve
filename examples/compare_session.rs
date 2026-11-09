//! Compare a solve's payloads with a browser capture of the same build.
//! Usage: compare_session <session-directory> <capture.json> [--values]
//!
//! The session directory is one the challenge CLI writes. Probe records are compared in the
//! reference build's names, by key and JSON type; the other payload fields, whose names the
//! vocabulary does not cover, by count and type. Timing values are ignored. `--values` also
//! prints each probe field whose value differs.

use std::collections::BTreeMap;
use std::path::Path;
use std::{env, fs};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::capture::CapturedSession;
use cfsolve::js::{JsObject, JsValue};
use cfsolve::script::Source;
use cfsolve::stage2::analysis::{self, Analysis};

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let directory = arguments.next().context("supply a session directory")?;
    let capture_path = arguments.next().context("supply a capture.json")?;
    let directory = Path::new(&directory);
    let read = |name: &str| fs::read_to_string(directory.join(name));
    let read_payload = |name: &str| -> Result<JsObject> { Ok(serde_json::from_str(&read(name)?)?) };

    let ours = analysis::analyze(
        &Source::try_new(&read("iframe.deobfuscated.js")?)?,
        &STANDARD.decode(read("response.decoded.txt")?.trim())?,
    )?;
    let capture = CapturedSession::read(Path::new(&capture_path))?;
    let theirs = analysis::analyze(&capture.source()?, &capture.program()?)?;

    let our_second = read_payload("second-payload.json")?;
    let their_second: &JsObject = capture.probe_payload()?;
    let our_values = values(&ours, &our_second);
    let their_values = values(&theirs, their_second);
    if env::args().any(|argument| argument == "--values") {
        for (probe, their_record) in &their_values {
            let Some(our_record) = our_values.get(probe) else {
                continue;
            };
            for (name, their_value) in their_record {
                let our_value = our_record.get(name).map_or("<missing>".to_owned(), short);
                let their_value = short(their_value);
                if our_value != their_value {
                    println!("{probe} {name}\n    ours   {our_value}\n    theirs {their_value}");
                }
            }
        }
    }
    let our_records = records(&our_values);
    let their_records = records(&their_values);
    let only = |a: &BTreeMap<String, String>, b: &BTreeMap<String, String>| -> Vec<String> {
        a.iter()
            .filter(|(key, kind)| b.get(*key) != Some(*kind))
            .map(|(key, kind)| format!("{key}:{kind}"))
            .collect()
    };
    for (probe, theirs) in &their_records {
        match our_records.get(probe) {
            None => println!("{probe}: only in the capture"),
            Some(ours) if ours != theirs => {
                println!(
                    "{probe}: ours {:?} theirs {:?}",
                    only(ours, theirs),
                    only(theirs, ours)
                );
            }
            Some(_) => {}
        }
    }
    for probe in our_records.keys() {
        if !their_records.contains_key(probe) {
            println!("{probe}: only in ours");
        }
    }

    println!(
        "second payload top level: {}",
        top_level(&our_second, their_second)
    );
    if let (Ok(ours), Some(theirs)) = (read_payload("third-payload.json"), capture.last_payload()) {
        println!("third payload top level: {}", top_level(&ours, theirs));
        if let (Some(ours), Some(theirs)) = (last_record(&ours), last_record(theirs)) {
            println!(
                "checkbox record: ours {} theirs {}",
                shape(ours),
                shape(theirs)
            );
        }
    }
    if let (Ok(ours), Ok(theirs)) = (read_payload("payload.json"), capture.first_payload()) {
        println!("first payload top level: {}", top_level(&ours, theirs));
    }
    Ok(())
}

/// Each probe's record in reference names, keyed by the reference probe or, for unpaired
/// probes, the family.
fn values(analysis: &Analysis, payload: &JsObject) -> BTreeMap<String, JsObject> {
    let plan = analysis.plan();
    let vocabulary = plan.vocabulary();
    let envelope = plan.record_fields.names();
    plan.probes()
        .iter()
        .filter_map(|probe| {
            let mut record = payload.get(&probe.index.to_string())?.as_object()?.clone();
            record.retain(|name, _| !envelope.contains(&name.as_str()));
            vocabulary.rewrite_to_reference(probe.position(), &mut record);
            let key = match (vocabulary.partner(probe.position()), &probe.operation) {
                (Some(reference), _) => format!("reference {reference:02}"),
                (None, Some(operation)) => format!("unpaired {}", operation.kind()),
                (None, None) => "unpaired ?".to_owned(),
            };
            Some((key, record))
        })
        .collect()
}

/// Each record from [`values`] with its fields' JSON types.
fn records(values: &BTreeMap<String, JsObject>) -> BTreeMap<String, BTreeMap<String, String>> {
    values
        .iter()
        .map(|(probe, record)| {
            let types = record
                .iter()
                .map(|(name, value)| (name.clone(), kind(value)))
                .collect();
            (probe.clone(), types)
        })
        .collect()
}

/// The record under the highest numeric key, which in the third payload is the checkbox's.
fn last_record(payload: &JsObject) -> Option<&JsObject> {
    payload
        .iter()
        .filter_map(|(key, value)| Some((key.parse::<usize>().ok()?, value)))
        .max_by_key(|(index, _)| *index)
        .and_then(|(_, value)| value.as_object())
}

fn short(value: &JsValue) -> String {
    value.to_string().chars().take(240).collect()
}

fn kind(value: &JsValue) -> String {
    match value {
        JsValue::Null => "null".into(),
        JsValue::Bool(_) => "bool".into(),
        JsValue::Number(_) => "number".into(),
        JsValue::String(text) if text.is_empty() => "empty".into(),
        JsValue::String(_) => "string".into(),
        JsValue::Array(items) => format!("array{}", items.len()),
        JsValue::Object(object) => format!("object{}", object.len()),
        JsValue::Undefined => "undefined".into(),
    }
}

/// Non-record fields: count and multiset of types on each side.
fn top_level(ours: &JsObject, theirs: &JsObject) -> String {
    let mut counts: BTreeMap<String, [usize; 2]> = BTreeMap::new();
    for (side, payload) in [ours, theirs].into_iter().enumerate() {
        for (key, value) in payload {
            if key.parse::<usize>().is_err() {
                counts.entry(kind(value)).or_default()[side] += 1;
            }
        }
    }
    let differing: Vec<String> = counts
        .iter()
        .filter(|(_, [ours, theirs])| ours != theirs)
        .map(|(kind, [ours, theirs])| format!("{kind} {ours}/{theirs}"))
        .collect();
    let total = |side: usize| counts.values().map(|count| count[side]).sum::<usize>();
    format!(
        "ours {} theirs {} fields; differing types (ours/theirs): {differing:?}",
        total(0),
        total(1),
    )
}

fn shape(record: &JsObject) -> String {
    let kinds: Vec<String> = record.values().map(kind).collect();
    format!("{} fields {kinds:?}", record.len())
}
