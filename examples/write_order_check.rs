//! Compares the record field order analysis predicts with the order browsers sent.
//! Usage: write_order_check <session directory>...
//!
//! Each directory is one capture proxy session: `capture.json` holds the iframe HTML and the
//! browser's second payload, `session.json` the decoded probe program. Fields go in sorted, so
//! a match comes from the recovered write order rather than the browser's own.

use std::{env, fs};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::script::Source;
use cfsolve::stage2::analysis;
use cfsolve::{JsObject, JsValue, challenge};
use serde_json::Value;

fn main() -> Result<()> {
    let (mut matched, mut differ) = (0, 0);
    for directory in env::args().skip(1) {
        let read = |name: &str| -> Result<Value> {
            let bytes = fs::read(format!("{directory}/{name}"))?;
            Ok(serde_json::from_slice(&bytes)?)
        };
        let (capture, session) = (read("capture.json")?, read("session.json")?);
        let html = capture["iframeHtml"].as_str().context("no iframe HTML")?;
        let deobfuscated = cfsolve::deobfuscate(challenge::inline_javascript(html)?)?;
        let source = Source::try_new(&deobfuscated.text)?;
        let program = session["posts"][0]["decodedProgram"]
            .as_str()
            .context("no decoded probe program")?;
        let analysis = analysis::analyze(&source, &STANDARD.decode(program.trim())?)?;
        let plan = analysis.plan();
        let payload: JsValue = capture["payloads"][1]["payload"].clone().into();
        let names = plan.record_fields.names();
        for probe in plan.probes() {
            let Some(record) = payload[probe.index.to_string()].as_object() else {
                continue;
            };
            let sent: Vec<&String> = record.keys().collect();
            let mut fields: Vec<(String, JsValue)> = record
                .iter()
                .filter(|(name, _)| !names.contains(&name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            fields.sort_by(|(left, _), (right, _)| left.cmp(right));
            let arranged = probe.writes.arrange(JsObject::from_iter(fields));
            let predicted: Vec<&String> = names[1..5]
                .iter()
                .copied()
                .chain(arranged.early.keys().map(String::as_str))
                .chain(names[5..].iter().copied())
                .chain(arranged.late.keys().map(String::as_str))
                .filter_map(|name| record.get_key_value(name).map(|(key, _)| key))
                .collect();
            if predicted == sent {
                matched += 1;
            } else {
                differ += 1;
                let kind = probe
                    .operation
                    .as_ref()
                    .map_or("-".into(), |operation| operation.family().to_string());
                println!("{directory} probe {} ({kind})", probe.index);
                println!("  sent      {sent:?}");
                println!("  predicted {predicted:?}");
            }
        }
    }
    println!("{matched} match, {differ} differ");
    Ok(())
}
