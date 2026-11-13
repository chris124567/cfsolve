//! Rebuild the reference from a capture of a new build, keeping the reference probe numbers.
//! Usage: rebase_reference <capture.json> <old reference.json> <reference.rs> <new reference.json>
//!
//! Each reference probe becomes the capture's probe paired with it, or the capture's probe of
//! the same family when that family is recognized without pairing; a family the build no longer
//! has keeps its old strings. Prints each hex name `reference.rs` declares with the capture's name
//! for it, through the vocabulary of every probe that mentions it, and `?` where a probe does not
//! translate it, so the declarations can be moved to the new reference.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::{env, fs};

use anyhow::{Context, Result};
use cfsolve::capture::CapturedSession;
use cfsolve::stage2::analysis;
use cfsolve::stage2::registry::Kind;
use serde_json::{Value, json};

fn main() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let [capture, old, declarations, new] = arguments.as_slice() else {
        anyhow::bail!("supply capture.json, the old reference.json, reference.rs and an output");
    };
    let capture = CapturedSession::read(Path::new(capture))?;
    let analysis = analysis::analyze(&capture.source()?, &capture.program()?)?;
    let plan = analysis.plan();
    let vocabulary = plan.vocabulary();
    let old: Value = serde_json::from_str(&fs::read_to_string(old)?)?;
    let old_probes = old["probes"].as_array().context("no reference probes")?;
    // Each reference probe's session probe position.
    let mut positions: BTreeMap<usize, usize> = BTreeMap::new();
    for (position, probe) in plan.probes().iter().enumerate() {
        let reference = vocabulary.partner(position).or_else(|| {
            let kind = probe.operation.as_ref()?.kind();
            match kind.references() {
                [reference] => Some(*reference),
                _ => None,
            }
        });
        if let Some(reference) = reference {
            anyhow::ensure!(
                positions.insert(reference, position).is_none(),
                "two probes stand for reference probe {reference}"
            );
        }
    }
    let mut probes = Vec::new();
    for (number, old_probe) in (1..).zip(old_probes) {
        if let Some(&position) = positions.get(&number) {
            probes.push(json!(plan.probes()[position].features));
        } else {
            eprintln!(
                "reference probe {number} ({}) has no probe in this build; keeping its strings",
                Kind::from_reference(number).map_or("?".into(), |kind| kind.to_string())
            );
            probes.push(old_probe.clone());
        }
    }
    let build = capture
        .iframe_html()
        .split("/turnstile/v0/g/")
        .nth(1)
        .and_then(|rest| rest.get(..12))
        .unwrap_or("unknown");
    let rebuilt = json!({"build": build, "probes": probes});
    fs::write(new, serde_json::to_string(&rebuilt)?)?;

    // Translate each declared name through the probes that mention it.
    let declarations = fs::read_to_string(declarations)?;
    let declared: BTreeSet<&str> = declarations
        .split('"')
        .filter(|text| text.len() == 25 && text.starts_with('_'))
        .filter(|text| text[1..].bytes().all(|byte| byte.is_ascii_hexdigit()))
        .collect();
    for name in declared {
        let mut translations = BTreeSet::new();
        for (number, old_probe) in (1..).zip(old_probes) {
            let Some(&position) = positions.get(&number) else {
                continue;
            };
            let strings = old_probe.as_array();
            if strings.is_some_and(|strings| strings.iter().any(|text| text == name)) {
                let session = vocabulary.to_session(position, name);
                translations.insert(if session == name {
                    format!("?@{number}")
                } else {
                    session.to_owned()
                });
            }
        }
        let translations: Vec<String> = translations.into_iter().collect();
        println!("{name} {}", translations.join(" "));
    }
    Ok(())
}
