//! Check stored answers against captured sessions of the current build.
//! Usage: check_answers <answers.json> <capture.json>...
//!
//! Translates each replayed probe's stored record into the session's names, as a solve does,
//! and compares its fields with the record the browser sent. Prints the fields only one side
//! has; a field the stored record keeps under a name the session lacks means the vocabulary
//! could not translate it.

use std::collections::BTreeSet;
use std::path::Path;
use std::{env, fs};

use anyhow::{Context, Result, ensure};
use cfsolve::capture::CapturedSession;
use cfsolve::js::JsValue;
use cfsolve::stage2::analysis;
use cfsolve::stage2::replay::Answers;

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let answers = arguments.next().context("supply answers.json")?;
    let answers: Answers = serde_json::from_str(&fs::read_to_string(&answers)?)?;
    let mut mismatched = 0;
    for path in arguments {
        let capture = CapturedSession::read(Path::new(&path))?;
        let analysis = analysis::analyze(&capture.source()?, &capture.program()?)?;
        let plan = analysis.plan();
        let vocabulary = plan.vocabulary();
        let envelope = plan.record_fields.names();
        let payload = capture.probe_payload()?;
        let (mut checked, mut differing) = (0, 0);
        for probe in plan.probes() {
            let position = probe.position();
            let Some(stored) = vocabulary
                .partner(position)
                .and_then(|partner| answers.probes.get(&partner))
            else {
                continue;
            };
            let mut fields = stored.fields.clone();
            vocabulary.rewrite_to_session(position, &mut fields);
            let ours: BTreeSet<&String> = fields.keys().collect();
            let sent: BTreeSet<&String> = payload
                .get(&probe.index.to_string())
                .and_then(JsValue::as_object)
                .into_iter()
                .flat_map(|record| record.keys())
                .filter(|name| !envelope.contains(&name.as_str()))
                .collect();
            checked += 1;
            if ours != sent {
                differing += 1;
                println!(
                    "{path} probe {}: only stored {:?}, only sent {:?}",
                    probe.index,
                    ours.difference(&sent).collect::<Vec<_>>(),
                    sent.difference(&ours).collect::<Vec<_>>(),
                );
            }
        }
        println!("{path}: {checked} replayed records, {differing} differ");
        mismatched += differing;
    }
    ensure!(mismatched == 0, "{mismatched} records differ");
    Ok(())
}
