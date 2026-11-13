//! Show each captured probe's closest reference probe and its non-name strings, to see why
//! probes of a new build fail to pair.
//! Usage: probe_similarity <capture.json> [probe index...]

use std::env;
use std::path::Path;

use anyhow::{Context, Result};
use cfsolve::capture::CapturedSession;
use cfsolve::stage2::analysis;

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let path = arguments.next().context("supply a capture JSON file")?;
    let detail: Vec<usize> = arguments.filter_map(|text| text.parse().ok()).collect();
    let capture = CapturedSession::read(Path::new(&path))?;
    let analysis = analysis::analyze(&capture.source()?, &capture.program()?)?;
    let plan = analysis.plan();
    let vocabulary = plan.vocabulary();
    for (position, probe) in plan.probes().iter().enumerate() {
        let candidate = vocabulary.candidate(position);
        println!(
            "{}\tpartner {:?}\tbest {:?}\t{} strings",
            probe.index,
            vocabulary.partner(position),
            candidate.map(|candidate| (candidate.reference, candidate.similarity)),
            probe.features.len(),
        );
        if detail.contains(&probe.index) {
            println!("    {:?}", probe.features);
            let payload = capture.probe_payload().ok();
            let record = payload.and_then(|payload| payload.get(&probe.index.to_string()));
            println!("    sent {}", serde_json::to_string(&record)?);
        }
    }
    Ok(())
}
