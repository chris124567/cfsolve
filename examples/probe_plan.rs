//! List a captured session's probes: each record's number in the payload,
//! its kind, whether it is replayed or computed, and the reference probe
//! its stored answer is filed under.
//! Usage: probe_plan <capture.json>
//!
//! The capture is what `scripts/cdp_capture.mjs` or the capture proxy
//! writes. Records are shuffled per session, so this is the key for reading
//! a capture's second payload by hand.

use std::env;
use std::path::Path;

use anyhow::{Context, Result};
use cfsolve::capture::CapturedSession;
use cfsolve::stage2::analysis;
use cfsolve::stage2::registry::Treatment;

fn main() -> Result<()> {
    let path = env::args().nth(1).context("supply a capture JSON file")?;
    let capture = CapturedSession::read(Path::new(&path))?;
    let analysis = analysis::analyze(&capture.source()?, &capture.program()?)?;
    let plan = analysis.plan();
    println!("record\tkind\ttreatment\treference");
    for (position, probe) in plan.probes().iter().enumerate() {
        let kind = probe.operation.as_ref().map(|operation| operation.kind());
        let treatment = kind.map(|kind| match kind.treatment() {
            Treatment::Replayed => "replayed",
            Treatment::Computed => "computed",
        });
        let reference = plan.vocabulary().partner(position);
        println!(
            "{}\t{}\t{}\t{}",
            probe.index,
            kind.map_or("-".into(), |kind| kind.to_string()),
            treatment.unwrap_or("-"),
            reference.map_or("-".into(), |partner| partner.to_string()),
        );
    }
    Ok(())
}
