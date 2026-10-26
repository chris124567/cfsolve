//! List a captured session's probes: each record's number in the payload,
//! its kind, whether it is replayed or computed, and the reference probe
//! its stored answer is filed under.
//! Usage: probe_plan <capture.json>
//!
//! The capture is what `scripts/cdp_capture.mjs` or the capture proxy
//! writes. Records are shuffled per session, so this is the key for reading
//! a capture's second payload by hand.

use std::{env, fs};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::challenge;
use cfsolve::script::Source;
use cfsolve::stage2::analysis;
use cfsolve::stage2::registry::Treatment;
use serde_json::Value;
use url::Url;

fn main() -> Result<()> {
    let path = env::args().nth(1).context("supply a capture JSON file")?;
    let capture: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let html = capture["iframeHtml"]
        .as_str()
        .context("the capture has no iframe HTML")?;
    let javascript = challenge::inline_javascript(html)?;
    let deobfuscated = cfsolve::deobfuscate(javascript)?;
    let source = Source::try_new(&deobfuscated.text)?;

    // The first payload's response is the probe program, masked with the ray
    // its URL carries.
    let post = &capture["posts"][0];
    let url = Url::parse(post["url"].as_str().context("the capture has no POST")?)?;
    let body = post["responseBody"]
        .as_str()
        .context("the first payload has no response")?;
    let program = STANDARD.decode(challenge::decode_response(
        body.as_bytes(),
        challenge::ray(&url)?,
    )?)?;

    let analysis = analysis::analyze(&source, &program)?;
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
