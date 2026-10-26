//! Show how a plan's probes translate into the reference build's names.
//! Usage: vocabulary <plan.json> <probe index> [reference names to look for...]
//!
//! Prints where the probe's translated strings still differ from its
//! reference probe's, which is where a recognizer's names can go missing.

use std::collections::HashSet;
use std::{env, fs};

use anyhow::{Context, Result};
use cfsolve::stage2::vocabulary::Vocabulary;
use serde_json::Value;

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let plan: Value = serde_json::from_slice(&fs::read(args.next().context("supply plan.json")?)?)?;
    let index: usize = args.next().context("supply a probe index")?.parse()?;
    let probes = plan["probes"].as_array().context("plan has no probes")?;
    // A saved plan's features are the session's strings, in order.
    let session: Vec<Vec<String>> = probes
        .iter()
        .map(|probe| {
            probe["features"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|text| Some(text.as_str()?.to_owned()))
                .collect()
        })
        .collect();
    let vocabulary = Vocabulary::infer(&session);
    let position = index - 1;
    let partner = vocabulary
        .partner(position)
        .context("the probe has no reference partner")?;
    println!("reference probe {partner}");
    let translated: Vec<&str> = session[position]
        .iter()
        .map(|text| vocabulary.to_reference(position, text))
        .collect();
    let reference: Value = serde_json::from_str(include_str!("../src/stage2/reference.json"))?;
    let reference = reference["probes"][partner - 1]
        .as_array()
        .context("no reference strings")?;
    let shared: HashSet<&str> = translated.iter().copied().collect();
    for text in reference.iter().filter_map(Value::as_str) {
        if !shared.contains(text) {
            println!("missing {text:.80}");
        }
    }
    for name in args {
        println!("{name}: {}", translated.contains(&name.as_str()));
    }
    Ok(())
}
