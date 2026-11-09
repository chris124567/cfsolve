//! Replays CPU work from a saved solve without network requests or expired challenges.
//!
//! `cargo run --release --example solver_profile -- /tmp/solve [deobfuscate|analyze|orchestrator]`
//!
//! Without a mode, deobfuscates `iframe.js`, writing `profile.deobfuscated.js`, and analyzes the
//! result, writing `profile.stage2.json`. `deobfuscate` stops after deobfuscation; `analyze`
//! analyzes the script the solve deobfuscated. `orchestrator` deobfuscates the saved
//! orchestrator script and disassembles its first returned program, writing
//! `profile.orchestrator.js` and `profile.orchestrator-listing.txt`.

use std::path::Path;
use std::time::Instant;
use std::{env, fs};

use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use cfsolve::script::Source;

const USAGE: &str = "usage: solver_profile <session directory> [deobfuscate|analyze|orchestrator]";

fn main() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let (directory, mode) = match &arguments[..] {
        [directory] => (Path::new(directory), None),
        [directory, mode] => (Path::new(directory), Some(mode.as_str())),
        _ => bail!(USAGE),
    };
    match mode {
        None | Some("deobfuscate") => {
            let text = deobfuscate(&directory.join("iframe.js"))?;
            fs::write(directory.join("profile.deobfuscated.js"), &text)?;
            if mode.is_none() {
                analyze(directory, &text)?;
            }
        }
        Some("analyze") => {
            let text = fs::read_to_string(directory.join("iframe.deobfuscated.js"))?;
            analyze(directory, &text)?;
        }
        Some("orchestrator") => {
            let text = deobfuscate(&directory.join("orchestrator.js"))?;
            fs::write(directory.join("profile.orchestrator.js"), &text)?;
            let program = STANDARD.decode(fs::read(
                directory.join("orchestrator-response.decoded.txt"),
            )?)?;
            let began = Instant::now();
            let listing = Source::try_new(&text)?.disassemble(&program)?;
            eprintln!("disassemble: {:?}", began.elapsed());
            fs::write(
                directory.join("profile.orchestrator-listing.txt"),
                format!("{listing:#?}"),
            )?;
        }
        Some(_) => bail!(USAGE),
    }
    Ok(())
}

fn deobfuscate(path: &Path) -> Result<String> {
    let javascript = fs::read_to_string(path)?;
    let began = Instant::now();
    let deobfuscated = cfsolve::deobfuscate(javascript)?;
    eprintln!("deobfuscate: {:?}", began.elapsed());
    if let Some(unconverged) = deobfuscated.unconverged {
        eprintln!("warning: {unconverged}");
    }
    Ok(deobfuscated.text)
}

fn analyze(directory: &Path, javascript: &str) -> Result<()> {
    let program = STANDARD.decode(fs::read(directory.join("response.decoded.txt"))?)?;
    let began = Instant::now();
    let source = Source::try_new(javascript)?;
    eprintln!("parse: {:?}", began.elapsed());
    let began = Instant::now();
    let analysis = cfsolve::stage2::analysis::analyze(&source, &program)?;
    eprintln!("analyze: {:?}", began.elapsed());
    fs::write(
        directory.join("profile.stage2.json"),
        serde_json::to_vec_pretty(&analysis.artifact())?,
    )?;
    Ok(())
}
