//! Store a real browser's probe answers for a device profile.
//! Usage: build_profile <capture.json> [cssom.json] > answers.json
//!
//! The capture is a session's `capture.json` from the capture proxy, or what
//! `scripts/cdp_capture.mjs` writes: the iframe's HTML, its POSTs with their
//! responses, and the plaintext payloads. Each probe's record from the second
//! payload is stored under the reference build's names; see
//! `cfsolve::stage2::replay`. An adjacent `iframe.deobfuscated.js` (from
//! `capture_session`) is used instead of deobfuscating the capture's script.

use std::path::Path;
use std::{env, fs};

use anyhow::{Context, Result};
use cfsolve::capture::CapturedSession;
use cfsolve::stage2::replay::Answers;

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let path = arguments.next().context("supply a capture JSON file")?;
    let capture = CapturedSession::read(Path::new(&path))?;
    let source = capture.source_beside(Path::new(&path))?;
    let program = capture.program()?;
    let payload = capture.probe_payload()?;
    let answers = match arguments.next() {
        Some(path) => Answers::capture_measured(
            &source,
            &program,
            payload,
            capture.iframe_html(),
            serde_json::from_str(&fs::read_to_string(path)?)?,
        )?,
        None => Answers::capture(&source, &program, payload)?,
    };
    println!("{}", serde_json::to_string_pretty(&answers)?);
    Ok(())
}
