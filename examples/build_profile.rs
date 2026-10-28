//! Store a real browser's probe answers for a device profile.
//! Usage: build_profile <capture.json> > answers.json
//!
//! The capture is a session's `capture.json` from the capture proxy, or what
//! `scripts/cdp_capture.mjs` writes: the iframe's HTML, its POSTs with their
//! responses, and the plaintext payloads. Each probe's record from the second
//! payload is stored under the reference build's names; see
//! `cfsolve::stage2::replay`.

use std::env;
use std::path::Path;

use anyhow::{Context, Result};
use cfsolve::capture::CapturedSession;
use cfsolve::stage2::replay::Answers;

fn main() -> Result<()> {
    let path = env::args().nth(1).context("supply a capture JSON file")?;
    let capture = CapturedSession::read(Path::new(&path))?;
    let answers = Answers::capture(
        &capture.source()?,
        &capture.program()?,
        capture.probe_payload()?,
    )?;
    println!("{}", serde_json::to_string_pretty(&answers)?);
    Ok(())
}
