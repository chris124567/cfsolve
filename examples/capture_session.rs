//! Write a capture as a session directory, for `stage2_snapshot` and other tools that read the
//! challenge CLI's output.
//! Usage: capture_session <capture.json> <output-directory>
//!
//! Writes `iframe.js`, `iframe.deobfuscated.js`, and each POST response's program as
//! `response.decoded.txt`, `second-response.decoded.txt` and `third-response.decoded.txt`.

use std::path::Path;
use std::{env, fs};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::capture::CapturedSession;

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let capture = arguments.next().context("supply a capture.json")?;
    let directory = arguments.next().context("supply an output directory")?;
    let capture = CapturedSession::read(Path::new(&capture))?;
    let directory = Path::new(&directory);
    fs::create_dir_all(directory)?;
    let javascript = capture.javascript()?;
    fs::write(directory.join("iframe.js"), &javascript)?;
    fs::write(
        directory.join("iframe.deobfuscated.js"),
        cfsolve::deobfuscate(javascript)?.text,
    )?;
    let names = ["response", "second-response", "third-response"];
    for (name, program) in names.iter().zip(capture.programs()?) {
        fs::write(
            directory.join(format!("{name}.decoded.txt")),
            STANDARD.encode(program),
        )?;
    }
    Ok(())
}
