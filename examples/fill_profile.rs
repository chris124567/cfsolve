//! Fill a device profile's measured sections from capture-proxy runs.
//! Usage: fill_profile <base-profile.json> <capture-dir>... > profile.json
//!
//! Each capture directory is one the proxy wrote with `--out`. The new profile keeps the base's
//! other values, and the notes on stderr say where each section came from and what was left out.
//! `build_profile` writes the answers the profile's `answers` names.

use std::path::Path;
use std::{env, fs};

use anyhow::{Context, Result, ensure};
use cfsolve::capture::{self, Recording};
use serde_json::Value;

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let base = arguments
        .next()
        .context("supply a base profile and capture directories")?;
    let recordings: Vec<Recording> = arguments
        .map(|dir| Recording::read(Path::new(&dir)))
        .collect::<Result<_>>()?;
    ensure!(
        !recordings.is_empty(),
        "supply at least one capture directory"
    );
    let text = fs::read(&base).with_context(|| format!("reading {base}"))?;
    let mut profile: Value = serde_json::from_slice(&text)?;
    for note in capture::fill_profile(&mut profile, &recordings)? {
        eprintln!("{note}");
    }
    println!("{}", serde_json::to_string_pretty(&profile)?);
    Ok(())
}
