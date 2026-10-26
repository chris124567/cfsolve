//! Deobfuscates a challenge script saved on disk.

use std::path::PathBuf;
use std::{env, fs};

use anyhow::{Context, Result, bail};

fn main() -> Result<()> {
    let arguments: Vec<PathBuf> = env::args_os().skip(1).map(PathBuf::from).collect();
    let [input, output] = &arguments[..] else {
        bail!("Usage: cfsolve <input.js> <output.js>");
    };
    let source =
        fs::read_to_string(input).with_context(|| format!("reading {}", input.display()))?;
    let deobfuscated = cfsolve::deobfuscate(source)?;
    if let Some(unconverged) = deobfuscated.unconverged {
        eprintln!("warning: {unconverged}");
    }
    fs::write(output, deobfuscated.text).with_context(|| format!("writing {}", output.display()))
}
