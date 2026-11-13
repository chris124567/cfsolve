//! Temporary: `listing_dump <deobfuscated.js> <program base64 file>` prints the full listing.

use std::time::Instant;
use std::{env, fs};

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::script::Source;

fn main() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let text = fs::read_to_string(&arguments[0])?;
    let program = STANDARD.decode(fs::read_to_string(&arguments[1])?.trim())?;
    let source = Source::try_new(&text)?;
    let machine = source.machine()?;
    let began = Instant::now();
    let listing = machine.disassemble_from(&program, &[machine.entry()], &["cf-chl-peek"])?;
    eprintln!("disassemble: {:?}", began.elapsed());
    if arguments.get(2).is_none_or(|flag| flag != "--quiet") {
        println!("{listing:#?}");
    }
    Ok(())
}
