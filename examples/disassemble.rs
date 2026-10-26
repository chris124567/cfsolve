//! Print the instructions of a session's VM program.
//!
//! `disassemble <deobfuscated.js> [program.txt [entries.json]]` reads the program as the
//! `runProgram` argument text (base64); without a file it disassembles the
//! script's own embedded program. A third argument adds entries the program
//! reaches some other way, such as a browser's recorded coverage.

use std::{env, fs};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::script::Source;
use cfsolve::vm::Position;

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let script = arguments
        .next()
        .context("usage: disassemble <deobfuscated.js> [program.txt]")?;
    let text = fs::read_to_string(&script)?;
    let program = match arguments.next() {
        Some(path) => fs::read_to_string(path)?,
        None => {
            let start =
                text.find("runProgram(`").context("no embedded program")? + "runProgram(`".len();
            let end = start + text[start..].find('`').context("unterminated program")?;
            text[start..end].to_owned()
        }
    };
    let program = STANDARD.decode(program.trim())?;
    let source = Source::try_new(&text)?;
    let machine = source.machine()?;
    // A third argument lists more entries, as JSON `[[pc, key], ...]`.
    let mut entries = vec![machine.entry()];
    if let Some(path) = arguments.next() {
        let extra: Vec<(u32, u8)> = serde_json::from_str(&fs::read_to_string(path)?)?;
        entries.extend(extra.into_iter().map(|(pc, key)| Position::new(pc, key)));
    }
    let listing = machine.disassemble_from(&program, &entries, &[])?;
    for instruction in listing.instructions.values() {
        print!("{instruction}");
    }
    for hidden in &listing.hidden {
        println!(
            "hidden {} {:?} -> {}",
            hidden.compare, hidden.string, hidden.target
        );
    }
    for failure in &listing.failures {
        eprintln!("failed at {}:{}: {failure}", failure.pc, failure.key);
    }
    eprintln!(
        "{} instructions, {} functions, {} bytes",
        listing.instructions.len(),
        listing.functions.len(),
        program.len()
    );
    Ok(())
}
