//! Structured disassembly snapshots, for comparing VM changes on real sessions.
//!
//! `vm_snapshot <deobfuscated.js> <program.txt|-> [name,...]` prints every
//! instruction, path, function entry, hidden branch and failure of the
//! program, one per line. `-` disassembles the script's embedded program. The
//! optional third argument lists API names to try on hashed branches, as
//! the probe analysis does with `cf-chl-peek`.
//!
//! `vm_snapshot --fixture <deobfuscated.js>` prints just the function that
//! defines the VM, as a script of its own: enough to build a `Machine`.

use std::time::Instant;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::script::Source;
use swc_core::common::{FileName, SourceMap, Spanned};
use swc_core::ecma::ast::{Class, ClassMember, Decl, Expr, Function, Lit, PropName, Stmt};
use swc_core::ecma::parser::{Parser, StringInput, Syntax};
use swc_core::ecma::visit::{Visit, VisitWith};

fn main() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [flag, script] if flag == "--fixture" => fixture(script),
        [script, program, rest @ ..] => snapshot(script, program, rest.first().map(String::as_str)),
        _ => bail!("usage: vm_snapshot <deobfuscated.js> <program.txt|-> [names]"),
    }
}

fn snapshot(path: &str, program: &str, names: Option<&str>) -> Result<()> {
    let source = fs::read_to_string(path)?;
    let text = if program == "-" {
        let start =
            source.find("runProgram(`").context("no embedded program")? + "runProgram(`".len();
        let end = start + source[start..].find('`').context("unterminated program")?;
        source[start..end].to_owned()
    } else {
        fs::read_to_string(program)?
    };
    let program = STANDARD.decode(text.trim())?;
    let names: Vec<&str> = names.map_or_else(Vec::new, |names| names.split(',').collect());

    let source = Source::try_new(&source)?;
    let started = Instant::now();
    let machine = source.machine()?;
    let built = started.elapsed();
    let listing = machine.disassemble_from(&program, &[machine.entry()], &names)?;
    let total = started.elapsed();

    println!("entry {:?}", (machine.entry().pc, machine.entry().key));
    for instruction in listing.instructions.values() {
        println!(
            "instruction {} {} op{}",
            instruction.pc, instruction.key, instruction.opcode
        );
        for path in &instruction.paths {
            println!("  path {:?} -> {:?}", path.conditions, path.exit);
            for effect in &path.effects {
                println!("    {effect:?}");
            }
        }
    }
    // Printed as the tuples these once were, so snapshots stay comparable.
    for function in &listing.functions {
        println!("function {:?}", (function.pc, function.key));
    }
    for hidden in &listing.hidden {
        println!(
            "hidden {:?}",
            (
                hidden.compare,
                &hidden.string,
                (hidden.target.pc, hidden.target.key)
            )
        );
    }
    for failure in &listing.failures {
        println!(
            "failure {:?}",
            (failure.pc, failure.key, failure.to_string())
        );
    }
    eprintln!(
        "{} instructions, {} functions, {} hidden, {} failures; machine {:.3}s, total {:.3}s",
        listing.instructions.len(),
        listing.functions.len(),
        listing.hidden.len(),
        listing.failures.len(),
        built.as_secs_f64(),
        total.as_secs_f64(),
    );
    Ok(())
}

/// The innermost function declaring a class with a `run` method, printed as
/// an immediately invoked expression with nothing else of the script.
fn fixture(path: &str) -> Result<()> {
    let source = fs::read_to_string(path)?;
    let source_map = SourceMap::default();
    let file = source_map.new_source_file(FileName::Custom(path.into()).into(), source.clone());
    let script = Parser::new(Syntax::default(), StringInput::from(&*file), None)
        .parse_script()
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let mut finder = Finder(None);
    script.visit_with(&mut finder);
    let function = finder.0.context("no VM class in the script")?;
    let span = function.span();
    let start = file.start_pos.0;
    let text = &source[(span.lo.0 - start) as usize..(span.hi.0 - start) as usize];
    println!("({text})();");
    Ok(())
}

struct Finder(Option<Function>);

impl Visit for Finder {
    fn visit_function(&mut self, function: &Function) {
        if let Some(body) = &function.body
            && body.stmts.iter().any(|statement| match statement {
                Stmt::Decl(Decl::Class(declaration)) => has_run(&declaration.class),
                _ => false,
            })
        {
            self.0 = Some(function.clone());
        }
        function.visit_children_with(self);
    }
}

fn has_run(class: &Class) -> bool {
    class.body.iter().any(|member| {
        let ClassMember::Method(method) = member else {
            return false;
        };
        match &method.key {
            PropName::Ident(name) => &*name.sym == "run",
            PropName::Str(name) => name.value == *"run",
            PropName::Computed(computed) => {
                matches!(&*computed.expr, Expr::Lit(Lit::Str(name)) if name.value == *"run")
            }
            _ => false,
        }
    })
}
