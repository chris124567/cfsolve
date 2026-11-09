//! Parses a classic challenge script, runs the deobfuscation rewrites in rounds, and prints the
//! result.
//!
//! The decoding steps normalize expressions and recover tables without removing the dispatcher
//! frames that stack extraction needs. The later steps inline helpers and reconstruct control
//! flow.

use std::fmt;

use anyhow::{Result, ensure};
use oxc::allocator::{Allocator, CloneIn, GetAllocator};
use oxc::ast::ast::Program;
use oxc::codegen::{Codegen, CodegenOptions, CommentOptions};
use oxc::parser::{ParseOptions, Parser};
use oxc::semantic::SemanticBuilder;
use oxc::span::{ContentEq, SourceType};

use super::analysis::Analysis;
use super::{
    HashMap, argument_arrays, arrow_blocks, bitwise, blocks, call_helpers, control_flow,
    copy_propagation, dead_branches, dead_properties, dispatch, encoded_strings, function_lengths,
    helper_objects, hygiene, int32_helpers, literals, loops, memoized_strings, merged_functions,
    register_arrays, simplify, state_machines, statements, static_members, unused_bindings,
};
use crate::js::ast::ParsedScript;
use crate::profiling;

/// Rewritten JavaScript and convergence diagnostics.
pub struct Deobfuscated {
    /// Printed JavaScript, which is partially rewritten if the rounds did not converge.
    pub text: String,
    pub unconverged: Option<Unconverged>,
}

/// Rewrites stopped at the round limit while a pass was still changing the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unconverged {
    pub rounds: usize,
}

impl fmt::Display for Unconverged {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "deobfuscation stopped after {} rounds without converging; the output may be partially transformed",
            self.rounds
        )
    }
}

/// Guards against passes that keep undoing each other.
const MAX_ROUNDS: usize = 10;

pub(super) type Rewrite = for<'a> fn(&mut Program<'a>, &mut Analysis<'a>) -> bool;

/// A rewrite and the name that tracks whether it can still change the program. Repeated
/// occurrences of a rewrite share its name.
struct Step {
    name: &'static str,
    rewrite: Rewrite,
}

const fn step(name: &'static str, rewrite: Rewrite) -> Step {
    Step { name, rewrite }
}

const DECODE: &[Step] = &[
    step("simplify", simplify::run),
    step("function lengths", function_lengths::run),
    step("bitwise operands", bitwise::run),
    step("dead branches", dead_branches::run),
    step("encoded strings", encoded_strings::run),
    step("memoized strings", memoized_strings::run),
    step("argument arrays", argument_arrays::run),
    step("dispatch", dispatch::run),
];

const LATER: &[Step] = &[
    step("register arrays", register_arrays::run),
    step("call helpers", call_helpers::run),
    step("call dispatchers", dispatch::run_all),
    step("merged functions", merged_functions::run),
    step("unused bindings", unused_bindings::run),
    step("static members", static_members::run),
    step("helper objects", helper_objects::run),
    step("static members", static_members::run),
    step("simplify", simplify::run),
    step("control flow", control_flow::run),
    step("state machines", state_machines::run),
    step("arrow blocks", arrow_blocks::run),
    step("helper objects", helper_objects::run),
    step("unused bindings", unused_bindings::run),
    step("static members", static_members::run),
    step("dead properties", dead_properties::run),
    step("simplify", simplify::run),
    step("control flow", control_flow::run),
    step("literals", literals::run),
    step("statements", statements::run),
    step("blocks", blocks::run),
    step("loops", loops::run),
    step("copy propagation", copy_propagation::run),
    step("int32 helpers", int32_helpers::run),
];

/// Removing a dead alias can expose another, so these cheap steps settle within each round.
const CLEANUP: &[Step] = &[
    step("unused bindings", unused_bindings::run),
    step("dead properties", dead_properties::run),
];

/// Parses a classic script and resolves its bindings before any rewrite observes them.
pub(super) fn parse<'a>(
    allocator: &'a Allocator,
    source: &'a str,
) -> Result<(Program<'a>, Analysis<'a>)> {
    // Oxc's rewrites and constant evaluator work on expression precedence, not parentheses.
    // Codegen restores the parentheses the tree requires.
    let options = ParseOptions {
        preserve_parens: false,
        ..ParseOptions::default()
    };
    let parsed = Parser::new(allocator, source, SourceType::cjs())
        .with_options(options)
        .parse();
    ensure!(
        parsed.diagnostics.is_empty(),
        "cannot parse challenge.js: {:?}",
        parsed.diagnostics
    );
    let analysis = analyze(allocator, &parsed.program, true)?;
    Ok((parsed.program, analysis))
}

/// Resolves the bindings of a program that parsed without errors. With `check`, also rejects
/// early errors such as redeclarations; copies of a checked program need not repeat it.
fn analyze<'a>(
    allocator: &'a Allocator,
    program: &Program<'a>,
    check: bool,
) -> Result<Analysis<'a>> {
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(check)
        .build(program);
    ensure!(
        semantic.diagnostics.is_empty(),
        "invalid challenge.js: {:?}",
        semantic.diagnostics
    );
    let mut analysis = Analysis::new(allocator, semantic.semantic.into_scoping());
    analysis.refresh(program);
    Ok(analysis)
}

pub(super) fn print(program: &Program<'_>) -> String {
    let options = CodegenOptions {
        comments: CommentOptions::disabled(),
        ..CodegenOptions::default()
    };
    Codegen::new().with_options(options).build(program).code
}

/// Runs a step unless it already left the current program version unchanged.
fn apply<'a>(
    program: &mut Program<'a>,
    analysis: &mut Analysis<'a>,
    step: &Step,
    version: &mut u64,
    unchanged: &mut HashMap<&'static str, u64>,
) -> bool {
    if unchanged.get(step.name) == Some(version) {
        return false;
    }
    let before = cfg!(test).then(|| program.clone_in_with_semantic_ids(analysis.allocator()));
    let started = profiling::start();
    let changed = (step.rewrite)(program, analysis);
    profiling::record(started, || step.name.to_owned());
    if let Some(before) = before {
        assert_eq!(
            changed,
            !program.content_eq(&before),
            "the {} pass misreported whether it changed the program",
            step.name
        )
    }
    if changed {
        *version += 1;
        analysis.refresh(program);
    } else {
        unchanged.insert(step.name, *version);
    }
    changed
}

/// Runs rounds of `steps` until no step changes the tree, a round makes no net printed change,
/// or the round limit is reached. With `cleanup`, each round ends by settling [`CLEANUP`].
fn settle<'a>(
    program: &mut Program<'a>,
    analysis: &mut Analysis<'a>,
    steps: impl Iterator<Item = &'static Step> + Clone,
    cleanup: bool,
) -> Option<Unconverged> {
    let mut unchanged = HashMap::default();
    let mut version = 0;
    for _ in 0..MAX_ROUNDS {
        let before = print(program);
        let mut changed = false;
        for step in steps.clone() {
            changed |= apply(program, analysis, step, &mut version, &mut unchanged);
        }
        if cleanup {
            for _ in 0..MAX_ROUNDS {
                let before = version;
                for step in CLEANUP {
                    changed |= apply(program, analysis, step, &mut version, &mut unchanged);
                }
                if before == version {
                    break;
                }
            }
        }
        if !changed || print(program) == before {
            return None;
        }
    }
    Some(Unconverged { rounds: MAX_ROUNDS })
}

/// Runs every rewrite, then hygiene, and prints the result.
fn rewrite<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> Deobfuscated {
    let unconverged = settle(program, analysis, DECODE.iter().chain(LATER), true);
    hygiene::run(program, analysis);
    Deobfuscated {
        text: print(program),
        unconverged,
    }
}

/// Deobfuscates a classic challenge script.
pub fn deobfuscate(source: String) -> Result<Deobfuscated> {
    let allocator = Allocator::default();
    let (mut program, mut analysis) = parse(&allocator, &source)?;
    let deobfuscated = rewrite(&mut program, &mut analysis);
    profiling::report("deobfuscation");
    Ok(deobfuscated)
}

/// Runs only the decoding steps, which keep dispatcher frames and source positions. Retained
/// spans are byte ranges into `source`.
pub(crate) fn decode(source: String) -> Result<ParsedScript> {
    ParsedScript::build("decoded challenge.js", source, |allocator, source| {
        let (mut program, mut analysis) = parse(allocator, source)?;
        settle(&mut program, &mut analysis, DECODE.iter(), false);
        Ok(program)
    })
}

/// Runs full deobfuscation and returns a decoding-only copy of the tree, as [`decode`] does,
/// without parsing twice. The copy gets its own semantic analysis. `read` sees the fully
/// rewritten tree after hygiene.
pub(crate) fn deobfuscate_capturing<T>(
    source: String,
    read: impl FnOnce(&Program<'_>) -> Result<T>,
) -> Result<(Deobfuscated, T, ParsedScript)> {
    let mut full = None;
    let decoded = ParsedScript::build("decoded challenge.js", source, |owned, source| {
        let allocator = Allocator::default();
        let (mut program, mut analysis) = parse(&allocator, source)?;
        let mut decoded = program.clone_in_with_semantic_ids(owned);
        let mut decoding = analyze(owned, &decoded, false)?;
        settle(&mut decoded, &mut decoding, DECODE.iter(), false);
        let deobfuscated = rewrite(&mut program, &mut analysis);
        full = Some((deobfuscated, read(&program)?));
        Ok(decoded)
    })?;
    let (deobfuscated, result) = full.expect("the build closure ran");
    profiling::report("deobfuscation");
    Ok((deobfuscated, result, decoded))
}
