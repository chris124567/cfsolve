//! Parses a challenge script, runs the deobfuscation rewrites in rounds, and prints the result
//! through SWC.

use std::fmt;
use std::sync::Arc;

use anyhow::Result;
use rustc_hash::FxHasher;
use swc::Compiler;
use swc::config::{Config, IsModule, JscConfig, Options};
use swc_core::common::comments::SingleThreadedComments;
use swc_core::common::errors::Handler;
use swc_core::common::{BytePos, FileName, GLOBALS, Globals, Mark, SourceMap};
use swc_core::ecma::ast::{EsVersion, Pass, Program, fn_pass, noop_pass};
use swc_ecma_transforms::optimization::simplify::expr::{self, Config as ExprSimplifierConfig};
use swc_ecma_transforms::{fixer, hygiene};

use super::analysis::Analysis;
use super::{
    HashMap, argument_arrays, arrow_blocks, bitwise, blocks, call_helpers, control_flow,
    copy_propagation, dead_branches, dead_properties, dispatch, encoded_strings, function_lengths,
    helper_objects, int32_helpers, literals, loops, memoized_strings, merged_functions,
    register_arrays, state_machines, statements, static_members, unused_bindings,
};

/// Deobfuscated JavaScript with optional convergence diagnostics for the caller to report.
pub struct Deobfuscated {
    /// JavaScript printed after the rewrites, including partial output if they hit the limit.
    pub text: String,
    /// Diagnostics when rewrites reached the round limit before settling.
    pub unconverged: Option<Unconverged>,
}

/// Applies the same SWC transformations to saved scripts and newly fetched iframe scripts.
pub fn deobfuscate(source: String) -> Result<Deobfuscated> {
    Ok(deobfuscate_with(source, |_, _| ())?.0)
}

/// Deobfuscates `source`, then calls `read` before printing the result. The callback receives
/// the deobfuscated program and the source's starting position. Retained nodes keep their
/// original spans so the callback can locate them in the input.
pub(crate) fn deobfuscate_with<T>(
    source: String,
    read: impl FnMut(&Program, BytePos) -> T,
) -> Result<(Deobfuscated, T)> {
    // Hygiene renames bindings whose references moved into conflicting scopes. It runs last
    // because it clears the syntax contexts the rewrites use.
    run(source, STEPS, hygiene::hygiene, read)
}

/// Calls `read` after normalization and table decoding, which preserve browser-visible
/// structure and positions. Passes the source and its starting position. Returns partial output
/// if decoding does not converge.
pub(crate) fn read_decoded<T>(
    source: String,
    read: impl FnMut(&Program, BytePos) -> Result<T>,
) -> Result<T> {
    run(source, &[DECODE_STEPS], noop_pass, read)?.1
}

/// Runs `steps`, then the pass `finish` returns, then `read`, and prints the result.
fn run<T, P: Pass>(
    source: String,
    steps: &'static [&'static [Step]],
    finish: impl FnOnce() -> P,
    mut read: impl FnMut(&Program, BytePos) -> T,
) -> Result<(Deobfuscated, T)> {
    use anyhow::Context;

    let mut result = None;
    let slot = &mut result;
    let mut unconverged = None;
    let text = transform(source, |start, unresolved_mark| {
        (
            Pipeline {
                steps,
                unconverged: &mut unconverged,
                analysis: Analysis::new(unresolved_mark),
                version: 0,
                unchanged_at: HashMap::default(),
            },
            finish(),
            fn_pass(move |program: &mut Program| *slot = Some(read(program, start))),
        )
    })?;
    let read = result.context("the script was never read")?;
    Ok((Deobfuscated { text, unconverged }, read))
}

/// Parses `source` as a classic script and applies `pass` before printing. The pass receives
/// the source start and the resolver's mark for unresolved references. Disables SWC's early
/// hygiene pass because it would clear syntax contexts needed by the rewrites.
pub(super) fn transform<P: Pass>(
    source: String,
    pass: impl FnOnce(BytePos, Mark) -> P,
) -> Result<String> {
    let source_map: Arc<SourceMap> = Arc::default();
    let handler =
        Handler::with_emitter_writer(Box::new(std::io::stderr()), Some(source_map.clone()));
    let compiler = Compiler::new(source_map.clone());
    let file = source_map.new_source_file(FileName::Custom("challenge.js".into()).into(), source);
    let start = file.start_pos;
    GLOBALS.set(&Globals::new(), || {
        // Marks belong to the globals they are created in.
        let unresolved_mark = Mark::new();
        let options = Options {
            disable_hygiene: true,
            skip_helper_injection: true,
            unresolved_mark: Some(unresolved_mark),
            top_level_mark: Some(Mark::new()),
            config: Config {
                jsc: JscConfig {
                    target: Some(EsVersion::EsNext),
                    ..Default::default()
                },
                is_module: Some(IsModule::Bool(false)),
                ..Default::default()
            },
            ..Default::default()
        };
        let output = compiler.process_js_with_custom_pass(
            file,
            None,
            &handler,
            &options,
            SingleThreadedComments::default(),
            |_| noop_pass(),
            |_| pass(start, unresolved_mark),
        )?;
        Ok(output.code)
    })
}

/// The rounds stopped at their limit while some rewrite still changed the
/// program, so the output may be partially transformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unconverged {
    /// How many rounds ran before the limit stopped them.
    pub rounds: usize,
}

impl fmt::Display for Unconverged {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "deobfuscation stopped after {} rounds without converging; \
             the output may be partially transformed",
            self.rounds
        )
    }
}

/// A named rewrite that reports whether it changed the program. Repeated occurrences share a
/// name. Running any occurrence records that the step has processed the current program.
struct Step {
    name: &'static str,
    rewrite: fn(&mut Program, &mut Analysis) -> bool,
}

const fn step(name: &'static str, rewrite: fn(&mut Program, &mut Analysis) -> bool) -> Step {
    Step { name, rewrite }
}

const SIMPLIFY: Step = step("simplify", simplify);
const STATIC_MEMBERS: Step = step("static members", static_members::run);
const HELPER_OBJECTS: Step = step("helper objects", helper_objects::run);
const CONTROL_FLOW: Step = step("control flow", control_flow::run);
const UNUSED_BINDINGS: Step = step("unused bindings", unused_bindings::run);
const FIX_PARENTHESES: Step = step("fix parentheses", fix_parentheses);

const STEPS: &[&[Step]] = &[DECODE_STEPS, LATER_STEPS];

/// The normalizing and table-recovering steps, which also form the decoding-only pass.
const DECODE_STEPS: &[Step] = &[
    // Normalize.
    SIMPLIFY,
    step("function lengths", function_lengths::run),
    step("bitwise operands", bitwise::run),
    step("dead branches", dead_branches::run),
    // Recover tables.
    step("encoded strings", encoded_strings::run),
    step("memoized strings", memoized_strings::run),
    step("argument arrays", argument_arrays::run),
    step("dispatch", dispatch::run),
];

/// The steps that restructure the script once its tables are decoded.
const LATER_STEPS: &[Step] = &[
    // Restore locals and method calls the obfuscator hides.
    step("register arrays", register_arrays::run),
    step("call helpers", call_helpers::run),
    // Inline call dispatchers first. Splitting merged functions would turn them into forwarders.
    step("call dispatchers", dispatch::run_all),
    step("merged functions", merged_functions::run),
    // Inline helpers, once unused scratch declarations no longer hide their returns.
    UNUSED_BINDINGS,
    STATIC_MEMBERS,
    HELPER_OBJECTS,
    STATIC_MEMBERS,
    SIMPLIFY,
    CONTROL_FLOW,
    step("state machines", state_machines::run),
    step("arrow blocks", arrow_blocks::run),
    // Remove dead helpers.
    HELPER_OBJECTS,
    UNUSED_BINDINGS,
    STATIC_MEMBERS,
    step("dead properties", dead_properties::run),
    SIMPLIFY,
    CONTROL_FLOW,
    // Expand statements.
    step("literals", literals::run),
    step("statements", statements::run),
    FIX_PARENTHESES,
    // Clean up locals. The next round fixes parentheses.
    step("blocks", blocks::run),
    step("loops", loops::run),
    step("copy propagation", copy_propagation::run),
    // Run after copy propagation so the masks are constants.
    step("int32 helpers", int32_helpers::run),
];

/// Guards against rewrites that keep undoing each other.
const MAX_ROUNDS: usize = 10;

/// Runs ordered groups of steps and tracks which have seen the current program. Grouping lets a
/// pass run a prefix of [`STEPS`].
struct Pipeline<'outcome> {
    steps: &'static [&'static [Step]],
    unconverged: &'outcome mut Option<Unconverged>,
    analysis: Analysis,
    /// Program version, incremented after each change.
    version: u64,
    /// Last program version each named step processed without changes.
    unchanged_at: HashMap<&'static str, u64>,
}

impl Pass for Pipeline<'_> {
    fn process(&mut self, program: &mut Program) {
        let mut converged = false;
        let mut rounds = 0;
        while !converged && rounds < MAX_ROUNDS {
            rounds += 1;
            let start = fingerprint(program);
            converged = self.round(program) || fingerprint(program) == start;
        }
        *self.unconverged = (!converged).then_some(Unconverged { rounds });
        // Even without convergence, fix parentheses introduced by the last rewrites so output
        // prints correctly.
        self.run(&FIX_PARENTHESES, program);
    }
}

impl Pipeline<'_> {
    /// Runs the steps in order, stopping early once every step has seen the current program.
    /// Returns whether that happened.
    fn round(&mut self, program: &mut Program) -> bool {
        let steps = self.steps.iter().copied().flatten();
        for step in steps.clone() {
            self.run(step, program);
            if steps.clone().all(|step| self.has_seen(step)) {
                return true;
            }
        }
        false
    }

    /// Whether `step` last ran on this exact program without changing it.
    fn has_seen(&self, step: &Step) -> bool {
        self.unchanged_at.get(step.name) == Some(&self.version)
    }

    /// Runs `step` unless it already ran on this exact program.
    fn run(&mut self, step: &Step, program: &mut Program) {
        if self.has_seen(step) {
            return;
        }
        // Tests check every step's report against the program itself.
        let before = cfg!(test).then(|| fingerprint(program));
        let changed = (step.rewrite)(program, &mut self.analysis);
        if let Some(before) = before {
            assert_eq!(
                changed,
                fingerprint(program) != before,
                "the {} step misreported whether it changed the program",
                step.name
            );
        }
        if changed {
            self.version += 1;
            self.analysis.invalidate();
        } else {
            self.unchanged_at.insert(step.name, self.version);
        }
    }
}

/// Hashes the entire syntax tree, including spans and syntax contexts, to detect unreported
/// changes. For a fixed input word, each FxHash step is reversible, so trees whose encodings
/// differ in exactly one word cannot collide.
fn fingerprint(program: &Program) -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = FxHasher::default();
    program.hash(&mut hasher);
    hasher.finish()
}

/// Folds constant expressions such as `1 + 2`. Compares fingerprints because the simplifier's
/// change flag misses some rewrites, such as single-element sequences.
fn simplify(program: &mut Program, analysis: &mut Analysis) -> bool {
    let before = fingerprint(program);
    expr::expr_simplifier(analysis.globals.mark, ExprSimplifierConfig::default()).process(program);
    fingerprint(program) != before
}

/// Adds parentheses that rewritten expressions need, such as in `x = (a, b)`. SWC's own fixer
/// ran before the rewrites.
fn fix_parentheses(program: &mut Program, _: &mut Analysis) -> bool {
    let before = fingerprint(program);
    fixer::fixer(None).process(program);
    fingerprint(program) != before
}
