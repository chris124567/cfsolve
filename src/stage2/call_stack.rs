//! Reconstructs `new Error()` stacks from the original script: the checkbox click's, the stack
//! probe's, and the challenge page's render call.
//!
//! The chain runs from the listener through the VM's runner and run function to the opcode
//! handler that constructs the error. Some builds use the runner directly as listener; others
//! add an arity-specific wrapper. Forwarders, helper-object methods, and selector-based
//! `Reflect.apply` helpers add their own frames. Recovery decodes only the string table,
//! preserving original positions and method keys.
//!
//! V8 names frames by call form, such as `Class.handler` or `HTMLInputElement.<anonymous>`, and
//! uses callee positions. JavaScriptCore names them by definition, leaving many methods
//! anonymous, uses the opening argument parenthesis, and includes native `Reflect.construct`
//! frames. The script is sloppy code, so JavaScriptCore does not eliminate tail calls.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use oxc::ast::AstKind;
use oxc::ast::ast::{
    Argument, ArrayExpression, ArrayExpressionElement, AssignmentExpression, AssignmentTarget,
    BindingPattern, CallExpression, Class, Expression, FormalParameter, Function, MemberExpression,
    MethodDefinition, NewExpression, ObjectExpression, ObjectProperty, ObjectPropertyKind,
    PropertyKind, Statement, SwitchCase, SwitchStatement, ThrowStatement, TryStatement,
    VariableDeclarator,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::SymbolId;
use oxc::span::{GetSpan, Span};
use oxc::syntax::operator::{AssignmentOperator, BinaryOperator, UnaryOperator};
use oxc::syntax::scope::ScopeFlags;
use serde::{Deserialize, Serialize};

use super::syntax::{
    assigned_member, is_optional_call, member, plain_parameter, walk_method, walk_property,
};
use crate::deobfuscate::{self, Deobfuscated};
use crate::engine::{self, Engine, Lines, StackFrame, V8_STACK_LIMIT};
use crate::js::ast::{self, Binding, ParsedScript};
use crate::{candidates, js};

/// Maps VM dispatch cases to opcodes at their original source positions. Deobfuscation resolves
/// case labels while preserving spans. Recovery uses the resolved labels to find each opcode's
/// case in the original script.
#[derive(Clone, Default)]
pub struct CaseOpcodes {
    opcodes: HashMap<Span, u8>,
    /// The decoded program captured during deobfuscation, with the source it was decoded from,
    /// shared so the cases stay cheap to clone.
    decoded: Option<Arc<ParsedScript>>,
}

/// Deobfuscates `source` and maps its dispatch cases' original positions to their opcodes.
pub fn deobfuscate_with_cases(source: String) -> Result<(Deobfuscated, CaseOpcodes)> {
    // Spans are stable across parses of the same script.
    struct Cases(HashMap<Span, u8>);
    impl<'a> Visit<'a> for Cases {
        fn visit_switch_case(&mut self, case: &SwitchCase<'a>) {
            if let Some(test) = &case.test
                && let Some(opcode) = ast::index_literal(test)
                && let Ok(opcode) = u8::try_from(opcode)
            {
                self.0.insert(case.span, opcode);
            }
            walk::walk_switch_case(self, case);
        }
    }
    let (deobfuscated, opcodes, decoded) = deobfuscate::deobfuscate_capturing(source, |program| {
        let mut cases = Cases(HashMap::new());
        cases.visit_program(program);
        Ok(cases.0)
    })?;
    let cases = CaseOpcodes {
        opcodes,
        decoded: Some(Arc::new(decoded)),
    };
    Ok((deobfuscated, cases))
}

/// Engine-specific function name and call position, measured from the script start in
/// zero-based lines and UTF-16 columns.
#[derive(Debug, Serialize)]
pub struct Frame {
    pub function: String,
    pub line: u32,
    pub column: u32,
}

/// The frames of a recovered stack, innermost first.
#[derive(Debug, Serialize)]
pub struct Geometry {
    /// Frame names and positions in V8 format.
    pub frames: Vec<Frame>,
    #[serde(skip)]
    pub jsc_frames: Vec<Frame>,
    /// Whether error construction uses `Reflect.construct`, which adds a JavaScriptCore frame.
    #[serde(skip)]
    pub reflected: bool,
}

/// Where the iframe script starts in its document, in zero-based lines and UTF-16 columns: the
/// origin of every frame's position.
pub struct ScriptPosition {
    pub url: String,
    pub line: u32,
    pub column: u32,
}

impl Geometry {
    /// Formats the stack of an `Error` created in the innermost frame for `engine`.
    #[must_use]
    pub fn format(&self, origin: &ScriptPosition, engine: Engine) -> String {
        let stack = engine.error_stack(self.placed(origin, engine));
        if engine == Engine::WebKit && self.reflected {
            return format!("construct@[native code]\n{stack}");
        }
        stack
    }

    /// The frames for `engine` in the script at `origin`, with one-based positions. Applies the
    /// script's column offset only on its first line.
    pub(crate) fn placed<'a>(
        &'a self,
        origin: &'a ScriptPosition,
        engine: Engine,
    ) -> impl Iterator<Item = StackFrame<'a>> {
        let frames = match engine {
            Engine::Chromium => &self.frames,
            Engine::WebKit => &self.jsc_frames,
        };
        frames.iter().map(|frame| {
            let column = frame.column + if frame.line == 0 { origin.column } else { 0 };
            StackFrame {
                function: &frame.function,
                url: &origin.url,
                line: (origin.line + frame.line + 1) as usize,
                column: (column + 1) as usize,
            }
        })
    }

    /// Returns frames adjusted for a script that starts `lines` lines into the source used for
    /// recovery.
    #[must_use]
    pub(crate) fn rebased(mut self, lines: u32) -> Self {
        let frames = self.frames.iter_mut().chain(&mut self.jsc_frames);
        for frame in frames {
            frame.line = frame.line.saturating_sub(lines);
        }
        self
    }
}

/// A VM function's method call: its opcode, its argument count, and the caller's arity.
#[derive(Clone, Copy, Debug)]
pub struct MethodCall {
    pub opcode: u8,
    pub passed: usize,
    pub arity: usize,
}

/// Call path to `new Error()` in the stack probe. The probe function calls a closure that
/// constructs the error.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ProbeCalls {
    /// The opcode that constructs `new Error()`.
    pub construct: u8,
}

/// The callback that last resumed the VM before the stack probe, whose listener is the probe's
/// outermost frame. Chrome and Safari captures show both; a Worker message is more common.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resumption {
    /// A timer, whose callback receives no arguments. V8 leaves its listener anonymous.
    Timer,
    /// A Worker's message event, which passes the event. V8 names the listener by its
    /// receiver, `Worker.<anonymous>`.
    WorkerMessage,
}

/// Recovers callback frames for a VM function with `arity` parameters and error-construction
/// opcode `construct`.
pub fn recover(source: &str, cases: &CaseOpcodes, construct: u8, arity: usize) -> Result<Geometry> {
    geometry(source, cases, |machine| {
        let mut chain = machine.construction(construct, false)?;
        // A DOM event calls the arity-specific listener directly, when there is one, with the
        // checkbox as receiver.
        if !machine.listeners.is_empty() {
            chain
                .frames
                .extend(machine.listener(arity, "HTMLInputElement.<anonymous>")?);
        }
        Ok(chain)
    })
}

/// Recovers frames for the stack probe, run after `resumed`. The VM executes closures in its
/// dispatch loop without JavaScript calls, so frames stop at the listener that resumed it. V8
/// retains only the innermost ten frames.
pub fn recover_probe(
    source: &str,
    cases: &CaseOpcodes,
    calls: ProbeCalls,
    resumed: Resumption,
) -> Result<Geometry> {
    geometry(source, cases, |machine| {
        // The probe registers an exception handler, so its instructions dispatch from the
        // guarded loop.
        let mut chain = machine.construction(calls.construct, true)?;
        let (arity, name) = match resumed {
            Resumption::Timer => (0, ""),
            Resumption::WorkerMessage => (1, "Worker.<anonymous>"),
        };
        chain.frames.extend(machine.listener(arity, name)?);
        chain.frames.truncate(V8_STACK_LIMIT);
        Ok(chain)
    })
}

/// Recovers the stack outside a native method called by a VM function, from the method call to
/// the listener. Closure-factory listeners are anonymous. Uses the guarded dispatch loop when
/// an exception handler is registered, including calls made by the program itself under a
/// handler.
pub fn recover_method_call(
    source: &str,
    cases: &CaseOpcodes,
    call: MethodCall,
    guarded: bool,
) -> Result<Geometry> {
    geometry(source, cases, |machine| {
        let mut frames = machine.method_call(call.opcode, call.passed, guarded)?;
        frames.extend(machine.listener(call.arity, "")?);
        Ok(Chain {
            frames,
            reflected: false,
        })
    })
}

/// Dispatch loop called by the run function, with details used to check stack recovery offline.
#[derive(Debug, Serialize)]
pub struct DispatchSummary {
    pub function: String,
    pub guarded: bool,
    /// V8 frames from the dispatch loop to the run function, innermost first.
    pub frames: Vec<String>,
    /// Number of opcodes dispatched by the loop.
    pub opcodes: usize,
    /// Opcodes whose cases do not call a function defined in the script.
    pub unresolved: Vec<u8>,
}

/// Summarizes dispatch loops called by the run function, including whether each case resolves to
/// a function.
pub fn dispatch_summary(source: &str, cases: &CaseOpcodes) -> Result<Vec<DispatchSummary>> {
    let decoded = deobfuscate::decode(source.to_owned())?;
    let machine = Machine::new(decoded.script(), cases)?;
    let script = &machine.script;
    let mut summaries = Vec::new();
    for dispatch_loop in &machine.loops {
        let name = script.appliers.name(dispatch_loop.name);
        let function = script.function(dispatch_loop.name)?;
        let scope = Scope::new(name, &function, &script.appliers);
        let mut opcodes = 0;
        let mut unresolved = Vec::new();
        for case in cases_of(script.js(), &function) {
            let Some(&opcode) = cases.opcodes.get(&case.span) else {
                continue;
            };
            opcodes += 1;
            let resolved = scope.target(case.call).is_ok_and(|target| {
                target
                    .callee
                    .is_some_and(|callee| script.function(callee).is_ok())
            });
            if !resolved {
                unresolved.push(opcode);
            }
        }
        let frames = dispatch_loop.call.frames(machine.run.frame());
        summaries.push(DispatchSummary {
            function: name.to_owned(),
            guarded: dispatch_loop.guarded,
            frames: frames.into_iter().map(|call| call.name.v8).collect(),
            opcodes,
            unresolved,
        });
    }
    Ok(summaries)
}

/// Parses `source` and places the frames `recover` finds in it as each engine reports them.
fn geometry(
    source: &str,
    cases: &CaseOpcodes,
    recover: impl FnOnce(&Machine<'_, '_>) -> Result<Chain>,
) -> Result<Geometry> {
    // Reuse the decoded program `cases` captured if it comes from the same source.
    let Chain { frames, reflected } = match &cases.decoded {
        Some(decoded) if decoded.script().source == source => {
            recover(&Machine::new(decoded.script(), cases)?)?
        }
        _ => recover(&Machine::new(
            deobfuscate::decode(source.to_owned())?.script(),
            cases,
        )?)?,
    };
    let frame = |function: String, at: u32| -> Result<Frame> {
        let prefix = source
            .get(..at as usize)
            .context("invalid source byte offset")?;
        let (line, column) = engine::line_and_column(prefix, Lines::Script);
        Ok(Frame {
            function,
            line,
            column,
        })
    };
    let mut geometry = Geometry {
        frames: Vec::new(),
        jsc_frames: Vec::new(),
        reflected,
    };
    for Call { name, site } in frames {
        geometry.frames.push(frame(name.v8, site.v8)?);
        geometry.jsc_frames.push(frame(name.jsc, site.jsc)?);
    }
    Ok(geometry)
}

/// Calls recovered from the innermost frame outward.
struct Chain {
    frames: Vec<Call>,
    /// Whether the error is built with `Reflect.construct`, which adds a JavaScriptCore frame.
    reflected: bool,
}

/// A function as each engine names its frame.
#[derive(Clone, Debug)]
struct Name {
    v8: String,
    jsc: String,
}

impl Name {
    fn same(name: String) -> Self {
        Self {
            v8: name.clone(),
            jsc: name,
        }
    }

    /// A function named by its call form in V8 and left anonymous in JavaScriptCore.
    fn anonymous(v8: String) -> Self {
        Self {
            v8,
            jsc: String::new(),
        }
    }
}

/// A call site's byte offset for each engine: see [`call_position`] and
/// [`arguments_position`].
#[derive(Clone, Copy, Debug)]
struct Site {
    v8: u32,
    jsc: u32,
}

impl Site {
    fn new(call: &CallExpression<'_>) -> Self {
        Self {
            v8: call_position(call),
            jsc: arguments_position(call),
        }
    }
}

#[derive(Clone, Debug)]
struct Call {
    name: Name,
    site: Site,
}

/// A function that call resolution identifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Callee<'a> {
    /// A function or value held by a binding, or by a global.
    Binding(Binding<'a>),
    /// An original function extracted from a merged function, indexed into
    /// [`Appliers::originals`].
    Original(usize),
}

impl Callee<'_> {
    /// The parameter or local `symbol`.
    fn symbol(symbol: SymbolId) -> Self {
        Self::Binding(Binding::Symbol(symbol))
    }
}

/// The VM's run function, the closure runner that calls it, and listeners that wrap the closure
/// runner for each closure parameter count.
struct Machine<'a, 'cases> {
    script: Script<'a>,
    run: RunFunction<'a>,
    /// The dispatch loops the run function calls.
    loops: Vec<DispatchLoop<'a>>,
    cases: &'cases CaseOpcodes,
    /// Frames from the call to the run function out to the closure runner, innermost first.
    runner: Vec<Call>,
    listeners: Vec<Invocation<'a>>,
}

impl<'a, 'cases> Machine<'a, 'cases> {
    fn new(js: ast::Script<'a>, cases: &'cases CaseOpcodes) -> Result<Self> {
        let script = Script::new(js);
        let run = RunFunction::installed(&script)?;
        // The closure runner passes the machine and the closure's program counter, key, and
        // arguments to the run function, copying arguments when required by the VM function.
        let mut runners = Vec::new();
        for (name, function) in &script.functions {
            let caller = Callee::Binding(*name);
            let caller_name = script.appliers.name(caller);
            let scope = Scope::new(caller_name, function, &script.appliers);
            for call in calls_of(js, function) {
                let Ok(target) = scope.target(call) else {
                    continue;
                };
                if target.callee == Some(run.name)
                    && let Some(handed) = handed(Arguments::of(call), &target)
                    && let [_, _, _, Operand::Expression(cells)] = handed[..]
                    && matches!(
                        cells.without_parentheses(),
                        Expression::ConditionalExpression(_)
                    )
                {
                    runners.push((caller, target.frames(Name::same(caller_name.to_owned()))));
                }
            }
        }
        let (runner, runner_frames) =
            candidates::exactly_one(runners, "closure-to-VM runner call")?;
        let mut listeners = Listeners {
            runner,
            appliers: &script.appliers,
            found: Vec::new(),
        };
        listeners.visit_program(js.program);
        let listeners: Vec<Invocation> = listeners.found.into_iter().collect::<Result<_>>()?;
        let loops = dispatch_loops(&script, &run);
        if loops.is_empty() {
            bail!("the run function calls no dispatch loop");
        }
        Ok(Self {
            runner: runner_frames,
            listeners,
            run,
            loops,
            script,
            cases,
        })
    }

    /// Finds the handler for `opcode` in the dispatch loop with or without exception handling.
    fn handler(&self, opcode: u8, guarded: bool) -> Result<Handler<'a, '_>> {
        let appliers = &self.script.appliers;
        for dispatch_loop in &self.loops {
            if dispatch_loop.guarded != guarded {
                continue;
            }
            let function = self.script.function(dispatch_loop.name)?;
            let Some(case) = cases_of(self.script.js(), &function)
                .into_iter()
                .find(|case| self.cases.opcodes.get(&case.span) == Some(&opcode))
            else {
                continue;
            };
            let scope = Scope::new(appliers.name(dispatch_loop.name), &function, appliers);
            let dispatch = scope.target(case.call)?;
            let handler = dispatch
                .callee
                .with_context(|| format!("opcode {opcode}'s dispatch calls no named handler"))?;
            let name = appliers.name(handler);
            let frame = Name {
                v8: if dispatch.method {
                    format!("{}.{name}", self.run.class)
                } else {
                    name.to_owned()
                },
                jsc: name.to_owned(),
            };
            return Ok(Handler {
                dispatch,
                name: handler,
                frame,
                dispatch_loop,
            });
        }
        bail!("no dispatch of opcode {opcode} (guarded: {guarded})")
    }

    /// Appends frames from the call to `handler` through the dispatch loop, the run function, and
    /// the closure runner.
    fn entered(&self, handler: &Handler<'a, '_>, mut frames: Vec<Call>) -> Vec<Call> {
        let dispatch_loop = handler.dispatch_loop;
        let name = self.script.appliers.name(dispatch_loop.name);
        frames.extend(handler.dispatch.frames(Name::same(name.to_owned())));
        frames.extend(dispatch_loop.call.frames(self.run.frame()));
        frames.extend(self.runner.iter().cloned());
        frames
    }

    /// Returns frames from error construction through the opcode handler to the runner. Uses the
    /// single construction site in the handler, preferring `Reflect.construct` over `new` without
    /// arguments.
    fn construction(&self, opcode: u8, guarded: bool) -> Result<Chain> {
        let handler = self.handler(opcode, guarded)?;
        let appliers = &self.script.appliers;
        let function = self.script.function(handler.name)?;
        let scope = Scope::new(appliers.name(handler.name), &function, appliers);
        let mut found = Vec::new();
        for call in calls_of(self.script.js(), &function) {
            let target = scope.target(call)?;
            // Find `Reflect.construct` in a binding or array slot, called directly or through a
            // helper.
            let named = target
                .callee
                .is_some_and(|callee| self.script.constructs.contains(&callee));
            let slotted = target
                .slot
                .is_some_and(|slot| self.script.construct_slots.contains(&slot));
            if named || slotted {
                found.push(target.frames(handler.frame.clone()));
            }
        }
        let reflected = !found.is_empty();
        if !reflected {
            #[derive(Default)]
            struct News(Vec<Site>);
            impl<'a> Visit<'a> for News {
                fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
                fn visit_class(&mut self, _: &Class<'a>) {}
                fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
                    walk_property(self, property);
                }
                // Ignore guard exceptions; they do not produce the handler's constructed value.
                fn visit_throw_statement(&mut self, _: &ThrowStatement<'a>) {}
                fn visit_new_expression(&mut self, construction: &NewExpression<'a>) {
                    if construction.arguments.is_empty() {
                        self.0.push(Site {
                            v8: construction.span.start,
                            jsc: construction.callee.span().end,
                        });
                    }
                    walk::walk_new_expression(self, construction);
                }
            }
            let mut news = News::default();
            function.visit(&mut news);
            for site in news.0 {
                found.push(vec![Call {
                    name: handler.frame.clone(),
                    site,
                }]);
            }
        }
        if found.len() > 1 {
            bail!("a constructor handler constructs in several places");
        }
        let Some(frames) = found.pop() else {
            bail!(
                "missing original function {} with the needed shape",
                appliers.name(handler.name)
            );
        };
        Ok(Chain {
            frames: self.entered(&handler, frames),
            reflected,
        })
    }

    /// Recovers frames from a method call in `opcode`'s handler through the runner: the handler
    /// passes the method, receiver, and `passed` arguments to a native apply forwarder.
    fn method_call(&self, opcode: u8, passed: usize, guarded: bool) -> Result<Vec<Call>> {
        let handler = self.handler(opcode, guarded)?;
        let appliers = &self.script.appliers;
        let function = self.script.function(handler.name)?;
        let scope = Scope::new(appliers.name(handler.name), &function, appliers);
        let mut calls = Vec::new();
        for call in calls_of(self.script.js(), &function) {
            let target = scope.target(call)?;
            if target.passed == Some(passed + 2)
                && let Some(callee) = target.callee
                && let Some(inner) = self.script.method_forwarder(callee)
            {
                calls.push((inner, target));
            }
        }
        let (mut frames, target) =
            candidates::exactly_one(calls, "method call in the call handler")?;
        frames.extend(target.frames(handler.frame.clone()));
        Ok(self.entered(&handler, frames))
    }

    /// The frames of the listener that wraps the runner for closures of `arity` parameters.
    fn listener(&self, arity: usize, name: &str) -> Result<Vec<Call>> {
        let listeners: Vec<&Invocation> = self
            .listeners
            .iter()
            .filter(|target| target.passed == Some(arity))
            .collect();
        let sites: Vec<u32> = listeners.iter().map(|target| target.site.v8).collect();
        let listener = candidates::exactly_one(listeners, "listener of the closure's arity")
            .with_context(|| {
                format!("no one listener for a closure of {arity} arguments, at {sites:?}")
            })?;
        Ok(listener.frames(Name::anonymous(name.to_owned())))
    }
}

/// The function a dispatch loop calls for an opcode.
struct Handler<'a, 'machine> {
    /// Call from the dispatch loop to this handler.
    dispatch: Invocation<'a>,
    name: Callee<'a>,
    frame: Name,
    dispatch_loop: &'machine DispatchLoop<'a>,
}

/// Function called by the run function with the machine to dispatch opcodes.
struct DispatchLoop<'a> {
    name: Callee<'a>,
    /// Call from the run function, either direct or through a helper.
    call: Invocation<'a>,
    /// Whether the call occurs in a `try` block that handles exceptions.
    guarded: bool,
}

/// Minimum case count for a dispatch switch. Dispatchers have a case per opcode, more than any
/// helper switch.
const DISPATCH_CASES: usize = 40;

/// Finds functions with dispatch switches that the run function calls with the machine.
fn dispatch_loops<'a>(script: &Script<'a>, run: &RunFunction<'a>) -> Vec<DispatchLoop<'a>> {
    struct Calls<'a> {
        js: ast::Script<'a>,
        machine: SymbolId,
        found: Vec<(&'a CallExpression<'a>, bool)>,
        guarded: bool,
    }
    impl<'a> Visit<'a> for Calls<'a> {
        fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
        fn visit_class(&mut self, _: &Class<'a>) {}
        fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
            walk_property(self, property);
        }
        // Only a `try` with a `catch` handles exceptions.
        fn visit_try_statement(&mut self, statement: &TryStatement<'a>) {
            let outer = self.guarded;
            self.guarded |= statement.handler.is_some();
            self.visit_block_statement(&statement.block);
            self.guarded = outer;
            if let Some(handler) = &statement.handler {
                self.visit_catch_clause(handler);
            }
            if let Some(finalizer) = &statement.finalizer {
                self.visit_block_statement(finalizer);
            }
        }
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            if !is_optional_call(call)
                && call.arguments.iter().any(|argument| {
                    self.js
                        .refers_to(ast::argument_expression(argument), self.machine)
                })
            {
                let call = self.js.lend(call, AstKind::as_call_expression);
                self.found.push((call, self.guarded));
            }
            walk::walk_call_expression(self, call);
        }
    }
    let mut calls = Calls {
        js: script.js(),
        machine: run.machine,
        found: Vec::new(),
        guarded: false,
    };
    run.body.visit(&mut calls);
    let scope = Scope::new(run.frame_name, &run.body, &script.appliers);
    calls
        .found
        .into_iter()
        .filter_map(|(call, guarded)| {
            let call = scope.target(call).ok()?;
            let name = call.callee?;
            let function = script.function(name).ok()?;
            (cases_of(script.js(), &function).len() > DISPATCH_CASES).then_some(DispatchLoop {
                name,
                call,
                guarded,
            })
        })
        .collect()
}

/// A function's parameters and statements. An original function extracted from a merged
/// function has the merged function's parameters after the selector and its case's statements.
#[derive(Clone, Copy)]
struct Body<'a> {
    parameters: &'a [FormalParameter<'a>],
    /// Whether a rest parameter follows `parameters`.
    rest: bool,
    /// Whether the body starts with a directive prologue, which no statement pattern accepts.
    prologue: bool,
    /// The statements, in two parts so that an original function can join its case block to the
    /// statements after it.
    head: &'a [Statement<'a>],
    tail: &'a [Statement<'a>],
}

impl<'a> Body<'a> {
    fn of(function: &'a Function<'a>) -> Self {
        let (prologue, head) = match &function.body {
            Some(body) => (!body.directives.is_empty(), &body.statements[..]),
            None => (false, &[][..]),
        };
        Self {
            parameters: &function.params.items,
            rest: function.params.rest.is_some(),
            prologue,
            head,
            tail: &[],
        }
    }

    fn statements(&self) -> impl DoubleEndedIterator<Item = &'a Statement<'a>> + Clone + use<'a> {
        self.head.iter().chain(self.tail)
    }

    /// The statements of a body without a directive prologue.
    fn plain_statements(
        &self,
    ) -> Option<impl DoubleEndedIterator<Item = &'a Statement<'a>> + Clone + use<'a>> {
        (!self.prologue).then(|| self.statements())
    }

    /// The only statement after leading local declarations without initializers.
    fn only_statement(&self) -> Option<&'a Statement<'a>> {
        let mut rest = self.plain_statements()?.skip_while(|statement| {
            matches!(statement, Statement::VariableDeclaration(declaration)
                if !declaration.kind.is_using()
                    && declaration.declarations.iter().all(|declarator| declarator.init.is_none()))
        });
        let only = rest.next()?;
        rest.next().is_none().then_some(only)
    }

    /// The bindings of the parameters, if they are all plain names.
    fn parameters(&self) -> Option<Vec<SymbolId>> {
        if self.rest {
            return None;
        }
        self.parameters.iter().map(plain_parameter).collect()
    }

    fn visit(&self, visitor: &mut impl Visit<'a>) {
        for statement in self.statements() {
            visitor.visit_statement(statement);
        }
    }
}

/// The script's declared and assigned functions, and aliases for `Reflect.construct` and
/// `Reflect.apply`.
struct Script<'a> {
    functions: Vec<(Binding<'a>, Body<'a>)>,
    constructs: Vec<Callee<'a>>,
    /// Array slots containing `Reflect.construct`, indexed by array and slot.
    construct_slots: Vec<(Binding<'a>, usize)>,
    applies: Vec<Callee<'a>>,
    /// Array slots containing `Reflect.apply`, indexed by array and slot.
    apply_slots: Vec<(Binding<'a>, usize)>,
    appliers: Appliers<'a>,
}

/// An original function extracted from a merged function. See [`merged`].
struct Original<'a> {
    /// The merged function's name, which frames of the original use.
    name: &'a str,
    body: Body<'a>,
}

/// Call helpers indexed by callee, including selector-based helpers, merged functions, and
/// forwarders. Also records numeric constants used by selectors.
struct Appliers<'a> {
    helpers: HashMap<Callee<'a>, Selection<Site>>,
    /// Merged functions, selecting originals indexed into `originals`.
    merged: HashMap<Binding<'a>, Selection<usize>>,
    /// Original functions extracted from merged functions.
    originals: Vec<Original<'a>>,
    forwarders: Forwarders<'a>,
    constants: Constants<'a>,
}

/// Bindings assigned a numeric value once, such as a shared case-label mask, and the script
/// that binds them.
struct Constants<'a> {
    js: ast::Script<'a>,
    values: HashMap<SymbolId, f64>,
}

impl<'a> Constants<'a> {
    fn new(js: ast::Script<'a>) -> Self {
        let mut values = HashMap::new();
        let mut assigned = HashSet::new();
        for node in js.nodes.iter() {
            match node.kind() {
                AstKind::VariableDeclarator(declarator) => {
                    if let BindingPattern::BindingIdentifier(name) = &declarator.id
                        && let Some(value) = declarator
                            .init
                            .as_ref()
                            .and_then(|init| ast::fold_number(init, &|_| None))
                    {
                        values.insert(name.symbol_id(), value);
                    }
                }
                AstKind::AssignmentExpression(assignment) => {
                    if let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left
                        && let Some(symbol) = js.symbol(name)
                    {
                        assigned.insert(symbol);
                    }
                }
                _ => {}
            }
        }
        values.retain(|symbol, _| !assigned.contains(symbol));
        Self { js, values }
    }

    /// The function or value `expression` names.
    fn binding(&self, expression: &Expression<'a>) -> Option<Binding<'a>> {
        match expression.without_parentheses() {
            Expression::Identifier(reference) => Some(self.js.binding(reference)),
            _ => None,
        }
    }
}

/// Functions that call their first parameter with the remaining parameters, as recorded by
/// [`Scope`].
#[derive(Default)]
struct Forwarders<'a> {
    /// Forwarders indexed by the binding holding their object and their property key.
    on_objects: HashMap<(Holder<'a>, &'a str), Forwarder>,
    /// Forwarders copied to bindings, as in `f = object.key`, with the frames produced when called
    /// through those bindings.
    held: HashMap<Holder<'a>, Vec<Call>>,
}

impl<'a> Forwarders<'a> {
    /// Keeps only forwarders whose object bindings are assigned once, so their values are known.
    fn retain_assigned_once(&mut self, assigned: &HashMap<Holder<'a>, usize>) {
        let once = |holder: &Holder| assigned.get(holder).is_none_or(|&count| count == 1);
        self.on_objects.retain(|(holder, _), _| once(holder));
        self.held.retain(|holder, _| once(holder));
    }
}

impl<'a> Appliers<'a> {
    fn new(js: ast::Script<'a>, functions: &[(Binding<'a>, Body<'a>)]) -> Self {
        let constants = Constants::new(js);
        let mut helpers: HashMap<Callee<'a>, Selection<Site>> = functions
            .iter()
            .filter_map(|(name, function)| {
                Some((Callee::Binding(*name), applier(function, &constants)?))
            })
            .collect();
        let mut merged_functions = HashMap::new();
        let mut originals = Vec::new();
        for (name, function) in functions {
            if !helpers.contains_key(&Callee::Binding(*name))
                && let Some(Selection { mask, cases }) = merged(function, &constants)
            {
                let mut indexed = Vec::new();
                for (label, body) in cases {
                    indexed.push((label, originals.len()));
                    originals.push(Original {
                        name: js.name(*name),
                        body,
                    });
                }
                merged_functions.insert(
                    *name,
                    Selection {
                        mask,
                        cases: indexed,
                    },
                );
            }
        }
        // A merged function may hold call helpers.
        for (index, original) in originals.iter().enumerate() {
            if let Some(helper) = applier(&original.body, &constants) {
                helpers.insert(Callee::Original(index), helper);
            }
        }
        let mut appliers = Self {
            helpers,
            merged: merged_functions,
            originals,
            forwarders: Forwarders::default(),
            constants,
        };
        appliers.forwarders = forwarders(&appliers);
        appliers
    }

    fn js(&self) -> ast::Script<'a> {
        self.constants.js
    }

    /// The name of `callee` in the source. An original function has its merged function's name.
    fn name(&self, callee: Callee<'a>) -> &'a str {
        match callee {
            Callee::Binding(binding) => self.js().name(binding),
            Callee::Original(index) => self.originals[index].name,
        }
    }

    /// Evaluates `operand` using numeric literals and known constants.
    fn number(&self, operand: Operand<'a>) -> Option<f64> {
        match operand {
            Operand::Expression(expression) => number(expression, &self.constants),
            Operand::Resolved(Callee::Binding(Binding::Symbol(symbol))) => {
                self.constants.values.get(&symbol).copied()
            }
            Operand::Resolved(_) => None,
        }
    }
}

/// Collects forwarders from each function via [`Scope`]. Keeps only those whose object bindings are
/// assigned once.
fn forwarders<'a>(appliers: &Appliers<'a>) -> Forwarders<'a> {
    struct Collect<'a, 's> {
        appliers: &'s Appliers<'a>,
        found: Forwarders<'a>,
        assigned: HashMap<Holder<'a>, usize>,
    }
    impl<'a> Visit<'a> for Collect<'a, '_> {
        fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
            let function = self.appliers.js().lend(function, AstKind::as_function);
            let name = function.id.as_ref().map_or("", |name| name.name.as_str());
            let scope = Scope::new(name, &Body::of(function), self.appliers);
            self.found.on_objects.extend(scope.forwarders.on_objects);
            self.found.held.extend(scope.forwarders.held);
            for (holder, count) in scope.assigned {
                *self.assigned.entry(holder).or_default() += count;
            }
            walk::walk_function(self, function, flags);
        }
        fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
            walk_property(self, property);
        }
        fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
            walk_method(self, method);
        }
    }
    let mut collect = Collect {
        appliers,
        found: Forwarders::default(),
        assigned: HashMap::new(),
    };
    collect.visit_program(appliers.js().program);
    collect.found.retain_assigned_once(&collect.assigned);
    collect.found
}

/// Evaluates `expression` using literals and `constants`.
fn number<'a>(expression: &Expression<'a>, constants: &Constants<'a>) -> Option<f64> {
    ast::fold_number(expression, &|leaf| match leaf {
        Expression::Identifier(reference) => constants
            .values
            .get(&constants.js.symbol(reference)?)
            .copied(),
        _ => None,
    })
}

/// The VM's run function, which calls the dispatch loops. The program runner installs it as
/// `<global>.<name> = function(p) { return <run>(new <Class>(p), pc, key, []); }`, possibly
/// calling it through a helper.
struct RunFunction<'a> {
    /// The VM class, which V8 names handlers called as methods of the machine after.
    class: &'a str,
    name: Callee<'a>,
    /// The run function's name in the source, which both engines name its frame after.
    frame_name: &'a str,
    body: Body<'a>,
    /// The parameter receiving the machine.
    machine: SymbolId,
}

impl<'a> RunFunction<'a> {
    /// Finds the run function from the one program runner.
    fn installed(script: &Script<'a>) -> Result<Self> {
        let js = script.js();
        let mut found = Vec::new();
        for function in js.functions() {
            let body = Body::of(function);
            let Some(Statement::ReturnStatement(returned)) = body.only_statement() else {
                continue;
            };
            let Some(Expression::CallExpression(call)) = &returned.argument else {
                continue;
            };
            let Ok(target) = Scope::new("", &body, &script.appliers).target(call) else {
                continue;
            };
            if let Some(name) = target.callee
                && let Some(handed) = handed(Arguments::of(call), &target)
                && let [
                    Operand::Expression(machine),
                    _,
                    _,
                    Operand::Expression(cells),
                ] = handed[..]
                && let Expression::NewExpression(machine) = machine.without_parentheses()
                && let Expression::Identifier(class) = &machine.callee
                && array(cells).is_some_and(|cells| cells.elements.is_empty())
            {
                found.push((name, class.name.as_str()));
            }
        }
        let (name, class) = candidates::exactly_one(found, "program runner")?;
        let body = script.function(name)?;
        let machine = body
            .parameters()
            .and_then(|parameters| parameters.first().copied())
            .context("the run function takes no machine")?;
        Ok(Self {
            class,
            name,
            frame_name: script.appliers.name(name),
            body,
            machine,
        })
    }

    /// The run function's frame.
    fn frame(&self) -> Name {
        Name::same(self.frame_name.to_owned())
    }
}

impl<'a> Script<'a> {
    fn new(js: ast::Script<'a>) -> Self {
        // Semantic analysis gives equal names in different lexical scopes distinct bindings,
        // while frame names keep their original spelling.
        let functions: Vec<(Binding<'a>, Body<'a>)> = js
            .named_functions()
            .into_iter()
            .map(|(name, function)| (name, Body::of(function)))
            .collect();
        let appliers = Appliers::new(js, &functions);
        let mut script = Self {
            functions,
            constructs: Vec::new(),
            construct_slots: Vec::new(),
            applies: Vec::new(),
            apply_slots: Vec::new(),
            appliers,
        };
        for node in js.nodes.iter() {
            if let AstKind::AssignmentExpression(assignment) = node.kind() {
                script.assignment(assignment);
            }
        }
        script
    }

    fn js(&self) -> ast::Script<'a> {
        self.appliers.js()
    }

    /// Tracks `Reflect.construct` and `Reflect.apply` in bindings or array slots, including
    /// indirect references to `Reflect`. Each assignment in a chain records its own target.
    fn assignment(&mut self, assignment: &'a AssignmentExpression<'a>) {
        let js = self.js();
        let mut value = &assignment.right;
        while let Expression::AssignmentExpression(inner) = value.without_parentheses() {
            value = &inner.right;
        }
        let Some(member) = member(value.without_parentheses()) else {
            return;
        };
        let method = ast::member_str(member);
        if let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left {
            let name = Callee::Binding(js.binding(name));
            match method {
                Some("construct") => self.constructs.push(name),
                Some("apply") => self.applies.push(name),
                _ => {}
            }
        }
        if let Some(MemberExpression::ComputedMemberExpression(slot)) =
            assigned_member(&assignment.left)
            && let Expression::Identifier(array) = &slot.object
            && let Some(index) =
                number(&slot.expression, &self.appliers.constants).and_then(ast::array_index)
        {
            let slot = (js.binding(array), index);
            match method {
                Some("construct") => self.construct_slots.push(slot),
                Some("apply") => self.apply_slots.push(slot),
                _ => {}
            }
        }
    }

    fn function(&self, callee: Callee<'a>) -> Result<Body<'a>> {
        match callee {
            Callee::Binding(binding) => self
                .functions
                .iter()
                .find(|(name, _)| *name == binding)
                .map(|(_, function)| *function),
            Callee::Original(index) => self
                .appliers
                .originals
                .get(index)
                .map(|original| original.body),
        }
        .with_context(|| format!("missing original function {}", self.appliers.name(callee)))
    }

    /// Returns frames for the function `callee` if it forwards a method call. Allows local
    /// variable declarations before the return.
    fn method_forwarder(&self, callee: Callee<'a>) -> Option<Vec<Call>> {
        let function = self.function(callee).ok()?;
        let parameters = function.parameters()?;
        let [method, receiver, ..] = parameters.as_slice() else {
            return None;
        };
        let mut statements = function.plain_statements()?;
        let Statement::ReturnStatement(returned) = statements.next_back()? else {
            return None;
        };
        if !statements.all(|statement| {
            matches!(statement, Statement::VariableDeclaration(declaration)
                if !declaration.kind.is_using())
        }) {
            return None;
        }
        let mut value = returned.argument.as_ref()?.without_parentheses();
        if let Expression::SequenceExpression(sequence) = value {
            value = sequence.expressions.last()?.without_parentheses();
        }
        let Expression::CallExpression(call) = value else {
            return None;
        };
        let name = self.appliers.name(callee);
        let target = Scope::new(name, &function, &self.appliers)
            .target(call)
            .ok()?;
        // Compare bindings so a nested function with the same name as a native apply
        // alias cannot be mistaken for that alias. Some builds keep the alias in an array slot.
        let native = match (target.callee, target.slot) {
            (Some(callee), _) => self.function(callee).is_err() || self.applies.contains(&callee),
            (None, Some(slot)) => self.apply_slots.contains(&slot),
            (None, None) => false,
        };
        if !native {
            return None;
        }
        let [first, second, ..] = handed(Arguments::of(call), &target)?[..] else {
            return None;
        };
        let constants = &self.appliers.constants;
        (first.callee(constants) == Some(Callee::symbol(*method))
            && second.callee(constants) == Some(Callee::symbol(*receiver)))
        .then(|| target.frames(Name::same(name.to_owned())))
    }
}

/// A call argument as call resolution reads it.
#[derive(Clone, Copy)]
enum Operand<'a> {
    Expression(&'a Expression<'a>),
    /// A function resolved without an expression that names it: a binding a forwarder reads back
    /// from an array copy, or an original function selected from a merged function.
    Resolved(Callee<'a>),
}

impl<'a> Operand<'a> {
    /// The function or value the operand names.
    fn callee(self, constants: &Constants<'a>) -> Option<Callee<'a>> {
        match self {
            Self::Expression(expression) => constants.binding(expression).map(Callee::Binding),
            Self::Resolved(callee) => Some(callee),
        }
    }
}

/// A call's arguments. In a forwarder, `copies` resolves arguments read back from array copies,
/// at the top level and in array literals.
#[derive(Clone, Copy)]
struct Arguments<'a, 'c> {
    list: &'a [Argument<'a>],
    copies: Option<&'c Copies<'a, 'c>>,
}

impl<'a, 'c> Arguments<'a, 'c> {
    fn of(call: &'a CallExpression<'a>) -> Self {
        Self {
            list: &call.arguments,
            copies: None,
        }
    }

    /// Reads an argument, resolving it through the copies unless it is an array literal.
    fn argument(&self, argument: &'a Argument<'a>) -> Operand<'a> {
        let expression = ast::argument_expression(argument);
        if let Some(copies) = self.copies
            && !matches!(
                expression.without_parentheses(),
                Expression::ArrayExpression(_)
            )
            && let Some(binding) = copies.resolve(expression)
        {
            return Operand::Resolved(Callee::Binding(binding));
        }
        Operand::Expression(expression)
    }

    /// Reads an array element, or `None` for a hole.
    fn element(&self, element: &'a ArrayExpressionElement<'a>) -> Option<Operand<'a>> {
        let expression = element_expression(element)?;
        Some(
            match self.copies.and_then(|copies| copies.resolve(expression)) {
                Some(binding) => Operand::Resolved(Callee::Binding(binding)),
                None => Operand::Expression(expression),
            },
        )
    }
}

/// The expression an array element holds, ignoring a spread, or `None` for a hole.
fn element_expression<'b, 'a>(
    element: &'b ArrayExpressionElement<'a>,
) -> Option<&'b Expression<'a>> {
    match element {
        ArrayExpressionElement::SpreadElement(spread) => Some(&spread.argument),
        ArrayExpressionElement::Elision(_) => None,
        element => Some(element.to_expression()),
    }
}

/// An array literal, possibly parenthesized.
fn array<'b, 'a>(expression: &'b Expression<'a>) -> Option<&'b ArrayExpression<'a>> {
    match expression.without_parentheses() {
        Expression::ArrayExpression(array) => Some(array),
        _ => None,
    }
}

/// Returns the arguments a call forwards to the callee identified by `target`. Skips leading
/// selectors, callee, and receiver. The forwarded arguments are either the trailing call arguments
/// or the trailing elements of an apply-helper argument list.
fn handed<'a>(arguments: Arguments<'a, '_>, target: &Invocation<'a>) -> Option<Vec<Operand<'a>>> {
    let operands: Vec<Operand<'a>> = if target.listed {
        let list = array(ast::argument_expression(arguments.list.last()?))?;
        list.elements
            .iter()
            .map(|element| arguments.element(element))
            .collect::<Option<_>>()?
    } else {
        arguments
            .list
            .iter()
            .map(|argument| arguments.argument(argument))
            .collect()
    };
    let start = operands.len().checked_sub(target.passed?)?;
    Some(operands[start..].to_vec())
}

/// Checks whether `call` forwards two captured values followed by `function`'s leading
/// parameters, as a closure-factory listener does. The function may also declare trailing
/// parameters used as local variables.
fn forwards_parameters<'a>(
    constants: &Constants<'a>,
    function: &Body<'a>,
    call: &'a CallExpression<'a>,
    target: &Invocation<'a>,
) -> bool {
    let (Some(handed), Some(parameters)) =
        (handed(Arguments::of(call), target), function.parameters())
    else {
        return false;
    };
    let Some(forwarded) = handed.get(2..) else {
        return false;
    };
    forwarded.len() <= parameters.len()
        && forwarded
            .iter()
            .zip(parameters)
            .all(|(argument, parameter)| {
                argument.callee(constants) == Some(Callee::symbol(parameter))
            })
}

/// Arrays a function fills with names before reading them back, such as `g = [f, a]` read as
/// `g[0]` and `g[1]`.
struct Copies<'a, 'c> {
    arrays: HashMap<Binding<'a>, Vec<Binding<'a>>>,
    /// Known constants used to evaluate array indices.
    constants: &'c Constants<'a>,
}

impl<'a, 'c> Copies<'a, 'c> {
    fn new(constants: &'c Constants<'a>) -> Self {
        Self {
            arrays: HashMap::new(),
            constants,
        }
    }

    /// Records `expression` if it is `array = [name, ...]`.
    fn record(&mut self, expression: &Expression<'a>) -> Option<()> {
        let Expression::AssignmentExpression(assignment) = expression else {
            return None;
        };
        let AssignmentTarget::AssignmentTargetIdentifier(array) = &assignment.left else {
            return None;
        };
        let Expression::ArrayExpression(list) = &assignment.right else {
            return None;
        };
        let names: Option<Vec<Binding<'a>>> = list
            .elements
            .iter()
            .map(|element| self.constants.binding(element_expression(element)?))
            .collect();
        self.arrays.insert(self.constants.js.binding(array), names?);
        Some(())
    }

    /// The binding `expression` reads, directly or through an element of a copied array.
    fn resolve(&self, expression: &Expression<'a>) -> Option<Binding<'a>> {
        match expression.without_parentheses() {
            Expression::Identifier(name) => Some(self.constants.js.binding(name)),
            Expression::ComputedMemberExpression(member) => {
                let Expression::Identifier(array) = &member.object else {
                    return None;
                };
                let index = ast::array_index(number(&member.expression, self.constants)?)?;
                self.arrays
                    .get(&self.constants.js.binding(array))?
                    .get(index)
                    .copied()
            }
            _ => None,
        }
    }

    /// The binding `operand` reads. See [`Copies::resolve`].
    fn resolve_operand(&self, operand: Operand<'a>) -> Option<Binding<'a>> {
        match operand {
            Operand::Expression(expression) => self.resolve(expression),
            Operand::Resolved(Callee::Binding(binding)) => Some(binding),
            Operand::Resolved(Callee::Original(_)) => None,
        }
    }
}

/// JavaScriptCore's call position: the opening argument parenthesis, which in minified source
/// immediately precedes the first argument. Decoding may change the callee's parentheses but
/// preserves argument positions.
fn arguments_position(call: &CallExpression<'_>) -> u32 {
    match call.arguments.first() {
        Some(first) => first.span().start - 1,
        None => call.span.end - 2,
    }
}

/// V8's call position: the method or function name, else JavaScriptCore's position.
fn call_position(call: &CallExpression<'_>) -> u32 {
    match &call.callee {
        callee if let Some(member) = member(callee) => match member {
            MemberExpression::StaticMemberExpression(member) => member.property.span.start,
            _ => callee.span().end,
        },
        Expression::Identifier(_) | Expression::Super(_) => call.span.start,
        _ => arguments_position(call),
    }
}

/// Finds the first call in a dispatch case.
struct Case<'a> {
    span: Span,
    call: &'a CallExpression<'a>,
}

fn cases_of<'a>(js: ast::Script<'a>, function: &Body<'a>) -> Vec<Case<'a>> {
    struct Cases<'a> {
        js: ast::Script<'a>,
        found: Vec<Case<'a>>,
    }
    // Visitors inspect only the supplied body. Skip nested functions and classes, but include
    // arrows.
    impl<'a> Visit<'a> for Cases<'a> {
        fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
        fn visit_class(&mut self, _: &Class<'a>) {}
        fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
            walk_property(self, property);
        }
        fn visit_switch_case(&mut self, case: &SwitchCase<'a>) {
            if case.test.is_some() {
                let case = self.js.lend(case, AstKind::as_switch_case);
                if let Some(&call) = calls_in(self.js, &case.consequent).first() {
                    self.found.push(Case {
                        span: case.span,
                        call,
                    });
                }
            }
            walk::walk_switch_case(self, case);
        }
    }
    let mut cases = Cases {
        js,
        found: Vec::new(),
    };
    function.visit(&mut cases);
    cases.found
}

/// Calls made by a function's own body, excluding nested functions.
struct Calls<'a> {
    js: ast::Script<'a>,
    found: Vec<&'a CallExpression<'a>>,
}

impl<'a> Visit<'a> for Calls<'a> {
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
    fn visit_class(&mut self, _: &Class<'a>) {}
    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        walk_property(self, property);
    }
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !is_optional_call(call) {
            self.found
                .push(self.js.lend(call, AstKind::as_call_expression));
        }
        walk::walk_call_expression(self, call);
    }
}

/// Calls made by `statements`, excluding nested functions.
fn calls_in<'a>(
    js: ast::Script<'a>,
    statements: impl IntoIterator<Item = &'a Statement<'a>>,
) -> Vec<&'a CallExpression<'a>> {
    let mut calls = Calls {
        js,
        found: Vec::new(),
    };
    for statement in statements {
        calls.visit_statement(statement);
    }
    calls.found
}

fn calls_of<'a>(js: ast::Script<'a>, function: &Body<'a>) -> Vec<&'a CallExpression<'a>> {
    calls_in(js, function.statements())
}

/// A call's target, resolved through helper functions.
struct Invocation<'a> {
    callee: Option<Callee<'a>>,
    /// Whether it invokes `callee.call(receiver, ...)`.
    method: bool,
    /// Intermediate helper frames, innermost first.
    helpers: Vec<Call>,
    site: Site,
    /// Argument count passed to `callee`, if statically known.
    passed: Option<usize>,
    /// Whether the final argument is an array literal containing the arguments passed to `callee`.
    listed: bool,
    /// The array slot the called function is read from, if any.
    slot: Option<(Binding<'a>, usize)>,
}

impl Invocation<'_> {
    /// An unresolved call at `site`.
    fn at(site: Site) -> Self {
        Self {
            callee: None,
            method: false,
            helpers: Vec::new(),
            site,
            passed: None,
            listed: false,
            slot: None,
        }
    }

    /// The frames of the call made from `caller`, innermost first.
    fn frames(&self, caller: Name) -> Vec<Call> {
        let mut frames = self.helpers.clone();
        frames.push(Call {
            name: caller,
            site: self.site,
        });
        frames
    }
}

/// A `switch (selector ^ mask)` whose case labels each select a `T`.
struct Selection<T> {
    mask: f64,
    cases: Vec<(f64, T)>,
}

impl<T: Copy> Selection<T> {
    /// The case `selector` selects.
    fn select(&self, selector: f64) -> Option<T> {
        let chosen = f64::from(js::int32(self.mask) ^ js::int32(selector));
        self.cases
            .iter()
            .find(|(label, _)| *label == chosen)
            .map(|&(_, case)| case)
    }
}

/// Recovers the `Reflect.apply` call site of each case of a selector-based helper. Calls can use
/// `Reflect.apply(f, _, list)` or `f(a, b)` with later parameters forwarded in order.
///
/// Handles copied selectors such as `(s = [selector], mask ^ s[0])`, indirect references to
/// `apply`, copied arguments such as `(g = [f, a], (0, g[0])(g[1]))`, and masks or labels computed
/// from constants.
fn applier<'a>(function: &Body<'a>, constants: &Constants<'a>) -> Option<Selection<Site>> {
    let parameters = function.parameters()?;
    let [selector, applied, rest @ ..] = parameters.as_slice() else {
        return None;
    };
    let (mask, switch, copies) = selection(function, *selector, constants)?;
    let is = |binding: Option<Binding<'a>>, parameter: &SymbolId| {
        binding == Some(Binding::Symbol(*parameter))
    };
    // Match `f(a, b)` when arguments follow parameter order.
    let passes_on = |call: &CallExpression<'a>| {
        let (callee, _) = undetached(&call.callee, constants);
        is(copies.resolve(callee), applied)
            && call.arguments.len() <= rest.len()
            && call
                .arguments
                .iter()
                .zip(rest)
                .all(|(argument, parameter)| match argument {
                    Argument::SpreadElement(_) => false,
                    argument => is(copies.resolve(argument.to_expression()), parameter),
                })
    };
    let applies = |call: &CallExpression<'a>| {
        let [first, _, third] = &call.arguments[..] else {
            return false;
        };
        member(call.callee.without_parentheses()).is_some()
            && is(constants.binding(ast::argument_expression(first)), applied)
            && rest
                .first()
                .is_some_and(|list| is(constants.binding(ast::argument_expression(third)), list))
    };
    let cases: Vec<(f64, Site)> = switch
        .cases
        .iter()
        .filter_map(|case| {
            let label = number(case.test.as_ref()?, constants)?;
            let [Statement::ReturnStatement(returned)] = &case.consequent[..] else {
                return None;
            };
            let Expression::CallExpression(call) =
                returned.argument.as_ref()?.without_parentheses()
            else {
                return None;
            };
            (applies(call) || passes_on(call)).then(|| (label, Site::new(call)))
        })
        .collect();
    // Other cases may call more helpers. Selectors routed there have no case in this helper.
    (!cases.is_empty()).then_some(Selection { mask, cases })
}

/// Extracts the mask and switch from a function containing `switch (selector ^ mask)`, with
/// optional leading local declarations. Also tracks arrays used to copy selector names, as in `(s =
/// [selector], mask ^ s[0])`.
fn selection<'a, 'c>(
    function: &Body<'a>,
    selector: SymbolId,
    constants: &'c Constants<'a>,
) -> Option<(f64, &'a SwitchStatement<'a>, Copies<'a, 'c>)> {
    let Statement::SwitchStatement(switch) = function.only_statement()? else {
        return None;
    };
    let mut discriminant = switch.discriminant.without_parentheses();
    let mut copies = Copies::new(constants);
    if let Expression::SequenceExpression(sequence) = discriminant {
        let (last, before) = sequence.expressions.split_last()?;
        for expression in before {
            copies.record(expression);
        }
        discriminant = last.without_parentheses();
    }
    let Expression::BinaryExpression(xor) = discriminant else {
        return None;
    };
    if xor.operator != BinaryOperator::BitwiseXOR {
        return None;
    }
    let is_selector =
        |expression: &Expression<'a>| copies.resolve(expression) == Some(Binding::Symbol(selector));
    let mask = match (
        xor.left.without_parentheses(),
        xor.right.without_parentheses(),
    ) {
        (other, mask) | (mask, other) if is_selector(other) => number(mask, constants)?,
        _ => return None,
    };
    Some((mask, switch, copies))
}

/// Recovers the original functions of a function that combines several, selected by its first
/// parameter:
///
/// ```js
/// function merged(selector, a) { switch (selector ^ mask) { case 1: { <original> } return; } }
/// ```
///
/// Both V8 and JavaScriptCore name every original function's frame after the merged function.
/// Each original keeps the merged function's other parameters.
fn merged<'a>(function: &Body<'a>, constants: &Constants<'a>) -> Option<Selection<Body<'a>>> {
    let selector = plain_parameter(function.parameters.first()?)?;
    let (mask, switch, _) = selection(function, selector, constants)?;
    let mut cases = Vec::new();
    for (at, case) in switch.cases.iter().enumerate() {
        let label = case.test.as_ref().and_then(|test| number(test, constants));
        // Labels sharing a body fall through to it.
        let body = switch.cases[at..]
            .iter()
            .map(|case| &case.consequent)
            .find(|body| !body.is_empty());
        let (Some(label), Some(body)) = (label, body) else {
            continue;
        };
        let (mut head, mut tail): (&[Statement], &[Statement]) = match &body[..] {
            [Statement::BlockStatement(original), rest @ ..] => (&original.body[..], rest),
            body => (body, &[]),
        };
        let last = if tail.is_empty() {
            &mut head
        } else {
            &mut tail
        };
        if let [statements @ .., Statement::ReturnStatement(returned)] = *last
            && returned.argument.is_none()
        {
            *last = statements;
        }
        let body = Body {
            parameters: &function.parameters[1..],
            rest: function.rest,
            prologue: false,
            head,
            tail,
        };
        cases.push((label, body));
    }
    (!cases.is_empty()).then_some(Selection { mask, cases })
}

/// Storage location in a scope: a binding or a constant array slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Holder<'a> {
    Name(Binding<'a>),
    Slot(Binding<'a>, usize),
}

/// A function's local aliases, string constants, and forwarders.
struct Scope<'a, 's> {
    appliers: &'s Appliers<'a>,
    /// V8's name prefix for functions assigned here, such as `Owner.`.
    prefix: String,
    forwarders: Forwarders<'a>,
    /// Assignment count for each storage location. Only values assigned once are known.
    assigned: HashMap<Holder<'a>, usize>,
    aliases: HashMap<Binding<'a>, Binding<'a>>,
    strings: HashMap<Binding<'a>, &'a str>,
}

/// Frames for an object function that forwards its first parameter with the remaining arguments.
/// Stores frames innermost first for each call form.
struct Forwarder {
    /// Frames for a method call. V8 adds the computed key: `object.<computed> [as key]`.
    method: Vec<Call>,
    /// Frames for a call through a copied binding or a detached call such as `(0, object.key)(f)`.
    plain: Vec<Call>,
}

impl<'a, 's> Scope<'a, 's> {
    /// `name` is empty for anonymous functions. V8 prefixes the names of functions assigned
    /// inside a capitalized function with its name, as it does for constructors.
    fn new(name: &str, function: &Body<'a>, appliers: &'s Appliers<'a>) -> Self {
        let mut scope = Self {
            appliers,
            prefix: if name.starts_with(char::is_uppercase) {
                format!("{name}.")
            } else {
                String::new()
            },
            forwarders: Forwarders::default(),
            assigned: HashMap::new(),
            aliases: HashMap::new(),
            strings: HashMap::new(),
        };
        function.visit(&mut scope);
        scope.forwarders.retain_assigned_once(&scope.assigned);
        scope
    }

    fn js(&self) -> ast::Script<'a> {
        self.appliers.js()
    }

    fn target(&self, call: &'a CallExpression<'a>) -> Result<Invocation<'a>> {
        self.resolve(call, None)
    }

    /// Resolves `call`, reading arguments through `copies` when given.
    fn resolve(
        &self,
        call: &'a CallExpression<'a>,
        copies: Option<&Copies<'a, '_>>,
    ) -> Result<Invocation<'a>> {
        let site = Site::new(call);
        let arguments = Arguments {
            list: &call.arguments,
            copies,
        };
        let (callee, detached) = undetached(&call.callee, &self.appliers.constants);
        // Resolve the function called by `target`.
        if let Expression::Identifier(name) = callee {
            let binding = self.js().binding(name);
            if let Some((original, arguments)) = self.merged_call(binding, arguments) {
                // The original function uses the merged function's frame at this call site.
                let original = Callee::Original(original);
                return self.named(original, Operand::Resolved(original), arguments, site);
            }
            return self.named(
                Callee::Binding(binding),
                Operand::Expression(callee),
                arguments,
                site,
            );
        }
        let mut target = Invocation::at(site);
        let count = arguments.list.len();
        let function = match member(callee) {
            // Some builds keep the key in a local: `handler[c](this)` with `c = "call"`.
            Some(member)
                if !detached
                    && matches!(member.object(), Expression::Identifier(_))
                    && self.key(member) == Some("call") =>
            {
                target.method = true;
                target.passed = Some(count.saturating_sub(1));
                Some(Operand::Expression(member.object()))
            }
            // The first argument to a forwarder is the function it calls.
            Some(member) if let Some(forwarder) = self.member_forwarder(member) => {
                target.helpers = if detached {
                    forwarder.plain.clone()
                } else {
                    forwarder.method.clone()
                };
                target.passed = Some(count.saturating_sub(1));
                arguments
                    .list
                    .first()
                    .map(|first| arguments.argument(first))
            }
            // Resolve an array-stored function, as in `(0, slots[i])(f, a)`.
            Some(member) if self.slot(member).is_some() => {
                target.passed = Some(count);
                Some(Operand::Expression(callee))
            }
            _ => None,
        };
        Ok(self.finish(target, function, arguments))
    }

    /// Resolves a call to the function `callee`, read as `operand`, directly or through a call
    /// helper.
    fn named(
        &self,
        callee: Callee<'a>,
        operand: Operand<'a>,
        arguments: Arguments<'a, '_>,
        site: Site,
    ) -> Result<Invocation<'a>> {
        let (target, function) = match self.applier_call(callee, arguments, site)? {
            Some(applied) => applied,
            None => {
                let mut target = Invocation::at(site);
                target.passed = Some(arguments.list.len());
                (target, operand)
            }
        };
        Ok(self.finish(target, Some(function), arguments))
    }

    /// Follows stored forwarders from `function`, then records the resolved callee and slot.
    fn finish(
        &self,
        mut target: Invocation<'a>,
        mut function: Option<Operand<'a>>,
        arguments: Arguments<'a, '_>,
    ) -> Invocation<'a> {
        // A stored forwarder calls its first argument with the remaining arguments.
        while let Some(operand) = function
            && let Some(frames) = self.held_by(operand)
            && let Some(first) =
                handed(arguments, &target).and_then(|handed| handed.first().copied())
        {
            function = Some(first);
            target.helpers = frames.iter().cloned().chain(target.helpers).collect();
            target.passed = target.passed.map(|passed| passed - 1);
        }
        target.callee = function.and_then(|function| function.callee(&self.appliers.constants));
        target.slot = function.and_then(|function| match self.holder(function)? {
            Holder::Slot(array, index) => Some((array, index)),
            Holder::Name(_) => None,
        });
        target
    }

    /// Resolves `merged(selector, a, b)` to the selected original function and the arguments
    /// `a, b`.
    fn merged_call<'c>(
        &self,
        callee: Binding<'a>,
        arguments: Arguments<'a, 'c>,
    ) -> Option<(usize, Arguments<'a, 'c>)> {
        let merged = self.appliers.merged.get(&callee)?;
        let (selector, rest) = arguments.list.split_first()?;
        let original = merged.select(self.appliers.number(arguments.argument(selector))?)?;
        Some((
            original,
            Arguments {
                list: rest,
                copies: arguments.copies,
            },
        ))
    }

    /// Resolves `applier(selector, f, [args])` or `applier(selector, f, a, b)` through a call
    /// helper. Also returns the called function `f`.
    fn applier_call(
        &self,
        callee: Callee<'a>,
        arguments: Arguments<'a, '_>,
        site: Site,
    ) -> Result<Option<(Invocation<'a>, Operand<'a>)>> {
        let (Some(applier), [selector, function, passed @ ..]) =
            (self.appliers.helpers.get(&callee), arguments.list)
        else {
            return Ok(None);
        };
        let Some(selector) = self.appliers.number(arguments.argument(selector)) else {
            return Ok(None);
        };
        let name = self.appliers.name(callee);
        let inner = applier
            .select(selector)
            .with_context(|| format!("{name} has no case for selector {selector}"))?;
        let (passed, listed) = match passed {
            [list] if let Some(list) = array(ast::argument_expression(list)) => {
                (list.elements.len(), true)
            }
            passed => (passed.len(), false),
        };
        let mut invocation = Invocation::at(site);
        invocation.helpers = vec![Call {
            name: Name::same(name.to_owned()),
            site: inner,
        }];
        invocation.passed = Some(passed);
        invocation.listed = listed;
        Ok(Some((invocation, arguments.argument(function))))
    }

    /// Resolves a member key from a literal or a local string binding.
    fn key(&self, member: &MemberExpression<'a>) -> Option<&'a str> {
        match member {
            MemberExpression::ComputedMemberExpression(computed)
                if let Expression::Identifier(name) = &computed.expression =>
            {
                self.strings.get(&self.js().binding(name)).copied()
            }
            member => ast::member_str(member),
        }
    }

    /// Finds the forwarder read by `object.key`.
    fn member_forwarder(&self, member: &'a MemberExpression<'a>) -> Option<&Forwarder> {
        let key = (
            self.holder(Operand::Expression(member.object()))?,
            self.key(member)?,
        );
        self.forwarders
            .on_objects
            .get(&key)
            .or_else(|| self.appliers.forwarders.on_objects.get(&key))
    }

    /// Returns frames for the stored forwarder read by `operand`.
    fn held_by(&self, operand: Operand<'a>) -> Option<&Vec<Call>> {
        let holder = self.holder(operand)?;
        self.forwarders
            .held
            .get(&holder)
            .or_else(|| self.appliers.forwarders.held.get(&holder))
    }

    /// Resolves the value read by `operand`, following local aliases. An original function is
    /// never stored.
    fn holder(&self, operand: Operand<'a>) -> Option<Holder<'a>> {
        match operand {
            Operand::Expression(expression) => match expression.without_parentheses() {
                Expression::Identifier(name) => {
                    Some(Holder::Name(self.object(self.js().binding(name))))
                }
                expression => self.slot(member(expression)?),
            },
            Operand::Resolved(Callee::Binding(binding)) => Some(Holder::Name(self.object(binding))),
            Operand::Resolved(Callee::Original(_)) => None,
        }
    }

    /// Resolves `array[index]` when the index is constant.
    fn slot(&self, member: &MemberExpression<'a>) -> Option<Holder<'a>> {
        let MemberExpression::ComputedMemberExpression(member) = member else {
            return None;
        };
        let Expression::Identifier(array) = &member.object else {
            return None;
        };
        let index = number(&member.expression, &self.appliers.constants)?;
        Some(Holder::Slot(
            self.object(self.js().binding(array)),
            ast::array_index(index)?,
        ))
    }

    /// Resolves the object held by `name` through local copies.
    fn object(&self, name: Binding<'a>) -> Binding<'a> {
        let mut name = name;
        for _ in 0..self.aliases.len() {
            match self.aliases.get(&name) {
                Some(&original) => name = original,
                None => break,
            }
        }
        name
    }

    /// Records the value stored by assigning `value` to `holder`.
    fn bind(&mut self, holder: Holder<'a>, value: &'a Expression<'a>) {
        *self.assigned.entry(holder).or_default() += 1;
        // Chained assignments store the innermost value in each target.
        let mut value = value.without_parentheses();
        while let Expression::AssignmentExpression(inner) = value
            && inner.operator == AssignmentOperator::Assign
        {
            value = inner.right.without_parentheses();
        }
        let forwarder = match member(value) {
            Some(member) if let Some(forwarder) = self.member_forwarder(member) => {
                Some(forwarder.plain.clone())
            }
            _ => self.held_by(Operand::Expression(value)).cloned(),
        };
        if let Some(frames) = forwarder {
            self.forwarders.held.insert(holder, frames);
            return;
        }
        match (holder, value) {
            (Holder::Name(name), Expression::Identifier(original)) => {
                self.aliases.insert(name, self.js().binding(original));
            }
            (holder, Expression::ObjectExpression(object)) => self.literal(holder, object),
            (Holder::Name(name), value) => {
                if let Some(text) = ast::static_str(value) {
                    self.strings.insert(name, text);
                }
            }
            _ => {}
        }
    }

    /// Records forwarders defined by an object literal assigned to `holder`. V8 names functions
    /// by their property keys, including computed keys. JavaScriptCore leaves functions under
    /// computed keys anonymous: obfuscation computes them with string decoder calls.
    fn literal(&mut self, holder: Holder<'a>, object: &'a ObjectExpression<'a>) {
        // Matches `key: function` properties and methods, but not accessors.
        for property in &object.properties {
            if let ObjectPropertyKind::ObjectProperty(property) = property
                && let Expression::FunctionExpression(function) = &property.value
                && property.kind == PropertyKind::Init
                && let Some(key) = ast::static_key_str(&property.key, property.computed)
                && let Some(frames) = self.forwarder(
                    function,
                    if property.computed {
                        Name::anonymous(key.to_owned())
                    } else {
                        Name::same(key.to_owned())
                    },
                )
            {
                let forwarder = Forwarder {
                    method: frames.clone(),
                    plain: frames,
                };
                self.forwarders.on_objects.insert((holder, key), forwarder);
            }
        }
    }

    /// Recovers frames, innermost first, for a function that calls its first parameter with
    /// later parameters. Accepts direct calls, array copies such as `(g = [f, b], (0, g[0])(a,
    /// g[1]))`, and call helpers. Extra parameters can act as locals. Allows local declarations
    /// before the call.
    fn forwarder(&self, function: &'a Function<'a>, frame: Name) -> Option<Vec<Call>> {
        let constants = &self.appliers.constants;
        let function = Body::of(function);
        let parameters = function.parameters()?;
        let (first, rest) = parameters.split_first()?;
        let first = Binding::Symbol(*first);
        let mut arrays = Copies::new(constants);
        let Statement::ReturnStatement(returned) = function.only_statement()? else {
            return None;
        };
        let mut value = returned.argument.as_ref()?.without_parentheses();
        if let Expression::SequenceExpression(sequence) = value {
            let (last, before) = sequence.expressions.split_last()?;
            for expression in before {
                // Obfuscation leaves expressions that do nothing.
                if arrays.record(expression).is_none() && !is_inert(expression, constants) {
                    return None;
                }
            }
            value = last.without_parentheses();
        }
        // Forwarded arguments must match the parameters after the target function.
        let passes_on = |arguments: &[Operand<'a>]| {
            arguments.len() <= rest.len()
                && arguments.iter().zip(rest).all(|(argument, parameter)| {
                    arrays.resolve_operand(*argument) == Some(Binding::Symbol(*parameter))
                })
        };
        let Expression::CallExpression(call) = value else {
            return None;
        };
        let (callee, _) = undetached(&call.callee, constants);
        // A spread has no expression, so it rejects the call.
        let arguments: Vec<Operand<'a>> = call
            .arguments
            .iter()
            .map(|argument| argument.as_expression().map(Operand::Expression))
            .collect::<Option<_>>()?;
        if arrays.resolve(callee) == Some(first) && passes_on(&arguments) {
            return Some(vec![Call {
                name: frame,
                site: Site::new(call),
            }]);
        }
        // Resolve copied names passed through a call helper.
        let target = self.resolve(call, Some(&arrays)).ok()?;
        let copied = Arguments {
            list: &call.arguments,
            copies: Some(&arrays),
        };
        (!target.helpers.is_empty()
            && target.callee == Some(Callee::Binding(first))
            && passes_on(&handed(copied, &target)?))
        .then(|| target.frames(frame))
    }
}

/// Whether `expression` has no effect, such as obfuscation's `true`, constant comparisons and
/// `void` expressions, including those using numeric `constants`.
fn is_inert<'a>(expression: &Expression<'a>, constants: &Constants<'a>) -> bool {
    let inert = |expression: &Expression<'a>| is_inert(expression, constants);
    match expression.without_parentheses() {
        expression if expression.is_literal() => true,
        Expression::Identifier(name) => constants
            .js
            .symbol(name)
            .is_some_and(|symbol| constants.values.contains_key(&symbol)),
        Expression::BinaryExpression(binary) => inert(&binary.left) && inert(&binary.right),
        Expression::LogicalExpression(logical) => inert(&logical.left) && inert(&logical.right),
        Expression::UnaryExpression(unary) => {
            unary.operator != UnaryOperator::Delete && inert(&unary.argument)
        }
        Expression::ArrayExpression(array) => array
            .elements
            .iter()
            .all(|element| element_expression(element).is_none_or(inert)),
        _ => false,
    }
}

/// Resolves the function produced by `callee` and checks whether a side-effect-free first operand
/// detaches its receiver. For example, `(0, f)(a)` calls `f` without a receiver.
fn undetached<'b, 'a>(
    callee: &'b Expression<'a>,
    constants: &Constants<'a>,
) -> (&'b Expression<'a>, bool) {
    let callee = callee.without_parentheses();
    if let Expression::SequenceExpression(sequence) = callee
        && let [discarded, last] = &sequence.expressions[..]
        && is_inert(discarded, constants)
    {
        return (last.without_parentheses(), true);
    }
    (callee, false)
}

impl<'a> Visit<'a> for Scope<'a, '_> {
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
    fn visit_class(&mut self, _: &Class<'a>) {}
    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        walk_property(self, property);
    }

    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        let assignment = self
            .js()
            .lend(assignment, AstKind::as_assignment_expression);
        if assignment.operator == AssignmentOperator::Assign {
            if let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left {
                self.bind(Holder::Name(self.js().binding(name)), &assignment.right);
            } else if let Some(member) = assigned_member(&assignment.left) {
                if let Some(slot) = self.slot(member) {
                    self.bind(slot, &assignment.right);
                } else if let Expression::FunctionExpression(function) = &assignment.right
                    && let Some(object) = self.holder(Operand::Expression(member.object()))
                    && let Some(path) = inferred_path(member.object())
                    && let Some(name) = ast::member_str(member)
                {
                    // V8 infers the name of an anonymous function from the member it is
                    // assigned to.
                    let path = format!("{}{path}", self.prefix);
                    let (inferred, method) =
                        if matches!(member, MemberExpression::ComputedMemberExpression(_)) {
                            let inferred = format!("{path}.<computed>");
                            (inferred.clone(), format!("{inferred} [as {name}]"))
                        } else {
                            let inferred = format!("{path}.{name}");
                            (inferred.clone(), inferred)
                        };
                    let frames = |name: String| self.forwarder(function, Name::anonymous(name));
                    if let (Some(method), Some(plain)) = (frames(method), frames(inferred)) {
                        self.forwarders
                            .on_objects
                            .insert((object, name), Forwarder { method, plain });
                    }
                }
            }
        }
        walk::walk_assignment_expression(self, assignment);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        let declarator = self.js().lend(declarator, AstKind::as_variable_declarator);
        if let BindingPattern::BindingIdentifier(name) = &declarator.id
            && let Some(init) = &declarator.init
        {
            self.bind(Holder::Name(Binding::Symbol(name.symbol_id())), init);
        }
        walk::walk_variable_declarator(self, declarator);
    }
}

/// Returns the V8 name inferred from an assignment target: `object` for an object or
/// `array.<computed>` for an array slot.
fn inferred_path(object: &Expression<'_>) -> Option<String> {
    match object.without_parentheses() {
        Expression::Identifier(name) => Some(name.name.to_string()),
        Expression::ComputedMemberExpression(member) => {
            let Expression::Identifier(array) = &member.object else {
                return None;
            };
            Some(format!("{}.<computed>", array.name))
        }
        _ => None,
    }
}

/// Finds runner calls from closure-factory listeners, including calls made through helpers, and
/// records calls it cannot resolve. Each listener forwards its captured machine and layout
/// followed by its own arguments.
struct Listeners<'a, 's> {
    runner: Callee<'a>,
    appliers: &'s Appliers<'a>,
    found: Vec<Result<Invocation<'a>>>,
}

impl<'a> Visit<'a> for Listeners<'a, '_> {
    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let js = self.appliers.js();
        let function = js.lend(function, AstKind::as_function);
        let body = Body::of(function);
        let scope = Scope::new("", &body, self.appliers);
        for call in calls_of(js, &body) {
            match scope.target(call) {
                // A listener passes the captured machine and layout, then its own
                // parameters. Other scopes may reuse the runner's name for another function,
                // and the message handler starts the runner with computed arguments.
                Ok(mut target)
                    if target.callee == Some(self.runner)
                        && forwards_parameters(&self.appliers.constants, &body, call, &target) =>
                {
                    target.passed = target.passed.map(|passed| passed - 2);
                    self.found.push(Ok(target));
                }
                Ok(_) => {}
                Err(error) => self.found.push(Err(error)),
            }
        }
        walk::walk_function(self, function, flags);
    }

    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        walk_property(self, property);
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        walk_method(self, method);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decoded program captured during deobfuscation equals the one decoding alone
    /// produces, for a saved script named by `CFSOLVE_CAPTURE_SCRIPT`.
    #[test]
    fn captures_the_decoded_program() {
        let Some(path) = std::env::var_os("CFSOLVE_CAPTURE_SCRIPT") else {
            return;
        };
        let source = std::fs::read_to_string(path).expect("the capture script is readable");
        // The debug form includes spans and semantic IDs.
        let debug = |decoded: &ParsedScript| format!("{:?}", decoded.script().program);
        let (_, cases) = deobfuscate_with_cases(source.clone()).unwrap();
        let captured = debug(&cases.decoded.unwrap());
        let alone = debug(&deobfuscate::decode(source).unwrap());
        assert!(
            captured == alone,
            "the captured program differs from the decoded one"
        );
    }

    #[test]
    fn appliers_may_copy_their_selector_and_name_apply_indirectly() {
        for source in [
            "function j(s,f,a){switch(5^s){case 6:return Reflect.apply(f,void 0,a)}}",
            "function j(s,f,a,e,c,n){switch(e={},c=`apply`,n=[s],5^n[0]){case 6:return Reflect[c](f,void 0,a)}}",
            "var j;j=function(s,f,a){switch(5^s){case 6:return Reflect.apply(f,void 0,a)}}",
        ] {
            with_script(source, |script| {
                let applier = &script.appliers.helpers[&binding(script, "j")];
                assert!(applier.select(3.0).is_some(), "{source}");
            });
        }
    }

    /// Checks a method forwarder that applies through a local object's helper, which reads
    /// arguments from an array. V8 prefixes the helper's name with the object and the enclosing
    /// function's capitalized name.
    #[test]
    fn method_forwarders_may_apply_through_a_local_object() {
        let source = "var B=Reflect.apply;\
            function S(a,n){return a.slice(n)}\
            function PA(f,r){var o,q;return o={},\
            o['k']=function(a,b,c,d,g){return g=[b,d],true,a(g[0],c,g[1])},\
            o['s']=function(a,b,c,g){return g=[c,a,b],(0,g[1])(g[2],g[0])},\
            q=o,q['k'](B,f,r,q['s'](S,arguments,2))}";
        with_script(source, |script| {
            let frames = script.method_forwarder(binding(script, "PA")).unwrap();
            assert_eq!(v8_names(&frames), ["PA.o.<computed> [as k]", "PA"]);
            assert!(script.method_forwarder(binding(script, "S")).is_none());
        });
    }

    /// Checks method forwarders that call a `Reflect.apply` alias kept in an array slot, directly
    /// or through a selector helper. Other slots are not apply aliases.
    #[test]
    fn method_forwarders_may_apply_through_an_array_slot() {
        let source = "var G=[];G[2]=Reflect.apply;G[3]=function(){};\
            function W(s,f,a,b,c){switch(s^1){case 0:return f(a,b,c)}}\
            function D(f,r,a){return(0,G[2])(f,r,[a])}\
            function H(f,r,a,b){return W(1,G[2],f,r,[a,b])}\
            function O(f,r,a){return(0,G[3])(f,r,[a])}";
        with_script(source, |script| {
            let cases: [(&str, &[&str]); 2] = [("D", &["D"]), ("H", &["W", "H"])];
            for (forwarder, expected) in cases {
                let frames = script
                    .method_forwarder(binding(script, forwarder))
                    .expect("`G[2]` holds `Reflect.apply`, so the call is a method forwarder");
                assert_eq!(
                    v8_names(&frames),
                    expected,
                    "frames of forwarder {forwarder}"
                );
            }
            assert!(
                script.method_forwarder(binding(script, "O")).is_none(),
                "`G[3]` holds a plain function, not `Reflect.apply`"
            );
        });
    }

    #[test]
    fn same_named_functions_resolve_to_the_called_binding() {
        let source = "function outer(){function h(){wrong()} h()} function h(){right()} function caller(){h()}";
        with_script(source, |script| {
            let target = first_target(script, "caller");
            let handler = script.function(target.callee.unwrap()).unwrap();
            let call = calls_of(script.js(), &handler)[0];
            let callee = Operand::Expression(&call.callee)
                .callee(&script.appliers.constants)
                .unwrap();
            assert_eq!(script.appliers.name(callee), "right");
        });
    }

    #[test]
    fn shadowed_appliers_and_runners_are_distinct_bindings() {
        let source = "function runner(){} function j(s,f,a){switch(5^s){case 6:return Reflect.apply(f,void 0,a)}} function outer(){function j(){} function runner(){} j(3,f,[]);return function(a){runner(vm,layout,a);j(3,f,[])}} function real(a){runner(vm,layout,a)}";
        with_script(source, |script| {
            let runner = first_target(script, "real").callee.unwrap();
            let mut listeners = Listeners {
                runner,
                appliers: &script.appliers,
                found: Vec::new(),
            };
            // Visit every collected function, including the anonymous listener inside outer.
            for (_, function) in script.js().named_functions() {
                listeners.visit_function(function, ScopeFlags::Function);
            }
            assert_eq!(listeners.found.len(), 1);
            let target = first_target(script, "outer");
            assert!(target.helpers.is_empty());
            assert_eq!(target.passed, Some(3));
            let callee = target.callee.expect("the call has a named callee");
            assert!(!script.appliers.helpers.contains_key(&callee));
        });
    }

    #[test]
    fn native_apply_alias_does_not_match_a_shadowed_function() {
        let source = "var B=Reflect.apply; function outer(){function B(){} function wrong(f,r){return B(f,r,[])}} function good(f,r){return B(f,r,[])}";
        with_script(source, |script| {
            assert!(script.method_forwarder(binding(script, "wrong")).is_none());
            assert!(script.method_forwarder(binding(script, "good")).is_some());
        });
    }

    #[test]
    fn block_locals_do_not_replace_an_outer_objects_forwarder() {
        let source = "function F(){let o={},q=o,c='k';o.k=function(f,a){return f(a)};{let o={},q=o,c='other';o.k=function(f,a){return 0};}return q[c](target,1)}";
        with_script(source, |script| {
            let target = first_target(script, "F");
            assert_eq!(script.appliers.name(target.callee.unwrap()), "target");
            assert_eq!(target.helpers.len(), 1);
            assert_eq!(target.helpers[0].name.v8, "F.o.k");
        });
    }

    /// Decodes `source` and analyzes it.
    fn with_script<T>(source: &str, read: impl for<'a> FnOnce(&Script<'a>) -> T) -> T {
        let decoded = deobfuscate::decode(source.to_owned()).unwrap();
        read(&Script::new(decoded.script()))
    }

    /// The binding of the script function named `name`.
    fn binding<'a>(script: &Script<'a>, name: &str) -> Callee<'a> {
        let (binding, _) = script
            .functions
            .iter()
            .find(|(binding, _)| script.js().name(*binding) == name)
            .unwrap();
        Callee::Binding(*binding)
    }

    fn v8_names(calls: &[Call]) -> Vec<&str> {
        calls.iter().map(|call| call.name.v8.as_str()).collect()
    }

    /// Returns the target of the first call in the script function named `name`.
    fn first_target<'a>(script: &Script<'a>, name: &str) -> Invocation<'a> {
        let function = script.function(binding(script, name)).unwrap();
        let call = calls_of(script.js(), &function)[0];
        Scope::new(name, &function, &script.appliers)
            .target(call)
            .unwrap()
    }

    /// The selector chooses an original function, which runs in the merged function's frame. In
    /// this case, the original is an apply helper with its own selector.
    #[test]
    fn merged_functions_run_the_original_their_selector_picks() {
        let source = "var C=7;\
            function e(s,t,f,a){switch(s^C){case 1:{var y;switch(y=[a],5^t){case 6:return f(y[0])}}return;case 2:{h(a)}return}}\
            function caller(x){return e(6,3,g,x)}\
            function other(x){e(5,x)}";
        with_script(source, |script| {
            let target = first_target(script, "caller");
            assert_eq!(script.appliers.name(target.callee.unwrap()), "g");
            assert_eq!(v8_names(&target.helpers), ["e"]);
            assert_eq!(target.passed, Some(1));
            let original = first_target(script, "other").callee.unwrap();
            assert!(matches!(original, Callee::Original(_)));
            assert_eq!(script.appliers.name(original), "e");
            let function = script.function(original).unwrap();
            let call = calls_of(script.js(), &function)[0];
            let callee = Operand::Expression(&call.callee)
                .callee(&script.appliers.constants)
                .unwrap();
            assert_eq!(script.appliers.name(callee), "h");
        });
    }

    /// V8 names a forwarder copied to a binding after its assignment target, without the property
    /// key used for method calls. This also applies when called through a helper.
    #[test]
    fn forwarders_held_in_names_add_their_inferred_frame() {
        let source = "var o,p,q;\
            function setup(){o={};o['k']=function(f,a,b){var c;return f(a,b)};p=o;q=p['k']}\
            function a(s,f,x,y,z){switch(s^5){case 6:return f(x,y,z)}}\
            function direct(m){return q(loop,m,1)}\
            function applied(m){return a(3,q,loop,m,1)}";
        with_script(source, |script| {
            for (caller, expected) in [
                ("direct", &["o.<computed>"][..]),
                ("applied", &["o.<computed>", "a"]),
            ] {
                let target = first_target(script, caller);
                assert_eq!(
                    script.appliers.name(target.callee.unwrap()),
                    "loop",
                    "{caller}"
                );
                assert_eq!(v8_names(&target.helpers), expected, "{caller}");
                assert_eq!(target.passed, Some(2), "{caller}");
            }
        });
    }

    #[test]
    fn a_call_key_kept_in_a_local_still_calls_the_handler() {
        let source = "function run(){var c='call';switch(o){case 1:h[c](this);break}}";
        with_script(source, |script| {
            let target = first_target(script, "run");
            assert_eq!(
                target.callee.map(|callee| script.appliers.name(callee)),
                Some("h")
            );
            assert!(target.method);
            assert_eq!(target.passed, Some(0));
        });
    }

    #[test]
    fn formats_frames_from_where_the_script_starts() {
        let frame = |function: &str, line, column| Frame {
            function: function.into(),
            line,
            column,
        };
        let geometry = Geometry {
            frames: vec![
                frame("a", 0, 10),
                frame("HTMLInputElement.<anonymous>", 2, 4),
            ],
            jsc_frames: vec![frame("a", 0, 11), frame("", 2, 7)],
            reflected: true,
        };
        let origin = ScriptPosition {
            url: "https://example.com/x".into(),
            line: 3,
            column: 100,
        };
        assert_eq!(
            geometry.format(&origin, Engine::Chromium),
            "Error\n    at a (https://example.com/x:4:111)\n    at HTMLInputElement.<anonymous> (https://example.com/x:6:5)",
            "the script's own first line is offset by its column in the page"
        );
        assert_eq!(
            geometry.format(&origin, Engine::WebKit),
            "construct@[native code]\na@https://example.com/x:4:112\n@https://example.com/x:6:8"
        );
    }

    /// Checks engine-specific frame names and positions. For apply helpers, V8 uses the helper
    /// name's position; JavaScriptCore uses the opening call parenthesis.
    #[test]
    fn jsc_frames_are_placed_at_their_arguments() {
        let source = "function a(s,f,l){switch(1^s){case 0:return Reflect.construct(f,void 0,l);case 3:return Reflect.apply(f,void 0,l)}}function h(){return a(1,Error,[])}";
        with_script(source, |script| {
            let target = first_target(script, "h");
            let frames = target.frames(Name::same("h".to_owned()));
            let names: Vec<_> = frames
                .iter()
                .map(|call| (call.name.v8.as_str(), call.name.jsc.as_str()))
                .collect();
            assert_eq!(names, [("a", "a"), ("h", "h")]);
            let at = |position: u32| &source[position as usize..][..2];
            let (applier, handler) = (&frames[0], &frames[1]);
            assert_eq!(at(handler.site.v8), "a(");
            assert_eq!(at(handler.site.jsc), "(1");
            assert_eq!(at(applier.site.jsc), "(f");
        });
    }
}
