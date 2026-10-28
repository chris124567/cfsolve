//! Reconstructs `new Error()` stacks from the original script: the checkbox click's, the stack
//! probe's, and the challenge page's render call.
//!
//! The chain runs from the listener through the VM's runner and `run` method to the opcode
//! handler that constructs the error. Some builds use the runner directly as listener; others
//! add an arity-specific wrapper. Forwarders, helper-object methods, and selector-based
//! `Reflect.apply` helpers add their own frames. Recovery decodes only the string table,
//! preserving original positions and method keys.
//!
//! V8 names frames by call form, such as `Class.run` or `HTMLInputElement.<anonymous>`, and
//! uses callee positions. JavaScriptCore names them by definition, leaving many methods
//! anonymous, uses the opening argument parenthesis, and includes native `Reflect.construct`
//! frames. The script is sloppy code, so JavaScriptCore does not eliminate tail calls.

use std::collections::{HashMap, HashSet};
use std::mem;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use swc_core::common::{BytePos, Mark, Span, Spanned, SyntaxContext};
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, BinaryOp, BlockStmt, CallExpr, Callee, Class, ClassDecl,
    ClassMember, Decl, Expr, FnDecl, FnExpr, Function, Id, Ident, MemberExpr, MemberProp, NewExpr,
    ObjectLit, Pat, Program, Prop, ReturnStmt, SimpleAssignTarget, Stmt, SwitchCase, SwitchStmt,
    ThrowStmt, TryStmt, UnaryOp, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::deobfuscate::{self, Deobfuscated};
use crate::engine::{self, Engine, Lines, StackFrame, V8_STACK_LIMIT};
use crate::js::ast;
use crate::{candidates, js};

/// Maps VM dispatch cases to opcodes at their original source positions. Deobfuscation resolves
/// case labels while preserving spans. Recovery uses the resolved labels to find each opcode's
/// case in the original script.
#[derive(Clone, Debug, Default)]
pub struct CaseOpcodes(HashMap<(u32, u32), u8>);

/// Returns a span's offset from the parse start, stable across parses of the same script.
fn offsets(span: Span, start: BytePos) -> (u32, u32) {
    (span.lo.0 - start.0, span.hi.0 - start.0)
}

/// Deobfuscates `source` and maps its dispatch cases' original positions to their opcodes.
pub fn deobfuscate_with_cases(source: String) -> Result<(Deobfuscated, CaseOpcodes)> {
    struct Cases {
        start: BytePos,
        opcodes: CaseOpcodes,
    }
    impl Visit for Cases {
        fn visit_switch_case(&mut self, case: &SwitchCase) {
            if let Some(test) = &case.test
                && let Some(opcode) = ast::index_literal(test)
                && let Ok(opcode) = u8::try_from(opcode)
            {
                self.opcodes
                    .0
                    .insert(offsets(case.span, self.start), opcode);
            }
            case.visit_children_with(self);
        }
    }
    deobfuscate::deobfuscate_with(source, |program, start| {
        let mut cases = Cases {
            start,
            opcodes: CaseOpcodes::default(),
        };
        program.visit_with(&mut cases);
        cases.opcodes
    })
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

/// Call path to `new Error()` in the stack probe. The listener enters the probe function, which
/// calls a closure that constructs the error.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ProbeCalls {
    /// The opcode that constructs `new Error()`.
    pub construct: u8,
    /// How many parameters the probe function declares.
    pub arity: usize,
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

/// Recovers frames for the stack probe. The VM executes closures in its dispatch loop without
/// JavaScript calls, so frames stop at the listener that entered the probe. V8 retains only the
/// innermost ten frames.
pub fn recover_probe(source: &str, cases: &CaseOpcodes, calls: ProbeCalls) -> Result<Geometry> {
    geometry(source, cases, |machine| {
        // The probe registers an exception handler, so its instructions dispatch from the
        // guarded loop.
        let mut chain = machine.construction(calls.construct, true)?;
        chain.frames.extend(machine.listener(calls.arity, "")?);
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

/// Dispatch loop called by `run`, with details used to check stack recovery offline.
#[derive(Debug, Serialize)]
pub struct DispatchSummary {
    pub function: String,
    pub guarded: bool,
    /// V8 frames from the dispatch loop to `run`, innermost first.
    pub frames: Vec<String>,
    /// Number of opcodes dispatched by the loop.
    pub opcodes: usize,
    /// Opcodes whose cases do not call a function defined in the script.
    pub unresolved: Vec<u8>,
}

/// Summarizes dispatch loops called by `run`, including whether each case resolves to a function.
pub fn dispatch_summary(source: &str, cases: &CaseOpcodes) -> Result<Vec<DispatchSummary>> {
    deobfuscate::read_decoded(source.to_owned(), |program, start| {
        let machine = Machine::new(program, start, cases)?;
        let script = &machine.script;
        let mut summaries = Vec::new();
        for dispatch_loop in &machine.loops {
            let function = script.function(&dispatch_loop.name)?;
            let scope = Scope::new(&dispatch_loop.name.0, function, &script.appliers);
            let mut opcodes = 0;
            let mut unresolved = Vec::new();
            for case in cases_of(function) {
                let Some(&opcode) = cases.0.get(&offsets(case.span, start)) else {
                    continue;
                };
                opcodes += 1;
                let resolved = scope.target(&case.call).is_ok_and(|target| {
                    target
                        .callee
                        .is_some_and(|callee| script.function(&callee).is_ok())
                });
                if !resolved {
                    unresolved.push(opcode);
                }
            }
            let frames = dispatch_loop.call.frames(Name::same("run".to_owned()));
            summaries.push(DispatchSummary {
                function: dispatch_loop.name.0.to_string(),
                guarded: dispatch_loop.guarded,
                frames: frames.into_iter().map(|call| call.name.v8).collect(),
                opcodes,
                unresolved,
            });
        }
        Ok(summaries)
    })
}

/// Parses `source` and places the frames `recover` finds in it as each engine reports them.
fn geometry(
    source: &str,
    cases: &CaseOpcodes,
    mut recover: impl FnMut(&Machine<'_>) -> Result<Chain>,
) -> Result<Geometry> {
    deobfuscate::read_decoded(source.to_owned(), |program, start| {
        let Chain { frames, reflected } = recover(&Machine::new(program, start, cases)?)?;
        let frame = |function: String, at: BytePos| -> Result<Frame> {
            let offset = (at.0 - start.0) as usize;
            let prefix = source.get(..offset).context("invalid source byte offset")?;
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
    })
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

/// A call site's position for each engine: see [`call_position`] and [`arguments_position`].
#[derive(Clone, Copy, Debug)]
struct Site {
    v8: BytePos,
    jsc: BytePos,
}

impl Site {
    fn new(call: &CallExpr) -> Self {
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

/// The VM dispatch method, its runner, and listeners that wrap the runner for each closure
/// parameter count.
struct Machine<'script> {
    script: Script,
    dispatch: DispatchMethod,
    /// The dispatch loops `run` calls.
    loops: Vec<DispatchLoop>,
    cases: &'script CaseOpcodes,
    start: BytePos,
    runner: Call,
    listeners: Vec<Invocation>,
}

impl<'script> Machine<'script> {
    fn new(program: &Program, start: BytePos, cases: &'script CaseOpcodes) -> Result<Self> {
        let mut script = Script::new(program);
        let classes = mem::take(&mut script.classes);
        // The runner passes the closure's program counter, key, and arguments to `run`,
        // copying arguments when required by the VM function.
        let mut runners = Vec::new();
        for (name, function) in &script.functions {
            for call in calls_of(function) {
                let calls_run = call
                    .callee
                    .as_expr()
                    .and_then(|callee| callee.as_member())
                    .is_some_and(|member| ast::member_str(&member.prop) == Some("run"));
                if calls_run && call.args.len() == 3 && call.args[2].expr.is_cond() {
                    runners.push((name, call));
                }
            }
        }
        let (runner, run_call) = candidates::exactly_one(runners, "closure-to-VM runner call")?;
        let mut listeners = Listeners {
            runner,
            appliers: &script.appliers,
            found: Vec::new(),
        };
        program.visit_with(&mut listeners);
        let listeners: Vec<Invocation> = listeners.found.into_iter().collect::<Result<_>>()?;
        let dispatches = classes.into_iter().filter_map(|dispatch| {
            let loops = dispatch_loops(&script, &dispatch.run);
            (!loops.is_empty()).then_some((dispatch, loops))
        });
        let (dispatch, loops) = candidates::exactly_one(dispatches, "VM dispatch method")?;
        Ok(Self {
            runner: Call {
                name: Name::same(runner.0.to_string()),
                site: Site::new(&run_call),
            },
            listeners,
            dispatch,
            loops,
            script,
            cases,
            start,
        })
    }

    /// Finds the handler for `opcode` in the dispatch loop with or without exception handling.
    fn handler(&self, opcode: u8, guarded: bool) -> Result<Handler<'_>> {
        for dispatch_loop in &self.loops {
            if dispatch_loop.guarded != guarded {
                continue;
            }
            let function = self.script.function(&dispatch_loop.name)?;
            let Some(case) = cases_of(function)
                .into_iter()
                .find(|case| self.cases.0.get(&offsets(case.span, self.start)) == Some(&opcode))
            else {
                continue;
            };
            let scope = Scope::new(&dispatch_loop.name.0, function, &self.script.appliers);
            let dispatch = scope.target(&case.call)?;
            let handler = dispatch
                .callee
                .clone()
                .with_context(|| format!("opcode {opcode}'s dispatch calls no named handler"))?;
            let frame = Name {
                v8: if dispatch.method {
                    format!("{}.{}", self.dispatch.class, handler.0)
                } else {
                    handler.0.to_string()
                },
                jsc: handler.0.to_string(),
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

    /// Appends frames from the call to `handler` through the dispatch loop, `run`, and the runner.
    fn entered(&self, handler: &Handler<'_>, mut frames: Vec<Call>) -> Vec<Call> {
        let DispatchMethod { class, key, .. } = &self.dispatch;
        let dispatch_loop = handler.dispatch_loop;
        frames.extend(
            handler
                .dispatch
                .frames(Name::same(dispatch_loop.name.0.to_string())),
        );
        frames.extend(dispatch_loop.call.frames(Name {
            v8: format!("{class}.run"),
            jsc: key.clone().unwrap_or_default(),
        }));
        frames.push(self.runner.clone());
        frames
    }

    /// Returns frames from error construction through the opcode handler to the runner. Uses the
    /// single construction site in the handler, preferring `Reflect.construct` over `new` without
    /// arguments.
    fn construction(&self, opcode: u8, guarded: bool) -> Result<Chain> {
        let handler = self.handler(opcode, guarded)?;
        let function = self.script.function(&handler.name)?;
        let scope = Scope::new(&handler.name.0, function, &self.script.appliers);
        let mut found = Vec::new();
        for call in calls_of(function) {
            let target = scope.target(&call)?;
            // Find `Reflect.construct` in a binding or array slot, called directly or through a
            // helper.
            let named = target
                .callee
                .as_ref()
                .is_some_and(|callee| self.script.constructs.contains(callee));
            let slotted = target
                .slot
                .as_ref()
                .is_some_and(|slot| self.script.construct_slots.contains(slot));
            if named || slotted {
                found.push(target.frames(handler.frame.clone()));
            }
        }
        let reflected = !found.is_empty();
        if !reflected {
            #[derive(Default)]
            struct News(Vec<Site>);
            impl Visit for News {
                fn visit_function(&mut self, _: &Function) {}
                fn visit_class(&mut self, _: &Class) {}
                // Ignore guard exceptions; they do not produce the handler's constructed value.
                fn visit_throw_stmt(&mut self, _: &ThrowStmt) {}
                fn visit_new_expr(&mut self, construction: &NewExpr) {
                    if construction.args.as_ref().is_none_or(Vec::is_empty) {
                        self.0.push(Site {
                            v8: construction.span.lo,
                            jsc: construction.callee.span().hi,
                        });
                    }
                    construction.visit_children_with(self);
                }
            }
            let mut news = News::default();
            function.body.visit_with(&mut news);
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
                handler.name.0
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
        let function = self.script.function(&handler.name)?;
        let scope = Scope::new(&handler.name.0, function, &self.script.appliers);
        let mut calls = Vec::new();
        for call in calls_of(function) {
            let target = scope.target(&call)?;
            if target.passed == Some(passed + 2)
                && let Some(callee) = &target.callee
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
        let sites: Vec<u32> = listeners
            .iter()
            .map(|target| target.site.v8.0 - self.start.0)
            .collect();
        let listener = candidates::exactly_one(listeners, "listener of the closure's arity")
            .with_context(|| {
                format!("no one listener for a closure of {arity} arguments, at {sites:?}")
            })?;
        Ok(listener.frames(Name::anonymous(name.to_owned())))
    }
}

/// The function `run` calls for an opcode.
struct Handler<'machine> {
    /// Call from the dispatch loop to this handler.
    dispatch: Invocation,
    name: Id,
    frame: Name,
    dispatch_loop: &'machine DispatchLoop,
}

/// Function called by `run` with the machine to dispatch opcodes.
struct DispatchLoop {
    name: Id,
    /// Call from `run`, either direct or through a helper.
    call: Invocation,
    /// Whether the call occurs in a `try` block that handles exceptions.
    guarded: bool,
}

/// Minimum case count for a dispatch switch. Dispatchers have a case per opcode, more than any
/// helper switch.
const DISPATCH_CASES: usize = 40;

/// Finds functions with dispatch switches that `run` calls with the machine.
fn dispatch_loops(script: &Script, run: &Function) -> Vec<DispatchLoop> {
    #[derive(Default)]
    struct Calls {
        found: Vec<(CallExpr, bool)>,
        guarded: bool,
    }
    impl Visit for Calls {
        fn visit_function(&mut self, _: &Function) {}
        fn visit_class(&mut self, _: &Class) {}
        // Only a `try` with a `catch` handles exceptions.
        fn visit_try_stmt(&mut self, statement: &TryStmt) {
            let outer = self.guarded;
            self.guarded |= statement.handler.is_some();
            statement.block.visit_with(self);
            self.guarded = outer;
            statement.handler.visit_with(self);
            statement.finalizer.visit_with(self);
        }
        fn visit_call_expr(&mut self, call: &CallExpr) {
            if call.args.iter().any(|argument| argument.expr.is_this()) {
                self.found.push((call.clone(), self.guarded));
            }
            call.visit_children_with(self);
        }
    }
    let mut calls = Calls::default();
    run.body.visit_with(&mut calls);
    let scope = Scope::new("", run, &script.appliers);
    calls
        .found
        .into_iter()
        .filter_map(|(call, guarded)| {
            let call = scope.target(&call).ok()?;
            let name = call.callee.clone()?;
            let function = script.function(&name).ok()?;
            (cases_of(function).len() > DISPATCH_CASES).then_some(DispatchLoop {
                name,
                call,
                guarded,
            })
        })
        .collect()
}

/// The script's declared and assigned functions, VM dispatch methods, and aliases for
/// `Reflect.construct` and `Reflect.apply`.
struct Script {
    functions: Vec<(Id, Function)>,
    /// Original functions extracted from merged functions, each using the merged function name. See
    /// [`Merged`].
    originals: Vec<(Id, Function)>,
    classes: Vec<DispatchMethod>,
    constructs: Vec<Id>,
    /// Array slots containing `Reflect.construct`, indexed by array and slot.
    construct_slots: Vec<(Id, usize)>,
    applies: Vec<Id>,
    appliers: Appliers,
}

/// Call helpers indexed by name, including selector-based helpers, merged functions, and
/// forwarders. Also records numeric constants used by selectors.
struct Appliers {
    helpers: HashMap<Id, Applier>,
    merged: HashMap<Id, Merged>,
    forwarders: Forwarders,
    /// Bindings assigned a numeric value once, such as a shared case-label mask.
    constants: HashMap<Id, f64>,
}

/// Functions that call their first parameter with the remaining parameters, as recorded by
/// [`Scope`].
#[derive(Default)]
struct Forwarders {
    /// Forwarders indexed by the binding holding their object and their property key.
    on_objects: HashMap<(Holder, String), Forwarder>,
    /// Forwarders copied to bindings, as in `f = object.key`, with the frames produced when called
    /// through those bindings.
    held: HashMap<Holder, Vec<Call>>,
}

impl Forwarders {
    /// Keeps only forwarders whose object bindings are assigned once, so their values are known.
    fn retain_assigned_once(&mut self, assigned: &HashMap<Holder, usize>) {
        let once = |holder: &Holder| assigned.get(holder).is_none_or(|&count| count == 1);
        self.on_objects.retain(|(holder, _), _| once(holder));
        self.held.retain(|holder, _| once(holder));
    }
}

impl Appliers {
    /// Also returns original functions extracted from merged functions, using names described by
    /// [`Merged`].
    fn new(program: &Program, functions: &[(Id, Function)]) -> (Self, Vec<(Id, Function)>) {
        #[derive(Default)]
        struct Constants {
            values: HashMap<Id, f64>,
            assigned: HashSet<Id>,
        }
        impl Visit for Constants {
            fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
                if let Pat::Ident(name) = &declarator.name
                    && let Some(value) = declarator
                        .init
                        .as_deref()
                        .and_then(|init| ast::fold_number(init, &|_| None))
                {
                    self.values.insert(name.to_id(), value);
                }
                declarator.visit_children_with(self);
            }
            fn visit_assign_expr(&mut self, assign: &AssignExpr) {
                if let Some(name) = assign.left.as_ident() {
                    self.assigned.insert(name.to_id());
                }
                assign.visit_children_with(self);
            }
        }
        let mut constants = Constants::default();
        program.visit_with(&mut constants);
        constants
            .values
            .retain(|name, _| !constants.assigned.contains(name));
        let values = constants.values;
        let applier = |(name, function): &(Id, Function)| {
            Some((name.clone(), Applier::new(function, &values)?))
        };
        let mut helpers: HashMap<Id, Applier> = functions.iter().filter_map(applier).collect();
        let mut merged = HashMap::new();
        let mut originals = Vec::new();
        for (name, function) in functions {
            if !helpers.contains_key(name)
                && let Some((selection, held)) = Merged::new(name, function, &values)
            {
                merged.insert(name.clone(), selection);
                originals.extend(held);
            }
        }
        // A merged function may hold call helpers.
        helpers.extend(originals.iter().filter_map(applier));
        let mut appliers = Self {
            helpers,
            merged,
            forwarders: Forwarders::default(),
            constants: values,
        };
        appliers.forwarders = forwarders(program, &appliers);
        (appliers, originals)
    }

    /// Evaluates `expression` using numeric literals and known constants.
    fn number(&self, expression: &Expr) -> Option<f64> {
        number(expression, &self.constants)
    }
}

/// Collects forwarders from each function via [`Scope`]. Keeps only those whose object bindings are
/// assigned once.
fn forwarders(program: &Program, appliers: &Appliers) -> Forwarders {
    struct Collect<'script> {
        appliers: &'script Appliers,
        found: Forwarders,
        assigned: HashMap<Holder, usize>,
    }
    impl Collect<'_> {
        fn scope(&mut self, name: &str, function: &Function) {
            let scope = Scope::new(name, function, self.appliers);
            self.found.on_objects.extend(scope.forwarders.on_objects);
            self.found.held.extend(scope.forwarders.held);
            for (holder, count) in scope.assigned {
                *self.assigned.entry(holder).or_default() += count;
            }
            function.visit_children_with(self);
        }
    }
    impl Visit for Collect<'_> {
        fn visit_fn_decl(&mut self, declaration: &FnDecl) {
            self.scope(&declaration.ident.sym, &declaration.function);
        }
        fn visit_fn_expr(&mut self, expression: &FnExpr) {
            let name = expression.ident.as_ref().map_or("", |name| &*name.sym);
            self.scope(name, &expression.function);
        }
        fn visit_function(&mut self, function: &Function) {
            self.scope("", function);
        }
    }
    let mut collect = Collect {
        appliers,
        found: Forwarders::default(),
        assigned: HashMap::new(),
    };
    program.visit_with(&mut collect);
    collect.found.retain_assigned_once(&collect.assigned);
    collect.found
}

/// Evaluates `expression` using literals and `constants`.
fn number(expression: &Expr, constants: &HashMap<Id, f64>) -> Option<f64> {
    ast::fold_number(expression, &|leaf| {
        constants.get(&leaf.as_ident()?.to_id()).copied()
    })
}

/// Finds the VM class method `run` that calls the dispatch loops.
struct DispatchMethod {
    class: String,
    run: Function,
    /// The method's literal property key, if present.
    key: Option<String>,
}

impl Script {
    fn new(program: &Program) -> Self {
        // The decoded AST retains resolver contexts, so equal names in different
        // lexical scopes have distinct IDs while frame names keep their original spelling.
        let functions = ast::named_functions(program);
        let (appliers, originals) = Appliers::new(program, &functions);
        let mut script = Self {
            functions,
            originals,
            classes: Vec::new(),
            constructs: Vec::new(),
            construct_slots: Vec::new(),
            applies: Vec::new(),
            appliers,
        };
        program.visit_with(&mut script);
        script
    }

    fn function(&self, name: &Id) -> Result<&Function> {
        self.functions
            .iter()
            .chain(&self.originals)
            .find(|(function_name, _)| function_name == name)
            .map(|(_, function)| function)
            .with_context(|| format!("missing original function {}", name.0))
    }

    /// Returns frames for the function bound to `name` if it forwards a method call. Allows
    /// local variable declarations before the return.
    fn method_forwarder(&self, name: &Id) -> Option<Vec<Call>> {
        let function = self.function(name).ok()?;
        let parameters = parameters(function)?;
        let [method, receiver, ..] = parameters.as_slice() else {
            return None;
        };
        let (Stmt::Return(returned), declarations) = function.body.as_ref()?.stmts.split_last()?
        else {
            return None;
        };
        if !declarations
            .iter()
            .all(|statement| matches!(statement, Stmt::Decl(Decl::Var(_))))
        {
            return None;
        }
        let mut value = returned.arg.as_deref()?.unwrap_parens();
        if let Expr::Seq(sequence) = value {
            value = sequence.exprs.last()?.unwrap_parens();
        }
        let call = value.as_call()?;
        let target = Scope::new(&name.0, function, &self.appliers)
            .target(call)
            .ok()?;
        // Compare bindings so a nested function with the same name as a native apply
        // alias cannot be mistaken for that alias.
        let callee = target.callee.as_ref()?;
        if self.function(callee).is_ok() && !self.applies.iter().any(|alias| alias == callee) {
            return None;
        }
        let [first, second, ..] = handed(call, &target)?[..] else {
            return None;
        };
        (self::name(first).as_ref() == Some(method)
            && self::name(second).as_ref() == Some(receiver))
        .then(|| target.frames(Name::same(name.0.to_string())))
    }
}

impl Visit for Script {
    fn visit_assign_expr(&mut self, assign: &AssignExpr) {
        // Track `Reflect.construct` and `Reflect.apply` in bindings or array slots, including
        // indirect references to `Reflect`. Visit child expressions to record every target in a
        // chained assignment.
        let mut value = &*assign.right;
        while let Expr::Assign(inner) = value.unwrap_parens() {
            value = &inner.right;
        }
        if let Expr::Member(member) = value.unwrap_parens() {
            let method = ast::member_str(&member.prop);
            match (assign.left.as_ident(), method) {
                (Some(name), Some("construct")) => self.constructs.push(name.to_id()),
                (Some(name), Some("apply")) => self.applies.push(name.to_id()),
                _ => {}
            }
            if method == Some("construct")
                && let AssignTarget::Simple(SimpleAssignTarget::Member(slot)) = &assign.left
                && let Some(array) = slot.obj.as_ident()
                && let Some(index) = slot.prop.as_computed()
                && let Some(index) = self.appliers.number(&index.expr).and_then(ast::array_index)
            {
                self.construct_slots.push((array.to_id(), index));
            }
        }
        assign.visit_children_with(self);
    }

    fn visit_class_decl(&mut self, declaration: &ClassDecl) {
        let run = declaration
            .class
            .body
            .iter()
            .filter_map(ClassMember::as_method)
            .find(|method| ast::static_key_str(&method.key) == Some("run"));
        if let Some(method) = run {
            self.classes.push(DispatchMethod {
                class: declaration.ident.sym.to_string(),
                run: (*method.function).clone(),
                key: ast::key_str(&method.key).map(str::to_owned),
            });
        }
        declaration.visit_children_with(self);
    }
}

fn name(expression: &Expr) -> Option<Id> {
    Some(expression.unwrap_parens().as_ident()?.to_id())
}

/// The names of a function's parameters, if they are all plain names.
fn parameters(function: &Function) -> Option<Vec<Id>> {
    function
        .params
        .iter()
        .map(|parameter| Some(parameter.pat.as_ident()?.to_id()))
        .collect()
}

/// Returns the arguments `call` forwards to the callee identified by `target`. Skips leading
/// selectors, callee, and receiver. The forwarded arguments are either the trailing call arguments
/// or the trailing elements of an apply-helper argument list.
fn handed<'call>(call: &'call CallExpr, target: &Invocation) -> Option<Vec<&'call Expr>> {
    let arguments: Vec<&Expr> = if target.listed {
        let list = call.args.last()?.expr.unwrap_parens().as_array()?;
        list.elems
            .iter()
            .map(|element| element.as_ref().map(|element| &*element.expr))
            .collect::<Option<_>>()?
    } else {
        call.args.iter().map(|argument| &*argument.expr).collect()
    };
    let start = arguments.len().checked_sub(target.passed?)?;
    Some(arguments[start..].to_vec())
}

/// Checks whether `call` forwards two captured values followed by `function`'s leading
/// parameters, as a closure-factory listener does. The function may also declare trailing
/// parameters used as local variables.
fn forwards_parameters(function: &Function, call: &CallExpr, target: &Invocation) -> bool {
    let (Some(handed), Some(parameters)) = (handed(call, target), parameters(function)) else {
        return false;
    };
    let Some(forwarded) = handed.get(2..) else {
        return false;
    };
    forwarded.len() <= parameters.len()
        && forwarded
            .iter()
            .zip(parameters)
            .all(|(argument, parameter)| name(argument) == Some(parameter))
}

/// Arrays a function fills with names before reading them back, such as `g = [f, a]` read as
/// `g[0]` and `g[1]`.
struct Copies<'constants> {
    arrays: HashMap<Id, Vec<Id>>,
    /// Known constants used to evaluate array indices.
    constants: &'constants HashMap<Id, f64>,
}

impl<'constants> Copies<'constants> {
    fn new(constants: &'constants HashMap<Id, f64>) -> Self {
        Self {
            arrays: HashMap::new(),
            constants,
        }
    }

    /// Records `expression` if it is `array = [name, ...]`.
    fn record(&mut self, expression: &Expr) -> Option<()> {
        let assign = expression.as_assign()?;
        let array = assign.left.as_ident()?;
        let names: Option<Vec<Id>> = assign
            .right
            .as_array()?
            .elems
            .iter()
            .map(|element| name(&element.as_ref()?.expr))
            .collect();
        self.arrays.insert(array.to_id(), names?);
        Some(())
    }

    /// The name `expression` reads, directly or through an element of a copied array.
    fn resolve(&self, expression: &Expr) -> Option<Id> {
        match expression.unwrap_parens() {
            Expr::Ident(name) => Some(name.to_id()),
            Expr::Member(member) => {
                let (Expr::Ident(array), MemberProp::Computed(index)) =
                    (&*member.obj, &member.prop)
                else {
                    return None;
                };
                let index = ast::array_index(number(&index.expr, self.constants)?)?;
                self.arrays.get(&array.to_id())?.get(index).cloned()
            }
            _ => None,
        }
    }
}

/// JavaScriptCore's call position: the opening argument parenthesis, which in minified source
/// immediately precedes the first argument. Decoding may change the callee's parentheses but
/// preserves argument positions.
fn arguments_position(call: &CallExpr) -> BytePos {
    match call.args.first() {
        Some(first) => first.span().lo - BytePos(1),
        None => call.span.hi - BytePos(2),
    }
}

/// V8's call position: the method or function name, else JavaScriptCore's position.
fn call_position(call: &CallExpr) -> BytePos {
    match &call.callee {
        Callee::Expr(callee) => match &**callee {
            Expr::Member(member) => match &member.prop {
                MemberProp::Ident(property) => property.span.lo,
                _ => callee.span().hi,
            },
            Expr::Ident(_) => call.span.lo,
            _ => arguments_position(call),
        },
        _ => call.span.lo,
    }
}

/// Finds the first call in a dispatch case.
struct Case {
    span: Span,
    call: CallExpr,
}

fn cases_of(function: &Function) -> Vec<Case> {
    #[derive(Default)]
    struct Cases(Vec<Case>);
    // Visitors inspect only the supplied body. Skip nested functions and classes, but include
    // arrows.
    impl Visit for Cases {
        fn visit_function(&mut self, _: &Function) {}
        fn visit_class(&mut self, _: &Class) {}
        fn visit_switch_case(&mut self, case: &SwitchCase) {
            if case.test.is_some() {
                let mut calls = Calls::default();
                case.cons.visit_with(&mut calls);
                if let Some(call) = calls.0.into_iter().next() {
                    self.0.push(Case {
                        span: case.span,
                        call,
                    });
                }
            }
            case.visit_children_with(self);
        }
    }
    let mut cases = Cases::default();
    function.body.visit_with(&mut cases);
    cases.0
}

/// Calls made by a function's own body, excluding nested functions.
#[derive(Default)]
struct Calls(Vec<CallExpr>);

impl Visit for Calls {
    fn visit_function(&mut self, _: &Function) {}
    fn visit_class(&mut self, _: &Class) {}
    fn visit_call_expr(&mut self, call: &CallExpr) {
        self.0.push(call.clone());
        call.visit_children_with(self);
    }
}

fn calls_of(function: &Function) -> Vec<CallExpr> {
    let mut calls = Calls::default();
    function.body.visit_with(&mut calls);
    calls.0
}

/// A call's target, resolved through helper functions.
struct Invocation {
    callee: Option<Id>,
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
    slot: Option<(Id, usize)>,
}

impl Invocation {
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

/// Recovers the XOR mask and call cases of a selector-based helper. Calls can use `Reflect.apply(f,
/// _, list)` or `f(a, b)` with later parameters forwarded in order.
///
/// Handles copied selectors such as `(s = [selector], mask ^ s[0])`, indirect references to
/// `apply`, copied arguments such as `(g = [f, a], (0, g[0])(g[1]))`, and masks or labels computed
/// from constants.
struct Applier {
    mask: f64,
    cases: Vec<ApplierCase>,
}

struct ApplierCase {
    label: f64,
    site: Site,
}

impl Applier {
    fn new(function: &Function, constants: &HashMap<Id, f64>) -> Option<Self> {
        let parameters = parameters(function)?;
        let [selector, applied, rest @ ..] = parameters.as_slice() else {
            return None;
        };
        let (mask, switch, copies) = selection(function, selector, constants)?;
        // Match `f(a, b)` when arguments follow parameter order.
        let passes_on = |call: &CallExpr| {
            let Some(callee) = call.callee.as_expr() else {
                return false;
            };
            let (callee, _) = undetached(callee, constants);
            copies.resolve(callee).as_ref() == Some(applied)
                && call.args.len() <= rest.len()
                && call.args.iter().zip(rest).all(|(argument, parameter)| {
                    argument.spread.is_none()
                        && copies.resolve(&argument.expr).as_ref() == Some(parameter)
                })
        };
        let applies = |call: &CallExpr| {
            let [first, _, third] = &call.args[..] else {
                return false;
            };
            call.callee
                .as_expr()
                .is_some_and(|callee| callee.unwrap_parens().is_member())
                && name(&first.expr).as_ref() == Some(applied)
                && rest
                    .first()
                    .is_some_and(|list| name(&third.expr).as_ref() == Some(list))
        };
        let cases: Vec<ApplierCase> = switch
            .cases
            .iter()
            .filter_map(|case| {
                let label = number(case.test.as_deref()?, constants)?;
                let [Stmt::Return(returned)] = &case.cons[..] else {
                    return None;
                };
                let Some(Expr::Call(call)) = returned.arg.as_deref().map(Expr::unwrap_parens)
                else {
                    return None;
                };
                (applies(call) || passes_on(call)).then(|| ApplierCase {
                    label,
                    site: Site::new(call),
                })
            })
            .collect();
        // Other cases may call more helpers. Selectors routed there have no case in this helper.
        (!cases.is_empty()).then_some(Self { mask, cases })
    }

    /// The `Reflect.apply` call in the case `selector` selects.
    fn call(&self, selector: f64) -> Option<Site> {
        let chosen = f64::from(js::int32(self.mask) ^ js::int32(selector));
        self.cases
            .iter()
            .find(|case| case.label == chosen)
            .map(|case| case.site)
    }
}

/// Extracts the mask and switch from a function containing `switch (selector ^ mask)`, with
/// optional leading local declarations. Also tracks arrays used to copy selector names, as in `(s =
/// [selector], mask ^ s[0])`.
fn selection<'function, 'constants>(
    function: &'function Function,
    selector: &Id,
    constants: &'constants HashMap<Id, f64>,
) -> Option<(f64, &'function SwitchStmt, Copies<'constants>)> {
    let [Stmt::Switch(switch)] = after_declarations(&function.body.as_ref()?.stmts) else {
        return None;
    };
    let mut discriminant = switch.discriminant.unwrap_parens();
    let mut copies = Copies::new(constants);
    if let Expr::Seq(sequence) = discriminant {
        let (last, before) = sequence.exprs.split_last()?;
        for expression in before {
            copies.record(expression);
        }
        discriminant = last.unwrap_parens();
    }
    let xor = discriminant
        .as_bin()
        .filter(|xor| xor.op == BinaryOp::BitXor)?;
    let is_selector = |expression: &Expr| copies.resolve(expression).as_ref() == Some(selector);
    let mask = match (xor.left.unwrap_parens(), xor.right.unwrap_parens()) {
        (other, mask) | (mask, other) if is_selector(other) => number(mask, constants)?,
        _ => return None,
    };
    Some((mask, switch, copies))
}

/// Returns `statements` after skipping leading local declarations without initializers.
fn after_declarations(statements: &[Stmt]) -> &[Stmt] {
    let start = statements
        .iter()
        .position(|statement| {
            !matches!(statement, Stmt::Decl(Decl::Var(declaration))
                if declaration.decls.iter().all(|declarator| declarator.init.is_none()))
        })
        .unwrap_or(statements.len());
    &statements[start..]
}

/// A function combining several original functions, selected by its first parameter:
///
/// ```js
/// function merged(selector, a) { switch (selector ^ mask) { case 1: { <original> } return; } }
/// ```
///
/// Both V8 and JavaScriptCore name every original function's frame after the merged function.
/// Recovery gives each original a fresh binding with that name and keeps the other parameters.
struct Merged {
    mask: f64,
    /// Original function for each case label, indexed into [`Script::originals`].
    cases: Vec<(f64, Id)>,
}

impl Merged {
    fn new(
        name: &Id,
        function: &Function,
        constants: &HashMap<Id, f64>,
    ) -> Option<(Self, Vec<(Id, Function)>)> {
        let selector = function.params.first()?.pat.as_ident()?.to_id();
        let (mask, switch, _) = selection(function, &selector, constants)?;
        let block = function.body.as_ref()?;
        let mut cases = Vec::new();
        let mut originals = Vec::new();
        for (at, case) in switch.cases.iter().enumerate() {
            let label = case
                .test
                .as_deref()
                .and_then(|test| number(test, constants));
            // Labels sharing a body fall through to it.
            let body = switch.cases[at..]
                .iter()
                .map(|case| &case.cons)
                .find(|body| !body.is_empty());
            let (Some(label), Some(body)) = (label, body) else {
                continue;
            };
            let mut statements: Vec<Stmt> = match &body[..] {
                [Stmt::Block(original), rest @ ..] => {
                    original.stmts.iter().chain(rest).cloned().collect()
                }
                _ => body.clone(),
            };
            if let Some(Stmt::Return(ReturnStmt { arg: None, .. })) = statements.last() {
                statements.pop();
            }
            let original = Function {
                params: function.params[1..].to_vec(),
                span: function.span,
                ctxt: function.ctxt,
                body: Some(BlockStmt {
                    span: block.span,
                    ctxt: block.ctxt,
                    stmts: statements,
                }),
                ..Function::default()
            };
            let binding = (
                name.0.clone(),
                SyntaxContext::empty().apply_mark(Mark::new()),
            );
            cases.push((label, binding.clone()));
            originals.push((binding, original));
        }
        (!cases.is_empty()).then_some((Self { mask, cases }, originals))
    }

    /// Returns the original function selected by `selector`.
    fn original(&self, selector: f64) -> Option<&Id> {
        let chosen = f64::from(js::int32(self.mask) ^ js::int32(selector));
        self.cases
            .iter()
            .find(|(label, _)| *label == chosen)
            .map(|(_, original)| original)
    }
}

/// Storage location in a scope: a binding or a constant array slot.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Holder {
    Name(Id),
    Slot(Id, usize),
}

/// A function's local aliases, string constants, and forwarders.
struct Scope<'script> {
    appliers: &'script Appliers,
    /// V8's name prefix for functions assigned here, such as `Owner.`.
    prefix: String,
    forwarders: Forwarders,
    /// Assignment count for each storage location. Only values assigned once are known.
    assigned: HashMap<Holder, usize>,
    aliases: HashMap<Id, Id>,
    strings: HashMap<Id, String>,
}

/// Frames for an object function that forwards its first parameter with the remaining arguments.
/// Stores frames innermost first for each call form.
struct Forwarder {
    /// Frames for a method call. V8 adds the computed key: `object.<computed> [as key]`.
    method: Vec<Call>,
    /// Frames for a call through a copied binding or a detached call such as `(0, object.key)(f)`.
    plain: Vec<Call>,
}

impl<'script> Scope<'script> {
    /// `name` is empty for anonymous functions. V8 prefixes the names of functions assigned
    /// inside a capitalized function with its name, as it does for constructors.
    fn new(name: &str, function: &Function, appliers: &'script Appliers) -> Self {
        let constructor = name.starts_with(char::is_uppercase);
        let mut scope = Self {
            appliers,
            prefix: constructor.then(|| format!("{name}.")).unwrap_or_default(),
            forwarders: Forwarders::default(),
            assigned: HashMap::new(),
            aliases: HashMap::new(),
            strings: HashMap::new(),
        };
        function.body.visit_with(&mut scope);
        scope.forwarders.retain_assigned_once(&scope.assigned);
        scope
    }

    fn target(&self, call: &CallExpr) -> Result<Invocation> {
        let mut target = Invocation {
            callee: None,
            method: false,
            helpers: Vec::new(),
            site: Site::new(call),
            passed: None,
            listed: false,
            slot: None,
        };
        let Some(callee) = call.callee.as_expr() else {
            return Ok(target);
        };
        let arguments = call.args.len();
        let (callee, detached) = undetached(callee, &self.appliers.constants);
        // Resolve the function called by `target`.
        let mut function = match callee {
            Expr::Ident(name) => {
                if let Some(original) = self.merged_call(name, call) {
                    // The original function uses the merged function's frame at this call site.
                    let mut target = self.target(&original)?;
                    target.site = Site::new(call);
                    return Ok(target);
                }
                if let Some((applied, function)) = self.applier_call(name, call)? {
                    target = applied;
                    Some(function)
                } else {
                    target.passed = Some(arguments);
                    Some(callee)
                }
            }
            // Some builds keep the key in a local: `handler[c](this)` with `c = "call"`.
            Expr::Member(member)
                if !detached && member.obj.is_ident() && self.key(&member.prop) == Some("call") =>
            {
                target.method = true;
                target.passed = Some(arguments.saturating_sub(1));
                Some(&*member.obj)
            }
            // The first argument to a forwarder is the function it calls.
            Expr::Member(member) if let Some(forwarder) = self.member_forwarder(member) => {
                target.helpers = if detached {
                    forwarder.plain.clone()
                } else {
                    forwarder.method.clone()
                };
                target.passed = Some(arguments.saturating_sub(1));
                call.args.first().map(|first| &*first.expr)
            }
            // Resolve an array-stored function, as in `(0, slots[i])(f, a)`.
            Expr::Member(member) if self.slot(member).is_some() => {
                target.passed = Some(arguments);
                Some(callee)
            }
            _ => None,
        };
        // A stored forwarder calls its first argument with the remaining arguments.
        while let Some(expression) = function
            && let Some(frames) = self.held_by(expression)
            && let Some(first) = handed(call, &target).and_then(|handed| handed.first().copied())
        {
            function = Some(first);
            target.helpers = frames.iter().cloned().chain(target.helpers).collect();
            target.passed = target.passed.map(|passed| passed - 1);
        }
        target.callee = function.and_then(name);
        target.slot = function.and_then(|function| match self.holder(function)? {
            Holder::Slot(array, index) => Some((array, index)),
            Holder::Name(_) => None,
        });
        Ok(target)
    }

    /// Converts `merged(selector, a, b)` to `original(a, b)` for the selected original function.
    fn merged_call(&self, callee: &Ident, call: &CallExpr) -> Option<CallExpr> {
        let merged = self.appliers.merged.get(&callee.to_id())?;
        let (selector, arguments) = call.args.split_first()?;
        let (name, context) = merged
            .original(self.appliers.number(&selector.expr)?)?
            .clone();
        Some(CallExpr {
            callee: Callee::Expr(Box::new(Expr::Ident(Ident::new(
                name,
                callee.span,
                context,
            )))),
            args: arguments.to_vec(),
            ..call.clone()
        })
    }

    /// Resolves `applier(selector, f, [args])` or `applier(selector, f, a, b)` through a call
    /// helper. Also returns the called function `f`.
    fn applier_call<'call>(
        &self,
        callee: &Ident,
        call: &'call CallExpr,
    ) -> Result<Option<(Invocation, &'call Expr)>> {
        let (Some(applier), [selector, function, passed @ ..]) =
            (self.appliers.helpers.get(&callee.to_id()), &call.args[..])
        else {
            return Ok(None);
        };
        let Some(selector) = self.appliers.number(&selector.expr) else {
            return Ok(None);
        };
        let inner = applier
            .call(selector)
            .with_context(|| format!("{} has no case for selector {selector}", callee.sym))?;
        let (passed, listed) = match passed {
            [list] if let Some(list) = list.expr.unwrap_parens().as_array() => {
                (list.elems.len(), true)
            }
            passed => (passed.len(), false),
        };
        let invocation = Invocation {
            callee: None,
            method: false,
            helpers: vec![Call {
                name: Name::same(callee.sym.to_string()),
                site: inner,
            }],
            site: Site::new(call),
            passed: Some(passed),
            listed,
            slot: None,
        };
        Ok(Some((invocation, &function.expr)))
    }

    /// Resolves a member key from a literal or a local string binding.
    fn key<'member>(&'member self, property: &'member MemberProp) -> Option<&'member str> {
        match property {
            MemberProp::Computed(computed) if let Expr::Ident(name) = &*computed.expr => {
                self.strings.get(&name.to_id()).map(String::as_str)
            }
            property => ast::member_str(property),
        }
    }

    /// Finds the forwarder read by `object.key`.
    fn member_forwarder(&self, member: &MemberExpr) -> Option<&Forwarder> {
        let key = (
            self.holder(&member.obj)?,
            self.key(&member.prop)?.to_owned(),
        );
        self.forwarders
            .on_objects
            .get(&key)
            .or_else(|| self.appliers.forwarders.on_objects.get(&key))
    }

    /// Returns frames for the stored forwarder read by `expression`.
    fn held_by(&self, expression: &Expr) -> Option<&Vec<Call>> {
        let holder = self.holder(expression)?;
        self.forwarders
            .held
            .get(&holder)
            .or_else(|| self.appliers.forwarders.held.get(&holder))
    }

    /// Resolves the value read by `expression`, following local aliases.
    fn holder(&self, expression: &Expr) -> Option<Holder> {
        match expression.unwrap_parens() {
            Expr::Ident(name) => Some(Holder::Name(self.object(&name.to_id()))),
            Expr::Member(member) => self.slot(member),
            _ => None,
        }
    }

    /// Resolves `array[index]` when the index is constant.
    fn slot(&self, member: &MemberExpr) -> Option<Holder> {
        let array = member.obj.as_ident()?;
        let index = self.appliers.number(&member.prop.as_computed()?.expr)?;
        Some(Holder::Slot(
            self.object(&array.to_id()),
            ast::array_index(index)?,
        ))
    }

    /// Resolves the object held by `name` through local copies.
    fn object(&self, name: &Id) -> Id {
        let mut name = name;
        for _ in 0..self.aliases.len() {
            match self.aliases.get(name) {
                Some(original) => name = original,
                None => break,
            }
        }
        name.to_owned()
    }

    /// Records the value stored by assigning `value` to `holder`.
    fn bind(&mut self, holder: Holder, value: &Expr) {
        *self.assigned.entry(holder.clone()).or_default() += 1;
        // Chained assignments store the innermost value in each target.
        let mut value = value.unwrap_parens();
        while let Expr::Assign(inner) = value
            && inner.op == AssignOp::Assign
        {
            value = inner.right.unwrap_parens();
        }
        let forwarder = match value {
            Expr::Member(member) if let Some(forwarder) = self.member_forwarder(member) => {
                Some(forwarder.plain.clone())
            }
            value => self.held_by(value).cloned(),
        };
        if let Some(frames) = forwarder {
            self.forwarders.held.insert(holder, frames);
            return;
        }
        match (holder, value) {
            (Holder::Name(name), Expr::Ident(original)) => {
                self.aliases.insert(name, original.to_id());
            }
            (holder, Expr::Object(object)) => self.literal(&holder, object),
            (Holder::Name(name), value) => {
                if let Some(text) = ast::static_str(value) {
                    self.strings.insert(name, text.to_owned());
                }
            }
            _ => {}
        }
    }

    /// Records forwarders defined by an object literal assigned to `holder`. Uses property keys as
    /// function names, including computed keys.
    fn literal(&mut self, holder: &Holder, object: &ObjectLit) {
        for property in &object.props {
            let (key, function) = match property.as_prop().map(|property| &**property) {
                Some(Prop::KeyValue(property)) if let Expr::Fn(function) = &*property.value => {
                    (&property.key, &*function.function)
                }
                Some(Prop::Method(method)) => (&method.key, &*method.function),
                _ => continue,
            };
            let Some(key) = ast::static_key_str(key) else {
                continue;
            };
            if let Some(frames) = self.forwarder(function, Name::same(key.to_owned())) {
                let forwarder = Forwarder {
                    method: frames.clone(),
                    plain: frames,
                };
                self.forwarders
                    .on_objects
                    .insert((holder.clone(), key.to_owned()), forwarder);
            }
        }
    }

    /// Recovers frames, innermost first, for a function that calls its first parameter with
    /// later parameters. Accepts direct calls, array copies such as `(g = [f, b], (0, g[0])(a,
    /// g[1]))`, and call helpers. Extra parameters can act as locals. Allows local declarations
    /// before the call.
    fn forwarder(&self, function: &Function, frame: Name) -> Option<Vec<Call>> {
        let parameters = parameters(function)?;
        let (first, rest) = parameters.split_first()?;
        let mut arrays = Copies::new(&self.appliers.constants);
        let [Stmt::Return(returned)] = after_declarations(&function.body.as_ref()?.stmts) else {
            return None;
        };
        let mut value = returned.arg.as_deref()?.unwrap_parens();
        if let Expr::Seq(sequence) = value {
            let (last, before) = sequence.exprs.split_last()?;
            for expression in before {
                // Obfuscation leaves expressions that do nothing.
                if arrays.record(expression).is_none()
                    && !is_inert(expression, &self.appliers.constants)
                {
                    return None;
                }
            }
            value = last.unwrap_parens();
        }
        // Forwarded arguments must match the parameters after the target function.
        let passes_on = |arguments: &[&Expr]| {
            arguments.len() <= rest.len()
                && arguments.iter().zip(rest).all(|(argument, parameter)| {
                    arrays.resolve(argument).as_ref() == Some(parameter)
                })
        };
        let call = value.as_call()?;
        let (callee, _) = undetached(call.callee.as_expr()?, &self.appliers.constants);
        if call.args.iter().any(|argument| argument.spread.is_some()) {
            return None;
        }
        let arguments: Vec<&Expr> = call.args.iter().map(|argument| &*argument.expr).collect();
        if arrays.resolve(callee).as_ref() == Some(first) && passes_on(&arguments) {
            return Some(vec![Call {
                name: frame,
                site: Site::new(call),
            }]);
        }
        // Resolve copied names passed through a call helper.
        let mut call = call.clone();
        for argument in &mut call.args {
            let copied = match argument.expr.unwrap_parens() {
                Expr::Array(list) => {
                    let mut list = list.clone();
                    for element in list.elems.iter_mut().flatten() {
                        if let Some(name) = arrays.resolve(&element.expr) {
                            *element.expr =
                                Expr::Ident(Ident::new(name.0, element.expr.span(), name.1));
                        }
                    }
                    Expr::Array(list)
                }
                expression => match arrays.resolve(expression) {
                    Some(name) => Expr::Ident(Ident::new(name.0, expression.span(), name.1)),
                    None => continue,
                },
            };
            *argument.expr = copied;
        }
        let target = self.target(&call).ok()?;
        (!target.helpers.is_empty()
            && target.callee.as_ref() == Some(first)
            && passes_on(&handed(&call, &target)?))
        .then(|| target.frames(frame))
    }
}

/// Whether `expression` has no effect, such as obfuscation's `true`, constant comparisons and
/// Matches `void` expressions, including those using numeric `constants`.
fn is_inert(expression: &Expr, constants: &HashMap<Id, f64>) -> bool {
    let inert = |expression: &Expr| is_inert(expression, constants);
    match expression.unwrap_parens() {
        Expr::Lit(_) => true,
        Expr::Ident(name) => constants.contains_key(&name.to_id()),
        Expr::Bin(binary) => inert(&binary.left) && inert(&binary.right),
        Expr::Unary(unary) => unary.op != UnaryOp::Delete && inert(&unary.arg),
        Expr::Array(array) => array
            .elems
            .iter()
            .all(|element| element.as_ref().is_none_or(|element| inert(&element.expr))),
        _ => false,
    }
}

/// Resolves the function produced by `callee` and checks whether a side-effect-free first operand
/// detaches its receiver. For example, `(0, f)(a)` calls `f` without a receiver.
fn undetached<'expression>(
    callee: &'expression Expr,
    constants: &HashMap<Id, f64>,
) -> (&'expression Expr, bool) {
    let callee = callee.unwrap_parens();
    if let Expr::Seq(sequence) = callee
        && let [discarded, last] = &sequence.exprs[..]
        && is_inert(discarded, constants)
    {
        return (last.unwrap_parens(), true);
    }
    (callee, false)
}

impl Visit for Scope<'_> {
    fn visit_function(&mut self, _: &Function) {}
    fn visit_class(&mut self, _: &Class) {}

    fn visit_assign_expr(&mut self, assign: &AssignExpr) {
        if assign.op == AssignOp::Assign {
            match &assign.left {
                AssignTarget::Simple(SimpleAssignTarget::Ident(name)) => {
                    self.bind(Holder::Name(name.to_id()), &assign.right);
                }
                AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
                    if let Some(slot) = self.slot(member) {
                        self.bind(slot, &assign.right);
                    } else if let Expr::Fn(function) = &*assign.right
                        && let Some(object) = self.holder(&member.obj)
                        && let Some(path) = inferred_path(&member.obj)
                        && let Some(name) = ast::member_str(&member.prop)
                    {
                        // V8 infers the name of an anonymous function from the member it is
                        // assigned to.
                        let path = format!("{}{path}", self.prefix);
                        let (inferred, method) = if member.prop.is_computed() {
                            let inferred = format!("{path}.<computed>");
                            (inferred.clone(), format!("{inferred} [as {name}]"))
                        } else {
                            let inferred = format!("{path}.{name}");
                            (inferred.clone(), inferred)
                        };
                        let frames = |name: String| {
                            self.forwarder(&function.function, Name::anonymous(name))
                        };
                        if let (Some(method), Some(plain)) = (frames(method), frames(inferred)) {
                            self.forwarders
                                .on_objects
                                .insert((object, name.to_owned()), Forwarder { method, plain });
                        }
                    }
                }
                _ => {}
            }
        }
        assign.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Pat::Ident(name) = &declarator.name
            && let Some(init) = &declarator.init
        {
            self.bind(Holder::Name(name.to_id()), init);
        }
        declarator.visit_children_with(self);
    }
}

/// Returns the V8 name inferred from an assignment target: `object` for an object or
/// `array.<computed>` for an array slot.
fn inferred_path(object: &Expr) -> Option<String> {
    match object.unwrap_parens() {
        Expr::Ident(name) => Some(name.sym.to_string()),
        Expr::Member(member) if member.prop.is_computed() => {
            Some(format!("{}.<computed>", member.obj.as_ident()?.sym))
        }
        _ => None,
    }
}

/// Finds runner calls from closure-factory listeners, including calls made through helpers, and
/// records calls it cannot resolve. Each listener forwards its captured machine and layout
/// followed by its own arguments.
struct Listeners<'script> {
    runner: &'script Id,
    appliers: &'script Appliers,
    found: Vec<Result<Invocation>>,
}

impl Visit for Listeners<'_> {
    fn visit_function(&mut self, function: &Function) {
        let scope = Scope::new("", function, self.appliers);
        for call in calls_of(function) {
            match scope.target(&call) {
                // A listener passes the captured machine and layout, then its own
                // parameters. Other scopes may reuse the runner's name for another function,
                // and the message handler starts the runner with computed arguments.
                Ok(mut target)
                    if target.callee.as_ref() == Some(self.runner)
                        && forwards_parameters(function, &call, &target) =>
                {
                    target.passed = target.passed.map(|passed| passed - 2);
                    self.found.push(Ok(target));
                }
                Ok(_) => {}
                Err(error) => self.found.push(Err(error)),
            }
        }
        function.visit_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appliers_may_copy_their_selector_and_name_apply_indirectly() {
        for source in [
            "function j(s,f,a){switch(5^s){case 6:return Reflect.apply(f,void 0,a)}}",
            "function j(s,f,a,e,c,n){switch(e={},c=`apply`,n=[s],5^n[0]){case 6:return Reflect[c](f,void 0,a)}}",
            "var j;j=function(s,f,a){switch(5^s){case 6:return Reflect.apply(f,void 0,a)}}",
        ] {
            let (script, _) = script(source);
            let applier = &script.appliers.helpers[&binding(&script, "j")];
            assert!(applier.call(3.0).is_some(), "{source}");
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
        let (script, _) = script(source);
        let frames = script.method_forwarder(&binding(&script, "PA")).unwrap();
        let names: Vec<&str> = frames.iter().map(|call| call.name.v8.as_str()).collect();
        assert_eq!(names, ["PA.o.<computed> [as k]", "PA"]);
        assert!(script.method_forwarder(&binding(&script, "S")).is_none());
    }

    #[test]
    fn same_named_functions_resolve_to_the_called_binding() {
        let (script, _) = script(
            "function outer(){function h(){wrong()} h()} function h(){right()} function caller(){h()}",
        );
        let target = first_target(&script, "caller");
        let handler = script.function(target.callee.as_ref().unwrap()).unwrap();
        assert_eq!(
            name(calls_of(handler)[0].callee.as_expr().unwrap())
                .unwrap()
                .0,
            "right"
        );
    }

    #[test]
    fn shadowed_appliers_and_runners_are_distinct_bindings() {
        let (script, _) = script(
            "function runner(){} function j(s,f,a){switch(5^s){case 6:return Reflect.apply(f,void 0,a)}} function outer(){function j(){} function runner(){} j(3,f,[]);return function(a){runner(vm,layout,a);j(3,f,[])}} function real(a){runner(vm,layout,a)}",
        );
        let runner = first_target(&script, "real").callee.unwrap();
        let mut listeners = Listeners {
            runner: &runner,
            appliers: &script.appliers,
            found: Vec::new(),
        };
        // Visit every collected body, including the anonymous listener inside outer.
        for (_, function) in &script.functions {
            function.visit_with(&mut listeners);
        }
        assert_eq!(listeners.found.len(), 1);
        let target = first_target(&script, "outer");
        assert!(target.helpers.is_empty());
        assert_eq!(target.passed, Some(3));
        let callee = target.callee.expect("the call has a named callee");
        assert!(!script.appliers.helpers.contains_key(&callee));
    }

    #[test]
    fn native_apply_alias_does_not_match_a_shadowed_function() {
        let (script, _) = script(
            "var B=Reflect.apply; function outer(){function B(){} function wrong(f,r){return B(f,r,[])}} function good(f,r){return B(f,r,[])}",
        );
        assert!(
            script
                .method_forwarder(&binding(&script, "wrong"))
                .is_none()
        );
        assert!(script.method_forwarder(&binding(&script, "good")).is_some());
    }

    #[test]
    fn block_locals_do_not_replace_an_outer_objects_forwarder() {
        let (script, _) = script(
            "function F(){let o={},q=o,c='k';o.k=function(f,a){return f(a)};{let o={},q=o,c='other';o.k=function(f,a){return 0};}return q[c](target,1)}",
        );
        let target = first_target(&script, "F");
        assert_eq!(target.callee.as_ref().unwrap().0, "target");
        assert_eq!(target.helpers.len(), 1);
        assert_eq!(target.helpers[0].name.v8, "F.o.k");
    }

    /// Analyzes `source` and returns the script's starting position.
    fn script(source: &str) -> (Script, BytePos) {
        deobfuscate::read_decoded(source.to_owned(), |program, start| {
            Ok((Script::new(program), start))
        })
        .unwrap()
    }

    fn binding(script: &Script, name: &str) -> Id {
        script
            .functions
            .iter()
            .find(|(id, _)| id.0 == name)
            .unwrap()
            .0
            .clone()
    }

    /// Returns the target of the first call in the script function named `name`.
    fn first_target(script: &Script, name: &str) -> Invocation {
        let function = script.function(&binding(script, name)).unwrap();
        let call = calls_of(function).remove(0);
        Scope::new(name, function, &script.appliers)
            .target(&call)
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
        let (script, _) = script(source);
        let target = first_target(&script, "caller");
        assert_eq!(target.callee.as_ref().unwrap().0, "g");
        let helpers: Vec<&str> = target
            .helpers
            .iter()
            .map(|call| call.name.v8.as_str())
            .collect();
        assert_eq!(helpers, ["e"]);
        assert_eq!(target.passed, Some(1));
        let original = first_target(&script, "other").callee.unwrap();
        assert_eq!(original.0, "e");
        let calls = calls_of(script.function(&original).unwrap());
        assert_eq!(name(calls[0].callee.as_expr().unwrap()).unwrap().0, "h");
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
        let (script, _) = script(source);
        for (caller, expected) in [
            ("direct", &["o.<computed>"][..]),
            ("applied", &["o.<computed>", "a"]),
        ] {
            let target = first_target(&script, caller);
            assert_eq!(target.callee.as_ref().unwrap().0, "loop", "{caller}");
            let helpers: Vec<&str> = target
                .helpers
                .iter()
                .map(|call| call.name.v8.as_str())
                .collect();
            assert_eq!(helpers, expected, "{caller}");
            assert_eq!(target.passed, Some(2), "{caller}");
        }
    }

    #[test]
    fn a_call_key_kept_in_a_local_still_calls_the_handler() {
        let source = "function run(){var c='call';switch(o){case 1:h[c](this);break}}";
        let (script, _) = script(source);
        let target = first_target(&script, "run");
        assert_eq!(target.callee.as_ref().map(|id| id.0.as_ref()), Some("h"));
        assert!(target.method);
        assert_eq!(target.passed, Some(0));
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
        let (script, start) = script(source);
        let target = first_target(&script, "h");
        let frames = target.frames(Name::same("h".to_owned()));
        let names: Vec<_> = frames
            .iter()
            .map(|call| (call.name.v8.as_str(), call.name.jsc.as_str()))
            .collect();
        assert_eq!(names, [("a", "a"), ("h", "h")]);
        let at = |position: BytePos| &source[(position.0 - start.0) as usize..][..2];
        let (applier, handler) = (&frames[0], &frames[1]);
        assert_eq!(at(handler.site.v8), "a(");
        assert_eq!(at(handler.site.jsc), "(1");
        assert_eq!(at(applier.site.jsc), "(f");
    }
}
