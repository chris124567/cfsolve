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

use std::collections::HashMap;
use std::mem;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use swc_core::common::{BytePos, Span, Spanned};
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, BinaryOp, CallExpr, Callee, Class, ClassDecl, ClassMember,
    Decl, Expr, ExprOrSpread, Function, Id, Ident, Lit, MemberProp, NewExpr, Pat, Program,
    SimpleAssignTarget, Stmt, SwitchCase, ThrowStmt, TryStmt, UnaryOp, VarDeclarator,
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
            // JavaScriptCore includes a native `Reflect.construct` frame.
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

/// The stack probe's VM calls, from the program's invocation of the probe to `new Error()`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ProbeCalls {
    /// The opcode that constructs `new Error()`.
    pub construct: u8,
    /// How many parameters the closure that constructs the error declares.
    pub inner: usize,
    /// The opcode with which the probe function calls that closure.
    pub call: u8,
    /// How many arguments that call passes.
    pub passed: usize,
    /// How many parameters the probe function declares.
    pub outer: usize,
    /// The opcode with which the program calls the probe function.
    pub dispatch: u8,
    /// How many arguments that call passes.
    pub dispatched: usize,
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

/// Recovers the stack probe's frames. V8 keeps only the innermost ten.
pub fn recover_probe(source: &str, cases: &CaseOpcodes, calls: ProbeCalls) -> Result<Geometry> {
    geometry(source, cases, |machine| {
        // The probe registers an exception handler, so its instructions dispatch from the
        // guarded loop.
        let mut chain = machine.construction(calls.construct, true)?;
        let frames = &mut chain.frames;
        frames.extend(machine.listener(calls.inner, "")?);
        frames.extend(machine.call(calls.call, calls.passed, true)?);
        frames.extend(machine.listener(calls.outer, "")?);
        // The program's dispatcher calls the probe function outside any exception handler.
        if frames.len() < V8_STACK_LIMIT {
            frames.extend(machine.call(calls.dispatch, calls.dispatched, false)?);
        }
        frames.truncate(V8_STACK_LIMIT);
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
        let runners = script.functions.iter().flat_map(|(name, function)| {
            calls_of(function)
                .into_iter()
                .filter(|call| {
                    call.args.len() == 3
                        && call.args[2].expr.is_cond()
                        && call
                            .callee
                            .as_expr()
                            .and_then(|callee| callee.as_member())
                            .is_some_and(|member| ast::member_str(&member.prop) == Some("run"))
                })
                .map(move |call| (name, call))
        });
        let (runner, run_call) = candidates::exactly_one(runners, "closure-to-VM runner call")?;
        let mut listeners = Listeners {
            runner,
            appliers: &script.appliers,
            found: Vec::new(),
        };
        program.visit_with(&mut listeners);
        let listeners: Vec<Invocation> = listeners.found.into_iter().collect::<Result<_>>()?;
        Ok(Self {
            runner: Call {
                name: Name::same(runner.0.to_string()),
                site: Site::new(&run_call),
            },
            listeners,
            dispatch: candidates::exactly_one(classes, "VM dispatch method")?,
            script,
            cases,
            start,
        })
    }

    /// The handler `run` calls for `opcode`, from the loop with or without exception handlers.
    fn handler(&self, opcode: u8, guarded: bool) -> Result<Handler> {
        let DispatchMethod { class, run, .. } = &self.dispatch;
        let case = cases_of(run)
            .into_iter()
            .find(|case| {
                case.guarded == guarded
                    && self.cases.0.get(&offsets(case.span, self.start)) == Some(&opcode)
            })
            .with_context(|| format!("no dispatch of opcode {opcode} (guarded: {guarded})"))?;
        let dispatch = Scope::new("", run, &self.script.appliers).target(&case.call)?;
        let handler = dispatch
            .callee
            .clone()
            .with_context(|| format!("opcode {opcode}'s dispatch calls no named handler"))?;
        let frame = Name {
            v8: if dispatch.method {
                format!("{class}.{}", handler.0)
            } else {
                handler.0.to_string()
            },
            jsc: handler.0.to_string(),
        };
        Ok(Handler {
            dispatch,
            name: handler,
            frame,
        })
    }

    /// Appends the frames from the handler call `dispatch` through `run` and the runner.
    fn entered(&self, dispatch: Invocation, mut frames: Vec<Call>) -> Vec<Call> {
        let DispatchMethod { class, key, .. } = &self.dispatch;
        frames.extend(dispatch.frames(Name {
            v8: format!("{class}.run"),
            jsc: key.clone().unwrap_or_default(),
        }));
        frames.push(self.runner.clone());
        frames
    }

    /// Frames from error construction through `opcode`'s handler out to the runner.
    fn construction(&self, opcode: u8, guarded: bool) -> Result<Chain> {
        let handler = self.handler(opcode, guarded)?;
        let name = &handler.name;
        let function = self.script.function(name)?;
        if let Some(chain) = construction(&name.0, function, &self.script, &handler.frame)? {
            return Ok(Chain {
                frames: self.entered(handler.dispatch, chain.frames),
                reflected: chain.reflected,
            });
        }
        bail!("missing original function {} with the needed shape", name.0)
    }

    /// Recovers frames from the one call in `opcode`'s handler that `select` accepts, through
    /// the runner. `select` returns the frames inside the call.
    fn handler_call(
        &self,
        opcode: u8,
        guarded: bool,
        what: &str,
        select: impl Fn(&CallExpr, &Invocation) -> Option<Vec<Call>>,
    ) -> Result<Vec<Call>> {
        let handler = self.handler(opcode, guarded)?;
        let function = self.script.function(&handler.name)?;
        let scope = Scope::new(&handler.name.0, function, &self.script.appliers);
        let mut calls = Vec::new();
        for call in calls_of(function) {
            let target = scope.target(&call)?;
            if let Some(inner) = select(&call, &target) {
                calls.push((inner, target));
            }
        }
        let (mut frames, target) = candidates::exactly_one(calls, what)?;
        frames.extend(target.frames(handler.frame));
        Ok(self.entered(handler.dispatch, frames))
    }

    /// Recovers frames from a closure call in `opcode`'s handler through the runner. The call
    /// passes `passed` arguments and computes its callee rather than naming a script function.
    fn call(&self, opcode: u8, passed: usize, guarded: bool) -> Result<Vec<Call>> {
        self.handler_call(
            opcode,
            guarded,
            "closure call in the call handler",
            |call, target| {
                // A function computed in place, such as `read(register)(a, b)`.
                let computed = call.callee.as_expr().is_some_and(|callee| {
                    callee.unwrap_parens().is_call() && call.args.len() == passed
                });
                let named = target
                    .callee
                    .as_ref()
                    .is_some_and(|callee| self.script.function(callee).is_ok());
                (computed || (target.passed == Some(passed) && !named)).then(Vec::new)
            },
        )
    }

    /// Recovers frames from a method call in `opcode`'s handler through the runner: the handler
    /// passes the method, receiver, and `passed` arguments to a native apply forwarder.
    fn method_call(&self, opcode: u8, passed: usize, guarded: bool) -> Result<Vec<Call>> {
        self.handler_call(
            opcode,
            guarded,
            "method call in the call handler",
            |_, target| {
                if target.passed != Some(passed + 2) {
                    return None;
                }
                self.script.method_forwarder(target.callee.as_ref()?)
            },
        )
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
        Ok(listener.clone().frames(Name::anonymous(name.to_owned())))
    }
}

/// The function `run` calls for an opcode.
struct Handler {
    /// How `run` calls it.
    dispatch: Invocation,
    name: Id,
    frame: Name,
}

/// The script's declared and assigned functions, VM dispatch methods, and aliases for
/// `Reflect.construct` and `Reflect.apply`.
struct Script {
    functions: Vec<(Id, Function)>,
    classes: Vec<DispatchMethod>,
    constructs: Vec<Id>,
    applies: Vec<Id>,
    appliers: HashMap<Id, Applier>,
}

/// A VM class's `run`: the method with the dispatch switch.
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
        let appliers: HashMap<Id, Applier> = functions
            .iter()
            .filter_map(|(name, function)| Some((name.clone(), Applier::new(function)?)))
            .collect();
        let mut script = Self {
            functions,
            classes: Vec::new(),
            constructs: Vec::new(),
            applies: Vec::new(),
            appliers,
        };
        program.visit_with(&mut script);
        script
    }

    fn function(&self, name: &Id) -> Result<&Function> {
        self.functions
            .iter()
            .find(|(function_name, _)| function_name == name)
            .map(|(_, function)| function)
            .with_context(|| format!("missing original function {}", name.0))
    }

    /// Frames of the method forwarder identified by its lexical binding.
    fn method_forwarder(&self, name: &Id) -> Option<Vec<Call>> {
        self.forwarder_frames(&name.0, self.function(name).ok()?)
    }

    /// Returns frames for `function`, named `name`, if it forwards a method call. Allows local
    /// variable declarations before the return.
    fn forwarder_frames(&self, name: &str, function: &Function) -> Option<Vec<Call>> {
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
        let target = Scope::new(name, function, &self.appliers)
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
        (self::name(first) == Some(method.clone()) && self::name(second) == Some(receiver.clone()))
            .then(|| target.frames(Name::same(name.to_owned())))
    }
}

impl Visit for Script {
    fn visit_assign_expr(&mut self, assign: &AssignExpr) {
        // `Reflect.construct` and `Reflect.apply`, however the script reaches `Reflect`.
        if let Some(name) = assign.left.as_ident()
            && let Expr::Member(member) = &*assign.right
        {
            match ast::member_str(&member.prop) {
                Some("construct") => self.constructs.push(name.to_id()),
                Some("apply") => self.applies.push(name.to_id()),
                _ => {}
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
            .map(|method| (cases_of(&method.function).len(), method))
            .filter(|(cases, _)| *cases > 100)
            .max_by_key(|(cases, _)| *cases);
        if let Some((_, method)) = run {
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

/// Returns arguments forwarded by `call` to `target`'s callee. Object-method forwarders pass
/// trailing arguments individually, apply helpers pass an argument list, and direct calls use
/// their own argument list.
fn handed<'call>(call: &'call CallExpr, target: &Invocation) -> Option<Vec<&'call Expr>> {
    let through_object = call
        .callee
        .as_expr()
        .is_some_and(|callee| callee.unwrap_parens().is_member());
    let arguments = call.args.iter().map(|argument| &*argument.expr);
    if through_object {
        Some(arguments.skip(1).collect())
    } else if target.helpers.is_empty() {
        Some(arguments.collect())
    } else {
        let list = call.args.get(2)?.expr.unwrap_parens().as_array()?;
        list.elems
            .iter()
            .map(|element| element.as_ref().map(|element| &*element.expr))
            .collect()
    }
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
#[derive(Default)]
struct Copies(HashMap<Id, Vec<Id>>);

impl Copies {
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
        self.0.insert(array.to_id(), names?);
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
                let index = ast::index_literal(&index.expr)?;
                self.0.get(&array.to_id())?.get(index).cloned()
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

/// A dispatch case's first call, and whether it belongs to the VM's `try` loop used with
/// registered exception handlers.
struct Case {
    span: Span,
    call: CallExpr,
    guarded: bool,
}

fn cases_of(function: &Function) -> Vec<Case> {
    #[derive(Default)]
    struct Cases {
        found: Vec<Case>,
        in_try: bool,
    }
    // Visitors inspect only the supplied body. Skip nested functions and classes, but include
    // arrows.
    impl Visit for Cases {
        fn visit_function(&mut self, _: &Function) {}
        fn visit_class(&mut self, _: &Class) {}
        fn visit_try_stmt(&mut self, statement: &TryStmt) {
            let outer = mem::replace(&mut self.in_try, true);
            statement.block.visit_with(self);
            self.in_try = outer;
            statement.handler.visit_with(self);
            statement.finalizer.visit_with(self);
        }
        fn visit_switch_case(&mut self, case: &SwitchCase) {
            if case.test.is_some() {
                let mut calls = Calls::default();
                case.cons.visit_with(&mut calls);
                if let Some(call) = calls.0.into_iter().next() {
                    self.found.push(Case {
                        span: case.span,
                        call,
                        guarded: self.in_try,
                    });
                }
            }
            case.visit_children_with(self);
        }
    }
    let mut cases = Cases::default();
    function.body.visit_with(&mut cases);
    cases.found
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

/// The frames from `function`'s one construction site, preferring `Reflect.construct` calls to
/// argumentless `new`.
fn construction(
    name: &str,
    function: &Function,
    script: &Script,
    frame: &Name,
) -> Result<Option<Chain>> {
    let scope = Scope::new(name, function, &script.appliers);
    let mut found = Vec::new();
    for call in calls_of(function) {
        let target = scope.target(&call)?;
        if target
            .callee
            .as_ref()
            .is_some_and(|callee| script.constructs.iter().any(|name| name == callee))
        {
            found.push(Chain {
                frames: target.frames(frame.clone()),
                reflected: true,
            });
        }
    }
    if found.is_empty() {
        #[derive(Default)]
        struct News(Vec<Site>);
        impl Visit for News {
            fn visit_function(&mut self, _: &Function) {}
            fn visit_class(&mut self, _: &Class) {}
            // Ignore exceptions thrown by guards; they are separate from the handler's
            // constructed value.
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
            found.push(Chain {
                frames: vec![Call {
                    name: frame.clone(),
                    site,
                }],
                reflected: false,
            });
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => bail!("a constructor handler constructs in several places"),
    }
}

/// A call's target, resolved through helper functions.
#[derive(Clone)]
struct Invocation {
    callee: Option<Id>,
    /// Whether it invokes `callee.call(receiver, ...)`.
    method: bool,
    /// Intermediate helper frames, innermost first.
    helpers: Vec<Call>,
    site: Site,
    /// Argument count passed to `callee`, if statically known.
    passed: Option<usize>,
}

impl Invocation {
    /// The frames of the call made from `caller`, innermost first.
    fn frames(self, caller: Name) -> Vec<Call> {
        let mut frames = self.helpers;
        frames.push(Call {
            name: caller,
            site: self.site,
        });
        frames
    }
}

/// Recovers a selector-based apply helper's XOR mask and each case's `Reflect.apply` position.
/// Accepts selector copies such as `(s = [selector], mask ^ s[0])` and indirect names for
/// `apply`.
struct Applier {
    mask: f64,
    cases: Vec<ApplierCase>,
}

struct ApplierCase {
    label: f64,
    site: Site,
}

impl Applier {
    fn new(function: &Function) -> Option<Self> {
        let parameters = parameters(function)?;
        let [selector, applied, list, ..] = parameters.as_slice() else {
            return None;
        };
        let [Stmt::Switch(switch)] = &function.body.as_ref()?.stmts[..] else {
            return None;
        };
        let mut discriminant = switch.discriminant.unwrap_parens();
        // Arrays the switch fills with names before it reads them.
        let mut copies = Copies::default();
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
        let is_selector = |expression: &Expr| copies.resolve(expression) == Some(selector.clone());
        let mask = match (xor.left.unwrap_parens(), xor.right.unwrap_parens()) {
            (Expr::Lit(Lit::Num(mask)), other) | (other, Expr::Lit(Lit::Num(mask)))
                if is_selector(other) =>
            {
                mask.value
            }
            _ => return None,
        };
        let cases = switch
            .cases
            .iter()
            .map(|case| {
                if let Expr::Lit(Lit::Num(value)) = &**case.test.as_ref()?
                    && let [Stmt::Return(returned)] = &case.cons[..]
                    && let Some(Expr::Call(call)) = returned.arg.as_deref().map(Expr::unwrap_parens)
                    && let Callee::Expr(callee) = &call.callee
                    && callee.unwrap_parens().is_member()
                    && let [first, _, third] = &call.args[..]
                    && name(&first.expr) == Some(applied.clone())
                    && name(&third.expr) == Some(list.clone())
                {
                    Some(ApplierCase {
                        label: value.value,
                        site: Site::new(call),
                    })
                } else {
                    None
                }
            })
            .collect::<Option<_>>()?;
        Some(Self { mask, cases })
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

/// A function's local aliases, string constants, and forwarders on local objects.
struct Scope<'script> {
    appliers: &'script HashMap<Id, Applier>,
    /// V8's name prefix for functions assigned here, such as `Owner.`.
    prefix: String,
    /// Each object and key's intermediate call frames, innermost first.
    forwarders: HashMap<(Id, String), Vec<Call>>,
    aliases: HashMap<Id, Id>,
    strings: HashMap<Id, String>,
}

impl<'script> Scope<'script> {
    /// `name` is empty for anonymous functions. V8 prefixes the names of functions assigned
    /// inside a capitalized function with its name, as it does for constructors.
    fn new(name: &str, function: &Function, appliers: &'script HashMap<Id, Applier>) -> Self {
        let constructor = name.starts_with(char::is_uppercase);
        let mut scope = Self {
            appliers,
            prefix: constructor.then(|| format!("{name}.")).unwrap_or_default(),
            forwarders: HashMap::new(),
            aliases: HashMap::new(),
            strings: HashMap::new(),
        };
        function.body.visit_with(&mut scope);
        scope
    }

    fn target(&self, call: &CallExpr) -> Result<Invocation> {
        let mut target = Invocation {
            callee: None,
            method: false,
            helpers: Vec::new(),
            site: Site::new(call),
            passed: None,
        };
        match call.callee.as_expr().map(|callee| callee.unwrap_parens()) {
            Some(Expr::Ident(callee)) => {
                if let Some(applied) = self.applier_call(callee, call)? {
                    return Ok(applied);
                }
                target.callee = Some(callee.to_id());
                target.passed = Some(call.args.len());
            }
            Some(Expr::Member(member)) if let Expr::Ident(object) = &*member.obj => {
                // Some builds keep the key in a local: `handler[c](this)` with `c = "call"`.
                let key = match &member.prop {
                    MemberProp::Computed(computed) if let Expr::Ident(name) = &*computed.expr => {
                        self.strings.get(&name.to_id()).map(String::as_str)
                    }
                    property => ast::member_str(property),
                };
                let forwarder = key.and_then(|key| {
                    self.forwarders
                        .get(&(self.object(&object.to_id()), key.to_owned()))
                });
                // Both forms pass the receiver or the callee first.
                if key == Some("call") {
                    target.callee = Some(object.to_id());
                    target.method = true;
                    target.passed = Some(call.args.len().saturating_sub(1));
                } else if let Some(helpers) = forwarder {
                    let first = call.args.first();
                    target.callee = first.and_then(|first| name(&first.expr));
                    target.helpers = helpers.clone();
                    target.passed = Some(call.args.len().saturating_sub(1));
                }
            }
            _ => {}
        }
        Ok(target)
    }

    /// Matches `applier(selector, f, [args])`, which calls `f` through an apply helper.
    fn applier_call(&self, callee: &Ident, call: &CallExpr) -> Result<Option<Invocation>> {
        let (Some(applier), [selector, function, ..]) =
            (self.appliers.get(&callee.to_id()), &call.args[..])
        else {
            return Ok(None);
        };
        let Expr::Lit(Lit::Num(selector)) = &*selector.expr else {
            return Ok(None);
        };
        let inner = applier.call(selector.value).with_context(|| {
            format!("{} has no case for selector {}", callee.sym, selector.value)
        })?;
        let list = call
            .args
            .get(2)
            .and_then(|list| list.expr.unwrap_parens().as_array());
        Ok(Some(Invocation {
            callee: name(&function.expr),
            method: false,
            helpers: vec![Call {
                name: Name::same(callee.sym.to_string()),
                site: inner,
            }],
            site: Site::new(call),
            passed: list.map(|list| list.elems.len()),
        }))
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

    fn bind(&mut self, name: Id, value: &Expr) {
        if let Expr::Ident(original) = value {
            self.aliases.insert(name, original.to_id());
        } else if let Some(text) = ast::static_str(value) {
            self.strings.insert(name, text.to_owned());
        }
    }

    /// Recovers frames, innermost first, for a function that calls its first parameter with
    /// later parameters. Accepts direct calls, array copies such as `(g = [f, b], (0, g[0])(a,
    /// g[1]))`, and apply helpers. Extra parameters may serve as local variables.
    fn forwarder(&self, function: &Function, frame: Name) -> Option<Vec<Call>> {
        let parameters = parameters(function)?;
        let (first, rest) = parameters.split_first()?;
        let mut arrays = Copies::default();
        let mut value = ast::returned(function)?.unwrap_parens();
        if let Expr::Seq(sequence) = value {
            let (last, before) = sequence.exprs.split_last()?;
            for expression in before {
                // Obfuscation leaves expressions that do nothing.
                if arrays.record(expression).is_none() && !is_inert(expression) {
                    return None;
                }
            }
            value = last.unwrap_parens();
        }
        // Forwarded arguments must match the parameters after the target function.
        let passes_on = |arguments: &[ExprOrSpread]| {
            arguments.len() <= rest.len()
                && arguments.iter().zip(rest).all(|(argument, parameter)| {
                    argument.spread.is_none()
                        && arrays.resolve(&argument.expr) == Some(parameter.clone())
                })
        };
        let call = value.as_call()?;
        let mut callee = call.callee.as_expr()?.unwrap_parens();
        if let Expr::Seq(sequence) = callee
            && let [discarded, last] = &sequence.exprs[..]
            && discarded.is_lit()
        {
            callee = last.unwrap_parens();
        }
        if arrays.resolve(callee) == Some(first.clone()) && passes_on(&call.args) {
            return Some(vec![Call {
                name: frame,
                site: Site::new(call),
            }]);
        }
        let applied = self.applier_call(callee.as_ident()?, call).ok()??;
        let [_, function, list] = &call.args[..] else {
            return None;
        };
        let list = list.expr.unwrap_parens().as_array()?;
        let list: Vec<ExprOrSpread> = list.elems.iter().cloned().collect::<Option<_>>()?;
        (arrays.resolve(&function.expr) == Some(first.clone()) && passes_on(&list))
            .then(|| applied.frames(frame))
    }
}

/// Whether `expression` has no effect, such as obfuscation's `true`, constant comparisons and
/// `void`.
fn is_inert(expression: &Expr) -> bool {
    match expression.unwrap_parens() {
        Expr::Lit(_) => true,
        Expr::Bin(binary) => is_inert(&binary.left) && is_inert(&binary.right),
        Expr::Unary(unary) => unary.op != UnaryOp::Delete && is_inert(&unary.arg),
        Expr::Array(array) => array.elems.iter().all(|element| {
            element
                .as_ref()
                .is_none_or(|element| is_inert(&element.expr))
        }),
        _ => false,
    }
}

impl Visit for Scope<'_> {
    fn visit_function(&mut self, _: &Function) {}
    fn visit_class(&mut self, _: &Class) {}

    fn visit_assign_expr(&mut self, assign: &AssignExpr) {
        if assign.op == AssignOp::Assign {
            match &assign.left {
                AssignTarget::Simple(SimpleAssignTarget::Ident(name)) => {
                    self.bind(name.to_id(), &assign.right);
                }
                AssignTarget::Simple(SimpleAssignTarget::Member(member))
                    if let Expr::Ident(object) = &*member.obj
                        && let Expr::Fn(function) = &*assign.right
                        && let Some(name) = ast::member_str(&member.prop) =>
                {
                    // A function assigned to a member has no name of its own.
                    let path = format!("{}{}", self.prefix, object.sym);
                    let frame = Name::anonymous(match &member.prop {
                        MemberProp::Computed(_) => format!("{path}.<computed> [as {name}]"),
                        _ => format!("{path}.{name}"),
                    });
                    if let Some(frames) = self.forwarder(&function.function, frame) {
                        self.forwarders
                            .insert((object.to_id(), name.to_owned()), frames);
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
            self.bind(name.to_id(), init);
        }
        declarator.visit_children_with(self);
    }
}

/// Finds runner calls from closure-factory listeners, including calls made through helpers, and
/// records calls it cannot resolve. Each listener forwards its captured machine and layout
/// followed by its own arguments.
struct Listeners<'script> {
    runner: &'script Id,
    appliers: &'script HashMap<Id, Applier>,
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
            assert!(
                script.appliers[&binding(&script, "j")].call(3.0).is_some(),
                "{source}"
            );
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
        let caller = script.function(&binding(&script, "caller")).unwrap();
        let call = calls_of(caller).remove(0);
        let target = Scope::new("caller", caller, &script.appliers)
            .target(&call)
            .unwrap();
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
        let real = script.function(&binding(&script, "real")).unwrap();
        let call = calls_of(real).remove(0);
        let runner = Scope::new("", real, &script.appliers)
            .target(&call)
            .unwrap()
            .callee
            .unwrap();
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
        let outer = script.function(&binding(&script, "outer")).unwrap();
        let call = calls_of(outer).remove(0);
        let target = Scope::new("", outer, &script.appliers)
            .target(&call)
            .unwrap();
        assert!(target.helpers.is_empty());
        assert_eq!(target.passed, Some(3));
        assert!(
            !script
                .appliers
                .contains_key(target.callee.as_ref().unwrap())
        );
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
        let function = script.function(&binding(&script, "F")).unwrap();
        let call = calls_of(function).remove(0);
        let target = Scope::new("F", function, &script.appliers)
            .target(&call)
            .unwrap();
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

    /// The target of the first call in `source`'s function `name`, and where the script starts.
    fn first_target(source: &str, name: &str) -> (Invocation, BytePos) {
        let (script, start) = script(source);
        let function = script.function(&binding(&script, name)).unwrap();
        let call = calls_of(function).remove(0);
        let target = Scope::new("", function, &script.appliers)
            .target(&call)
            .unwrap();
        (target, start)
    }

    #[test]
    fn a_call_key_kept_in_a_local_still_calls_the_handler() {
        let source = "function run(){var c='call';switch(o){case 1:h[c](this);break}}";
        let (target, _) = first_target(source, "run");
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
        let (target, start) = first_target(source, "h");
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
