//! Reconstructs the render call-stack sample sent with `extraParams`.
//!
//! When `api.js` renders a widget, it records a method code, elapsed milliseconds, and
//! `new Error().stack`. The iframe copies the sample into its first payload. The loader's own
//! frames follow from its source names and call positions. Widgets declared in markup are
//! rendered from the loader's DOM-ready handler; a page script's `turnstile.render` call adds
//! that script's frames instead.
//!
//! V8 starts with `Error`, locates frames at the callee's start, names render calls by their
//! property, and keeps ten frames. JavaScriptCore uses `name@url:line:column` and locates
//! frames at the opening argument parenthesis. In strict code, tail calls can replace their
//! caller's frame.

use std::collections::{HashMap, HashSet};
use std::mem;

use anyhow::{Context, Result};
use swc_core::atoms::Atom;
use swc_core::common::BytePos;
use swc_core::ecma::ast::{
    BinaryOp, CallExpr, Callee, CondExpr, Expr, FnDecl, Function, KeyValueProp, Lit, MemberExpr,
    MemberProp, Pat, PropName, ReturnStmt, TryStmt, UnaryOp, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};
use url::Url;

use crate::candidates;
use crate::engine::{Engine, StackFrame, V8_STACK_LIMIT};
use crate::js::ast::{self, ParsedScript};

/// The loader's entry point for widgets declared in markup.
const IMPLICIT_RENDER: &str = "runImplicitRender";
/// The loader's entry point for page scripts.
const EXPLICIT_RENDER: &str = "render";

/// The sample the loader takes when it renders a widget.
#[derive(Debug, Clone)]
pub(crate) struct RenderSample {
    /// The code the loader records for the render.
    pub method: f64,
    pub stack: String,
}

impl RenderSample {
    /// Rebuilds the stack for markup-triggered rendering from `parsed`, using `engine`'s format
    /// and `url` as the script name.
    pub(crate) fn from_parsed(parsed: &ParsedScript, url: &Url, engine: Engine) -> Result<Self> {
        let loader = Loader::read(parsed);
        let (method, mut frames) = loader.sampled(IMPLICIT_RENDER, engine)?;
        // The outer frames cover queue insertion and the DOM-ready handler draining that queue.
        let queued = candidates::at_most_one_distinct(
            &loader.implicit_calls,
            "named calls of the implicit render",
        )?
        .context("loader never calls its implicit render from a named function")?;
        let ready = candidates::at_most_one_distinct(&loader.ready, "DOMContentLoaded handlers")?
            .context("loader waits for no DOMContentLoaded")?;
        let drained = loader
            .calls
            .iter()
            .find(|call| call.scope.as_ref() == Some(ready))
            .context("the ready handler calls nothing it queued")?;
        frames.push((queued.function.to_string(), &queued.site));
        frames.push((ready.to_string(), &drained.site));
        Ok(Self {
            method,
            stack: engine.error_stack(placed(parsed, url, &frames, engine)),
        })
    }

    /// Rebuilds the stack for a page script calling `turnstile.render` in the loader fetched
    /// from `url`. `caller` supplies script frames from innermost to outermost, ending at the
    /// callback invoked by the loader's `onload` timer. V8's ten-frame limit ends the stack
    /// inside the script; JavaScriptCore also includes the timer.
    pub(crate) fn explicit<'caller>(
        source: &str,
        url: &Url,
        caller: impl IntoIterator<Item = StackFrame<'caller>>,
        engine: Engine,
    ) -> Result<Self> {
        let parsed = ast::parse_javascript("the Turnstile loader", source)?;
        let loader = Loader::read(&parsed);
        let (method, frames) = loader.sampled(EXPLICIT_RENDER, engine)?;
        let caller = caller.into_iter().map(|frame| StackFrame { ..frame });
        let frames = placed(&parsed, url, &frames, engine)
            .into_iter()
            .chain(caller);
        let stack = match engine {
            Engine::Chromium => engine.error_stack(frames.take(V8_STACK_LIMIT)),
            Engine::WebKit => {
                let onload = candidates::at_most_one_distinct(
                    &loader.onload_calls,
                    "onload callback calls",
                )?
                .context("loader never calls an onload callback")?;
                let timer = [(String::new(), onload)];
                engine.error_stack(frames.chain(placed(&parsed, url, &timer, engine)))
            }
        };
        Ok(Self { method, stack })
    }
}

/// Places loader frames for `engine`, leaving out the frames JavaScriptCore's tail calls
/// replace.
fn placed<'a>(
    parsed: &ParsedScript,
    url: &'a Url,
    frames: &'a [(String, &Site)],
    engine: Engine,
) -> Vec<StackFrame<'a>> {
    let mut surviving = Vec::with_capacity(frames.len());
    for (function, site) in frames {
        let at = match engine {
            Engine::Chromium => site.v8,
            Engine::WebKit if site.tail => continue,
            Engine::WebKit => site.jsc,
        };
        let (line, column) = parsed.position(at);
        surviving.push(StackFrame {
            function,
            url: url.as_str(),
            line,
            column,
        });
    }
    surviving
}

/// Engine-specific source positions for a call frame.
#[derive(Debug, PartialEq)]
struct Site {
    /// The start of the callee, V8's position.
    v8: BytePos,
    /// The opening argument parenthesis, used by JavaScriptCore.
    jsc: BytePos,
    /// Whether this call is directly returned and therefore eligible for JavaScriptCore
    /// tail-call replacement.
    tail: bool,
}

/// A call through a plain identifier.
#[derive(Debug, PartialEq)]
struct Call {
    scope: Option<Atom>,
    callee: Atom,
    site: Site,
    first: Option<Atom>,
}

/// A frame position inside the named function `function`.
#[derive(Debug, PartialEq)]
struct FunctionSite {
    function: Atom,
    site: Site,
}

/// Finds the functions and calls involved in stack sampling.
#[derive(Default)]
struct Loader {
    scope: Option<Atom>,
    /// `new Error().stack` reads, at the error's construction site.
    samples: Vec<FunctionSite>,
    calls: Vec<Call>,
    /// `runImplicitRender` property calls.
    implicit_calls: Vec<FunctionSite>,
    /// Calls returned directly outside `try` blocks.
    tail_calls: HashSet<BytePos>,
    /// Whether the visit is inside a `try` block of the current function.
    in_try: bool,
    /// `key: function` in object literals.
    properties: HashMap<Atom, Atom>,
    /// Variables initialised to a number.
    numbers: HashMap<Atom, f64>,
    /// The functions handed to `addEventListener("DOMContentLoaded", ...)`.
    ready: Vec<Atom>,
    /// Delay of the timer whose callback is currently being visited.
    timer_delay: Option<f64>,
    /// Calls to the page's defined `onload` callback from a timer with no delay. Another timer
    /// retries after one second if the callback is not yet defined.
    onload_calls: Vec<Site>,
}

impl Loader {
    fn read(parsed: &ParsedScript) -> Self {
        let mut loader = Self::default();
        parsed.script.visit_with(&mut loader);
        loader
    }

    /// Returns the sampling method code for loader export `property` and its frames, innermost
    /// first: sampler, timing wrapper, and export. Fails if any step is ambiguous.
    fn sampled(&self, property: &str, engine: Engine) -> Result<(f64, Vec<(String, &Site)>)> {
        let sample = candidates::at_most_one_distinct(&self.samples, "stack samplers")?
            .context("loader takes no stack sample")?;
        let wrapper = candidates::at_most_one_distinct(
            self.calls
                .iter()
                .filter(|call| call.callee == sample.function),
            "calls of the stack sampler",
        )?
        .context("loader never calls its stack sampler")?;
        let measured = wrapper
            .scope
            .as_ref()
            .context("the stack sampler is called from an anonymous function")?;
        let exported = self
            .properties
            .get(&Atom::from(property))
            .with_context(|| format!("loader exports no {property}"))?;
        let call = candidates::at_most_one_distinct(
            self.calls
                .iter()
                .filter(|call| call.scope.as_ref() == Some(exported) && call.callee == *measured),
            "stack samples in the exported render",
        )?
        .with_context(|| format!("the loader's {property} takes no stack sample"))?;
        let method = call
            .first
            .as_ref()
            .and_then(|code| self.numbers.get(code))
            .with_context(|| format!("the loader's {property} has no constant method code"))?;
        let exported = match engine {
            Engine::Chromium => format!("Object.{exported} [as {property}]"),
            Engine::WebKit => exported.to_string(),
        };
        Ok((
            *method,
            vec![
                (sample.function.to_string(), &sample.site),
                (measured.to_string(), &wrapper.site),
                (exported, &call.site),
            ],
        ))
    }

    fn within(&mut self, name: Option<Atom>, function: &Function) {
        let previous = mem::replace(&mut self.scope, name);
        let in_try = mem::take(&mut self.in_try);
        function.visit_children_with(self);
        self.scope = previous;
        self.in_try = in_try;
    }

    fn site(&self, call: &CallExpr, v8: BytePos, jsc: BytePos) -> Site {
        Site {
            v8,
            jsc,
            tail: self.tail_calls.contains(&call.span.lo),
        }
    }
}

impl Visit for Loader {
    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        self.within(Some(declaration.ident.sym.clone()), &declaration.function);
    }

    fn visit_function(&mut self, function: &Function) {
        self.within(None, function);
    }

    /// V8 names a function expression after the variable it initialises.
    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Pat::Ident(name) = &declarator.name {
            match declarator.init.as_deref() {
                Some(Expr::Fn(function)) => {
                    self.within(Some(name.id.sym.clone()), &function.function);
                    return;
                }
                Some(Expr::Lit(Lit::Num(number))) => {
                    self.numbers.insert(name.id.sym.clone(), number.value);
                }
                _ => {}
            }
        }
        declarator.visit_children_with(self);
    }

    fn visit_member_expr(&mut self, member: &MemberExpr) {
        if ast::member_str(&member.prop) == Some("stack")
            && let Expr::New(error) = &*member.obj
            && let Expr::Ident(callee) = &*error.callee
            && callee.sym == "Error"
            && let Some(function) = self.scope.clone()
        {
            self.samples.push(FunctionSite {
                function,
                site: Site {
                    v8: error.span.lo,
                    jsc: callee.span.hi,
                    tail: false,
                },
            });
        }
        member.visit_children_with(self);
    }

    /// `found === void 0 ? report() : found()`: the call of a callback once it is defined.
    fn visit_cond_expr(&mut self, conditional: &CondExpr) {
        if self.timer_delay == Some(0.0)
            && let Expr::Bin(test) = &*conditional.test
            && test.op == BinaryOp::EqEqEq
            && let Expr::Ident(tested) = &*test.left
            && matches!(&*test.right, Expr::Unary(unary) if unary.op == UnaryOp::Void)
            && let Expr::Call(call) = &*conditional.alt
            && call.args.is_empty()
            && let Callee::Expr(callee) = &call.callee
            && let Expr::Ident(callee) = &**callee
            && callee.sym == tested.sym
        {
            let site = self.site(call, callee.span.lo, callee.span.hi);
            self.onload_calls.push(site);
        }
        conditional.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, call: &CallExpr) {
        let outer_delay = self.timer_delay;
        if let Callee::Expr(callee) = &call.callee {
            match &**callee {
                Expr::Ident(callee) => {
                    // `setTimeout(function () { ... }, delay)`: the callback runs from a timer.
                    if callee.sym == "setTimeout"
                        && let [callback, delay] = &call.args[..]
                        && callback.expr.is_fn_expr()
                    {
                        self.timer_delay = ast::number(&delay.expr);
                    }
                    self.calls.push(Call {
                        scope: self.scope.clone(),
                        callee: callee.sym.clone(),
                        site: self.site(call, callee.span.lo, callee.span.hi),
                        first: call
                            .args
                            .first()
                            .and_then(|argument| Some(argument.expr.as_ident()?.sym.clone())),
                    });
                }
                Expr::Member(member) => {
                    if let MemberProp::Ident(property) = &member.prop
                        && property.sym == IMPLICIT_RENDER
                        && let Some(function) = self.scope.clone()
                    {
                        let site = self.site(call, property.span.lo, property.span.hi);
                        self.implicit_calls.push(FunctionSite { function, site });
                    }
                    if ast::member_str(&member.prop) == Some("addEventListener")
                        && let [event, listener, ..] = &call.args[..]
                        && matches!(&*event.expr, Expr::Lit(Lit::Str(_)))
                        && ast::static_str(&event.expr) == Some("DOMContentLoaded")
                        && let Expr::Ident(listener) = &*listener.expr
                    {
                        self.ready.push(listener.sym.clone());
                    }
                }
                _ => {}
            }
        }
        call.visit_children_with(self);
        self.timer_delay = outer_delay;
    }

    /// A directly returned call is in tail position unless an enclosing `try` requires work
    /// after it returns.
    fn visit_return_stmt(&mut self, statement: &ReturnStmt) {
        if !self.in_try
            && let Some(Expr::Call(call)) = statement.arg.as_deref()
        {
            self.tail_calls.insert(call.span.lo);
        }
        statement.visit_children_with(self);
    }

    fn visit_try_stmt(&mut self, statement: &TryStmt) {
        let outer = mem::replace(&mut self.in_try, true);
        statement.block.visit_with(self);
        self.in_try = outer;
        statement.handler.visit_with(self);
        statement.finalizer.visit_with(self);
    }

    fn visit_key_value_prop(&mut self, property: &KeyValueProp) {
        if let PropName::Ident(key) = &property.key
            && let Expr::Ident(value) = &*property.value
        {
            self.properties.insert(key.sym.clone(), value.sym.clone());
        }
        property.visit_children_with(self);
    }
}
