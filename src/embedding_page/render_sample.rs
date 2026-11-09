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
use oxc::ast::ast::{
    Argument, BindingPattern, CallExpression, ConditionalExpression, Expression, Function,
    MemberExpression, ObjectPropertyKind, PropertyKey, ReturnStatement, TryStatement,
    VariableDeclarator,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::{ScopeFlags, SymbolId};
use oxc::span::GetSpan;
use oxc::syntax::operator::{BinaryOperator, UnaryOperator};
use url::Url;

use crate::candidates;
use crate::engine::{Engine, StackFrame, V8_STACK_LIMIT};
use crate::js::ast::{self, Binding, ParsedScript, Script};

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
    /// Rebuilds the stack for markup-triggered rendering from `script`, using `engine`'s format
    /// and `url` as the script name.
    pub(crate) fn from_script(script: Script<'_>, url: &Url, engine: Engine) -> Result<Self> {
        let loader = Loader::read(script);
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
            .find(|call| call.scope.map(Binding::Symbol) == Some(*ready))
            .context("the ready handler calls nothing it queued")?;
        frames.push((loader.name(queued.function).to_owned(), &queued.site));
        frames.push((script.name(*ready).to_owned(), &drained.site));
        Ok(Self {
            method,
            stack: engine.error_stack(placed(script, url, &frames, engine)),
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
        let parsed = ParsedScript::parse("the Turnstile loader", source)?;
        let script = parsed.script();
        let loader = Loader::read(script);
        let (method, frames) = loader.sampled(EXPLICIT_RENDER, engine)?;
        let caller = caller.into_iter().map(|frame| StackFrame { ..frame });
        let frames = placed(script, url, &frames, engine)
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
                engine.error_stack(frames.chain(placed(script, url, &timer, engine)))
            }
        };
        Ok(Self { method, stack })
    }
}

/// Places loader frames for `engine`, leaving out the frames JavaScriptCore's tail calls
/// replace.
fn placed<'a>(
    script: Script<'_>,
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
        let (line, column) = script.position(at);
        surviving.push(StackFrame {
            function,
            url: url.as_str(),
            line,
            column,
        });
    }
    surviving
}

/// Engine-specific source offsets for a call frame.
#[derive(Debug, PartialEq)]
struct Site {
    /// The start of the callee, V8's position.
    v8: u32,
    /// The opening argument parenthesis, used by JavaScriptCore.
    jsc: u32,
    /// Whether this call is directly returned and therefore eligible for JavaScriptCore
    /// tail-call replacement.
    tail: bool,
}

/// A call through a plain identifier.
#[derive(Debug, PartialEq)]
struct Call<'a> {
    /// The named function containing the call.
    scope: Option<SymbolId>,
    callee: Binding<'a>,
    site: Site,
    /// The first argument, when it is a plain identifier.
    first: Option<Binding<'a>>,
}

/// A frame position inside the named function `function`.
#[derive(Debug, PartialEq)]
struct FunctionSite {
    function: SymbolId,
    site: Site,
}

/// Finds the functions and calls involved in stack sampling.
struct Loader<'a> {
    script: Script<'a>,
    /// The named function being visited.
    scope: Option<SymbolId>,
    /// `new Error().stack` reads, at the error's construction site.
    samples: Vec<FunctionSite>,
    calls: Vec<Call<'a>>,
    /// `runImplicitRender` property calls.
    implicit_calls: Vec<FunctionSite>,
    /// Starts of calls returned directly outside `try` blocks.
    tail_calls: HashSet<u32>,
    /// Whether the visit is inside a `try` block of the current function.
    in_try: bool,
    /// `key: function` in object literals.
    properties: HashMap<&'a str, Binding<'a>>,
    /// Variables initialised to a number.
    numbers: HashMap<SymbolId, f64>,
    /// The functions handed to `addEventListener("DOMContentLoaded", ...)`.
    ready: Vec<Binding<'a>>,
    /// Delay of the timer whose callback is currently being visited.
    timer_delay: Option<f64>,
    /// Calls to the page's defined `onload` callback from a timer with no delay. Another timer
    /// retries after one second if the callback is not yet defined.
    onload_calls: Vec<Site>,
}

impl<'a> Loader<'a> {
    fn read(script: Script<'a>) -> Self {
        let mut loader = Self {
            script,
            scope: None,
            samples: Vec::new(),
            calls: Vec::new(),
            implicit_calls: Vec::new(),
            tail_calls: HashSet::new(),
            in_try: false,
            properties: HashMap::new(),
            numbers: HashMap::new(),
            ready: Vec::new(),
            timer_delay: None,
            onload_calls: Vec::new(),
        };
        loader.visit_program(script.program);
        loader
    }

    /// The declared name of the function `symbol` binds.
    fn name(&self, symbol: SymbolId) -> &'a str {
        self.script.scoping.symbol_name(symbol)
    }

    /// Returns the sampling method code for loader export `property` and its frames, innermost
    /// first: sampler, timing wrapper, and export. Fails if any step is ambiguous.
    fn sampled(&self, property: &str, engine: Engine) -> Result<(f64, Vec<(String, &Site)>)> {
        let sample = candidates::at_most_one_distinct(&self.samples, "stack samplers")?
            .context("loader takes no stack sample")?;
        let wrapper = candidates::at_most_one_distinct(
            self.calls
                .iter()
                .filter(|call| call.callee == Binding::Symbol(sample.function)),
            "calls of the stack sampler",
        )?
        .context("loader never calls its stack sampler")?;
        let measured = wrapper
            .scope
            .context("the stack sampler is called from an anonymous function")?;
        let exported = *self
            .properties
            .get(property)
            .with_context(|| format!("loader exports no {property}"))?;
        let call = candidates::at_most_one_distinct(
            self.calls.iter().filter(|call| {
                call.scope.map(Binding::Symbol) == Some(exported)
                    && call.callee == Binding::Symbol(measured)
            }),
            "stack samples in the exported render",
        )?
        .with_context(|| format!("the loader's {property} takes no stack sample"))?;
        let method = match call.first {
            Some(Binding::Symbol(code)) => self.numbers.get(&code),
            _ => None,
        }
        .with_context(|| format!("the loader's {property} has no constant method code"))?;
        let exported = self.script.name(exported);
        let exported = match engine {
            Engine::Chromium => format!("Object.{exported} [as {property}]"),
            Engine::WebKit => exported.to_owned(),
        };
        Ok((
            *method,
            vec![
                (self.name(sample.function).to_owned(), &sample.site),
                (self.name(measured).to_owned(), &wrapper.site),
                (exported, &call.site),
            ],
        ))
    }

    /// Visits `function` as the body of the function `name` binds, or of an anonymous one.
    fn within(&mut self, name: Option<SymbolId>, function: &Function<'a>, flags: ScopeFlags) {
        let previous = mem::replace(&mut self.scope, name);
        let in_try = mem::take(&mut self.in_try);
        walk::walk_function(self, function, flags);
        self.scope = previous;
        self.in_try = in_try;
    }

    fn site(&self, call: &CallExpression<'_>, v8: u32, jsc: u32) -> Site {
        Site {
            v8,
            jsc,
            tail: self.tail_calls.contains(&call.span.start),
        }
    }
}

impl<'a> Visit<'a> for Loader<'a> {
    /// Declared functions are named by their binding; expressions are anonymous unless a
    /// variable names them.
    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let name = function
            .id
            .as_ref()
            .filter(|_| function.is_declaration())
            .map(|id| id.symbol_id());
        self.within(name, function, flags);
    }

    /// V8 names a function expression after the variable it initialises.
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let BindingPattern::BindingIdentifier(name) = &declarator.id {
            match &declarator.init {
                Some(Expression::FunctionExpression(function)) => {
                    self.within(Some(name.symbol_id()), function, ScopeFlags::Function);
                    return;
                }
                Some(Expression::NumericLiteral(number)) => {
                    self.numbers.insert(name.symbol_id(), number.value);
                }
                _ => {}
            }
        }
        walk::walk_variable_declarator(self, declarator);
    }

    fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
        if ast::member_str(member) == Some("stack")
            && let Expression::NewExpression(error) = member.object()
            && self.script.is_global(&error.callee, "Error")
            && let Some(function) = self.scope
        {
            self.samples.push(FunctionSite {
                function,
                site: Site {
                    v8: error.span.start,
                    jsc: error.callee.span().end,
                    tail: false,
                },
            });
        }
        walk::walk_member_expression(self, member);
    }

    /// `found === void 0 ? report() : found()`: the call of a callback once it is defined.
    fn visit_conditional_expression(&mut self, conditional: &ConditionalExpression<'a>) {
        if self.timer_delay == Some(0.0)
            && let Expression::BinaryExpression(test) = &conditional.test
            && test.operator == BinaryOperator::StrictEquality
            && let Expression::Identifier(tested) = &test.left
            && matches!(&test.right, Expression::UnaryExpression(unary)
                if unary.operator == UnaryOperator::Void)
            && let Expression::CallExpression(call) = &conditional.alternate
            && call.arguments.is_empty()
            && let Expression::Identifier(callee) = &call.callee
            && self.script.binding(callee) == self.script.binding(tested)
        {
            let site = self.site(call, callee.span.start, callee.span.end);
            self.onload_calls.push(site);
        }
        walk::walk_conditional_expression(self, conditional);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        let outer_delay = self.timer_delay;
        match &call.callee {
            Expression::Identifier(callee) => {
                // `setTimeout(function () { ... }, delay)`: the callback runs from a timer.
                if self.script.is_global(&call.callee, "setTimeout")
                    && let [callback, delay] = &call.arguments[..]
                    && matches!(
                        callback.as_expression(),
                        Some(Expression::FunctionExpression(_))
                    )
                {
                    self.timer_delay = delay.as_expression().and_then(ast::number);
                }
                self.calls.push(Call {
                    scope: self.scope,
                    callee: self.script.binding(callee),
                    site: self.site(call, callee.span.start, callee.span.end),
                    first: match call.arguments.first().and_then(Argument::as_expression) {
                        Some(Expression::Identifier(first)) => Some(self.script.binding(first)),
                        _ => None,
                    },
                });
            }
            callee => {
                if let Expression::StaticMemberExpression(member) = callee
                    && member.property.name == IMPLICIT_RENDER
                    && let Some(function) = self.scope
                {
                    let property = member.property.span;
                    let site = self.site(call, property.start, property.end);
                    self.implicit_calls.push(FunctionSite { function, site });
                }
                if let Some(member) = callee.as_member_expression()
                    && ast::member_str(member) == Some("addEventListener")
                    && let [event, listener, ..] = &call.arguments[..]
                    && let Some(event @ Expression::StringLiteral(_)) = event.as_expression()
                    && ast::static_str(event) == Some("DOMContentLoaded")
                    && let Some(Expression::Identifier(listener)) = listener.as_expression()
                {
                    self.ready.push(self.script.binding(listener));
                }
            }
        }
        walk::walk_call_expression(self, call);
        self.timer_delay = outer_delay;
    }

    /// A directly returned call is in tail position unless an enclosing `try` requires work
    /// after it returns.
    fn visit_return_statement(&mut self, statement: &ReturnStatement<'a>) {
        if !self.in_try
            && let Some(Expression::CallExpression(call)) = &statement.argument
        {
            self.tail_calls.insert(call.span.start);
        }
        walk::walk_return_statement(self, statement);
    }

    fn visit_try_statement(&mut self, statement: &TryStatement<'a>) {
        let outer = mem::replace(&mut self.in_try, true);
        self.visit_block_statement(&statement.block);
        self.in_try = outer;
        if let Some(handler) = &statement.handler {
            self.visit_catch_clause(handler);
        }
        if let Some(finalizer) = &statement.finalizer {
            self.visit_block_statement(finalizer);
        }
    }

    fn visit_object_property_kind(&mut self, property: &ObjectPropertyKind<'a>) {
        if let Some(entry) = ast::key_value(property)
            && !entry.computed
            && let PropertyKey::StaticIdentifier(key) = &entry.key
            && let Expression::Identifier(value) = &entry.value
        {
            self.properties
                .insert(key.name.as_str(), self.script.binding(value));
        }
        walk::walk_object_property_kind(self, property);
    }
}
