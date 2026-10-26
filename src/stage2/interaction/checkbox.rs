//! Recovers the selectors the iframe queries while rendering its checkbox.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use swc_core::ecma::ast::{
    ArrowExpr, AssignExpr, AssignTarget, BinaryOp, CallExpr, Callee, Expr, Function, IfStmt,
    SimpleAssignTarget, UnaryOp,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::challenge::expression;
use crate::js::{JsObject, JsValue, Options, ast};
use crate::script::Source;
use crate::{candidates, js};

/// How many nested expressions and aliases [`Builder::value`] follows.
const VALUE_DEPTH: usize = 16;

/// Tracks member-read aliases and the functions that fill an element with a message.
#[derive(Default)]
struct Declarations {
    aliases: BTreeMap<String, Box<Expr>>,
    /// Each message function, with the selectors its link binder queries.
    messages: BTreeMap<String, Vec<String>>,
}

/// Identifies a message function from its writes to its first parameter.
#[derive(Default)]
struct Adapters {
    parameter: String,
    html: bool,
    /// Functions that receive an element and a computed message, such as a translation.
    translated: Vec<String>,
    /// Functions that receive the element, such as link binders.
    forwarded: Vec<String>,
}

impl Visit for Adapters {
    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && ast::member_str(&member.prop) == Some("innerHTML")
            && matches!(&*member.obj, Expr::Ident(name) if name.sym == self.parameter)
        {
            self.html = true;
        }
        assignment.visit_children_with(self);
    }
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(callee) = &call.callee
            && let Expr::Ident(name) = &**callee
            && call.args.first().is_some_and(|argument| {
                matches!(&*argument.expr, Expr::Ident(name) if name.sym == self.parameter)
            })
        {
            self.forwarded.push(name.sym.to_string());
            if call.args.get(1).is_some_and(|argument| argument.expr.is_call()) {
                self.translated.push(name.sym.to_string());
            }
        }
        call.visit_children_with(self);
    }
}

impl Visit for Declarations {
    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(name)) = &assignment.left
            && matches!(&*assignment.right, Expr::Member(_))
        {
            self.aliases
                .entry(name.id.sym.to_string())
                .or_insert_with(|| assignment.right.clone());
        }
        assignment.visit_children_with(self);
    }
}

/// Finds the translation for `key` at any option depth and decodes `%XX` escapes.
fn translation(object: &JsObject, key: &str) -> Option<String> {
    if let Some(text) = object.get(key).and_then(JsValue::as_str) {
        return percent_encoding::percent_decode_str(text)
            .decode_utf8()
            .ok()
            .map(String::from);
    }
    object
        .values()
        .filter_map(JsValue::as_object)
        .find_map(|object| translation(object, key))
}

/// The selectors a function body passes to `querySelectorAll`, in order.
#[derive(Default)]
struct Queries(Vec<String>);

impl Visit for Queries {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Some(member) = call.callee.as_expr().and_then(|callee| callee.as_member())
            && ast::member_str(&member.prop) == Some("querySelectorAll")
            && let Some(selector) = call.args.first()
            && let Some(JsValue::String(selector)) =
                expression::static_value(&selector.expr, &Options::new())
        {
            self.0.push(selector);
        }
        call.visit_children_with(self);
    }
}

/// Statically evaluates one function body to find the elements it creates and the messages it
/// fills. Selects known branches and skips nested functions.
struct Builder<'input> {
    declarations: &'input Declarations,
    options: &'input Options,
    values: BTreeMap<String, JsValue>,
    /// The variables holding created elements, with each one's `type` attribute.
    elements: BTreeMap<String, Option<String>>,
    /// Selectors queried by filled messages, in query order.
    queried: Vec<String>,
}

impl Builder<'_> {
    fn value(&self, expression: &Expr, depth: usize) -> Option<JsValue> {
        if depth == 0 {
            return None;
        }
        if let Some(value) = expression::static_value(expression, self.options) {
            return Some(value);
        }
        match expression {
            Expr::Ident(name) => self.values.get(name.sym.as_ref()).cloned().or_else(|| {
                self.value(self.declarations.aliases.get(name.sym.as_ref())?, depth - 1)
            }),
            Expr::Member(member) => self
                .value(&member.obj, depth - 1)?
                .get(ast::member_str(&member.prop)?)
                .cloned(),
            Expr::Unary(unary) if unary.op == UnaryOp::Bang => Some(JsValue::Bool(!js::truthy(
                &self.value(&unary.arg, depth - 1)?,
            ))),
            Expr::Bin(binary)
                if matches!(binary.op, BinaryOp::LogicalOr | BinaryOp::LogicalAnd) =>
            {
                let left = self.value(&binary.left, depth - 1)?;
                if js::truthy(&left) == (binary.op == BinaryOp::LogicalOr) {
                    Some(left)
                } else {
                    self.value(&binary.right, depth - 1)
                }
            }
            Expr::Call(call) => {
                let key = self.value(&call.args.first()?.expr, depth - 1)?;
                translation(self.options, key.as_str()?).map(JsValue::String)
            }
            _ => None,
        }
    }
    /// The expression's value as `setAttribute` converts it: `String(value)`.
    fn text(&self, expression: &Expr) -> Option<String> {
        let value = self.value(expression, VALUE_DEPTH)?;
        Some(js::string(Some(&value)))
    }
    /// Whether `call` creates an element with `createElement(NS)` and a known tag.
    fn creates(&self, call: &CallExpr) -> bool {
        let Some(Expr::Member(member)) = call.callee.as_expr().map(|callee| &**callee) else {
            return false;
        };
        let tag = match ast::member_str(&member.prop) {
            Some("createElement") => 0,
            Some("createElementNS") => 1,
            _ => return false,
        };
        call.args
            .get(tag)
            .is_some_and(|tag| self.text(&tag.expr).is_some())
    }
}

impl Visit for Builder<'_> {
    fn visit_function(&mut self, _: &Function) {}
    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
    fn visit_if_stmt(&mut self, statement: &IfStmt) {
        match self.value(&statement.test, VALUE_DEPTH) {
            Some(value) if js::truthy(&value) => statement.cons.visit_with(self),
            Some(_) => statement.alt.visit_with(self),
            None => statement.visit_children_with(self),
        }
    }
    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        let expression = &*assignment.right;
        match &assignment.left {
            AssignTarget::Simple(SimpleAssignTarget::Ident(name)) => {
                let name = name.id.sym.to_string();
                if let Expr::Call(call) = expression
                    && self.creates(call)
                {
                    self.elements.insert(name, None);
                } else if let Some(value) = self.value(expression, VALUE_DEPTH) {
                    self.values.insert(name, value);
                }
            }
            AssignTarget::Simple(SimpleAssignTarget::Member(member))
                if ast::member_str(&member.prop) == Some("type") =>
            {
                if let Expr::Ident(name) = &*member.obj
                    && let Some(value) = self.text(expression)
                    && let Some(kind) = self.elements.get_mut(name.sym.as_ref())
                {
                    *kind = Some(value);
                }
            }
            _ => {}
        }
    }
    fn visit_call_expr(&mut self, call: &CallExpr) {
        let Callee::Expr(callee) = &call.callee else {
            return;
        };
        match &**callee {
            Expr::Member(member) => {
                if ast::member_str(&member.prop) == Some("setAttribute")
                    && let Expr::Ident(name) = &*member.obj
                    && let [key, value] = &call.args[..]
                    && let (Some(key), Some(value)) = (self.text(&key.expr), self.text(&value.expr))
                    && key == "type"
                    && let Some(kind) = self.elements.get_mut(name.sym.as_ref())
                {
                    *kind = Some(value);
                }
            }
            // Filling a message binds its links, running their queries.
            Expr::Ident(message) => {
                if let Some(queries) = self.declarations.messages.get(message.sym.as_ref()) {
                    self.queried.extend(queries.iter().cloned());
                }
            }
            _ => {}
        }
    }
}

/// The name of `function`'s first parameter, if it is a plain identifier.
fn first_parameter(function: &Function) -> Option<String> {
    Some(function.params.first()?.pat.as_ident()?.id.sym.to_string())
}

/// Returns selectors queried by the checkbox constructor, in order. Includes link-binding
/// queries from every message it fills; the iframe records all of them.
pub fn queries(source: &Source, options: &Options) -> Result<Vec<String>> {
    let parsed = source.parsed();
    let functions = ast::declared_functions(&parsed.script);
    let mut syntax = Declarations::default();
    parsed.script.visit_with(&mut syntax);
    let mut translators = Vec::new();
    for (name, function) in &functions {
        let (Some(parameter), Some(body)) = (first_parameter(function), &function.body) else {
            continue;
        };
        let mut adapter = Adapters {
            parameter,
            ..Adapters::default()
        };
        body.visit_with(&mut adapter);
        if adapter.html {
            // A message function hands the element it fills to a link binder.
            let mut queries = Queries::default();
            for callee in &adapter.forwarded {
                let binder = functions.iter().find(|(binder, _)| binder == callee);
                if let Some(body) = binder.and_then(|(_, binder)| binder.body.as_ref()) {
                    body.visit_with(&mut queries);
                }
            }
            syntax.messages.insert(name.clone(), queries.0);
        }
        translators.push((name, adapter.translated));
    }
    // Also recognize functions that fill an element with a translation through another message
    // function.
    let mut translated = BTreeMap::new();
    for (name, callees) in translators {
        let filled = callees
            .iter()
            .find_map(|callee| syntax.messages.get(callee));
        if let Some(queries) = filled {
            translated.insert(name.clone(), queries.clone());
        }
    }
    syntax.messages.extend(translated);
    let mut constructors = Vec::new();
    for (_, function) in &functions {
        let Some(body) = &function.body else {
            continue;
        };
        let mut builder = Builder {
            declarations: &syntax,
            options,
            values: first_parameter(function)
                .into_iter()
                .map(|name| (name, JsValue::Bool(true)))
                .collect(),
            elements: BTreeMap::new(),
            queried: Vec::new(),
        };
        body.visit_with(&mut builder);
        if builder
            .elements
            .values()
            .any(|kind| kind.as_deref() == Some("checkbox"))
        {
            constructors.push(builder.queried);
        }
    }
    candidates::exactly_one(constructors, "checkbox constructor")
        .context("iframe has no recognized checkbox")
}
