//! Recovers the selectors the iframe queries while rendering its checkbox.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use oxc::ast::AstKind;
use oxc::ast::ast::{
    ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, CallExpression, Expression,
    Function, IfStatement, MethodDefinition, ObjectProperty,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::SymbolId;
use oxc::syntax::operator::{LogicalOperator, UnaryOperator};
use oxc::syntax::scope::ScopeFlags;

use crate::challenge::expression;
use crate::js::ast::{self, Binding, Script};
use crate::js::{JsObject, JsValue, Options};
use crate::script::Source;
use crate::stage2::syntax::{
    assigned_member, is_optional_call, member, plain_parameter, walk_method, walk_property,
};
use crate::{candidates, js};

/// How many nested expressions and aliases [`Builder::value`] follows.
const VALUE_DEPTH: usize = 16;

/// Tracks member-read aliases and the functions that fill an element with a message.
struct Declarations<'a> {
    /// The member read first assigned to each binding.
    aliases: BTreeMap<Binding<'a>, &'a Expression<'a>>,
    /// Each message function, with the selectors its link binder queries.
    messages: BTreeMap<Binding<'a>, Vec<String>>,
}

/// Identifies a message function from its writes to its first parameter.
struct Adapters<'a> {
    script: Script<'a>,
    parameter: SymbolId,
    html: bool,
    /// Functions that receive an element and a computed message, such as a translation.
    translated: Vec<Binding<'a>>,
    /// Functions that receive the element, such as link binders.
    forwarded: Vec<Binding<'a>>,
}

impl<'a> Visit<'a> for Adapters<'a> {
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let Some(member) = assigned_member(&assignment.left)
            && ast::member_str(member) == Some("innerHTML")
            && self.script.refers_to(member.object(), self.parameter)
        {
            self.html = true;
        }
        walk::walk_assignment_expression(self, assignment);
    }
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !is_optional_call(call)
            && let Expression::Identifier(name) = &call.callee
            && call.arguments.first().is_some_and(|argument| {
                self.script
                    .refers_to(ast::argument_expression(argument), self.parameter)
            })
        {
            let callee = self.script.binding(name);
            self.forwarded.push(callee);
            if call.arguments.get(1).is_some_and(|argument| {
                matches!(
                    ast::argument_expression(argument),
                    Expression::CallExpression(_)
                )
            }) {
                self.translated.push(callee);
            }
        }
        walk::walk_call_expression(self, call);
    }
}

impl<'a> Declarations<'a> {
    fn new(script: Script<'a>) -> Self {
        let mut aliases = BTreeMap::new();
        for node in script.nodes.iter() {
            if let AstKind::AssignmentExpression(assignment) = node.kind()
                && let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left
                && member(&assignment.right).is_some()
            {
                aliases
                    .entry(script.binding(name))
                    .or_insert(&assignment.right);
            }
        }
        Self {
            aliases,
            messages: BTreeMap::new(),
        }
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
struct Queries<'a> {
    script: Script<'a>,
    found: Vec<String>,
}

impl<'a> Visit<'a> for Queries<'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !is_optional_call(call)
            && let Some(member) = member(&call.callee)
            && ast::member_str(member) == Some("querySelectorAll")
            && let Some(selector) = call.arguments.first()
            && let Some(JsValue::String(selector)) = expression::static_value(
                self.script,
                ast::argument_expression(selector),
                &Options::new(),
            )
        {
            self.found.push(selector);
        }
        walk::walk_call_expression(self, call);
    }
}

/// Statically evaluates one function body to find the elements it creates and the messages it
/// fills. Selects known branches and skips nested functions.
struct Builder<'a, 'input> {
    script: Script<'a>,
    declarations: &'input Declarations<'a>,
    options: &'input Options,
    values: BTreeMap<Binding<'a>, JsValue>,
    /// The bindings holding created elements, with each one's `type` attribute.
    elements: BTreeMap<Binding<'a>, Option<String>>,
    /// Selectors queried by filled messages, in query order.
    queried: Vec<String>,
}

impl<'a> Builder<'a, '_> {
    fn value(&self, expression: &Expression<'a>, depth: usize) -> Option<JsValue> {
        if depth == 0 {
            return None;
        }
        if let Some(value) = expression::static_value(self.script, expression, self.options) {
            return Some(value);
        }
        match expression {
            Expression::Identifier(name) => {
                let name = self.script.binding(name);
                self.values
                    .get(&name)
                    .cloned()
                    .or_else(|| self.value(self.declarations.aliases.get(&name)?, depth - 1))
            }
            expression if let Some(member) = member(expression) => self
                .value(member.object(), depth - 1)?
                .get(ast::member_str(member)?)
                .cloned(),
            Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => {
                Some(JsValue::Bool(!js::truthy(
                    &self.value(&unary.argument, depth - 1)?,
                )))
            }
            Expression::LogicalExpression(logical)
                if matches!(logical.operator, LogicalOperator::Or | LogicalOperator::And) =>
            {
                let left = self.value(&logical.left, depth - 1)?;
                if js::truthy(&left) == (logical.operator == LogicalOperator::Or) {
                    Some(left)
                } else {
                    self.value(&logical.right, depth - 1)
                }
            }
            Expression::CallExpression(call) => {
                let key =
                    self.value(ast::argument_expression(call.arguments.first()?), depth - 1)?;
                translation(self.options, key.as_str()?).map(JsValue::String)
            }
            _ => None,
        }
    }
    /// The expression's value as `setAttribute` converts it: `String(value)`.
    fn text(&self, expression: &Expression<'a>) -> Option<String> {
        let value = self.value(expression, VALUE_DEPTH)?;
        Some(js::string(Some(&value)))
    }
    /// Whether `call` creates an element with `createElement(NS)` and a known tag.
    fn creates(&self, call: &CallExpression<'a>) -> bool {
        let Some(member) = member(&call.callee) else {
            return false;
        };
        let tag = match ast::member_str(member) {
            Some("createElement") => 0,
            Some("createElementNS") => 1,
            _ => return false,
        };
        call.arguments
            .get(tag)
            .is_some_and(|tag| self.text(ast::argument_expression(tag)).is_some())
    }
}

impl<'a> Visit<'a> for Builder<'a, '_> {
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        walk_property(self, property);
    }
    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        walk_method(self, method);
    }
    fn visit_if_statement(&mut self, statement: &IfStatement<'a>) {
        match self.value(&statement.test, VALUE_DEPTH) {
            Some(value) if js::truthy(&value) => self.visit_statement(&statement.consequent),
            Some(_) => {
                if let Some(alternate) = &statement.alternate {
                    self.visit_statement(alternate);
                }
            }
            None => walk::walk_if_statement(self, statement),
        }
    }
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        let expression = &assignment.right;
        if let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left {
            let name = self.script.binding(name);
            if let Expression::CallExpression(call) = expression
                && self.creates(call)
            {
                self.elements.insert(name, None);
            } else if let Some(value) = self.value(expression, VALUE_DEPTH) {
                self.values.insert(name, value);
            }
        } else if let Some(member) = assigned_member(&assignment.left)
            && ast::member_str(member) == Some("type")
            && let Expression::Identifier(name) = member.object()
            && let Some(value) = self.text(expression)
            && let Some(kind) = self.elements.get_mut(&self.script.binding(name))
        {
            *kind = Some(value);
        }
    }
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // An optional call's operands may still make calls.
        if is_optional_call(call) {
            walk::walk_call_expression(self, call);
            return;
        }
        if let Some(member) = member(&call.callee) {
            if ast::member_str(member) == Some("setAttribute")
                && let Expression::Identifier(name) = member.object()
                && let [key, value] = &call.arguments[..]
                && let (Some(key), Some(value)) = (
                    self.text(ast::argument_expression(key)),
                    self.text(ast::argument_expression(value)),
                )
                && key == "type"
                && let Some(kind) = self.elements.get_mut(&self.script.binding(name))
            {
                *kind = Some(value);
            }
        } else if let Expression::Identifier(message) = &call.callee
            // Filling a message binds its links, running their queries.
            && let Some(queries) = self.declarations.messages.get(&self.script.binding(message))
        {
            self.queried.extend(queries.iter().cloned());
        }
    }
}

/// Returns selectors queried by the checkbox constructor, in order. Includes link-binding
/// queries from every message it fills; the iframe records all of them.
pub fn queries(source: &Source, options: &Options) -> Result<Vec<String>> {
    let script = source.script();
    let functions: Vec<(SymbolId, &Function)> = script
        .in_declared_functions(|function| Some((function.id.as_ref()?.symbol_id(), function)));
    let mut syntax = Declarations::new(script);
    let mut translators = Vec::new();
    for &(name, function) in &functions {
        let (Some(parameter), Some(body)) = (
            function.params.items.first().and_then(plain_parameter),
            &function.body,
        ) else {
            continue;
        };
        let mut adapter = Adapters {
            script,
            parameter,
            html: false,
            translated: Vec::new(),
            forwarded: Vec::new(),
        };
        adapter.visit_function_body(body);
        if adapter.html {
            // A message function hands the element it fills to a link binder.
            let mut queries = Queries {
                script,
                found: Vec::new(),
            };
            for callee in &adapter.forwarded {
                let binder = functions
                    .iter()
                    .find(|(binder, _)| Binding::Symbol(*binder) == *callee);
                if let Some(body) = binder.and_then(|(_, binder)| binder.body.as_ref()) {
                    queries.visit_function_body(body);
                }
            }
            syntax.messages.insert(Binding::Symbol(name), queries.found);
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
            translated.insert(Binding::Symbol(name), queries.clone());
        }
    }
    syntax.messages.extend(translated);
    let mut constructors = Vec::new();
    for &(_, function) in &functions {
        let Some(body) = &function.body else {
            continue;
        };
        let mut builder = Builder {
            script,
            declarations: &syntax,
            options,
            values: function
                .params
                .items
                .first()
                .and_then(plain_parameter)
                .into_iter()
                .map(|name| (Binding::Symbol(name), JsValue::Bool(true)))
                .collect(),
            elements: BTreeMap::new(),
            queried: Vec::new(),
        };
        builder.visit_function_body(body);
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
