//! Recovers the iframe's trace frames from its script.
//!
//! The iframe stores trace frames in `o.<global>`. One helper replaces the last frame; another
//! pushes a frame. Startup uses one root frame, and the callback returned by a response program
//! uses another. The environment audit groups the trace global by its observed frames.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use oxc::ast::AstKind;
use oxc::ast::ast::{
    AssignmentExpression, AssignmentTarget, CallExpression, Expression, Function, MethodDefinition,
    ObjectProperty, Statement,
};
use oxc::ast_visit::{Visit, walk};
use oxc::syntax::operator::BinaryOperator;
use oxc::syntax::scope::ScopeFlags;

use super::syntax::{assigned_member, is_optional_call, member, walk_method, walk_property};
use super::vocabulary;
use crate::js::ast::{self, Binding, Script};
use crate::script::Source;
use crate::{candidates, vm};

/// Trace helpers and root frame names recovered from the iframe script.
pub struct Trace {
    /// The global property holding the trace array.
    pub(crate) global: String,
    /// The helper that replaces the trace's last frame.
    pub(crate) replace: String,
    /// The helper that pushes a frame onto the same array, if there is exactly one.
    pub(crate) push: Option<String>,
    /// The frame named before the initial program starts.
    pub(crate) initial_root: String,
    /// The frame named before the returned program's callback is called.
    pub(crate) returned_root: String,
}

impl Trace {
    /// The frames the environment audit reports, including a worker continuation when present.
    pub fn audit_key(&self, features: &[String], controller: Option<&str>) -> Result<String> {
        let entered = features
            .windows(2)
            .find_map(|pair| match pair {
                [name, next] if *next == self.replace && !vocabulary::is_hex_name(name) => {
                    Some(name)
                }
                [previous, name] if *previous == self.replace && name.contains('$') => Some(name),
                _ => None,
            })
            .context("environment audit has no session trace entry")?;
        let second = controller.unwrap_or(&self.returned_root);
        Ok(format!("{},{second},{entered}", self.initial_root))
    }

    /// Recovers the iframe's trace if its helpers and entry sites are present and unambiguous.
    #[must_use]
    pub fn recover(source: &Source) -> Option<Self> {
        let script = source.script();
        let mut structure = Structure {
            script,
            runner: vm::runner_name(script)?,
            replacements: BTreeSet::new(),
            pushes: BTreeSet::new(),
            initializers: BTreeSet::new(),
            returned: BTreeSet::new(),
            roots: Vec::new(),
        };
        for node in script.nodes.iter() {
            match node.kind() {
                AstKind::Function(function) if function.is_declaration() => {
                    structure.declaration(function);
                }
                AstKind::AssignmentExpression(assignment) => structure.assignment(assignment),
                AstKind::BlockStatement(block) => structure.block(&block.body),
                AstKind::FunctionBody(body) => structure.block(&body.statements),
                AstKind::StaticBlock(block) => structure.block(&block.body),
                _ => {}
            }
        }
        let replacement =
            candidates::exactly_one(&structure.replacements, "trace replace helper").ok()?;
        let root = |entries: &BTreeSet<Binding>, what: &str| {
            let frames: BTreeSet<&str> = structure
                .roots
                .iter()
                .filter(|root| root.helper == replacement.helper && entries.contains(&root.entry))
                .map(|root| root.frame)
                .collect();
            candidates::exactly_one(frames, what)
                .ok()
                .map(str::to_owned)
        };
        // A returned program may push a controller frame over the iframe callback frame.
        // Recovering it needs a unique push helper that edits the replace helper's array.
        let pushes = structure
            .pushes
            .iter()
            .filter(|push| push.array == replacement.array);
        Some(Self {
            global: replacement.array.to_owned(),
            replace: replacement.helper.to_owned(),
            push: candidates::exactly_one(pushes, "trace push helper")
                .ok()
                .map(|push| push.helper.to_owned()),
            initial_root: root(&structure.initializers, "initial root frame")?,
            returned_root: root(&structure.returned, "returned root frame")?,
        })
    }
}

/// Reads a literal string through surrounding parentheses. Rejects lone surrogates because
/// lossy conversion would produce a frame name the program never uses.
fn string<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    ast::static_str(expression.without_parentheses())
}

/// The call an expression statement makes, through parentheses.
fn call<'b, 'a>(statement: &'b Statement<'a>) -> Option<&'b CallExpression<'a>> {
    let Statement::ExpressionStatement(statement) = statement else {
        return None;
    };
    match statement.expression.without_parentheses() {
        Expression::CallExpression(call) => Some(call),
        _ => None,
    }
}

/// Returns the program passed to a call of the program runner `runner`.
fn run_program<'b, 'a>(call: &'b CallExpression<'a>, runner: &str) -> Option<&'b Expression<'a>> {
    if !vm::calls_runner(call, runner) {
        return None;
    }
    Some(ast::argument_expression(call.arguments.first()?))
}

/// Checks for calls running a literal program in this function's own body, as used by the
/// iframe initializer. Skips nested functions.
struct Calls<'runner> {
    runner: &'runner str,
    literal_program: bool,
}

impl<'a> Visit<'a> for Calls<'_> {
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        walk_property(self, property);
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        walk_method(self, method);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !is_optional_call(call) {
            self.literal_program |=
                run_program(call, self.runner).is_some_and(|program| string(program).is_some());
        }
        walk::walk_call_expression(self, call);
    }
}

/// Finds array properties modified by a helper: last-element replacement through
/// `o.array[o.array.length - 1] = value` and append through `o.array.push(value)`.
#[derive(Default)]
struct Helpers<'a> {
    replace: Option<&'a str>,
    push: Option<&'a str>,
}

impl<'a> Visit<'a> for Helpers<'a> {
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let AssignmentTarget::ComputedMemberExpression(member) = &assignment.left
            && let Expression::BinaryExpression(index) = member.expression.without_parentheses()
            && index.operator == BinaryOperator::Subtraction
            && matches!(
                index.right.without_parentheses(),
                Expression::NumericLiteral(number) if number.value == 1.0
            )
            && let Some(length) = self::member(index.left.without_parentheses())
            && ast::member_str(length) == Some("length")
            && let Some(array) = self::member(member.object.without_parentheses())
        {
            self.replace = ast::member_str(array);
        }
        walk::walk_assignment_expression(self, assignment);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if !is_optional_call(call)
            && let Some(member) = self::member(call.callee.without_parentheses())
            && ast::member_str(member) == Some("push")
            && let Some(array) = self::member(member.object().without_parentheses())
        {
            self.push = ast::member_str(array);
        }
        walk::walk_call_expression(self, call);
    }
}

/// A helper `o.<helper> = function ...` that edits the array `o.<array>`.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct ArrayHelper<'a> {
    helper: &'a str,
    array: &'a str,
}

/// A call `o.<helper>("<frame>")` immediately followed by a call of `<entry>`, which names a
/// root frame when `helper` is the replace helper.
struct RootSite<'a> {
    helper: &'a str,
    frame: &'a str,
    entry: Binding<'a>,
}

/// Script components used to recover the trace.
struct Structure<'a> {
    script: Script<'a>,
    /// The name the program runner is installed under.
    runner: String,
    replacements: BTreeSet<ArrayHelper<'a>>,
    pushes: BTreeSet<ArrayHelper<'a>>,
    /// Functions that run a literal program (see [`Calls`]).
    initializers: BTreeSet<Binding<'a>>,
    /// Bindings holding callbacks returned by programs run from nonliteral inputs.
    returned: BTreeSet<Binding<'a>>,
    roots: Vec<RootSite<'a>>,
}

impl<'a> Structure<'a> {
    /// Records a function declaration that runs a literal program.
    fn declaration(&mut self, function: &'a Function<'a>) {
        let (Some(name), Some(body)) = (&function.id, &function.body) else {
            return;
        };
        let mut calls = Calls {
            runner: &self.runner,
            literal_program: false,
        };
        calls.visit_function_body(body);
        if calls.literal_program {
            self.initializers.insert(Binding::Symbol(name.symbol_id()));
        }
    }

    fn assignment(&mut self, assignment: &'a AssignmentExpression<'a>) {
        if let Some(member) = assigned_member(&assignment.left)
            && let Some(helper) = ast::member_str(member)
            && let Expression::FunctionExpression(function) = assignment.right.without_parentheses()
            && let Some(body) = &function.body
        {
            let mut helpers = Helpers::default();
            helpers.visit_function_body(body);
            let edits = |array| ArrayHelper { helper, array };
            self.replacements.extend(helpers.replace.map(edits));
            self.pushes.extend(helpers.push.map(edits));
        }
        if let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left
            && let Expression::CallExpression(call) = assignment.right.without_parentheses()
            && run_program(call, &self.runner).is_some_and(|program| string(program).is_none())
        {
            self.returned.insert(self.script.binding(name));
        }
    }

    /// Records root sites among a block's consecutive statements.
    fn block(&mut self, statements: &'a [Statement<'a>]) {
        for statements in statements.windows(2) {
            if let [trace_statement, entry_statement] = statements
                && let Some(trace_call) = call(trace_statement)
                && let Some(member) = member(trace_call.callee.without_parentheses())
                && let Some(helper) = ast::member_str(member)
                && let Some(argument) = trace_call.arguments.first()
                && let Some(frame) = string(ast::argument_expression(argument))
                && let Some(entry_call) = call(entry_statement)
                && let Expression::Identifier(entry) = entry_call.callee.without_parentheses()
            {
                self.roots.push(RootSite {
                    helper,
                    frame,
                    entry: self.script.binding(entry),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The replace helper, the program runner, and calls where `replaceTrace` sets the root frame
    /// names.
    const ENTRIES: &str = r#"
        window.replaceTrace = function(value) {
            if (window.trace.length > 0) {
                window.trace[window.trace.length - 1] = value;
            } else {
                window.pushTrace(value);
            }
        };
        window.vlJM8 = function(p) { return run(new M(p), 0, 1, []); };
        function start() { window.vlJM8("initial", window); }
        function ready() { window.replaceTrace("fresh-root"); start(); }
        function response(body) {
            callback = vlJM8(body, window);
            if (typeof callback === 'function') {
                window.replaceTrace("fresh-response"); callback({}, send);
            }
        }
    "#;

    /// The trace of a script defining `helpers` and [`ENTRIES`].
    fn recover(helpers: &str) -> Trace {
        Trace::recover(&Source::try_new(&format!("{helpers}{ENTRIES}")).unwrap()).unwrap()
    }

    #[test]
    fn recovers_trace_helpers_and_roots_from_entry_calls() {
        let trace = recover(
            r#"
            window.pushTrace = function(value) {
                if (window.trace.length < window.limit) {
                    window.trace.push(value);
                }
            };
        "#,
        );
        assert_eq!(trace.push.as_deref(), Some("pushTrace"));
        assert_eq!(trace.global, "trace");
        assert_eq!(trace.replace, "replaceTrace");
        assert_eq!(trace.initial_root, "fresh-root");
        assert_eq!(trace.returned_root, "fresh-response");
        assert_eq!(
            recover("").push,
            None,
            "no push helper, so no controller frame"
        );
    }
}
