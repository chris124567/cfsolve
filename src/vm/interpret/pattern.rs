//! Structural matching of script functions against JavaScript templates, for native versions
//! of functions whose shape the obfuscator varies only superficially.
//!
//! A template matches a function exactly, up to:
//!
//! - consistent renaming of locals (each template local names one function local, and the
//!   reverse);
//! - names beginning with `$`, which match one free binding of the function each, consistently;
//! - names beginning with `$c_`, which match a numeric literal and capture its value;
//! - names beginning with `$e_`, which match any [`Formula`] over locals already matched, and
//!   capture it with each local named as in the template;
//! - operand order of `*`, `===`, `!==`, `==`, and `!=`, and the order of operands in chains of
//!   `&`, `|`, or `^`;
//! - declarations without initializers, which only scope names;
//! - the function's dead helper-object statements (see [`dead_statements`]);
//! - mixed boolean-arithmetic forms of `|`, `^` and `&`, with their operands bound to
//!   temporaries nothing else reads (see [`Matcher::normalized`]);
//! - calls to [`BinaryHelper`]s, which return one operator applied to their two parameters;
//! - statements after a `return` or `throw`, except function and initialized declarations;
//! - blocks that declare nothing block-scoped, which only group statements.
//!
//! Other free names, such as `Error`, must be the same globals. Reordering operands changes
//! evaluation order, so callers must only rely on a match where every operand is free of side
//! effects, which the templates' native versions check by matching each function they call.
//!
//! Normal forms are built in the matcher's own arena from copies of the function's nodes. The
//! copies keep their semantic IDs, so their references still resolve in the function's script.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::{ptr, slice};

use oxc::allocator::{Allocator, CloneIn};
use oxc::ast::AstKind;
use oxc::ast::ast::{
    Argument, ArrayExpressionElement, AssignmentOperator, AssignmentTarget,
    AssignmentTargetPropertyIdentifier, BinaryExpression, BindingIdentifier, BindingPattern, Class,
    Expression, ForStatement, ForStatementInit, Function, IdentifierReference, LogicalExpression,
    MemberExpression, ObjectPropertyKind, PropertyKey, PropertyKind, SequenceExpression,
    SimpleAssignmentTarget, Statement, UpdateExpression, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use oxc::ast::builder::AstBuilder;
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::semantic::{ScopeFlags, SymbolId};
use oxc::span::{ContentEq, SPAN};
use oxc::syntax::operator::{BinaryOperator, LogicalOperator};

use super::formula::Formula;
use super::plan::Routine;
use crate::js;
use crate::js::ast::{Binding, ParsedScript, Script};
use crate::vm::session::Session;
use crate::vm::value::{Callable, Value};
use crate::vm::{HashMap, HashSet, extract};

/// What a match bound, by template name: free bindings, constants, and formulas.
#[derive(Clone, Default)]
pub(super) struct Captures<'a> {
    names: BTreeMap<String, Binding<'a>>,
    constants: BTreeMap<String, f64>,
    formulas: BTreeMap<String, Formula>,
    /// The binary helpers inlined by any attempted match, a superset of those the match relies
    /// on. They must still name the same functions wherever the match is relied on.
    pub(super) helpers: BTreeSet<Binding<'a>>,
}

impl<'a> Captures<'a> {
    pub(super) fn name(&self, placeholder: &str) -> Option<Binding<'a>> {
        self.names.get(placeholder).copied()
    }

    pub(super) fn constant(&self, placeholder: &str) -> Option<f64> {
        self.constants.get(placeholder).copied()
    }

    pub(super) fn formula(&self, placeholder: &str) -> Option<Formula> {
        self.formulas.get(placeholder).cloned()
    }
}

/// An operator a [`BinaryHelper`] applies.
#[derive(Clone, Copy)]
enum Operator {
    Binary(BinaryOperator),
    Logical(LogicalOperator),
}

/// A free function `function (p, q) { return p <op> q; }`, or `q <op> p` if `swapped`. A call to
/// one with two arguments computes the operator on them.
#[derive(Clone, Copy)]
pub(super) struct BinaryHelper {
    operator: Operator,
    swapped: bool,
}

pub(super) type BinaryHelpers<'a> = HashMap<Binding<'a>, BinaryHelper>;

/// The session's binary helpers: functions declared beside the class that no binding shadows,
/// and bindings holding script functions.
pub(super) fn binary_helpers<'a>(session: &Session<'a>) -> BinaryHelpers<'a> {
    let script = session.script;
    let mut helpers = BinaryHelpers::default();
    for (&symbol, function) in &session.functions {
        let binding = Binding::Symbol(symbol);
        if !session.bindings.contains_key(&binding)
            && let Some(helper) = binary_helper(script, function)
        {
            helpers.insert(binding, helper);
        }
    }
    for (&binding, value) in &session.bindings {
        let function = script_function(value);
        if let Some(helper) = function.and_then(|function| binary_helper(script, function)) {
            helpers.insert(binding, helper);
        }
    }
    helpers
}

fn binary_helper(script: Script<'_>, function: &Function<'_>) -> Option<BinaryHelper> {
    if function.r#async || function.generator || extract::parameter_count(&function.params) != 2 {
        return None;
    }
    let first = extract::parameter(&function.params, 0)?.symbol_id();
    let second = extract::parameter(&function.params, 1)?.symbol_id();
    let body = function.body.as_deref()?;
    let ([], [Statement::ReturnStatement(returned)]) = (&body.directives[..], &body.statements[..])
    else {
        return None;
    };
    let (operator, left, right) = match returned.argument.as_ref()?.without_parentheses() {
        Expression::BinaryExpression(binary) => (
            Operator::Binary(binary.operator),
            &binary.left,
            &binary.right,
        ),
        Expression::LogicalExpression(logical) => (
            Operator::Logical(logical.operator),
            &logical.left,
            &logical.right,
        ),
        _ => return None,
    };
    let symbol = |expression: &Expression<'_>| match expression.without_parentheses() {
        Expression::Identifier(name) => script.symbol(name),
        _ => None,
    };
    let (left, right) = (symbol(left)?, symbol(right)?);
    if first == second {
        return None;
    }
    let swapped = if left == first && right == second {
        false
    } else if left == second && right == first {
        true
    } else {
        return None;
    };
    Some(BinaryHelper { operator, swapped })
}

/// The function a script function value runs.
pub(super) fn script_function<'ast>(value: &Value<'ast>) -> Option<&'ast Function<'ast>> {
    if let Value::Function(callable) = value
        && let Callable::Script { function, .. } = &**callable
    {
        return Some(*function);
    }
    None
}

/// Parses a template, which declares one function.
pub(super) fn template(source: &str) -> ParsedScript {
    ParsedScript::parse("template", source).expect("templates parse")
}

/// The one function a template declares.
fn template_function<'t>(template: Script<'t>) -> &'t Function<'t> {
    let functions = extract::functions(&template.program.body);
    let [function] = functions.values().copied().collect::<Vec<_>>()[..] else {
        unreachable!("each template declares one function");
    };
    function
}

/// Matches `template` against `function` in `script`, including nested function declarations.
pub(super) fn matches<'a>(
    template: &ParsedScript,
    script: Script<'a>,
    function: &'a Function<'a>,
    helpers: &BinaryHelpers<'a>,
) -> Option<Captures<'a>> {
    if !function.body.as_deref()?.directives.is_empty() {
        return None;
    }
    matches_routine(
        template,
        script,
        function,
        Routine::function(function)?,
        helpers,
    )
}

/// Matches `template` against `routine`, which is `function`'s or is assembled from it.
pub(super) fn matches_routine<'a>(
    template: &ParsedScript,
    script: Script<'a>,
    function: &'a Function<'a>,
    routine: Routine<'a>,
    helpers: &BinaryHelpers<'a>,
) -> Option<Captures<'a>> {
    let template = template.script();
    let template_function = template_function(template);
    let matcher = Matcher {
        template,
        script,
        template_locals: locals(Routine::function(template_function)?),
        actual_locals: locals(routine),
        dead: dead_statements(script, routine),
        mentions: mentions(script, |visitor| visit_routine(visitor, routine)),
        helpers,
        inlined: RefCell::default(),
        allocator: Allocator::default(),
    };
    let mut state = State::default();
    if !matcher.routine(template_function, function, routine, &mut state) {
        return None;
    }
    state.captures.helpers = matcher.inlined.into_inner();
    Some(state.captures)
}

/// Matching state, cloned at choices so a failed alternative leaves no bindings.
#[derive(Clone, Default)]
struct State<'a> {
    /// Function locals by template local, and the reverse.
    locals: HashMap<SymbolId, SymbolId>,
    reverse: HashMap<SymbolId, SymbolId>,
    captures: Captures<'a>,
}

/// Runs `matches` on a copy of `state`, and keeps the copy only if it matched.
fn attempt<'a>(state: &mut State<'a>, matches: impl FnOnce(&mut State<'a>) -> bool) -> bool {
    let mut attempt = state.clone();
    let matched = matches(&mut attempt);
    if matched {
        *state = attempt;
    }
    matched
}

struct Matcher<'t, 'a, 'helpers> {
    template: Script<'t>,
    script: Script<'a>,
    template_locals: HashSet<SymbolId>,
    actual_locals: HashSet<SymbolId>,
    /// Statements of the function to skip, by address.
    dead: HashSet<usize>,
    /// Reads of each binding in the function.
    mentions: HashMap<Binding<'a>, usize>,
    helpers: &'helpers BinaryHelpers<'a>,
    /// See [`Captures::helpers`].
    inlined: RefCell<BTreeSet<Binding<'a>>>,
    /// Holds normal forms of the function's expressions.
    allocator: Allocator,
}

/// Visits a routine's parameters, statements, and what it returns. Its declarations have no
/// initializers, so they read and write nothing.
fn visit_routine<'a>(visitor: &mut impl Visit<'a>, routine: Routine<'a>) {
    visitor.visit_formal_parameters(routine.parameters);
    for statement in routine.statements {
        visitor.visit_statement(statement);
    }
    if let Some(returned) = routine.returns {
        visitor.visit_expression(returned);
    }
}

/// Every binding a routine declares, including in nested functions, but not the name of its
/// function.
fn locals(routine: Routine<'_>) -> HashSet<SymbolId> {
    #[derive(Default)]
    struct Locals(HashSet<SymbolId>);

    impl<'a> Visit<'a> for Locals {
        fn visit_binding_identifier(&mut self, name: &BindingIdentifier<'a>) {
            self.0.insert(name.symbol_id());
        }
    }

    let mut locals = Locals::default();
    for declaration in routine.declarations {
        for declarator in &declaration.declarations {
            locals.visit_binding_pattern(&declarator.id);
        }
    }
    visit_routine(&mut locals, routine);
    locals.0
}

/// What `reference` resolves to in `script`. Also resolves copies of the script's references,
/// which keep their reference IDs.
fn resolve<'s>(script: Script<'s>, reference: &IdentifierReference<'_>) -> Binding<'s> {
    let reference = script.scoping.get_reference(reference.reference_id());
    match reference.symbol_id() {
        Some(symbol) => Binding::Symbol(symbol),
        None => match script.nodes.kind(reference.node_id()) {
            AstKind::IdentifierReference(original) => Binding::Global(original.name.as_str()),
            _ => unreachable!("a reference belongs to an identifier"),
        },
    }
}

fn address(statement: &Statement<'_>) -> usize {
    ptr::from_ref(statement).addr()
}

/// A statement that may only build a helper object.
struct Candidate<'a> {
    address: usize,
    object: Binding<'a>,
    /// The local `x` of `x = d.k`.
    copy: Option<Binding<'a>>,
}

/// Statements that only build helper objects nothing uses: `d = {}` or `d = { k: function ..
/// }`, `d.k = function ..`, and `x = d.k`, where `d` and `x` are never otherwise mentioned.
/// They create objects and functions and read plain data properties, so skipping them changes
/// nothing observable.
fn dead_statements<'a>(script: Script<'a>, routine: Routine<'a>) -> HashSet<usize> {
    let statements = flattened(script, routine.statements);
    // `d` of `d.k`.
    let object = |member: Option<&MemberExpression<'a>>| match member? {
        MemberExpression::StaticMemberExpression(member) => match &member.object {
            Expression::Identifier(object) => Some(script.binding(object)),
            _ => None,
        },
        _ => None,
    };
    let mut candidates = Vec::new();
    for &statement in &statements {
        let Statement::ExpressionStatement(expression) = statement else {
            continue;
        };
        let Expression::AssignmentExpression(assignment) = &expression.expression else {
            continue;
        };
        if assignment.operator != AssignmentOperator::Assign {
            continue;
        }
        let (object, copy) = match (&assignment.left, &assignment.right) {
            (
                AssignmentTarget::AssignmentTargetIdentifier(object),
                Expression::ObjectExpression(literal),
            ) if literal.properties.iter().all(is_function_property) => {
                (script.binding(object), None)
            }
            (AssignmentTarget::AssignmentTargetIdentifier(copy), right) => {
                let Some(object) = object(right.as_member_expression()) else {
                    continue;
                };
                (object, Some(script.binding(copy)))
            }
            (left, Expression::FunctionExpression(_)) => {
                let Some(object) = object(left.as_member_expression()) else {
                    continue;
                };
                (object, None)
            }
            _ => continue,
        };
        candidates.push(Candidate {
            address: address(statement),
            object,
            copy,
        });
    }
    // Drop candidates until every helper object and copy is mentioned only in the remaining
    // candidates, so no kept statement reads a removed object.
    let all_mentions = mentions(script, |visitor| visit_routine(visitor, routine));
    let all_writes = writes(script, |visitor| visit_routine(visitor, routine));
    loop {
        let objects: HashSet<Binding<'a>> = candidates
            .iter()
            .filter(|candidate| candidate.copy.is_none())
            .map(|candidate| candidate.object)
            .collect();
        let mut inside_mentions: HashMap<Binding<'a>, usize> = HashMap::default();
        let mut inside_writes: HashMap<Binding<'a>, usize> = HashMap::default();
        for &statement in &statements {
            if candidates
                .iter()
                .any(|candidate| candidate.address == address(statement))
            {
                let read = mentions(script, |visitor| visitor.visit_statement(statement));
                for (binding, count) in read {
                    *inside_mentions.entry(binding).or_default() += count;
                }
                let written = writes(script, |visitor| visitor.visit_statement(statement));
                for (binding, count) in written {
                    *inside_writes.entry(binding).or_default() += count;
                }
            }
        }
        let only_inside =
            |binding: &Binding<'a>| all_mentions.get(binding) == inside_mentions.get(binding);
        // Helper objects must also hold only the literals these statements assign.
        let only_written_inside =
            |binding: &Binding<'a>| all_writes.get(binding) == inside_writes.get(binding);
        let before = candidates.len();
        candidates.retain(|candidate| {
            objects.contains(&candidate.object)
                && only_inside(&candidate.object)
                && only_written_inside(&candidate.object)
                && candidate.copy.as_ref().is_none_or(only_inside)
        });
        if candidates.len() == before {
            break;
        }
    }
    candidates
        .into_iter()
        .map(|candidate| candidate.address)
        .collect()
}

/// A plain property whose value is a function expression.
fn is_function_property(property: &ObjectPropertyKind<'_>) -> bool {
    let ObjectPropertyKind::ObjectProperty(property) = property else {
        return false;
    };
    if property.kind != PropertyKind::Init
        || property.method
        || property.shorthand
        || property.computed
    {
        return false;
    }
    let plain = match &property.key {
        PropertyKey::StaticIdentifier(key) => key.name != "__proto__",
        PropertyKey::StringLiteral(key) => key.value != "__proto__",
        _ => false,
    };
    plain && matches!(property.value, Expression::FunctionExpression(_))
}

/// Binding mentions in what `visit` visits.
fn mentions<'s>(
    script: Script<'s>,
    visit: impl FnOnce(&mut Mentions<'s>),
) -> HashMap<Binding<'s>, usize> {
    let mut mentions = Mentions {
        script,
        counts: HashMap::default(),
    };
    visit(&mut mentions);
    mentions.counts
}

/// Reads of bindings, and names of declared functions and classes. Declarations and assignment
/// targets are not mentions: removing a write to a binding nothing reads changes nothing.
struct Mentions<'s> {
    script: Script<'s>,
    counts: HashMap<Binding<'s>, usize>,
}

impl<'s> Mentions<'s> {
    fn count(&mut self, binding: Binding<'s>) {
        *self.counts.entry(binding).or_default() += 1;
    }
}

impl<'x> Visit<'x> for Mentions<'_> {
    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'x>) {
        self.count(resolve(self.script, reference));
    }

    fn visit_simple_assignment_target(&mut self, target: &SimpleAssignmentTarget<'x>) {
        if !matches!(
            target,
            SimpleAssignmentTarget::AssignmentTargetIdentifier(_)
        ) {
            walk::walk_simple_assignment_target(self, target);
        }
    }

    fn visit_assignment_target_property_identifier(
        &mut self,
        property: &AssignmentTargetPropertyIdentifier<'x>,
    ) {
        if let Some(init) = &property.init {
            self.visit_expression(init);
        }
    }

    /// An increment reads its operand.
    fn visit_update_expression(&mut self, update: &UpdateExpression<'x>) {
        match &update.argument {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(name) => {
                self.count(resolve(self.script, name));
            }
            _ => walk::walk_update_expression(self, update),
        }
    }

    fn visit_function(&mut self, function: &Function<'x>, flags: ScopeFlags) {
        if let Some(name) = &function.id {
            self.count(Binding::Symbol(name.symbol_id()));
        }
        walk::walk_function(self, function, flags);
    }

    fn visit_class(&mut self, class: &Class<'x>) {
        if let Some(name) = &class.id {
            self.count(Binding::Symbol(name.symbol_id()));
        }
        walk::walk_class(self, class);
    }
}

/// Binding occurrences other than declarations without initializers: assignment targets,
/// initialized declarations, parameters, and patterns.
fn writes<'s>(
    script: Script<'s>,
    visit: impl FnOnce(&mut Writes<'s>),
) -> HashMap<Binding<'s>, usize> {
    let mut writes = Writes {
        script,
        counts: HashMap::default(),
    };
    visit(&mut writes);
    writes.counts
}

struct Writes<'s> {
    script: Script<'s>,
    counts: HashMap<Binding<'s>, usize>,
}

impl<'s> Writes<'s> {
    fn count(&mut self, binding: Binding<'s>) {
        *self.counts.entry(binding).or_default() += 1;
    }
}

impl<'x> Visit<'x> for Writes<'_> {
    fn visit_binding_identifier(&mut self, name: &BindingIdentifier<'x>) {
        self.count(Binding::Symbol(name.symbol_id()));
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'x>) {
        if declarator.init.is_some() {
            walk::walk_variable_declarator(self, declarator);
        }
    }

    fn visit_simple_assignment_target(&mut self, target: &SimpleAssignmentTarget<'x>) {
        match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(name) => {
                self.count(resolve(self.script, name));
            }
            target => walk::walk_simple_assignment_target(self, target),
        }
    }

    fn visit_assignment_target_property_identifier(
        &mut self,
        property: &AssignmentTargetPropertyIdentifier<'x>,
    ) {
        self.count(resolve(self.script, &property.binding));
        if let Some(init) = &property.init {
            self.visit_expression(init);
        }
    }

    /// Only assignments write; an increment's operand is a read.
    fn visit_update_expression(&mut self, update: &UpdateExpression<'x>) {
        if !matches!(
            update.argument,
            SimpleAssignmentTarget::AssignmentTargetIdentifier(_)
        ) {
            walk::walk_update_expression(self, update);
        }
    }

    /// A function's name is not a write.
    fn visit_function(&mut self, function: &Function<'x>, _: ScopeFlags) {
        self.visit_formal_parameters(&function.params);
        if let Some(body) = &function.body {
            self.visit_function_body(body);
        }
    }

    /// A class's name is not a write.
    fn visit_class(&mut self, class: &Class<'x>) {
        if let Some(heritage) = &class.heritage {
            self.visit_expression(&heritage.expression);
        }
        self.visit_class_body(&class.body);
    }
}

/// A name in a template or function: a reference or a binding.
#[derive(Clone, Copy)]
enum Name<'n, 'x> {
    Reference(&'n IdentifierReference<'x>),
    Binding(&'n BindingIdentifier<'x>),
}

impl<'n> Name<'n, '_> {
    fn text(self) -> &'n str {
        match self {
            Self::Reference(reference) => reference.name.as_str(),
            Self::Binding(binding) => binding.name.as_str(),
        }
    }
}

impl<'a> Matcher<'_, 'a, '_> {
    /// Matches the template's function against `actual`, which is `function`'s routine or
    /// assembled from it.
    fn routine(
        &self,
        template: &Function<'_>,
        function: &Function<'_>,
        actual: Routine<'a>,
        state: &mut State<'a>,
    ) -> bool {
        if !self.signature(template, function, state) {
            return false;
        }
        let Some(body) = &template.body else {
            return false;
        };
        let template = running(self.template, &body.statements, None).0;
        let (statements, completes) = running(self.script, actual.statements, Some(&self.dead));
        match actual.returns {
            // The return follows the routine's statements if they can complete.
            Some(returned) if completes => {
                let Some((last, template)) = template.split_last() else {
                    return false;
                };
                template.len() == statements.len()
                    && self.pairs(template, &statements, state)
                    && match last {
                        Statement::ReturnStatement(last) => last
                            .argument
                            .as_ref()
                            .is_some_and(|argument| self.expression(argument, returned, state)),
                        _ => false,
                    }
            }
            _ => template.len() == statements.len() && self.pairs(&template, &statements, state),
        }
    }

    /// Matches asynchrony, generators, and parameters.
    fn signature(
        &self,
        template: &Function<'_>,
        actual: &Function<'_>,
        state: &mut State<'a>,
    ) -> bool {
        let count = extract::parameter_count(&template.params);
        if template.r#async != actual.r#async
            || template.generator != actual.generator
            || count != extract::parameter_count(&actual.params)
        {
            return false;
        }
        (0..count).all(|index| {
            let template = extract::parameter(&template.params, index);
            let actual = extract::parameter(&actual.params, index);
            template.zip(actual).is_some_and(|(template, actual)| {
                self.name(Name::Binding(template), Name::Binding(actual), state)
            })
        })
    }

    /// Matches a nested function declaration's function.
    fn function(
        &self,
        template: &Function<'_>,
        actual: &Function<'_>,
        state: &mut State<'a>,
    ) -> bool {
        if !self.signature(template, actual, state) {
            return false;
        }
        match (&template.body, &actual.body) {
            (Some(template), Some(actual)) if actual.directives.is_empty() => {
                self.list(&template.statements, &actual.statements, state)
            }
            _ => false,
        }
    }

    fn list(
        &self,
        template: &[Statement<'_>],
        actual: &[Statement<'_>],
        state: &mut State<'a>,
    ) -> bool {
        let template = running(self.template, template, None).0;
        let actual = running(self.script, actual, Some(&self.dead)).0;
        template.len() == actual.len() && self.pairs(&template, &actual, state)
    }

    /// Matches statements pairwise, in order.
    fn pairs(
        &self,
        template: &[&Statement<'_>],
        actual: &[&Statement<'_>],
        state: &mut State<'a>,
    ) -> bool {
        template
            .iter()
            .zip(actual)
            .all(|(template, actual)| self.statement(template, actual, state))
    }

    /// A statement, treating a lone statement and a block holding only it alike.
    fn body(
        &self,
        template: &Statement<'_>,
        actual: &Statement<'_>,
        state: &mut State<'a>,
    ) -> bool {
        self.list(as_list(template), as_list(actual), state)
    }

    fn statement(
        &self,
        template: &Statement<'_>,
        actual: &Statement<'_>,
        state: &mut State<'a>,
    ) -> bool {
        // `var x = y = e;`, where nothing reads `x`, only assigns `y`.
        if let Statement::VariableDeclaration(declaration) = actual
            && !declaration.kind.is_using()
            && let [declarator] = &declaration.declarations[..]
            && let BindingPattern::BindingIdentifier(unread) = &declarator.id
            && !self
                .mentions
                .contains_key(&Binding::Symbol(unread.symbol_id()))
            && let Some(Expression::AssignmentExpression(chained)) = &declarator.init
            && chained.operator == AssignmentOperator::Assign
            && let AssignmentTarget::AssignmentTargetIdentifier(target) = &chained.left
            && let Some((name, value)) = assigned(template)
        {
            return self.name(Name::Reference(name), Name::Reference(target), state)
                && self.expression(value, &chained.right, state);
        }
        if let (Some((name, value)), Some((other, init))) =
            (assigned(template), initialized(actual))
        {
            return self.name(Name::Reference(name), Name::Binding(other), state)
                && self.expression(value, init, state);
        }
        if let (Some((name, init)), Some((other, value))) =
            (initialized(template), assigned(actual))
        {
            return self.name(Name::Binding(name), Name::Reference(other), state)
                && self.expression(init, value, state);
        }
        match (template, actual) {
            (Statement::ExpressionStatement(template), Statement::ExpressionStatement(actual)) => {
                self.expression(&template.expression, &actual.expression, state)
            }
            (Statement::ReturnStatement(template), Statement::ReturnStatement(actual)) => {
                self.optional(template.argument.as_ref(), actual.argument.as_ref(), state)
            }
            (Statement::ThrowStatement(template), Statement::ThrowStatement(actual)) => {
                self.expression(&template.argument, &actual.argument, state)
            }
            (Statement::BlockStatement(template), Statement::BlockStatement(actual)) => {
                self.list(&template.body, &actual.body, state)
            }
            (Statement::IfStatement(template), Statement::IfStatement(actual)) => {
                self.expression(&template.test, &actual.test, state)
                    && self.body(&template.consequent, &actual.consequent, state)
                    && match (&template.alternate, &actual.alternate) {
                        (None, None) => true,
                        (Some(template), Some(actual)) => self.body(template, actual, state),
                        _ => false,
                    }
            }
            (Statement::ForStatement(template), Statement::ForStatement(actual)) => {
                self.for_loop(template, actual, state)
            }
            (Statement::VariableDeclaration(template), Statement::VariableDeclaration(actual))
                if !template.kind.is_using() && !actual.kind.is_using() =>
            {
                self.declarations(template, actual, state)
            }
            (Statement::FunctionDeclaration(template), Statement::FunctionDeclaration(actual)) => {
                template
                    .id
                    .as_ref()
                    .zip(actual.id.as_ref())
                    .is_some_and(|(name, other)| {
                        self.name(Name::Binding(name), Name::Binding(other), state)
                    })
                    && self.function(template, actual, state)
            }
            _ => false,
        }
    }

    fn for_loop(
        &self,
        template: &ForStatement<'_>,
        actual: &ForStatement<'_>,
        state: &mut State<'a>,
    ) -> bool {
        let initialized = match (&template.init, &actual.init) {
            (None, None) => true,
            (
                Some(ForStatementInit::VariableDeclaration(template)),
                Some(ForStatementInit::VariableDeclaration(actual)),
            ) => {
                !template.kind.is_using()
                    && !actual.kind.is_using()
                    && self.declarations(template, actual, state)
            }
            (Some(ForStatementInit::VariableDeclaration(_)), _)
            | (_, Some(ForStatementInit::VariableDeclaration(_))) => false,
            (Some(template), Some(actual)) => {
                self.expression(template.to_expression(), actual.to_expression(), state)
            }
            _ => false,
        };
        initialized
            && self.optional(template.test.as_ref(), actual.test.as_ref(), state)
            && self.optional(template.update.as_ref(), actual.update.as_ref(), state)
            && self.body(&template.body, &actual.body, state)
    }

    fn declarations(
        &self,
        template: &VariableDeclaration<'_>,
        actual: &VariableDeclaration<'_>,
        state: &mut State<'a>,
    ) -> bool {
        template.kind == actual.kind
            && template.declarations.len() == actual.declarations.len()
            && template
                .declarations
                .iter()
                .zip(&actual.declarations)
                .all(|(template, actual)| {
                    let (
                        BindingPattern::BindingIdentifier(name),
                        BindingPattern::BindingIdentifier(other),
                    ) = (&template.id, &actual.id)
                    else {
                        return false;
                    };
                    self.name(Name::Binding(name), Name::Binding(other), state)
                        && self.optional(template.init.as_ref(), actual.init.as_ref(), state)
                })
    }

    fn optional(
        &self,
        template: Option<&Expression<'_>>,
        actual: Option<&Expression<'_>>,
        state: &mut State<'a>,
    ) -> bool {
        match (template, actual) {
            (None, None) => true,
            (Some(template), Some(actual)) => self.expression(template, actual, state),
            _ => false,
        }
    }

    /// Binds a template name to a function name: free names to free bindings, and locals to
    /// locals one to one.
    fn name(&self, template: Name<'_, '_>, actual: Name<'_, '_>, state: &mut State<'a>) -> bool {
        let text = template.text();
        // Constant placeholders only match numeric literals.
        if text.starts_with("$c_") {
            return false;
        }
        let template_symbol = match template {
            Name::Reference(reference) => self.template.symbol(reference),
            Name::Binding(binding) => Some(binding.symbol_id()),
        };
        let actual_binding = match actual {
            Name::Reference(reference) => resolve(self.script, reference),
            Name::Binding(binding) => Binding::Symbol(binding.symbol_id()),
        };
        let template_local = template_symbol.filter(|symbol| self.template_locals.contains(symbol));
        let actual_local = match actual_binding {
            Binding::Symbol(symbol) if self.actual_locals.contains(&symbol) => Some(symbol),
            _ => None,
        };
        let (Some(template_local), Some(actual_local)) = (template_local, actual_local) else {
            if text.starts_with('$') && template_local.is_none() {
                let names = &mut state.captures.names;
                return actual_local.is_none()
                    && *names.entry(text.to_owned()).or_insert(actual_binding) == actual_binding;
            }
            // Other free names, such as `Error`, must be the same global.
            return template_symbol.is_none() && actual_binding == Binding::Global(text);
        };
        match (
            state.locals.get(&template_local),
            state.reverse.get(&actual_local),
        ) {
            (Some(bound), _) => *bound == actual_local,
            (None, Some(_)) => false,
            (None, None) => {
                state.locals.insert(template_local, actual_local);
                state.reverse.insert(actual_local, template_local);
                true
            }
        }
    }

    fn expression(
        &self,
        template: &Expression<'_>,
        actual: &Expression<'_>,
        state: &mut State<'a>,
    ) -> bool {
        if let Expression::Identifier(placeholder) = template.without_parentheses()
            && placeholder.name.starts_with("$e_")
        {
            return self.formula(placeholder.name.as_str(), actual, state);
        }
        if let Some(normalized) = self.normalized(actual) {
            return self.expression(template, normalized, state);
        }
        match (template.without_parentheses(), actual.without_parentheses()) {
            (Expression::Identifier(template), Expression::NumericLiteral(number))
                if template.name.starts_with("$c_") =>
            {
                let constants = &mut state.captures.constants;
                let bound = *constants
                    .entry(template.name.as_str().to_owned())
                    .or_insert(number.value);
                bound.to_bits() == number.value.to_bits()
            }
            (Expression::Identifier(template), Expression::Identifier(actual)) => {
                self.name(Name::Reference(template), Name::Reference(actual), state)
            }
            (Expression::NumericLiteral(template), Expression::NumericLiteral(actual)) => {
                template.value.to_bits() == actual.value.to_bits()
            }
            (Expression::StringLiteral(template), Expression::StringLiteral(actual)) => {
                template.value == actual.value
            }
            (Expression::BooleanLiteral(template), Expression::BooleanLiteral(actual)) => {
                template.value == actual.value
            }
            (Expression::NullLiteral(_), Expression::NullLiteral(_)) => true,
            (Expression::TemplateLiteral(template), Expression::TemplateLiteral(actual)) => {
                template.expressions.is_empty()
                    && actual.expressions.is_empty()
                    && template.quasis.len() == actual.quasis.len()
                    && template
                        .quasis
                        .iter()
                        .zip(&actual.quasis)
                        .all(|(template, actual)| template.value.cooked == actual.value.cooked)
            }
            (Expression::ArrayExpression(template), Expression::ArrayExpression(actual)) => {
                template.elements.len() == actual.elements.len()
                    && template
                        .elements
                        .iter()
                        .zip(&actual.elements)
                        .all(|pair| match pair {
                            (
                                ArrayExpressionElement::Elision(_)
                                | ArrayExpressionElement::SpreadElement(_),
                                _,
                            )
                            | (
                                _,
                                ArrayExpressionElement::Elision(_)
                                | ArrayExpressionElement::SpreadElement(_),
                            ) => false,
                            (template, actual) => self.expression(
                                template.to_expression(),
                                actual.to_expression(),
                                state,
                            ),
                        })
            }
            (Expression::CallExpression(template), Expression::CallExpression(actual)) => {
                self.expression(&template.callee, &actual.callee, state)
                    && self.arguments(&template.arguments, &actual.arguments, state)
            }
            (Expression::NewExpression(template), Expression::NewExpression(actual)) => {
                self.expression(&template.callee, &actual.callee, state)
                    && self.arguments(&template.arguments, &actual.arguments, state)
            }
            (Expression::UnaryExpression(template), Expression::UnaryExpression(actual)) => {
                template.operator == actual.operator
                    && self.expression(&template.argument, &actual.argument, state)
            }
            (Expression::UpdateExpression(template), Expression::UpdateExpression(actual)) => {
                template.operator == actual.operator
                    && template.prefix == actual.prefix
                    && self.simple_target(&template.argument, &actual.argument, state)
            }
            (
                Expression::ConditionalExpression(template),
                Expression::ConditionalExpression(actual),
            ) => {
                self.expression(&template.test, &actual.test, state)
                    && self.expression(&template.consequent, &actual.consequent, state)
                    && self.expression(&template.alternate, &actual.alternate, state)
            }
            (
                Expression::AssignmentExpression(template),
                Expression::AssignmentExpression(actual),
            ) => {
                template.operator == actual.operator
                    && self.target(&template.left, &actual.left, state)
                    && self.expression(&template.right, &actual.right, state)
            }
            (Expression::BinaryExpression(template), Expression::BinaryExpression(actual))
                if template.operator == actual.operator =>
            {
                self.binary(template, actual, state)
            }
            (Expression::LogicalExpression(template), Expression::LogicalExpression(actual))
                if template.operator == actual.operator =>
            {
                attempt(state, |attempt| {
                    self.expression(&template.left, &actual.left, attempt)
                        && self.expression(&template.right, &actual.right, attempt)
                })
            }
            (template, actual) => template
                .as_member_expression()
                .zip(actual.as_member_expression())
                .is_some_and(|(template, actual)| self.member(template, actual, state)),
        }
    }

    fn member(
        &self,
        template: &MemberExpression<'_>,
        actual: &MemberExpression<'_>,
        state: &mut State<'a>,
    ) -> bool {
        if matches!(template.object(), Expression::Super(_))
            || matches!(actual.object(), Expression::Super(_))
        {
            return false;
        }
        self.expression(template.object(), actual.object(), state)
            && match (template, actual) {
                (
                    MemberExpression::StaticMemberExpression(template),
                    MemberExpression::StaticMemberExpression(actual),
                ) => template.property.name == actual.property.name,
                (
                    MemberExpression::ComputedMemberExpression(template),
                    MemberExpression::ComputedMemberExpression(actual),
                ) => self.expression(&template.expression, &actual.expression, state),
                _ => false,
            }
    }

    /// Matches binary expressions with the same operator. The function's expression is not a
    /// normalized form (see [`Self::normalized`]).
    fn binary(
        &self,
        template: &BinaryExpression<'_>,
        actual: &BinaryExpression<'_>,
        state: &mut State<'a>,
    ) -> bool {
        let operator = template.operator;
        if matches!(
            operator,
            BinaryOperator::BitwiseAnd | BinaryOperator::BitwiseOR | BinaryOperator::BitwiseXOR
        ) {
            let (mut template_operands, mut actual_operands) = (Vec::new(), Vec::new());
            self.chain(operator, &template.left, &mut template_operands, false);
            self.chain(operator, &template.right, &mut template_operands, false);
            self.chain(operator, &actual.left, &mut actual_operands, true);
            self.chain(operator, &actual.right, &mut actual_operands, true);
            return template_operands.len() == actual_operands.len()
                && self.permutation(&template_operands, &mut actual_operands, state);
        }
        let ordered = attempt(state, |attempt| {
            self.expression(&template.left, &actual.left, attempt)
                && self.expression(&template.right, &actual.right, attempt)
        });
        if ordered {
            return true;
        }
        let commutes = matches!(
            operator,
            BinaryOperator::Multiplication
                | BinaryOperator::StrictEquality
                | BinaryOperator::StrictInequality
                | BinaryOperator::Equality
                | BinaryOperator::Inequality
        );
        commutes
            && attempt(state, |attempt| {
                self.expression(&template.left, &actual.right, attempt)
                    && self.expression(&template.right, &actual.left, attempt)
            })
    }

    /// Matches each template operand to a distinct remaining operand, in some order.
    fn permutation(
        &self,
        template: &[&Expression<'_>],
        actual: &mut Vec<&Expression<'_>>,
        state: &mut State<'a>,
    ) -> bool {
        let Some((first, rest)) = template.split_first() else {
            return actual.is_empty();
        };
        for index in 0..actual.len() {
            let mut attempt = state.clone();
            if !self.expression(first, actual[index], &mut attempt) {
                continue;
            }
            let candidate = actual.remove(index);
            if self.permutation(rest, actual, &mut attempt) {
                *state = attempt;
                return true;
            }
            actual.insert(index, candidate);
        }
        false
    }

    /// Captures `actual`, in normal form, as the formula `placeholder` names. Its locals must
    /// already match template locals, whose names the formula uses.
    fn formula(&self, placeholder: &str, actual: &Expression<'_>, state: &mut State<'a>) -> bool {
        if state.captures.formulas.contains_key(placeholder) {
            return false;
        }
        let name = |identifier: &IdentifierReference<'_>| {
            let Binding::Symbol(symbol) = resolve(self.script, identifier) else {
                return None;
            };
            let template = state.reverse.get(&symbol)?;
            Some(self.template.scoping.symbol_name(*template).to_owned())
        };
        let Some(formula) = Formula::compile(actual, &|expression| self.normal(expression), &name)
        else {
            return false;
        };
        state
            .captures
            .formulas
            .insert(placeholder.to_owned(), formula);
        true
    }

    /// `expression` in normal form (see [`Self::normalized`]).
    fn normal<'m>(&'m self, mut expression: &'m Expression<'m>) -> &'m Expression<'m> {
        while let Some(normalized) = self.normalized(expression) {
            expression = normalized;
        }
        expression
    }

    /// Collects the operands of a chain of `operator`, looking through parentheses and, if
    /// `normalize` (in the function), normalized forms.
    fn chain<'m>(
        &'m self,
        operator: BinaryOperator,
        expression: &'m Expression<'m>,
        operands: &mut Vec<&'m Expression<'m>>,
        normalize: bool,
    ) {
        if normalize && let Some(normalized) = self.normalized(expression) {
            return self.chain(operator, normalized, operands, normalize);
        }
        match expression.without_parentheses() {
            Expression::BinaryExpression(binary) if binary.operator == operator => {
                self.chain(operator, &binary.left, operands, normalize);
                self.chain(operator, &binary.right, operands, normalize);
            }
            operand => operands.push(operand),
        }
    }

    /// Rewrites a function expression to the plain form it computes, or returns `None`:
    ///
    /// - `(t = a, u = b, e)`, where nothing outside `e` reads `t` or `u`, becomes `e` with `a`
    ///   and `b` in place of `t` and `u`. A match only accepts side-effect-free operands, so
    ///   evaluating them where `e` reads them computes the same values.
    /// - `(x ^ y) + (x & y)` becomes `x | y`, `(x | y) - (x & y)` becomes `x ^ y`, and
    ///   `(x | 0) + (0 | y) - (y | x)` becomes `x & y`, each also under `| 0`. These are
    ///   identities of two's-complement integers, and `|`, `^` and `&` convert both operands to
    ///   them.
    /// - A call to a binary helper becomes its operator applied to the arguments.
    fn normalized<'m>(&'m self, expression: &Expression<'_>) -> Option<&'m Expression<'m>> {
        let expression = expression.without_parentheses();
        if let Expression::SequenceExpression(sequence) = expression {
            return self.substituted(sequence);
        }
        if let Expression::CallExpression(call) = expression
            && let Expression::Identifier(callee) = &call.callee
            && let callee = resolve(self.script, callee)
            && !matches!(callee, Binding::Symbol(symbol) if self.actual_locals.contains(&symbol))
            && let Some(helper) = self.helpers.get(&callee)
            && let [first, second] = &call.arguments[..]
            && let (Some(first), Some(second)) = (first.as_expression(), second.as_expression())
        {
            self.inlined.borrow_mut().insert(callee);
            let (left, right) = if helper.swapped {
                (second, first)
            } else {
                (first, second)
            };
            return Some(self.operation(helper.operator, left, right));
        }
        let Expression::BinaryExpression(outer) = expression else {
            return None;
        };
        if outer.operator == BinaryOperator::BitwiseOR
            && let Some(inner) = truncated(expression)
            && let Some(normalized) = self.normalized(inner)
            && matches!(normalized, Expression::BinaryExpression(found)
                if matches!(found.operator,
                    BinaryOperator::BitwiseOR | BinaryOperator::BitwiseXOR | BinaryOperator::BitwiseAnd))
        {
            return Some(normalized);
        }
        let binary =
            |operator, (left, right)| Some(self.operation(Operator::Binary(operator), left, right));
        match outer.operator {
            BinaryOperator::Addition => {
                let (xor, and) = pair(&outer.left, BinaryOperator::BitwiseXOR)
                    .zip(pair(&outer.right, BinaryOperator::BitwiseAnd))
                    .or_else(|| {
                        pair(&outer.right, BinaryOperator::BitwiseXOR)
                            .zip(pair(&outer.left, BinaryOperator::BitwiseAnd))
                    })?;
                if !self.same_operands(xor, and) {
                    return None;
                }
                binary(BinaryOperator::BitwiseOR, xor)
            }
            BinaryOperator::Subtraction => {
                if let (Some(or), Some(and)) = (
                    pair(&outer.left, BinaryOperator::BitwiseOR),
                    pair(&outer.right, BinaryOperator::BitwiseAnd),
                ) && !is_zero(or.0)
                    && !is_zero(or.1)
                    && self.same_operands(or, and)
                {
                    return binary(BinaryOperator::BitwiseXOR, or);
                }
                let or = pair(&outer.right, BinaryOperator::BitwiseOR)?;
                let (left, right) = pair(&outer.left, BinaryOperator::Addition)?;
                let x = truncated(left).or_else(|| int32_literal(left))?;
                let y = truncated(right).or_else(|| int32_literal(right))?;
                if !self.same_operands((x, y), or) {
                    return None;
                }
                binary(BinaryOperator::BitwiseAnd, (x, y))
            }
            _ => None,
        }
    }

    /// `(t = a, u = b, e)` with the temporaries substituted (see [`Self::normalized`]).
    fn substituted<'m>(&'m self, sequence: &SequenceExpression<'_>) -> Option<&'m Expression<'m>> {
        let (last, temporaries) = sequence.expressions.split_last()?;
        let mut values: HashMap<SymbolId, &'m Expression<'m>> = HashMap::default();
        for temporary in temporaries {
            let Expression::AssignmentExpression(assignment) = temporary else {
                return None;
            };
            let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left else {
                return None;
            };
            let Binding::Symbol(name) = resolve(self.script, name) else {
                return None;
            };
            if assignment.operator != AssignmentOperator::Assign
                || !self.actual_locals.contains(&name)
                || values.contains_key(&name)
            {
                return None;
            }
            let value = self.substitute(&assignment.right, &values);
            values.insert(name, value);
        }
        // Every read of each temporary is in the final expression, which does not write it.
        let reads = mentions(self.script, |visitor| visitor.visit_expression(last));
        let written = writes(self.script, |visitor| visitor.visit_expression(last));
        let all_read_here = values.keys().all(|&name| {
            let name = Binding::Symbol(name);
            self.mentions.get(&name) == reads.get(&name) && !written.contains_key(&name)
        });
        if !all_read_here {
            return None;
        }
        Some(self.substitute(last, &values))
    }

    /// A copy of `expression` with each temporary in `values` replaced by its value.
    fn substitute<'m>(
        &'m self,
        expression: &Expression<'_>,
        values: &HashMap<SymbolId, &'m Expression<'m>>,
    ) -> &'m Expression<'m> {
        struct Substitute<'v, 'm, 'a> {
            script: Script<'a>,
            allocator: &'m Allocator,
            values: &'v HashMap<SymbolId, &'m Expression<'m>>,
        }

        impl<'m> VisitMut<'m> for Substitute<'_, 'm, '_> {
            fn visit_expression(&mut self, expression: &mut Expression<'m>) {
                if let Expression::Identifier(name) = expression
                    && let Binding::Symbol(symbol) = resolve(self.script, name)
                    && let Some(value) = self.values.get(&symbol)
                {
                    *expression = value.clone_in_with_semantic_ids(self.allocator);
                    return;
                }
                walk_mut::walk_expression(self, expression);
            }
        }

        let mut copy = expression.clone_in_with_semantic_ids(&self.allocator);
        Substitute {
            script: self.script,
            allocator: &self.allocator,
            values,
        }
        .visit_expression(&mut copy);
        self.allocator.alloc(copy)
    }

    /// `left <operator> right`, built from copies of the operands.
    fn operation<'m>(
        &'m self,
        operator: Operator,
        left: &Expression<'_>,
        right: &Expression<'_>,
    ) -> &'m Expression<'m> {
        let builder = AstBuilder::new(&self.allocator);
        let left = left.clone_in_with_semantic_ids(&self.allocator);
        let right = right.clone_in_with_semantic_ids(&self.allocator);
        let expression = match operator {
            Operator::Binary(operator) => Expression::BinaryExpression(BinaryExpression::boxed(
                SPAN, left, operator, right, &builder,
            )),
            Operator::Logical(operator) => Expression::LogicalExpression(LogicalExpression::boxed(
                SPAN, left, operator, right, &builder,
            )),
        };
        self.allocator.alloc(expression)
    }

    /// Whether two operand pairs hold the same operands, in either order.
    fn same_operands(
        &self,
        (a, b): (&Expression<'_>, &Expression<'_>),
        (c, d): (&Expression<'_>, &Expression<'_>),
    ) -> bool {
        (self.same(a, c) && self.same(b, d)) || (self.same(a, d) && self.same(b, c))
    }

    /// Whether two expressions are the same syntax, outside their parentheses, with the same
    /// bindings.
    fn same(&self, left: &Expression<'_>, right: &Expression<'_>) -> bool {
        let (left, right) = (left.without_parentheses(), right.without_parentheses());
        left.content_eq(right) && self.bindings(left) == self.bindings(right)
    }

    /// The bindings `expression` references or declares, in order.
    fn bindings(&self, expression: &Expression<'_>) -> Vec<Binding<'a>> {
        struct Bindings<'a> {
            script: Script<'a>,
            found: Vec<Binding<'a>>,
        }

        impl<'x> Visit<'x> for Bindings<'_> {
            fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'x>) {
                self.found.push(resolve(self.script, reference));
            }

            fn visit_binding_identifier(&mut self, name: &BindingIdentifier<'x>) {
                self.found.push(Binding::Symbol(name.symbol_id()));
            }
        }

        let mut bindings = Bindings {
            script: self.script,
            found: Vec::new(),
        };
        bindings.visit_expression(expression);
        bindings.found
    }

    fn arguments(
        &self,
        template: &[Argument<'_>],
        actual: &[Argument<'_>],
        state: &mut State<'a>,
    ) -> bool {
        template.len() == actual.len()
            && template.iter().zip(actual).all(|(template, actual)| {
                template
                    .as_expression()
                    .zip(actual.as_expression())
                    .is_some_and(|(template, actual)| self.expression(template, actual, state))
            })
    }

    fn target(
        &self,
        template: &AssignmentTarget<'_>,
        actual: &AssignmentTarget<'_>,
        state: &mut State<'a>,
    ) -> bool {
        template
            .as_simple_assignment_target()
            .zip(actual.as_simple_assignment_target())
            .is_some_and(|(template, actual)| self.simple_target(template, actual, state))
    }

    fn simple_target(
        &self,
        template: &SimpleAssignmentTarget<'_>,
        actual: &SimpleAssignmentTarget<'_>,
        state: &mut State<'a>,
    ) -> bool {
        match (template, actual) {
            (
                SimpleAssignmentTarget::AssignmentTargetIdentifier(template),
                SimpleAssignmentTarget::AssignmentTargetIdentifier(actual),
            ) => self.name(Name::Reference(template), Name::Reference(actual), state),
            (template, actual) => template
                .as_member_expression()
                .zip(actual.as_member_expression())
                .is_some_and(|(template, actual)| self.member(template, actual, state)),
        }
    }
}

/// The statements that run, without plain declarations and, given `dead`, dead statements, and
/// whether the last of them can complete.
fn running<'s, 'x>(
    script: Script<'_>,
    statements: &'s [Statement<'x>],
    dead: Option<&HashSet<usize>>,
) -> (Vec<&'s Statement<'x>>, bool) {
    let mut running = Vec::new();
    // Nothing after a `return` or `throw` runs, but functions and `var` bindings hoist.
    let mut reachable = true;
    for statement in flattened(script, statements) {
        let declaration = match statement {
            Statement::VariableDeclaration(declaration) if !declaration.kind.is_using() => {
                Some(declaration)
            }
            _ => None,
        };
        let initializes = declaration.is_some_and(|declaration| {
            declaration
                .declarations
                .iter()
                .any(|declarator| declarator.init.is_some())
        });
        let kept =
            reachable || initializes || matches!(statement, Statement::FunctionDeclaration(_));
        reachable &= !matches!(
            statement,
            Statement::ReturnStatement(_) | Statement::ThrowStatement(_)
        );
        let runs = match statement {
            _ if declaration.is_some() => initializes,
            Statement::EmptyStatement(_) => false,
            statement => !dead.is_some_and(|dead| dead.contains(&address(statement))),
        };
        if kept && runs {
            running.push(statement);
        }
    }
    (running, reachable)
}

/// `var x = e;`, which assigns where it stands: the declaration itself only scopes `x`. A `let`
/// behaves the same once the template has matched every use after it.
fn initialized<'s, 'x>(
    statement: &'s Statement<'x>,
) -> Option<(&'s BindingIdentifier<'x>, &'s Expression<'x>)> {
    let Statement::VariableDeclaration(declaration) = statement else {
        return None;
    };
    let [declarator] = &declaration.declarations[..] else {
        return None;
    };
    if matches!(
        declaration.kind,
        VariableDeclarationKind::Const
            | VariableDeclarationKind::Using
            | VariableDeclarationKind::AwaitUsing
    ) {
        return None;
    }
    let BindingPattern::BindingIdentifier(name) = &declarator.id else {
        return None;
    };
    Some((name, declarator.init.as_ref()?))
}

/// `x = e;`.
fn assigned<'s, 'x>(
    statement: &'s Statement<'x>,
) -> Option<(&'s IdentifierReference<'x>, &'s Expression<'x>)> {
    let Statement::ExpressionStatement(statement) = statement else {
        return None;
    };
    let Expression::AssignmentExpression(assignment) = &statement.expression else {
        return None;
    };
    if assignment.operator != AssignmentOperator::Assign {
        return None;
    }
    let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left else {
        return None;
    };
    Some((name, &assignment.right))
}

/// The operands of `expression` if it applies `operator`.
fn pair<'e, 'x>(
    expression: &'e Expression<'x>,
    operator: BinaryOperator,
) -> Option<(&'e Expression<'x>, &'e Expression<'x>)> {
    match expression.without_parentheses() {
        Expression::BinaryExpression(found) if found.operator == operator => {
            Some((&found.left, &found.right))
        }
        _ => None,
    }
}

fn is_zero(expression: &Expression<'_>) -> bool {
    matches!(expression.without_parentheses(), Expression::NumericLiteral(number) if number.value == 0.0)
}

/// `x` of `x | 0` or `0 | x`.
fn truncated<'e, 'x>(expression: &'e Expression<'x>) -> Option<&'e Expression<'x>> {
    let (left, right) = pair(expression, BinaryOperator::BitwiseOR)?;
    if is_zero(right) {
        Some(left)
    } else if is_zero(left) {
        Some(right)
    } else {
        None
    }
}

/// An int32 literal, which is its own `| 0`.
fn int32_literal<'e, 'x>(expression: &'e Expression<'x>) -> Option<&'e Expression<'x>> {
    match expression.without_parentheses() {
        Expression::NumericLiteral(number)
            if f64::from(js::int32(number.value)) == number.value =>
        {
            Some(expression)
        }
        _ => None,
    }
}

/// Statements with blocks that declare nothing block-scoped replaced by their statements. A
/// block may declare functions no other statement mentions: they are then callable only inside
/// the block, where it makes no difference that they hoist to the block's start instead.
fn flattened<'s, 'x>(
    script: Script<'_>,
    statements: &'s [Statement<'x>],
) -> Vec<&'s Statement<'x>> {
    let mut flat = Vec::with_capacity(statements.len());
    for (index, statement) in statements.iter().enumerate() {
        let flattens = |inner: &Statement<'x>| match inner {
            Statement::VariableDeclaration(declaration) => {
                declaration.kind == VariableDeclarationKind::Var
            }
            Statement::FunctionDeclaration(function) => {
                let Some(name) = &function.id else {
                    return false;
                };
                let name = Binding::Symbol(name.symbol_id());
                statements
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .all(|(_, other)| {
                        !mentions(script, |visitor| visitor.visit_statement(other))
                            .contains_key(&name)
                    })
            }
            inner => !inner.is_declaration(),
        };
        match statement {
            Statement::BlockStatement(block) if block.body.iter().all(flattens) => {
                flat.extend(flattened(script, &block.body));
            }
            statement => flat.push(statement),
        }
    }
    flat
}

/// A block's statements, or a lone statement.
fn as_list<'s, 'x>(statement: &'s Statement<'x>) -> &'s [Statement<'x>] {
    match statement {
        Statement::BlockStatement(block) => &block.body,
        statement => slice::from_ref(statement),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names, by placeholder, the constants, and the number of helpers a match captured.
    type Matched = (BTreeMap<String, String>, BTreeMap<String, f64>, usize);

    /// Matches `template` against the function `actual` declares, with the binary helpers
    /// `xor` and `sub`. Returns the free bindings captured, by name.
    fn check(template: &str, actual: &str) -> Option<Matched> {
        let helper = |name: &'static str, source| {
            let parsed = super::template(source);
            let script = parsed.script();
            let helper = binary_helper(script, template_function(script)).expect("a binary helper");
            (Binding::Global(name), helper)
        };
        let helpers = BinaryHelpers::from_iter([
            helper("xor", "function xor(p, q) { return p ^ q; }"),
            helper("sub", "function sub(p, q) { return q - p; }"),
        ]);
        let template = super::template(template);
        let actual = super::template(actual);
        let script = actual.script();
        let captures = matches(&template, script, template_function(script), &helpers)?;
        let names = captures
            .names
            .iter()
            .map(|(placeholder, binding)| {
                let name = match *binding {
                    Binding::Symbol(symbol) => script.scoping.symbol_name(symbol),
                    Binding::Global(name) => name,
                };
                (placeholder.clone(), name.to_owned())
            })
            .collect();
        Some((names, captures.constants, captures.helpers.len()))
    }

    #[test]
    fn inlines_binary_helpers_and_skips_unreachable_statements() {
        let template = "function f(a, b) { return a ^ b - 1; }";
        let captures = check(
            template,
            "function f(a, b) { return xor(sub(1, b), a); return; }",
        );
        assert_eq!(captures.expect("matches").2, 2);
        // Swapped helper arguments, or a local shadowing a helper, fail.
        for other in [
            "function f(a, b) { return xor(sub(b, 1), a); }",
            "function f(a, b) { var xor; return xor(sub(1, b), a); }",
        ] {
            assert!(check(template, other).is_none(), "{other}");
        }
    }

    #[test]
    fn matches_renamed_and_reordered_functions() {
        let template =
            "function f(a, b) { var c; c = $mix(a) ^ b & 255 ^ $c_1; return c * 2 === 0; }";
        let (names, constants, _) = check(
            template,
            "function g(x, y) { var z, w; z = 7 ^ (255 & y) ^ Ut(x); return 0 === 2 * z; }",
        )
        .expect("matches");
        assert_eq!(names.get("$mix").map(String::as_str), Some("Ut"));
        assert_eq!(constants.get("$c_1"), Some(&7.0));
        // Different operators, swapped noncommutative operands, and inconsistent locals fail.
        for other in [
            "function g(x, y) { var z; z = Ut(x) ^ y | 255 ^ 7; return z * 2 === 0; }",
            "function g(x, y) { var z; z = Ut(x) ^ y & 255 ^ 7; return 2 - z === 0; }",
            "function g(x, y) { var z; z = Ut(y) ^ y & 255 ^ 7; return z * 2 === 0; }",
            "function g(x, y) { var z; z = x ^ y & 255 ^ 7; return z * 2 === 0; }",
        ] {
            assert!(check(template, other).is_none(), "{other}");
        }
    }

    #[test]
    fn normalizes_mixed_boolean_arithmetic() {
        let template = "function f(a, b) { return (a | b) ^ b ^ 255 ^ a & b; }";
        let normalized = "function f(a, b) { var t, u; return (t = a, u = b, (t ^ u) + (u & t) | 0) ^ (0 | (b | 255) - (255 & b)) ^ (0 | (a | 0) + (0 | b) - (b | a)); }";
        assert!(check(template, normalized).is_some());
        // A temporary read elsewhere, or a wrong identity, does not normalize.
        for other in [
            "function f(a, b) { var t, u; return (t = a, u = b, (t ^ u) + (u & t) | 0) ^ t ^ b ^ 255 ^ a & b; }",
            "function f(a, b) { return (a ^ b) - (a & b) ^ b ^ 255 ^ a & b; }",
        ] {
            assert!(check(template, other).is_none(), "{other}");
        }
    }

    #[test]
    fn skips_only_dead_helper_objects() {
        let template = "function f(a) { return a - 1; }";
        for dead in [
            "function f(a) { var h, s; h = {}; h._x = function(p, q) { return p - q; }; s = h._x; return a - 1; }",
            "function f(a) { var h; h = { _x: function(p, q) { return p - q; } }; return a - 1; }",
        ] {
            assert!(check(template, dead).is_some(), "{dead}");
        }
        // A used helper, or a getter, keeps its statements.
        for other in [
            "function f(a) { var h, s; h = {}; h._x = function(p, q) { return p - q; }; s = h._x; s(a, 1); return a - 1; }",
            "function f(a) { var h; h = { get _x() { return 1; } }; return a - 1; }",
            "function f(a) { var h; h = {}; h = g(); h._x = function(p) { return p; }; return a - 1; }",
        ] {
            assert!(check(template, other).is_none(), "{other}");
        }
    }
}
