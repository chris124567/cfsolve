//! Oxc parsing, semantic analysis, and syntax matchers used by extraction and the VM.
//!
//! Every parsed script carries its [`Scoping`], so code identifies bindings by [`SymbolId`].
//! Names identify only unresolved references, which are globals. Matchers accept different
//! syntax depending on the extractor's requirements.

use std::collections::BTreeSet;
use std::{fmt, mem};

use anyhow::{Result, ensure};
use oxc::allocator::Allocator;
use oxc::ast::AstKind;
use oxc::ast::ast::{
    AccessorProperty, Argument, AssignmentTarget, BindingPattern, BindingProperty, Directive,
    Expression, Function, IdentifierReference, MemberExpression, MethodDefinition,
    ObjectExpression, ObjectProperty, ObjectPropertyKind, Program, PropertyDefinition, PropertyKey,
    PropertyKind,
};
use oxc::ast_visit::{Visit, walk};
use oxc::parser::{ParseOptions, Parser};
use oxc::semantic::{AstNodes, Scoping, SemanticBuilder, SymbolId};
use oxc::span::{GetSpan, SourceType};
use oxc::str::JSStr;
use oxc::syntax::node::GetNodeId;
use oxc::syntax::operator::{AssignmentOperator, BinaryOperator, UnaryOperator};
use oxc::syntax::scope::ScopeFlags;
use self_cell::self_cell;

use crate::engine::{self, Lines};

/// The arena and source text a [`Parsed`] tree borrows.
struct Owner {
    allocator: Allocator,
    source: String,
}

/// A tree, allocated in its arena, and its semantic analysis.
struct Parsed<'a> {
    program: &'a Program<'a>,
    scoping: Scoping,
    nodes: AstNodes<'a>,
}

self_cell!(
    struct Cell {
        owner: Owner,
        #[covariant]
        dependent: Parsed,
    }
);

/// A parsed script that owns its arena, source text, and semantic analysis. See [`Script`] for
/// the borrowed view extractors use.
pub(crate) struct ParsedScript(Cell);

// SAFETY: Oxc trees are `!Send` and `!Sync` because their arena vectors can allocate through a
// shared `&Allocator`, and their nodes hold semantic IDs in `Cell`s. A `ParsedScript` owns the
// arena together with every node allocated in it, so moving it moves them all, and it never
// exposes the `Allocator`. Semantic IDs are written only by `SemanticBuilder` while the script is
// built; afterwards the tree is only read, so shared references cannot race.
unsafe impl Send for ParsedScript {}
// SAFETY: See `Send` above: after construction nothing allocates in the arena or writes a node.
unsafe impl Sync for ParsedScript {}

impl ParsedScript {
    /// Parses `source` as a classic script, using `what` to identify it in errors. Rejects
    /// recoverable parse errors and early errors. Parentheses remain in the tree.
    pub(crate) fn parse(what: &str, source: &str) -> Result<Self> {
        Self::build(what, source.to_owned(), |allocator, source| {
            let parsed = Parser::new(allocator, source, SourceType::script())
                .with_options(ParseOptions::default())
                .parse();
            ensure!(
                parsed.diagnostics.is_empty(),
                "cannot parse {what}: {:?}",
                parsed.diagnostics
            );
            Ok(parsed.program)
        })
    }

    /// Builds a script from the tree `build` returns for `source` and analyzes its scopes.
    /// `build` may rewrite the tree, such as by decoding strings; spans keep pointing into
    /// `source`.
    pub(crate) fn build(
        what: &str,
        source: String,
        build: impl for<'a> FnOnce(&'a Allocator, &'a str) -> Result<Program<'a>>,
    ) -> Result<Self> {
        let owner = Owner {
            allocator: Allocator::default(),
            source,
        };
        Cell::try_new(owner, |owner| {
            let program = owner
                .allocator
                .alloc(build(&owner.allocator, &owner.source)?);
            let semantic = SemanticBuilder::new()
                .with_check_syntax_error(true)
                .with_build_nodes(true)
                .build(program);
            ensure!(
                semantic.diagnostics.is_empty(),
                "{what} has early errors: {:?}",
                semantic.diagnostics
            );
            let (scoping, nodes) = semantic.semantic.into_scoping_and_nodes();
            Ok(Parsed {
                program,
                scoping,
                nodes,
            })
        })
        .map(Self)
    }

    #[must_use]
    pub(crate) fn script(&self) -> Script<'_> {
        let parsed = self.0.borrow_dependent();
        Script {
            program: parsed.program,
            scoping: &parsed.scoping,
            nodes: &parsed.nodes,
            source: &self.0.borrow_owner().source,
        }
    }
}

/// A program with its scopes, semantic nodes, and source text. Spans are byte offsets into the
/// source. [`AstNodes`] list every node in source order with its parent, and lend nodes for the
/// program's lifetime, unlike [`Visit`], whose borrows end with each visit.
#[derive(Clone, Copy)]
pub(crate) struct Script<'a> {
    pub program: &'a Program<'a>,
    pub scoping: &'a Scoping,
    pub nodes: &'a AstNodes<'a>,
    pub source: &'a str,
}

/// What an identifier reference resolves to: a binding in the script, or a global by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Binding<'a> {
    Symbol(SymbolId),
    Global(&'a str),
}

impl<'a> Script<'a> {
    /// Returns the original source text of `node`.
    ///
    /// # Panics
    ///
    /// Panics if `node` was not parsed from this script.
    #[must_use]
    pub(crate) fn text(&self, node: &impl GetSpan) -> &'a str {
        node.span().source_text(self.source)
    }

    /// Returns the one-based line and UTF-16 column of byte offset `at`, matching V8 stack
    /// traces.
    ///
    /// # Panics
    ///
    /// Panics if `at` is outside this script.
    #[must_use]
    pub(crate) fn position(&self, at: u32) -> (usize, usize) {
        let (line, column) = engine::line_and_column(&self.source[..at as usize], Lines::Script);
        (line as usize + 1, column as usize + 1)
    }

    /// The binding `reference` resolves to, or `None` for a global.
    #[must_use]
    pub(crate) fn symbol(&self, reference: &IdentifierReference<'_>) -> Option<SymbolId> {
        self.scoping
            .get_reference(reference.reference_id())
            .symbol_id()
    }

    /// What `reference` resolves to.
    #[must_use]
    pub(crate) fn binding(&self, reference: &IdentifierReference<'a>) -> Binding<'a> {
        match self.symbol(reference) {
            Some(symbol) => Binding::Symbol(symbol),
            None => Binding::Global(reference.name.as_str()),
        }
    }

    /// Whether `expression` is a reference to the global `name`, which no binding shadows.
    #[must_use]
    pub(crate) fn is_global(&self, expression: &Expression<'_>, name: &str) -> bool {
        matches!(expression, Expression::Identifier(reference)
            if reference.name == name && self.symbol(reference).is_none())
    }

    /// Whether `expression` is a reference to `symbol`.
    #[must_use]
    pub(crate) fn refers_to(&self, expression: &Expression<'_>, symbol: SymbolId) -> bool {
        matches!(expression, Expression::Identifier(reference)
            if self.symbol(reference) == Some(symbol))
    }

    /// Whether an expression is a `Date.now()` call on the global `Date`.
    #[must_use]
    pub(crate) fn is_date_now(&self, expression: &Expression<'_>) -> bool {
        matches!(expression, Expression::CallExpression(call) if call
            .callee
            .as_member_expression()
            .is_some_and(|member| self.is_method_of(member, "Date", "now")))
    }

    /// Matches `<object>.<property>` where `object` is an unshadowed global, such as
    /// `Math.floor`.
    #[must_use]
    pub(crate) fn is_method_of(
        &self,
        member: &MemberExpression<'_>,
        object: &str,
        property: &str,
    ) -> bool {
        self.is_global(member.object(), object) && member_str(member) == Some(property)
    }

    /// Every function in the program, declared, expressed, or a method, in source order.
    pub(crate) fn functions(&self) -> impl Iterator<Item = &'a Function<'a>> + use<'a> {
        self.nodes
            .iter()
            .filter_map(|node| node.kind().as_function())
    }

    /// Applies `read` to each function declaration in the program, in source order, keeping
    /// what it returns.
    pub(crate) fn in_declared_functions<T>(
        &self,
        read: impl FnMut(&'a Function<'a>) -> Option<T>,
    ) -> Vec<T> {
        self.functions()
            .filter(|function| function.is_declaration())
            .filter_map(read)
            .collect()
    }

    /// Returns declared, assigned, and variable-initialized functions by binding, in source
    /// order, including functions assigned to globals.
    #[must_use]
    pub(crate) fn named_functions(&self) -> Vec<(Binding<'a>, &'a Function<'a>)> {
        self.nodes
            .iter()
            .filter_map(|node| match node.kind() {
                AstKind::Function(function) if function.is_declaration() => {
                    Some((Binding::Symbol(function.id.as_ref()?.symbol_id()), function))
                }
                AstKind::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign
                        && let AssignmentTarget::AssignmentTargetIdentifier(name) =
                            &assignment.left
                        && let Expression::FunctionExpression(function) = &assignment.right =>
                {
                    Some((self.binding(name), &**function))
                }
                AstKind::VariableDeclarator(declaration)
                    if let BindingPattern::BindingIdentifier(name) = &declaration.id
                        && let Some(Expression::FunctionExpression(function)) =
                            &declaration.init =>
                {
                    Some((Binding::Symbol(name.symbol_id()), &**function))
                }
                _ => None,
            })
            .collect()
    }

    /// The source name of `binding`: its declared name, or the global's.
    #[must_use]
    pub(crate) fn name(&self, binding: Binding<'a>) -> &'a str {
        match binding {
            Binding::Symbol(symbol) => self.scoping.symbol_name(symbol),
            Binding::Global(name) => name,
        }
    }

    /// Lends `node`, which a visitor borrowed briefly, for the program's lifetime, using `kind`
    /// such as `AstKind::as_call_expression`.
    ///
    /// # Panics
    ///
    /// Panics if `node` is not from this program.
    #[must_use]
    pub(crate) fn lend<T: GetNodeId>(
        &self,
        node: &T,
        kind: fn(AstKind<'a>) -> Option<&'a T>,
    ) -> &'a T {
        kind(self.nodes.kind(node.node_id())).expect("semantic nodes match the tree")
    }
}

/// Returns a string literal or template without substitutions as JavaScript code units,
/// preserving lone surrogates. Does not unwrap parentheses.
#[must_use]
pub(crate) fn static_string<'a>(expression: &Expression<'a>) -> Option<JSStr<'a>> {
    match expression {
        Expression::StringLiteral(value) => Some(value.value),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            template.quasis.first()?.value.cooked
        }
        _ => None,
    }
}

/// Converts [`static_string`] to a Rust string. Returns `None` for lone surrogates instead of
/// replacing them with U+FFFD and changing the recovered value.
#[must_use]
pub(crate) fn static_str<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    static_string(expression)?.as_str()
}

/// The static name of a member property: `object.name`, `object["name"]`, or
/// ``object[`name`]`` when the template has no substitutions.
#[must_use]
pub(crate) fn member_str<'a>(member: &MemberExpression<'a>) -> Option<&'a str> {
    match member {
        MemberExpression::StaticMemberExpression(member) => Some(member.property.name.as_str()),
        MemberExpression::ComputedMemberExpression(member) => static_str(&member.expression),
        MemberExpression::PrivateFieldExpression(_) => None,
    }
}

/// Matches a property read directly from an identifier, such as a namespace or local, using
/// [`member_str`].
#[must_use]
pub(crate) fn ident_property<'a>(member: &MemberExpression<'a>) -> Option<&'a str> {
    match member.object() {
        Expression::Identifier(_) => member_str(member),
        _ => None,
    }
}

/// Reads an identifier or quoted property key. Excludes numeric and computed keys.
#[must_use]
pub(crate) fn key_str<'a>(key: &PropertyKey<'a>, computed: bool) -> Option<&'a str> {
    match key {
        _ if computed => None,
        PropertyKey::StaticIdentifier(name) => Some(name.name.as_str()),
        PropertyKey::StringLiteral(name) => name.value.as_str(),
        _ => None,
    }
}

/// Reads keys accepted by [`key_str`], plus computed static strings such as `["name"]` or
/// ``[`name`]``.
#[must_use]
pub(crate) fn static_key_str<'a>(key: &PropertyKey<'a>, computed: bool) -> Option<&'a str> {
    if computed {
        static_str(key.as_expression()?)
    } else {
        key_str(key, false)
    }
}

/// The expression an argument passes, through a spread, as `x` in `f(...x)`.
#[must_use]
pub(crate) fn argument_expression<'b, 'a>(argument: &'b Argument<'a>) -> &'b Expression<'a> {
    match argument {
        Argument::SpreadElement(spread) => &spread.argument,
        argument => argument.to_expression(),
    }
}

/// Matches `key: value` properties, excluding spreads, methods, accessors, and shorthand
/// entries.
#[must_use]
pub(crate) fn key_value<'b, 'a>(
    property: &'b ObjectPropertyKind<'a>,
) -> Option<&'b ObjectProperty<'a>> {
    match property {
        ObjectPropertyKind::ObjectProperty(property)
            if property.kind == PropertyKind::Init && !property.method && !property.shorthand =>
        {
            Some(property)
        }
        _ => None,
    }
}

/// Returns only [`key_value`] properties from an object literal.
pub(crate) fn key_values<'b, 'a>(
    object: &'b ObjectExpression<'a>,
) -> impl Iterator<Item = &'b ObjectProperty<'a>> {
    object.properties.iter().filter_map(key_value)
}

/// Collects distinct static strings, see [`static_str`], from the nodes `visit` walks, such as
/// `|literals| literals.visit_program(program)`.
#[must_use]
pub(crate) fn string_literals(visit: impl FnOnce(&mut StringLiterals)) -> BTreeSet<String> {
    let mut literals = StringLiterals::default();
    visit(&mut literals);
    literals.literals
}

/// Collects static strings in expression position. Directives such as `"use strict"` count;
/// non-computed keys such as `{"key": value}` are names, not expressions, and don't.
#[derive(Default)]
pub(crate) struct StringLiterals {
    literals: BTreeSet<String>,
    /// Whether the property key about to be visited is computed.
    computed_key: bool,
}

impl StringLiterals {
    fn key(&mut self, computed: bool, key: &PropertyKey<'_>) {
        self.computed_key = computed;
        self.visit_property_key(key);
    }
}

impl<'a> Visit<'a> for StringLiterals {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if let Some(literal) = static_str(expression) {
            self.literals.insert(literal.to_owned());
        }
        walk::walk_expression(self, expression);
    }

    fn visit_directive(&mut self, directive: &Directive<'a>) {
        if let Some(literal) = directive.expression.value.as_str() {
            self.literals.insert(literal.to_owned());
        }
    }

    fn visit_property_key(&mut self, key: &PropertyKey<'a>) {
        if mem::take(&mut self.computed_key) {
            walk::walk_property_key(self, key);
        }
    }

    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        self.key(property.computed, &property.key);
        self.visit_expression(&property.value);
    }

    fn visit_binding_property(&mut self, property: &BindingProperty<'a>) {
        self.key(property.computed, &property.key);
        self.visit_binding_pattern(&property.value);
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        self.visit_decorators(&method.decorators);
        self.key(method.computed, &method.key);
        self.visit_function(&method.value, ScopeFlags::Function);
    }

    fn visit_property_definition(&mut self, property: &PropertyDefinition<'a>) {
        self.visit_decorators(&property.decorators);
        self.key(property.computed, &property.key);
        if let Some(value) = &property.value {
            self.visit_expression(value);
        }
    }

    fn visit_accessor_property(&mut self, property: &AccessorProperty<'a>) {
        self.visit_decorators(&property.decorators);
        self.key(property.computed, &property.key);
        if let Some(value) = &property.value {
            self.visit_expression(value);
        }
    }
}

/// Matches `callee(args)` when the callee is a plain identifier.
#[must_use]
pub(crate) fn direct_call<'b, 'a>(
    expression: &'b Expression<'a>,
) -> Option<(&'b IdentifierReference<'a>, &'b [Argument<'a>])> {
    match expression {
        Expression::CallExpression(call) if let Expression::Identifier(callee) = &call.callee => {
            Some((callee, &call.arguments))
        }
        _ => None,
    }
}

/// Returns the object and arguments from `object.name(args)` or `object["name"](args)`.
#[must_use]
pub(crate) fn method_call<'b, 'a>(
    expression: &'b Expression<'a>,
    name: &str,
) -> Option<(&'b Expression<'a>, &'b [Argument<'a>])> {
    let Expression::CallExpression(call) = expression else {
        return None;
    };
    let member = call.callee.as_member_expression()?;
    (member_str(member) == Some(name)).then_some((member.object(), &call.arguments[..]))
}

/// A numeric literal, possibly signed or parenthesized.
#[must_use]
pub(crate) fn number(expression: &Expression<'_>) -> Option<f64> {
    match expression {
        Expression::NumericLiteral(value) => Some(value.value),
        Expression::ParenthesizedExpression(value) => number(&value.expression),
        Expression::UnaryExpression(value) if value.operator == UnaryOperator::UnaryNegation => {
            Some(-number(&value.argument)?)
        }
        Expression::UnaryExpression(value) if value.operator == UnaryOperator::UnaryPlus => {
            number(&value.argument)
        }
        _ => None,
    }
}

/// Evaluates numeric arithmetic: literals, parentheses, and the unary and binary numeric
/// operators. `leaf` supplies the value of anything else, such as a known parameter.
#[must_use]
pub(crate) fn fold_number<'a>(
    expression: &Expression<'a>,
    leaf: &impl Fn(&Expression<'a>) -> Option<f64>,
) -> Option<f64> {
    let fold = |expression: &Expression<'a>| fold_number(expression, leaf);
    match expression {
        Expression::NumericLiteral(value) => Some(value.value),
        Expression::ParenthesizedExpression(value) => fold(&value.expression),
        Expression::UnaryExpression(value) => {
            let operand = fold(&value.argument)?;
            match value.operator {
                UnaryOperator::UnaryNegation => Some(-operand),
                UnaryOperator::UnaryPlus => Some(operand),
                UnaryOperator::BitwiseNot => Some(super::bit_not(operand)),
                _ => None,
            }
        }
        Expression::BinaryExpression(binary) => {
            let (left, right) = (fold(&binary.left)?, fold(&binary.right)?);
            match binary.operator {
                BinaryOperator::Addition => Some(left + right),
                BinaryOperator::Subtraction => Some(left - right),
                BinaryOperator::Multiplication => Some(left * right),
                BinaryOperator::Division => Some(left / right),
                BinaryOperator::Remainder => Some(left % right),
                BinaryOperator::BitwiseAnd => Some(super::bit_and(left, right)),
                BinaryOperator::BitwiseOR => Some(super::bit_or(left, right)),
                BinaryOperator::BitwiseXOR => Some(super::bit_xor(left, right)),
                BinaryOperator::ShiftLeft => Some(super::shl(left, right)),
                BinaryOperator::ShiftRight => Some(super::shr(left, right)),
                BinaryOperator::ShiftRightZeroFill => Some(super::ushr(left, right)),
                _ => None,
            }
        }
        _ => leaf(expression),
    }
}

/// Converts `value` to a nonnegative array index, treating `-0` as zero. Rejects infinities and
/// NaN. Saturates finite values above `usize::MAX` so bounds checks still reject them.
#[must_use]
pub(crate) fn array_index(value: f64) -> Option<usize> {
    (value.fract() == 0.0 && value >= 0.0).then_some(value as usize)
}

/// Matches a numeric-literal [`array_index`]. Unlike [`number`], does not unwrap signs or
/// parentheses.
#[must_use]
pub(crate) fn index_literal(expression: &Expression<'_>) -> Option<usize> {
    match expression {
        Expression::NumericLiteral(value) => array_index(value.value),
        _ => None,
    }
}

/// Parses `source` and passes its first statement's expression, without the parentheses
/// wrapped around it, to `read`.
#[cfg(test)]
pub(crate) fn with_expression<T>(
    source: &str,
    read: impl for<'a> FnOnce(Script<'a>, &'a Expression<'a>) -> T,
) -> T {
    use oxc::ast::ast::Statement;

    // Parentheses make leading braces parse as an object literal.
    let parsed = ParsedScript::parse("expression", &format!("({source})")).unwrap();
    let script = parsed.script();
    let [Statement::ExpressionStatement(statement)] = script.program.body.as_slice() else {
        panic!("{source} is not one expression");
    };
    read(script, statement.expression.without_parentheses())
}

impl fmt::Debug for ParsedScript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParsedScript")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use oxc::ast::ast::CallExpression;

    use super::*;

    /// Only a static key reads through a computed string literal.
    #[test]
    fn static_keys_also_accept_computed_strings() {
        with_expression(r#"{a: 1, "b": 2, ["c"]: 3, [d]: 4, 5: 5}"#, |_, object| {
            let Expression::ObjectExpression(object) = object else {
                panic!("not an object")
            };
            let keys: Vec<_> = key_values(object)
                .map(|p| key_str(&p.key, p.computed))
                .collect();
            assert_eq!(keys, [Some("a"), Some("b"), None, None, None]);
            let keys: Vec<_> = key_values(object)
                .map(|p| static_key_str(&p.key, p.computed))
                .collect();
            assert_eq!(keys, [Some("a"), Some("b"), Some("c"), None, None]);
        });
    }

    #[test]
    fn globals_are_unshadowed_references() {
        let parsed =
            ParsedScript::parse("t", "Date.now(); function f(Date) { Date.now(); }").unwrap();
        let script = parsed.script();
        let mut found = Vec::new();
        struct Calls<'s, 'a>(Script<'a>, &'s mut Vec<bool>);
        impl<'a> Visit<'a> for Calls<'_, 'a> {
            fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
                let Calls(script, found) = self;
                let member = call.callee.as_member_expression().unwrap();
                found.push(script.is_method_of(member, "Date", "now"));
                walk::walk_call_expression(self, call);
            }
        }
        Calls(script, &mut found).visit_program(script.program);
        assert_eq!(found, [true, false]);
    }
}
