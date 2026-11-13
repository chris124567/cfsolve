//! Syntax matchers and constructors shared by the deobfuscation passes.
//!
//! JavaScript strings keep lone surrogates, so lookups by Rust string decline those keys instead
//! of conflating them with replacement characters.

use oxc::allocator::{CloneIn, GetAllocator, Vec as ArenaVec};
use oxc::ast::ast::{
    Argument, ArrowFunctionExpression, BindingIdentifier, BindingPattern, CallExpression, Class,
    Expression, Function, FunctionType, IdentifierReference, LabeledStatement, ObjectProperty,
    Program, PropertyKey, Statement, VariableDeclarator,
};
use oxc::ast::builder::AstBuilder;
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::span::{GetSpan, Span};
use oxc::str::Ident;
use oxc::syntax::number::NumberBase;
use oxc::syntax::scope::ScopeFlags;

use super::analysis::{Analysis, Id};
use super::{HashMap, HashSet};
pub(super) use crate::js::ast::{fold_number, number, static_str, static_string};

/// Checks for a primitive literal or a template without substitutions: a value that can be
/// copied to each read. Regular expression literals are excluded because each evaluation creates
/// a new object with its own state.
pub(super) fn is_constant(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::RegExpLiteral(_) => false,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        expression => expression.is_literal(),
    }
}

/// Checks for a reference named `arguments`, which in a non-arrow function may read the
/// implicit arguments object rather than a declared binding.
pub(super) fn is_arguments(reference: &IdentifierReference<'_>) -> bool {
    reference.name == "arguments"
}

/// Returns the value from a function whose entire body is a single `return value`.
pub(super) fn returned<'b, 'a>(function: &'b Function<'a>) -> Option<&'b Expression<'a>> {
    match function.body.as_ref()?.statements.as_slice() {
        [Statement::ReturnStatement(statement)] => statement.argument.as_ref(),
        _ => None,
    }
}

/// Returns the parameter bindings if they are all plain, without defaults, rest, or patterns.
pub(super) fn parameters(function: &Function<'_>) -> Option<Vec<Id>> {
    if function.params.rest.is_some() {
        return None;
    }
    let parameters = function.params.items.iter();
    parameters
        .map(|parameter| match parameter.initializer {
            Some(_) => None,
            None => pattern_id(&parameter.pattern),
        })
        .collect()
}

/// Returns the binding of a plain identifier pattern.
pub(super) fn pattern_id(pattern: &BindingPattern<'_>) -> Option<Id> {
    Some(Id::Local(
        pattern.get_binding_identifier()?.symbol_id.get()?,
    ))
}

/// Returns the binding a named function declares.
pub(super) fn function_id(function: &Function<'_>) -> Option<Id> {
    Some(Id::Local(function.id.as_ref()?.symbol_id.get()?))
}

/// Folds a constant non-negative integer index. Values above `usize::MAX` saturate.
pub(super) fn index(expression: &Expression<'_>) -> Option<usize> {
    let index = fold_number(expression, &|_| None)?;
    (index >= 0.0 && index.fract() == 0.0).then_some(index as usize)
}

/// Matches a non-optional call of a plain identifier.
pub(super) fn direct_call<'b, 'a>(
    expression: &'b Expression<'a>,
) -> Option<(&'b IdentifierReference<'a>, &'b [Argument<'a>])> {
    match expression.get_inner_expression() {
        Expression::CallExpression(call) if !call.optional => {
            Some((call.callee.get_identifier_reference()?, &call.arguments))
        }
        _ => None,
    }
}

/// Matches a non-optional call of the static method `name`, returning its receiver.
pub(super) fn method_call<'b, 'a>(
    expression: &'b Expression<'a>,
    name: &str,
) -> Option<(&'b Expression<'a>, &'b [Argument<'a>])> {
    let Expression::CallExpression(call) = expression.get_inner_expression() else {
        return None;
    };
    let member = call.callee.as_member_expression()?;
    if call.optional || member.optional() || member.static_property_name()? != name {
        return None;
    }
    Some((member.object(), &call.arguments))
}

/// Reads an identifier or static string property key.
pub(super) fn key<'a>(key: &PropertyKey<'a>, computed: bool) -> Option<&'a str> {
    match key {
        PropertyKey::StaticIdentifier(identifier) if !computed => Some(identifier.name.as_str()),
        _ => key.as_expression().and_then(static_str),
    }
}

pub(super) fn number_literal<'a>(
    span: Span,
    value: f64,
    builder: &AstBuilder<'a>,
) -> Expression<'a> {
    Expression::new_numeric_literal(span, value, None, NumberBase::Decimal, builder)
}

/// Creates a statement with the expression's span.
pub(super) fn expression_statement<'a>(
    expression: Expression<'a>,
    builder: &AstBuilder<'a>,
) -> Statement<'a> {
    Statement::new_expression_statement(expression.span(), expression, builder)
}

/// Snapshots the single-write functions that `accept` admits, by binding. Snapshots keep semantic
/// IDs, so later tree mutations neither change them nor redirect their references.
pub(super) fn functions<'a>(
    program: &Program<'a>,
    analysis: &Analysis<'a>,
    accept: &dyn Fn(&Function<'a>) -> bool,
) -> HashMap<Id, &'a Function<'a>> {
    let mut functions = Functions {
        analysis,
        accept,
        found: HashMap::default(),
    };
    functions.visit_program(program);
    functions.found
}

struct Functions<'b, 'a> {
    analysis: &'b Analysis<'a>,
    accept: &'b dyn Fn(&Function<'a>) -> bool,
    found: HashMap<Id, &'a Function<'a>>,
}

impl<'a> Functions<'_, 'a> {
    fn insert(&mut self, id: Id, function: &Function<'a>) {
        if self.analysis.bindings.is_written_once(&id) && (self.accept)(function) {
            self.found.insert(id, self.analysis.save(function));
        }
    }
}

impl<'a> Visit<'a> for Functions<'_, 'a> {
    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        if function.r#type == FunctionType::FunctionDeclaration
            && let Some(id) = function_id(function)
        {
            self.insert(id, function)
        }
        walk::walk_function(self, function, flags)
    }

    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if let Some((id, Expression::FunctionExpression(function))) =
            self.analysis.assignment(expression)
        {
            self.insert(id, function)
        }
        walk::walk_expression(self, expression)
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(id) = pattern_id(&declarator.id)
            && let Some(Expression::FunctionExpression(function)) = &declarator.init
        {
            self.insert(id, function)
        }
        walk::walk_variable_declarator(self, declarator)
    }
}

/// Checks references and declarations, including in nested functions, for any of `ids`.
pub(super) fn mentions(statements: &[Statement<'_>], ids: &[Id], analysis: &Analysis<'_>) -> bool {
    struct Mentions<'b, 'a> {
        analysis: &'b Analysis<'a>,
        ids: &'b [Id],
        found: bool,
    }

    impl<'a> Visit<'a> for Mentions<'_, 'a> {
        fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
            self.found |= self
                .analysis
                .id(reference)
                .is_some_and(|id| self.ids.contains(&id))
        }

        fn visit_binding_identifier(&mut self, binding: &BindingIdentifier<'a>) {
            self.found |= binding
                .symbol_id
                .get()
                .is_some_and(|symbol| self.ids.contains(&Id::Local(symbol)))
        }
    }

    let mut mentions = Mentions {
        analysis,
        ids,
        found: false,
    };
    for statement in statements {
        mentions.visit_statement(statement)
    }
    mentions.found
}

/// Keeps shorthand and `__proto__` data-property semantics after replacing a property's value.
pub(super) fn normalize_property<'a>(property: &mut ObjectProperty<'a>, builder: &AstBuilder<'a>) {
    if let PropertyKey::StaticIdentifier(key) = &property.key
        && property.shorthand
        && property
            .value
            .get_identifier_reference()
            .is_none_or(|value| value.name != key.name)
    {
        property.shorthand = false;
        if key.name == "__proto__" {
            property.computed = true;
            property.key = PropertyKey::new_string_literal(key.span, "__proto__", None, builder);
        }
    }
}

/// Returns the truthiness of a literal whose evaluation has no observable effects.
pub(super) fn truthiness(expression: &Expression<'_>) -> Option<bool> {
    match expression.get_inner_expression() {
        Expression::NumericLiteral(number) => Some(number.value != 0.0 && !number.value.is_nan()),
        Expression::StringLiteral(string) => Some(!string.value.is_empty()),
        Expression::BooleanLiteral(boolean) => Some(boolean.value),
        Expression::NullLiteral(_) => Some(false),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => {
            Some(!template.quasis.first()?.value.cooked?.is_empty())
        }
        Expression::ArrayExpression(array) if array.elements.is_empty() => Some(true),
        Expression::ObjectExpression(object) if object.properties.is_empty() => Some(true),
        _ => None,
    }
}

/// Which labeled `continue` statements [`escapes`] accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LabeledContinue {
    /// Any: labels around the copied statements stay in place, and a merged function cannot
    /// jump to a label outside that function.
    Any,
    /// Only those targeting a loop declared within the copied statements, because the labeled
    /// loop around them is replaced by a block.
    Inner,
}

/// Checks whether `statement` always ends with `return` or `throw`, or, with `jumps`, also with
/// `break` or `continue`. A labeled statement may be the target of its own `break`, so it never
/// counts.
pub(super) fn abrupt(statement: &Statement<'_>, jumps: bool) -> bool {
    match statement {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => true,
        Statement::BreakStatement(_) | Statement::ContinueStatement(_) => jumps,
        Statement::BlockStatement(block) => block.body.iter().any(|inner| abrupt(inner, jumps)),
        Statement::IfStatement(branch) => {
            abrupt(&branch.consequent, jumps)
                && (branch.alternate.as_ref()).is_some_and(|alternate| abrupt(alternate, jumps))
        }
        _ => false,
    }
}

/// Detects jumps whose loop or switch target would be removed when `statements` are copied out
/// of a case. Labeled breaks keep their explicit target, which still encloses the copy.
pub(super) fn escapes(statements: &[Statement<'_>], labeled_continue: LabeledContinue) -> bool {
    let mut jumps = Jumps {
        loops: 0,
        switches: 0,
        labels: HashSet::default(),
        labeled_continue,
        escapes: false,
    };
    for statement in statements {
        jumps.visit_statement(statement)
    }
    jumps.escapes
}

struct Jumps<'a> {
    loops: usize,
    switches: usize,
    /// Labels declared around the visited statement, within the copied statements.
    labels: HashSet<Ident<'a>>,
    labeled_continue: LabeledContinue,
    escapes: bool,
}

impl<'a> Visit<'a> for Jumps<'a> {
    fn visit_statement(&mut self, statement: &Statement<'a>) {
        let is_loop = usize::from(statement.is_iteration_statement());
        let is_switch = usize::from(matches!(statement, Statement::SwitchStatement(_)));
        self.loops += is_loop;
        self.switches += is_switch;
        match statement {
            Statement::BreakStatement(jump) => {
                self.escapes |= jump.label.is_none() && self.loops == 0 && self.switches == 0
            }
            Statement::ContinueStatement(jump) => {
                self.escapes |= match &jump.label {
                    Some(label) => {
                        self.labeled_continue == LabeledContinue::Inner
                            && !self.labels.contains(&label.name)
                    }
                    None => self.loops == 0,
                }
            }
            _ => walk::walk_statement(self, statement),
        }
        self.loops -= is_loop;
        self.switches -= is_switch
    }

    fn visit_labeled_statement(&mut self, statement: &LabeledStatement<'a>) {
        let added = self.labels.insert(statement.label.name);
        self.visit_statement(&statement.body);
        if added {
            self.labels.remove(&statement.label.name);
        }
    }

    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}

    fn visit_class(&mut self, _: &Class<'a>) {}
}

/// Substitutes argument expressions while retaining their binding identities. Oxc prints the
/// parentheses needed for precedence. A substituted member callee or `eval` is detached with
/// `(0, callee)` so the wrapper's value call does not acquire a receiver or become direct eval.
pub(super) fn replace_parameters<'a>(
    expression: &Expression<'a>,
    values: &HashMap<Id, &Expression<'a>>,
    analysis: &Analysis<'a>,
) -> Expression<'a> {
    let mut expression = expression.clone_in_with_semantic_ids(analysis.allocator());
    Replace { analysis, values }.visit_expression(&mut expression);
    expression
}

struct Replace<'b, 'a> {
    analysis: &'b Analysis<'a>,
    values: &'b HashMap<Id, &'b Expression<'a>>,
}

impl<'a> VisitMut<'a> for Replace<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some(id) = self.analysis.expression_id(expression)
            && let Some(value) = self.values.get(&id)
        {
            *expression = value.clone_in_with_semantic_ids(self.analysis.allocator());
        }
    }

    fn visit_object_property(&mut self, property: &mut ObjectProperty<'a>) {
        walk_mut::walk_object_property(self, property);
        normalize_property(property, &self.analysis.ast)
    }

    fn visit_call_expression(&mut self, call: &mut CallExpression<'a>) {
        let id = self.analysis.expression_id(&call.callee);
        let parameter = id.is_some_and(|id| self.values.contains_key(&id));
        walk_mut::walk_call_expression(self, call);
        let eval = call.callee.get_identifier_reference();
        if parameter
            && (call.callee.is_member_expression() || eval.is_some_and(|eval| eval.name == "eval"))
        {
            let builder = &self.analysis.ast;
            let span = call.callee.span();
            let zero = number_literal(span, 0.0, builder);
            let callee = call.callee.clone_in_with_semantic_ids(builder.allocator());
            let expressions = ArenaVec::from_array_in([zero, callee], builder);
            call.callee = Expression::new_sequence_expression(span, expressions, builder);
        }
    }
}
