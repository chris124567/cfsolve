//! Inlines dispatcher calls by following `if`, `switch`, and nested blocks with known numeric
//! arguments. Handles applied calls, direct calls, and operator expressions:
//!
//! ```js
//! function b(n, f, args) {
//!   switch (3832 ^ n) {
//!     case 973348: return Reflect.apply(f, undefined, args);
//!   }
//! }
//! function c(n, m, f, x) { switch (n) { case 1: switch (m) { case 2: return f(x); } } }
//! function w(op, x, y) { if (op === 0) return x + y; else return x - y; }
//!
//! b(971996, encode, [payload]);  // encode(payload)
//! c(1, 2, encode, payload);      // encode(payload)
//! w(1, 630, 622);                // 630 - 622
//! ```
//!
//! The first selector must be a literal. Applied and direct call targets must be identifiers to
//! keep `this` undefined. Direct calls must forward the remaining parameters in order, omitting
//! only numeric selectors. Operator arguments must have no side effects because they may be
//! evaluated repeatedly or in a different order. `Reflect` and `undefined` must refer to globals.
//!
//! The decoding pass only follows the first argument and leaves direct calls unchanged. This
//! preserves the dispatcher frames needed to recover click stacks.

use std::iter;

use oxc::allocator::{CloneIn, GetAllocator, Vec as ArenaVec};
use oxc::ast::ast::{Argument, Expression, Function, Program, Statement};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::Span;
use oxc::syntax::operator::{BinaryOperator, UnaryOperator};
use oxc_ecmascript::side_effects::MayHaveSideEffects;

use super::analysis::{Analysis, Id};
use super::{HashMap, ast};

/// Inlines applications and operations selected by the first numeric argument, preserving
/// direct-call frames.
pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    inline(program, analysis, /* all= */ false)
}

/// Also inlines direct target calls and numeric selectors in later argument positions.
pub(super) fn run_all<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    inline(program, analysis, /* all= */ true)
}

fn inline<'a>(program: &mut Program<'a>, analysis: &Analysis<'a>, all: bool) -> bool {
    let functions = ast::functions(program, analysis, &|function| {
        let body = function.body.as_ref();
        body.is_some_and(|body| may_select(&body.statements))
    });
    let mut inline = Inline {
        analysis,
        functions: &functions,
        all,
        changed: false,
    };
    inline.visit_program(program);
    inline.changed
}

/// Rejects unrelated function bodies before taking an arena snapshot. A supported path must
/// reach a return through blocks, conditionals, or switches without executing other statements.
fn may_select<'b, 'a: 'b>(statements: impl IntoIterator<Item = &'b Statement<'a>>) -> bool {
    for statement in statements {
        let selects = match statement {
            Statement::ReturnStatement(statement) => return statement.argument.is_some(),
            Statement::BlockStatement(block) => may_select(&block.body),
            Statement::EmptyStatement(_) => false,
            Statement::IfStatement(branch) => {
                may_select([&branch.consequent]) || may_select(branch.alternate.iter())
            }
            Statement::SwitchStatement(switch) => {
                switch.cases.iter().any(|case| may_select(&case.consequent))
            }
            _ => return false,
        };
        if selects {
            return true;
        }
    }
    false
}

/// Follows a helper body using only the numeric parameter values known at this call.
struct Path<'b, 'a> {
    values: HashMap<Id, f64>,
    analysis: &'b Analysis<'a>,
}

impl<'a> Path<'_, 'a> {
    fn number(&self, expression: &Expression<'a>) -> Option<f64> {
        ast::fold_number(expression, &|leaf| {
            let id = self.analysis.expression_id(leaf)?;
            self.values.get(&id).copied()
        })
    }

    fn truthy(&self, expression: &Expression<'a>) -> Option<bool> {
        match expression.get_inner_expression() {
            Expression::BooleanLiteral(literal) => Some(literal.value),
            Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::LogicalNot => {
                Some(!self.truthy(&unary.argument)?)
            }
            Expression::BinaryExpression(binary) => {
                let left = self.number(&binary.left)?;
                let right = self.number(&binary.right)?;
                Some(match binary.operator {
                    BinaryOperator::Equality | BinaryOperator::StrictEquality => left == right,
                    BinaryOperator::Inequality | BinaryOperator::StrictInequality => left != right,
                    BinaryOperator::LessThan => left < right,
                    BinaryOperator::LessEqualThan => left <= right,
                    BinaryOperator::GreaterThan => left > right,
                    BinaryOperator::GreaterEqualThan => left >= right,
                    _ => return None,
                })
            }
            _ => None,
        }
    }

    /// Returns `Some(Some(value))` for a reached value return, `Some(None)` for normal completion,
    /// and `None` for an unsupported path. Switch selection follows fallthrough until a return;
    /// paths with a `break` are left to other rewrites.
    fn run<'c>(
        &self,
        statements: impl IntoIterator<Item = &'c Statement<'a>>,
    ) -> Option<Option<&'c Expression<'a>>>
    where
        'a: 'c,
    {
        for statement in statements {
            let returned = match statement {
                Statement::ReturnStatement(statement) => {
                    return Some(Some(statement.argument.as_ref()?));
                }
                Statement::BlockStatement(block) => self.run(&block.body)?,
                Statement::EmptyStatement(_) => None,
                Statement::IfStatement(branch) => {
                    if self.truthy(&branch.test)? {
                        self.run([&branch.consequent])?
                    } else {
                        self.run(branch.alternate.iter())?
                    }
                }
                Statement::SwitchStatement(switch) => {
                    let value = self.number(&switch.discriminant)?;
                    let mut matched = None;
                    let mut default = None;
                    for (index, case) in switch.cases.iter().enumerate() {
                        if let Some(test) = &case.test {
                            if self.number(test)? == value {
                                matched.get_or_insert(index);
                            }
                        } else {
                            default = Some(index)
                        }
                    }
                    let Some(start) = matched.or(default) else {
                        continue;
                    };
                    let cases = switch.cases[start..].iter();
                    let body: Vec<&Statement<'a>> =
                        cases.flat_map(|case| &case.consequent).collect();
                    if body
                        .iter()
                        .any(|statement| matches!(statement, Statement::BreakStatement(_)))
                    {
                        return None;
                    }
                    self.run(body)?
                }
                _ => return None,
            };
            if returned.is_some() {
                return Some(returned);
            }
        }
        Some(None)
    }
}

/// Accepts unary and binary operations whose leaves pass `leaf`, excluding `delete`.
fn operation(expression: &Expression<'_>, leaf: &impl Fn(&Expression<'_>) -> bool) -> bool {
    match expression.get_inner_expression() {
        Expression::UnaryExpression(unary) => {
            unary.operator != UnaryOperator::Delete && operation(&unary.argument, leaf)
        }
        Expression::BinaryExpression(binary) => {
            operation(&binary.left, leaf) && operation(&binary.right, leaf)
        }
        Expression::LogicalExpression(logical) => {
            operation(&logical.left, leaf) && operation(&logical.right, leaf)
        }
        expression => leaf(expression),
    }
}

struct Inline<'b, 'a> {
    analysis: &'b Analysis<'a>,
    functions: &'b HashMap<Id, &'a Function<'a>>,
    all: bool,
    changed: bool,
}

impl<'a> Inline<'_, 'a> {
    /// Selects the reached return without evaluating unknown code, then checks its forwarding form.
    /// Direct calls must preserve argument order and omit only numeric selectors. `Reflect.apply`
    /// requires global `Reflect` and an effect-free undefined receiver. Repeated or reordered
    /// operator operands must themselves be effect-free.
    fn replacement(
        &self,
        id: Id,
        arguments: &[Argument<'a>],
        span: Span,
    ) -> Option<Expression<'a>> {
        let analysis = self.analysis;
        let function = *self.functions.get(&id)?;
        if function.r#async || function.generator {
            return None;
        }
        let parameters = ast::parameters(function)?;
        let arguments: Vec<&Expression<'a>> = arguments
            .iter()
            .map(Argument::as_expression)
            .collect::<Option<_>>()?;
        ast::number(arguments.first()?)?;
        let count = if self.all { arguments.len() } else { 1 };
        let known = parameters.iter().zip(arguments.iter().take(count));
        let values = known
            .filter_map(|(&id, argument)| Some((id, ast::number(argument)?)))
            .collect();
        let path = Path { values, analysis };
        let returned = path.run(&function.body.as_ref()?.statements)??;
        let position = |expression: Option<&Expression<'a>>| {
            let id = analysis.expression_id(expression?)?;
            parameters.iter().position(|parameter| *parameter == id)
        };
        if self.all
            && let Expression::CallExpression(call) = returned
            && let Some(positions) = iter::once(Some(&call.callee))
                .chain(call.arguments.iter().map(Argument::as_expression))
                .map(&position)
                .collect::<Option<Vec<usize>>>()
            && arguments.len() == parameters.len()
            && positions.is_sorted_by(|left, right| left < right)
            && (0..arguments.len())
                .all(|index| positions.contains(&index) || ast::number(arguments[index]).is_some())
            && let [target, passed @ ..] = positions.as_slice()
            && matches!(arguments[*target], Expression::Identifier(_))
        {
            let passed = passed.iter().map(|&index| self.argument(arguments[index]));
            let passed = ArenaVec::from_iter_in(passed, &analysis.ast);
            return Some(self.call(span, arguments[*target], passed));
        }
        if let Some((reflect, [function, this, applied])) = ast::method_call(returned, "apply")
            && let Expression::Identifier(reflect) = reflect
            && analysis.is_global(reflect, "Reflect")
            && let Some(this) = this.as_expression()
            && analysis.is_undefined(this)
        {
            let target = position(function.as_expression())?;
            let applied = position(applied.as_expression())?;
            let (Expression::Identifier(_), Expression::ArrayExpression(array)) =
                (arguments.get(target)?, arguments.get(applied)?)
            else {
                return None;
            };
            let elements = array.elements.iter();
            let passed = elements
                .map(|element| Some(self.argument(element.as_expression()?)))
                .collect::<Option<Vec<_>>>()?;
            let passed = ArenaVec::from_iter_in(passed, &analysis.ast);
            return Some(self.call(span, arguments[target], passed));
        }
        let forwards = |expression: &Expression<'_>| {
            let id = analysis.expression_id(expression);
            id.is_some_and(|id| parameters.contains(&id))
                || matches!(expression, Expression::NumericLiteral(_))
        };
        let effect_free = |expression: &Expression<'_>| {
            expression.is_literal()
                || matches!(expression, Expression::Identifier(_))
                    && !expression.may_have_side_effects(analysis)
        };
        if arguments.len() == parameters.len()
            && operation(returned, &forwards)
            && arguments
                .iter()
                .all(|argument| operation(argument, &effect_free))
        {
            let values = parameters.into_iter().zip(arguments).collect();
            return Some(ast::replace_parameters(returned, &values, analysis));
        }
        None
    }

    fn argument(&self, expression: &Expression<'a>) -> Argument<'a> {
        Argument::from(expression.clone_in_with_semantic_ids(self.analysis.allocator()))
    }

    fn call(
        &self,
        span: Span,
        callee: &Expression<'a>,
        arguments: ArenaVec<'a, Argument<'a>>,
    ) -> Expression<'a> {
        let callee = callee.clone_in_with_semantic_ids(self.analysis.allocator());
        Expression::new_call_expression(span, callee, None, arguments, false, &self.analysis.ast)
    }
}

impl<'a> VisitMut<'a> for Inline<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some((callee, arguments)) = ast::direct_call(expression)
            && let Some(id) = self.analysis.id(callee)
            && let Some(value) = self.replacement(id, arguments, callee.span)
        {
            *expression = value;
            self.changed = true
        }
    }
}

#[cfg(test)]
mod tests {
    use oxc::allocator::Allocator;
    use oxc::ast::ast::Statement;

    use crate::deobfuscate::{pipeline, testing};

    const APPLY: &str = "var b; b = function (n, m, r) {
        switch (3832 ^ n) {
            case 973348: return Reflect.apply(m, undefined, r);
            case 428312: return Reflect.apply(m, void 0, r);
        }
    };";

    const OPERATOR: &str = "var w; w = function (E, P, S) {
        switch (E) { case 0: return P + S; case 1: return P - S; case 2: return S * P; default: return P % S; }
    };";

    #[test]
    fn applies_the_target_only_for_provable_applications() {
        let inline = |source: &str| testing::rewrite(source, super::run);
        let output = inline(&format!(
            "{APPLY} f(b(971996, encode, [x, 1]), b(428000, g, []));"
        ));
        assert!(output.contains("f(encode(x, 1), g())"), "{output}");
        for call in [
            "b(1, encode, [x])",
            "b(971996, o.encode, [x])",
            "b(971996, encode, args)",
            "b(971996, encode, [...x])",
        ] {
            let output = inline(&format!("{APPLY} f({call});"));
            assert!(output.contains("f(b("), "{output}");
        }
        let reassigned = inline(&format!("{APPLY} b = h; f(b(971996, encode, [x]));"));
        assert!(reassigned.contains("f(b("), "{reassigned}");
    }

    #[test]
    fn calls_targets_selected_by_several_selectors_only_in_argument_order() {
        let inline = |source: &str| testing::rewrite(source, super::run_all);
        let dispatchers = "function c(n, m, f, x, y) {
                switch (n ^ 5) { case 1: switch (3 ^ m) { case 1: return f(x, y); } return; }
            }
            function d(n, f, x, y) { switch (n) { case 0: return f(y, x); } }";
        let source = format!("{dispatchers} g(c(4, 2, encode, a(), b));");
        let output = inline(&source);
        assert!(output.contains("g(encode(a(), b))"), "{output}");
        let decoding = testing::rewrite(&source, super::run);
        assert!(decoding.contains("g(c(4, 2,"), "{decoding}");
        for call in [
            "c(4, 2, o.encode, a, b)",
            "c(4, 2, encode, a)",
            "c(4, 1, encode, a, b)",
            "d(0, encode, a, b)",
        ] {
            let output = inline(&format!("{dispatchers} g({call});"));
            assert!(output.contains(&format!("g({call})")), "{output}");
        }
    }

    #[test]
    fn inlines_selected_operations_through_switches_if_chains_and_xor_keys() {
        let inline = |source: &str| testing::rewrite(source, super::run);
        let output = inline(&format!(
            "{OPERATOR} function g(a, b) {{ f(w(1, 630, 622), w(2, a, b + 1), w(9, 7, 2)); }}"
        ));
        testing::assert_contains(&output, &["f(630 - 622, (b + 1) * a, 7 % 2)"]);
        let output = inline(
            "t = function (V, c, X) {
                if (!(V !== 0)) { return c + X; } else { if (!(2 === V)) { return c % X; } else { return X * c; } }
            };
            function q(J, r, n) { switch (2774 ^ J) { case 0: return r | n; default: return r & n; } }
            function g(a, b) { f(t(0, a, b), t(2, a, b), t(5, a, b), q(2774, a, b), q(2775, a, b)); }",
        );
        testing::assert_contains(&output, &["f(a + b, b * a, a % b, a | b, a & b)"]);
        // Arguments with effects and unknown selectors stay.
        for call in ["w(1, g(), 2)", "w(n, 1, 2)", "w(1, 2)", "w(1, missing, 2)"] {
            let output = inline(&format!("{OPERATOR} f({call});"));
            assert!(output.contains(&format!("f({call})")), "{output}");
        }
    }

    #[test]
    fn only_bodies_that_can_select_a_return_are_candidates() {
        let selects = |body: &str| {
            let allocator = Allocator::default();
            let source = format!("function f(n) {{ {body} }}");
            let (program, _) = pipeline::parse(&allocator, &source).unwrap();
            let Statement::FunctionDeclaration(function) = &program.body[0] else {
                panic!("not a function declaration")
            };
            super::may_select(&function.body.as_ref().unwrap().statements)
        };
        for body in [
            "return 1;",
            ";{ if (n) {} else { return 2; } }",
            "switch (n) { case 0: g(); case 1: return 3; }",
        ] {
            assert!(selects(body), "{body}");
        }
        for body in [
            "",
            "return;",
            "var x = 1; return x;",
            "while (n) { return 1; }",
        ] {
            assert!(!selects(body), "{body}");
        }
    }
}
