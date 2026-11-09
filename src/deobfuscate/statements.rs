//! Expands comma and conditional expressions into statement control flow:
//!
//! ```js
//! flag && (third(), fourth());  // becomes if (flag) { third(); fourth(); }
//! ```
//!
//! Expands comma expressions only where doing so preserves evaluation order and values. Turns
//! conditional values into `if` branches so only the selected expression runs. Runs after
//! simplification, which could otherwise combine the statements again.

use oxc::allocator::{TakeIn, Vec};
use oxc::ast::ast::{
    ConditionalExpression, Expression, LabeledStatement, Program, Statement,
    VariableDeclarationKind,
};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::{GetSpan, SPAN, Span};
use oxc::syntax::operator::{AssignmentOperator, LogicalOperator, UnaryOperator};

use super::analysis::Analysis;
use super::ast;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut expand = Expand {
        analysis,
        changed: false,
    };
    expand.visit_program(program);
    expand.changed
}

struct Expand<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

/// The statement that applies to each arm of an expanded conditional.
enum Arm {
    Expression,
    Return,
    Throw,
}

/// Keeps `name = (effects, function () {})` and equivalent arrow and class sequences intact.
/// Removing the sequence could give the anonymous value an inferred `.name` it did not have.
fn anonymous(expression: &Expression<'_>) -> bool {
    match expression.get_inner_expression() {
        Expression::SequenceExpression(sequence) => {
            sequence.expressions.last().is_some_and(anonymous)
        }
        Expression::FunctionExpression(function) => function.id.is_none(),
        Expression::ClassExpression(class) => class.id.is_none(),
        Expression::ArrowFunctionExpression(_) => true,
        _ => false,
    }
}

impl<'a> Expand<'_, 'a> {
    /// Wraps newly exposed string statements in a block so they cannot become directives.
    fn statement(&self, expression: Expression<'a>) -> Statement<'a> {
        let builder = &self.analysis.ast;
        let span = expression.span();
        let string = matches!(expression, Expression::StringLiteral(_));
        let statement = ast::expression_statement(expression, builder);
        if string {
            Statement::new_block_statement(span, Vec::from_array_in([statement], builder), builder)
        } else {
            statement
        }
    }

    /// Moves leading sequence operands into `prefix` as statements and returns the final value.
    /// Callers use this only where lifting operands preserves evaluation order.
    fn split(
        &mut self,
        expression: Expression<'a>,
        prefix: &mut Vec<'a, Statement<'a>>,
    ) -> Expression<'a> {
        match expression {
            Expression::ParenthesizedExpression(parenthesized) => {
                self.changed = true;
                self.split(parenthesized.unbox().expression, prefix)
            }
            Expression::SequenceExpression(sequence) => {
                let mut expressions = sequence.unbox().expressions;
                let last = expressions
                    .pop()
                    .expect("a JavaScript sequence is nonempty");
                self.changed = true;
                for expression in expressions {
                    let statement = self.statement(expression);
                    prefix.extend(self.expand(statement))
                }
                self.split(last, prefix)
            }
            expression => expression,
        }
    }

    /// Turns a conditional into an `if` statement that applies `arm` to each branch.
    fn conditional(
        &mut self,
        conditional: ConditionalExpression<'a>,
        span: Span,
        arm: Arm,
    ) -> Statement<'a> {
        let builder = &self.analysis.ast;
        self.changed = true;
        let mut branch = |expression| {
            let statement = match arm {
                Arm::Expression => self.statement(expression),
                Arm::Return => Statement::new_return_statement(span, Some(expression), builder),
                Arm::Throw => Statement::new_throw_statement(span, expression, builder),
            };
            Statement::new_block_statement(span, self.expand(statement), builder)
        };
        let consequent = branch(conditional.consequent);
        let alternate = branch(conditional.alternate);
        Statement::new_if_statement(span, conditional.test, consequent, Some(alternate), builder)
    }

    /// Lifts commas and conditional values only at safe statement positions. Member assignment
    /// receivers and keys, compound assignments, callees, loop tests, and loop updates keep their
    /// original evaluation sites. Variable initializers also retain earlier lexical initialization.
    fn expand(&mut self, statement: Statement<'a>) -> Vec<'a, Statement<'a>> {
        let builder = &self.analysis.ast;
        let mut prefix = Vec::new_in(builder);
        let mut statement = match statement {
            Statement::ExpressionStatement(statement)
                if matches!(statement.expression, Expression::StringLiteral(_)) =>
            {
                return Vec::from_array_in([Statement::ExpressionStatement(statement)], builder);
            }
            Statement::ExpressionStatement(mut statement) => {
                let expression = statement.expression.take_in(builder);
                statement.expression = self.split(expression, &mut prefix);
                if let Expression::AssignmentExpression(assignment) = &mut statement.expression
                    && assignment.operator == AssignmentOperator::Assign
                    && self.analysis.target_id(&assignment.left).is_some()
                    && !anonymous(&assignment.right)
                {
                    assignment.right = self.split(assignment.right.take_in(builder), &mut prefix);
                }
                let span = statement.span;
                match statement.unbox().expression {
                    Expression::ConditionalExpression(conditional) => {
                        self.conditional(conditional.unbox(), span, Arm::Expression)
                    }
                    Expression::LogicalExpression(logical)
                        if logical.operator != LogicalOperator::Coalesce =>
                    {
                        self.changed = true;
                        let logical = logical.unbox();
                        let test = match logical.operator {
                            LogicalOperator::Or => Expression::new_unary_expression(
                                logical.span,
                                UnaryOperator::LogicalNot,
                                logical.left,
                                builder,
                            ),
                            _ => logical.left,
                        };
                        let body = self.statement(logical.right);
                        let body = Statement::new_block_statement(span, self.expand(body), builder);
                        Statement::new_if_statement(span, test, body, None, builder)
                    }
                    expression => self.statement(expression),
                }
            }
            Statement::ReturnStatement(mut statement) => {
                let argument = statement.argument.take();
                match argument.map(|argument| self.split(argument, &mut prefix)) {
                    Some(Expression::ConditionalExpression(conditional)) => {
                        self.conditional(conditional.unbox(), statement.span, Arm::Return)
                    }
                    Some(Expression::UnaryExpression(unary))
                        if unary.operator == UnaryOperator::Void =>
                    {
                        self.changed = true;
                        let effect = self.statement(unary.unbox().argument);
                        prefix.extend(self.expand(effect));
                        Statement::ReturnStatement(statement)
                    }
                    argument => {
                        statement.argument = argument;
                        Statement::ReturnStatement(statement)
                    }
                }
            }
            Statement::ThrowStatement(mut statement) => {
                match self.split(statement.argument.take_in(builder), &mut prefix) {
                    Expression::ConditionalExpression(conditional) => {
                        self.conditional(conditional.unbox(), statement.span, Arm::Throw)
                    }
                    argument => {
                        statement.argument = argument;
                        Statement::ThrowStatement(statement)
                    }
                }
            }
            Statement::SwitchStatement(mut statement) => {
                let discriminant = statement.discriminant.take_in(builder);
                statement.discriminant = self.split(discriminant, &mut prefix);
                Statement::SwitchStatement(statement)
            }
            Statement::VariableDeclaration(mut declaration) => {
                let first = match declaration.kind {
                    VariableDeclarationKind::Var => declaration
                        .declarations
                        .iter()
                        .position(|declarator| declarator.init.is_some()),
                    _ => Some(0),
                };
                let declarations = &mut declaration.declarations;
                if let Some(declarator) = first.and_then(|first| declarations.get_mut(first))
                    && let Some(init) = declarator.init.take_if(|init| !anonymous(init))
                {
                    declarator.init = Some(self.split(init, &mut prefix))
                }
                Statement::VariableDeclaration(declaration)
            }
            Statement::ForStatement(mut statement) => {
                if let Some(init) = statement.init.take_if(|init| init.is_expression()) {
                    let init = self.statement(init.into_expression());
                    prefix.extend(self.expand(init));
                    self.changed = true
                }
                Statement::ForStatement(statement)
            }
            statement => statement,
        };
        if let Statement::IfStatement(statement) = &mut statement {
            statement.test = self.split(statement.test.take_in(builder), &mut prefix)
        }
        prefix.push(statement);
        prefix
    }
}

impl<'a> VisitMut<'a> for Expand<'_, 'a> {
    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        let mut expanded = Vec::new_in(&self.analysis.ast);
        for mut statement in statements.take_in(&self.analysis.ast) {
            walk_mut::walk_statement(self, &mut statement);
            expanded.extend(self.expand(statement));
        }
        *statements = expanded;
    }

    fn visit_statement(&mut self, statement: &mut Statement<'a>) {
        walk_mut::walk_statement(self, statement);
        let builder = &self.analysis.ast;
        let mut expanded = self.expand(statement.take_in(builder));
        *statement = if expanded.len() == 1 {
            expanded.pop().expect("one statement")
        } else {
            Statement::new_block_statement(SPAN, expanded, builder)
        }
    }

    /// Keeps a labeled loop directly under its label, so lifted statements cannot break
    /// `continue label`.
    fn visit_labeled_statement(&mut self, statement: &mut LabeledStatement<'a>) {
        if let Statement::LabeledStatement(nested) = &mut statement.body {
            self.visit_labeled_statement(nested)
        } else {
            walk_mut::walk_statement(self, &mut statement.body)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn expands_sequences_conditionals_and_void_returns() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform(
            "function f(flag) { first(), second(); flag && (third(), fourth()); \
             flag || fallback(); return before(), flag ? (yes(), result()) : void no(); }",
        );
        testing::assert_contains(
            &output,
            &[
                "if (flag)",
                "if (!flag)",
                "return result();",
                "first(); second();",
                "no(); return;",
            ],
        );
        testing::assert_lacks(&output, &["&&", " ? "]);
        let output = transform(
            "function f(flag) { if (before(), flag) a(); \
             switch (select(), flag) { case 1: break; } \
             throw prepare(), flag ? (yes(), one) : (no(), two); }",
        );
        testing::assert_contains(
            &output,
            &[
                "throw one;",
                "throw two;",
                "before(); if (flag)",
                "select(); switch(flag)",
            ],
        );
        assert!(!output.contains("throw prepare()"), "{output}");
        // A single-statement body expands without changing which `if` an `else` binds to.
        let output = transform("function f(a, b) { if (a) b ? yes() : no(); else other(); }");
        testing::assert_contains(&output, &["if (a)", "if (b)"]);
        assert_eq!(output.matches("else").count(), 2, "{output}");
        assert!(!output.contains('?'), "{output}");
        assert_eq!(transform(&output), output);
    }

    #[test]
    fn preserves_evaluation_order_frequency_labels_and_references() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        // Only sequences assigned to identifiers are lifted out of assignments.
        let output = transform(
            "function f(a, b, obj) { a = (b = obj.x, first(), b + 1); \
             obj[key()] = (effect(), value); obj.y = (effect(), value); a += (effect(), 1); \
             a = (effect(), function () {}); a = (effect(), () => 1); a = (effect(), function named() {}); }",
        );
        testing::assert_contains(
            &output,
            &[
                "a = (effect(), function() {})",
                "a = (effect(), ()=>1)",
                "obj[key()] = (effect(), value)",
                "obj.y = (effect(), value)",
                "a += (effect(), 1)",
                "effect(); a = function named() {}",
                "b = obj.x; first(); a = b + 1;",
            ],
        );
        // The sequence in the first initializer runs before the value is stored.
        let output = transform(
            "function f() { var v = (first(), flag && second(), value), w = (third(), more); \
             var g = (effect(), function () {}); }",
        );
        testing::assert_contains(
            &output,
            &[
                "w = (third(), more)",
                "g = (effect(), function() {})",
                "first(); if (flag) { second(); } var v = value",
            ],
        );
        // Earlier uninitialized `var` declarations have no effect.
        let output = transform(
            "function f() { var a, b = (a = first(), value); let c, d = (c = second(), other); }",
        );
        testing::assert_contains(
            &output,
            &[
                "d = (c = second(), other)",
                "a = first(); var a, b = value;",
            ],
        );
        let output = transform(
            "function f() { for (start(), setup(); test(), ready; tick(), step()) body(); \
             outer: inner: for (init(), reset(); check(); next()) { continue outer; } \
             for (let i = 0; i < 2; i++) use(i); \
             while (poll(), ready) work(); do work(); while (poll(), ready); }",
        );
        testing::assert_contains(
            &output,
            &[
                "test(), ready; tick(), step()",
                "outer: inner: for(init(), reset();",
                "continue outer;",
                "for(let i = 0;",
                "while(poll(), ready)",
                "while (poll(), ready)",
                "start(); setup();",
            ],
        );
        let output = transform(
            r#"function f() { (0, obj.method)(); (0, eval)("x");
                consume(first(), (second(), third())); return left && right; }"#,
        );
        let expected = [
            "(0, obj.method)()",
            "(0, eval)(\"x\")",
            "consume(first(), (second(), third()))",
            "return left && right;",
        ];
        testing::assert_contains(&output, &expected);
    }
}
