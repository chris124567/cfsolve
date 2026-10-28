//! Expands comma and conditional expressions into statement control flow:
//!
//! ```js
//! flag && (third(), fourth());  // becomes if (flag) { third(); fourth(); }
//! ```
//!
//! Expands comma expressions only where doing so preserves evaluation order and values. Turns
//! conditional values into `if` branches so only the selected expression runs. Runs after
//! simplification, which could otherwise combine the statements again.

use std::mem;

use swc_core::common::Span;
use swc_core::common::util::take::Take;
use swc_core::ecma::ast::{
    AssignOp, BinaryOp, CondExpr, Decl, Expr, IfStmt, LabeledStmt, Lit, Program, ReturnStmt, Stmt,
    ThrowStmt, UnaryExpr, UnaryOp, VarDeclKind, VarDeclOrExpr,
};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::Analysis;
use crate::js::ast;

pub(super) fn run(program: &mut Program, _: &mut Analysis) -> bool {
    let mut expand = ExpandStatements { changed: false };
    program.visit_mut_with(&mut expand);
    expand.changed
}

struct ExpandStatements {
    changed: bool,
}

impl VisitMut for ExpandStatements {
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        let mut expanded = Vec::with_capacity(statements.len());
        for mut statement in mem::take(statements) {
            statement.visit_mut_children_with(self);
            expanded.extend(self.expand(statement));
        }
        *statements = expanded;
    }

    fn visit_mut_stmt(&mut self, statement: &mut Stmt) {
        statement.visit_mut_children_with(self);
        let statements = self.expand(statement.take());
        // This position accepts one statement. Wrap multi-statement expansions in a block.
        *statement = match <[Stmt; 1]>::try_from(statements) {
            Ok([single]) => single,
            Err(statements) => ast::block(statements),
        };
    }

    fn visit_mut_labeled_stmt(&mut self, statement: &mut LabeledStmt) {
        // A label on a loop must stay on the loop for `continue label`.
        // In particular, do not replace its body with a block of lifted initializers.
        if let Stmt::Labeled(nested) = &mut *statement.body {
            self.visit_mut_labeled_stmt(nested);
        } else {
            statement.body.visit_mut_children_with(self);
        }
    }
}

/// A statement evaluating an expression taken out of a larger one.
fn expression_statement(expression: Box<Expr>) -> Stmt {
    guard_directive(ast::expression_statement(expression))
}

/// Wrap newly exposed string statements in a block so they cannot become function or script
/// directives.
fn guard_directive(statement: Stmt) -> Stmt {
    if is_string_statement(&statement) {
        ast::block(vec![statement])
    } else {
        statement
    }
}

fn is_string_statement(statement: &Stmt) -> bool {
    matches!(
        statement,
        Stmt::Expr(statement) if matches!(&*statement.expr, Expr::Lit(Lit::Str(_)))
    )
}

/// Keeps sequences such as `name = (effects, function () {})`. Removing the sequence would give
/// the function an inferred `.name` that the original did not have.
fn ends_with_anonymous_function(expression: &Expr) -> bool {
    match expression {
        Expr::Paren(paren) => ends_with_anonymous_function(&paren.expr),
        Expr::Seq(sequence) => sequence
            .exprs
            .last()
            .is_some_and(|last| ends_with_anonymous_function(last)),
        Expr::Fn(function) => function.ident.is_none(),
        Expr::Class(class) => class.ident.is_none(),
        Expr::Arrow(_) => true,
        _ => false,
    }
}

impl ExpandStatements {
    /// Applies the same statement to either arm of a conditional value.
    fn conditional(
        &mut self,
        conditional: CondExpr,
        span: Span,
        statement: impl Fn(Box<Expr>) -> Stmt,
    ) -> Stmt {
        self.changed = true;
        Stmt::If(IfStmt {
            span,
            test: conditional.test,
            cons: Box::new(ast::block(self.expand(statement(conditional.cons)))),
            alt: Some(Box::new(ast::block(
                self.expand(statement(conditional.alt)),
            ))),
        })
    }

    /// Moves sequence operands into statements only where evaluation order and values are
    /// preserved. Leaves commas in callees, assignment targets, and loop tests or updates in
    /// place.
    fn split_sequence(&mut self, mut expression: Box<Expr>) -> (Vec<Stmt>, Box<Expr>) {
        while let Expr::Paren(paren) = *expression {
            expression = paren.expr;
            self.changed = true;
        }
        if let Expr::Seq(sequence) = &mut *expression
            && let Some(last) = sequence.exprs.pop()
        {
            self.changed = true;
            let mut prefix = Vec::new();
            for expression in mem::take(&mut sequence.exprs) {
                prefix.extend(self.expand(expression_statement(expression)));
            }
            let (tail_prefix, last) = self.split_sequence(last);
            prefix.extend(tail_prefix);
            (prefix, last)
        } else {
            (vec![], expression)
        }
    }

    fn expand(&mut self, statement: Stmt) -> Vec<Stmt> {
        let mut prefix = Vec::new();
        let mut statement = match statement {
            // A string statement stays as written: it may be a directive.
            statement if is_string_statement(&statement) => return vec![statement],
            Stmt::Expr(mut statement) => {
                (prefix, statement.expr) = self.split_sequence(statement.expr);
                // `name = (first(), value)` evaluates `first()` before the store, and a
                // plain identifier target has nothing to evaluate ahead of it.
                if let Expr::Assign(assignment) = &mut *statement.expr
                    && assignment.op == AssignOp::Assign
                    && assignment.left.as_ident().is_some()
                    && !ends_with_anonymous_function(&assignment.right)
                {
                    let (effects, value) = self.split_sequence(assignment.right.take());
                    prefix.extend(effects);
                    assignment.right = value;
                }
                match *statement.expr {
                    Expr::Cond(conditional) => {
                        self.conditional(conditional, statement.span, expression_statement)
                    }
                    Expr::Bin(binary)
                        if matches!(binary.op, BinaryOp::LogicalAnd | BinaryOp::LogicalOr) =>
                    {
                        self.changed = true;
                        let test = if binary.op == BinaryOp::LogicalOr {
                            Box::new(Expr::Unary(UnaryExpr {
                                span: binary.span,
                                op: UnaryOp::Bang,
                                arg: binary.left,
                            }))
                        } else {
                            binary.left
                        };
                        Stmt::If(IfStmt {
                            span: statement.span,
                            test,
                            cons: Box::new(ast::block(
                                self.expand(expression_statement(binary.right)),
                            )),
                            alt: None,
                        })
                    }
                    // Splitting or removing parentheses can expose a string.
                    expression => {
                        statement.expr = Box::new(expression);
                        guard_directive(Stmt::Expr(statement))
                    }
                }
            }
            Stmt::Return(mut statement) => {
                let Some(argument) = statement.arg.take() else {
                    return vec![Stmt::Return(statement)];
                };
                let (effects, argument) = self.split_sequence(argument);
                prefix = effects;
                match *argument {
                    Expr::Cond(conditional) => {
                        self.conditional(conditional, statement.span, |arg| {
                            Stmt::Return(ReturnStmt {
                                span: statement.span,
                                arg: Some(arg),
                            })
                        })
                    }
                    Expr::Unary(unary) if unary.op == UnaryOp::Void => {
                        self.changed = true;
                        prefix.extend(self.expand(expression_statement(unary.arg)));
                        Stmt::Return(statement)
                    }
                    argument => {
                        statement.arg = Some(Box::new(argument));
                        Stmt::Return(statement)
                    }
                }
            }
            Stmt::Throw(mut statement) => {
                (prefix, statement.arg) = self.split_sequence(statement.arg);
                if let Expr::Cond(conditional) = *statement.arg {
                    self.conditional(conditional, statement.span, |arg| {
                        Stmt::Throw(ThrowStmt {
                            span: statement.span,
                            arg,
                        })
                    })
                } else {
                    Stmt::Throw(statement)
                }
            }
            Stmt::Switch(mut statement) => {
                (prefix, statement.discriminant) = self.split_sequence(statement.discriminant);
                Stmt::Switch(statement)
            }
            // In `var name = (first(), value)`, `first()` runs before the value is stored. Moving
            // it before earlier uninitialized `var` declarations is safe because those declarations
            // do nothing: `var a, b = (a = f(), v)`. This would be unsafe with `let` or `const`,
            // because `a` would not yet be initialized.
            Stmt::Decl(Decl::Var(mut declaration)) => {
                let storing = match declaration.kind {
                    VarDeclKind::Var => declaration
                        .decls
                        .iter()
                        .position(|declarator| declarator.init.is_some()),
                    VarDeclKind::Let | VarDeclKind::Const => Some(0),
                };
                if let Some(declarator) = storing.and_then(|at| declaration.decls.get_mut(at))
                    && let Some(init) = &mut declarator.init
                    && !ends_with_anonymous_function(init)
                {
                    (prefix, *init) = self.split_sequence(init.take());
                }
                Stmt::Decl(Decl::Var(declaration))
            }
            Stmt::For(mut statement) => {
                statement.init = match statement.init.take() {
                    Some(VarDeclOrExpr::Expr(initializer)) => {
                        self.changed = true;
                        prefix.extend(self.expand(expression_statement(initializer)));
                        None
                    }
                    initializer => initializer,
                };
                Stmt::For(statement)
            }
            statement => statement,
        };
        // Conditions created above can themselves have a comma prefix.
        if let Stmt::If(conditional) = &mut statement {
            let (effects, test) = self.split_sequence(conditional.test.take());
            prefix.extend(effects);
            conditional.test = test;
        }
        prefix.push(statement);
        prefix
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn expands_sequences_conditionals_and_void_returns() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform(
            "function f(flag) { first(), second(); flag && (third(), fourth()); \
             flag || fallback(); return before(), flag ? (yes(), result()) : void no(); }",
        );
        testing::assert_contains(
            &output,
            &["if (flag)", "if (!flag)", "return result();"],
            &["first(); second();", "no(); return;"],
        );
        testing::assert_lacks(&output, &["&&", " ? "]);
        let output = transform(
            "function f(flag) { if (before(), flag) a(); \
             switch (select(), flag) { case 1: break; } \
             throw prepare(), flag ? (yes(), one) : (no(), two); }",
        );
        testing::assert_contains(
            &output,
            &["throw one;", "throw two;"],
            &["before(); if (flag)", "select(); switch(flag)"],
        );
        assert!(!output.contains("throw prepare()"), "{output}");
        // A single-statement body expands without changing which `if` an `else` binds to.
        let output = transform("function f(a, b) { if (a) b ? yes() : no(); else other(); }");
        testing::assert_contains(&output, &["if (a)", "if (b)"], &[]);
        assert_eq!(output.matches("else").count(), 2, "{output}");
        assert!(!output.contains('?'), "{output}");
        assert_eq!(transform(&output), output);
    }

    #[test]
    fn preserves_evaluation_order_frequency_labels_and_references() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
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
            ],
            &[
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
            &["w = (third(), more)", "g = (effect(), function() {})"],
            &["first(); if (flag) { second(); } var v = value"],
        );
        // Earlier uninitialized `var` declarations have no effect.
        let output = transform(
            "function f() { var a, b = (a = first(), value); let c, d = (c = second(), other); }",
        );
        testing::assert_contains(
            &output,
            &["d = (c = second(), other)"],
            &["a = first(); var a, b = value;"],
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
            ],
            &["start(); setup();"],
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
        testing::assert_contains(&output, &expected, &[]);
    }
}
