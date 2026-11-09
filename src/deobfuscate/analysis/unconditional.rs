//! Visits the parts of statements and expressions that always run with them, in order, so a pass
//! can learn facts from assignments and declarations that hold once those parts have run.
//!
//! Always running are: a statement's expression, the argument of `return` and `throw`, an `if`
//! test, a `switch` discriminant, and variable initializers; within those, every operand of a
//! sequence, the left operand of `&&`, `||` and `??`, and both sides of an assignment. Every
//! other part is visited normally, so facts learned in a conditional part do not escape it.

use oxc::ast::ast::{AssignmentExpression, Expression, Statement, VariableDeclarator};
use oxc::ast_visit::VisitMut;

pub(in crate::deobfuscate) trait Unconditional<'a>: VisitMut<'a> {
    /// Called once `assignment`, which always runs, has run.
    fn assigned(&mut self, assignment: &AssignmentExpression<'a>);

    /// Called once the initializer of `declarator`, which always runs, has run.
    fn declared(&mut self, declarator: &VariableDeclarator<'a>);

    fn unconditional_expression(&mut self, expression: &mut Expression<'a>) {
        match expression {
            Expression::ParenthesizedExpression(parenthesized) => {
                self.unconditional_expression(&mut parenthesized.expression)
            }
            Expression::SequenceExpression(sequence) => {
                for expression in &mut sequence.expressions {
                    self.unconditional_expression(expression)
                }
            }
            Expression::LogicalExpression(logical) => {
                self.unconditional_expression(&mut logical.left);
                self.visit_expression(&mut logical.right)
            }
            Expression::AssignmentExpression(assignment) => {
                self.visit_assignment_target(&mut assignment.left);
                self.unconditional_expression(&mut assignment.right);
                self.assigned(assignment)
            }
            expression => self.visit_expression(expression),
        }
    }

    fn unconditional_statement(&mut self, statement: &mut Statement<'a>) {
        match statement {
            Statement::ExpressionStatement(statement) => {
                self.unconditional_expression(&mut statement.expression)
            }
            Statement::ReturnStatement(statement) => {
                if let Some(argument) = &mut statement.argument {
                    self.unconditional_expression(argument)
                }
            }
            Statement::ThrowStatement(statement) => {
                self.unconditional_expression(&mut statement.argument)
            }
            Statement::IfStatement(branch) => {
                self.unconditional_expression(&mut branch.test);
                self.visit_statement(&mut branch.consequent);
                if let Some(alternate) = &mut branch.alternate {
                    self.visit_statement(alternate)
                }
            }
            Statement::SwitchStatement(switch) => {
                self.unconditional_expression(&mut switch.discriminant);
                for case in &mut switch.cases {
                    self.visit_switch_case(case)
                }
            }
            Statement::VariableDeclaration(declaration) => {
                for declarator in &mut declaration.declarations {
                    if let Some(value) = &mut declarator.init {
                        self.unconditional_expression(value);
                        self.declared(declarator)
                    }
                }
            }
            statement => self.visit_statement(statement),
        }
    }
}
