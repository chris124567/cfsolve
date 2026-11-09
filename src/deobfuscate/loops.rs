//! Restores loop bodies and `while` loops from minified `for` headers:
//!
//! ```js
//! for (; test; effect(), i++);  // becomes for (; test; i++) { effect(); }
//! ```
//!
//! Moves the leading update operands into an empty body, leaving the final operand in the
//! header. The body must be empty so those evaluations still run at the same point in each
//! iteration. A loop with no initializer or update becomes `while`; an absent test means `true`.

use oxc::allocator::{TakeIn, Vec};
use oxc::ast::ast::{Expression, Program, Statement};
use oxc::ast_visit::{VisitMut, walk_mut};

use super::analysis::Analysis;
use super::ast;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut loops = Loops {
        analysis,
        changed: false,
    };
    loops.visit_program(program);
    loops.changed
}

struct Loops<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> VisitMut<'a> for Loops<'_, 'a> {
    fn visit_statement(&mut self, statement: &mut Statement<'a>) {
        walk_mut::walk_statement(self, statement);
        let builder = &self.analysis.ast;
        let Statement::ForStatement(for_statement) = statement else {
            return;
        };
        if matches!(for_statement.body, Statement::EmptyStatement(_))
            && let Some(Expression::SequenceExpression(sequence)) = &mut for_statement.update
            && let Some(last) = sequence.expressions.pop()
        {
            let effects = sequence
                .expressions
                .drain(..)
                .map(|effect| ast::expression_statement(effect, builder));
            let effects = Vec::from_iter_in(effects, builder);
            for_statement.body =
                Statement::new_block_statement(for_statement.span, effects, builder);
            for_statement.update = Some(last);
            self.changed = true;
        }
        if for_statement.init.is_none() && for_statement.update.is_none() {
            let span = for_statement.span;
            let test = for_statement.test.take();
            let test = test.unwrap_or_else(|| Expression::new_boolean_literal(span, true, builder));
            let body = for_statement.body.take_in(builder);
            *statement = Statement::new_while_statement(span, test, body, builder);
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn restores_loop_bodies_and_while_loops() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform("for (var i = 0; i < n; use(i), tick(), i++);");
        assert!(output.contains("for (var i = 0; i < n; i++)"), "{output}");
        testing::assert_contains(&output, &["use(i); tick();"]);
        let output = transform("for (; ready; use(i), i++) work();");
        assert!(
            output.contains("for (; ready; use(i), i++)"),
            "only an empty body takes the effects: {output}"
        );
        let output = transform("for (;;) tick(); for (; ready;) work(); for (; ready; step());");
        let expected = ["while(true)", "while(ready)", "for(; ready; step())"];
        testing::assert_contains(&output, &expected);
    }
}
