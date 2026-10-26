//! Restores loop bodies and `while` loops from minified `for` headers:
//!
//! ```js
//! for (; test; effect(), i++);  // becomes for (; test; i++) { effect(); }
//! ```
//!
//! Requires a final increment preceded only by effects. Moving those effects into an empty body
//! preserves their execution point. A loop with no initializer or update becomes `while`.

use std::mem;

use swc_core::ecma::ast::{Bool, Expr, Lit, Program, Stmt, WhileStmt};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::Analysis;
use crate::js::ast;

pub(super) fn run(program: &mut Program, _: &mut Analysis) -> bool {
    let mut restore = RestoreLoops { changed: false };
    program.visit_mut_with(&mut restore);
    restore.changed
}

struct RestoreLoops {
    changed: bool,
}

impl VisitMut for RestoreLoops {
    fn visit_mut_stmt(&mut self, statement: &mut Stmt) {
        use swc_core::common::util::take::Take;

        statement.visit_mut_children_with(self);
        let Stmt::For(loop_statement) = statement else {
            return;
        };
        if loop_statement.body.is_empty()
            && let Some(update) = &mut loop_statement.update
            && let Expr::Seq(sequence) = &mut **update
            && let Some(last) = sequence.exprs.pop()
        {
            let effects = mem::take(&mut sequence.exprs);
            **update = *last;
            let statements: Vec<Stmt> =
                effects.into_iter().map(ast::expression_statement).collect();
            *loop_statement.body = ast::block(statements);
            self.changed = true;
        }
        // An absent test is the implicit `true` that `for (;;)` means.
        if loop_statement.init.is_none() && loop_statement.update.is_none() {
            let span = loop_statement.span;
            *statement = Stmt::While(WhileStmt {
                span,
                test: loop_statement
                    .test
                    .take()
                    .unwrap_or_else(|| Box::new(Expr::Lit(Lit::Bool(Bool { span, value: true })))),
                body: loop_statement.body.take(),
            });
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn restores_loop_bodies_and_while_loops() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = transform("for (var i = 0; i < n; use(i), tick(), i++);");
        assert!(output.contains("for(var i = 0; i < n; i++)"), "{output}");
        testing::assert_contains(&output, &[], &["use(i); tick();"]);
        let output = transform("for (; ready; use(i), i++) work();");
        assert!(
            output.contains("for(; ready; use(i), i++)"),
            "only an empty body takes the effects: {output}"
        );
        let output = transform("for (;;) tick(); for (; ready;) work(); for (; ready; step());");
        let expected = ["while(true)", "while(ready)", "for(; ready; step())"];
        testing::assert_contains(&output, &expected, &[]);
    }
}
