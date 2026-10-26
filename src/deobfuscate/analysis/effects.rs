//! Tracks expression side effects and binding reads and writes.

use swc_core::ecma::ast::{ArrowExpr, AssignExpr, Expr, Function, Id, Ident, UpdateExpr};
use swc_core::ecma::visit::{Visit, VisitWith};
use swc_ecma_utils::ExprCtx;

use super::Globals;
use crate::deobfuscate::HashSet;

/// Checks for observable effects, including getters and coercions.
///
/// SWC treats local binding reads as effect-free. A global read is effect-free only if it names
/// a known browser global without a getter, such as `Math` or `undefined`. Other globals may
/// throw `ReferenceError` or invoke a getter.
#[must_use]
pub(crate) fn may_have_effects(expression: &Expr, globals: Globals) -> bool {
    use swc_ecma_utils::ExprExt;

    expression.may_have_side_effects(ExprCtx {
        unresolved_ctxt: globals.unresolved,
        is_unresolved_ref_safe: false,
        in_strict: false,
        remaining_depth: 4,
    })
}

/// Tracks binding reads and writes outside function bodies. Creating a closure does not execute
/// its body. Does not analyze the effects of calls, `new`, tagged templates, `await`, or
/// `yield`.
#[derive(Default)]
pub(crate) struct Effects {
    pub reads: HashSet<Id>,
    pub writes: HashSet<Id>,
    pub opaque: bool,
}

impl Effects {
    #[must_use]
    pub(crate) fn collect(expression: &Expr) -> Self {
        let mut effects = Self::default();
        expression.visit_with(&mut effects);
        effects
    }
}

impl Visit for Effects {
    fn visit_ident(&mut self, identifier: &Ident) {
        self.reads.insert(identifier.to_id());
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        self.writes
            .extend(swc_ecma_utils::find_pat_ids::<_, Id>(&assignment.left));
        assignment.visit_children_with(self);
    }

    fn visit_update_expr(&mut self, update: &UpdateExpr) {
        if let Some(identifier) = update.arg.as_ident() {
            self.writes.insert(identifier.to_id());
        }
        update.arg.visit_with(self);
    }

    fn visit_expr(&mut self, expression: &Expr) {
        self.opaque |= matches!(
            expression,
            Expr::Call(_) | Expr::New(_) | Expr::TaggedTpl(_) | Expr::Await(_) | Expr::Yield(_)
        );
        expression.visit_children_with(self);
    }

    fn visit_function(&mut self, _: &Function) {}

    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
}
