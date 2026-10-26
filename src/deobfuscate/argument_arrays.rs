//! Replaces reads from scratch argument arrays with their elements:
//!
//! ```js
//! function (a, b) { var f; f = [a, b]; return f[1] ^ f[0]; }  // return b ^ a
//! ```
//!
//! Requires a single array assignment and reads at constant indices only (see
//! [`Properties`](super::analysis::Properties)). Elements must be literals or bindings
//! unchanged by assignments or `arguments`. Excludes globals because repeated reads could throw
//! or invoke getters.

use swc_core::ecma::ast::{ArrayLit, Expr, Id, Program};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::{self, Analysis, Globals, effects};
use super::{HashMap, removal};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let globals = analysis.globals;
    let (bindings, properties) = analysis.properties(program);
    let mut packed = Packed::default();
    program.visit_with(&mut packed);
    // An element reads the same value wherever the array is indexed.
    let is_fixed = |element: &Expr| match element {
        Expr::Ident(identifier) => {
            bindings.write_count(&identifier.to_id()) == 0
                && !bindings.is_mapped_parameter(&identifier.to_id())
                && !effects::may_have_effects(element, globals)
        }
        _ => true,
    };
    packed.0.retain(|id, elements| {
        bindings.is_written_once(id)
            && properties.binding(id).is_only_indexed()
            && elements.iter().all(is_fixed)
    });
    if packed.0.is_empty() {
        return false;
    }
    let mut unpack = UnpackArguments {
        arrays: &packed.0,
        globals,
        changed: false,
    };
    program.visit_mut_with(&mut unpack);
    let changed = unpack.changed;
    let removed = removal::remove_definitions(program, &packed.0.into_keys().collect());
    changed || removed
}

/// Bindings assigned an array of identifiers and literals, with its elements.
#[derive(Default)]
struct Packed(HashMap<Id, Vec<Expr>>);

impl Visit for Packed {
    fn visit_expr(&mut self, expression: &Expr) {
        if let Some((target, Expr::Array(array))) = ast::assignment(expression)
            && let Some(elements) = packed_elements(array)
        {
            self.0.insert(target, elements);
        }
        expression.visit_children_with(self);
    }
}

/// Returns array elements only if all are identifiers or literals, with no holes or spreads.
fn packed_elements(array: &ArrayLit) -> Option<Vec<Expr>> {
    array
        .elems
        .iter()
        .map(|element| {
            let element = element
                .as_ref()
                .filter(|element| element.spread.is_none())?;
            matches!(*element.expr, Expr::Ident(_) | Expr::Lit(_)).then(|| *element.expr.clone())
        })
        .collect()
}

struct UnpackArguments<'arrays> {
    arrays: &'arrays HashMap<Id, Vec<Expr>>,
    globals: Globals,
    changed: bool,
}

impl VisitMut for UnpackArguments<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        if let Expr::Member(member) = expression
            && let Some(array) = member.obj.as_ident()
            && let Some(index) = analysis::constant_index(&member.prop)
            && let Some(elements) = self.arrays.get(&array.to_id())
        {
            self.changed = true;
            // Out-of-bounds array reads produce `undefined`. Give the replacement the original
            // read's source position, which JavaScript engines use in call stack traces.
            *expression = elements
                .get(index)
                .map(|element| element.clone().with_span(member.span))
                .unwrap_or_else(|| Expr::Ident(self.globals.reference("undefined", member.span)));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn unpacks_arrays_that_neither_change_nor_escape() {
        let unpack = |source: &str| testing::rewrite(source, super::run, /* fix= */ false);
        let output = unpack(
            "g = function (a, b) { var f; f = [a, b, 3]; return f[1] ^ f[0] + f[2] + f[5]; };",
        );
        assert!(output.contains("return b ^ a + 3 + undefined;"), "{output}");
        assert!(!output.contains("f = ["), "{output}");
        for source in [
            "g = function (a) { var f; f = [a]; f[0] = 2; return f[0]; };",
            "g = function (a) { var f; f = [a]; a = 2; return f[0]; };",
            "g = function (a) { var f; f = [a]; f = [1]; return f[0]; };",
        ] {
            let output = unpack(source);
            assert!(output.contains("f = ["), "{output}");
        }
    }
}
