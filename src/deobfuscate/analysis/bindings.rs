//! Counts binding reads and writes and tracks simple assigned values, so rewrites can identify
//! single assignments and follow copies to their source.

use std::mem;

use swc_core::ecma::ast::{
    ArrowExpr, AssignExpr, AssignOp, ClassDecl, Expr, FnDecl, ForHead, Function, Id, Ident, Param,
    Program, Prop, UpdateExpr, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};
use swc_ecma_utils::DestructuringFinder;

use crate::deobfuscate::{HashMap, HashSet};

/// Tracks writes and references by resolved [`Id`]. Names are not enough
/// because the obfuscator reuses them across scopes.
///
/// Writes include assignments, updates, initialized declarations, `for-in` and `for-of`
/// targets, and function or class declarations. Parameters and catch clauses do not count:
/// helpers may use parameter slots whose incoming values are never read. An assigned value can
/// be used for substitution only when its binding has exactly one write.
#[derive(Default)]
pub(crate) struct Bindings {
    writes: HashMap<Id, Vec<Write>>,
    references: HashMap<Id, usize>,
    /// Bindings that receive a copy of each binding's value.
    copies: HashMap<Id, Vec<Id>>,
    /// Parameters of functions and arrows.
    parameters: HashSet<Id>,
    /// Parameters of functions that use `arguments`.
    mapped: HashSet<Id>,
    /// Whether the function being visited refers to its `arguments`.
    uses_arguments: bool,
}

/// One write, and the assigned value when analysis can follow it.
enum Write {
    /// `binding = other` or `var binding = other`.
    Copy(Id),
    Other,
}

impl Bindings {
    #[must_use]
    pub(crate) fn collect(program: &Program) -> Self {
        let mut bindings = Self::default();
        program.visit_with(&mut bindings);
        bindings
    }

    #[must_use]
    pub(crate) fn write_count(&self, id: &Id) -> usize {
        self.writes.get(id).map_or(0, Vec::len)
    }

    /// Checks for exactly one write, allowing later reads to use that assigned value.
    #[must_use]
    pub(crate) fn is_written_once(&self, id: &Id) -> bool {
        self.write_count(id) == 1
    }

    /// Returns the number of value reads, including reads through `binding.property`.
    #[must_use]
    pub(crate) fn references(&self, id: &Id) -> usize {
        self.references.get(id).copied().unwrap_or(0)
    }

    /// Returns whether the binding is a function or arrow parameter that can hold an argument.
    #[must_use]
    pub(crate) fn is_parameter(&self, id: &Id) -> bool {
        self.parameters.contains(id)
    }

    /// Checks whether this is a parameter of a function using `arguments`. In sloppy mode,
    /// `arguments[i]` can observe parameter writes and changes to the parameter list.
    #[must_use]
    pub(crate) fn is_mapped_parameter(&self, id: &Id) -> bool {
        self.mapped.contains(id)
    }

    /// Returns the source binding when `id` has exactly one write that copies it.
    #[must_use]
    pub(crate) fn copy_source(&self, id: &Id) -> Option<&Id> {
        match self.writes.get(id)?.as_slice() {
            [Write::Copy(source)] => Some(source),
            _ => None,
        }
    }

    /// Follows [`Self::copy_source`] to the original binding in a copy chain. This identifies
    /// the first binding assigned a helper object.
    #[must_use]
    pub(crate) fn root(&self, id: &Id) -> Id {
        let mut current = id.clone();
        let mut seen = HashSet::default();
        while let Some(source) = self.copy_source(&current) {
            if !seen.insert(current.clone()) {
                break;
            }
            current = source.clone();
        }
        current
    }

    /// The [`Self::root`] of every binding that has a copy source.
    #[must_use]
    pub(crate) fn roots(&self) -> HashMap<Id, Id> {
        let copies = self
            .writes
            .keys()
            .filter(|id| self.copy_source(id).is_some());
        copies.map(|id| (id.clone(), self.root(id))).collect()
    }

    /// Checks whether another binding copies `id` (see [`Self::copy_source`]).
    #[must_use]
    pub(crate) fn is_copied(&self, id: &Id) -> bool {
        self.copies
            .get(id)
            .is_some_and(|copies| copies.iter().any(|copy| self.copy_source(copy) == Some(id)))
    }

    fn write<N: VisitWith<DestructuringFinder<Id>>>(&mut self, target: &N) {
        for id in swc_ecma_utils::find_pat_ids::<_, Id>(target) {
            self.writes.entry(id).or_default().push(Write::Other);
        }
    }

    /// A write of `value` to the plain identifier `id`.
    fn write_value(&mut self, id: Id, value: &Expr) {
        let write = if let Some(source) = value.as_ident() {
            self.copies
                .entry(source.to_id())
                .or_default()
                .push(id.clone());
            Write::Copy(source.to_id())
        } else {
            Write::Other
        };
        self.writes.entry(id).or_default().push(write);
    }

    fn reference(&mut self, id: Id) {
        *self.references.entry(id).or_default() += 1;
    }
}

impl Visit for Bindings {
    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        match assignment.left.as_ident() {
            Some(target) if assignment.op == AssignOp::Assign => {
                self.write_value(target.to_id(), &assignment.right);
            }
            _ => self.write(&assignment.left),
        }
        assignment.visit_children_with(self);
    }

    fn visit_update_expr(&mut self, update: &UpdateExpr) {
        if let Expr::Ident(id) = &*update.arg {
            self.write(id);
        }
        update.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Some(init) = &declarator.init {
            match declarator.name.as_ident() {
                Some(name) => self.write_value(name.to_id(), init),
                None => self.write(&declarator.name),
            }
        }
        declarator.visit_children_with(self);
    }

    /// Loop heads assign on every iteration, whether or not they declare.
    fn visit_for_head(&mut self, head: &ForHead) {
        self.write(head);
        head.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, function: &FnDecl) {
        self.write(&function.ident);
        function.visit_children_with(self);
    }

    fn visit_class_decl(&mut self, class: &ClassDecl) {
        self.write(&class.ident);
        class.visit_children_with(self);
    }

    fn visit_function(&mut self, function: &Function) {
        // A nested function has its own `arguments`; an arrow shares its enclosing function's.
        let outer = mem::take(&mut self.uses_arguments);
        function.visit_children_with(self);
        if mem::replace(&mut self.uses_arguments, outer) {
            self.mapped.extend(
                function
                    .params
                    .iter()
                    .flat_map(|param| swc_ecma_utils::find_pat_ids::<_, Id>(&param.pat)),
            );
        }
    }

    fn visit_param(&mut self, parameter: &Param) {
        self.parameters
            .extend(swc_ecma_utils::find_pat_ids::<_, Id>(&parameter.pat));
        parameter.visit_children_with(self);
    }

    fn visit_arrow_expr(&mut self, arrow: &ArrowExpr) {
        self.parameters
            .extend(swc_ecma_utils::find_pat_ids::<_, Id>(&arrow.params));
        arrow.visit_children_with(self);
    }

    fn visit_ident(&mut self, identifier: &Ident) {
        self.uses_arguments |= identifier.sym == "arguments";
    }

    fn visit_expr(&mut self, expression: &Expr) {
        if let Expr::Ident(id) = expression {
            self.reference(id.to_id());
        }
        expression.visit_children_with(self);
    }

    fn visit_prop(&mut self, property: &Prop) {
        if let Prop::Shorthand(id) = property {
            self.reference(id.to_id());
        }
        property.visit_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use super::Bindings;
    use crate::deobfuscate::testing;

    #[test]
    fn counts_writes_and_references() {
        testing::check(
            "function f(once, twice, escaped, counted, param, m, mutated) {
                once = {}; twice = {}; twice = 1; escaped = {}; use(escaped);
                counted = {}; counted++; var declared = 1; function g() {}
                mutated = {}; mutated.x = 1; [m.w] = [1];
                for (const [a, b] of list) {}
                return once.x + escaped.y + m.z + m[\"w\"] + mutated.x + { param };
            }",
            |program, id| {
                let writes = Bindings::collect(program);
                assert!(writes.is_written_once(&id("once")));
                assert!(!writes.is_written_once(&id("twice")));
                assert!(writes.is_written_once(&id("escaped")));
                assert!(!writes.is_written_once(&id("counted")));
                assert!(writes.is_written_once(&id("declared")));
                assert!(writes.is_written_once(&id("g")));
                assert!(writes.is_written_once(&id("a")));
                assert!(!writes.is_written_once(&id("m")));
                assert_eq!(writes.references(&id("m")), 3);
                assert_eq!(writes.references(&id("escaped")), 2);
                assert_eq!(writes.references(&id("param")), 1);
                assert_eq!(writes.references(&id("mutated")), 2);
            },
        );
    }

    #[test]
    fn follows_copies_and_mapped_parameters() {
        testing::check(
            "function f(late, middle, mixed, h, p, q) {
                late = middle; middle = d; mixed = d; mixed = g();
                function d() {}
                h = {}; p = h; var q = p;
                return late;
            }",
            |program, id| {
                let bindings = Bindings::collect(program);
                assert_eq!(bindings.root(&id("q")), id("h"));
                assert_eq!(bindings.root(&id("late")), id("d"));
                assert_eq!(bindings.root(&id("mixed")), id("mixed"));
            },
        );
        testing::check(
            "function f(a, [b]) { return () => arguments[0]; }
             function g(c) { return function () { return arguments; }; }",
            |program, id| {
                let bindings = Bindings::collect(program);
                assert!(bindings.is_mapped_parameter(&id("a")));
                assert!(bindings.is_mapped_parameter(&id("b")));
                assert!(!bindings.is_mapped_parameter(&id("c")));
            },
        );
    }
}
