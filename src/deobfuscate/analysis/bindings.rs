//! Counts binding writes and reads in the current tree.

use std::mem;

use oxc::ast::ast::{
    AssignmentExpression, AssignmentTarget, BindingPattern, Class, ClassType, Expression,
    ForStatementLeft, FormalParameters, Function, FunctionType, IdentifierReference,
    MemberExpression, Program, SimpleAssignmentTarget, UpdateExpression, VariableDeclarator,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::Scoping;
use oxc::syntax::operator::AssignmentOperator;
use oxc::syntax::scope::ScopeFlags;

use super::Id;
use crate::deobfuscate::{HashMap, HashSet, ast};

/// Writes and value reads by binding identity, since spelling alone does not identify a local
/// across scopes.
///
/// Writes include assignments, updates, initialized declarations, `for-in` and `for-of` targets,
/// and function or class declarations. Parameters and catch bindings do not count as writes:
/// helpers may use parameter slots whose incoming values are never read.
#[derive(Default)]
pub(in crate::deobfuscate) struct Bindings {
    writes: HashMap<Id, usize>,
    /// Counted from reference flags, including the object read in `binding.property`.
    reads: HashMap<Id, usize>,
    /// The source of each plain copy assignment `target = source`.
    copies: HashMap<Id, Id>,
    /// Function and arrow parameters, including bindings inside destructuring patterns.
    parameters: HashSet<Id>,
    /// Parameters of functions that use `arguments`. In sloppy mode, `arguments[i]` can observe
    /// parameter writes, so passes must preserve those stores and parameter bindings.
    mapped: HashSet<Id>,
}

impl Bindings {
    pub(super) fn collect(program: &Program<'_>, scoping: &Scoping) -> Self {
        let mut collect = Collect {
            scoping,
            bindings: Self::default(),
            arguments: false,
        };
        collect.visit_program(program);
        collect.bindings
    }

    pub(in crate::deobfuscate) fn write_count(&self, id: &Id) -> usize {
        self.writes.get(id).copied().unwrap_or(0)
    }

    pub(in crate::deobfuscate) fn references(&self, id: &Id) -> usize {
        self.reads.get(id).copied().unwrap_or(0)
    }

    pub(in crate::deobfuscate) fn is_written_once(&self, id: &Id) -> bool {
        self.write_count(id) == 1
    }

    /// Checks for a local binding that is never assigned and that `arguments` does not alias, so
    /// every read sees the value it was declared or called with.
    pub(in crate::deobfuscate) fn is_never_written(&self, id: &Id) -> bool {
        !id.is_global() && self.write_count(id) == 0 && !self.is_mapped_parameter(id)
    }

    pub(in crate::deobfuscate) fn is_parameter(&self, id: &Id) -> bool {
        self.parameters.contains(id)
    }

    pub(in crate::deobfuscate) fn is_mapped_parameter(&self, id: &Id) -> bool {
        self.mapped.contains(id)
    }

    /// Returns the source of a plain copy assignment if it is the binding's only write.
    pub(in crate::deobfuscate) fn copy_source(&self, id: &Id) -> Option<&Id> {
        self.copies.get(id).filter(|_| self.is_written_once(id))
    }

    /// Checks whether another single-write binding copies this binding's value.
    pub(in crate::deobfuscate) fn is_copied(&self, id: &Id) -> bool {
        self.copies
            .iter()
            .any(|(alias, source)| source == id && self.is_written_once(alias))
    }

    /// Follows single-write copies to their original binding, stopping at cycles.
    pub(in crate::deobfuscate) fn root(&self, id: &Id) -> Id {
        let mut id = *id;
        let mut seen = HashSet::default();
        while let Some(&next) = self.copy_source(&id) {
            if !seen.insert(id) {
                break;
            }
            id = next
        }
        id
    }
}

struct Collect<'s> {
    scoping: &'s Scoping,
    bindings: Bindings,
    /// Whether the current function mentions `arguments`.
    arguments: bool,
}

impl Collect<'_> {
    fn write(&mut self, id: Id, value: Option<&Expression<'_>>) {
        *self.bindings.writes.entry(id).or_default() += 1;
        let source = value
            .and_then(Expression::get_identifier_reference)
            .and_then(|reference| Id::of(reference, self.scoping));
        if let Some(source) = source {
            self.bindings.copies.insert(id, source);
        }
    }

    fn write_pattern(&mut self, pattern: &BindingPattern<'_>) {
        for id in pattern_ids(pattern) {
            self.write(id, None)
        }
    }
}

fn pattern_ids(pattern: &BindingPattern<'_>) -> impl Iterator<Item = Id> {
    let bindings = pattern.get_binding_identifiers().into_iter();
    bindings.filter_map(|binding| binding.symbol_id.get().map(Id::Local))
}

/// Visits only target bindings; computed member operands and default values execute separately.
struct Targets<'b, 's>(&'b mut Collect<'s>);

impl<'a> Visit<'a> for Targets<'_, '_> {
    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        if let Some(id) = Id::of(reference, self.0.scoping) {
            self.0.write(id, None)
        }
    }

    fn visit_member_expression(&mut self, _: &MemberExpression<'a>) {}

    fn visit_expression(&mut self, _: &Expression<'a>) {}
}

impl<'a> Visit<'a> for Collect<'_> {
    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        self.arguments |= ast::is_arguments(reference);
        if let Some(id) = Id::of(reference, self.scoping) {
            let reference_id = reference.reference_id.get().expect("resolved reference");
            if self.scoping.get_reference(reference_id).is_read() {
                *self.bindings.reads.entry(id).or_default() += 1
            }
        }
    }

    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left {
            if let Some(id) = Id::of(target, self.scoping) {
                let copied = assignment.operator == AssignmentOperator::Assign;
                self.write(id, copied.then_some(&assignment.right))
            }
        } else {
            Targets(self).visit_assignment_target(&assignment.left);
        }
        walk::walk_assignment_expression(self, assignment)
    }

    fn visit_update_expression(&mut self, update: &UpdateExpression<'a>) {
        if let SimpleAssignmentTarget::AssignmentTargetIdentifier(target) = &update.argument
            && let Some(id) = Id::of(target, self.scoping)
        {
            self.write(id, None)
        }
        walk::walk_update_expression(self, update)
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(value) = &declarator.init {
            match ast::pattern_id(&declarator.id) {
                Some(id) => self.write(id, Some(value)),
                None => self.write_pattern(&declarator.id),
            }
        }
        walk::walk_variable_declarator(self, declarator)
    }

    fn visit_for_statement_left(&mut self, left: &ForStatementLeft<'a>) {
        if let ForStatementLeft::VariableDeclaration(declaration) = left {
            for declarator in &declaration.declarations {
                self.write_pattern(&declarator.id)
            }
        } else if let Some(target) = left.as_assignment_target() {
            Targets(self).visit_assignment_target(target)
        }
        walk::walk_for_statement_left(self, left)
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        if function.r#type == FunctionType::FunctionDeclaration
            && let Some(id) = ast::function_id(function)
        {
            self.write(id, None)
        }
        let outer = mem::take(&mut self.arguments);
        walk::walk_function(self, function, flags);
        if mem::replace(&mut self.arguments, outer) {
            for parameter in &function.params.items {
                self.bindings.mapped.extend(pattern_ids(&parameter.pattern));
            }
        }
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        if class.r#type == ClassType::ClassDeclaration
            && let Some(symbol) = class.id.as_ref().and_then(|id| id.symbol_id.get())
        {
            self.write(Id::Local(symbol), None)
        }
        walk::walk_class(self, class)
    }

    fn visit_formal_parameters(&mut self, parameters: &FormalParameters<'a>) {
        for pattern in parameters.iter_bindings() {
            self.bindings.parameters.extend(pattern_ids(pattern));
        }
        walk::walk_formal_parameters(self, parameters)
    }
}

#[cfg(test)]
mod tests {
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
            |_, analysis, id| {
                let bindings = &analysis.bindings;
                assert!(bindings.is_written_once(&id("once")));
                assert!(!bindings.is_written_once(&id("twice")));
                assert!(bindings.is_written_once(&id("escaped")));
                assert!(!bindings.is_written_once(&id("counted")));
                assert!(bindings.is_written_once(&id("declared")));
                assert!(bindings.is_written_once(&id("g")));
                assert!(bindings.is_written_once(&id("a")));
                assert!(!bindings.is_written_once(&id("m")));
                assert_eq!(bindings.references(&id("m")), 3);
                assert_eq!(bindings.references(&id("escaped")), 2);
                assert_eq!(bindings.references(&id("param")), 1);
                assert_eq!(bindings.references(&id("mutated")), 2);
            },
        );
        // Compound assignments and destructuring loop heads are writes.
        testing::check(
            "function f(a,b,c){a+=b;c=1;for([c] of list){}}",
            |_, analysis, id| {
                assert_eq!(analysis.bindings.copy_source(&id("a")), None);
                assert_eq!(analysis.bindings.write_count(&id("a")), 1);
                assert_eq!(analysis.bindings.write_count(&id("c")), 2);
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
            |_, analysis, id| {
                let bindings = &analysis.bindings;
                assert_eq!(bindings.root(&id("q")), id("h"));
                assert_eq!(bindings.root(&id("late")), id("d"));
                assert_eq!(bindings.root(&id("mixed")), id("mixed"));
            },
        );
        testing::check(
            "function f(a, [b]) { return () => arguments[0]; }
             function g(c) { return function () { return arguments; }; }",
            |_, analysis, id| {
                let bindings = &analysis.bindings;
                assert!(bindings.is_mapped_parameter(&id("a")));
                assert!(bindings.is_mapped_parameter(&id("b")));
                assert!(!bindings.is_mapped_parameter(&id("c")));
            },
        );
    }
}
