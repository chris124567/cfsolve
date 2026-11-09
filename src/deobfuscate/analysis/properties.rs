//! Tracks static property reads, calls, definitions, escapes, and dynamic accesses, so rewrites
//! can decide whether properties keep their defined values.

use oxc::ast::ast::{
    AssignmentExpression, AssignmentTarget, CallExpression, Expression, IdentifierReference,
    MemberExpression, ObjectExpression, ObjectPropertyKind, Program, PropertyKind, ThisExpression,
    UnaryExpression, UpdateExpression, VariableDeclarator,
};
use oxc::ast_visit::{Visit, walk};
use oxc::syntax::operator::{AssignmentOperator, UnaryOperator};

use super::{Analysis, Id};
use crate::deobfuscate::{HashMap, HashSet, ast};

/// Observations and definitions of an object, merged over its single-assignment aliases.
#[derive(Default)]
pub(in crate::deobfuscate) struct Uses<'a> {
    /// The object escapes: it is passed, returned, stored, coerced, or copied into a binding
    /// with several writes.
    pub whole: bool,
    /// An unknown or special key, unsupported property definition, or indexed method call.
    pub dynamic: bool,
    /// Accessed through a constant non-negative integer index.
    pub indexed: bool,
    /// Deleting a property can expose inherited values.
    pub deleted: bool,
    /// A property value mentions `this` and may observe or mutate the object when called.
    pub this: bool,
    /// A property is assigned or updated through some alias.
    pub written: bool,
    /// Static keys read, called, updated, or written by destructuring and loop targets.
    pub read: HashSet<&'a str>,
    /// Static keys called with the object as receiver, including inherited methods.
    pub called: HashSet<&'a str>,
    /// Definition counts from literal entries, assignments, updates, and pattern targets.
    pub defined: HashMap<&'a str, usize>,
}

impl Uses<'_> {
    /// Checks that no untracked observation can change the object's properties. Rejects escapes,
    /// dynamic or indexed keys, deletion, `this` in property values, and calls to inherited
    /// methods such as `hasOwnProperty`.
    pub(in crate::deobfuscate) fn is_tracked(&self) -> bool {
        !self.whole
            && !self.dynamic
            && !self.indexed
            && !self.deleted
            && !self.this
            && self.called.iter().all(|key| self.defined.contains_key(key))
    }
}

/// Property uses by object identity. Single-write copies such as `alias = object` share a root;
/// the copy itself is not an escape.
#[derive(Default)]
pub(in crate::deobfuscate) struct Properties<'a> {
    uses: HashMap<Id, Uses<'a>>,
}

impl<'a> Properties<'a> {
    pub(crate) fn collect(program: &Program<'a>, analysis: &Analysis<'a>) -> Self {
        let mut collect = Collect {
            analysis,
            properties: Self::default(),
        };
        collect.visit_program(program);
        collect.properties
    }

    /// Returns the uses merged over every binding with the same copy-chain root as `id`.
    pub(crate) fn get(&self, id: Id, analysis: &Analysis<'_>) -> Option<&Uses<'a>> {
        self.uses.get(&analysis.bindings.root(&id))
    }

    /// Checks that `id.key` has exactly one definition and no untracked observation can change
    /// it (see [`Uses::is_tracked`]). Inlining also needs a separate proof that the definition
    /// runs first.
    pub(crate) fn stable(&self, id: Id, key: &str, analysis: &Analysis<'_>) -> bool {
        self.get(id, analysis)
            .is_some_and(|uses| uses.is_tracked() && uses.defined.get(key) == Some(&1))
    }

    /// Checks that every observation is a constant-index read, with no calls, writes, or escapes.
    pub(crate) fn only_indexed(&self, id: Id, analysis: &Analysis<'_>) -> bool {
        self.get(id, analysis).is_some_and(|uses| {
            !uses.whole
                && !uses.dynamic
                && !uses.deleted
                && !uses.this
                && !uses.written
                && uses.called.is_empty()
                && uses.read.is_empty()
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Call,
    Delete,
    Write,
    ReadWrite,
}

struct Collect<'b, 'a> {
    analysis: &'b Analysis<'a>,
    properties: Properties<'a>,
}

impl<'a> Collect<'_, 'a> {
    fn uses(&mut self, id: Id) -> &mut Uses<'a> {
        let root = self.analysis.bindings.root(&id);
        self.properties.uses.entry(root).or_default()
    }

    /// Records an object literal assigned to `id`, and returns whether `value` is the tracked
    /// copy that makes `id` an alias.
    fn define(&mut self, id: Id, value: &Expression<'a>) -> bool {
        if let Expression::ObjectExpression(object) = value.get_inner_expression() {
            self.object(id, object)
        }
        self.analysis
            .expression_id(value)
            .is_some_and(|source| self.analysis.bindings.copy_source(&id) == Some(&source))
    }

    fn object(&mut self, id: Id, object: &ObjectExpression<'a>) {
        let uses = self.uses(id);
        for property in &object.properties {
            let ObjectPropertyKind::ObjectProperty(property) = property else {
                uses.dynamic = true;
                continue;
            };
            let Some(key) = ast::key(&property.key, property.computed) else {
                uses.dynamic = true;
                continue;
            };
            uses.dynamic |= property.method || property.kind != PropertyKind::Init;
            uses.dynamic |= key == "__proto__";
            *uses.defined.entry(key).or_default() += 1;
            uses.this |= mentions_this(&property.value);
        }
    }

    /// Records how a member is used, then visits its evaluated object and computed key operands.
    fn member(&mut self, member: &MemberExpression<'a>, access: Access) {
        if let Some(id) = self.analysis.expression_id(member.object()) {
            let key = member.static_property_name().and_then(|name| name.as_str());
            let indexed = matches!(member, MemberExpression::ComputedMemberExpression(computed)
                if ast::number(&computed.expression)
                    .is_some_and(|index| index >= 0.0 && index.fract() == 0.0));
            let uses = self.uses(id);
            let write = matches!(access, Access::Write | Access::ReadWrite);
            uses.dynamic |= access == Access::Call && key.is_none();
            uses.written |= write;
            uses.deleted |= access == Access::Delete;
            if let Some(key) = key {
                if write {
                    *uses.defined.entry(key).or_default() += 1;
                }
                if access != Access::Write {
                    uses.read.insert(key);
                }
                if access == Access::Call {
                    uses.called.insert(key);
                }
                uses.dynamic |= key == "__proto__";
            } else if indexed {
                uses.indexed = true
            } else {
                uses.dynamic = true
            }
        } else {
            self.visit_expression(member.object())
        }
        if let MemberExpression::ComputedMemberExpression(computed) = member {
            self.visit_expression(&computed.expression)
        }
    }
}

impl<'a> Visit<'a> for Collect<'_, 'a> {
    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        if let Some(id) = self.analysis.id(reference) {
            self.uses(id).whole = true
        }
    }

    fn visit_expression(&mut self, expression: &Expression<'a>) {
        match expression.as_member_expression() {
            Some(member) => self.member(member, Access::Read),
            None => walk::walk_expression(self, expression),
        }
    }

    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let Some(id) = self.analysis.target_id(&assignment.left) {
            if !self.define(id, &assignment.right) {
                self.visit_expression(&assignment.right)
            }
        } else if let Some(member) = assignment.left.as_member_expression() {
            if let Some(id) = self.analysis.expression_id(member.object()) {
                self.uses(id).this |= mentions_this(&assignment.right)
            }
            let access = if assignment.operator == AssignmentOperator::Assign {
                Access::Write
            } else {
                Access::ReadWrite
            };
            self.member(member, access);
            self.visit_expression(&assignment.right)
        } else {
            walk::walk_assignment_expression(self, assignment)
        }
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(id) = ast::pattern_id(&declarator.id)
            && let Some(value) = &declarator.init
            && self.define(id, value)
        {
            return;
        }
        walk::walk_variable_declarator(self, declarator)
    }

    fn visit_assignment_target(&mut self, target: &AssignmentTarget<'a>) {
        match target.as_member_expression() {
            Some(member) => self.member(member, Access::ReadWrite),
            None => walk::walk_assignment_target(self, target),
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        match call.callee.get_inner_expression().as_member_expression() {
            Some(member) => self.member(member, Access::Call),
            None => self.visit_expression(&call.callee),
        }
        for argument in &call.arguments {
            self.visit_argument(argument)
        }
    }

    fn visit_unary_expression(&mut self, unary: &UnaryExpression<'a>) {
        if unary.operator == UnaryOperator::Delete
            && let Some(member) = unary.argument.get_inner_expression().as_member_expression()
        {
            self.member(member, Access::Delete)
        } else {
            walk::walk_unary_expression(self, unary)
        }
    }

    fn visit_update_expression(&mut self, update: &UpdateExpression<'a>) {
        match update.argument.as_member_expression() {
            Some(member) => self.member(member, Access::ReadWrite),
            None => walk::walk_update_expression(self, update),
        }
    }
}

/// Checks for `this`, including in nested functions, since a method may pass its receiver on.
fn mentions_this(value: &Expression<'_>) -> bool {
    struct This(bool);

    impl<'a> Visit<'a> for This {
        fn visit_this_expression(&mut self, _: &ThisExpression) {
            self.0 = true
        }
    }

    let mut this = This(false);
    this.visit_expression(value);
    this.0
}

#[cfg(test)]
mod tests {
    use super::Properties;
    use crate::deobfuscate::testing;

    #[test]
    fn counts_definitions_through_aliases() {
        testing::check(
            "function f(h,p,q,o){h={a:1,b:function(){}};p=h;var q=p;q.c=2;p.a+=1;h.b();o={d:1};o.d++;return [q.a,p.c];}",
            |program, analysis, id| {
                let properties = Properties::collect(program, analysis);
                assert!(!properties.stable(id("h"), "a", analysis));
                assert!(properties.stable(id("q"), "b", analysis));
                assert!(properties.stable(id("h"), "c", analysis));
                assert!(!properties.stable(id("o"), "d", analysis));
                let object = properties.get(id("p"), analysis).unwrap();
                for key in ["a", "b", "c"] {
                    assert!(object.read.contains(key), "{key}")
                }
            },
        );
    }

    #[test]
    fn rejects_escapes_dynamic_keys_and_observable_mutations() {
        for source in [
            "use(h);",
            "use({h});",
            "h[k]=1;",
            "h[0];",
            "h.__proto__;",
            "delete h.a;",
            "h.hasOwnProperty('a');",
            "(h.hasOwnProperty)('a');",
            "h?.hasOwnProperty('a');",
            "h.m=function(){return this};h.m();",
            "p=h;p=2;h.a;",
            "[h.a]=[1];",
            "for(h.a of list);",
            "h.a++;",
            "h.a+=1;",
        ] {
            testing::check(
                &format!("function f(h,p,k){{h={{a:1}};{source}}}"),
                |program, analysis, id| {
                    assert!(
                        !Properties::collect(program, analysis).stable(id("h"), "a", analysis),
                        "{source}"
                    )
                },
            );
        }
    }

    #[test]
    fn distinguishes_constant_index_reads_from_writes() {
        for (source, only_indexed) in [
            ("f[0]+f[3];", true),
            ("f[0]();", false),
            ("f[0]=1;", false),
            ("f[0]++;", false),
            ("delete f[0];", false),
            ("[f[0]]=[1];", false),
            ("for(f[0] of [1]);", false),
            ("f.length;", false),
            ("f[i];", false),
            ("use({f});", false),
        ] {
            testing::check(
                &format!("function g(a,f,i){{f=[a];{source}}}"),
                |program, analysis, id| {
                    assert_eq!(
                        Properties::collect(program, analysis).only_indexed(id("f"), analysis),
                        only_indexed,
                        "{source}"
                    )
                },
            );
        }
    }
}
