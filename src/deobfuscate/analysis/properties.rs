//! Tracks static property reads, calls, definitions, escapes, and dynamic accesses, so rewrites
//! can decide whether properties retain their defined values.

use swc_core::atoms::Atom;
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, BindingIdent, CallExpr, Callee, Expr, Id, Ident,
    MemberExpr, MemberProp, OptCall, OptChainBase, Pat, Program, Prop, PropName,
    SimpleAssignTarget, TaggedTpl, ThisExpr, UnaryExpr, UnaryOp, UpdateExpr, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use super::Bindings;
use crate::deobfuscate::{HashMap, HashSet};
use crate::js::ast;

/// Tracks property uses by binding and by object. Merges uses through single-assignment copies
/// such as `alias = object`; the copies themselves do not count as uses. See
/// [`Bindings::root`].
pub(crate) struct Properties {
    uses: HashMap<Id, Uses>,
    /// The uses of each root, merged over every binding with that root.
    objects: HashMap<Id, Uses>,
    /// See [`Bindings::roots`].
    roots: HashMap<Id, Id>,
    none: Uses,
}

/// Uses of a binding or of all aliases sharing an object.
#[derive(Default, PartialEq)]
pub(crate) struct Uses {
    /// Passed, returned, stored, coerced, or copied to a multiply assigned binding. Such uses
    /// expose the object to code this summary cannot track.
    whole: bool,
    /// Accessed or defined with an unknown key, including `__proto__`, except for reads at
    /// constant indices.
    computed: bool,
    /// Read through a constant non-negative integer index, `binding[0]`.
    indexed: bool,
    deleted: bool,
    /// A property value mentions `this`, so calling it as a method may observe or mutate the
    /// object.
    this: bool,
    /// Assigned through a property with `=`: `binding.key = value` or `binding[key] = value`.
    pub(crate) written_through: bool,
    /// Static keys accessed through reads, calls, updates, deletions, destructuring writes, or
    /// loop targets. Excludes plain `binding.key = value` assignments.
    pub(crate) accessed: HashSet<Atom>,
    /// The static keys called as methods, `binding.key(...)`.
    called: HashSet<Atom>,
    /// Definition counts for static keys, including object literals, assignments, updates,
    /// destructuring patterns, and loop targets.
    defined: HashMap<Atom, usize>,
}

impl Uses {
    fn merge(&mut self, other: &Self) {
        self.whole |= other.whole;
        self.computed |= other.computed;
        self.indexed |= other.indexed;
        self.deleted |= other.deleted;
        self.this |= other.this;
        self.written_through |= other.written_through;
        self.accessed.extend(other.accessed.iter().cloned());
        self.called.extend(other.called.iter().cloned());
        for (key, count) in &other.defined {
            *self.defined.entry(key.clone()).or_default() += count;
        }
    }

    /// Checks for uses of the whole object or access through a key that could name any
    /// property.
    #[must_use]
    pub(crate) fn is_used_dynamically(&self) -> bool {
        self.whole || self.computed || self.indexed
    }

    /// Checks that every use is a read at a constant index.
    #[must_use]
    pub(crate) fn is_only_indexed(&self) -> bool {
        let indexed_reads = Self {
            indexed: self.indexed,
            ..Self::default()
        };
        *self == indexed_reads
    }
}

impl Properties {
    #[must_use]
    pub(crate) fn collect(program: &Program, bindings: &Bindings) -> Self {
        let mut collect = Collect {
            bindings,
            uses: HashMap::default(),
        };
        program.visit_with(&mut collect);
        let uses = collect.uses;
        let mut objects: HashMap<Id, Uses> = HashMap::default();
        for (id, uses) in &uses {
            objects.entry(bindings.root(id)).or_default().merge(uses);
        }
        Self {
            uses,
            objects,
            roots: bindings.roots(),
            none: Uses::default(),
        }
    }

    /// The uses through `id` itself.
    #[must_use]
    pub(crate) fn binding(&self, id: &Id) -> &Uses {
        self.uses.get(id).unwrap_or(&self.none)
    }

    /// Returns uses through all bindings that share `id`'s object.
    #[must_use]
    pub(crate) fn object(&self, id: &Id) -> &Uses {
        let root = self.roots.get(id).unwrap_or(id);
        self.objects.get(root).unwrap_or(&self.none)
    }

    /// Checks for untracked object observations or mutations: escapes, dynamic keys, deletion,
    /// or methods that may use `this`. Includes inherited methods such as `hasOwnProperty` and
    /// defined methods mentioning `this`.
    #[must_use]
    pub(crate) fn is_opaque(&self, id: &Id) -> bool {
        let object = self.object(id);
        object.is_used_dynamically()
            || object.deleted
            || object.this
            || object
                .called
                .iter()
                .any(|name| !object.defined.contains_key(name))
    }

    /// Checks that `id.key` has one definition. Reads must see that value, or an absent
    /// property if they precede the definition.
    #[must_use]
    pub(crate) fn is_stable(&self, id: &Id, key: &Atom) -> bool {
        !self.is_opaque(id) && self.object(id).defined.get(key) == Some(&1)
    }
}

/// How a member expression is used.
#[derive(Clone, Copy, PartialEq)]
enum Access {
    Read,
    Call,
    /// `binding.key = value`.
    Assign,
    /// Read and written: a compound assignment or an update.
    Update,
    /// Written by a destructuring pattern or a loop head.
    Pattern,
    Delete,
}

struct Collect<'bindings> {
    bindings: &'bindings Bindings,
    uses: HashMap<Id, Uses>,
}

impl Collect<'_> {
    fn uses(&mut self, id: &Ident) -> &mut Uses {
        self.uses.entry(id.to_id()).or_default()
    }

    /// Records an `access` to `member` when its object is a binding, then visits the remaining
    /// evaluated expressions.
    fn member(&mut self, member: &MemberExpr, access: Access) {
        let Some(object) = member.obj.as_ident() else {
            member.visit_children_with(self);
            return;
        };
        let uses = self.uses(object);
        match member_key(&member.prop) {
            Some(key) => {
                if matches!(access, Access::Assign | Access::Update | Access::Pattern) {
                    *uses.defined.entry(key.clone()).or_default() += 1;
                }
                if access == Access::Call {
                    uses.called.insert(key.clone());
                }
                if access != Access::Assign {
                    uses.accessed.insert(key);
                }
            }
            None if access == Access::Read && constant_index(&member.prop).is_some() => {
                uses.indexed = true;
            }
            None => uses.computed = true,
        }
        uses.written_through |= access == Access::Assign;
        uses.deleted |= access == Access::Delete;
        member.prop.visit_with(self);
    }

    /// Records `binding = value`. Returns whether it only copies an alias of the same object;
    /// such copies do not count as object uses.
    fn assignment(&mut self, binding: &Ident, value: &Expr) -> bool {
        let Expr::Object(literal) = value else {
            let copy_source = self.bindings.copy_source(&binding.to_id());
            return value
                .as_ident()
                .is_some_and(|value| copy_source == Some(&value.to_id()));
        };
        let this = mentions_this(literal);
        let uses = self.uses(binding);
        uses.this |= this;
        for property in &literal.props {
            let key = match property.as_prop().map(|property| &**property) {
                Some(Prop::KeyValue(property)) => prop_key(&property.key),
                Some(Prop::Getter(property)) => prop_key(&property.key),
                Some(Prop::Setter(property)) => prop_key(&property.key),
                Some(Prop::Method(property)) => prop_key(&property.key),
                Some(Prop::Shorthand(property)) => Some(property.sym.clone()),
                Some(Prop::Assign(_)) | None => None,
            };
            match key {
                Some(key) => *uses.defined.entry(key).or_default() += 1,
                None => uses.computed = true,
            }
        }
        false
    }

    /// Records a call, including the receiver passed as `this` for member callees.
    fn callee(&mut self, callee: &Expr) {
        match callee {
            Expr::Paren(paren) => self.callee(&paren.expr),
            Expr::Member(member) => self.member(member, Access::Call),
            Expr::OptChain(chain) => match &*chain.base {
                OptChainBase::Member(member) => self.member(member, Access::Call),
                OptChainBase::Call(_) => chain.visit_with(self),
            },
            callee => callee.visit_with(self),
        }
    }
}

impl Visit for Collect<'_> {
    /// Any mention of a binding that the cases below do not account for.
    fn visit_ident(&mut self, identifier: &Ident) {
        self.uses(identifier).whole = true;
    }

    /// Declaring or assigning a binding does not access the object's contents.
    fn visit_binding_ident(&mut self, _: &BindingIdent) {}

    fn visit_member_expr(&mut self, member: &MemberExpr) {
        self.member(member, Access::Read);
    }

    fn visit_call_expr(&mut self, call: &CallExpr) {
        match &call.callee {
            Callee::Expr(callee) => self.callee(callee),
            callee => callee.visit_with(self),
        }
        call.args.visit_with(self);
    }

    fn visit_opt_call(&mut self, call: &OptCall) {
        self.callee(&call.callee);
        call.args.visit_with(self);
    }

    fn visit_tagged_tpl(&mut self, template: &TaggedTpl) {
        self.callee(&template.tag);
        template.tpl.visit_with(self);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        let target = match &assignment.left {
            AssignTarget::Simple(SimpleAssignTarget::Paren(paren)) => paren.expr.as_member(),
            AssignTarget::Simple(SimpleAssignTarget::Member(member)) => Some(member),
            _ => None,
        };
        if let Some(member) = target {
            let access = if assignment.op == AssignOp::Assign {
                Access::Assign
            } else {
                Access::Update
            };
            if let Some(object) = member.obj.as_ident()
                && mentions_this(&assignment.right)
            {
                self.uses(object).this = true;
            }
            self.member(member, access);
        } else if assignment.op == AssignOp::Assign
            && let Some(target) = assignment.left.as_ident()
        {
            if self.assignment(&target.id, &assignment.right) {
                return;
            }
        } else {
            assignment.left.visit_with(self);
        }
        assignment.right.visit_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Pat::Ident(name) = &declarator.name
            && let Some(init) = &declarator.init
            && self.assignment(&name.id, init)
        {
            return;
        }
        declarator.visit_children_with(self);
    }

    fn visit_update_expr(&mut self, update: &UpdateExpr) {
        match &*update.arg {
            Expr::Member(member) => self.member(member, Access::Update),
            argument => argument.visit_with(self),
        }
    }

    fn visit_unary_expr(&mut self, unary: &UnaryExpr) {
        match &*unary.arg {
            Expr::Member(member) if unary.op == UnaryOp::Delete => {
                self.member(member, Access::Delete);
            }
            argument => argument.visit_with(self),
        }
    }

    /// A member a destructuring pattern or a loop head writes.
    fn visit_pat(&mut self, pattern: &Pat) {
        match pattern {
            Pat::Expr(target) if let Expr::Member(member) = &**target => {
                self.member(member, Access::Pattern);
            }
            pattern => pattern.visit_children_with(self),
        }
    }
}

/// The index `[i]` reads, for a non-negative integer `i`.
#[must_use]
pub(crate) fn constant_index(property: &MemberProp) -> Option<usize> {
    ast::index_literal(&property.as_computed()?.expr)
}

/// Identifies `__proto__`, which has special behavior: reads can invoke an inherited accessor,
/// assignments can change the prototype, and object-literal entries set the prototype.
const PROTO: &str = "__proto__";

/// Returns the own-property name in `object.name`, `object["name"]`, or ``object[`name`]``.
/// Rejects keys containing lone surrogates, since converting them to Rust strings would replace
/// them with U+FFFD and could match a different key.
#[must_use]
pub(crate) fn member_key(property: &MemberProp) -> Option<Atom> {
    ast::member_str(property)
        .filter(|name| *name != PROTO)
        .map(Atom::from)
}

/// The own property an object-literal key defines (see [`member_key`]).
#[must_use]
pub(crate) fn prop_key(key: &PropName) -> Option<Atom> {
    ast::key_str(key)
        .filter(|name| *name != PROTO)
        .map(Atom::from)
}

/// Checks for `this` anywhere in `node`, including nested functions. A method mentioning it may
/// observe or change its receiver.
fn mentions_this<N: VisitWith<This>>(node: &N) -> bool {
    let mut this = This(false);
    node.visit_with(&mut this);
    this.0
}

struct This(bool);

impl Visit for This {
    fn visit_this_expr(&mut self, _: &ThisExpr) {
        self.0 = true;
    }
}

#[cfg(test)]
mod tests {
    use swc_core::atoms::Atom;
    use swc_core::ecma::ast::{Expr, MemberProp, Program, PropName};

    use super::{Properties, member_key, prop_key};
    use crate::deobfuscate::analysis::Bindings;
    use crate::deobfuscate::testing;
    use crate::js::ast;

    fn properties(program: &Program) -> Properties {
        Properties::collect(program, &Bindings::collect(program))
    }

    fn member(source: &str) -> MemberProp {
        match ast::parse_expression("member", source).unwrap() {
            Expr::Member(member) => member.prop,
            other => panic!("{source} is {other:?}"),
        }
    }

    fn key(source: &str) -> PropName {
        let Expr::Object(object) = ast::parse_expression("object", source).unwrap() else {
            panic!("{source} is not an object");
        };
        let property = object.props[0].as_prop().unwrap();
        property.as_key_value().unwrap().key.clone()
    }

    #[test]
    fn resolves_static_keys() {
        for source in ["o.name", "o['name']", "o[`name`]", r#"o["n\x61me"]"#] {
            assert_eq!(
                member_key(&member(source)).as_deref(),
                Some("name"),
                "{source}"
            );
        }
        assert_eq!(prop_key(&key("{ 'name': 1 }")).as_deref(), Some("name"));
        assert_eq!(prop_key(&key("{ name: 1 }")).as_deref(), Some("name"));
        // Dynamic, prototype, and lone-surrogate names have no key.
        for source in [
            "o[k]",
            "o[0]",
            "o[`${k}`]",
            "o.__proto__",
            "o['__proto__']",
            r#"o["\uD800"]"#,
            r#"o["\uDC00"]"#,
        ] {
            assert_eq!(member_key(&member(source)), None, "{source}");
        }
        for source in [
            "{ __proto__: 1 }",
            "{ '__proto__': 1 }",
            "{ 0: 1 }",
            "{ [k]: 1 }",
        ] {
            assert_eq!(prop_key(&key(source)), None, "{source}");
        }
        assert_eq!(
            prop_key(&key(r#"{ "\uD800": 1 }"#)),
            None,
            "two different lone surrogates must not become the same key"
        );
    }

    #[test]
    fn counts_definitions_through_aliases() {
        testing::check(
            "function f(h, p, q, o) {
                h = { a: 1, b: function () {} }; p = h; var q = p;
                q.c = 2; p.a += 1; h.b(); o = { d: 1 }; o.d++;
                return [q.a, p.c];
            }",
            |program, id| {
                let properties = properties(program);
                assert!(!properties.is_opaque(&id("q")));
                assert!(!properties.is_stable(&id("h"), &"a".into()));
                assert!(properties.is_stable(&id("q"), &"b".into()));
                assert!(properties.is_stable(&id("h"), &"c".into()));
                assert!(!properties.is_stable(&id("o"), &"d".into()));
                let object = properties.object(&id("p"));
                for key in ["a", "b", "c"] {
                    assert!(object.accessed.contains(&Atom::from(key)), "{key}");
                }
                assert!(properties.binding(&id("q")).written_through);
                assert!(!properties.binding(&id("h")).written_through);
            },
        );
    }

    #[test]
    fn makes_objects_opaque() {
        for (source, opaque) in [
            ("h = {}; use(h);", true),
            ("h = {}; use({ h });", true),
            ("h = {}; h[k] = 1;", true),
            ("h = {}; h[0];", true),
            ("h = {}; h.__proto__;", true),
            ("h = { __proto__: p };", true),
            ("h = { [k]: 1 };", true),
            ("h = {}; delete h.a;", true),
            ("h = {}; h.hasOwnProperty('a');", true),
            ("h = {}; (h.hasOwnProperty)('a');", true),
            ("h = {}; h?.hasOwnProperty('a');", true),
            ("h = { m: function () { return this; } };", true),
            ("h = {}; h.m = function () { return this; };", true),
            ("h = {}; p = h; p = 2; h.a;", true),
            (
                "h = { m: function () {} }; h.m(); h.a = 1; [h.b] = [1]; h.c;",
                false,
            ),
        ] {
            testing::check(
                &format!("function f(h, p, k) {{ {source} }}"),
                |program, id| {
                    assert_eq!(properties(program).is_opaque(&id("h")), opaque, "{source}");
                },
            );
        }
    }

    #[test]
    fn tells_constant_index_reads_from_other_uses() {
        for (source, only_indexed) in [
            ("f = [a]; f[0] + f[3];", true),
            ("f = [a]; f[0]();", false),
            ("f = [a]; f[0] = 1;", false),
            ("f = [a]; f[0]++;", false),
            ("f = [a]; delete f[0];", false),
            ("f = [a]; [f[0]] = [1];", false),
            ("f = [a]; for (f[0] of [1]);", false),
            ("f = [a]; f.length;", false),
            ("f = [a]; f[i];", false),
            ("f = [a]; use({ f });", false),
        ] {
            testing::check(
                &format!("function g(a, f, i) {{ {source} }}"),
                |program, id| {
                    assert_eq!(
                        properties(program).binding(&id("f")).is_only_indexed(),
                        only_indexed,
                        "{source}"
                    );
                },
            );
        }
    }
}
