//! Converts constant property accesses to dot notation and constant object keys to named keys:
//!
//! ```js
//! console["log"];       // becomes console.log
//! h = { ["add"]: f };   // becomes h = { add: f }
//! ```
//!
//! Accepts string literals and templates without substitutions only when the value is a valid
//! identifier. Both forms access the same property. A computed `__proto__` key stays computed: it
//! defines a property, while a named key sets the prototype.

use oxc::allocator::TakeIn;
use oxc::ast::ast::{IdentifierName, MemberExpression, ObjectProperty, Program, PropertyKey};
use oxc::ast_visit::{VisitMut, walk_mut};
use oxc::span::GetSpan;
use oxc::str::Ident;
use oxc::syntax::identifier::is_identifier_name;

use super::analysis::Analysis;
use super::ast;

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut members = StaticMembers {
        analysis,
        changed: false,
    };
    members.visit_program(program);
    members.changed
}

struct StaticMembers<'b, 'a> {
    analysis: &'b Analysis<'a>,
    changed: bool,
}

impl<'a> VisitMut<'a> for StaticMembers<'_, 'a> {
    fn visit_member_expression(&mut self, member: &mut MemberExpression<'a>) {
        walk_mut::walk_member_expression(self, member);
        if let MemberExpression::ComputedMemberExpression(computed) = member
            && let Some(name) = ast::static_str(&computed.expression)
            && is_identifier_name(name)
        {
            let builder = &self.analysis.ast;
            let name = Ident::from_str_in(name, builder);
            let property = IdentifierName::new(computed.expression.span(), name, builder);
            let object = computed.object.take_in(builder);
            *member = MemberExpression::new_static_member_expression(
                computed.span,
                object,
                property,
                computed.optional,
                builder,
            );
            self.changed = true;
        }
    }

    fn visit_object_property(&mut self, property: &mut ObjectProperty<'a>) {
        walk_mut::walk_object_property(self, property);
        if let Some(name) = ast::key(&property.key, property.computed)
            && is_identifier_name(name)
            && !matches!(property.key, PropertyKey::StaticIdentifier(_))
            && !(name == "__proto__" && property.computed)
        {
            let builder = &self.analysis.ast;
            let name = Ident::from_str_in(name, builder);
            let key = IdentifierName::boxed(property.key.span(), name, builder);
            property.key = PropertyKey::StaticIdentifier(key);
            property.computed = false;
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn uses_cooked_static_template_properties() {
        let output =
            testing::transform(r#"obj[`log`](); obj?.[`name`]; obj[`a-b`]; obj[`${key}`];"#);
        let expected = ["obj.log()", "obj?.name", "obj[`a-b`]", "obj[`${key}`]"];
        testing::assert_contains(&output, &expected);
        let output = testing::transform(r#"f({ ["add"]: 1, [`a-b`]: 2, ["__proto__"]: 3 });"#);
        testing::assert_contains(&output, &["add: 1", "[`a-b`]: 2", r#"["__proto__"]: 3"#]);
    }
}
