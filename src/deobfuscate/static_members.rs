//! Replaces computed properties with dot accesses:
//!
//! ```js
//! console["log"];  // becomes console.log
//! ```
//!
//! Accepts string literals and templates without substitutions only when the value is a valid
//! identifier. Both forms then access the same property.

use swc_core::ecma::ast::{IdentName, MemberExpr, MemberProp, Program};
use swc_core::ecma::visit::{VisitMut, VisitMutWith};

use super::analysis::Analysis;
use crate::js::ast;

pub(super) fn run(program: &mut Program, _: &mut Analysis) -> bool {
    let mut members = NameStaticMembers { changed: false };
    program.visit_mut_with(&mut members);
    members.changed
}

struct NameStaticMembers {
    changed: bool,
}

impl VisitMut for NameStaticMembers {
    fn visit_mut_member_expr(&mut self, member: &mut MemberExpr) {
        member.visit_mut_children_with(self);

        if let MemberProp::Computed(property) = &member.prop
            && let Some(property_name) = ast::static_str(&property.expr)
            && swc_ecma_utils::is_valid_ident(property_name)
        {
            member.prop = MemberProp::Ident(IdentName::new(property_name.into(), property.span));
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
            testing::transform(r#"obj[`lo\u0067`](); obj?.[`name`]; obj[`a-b`]; obj[`${key}`];"#);
        let expected = ["obj.log()", "obj?.name", "obj[`a-b`]", "obj[`${key}`]"];
        testing::assert_contains(&output, &expected, &[]);
    }
}
