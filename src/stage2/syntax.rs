//! Syntax matchers and walkers shared by stage-two extractors.
//!
//! Extractors draw these distinctions, which Oxc's tree does not:
//! - A call after `?.` in an optional chain, such as `a?.b()`, is not matched as a call.
//! - `super.x` is not matched as a member expression.
//! - The bodies of object getters and setters and of class constructors belong to the enclosing
//!   code rather than to nested functions.

use oxc::ast::ast::{
    AssignmentTarget, BindingPattern, CallExpression, Expression, FormalParameter,
    MemberExpression, MethodDefinition, MethodDefinitionKind, ObjectProperty, PropertyKind,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::SymbolId;
use oxc::syntax::scope::ScopeFlags;

/// Whether `call` follows a `?.` in an optional chain. Call matchers skip such calls.
pub(super) fn is_optional_call(call: &CallExpression<'_>) -> bool {
    fn optional(expression: &Expression<'_>) -> bool {
        match expression {
            Expression::CallExpression(call) => call.optional || optional(&call.callee),
            _ => expression
                .as_member_expression()
                .is_some_and(|member| member.optional() || optional(member.object())),
        }
    }
    call.optional || optional(&call.callee)
}

/// Matches a member expression whose object is not `super`.
pub(super) fn member<'b, 'a>(expression: &'b Expression<'a>) -> Option<&'b MemberExpression<'a>> {
    expression
        .as_member_expression()
        .filter(|member| !is_super(member))
}

/// Matches assignment to a member whose object is not `super`.
pub(super) fn assigned_member<'b, 'a>(
    target: &'b AssignmentTarget<'a>,
) -> Option<&'b MemberExpression<'a>> {
    target
        .as_member_expression()
        .filter(|member| !is_super(member))
}

/// The binding of a parameter without a pattern or default value.
pub(super) fn plain_parameter(parameter: &FormalParameter<'_>) -> Option<SymbolId> {
    match &parameter.pattern {
        BindingPattern::BindingIdentifier(name) if parameter.initializer.is_none() => {
            Some(name.symbol_id())
        }
        _ => None,
    }
}

fn is_super(member: &MemberExpression<'_>) -> bool {
    matches!(member.object(), Expression::Super(_))
}

/// Walks `property`, visiting an accessor's body in place instead of as a nested function.
/// Visitors that skip or scope nested functions call this from `visit_object_property`.
pub(super) fn walk_property<'a>(visitor: &mut impl Visit<'a>, property: &ObjectProperty<'a>) {
    match &property.value {
        Expression::FunctionExpression(function)
            if matches!(property.kind, PropertyKind::Get | PropertyKind::Set) =>
        {
            visitor.visit_property_key(&property.key);
            walk::walk_function(visitor, function, ScopeFlags::Function);
        }
        _ => walk::walk_object_property(visitor, property),
    }
}

/// Walks `method`, visiting a constructor's body in place instead of as a nested function.
/// Visitors that skip or scope nested functions but enter classes call this from
/// `visit_method_definition`.
pub(super) fn walk_method<'a>(visitor: &mut impl Visit<'a>, method: &MethodDefinition<'a>) {
    if method.kind == MethodDefinitionKind::Constructor {
        visitor.visit_property_key(&method.key);
        walk::walk_function(
            visitor,
            &method.value,
            ScopeFlags::Function | ScopeFlags::Constructor,
        );
    } else {
        walk::walk_method_definition(visitor, method);
    }
}
