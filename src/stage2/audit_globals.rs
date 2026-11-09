//! Pairs iframe globals by their definitions, independently of randomized identifiers.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use oxc::ast::AstKind;
use oxc::ast::ast::{
    Directive, Expression, MemberExpression, MethodDefinition, ObjectProperty, PropertyDefinition,
    PropertyKind, UpdateExpression,
};
use oxc::ast_visit::{Visit, walk};
use oxc::syntax::scope::ScopeFlags;
use serde::{Deserialize, Serialize};
use url::Url;

use super::syntax::assigned_member;
use super::vocabulary;
use crate::challenge::installed::Installed;
use crate::challenge::program::PreparedSession;
use crate::js::ast::{self, Binding, Script};
use crate::script::Source;

/// A bag of syntax and browser API features. Local variable names, statement order, numeric
/// constants, and session names do not participate in matching.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Signature {
    kind: String,
    features: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
}

/// Signatures of the iframe's session-named globals, by name.
#[derive(Default)]
pub struct Globals(pub BTreeMap<String, Signature>);

impl Globals {
    /// Signatures of the hex-named globals the initial VM program installs.
    pub(crate) fn installed(installed: &Installed) -> Self {
        let mut globals = Self::default();
        for (name, value) in &installed.audit {
            if !vocabulary::is_hex_name(name) {
                continue;
            }
            let role = installed.audit_roles.get(name).map(String::as_str);
            let feature = match role {
                Some(role) => format!("role:{role}"),
                None if vocabulary::is_hex_name(value) => "session-name".into(),
                None => format!("value:{value}"),
            };
            let signature = Signature {
                kind: "installed".into(),
                features: BTreeMap::from([(feature, 1)]),
                // Native function strings use each engine's whitespace and formatting.
                // Preserve the captured classification instead of imposing Chromium's.
                value: (!matches!(role, Some("clock-delta" | "native-array")))
                    .then(|| value.clone()),
            };
            globals.0.insert(name.clone(), signature);
        }
        globals
    }

    /// Recovers both script definitions and globals installed by the initial VM program.
    pub fn capture(source: &Source) -> Result<Self> {
        let prepared =
            PreparedSession::try_new(source, &Url::parse("https://challenges.cloudflare.com/")?)?;
        let mut globals = Self::installed(&prepared.program().installed);
        globals.0.extend(Self::recover(source).0);
        Ok(globals)
    }

    /// Signatures of the hex-named globals the iframe script assigns on `window` or an alias.
    pub(crate) fn recover(source: &Source) -> Self {
        let script = source.script();
        let aliases = aliases(script);
        let mut globals = Self::default();
        for node in script.nodes.iter() {
            let AstKind::AssignmentExpression(assignment) = node.kind() else {
                continue;
            };
            if let Some(member) = assigned_member(&assignment.left)
                && let Expression::Identifier(alias) = member.object().without_parentheses()
                && aliases.contains(&script.binding(alias))
                && let Some(name) = ast::member_str(member)
                && vocabulary::is_hex_name(name)
            {
                let signature = globals.0.entry(name.to_owned()).or_default();
                if signature.kind.is_empty() {
                    signature.kind = match assignment.right.without_parentheses() {
                        Expression::FunctionExpression(_)
                        | Expression::ArrowFunctionExpression(_) => "function",
                        Expression::ObjectExpression(_) => "object",
                        Expression::ArrayExpression(_) => "array",
                        _ => "value",
                    }
                    .into();
                }
                signature.visit_expression(&assignment.right);
            }
        }
        globals
    }

    /// Accepts only a unique best candidate in both directions. Ambiguous definitions are
    /// omitted rather than assigning an unrelated global the recorded value.
    pub fn mapping(&self, recorded: &BTreeMap<String, Signature>) -> BTreeMap<String, String> {
        let mut scores = Vec::new();
        for (old, signature) in recorded {
            for (new, candidate) in &self.0 {
                let score = signature.similarity(candidate);
                if score >= 0.9 {
                    scores.push((old, new, score));
                }
            }
        }
        scores
            .iter()
            .filter(|(old, new, score)| {
                !scores.iter().any(|(other_old, other_new, other_score)| {
                    (other_old == old && other_new != new || other_new == new && other_old != old)
                        && other_score >= score
                })
            })
            .map(|(old, new, _)| ((*old).clone(), (*new).clone()))
            .collect()
    }
}

impl Signature {
    /// A global's initial audit value when recovered from VM initialization.
    #[must_use]
    pub fn audit_value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// The startup timer's measured delta varies between otherwise equivalent sessions.
    #[must_use]
    pub fn is_elapsed_time(&self) -> bool {
        self.features.contains_key("role:clock-delta")
    }

    fn similarity(&self, other: &Self) -> f64 {
        if self.kind != other.kind {
            return 0.0;
        }
        let mut intersection = 0;
        let mut union = 0;
        let keys: BTreeSet<&String> = self.features.keys().chain(other.features.keys()).collect();
        for key in keys {
            let a = self.features.get(key).copied().unwrap_or_default();
            let b = other.features.get(key).copied().unwrap_or_default();
            intersection += a.min(b);
            union += a.max(b);
        }
        let structural = intersection as f64 / union.max(1) as f64;
        let anchors = |signature: &Self| {
            signature
                .features
                .keys()
                .filter(|key| key.starts_with("property:") || key.starts_with("string:"))
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        let own_anchors = anchors(self);
        if self.kind == "function" && own_anchors.len() >= 2 && own_anchors == anchors(other) {
            // Deobfuscation can duplicate reads and move local declarations while preserving
            // the APIs and fixed strings that identify the helper.
            structural.max(0.9 + 0.1 * structural)
        } else {
            structural
        }
    }

    fn feature(&mut self, feature: String) {
        *self.features.entry(feature).or_default() += 1;
    }

    /// Counts a string literal's features, as [`Visit::visit_expression`] does for an expression.
    fn literal(&mut self, text: Option<&str>) {
        if let Some(text) = text
            && !vocabulary::is_hex_name(text)
            && text.len() <= 64
            && text
                .chars()
                .all(|character| character.is_ascii_alphabetic() || " ._-/".contains(character))
        {
            self.feature(format!("string:{text}"));
        }
    }
}

/// The global `window` and the bindings whose `_cf_chl_opt` property the script reads.
fn aliases(script: Script<'_>) -> BTreeSet<Binding<'_>> {
    struct Aliases<'a> {
        script: Script<'a>,
        found: BTreeSet<Binding<'a>>,
    }
    impl<'a> Visit<'a> for Aliases<'a> {
        fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
            if ast::member_str(member) == Some("_cf_chl_opt")
                && let Expression::Identifier(alias) = member.object().without_parentheses()
            {
                self.found.insert(self.script.binding(alias));
            }
            walk::walk_member_expression(self, member);
        }
    }
    let mut aliases = Aliases {
        script,
        found: BTreeSet::from([Binding::Global("window")]),
    };
    aliases.visit_program(script.program);
    aliases.found
}

/// Counts the syntax and API features of a definition. Features count expressions, so property
/// keys, shorthand values, and object methods and accessors, which are not written as
/// expressions, add none; directives count as the string expressions they are written as.
impl<'a> Visit<'a> for Signature {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        let feature = match expression {
            // `super` is not an expression; see `visit_member_expression`.
            Expression::Super(_) => return,
            Expression::BinaryExpression(value) => format!("binary:{:?}", value.operator.as_str()),
            Expression::LogicalExpression(value) => format!("binary:{:?}", value.operator.as_str()),
            Expression::UnaryExpression(value) => format!("unary:{:?}", value.operator.as_str()),
            Expression::CallExpression(_) | Expression::ImportExpression(_) => "call".into(),
            Expression::NewExpression(_) => "new".into(),
            Expression::ConditionalExpression(_) => "conditional".into(),
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) => {
                "function".into()
            }
            Expression::ArrayExpression(_) => "array".into(),
            Expression::ObjectExpression(_) => "object".into(),
            Expression::AssignmentExpression(value) => {
                format!("assign:{:?}", value.operator.as_str())
            }
            Expression::BooleanLiteral(value) => format!("bool:{}", value.value),
            _ => "expression".into(),
        };
        self.feature(feature);
        self.literal(ast::static_str(expression));
        walk::walk_expression(self, expression);
    }

    fn visit_directive(&mut self, directive: &Directive<'a>) {
        self.feature("expression".into());
        self.literal(directive.expression.value.as_str());
    }

    fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
        if property.computed {
            self.visit_property_key(&property.key);
        }
        match &property.value {
            Expression::FunctionExpression(function)
                if property.method || property.kind != PropertyKind::Init =>
            {
                walk::walk_function(self, function, ScopeFlags::Function);
            }
            _ if property.shorthand => {}
            value => self.visit_expression(value),
        }
    }

    fn visit_method_definition(&mut self, method: &MethodDefinition<'a>) {
        if method.computed {
            self.visit_property_key(&method.key);
        }
        self.visit_function(&method.value, ScopeFlags::Function);
    }

    fn visit_property_definition(&mut self, property: &PropertyDefinition<'a>) {
        if property.computed {
            self.visit_property_key(&property.key);
        }
        if let Some(value) = &property.value {
            self.visit_expression(value);
        }
    }

    /// Counts the operand of an update, which is written as an expression.
    fn visit_update_expression(&mut self, update: &UpdateExpression<'a>) {
        self.feature("expression".into());
        walk::walk_update_expression(self, update);
    }

    fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
        let randomized = |name: &str| {
            vocabulary::is_hex_name(name)
                || name.strip_prefix("_0x").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        };
        // A `super` property read is not a member expression.
        if matches!(member.object(), Expression::Super(_)) {
            if let MemberExpression::ComputedMemberExpression(member) = member {
                self.visit_expression(&member.expression);
            }
            return;
        }
        if let Some(name) = ast::member_str(member)
            && !randomized(name)
        {
            self.feature(format!("property:{name}"));
        }
        walk::walk_member_expression(self, member);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn globals(script: &str) -> Globals {
        Globals::recover(&Source::try_new(script).unwrap())
    }

    #[test]
    fn pairs_definitions_across_aliases_and_local_names() {
        let old = globals(
            r#"
            var x = window; x._cf_chl_opt;
            window._111111111111111111111111 = function(a) { return a.createHTML(); };
            x._222222222222222222222222 = function(b) { return b.createScript(); };
        "#,
        );
        let new = globals(
            r#"
            var y = window; y._cf_chl_opt;
            y._aaaaaaaaaaaaaaaaaaaaaaaa = function(c) { return c.createScript(); };
            window._bbbbbbbbbbbbbbbbbbbbbbbb = function(d) { return d.createHTML(); };
        "#,
        );
        let mapping = new.mapping(&old.0);
        assert_eq!(mapping.len(), 2);
        assert_eq!(
            mapping["_111111111111111111111111"],
            "_bbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            mapping["_222222222222222222222222"],
            "_aaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn ambiguous_or_different_definitions_are_omitted() {
        let old = globals("window._111111111111111111111111 = function(a) { return a; };");
        let duplicates = globals(
            r#"
            window._aaaaaaaaaaaaaaaaaaaaaaaa = function(b) { return b; };
            window._bbbbbbbbbbbbbbbbbbbbbbbb = function(c) { return c; };
        "#,
        );
        assert!(duplicates.mapping(&old.0).is_empty());
        let different = globals("window._aaaaaaaaaaaaaaaaaaaaaaaa = { value: true };");
        assert!(different.mapping(&old.0).is_empty());
    }

    #[test]
    fn injected_operator_helpers_do_not_change_api_identity() {
        let old = globals(
            "window._111111111111111111111111 = \
             function(a) { return a.getOwnPropertyNames().concat(a.keys()); };",
        );
        let new = globals(
            "window._aaaaaaaaaaaaaaaaaaaaaaaa = function(b) { \
             var h = {_0xabc: function(x) { return x; }}; h._0xabc(b); \
             return b.getOwnPropertyNames().concat(b.keys()); };",
        );
        assert_eq!(
            new.mapping(&old.0)["_111111111111111111111111"],
            "_aaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }
}
