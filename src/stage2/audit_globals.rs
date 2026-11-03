//! Pairs iframe globals by their definitions, independently of randomized identifiers.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use swc_core::ecma::ast::{AssignExpr, AssignTarget, Expr, Lit, MemberExpr, SimpleAssignTarget};
use swc_core::ecma::visit::{Visit, VisitWith};
use url::Url;

use super::vocabulary;
use crate::challenge::installed::Installed;
use crate::challenge::program::PreparedSession;
use crate::js::ast;
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
        let mut aliases = Aliases(BTreeSet::from(["window".to_owned()]));
        source.parsed().script.visit_with(&mut aliases);
        let mut definitions = Definitions {
            aliases: aliases.0,
            globals: Self::default(),
        };
        source.parsed().script.visit_with(&mut definitions);
        definitions.globals
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
        for key in self
            .features
            .keys()
            .chain(other.features.keys())
            .collect::<BTreeSet<_>>()
        {
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
}

struct Aliases(BTreeSet<String>);

impl Visit for Aliases {
    fn visit_member_expr(&mut self, member: &MemberExpr) {
        if ast::member_str(&member.prop) == Some("_cf_chl_opt")
            && let Expr::Ident(alias) = member.obj.unwrap_parens()
        {
            self.0.insert(alias.sym.to_string());
        }
        member.visit_children_with(self);
    }
}

struct Definitions {
    aliases: BTreeSet<String>,
    globals: Globals,
}

impl Visit for Definitions {
    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && let Expr::Ident(alias) = member.obj.unwrap_parens()
            && self.aliases.contains(alias.sym.as_ref())
            && let Some(name) = ast::member_str(&member.prop)
            && vocabulary::is_hex_name(name)
        {
            let signature = self.globals.0.entry(name.to_owned()).or_default();
            if signature.kind.is_empty() {
                signature.kind = match assignment.right.unwrap_parens() {
                    Expr::Fn(_) | Expr::Arrow(_) => "function",
                    Expr::Object(_) => "object",
                    Expr::Array(_) => "array",
                    _ => "value",
                }
                .into();
            }
            assignment.right.visit_with(signature);
        }
        assignment.visit_children_with(self);
    }
}

impl Visit for Signature {
    fn visit_expr(&mut self, expression: &Expr) {
        let feature = match expression {
            Expr::Bin(value) => format!("binary:{:?}", value.op),
            Expr::Unary(value) => format!("unary:{:?}", value.op),
            Expr::Call(_) => "call".into(),
            Expr::New(_) => "new".into(),
            Expr::Cond(_) => "conditional".into(),
            Expr::Fn(_) | Expr::Arrow(_) => "function".into(),
            Expr::Array(_) => "array".into(),
            Expr::Object(_) => "object".into(),
            Expr::Assign(value) => format!("assign:{:?}", value.op),
            Expr::Lit(Lit::Bool(value)) => format!("bool:{}", value.value),
            _ => "expression".into(),
        };
        self.feature(feature);
        if let Some(text) = ast::static_str(expression)
            && !vocabulary::is_hex_name(text)
            && text.len() <= 64
            && text
                .chars()
                .all(|character| character.is_ascii_alphabetic() || " ._-/".contains(character))
        {
            self.feature(format!("string:{text}"));
        }
        expression.visit_children_with(self);
    }

    fn visit_member_expr(&mut self, member: &MemberExpr) {
        let randomized = |name: &str| {
            vocabulary::is_hex_name(name)
                || name.strip_prefix("_0x").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
        };
        if let Some(name) = ast::member_str(&member.prop)
            && !randomized(name)
        {
            self.feature(format!("property:{name}"));
        }
        member.visit_children_with(self);
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
