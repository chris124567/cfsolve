//! Refreshes program-specific names and namespace classifications in captured device facts.

use std::{
    collections::{BTreeMap, BTreeSet},
    mem,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use swc_core::ecma::{
    ast::{
        AssignExpr, AssignTarget, BinaryOp, Expr, IfStmt, Lit, Pat, SimpleAssignTarget, Stmt,
        VarDeclarator,
    },
    visit::{Visit, VisitWith},
};
use url::Url;

use super::{
    records::{Probe, ProbePlan},
    reference::ENVIRONMENT_AUDIT_GROUPS,
    trace::Trace,
    vocabulary::Vocabulary,
};
use crate::{
    challenge::program::PreparedSession,
    js::{JsObject, JsValue, Payload, ast},
    script::Source,
};

type Groups = BTreeMap<String, Vec<String>>;

#[derive(Default)]
struct Namespace {
    roots: BTreeSet<String>,
    writes: Vec<(String, String, String)>,
}

fn is_root(value: &Expr) -> bool {
    let Expr::Bin(expression) = value.unwrap_parens() else {
        return false;
    };
    expression.op == BinaryOp::LogicalOr
        && matches!(expression.left.unwrap_parens(), Expr::This(_))
        && matches!(expression.right.unwrap_parens(), Expr::Ident(name) if name.sym == *"self")
}

impl Visit for Namespace {
    fn visit_var_declarator(&mut self, declaration: &VarDeclarator) {
        if let (Pat::Ident(binding), Some(value)) = (&declaration.name, &declaration.init)
            && is_root(value)
        {
            self.roots.insert(binding.id.sym.to_string());
        }
        declaration.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(binding)) = &assignment.left
            && is_root(&assignment.right)
        {
            self.roots.insert(binding.id.sym.to_string());
        }
        if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && let (Expr::Ident(owner), Some(name)) =
                (member.obj.unwrap_parens(), ast::member_str(&member.prop))
        {
            let kind = match assignment.right.unwrap_parens() {
                Expr::Fn(_) => "function".into(),
                Expr::Object(_) => "object".into(),
                Expr::Array(_) => "array".into(),
                Expr::Lit(Lit::Bool(v)) => v.value.to_string(),
                Expr::Lit(Lit::Num(v)) => v.value.to_string(),
                _ => "other".into(),
            };
            self.writes.push((owner.sym.to_string(), name.into(), kind));
        }
        assignment.visit_children_with(self);
    }
}

fn source_names(source: &Source) -> Groups {
    let mut ns = Namespace::default();
    source.parsed().script.visit_with(&mut ns);
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (root, name, kind) in ns.writes {
        if ns.roots.contains(&root) {
            let group = groups.entry(format!("source:{kind}")).or_default();
            if !group.contains(&name) {
                group.push(name);
            }
        }
    }
    groups
}

struct Evidence {
    groups: Groups,
    markers: BTreeMap<String, String>,
    functions: Vec<String>,
}

fn names(source: &Source) -> Result<Evidence> {
    let mut groups = source_names(source);
    let prepared =
        PreparedSession::try_new(source, &Url::parse("https://challenges.cloudflare.com/")?)?;
    let installed = &prepared.program().installed;
    let mut functions = groups.get("source:function").cloned().unwrap_or_default();
    functions.extend(installed.factories.iter().cloned());
    functions.extend(
        installed
            .audit
            .iter()
            .filter(|(_, kind)| kind.as_str() == "N")
            .map(|(name, _)| name.clone()),
    );
    let mut markers = BTreeMap::new();
    for name in &installed.audit_order {
        let kind = &installed.audit[name];
        let kind = if installed
            .window
            .get(name)
            .and_then(JsValue::as_str)
            .is_some()
        {
            "string"
        } else {
            kind.as_str()
        };
        groups
            .entry(format!("installed:{kind}"))
            .or_default()
            .push(name.clone());
        if kind == "string" {
            markers.insert(name.clone(), installed.audit[name].clone());
        }
    }
    Ok(Evidence {
        groups,
        markers,
        functions,
    })
}

/// The audit gives the iframe's Array constructor a build-specific class marker.
fn array_class(source: &Source) -> Option<String> {
    #[derive(Default)]
    struct Classes(BTreeSet<String>);
    impl Visit for Classes {
        fn visit_if_stmt(&mut self, statement: &IfStmt) {
            if let Expr::Bin(test) = statement.test.unwrap_parens()
                && matches!(test.op, BinaryOp::EqEq | BinaryOp::EqEqEq)
                && [&test.left, &test.right].iter().any(|operand| {
                    matches!(operand.unwrap_parens(), Expr::Member(member) if ast::member_str(&member.prop) == Some("Array"))
                })
            {
                let consequent = match &*statement.cons {
                    Stmt::Block(block) if block.stmts.len() == 1 => &block.stmts[0],
                    consequent => consequent,
                };
                if let Stmt::Return(returned) = consequent
                    && let Some(value) = &returned.arg
                    && let Expr::Call(call) = value.unwrap_parens()
                    && let Some(Expr::Member(callee)) = call.callee.as_expr().map(|value| value.unwrap_parens())
                    && matches!(callee.obj.unwrap_parens(), Expr::Ident(name) if name.sym == *"String")
                    && ast::member_str(&callee.prop) == Some("fromCharCode")
                    && let [argument] = call.args.as_slice()
                    && let Expr::Lit(Lit::Num(number)) = argument.expr.unwrap_parens()
                    && number.value.fract() == 0.0
                    && (1.0..=127.0).contains(&number.value)
                {
                    self.0.insert((number.value as u8 as char).to_string());
                }
            }
            statement.visit_children_with(self);
        }
    }
    let mut classes = Classes::default();
    source.parsed().script.visit_with(&mut classes);
    (classes.0.len() == 1).then(|| classes.0.into_iter().next().unwrap())
}

/// Captured program strings and namespace roles used to refresh session-dependent values.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CapturedNames {
    features: Vec<Vec<String>>,
    references: Vec<Option<usize>>,
    globals: BTreeMap<String, Vec<String>>,
    markers: BTreeMap<String, String>,
    trace: Option<CapturedTrace>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CapturedTrace {
    initial_root: String,
    returned_root: String,
    controller: Option<String>,
    frames: Vec<String>,
}

impl CapturedNames {
    pub(crate) fn capture(source: &Source, plan: &ProbePlan, payload: &Payload) -> Result<Self> {
        let Evidence {
            groups: globals,
            markers,
            ..
        } = names(source)?;
        let trace = if let Some(trace) = Trace::recover(source) {
            let probe = plan
                .probes()
                .iter()
                .find(|p| plan.vocabulary().partner(p.position()) == Some(2))
                .context("no captured audit")?;
            let field = plan
                .vocabulary()
                .to_session(probe.position(), ENVIRONMENT_AUDIT_GROUPS);
            let groups = payload
                .get(&probe.index.to_string())
                .and_then(|record| record.get(field))
                .and_then(JsValue::as_object)
                .context("no captured groups")?;
            let member = JsValue::String(format!("o.{}", trace.global));
            let frames = groups
                .iter()
                .find(|(_, names)| {
                    names
                        .as_array()
                        .is_some_and(|names| names.contains(&member))
                })
                .map(|(frames, _)| frames.split(',').map(str::to_owned).collect())
                .context("no captured trace")?;
            Some(CapturedTrace {
                initial_root: trace.initial_root,
                returned_root: trace.returned_root,
                controller: plan.controller_trace.clone(),
                frames,
            })
        } else {
            None
        };
        Ok(Self {
            features: plan
                .probes()
                .iter()
                .map(|p| p.expanded_features.clone())
                .collect(),
            references: plan
                .probes()
                .iter()
                .map(|p| plan.vocabulary().partner(p.position()))
                .collect(),
            globals,
            markers,
            trace,
        })
    }
}

pub(crate) struct Refresh {
    direct: Vocabulary,
    aliases: BTreeMap<String, String>,
    trace_key: Option<String>,
    functions: Vec<String>,
    array_class: Option<String>,
    trace: Option<Trace>,
}

impl Refresh {
    pub(crate) fn new(captured: &CapturedNames, source: &Source, plan: &ProbePlan) -> Result<Self> {
        let current: Vec<_> = plan
            .probes()
            .iter()
            .map(|p| p.expanded_features.clone())
            .collect();
        let direct = Vocabulary::between(&current, &captured.features);
        let Evidence {
            groups: new_names,
            markers: new_markers,
            functions,
        } = names(source)?;
        let mut aliases = BTreeMap::new();
        for (kind, old) in &captured.globals {
            let new = new_names
                .get(kind)
                .with_context(|| format!("missing namespace category {kind}"))?;
            ensure!(
                old.len() == new.len(),
                "namespace category {kind} changed count"
            );
            for (old, new) in old.iter().zip(new) {
                aliases.insert(old.clone(), new.clone());
                if let (Some(before), Some(after)) =
                    (captured.markers.get(old), new_markers.get(new))
                {
                    aliases.insert(before.clone(), after.clone());
                }
            }
        }
        let trace = Trace::recover(source);
        let trace_key = if let (Some(old_trace), Some(new_trace)) = (&captured.trace, &trace) {
            let mut updated = vec![];
            for frame in &old_trace.frames {
                if frame == &old_trace.initial_root {
                    updated.push(new_trace.initial_root.clone());
                    continue;
                }
                if frame == &old_trace.returned_root {
                    updated.push(new_trace.returned_root.clone());
                    continue;
                }
                if Some(frame) == old_trace.controller.as_ref()
                    && let Some(frame) = &plan.controller_trace
                {
                    updated.push(frame.clone());
                    continue;
                }
                let mut candidates = BTreeSet::new();
                for (old, partner) in captured.features.iter().zip(&captured.references) {
                    if partner.is_none() {
                        continue;
                    }
                    let Some(new_probe) = plan
                        .probes()
                        .iter()
                        .find(|probe| plan.vocabulary().partner(probe.position()) == *partner)
                    else {
                        continue;
                    };
                    if old.len() != new_probe.expanded_features.len() {
                        continue;
                    }
                    for (old, new) in old.iter().zip(&new_probe.expanded_features) {
                        if old == frame {
                            candidates.insert(new.clone());
                        }
                    }
                }
                if candidates.len() == 1 {
                    updated.push(candidates.into_iter().next().unwrap());
                }
            }
            (updated.len() == 3).then(|| updated.join(","))
        } else {
            None
        };
        Ok(Self {
            direct,
            aliases,
            trace_key,
            functions,
            array_class: array_class(source),
            trace,
        })
    }
    pub(crate) fn apply(
        &self,
        probe: &Probe,
        plan: &ProbePlan,
        fields: &mut JsObject,
    ) -> Result<()> {
        self.direct.rewrite_to_session(probe.position(), fields);
        fn rewrite(value: &mut JsValue, names: &BTreeMap<String, String>) {
            fn text(value: &mut String, names: &BTreeMap<String, String>) {
                if let Some(new) = names.get(value) {
                    *value = new.clone();
                    return;
                }
                if let Some(name) = value.strip_prefix("o.").and_then(|name| names.get(name)) {
                    *value = format!("o.{name}");
                }
            }
            match value {
                JsValue::String(value) => text(value, names),
                JsValue::Array(values) => {
                    for value in values {
                        rewrite(value, names)
                    }
                }
                JsValue::Object(values) => {
                    for (mut name, mut value) in mem::take(values) {
                        text(&mut name, names);
                        rewrite(&mut value, names);
                        values.insert(name, value);
                    }
                }
                _ => {}
            }
        }
        let mut value = JsValue::Object(mem::take(fields));
        rewrite(&mut value, &self.aliases);
        let JsValue::Object(refreshed) = value else {
            unreachable!()
        };
        *fields = refreshed;
        let key = plan
            .vocabulary()
            .to_session(probe.position(), ENVIRONMENT_AUDIT_GROUPS);
        if let Some(groups) = fields.get_mut(key).and_then(JsValue::as_object_mut) {
            if let Some(functions) = groups.get_mut("N").and_then(JsValue::as_array_mut) {
                functions.retain(|name| {
                    !name
                        .as_str()
                        .is_some_and(|name| name.starts_with("o.") && name != "o.Array")
                });
                functions.extend(
                    self.functions
                        .iter()
                        .map(|name| JsValue::String(format!("o.{name}"))),
                );
            }
            if let Some(class) = &self.array_class {
                move_member(groups, "Array".into(), class)?;
            }
            let trace = self
                .trace
                .as_ref()
                .context("the current program has no namespace trace")?;
            super::replay::refresh_trace(
                trace,
                groups,
                &probe.expanded_features,
                plan.controller_trace.as_deref(),
            )?;
            if let Some(key) = &self.trace_key {
                move_member(groups, format!("o.{}", trace.global), key)?;
            }
        }
        Ok(())
    }
}

/// Moves a captured member into the class recovered from the current program.
fn move_member(groups: &mut JsObject, member: String, class: &str) -> Result<()> {
    let member = JsValue::String(member);
    let mut found = false;
    for members in groups.values_mut() {
        let members = members
            .as_array_mut()
            .context("an environment audit group is not an array")?;
        found |= members.contains(&member);
        members.retain(|name| name != &member);
    }
    groups.retain(|_, members| {
        members
            .as_array()
            .is_some_and(|members| !members.is_empty())
    });
    if found {
        groups
            .entry(class.to_owned())
            .or_insert_with(|| JsValue::Array(vec![]))
            .as_array_mut()
            .expect("audit groups were validated")
            .push(member);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reclassification_preserves_other_members_and_merges_classes() {
        let mut groups = JsObject::from_iter([
            ("old".into(), crate::js::json!(["Array", "other"])),
            ("current".into(), crate::js::json!(["existing"])),
        ]);
        move_member(&mut groups, "Array".into(), "current").unwrap();
        assert_eq!(groups["old"], crate::js::json!(["other"]));
        assert_eq!(groups["current"], crate::js::json!(["existing", "Array"]));
        move_member(&mut groups, "missing".into(), "unused").unwrap();
        assert!(!groups.contains_key("unused"));
        groups.insert("malformed".into(), JsValue::Null);
        assert!(move_member(&mut groups, "Array".into(), "old").is_err());
    }

    #[test]
    fn array_class_comes_from_the_constructor_check() {
        let source = Source::try_new("function classify(frame, value) { if (value === frame.Array) { return String.fromCharCode(68); } if (value === frame.Function) { return String.fromCharCode(67); } }").unwrap();
        assert_eq!(array_class(&source).as_deref(), Some("D"));
        let ambiguous = Source::try_new("function classify(frame, value) { if (value === frame.Array) return String.fromCharCode(68); if (frame.Array === value) return String.fromCharCode(67); }").unwrap();
        assert_eq!(array_class(&ambiguous), None);
        let unrelated =
            Source::try_new("function unrelated() { return String.fromCharCode(68); }").unwrap();
        assert_eq!(array_class(&unrelated), None);
    }

    #[test]
    fn namespace_roles_follow_assignments_and_ignore_unrelated_helper_objects() {
        let source=Source::try_new("var root = this || self; var helper = {}; helper.unrelated = function() {}; root.first = function() {}; root.second = function() {}; root.state = {}; root.enabled = true; var other; other = this || self; other.third = function() {};").unwrap();
        let groups = source_names(&source);
        assert_eq!(groups["source:function"], vec!["first", "second", "third"]);
        assert_eq!(groups["source:object"], vec!["state"]);
        assert_eq!(groups["source:true"], vec!["enabled"]);
        assert_eq!(groups.len(), 3);
    }
}
