//! Refreshes program-specific names and namespace classifications in captured device facts.

use std::collections::{BTreeMap, BTreeSet};

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
    challenge::{installed::Installed, program::PreparedSession},
    js::{JsObject, JsValue, ast},
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

fn names(source: &Source, installed: &Installed) -> Evidence {
    let mut groups = source_names(source);
    let mut functions = groups.remove("source:function").unwrap_or_default();
    functions.extend(installed.factories.iter().cloned());
    functions.extend(
        installed
            .audit
            .iter()
            .filter(|(name, kind)| kind.as_str() == "N" && !installed.window.contains_key(*name))
            .map(|(name, _)| name.clone()),
    );
    let mut markers = BTreeMap::new();
    for (name, kind) in &installed.audit {
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
        if kind == "N" {
            continue;
        }
        groups
            .entry(format!("installed:{kind}"))
            .or_default()
            .push(name.clone());
        if kind == "string" {
            markers.insert(name.clone(), installed.audit[name].clone());
        }
    }
    Evidence {
        groups,
        markers,
        functions,
    }
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
    globals: Groups,
    markers: BTreeMap<String, String>,
}

impl CapturedNames {
    pub(crate) fn capture(source: &Source, plan: &ProbePlan) -> Result<Self> {
        let prepared =
            PreparedSession::try_new(source, &Url::parse("https://challenges.cloudflare.com/")?)?;
        let Evidence {
            groups: globals,
            markers,
            ..
        } = names(source, &prepared.program().installed);
        Ok(Self {
            features: plan
                .probes()
                .iter()
                .map(|p| p.expanded_features.clone())
                .collect(),
            globals,
            markers,
        })
    }
}

pub(crate) struct Refresh {
    direct: Vocabulary,
    aliases: BTreeMap<String, String>,
    functions: Vec<String>,
    array_class: Option<String>,
    trace: Option<Trace>,
    controller: Option<String>,
}

impl Refresh {
    pub(crate) fn new(
        captured: &CapturedNames,
        source: &Source,
        plan: &ProbePlan,
        installed: &Installed,
    ) -> Result<Self> {
        let current: Vec<_> = plan
            .probes()
            .iter()
            .map(|p| p.expanded_features.as_slice())
            .collect();
        let direct = Vocabulary::between(&current, &captured.features);
        let Evidence {
            groups: new_names,
            markers: new_markers,
            functions,
        } = names(source, installed);
        let mut aliases = BTreeMap::new();
        for (kind, old) in &captured.globals {
            // Functions are rebuilt from the current program, so neither their order nor
            // their count needs to match the captured build.
            if matches!(kind.as_str(), "source:function" | "installed:N") {
                continue;
            }
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
        Ok(Self {
            direct,
            aliases,
            functions,
            array_class: array_class(source),
            trace: Trace::recover(source),
            controller: plan.controller_trace.clone(),
        })
    }
    pub(crate) fn apply(
        &self,
        probe: &Probe,
        vocabulary: &Vocabulary,
        fields: &mut JsObject,
    ) -> Result<()> {
        self.direct.rewrite_to_session(probe.position(), fields);
        super::vocabulary::rewrite_object(fields, &|value| {
            if let Some(new) = self.aliases.get(value) {
                *value = new.clone();
            } else if let Some(name) = value
                .strip_prefix("o.")
                .and_then(|name| self.aliases.get(name))
            {
                *value = format!("o.{name}");
            }
        });
        let key = vocabulary.to_session(probe.position(), ENVIRONMENT_AUDIT_GROUPS);
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
                self.controller.as_deref(),
            )?;
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
    fn namespace_refresh_uses_the_current_trace_with_or_without_a_controller() {
        let probe = Probe {
            index: 1,
            token: "test".into(),
            input: JsValue::Null,
            operation: None,
            features: vec![],
            expanded_features: ["entry", "replaceTrace"].map(str::to_owned).to_vec(),
            writes: Default::default(),
        };
        let vocabulary = Vocabulary::infer::<&[String]>(&[]);
        for controller in [None, Some("controller".to_owned())] {
            let refresh = Refresh {
                direct: vocabulary.clone(),
                aliases: BTreeMap::new(),
                functions: vec![],
                array_class: None,
                trace: Some(Trace {
                    global: "trace".into(),
                    replace: "replaceTrace".into(),
                    push: None,
                    initial_root: "initial".into(),
                    returned_root: "callback".into(),
                }),
                controller: controller.clone(),
            };
            let mut fields = JsObject::from_iter([(
                ENVIRONMENT_AUDIT_GROUPS.into(),
                crate::js::json!({
                    "obsolete-captured-trace": ["o.trace", "other"],
                }),
            )]);
            refresh.apply(&probe, &vocabulary, &mut fields).unwrap();
            let current = format!(
                "initial,{},entry",
                controller.as_deref().unwrap_or("callback")
            );
            assert_eq!(
                fields[ENVIRONMENT_AUDIT_GROUPS][&current],
                crate::js::json!(["o.trace"])
            );
            assert_eq!(
                fields[ENVIRONMENT_AUDIT_GROUPS]["obsolete-captured-trace"],
                crate::js::json!(["other"])
            );
        }
    }

    #[test]
    fn rebuilds_functions_when_their_count_changes_without_positional_aliases() {
        let source = Source::try_new("var root = this || self; root.a = function() {}; root.b = function() {}; root.state = {};").unwrap();
        let mut installed = Installed::default();
        installed.audit.insert("marker".into(), "N".into());
        installed
            .window
            .insert("marker".into(), JsValue::String("N".into()));
        let evidence = names(&source, &installed);
        assert_eq!(
            evidence.functions,
            ["a", "b"],
            "a string marker must not become a function"
        );
        let plan = crate::js::from_value(crate::js::json!({
            "record_fields":{"counter":"counter", "token":"token", "input":"input",
                "status":"status", "message":"message", "started":"started",
                "finished":"finished", "duration":"duration"},
            "payload":{"template":{"fields":{}}, "published":[], "footer":{}, "pending":null},
            "probes":[]
        }))
        .unwrap();
        let captured = CapturedNames {
            features: vec![],
            globals: BTreeMap::from([
                ("source:function".into(), vec!["old_function".into()]),
                ("installed:N".into(), vec!["old_factory".into()]),
                ("source:object".into(), vec!["old_state".into()]),
            ]),
            markers: BTreeMap::new(),
        };
        let refreshed = Refresh::new(&captured, &source, &plan, &installed).unwrap();
        assert_eq!(refreshed.functions, ["a", "b"]);
        assert_eq!(
            refreshed.aliases,
            BTreeMap::from([("old_state".into(), "state".into())])
        );
    }

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
