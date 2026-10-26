//! Recovers the tally the iframe keeps of the visitor's input events, and counts events into it
//! as the iframe's listener would.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use swc_core::ecma::ast::{
    AssignExpr, AssignTarget, BlockStmt, Expr, IfStmt, Lit, Pat, Script, SimpleAssignTarget,
    UpdateExpr, UpdateOp, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::candidates;
use crate::challenge::expression::{self, BuiltObject, ObjectField};
use crate::js::{JsValue, Window, ast, json};

/// Minimum number of zeroed fields used to recognize an interaction tally.
const COUNTERS: usize = 4;
/// Input event types counted by the iframe listener. Native tally updates require all mappings.
const COUNTED_EVENTS: [&str; 7] = [
    "mousemove",
    "pointermove",
    "pointerover",
    "touchstart",
    "click",
    "keydown",
    "wheel",
];

/// The tally the script keeps of the visitor's interactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tally {
    pub global: String,
    pub counters: Vec<String>,
}

/// Counts input events using the iframe listener's event mapping.
#[derive(Debug)]
pub struct CounterEvents {
    /// The global holding the tally.
    pub global: String,
    /// Each counted event type, mapped to the field its branch increments.
    pub events: BTreeMap<String, String>,
    /// The field every counted event increments as well.
    pub total: String,
}

impl CounterEvents {
    pub(super) fn recover(script: &Script, tally: &Tally) -> Result<Self> {
        let mut aliases = Aliases {
            global: &tally.global,
            found: BTreeSet::new(),
        };
        script.visit_with(&mut aliases);
        let mut handlers = Handlers {
            aliases: &aliases.found,
            names: &tally.counters,
            events: BTreeMap::new(),
        };
        script.visit_with(&mut handlers);
        let used: BTreeSet<_> = handlers.events.values().collect();
        let remaining = tally.counters.iter().filter(|name| !used.contains(name));
        let total = candidates::exactly_one(remaining, "unhandled counter")
            .context("finding the input event tally's total")?
            .clone();
        ensure!(
            handlers.events.len() == COUNTED_EVENTS.len() && used.len() == COUNTED_EVENTS.len(),
            "the input listener counts {} of the {} input events, into {} distinct counters",
            handlers.events.len(),
            COUNTED_EVENTS.len(),
            used.len()
        );
        Ok(Self {
            global: tally.global.clone(),
            events: handlers.events,
            total,
        })
    }

    /// Counts supported `events` in the tally stored on `window`. Ignores event types the
    /// iframe listener does not count.
    pub fn record(&self, window: &mut Window, events: &[&str]) -> Result<()> {
        let tally = window
            .get_mut(&self.global)
            .and_then(JsValue::as_object_mut)
            .context("iframe has no input event tally")?;
        for event in events {
            let Some(field) = self.events.get(*event) else {
                continue;
            };
            for field in [field, &self.total] {
                let count = tally
                    .get(field)
                    .and_then(JsValue::as_u64)
                    .context("input event tally is not an integer")?;
                tally.insert(field.clone(), json!(count + 1));
            }
        }
        Ok(())
    }
}

/// The locals the tally's global is copied into: `local = <namespace>.<global>`.
struct Aliases<'tally> {
    global: &'tally str,
    found: BTreeSet<String>,
}

impl Visit for Aliases<'_> {
    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(local)) = &assignment.left
            && let Expr::Member(member) = &*assignment.right
            && ast::member_str(&member.prop) == Some(self.global)
        {
            self.found.insert(local.id.sym.to_string());
        }
        assignment.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, variable: &VarDeclarator) {
        if let Pat::Ident(local) = &variable.name
            && let Some(Expr::Member(member)) = variable.init.as_deref()
            && ast::member_str(&member.prop) == Some(self.global)
        {
            self.found.insert(local.id.sym.to_string());
        }
        variable.visit_children_with(self);
    }
}

/// The tally fields incremented through an alias: `<alias>.<field>++`.
struct Updates<'tally> {
    aliases: &'tally BTreeSet<String>,
    names: &'tally [String],
    found: BTreeSet<String>,
}

impl Visit for Updates<'_> {
    fn visit_update_expr(&mut self, update: &UpdateExpr) {
        if update.op == UpdateOp::PlusPlus
            && let Expr::Member(member) = &*update.arg
            && let Expr::Ident(object) = &*member.obj
            && self.aliases.contains(object.sym.as_ref())
            && let Some(field) = ast::member_str(&member.prop)
            && self.names.iter().any(|name| name == field)
        {
            self.found.insert(field.to_owned());
        }
        update.visit_children_with(self);
    }
}

/// Maps each individually tested event type to the counter incremented by its branch.
struct Handlers<'tally> {
    aliases: &'tally BTreeSet<String>,
    names: &'tally [String],
    events: BTreeMap<String, String>,
}

impl Visit for Handlers<'_> {
    fn visit_if_stmt(&mut self, branch: &IfStmt) {
        let events = ast::string_literals(&*branch.test)
            .into_iter()
            .filter(|text| COUNTED_EVENTS.contains(&text.as_str()));
        let mut updates = Updates {
            aliases: self.aliases,
            names: self.names,
            found: BTreeSet::new(),
        };
        branch.cons.visit_with(&mut updates);
        if let Ok(event) = candidates::exactly_one(events, "event type")
            && let Ok(field) = candidates::exactly_one(updates.found, "incremented field")
        {
            self.events.insert(event, field);
        }
        branch.visit_children_with(self);
    }
}

/// Finds the first interaction tally published as `<namespace>.<global> = {...}`. Accepts
/// direct assignment or assignment through a local.
pub(super) fn published_tally(body: &BlockStmt) -> Option<Tally> {
    let mut built: Vec<BuiltObject> = Vec::new();
    for assignment in expression::assignments(body) {
        if expression::track(&mut built, assignment) {
            continue;
        }
        let counters = match &*assignment.right {
            Expr::Ident(ident) => built
                .iter()
                .rfind(|object| object.local == &*ident.sym)
                .and_then(|object| zeroed(&object.fields)),
            right => expression::object_fields(right).as_deref().and_then(zeroed),
        };
        if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && let Some(global) = ast::ident_property(member)
            && let Some(counters) = counters
        {
            return Some(Tally {
                global: global.to_owned(),
                counters,
            });
        }
    }
    None
}

/// Returns counter names when there are enough fields and every value starts at zero.
fn zeroed(fields: &[ObjectField<'_>]) -> Option<Vec<String>> {
    if fields.len() < COUNTERS {
        return None;
    }
    fields
        .iter()
        .map(|field| {
            matches!(field.value, Expr::Lit(Lit::Num(number)) if number.value == 0.0)
                .then(|| field.key.to_owned())
        })
        .collect()
}
