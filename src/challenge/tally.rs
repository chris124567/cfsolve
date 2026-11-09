//! Recovers the tally the iframe keeps of the visitor's input events, and counts events into it
//! as the iframe's listener would.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use oxc::ast::ast::{
    AssignmentExpression, AssignmentTarget, BindingPattern, Expression, FunctionBody, IfStatement,
    UpdateExpression, VariableDeclarator,
};
use oxc::ast_visit::{Visit, walk};
use oxc::syntax::operator::UpdateOperator;

use crate::candidates;
use crate::challenge::expression::{self, BuiltObject, ObjectField};
use crate::js::ast::{self, Binding, Script};
use crate::js::{JsValue, Window, json};

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
    pub(super) fn recover(script: Script<'_>, tally: &Tally) -> Result<Self> {
        let mut aliases = Aliases {
            script,
            global: &tally.global,
            found: BTreeSet::new(),
        };
        aliases.visit_program(script.program);
        let mut handlers = Handlers {
            script,
            aliases: &aliases.found,
            names: &tally.counters,
            events: BTreeMap::new(),
        };
        handlers.visit_program(script.program);
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
struct Aliases<'tally, 'a> {
    script: Script<'a>,
    global: &'tally str,
    found: BTreeSet<Binding<'a>>,
}

impl<'a> Visit<'a> for Aliases<'_, 'a> {
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(local) = &assignment.left
            && let Some(member) = assignment.right.as_member_expression()
            && ast::member_str(member) == Some(self.global)
        {
            self.found.insert(self.script.binding(local));
        }
        walk::walk_assignment_expression(self, assignment);
    }

    fn visit_variable_declarator(&mut self, variable: &VariableDeclarator<'a>) {
        if let BindingPattern::BindingIdentifier(local) = &variable.id
            && let Some(member) = variable
                .init
                .as_ref()
                .and_then(Expression::as_member_expression)
            && ast::member_str(member) == Some(self.global)
        {
            self.found.insert(Binding::Symbol(local.symbol_id()));
        }
        walk::walk_variable_declarator(self, variable);
    }
}

/// The tally fields incremented through an alias: `<alias>.<field>++`.
struct Updates<'tally, 'a> {
    script: Script<'a>,
    aliases: &'tally BTreeSet<Binding<'a>>,
    names: &'tally [String],
    found: BTreeSet<String>,
}

impl<'a> Visit<'a> for Updates<'_, 'a> {
    fn visit_update_expression(&mut self, update: &UpdateExpression<'a>) {
        if update.operator == UpdateOperator::Increment
            && let Some(member) = update.argument.as_member_expression()
            && let Expression::Identifier(object) = member.object()
            && self.aliases.contains(&self.script.binding(object))
            && let Some(field) = ast::member_str(member)
            && self.names.iter().any(|name| name == field)
        {
            self.found.insert(field.to_owned());
        }
        walk::walk_update_expression(self, update);
    }
}

/// Maps each individually tested event type to the counter incremented by its branch.
struct Handlers<'tally, 'a> {
    script: Script<'a>,
    aliases: &'tally BTreeSet<Binding<'a>>,
    names: &'tally [String],
    events: BTreeMap<String, String>,
}

impl<'a> Visit<'a> for Handlers<'_, 'a> {
    fn visit_if_statement(&mut self, branch: &IfStatement<'a>) {
        let events = ast::string_literals(|literals| literals.visit_expression(&branch.test))
            .into_iter()
            .filter(|text| COUNTED_EVENTS.contains(&text.as_str()));
        let mut updates = Updates {
            script: self.script,
            aliases: self.aliases,
            names: self.names,
            found: BTreeSet::new(),
        };
        updates.visit_statement(&branch.consequent);
        if let Ok(event) = candidates::exactly_one(events, "event type")
            && let Ok(field) = candidates::exactly_one(updates.found, "incremented field")
        {
            self.events.insert(event, field);
        }
        walk::walk_if_statement(self, branch);
    }
}

/// Finds the first interaction tally published as `<namespace>.<global> = {...}`. Accepts
/// direct assignment or assignment through a local.
pub(super) fn published_tally<'a>(script: Script<'a>, body: &FunctionBody<'a>) -> Option<Tally> {
    let mut built: Vec<BuiltObject> = Vec::new();
    for assignment in expression::assignments(body) {
        if expression::track(script, &mut built, assignment) {
            continue;
        }
        let counters = match &assignment.right {
            Expression::Identifier(ident) => {
                let local = script.binding(ident);
                built
                    .iter()
                    .rfind(|object| object.local == local)
                    .and_then(|object| zeroed(&object.fields))
            }
            right => expression::object_fields(right).as_deref().and_then(zeroed),
        };
        if let Some(member) = assignment.left.as_member_expression()
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
fn zeroed(fields: &[ObjectField<'_, '_>]) -> Option<Vec<String>> {
    if fields.len() < COUNTERS {
        return None;
    }
    fields
        .iter()
        .map(|field| {
            matches!(field.value, Expression::NumericLiteral(number) if number.value == 0.0)
                .then(|| field.key.to_owned())
        })
        .collect()
}
