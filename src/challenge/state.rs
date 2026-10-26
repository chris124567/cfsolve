//! Recovers the script state the first payload reports: `Date.now()` marks, the interaction
//! tally ([`super::tally`]), the sender's additions, and the resource timing format
//! ([`super::reduced_timing`]).

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use swc_core::ecma::ast::{
    ArrowExpr, AssignExpr, AssignTarget, BinaryOp, Expr, Function, IfStmt, ObjectLit,
    SimpleAssignTarget, Stmt,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::candidates;
use crate::challenge::reduced_timing::{self, ResourceTiming};
use crate::challenge::tally::{self, CounterEvents, Tally};
use crate::challenge::{expression, source};
use crate::js::ast::{self, ParsedScript};
use crate::js::{JsValue, Options};

/// Script state reported in the first payload.
#[derive(Debug, Default)]
pub struct ScriptState {
    /// Options assigned `Date.now()`.
    pub marks: Vec<Mark>,
    pub counters: Option<Tally>,
    /// Recovered event mapping for the interaction tally. Keeps any recovery error until
    /// interaction code requests the mapping.
    pub counter_events: Option<Result<CounterEvents>>,
    /// The time the sender reports just before it encodes.
    pub elapsed: Option<Elapsed>,
    /// Options copied into the payload under their original names at send time.
    pub forwarded: Vec<String>,
    pub timing: Option<ResourceTiming>,
    /// Functions on the script's namespace, mapped to the option each returns.
    pub getters: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub option: String,
    /// Whether the assignment is inside the function that builds the payload.
    pub in_builder: bool,
}

/// An elapsed-time field appended by the sender before encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elapsed {
    pub key: String,
    /// The option holding the mark it measures from.
    pub mark: String,
}

/// A timestamp pair reported as `later - earlier`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    pub later: String,
    pub earlier: String,
}

/// Durations reported in the first payload, loaded from the fingerprint's `intervals` section.
/// These come from a browser capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intervals {
    /// Time between the two startup timestamps.
    #[serde(deserialize_with = "unsigned")]
    pub initialise: i64,
    /// Time between merging the page's parameters and entering the payload builder.
    #[serde(deserialize_with = "unsigned")]
    pub handoff: i64,
    /// Time spent building the payload.
    #[serde(deserialize_with = "unsigned")]
    pub collect: i64,
    /// Time from entering the payload builder to sending, reported by the sender.
    #[serde(deserialize_with = "unsigned")]
    pub send: i64,
}

/// Widens an unsigned duration for clock arithmetic.
fn unsigned<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    u32::deserialize(deserializer).map(i64::from)
}

impl ScriptState {
    #[cfg(test)]
    pub(crate) fn from_javascript(javascript: &str) -> Result<Self> {
        let parsed = ast::parse_iframe_javascript(javascript)?;
        Self::from_parsed(&parsed, &source::bootstrap_options(&parsed))
    }

    /// Recovers the state of a parsed script, using bootstrap options to identify its payload
    /// template.
    pub(crate) fn from_parsed(parsed: &ParsedScript, options: &Options) -> Result<Self> {
        let script = &parsed.script;
        let mut scopes = Scopes {
            options,
            stack: Vec::new(),
            found: Vec::new(),
        };
        script.visit_with(&mut scopes);
        let mut sender = Sender::default();
        script.visit_with(&mut sender);
        let elapsed = candidates::at_most_one_distinct(sender.elapsed, "elapsed-time field")?;
        let sender_scope = elapsed.as_ref().map(|(scope, _)| *scope);
        // The sender forwards option values directly. Another function copies collected
        // resource timings into the payload.
        let (forwarded, collected): (Vec<_>, Vec<_>) = sender
            .copies
            .into_iter()
            .partition(|(scope, _)| Some(*scope) == sender_scope);
        let collected = candidates::at_most_one_distinct(
            collected.into_iter().map(|(_, key)| key),
            "collected resource timing option",
        )?;
        let tallies = ast::in_declared_functions(script, |function| {
            tally::published_tally(function.function.body.as_ref()?)
        });
        let counters = candidates::at_most_one_distinct(tallies, "interaction tally")?;
        let timing = match collected {
            Some(option) => {
                let reductions = ast::in_declared_functions(script, |function| {
                    reduced_timing::reduction(function.function.body.as_ref()?)
                });
                candidates::at_most_one_distinct(reductions, "resource timing reducer")?
                    .map(|fields| ResourceTiming { option, fields })
            }
            None => None,
        };
        let counter_events = counters
            .as_ref()
            .map(|tally| CounterEvents::recover(script, tally));
        Ok(Self {
            marks: scopes.found,
            counters,
            counter_events,
            elapsed: elapsed.map(|(_, elapsed)| elapsed),
            forwarded: forwarded.into_iter().map(|(_, key)| key).collect(),
            timing,
            getters: distinct_getters(sender.getters)?,
        })
    }

    /// Returns the event-to-counter mapping, or the error preventing native tally updates.
    pub fn counter_events(&self) -> Result<&CounterEvents> {
        let reason = match &self.counter_events {
            Some(Ok(counters)) => return Ok(counters),
            Some(Err(error)) => format!("{error:#}"),
            None => "it keeps no tally".to_owned(),
        };
        bail!("could not recover the iframe's input event counters: {reason}")
    }

    fn builds_payload(&self, option: &str) -> bool {
        self.marks
            .iter()
            .any(|mark| mark.option == option && mark.in_builder)
    }

    /// Assigns timestamps to match configured durations. Skips timestamps unused in
    /// differences. Keeps the first value assigned to each timestamp, even if a later duration
    /// constraint conflicts.
    #[must_use]
    pub fn timestamps(
        &self,
        differences: &[Difference],
        merged: Option<&str>,
        merged_at: i64,
        intervals: &Intervals,
    ) -> Options {
        let mut clock: IndexMap<&str, i64> = IndexMap::new();
        if let Some(merged) = merged {
            clock.insert(merged, merged_at);
        }
        for Difference { later, earlier } in differences {
            if !self.marks.iter().any(|mark| &mark.option == later) {
                continue;
            }
            // The builder starts after the parameter merge. Other measured work overlaps the
            // handoff.
            let (start, duration) = if self.builds_payload(later) {
                (merged_at + intervals.handoff + 1, intervals.collect)
            } else if Some(earlier.as_str()) == merged {
                (merged_at + 1, intervals.handoff)
            } else {
                (merged_at + 1, intervals.initialise)
            };
            let start = *clock.entry(earlier).or_insert(start);
            clock.entry(later).or_insert(start + duration);
        }
        clock
            .into_iter()
            .map(|(option, when)| (option.to_owned(), JsValue::from(when)))
            .collect()
    }
}

/// Groups timestamps by their innermost function and finds the function containing the payload
/// template. A template in a nested callback may subtract timestamps set by different
/// functions.
struct Scopes<'options> {
    options: &'options Options,
    /// The enclosing functions, innermost last.
    stack: Vec<Scope>,
    found: Vec<Mark>,
}

/// One function's timestamp options, and whether it holds the payload template.
#[derive(Default)]
struct Scope {
    marks: Vec<String>,
    builds_payload: bool,
}

impl Scopes<'_> {
    fn within<N: VisitWith<Self>>(&mut self, node: &N) {
        self.stack.push(Scope::default());
        node.visit_children_with(self);
        let scope = self.stack.pop().expect("entered a scope first");
        let marks = scope.marks.into_iter().map(|option| Mark {
            option,
            in_builder: scope.builds_payload,
        });
        self.found.extend(marks);
    }
}

impl Visit for Scopes<'_> {
    fn visit_function(&mut self, function: &Function) {
        self.within(function);
    }

    fn visit_arrow_expr(&mut self, arrow: &ArrowExpr) {
        self.within(arrow);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let Some(option) = expression::option_assignment(&assignment.left)
            && ast::is_date_now(&assignment.right)
            && let Some(scope) = self.stack.last_mut()
        {
            scope.marks.push(option.to_owned());
        }
        assignment.visit_children_with(self);
    }

    fn visit_if_stmt(&mut self, conditional: &IfStmt) {
        let options = self.options;
        source::visit_taken_branches(self, conditional, options);
    }

    fn visit_object_lit(&mut self, object: &ObjectLit) {
        if source::is_payload_template(object, self.options)
            && let Some(scope) = self.stack.last_mut()
        {
            scope.builds_payload = true;
        }
        object.visit_children_with(self);
    }
}

/// Finds property writes that add payload fields or install namespace getters. Records the
/// enclosing function for each write.
#[derive(Default)]
struct Sender {
    entered: usize,
    scopes: Vec<usize>,
    elapsed: Vec<(usize, Elapsed)>,
    copies: Vec<(usize, String)>,
    getters: Vec<Getter>,
}

/// A namespace getter named `function` that returns the option `option`.
struct Getter {
    function: String,
    option: String,
}

impl Sender {
    fn within<N: VisitWith<Self>>(&mut self, node: &N) {
        self.entered += 1;
        self.scopes.push(self.entered);
        node.visit_children_with(self);
        self.scopes.pop();
    }
}

impl Visit for Sender {
    fn visit_function(&mut self, function: &Function) {
        self.within(function);
    }

    fn visit_arrow_expr(&mut self, arrow: &ArrowExpr) {
        self.within(arrow);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        let scope = self.scopes.last().copied().unwrap_or_default();
        if let AssignTarget::Simple(SimpleAssignTarget::Member(target)) = &assignment.left
            && let Some(key) = ast::ident_property(target)
        {
            match &*assignment.right {
                // `payload.<key> = Date.now() - _cf_chl_opt.<mark>`
                Expr::Bin(binary)
                    if binary.op == BinaryOp::Sub
                        && ast::is_date_now(&binary.left)
                        && let Some(mark) = expression::option_key(&binary.right) =>
                {
                    let elapsed = Elapsed {
                        key: key.to_owned(),
                        mark: mark.to_owned(),
                    };
                    self.elapsed.push((scope, elapsed));
                }
                // `<namespace>.<key> = function () { var ...; local = _cf_chl_opt.<option>; ... }`
                Expr::Fn(getter)
                    if let Some(body) = &getter.function.body
                        && let Some(first) = body.stmts.iter().find_map(Stmt::as_expr)
                        && let Expr::Assign(first) = &*first.expr
                        && let Some(option) = expression::option_key(&first.right) =>
                {
                    self.getters.push(Getter {
                        function: key.to_owned(),
                        option: option.to_owned(),
                    });
                }
                // `payload.<key> = _cf_chl_opt.<key>`
                right if expression::option_key(right) == Some(key) => {
                    self.copies.push((scope, key.to_owned()));
                }
                _ => {}
            }
        }
        assignment.visit_children_with(self);
    }
}

/// Rejects a getter name that returns different options.
fn distinct_getters(getters: Vec<Getter>) -> Result<BTreeMap<String, String>> {
    let mut distinct = BTreeMap::new();
    for Getter { function, option } in getters {
        let previous = distinct.entry(function.clone()).or_insert(option.clone());
        ensure!(
            *previous == option,
            "getter {function} reads both {previous} and {option}"
        );
    }
    Ok(distinct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_senders_that_disagree_about_the_elapsed_field() {
        let source = r#"
            function s1() { p.k = Date.now() - e._cf_chl_opt.m1; }
            function s2() { p.j = Date.now() - e._cf_chl_opt.m2; }"#;
        let error = ScriptState::from_javascript(source)
            .unwrap_err()
            .to_string();
        assert!(error.contains("conflicting elapsed-time field"), "{error}");
        let source =
            r#"function s1() { p.k = Date.now() - e._cf_chl_opt.m1; p.f = e._cf_chl_opt.f; }"#;
        let script = ScriptState::from_javascript(source).unwrap();
        assert_eq!(
            script.elapsed,
            Some(Elapsed {
                key: "k".into(),
                mark: "m1".into(),
            })
        );
        assert_eq!(script.forwarded, ["f"]);
    }

    /// Checks timestamp assignment with the tracked profile's 7 ms between startup timestamps.
    /// Assigned timestamps keep their first value.
    #[test]
    fn places_marks_so_every_reported_difference_matches_its_interval() {
        let script = ScriptState {
            marks: vec![Mark {
                option: "b".into(),
                in_builder: false,
            }],
            ..ScriptState::default()
        };
        let differences = [("b", "a"), ("b", "merged")].map(|(later, earlier)| Difference {
            later: later.into(),
            earlier: earlier.into(),
        });
        let intervals = &crate::browser::Browser::safari().page.intervals;
        let at = script.timestamps(&differences, Some("merged"), 0, intervals);
        assert_eq!(JsValue::from(at).to_string(), r#"{"merged":0,"a":1,"b":8}"#);
    }
}
