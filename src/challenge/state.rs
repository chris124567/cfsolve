//! Recovers the script state the first payload reports: `Date.now()` marks, the interaction
//! tally ([`super::tally`]), the sender's additions and POST log, and the resource timing
//! format ([`super::reduced_timing`]).

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use swc_core::ecma::ast::{
    ArrowExpr, AssignExpr, AssignTarget, BinaryOp, CallExpr, Expr, Function, IfStmt, ObjectLit,
    SimpleAssignTarget, Stmt, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::candidates;
use crate::challenge::payload::Field;
use crate::challenge::reduced_timing::{self, ResourceTiming};
use crate::challenge::tally::{self, CounterEvents, Tally};
use crate::challenge::{expression, source};
use crate::js::ast::{self, ParsedScript};
use crate::js::{JsObject, JsValue, Options, Payload, json};
use crate::resource_timing::LoadTiming;

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
    pub post_log: Option<PostLog>,
}

/// Log of challenge POSTs. Each payload includes the log so far. The sender then adds an entry for
/// the current POST and records its response time when the response arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostLog {
    /// The option holding the log.
    pub option: String,
    /// Option containing the POST counter recorded in each entry.
    pub counter: String,
    /// Entry fields in insertion order, excluding the response time added later.
    pub fields: Vec<(String, Logged)>,
    /// The field holding the response time.
    pub answered: String,
}

/// Value recorded by a field in a POST log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logged {
    Url,
    Count,
    /// When the POST was sent.
    Sent,
}

impl PostLog {
    /// Initializes an empty log, matching the iframe before its first POST.
    pub(crate) fn start(&self, options: &mut Options) {
        options.insert(self.option.clone(), json!([]));
        options.insert(self.counter.clone(), json!(0));
    }

    /// Appends `post` to the log in `options`. Times are relative to `origin_ms`, the document
    /// navigation time in milliseconds since the Unix epoch.
    pub(crate) fn record(
        &self,
        options: &mut Options,
        post: &LoadTiming,
        origin_ms: i64,
    ) -> Result<()> {
        let count = options
            .get(&self.counter)
            .and_then(JsValue::as_i64)
            .unwrap_or(0)
            + 1;
        options.insert(self.counter.clone(), json!(count));
        let mut entry = JsObject::new();
        for (field, logged) in &self.fields {
            let value = match logged {
                Logged::Url => json!(post.url),
                Logged::Count => json!(count),
                Logged::Sent => json!((post.started_ms - origin_ms) as f64),
            };
            entry.insert(field.clone(), value);
        }
        entry.insert(
            self.answered.clone(),
            json!(post.ended_ms() - origin_ms as f64),
        );
        options
            .get_mut(&self.option)
            .and_then(JsValue::as_array_mut)
            .context("the session keeps no POST log")?
            .push(JsValue::Object(entry));
        Ok(())
    }
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
        let post_log = sender.post_log()?;
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
            post_log,
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

    /// Identifies the interval measured by `difference`, using `merged` as the marked option.
    /// Returns no interval if the script never marks the later timestamp.
    fn span(&self, difference: &Difference, merged: Option<&str>) -> Option<Span> {
        let Difference { later, earlier } = difference;
        if !self.marks.iter().any(|mark| &mark.option == later) {
            return None;
        }
        Some(if self.builds_payload(later) {
            Span::Collect
        } else if Some(earlier.as_str()) == merged {
            Span::Handoff
        } else {
            Span::Initialise
        })
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
        for difference in differences {
            let Some(span) = self.span(difference, merged) else {
                continue;
            };
            // The builder starts after the parameter merge. Other measured work overlaps the
            // handoff.
            let (start, duration) = match span {
                Span::Collect => (merged_at + intervals.handoff + 1, intervals.collect),
                Span::Handoff => (merged_at + 1, intervals.handoff),
                Span::Initialise => (merged_at + 1, intervals.initialise),
            };
            let start = *clock.entry(&difference.earlier).or_insert(start);
            clock.entry(&difference.later).or_insert(start + duration);
        }
        clock
            .into_iter()
            .map(|(option, when)| (option.to_owned(), JsValue::from(when)))
            .collect()
    }

    /// Recovers intervals from a captured first `payload` using its template `fields`. This
    /// reverses [`Self::timestamps`]. Uses the first difference that measures each interval; `send`
    /// is the sender's elapsed time.
    pub fn intervals(
        &self,
        fields: &[Field],
        merged: Option<&str>,
        payload: &Payload,
    ) -> Result<Intervals> {
        let (mut initialise, mut handoff, mut collect) = (None, None, None);
        for field in fields {
            let span = field
                .difference()
                .and_then(|difference| self.span(&difference, merged));
            let slot = match span {
                Some(Span::Initialise) => &mut initialise,
                Some(Span::Handoff) => &mut handoff,
                Some(Span::Collect) => &mut collect,
                None => continue,
            };
            if let Some(value) = payload.get(&field.name).and_then(JsValue::as_i64) {
                slot.get_or_insert(value);
            }
        }
        let send = self
            .elapsed
            .as_ref()
            .and_then(|elapsed| payload.get(&elapsed.key)?.as_i64());
        let reported = |interval: Option<i64>, name: &str| {
            interval.with_context(|| format!("the payload reports no {name} interval"))
        };
        Ok(Intervals {
            initialise: reported(initialise, "initialise")?,
            handoff: reported(handoff, "handoff")?,
            collect: reported(collect, "collect")?,
            send: reported(send, "send")?,
        })
    }
}

/// Interval measured by a timestamp difference in the first payload.
#[derive(Clone, Copy)]
enum Span {
    Initialise,
    Handoff,
    Collect,
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
    pushes: Vec<Push>,
    entries: Vec<LogEntry>,
    stamps: Vec<Stamp>,
}

/// A namespace getter named `function` that returns the option `option`.
struct Getter {
    function: String,
    option: String,
}

/// Matches `_cf_chl_opt.<log>.push(<local>)`.
struct Push {
    log: String,
    local: String,
}

/// Matches `<local>.<key> = <clock>()`.
struct Stamp {
    local: String,
    key: String,
}

impl Sender {
    fn within<N: VisitWith<Self>>(&mut self, node: &N) {
        self.entered += 1;
        self.scopes.push(self.entered);
        node.visit_children_with(self);
        self.scopes.pop();
    }

    /// Finds the log that receives an entry whose response time is assigned later.
    fn post_log(&self) -> Result<Option<PostLog>> {
        let logs = self.pushes.iter().filter_map(|push| {
            let entry = self
                .entries
                .iter()
                .find(|entry| entry.local == push.local)?;
            let answered = self.stamps.iter().find(|stamp| {
                stamp.local == push.local
                    && !entry.fields.iter().any(|(field, _)| *field == stamp.key)
            })?;
            Some(PostLog {
                option: push.log.clone(),
                counter: entry.counter.clone(),
                fields: entry.fields.clone(),
                answered: answered.key.clone(),
            })
        });
        candidates::at_most_one_distinct(logs, "POST log")
    }
}

/// Finds a local initialized with a POST log entry: `{ url: new URL(...).href, count:
/// _cf_chl_opt.<counter>, sent: clock() }`.
struct LogEntry {
    local: String,
    fields: Vec<(String, Logged)>,
    counter: String,
}

impl LogEntry {
    fn read(local: &str, value: &Expr) -> Option<Self> {
        let Expr::Object(object) = value.unwrap_parens() else {
            return None;
        };
        let mut fields = Vec::new();
        let mut counter = None;
        for property in ast::key_values(object) {
            let value = property.value.unwrap_parens();
            let logged = if let Some(option) = expression::option_key(value) {
                counter = Some(option.to_owned());
                Logged::Count
            } else if value.as_call().is_some_and(|call| call.args.is_empty()) {
                Logged::Sent
            } else if let Expr::Member(member) = value
                && ast::member_str(&member.prop) == Some("href")
                && member.obj.unwrap_parens().is_new()
            {
                Logged::Url
            } else {
                return None;
            };
            fields.push((ast::key_str(&property.key)?.to_owned(), logged));
        }
        let complete = fields.len() == 3
            && [Logged::Url, Logged::Count, Logged::Sent]
                .iter()
                .all(|logged| fields.iter().any(|(_, field)| field == logged));
        complete.then_some(Self {
            local: local.to_owned(),
            fields,
            counter: counter?,
        })
    }
}

impl Visit for Sender {
    fn visit_function(&mut self, function: &Function) {
        self.within(function);
    }

    fn visit_arrow_expr(&mut self, arrow: &ArrowExpr) {
        self.within(arrow);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Some(local) = declarator.name.as_ident()
            && let Some(init) = &declarator.init
            && let Some(entry) = LogEntry::read(&local.sym, init)
        {
            self.entries.push(entry);
        }
        declarator.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, call: &CallExpr) {
        // `_cf_chl_opt.<log>.push(<entry>)`
        if let Some(callee) = call.callee.as_expr().and_then(|callee| callee.as_member())
            && ast::member_str(&callee.prop) == Some("push")
            && let Some(option) = expression::option_key(&callee.obj)
            && let [entry] = &call.args[..]
            && let Some(local) = entry.expr.as_ident()
        {
            self.pushes.push(Push {
                log: option.to_owned(),
                local: local.sym.to_string(),
            });
        }
        call.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        let scope = self.scopes.last().copied().unwrap_or_default();
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(local)) = &assignment.left
            && let Some(entry) = LogEntry::read(&local.sym, &assignment.right)
        {
            self.entries.push(entry);
        }
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
                // `entry.<key> = clock()`
                Expr::Call(call)
                    if call.args.is_empty()
                        && let Some(local) = target.obj.as_ident() =>
                {
                    self.stamps.push(Stamp {
                        local: local.sym.to_string(),
                        key: key.to_owned(),
                    });
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
    use crate::challenge::payload;
    use crate::js::Window;

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

    /// Builds from 2026-10-27 onward log each POST and include the log in every payload.
    #[test]
    fn recovers_the_senders_post_log() {
        let source = r#"
            function send(url, payload, attempt) {
                var entry;
                payload.k = Date.now() - w._cf_chl_opt.m;
                payload.log = w._cf_chl_opt.log;
                if (attempt === 0) w._cf_chl_opt.n++;
                entry = { u: new URL(url, w.location.href).href, c: w._cf_chl_opt.n, s: clock() };
                w._cf_chl_opt.log.push(entry);
                function answered() { if (entry && entry.a === undefined) entry.a = clock(); }
            }"#;
        let script = ScriptState::from_javascript(source).unwrap();
        assert_eq!(script.forwarded, ["log"]);
        let log = script.post_log.unwrap();
        assert_eq!(
            [&log.option, &log.counter, &log.answered],
            ["log", "n", "a"]
        );
        let mut options = Options::new();
        log.start(&mut options);
        assert_eq!(options.get("log"), Some(&json!([])));
        let post = LoadTiming {
            url: "https://example.com/fo".into(),
            started_ms: 1_100,
            duration_ms: 250.0,
            waiting_ms: 0.0,
            receiving_ms: 0.0,
            body_bytes: 1,
        };
        log.record(&mut options, &post, 1_000).unwrap();
        assert_eq!(
            options.get("log"),
            Some(&json!([{"u": "https://example.com/fo", "c": 1, "s": 100.0, "a": 350.0}]))
        );
        assert_eq!(options.get("n"), Some(&json!(1)));
    }

    /// Building a payload from [`ScriptState::timestamps`] preserves the input intervals.
    #[test]
    fn reads_back_the_intervals_a_payload_reports() {
        let script = ScriptState {
            elapsed: Some(Elapsed {
                key: "sent".into(),
                mark: "zWnC9".into(),
            }),
            marks: [("dwQH2", false), ("WVhrW1", true), ("mrjlM3", false)]
                .map(|(option, in_builder)| Mark {
                    option: option.into(),
                    in_builder,
                })
                .to_vec(),
            ..ScriptState::default()
        };
        let pairs = [
            ("dwQH2", "pUyWp4"),
            ("WVhrW1", "gyhng3"),
            ("mrjlM3", "zWnC9"),
        ];
        let fields: Vec<Field> = pairs
            .iter()
            .enumerate()
            .map(|(index, (later, earlier))| {
                let text = format!("e._cf_chl_opt.{later} - e._cf_chl_opt.{earlier}");
                Field {
                    name: format!("f{index}"),
                    expression: ast::parse_expression("t", &text).unwrap(),
                    text,
                    bootstrap_value: None,
                }
            })
            .collect();
        let intervals = &Intervals {
            initialise: 15,
            handoff: 17,
            collect: 70,
            send: 123,
        };
        let differences = payload::differences(&fields);
        let clock = script.timestamps(&differences, Some("zWnC9"), 0, intervals);
        let mut built = payload::build(&fields, &clock, &Window::new()).unwrap();
        built.insert("sent".into(), json!(intervals.send));
        let read = script.intervals(&fields, Some("zWnC9"), &built).unwrap();
        assert_eq!(
            [read.initialise, read.handoff, read.collect, read.send],
            [
                intervals.initialise,
                intervals.handoff,
                intervals.collect,
                intervals.send
            ]
        );
        built.shift_remove("sent");
        let error = script
            .intervals(&fields, Some("zWnC9"), &built)
            .unwrap_err();
        assert!(error.to_string().contains("no send interval"), "{error}");
    }
}
