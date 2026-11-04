//! Analyzes response programs used by the challenge-page orchestrator.
//!
//! The first response renders a Turnstile widget and prepares a second payload containing
//! session state, one widget-outcome record, and literal footer fields. On a precursor
//! interstitial, it loads the precursor script instead, and its record reports that script's
//! completion. The next response submits a form to obtain clearance.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use swc_core::ecma::ast::BinaryOp;
use url::Url;

use crate::candidates;
use crate::js::{JsObject, JsValue, Options, Payload, Window, json};
use crate::listing::fold::DECODER_CELL;
use crate::listing::query::Store;
use crate::listing::{self, Index};
use crate::stage2::call_stack::MethodCall;
use crate::stage2::payload::{
    self, Document, Environment, Expression, Layout, RecordTemplate, Recovered, Scope, State,
};
use crate::vm::{Constant, Effect, Listing, Term};

/// Widget parameters passed to `turnstile.render`, excluding callbacks.
const RENDER_PARAMETERS: [&str; 8] = [
    "sitekey",
    "theme",
    "action",
    "cData",
    "chlPageData",
    "retry",
    "refresh-expired",
    "refresh-timeout",
];

fn literal(value: JsValue) -> Expression {
    Expression::Literal { value }
}

/// Evaluates a program value using only orchestrator options and window globals.
fn resolve(expression: &Expression, options: &Options, window: &Window) -> Result<Option<JsValue>> {
    let (calls, input) = (Window::new(), Payload::new());
    let state = State {
        environment: Environment {
            options,
            window,
            calls: &calls,
        },
        input: &input,
    };
    expression.evaluate(&state)
}

/// Payload sent after the widget settles.
#[derive(Debug)]
pub(crate) struct WidgetProgram {
    /// The record counter, which the template starts at zero.
    pub counter: String,
    pub layout: Layout,
    /// The record the program adds, with its literal token and input.
    pub record: RecordTemplate,
    /// How the record reports the widget's end.
    pub outcome: SettledFields,
    /// `turnstile.render`'s parameters, by name.
    pub render: IndexMap<String, Expression>,
    /// The VM call to `turnstile.render`, used to reconstruct the loader's stack sample.
    pub render_call: MethodCall,
    /// Window globals the program sets to literals of its own.
    pub window: Window,
    /// Payload field receiving the iframe's `aC` through `api.js`'s optional `_acCb` callback.
    pub after_challenge: Option<String>,
}

/// How the widget settled, as its callbacks reported it.
#[derive(Debug, Clone)]
pub(crate) struct Settled {
    pub token: String,
    /// The iframe's `aC`, which `api.js` hands `_acCb`.
    pub after_challenge: Option<String>,
    /// When the program created its record, and when the widget settled, in epoch milliseconds.
    pub started_ms: i64,
    pub ended_ms: i64,
}

/// Record fields written by the widget's completion callbacks.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SettledFields {
    /// Receives the widget's token on success, and `""` otherwise.
    pub token: String,
    /// `""` on success, otherwise why the widget stopped.
    pub status: String,
    /// Fields written by the shared callback-finishing function, in order.
    pub finish: Vec<(String, JsValue)>,
    /// Copied start time, end time, and duration fields. The original start field is cleared
    /// before sending.
    pub started: String,
    pub ended: String,
    pub duration: String,
}

impl WidgetProgram {
    pub(crate) fn recover(listing: &Listing) -> Result<Self> {
        ensure!(
            listing.failures.is_empty(),
            "widget program has undecoded instructions"
        );
        let index = Index::new(listing);
        let Recovered {
            pool,
            counter,
            layout,
            record,
            ..
        } = payload::recover_unique(&index, "widget program")?;
        let reader = Reader {
            index: &index,
            pool,
        };
        let window = reader.window_literals();
        let (render, callbacks) = reader.render()?;
        let render_call = reader.render_call()?;
        let outcome = reader.outcome(&callbacks, &record.started_field)?;
        let after_challenge = callbacks.get("_acCb").and_then(|&entry| {
            reader
                .stores_in(reader.index.function_at(entry))
                .next()
                .map(|store| store.key.clone())
        });
        Ok(Self {
            counter,
            layout,
            record,
            outcome,
            render,
            render_call,
            window,
            after_challenge,
        })
    }

    /// Builds the payload passed to the orchestrator sender after widget success, before sender
    /// fields are appended. `state` uses the orchestrator's first payload as input.
    pub(crate) fn payload(&self, state: &State<'_>, settled: &Settled) -> Result<Payload> {
        ensure!(
            self.layout
                .published
                .iter()
                .all(|(_, value)| value.is_some()),
            "widget program publishes a field only a browser computes"
        );
        let outcome = &self.outcome;
        // Preserve first-write order: literals, state moved by the finishing function, callback
        // result, then closing timestamps.
        let mut written = JsObject::from_iter(outcome.finish.iter().cloned());
        written.insert(outcome.token.clone(), json!(settled.token));
        written.insert(outcome.status.clone(), json!(""));
        let closing = Closing {
            started: &outcome.started,
            ended: &outcome.ended,
            duration: &outcome.duration,
        };
        let records = closing.records(&self.record, written, settled.started_ms, settled.ended_ms);
        let mut extra = JsObject::new();
        if let (Some(field), Some(value)) = (&self.after_challenge, &settled.after_challenge) {
            extra.insert(field.clone(), json!(value));
        }
        self.layout.assemble(
            state,
            &Document::default(),
            records,
            &self.counter,
            extra,
            None,
        )
    }

    pub(crate) fn render_parameters(&self, options: &Options, window: &Window) -> Result<JsObject> {
        self.render
            .iter()
            .map(|(name, expression)| {
                let value = resolve(expression, options, window)?
                    .with_context(|| format!("render parameter {name} has no value"))?;
                Ok((name.clone(), value))
            })
            .collect()
    }
}

/// Whether a first response program renders a widget, by writing its `sitekey`. A precursor
/// interstitial's program loads the precursor script instead.
#[must_use]
pub(crate) fn renders_widget(listing: &Listing) -> bool {
    let index = Index::new(listing);
    index.stores().iter().any(|store| store.key == "sitekey")
}

/// A precursor interstitial's first response program. It loads Cloudflare's precursor script
/// into the page, handing it a callback on `window._cf_chl_opt`, and sends its second payload
/// once the script has run and called back.
#[derive(Debug)]
pub(crate) struct PrecursorProgram {
    /// The record counter, which the template starts at zero.
    pub counter: String,
    pub layout: Layout,
    /// The record the program adds, with its literal token and input.
    pub record: RecordTemplate,
    /// The script's address, as the parts the program concatenates.
    pub script: Vec<Expression>,
    /// The record's status and message, as the callback writes them, in order.
    pub finish: Vec<(String, JsValue)>,
    /// Copied start time, end time, and duration fields. The original start field is cleared
    /// before sending.
    pub started: String,
    pub ended: String,
    pub duration: String,
    /// Window globals the program sets to literals of its own.
    pub window: Window,
}

impl PrecursorProgram {
    pub(crate) fn recover(listing: &Listing) -> Result<Self> {
        ensure!(
            listing.failures.is_empty(),
            "precursor program has undecoded instructions"
        );
        let index = Index::new(listing);
        let Recovered {
            pool,
            counter,
            layout,
            record,
            ..
        } = payload::recover_unique(&index, "precursor program")?;
        let reader = Reader {
            index: &index,
            pool,
        };
        // The script element's `src`; the program's other elements are a sandbox iframe and
        // workers, which it gives no address.
        let script = candidates::exactly_one(
            index
                .stores()
                .iter()
                .filter(|store| store.key == "src")
                .filter_map(|store| reader.concatenation(store.pc, &store.value)),
            "precursor script address",
        )?;
        let callback = candidates::exactly_one(reader.option_callbacks(), "precursor callback")?;
        let finish = reader
            .stores_in(index.function_at(callback))
            .filter_map(|store| match reader.origin(store.pc, &store.value)? {
                Expression::Literal { value } => Some((store.key.clone(), value)),
                _ => None,
            })
            .collect();
        let [started, ended, duration] = reader
            .closing(&record.started_field)?
            .map(|store| store.key.clone());
        Ok(Self {
            counter,
            layout,
            record,
            script,
            finish,
            started,
            ended,
            duration,
            window: reader.window_literals(),
        })
    }

    /// The precursor script's address on `page`.
    pub(crate) fn script_url(&self, options: &Options, window: &Window, page: &Url) -> Result<Url> {
        let mut path = String::new();
        for part in &self.script {
            let value = resolve(part, options, window)?;
            let text = value
                .as_ref()
                .and_then(JsValue::as_str)
                .with_context(|| format!("precursor script address part {part:?} is not text"))?;
            path.push_str(text);
        }
        Ok(page.join(&path)?)
    }

    /// Builds the payload passed to the orchestrator sender once the script has called back,
    /// before sender fields are appended. `state` uses the orchestrator's first payload as
    /// input.
    pub(crate) fn payload(
        &self,
        state: &State<'_>,
        started_ms: i64,
        ended_ms: i64,
    ) -> Result<Payload> {
        ensure!(
            self.layout
                .published
                .iter()
                .all(|(_, value)| value.is_some()),
            "precursor program publishes a field only a browser computes"
        );
        let closing = Closing {
            started: &self.started,
            ended: &self.ended,
            duration: &self.duration,
        };
        let written = JsObject::from_iter(self.finish.iter().cloned());
        let records = closing.records(&self.record, written, started_ms, ended_ms);
        self.layout.assemble(
            state,
            &Document::default(),
            records,
            &self.counter,
            JsObject::new(),
            None,
        )
    }
}

/// The fields that close a program's record: a copy of its start, its end, and the time
/// between.
struct Closing<'field> {
    started: &'field str,
    ended: &'field str,
    duration: &'field str,
}

impl Closing<'_> {
    /// The payload's numbered records: `record`'s literals, the fields `written` while it was
    /// open, then the closing timestamps. The original start is cleared before sending, so it
    /// is left out.
    fn records(
        &self,
        record: &RecordTemplate,
        written: JsObject,
        started_ms: i64,
        ended_ms: i64,
    ) -> JsObject {
        let mut fields = JsObject::new();
        fields.insert(record.token_field.clone(), json!(record.token));
        fields.insert(record.input_field.clone(), record.input.clone());
        fields.extend(written);
        fields.insert(self.started.to_owned(), json!(started_ms));
        fields.insert(self.ended.to_owned(), json!(ended_ms));
        fields.insert(self.duration.to_owned(), json!(ended_ms - started_ms));
        // This record is the first numbered entry.
        JsObject::from_iter([("1".to_owned(), JsValue::Object(fields))])
    }
}

/// Resolves values within a single listing.
struct Reader<'listing> {
    index: &'listing Index<'listing>,
    pool: &'listing str,
}

impl Reader<'_> {
    fn stores_in(&self, range: Range<u32>) -> impl Iterator<Item = &Store> {
        self.index
            .stores()
            .iter()
            .filter(move |store| range.contains(&store.pc))
    }

    /// Checks whether `term` holds the global object's `window` property at `pc`.
    fn is_window(&self, pc: u32, term: &Term) -> bool {
        let global = self.index.global();
        matches!(self.index.dereference(pc, term), Some((at, Term::Get(object, key)))
            if matches!(*object, Term::Reg(register) if Some(register) == global)
                && self.index.text(at, &key).as_deref() == Some("window"))
    }

    /// Where `term`'s value at `pc` comes from: a literal, decoded literal, option, or global.
    fn origin(&self, pc: u32, term: &Term) -> Option<Expression> {
        let read = |scope, name| Expression::Read {
            scope,
            path: vec![name],
        };
        if let Some(name) = self.index.option_read(pc, term) {
            return Some(read(Scope::Options, name));
        }
        let (at, value) = self.index.dereference(pc, term)?;
        Some(match value {
            Term::Const(Constant::String(text)) => literal(json!(text)),
            Term::Const(Constant::Bool(value)) => literal(json!(value)),
            Term::Const(Constant::Number(value)) => literal(json!(value)),
            // The program's string decoder, which it keeps in `DECODER_CELL`.
            Term::Call {
                callee, arguments, ..
            } if matches!(
                self.index.dereference(at, &callee),
                Some((_, Term::Cell(DECODER_CELL)))
            ) =>
            {
                let descriptor = self.index.text(at, arguments.first()?)?;
                literal(json!(listing::decode_string(&descriptor, self.pool).ok()?))
            }
            Term::Get(object, key) if self.is_window(at, &object) => {
                read(Scope::Window, self.index.text(at, &key)?)
            }
            _ => return None,
        })
    }

    /// The parts of a string `term` concatenates at `pc` with `+`, each resolved by
    /// [`Self::origin`].
    fn concatenation(&self, pc: u32, term: &Term) -> Option<Vec<Expression>> {
        if let Some((at, Term::Binary(BinaryOp::Add, left, right))) =
            self.index.dereference(pc, term)
        {
            let mut parts = self.concatenation(at, &left)?;
            parts.extend(self.concatenation(at, &right)?);
            return Some(parts);
        }
        Some(vec![self.origin(pc, term)?])
    }

    /// Entry points of the program functions stored on `window._cf_chl_opt`, directly or
    /// through cells, for another script to call.
    fn option_callbacks(&self) -> BTreeSet<u32> {
        let mut entries = BTreeSet::new();
        for store in self.index.stores() {
            let on_options = self.index.holds_options(store.pc, &Term::Reg(store.object));
            match self.index.dereference(store.pc, &store.value) {
                Some((_, Term::Closure { pc, .. })) if on_options => {
                    entries.insert(pc);
                }
                Some((_, Term::Cell(cell))) if on_options => entries.extend(self.closures_in(cell)),
                _ => {}
            }
        }
        entries
    }

    fn window_literals(&self) -> Window {
        let mut window = Window::new();
        for store in self.index.stores() {
            if self.is_window(store.pc, &Term::Reg(store.object))
                && let Some(Expression::Literal { value }) = self.origin(store.pc, &store.value)
            {
                window.insert(store.key.clone(), value);
            }
        }
        window
    }

    /// The widget parameters stored beside `sitekey`, and the callbacks' entry points, by name.
    fn render(&self) -> Result<(IndexMap<String, Expression>, BTreeMap<String, u32>)> {
        let sitekey = self
            .index
            .stores()
            .iter()
            .find(|store| store.key == "sitekey")
            .context("widget program renders no widget")?;
        let mut parameters = IndexMap::new();
        let mut callbacks = BTreeMap::new();
        for store in self.stores_in(self.index.function_at(sitekey.pc)) {
            if let Some((_, Term::Closure { pc, .. })) =
                self.index.dereference(store.pc, &store.value)
            {
                callbacks.insert(store.key.clone(), pc);
                continue;
            }
            if !RENDER_PARAMETERS.contains(&store.key.as_str()) {
                continue;
            }
            // The program checks the dark-mode preference; the emulated page prefers light, as
            // headless Chromium does.
            let origin = if store.key == "theme" {
                literal(json!("light"))
            } else {
                self.origin(store.pc, &store.value)
                    .with_context(|| format!("render parameter {} has no known value", store.key))?
            };
            parameters.insert(store.key.clone(), origin);
        }
        ensure!(
            parameters.contains_key("sitekey"),
            "render parameters name no sitekey"
        );
        Ok((parameters, callbacks))
    }

    /// The program's one call of a `render` method.
    fn render_call(&self) -> Result<MethodCall> {
        let index = self.index;
        // Each of an instruction's paths may make the call.
        let mut calls: BTreeSet<(u32, usize)> = BTreeSet::new();
        for (pc, effect) in index.effects_in(..) {
            if let Some((callee, arguments)) = effect.call()
                && index.method(pc, callee).as_deref() == Some("render")
            {
                calls.insert((pc, arguments.len()));
            }
        }
        let (pc, passed) = candidates::exactly_one(calls, "turnstile.render call")?;
        let function = index
            .entry_at_or_before(pc)
            .context("the render call is in no function")?;
        let arity = index
            .arity(function)
            .context("the function calling render is no closure")?;
        Ok(MethodCall {
            opcode: index.listing().instructions[&pc].opcode,
            passed,
            arity,
        })
    }

    /// Recovers outcome fields from callbacks. Expiry writes `"expired"` and clears the token;
    /// success writes the token. Both call shared finishing functions.
    fn outcome(&self, callbacks: &BTreeMap<String, u32>, started: &str) -> Result<SettledFields> {
        let entry = |name: &str| {
            callbacks
                .get(name)
                .copied()
                .with_context(|| format!("widget is rendered without its {name}"))
        };
        let expired: Vec<&Store> = self
            .stores_in(self.index.function_at(entry("expired-callback")?))
            .collect();
        let status = expired
            .iter()
            .find(|store| self.origin(store.pc, &store.value) == Some(literal(json!("expired"))))
            .context("expiry callback writes no status")?
            .key
            .clone();
        let token = expired
            .iter()
            .find(|store| store.key != status)
            .context("expiry callback clears no token")?
            .key
            .clone();
        let success = self.index.function_at(entry("callback")?);
        ensure!(
            self.stores_in(success.clone())
                .any(|store| store.key == token),
            "success callback writes no token"
        );
        let mut finish = Vec::new();
        for function in self.called_functions(success) {
            for store in self.stores_in(self.index.function_at(function)) {
                if store.key == token || store.key == status {
                    continue;
                }
                if let Some(Expression::Literal { value }) = self.origin(store.pc, &store.value) {
                    finish.push((store.key.clone(), value));
                }
            }
        }
        let [started, ended, duration] = self.closing(started)?.map(|store| store.key.clone());
        Ok(SettledFields {
            token,
            status,
            finish,
            started,
            ended,
            duration,
        })
    }

    /// Returns entry points of program functions called through cells.
    fn called_functions(&self, range: Range<u32>) -> Vec<u32> {
        let mut cells = Vec::new();
        for (_, effect) in self.index.effects_in(range) {
            effect.visit_terms(&mut |term| {
                if let Term::Call { callee, .. } = term
                    && let Term::Cell(cell) = **callee
                    && !cells.contains(&cell)
                {
                    cells.push(cell);
                }
            });
        }
        let mut entries = Vec::new();
        for cell in cells {
            for entry in self.closures_in(cell) {
                if !entries.contains(&entry) {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    /// Entry points of the program functions stored in `cell`, in program order.
    fn closures_in(&self, cell: u32) -> impl Iterator<Item = u32> {
        self.index
            .effects_in(..)
            .filter_map(move |(pc, effect)| match effect {
                Effect::SetCell(target, value) if *target == cell => {
                    match self.index.dereference(pc, value) {
                        Some((_, Term::Closure { pc: entry, .. })) => Some(entry),
                        _ => None,
                    }
                }
                _ => None,
            })
    }

    /// The closing writes: a copy of the start, the end, and end minus start. The original start
    /// is cleared afterward.
    fn closing(&self, started: &str) -> Result<[&Store; 3]> {
        let stores = self.index.stores();
        let copy = stores
            .iter()
            .position(|store| self.index.reads(store.pc, &store.value, started))
            .context("record's start is never copied")?;
        let closing: Vec<&Store> = stores[copy..].iter().collect();
        let marks = self.index.clock_marks(&closing)?;
        ensure!(
            marks[0].pc == stores[copy].pc,
            "record's duration does not start at its copied start"
        );
        Ok(marks)
    }
}

/// The iframe's `aC`, which `api.js` hands the widget's `_acCb` with the completion token.
#[must_use]
pub(crate) fn completion_extra(listing: &Listing) -> Option<String> {
    let index = Index::new(listing);
    let store = index.stores().iter().find(|store| store.key == "aC")?;
    index.text(store.pc, &store.value)
}

/// The form the clearance program submits.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Form {
    pub action: Expression,
    pub method: String,
    pub enctype: String,
    /// Each input's name and value, in order.
    pub fields: Vec<(String, Expression)>,
}

impl Form {
    /// Reads form attributes from `setAttribute` calls in program order: `action`, `method`,
    /// `enctype`, then each input's `name` and `value`.
    pub(crate) fn recover(listing: &Listing) -> Result<Self> {
        ensure!(
            listing.failures.is_empty(),
            "clearance program has undecoded instructions"
        );
        let index = Index::new(listing);
        let (_, pool) = index
            .pool()
            .context("clearance program has no string pool")?;
        let reader = Reader {
            index: &index,
            pool,
        };
        let mut attributes: Vec<(String, Expression)> = Vec::new();
        for (&pc, instruction) in &listing.instructions {
            let mut set = None;
            for effect in instruction.effects() {
                effect.visit_terms(&mut |term| {
                    if set.is_none()
                        && let Term::Call {
                            callee, arguments, ..
                        } = term
                        && let [name, value] = arguments.as_slice()
                        && index.method(pc, callee).as_deref() == Some("setAttribute")
                        && let Some(name) = index.text(pc, name)
                        && let Some(value) = reader.origin(pc, value)
                    {
                        set = Some((name, value));
                    }
                });
            }
            attributes.extend(set);
        }
        let attribute = |name: &str| {
            attributes
                .iter()
                .find(|(attribute, _)| attribute == name)
                .map(|(_, value)| value.clone())
                .with_context(|| format!("clearance form sets no {name}"))
        };
        let literal = |name: &str| -> Result<String> {
            match attribute(name)? {
                Expression::Literal {
                    value: JsValue::String(text),
                } => Ok(text),
                other => bail!("clearance form's {name} is not a literal: {other:?}"),
            }
        };
        let mut fields = Vec::new();
        let mut pending = None;
        for (name, value) in &attributes {
            match name.as_str() {
                "name" => {
                    let Expression::Literal {
                        value: JsValue::String(input),
                    } = value
                    else {
                        bail!("clearance form input has no literal name");
                    };
                    pending = Some(input.clone());
                }
                "value" => {
                    let input = pending.take().context("clearance form input has no name")?;
                    fields.push((input, value.clone()));
                }
                _ => {}
            }
        }
        ensure!(!fields.is_empty(), "clearance form has no inputs");
        Ok(Self {
            action: attribute("action")?,
            method: literal("method")?,
            enctype: literal("enctype")?,
            fields,
        })
    }

    /// Resolves the action against `page` and the values against the orchestrator's state.
    /// Supports only URL-encoded POST forms.
    pub(crate) fn resolve(
        &self,
        options: &Options,
        window: &Window,
        page: &Url,
    ) -> Result<ResolvedForm> {
        let text = |value: &Expression| -> Result<String> {
            resolve(value, options, window)?
                .and_then(|value| value.as_str().map(str::to_owned))
                .with_context(|| format!("clearance form value {value:?} is not text"))
        };
        let action = page.join(&text(&self.action)?)?;
        let fields: Vec<(String, String)> = self
            .fields
            .iter()
            .map(|(name, value)| Ok((name.clone(), text(value)?)))
            .collect::<Result<_>>()?;
        ensure!(
            self.method.eq_ignore_ascii_case("post")
                && self.enctype == "application/x-www-form-urlencoded",
            "clearance form is not a URL-encoded POST"
        );
        Ok(ResolvedForm { action, fields })
    }
}

/// A clearance [`Form`] with its values known.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ResolvedForm {
    pub action: Url,
    /// Each input's name and value, in order.
    pub fields: Vec<(String, String)>,
}
