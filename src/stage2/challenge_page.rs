//! Analyzes response programs used by the challenge-page orchestrator.
//!
//! The first response renders a Turnstile widget and prepares a second payload containing
//! session state, one widget-outcome record, and literal footer fields. The next response
//! submits a form to obtain clearance.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
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
        // result, then closing timestamps. Clear the original start before sending.
        let mut record = JsObject::new();
        record.insert(self.record.token_field.clone(), json!(self.record.token));
        record.insert(self.record.input_field.clone(), self.record.input.clone());
        record.extend(outcome.finish.iter().cloned());
        record.insert(outcome.token.clone(), json!(settled.token));
        record.insert(outcome.status.clone(), json!(""));
        record.insert(outcome.started.clone(), json!(settled.started_ms));
        record.insert(outcome.ended.clone(), json!(settled.ended_ms));
        record.insert(
            outcome.duration.clone(),
            json!(settled.ended_ms - settled.started_ms),
        );
        // This record is the first numbered entry.
        let records = JsObject::from_iter([("1".to_owned(), JsValue::Object(record))]);
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
            for (pc, effect) in self.index.effects_in(..) {
                if let Effect::SetCell(target, value) = effect
                    && *target == cell
                    && let Some((_, Term::Closure { pc: entry, .. })) =
                        self.index.dereference(pc, value)
                    && !entries.contains(&entry)
                {
                    entries.push(entry);
                }
            }
        }
        entries
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
