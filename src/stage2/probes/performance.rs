//! Reduces `performance.getEntries()` results to rows with type-specific formats.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::ops::ControlFlow;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use swc_core::ecma::ast::{BinaryOp, UnaryOp};

use crate::engine::Engine;
use crate::js::{JsObject, JsValue, json};
use crate::listing::fold::{self, Frame, Known};
use crate::resource_timing::{LoadTiming, NEXT_HOP_PROTOCOL};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::records::ProbePlan;
use crate::stage2::registry::Operation;
use crate::vm::{Effect, Exit, Listing, Term, dataflow};

/// How the probe writes the row of one entry type.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Format {
    pub marker: String,
    /// The row's fields in the order the program writes them.
    pub columns: Vec<(String, Column)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Column {
    Property(String),
    /// `responseEnd - requestStart`.
    Duration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub entries: String,
    pub discriminator: String,
    pub formats: BTreeMap<String, Format>,
    /// The marker of an entry whose type has no format.
    pub unknown: String,
    /// Field receiving the full entry when its type has no row format.
    pub raw: String,
    /// Prefix combined with the session ray to name the probe's initial mark.
    pub mark_prefix: String,
}

/// API entries sampled after the probe calls `performance.mark`.
pub struct Measurement {
    pub entries: Vec<JsValue>,
}

impl Measurement {
    /// Builds `performance.getEntries()` for probe `index`. Includes navigation, Chromium
    /// visibility, startup frame and paints, first POST and response frame, earlier probe
    /// loads, and this probe's mark at `marked_ms`. Reports times at 0.1 ms resolution relative
    /// to iframe navigation.
    #[must_use]
    pub(crate) fn observed(
        plan: &ProbePlan,
        index: usize,
        navigation: &LoadTiming,
        first_post: &LoadTiming,
        fetches: &[LoadTiming],
        mark_name: &str,
        marked_ms: i64,
        engine: Engine,
    ) -> Self {
        let tenth = |ms: f64| (ms * 10.0).round() / 10.0;
        let at = |wall_ms: f64| tenth(wall_ms - navigation.started_ms as f64);
        let loaded = at(navigation.ended_ms());
        let resource = |fetch: &LoadTiming, initiator: &str| {
            let start = at(fetch.started_ms as f64);
            let measured = fetch.measurement();
            json!({"entryType": "resource", "name": fetch.url, "initiatorType": initiator,
                "startTime": start, "requestStart": start, "responseEnd": at(fetch.ended_ms()),
                "nextHopProtocol": NEXT_HOP_PROTOCOL,
                "transferSize": measured.transfer_size,
                "encodedBodySize": measured.body_size})
        };
        let long_animation_frame = |start: f64| {
            json!({"entryType": "long-animation-frame", "name": "long-animation-frame",
                "startTime": start})
        };
        let chromium = engine == Engine::Chromium;
        let mut entries = vec![json!({"entryType": "navigation", "name": navigation.url,
            "type": "navigate", "startTime": 0, "duration": loaded})];
        if chromium {
            // Chrome captures list the startup's long animation frame, then the first paints,
            // before the first POST goes out.
            let posted = at(first_post.started_ms as f64);
            let between = |share: f64| tenth(loaded + (posted - loaded) * share);
            let painted = between(0.5);
            entries.extend([
                json!({"entryType": "visibility-state", "name": "visible", "startTime": 0,
                    "duration": 0}),
                long_animation_frame(between(0.25)),
                json!({"entryType": "paint", "name": "first-paint", "startTime": painted}),
                json!({"entryType": "paint", "name": "first-contentful-paint",
                    "startTime": painted}),
            ]);
        }
        entries.push(resource(first_post, "xmlhttprequest"));
        if chromium {
            // Running the response's program takes a long animation frame.
            entries.push(long_animation_frame(at(first_post.ended_ms())));
        }
        // The image probe preloads its image with a link before loading it.
        let image_before = plan.probes().iter().any(|probe| {
            probe.index < index && matches!(probe.operation, Some(Operation::Image { .. }))
        });
        if image_before && let Some(image) = fetches.first() {
            entries.push(resource(image, "link"));
        }
        entries.push(json!({"entryType": "mark", "name": mark_name,
            "startTime": at(marked_ms as f64), "duration": 0}));
        Self { entries }
    }
}

impl Fields {
    #[must_use]
    pub fn mark_name(&self, ray: &str) -> String {
        format!("{}{ray}", self.mark_prefix)
    }

    /// Converts entries to rows by type, copying entries of unknown types whole.
    pub fn collect(&self, measurement: &Measurement) -> Result<JsObject> {
        let mut projected = Vec::new();
        for entry in &measurement.entries {
            let kind = entry.get("entryType").and_then(JsValue::as_str);
            let format = kind.and_then(|kind| self.formats.get(kind));
            let marker = format.map_or(&self.unknown, |format| &format.marker);
            let mut row = JsObject::from_iter([(self.discriminator.clone(), json!(marker))]);
            let Some(format) = format else {
                row.insert(self.raw.clone(), entry.clone());
                projected.push(JsValue::Object(row));
                continue;
            };
            for (field, column) in &format.columns {
                let value = match column {
                    Column::Property(property) => entry.get(property).cloned(),
                    // Serialize NaN as null, including differences using missing timestamps.
                    // Preserve negative differences.
                    Column::Duration => {
                        let end = number(entry.get("responseEnd"))?;
                        Some(json!(end - number(entry.get("requestStart"))?))
                    }
                };
                if let Some(value) = value {
                    row.insert(field.clone(), value);
                }
            }
            projected.push(JsValue::Object(row));
        }
        Ok(JsObject::from_iter([(
            self.entries.clone(),
            JsValue::Array(projected),
        )]))
    }
}

fn number(value: Option<&JsValue>) -> Result<f64> {
    match value {
        None => Ok(f64::NAN),
        Some(JsValue::Null) => Ok(0.0),
        Some(JsValue::Number(value)) => Ok(*value),
        Some(_) => bail!("performance resource timestamp is not a number"),
    }
}

/// Additional values tracked while analyzing performance-probe code.
#[derive(Clone, Debug, PartialEq)]
enum Held {
    /// Result of `getEntries()`.
    Entries,
    /// One of those entries.
    Entry,
    EntryType,
    Property(String),
    /// `responseEnd - requestStart` of an entry.
    Duration,
    /// A property of another object, such as the record holding the output list.
    Field(String),
    /// A string starting with this text.
    Prefixed(String),
}

/// A row's destination list and columns in insertion order.
#[derive(Default)]
struct Row {
    list: String,
    columns: Vec<RowWrite>,
}

struct RowWrite {
    field: String,
    value: Known<Held>,
}

/// Recovers row formats from `entryType` comparisons and the row blocks they branch to.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let index = probe.index;
    let listing = index.listing();
    let code = index.reachable(probe.entry);
    // Registers are reused across branches. At each instruction, keep only facts shared by every
    // incoming path. The probe and its nested functions start with no known values. Ignore paths
    // ruled out by known values.
    let mut entries = vec![probe.entry];
    for pc in &code {
        for effect in listing.instructions[pc].effects() {
            effect.visit_terms(&mut |term| {
                if let Term::Closure { pc, .. } = term {
                    entries.push(*pc);
                }
            });
        }
    }
    let starts = entries.into_iter().map(|pc| (pc, Frame::default()));
    let ControlFlow::Continue(incoming) = dataflow::forward(listing, starts, |pc, path, frame| {
        frame.begin();
        let runs = fold::feasible(path, |term| frame.resolve(term));
        if runs {
            frame.follow(pc, &path.effects, evaluate, |_, _| {});
        }
        ControlFlow::<Infallible, bool>::Continue(runs)
    });
    let mut targets: Vec<(String, u32)> = Vec::new();
    let mut mark_prefix = None;
    // Index rows by the program counter where their objects were created.
    let mut rows: BTreeMap<u32, Row> = BTreeMap::new();
    for &pc in &code {
        for path in &listing.instructions[&pc].paths {
            let mut frame: Frame<Held> = incoming.get(&pc).cloned().unwrap_or_default();
            frame.begin();
            if !fold::feasible(path, |term| frame.resolve(term)) {
                continue;
            }
            // A comparison against a type string leads to that type's block.
            if let Exit::Next { pc: target, .. } = path.exit
                && let [(condition, holds)] = path.conditions.as_slice()
                && let Some((left, right)) = equality(condition, *holds)
            {
                match (frame.resolve(left), frame.resolve(right)) {
                    (
                        Some(Known::Ext(Held::EntryType)),
                        Some(Known::Literal(JsValue::String(kind))),
                    )
                    | (
                        Some(Known::Literal(JsValue::String(kind))),
                        Some(Known::Ext(Held::EntryType)),
                    ) => targets.push((kind, target)),
                    _ => {}
                }
            }
            frame.follow(pc, &path.effects, evaluate, |frame, effect| {
                // The probe creates its mark with `performance.mark(prefix + ray)`.
                if let Some((Term::Get(_, key), [Term::Reg(argument)])) = effect.call()
                    && is_text(frame, key, "mark")
                    && let Some(Known::Ext(Held::Prefixed(prefix))) = frame.register(*argument)
                {
                    mark_prefix = Some(prefix.clone());
                }
                let Effect::SetProperty { object, key, value } = effect else {
                    return;
                };
                // Columns contain string markers and entry values. Other constants would change
                // which value is identified as the first-column marker.
                if let Some(Known::Object(row)) = frame.resolve(object)
                    && let Some(Known::Literal(JsValue::String(field))) = frame.resolve(key)
                    && let Some(value) = frame.resolve(value)
                    && matches!(
                        value,
                        Known::Literal(JsValue::String(_)) | Known::Object(_) | Known::Ext(_)
                    )
                {
                    rows.entry(row)
                        .or_default()
                        .columns
                        .push(RowWrite { field, value });
                }
                if let Some(Known::Ext(Held::Field(list))) = frame.resolve(object)
                    && let Some(Known::Object(row)) = frame.resolve(value)
                {
                    rows.entry(row).or_default().list = list;
                }
            });
        }
    }

    // Every row starts with the same discriminator and its type's marker.
    let discriminator = rows.values().find_map(|row| {
        let first = row.columns.first()?;
        let literal = matches!(first.value, Known::Literal(JsValue::String(_)));
        literal.then(|| first.field.clone())
    })?;
    let entries = rows
        .values()
        .find_map(|row| (!row.list.is_empty()).then(|| row.list.clone()))?;
    let mut formats = BTreeMap::new();
    let mut claimed = BTreeSet::new();
    for (kind, target) in targets {
        let Some(pc) = block_row(listing, &rows, target) else {
            continue;
        };
        let row = &rows[&pc];
        claimed.insert(pc);
        let (marker, rest) = marked(&row.columns)?;
        let columns: Vec<(String, Column)> = rest
            .iter()
            .filter_map(|write| match &write.value {
                Known::Ext(Held::Property(property)) => {
                    Some((write.field.clone(), Column::Property(property.clone())))
                }
                Known::Ext(Held::Duration) => Some((write.field.clone(), Column::Duration)),
                _ => None,
            })
            .collect();
        let marker = marker.to_owned();
        formats.insert(kind, Format { marker, columns });
    }
    // The row with no incoming type branch is the fallback. It copies the whole entry.
    let mut unclaimed = rows.iter().filter(|&(pc, _)| !claimed.contains(pc));
    let (unknown, raw) = unclaimed.find_map(|(_, row)| {
        let (marker, rest) = marked(&row.columns)?;
        let raw = rest
            .iter()
            .find(|write| write.value == Known::Ext(Held::Entry))?;
        Some((marker.to_owned(), raw.field.clone()))
    })?;
    let mark_prefix = mark_prefix?;
    (!formats.is_empty()).then_some(Fields {
        entries,
        discriminator,
        formats,
        unknown,
        raw,
        mark_prefix,
    })
}

/// Finds the first row created by a type's block, following the single path from `target`. Returns
/// no row for comparisons that only produce a boolean for a later branch.
fn block_row(listing: &Listing, rows: &BTreeMap<u32, Row>, target: u32) -> Option<u32> {
    let mut pc = target;
    loop {
        if rows.contains_key(&pc) {
            return Some(pc);
        }
        let instruction = listing.instructions.get(&pc)?;
        let mut next = instruction
            .paths
            .iter()
            .filter_map(|path| path.exit.continues_at());
        let first = next.next()?;
        // Ignore paths that throw, such as call guards.
        if next.any(|other| other.pc != first.pc) || first.pc <= pc {
            return None;
        }
        pc = first.pc;
    }
}

/// The row's marker and columns, with its first column stored separately.
fn marked(columns: &[RowWrite]) -> Option<(&str, &[RowWrite])> {
    let (first, rest) = columns.split_first()?;
    match &first.value {
        Known::Literal(JsValue::String(marker)) => Some((marker.as_str(), rest)),
        _ => None,
    }
}

/// Finds terms known to be equal when `condition` evaluates to `holds`. Looks through
/// negations.
fn equality(condition: &Term, holds: bool) -> Option<(&Term, &Term)> {
    match condition {
        Term::Unary(UnaryOp::Bang, inner) => equality(inner, !holds),
        Term::Binary(BinaryOp::EqEqEq | BinaryOp::EqEq, left, right) if holds => {
            Some((left, right))
        }
        Term::Binary(BinaryOp::NotEqEq | BinaryOp::NotEq, left, right) if !holds => {
            Some((left, right))
        }
        _ => None,
    }
}

fn is_text(frame: &Frame<Held>, term: &Term, text: &str) -> bool {
    frame
        .resolve(term)
        .is_some_and(|known| known.text() == Some(text))
}

fn evaluate(frame: &Frame<Held>, term: &Term) -> Option<Known<Held>> {
    Some(match term {
        Term::Call { callee, .. } => match &**callee {
            Term::Get(_, key) if is_text(frame, key, "getEntries") => Known::Ext(Held::Entries),
            _ => return None,
        },
        // If `getEntries` is missing, the probe uses an empty list, which also has no entries.
        Term::Array(elements) if elements.is_empty() => Known::Ext(Held::Entries),
        Term::Get(object, key) => match (frame.resolve(object), frame.resolve(key)) {
            (Some(Known::Ext(Held::Entries)), _) => Known::Ext(Held::Entry),
            (Some(Known::Ext(Held::Entry)), Some(Known::Literal(JsValue::String(name))))
                if name == "entryType" =>
            {
                Known::Ext(Held::EntryType)
            }
            (Some(Known::Ext(Held::Entry)), Some(Known::Literal(JsValue::String(name)))) => {
                Known::Ext(Held::Property(name))
            }
            (None, Some(Known::Literal(JsValue::String(name)))) => Known::Ext(Held::Field(name)),
            _ => return None,
        },
        Term::Binary(BinaryOp::Add, left, _) => match frame.resolve(left)? {
            Known::Literal(JsValue::String(prefix)) => Known::Ext(Held::Prefixed(prefix)),
            _ => return None,
        },
        Term::Binary(BinaryOp::Sub, left, right) => {
            match (frame.resolve(left)?, frame.resolve(right)?) {
                (Known::Ext(Held::Property(end)), Known::Ext(Held::Property(start)))
                    if end == "responseEnd" && start == "requestStart" =>
                {
                    Known::Ext(Held::Duration)
                }
                _ => return None,
            }
        }
        term => frame.resolve(term)?,
    })
}
