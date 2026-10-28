//! Recovers the checkbox program's plan and assembles its payload.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use swc_core::ecma::ast::BinaryOp;

use super::{click, diagnostics, initialization, ui};
use crate::candidates;
use crate::js::{JsObject, JsValue, Payload, json};
use crate::listing::query::Store;
use crate::listing::{self, Index};
use crate::stage2::payload::{
    self, Document, Environment, Layout, RecordTemplate, Recovered, State,
};
use crate::stage2::proof::{Proof, ProofFields};
use crate::stage2::records::{ArrangedFields, COMPLETED_STATUS, Completion};
use crate::vm::{Constant, Effect, Listing, Term};

/// Recovered checkbox record fields and rules for filling them.
#[derive(Debug, Deserialize, Serialize)]
pub struct Plan {
    /// Payload field holding the number of earlier records.
    pub counter: String,
    /// How long the click handler waits before launching the proof.
    pub click_delay_ms: u64,
    pub record: RecordTemplate,
    pub payload: Layout,
    pub proof: Proof,
    pub click: click::Plan,
    pub ui: ui::Plan,
    pub diagnostics: diagnostics::Plan,
    pub initialization: initialization::Plan,
    pub proof_fields: ProofFields,
    pub envelope: Completion,
}

impl Plan {
    /// Appends the checkbox record built from measured `fields`, preserving earlier records.
    pub fn append_record(
        &self,
        input: &Payload,
        fields: JsObject,
        started_ms: i64,
        finished_ms: i64,
    ) -> Result<Payload> {
        let counter = input
            .get(&self.counter)
            .and_then(JsValue::as_u64)
            .context("checkbox program input has no integer record counter")?
            + 1;
        ensure!(
            !input.contains_key(&counter.to_string()),
            "checkbox program would overwrite an existing record"
        );
        let created = [
            (self.record.token_field.clone(), json!(self.record.token)),
            (self.record.input_field.clone(), self.record.input.clone()),
        ];
        // The record's own start mark is removed before it is sent.
        let record = self.envelope.complete(
            created,
            ArrangedFields {
                early: fields,
                ..ArrangedFields::default()
            },
            &[self.record.started_field.as_str()],
            started_ms,
            finished_ms,
        )?;
        let mut payload = input.clone();
        payload.insert(self.counter.clone(), JsValue::from(counter));
        payload.insert(counter.to_string(), JsValue::Object(record));
        Ok(payload)
    }

    /// Refreshes fields published before the sender call from this program's layout, keeping
    /// earlier records. Both steps read the payload as it was before either writes.
    pub fn finish_payload(
        &self,
        mut payload: Payload,
        environment: Environment<'_>,
        document: &Document,
    ) -> Result<Payload> {
        let state = State {
            environment,
            input: &payload,
        };
        let mut writes = self.payload.publication(&state, document)?;
        // Click completion resumes the sender without the pending-probe callback, preserving
        // the earlier wait duration.
        writes.extend(self.payload.footer(&state, None)?);
        payload.extend(writes);
        Ok(payload)
    }
}

/// Analyzes a returned checkbox program's listing.
pub fn recover(listing: &Listing) -> Result<Plan> {
    ensure!(
        listing.failures.is_empty(),
        "checkbox program has undecoded instructions"
    );
    let index = Index::new(listing);
    let strings = index.strings();
    ensure!(
        strings.values().any(|text| *text == "click"),
        "program is not a checkbox program"
    );
    let Recovered {
        pool,
        counter,
        layout: payload,
        record,
        literals,
    } = payload::recover_unique(&index, "checkbox program")?;
    let (&config_pc, config) = strings
        .iter()
        .find(|(_, text)| text.starts_with("var ") && text.ends_with(':'))
        .context("checkbox program has no proof worker configuration")?;
    let (_, budget_field) = config
        .strip_prefix("var ")
        .and_then(|text| text.split_once("={"))
        .context("unexpected proof configuration declaration")?;
    let budget_field = budget_field.trim().trim_end_matches(':');
    let suffix_field = strings
        .range(config_pc + 1..)
        .find_map(|(_, text)| {
            text.strip_prefix("',")
                .and_then(|text| text.strip_suffix(":'"))
        })
        .context("proof configuration has no suffix field")?;
    let unique_literal = |field: &str| -> Result<JsValue> {
        let values = literals
            .iter()
            .filter(|literal| literal.field == field)
            .map(|literal| &literal.value);
        candidates::at_most_one_distinct(values, &format!("proof field {field} literal"))?
            .cloned()
            .with_context(|| format!("proof field {field} has no literal"))
    };
    let budget_ms = unique_literal(budget_field)?
        .as_f64()
        .context("proof budget is not numeric")?;
    ensure!(
        budget_ms.is_finite() && budget_ms >= 0.0,
        "invalid proof time budget"
    );
    let suffix = unique_literal(suffix_field)?
        .as_str()
        .context("proof suffix is not text")?
        .to_owned();
    let (prefix_pc, prefix_option) = prefix_option(&index, config_pc)?;
    let iterations: BTreeSet<u64> = strings
        .range(prefix_pc..config_pc)
        .filter_map(|(_, text)| listing::decode_string(text, pool).ok()?.parse().ok())
        .collect();
    let iteration = candidates::exactly_one(iterations, "proof prefix iteration literal")?;
    let envelope = envelope(&index, &record)?;
    let click = click::recover(&index)?;
    let diagnostics = diagnostics::recover(&index)?;
    let proof_fields = proof_fields(&index, config_pc)?;
    let initialization = initialization::recover(
        &index,
        &literals,
        &diagnostics,
        &proof_fields,
        &click.output,
    )?;
    Ok(Plan {
        counter,
        click_delay_ms: click_delay(&index, &diagnostics.stack)?,
        record,
        payload,
        proof: Proof {
            budget_ms,
            suffix,
            prefix_option,
            iteration,
        },
        click,
        ui: ui::recover(&index)?,
        diagnostics,
        initialization,
        proof_fields,
        envelope,
    })
}

/// The click handler schedules the proof launcher after its diagnostic writes.
fn click_delay(index: &Index<'_>, stack_field: &str) -> Result<u64> {
    let store = index
        .stores()
        .iter()
        .find(|store| store.key == stack_field)
        .context("click handler has no stack write")?;
    let mut delays = BTreeSet::new();
    for (pc, effect) in index.effects_in(store.pc..index.function_at(store.pc).end) {
        effect.visit_terms(&mut |term| {
            if let Term::Call {
                callee, arguments, ..
            } = term
                && index.method(pc, callee).as_deref() == Some("setTimeout")
                && let Some((_, Term::Const(Constant::Number(delay)))) = arguments
                    .get(1)
                    .and_then(|argument| index.dereference(pc, argument))
                && delay >= 0.0
                && delay < u64::MAX as f64
                && delay.fract() == 0.0
            {
                delays.insert(delay as u64);
            }
        });
    }
    candidates::exactly_one(delays, "click handler proof delay")
}

/// The checkbox program record's status, message and clock fields.
fn envelope(index: &Index<'_>, record: &RecordTemplate) -> Result<Completion> {
    let stores = index.stores();
    // Look for field names throughout the program; they are not limited to the header.
    let status = candidates::exactly_one(
        stores.iter().filter(|store| {
            matches!(store.value, Term::Const(Constant::Number(status))
                if status == f64::from(COMPLETED_STATUS))
        }),
        "completed status write",
    )?;
    let message = stores
        .iter()
        .find(|store| store.pc > status.pc && store.object == status.object)
        .context("checkbox program has no completion message field")?;
    ensure!(
        index.text(message.pc, &message.value).as_deref() == Some(""),
        "checkbox program success message is not empty"
    );
    // The record's own start mark is cleared after its clock marks are written.
    let removed = stores
        .iter()
        .find(|store| {
            store.key == record.started_field
                && matches!(
                    index.dereference(store.pc, &store.value),
                    Some((_, Term::Const(Constant::Undefined)))
                )
        })
        .context("checkbox program does not remove its initial clock mark")?;
    let epilogue = index.entry_at_or_before(removed.pc).unwrap_or(0)..removed.pc;
    let marked: Vec<&Store> = stores
        .iter()
        .filter(|store| store.object == removed.object && epilogue.contains(&store.pc))
        .collect();
    let [started, finished, duration] = index.clock_marks(&marked)?;
    Ok(Completion {
        status: status.key.clone(),
        message: message.key.clone(),
        started: started.key.clone(),
        finished: finished.key.clone(),
        duration: duration.key.clone(),
    })
}

/// The fields the proof's success callback assigns.
fn proof_fields(index: &Index<'_>, config_pc: u32) -> Result<ProofFields> {
    let stores = index.stores();
    // The error callback writes a fixed diagnostic into the same field that
    // the success callback fills with the winning nonce.
    let failure = stores
        .iter()
        .find(|store| {
            index.text(store.pc, &store.value).as_deref()
                == Some("the force is not strong with this one")
        })
        .context("proof failure callback not found")?;
    let success = stores
        .iter()
        .find(|store| store.pc < failure.pc && store.key == failure.key)
        .context("proof success callback not found")?;
    let callback = index
        .function_range(success.pc)
        .context("proof callback has no function entry or end")?;
    let (mut hashes, mut workers, mut elapsed, mut finished) = (None, None, None, None);
    let fields: Vec<_> = stores
        .iter()
        .filter(|store| callback.contains(&store.pc) && store.object == success.object)
        .collect();
    ensure!(
        fields.len() == 5,
        "proof callback does not have five record writes"
    );
    for store in fields {
        if store.key == success.key {
            continue;
        }
        let Term::Reg(register) = &store.value else {
            bail!("proof result is not register-held");
        };
        let (_, value) = index
            .assignment(store.pc, *register)
            .context("proof result has no assignment")?;
        let destination = match value {
            Term::Cell(_) => &mut hashes,
            Term::Reg(_) => &mut workers,
            Term::Binary(BinaryOp::Sub, _, _) => &mut elapsed,
            _ if index.is_date_now(store.pc, &store.value) => &mut finished,
            _ => bail!("unrecognized proof callback write {}", store.key),
        };
        ensure!(
            destination.replace(store.key.clone()).is_none(),
            "ambiguous proof callback projection"
        );
    }
    let before = index
        .entry_at_or_before(config_pc)
        .context("proof has no worker setup function")?;
    let requested = stores
        .iter()
        .filter(|store| (before..config_pc).contains(&store.pc))
        .filter(|store| {
            let value = index.dereference(store.pc, &store.value);
            matches!(value, Some((pc, Term::Call { callee, .. }))
                if index.method(pc, &callee).as_deref() == Some("min"))
        });
    let requested = candidates::exactly_one(requested, "requested worker count projection")?;
    // Require worker-setup structure to distinguish this call from an unrelated numeric
    // `min()`.
    let mut reads_concurrency = false;
    for (_, effect) in index.effects_in(before..config_pc) {
        effect.visit_terms(&mut |term| {
            reads_concurrency |=
                matches!(term, Term::Get(_, key) if key.string() == Some("hardwareConcurrency"));
        });
    }
    ensure!(
        reads_concurrency,
        "proof worker count does not read hardware concurrency"
    );
    Ok(ProofFields {
        nonce: success.key.clone(),
        hashes: hashes.context("proof has no hash count projection")?,
        workers: workers.context("proof has no completed worker count projection")?,
        elapsed: elapsed.context("proof has no elapsed projection")?,
        finished: finished.context("proof has no completion time projection")?,
        requested_workers: requested.key.clone(),
    })
}

/// Finds the proof prefix's read of `window._cf_chl_opt[key]` before a `"|"` separator. Returns
/// its position and `key`.
fn prefix_option(index: &Index<'_>, before: u32) -> Result<(u32, String)> {
    let listing = index.listing();
    let mut options = Vec::new();
    let separators = index
        .strings()
        .range(..before)
        .filter(|(_, text)| **text == "|");
    for (&pc, _) in separators {
        let Some((&previous, instruction)) = listing.instructions.range(..pc).next_back() else {
            continue;
        };
        for effect in instruction.effects() {
            if let Effect::Set(_, value) = effect
                && let Some(key) = index.option_read(previous, value)
            {
                options.push((previous, key));
            }
        }
    }
    candidates::at_most_one_distinct(options, "proof prefix options read")?
        .context("proof prefix has no options read")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js;
    use crate::js::{Options, Window};

    fn fixture() -> Plan {
        js::from_value(json!({
            "counter": "count",
            "click_delay_ms": 250,
            "record": {"token_field": "token", "token": "new-session-token",
                "input_field": "input", "input": "new-input-token",
                "started_field": "temporary_start"},
            "payload": {"template": {"fields": {}}, "published": [], "footer": {},
                "pending": null},
            "proof": {"budget_ms": 0, "suffix": "", "prefix_option": "", "iteration": 0},
            "click": {"output": "click", "fields": {}},
            "ui": {"output": "ui"},
            "diagnostics": {"stack": "", "construct": 0, "callback_arity": 0, "console": "",
                "stack_untouched": "", "stack_touched": "", "programmatic": ""},
            "initialization": {"literals": {}, "setup": "", "ready": "", "proof_started": ""},
            "proof_fields": {"nonce": "", "hashes": "", "workers": "", "elapsed": "",
                "finished": "", "requested_workers": ""},
            "envelope": {"status": "status", "message": "message", "started": "start",
                "finished": "end", "duration": "duration"},
        }))
        .unwrap()
    }

    #[test]
    fn checkbox_program_appends_its_record_after_previous_ones() {
        let plan = fixture();
        let input: Payload =
            js::from_value(json!({"count": 1, "1": {"previous": true}, "session": "kept"}))
                .unwrap();
        let mut fields = JsObject::from_iter([("click".to_owned(), json!({}))]);
        let payload = plan.append_record(&input, fields.clone(), 100, 98).unwrap();
        // The record's own start mark is not sent.
        assert_eq!(
            JsValue::from(payload),
            json!({"count": 2, "1": {"previous": true}, "session": "kept", "2": {
                "token": "new-session-token", "input": "new-input-token", "status": 3,
                "message": "", "click": {}, "start": 100, "end": 98, "duration": -2}})
        );
        fields.insert("token".into(), json!("stale-token"));
        assert!(plan.append_record(&input, fields, 100, 98).is_err());
    }

    #[test]
    fn checkbox_program_refreshes_footer_and_omits_undefined_writes() {
        let missing = json!({"kind": "read", "scope": "window", "path": ["missing"]});
        let mut plan = fixture();
        plan.payload = js::from_value(json!({"template": {"fields": {}}, "pending": "pending",
            "published": [["stale_published", missing],
                ["resources", {"kind": "read", "scope": "options", "path": ["resources"]}]],
            "footer": {"session": {"kind": "literal", "value": "new-token"},
                "stale_footer": missing}}))
        .unwrap();
        let input: Payload = js::from_value(json!({"count":2, "1":{"previous":true},
            "2":{"new":true}, "session":"old-token", "stale_footer":true, "stale_published":true,
            "resources":["previous-resource"], "pending":15}))
        .unwrap();
        let options: Options = js::from_value(json!({"resources":[]})).unwrap();
        let empty = Window::new();
        let environment = Environment {
            options: &options,
            window: &empty,
            calls: &empty,
        };
        let mut result = plan
            .finish_payload(input, environment, &Document::default())
            .unwrap();
        // The stale fields are assigned `undefined`, which serialization leaves out.
        result.retain(|_, value| !value.is_undefined());
        assert_eq!(
            JsValue::from(result),
            json!({"count": 2, "1": {"previous": true}, "2": {"new": true},
                "session": "new-token", "resources": ["previous-resource"], "pending": 15})
        );
    }
}
