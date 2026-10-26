//! Literal record configuration and clock marks around UI setup and proof.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::diagnostics;
use crate::candidates;
use crate::js::{JsObject, JsValue};
use crate::listing::Index;
use crate::listing::query::Store;
use crate::stage2::payload::RecordLiteral;
use crate::stage2::proof::ProofFields;
use crate::vm::{Constant, Term};

/// The record's literal configuration, and its setup, UI-ready and proof-start clock fields.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Plan {
    pub literals: JsObject,
    pub setup: String,
    pub ready: String,
    pub proof_started: String,
}

impl Plan {
    /// The record's literal configuration with setup and readiness timestamps. The proof-start
    /// timestamp is added after the click fields.
    #[must_use]
    pub fn collect(&self, setup_ms: i64, ready_ms: i64) -> JsObject {
        let mut fields = self.literals.clone();
        fields.extend([
            (self.setup.clone(), JsValue::from(setup_ms)),
            (self.ready.clone(), JsValue::from(ready_ms)),
        ]);
        fields
    }
}

pub(super) fn recover(
    index: &Index<'_>,
    literals: &[RecordLiteral],
    diagnostics: &diagnostics::Plan,
    proof: &ProofFields,
    click_output: &str,
) -> Result<Plan> {
    let stores = index.stores();
    let initial = stores
        .iter()
        .find(|store| {
            store.key == diagnostics.console
                && matches!(
                    index.dereference(store.pc, &store.value),
                    Some((_, Term::Const(Constant::Bool(false))))
                )
        })
        .context("checkbox program has no initial console flag")?;
    let (origin, _) = index
        .assignment(initial.pc, initial.object)
        .context("record initialization has no object assignment")?;
    let initializer = index
        .entry_at_or_before(initial.pc)
        .context("record has no initializer entry")?;
    // The cell holding the object a store writes to.
    let cell_of = |store: &Store| match index.dereference(store.pc, &Term::Reg(store.object)) {
        Some((_, Term::Cell(cell))) => Some(cell),
        _ => None,
    };
    let cell = stores
        .iter()
        .filter(|store| store.key == click_output)
        .find_map(cell_of)
        .context("click record has no captured record cell")?;
    let is_initial = |store: &Store| {
        store.object == initial.object
            && store.pc >= initial.pc
            && index.assignment(store.pc, store.object).map(|(pc, _)| pc) == Some(origin)
    };
    let mut configuration = JsObject::new();
    let mut setup = Vec::new();
    let mut ready = Vec::new();
    let mut proof_started = Vec::new();
    for store in stores {
        let initial = is_initial(store);
        if !initial && cell_of(store) != Some(cell) {
            continue;
        }
        if initial
            && let Some(literal) = literals
                .iter()
                .find(|literal| literal.pc == store.pc && literal.field == store.key)
        {
            configuration.insert(store.key.clone(), literal.value.clone());
            continue;
        }
        // A `Date.now()` clock mark.
        if store.key != proof.finished && index.is_date_now(store.pc, &store.value) {
            let entry = index
                .entry_at_or_before(store.pc)
                .context("clock write has no function entry")?;
            let group = if initial {
                &mut setup
            } else if entry == initializer {
                &mut ready
            } else {
                &mut proof_started
            };
            group.push(store.key.clone());
        }
    }
    ensure!(
        configuration.len() >= 4,
        "incomplete record initialization literals"
    );
    Ok(Plan {
        literals: configuration,
        setup: candidates::exactly_one(setup, "record setup clock mark")?,
        ready: candidates::exactly_one(ready, "record ready clock mark")?,
        proof_started: candidates::exactly_one(proof_started, "record proof-start clock mark")?,
    })
}
