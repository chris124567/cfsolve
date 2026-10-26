//! Reconstructs the checkbox program's limited scan of body divs and CSS keyframe rules.

use std::ops::Range;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::candidates;
use crate::js::{JsValue, json};
use crate::listing::Index;
use crate::vm::{Constant, Effect, Term};

/// The record field the scan's audit is written to.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Plan {
    pub output: String,
}

/// A stylesheet rule, as the scan reads it.
#[derive(Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Rule {
    Other,
    Keyframes { text: String },
}

#[derive(Deserialize, Serialize)]
pub struct Sheet {
    pub rules: Vec<Rule>,
}

/// The document's stylesheets, measured natively.
#[derive(Deserialize, Serialize)]
pub struct Measurement {
    pub sheets: Vec<Sheet>,
}

impl Plan {
    /// Builds UI audit output from serialized keyframes and flags for skipped input. Captures
    /// show no divs with an ID or style in the iframe body, so the corresponding lists are
    /// empty.
    #[must_use]
    pub fn collect(&self, measurement: &Measurement) -> JsValue {
        let mut keyframes = Vec::new();
        let mut flags = 0u8;
        // Limit each string to 512 UTF-16 code units and the total to 28,000.
        let mut length = 0;
        if measurement.sheets.len() > 16 {
            flags |= 2;
        }
        // At most 256 rules across the scanned sheets.
        let mut rules = measurement
            .sheets
            .iter()
            .take(16)
            .flat_map(|sheet| &sheet.rules);
        let scanned = rules.by_ref().take(256);
        for rule in scanned {
            if let Rule::Keyframes { text } = rule {
                let units = text.encode_utf16().count();
                if units <= 512 && length + units <= 28_000 {
                    length += units;
                    keyframes.push(text.as_str());
                } else {
                    flags |= 8;
                }
            }
        }
        if rules.next().is_some() {
            flags |= 2;
        }
        json!([[], [], keyframes, flags])
    }
}

pub(super) fn recover(index: &Index<'_>) -> Result<Plan> {
    let anchor = index
        .effects_in(..)
        .find_map(|(pc, effect)| {
            matches!(effect, Effect::Set(_, Term::Get(_, key)) if key.string() == Some("styleSheets"))
            .then_some(pc)
        })
        .context("checkbox program has no UI stylesheet scan")?;
    let scan = index
        .function_range(anchor)
        .context("UI scan has no function entry or end")?;
    let has_limits = |function: Range<u32>, limits: &[f64]| {
        let numbers: Vec<f64> = index
            .effects_in(function)
            .filter_map(|(_, effect)| match effect {
                Effect::Set(_, Term::Const(Constant::Number(number))) => Some(*number),
                _ => None,
            })
            .collect();
        limits.iter().all(|limit| numbers.contains(limit))
    };
    ensure!(
        has_limits(scan.clone(), &[64.0, 16.0, 256.0]),
        "unrecognized UI scan limits"
    );
    // The two append helpers enforce per-string and shared UTF-16 limits.
    for helper in index.closures_in(scan.clone()) {
        let helper = index
            .function_range(helper)
            .context("UI append helper has no end")?;
        ensure!(
            has_limits(helper, &[512.0, 28_000.0]),
            "unrecognized UI string limits"
        );
    }
    let cells: Vec<u32> = index
        .effects_in(..)
        .filter_map(|(pc, effect)| {
            let Effect::SetCell(cell, value) = effect else {
                return None;
            };
            matches!(index.dereference(pc, value),
            Some((_, Term::Closure { pc, .. })) if pc == scan.start)
            .then_some(*cell)
        })
        .collect();
    let outputs = index.stores().iter().filter_map(|store| {
        let (_, Term::Call { callee, .. }) = index.dereference(store.pc, &store.value)? else {
            return None;
        };
        matches!(*callee, Term::Cell(cell) if cells.contains(&cell)).then(|| store.key.clone())
    });
    Ok(Plan {
        output: candidates::exactly_one(outputs, "UI scan output field")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js;

    #[test]
    fn strings_and_rules_are_limited_across_sheets() {
        let keyframes = |text: String| json!({"outcome": "keyframes", "text": text});
        let other = json!({"outcome": "other"});
        let short = keyframes("x".into());
        for (sheets, expected) in [
            // Lengths are in UTF-16 units, and a rejected string leaves room for later ones.
            (
                json!([{"rules": [keyframes("😀".repeat(257)), keyframes("😀".repeat(256)), other]}]),
                json!([[], [], ["😀".repeat(256)], 8]),
            ),
            // The total length and the rule count are limited across sheets.
            (
                json!([{"rules": vec![keyframes("k".repeat(500)); 56]}, {"rules": [short]}]),
                json!([[], [], vec!["k".repeat(500); 56], 8]),
            ),
            (
                json!([{"rules": vec![other; 256]}, {"rules": [short]}]),
                json!([[], [], [], 2]),
            ),
        ] {
            let measurement: Measurement = js::from_value(json!({"sheets": sheets})).unwrap();
            let plan = Plan {
                output: "audit".into(),
            };
            assert_eq!(plan.collect(&measurement), expected);
        }
    }
}
