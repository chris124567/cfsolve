//! Measures worker `performance.now()` resolution.

use anyhow::{Result, ensure};

use crate::js::{JsObject, JsValue};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

/// Number of consecutive reading pairs compared by the worker.
pub(crate) const PAIRS: usize = 5000;

/// The smallest positive difference between paired `readings`, capped at one millisecond.
pub(crate) fn collect(readings: &[[f64; 2]]) -> Result<JsObject> {
    use swc_ecma_utils::number::ToJsString;

    ensure!(
        readings.len() >= PAIRS,
        "clock probe needs {PAIRS} pairs of readings"
    );
    let mut minimum = 1.0_f64;
    for &[before, after] in &readings[..PAIRS] {
        ensure!(
            before.is_finite() && after.is_finite(),
            "clock readings must be finite"
        );
        if before < after {
            minimum = minimum.min(after - before);
        }
    }
    Ok(JsObject::from_iter([(
        reference::SHARED_RESULT.to_owned(),
        JsValue::String(minimum.to_js_string()),
    )]))
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<()> {
    let strings = &probe.strings;
    let worker = strings
        .features()
        .iter()
        .any(|text| text.starts_with("for(var a=1,b=1,c,d=0;5E3>d;d++)"));
    (worker && strings.stores(reference::SHARED_RESULT) && strings.has(reference::CLOCK_FALLBACK))
        .then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::json;

    #[test]
    fn uses_positive_differences_with_a_one_millisecond_ceiling() {
        let mut readings = vec![[10.0, 10.0]; PAIRS];
        readings[7] = [10.0, 12.0];
        readings[8] = [10.0, 9.0];
        readings[9] = [10.0, 10.125];
        readings.push([0.0, 0.001]); // The worker only runs 5000 iterations.
        assert_eq!(
            collect(&readings).unwrap()[reference::SHARED_RESULT],
            json!("0.125")
        );
    }
}
