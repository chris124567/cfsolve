//! Payload field sources and assignment order.
//!
//! Collects field assignments in a [`JsObject`] before applying them to the payload.
//! Reassigning a field preserves its position, matching JavaScript property order. Assigning
//! `undefined` also keeps the position, but omits the field from serialization.

use anyhow::{Result, ensure};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::expression::{Environment, Expression, State};
use crate::js::{JsObject, JsValue, Payload, json};

/// Replacement payload object built when the input's record counter is zero.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Template {
    /// Fields in assignment order.
    pub fields: IndexMap<String, Expression>,
}

/// Where each top-level field of the second payload comes from.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Layout {
    pub template: Template,
    /// Ordered writes made after template publication. `None` marks a value requiring browser
    /// computation.
    pub published: Vec<(String, Option<Expression>)>,
    /// Writes made just before passing the payload to the sender.
    pub footer: IndexMap<String, Expression>,
    /// Field reporting the pending-work wait duration.
    pub pending: Option<String>,
    /// Writes made after sending the payload. These affect later payloads only if a later
    /// program reuses the same object.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub sent: IndexMap<String, Expression>,
}

/// The new numbered record created by a checkbox program.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecordTemplate {
    pub token_field: String,
    pub token: String,
    pub input_field: String,
    pub input: JsValue,
    pub started_field: String,
}

impl Template {
    /// Only counter-zero inputs build a replacement object. Later invocations retain their
    /// input object, matching the program guard.
    pub fn build(&self, state: &State<'_>, counter: &str) -> Result<Payload> {
        if state.input.get(counter) != Some(&JsValue::Number(0.0)) {
            return Ok(state.input.clone());
        }
        let mut payload = Payload::new();
        for (key, expression) in &self.fields {
            if let Some(value) = expression.evaluate(state)? {
                payload.insert(key.clone(), value);
            }
        }
        Ok(payload)
    }
}

/// Browser-computed payload values outside probe records.
#[derive(Debug, Default, Deserialize)]
pub struct Document {
    /// JSON report from attaching a shadow root to the body. This is the only published field
    /// that requires browser computation.
    pub shadow_root: String,
}

/// Returns ordered writes for `fields`.
fn evaluate_all(fields: &IndexMap<String, Expression>, state: &State<'_>) -> Result<JsObject> {
    let mut writes = JsObject::new();
    for (field, expression) in fields {
        let value = expression.evaluate(state)?.unwrap_or(JsValue::Undefined);
        writes.insert(field.clone(), value);
    }
    Ok(writes)
}

impl Layout {
    /// Assembles numbered `records`, the template with its updated count, publication fields,
    /// `extra` writes, and the footer. Omits sender fields. JavaScript property ordering places
    /// integer keys first.
    pub fn assemble(
        &self,
        state: &State<'_>,
        document: &Document,
        records: JsObject,
        counter: &str,
        extra: JsObject,
        pending_ms: Option<i64>,
    ) -> Result<Payload> {
        let count = records.len();
        let mut payload = Payload::from(records);
        payload.extend(self.template.build(state, counter)?);
        payload.insert(counter.to_owned(), json!(count));
        payload.extend(self.publication(state, document)?);
        payload.extend(extra);
        payload.extend(self.footer(state, pending_ms)?);
        Ok(payload)
    }

    /// The writes made after template publication. Preserves the existing resource list
    /// when the new list is empty, matching the program's check.
    pub fn publication(&self, state: &State<'_>, document: &Document) -> Result<JsObject> {
        let browser = self.published.iter().filter(|(_, value)| value.is_none());
        ensure!(
            browser.count() <= 1,
            "the program publishes more browser-computed fields than a shadow-root report"
        );
        let mut writes = JsObject::new();
        for (field, expression) in &self.published {
            let value = match expression {
                Some(expression) => expression.evaluate(state)?.unwrap_or(JsValue::Undefined),
                None => json!(document.shadow_root),
            };
            if value.as_array().is_none_or(|values| !values.is_empty()) {
                writes.insert(field.clone(), value);
            }
        }
        Ok(writes)
    }

    /// Applies writes made after `payload` is passed to the sender.
    pub fn after_send(&self, payload: &mut Payload, environment: Environment<'_>) -> Result<()> {
        let state = State {
            environment,
            input: payload,
        };
        let writes = evaluate_all(&self.sent, &state)?;
        payload.extend(writes);
        Ok(())
    }

    /// Adds footer fields and, if the program waited for pending work, that wait duration.
    pub fn footer(&self, state: &State<'_>, pending_ms: Option<i64>) -> Result<JsObject> {
        let mut writes = evaluate_all(&self.footer, state)?;
        if let (Some(field), Some(pending_ms)) = (&self.pending, pending_ms) {
            writes.insert(field.clone(), JsValue::from(pending_ms));
        }
        Ok(writes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::{self, Options, Window};

    #[test]
    fn a_later_invocation_keeps_its_input_object() {
        let template: Template =
            js::from_value(json!({"fields": {"fresh": {"kind": "literal", "value": 1}}})).unwrap();
        let (options, window) = (Options::new(), Window::new());
        let environment = Environment {
            options: &options,
            window: &window,
            calls: &window,
        };
        for (counter, expected) in [
            (json!(0), json!({"fresh": 1})),
            (json!(2), json!({"count": 2})),
        ] {
            let input = Payload::from_iter([("count".to_owned(), counter)]);
            let state = State {
                environment,
                input: &input,
            };
            assert_eq!(
                JsValue::from(template.build(&state, "count").unwrap()),
                expected
            );
        }
    }
}
