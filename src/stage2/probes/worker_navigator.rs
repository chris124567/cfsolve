//! Recovered fields for the worker navigator probe.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::js::{JsObject, JsValue};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;
use crate::stage2::registry::{self, Missing};

pub(crate) const OUTPUTS: [&str; 2] = [
    reference::WORKER_NAVIGATOR_INDICATOR,
    reference::WORKER_NAVIGATOR_RESULT,
];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    /// Maps output fields to navigator properties in the order the worker posts them.
    #[serde(rename = "fields")]
    pub properties: IndexMap<String, String>,
}

/// Recovers navigator properties from the worker source text after each output field name.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    const PROPERTIES: [&str; 5] = [
        "platform",
        "languages",
        "hardwareConcurrency",
        "deviceMemory",
        "userAgent",
    ];
    let strings = &probe.strings;
    if !(strings.has("var n=self.navigator;postMessage({ ") && strings.stores_all(&OUTPUTS)) {
        return None;
    }
    let mut properties = IndexMap::new();
    for pair in strings.features().windows(2) {
        for property in PROPERTIES {
            if pair[1].starts_with(&format!(":n.{property}")) {
                properties.insert(pair[0].clone(), property.to_owned());
            }
        }
    }
    (properties.len() == PROPERTIES.len()).then_some(Fields { properties })
}

impl Fields {
    #[must_use]
    pub(crate) fn collect(&self, source: &JsObject) -> JsObject {
        let navigator = registry::project(&self.properties, Some(source), Missing::Omitted);
        JsObject::from_iter([
            (
                reference::WORKER_NAVIGATOR_INDICATOR.to_owned(),
                JsValue::from(0),
            ),
            (
                reference::WORKER_NAVIGATOR_RESULT.to_owned(),
                JsValue::Object(navigator),
            ),
        ])
    }
}
