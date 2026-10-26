//! Recovered fields for the network information probe.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::stage2::analysis::recognize::ProbeView;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    /// Maps output fields to connection properties in the order the probe stores them.
    #[serde(rename = "fields")]
    pub properties: IndexMap<String, String>,
}

/// Recovers `navigator.connection` properties from the strings after their output names.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    const PROPERTIES: [&str; 6] = [
        "downlink",
        "downlinkMax",
        "effectiveType",
        "rtt",
        "saveData",
        "type",
    ];
    let strings = &probe.strings;
    if !(strings.has("connection") && strings.has("downlinkMax")) {
        return None;
    }
    let mut properties = IndexMap::new();
    for pair in strings.features().windows(2) {
        if PROPERTIES.contains(&pair[1].as_str()) && !PROPERTIES.contains(&pair[0].as_str()) {
            properties.insert(pair[0].clone(), pair[1].clone());
        }
    }
    let stored = properties.keys().all(|field| strings.stores(field));
    (properties.len() == PROPERTIES.len() && stored).then_some(Fields { properties })
}
