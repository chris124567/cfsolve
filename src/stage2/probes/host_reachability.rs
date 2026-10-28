//! Measures worker fetch times for Cloudflare hosts. Some builds from 2026-10-27 onward include
//! this probe; the reference build has no matching probe.
//!
//! The worker fetches each URL with `{method: "GET", mode: "cors", credentials: "omit", cache:
//! "no-store", redirect: "error", referrerPolicy: "no-referrer"}`. It reports the response time,
//! rejection, or exception. Each result is `[elapsed, status]`; `elapsed` is null unless a response
//! arrived.

use serde::{Deserialize, Serialize};

use crate::js::{JsObject, JsValue, json};
use crate::stage2::analysis::recognize::ProbeView;

/// Worker script prefix, completed with the URL for each fetch.
const SCRIPT: &str = "var t=Date.now();try{fetch(";

/// URLs fetched by the probe and field names used in its results.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub urls: Vec<String>,
    /// Result field written after all fetches finish.
    pub result: String,
    /// Status strings for a response and a rejected fetch.
    pub answered: String,
    pub rejected: String,
}

/// Outcome of one fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Answered { elapsed_ms: i64 },
    Rejected,
}

impl Fields {
    #[must_use]
    pub fn collect(&self, outcomes: &[Outcome]) -> JsObject {
        let results: Vec<JsValue> = outcomes
            .iter()
            .map(|outcome| match outcome {
                Outcome::Answered { elapsed_ms } => json!([elapsed_ms, self.answered]),
                Outcome::Rejected => json!([null, self.rejected]),
            })
            .collect();
        JsObject::from_iter([(self.result.clone(), JsValue::Array(results))])
    }
}

/// Recognizes the probe from its worker script. The message handler checks exception and rejection
/// flags before elapsed time. As a result, the status strings appear before the script in this
/// order: answered, rejected, threw.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let strings = probe.session_features;
    let script = strings.iter().position(|text| text == SCRIPT)?;
    let [answered, rejected, _threw] = strings.get(script.checked_sub(3)?..script)? else {
        return None;
    };
    let urls: Vec<String> = strings
        .iter()
        .filter(|text| text.starts_with("https://") && text.ends_with('/'))
        .cloned()
        .collect();
    let [result] = &probe.writes.late[..] else {
        return None;
    };
    (!urls.is_empty()).then(|| Fields {
        urls,
        result: result.clone(),
        answered: answered.clone(),
        rejected: rejected.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_each_fetch_as_elapsed_and_status() {
        let fields = Fields {
            urls: vec!["https://a.example/".into(), "https://b.example/".into()],
            result: "r".into(),
            answered: "ok".into(),
            rejected: "no".into(),
        };
        let outcomes = [Outcome::Rejected, Outcome::Answered { elapsed_ms: 12 }];
        assert_eq!(
            JsValue::Object(fields.collect(&outcomes)),
            json!({"r": [[null, "no"], [12, "ok"]]})
        );
    }
}
