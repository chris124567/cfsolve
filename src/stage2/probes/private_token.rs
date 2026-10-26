//! Builds the Private Access Token worker result and elapsed wall-clock duration.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use super::platform;
use crate::js::{JsObject, JsValue, Options, json};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

pub(crate) const OUTPUTS: [&str; 5] = [
    reference::SHARED_RESULT,
    reference::PRIVATE_TOKEN_ELAPSED,
    reference::PRIVATE_TOKEN_ERROR,
    reference::PRIVATE_TOKEN_TOKEN,
    reference::PRIVATE_TOKEN_TIMESTAMP,
];

/// Maximum response length in UTF-16 code units, as limited by `substring`.
const LIMIT_UTF16: usize = 2048;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub token_value: String,
    pub timestamp_value: String,
    pub url_path: String,
    /// The session's option naming the platform segment of the request path.
    pub platform_property: String,
}

/// How the worker's fetch settled.
pub enum WorkerOutcome {
    Response { ok: bool, status: u16, text: String },
    Rejected { worker_error: String },
}

pub struct Measurement {
    pub outcome: WorkerOutcome,
    pub started_ms: i64,
    pub finished_ms: i64,
}

impl Fields {
    /// Builds the resource URL using the family's platform segment and path.
    pub fn url(&self, options: &Options, input: &JsValue, base: &Url) -> Result<Url> {
        platform::url(
            options,
            &self.platform_property,
            &self.url_path,
            input,
            base,
        )
    }

    /// Builds a record from truncated response text or a fetch error, plus elapsed time.
    pub fn collect(&self, input: &Measurement) -> Result<JsObject> {
        let elapsed = input
            .finished_ms
            .checked_sub(input.started_ms)
            .context("PAT elapsed duration overflow")?;
        let fields = [
            (reference::PRIVATE_TOKEN_TOKEN, json!(self.token_value)),
            (
                reference::PRIVATE_TOKEN_TIMESTAMP,
                json!(self.timestamp_value),
            ),
            (reference::PRIVATE_TOKEN_ELAPSED, json!(elapsed)),
        ];
        let mut fields =
            JsObject::from_iter(fields.map(|(field, value)| (field.to_owned(), value)));
        let result = match &input.outcome {
            WorkerOutcome::Response { ok, status, text } => {
                let text = if *ok {
                    text.clone()
                } else {
                    format!("status_{status}")
                };
                let units: Vec<u16> = text.encode_utf16().take(LIMIT_UTF16).collect();
                String::from_utf16(&units).context("PAT substring ends in an unpaired surrogate")?
            }
            WorkerOutcome::Rejected { worker_error } => {
                // The parent creates a new Error from the worker's stringified error. The
                // promise catch then stringifies that new Error.
                fields.insert(
                    reference::PRIVATE_TOKEN_ERROR.to_owned(),
                    json!(if worker_error.is_empty() {
                        "Error".into()
                    } else {
                        format!("Error: {worker_error}")
                    }),
                );
                "E".into()
            }
        };
        fields.insert(reference::SHARED_RESULT.to_owned(), json!(result));
        Ok(fields)
    }
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let strings = &probe.strings;
    let markers = [
        "isSecureContext",
        "no-cache",
        "follow",
        "status_",
        "substring",
        reference::PRIVATE_TOKEN_TIMEOUT_ERROR,
        reference::PRIVATE_TOKEN_WORKER_REPLIED,
        reference::PRIVATE_TOKEN_WORKER_ERROR,
        ").then(function(r){return r.text().then(function(b){postMessage({",
    ];
    if !(strings.stores_all(&OUTPUTS) && strings.has_all(&markers)) {
        return None;
    }
    Some(Fields {
        token_value: strings.decoded_after(reference::PRIVATE_TOKEN_TOKEN)?,
        timestamp_value: strings.decoded_after(reference::PRIVATE_TOKEN_TIMESTAMP)?,
        url_path: strings.decoded_starting("/pat/")?,
        platform_property: probe.session_name(reference::PLATFORM_OPTION),
    })
}
