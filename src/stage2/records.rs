//! The common record envelope around each native collection operation.

use std::sync::OnceLock;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::payload::{Document, Layout, State};
use super::reference::ERROR_MESSAGE_LENGTH_RESULT;
use super::registry::{Kind, Operation};
use super::vocabulary::Vocabulary;
use crate::js::{self, JsObject, JsValue, Options, Payload, json};

/// Initial status set by the record wrapper before collection.
pub(crate) const INITIAL_STATUS: u8 = 0;
/// The status of a record whose probe completed.
pub(crate) const COMPLETED_STATUS: u8 = 3;

/// Probe-envelope field names for counter, token, input, and completion data.
#[derive(Debug, Deserialize, Serialize)]
pub struct Envelope {
    pub counter: String,
    pub token: String,
    pub input: String,
    #[serde(flatten)]
    pub completion: Completion,
}

/// Completion field names shared by probe and checkbox records: status, message, timestamps,
/// and duration.
#[derive(Debug, Deserialize, Serialize)]
pub struct Completion {
    pub status: String,
    pub message: String,
    pub started: String,
    pub finished: String,
    pub duration: String,
}

impl Envelope {
    #[must_use]
    pub fn names(&self) -> [&str; 8] {
        let completion = &self.completion;
        [
            &self.counter,
            &self.token,
            &self.input,
            &completion.status,
            &completion.message,
            &completion.started,
            &completion.finished,
            &completion.duration,
        ]
    }
}

impl Completion {
    /// Completes a record initialized with `created`, token, and input. Writes success status,
    /// an empty message, early result fields, timestamps, duration, and late callback fields in
    /// that order. Preserves negative durations when the wall clock moves backward. Rejects
    /// writes to envelope fields or `reserved` names.
    pub fn complete(
        &self,
        created: [(String, JsValue); 2],
        fields: ArrangedFields,
        reserved: &[&str],
        started: i64,
        finished: i64,
    ) -> Result<JsObject> {
        let mut record = JsObject::from_iter(created);
        record.insert(self.status.clone(), json!(COMPLETED_STATUS));
        record.insert(self.message.clone(), json!(""));
        let marked = [&self.started, &self.finished, &self.duration];
        let write = |record: &mut JsObject, (field, value): (String, JsValue)| {
            ensure!(
                !record.contains_key(&field)
                    && !marked.contains(&&field)
                    && !reserved.contains(&field.as_str()),
                "collector overwrote record field {field}"
            );
            record.insert(field, value);
            Ok(())
        };
        for field in fields.early {
            write(&mut record, field)?;
        }
        record.insert(self.started.clone(), json!(started));
        record.insert(self.finished.clone(), json!(finished));
        record.insert(self.duration.clone(), json!(finished - started));
        for field in fields.late {
            write(&mut record, field)?;
        }
        Ok(record)
    }
}

/// Result fields grouped by when they reach the record: before or after its timestamps. Late
/// fields come from callbacks that finish after the probe.
#[derive(Debug, Default)]
pub struct ArrangedFields {
    pub early: JsObject,
    pub late: JsObject,
}

impl ArrangedFields {
    /// Splits `fields` into early and late writes according to `late`, preserving order within
    /// each group.
    #[must_use]
    pub fn split(fields: JsObject, late: &[String]) -> Self {
        let (late, early) = fields
            .into_iter()
            .partition(|(name, _)| late.contains(name));
        Self { early, late }
    }
}

/// A probe numbered from one in execution order, with its recognized operation if available.
#[derive(Debug, Deserialize)]
pub struct Probe {
    /// The probe's number, counting from one, which keys its record in the payload.
    pub index: usize,
    pub token: String,
    pub input: JsValue,
    pub operation: Option<Operation>,
    /// The strings the probe's collection function uses, in order.
    pub features: Vec<String>,
    /// Recovered write order used to arrange computed fields. Replayed answers retain the
    /// browser's recorded order.
    #[serde(default)]
    pub writes: WriteOrder,
}

impl Probe {
    /// Where the probe sits among the program's probes, counting from zero.
    #[must_use]
    pub fn position(&self) -> usize {
        self.index - 1
    }
}

/// The order in which a probe's collection function writes its record's fields.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WriteOrder {
    /// Stored names in execution order: the synchronous body first, then its callbacks.
    pub fields: Vec<String>,
    /// Fields that only callbacks write after the probe has finished. They follow the clock
    /// marks.
    pub late: Vec<String>,
}

impl WriteOrder {
    /// Orders `fields` by recovered write order and separates late writes. If any field has no
    /// known position, keeps the collector's order.
    #[must_use]
    pub fn arrange(&self, mut fields: JsObject) -> ArrangedFields {
        let position = |name: &str| self.fields.iter().position(|field| field == name);
        if fields.keys().all(|name| position(name).is_some()) {
            fields.sort_by_key(|name, _| position(name));
        }
        ArrangedFields::split(fields, &self.late)
    }
}

/// Recovered envelope names, ordered probes, and payload layout.
///
/// Probes are numbered consecutively from one: position `p` has index `p + 1`.
#[derive(Debug, Deserialize)]
pub struct ProbePlan {
    pub record_fields: Envelope,
    pub(crate) probes: Vec<Probe>,
    pub payload: Layout,
    /// Trace frame left by the probe before the environment audit. Replaces the iframe callback
    /// frame in the audit group key. Absent if no such frame is recovered.
    pub controller_trace: Option<String>,
    /// Maps session probe names to reference names. Deserialized plans infer the mapping from
    /// their features on first use.
    #[serde(skip)]
    pub(crate) vocabulary: OnceLock<Vocabulary>,
}

impl ProbePlan {
    /// The probes, in the order the program runs them.
    #[must_use]
    pub fn probes(&self) -> &[Probe] {
        &self.probes
    }

    /// Returns the first probe with an operation of `kind`, together with that operation.
    #[must_use]
    pub fn operation(&self, kind: Kind) -> Option<(&Probe, &Operation)> {
        self.probes.iter().find_map(|probe| {
            let operation = probe.operation.as_ref()?;
            (operation.kind() == kind).then_some((probe, operation))
        })
    }

    #[must_use]
    pub fn vocabulary(&self) -> &Vocabulary {
        self.vocabulary.get_or_init(|| {
            let features: Vec<&[String]> = self
                .probes
                .iter()
                .map(|probe| probe.features.as_slice())
                .collect();
            Vocabulary::infer(&features)
        })
    }

    /// The selectors the iframe queries, in order, starting with the program's frame-element
    /// lookup. `options` decide whether the isolation probe queries its CSP nonce.
    #[must_use]
    pub fn selector_log(&self, options: &Options) -> Vec<String> {
        let mut selectors = vec!["window.frameElement".to_owned()];
        for probe in &self.probes {
            let Some(operation) = &probe.operation else {
                continue;
            };
            selectors.extend(operation.selectors());
            // The isolation probe's srcdoc check takes its CSP nonce from an option, falling back
            // to a document query. The option's name follows the last `_cf_chl_opt` before it.
            let features = &probe.features;
            if let Some(query) = features.iter().position(|text| text == "script[nonce]") {
                let supplied = features[..query]
                    .iter()
                    .rposition(|text| text == "_cf_chl_opt")
                    .and_then(|index| features.get(index + 1))
                    .and_then(|name| options.get(name))
                    .is_some_and(js::truthy);
                if !supplied {
                    selectors.push("script[nonce]".into());
                }
            }
        }
        selectors
    }

    /// Collects result fields, arranged around the clock marks, independently for each probe in
    /// order. Any error aborts assembly.
    pub fn collect_records_with(
        &self,
        mut collect: impl FnMut(&Probe) -> Result<ArrangedFields>,
        mut now: impl FnMut() -> i64,
    ) -> Result<JsObject> {
        let mut records = JsObject::new();
        for probe in &self.probes {
            let started = now();
            let fields = collect(probe)?;
            let finished = now();
            let created = [
                (self.record_fields.token.clone(), json!(probe.token)),
                (self.record_fields.input.clone(), probe.input.clone()),
            ];
            let completion = &self.record_fields.completion;
            let record = completion.complete(created, fields, &[], started, finished)?;
            records.insert(probe.index.to_string(), JsValue::Object(record));
        }
        Ok(records)
    }

    /// Builds the second POST payload from indexed probe `records`, before the sender appends
    /// its send-time fields (see [`crate::challenge::payload::append_send_time`]). `state` holds
    /// the first payload as input; `pending_ms` is the wait for outstanding work.
    pub(crate) fn assemble(
        &self,
        state: &State<'_>,
        records: JsObject,
        document: &Document,
        pending_ms: i64,
    ) -> Result<Payload> {
        // The error-message probe publishes its length beside its record.
        let mut lengths = JsObject::new();
        for probe in &self.probes {
            if let Some(Operation::ErrorMessageLength {}) = &probe.operation {
                let field = self
                    .vocabulary()
                    .to_session(probe.position(), ERROR_MESSAGE_LENGTH_RESULT);
                let length = records
                    .get(&probe.index.to_string())
                    .and_then(|record| record.get(field))
                    .cloned()
                    .with_context(|| format!("probe {} recorded no length", probe.index))?;
                lengths.insert(field.to_owned(), length);
            }
        }
        let counter = &self.record_fields.counter;
        self.payload
            .assemble(state, document, records, counter, lengths, Some(pending_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plan of `probes` whose envelope fields are named after their roles.
    fn plan(probes: JsValue) -> ProbePlan {
        js::from_value(json!({
            "record_fields":{"counter":"counter", "token":"token", "input":"input",
                "status":"status", "message":"message", "started":"started",
                "finished":"finished", "duration":"duration"},
            "payload":{"template":{"fields":{}}, "published":[], "footer":{}, "pending":null},
            "probes": probes,
        }))
        .unwrap()
    }

    /// Callbacks that outlive a probe write their fields after its clock marks.
    #[test]
    fn records_are_collected_in_order_with_signed_clock_differences() {
        let plan = plan(json!([
            {"index":1,"token":"first","input":[],"operation":{"kind":"empty"},"features":[]},
            {"index":2,"token":"second","input":{},"operation":{"kind":"empty"},"features":[]}
        ]));
        let mut calls = Vec::new();
        let mut clocks = [100, 98, 101, 105].into_iter();
        let records = plan
            .collect_records_with(
                |probe| {
                    calls.push(probe.index);
                    let fields = JsObject::from_iter([
                        ("result".into(), json!(probe.index)),
                        ("callback".into(), json!(true)),
                    ]);
                    Ok(ArrangedFields::split(fields, &["callback".to_owned()]))
                },
                || clocks.next().unwrap(),
            )
            .unwrap();
        assert_eq!(calls, [1, 2]);
        // Compare serialized JSON to check field order too.
        assert_eq!(
            records["1"].to_string(),
            r#"{"token":"first","input":[],"status":3,"message":"","result":1,"started":100,"finished":98,"duration":-2,"callback":true}"#
        );
        assert_eq!(records["2"]["duration"], 4);
        let status = || ArrangedFields {
            early: JsObject::from_iter([("status".into(), json!(0))]),
            ..ArrangedFields::default()
        };
        assert!(
            plan.collect_records_with(|_| Ok(status()), || 0).is_err(),
            "a collector may not overwrite the record's envelope"
        );
    }

    #[test]
    fn isolation_nonce_lookup_is_logged_only_without_a_supplied_nonce() {
        let plan = plan(json!([{"index":1, "token":"token", "input":null,
            "operation":{"kind":"replay", "reference":35},
            "features":["_cf_chl_opt", "random_nonce_option", "", "script[nonce]",
                "querySelector"]}]));
        let queried = ["window.frameElement", "script[nonce]"];
        for nonce in [JsValue::Null, json!(false), json!(0), json!("")] {
            let options = Options::from_iter([("random_nonce_option".into(), nonce)]);
            assert_eq!(plan.selector_log(&options), queried);
        }
        let supplied = Options::from_iter([("random_nonce_option".into(), json!("supplied"))]);
        assert_eq!(plan.selector_log(&supplied), ["window.frameElement"]);
        assert_eq!(plan.selector_log(&Options::new()), queried);
    }
}
