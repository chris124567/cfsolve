//! Registers probe families, recovered operations, profile [`Facts`], and current-session
//! [`Observed`] measurements.
//!
//! Each family provides `recognize(&ProbeView) -> Option<Fields>` and may provide `collect` to
//! compute answers. `families!` registers them in recognition order within each phase. Families
//! with no recovered fields return `Some(())` when recognized.

use std::fmt;

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use super::analysis::recognize::{Phase, ProbeView};
use super::probes::{
    clock, dates, dom_mutation, empty, error_message_length, host_reachability, image, media,
    network_information, parent_info, performance, private_token, rects, stack, websocket_echo,
    worker_fetch, worker_navigator,
};
use super::{benchmark, proof};
use crate::embedding_page::page::PageSignals;
use crate::engine::Engine;
use crate::js::{JsObject, JsValue};

/// Whether a probe uses stored answers or current measurements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Treatment {
    /// Replayed device facts, patched by [`super::replay::Session`] for this session.
    Replayed,
    /// Current requests, connection state, timing, or page data.
    Computed,
}

/// Constructs a family variant holding `$bind`. Tuple variants use brace syntax and field `0`;
/// variants without fields take `()`.
macro_rules! variant {
    ($variant:ident {}, $bind:ident) => {{
        let () = $bind;
        Operation::$variant {}
    }};
    ($variant:ident { $field:ident : $type:ty }, $bind:ident) => {
        Operation::$variant { $field: $bind }
    };
    ($variant:ident($type:ty), $bind:ident) => {
        Operation::$variant { 0: $bind }
    };
}

/// Declares each family's saved representation, module, name, recognition phase, answer source,
/// and one-based reference probe indices. Includes reference indices for empty wrappers and
/// families supported only by replay.
macro_rules! families {
    (
        $( $variant:ident $shape:tt => $module:ident, $name:literal, $phase:ident, $treatment:ident, [$($reference:literal),*]; )*
        @empty [$($empty:literal),*];
        @replayed { $( $stored:ident => $stored_name:literal, $position:literal; )* }
    ) => {
        /// A probe's recovered operation fields or replay source.
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        pub enum Operation {
            $( #[serde(rename = $name)] $variant $shape, )*
            /// A wrapper whose successful path only changes status and timing.
            Empty,
            /// A device-fact answer replayed from the paired reference probe's one-based index.
            Replay { reference: usize },
        }

        /// A probe family, independent of its randomized output fields.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Kind {
            $( $variant, )*
            Empty,
            Replay,
            $( $stored, )*
        }

        impl Kind {
            /// All families, with recognized families in precedence order.
            pub const ALL: &'static [Self] =
                &[$(Self::$variant,)* Self::Empty, Self::Replay, $(Self::$stored,)*];

            /// Returns the family's name used in saved plans and profile durations.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                    Self::Empty => "empty",
                    Self::Replay => "replay",
                    $(Self::$stored => $stored_name,)*
                }
            }

            #[must_use]
            pub const fn treatment(self) -> Treatment {
                match self {
                    $(Self::$variant => Treatment::$treatment,)*
                    Self::Empty => Treatment::Computed,
                    Self::Replay $(| Self::$stored)* => Treatment::Replayed,
                }
            }

            /// Recognition phase, if this family has a recognizer.
            const fn phase(self) -> Option<Phase> {
                match self {
                    $(Self::$variant => Some(Phase::$phase),)*
                    Self::Empty => Some(Phase::Structural),
                    _ => None,
                }
            }

            /// The families `phase` recognizes, in precedence order.
            pub(crate) fn in_phase(phase: Phase) -> impl Iterator<Item = Self> {
                Self::ALL.iter().copied().filter(move |kind| kind.phase() == Some(phase))
            }

            pub(crate) fn recognize(self, probe: &ProbeView<'_>) -> Option<Operation> {
                match self {
                    $(Self::$variant => {
                        $module::recognize(probe).map(|fields| variant!($variant $shape, fields))
                    })*
                    Self::Empty => empty::recognize(probe).map(|()| Operation::Empty),
                    _ => None,
                }
            }

            /// The family of the one-based reference probe `reference`.
            #[must_use]
            pub fn from_reference(reference: usize) -> Option<Self> {
                Self::ALL.iter().copied().find(|kind| kind.references().contains(&reference))
            }

            /// Returns the family's one-based reference probe indices.
            #[must_use]
            pub const fn references(self) -> &'static [usize] {
                match self {
                    $(Self::$variant => &[$($reference),*],)*
                    Self::Empty => &[$($empty),*],
                    Self::Replay => &[],
                    $(Self::$stored => &[$position],)*
                }
            }
        }

        impl Operation {
            #[must_use]
            pub fn kind(&self) -> Kind {
                match self {
                    $(Self::$variant { .. } => Kind::$variant,)*
                    Self::Empty => Kind::Empty,
                    Self::Replay { .. } => Kind::Replay,
                }
            }
        }
    };
}

families! {
    Media { fields: Box<media::Fields> } =>
        media, "media", Reference, Computed, [16];
    PrivateToken { fields: private_token::Fields } =>
        private_token, "private_token", Reference, Computed, [4];
    WorkerFetch { fields: worker_fetch::Fields } =>
        worker_fetch, "worker_fetch", Reference, Computed, [5];
    Image { fields: image::Fields } =>
        image, "image", Reference, Computed, [30];
    ParentInfo {} =>
        parent_info, "parent_info", Reference, Computed, [24];
    DateParsingOffsets(dates::Fields) =>
        dates, "date_parsing_offsets", Reference, Computed, [38];
    // The payload publishes the error-message length beside the record.
    ErrorMessageLength {} =>
        error_message_length, "error_message_length", Reference, Replayed, [3];
    NetworkInformation(network_information::Fields) =>
        network_information, "network_information", Reference, Computed, [29];
    WorkerNavigator(worker_navigator::Fields) =>
        worker_navigator, "worker_navigator", Reference, Computed, [1];
    ClockResolution {} =>
        clock, "clock_resolution", Reference, Computed, [9];
    Benchmark { fields: benchmark::Fields } =>
        benchmark, "benchmark", Structural, Computed, [];
    // Element ID queries from this probe appear in the selector log.
    Rects { fields: rects::Fields } =>
        rects, "rects", Structural, Replayed, [37];
    DomMutation { fields: dom_mutation::Fields } =>
        dom_mutation, "dom_mutation", Structural, Computed, [17];
    PerformanceEntries { fields: performance::Fields } =>
        performance, "performance_entries", Structural, Computed, [36];
    // Rebuilt from the session's own script. The reference build's stack probe is probe 28.
    Stack { fields: stack::Fields } =>
        stack, "stack", Structural, Computed, [28];
    HostReachability { fields: host_reachability::Fields } =>
        host_reachability, "host_reachability", Structural, Computed, [];
    WebSocketEcho { fields: websocket_echo::Fields } =>
        websocket_echo, "websocket_echo", Structural, Computed, [];
    @empty [11, 26, 33];
    @replayed {
        EnvironmentAudit => "environment_audit", 2;
        Environment => "environment", 6;
        HighEntropyUserAgent => "high_entropy_user_agent", 7;
        EmojiColor => "emoji_color", 8;
        Behavior => "behavior", 10;
        KeyboardLayout => "keyboard_layout", 12;
        Console => "console", 13;
        Math => "math", 14;
        DocumentStructure => "document_structure", 15;
        Graphics => "graphics", 18;
        SvgGeometry => "svg_geometry", 19;
        SummarizerAvailability => "summarizer_availability", 20;
        Audio => "audio", 21;
        NativeInspection => "native_inspection", 22;
        FontEnumeration => "font_enumeration", 23;
        DocumentSummary => "document_summary", 25;
        ComputedStyleHash => "computed_style_hash", 27;
        Intl => "intl", 31;
        Storage => "storage", 32;
        Stylesheets => "stylesheets", 34;
        Isolation => "isolation", 35;
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Copies properties into output fields using `properties`.
#[must_use]
pub(super) fn project(
    properties: &IndexMap<String, String>,
    source: Option<&JsObject>,
    missing: Missing,
) -> JsObject {
    let mut result = JsObject::new();
    for (field, property) in properties {
        if let Some(value) = source.and_then(|source| source.get(property)) {
            result.insert(field.clone(), value.clone());
        } else if missing == Missing::Null {
            result.insert(field.clone(), JsValue::Null);
        }
    }
    result
}

/// How [`project`] writes a property the source lacks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Missing {
    Null,
    /// Omitted, as `undefined` is.
    Omitted,
}

/// The reference build's environment-audit probe.
pub const AUDIT_PROBE: usize = Kind::EnvironmentAudit.references()[0];

/// Read-only profile inputs for computed probes. Maps use stable API property names rather than
/// randomized output names.
#[derive(Deserialize)]
pub struct Facts {
    #[serde(default)]
    pub navigator: JsObject,
    pub connection: Option<JsObject>,
    /// Recorded media capabilities and connection, which the session refreshes.
    pub media: Option<media::Measurement>,
    /// Whether the worker fetch probe's request fails before it reaches the network, as it does
    /// in every iOS Safari 26.6 capture.
    #[serde(default)]
    pub worker_fetch_rejected: bool,
    /// The browser's own cost of running the interaction's proof workers.
    pub proof_worker: proof::WorkerCosts,
    /// The browser's own cost of instantiating and running the benchmark's module.
    pub benchmark_worker: benchmark::WorkerCosts,
}

/// Current-session observations used by computed probes.
#[derive(Default)]
pub struct Observed {
    /// What the embedding page reported about itself, which the parent info probe copies.
    pub(crate) page_signals: Option<PageSignals>,
    pub media: Option<media::Measurement>,
    pub private_token: Option<private_token::Measurement>,
    pub worker_fetch: Option<worker_fetch::Measurement>,
    /// Host reachability fetch outcomes in URL order.
    pub host_reachability: Option<Vec<host_reachability::Outcome>>,
    pub websocket_echo: Option<websocket_echo::Measurement>,
    pub image: Option<image::Measurement>,
    pub performance: Option<performance::Measurement>,
    /// Pairs of consecutive worker clock readings.
    pub clock: Option<Vec<[f64; 2]>>,
    pub benchmark: Option<benchmark::Measurement>,
    /// The stack probe's result, rebuilt from this session's script.
    pub stack: Option<String>,
}

impl Observed {
    /// Returns the measured duration of completed work for a probe of `kind` in this session.
    #[must_use]
    pub fn duration_ms(&self, kind: Kind) -> Option<i64> {
        match kind {
            Kind::Benchmark => self
                .benchmark
                .as_ref()
                .map(|run| run.elapsed_ms().ceil() as i64),
            Kind::WebSocketEcho => self.websocket_echo.as_ref().map(|run| run.elapsed_ms),
            _ => None,
        }
    }
}

impl Operation {
    /// Tries reference recognizers, then structural ones, and returns the first match.
    #[must_use]
    pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Self> {
        Kind::in_phase(Phase::Reference)
            .chain(Kind::in_phase(Phase::Structural))
            .find_map(|kind| kind.recognize(probe))
    }

    /// Collects result fields using `engine`'s behavior. Families recognized by the reference
    /// build name their fields as it does; the session's vocabulary renames them. Common status
    /// and timing fields are added separately.
    pub fn collect(&self, facts: &Facts, observed: &Observed, engine: Engine) -> Result<JsObject> {
        fn measured<'a, T: ?Sized>(measurement: Option<&'a T>, what: &str) -> Result<&'a T> {
            measurement.with_context(|| format!("missing {what}"))
        }
        match self {
            Self::Media { fields } => {
                fields.collect(measured(observed.media.as_ref(), "media measurements")?)
            }
            Self::PrivateToken { fields } => fields.collect(measured(
                observed.private_token.as_ref(),
                "private-token measurement",
            )?),
            Self::WorkerFetch { fields } => Ok(fields.collect(measured(
                observed.worker_fetch.as_ref(),
                "worker fetch measurement",
            )?)),
            Self::HostReachability { fields } => Ok(fields.collect(measured(
                observed.host_reachability.as_deref(),
                "host reachability measurement",
            )?)),
            Self::WebSocketEcho { fields } => Ok(fields.collect(measured(
                observed.websocket_echo.as_ref(),
                "WebSocket echo measurement",
            )?)),
            Self::Image { fields } => {
                Ok(fields.collect(measured(observed.image.as_ref(), "image measurement")?))
            }
            Self::PerformanceEntries { fields } => fields.collect(measured(
                observed.performance.as_ref(),
                "performance entry measurement",
            )?),
            Self::ClockResolution {} => clock::collect(measured(
                observed.clock.as_ref(),
                "worker clock measurement",
            )?),
            Self::Benchmark { fields } => Ok(fields.collect(measured(
                observed.benchmark.as_ref(),
                "benchmark measurements",
            )?)),
            Self::ParentInfo {} => Ok(parent_info::collect(measured(
                observed.page_signals.as_ref(),
                "the embedding page's signals",
            )?)),
            Self::DateParsingOffsets(fields) => fields.collect(engine),
            Self::NetworkInformation(fields) => {
                let connection = facts.connection.as_ref();
                Ok(project(&fields.properties, connection, Missing::Null))
            }
            Self::WorkerNavigator(fields) => Ok(fields.collect(&facts.navigator)),
            Self::DomMutation { fields } => fields.collect(),
            Self::Stack { fields } => {
                Ok(fields.collect(measured(observed.stack.as_deref(), "rebuilt stack")?))
            }
            Self::Empty => Ok(JsObject::new()),
            Self::ErrorMessageLength {} | Self::Rects { .. } | Self::Replay { .. } => bail!(
                "a {} probe is answered from the stored answers",
                self.kind()
            ),
        }
    }

    /// Replayed operations use the family of their reference probe.
    #[must_use]
    pub fn family(&self) -> Kind {
        match self {
            Self::Replay { reference } => Kind::from_reference(*reference).unwrap_or(Kind::Replay),
            operation => operation.kind(),
        }
    }

    /// The selectors the probe queries, in order. The iframe logs every query and reports the log
    /// with the payload.
    #[must_use]
    pub fn selectors(&self) -> Vec<String> {
        match self {
            Self::DomMutation { fields } => fields.selectors(),
            Self::Rects { fields } => fields.selectors(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::{self, json};
    use crate::stage2::reference::{self, REFERENCE};

    /// Builds test facts with zero worker overhead and values supplied by `extra`.
    fn facts(extra: JsValue) -> Facts {
        let mut facts = json!({"proof_worker": {"startup_ms": [0], "digest_us": [0]},
            "benchmark_worker": {"compile_ms": [0], "kernel_ms_per_million": [[1], [1], [1], [1]]}});
        if let (JsValue::Object(facts), JsValue::Object(extra)) = (&mut facts, extra) {
            facts.extend(extra);
        }
        js::from_value(facts).unwrap()
    }

    #[test]
    fn the_families_name_every_reference_probe() {
        let probes = REFERENCE.probes.len();
        assert!((1..=probes).all(|reference| Kind::from_reference(reference).is_some()));
        assert_eq!(Kind::from_reference(probes + 1), None);
        assert_eq!(Kind::from_reference(0), None);
        assert_eq!(
            Kind::from_reference(AUDIT_PROBE),
            Some(Kind::EnvironmentAudit)
        );
    }

    /// A missing measurement is an error rather than an empty result.
    #[test]
    fn clock_collection_needs_a_measurement() {
        let operation = Operation::ClockResolution {};
        let error = operation
            .collect(&facts(json!({})), &Observed::default(), Engine::Chromium)
            .unwrap_err();
        assert_eq!(error.to_string(), "missing worker clock measurement");
        let replayed = Operation::Replay { reference: 3 };
        assert!(
            replayed
                .collect(&facts(json!({})), &Observed::default(), Engine::Chromium)
                .is_err()
        );
    }

    /// Network information keeps false and zero and returns null for missing properties; the
    /// worker navigator omits undefined values.
    #[test]
    fn profile_facts_are_copied_into_output_fields() {
        let network = json!({"kind": "network_information",
            "fields": {"a": "downlink", "b": "saveData", "c": "type"}});
        let worker = json!({"kind": "worker_navigator",
            "fields": {"a": "platform", "b": "deviceMemory"}});
        let cases = [
            (
                &network,
                json!({"connection": {"downlink": 0, "saveData": false}}),
                json!({"a": 0, "b": false, "c": null}),
            ),
            (
                &network,
                json!({}),
                json!({"a": null, "b": null, "c": null}),
            ),
            (
                &worker,
                json!({"navigator": {"platform": "Linux x86_64"}}),
                json!({(reference::WORKER_NAVIGATOR_INDICATOR): 0,
                    (reference::WORKER_NAVIGATOR_RESULT): {"a": "Linux x86_64"}}),
            ),
        ];
        for (operation, extra, expected) in cases {
            let operation: Operation = js::from_value(operation.clone()).unwrap();
            let fields = operation.collect(&facts(extra), &Observed::default(), Engine::Chromium);
            assert_eq!(JsValue::Object(fields.unwrap()), expected);
        }
    }
}
