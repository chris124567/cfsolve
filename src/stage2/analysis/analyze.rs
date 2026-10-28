//! Runs the analysis pipeline described by [`super`].

use std::collections::BTreeSet;
use std::sync::OnceLock;

use anyhow::Result;
use serde::Serialize;

use super::recognize::{ProbeView, Strings};
use super::{audit, controller, discovery, envelope};
use crate::candidates;
use crate::js::JsValue;
use crate::listing::Index;
use crate::script::Source;
use crate::stage2::payload::{self, Layout};
use crate::stage2::records::{Envelope, Probe, ProbePlan, WriteOrder};
use crate::stage2::registry::{AUDIT_PROBE, Operation};
use crate::stage2::trace::Trace;
use crate::stage2::vocabulary::Vocabulary;
use crate::vm::{Failure, Position};

/// A recovered probe plan with supporting analysis evidence.
pub struct Analysis {
    plan: ProbePlan,
    program_bytes: usize,
    instructions: usize,
    /// The program's string pool, and where it is loaded.
    pool_pc: u32,
    pool_text: String,
    /// Positions that do not decode.
    failures: Vec<Failure>,
    /// Each probe's evidence, in the plan's order.
    evidence: Vec<ProbeEvidence>,
}

/// How one probe was found and recognized.
#[derive(Debug)]
pub struct ProbeEvidence {
    /// Dispatcher states for record creation, result collection, and completion.
    pub states: [String; 3],
    /// Where its collection function starts.
    pub function: Position,
    /// The one-based index of the reference probe it was paired with.
    pub reference: Option<usize>,
}

impl Analysis {
    #[must_use]
    pub fn plan(&self) -> &ProbePlan {
        &self.plan
    }

    /// Each probe with its evidence, in the order the program runs them.
    pub fn probes(&self) -> impl Iterator<Item = (&Probe, &ProbeEvidence)> {
        self.plan.probes().iter().zip(&self.evidence)
    }

    #[must_use]
    pub fn artifact(&self) -> Artifact<'_> {
        let failures = self.failures.iter();
        let probes = self.probes().map(|(probe, evidence)| ProbeArtifact {
            index: probe.index,
            states: &evidence.states,
            token: &probe.token,
            input: &probe.input,
            function: (evidence.function.pc, evidence.function.key),
            operation: probe.operation.as_ref(),
            features: &probe.features,
            writes: &probe.writes,
            reference: evidence.reference,
        });
        Artifact {
            payload: &self.plan.payload,
            program_bytes: self.program_bytes,
            instructions: self.instructions,
            pool_pc: self.pool_pc,
            pool_text: &self.pool_text,
            failures: failures
                .map(|failure| (failure.pc, failure.key, failure.to_string()))
                .collect(),
            record_fields: &self.plan.record_fields,
            probes: probes.collect(),
            controller_trace: self.plan.controller_trace.as_deref(),
        }
    }
}

/// `stage2.json`, in its established field order and encodings.
#[derive(Serialize)]
pub struct Artifact<'analysis> {
    payload: &'analysis Layout,
    program_bytes: usize,
    instructions: usize,
    pool_pc: u32,
    pool_text: &'analysis str,
    /// `[pc, key, cause]` arrays.
    failures: Vec<(u32, u8, String)>,
    record_fields: &'analysis Envelope,
    probes: Vec<ProbeArtifact<'analysis>>,
    controller_trace: Option<&'analysis str>,
}

/// A probe in `stage2.json`, with its evidence.
#[derive(Serialize)]
struct ProbeArtifact<'analysis> {
    index: usize,
    states: &'analysis [String; 3],
    token: &'analysis str,
    input: &'analysis JsValue,
    /// The collection function's start, as a `[pc, key]` array.
    function: (u32, u8),
    operation: Option<&'analysis Operation>,
    features: &'analysis [String],
    writes: &'analysis WriteOrder,
    reference: Option<usize>,
}

/// Analyzes a probe program using the VM recovered from its session script.
pub fn analyze(source: &Source, program: &[u8]) -> Result<Analysis> {
    // Include `cf-chl-peek` when resolving hashed comparisons. The worker-fetch probe reads
    // this header but does not store its name as a program string.
    let machine = source.machine()?;
    let listing = machine.disassemble_from(program, &[machine.entry()], &["cf-chl-peek"])?;
    let index = Index::new(&listing);
    let (pool_pc, pool) = index.pool()?;
    let discovery = discovery::discover(&index, pool)?;
    let session_features: Vec<&[String]> = discovery
        .probes
        .iter()
        .map(|probe| probe.features.as_slice())
        .collect();
    let mut vocabulary = Vocabulary::infer(&session_features);
    for (position, raw) in discovery.probes.iter().enumerate() {
        if vocabulary.partner(position) == Some(AUDIT_PROBE)
            && let Some(names) = audit::names(&index, &raw.writes.fields)
        {
            vocabulary.pin(position, names);
        }
    }
    let header: BTreeSet<String> = index.header().values().cloned().collect();
    let mut wrapper: BTreeSet<String> = discovery
        .probes
        .first()
        .map(|first| first.features.iter().cloned().collect())
        .unwrap_or_default();
    for probe in &discovery.probes {
        wrapper.retain(|text| probe.features.contains(text));
    }
    let mut probes = Vec::new();
    let mut evidence = Vec::new();
    for (position, raw) in discovery.probes.into_iter().enumerate() {
        let to_reference = |text: &String| vocabulary.to_reference(position, text).to_owned();
        let features: Vec<String> = raw.features.iter().map(to_reference).collect();
        let outputs: BTreeSet<String> = raw.outputs.iter().map(to_reference).collect();
        let reference = vocabulary.partner(position);
        // Treat an unrecognized computed probe as a device fact and replay its paired reference
        // answer.
        let operation = Operation::recognize(&ProbeView {
            index: &index,
            vocabulary: &vocabulary,
            position,
            header: &header,
            wrapper: &wrapper,
            pool,
            entry: raw.function.pc,
            session_features: &raw.features,
            writes: &raw.writes,
            strings: Strings::new(&features, &outputs),
        })
        .or(reference.map(|reference| Operation::Replay { reference }));
        probes.push(Probe {
            index: raw.index,
            token: raw.token,
            input: raw.input,
            operation,
            features: raw.features,
            writes: raw.writes,
        });
        evidence.push(ProbeEvidence {
            states: raw.states,
            function: raw.function,
            reference,
        });
    }
    let scan = payload::scan(&index, pool);
    let record_fields = envelope::recover(
        &index,
        &probes,
        evidence.first().map_or(0, |evidence| evidence.function.pc),
        &discovery.creation,
        &discovery.finish,
        &scan.literals(),
    )?;
    let payload = scan.layout(&record_fields.counter)?;
    let controller_trace = Trace::recover(source)
        .and_then(|trace| controller_frame(&index, &evidence, trace.push.as_deref()?));
    Ok(Analysis {
        plan: ProbePlan {
            record_fields,
            probes,
            payload,
            controller_trace,
            vocabulary: OnceLock::from(vocabulary),
        },
        program_bytes: program.len(),
        instructions: listing.instructions.len(),
        pool_pc,
        pool_text: pool.to_owned(),
        failures: listing.failures.clone(),
        evidence,
    })
}

/// Finds the frame left by the probe immediately before the uniquely paired environment audit.
/// If the audit runs first, retains the iframe's root frames.
fn controller_frame(index: &Index<'_>, evidence: &[ProbeEvidence], push: &str) -> Option<String> {
    let audits =
        (0..evidence.len()).filter(|&position| evidence[position].reference == Some(AUDIT_PROBE));
    let position = candidates::exactly_one(audits, "environment audit").ok()?;
    let preceding = evidence.get(position.checked_sub(1)?)?;
    controller::controller_trace(index, push, preceding.function.pc)
}
