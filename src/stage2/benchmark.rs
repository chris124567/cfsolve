//! Reports the benchmark worker's four arithmetic kernels using recorded device speeds.
//! Recovers the execution plan and record names from worker source and VM constants. Accepts
//! only the WebAssembly kernels corresponding to those measurements.

use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use swc_core::ecma::ast::{CallExpr, Callee, MemberExpr, MemberProp, VarDeclarator};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::js::{self, JsObject, ast, json};
use crate::performance_clock::{PerformanceClock, Resolution};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::worker_timing::Samples;
use crate::vm::{Constant, Term};
use crate::{candidates, listing};

/// Recovered benchmark execution plan and output field names.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub samples: String,
    pub compilation: String,
    pub total: String,
    pub order: Vec<usize>,
    pub iterations: Vec<u32>,
    pub rounds: u32,
    pub warmup: u32,
    /// Records execution order, iteration counts, and document visibility before starting the
    /// worker.
    pub order_field: String,
    pub iterations_field: String,
    pub visible_field: String,
}

/// The device's benchmark worker costs, measured with the returned worker.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerCosts {
    /// `WebAssembly.instantiate` times.
    pub compile_ms: Vec<f64>,
    /// Each kernel's speed, in milliseconds per million iterations.
    pub kernel_ms_per_million: Vec<Vec<f64>>,
}

/// Benchmark timings: each kernel's samples, and how long compiling and running took.
#[derive(Clone)]
pub struct Measurement {
    pub samples: Vec<Vec<f64>>,
    pub compilation_ms: f64,
    pub total_ms: f64,
}

impl Measurement {
    /// How long compiling and running the kernels took.
    #[must_use]
    pub fn elapsed_ms(&self) -> f64 {
        self.compilation_ms + self.total_ms
    }
}

impl Fields {
    /// Builds probe record fields from `measurement`. The probe stores its plan on its record
    /// before the worker replies.
    #[must_use]
    pub fn collect(&self, measurement: &Measurement) -> JsObject {
        // Report the emulated page as visible.
        JsObject::from_iter([
            (self.order_field.clone(), json!(self.order)),
            (self.iterations_field.clone(), json!(self.iterations)),
            (self.visible_field.clone(), json!(true)),
            (self.samples.clone(), json!(measurement.samples)),
            (self.compilation.clone(), json!(measurement.compilation_ms)),
            (self.total.clone(), json!(measurement.total_ms)),
        ])
    }

    /// Reports the device's recorded instantiation time and kernel speeds, one warmup per sample,
    /// on a fresh worker clock.
    pub(crate) fn measure(
        &self,
        costs: &WorkerCosts,
        resolution: Resolution,
    ) -> Result<Measurement> {
        let instantiated =
            Samples::try_new(&costs.compile_ms, 1000.0, "benchmark instantiate")?.pick()?;
        let speeds = costs
            .kernel_ms_per_million
            .iter()
            .map(|samples| Samples::try_new(samples, 1000.0, "benchmark kernel speed"))
            .collect::<Result<Vec<_>>>()?;
        let clock = PerformanceClock::started_now(resolution);
        let mut elapsed = Duration::ZERO;
        let mut spend = |duration: Duration| {
            elapsed += duration;
            clock.after(elapsed)
        };
        let prepared = spend(Duration::ZERO);
        let compiled = spend(instantiated);
        let mut samples: Vec<Vec<f64>> = vec![Vec::new(); self.order.len()];
        for _ in 0..self.rounds {
            let kernels = self.order.iter().zip(&self.iterations).zip(&mut samples);
            for ((&index, &iterations), samples) in kernels {
                let speed = speeds
                    .get(index)
                    .with_context(|| format!("no recorded speed for benchmark kernel {index}"))?
                    .pick()?;
                let per = |count: u32| speed.mul_f64(f64::from(count) / 1e6);
                let at = spend(per(iterations.min(self.warmup)));
                samples.push(spend(per(iterations)) - at);
            }
        }
        Ok(Measurement {
            samples,
            compilation_ms: compiled - prepared,
            total_ms: spend(Duration::ZERO) - compiled,
        })
    }

    /// Recovers device costs from a browser benchmark `record`, reversing [`Self::measure`].
    /// Includes instantiation time and each kernel speed per round, rounded to a microsecond per
    /// million iterations.
    pub fn costs(&self, record: &JsObject) -> Result<WorkerCosts> {
        let read = |name: &str| {
            record
                .get(name)
                .with_context(|| format!("the benchmark record has no `{name}`"))
        };
        let samples: Vec<Vec<f64>> = js::from_value(read(&self.samples)?.clone())
            .context("the benchmark samples are not lists of times")?;
        let compile_ms = read(&self.compilation)?
            .as_f64()
            .context("the benchmark's instantiation time is not a number")?;
        let mut speeds: Vec<Vec<f64>> = vec![Vec::new(); self.order.len()];
        let kernels = self.order.iter().zip(&self.iterations).zip(&samples);
        for ((&index, &iterations), samples) in kernels {
            let per_million = |ms: &f64| (ms * 1e9 / f64::from(iterations)).round() / 1000.0;
            speeds
                .get_mut(index)
                .with_context(|| format!("benchmark kernel {index} is outside the plan"))?
                .extend(samples.iter().map(per_million));
        }
        Ok(WorkerCosts {
            compile_ms: vec![compile_ms],
            kernel_ms_per_million: speeds,
        })
    }
}

/// Recovers field names from the worker AST and the execution plan from VM constants.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let index = probe.index;
    let mut strings = Vec::new();
    for pc in index.reachable(probe.entry).iter() {
        for effect in index.listing().instructions[pc].effects() {
            effect.visit_terms(&mut |term| {
                if let Term::Const(Constant::String(text)) = term
                    && !strings.contains(text)
                {
                    strings.push(text.clone());
                }
            });
        }
    }
    let source = strings
        .iter()
        .find(|text| text.contains("WebAssembly.instantiate"))?;
    let parsed = ast::parse_javascript("benchmark worker", source).ok()?;
    let mut worker = Worker::default();
    parsed.script.visit_with(&mut worker);
    // Only the kernels the recorded speeds measure are supported. Field names are recovered
    // separately and may change without changing the binary.
    if functions_digest(&worker.module?)? != KERNELS {
        return None;
    }
    let [samples, compilation, total]: [String; 3] = worker.outputs.try_into().ok()?;
    let [warmup, _, _, rounds]: [String; 4] = worker.plan.try_into().ok()?;
    let number = |name: &str| {
        strings.iter().find_map(|text| {
            text.strip_prefix(&format!("{name}:"))?
                .trim_end_matches([',', '}', ';'])
                .parse::<u32>()
                .ok()
        })
    };
    let arrays: Vec<Vec<u32>> = strings
        .iter()
        .filter_map(|text| {
            let decoded = listing::decode_string(text, "").ok()?;
            serde_json::from_str(&decoded).ok()
        })
        .collect();
    let order = arrays
        .iter()
        .find(|items| items.len() == 4 && (0..4).all(|kernel| items.contains(&kernel)))?;
    let iterations = arrays
        .iter()
        .find(|items| items.len() == order.len() && *items != order)?;
    // The worker's source begins `var plan={<order>:[...],<iterations>:[...],`,
    // and the record takes the same two names.
    let identifier =
        |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_alphanumeric());
    let [order_field, iterations_field]: [String; 2] = strings
        .iter()
        .skip_while(|text| *text != "var plan={")
        .filter_map(|text| text.strip_suffix(':'))
        .filter(|name| identifier(name))
        .take(2)
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .try_into()
        .ok()?;
    // Then `<visible> = typeof document === "undefined" ? false :
    // document.visibilityState !== "hidden"`.
    let after = strings.iter().position(|text| *text == iterations_field)?;
    let visibility = after
        + strings[after..]
            .iter()
            .position(|text| text == "visibilityState")?;
    let visible = strings[after + 1..visibility]
        .iter()
        .filter(|text| identifier(text) && !["undefined", "document"].contains(&text.as_str()));
    let visible_field = candidates::exactly_one(visible, "visibility field")
        .ok()?
        .clone();
    Some(Fields {
        samples,
        compilation,
        total,
        order: order.iter().map(|&index| index as usize).collect(),
        iterations: iterations.clone(),
        rounds: number(&rounds)?,
        warmup: number(&warmup)?,
        order_field,
        iterations_field,
        visible_field,
    })
}

/// Digest of the kernel functions measured by the profiles; see [`functions_digest`].
const KERNELS: &str = "259924f166f0a6ab5c9709a91c80f12f9cfd24cc1827c3a76bf93ac5cbb60a3a";

/// Hashes the type, function, and code sections, ignoring linker globals and exports such as
/// `__data_end` and `__heap_base`, which can change independently of kernel code.
fn functions_digest(module: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};

    let mut rest = module.strip_prefix(b"\0asm\x01\0\0\0")?;
    let mut digest = Sha256::new();
    while let [id, after @ ..] = rest {
        let (length, body) = leb128(after)?;
        let section = rest.get(..rest.len() - body.len() + length)?;
        if matches!(id, 1 | 3 | 10) {
            digest.update(section);
        }
        rest = &rest[section.len()..];
    }
    Some(format!("{:x}", digest.finalize()))
}

/// Decodes an unsigned LEB128 `u32` and returns the remaining bytes.
fn leb128(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let mut value = 0;
    // A `u32` takes at most five 7-bit groups.
    let groups = bytes.iter().enumerate().take(5);
    for (index, &byte) in groups {
        value |= usize::from(byte & 0x7f) << (7 * index);
        if byte < 0x80 {
            return Some((value, &bytes[index + 1..]));
        }
    }
    None
}

#[derive(Default)]
struct Worker {
    module: Option<Vec<u8>>,
    outputs: Vec<String>,
    plan: Vec<String>,
}

impl Visit for Worker {
    fn visit_var_declarator(&mut self, declaration: &VarDeclarator) {
        if let Some(value) = declaration.init.as_deref().and_then(ast::static_str)
            && let Ok(bytes) = STANDARD.decode(value)
            && bytes.starts_with(b"\0asm")
        {
            self.module = Some(bytes);
        }
        declaration.visit_children_with(self);
    }
    fn visit_member_expr(&mut self, member: &MemberExpr) {
        if member.obj.as_ident().is_some_and(|name| name.sym == "plan")
            && let MemberProp::Ident(name) = &member.prop
            && !self.plan.contains(&name.sym.to_string())
        {
            self.plan.push(name.sym.to_string());
        }
        member.visit_children_with(self);
    }
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(callee) = &call.callee
            && let Some(member) = callee.as_member()
            && let MemberProp::Ident(name) = &member.prop
            && name.sym == "postMessage"
            && let Some(argument) = call.args.first()
            && let Some(object) = argument.expr.as_object()
        {
            let objects = ast::key_values(object).filter_map(|property| property.value.as_object());
            for data in objects {
                self.outputs = ast::key_values(data)
                    .filter_map(|property| ast::key_str(&property.key).map(str::to_owned))
                    .collect();
            }
        }
        call.visit_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js;

    fn sample() -> Fields {
        js::from_value(json!({
            "samples": "samples", "compilation": "compile", "total": "total",
            "order": [3, 2, 0, 1], "iterations": [9, 8, 7, 0], "rounds": 3, "warmup": 5,
            "order_field": "order", "iterations_field": "iterations", "visible_field": "visible"
        }))
        .unwrap()
    }

    #[test]
    fn the_record_holds_the_plan_before_the_timings() {
        let measurement = Measurement {
            samples: vec![vec![0.5]],
            compilation_ms: 1.5,
            total_ms: 2.0,
        };
        assert_eq!(
            js::stringify_object(&sample().collect(&measurement)),
            r#"{"order":[3,2,0,1],"iterations":[9,8,7,0],"visible":true,"samples":[[0.5]],"compile":1.5,"total":2}"#
        );
    }

    /// Checks that recorded device speeds determine kernel samples on the worker's clock.
    #[test]
    fn a_recorded_kernel_speed_sets_the_samples() {
        let fields = Fields {
            iterations: vec![2_000_000, 1_000_000, 2_000_000, 500_000],
            rounds: 2,
            warmup: 0,
            ..sample()
        };
        let costs = WorkerCosts {
            compile_ms: vec![3.0],
            kernel_ms_per_million: vec![vec![0.5], vec![2.0], vec![1.0], vec![4.0]],
        };
        let measured = fields
            .measure(&costs, Resolution::WebKitMillisecond)
            .unwrap();
        assert_eq!(
            measured.samples,
            [[8.0, 8.0], [1.0, 1.0], [1.0, 1.0], [1.0, 1.0]]
        );
        assert_eq!((measured.compilation_ms, measured.total_ms), (3.0, 22.0));
        // Recover the input speeds from each round of the record.
        let read = fields.costs(&fields.collect(&measured)).unwrap();
        assert_eq!(read.compile_ms, [3.0]);
        assert_eq!(
            read.kernel_ms_per_million,
            [[0.5, 0.5], [2.0, 2.0], [1.0, 1.0], [4.0, 4.0]]
        );
        let missing = WorkerCosts {
            kernel_ms_per_million: costs.kernel_ms_per_million[..3].to_vec(),
            ..costs
        };
        let missing = fields.measure(&missing, Resolution::WebKitMillisecond);
        assert!(missing.is_err());
    }

    /// Chrome's clamped clock reports whole 100 µs steps.
    #[test]
    fn chrome_readings_are_whole_clock_steps() {
        let costs = WorkerCosts {
            compile_ms: vec![2.53],
            kernel_ms_per_million: vec![vec![5.69], vec![3.02], vec![2.17], vec![13.72]],
        };
        let measured = sample().measure(&costs, Resolution::Chromium).unwrap();
        let mut readings = measured.samples.concat();
        readings.extend([measured.compilation_ms, measured.total_ms]);
        for value in readings {
            assert!(
                (value * 10.0 - (value * 10.0).round()).abs() < 1e-5,
                "{value} ms is not whole 100 µs steps of Chrome's clamped clock"
            );
        }
    }

}
