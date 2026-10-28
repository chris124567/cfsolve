//! Recovers the format the iframe uses to summarize resource timings, then converts this
//! client's fetch measurements to that format. Depending on the build, entries contain rounded-down
//! phase durations or the original timestamps.

use swc_core::ecma::ast::{AssignTarget, BinaryOp, BlockStmt, Expr, SimpleAssignTarget};

use crate::challenge::expression::{self, BuiltObject, ObjectField};
use crate::js::{JsObject, JsValue, ast, json};
use crate::resource_timing::{LoadTiming, Phases, ResourceMeasurement};

/// The resource timing property represented by an output field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measure {
    Name,
    /// `Math.floor(responseEnd - responseStart)`.
    Response,
    /// `Math.floor(responseStart - requestStart)`.
    Request,
    /// `Math.floor(duration)`.
    Duration,
    Transfer,
    Body,
    /// Original timestamps: `startTime`, `requestStart`, `responseStart`, `responseEnd`, and
    /// `duration`.
    Start,
    RequestStart,
    ResponseStart,
    ResponseEnd,
    ExactDuration,
}

/// A resource load with its name, start time, and measured phases. The start time is in
/// milliseconds from the document's time origin. The response ends when the load finishes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Entry<'a> {
    pub name: &'a str,
    pub start: f64,
    pub measured: ResourceMeasurement,
}

/// Maps collected resource timings to the six fields sent under the collection's option name.
#[derive(Debug, Clone)]
pub struct ResourceTiming {
    /// The option the session collects its entries under.
    pub option: String,
    /// Output keys and their measurements, in insertion order.
    pub fields: Vec<(String, Measure)>,
}

impl ResourceTiming {
    /// Converts a load to the resource timing format used by this session.
    #[must_use]
    pub(crate) fn reduce(&self, entry: &Entry<'_>) -> JsValue {
        let measured = &entry.measured;
        // Restricted entries report a response start of zero; see
        // `ResourceMeasurement::restricted`.
        let response_end = entry.start + measured.duration;
        let response_start = response_end - measured.response;
        let request_start = response_start - measured.request;
        let mut reduced = JsObject::new();
        for (name, measure) in &self.fields {
            let value = match measure {
                Measure::Name => json!(entry.name),
                Measure::Response => json!(measured.response.floor()),
                Measure::Request => json!(measured.request.floor()),
                Measure::Duration => json!(measured.duration.floor()),
                Measure::Transfer => json!(measured.transfer_size),
                Measure::Body => json!(measured.body_size),
                Measure::Start => json!(entry.start),
                Measure::RequestStart => json!(request_start),
                Measure::ResponseStart => json!(response_start),
                Measure::ResponseEnd => json!(response_end),
                Measure::ExactDuration => json!(measured.duration),
            };
            reduced.insert(name.clone(), value);
        }
        JsValue::Object(reduced)
    }

    /// Converts measured phases from `load` to the session format. Times are relative to
    /// `origin_ms`, the document navigation time in milliseconds since the Unix epoch.
    #[must_use]
    pub(crate) fn entry(&self, load: &LoadTiming, origin_ms: i64) -> JsValue {
        self.reduce(&Entry {
            name: &load.url,
            start: (load.started_ms - origin_ms) as f64,
            measured: load.measurement(),
        })
    }

    /// Splits the total document load time into navigation `phases`. Navigation starts at the
    /// document's time origin.
    #[must_use]
    pub(crate) fn navigation(
        &self,
        url: &str,
        duration: f64,
        bytes: u64,
        phases: Phases,
    ) -> JsValue {
        self.reduce(&Entry {
            name: url,
            start: 0.0,
            measured: ResourceMeasurement::estimated(duration, bytes, phases),
        })
    }
}

/// Finds the first resource summary object in `body`, using the resource name and locals
/// holding floored measurements.
pub(super) fn reduction(body: &BlockStmt) -> Option<Vec<(String, Measure)>> {
    let mut measured: Vec<(&str, Measure)> = Vec::new();
    let mut built: Vec<BuiltObject> = Vec::new();
    for assignment in expression::assignments(body) {
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(local)) = &assignment.left
            && let Some(measure) = floored(&assignment.right)
        {
            measured.push((&local.id.sym, measure));
        } else {
            expression::track(&mut built, assignment);
        }
    }
    built
        .iter()
        .find_map(|object| reduced_fields(&object.fields, &measured))
}

/// Recognizes a reduced entry when it has enough fields, includes the resource name, and uses
/// only properties of the entry itself or locals listed in `measured`.
fn reduced_fields(
    fields: &[ObjectField<'_>],
    measured: &[(&str, Measure)],
) -> Option<Vec<(String, Measure)>> {
    let mut reduced = Vec::with_capacity(fields.len());
    for field in fields {
        let measure = match field.value {
            Expr::Member(member) => match ast::member_str(&member.prop)? {
                "name" => Measure::Name,
                "startTime" => Measure::Start,
                "requestStart" => Measure::RequestStart,
                "responseStart" => Measure::ResponseStart,
                "responseEnd" => Measure::ResponseEnd,
                "duration" => Measure::ExactDuration,
                "transferSize" => Measure::Transfer,
                "encodedBodySize" => Measure::Body,
                _ => return None,
            },
            Expr::Ident(ident) => {
                let (_, measure) = measured.iter().rfind(|(local, _)| *local == &*ident.sym)?;
                *measure
            }
            _ => return None,
        };
        reduced.push((field.key.to_owned(), measure));
    }
    let names_the_resource = reduced.iter().any(|(_, measure)| *measure == Measure::Name);
    (names_the_resource && reduced.len() >= 4).then_some(reduced)
}

/// `Math.floor(entry.a - entry.b)` or `Math.floor(entry.a)`.
fn floored(expression: &Expr) -> Option<Measure> {
    let call = expression.as_call()?;
    let member = call.callee.as_expr()?.as_member()?;
    if !ast::is_method_of(member, "Math", "floor") {
        return None;
    }
    fn attribute(expression: &Expr) -> Option<&str> {
        ast::ident_property(expression.as_member()?)
    }
    match &*call.args.first()?.expr {
        Expr::Bin(binary) if binary.op == BinaryOp::Sub => {
            match (attribute(&binary.left)?, attribute(&binary.right)?) {
                ("responseEnd", "responseStart") => Some(Measure::Response),
                ("responseStart", "requestStart") => Some(Measure::Request),
                _ => None,
            }
        }
        single => match attribute(single)? {
            "duration" => Some(Measure::Duration),
            "transferSize" => Some(Measure::Transfer),
            "encodedBodySize" => Some(Measure::Body),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Uses a 137 ms navigation that iOS Safari reported as 124 ms receiving the response and
    /// zero time waiting for it.
    #[test]
    fn navigations_split_into_the_browsers_phases() {
        let timing = ResourceTiming {
            option: "t".into(),
            fields: vec![
                ("n".into(), Measure::Name),
                ("r".into(), Measure::Response),
                ("q".into(), Measure::Request),
                ("d".into(), Measure::Duration),
                ("t".into(), Measure::Transfer),
                ("b".into(), Measure::Body),
            ],
        };
        let webkit = Phases {
            request: 0.0,
            response: 0.9,
        };
        assert_eq!(
            timing.navigation("u", 137.0, 1, webkit),
            json!({"n": "u", "r": 123.0, "q": 0.0, "d": 137.0, "t": 301, "b": 1})
        );
        let chromium = Phases {
            request: 0.07,
            response: 0.04,
        };
        assert_eq!(
            timing.navigation("u", 137.0, 1, chromium),
            json!({"n": "u", "r": 5.0, "q": 9.0, "d": 137.0, "t": 301, "b": 1})
        );
    }

    /// Builds from 2026-10-27 onward copy original timestamps rather than rounding down phase
    /// durations.
    #[test]
    fn summaries_may_copy_the_entrys_timestamps() {
        let parsed = ast::parse_javascript(
            "t.js",
            "function f(e) { var r; r = { a: e.name, b: e.startTime, c: e.requestStart, \
             d: e.responseStart, g: e.responseEnd, h: e.duration, i: e.transferSize, \
             j: e.encodedBodySize }; list.push(r); }",
        )
        .unwrap();
        let function = parsed.script.body[0]
            .as_decl()
            .unwrap()
            .as_fn_decl()
            .unwrap();
        let fields = reduction(function.function.body.as_ref().unwrap()).unwrap();
        let measures: Vec<Measure> = fields.iter().map(|(_, measure)| *measure).collect();
        assert_eq!(
            measures,
            [
                Measure::Name,
                Measure::Start,
                Measure::RequestStart,
                Measure::ResponseStart,
                Measure::ResponseEnd,
                Measure::ExactDuration,
                Measure::Transfer,
                Measure::Body,
            ]
        );
        let timing = ResourceTiming {
            option: "t".into(),
            fields,
        };
        let entry = Entry {
            name: "u",
            start: 10.0,
            measured: ResourceMeasurement {
                duration: 100.0,
                request: 60.0,
                response: 5.0,
                transfer_size: 1300,
                body_size: 1000,
            },
        };
        assert_eq!(
            timing.reduce(&entry),
            json!({"a": "u", "b": 10.0, "c": 45.0, "d": 105.0, "g": 110.0, "h": 100.0,
                "i": 1300, "j": 1000})
        );
    }
}
