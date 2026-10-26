//! Recovers the format the iframe uses to summarize resource timings, then converts this
//! client's fetch measurements to that format.

use swc_core::ecma::ast::{AssignTarget, BinaryOp, BlockStmt, Expr, SimpleAssignTarget};

use crate::challenge::expression::{self, BuiltObject, ObjectField};
use crate::js::{JsObject, JsValue, ast, json};
use crate::resource_timing::{LoadTiming, Phases, ResourceMeasurement};

/// The resource timing property represented by an output field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measure {
    Name,
    /// `responseEnd - responseStart`.
    Response,
    /// `responseStart - requestStart`.
    Request,
    Duration,
    Transfer,
    Body,
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
    /// Reduces a measured fetch to the session's resource timing format.
    #[must_use]
    pub(crate) fn reduce(&self, url: &str, measured: &ResourceMeasurement) -> JsValue {
        let mut entry = JsObject::new();
        for (name, measure) in &self.fields {
            let value = match measure {
                Measure::Name => json!(url),
                Measure::Response => json!(measured.response.floor()),
                Measure::Request => json!(measured.request.floor()),
                Measure::Duration => json!(measured.duration.floor()),
                Measure::Transfer => json!(measured.transfer_size),
                Measure::Body => json!(measured.body_size),
            };
            entry.insert(name.clone(), value);
        }
        JsValue::Object(entry)
    }

    /// Reduces `load` using its measured phases.
    #[must_use]
    pub(crate) fn entry(&self, load: &LoadTiming) -> JsValue {
        self.reduce(&load.url, &load.measurement())
    }

    /// Splits the session's total document load time into the navigation's `phases`.
    #[must_use]
    pub(crate) fn navigation(
        &self,
        url: &str,
        duration: f64,
        bytes: u64,
        phases: Phases,
    ) -> JsValue {
        self.reduce(
            url,
            &ResourceMeasurement::estimated(duration, bytes, phases),
        )
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
/// only the name or `measured` locals.
fn reduced_fields(
    fields: &[ObjectField<'_>],
    measured: &[(&str, Measure)],
) -> Option<Vec<(String, Measure)>> {
    let mut reduced = Vec::with_capacity(fields.len());
    for field in fields {
        let measure = match field.value {
            Expr::Member(member) if ast::member_str(&member.prop) == Some("name") => Measure::Name,
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
}
