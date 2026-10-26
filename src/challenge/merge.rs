//! Recovers how the iframe copies the embedding page's `extraParams` message fields into
//! randomly named `_cf_chl_opt` options.

use anyhow::{Context, Result};
use swc_core::ecma::ast::{
    AssignTarget, BinaryOp, CallExpr, Callee, Expr, FnDecl, SimpleAssignTarget, Stmt, UnaryOp,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::challenge::expression;
use crate::js::ast::{self, ParsedScript};
use crate::js::{JsValue, Options, json};
use crate::{candidates, js};

/// Minimum number of option writes from parameter fields that identifies the merge function.
const MINIMUM_FIELDS: usize = 10;

/// Where one option's value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionSource {
    /// A field of the embedding page's `extraParams` message.
    Message(String),
    /// The origin the message arrived from.
    Origin,
    /// The time the iframe merged the message.
    Merged,
    /// Copied from another option, possibly after stored state overrides it.
    Copied(String),
    /// Embedding-page call-stack samples, rewritten by the iframe during copying.
    Samples(String),
    /// The iframe's own state. The embedding page supplies nothing for these.
    Runtime,
}

/// An option written by the merge and the source of its value.
#[derive(Debug, Clone)]
pub struct OptionEntry {
    pub option: String,
    pub source: OptionSource,
    /// The fallback the iframe substitutes for a falsy value.
    pub default: Option<JsValue>,
}

/// Every option the merge writes, in the order the iframe writes them.
#[derive(Debug, Clone)]
pub struct Mapping(pub Vec<OptionEntry>);

impl Mapping {
    #[cfg(test)]
    pub(crate) fn from_javascript(source: &str) -> Result<Self> {
        Self::from_parsed(&ast::parse_iframe_javascript(source)?)
    }

    pub(crate) fn from_parsed(parsed: &ParsedScript) -> Result<Self> {
        let merges = ast::in_declared_functions(&parsed.script, merge_function);
        let merge =
            candidates::exactly_one(merges, "function merging the embedding page's parameters")?;
        let mut calls = Calls {
            merge: &merge,
            roles: Vec::new(),
        };
        parsed.script.visit_with(&mut calls);
        let roles = candidates::at_most_one_distinct(calls.roles, "merge call arguments")?
            .context("could not find where the merge is called")?;
        let entries = merge.writes.into_iter().map(|write| write.entry(&roles));
        Ok(Self(entries.collect()))
    }

    /// Merges the collected message into bootstrap options. Returns the options that still need
    /// iframe state unavailable to this caller.
    pub fn merge(
        &self,
        options: &mut Options,
        message: &JsValue,
        origin: &str,
        merged_at: i64,
    ) -> Vec<String> {
        let mut runtime = Vec::new();
        for entry in &self.0 {
            let value = match &entry.source {
                OptionSource::Message(key) => message.get(key).cloned(),
                OptionSource::Origin => Some(json!(origin)),
                OptionSource::Merged => Some(json!(merged_at)),
                OptionSource::Copied(from) => options.get(from).cloned(),
                OptionSource::Samples(key) => Some(samples(message.get(key))),
                OptionSource::Runtime => {
                    runtime.push(entry.option.clone());
                    continue;
                }
            };
            let value = value
                .filter(|value| entry.default.is_none() || js::truthy(value))
                .or_else(|| entry.default.clone());
            if let Some(value) = value {
                options.insert(entry.option.clone(), value);
            } else {
                // Assigning `undefined` removes the field from the payload.
                options.shift_remove(&entry.option);
            }
        }
        runtime
    }

    /// The option timestamped when the iframe merges the embedding page's parameters.
    #[must_use]
    pub fn merged(&self) -> Option<&str> {
        self.0
            .iter()
            .find(|entry| entry.source == OptionSource::Merged)
            .map(|entry| entry.option.as_str())
    }

    /// Lists `extraParams` fields read by this session so collectors can be checked against the
    /// script.
    #[must_use]
    pub fn fields(&self) -> Vec<&str> {
        let mut fields: Vec<&str> = self
            .0
            .iter()
            .filter_map(|entry| match &entry.source {
                OptionSource::Message(key) => Some(key.as_str()),
                _ => None,
            })
            .collect();
        fields.sort_unstable();
        fields.dedup();
        fields
    }
}

/// The source of an option assignment's right-hand side.
enum Written {
    /// A parameter, or a field of one.
    Field {
        parameter: usize,
        key: Option<String>,
    },
    /// Another option's value, copied through a local variable.
    Copied(String),
    Samples {
        parameter: usize,
        key: String,
    },
    Now,
    Other,
}

/// One `_cf_chl_opt.<option> = ...` in the merge's body.
struct OptionWrite {
    option: String,
    value: Written,
    /// The literal the value falls back to when it is falsy.
    default: Option<JsValue>,
}

impl OptionWrite {
    /// Resolves an assignment's source from the merge arguments. If the caller extracted a
    /// message field before the call, uses the fallback supplied by that caller.
    fn entry(self, roles: &[Role]) -> OptionEntry {
        let (source, fallback) = match self.value {
            Written::Now => (OptionSource::Merged, None),
            Written::Copied(from) => (OptionSource::Copied(from), None),
            Written::Other => (OptionSource::Runtime, None),
            Written::Field { parameter, key } => match (&roles[parameter], key) {
                // Reading a property of the message supplies the field name.
                (Role::Message, Some(key)) => (OptionSource::Message(key), None),
                (Role::Origin, None) => (OptionSource::Origin, None),
                // The caller passed a message field directly.
                (Role::Field { key, fallback }, None) => {
                    (OptionSource::Message(key.clone()), fallback.clone())
                }
                _ => (OptionSource::Runtime, None),
            },
            Written::Samples { parameter, key } => match &roles[parameter] {
                Role::Message => (OptionSource::Samples(key), None),
                _ => (OptionSource::Runtime, None),
            },
        };
        OptionEntry {
            option: self.option,
            source,
            default: self.default.or(fallback),
        }
    }
}

/// The value passed as one merge argument.
#[derive(Debug, Clone, PartialEq)]
enum Role {
    Message,
    Origin,
    /// A field of the message, unwrapped by the caller with the fallback it applied.
    Field {
        key: String,
        fallback: Option<JsValue>,
    },
    Unknown,
}

/// A candidate merge function.
struct Merge {
    name: String,
    arity: usize,
    writes: Vec<OptionWrite>,
}

/// A function declaration that writes enough options from parameter fields to be the merge.
fn merge_function(function: &FnDecl) -> Option<Merge> {
    let writes = writes(function);
    let fields = writes
        .iter()
        .filter(|write| matches!(write.value, Written::Field { key: Some(_), .. }));
    (fields.count() >= MINIMUM_FIELDS).then(|| Merge {
        name: function.ident.sym.to_string(),
        arity: function.function.params.len(),
        writes,
    })
}

/// Identifies arguments in merge calls that pass the message exactly once and have no unknown
/// arguments. Calls that deliver the message also pass its origin. Other calls use stored local
/// variables; treating them as message delivery would produce incorrect field mappings.
struct Calls<'merge> {
    merge: &'merge Merge,
    roles: Vec<Vec<Role>>,
}

impl Visit for Calls<'_> {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(callee) = &call.callee
            && let Expr::Ident(ident) = &**callee
            && ident.sym == *self.merge.name
            && call.args.len() == self.merge.arity
        {
            let roles: Vec<Role> = call
                .args
                .iter()
                .map(|argument| role(&argument.expr))
                .collect();
            if roles.iter().filter(|role| **role == Role::Message).count() == 1
                && !roles.contains(&Role::Unknown)
            {
                self.roles.push(roles);
            }
        }
        call.visit_children_with(self);
    }
}

fn role(expression: &Expr) -> Role {
    match expression {
        Expr::Ident(_) => Role::Message,
        Expr::Bin(binary) if binary.op == BinaryOp::LogicalOr => match role(&binary.left) {
            Role::Field { key, .. } => Role::Field {
                key,
                fallback: expression::static_value(&binary.right, &Options::new()),
            },
            other => other,
        },
        _ => match expression.as_member().and_then(ast::ident_property) {
            Some("origin") => Role::Origin,
            Some(key) => Role::Field {
                key: key.to_owned(),
                fallback: None,
            },
            None => Role::Unknown,
        },
    }
}

/// Every `_cf_chl_opt.<name> = ...` in a function's own body.
fn writes(function: &FnDecl) -> Vec<OptionWrite> {
    let parameters: Vec<&str> = function
        .function
        .params
        .iter()
        .map(|parameter| parameter.pat.as_ident().map_or("", |ident| &*ident.id.sym))
        .collect();
    let Some(body) = &function.function.body else {
        return Vec::new();
    };
    // Some options pass through a local so stored browser state can override them before they
    // are written back.
    let mut staged: Vec<(&str, &str)> = Vec::new();
    let mut writes = Vec::new();
    for statement in &body.stmts {
        if let Some(write) = sampled(statement, &parameters) {
            writes.push(write);
            continue;
        }
        let Some(assignment) = expression::assignment(statement) else {
            continue;
        };
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(local)) = &assignment.left
            && let Some(option) = expression::option_key(&assignment.right)
        {
            staged.push((&local.id.sym, option));
            continue;
        }
        let Some(option) = expression::option_assignment(&assignment.left).map(str::to_owned)
        else {
            continue;
        };
        let (mut value, default) = read(&assignment.right, &parameters);
        if let (Written::Other, Expr::Ident(ident)) = (&value, &*assignment.right)
            && let Some((_, from)) = staged.iter().rfind(|(local, _)| *local == &*ident.sym)
        {
            value = Written::Copied((*from).to_owned());
        }
        writes.push(OptionWrite {
            option,
            value,
            default,
        });
    }
    writes
}

/// Recognizes the first sample copy: `if (!_cf_chl_opt.<option>.length) {
/// copy(<parameter>.<key>); }`.
fn sampled(statement: &Stmt, parameters: &[&str]) -> Option<OptionWrite> {
    if let Stmt::If(branch) = statement
        && let Expr::Unary(test) = &*branch.test
        && test.op == UnaryOp::Bang
        && let Expr::Member(length) = &*test.arg
        && ast::member_str(&length.prop) == Some("length")
        && let Some(option) = expression::option_key(&length.obj)
        && let Stmt::Block(block) = &*branch.cons
        && let [Stmt::Expr(copy)] = &block.stmts[..]
        && let Expr::Call(copy) = &*copy.expr
        && let [argument] = &copy.args[..]
        && let (Written::Field { parameter, key }, _) = read(&argument.expr, parameters)
        && let Some(key) = key
    {
        Some(OptionWrite {
            option: option.to_owned(),
            value: Written::Samples { parameter, key },
            default: None,
        })
    } else {
        None
    }
}

/// Converts `[method, time, stack, count]` samples to the iframe's object format, with a letter
/// identifying the method.
fn samples(entries: Option<&JsValue>) -> JsValue {
    let entries = entries.and_then(JsValue::as_array).into_iter().flatten();
    let samples = entries.filter_map(|entry| {
        let [method, time, stack, count] = entry.as_array()?.as_slice() else {
            return None;
        };
        Some(json!({
            "m": char::from(b'a' + method.as_f64()? as u8).to_string(),
            "t": time,
            "s": stack,
            "c": count,
        }))
    });
    samples.collect()
}

/// Resolves `expression` and its literal fallback for falsy values.
fn read(expression: &Expr, parameters: &[&str]) -> (Written, Option<JsValue>) {
    let field = |name: &str, key: Option<&str>| {
        let parameter = parameters.iter().position(|parameter| *parameter == name)?;
        let key = key.map(str::to_owned);
        Some(Written::Field { parameter, key })
    };
    let written = match expression {
        Expr::Paren(paren) => return read(&paren.expr, parameters),
        Expr::Bin(binary) if binary.op == BinaryOp::LogicalOr => {
            let (written, _) = read(&binary.left, parameters);
            let fallback = expression::static_value(&binary.right, &Options::new());
            return (written, fallback);
        }
        Expr::Ident(ident) => field(&ident.sym, None),
        Expr::Member(member) => match (&*member.obj, ast::member_str(&member.prop)) {
            (Expr::Ident(object), Some(key)) => field(&object.sym, Some(key)),
            _ => None,
        },
        Expr::Call(_) if ast::is_date_now(expression) => Some(Written::Now),
        _ => None,
    };
    (written.unwrap_or(Written::Other), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = r#"
        function tC(tL, tq, ta, tn) {
            e._cf_chl_opt.OqAoN4 = tL.action;
            e._cf_chl_opt.BkYo5 = tL.cData;
            e._cf_chl_opt.vXDzj6 = tL.url;
            e._cf_chl_opt.YghXX0 = tL.retry || "auto";
            e._cf_chl_opt.XOKPk1 = tL["retry-interval"] || 8e3;
            e._cf_chl_opt.CHyD3 = tL.language || "auto";
            e._cf_chl_opt.ZTew0 = tL.execution || "render";
            e._cf_chl_opt.VnGsz1 = tq;
            e._cf_chl_opt.IPeXW2 = tL.ch || ``;
            e._cf_chl_opt.vVvpJ8 = tL.wPr || {};
            e._cf_chl_opt.tZwbF3 = tL.timeLoadInitMs || 0;
            e._cf_chl_opt.yAFE2 = ta;
            e._cf_chl_opt.zfniV9 = tn;
            e._cf_chl_opt.AOzXq2 = Date.now();
            e._cf_chl_opt.WbdgY0 = z2;
        }
        function handler(tP) {
            var tU = tP.data;
            if (tU.event === "extraParams") {
                tC(tU, tP.origin, tU.apiJsMismatchReloadAttempts || 0, tU.apiJsMismatchReloadCompletedCount || 0);
            }
        }"#;

    #[test]
    fn recovers_field_names_defaults_and_argument_roles() {
        let mapping = Mapping::from_javascript(SOURCE).unwrap();
        let message = |field: &str| OptionSource::Message(field.into());
        for (option, source, default) in [
            ("OqAoN4", message("action"), None),
            ("XOKPk1", message("retry-interval"), Some(json!(8000))),
            ("vVvpJ8", message("wPr"), Some(json!({}))),
            ("IPeXW2", message("ch"), Some(json!(""))),
            ("VnGsz1", OptionSource::Origin, None),
            // The call site unwrapped this argument; it keeps the field name it came from.
            (
                "yAFE2",
                message("apiJsMismatchReloadAttempts"),
                Some(json!(0)),
            ),
            ("AOzXq2", OptionSource::Merged, None),
            ("WbdgY0", OptionSource::Runtime, None),
        ] {
            let entry = mapping
                .0
                .iter()
                .find(|entry| entry.option == option)
                .unwrap();
            assert_eq!(
                (&entry.source, &entry.default),
                (&source, &default),
                "{option}"
            );
        }
        assert!(mapping.fields().contains(&"wPr"));
    }

    #[test]
    fn rejects_merge_calls_that_disagree_about_their_arguments() {
        let source = format!("{SOURCE}\nfunction other(tU) {{ tC(tU, tU.origin, tU.x, tU.y); }}");
        let error = Mapping::from_javascript(&source).unwrap_err().to_string();
        assert!(error.contains("conflicting"), "{error}");
        // This call passes the message through two local variables, so it cannot be the
        // delivery call. Repeating it does not create a conflicting mapping.
        for caller in [
            "function replay(r0, r1) { tC(r0, r1, r0.apiJsMismatchReloadAttempts || 0, r0.apiJsMismatchReloadCompletedCount || 0); }",
            "function again(tP) { var tU = tP.data; tC(tU, tP.origin, tU.apiJsMismatchReloadAttempts || 0, tU.apiJsMismatchReloadCompletedCount || 0); }",
        ] {
            let source = format!("{SOURCE}\n{caller}");
            assert!(Mapping::from_javascript(&source).is_ok(), "{caller}");
        }
    }

    /// Uses fallbacks for falsy values. Omits absent fields without fallbacks as `undefined`,
    /// and leaves runtime options for the iframe to supply.
    #[test]
    fn merge_applies_javascript_fallbacks_and_reports_what_it_cannot_fill() {
        let mapping = Mapping::from_javascript(SOURCE).unwrap();
        let mut options = Options::from_iter([("WbdgY0".to_owned(), json!("bootstrap-id"))]);
        let message = json!({
            "action": "login",
            "url": "https://example.com/",
            "retry": "",
            "retry-interval": 0,
            "language": "de",
            "wPr": {"w.iW": 1280},
            "timeLoadInitMs": 323,
            "apiJsMismatchReloadAttempts": 0,
        });
        let runtime = mapping.merge(
            &mut options,
            &message,
            "https://example.com",
            1_789_331_612_058,
        );
        assert_eq!(runtime, ["WbdgY0"]);
        assert_eq!(
            JsValue::from(options),
            json!({
                "WbdgY0": "bootstrap-id",
                "OqAoN4": "login",
                "vXDzj6": "https://example.com/",
                "YghXX0": "auto",
                "XOKPk1": 8000,
                "CHyD3": "de",
                "ZTew0": "render",
                "VnGsz1": "https://example.com",
                "IPeXW2": "",
                "vVvpJ8": {"w.iW": 1280},
                "tZwbF3": 323,
                "yAFE2": 0,
                "zfniV9": 0,
                "AOzXq2": 1_789_331_612_058_i64,
            })
        );
    }
}
