//! Recovers the iframe's trace frames from its script.
//!
//! The iframe stores trace frames in `o.<global>`. One helper replaces the last frame; another
//! pushes a frame. Startup uses one root frame, and the callback returned by a response program
//! uses another. The environment audit groups the trace global by its observed frames.

use std::collections::BTreeSet;

use swc_core::ecma::ast::{
    AssignExpr, AssignTarget, BinaryOp, BlockStmt, CallExpr, Expr, FnDecl, Function, Lit,
    MemberProp, SimpleAssignTarget, Stmt,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use crate::js::ast::{self, ParsedScript};
use crate::script::Source;
use crate::{candidates, vm};

/// Trace helpers and root frame names recovered from the iframe script.
pub struct Trace {
    /// The global property holding the trace array.
    pub(crate) global: String,
    /// The helper that replaces the trace's last frame.
    pub(crate) replace: String,
    /// The helper that pushes a frame onto the same array, if there is exactly one.
    pub(crate) push: Option<String>,
    /// The frame named before the initial program starts.
    pub(crate) initial_root: String,
    /// The frame named before the returned program's callback is called.
    pub(crate) returned_root: String,
}

impl Trace {
    /// Recovers the iframe's trace if its helpers and entry sites are present and unambiguous.
    #[must_use]
    pub fn recover(source: &Source) -> Option<Self> {
        Self::from_parsed(source.parsed())
    }

    fn from_parsed(parsed: &ParsedScript) -> Option<Self> {
        let mut structure = Structure {
            runner: vm::runner_name(&parsed.script)?,
            ..Structure::default()
        };
        parsed.script.visit_with(&mut structure);
        let replacement =
            candidates::exactly_one(&structure.replacements, "trace replace helper").ok()?;
        let root = |entries: &BTreeSet<String>, what: &str| {
            let frames: BTreeSet<&str> = structure
                .roots
                .iter()
                .filter(|root| root.helper == replacement.helper && entries.contains(&root.entry))
                .map(|root| root.frame.as_str())
                .collect();
            candidates::exactly_one(frames, what)
                .ok()
                .map(str::to_owned)
        };
        // A returned program may push a controller frame over the iframe callback frame.
        // Recovering it needs a unique push helper that edits the replace helper's array.
        let pushes = structure
            .pushes
            .iter()
            .filter(|push| push.array == replacement.array);
        Some(Self {
            global: replacement.array.clone(),
            replace: replacement.helper.clone(),
            push: candidates::exactly_one(pushes, "trace push helper")
                .ok()
                .map(|push| push.helper.clone()),
            initial_root: root(&structure.initializers, "initial root frame")?,
            returned_root: root(&structure.returned, "returned root frame")?,
        })
    }
}

/// Reads a literal string through surrounding parentheses. Rejects lone surrogates because
/// lossy conversion would produce a frame name the program never uses.
fn string(expression: &Expr) -> Option<&str> {
    ast::static_str(expression.unwrap_parens())
}

fn call(statement: &Stmt) -> Option<&CallExpr> {
    statement.as_expr()?.expr.unwrap_parens().as_call()
}

fn callee(call: &CallExpr) -> Option<&Expr> {
    Some(call.callee.as_expr()?.unwrap_parens())
}

/// Returns the program passed to a call of the program runner `runner`.
fn run_program<'call>(call: &'call CallExpr, runner: &str) -> Option<&'call Expr> {
    if !vm::calls_runner(call, runner) {
        return None;
    }
    Some(&*call.args.first()?.expr)
}

/// Checks for calls running a literal program in this function's own body, as used by the
/// iframe initializer. Skips nested functions.
struct Calls<'runner> {
    runner: &'runner str,
    literal_program: bool,
}

impl Visit for Calls<'_> {
    fn visit_function(&mut self, _: &Function) {}

    fn visit_call_expr(&mut self, call: &CallExpr) {
        self.literal_program |=
            run_program(call, self.runner).is_some_and(|program| string(program).is_some());
        call.visit_children_with(self);
    }
}

/// Finds array properties modified by a helper: last-element replacement through
/// `o.array[o.array.length - 1] = value` and append through `o.array.push(value)`.
#[derive(Default)]
struct Helpers {
    replace: Option<String>,
    push: Option<String>,
}

impl Visit for Helpers {
    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && let MemberProp::Computed(index) = &member.prop
            && let Expr::Bin(index) = index.expr.unwrap_parens()
            && index.op == BinaryOp::Sub
            && matches!(
                index.right.unwrap_parens(),
                Expr::Lit(Lit::Num(number)) if number.value == 1.0
            )
            && let Expr::Member(length) = index.left.unwrap_parens()
            && ast::member_str(&length.prop) == Some("length")
            && let Expr::Member(array) = member.obj.unwrap_parens()
        {
            self.replace = ast::member_str(&array.prop).map(str::to_owned);
        }
        assignment.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Some(Expr::Member(member)) = callee(call)
            && ast::member_str(&member.prop) == Some("push")
            && let Expr::Member(array) = member.obj.unwrap_parens()
        {
            self.push = ast::member_str(&array.prop).map(str::to_owned);
        }
        call.visit_children_with(self);
    }
}

/// A helper `o.<helper> = function ...` that edits the array `o.<array>`.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct ArrayHelper {
    helper: String,
    array: String,
}

/// A call `o.<helper>("<frame>")` immediately followed by a call of `<entry>`, which names a
/// root frame when `helper` is the replace helper.
struct RootSite {
    helper: String,
    frame: String,
    entry: String,
}

/// Script components used to recover the trace.
#[derive(Default)]
struct Structure {
    /// The name the program runner is installed under.
    runner: String,
    replacements: BTreeSet<ArrayHelper>,
    pushes: BTreeSet<ArrayHelper>,
    /// Functions that run a literal program (see [`Calls`]).
    initializers: BTreeSet<String>,
    /// Bindings holding callbacks returned by programs run from nonliteral inputs.
    returned: BTreeSet<String>,
    roots: Vec<RootSite>,
}

impl Visit for Structure {
    fn visit_fn_decl(&mut self, function: &FnDecl) {
        if let Some(body) = &function.function.body {
            let mut calls = Calls {
                runner: &self.runner,
                literal_program: false,
            };
            body.visit_with(&mut calls);
            if calls.literal_program {
                self.initializers.insert(function.ident.sym.to_string());
            }
        }
        function.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && let Some(helper) = ast::member_str(&member.prop)
            && let Expr::Fn(function) = assignment.right.unwrap_parens()
            && let Some(body) = &function.function.body
        {
            let mut helpers = Helpers::default();
            body.visit_with(&mut helpers);
            let edits = |array| ArrayHelper {
                helper: helper.to_owned(),
                array,
            };
            self.replacements.extend(helpers.replace.map(edits));
            self.pushes.extend(helpers.push.map(edits));
        }
        if let AssignTarget::Simple(SimpleAssignTarget::Ident(name)) = &assignment.left
            && let Expr::Call(call) = assignment.right.unwrap_parens()
            && run_program(call, &self.runner).is_some_and(|program| string(program).is_none())
        {
            self.returned.insert(name.id.sym.to_string());
        }
        assignment.visit_children_with(self);
    }

    fn visit_block_stmt(&mut self, block: &BlockStmt) {
        for statements in block.stmts.windows(2) {
            if let [trace_statement, entry_statement] = statements
                && let Some(trace_call) = call(trace_statement)
                && let Some(Expr::Member(member)) = callee(trace_call)
                && let Some(helper) = ast::member_str(&member.prop)
                && let Some(argument) = trace_call.args.first()
                && let Some(frame) = string(&argument.expr)
                && let Some(entry_call) = call(entry_statement)
                && let Some(Expr::Ident(entry)) = callee(entry_call)
            {
                self.roots.push(RootSite {
                    helper: helper.to_owned(),
                    frame: frame.to_owned(),
                    entry: entry.sym.to_string(),
                });
            }
        }
        block.visit_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The replace helper, the program runner, and calls where `replaceTrace` sets the root frame
    /// names.
    const ENTRIES: &str = r#"
        window.replaceTrace = function(value) {
            if (window.trace.length > 0) {
                window.trace[window.trace.length - 1] = value;
            } else {
                window.pushTrace(value);
            }
        };
        window.vlJM8 = function(p) { return new M(p).run(0, 1, []); };
        function start() { window.vlJM8("initial", window); }
        function ready() { window.replaceTrace("fresh-root"); start(); }
        function response(body) {
            callback = vlJM8(body, window);
            if (typeof callback === 'function') {
                window.replaceTrace("fresh-response"); callback({}, send);
            }
        }
    "#;

    /// The trace of a script defining `helpers` and [`ENTRIES`].
    fn recover(helpers: &str) -> Trace {
        let parsed = ast::parse_iframe_javascript(&format!("{helpers}{ENTRIES}")).unwrap();
        Trace::from_parsed(&parsed).unwrap()
    }

    #[test]
    fn recovers_trace_helpers_and_roots_from_entry_calls() {
        let trace = recover(
            r#"
            window.pushTrace = function(value) {
                if (window.trace.length < window.limit) {
                    window.trace.push(value);
                }
            };
        "#,
        );
        assert_eq!(trace.push.as_deref(), Some("pushTrace"));
        assert_eq!(trace.global, "trace");
        assert_eq!(trace.replace, "replaceTrace");
        assert_eq!(trace.initial_root, "fresh-root");
        assert_eq!(trace.returned_root, "fresh-response");
        assert_eq!(
            recover("").push,
            None,
            "no push helper, so no controller frame"
        );
    }
}
