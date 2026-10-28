//! Inlines dispatcher calls by following `if`, `switch`, and nested blocks with known numeric
//! arguments. Handles applied calls, direct calls, and operator expressions:
//!
//! ```js
//! function b(n, f, args) {
//!   switch (3832 ^ n) {
//!     case 973348: return Reflect.apply(f, undefined, args);
//!   }
//! }
//! function c(n, m, f, x) { switch (n) { case 1: switch (m) { case 2: return f(x); } } }
//! function w(op, x, y) { if (op === 0) return x + y; else return x - y; }
//!
//! b(971996, encode, [payload]);  // encode(payload)
//! c(1, 2, encode, payload);      // encode(payload)
//! w(1, 630, 622);                // 630 - 622
//! ```
//!
//! The first selector must be a literal. Applied and direct call targets must be identifiers to
//! keep `this` undefined. Direct calls must forward the remaining parameters in order, omitting
//! only numeric selectors. Operator arguments must have no side effects because they may be
//! evaluated repeatedly or in a different order. `Reflect` and `undefined` must refer to globals.
//!
//! The decoding pass only follows the first argument and leaves direct calls unchanged. This
//! preserves the dispatcher frames needed to recover click stacks.

use std::iter;

use swc_core::ecma::ast::{
    BinaryOp, CallExpr, Callee, Expr, ExprOrSpread, FnDecl, Function, Id, Lit, Program, Stmt,
    UnaryOp,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::{Analysis, Globals, effects, names};
use super::{HashMap, helper_objects};
use crate::js::ast;

/// Dispatcher patterns enabled for a pass.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Applied calls and operations selected by the first argument.
    Decoding,
    /// Also includes direct calls and selection by any numeric argument.
    All,
}

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    inline(program, analysis, Reach::Decoding)
}

pub(super) fn run_all(program: &mut Program, analysis: &mut Analysis) -> bool {
    inline(program, analysis, Reach::All)
}

fn inline(program: &mut Program, analysis: &mut Analysis, reach: Reach) -> bool {
    let globals = analysis.globals;
    let bindings = analysis.bindings(program);
    let mut functions = Functions::default();
    program.visit_with(&mut functions);
    // The declaration or assignment that defines the function is its only write, so every call
    // reaches this function.
    functions.0.retain(|id, _| bindings.is_written_once(id));
    if functions.0.is_empty() {
        return false;
    }
    let mut inline = InlineDispatchers {
        functions: &functions.0,
        globals,
        reach,
        changed: false,
    };
    program.visit_mut_with(&mut inline);
    inline.changed
}

/// Functions with only identifier parameters.
#[derive(Default)]
struct Functions(HashMap<Id, Candidate>);

struct Candidate {
    params: Vec<Id>,
    body: Vec<Stmt>,
}

impl Candidate {
    fn try_new(function: &Function) -> Option<Self> {
        let params = names::parameter_ids(&function.params)?;
        let body = &function.body.as_ref()?.stmts;
        (!params.is_empty() && !function.is_async && !function.is_generator && may_select(body))
            .then(|| Self {
                params,
                body: body.clone(),
            })
    }
}

impl Visit for Functions {
    fn visit_expr(&mut self, expression: &Expr) {
        if let Some((id, Expr::Fn(function))) = ast::assignment(expression)
            && let Some(candidate) = Candidate::try_new(&function.function)
        {
            self.0.insert(id, candidate);
        }
        expression.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        if let Some(candidate) = Candidate::try_new(&declaration.function) {
            self.0.insert(declaration.ident.to_id(), candidate);
        }
        declaration.visit_children_with(self);
    }
}

/// Checks whether some selector could reach `return value` through [`Path::run`]. Avoids
/// cloning large unrelated functions, such as VM helpers.
fn may_select<'a>(statements: impl IntoIterator<Item = &'a Stmt>) -> bool {
    for statement in statements {
        let selects = match statement {
            Stmt::Return(returned) => return returned.arg.is_some(),
            Stmt::Block(block) => may_select(&block.stmts),
            Stmt::Empty(_) => false,
            Stmt::If(conditional) => {
                may_select([&*conditional.cons]) || may_select(conditional.alt.as_deref())
            }
            Stmt::Switch(switch) => switch.cases.iter().any(|case| may_select(&case.cons)),
            _ => return false,
        };
        if selects {
            return true;
        }
    }
    false
}

/// Follows a function body for known numeric parameter values.
struct Path {
    values: HashMap<Id, f64>,
}

impl Path {
    /// Returns `Some(Some(value))` for a return with a value, `Some(None)` for normal
    /// completion, and `None` for a path it cannot analyze.
    fn run<'body>(
        &self,
        statements: impl IntoIterator<Item = &'body Stmt>,
    ) -> Option<Option<&'body Expr>> {
        for statement in statements {
            let returned = match statement {
                Stmt::Return(returned) => return Some(Some(returned.arg.as_deref()?)),
                Stmt::Block(block) => self.run(&block.stmts)?,
                Stmt::Empty(_) => None,
                Stmt::If(conditional) => match self.truthy(&conditional.test)? {
                    true => self.run([&*conditional.cons])?,
                    false => self.run(conditional.alt.as_deref())?,
                },
                Stmt::Switch(switch) => {
                    let value = self.number(&switch.discriminant)?;
                    let mut matching = None;
                    let mut default = None;
                    for (index, case) in switch.cases.iter().enumerate() {
                        let Some(test) = &case.test else {
                            default.get_or_insert(index);
                            continue;
                        };
                        if self.number(test)? == value {
                            matching.get_or_insert(index);
                        }
                    }
                    let Some(start) = matching.or(default) else {
                        continue;
                    };
                    // Fall through from the matching case until a return.
                    let body: Vec<&Stmt> = switch.cases[start..]
                        .iter()
                        .flat_map(|case| &case.cons)
                        .collect();
                    if body
                        .iter()
                        .any(|statement| matches!(statement, Stmt::Break(_)))
                    {
                        return None;
                    }
                    self.run(body)?
                }
                _ => return None,
            };
            if returned.is_some() {
                return Some(returned);
            }
        }
        Some(None)
    }

    fn truthy(&self, expression: &Expr) -> Option<bool> {
        match expression {
            Expr::Paren(inner) => self.truthy(&inner.expr),
            Expr::Unary(unary) if unary.op == UnaryOp::Bang => Some(!self.truthy(&unary.arg)?),
            Expr::Lit(Lit::Bool(value)) => Some(value.value),
            Expr::Bin(binary) => {
                let (left, right) = (self.number(&binary.left)?, self.number(&binary.right)?);
                match binary.op {
                    BinaryOp::EqEqEq | BinaryOp::EqEq => Some(left == right),
                    BinaryOp::NotEqEq | BinaryOp::NotEq => Some(left != right),
                    BinaryOp::Lt => Some(left < right),
                    BinaryOp::LtEq => Some(left <= right),
                    BinaryOp::Gt => Some(left > right),
                    BinaryOp::GtEq => Some(left >= right),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn number(&self, expression: &Expr) -> Option<f64> {
        ast::fold_number(expression, &|leaf| {
            self.values.get(&leaf.as_ident()?.to_id()).copied()
        })
    }
}

/// Returns parameter positions for the target and arguments of a call such as `target(a, b)`. Each
/// must refer to a parameter.
fn parameter_call(expression: &Expr, params: &[Id]) -> Option<Vec<usize>> {
    let call = expression.as_call()?;
    let arguments = call
        .args
        .iter()
        .map(|arg| arg.spread.is_none().then_some(&*arg.expr));
    iter::once(Some(&**call.callee.as_expr()?))
        .chain(arguments)
        .map(|expression| parameter_position(expression?, params))
        .collect()
}

/// Returns the index in `params` of the parameter named by `expression`.
fn parameter_position(expression: &Expr, params: &[Id]) -> Option<usize> {
    let id = expression.as_ident()?.to_id();
    params.iter().position(|param| *param == id)
}

/// The parameter positions of `target` and `args` in `Reflect.apply(target, undefined, args)`.
struct ReflectApply {
    target: usize,
    arguments: usize,
}

fn reflect_apply(expression: &Expr, params: &[Id], globals: Globals) -> Option<ReflectApply> {
    if let Some((reflect, [function, this, arguments])) = ast::method_call(expression, "apply")
        && reflect
            .as_ident()
            .is_some_and(|id| globals.is(id, "Reflect"))
        && [function, this, arguments]
            .iter()
            .all(|arg| arg.spread.is_none())
        && match &*this.expr {
            Expr::Ident(id) => globals.is(id, "undefined"),
            Expr::Unary(unary) => {
                unary.op == UnaryOp::Void && !effects::may_have_effects(&unary.arg, globals)
            }
            _ => false,
        }
    {
        Some(ReflectApply {
            target: parameter_position(&function.expr, params)?,
            arguments: parameter_position(&arguments.expr, params)?,
        })
    } else {
        None
    }
}

/// Operators other than `delete` combining leaves that `leaf` accepts.
fn is_operation(expression: &Expr, leaf: &impl Fn(&Expr) -> bool) -> bool {
    match expression {
        Expr::Paren(inner) => is_operation(&inner.expr, leaf),
        Expr::Unary(unary) => unary.op != UnaryOp::Delete && is_operation(&unary.arg, leaf),
        Expr::Bin(binary) => is_operation(&binary.left, leaf) && is_operation(&binary.right, leaf),
        expression => leaf(expression),
    }
}

struct InlineDispatchers<'functions> {
    functions: &'functions HashMap<Id, Candidate>,
    globals: Globals,
    reach: Reach,
    changed: bool,
}

impl InlineDispatchers<'_> {
    fn replacement(&self, callee: &Id, args: &[ExprOrSpread]) -> Option<Expr> {
        let candidate = self.functions.get(callee)?;
        if args.iter().any(|arg| arg.spread.is_some()) {
            return None;
        }
        let number = |arg: &ExprOrSpread| match &*arg.expr {
            Expr::Lit(Lit::Num(number)) => Some(number.value),
            _ => None,
        };
        number(args.first()?)?;
        let selectors = match self.reach {
            Reach::Decoding => 1,
            Reach::All => args.len(),
        };
        // Returns the selected expression only if choosing it requires constant selector
        // comparisons with no other evaluation.
        let path = Path {
            values: candidate
                .params
                .iter()
                .zip(&args[..selectors])
                .filter_map(|(param, arg)| Some((param.clone(), number(arg)?)))
                .collect(),
        };
        let returned = path.run(&candidate.body)??;
        if self.reach == Reach::All
            && let Some(positions) = parameter_call(returned, &candidate.params)
            && args.len() == candidate.params.len()
            && positions.is_sorted_by(|before, after| before < after)
            && (0..args.len())
                .all(|index| positions.contains(&index) || number(&args[index]).is_some())
            && let [target, passed @ ..] = &positions[..]
            && args[*target].expr.is_ident()
        {
            return Some(Expr::Call(CallExpr {
                callee: Callee::Expr(args[*target].expr.clone()),
                args: passed.iter().map(|&index| args[index].clone()).collect(),
                ..Default::default()
            }));
        }
        if let Some(apply) = reflect_apply(returned, &candidate.params, self.globals)
            && let Some(target) = args.get(apply.target)
            && target.expr.is_ident()
            && let Expr::Array(applied) = &*args.get(apply.arguments)?.expr
            && let Some(applied) = applied
                .elems
                .iter()
                .map(|element| element.clone().filter(|element| element.spread.is_none()))
                .collect::<Option<Vec<_>>>()
        {
            return Some(Expr::Call(CallExpr {
                callee: Callee::Expr(target.expr.clone()),
                args: applied,
                ..Default::default()
            }));
        }
        // The operation may repeat or reorder arguments. Allow only literals and bindings whose
        // reads have no effects. Unknown globals could throw or invoke getters.
        let is_parameter_or_number = |leaf: &Expr| match leaf {
            Expr::Ident(id) => candidate.params.contains(&id.to_id()),
            leaf => matches!(leaf, Expr::Lit(Lit::Num(_))),
        };
        let is_pure = |leaf: &Expr| match leaf {
            Expr::Ident(_) => !effects::may_have_effects(leaf, self.globals),
            leaf => matches!(leaf, Expr::Lit(Lit::Num(_) | Lit::Str(_) | Lit::Bool(_))),
        };
        if args.len() == candidate.params.len()
            && is_operation(returned, &is_parameter_or_number)
            && args.iter().all(|arg| is_operation(&arg.expr, &is_pure))
        {
            let values: HashMap<Id, &Expr> = candidate
                .params
                .iter()
                .cloned()
                .zip(args.iter().map(|arg| &*arg.expr))
                .collect();
            // The operation calls nothing, so no parameter needs detaching.
            Some(helper_objects::replace_parameters(returned, values))
        } else {
            None
        }
    }
}

impl VisitMut for InlineDispatchers<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        if let Some((callee, args)) = ast::direct_call(expression)
            && let Some(replacement) = self.replacement(&callee.to_id(), args)
        {
            *expression = replacement;
            self.changed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    const APPLY: &str = "var b; b = function (n, m, r) {
        switch (3832 ^ n) {
            case 973348: return Reflect.apply(m, undefined, r);
            case 428312: return Reflect.apply(m, void 0, r);
        }
    };";

    const OPERATOR: &str = "var w; w = function (E, P, S) {
        switch (E) { case 0: return P + S; case 1: return P - S; case 2: return S * P; default: return P % S; }
    };";

    #[test]
    fn applies_the_target_only_for_provable_applications() {
        let inline = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = inline(&format!(
            "{APPLY} f(b(971996, encode, [x, 1]), b(428000, g, []));"
        ));
        assert!(output.contains("f(encode(x, 1), g())"), "{output}");
        for call in [
            "b(1, encode, [x])",
            "b(971996, o.encode, [x])",
            "b(971996, encode, args)",
            "b(971996, encode, [...x])",
        ] {
            let output = inline(&format!("{APPLY} f({call});"));
            assert!(output.contains("f(b("), "{output}");
        }
        let reassigned = inline(&format!("{APPLY} b = h; f(b(971996, encode, [x]));"));
        assert!(reassigned.contains("f(b("), "{reassigned}");
    }

    #[test]
    fn calls_targets_selected_by_several_selectors_only_in_argument_order() {
        let inline = |source: &str| testing::rewrite(source, super::run_all, /* fix= */ true);
        let dispatchers = "function c(n, m, f, x, y) {
                switch (n ^ 5) { case 1: switch (3 ^ m) { case 1: return f(x, y); } return; }
            }
            function d(n, f, x, y) { switch (n) { case 0: return f(y, x); } }";
        let source = format!("{dispatchers} g(c(4, 2, encode, a(), b));");
        let output = inline(&source);
        assert!(output.contains("g(encode(a(), b))"), "{output}");
        let decoding = testing::rewrite(&source, super::run, /* fix= */ true);
        assert!(decoding.contains("g(c(4, 2,"), "{decoding}");
        for call in [
            "c(4, 2, o.encode, a, b)",
            "c(4, 2, encode, a)",
            "c(4, 1, encode, a, b)",
            "d(0, encode, a, b)",
        ] {
            let output = inline(&format!("{dispatchers} g({call});"));
            assert!(output.contains(&format!("g({call})")), "{output}");
        }
    }

    #[test]
    fn inlines_selected_operations_through_switches_if_chains_and_xor_keys() {
        let inline = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
        let output = inline(&format!(
            "{OPERATOR} function g(a, b) {{ f(w(1, 630, 622), w(2, a, b + 1), w(9, 7, 2)); }}"
        ));
        testing::assert_contains(&output, &["f(630 - 622, (b + 1) * a, 7 % 2)"], &[]);
        let output = inline(
            "t = function (V, c, X) {
                if (!(V !== 0)) { return c + X; } else { if (!(2 === V)) { return c % X; } else { return X * c; } }
            };
            function q(J, r, n) { switch (2774 ^ J) { case 0: return r | n; default: return r & n; } }
            function g(a, b) { f(t(0, a, b), t(2, a, b), t(5, a, b), q(2774, a, b), q(2775, a, b)); }",
        );
        testing::assert_contains(&output, &["f(a + b, b * a, a % b, a | b, a & b)"], &[]);
        // Arguments with effects and unknown selectors stay.
        for call in ["w(1, g(), 2)", "w(n, 1, 2)", "w(1, 2)", "w(1, missing, 2)"] {
            let output = inline(&format!("{OPERATOR} f({call});"));
            assert!(output.contains(&format!("f({call})")), "{output}");
        }
    }

    #[test]
    fn only_bodies_that_can_select_a_return_are_candidates() {
        use swc_core::ecma::ast::{Decl, Stmt};

        let selects = |body: &str| {
            let script =
                crate::js::ast::parse_javascript("a test", &format!("function f(n) {{ {body} }}"))
                    .unwrap()
                    .script;
            let Some(Stmt::Decl(Decl::Fn(function))) = script.body.first() else {
                panic!("not a function declaration: {body}");
            };
            super::may_select(&function.function.body.as_ref().unwrap().stmts)
        };
        for body in [
            "return 1;",
            ";{ if (n) {} else { return 2; } }",
            "switch (n) { case 0: g(); case 1: return 3; }",
        ] {
            assert!(selects(body), "{body}");
        }
        for body in [
            "",
            "return;",
            "var x = 1; return x;",
            "while (n) { return 1; }",
        ] {
            assert!(!selects(body), "{body}");
        }
    }
}
