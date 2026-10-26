//! Precomputes opcode decoding and dispatch-key updates without running the VM.
//!
//! Builds use different formulas, so this module compiles them from the session's dispatch
//! loop, inlining single-return operator helpers, and evaluates every key and byte.

use std::mem;

use anyhow::{Result, ensure};
use swc_core::atoms::Atom;
use swc_core::ecma::ast::{
    AssignExpr, AssignTarget, CallExpr, Callee, Decl, Expr, Function, Lit, MemberExpr, ObjectLit,
    Pat, Script, SimpleAssignTarget, Stmt, UnaryOp, UpdateOp, VarDecl, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use super::{HashMap, interpret};
use crate::js;
use crate::js::ast;

/// Decoded result for every byte and dispatch key, indexed by `key << 8 | byte`.
pub(crate) struct Dispatch(Vec<Decoded>);

/// What one program byte decodes to under one dispatch key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Decoded {
    pub(crate) opcode: u8,
    /// The dispatch key the next byte decodes under.
    pub(crate) key: u8,
}

impl Dispatch {
    /// Evaluates each dispatch loop's decoding formula and checks that all loops agree.
    pub(crate) fn from_run(run: &Function, helpers: &Helpers) -> Result<Self> {
        use anyhow::Context;

        let mut loops = Loops::default();
        run.visit_with(&mut loops);
        let mut tables = loops
            .0
            .iter()
            .filter_map(|(prefix, opcode)| tabulate(prefix, opcode, helpers));
        let table = tables
            .next()
            .context("expected a dispatch loop in the VM's run method")?;
        ensure!(
            tables.all(|other| other == table),
            "the VM's dispatch loops disagree"
        );
        Ok(Self(table))
    }

    #[must_use]
    pub(crate) fn decode(&self, key: u8, byte: u8) -> Decoded {
        self.0[usize::from(key) << 8 | usize::from(byte)]
    }
}

/// Recovers opcode decoding and key updates from statements preceding a dispatch switch.
fn tabulate(prefix: &[Stmt], opcode: &Atom, helpers: &Helpers) -> Option<Vec<Decoded>> {
    let decode = prefix
        .iter()
        .rposition(|statement| assigned(statement).is_some_and(|(name, _)| name == *opcode))?;
    let statements = &prefix[decode..];
    // The last register write before dispatch updates the key; the other array read supplies
    // program bytes.
    let (key_array, key_index) = statements.iter().rev().find_map(|statement| {
        cell(
            statement
                .as_expr()?
                .expr
                .as_assign()?
                .left
                .as_simple()?
                .as_member()?,
        )
    })?;
    let (_, decoded) = assigned(&statements[0])?;
    let mut reads = Reads::default();
    decoded.visit_with(&mut reads);
    let program = reads.0.into_iter().find(|array| *array != key_array)?;

    let mut compiler = FormulaCompiler::new(helpers, program);
    let formulas: Vec<Formula> = statements
        .iter()
        .map(|statement| compiler.statement(statement))
        .collect::<Option<_>>()?;
    let key = compiler.variable(Slot::Cell {
        array: key_array,
        index: key_index,
    });
    let opcode = compiler.variable(Slot::Local(opcode.clone()));
    let variables = compiler.variables.len();
    // Reuse one buffer for all entries, resetting values to NaN to represent `undefined` in
    // arithmetic.
    let mut values = vec![f64::NAN; variables];
    let mut table = Vec::with_capacity(1 << 16);
    for key_value in 0..=u8::MAX {
        for byte in 0..=u8::MAX {
            values.fill(f64::NAN);
            values[key] = f64::from(key_value);
            for formula in &formulas {
                formula.evaluate(&mut values, f64::from(byte));
            }
            table.push(Decoded {
                opcode: js::int32(values[opcode]) as u8,
                key: js::int32(values[key]) as u8,
            });
        }
    }
    Some(table)
}

/// An arithmetic formula compiled from the VM source.
enum Formula {
    Number(f64),
    Variable(usize),
    /// A read of the program array. Uses the byte being tabulated regardless of index.
    Byte(Box<Formula>),
    /// `x++`, `x--`, `++x` or `--x`.
    Update {
        variable: usize,
        delta: f64,
        prefix: bool,
    },
    Unary(fn(f64) -> f64, Box<Formula>),
    Binary(fn(f64, f64) -> f64, Box<Formula>, Box<Formula>),
    Assign(usize, Box<Formula>),
    /// A helper call: arguments evaluate left to right into parameter slots, then the body.
    Inline {
        arguments: Vec<(usize, Formula)>,
        body: Box<Formula>,
    },
}

impl Formula {
    fn evaluate(&self, values: &mut [f64], byte: f64) -> f64 {
        match self {
            Self::Number(value) => *value,
            Self::Variable(variable) => values[*variable],
            Self::Byte(index) => {
                index.evaluate(values, byte);
                byte
            }
            Self::Update {
                variable,
                delta,
                prefix,
            } => {
                let old = values[*variable];
                values[*variable] = old + delta;
                if *prefix { old + delta } else { old }
            }
            Self::Unary(operation, operand) => operation(operand.evaluate(values, byte)),
            Self::Binary(operation, left, right) => {
                let left = left.evaluate(values, byte);
                let right = right.evaluate(values, byte);
                operation(left, right)
            }
            Self::Assign(variable, value) => {
                let value = value.evaluate(values, byte);
                values[*variable] = value;
                value
            }
            Self::Inline { arguments, body } => {
                for (parameter, argument) in arguments {
                    values[*parameter] = argument.evaluate(values, byte);
                }
                body.evaluate(values, byte)
            }
        }
    }
}

/// Where a compiled formula keeps one value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Slot {
    Local(Atom),
    /// Variable slot for an `array[index]` access whose index is a variable.
    Cell {
        array: Atom,
        index: Atom,
    },
    /// One parameter of one inlined helper call.
    Argument(usize),
}

/// Compiles numeric statements and expressions. Reads from `program` supply bytes; other
/// indexed accesses get variable slots.
struct FormulaCompiler<'helpers> {
    helpers: &'helpers Helpers,
    program: Atom,
    variables: Vec<Slot>,
    /// The parameters of the helper being inlined, bound to their slots.
    arguments: HashMap<Atom, usize>,
    /// The helpers being inlined, innermost last, to reject recursion.
    inlining: Vec<&'helpers (Atom, Atom)>,
}

impl<'helpers> FormulaCompiler<'helpers> {
    fn new(helpers: &'helpers Helpers, program: Atom) -> Self {
        Self {
            helpers,
            program,
            variables: Vec::new(),
            arguments: HashMap::default(),
            inlining: Vec::new(),
        }
    }

    fn variable(&mut self, slot: Slot) -> usize {
        if let Some(index) = self.variables.iter().position(|variable| *variable == slot) {
            return index;
        }
        self.variables.push(slot);
        self.variables.len() - 1
    }

    /// The slot of an active helper parameter or local named `name`.
    fn local(&mut self, name: &Atom) -> usize {
        match self.arguments.get(name) {
            Some(&slot) => slot,
            None => self.variable(Slot::Local(name.clone())),
        }
    }

    fn cell(&mut self, member: &MemberExpr) -> Option<usize> {
        let (array, index) = cell(member)?;
        Some(self.variable(Slot::Cell { array, index }))
    }

    fn statement(&mut self, statement: &Stmt) -> Option<Formula> {
        if let Stmt::Expr(statement) = statement {
            return self.expression(&statement.expr);
        }
        let (name, init) = assigned(statement)?;
        let value = self.expression(init)?;
        let variable = self.local(&name);
        Some(Formula::Assign(variable, Box::new(value)))
    }

    fn expression(&mut self, expression: &Expr) -> Option<Formula> {
        Some(match expression {
            Expr::Lit(Lit::Num(number)) => Formula::Number(number.value),
            Expr::Paren(paren) => self.expression(&paren.expr)?,
            Expr::Ident(name) => Formula::Variable(self.local(&name.sym)),
            Expr::Member(member) => {
                if member.obj.as_ident()?.sym == self.program {
                    let index = &member.prop.as_computed()?.expr;
                    Formula::Byte(Box::new(self.expression(index)?))
                } else {
                    Formula::Variable(self.cell(member)?)
                }
            }
            Expr::Unary(unary) => {
                let operation: fn(f64) -> f64 = match unary.op {
                    UnaryOp::Minus => |value| -value,
                    UnaryOp::Plus => |value| value,
                    UnaryOp::Tilde => js::bit_not,
                    UnaryOp::Bang => |value| f64::from(u8::from(value == 0.0 || value.is_nan())),
                    _ => return None,
                };
                Formula::Unary(operation, Box::new(self.expression(&unary.arg)?))
            }
            Expr::Bin(binary) => Formula::Binary(
                interpret::numeric(binary.op)?,
                Box::new(self.expression(&binary.left)?),
                Box::new(self.expression(&binary.right)?),
            ),
            Expr::Update(update) => Formula::Update {
                variable: self.local(&update.arg.as_ident()?.sym),
                delta: match update.op {
                    UpdateOp::PlusPlus => 1.0,
                    UpdateOp::MinusMinus => -1.0,
                },
                prefix: update.prefix,
            },
            Expr::Assign(assign) => {
                let variable = match &assign.left {
                    AssignTarget::Simple(SimpleAssignTarget::Ident(name)) => {
                        self.local(&name.id.sym)
                    }
                    AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
                        self.cell(member)?
                    }
                    _ => return None,
                };
                let value = self.expression(&assign.right)?;
                let value = match assign.op.to_update() {
                    None => value,
                    Some(operator) => Formula::Binary(
                        interpret::numeric(operator)?,
                        Box::new(Formula::Variable(variable)),
                        Box::new(value),
                    ),
                };
                Formula::Assign(variable, Box::new(value))
            }
            Expr::Call(call) => self.inline(call)?,
            _ => return None,
        })
    }

    /// Compiles a helper call in JavaScript evaluation order: each argument once, left to
    /// right, then the body. Rejects spreads, argument-count mismatches, and recursion.
    fn inline(&mut self, call: &CallExpr) -> Option<Formula> {
        let callee = call.callee.as_expr()?.as_member()?;
        let helpers = self.helpers;
        let name = (
            callee.obj.as_ident()?.sym.clone(),
            Atom::from(ast::member_str(&callee.prop)?),
        );
        let (name, helper) = helpers.0.get_key_value(&name)?;
        if call.args.len() != helper.parameters.len()
            || call.args.iter().any(|argument| argument.spread.is_some())
            || self.inlining.contains(&name)
        {
            return None;
        }
        let mut arguments = Vec::new();
        let mut parameters = HashMap::default();
        for (parameter, argument) in helper.parameters.iter().zip(&call.args) {
            let value = self.expression(&argument.expr)?;
            // Allocate a fresh slot so separate calls cannot share parameter storage.
            let slot = self.variable(Slot::Argument(self.variables.len()));
            arguments.push((slot, value));
            parameters.insert(parameter.clone(), slot);
        }
        let outer = mem::replace(&mut self.arguments, parameters);
        self.inlining.push(name);
        let body = self.expression(&helper.body);
        self.inlining.pop();
        self.arguments = outer;
        Some(Formula::Inline {
            arguments,
            body: Box::new(body?),
        })
    }
}

/// A helper of the form `function(parameters...) { return body; }`.
struct Helper {
    parameters: Vec<Atom>,
    body: Expr,
}

/// Single-return operator helpers by object and property name, from object literals and from
/// later property assignments such as `x = {}; x.wQKAm = function(a, b) { return b ^ a; };`.
#[derive(Default)]
pub(crate) struct Helpers(HashMap<(Atom, Atom), Helper>);

impl Helpers {
    #[must_use]
    pub(crate) fn new(script: &Script) -> Self {
        let mut helpers = Self::default();
        script.visit_with(&mut helpers);
        helpers
    }

    fn record_literal(&mut self, object: &Atom, literal: &ObjectLit) {
        for property in ast::key_values(literal) {
            if let Some(name) = ast::key_str(&property.key).map(Atom::from) {
                self.record(object, name, &property.value);
            }
        }
    }

    /// Records `object.property = value` when `value` defines a helper.
    fn record(&mut self, object: &Atom, property: Atom, value: &Expr) {
        if let Expr::Fn(function) = value
            && let Some(value) = ast::returned(&function.function)
            && let Some(parameters) = function
                .function
                .params
                .iter()
                .map(|parameter| parameter.pat.as_ident().map(|name| name.id.sym.clone()))
                .collect::<Option<Vec<_>>>()
        {
            let helper = Helper {
                parameters,
                body: value.clone(),
            };
            self.0.insert((object.clone(), property), helper);
        }
    }
}

impl Visit for Helpers {
    fn visit_assign_expr(&mut self, assign: &AssignExpr) {
        match &assign.left {
            AssignTarget::Simple(SimpleAssignTarget::Ident(object)) => {
                if let Expr::Object(literal) = &*assign.right {
                    self.record_literal(&object.id.sym, literal);
                }
            }
            AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
                if let Expr::Ident(object) = &*member.obj
                    && let Some(name) = ast::member_str(&member.prop).map(Atom::from)
                {
                    self.record(&object.sym, name, &assign.right);
                }
            }
            _ => {}
        }
        assign.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Pat::Ident(object) = &declarator.name
            && let Some(init) = &declarator.init
            && let Expr::Object(literal) = &**init
        {
            self.record_literal(&object.id.sym, literal);
        }
        declarator.visit_children_with(self);
    }
}

/// The statements preceding each switch on a variable, with multi-variable declarations split
/// into single declarations in order.
#[derive(Default)]
struct Loops(Vec<(Vec<Stmt>, Atom)>);

impl Visit for Loops {
    fn visit_stmts(&mut self, statements: &[Stmt]) {
        for (index, statement) in statements.iter().enumerate() {
            if let Stmt::Switch(switch) = statement
                && let Expr::Ident(opcode) = &*switch.discriminant
            {
                let prefix: Vec<Stmt> = statements[..index].iter().flat_map(split).collect();
                self.0.push((prefix, opcode.sym.clone()));
            }
        }
        statements.visit_children_with(self);
    }
}

fn split(statement: &Stmt) -> Vec<Stmt> {
    match statement {
        Stmt::Decl(Decl::Var(declaration)) if declaration.decls.len() > 1 => declaration
            .decls
            .iter()
            .map(|declarator| {
                Stmt::Decl(Decl::Var(Box::new(VarDecl {
                    decls: vec![declarator.clone()],
                    ..(**declaration).clone()
                })))
            })
            .collect(),
        _ => vec![statement.clone()],
    }
}

/// Arrays indexed by an expression, except in callees.
#[derive(Default)]
struct Reads(Vec<Atom>);

impl Visit for Reads {
    fn visit_member_expr(&mut self, member: &MemberExpr) {
        if let Expr::Ident(array) = &*member.obj
            && member.prop.is_computed()
        {
            self.0.push(array.sym.clone());
        }
        member.visit_children_with(self);
    }

    fn visit_callee(&mut self, _: &Callee) {}
}

/// Returns the target variable and value from `x = value`, `x op= value`, or `let x = value`.
fn assigned(statement: &Stmt) -> Option<(Atom, &Expr)> {
    match statement {
        Stmt::Expr(statement) => {
            let assign = statement.expr.as_assign()?;
            let name = assign.left.as_simple()?.as_ident()?;
            Some((name.id.sym.clone(), &assign.right))
        }
        Stmt::Decl(Decl::Var(declaration)) => match &declaration.decls[..] {
            [
                VarDeclarator {
                    name: Pat::Ident(name),
                    init: Some(init),
                    ..
                },
            ] => Some((name.id.sym.clone(), init)),
            _ => None,
        },
        _ => None,
    }
}

/// The array and index of `array[index]`, both identifiers.
fn cell(member: &MemberExpr) -> Option<(Atom, Atom)> {
    let array = member.obj.as_ident()?.sym.clone();
    Some((
        array,
        member.prop.as_computed()?.expr.as_ident()?.sym.clone(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(source: &str) -> Script {
        ast::parse_javascript("t.js", source).unwrap().script
    }

    const HELPERS: &str = "h = { x: function(a, b) { return b ^ a; } }; \
                           q = {}; q.y = function(a, b) { return b ^ a; };";

    fn dispatch(loops: &[&str]) -> Result<Dispatch> {
        let loops: String = loops
            .iter()
            .map(|body| format!("while (true) {{ {body} switch (G) {{}} }}"))
            .collect();
        let script = script(&format!("{HELPERS} (function() {{ {loops} }});"));
        let function = script.body.last().unwrap().as_expr().unwrap();
        let function = function.expr.as_paren().unwrap();
        Dispatch::from_run(
            &function.expr.as_fn_expr().unwrap().function,
            &Helpers::new(&script),
        )
    }

    fn assert_dispatch(loops: &[&str], offset: u8, step: impl Fn(u32) -> u32) {
        let dispatch = dispatch(loops).unwrap();
        for key in 0..=u8::MAX {
            for byte in [0_u8, 1, 0x7f, 0x90, 0xff] {
                let opcode = key ^ byte.wrapping_sub(offset);
                let next = step(u32::from(key) + u32::from(opcode)) as u8;
                assert_eq!(
                    dispatch.decode(key, byte),
                    Decoded { opcode, key: next },
                    "misread {loops:?} at key {key}, byte {byte}"
                );
            }
        }
    }

    #[test]
    fn evaluates_the_dispatch_loop_however_it_is_spelled() {
        let linear = |t: u32| t.wrapping_mul(46006).wrapping_add(28231);
        for body in [
            "G = k[i] ^ p[G] - 177 + 256 & 255; k[i] = (k[i] + G) * 46006 + 28231 & 255;",
            "G = 79 + p[G] & 255 ^ k[i]; k[i] = 255 & 46006 * (k[i] + G) + 28231;",
            "G = k[i] ^ 255 & 79 + p[G]; k[i] = 255 & (k[i] + G) * 46006 + 28231;",
            // A later build drops the `+ 256` and XORs through a helper.
            "G = h.x(k[i], p[G] - 177 & 255); k[i] = 46006 * (k[i] + G) + 28231 & 255;",
        ] {
            assert_dispatch(&[body], 177, linear);
        }
        // Later variants use a quadratic key update stored separately. One loop declares values
        // that the other assigns.
        assert_dispatch(
            &[
                "P = r[j]; r[j] = P + 1; G = h.x(k[i], 255 & p[P] - 144); t = k[i] + G; \
                 k[i] = t * t * 6697 + t * 55697 + 22825 & 255;",
                "let G = k[i] ^ p[P] - 144 & 255; let t = k[i] + G; \
                 k[i] = 255 & t * t * 6697 + 55697 * t + 22825;",
            ],
            144,
            |t| t * t * 6697 + t * 55697 + 22825,
        );
        // This build declares opcode and key sum together and constructs helpers through
        // property writes. Either loop must produce the full table independently.
        let quadratic = |t: u32| {
            t.wrapping_mul(t)
                .wrapping_mul(45252)
                .wrapping_add(t * 58234)
                .wrapping_add(22596)
        };
        let declared = "P = r[j]; r[j] = P + 1; let G = k[i] ^ 255 & p[P] - 84, t = k[i] + G; \
                        k[i] = t * t * 45252 + 58234 * t + 22596 & 255;";
        let assigned = "P = r[j]; r[j] = P + 1; G = q.y(k[i], 255 & p[P] - 84); t = k[i] + G; \
                        k[i] = 45252 * (t * t) + t * 58234 + 22596 & 255;";
        assert_dispatch(&[declared], 84, quadratic);
        assert_dispatch(&[assigned], 84, quadratic);
        assert_dispatch(&[declared, assigned], 84, quadratic);
        assert!(
            dispatch(&[
                "G = k[i] ^ p[G] - 177 + 256 & 255; k[i] = (k[i] + G) * 46006 + 28231 & 255;",
                "G = k[i] ^ p[G] - 97 + 256 & 255; k[i] = (k[i] + G) * 46006 + 28231 & 255;",
            ])
            .is_err(),
            "two loops that disagree are not one VM's dispatch"
        );
    }

    #[test]
    fn inlined_helpers_evaluate_each_argument_once_in_call_order() {
        let helpers = Helpers::new(&script(
            "var h = { s: function(a, b) { return b - a; }, d: function(a) { return a + a; }, r: function(a) { return h.r(a); } };",
        ));
        for (source, expected, why) in [
            (
                "x = h.s(i++, i++);",
                Some(1.0),
                "the body reads `b` first, but `a` runs first",
            ),
            (
                "x = h.d(i++) + i;",
                Some(1.0),
                "a parameter used twice runs its argument once",
            ),
            (
                "x = h.s(1, h.d(2));",
                Some(3.0),
                "a helper call is an argument",
            ),
            (
                "x = h.s(i);",
                None,
                "a call with too few arguments is not compiled",
            ),
            (
                "x = h.d(...p);",
                None,
                "a call that spreads is not compiled",
            ),
            ("x = h.r(1);", None, "a recursive call is not compiled"),
        ] {
            let statement = script(source).body.into_iter().next().unwrap();
            let mut compiler = FormulaCompiler::new(&helpers, Atom::from("p"));
            let value = compiler.statement(&statement).map(|formula| {
                let i = compiler.variable(Slot::Local(Atom::from("i")));
                let mut values = vec![f64::NAN; compiler.variables.len()];
                values[i] = 0.0;
                formula.evaluate(&mut values, 0.0)
            });
            assert_eq!(value, expected, "{source}: {why}");
        }
    }
}
