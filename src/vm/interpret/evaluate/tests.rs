//! Compares slot plans with scoped plans by running every tested function both ways.

use swc_core::atoms::Atom;
use swc_core::ecma::ast::BinaryOp;

use crate::js::ast;
use crate::vm::extract;
use crate::vm::interpret::plan::FunctionPlan;
use crate::vm::interpret::run::Stop;
use crate::vm::interpret::{Run, semantics};
use crate::vm::output::Term;
use crate::vm::session::Session;
use crate::vm::value::{Callable, Value};

/// Compares results, exceptions, symbolic effects, branches, and global writes. Each execution
/// has independent mutable state.
fn compare(source: &str, arguments: Vec<Value<'static>>, decisions: Vec<bool>, slots: bool) {
    // Leak the script text so arguments can be prepared before parsing it.
    let parsed: &_ = Box::leak(Box::new(ast::parse_iframe_javascript(source).unwrap()));
    let mut session = Session::empty();
    session.functions = extract::functions(&parsed.script.body);
    let function = session.functions.get(&Atom::from("f")).unwrap();
    assert_eq!(FunctionPlan::compile(function).is_some(), slots, "{source}");
    session
        .bindings
        .insert(Atom::from("outer"), Value::Number(17.0));
    let execute = |disabled| {
        session.compiled.disabled.set(disabled);
        let mut run = Run::method(&session);
        run.program = &[3, 7, 255];
        run.branches.decisions = decisions.clone();
        let result = run.invoke(
            &Callable::Script {
                name: None,
                function,
                scope: None,
            },
            Value::Number(23.0),
            arguments.clone(),
        );
        let result = match result {
            Ok(value) => format!("return {:?}", value.expr()),
            Err(stop) => match *stop {
                Stop::Throw(value) => format!("throw {:?}", value.expr()),
                Stop::Unsupported(reason) => format!("unsupported {reason}"),
            },
        };
        let mut globals: Vec<_> = run
            .globals
            .iter()
            .map(|(name, value)| (name.to_string(), format!("{:?}", value.expr())))
            .collect();
        globals.sort();
        format!(
            "{result}\n{:?}\n{:?}\n{globals:?}",
            run.effects, run.branches.decisions
        )
    };
    assert_eq!(execute(false), execute(true), "{source}");
}

#[test]
fn locals_calls_and_operand_order_match() {
    for source in [
        "function f(a) { var b = a + 3; b *= 2; return b; }",
        "function f(a, a) { return a; }",
        "function f(a) { var b; b = a++; return b * 100 + a; }",
        "function f(a) { var x = 3; x += (x = 4); return x; }",
        "function f(a) { var x = [1, 2]; x[0] += (x[0] = 4); return x; }",
        "function f(a) { var x = [a]; x.push(3); return x.slice(0); }",
        "function g(x) { return x * 3; } function f(a) { return g(a) + this; }",
        "function f(a) { outer += a; return outer; }",
        "function f(a) { outer = 4; var outer = outer + 1; return outer; }",
        "function f(a) { missing = 4; var missing = missing + a; return missing; }",
        "function f(a) { var s = ''; for (var i = 0; i < a; i++) { s += 'x'; } return s; }",
        "function f(a) { return '\\ud800' + '\\udc00'; }",
        "function f(a) { return Array(a); }",
        "function f(a) { switch(a) { default: a++; case 2: a += 3; case 5: a *= 2; break; } return a; }",
        "function f(a) { return new Array(a); }",
        "function f(a) { throw a + 1; }",
        "function f(a) { return arguments[1] + arguments.length + a; }",
        "function f(a) { arguments = 3; return arguments; }",
        "function f(a) { var o = {x: a, 'y': 2, 3: outer}; o.x += 1; return o; }",
        "function f(a) { var o = {}; o.g = function(x, y) { return x | y + outer; }; return o.g(a, 4); }",
        "function f(a) { var g = function h(n) { return n ? h(n - 1) + 1 : 0; }; return g(a); }",
        "function f(a) { var g = (x) => x * 2 + this; return g(a); }",
        "function f(a) { try { throw a; } catch (e) { return e + 1; } finally { outer = a; } }",
    ] {
        compare(
            source,
            vec![Value::Number(2.0), Value::Number(5.0)],
            vec![],
            true,
        );
    }
}

#[test]
fn branches_and_loops_match() {
    for source in [
        "function f(a) { if (a) return 1; else return 2; }",
        "function f(a) { return a && 3; }",
        "function f(a) { return a || 3; }",
        "function f(a) { return a ?? 3; }",
        "function f(a) { return a && absent.x; }",
        "function f(a) { var x = 0; return (a && (x = 7)) + x; }",
        "function f(a) { return a ? 1 : 2; }",
        "function f(a) { var n = 0; while (n < 5) { n++; if (n == 2) continue; if (n == 4) break; } return n; }",
        "function f(a) { var n = 0; do { n++; } while(n < 3); return n; }",
        "function f(a) { var n = 0; again: for(var i = 0; i < 5; i++) { if (i == 2) continue again; n++; } return n; }",
        "function f(a) { end: { if (a) break end; return 1; } return 2; }",
        "function f(a) { while(a) { return 1; } return 2; }",
    ] {
        for decision in [true, false] {
            compare(
                source,
                vec![Value::symbolic(Term::Reg(7))],
                vec![decision],
                true,
            );
        }
    }
}

#[test]
fn rejected_functions_use_scoped_plans() {
    for source in [
        "function f(a) { return (function() { return a; })(); }",
        "function f(a) { var g = () => a; return g(); }",
        "function f(a) { var g = () => arguments[0]; return g(); }",
        "function f(a) { var g = function() { return a; }; return g(); }",
        "function f(arguments) { return arguments; }",
        "function f(a) { return {[a]: 1}; }",
        "function f(a) { try { return a; } catch ({ e }) { return 0; } }",
    ] {
        compare(source, vec![Value::Number(2.0)], vec![], false);
    }
}

#[test]
fn numeric_operands_and_effects_match() {
    for source in [
        "function f(a) { var i = 0; return a + i++ * 2 + i; }",
        "function f(a) { var i = 1; return (a * i++ + --i) ^ (i << 2); }",
        "function f(a) { var i = 0; return (a + i++) < i; }",
        "function f(a) { return ~a + (+a) - (-a); }",
    ] {
        for value in [
            Value::Number(2.0),
            Value::Number(f64::NAN),
            Value::Undefined,
            Value::Null,
            Value::Bool(true),
            Value::string("2"),
            Value::symbolic(Term::Reg(7)),
        ] {
            compare(source, vec![value], vec![], true);
        }
    }
}

#[test]
fn program_bytes_match() {
    for source in [
        "function f(a) { return a[0]; }",
        "function f(a) { return a[99]; }",
        "function f(a) { return typeof a[99]; }",
        "function f(a) { return a[99] === a[98]; }",
        "function f(a) { return a[99] == null; }",
        "function f(a) { return a[99] + 1; }",
        "function f(a) { return a[99] < 1; }",
        "function f(a) { return !a[99]; }",
        "function f(a) { var i = 0; return a[i++] | (a[i++] << 8) | (a[i] << 16); }",
        "function f(a) { var i = 0; return a[i++] * 2 + a[i++] + i; }",
    ] {
        compare(source, vec![Value::Program], vec![], true);
    }
}

#[test]
fn numeric_operations_match_javascript_semantics() {
    let values = [
        0.0,
        -0.0,
        1.0,
        -1.0,
        255.0,
        4294967297.0,
        1e30,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];
    let operators = [
        BinaryOp::Add,
        BinaryOp::Sub,
        BinaryOp::Mul,
        BinaryOp::Div,
        BinaryOp::Mod,
        BinaryOp::Exp,
        BinaryOp::BitAnd,
        BinaryOp::BitOr,
        BinaryOp::BitXor,
        BinaryOp::LShift,
        BinaryOp::RShift,
        BinaryOp::ZeroFillRShift,
        BinaryOp::EqEq,
        BinaryOp::EqEqEq,
        BinaryOp::NotEq,
        BinaryOp::NotEqEq,
        BinaryOp::Lt,
        BinaryOp::LtEq,
        BinaryOp::Gt,
        BinaryOp::GtEq,
    ];
    for operator in operators {
        for a in values {
            for b in values {
                let actual = super::binary_value(operator, Value::Number(a), Value::Number(b));
                let expected =
                    semantics::binary_value(operator, Value::Number(a), Value::Number(b));
                // Debug retains signed zero and compares NaN results by spelling.
                assert_eq!(
                    format!("{:?}", actual.expr()),
                    format!("{:?}", expected.expr()),
                    "{a} {operator:?} {b}"
                );
            }
        }
    }
}
