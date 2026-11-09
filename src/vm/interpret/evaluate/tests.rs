//! Compares slot plans with scoped plans by running every tested function both ways.

use oxc::syntax::operator::BinaryOperator;

use crate::js::ast::{Binding, ParsedScript, Script};
use crate::vm::disassemble;
use crate::vm::interpret::plan::{FunctionPlan, Name, Routine};
use crate::vm::interpret::run::Stop;
use crate::vm::interpret::{Run, semantics};
use crate::vm::output::{Effect, Position, Term};
use crate::vm::session::{Layout, Session};
use crate::vm::value::{Callable, Value};

#[test]
fn concrete_register_stack_keeps_its_exception_continuation() {
    let parsed = ParsedScript::parse("t", "function f(stack) { stack.push([42, 9, [], 0]); }")
        .expect("the source parses");
    let mut session = Session::empty(parsed.script());
    session.layout = Layout {
        pc: 240,
        key: 241,
        program: 242,
        cells: 243,
    };
    session.initial = vec![(7, Value::array(Vec::new()))];
    let mut run = Run::method(&session);
    run.start_at(0, 0);
    let stack = Value::array(Vec::new());
    run.registers.insert(7, stack.clone());
    let function = Callable::Script {
        name: None,
        function: session.declared("f"),
        scope: None,
    };
    let result = run.invoke(&function, Value::Undefined, vec![stack]);
    let path = run.finish(result).expect("the call completes");
    let catches = |frame: &Term| {
        matches!(frame, Term::Array(values)
            if disassemble::catch_frame(values) == Some(Position::new(42, 9)))
    };
    assert!(
        path.effects.iter().any(|effect| matches!(effect,
            Effect::Set(7, Term::Array(frames)) if frames.iter().any(catches))),
        "the pushed catch frame is kept as a register effect: {:?}",
        path.effects
    );
}

/// Compares results, exceptions, symbolic effects, branches, and global writes. Each execution
/// has independent mutable state. Returns the shared outcome, starting with the result.
fn compare(
    source: &str,
    arguments: Vec<Value<'static>>,
    decisions: Vec<bool>,
    slots: bool,
) -> String {
    assert_eq!(plan_of(source).is_some(), slots, "{source}");
    let mut session = Session::empty(parse(source));
    let function = session.declared("f");
    session
        .bindings
        .insert(Binding::Global("outer"), Value::Number(17.0));
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
            .map(|(binding, value)| (session.script.name(*binding), format!("{:?}", value.expr())))
            .collect();
        globals.sort();
        format!(
            "{result}\n{:?}\n{:?}\n{globals:?}",
            run.effects, run.branches.decisions
        )
    };
    let outcome = execute(false);
    assert_eq!(outcome, execute(true), "{source}");
    outcome
}

/// Parses `source`, leaking it so values can be prepared before parsing.
fn parse(source: &str) -> Script<'static> {
    let parsed = ParsedScript::parse("t", source).expect("the source parses");
    Box::leak(Box::new(parsed)).script()
}

/// The slot plan of the function `f` that `source` declares, if it has one.
fn plan_of(source: &str) -> Option<FunctionPlan<'static>> {
    let script = parse(source);
    let function = Session::empty(script).declared("f");
    FunctionPlan::compile(script, Routine::function(function).expect("`f` has a body"))
}

#[test]
fn shadowed_nested_names_do_not_force_outer_locals_into_scopes() {
    let source = "function f(x) { var n = 0, g = function(x) { return x + 1; }; for (; n < 4; n++) x += g(n); return x; }";
    let plan = plan_of(source).expect("`f` has a slot plan");
    assert!(matches!(plan.parameters[..], [Name::Local(..)]));
    assert_eq!(plan.locals, 3, "x, n and g need only numbered slots");
    compare(source, vec![Value::Number(2.0)], vec![], true);

    let plan = plan_of("function f(x) { return function(y) { return x + y; }; }")
        .expect("`f` has a slot plan");
    assert!(
        matches!(plan.parameters[..], [Name::Scoped(_)]),
        "a true capture still needs a scope"
    );
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
fn functions_declared_in_blocks_are_bound_on_entry() {
    // A function declared after a block's `return` is callable from the start of the block,
    // including one that reads the enclosing function's locals.
    for (source, result) in [
        (
            "function f(a) { { return g(a) + 1; function g(x) { return x * 3; } } }",
            "return Const(Number(7.0))",
        ),
        (
            "function f(a) { { var b = 4; return g(1); function g(x) { return a + b + x; } } }",
            "return Const(Number(7.0))",
        ),
        (
            "function f(a) { try { return g(a); function g(x) { return x + 1; } } finally {} }",
            "return Const(Number(3.0))",
        ),
    ] {
        let outcome = compare(source, vec![Value::Number(2.0)], vec![], true);
        assert!(outcome.starts_with(result), "{source}: {outcome}");
    }
}

#[test]
fn rejected_functions_use_scoped_plans() {
    for source in [
        "function f(a) { return (function() { return a; })(); }",
        "function f(a) { var g = () => arguments[0]; return g(); }",
        "function f(arguments) { return arguments; }",
        "function f(a) { return {[a]: 1}; }",
        "function f(a) { try { return a; } catch ({ e }) { return 0; } }",
    ] {
        compare(source, vec![Value::Number(2.0)], vec![], false);
    }
}

/// Locals that nested functions mention stay in the call's scope, and both the outer
/// function and its closures keep slot plans.
#[test]
fn closures_share_captured_locals() {
    for source in [
        "function f(a) { var g = () => a; return g(); }",
        "function f(a) { var g = function() { return a; }; return g(); }",
        "function f(a) { var s = 0; function g(x) { return k + x; } var k = a * 3; s = g(1) + g(2); return s; }",
        "function f(a) { var n = 0; var inc = function() { n += a; return n; }; inc(); inc(); return n; }",
        "function f(a) { var mk = function(b) { return function(c) { return a + b + c; }; }; return mk(1)(2); }",
        "function f(a) { a = a + 1; var g = function() { return a; }; a = a * 10; return g(); }",
        "function f(a) { var t = [a]; var g = function(i) { return t[i] + outer; }; return g(0); }",
        "function f(a) { function r(n) { return n ? r(n - 1) + a : 0; } return r(3); }",
        "function f(a) { var s = ''; for (var i = 0; i < a; i++) { s += c(i); } return s; function c(j) { var x = j * 2; return k[x]; } var k; }",
        "function f(a) { var k = 'abcdef', s = ''; for (var i = 0; i < a; i++) { s += c(i); } return s; function c(j) { var x = j * 2; return k[x]; } }",
        "function f(a) { var o = {}; o.h = function(x, y) { return x ^ y; }; var h = o.h; return h(a, 6); }",
    ] {
        compare(source, vec![Value::Number(2.0)], vec![], true);
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
        BinaryOperator::Addition,
        BinaryOperator::Subtraction,
        BinaryOperator::Multiplication,
        BinaryOperator::Division,
        BinaryOperator::Remainder,
        BinaryOperator::Exponential,
        BinaryOperator::BitwiseAnd,
        BinaryOperator::BitwiseOR,
        BinaryOperator::BitwiseXOR,
        BinaryOperator::ShiftLeft,
        BinaryOperator::ShiftRight,
        BinaryOperator::ShiftRightZeroFill,
        BinaryOperator::Equality,
        BinaryOperator::StrictEquality,
        BinaryOperator::Inequality,
        BinaryOperator::StrictInequality,
        BinaryOperator::LessThan,
        BinaryOperator::LessEqualThan,
        BinaryOperator::GreaterThan,
        BinaryOperator::GreaterEqualThan,
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
