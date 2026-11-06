//! Regression checks for `cfsolve::vm`, on a small hand-written VM in the
//! shape of a session's that covers cases a real program does not isolate.

use cfsolve::vm::{Cause, Constant, Definition, Effect, Exit, Machine, Path, Position, Term};
use swc_core::common::{FileName, SourceMap};
use swc_core::ecma::parser::{Parser, StringInput, Syntax};

fn definition(source: &str) -> Definition {
    let source_map = SourceMap::default();
    let file = source_map.new_source_file(FileName::Anon.into(), source.to_owned());
    let script = Parser::new(Syntax::default(), StringInput::from(&*file), None)
        .parse_script()
        .expect("the script parses");
    Definition::from_script(&script).expect("the script defines a VM")
}

/// A VM in the shape of the session's: a class whose constructor builds the
/// register file and masked pc/key/program/cells indices, a `run` that stores
/// its cells argument in a register and reads the program back, and a dispatch
/// loop that decodes one opcode per step with the key reset to 0. Setup code
/// builds tables the handlers share.
const TOY: &str = r#"
(function () {
    var g = {}, table = [0, 0], secret = "outer";
    // Setup the interpreter cannot follow: `broken` is never bound.
    var broken = table.map(Number);
    // A closure over state of its own, which every run starts from afresh.
    var counter = (function () {
        var n = 0;
        return function () { return ++n; };
    })();
    class VM {
        constructor() {
            this.k = {};
            this.m = 1 + Math.random() * 254 | 0;
            this.u = this.m ^ 0;
            this.v = this.m ^ 1;
            this.w = this.m ^ 2;
            this.x = this.m ^ 3;
            this.k.C = this.u;
            this.k.D = this.v;
            this.kf = makeCounter();
        }
        ["run"](pc, key, cells) {
            var file, p;
            file = this.k;
            file.write(this.x, cells);
            p = file.read(this.w);
            step(this, file, p);
        }
    }
    function step(machine, file, p) {
        var key, op, pc;
        while (true) {
            pc = machine.k.h;
            key = machine.k.j;
            machine.k.j = 0;
            machine.k.h = pc + 1;
            op = key ^ p[pc];
                switch (op) {
                    case 1: mutate(machine); break;
                    case 2: load(machine); break;
                    case 3: fault(machine); break;
                    case 4: spin(machine); break;
                    case 5: compare(machine); break;
                    case 6: readBroken(machine); break;
                    case 7: shortCircuit(machine); break;
                    case 8: arrows(machine); break;
                    case 9: labels(machine); break;
                    case 10: compound(machine); break;
                    case 11: liveRead(machine); break;
                    case 12: closureWrite(machine); break;
                    case 13: nested(machine); break;
                    case 14: shadow(machine); break;
                    case 15: count(machine); break;
                    case 16: countString(machine); break;
                    case 17: identity(machine); break;
                    case 18: stringIndex(machine); break;
                }
            }
        }
    // One branch writes the shared table; both read it.
    function mutate(machine) {
        var h = machine.k, m = machine.m;
        if (h.read(m ^ 9)) {
            table[0] = 7;
        }
        h.write(m ^ 10, table[0]);
    }
    // `r[operand] = 100 + operand`, two bytes long.
    function load(machine) {
        var h = machine.k, m = machine.m, p, pc, q;
        p = h.read(m ^ 2);
        pc = h.h;
        q = p[pc];
        h.write(m ^ q, 100 + q);
        h.h = pc + 1;
    }
    function fault(machine) {
        throw "not an instruction";
    }
    function spin(machine) {
        var h = machine.k, m = machine.m;
        while (h.read(m ^ 9)) {}
    }
    // A candidate string writes the shared table on its way through.
    function compare(machine) {
        var h = machine.k, m = machine.m;
        if (h.read(m ^ 9) === "a") {
            table[1] = 1;
        }
        h.write(m ^ 11, table[1]);
    }
    function readBroken(machine) {
        var h = machine.k, m = machine.m;
        h.write(m ^ 12, broken[0]);
    }
    // The write happens only when r9 is truthy.
    function shortCircuit(machine) {
        var h = machine.k, m = machine.m;
        h.read(m ^ 9) && h.write(m ^ 13, 1);
    }
    function arrows(machine) {
        var h = machine.k, m = machine.m;
        var add = (a, b) => a + b;
        h.write(m ^ 14, add(2, 3));
    }
    function labels(machine) {
        var h = machine.k, m = machine.m, n = 0, i, j;
        outer: for (i = 0; i < 3; i++) {
            for (j = 0; j < 3; j++) {
                if (j == 1) continue outer;
                n++;
            }
        }
        h.write(m ^ 15, n);
    }
    // The old value is read before the right side assigns.
    function compound(machine) {
        var h = machine.k, m = machine.m, x = 1;
        x += (x = 5);
        h.write(m ^ 16, x);
    }
    function makeCounter() {
        var n = 0;
        return function () { return ++n; };
    }
    // A closure reads its variables when it runs, not when it is made.
    function liveRead(machine) {
        var h = machine.k, m = machine.m, x = 1, f, fact;
        f = function () { return x; };
        x = 2;
        h.write(m ^ 17, f());
        fact = function (n) { return n <= 1 ? 1 : n * fact(n - 1); };
        h.write(m ^ 28, fact(5));
    }
    function closureWrite(machine) {
        var h = machine.k, m = machine.m, x = 1, set;
        set = function (v) { x = v; };
        set(5);
        h.write(m ^ 18, x);
    }
    function nested(machine) {
        var h = machine.k, m = machine.m, a = 1, outer, inner;
        outer = function (b) {
            return function (c) { return a + b + c; };
        };
        inner = outer(10);
        a = 100;
        h.write(m ^ 19, inner(1000));
    }
    // `peek` sees the scope it is declared in, not its caller's.
    function peek() {
        return secret;
    }
    function shadow(machine) {
        var h = machine.k, m = machine.m, secret = "inner";
        h.write(m ^ 20, peek());
    }
    // One branch calls the setup's and the constructor's closures once more.
    function count(machine) {
        var h = machine.k, m = machine.m, k = machine.kf;
        if (h.read(m ^ 9)) {
            counter();
            k();
        }
        h.write(m ^ 21, counter());
        h.write(m ^ 22, k());
    }
    function countString(machine) {
        var h = machine.k, m = machine.m;
        if (h.read(m ^ 9) === "a") {
            counter();
        }
        h.write(m ^ 23, counter());
    }
    function identity(machine) {
        var h = machine.k, m = machine.m, a = {}, b = {};
        h.write(m ^ 24, a == a);
        h.write(m ^ 25, a == b);
    }
    function stringIndex(machine) {
        var h = machine.k, m = machine.m, a = [7, 8];
        h.write(m ^ 26, a["1"]);
        a["0"] = 9;
        h.write(m ^ 27, a[0]);
    }
    g.runProgram = function (p) {
        return new VM(p).run(0, 0, []);
    };
})();
"#;

fn sets(path: &Path, register: u8) -> Option<Term> {
    path.effects.iter().find_map(|effect| match effect {
        Effect::Set(target, value) if *target == register => Some(value.clone()),
        _ => None,
    })
}

fn number(value: f64) -> Term {
    Term::Const(Constant::Number(value))
}

/// The one path through the toy instruction `program` starts with, with r9
/// holding `text` if given.
fn only_path(machine: &Machine<'_>, program: &[u8], text: Option<&str>) -> Path {
    let instruction = match text {
        Some(text) => machine.instruction_with_string(program, 0, 0, 9, text),
        None => machine.instruction(program, 0, 0),
    };
    let mut paths = instruction.unwrap().paths;
    assert_eq!(paths.len(), 1, "{paths:?}");
    paths.remove(0)
}

#[test]
fn toy_vm_decodes_instructions_and_failures() {
    let definition = definition(TOY);
    let machine = Machine::try_new(&definition).unwrap();
    assert_eq!(machine.entry(), Position::new(0, 0));
    let path = only_path(&machine, &[2, 5], None);
    assert_eq!(sets(&path, 5), Some(number(105.0)));
    assert_eq!(path.exit, Exit::Next { pc: 2, key: 0 });

    // A handler that always throws, and an opcode without one.
    let failure = machine.instruction(&[3], 0, 0).unwrap_err();
    assert_eq!(
        failure.cause,
        Cause::Faults {
            opcode: 3,
            reasons: vec!["\"not an instruction\"".into()]
        }
    );
    let failure = machine.instruction(&[200], 0, 0).unwrap_err();
    assert_eq!(failure.cause, Cause::NoHandler { opcode: 200 });

    let instruction = machine.instruction(&[4], 0, 0).unwrap();
    assert!(
        instruction
            .paths
            .iter()
            .any(|path| matches!(&path.exit, Exit::Unfollowed { pc: 1, key: 0, .. })),
        "a loop over registers is not followed: {instruction:?}"
    );
    let Exit::Unfollowed { reason, .. } = only_path(&machine, &[6], None).exit else {
        panic!("setup that could not be followed is followed");
    };
    assert!(
        reason.contains("broken") && reason.contains("map"),
        "{reason}"
    );

    let listing = machine.disassemble(&[2, 5, 2, 6, 3]).unwrap();
    let pcs: Vec<u32> = listing.instructions.keys().copied().collect();
    assert_eq!(pcs, [0, 2]);
    assert_eq!(listing.failures.len(), 1);
    assert_eq!((listing.failures[0].pc, listing.failures[0].key), (4, 0));
}

#[test]
fn toy_vm_runs_do_not_share_writes() {
    let definition = definition(TOY);
    let machine = Machine::try_new(&definition).unwrap();
    for _ in 0..2 {
        let instruction = machine.instruction(&[1], 0, 0).unwrap();
        let values: Vec<_> = instruction
            .paths
            .iter()
            .map(|path| (path.conditions[0].1, sets(path, 10)))
            .collect();
        assert_eq!(
            values,
            [(true, Some(number(7.0))), (false, Some(number(0.0)))],
            "each path starts from the session's own table"
        );
        let instruction = machine.instruction(&[15], 0, 0).unwrap();
        let values: Vec<_> = instruction
            .paths
            .iter()
            .map(|path| (path.conditions[0].1, sets(path, 21), sets(path, 22)))
            .collect();
        assert_eq!(
            values,
            [
                (true, Some(number(2.0)), Some(number(2.0))),
                (false, Some(number(1.0)), Some(number(1.0))),
            ],
            "each path starts from the session's own closures"
        );
    }
    let read = |opcode: u8, text: &str, register: u8| {
        sets(&only_path(&machine, &[opcode], Some(text)), register)
    };
    assert_eq!(read(5, "a", 11), Some(number(1.0)));
    assert_eq!(read(5, "b", 11), Some(number(0.0)));
    assert_eq!(read(16, "a", 23), Some(number(2.0)));
    assert_eq!(read(16, "b", 23), Some(number(1.0)));
    assert_eq!(read(16, "a", 23), Some(number(2.0)));
}

#[test]
fn toy_vm_follows_javascript_semantics() {
    let definition = definition(TOY);
    let machine = Machine::try_new(&definition).unwrap();
    let one = |opcode: u8, register: u8| sets(&only_path(&machine, &[opcode], None), register);
    assert_eq!(one(8, 14), Some(number(5.0)));
    assert_eq!(one(9, 15), Some(number(3.0)));
    assert_eq!(one(10, 16), Some(number(6.0)));
    // Closures are lexical: a read after the variable is reassigned, a
    // closure calling itself, a write inside the closure seen by the function
    // it was made in, two scopes up, and not the caller's variable.
    assert_eq!(one(11, 17), Some(number(2.0)));
    assert_eq!(one(11, 28), Some(number(120.0)));
    assert_eq!(one(12, 18), Some(number(5.0)));
    assert_eq!(one(13, 19), Some(number(1110.0)));
    let outer = Term::Const(Constant::String("outer".into()));
    assert_eq!(one(14, 20), Some(outer));
    // Objects compare by identity, and a string key indexes an array.
    assert_eq!(one(17, 24), Some(Term::Const(Constant::Bool(true))));
    assert_eq!(one(17, 25), Some(Term::Const(Constant::Bool(false))));
    assert_eq!(one(18, 26), Some(number(8.0)));
    assert_eq!(one(18, 27), Some(number(9.0)));

    let instruction = machine.instruction(&[7], 0, 0).unwrap();
    let writes: Vec<_> = instruction
        .paths
        .iter()
        .map(|path| (path.conditions.clone(), sets(path, 13)))
        .collect();
    assert_eq!(
        writes,
        [
            (vec![(Term::Reg(9), true)], Some(number(1.0))),
            (vec![(Term::Reg(9), false)], None),
        ]
    );
}
