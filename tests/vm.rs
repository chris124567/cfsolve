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

/// A VM in the shape of the session's: a class whose `run` decodes one
/// opcode per step (here the byte itself, with the key reset to 0) and calls
/// its handler, and setup code that builds a table the handlers share.
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
        constructor(p) {
            this.h = Array(256);
            this.m = 1 + Math.random() * 254 | 0;
            this.j = this.m ^ 1;
            this.i = this.m ^ 2;
            this.l = this.m ^ 3;
            this.o = this.m ^ 4;
            this.k = makeCounter();
        }
        ["run"](pc, key, cells) {
            var h, j, i, op, p;
            h = this.h;
            j = this.j;
            i = this.i;
            h[j] = pc;
            h[i] = key;
            h[this.o] = cells;
            p = h[this.l];
            while (true) {
                op = h[j];
                h[j] = op + 1;
                op = h[i] ^ p[op];
                h[i] = 0;
                switch (op) {
                    case 1: mutate.call(this); break;
                    case 2: load.call(this, 100); break;
                    case 3: fault.call(this); break;
                    case 4: spin.call(this); break;
                    case 5: compare.call(this); break;
                    case 6: readBroken.call(this); break;
                    case 7: shortCircuit.call(this); break;
                    case 8: arrows.call(this); break;
                    case 9: labels.call(this); break;
                    case 10: compound.call(this); break;
                    case 11: liveRead.call(this); break;
                    case 12: closureWrite.call(this); break;
                    case 13: nested.call(this); break;
                    case 14: shadow.call(this); break;
                    case 15: count.call(this); break;
                    case 16: countString.call(this); break;
                    case 17: identity.call(this); break;
                    case 18: stringIndex.call(this); break;
                }
            }
        }
    }
    // One branch writes the shared table; both read it.
    function mutate() {
        var h = this.h;
        if (h[9]) {
            table[0] = 7;
        }
        h[10] = table[0];
    }
    // `r[operand] = constant + operand`, two bytes long.
    function load(base) {
        var h = this.h, p = h[this.l], pc = h[this.j];
        h[p[pc]] = base + p[pc];
        h[this.j] = pc + 1;
    }
    function fault() {
        throw "not an instruction";
    }
    function spin() {
        var h = this.h;
        while (h[9]) {}
    }
    // A candidate string writes the shared table on its way through.
    function compare() {
        var h = this.h;
        if (h[9] === "a") {
            table[1] = 1;
        }
        h[11] = table[1];
    }
    function readBroken() {
        this.h[12] = broken[0];
    }
    // The write happens only when r9 is truthy.
    function shortCircuit() {
        var h = this.h;
        h[9] && (h[13] = 1);
    }
    function arrows() {
        var add = (a, b) => a + b;
        this.h[14] = add(2, 3);
    }
    function labels() {
        var n = 0, i, j;
        outer: for (i = 0; i < 3; i++) {
            for (j = 0; j < 3; j++) {
                if (j == 1) continue outer;
                n++;
            }
        }
        this.h[15] = n;
    }
    // The old value is read before the right side assigns.
    function compound() {
        var x = 1;
        x += (x = 5);
        this.h[16] = x;
    }
    function makeCounter() {
        var n = 0;
        return function () { return ++n; };
    }
    // A closure reads its variables when it runs, not when it is made.
    function liveRead() {
        var x = 1;
        var f = function () { return x; };
        x = 2;
        this.h[17] = f();
        var fact = function (n) { return n <= 1 ? 1 : n * fact(n - 1); };
        this.h[28] = fact(5);
    }
    function closureWrite() {
        var x = 1;
        var set = function (v) { x = v; };
        set(5);
        this.h[18] = x;
    }
    function nested() {
        var a = 1;
        var outer = function (b) {
            return function (c) { return a + b + c; };
        };
        var inner = outer(10);
        a = 100;
        this.h[19] = inner(1000);
    }
    // `peek` sees the scope it is declared in, not its caller's.
    function peek() {
        return secret;
    }
    function shadow() {
        var secret = "inner";
        this.h[20] = peek();
    }
    // One branch calls the setup's and the constructor's closures once more.
    function count() {
        var h = this.h, k = this.k;
        if (h[9]) {
            counter();
            k();
        }
        h[21] = counter();
        h[22] = k();
    }
    function countString() {
        var h = this.h;
        if (h[9] === "a") {
            counter();
        }
        h[23] = counter();
    }
    function identity() {
        var a = {}, b = {};
        this.h[24] = a == a;
        this.h[25] = a == b;
    }
    function stringIndex() {
        var a = [7, 8];
        this.h[26] = a["1"];
        a["0"] = 9;
        this.h[27] = a[0];
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
