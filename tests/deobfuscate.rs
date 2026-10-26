//! Whole-pipeline checks for `cfsolve::deobfuscate`.
//!
//! The differential cases run small scripts before and after deobfuscation in
//! V8, with `log` as the only observable, to catch rewrites that change
//! effects, their order, or thrown errors.

use std::sync::Once;

/// Scripts whose `log` calls must not change. Each one exercises a shape the
/// rewrites must recognize, or one they must leave alone.
const CASES: [(&str, &str); 26] = [
    (
        "helper call order",
        r#"
        function a() { log('a'); return 1; }
        function b() { log('b'); return 2; }
        (function (h) {
            h = { add: function (x, y) { return x + y; }, sub: function (x, y) { return y - x; },
                  same: function (x, y) { return x - x; }, call: function (f, x) { return f(x); } };
            log(h.add(a(), b()), h.sub(a(), b()), h.sub(a(), 5), h.same(a(), b()));
            var o = { v: 3, m: function (x) { return typeof this + x; } };
            log(h.call(o.m, 1), h.call(eval, '1 + 1'));
        })();
        "#,
    ),
    (
        "getters",
        r#"
        var g = { get p() { log('get p'); return 5; } };
        log(g.p, g['p']);
        (function (m) {
            m = { A: 10, B: 20 };
            log(m.A + m.B);
        })();
        "#,
    ),
    (
        "shadowing",
        r#"
        (function (G, K, p) {
            G = Math;
            K = { m: function (a, b) { return G.min(a, b); } };
            p = function (G) { return K.m(G, 1); };
            log(p(5), p(-5));
        })();
        "#,
    ),
    (
        "hoisting",
        r#"
        log(typeof later);
        if (false) { var later = 1; }
        (function (a) { g(); function g() { log(a); } a = 1; })('arg');
        (function (a, b) { log(typeof inner); b = 2; return; function inner() {} })();
        "#,
    ),
    (
        "directives",
        r#"
        function strict() { 'use strict'; return this === undefined; }
        function sloppy() { ('use strict', log('effect')); return this === undefined; }
        log(strict(), sloppy());
        "#,
    ),
    (
        "labelled continue",
        r#"
        var n = 0, i, j;
        outer: for (log('init'), i = 0; i < 3; i++) { for (j = 0; ; j++) { n++; continue outer; } }
        log(n, i, j);
        inner: for (i = 0; i < 2; log('update'), i++) continue inner;
        "#,
    ),
    (
        "unused arguments",
        r#"
        function f(a, b, c) { c = a + 1; return c; }
        log(f(1), f(1, 2, 3));
        (function (a, b, c) { log(a, b, c); b = 2; c = 3; log(b, c); })(1);
"#,
    ),
    (
        "obfuscator patterns",
        r#"
        (function (order, cursor, w, h, m) {
            m = { a: 2, b: 1 };
            w = function (E, P, S) { switch (E) { case 0: return P + S; case 1: return P - S; default: return P * S; } };
            h = {}; h.op = function (x, y) { return x ^ y; }; h.k = 'key';
            for (order = '1|0|2'.split('|'), cursor = 0; true;) {
                switch (order[cursor++]) {
                    case '0': log('zero', w(m.a, 3, 4)); continue;
                    case '1': log('one', w(1, m.b, 5)); continue;
                    case '2': log('two', h.op(6, 3), h.k); continue;
                }
                break;
            }
        })();
        "#,
    ),
    (
        "string table",
        r#"
        (function () {
            (function (factory, target, alias, values, checksum) {
                for (alias = decoder, values = factory(); true;) try {
                    if (checksum = parseInt(alias(21)) + parseInt(alias(22)), target === checksum) break;
                    else values.push(values.shift());
                } catch (error) { values.push(values.shift()); }
            })(provider, 18);
            function decoder(index, unused, values, result) {
                return index = index - 21, values = provider(), result = values[index], result;
            }
            function provider(values) {
                return values = 'noise;7abc;11def;message'.split(';'),
                    provider = function () { return values; }, provider();
            }
            function wrap(i, o) { return decoder(i + o); }
            log(decoder(23), wrap(20, 3), decoder(24));
        })();
        "#,
    ),
    (
        "computed keys",
        r#"
        (function (m, out, key) {
            m = { A: 10, B: 20 };
            key = 'A';
            out = [m.A, m['B'], m[key]];
            log(out.join());
        })();
        "#,
    ),
    (
        "alias mutation",
        r#"
        (function (h, alias) {
            h = { name: 'first', f: function (a) { return a + 1; } };
            alias = h;
            alias.name = 'changed';
            log(h.name, alias.f(1));
        })();
        (function (h) {
            h = { name: 'first' };
            if (Math.random() < 2) h.name = 'second';
            log(h.name);
        })();
        (function (t) {
            t = ['x', 'y'];
            function at(i) { return t[i]; }
            t[0] = 'z';
            log(at(0));
        })();
        (function (c, d) {
            c = 1; d = c; c = 2;
            log(d, c);
        })();
        "#,
    ),
    (
        "arguments object",
        r#"
        function mapped(a, b) { b = 2; return arguments[1]; }
        log(mapped(1, 5), mapped(1));
        "#,
    ),
    (
        "helper context",
        r#"
        var o = { v: 1, h: null };
        o.h = (function (h) {
            h = { self: function () { return this; }, args: function (a) { return arguments.length; } };
            return function () { return [h.self() === h, h.args(1, 2)]; };
        })();
        log(o.h().join());
        "#,
    ),
    (
        "conditional helper properties",
        r#"
        (function (c, x) {
            c = {};
            c.a = function () { return 1; };
            if (x) c.b = 2;
            log(c.a(), typeof c.b);
        })(0);
        (function (c, x) {
            c = {};
            c.a = function () { return 1; };
            if (x === undefined) c.b = 2;
            log(c.a());
        })();
        "#,
    ),
    (
        "scratch parameters across try, switch, labels and loops",
        r#"
        function thrower() { throw 0; }
        function caught(a) { try { thrower(); a = 1; } catch (e) { return a; } }
        function finished(a) { try { thrower(); a = 1; } finally { return a; } }
        function fallthrough(k, a) { switch (k) { case 0: a = 1; case 1: return a; } }
        function labelled(c, a) { block: { if (c) break block; a = 1; } return a; }
        function updated(a) { for (var i = 0; i < 1; a = 1) { return a; } }
        function repeated(c, a) { do { if (c) return a; c = 1; } while ((a = 1, c)); }
        log(caught('arg'), finished('arg'), fallthrough(1, 'arg'), labelled(true, 'arg'));
        log(updated('arg'), repeated(true, 'arg'), repeated(false, 'arg'));
        "#,
    ),
    (
        "scratch parameters in strict functions",
        r#"
        function strict(a) { 'use strict'; a = String(this); return a; }
        log(strict(), strict(5));
        "#,
    ),
    (
        "hoisted readers of later definitions",
        r#"
        (function (h, out) {
            h = {};
            out = g();
            h.k = 1;
            log(out, g());
            function g() { return h.k; }
        })();
        (function (m) {
            log(g());
            m = { A: 1 };
            log(g());
            function g() { try { return m.A; } catch (e) { return e.name; } }
        })();
        (function (h) {
            log(f());
            h = { k: 1 };
            log(f());
            function f() { return g(); }
            function g() { try { return h.k; } catch (e) { return e.name; } }
        })();
        (function (a, b) {
            log(g());
            a = 1;
            b = a;
            log(g());
            function g() { return [a, b].join(); }
        })();
        "#,
    ),
    (
        "unresolved globals",
        r#"
        (function (h) {
            h = { second: function (x, y) { return y; }, sub: function (x, y) { return y - x; } };
            try { log(h.second(missingGlobal, 1)); } catch (e) { log(e.name); }
            try { log(h.sub(missingA, missingB)); } catch (e) { log(e.message); }
        })();
        (function (w) {
            w = function (E, P, S) { switch (E) { case 0: return P; default: return S; } };
            try { log(w(0, 1, missingGlobal)); } catch (e) { log(e.name); }
        })();
        try { log((missingGlobal, 1)); } catch (e) { log(e.name); }
        (function (f) {
            try { f = [1, missingGlobal]; log(f[0]); } catch (e) { log(e.name); }
        })();
        "#,
    ),
    (
        "shadowed globals",
        r#"
        (function (Reflect) {
            log(b(1, String, [5]));
            function b(n, m, r) { switch (n) { case 1: return Reflect.apply(m, undefined, r); } }
        })({ apply: function () { return 'shadowed'; } });
        (function (undefined) {
            function t() { 'use strict'; return typeof this; }
            function b(n, m, r) { switch (n) { case 1: return Reflect.apply(m, undefined, r); } }
            log(b(1, t, []));
        })({});
        "#,
    ),
    (
        "jumps inside flattened cases",
        r#"
        (function (order, cursor, x) {
            for (order = '0|1|2'.split('|'), cursor = 0; true;) {
                switch (order[cursor++]) {
                    case '0': log('zero'); continue;
                    case '1': if (x) { log('skip'); continue; } log('one'); continue;
                    case '2': log('two'); continue;
                }
                break;
            }
        })(1);
        "#,
    ),
    (
        "breaks inside flattened cases",
        r#"
        (function (order, cursor) {
            for (order = '0|1'.split('|'), cursor = 0; true;) {
                switch (order[cursor++]) {
                    case '0': for (;;) { break; } if (order) break; log('zero'); continue;
                    case '1': log('one'); continue;
                }
                break;
            }
            log('after');
        })();
        "#,
    ),
    (
        "dispatcher bindings read by cases or later",
        r#"
        (function (order, cursor) {
            for (order = '1|0'.split('|'), cursor = 0; true;) {
                switch (order[cursor++]) {
                    case '0': log('zero', cursor); continue;
                    case '1': log('one'); continue;
                }
                break;
            }
            log(order.join('-'));
        })();
        "#,
    ),
    (
        "argument arrays whose elements are written",
        r#"
        (function (a, b, f) { f = [a, b]; [a] = [9]; log(f[0], f[1]); })(1, 2);
        (function (a, f) { f = [a]; for (a of [7]); log(f[0]); })(1);
        (function (a, f) { f = [a]; var a = 5; log(f[0]); })(1);
        (function (a, f) { f = [a]; arguments[0] = 3; log(f[0]); })(1);
        "#,
    ),
    (
        "argument arrays that escape or change",
        r#"
        (function (a, f) { f = [a]; log(f[0], JSON.stringify({ f })); })(1);
        (function (a, b, f) { f = [a, b]; delete f[0]; log(f[0], f[1]); })(1, 2);
        (function (a, f) { f = [a]; log(typeof f[0]()); })(function () { 'use strict'; return this; });
        (function (a, f) { f = [a]; [f[0]] = [4]; log(f[0]); })(1);
        "#,
    ),
    (
        "properties written by patterns and loop heads",
        r#"
        (function (h) { h = { x: 1 }; for (h.x of [2]); log(h.x); })();
        (function (h) { h = { x: 1 }; for (h.x in { k: 0 }); log(h.x); })();
        (function (h) { h = { x: 1 }; [h.x] = [3]; log(h.x); })();
        (function (h) { h = { f: function () { return 1; } }; ({ g: h.f } = { g: function () { return 2; } }); log(h.f()); })();
        "#,
    ),
    (
        "property keys",
        r#"
        (function (h) { h = { __proto__: 5, y: 1 }; log(typeof h.__proto__, h.y); })();
        (function (h) { h = { '\uD800': 1, k: 2 }; log(h['\uFFFD'], h['\uD800'], h.k); })();
        (function (h) {
            h = { 'a-b': function (x) { return x * 2; }, 'c-d': 'v' };
            log(h['a-b'](3), h[`a-b`](4), h['c-d']);
        })();
        (function (m) { m = { 'a-b': 5, B: 6 }; log(m['a-b'], m[`B`]); })();
        "#,
    ),
];

/// Runs `source` as a classic script and returns what it logged, followed by
/// the exception it ended with, if any.
fn observe(source: &str) -> Vec<String> {
    static INITIALIZED: Once = Once::new();
    INITIALIZED.call_once(|| {
        v8::V8::initialize_platform(v8::new_default_platform(0, false).make_shared());
        v8::V8::initialize();
    });
    let isolate = &mut v8::Isolate::new(Default::default());
    v8::scope!(let scope, isolate);
    let context = v8::Context::new(scope, Default::default());
    let scope = &mut v8::ContextScope::new(scope, context);
    let run = |scope: &mut v8::PinScope, source: &str| -> Result<String, String> {
        v8::tc_scope!(let tc, scope);
        let code = v8::String::new(tc, source).unwrap();
        let result = v8::Script::compile(tc, code, None).and_then(|script| script.run(tc));
        match result {
            Some(value) => Ok(value.to_rust_string_lossy(tc)),
            None => Err(tc.exception().map_or_else(
                || "terminated".to_owned(),
                |exception| exception.to_rust_string_lossy(tc),
            )),
        }
    };
    run(
        scope,
        "var __log = []; function log() { __log.push(Array.prototype.map.call(arguments, String).join(' ')); }",
    )
    .unwrap();
    let outcome = run(scope, source);
    let logged = run(scope, "JSON.stringify(__log)").unwrap();
    let mut observed: Vec<String> = serde_json::from_str(&logged).unwrap();
    if let Err(exception) = outcome {
        observed.push(format!("threw {exception}"));
    }
    observed
}

#[test]
fn preserves_observable_behavior() {
    let mut failures = vec![];
    for (name, source) in CASES {
        let output = cfsolve::deobfuscate(source.to_owned()).unwrap().text;
        let (before, after) = (observe(source), observe(&output));
        if before != after {
            failures.push(format!(
                "{name}:\n  before {before:?}\n  after  {after:?}\n{output}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
