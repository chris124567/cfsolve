//! Deobfuscation with [`cfsolve::Allocator`] installed: its tree copies go into per-thread
//! chunks that are handed back when each tree is dropped. Several threads deobfuscating at once,
//! over and over, must each get the same text as the first run, with the chunks reused safely.

use std::thread;

#[global_allocator]
static ALLOCATOR: cfsolve::Allocator<std::alloc::System> =
    cfsolve::Allocator::new(std::alloc::System);

/// A script with the shapes the rewrites take apart: a string table read through a helper,
/// a helper object, a flattened state machine and a dispatch loop.
const SCRIPT: &str = r#"
(function () {
    var table = ["log", "push", "length", "abc"];
    function at(index) { return table[index - 100]; }
    var helpers = { add: function (a, b) { return a + b; }, key: "value" };
    function run(program) {
        var state = 0, out = [];
        while (true) {
            switch (state) {
                case 0: out[at(101)](helpers.add(1, 2)); state = 2; break;
                case 2: out[at(101)](helpers.key); state = 1; break;
                case 1: return out[at(102)];
            }
        }
    }
    console[at(100)](run([1, 2, 3]), at(103));
})();
"#;

#[test]
fn concurrent_deobfuscations_agree_with_the_first() {
    let expected = cfsolve::deobfuscate(SCRIPT.to_owned()).unwrap().text;
    thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| {
                for _ in 0..20 {
                    let text = cfsolve::deobfuscate(SCRIPT.to_owned()).unwrap().text;
                    assert_eq!(text, expected);
                }
            });
        }
    });
}
