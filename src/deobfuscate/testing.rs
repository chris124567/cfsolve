//! Helpers for testing deobfuscation passes on source text.

use swc_core::ecma::ast::{Id, Ident, Pass, Program, fn_pass};
use swc_core::ecma::visit::{Visit, VisitWith};
use swc_ecma_transforms::fixer;

use super::analysis::Analysis;

/// The whole deobfuscation pass, as the library applies it.
pub(crate) fn transform(source: &str) -> String {
    super::deobfuscate(source.to_owned())
        .expect("test deobfuscation should succeed")
        .text
}

/// Checks that `output` contains each `expected` string verbatim and each `code` string
/// ignoring whitespace, so printer layout does not affect the check.
pub(crate) fn assert_contains(output: &str, expected: &[&str], code: &[&str]) {
    for expected in expected {
        assert!(output.contains(expected), "{expected}: {output}");
    }
    let strip = |text: &str| -> String { text.split_whitespace().collect() };
    for code in code {
        assert!(strip(output).contains(&strip(code)), "{code}: {output}");
    }
}

pub(crate) fn assert_lacks(output: &str, absent: &[&str]) {
    for absent in absent {
        assert!(!output.contains(absent), "{absent}: {output}");
    }
}

/// One rewrite in isolation, followed by the fixer when `fix` is set.
pub(super) fn rewrite(
    source: &str,
    rewrite: fn(&mut Program, &mut Analysis) -> bool,
    fix: bool,
) -> String {
    super::pipeline::transform(source.to_owned(), |_, unresolved_mark| {
        fn_pass(move |program: &mut Program| {
            rewrite(program, &mut Analysis::new(unresolved_mark));
            if fix {
                fixer::fixer(None).process(program);
            }
        })
    })
    .expect("test transformation should succeed")
}

/// Every identifier of a program, in visiting order.
struct Names(Vec<Id>);

impl Visit for Names {
    fn visit_ident(&mut self, identifier: &Ident) {
        self.0.push(identifier.to_id());
    }
}

/// Resolves names in `source` and runs `check` with a lookup from each spelling to the binding
/// of its first identifier.
pub(crate) fn check(source: &str, mut check: impl FnMut(&Program, &dyn Fn(&str) -> Id)) {
    let checked = super::pipeline::transform(source.to_owned(), |_, _| {
        fn_pass(|program: &mut Program| {
            let mut names = Names(vec![]);
            program.visit_with(&mut names);
            check(program, &|name: &str| {
                names
                    .0
                    .iter()
                    .find(|(spelling, _)| *spelling == name)
                    .unwrap_or_else(|| panic!("{name} not found"))
                    .clone()
            });
        })
    });
    checked.expect("test transformation should succeed");
}
