//! Helpers for testing deobfuscation passes on source text.

use oxc::allocator::{Allocator, CloneIn};
use oxc::ast::ast::Program;
use oxc::span::ContentEq;

use super::analysis::{Analysis, Id};
use super::pipeline::{self, Rewrite};

pub(super) fn transform(source: &str) -> String {
    super::deobfuscate(source.to_owned())
        .expect("test deobfuscation should succeed")
        .text
}

/// Runs one rewrite and checks that it reports truthfully whether it changed the program.
pub(super) fn rewrite(source: &str, rewrite: Rewrite) -> String {
    let allocator = Allocator::default();
    let (mut program, mut analysis) =
        pipeline::parse(&allocator, source).expect("test script should parse");
    let before = program.clone_in_with_semantic_ids(&allocator);
    let changed = rewrite(&mut program, &mut analysis);
    assert_eq!(
        changed,
        !program.content_eq(&before),
        "rewrite misreported whether it changed the program"
    );
    pipeline::print(&program)
}

/// Checks that `output` contains each expected snippet, ignoring whitespace and quote style.
pub(super) fn assert_contains(output: &str, expected: &[&str]) {
    let compact = |text: &str| {
        text.split_whitespace()
            .collect::<String>()
            .replace('\'', "\"")
    };
    for expected in expected {
        assert!(
            compact(output).contains(&compact(expected)),
            "{expected}: {output}"
        );
    }
}

pub(super) fn assert_lacks(output: &str, absent: &[&str]) {
    for absent in absent {
        assert!(!output.contains(absent), "{absent}: {output}")
    }
}

/// Parses `source` and runs `check` with a lookup of local bindings by name.
pub(super) fn check(
    source: &str,
    check: impl FnOnce(&Program<'_>, &Analysis<'_>, &dyn Fn(&str) -> Id),
) {
    let allocator = Allocator::default();
    let (program, analysis) =
        pipeline::parse(&allocator, source).expect("test script should parse");
    let id = |name: &str| {
        let mut symbols = analysis.scoping.symbol_ids();
        let symbol = symbols
            .find(|&symbol| analysis.scoping.symbol_name(symbol) == name)
            .unwrap_or_else(|| panic!("{name} not found"));
        Id::Local(symbol)
    };
    check(&program, &analysis, &id);
}
