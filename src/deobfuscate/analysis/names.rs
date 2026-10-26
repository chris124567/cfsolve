//! Finds bindings mentioned by a piece of code.

use swc_core::ecma::ast::{Function, Id, Ident, Param};
use swc_core::ecma::visit::{Visit, VisitWith};

/// Checks whether `node` mentions any of `ids`, including values, declarations, assignment
/// targets, and nested functions.
#[must_use]
pub(crate) fn mentions<N: for<'a> VisitWith<Mentions<'a>> + ?Sized>(node: &N, ids: &[Id]) -> bool {
    let mut mentions = Mentions { ids, found: false };
    node.visit_with(&mut mentions);
    mentions.found
}

pub(crate) struct Mentions<'ids> {
    ids: &'ids [Id],
    found: bool,
}

impl Visit for Mentions<'_> {
    fn visit_ident(&mut self, identifier: &Ident) {
        self.found |= self.ids.contains(&identifier.to_id());
    }
}

/// Checks for any identifier named `arguments`, following arrows, which share the enclosing
/// function's `arguments`, but not nested ordinary functions, which have their own.
#[must_use]
pub(crate) fn uses_arguments<N: VisitWith<Arguments> + ?Sized>(node: &N) -> bool {
    let mut arguments = Arguments(false);
    node.visit_with(&mut arguments);
    arguments.0
}

pub(crate) struct Arguments(bool);

impl Visit for Arguments {
    fn visit_ident(&mut self, identifier: &Ident) {
        self.0 |= identifier.sym == "arguments";
    }

    fn visit_function(&mut self, _: &Function) {}
}

/// The bindings of `params`, if every parameter is a plain identifier.
#[must_use]
pub(crate) fn parameter_ids(params: &[Param]) -> Option<Vec<Id>> {
    params
        .iter()
        .map(|param| Some(param.pat.as_ident()?.to_id()))
        .collect()
}
