//! Identifies environment-audit fields by the values assigned to them.
//!
//! The audit fills a values object and publishes it beside its reader groups. Builds move these
//! writes relative to nearby strings, making vocabulary alignment unreliable. The stored values
//! provide a more reliable way to identify fields.

use std::collections::{BTreeMap, BTreeSet};

use swc_core::ecma::ast::BinaryOp;

use crate::candidates;
use crate::listing::Index;
use crate::listing::query::Store;
use crate::stage2::reference::{
    ENVIRONMENT_AUDIT_DECODED, ENVIRONMENT_AUDIT_ENCODED, ENVIRONMENT_AUDIT_GROUPS,
    ENVIRONMENT_AUDIT_PERMISSION, ENVIRONMENT_AUDIT_REDUCTION, ENVIRONMENT_AUDIT_SECURE,
    ENVIRONMENT_AUDIT_TOUCH, ENVIRONMENT_AUDIT_VALUES,
};
use crate::vm::Term;

/// The audit's fields: the two published objects and the six values.
const FIELDS: usize = 8;

/// Pairs the audit's session field names with reference names. `fields` lists names stored by
/// the collection function. Returns `None` unless each required field is found exactly once.
pub(super) fn names(
    index: &Index<'_>,
    fields: &[String],
) -> Option<BTreeMap<String, &'static str>> {
    let stores: Vec<&Store> = index
        .stores()
        .iter()
        .filter(|store| fields.contains(&store.key))
        .collect();
    let object = |store: &Store| index.created_at(store.pc, &Term::Reg(store.object));
    let unique = |what: &str, keep: &dyn Fn(&Store) -> bool| {
        candidates::exactly_one(stores.iter().copied().filter(|store| keep(store)), what).ok()
    };
    // The values object is the one holding the navigation's decoded size.
    let decoded = unique("decoded size", &|store| {
        index.reads(store.pc, &store.value, "decodedBodySize")
    })?;
    let values = object(decoded)?;
    let published = unique("published values", &|store| {
        index.created_at(store.pc, &store.value) == Some(values)
    })?;
    let record = object(published)?;
    let groups = unique("groups", &|store| {
        store.key != published.key && object(store) == Some(record)
    })?;
    let mut names = BTreeMap::from([
        (published.key.clone(), ENVIRONMENT_AUDIT_VALUES),
        (groups.key.clone(), ENVIRONMENT_AUDIT_GROUPS),
    ]);
    let value_stores = stores.iter().filter(|store| object(store) == Some(values));
    for store in value_stores {
        let role = value_role(index, store)?;
        if *names.entry(store.key.clone()).or_insert(role) != role {
            return None;
        }
    }
    let roles: BTreeSet<&str> = names.values().copied().collect();
    (roles.len() == FIELDS && names.len() == FIELDS).then_some(names)
}

/// Returns a values field's reference name based on the value assigned to it.
fn value_role(index: &Index<'_>, store: &Store) -> Option<&'static str> {
    let (pc, value) = (store.pc, &store.value);
    if let Some(member) = index.member(pc, value) {
        return match member.key.as_str() {
            "decodedBodySize" => Some(ENVIRONMENT_AUDIT_DECODED),
            "encodedBodySize" => Some(ENVIRONMENT_AUDIT_ENCODED),
            "isSecureContext" => Some(ENVIRONMENT_AUDIT_SECURE),
            "permission" => Some(ENVIRONMENT_AUDIT_PERMISSION),
            _ => None,
        };
    }
    match index.dereference(pc, value)? {
        // The decoded size less a Server-Timing duration.
        (at, Term::Binary(BinaryOp::Sub, left, _)) if index.reads(at, &left, "decodedBodySize") => {
            Some(ENVIRONMENT_AUDIT_REDUCTION)
        }
        // A touch-support check given the probe frame's document.
        (at, Term::Call { arguments, .. })
            if arguments
                .iter()
                .any(|argument| index.reads(at, argument, "contentDocument")) =>
        {
            Some(ENVIRONMENT_AUDIT_TOUCH)
        }
        _ => None,
    }
}
