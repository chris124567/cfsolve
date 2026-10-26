//! Rejects ambiguous script analysis results. Conflicting values indicate an unsupported script
//! build.

use std::fmt::Debug;

use anyhow::{Result, bail};

/// Returns the only item in `items`. Fails unless there is exactly one.
pub(crate) fn exactly_one<T>(items: impl IntoIterator<Item = T>, what: &str) -> Result<T> {
    let mut items = items.into_iter();
    match (items.next(), items.next()) {
        (Some(item), None) => Ok(item),
        (None, _) => bail!("expected one {what}, found 0"),
        (Some(_), Some(_)) => bail!("expected one {what}, found {}", items.count() + 2),
    }
}

/// Returns the distinct item in `items`, or `None` if empty. Ignores equal duplicates and
/// reports conflicting values in an error naming `what`.
pub(crate) fn at_most_one_distinct<T: PartialEq + Debug>(
    items: impl IntoIterator<Item = T>,
    what: &str,
) -> Result<Option<T>> {
    let mut items = items.into_iter();
    let Some(first) = items.next() else {
        return Ok(None);
    };
    if let Some(other) = items.find(|other| *other != first) {
        bail!("found conflicting {what} candidates: {first:?} and {other:?}");
    }
    Ok(Some(first))
}
