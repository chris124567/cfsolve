//! Session artifact storage and progress reporting.

use std::fmt;

use anyhow::{Context, Result};
use serde::Serialize;

/// Destination for session artifacts and progress messages.
pub trait Sink: Send + Sync {
    /// Saves `contents` under artifact `name` as soon as it is available.
    fn artifact(&self, name: &str, contents: &[u8]) -> Result<()>;
    /// Receives progress messages during a solve, including diagnostics before a failure.
    fn progress(&self, message: &str);
}

pub(crate) struct Discard;

impl Sink for Discard {
    fn artifact(&self, _: &str, _: &[u8]) -> Result<()> {
        Ok(())
    }

    fn progress(&self, _: &str) {}
}

/// Marks a failure as the sink's own, so it is not mistaken for a challenge the solver cannot
/// handle.
#[derive(Debug)]
pub(crate) struct SinkFailed {
    name: String,
}

impl fmt::Display for SinkFailed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "saving artifact {}", self.name)
    }
}

impl dyn Sink + '_ {
    /// Saves `contents` under artifact `name` with [`Sink::artifact`], marking a failure with
    /// [`SinkFailed`].
    pub(crate) fn save(&self, name: &str, contents: &[u8]) -> Result<()> {
        self.artifact(name, contents).map_err(|error| {
            error.context(SinkFailed {
                name: name.to_owned(),
            })
        })
    }

    /// Saves `value` as pretty-printed JSON under artifact `name`.
    pub(crate) fn json(&self, name: &str, value: &impl Serialize) -> Result<()> {
        let json =
            serde_json::to_vec_pretty(value).with_context(|| format!("serializing {name}"))?;
        self.save(name, &json)
    }
}
