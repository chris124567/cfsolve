//! Session artifact storage and progress reporting.

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

impl dyn Sink + '_ {
    /// Saves `value` as pretty-printed JSON under artifact `name`.
    pub(crate) fn json(&self, name: &str, value: &impl Serialize) -> Result<()> {
        let json =
            serde_json::to_vec_pretty(value).with_context(|| format!("serializing {name}"))?;
        self.artifact(name, &json)
    }
}
