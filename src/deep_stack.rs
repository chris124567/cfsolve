//! Runs recursive work on a thread with a dedicated stack, independent of the caller's runtime.

use std::thread;

use anyhow::{Context, Result};
use tokio::sync::oneshot;

/// Stack size for recursive deobfuscation, matching the usual Linux main-thread stack.
const STACK_SIZE: usize = 8 << 20;

/// Runs `work` on a new thread named `name` and awaits its result without blocking the runtime.
pub(crate) async fn run<T: Send + 'static>(
    name: &str,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    let (sender, receiver) = oneshot::channel();
    thread::Builder::new()
        .name(name.into())
        .stack_size(STACK_SIZE)
        .spawn(move || {
            // The receiver is gone only if the caller stopped waiting.
            let _ = sender.send(work());
        })
        .with_context(|| format!("starting the {name} thread"))?;
    receiver
        .await
        .with_context(|| format!("the {name} thread failed"))
}
