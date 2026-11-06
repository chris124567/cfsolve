//! Per-solve execution trace used by the API documentary and latency profiler.
//!
//! Enable it with `CFSOLVE_DET_LOG=1`. A solve runs on one dedicated runtime thread, so a
//! thread-local origin keeps concurrent traces independent without locking the hot path.

use std::cell::RefCell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

struct Origin {
    id: u64,
    started: Instant,
}

thread_local! {
    static ORIGIN: RefCell<Option<Origin>> = const { RefCell::new(None) };
}

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("CFSOLVE_DET_LOG").is_some())
}

/// Starts a new trace on the current solve thread and returns its process-local ID.
pub(crate) fn solve_start(requested_id: Option<u64>) -> u64 {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = requested_id.unwrap_or_else(|| NEXT_ID.fetch_add(1, Ordering::Relaxed));
    ORIGIN.with(|origin| {
        *origin.borrow_mut() = Some(Origin {
            id,
            started: Instant::now(),
        });
    });
    id
}

/// Logs a function boundary/output with the current solve ID and elapsed milliseconds.
pub(crate) fn stamp(label: &str) {
    if !enabled() {
        return;
    }
    ORIGIN.with(|origin| {
        let origin = origin.borrow();
        if let Some(origin) = origin.as_ref() {
            eprintln!(
                "[cfsolve][solve={}][+{:6} ms] {label}",
                origin.id,
                origin.started.elapsed().as_millis()
            );
        }
    });
}
