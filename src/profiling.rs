//! CPU stage timings, printed when the `CFSOLVE_PROFILE` environment variable is set.

use std::cell::RefCell;
use std::cmp::Reverse;
use std::env;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;

#[derive(Default)]
struct Timing {
    calls: usize,
    total: Duration,
}

thread_local! {
    static TIMINGS: RefCell<FxHashMap<String, Timing>> = RefCell::default();
}

/// Returns the current time if profiling is enabled.
pub(crate) fn start() -> Option<Instant> {
    static ENABLED: LazyLock<bool> = LazyLock::new(|| env::var_os("CFSOLVE_PROFILE").is_some());
    ENABLED.then(Instant::now)
}

/// Adds the time since `started` to `name`'s total. `name` is only called when profiling.
pub(crate) fn record(started: Option<Instant>, name: impl FnOnce() -> String) {
    let Some(started) = started else {
        return;
    };
    let elapsed = started.elapsed();
    TIMINGS.with_borrow_mut(|timings| {
        let timing = timings.entry(name()).or_default();
        timing.calls += 1;
        timing.total += elapsed;
    });
}

/// Prints the slowest timings recorded on this thread for `stage`, then clears them.
pub(crate) fn report(stage: &str) {
    let mut timings: Vec<(String, Timing)> =
        TIMINGS.with_borrow_mut(|timings| timings.drain().collect());
    timings.sort_unstable_by_key(|(_, timing)| Reverse(timing.total));
    timings.truncate(30);
    for (name, Timing { calls, total }) in timings {
        eprintln!("{stage}: {name}: {calls} calls, {total:?}");
    }
}
