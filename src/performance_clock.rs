//! Computes `performance.now()` using browser clock rules.
//!
//! On Linux, Chrome reads `CLOCK_MONOTONIC` through `base::TimeTicks`, and on Windows
//! `QueryPerformanceCounter`. It clamps the reading and time origin to 100 µs (5 µs in the
//! widget iframe on Cloudflare's challenge page, in every Chrome 156 capture) using jitter at
//! each interval boundary, converts both to floating-point milliseconds, and subtracts. Conversion loses precision as uptime grows,
//! producing values such as `23.300000000745058`. Use this module for all reported readings and
//! differences to preserve that rounding behavior.
//!
//! WebKit floors elapsed monotonic time. The iOS Safari 26.6 widget iframe uses whole
//! milliseconds, giving a measured resolution of 1. Cloudflare's challenge page uses 20 µs
//! steps calculated in seconds, yielding differences such as `0.01999999999998181`.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The wall clock, in milliseconds since the epoch, as `Date.now()` reads it.
#[must_use]
pub(crate) fn epoch_ms() -> i64 {
    epoch_us() / 1000
}

fn epoch_us() -> i64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    since
        .expect("the wall clock reads after the epoch")
        .as_micros() as i64
}

/// Chrome's coarse resolution, for contexts that are not cross-origin isolated.
const CHROMIUM_COARSE_US: i64 = 100;
/// Chrome's fine resolution, which the widget iframe on Cloudflare's challenge page measures.
const CHROMIUM_FINE_US: i64 = 5;

/// WebKit's step on Cloudflare's challenge page, in seconds.
const WEBKIT_FINE_STEP_S: f64 = 20e-6;

/// How a context's clock reports time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    /// Chrome's 100 µs intervals with jitter at each boundary, in a site's widget iframe.
    Chromium,
    /// Chrome's 5 µs intervals with jitter at each boundary, on Cloudflare's own challenge page.
    ChromiumFine,
    /// WebKit's whole milliseconds, in a site's widget iframe.
    WebKitMillisecond,
    /// WebKit's 20 µs steps, on Cloudflare's own challenge page.
    WebKitFine,
}

/// A document or worker's `performance` clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PerformanceClock {
    /// Monotonic time origin in microseconds, clamped like readings for Chromium.
    origin_us: i64,
    resolution: Resolution,
}

impl PerformanceClock {
    /// Creates a clock for a context starting now, such as a new worker.
    #[must_use]
    pub(crate) fn started_now(resolution: Resolution) -> Self {
        Self::with_origin(monotonic_us(), resolution)
    }

    /// Creates a clock with wall-clock origin `epoch_ms`, mapped to monotonic time using the
    /// current offset between the clocks.
    #[must_use]
    pub(crate) fn from_epoch_origin(epoch_ms: i64, resolution: Resolution) -> Self {
        let since_us = epoch_us() - epoch_ms * 1000;
        Self::with_origin(monotonic_us() - since_us, resolution)
    }

    fn with_origin(origin_us: i64, resolution: Resolution) -> Self {
        let origin_us = match resolution.chromium_interval_us() {
            Some(interval_us) => clamp(origin_us, interval_us),
            None => origin_us,
        };
        Self {
            origin_us,
            resolution,
        }
    }

    /// Returns the current `performance.now()` reading.
    #[must_use]
    pub(crate) fn now(&self) -> f64 {
        self.at(monotonic_us())
    }

    /// Returns `performance.now()` for `elapsed` time since the origin. Used for work whose
    /// duration is modeled instead of measured.
    #[must_use]
    pub(crate) fn after(&self, elapsed: Duration) -> f64 {
        self.at(self.origin_us + elapsed.as_micros() as i64)
    }

    /// Returns `performance.now()` for monotonic time `now_us`.
    fn at(&self, now_us: i64) -> f64 {
        let elapsed_us = now_us - self.origin_us;
        match self.resolution {
            Resolution::Chromium | Resolution::ChromiumFine => {
                let interval_us = self
                    .resolution
                    .chromium_interval_us()
                    .expect("a Chromium clock");
                clamp(now_us, interval_us) as f64 / 1000.0 - self.origin_us as f64 / 1000.0
            }
            Resolution::WebKitMillisecond => elapsed_us.div_euclid(1000) as f64,
            Resolution::WebKitFine => {
                let seconds = elapsed_us as f64 / 1e6;
                (seconds / WEBKIT_FINE_STEP_S).floor() * WEBKIT_FINE_STEP_S * 1000.0
            }
        }
    }

    /// Takes `count` pairs of consecutive readings for clock-resolution measurement.
    #[must_use]
    pub(crate) fn back_to_back(&self, count: usize) -> Vec<[f64; 2]> {
        (0..count).map(|_| [self.now(), self.now()]).collect()
    }
}

impl Resolution {
    /// The clamping interval of a Chromium clock.
    fn chromium_interval_us(self) -> Option<i64> {
        match self {
            Self::Chromium => Some(CHROMIUM_COARSE_US),
            Self::ChromiumFine => Some(CHROMIUM_FINE_US),
            Self::WebKitMillisecond | Self::WebKitFine => None,
        }
    }
}

/// Implements `blink::TimeClamper::ClampTimeResolution` for nonnegative times. Rounds down
/// until a fixed pseudorandom threshold in each interval, then rounds up. This prevents timing
/// measurements from locating the boundary.
///
/// # Panics
///
/// Panics if operating-system entropy is unavailable for the process secret.
fn clamp(time_us: i64, interval_us: i64) -> i64 {
    static SECRET: OnceLock<u64> = OnceLock::new();
    let secret = SECRET.get_or_init(|| {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).expect("drawing the time clamper secret");
        u64::from_le_bytes(bytes)
    });
    clamp_with(time_us, interval_us, *secret)
}

fn clamp_with(time_us: i64, interval_us: i64, secret: u64) -> i64 {
    let remainder = time_us.rem_euclid(interval_us);
    let boundary = time_us - remainder;
    if remainder >= threshold(boundary, interval_us, secret) {
        boundary + interval_us
    } else {
        boundary
    }
}

fn threshold(boundary_us: i64, interval_us: i64, secret: u64) -> i64 {
    let hash = murmur3_fmix64(boundary_us as u64 ^ secret);
    // Match `TimeClamper::ToDouble` by scaling the top 53 bits to a fraction below one.
    let fraction = (hash >> 11) as f64 * (1.0 / (1u64 << 53) as f64);
    (interval_us as f64 * fraction) as i64
}

fn murmur3_fmix64(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^ (value >> 33)
}

#[cfg(unix)]
fn monotonic_us() -> i64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a live, writable, aligned `timespec`, and `clock_gettime` writes only
    // through that pointer. `CLOCK_MONOTONIC` is valid on Linux.
    //
    // The absolute monotonic reading is needed to reproduce floating-point precision loss.
    // `std::time::Instant` reads this clock but hides its absolute value.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) };
    assert_eq!(status, 0, "CLOCK_MONOTONIC is unavailable");
    time.tv_sec * 1_000_000 + time.tv_nsec / 1000
}

#[cfg(windows)]
fn monotonic_us() -> i64 {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };

    let (mut count, mut frequency) = (0, 0);
    // SAFETY: both pointers are to live, writable, aligned `i64`s, which the calls only write
    // through. Neither call fails on Windows XP or later.
    unsafe {
        QueryPerformanceCounter(&mut count);
        QueryPerformanceFrequency(&mut frequency);
    }
    // As `base::TimeTicks` converts it, without overflowing at high frequencies.
    (i128::from(count) * 1_000_000 / i128::from(frequency)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_threshold_is_fixed_by_the_secret_and_boundary() {
        // With a fixed secret, each boundary has one threshold below which times round down.
        let boundary = 18_000_000_000;
        for interval in [CHROMIUM_COARSE_US, CHROMIUM_FINE_US] {
            for secret in [0, 1, 0xdead_beef] {
                let cut = threshold(boundary, interval, secret);
                assert!((0..interval).contains(&cut));
                for offset in 0..interval {
                    let expected = if offset >= cut {
                        boundary + interval
                    } else {
                        boundary
                    };
                    assert_eq!(clamp_with(boundary + offset, interval, secret), expected);
                }
            }
        }
    }

    #[test]
    fn a_new_context_starts_near_zero_and_never_runs_backwards() {
        for resolution in [
            Resolution::Chromium,
            Resolution::ChromiumFine,
            Resolution::WebKitMillisecond,
            Resolution::WebKitFine,
        ] {
            let clock = PerformanceClock::started_now(resolution);
            let mut previous = clock.now();
            assert!((0.0..=1.0).contains(&previous), "{previous}");
            for _ in 0..10_000 {
                let reading = clock.now();
                assert!(reading >= previous);
                previous = reading;
            }
        }
    }

    #[test]
    fn an_epoch_origin_maps_to_the_elapsed_wall_time_in_the_resolution_steps() {
        let origin = epoch_ms() - 1500;
        let read = |resolution| PerformanceClock::from_epoch_origin(origin, resolution).now();
        let chromium = read(Resolution::Chromium);
        let chromium_fine = read(Resolution::ChromiumFine);
        let millisecond = read(Resolution::WebKitMillisecond);
        let fine = read(Resolution::WebKitFine);
        for reading in [chromium, chromium_fine, millisecond, fine] {
            assert!((1499.0..1600.0).contains(&reading), "{reading}");
        }
        assert_eq!(millisecond.fract(), 0.0);
        let steps = fine / 0.02;
        assert!((steps - steps.round()).abs() < 1e-6, "{fine}");
    }

    /// Back-to-back readings of each clock differ by at least its step, as the clock probe
    /// measures: 0.1 ms in a site's widget, 0.005 ms on Cloudflare's challenge page (Chrome 156
    /// reports `0.004999995231628418` there, the step less the subtraction's rounding).
    #[test]
    fn back_to_back_readings_step_by_the_chromium_interval() {
        for (resolution, step) in [
            (Resolution::Chromium, 0.1),
            (Resolution::ChromiumFine, 0.005),
        ] {
            let readings = PerformanceClock::started_now(resolution).back_to_back(200_000);
            let smallest = readings
                .iter()
                .map(|[before, after]| after - before)
                .filter(|difference| *difference > 0.0)
                .fold(f64::INFINITY, f64::min);
            assert!((smallest - step).abs() < 1e-6, "{resolution:?}: {smallest}");
        }
    }
}
