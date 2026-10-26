//! Paces native work by browser worker overhead, such as startup and event-loop round trips,
//! which direct native execution lacks. Each run draws a random measured sample, reflecting
//! variation in machine load.

use std::hint;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};

/// Duration samples validated before work starts. Invalid samples cause an error regardless of
/// which sample is later chosen.
pub(super) struct Samples(Vec<Duration>);

impl Samples {
    /// Converts samples in units of `1 / per_second` seconds, naming them `what` in errors.
    pub(super) fn try_new(samples: &[f64], per_second: f64, what: &str) -> Result<Self> {
        ensure!(!samples.is_empty(), "{what} samples are empty");
        let mut durations = Vec::with_capacity(samples.len());
        for &sample in samples {
            ensure!(
                sample.is_finite() && sample >= 0.0,
                "invalid {what} sample {sample}"
            );
            let duration = Duration::try_from_secs_f64(sample / per_second)
                .with_context(|| format!("{what} sample {sample} is out of range"))?;
            durations.push(duration);
        }
        Ok(Self(durations))
    }

    /// One of the samples, chosen at random.
    pub(super) fn pick(&self) -> Result<Duration> {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).context("choosing a worker cost sample")?;
        Ok(self.0[(u64::from_le_bytes(bytes) % self.0.len() as u64) as usize])
    }
}

/// Waits until `start + delay`, failing if that time is outside the clock's range. Busy-waits
/// for delays too short for scheduler sleeps to preserve the measured duration.
pub(super) fn spin_until(start: Instant, delay: Duration) -> Result<()> {
    let deadline = start
        .checked_add(delay)
        .context("worker cost delay is beyond the clock's range")?;
    while Instant::now() < deadline {
        hint::spin_loop();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sample_is_validated_before_any_is_drawn() {
        assert!(Samples::try_new(&[], 1000.0, "startup").is_err());
        for invalid in [f64::NAN, f64::INFINITY, -1.0, 1e300] {
            let error = Samples::try_new(&[1.0, invalid], 1000.0, "startup")
                .err()
                .unwrap();
            assert!(error.to_string().contains("startup"), "{error}");
        }
        let samples = Samples::try_new(&[2.5, 2.5], 1000.0, "startup").unwrap();
        assert_eq!(samples.pick().unwrap(), Duration::from_micros(2500));
    }

    #[test]
    fn deadlines_beyond_the_clock_are_errors() {
        let now = Instant::now();
        assert!(spin_until(now, Duration::MAX).is_err());
        spin_until(now, Duration::ZERO).unwrap();
    }
}
