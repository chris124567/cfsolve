//! Runs the returned worker's timed SHA-256 nonce search using recovered checkbox proof
//! settings.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::worker_timing::{self, Samples};
use crate::js::{JsObject, JsValue, Options};

/// Search input: nonce prefix and counter, plus a suffix included in the digest.
#[derive(Debug)]
pub struct Challenge {
    pub prefix: String,
    pub suffix: String,
}

/// First nonce achieving the best leading-zero score, with the total digest count.
#[derive(Debug, Default)]
pub struct Answer {
    /// Includes the session prefix, as in the worker's response.
    pub nonce: String,
    pub hashes: u64,
    pub leading_zeros: u32,
}

fn leading_zeros(digest: &[u8]) -> u32 {
    let zero_bytes = digest.iter().take_while(|&&byte| byte == 0).count();
    zero_bytes as u32 * 8
        + digest
            .get(zero_bytes)
            .map_or(0, |byte| byte.leading_zeros())
}

impl Challenge {
    /// Runs one worker with a budget starting when its script begins. Computes real digests but
    /// paces delivery to match the browser's crypto-thread and event-loop round trips.
    fn search_timed(
        &self,
        start: u32,
        budget: Duration,
        startup: Duration,
        digest_cost: Duration,
    ) -> Result<Answer> {
        use sha2::Digest;

        worker_timing::spin_until(Instant::now(), startup)?;
        let began = Instant::now();
        let mut next = u64::from(start);
        let mut answer = Answer::default();
        loop {
            let digest_began = Instant::now();
            let nonce = format!("{}{next}", self.prefix);
            next += 1;
            let digest = Sha256::new()
                .chain_update(nonce.as_bytes())
                .chain_update(self.suffix.as_bytes())
                .finalize();
            let zeros = leading_zeros(&digest);
            // The JS worker starts its best score at -1 and retains the first
            // nonce on ties. All real digest scores are nonnegative.
            if answer.hashes == 0 || zeros > answer.leading_zeros {
                answer.nonce = nonce;
                answer.leading_zeros = zeros;
            }
            answer.hashes += 1;
            worker_timing::spin_until(digest_began, digest_cost)?;
            if began.elapsed() >= budget {
                return Ok(answer);
            }
        }
    }

    /// Runs workers with independent budgets and incrementing nonces. On equal scores, the
    /// first reply wins, matching the message handler.
    pub fn search(&self, starts: &[u32], budget: Duration, costs: &WorkerCosts) -> Result<Answer> {
        // The workers are created together, so they share one start-up delay.
        let startup =
            Samples::try_new(&costs.startup_ms, 1000.0, "proof worker startup")?.pick()?;
        let digest = Samples::try_new(&costs.digest_us, 1e6, "proof digest round trip")?;
        let digests: Vec<Duration> = starts
            .iter()
            .map(|_| digest.pick())
            .collect::<Result<_>>()?;
        let workers = starts.iter().zip(&digests);
        let (send, receive) = mpsc::channel();
        thread::scope(|scope| {
            for (&start, &digest) in workers {
                let send = send.clone();
                scope.spawn(move || {
                    let _ = send.send(self.search_timed(start, budget, startup, digest));
                });
            }
            drop(send);
            let mut answers = receive.into_iter();
            let mut best = answers
                .next()
                .context("proof workers produced no answer")??;
            for answer in answers {
                let answer = answer?;
                let hashes = best.hashes + answer.hashes;
                if answer.leading_zeros > best.leading_zeros {
                    best = answer;
                }
                best.hashes = hashes;
            }
            Ok(best)
        })
    }
}

/// Measured proof-worker timing samples: delay from worker creation to budget start, and
/// average digest round-trip time calculated as budget divided by hash count. Each run chooses
/// a sample to reflect variation in machine load.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WorkerCosts {
    pub startup_ms: Vec<f64>,
    pub digest_us: Vec<f64>,
}

/// Worker count: `min(32, max(1, ceil(hardwareConcurrency * .75 || 6)))`.
fn workers(hardware_concurrency: f64) -> usize {
    let mut scaled = hardware_concurrency * 0.75;
    if scaled == 0.0 || scaled.is_nan() {
        scaled = 6.0;
    }
    scaled.ceil().clamp(1.0, 32.0) as usize
}

/// Fields assigned by the proof's success callback, separate from the ordinary worker's message
/// keys.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProofFields {
    pub nonce: String,
    pub hashes: String,
    pub workers: String,
    pub elapsed: String,
    pub finished: String,
    pub requested_workers: String,
}

impl ProofFields {
    /// Builds success callback fields from `answer`, found using `workers` workers.
    #[must_use]
    pub fn finish(
        &self,
        answer: &Answer,
        workers: usize,
        elapsed_ms: f64,
        finished_ms: i64,
    ) -> JsObject {
        JsObject::from_iter([
            (self.requested_workers.clone(), JsValue::from(workers)),
            (self.nonce.clone(), JsValue::String(answer.nonce.clone())),
            (self.hashes.clone(), JsValue::from(answer.hashes)),
            (self.workers.clone(), JsValue::from(workers)),
            (self.elapsed.clone(), JsValue::from(elapsed_ms)),
            (self.finished.clone(), JsValue::from(finished_ms)),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Proof {
    pub budget_ms: f64,
    pub suffix: String,
    pub prefix_option: String,
    pub iteration: u64,
}

impl Proof {
    /// Builds search input from `options` for a proof starting at `now_ms`.
    pub fn challenge(&self, options: &Options, now_ms: i64) -> Result<Challenge> {
        let prefix = options
            .get(&self.prefix_option)
            .and_then(JsValue::as_str)
            .context("proof prefix option is missing or not a string")?;
        Ok(Challenge {
            prefix: format!("{prefix}|{now_ms}|{}|", self.iteration),
            suffix: self.suffix.clone(),
        })
    }

    /// Runs the bounded worker search from fresh random nonces. Reports the actual number of
    /// hashes computed.
    pub fn search(
        &self,
        options: &Options,
        started_ms: i64,
        hardware_concurrency: f64,
        costs: &WorkerCosts,
    ) -> Result<ProofSearch> {
        let count = workers(hardware_concurrency);
        let mut random: Vec<u8> = vec![0; count * 4];
        getrandom::fill(&mut random).context("selecting proof starting nonces")?;
        let (chunks, _) = random.as_chunks::<4>();
        let starts: Vec<u32> = chunks
            .iter()
            .map(|bytes| u32::from_le_bytes(*bytes) % 10_000)
            .collect();
        let budget = Duration::try_from_secs_f64(self.budget_ms / 1000.0)
            .context("proof time budget is out of range")?;
        let answer = self
            .challenge(options, started_ms)?
            .search(&starts, budget, costs)?;
        Ok(ProofSearch {
            answer,
            workers: count,
        })
    }
}

pub struct ProofSearch {
    pub answer: Answer,
    pub workers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::{self, json};

    /// Checks that startup happens before hashing and digest round-trip delays limit each
    /// worker's hash count to the measured browser rate.
    #[test]
    fn measured_costs_pace_the_workers_like_a_browser() {
        let costs = WorkerCosts {
            startup_ms: vec![15.0],
            digest_us: vec![100.0],
        };
        let challenge = Challenge {
            prefix: "ray|1|0|".into(),
            suffix: "suffix".into(),
        };
        let began = Instant::now();
        let answer = challenge
            .search(&[1, 2, 3], Duration::from_millis(20), &costs)
            .unwrap();
        let elapsed = began.elapsed();
        assert!(
            elapsed >= Duration::from_millis(35),
            "start-up and budget run in turn: {elapsed:?}"
        );
        assert!(
            answer.hashes <= 3 * 201,
            "at most one digest per 100 µs per worker, plus the final one: {}",
            answer.hashes
        );
        assert!(
            answer.hashes >= 3 * 10,
            "workers competing for cores hash less, as a browser's would, but not this much \
             less: {}",
            answer.hashes
        );
        assert!(answer.nonce.starts_with("ray|1|0|"));
    }

    #[test]
    fn search_prefixes_nonces_with_the_session_ray_and_start_time() {
        let proof: Proof = js::from_value(json!({"budget_ms": 0, "suffix": "suffix",
            "prefix_option": "ray", "iteration": 2}))
        .unwrap();
        let options: Options = js::from_value(json!({"ray": "current-ray"})).unwrap();
        let challenge = proof.challenge(&options, 1_791_415_784_000).unwrap();
        assert_eq!(challenge.prefix, "current-ray|1791415784000|2|");
        assert_eq!(challenge.suffix, "suffix");
        assert!(proof.challenge(&Options::new(), 0).is_err());
        assert!(
            proof
                .challenge(&js::from_value(json!({"ray": 42})).unwrap(), 0)
                .is_err()
        );
        let free = WorkerCosts {
            startup_ms: vec![0.0],
            digest_us: vec![0.0],
        };
        let ProofSearch { answer, workers } = proof.search(&options, 123, 4.0, &free).unwrap();
        assert_eq!(workers, 3, "ceil(4 * .75)");
        assert_eq!(
            answer.hashes, 3,
            "a zero budget still hashes once per worker"
        );
        assert!(answer.nonce.starts_with("current-ray|123|2|"));
    }
}
