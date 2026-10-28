//! The proxy's RSA-1024 keypair, which lets it read the seeds browsers encrypt.
//!
//! The encoder encrypts its seed with textbook RSA and `e = 65537` under a modulus in the iframe
//! script (see `crate::challenge::codec`). The proxy swaps in its own modulus, then rewraps each
//! POST's seed under the real one. A body holds the wrapped seed, a padding byte, and an
//! XTEA-encrypted frame that does not depend on the modulus.

use std::iter;
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use regex::Regex;
use serde_json::Value;

use crate::candidates;
use crate::challenge::codec::{self, Envelope, KEY_LENGTH, PUBLIC_EXPONENT, SEED_LENGTH};
use crate::deobfuscate::{self, Encoded};

/// Matches a `BigInt` call with a hexadecimal literal, capturing its quotes and digits. The
/// regex engine has no backreferences, so code checks that the quotes match.
static MODULUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"BigInt\((["'`])0x([0-9a-fA-F]+)(["'`])\)"#).expect("a fixed pattern")
});

/// A 1024-bit RSA keypair with `e = 65537` and the modulus's top bit set. Every seed starts
/// with byte 2, so it is smaller than the modulus.
pub(super) struct ProxyKey {
    pub(super) modulus: BigUint,
    private: BigUint,
}

/// A rewrapped body and the values decrypted for logging.
pub(super) struct Rewrapped {
    /// The body to forward upstream, encoded with the session's alphabet.
    pub(super) body: String,
    pub(super) seed: [u8; SEED_LENGTH],
    pub(super) padding: u8,
}

impl ProxyKey {
    /// Generates two distinct primes whose product has the seed's width and whose totient is
    /// coprime to `e`.
    pub(super) fn generate() -> Result<Self> {
        let exponent = BigUint::from(PUBLIC_EXPONENT);
        loop {
            let (first, second) = (random_prime()?, random_prime()?);
            let modulus = &first * &second;
            if first == second || modulus.bits() != SEED_LENGTH as u64 * 8 {
                continue;
            }
            let totient = (first - 1u32) * (second - 1u32);
            if let Some(private) = exponent.modinv(&totient) {
                return Ok(Self { modulus, private });
            }
        }
    }

    /// Rewraps the seed in `body` with `real`, keeping the padding byte and frame. Rejects seeds
    /// that do not unwrap to a value starting with the encoder's fixed byte.
    pub(super) fn rewrap(&self, body: &str, alphabet: &str, real: &BigUint) -> Result<Rewrapped> {
        let engine = codec::engine(alphabet)?;
        let envelope = Envelope::decode(body, &engine)?;
        let seed = codec::rsa(&envelope.wrapped_seed, &self.private, &self.modulus);
        ensure!(
            seed[0] == codec::SEED_MARKER,
            "the unwrapped seed is not the encoder's: refusing to forward it"
        );
        let padding = envelope.padding;
        let rewrapped = Envelope {
            wrapped_seed: codec::wrap_seed(&seed, real),
            ..envelope
        };
        Ok(Rewrapped {
            body: rewrapped.encode(&engine),
            seed,
            padding,
        })
    }

    /// Decrypts a body's payload with the session's alphabet and key-transform secret.
    pub(super) fn read_payload(
        &self,
        body: &str,
        alphabet: &str,
        secret: &[u8; KEY_LENGTH],
    ) -> Result<Value> {
        let envelope = Envelope::decode(body, &codec::engine(alphabet)?)?;
        let seed = codec::rsa(&envelope.wrapped_seed, &self.private, &self.modulus);
        envelope.payload(&seed, secret)
    }
}

/// Replaces the iframe's 128-byte RSA modulus with `proxy`. Returns the rewritten HTML and the
/// original modulus. See `rsa_modulus` in `crate::challenge::program`.
///
/// Pads the replacement with zeros to preserve HTML length and stack trace positions. The modulus
/// can be a hexadecimal `BigInt` literal or an inline encoded string from `strings`. Encoded
/// replacements use the original key.
pub(super) fn swap_modulus(
    html: &str,
    strings: &[Encoded],
    proxy: &BigUint,
) -> Result<(String, BigUint)> {
    let wide = |modulus: &BigUint| modulus.bits().div_ceil(8) == SEED_LENGTH as u64;
    let literals: Vec<_> = MODULUS
        .captures_iter(html)
        .filter_map(|captures| {
            let (_, [open, digits, close]) = captures.extract();
            let modulus = BigUint::parse_bytes(digits.as_bytes(), 16).expect("hex digits");
            (open == close && wide(&modulus))
                .then(|| (captures.get(2).expect("the digits group").range(), modulus))
        })
        .collect();
    if !literals.is_empty() {
        let what = format!("{SEED_LENGTH}-byte BigInt literal in the iframe");
        let (digits, real) = candidates::exactly_one(literals, &what)?;
        let mut rewritten = html.to_owned();
        rewritten.replace_range(digits.clone(), &padded(proxy, digits.len())?);
        return Ok((rewritten, real));
    }
    let encoded = strings.iter().filter_map(|string| {
        let digits = string.decoded.strip_prefix("0x")?;
        let modulus = BigUint::parse_bytes(digits.as_bytes(), 16)?;
        wide(&modulus).then_some((string, digits.len(), modulus))
    });
    let what = format!("{SEED_LENGTH}-byte modulus in the iframe");
    let (string, width, real) = candidates::exactly_one(encoded, &what)?;
    let replacement =
        deobfuscate::encode_string(&format!("0x{}", padded(proxy, width)?), string.key);
    ensure!(
        replacement.len() == string.encoded.len() && html.matches(&string.encoded).count() == 1,
        "the encoded modulus cannot be replaced in place"
    );
    Ok((html.replacen(&string.encoded, &replacement, 1), real))
}

/// Formats `proxy` as hexadecimal, padded with zeros to `width`.
fn padded(proxy: &BigUint, width: usize) -> Result<String> {
    let digits = proxy.to_str_radix(16);
    ensure!(
        digits.len() <= width,
        "the proxy modulus needs {} hex digits, wider than the session's {width}",
        digits.len()
    );
    Ok(format!("{digits:0>width$}"))
}

/// Generates a random prime half the seed's width, with its top bit set.
fn random_prime() -> Result<BigUint> {
    let mut bytes = [0; SEED_LENGTH / 2];
    loop {
        getrandom::fill(&mut bytes).context("drawing prime bits")?;
        bytes[0] |= 0x80;
        bytes[SEED_LENGTH / 2 - 1] |= 1;
        let candidate = BigUint::from_bytes_be(&bytes);
        if is_prime(&candidate)? {
            return Ok(candidate);
        }
    }
}

/// Tests a candidate greater than 1 using trial division and 16 Miller-Rabin rounds with random
/// bases. Always accepts primes; may accept a composite with negligible probability.
fn is_prime(candidate: &BigUint) -> Result<bool> {
    let one = BigUint::from(1u32);
    let trial_divisors = iter::once(2u32).chain((3..1000).step_by(2));
    for factor in trial_divisors {
        if candidate % factor == BigUint::ZERO {
            return Ok(*candidate == BigUint::from(factor));
        }
    }
    let less_one = candidate - 1u32;
    let squarings = less_one.trailing_zeros().expect("an odd candidate above 2");
    let odd = &less_one >> squarings;
    let mut bytes = vec![0; candidate.bits().div_ceil(8) as usize];
    'bases: for _ in 0..16 {
        getrandom::fill(&mut bytes).context("drawing a Miller-Rabin base")?;
        // A base in [2, candidate - 2].
        let base = BigUint::from_bytes_be(&bytes) % (candidate - 3u32) + 2u32;
        let mut witness = base.modpow(&odd, candidate);
        if witness == one || witness == less_one {
            continue;
        }
        for _ in 1..squarings {
            witness = &witness * &witness % candidate;
            if witness == less_one {
                continue 'bases;
            }
        }
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use serde_json::json;

    use super::*;
    use crate::challenge::codec::Codec;
    use crate::js::JsObject;

    /// A permuted alphabet, to check that encoding respects the session's character order.
    const ALPHABET: &str = "NOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ABCDEFGHIJKLM";
    const SECRET: [u8; KEY_LENGTH] = *b"0123456789abcdef";

    /// Generates proxy, real, and unrelated keypairs once because prime generation is the
    /// slowest part of the suite.
    fn keys() -> &'static [ProxyKey; 3] {
        static KEYS: OnceLock<[ProxyKey; 3]> = OnceLock::new();
        KEYS.get_or_init(|| std::array::from_fn(|_| ProxyKey::generate().unwrap()))
    }

    fn encode(modulus: &BigUint, payload: &Value, seed: [u8; SEED_LENGTH]) -> String {
        let payload: JsObject = serde_json::from_value(payload.clone()).unwrap();
        let codec = Codec::try_new(ALPHABET, modulus.clone(), SECRET).unwrap();
        codec.encode(&payload, seed)
    }

    /// A page with a narrow decoy literal before the modulus literal.
    fn page(quote: char, modulus: &BigUint) -> String {
        format!("var a = BigInt(\"0x1234\"); var n = BigInt({quote}0x{modulus:x}{quote}); send(n);")
    }

    #[test]
    fn small_primes_pass_and_composites_fail() {
        for candidate in [2u32, 3, 5, 101, 65537] {
            assert!(is_prime(&BigUint::from(candidate)).unwrap(), "{candidate}");
        }
        for candidate in [4u32, 9, 561, 65537 * 257] {
            assert!(!is_prime(&BigUint::from(candidate)).unwrap(), "{candidate}");
        }
    }

    #[test]
    fn rewrap_rejects_garbage() {
        let [proxy, real, other] = keys();
        assert!(proxy.rewrap("!!!", ALPHABET, &real.modulus).is_err());
        let body = encode(&other.modulus, &json!({"a": 1}), [3; SEED_LENGTH]);
        assert!(
            proxy.rewrap(&body, ALPHABET, &real.modulus).is_err(),
            "a body wrapped under another key does not open under the proxy's"
        );
    }

    /// Rewrapping matches the session encoder's output for the same seed, padding, and frame, and
    /// both raw and DEFLATE-compressed payloads read back.
    #[test]
    fn rewrap_matches_encoding_under_the_real_modulus() {
        let [proxy, real, _] = keys();
        let payloads = [
            json!({"1": {"a": [1, 2, {"b": "x"}]}, "counter": 39}),
            json!({"1": {"a": "x".repeat(500)}, "2": [1, 2, 3]}),
        ];
        for payload in payloads {
            let body = encode(&proxy.modulus, &payload, [11; SEED_LENGTH]);
            let rewrapped = proxy.rewrap(&body, ALPHABET, &real.modulus).unwrap();
            assert_eq!(
                rewrapped.body,
                encode(&real.modulus, &payload, rewrapped.seed)
            );
            let read = proxy.read_payload(&body, ALPHABET, &SECRET).unwrap();
            assert_eq!(read, payload);
        }
    }

    /// The pages spell the literal with double quotes or template literals.
    #[test]
    fn swap_replaces_only_the_modulus_digits() {
        let [proxy, real, _] = keys();
        for quote in ['"', '`'] {
            let html = page(quote, &real.modulus);
            let (rewritten, found) = swap_modulus(&html, &[], &proxy.modulus).unwrap();
            assert_eq!(found, real.modulus);
            assert_eq!(rewritten, page(quote, &proxy.modulus));
        }
    }

    /// Find the modulus inside a decoder call when the build encodes strings.
    #[test]
    fn swap_reencodes_an_encoded_modulus() {
        let [proxy, real, _] = keys();
        let key = 59141;
        let text = |modulus: &BigUint| format!("0x00{modulus:x}");
        let encoded = deobfuscate::encode_string(&text(&real.modulus), key);
        let html = format!("<script>n = BigInt(decode(`{encoded}`));</script>");
        let strings = [Encoded {
            encoded: encoded.clone(),
            key,
            decoded: text(&real.modulus),
        }];
        let (rewritten, found) = swap_modulus(&html, &strings, &proxy.modulus).unwrap();
        assert_eq!(found, real.modulus);
        let swapped = deobfuscate::encode_string(&text(&proxy.modulus), key);
        assert_eq!(rewritten, html.replace(&encoded, &swapped));
    }

    #[test]
    fn swap_fails_closed() {
        let [proxy, real, _] = keys();
        let wide = page('"', &real.modulus);
        let narrow = (BigUint::from(1u32) << 1016) + 7u32;
        let cases = [
            ("var n = 1;".to_owned(), "no literal at all"),
            (page('"', &BigUint::from(0x1234u32)), "only narrow literals"),
            (wide.repeat(2), "two wide literals"),
            (
                format!("BigInt(\"0x{:x}`)", real.modulus),
                "quotes that do not match",
            ),
            (
                page('"', &narrow),
                "a literal narrower than the proxy modulus",
            ),
        ];
        for (html, case) in cases {
            assert!(swap_modulus(&html, &[], &proxy.modulus).is_err(), "{case}");
        }
    }
}
