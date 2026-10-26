//! Encodes payloads in the session's format, and reads them back.
//!
//! Sessions share one algorithm but differ in base64 alphabet, RSA modulus, and key-transform
//! secret. The serialized JSON, wrapped in spaces, is deflated if that makes it smaller, framed,
//! padded to whole blocks, and encrypted with XTEA under a key taken from a random seed. The
//! seed, encrypted with textbook RSA, precedes the ciphertext.
//!
//! [`decode_response`] removes the simpler mask applied to POST responses.

use std::{array, iter};

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use base64::alphabet::Alphabet;
use base64::engine::general_purpose::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use flate2::read::DeflateDecoder;
use num_bigint::BigUint;
use serde_json::Value;

use crate::js::{self, JsObject};

/// Random seed length, also the RSA-encrypted seed length.
pub(crate) const SEED_LENGTH: usize = 128;
/// Length of the symmetric key and key-transform secret.
pub(crate) const KEY_LENGTH: usize = 16;
/// XTEA encrypts 8-byte blocks; the frame is padded to whole blocks.
const BLOCK_LENGTH: usize = 8;
/// The frame's leading `fd 01` marker and version.
const FRAME_MARKER: [u8; 2] = [0xfd, 1];
/// The seed's first byte, which the encoder fixes to keep the seed below the modulus.
pub(crate) const SEED_MARKER: u8 = 2;
/// RSA public exponent used to encrypt seeds in every session.
pub(crate) const PUBLIC_EXPONENT: u32 = 65_537;
/// Serialized payloads shorter than this are never compressed.
const COMPRESSION_THRESHOLD: usize = 128;
/// XTEA's key schedule constant.
const DELTA: u32 = 0x9e37_79b9;

#[derive(Clone)]
pub(crate) struct Codec {
    /// The 64-character alphabet as the session spells it, kept for export.
    pub(crate) alphabet_text: String,
    alphabet: GeneralPurpose,
    pub(crate) modulus: BigUint,
    pub(crate) secret: [u8; KEY_LENGTH],
}

impl Codec {
    /// Requires 64 distinct printable ASCII characters and a modulus exactly as wide as the
    /// seed.
    pub(crate) fn try_new(
        alphabet: &str,
        modulus: BigUint,
        secret: [u8; KEY_LENGTH],
    ) -> Result<Self> {
        ensure!(
            modulus.bits().div_ceil(8) == SEED_LENGTH as u64,
            "RSA modulus must be {SEED_LENGTH} bytes wide, not {} bits",
            modulus.bits()
        );
        Ok(Self {
            alphabet_text: alphabet.to_owned(),
            alphabet: engine(alphabet)?,
            modulus,
            secret,
        })
    }

    #[must_use]
    pub(crate) fn encode(&self, payload: &JsObject, mut seed: [u8; SEED_LENGTH]) -> String {
        let mut frame = frame(payload);
        let padded = frame.len().next_multiple_of(BLOCK_LENGTH);
        let padding = (padded - frame.len()) as u8;
        frame.resize(padded, 0);

        seed[0] = SEED_MARKER;
        let key = frame_key(&seed, padding, &self.secret);
        apply(&mut frame, &key, encrypt_block);
        Envelope {
            wrapped_seed: wrap_seed(&seed, &self.modulus),
            padding,
            frame,
        }
        .encode(&self.alphabet)
    }
}

/// A request body's parts: the RSA-wrapped seed, the padding byte, and the encrypted frame.
pub(crate) struct Envelope {
    pub(crate) wrapped_seed: [u8; SEED_LENGTH],
    pub(crate) padding: u8,
    pub(crate) frame: Vec<u8>,
}

impl Envelope {
    pub(crate) fn decode(body: &str, engine: &GeneralPurpose) -> Result<Self> {
        let envelope = engine.decode(body).context("decoding the POST envelope")?;
        let (wrapped_seed, rest) = envelope
            .split_first_chunk()
            .context("the POST envelope is shorter than a wrapped seed")?;
        let (&padding, frame) = rest
            .split_first()
            .context("the POST envelope has no padding byte")?;
        ensure!(
            frame.len().is_multiple_of(BLOCK_LENGTH),
            "the POST frame is not whole blocks: {} bytes",
            frame.len()
        );
        ensure!(
            usize::from(padding) < BLOCK_LENGTH,
            "the padding byte is not below a block: {padding}"
        );
        Ok(Self {
            wrapped_seed: *wrapped_seed,
            padding,
            frame: frame.to_vec(),
        })
    }

    #[must_use]
    pub(crate) fn encode(&self, engine: &GeneralPurpose) -> String {
        engine.encode([&self.wrapped_seed[..], &[self.padding], &self.frame].concat())
    }

    /// Decrypts the frame with the key derived from `seed` and the session's key-transform
    /// `secret`, and reads its payload.
    pub(crate) fn payload(
        mut self,
        seed: &[u8; SEED_LENGTH],
        secret: &[u8; KEY_LENGTH],
    ) -> Result<Value> {
        let key = frame_key(seed, self.padding, secret);
        apply(&mut self.frame, &key, decrypt_block);
        unframe(&self.frame, self.padding)
    }
}

/// A session's base64 engine. It encodes without padding characters and,
/// as the challenge server does, decodes with or without them.
pub(crate) fn engine(alphabet: &str) -> Result<GeneralPurpose> {
    Ok(GeneralPurpose::new(
        &Alphabet::new(alphabet).context("session base64 alphabet")?,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::Indifferent),
    ))
}

/// Encrypts `seed` with `modulus` using the encoder's textbook RSA.
#[must_use]
pub(crate) fn wrap_seed(seed: &[u8; SEED_LENGTH], modulus: &BigUint) -> [u8; SEED_LENGTH] {
    rsa(seed, &PUBLIC_EXPONENT.into(), modulus)
}

/// Computes `block^exponent mod modulus` as big-endian bytes, left-padded to [`SEED_LENGTH`].
///
/// # Panics
///
/// Panics if a modulus wider than [`SEED_LENGTH`] produces a longer result.
#[must_use]
pub(crate) fn rsa(
    block: &[u8; SEED_LENGTH],
    exponent: &BigUint,
    modulus: &BigUint,
) -> [u8; SEED_LENGTH] {
    let value = BigUint::from_bytes_be(block)
        .modpow(exponent, modulus)
        .to_bytes_be();
    let mut padded = [0; SEED_LENGTH];
    padded[SEED_LENGTH - value.len()..].copy_from_slice(&value);
    padded
}

/// Derives the XTEA key from a seed window selected by `padding`, masked with the session's
/// key-transform secret.
#[must_use]
fn frame_key(seed: &[u8; SEED_LENGTH], padding: u8, secret: &[u8; KEY_LENGTH]) -> [u8; KEY_LENGTH] {
    let start = 40 + 9 * usize::from(padding);
    array::from_fn(|index| seed[start + index] ^ secret[index])
}

/// Builds a frame containing the `fd 01` marker and version, a compression flag, and the
/// serialized payload.
fn frame(payload: &JsObject) -> Vec<u8> {
    let json = format!(" {} ", js::stringify_object(payload)).into_bytes();
    if json.len() >= COMPRESSION_THRESHOLD {
        let compressed = deflate(&json);
        if compressed.len() < json.len() {
            return [&FRAME_MARKER[..], &[1], &compressed].concat();
        }
    }
    [&FRAME_MARKER[..], &[0], &json].concat()
}

/// Reads a payload from a decrypted frame after removing `padding` zero bytes. Reverses
/// [`frame`].
fn unframe(frame: &[u8], padding: u8) -> Result<Value> {
    use std::io::Read;

    let unpadded = frame
        .len()
        .checked_sub(usize::from(padding))
        .context("the padding overruns the frame")?;
    let (frame, zeros) = frame.split_at(unpadded);
    ensure!(
        zeros.iter().all(|&byte| byte == 0),
        "the frame's padding is not zero bytes"
    );
    let (&flag, payload) = frame
        .strip_prefix(&FRAME_MARKER)
        .context("the frame has no fd 01 marker")?
        .split_first()
        .context("the frame has no compression flag")?;
    let json = match flag {
        0 => payload.to_vec(),
        1 => {
            let mut inflated = Vec::new();
            DeflateDecoder::new(payload)
                .read_to_end(&mut inflated)
                .context("inflating the frame payload")?;
            inflated
        }
        flag => bail!("the frame names no compression {flag}"),
    };
    let json = json
        .strip_prefix(b" ")
        .and_then(|json| json.strip_suffix(b" "))
        .context("the frame payload is not space-wrapped JSON")?;
    serde_json::from_slice(json).context("parsing the frame payload")
}

const LENGTH_BASES: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA_BITS: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASES: [usize; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA_BITS: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Maximum DEFLATE match length, in bytes.
const MAXIMUM_MATCH: usize = 258;
/// Maximum backward distance for a DEFLATE match, in bytes.
const WINDOW: usize = 32_768;

/// Encodes raw DEFLATE in one fixed-Huffman block. Finds matches with a 13-bit hash of the next
/// three bytes and checks at most two earlier positions per hash.
fn deflate(input: &[u8]) -> Vec<u8> {
    let mut out = Bits::default();
    // `BFINAL` set, then `BTYPE` 01: a final block with fixed Huffman codes.
    out.write(0b011, 3);

    let mut chains = Chains {
        heads: vec![None; 8192],
        links: vec![None; WINDOW],
    };
    let mut position = 0;
    while position < input.len() {
        let (mut length, mut distance) = (0, 0);
        if position + 3 <= input.len() {
            let limit = MAXIMUM_MATCH.min(input.len() - position);
            let candidates = iter::successors(chains.insert(input, position), |&earlier| {
                chains.before(earlier)
            });
            let nearest = candidates
                .take_while(|&earlier| earlier < position && position - earlier <= WINDOW)
                .take(2);
            for earlier in nearest {
                let matched = (0..limit)
                    .take_while(|&offset| input[earlier + offset] == input[position + offset])
                    .count();
                if matched > length && matched > 2 {
                    (length, distance) = (matched, position - earlier);
                    if matched == limit {
                        break;
                    }
                }
            }
        }
        if length > 2 {
            out.back_reference(length, distance);
            let covered =
                (position + 1..position + length).take_while(|&skipped| skipped + 3 <= input.len());
            for skipped in covered {
                chains.insert(input, skipped);
            }
            position += length;
        } else {
            out.symbol(usize::from(input[position]));
            position += 1;
        }
    }
    out.symbol(256);
    out.finish()
}

/// Stores earlier positions by their three-byte hash, newest first.
struct Chains {
    heads: Vec<Option<usize>>,
    links: Vec<Option<usize>>,
}

impl Chains {
    /// Records `position` and returns the most recent earlier position with the same hash.
    fn insert(&mut self, input: &[u8], position: usize) -> Option<usize> {
        let hash = (usize::from(input[position]) << 5
            ^ usize::from(input[position + 1]) << 2
            ^ usize::from(input[position + 2]))
            & 8191;
        let previous = self.heads[hash].replace(position);
        self.links[position % WINDOW] = previous;
        previous
    }

    fn before(&self, position: usize) -> Option<usize> {
        self.links[position % WINDOW]
    }
}

/// A DEFLATE bit stream, least significant bit first.
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    pending: u32,
    count: u32,
}

impl Bits {
    fn write(&mut self, value: u32, bits: u32) {
        self.pending |= value << self.count;
        self.count += bits;
        while self.count >= 8 {
            self.bytes.push(self.pending as u8);
            self.pending >>= 8;
            self.count -= 8;
        }
    }

    /// Writes a literal or length symbol using fixed Huffman codes, most significant bit first.
    fn symbol(&mut self, symbol: usize) {
        let (code, bits) = match symbol {
            0..144 => (0x30 + symbol, 8),
            144..256 => (0x190 + symbol - 144, 9),
            256..280 => (symbol - 256, 7),
            _ => (0xc0 + symbol - 280, 8),
        };
        self.write(reverse(code, bits), bits);
    }

    /// Encodes length and distance using the first code range that contains each value.
    fn back_reference(&mut self, length: usize, distance: usize) {
        let code = (0..LENGTH_BASES.len())
            .find(|&code| length < LENGTH_BASES[code] + (1 << LENGTH_EXTRA_BITS[code]))
            .expect("matches are at most 258 bytes long");
        self.symbol(257 + code);
        self.write(
            (length - LENGTH_BASES[code]) as u32,
            LENGTH_EXTRA_BITS[code],
        );
        let code = (0..DISTANCE_BASES.len())
            .find(|&code| distance < DISTANCE_BASES[code] + (1 << DISTANCE_EXTRA_BITS[code]))
            .expect("matches are at most 32768 bytes back");
        self.write(reverse(code, 5), 5);
        self.write(
            (distance - DISTANCE_BASES[code]) as u32,
            DISTANCE_EXTRA_BITS[code],
        );
    }

    fn finish(mut self) -> Vec<u8> {
        if self.count > 0 {
            self.bytes.push(self.pending as u8);
        }
        self.bytes
    }
}

fn reverse(code: usize, bits: u32) -> u32 {
    (code as u32).reverse_bits() >> (32 - bits)
}

/// Applies `cipher` to each complete block. Block `i` uses a key derived by encrypting `i` and
/// `i + 1`, modulo 256, with the original key.
fn apply(data: &mut [u8], key: &[u8; KEY_LENGTH], cipher: fn([u32; 2], &[u32; 64]) -> [u32; 2]) {
    let base = schedule(words(key));
    let schedules: Vec<_> = (0..=u8::MAX)
        .take(data.len() / BLOCK_LENGTH)
        .map(|index| {
            let [a, b] = encrypt_block([0, index.into()], &base);
            let [c, d] = encrypt_block([0, index.wrapping_add(1).into()], &base);
            schedule([a, b, c, d])
        })
        .collect();
    let (blocks, _) = data.as_chunks_mut::<BLOCK_LENGTH>();
    let keyed_blocks = blocks.iter_mut().zip(schedules.iter().cycle());
    for (block, keys) in keyed_blocks {
        let [a, b] = cipher(words(block), keys);
        block[..4].copy_from_slice(&a.to_be_bytes());
        block[4..].copy_from_slice(&b.to_be_bytes());
    }
}

/// XTEA's round keys, each with its running sum already added.
fn schedule(key: [u32; 4]) -> [u32; 64] {
    let mut keys = [0; 64];
    let mut sum = 0_u32;
    for round in keys.as_chunks_mut::<2>().0 {
        round[0] = sum.wrapping_add(key[(sum & 3) as usize]);
        sum = sum.wrapping_add(DELTA);
        round[1] = sum.wrapping_add(key[(sum >> 11 & 3) as usize]);
    }
    keys
}

fn encrypt_block([mut a, mut b]: [u32; 2], keys: &[u32; 64]) -> [u32; 2] {
    let mix = |value: u32| ((value << 4) ^ (value >> 5)).wrapping_add(value);
    for [first, second] in keys.as_chunks::<2>().0 {
        a = a.wrapping_add(mix(b) ^ first);
        b = b.wrapping_add(mix(a) ^ second);
    }
    [a, b]
}

fn decrypt_block([mut a, mut b]: [u32; 2], keys: &[u32; 64]) -> [u32; 2] {
    let mix = |value: u32| ((value << 4) ^ (value >> 5)).wrapping_add(value);
    let (rounds, _) = keys.as_chunks::<2>();
    for [first, second] in rounds.iter().rev() {
        b = b.wrapping_sub(mix(a) ^ second);
        a = a.wrapping_sub(mix(b) ^ first);
    }
    [a, b]
}

fn words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    array::from_fn(|index| u32::from_be_bytes(bytes.as_chunks().0[index]))
}

/// Removes the response mask before the program runs. `token` is the ray identifier in the
/// request path `/fo/.../<ray>/...`.
pub fn decode_response(body: &[u8], token: &str) -> Result<Vec<u8>> {
    ensure!(token.is_ascii(), "response token must be ASCII");
    let mask = token
        .bytes()
        .chain(b"_0".iter().copied())
        .fold(32_u8, |mask, byte| mask ^ byte);
    let bytes = STANDARD
        .decode(body)
        .context("decoding the response envelope")?;
    // The position term repeats every 65535 bytes, and bytes are reduced modulo 255, not 256.
    Ok(bytes
        .into_iter()
        .enumerate()
        .map(|(index, byte)| {
            (i64::from(byte) - i64::from(mask) - (index % 65_535) as i64).rem_euclid(255) as u8
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that an independent inflater handles output with no matches, overlapping runs,
    /// maximum match lengths, and distances spanning the window.
    #[test]
    fn deflate_round_trips_through_an_independent_inflater() {
        use std::io::Read;

        let mut noise = 0x2545_f491_u32;
        let random: Vec<u8> = (0..70_000)
            .map(|_| {
                noise ^= noise << 13;
                noise ^= noise >> 17;
                noise ^= noise << 5;
                noise as u8
            })
            .collect();
        let mut far = random[..WINDOW - 10].to_vec();
        far.extend_from_slice(&random[..300]);
        let inputs: [&[u8]; 7] = [
            b"",
            b"a",
            b"abcabcabcabcabcabcabc",
            &[b'x'; 1000],
            br#"{"a":1,"b":[1,2,3],"c":{"a":1,"b":[1,2,3]}}"#,
            &random,
            &far,
        ];
        for input in inputs {
            let mut inflated = Vec::new();
            DeflateDecoder::new(&deflate(input)[..])
                .read_to_end(&mut inflated)
                .unwrap();
            assert!(inflated == input, "{} bytes", input.len());
        }
    }

    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    #[test]
    fn rejects_parameters_the_encoding_cannot_use() {
        let modulus = BigUint::from(1u8) << (SEED_LENGTH * 8 - 1);
        let secret = [7; KEY_LENGTH];
        assert!(Codec::try_new(ALPHABET, modulus.clone(), secret).is_ok());
        for bad in [BigUint::ZERO, BigUint::from(3u8), modulus.clone() << 1] {
            assert!(
                Codec::try_new(ALPHABET, bad, secret).is_err(),
                "a zero or narrow modulus would reach modpow or under-size the envelope; a wide \
                 one would overflow it"
            );
        }
        for alphabet in [&ALPHABET[1..], "é".repeat(32).as_str(), &"A".repeat(64)] {
            assert!(Codec::try_new(alphabet, modulus.clone(), secret).is_err());
        }
    }

    #[test]
    fn response_position_wraps_at_65535() {
        let token = "abcdef0123456789";
        let mask = token
            .bytes()
            .chain(b"_0".iter().copied())
            .fold(32_u8, |mask, byte| mask ^ byte);
        let plaintext: Vec<_> = (0..65538).map(|index| (index % 254) as u8).collect();
        let masked: Vec<_> = plaintext
            .iter()
            .enumerate()
            .map(|(index, &byte)| {
                ((usize::from(byte) + usize::from(mask) + index % 65535) % 255) as u8
            })
            .collect();
        assert_eq!(
            decode_response(STANDARD.encode(masked).as_bytes(), token).unwrap(),
            plaintext
        );
    }
}
