//! Generates short random identifiers in the scripts' format.

use std::iter;

/// Draws `length` uniformly distributed characters from `alphabet`.
///
/// # Panics
///
/// Panics unless `alphabet` is a nonempty set of at most 256 ASCII characters. Also panics if
/// operating-system entropy is unavailable; a session requires unpredictable identifiers.
#[must_use]
pub(crate) fn random_id(alphabet: &[u8], length: usize) -> String {
    let bytes = iter::repeat_with(|| {
        let mut chunk = [0; 32];
        getrandom::fill(&mut chunk).expect("drawing a random identifier");
        chunk
    })
    .flatten();
    id_from_bytes(alphabet, length, bytes)
}

/// Generates an identifier from random bytes. Avoids selection bias by rejecting bytes at or
/// above the largest multiple of the alphabet size below or equal to 256.
fn id_from_bytes(alphabet: &[u8], length: usize, bytes: impl IntoIterator<Item = u8>) -> String {
    assert!(
        !alphabet.is_empty() && alphabet.len() <= 256 && alphabet.is_ascii(),
        "an identifier alphabet is 1 to 256 ASCII characters"
    );
    let size = alphabet.len();
    let limit = 256 - 256 % size;
    bytes
        .into_iter()
        .filter(|&byte| usize::from(byte) < limit)
        .take(length)
        .map(|byte| char::from(alphabet[usize::from(byte) % size]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_bytes_that_would_favour_early_characters() {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(
            id_from_bytes(alphabet, 4, [255, 252, 0, 35, 36, 251]),
            "a9a9",
            "256 is not a multiple of 36, so the top 4 byte values are unused"
        );
        assert_eq!(
            id_from_bytes(b"abcdef0123456789", 2, [255, 0]),
            "9a",
            "a power-of-two alphabet uses every byte"
        );
    }
}
