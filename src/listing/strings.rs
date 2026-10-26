//! Decodes compact string descriptors and references to the program's string pool.

use anyhow::{Context, Result, ensure};

/// A descriptor length of this value introduces a pooled string.
const POOLED: usize = 65_535;
/// Number of UTF-16 code units preceding the pool's first string.
const POOL_HEADER: usize = 2;

/// Decodes a compact string descriptor using UTF-16 code-unit offsets and lengths, matching
/// JavaScript's `charCodeAt` and `slice`.
///
/// Ordinary descriptors contain a big-endian length followed by inline text. Length `ffff`
/// introduces an inline-prefix length, a four-byte pool offset, and a four-byte suffix length.
/// Skips the pool's two-unit header.
pub(crate) fn decode_string(descriptor: &str, pool: &str) -> Result<String> {
    let descriptor: Vec<u16> = descriptor.encode_utf16().collect();
    let length = integer(&descriptor, 0, 2)?;
    let text = if length == POOLED {
        let prefix = integer(&descriptor, 2, 2)?;
        let offset = integer(&descriptor, 4, 4)?;
        let suffix = integer(&descriptor, 8, 4)?;
        let pool: Vec<u16> = pool.encode_utf16().collect();
        let mut text = slice(&descriptor, 12, prefix).to_vec();
        text.extend_from_slice(slice(&pool, offset.saturating_add(POOL_HEADER), suffix));
        text
    } else {
        slice(&descriptor, 2, length).to_vec()
    };
    String::from_utf16(&text).context("decoded string contains an unpaired surrogate")
}

fn integer(text: &[u16], offset: usize, width: usize) -> Result<usize> {
    let bytes = text
        .get(offset..offset + width)
        .context("truncated string descriptor")?;
    ensure!(
        bytes.iter().all(|&byte| byte <= 255),
        "descriptor header is not byte-valued"
    );
    Ok(bytes
        .iter()
        .fold(0, |value, &byte| (value << 8) | usize::from(byte)))
}

// JavaScript slice clamps its positive indexes to the string's length.
fn slice(text: &[u16], start: usize, length: usize) -> &[u16] {
    let start = start.min(text.len());
    &text[start..start.saturating_add(length).min(text.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_offsets_count_utf16_units_and_ignore_padding() {
        assert_eq!(decode_string("\0\u{3}a😀ignored", "").unwrap(), "a😀");
        let descriptor = "ÿÿ\0\u{2}\0\0\0\u{3}\0\0\0\u{3}hiignored";
        assert_eq!(decode_string(descriptor, "\0\u{9}a😀xyz").unwrap(), "hixyz");
        assert!(decode_string("ÿÿ\0", "").is_err());
    }
}
