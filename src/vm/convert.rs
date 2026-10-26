//! Converts JavaScript numbers to VM operands, rejecting values that would require truncation
//! or saturation.

/// Maximum allocated array length. Decoded constants are much shorter; larger lengths indicate
/// invalid operands.
pub(crate) const MAXIMUM_LENGTH: usize = 1 << 16;

/// Converts `number` to an opcode, register index, or dispatch key.
#[must_use]
pub(crate) fn byte(number: f64) -> Option<u8> {
    (number.fract() == 0.0 && (0.0..=255.0).contains(&number)).then_some(number as u8)
}

/// Converts `number` to a program position or cell index.
#[must_use]
pub(crate) fn position(number: f64) -> Option<u32> {
    (number.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&number))
        .then_some(number as u32)
}

/// Converts `number` to an index into a program, array, or string.
#[must_use]
pub(crate) fn index(number: f64) -> Option<usize> {
    position(number).map(|index| index as usize)
}

/// Converts `number` to an array index or length within [`MAXIMUM_LENGTH`].
#[must_use]
pub(crate) fn length(number: f64) -> Option<usize> {
    (number.fract() == 0.0 && (0.0..=MAXIMUM_LENGTH as f64).contains(&number))
        .then_some(number as usize)
}
