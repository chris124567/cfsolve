//! The VM register file, whose reader and writer functions access 256 registers.
//!
//! Each value has a type tag and is masked by a rolling `state`. A digest updated on every write
//! determines the mask. Separate fields hold the program counter and dispatch key. Handlers access
//! registers through the reader and writer, direct tag and value writes, or the counter and key
//! fields.
//!
//! The interpreter keeps the mask and digest at zero. Stored values are therefore unmasked, and
//! changing the mask has no effect. Member names match the current build.

use crate::js;

/// Meaning of a field on the register file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Member {
    /// Rolling mask, the digest used to compute it, or the digest's halves.
    Mask,
    /// Flag indicating whether the program counter or dispatch key holds a masked integer.
    Integer,
    Pc,
    Key,
    /// Program counter or dispatch key value when it is not an integer.
    OtherPc,
    OtherKey,
    /// Register indices for the program counter and dispatch key.
    PcIndex,
    KeyIndex,
    Values,
    Tags,
}

impl Member {
    #[must_use]
    pub(crate) fn of(name: &str) -> Option<Self> {
        Some(match name {
            "h" | "O" | "K" | "L" => Self::Mask,
            "j" | "m" => Self::Integer,
            "i" => Self::Pc,
            "l" => Self::Key,
            "A" => Self::OtherPc,
            "v" => Self::OtherKey,
            "D" => Self::PcIndex,
            "F" => Self::KeyIndex,
            "H" => Self::Values,
            "J" => Self::Tags,
            _ => return None,
        })
    }
}

/// Arrays storing register values and tags at matching indices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Slots {
    Values,
    Tags,
}

/// Decoding rule used by the reader for a value with `tag`, assuming a zero mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    /// Tag 1 stores an integer XORed with the tag's upper bits.
    Integer(i32),
    /// Tag 2 stores a boolean as a comparison with the tag's upper bits.
    Boolean(i32),
    /// Tag -4 stores an encrypted string record, decrypted by the reader.
    Record,
    /// All other tags store the value directly.
    Plain,
}

impl Stored {
    #[must_use]
    pub(crate) fn of(tag: f64) -> Self {
        let tag = js::int32(tag);
        if tag == -4 {
            return Self::Record;
        }
        match tag & 3 {
            1 => Self::Integer(tag >> 2),
            2 => Self::Boolean(tag >> 2),
            _ => Self::Plain,
        }
    }
}
