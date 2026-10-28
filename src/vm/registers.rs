//! The VM register file, whose `read` and `write` methods access 256 registers.
//!
//! Each value has a type tag and is masked by a rolling `state`. A digest updated on every write
//! determines the mask. Separate fields hold the program counter and dispatch key. Handlers access
//! registers through methods, direct tag and value writes, or the counter and key fields.
//!
//! The interpreter keeps the mask and digest at zero. Stored values are therefore unmasked, and
//! changing the mask has no effect. Member names match the current build.

use crate::js;

/// Meaning of a field or method on the register file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Member {
    /// Read methods: `read(index)` and `save(index)`. They differ only for closures.
    Read,
    /// Write methods: `write(index, value)` and `restore(index, value)`. They differ only for
    /// closures.
    Write,
    /// Rolling mask or the digest used to compute it.
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
            "read" | "save" => Self::Read,
            "write" | "restore" => Self::Write,
            "state" | "digest" | "I" | "J" => Self::Mask,
            "i" | "l" => Self::Integer,
            "h" => Self::Pc,
            "j" => Self::Key,
            "v" => Self::OtherPc,
            "u" => Self::OtherKey,
            "C" => Self::PcIndex,
            "D" => Self::KeyIndex,
            "values" => Self::Values,
            "H" => Self::Tags,
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

/// Decoding rule used by `read` for a value with `tag`, assuming a zero mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    /// Tag 1 stores an integer XORed with the tag's upper bits.
    Integer(i32),
    /// Tag 2 stores a boolean as a comparison with the tag's upper bits.
    Boolean(i32),
    /// Tag -4 stores an encrypted string record, decrypted by `read`.
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
