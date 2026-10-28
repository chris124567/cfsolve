//! JavaScript support shared across the crate: syntax helpers, numeric conversions, value
//! semantics, and the challenge's typed objects.

pub(crate) mod ast;
mod numeric;
mod objects;
mod value;

pub(crate) use numeric::{
    bit_and, bit_not, bit_or, bit_xor, int32, shl, shr, string_number, uint32, ushr,
};
pub use objects::{Options, Payload, Window};
pub(crate) use value::{
    ErrorValue, from_value, json, number, present, string, stringify_object, truthy,
};
pub use value::{JsObject, JsValue};
