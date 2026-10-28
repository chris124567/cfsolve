//! JavaScript values, conversions, and JSON serialization.
//!
//! All numbers use `f64`, so `1` and `1.0` are the same value. Assigning `undefined` to a
//! property preserves its position, but `JSON.stringify` omits it. A missing property reads as
//! `None` and converts as `undefined`.

use std::fmt;
use std::ops::Index;

use indexmap::IndexMap;
use ryu_js::Buffer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::numeric;

/// Object properties in insertion order. `JSON.stringify` preserves this order for keys that
/// are not array indices. Use `shift_remove` to remove a property or assign
/// [`JsValue::Undefined`] as the script does. `swap_remove` would change the remaining order.
pub type JsObject = IndexMap<String, JsValue>;

/// A JavaScript value represented by its contents, without object identity. Supports JSON
/// values, `undefined`, and non-finite numbers.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum JsValue {
    Undefined,
    #[default]
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsValue>),
    Object(JsObject),
}

/// Value returned when indexing a missing property.
static UNDEFINED: JsValue = JsValue::Undefined;

impl JsValue {
    #[must_use]
    pub fn is_undefined(&self) -> bool {
        matches!(self, Self::Undefined)
    }

    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    /// Returns the number if it is an integer exactly representable as `i64`.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        const LIMIT: f64 = 9_223_372_036_854_775_808.0;
        let value = self.as_f64()?;
        (value.fract() == 0.0 && (-LIMIT..LIMIT).contains(&value)).then_some(value as i64)
    }

    /// Returns the number if it is a nonnegative integer exactly representable as `u64`.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        const LIMIT: f64 = 18_446_744_073_709_551_616.0;
        let value = self.as_f64()?;
        (value.fract() == 0.0 && (0.0..LIMIT).contains(&value)).then_some(value as u64)
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&Vec<JsValue>> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<JsValue>> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_object(&self) -> Option<&JsObject> {
        match self {
            Self::Object(properties) => Some(properties),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_object_mut(&mut self) -> Option<&mut JsObject> {
        match self {
            Self::Object(properties) => Some(properties),
            _ => None,
        }
    }

    /// An object's property or an array's element; `None` if absent.
    #[must_use]
    pub fn get<P: Property>(&self, property: P) -> Option<&JsValue> {
        property.read(self)
    }

    /// `JSON.stringify(value)`, or `None` for `undefined`, which it does not serialize. Numbers
    /// are written as `Number.prototype.toString` writes them, and non-finite numbers and
    /// `undefined` elements as `null`.
    #[must_use]
    pub fn stringify(&self) -> Option<String> {
        if self.is_undefined() {
            return None;
        }
        let mut out = String::new();
        self.write_json(&mut out);
        Some(out)
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Self::Undefined | Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) if value.is_finite() => out.push_str(Buffer::new().format(*value)),
            Self::Number(_) => out.push_str("null"),
            Self::String(text) => quote(text, out),
            Self::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    value.write_json(out);
                }
                out.push(']');
            }
            Self::Object(properties) => write_object(properties, out),
        }
    }
}

/// [`JsValue::stringify`] for an object, which always has a serialization.
#[must_use]
pub(crate) fn stringify_object(properties: &JsObject) -> String {
    let mut out = String::new();
    write_object(properties, &mut out);
    out
}

/// Writes defined properties in JavaScript enumeration order: array-index keys in numeric
/// order, then other keys in insertion order. For example, `payload[40]` follows record 39 even
/// if it was added after named fields.
fn write_object(properties: &JsObject, out: &mut String) {
    // Array indices are below 2^32 - 1 and spelled canonically: no sign or leading zero.
    let index = |key: &str| {
        let index: u32 = key.parse().ok()?;
        (index != u32::MAX && index.to_string() == key).then_some(index)
    };
    let mut defined: Vec<_> = properties
        .iter()
        .filter(|(_, value)| !value.is_undefined())
        .collect();
    defined.sort_by_key(|(key, _)| index(key).unwrap_or(u32::MAX));
    out.push('{');
    for (position, (key, value)) in defined.into_iter().enumerate() {
        if position > 0 {
            out.push(',');
        }
        quote(key, out);
        out.push(':');
        value.write_json(out);
    }
    out.push('}');
}

/// `JSON.stringify`'s quoting: escapes only quotes, backslashes, and control characters, and
/// writes all other text as is.
fn quote(text: &str, out: &mut String) {
    use std::fmt::Write;

    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if control < ' ' => {
                write!(out, "\\u{:04x}", u32::from(control)).expect("writing to a String");
            }
            character => out.push(character),
        }
    }
    out.push('"');
}

/// A property name or array index accepted by [`JsValue::get`].
pub trait Property {
    fn read<'value>(&self, value: &'value JsValue) -> Option<&'value JsValue>;
}

impl Property for str {
    fn read<'value>(&self, value: &'value JsValue) -> Option<&'value JsValue> {
        value.as_object()?.get(self)
    }
}

impl Property for String {
    fn read<'value>(&self, value: &'value JsValue) -> Option<&'value JsValue> {
        self.as_str().read(value)
    }
}

impl Property for usize {
    fn read<'value>(&self, value: &'value JsValue) -> Option<&'value JsValue> {
        value.as_array()?.get(*self)
    }
}

impl<P: Property + ?Sized> Property for &P {
    fn read<'value>(&self, value: &'value JsValue) -> Option<&'value JsValue> {
        (**self).read(value)
    }
}

/// Reads a property as JavaScript does: a missing one is `undefined`.
impl<P: Property> Index<P> for JsValue {
    type Output = JsValue;

    fn index(&self, property: P) -> &JsValue {
        self.get(property).unwrap_or(&UNDEFINED)
    }
}

/// Writes the JSON serialization, or `undefined` if there is no JSON representation.
impl fmt::Display for JsValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stringify().as_deref().unwrap_or("undefined"))
    }
}

/// Serializes as JSON for files and reports. Integers are written without a fraction,
/// non-finite numbers and `undefined` elements as `null`, and `undefined` properties are left
/// out. Payloads on the wire use [`JsValue::stringify`].
impl Serialize for JsValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Integers beyond 2^53 may lose precision when converted to `f64`.
        const EXACT: f64 = 9_007_199_254_740_992.0;
        match self {
            Self::Undefined | Self::Null => serializer.serialize_unit(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Number(value) if value.fract() == 0.0 && value.abs() <= EXACT => {
                serializer.serialize_i64(*value as i64)
            }
            Self::Number(value) if value.is_finite() => serializer.serialize_f64(*value),
            Self::Number(_) => serializer.serialize_unit(),
            Self::String(text) => serializer.serialize_str(text),
            Self::Array(values) => serializer.collect_seq(values),
            Self::Object(properties) => {
                serializer.collect_map(properties.iter().filter(|(_, value)| !value.is_undefined()))
            }
        }
    }
}

/// Reads JSON as `JSON.parse` does: every number becomes an `f64`.
impl<'de> Deserialize<'de> for JsValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde_json::Value::deserialize(deserializer).map(Self::from)
    }
}

/// Builds a [`JsValue`] with `serde_json::json!`'s syntax.
macro_rules! json {
    ($($json:tt)+) => {
        $crate::js::JsValue::from(::serde_json::json!($($json)+))
    };
}
pub(crate) use json;

/// Deserializes `T` from a JavaScript value using the same rules as `serde_json::from_value`.
pub(crate) fn from_value<T: serde::de::DeserializeOwned>(value: JsValue) -> serde_json::Result<T> {
    serde_json::from_value(serde_json::Value::from(value))
}

impl From<serde_json::Value> for JsValue {
    fn from(value: serde_json::Value) -> Self {
        use serde_json::Value;
        match value {
            Value::Null => Self::Null,
            Value::Bool(value) => Self::Bool(value),
            Value::Number(number) => Self::Number(number.as_f64().unwrap_or(f64::NAN)),
            Value::String(text) => Self::String(text),
            Value::Array(values) => Self::Array(values.into_iter().map(Self::from).collect()),
            Value::Object(properties) => Self::Object(
                properties
                    .into_iter()
                    .map(|(key, value)| (key, Self::from(value)))
                    .collect(),
            ),
        }
    }
}

impl From<JsValue> for serde_json::Value {
    fn from(value: JsValue) -> Self {
        serde_json::to_value(value).expect("every JsValue serializes")
    }
}

impl From<bool> for JsValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

macro_rules! from_number {
    ($($number:ty),*) => {$(
        impl From<$number> for JsValue {
            fn from(value: $number) -> Self {
                Self::Number(value as f64)
            }
        }

        impl PartialEq<$number> for JsValue {
            fn eq(&self, other: &$number) -> bool {
                self.as_f64() == Some(*other as f64)
            }
        }
    )*};
}
from_number!(f64, i32, i64, u64, usize);

impl From<&str> for JsValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for JsValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<JsObject> for JsValue {
    fn from(properties: JsObject) -> Self {
        Self::Object(properties)
    }
}

impl<T: Into<JsValue>> FromIterator<T> for JsValue {
    fn from_iter<I: IntoIterator<Item = T>>(values: I) -> Self {
        Self::Array(values.into_iter().map(Into::into).collect())
    }
}

impl PartialEq<bool> for JsValue {
    fn eq(&self, other: &bool) -> bool {
        matches!(self, Self::Bool(value) if value == other)
    }
}

impl PartialEq<str> for JsValue {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Some(other)
    }
}

impl PartialEq<&str> for JsValue {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Some(*other)
    }
}

impl PartialEq<String> for JsValue {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == Some(other.as_str())
    }
}

/// A thrown undefined value, JSON value, plain object, or Error. Includes inherited exception
/// properties such as `DOMException.code`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ErrorValue {
    Undefined,
    Value {
        value: JsValue,
    },
    Object {
        tag: String,
        properties: JsObject,
    },
    Exception {
        name: String,
        message: String,
        #[serde(default)]
        properties: JsObject,
    },
}

/// Applies `String(value)`, using `None` for an absent property. Arrays join elements with
/// commas and render null and undefined elements as empty strings.
#[must_use]
pub(crate) fn string(value: Option<&JsValue>) -> String {
    match value {
        None | Some(JsValue::Undefined) => "undefined".into(),
        Some(JsValue::Null) => "null".into(),
        Some(JsValue::Bool(value)) => value.to_string(),
        Some(JsValue::Number(value)) => Buffer::new().format(*value).to_owned(),
        Some(JsValue::String(value)) => value.clone(),
        Some(JsValue::Object(_)) => "[object Object]".into(),
        Some(JsValue::Array(values)) => {
            let elements: Vec<String> = values
                .iter()
                .map(|value| match value {
                    JsValue::Undefined | JsValue::Null => String::new(),
                    value => string(Some(value)),
                })
                .collect();
            elements.join(",")
        }
    }
}

/// `Number(value)`, with `None` standing for an absent property.
#[must_use]
pub(crate) fn number(value: Option<&JsValue>) -> f64 {
    match value {
        None | Some(JsValue::Undefined | JsValue::Object(_)) => f64::NAN,
        Some(JsValue::Null) => 0.0,
        Some(JsValue::Bool(value)) => f64::from(u8::from(*value)),
        Some(JsValue::Number(value)) => *value,
        Some(JsValue::Array(_)) => numeric::string_number(&string(value)),
        Some(JsValue::String(text)) => numeric::string_number(text),
    }
}

/// Tests JavaScript truthiness. Arrays and objects are truthy even when empty; `NaN` is falsy.
#[must_use]
pub(crate) fn truthy(value: &JsValue) -> bool {
    match value {
        JsValue::Undefined | JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    }
}

/// Deserializes any present property, including `null`, as `Some`. With `#[serde(default,
/// deserialize_with = "js::present")]`, absence remains `None` (`undefined`).
pub(crate) fn present<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<JsValue>, D::Error> {
    JsValue::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_follows_javascript_conversion() {
        assert_eq!(string(None), "undefined");
        assert_eq!(string(Some(&JsValue::Undefined)), "undefined");
        assert_eq!(string(Some(&JsValue::Null)), "null");
        assert_eq!(string(Some(&json!(1e21))), "1e+21");
        assert_eq!(string(Some(&json!(0.1))), "0.1");
        assert_eq!(string(Some(&json!(2.0))), "2");
        assert_eq!(string(Some(&json!([null, "a", [1, 2]]))), ",a,1,2");
        assert_eq!(string(Some(&json!({}))), "[object Object]");
    }

    /// More string cases are in [`numeric::string_number`]'s tests.
    #[test]
    fn numeric_coercion_follows_string_to_number() {
        assert!(number(None).is_nan());
        assert!(number(Some(&JsValue::Undefined)).is_nan());
        assert_eq!(number(Some(&JsValue::Null)), 0.0);
        assert_eq!(number(Some(&json!(" \u{feff}12 "))), 12.0);
        assert_eq!(number(Some(&json!([7]))), 7.0);
        assert!(number(Some(&json!({}))).is_nan());
    }

    #[test]
    fn empty_arrays_and_objects_are_truthy() {
        for value in [json!([]), json!({}), json!("0"), json!(-1)] {
            assert!(truthy(&value), "{value}");
        }
        let falsy = [
            JsValue::Undefined,
            JsValue::Null,
            json!(false),
            json!(0),
            json!(-0.0),
            JsValue::Number(f64::NAN),
            json!(""),
        ];
        for value in falsy {
            assert!(!truthy(&value), "{value}");
        }
    }

    #[test]
    fn present_properties_distinguish_null_from_absent() {
        #[derive(Deserialize)]
        struct Holder {
            #[serde(default, deserialize_with = "present")]
            value: Option<JsValue>,
        }
        let read = |text| serde_json::from_str::<Holder>(text).unwrap().value;
        assert_eq!(read("{}"), None);
        assert_eq!(read(r#"{"value":null}"#), Some(JsValue::Null));
    }

    /// Integers and floats parse to one number, as `JSON.parse` reads them.
    #[test]
    fn numbers_are_doubles() {
        let parsed: JsValue = serde_json::from_str(r#"[1, 1.0, -0, 1e2]"#).unwrap();
        assert_eq!(parsed, json!([1.0, 1, 0, 100]));
        assert_eq!(parsed[0], 1);
        assert_eq!(parsed[1].as_u64(), Some(1));
        assert_eq!(json!(1.5).as_i64(), None);
        assert_eq!(json!(-1).as_u64(), None);
    }

    #[test]
    fn stringify_writes_what_chrome_writes() {
        for (value, expected) in [
            (json!({"b": 1, "a": 2.0}), r#"{"b":1,"a":2}"#),
            (
                json!([1.5, -0.0, 1e21, 1e-7, 123_456_789_012.0]),
                "[1.5,0,1e+21,1e-7,123456789012]",
            ),
            (JsValue::Number(f64::NAN), "null"),
            (json!([JsValue::Number(f64::INFINITY)]), "[null]"),
            (
                json!("q\"\\\u{8}\t\n\u{c}\r\u{1}é"),
                r#""q\"\\\b\t\n\f\r\u0001é""#,
            ),
            // `undefined` properties are left out and `undefined` elements written as `null`.
            (
                JsValue::Object(JsObject::from_iter([
                    ("a".to_owned(), JsValue::Undefined),
                    ("b".to_owned(), json!(1)),
                ])),
                r#"{"b":1}"#,
            ),
            (
                JsValue::Array(vec![JsValue::Undefined, json!(1)]),
                "[null,1]",
            ),
            // Array indices come first, as in a payload whose newest record was added last.
            (
                json!({"1": 1, "counter": 2, "10": 10, "01": 0, "2": 2, "": 3, "4294967295": 4}),
                r#"{"1":1,"2":2,"10":10,"counter":2,"01":0,"":3,"4294967295":4}"#,
            ),
        ] {
            assert_eq!(value.stringify().as_deref(), Some(expected), "{value:?}");
        }
        assert_eq!(JsValue::Undefined.stringify(), None);
    }

    #[test]
    fn missing_properties_read_as_undefined() {
        assert_eq!(json!({"a": 1})["missing"], JsValue::Undefined);
        assert_eq!(json!([1])[1], JsValue::Undefined);
    }

    /// Files keep integers without a fraction, so they read back unchanged.
    #[test]
    fn serializes_integers_as_integers() {
        let value = JsValue::Object(JsObject::from_iter([
            ("count".to_owned(), JsValue::Number(3.0)),
            ("ratio".to_owned(), JsValue::Number(0.5)),
            ("unset".to_owned(), JsValue::Undefined),
            ("nan".to_owned(), JsValue::Number(f64::NAN)),
        ]));
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"count":3,"ratio":0.5,"nan":null}"#
        );
    }
}
