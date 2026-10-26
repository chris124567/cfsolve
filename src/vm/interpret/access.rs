//! Reads and writes properties on VM state and JavaScript values.

use std::borrow::Cow;
use std::rc::Rc;

use super::builtin::{self, Builtin};
use super::run::{Evaluation, Run, Stop};
use super::semantics;
use crate::js;
use crate::vm::convert::{self, MAXIMUM_LENGTH};
use crate::vm::output::{Constant, Effect, Term};
use crate::vm::value::{Callable, JsString, Value};

/// A property key with text retained for named-property lookup.
#[derive(Clone)]
pub(super) enum Key<'key, 'ast> {
    Name(Cow<'key, str>),
    /// Other keys: numbers, symbols, lone-surrogate strings with no usable name, or
    /// register-dependent values.
    Value(Value<'ast>),
}

impl<'ast> From<Value<'ast>> for Key<'_, 'ast> {
    fn from(value: Value<'ast>) -> Self {
        match &value {
            Value::String(string) => match string.text() {
                Some(text) => Self::Name(Cow::Owned(text)),
                None => Self::Value(value),
            },
            _ => Self::Value(value),
        }
    }
}

impl<'key> Key<'key, '_> {
    pub(super) fn name(name: &'key str) -> Self {
        Self::Name(Cow::Borrowed(name))
    }

    fn text(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            Self::Value(_) => None,
        }
    }

    /// Numeric key after JavaScript's `ToNumber` conversion.
    fn number(&self) -> Option<f64> {
        match self {
            Self::Name(name) => Some(js::string_number(name)),
            Self::Value(value) => value.number(),
        }
    }

    /// The key as property-name text (see [`semantics::property_key`]).
    pub(super) fn property(&self) -> Option<String> {
        match self {
            Self::Name(name) => Some(name.clone().into_owned()),
            Self::Value(value) => semantics::property_key(value),
        }
    }

    fn expr(&self) -> Term {
        match self {
            Self::Name(name) => Term::Const(Constant::String(name.clone().into_owned())),
            Self::Value(value) => value.expr(),
        }
    }
}

impl<'ast> Run<'ast, '_> {
    pub(super) fn get(
        &mut self,
        object: &Value<'ast>,
        key: &Key<'_, 'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let name = key.text();
        // Arrays and strings interpret string keys as numbers only when canonically spelled.
        // Lone-surrogate keys have no usable name and produce NaN here.
        let index = match key {
            Key::Name(_) => None,
            Key::Value(value) => value.number(),
        };
        Ok(match object {
            Value::Registers => {
                let register = self.register(key)?;
                match self.registers.get(&register) {
                    Some(value) => value.clone(),
                    None => Value::symbolic(Term::Reg(register)),
                }
            }
            Value::Program => match (index, name) {
                (Some(index), _) => convert::index(index)
                    .and_then(|index| self.program.get(index))
                    .map_or(Value::Undefined, |byte| Value::Number(f64::from(*byte))),
                (None, Some("length")) => Value::Number(self.program.len() as f64),
                _ => return Err(unsupported("program member", key)),
            },
            Value::Machine => match (key, name) {
                (Key::Value(Value::Symbol(symbol)), _)
                    if self
                        .session
                        .program_key
                        .as_ref()
                        .is_some_and(|key| Rc::ptr_eq(key, symbol)) =>
                {
                    Value::Program
                }
                (_, Some(name)) => match self.session.state.get(name) {
                    Some(value) => value.clone(),
                    None => self.field(name),
                },
                _ => return Err(unsupported("machine member", key)),
            },
            // A page's realm has the same builtins; only the document differs.
            Value::Namespace(path) => match name {
                Some("document") if path.is_empty() => Value::Undefined,
                Some(name) => builtin::member(path, name),
                None => return Err(unsupported("global member", key)),
            },
            Value::Cache => self.cached(index).unwrap_or(Value::Undefined),
            Value::Cells => match (index.and_then(convert::position), name) {
                (Some(index), _) => Value::Cell(index),
                (None, Some(_)) => {
                    Value::symbolic(Term::Get(Box::new(Term::Cells), Box::new(key.expr())))
                }
                _ => return Err(unsupported("cells member", key)),
            },
            // A cell is an object holding one value, under whichever name
            // the script gives it.
            Value::Cell(cell) => match name {
                Some(_) => Value::symbolic(Term::Cell(*cell)),
                None => return Err(unsupported("cell member", key)),
            },
            Value::Array(elements) => match (index.or_else(|| key_index(name?)), name) {
                // Any other number names a property no array here has.
                (Some(index), _) => convert::index(index)
                    .and_then(|index| elements.borrow().get(index).cloned())
                    .unwrap_or(Value::Undefined),
                (None, Some("length")) => Value::Number(elements.borrow().len() as f64),
                (None, Some(method)) => builtin::method("Array.prototype", method)
                    .ok_or_else(|| Stop::unsupported(&format!("array method {method}")))?,
                _ => return Err(unsupported("array member", key)),
            },
            Value::String(string) => match (index.or_else(|| key_index(name?)), name) {
                (Some(index), _) => convert::index(index)
                    .and_then(|index| string.unit(index))
                    .map_or(Value::Undefined, |unit| {
                        Value::String(JsString::from(vec![unit]))
                    }),
                (None, Some("length")) => Value::Number(string.len() as f64),
                (None, Some("charCodeAt")) => {
                    Value::function(Callable::Builtin(Builtin::CharCodeAt))
                }
                (None, Some(method)) if STRING_MEMBERS.contains(&method) => {
                    return Err(Stop::unsupported(&format!("string method {method}")));
                }
                // The property is absent on strings, but a handler may still try to call it,
                // such as reading `call` from a name string.
                (None, Some(_)) => Value::Undefined,
                _ => return Err(unsupported("string member", key)),
            },
            Value::Object(properties) => {
                let name = key
                    .property()
                    .ok_or_else(|| unsupported("object key", key))?;
                properties
                    .borrow()
                    .iter()
                    .find(|(key, _)| **key == *name)
                    .map_or(Value::Undefined, |(_, value)| value.clone())
            }
            Value::Set(_) => match name.and_then(|name| builtin::method("Set.prototype", name)) {
                Some(method) => method,
                None => return Err(unsupported("set member", key)),
            },
            Value::Function(function) => match (&**function, name) {
                (_, Some("call")) => Value::function(Callable::Call(object.clone())),
                (_, Some("apply")) => Value::function(Callable::Apply(object.clone())),
                (_, Some("bind")) => Value::function(Callable::Bind(object.clone())),
                (Callable::Builtin(function), Some(name)) => builtin::member(function.path(), name),
                (Callable::Standard(path), Some(name)) => builtin::member(path, name),
                _ => return Err(unsupported("function member", key)),
            },
            Value::Symbolic(expr) => match (&**expr, name) {
                (Term::Global(path), Some(name)) => builtin::member(path, name),
                (_, Some("call")) => Value::function(Callable::Call(object.clone())),
                (_, Some("apply")) => Value::function(Callable::Apply(object.clone())),
                _ => Value::symbolic(Term::Get(Box::new((**expr).clone()), Box::new(key.expr()))),
            },
            Value::Undefined | Value::Null => {
                let key = key.expr();
                return Err(Stop::throw(Value::string(&format!(
                    "TypeError: reading {key}"
                ))));
            }
            Value::Bool(_) | Value::Number(_) | Value::Symbol(_) => {
                return Err(unsupported("member of a primitive", key));
            }
        })
    }

    pub(super) fn set(
        &mut self,
        object: &Value<'ast>,
        key: &Key<'_, 'ast>,
        value: Value<'ast>,
    ) -> Evaluation<'ast, ()> {
        let layout = self.session.layout;
        match object {
            Value::Registers => {
                let register = self.register(key)?;
                if register != layout.pc && register != layout.key {
                    self.effects.push(Effect::Set(register, value.expr()));
                }
                self.set_register(register, value);
            }
            Value::Cells => {
                let cell = key
                    .number()
                    .and_then(convert::position)
                    .ok_or_else(|| unsupported("cell index", key))?;
                self.effects.push(Effect::NewCell(cell));
            }
            Value::Cell(cell) => self.effects.push(Effect::SetCell(*cell, value.expr())),
            Value::Cache => self.cache(key, &value),
            Value::Machine => {
                let name = key
                    .text()
                    .ok_or_else(|| unsupported("machine member", key))?;
                self.set_field(name.to_owned(), value);
            }
            Value::Array(elements) => {
                let index = match key {
                    Key::Name(name) => key_index(name),
                    Key::Value(Value::String(_)) => None,
                    Key::Value(key) => key.number(),
                };
                let index = index
                    .and_then(convert::length)
                    .filter(|&index| index < MAXIMUM_LENGTH)
                    .ok_or_else(|| unsupported("array index", key))?;
                let mut elements = elements.borrow_mut();
                if elements.len() <= index {
                    elements.resize(index + 1, Value::Undefined);
                }
                elements[index] = value;
            }
            Value::Object(properties) => {
                let name = key
                    .property()
                    .ok_or_else(|| unsupported("object key", key))?;
                let mut properties = properties.borrow_mut();
                match properties
                    .iter_mut()
                    .find(|(existing, _)| **existing == *name)
                {
                    Some((_, slot)) => *slot = value,
                    None => properties.push((name, value)),
                }
            }
            Value::Symbolic(_) | Value::Namespace(_) => self.effects.push(Effect::SetProperty {
                object: Box::new(object.expr()),
                key: Box::new(key.expr()),
                value: Box::new(value.expr()),
            }),
            Value::Undefined | Value::Null => {
                let key = key.expr();
                return Err(Stop::throw(Value::string(&format!(
                    "TypeError: setting {key}"
                ))));
            }
            _ => return Err(unsupported("setting a member", key)),
        }
        Ok(())
    }

    /// Returns a decoded-string cache entry as a new array.
    fn cached(&self, index: Option<f64>) -> Option<Value<'ast>> {
        let slot = (self.handler?, convert::position(index?)?);
        let decoded = self.session.decoded.borrow();
        Some(Value::array(decoded.get(&slot)?.clone()))
    }

    /// Caches `value` at `key` only during handler execution and only when the entry is fully
    /// determined by program bytes.
    fn cache(&self, key: &Key<'_, 'ast>, value: &Value<'ast>) {
        let primitive = |value: &Value<'_>| {
            matches!(
                value,
                Value::Undefined
                    | Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::String(_)
            )
        };
        if let (Some(handler), Key::Value(index), Value::Array(entry)) = (self.handler, key, value)
            && let Some(index) = index.number().and_then(convert::position)
            && entry.borrow().iter().all(primitive)
        {
            let entry = entry.borrow().clone();
            self.session
                .decoded
                .borrow_mut()
                .insert((handler, index), entry);
        }
    }

    /// The register `key` names.
    fn register(&self, key: &Key<'_, 'ast>) -> Evaluation<'ast, u8> {
        match key {
            Key::Value(value) if !matches!(value, Value::String(_)) => {
                value.number().and_then(convert::byte)
            }
            _ => None,
        }
        .ok_or_else(|| unsupported("register index", key))
    }
}

/// Parses a canonical numeric property key so `a["0"]` matches `a[0]`. Noncanonical strings
/// such as `"01"` and `"-0"` remain named properties.
fn key_index(name: &str) -> Option<f64> {
    use swc_ecma_utils::number::ToJsString;

    // Most property keys are names rather than numeric strings.
    let first = name.bytes().next()?;
    if !(first.is_ascii_digit() || matches!(first, b'-' | b'I' | b'N')) {
        return None;
    }
    let number = js::string_number(name);
    (number.to_js_string() == name).then_some(number)
}

pub(super) fn unsupported<'a>(what: &str, key: &Key<'_, '_>) -> Box<Stop<'a>> {
    Stop::unsupported(&format!("{what} {}", key.expr()))
}

/// Properties strings inherit from `String.prototype` and `Object.prototype`.
const STRING_MEMBERS: &[&str] = &[
    "anchor",
    "at",
    "big",
    "blink",
    "bold",
    "charAt",
    "codePointAt",
    "concat",
    "constructor",
    "endsWith",
    "fixed",
    "fontcolor",
    "fontsize",
    "hasOwnProperty",
    "includes",
    "indexOf",
    "isPrototypeOf",
    "isWellFormed",
    "italics",
    "lastIndexOf",
    "link",
    "localeCompare",
    "match",
    "matchAll",
    "normalize",
    "padEnd",
    "padStart",
    "propertyIsEnumerable",
    "repeat",
    "replace",
    "replaceAll",
    "search",
    "slice",
    "small",
    "split",
    "startsWith",
    "strike",
    "sub",
    "substr",
    "substring",
    "sup",
    "toLocaleLowerCase",
    "toLocaleString",
    "toLocaleUpperCase",
    "toLowerCase",
    "toString",
    "toUpperCase",
    "toWellFormed",
    "trim",
    "trimEnd",
    "trimLeft",
    "trimRight",
    "trimStart",
    "valueOf",
    "__proto__",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];
