//! Reads and writes properties on VM state and JavaScript values.

use std::borrow::Cow;
use std::rc::Rc;

use swc_core::ecma::ast::BinaryOp;

use super::builtin::{self, Builtin};
use super::run::{Evaluation, Run, Stop};
use super::semantics;
use crate::js;
use crate::vm::convert::{self, MAXIMUM_LENGTH};
use crate::vm::output::{Constant, Effect, Term};
use crate::vm::registers::{Member, Slots, Stored};
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
            Value::Registers if let Some(member) = name.and_then(Member::of) => {
                self.register_member(member)
            }
            Value::Registers | Value::RegisterSlots(Slots::Values) => {
                self.register_value(self.register(key)?)
            }
            Value::RegisterSlots(Slots::Tags) => {
                let register = self.register(key)?;
                self.tags
                    .get(&register)
                    .cloned()
                    .ok_or_else(|| unsupported("tag of a register", key))?
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
                (Key::Value(Value::Symbol(symbol)), _) => {
                    let (_, field) = self
                        .session
                        .symbol_fields
                        .iter()
                        .find(|(key, _)| Rc::ptr_eq(key, symbol))
                        .ok_or_else(|| unsupported("machine member", key))?;
                    self.isolate(field)
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
                (None, Some("repeat")) => Value::function(Callable::Builtin(Builtin::Repeat)),
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
            Value::Map(_) => match name.and_then(|name| builtin::method("Map.prototype", name)) {
                Some(method) => method,
                None => return Err(unsupported("map member", key)),
            },
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
            Value::Registers => match key.text().and_then(Member::of) {
                Some(Member::Pc | Member::OtherPc) => self.set_register(layout.pc, value),
                Some(Member::Key | Member::OtherKey) => self.set_register(layout.key, value),
                // These fields have fixed values in the interpreter model.
                Some(Member::Mask | Member::Integer | Member::PcIndex | Member::KeyIndex) => {}
                Some(_) => return Err(unsupported("register file member", key)),
                None => self.write_register(self.register(key)?, value),
            },
            Value::RegisterSlots(Slots::Tags) => {
                let register = self.register(key)?;
                self.tags.insert(register, value);
            }
            // Value storage helpers write the tag before writing the value.
            Value::RegisterSlots(Slots::Values) => {
                let register = self.register(key)?;
                let tag = self.tags.remove(&register).and_then(|tag| tag.number());
                let tag = tag.map_or(Stored::Plain, Stored::of);
                let value = match (tag, &value) {
                    // `read` decrypts on every access, but caching the decrypted value has the same
                    // result. Values copied from another register were already decrypted when first
                    // stored.
                    (Stored::Record, Value::Array(_)) => self.decrypted(value)?,
                    (tag, _) => stored(tag, value),
                };
                self.write_register(register, value);
            }
            Value::Cells => {
                let cell = key
                    .number()
                    .and_then(convert::position)
                    .ok_or_else(|| unsupported("cell index", key))?;
                self.effects.push(Effect::NewCell(cell));
            }
            Value::Cell(cell) => self.effects.push(Effect::SetCell(*cell, value.expr())),
            Value::Machine => {
                let name = key
                    .text()
                    .ok_or_else(|| unsupported("machine member", key))?;
                self.set_field(name.to_owned(), value);
            }
            Value::Array(elements) if key.text() == Some("length") => {
                match value.number() {
                    Some(length) => {
                        let length = convert::length(length)
                            .filter(|&length| length < MAXIMUM_LENGTH)
                            .ok_or_else(|| unsupported("array length", key))?;
                        elements.borrow_mut().resize(length, Value::Undefined);
                    }
                    // An earlier instruction restored the stack length. Keep the known elements
                    // from this run; see `Builtin::Pop`.
                    None if value.is_symbolic() => {}
                    None => return Err(unsupported("array length", key)),
                }
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

    /// Returns the register value, using a symbolic value unless this run has assigned it.
    pub(super) fn register_value(&self, register: u8) -> Value<'ast> {
        match self.registers.get(&register) {
            Some(value) => self.refined(value),
            None => self.refined(&Value::symbolic(Term::Reg(register))),
        }
    }

    /// Sets a register, recording the write unless it moves the program counter or key.
    pub(super) fn write_register(&mut self, register: u8, value: Value<'ast>) {
        let layout = self.session.layout;
        if register != layout.pc && register != layout.key {
            self.effects.push(Effect::Set(register, value.expr()));
        }
        self.set_register(register, value);
    }

    /// Decrypts a string record using the same logic as the register file's `read` method.
    fn decrypted(&mut self, record: Value<'ast>) -> Evaluation<'ast, Value<'ast>> {
        let Value::Array(elements) = &record else {
            return Ok(record);
        };
        let field = |index: usize| elements.borrow().get(index).and_then(Value::number);
        let key = match (field(1), field(2), field(3)) {
            (Some(pc), Some(length), Some(key)) => Some((pc as u32, length as u32, key as u32)),
            _ => None,
        };
        if let Some(key) = key
            && let Some(text) = self.session.decrypted.borrow().get(&key)
        {
            return Ok(text.clone());
        }
        let decoder = self
            .session
            .record_decoder
            .as_ref()
            .ok_or_else(|| Stop::unsupported("an encrypted string with no decoder"))?;
        let decoder = self.lookup(decoder)?;
        let text = self.apply(decoder, Value::Undefined, vec![record])?;
        if let (Some(key), Value::String(_)) = (key, &text) {
            self.session
                .decrypted
                .borrow_mut()
                .insert(key, text.clone());
        }
        Ok(text)
    }

    /// A member of the register file (see [`Member`]).
    fn register_member(&self, member: Member) -> Value<'ast> {
        let layout = self.session.layout;
        match member {
            Member::Read => Value::function(Callable::Builtin(Builtin::RegisterRead)),
            Member::Write => Value::function(Callable::Builtin(Builtin::RegisterWrite)),
            Member::Mask => Value::Number(0.0),
            Member::Integer => Value::Number(1.0),
            Member::Pc => self.register_value(layout.pc),
            Member::Key => self.register_value(layout.key),
            Member::OtherPc | Member::OtherKey => Value::Undefined,
            Member::PcIndex => Value::Number(f64::from(layout.pc)),
            Member::KeyIndex => Value::Number(f64::from(layout.key)),
            Member::Values => Value::RegisterSlots(Slots::Values),
            Member::Tags => Value::RegisterSlots(Slots::Tags),
        }
    }

    /// Resolves the register index identified by `key`.
    pub(super) fn register(&self, key: &Key<'_, 'ast>) -> Evaluation<'ast, u8> {
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

/// Decodes `value` stored with `tag`, matching the value returned by the register reader.
fn stored(tag: Stored, value: Value<'_>) -> Value<'_> {
    match tag {
        Stored::Integer(upper) => {
            semantics::binary_value(BinaryOp::BitXor, Value::Number(f64::from(upper)), value)
        }
        Stored::Boolean(upper) => {
            let bits =
                semantics::binary_value(BinaryOp::BitXor, value, Value::Number(f64::from(upper)));
            semantics::binary_value(BinaryOp::NotEqEq, bits, Value::Number(0.0))
        }
        Stored::Plain | Stored::Record => value,
    }
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
