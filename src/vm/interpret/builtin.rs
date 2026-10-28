//! Standard-library functions used by handlers and the global paths exposing them.

use std::cell::RefCell;
use std::rc::Rc;

use swc_ecma_utils::number::JsNumber;

use super::access::Key;
use super::run::{Evaluation, Run, Stop};
use super::semantics;
use crate::js;
use crate::vm::convert;
use crate::vm::output::{Constant, Term};
use crate::vm::value::{Callable, JsString, Value};

/// Defines builtins and global paths in one list. [`Builtin::path`] maps builtins to paths;
/// [`member`] resolves paths to builtins.
macro_rules! builtins {
    ($($(#[$attribute:meta])* $builtin:ident => $path:literal,)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum Builtin {
            $($(#[$attribute])* $builtin,)*
        }

        /// Standard-library functions supported by the interpreter, identified by global path.
        const BUILTINS: &[(Builtin, &str)] = &[$((Builtin::$builtin, $path),)*];

        impl Builtin {
            /// Returns the function's path from the global object.
            #[must_use]
            pub(crate) fn path(self) -> &'static str {
                match self {
                    $(Self::$builtin => $path,)*
                }
            }
        }
    };
}

builtins! {
    FromCharCode => "String.fromCharCode",
    Join => "Array.prototype.join",
    Slice => "Array.prototype.slice",
    Push => "Array.prototype.push",
    Pop => "Array.prototype.pop",
    IsArray => "Array.isArray",
    CharCodeAt => "String.prototype.charCodeAt",
    Repeat => "String.prototype.repeat",
    /// `Function.prototype.call`, `apply`, and `bind`, plus `Reflect.apply` and
    /// `Reflect.construct`.
    Call => "Function.prototype.call",
    Apply => "Function.prototype.apply",
    Bind => "Function.prototype.bind",
    ReflectApply => "Reflect.apply",
    Construct => "Reflect.construct",
    Pow => "Math.pow",
    Min => "Math.min",
    Max => "Math.max",
    Floor => "Math.floor",
    Array => "Array",
    From => "Array.from",
    Error => "Error",
    RegExp => "RegExp",
    Symbol => "Symbol",
    /// `Set` and `WeakSet`, and their methods.
    Set => "Set",
    Has => "Set.prototype.has",
    Add => "Set.prototype.add",
    Delete => "Set.prototype.delete",
    /// `Map` and `WeakMap`, and their methods.
    Map => "Map",
    MapGet => "Map.prototype.get",
    MapSet => "Map.prototype.set",
    MapHas => "Map.prototype.has",
    MapDelete => "Map.prototype.delete",
    /// Typed arrays are modeled as empty objects because the script only uses them to cache values
    /// it can recompute.
    Int32Array => "Int32Array",
    /// The register file's `read` and `write` methods (see [`crate::vm::registers`]).
    RegisterRead => "registers.read",
    RegisterWrite => "registers.write",
}

impl<'ast> Run<'ast, '_> {
    pub(super) fn builtin(
        &mut self,
        builtin: Builtin,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        // A call with a register-dependent result.
        let symbolic = |run: &mut Self, callee: Term| {
            Ok(run.temp(Term::Call {
                callee: Box::new(callee),
                this: None,
                arguments: arguments.iter().map(Value::expr).collect(),
            }))
        };
        let global = || Term::Global(builtin.path().into());
        let numbers = || -> Evaluation<'ast, Vec<f64>> {
            arguments
                .iter()
                .map(|argument| {
                    argument.number().ok_or_else(|| {
                        Stop::unsupported(&format!("{} of {}", builtin.path(), argument.expr()))
                    })
                })
                .collect()
        };
        // A missing argument is `undefined`.
        let argument = |index: usize| arguments.get(index).cloned().unwrap_or(Value::Undefined);
        let registers_decide = arguments.iter().any(Value::is_symbolic);
        match builtin {
            Builtin::FromCharCode if registers_decide => symbolic(self, global()),
            Builtin::FromCharCode => {
                let units: JsString = numbers()?
                    .into_iter()
                    .map(|code| js::uint32(code) as u16)
                    .collect();
                Ok(Value::String(units))
            }
            Builtin::Join => {
                let Value::Array(elements) = this else {
                    return Err(Stop::unsupported(&format!("join of {}", this.expr())));
                };
                let separator = match argument(0) {
                    Value::Undefined => JsString::from(","),
                    separator => text_units(&separator)?,
                };
                let elements = elements.borrow();
                let mut units = Vec::new();
                for (index, element) in elements.iter().enumerate() {
                    if index > 0 {
                        units.extend_from_slice(separator.units());
                    }
                    match element {
                        Value::Undefined | Value::Null => {}
                        element => units.extend_from_slice(text_units(element)?.units()),
                    }
                }
                Ok(Value::String(units.into()))
            }
            Builtin::Repeat => {
                let (Value::String(string), Some(count)) = (&this, argument(0).number()) else {
                    return symbolic(self, global());
                };
                let count = convert::length(count)
                    .filter(|&count| count.saturating_mul(string.len()) <= convert::MAXIMUM_LENGTH)
                    .ok_or_else(|| Stop::unsupported(&format!("repeating {count} times")))?;
                Ok(Value::String(JsString::from(string.units().repeat(count))))
            }
            Builtin::CharCodeAt => {
                let method = || {
                    let name = Term::Const(Constant::String("charCodeAt".into()));
                    Term::Get(Box::new(this.expr()), Box::new(name))
                };
                let string = match &this {
                    Value::String(string) if !registers_decide => string,
                    _ if registers_decide || this.is_symbolic() => return symbolic(self, method()),
                    _ => return Err(Stop::unsupported(&format!("charCodeAt of {}", this.expr()))),
                };
                // `ToIntegerOrInfinity` converts NaN and `undefined` to index 0.
                let index = argument(0).number().map_or(0.0, |index| {
                    if index.is_nan() { 0.0 } else { index.trunc() }
                });
                let unit = (index >= 0.0)
                    .then(|| string.unit(index as usize))
                    .flatten();
                Ok(Value::Number(unit.map_or(f64::NAN, f64::from)))
            }
            Builtin::Call => self.invoke(&Callable::Call(this), Value::Undefined, arguments),
            Builtin::Apply => self.invoke(&Callable::Apply(this), Value::Undefined, arguments),
            Builtin::Bind => self.invoke(&Callable::Bind(this), Value::Undefined, arguments),
            Builtin::ReflectApply => {
                let mut arguments = arguments.into_iter();
                let target = arguments.next().unwrap_or(Value::Undefined);
                let rest: Vec<Value<'ast>> = arguments.collect();
                self.invoke(&Callable::Apply(target), Value::Undefined, rest)
            }
            Builtin::Construct => {
                let target = argument(0);
                match argument(1) {
                    Value::Array(list) => {
                        let list = list.borrow().clone();
                        self.construct(target, list)
                    }
                    list => Err(Stop::unsupported(&format!(
                        "constructing over {}",
                        list.expr()
                    ))),
                }
            }
            Builtin::Slice => {
                let Value::Array(elements) = &this else {
                    return self.apply(Value::symbolic(global()), this, arguments);
                };
                let elements = elements.borrow();
                let length = elements.len() as f64;
                // `ToIntegerOrInfinity` interprets negative bounds relative to the end.
                let bound = |value: Value<'ast>, default: f64| -> Evaluation<'ast, usize> {
                    let value = match value {
                        Value::Undefined => default,
                        value => value.number().ok_or_else(|| {
                            Stop::unsupported(&format!("slice at {}", value.expr()))
                        })?,
                    };
                    let value = if value.is_nan() { 0.0 } else { value.trunc() };
                    let value = if value < 0.0 { length + value } else { value };
                    Ok(value.clamp(0.0, length) as usize)
                };
                let start = bound(argument(0), 0.0)?;
                let end = bound(argument(1), length)?;
                Ok(Value::array(elements[start..end.max(start)].to_vec()))
            }
            Builtin::Push => {
                let Value::Array(elements) = &this else {
                    return self.apply(Value::symbolic(global()), this, arguments);
                };
                let mut elements = elements.borrow_mut();
                elements.extend(arguments);
                Ok(Value::Number(elements.len() as f64))
            }
            // Handlers start with constructor-created stacks that earlier instructions may have
            // filled. Popping beyond values pushed in this run returns a value from an earlier
            // instruction.
            Builtin::Pop => {
                let Value::Array(elements) = &this else {
                    return self.apply(Value::symbolic(global()), this, arguments);
                };
                let popped = elements.borrow_mut().pop();
                match popped {
                    Some(value) => Ok(value),
                    None => symbolic(self, global()),
                }
            }
            Builtin::IsArray => match argument(0) {
                Value::Array(_) => Ok(Value::Bool(true)),
                value if value.is_symbolic() => symbolic(self, global()),
                _ => Ok(Value::Bool(false)),
            },
            Builtin::Pow | Builtin::Min | Builtin::Max | Builtin::Floor if registers_decide => {
                symbolic(self, global())
            }
            Builtin::Pow => {
                let values = numbers()?;
                let value = |index: usize| values.get(index).copied().unwrap_or(f64::NAN);
                Ok(Value::Number(
                    *JsNumber::from(value(0)).pow(value(1).into()),
                ))
            }
            Builtin::Floor => {
                let value = numbers()?.first().copied().unwrap_or(f64::NAN);
                Ok(Value::Number(value.floor()))
            }
            Builtin::Min | Builtin::Max => {
                let values = numbers()?;
                // Except for NaN, `total_cmp` matches this numeric ordering, including -0
                // before +0.
                let value = if values.iter().any(|value| value.is_nan()) {
                    f64::NAN
                } else if builtin == Builtin::Min {
                    let minimum = values.into_iter().min_by(f64::total_cmp);
                    minimum.unwrap_or(f64::INFINITY)
                } else {
                    let maximum = values.into_iter().max_by(f64::total_cmp);
                    maximum.unwrap_or(f64::NEG_INFINITY)
                };
                Ok(Value::Number(value))
            }
            Builtin::Array => match arguments.as_slice() {
                [Value::Number(length)] => match convert::length(*length) {
                    Some(length) => Ok(Value::array(vec![Value::Undefined; length])),
                    None if convert::position(*length).is_some() => {
                        Err(Stop::unsupported(&format!("an array of {length} elements")))
                    }
                    None => Err(Stop::throw(Value::string(&format!(
                        "RangeError: invalid array length {length}"
                    )))),
                },
                [length] if length.is_symbolic() => symbolic(self, global()),
                _ => Ok(Value::array(arguments)),
            },
            Builtin::From => {
                let elements: Vec<Value<'ast>> = match argument(0) {
                    Value::Array(elements) => elements.borrow().clone(),
                    source @ Value::Object(_) => {
                        let length = self.get(&source, &Key::name("length"))?;
                        let length =
                            length.number().and_then(convert::length).ok_or_else(|| {
                                let length = length.expr();
                                Stop::unsupported(&format!("Array.from of length {length}"))
                            })?;
                        (0..length)
                            .map(|index| {
                                self.get(&source, &Key::Value(Value::Number(index as f64)))
                            })
                            .collect::<Evaluation<'ast, _>>()?
                    }
                    source => {
                        return Err(Stop::unsupported(&format!(
                            "Array.from of {}",
                            source.expr()
                        )));
                    }
                };
                let map = match argument(1) {
                    Value::Undefined => return Ok(Value::array(elements)),
                    map => map,
                };
                let mut mapped = Vec::with_capacity(elements.len());
                for (index, element) in elements.into_iter().enumerate() {
                    let index = Value::Number(index as f64);
                    mapped.push(self.apply(map.clone(), Value::Undefined, vec![element, index])?);
                }
                Ok(Value::array(mapped))
            }
            Builtin::Symbol => Ok(Value::Symbol(Rc::new(()))),
            Builtin::Int32Array => Ok(Value::Object(Rc::default())),
            Builtin::RegisterRead => {
                let register = self.register(&Key::from(argument(0)))?;
                Ok(self.register_value(register))
            }
            Builtin::RegisterWrite => {
                let register = self.register(&Key::from(argument(0)))?;
                let value = argument(1);
                self.write_register(register, value.clone());
                Ok(value)
            }
            Builtin::Set => match argument(0) {
                Value::Undefined | Value::Null => Ok(Value::Set(Rc::default())),
                Value::Array(elements) => {
                    let elements = elements.borrow();
                    let mut members = Vec::new();
                    for element in elements.iter() {
                        // Retain register-dependent members. Possible duplicates do not affect
                        // the supported set operations.
                        if contains(&members, element) != Some(true) {
                            members.push(element.clone());
                        }
                    }
                    Ok(Value::Set(Rc::new(RefCell::new(members))))
                }
                source => Err(Stop::unsupported(&format!("a set of {}", source.expr()))),
            },
            Builtin::Has | Builtin::Add | Builtin::Delete => {
                let Value::Set(members) = &this else {
                    return self.apply(Value::symbolic(global()), this, arguments);
                };
                let key = argument(0);
                match builtin {
                    // Objects in the machine's validation sets were checked when created.
                    Builtin::Has
                        if matches!(
                            key,
                            Value::Machine | Value::Registers | Value::Program | Value::Cells
                        ) =>
                    {
                        Ok(Value::Bool(true))
                    }
                    Builtin::Has => match contains(&members.borrow(), &key) {
                        Some(contained) => Ok(Value::Bool(contained)),
                        None => {
                            let has = Term::Const(Constant::String("has".into()));
                            symbolic(self, Term::Get(Box::new(this.expr()), Box::new(has)))
                        }
                    },
                    Builtin::Add => {
                        if contains(&members.borrow(), &key) == Some(false) {
                            members.borrow_mut().push(key);
                        }
                        Ok(this.clone())
                    }
                    _ => {
                        let mut members = members.borrow_mut();
                        let before = members.len();
                        members.retain(|member| {
                            semantics::same_value_zero(member, &key) != Some(true)
                        });
                        Ok(Value::Bool(members.len() < before))
                    }
                }
            }
            Builtin::Map => match argument(0) {
                Value::Undefined | Value::Null => Ok(Value::Map(Rc::default())),
                source => Err(Stop::unsupported(&format!("a map of {}", source.expr()))),
            },
            // Handlers start with constructor-created maps, such as the program closure registry.
            // Earlier instructions may have filled them. Treat keys that depend on register values
            // as absent.
            Builtin::MapGet | Builtin::MapSet | Builtin::MapHas | Builtin::MapDelete => {
                let Value::Map(entries) = &this else {
                    return self.apply(Value::symbolic(global()), this, arguments);
                };
                let key = argument(0);
                let position = entries
                    .borrow()
                    .iter()
                    .position(|(member, _)| semantics::same_value_zero(member, &key) == Some(true));
                match builtin {
                    Builtin::MapGet => Ok(position.map_or(Value::Undefined, |position| {
                        entries.borrow()[position].1.clone()
                    })),
                    Builtin::MapHas => Ok(Value::Bool(position.is_some())),
                    Builtin::MapSet => {
                        let value = argument(1);
                        let mut entries = entries.borrow_mut();
                        match position {
                            Some(position) => entries[position].1 = value,
                            None => entries.push((key, value)),
                        }
                        Ok(this.clone())
                    }
                    _ => {
                        if let Some(position) = position {
                            entries.borrow_mut().remove(position);
                        }
                        Ok(Value::Bool(position.is_some()))
                    }
                }
            }
            Builtin::Error => Ok(Value::Object(Rc::new(RefCell::new(vec![(
                "name".into(),
                Value::string("Error"),
            )])))),
            Builtin::RegExp => Ok(Value::symbolic(Term::Call {
                callee: Box::new(global()),
                this: None,
                arguments: arguments.iter().map(Value::expr).collect(),
            })),
        }
    }
}

/// Tests membership using `SameValueZero`, unless the result depends on registers.
fn contains<'a>(members: &[Value<'a>], key: &Value<'a>) -> Option<bool> {
    let mut unknown = false;
    for member in members {
        match semantics::same_value_zero(member, key) {
            Some(true) => return Some(true),
            Some(false) => {}
            None => unknown = true,
        }
    }
    (!unknown).then_some(false)
}

/// Applies `ToString` when the value is determined by program bytes.
fn text_units<'a>(value: &Value<'a>) -> Evaluation<'a, JsString> {
    semantics::text(value).ok_or_else(|| match value {
        Value::Symbolic(_) => Stop::unsupported(&format!("joining {}", value.expr())),
        value => Stop::unsupported(&format!("text of {}", value.expr())),
    })
}

/// Resolves a builtin at `object.name` without constructing its full path.
fn builtin_at(object: &str, name: &str) -> Option<Builtin> {
    BUILTINS
        .iter()
        .find(|(_, path)| is_member(path, object, name))
        .map(|&(builtin, _)| builtin)
}

/// Resolves instance method `name` inherited from `prototype`.
pub(super) fn method<'a>(prototype: &str, name: &str) -> Option<Value<'a>> {
    builtin_at(prototype, name).map(|builtin| Value::function(Callable::Builtin(builtin)))
}

/// Resolves the global at `object.name`, or `name` when the object path is empty.
pub(super) fn member<'a>(object: &str, name: &str) -> Value<'a> {
    if let Some(builtin) = builtin_at(object, name) {
        return Value::function(Callable::Builtin(builtin));
    }
    let path = match object {
        "" => name.to_owned(),
        object => format!("{object}.{name}"),
    };
    match &*path {
        "WeakSet" => Value::function(Callable::Builtin(Builtin::Set)),
        "WeakMap" => Value::function(Callable::Builtin(Builtin::Map)),
        "Number.NaN" => Value::Number(f64::NAN),
        "Number.POSITIVE_INFINITY" => Value::Number(f64::INFINITY),
        "Number.NEGATIVE_INFINITY" => Value::Number(f64::NEG_INFINITY),
        "Atomics" | "Intl" | "JSON" | "Math" | "Reflect" => Value::Namespace(Rc::new(path)),
        _ if is_standard_function(&path) => Value::function(Callable::Standard(path)),
        _ => Value::symbolic(Term::Global(path)),
    }
}

/// Whether `path` is `object.name`, or `name` when `object` is empty.
fn is_member(path: &str, object: &str, name: &str) -> bool {
    match object {
        "" => path == name,
        object => {
            path.strip_prefix(object)
                .and_then(|rest| rest.strip_prefix('.'))
                == Some(name)
        }
    }
}

/// Checks for a function shared by every realm, as scripts do before trusting a realm's
/// builtins.
fn is_standard_function(path: &str) -> bool {
    match path.split_once('.') {
        None => CONSTRUCTORS.contains(&path),
        Some(("Reflect", _)) => true,
        Some(("Math", name)) => name.starts_with(|first: char| first.is_ascii_lowercase()),
        Some(_) => STATIC_FUNCTIONS.contains(&path),
    }
}

const CONSTRUCTORS: &[&str] = &[
    "Array",
    "ArrayBuffer",
    "BigInt",
    "Boolean",
    "DataView",
    "Date",
    "Error",
    "Float32Array",
    "Float64Array",
    "Function",
    "Int16Array",
    "Int32Array",
    "Int8Array",
    "Map",
    "Number",
    "Object",
    "Promise",
    "Proxy",
    "RangeError",
    "RegExp",
    "Set",
    "String",
    "Symbol",
    "TextDecoder",
    "TextEncoder",
    "TypeError",
    "Uint16Array",
    "Uint32Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "WeakMap",
    "WeakSet",
];

const STATIC_FUNCTIONS: &[&str] = &[
    "Array.from",
    "Array.isArray",
    "Array.of",
    "ArrayBuffer.isView",
    "Number.isFinite",
    "Number.isInteger",
    "Number.isNaN",
    "Object.assign",
    "Object.create",
    "Object.defineProperty",
    "Object.entries",
    "Object.freeze",
    "Object.getOwnPropertyDescriptor",
    "Object.getOwnPropertyNames",
    "Object.getPrototypeOf",
    "Object.keys",
    "Object.values",
    "String.fromCharCode",
];

#[cfg(test)]
mod tests {
    use swc_core::ecma::ast::BinaryOp;

    use super::super::{Run, semantics};
    use super::*;
    use crate::vm::session::Session;

    fn number(value: Evaluation<'_, Value<'_>>) -> f64 {
        match value {
            Ok(Value::Number(number)) => number,
            _ => panic!("not a number"),
        }
    }

    #[test]
    fn math_follows_javascript() {
        let session = Session::empty();
        let mut run = Run::method(&session);
        let mut call = |builtin, arguments: &[f64]| {
            let arguments = arguments.iter().copied().map(Value::Number).collect();
            number(run.builtin(builtin, Value::Undefined, arguments))
        };
        assert!(call(Builtin::Min, &[0.0, -0.0]).is_sign_negative());
        assert!(call(Builtin::Max, &[-0.0, 0.0]).is_sign_positive());
        assert!(call(Builtin::Max, &[1.0, f64::NAN, 2.0]).is_nan());
        assert_eq!(call(Builtin::Min, &[]), f64::INFINITY);
        assert!(call(Builtin::Pow, &[1.0, f64::INFINITY]).is_nan());
        assert!(call(Builtin::Pow, &[2.0]).is_nan());
        assert!(call(Builtin::Floor, &[]).is_nan());
    }

    /// Checks `SameValueZero` membership: the set contains 1, "1", NaN, and 0 after duplicate
    /// removal.
    #[test]
    fn a_set_keeps_each_member_once() {
        let session = Session::empty();
        let mut run = Run::method(&session);
        let source = [1.0, 1.0, f64::NAN, f64::NAN, 0.0, -0.0].map(Value::Number);
        let mut source = source.to_vec();
        source.insert(2, Value::string("1"));
        let Ok(Value::Set(members)) =
            run.builtin(Builtin::Set, Value::Undefined, vec![Value::array(source)])
        else {
            panic!("new Set of an array is not a set");
        };
        assert_eq!(members.borrow().len(), 4);
        let mut has = |key: f64| {
            let set = Value::Set(members.clone());
            let has = run.builtin(Builtin::Has, set, vec![Value::Number(key)]);
            matches!(has, Ok(Value::Bool(true)))
        };
        assert!(has(f64::NAN));
        assert!(has(-0.0));
        assert!(!has(2.0));
    }

    /// Checks that each builtin and its global path resolve to each other.
    #[test]
    fn every_builtin_is_found_at_its_path() {
        let builtin_of = |value: Value<'_>| match value {
            Value::Function(callable) => match *callable {
                Callable::Builtin(found) => Some(found),
                _ => None,
            },
            _ => None,
        };
        for &(builtin, path) in BUILTINS {
            assert_eq!(builtin_of(member("", path)), Some(builtin), "{path}");
            if let Some((object, name)) = path.rsplit_once('.') {
                let found = builtin_of(member(object, name));
                assert_eq!(
                    found,
                    Some(builtin),
                    "{path} is not found as member {name} of {object}"
                );
            }
            let value = Value::function(Callable::Builtin(builtin));
            assert_eq!(
                value.expr(),
                Term::Global(path.into()),
                "{path} does not print as its path"
            );
        }
        assert!(
            method("Array.prototype", "splice").is_none(),
            "an array method that is not a builtin is not followed"
        );
        assert!(
            matches!(member("", "Array.prototype.splice"), Value::Symbolic(_)),
            "what is not a builtin stays a global the registers decide"
        );
        let Value::Function(random) = member("Math", "random") else {
            panic!("Math.random is not a function");
        };
        assert!(
            matches!(&*random, Callable::Standard(path) if path == "Math.random"),
            "a standard function that is not a builtin is known to exist"
        );
    }

    /// Surrogate halves survive until `join` or `+` puts them together. Length, indexing, and
    /// `charCodeAt` operate on code units, and a string with a lone surrogate prints as units.
    #[test]
    fn strings_are_code_units() {
        let session = Session::empty();
        let mut run = Run::method(&session);
        let mut call = |builtin: Builtin, this, arguments| {
            let Ok(value) = run.builtin(builtin, this, arguments) else {
                panic!("{builtin:?} failed");
            };
            value
        };
        let halves = [55356.0, 56826.0, 55356.0, 56824.0].map(|unit| {
            call(
                Builtin::FromCharCode,
                Value::Undefined,
                vec![Value::Number(unit)],
            )
        });
        let joined = call(
            Builtin::Join,
            Value::array(halves.to_vec()),
            vec![Value::string("")],
        );
        let string = Value::String([0x61, 0xd83c, 0x62].into_iter().collect());
        let codes = [1.0, -1.0].map(|index| {
            call(
                Builtin::CharCodeAt,
                string.clone(),
                vec![Value::Number(index)],
            )
            .expr()
        });
        let sum = halves
            .into_iter()
            .reduce(|left, right| semantics::binary_value(BinaryOp::Add, left, right))
            .expect("there are four halves");
        for string in [joined, sum] {
            let text = semantics::text(&string).and_then(|text| text.text());
            assert_eq!(text.as_deref(), Some("🇺🇸"));
        }
        let mut read: Vec<String> = codes.iter().map(ToString::to_string).collect();
        read.push(string.expr().to_string());
        let keys = [
            Value::Number(1.0),
            Value::string("2"),
            Value::Number(3.0),
            Value::string("length"),
        ];
        for key in keys {
            let Ok(value) = run.get(&string, &Key::from(key)) else {
                panic!("reading a string member failed");
            };
            read.push(value.expr().to_string());
        }
        assert_eq!(
            read,
            [
                "55356",
                "NaN",
                "<String.fromCharCode(97, 55356, 98)>",
                "<String.fromCharCode(55356)>",
                "\"b\"",
                "undefined",
                "3"
            ]
        );
    }
}
