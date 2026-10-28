//! Handler values: concrete when determined by bytes, symbolic when dependent on registers.

use std::cell::RefCell;
use std::mem;
use std::rc::Rc;

use swc_core::atoms::Atom;
use swc_core::ecma::ast::{ArrowExpr, Function as ScriptFunction};

use super::interpret::Builtin;
use super::output::{Constant, Term};
use super::registers::Slots;
use super::{HashMap, convert};

/// A value produced by a handler. Uses a word-sized discriminant so the whole value occupies
/// two words.
#[derive(Clone)]
#[repr(u64)]
pub(crate) enum Value<'ast> {
    Undefined,
    Null,
    Bool(bool),
    Number(f64),
    String(JsString),
    Array(Rc<RefCell<Vec<Value<'ast>>>>),
    Object(Rc<RefCell<Vec<(String, Value<'ast>)>>>),
    /// A `Set` or `WeakSet`.
    Set(Rc<RefCell<Vec<Value<'ast>>>>),
    /// A `Map` or `WeakMap`, with its entries in insertion order.
    Map(Rc<RefCell<Vec<(Value<'ast>, Value<'ast>)>>>),
    Function(Rc<Callable<'ast>>),
    /// A `Symbol()`, which only equals itself.
    Symbol(Rc<()>),
    /// A realm's global object at the empty path, or a standard-library namespace such as
    /// `Math`. Page-specific state is not modeled.
    Namespace(Rc<String>),
    /// A register-dependent symbolic value.
    Symbolic(Rc<Term>),
    /// The interpreter instance, `this` inside a handler.
    Machine,
    /// The register file (see [`super::registers`]).
    Registers,
    /// One of the register file's parallel arrays.
    RegisterSlots(Slots),
    Program,
    /// The closure cells of the running function.
    Cells,
    Cell(u32),
}

/// Variables of a call or of setup. Functions capture scopes by reference, so later assignments
/// are visible to every function sharing the scope.
pub(crate) struct Env<'ast> {
    pub variables: HashMap<Atom, Value<'ast>>,
    pub outer: Option<Scope<'ast>>,
}

pub(crate) type Scope<'ast> = Rc<RefCell<Env<'ast>>>;

impl<'ast> Env<'ast> {
    pub(super) fn scope(
        variables: HashMap<Atom, Value<'ast>>,
        outer: Option<Scope<'ast>>,
    ) -> Scope<'ast> {
        Rc::new(RefCell::new(Self { variables, outer }))
    }

    pub(super) fn find(scope: &RefCell<Self>, name: &Atom) -> Option<Value<'ast>> {
        let scope = scope.borrow();
        match scope.variables.get(name) {
            Some(value) => Some(value.clone()),
            None => Self::find(scope.outer.as_ref()?, name),
        }
    }

    /// Assigns `name` in the nearest scope containing it. Returns `value` if no scope contains
    /// the name.
    pub(super) fn assign(
        scope: &RefCell<Self>,
        name: &Atom,
        value: Value<'ast>,
    ) -> Option<Value<'ast>> {
        let mut scope = scope.borrow_mut();
        if let Some(slot) = scope.variables.get_mut(name) {
            *slot = value;
            return None;
        }
        match &scope.outer {
            Some(outer) => Self::assign(outer, name, value),
            None => Some(value),
        }
    }
}

pub(crate) enum Callable<'ast> {
    Script {
        name: Option<Atom>,
        function: &'ast ScriptFunction,
        /// Scope captured at function creation. Functions declared beside the class use `None`
        /// and resolve through setup or session bindings.
        scope: Option<Scope<'ast>>,
    },
    /// Arrow function with captured `this` and scope. A copied function uses `None` when its
    /// entire scope chain is empty.
    Arrow {
        arrow: &'ast ArrowExpr,
        this: Value<'ast>,
        scope: Option<Scope<'ast>>,
    },
    Builtin(Builtin),
    /// Known standard-library function without a [`Builtin`] implementation. Calls remain
    /// register-dependent.
    Standard(String),
    /// `f.call` or `f.apply` of a function value.
    Call(Value<'ast>),
    Apply(Value<'ast>),
    /// `f.bind` of a function value.
    Bind(Value<'ast>),
    Bound {
        target: Value<'ast>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    },
}

/// A JavaScript string as UTF-16 code units. Handlers may build strings one code unit at a
/// time, temporarily separating surrogate pairs, so lone surrogates must survive.
///
/// A `Vec` lets uniquely owned strings grow in place (see [`JsString::concat`]).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct JsString(Rc<Vec<u16>>);

impl JsString {
    pub(super) fn units(&self) -> &[u16] {
        &self.0
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The code unit at `index`, as `charCodeAt` reads it.
    pub(super) fn unit(&self, index: usize) -> Option<u16> {
        self.0.get(index).copied()
    }

    /// Converts to Rust text, returning `None` if the string contains a lone surrogate.
    pub(super) fn text(&self) -> Option<String> {
        String::from_utf16(&self.0).ok()
    }

    /// Grows uniquely owned `self` in place, avoiding copies while handlers build strings.
    pub(super) fn concat(mut self, other: &Self) -> Self {
        if other.is_empty() {
            return self;
        }
        if self.is_empty() {
            return other.clone();
        }
        if let Some(units) = Rc::get_mut(&mut self.0) {
            units.extend_from_slice(&other.0);
            return self;
        }
        self.0.iter().chain(other.0.iter()).copied().collect()
    }
}

impl From<&str> for JsString {
    fn from(text: &str) -> Self {
        text.encode_utf16().collect()
    }
}

impl From<Vec<u16>> for JsString {
    fn from(units: Vec<u16>) -> Self {
        Self(Rc::new(units))
    }
}

impl FromIterator<u16> for JsString {
    fn from_iter<I: IntoIterator<Item = u16>>(units: I) -> Self {
        Self(Rc::new(units.into_iter().collect()))
    }
}

impl<'ast> Value<'ast> {
    pub(super) fn string(text: &str) -> Self {
        Self::String(JsString::from(text))
    }

    pub(super) fn array(elements: Vec<Value<'ast>>) -> Self {
        Self::Array(Rc::new(RefCell::new(elements)))
    }

    pub(super) fn symbolic(expr: Term) -> Self {
        Self::Symbolic(Rc::new(expr))
    }

    pub(super) fn function(callable: Callable<'ast>) -> Self {
        Self::Function(Rc::new(callable))
    }

    /// Drops the value, skipping the destructor call for numbers and other nonowning values.
    #[inline(always)]
    pub(super) fn discard(self) {
        if matches!(
            self,
            Self::Undefined | Self::Null | Self::Bool(_) | Self::Number(_)
        ) {
            mem::forget(self);
        }
    }

    pub(super) fn is_symbolic(&self) -> bool {
        matches!(self, Self::Symbolic(_))
    }

    pub(super) fn expr(&self) -> Term {
        match self {
            Self::Undefined => Term::Const(Constant::Undefined),
            Self::Null => Term::Const(Constant::Null),
            Self::Bool(value) => Term::Const(Constant::Bool(*value)),
            Self::Number(number) => Term::Const(Constant::Number(*number)),
            Self::String(string) => match string.text() {
                Some(text) => Term::Const(Constant::String(text)),
                None => {
                    let units: Vec<String> = string.units().iter().map(u16::to_string).collect();
                    Term::Opaque(format!("String.fromCharCode({})", units.join(", ")))
                }
            },
            Self::Array(elements) => {
                Term::Array(elements.borrow().iter().map(Value::expr).collect())
            }
            Self::Object(properties) => Term::Object(
                properties
                    .borrow()
                    .iter()
                    .map(|(key, value)| (key.clone(), value.expr()))
                    .collect(),
            ),
            Self::Symbolic(expr) => (**expr).clone(),
            Self::Cells => Term::Cells,
            Self::Cell(cell) => Term::Cell(*cell),
            Self::Function(callable) => match &**callable {
                Callable::Builtin(builtin) => Term::Global(builtin.path().into()),
                Callable::Standard(path) => Term::Global(path.clone()),
                callable => closure(callable).unwrap_or_else(|| Term::Opaque("function".into())),
            },
            Self::Set(_) => Term::Opaque("set".into()),
            Self::Map(_) => Term::Opaque("map".into()),
            Self::Symbol(_) => Term::Opaque("symbol".into()),
            Self::Namespace(path) if path.is_empty() => Term::Global("globalThis".into()),
            Self::Namespace(path) => Term::Global(path.to_string()),
            Self::Machine | Self::Registers | Self::RegisterSlots(_) | Self::Program => {
                Term::Opaque("machine internals".into())
            }
        }
    }
}

/// A program function stored as a bound machine entry with layout `[pc, key, cells, parameters,
/// arity, ...]`, or as a closure capturing both.
fn closure(callable: &Callable<'_>) -> Option<Term> {
    let layout = match callable {
        Callable::Bound { arguments, .. } => match arguments.as_slice() {
            [Value::Machine, Value::Array(layout)] => layout.clone(),
            _ => return None,
        },
        Callable::Script {
            scope: Some(scope), ..
        } => {
            // Use the factory's variables; its `arguments` also contains the machine and layout.
            let scope = scope.borrow();
            let variables = &scope.variables;
            let mut layouts = variables.iter().filter_map(|(name, value)| match value {
                Value::Array(layout) if &**name != "arguments" => Some(layout),
                _ => None,
            });
            let machine = variables
                .values()
                .any(|value| matches!(value, Value::Machine));
            match (layouts.next(), layouts.next()) {
                (Some(layout), None) if machine => layout.clone(),
                _ => return None,
            }
        }
        _ => return None,
    };
    let layout = layout.borrow();
    let number = |index: usize| layout.get(index).and_then(Value::number);
    let parameters: Vec<u8> = match layout.get(3) {
        Some(Value::Array(parameters)) => parameters
            .borrow()
            .iter()
            .map(|register| register.number().and_then(convert::byte))
            .collect::<Option<_>>()?,
        _ => Vec::new(),
    };
    Some(Term::Closure {
        pc: convert::position(number(0)?)?,
        key: convert::byte(number(1)?)?,
        parameters,
        arity: convert::byte(number(4)?)?,
    })
}

const _: () = assert!(
    size_of::<Value>() == 16,
    "a value should move as two words through every step of evaluation"
);
const _: () = assert!(
    size_of::<Result<Value, Box<()>>>() == 16,
    "with a stop boxed, an evaluation should be as small as a value"
);
