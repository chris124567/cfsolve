//! Copies session objects so mutations remain isolated to one run.

use std::cell::RefCell;
use std::rc::Rc;

use swc_core::atoms::Atom;

use crate::vm::HashMap;
use crate::vm::value::{Callable, Env, Scope, Value};

/// Copied session values indexed by original address.
#[derive(Default)]
pub(super) struct Copies<'ast> {
    values: HashMap<usize, Value<'ast>>,
    /// Captured scopes, or `None` if the scope chain contains no variables.
    pub(super) scopes: HashMap<usize, Option<Scope<'ast>>>,
}

/// Deep-copies mutable state in `value`. Uses original addresses in `copies` to preserve shared
/// references and avoid copying twice.
pub(super) fn copy<'a>(value: &Value<'a>, copies: &mut Copies<'a>) -> Value<'a> {
    let address = match value {
        Value::Array(elements) => Rc::as_ptr(elements).addr(),
        Value::Object(properties) => Rc::as_ptr(properties).addr(),
        Value::Set(members) => Rc::as_ptr(members).addr(),
        Value::Map(entries) => Rc::as_ptr(entries).addr(),
        Value::Function(callable) => Rc::as_ptr(callable).addr(),
        _ => return value.clone(),
    };
    if let Some(copy) = copies.values.get(&address) {
        return copy.clone();
    }
    match value {
        Value::Array(elements) => copy_elements(elements, address, copies, Value::Array, copy),
        Value::Set(members) => copy_elements(members, address, copies, Value::Set, copy),
        Value::Map(entries) => copy_elements(
            entries,
            address,
            copies,
            Value::Map,
            |(key, value), copies| (copy(key, copies), copy(value, copies)),
        ),
        Value::Object(properties) => copy_elements(
            properties,
            address,
            copies,
            Value::Object,
            |(name, value), copies| (name.clone(), copy(value, copies)),
        ),
        Value::Function(callable) => {
            let copied = match &**callable {
                Callable::Script {
                    name,
                    function,
                    scope: Some(scope),
                } => match copy_scope(scope, copies) {
                    // The function captures no mutable state.
                    None => return value.clone(),
                    scope => Callable::Script {
                        name: name.clone(),
                        function,
                        scope,
                    },
                },
                Callable::Script { scope: None, .. }
                | Callable::Builtin(_)
                | Callable::Standard(_) => return value.clone(),
                Callable::Arrow { arrow, this, scope } => Callable::Arrow {
                    arrow,
                    this: copy(this, copies),
                    scope: scope.as_ref().and_then(|scope| copy_scope(scope, copies)),
                },
                Callable::Call(target) => Callable::Call(copy(target, copies)),
                Callable::Apply(target) => Callable::Apply(copy(target, copies)),
                Callable::Bind(target) => Callable::Bind(copy(target, copies)),
                Callable::Bound {
                    target,
                    this,
                    arguments,
                } => Callable::Bound {
                    target: copy(target, copies),
                    this: copy(this, copies),
                    arguments: arguments
                        .iter()
                        .map(|argument| copy(argument, copies))
                        .collect(),
                },
            };
            // A captured value may refer back to this function and copy it first.
            if let Some(copy) = copies.values.get(&address) {
                return copy.clone();
            }
            let copied = Value::function(copied);
            copies.values.insert(address, copied.clone());
            copied
        }
        _ => unreachable!("only objects have addresses"),
    }
}

/// Copies the elements of an array, set, or object with `copy_element`.
fn copy_elements<'a, T>(
    elements: &RefCell<Vec<T>>,
    address: usize,
    copies: &mut Copies<'a>,
    wrap: fn(Rc<RefCell<Vec<T>>>) -> Value<'a>,
    copy_element: impl Fn(&T, &mut Copies<'a>) -> T,
) -> Value<'a> {
    // Cache before copying elements because they may refer back to this object.
    let copied = Rc::new(RefCell::new(Vec::new()));
    copies.values.insert(address, wrap(copied.clone()));
    let elements: Vec<T> = elements
        .borrow()
        .iter()
        .map(|element| copy_element(element, copies))
        .collect();
    *copied.borrow_mut() = elements;
    wrap(copied)
}

/// Copies `scope` and its parents. Omits chains with no variables: completed session calls
/// cannot add variables to those scopes.
fn copy_scope<'a>(scope: &Scope<'a>, copies: &mut Copies<'a>) -> Option<Scope<'a>> {
    let address = Rc::as_ptr(scope).addr();
    if let Some(copy) = copies.scopes.get(&address) {
        return copy.clone();
    }
    let original = scope.borrow();
    if original.variables.is_empty() {
        let copied = original
            .outer
            .as_ref()
            .and_then(|outer| copy_scope(outer, copies));
        copies.scopes.insert(address, copied.clone());
        return copied;
    }
    // Cache before copying variables because they may hold functions capturing this scope.
    let copied = Env::scope(HashMap::default(), None);
    copies.scopes.insert(address, Some(copied.clone()));
    let outer = original
        .outer
        .as_ref()
        .and_then(|outer| copy_scope(outer, copies));
    let variables: HashMap<Atom, Value<'a>> = original
        .variables
        .iter()
        .map(|(name, value)| (name.clone(), copy(value, copies)))
        .collect();
    *copied.borrow_mut() = Env { variables, outer };
    Some(copied)
}
