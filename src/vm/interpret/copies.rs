//! Copies session objects so mutations remain isolated to one run.

use std::cell::RefCell;
use std::rc::Rc;

use super::frozen::{self, Frozen};
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
/// references and avoid copying twice. Objects in `frozen` stay shared.
pub(super) fn copy<'a>(
    value: &Value<'a>,
    copies: &mut Copies<'a>,
    frozen: Option<&Frozen>,
) -> Value<'a> {
    Isolation { copies, frozen }.copy(value)
}

/// The deep copy shared by [`copy`] and [`Fork`], which differ in the scopes they copy.
trait Copier<'ast>: Sized {
    /// Shared session objects, which are not copied.
    fn frozen(&self) -> Option<&Frozen>;
    /// Copies by original address.
    fn values(&mut self) -> &mut HashMap<usize, Value<'ast>>;
    /// Copies a function's captured scope, or returns `None` if it needs no copy.
    fn captured(&mut self, scope: &Scope<'ast>) -> Option<Scope<'ast>>;

    fn copy(&mut self, value: &Value<'ast>) -> Value<'ast> {
        if let Some(frozen) = self.frozen()
            && let Some(address) = frozen::address(value)
            && frozen.contains(address)
        {
            return value.clone();
        }
        let address = match (value, frozen::address(value)) {
            (Value::Function(callable), _) => Rc::as_ptr(callable).addr(),
            (_, Some(address)) => address,
            (_, None) => return value.clone(),
        };
        if let Some(copy) = self.values().get(&address) {
            return copy.clone();
        }
        match value {
            Value::Array(elements) => self.elements(elements, address, Value::Array, Self::copy),
            Value::Set(members) => self.elements(members, address, Value::Set, Self::copy),
            Value::Map(entries) => {
                self.elements(entries, address, Value::Map, |copier, (key, value)| {
                    (copier.copy(key), copier.copy(value))
                })
            }
            Value::Object(properties) => self.elements(
                properties,
                address,
                Value::Object,
                |copier, (name, value)| (name.clone(), copier.copy(value)),
            ),
            Value::Function(callable) => {
                let copied = match &**callable {
                    Callable::Script {
                        name,
                        function,
                        scope: Some(scope),
                    } => match self.captured(scope) {
                        // The function captures no mutable state.
                        None => return value.clone(),
                        scope => Callable::Script {
                            name: *name,
                            function,
                            scope,
                        },
                    },
                    Callable::Script { scope: None, .. }
                    | Callable::Builtin(_)
                    | Callable::Standard(_) => return value.clone(),
                    Callable::Arrow { arrow, this, scope } => Callable::Arrow {
                        arrow,
                        this: self.copy(this),
                        scope: scope.as_ref().and_then(|scope| self.captured(scope)),
                    },
                    Callable::Call(target) => Callable::Call(self.copy(target)),
                    Callable::Apply(target) => Callable::Apply(self.copy(target)),
                    Callable::Bind(target) => Callable::Bind(self.copy(target)),
                    Callable::Bound {
                        target,
                        this,
                        arguments,
                    } => Callable::Bound {
                        target: self.copy(target),
                        this: self.copy(this),
                        arguments: arguments
                            .iter()
                            .map(|argument| self.copy(argument))
                            .collect(),
                    },
                };
                // A captured value may refer back to this function and copy it first.
                if let Some(copy) = self.values().get(&address) {
                    return copy.clone();
                }
                let copied = Value::function(copied);
                self.values().insert(address, copied.clone());
                copied
            }
            _ => unreachable!("only objects have addresses"),
        }
    }

    /// Copies the elements of an array, set, map, or object with `copy_element`.
    fn elements<T>(
        &mut self,
        elements: &RefCell<Vec<T>>,
        address: usize,
        wrap: fn(Rc<RefCell<Vec<T>>>) -> Value<'ast>,
        copy_element: impl Fn(&mut Self, &T) -> T,
    ) -> Value<'ast> {
        // Cache before copying elements because they may refer back to this object.
        let copied = Rc::new(RefCell::new(Vec::new()));
        self.values().insert(address, wrap(copied.clone()));
        let elements: Vec<T> = elements
            .borrow()
            .iter()
            .map(|element| copy_element(self, element))
            .collect();
        *copied.borrow_mut() = elements;
        wrap(copied)
    }
}

/// The state of a [`copy`].
struct Isolation<'copies, 'frozen, 'ast> {
    copies: &'copies mut Copies<'ast>,
    frozen: Option<&'frozen Frozen>,
}

impl<'ast> Copier<'ast> for Isolation<'_, '_, 'ast> {
    fn frozen(&self) -> Option<&Frozen> {
        self.frozen
    }

    fn values(&mut self) -> &mut HashMap<usize, Value<'ast>> {
        &mut self.copies.values
    }

    /// Copies `scope` and its parents. Omits chains with no variables: completed session calls
    /// cannot add variables to those scopes.
    fn captured(&mut self, scope: &Scope<'ast>) -> Option<Scope<'ast>> {
        let address = Rc::as_ptr(scope).addr();
        if let Some(copy) = self.copies.scopes.get(&address) {
            return copy.clone();
        }
        let original = scope.borrow();
        if original.variables.is_empty() {
            let copied = original
                .outer
                .as_ref()
                .and_then(|outer| self.captured(outer));
            self.copies.scopes.insert(address, copied.clone());
            return copied;
        }
        // Cache before copying variables because they may hold functions capturing this scope.
        let copied = Env::scope(HashMap::default(), None);
        self.copies.scopes.insert(address, Some(copied.clone()));
        let outer = original
            .outer
            .as_ref()
            .and_then(|outer| self.captured(outer));
        let variables = original
            .variables
            .iter()
            .map(|(name, value)| (*name, self.copy(value)))
            .collect();
        *copied.borrow_mut() = Env { variables, outer };
        Some(copied)
    }
}

/// Deep-copies a run's state for another path to resume from (see
/// [`super::run::Snapshot`]). Unlike [`copy`], it copies every scope, since the run may still
/// add variables to them, and it clones maps before copying their values so they keep the
/// original's layout and iteration order.
pub(super) struct Fork<'frozen, 'ast> {
    frozen: Option<&'frozen Frozen>,
    values: HashMap<usize, Value<'ast>>,
    scopes: HashMap<usize, Scope<'ast>>,
    /// Every scope copied, for breaking cycles when the copy is dropped.
    pub(super) copied: Vec<Scope<'ast>>,
}

impl<'ast> Copier<'ast> for Fork<'_, 'ast> {
    fn frozen(&self) -> Option<&Frozen> {
        self.frozen
    }

    fn values(&mut self) -> &mut HashMap<usize, Value<'ast>> {
        &mut self.values
    }

    fn captured(&mut self, scope: &Scope<'ast>) -> Option<Scope<'ast>> {
        Some(self.scope(scope))
    }
}

impl<'frozen, 'ast> Fork<'frozen, 'ast> {
    pub(super) fn new(frozen: Option<&'frozen Frozen>) -> Self {
        Self {
            frozen,
            values: HashMap::default(),
            scopes: HashMap::default(),
            copied: Vec::new(),
        }
    }

    pub(super) fn value(&mut self, value: &Value<'ast>) -> Value<'ast> {
        self.copy(value)
    }

    pub(super) fn scope(&mut self, scope: &Scope<'ast>) -> Scope<'ast> {
        let address = Rc::as_ptr(scope).addr();
        if let Some(copy) = self.scopes.get(&address) {
            return copy.clone();
        }
        // Cache before copying variables because they may hold functions capturing this scope.
        let copied = Env::scope(HashMap::default(), None);
        self.scopes.insert(address, copied.clone());
        self.copied.push(copied.clone());
        let original = scope.borrow();
        let outer = original.outer.as_ref().map(|outer| self.scope(outer));
        let variables = self.map(&original.variables);
        *copied.borrow_mut() = Env { variables, outer };
        copied
    }

    /// Copies a map's values, keeping its layout.
    pub(super) fn map<K: Clone>(
        &mut self,
        map: &HashMap<K, Value<'ast>>,
    ) -> HashMap<K, Value<'ast>> {
        let mut copied = map.clone();
        for value in copied.values_mut() {
            *value = self.copy(value);
        }
        copied
    }

    /// Copies the run's [`Copies`], mapping session objects to copies of their run copies.
    pub(super) fn copies(&mut self, copies: &Copies<'ast>) -> Copies<'ast> {
        let values = self.map(&copies.values);
        let mut scopes = copies.scopes.clone();
        for scope in scopes.values_mut().flatten() {
            *scope = self.scope(scope);
        }
        Copies { values, scopes }
    }
}
