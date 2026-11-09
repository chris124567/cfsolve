//! Session objects that handler runs share instead of copying while no run changes them.
//!
//! Runs copy every session object they reach (see [`super::copies`]), but most session
//! bindings are tables that handlers only read. Objects reachable from bindings form groups:
//! bindings that share an object belong to one group. Handler and decoder runs share a
//! group's objects as they are. The first run that writes to one thaws its group, so later
//! runs copy it as before, and stops; the caller then reruns the instruction from the start.
//! Every completed run therefore sees what a run that copied everything would.
//!
//! Groups that reach a function with captured state are never shared: calling it would write
//! to a session scope.

use std::cell::RefCell;
use std::rc::Rc;

use crate::js::ast::Binding;
use crate::vm::value::Value;
use crate::vm::{HashMap, HashSet};

#[derive(Default)]
pub(crate) struct Frozen {
    /// Addresses of the objects runs share.
    shared: RefCell<HashSet<usize>>,
    /// Each shared object's group root, by address.
    groups: HashMap<usize, usize>,
    /// Each group's objects, by root.
    members: HashMap<usize, Vec<usize>>,
}

impl Frozen {
    /// Groups the objects reachable from `bindings` and shares those of groups that reach no
    /// function with captured state.
    pub(crate) fn of(bindings: &HashMap<Binding<'_>, Value<'_>>) -> Self {
        let mut groups = Groups::default();
        for value in bindings.values() {
            let mut reached = Reached::default();
            reached.visit(value);
            groups.join(&reached);
        }
        groups.frozen()
    }

    /// Whether runs share the object at `address`.
    pub(super) fn contains(&self, address: usize) -> bool {
        let shared = self.shared.borrow();
        !shared.is_empty() && shared.contains(&address)
    }

    /// Stops sharing the group of the object at `address`.
    pub(super) fn thaw(&self, address: usize) {
        if let Some(&group) = self.groups.get(&address) {
            let mut shared = self.shared.borrow_mut();
            for member in &self.members[&group] {
                shared.remove(member);
            }
        }
    }
}

/// The address of `value` if it is an object a run can change.
pub(super) fn address(value: &Value<'_>) -> Option<usize> {
    Some(match value {
        Value::Array(elements) => Rc::as_ptr(elements).addr(),
        Value::Object(properties) => Rc::as_ptr(properties).addr(),
        Value::Set(members) => Rc::as_ptr(members).addr(),
        Value::Map(entries) => Rc::as_ptr(entries).addr(),
        _ => return None,
    })
}

/// The objects reachable from one binding.
#[derive(Default)]
struct Reached {
    seen: HashSet<usize>,
    /// Whether a function with captured state is reachable.
    stateful: bool,
}

impl Reached {
    fn visit(&mut self, value: &Value<'_>) {
        if let Value::Function(_) = value {
            self.stateful |= !value.is_immutable();
            return;
        }
        let Some(address) = address(value) else {
            return;
        };
        if !self.seen.insert(address) {
            return;
        }
        match value {
            Value::Array(elements) | Value::Set(elements) => {
                for element in elements.borrow().iter() {
                    self.visit(element);
                }
            }
            Value::Object(properties) => {
                for (_, property) in properties.borrow().iter() {
                    self.visit(property);
                }
            }
            Value::Map(entries) => {
                for (key, entry) in entries.borrow().iter() {
                    self.visit(key);
                    self.visit(entry);
                }
            }
            _ => {}
        }
    }
}

/// Union-find over objects, joining the objects each binding reaches.
#[derive(Default)]
struct Groups {
    /// Each object's parent in the union-find forest, by address.
    parents: HashMap<usize, usize>,
    /// Roots whose group reaches a function with captured state.
    stateful: HashSet<usize>,
}

impl Groups {
    fn root(&mut self, mut address: usize) -> usize {
        self.parents.entry(address).or_insert(address);
        while let Some(&parent) = self.parents.get(&address)
            && parent != address
        {
            let grandparent = self.parents[&parent];
            self.parents.insert(address, grandparent);
            address = grandparent;
        }
        address
    }

    fn join(&mut self, reached: &Reached) {
        let mut objects = reached.seen.iter().copied();
        let Some(first) = objects.next() else {
            return;
        };
        let root = self.root(first);
        for object in objects {
            let other = self.root(object);
            if other != root {
                self.parents.insert(other, root);
                if self.stateful.remove(&other) {
                    self.stateful.insert(root);
                }
            }
        }
        if reached.stateful {
            self.stateful.insert(root);
        }
    }

    fn frozen(mut self) -> Frozen {
        let objects: Vec<_> = self.parents.keys().copied().collect();
        let mut frozen = Frozen::default();
        for object in objects {
            let root = self.root(object);
            if self.stateful.contains(&root) {
                continue;
            }
            frozen.members.entry(root).or_default().push(object);
            frozen.groups.insert(object, root);
            frozen.shared.get_mut().insert(object);
        }
        frozen
    }
}
