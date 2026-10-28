//! Calls and constructions of script functions, arrows, builtins, and bound functions.

use swc_core::atoms::{Atom, atom};
use swc_core::ecma::ast::{ArrowExpr, Decl, Function, Pat, Stmt};

use super::access::Key;
use super::plan;
use super::run::{Evaluation, Frame, Run, Stop};
use crate::vm::HashMap;
use crate::vm::output::Term;
use crate::vm::value::{Callable, Env, Scope, Value};

impl<'ast> Run<'ast, '_> {
    /// Creates a function capturing its current scope, such as a closure factory's machine and
    /// layout.
    pub(super) fn function_value(
        &mut self,
        name: Option<Atom>,
        function: &'ast Function,
    ) -> Value<'ast> {
        Value::function(Callable::Script {
            name,
            function,
            scope: Some(self.closure_scope()),
        })
    }

    /// Creates an arrow function capturing both the current scope and `this`.
    pub(super) fn arrow_value(&mut self, arrow: &'ast ArrowExpr) -> Value<'ast> {
        let this = self.frame().this.clone();
        let scope = Some(self.closure_scope());
        Value::function(Callable::Arrow { arrow, this, scope })
    }

    pub(super) fn apply(
        &mut self,
        callee: Value<'ast>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        if let Value::Symbolic(term) = &callee
            && let Term::Global(path) = &**term
            && let Some(method) = self.own_method(path, &this)?
        {
            return self.apply(method, this, arguments);
        }
        match callee {
            Value::Function(callable) => self.invoke(&callable, this, arguments),
            Value::Symbolic(callee) => {
                // A method of a register value: `object.method(...)`.
                let this = match (&*callee, &this) {
                    (Term::Get(object, _), receiver) if receiver.expr() == **object => None,
                    (_, Value::Undefined) => None,
                    (_, receiver) => Some(Box::new(receiver.expr())),
                };
                Ok(self.temp(Term::Call {
                    callee: Box::new((*callee).clone()),
                    this,
                    arguments: arguments.iter().map(Value::expr).collect(),
                }))
            }
            callee => Err(Stop::throw(Value::string(&format!(
                "TypeError: {} is not a function",
                callee.expr()
            )))),
        }
    }

    /// Resolves a receiver's own method for uncurried calls such as
    /// `call.bind(Array.prototype.push)`. Returns `None` if `path` is not a tracked prototype
    /// method or the receiver is unavailable.
    fn own_method(
        &mut self,
        path: &str,
        this: &Value<'ast>,
    ) -> Evaluation<'ast, Option<Value<'ast>>> {
        let Some((_, name)) = path.rsplit_once(".prototype.") else {
            return Ok(None);
        };
        if matches!(this, Value::Undefined | Value::Null | Value::Namespace(_)) {
            return Ok(None);
        }
        let method = self.get(this, &Key::name(name))?;
        // Do not substitute the same prototype method for itself; that would recurse forever.
        let same = match &method {
            Value::Symbolic(method) => matches!(&**method, Term::Global(own) if own == path),
            Value::Function(callable) => match &**callable {
                Callable::Standard(standard) => standard == path,
                Callable::Builtin(builtin) => builtin.path() == path,
                _ => false,
            },
            _ => false,
        };
        if same {
            return Err(Stop::unsupported(&format!("{path} of its own prototype")));
        }
        Ok(Some(method))
    }

    pub(crate) fn invoke(
        &mut self,
        callable: &Callable<'ast>,
        this: Value<'ast>,
        mut arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        match callable {
            // Evaluate helpers with symbolic arguments when their control flow can be followed,
            // such as validation or forwarding wrappers. Record an unresolved call otherwise,
            // as for hashes looping over register strings.
            Callable::Script {
                name: Some(name),
                function,
                scope,
            } if arguments.iter().any(Value::is_symbolic) => {
                let call = Term::Call {
                    callee: Box::new(Term::Global(name.to_string())),
                    this: None,
                    arguments: arguments.iter().map(Value::expr).collect(),
                };
                let checkpoint = self.checkpoint();
                match self.script(function, scope.as_ref(), this, arguments) {
                    Err(stop) if matches!(*stop, Stop::Unsupported(_)) => {
                        self.restore(checkpoint);
                        Ok(self.temp(call))
                    }
                    outcome => {
                        self.release(checkpoint);
                        outcome
                    }
                }
            }
            Callable::Script {
                function, scope, ..
            } => self.script(function, scope.as_ref(), this, arguments),
            Callable::Arrow { arrow, this, scope } => {
                let locals = parameters(arrow.params.iter(), arguments, 0)?;
                let scope = self.call_scope(locals, scope.as_ref());
                let body = self.session.compiled.scoped(*arrow, plan::scoped_arrow);
                self.body(
                    Frame {
                        this: this.clone(),
                        scope,
                    },
                    &body,
                    &mut [],
                )
            }
            Callable::Builtin(builtin) => self.builtin(*builtin, this, arguments),
            Callable::Standard(path) => {
                self.apply(Value::symbolic(Term::Global(path.clone())), this, arguments)
            }
            Callable::Call(target) => {
                let this = if arguments.is_empty() {
                    Value::Undefined
                } else {
                    arguments.remove(0)
                };
                self.apply(target.clone(), this, arguments)
            }
            Callable::Apply(target) => {
                let mut arguments = arguments.into_iter();
                let this = arguments.next().unwrap_or(Value::Undefined);
                let list = match arguments.next() {
                    Some(Value::Array(list)) => list.borrow().clone(),
                    None | Some(Value::Undefined | Value::Null) => Vec::new(),
                    Some(list) => {
                        return Err(Stop::unsupported(&format!("apply over {}", list.expr())));
                    }
                };
                self.apply(target.clone(), this, list)
            }
            Callable::Bind(target) => {
                let mut arguments = arguments.into_iter();
                Ok(Value::function(Callable::Bound {
                    target: target.clone(),
                    this: arguments.next().unwrap_or(Value::Undefined),
                    arguments: arguments.collect(),
                }))
            }
            Callable::Bound {
                target,
                this,
                arguments: bound,
            } => {
                let all: Vec<Value<'ast>> = match bound.is_empty() {
                    true => arguments,
                    false => bound.iter().cloned().chain(arguments).collect(),
                };
                self.apply(target.clone(), this.clone(), all)
            }
        }
    }

    /// Calls a function through its slot plan if it has one and is not a closure, or else
    /// through its scoped plan.
    fn script(
        &mut self,
        function: &'ast Function,
        scope: Option<&Scope<'ast>>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        if scope.is_none()
            && self.setup.is_none()
            && let Some(plan) = self.session.compiled.slots(function)
        {
            return self.call_plan(&plan, this, arguments);
        }
        let body = function
            .body
            .as_ref()
            .ok_or_else(|| Stop::unsupported("declared function"))?;
        let patterns = function.params.iter().map(|parameter| &parameter.pat);
        let all = Value::array(arguments.clone());
        // Room for `arguments` and the variables the body declares.
        let mut locals = parameters(patterns, arguments, 1 + declared(&body.stmts))?;
        locals.insert(atom!("arguments"), all);
        let scope = self.call_scope(locals, scope);
        let body = self
            .session
            .compiled
            .scoped(body, |body| plan::scoped_body(&body.stmts));
        self.body(Frame { this, scope }, &body, &mut [])
    }

    /// Creates a call scope with `locals`, nested in the function's captured scope. Functions
    /// declared beside the VM class use setup bindings during setup and session bindings
    /// afterward. Unresolved names fall back to session bindings.
    fn call_scope(
        &self,
        locals: HashMap<Atom, Value<'ast>>,
        closed: Option<&Scope<'ast>>,
    ) -> Scope<'ast> {
        let outer = closed.or(self.setup.as_ref()).cloned();
        Env::scope(locals, outer)
    }

    pub(super) fn construct(
        &mut self,
        callee: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        match callee {
            Value::Function(callable) if matches!(*callable, Callable::Builtin(_)) => {
                self.invoke(&callable, Value::Undefined, arguments)
            }
            callee => Ok(self.temp(Term::New {
                callee: Box::new(callee.expr()),
                arguments: arguments.iter().map(Value::expr).collect(),
            })),
        }
    }
}

/// Binds call arguments to parameters and reserves `room` additional local slots.
fn parameters<'ast, 'pattern>(
    patterns: impl Iterator<Item = &'pattern Pat>,
    arguments: Vec<Value<'ast>>,
    room: usize,
) -> Evaluation<'ast, HashMap<Atom, Value<'ast>>> {
    let mut arguments = arguments.into_iter();
    let capacity = patterns.size_hint().0 + room;
    let mut locals = HashMap::with_capacity_and_hasher(capacity, Default::default());
    for pattern in patterns {
        let Pat::Ident(name) = pattern else {
            return Err(Stop::unsupported("a parameter pattern"));
        };
        let argument = arguments.next().unwrap_or(Value::Undefined);
        locals.insert(name.id.sym.clone(), argument);
    }
    Ok(locals)
}

/// Counts top-level `var` declarations in `statements` to reserve local storage for a call.
fn declared(statements: &[Stmt]) -> usize {
    statements
        .iter()
        .map(|statement| match statement {
            Stmt::Decl(Decl::Var(declaration)) => declaration.decls.len(),
            _ => 0,
        })
        .sum()
}
