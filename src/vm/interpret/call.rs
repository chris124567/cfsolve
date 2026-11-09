//! Calls and constructions of script functions, arrows, builtins, and bound functions.

use std::ptr;

use oxc::ast::ast::{
    ArrowFunctionExpression, FormalParameters, Function, Statement, VariableDeclaration,
};

use super::access::Key;
use super::intrinsic::{self, Intrinsic};
use super::plan::{self, Routine};
use super::run::{CallScope, Evaluation, Frame, RecordKey, RecordPart, Run, Stop};
use crate::js::ast::Binding;
use crate::profiling;
use crate::vm::output::Term;
use crate::vm::value::{Callable, Env, Scope, Value};
use crate::vm::{HashMap, extract};

impl<'ast> Run<'ast, '_> {
    /// Creates a function capturing its current scope, such as a closure factory's machine and
    /// layout.
    pub(super) fn function_value(
        &mut self,
        name: Option<&'ast str>,
        function: &'ast Function<'ast>,
    ) -> Value<'ast> {
        Value::function(Callable::Script {
            name,
            function,
            scope: Some(self.closure_scope()),
        })
    }

    /// Creates an arrow function capturing both the current scope and `this`.
    pub(super) fn arrow_value(
        &mut self,
        arrow: &'ast ArrowFunctionExpression<'ast>,
    ) -> Value<'ast> {
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
        if let Callable::Script { function, .. } = callable
            && let Some(&intrinsic) = self.session.intrinsics.get(&intrinsic::address(function))
            && let Some(value) = intrinsic.call(self, &arguments)
        {
            arguments.clear();
            self.spare.arguments.push(arguments);
            return Ok(value);
        }
        match callable {
            // Evaluate helpers with symbolic arguments when their control flow can be followed,
            // such as validation or forwarding wrappers. Record an unresolved call otherwise,
            // as for hashes looping over register strings.
            Callable::Script {
                name: Some(name),
                function,
                scope,
            } if arguments.iter().any(Value::is_symbolic) => {
                // The call records the arguments as they were before the attempt. Only
                // containers can change during it, so calls without them are kept (`Err`) and
                // recorded only when the attempt fails.
                let call = |arguments: &[Value<'ast>]| Term::Call {
                    callee: Box::new(Term::Global((*name).to_owned())),
                    this: None,
                    arguments: arguments.iter().map(Value::expr).collect(),
                };
                let recorded = if arguments.iter().all(Value::is_immutable) {
                    Err(arguments.clone())
                } else {
                    Ok(call(&arguments))
                };
                let checkpoint = self.checkpoint();
                match self.script(function, scope.as_ref(), this, arguments) {
                    Err(stop) if matches!(*stop, Stop::Unsupported(_)) => {
                        self.restore(checkpoint);
                        let call = recorded.unwrap_or_else(|kept| call(&kept));
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
                let locals = parameters(&arrow.params, arguments, 0)?;
                let scope = self.call_scope(locals, scope.as_ref());
                let script = self.session.script;
                let body = self
                    .session
                    .compiled
                    .scoped(ptr::from_ref(*arrow).addr(), || {
                        plan::scoped_arrow(script, arrow)
                    });
                self.body(
                    Frame {
                        this: this.clone(),
                        scope: CallScope::Own(scope),
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
                let all: Vec<Value<'ast>> = if bound.is_empty() {
                    arguments
                } else {
                    bound.iter().cloned().chain(arguments).collect()
                };
                self.apply(target.clone(), this.clone(), all)
            }
        }
    }

    /// Calls a script function, timing it when profiling.
    pub(super) fn script(
        &mut self,
        function: &'ast Function<'ast>,
        scope: Option<&Scope<'ast>>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let started = profiling::start();
        let result = self.run_script(function, scope, this, arguments);
        profiling::record(started, || format!("function@{}", function.span.start));
        result
    }

    /// Calls a script function: natively if it computes BLAKE3 compression on arguments the
    /// native version accepts, from the program's cache if it decrypts a string record decrypted
    /// before, or else interpreted.
    fn run_script(
        &mut self,
        function: &'ast Function<'ast>,
        scope: Option<&Scope<'ast>>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        if let Some(Intrinsic::Blake3Compress) =
            self.session.intrinsics.get(&intrinsic::address(function))
        {
            // Intrinsics may write to their arguments.
            for argument in &arguments {
                self.writable(argument)?;
            }
            if let Some(value) = intrinsic::blake3_compress(&arguments) {
                return Ok(value);
            }
        }
        // Handlers decrypt strings both by reading registers and by calling the decoder.
        if self
            .session
            .record_decoder
            .is_some_and(|decoder| ptr::eq(decoder, function))
            && let Some(decrypted) = self.decrypted
            && let [record] = &arguments[..]
            && let Some(key) = record_key(record)
        {
            if let Some(text) = decrypted.borrow().get(&key) {
                return Ok(text.clone());
            }
            let native = self
                .session
                .string_decoder
                .as_ref()
                .and_then(|decoder| decoder.decrypt(self, record));
            let text = match native {
                Some(text) => text,
                None => self.interpret(function, scope, this, arguments)?,
            };
            // A run that thawed a shared object may have computed the text differently.
            if matches!(text, Value::String(_)) && !self.thawed {
                decrypted.borrow_mut().insert(key, text.clone());
            }
            return Ok(text);
        }
        self.interpret(function, scope, this, arguments)
    }

    /// Runs a function through its routine (see [`Run::routine`]).
    fn interpret(
        &mut self,
        function: &'ast Function<'ast>,
        scope: Option<&Scope<'ast>>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let routine =
            Routine::function(function).ok_or_else(|| Stop::unsupported("declared function"))?;
        self.routine(routine, scope, this, arguments)
    }

    /// Runs a routine through its slot plan if it has one, or else through its scoped plan.
    pub(super) fn routine(
        &mut self,
        routine: Routine<'ast>,
        scope: Option<&Scope<'ast>>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let script = self.session.script;
        if self.setup.is_none()
            && let Some(plan) = self.session.compiled.slots(script, routine)
        {
            return self.call_plan(&plan, scope, this, arguments);
        }
        let all = Value::array(arguments.clone());
        // Room for `arguments` and the variables the body declares.
        let mut locals = parameters(routine.parameters, arguments, 1 + declared(routine))?;
        locals.insert(Binding::Global("arguments"), all);
        let scope = self.call_scope(locals, scope);
        let body = self
            .session
            .compiled
            .scoped(routine.address, || plan::scoped_routine(script, routine));
        self.body(
            Frame {
                this,
                scope: CallScope::Own(scope),
            },
            &body,
            &mut [],
        )
    }

    /// Creates a call scope with `locals`, nested in the function's captured scope. Functions
    /// declared beside the VM class use setup bindings during setup and session bindings
    /// afterward. Unresolved names fall back to session bindings.
    fn call_scope(
        &self,
        locals: HashMap<Binding<'ast>, Value<'ast>>,
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

/// Identifies a string record: the program, then numbers and arrays of numbers. A program's
/// records with the same contents decrypt to the same string.
fn record_key(record: &Value<'_>) -> Option<RecordKey> {
    let Value::Array(elements) = record else {
        return None;
    };
    let elements = elements.borrow();
    let (Value::Program, rest) = elements.split_first()? else {
        return None;
    };
    let bits = |value: &Value<'_>| match value {
        Value::Number(number) => Some(number.to_bits()),
        _ => None,
    };
    rest.iter()
        .map(|element| match element {
            Value::Array(numbers) => numbers
                .borrow()
                .iter()
                .map(bits)
                .collect::<Option<_>>()
                .map(RecordPart::Numbers),
            element => bits(element).map(RecordPart::Number),
        })
        .collect()
}

/// Binds call arguments to parameters and reserves `room` additional local slots.
fn parameters<'ast>(
    parameters: &FormalParameters<'_>,
    arguments: Vec<Value<'ast>>,
    room: usize,
) -> Evaluation<'ast, HashMap<Binding<'ast>, Value<'ast>>> {
    let names =
        extract::parameters(parameters).ok_or_else(|| Stop::unsupported("a parameter pattern"))?;
    let mut arguments = arguments.into_iter();
    let capacity = names.len() + room;
    let mut locals = HashMap::with_capacity_and_hasher(capacity, Default::default());
    for name in names {
        let argument = arguments.next().unwrap_or(Value::Undefined);
        locals.insert(Binding::Symbol(name.symbol_id()), argument);
    }
    Ok(locals)
}

/// Counts top-level variable declarations in `routine` to reserve local storage for a call.
fn declared(routine: Routine<'_>) -> usize {
    let count = |declaration: &VariableDeclaration<'_>| declaration.declarations.len();
    let statements = routine.statements.iter().map(|statement| match statement {
        Statement::VariableDeclaration(declaration) => count(declaration),
        _ => 0,
    });
    let declarations = routine
        .declarations
        .iter()
        .map(|declaration| count(declaration));
    statements.chain(declarations).sum()
}
