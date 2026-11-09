//! Runs plans compiled by [`super::compile`]. Computes byte-dependent values and leaves
//! register-dependent values symbolic. Slot plans store locals in `locals`; scoped plans pass
//! no local slots.

use oxc::ast::ast::{Expression as Expr, Statement as Stmt};
use oxc::syntax::operator::{BinaryOperator, LogicalOperator, UpdateOperator};

use super::access::Key;
use super::compile::{self, Code};
use super::plan::{self, FunctionPlan, Name};
use super::run::{CallScope, Evaluation, Flow, Frame, Run, Stop};
use super::semantics;
use crate::vm::output::Term;
use crate::vm::value::{Scope, Value};

impl<'ast> Run<'ast, '_> {
    /// Runs `statement` through a scoped plan.
    pub(super) fn statement(
        &mut self,
        statement: &'ast Stmt<'ast>,
    ) -> Evaluation<'ast, Flow<'ast>> {
        compile::statement(&plan::scoped_statement(self.session.script, statement))(self, &mut [])
    }

    /// Evaluates `expression` through a scoped plan.
    pub(in crate::vm) fn expression(
        &mut self,
        expression: &'ast Expr<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        compile::compute(&plan::scoped_expression(self.session.script, expression))(self, &mut [])
    }

    /// Calls a slot plan. Its scope holds the locals nested functions mention, inside `closed`,
    /// the scope the function captured, if any.
    pub(super) fn call_plan(
        &mut self,
        plan: &FunctionPlan<'ast>,
        closed: Option<&Scope<'ast>>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let mut locals = self.enter_plan(plan, closed, this, arguments);
        let result = compile::run_all(&plan.code, self, &mut locals).map(returned);
        self.frames.pop();
        self.release_locals(locals);
        result
    }

    /// Calls a handler's slot plan as [`Run::call_plan`] does, with no captured scope. Before
    /// each top-level statement, `before` sees the statement's index and the locals.
    pub(super) fn call_handler(
        &mut self,
        plan: &FunctionPlan<'ast>,
        this: Value<'ast>,
        arguments: Vec<Value<'ast>>,
        before: &mut dyn FnMut(&Self, usize, &Locals<'ast>),
    ) -> Evaluation<'ast, Value<'ast>> {
        let mut locals = self.enter_plan(plan, None, this, arguments);
        let result = self.handler_statements(plan, 0, &mut locals, before);
        self.release_locals(locals);
        result
    }

    /// Binds a slot plan's parameters and pushes its frame. Returns the call's locals.
    #[inline]
    fn enter_plan(
        &mut self,
        plan: &FunctionPlan<'ast>,
        closed: Option<&Scope<'ast>>,
        this: Value<'ast>,
        mut arguments: Vec<Value<'ast>>,
    ) -> Vec<Option<Value<'ast>>> {
        let mut locals = self.spare.locals.pop().unwrap_or_default();
        locals.resize(plan.locals, None);
        if let Some(slot) = plan.arguments {
            locals[slot] = Some(Value::array(arguments.clone()));
        }
        let mut frame = Frame {
            this,
            scope: CallScope::Deferred(closed.cloned()),
        };
        let mut values = arguments.drain(..);
        for parameter in &plan.parameters {
            let value = values.next().unwrap_or(Value::Undefined);
            match *parameter {
                Name::Local(slot, _) => locals[slot] = Some(value),
                Name::Scoped(binding) => {
                    frame
                        .own_scope()
                        .borrow_mut()
                        .variables
                        .insert(binding, value);
                }
            }
        }
        drop(values);
        self.spare.arguments.push(arguments);
        self.frames.push(frame);
        locals
    }

    /// Runs a handler's top-level statements from `start` in the frame the run holds, then
    /// leaves that frame, as [`Run::body`] does.
    pub(super) fn handler_statements(
        &mut self,
        plan: &FunctionPlan<'ast>,
        start: usize,
        locals: &mut Locals<'ast>,
        before: &mut dyn FnMut(&Self, usize, &Locals<'ast>),
    ) -> Evaluation<'ast, Value<'ast>> {
        let mut flow = Ok(Flow::Normal);
        for (index, statement) in plan.code.iter().enumerate().skip(start) {
            before(self, index, locals);
            flow = statement(self, locals);
            if !matches!(flow, Ok(Flow::Normal)) {
                break;
            }
        }
        self.frames.pop();
        flow.map(returned)
    }

    /// Returns a call's locals to the spare buffers.
    fn release_locals(&mut self, mut locals: Vec<Option<Value<'ast>>>) {
        // Numeric locals need no destructor call.
        for local in locals.drain(..).flatten() {
            local.discard();
        }
        self.spare.locals.push(locals);
    }

    /// Runs a function body in `frame`.
    pub(super) fn body(
        &mut self,
        frame: Frame<'ast>,
        body: &[Code<'ast>],
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        self.frames.push(frame);
        let flow = compile::run_all(body, self, locals);
        self.frames.pop();
        flow.map(returned)
    }

    /// Declares `name` with `value`.
    pub(super) fn bind(&mut self, name: Name<'ast>, value: Value<'ast>, locals: &mut Locals<'ast>) {
        match name {
            Name::Local(slot, _) => locals[slot] = Some(value),
            Name::Scoped(binding) => self.declare(binding, value),
        }
    }

    /// Assigns to `target` with `operator`, as in `target += right`, where `right` evaluates
    /// the right side.
    #[inline]
    pub(super) fn compound(
        &mut self,
        target: Location<'ast>,
        operator: BinaryOperator,
        locals: &mut Locals<'ast>,
        right: impl FnOnce(&mut Self, &mut Locals<'ast>) -> Evaluation<'ast, Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        // The script reapplies a new rolling mask to the program counter or key. The
        // interpreter keeps that mask at zero; see `crate::vm::registers`.
        if matches!(&target, Location::Member(Value::Registers, Key::Name(_))) {
            right(self, locals)?;
            return self.read(&target, locals);
        }
        // The target's old value is read before the right side runs.
        let old = self.read(&target, locals)?;
        let right = right(self, locals)?;
        // Release the old value before overwriting it, allowing `s += c` to append in place.
        match &target {
            Location::Name(Name::Local(slot, _)) if locals[*slot].is_some() => {
                locals[*slot] = Some(Value::Undefined);
            }
            Location::Name(name) => {
                self.frame().assign(name.binding(), Value::Undefined);
            }
            Location::Member(..) => {}
        }
        let value = binary_value(operator, old, right);
        self.write(target, value.clone(), locals)?;
        Ok(value)
    }

    /// Applies `++` or `--` to the number at `target`.
    pub(super) fn update_location(
        &mut self,
        target: Location<'ast>,
        operator: UpdateOperator,
        prefix: bool,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let old = self.read(&target, locals)?;
        let mut number = old
            .number()
            .ok_or_else(|| Stop::unsupported(&format!("incrementing {}", old.expr())))?;
        let value = step(operator, prefix, &mut number);
        self.write(target, Value::Number(number), locals)?;
        Ok(Value::Number(value))
    }

    /// Finishes `&&`, `||`, or `??` after its left side, calling `right` to evaluate the right
    /// side only when needed.
    #[inline]
    pub(super) fn short_circuit(
        &mut self,
        operator: LogicalOperator,
        left: Value<'ast>,
        pure: bool,
        locals: &mut Locals<'ast>,
        right: impl Fn(&mut Self, &mut Locals<'ast>) -> Evaluation<'ast, Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        // Condition controlling right-operand evaluation and the branch direction that
        // evaluates it.
        let (test, runs_right) = match operator {
            LogicalOperator::And => (left.clone(), true),
            LogicalOperator::Or => (left.clone(), false),
            LogicalOperator::Coalesce => (
                semantics::binary_value(BinaryOperator::Equality, left.clone(), Value::Null),
                true,
            ),
        };
        if test.truthy().is_none() && pure {
            // An effect-free right operand may become a symbolic term only if evaluating it
            // cannot introduce an exception on a skipped path.
            let effects = self.effects.len();
            if let Ok(right) = right(self, locals) {
                debug_assert_eq!(
                    effects,
                    self.effects.len(),
                    "a pure right side runs without effects"
                );
                return Ok(Value::symbolic(Term::Logical(
                    operator,
                    Box::new(left.expr()),
                    Box::new(right.expr()),
                )));
            }
        }
        if self.decide(&test) == runs_right {
            right(self, locals)
        } else {
            Ok(left)
        }
    }

    pub(super) fn read(
        &mut self,
        target: &Location<'ast>,
        locals: &Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        match target {
            Location::Name(Name::Local(slot, binding)) => match &locals[*slot] {
                Some(value) => Ok(value.clone()),
                None => self.lookup(*binding),
            },
            Location::Name(Name::Scoped(binding)) => self.lookup(*binding),
            Location::Member(object, key) => self.get(object, key),
        }
    }

    /// Writes locals directly, since they are the most common assignment target.
    #[inline]
    pub(super) fn write(
        &mut self,
        target: Location<'ast>,
        value: Value<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, ()> {
        match target {
            Location::Name(Name::Local(slot, _)) => locals[slot] = Some(value),
            Location::Name(Name::Scoped(binding)) => self.assign(binding, value),
            Location::Member(object, key) => return self.set(&object, &key, value),
        }
        Ok(())
    }
}

/// Clones a value, using a fast path for numbers.
#[inline(always)]
pub(super) fn copied<'a>(value: &Value<'a>) -> Value<'a> {
    match value {
        Value::Number(number) => Value::Number(*number),
        value => value.clone(),
    }
}

/// Converts the result of compiled numeric evaluation to a value.
#[inline(always)]
pub(super) fn number_value(number: Result<f64, Value<'_>>) -> Value<'_> {
    number.map_or_else(|value| value, Value::Number)
}

/// Slot-indexed call locals; `None` until declared or written.
pub(super) type Locals<'ast> = [Option<Value<'ast>>];

pub(super) enum Location<'ast> {
    Name(Name<'ast>),
    Member(Value<'ast>, Key<'ast, 'ast>),
}

/// Applies [`semantics::binary_value`] to numeric operands without coercion or symbolic terms.
#[inline(always)]
pub(super) fn binary_value<'a>(
    operator: BinaryOperator,
    left: Value<'a>,
    right: Value<'a>,
) -> Value<'a> {
    let (&Value::Number(a), &Value::Number(b)) = (&left, &right) else {
        return semantics::binary_value(operator, left, right);
    };
    left.discard();
    right.discard();
    if let Some(operation) = semantics::numeric(operator) {
        return Value::Number(operation(a, b));
    }
    Value::Bool(match operator {
        BinaryOperator::Equality | BinaryOperator::StrictEquality => a == b,
        BinaryOperator::Inequality | BinaryOperator::StrictInequality => a != b,
        BinaryOperator::LessThan => a < b,
        BinaryOperator::LessEqualThan => a <= b,
        BinaryOperator::GreaterThan => a > b,
        BinaryOperator::GreaterEqualThan => a >= b,
        _ => return semantics::binary_value(operator, Value::Number(a), Value::Number(b)),
    })
}

/// Applies `++` or `--` to `number` in place. Returns the expression's result: the new number
/// in prefix form, or the old number in postfix form.
#[inline(always)]
pub(super) fn step(operator: UpdateOperator, prefix: bool, number: &mut f64) -> f64 {
    let old = *number;
    *number = match operator {
        UpdateOperator::Increment => old + 1.0,
        UpdateOperator::Decrement => old - 1.0,
    };
    if prefix { *number } else { old }
}

/// The result of a call whose body completed with `flow`.
#[inline]
fn returned(flow: Flow<'_>) -> Value<'_> {
    match flow {
        Flow::Return(value) => value,
        _ => Value::Undefined,
    }
}

#[cfg(test)]
mod tests;
