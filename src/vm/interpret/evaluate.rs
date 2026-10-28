//! Runs compiled plans from [`super::plan`]. Computes byte-dependent values and leaves
//! register-dependent values symbolic. Slot plans store locals in `locals`; scoped plans pass
//! no local slots.

use std::cell::RefCell;
use std::rc::Rc;
use std::{mem, slice};

use swc_core::ecma::ast::{BinaryOp, Expr, Stmt, UpdateOp};

use super::access::{self, Key};
use super::plan::{self, Case, Expression, FunctionPlan, Name, Property, Statement, Target};
use super::run::{Evaluation, Flow, Frame, Run, Stop};
use super::semantics;
use crate::vm::output::Term;
use crate::vm::value::{Env, Value};

/// Maximum handler loop count. Valid constants require fewer iterations; exceeding it indicates
/// invalid instruction bytes.
const MAXIMUM_ITERATIONS: usize = 1 << 16;

impl<'ast> Run<'ast, '_> {
    pub(super) fn statement(&mut self, statement: &'ast Stmt) -> Evaluation<'ast, Flow<'ast>> {
        self.execute_all(&plan::scoped(slice::from_ref(statement)), &mut [])
    }

    pub(in crate::vm) fn expression(&mut self, expr: &'ast Expr) -> Evaluation<'ast, Value<'ast>> {
        self.evaluate(&plan::scoped_expression(expr), &mut [])
    }

    pub(super) fn call_plan(
        &mut self,
        plan: &FunctionPlan<'ast>,
        this: Value<'ast>,
        mut arguments: Vec<Value<'ast>>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let mut locals = self.spare.locals.pop().unwrap_or_default();
        locals.resize(plan.locals, None);
        if let Some(slot) = plan.arguments {
            locals[slot] = Some(Value::array(arguments.clone()));
        }
        let mut values = arguments.drain(..);
        for &slot in &plan.parameters {
            locals[slot] = Some(values.next().unwrap_or(Value::Undefined));
        }
        drop(values);
        self.spare.arguments.push(arguments);
        let result = self.body(Frame::new(this), &plan.body, &mut locals);
        // Numeric locals need no destructor call.
        let assigned = locals.drain(..).flatten();
        for local in assigned {
            local.discard();
        }
        self.spare.locals.push(locals);
        result
    }

    /// Runs a function body in `frame`.
    pub(super) fn body(
        &mut self,
        frame: Frame<'ast>,
        body: &[Statement<'ast>],
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        self.frames.push(frame);
        let flow = self.execute_all(body, locals);
        self.frames.pop();
        match flow? {
            Flow::Return(value) => Ok(value),
            _ => Ok(Value::Undefined),
        }
    }

    fn execute_all(
        &mut self,
        statements: &[Statement<'ast>],
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Flow<'ast>> {
        for statement in statements {
            let flow = self.execute(statement, locals)?;
            if !matches!(flow, Flow::Normal) {
                return Ok(flow);
            }
        }
        Ok(Flow::Normal)
    }

    /// Checks whether `name` has already been declared in the current function.
    fn declared(&self, name: Name<'ast>, locals: &Locals<'ast>) -> bool {
        match name {
            Name::Local(slot, _) => locals[slot].is_some(),
            Name::Global(name) => self.frame().scope.borrow().variables.contains_key(name),
        }
    }

    /// Declares `name` with `value`.
    fn bind(&mut self, name: Name<'ast>, value: Value<'ast>, locals: &mut Locals<'ast>) {
        match name {
            Name::Local(slot, _) => locals[slot] = Some(value),
            Name::Global(name) => self.declare(name.clone(), value),
        }
    }

    fn execute(
        &mut self,
        statement: &Statement<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Flow<'ast>> {
        match statement {
            Statement::Switch(discriminant, cases) => {
                return self.switch(discriminant, cases, locals);
            }
            Statement::Empty => {}
            Statement::Expression(expression) => self.evaluate(expression, locals)?.discard(),
            Statement::Declare(declarations) => {
                for declaration in declarations {
                    let value = match &declaration.init {
                        Some(expression) => self.evaluate(expression, locals)?,
                        None if declaration.keeps && self.declared(declaration.name, locals) => {
                            continue;
                        }
                        None => Value::Undefined,
                    };
                    self.bind(declaration.name, value, locals);
                }
            }
            Statement::Try {
                block,
                parameter,
                handler,
                finalizer,
            } => {
                let mut outcome = self.execute_all(block, locals);
                if let Some(handler) = handler
                    && let Err(stop) = &mut outcome
                    && let Stop::Throw(exception) = &mut **stop
                {
                    let exception = mem::replace(exception, Value::Undefined);
                    if let Some(parameter) = parameter {
                        self.bind(*parameter, exception, locals);
                    }
                    outcome = self.execute_all(handler, locals);
                }
                // A jump from `finally` overrides the previous completion of the block.
                if let Some(finalizer) = finalizer {
                    match self.execute_all(finalizer, locals)? {
                        Flow::Normal => {}
                        flow => return Ok(flow),
                    }
                }
                return outcome;
            }
            Statement::Block(statements) => return self.execute_all(statements, locals),
            Statement::If(test, yes, no) => {
                let test = self.evaluate(test, locals)?;
                if self.decide(&test) {
                    return self.execute(yes, locals);
                }
                if let Some(no) = no {
                    return self.execute(no, locals);
                }
            }
            Statement::Return(expression) => {
                return Ok(Flow::Return(match expression {
                    Some(expression) => self.evaluate(expression, locals)?,
                    None => Value::Undefined,
                }));
            }
            Statement::Throw(expression) => {
                return Err(Stop::throw(self.evaluate(expression, locals)?));
            }
            Statement::Break(label) => return Ok(Flow::Break(label.cloned())),
            Statement::Continue(label) => return Ok(Flow::Continue(label.cloned())),
            Statement::Label(label, body) => {
                return Ok(match self.execute(body, locals)? {
                    Flow::Break(Some(target)) if target == **label => Flow::Normal,
                    flow => flow,
                });
            }
            Statement::Loop {
                init,
                test,
                update,
                body,
                body_first,
                label,
            } => {
                if let Some(init) = init {
                    self.execute(init, locals)?;
                }
                let mut first = *body_first;
                for _ in 0..MAXIMUM_ITERATIONS {
                    if !first && let Some(test) = test {
                        let condition = self.evaluate(test, locals)?;
                        let repeats = condition
                            .truthy()
                            .ok_or_else(|| Stop::unsupported("a loop over registers"))?;
                        if !repeats {
                            return Ok(Flow::Normal);
                        }
                    }
                    first = false;
                    match self.execute(body, locals)? {
                        Flow::Normal | Flow::Continue(None) => {}
                        Flow::Continue(Some(target)) if Some(&target) == *label => {}
                        Flow::Break(None) => return Ok(Flow::Normal),
                        flow => return Ok(flow),
                    }
                    if let Some(update) = update {
                        self.evaluate(update, locals)?;
                    }
                }
                return Err(Stop::unsupported("a loop past the longest constant"));
            }
        }
        Ok(Flow::Normal)
    }

    /// Runs from the first case strictly equal to `discriminant`, or else from the default.
    fn switch(
        &mut self,
        discriminant: &Expression<'ast>,
        cases: &[Case<'ast>],
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Flow<'ast>> {
        let discriminant = self.evaluate(discriminant, locals)?;
        let mut matched = None;
        let mut default = None;
        for (index, case) in cases.iter().enumerate() {
            let Some(test) = &case.test else {
                default = default.or(Some(index));
                continue;
            };
            let test = self.evaluate(test, locals)?;
            let equal = semantics::strict_equal(&discriminant, &test)
                .ok_or_else(|| Stop::unsupported("a switch over registers"))?;
            if equal {
                matched = Some(index);
                break;
            }
        }
        let Some(start) = matched.or(default) else {
            return Ok(Flow::Normal);
        };
        for case in &cases[start..] {
            match self.execute_all(&case.body, locals)? {
                Flow::Normal => {}
                Flow::Break(None) => return Ok(Flow::Normal),
                flow => return Ok(flow),
            }
        }
        Ok(Flow::Normal)
    }

    fn property(
        &mut self,
        property: &Property<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Key<'ast, 'ast>> {
        Ok(match property {
            Property::Name(name) => Key::name(name),
            Property::Computed(expression) => Key::from(self.evaluate(expression, locals)?),
        })
    }

    /// Reads common constants and locals directly. Delegates other nodes to separate functions
    /// to keep recursive stack frames small.
    #[inline(always)]
    fn evaluate(
        &mut self,
        expression: &Expression<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        match expression {
            Expression::Constant(value) => Ok(copied(value)),
            Expression::Name(Name::Local(slot, _)) if let Some(value) = &locals[*slot] => {
                Ok(match value {
                    Value::Symbolic(_) => self.refined(value),
                    value => copied(value),
                })
            }
            Expression::Binary(operator, left, right) => {
                self.binary(*operator, left, right, locals)
            }
            Expression::Arithmetic { .. } => self.arithmetic(expression, locals),
            Expression::Member(object, property) => self.member(object, property, locals),
            Expression::Assign(target, operator, right) => {
                self.assignment(target, *operator, right, locals)
            }
            Expression::Update {
                target,
                operator,
                prefix,
            } => self.update(target, *operator, *prefix, locals),
            Expression::Call(callee, arguments) => self.call(callee, arguments, locals),
            Expression::Logical {
                operator,
                left,
                right,
                pure,
            } => self.logical(*operator, left, right, *pure, locals),
            expression => self.other(expression, locals),
        }
    }

    #[inline(never)]
    fn binary(
        &mut self,
        operator: BinaryOp,
        left: &Expression<'ast>,
        right: &Expression<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let left = self.evaluate(left, locals)?;
        let right = self.evaluate(right, locals)?;
        Ok(binary_value(operator, left, right))
    }

    #[inline(never)]
    fn arithmetic(
        &mut self,
        expression: &Expression<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        Ok(number_value(self.number(expression, locals)?))
    }

    /// Evaluates numeric arithmetic without wrapping intermediate results. If an operand is
    /// nonnumeric, switches to general evaluation for that operator and its enclosing
    /// operators, reusing evaluated operands. Returns that general result in `Err`.
    fn number(
        &mut self,
        expression: &Expression<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Result<f64, Value<'ast>>> {
        let Expression::Arithmetic {
            operator,
            operation,
            left,
            right,
        } = expression
        else {
            return Ok(match self.evaluate(expression, locals)? {
                Value::Number(number) => Ok(number),
                value => Err(value),
            });
        };
        let left = self.operand(left, locals)?;
        let right = self.operand(right, locals)?;
        Ok(match (left, right) {
            (Ok(left), Ok(right)) => Ok(operation(left, right)),
            (left, right) => Err(binary_value(
                *operator,
                number_value(left),
                number_value(right),
            )),
        })
    }

    /// An operand of arithmetic. Reads numeric constants and locals without a call.
    #[inline(always)]
    fn operand(
        &mut self,
        expression: &Expression<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Result<f64, Value<'ast>>> {
        match expression {
            Expression::Constant(Value::Number(number)) => Ok(Ok(*number)),
            Expression::Name(Name::Local(slot, _))
                if let Some(Value::Number(number)) = locals[*slot] =>
            {
                Ok(Ok(number))
            }
            expression => self.number(expression, locals),
        }
    }

    #[inline(never)]
    fn member(
        &mut self,
        object: &Expression<'ast>,
        property: &Property<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let object = self.evaluate(object, locals)?;
        let key = self.property(property, locals)?;
        self.get(&object, &key)
    }

    #[inline(never)]
    fn other(
        &mut self,
        expression: &Expression<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        Ok(match expression {
            Expression::Name(name) => self.lookup(name.atom())?,
            Expression::This => self.frame().this.clone(),
            Expression::Sequence(expressions) => {
                let mut value = Value::Undefined;
                for expression in expressions {
                    value = self.evaluate(expression, locals)?;
                }
                value
            }
            Expression::New(callee, arguments) => self.construction(callee, arguments, locals)?,
            Expression::Unary(operator, argument) => {
                let argument = self.evaluate(argument, locals)?;
                semantics::unary_value(*operator, argument)
            }
            Expression::Conditional(test, yes, no) => {
                let test = self.evaluate(test, locals)?;
                let branch = if self.decide(&test) { yes } else { no };
                self.evaluate(branch, locals)?
            }
            Expression::Array(elements) => {
                let mut values = Vec::with_capacity(elements.len());
                for element in elements {
                    values.push(match element {
                        Some(element) => self.evaluate(element, locals)?,
                        None => Value::Undefined,
                    });
                }
                Value::array(values)
            }
            Expression::Object(properties) => {
                let mut entries = Vec::with_capacity(properties.len());
                for (key, value) in properties {
                    let key = self.property(key, locals)?;
                    let name = key
                        .property()
                        .ok_or_else(|| access::unsupported("object key", &key))?;
                    entries.push((name, self.evaluate(value, locals)?));
                }
                Value::Object(Rc::new(RefCell::new(entries)))
            }
            Expression::Function(name, function) => self.function_value(name.cloned(), function),
            Expression::Arrow(arrow) => self.arrow_value(arrow),
            Expression::Unsupported(reason) => return Err(Stop::unsupported(reason)),
            // Keep this list synchronized with the cases handled directly by `evaluate`.
            Expression::Constant(_)
            | Expression::Binary(..)
            | Expression::Arithmetic { .. }
            | Expression::Member(..)
            | Expression::Assign(..)
            | Expression::Update { .. }
            | Expression::Call(..)
            | Expression::Logical { .. } => unreachable!("dispatched by evaluate"),
        })
    }

    // Handle calls and writes separately because they keep several values and keys live. Avoid
    // adding that storage to every recursive operand frame.
    #[inline(never)]
    fn call(
        &mut self,
        callee: &Expression<'ast>,
        arguments: &[Expression<'ast>],
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let (callee, this) = match callee {
            Expression::Member(object, property) => {
                let object = self.evaluate(object, locals)?;
                let key = self.property(property, locals)?;
                (self.get(&object, &key)?, object)
            }
            callee => (self.evaluate(callee, locals)?, Value::Undefined),
        };
        let arguments = self.arguments(arguments, locals)?;
        self.apply(callee, this, arguments)
    }

    /// Evaluates call arguments into a reused buffer.
    fn arguments(
        &mut self,
        arguments: &[Expression<'ast>],
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Vec<Value<'ast>>> {
        let mut values = self.spare.arguments.pop().unwrap_or_default();
        for argument in arguments {
            values.push(self.evaluate(argument, locals)?);
        }
        Ok(values)
    }

    #[inline(never)]
    fn construction(
        &mut self,
        callee: &Expression<'ast>,
        arguments: &[Expression<'ast>],
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let callee = self.evaluate(callee, locals)?;
        let arguments = self.arguments(arguments, locals)?;
        self.construct(callee, arguments)
    }

    #[inline(never)]
    fn assignment(
        &mut self,
        target: &Target<'ast>,
        operator: Option<BinaryOp>,
        right: &Expression<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let target = self.locate(target, locals)?;
        let value = match operator {
            None => self.evaluate(right, locals)?,
            Some(BinaryOp::LogicalAnd | BinaryOp::LogicalOr | BinaryOp::NullishCoalescing) => {
                return Err(Stop::unsupported("a logical assignment"));
            }
            // The script reapplies a new rolling mask to the program counter or key. The
            // interpreter keeps that mask at zero; see `crate::vm::registers`.
            Some(_) if matches!(&target, Location::Member(Value::Registers, Key::Name(_))) => {
                self.evaluate(right, locals)?;
                return self.read(&target, locals);
            }
            // The target's old value is read before the right side runs.
            Some(operator) => {
                let old = self.read(&target, locals)?;
                let right = self.evaluate(right, locals)?;
                // Release the old value before overwriting it, allowing `s += c` to append in
                // place.
                match &target {
                    Location::Name(Name::Local(slot, _)) if locals[*slot].is_some() => {
                        locals[*slot] = Some(Value::Undefined);
                    }
                    Location::Name(name) => {
                        Env::assign(&self.frame().scope, name.atom(), Value::Undefined);
                    }
                    Location::Member(..) => {}
                }
                binary_value(operator, old, right)
            }
        };
        self.write(target, value.clone(), locals)?;
        Ok(value)
    }

    #[inline(never)]
    fn update(
        &mut self,
        target: &Target<'ast>,
        operator: UpdateOp,
        prefix: bool,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        // A counter: the local is read and written in place.
        if let Target::Name(Name::Local(slot, _)) = target
            && let Some(Value::Number(number)) = &mut locals[*slot]
        {
            let change = updated(operator, prefix, *number);
            *number = change.written;
            return Ok(Value::Number(change.value));
        }
        let target = self.locate(target, locals)?;
        let old = self.read(&target, locals)?;
        let old = old
            .number()
            .ok_or_else(|| Stop::unsupported(&format!("incrementing {}", old.expr())))?;
        let change = updated(operator, prefix, old);
        self.write(target, Value::Number(change.written), locals)?;
        Ok(Value::Number(change.value))
    }

    /// Evaluates `&&`, `||`, or `??`, evaluating `right` only when needed.
    #[inline(never)]
    fn logical(
        &mut self,
        operator: BinaryOp,
        left: &Expression<'ast>,
        right: &Expression<'ast>,
        pure: bool,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        let left = self.evaluate(left, locals)?;
        // Condition controlling right-operand evaluation and the branch direction that
        // evaluates it.
        let (test, runs_right) = match operator {
            BinaryOp::LogicalAnd => (left.clone(), true),
            BinaryOp::LogicalOr => (left.clone(), false),
            _ => (
                semantics::binary_value(BinaryOp::EqEq, left.clone(), Value::Null),
                true,
            ),
        };
        if test.truthy().is_none() && pure {
            // An effect-free right operand may become a symbolic term only if evaluating it
            // cannot introduce an exception on a skipped path.
            let effects = self.effects.len();
            if let Ok(right) = self.evaluate(right, locals) {
                debug_assert_eq!(
                    effects,
                    self.effects.len(),
                    "a pure right side runs without effects"
                );
                return Ok(Value::symbolic(Term::Binary(
                    operator,
                    Box::new(left.expr()),
                    Box::new(right.expr()),
                )));
            }
        }
        if self.decide(&test) == runs_right {
            self.evaluate(right, locals)
        } else {
            Ok(left)
        }
    }

    #[inline]
    fn locate(
        &mut self,
        target: &Target<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Location<'ast>> {
        Ok(match target {
            Target::Name(name) => Location::Name(*name),
            Target::Member(object, key) => {
                let object = self.evaluate(object, locals)?;
                let key = self.property(key, locals)?;
                Location::Member(object, key)
            }
        })
    }

    fn read(
        &mut self,
        target: &Location<'ast>,
        locals: &Locals<'ast>,
    ) -> Evaluation<'ast, Value<'ast>> {
        match target {
            Location::Name(Name::Local(slot, name)) => match &locals[*slot] {
                Some(value) => Ok(value.clone()),
                None => self.lookup(name),
            },
            Location::Name(Name::Global(name)) => self.lookup(name),
            Location::Member(object, key) => self.get(object, key),
        }
    }

    /// Writes declared locals directly, since they are the most common assignment target.
    #[inline]
    fn write(
        &mut self,
        target: Location<'ast>,
        value: Value<'ast>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, ()> {
        match target {
            Location::Name(Name::Local(slot, name)) => {
                // Until its declaration runs, a local's name still assigns a session binding.
                if locals[slot].is_none()
                    && (self.globals.contains_key(name) || self.session.bindings.contains_key(name))
                {
                    self.assign_name(name, value);
                } else {
                    locals[slot] = Some(value);
                }
            }
            Location::Name(Name::Global(name)) => self.assign_name(name, value),
            Location::Member(object, key) => return self.set(&object, &key, value),
        }
        Ok(())
    }
}

/// Clones a value, using a fast path for numbers.
#[inline(always)]
fn copied<'a>(value: &Value<'a>) -> Value<'a> {
    match value {
        Value::Number(number) => Value::Number(*number),
        value => value.clone(),
    }
}

/// Extracts the value from a [`Run::number`] result.
#[inline(always)]
fn number_value(number: Result<f64, Value<'_>>) -> Value<'_> {
    number.map_or_else(|value| value, Value::Number)
}

/// Slot-indexed call locals; `None` until declared or written.
type Locals<'ast> = [Option<Value<'ast>>];

enum Location<'ast> {
    Name(Name<'ast>),
    Member(Value<'ast>, Key<'ast, 'ast>),
}

/// Applies [`semantics::binary_value`] to numeric operands without coercion or symbolic terms.
#[inline(always)]
fn binary_value<'a>(operator: BinaryOp, left: Value<'a>, right: Value<'a>) -> Value<'a> {
    let (&Value::Number(a), &Value::Number(b)) = (&left, &right) else {
        return semantics::binary_value(operator, left, right);
    };
    left.discard();
    right.discard();
    if let Some(operation) = semantics::numeric(operator) {
        return Value::Number(operation(a, b));
    }
    Value::Bool(match operator {
        BinaryOp::EqEq | BinaryOp::EqEqEq => a == b,
        BinaryOp::NotEq | BinaryOp::NotEqEq => a != b,
        BinaryOp::Lt => a < b,
        BinaryOp::LtEq => a <= b,
        BinaryOp::Gt => a > b,
        BinaryOp::GtEq => a >= b,
        _ => return semantics::binary_value(operator, Value::Number(a), Value::Number(b)),
    })
}

/// Values produced and stored by an increment or decrement.
struct Updated {
    /// The number written back.
    written: f64,
    /// Expression result: the new number for prefix form, or the old number for postfix form.
    value: f64,
}

/// Computes the result and stored value for `++` or `--` applied to `old`.
#[inline(always)]
fn updated(operator: UpdateOp, prefix: bool, old: f64) -> Updated {
    let new = match operator {
        UpdateOp::PlusPlus => old + 1.0,
        UpdateOp::MinusMinus => old - 1.0,
    };
    Updated {
        written: new,
        value: if prefix { new } else { old },
    }
}

#[cfg(test)]
mod tests;
