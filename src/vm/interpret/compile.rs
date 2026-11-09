//! Compiles plans into closures, which resolve each node's kind and operands once, when the
//! plan is compiled.
//!
//! A few common shapes in slot plans run more directly: assignments to locals in statement
//! position skip the result they would discard, and arithmetic reads program bytes at local
//! indexes, as in `program[pc++]`, without building values.

use std::cell::RefCell;
use std::mem;
use std::rc::Rc;

use oxc::syntax::operator::{BinaryOperator, UpdateOperator};

use super::access::{self, Key};
use super::evaluate::{self, Locals, Location};
use super::plan::{Case, Declaration, Expression, Name, Property, Statement, Target};
use super::run::{Evaluation, Flow, Run, Stop};
use super::semantics;
use crate::vm::convert;
use crate::vm::value::Value;

/// Maximum handler loop count. Valid constants require fewer iterations; exceeding it indicates
/// invalid instruction bytes.
const MAXIMUM_ITERATIONS: usize = 1 << 16;

/// Compiled code producing `T`.
type Compiled<'ast, T> = Box<
    dyn for<'session> Fn(&mut Run<'ast, 'session>, &mut Locals<'ast>) -> Evaluation<'ast, T> + 'ast,
>;

/// A compiled statement.
pub(super) type Code<'ast> = Compiled<'ast, Flow<'ast>>;

/// A compiled expression.
type Compute<'ast> = Compiled<'ast, Value<'ast>>;

/// A compiled operand of arithmetic: a number, or the value of a nonnumeric operand.
type Numeric<'ast> = Compiled<'ast, Result<f64, Value<'ast>>>;

/// Compiles a function body or block.
pub(super) fn statements<'ast>(statements: &[Statement<'ast>]) -> Vec<Code<'ast>> {
    statements.iter().map(statement).collect()
}

/// Runs statements in order until one jumps.
pub(super) fn run_all<'ast>(
    code: &[Code<'ast>],
    run: &mut Run<'ast, '_>,
    locals: &mut Locals<'ast>,
) -> Evaluation<'ast, Flow<'ast>> {
    for statement in code {
        let flow = statement(run, locals)?;
        if !matches!(flow, Flow::Normal) {
            return Ok(flow);
        }
    }
    Ok(Flow::Normal)
}

pub(super) fn statement<'ast>(statement: &Statement<'ast>) -> Code<'ast> {
    match statement {
        Statement::Switch(discriminant, cases) => switch(discriminant, cases),
        Statement::Empty => code(|_, _| Ok(Flow::Normal)),
        Statement::Expression(expression) => effect(expression),
        Statement::Declare(declarations) => declare(declarations),
        Statement::Try {
            block,
            parameter,
            handler,
            finalizer,
        } => {
            let block = statements(block);
            let parameter = *parameter;
            let handler = handler.as_deref().map(statements);
            let finalizer = finalizer.as_deref().map(statements);
            code(move |run, locals| {
                let mut outcome = run_all(&block, run, locals);
                if let Some(handler) = &handler
                    && let Err(stop) = &mut outcome
                    && let Stop::Throw(exception) = &mut **stop
                {
                    let exception = mem::replace(exception, Value::Undefined);
                    if let Some(parameter) = parameter {
                        run.bind(parameter, exception, locals);
                    }
                    outcome = run_all(handler, run, locals);
                }
                // A jump from `finally` overrides the previous completion of the block.
                if let Some(finalizer) = &finalizer {
                    match run_all(finalizer, run, locals)? {
                        Flow::Normal => {}
                        flow => return Ok(flow),
                    }
                }
                outcome
            })
        }
        Statement::Block(block) => {
            let block = statements(block);
            code(move |run, locals| run_all(&block, run, locals))
        }
        Statement::If(test, yes, no) => {
            let test = compute(test);
            let yes = self::statement(yes);
            let no = no.as_deref().map(self::statement);
            code(move |run, locals| {
                let test = test(run, locals)?;
                if run.decide(&test) {
                    return yes(run, locals);
                }
                no.as_ref().map_or(Ok(Flow::Normal), |no| no(run, locals))
            })
        }
        Statement::Return(Some(expression)) => {
            let expression = compute(expression);
            code(move |run, locals| Ok(Flow::Return(expression(run, locals)?)))
        }
        Statement::Return(None) => code(|_, _| Ok(Flow::Return(Value::Undefined))),
        Statement::Throw(expression) => {
            let expression = compute(expression);
            code(move |run, locals| Err(Stop::throw(expression(run, locals)?)))
        }
        Statement::Break(label) => {
            let label = *label;
            code(move |_, _| Ok(Flow::Break(label)))
        }
        Statement::Continue(label) => {
            let label = *label;
            code(move |_, _| Ok(Flow::Continue(label)))
        }
        Statement::Label(label, body) => {
            let label = *label;
            let body = self::statement(body);
            code(move |run, locals| {
                Ok(match body(run, locals)? {
                    Flow::Break(Some(target)) if target == label => Flow::Normal,
                    flow => flow,
                })
            })
        }
        Statement::Loop {
            init,
            test,
            update,
            body,
            body_first,
            label,
        } => {
            let init = init.as_deref().map(self::statement);
            let test = test.as_ref().map(compute);
            let update = update.as_ref().map(compute);
            let body = self::statement(body);
            let (body_first, label) = (*body_first, *label);
            code(move |run, locals| {
                if let Some(init) = &init {
                    init(run, locals)?;
                }
                let mut first = body_first;
                for _ in 0..MAXIMUM_ITERATIONS {
                    if !first && let Some(test) = &test {
                        let repeats = test(run, locals)?.truthy();
                        if !repeats.ok_or_else(|| Stop::unsupported("a loop over registers"))? {
                            return Ok(Flow::Normal);
                        }
                    }
                    first = false;
                    match body(run, locals)? {
                        Flow::Normal | Flow::Continue(None) => {}
                        Flow::Continue(Some(target)) if Some(target) == label => {}
                        Flow::Break(None) => return Ok(Flow::Normal),
                        flow => return Ok(flow),
                    }
                    if let Some(update) = &update {
                        update(run, locals)?;
                    }
                }
                Err(Stop::unsupported("a loop past the longest constant"))
            })
        }
    }
}

/// An expression statement. Assigning a local writes the value without keeping the result.
fn effect<'ast>(expression: &Expression<'ast>) -> Code<'ast> {
    if let Expression::Assign(Target::Name(name @ Name::Local(..)), None, right) = expression {
        let (name, right) = (*name, compute(right));
        return code(move |run, locals| {
            let value = right(run, locals)?;
            run.write(Location::Name(name), value, locals)?;
            Ok(Flow::Normal)
        });
    }
    let expression = compute(expression);
    code(move |run, locals| {
        expression(run, locals)?.discard();
        Ok(Flow::Normal)
    })
}

fn declare<'ast>(declarations: &[Declaration<'ast>]) -> Code<'ast> {
    let declarations: Vec<_> = declarations
        .iter()
        .map(|Declaration { name, init, keeps }| (*name, init.as_ref().map(compute), *keeps))
        .collect();
    code(move |run, locals| {
        for (name, init, keeps) in &declarations {
            let value = match init {
                Some(init) => init(run, locals)?,
                None if *keeps
                    && match *name {
                        Name::Local(slot, _) => locals[slot].is_some(),
                        Name::Scoped(binding) => run.frame().declares(binding),
                    } =>
                {
                    continue;
                }
                None => Value::Undefined,
            };
            run.bind(*name, value, locals);
        }
        Ok(Flow::Normal)
    })
}

/// Runs from the first case strictly equal to the discriminant, or else from the default.
fn switch<'ast>(discriminant: &Expression<'ast>, cases: &[Case<'ast>]) -> Code<'ast> {
    let discriminant = compute(discriminant);
    let cases: Vec<_> = cases
        .iter()
        .map(|case| (case.test.as_ref().map(compute), statements(&case.body)))
        .collect();
    code(move |run, locals| {
        let discriminant = discriminant(run, locals)?;
        let mut matched = None;
        let mut default = None;
        for (index, (test, _)) in cases.iter().enumerate() {
            let Some(test) = test else {
                default = default.or(Some(index));
                continue;
            };
            let equal = semantics::strict_equal(&discriminant, &test(run, locals)?);
            if equal.ok_or_else(|| Stop::unsupported("a switch over registers"))? {
                matched = Some(index);
                break;
            }
        }
        let Some(start) = matched.or(default) else {
            return Ok(Flow::Normal);
        };
        for (_, body) in &cases[start..] {
            match run_all(body, run, locals)? {
                Flow::Normal => {}
                Flow::Break(None) => return Ok(Flow::Normal),
                flow => return Ok(flow),
            }
        }
        Ok(Flow::Normal)
    })
}

/// A compiled property key.
enum Keyed<'ast> {
    Name(&'ast str),
    Computed(Compute<'ast>),
}

impl<'ast> Keyed<'ast> {
    fn new(property: &Property<'ast>) -> Self {
        match property {
            Property::Name(name) => Self::Name(name),
            Property::Computed(expression) => Self::Computed(compute(expression)),
        }
    }

    fn key(
        &self,
        run: &mut Run<'ast, '_>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Key<'ast, 'ast>> {
        Ok(match self {
            Self::Name(name) => Key::name(name),
            Self::Computed(expression) => Key::from(expression(run, locals)?),
        })
    }
}

/// A compiled assignment target.
enum Located<'ast> {
    Name(Name<'ast>),
    Member(Compute<'ast>, Keyed<'ast>),
}

impl<'ast> Located<'ast> {
    fn new(target: &Target<'ast>) -> Self {
        match target {
            Target::Name(name) => Self::Name(*name),
            Target::Member(object, key) => Self::Member(compute(object), Keyed::new(key)),
        }
    }

    fn locate(
        &self,
        run: &mut Run<'ast, '_>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Location<'ast>> {
        Ok(match self {
            Self::Name(name) => Location::Name(*name),
            Self::Member(object, key) => {
                Location::Member(object(run, locals)?, key.key(run, locals)?)
            }
        })
    }
}

/// Compiled call arguments.
struct Arguments<'ast>(Vec<Compute<'ast>>);

impl<'ast> Arguments<'ast> {
    fn new(arguments: &[Expression<'ast>]) -> Self {
        Self(arguments.iter().map(compute).collect())
    }

    /// Evaluates the arguments into a reused buffer.
    fn values(
        &self,
        run: &mut Run<'ast, '_>,
        locals: &mut Locals<'ast>,
    ) -> Evaluation<'ast, Vec<Value<'ast>>> {
        let mut values = run.spare.arguments.pop().unwrap_or_default();
        for argument in &self.0 {
            values.push(argument(run, locals)?);
        }
        Ok(values)
    }
}

pub(super) fn compute<'ast>(expression: &Expression<'ast>) -> Compute<'ast> {
    match expression {
        Expression::Constant(value) => {
            let value = value.clone();
            code(move |_, _| Ok(evaluate::copied(&value)))
        }
        Expression::Name(Name::Local(slot, name)) => {
            let (slot, name) = (*slot, *name);
            code(move |run, locals| match &locals[slot] {
                Some(value @ Value::Symbolic(_)) => Ok(run.refined(value)),
                Some(value) => Ok(evaluate::copied(value)),
                None => run.lookup(name),
            })
        }
        Expression::Name(Name::Scoped(binding)) => {
            let binding = *binding;
            code(move |run, _| run.lookup(binding))
        }
        Expression::This => code(|run, _| Ok(run.frame().this.clone())),
        Expression::Binary(operator, left, right) => {
            let (operator, left, right) = (*operator, compute(left), compute(right));
            code(move |run, locals| {
                Ok(evaluate::binary_value(
                    operator,
                    left(run, locals)?,
                    right(run, locals)?,
                ))
            })
        }
        Expression::Arithmetic { .. } => {
            let number = number(expression);
            code(move |run, locals| Ok(evaluate::number_value(number(run, locals)?)))
        }
        Expression::Member(object, property) => {
            let (object, property) = (compute(object), Keyed::new(property));
            code(move |run, locals| {
                let object = object(run, locals)?;
                let key = property.key(run, locals)?;
                run.get(&object, &key)
            })
        }
        Expression::Assign(target, operator, right) => assignment(target, *operator, right),
        Expression::LogicalAssign(target) => {
            let target = Located::new(target);
            code(move |run, locals| {
                target.locate(run, locals)?;
                Err(Stop::unsupported("a logical assignment"))
            })
        }
        Expression::Update {
            target,
            operator,
            prefix,
        } => update(target, *operator, *prefix),
        Expression::Call(callee, arguments) => call(callee, arguments),
        // `&&`, `||`, or `??`, evaluating the right side only when needed.
        Expression::Logical {
            operator,
            left,
            right,
            pure,
        } => {
            let (operator, pure, left, right) = (*operator, *pure, compute(left), compute(right));
            code(move |run, locals| {
                let left = left(run, locals)?;
                run.short_circuit(operator, left, pure, locals, &right)
            })
        }
        Expression::Sequence(expressions) => {
            let expressions: Vec<_> = expressions.iter().map(compute).collect();
            code(move |run, locals| {
                let mut value = Value::Undefined;
                for expression in &expressions {
                    value = expression(run, locals)?;
                }
                Ok(value)
            })
        }
        Expression::New(callee, arguments) => {
            let (callee, arguments) = (compute(callee), Arguments::new(arguments));
            code(move |run, locals| {
                let callee = callee(run, locals)?;
                let arguments = arguments.values(run, locals)?;
                run.construct(callee, arguments)
            })
        }
        Expression::Unary(operator, argument) => {
            let (operator, argument) = (*operator, compute(argument));
            code(move |run, locals| Ok(semantics::unary_value(operator, argument(run, locals)?)))
        }
        Expression::Conditional(test, yes, no) => {
            let (test, yes, no) = (compute(test), compute(yes), compute(no));
            code(move |run, locals| {
                let test = test(run, locals)?;
                let branch = if run.decide(&test) { &yes } else { &no };
                branch(run, locals)
            })
        }
        Expression::Array(elements) => {
            let elements: Vec<_> = elements
                .iter()
                .map(|element| element.as_ref().map(compute))
                .collect();
            code(move |run, locals| {
                let mut values = Vec::with_capacity(elements.len());
                for element in &elements {
                    values.push(match element {
                        Some(element) => element(run, locals)?,
                        None => Value::Undefined,
                    });
                }
                Ok(Value::array(values))
            })
        }
        Expression::Object(properties) => {
            let properties: Vec<_> = properties
                .iter()
                .map(|(key, value)| (Keyed::new(key), compute(value)))
                .collect();
            code(move |run, locals| {
                let mut entries = Vec::with_capacity(properties.len());
                for (key, value) in &properties {
                    let key = key.key(run, locals)?;
                    let name = key
                        .property()
                        .ok_or_else(|| access::unsupported("object key", &key))?;
                    entries.push((name, value(run, locals)?));
                }
                Ok(Value::Object(Rc::new(RefCell::new(entries))))
            })
        }
        Expression::Function(name, function) => {
            let (name, function) = (*name, *function);
            code(move |run, _| Ok(run.function_value(name, function)))
        }
        Expression::Arrow(arrow) => {
            let arrow = *arrow;
            code(move |run, _| Ok(run.arrow_value(arrow)))
        }
        Expression::Unsupported(reason) => {
            let reason = *reason;
            code(move |_, _| Err(Stop::unsupported(reason)))
        }
    }
}

fn call<'ast>(callee: &Expression<'ast>, arguments: &[Expression<'ast>]) -> Compute<'ast> {
    let arguments = Arguments::new(arguments);
    match callee {
        Expression::Member(object, property) => {
            let (object, property) = (compute(object), Keyed::new(property));
            code(move |run, locals| {
                let object = object(run, locals)?;
                let key = property.key(run, locals)?;
                let callee = run.get(&object, &key)?;
                let arguments = arguments.values(run, locals)?;
                run.apply(callee, object, arguments)
            })
        }
        callee => {
            let callee = compute(callee);
            code(move |run, locals| {
                let callee = callee(run, locals)?;
                let arguments = arguments.values(run, locals)?;
                run.apply(callee, Value::Undefined, arguments)
            })
        }
    }
}

fn assignment<'ast>(
    target: &Target<'ast>,
    operator: Option<BinaryOperator>,
    right: &Expression<'ast>,
) -> Compute<'ast> {
    let (target, right) = (Located::new(target), compute(right));
    match operator {
        None => code(move |run, locals| {
            let location = target.locate(run, locals)?;
            let value = right(run, locals)?;
            run.write(location, value.clone(), locals)?;
            Ok(value)
        }),
        Some(operator) => code(move |run, locals| {
            let location = target.locate(run, locals)?;
            run.compound(location, operator, locals, &right)
        }),
    }
}

fn update<'ast>(target: &Target<'ast>, operator: UpdateOperator, prefix: bool) -> Compute<'ast> {
    let target = Located::new(target);
    code(move |run, locals| {
        // A counter: the local is read and written in place.
        if let Located::Name(Name::Local(slot, _)) = target
            && let Some(Value::Number(number)) = &mut locals[slot]
        {
            return Ok(Value::Number(evaluate::step(operator, prefix, number)));
        }
        let location = target.locate(run, locals)?;
        run.update_location(location, operator, prefix, locals)
    })
}

/// Evaluates numeric arithmetic without wrapping intermediate results. If an operand is
/// nonnumeric, switches to general evaluation for that operator and its enclosing operators,
/// reusing evaluated operands, and returns that general result in `Err`.
fn number<'ast>(expression: &Expression<'ast>) -> Numeric<'ast> {
    let Expression::Arithmetic {
        operator,
        operation,
        left,
        right,
    } = expression
    else {
        let general = compute(expression);
        let general = code(move |run, locals| {
            Ok(match general(run, locals)? {
                Value::Number(number) => Ok(number),
                value => Err(value),
            })
        });
        return program_read(expression, general);
    };
    let (operator, operation, left) = (*operator, *operation, operand(left));
    if let Expression::Constant(Value::Number(constant)) = **right {
        return code(move |run, locals| {
            Ok(match left(run, locals)? {
                Ok(left) => Ok(operation(left, constant)),
                left => Err(evaluate::binary_value(
                    operator,
                    evaluate::number_value(left),
                    Value::Number(constant),
                )),
            })
        });
    }
    let right = operand(right);
    code(move |run, locals| {
        let left = left(run, locals)?;
        let right = right(run, locals)?;
        Ok(match (left, right) {
            (Ok(left), Ok(right)) => Ok(operation(left, right)),
            (left, right) => Err(evaluate::binary_value(
                operator,
                evaluate::number_value(left),
                evaluate::number_value(right),
            )),
        })
    })
}

/// An operand of arithmetic, reading numeric constants and locals directly.
fn operand<'ast>(expression: &Expression<'ast>) -> Numeric<'ast> {
    match expression {
        Expression::Constant(Value::Number(number)) => {
            let number = *number;
            code(move |_, _| Ok(Ok(number)))
        }
        Expression::Name(Name::Local(slot, _)) => {
            let (slot, general) = (*slot, number(expression));
            code(move |run, locals| match locals[slot] {
                Some(Value::Number(number)) => Ok(Ok(number)),
                _ => general(run, locals),
            })
        }
        expression => number(expression),
    }
}

/// `program[index++]` and the like, where both are locals: reads the byte directly while the
/// first local holds the program and the second a number, and runs `general` otherwise.
fn program_read<'ast>(expression: &Expression<'ast>, general: Numeric<'ast>) -> Numeric<'ast> {
    let Expression::Member(object, Property::Computed(key)) = expression else {
        return general;
    };
    let (
        Expression::Name(Name::Local(program, _)),
        Expression::Update {
            target: Target::Name(Name::Local(index, _)),
            operator,
            prefix,
        },
    ) = (&**object, &**key)
    else {
        return general;
    };
    let (program, index, operator, prefix) = (*program, *index, *operator, *prefix);
    code(move |run, locals| {
        if matches!(locals[program], Some(Value::Program))
            && let Some(Value::Number(number)) = &mut locals[index]
        {
            let position = evaluate::step(operator, prefix, number);
            let byte = convert::index(position).and_then(|position| run.program.get(position));
            return Ok(byte.map_or(Err(Value::Undefined), |byte| Ok(f64::from(*byte))));
        }
        general(run, locals)
    })
}

/// Boxes compiled code, giving closures their signature.
fn code<'ast, T>(
    code: impl for<'session> Fn(&mut Run<'ast, 'session>, &mut Locals<'ast>) -> Evaluation<'ast, T>
    + 'ast,
) -> Compiled<'ast, T> {
    Box::new(code)
}
