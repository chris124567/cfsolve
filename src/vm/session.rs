//! VM state initialized from the script before any program runs: setup bindings, register
//! layout, instance fields, and opcode handlers. [`Session::constructed`] adds the constructor
//! fields that depend on a program.
//!
//! Each handler run copies mutable values; see [`super::interpret`]. Only lazily compiled plans
//! are cached between runs, besides the decrypted strings a loaded program caches.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use anyhow::{Context, Result, bail, ensure};
use oxc::ast::ast::{
    AssignmentExpression, AssignmentTarget, BindingPattern, Expression, Function, MemberExpression,
    ObjectExpression, Statement,
};
use oxc::semantic::SymbolId;
use oxc::syntax::operator::BinaryOperator;

use super::extract::{self, RunMethod};
use super::interpret::{self, Branching, Frozen, Intrinsics, Plans, Run, Spare, StringDecoder};
use super::machine::Definition;
use super::output::{Constant, Position, Term};
use super::registers::Member;
use super::value::Value;
use super::{HashMap, convert};
use crate::js::ast::{self, Binding, Script};

pub(crate) struct Session<'ast> {
    /// The script defining the VM, which resolves its bindings.
    pub script: Script<'ast>,
    /// Functions declared beside the class: handlers and their helpers.
    pub functions: HashMap<SymbolId, &'ast Function<'ast>>,
    /// Function values created lazily and shared across runs. Functions declared beside the
    /// class capture no state that a run can change.
    pub function_values: RefCell<HashMap<SymbolId, Value<'ast>>>,
    /// Lazily prepared handlers and helpers, including unsupported functions.
    pub compiled: Plans<'ast>,
    pub spare: RefCell<Spare<'ast>>,
    /// Session binding objects handler runs share instead of copying.
    pub frozen: Frozen,
    /// What exploration has learned about each handler's paths, by handler address.
    pub branching: RefCell<HashMap<usize, Branching>>,
    pub bindings: HashMap<Binding<'ast>, Value<'ast>>,
    /// Bindings interrupted setup statements may have written, with their errors. Reading them
    /// stops interpretation.
    pub unavailable: HashMap<Binding<'ast>, String>,
    pub layout: Layout,
    /// Handler state: registers, register mask, and state-register indices.
    pub state: HashMap<String, Value<'ast>>,
    /// Initial register stacks created by the constructor for handler execution.
    pub initial: Vec<(u8, Value<'ast>)>,
    /// Function used to decrypt string records stored in registers.
    pub record_decoder: Option<&'ast Function<'ast>>,
    /// Script functions run natively.
    pub intrinsics: Intrinsics,
    /// The record decoder, run natively, if it has the recognized shape.
    pub string_decoder: Option<StringDecoder<'ast>>,
    /// The symbol the instance keeps its program under, if any.
    pub program_key: Option<Rc<()>>,
    /// Instance objects stored under the remaining symbols.
    pub symbol_fields: Vec<(Rc<()>, Value<'ast>)>,
    /// Other fields the constructor initializes, including the string-hash cache that hashed
    /// comparisons use.
    pub fields: HashMap<String, Value<'ast>>,
    /// The constructor's statements.
    constructor: &'ast [Statement<'ast>],
    pub handlers: HashMap<u8, &'ast Function<'ast>>,
    /// Where the program runner starts a program.
    pub entry: Position,
}

/// Instance state register indices, with zero as the per-run register mask.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Layout {
    pub pc: u8,
    pub key: u8,
    pub program: u8,
    pub cells: u8,
}

impl<'ast> Session<'ast> {
    /// Evaluates the setup before and beside the VM class `definition` finds, then the
    /// constructor.
    pub(super) fn try_new(definition: &Definition<'ast>) -> Result<Self> {
        let &Definition {
            script,
            body,
            class,
            ref prelude,
            ref functions,
            ref run,
            ..
        } = definition;
        let constructor = extract::constructor(class)?;
        let handlers = extract::handlers(script, functions, &run.dispatch)?;
        let record_decoder = extract::record_decoder(script, body)
            .and_then(|symbol| functions.get(&symbol).copied());
        let mut session = Self {
            functions: functions.clone(),
            handlers,
            entry: extract::entry(body)?,
            record_decoder,
            ..Self::unevaluated(script, constructor)
        };
        (session.bindings, session.unavailable) =
            interpret::setup(&session, prelude, &body.statements);
        let constructed = construct(&mut Run::method(&session), constructor);
        recover_state(&mut session, run, &constructed)?;
        session.symbol_fields = constructed.objects;
        session.program_key = match &constructed.programs[..] {
            [] => None,
            [symbol] => Some(symbol.clone()),
            symbols => bail!("the VM constructor keys {} values by symbol", symbols.len()),
        };
        session.fields = concrete(constructed.fields);
        session.intrinsics = interpret::intrinsics(&session);
        session.string_decoder = StringDecoder::recognize(&session);
        session.frozen = Frozen::of(&session.bindings);
        Ok(session)
    }

    fn unevaluated(script: Script<'ast>, constructor: &'ast [Statement<'ast>]) -> Self {
        Self {
            script,
            functions: HashMap::default(),
            function_values: RefCell::default(),
            compiled: Plans::default(),
            spare: RefCell::default(),
            frozen: Frozen::default(),
            branching: RefCell::default(),
            bindings: HashMap::default(),
            unavailable: HashMap::default(),
            layout: Layout::default(),
            state: HashMap::default(),
            program_key: None,
            symbol_fields: Vec::new(),
            initial: Vec::new(),
            record_decoder: None,
            intrinsics: Intrinsics::default(),
            string_decoder: None,
            fields: HashMap::default(),
            constructor,
            handlers: HashMap::default(),
            entry: Position::new(0, 0),
        }
    }

    /// Evaluates the constructor fields for `program`, including program-dependent data such as
    /// its string table.
    pub(super) fn constructed(&self, program: &[u8]) -> HashMap<String, Value<'ast>> {
        concrete(construct(&mut Run::constructor(self, program), self.constructor).fields)
    }

    /// The function declared beside the class that `binding` refers to.
    pub(crate) fn function(&self, binding: Binding<'ast>) -> Option<&'ast Function<'ast>> {
        match binding {
            Binding::Symbol(symbol) => self.functions.get(&symbol).copied(),
            Binding::Global(_) => None,
        }
    }
}

#[cfg(test)]
impl<'ast> Session<'ast> {
    /// Creates an empty session over `script` for interpreter tests. Declares the script's
    /// function declarations beside the class.
    pub(crate) fn empty(script: Script<'ast>) -> Self {
        Self {
            functions: extract::functions(&script.program.body),
            ..Self::unevaluated(script, &[])
        }
    }

    /// The function the script declares as `name`.
    pub(crate) fn declared(&self, name: &str) -> &'ast Function<'ast> {
        let symbol = self.script.scoping.get_root_binding(name.into());
        self.functions[&symbol.expect("the function is declared")]
    }
}

/// Values initialized by the constructor.
#[derive(Default)]
struct Constructed<'a> {
    fields: HashMap<String, Value<'a>>,
    /// Symbol-keyed values other than object literals, including the program.
    programs: Vec<Rc<()>>,
    /// Object literals indexed by their symbol keys.
    objects: Vec<(Rc<()>, Value<'a>)>,
    /// Source fields for the register file program counter and dispatch key indices.
    pc: Option<String>,
    key: Option<String>,
    registers: Vec<RegisterWrite<'a>>,
}

/// Matches register writes as `<file>.write(<mask> ^ <register>, <value>)` or equivalent helper
/// calls: `store(<file>, <mask> ^ <register>, <value>)`.
struct RegisterWrite<'a> {
    /// The field holding the register file.
    file: String,
    /// The field holding the index mask.
    mask: String,
    register: u8,
    value: Value<'a>,
}

/// Locals holding copies of instance fields, by binding.
type Copies<'a> = HashMap<Binding<'a>, String>;

/// Evaluates object literal properties. Uses null for properties computed from program bytes, such
/// as the word array used by a faster string decoder. This makes handlers use byte-by-byte decoding
/// instead.
fn object_fields<'a>(run: &mut Run<'a, '_>, object: &'a ObjectExpression<'a>) -> Value<'a> {
    let properties = ast::key_values(object)
        .filter_map(|property| {
            let name = ast::key_str(&property.key, property.computed)?.to_owned();
            let value = run
                .expression(&property.value)
                .ok()
                .filter(|value| !value.is_symbolic());
            Some((name, value.unwrap_or(Value::Null)))
        })
        .collect();
    Value::Object(Rc::new(RefCell::new(properties)))
}

/// Evaluates constructor field assignments in order through `run`, including nested blocks. Follows
/// field copies through locals to find the source fields for the program counter and dispatch key
/// indices.
fn construct<'a>(run: &mut Run<'a, '_>, constructor: &'a [Statement<'a>]) -> Constructed<'a> {
    let mut constructed = Constructed::default();
    let mut copies = HashMap::default();
    construct_statements(run, constructor, &mut constructed, &mut copies);
    constructed
}

fn construct_statements<'a>(
    run: &mut Run<'a, '_>,
    statements: &'a [Statement<'a>],
    constructed: &mut Constructed<'a>,
    copies: &mut Copies<'a>,
) {
    for statement in statements {
        match statement {
            Statement::BlockStatement(block) => {
                construct_statements(run, &block.body, constructed, copies);
            }
            Statement::ExpressionStatement(statement) => {
                construct_expression(run, &statement.expression, constructed, copies);
            }
            // In `var copy = (local = this.field, this.other)`, `copy` receives the final operand,
            // `this.other`.
            Statement::VariableDeclaration(declaration) if !declaration.kind.is_using() => {
                for declarator in &declaration.declarations {
                    let Some(init) = &declarator.init else {
                        continue;
                    };
                    construct_expression(run, init, constructed, copies);
                    let BindingPattern::BindingIdentifier(name) = &declarator.id else {
                        continue;
                    };
                    let value = match init.without_parentheses() {
                        Expression::SequenceExpression(sequence)
                            if let Some(last) = sequence.expressions.last() =>
                        {
                            last.without_parentheses()
                        }
                        value => value,
                    };
                    track_copy(
                        run.source(),
                        Binding::Symbol(name.symbol_id()),
                        value,
                        copies,
                    );
                }
            }
            _ => {}
        }
    }
}

/// Visits assignments in `expr` in evaluation order, including sequence operands.
fn construct_expression<'a>(
    run: &mut Run<'a, '_>,
    expr: &'a Expression<'a>,
    constructed: &mut Constructed<'a>,
    copies: &mut Copies<'a>,
) {
    match expr {
        Expression::ParenthesizedExpression(paren) => {
            construct_expression(run, &paren.expression, constructed, copies);
        }
        Expression::SequenceExpression(sequence) => {
            for expr in &sequence.expressions {
                construct_expression(run, expr, constructed, copies);
            }
        }
        Expression::AssignmentExpression(assign) => {
            construct_assignment(run, assign, constructed, copies);
        }
        Expression::CallExpression(call) => {
            let (file, index, value) = match (ast::method_call(expr, "write"), &call.arguments[..])
            {
                (Some((file, _)), [index, value]) => (
                    file,
                    ast::argument_expression(index),
                    ast::argument_expression(value),
                ),
                (None, [file, index, value]) => (
                    ast::argument_expression(file),
                    ast::argument_expression(index),
                    ast::argument_expression(value),
                ),
                _ => return,
            };
            if let Expression::Identifier(file) = file
                && let Some(file) = copies.get(&run.source().binding(file))
                && let Some((mask, register)) = masked_index(run.source(), index, copies)
                && let Ok(value) = run.expression(value)
            {
                constructed.registers.push(RegisterWrite {
                    file: file.clone(),
                    mask,
                    register,
                    value,
                });
            }
        }
        _ => {}
    }
}

/// Extracts the mask field and register from `<mask> ^ <register>`. The mask can be a field access
/// or a local copy of one.
fn masked_index<'a>(
    script: Script<'a>,
    index: &Expression<'a>,
    copies: &Copies<'a>,
) -> Option<(String, u8)> {
    let Expression::BinaryExpression(xor) = index.without_parentheses() else {
        return None;
    };
    if xor.operator != BinaryOperator::BitwiseXOR {
        return None;
    }
    let field = |expr: &Expression<'a>| copied_field(script, expr.without_parentheses(), copies);
    let register = |expr: &Expression<'a>| convert::byte(ast::number(expr)?);
    match (field(&xor.left), field(&xor.right)) {
        (Some(mask), None) => Some((mask, register(&xor.right)?)),
        (None, Some(mask)) => Some((mask, register(&xor.left)?)),
        _ => None,
    }
}

fn construct_assignment<'a>(
    run: &mut Run<'a, '_>,
    assign: &'a AssignmentExpression<'a>,
    constructed: &mut Constructed<'a>,
    copies: &mut Copies<'a>,
) {
    let script = run.source();
    if let AssignmentTarget::AssignmentTargetIdentifier(name) = &assign.left {
        track_copy(script, script.binding(name), &assign.right, copies);
        return;
    }
    let Some(target) = assign.left.as_member_expression() else {
        return;
    };
    match target.object() {
        Expression::ThisExpression(_) => {
            if let Some(field) = ast::member_str(target).map(str::to_owned) {
                if let Ok(value) = run.expression(&assign.right) {
                    constructed.fields.insert(field, value);
                }
            } else if let MemberExpression::ComputedMemberExpression(target) = target
                && let Ok(Value::Symbol(symbol)) = run.expression(&target.expression)
            {
                match &assign.right {
                    Expression::ObjectExpression(object) => {
                        let value = object_fields(run, object);
                        constructed.objects.push((symbol, value));
                    }
                    _ => constructed.programs.push(symbol),
                }
            }
        }
        Expression::Super(_) => {}
        // `registers.<index> = <copy of a field>`.
        _ => {
            let field = copied_field(script, &assign.right, copies);
            match ast::member_str(target).and_then(Member::of) {
                Some(Member::PcIndex) => constructed.pc = field,
                Some(Member::KeyIndex) => constructed.key = field,
                _ => {}
            }
        }
    }
}

/// Records the source field if assigning `value` makes local `binding` a copy of that field.
fn track_copy<'a>(
    script: Script<'a>,
    binding: Binding<'a>,
    value: &Expression<'a>,
    copies: &mut Copies<'a>,
) {
    match copied_field(script, value, copies) {
        Some(field) => copies.insert(binding, field),
        None => copies.remove(&binding),
    };
}

/// Resolves the field read by `expr`, either directly as `this.field` or through a local copy.
fn copied_field<'a>(
    script: Script<'a>,
    expr: &Expression<'a>,
    copies: &Copies<'a>,
) -> Option<String> {
    match expr {
        Expression::Identifier(name) => copies.get(&script.binding(name)).cloned(),
        expr => extract::this_field(expr).map(str::to_owned),
    }
}

/// Keeps the fields whose values depend only on the script.
fn concrete<'a>(mut fields: HashMap<String, Value<'a>>) -> HashMap<String, Value<'a>> {
    fields.retain(|_, value| !value.is_symbolic());
    fields
}

/// Recovers the session's handler state, register layout, and initial register stacks. The
/// constructor computes indices as `this.<mask> ^ <register>` with a random mask per run. Uses
/// zero for the mask during analysis.
fn recover_state<'a>(
    session: &mut Session<'a>,
    names: &RunMethod<'_>,
    constructed: &Constructed<'a>,
) -> Result<()> {
    let fields = &constructed.fields;
    let pc = constructed
        .pc
        .as_deref()
        .context("the VM constructor sets no program counter register")?;
    let key = constructed
        .key
        .as_deref()
        .context("the VM constructor sets no dispatch key register")?;
    let mut state = HashMap::default();
    let mut masks = BTreeSet::new();
    let mut register = |name: &str| -> Result<u8> {
        let value = fields
            .get(name)
            .with_context(|| format!("the VM constructor sets no this.{name}"))?;
        let (mask, register) = masked(value)
            .with_context(|| format!("the VM constructor's this.{name} is not a register"))?;
        masks.extend(mask);
        state.insert(name.to_owned(), Value::Number(f64::from(register)));
        Ok(register)
    };
    let layout = Layout {
        pc: register(pc)?,
        key: register(key)?,
        program: register(&names.program)?,
        cells: register(&names.cells)?,
    };
    ensure!(
        masks.len() <= 1,
        "the VM's registers use {} masks",
        masks.len()
    );
    state.insert(names.registers.clone(), Value::Registers);
    let mask = masks.pop_first();
    // Collect constructor-created stacks, excluding the state registers used to start handlers.
    // Keep external objects, such as the global object, dependent on their registers so listing
    // readers can recognize how the program accesses them.
    let state_registers = [layout.pc, layout.key, layout.program, layout.cells];
    session.initial = constructed
        .registers
        .iter()
        .filter(|write| {
            write.file == names.registers
                && Some(&write.mask) == mask.as_ref()
                && !state_registers.contains(&write.register)
                && matches!(write.value, Value::Array(_))
        })
        .map(|write| (write.register, write.value.clone()))
        .collect();
    state.extend(mask.map(|mask| (mask, Value::Number(0.0))));
    session.state = state;
    session.layout = layout;
    Ok(())
}

/// Extracts the register and optional mask field from `this.<mask> ^ <register>` or a bare
/// `<register>`.
fn masked(value: &Value<'_>) -> Option<(Option<String>, u8)> {
    let term = match value {
        Value::Number(register) => return Some((None, convert::byte(*register)?)),
        Value::Symbolic(term) => &**term,
        _ => return None,
    };
    let Term::Binary(BinaryOperator::BitwiseXOR, left, right) = term else {
        return None;
    };
    match (&**left, &**right) {
        (Term::Field(mask), Term::Const(Constant::Number(register)))
        | (Term::Const(Constant::Number(register)), Term::Field(mask)) => {
            Some((Some(mask.clone()), convert::byte(*register)?))
        }
        _ => None,
    }
}
