//! VM state initialized from the script before any program runs: setup bindings, register
//! layout, instance fields, and opcode handlers. [`Session::constructed`] adds the constructor
//! fields that depend on a program.
//!
//! Each handler run copies mutable values; see [`super::interpret`]. Only decrypted strings
//! ([`Session::decrypted`]) and lazily compiled plans are cached between runs.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use anyhow::{Context, Result, bail, ensure};
use swc_core::atoms::Atom;
use swc_core::ecma::ast::{
    AssignExpr, AssignTarget, BinaryOp, BlockStmt, Class, Decl, Expr, Function, MemberProp,
    ObjectLit, SimpleAssignTarget, Stmt,
};

use super::extract::{self, RunMethod};
use super::interpret::{self, Plans, Run, Spare};
use super::output::{Constant, Position, Term};
use super::registers::Member;
use super::value::Value;
use super::{HashMap, convert};
use crate::js::ast;

pub(crate) struct Session<'ast> {
    /// Functions declared beside the class: handlers and their helpers.
    pub functions: HashMap<Atom, &'ast Function>,
    /// Function values created lazily and shared across runs. Functions declared beside the
    /// class capture no state that a run can change.
    pub function_values: RefCell<HashMap<Atom, Value<'ast>>>,
    /// Lazily prepared handlers and helpers, including unsupported functions.
    pub compiled: Plans<'ast>,
    pub spare: RefCell<Spare<'ast>>,
    pub bindings: HashMap<Atom, Value<'ast>>,
    /// Names interrupted setup statements may have written, with their errors. Reading them
    /// stops interpretation.
    pub unavailable: HashMap<Atom, String>,
    pub layout: Layout,
    /// Handler state: registers, register mask, and state-register indices.
    pub state: HashMap<String, Value<'ast>>,
    /// Initial register stacks created by the constructor for handler execution.
    pub initial: Vec<(u8, Value<'ast>)>,
    /// Function used to decrypt string records stored in registers.
    pub record_decoder: Option<Atom>,
    /// Decrypted strings cached by record position, length, and key.
    pub decrypted: RefCell<HashMap<(u32, u32, u32), Value<'ast>>>,
    /// The symbol the instance keeps its program under, if any.
    pub program_key: Option<Rc<()>>,
    /// Instance objects stored under the remaining symbols.
    pub symbol_fields: Vec<(Rc<()>, Value<'ast>)>,
    /// Other fields the constructor initializes, including the string-hash cache that hashed
    /// comparisons use.
    pub fields: HashMap<String, Value<'ast>>,
    constructor: &'ast BlockStmt,
    pub handlers: HashMap<u8, &'ast Function>,
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
    /// Evaluates the enclosing `prelude`, the setup in `body` that defines the VM `class`, and
    /// the constructor.
    pub(super) fn try_new(
        body: &'ast BlockStmt,
        class: &'ast Class,
        prelude: &'ast [Stmt],
    ) -> Result<Self> {
        let run = extract::method(class, "run").context("the VM class has no run method")?;
        let constructor = extract::constructor(class)?;
        let functions = extract::functions(&body.stmts);
        let run = extract::run_method(&functions, run)?;
        let handlers = extract::handlers(&functions, &run.dispatch)?;
        let mut session = Self {
            functions,
            handlers,
            entry: extract::entry(body)?,
            record_decoder: extract::record_decoder(body),
            ..Self::unevaluated(constructor)
        };
        (session.bindings, session.unavailable) = interpret::setup(&session, prelude, &body.stmts);
        let constructed = construct(&mut Run::method(&session), constructor);
        (session.state, session.layout, session.initial) = state(&run, &constructed)?;
        session.symbol_fields = constructed.objects;
        session.program_key = match &constructed.programs[..] {
            [] => None,
            [symbol] => Some(symbol.clone()),
            symbols => bail!("the VM constructor keys {} values by symbol", symbols.len()),
        };
        session.fields = concrete(constructed.fields);
        Ok(session)
    }

    fn unevaluated(constructor: &'ast BlockStmt) -> Self {
        Self {
            functions: HashMap::default(),
            function_values: RefCell::default(),
            compiled: Default::default(),
            spare: RefCell::default(),
            bindings: HashMap::default(),
            unavailable: HashMap::default(),
            layout: Layout::default(),
            state: HashMap::default(),
            program_key: None,
            symbol_fields: Vec::new(),
            initial: Vec::new(),
            record_decoder: None,
            decrypted: RefCell::default(),
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
}

#[cfg(test)]
impl Session<'_> {
    /// Creates an empty session for interpreter tests.
    pub(crate) fn empty() -> Self {
        Self::unevaluated(Box::leak(Box::default()))
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

/// Evaluates object literal properties. Uses null for properties computed from program bytes, such
/// as the word array used by a faster string decoder. This makes handlers use byte-by-byte decoding
/// instead.
fn object_fields<'a>(run: &mut Run<'a, '_>, object: &'a ObjectLit) -> Value<'a> {
    let properties = ast::key_values(object)
        .filter_map(|property| {
            let name = ast::key_str(&property.key)?.to_owned();
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
fn construct<'a>(run: &mut Run<'a, '_>, constructor: &'a BlockStmt) -> Constructed<'a> {
    let mut constructed = Constructed::default();
    let mut copies = HashMap::default();
    construct_statements(run, &constructor.stmts, &mut constructed, &mut copies);
    constructed
}

fn construct_statements<'a>(
    run: &mut Run<'a, '_>,
    statements: &'a [Stmt],
    constructed: &mut Constructed<'a>,
    copies: &mut HashMap<Atom, String>,
) {
    for statement in statements {
        match statement {
            Stmt::Block(block) => construct_statements(run, &block.stmts, constructed, copies),
            Stmt::Expr(statement) => {
                construct_expression(run, &statement.expr, constructed, copies);
            }
            // In `var copy = (local = this.field, this.other)`, `copy` receives the final operand,
            // `this.other`.
            Stmt::Decl(Decl::Var(declaration)) => {
                for declarator in &declaration.decls {
                    let Some(init) = &declarator.init else {
                        continue;
                    };
                    construct_expression(run, init, constructed, copies);
                    let Some(name) = declarator.name.as_ident() else {
                        continue;
                    };
                    let value = match init.unwrap_parens() {
                        Expr::Seq(sequence) if let Some(last) = sequence.exprs.last() => {
                            last.unwrap_parens()
                        }
                        value => value,
                    };
                    track_copy(&name.sym, value, copies);
                }
            }
            _ => {}
        }
    }
}

/// Visits assignments in `expr` in evaluation order, including sequence operands.
fn construct_expression<'a>(
    run: &mut Run<'a, '_>,
    expr: &'a Expr,
    constructed: &mut Constructed<'a>,
    copies: &mut HashMap<Atom, String>,
) {
    match expr {
        Expr::Paren(paren) => construct_expression(run, &paren.expr, constructed, copies),
        Expr::Seq(sequence) => {
            for expr in &sequence.exprs {
                construct_expression(run, expr, constructed, copies);
            }
        }
        Expr::Assign(assign) => construct_assignment(run, assign, constructed, copies),
        Expr::Call(call) => {
            let (file, index, value) = match (ast::method_call(expr, "write"), &call.args[..]) {
                (Some((file, _)), [index, value]) => (file, index, value),
                (None, [file, index, value]) => (&*file.expr, index, value),
                _ => return,
            };
            if let Some(file) = file.as_ident().and_then(|name| copies.get(&name.sym))
                && let Some((mask, register)) = masked_index(&index.expr, copies)
                && let Ok(value) = run.expression(&value.expr)
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
fn masked_index(index: &Expr, copies: &HashMap<Atom, String>) -> Option<(String, u8)> {
    let xor = index.unwrap_parens().as_bin()?;
    if xor.op != BinaryOp::BitXor {
        return None;
    }
    let field = |expr: &Expr| copied_field(expr.unwrap_parens(), copies);
    let register = |expr: &Expr| convert::byte(ast::number(expr)?);
    match (field(&xor.left), field(&xor.right)) {
        (Some(mask), None) => Some((mask, register(&xor.right)?)),
        (None, Some(mask)) => Some((mask, register(&xor.left)?)),
        _ => None,
    }
}

fn construct_assignment<'a>(
    run: &mut Run<'a, '_>,
    assign: &'a AssignExpr,
    constructed: &mut Constructed<'a>,
    copies: &mut HashMap<Atom, String>,
) {
    match &assign.left {
        AssignTarget::Simple(SimpleAssignTarget::Member(target)) if target.obj.is_this() => {
            if let Some(field) = ast::member_str(&target.prop).map(str::to_owned) {
                if let Ok(value) = run.expression(&assign.right) {
                    constructed.fields.insert(field, value);
                }
            } else if let MemberProp::Computed(key) = &target.prop
                && let Ok(Value::Symbol(symbol)) = run.expression(&key.expr)
            {
                match &*assign.right {
                    Expr::Object(object) => {
                        let value = object_fields(run, object);
                        constructed.objects.push((symbol, value));
                    }
                    _ => constructed.programs.push(symbol),
                }
            }
        }
        // `registers.<index> = <copy of a field>`.
        AssignTarget::Simple(SimpleAssignTarget::Member(target)) => {
            let field = copied_field(&assign.right, copies);
            match ast::member_str(&target.prop).and_then(Member::of) {
                Some(Member::PcIndex) => constructed.pc = field,
                Some(Member::KeyIndex) => constructed.key = field,
                _ => {}
            }
        }
        AssignTarget::Simple(SimpleAssignTarget::Ident(name)) => {
            track_copy(&name.sym, &assign.right, copies);
        }
        _ => {}
    }
}

/// Records the source field if assigning `value` makes local `name` a copy of that field.
fn track_copy(name: &Atom, value: &Expr, copies: &mut HashMap<Atom, String>) {
    match copied_field(value, copies) {
        Some(field) => copies.insert(name.clone(), field),
        None => copies.remove(name),
    };
}

/// Resolves the field read by `expr`, either directly as `this.field` or through a local copy.
fn copied_field(expr: &Expr, copies: &HashMap<Atom, String>) -> Option<String> {
    match expr {
        Expr::Member(member) if member.obj.is_this() => {
            ast::member_str(&member.prop).map(str::to_owned)
        }
        Expr::Ident(name) => copies.get(&name.sym).cloned(),
        _ => None,
    }
}

/// Keeps the fields whose values depend only on the script.
fn concrete<'a>(mut fields: HashMap<String, Value<'a>>) -> HashMap<String, Value<'a>> {
    fields.retain(|_, value| !value.is_symbolic());
    fields
}

/// Recovers state-field values and register layout. The constructor computes indices as
/// `this.<mask> ^ <register>` with a random mask per run. Uses zero for the mask during
/// analysis.
fn state<'a>(
    names: &RunMethod<'_>,
    constructed: &Constructed<'a>,
) -> Result<(HashMap<String, Value<'a>>, Layout, Vec<(u8, Value<'a>)>)> {
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
    let initial = constructed
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
    Ok((state, layout, initial))
}

/// Extracts the register and optional mask field from `this.<mask> ^ <register>` or a bare
/// `<register>`.
fn masked(value: &Value<'_>) -> Option<(Option<String>, u8)> {
    let term = match value {
        Value::Number(register) => return Some((None, convert::byte(*register)?)),
        Value::Symbolic(term) => &**term,
        _ => return None,
    };
    let Term::Binary(BinaryOp::BitXor, left, right) = term else {
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
