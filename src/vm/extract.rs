//! Recognizes VM structure in script syntax: the dispatch class, constructor, opcode handlers,
//! helper functions, state fields, and program runner. [`super::session`] evaluates what this
//! module finds.

use anyhow::{Context, Result, bail, ensure};
use swc_core::atoms::Atom;
use swc_core::common::Span;
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, BlockStmt, CallExpr, Callee, Class, ClassMember, Decl,
    Expr, ExprOrSpread, Function, Lit, MemberExpr, MemberProp, ReturnStmt, Script,
    SimpleAssignTarget, Stmt, SwitchStmt,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use super::output::Position;
use super::{HashMap, convert};
use crate::js::ast;

/// The handler an opcode dispatches to, and what the dispatch case passes it.
pub(crate) struct Handler<'ast> {
    pub function: &'ast Function,
    /// Whether the case calls it with the machine as `this`.
    pub bound: bool,
    pub arguments: Vec<Operand>,
}

#[derive(Clone, Copy)]
pub(crate) enum Operand {
    Machine,
    Number(f64),
}

/// Names of the fields that keep the run loop's state in `this.<registers>[this.<field>]`.
pub(super) struct StateFields {
    pub registers: String,
    pub pc: String,
    pub key: String,
    pub cells: String,
    pub program: String,
}

/// Finds a class with a `run` method and the innermost function body declaring it.
#[derive(Default)]
pub(super) struct Finder {
    pub found: Option<(BlockStmt, Class)>,
}

impl Visit for Finder {
    fn visit_function(&mut self, function: &Function) {
        if let Some(body) = &function.body
            && let Some(class) = machine_class(body)
        {
            self.found = Some((body.clone(), class.clone()));
        }
        function.visit_children_with(self);
    }
}

/// Collects the statements that run before the VM's scope is entered, both at script level and
/// in each enclosing function.
pub(super) fn prelude(script: &Script, body: &BlockStmt) -> Vec<Stmt> {
    use swc_core::common::Spanned;

    /// The outermost function body inside a statement that encloses `target`.
    struct Enclosing {
        target: Span,
        body: Option<BlockStmt>,
    }

    impl Visit for Enclosing {
        fn visit_function(&mut self, function: &Function) {
            match &function.body {
                Some(body) if body.span.contains(self.target) => self.body = Some(body.clone()),
                _ => function.visit_children_with(self),
            }
        }
    }

    let mut prelude = Vec::new();
    let mut statements = script.body.clone();
    while let Some(index) = statements
        .iter()
        .position(|statement| statement.span().contains(body.span))
    {
        let mut enclosing = Enclosing {
            target: body.span,
            body: None,
        };
        statements[index].visit_with(&mut enclosing);
        statements.truncate(index);
        prelude.append(&mut statements);
        match enclosing.body {
            Some(enclosing) if enclosing.span != body.span => statements = enclosing.stmts,
            _ => break,
        }
    }
    prelude
}

/// Functions declared beside the class: handlers and their helpers.
pub(super) fn functions(statements: &[Stmt]) -> HashMap<Atom, &Function> {
    statements
        .iter()
        .filter_map(|statement| {
            let function = statement.as_decl()?.as_fn_decl()?;
            Some((function.ident.sym.clone(), &*function.function))
        })
        .collect()
}

pub(super) fn constructor(class: &Class) -> Result<&BlockStmt> {
    class
        .body
        .iter()
        .find_map(|member| member.as_constructor()?.body.as_ref())
        .context("the VM class has no constructor")
}

/// What a `run` local holds.
#[derive(Clone)]
enum Source {
    Parameter(usize),
    /// `this.<name>`.
    Field(String),
    /// `this.<registers>[this.<index>]`.
    Register {
        registers: String,
        index: String,
    },
}

/// Finds [`StateFields`] by tracking plain assignments in `run`'s own statements. An unsupported
/// assigned value invalidates what is known about its local.
pub(super) fn state_fields(run: &Function) -> Result<StateFields> {
    let body = run.body.as_ref().context("the run method has no body")?;
    let mut locals: HashMap<Atom, Source> = run
        .params
        .iter()
        .enumerate()
        .filter_map(|(index, parameter)| {
            Some((
                parameter.pat.as_ident()?.sym.clone(),
                Source::Parameter(index),
            ))
        })
        .collect();
    let mut stored: [Option<(String, String)>; 3] = Default::default();
    let mut loaded = Vec::new();
    for statement in &body.stmts {
        let Stmt::Expr(statement) = statement else {
            continue;
        };
        let expressions: Vec<&Expr> = match &*statement.expr {
            Expr::Seq(sequence) => sequence.exprs.iter().map(|expr| &**expr).collect(),
            expr => vec![expr],
        };
        for expr in expressions {
            let Expr::Assign(assign) = expr else { continue };
            let value = match assign.op {
                AssignOp::Assign => source(&locals, &assign.right),
                _ => None,
            };
            match &assign.left {
                AssignTarget::Simple(SimpleAssignTarget::Ident(name)) => {
                    if let Some(Source::Register { index, .. }) = &value {
                        loaded.push(index.clone());
                    }
                    match value {
                        Some(value) => locals.insert(name.sym.clone(), value),
                        None => locals.remove(&name.sym),
                    };
                }
                AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
                    if let Some(Source::Register { registers, index }) =
                        member_source(&locals, member)
                        && let Some(Source::Parameter(parameter)) = value
                        && let Some(slot) = stored.get_mut(parameter)
                    {
                        *slot = Some((registers, index));
                    }
                }
                _ => {}
            }
        }
    }
    let [
        Some((registers, pc)),
        Some((key_registers, key)),
        Some((cell_registers, cells)),
    ] = stored
    else {
        bail!("the run method does not store its pc, key and cells in registers");
    };
    ensure!(
        registers == key_registers && registers == cell_registers,
        "the run method stores its arguments in different register files"
    );
    loaded.retain(|index| ![&pc, &key, &cells].contains(&index));
    loaded.sort();
    loaded.dedup();
    let [program] = &loaded[..] else {
        bail!(
            "the run method loads {} registers besides its arguments",
            loaded.len()
        );
    };
    Ok(StateFields {
        program: program.clone(),
        registers,
        pc,
        key,
        cells,
    })
}

fn source(locals: &HashMap<Atom, Source>, expr: &Expr) -> Option<Source> {
    match expr {
        Expr::Ident(name) => locals.get(&name.sym).cloned(),
        Expr::Paren(paren) => source(locals, &paren.expr),
        Expr::Member(member) => member_source(locals, member),
        _ => None,
    }
}

fn member_source(locals: &HashMap<Atom, Source>, member: &MemberExpr) -> Option<Source> {
    if let Expr::This(_) = &*member.obj {
        return Some(Source::Field(ast::member_str(&member.prop)?.to_owned()));
    }
    let MemberProp::Computed(index) = &member.prop else {
        return None;
    };
    match (source(locals, &member.obj)?, source(locals, &index.expr)?) {
        (Source::Field(registers), Source::Field(index)) => {
            Some(Source::Register { registers, index })
        }
        _ => None,
    }
}

/// The first class declaration with a `run` method.
fn machine_class(body: &BlockStmt) -> Option<&Class> {
    body.stmts.iter().find_map(|statement| match statement {
        Stmt::Decl(Decl::Class(declaration)) if method(&declaration.class, "run").is_some() => {
            Some(&*declaration.class)
        }
        _ => None,
    })
}

pub(super) fn method<'a>(class: &'a Class, name: &str) -> Option<&'a Function> {
    class.body.iter().find_map(|member| match member {
        ClassMember::Method(method) if ast::static_key_str(&method.key) == Some(name) => {
            Some(&*method.function)
        }
        _ => None,
    })
}

/// Reads `case <opcode>: <handler>(<operands>...); break;`, or `<handler>.call(this,
/// <operands>...)`, where each operand is `this` or a number.
pub(super) fn handlers<'a>(
    functions: &HashMap<Atom, &'a Function>,
    run: &'a Function,
) -> Result<HashMap<u8, Handler<'a>>> {
    let body = run.body.as_ref().context("the run method has no body")?;
    let switch = body
        .stmts
        .iter()
        .find_map(first_switch)
        .context("the run method has no switch")?;
    let mut handlers = HashMap::default();
    for case in &switch.cases {
        let Some(test) = &case.test else { continue };
        let Expr::Lit(Lit::Num(opcode)) = &**test else {
            bail!("a dispatch case is not a number");
        };
        let opcode = convert::byte(opcode.value).context("a dispatch case is not an opcode")?;
        let call = case
            .cons
            .iter()
            .find_map(|statement| statement.as_expr()?.expr.as_call())
            .with_context(|| format!("dispatch case {opcode} calls no handler"))?;
        let Callee::Expr(callee) = &call.callee else {
            bail!("dispatch case {opcode} calls no handler");
        };
        let (name, bound, operands) = match &**callee {
            Expr::Ident(name) => (name, false, &call.args[..]),
            Expr::Member(member) if ast::member_str(&member.prop) == Some("call") => {
                let Expr::Ident(name) = &*member.obj else {
                    bail!("dispatch case {opcode} calls no named handler");
                };
                let [receiver, operands @ ..] = &call.args[..] else {
                    bail!(
                        "dispatch case {opcode} calls {} without a receiver",
                        name.sym
                    );
                };
                ensure!(
                    matches!(operand(receiver), Some(Operand::Machine)),
                    "dispatch case {opcode} does not call {} on the machine",
                    name.sym
                );
                (name, true, operands)
            }
            _ => bail!("dispatch case {opcode} calls no named handler"),
        };
        let function = functions
            .get(&name.sym)
            .with_context(|| format!("no handler function {}", name.sym))?;
        let arguments: Option<Vec<Operand>> = operands.iter().map(operand).collect();
        let arguments = arguments.with_context(|| {
            let name = &name.sym;
            format!("an argument of handler {name} is neither the machine nor a number")
        })?;
        let previous = handlers.insert(
            opcode,
            Handler {
                function,
                bound,
                arguments,
            },
        );
        ensure!(previous.is_none(), "opcode {opcode} has two dispatch cases");
    }
    Ok(handlers)
}

fn operand(argument: &ExprOrSpread) -> Option<Operand> {
    match (&argument.spread, &*argument.expr) {
        (None, Expr::This(_)) => Some(Operand::Machine),
        (None, Expr::Lit(Lit::Num(number))) => Some(Operand::Number(number.value)),
        _ => None,
    }
}

/// Finds the first dispatch `switch`; both dispatch loops use the same form.
fn first_switch(statement: &Stmt) -> Option<&SwitchStmt> {
    match statement {
        Stmt::Switch(switch) => Some(switch),
        Stmt::Block(block) => block.stmts.iter().find_map(first_switch),
        Stmt::While(looping) => first_switch(&looping.body),
        Stmt::If(branch) => {
            first_switch(&branch.cons).or_else(|| first_switch(branch.alt.as_deref()?))
        }
        Stmt::Try(attempt) => attempt.block.stmts.iter().find_map(first_switch),
        _ => None,
    }
}

/// Where the program runner starts a program (see [`Runner`]).
pub(super) fn entry(body: &BlockStmt) -> Result<Position> {
    let runner = body
        .stmts
        .iter()
        .find_map(|statement| Runner::installed_by(statement.as_expr()?.expr.as_assign()?))
        .context("no program runner in the VM's scope")?;
    let pc = convert::position(runner.pc).context("the runner starts at no program position")?;
    let key = convert::byte(runner.key).context("the runner starts with no dispatch key")?;
    Ok(Position::new(pc, key))
}

/// The program runner, installed by
/// `<global>.<name> = function(p) { return new <Class>(p).run(pc, key, []); }`.
struct Runner<'ast> {
    /// The global property the runner is installed under. The name is random.
    name: &'ast str,
    /// Initial program counter from the source.
    pc: f64,
    /// Initial dispatch key from the source.
    key: f64,
}

impl<'ast> Runner<'ast> {
    fn installed_by(assign: &'ast AssignExpr) -> Option<Self> {
        let AssignTarget::Simple(SimpleAssignTarget::Member(target)) = &assign.left else {
            return None;
        };
        let body = assign.right.as_fn_expr()?.function.body.as_ref()?;
        let [
            Stmt::Return(ReturnStmt {
                arg: Some(call), ..
            }),
        ] = after_bare_declarations(&body.stmts)
        else {
            return None;
        };
        let (machine, [pc, key, ..]) = ast::method_call(call, "run")? else {
            return None;
        };
        let (Expr::New(_), Expr::Lit(Lit::Num(pc)), Expr::Lit(Lit::Num(key))) =
            (machine, &*pc.expr, &*key.expr)
        else {
            return None;
        };
        Some(Self {
            name: ast::member_str(&target.prop)?,
            pc: pc.value,
            key: key.value,
        })
    }
}

/// Returns the installed program runner's name if exactly one exists (see [`Runner`]).
pub(crate) fn runner_name(script: &Script) -> Option<String> {
    #[derive(Default)]
    struct Names(Vec<String>);

    impl Visit for Names {
        fn visit_assign_expr(&mut self, assign: &AssignExpr) {
            if let Some(runner) = Runner::installed_by(assign) {
                self.0.push(runner.name.to_owned());
            }
            assign.visit_children_with(self);
        }
    }

    let mut names = Names::default();
    script.visit_with(&mut names);
    let [name]: [String; 1] = names.0.try_into().ok()?;
    Some(name)
}

/// Whether `call` calls the runner `name` installs, as `name(...)` or `<global>.name(...)`.
pub(crate) fn calls_runner(call: &CallExpr, name: &str) -> bool {
    match call.callee.as_expr().map(|callee| callee.unwrap_parens()) {
        Some(Expr::Ident(callee)) => callee.sym == name,
        Some(Expr::Member(member)) => ast::member_str(&member.prop) == Some(name),
        _ => false,
    }
}

/// Skips leading `var x;` declarations. Deobfuscation removes helper objects used to calculate
/// `run` arguments but may leave their declarations.
fn after_bare_declarations(statements: &[Stmt]) -> &[Stmt] {
    let start = statements
        .iter()
        .position(|statement| {
            !matches!(statement, Stmt::Decl(Decl::Var(declaration))
                if declaration.decls.iter().all(|declarator| declarator.init.is_none()))
        })
        .unwrap_or(statements.len());
    &statements[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_of(source: &str) -> Result<Position> {
        let parsed = ast::parse_javascript("t", source).unwrap();
        let Some(Stmt::Decl(Decl::Fn(function))) = parsed.script.body.first() else {
            panic!("the test source declares no function");
        };
        entry(function.function.body.as_ref().unwrap())
    }

    #[test]
    fn finds_the_entry_past_leftover_declarations() {
        for source in [
            "function f(O) { O.vlJM8 = function(p) { return new M(p).run(0, 238, []); }; }",
            "function f(O) { O.vlJM8 = function(p) { var a; var b, c; return new M(p).run(0, 238, []); }; }",
        ] {
            assert_eq!(entry_of(source).unwrap(), Position::new(0, 238), "{source}");
        }
        let source = "function f(O) { O.vlJM8 = function(p) { var a = g(); return new M(p).run(0, 238, []); }; }";
        assert!(
            entry_of(source).is_err(),
            "a body that does more than return is not the entry"
        );
    }

    #[test]
    fn names_the_runner_its_callers_call() {
        let parsed = ast::parse_javascript(
            "t",
            "O.vlJM8 = function(p) { return new M(p).run(0, 238, []); }; \
             O.other = function(p) { return M(p).run(0, 238, []); }; O.vlJM8('a'); vlJM8('b');",
        )
        .unwrap();
        let name = runner_name(&parsed.script).unwrap();
        assert_eq!(name, "vlJM8");
        let calls: Vec<&CallExpr> = parsed
            .script
            .body
            .iter()
            .filter_map(|statement| statement.as_expr()?.expr.as_call())
            .collect();
        assert!(calls.iter().all(|call| calls_runner(call, &name)));
    }
}
