//! Recognizes VM structure in script syntax: the dispatch class, constructor, opcode handlers,
//! helper functions, state fields, and program runner. [`super::session`] evaluates what this
//! module finds.

use anyhow::{Context, Result, bail, ensure};
use swc_core::atoms::Atom;
use swc_core::common::Span;
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, BlockStmt, CallExpr, Class, ClassMember, Decl, Expr,
    ExprOrSpread, Function, Lit, ReturnStmt, Script, SimpleAssignTarget, Stmt, SwitchStmt,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use super::output::Position;
use super::{HashMap, convert};
use crate::js::ast;

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
    /// Register read as `<registers>.read(<index>)`. Both the register file and index come from
    /// fields.
    Register {
        registers: String,
        index: String,
    },
}

/// Register layout and state setup recovered from `run`.
pub(super) struct RunMethod<'ast> {
    /// Field containing the register file. Fields on that file identify the program counter and
    /// dispatch key registers.
    pub registers: String,
    /// Fields containing the cells and program register indices.
    pub cells: String,
    pub program: String,
    pub dispatch: DispatchLoop<'ast>,
}

/// Dispatch function declared beside the class and called by `run` with the machine. Some builds
/// move both loops out of `run`; both dispatch the same handlers.
pub(crate) struct DispatchLoop<'ast> {
    pub function: &'ast Function,
    /// Argument values passed by `run`, in parameter order.
    pub arguments: Vec<Argument>,
}

/// Argument passed from `run` to a dispatch loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Argument {
    Machine,
    Registers,
    Program,
    Other,
}

impl DispatchLoop<'_> {
    /// The parameter receiving the machine.
    fn machine(&self) -> Option<&Atom> {
        let position = self
            .arguments
            .iter()
            .position(|argument| *argument == Argument::Machine)?;
        Some(&self.function.params.get(position)?.pat.as_ident()?.sym)
    }
}

/// Tracks assignments in `run`, including copies of register fields and indices, program counter
/// and key setup, storing the third argument in the cells register, reading the program register,
/// and calling dispatch loops. An unsupported assignment clears the known value of its local.
pub(super) fn run_method<'a>(
    functions: &HashMap<Atom, &'a Function>,
    run: &Function,
) -> Result<RunMethod<'a>> {
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
    let mut cells = None;
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
            if let Some((Source::Field(registers), arguments)) = method_call(&locals, expr, "write")
                && let [Some(Source::Field(index)), Some(Source::Parameter(2))] = &arguments[..]
            {
                cells = Some((registers, index.clone()));
                continue;
            }
            let Expr::Assign(assign) = expr else { continue };
            let AssignTarget::Simple(SimpleAssignTarget::Ident(name)) = &assign.left else {
                continue;
            };
            let value = match assign.op {
                AssignOp::Assign => source(&locals, &assign.right),
                _ => None,
            };
            if let Some(Source::Register { registers, index }) = &value {
                loaded.push((registers.clone(), index.clone()));
            }
            match value {
                Some(value) => locals.insert(name.sym.clone(), value),
                None => locals.remove(&name.sym),
            };
        }
    }
    let (registers, cells) =
        cells.context("the run method writes its cells argument to no register")?;
    loaded.retain(|(file, index)| *file == registers && *index != cells);
    loaded.sort();
    loaded.dedup();
    let [(_, program)] = &loaded[..] else {
        bail!(
            "the run method loads {} registers besides its arguments",
            loaded.len()
        );
    };
    let program = program.clone();
    let mut calls = DispatchCall {
        functions,
        found: None,
    };
    body.visit_with(&mut calls);
    let (function, call) = calls
        .found
        .context("the run method calls no dispatch loop with the machine")?;
    let arguments = call
        .args
        .iter()
        .map(|argument| match &*argument.expr {
            Expr::This(_) => Argument::Machine,
            Expr::Ident(name) => match locals.get(&name.sym) {
                Some(Source::Field(field)) if *field == registers => Argument::Registers,
                Some(Source::Register { index, .. }) if *index == program => Argument::Program,
                _ => Argument::Other,
            },
            _ => Argument::Other,
        })
        .collect();
    Ok(RunMethod {
        registers,
        cells,
        program,
        dispatch: DispatchLoop {
            function,
            arguments,
        },
    })
}

/// Finds the first call in `run` whose first argument is the machine and whose target contains a
/// dispatch switch.
struct DispatchCall<'functions, 'ast> {
    functions: &'functions HashMap<Atom, &'ast Function>,
    found: Option<(&'ast Function, CallExpr)>,
}

impl Visit for DispatchCall<'_, '_> {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if self.found.is_none()
            && call
                .args
                .first()
                .is_some_and(|argument| argument.expr.is_this())
            && let Some(callee) = call.callee.as_expr().and_then(|callee| callee.as_ident())
            && let Some(&function) = self.functions.get(&callee.sym)
            && first_switch_in(function).is_some()
        {
            self.found = Some((function, call.clone()));
        }
        call.visit_children_with(self);
    }
}

/// Resolves `<object>.<name>(<arguments>)`, including the values of the object and arguments.
fn method_call(
    locals: &HashMap<Atom, Source>,
    expr: &Expr,
    name: &str,
) -> Option<(Source, Vec<Option<Source>>)> {
    let (object, arguments) = ast::method_call(expr, name)?;
    let arguments = arguments
        .iter()
        .map(|argument| source(locals, &argument.expr))
        .collect();
    Some((source(locals, object)?, arguments))
}

fn source(locals: &HashMap<Atom, Source>, expr: &Expr) -> Option<Source> {
    match expr {
        Expr::Ident(name) => locals.get(&name.sym).cloned(),
        Expr::Paren(paren) => source(locals, &paren.expr),
        Expr::Member(member) if member.obj.is_this() => {
            Some(Source::Field(ast::member_str(&member.prop)?.to_owned()))
        }
        Expr::Call(_) => match method_call(locals, expr, "read")? {
            (Source::Field(registers), arguments) => match &arguments[..] {
                [Some(Source::Field(index))] => Some(Source::Register {
                    registers,
                    index: index.clone(),
                }),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// Finds the string decryption function called by the register reader as
/// `decrypt(this.<values>[index])`.
pub(super) fn record_decoder(body: &BlockStmt) -> Option<Atom> {
    /// Matches `<decoder>(this.<values>[<index>])`.
    struct Decoders {
        index: Atom,
        found: Vec<Atom>,
    }

    impl Visit for Decoders {
        fn visit_call_expr(&mut self, call: &CallExpr) {
            if let Some(callee) = call.callee.as_expr().and_then(|callee| callee.as_ident())
                && let [argument] = &call.args[..]
                && let Some(member) = argument.expr.as_member()
                && member
                    .obj
                    .as_member()
                    .is_some_and(|values| values.obj.is_this())
                && member
                    .prop
                    .as_computed()
                    .and_then(|index| index.expr.as_ident())
                    .is_some_and(|name| name.sym == self.index)
            {
                self.found.push(callee.sym.clone());
            }
            call.visit_children_with(self);
        }
    }

    let read = body.stmts.iter().find_map(|statement| match statement {
        Stmt::Decl(Decl::Class(declaration)) if method(&declaration.class, "write").is_some() => {
            method(&declaration.class, "read")
        }
        _ => None,
    })?;
    let mut decoders = Decoders {
        index: read.params.first()?.pat.as_ident()?.sym.clone(),
        found: Vec::new(),
    };
    read.visit_with(&mut decoders);
    let [decoder]: [Atom; 1] = decoders.found.try_into().ok()?;
    Some(decoder)
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

/// Extracts opcode and handler pairs from `case <opcode>: <handler>(<machine>); break;`.
pub(super) fn handlers<'a>(
    functions: &HashMap<Atom, &'a Function>,
    dispatch: &DispatchLoop<'a>,
) -> Result<HashMap<u8, &'a Function>> {
    let switch = first_switch_in(dispatch.function).context("the dispatch loop has no switch")?;
    let machine = dispatch.machine();
    let is_machine = |argument: &ExprOrSpread| {
        argument.spread.is_none()
            && argument
                .expr
                .as_ident()
                .is_some_and(|name| Some(&name.sym) == machine)
    };
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
        let Some(name) = call.callee.as_expr().and_then(|callee| callee.as_ident()) else {
            bail!("dispatch case {opcode} calls no named handler");
        };
        let function = functions
            .get(&name.sym)
            .with_context(|| format!("no handler function {}", name.sym))?;
        ensure!(
            matches!(&call.args[..], [argument] if is_machine(argument)),
            "dispatch case {opcode} does not pass {} only the machine",
            name.sym
        );
        let previous = handlers.insert(opcode, *function);
        ensure!(previous.is_none(), "opcode {opcode} has two dispatch cases");
    }
    Ok(handlers)
}

/// Finds the first dispatch switch in the body of `function`.
fn first_switch_in(function: &Function) -> Option<&SwitchStmt> {
    function.body.as_ref()?.stmts.iter().find_map(first_switch)
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
