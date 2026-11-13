//! Recognizes VM structure in script syntax: the dispatch class, constructor, opcode handlers,
//! helper functions, state fields, and program runner. [`super::session`] evaluates what this
//! module finds.

use std::ptr;

use anyhow::{Context, Result, bail, ensure};
use oxc::ast::AstKind;
use oxc::ast::ast::{
    Argument as CallArgument, AssignmentExpression, AssignmentTarget, BindingIdentifier,
    BindingPattern, CallExpression, Class, ClassElement, Expression, FormalParameters, Function,
    FunctionBody, IdentifierReference, MemberExpression, MethodDefinitionKind, Statement,
    SwitchStatement,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::{ScopeFlags, SymbolId};
use oxc::span::GetSpan;
use oxc::syntax::operator::AssignmentOperator;

use super::output::Position;
use super::{HashMap, convert};
use crate::candidates;
use crate::js::ast::{self, Binding, Script};

/// The VM as the program runner (see [`Runner`]) reveals it.
pub(super) struct Found<'a> {
    /// The function body declaring the class, the run function, and the handlers.
    pub body: &'a FunctionBody<'a>,
    pub class: &'a Class<'a>,
    /// The run function, called with a new machine, the entry position, and the cells.
    pub run: &'a Function<'a>,
    /// Where the runner starts a program.
    pub entry: Position,
}

/// Finds the VM from its one program runner: the class the runner constructs, the run function
/// it calls, and the function body declaring both.
pub(super) fn find<'a>(script: Script<'a>) -> Result<Found<'a>> {
    let runner = candidates::exactly_one(runners(script), "program runner")?;
    // The declaration of `reference` and its parent.
    let declaration = |reference: &IdentifierReference<'_>| {
        let symbol = script
            .symbol(reference)
            .with_context(|| format!("the runner's {} is global", reference.name))?;
        let node = script.scoping.symbol_declaration(symbol);
        anyhow::Ok((script.nodes.kind(node), script.nodes.parent_kind(node)))
    };
    let (AstKind::Class(class), AstKind::FunctionBody(body)) = declaration(runner.class)? else {
        bail!("the runner constructs no class declared directly in a function");
    };
    let (AstKind::Function(run), AstKind::FunctionBody(beside)) = declaration(runner.run)? else {
        bail!("the runner calls no function declared directly in a function");
    };
    ensure!(
        ptr::eq(body, beside),
        "the run function is not declared beside the VM class"
    );
    let pc = convert::position(runner.pc).context("the runner starts at no program position")?;
    let key = convert::byte(runner.key).context("the runner starts with no dispatch key")?;
    Ok(Found {
        body,
        class,
        run,
        entry: Position::new(pc, key),
    })
}

/// Collects the statements that run before the VM's scope is entered, both at script level and
/// in each enclosing function: at each level, the statements before the one containing `body`.
pub(super) fn prelude<'a>(
    script: Script<'a>,
    body: &'a FunctionBody<'a>,
) -> Vec<&'a Statement<'a>> {
    let mut enclosing: Vec<&'a [Statement<'a>]> = script
        .nodes
        .ancestor_kinds(body.node_id.get())
        .filter_map(|kind| match kind {
            AstKind::Function(function) => function.body.as_deref(),
            _ => None,
        })
        .filter(|enclosing| !ptr::eq(*enclosing, body))
        .map(|enclosing| &enclosing.statements[..])
        .collect();
    enclosing.push(&script.program.body);
    let mut prelude = Vec::new();
    for statements in enclosing.into_iter().rev() {
        let Some(index) = statements
            .iter()
            .position(|statement| statement.span().contains_inclusive(body.span))
        else {
            break;
        };
        prelude.extend(&statements[..index]);
    }
    prelude
}

/// Functions declared beside the class: handlers and their helpers.
pub(super) fn functions<'a>(
    statements: &'a [Statement<'a>],
) -> HashMap<SymbolId, &'a Function<'a>> {
    statements
        .iter()
        .filter_map(|statement| match statement {
            Statement::FunctionDeclaration(function) => {
                Some((function.id.as_ref()?.symbol_id(), &**function))
            }
            _ => None,
        })
        .collect()
}

/// Every parameter, if each is a plain identifier: no pattern, default, or rest.
pub(super) fn parameters<'a>(
    parameters: &'a FormalParameters<'a>,
) -> Option<Vec<&'a BindingIdentifier<'a>>> {
    if parameters.rest.is_some() {
        return None;
    }
    (0..parameters.items.len())
        .map(|index| parameter(parameters, index))
        .collect()
}

/// The parameter at `index`, if it is a plain identifier.
pub(super) fn parameter<'a>(
    parameters: &'a FormalParameters<'a>,
    index: usize,
) -> Option<&'a BindingIdentifier<'a>> {
    let parameter = parameters.items.get(index)?;
    match &parameter.pattern {
        BindingPattern::BindingIdentifier(name) if parameter.initializer.is_none() => Some(name),
        _ => None,
    }
}

/// The number of parameters, including a rest parameter.
pub(super) fn parameter_count(parameters: &FormalParameters<'_>) -> usize {
    parameters.items.len() + usize::from(parameters.rest.is_some())
}

/// The constructor's statements.
pub(super) fn constructor<'a>(class: &'a Class<'a>) -> Result<&'a [Statement<'a>]> {
    class
        .body
        .body
        .iter()
        .find_map(|element| match element {
            ClassElement::MethodDefinition(method)
                if method.kind == MethodDefinitionKind::Constructor =>
            {
                Some(&method.value.body.as_deref()?.statements[..])
            }
            _ => None,
        })
        .context("the VM class has no constructor")
}

/// What a local of the run function holds.
#[derive(Clone)]
enum Source {
    Parameter(usize),
    /// `<machine>.<name>`.
    Field(String),
    /// Register read as `<read>(<registers>, <index>)`. Both the register file and index come
    /// from fields.
    Register {
        registers: String,
        index: String,
        read: SymbolId,
    },
}

/// Register layout and state setup recovered from the run function.
pub(super) struct RunFunction<'ast> {
    /// Field containing the register file. Fields on that file identify the program counter and
    /// dispatch key registers.
    pub registers: String,
    /// Fields containing the cells and program register indices.
    pub cells: String,
    pub program: String,
    pub accessors: Accessors<'ast>,
    pub dispatch: DispatchLoop<'ast>,
}

/// The register file's reader, `read(registers, index)`, and writer,
/// `write(registers, index, value)`, which the run function calls.
#[derive(Clone, Copy)]
pub(crate) struct Accessors<'ast> {
    pub read: &'ast Function<'ast>,
    pub write: &'ast Function<'ast>,
}

/// Dispatch function declared beside the class and called by the run function with the machine.
/// Both dispatch loops dispatch the same handlers.
pub(crate) struct DispatchLoop<'ast> {
    pub function: &'ast Function<'ast>,
    /// Argument values passed by the run function, in parameter order.
    pub arguments: Vec<Argument>,
}

/// Argument passed from the run function to a dispatch loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Argument {
    Machine,
    Registers,
    Program,
    Other,
}

impl DispatchLoop<'_> {
    /// The parameter receiving the machine.
    fn machine(&self) -> Option<SymbolId> {
        let position = self
            .arguments
            .iter()
            .position(|argument| *argument == Argument::Machine)?;
        Some(parameter(&self.function.params, position)?.symbol_id())
    }
}

/// The locals of the run function and what they hold.
struct Locals<'a> {
    script: Script<'a>,
    /// The parameter receiving the machine.
    machine: SymbolId,
    sources: HashMap<Binding<'a>, Source>,
}

/// Tracks assignments in `run(machine, pc, key, cells)`, including copies of register fields and
/// indices, program counter and key setup, storing the cells argument in its register, reading
/// the program register, and calling dispatch loops. An unsupported assignment clears the known
/// value of its local.
pub(super) fn run_function<'a>(
    script: Script<'a>,
    functions: &HashMap<SymbolId, &'a Function<'a>>,
    run: &'a Function<'a>,
) -> Result<RunFunction<'a>> {
    let body = run
        .body
        .as_deref()
        .context("the run function has no body")?;
    let machine = parameter(&run.params, 0)
        .context("the run function takes no machine")?
        .symbol_id();
    let sources = (1..run.params.items.len())
        .filter_map(|index| {
            let name = parameter(&run.params, index)?;
            Some((Binding::Symbol(name.symbol_id()), Source::Parameter(index)))
        })
        .collect();
    let mut locals = Locals {
        script,
        machine,
        sources,
    };
    let mut cells = None;
    let mut loaded = Vec::new();
    for statement in &body.statements {
        let Statement::ExpressionStatement(statement) = statement else {
            continue;
        };
        let expressions: Vec<&Expression<'a>> = match &statement.expression {
            Expression::SequenceExpression(sequence) => sequence.expressions.iter().collect(),
            expression => vec![expression],
        };
        for expression in expressions {
            if let Some((write, arguments)) = locals.call(expression)
                && let [
                    Some(Source::Field(registers)),
                    Some(Source::Field(index)),
                    Some(Source::Parameter(3)),
                ] = &arguments[..]
            {
                cells = Some((registers.clone(), index.clone(), write));
                continue;
            }
            let Expression::AssignmentExpression(assignment) = expression else {
                continue;
            };
            let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left else {
                continue;
            };
            let value = match assignment.operator {
                AssignmentOperator::Assign => locals.source(&assignment.right),
                _ => None,
            };
            if let Some(Source::Register {
                registers,
                index,
                read,
            }) = &value
            {
                loaded.push((registers.clone(), index.clone(), *read));
            }
            let binding = script.binding(name);
            match value {
                Some(value) => locals.sources.insert(binding, value),
                None => locals.sources.remove(&binding),
            };
        }
    }
    let (registers, cells, write) =
        cells.context("the run function writes its cells argument to no register")?;
    loaded.retain(|(file, index, _)| *file == registers && *index != cells);
    loaded.sort();
    loaded.dedup();
    let [(_, program, read)] = &loaded[..] else {
        bail!(
            "the run function loads {} registers besides its arguments",
            loaded.len()
        );
    };
    let program = program.clone();
    let declared = |symbol: SymbolId, what: &str| {
        functions
            .get(&symbol)
            .copied()
            .with_context(|| format!("the register {what} is not declared beside the VM class"))
    };
    let accessors = Accessors {
        read: declared(*read, "reader")?,
        write: declared(write, "writer")?,
    };
    let mut calls = DispatchCall {
        script,
        functions,
        machine,
        found: None,
    };
    calls.visit_function_body(body);
    let (function, call) = calls
        .found
        .context("the run function calls no dispatch loop with the machine")?;
    let arguments = call
        .arguments
        .iter()
        .map(|argument| match ast::argument_expression(argument) {
            Expression::Identifier(name) if script.symbol(name) == Some(machine) => {
                Argument::Machine
            }
            Expression::Identifier(name) => match locals.sources.get(&script.binding(name)) {
                Some(Source::Field(field)) if *field == registers => Argument::Registers,
                Some(Source::Register { index, .. }) if *index == program => Argument::Program,
                _ => Argument::Other,
            },
            _ => Argument::Other,
        })
        .collect();
    Ok(RunFunction {
        registers,
        cells,
        program,
        accessors,
        dispatch: DispatchLoop {
            function,
            arguments,
        },
    })
}

/// Finds the first call in the run function whose first argument is the machine and whose target
/// contains a dispatch switch.
struct DispatchCall<'functions, 'a> {
    script: Script<'a>,
    functions: &'functions HashMap<SymbolId, &'a Function<'a>>,
    machine: SymbolId,
    found: Option<(&'a Function<'a>, &'a CallExpression<'a>)>,
}

impl<'a> Visit<'a> for DispatchCall<'_, 'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.found.is_none()
            && call.arguments.first().is_some_and(|first| {
                self.script
                    .refers_to(ast::argument_expression(first), self.machine)
            })
            && let Expression::Identifier(callee) = &call.callee
            && let Some(symbol) = self.script.symbol(callee)
            && let Some(&function) = self.functions.get(&symbol)
            && first_switch_in(function).is_some()
        {
            self.found = Some((
                function,
                self.script.lend(call, AstKind::as_call_expression),
            ));
        }
        walk::walk_call_expression(self, call);
    }
}

impl<'a> Locals<'a> {
    /// Resolves `<callee>(<arguments>)` for a callee the script declares, including the values
    /// of the arguments.
    fn call(&self, expression: &Expression<'a>) -> Option<(SymbolId, Vec<Option<Source>>)> {
        let (callee, arguments) = ast::direct_call(expression)?;
        let arguments = arguments
            .iter()
            .map(|argument| self.source(ast::argument_expression(argument)))
            .collect();
        Some((self.script.symbol(callee)?, arguments))
    }

    fn source(&self, expression: &Expression<'a>) -> Option<Source> {
        match expression {
            Expression::Identifier(name) => self.sources.get(&self.script.binding(name)).cloned(),
            Expression::ParenthesizedExpression(paren) => self.source(&paren.expression),
            Expression::CallExpression(_) => {
                let (read, arguments) = self.call(expression)?;
                let [Some(Source::Field(registers)), Some(Source::Field(index))] = &arguments[..]
                else {
                    return None;
                };
                Some(Source::Register {
                    registers: registers.clone(),
                    index: index.clone(),
                    read,
                })
            }
            expression => {
                let member = expression.as_member_expression()?;
                let field = ast::member_str(member)?;
                self.script
                    .refers_to(member.object(), self.machine)
                    .then(|| Source::Field(field.to_owned()))
            }
        }
    }
}

/// The field `this.<field>` reads.
pub(super) fn this_field<'a>(expression: &Expression<'a>) -> Option<&'a str> {
    let member = expression.as_member_expression()?;
    match member.object() {
        Expression::ThisExpression(_) => ast::member_str(member),
        _ => None,
    }
}

/// Finds the string decryption function the register reader `read(registers, index)` calls as
/// `decrypt(registers.<values>[index])`.
pub(super) fn record_decoder<'a>(script: Script<'a>, read: &'a Function<'a>) -> Option<SymbolId> {
    /// Matches `<decoder>(<registers>.<values>[<index>])`.
    struct Decoders<'a> {
        script: Script<'a>,
        registers: SymbolId,
        index: SymbolId,
        found: Vec<Binding<'a>>,
    }

    impl<'a> Visit<'a> for Decoders<'a> {
        fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
            if let Expression::Identifier(callee) = &call.callee
                && let [argument] = &call.arguments[..]
                && let Some(member) = ast::argument_expression(argument).as_member_expression()
                && member
                    .object()
                    .as_member_expression()
                    .is_some_and(|values| self.script.refers_to(values.object(), self.registers))
                && let MemberExpression::ComputedMemberExpression(member) = member
                && self.script.refers_to(&member.expression, self.index)
            {
                self.found.push(self.script.binding(callee));
            }
            walk::walk_call_expression(self, call);
        }
    }

    let mut decoders = Decoders {
        script,
        registers: parameter(&read.params, 0)?.symbol_id(),
        index: parameter(&read.params, 1)?.symbol_id(),
        found: Vec::new(),
    };
    decoders.visit_function(read, ScopeFlags::Function);
    let [Binding::Symbol(decoder)] = decoders.found[..] else {
        return None;
    };
    Some(decoder)
}

/// Extracts opcode and handler pairs from `case <opcode>: <handler>(<machine>); break;`.
pub(super) fn handlers<'a>(
    script: Script<'a>,
    functions: &HashMap<SymbolId, &'a Function<'a>>,
    dispatch: &DispatchLoop<'a>,
) -> Result<HashMap<u8, &'a Function<'a>>> {
    let switch = first_switch_in(dispatch.function).context("the dispatch loop has no switch")?;
    let machine = dispatch.machine();
    let is_machine = |argument: &CallArgument<'_>| {
        argument.as_expression().is_some_and(|argument| {
            machine.is_some_and(|machine| script.refers_to(argument, machine))
        })
    };
    let mut handlers = HashMap::default();
    for case in &switch.cases {
        let Some(test) = &case.test else { continue };
        let Expression::NumericLiteral(opcode) = test else {
            bail!("a dispatch case is not a number");
        };
        let opcode = convert::byte(opcode.value).context("a dispatch case is not an opcode")?;
        let call = case
            .consequent
            .iter()
            .find_map(|statement| match statement {
                Statement::ExpressionStatement(statement) => match &statement.expression {
                    Expression::CallExpression(call) => Some(call),
                    _ => None,
                },
                _ => None,
            })
            .with_context(|| format!("dispatch case {opcode} calls no handler"))?;
        let Expression::Identifier(name) = &call.callee else {
            bail!("dispatch case {opcode} calls no named handler");
        };
        let function = script
            .symbol(name)
            .and_then(|symbol| functions.get(&symbol))
            .with_context(|| format!("no handler function {}", name.name))?;
        ensure!(
            matches!(&call.arguments[..], [argument] if is_machine(argument)),
            "dispatch case {opcode} does not pass {} only the machine",
            name.name
        );
        let previous = handlers.insert(opcode, *function);
        ensure!(previous.is_none(), "opcode {opcode} has two dispatch cases");
    }
    Ok(handlers)
}

/// Finds the first dispatch switch in the body of `function`.
fn first_switch_in<'a>(function: &'a Function<'a>) -> Option<&'a SwitchStatement<'a>> {
    function
        .body
        .as_deref()?
        .statements
        .iter()
        .find_map(first_switch)
}

/// Finds the first dispatch `switch`; both dispatch loops use the same form.
fn first_switch<'a>(statement: &'a Statement<'a>) -> Option<&'a SwitchStatement<'a>> {
    match statement {
        Statement::SwitchStatement(switch) => Some(switch),
        Statement::BlockStatement(block) => block.body.iter().find_map(first_switch),
        Statement::WhileStatement(looping) => first_switch(&looping.body),
        Statement::IfStatement(branch) => {
            first_switch(&branch.consequent).or_else(|| first_switch(branch.alternate.as_ref()?))
        }
        Statement::TryStatement(attempt) => attempt.block.body.iter().find_map(first_switch),
        _ => None,
    }
}

/// The program runner, installed by
/// `<global>.<name> = function(p) { return <run>(new <Class>(p), pc, key, []); }`.
struct Runner<'ast> {
    /// The global property the runner is installed under. The name is random.
    name: &'ast str,
    /// The run function.
    run: &'ast IdentifierReference<'ast>,
    /// The VM class.
    class: &'ast IdentifierReference<'ast>,
    /// Initial program counter from the source.
    pc: f64,
    /// Initial dispatch key from the source.
    key: f64,
}

impl<'ast> Runner<'ast> {
    fn installed_by(assignment: &'ast AssignmentExpression<'ast>) -> Option<Self> {
        let target = assignment.left.as_member_expression()?;
        if matches!(target.object(), Expression::Super(_)) {
            return None;
        }
        let Expression::FunctionExpression(function) = &assignment.right else {
            return None;
        };
        let body = function.body.as_deref()?;
        if !body.directives.is_empty() {
            return None;
        }
        let [Statement::ReturnStatement(returned)] = after_bare_declarations(&body.statements)
        else {
            return None;
        };
        let (run, [machine, pc, key, _]) = ast::direct_call(returned.argument.as_ref()?)? else {
            return None;
        };
        let (
            Expression::NewExpression(machine),
            Expression::NumericLiteral(pc),
            Expression::NumericLiteral(key),
        ) = (
            ast::argument_expression(machine),
            ast::argument_expression(pc),
            ast::argument_expression(key),
        )
        else {
            return None;
        };
        let Expression::Identifier(class) = &machine.callee else {
            return None;
        };
        Some(Self {
            name: ast::member_str(target)?,
            run,
            class,
            pc: pc.value,
            key: key.value,
        })
    }
}

/// Every program runner the script installs.
fn runners<'a>(script: Script<'a>) -> impl Iterator<Item = Runner<'a>> {
    script.nodes.iter().filter_map(|node| match node.kind() {
        AstKind::AssignmentExpression(assignment) => Runner::installed_by(assignment),
        _ => None,
    })
}

/// Returns the installed program runner's name if exactly one exists (see [`Runner`]).
pub(crate) fn runner_name(script: Script<'_>) -> Option<String> {
    let runner = candidates::exactly_one(runners(script), "program runner").ok()?;
    Some(runner.name.to_owned())
}

/// Whether `call` calls the runner `name` installs, as `name(...)` or `<global>.name(...)`.
pub(crate) fn calls_runner(call: &CallExpression<'_>, name: &str) -> bool {
    match call.callee.without_parentheses() {
        Expression::Identifier(callee) => callee.name == name,
        callee => callee.as_member_expression().is_some_and(|member| {
            !matches!(member.object(), Expression::Super(_))
                && ast::member_str(member) == Some(name)
        }),
    }
}

/// Skips leading `var x;` declarations. Deobfuscation removes helper objects used to calculate
/// `run` arguments but may leave their declarations.
fn after_bare_declarations<'b, 'a>(statements: &'b [Statement<'a>]) -> &'b [Statement<'a>] {
    let start = statements
        .iter()
        .position(|statement| {
            !matches!(statement, Statement::VariableDeclaration(declaration)
                if !declaration.kind.is_using()
                    && declaration.declarations.iter().all(|declarator| declarator.init.is_none()))
        })
        .unwrap_or(statements.len());
    &statements[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::ast::ParsedScript;

    fn entry_of(source: &str) -> Result<Position> {
        let parsed = ParsedScript::parse("t", source).unwrap();
        find(parsed.script()).map(|found| found.entry)
    }

    #[test]
    fn finds_the_entry_past_leftover_declarations() {
        let vm = |runner: &str| {
            format!(
                "function f(O) {{ class M {{}} function run(m, pc, key, cells) {{}} O.vlJM8 = function(p) {{ {runner} }}; }}"
            )
        };
        for runner in [
            "return run(new M(p), 0, 238, []);",
            "var a; var b, c; return run(new M(p), 0, 238, []);",
        ] {
            let source = vm(runner);
            assert_eq!(
                entry_of(&source).unwrap(),
                Position::new(0, 238),
                "{source}"
            );
        }
        let source = vm("var a = g(); return run(new M(p), 0, 238, []);");
        assert!(
            entry_of(&source).is_err(),
            "a body that does more than return is not the entry"
        );
        let source = "function f(O) { class M {} O.vlJM8 = function(p) { return run(new M(p), 0, 238, []); }; } function run(m, pc, key, cells) {}";
        assert!(
            entry_of(source).is_err(),
            "the run function is declared beside the class"
        );
    }

    #[test]
    fn names_the_runner_its_callers_call() {
        let parsed = ParsedScript::parse(
            "t",
            "O.vlJM8 = function(p) { return run(new M(p), 0, 238, []); }; \
             O.other = function(p) { return run(M(p), 0, 238, []); }; O.vlJM8('a'); vlJM8('b');",
        )
        .unwrap();
        let script = parsed.script();
        let name = runner_name(script).unwrap();
        assert_eq!(name, "vlJM8");
        let calls: Vec<&CallExpression<'_>> = script
            .program
            .body
            .iter()
            .filter_map(|statement| match statement {
                Statement::ExpressionStatement(statement) => match &statement.expression {
                    Expression::CallExpression(call) => Some(&**call),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|call| calls_runner(call, &name)));
    }
}
