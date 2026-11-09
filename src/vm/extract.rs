//! Recognizes VM structure in script syntax: the dispatch class, constructor, opcode handlers,
//! helper functions, state fields, and program runner. [`super::session`] evaluates what this
//! module finds.

use std::ptr;

use anyhow::{Context, Result, bail, ensure};
use oxc::ast::AstKind;
use oxc::ast::ast::{
    Argument as CallArgument, AssignmentExpression, AssignmentTarget, BindingIdentifier,
    BindingPattern, CallExpression, Class, ClassElement, Expression, FormalParameters, Function,
    FunctionBody, MemberExpression, MethodDefinitionKind, Statement, SwitchStatement,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::{ScopeFlags, SymbolId};
use oxc::span::GetSpan;
use oxc::syntax::operator::AssignmentOperator;

use super::output::Position;
use super::{HashMap, convert};
use crate::candidates;
use crate::js::ast::{self, Binding, Script};

/// Finds a class with a `run` method and the innermost function body declaring it: the last such
/// body in source order.
pub(super) fn find<'a>(script: Script<'a>) -> Option<(&'a FunctionBody<'a>, &'a Class<'a>)> {
    script
        .functions()
        .filter_map(|function| {
            let body = function.body.as_deref()?;
            Some((body, machine_class(body)?))
        })
        .last()
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
    pub function: &'ast Function<'ast>,
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
    fn machine(&self) -> Option<SymbolId> {
        let position = self
            .arguments
            .iter()
            .position(|argument| *argument == Argument::Machine)?;
        Some(parameter(&self.function.params, position)?.symbol_id())
    }
}

/// The locals of `run` and what they hold.
struct Locals<'a> {
    script: Script<'a>,
    sources: HashMap<Binding<'a>, Source>,
}

/// Tracks assignments in `run`, including copies of register fields and indices, program counter
/// and key setup, storing the third argument in the cells register, reading the program register,
/// and calling dispatch loops. An unsupported assignment clears the known value of its local.
pub(super) fn run_method<'a>(
    script: Script<'a>,
    functions: &HashMap<SymbolId, &'a Function<'a>>,
    run: &'a Function<'a>,
) -> Result<RunMethod<'a>> {
    let body = run.body.as_deref().context("the run method has no body")?;
    let sources = (0..run.params.items.len())
        .filter_map(|index| {
            let name = parameter(&run.params, index)?;
            Some((Binding::Symbol(name.symbol_id()), Source::Parameter(index)))
        })
        .collect();
    let mut locals = Locals { script, sources };
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
            if let Some((Source::Field(registers), arguments)) =
                locals.method_call(expression, "write")
                && let [Some(Source::Field(index)), Some(Source::Parameter(2))] = &arguments[..]
            {
                cells = Some((registers, index.clone()));
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
            if let Some(Source::Register { registers, index }) = &value {
                loaded.push((registers.clone(), index.clone()));
            }
            let binding = script.binding(name);
            match value {
                Some(value) => locals.sources.insert(binding, value),
                None => locals.sources.remove(&binding),
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
        script,
        functions,
        found: None,
    };
    calls.visit_function_body(body);
    let (function, call) = calls
        .found
        .context("the run method calls no dispatch loop with the machine")?;
    let arguments = call
        .arguments
        .iter()
        .map(|argument| match ast::argument_expression(argument) {
            Expression::ThisExpression(_) => Argument::Machine,
            Expression::Identifier(name) => match locals.sources.get(&script.binding(name)) {
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
struct DispatchCall<'functions, 'a> {
    script: Script<'a>,
    functions: &'functions HashMap<SymbolId, &'a Function<'a>>,
    found: Option<(&'a Function<'a>, &'a CallExpression<'a>)>,
}

impl<'a> Visit<'a> for DispatchCall<'_, 'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.found.is_none()
            && call.arguments.first().is_some_and(|first| {
                matches!(
                    ast::argument_expression(first),
                    Expression::ThisExpression(_)
                )
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
    /// Resolves `<object>.<name>(<arguments>)`, including the values of the object and
    /// arguments.
    fn method_call(
        &self,
        expression: &Expression<'a>,
        name: &str,
    ) -> Option<(Source, Vec<Option<Source>>)> {
        let (object, arguments) = ast::method_call(expression, name)?;
        let arguments = arguments
            .iter()
            .map(|argument| self.source(ast::argument_expression(argument)))
            .collect();
        Some((self.source(object)?, arguments))
    }

    fn source(&self, expression: &Expression<'a>) -> Option<Source> {
        match expression {
            Expression::Identifier(name) => self.sources.get(&self.script.binding(name)).cloned(),
            Expression::ParenthesizedExpression(paren) => self.source(&paren.expression),
            Expression::CallExpression(_) => match self.method_call(expression, "read")? {
                (Source::Field(registers), arguments) => match &arguments[..] {
                    [Some(Source::Field(index))] => Some(Source::Register {
                        registers,
                        index: index.clone(),
                    }),
                    _ => None,
                },
                _ => None,
            },
            expression => Some(Source::Field(this_field(expression)?.to_owned())),
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

/// Finds the string decryption function called by the register reader as
/// `decrypt(this.<values>[index])`.
pub(super) fn record_decoder<'a>(
    script: Script<'a>,
    body: &'a FunctionBody<'a>,
) -> Option<SymbolId> {
    /// Matches `<decoder>(this.<values>[<index>])`.
    struct Decoders<'a> {
        script: Script<'a>,
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
                    .is_some_and(|values| matches!(values.object(), Expression::ThisExpression(_)))
                && let MemberExpression::ComputedMemberExpression(member) = member
                && self.script.refers_to(&member.expression, self.index)
            {
                self.found.push(self.script.binding(callee));
            }
            walk::walk_call_expression(self, call);
        }
    }

    let read = body
        .statements
        .iter()
        .find_map(|statement| match statement {
            Statement::ClassDeclaration(class) if method(class, "write").is_some() => {
                method(class, "read")
            }
            _ => None,
        })?;
    let mut decoders = Decoders {
        script,
        index: parameter(&read.params, 0)?.symbol_id(),
        found: Vec::new(),
    };
    decoders.visit_function(read, ScopeFlags::Function);
    let [Binding::Symbol(decoder)] = decoders.found[..] else {
        return None;
    };
    Some(decoder)
}

/// The first class declaration with a `run` method.
fn machine_class<'a>(body: &'a FunctionBody<'a>) -> Option<&'a Class<'a>> {
    body.statements
        .iter()
        .find_map(|statement| match statement {
            Statement::ClassDeclaration(class) if method(class, "run").is_some() => Some(&**class),
            _ => None,
        })
}

/// The method, getter, or setter named `name`, excluding the constructor.
pub(super) fn method<'a>(class: &'a Class<'a>, name: &str) -> Option<&'a Function<'a>> {
    class.body.body.iter().find_map(|element| match element {
        ClassElement::MethodDefinition(method)
            if method.kind != MethodDefinitionKind::Constructor
                && ast::static_key_str(&method.key, method.computed) == Some(name) =>
        {
            Some(&*method.value)
        }
        _ => None,
    })
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

/// Where the program runner starts a program (see [`Runner`]).
pub(super) fn entry(body: &FunctionBody<'_>) -> Result<Position> {
    let runner = body
        .statements
        .iter()
        .find_map(|statement| match statement {
            Statement::ExpressionStatement(statement) => match &statement.expression {
                Expression::AssignmentExpression(assignment) => Runner::installed_by(assignment),
                _ => None,
            },
            _ => None,
        })
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
    fn installed_by(assignment: &AssignmentExpression<'ast>) -> Option<Self> {
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
        let (machine, [pc, key, ..]) = ast::method_call(returned.argument.as_ref()?, "run")? else {
            return None;
        };
        let (
            Expression::NewExpression(_),
            Expression::NumericLiteral(pc),
            Expression::NumericLiteral(key),
        ) = (
            machine,
            ast::argument_expression(pc),
            ast::argument_expression(key),
        )
        else {
            return None;
        };
        Some(Self {
            name: ast::member_str(target)?,
            pc: pc.value,
            key: key.value,
        })
    }
}

/// Returns the installed program runner's name if exactly one exists (see [`Runner`]).
pub(crate) fn runner_name(script: Script<'_>) -> Option<String> {
    let runners = script.nodes.iter().filter_map(|node| match node.kind() {
        AstKind::AssignmentExpression(assignment) => Runner::installed_by(assignment),
        _ => None,
    });
    let runner = candidates::exactly_one(runners, "program runner").ok()?;
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
        let script = parsed.script();
        let Some(Statement::FunctionDeclaration(function)) = script.program.body.first() else {
            panic!("the test source declares no function");
        };
        entry(function.body.as_deref().unwrap())
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
        let parsed = ParsedScript::parse(
            "t",
            "O.vlJM8 = function(p) { return new M(p).run(0, 238, []); }; \
             O.other = function(p) { return M(p).run(0, 238, []); }; O.vlJM8('a'); vlJM8('b');",
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
