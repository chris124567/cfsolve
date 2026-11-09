//! Compiles JavaScript into plans, which [`super::compile`] turns into closures. Slot plans store function locals
//! in numbered slots, except locals that nested functions mention, which stay in the call's
//! scope for those functions to capture. Scoped plans resolve every binding through scopes.
//! Unsupported syntax becomes a node that stops evaluation if reached.

#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::ptr;
use std::rc::Rc;

use oxc::ast::ast::{
    Argument, ArrayExpressionElement, ArrowFunctionBody, ArrowFunctionExpression,
    BindingIdentifier, BindingPattern, CatchClause, Class, Expression as Expr, ForStatementInit,
    FormalParameters, Function, IdentifierReference, MemberExpression, ObjectPropertyKind,
    PropertyKey, PropertyKind, SimpleAssignmentTarget, Statement as Stmt, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::{ScopeFlags, SymbolId};
use oxc::syntax::operator::{BinaryOperator, LogicalOperator, UnaryOperator, UpdateOperator};

use super::compile::{self, Code};
use super::semantics;
use crate::js::ast::{Binding, Script};
use crate::vm::value::Value;
use crate::vm::{HashMap, HashSet, extract};

/// What a call runs: parameters, then a body. A script function's body is its statements; the
/// dispatch decoder's is assembled from the dispatch loop (see [`crate::vm::dispatch`]).
#[derive(Clone, Copy)]
pub(crate) struct Routine<'ast> {
    pub(crate) parameters: &'ast FormalParameters<'ast>,
    /// Declarations run first without their initializers, so they only declare their names.
    pub(crate) declarations: &'ast [&'ast VariableDeclaration<'ast>],
    pub(crate) statements: &'ast [Stmt<'ast>],
    /// What the routine returns after its statements, if they do not return.
    pub(crate) returns: Option<&'ast Expr<'ast>>,
    /// Identifies the routine's plans: the address of the function body or decoder.
    pub(crate) address: usize,
}

impl<'ast> Routine<'ast> {
    /// The routine of a function with a body.
    pub(crate) fn function(function: &'ast Function<'ast>) -> Option<Self> {
        let body = function.body.as_deref()?;
        Some(Self {
            parameters: &function.params,
            declarations: &[],
            statements: &body.statements,
            returns: None,
            address: ptr::from_ref(body).addr(),
        })
    }
}

/// Caches plans by source-node address. The session's definition keeps those nodes alive longer
/// than the cache.
#[derive(Default)]
pub(crate) struct Plans<'ast> {
    /// `None` marks routines that need a scoped plan.
    pub(super) slot_plans: RefCell<HashMap<usize, Option<Rc<FunctionPlan<'ast>>>>>,
    scoped_plans: RefCell<HashMap<usize, Rc<[Code<'ast>]>>>,
    /// Forces scoped plans for comparison tests.
    #[cfg(test)]
    pub(super) disabled: Cell<bool>,
}

impl<'ast> Plans<'ast> {
    pub(super) fn slots(
        &self,
        script: Script<'ast>,
        routine: Routine<'ast>,
    ) -> Option<Rc<FunctionPlan<'ast>>> {
        #[cfg(test)]
        if self.disabled.get() {
            return None;
        }
        if let Some(plan) = self.slot_plans.borrow().get(&routine.address) {
            return plan.clone();
        }
        let plan = FunctionPlan::compile(script, routine).map(Rc::new);
        self.slot_plans
            .borrow_mut()
            .insert(routine.address, plan.clone());
        plan
    }

    /// Returns the scoped plan of the routine or arrow at `address`, compiling `plan` on first
    /// use.
    pub(super) fn scoped(
        &self,
        address: usize,
        plan: impl FnOnce() -> Vec<Statement<'ast>>,
    ) -> Rc<[Code<'ast>]> {
        if let Some(plan) = self.scoped_plans.borrow().get(&address) {
            return plan.clone();
        }
        let plan: Rc<[Code<'ast>]> = compile::statements(&plan()).into();
        self.scoped_plans.borrow_mut().insert(address, plan.clone());
        plan
    }
}

pub(super) struct FunctionPlan<'ast> {
    /// Where each parameter is bound: a slot, or the call's scope if a nested function
    /// mentions it.
    pub(super) parameters: Vec<Name<'ast>>,
    /// The slot of `arguments`, if the body reads it.
    pub(super) arguments: Option<usize>,
    pub(super) locals: usize,
    /// The body, compiled into closures.
    pub(super) code: Vec<Code<'ast>>,
}

impl<'ast> FunctionPlan<'ast> {
    /// Attempts to compile a slot plan. Returns `None` to request a scoped plan for unsupported
    /// syntax, parenthesized callees, computed object keys, logical assignments, parameter
    /// patterns, variables named `arguments`, or arrows reading `arguments`.
    pub(super) fn compile(script: Script<'ast>, routine: Routine<'ast>) -> Option<Self> {
        let mut compiler = PlanCompiler {
            captured: captured(script, routine),
            ..PlanCompiler::new(script)
        };
        let parameters = extract::parameters(routine.parameters)?;
        let mut names = Vec::with_capacity(parameters.len());
        for parameter in parameters {
            if parameter.name == "arguments" {
                return None;
            }
            let binding = Binding::Symbol(parameter.symbol_id());
            compiler.local(binding);
            names.push(compiler.name(binding));
        }
        for declaration in routine.declarations {
            for declarator in &declaration.declarations {
                compiler.declared(declarator);
            }
        }
        for statement in routine.statements {
            compiler.visit_statement(statement);
        }
        let body = compiler.routine(routine);
        if compiler.rejected {
            return None;
        }
        Some(Self {
            parameters: names,
            arguments: compiler.locals.get(&Binding::Global("arguments")).copied(),
            locals: compiler.locals.len(),
            code: compile::statements(&body),
        })
    }
}

pub(super) fn scoped_statement<'ast>(
    script: Script<'ast>,
    statement: &'ast Stmt<'ast>,
) -> Statement<'ast> {
    PlanCompiler::new(script).statement(statement, None)
}

/// Scoped execution plan for a routine's body. Function declarations bind their names at the
/// start of the call.
pub(super) fn scoped_routine<'ast>(
    script: Script<'ast>,
    routine: Routine<'ast>,
) -> Vec<Statement<'ast>> {
    PlanCompiler::new(script).routine(routine)
}

pub(super) fn scoped_expression<'ast>(
    script: Script<'ast>,
    expression: &'ast Expr<'ast>,
) -> Expression<'ast> {
    PlanCompiler::new(script).expression(expression)
}

pub(super) fn scoped_arrow<'ast>(
    script: Script<'ast>,
    arrow: &'ast ArrowFunctionExpression<'ast>,
) -> Vec<Statement<'ast>> {
    let mut compiler = PlanCompiler::new(script);
    match &arrow.body {
        ArrowFunctionBody::FunctionBody(body) => compiler.body(&body.statements),
        body => {
            let body = body
                .as_expression()
                .expect("an arrow body is a block or an expression");
            vec![Statement::Return(Some(compiler.expression(body)))]
        }
    }
}

struct PlanCompiler<'a> {
    script: Script<'a>,
    /// Slots of a slot plan's locals; empty for scoped plans.
    locals: HashMap<Binding<'a>, usize>,
    /// Bindings nested functions mention. These locals stay in the call's scope.
    captured: HashSet<SymbolId>,
    /// Whether compilation needs a scoped plan. Ignored when compiling scoped plans.
    rejected: bool,
}

impl<'a> Visit<'a> for PlanCompiler<'a> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        self.declared(declarator);
        walk::walk_variable_declarator(self, declarator);
    }

    fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
        if reference.name == "arguments" {
            self.local(self.script.binding(reference));
        }
    }

    /// Treat a nested function declaration as a local binding in the enclosing function. A
    /// nested function's own locals remain separate.
    fn visit_function(&mut self, function: &Function<'a>, _: ScopeFlags) {
        if function.is_declaration()
            && let Some(name) = &function.id
        {
            self.local(Binding::Symbol(name.symbol_id()));
        }
    }

    /// Treat a `catch` parameter as a function local in the execution plan.
    fn visit_catch_clause(&mut self, clause: &CatchClause<'a>) {
        if let Some(parameter) = &clause.param
            && let BindingPattern::BindingIdentifier(name) = &parameter.pattern
        {
            self.local(Binding::Symbol(name.symbol_id()));
        }
        walk::walk_catch_clause(self, clause);
    }

    fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
    fn visit_class(&mut self, _: &Class<'a>) {}
}

/// The symbols of a routine's own bindings that functions, arrows, and classes nested in it
/// reference. A function's `arguments` has no symbol; arrows reading it are rejected.
fn captured<'a>(script: Script<'a>, routine: Routine<'a>) -> HashSet<SymbolId> {
    #[derive(Default)]
    struct Bindings(HashSet<SymbolId>);

    impl<'a> Visit<'a> for Bindings {
        fn visit_binding_identifier(&mut self, name: &BindingIdentifier<'a>) {
            self.0.insert(name.symbol_id());
        }

        fn visit_function(&mut self, function: &Function<'a>, _: ScopeFlags) {
            if function.is_declaration()
                && let Some(name) = &function.id
            {
                self.0.insert(name.symbol_id());
            }
        }

        fn visit_class(&mut self, class: &Class<'a>) {
            if class.is_declaration()
                && let Some(name) = &class.id
            {
                self.0.insert(name.symbol_id());
            }
        }

        fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
    }

    struct References<'s, 'a> {
        script: Script<'a>,
        bindings: &'s HashSet<SymbolId>,
        captured: HashSet<SymbolId>,
    }

    impl<'a> Visit<'a> for References<'_, 'a> {
        fn visit_identifier_reference(&mut self, reference: &IdentifierReference<'a>) {
            if let Some(symbol) = self.script.symbol(reference)
                && self.bindings.contains(&symbol)
            {
                self.captured.insert(symbol);
            }
        }
    }

    struct Nested<'s, 'a>(References<'s, 'a>);

    impl<'a> Visit<'a> for Nested<'_, 'a> {
        fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
            self.0.visit_function(function, flags);
        }

        fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
            self.0.visit_arrow_function_expression(arrow);
        }

        fn visit_class(&mut self, class: &Class<'a>) {
            self.0.visit_class(class);
        }
    }

    let mut bindings = Bindings::default();
    bindings.visit_formal_parameters(routine.parameters);
    for declaration in routine.declarations {
        for declarator in &declaration.declarations {
            bindings.visit_binding_pattern(&declarator.id);
        }
    }
    for statement in routine.statements {
        bindings.visit_statement(statement);
    }
    let mut nested = Nested(References {
        script,
        bindings: &bindings.0,
        captured: HashSet::default(),
    });
    for statement in routine.statements {
        nested.visit_statement(statement);
    }
    nested.0.captured
}

/// Whether a visited node mentions `arguments`, to reject arrows that read the enclosing one.
#[derive(Default)]
struct MentionsArguments(bool);

impl<'a> Visit<'a> for MentionsArguments {
    fn visit_identifier_reference(&mut self, name: &IdentifierReference<'a>) {
        self.0 |= name.name == "arguments";
    }

    fn visit_binding_identifier(&mut self, name: &BindingIdentifier<'a>) {
        self.0 |= name.name == "arguments";
    }
}

pub(super) struct Case<'ast> {
    pub(super) test: Option<Expression<'ast>>,
    pub(super) body: Vec<Statement<'ast>>,
}

/// One variable a `var` statement declares.
pub(super) struct Declaration<'ast> {
    pub(super) name: Name<'ast>,
    pub(super) init: Option<Expression<'ast>>,
    /// A `var` declaration without an initializer preserves any existing value.
    pub(super) keeps: bool,
}

pub(super) enum Statement<'ast> {
    Switch(Expression<'ast>, Vec<Case<'ast>>),
    Expression(Expression<'ast>),
    Declare(Vec<Declaration<'ast>>),
    Block(Vec<Statement<'ast>>),
    If(
        Expression<'ast>,
        Box<Statement<'ast>>,
        Option<Box<Statement<'ast>>>,
    ),
    Return(Option<Expression<'ast>>),
    Throw(Expression<'ast>),
    Loop {
        init: Option<Box<Statement<'ast>>>,
        test: Option<Expression<'ast>>,
        update: Option<Expression<'ast>>,
        body: Box<Statement<'ast>>,
        /// Whether the body runs once before the test, as in `do ... while`.
        body_first: bool,
        label: Option<&'ast str>,
    },
    Break(Option<&'ast str>),
    Continue(Option<&'ast str>),
    Label(&'ast str, Box<Statement<'ast>>),
    /// A `try` statement with its catch parameter, catch body, and finally body.
    Try {
        block: Vec<Statement<'ast>>,
        parameter: Option<Name<'ast>>,
        handler: Option<Vec<Statement<'ast>>>,
        finalizer: Option<Vec<Statement<'ast>>>,
    },
    Empty,
}

pub(super) enum Expression<'ast> {
    Logical {
        operator: LogicalOperator,
        left: Box<Expression<'ast>>,
        right: Box<Expression<'ast>>,
        /// Whether the right side is [`pure`].
        pure: bool,
    },
    Constant(Value<'ast>),
    Name(Name<'ast>),
    This,
    Sequence(Vec<Expression<'ast>>),
    Member(Box<Expression<'ast>>, Property<'ast>),
    Call(Box<Expression<'ast>>, Vec<Expression<'ast>>),
    New(Box<Expression<'ast>>, Vec<Expression<'ast>>),
    Binary(BinaryOperator, Box<Expression<'ast>>, Box<Expression<'ast>>),
    /// An arithmetic or bitwise operator, with its operation on numbers (see
    /// [`semantics::numeric`]).
    Arithmetic {
        operator: BinaryOperator,
        operation: fn(f64, f64) -> f64,
        left: Box<Expression<'ast>>,
        right: Box<Expression<'ast>>,
    },
    Unary(UnaryOperator, Box<Expression<'ast>>),
    Assign(Target<'ast>, Option<BinaryOperator>, Box<Expression<'ast>>),
    /// `&&=`, `||=` or `??=`, which stops evaluation once its target is located.
    LogicalAssign(Target<'ast>),
    Update {
        target: Target<'ast>,
        operator: UpdateOperator,
        prefix: bool,
    },
    Conditional(
        Box<Expression<'ast>>,
        Box<Expression<'ast>>,
        Box<Expression<'ast>>,
    ),
    Array(Vec<Option<Expression<'ast>>>),
    Object(Vec<(Property<'ast>, Expression<'ast>)>),
    Function(Option<&'ast str>, &'ast Function<'ast>),
    Arrow(&'ast ArrowFunctionExpression<'ast>),
    /// Syntax the interpreter does not follow, described for diagnostics.
    Unsupported(&'static str),
}

pub(super) enum Property<'ast> {
    Name(&'ast str),
    Computed(Box<Expression<'ast>>),
}

pub(super) enum Target<'ast> {
    Name(Name<'ast>),
    Member(Box<Expression<'ast>>, Property<'ast>),
}

/// A binding a plan reads or writes: a local, by its slot, or a binding resolved through
/// scopes.
#[derive(Clone, Copy)]
pub(super) enum Name<'ast> {
    Local(usize, Binding<'ast>),
    Scoped(Binding<'ast>),
}

impl<'ast> Name<'ast> {
    pub(super) fn binding(self) -> Binding<'ast> {
        match self {
            Self::Local(_, binding) | Self::Scoped(binding) => binding,
        }
    }
}

impl<'a> PlanCompiler<'a> {
    fn new(script: Script<'a>) -> Self {
        Self {
            script,
            locals: HashMap::default(),
            captured: HashSet::default(),
            rejected: false,
        }
    }

    /// Gives local `binding` a slot unless a nested function mentions it.
    fn local(&mut self, binding: Binding<'a>) {
        if let Binding::Symbol(symbol) = binding
            && self.captured.contains(&symbol)
        {
            return;
        }
        let next = self.locals.len();
        self.locals.entry(binding).or_insert(next);
    }

    /// Gives the variable `declarator` declares a slot.
    fn declared(&mut self, declarator: &VariableDeclarator<'a>) {
        if let BindingPattern::BindingIdentifier(name) = &declarator.id {
            self.local(Binding::Symbol(name.symbol_id()));
        }
    }

    /// Plans a routine: its function declarations, then its declarations without initializers,
    /// its statements, and what it returns.
    fn routine(&mut self, routine: Routine<'a>) -> Vec<Statement<'a>> {
        let mut plan = self.hoisted(routine.statements);
        for declaration in routine.declarations {
            plan.push(self.variables(declaration, false));
        }
        plan.extend(self.statements(routine.statements));
        if let Some(returned) = routine.returns {
            plan.push(Statement::Return(Some(self.expression(returned))));
        }
        plan
    }

    /// Plans a function body or block, binding its function declarations before executing
    /// statements, as JavaScript hoists them to the start of the body or block. Declarations
    /// beside the VM class are planned as statements and resolve through the session.
    fn body(&mut self, statements: &'a [Stmt<'a>]) -> Vec<Statement<'a>> {
        let mut plan = self.hoisted(statements);
        plan.extend(self.statements(statements));
        plan
    }

    /// Declarations binding the functions `statements` declare.
    fn hoisted(&mut self, statements: &'a [Stmt<'a>]) -> Vec<Statement<'a>> {
        let mut plan = Vec::with_capacity(statements.len());
        for statement in statements {
            if let Stmt::FunctionDeclaration(function) = statement
                && let Some(name) = &function.id
            {
                plan.push(Statement::Declare(vec![Declaration {
                    name: self.name(Binding::Symbol(name.symbol_id())),
                    init: Some(Expression::Function(Some(name.name.as_str()), function)),
                    keeps: false,
                }]));
            }
        }
        plan
    }

    fn statements(&mut self, statements: &'a [Stmt<'a>]) -> Vec<Statement<'a>> {
        statements
            .iter()
            .map(|statement| self.statement(statement, None))
            .collect()
    }

    fn statement(&mut self, statement: &'a Stmt<'a>, label: Option<&'a str>) -> Statement<'a> {
        match statement {
            Stmt::ExpressionStatement(expression) => {
                Statement::Expression(self.expression(&expression.expression))
            }
            Stmt::VariableDeclaration(declaration) if !declaration.kind.is_using() => {
                self.variables(declaration, true)
            }
            // Declarations do not bind their names; the names resolve through scopes.
            Stmt::FunctionDeclaration(_) | Stmt::ClassDeclaration(_) | Stmt::EmptyStatement(_) => {
                Statement::Empty
            }
            Stmt::BlockStatement(block) => Statement::Block(self.body(&block.body)),
            Stmt::IfStatement(branch) => Statement::If(
                self.expression(&branch.test),
                Box::new(self.statement(&branch.consequent, None)),
                branch
                    .alternate
                    .as_ref()
                    .map(|alternate| Box::new(self.statement(alternate, None))),
            ),
            Stmt::ReturnStatement(returned) => Statement::Return(
                returned
                    .argument
                    .as_ref()
                    .map(|argument| self.expression(argument)),
            ),
            Stmt::ThrowStatement(thrown) => Statement::Throw(self.expression(&thrown.argument)),
            Stmt::SwitchStatement(switch) => {
                let discriminant = self.expression(&switch.discriminant);
                let cases = switch.cases.iter().map(|case| Case {
                    test: case.test.as_ref().map(|test| self.expression(test)),
                    body: self.statements(&case.consequent),
                });
                Statement::Switch(discriminant, cases.collect())
            }
            Stmt::BreakStatement(branch) => {
                Statement::Break(branch.label.as_ref().map(|label| label.name.as_str()))
            }
            Stmt::ContinueStatement(branch) => {
                Statement::Continue(branch.label.as_ref().map(|label| label.name.as_str()))
            }
            Stmt::LabeledStatement(labeled) => {
                let name = labeled.label.name.as_str();
                Statement::Label(name, Box::new(self.statement(&labeled.body, Some(name))))
            }
            Stmt::ForStatement(looping) => Statement::Loop {
                init: looping.init.as_ref().map(|init| {
                    Box::new(match init {
                        ForStatementInit::VariableDeclaration(declaration)
                            if !declaration.kind.is_using() =>
                        {
                            self.variables(declaration, true)
                        }
                        ForStatementInit::VariableDeclaration(_) => {
                            Statement::Expression(self.unsupported("a declaration"))
                        }
                        init => Statement::Expression(
                            self.expression(init.as_expression().expect("an expression")),
                        ),
                    })
                }),
                test: looping.test.as_ref().map(|test| self.expression(test)),
                update: looping
                    .update
                    .as_ref()
                    .map(|update| self.expression(update)),
                body: Box::new(self.statement(&looping.body, None)),
                body_first: false,
                label,
            },
            Stmt::WhileStatement(looping) => Statement::Loop {
                init: None,
                test: Some(self.expression(&looping.test)),
                update: None,
                body: Box::new(self.statement(&looping.body, None)),
                body_first: false,
                label,
            },
            Stmt::DoWhileStatement(looping) => Statement::Loop {
                init: None,
                test: Some(self.expression(&looping.test)),
                update: None,
                body: Box::new(self.statement(&looping.body, None)),
                body_first: true,
                label,
            },
            Stmt::TryStatement(attempt) => {
                let handler = attempt.handler.as_deref();
                let parameter = match handler.and_then(|handler| handler.param.as_ref()) {
                    None => None,
                    Some(parameter) => match &parameter.pattern {
                        BindingPattern::BindingIdentifier(name) => {
                            Some(self.name(Binding::Symbol(name.symbol_id())))
                        }
                        _ => {
                            return Statement::Expression(
                                self.unsupported("a destructuring catch"),
                            );
                        }
                    },
                };
                Statement::Try {
                    block: self.body(&attempt.block.body),
                    parameter,
                    handler: handler.map(|handler| self.body(&handler.body.body)),
                    finalizer: attempt.finalizer.as_ref().map(|body| self.body(&body.body)),
                }
            }
            Stmt::ForInStatement(_) | Stmt::ForOfStatement(_) => {
                Statement::Expression(self.unsupported("a for-in or for-of loop"))
            }
            Stmt::WithStatement(_) => Statement::Expression(self.unsupported("a with statement")),
            Stmt::DebuggerStatement(_) => {
                Statement::Expression(self.unsupported("a debugger statement"))
            }
            _ => Statement::Expression(self.unsupported("a declaration")),
        }
    }

    /// Plans a variable declaration, with its initializers if `initialized`.
    fn variables(
        &mut self,
        declaration: &'a VariableDeclaration<'a>,
        initialized: bool,
    ) -> Statement<'a> {
        let mut declarations = Vec::with_capacity(declaration.declarations.len());
        for declarator in &declaration.declarations {
            let BindingPattern::BindingIdentifier(name) = &declarator.id else {
                // The declarators before it run first.
                let stop = self.unsupported("a destructuring declaration");
                return Statement::Block(vec![
                    Statement::Declare(declarations),
                    Statement::Expression(stop),
                ]);
            };
            self.rejected |= name.name == "arguments";
            let init = declarator.init.as_ref().filter(|_| initialized);
            declarations.push(Declaration {
                name: self.name(Binding::Symbol(name.symbol_id())),
                init: init.map(|init| self.expression(init)),
                keeps: declaration.kind == VariableDeclarationKind::Var && init.is_none(),
            });
        }
        Statement::Declare(declarations)
    }

    fn name(&self, binding: Binding<'a>) -> Name<'a> {
        match self.locals.get(&binding) {
            Some(&slot) => Name::Local(slot, binding),
            None => Name::Scoped(binding),
        }
    }

    fn reference(&self, reference: &IdentifierReference<'a>) -> Name<'a> {
        self.name(self.script.binding(reference))
    }

    /// Plans the object and property of `member`, or returns `None` for a `super` property.
    fn member(
        &mut self,
        member: &'a MemberExpression<'a>,
    ) -> Option<(Expression<'a>, Property<'a>)> {
        if matches!(member.object(), Expr::Super(_)) {
            return None;
        }
        let object = self.expression(member.object());
        let property = match member {
            MemberExpression::StaticMemberExpression(member) => {
                Property::Name(member.property.name.as_str())
            }
            MemberExpression::ComputedMemberExpression(member) => {
                Property::Computed(Box::new(self.expression(&member.expression)))
            }
            MemberExpression::PrivateFieldExpression(_) => self.unsupported_key("a private name"),
        };
        Some((object, property))
    }

    fn arguments(&mut self, arguments: &'a [Argument<'a>]) -> Vec<Expression<'a>> {
        arguments
            .iter()
            .map(|argument| match argument.as_expression() {
                Some(argument) => self.expression(argument),
                None => self.unsupported("a spread argument"),
            })
            .collect()
    }

    /// Compiles a `key: value` property. Unsupported property forms stop evaluation before the
    /// value.
    fn object_property(
        &mut self,
        property: &'a ObjectPropertyKind<'a>,
    ) -> (Property<'a>, Expression<'a>) {
        let property = match property {
            ObjectPropertyKind::ObjectProperty(property)
                if property.kind == PropertyKind::Init
                    && !property.method
                    && !property.shorthand =>
            {
                property
            }
            ObjectPropertyKind::ObjectProperty(_) => {
                return self.unsupported_property("an object method or shorthand");
            }
            ObjectPropertyKind::SpreadProperty(_) => {
                return self.unsupported_property("a spread property");
            }
        };
        let key = match &property.key {
            key if property.computed => {
                self.rejected = true;
                let key = key
                    .as_expression()
                    .expect("a computed key is an expression");
                Property::Computed(Box::new(self.expression(key)))
            }
            PropertyKey::StaticIdentifier(name) => Property::Name(name.name.as_str()),
            // Property keys require text; lone-surrogate strings have no text representation.
            PropertyKey::StringLiteral(name) => match name.value.as_str() {
                Some(name) => Property::Name(name),
                None => self.unsupported_key("an object key with a lone surrogate"),
            },
            PropertyKey::NumericLiteral(number) => {
                Property::Computed(Box::new(Expression::Constant(Value::Number(number.value))))
            }
            PropertyKey::BigIntLiteral(_) => self.unsupported_key("a bigint key"),
            _ => self.unsupported_key("a private name"),
        };
        (key, self.expression(&property.value))
    }

    /// Compiles unsupported syntax as a node that stops evaluation. Slot-plan compilation
    /// rejects it.
    fn unsupported(&mut self, reason: &'static str) -> Expression<'a> {
        self.rejected = true;
        Expression::Unsupported(reason)
    }

    fn unsupported_key(&mut self, reason: &'static str) -> Property<'a> {
        Property::Computed(Box::new(self.unsupported(reason)))
    }

    /// A property that stops at its key; its value is never reached.
    fn unsupported_property(&mut self, reason: &'static str) -> (Property<'a>, Expression<'a>) {
        (
            self.unsupported_key(reason),
            Expression::Unsupported(reason),
        )
    }

    /// Plans a name or member target, or returns `None` for other targets.
    fn target(&mut self, target: &'a SimpleAssignmentTarget<'a>) -> Option<Target<'a>> {
        match target {
            SimpleAssignmentTarget::AssignmentTargetIdentifier(name) => {
                Some(Target::Name(self.reference(name)))
            }
            target => {
                let (object, property) = self.member(target.as_member_expression()?)?;
                Some(Target::Member(Box::new(object), property))
            }
        }
    }

    fn expression(&mut self, expression: &'a Expr<'a>) -> Expression<'a> {
        match expression {
            Expr::NumericLiteral(number) => Expression::Constant(Value::Number(number.value)),
            // Literals may hold lone surrogates, which only code units keep.
            Expr::StringLiteral(text) => {
                Expression::Constant(Value::String(text.value.encode_utf16().collect()))
            }
            Expr::BooleanLiteral(value) => Expression::Constant(Value::Bool(value.value)),
            Expr::NullLiteral(_) => Expression::Constant(Value::Null),
            Expr::RegExpLiteral(_) | Expr::BigIntLiteral(_) => {
                self.unsupported("a regular expression or bigint literal")
            }
            Expr::TemplateLiteral(template) if template.expressions.is_empty() => {
                match template.quasis.first().and_then(|quasi| quasi.value.cooked) {
                    Some(cooked) => {
                        Expression::Constant(Value::String(cooked.encode_utf16().collect()))
                    }
                    None => self.unsupported("a raw template"),
                }
            }
            Expr::Identifier(name) => Expression::Name(self.reference(name)),
            Expr::ThisExpression(_) => Expression::This,
            Expr::ParenthesizedExpression(paren) => self.expression(&paren.expression),
            Expr::SequenceExpression(sequence) => Expression::Sequence(
                sequence
                    .expressions
                    .iter()
                    .map(|expression| self.expression(expression))
                    .collect(),
            ),
            Expr::StaticMemberExpression(_)
            | Expr::ComputedMemberExpression(_)
            | Expr::PrivateFieldExpression(_) => {
                let member = expression
                    .as_member_expression()
                    .expect("a member expression");
                match self.member(member) {
                    Some((object, property)) => Expression::Member(Box::new(object), property),
                    None => self.unsupported("a super property expression"),
                }
            }
            Expr::CallExpression(call) => {
                let callee = &call.callee;
                if matches!(callee, Expr::Super(_)) {
                    return self.unsupported("a super or import call");
                }
                self.rejected |= matches!(callee, Expr::ParenthesizedExpression(_));
                // The interpreter calls parenthesized members without a receiver, like
                // `(0, o.f)()`. JavaScript normally preserves the receiver in `(o.f)()`.
                let callee = match (callee, self.expression(callee)) {
                    (Expr::ParenthesizedExpression(_), member @ Expression::Member(..)) => {
                        Expression::Sequence(vec![member])
                    }
                    (_, callee) => callee,
                };
                Expression::Call(Box::new(callee), self.arguments(&call.arguments))
            }
            Expr::ImportExpression(_) => self.unsupported("a super or import call"),
            Expr::NewExpression(construction) => Expression::New(
                Box::new(self.expression(&construction.callee)),
                self.arguments(&construction.arguments),
            ),
            Expr::LogicalExpression(logical) => Expression::Logical {
                operator: logical.operator,
                left: Box::new(self.expression(&logical.left)),
                right: Box::new(self.expression(&logical.right)),
                pure: pure(&logical.right),
            },
            Expr::BinaryExpression(binary) => {
                let left = Box::new(self.expression(&binary.left));
                let right = Box::new(self.expression(&binary.right));
                let operator = binary.operator;
                match semantics::numeric(operator) {
                    Some(operation) => Expression::Arithmetic {
                        operator,
                        operation,
                        left,
                        right,
                    },
                    None => Expression::Binary(operator, left, right),
                }
            }
            Expr::UnaryExpression(unary) if unary.operator == UnaryOperator::Delete => {
                self.unsupported("delete")
            }
            Expr::UnaryExpression(unary) => {
                Expression::Unary(unary.operator, Box::new(self.expression(&unary.argument)))
            }
            Expr::AssignmentExpression(assignment) => {
                let target = assignment.left.as_simple_assignment_target();
                let Some(target) = target.and_then(|target| self.target(target)) else {
                    return self.unsupported("a destructuring assignment");
                };
                if assignment.operator.is_logical() {
                    self.rejected = true;
                    return Expression::LogicalAssign(target);
                }
                let operator = assignment.operator.to_binary_operator();
                let right = Box::new(self.expression(&assignment.right));
                Expression::Assign(target, operator, right)
            }
            Expr::UpdateExpression(update) => match self.target(&update.argument) {
                Some(target) => Expression::Update {
                    target,
                    operator: update.operator,
                    prefix: update.prefix,
                },
                None => self.unsupported("an increment of an expression"),
            },
            Expr::ConditionalExpression(conditional) => Expression::Conditional(
                Box::new(self.expression(&conditional.test)),
                Box::new(self.expression(&conditional.consequent)),
                Box::new(self.expression(&conditional.alternate)),
            ),
            Expr::ArrayExpression(array) => Expression::Array(
                array
                    .elements
                    .iter()
                    .map(|element| match element {
                        ArrayExpressionElement::Elision(_) => None,
                        ArrayExpressionElement::SpreadElement(_) => {
                            Some(self.unsupported("a spread element"))
                        }
                        element => {
                            Some(self.expression(element.as_expression().expect("an element")))
                        }
                    })
                    .collect(),
            ),
            Expr::ObjectExpression(object) => Expression::Object(
                object
                    .properties
                    .iter()
                    .map(|property| self.object_property(property))
                    .collect(),
            ),
            Expr::FunctionExpression(function) => {
                let name = function.id.as_ref().map(|name| name.name.as_str());
                Expression::Function(name, function)
            }
            // Arrows inherit `arguments`, which slot plans keep out of scopes.
            Expr::ArrowFunctionExpression(arrow) => {
                let mut mentions = MentionsArguments::default();
                mentions.visit_arrow_function_expression(arrow);
                self.rejected |= mentions.0;
                Expression::Arrow(arrow)
            }
            expression => self.unsupported(match expression {
                Expr::TemplateLiteral(_) => "a template expression",
                Expr::TaggedTemplateExpression(_) => "a tagged template expression",
                Expr::ChainExpression(_) => "an optional chain expression",
                Expr::AwaitExpression(_) => "an await expression",
                Expr::YieldExpression(_) => "a yield expression",
                Expr::ClassExpression(_) => "a class expression",
                Expr::ImportMeta(_) | Expr::NewTarget(_) => "a meta property expression",
                _ => "an unsupported expression",
            }),
        }
    }
}

/// Checks whether `expr` only produces a value or throws. Rejects calls, writes, and
/// register-dependent branches.
fn pure(expr: &Expr<'_>) -> bool {
    match expr {
        Expr::NumericLiteral(_)
        | Expr::StringLiteral(_)
        | Expr::BooleanLiteral(_)
        | Expr::NullLiteral(_)
        | Expr::BigIntLiteral(_)
        | Expr::RegExpLiteral(_)
        | Expr::Identifier(_)
        | Expr::ThisExpression(_)
        | Expr::FunctionExpression(_)
        | Expr::ArrowFunctionExpression(_) => true,
        Expr::TemplateLiteral(template) => template.expressions.is_empty(),
        Expr::ParenthesizedExpression(paren) => pure(&paren.expression),
        Expr::SequenceExpression(sequence) => sequence.expressions.iter().all(pure),
        Expr::StaticMemberExpression(member) => pure(&member.object),
        Expr::PrivateFieldExpression(member) => pure(&member.object),
        Expr::ComputedMemberExpression(member) => pure(&member.object) && pure(&member.expression),
        Expr::UnaryExpression(unary) => {
            unary.operator != UnaryOperator::Delete && pure(&unary.argument)
        }
        Expr::BinaryExpression(binary) => pure(&binary.left) && pure(&binary.right),
        Expr::LogicalExpression(logical) => pure(&logical.left) && pure(&logical.right),
        _ => false,
    }
}
