//! Compiles JavaScript into plans run by [`super::evaluate`]. Slot plans store function locals
//! in numbered slots and cannot support closures capturing those locals. Scoped plans resolve
//! names through scopes. Unsupported syntax becomes a node that stops evaluation if reached.

#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::ptr;
use std::rc::Rc;

use swc_core::atoms::{Atom, atom};
use swc_core::ecma::ast::{
    ArrowExpr, AssignTarget, BinaryOp, BlockStmtOrExpr, Callee, CatchClause, Class, Decl,
    DoWhileStmt, Expr, ExprOrSpread, FnDecl, Function, Ident, Lit, MemberExpr, MemberProp, Pat,
    Prop, PropName, PropOrSpread, SimpleAssignTarget, Stmt, UnaryOp, UpdateOp, VarDecl,
    VarDeclKind, VarDeclOrExpr, VarDeclarator, WhileStmt,
};
use swc_core::ecma::visit::{Visit, VisitWith};

use super::semantics;
use crate::vm::HashMap;
use crate::vm::value::Value;

/// Caches plans by source-node address. The session's definition keeps those nodes alive longer
/// than the cache.
#[derive(Default)]
pub(crate) struct Plans<'ast> {
    /// `None` marks functions that need a scoped plan.
    pub(super) slot_plans: RefCell<HashMap<usize, Option<Rc<FunctionPlan<'ast>>>>>,
    scoped_plans: RefCell<HashMap<usize, Rc<[Statement<'ast>]>>>,
    /// Forces scoped plans for comparison tests.
    #[cfg(test)]
    pub(super) disabled: Cell<bool>,
}

impl<'ast> Plans<'ast> {
    pub(super) fn slots(&self, function: &'ast Function) -> Option<Rc<FunctionPlan<'ast>>> {
        #[cfg(test)]
        if self.disabled.get() {
            return None;
        }
        let address = ptr::from_ref(function).addr();
        if let Some(plan) = self.slot_plans.borrow().get(&address) {
            return plan.clone();
        }
        let plan = FunctionPlan::compile(function).map(Rc::new);
        self.slot_plans.borrow_mut().insert(address, plan.clone());
        plan
    }

    /// Returns the scoped plan of a function body or arrow, compiling it on first use.
    pub(super) fn scoped<T>(
        &self,
        code: &'ast T,
        compile: impl FnOnce(&'ast T) -> Vec<Statement<'ast>>,
    ) -> Rc<[Statement<'ast>]> {
        let address = ptr::from_ref(code).addr();
        if let Some(plan) = self.scoped_plans.borrow().get(&address) {
            return plan.clone();
        }
        let plan: Rc<[Statement<'ast>]> = compile(code).into();
        self.scoped_plans.borrow_mut().insert(address, plan.clone());
        plan
    }
}

pub(super) struct FunctionPlan<'ast> {
    pub(super) parameters: Vec<usize>,
    /// The slot of `arguments`, if the body reads it.
    pub(super) arguments: Option<usize>,
    pub(super) locals: usize,
    pub(super) body: Vec<Statement<'ast>>,
}

impl<'ast> FunctionPlan<'ast> {
    /// Attempts to compile a slot plan. Returns `None` to request a scoped plan for unsupported
    /// syntax, parenthesized callees, computed object keys, logical assignments, parameter
    /// patterns, variables named `arguments`, or nested functions capturing locals.
    pub(super) fn compile(function: &'ast Function) -> Option<Self> {
        let mut compiler = PlanCompiler::default();
        let mut parameters = Vec::with_capacity(function.params.len());
        for parameter in &function.params {
            let name = &parameter.pat.as_ident()?.sym;
            if name == "arguments" {
                return None;
            }
            parameters.push(compiler.slot(name));
        }
        let body = function.body.as_ref()?;
        body.visit_with(&mut compiler);
        let body = compiler.body(&body.stmts);
        if compiler.rejected {
            return None;
        }
        Some(Self {
            parameters,
            arguments: compiler.locals.get(&atom!("arguments")).copied(),
            locals: compiler.locals.len(),
            body,
        })
    }
}

pub(super) fn scoped(statements: &[Stmt]) -> Vec<Statement<'_>> {
    PlanCompiler::default().statements(statements)
}

/// Scoped execution plan for a function body. Function declarations bind their names at the start
/// of the call.
pub(super) fn scoped_body(statements: &[Stmt]) -> Vec<Statement<'_>> {
    PlanCompiler::default().body(statements)
}

pub(super) fn scoped_expression(expression: &Expr) -> Expression<'_> {
    PlanCompiler::default().expression(expression)
}

pub(super) fn scoped_arrow(arrow: &ArrowExpr) -> Vec<Statement<'_>> {
    match &*arrow.body {
        BlockStmtOrExpr::BlockStmt(body) => scoped_body(&body.stmts),
        BlockStmtOrExpr::Expr(body) => vec![Statement::Return(Some(scoped_expression(body)))],
    }
}

#[derive(Default)]
struct PlanCompiler {
    /// Slots of a slot plan's locals; empty for scoped plans.
    locals: HashMap<Atom, usize>,
    /// Whether compilation needs a scoped plan. Ignored when compiling scoped plans.
    rejected: bool,
}

impl Visit for PlanCompiler {
    fn visit_var_declarator(&mut self, declaration: &VarDeclarator) {
        if let Pat::Ident(name) = &declaration.name {
            self.slot(&name.sym);
        }
        declaration.visit_children_with(self);
    }

    fn visit_ident(&mut self, name: &Ident) {
        if name.sym == "arguments" {
            self.slot(&name.sym);
        }
    }

    /// Treat a nested function declaration as a local binding in the enclosing function.
    fn visit_fn_decl(&mut self, declaration: &FnDecl) {
        self.slot(&declaration.ident.sym);
    }

    /// Treat a `catch` parameter as a function local in the execution plan.
    fn visit_catch_clause(&mut self, clause: &CatchClause) {
        if let Some(Pat::Ident(name)) = &clause.param {
            self.slot(&name.sym);
        }
        clause.visit_children_with(self);
    }

    // Compile a nested function only if it captures no outer locals (see
    // [`PlanCompiler::closes_over_nothing`]). Its own locals remain separate.
    fn visit_function(&mut self, _: &Function) {}
    fn visit_arrow_expr(&mut self, _: &ArrowExpr) {}
    fn visit_class(&mut self, _: &Class) {}
}

/// Every name a nested function mentions, at any depth.
#[derive(Default)]
struct Names(Vec<Atom>);

impl Visit for Names {
    fn visit_ident(&mut self, name: &Ident) {
        self.0.push(name.sym.clone());
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
        label: Option<&'ast Atom>,
    },
    Break(Option<&'ast Atom>),
    Continue(Option<&'ast Atom>),
    Label(&'ast Atom, Box<Statement<'ast>>),
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
        operator: BinaryOp,
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
    Binary(BinaryOp, Box<Expression<'ast>>, Box<Expression<'ast>>),
    /// An arithmetic or bitwise operator, with its operation on numbers (see
    /// [`semantics::numeric`]).
    Arithmetic {
        operator: BinaryOp,
        operation: fn(f64, f64) -> f64,
        left: Box<Expression<'ast>>,
        right: Box<Expression<'ast>>,
    },
    Unary(UnaryOp, Box<Expression<'ast>>),
    Assign(Target<'ast>, Option<BinaryOp>, Box<Expression<'ast>>),
    Update {
        target: Target<'ast>,
        operator: UpdateOp,
        prefix: bool,
    },
    Conditional(
        Box<Expression<'ast>>,
        Box<Expression<'ast>>,
        Box<Expression<'ast>>,
    ),
    Array(Vec<Option<Expression<'ast>>>),
    Object(Vec<(Property<'ast>, Expression<'ast>)>),
    Function(Option<&'ast Atom>, &'ast Function),
    Arrow(&'ast ArrowExpr),
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

/// A name a plan reads or writes: a local, by its slot, or a name resolved through scopes.
#[derive(Clone, Copy)]
pub(super) enum Name<'ast> {
    Local(usize, &'ast Atom),
    Global(&'ast Atom),
}

impl<'ast> Name<'ast> {
    pub(super) fn atom(self) -> &'ast Atom {
        match self {
            Self::Local(_, name) | Self::Global(name) => name,
        }
    }
}

impl PlanCompiler {
    fn slot(&mut self, name: &Atom) -> usize {
        let next = self.locals.len();
        *self.locals.entry(name.clone()).or_insert(next)
    }

    /// Checks that a nested function captures no locals from the function being compiled.
    /// Slot plans do not put these locals in the scope chain. Ordinary functions shadow
    /// `arguments`; arrows inherit it and must not read it.
    fn closes_over_nothing(&self, nested: &impl VisitWith<Names>, arrow: bool) -> bool {
        let mut names = Names::default();
        nested.visit_with(&mut names);
        names
            .0
            .iter()
            .all(|name| !self.locals.contains_key(name) && !(arrow && name == "arguments"))
    }

    /// Plans a function body, binding function declarations before executing statements.
    /// Declarations beside the VM class are planned as statements and resolved as globals.
    fn body<'a>(&mut self, statements: &'a [Stmt]) -> Vec<Statement<'a>> {
        let mut plan = Vec::with_capacity(statements.len());
        for statement in statements {
            if let Stmt::Decl(Decl::Fn(declaration)) = statement {
                let name = &declaration.ident.sym;
                self.rejected |= !self.closes_over_nothing(&*declaration.function, false);
                plan.push(Statement::Declare(vec![Declaration {
                    name: self.name(name),
                    init: Some(Expression::Function(Some(name), &declaration.function)),
                    keeps: false,
                }]));
            }
        }
        plan.extend(self.statements(statements));
        plan
    }

    fn statements<'a>(&mut self, statements: &'a [Stmt]) -> Vec<Statement<'a>> {
        statements
            .iter()
            .map(|statement| self.statement(statement, None))
            .collect()
    }

    fn statement<'a>(&mut self, statement: &'a Stmt, label: Option<&'a Atom>) -> Statement<'a> {
        match statement {
            Stmt::Expr(expression) => Statement::Expression(self.expression(&expression.expr)),
            Stmt::Decl(Decl::Var(declaration)) => self.variables(declaration),
            // Declarations do not bind their names; the names resolve as globals.
            Stmt::Decl(Decl::Fn(_) | Decl::Class(_)) | Stmt::Empty(_) => Statement::Empty,
            Stmt::Decl(_) => Statement::Expression(self.unsupported("a declaration")),
            // A block shares its function's scope, so its function declarations bind at its start.
            Stmt::Block(block) => Statement::Block(self.body(&block.stmts)),
            Stmt::If(branch) => Statement::If(
                self.expression(&branch.test),
                Box::new(self.statement(&branch.cons, None)),
                branch
                    .alt
                    .as_ref()
                    .map(|alt| Box::new(self.statement(alt, None))),
            ),
            Stmt::Return(returned) => {
                Statement::Return(returned.arg.as_ref().map(|arg| self.expression(arg)))
            }
            Stmt::Throw(thrown) => Statement::Throw(self.expression(&thrown.arg)),
            Stmt::Switch(switch) => {
                let discriminant = self.expression(&switch.discriminant);
                let cases = switch.cases.iter().map(|case| Case {
                    test: case.test.as_ref().map(|test| self.expression(test)),
                    body: self.statements(&case.cons),
                });
                Statement::Switch(discriminant, cases.collect())
            }
            Stmt::Break(branch) => Statement::Break(branch.label.as_ref().map(|label| &label.sym)),
            Stmt::Continue(branch) => {
                Statement::Continue(branch.label.as_ref().map(|label| &label.sym))
            }
            Stmt::Labeled(labeled) => Statement::Label(
                &labeled.label.sym,
                Box::new(self.statement(&labeled.body, Some(&labeled.label.sym))),
            ),
            Stmt::For(looping) => Statement::Loop {
                init: looping.init.as_ref().map(|init| {
                    Box::new(match init {
                        VarDeclOrExpr::VarDecl(declaration) => self.variables(declaration),
                        VarDeclOrExpr::Expr(init) => Statement::Expression(self.expression(init)),
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
            Stmt::While(WhileStmt { test, body, .. })
            | Stmt::DoWhile(DoWhileStmt { test, body, .. }) => Statement::Loop {
                init: None,
                test: Some(self.expression(test)),
                update: None,
                body: Box::new(self.statement(body, None)),
                body_first: matches!(statement, Stmt::DoWhile(_)),
                label,
            },
            Stmt::Try(attempt) => {
                let handler = attempt.handler.as_ref();
                let parameter = match handler.and_then(|handler| handler.param.as_ref()) {
                    None => None,
                    Some(Pat::Ident(name)) => Some(self.name(&name.sym)),
                    Some(_) => {
                        return Statement::Expression(self.unsupported("a destructuring catch"));
                    }
                };
                Statement::Try {
                    block: self.statements(&attempt.block.stmts),
                    parameter,
                    handler: handler.map(|handler| self.statements(&handler.body.stmts)),
                    finalizer: attempt
                        .finalizer
                        .as_ref()
                        .map(|body| self.statements(&body.stmts)),
                }
            }
            Stmt::ForIn(_) | Stmt::ForOf(_) => {
                Statement::Expression(self.unsupported("a for-in or for-of loop"))
            }
            Stmt::With(_) => Statement::Expression(self.unsupported("a with statement")),
            Stmt::Debugger(_) => Statement::Expression(self.unsupported("a debugger statement")),
        }
    }

    fn variables<'a>(&mut self, declaration: &'a VarDecl) -> Statement<'a> {
        let mut declarations = Vec::with_capacity(declaration.decls.len());
        for declarator in &declaration.decls {
            let Pat::Ident(name) = &declarator.name else {
                // The declarators before it run first.
                let stop = self.unsupported("a destructuring declaration");
                return Statement::Block(vec![
                    Statement::Declare(declarations),
                    Statement::Expression(stop),
                ]);
            };
            self.rejected |= name.sym == "arguments";
            declarations.push(Declaration {
                name: self.name(&name.sym),
                init: declarator.init.as_ref().map(|init| self.expression(init)),
                keeps: declaration.kind == VarDeclKind::Var && declarator.init.is_none(),
            });
        }
        Statement::Declare(declarations)
    }

    fn property<'a>(&mut self, property: &'a MemberProp) -> Property<'a> {
        match property {
            MemberProp::Ident(name) => Property::Name(&name.sym),
            MemberProp::Computed(key) => Property::Computed(Box::new(self.expression(&key.expr))),
            MemberProp::PrivateName(_) => self.unsupported_key("a private name"),
        }
    }

    fn name<'a>(&self, name: &'a Atom) -> Name<'a> {
        match self.locals.get(name) {
            Some(&slot) => Name::Local(slot, name),
            None => Name::Global(name),
        }
    }

    fn member_target<'a>(&mut self, member: &'a MemberExpr) -> Target<'a> {
        Target::Member(
            Box::new(self.expression(&member.obj)),
            self.property(&member.prop),
        )
    }

    fn arguments<'a>(&mut self, arguments: &'a [ExprOrSpread]) -> Vec<Expression<'a>> {
        arguments
            .iter()
            .map(|argument| match argument.spread {
                None => self.expression(&argument.expr),
                Some(_) => self.unsupported("a spread argument"),
            })
            .collect()
    }

    /// Compiles a `key: value` property. Unsupported property forms stop evaluation before the
    /// value.
    fn object_property<'a>(
        &mut self,
        property: &'a PropOrSpread,
    ) -> (Property<'a>, Expression<'a>) {
        let property = match property {
            PropOrSpread::Prop(property) => match &**property {
                Prop::KeyValue(property) => property,
                _ => return self.unsupported_property("an object method or shorthand"),
            },
            PropOrSpread::Spread(_) => return self.unsupported_property("a spread property"),
        };
        let key = match &property.key {
            PropName::Ident(name) => Property::Name(&name.sym),
            // Property keys require text; lone-surrogate strings have no text representation.
            PropName::Str(name) => match name.value.as_str() {
                Some(name) => Property::Name(name),
                None => self.unsupported_key("an object key with a lone surrogate"),
            },
            PropName::Num(number) => {
                Property::Computed(Box::new(Expression::Constant(Value::Number(number.value))))
            }
            PropName::Computed(key) => {
                self.rejected = true;
                Property::Computed(Box::new(self.expression(&key.expr)))
            }
            PropName::BigInt(_) => self.unsupported_key("a bigint key"),
        };
        (key, self.expression(&property.value))
    }

    /// Compiles unsupported syntax as a node that stops evaluation. Slot-plan compilation
    /// rejects it.
    fn unsupported<'a>(&mut self, reason: &'static str) -> Expression<'a> {
        self.rejected = true;
        Expression::Unsupported(reason)
    }

    fn unsupported_key<'a>(&mut self, reason: &'static str) -> Property<'a> {
        Property::Computed(Box::new(self.unsupported(reason)))
    }

    /// A property that stops at its key; its value is never reached.
    fn unsupported_property<'a>(&mut self, reason: &'static str) -> (Property<'a>, Expression<'a>) {
        (
            self.unsupported_key(reason),
            Expression::Unsupported(reason),
        )
    }

    fn expression<'a>(&mut self, expression: &'a Expr) -> Expression<'a> {
        match expression {
            Expr::Lit(literal) => Expression::Constant(match literal {
                Lit::Num(number) => Value::Number(number.value),
                // Literals may hold lone surrogates, which only code units keep.
                Lit::Str(text) => Value::String(text.value.to_ill_formed_utf16().collect()),
                Lit::Bool(value) => Value::Bool(value.value),
                Lit::Null(_) => Value::Null,
                _ => return self.unsupported("a regular expression or bigint literal"),
            }),
            Expr::Tpl(template) if template.exprs.is_empty() => {
                match template
                    .quasis
                    .first()
                    .and_then(|quasi| quasi.cooked.as_ref())
                {
                    Some(cooked) => {
                        Expression::Constant(Value::String(cooked.to_ill_formed_utf16().collect()))
                    }
                    None => self.unsupported("a raw template"),
                }
            }
            Expr::Ident(name) => Expression::Name(self.name(&name.sym)),
            Expr::This(_) => Expression::This,
            Expr::Paren(paren) => self.expression(&paren.expr),
            Expr::Seq(sequence) => Expression::Sequence(
                sequence
                    .exprs
                    .iter()
                    .map(|expression| self.expression(expression))
                    .collect(),
            ),
            Expr::Member(member) => Expression::Member(
                Box::new(self.expression(&member.obj)),
                self.property(&member.prop),
            ),
            Expr::Call(call) => {
                let Callee::Expr(callee) = &call.callee else {
                    return self.unsupported("a super or import call");
                };
                self.rejected |= matches!(&**callee, Expr::Paren(_));
                // The interpreter calls parenthesized members without a receiver, like
                // `(0, o.f)()`. JavaScript normally preserves the receiver in `(o.f)()`.
                let callee = match (&**callee, self.expression(callee)) {
                    (Expr::Paren(_), member @ Expression::Member(..)) => {
                        Expression::Sequence(vec![member])
                    }
                    (_, callee) => callee,
                };
                Expression::Call(Box::new(callee), self.arguments(&call.args))
            }
            Expr::New(construction) => Expression::New(
                Box::new(self.expression(&construction.callee)),
                match &construction.args {
                    Some(arguments) => self.arguments(arguments),
                    None => Vec::new(),
                },
            ),
            Expr::Bin(binary) => {
                let left = Box::new(self.expression(&binary.left));
                let right = Box::new(self.expression(&binary.right));
                match binary.op {
                    operator @ (BinaryOp::LogicalAnd
                    | BinaryOp::LogicalOr
                    | BinaryOp::NullishCoalescing) => Expression::Logical {
                        operator,
                        left,
                        right,
                        pure: pure(&binary.right),
                    },
                    operator => match semantics::numeric(operator) {
                        Some(operation) => Expression::Arithmetic {
                            operator,
                            operation,
                            left,
                            right,
                        },
                        None => Expression::Binary(operator, left, right),
                    },
                }
            }
            Expr::Unary(unary) if unary.op == UnaryOp::Delete => self.unsupported("delete"),
            Expr::Unary(unary) => {
                Expression::Unary(unary.op, Box::new(self.expression(&unary.arg)))
            }
            Expr::Assign(assign) => {
                let target = match &assign.left {
                    AssignTarget::Simple(SimpleAssignTarget::Ident(name)) => {
                        Target::Name(self.name(&name.id.sym))
                    }
                    AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
                        self.member_target(member)
                    }
                    _ => return self.unsupported("a destructuring assignment"),
                };
                let operator = assign.op.to_update();
                self.rejected |= matches!(
                    operator,
                    Some(BinaryOp::LogicalAnd | BinaryOp::LogicalOr | BinaryOp::NullishCoalescing)
                );
                let right = Box::new(self.expression(&assign.right));
                Expression::Assign(target, operator, right)
            }
            Expr::Update(update) => Expression::Update {
                target: match &*update.arg {
                    Expr::Ident(name) => Target::Name(self.name(&name.sym)),
                    Expr::Member(member) => self.member_target(member),
                    _ => return self.unsupported("an increment of an expression"),
                },
                operator: update.op,
                prefix: update.prefix,
            },
            Expr::Cond(conditional) => Expression::Conditional(
                Box::new(self.expression(&conditional.test)),
                Box::new(self.expression(&conditional.cons)),
                Box::new(self.expression(&conditional.alt)),
            ),
            Expr::Array(array) => Expression::Array(
                array
                    .elems
                    .iter()
                    .map(|element| match element {
                        Some(element) if element.spread.is_none() => {
                            Some(self.expression(&element.expr))
                        }
                        Some(_) => Some(self.unsupported("a spread element")),
                        None => None,
                    })
                    .collect(),
            ),
            Expr::Object(object) => Expression::Object(
                object
                    .props
                    .iter()
                    .map(|property| self.object_property(property))
                    .collect(),
            ),
            Expr::Fn(function) => {
                self.rejected |= !self.closes_over_nothing(&function.function, false);
                let name = function.ident.as_ref().map(|ident| &ident.sym);
                Expression::Function(name, &function.function)
            }
            Expr::Arrow(arrow) => {
                self.rejected |= !self.closes_over_nothing(arrow, true);
                Expression::Arrow(arrow)
            }
            expression => self.unsupported(match expression {
                Expr::Tpl(_) => "a template expression",
                Expr::TaggedTpl(_) => "a tagged template expression",
                Expr::OptChain(_) => "an optional chain expression",
                Expr::Await(_) => "an await expression",
                Expr::Yield(_) => "a yield expression",
                Expr::Class(_) => "a class expression",
                Expr::MetaProp(_) => "a meta property expression",
                Expr::SuperProp(_) => "a super property expression",
                _ => "an unsupported expression",
            }),
        }
    }
}

/// Checks whether `expr` only produces a value or throws. Rejects calls, writes, and
/// register-dependent branches.
fn pure(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(_) | Expr::Ident(_) | Expr::This(_) | Expr::Fn(_) | Expr::Arrow(_) => true,
        Expr::Tpl(template) => template.exprs.is_empty(),
        Expr::Paren(paren) => pure(&paren.expr),
        Expr::Seq(sequence) => sequence.exprs.iter().all(|expr| pure(expr)),
        Expr::Member(member) => {
            pure(&member.obj)
                && match &member.prop {
                    MemberProp::Computed(computed) => pure(&computed.expr),
                    _ => true,
                }
        }
        Expr::Unary(unary) => unary.op != UnaryOp::Delete && pure(&unary.arg),
        Expr::Bin(binary) => pure(&binary.left) && pure(&binary.right),
        _ => false,
    }
}
