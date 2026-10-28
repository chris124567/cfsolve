//! Inlines literal and single-return function properties of helper objects:
//!
//! ```js
//! h = { add: function (a, b) { return a + b; }, key: "name" };
//! h.add(x, 1); h.key;  // becomes (x) + (1); "name"
//! ```
//!
//! Requires each property to be defined once on an object that does not escape (see
//! [`Properties::is_stable`]), and calls that preserve argument evaluation and order (see
//! [`can_inline`]). Hoisted function bodies use only objects known wherever they can be called
//! (see [`hoisting`]).

use std::iter;
use std::rc::Rc;

use swc_core::atoms::Atom;
use swc_core::common::SyntaxContext;
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, BlockStmt, CallExpr, Callee, Decl, Expr, ExprOrSpread,
    FnExpr, ForStmt, Function, Id, Ident, Lit, MemberExpr, MemberProp, MetaPropExpr, Number,
    ObjectLit, Program, ReturnStmt, SeqExpr, SimpleAssignTarget, Stmt, Super, ThisExpr, UnaryOp,
    VarDeclOrExpr,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::HashMap;
use super::analysis::effects::{self, Effects};
use super::analysis::hoisting::{self, HoistFacts, Hoisted, Hoisting, List};
use super::analysis::{self, Analysis, Bindings, Globals, Properties, names};
use crate::js::ast;

/// Tracks helper objects and aliases only while their bindings have exactly one write, leaving
/// reassigned bindings unchanged.
pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let globals = analysis.globals;
    let (bindings, properties) = analysis.properties(program);
    let mut inline = InlineHelpers {
        bindings,
        properties,
        globals,
        hoisting: Hoisting::default(),
        lists: 0,
        defined_in: HashMap::default(),
        changed: false,
    };
    program.visit_mut_with(&mut inline);
    inline.changed
}

/// Properties of one helper object that can replace property reads.
#[derive(Clone, Default)]
struct ObjectProperties {
    functions: HashMap<Atom, FnExpr>,
    literals: HashMap<Atom, Expr>,
}

impl ObjectProperties {
    /// Every inlinable property of a helper object literal.
    fn collect(object: &ObjectLit) -> Self {
        let mut properties = Self::default();
        for property in ast::key_values(object) {
            if let Some(name) = analysis::prop_key(&property.key) {
                properties.insert(name, &property.value);
            }
        }
        properties
    }

    /// Records substitutable properties. Leaves unsupported properties as object reads.
    fn insert(&mut self, name: Atom, value: &Expr) {
        match value {
            Expr::Fn(function) => {
                self.functions.insert(name, function.clone());
            }
            // A regular expression carries state and identity, so it cannot
            // stand in for every read.
            Expr::Lit(literal) if !matches!(literal, Lit::Regex(_)) => {
                self.literals.insert(name, Expr::Lit(literal.clone()));
            }
            _ => {}
        }
    }
}

/// The helper objects and functions known at one point, by binding.
#[derive(Clone, Default)]
struct Helpers {
    objects: HashMap<Id, Rc<ObjectProperties>>,
    /// Functions assigned to a binding written once.
    functions: HashMap<Id, Rc<FnExpr>>,
}

/// At a control-flow join, keeps the objects and properties known on both paths.
impl HoistFacts for Helpers {
    fn meet(&mut self, other: &Self) {
        self.objects.retain(|id, properties| {
            let Some(theirs) = other.objects.get(id) else {
                return false;
            };
            if !Rc::ptr_eq(properties, theirs) {
                let properties = Rc::make_mut(properties);
                properties
                    .functions
                    .retain(|name, _| theirs.functions.contains_key(name));
                properties
                    .literals
                    .retain(|name, _| theirs.literals.contains_key(name));
            }
            true
        });
        self.functions.meet(&other.functions);
    }
}

struct InlineHelpers<'analysis> {
    bindings: &'analysis Bindings,
    properties: &'analysis Properties,
    globals: Globals,
    /// Tracks known helpers. An alias gets the properties known when its assignment runs.
    hoisting: Hoisting<Helpers>,
    /// Counter assigning an identity to each entered statement list or sequence.
    lists: usize,
    /// The statement list or sequence whose top level assigns each object binding.
    defined_in: HashMap<Id, usize>,
    changed: bool,
}

impl InlineHelpers<'_> {
    /// Visits a statement in `list`, recording expressions that always execute before visiting
    /// its children. These include expression statements, return and throw values, loop
    /// initializers, branch tests, switch discriminants, and `var` initializers.
    fn statement(&mut self, statement: &mut Stmt, list: usize) {
        match statement {
            Stmt::Expr(statement) => self.top_level(&mut statement.expr, list),
            Stmt::Return(ReturnStmt {
                arg: Some(argument),
                ..
            }) => self.top_level(argument, list),
            Stmt::Throw(statement) => self.top_level(&mut statement.arg, list),
            Stmt::If(statement) => {
                self.top_level(&mut statement.test, list);
                statement.cons.visit_mut_with(self);
                statement.alt.visit_mut_with(self);
            }
            Stmt::Switch(statement) => {
                self.top_level(&mut statement.discriminant, list);
                statement.cases.visit_mut_with(self);
            }
            Stmt::Decl(Decl::Var(declaration)) => {
                for declarator in &mut declaration.decls {
                    declarator.name.visit_mut_with(self);
                    if let Some(init) = &mut declarator.init {
                        self.top_level(init, list);
                    }
                }
            }
            Stmt::For(ForStmt {
                init: Some(VarDeclOrExpr::Expr(init)),
                test,
                update,
                body,
                ..
            }) => {
                self.top_level(init, list);
                test.visit_mut_with(self);
                update.visit_mut_with(self);
                body.visit_mut_with(self);
            }
            statement => statement.visit_mut_with(self),
        }
    }

    /// Visits an expression guaranteed to run with its statement or sequence, preserving
    /// sequence order.
    fn top_level(&mut self, expression: &mut Expr, list: usize) {
        if let Expr::Seq(sequence) = expression {
            for operand in &mut sequence.exprs {
                self.top_level(operand, list);
            }
            return;
        }
        expression.visit_mut_with(self);
        let Expr::Assign(assignment) = expression else {
            return;
        };
        if let Some(target) = assignment.left.as_ident()
            && self.hoisting.facts.objects.contains_key(&target.to_id())
        {
            self.defined_in.insert(target.to_id(), list);
        } else if assignment.op == AssignOp::Assign
            && let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left
            && let Some(identifier) = member.obj.as_ident()
            && let Some(property) = analysis::member_key(&member.prop)
            && self.defined_in.get(&identifier.to_id()) == Some(&list)
            && let Some(object) = self.hoisting.facts.objects.get_mut(&identifier.to_id())
        {
            // Only property assignments beside the object's definition safely extend it.
            // Elsewhere, a read might run before the assignment.
            Rc::make_mut(object).insert(property, &assignment.right);
        }
    }

    /// Resolves a stable `helper.name` read to its helper object and property.
    fn stable(&self, member: &MemberExpr) -> Option<(&ObjectProperties, Atom)> {
        let identifier = member.obj.as_ident()?.to_id();
        let property = analysis::member_key(&member.prop)?;
        if !self.properties.is_stable(&identifier, &property) {
            return None;
        }
        Some((self.hoisting.facts.objects.get(&identifier)?, property))
    }
}

impl VisitMut for InlineHelpers<'_> {
    fn visit_mut_assign_expr(&mut self, assignment: &mut AssignExpr) {
        assignment.visit_mut_children_with(self);

        if assignment.op == AssignOp::Assign
            && let Some(target) = assignment.left.as_ident()
            && self.bindings.is_written_once(&target.to_id())
        {
            let target = target.to_id();
            let method = assignment
                .right
                .as_member()
                .and_then(|member| self.stable(member))
                .and_then(|(object, property)| object.functions.get(&property))
                .cloned();
            // Track object definitions, helper functions, and copies of objects and helper methods
            // by binding.
            let helpers = &mut self.hoisting.facts;
            if let Some(method) = method {
                helpers.functions.insert(target, Rc::new(method));
            } else if let Some(object) = assignment.right.as_object() {
                let properties = Rc::new(ObjectProperties::collect(object));
                helpers.objects.insert(target, properties);
            } else if let Some(function) = assignment.right.as_fn_expr() {
                helpers.functions.insert(target, Rc::new(function.clone()));
            } else if let Some(alias) = assignment.right.as_ident()
                && let Some(object) = helpers.objects.get(&alias.to_id()).cloned()
            {
                helpers.objects.insert(target, object);
            }
        }
    }

    /// Visit function declarations last with objects known at every possible call.
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        self.lists += 1;
        let list = self.lists;
        // Function declarations are available from the start of a function body. Top-level
        // declarations can be replaced by other scripts.
        if self.hoisting.list == List::FunctionBody {
            for statement in statements.iter() {
                if let Stmt::Decl(Decl::Fn(declaration)) = statement
                    && self.bindings.is_written_once(&declaration.ident.to_id())
                {
                    let function = Rc::new(FnExpr::from(declaration.function.clone()));
                    self.hoisting
                        .facts
                        .functions
                        .insert(declaration.ident.to_id(), function);
                }
            }
        }
        hoisting::visit_mut_stmts(self, statements, |inline, statement| {
            inline.statement(statement, list);
        });
    }

    fn visit_mut_function(&mut self, function: &mut Function) {
        hoisting::visit_mut_function(self, function);
    }

    fn visit_mut_block_stmt(&mut self, block: &mut BlockStmt) {
        hoisting::visit_mut_block(self, block);
    }

    fn visit_mut_ident(&mut self, identifier: &mut Ident) {
        hoisting::reference(self, identifier);
    }

    /// The operands of a sequence run together and in order, like the statements of a list.
    fn visit_mut_seq_expr(&mut self, sequence: &mut SeqExpr) {
        self.lists += 1;
        let list = self.lists;
        for operand in &mut sequence.exprs {
            self.top_level(operand, list);
        }
    }

    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);

        // `helper.name(...)`, with the expression the function returns.
        if let Expr::Call(call) = expression
            && let Callee::Expr(callee) = &call.callee
            && let Expr::Member(member) = &**callee
            && let Some((object, property)) = self.stable(member)
            && let Some(function) = object.functions.get(&property)
            && let Some(result) = ast::returned(&function.function)
            && can_inline(function, result, &call.args, self.globals)
            && let Some(replacement) = substitute(function, result, &call.args)
        {
            *expression = replacement;
            self.changed = true;
        }

        // Inline a helper call only when its result uses parameters, sibling bindings, or
        // globals visible to every caller.
        if let Some((callee, args)) = ast::direct_call(expression)
            && let Some(function) = self.hoisting.facts.functions.get(&callee.to_id())
            && let Some(result) = ast::returned(&function.function)
            && names_only(result, &function.function, callee.ctxt, self.globals)
            && can_inline(function, result, args, self.globals)
            && let Some(replacement) = substitute(function, result, args)
        {
            *expression = replacement;
            self.changed = true;
        }

        // A `helper.name` read of a literal.
        if let Some(member) = expression.as_member()
            && let Some((object, property)) = self.stable(member)
            && let Some(value) = object.literals.get(&property)
        {
            *expression = value.clone();
            self.changed = true;
        }
    }
}

/// Checks that every name in `result` is a parameter of `function`, a binding in `scope`, or a
/// global.
fn names_only(result: &Expr, function: &Function, scope: SyntaxContext, globals: Globals) -> bool {
    struct Names {
        parameters: Vec<Id>,
        scopes: [SyntaxContext; 2],
        all_allowed: bool,
    }

    impl Visit for Names {
        fn visit_ident(&mut self, identifier: &Ident) {
            self.all_allowed &= self.scopes.contains(&identifier.ctxt)
                || self.parameters.contains(&identifier.to_id());
        }
    }

    let mut names = Names {
        parameters: function
            .params
            .iter()
            .filter_map(|parameter| Some(parameter.pat.as_ident()?.to_id()))
            .collect(),
        scopes: [scope, globals.unresolved],
        all_allowed: true,
    };
    result.visit_with(&mut names);
    names.all_allowed
}

impl Hoisted for InlineHelpers<'_> {
    type Facts = Helpers;

    fn hoisting(&mut self) -> &mut Hoisting<Helpers> {
        &mut self.hoisting
    }
}

/// Checks whether substituting `args` into `result` preserves evaluations and their order.
#[must_use]
fn can_inline(function: &FnExpr, result: &Expr, args: &[ExprOrSpread], globals: Globals) -> bool {
    function.function.params.len() >= args.len()
        && trailing_parameters_unused(function, result, args.len())
        && args.iter().all(|argument| argument.spread.is_none())
        && !function.function.is_async
        && !function.function.is_generator
        && !uses_own_context(result)
        && (evaluates_arguments_safely(function, result, args, globals)
            || args
                .iter()
                .all(|argument| !effects::may_have_effects(&argument.expr, globals)))
}

/// Parameters without arguments disappear when the call is inlined. Allow this only for unused
/// plain identifiers. Destructuring may evaluate defaults, and referenced parameters would have
/// no binding after substitution.
fn trailing_parameters_unused(function: &FnExpr, result: &Expr, argument_count: usize) -> bool {
    let params = &function.function.params;
    let trailing = names::parameter_ids(&params[argument_count.min(params.len())..]);
    trailing.is_some_and(|trailing| !names::mentions(result, &trailing))
}

/// Checks for `this`, `arguments`, `new.target`, or `super` outside nested functions, which
/// inlining would resolve in the caller instead.
fn uses_own_context(result: &Expr) -> bool {
    struct Context(bool);

    impl Visit for Context {
        fn visit_this_expr(&mut self, _: &ThisExpr) {
            self.0 = true;
        }

        fn visit_super(&mut self, _: &Super) {
            self.0 = true;
        }

        fn visit_meta_prop_expr(&mut self, _: &MetaPropExpr) {
            self.0 = true;
        }

        fn visit_function(&mut self, _: &Function) {}
    }

    let mut context = Context(false);
    result.visit_with(&mut context);
    context.0 || names::uses_arguments(result)
}

/// Requires each supplied parameter to appear exactly once in an operand that always runs.
/// Reordering operands must preserve behavior. Coercions must run after operand evaluation, so
/// nested arithmetic and short-circuit expressions need stricter checks.
fn evaluates_arguments_safely(
    function: &FnExpr,
    result: &Expr,
    args: &[ExprOrSpread],
    globals: Globals,
) -> bool {
    let Some(operands) = eager_operands(result).filter(|operands| operands.len() == args.len())
    else {
        return false;
    };
    // The supplied parameters not yet read by an operand.
    let mut unread: Vec<Option<Id>> = function
        .function
        .params
        .iter()
        .take(args.len())
        .map(|parameter| Some(parameter.pat.as_ident()?.to_id()))
        .collect();
    // The parameter each operand reads, in evaluation order.
    let mut order = Vec::with_capacity(args.len());
    for operand in operands {
        let operand = operand.as_ident().map(Ident::to_id);
        let Some(index) = unread
            .iter()
            .position(|parameter| parameter.is_some() && *parameter == operand)
        else {
            return false;
        };
        unread[index] = None;
        order.push(index);
    }
    for (position, &first) in order.iter().enumerate() {
        for &second in &order[position + 1..] {
            if first > second && !commutes(&args[first].expr, &args[second].expr, globals) {
                return false;
            }
        }
    }
    true
}

/// Two arguments may swap if both have no effects, or one has no effects and reads no binding
/// the other writes. Calls and other opaque operations may write through closures, so binding
/// reads cannot move across them.
fn commutes(first: &Expr, second: &Expr, globals: Globals) -> bool {
    let (pure, impure) = match (
        effects::may_have_effects(first, globals),
        effects::may_have_effects(second, globals),
    ) {
        (false, false) => return true,
        (false, true) => (first, second),
        (true, false) => (second, first),
        (true, true) => return false,
    };
    let pure = Effects::collect(pure);
    pure.reads.is_empty() || {
        let impure = Effects::collect(impure);
        !impure.opaque && impure.writes.is_disjoint(&pure.reads)
    }
}

/// Lists operands in evaluation order. Looks through outer unary operators such as `!` in `!(b
/// !== a)`, which run after their operands. Excludes `delete`, which does not read its operand.
fn eager_operands(result: &Expr) -> Option<Vec<&Expr>> {
    match result {
        Expr::Paren(paren) => eager_operands(&paren.expr),
        Expr::Unary(unary) if unary.op != UnaryOp::Delete => eager_operands(&unary.arg),
        Expr::Bin(binary) if !binary.op.may_short_circuit() => {
            Some(vec![&binary.left, &binary.right])
        }
        // The property key is converted after both operands are evaluated.
        Expr::Member(member) => match &member.prop {
            MemberProp::Ident(_) => Some(vec![&member.obj]),
            MemberProp::Computed(key) => Some(vec![&member.obj, &key.expr]),
            MemberProp::PrivateName(_) => None,
        },
        Expr::Call(call)
            if let Callee::Expr(callee) = &call.callee
                && call.args.iter().all(|argument| argument.spread.is_none()) =>
        {
            Some(
                iter::once(&**callee)
                    .chain(call.args.iter().map(|argument| &*argument.expr))
                    .collect(),
            )
        }
        _ => None,
    }
}

/// Substitutes arguments for `function` parameters in `result`. Returns `None` unless
/// parameters are distinct plain identifiers.
#[must_use]
fn substitute(function: &FnExpr, result: &Expr, args: &[ExprOrSpread]) -> Option<Expr> {
    let mut parameters = HashMap::default();
    let bound = function.function.params.iter().zip(args);
    for (parameter, argument) in bound {
        let parameter = parameter.pat.as_ident()?;
        if parameters
            .insert(parameter.to_id(), &*argument.expr)
            .is_some()
        {
            return None;
        }
    }
    Some(replace_parameters(result, parameters))
}

/// Substitutes parenthesized arguments for parameter references and parenthesizes the result.
/// Preserves calls without a receiver; see [`needs_detaching`].
#[must_use]
pub(super) fn replace_parameters(expression: &Expr, parameters: HashMap<Id, &Expr>) -> Expr {
    let mut replacement = expression.clone();
    replacement.visit_mut_with(&mut ParameterReplacer { parameters });
    ast::parenthesized(Box::new(replacement))
}

struct ParameterReplacer<'arguments> {
    parameters: HashMap<Id, &'arguments Expr>,
}

impl VisitMut for ParameterReplacer<'_> {
    fn visit_mut_call_expr(&mut self, call: &mut CallExpr) {
        use swc_core::common::Spanned;

        let parameter_callee = matches!(&call.callee, Callee::Expr(callee)
            if callee.as_ident().is_some_and(|id| self.parameters.contains_key(&id.to_id())));
        call.visit_mut_children_with(self);
        if parameter_callee
            && let Callee::Expr(callee) = &mut call.callee
            && needs_detaching(callee.unwrap_parens())
        {
            // The wrapper calls a parameter as a value. Substituting `obj.method`
            // must not bind `obj` as `this`, or turn a passed `eval` into direct eval.
            **callee = Expr::Seq(SeqExpr {
                span: callee.span(),
                exprs: vec![
                    Box::new(Expr::Lit(Lit::Num(Number {
                        span: callee.span(),
                        value: 0.0,
                        raw: None,
                    }))),
                    callee.clone(),
                ],
            });
        }
    }

    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);

        if let Expr::Ident(identifier) = expression
            && let Some(value) = self.parameters.get(&identifier.to_id())
        {
            *expression = ast::parenthesized(Box::new((*value).clone()));
        }
    }
}

/// Checks whether a substituted callee needs `(0, callee)` to preserve call behavior. Member
/// references would otherwise receive `this`, and `eval` could become a direct eval call. A
/// local named `eval` may also hold the built-in function.
fn needs_detaching(callee: &Expr) -> bool {
    match callee {
        Expr::Member(_) | Expr::SuperProp(_) | Expr::OptChain(_) => true,
        Expr::Ident(identifier) => identifier.sym == "eval",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    /// Helper-call test cases and expected results. Calls remain unchanged when inlining could
    /// alter evaluation or its order. `set()` writes the parameters read by the arguments;
    /// `first()` and `second()` have unknown effects.
    const CALLS: [(&str, &str, &str); 27] = [
        // Inlined results are parenthesized, as are their substituted arguments.
        (
            "function(a, b) { return a & b; }",
            "h.op(local >>> 16, 65535) * 8133",
            "((local >>> 16) & (65535)) * 8133",
        ),
        // Eager operators evaluate their operands in argument order.
        (
            "function(a, b) { return a + b; }",
            "h.op(values[i++], first())",
            "(values[i++]) + (first())",
        ),
        // Reordering is safe when only one operand has effects and the other reads no affected
        // binding.
        (
            "function(a, b) { return b - a; }",
            "h.op(values[i++], 2)",
            "(2) - (values[i++])",
        ),
        (
            "function(a, b) { return b === a; }",
            "h.op(typeof values, 'object')",
            "('object') === (typeof values)",
        ),
        (
            "function(a, b) { return b | a; }",
            "h.op(first(), 2)",
            "(2) | (first())",
        ),
        // An effect-free operand may move past a write only if it does not read the written
        // binding.
        (
            "function(a, b) { return b | a; }",
            "h.op(values[i++], local)",
            "(local) | (values[i++])",
        ),
        (
            "function(a, b) { return b | a; }",
            "h.op(values[i++], i)",
            "h.op(values[i++], i)",
        ),
        (
            "function(a, b) { return b | a; }",
            "h.op(set(), v)",
            "h.op(set(), v)",
        ),
        (
            "function(a, b) { return b | a; }",
            "h.op(v, set())",
            "h.op(v, set())",
        ),
        (
            "function(a, b) { return b === a; }",
            "h.op(first(), second())",
            "h.op(first(), second())",
        ),
        // An outer unary operator runs after both operands, so `!(b !== a)` permits the same
        // reordering as `b === a`. `delete` has different operand evaluation rules.
        (
            "function(aX, ae) { return !(ae !== aX); }",
            "h.op(q._cf_chl_opt.EcMJs8, 1)",
            "!((1) !== (q._cf_chl_opt.EcMJs8))",
        ),
        (
            "function(a, b) { return -(b - a); }",
            "h.op(q.x, 2)",
            "-((2) - (q.x))",
        ),
        (
            "function(aX, ae) { return !(ae !== aX); }",
            "h.op(first(), second())",
            "h.op(first(), second())",
        ),
        (
            "function(a, b) { return delete b[a]; }",
            "h.op(first(), q)",
            "h.op(first(), q)",
        ),
        // A member read evaluates its object, then its key.
        (
            "function(a) { return a.key; }",
            "h.op(first())",
            "(first()).key",
        ),
        (
            "function(a, b) { return b[a]; }",
            "h.op(first(), second())",
            "h.op(first(), second())",
        ),
        // Unused parameters beyond the supplied arguments can be removed.
        (
            "function(rn, rw, ri, ru, KA) { return rn(rw, ri, ru); }",
            "h.op(local, 1, 2, 3)",
            "(local)((1), (2), (3))",
        ),
        (
            "function(a, b, extra) { return b | a; }",
            "h.op(local, 2, 3)",
            "(2) | (local)",
        ),
        (
            "function(a, b, extra) { return extra + b; }",
            "h.op(1, 2)",
            "h.op(1, 2)",
        ),
        (
            "function(a, b) { return a + b; }",
            "h.op(1, 2, 3)",
            "h.op(1, 2, 3)",
        ),
        // Reading an undefined global throws, so such an argument is not
        // dropped; a known one like `Math` can be.
        (
            "function(a, b) { return b; }",
            "h.op(missing, 1)",
            "h.op(missing, 1)",
        ),
        ("function(a, b) { return b; }", "h.op(Math, 1)", "((1))"),
        // Tests bodies that skip, repeat, or reorder operands within larger expressions.
        (
            "function(a, b) { return a + a; }",
            "h.op(first(), second())",
            "h.op(first(), second())",
        ),
        (
            "function(a, b) { return a && b; }",
            "h.op(first(), second())",
            "h.op(first(), second())",
        ),
        (
            "function(a, b) { return (a + 1) + b; }",
            "h.op(first(), second())",
            "h.op(first(), second())",
        ),
        (
            "function(a, a) { return a + a; }",
            "h.op(first(), second())",
            "h.op(first(), second())",
        ),
        (
            "async function(a, b) { return a + b; }",
            "h.op(1, 2)",
            "h.op(1, 2)",
        ),
    ];

    fn transform(source: &str) -> String {
        testing::rewrite(source, super::run, /* fix= */ false)
    }

    #[test]
    fn inlines_calls_only_when_evaluation_is_unchanged() {
        for (method, call, expected) in CALLS {
            let output = transform(&format!(
                "function f(h, i, values, q, local, v) {{ h = {{ op: {method} }}; \
                 const set = () => v = 1; return {call}; }}"
            ));
            assert!(output.contains(expected), "{method} {call}: {output}");
        }
        // Forwarded methods and `eval` are detached from their receiver.
        let output = testing::transform(
            r#"function f(h, obj, plain) {
                h = { invoke: function(fn, arg) { return fn(arg); } };
                h.invoke(obj.method, effect());
                h.invoke(plain, 1);
                h.invoke(Number, obj.value);
                return h.invoke(eval, "typeof local");
            }"#,
        );
        testing::assert_contains(&output, &["(0, obj.method)(effect())", "plain(1);"], &[]);
        let expected = ["(0, eval)(\"typeof local\")", "Number(obj.value);"];
        testing::assert_contains(&output, &expected, &[]);
        assert!(!output.contains("(0, plain)"), "{output}");
    }

    #[test]
    fn inlines_member_assigned_properties_and_helper_functions() {
        let output = transform(
            "function f(h, p) { h = {}; h.op = function (a, b) { return a + b; }; \
             h.name = \"n\"; p = h; return [p.op(1, 2), p.name, h.name]; }",
        );
        assert!(output.contains("(1) + (2)"), "{output}");
        testing::assert_lacks(&output, &["p.name", "h.name]"]);
        // Helper functions inline when they name only what callers see.
        let output = transform(
            "function f(add, call, read, g) { add = function(a, b) { return a + b; }; \
             call = function(a) { return add(a, 1) + Math.max(a); }; \
             g = function(local) { read = function() { return local; }; }; \
             g(5); return [call(2), add(3, 4), read()]; }",
        );
        let expected = ["((2)) + (1))", "Math.max((2))", "(3) + (4)", "read()]"];
        testing::assert_contains(&output, &[], &expected);
        // Function declarations inside function bodies are also stable; top-level declarations are
        // not.
        let output = transform(
            "function f(x) { return g(x, 1); function g(a, b) { return a + b; } } \
             function h(a) { return a; } k(h(2));",
        );
        testing::assert_contains(&output, &[], &["return ((x) + (1));", "k(h(2));"]);
        // Copies of helper methods are stable too.
        let output = transform(
            "function f(h, m) { h = { shr: function (a, b) { return a >> b; } }; m = h.shr; \
             return m(8, 1); }",
        );
        assert!(output.contains("(8) >> (1)"), "{output}");
    }

    #[test]
    fn preserves_reassigned_objects_regular_expressions_and_what_methods_reach() {
        let output = transform(
            r#"function g(h, out) {
                h = { add: function (a, b) { return a + b; }, name: "first" };
                out = [h.add(1, 2), h.name];
                h = other();
                out.push(h.add(3, 4), h.name);
                return out;
            }
            function k(h, alias) {
                h = { add: function (a, b) { return a + b; }, name: "first" };
                alias = h;
                alias = other();
                return [alias.add(1, 2), alias.name, h.add(1, 2)];
            }"#,
        );
        testing::assert_contains(&output, &["h.add(1, 2)", "h.add(3, 4)"], &[]);
        assert!(output.matches("h.name").count() == 2, "{output}");
        testing::assert_contains(&output, &["alias.add(1, 2)", "alias.name"], &[]);
        assert!(
            !output.contains("(1) + (2)"),
            "`h` is copied into a binding that is assigned again, which could change it before \
             that, so its properties are not trusted either: {output}"
        );
        assert!(
            output.matches("\"first\"").count() == 2,
            "nor are the literals of `h`: {output}"
        );
        let output = transform(
            "function f(s, h) { s = { n: 0, inc: function () { this.n++; } }; s.inc(); \
             h = { re: /a/g }; return [s.n, h.re.test(x), h.re.test(x)]; }",
        );
        assert!(output.contains("s.n,"), "{output}");
        assert_eq!(output.matches("h.re.test").count(), 2, "{output}");
    }

    /// A block function can run after the block references it or, in sloppy mode, after its
    /// declaration exposes it to the enclosing function. Properties assigned before either point
    /// are known.
    #[test]
    fn block_functions_see_properties_set_before_they_can_run() {
        let output = transform(
            r#"function f(h, p) { { h = {}; h.k = "v"; p = h; listen(g); function g(e) {
                return e === p.k; } } }"#,
        );
        assert!(output.contains(r#"e === "v""#), "{output}");
        // The function is referenced before its properties are assigned.
        let output = transform(
            r#"function f(h) { { listen(g); h = {}; h.k = "v"; function g(e) { return e === h.k; } } }"#,
        );
        assert!(output.contains("e === h.k"), "{output}");
        // The declaration exposes the function to the enclosing scope before its properties are
        // assigned.
        let output = transform(
            r#"function f(h) { { function g(e) { return e === h.k; } h = {}; h.k = "v"; } listen(g); }"#,
        );
        assert!(output.contains("e === h.k"), "{output}");
    }
}
