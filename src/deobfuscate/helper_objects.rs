//! Inlines literal and single-return function properties of helper objects:
//!
//! ```js
//! h = { add: function (a, b) { return a + b; }, key: "name" };
//! h.add(x, 1); h.key;  // becomes x + 1; "name"
//! ```
//!
//! Requires each property to be defined once on an object that does not escape (see
//! [`Properties::stable`]), and calls that preserve argument evaluation and order (see
//! [`substitute`]). Hoisted function bodies use only objects known wherever they can be called
//! (see [`hoisting`]).

use std::rc::Rc;
use std::{iter, mem};

use oxc::allocator::{CloneIn, GetAllocator, Vec as ArenaVec};
use oxc::ast::ast::{
    Argument, AssignmentExpression, BlockStatement, Expression, Function, IdentifierReference,
    ObjectPropertyKind, Program, SequenceExpression, Statement, VariableDeclarator,
};
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::syntax::operator::{AssignmentOperator, UnaryOperator};
use oxc::syntax::scope::ScopeFlags;
use oxc_ecmascript::side_effects::MayHaveSideEffects;

use super::analysis::effects::Effects;
use super::analysis::hoisting::{self, Facts, Hoisted, Hoisting, List};
use super::analysis::properties::Properties;
use super::analysis::unconditional::Unconditional;
use super::analysis::{Analysis, Id};
use super::{HashMap, ast};

/// The helper objects and functions known at one point, indexed by binding identity.
#[derive(Clone, Default)]
struct Helpers<'a> {
    /// Known object properties, shared between snapshots until a new definition extends them.
    objects: HashMap<Id, Rc<HashMap<&'a str, &'a Expression<'a>>>>,
    /// Single-return functions assigned to bindings with exactly one write.
    functions: HashMap<Id, &'a Function<'a>>,
}

impl Facts for Helpers<'_> {
    fn meet(&mut self, other: &Self) {
        self.objects.retain(|id, properties| {
            let Some(other) = other.objects.get(id) else {
                return false;
            };
            if !Rc::ptr_eq(properties, other) {
                Rc::make_mut(properties).retain(|key, _| other.contains_key(key))
            }
            true
        });
        self.functions.meet(&other.functions)
    }
}

/// Tracks helper objects and aliases only while their bindings have exactly one write.
pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let properties = Properties::collect(program, analysis);
    let mut inline = Inline {
        analysis,
        properties: &properties,
        hoisting: Hoisting::default(),
        lists: 0,
        list: 0,
        defined_in: HashMap::default(),
        changed: false,
    };
    inline.visit_program(program);
    inline.changed
}

struct Inline<'b, 'a> {
    analysis: &'b Analysis<'a>,
    properties: &'b Properties<'a>,
    /// Aliases receive the properties known when their assignment runs.
    hoisting: Hoisting<Rc<Helpers<'a>>>,
    /// Counts entered statement lists and sequences, to identify each one.
    lists: usize,
    /// The innermost statement list or sequence being visited.
    list: usize,
    /// The list or sequence that defines each object; only definitions in that same list may
    /// extend it.
    defined_in: HashMap<Id, usize>,
    changed: bool,
}

impl<'a> Hoisted<'a> for Inline<'_, 'a> {
    type Facts = Rc<Helpers<'a>>;

    fn analysis(&self) -> &Analysis<'a> {
        self.analysis
    }

    fn hoisting(&mut self) -> &mut Hoisting<Self::Facts> {
        &mut self.hoisting
    }
}

impl<'a> Inline<'_, 'a> {
    fn save_function(&mut self, id: Id, function: &Function<'a>) {
        let function = self.analysis.save(function);
        self.facts_mut().functions.insert(id, function);
    }

    /// Unshares the current facts before a change.
    fn facts_mut(&mut self) -> &mut Helpers<'a> {
        Rc::make_mut(&mut self.hoisting.facts)
    }

    /// Records a single-write object, function, or alias with the properties known at this
    /// assignment.
    fn record(&mut self, id: Id, value: &Expression<'a>) {
        if !self.analysis.bindings.is_written_once(&id) {
            return;
        }
        match value.get_inner_expression() {
            Expression::ObjectExpression(object) => {
                let mut properties = HashMap::default();
                for property in &object.properties {
                    if let ObjectPropertyKind::ObjectProperty(property) = property
                        && let Some(key) = ast::key(&property.key, property.computed)
                    {
                        properties.insert(key, self.analysis.save(&property.value));
                    }
                }
                self.facts_mut().objects.insert(id, Rc::new(properties));
            }
            Expression::FunctionExpression(function) if ast::returned(function).is_some() => {
                self.save_function(id, function)
            }
            Expression::Identifier(identifier) => {
                if let Some(source) = self.analysis.id(identifier)
                    && let Some(object) = self.hoisting.facts.objects.get(&source).cloned()
                {
                    self.facts_mut().objects.insert(id, object);
                }
            }
            _ => {
                if let Some(Expression::FunctionExpression(function)) = self.stable_value(value) {
                    self.save_function(id, function)
                }
            }
        }
    }

    /// Resolves a static member read only when both property stability and execution-order
    /// facts hold.
    fn stable_value(&self, expression: &Expression<'a>) -> Option<&'a Expression<'a>> {
        let member = expression.as_member_expression()?;
        let id = self.analysis.expression_id(member.object())?;
        let key = member.static_property_name()?.as_str()?;
        if !self.properties.stable(id, key, self.analysis) {
            return None;
        }
        self.hoisting.facts.objects.get(&id)?.get(key).copied()
    }

    /// Returns a known helper function that a call can inline.
    fn callee(&self, callee: &Expression<'a>) -> Option<&'a Function<'a>> {
        let Some(reference) = callee.get_identifier_reference() else {
            return match self.stable_value(callee)? {
                Expression::FunctionExpression(function) => Some(&**function),
                _ => None,
            };
        };
        let id = self.analysis.id(reference)?;
        let function = *self.hoisting.facts.functions.get(&id)?;
        names_only(function, id, self.analysis).then_some(function)
    }
}

/// Only property definitions in the object's defining list extend its known properties.
impl<'a> Unconditional<'a> for Inline<'_, 'a> {
    fn assigned(&mut self, assignment: &AssignmentExpression<'a>) {
        if let Some(id) = self.analysis.target_id(&assignment.left) {
            self.record(id, &assignment.right);
            self.defined_in.insert(id, self.list);
        } else if let Some(member) = assignment.left.as_member_expression()
            && let Some(id) = self.analysis.expression_id(member.object())
            && let Some(key) = member.static_property_name().and_then(|key| key.as_str())
            && self.defined_in.get(&id) == Some(&self.list)
            && self.hoisting.facts.objects.contains_key(&id)
        {
            let value = self.analysis.save(&assignment.right);
            let objects = &mut self.facts_mut().objects;
            let properties = objects.get_mut(&id).expect("the object is known");
            Rc::make_mut(properties).insert(key, value);
        }
    }

    fn declared(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(id) = ast::pattern_id(&declarator.id)
            && let Some(value) = &declarator.init
        {
            self.record(id, value);
            self.defined_in.insert(id, self.list);
        }
    }
}

impl<'a> VisitMut<'a> for Inline<'_, 'a> {
    fn visit_statements(&mut self, statements: &mut ArenaVec<'a, Statement<'a>>) {
        self.lists += 1;
        let outer = mem::replace(&mut self.list, self.lists);
        if self.hoisting.list == List::FunctionBody {
            for statement in statements.iter() {
                if let Statement::FunctionDeclaration(function) = statement
                    && let Some(id) = ast::function_id(function)
                    && self.analysis.bindings.is_written_once(&id)
                    && ast::returned(function).is_some()
                {
                    self.save_function(id, function)
                }
            }
        }
        hoisting::statements(self, statements, Self::unconditional_statement);
        self.list = outer;
    }

    fn visit_function(&mut self, function: &mut Function<'a>, _: ScopeFlags) {
        let outer = self.hoisting.facts.clone();
        hoisting::function(self, function);
        self.hoisting.facts = outer;
    }

    fn visit_block_statement(&mut self, block: &mut BlockStatement<'a>) {
        hoisting::block(self, block)
    }

    fn visit_identifier_reference(&mut self, reference: &mut IdentifierReference<'a>) {
        hoisting::reference(self, reference)
    }

    fn visit_sequence_expression(&mut self, sequence: &mut SequenceExpression<'a>) {
        self.lists += 1;
        let outer = mem::replace(&mut self.list, self.lists);
        for expression in &mut sequence.expressions {
            self.unconditional_expression(expression)
        }
        self.list = outer;
    }

    fn visit_assignment_expression(&mut self, assignment: &mut AssignmentExpression<'a>) {
        walk_mut::walk_assignment_expression(self, assignment);
        if assignment.operator == AssignmentOperator::Assign
            && let Some(id) = self.analysis.target_id(&assignment.left)
        {
            self.record(id, &assignment.right)
        }
    }

    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Expression::CallExpression(call) = expression
            && let Some(function) = self.callee(&call.callee)
            && let Some(value) = ast::returned(function)
            && let Some(replacement) = substitute(function, value, &call.arguments, self.analysis)
        {
            *expression = replacement;
            self.changed = true;
            return;
        }
        if let Some(value) = self.stable_value(expression)
            && ast::is_constant(value)
        {
            *expression = value.clone_in_with_semantic_ids(self.analysis.allocator());
            self.changed = true;
        }
    }
}

/// Checks that a direct helper's result names only parameters, globals, or bindings visible to
/// callers.
fn names_only(function: &Function<'_>, binding: Id, analysis: &Analysis<'_>) -> bool {
    let (Some(parameters), Some(value)) = (ast::parameters(function), ast::returned(function))
    else {
        return false;
    };
    let scope = analysis.scope(binding);
    let uses = Effects::expression(value, analysis);
    uses.reads.iter().chain(&uses.writes).all(|id| {
        let mut ancestors = analysis.scoping.scope_ancestors(scope);
        id.is_global()
            || parameters.contains(id)
            || ancestors.any(|scope| scope == analysis.scope(*id))
    })
}

/// Checks for `this`, `arguments`, `new.target`, or `super` outside ordinary nested functions.
/// Inlining would otherwise resolve these names in the caller instead of the helper.
fn own_context(expression: &Expression<'_>) -> bool {
    struct Context(bool);

    impl<'a> Visit<'a> for Context {
        fn visit_expression(&mut self, expression: &Expression<'a>) {
            self.0 |= match expression {
                Expression::ThisExpression(_) | Expression::Super(_) | Expression::NewTarget(_) => {
                    true
                }
                Expression::Identifier(identifier) => ast::is_arguments(identifier),
                _ => false,
            };
            walk::walk_expression(self, expression)
        }

        fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}
    }

    let mut context = Context(false);
    context.visit_expression(expression);
    context.0
}

/// Lists operands that always run, in evaluation order. Looks through outer unary operators
/// that run after their operands. Excludes `delete`, which does not evaluate a value read.
fn operands<'b, 'a>(expression: &'b Expression<'a>) -> Option<Vec<&'b Expression<'a>>> {
    match expression.get_inner_expression() {
        Expression::UnaryExpression(unary) if unary.operator != UnaryOperator::Delete => {
            operands(&unary.argument).or_else(|| Some(vec![&unary.argument]))
        }
        Expression::BinaryExpression(binary) => Some(vec![&binary.left, &binary.right]),
        Expression::StaticMemberExpression(member) => Some(vec![&member.object]),
        Expression::ComputedMemberExpression(member) => {
            Some(vec![&member.object, &member.expression])
        }
        Expression::CallExpression(call) if !call.optional => {
            let arguments = call.arguments.iter().map(Argument::as_expression);
            iter::once(Some(&call.callee)).chain(arguments).collect()
        }
        _ => None,
    }
}

/// Two arguments may swap if both have no effects, or one is effect-free and reads no binding
/// the other writes. Opaque operations may write through closures, so local reads cannot cross
/// them.
fn commutes(left: &Expression<'_>, right: &Expression<'_>, analysis: &Analysis<'_>) -> bool {
    let effects = (
        left.may_have_side_effects(analysis),
        right.may_have_side_effects(analysis),
    );
    let (pure, impure) = match effects {
        (false, false) => return true,
        (false, true) => (left, right),
        (true, false) => (right, left),
        (true, true) => return false,
    };
    let pure = Effects::expression(pure, analysis);
    if pure.reads.is_empty() {
        return true;
    }
    let impure = Effects::expression(impure, analysis);
    !impure.opaque && impure.writes.is_disjoint(&pure.reads)
}

/// Checks argument evaluation before substituting a helper's single return expression.
/// Parameters must be plain identifiers; missing arguments are allowed only for unused trailing
/// parameters. Async functions, generators, helper-context reads, and parameter stores are kept.
/// Effectful arguments must occur exactly once in eager operands, with only commuting arguments
/// reordered. Nested arithmetic and short-circuit expressions need the stricter effect-free path.
fn substitute<'a>(
    function: &Function<'a>,
    value: &Expression<'a>,
    arguments: &[Argument<'a>],
    analysis: &Analysis<'a>,
) -> Option<Expression<'a>> {
    let parameters = ast::parameters(function)?;
    if function.r#async
        || function.generator
        || own_context(value)
        || arguments.len() > parameters.len()
    {
        return None;
    }
    let arguments: Vec<&Expression<'a>> = arguments
        .iter()
        .map(Argument::as_expression)
        .collect::<Option<_>>()?;
    let used = Effects::expression(value, analysis);
    // Parameter stores need a fresh local environment, which expression substitution cannot
    // supply.
    if parameters.iter().any(|id| used.writes.contains(id))
        || parameters[arguments.len()..]
            .iter()
            .any(|id| used.reads.contains(id))
    {
        return None;
    }
    if arguments
        .iter()
        .any(|argument| argument.may_have_side_effects(analysis))
    {
        let operands = operands(value)?;
        if operands.len() != arguments.len() {
            return None;
        }
        let mut order = vec![];
        for operand in operands {
            let id = analysis.expression_id(operand)?;
            let index = parameters.iter().position(|parameter| *parameter == id)?;
            if order.contains(&index) || index >= arguments.len() {
                return None;
            }
            order.push(index)
        }
        for (position, &first) in order.iter().enumerate() {
            for &second in &order[position + 1..] {
                if first > second && !commutes(arguments[first], arguments[second], analysis) {
                    return None;
                }
            }
        }
    }
    let values = parameters.into_iter().zip(arguments).collect();
    Some(ast::replace_parameters(value, &values, analysis))
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    /// Helper-call test cases and expected results. Calls remain unchanged when inlining could
    /// alter evaluation or its order. `set()` writes the parameters read by the arguments;
    /// `first()` and `second()` have unknown effects.
    const CALLS: [(&str, &str, &str); 28] = [
        // Inlined results keep the precedence of their substituted arguments.
        (
            "function(a, b) { return a & b; }",
            "h.op(local >>> 16, 65535) * 8133",
            "(local >>> 16 & 65535) * 8133",
        ),
        // Eager operators evaluate their operands in argument order.
        (
            "function(a, b) { return a + b; }",
            "h.op(values[i++], first())",
            "values[i++] + first()",
        ),
        // Reordering is safe when only one operand has effects and the other reads no affected
        // binding.
        (
            "function(a, b) { return b - a; }",
            "h.op(values[i++], 2)",
            "2 - values[i++]",
        ),
        (
            "function(a, b) { return b === a; }",
            "h.op(typeof values, 'object')",
            r#""object" === typeof values"#,
        ),
        (
            "function(a, b) { return b | a; }",
            "h.op(first(), 2)",
            "2 | first()",
        ),
        // An effect-free operand may move past a write only if it does not read the written
        // binding.
        (
            "function(a, b) { return b | a; }",
            "h.op(values[i++], local)",
            "local | values[i++]",
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
        (
            "function(a, b) { return b + a; }",
            "h.op(v, [v] = [2])",
            "h.op(v, [v] = [2])",
        ),
        // An outer unary operator runs after both operands, so `!(b !== a)` permits the same
        // reordering as `b === a`. `delete` has different operand evaluation rules.
        (
            "function(aX, ae) { return !(ae !== aX); }",
            "h.op(q._cf_chl_opt.EcMJs8, 1)",
            "!(1 !== q._cf_chl_opt.EcMJs8)",
        ),
        (
            "function(a, b) { return -(b - a); }",
            "h.op(q.x, 2)",
            "-(2 - q.x)",
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
            "first().key",
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
            "local(1, 2, 3)",
        ),
        (
            "function(a, b, extra) { return b | a; }",
            "h.op(local, 2, 3)",
            "2 | local",
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
        ("function(a, b) { return b; }", "h.op(Math, 1)", "return 1;"),
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
        testing::rewrite(source, super::run)
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
        testing::assert_contains(&output, &["(0, obj.method)(effect())", "plain(1);"]);
        let expected = ["(0, eval)(\"typeof local\")", "Number(obj.value);"];
        testing::assert_contains(&output, &expected);
        assert!(!output.contains("(0, plain)"), "{output}");
    }

    #[test]
    fn inlines_member_assigned_properties_and_helper_functions() {
        let output = transform(
            "function f(h, p) { h = {}; h.op = function (a, b) { return a + b; }; \
             h.name = \"n\"; p = h; return [p.op(1, 2), p.name, h.name]; }",
        );
        assert!(output.contains("1 + 2"), "{output}");
        testing::assert_lacks(&output, &["p.name", "h.name]"]);
        // Static templates inline into later callbacks, as in a payload built after a delay.
        let output = transform(
            "function f(h, g) { h = { key: `_field` }; g(function () { return w[h.key]; }); }",
        );
        assert!(output.contains("w[`_field`]"), "{output}");
        // A unary helper evaluates its argument first either way, even a member read.
        let output =
            transform("function f(n) { n = function (a) { return !a; }; if (n(w.x)) g(); }");
        assert!(output.contains("!w.x"), "{output}");
        // Helper functions inline when they name only what callers see.
        let output = transform(
            "function f(add, call, read, g) { add = function(a, b) { return a + b; }; \
             call = function(a) { return add(a, 1) + Math.max(a); }; \
             g = function(local) { read = function() { return local; }; }; \
             g(5); return [call(2), add(3, 4), read()]; }",
        );
        let expected = ["2 + 1", "Math.max(2)", "3 + 4", "read()]"];
        testing::assert_contains(&output, &expected);
        // Function declarations inside function bodies are also stable; top-level declarations are
        // not.
        let output = transform(
            "function f(x) { return g(x, 1); function g(a, b) { return a + b; } } \
             function h(a) { return a; } k(h(2));",
        );
        testing::assert_contains(&output, &["return x + 1;", "k(h(2));"]);
        // Copies of helper methods are stable too.
        let output = transform(
            "function f(h, m) { h = { shr: function (a, b) { return a >> b; } }; m = h.shr; \
             return m(8, 1); }",
        );
        assert!(output.contains("8 >> 1"), "{output}");
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
        testing::assert_contains(&output, &["h.add(1, 2)", "h.add(3, 4)"]);
        assert!(output.matches("h.name").count() == 2, "{output}");
        testing::assert_contains(&output, &["alias.add(1, 2)", "alias.name"]);
        assert!(
            !output.contains("1 + 2"),
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
