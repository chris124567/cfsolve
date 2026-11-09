//! Replaces local array slots with separate variables when all accesses use constant indices:
//!
//! ```js
//! var r, a;
//! r = [void 0, void 0, void 0];
//! a = r[1] = f(); g(r[0]++); r[2] = h();  // becomes
//! var r_0, a;
//! a = f(); g(r_0++); h();
//! ```
//!
//! The array must be local to a function and initialized or assigned once from a literal without spreads.
//! That assignment must discard its value. All other uses must access constant indices within
//! bounds, without calling or deleting slots. Writes to unread slots keep only the assigned
//! expression so its side effects still run.
//!
//! Undefined slots need no assignment if the literal runs at most once per call, in the
//! declaring function and outside loops. The replacement locals already start undefined. A
//! `void` element there keeps only its operand, so a constant hidden as `void (k ^ x ^ (k ^ x))`
//! leaves the slot's later write as its local's only one, which copy propagation can inline.

use std::mem;

use oxc::allocator::{Box, CloneIn, GetAllocator, TakeIn, Vec as ArenaVec};
use oxc::ast::ast::{
    ArrayExpression, ArrowFunctionExpression, AssignmentExpression, AssignmentTarget,
    BindingIdentifier, BindingPattern, CallExpression, Expression, ExpressionStatement,
    ForStatement, Function, IdentifierReference, MemberExpression, Program, SimpleAssignmentTarget,
    Statement, TaggedTemplateExpression, UnaryExpression, UpdateExpression, VariableDeclaration,
    VariableDeclarator,
};
use oxc::ast::builder::AstBuilder;
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::span::{GetSpan, Span};
use oxc::syntax::operator::{AssignmentOperator, UnaryOperator};
use oxc::syntax::reference::ReferenceFlags;
use oxc::syntax::scope::{ScopeFlags, ScopeId};

use super::analysis::{Analysis, Id};
use super::{HashMap, HashSet, ast};

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let root = analysis.scoping.root_scope_id();
    let mut uses = Uses {
        analysis,
        created: HashMap::default(),
        slots: HashMap::default(),
        function: root,
        loops: 0,
        discarded: false,
    };
    uses.visit_program(program);
    let mut slots = uses.slots;
    let mut arrays = HashMap::default();
    for (id, created) in uses.created {
        let [creation] = created.as_slice() else {
            continue;
        };
        let slots = slots.remove(&id).unwrap_or_default();
        let bindings = &analysis.bindings;
        if creation.function == root
            || analysis.scope(id) != creation.function
            || !bindings.is_written_once(&id)
            || bindings.is_parameter(&id)
            || slots.opaque
            || slots.accesses != bindings.references(&id)
            || slots
                .read
                .iter()
                .chain(&slots.written)
                .any(|&index| index >= creation.length)
        {
            continue;
        }
        let base = analysis.name(id).to_owned();
        let span = analysis.span(id);
        let locals = (0..creation.length).map(|index| {
            let used = slots.read.contains(&index) || creation.defined.contains(&index);
            used.then(|| {
                analysis.fresh_binding(&format!("{base}_{index}"), creation.function, span)
            })
        });
        let array = Array {
            locals: locals.collect(),
            read: slots.read,
            reset: !creation.once,
        };
        arrays.insert(id, array);
    }
    if arrays.is_empty() {
        return false;
    }
    Split {
        analysis,
        arrays: &arrays,
    }
    .visit_program(program);
    true
}

/// Recognizes a hole or an [`Analysis::is_undefined`] value.
fn undefined(value: Option<&Expression<'_>>, analysis: &Analysis<'_>) -> bool {
    value.is_none_or(|value| analysis.is_undefined(value))
}

/// Extracts `array[index]` with a constant non-negative integer index, rejecting optional access.
fn slot(member: Option<&MemberExpression<'_>>, analysis: &Analysis<'_>) -> Option<(Id, usize)> {
    let Some(MemberExpression::ComputedMemberExpression(member)) = member else {
        return None;
    };
    if member.optional {
        return None;
    }
    Some((
        analysis.expression_id(&member.object)?,
        ast::index(&member.expression)?,
    ))
}

fn void_zero<'a>(span: Span, builder: &AstBuilder<'a>) -> Expression<'a> {
    let zero = ast::number_literal(span, 0.0, builder);
    Expression::new_unary_expression(span, UnaryOperator::Void, zero, builder)
}

/// An array-literal creation and the context that executes it.
struct Creation {
    length: usize,
    /// Slots initialized to values other than effect-free undefined.
    defined: HashSet<usize>,
    function: ScopeId,
    /// Creation runs outside loops and at most once per invocation of its declaring function.
    once: bool,
}

#[derive(Default)]
struct Slots {
    /// Compared with the binding's reference count to detect other uses.
    accesses: usize,
    /// Slots read, updated, or assigned with an operator other than plain `=`.
    read: HashSet<usize>,
    written: HashSet<usize>,
    /// A slot is called, tagged, or deleted; these uses depend on the array itself.
    opaque: bool,
}

/// Collects discarded array assignments, declared initializers, and slot accesses.
struct Uses<'b, 'a> {
    analysis: &'b Analysis<'a>,
    created: HashMap<Id, Vec<Creation>>,
    slots: HashMap<Id, Slots>,
    function: ScopeId,
    loops: usize,
    /// The visited expression's value is discarded.
    discarded: bool,
}

impl<'a> Uses<'_, 'a> {
    fn create(&mut self, id: Id, array: &ArrayExpression<'a>) {
        if array.elements.iter().any(|element| element.is_spread()) {
            return;
        }
        let mut defined = HashSet::default();
        for (index, element) in array.elements.iter().enumerate() {
            if !undefined(element.as_expression(), self.analysis) {
                defined.insert(index);
            }
        }
        self.created.entry(id).or_default().push(Creation {
            length: array.elements.len(),
            defined,
            function: self.function,
            once: self.loops == 0,
        });
    }

    fn access(&mut self, member: Option<&MemberExpression<'a>>, read: bool) {
        if let Some((id, index)) = slot(member, self.analysis) {
            let slots = self.slots.entry(id).or_default();
            slots.accesses += 1;
            if read {
                slots.read.insert(index);
            } else {
                slots.written.insert(index);
            }
        }
    }

    fn opaque(&mut self, expression: &Expression<'a>) {
        if let Some((id, _)) = slot(expression.as_member_expression(), self.analysis) {
            self.slots.entry(id).or_default().opaque = true
        }
    }

    fn expression(&mut self, expression: &Expression<'a>, discarded: bool) {
        let outer = mem::replace(&mut self.discarded, discarded);
        self.visit_expression(expression);
        self.discarded = outer;
    }

    /// Visits a function body with its own scope and outside the enclosing loops.
    fn function(&mut self, scope: Option<ScopeId>, walk: impl FnOnce(&mut Self)) {
        let scope = scope.expect("semantic analysis assigns function scopes");
        let outer = mem::replace(&mut self.function, scope);
        let loops = mem::take(&mut self.loops);
        walk(self);
        self.function = outer;
        self.loops = loops;
    }
}

impl<'a> Visit<'a> for Uses<'_, 'a> {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        let discarded = mem::replace(&mut self.discarded, false);
        if discarded
            && let Some((id, Expression::ArrayExpression(array))) =
                self.analysis.assignment(expression)
        {
            self.create(id, array)
        }
        self.access(expression.as_member_expression(), true);
        if let Expression::SequenceExpression(sequence) = expression {
            let length = sequence.expressions.len();
            for (index, expression) in sequence.expressions.iter().enumerate() {
                self.expression(expression, index + 1 < length || discarded)
            }
        } else {
            walk::walk_expression(self, expression)
        }
        self.discarded = discarded;
    }

    fn visit_expression_statement(&mut self, statement: &ExpressionStatement<'a>) {
        self.expression(&statement.expression, true)
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(id) = ast::pattern_id(&declarator.id)
            && let Some(Expression::ArrayExpression(array)) = &declarator.init
        {
            self.create(id, array)
        }
        walk::walk_variable_declarator(self, declarator)
    }

    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        let Some(member) = assignment.left.as_member_expression() else {
            return walk::walk_assignment_expression(self, assignment);
        };
        self.access(
            Some(member),
            assignment.operator != AssignmentOperator::Assign,
        );
        self.visit_expression(member.object());
        if let MemberExpression::ComputedMemberExpression(computed) = member {
            self.visit_expression(&computed.expression)
        }
        self.visit_expression(&assignment.right)
    }

    fn visit_update_expression(&mut self, update: &UpdateExpression<'a>) {
        self.access(update.argument.as_member_expression(), true);
        walk::walk_update_expression(self, update)
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.opaque(&call.callee);
        walk::walk_call_expression(self, call)
    }

    fn visit_tagged_template_expression(&mut self, template: &TaggedTemplateExpression<'a>) {
        self.opaque(&template.tag);
        walk::walk_tagged_template_expression(self, template)
    }

    fn visit_unary_expression(&mut self, unary: &UnaryExpression<'a>) {
        if unary.operator == UnaryOperator::Delete {
            self.opaque(&unary.argument)
        }
        walk::walk_unary_expression(self, unary)
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        self.function(function.scope_id.get(), |uses| {
            walk::walk_function(uses, function, flags)
        })
    }

    fn visit_arrow_function_expression(&mut self, arrow: &ArrowFunctionExpression<'a>) {
        self.function(arrow.scope_id.get(), |uses| {
            walk::walk_arrow_function_expression(uses, arrow)
        })
    }

    fn visit_statement(&mut self, statement: &Statement<'a>) {
        let is_loop = usize::from(matches!(
            statement,
            Statement::WhileStatement(_)
                | Statement::DoWhileStatement(_)
                | Statement::ForInStatement(_)
                | Statement::ForOfStatement(_)
        ));
        self.loops += is_loop;
        walk::walk_statement(self, statement);
        self.loops -= is_loop;
    }

    /// The initializer runs once, unlike the rest of the loop.
    fn visit_for_statement(&mut self, for_loop: &ForStatement<'a>) {
        if let Some(init) = &for_loop.init {
            match init.as_expression() {
                Some(expression) => self.expression(expression, true),
                None => self.visit_for_statement_init(init),
            }
        }
        self.loops += 1;
        if let Some(test) = &for_loop.test {
            self.visit_expression(test)
        }
        if let Some(update) = &for_loop.update {
            self.visit_expression(update)
        }
        self.visit_statement(&for_loop.body);
        self.loops -= 1;
    }
}

/// A split array.
struct Array<'a> {
    /// Replacement binding for each slot that is read or initialized with a value.
    locals: Vec<Option<BindingIdentifier<'a>>>,
    read: HashSet<usize>,
    /// Creation can repeat, so even undefined slots need explicit assignments.
    reset: bool,
}

struct Split<'b, 'a> {
    analysis: &'b mut Analysis<'a>,
    arrays: &'b HashMap<Id, Array<'a>>,
}

impl<'b, 'a> Split<'b, 'a> {
    /// Returns the replacement local of a split array's slot.
    fn local(&self, member: Option<&MemberExpression<'a>>) -> Option<&'b BindingIdentifier<'a>> {
        let (id, index) = slot(member, self.analysis)?;
        self.arrays.get(&id)?.locals[index].as_ref()
    }

    fn reference(
        &mut self,
        local: &BindingIdentifier<'a>,
        span: Span,
        flags: ReferenceFlags,
    ) -> Box<'a, IdentifierReference<'a>> {
        let reference = self.analysis.reference(local.symbol_id(), span, flags);
        Box::new_in(reference, &self.analysis.ast)
    }

    /// Builds scalar assignments in the array literal's element order. Locals already start
    /// undefined on each function call, so a once-only `void` element keeps just its operand;
    /// creations inside loops must reset undefined slots on every iteration.
    fn initial(
        &mut self,
        array: &Array<'a>,
        literal: &ArrayExpression<'a>,
    ) -> ArenaVec<'a, Expression<'a>> {
        let allocator = self.analysis.allocator();
        let span = literal.span;
        let mut initial = ArenaVec::new_in(&self.analysis.ast);
        for (index, element) in literal.elements.iter().enumerate() {
            let value = element.as_expression();
            if !array.reset {
                if undefined(value, self.analysis) {
                    continue;
                }
                if let Some(Expression::UnaryExpression(unary)) = value
                    && unary.operator == UnaryOperator::Void
                {
                    initial.push(unary.argument.clone_in_with_semantic_ids(allocator));
                    continue;
                }
            }
            let value = match value {
                Some(value) => value.clone_in_with_semantic_ids(allocator),
                None => void_zero(span, &self.analysis.ast),
            };
            let Some(local) = &array.locals[index] else {
                initial.push(value);
                continue;
            };
            let reference = self.reference(local, span, ReferenceFlags::Write);
            let target = AssignmentTarget::AssignmentTargetIdentifier(reference);
            initial.push(Expression::new_assignment_expression(
                span,
                AssignmentOperator::Assign,
                target,
                value,
                &self.analysis.ast,
            ));
        }
        initial
    }
}

impl<'a> VisitMut<'a> for Split<'_, 'a> {
    fn visit_assignment_target(&mut self, target: &mut AssignmentTarget<'a>) {
        let Some(local) = self.local(target.as_member_expression()) else {
            return walk_mut::walk_assignment_target(self, target);
        };
        let reference = self.reference(local, target.span(), ReferenceFlags::Write);
        *target = AssignmentTarget::AssignmentTargetIdentifier(reference);
    }

    fn visit_simple_assignment_target(&mut self, target: &mut SimpleAssignmentTarget<'a>) {
        let Some(local) = self.local(target.as_member_expression()) else {
            return walk_mut::walk_simple_assignment_target(self, target);
        };
        let flags = ReferenceFlags::Read | ReferenceFlags::Write;
        let reference = self.reference(local, target.span(), flags);
        *target = SimpleAssignmentTarget::AssignmentTargetIdentifier(reference);
    }

    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        if let Expression::AssignmentExpression(assignment) = expression {
            // A write to a slot that is never read keeps only its value.
            if let Some((id, index)) = slot(assignment.left.as_member_expression(), self.analysis)
                && let Some(array) = self.arrays.get(&id)
                && !array.read.contains(&index)
            {
                let mut value = assignment.right.take_in(&self.analysis.ast);
                self.visit_expression(&mut value);
                *expression = value;
                return;
            }
            if let Some(id) = self.analysis.target_id(&assignment.left)
                && let Some(array) = self.arrays.get(&id)
                && let Expression::ArrayExpression(literal) = &assignment.right
            {
                let mut initial = self.initial(array, literal);
                *expression = if initial.len() > 1 {
                    Expression::new_sequence_expression(assignment.span, initial, self.analysis)
                } else {
                    initial
                        .pop()
                        .unwrap_or_else(|| void_zero(assignment.span, &self.analysis.ast))
                };
                return;
            }
        }
        walk_mut::walk_expression(self, expression);
        if let Some(local) = self.local(expression.as_member_expression()) {
            let reference = self.reference(local, expression.span(), ReferenceFlags::Read);
            *expression = Expression::Identifier(reference);
        }
    }

    fn visit_variable_declaration(&mut self, declaration: &mut VariableDeclaration<'a>) {
        let allocator = self.analysis.allocator();
        let mut declarators = ArenaVec::new_in(&self.analysis.ast);
        for declarator in declaration.declarations.take_in(&self.analysis.ast) {
            let array = ast::pattern_id(&declarator.id).and_then(|id| self.arrays.get(&id));
            let Some(array) = array else {
                declarators.push(declarator);
                continue;
            };
            for (index, local) in array.locals.iter().enumerate() {
                let Some(local) = local else { continue };
                let init = match &declarator.init {
                    Some(Expression::ArrayExpression(literal)) => literal.elements[index]
                        .as_expression()
                        .filter(|value| array.reset || !undefined(Some(value), self.analysis))
                        .map(|value| value.clone_in_with_semantic_ids(allocator)),
                    _ => None,
                };
                let local = Box::new_in(
                    local.clone_in_with_semantic_ids(allocator),
                    &self.analysis.ast,
                );
                let pattern = BindingPattern::BindingIdentifier(local);
                declarators.push(VariableDeclarator::new(
                    declarator.span,
                    pattern,
                    None,
                    init,
                    false,
                    &self.analysis.ast,
                ));
            }
        }
        declaration.declarations = declarators;
        walk_mut::walk_variable_declaration(self, declaration);
    }

    /// Drops the statements left by removed undefined writes.
    fn visit_statements(&mut self, statements: &mut ArenaVec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        statements.retain(|statement| {
            !matches!(statement, Statement::ExpressionStatement(statement)
                if undefined(Some(&statement.expression), self.analysis))
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn splits_arrays_reached_only_through_constant_slots() {
        let transform = |source: &str| testing::rewrite(source, super::run);
        let output = transform(
            "function f(x) {
                var r, a, s = [1, void 0];
                r = [void 0, void (2 ^ (3 + (4 | (5 ^ (6 + 7))))), void 0];
                a = r[1] = g(); g(r[0]++, s[0], s[1]); r[2] = h();
                return function() { return r[0]; };
            }",
        );
        testing::assert_contains(
            &output,
            &[
                "var r_0, a, s_0 = 1, s_1;",
                "a = g(); g(r_0++, s_0, s_1); h();",
                "return r_0;",
            ],
        );
        testing::assert_lacks(&output, &["r_1", "r_2", "[", "void 0"]);
        // A loop's initializer runs once.
        let output = transform(
            "function f() { var r, i; for (r = [void 0], i = 0; i < 2; i++) { h(r[0]); r[0] = i; } }",
        );
        testing::assert_contains(&output, &["h(r_0);", "r_0 = i;"]);
        testing::assert_lacks(&output, &["r_0 = void 0", "["]);
        // A `void` element runs its operand without writing the local.
        let output =
            transform("function f() { var r; r = [void (7 ^ k ^ (7 ^ k))]; r[0] = 1; g(r[0]); }");
        testing::assert_contains(&output, &["7 ^ k ^ (7 ^ k);", "r_0 = 1;", "g(r_0);"]);
        testing::assert_lacks(&output, &["r_0 = void"]);
        // A creation in a loop resets the slots on every iteration.
        let output =
            transform("function f() { var r; while (g()) { r = [void 0]; h(r[0]); r[0] = 1; } }");
        testing::assert_contains(&output, &["r_0 = void 0;", "h(r_0);", "r_0 = 1;"]);
        for kept in [
            "function f() { var r; r = [1]; g(r); }",
            "function f() { var r; r = [1]; r[0](); }",
            "function f() { var r; r = [1]; delete r[0]; }",
            "function f() { var r; r = [1]; g(r[1]); }",
            "function f() { var r; r = [1]; g(r[i]); }",
            "function f() { var r; r = [1]; r = [2]; g(r[0]); }",
            "function f() { var r; g(r = [1]); g(r[0]); }",
            "function f(r) { var r; r = [1]; g(r[0]); }",
            "function f() { var r; (function() { r = [1]; })(); g(r[0]); }",
            "function f() { var r; r = [...a]; g(r[0]); }",
            "var r; r = [1]; g(r[0]);",
        ] {
            let output = transform(kept);
            assert!(!output.contains("r_0"), "{output}");
        }
    }
}
