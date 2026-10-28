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
//! The array must be local to a function and assigned once from a literal without spreads.
//! That assignment must discard its value. All other uses must access constant indices within
//! bounds, without calling or deleting slots. Writes to unread slots keep only the assigned
//! expression so its side effects still run.
//!
//! Undefined slots need no assignment if the literal runs at most once per call, in the
//! declaring function and outside loops. The replacement locals already start undefined.

use swc_core::common::util::take::Take;
use swc_core::common::{DUMMY_SP, Mark, SyntaxContext};
use swc_core::ecma::ast::{
    ArrayLit, ArrowExpr, AssignExpr, AssignOp, AssignTarget, BindingIdent, CallExpr, Callee,
    Constructor, Expr, ExprStmt, ForStmt, Function, GetterProp, Id, Ident, MemberExpr, Pat,
    Program, SeqExpr, SetterProp, SimpleAssignTarget, Stmt, TaggedTpl, UnaryExpr, UnaryOp,
    VarDeclOrExpr, VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::{Analysis, Globals, effects};
use super::{HashMap, HashSet, removal};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let globals = analysis.globals;
    let bindings = analysis.bindings(program);
    let mut uses = Uses {
        globals,
        created: HashMap::default(),
        slots: HashMap::default(),
        declared: HashMap::default(),
        function: 0,
        functions: 0,
        loops: 0,
    };
    program.visit_with(&mut uses);
    let mut arrays = HashMap::default();
    for (id, created) in uses.created {
        let slots = uses.slots.remove(&id).unwrap_or_default();
        let [creation] = &created[..] else {
            continue;
        };
        if creation.function == 0
            || uses.declared.get(&id) != Some(&creation.function)
            || bindings.write_count(&id) != 1
            || bindings.is_parameter(&id)
            || slots.opaque
            || slots.accesses != bindings.references(&id)
            || slots
                .read
                .iter()
                .chain(&slots.written)
                .any(|&slot| slot >= creation.length)
        {
            continue;
        }
        // Give each array a separate context so same-named arrays stay distinct until hygiene
        // renames them.
        let context = SyntaxContext::empty().apply_mark(Mark::new());
        let locals: Vec<Option<Ident>> = (0..creation.length)
            .map(|slot| {
                let needed = slots.read.contains(&slot) || creation.defined.contains(&slot);
                needed.then(|| Ident::new(format!("{}_{slot}", id.0).into(), DUMMY_SP, context))
            })
            .collect();
        arrays.insert(
            id,
            Array {
                locals,
                read: slots.read,
                // Replacement locals already start undefined on each call.
                assign_undefined: !creation.once,
            },
        );
    }
    if arrays.is_empty() {
        return false;
    }
    program.visit_mut_with(&mut Split {
        arrays: &arrays,
        globals,
    });
    true
}

/// Checks whether an element is undefined with no side effects: a hole, a side-effect-free `void`
/// expression, or global `undefined`.
fn is_undefined(element: Option<&Expr>, globals: Globals) -> bool {
    match element {
        None => true,
        // Constant arithmetic has no side effects, even when nested.
        Some(Expr::Unary(unary)) => {
            unary.op == UnaryOp::Void
                && (ast::fold_number(&unary.arg, &|_| None).is_some()
                    || !effects::may_have_effects(&unary.arg, globals))
        }
        Some(Expr::Ident(identifier)) => globals.is(identifier, "undefined"),
        Some(_) => false,
    }
}

fn undefined() -> Expr {
    Expr::Unary(UnaryExpr {
        span: DUMMY_SP,
        op: UnaryOp::Void,
        arg: 0.0.into(),
    })
}

/// Extracts the array and constant index from `array[slot]`. Folds indices because the simplifier
/// leaves them unchanged in optional chains.
fn slot(member: &MemberExpr) -> Option<(Id, usize)> {
    let index = &member.prop.as_computed()?.expr;
    let slot = ast::array_index(ast::fold_number(index, &|_| None)?)?;
    Some((member.obj.as_ident()?.to_id(), slot))
}

struct Creation {
    length: usize,
    /// Slots initialized to values other than undefined.
    defined: HashSet<usize>,
    function: usize,
    /// Whether creation occurs outside loops and at most once per call of `function`.
    once: bool,
}

#[derive(Default)]
struct Slots {
    /// Number of constant-index accesses, for comparison with the total reference count.
    accesses: usize,
    /// Slots read, updated, or assigned with an operator other than `=`.
    read: HashSet<usize>,
    written: HashSet<usize>,
    /// Whether a slot is called or deleted. These operations depend on the array itself.
    opaque: bool,
}

/// Collects array assignments whose values are discarded, slot accesses, and the function declaring
/// each array binding.
struct Uses {
    globals: Globals,
    created: HashMap<Id, Vec<Creation>>,
    slots: HashMap<Id, Slots>,
    declared: HashMap<Id, usize>,
    /// Current function number in traversal order; 0 denotes the script.
    function: usize,
    functions: usize,
    loops: usize,
}

impl Uses {
    fn create(&mut self, id: Id, array: &ArrayLit) {
        let mut defined = HashSet::default();
        for (slot, element) in array.elems.iter().enumerate() {
            if element
                .as_ref()
                .is_some_and(|element| element.spread.is_some())
            {
                return;
            }
            if !is_undefined(element.as_ref().map(|element| &*element.expr), self.globals) {
                defined.insert(slot);
            }
        }
        let creation = Creation {
            length: array.elems.len(),
            defined,
            function: self.function,
            once: self.loops == 0,
        };
        self.created.entry(id).or_default().push(creation);
    }

    /// Records an array assignment whose value is discarded by a statement. Sequence expressions
    /// handle their other operands separately.
    fn statement(&mut self, expression: &Expr) {
        let last = expression
            .as_seq()
            .and_then(|sequence| sequence.exprs.last());
        self.discarded(last.map_or(expression, |last| &**last));
    }

    /// Records `binding = [...]`.
    fn discarded(&mut self, expression: &Expr) {
        if let Some((id, Expr::Array(array))) = ast::assignment(expression) {
            self.create(id, array);
        }
    }

    fn access(&mut self, member: &MemberExpr, read: bool) {
        if let Some((id, slot)) = slot(member) {
            let slots = self.slots.entry(id).or_default();
            slots.accesses += 1;
            if read {
                slots.read.insert(slot);
            } else {
                slots.written.insert(slot);
            }
        }
    }

    fn opaque(&mut self, expression: &Expr) {
        if let Some(member) = expression.unwrap_parens().as_member()
            && let Some((id, _)) = slot(member)
        {
            self.slots.entry(id).or_default().opaque = true;
        }
    }

    fn in_function(&mut self, visit: impl FnOnce(&mut Self)) {
        self.functions += 1;
        let function = std::mem::replace(&mut self.function, self.functions);
        let loops = std::mem::take(&mut self.loops);
        visit(self);
        self.function = function;
        self.loops = loops;
    }

    fn in_loop(&mut self, visit: impl FnOnce(&mut Self)) {
        self.loops += 1;
        visit(self);
        self.loops -= 1;
    }
}

impl Visit for Uses {
    fn visit_expr_stmt(&mut self, statement: &ExprStmt) {
        self.statement(&statement.expr);
        statement.visit_children_with(self);
    }

    fn visit_seq_expr(&mut self, sequence: &SeqExpr) {
        if let [discarded @ .., _] = &sequence.exprs[..] {
            for expression in discarded {
                self.discarded(expression);
            }
        }
        sequence.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Some(name) = declarator.name.as_ident() {
            self.declared.insert(name.to_id(), self.function);
            if let Some(Expr::Array(array)) = declarator.init.as_deref() {
                self.create(name.to_id(), array);
            }
        }
        declarator.visit_children_with(self);
    }

    fn visit_expr(&mut self, expression: &Expr) {
        if let Expr::Member(member) = expression {
            self.access(member, /* read= */ true);
        }
        expression.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, assignment: &AssignExpr) {
        if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left {
            self.access(member, assignment.op != AssignOp::Assign);
        }
        assignment.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Callee::Expr(callee) = &call.callee {
            self.opaque(callee);
        }
        call.visit_children_with(self);
    }

    fn visit_tagged_tpl(&mut self, template: &TaggedTpl) {
        self.opaque(&template.tag);
        template.visit_children_with(self);
    }

    fn visit_unary_expr(&mut self, unary: &UnaryExpr) {
        if unary.op == UnaryOp::Delete {
            self.opaque(&unary.arg);
        }
        unary.visit_children_with(self);
    }

    fn visit_function(&mut self, function: &Function) {
        self.in_function(|uses| function.visit_children_with(uses));
    }

    fn visit_arrow_expr(&mut self, arrow: &ArrowExpr) {
        self.in_function(|uses| arrow.visit_children_with(uses));
    }

    fn visit_constructor(&mut self, constructor: &Constructor) {
        self.in_function(|uses| constructor.visit_children_with(uses));
    }

    fn visit_getter_prop(&mut self, getter: &GetterProp) {
        self.in_function(|uses| getter.visit_children_with(uses));
    }

    fn visit_setter_prop(&mut self, setter: &SetterProp) {
        self.in_function(|uses| setter.visit_children_with(uses));
    }

    /// A loop initializer runs once before the loop and discards its value.
    fn visit_for_stmt(&mut self, statement: &ForStmt) {
        if let Some(VarDeclOrExpr::Expr(init)) = &statement.init {
            self.statement(init);
        }
        statement.init.visit_with(self);
        self.in_loop(|uses| {
            statement.test.visit_with(uses);
            statement.update.visit_with(uses);
            statement.body.visit_with(uses);
        });
    }

    fn visit_stmt(&mut self, statement: &Stmt) {
        if matches!(
            statement,
            Stmt::ForIn(_) | Stmt::ForOf(_) | Stmt::While(_) | Stmt::DoWhile(_)
        ) {
            self.in_loop(|uses| statement.visit_children_with(uses));
        } else {
            statement.visit_children_with(self);
        }
    }
}

struct Array {
    /// Replacement local for each slot that is read or initialized with a value.
    locals: Vec<Option<Ident>>,
    read: HashSet<usize>,
    assign_undefined: bool,
}

struct Split<'arrays> {
    arrays: &'arrays HashMap<Id, Array>,
    globals: Globals,
}

impl Split<'_> {
    /// Builds assignments to replacement locals for an array initialization.
    fn initial(&self, array: &Array, literal: &mut ArrayLit) -> Vec<(Ident, Box<Expr>)> {
        let mut assignments = vec![];
        for (local, element) in array.locals.iter().zip(&mut literal.elems) {
            let element = element.take().map(|element| element.expr);
            if let Some(local) = local
                && (array.assign_undefined || !is_undefined(element.as_deref(), self.globals))
            {
                let value = element.unwrap_or_else(|| Box::new(undefined()));
                assignments.push((local.clone(), value));
            }
        }
        assignments
    }

    /// Replaces slot assignment targets in place. Returns a replacement expression for slot reads,
    /// writes to unread slots, and array creation.
    fn replacement(&self, expression: &mut Expr) -> Option<Expr> {
        match expression {
            Expr::Member(member) => {
                let (id, slot) = slot(member)?;
                let local = self.arrays.get(&id)?.locals.get(slot)?.clone()?;
                Some(Expr::Ident(local))
            }
            Expr::Assign(assignment) => {
                if let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assignment.left {
                    let (id, slot) = slot(member)?;
                    let array = self.arrays.get(&id)?;
                    return match &array.locals[slot] {
                        Some(local) if array.read.contains(&slot) => {
                            assignment.left = AssignTarget::Simple(SimpleAssignTarget::Ident(
                                local.clone().into(),
                            ));
                            None
                        }
                        _ => Some(*assignment.right.take()),
                    };
                }
                // The array binding is assigned only when the array is created.
                let array = self.arrays.get(&assignment.left.as_ident()?.to_id())?;
                let Expr::Array(literal) = &mut *assignment.right else {
                    return None;
                };
                let mut assignments: Vec<Box<Expr>> = self
                    .initial(array, literal)
                    .into_iter()
                    .map(|(local, value)| {
                        Box::new(Expr::Assign(AssignExpr {
                            span: DUMMY_SP,
                            op: AssignOp::Assign,
                            left: AssignTarget::Simple(SimpleAssignTarget::Ident(local.into())),
                            right: value,
                        }))
                    })
                    .collect();
                Some(match assignments.len() {
                    0 => undefined(),
                    1 => *assignments.remove(0),
                    _ => Expr::Seq(SeqExpr {
                        span: assignment.span,
                        exprs: assignments,
                    }),
                })
            }
            _ => None,
        }
    }
}

impl VisitMut for Split<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        if let Some(replacement) = self.replacement(expression) {
            *expression = replacement;
        }
    }

    /// Removes `void 0` left by array creations that need no assignments.
    fn visit_mut_stmts(&mut self, statements: &mut Vec<Stmt>) {
        statements.visit_mut_children_with(self);
        removal::remove_expr_stmts(statements, |expression| {
            is_undefined(Some(expression), self.globals)
        });
    }

    fn visit_mut_var_declarators(&mut self, declarators: &mut Vec<VarDeclarator>) {
        declarators.visit_mut_children_with(self);
        let mut split = Vec::with_capacity(declarators.len());
        for mut declarator in declarators.drain(..) {
            let Some(array) = declarator
                .name
                .as_ident()
                .and_then(|name| self.arrays.get(&name.to_id()))
            else {
                split.push(declarator);
                continue;
            };
            let mut initial: HashMap<Id, Box<Expr>> = match declarator.init.as_deref_mut() {
                Some(Expr::Array(literal)) => self
                    .initial(array, literal)
                    .into_iter()
                    .map(|(local, value)| (local.to_id(), value))
                    .collect(),
                _ => HashMap::default(),
            };
            split.extend(array.locals.iter().flatten().map(|local| VarDeclarator {
                span: declarator.span,
                name: Pat::Ident(BindingIdent::from(local.clone())),
                init: initial.remove(&local.to_id()),
                definite: false,
            }));
        }
        *declarators = split;
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    #[test]
    fn splits_arrays_reached_only_through_constant_slots() {
        let transform = |source: &str| testing::rewrite(source, super::run, /* fix= */ true);
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
            &[],
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
        testing::assert_contains(&output, &[], &["h(r_0);", "r_0 = i;"]);
        testing::assert_lacks(&output, &["r_0 = void 0", "["]);
        // A creation in a loop resets the slots on every iteration.
        let output =
            transform("function f() { var r; while (g()) { r = [void 0]; h(r[0]); r[0] = 1; } }");
        testing::assert_contains(&output, &[], &["r_0 = void 0;", "h(r_0);", "r_0 = 1;"]);
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
