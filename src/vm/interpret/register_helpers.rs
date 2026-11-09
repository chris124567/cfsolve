//! Recognizes register bookkeeping that is redundant in the interpreter's unmasked model.
//! Recognition checks the whole body; calls with ordinary JavaScript objects still interpret it.

use oxc::ast::ast::{
    AssignmentOperator, AssignmentTarget, BindingPattern, Expression, Function, MemberExpression,
    Statement, UnaryOperator,
};
use oxc::semantic::SymbolId;
use oxc::syntax::operator::BinaryOperator;

use super::mix32;
use crate::js::ast::{self, Script};
use crate::vm::registers::Member;
use crate::vm::{HashSet, extract};

#[derive(Clone, Copy)]
pub(crate) enum Helper {
    Mask,
    Pc,
    Key,
    Number,
}

pub(super) fn recognize(script: Script<'_>, function: &Function<'_>) -> Option<Helper> {
    if function.r#async || function.generator {
        return None;
    }
    let parameters: Vec<SymbolId> = extract::parameters(&function.params)?
        .into_iter()
        .map(|parameter| parameter.symbol_id())
        .collect();
    let body = function.body.as_deref()?;
    if !body.directives.is_empty() {
        return None;
    }
    let recognizer = Recognizer { script };
    let body = &body.statements;
    if let [value] = parameters[..]
        && let [
            Statement::IfStatement(check),
            Statement::ReturnStatement(returned),
        ] = &body[..]
        && recognizer.returns(returned.argument.as_ref(), value)
        && let Some(test) = mix32::binary(&check.test)
        && matches!(
            test.operator,
            BinaryOperator::StrictInequality | BinaryOperator::Inequality
        )
        && let Expression::UnaryExpression(kind) = test.left.without_parentheses()
        && kind.operator == UnaryOperator::Typeof
        && mix32::is_symbol(script, &kind.argument, value)
        && matches!(test.right.without_parentheses(),
            Expression::StringLiteral(text) if text.value == "number")
        && matches!(check.consequent, Statement::ThrowStatement(_))
        && check.alternate.is_none()
    {
        return Some(Helper::Number);
    }
    let [object, value] = parameters[..] else {
        return None;
    };
    if object == value {
        return None;
    }
    if let [
        Statement::IfStatement(branch),
        Statement::ReturnStatement(returned),
    ] = &body[..]
        && recognizer.returns(returned.argument.as_ref(), value)
        && recognizer.guard(&branch.test, &HashSet::from_iter([value]))
        && let Some(other) = &branch.alternate
        && let Some(first) = recognizer.setter(&branch.consequent, object, value)
        && let Some(second) = recognizer.setter(other, object, value)
        && first == second
    {
        return Some(match first {
            Member::Pc => Helper::Pc,
            _ => Helper::Key,
        });
    }
    let mut locals = HashSet::from_iter([value]);
    let is_noop = body
        .iter()
        .all(|statement| recognizer.noop(statement, object, &mut locals));
    is_noop.then_some(Helper::Mask)
}

fn constant(member: Member) -> bool {
    matches!(
        member,
        Member::Mask | Member::Integer | Member::PcIndex | Member::KeyIndex
    )
}

/// Resolves the helper's references in the script declaring it.
struct Recognizer<'s> {
    script: Script<'s>,
}

impl Recognizer<'_> {
    fn returns(&self, returned: Option<&Expression<'_>>, value: SymbolId) -> bool {
        returned.is_some_and(|returned| mix32::is_symbol(self.script, returned, value))
    }

    fn member(&self, member: &MemberExpression<'_>, object: SymbolId) -> Option<Member> {
        if !mix32::is_symbol(self.script, member.object(), object) {
            return None;
        }
        Member::of(ast::member_str(member)?)
    }

    fn target_member(&self, target: &AssignmentTarget<'_>, object: SymbolId) -> Option<Member> {
        self.member(target.as_member_expression()?, object)
    }

    fn guard(&self, expression: &Expression<'_>, locals: &HashSet<SymbolId>) -> bool {
        if let Expression::LogicalExpression(logical) = expression.without_parentheses() {
            return self.guard(&logical.left, locals) && self.guard(&logical.right, locals);
        }
        self.pure(expression, locals, None)
    }

    /// Expressions with no calls, property coercions, assignments, or symbolic control flow.
    fn pure(
        &self,
        expression: &Expression<'_>,
        locals: &HashSet<SymbolId>,
        object: Option<SymbolId>,
    ) -> bool {
        match expression.without_parentheses() {
            Expression::Identifier(name) => self
                .script
                .symbol(name)
                .is_some_and(|symbol| locals.contains(&symbol)),
            Expression::NumericLiteral(_)
            | Expression::StringLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_) => true,
            Expression::BinaryExpression(binary)
                if !matches!(
                    binary.operator,
                    BinaryOperator::In | BinaryOperator::Instanceof
                ) =>
            {
                self.pure(&binary.left, locals, object) && self.pure(&binary.right, locals, object)
            }
            Expression::UnaryExpression(unary) if unary.operator != UnaryOperator::Delete => {
                self.pure(&unary.argument, locals, object)
            }
            expression => match expression.as_member_expression() {
                Some(read) => object
                    .and_then(|object| self.member(read, object))
                    .is_some_and(constant),
                None => false,
            },
        }
    }

    /// Both branches of a counter/key setter store the same integer in the unmasked model.
    fn setter(
        &self,
        statement: &Statement<'_>,
        object: SymbolId,
        value: SymbolId,
    ) -> Option<Member> {
        let Statement::BlockStatement(block) = statement else {
            return None;
        };
        let [flag, stored] = &block.body[..] else {
            return None;
        };
        let flag = mix32::assignment(flag)?;
        if flag.operator != AssignmentOperator::Assign
            || self.target_member(&flag.left, object)? != Member::Integer
            || !matches!(
                flag.right.without_parentheses(),
                Expression::NumericLiteral(_)
            )
        {
            return None;
        }
        let stored = mix32::assignment(stored)?;
        if stored.operator != AssignmentOperator::Assign {
            return None;
        }
        let target = match self.target_member(&stored.left, object)? {
            Member::Pc | Member::OtherPc => Member::Pc,
            Member::Key | Member::OtherKey => Member::Key,
            _ => return None,
        };
        if mix32::is_symbol(self.script, &stored.right, value) {
            return Some(target);
        }
        let binary = mix32::binary(&stored.right)?;
        let mask = |expression: &Expression<'_>| {
            let read = expression.without_parentheses().as_member_expression();
            read.and_then(|read| self.member(read, object)) == Some(Member::Mask)
        };
        let is_value =
            |expression: &Expression<'_>| mix32::is_symbol(self.script, expression, value);
        let masked = (is_value(&binary.left) && mask(&binary.right))
            || (mask(&binary.left) && is_value(&binary.right));
        (binary.operator == BinaryOperator::BitwiseXOR && masked).then_some(target)
    }

    fn noop(
        &self,
        statement: &Statement<'_>,
        object: SymbolId,
        locals: &mut HashSet<SymbolId>,
    ) -> bool {
        match statement {
            Statement::EmptyStatement(_) => true,
            Statement::VariableDeclaration(declaration) if !declaration.kind.is_using() => {
                declaration.declarations.iter().all(|declarator| {
                    let BindingPattern::BindingIdentifier(name) = &declarator.id else {
                        return false;
                    };
                    let name = name.symbol_id();
                    let initialized = declarator.init.as_ref();
                    if name == object
                        || !initialized.is_none_or(|init| self.pure(init, locals, Some(object)))
                    {
                        return false;
                    }
                    locals.insert(name);
                    true
                })
            }
            Statement::ExpressionStatement(_) => {
                let Some(assignment) = mix32::assignment(statement) else {
                    return false;
                };
                if assignment.operator.is_logical() {
                    return false;
                }
                let target = match &assignment.left {
                    AssignmentTarget::AssignmentTargetIdentifier(local) => self
                        .script
                        .symbol(local)
                        .is_some_and(|symbol| locals.contains(&symbol)),
                    left => self.target_member(left, object).is_some_and(|field| {
                        constant(field)
                            || (assignment.operator != AssignmentOperator::Assign
                                && matches!(field, Member::Pc | Member::Key))
                    }),
                };
                target && self.pure(&assignment.right, locals, Some(object))
            }
            Statement::BlockStatement(block) => block
                .body
                .iter()
                .all(|statement| self.noop(statement, object, locals)),
            Statement::IfStatement(branch) => {
                self.pure(&branch.test, &HashSet::default(), Some(object))
                    && self.noop(&branch.consequent, object, locals)
                    && branch
                        .alternate
                        .as_ref()
                        .is_none_or(|other| self.noop(other, object, locals))
            }
            Statement::ReturnStatement(returned) => returned.argument.is_none(),
            _ => false,
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::js::ast::ParsedScript;
    use crate::vm::Term;
    use crate::vm::interpret::{Run, intrinsics};
    use crate::vm::session::{Layout, Session};
    use crate::vm::value::{Callable, Value};

    /// Asserts that `recognized` accepts the function `source` declares, and that calling it on
    /// assorted values, after a register object if it takes two parameters, has the same
    /// outcome with and without native versions.
    pub(in crate::vm::interpret) fn assert_native_matches_interpreted(
        source: &str,
        recognized: fn(Script<'_>, &Function<'_>) -> bool,
    ) {
        let parsed = ParsedScript::parse("t", source).expect("test sources parse");
        let script = parsed.script();
        let functions = extract::functions(&script.program.body);
        let function = *functions.values().next().expect("one function");
        assert!(recognized(script, function), "{source}");
        let mut numbers = vec![
            0.0,
            -0.0,
            1.0,
            -1.0,
            2147483647.0,
            4294967297.0,
            -2147483649.0,
            0.25,
            0.5,
            1e30,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        let mut state = 42u32;
        for _ in 0..256 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            numbers.push(f64::from(state));
        }
        let values = numbers.into_iter().map(Value::Number);
        let values = values.chain([
            Value::symbolic(Term::Reg(7)),
            Value::string("x"),
            Value::string("12"),
        ]);
        for value in values {
            let execute = |native| {
                let mut session = Session::empty(script);
                session.layout = Layout {
                    pc: 240,
                    key: 241,
                    ..Layout::default()
                };
                if native {
                    session.intrinsics = intrinsics(&session);
                }
                let mut run = Run::method(&session);
                run.start_at(42, 17);
                let arguments = if extract::parameter_count(&function.params) == 1 {
                    vec![value.clone()]
                } else {
                    vec![Value::Registers, value.clone()]
                };
                let callable = Callable::Script {
                    name: None,
                    function,
                    scope: None,
                };
                let result = run.invoke(&callable, Value::Undefined, arguments);
                let returned = result.as_ref().map(Value::expr).ok();
                let mut registers: Vec<_> = run
                    .registers
                    .iter()
                    .map(|(key, value)| (*key, format!("{:?}", value.expr())))
                    .collect();
                registers.sort();
                format!("{returned:?} {registers:?} {:?}", run.finish(result))
            };
            assert_eq!(execute(true), execute(false), "{source}");
        }
    }

    #[test]
    fn native_bookkeeping_matches_interpretation() {
        for source in [
            "function f(a,b) { var x,y; x = a.J ^ (b & 65535); y = x * 403; if (a.i === 1) { a.h ^= y; } if (1 === a.l) { a.j ^= y; } a.state = x; a.J = y; }",
            "function f(a,b) { if (typeof b === 'number' && (b | 0) === b && (b !== 0 || 1/b > 0)) { a.i=1; a.h=b^a.state; } else { a.i=0; a.v=b; } return b; }",
            "function f(a,b) { if ('number' === typeof b && b === (0 | b) && (b !== 0 || 1/b > 0)) { a.l=1; a.j=a.state^b; } else { a.l=0; a.u=b; } return b; }",
            "function f(b) { if (typeof b !== 'number') throw new TypeError; return b; }",
        ] {
            assert_native_matches_interpreted(source, |script, function| {
                recognize(script, function).is_some()
            });
        }
    }

    #[test]
    fn observable_work_is_never_skipped() {
        for source in [
            "function f(a,b) { a.state = sideEffect(b); }",
            "function f(a,b) { a.h = b; }",
            "function f(a,b) { a.state = b; return b; }",
            "function f(a,b) { if (b) a.state = 0; }",
            "function f(a,b) { a.other = b; }",
            "function f(a,b) { b.x = 1; }",
            "function f(a,b) { a.h ||= b; }",
        ] {
            let parsed = ParsedScript::parse("t", source).expect("test sources parse");
            let script = parsed.script();
            for function in extract::functions(&script.program.body).values() {
                assert!(recognize(script, function).is_none(), "{source}");
            }
        }
    }
}
