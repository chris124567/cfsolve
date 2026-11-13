//! Recognizes the register file's accessors and register bookkeeping that is redundant in the
//! interpreter's unmasked model. Recognition checks the whole body; calls with ordinary
//! JavaScript objects still interpret it.

use std::ptr;

use oxc::ast::ast::{
    Argument, ArrowFunctionExpression, AssignmentOperator, AssignmentTarget, BindingPattern,
    Expression, Function, FunctionBody, IdentifierReference, IfStatement, MemberExpression,
    ReturnStatement, Statement, UnaryOperator,
};
use oxc::ast_visit::Visit;
use oxc::semantic::{ScopeFlags, SymbolId};
use oxc::syntax::operator::BinaryOperator;

use super::mix32;
use crate::js::ast::{self, Script};
use crate::vm::HashSet;
use crate::vm::extract::{self, Accessors};
use crate::vm::registers::Member;

#[derive(Clone, Copy)]
pub(crate) enum Helper {
    Mask,
    Pc,
    Key,
    Number,
    /// `read(registers, index)`: the register's value.
    Read,
    /// `write(registers, index, value)`: stores the value and returns nothing.
    Write,
}

/// Recognizes a register helper. With `accessors`, also recognizes the register file's reader and
/// writer, and the wrappers that differ from them only in ways the interpreter's model does not
/// represent:
///
/// - `save(registers, index)` returns a string record's stored form instead of decrypting it:
///   `if (<tag> === registers.<tags>[index]) return registers.<values>[index]; else return
///   read(registers, index);`. The model stores records decrypted, so both branches read the
///   same value.
/// - `restore(registers, index, value)` restores closures through a separate function:
///   `if (<closure test>) <restore>(registers, index, value); else write(registers, index,
///   value);`. The model stores closures as values.
pub(super) fn recognize(
    script: Script<'_>,
    accessors: Option<Accessors<'_>>,
    function: &Function<'_>,
) -> Option<Helper> {
    if function.r#async || function.generator {
        return None;
    }
    let body = function.body.as_deref()?;
    if !body.directives.is_empty() {
        return None;
    }
    if let Some(accessors) = accessors {
        if ptr::eq(function, accessors.read) {
            return Some(Helper::Read);
        }
        if ptr::eq(function, accessors.write) && returns_nothing(body) {
            return Some(Helper::Write);
        }
    }
    let parameters: Vec<SymbolId> = extract::parameters(&function.params)?
        .into_iter()
        .map(|parameter| parameter.symbol_id())
        .collect();
    let recognizer = Recognizer { script };
    if let Some(accessors) = accessors
        && let [Statement::IfStatement(branch)] = &body.statements[..]
        && let Some(helper) = recognizer.wrapper(accessors, branch, &parameters)
    {
        return Some(helper);
    }
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
    /// Recognizes the reader and writer wrappers that [`recognize`] describes.
    fn wrapper(
        &self,
        accessors: Accessors<'_>,
        branch: &IfStatement<'_>,
        parameters: &[SymbolId],
    ) -> Option<Helper> {
        let script = self.script;
        let alternate = branch.alternate.as_ref()?;
        // The callee `statement` passes the parameters to unchanged.
        let forwarded = |statement: &Statement<'_>, returned: bool| {
            let (callee, arguments) = call_statement(only(statement), returned)?;
            let unchanged = arguments.len() == parameters.len()
                && arguments
                    .iter()
                    .zip(parameters)
                    .all(|(argument, parameter)| {
                        (argument.as_expression())
                            .is_some_and(|argument| script.refers_to(argument, *parameter))
                    });
            unchanged.then(|| script.symbol(callee))
        };
        let symbol = |function: &Function<'_>| Some(function.id.as_ref().map(|id| id.symbol_id()));
        match *parameters {
            [registers, index] => {
                let slot = |expression: &Expression<'_>, member| {
                    let Some(MemberExpression::ComputedMemberExpression(element)) =
                        expression.without_parentheses().as_member_expression()
                    else {
                        return false;
                    };
                    script.refers_to(&element.expression, index)
                        && element
                            .object
                            .as_member_expression()
                            .is_some_and(|slots| self.member(slots, registers) == Some(member))
                };
                let Expression::BinaryExpression(test) = branch.test.without_parentheses() else {
                    return None;
                };
                let tagged = test.operator == BinaryOperator::StrictEquality
                    && ((ast::number(&test.left).is_some() && slot(&test.right, Member::Tags))
                        || (slot(&test.left, Member::Tags) && ast::number(&test.right).is_some()));
                let Statement::ReturnStatement(stored) = only(&branch.consequent) else {
                    return None;
                };
                let stored = stored
                    .argument
                    .as_ref()
                    .is_some_and(|stored| slot(stored, Member::Values));
                let reads = forwarded(alternate, true) == symbol(accessors.read);
                (tagged && stored && reads).then_some(Helper::Read)
            }
            [_, _, _] => (forwarded(&branch.consequent, false).is_some()
                && forwarded(alternate, false) == symbol(accessors.write))
            .then_some(Helper::Write),
            _ => None,
        }
    }

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

/// The statement a block of one statement holds, or else `statement`.
fn only<'b, 'a>(statement: &'b Statement<'a>) -> &'b Statement<'a> {
    match statement {
        Statement::BlockStatement(block) if let [statement] = &block.body[..] => only(statement),
        statement => statement,
    }
}

/// Matches `<callee>(<arguments>);`, or `return <callee>(<arguments>);` if `returned`.
fn call_statement<'b, 'a>(
    statement: &'b Statement<'a>,
    returned: bool,
) -> Option<(&'b IdentifierReference<'a>, &'b [Argument<'a>])> {
    let expression = match statement {
        Statement::ExpressionStatement(statement) if !returned => &statement.expression,
        Statement::ReturnStatement(statement) if returned => statement.argument.as_ref()?,
        _ => return None,
    };
    ast::direct_call(expression.without_parentheses())
}

/// Whether every return in `body`, outside nested functions, returns nothing.
fn returns_nothing(body: &FunctionBody<'_>) -> bool {
    struct Returns(bool);

    impl<'a> Visit<'a> for Returns {
        fn visit_return_statement(&mut self, statement: &ReturnStatement<'a>) {
            self.0 |= statement.argument.is_some();
        }

        fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

        fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {}
    }

    let mut returns = Returns(false);
    returns.visit_function_body(body);
    !returns.0
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
            "function f(a,b) { var x,y; x = a.L ^ (b & 65535); y = x * 403; if (a.j === 1) { a.i ^= y; } if (1 === a.m) { a.l ^= y; } a.h = x; a.L = y; }",
            "function f(a,b) { if (typeof b === 'number' && (b | 0) === b && (b !== 0 || 1/b > 0)) { a.j=1; a.i=b^a.h; } else { a.j=0; a.A=b; } return b; }",
            "function f(a,b) { if ('number' === typeof b && b === (0 | b) && (b !== 0 || 1/b > 0)) { a.m=1; a.l=a.h^b; } else { a.m=0; a.v=b; } return b; }",
            "function f(b) { if (typeof b !== 'number') throw new TypeError; return b; }",
        ] {
            assert_native_matches_interpreted(source, |script, function| {
                recognize(script, None, function).is_some()
            });
        }
    }

    /// The run function names the reader and writer. Wrappers are accessors only if they forward
    /// to them unchanged.
    #[test]
    fn recognizes_accessors_and_their_wrappers() {
        let source = "function read(r,i) { return r.H[i]; }\
            function write(r,i,v) { if (i === r.D) pc(r,v); else r.H[i] = v; }\
            function save(r,i) { if (-4 === r.J[i]) { return r.H[i]; } else { return read(r,i); } }\
            function restore(r,i,v) { if (typeof v === 'object' && has(v)) { closure(r,i,v); } else { write(r,i,v); } }\
            function swapped(r,i) { if (-4 === r.J[i]) { return r.H[i]; } else { return read(i,r); } }\
            function other(r,i) { if (-4 === r.J[i]) { return r.J[i]; } else { return read(r,i); } }\
            function sideways(r,i,v) { if (v) { closure(r,i,v); } else { write(r,v,i); } }\
            function returning(r,i,v) { write(r,i,v); return v; }";
        let parsed = ParsedScript::parse("t", source).unwrap();
        let script = parsed.script();
        let session = Session::empty(script);
        let accessors = Accessors {
            read: session.declared("read"),
            write: session.declared("write"),
        };
        let recognized =
            |name: &str| match recognize(script, Some(accessors), session.declared(name)) {
                Some(Helper::Read) => "read",
                Some(Helper::Write) => "write",
                Some(_) => "other",
                None => "none",
            };
        for (name, expected) in [
            ("read", "read"),
            ("write", "write"),
            ("save", "read"),
            ("restore", "write"),
            ("swapped", "none"),
            ("other", "none"),
            ("sideways", "none"),
            ("returning", "none"),
        ] {
            assert_eq!(recognized(name), expected, "{name}");
        }
        let returns = Accessors {
            write: session.declared("returning"),
            ..accessors
        };
        assert!(
            recognize(script, Some(returns), session.declared("returning")).is_none(),
            "a writer that returns a value is not the native writer"
        );
    }

    /// Writing through the native writer returns nothing, and reading returns what it stored.
    #[test]
    fn native_accessors_access_registers() {
        let source = "function read(r,i) { return r.H[i]; }\
            function write(r,i,v) { if (typeof v === 'number') r.H[i] = v; }";
        let parsed = ParsedScript::parse("t", source).unwrap();
        let script = parsed.script();
        let mut session = Session::empty(script);
        session.accessors = Some(Accessors {
            read: session.declared("read"),
            write: session.declared("write"),
        });
        session.intrinsics = intrinsics(&session);
        let mut run = Run::method(&session);
        let function = |name| Callable::Script {
            name: None,
            function: session.declared(name),
            scope: None,
        };
        let symbolic = Value::symbolic(Term::Reg(7));
        let arguments = vec![Value::Registers, Value::Number(5.0), symbolic.clone()];
        let written = run.invoke(&function("write"), Value::Undefined, arguments);
        assert_eq!(
            written.ok().map(|value| value.expr()),
            Some(Value::Undefined.expr())
        );
        let arguments = vec![Value::Registers, Value::Number(5.0)];
        let read = run.invoke(&function("read"), Value::Undefined, arguments);
        assert_eq!(read.ok().map(|value| value.expr()), Some(symbolic.expr()));
    }

    #[test]
    fn observable_work_is_never_skipped() {
        for source in [
            "function f(a,b) { a.h = sideEffect(b); }",
            "function f(a,b) { a.i = b; }",
            "function f(a,b) { a.h = b; return b; }",
            "function f(a,b) { if (b) a.h = 0; }",
            "function f(a,b) { a.other = b; }",
            "function f(a,b) { b.x = 1; }",
            "function f(a,b) { a.i ||= b; }",
        ] {
            let parsed = ParsedScript::parse("t", source).expect("test sources parse");
            let script = parsed.script();
            for function in extract::functions(&script.program.body).values() {
                assert!(recognize(script, None, function).is_none(), "{source}");
            }
        }
    }
}
