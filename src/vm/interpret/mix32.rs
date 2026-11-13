//! The straight-line integer mixer used for instruction positions and string offsets. Match
//! every operation and recover its constants; leave all other functions to the interpreter.

use std::rc::Rc;

use oxc::ast::ast::{
    AssignmentExpression, AssignmentOperator, AssignmentTarget, BinaryExpression, BindingPattern,
    Expression, Function, Statement, VariableDeclarationKind,
};
use oxc::semantic::SymbolId;
use oxc::syntax::operator::BinaryOperator;

use crate::js;
use crate::js::ast::{self, Script};
use crate::vm::{HashMap, HashSet, extract};

#[derive(Clone, Copy)]
pub(crate) struct Mix32 {
    seed: i32,
    rounds: [Round; 2],
    final_shift: u32,
}

/// `x = (x ^ x >>> shift) * multiplier | 0`.
#[derive(Clone, Copy)]
struct Round {
    shift: u32,
    multiplier: f64,
}

impl Mix32 {
    /// Recognizes `function (x) { x ^= seed; x = (x ^ x >>> s1) * m1 | 0; x = (x ^ x >>>
    /// s2) * m2 | 0; return x ^ x >>> s3; }` however its straight-line statements spell it.
    pub(super) fn recognize(script: Script<'_>, function: &Function<'_>) -> Option<Self> {
        if function.r#async || function.generator {
            return None;
        }
        let [parameter] = extract::parameters(&function.params)?[..] else {
            return None;
        };
        let body = function.body.as_deref()?;
        if !body.directives.is_empty() {
            return None;
        }
        // A declared function would replace the parameter's value when the call starts.
        if body
            .statements
            .iter()
            .any(|statement| matches!(statement, Statement::FunctionDeclaration(_)))
        {
            return None;
        }
        let parameter = parameter.symbol_id();
        let evaluator = Evaluator {
            script,
            values: HashMap::from_iter([(parameter, Rc::new(Term::Parameter))]),
            locals: HashSet::from_iter([parameter]),
        };
        let returned = evaluator.run(&body.statements)?;
        // `x ^ x >>> s3`, with `x` the second round's result.
        let (second, final_shift) = shifted_xor(&returned)?;
        let (first, second) = round(int32(second)?)?;
        let (seeded, first) = round(int32(first)?)?;
        let seed = operands(seeded, BinaryOperator::BitwiseXOR)?
            .into_iter()
            .find_map(|pair| match pair {
                (Term::Parameter, Term::Number(seed)) => Some(*seed),
                _ => None,
            })?;
        Some(Self {
            seed: js::int32(seed),
            rounds: [first, second],
            final_shift,
        })
    }

    pub(super) fn call(self, number: f64) -> f64 {
        let mut value = js::int32(number) ^ self.seed;
        for Round { shift, multiplier } in self.rounds {
            let mixed = value ^ ((value as u32) >> shift) as i32;
            value = js::int32(f64::from(mixed) * multiplier);
        }
        f64::from(value ^ ((value as u32) >> self.final_shift) as i32)
    }
}

/// A pure value computed from the mixer's parameter.
#[derive(Clone, Debug, PartialEq)]
enum Term {
    Parameter,
    Number(f64),
    Binary(BinaryOperator, Rc<Term>, Rc<Term>),
}

/// Evaluates a mixer's straight-line statements to the term it returns. Reads only the parameter
/// and locals it has assigned, and computes only binary operators on numbers, so substituting
/// each local's term where it is read computes the same values.
struct Evaluator<'s> {
    script: Script<'s>,
    values: HashMap<SymbolId, Rc<Term>>,
    /// The parameter and the locals the body declares.
    locals: HashSet<SymbolId>,
}

impl Evaluator<'_> {
    fn run(mut self, statements: &[Statement<'_>]) -> Option<Rc<Term>> {
        // `var` declarations scope their names before anything runs.
        for statement in statements {
            if let Statement::VariableDeclaration(declaration) = statement
                && declaration.kind == VariableDeclarationKind::Var
            {
                for declarator in &declaration.declarations {
                    let BindingPattern::BindingIdentifier(name) = &declarator.id else {
                        return None;
                    };
                    self.locals.insert(name.symbol_id());
                }
            }
        }
        for statement in statements {
            match statement {
                Statement::ReturnStatement(returned) => {
                    return self.term(returned.argument.as_ref()?);
                }
                Statement::EmptyStatement(_) => {}
                Statement::VariableDeclaration(declaration)
                    if declaration.kind == VariableDeclarationKind::Var =>
                {
                    for declarator in &declaration.declarations {
                        if let (BindingPattern::BindingIdentifier(name), Some(init)) =
                            (&declarator.id, &declarator.init)
                        {
                            let value = self.term(init)?;
                            self.values.insert(name.symbol_id(), value);
                        }
                    }
                }
                Statement::ExpressionStatement(expression) => {
                    let Expression::AssignmentExpression(assignment) = &expression.expression
                    else {
                        return None;
                    };
                    let AssignmentTarget::AssignmentTargetIdentifier(name) = &assignment.left
                    else {
                        return None;
                    };
                    let symbol = self.script.symbol(name)?;
                    if !self.locals.contains(&symbol) {
                        return None;
                    }
                    let right = self.term(&assignment.right)?;
                    let value = match assignment.operator.to_binary_operator() {
                        None if assignment.operator == AssignmentOperator::Assign => right,
                        Some(operator) if supported(operator) => {
                            let old = self.values.get(&symbol)?.clone();
                            Rc::new(Term::Binary(operator, old, right))
                        }
                        _ => return None,
                    };
                    self.values.insert(symbol, value);
                }
                _ => return None,
            }
        }
        None
    }

    fn term(&self, expression: &Expression<'_>) -> Option<Rc<Term>> {
        if let Some(number) = number(expression) {
            return Some(Rc::new(Term::Number(number)));
        }
        match expression.without_parentheses() {
            Expression::Identifier(name) => {
                let symbol = self.script.symbol(name)?;
                // A local read before it is assigned holds `undefined`.
                self.values.get(&symbol).cloned()
            }
            Expression::BinaryExpression(binary) if supported(binary.operator) => {
                Some(Rc::new(Term::Binary(
                    binary.operator,
                    self.term(&binary.left)?,
                    self.term(&binary.right)?,
                )))
            }
            _ => None,
        }
    }
}

/// Operators whose results on numbers are numbers.
fn supported(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::BitwiseXOR
            | BinaryOperator::BitwiseOR
            | BinaryOperator::BitwiseAnd
            | BinaryOperator::ShiftLeft
            | BinaryOperator::ShiftRight
            | BinaryOperator::ShiftRightZeroFill
            | BinaryOperator::Addition
            | BinaryOperator::Subtraction
            | BinaryOperator::Multiplication
    )
}

/// The operands of `operator`, in either order.
fn operands(term: &Term, operator: BinaryOperator) -> Option<[(&Term, &Term); 2]> {
    match term {
        Term::Binary(found, left, right) if *found == operator => {
            Some([(&**left, &**right), (&**right, &**left)])
        }
        _ => None,
    }
}

/// `e` of `e <operator> 0` or `0 <operator> e`.
fn with_zero(term: &Term, operator: BinaryOperator) -> Option<&Term> {
    operands(term, operator)?
        .into_iter()
        .find_map(|(value, zero)| matches!(zero, Term::Number(0.0)).then_some(value))
}

/// `e` of a term computing `ToInt32(e)`: `e | 0` or `0 | e`, or `(e ^ 0) + (e & 0)`, which is
/// `ToInt32(e) + 0`. Truncating again changes nothing.
fn int32(term: &Term) -> Option<&Term> {
    let inner = with_zero(term, BinaryOperator::BitwiseOR).or_else(|| {
        operands(term, BinaryOperator::Addition)?
            .into_iter()
            .find_map(|(xor, and)| {
                let xor = with_zero(xor, BinaryOperator::BitwiseXOR)?;
                (Some(xor) == with_zero(and, BinaryOperator::BitwiseAnd)).then_some(xor)
            })
    })?;
    Some(int32(inner).unwrap_or(inner))
}

/// `x` and `s` of `x ^ x >>> s`.
fn shifted_xor(term: &Term) -> Option<(&Term, u32)> {
    operands(term, BinaryOperator::BitwiseXOR)?
        .into_iter()
        .find_map(|(value, shifted)| {
            let Term::Binary(BinaryOperator::ShiftRightZeroFill, shifted, shift) = shifted else {
                return None;
            };
            let Term::Number(shift) = **shift else {
                return None;
            };
            (**shifted == *value).then_some((value, js::int32(shift) as u32 & 31))
        })
}

/// `x` and the round of `(x ^ x >>> shift) * multiplier`, where `x` is an int32: the seeded
/// parameter or a truncated round.
fn round(term: &Term) -> Option<(&Term, Round)> {
    operands(term, BinaryOperator::Multiplication)?
        .into_iter()
        .find_map(|(mixed, multiplier)| {
            let Term::Number(multiplier) = *multiplier else {
                return None;
            };
            let (value, shift) = shifted_xor(mixed)?;
            let int32 = match value {
                Term::Binary(BinaryOperator::BitwiseXOR, ..) => true,
                value => int32(value).is_some(),
            };
            int32.then_some((value, Round { shift, multiplier }))
        })
}

fn number(expression: &Expression<'_>) -> Option<f64> {
    ast::fold_number(expression, &|_| None)
}

/// Whether `expression`, inside any parentheses, is a reference to `symbol`.
pub(super) fn is_symbol(script: Script<'_>, expression: &Expression<'_>, symbol: SymbolId) -> bool {
    script.refers_to(expression.without_parentheses(), symbol)
}

/// The assignment an expression statement makes.
pub(super) fn assignment<'s, 'a>(
    statement: &'s Statement<'a>,
) -> Option<&'s AssignmentExpression<'a>> {
    match statement {
        Statement::ExpressionStatement(statement) => match &statement.expression {
            Expression::AssignmentExpression(assignment) => Some(assignment),
            _ => None,
        },
        _ => None,
    }
}

/// The binary expression inside any parentheses.
pub(super) fn binary<'s, 'a>(expression: &'s Expression<'a>) -> Option<&'s BinaryExpression<'a>> {
    match expression.without_parentheses() {
        Expression::BinaryExpression(binary) => Some(binary),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::interpret::register_helpers::tests::assert_native_matches_interpreted;

    #[test]
    fn native_mixers_match_their_scripts() {
        for source in [
            "function f(x) { x ^= 1265281276; x = (x ^ x >>> 16) * 40503 | 0; x = 13849 * (x ^ x >>> 13) | 0; return x >>> 16 ^ x; }",
            "function f(renamed) { renamed ^= -123; renamed = 0 | 7 * (renamed >>> 3 ^ renamed); renamed = ((renamed ^ renamed >>> 0) * 11) | 0; return renamed ^ renamed >>> 31; }",
            "function f(x) { x ^= 1265281276; x = (x >>> 16 ^ x) * 40503 | 0; x = 0 | 13849 * (x ^ x >>> 13); return x ^ x >>> 16; return; }",
            "function f(x) { var t; x ^= 2067932536; x = 40503 * (x >>> 16 ^ x) | 0; t = (x ^ x >>> 13) * 13849; x = 0 | (t ^ 0) + (t & 0); return x >>> 16 ^ x; }",
            "function f(x) { var t = x ^ -5, u; u = 0 | (t ^ t >>> 7) * 3; x = (u ^ u >>> 9) * 5 | 0 | 0; return x ^ x >>> 2; }",
        ] {
            assert_native_matches_interpreted(source, |script, function| {
                Mix32::recognize(script, function).is_some()
            });
        }
    }
}
