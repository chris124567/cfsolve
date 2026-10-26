//! Folds constants along listing paths without executing the program.
//!
//! Registers retain values across instructions; temporaries are local to one path. Resolves
//! constants directly and folds known strings through `JSON.parse` and the decoder in
//! [`DECODER_CELL`]. Known values also eliminate impossible handler paths, such as an
//! incompatible call form for a known receiver; see [`feasible`].
//!
//! Callers use [`Frame::follow`] to process a path's assignments. They can supply values
//! through [`Known::Ext`] and apply their own rules before [`Frame::resolve`]. Callers choose
//! traversal order.

use std::collections::BTreeMap;
use std::convert::Infallible;

use swc_core::ecma::ast::{BinaryOp, UnaryOp};

use crate::js::{JsValue, json};
use crate::vm::dataflow::Facts;
use crate::vm::{Constant, Effect, Path, Term};

/// Cell holding the input payload, later replaced with the output payload.
pub(crate) const PAYLOAD_CELL: u32 = 1;

/// The cell the program keeps its string decoder in.
pub(crate) const DECODER_CELL: u32 = 4;

/// A known register or temporary value. `X` supplies reader-specific values and can be omitted
/// when none are needed.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Known<X = Infallible> {
    /// `undefined`, which [`Known::Literal`] never holds.
    Undefined,
    /// A literal or constant-folded value.
    Literal(JsValue),
    /// A decoded string or JSON parsed from one.
    Decoded(JsValue),
    /// The program's string decoder, as [`DECODER_CELL`] holds it.
    Decoder,
    /// A new object, identified by the instruction that creates it.
    Object(u32),
    Ext(X),
}

impl<X> Known<X> {
    /// A literal string, decoded or not.
    #[must_use]
    pub(crate) fn text(&self) -> Option<&str> {
        match self {
            Self::Literal(value) | Self::Decoded(value) => value.as_str(),
            _ => None,
        }
    }

    /// Treats decoded literals as ordinary literals when their origin is irrelevant to the reader.
    #[must_use]
    pub(crate) fn forget_decoding(self) -> Self {
        match self {
            Self::Decoded(value) => Self::Literal(value),
            known => known,
        }
    }
}

/// Known register values and temporaries for the current path.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Frame<X = Infallible> {
    registers: BTreeMap<u8, Known<X>>,
    temporaries: BTreeMap<usize, Known<X>>,
}

impl<X> Default for Frame<X> {
    fn default() -> Self {
        Self {
            registers: BTreeMap::new(),
            temporaries: BTreeMap::new(),
        }
    }
}

impl<X: Clone> Frame<X> {
    /// Seeds registers with the header's common names (see [`super::Index::header`]).
    #[must_use]
    pub(crate) fn seeded(header: &BTreeMap<u8, String>) -> Self {
        Self {
            registers: header
                .iter()
                .map(|(&register, text)| (register, Known::Literal(json!(text))))
                .collect(),
            temporaries: BTreeMap::new(),
        }
    }

    #[must_use]
    pub(crate) fn register(&self, register: u8) -> Option<&Known<X>> {
        self.registers.get(&register)
    }

    /// Resolves `term` from known registers and temporaries, constants, and the decoder cell.
    #[must_use]
    pub(crate) fn resolve(&self, term: &Term) -> Option<Known<X>> {
        match term {
            Term::Reg(register) => self.registers.get(register).cloned(),
            Term::Temp(temporary) => self.temporaries.get(temporary).cloned(),
            Term::Const(Constant::Undefined) => Some(Known::Undefined),
            Term::Const(Constant::Null) => Some(Known::Literal(JsValue::Null)),
            Term::Const(Constant::Bool(boolean)) => Some(Known::Literal(json!(boolean))),
            Term::Const(Constant::Number(number)) => Some(Known::Literal(json!(number))),
            Term::Const(Constant::String(text)) => Some(Known::Literal(json!(text))),
            Term::Cell(DECODER_CELL) => Some(Known::Decoder),
            _ => None,
        }
    }

    /// Starts a path, clearing previous temporaries while retaining registers.
    pub(crate) fn begin(&mut self) {
        self.temporaries.clear();
    }

    /// Applies `Set(register, value)`. An unknown value invalidates the register's previous value.
    pub(crate) fn set(&mut self, register: u8, value: Option<Known<X>>) {
        match value {
            Some(value) => self.registers.insert(register, value),
            None => self.registers.remove(&register),
        };
    }

    /// Assigns a path-local temporary: `Let(temporary, value)`.
    pub(crate) fn bind(&mut self, temporary: usize, value: Option<Known<X>>) {
        match value {
            Some(value) => self.temporaries.insert(temporary, value),
            None => self.temporaries.remove(&temporary),
        };
    }

    /// Folds a path's `effects` after [`Frame::begin`] starts the instruction at `pc`. Calls
    /// `visit` before each effect with the frame's current state. `Set` and `Let` keep the
    /// value returned by `evaluate`, except that an empty object literal assigned to a register
    /// becomes a new [`Known::Object`] identified by `pc`.
    pub(crate) fn follow(
        &mut self,
        pc: u32,
        effects: &[Effect],
        evaluate: impl Fn(&Self, &Term) -> Option<Known<X>>,
        mut visit: impl FnMut(&Self, &Effect),
    ) {
        for effect in effects {
            visit(self, effect);
            match effect {
                Effect::Set(register, Term::Object(properties)) if properties.is_empty() => {
                    self.set(*register, Some(Known::Object(pc)));
                }
                Effect::Set(register, value) => {
                    let value = evaluate(self, value);
                    self.set(*register, value);
                }
                Effect::Let(temporary, value) => {
                    let value = evaluate(self, value);
                    self.bind(*temporary, value);
                }
                _ => {}
            }
        }
    }
}

/// Intersects register facts from incoming paths. Temporaries do not cross instruction boundaries.
impl<X: Clone + PartialEq> Facts for Frame<X> {
    fn meet(&mut self, other: &Self) -> bool {
        self.registers.meet(&other.registers)
    }
}

/// Decodes the known string `argument` using the program's decoder.
#[must_use]
pub(crate) fn decode<X>(argument: &Known<X>, pool: &str) -> Option<Known<X>> {
    let decoded = super::decode_string(argument.text()?, pool).ok()?;
    Some(Known::Decoded(json!(decoded)))
}

/// Parses a known JSON string and remembers whether the string came from the decoder.
#[must_use]
pub(crate) fn parse<X>(argument: &Known<X>) -> Option<Known<X>> {
    let value: JsValue = serde_json::from_str(argument.text()?).ok()?;
    Some(match argument {
        Known::Decoded(_) => Known::Decoded(value),
        _ => Known::Literal(value),
    })
}

/// Checks whether known values allow a path's conditions to hold. A known receiver determines
/// whether a call handler can take its receiver or receiverless path.
#[must_use]
pub(crate) fn feasible<X>(path: &Path, resolve: impl Fn(&Term) -> Option<Known<X>>) -> bool {
    path.conditions.iter().all(|(condition, expected)| {
        truth(condition, &resolve).is_none_or(|actual| actual == *expected)
    })
}

/// Evaluates a strict comparison with `undefined`, with optional surrounding negations. Other
/// known values count as defined, and comparisons between them stay undecided.
fn truth<X>(condition: &Term, resolve: &impl Fn(&Term) -> Option<Known<X>>) -> Option<bool> {
    match condition {
        Term::Unary(UnaryOp::Bang, inner) => truth(inner, resolve).map(|value| !value),
        Term::Binary(operator @ (BinaryOp::EqEqEq | BinaryOp::NotEqEq), left, right) => {
            let equal = match (resolve(left)?, resolve(right)?) {
                (Known::Undefined, Known::Undefined) => true,
                (Known::Undefined, _) | (_, Known::Undefined) => false,
                _ => return None,
            };
            Some(equal == (*operator == BinaryOp::EqEqEq))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::Exit;

    fn strict(operator: BinaryOp, left: Term, right: Term) -> Term {
        Term::Binary(operator, Box::new(left), Box::new(right))
    }

    #[test]
    fn shared_rules_fold_constants_registers_temporaries_and_the_decoder() {
        let mut frame: Frame = Frame::seeded(&BTreeMap::from([(7, "push".to_owned())]));
        let literal = |value| Some(Known::Literal(value));
        let resolved: [(Term, Option<Known>); 7] = [
            (Term::Reg(7), literal(json!("push"))),
            (Term::Const(Constant::Undefined), Some(Known::Undefined)),
            (Term::Const(Constant::Number(3.0)), literal(json!(3.0))),
            (Term::Const(Constant::Null), literal(JsValue::Null)),
            (Term::Cell(DECODER_CELL), Some(Known::Decoder)),
            (Term::Cell(PAYLOAD_CELL), None),
            (Term::Global("Math".into()), None),
        ];
        for (term, known) in resolved {
            assert_eq!(frame.resolve(&term), known, "{term:?}");
        }

        frame.bind(0, Some(Known::Literal(json!(true))));
        let copied = frame.resolve(&Term::Temp(0));
        frame.set(1, copied);
        frame.begin();
        assert_eq!(
            frame.resolve(&Term::Temp(0)),
            None,
            "a new path has none of the last one's temporaries"
        );
        assert_eq!(
            frame.register(1),
            Some(&Known::Literal(json!(true))),
            "a new path keeps the registers the last one's temporaries were copied into"
        );
        frame.set(7, None);
        assert_eq!(
            frame.resolve(&Term::Reg(7)),
            None,
            "writing something unknown forgets what a register held"
        );
    }

    #[test]
    fn following_a_path_creates_objects_and_shows_each_effect_before_it_applies() {
        let mut frame: Frame = Frame::default();
        let effects = [
            Effect::Set(1, Term::Object(Vec::new())),
            Effect::Let(0, Term::Const(Constant::Number(2.0))),
            Effect::Set(2, Term::Temp(0)),
            Effect::Set(2, Term::Global("Math".into())),
        ];
        let mut seen = Vec::new();
        frame.follow(
            9,
            &effects,
            |frame, term| frame.resolve(term),
            |frame, _| seen.push(frame.register(2).cloned()),
        );
        assert_eq!(frame.register(1), Some(&Known::Object(9)));
        assert_eq!(
            frame.register(2),
            None,
            "an unknown value replaces the last one"
        );
        let two = Some(Known::Literal(json!(2.0)));
        assert_eq!(seen, [None, None, None, two]);
    }

    #[test]
    fn decoder_and_parse_fold_known_strings_and_keep_provenance() {
        let literal: Known = Known::Literal(json!("\0\u{3}abc"));
        assert_eq!(decode(&literal, ""), Some(Known::Decoded(json!("abc"))));
        assert_eq!(decode(&Known::<Infallible>::Literal(json!(1)), ""), None);
        assert_eq!(decode(&Known::<Infallible>::Undefined, ""), None);

        let list: Known = Known::Literal(json!("[1,2]"));
        assert_eq!(parse(&list), Some(Known::Literal(json!([1, 2]))));
        let decoded: Known = Known::Decoded(json!("{\"a\":1}"));
        assert_eq!(parse(&decoded), Some(Known::Decoded(json!({"a": 1}))));
        assert_eq!(parse(&Known::<Infallible>::Literal(json!("{"))), None);

        let x: Known = Known::Decoded(json!("x"));
        assert_eq!(x.text(), Some("x"));
        assert_eq!(x.forget_decoding(), Known::Literal(json!("x")));
    }

    #[test]
    fn feasibility_rules_out_paths_the_equality_decides_against() {
        let mut frame: Frame = Frame::default();
        frame.set(1, Some(Known::Undefined));
        frame.set(2, Some(Known::Decoder));
        frame.set(3, Some(Known::Literal(json!("a"))));
        let undefined = || Term::Const(Constant::Undefined);
        let is_undefined = |register| strict(BinaryOp::EqEqEq, Term::Reg(register), undefined());
        let a = Term::Const(Constant::String("a".into()));
        let same_as_a = Term::Unary(
            UnaryOp::Bang,
            Box::new(strict(BinaryOp::NotEqEq, Term::Reg(3), a)),
        );
        let loose = strict(BinaryOp::EqEq, Term::Reg(1), undefined());
        // A condition, the outcome the path requires, and whether the path stays feasible.
        let cases = [
            // An undefined receiver selects the call without one and rules out the call with one.
            (is_undefined(1), true, true),
            (is_undefined(1), false, false),
            // Every other known value, such as the decoder, is defined.
            (is_undefined(2), true, false),
            // Literals are not compared with each other, even through `!` and `!==`.
            (same_as_a, false, true),
            // Unknown operands and other comparisons decide nothing.
            (is_undefined(9), false, true),
            (loose, false, true),
        ];
        for (condition, expected, feasibility) in cases {
            let path = Path {
                conditions: vec![(condition, expected)],
                effects: Vec::new(),
                exit: Exit::Return,
            };
            assert_eq!(
                feasible(&path, |term| frame.resolve(term)),
                feasibility,
                "{:?}",
                path.conditions
            );
        }
    }
}
