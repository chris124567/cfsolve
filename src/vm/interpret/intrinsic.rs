//! Native versions of script functions. Register bookkeeping is recognized structurally;
//! BLAKE3 compression must also agree on test inputs. Calls outside each native version's
//! supported arguments are interpreted.

use std::ptr;

use oxc::ast::ast::{Function, NumericLiteral, ObjectProperty};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::ScopeFlags;

use super::copies::Copies;
use super::mix32::Mix32;
use super::register_helpers::{self, Helper};
use super::run::Run;
use crate::js;
use crate::vm::session::Session;
use crate::vm::value::{Callable, Value};
use crate::vm::{HashMap, extract};

/// A native function equivalent to a script function.
#[derive(Clone, Copy)]
pub(crate) enum Intrinsic {
    /// Bookkeeping on the interpreter's unmasked register file.
    Register(Helper),
    Mix32(Mix32),
    /// `compress(cv, block, counter, length, flags)`: overwrites the 8 words of `cv` with the
    /// BLAKE3 compression of the 16-word `block`.
    Blake3Compress,
}

/// Script functions with native equivalents, by function address.
pub(crate) type Intrinsics = HashMap<usize, Intrinsic>;

/// The address identifying `function` in [`Intrinsics`].
pub(super) fn address(function: &Function<'_>) -> usize {
    ptr::from_ref(function).addr()
}

/// Finds register helpers and mixers, and validates BLAKE3 candidates taking five parameters
/// and mentioning its initialization vector's first word, which some builds store complemented.
pub(crate) fn intrinsics(session: &Session<'_>) -> Intrinsics {
    let mut intrinsics = Intrinsics::default();
    let script = session.script;
    for function in session.functions.values() {
        let intrinsic = if let Some(helper) = register_helpers::recognize(script, function) {
            Intrinsic::Register(helper)
        } else if let Some(mixer) = Mix32::recognize(script, function) {
            Intrinsic::Mix32(mixer)
        } else if extract::parameter_count(&function.params) == 5
            // `~IV[0]` is written as the negation of `IV[0] + 1`.
            && (mentions(function, f64::from(IV[0]))
                || mentions(function, f64::from(IV[0]) + 1.0))
            && compresses_like_native(session, function)
        {
            Intrinsic::Blake3Compress
        } else {
            continue;
        };
        intrinsics.insert(address(function), intrinsic);
    }
    intrinsics
}

impl Intrinsic {
    /// Runs a register helper or mixer natively. Returns `None` for BLAKE3 compression, which
    /// [`blake3_compress`] runs, and for arguments outside what the native version reproduces
    /// exactly, leaving the call to the interpreter.
    pub(super) fn call<'ast>(
        self,
        run: &mut Run<'ast, '_>,
        arguments: &[Value<'ast>],
    ) -> Option<Value<'ast>> {
        let register = match self {
            Self::Mix32(mixer) => {
                let Some(Value::Number(number)) = arguments.first() else {
                    return None;
                };
                return Some(Value::Number(mixer.call(*number)));
            }
            Self::Register(Helper::Number) => {
                return arguments
                    .first()
                    .filter(|value| matches!(value, Value::Number(_)))
                    .cloned();
            }
            Self::Register(Helper::Mask) => {
                return matches!(arguments.first(), Some(Value::Registers))
                    .then_some(Value::Undefined);
            }
            Self::Register(Helper::Pc) => run.session.layout.pc,
            Self::Register(Helper::Key) => run.session.layout.key,
            Self::Blake3Compress => return None,
        };
        let [Value::Registers, value @ Value::Number(number), ..] = arguments else {
            return None;
        };
        // Both setter branches store exactly this value for signed integers other than -0.
        if *number != f64::from(js::int32(*number)) || (*number == 0.0 && number.is_sign_negative())
        {
            return None;
        }
        run.set_register(register, value.clone());
        Some(value.clone())
    }
}

/// Runs [`Intrinsic::Blake3Compress`]. Returns `None` if the arguments are outside what it
/// reproduces exactly, leaving the call to the interpreter.
pub(super) fn blake3_compress<'ast>(arguments: &[Value<'ast>]) -> Option<Value<'ast>> {
    let [
        Value::Array(cv),
        Value::Array(block),
        counter,
        length,
        flags,
    ] = arguments
    else {
        return None;
    };
    let output = {
        let (cv, block) = (cv.borrow(), block.borrow());
        compress(
            &words(cv.get(..8)?)?,
            &words(block.get(..16)?)?,
            Counter::of(counter.as_number()?),
            js::int32(length.as_number()?) as u32,
            js::int32(flags.as_number()?) as u32,
        )
    };
    let mut cv = cv.borrow_mut();
    for (slot, word) in cv.iter_mut().zip(output) {
        // The script stores the results of `^`, which are signed.
        *slot = Value::Number(f64::from(word as i32));
    }
    Some(Value::Undefined)
}

impl Value<'_> {
    fn as_number(&self) -> Option<f64> {
        match self {
            Self::Number(number) => Some(*number),
            _ => None,
        }
    }
}

/// Converts state or message words. The script first adds three words before truncating, which
/// matches wrapping addition only while the sum is exact, so larger or fractional words are
/// rejected.
pub(super) fn words<const N: usize>(values: &[Value<'_>]) -> Option<[u32; N]> {
    let mut words = [0; N];
    for (word, value) in words.iter_mut().zip(values) {
        let number = value.as_number()?;
        if number.fract() != 0.0 || number.abs() >= 2f64.powi(51) {
            return None;
        }
        *word = js::int32(number) as u32;
    }
    Some(words)
}

/// A block counter split as the script splits it: `counter | 0` and
/// `counter / 4294967296 | 0`.
#[derive(Clone, Copy)]
pub(super) struct Counter {
    low: u32,
    high: u32,
}

impl Counter {
    pub(super) fn of(counter: f64) -> Self {
        Self {
            low: js::int32(counter) as u32,
            high: js::int32(counter / 4_294_967_296.0) as u32,
        }
    }
}

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Message word order of each round after the first, relative to the previous round.
const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The BLAKE3 compression function, truncated to the chaining value.
pub(super) fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: Counter,
    length: u32,
    flags: u32,
) -> [u32; 8] {
    let mut state = [0; 16];
    state[..8].copy_from_slice(cv);
    state[8..12].copy_from_slice(&IV[..4]);
    state[12..].copy_from_slice(&[counter.low, counter.high, length, flags]);
    let mut message = *block;
    for round in 0..7 {
        if round > 0 {
            message = PERMUTATION.map(|index| message[index]);
        }
        mix(&mut state, [0, 4, 8, 12], message[0], message[1]);
        mix(&mut state, [1, 5, 9, 13], message[2], message[3]);
        mix(&mut state, [2, 6, 10, 14], message[4], message[5]);
        mix(&mut state, [3, 7, 11, 15], message[6], message[7]);
        mix(&mut state, [0, 5, 10, 15], message[8], message[9]);
        mix(&mut state, [1, 6, 11, 12], message[10], message[11]);
        mix(&mut state, [2, 7, 8, 13], message[12], message[13]);
        mix(&mut state, [3, 4, 9, 14], message[14], message[15]);
    }
    std::array::from_fn(|index| state[index] ^ state[index + 8])
}

/// The BLAKE3 quarter-round `G` on state words `a`, `b`, `c` and `d`.
fn mix(state: &mut [u32; 16], [a, b, c, d]: [usize; 4], x: u32, y: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// Whether `function` contains the numeric literal `number`.
fn mentions(function: &Function<'_>, number: f64) -> bool {
    struct Finder {
        number: f64,
        found: bool,
    }

    impl<'a> Visit<'a> for Finder {
        fn visit_numeric_literal(&mut self, literal: &NumericLiteral<'a>) {
            self.found |= literal.value == self.number;
        }

        /// A numeric key names a property; only computed keys hold values.
        fn visit_object_property(&mut self, property: &ObjectProperty<'a>) {
            if property.computed {
                walk::walk_object_property(self, property);
            } else {
                self.visit_expression(&property.value);
            }
        }
    }

    let mut finder = Finder {
        number,
        found: false,
    };
    finder.visit_function(function, ScopeFlags::Function);
    finder.found
}

/// Whether interpreting `function` gives the result of [`blake3_compress`] on every
/// test input, returning nothing and recording no effects.
fn compresses_like_native<'ast>(session: &Session<'ast>, function: &'ast Function<'ast>) -> bool {
    TEST_INPUTS.iter().all(|input| {
        let native = input.arguments();
        if blake3_compress(&native).is_none() {
            return false;
        }
        // Clones share the arrays, so `interpreted` shows what the script wrote.
        let interpreted = input.arguments();
        let mut run = Run::new(session, &[], Vec::new(), Some(Copies::default()));
        let callable = Callable::Script {
            name: None,
            function,
            scope: None,
        };
        let outcome = run.invoke(&callable, Value::Undefined, interpreted.clone());
        let same = matches!(outcome, Ok(Value::Undefined))
            && run.effects.is_empty()
            && numbers(&interpreted[0]) == numbers(&native[0]);
        for scope in run.scopes() {
            scope.borrow_mut().variables.clear();
        }
        same
    })
}

/// Arguments for [`Intrinsic::Blake3Compress`], covering signed and unsigned words and a counter
/// above 32 bits.
struct TestInput {
    cv: [f64; 8],
    block: [f64; 16],
    counter: f64,
    length: f64,
    flags: f64,
}

const TEST_INPUTS: [TestInput; 2] = [
    TestInput {
        cv: [
            3_144_134_277.0,
            -1_521_486_534.0,
            7.0,
            4_294_967_295.0,
            1_359_893_119.0,
            0.0,
            -1.0,
            2_147_483_648.0,
        ],
        block: [
            1.0,
            2.0,
            3.0,
            255.0,
            65_536.0,
            -2.0,
            1_779_033_703.0,
            3_000_000_000.0,
            12.0,
            -2_147_483_648.0,
            99.0,
            100_000.0,
            31.0,
            4_000_000_000.0,
            5.0,
            6.0,
        ],
        counter: 4_294_967_301.0,
        length: 64.0,
        flags: 11.0,
    },
    TestInput {
        cv: [
            1_779_033_703.0,
            3_144_134_277.0,
            1_013_904_242.0,
            2_773_480_762.0,
            1_359_893_119.0,
            2_600_822_924.0,
            528_734_635.0,
            1_541_459_225.0,
        ],
        block: [
            827_605_328.0,
            17.0,
            0.0,
            0.0,
            -5.0,
            0.0,
            0.0,
            1_234.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        ],
        counter: 3.0,
        length: 13.0,
        flags: 1.0,
    },
];

impl TestInput {
    fn arguments<'ast>(&self) -> Vec<Value<'ast>> {
        let array =
            |numbers: &[f64]| Value::array(numbers.iter().copied().map(Value::Number).collect());
        vec![
            array(&self.cv),
            array(&self.block),
            Value::Number(self.counter),
            Value::Number(self.length),
            Value::Number(self.flags),
        ]
    }
}

fn numbers(value: &Value<'_>) -> Option<Vec<f64>> {
    let Value::Array(elements) = value else {
        return None;
    };
    elements.borrow().iter().map(Value::as_number).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLAKE3 of the empty input is one compression of an empty block with the chunk-start,
    /// chunk-end and root flags.
    #[test]
    fn compresses_like_blake3() {
        let digest = compress(&IV, &[0; 16], Counter::of(0.0), 0, 1 | 2 | 8);
        let bytes: Vec<u8> = digest.iter().flat_map(|word| word.to_le_bytes()).collect();
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn rejects_inexact_words() {
        let mut arguments = TEST_INPUTS[0].arguments();
        arguments[1] = Value::array(vec![Value::Number(0.5); 16]);
        assert!(blake3_compress(&arguments).is_none());
    }
}
