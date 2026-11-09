//! Opcode decoding, run natively.
//!
//! The dispatch loop's fallback unmasks each opcode byte with the dispatch key and a mixer hash
//! of its position, then derives the next key from a polynomial in the key and opcode.
//! Interpreting it for every instruction costs about as much as a small handler.
//!
//! The extracted decoder and its unmask helper must match [`DECODER`] and [`UNMASK`] (see
//! [`super::pattern`]); the helpers they call must be the recognized mixer and register setters,
//! and the hash cache must be a session array or object. Positions the native version does not
//! reproduce exactly are interpreted.

use super::formula::{Formula, Input};
use super::intrinsic::{self, Intrinsic};
use super::mix32::Mix32;
use super::pattern;
use super::register_helpers::Helper;
use crate::js;
use crate::js::ast::Binding;
use crate::vm::dispatch::{Decoded, Decoder};
use crate::vm::extract::Argument;
use crate::vm::session::Session;
use crate::vm::value::Value;

/// The decoding statements of the dispatch loop, as [`crate::vm::dispatch::Dispatch`] extracts
/// them. `PARAMETERS` stands for the loop's parameter names (see [`template_parameters`]).
/// `ACCUMULATE` stands for `key += position;` in builds that add the opcode to the key before
/// computing the next key, and for nothing in builds that compute it from the key directly.
const DECODER: &str = "
function decoder(PARAMETERS) {
    var position, key;
    position = 1 === registers.i ? registers.h ^ registers.state : registers.v;
    if (position !== position) return true;
    if (position < 0 || position >= program.length) throw Error();
    $setpc(registers, position + 1);
    key = 1 === registers.l ? registers.j ^ registers.state : registers.u;
    position = $unmask(key ^ program[position] - $c_offset & 255, key, position);
    ACCUMULATE
    $setkey(registers, $e_next);
    return position;
}";

/// `unmask(value, key, position)`: undoes the position hash and key rotation.
const UNMASK: &str = "
function unmask(value, key, position) {
    var cached;
    cached = $cache[position];
    if (!cached) {
        cached = ($mix(position) & 255) + 1;
        $cache[position] = cached;
    }
    value ^= 255 & (cached - 1 ^ $c_factor * key);
    key &= 7;
    return (value >>> key | value << 8 - key) & 255;
}";

/// A recognized opcode decoder and its constants.
pub(crate) struct NativeDispatch<'ast> {
    mixer: Mix32,
    cache: Binding<'ast>,
    offset: f64,
    factor: f64,
    /// The next key, from `key` and `position`, the opcode.
    next: Formula,
    /// Whether the decoder adds the opcode to `key` before computing the next key.
    accumulates: bool,
}

/// Template parameter names for the loop's `arguments`: one `registers` and one `program`,
/// and distinct names for the rest.
fn template_parameters(arguments: &[Argument]) -> Option<String> {
    let mut names = Vec::with_capacity(arguments.len());
    let (mut registers, mut program) = (0, 0);
    for (index, argument) in arguments.iter().enumerate() {
        names.push(match argument {
            Argument::Registers => {
                registers += 1;
                "registers".to_owned()
            }
            Argument::Program => {
                program += 1;
                "program".to_owned()
            }
            Argument::Machine | Argument::Other => format!("unused{index}"),
        });
    }
    (registers == 1 && program == 1).then(|| names.join(", "))
}

impl<'ast> NativeDispatch<'ast> {
    /// Recognizes `decoder`, called with `arguments`, in `session`.
    pub(crate) fn recognize(
        session: &Session<'ast>,
        decoder: &'ast Decoder<'_>,
        arguments: &[Argument],
    ) -> Option<Self> {
        let parameters = template_parameters(arguments)?;
        let script = session.script;
        let helpers = pattern::binary_helpers(session);
        let matched = |accumulate: &str| {
            let source = DECODER
                .replace("PARAMETERS", &parameters)
                .replace("ACCUMULATE", accumulate);
            let template = pattern::template(&source);
            pattern::matches_routine(
                &template,
                script,
                decoder.function,
                decoder.routine(),
                &helpers,
            )
        };
        let (accumulates, captures) = match matched("key += position;") {
            Some(captures) => (true, captures),
            None => (false, matched("")?),
        };
        // A decoding run starts without overrides, so names resolve to setup bindings, then to
        // functions declared beside the class.
        let function = |binding: Binding<'ast>| {
            if session.bindings.contains_key(&binding) || session.unavailable.contains_key(&binding)
            {
                return None;
            }
            session.function(binding)
        };
        let intrinsic = |binding| {
            let address = intrinsic::address(function(binding)?);
            session.intrinsics.get(&address).copied()
        };
        let Intrinsic::Register(Helper::Pc) = intrinsic(captures.name("$setpc")?)? else {
            return None;
        };
        let Intrinsic::Register(Helper::Key) = intrinsic(captures.name("$setkey")?)? else {
            return None;
        };
        let unmask = function(captures.name("$unmask")?)?;
        let unmask_captures =
            pattern::matches(&pattern::template(UNMASK), script, unmask, &helpers)?;
        // Inlined helpers also resolve as recognized, unless setup left them unavailable.
        let mut inlined = captures.helpers.iter().chain(&unmask_captures.helpers);
        if inlined.any(|binding| session.unavailable.contains_key(binding)) {
            return None;
        }
        let Intrinsic::Mix32(mixer) = intrinsic(unmask_captures.name("$mix")?)? else {
            return None;
        };
        let cache = unmask_captures.name("$cache")?;
        if session.unavailable.contains_key(&cache)
            || !matches!(
                session.bindings.get(&cache),
                Some(Value::Array(_) | Value::Object(_))
            )
        {
            return None;
        }
        Some(Self {
            mixer,
            cache,
            offset: captures.constant("$c_offset")?,
            factor: unmask_captures.constant("$c_factor")?,
            next: captures.formula("$e_next")?,
            accumulates,
        })
    }

    /// Decodes the opcode at `pc` with dispatch key `key`, or returns `None` to interpret it.
    pub(crate) fn decode(
        &self,
        session: &Session<'_>,
        program: &[u8],
        pc: u32,
        key: u8,
    ) -> Option<Decoded> {
        // A run starts with the program counter and key in their registers, which the register
        // model reads back unmasked.
        let position = i32::try_from(pc).ok()?;
        let byte = *program.get(pc as usize)?;
        let key = i32::from(key);
        // An array reads the element; an object, such as a modeled typed array, the property
        // named by the position.
        let entry = match session.bindings.get(&self.cache)? {
            Value::Array(elements) => elements.borrow().get(pc as usize).cloned(),
            Value::Object(properties) => {
                let name = pc.to_string();
                let properties = properties.borrow();
                let property = properties.iter().find(|(key, _)| *key == name);
                property.map(|(_, value)| value.clone())
            }
            _ => return None,
        };
        let cached = match entry {
            Some(Value::Number(number)) if number != 0.0 && !number.is_nan() => number,
            None | Some(Value::Undefined | Value::Null | Value::Number(_)) => {
                f64::from((js::int32(self.mixer.call(f64::from(position))) & 255) + 1)
            }
            Some(_) => return None,
        };
        let mut value = key ^ (js::int32(f64::from(byte) - self.offset) & 255);
        value ^= 255 & (js::int32(cached - 1.0) ^ js::int32(self.factor * f64::from(key)));
        let rotation = key & 7;
        let opcode = (((value as u32) >> rotation) as i32 | value << (8 - rotation)) & 255;
        let key = if self.accumulates {
            f64::from(key) + f64::from(opcode)
        } else {
            f64::from(key)
        };
        let next = self.next.evaluate(&[
            ("key", Input::Number(key)),
            ("position", Input::Number(f64::from(opcode))),
        ])?;
        // The key setter stores signed integers other than -0 as given, and decoding then needs
        // a byte.
        if next.fract() != 0.0 || !(0.0..=255.0).contains(&next) || next.is_sign_negative() {
            return None;
        }
        Some(Decoded {
            opcode: u8::try_from(opcode).ok()?,
            key: next as u8,
        })
    }
}
