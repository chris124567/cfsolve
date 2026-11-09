//! The program string decoder, run natively.
//!
//! Each encrypted string record names its bytes in the program and a key. The decoder derives a
//! record key with BLAKE3, checks a keyed BLAKE3 MAC of the ciphertext, and XORs the ciphertext
//! with a BLAKE3 keystream. Interpreting it dominates string decryption, which every handler run
//! that loads a string constant needs.
//!
//! The decoder, its MAC and keystream functions must match [`DECODER`], [`MAC`] and
//! [`KEYSTREAM`] (see [`super::pattern`]), the functions they call must be the recognized
//! mixer and BLAKE3 compression intrinsics, and the session values they read must be the
//! character table, `Array`, and bound `charCodeAt` and `repeat` they are in known builds.
//! Each call also resolves every binding as the interpreter would. Records outside what the native
//! version reproduces exactly, including every record the script would reject, are interpreted.

use std::collections::BTreeSet;
use std::ptr;

use oxc::ast::ast::Function;

use super::builtin::Builtin;
use super::formula::{Formula, Input};
use super::intrinsic::{self, Counter, Intrinsic};
use super::mix32::Mix32;
use super::pattern;
use super::run::Run;
use crate::js;
use crate::js::ast::Binding;
use crate::vm::convert;
use crate::vm::session::Session;
use crate::vm::value::{Callable, JsString, Value};

/// `decoder(record)`: `record` is `[program, offset, length, b3, b4, key]`.
const DECODER: &str = "
function decoder(record) {
    var bytes, offset, length, key, seed, block, count, text, keystream, index, value;
    bytes = record[0];
    offset = record[1];
    length = record[2];
    key = record[5];
    seed = $mix(offset);
    block = [$c_block, offset, length, 0, 0, 0, 0, record[4] << 8 | record[3], 0, 0, 0, 0, 0, 0, 0, 0];
    count = 0;
    for (; count < 16; count++) {
        block[3 + (count >>> 2)] |= read(count) << 8 * (count & 3);
    }
    count = read(16) << 8 | read(17);
    if (count > length) throw Error();
    key = [key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]];
    $compress(key, block, 0, 32, 27);
    block = new $array(count);
    text = ``;
    index = 0;
    for (; index < 4; index++) {
        text += $table[255 & key[0] >>> index * 8];
    }
    index = 0;
    for (; index < count; index++) {
        value = read(18 + index);
        block[index] = value;
        text += $table[value];
    }
    index = 8 + 2 * text.length;
    text = $mac(text, index, 0, ((index - 1) / 1024 | 0) + 1, true, key, true);
    index = 0;
    value = 0;
    for (; value < 16; value++) {
        index |= read(18 + length + value) ^ text[value >>> 2] >>> 8 * (value & 3) & 255;
    }
    if (index) throw Error();
    text = ``;
    index = 0;
    for (; index < count; index++) {
        if ((31 & index) === 0) {
            keystream = $keystream(key, index >>> 5);
        }
        text += $table[block[index] ^ keystream[index >>> 2 & 7] >>> (index & 3) * 8 & 255];
    }
    return text + $repeat(`\\0`, length - count);
    function read(position) {
        var mixed;
        mixed = seed + 2654435769 * position | 0;
        return $e_read;
    }
}";

/// `mac(text, length, chunk, chunks, root, key, keyed)`: the keyed BLAKE3 hash of `length`
/// bytes, eight zero bytes then `text` as UTF-16BE, starting at 1024-byte chunk `chunk`.
const MAC: &str = "
function mac(text, length, chunk, chunks, root, key, keyed) {
    var left, flags;
    var state;
    state = key ? [key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]] : [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225];
    flags = key ? 16 : 0;
    if (chunks > 1) {
        var half;
        half = 1;
        for (; 2 * half < chunks; half *= 2);
        left = $self(text, length, chunk, half, false, key, keyed);
        text = $self(text, length, chunk + half, chunks - half, false, key, keyed);
        $compress(state, [left[0], left[1], left[2], left[3], left[4], left[5], left[6], left[7], text[0], text[1], text[2], text[3], text[4], text[5], text[6], text[7]], 0, 64, (root ? 8 : 0) | (flags | 4));
        return state;
    }
    left = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    chunks = chunk * 1024;
    length = chunks + 1024 < length ? chunks + 1024 : length;
    key = chunks;
    for (; key < length; key += 64) {
        half = 0;
        for (; half < 16; half++) {
            let position = key / 2 + 2 * half - 4, word = 0;
            if (position < 0) {
                word = keyed ? 0 : half === 0 ? $c_prefix0 : $c_prefix1;
            } else {
                if (position < text.length) {
                    word = $code(text, position) << 16 | (position + 1 < text.length ? $code(text, position + 1) : 0);
                }
            }
            left[half] = (word & 255) << 24 | (word & 65280) << 8 | word >>> 8 & 65280 | word >>> 24;
        }
        half = key + 64 >= length;
        $compress(state, left, chunk, half ? length - key : 64, flags | (chunks === key ? 1 : 0) | (half ? 2 : 0) | (half && root ? 8 : 0));
    }
    return state;
}";

/// `keystream(key, counter)`: one 32-byte keystream block.
const KEYSTREAM: &str = "
function keystream(key, counter) {
    key = [key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]];
    $compress(key, [$c_stream, counter, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, 8, 27);
    return key;
}";

/// A recognized decoder: the bindings it reads, the functions they must resolve to, and its
/// constants.
pub(crate) struct StringDecoder<'ast> {
    mixer: Mix32,
    /// Bindings resolving to script functions: the decoder's callees and the binary helpers
    /// declared beside the class that its match inlined.
    functions: Vec<NamedFunction<'ast>>,
    /// Inlined binary helpers that are session bindings.
    bound_helpers: Vec<NamedFunction<'ast>>,
    table: Binding<'ast>,
    array: Binding<'ast>,
    repeat: Binding<'ast>,
    code: Binding<'ast>,
    block: f64,
    /// A program byte's value, from `bytes`, `offset`, `position`, `record` and `mixed`.
    read: Formula,
    stream: f64,
}

struct NamedFunction<'ast> {
    binding: Binding<'ast>,
    function: &'ast Function<'ast>,
}

impl<'ast> StringDecoder<'ast> {
    /// Recognizes the session's record decoder.
    pub(crate) fn recognize(session: &Session<'ast>) -> Option<Self> {
        let decoder = session.record_decoder?;
        let script = session.script;
        let helpers = pattern::binary_helpers(session);
        let captures = pattern::matches(&pattern::template(DECODER), script, decoder, &helpers)?;
        // Functions resolve through bindings first.
        let function = |binding: Binding<'ast>| {
            if session.bindings.contains_key(&binding) {
                return None;
            }
            session.function(binding)
        };
        let mix = captures.name("$mix")?;
        let compress = captures.name("$compress")?;
        let mac = captures.name("$mac")?;
        let keystream = captures.name("$keystream")?;
        let mix_function = function(mix)?;
        let compress_function = function(compress)?;
        let mac_function = function(mac)?;
        let keystream_function = function(keystream)?;
        let native = |function| {
            session
                .intrinsics
                .get(&intrinsic::address(function))
                .copied()
        };
        let Some(Intrinsic::Mix32(mixer)) = native(mix_function) else {
            return None;
        };
        let Some(Intrinsic::Blake3Compress) = native(compress_function) else {
            return None;
        };
        let mac_captures =
            pattern::matches(&pattern::template(MAC), script, mac_function, &helpers)?;
        let stream_captures = pattern::matches(
            &pattern::template(KEYSTREAM),
            script,
            keystream_function,
            &helpers,
        )?;
        if mac_captures.name("$self")? != mac
            || mac_captures.name("$compress")? != compress
            || stream_captures.name("$compress")? != compress
        {
            return None;
        }
        let table = captures.name("$table")?;
        let array = captures.name("$array")?;
        let repeat = captures.name("$repeat")?;
        let code = mac_captures.name("$code")?;
        // Values the decoder reads are session bindings, not functions or builtins.
        if ![table, array, repeat, code]
            .iter()
            .all(|binding| session.bindings.contains_key(binding))
        {
            return None;
        }
        let named = |binding, function| NamedFunction { binding, function };
        let mut functions = vec![
            named(mix, mix_function),
            named(compress, compress_function),
            named(mac, mac_function),
            named(keystream, keystream_function),
        ];
        let mut bound_helpers = Vec::new();
        let inlined: BTreeSet<Binding<'ast>> = (captures.helpers.iter())
            .chain(&mac_captures.helpers)
            .chain(&stream_captures.helpers)
            .copied()
            .collect();
        for binding in inlined {
            if let Some(value) = session.bindings.get(&binding) {
                let function = pattern::script_function(value);
                let function = function.expect("bound binary helpers are script functions");
                bound_helpers.push(named(binding, function));
            } else {
                let function = session.function(binding);
                let function = function.expect("unbound binary helpers are declared functions");
                functions.push(named(binding, function));
            }
        }
        Some(Self {
            mixer,
            functions,
            bound_helpers,
            table,
            array,
            repeat,
            code,
            block: captures.constant("$c_block")?,
            read: captures.formula("$e_read")?,
            stream: stream_captures.constant("$c_stream")?,
        })
    }

    /// Decrypts `record` as the script would, or returns `None` to interpret it.
    pub(super) fn decrypt(&self, run: &Run<'ast, '_>, record: &Value<'ast>) -> Option<Value<'ast>> {
        if run.setup.is_some() || !self.resolves(run) {
            return None;
        }
        let Value::Array(record) = record else {
            return None;
        };
        let record = record.borrow();
        let [
            Value::Program,
            Value::Number(offset),
            Value::Number(length),
            Value::Number(low),
            Value::Number(high),
            Value::Array(key),
            ..,
        ] = &record[..]
        else {
            return None;
        };
        let (offset, length) = (*offset, *length);
        let (low, high) = (js::int32(*low), js::int32(*high));
        let key: [u32; 8] = intrinsic::words(key.borrow().get(..8)?)?;
        let program = run.program;
        let seed = self.mixer.call(offset);
        // Byte values only: other results would index the character table outside it.
        let read = |position: f64| -> Option<i32> {
            let mixed = js::int32(seed + 2_654_435_769.0 * position);
            let value = self.read.evaluate(&[
                ("bytes", Input::Bytes(program)),
                ("offset", Input::Number(offset)),
                ("position", Input::Number(position)),
                ("record", Input::Array(&record)),
                ("mixed", Input::Number(f64::from(mixed))),
            ])?;
            (value.fract() == 0.0 && (0.0..=255.0).contains(&value)).then_some(value as i32)
        };
        // The record key, derived from the record's position, length and first bytes.
        let mut header = [0i32; 4];
        for count in 0..16 {
            header[count >> 2] |= read(count as f64)? << (8 * (count & 3));
        }
        let mut block = [self.block, offset, length, 0.0, 0.0, 0.0, 0.0, 0.0];
        for (slot, word) in block[3..7].iter_mut().zip(header) {
            *slot = f64::from(word);
        }
        block[7] = f64::from(high << 8 | low);
        let mut words = [0u32; 16];
        words[..8].copy_from_slice(&intrinsic::words::<8>(&block.map(Value::Number))?);
        let key = intrinsic::compress(&key, &words, Counter::of(0.0), 32, 27);
        let count = read(16.0)? << 8 | read(17.0)?;
        if f64::from(count) > length {
            return None;
        }
        let count = usize::try_from(count).ok()?;
        let mut ciphertext = Vec::with_capacity(count);
        for index in 0..count {
            ciphertext.push(u8::try_from(read((18 + index) as f64)?).ok()?);
        }
        // The MAC covers the key's first word and the ciphertext.
        let mut text = Vec::with_capacity(4 + count);
        text.extend((0..4).map(|index| ((key[0] >> (8 * index)) & 255) as u16));
        text.extend(ciphertext.iter().map(|&byte| u16::from(byte)));
        let bytes = 8 + 2 * text.len();
        let mac = mac(&text, bytes, 0, (bytes - 1) / 1024 + 1, true, &key);
        let mut difference = 0;
        for value in 0..16 {
            let expected = (mac[value >> 2] >> (8 * (value & 3))) & 255;
            difference |= read(18.0 + length + value as f64)? ^ expected as i32;
        }
        if difference != 0 {
            return None;
        }
        let mut plain = Vec::with_capacity(count);
        let mut stream = [0u32; 8];
        for (index, byte) in ciphertext.iter().enumerate() {
            if index & 31 == 0 {
                let mut block = [0u32; 16];
                block[0] = intrinsic::words::<1>(&[Value::Number(self.stream)])?[0];
                block[1] = (index >> 5) as u32;
                stream = intrinsic::compress(&key, &block, Counter::of(0.0), 8, 27);
            }
            let mask = (stream[(index >> 2) & 7] >> ((index & 3) * 8)) & 255;
            plain.push(u16::from(*byte) ^ mask as u16);
        }
        // `"\0".repeat(length - count)`, within the interpreter's length limit.
        let padding = convert::length(length - count as f64)?;
        plain.resize(count + padding, 0);
        Some(Value::String(JsString::from(plain)))
    }

    /// Whether every binding the decoder reads resolves, in `run`, to what was recognized.
    fn resolves(&self, run: &Run<'ast, '_>) -> bool {
        let unshadowed = |binding: &Binding<'ast>| !run.unavailable.contains_key(binding);
        let value = |binding: &Binding<'ast>| {
            if !unshadowed(binding) {
                return None;
            }
            run.globals
                .get(binding)
                .or_else(|| run.session.bindings.get(binding))
        };
        let functions = self
            .functions
            .iter()
            .all(|NamedFunction { binding, function }| {
                unshadowed(binding)
                    && run.globals.get(binding).is_none_or(|global| {
                        pattern::script_function(global)
                            .is_some_and(|found| ptr::eq(found, *function))
                    })
            });
        let bound_helpers = self
            .bound_helpers
            .iter()
            .all(|NamedFunction { binding, function }| {
                value(binding)
                    .and_then(pattern::script_function)
                    .is_some_and(|found| ptr::eq(found, *function))
            });
        functions
            && bound_helpers
            && value(&self.table).is_some_and(is_character_table)
            && value(&self.array).is_some_and(|array| is_builtin(array, Builtin::Array))
            && value(&self.repeat).is_some_and(|repeat| is_bound_call(repeat, Builtin::Repeat))
            && value(&self.code).is_some_and(|code| is_bound_call(code, Builtin::CharCodeAt))
    }
}

/// The MAC function on `bytes` bytes of `text`, from chunk `chunk`, for keyed calls without a
/// prefix, as the decoder makes them.
fn mac(
    text: &[u16],
    bytes: usize,
    chunk: usize,
    chunks: usize,
    root: bool,
    key: &[u32; 8],
) -> [u32; 8] {
    const KEYED: u32 = 16;
    if chunks > 1 {
        let mut half = 1;
        while 2 * half < chunks {
            half *= 2;
        }
        let mut block = [0u32; 16];
        block[..8].copy_from_slice(&mac(text, bytes, chunk, half, false, key));
        block[8..].copy_from_slice(&mac(text, bytes, chunk + half, chunks - half, false, key));
        let flags = if root { 8 } else { 0 } | KEYED | 4;
        return intrinsic::compress(key, &block, Counter::of(0.0), 64, flags);
    }
    let mut state = *key;
    let start = chunk * 1024;
    let end = (start + 1024).min(bytes);
    let mut position = start;
    while position < end {
        let mut block = [0u32; 16];
        for (half, slot) in block.iter_mut().enumerate() {
            // Code unit index; the first four units are the zero prefix.
            let unit = (position / 2 + 2 * half).checked_sub(4);
            let word = match unit {
                Some(unit) if unit < text.len() => {
                    let low = text.get(unit + 1).map_or(0, |&unit| u32::from(unit));
                    u32::from(text[unit]) << 16 | low
                }
                _ => 0,
            };
            *slot = word.swap_bytes();
        }
        let last = position + 64 >= end;
        let length = if last { end - position } else { 64 };
        let flags = KEYED
            | u32::from(start == position)
            | if last { 2 } else { 0 }
            | if last && root { 8 } else { 0 };
        let counter = Counter::of(chunk as f64);
        state = intrinsic::compress(&state, &block, counter, length as u32, flags);
        position += 64;
    }
    state
}

/// `String.fromCharCode(i)` at each index `i` below 256.
fn is_character_table(table: &Value<'_>) -> bool {
    let Value::Array(elements) = table else {
        return false;
    };
    let elements = elements.borrow();
    elements.len() == 256
        && elements.iter().enumerate().all(|(index, element)| {
            matches!(element, Value::String(text) if text.units() == [index as u16])
        })
}

fn is_builtin(value: &Value<'_>, builtin: Builtin) -> bool {
    matches!(value, Value::Function(callable)
        if matches!(&**callable, Callable::Builtin(found) if *found == builtin))
}

/// `Function.prototype.call.bind(method)`, as `bind.bind(call)(method)` creates it.
fn is_bound_call(value: &Value<'_>, method: Builtin) -> bool {
    let Value::Function(callable) = value else {
        return false;
    };
    matches!(&**callable, Callable::Bound { target, this, arguments }
        if arguments.is_empty() && is_builtin(target, Builtin::Call) && is_builtin(this, method))
}

#[cfg(test)]
mod tests {
    use std::{env, fs};

    use crate::script::Source;

    /// Recognizes the decoder of a saved deobfuscated script named by `CFSOLVE_DECODER_SCRIPT`.
    #[test]
    fn recognizes_saved_script() {
        let Some(path) = env::var_os("CFSOLVE_DECODER_SCRIPT") else {
            return;
        };
        let source = fs::read_to_string(path).expect("the saved script is readable");
        let source = Source::try_new(&source).expect("the saved script parses");
        let machine = source.machine().expect("the saved script builds a machine");
        assert!(machine.session.string_decoder.is_some(), "string decoder");
        assert!(machine.native_dispatch.is_some(), "native dispatch");
    }
}
