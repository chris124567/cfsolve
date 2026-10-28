//! Replaces constant calls to the obfuscator's string decoder with their results:
//!
//! ```js
//! var decode = function(global) { ... return function(encoded) { ... } }(globalThis);
//! decode(`ZJd1i3w=`);  // becomes "apply"
//! ```
//!
//! The decoder swaps the bytes of a 16-bit key before processing each byte, then XORs the input
//! byte with the key's high byte. A byte of 255 introduces a code unit encoded in the next two
//! bytes. Only the key varies between scripts. Requires a decoder binding assigned once.
//! Because decoding has no side effects, constant calls can be replaced wherever they occur.
//! Removes the decoder when no reads remain.

use base64::engine::general_purpose::STANDARD;
use swc_core::atoms::Wtf8Atom;
use swc_core::atoms::wtf8::Wtf8Buf;
use swc_core::ecma::ast::{BinaryOp, Expr, Id, Lit, Program, Script, Str, VarDeclarator};
use swc_core::ecma::visit::{Visit, VisitMut, VisitMutWith, VisitWith};

use super::analysis::Analysis;
use super::{HashMap, HashSet, removal};
use crate::js::ast;

pub(super) fn run(program: &mut Program, analysis: &mut Analysis) -> bool {
    let bindings = analysis.bindings(program);
    let mut decoders = Decoders::default();
    program.visit_with(&mut decoders);
    decoders.0.retain(|id, _| bindings.is_written_once(id));
    if decoders.0.is_empty() {
        return false;
    }
    let mut decode = DecodeCalls {
        decoders: &decoders.0,
        decoded: HashMap::default(),
    };
    program.visit_mut_with(&mut decode);
    let unread = removal::unread(&decode.decoded, bindings);
    program.visit_mut_with(&mut DropDecoders(unread));
    !decode.decoded.is_empty()
}

/// A string decoder call with constant arguments in the original script, including the encoded
/// input, key, and decoded text.
pub(crate) struct Encoded {
    pub(crate) encoded: String,
    pub(crate) key: u16,
    pub(crate) decoded: String,
}

/// Finds constant decoder calls in `script` before name resolution. Identifies decoders by their
/// declared names.
pub(crate) fn inline_strings(script: &Script) -> Vec<Encoded> {
    struct Calls<'decoders> {
        decoders: &'decoders HashMap<Id, u16>,
        found: Vec<Encoded>,
    }
    impl Visit for Calls<'_> {
        fn visit_expr(&mut self, expression: &Expr) {
            if let Some((callee, [argument])) = ast::direct_call(expression)
                && argument.spread.is_none()
                && let Some(&key) = self.decoders.get(&callee.to_id())
                && let Some(encoded) = ast::static_str(&argument.expr)
                && let Some(decoded) = decode(encoded, key)
                && let Some(decoded) = decoded.as_str()
            {
                self.found.push(Encoded {
                    encoded: encoded.to_owned(),
                    key,
                    decoded: decoded.to_owned(),
                });
            }
            expression.visit_children_with(self);
        }
    }
    let mut decoders = Decoders::default();
    script.visit_with(&mut decoders);
    let mut calls = Calls {
        decoders: &decoders.0,
        found: Vec::new(),
    };
    script.visit_with(&mut calls);
    calls.found
}

/// Encodes `text` so that [`decode`] with `key` returns it.
pub(crate) fn encode(text: &str, mut key: u16) -> String {
    use base64::Engine;

    let mut bytes = Vec::new();
    let mut push = |byte: u8| {
        key = key.rotate_left(8);
        bytes.push(byte ^ (key >> 8) as u8);
    };
    for unit in text.encode_utf16() {
        match u8::try_from(unit) {
            Ok(byte) if byte != 255 => push(byte),
            _ => {
                let [low, high] = unit.to_le_bytes();
                push(255);
                push(low);
                push(high);
            }
        }
    }
    STANDARD.encode(bytes)
}

/// Decodes `encoded` as the decoder holding `key` does, or `None` if it is not base64.
fn decode(encoded: &str, mut key: u16) -> Option<Wtf8Atom> {
    use base64::Engine;

    let mut bytes = STANDARD.decode(encoded).ok()?.into_iter();
    let mut next = || {
        key = key.rotate_left(8);
        Some(bytes.next()? ^ (key >> 8) as u8)
    };
    let mut units = vec![];
    while let Some(unit) = next() {
        units.push(if unit == 255 {
            u16::from_le_bytes([next()?, next()?])
        } else {
            u16::from(unit)
        });
    }
    Some(Wtf8Atom::from(Wtf8Buf::from_ill_formed_utf16(&units)))
}

/// Decoders by binding, with their keys.
#[derive(Default)]
struct Decoders(HashMap<Id, u16>);

impl Visit for Decoders {
    fn visit_var_declarator(&mut self, declarator: &VarDeclarator) {
        if let Some(name) = declarator.name.as_ident()
            && let Some(key) = declarator.init.as_deref().and_then(decoder_key)
        {
            self.0.insert(name.to_id(), key);
        }
        declarator.visit_children_with(self);
    }
}

/// The key of `function(global) { ...; return function(encoded) { ... } }(globalThis)`. The
/// inner decoder declares it beside `bytes = global.atob(encoded)` and rotates it by
/// `key = (key << 8 | key >>> 8) & 65535`.
fn decoder_key(expression: &Expr) -> Option<u16> {
    let call = expression.as_call()?;
    let [global] = &call.args[..] else {
        return None;
    };
    if global.spread.is_some() || global.expr.as_ident()?.sym != "globalThis" {
        return None;
    }
    let outer = call.callee.as_expr()?.unwrap_parens().as_fn_expr()?;
    let returned = outer
        .function
        .body
        .as_ref()?
        .stmts
        .last()?
        .as_return_stmt()?;
    let decoder = &returned.arg.as_deref()?.as_fn_expr()?.function;
    let [parameter] = &decoder.params[..] else {
        return None;
    };
    let mut keys = Keys {
        encoded: parameter.pat.as_ident()?.to_id(),
        key: None,
        rotated: false,
    };
    decoder.visit_with(&mut keys);
    let (_, key) = keys.key?;
    keys.rotated.then_some(key)
}

/// Finds the key declaration and its rotation in an inner decoder.
struct Keys {
    encoded: Id,
    key: Option<(Id, u16)>,
    rotated: bool,
}

impl Visit for Keys {
    fn visit_var_declarators(&mut self, declarators: &[VarDeclarator]) {
        for pair in declarators.windows(2) {
            if let [bytes, key] = pair
                && let Some(init) = bytes.init.as_deref()
                && let Some((_, [argument])) = ast::method_call(init, "atob")
                && argument
                    .expr
                    .as_ident()
                    .is_some_and(|id| id.to_id() == self.encoded)
                && let Some(name) = key.name.as_ident()
                && let Some(value) = key.init.as_deref().and_then(ast::number)
                && value.fract() == 0.0
                && let Ok(value) = u16::try_from(value as i64)
            {
                self.key = Some((name.to_id(), value));
            }
        }
        declarators.visit_children_with(self);
    }

    fn visit_expr(&mut self, expression: &Expr) {
        if let Some((key, _)) = &self.key
            && is_rotation(expression, key)
        {
            self.rotated = true;
        }
        expression.visit_children_with(self);
    }
}

/// `(key << 8 | key >>> 8) & 65535`.
fn is_rotation(expression: &Expr, key: &Id) -> bool {
    let shifts_key = |expression: &Expr, op| {
        expression.as_bin().is_some_and(|shift| {
            shift.op == op
                && shift
                    .left
                    .as_ident()
                    .is_some_and(|name| name.to_id() == *key)
                && ast::number(&shift.right) == Some(8.0)
        })
    };
    let Some(mask) = expression.as_bin() else {
        return false;
    };
    let Some(swap) = mask.left.unwrap_parens().as_bin() else {
        return false;
    };
    mask.op == BinaryOp::BitAnd
        && ast::number(&mask.right) == Some(65535.0)
        && swap.op == BinaryOp::BitOr
        && shifts_key(&swap.left, BinaryOp::LShift)
        && shifts_key(&swap.right, BinaryOp::ZeroFillRShift)
}

/// Replaces `decoder(encoded)` with its result, counting the calls replaced per decoder.
struct DecodeCalls<'decoders> {
    decoders: &'decoders HashMap<Id, u16>,
    decoded: HashMap<Id, usize>,
}

impl VisitMut for DecodeCalls<'_> {
    fn visit_mut_expr(&mut self, expression: &mut Expr) {
        expression.visit_mut_children_with(self);
        if let Some((callee, [encoded])) = ast::direct_call(expression)
            && encoded.spread.is_none()
            && let Some(&key) = self.decoders.get(&callee.to_id())
            && let Some(value) = ast::static_str(&encoded.expr).and_then(|text| decode(text, key))
        {
            *self.decoded.entry(callee.to_id()).or_default() += 1;
            *expression = Expr::Lit(Lit::Str(Str {
                span: callee.span,
                value,
                raw: None,
            }));
        }
    }
}

/// Drops the initializers of decoders nothing reads, leaving `var decoder;`.
struct DropDecoders(HashSet<Id>);

impl VisitMut for DropDecoders {
    fn visit_mut_var_declarator(&mut self, declarator: &mut VarDeclarator) {
        if declarator
            .name
            .as_ident()
            .is_some_and(|name| self.0.contains(&name.to_id()))
        {
            declarator.init = None;
        }
        declarator.visit_mut_children_with(self);
    }
}

#[cfg(test)]
mod tests {
    use crate::deobfuscate::testing;

    /// The decoder of a challenge script, with its key.
    const DECODER: &str = "var decode = function(J) {
        var d = { __proto__: null }, e = J.String;
        return function(l) {
            var E = d[l];
            if (E === void 0) {
                var V = J.atob(l), z = 59141, E = ``, H = 0, C = [];
                while (H < V.length) {
                    z = (z << 8 | z >>> 8) & 65535;
                    var t = V.charCodeAt(H++) ^ z >>> 8;
                    if (t === 255) {
                        z = (z << 8 | z >>> 8) & 65535;
                        t = V.charCodeAt(H++) ^ z >>> 8;
                        z = (z << 8 | z >>> 8) & 65535;
                        t |= (V.charCodeAt(H++) ^ z >>> 8) << 8;
                    }
                    C.push(t);
                    if (C.length === 128) {
                        E += e.fromCharCode.apply(e, C);
                        C = [];
                    }
                }
                E += e.fromCharCode.apply(e, C);
                d[l] = E;
            }
            return E;
        };
    }(globalThis);";

    #[test]
    fn decodes_constant_calls_and_drops_an_unread_decoder() {
        let transform = |source: &str| {
            testing::rewrite(
                &format!("{DECODER}\n{source}"),
                super::run,
                /* fix= */ true,
            )
        };
        let output = transform("f(decode(`ZJd1i3w=`), decode('ZoZpiw=='));");
        testing::assert_contains(&output, &["\"apply\"", "\"call\""], &["var decode;"]);
        // Dynamic calls keep the decoder; reassignment disables decoding.
        let output = transform("f(decode(`ZJd1i3w=`), decode(name));");
        let expected = ["\"apply\"", "decode(name)"];
        testing::assert_contains(&output, &expected, &["var decode = function"]);
        let output = transform("decode = other; f(decode(`ZJd1i3w=`));");
        assert!(output.contains("decode(`ZJd1i3w=`)"), "{output}");
    }

    #[test]
    fn finds_and_reencodes_the_strings_a_served_script_decodes() {
        let source = format!("{DECODER}\nf(decode(`ZJd1i3w=`), decode('ZoZpiw=='), other(`x`));");
        let parsed = crate::js::ast::parse_javascript("x.js", &source).unwrap();
        let strings = super::inline_strings(&parsed.script);
        let decoded: Vec<(&str, &str)> = strings
            .iter()
            .map(|string| (string.encoded.as_str(), string.decoded.as_str()))
            .collect();
        assert_eq!(decoded, [("ZJd1i3w=", "apply"), ("ZoZpiw==", "call")]);
        assert_eq!(super::encode("apply", strings[0].key), "ZJd1i3w=");
        // Code units of 255 or greater need an escape byte followed by two bytes.
        let encoded = super::encode("a€", 59141);
        assert_eq!(super::decode(&encoded, 59141).unwrap().as_str(), Some("a€"));
    }

    #[test]
    fn decodes_escaped_code_units() {
        use base64::Engine;

        // 255 escapes the code unit U+D800, a lone surrogate.
        let encoded = super::STANDARD.encode([255 ^ 0x05, 0x00 ^ 0xe7, 0xd8 ^ 0x05]);
        let decoded = super::decode(&encoded, 59141).unwrap();
        assert_eq!(
            decoded.as_wtf8().to_ill_formed_utf16().collect::<Vec<_>>(),
            [0xd800]
        );
    }
}
