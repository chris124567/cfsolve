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

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oxc::allocator::{Allocator, GetAllocator};
use oxc::ast::ast::{
    BinaryExpression, Expression, Program, Statement, VariableDeclaration, VariableDeclarator,
};
use oxc::ast_visit::{Visit, VisitMut, walk, walk_mut};
use oxc::str::{JSStr, JSStrBuilder};
use oxc::syntax::operator::BinaryOperator;
use oxc::syntax::scope::ScopeFlags;

use super::analysis::{Analysis, Id};
use super::{HashMap, ast, pipeline, removal};

/// A constant decoder call in the original script, with its encoded input, key, and decoded text.
pub(crate) struct Encoded {
    pub(crate) encoded: String,
    pub(crate) key: u16,
    pub(crate) decoded: String,
}

/// Encodes `text` so that [`decode`] with the same key recovers its UTF-16 code units.
pub(crate) fn encode(text: &str, mut key: u16) -> String {
    let mut bytes = Vec::new();
    let mut push = |byte: u8| {
        key = key.rotate_left(8);
        bytes.push(byte ^ (key >> 8) as u8)
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

/// Decodes base64 with the key's alternating byte order. A 255 byte escapes a little-endian
/// UTF-16 code unit. The arena string preserves lone surrogates; malformed base64 or a truncated
/// escape returns `None` instead of inventing replacement characters.
fn decode<'a>(encoded: &str, mut key: u16, allocator: &'a Allocator) -> Option<JSStr<'a>> {
    let mut bytes = STANDARD.decode(encoded).ok()?.into_iter();
    let mut next = || {
        key = key.rotate_left(8);
        Some(bytes.next()? ^ (key >> 8) as u8)
    };
    let mut decoded = JSStrBuilder::new_in(&allocator);
    while let Some(unit) = next() {
        decoded.push_code_unit(if unit == 255 {
            u16::from_le_bytes([next()?, next()?])
        } else {
            u16::from(unit)
        })
    }
    Some(decoded.into_js_str())
}

/// Recognizes `function(global) { ...; return function(encoded) { ... } }(globalThis)` and returns
/// its key.
fn decoder_key<'a>(expression: &Expression<'a>, analysis: &Analysis<'a>) -> Option<u16> {
    let Expression::CallExpression(call) = expression.get_inner_expression() else {
        return None;
    };
    let [global] = call.arguments.as_slice() else {
        return None;
    };
    if global.as_expression()?.get_identifier_reference()?.name != "globalThis" {
        return None;
    }
    let Expression::FunctionExpression(outer) = call.callee.get_inner_expression() else {
        return None;
    };
    let Statement::ReturnStatement(returned) = outer.body.as_ref()?.statements.last()? else {
        return None;
    };
    let Expression::FunctionExpression(decoder) =
        returned.argument.as_ref()?.get_inner_expression()
    else {
        return None;
    };
    let [parameter] = decoder.params.items.as_slice() else {
        return None;
    };
    let mut search = KeySearch {
        analysis,
        encoded: ast::pattern_id(&parameter.pattern)?,
        key: None,
        value: 0,
        rotated: false,
    };
    search.visit_function(decoder, ScopeFlags::Function);
    (search.key.is_some() && search.rotated).then_some(search.value)
}

/// Finds the key declared beside `bytes = global.atob(encoded)`, and whether that same binding is
/// rotated with `(key << 8 | key >>> 8) & 65535`. Resolved identities distinguish shadows.
struct KeySearch<'b, 'a> {
    analysis: &'b Analysis<'a>,
    encoded: Id,
    key: Option<Id>,
    /// The initial value of `key`.
    value: u16,
    rotated: bool,
}

impl<'a> KeySearch<'_, 'a> {
    /// Matches `key << 8` or `key >>> 8`.
    fn shifts(&self, expression: &Expression<'a>, operator: BinaryOperator, key: Id) -> bool {
        matches!(
            expression.get_inner_expression(),
            Expression::BinaryExpression(shift) if shift.operator == operator
                && self.analysis.expression_id(&shift.left) == Some(key)
                && ast::number(&shift.right) == Some(8.0)
        )
    }
}

impl<'a> Visit<'a> for KeySearch<'_, 'a> {
    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'a>) {
        for pair in declaration.declarations.windows(2) {
            let [bytes, key] = pair else { continue };
            if let Some(init) = &bytes.init
                && let Some((_, [argument])) = ast::method_call(init, "atob")
                && argument
                    .as_expression()
                    .and_then(Expression::get_identifier_reference)
                    .is_some_and(|encoded| self.analysis.id(encoded) == Some(self.encoded))
                && let Some(id) = ast::pattern_id(&key.id)
                && let Some(value) = key.init.as_ref().and_then(ast::number)
                && value.fract() == 0.0
                && (0.0..=u16::MAX as f64).contains(&value)
            {
                self.key = Some(id);
                self.value = value as u16;
            }
        }
        walk::walk_variable_declaration(self, declaration)
    }

    fn visit_binary_expression(&mut self, binary: &BinaryExpression<'a>) {
        if let Some(key) = self.key
            && binary.operator == BinaryOperator::BitwiseAnd
            && ast::number(&binary.right) == Some(65535.0)
            && let Expression::BinaryExpression(swap) = binary.left.get_inner_expression()
            && swap.operator == BinaryOperator::BitwiseOR
        {
            self.rotated |= self.shifts(&swap.left, BinaryOperator::ShiftLeft, key)
                && self.shifts(&swap.right, BinaryOperator::ShiftRightZeroFill, key);
        }
        walk::walk_binary_expression(self, binary)
    }
}

/// Finds decoder initializers by their declared binding and recovers each key.
fn decoders<'a>(program: &Program<'a>, analysis: &Analysis<'a>) -> HashMap<Id, u16> {
    let mut decoders = Decoders {
        analysis,
        found: HashMap::default(),
    };
    decoders.visit_program(program);
    decoders.found
}

struct Decoders<'b, 'a> {
    analysis: &'b Analysis<'a>,
    found: HashMap<Id, u16>,
}

impl<'a> Visit<'a> for Decoders<'_, 'a> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(id) = ast::pattern_id(&declarator.id)
            && let Some(value) = &declarator.init
            && let Some(key) = decoder_key(value, self.analysis)
        {
            self.found.insert(id, key);
        }
        walk::walk_variable_declarator(self, declarator)
    }
}

pub(super) fn run<'a>(program: &mut Program<'a>, analysis: &mut Analysis<'a>) -> bool {
    let mut decoders = decoders(program, analysis);
    decoders.retain(|id, _| analysis.bindings.is_written_once(id));
    let mut inline = Inline {
        analysis,
        decoders: &decoders,
        replaced: HashMap::default(),
    };
    inline.visit_program(program);
    if inline.replaced.is_empty() {
        return false;
    }
    let unread = removal::unread(&inline.replaced, analysis);
    removal::remove_initializers(program, &unread);
    true
}

struct Inline<'b, 'a> {
    analysis: &'b Analysis<'a>,
    decoders: &'b HashMap<Id, u16>,
    /// Replacement counts by decoder.
    replaced: HashMap<Id, usize>,
}

impl<'a> VisitMut<'a> for Inline<'_, 'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some((callee, [argument])) = ast::direct_call(expression)
            && let Some(id) = self.analysis.id(callee)
            && let Some(&key) = self.decoders.get(&id)
            && let Some(encoded) = argument.as_expression().and_then(ast::static_str)
            && let Some(value) = decode(encoded, key, self.analysis.allocator())
        {
            *self.replaced.entry(id).or_default() += 1;
            *expression =
                Expression::new_string_literal(callee.span, value, None, &self.analysis.ast);
        }
    }
}

/// Parses and resolves the original script as deobfuscation does, then finds constant calls to
/// recognized decoders. Returns an owned inventory for capture rewriting; strings with lone
/// surrogates are omitted from this Rust-string inventory, while the AST rewrite preserves their
/// code units.
pub(crate) fn inline_strings(source: &str) -> Result<Vec<Encoded>> {
    let allocator = Allocator::default();
    let (program, analysis) = pipeline::parse(&allocator, source)?;
    let decoders = decoders(&program, &analysis);
    let mut calls = Calls {
        analysis: &analysis,
        decoders: &decoders,
        found: Vec::new(),
    };
    calls.visit_program(&program);
    Ok(calls.found)
}

struct Calls<'b, 'a> {
    analysis: &'b Analysis<'a>,
    decoders: &'b HashMap<Id, u16>,
    found: Vec<Encoded>,
}

impl<'a> Visit<'a> for Calls<'_, 'a> {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        if let Some((callee, [argument])) = ast::direct_call(expression)
            && let Some(&key) = self
                .analysis
                .id(callee)
                .and_then(|id| self.decoders.get(&id))
            && let Some(encoded) = argument.as_expression().and_then(ast::static_str)
            && let Some(decoded) = decode(encoded, key, self.analysis.allocator())
            && let Some(decoded) = decoded.as_str()
        {
            self.found.push(Encoded {
                encoded: encoded.to_owned(),
                key,
                decoded: decoded.to_owned(),
            })
        }
        walk::walk_expression(self, expression)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use oxc::allocator::Allocator;

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
        let transform =
            |source: &str| testing::rewrite(&format!("{DECODER}\n{source}"), super::run);
        let output = transform("f(decode(`ZJd1i3w=`), decode('ZoZpiw=='));");
        testing::assert_contains(&output, &["\"apply\"", "\"call\"", "var decode;"]);
        // Dynamic calls keep the decoder; reassignment disables decoding.
        let output = transform("f(decode(`ZJd1i3w=`), decode(name));");
        let expected = ["\"apply\"", "decode(name)", "var decode = function"];
        testing::assert_contains(&output, &expected);
        let output = transform("decode = other; f(decode(`ZJd1i3w=`));");
        assert!(output.contains("decode(`ZJd1i3w=`)"), "{output}");
    }

    #[test]
    fn finds_and_reencodes_the_strings_a_served_script_decodes() {
        let source = format!("{DECODER}\nf(decode(`ZJd1i3w=`), decode('ZoZpiw=='), other(`x`));");
        let strings = super::inline_strings(&source).unwrap();
        let decoded: Vec<(&str, &str)> = strings
            .iter()
            .map(|string| (string.encoded.as_str(), string.decoded.as_str()))
            .collect();
        assert_eq!(decoded, [("ZJd1i3w=", "apply"), ("ZoZpiw==", "call")]);
        assert_eq!(super::encode("apply", strings[0].key), "ZJd1i3w=");
        // Code units of 255 or greater need an escape byte followed by two bytes.
        let encoded = super::encode("a€", 59141);
        let allocator = Allocator::default();
        let decoded = super::decode(&encoded, 59141, &allocator).expect("valid encoding");
        assert_eq!(decoded.as_str(), Some("a€"));
        // 255 escapes the code unit U+D800, a lone surrogate. The bytes 255, 0x00, 0xd8 are
        // XORed with the key 59141 (0xe705), low byte first.
        let encoded = super::STANDARD.encode([255 ^ 0x05, 0xe7, 0xd8 ^ 0x05]);
        let decoded = super::decode(&encoded, 59141, &allocator).expect("valid encoding");
        assert_eq!(decoded.encode_utf16().collect::<Vec<_>>(), [0xd800]);
    }
}
