//! Parses iframe stylesheets and serializes keyframes using each engine's formatting.

use cssparser::{ParseError, Parser, ParserInput, Token};

use crate::engine::Engine;

/// One rule: its prelude, and its block's contents.
pub(super) struct Rule {
    pub header: String,
    pub body: String,
}

/// Tokenizes rules while preserving quoted values, comments, and nested blocks in stylesheets
/// and keyframes.
#[must_use]
pub(super) fn rules(css: &str) -> Vec<Rule> {
    let mut input = ParserInput::new(css);
    let mut parser = Parser::new(&mut input);
    let mut output = Vec::new();
    let mut start = parser.position();
    while let Ok(token) = parser.next_including_whitespace_and_comments().cloned() {
        if matches!(token, Token::CurlyBracketBlock) {
            let header = parser
                .slice(start..parser.position())
                .trim()
                .trim_end_matches('{')
                .trim()
                .to_owned();
            let body: Result<String, ParseError<'_, ()>> = parser.parse_nested_block(|nested| {
                let start = nested.position();
                while nested.next_including_whitespace_and_comments().is_ok() {}
                Ok(nested.slice_from(start).to_owned())
            });
            if let Ok(body) = body {
                output.push(Rule { header, body });
            }
            start = parser.position();
        } else if matches!(token, Token::Semicolon) {
            // Skip statements such as `@charset` and `@import`; external sheets are not
            // recovered.
            start = parser.position();
        }
    }
    output
}

fn declarations(css: &str) -> Vec<(String, String)> {
    let mut input = ParserInput::new(css);
    let mut parser = Parser::new(&mut input);
    let mut start = parser.position();
    let mut parts = Vec::new();
    while let Ok(token) = parser.next_including_whitespace_and_comments().cloned() {
        if matches!(token, Token::Semicolon) {
            let part = parser.slice(start..parser.position());
            parts.push(part.trim_end_matches(';'));
            start = parser.position();
        }
    }
    parts.push(parser.slice_from(start));
    parts
        .into_iter()
        .filter_map(|part| {
            let (key, value) = part.split_once(':')?;
            Some((key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect()
}

fn serialize_value(parser: &mut Parser<'_, '_>, function: &str) -> String {
    use cssparser::ToCss;

    let mut result = String::new();
    while let Ok(token) = parser.next_including_whitespace_and_comments().cloned() {
        match token {
            Token::WhiteSpace(_) => {
                if !result.is_empty() && !result.ends_with(' ') {
                    result.push(' ');
                }
            }
            Token::Comment(_) => {}
            Token::Comma => {
                result = result.trim_end().to_owned();
                result.push_str(", ");
            }
            Token::Function(name) => {
                let value: Result<_, ParseError<'_, ()>> =
                    parser.parse_nested_block(|nested| Ok(serialize_value(nested, &name)));
                result.push_str(&format!("{name}({})", value.unwrap_or_default()));
            }
            Token::Number { value, .. } if value == 0.0 && function.starts_with("translate") => {
                result.push_str("0px");
            }
            Token::Number { value, .. } if value == 0.0 && function.starts_with("rotate") => {
                result.push_str("0deg");
            }
            _ => result.push_str(&token.to_css_string()),
        }
    }
    result.trim().to_owned()
}

/// A `@keyframes` rule's `cssText`, spelled as `engine` serializes it. WebKit joins keyframe
/// selectors without a space, and gives unitless zero stroke lengths a unit where Chromium
/// preserves the number.
#[must_use]
pub(super) fn keyframes(rule: &Rule, engine: Engine) -> String {
    let mut output = format!("{} {{ \n", rule.header);
    for frame in rules(&rule.body) {
        let mut input = ParserInput::new(&frame.header);
        let mut header = serialize_value(&mut Parser::new(&mut input), "");
        if engine == Engine::WebKit {
            header = header.replace(", ", ",");
        }
        output.push_str(&format!("  {header} {{"));
        for (key, value) in declarations(&frame.body) {
            let mut input = ParserInput::new(&value);
            let mut value = serialize_value(&mut Parser::new(&mut input), "");
            let stroke_length = ["stroke-width", "stroke-dashoffset"].contains(&&*key);
            if engine == Engine::WebKit && value == "0" && stroke_length {
                value = "0px".to_owned();
            }
            output.push_str(&format!(" {key}: {value};"));
        }
        output.push_str(" }\n");
    }
    output.push('}');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenization_preserves_braces_in_strings() {
        let parsed =
            rules("/* before */.x{content:'}';color:red}@media(max-width:350px){.y{width:24px}}");
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].body.contains("content:'}'"));
        assert_eq!(rules(&parsed[1].body).len(), 1);
    }

    /// The checkbox's keyframes, as Chromium 155 and iOS Safari 26 reported them.
    #[test]
    fn each_engine_spells_keyframes_its_own_way() {
        let css = "@keyframes scale{0%, 100%{transform:none}50%{transform:scale3d(1, 1, 1)}}\
            @keyframes unspin{40%{stroke-width:1px;stroke-linecap:square;stroke-dashoffset:192}100%{stroke-width:0}}";
        let spelled = |engine| -> Vec<String> {
            rules(css)
                .iter()
                .map(|rule| keyframes(rule, engine))
                .collect()
        };
        assert_eq!(
            spelled(Engine::Chromium),
            [
                "@keyframes scale { \n  0%, 100% { transform: none; }\n  50% { transform: scale3d(1, 1, 1); }\n}",
                "@keyframes unspin { \n  40% { stroke-width: 1px; stroke-linecap: square; stroke-dashoffset: 192; }\n  100% { stroke-width: 0; }\n}",
            ]
        );
        assert_eq!(
            spelled(Engine::WebKit),
            [
                "@keyframes scale { \n  0%,100% { transform: none; }\n  50% { transform: scale3d(1, 1, 1); }\n}",
                "@keyframes unspin { \n  40% { stroke-width: 1px; stroke-linecap: square; stroke-dashoffset: 192; }\n  100% { stroke-width: 0px; }\n}",
            ]
        );
    }
}
