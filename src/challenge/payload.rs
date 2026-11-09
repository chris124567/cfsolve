//! Builds the plaintext first challenge payload by evaluating the template's field expressions
//! against session options and the script's namespace.

use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result, ensure};
use oxc::ast::ast::{Expression, Statement};
use oxc::syntax::operator::BinaryOperator;
use regex::Regex;

use crate::challenge::expression;
use crate::challenge::state::{Difference, Getter, ScriptState};
use crate::js::ast::{self, ParsedScript, Script};
use crate::js::{JsValue, Options, Payload, Window, json};
use crate::random_id;

/// The global selector log serialized in the payload. Starts empty.
#[must_use]
pub(crate) fn selector_log(fields: &[Field]) -> Option<String> {
    fields.iter().find_map(|field| match field.global()? {
        (name, Shape::Stringified) => Some(name.to_owned()),
        _ => None,
    })
}

/// Supplies globals read by payload fields. Uses values installed by the initial program when
/// available; otherwise infers the value from the expression. Getter calls read options,
/// stringified reads report arrays, and plain reads report the interaction tally or a per-load
/// identifier.
#[must_use]
pub(crate) fn infer_globals(
    fields: &[Field],
    script: &ScriptState,
    options: &Options,
    installed: &Window,
) -> Window {
    let mut globals = Window::new();
    for field in fields {
        let Some((name, shape)) = field.global() else {
            continue;
        };
        let value = match (installed.get(name), shape) {
            (Some(value), _) => value.clone(),
            // Initialize the getter from its option, which is empty until the script writes it.
            (None, Shape::Called) => script
                .getters
                .get(name)
                .and_then(|getter| called(getter, options))
                .unwrap_or_else(|| json!([])),
            // No interaction has been recorded, so the collection is empty.
            (None, Shape::Stringified) => json!([]),
            (None, Shape::Read) => match &script.counters {
                Some(tally) if tally.global == name => JsValue::Object(
                    tally
                        .counters
                        .iter()
                        .map(|counter| (counter.clone(), json!(0)))
                        .collect(),
                ),
                // Generate a per-load identifier with the same format as session names.
                _ => json!(random_id::random_id(
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    6
                )),
            },
        };
        globals.insert(name.to_owned(), value);
    }
    globals
}

/// The value `getter` returns: its option, with each render sample's stack split at page URLs
/// if the getter does so.
fn called(getter: &Getter, options: &Options) -> Option<JsValue> {
    let mut value = options.get(&getter.option)?.clone();
    if let Some(origin) = &getter.page_origin
        && let JsValue::Array(samples) = &mut value
    {
        let origin = options
            .get(origin)
            .and_then(JsValue::as_str)
            .unwrap_or_default();
        for sample in samples {
            if let JsValue::Object(sample) = sample
                && let Some(stack) = sample.get("s").and_then(JsValue::as_str)
            {
                let split = split_page_urls(stack, origin);
                sample.insert("s".to_owned(), split);
            }
        }
    }
    Some(value)
}

/// Splits `stack` as the iframe's sample getter does. Each URL on `origin`, less a trailing
/// `:line` or `:line:column`, becomes the index of that URL in a list of at most 64. Returns
/// `[parts, urls]`, where `parts` alternates text and indices and ends with text.
fn split_page_urls(stack: &str, origin: &str) -> JsValue {
    const MAX_URLS: usize = 64;
    static URL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"https?://[^\s)"'<>]+"#).expect("the URL pattern is valid"));
    static POSITION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r":[0-9]+(?::[0-9]+)?$").expect("the position pattern is valid")
    });
    let mut parts = Vec::new();
    let mut urls: Vec<&str> = Vec::new();
    let mut copied = 0;
    for found in URL.find_iter(stack) {
        let url = found.as_str();
        let url = POSITION
            .find(url)
            .map_or(url, |position| &url[..position.start()]);
        if url != origin && !url.starts_with(&format!("{origin}/")) {
            continue;
        }
        let index = match urls.iter().position(|known| *known == url) {
            Some(index) => index,
            None if urls.len() >= MAX_URLS => continue,
            None => {
                urls.push(url);
                urls.len() - 1
            }
        };
        parts.push(json!(&stack[copied..found.start()]));
        parts.push(json!(index));
        copied = found.start() + url.len();
    }
    parts.push(json!(&stack[copied..]));
    json!([parts, urls])
}

/// A payload template field. The expression is parsed from its source text on its own, so the
/// field outlives the script it came from; the text is the expression exactly as written there.
#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    /// The expression's original source text.
    pub text: String,
    /// Static value before the session runs, if known.
    pub bootstrap_value: Option<JsValue>,
    parsed: Arc<ParsedScript>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Read,
    Called,
    Stringified,
}

impl Field {
    /// Parses the field expression `text`. Every identifier in it is unresolved, so locals of the
    /// script it came from read as globals.
    pub(crate) fn parse(
        name: String,
        text: String,
        bootstrap_value: Option<JsValue>,
    ) -> Result<Self> {
        // Parentheses make leading braces parse as an object literal.
        let parsed = ParsedScript::parse("payload field", &format!("({text})"))?;
        ensure!(
            matches!(
                parsed.script().program.body.as_slice(),
                [Statement::ExpressionStatement(_)]
            ),
            "payload field {name} is not one expression: {text}"
        );
        Ok(Self {
            name,
            text,
            bootstrap_value,
            parsed: Arc::new(parsed),
        })
    }

    /// The field's script and its expression, without surrounding parentheses.
    fn expression(&self) -> (Script<'_>, &Expression<'_>) {
        let script = self.parsed.script();
        let [Statement::ExpressionStatement(statement)] = script.program.body.as_slice() else {
            unreachable!("a field holds one expression, checked when it was parsed");
        };
        (script, statement.expression.without_parentheses())
    }

    /// Returns the option reported by this field, whether read directly or through a namespace
    /// getter.
    #[must_use]
    pub(crate) fn option<'a>(&'a self, script: &'a ScriptState) -> Option<&'a str> {
        expression::option_key(self.expression().1).or_else(|| match self.global()? {
            (name, Shape::Called) => script
                .getters
                .get(name)
                .map(|getter| getter.option.as_str()),
            _ => None,
        })
    }

    /// Returns the two options subtracted by this field, if it reports a time difference.
    #[must_use]
    pub(crate) fn difference(&self) -> Option<Difference> {
        match self.expression().1 {
            Expression::BinaryExpression(binary)
                if binary.operator == BinaryOperator::Subtraction =>
            {
                Some(Difference {
                    later: expression::option_key(&binary.left)?.to_owned(),
                    earlier: expression::option_key(&binary.right)?.to_owned(),
                })
            }
            _ => None,
        }
    }

    /// The namespace property this field reads, if any.
    fn global(&self) -> Option<(&str, Shape)> {
        fn global<'a>(expression: &Expression<'a>) -> Option<&'a str> {
            ast::ident_property(expression.as_member_expression()?)
        }
        let (script, expression) = self.expression();
        match expression {
            Expression::CallExpression(call) => match &call.callee {
                callee
                    if callee
                        .as_member_expression()
                        .is_some_and(|member| script.is_method_of(member, "JSON", "stringify")) =>
                {
                    Some((
                        global(call.arguments.first()?.as_expression()?)?,
                        Shape::Stringified,
                    ))
                }
                callee => Some((global(callee)?, Shape::Called)),
            },
            expression => Some((global(expression)?, Shape::Read)),
        }
    }
}

/// Finds option pairs whose time difference appears in the payload.
#[must_use]
pub(crate) fn differences(fields: &[Field]) -> Vec<Difference> {
    fields.iter().filter_map(Field::difference).collect()
}

/// Evaluates fields against session options, omitting `undefined` values as `JSON.stringify`
/// does.
pub(crate) fn build(fields: &[Field], options: &Options, globals: &Window) -> Result<Payload> {
    let mut payload = Payload::new();
    for field in fields {
        let (script, expression) = field.expression();
        let value = expression::evaluate(script, expression, options, globals)
            .with_context(|| format!("evaluating payload field {}: {}", field.name, field.text))?;
        if let Some(value) = value {
            payload.insert(field.name.clone(), value);
        }
    }
    ensure!(!payload.is_empty(), "no payload field could be evaluated");
    Ok(payload)
}

/// Appends the sender's fields in the script's insertion order, which `JSON.stringify` keeps:
/// collected resource timings (if any), payload duration, then forwarded options.
pub(crate) fn append_send_time(
    payload: &mut Payload,
    script: &ScriptState,
    options: &Options,
    resources: &[JsValue],
    elapsed: i64,
) {
    if let Some(timing) = &script.timing
        && !resources.is_empty()
    {
        payload.insert(timing.option.clone(), json!(resources));
    }
    if let Some(sender) = &script.elapsed {
        payload.insert(sender.key.clone(), json!(elapsed));
    }
    for key in &script.forwarded {
        if let Some(value) = options.get(key) {
            payload.insert(key.clone(), value.clone());
        }
    }
}

/// Appends send-time fields without resource timings. Measures duration from the start mark to
/// `send_at`; see [`append_send_time`].
pub(crate) fn append_send_time_at(
    payload: &mut Payload,
    script: &ScriptState,
    options: &Options,
    send_at: i64,
) {
    let elapsed = script
        .elapsed
        .as_ref()
        .and_then(|sender| options.get(&sender.mark)?.as_i64())
        .map_or(0, |mark| send_at - mark);
    append_send_time(payload, script, options, &[], elapsed);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::challenge::reduced_timing::ResourceTiming;
    use crate::challenge::state::Elapsed;
    use crate::challenge::tally::Tally;

    /// Page URLs become indices into a list of distinct URLs; other hosts stay in the text.
    #[test]
    fn splits_stacks_at_page_urls() {
        let stack = "Error\n    at f (https://captchatest.book.bi/app.js:1:20)\n    at g \
                     (https://challenges.cloudflare.com/turnstile/v0/api.js:2:7)\n    at h \
                     (https://captchatest.book.bi/app.js:3:4)";
        assert_eq!(
            split_page_urls(stack, "https://captchatest.book.bi"),
            json!([
                [
                    "Error\n    at f (",
                    0,
                    ":1:20)\n    at g (https://challenges.cloudflare.com/turnstile/v0/api.js:2:7)\n    at h (",
                    0,
                    ":3:4)"
                ],
                ["https://captchatest.book.bi/app.js"]
            ])
        );
        // As in the captured sessions, a stack without page URLs stays whole.
        assert_eq!(
            split_page_urls(stack, "https://example.com"),
            json!([[stack], []])
        );
        assert_eq!(split_page_urls(stack, ""), json!([[stack], []]));
        assert_eq!(
            split_page_urls("at https://a.b:443/x.js:2:7", "https://a.b:443"),
            json!([["at ", 0, ":2:7"], ["https://a.b:443/x.js"]])
        );
    }

    fn field(name: &str, text: &str) -> Field {
        Field::parse(name.into(), text.into(), None).unwrap()
    }

    /// Checks JavaScript evaluation and omission of `undefined` fields during JSON
    /// serialization.
    #[test]
    fn evaluates_fields_with_javascript_semantics() {
        let options = Options::from_iter([
            ("a".to_owned(), json!(1)),
            ("b".to_owned(), json!(5)),
            ("o".to_owned(), json!({})),
        ]);
        // Each field as `JSON.stringify` writes it, or `None` when it leaves it out.
        let cases = [
            ("e._cf_chl_opt.a", Some("1")),
            ("e._cf_chl_opt.missing", None),
            ("(e._cf_chl_opt.missing || {}).x", None),
            ("undefined", None),
            ("JSON.stringify(e.missing)", None),
            ("null", Some("null")),
            ("[undefined, null, e.missing]", Some("[null,null,null]")),
            (
                "({a: undefined, b: null, c: x(), d: 1})",
                Some(r#"{"b":null,"d":1}"#),
            ),
            ("JSON.stringify(null)", Some(r#""null""#)),
            (
                "JSON.stringify({b: 1, a: 2.5})",
                Some(r#""{\"b\":1,\"a\":2.5}""#),
            ),
            ("!undefined", Some("true")),
            ("![]", Some("false")),
            ("null || 3", Some("3")),
            ("[] || x()", Some("[]")),
            ("true + null", Some("1")),
            ("[1, null, 2] + {}", Some(r#""1,,2[object Object]""#)),
            ("undefined + 'x'", Some(r#""undefinedx""#)),
            ("1 === 1.0", Some("true")),
            ("1 === '1'", Some("false")),
            ("null === undefined", Some("false")),
            ("null !== undefined", Some("true")),
            ("undefined === {}", Some("false")),
            ("[] === undefined", Some("false")),
            ("({}) === null", Some("false")),
            // Sessions send `!(_cf_chl_opt.<flag> !== 1)`, which is `false`
            // rather than absent when the flag was never set.
            ("!(e._cf_chl_opt.missing !== 1)", Some("false")),
            ("!(e._cf_chl_opt.a !== 1)", Some("true")),
            ("e._cf_chl_opt.missing === undefined", Some("true")),
            // `+` and `-` coerce as JavaScript does; `NaN` serialises as `null`.
            ("e._cf_chl_opt.b - e._cf_chl_opt.a", Some("4")),
            ("e._cf_chl_opt.a + 1", Some("2")),
            ("'x' + e._cf_chl_opt.a", Some(r#""x1""#)),
            ("e._cf_chl_opt.o - 1", Some("null")),
            ("e._cf_chl_opt.a - e._cf_chl_opt.missing", Some("null")),
            // The right-hand side is never reached when the left is truthy.
            ("e._cf_chl_opt.a || x()", Some("1")),
        ];
        let fields: Vec<_> = cases.iter().map(|(text, _)| field(text, text)).collect();
        let built = build(&fields, &options, &Window::new()).unwrap();
        for (text, expected) in cases {
            let sent = built.get(text).and_then(JsValue::stringify);
            assert_eq!(sent.as_deref(), expected, "{text}");
        }
    }

    #[test]
    fn unsupported_expressions_fail_naming_their_field() {
        let options = Options::from_iter([("a".to_owned(), json!(1)), ("o".to_owned(), json!({}))]);
        for (text, reason) in [
            ("e._cf_chl_opt.a * 2", "unsupported operator *"),
            ("!foo()", "unsupported call"),
            ("e._cf_chl_opt.missing.x", "reads x of undefined"),
            ("e._cf_chl_opt.o === e._cf_chl_opt.o", "identity comparison"),
            ("bare", "unsupported expression"),
            ("[1,,2]", "unsupported array hole"),
            ("[...[]]", "unsupported spread element"),
            ("JSON.stringify()", "unsupported JSON.stringify arguments"),
            ("JSON.stringify(...[])", "unsupported spread argument"),
            ("(JSON.stringify)(null)", "unsupported call"),
            ("null.x", "unsupported read of x from null"),
            ("[] === {}", "identity comparison"),
            ("[] !== []", "identity comparison"),
            ("`${e._cf_chl_opt.a}`", "unsupported template"),
            // Short-circuiting reaches the right-hand side here.
            ("e._cf_chl_opt.missing || x()", "unsupported call"),
        ] {
            let fields = vec![field("ok", "1"), field("bad", text)];
            let error = build(&fields, &options, &Window::new()).unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains("payload field bad"), "{text}: {error}");
            assert!(error.contains(reason), "{text}: {error}");
        }
    }

    #[test]
    fn infers_globals_from_the_window_the_analysis_and_their_shape() {
        let fields = vec![
            field("id", "e.unknown"),
            field("tally", "e.tally"),
            field("called", "e.getter()"),
            field("selectors", "JSON.stringify(e.log)"),
        ];
        let script = ScriptState {
            counters: Some(Tally {
                global: "tally".into(),
                counters: vec!["a".into()],
            }),
            getters: BTreeMap::from([(
                "getter".into(),
                Getter {
                    option: "opt".into(),
                    page_origin: None,
                },
            )]),
            ..ScriptState::default()
        };
        let options = Options::from_iter([("opt".to_owned(), json!(["x"]))]);
        let installed = Window::from_iter([("unknown".to_owned(), json!("loadId"))]);
        let globals = infer_globals(&fields, &script, &options, &installed);
        assert_eq!(
            JsValue::from(globals),
            json!({"unknown": "loadId", "tally": {"a": 0}, "getter": ["x"], "log": []})
        );

        let guessed = infer_globals(&fields, &script, &options, &Window::new());
        assert_eq!(
            guessed["unknown"].as_str().unwrap().len(),
            6,
            "a guess draws an identifier for the unknown read"
        );
        assert_eq!(guessed["getter"], json!(["x"]));
    }

    /// The builder attaches the timings before the sender adds its own keys.
    #[test]
    fn appends_timings_before_the_senders_keys() {
        let script = ScriptState {
            elapsed: Some(Elapsed {
                key: "elapsed".into(),
                mark: "mark".into(),
            }),
            forwarded: vec!["forwarded".into()],
            timing: Some(ResourceTiming {
                option: "timings".into(),
                fields: Vec::new(),
            }),
            ..ScriptState::default()
        };
        let options = Options::from_iter([("forwarded".to_owned(), json!("x"))]);
        let mut payload = Payload::from_iter([("literal".to_owned(), json!(1))]);
        append_send_time(&mut payload, &script, &options, &[json!({})], 5);
        let keys: Vec<_> = payload.keys().cloned().collect();
        assert_eq!(keys, ["literal", "timings", "elapsed", "forwarded"]);
    }
}
