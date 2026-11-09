//! Extracts session parameters from syntax and usage without relying on randomized names.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use oxc::ast::ast::{
    Argument, AssignmentExpression, BinaryExpression, CallExpression, Expression, Function,
    IfStatement, ObjectExpression, UnaryExpression,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::ScopeFlags;
use oxc::syntax::operator::{AssignmentOperator, LogicalOperator, UnaryOperator};
use scraper::{Html, Selector};
use url::Url;

use crate::candidates;
use crate::challenge::expression;
use crate::js::ast::{self, Script};
use crate::js::{JsValue, Options};
use crate::script::Source;

/// Whether `text` is a randomized name in the form newer builds use: `_` and 24 lowercase hex
/// digits, such as `_2b78d2cde0fa83bfaec4edae`.
pub(crate) fn is_hex_name(text: &str) -> bool {
    text.strip_prefix('_').is_some_and(|hex| {
        hex.len() == 24
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Minimum property count distinguishing a payload template from an ordinary options object.
const PAYLOAD_FIELDS: usize = 20;
/// Stable prefix of the initial challenge type: `chl_api_m` for managed widgets or `chl_api_ni`
/// for non-interactive widgets. The containing option name varies by session.
const INITIAL_CHALLENGE: &str = "chl_api_";
/// Challenge types used by page orchestrators. Count these only when no option has an iframe's
/// `chl_api_` type. A page may require interaction but cannot be invisible.
const PAGE_CHALLENGES: [&str; 3] = ["managed", "non-interactive", "interactive"];
/// Turnstile iframe modes echoed by the embedding page's summary.
const WIDGET_MODES: [&str; 3] = ["managed", "non-interactive", "invisible"];

/// The request carrying the session's first payload, as its bootstrap script builds it.
#[derive(Debug, Clone)]
pub struct InitialRequest {
    pub url: Url,
    /// The token the POST carries in its `cf-chl` header.
    pub cf_chl: String,
    /// The `_cf_chl_opt` object the bootstrap installs.
    pub options: Options,
}

impl InitialRequest {
    pub fn ray(&self) -> Result<&str> {
        ray(&self.url)
    }

    #[cfg(test)]
    pub(crate) fn from_javascript(source: &str, iframe_url: &Url) -> Result<Self> {
        Self::from_script(ast::ParsedScript::parse("t", source)?.script(), iframe_url)
    }

    pub(crate) fn from_script(script: Script<'_>, iframe_url: &Url) -> Result<Self> {
        let options = bootstrap_options(script);
        ensure!(!options.is_empty(), "missing _cf_chl_opt object");
        let mut request = Request {
            script,
            options: &options,
            paths: BTreeSet::new(),
            tokens: BTreeSet::new(),
        };
        request.visit_program(script.program);
        let token = candidates::exactly_one(request.tokens, "cf-chl token")?;
        let path = candidates::exactly_one(
            request
                .paths
                .into_iter()
                .filter(|path| path.rsplit('/').next() == Some(token.as_str())),
            "initial /fo/ URL matching cf-chl",
        )?;
        let url = iframe_url.join(&path)?;
        ensure!(
            url.origin() == iframe_url.origin(),
            "POST URL changed origin"
        );
        Ok(Self {
            url,
            cf_chl: token,
            options,
        })
    }
}

/// Whether `path` is a challenge-platform `/fo/` path, where challenge payloads are posted.
#[must_use]
pub fn is_post_path(path: &str) -> bool {
    path.starts_with("/cdn-cgi/challenge-platform/") && path.contains("/fo/")
}

/// The ray a challenge POST `url` carries after `/fo/<id>/`.
pub fn ray(url: &Url) -> Result<&str> {
    url.path()
        .split("/fo/")
        .nth(1)
        .and_then(|path| path.split('/').nth(1))
        .context("the challenge URL carries no ray")
}

/// Reads bootstrap `_cf_chl_opt` values and later static assignments. Returns an empty map if
/// the script installs no options.
#[must_use]
pub(crate) fn bootstrap_options(script: Script<'_>) -> Options {
    let mut assigned = StaticOptions {
        script,
        options: Options::new(),
    };
    assigned.visit_program(script.program);
    let mut renames = Renames::default();
    renames.visit_program(script.program);
    let mut options = assigned.options;
    for (to, from) in renames.copies {
        if renames.deleted.contains(&from)
            && !options.contains_key(&to)
            && let Some(value) = options.shift_remove(&from)
        {
            options.insert(to, value);
        }
    }
    options
}

/// The mode this session's widget runs in (see [`WIDGET_MODES`]). Its option
/// name is randomised, but its value is not.
#[must_use]
pub(crate) fn mode(options: &Options) -> Option<&str> {
    options
        .values()
        .filter_map(JsValue::as_str)
        .find(|value| WIDGET_MODES.contains(value))
}

/// Reads the `api.js` build, padded to twelve hex digits, that this session requires. If it
/// differs from the loader's `ch`, the iframe saves the parameters and asks the page to reload
/// `api.js`. Conflicting candidates produce no build.
#[must_use]
pub(crate) fn expected_build(source: &Source) -> Option<String> {
    #[derive(Default)]
    struct Builds(Vec<String>);
    impl<'a> Visit<'a> for Builds {
        fn visit_binary_expression(&mut self, binary: &BinaryExpression<'a>) {
            if let Some(build) = expression::padded_build(binary).filter(|build| build.len() == 12)
            {
                self.0.push(build);
            }
            walk::walk_binary_expression(self, binary);
        }
    }
    let mut builds = Builds::default();
    builds.visit_program(source.script().program);
    candidates::at_most_one_distinct(builds.0, "loader build").ok()?
}

/// Identifies a payload template by its size and a field that reads the initial challenge type
/// option.
#[must_use]
pub(crate) fn is_payload_template(object: &ObjectExpression<'_>, options: &Options) -> bool {
    let challenge = |value: &str| value.starts_with(INITIAL_CHALLENGE);
    let in_iframe = options
        .values()
        .any(|value| value.as_str().is_some_and(challenge));
    // The string values of the options the fields read.
    let mut read = ast::key_values(object).filter_map(|property| {
        let member = property.value.as_member_expression()?;
        options.get(ast::member_str(member)?)?.as_str()
    });
    object.properties.len() > PAYLOAD_FIELDS
        && read.any(|value| challenge(value) || !in_iframe && PAGE_CHALLENGES.contains(&value))
}

/// Visits branches using known option values. For a condition guarded by an unset option,
/// visits only `else`; otherwise visits both branches. This skips an unused second payload
/// template in page orchestrators.
pub(crate) fn visit_taken_branches<'a, V: Visit<'a>>(
    visitor: &mut V,
    conditional: &IfStatement<'a>,
    options: &Options,
) {
    if expression::option_key(conditional.test.without_parentheses())
        .is_some_and(|option| !options.contains_key(option))
    {
        if let Some(alternate) = &conditional.alternate {
            visitor.visit_statement(alternate);
        }
    } else {
        walk::walk_if_statement(visitor, conditional);
    }
}

/// Follows option renaming during orchestrator startup. Recognizes copies of
/// `_cf_chl_opt.<old>` to `_cf_chl_opt.<new>`, optionally with an `override ||` fallback.
/// Counts a copy as a rename only if the script also deletes the old option.
#[derive(Default)]
struct Renames {
    /// `(to, from)` pairs.
    copies: Vec<(String, String)>,
    deleted: Vec<String>,
}

impl<'a> Visit<'a> for Renames {
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        let source = match assignment.right.without_parentheses() {
            Expression::LogicalExpression(logical) if logical.operator == LogicalOperator::Or => {
                logical.right.without_parentheses()
            }
            other => other,
        };
        if assignment.operator == AssignmentOperator::Assign
            && let Some(to) = expression::option_assignment(&assignment.left)
            && let Some(from) = expression::option_key(source)
        {
            self.copies.push((to.to_owned(), from.to_owned()));
        }
        walk::walk_assignment_expression(self, assignment);
    }

    fn visit_unary_expression(&mut self, unary: &UnaryExpression<'a>) {
        if unary.operator == UnaryOperator::Delete
            && let Some(option) = expression::option_key(unary.argument.without_parentheses())
        {
            self.deleted.push(option.to_owned());
        }
        walk::walk_unary_expression(self, unary);
    }
}

/// The options the script assigns statically.
struct StaticOptions<'a> {
    script: Script<'a>,
    options: Options,
}

impl<'a> Visit<'a> for StaticOptions<'a> {
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let Some(member) = assignment.left.as_member_expression() {
            if ast::member_str(member) == Some("_cf_chl_opt") {
                if let Some(JsValue::Object(options)) =
                    expression::static_value(self.script, &assignment.right, &Options::new())
                {
                    self.options = Options::from(options);
                }
            } else if expression::is_options(member.object())
                && let (Some(key), Some(value)) = (
                    ast::member_str(member),
                    expression::static_value(self.script, &assignment.right, &self.options),
                )
            {
                self.options.insert(key.to_owned(), value);
            }
        }
        walk::walk_assignment_expression(self, assignment);
    }

    // Only the bootstrap IIFE, entered below, runs now. Other functions mutate the options
    // later, and their writes must not overwrite the bootstrap values.
    fn visit_function(&mut self, _: &Function<'a>, _: ScopeFlags) {}

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Expression::FunctionExpression(function) = call.callee.without_parentheses()
            && let Some(body) = &function.body
        {
            self.visit_function_body(body);
        }
    }
}

struct Request<'options, 'a> {
    script: Script<'a>,
    options: &'options Options,
    paths: BTreeSet<String>,
    tokens: BTreeSet<String>,
}

impl<'a> Visit<'a> for Request<'_, 'a> {
    fn visit_expression(&mut self, expression: &Expression<'a>) {
        // Only inspect string concatenations, avoiding evaluation of complete
        // function bodies or the encoded VM program.
        if matches!(
            expression,
            Expression::BinaryExpression(_)
                | Expression::LogicalExpression(_)
                | Expression::TemplateLiteral(_)
                | Expression::StringLiteral(_)
        ) && let Some(JsValue::String(path)) =
            expression::static_value(self.script, expression, self.options)
            && is_post_path(&path)
        {
            self.paths.insert(path);
        }
        walk::walk_expression(self, expression);
    }

    /// Finds arguments to `<request>.setRequestHeader('cf-chl', <token>)`, even when the method
    /// name comes from a variable.
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        let value = |argument: &Argument<'_>| {
            expression::static_value(self.script, argument.as_expression()?, self.options)
        };
        if let [header, token] = &call.arguments[..]
            && value(header) == Some(JsValue::String("cf-chl".into()))
            && let Some(JsValue::String(token)) = value(token)
        {
            self.tokens.insert(token);
        }
        walk::walk_call_expression(self, call);
    }
}

/// Joins inline scripts from challenge `html`. HTML parsing preserves raw script text,
/// including `<` and text resembling entities.
pub fn inline_javascript(html: &str) -> Result<String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("script").expect("static selector");
    let inline = document.select(&selector).filter(|script| {
        let script = script.value();
        script.attr("src").is_none()
            && matches!(
                script.attr("type").unwrap_or(""),
                "" | "text/javascript" | "application/javascript"
            )
    });
    let scripts: Vec<String> = inline.map(|script| script.text().collect()).collect();
    let javascript = scripts.join("\n;\n");
    ensure!(
        javascript.contains("_cf_chl_opt"),
        "iframe contains no challenge options; inspect the returned HTML"
    );
    Ok(javascript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deobfuscate;

    #[test]
    fn extracts_requests_after_folding_parenthesized_helpers_and_cached_paths() {
        let javascript = r#"window._cf_chl_opt = {variant:'g',ray:'ray-id',token:'session-token'};
            (function(global) {
                var prefix, path;
                var options = function(value) { return value._cf_chl_opt; };
                function send(xhr) {
                    xhr.setRequestHeader('cf-chl', (27253 ^ (36202 ^ 59167), options)(global).token);
                    xhr.open('POST', (prefix || (prefix = '/cdn-cgi/challenge-platform/h/'))
                        + global._cf_chl_opt.variant + (path || (path = '/fo/build/'))
                        + global._cf_chl_opt.ray + '/' + global._cf_chl_opt.token);
                }
                install(send);
            })(window);"#;
        let text = deobfuscate::deobfuscate(javascript.to_owned()).unwrap();
        assert!(text.unconverged.is_none());
        let request = InitialRequest::from_javascript(
            &text.text,
            &Url::parse("https://example.com/").unwrap(),
        )
        .unwrap_or_else(|error| panic!("{error:#}\n{}", text.text));
        assert_eq!(request.cf_chl, "session-token");
        assert_eq!(
            request.url.path(),
            "/cdn-cgi/challenge-platform/h/g/fo/build/ray-id/session-token"
        );
    }

    #[test]
    fn finds_session_parameters_with_different_randomized_names() {
        for (variant, ray, token) in [("aaa", "bbb", "ccc"), ("Q7", "jJ1", "zyZ")] {
            let source = format!(
                r#"(function() {{
                    window._cf_chl_opt = {{ {variant}: 'g', {ray}: 'ray-id', {token}: 'session-token',
                        callback: function() {{ window._cf_chl_opt.{token} = 'wrong-token'; }}
                    }};
                }})();
                ~function() {{
                    function sender(method) {{
                        method = 'setRequestHeader';
                        xhr[method]('cf-chl', global._cf_chl_opt['{token}']);
                    }}
                    function start() {{
                        var path = '/cdn-cgi/challenge-platform/h/' + global._cf_chl_opt.{variant}
                            + `/fo/build/` + global._cf_chl_opt.{ray} + '/' + global._cf_chl_opt.{token};
                    }}
                }}();"#
            );
            let base = Url::parse("https://challenges.cloudflare.com/iframe").unwrap();
            let request = InitialRequest::from_javascript(&source, &base).unwrap();
            assert_eq!(
                request.url.path(),
                "/cdn-cgi/challenge-platform/h/g/fo/build/ray-id/session-token"
            );
            assert_eq!(request.cf_chl, "session-token");
            assert!(!request.options.contains_key("callback"));
        }
    }

    #[test]
    fn finds_payload_template_for_managed_and_non_interactive_widgets() {
        let fields: String = (0..PAYLOAD_FIELDS)
            .map(|index| format!("f{index}: {index}, "))
            .collect();
        let template = format!("{{ {fields}kind: b._cf_chl_opt.mode }}");
        ast::with_expression(&template, |_, template| {
            let Expression::ObjectExpression(template) = template else {
                panic!("not an object");
            };
            // An iframe uses its `chl_api_` type. A page type is valid only for an orchestrator
            // with no `chl_api_` option.
            for (challenge, other, expected) in [
                ("chl_api_m", "x", true),
                ("chl_api_ni", "x", true),
                ("managed", "chl_api_m", false),
                ("managed", "x", true),
                ("unknown", "x", false),
            ] {
                let options = Options::from_iter([
                    ("mode".to_owned(), JsValue::from(challenge)),
                    ("other".to_owned(), JsValue::from(other)),
                ]);
                assert_eq!(
                    is_payload_template(template, &options),
                    expected,
                    "{challenge}"
                );
            }
        });
    }

    #[test]
    fn follows_an_orchestrators_moved_options() {
        let source = r#"(function() {
                window._cf_chl_opt = { cFPWv: 'b', cH: 'session-token', cRay: 'ray-id', cType: 'managed' };
            })();
            ~function() {
                function start() {
                    global._cf_chl_opt.variant = global.override || global._cf_chl_opt.cFPWv;
                    delete global._cf_chl_opt.cFPWv;
                    global._cf_chl_opt.token = global._cf_chl_opt.cH;
                    delete global._cf_chl_opt.cH;
                    global._cf_chl_opt.ray = global._cf_chl_opt.cRay;
                    delete global._cf_chl_opt.cRay;
                    // A copy whose source stays is not a move.
                    global._cf_chl_opt.kind = global._cf_chl_opt.cType;
                    var path = '/cdn-cgi/challenge-platform/h/' + global._cf_chl_opt.variant
                        + `/fo/build/` + global._cf_chl_opt.ray + '/' + global._cf_chl_opt.token;
                    xhr.setRequestHeader('cf-chl', global._cf_chl_opt.token);
                }
            }();"#;
        let base = Url::parse("https://example.com/protected").unwrap();
        let request = InitialRequest::from_javascript(source, &base).unwrap();
        assert_eq!(
            request.url.as_str(),
            "https://example.com/cdn-cgi/challenge-platform/h/b/fo/build/ray-id/session-token"
        );
        assert_eq!(request.cf_chl, "session-token");
        assert!(!request.options.contains_key("cH"));
        assert_eq!(request.options["cType"], "managed");
        assert!(!request.options.contains_key("kind"));
    }

    #[test]
    fn rejects_missing_or_ambiguous_session_instead_of_using_old_values() {
        let base = Url::parse("https://challenges.cloudflare.com/iframe").unwrap();
        assert!(InitialRequest::from_javascript("window._cf_chl_opt = {};", &base).is_err());
        let source = r#"window._cf_chl_opt = {a: 'first', b: 'second'};
            xhr.setRequestHeader('cf-chl', window._cf_chl_opt.a);
            xhr.setRequestHeader('cf-chl', window._cf_chl_opt.b);"#;
        assert!(
            InitialRequest::from_javascript(source, &base)
                .unwrap_err()
                .to_string()
                .contains("found 2")
        );
    }

    #[test]
    fn reads_the_expected_build_however_its_constant_is_spelled() {
        let parse = |source: &str| Source::try_new(source).unwrap();
        for source in [
            r#"m = ("000000000000" + 0xe694063b5082.toString(16)).slice(-12);"#,
            r#"m = ('000000000000'+253523434098818..toString(16)).slice(-12);"#,
            r#"m = (`000000000000` + 0XE694063B5082.toString(0x10)).slice(-12);"#,
            // The same build twice is no conflict.
            r#"m = "000000000000" + 0xe694063b5082.toString(16); n = "000000000000" + 253523434098818..toString(16);"#,
        ] {
            assert_eq!(
                expected_build(&parse(source)).as_deref(),
                Some("e694063b5082"),
                "{source:.80}"
            );
        }
        for source in [
            r#"m = "000000000000" + 0xe694063b5082.toString(16); n = "000000000000" + 0x1.toString(16);"#,
            // Without the radix the digits would be decimal.
            r#"m = "000000000000" + 0xe694063b5082;"#,
            r#"m = "000000000000" + 0xe694063b5082.toString(10);"#,
            r#"m = "000000000000" + build.toString(16);"#,
            // Thirteen digits do not fit the padding.
            r#"m = "000000000000" + 0x1e694063b5082.toString(16);"#,
            "m = 1;",
        ] {
            assert_eq!(expected_build(&parse(source)), None, "{source}");
        }
    }

    #[test]
    fn reads_the_ray_from_the_challenge_url() {
        let url = Url::parse(
            "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/flow/ov1/0.1:1:abc/fo/session/8f3c2a1b9d4e5f60",
        )
        .unwrap();
        assert_eq!(ray(&url).unwrap(), "8f3c2a1b9d4e5f60");
        assert!(ray(&Url::parse("https://challenges.cloudflare.com/no-ray").unwrap()).is_err());
    }

    #[test]
    fn extracts_raw_inline_javascript_without_json_or_external_scripts() {
        let source = inline_javascript(
            r#"<script src="api.js"></script>
            <script type="application/json">{"ignored":true}</script>
            <script nonce="x">window._cf_chl_opt = {}; if (1 < 2) x = '&amp;';</script>
            <script>another();</script>"#,
        )
        .unwrap();
        assert!(source.contains("if (1 < 2) x = '&amp;'"));
        assert!(source.contains("\n;\nanother();"));
        assert!(!source.contains("ignored"));
    }
}
