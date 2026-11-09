//! Reads Cloudflare's challenge page, served with status 403 as "Just a moment...".
//!
//! The page's inline script installs options and loads an orchestrator from the protected
//! site's origin, which uses the iframe's VM and encoder. Its first response program renders a
//! Turnstile widget; after the widget completes, a second POST returns a program that submits
//! the form that obtains the clearance cookie.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use oxc::ast::ast::{
    AssignmentExpression, BinaryExpression, CallExpression, Expression, MemberExpression,
};
use oxc::ast_visit::{Visit, walk};
use oxc::semantic::{ScopeFlags, SymbolId};
use oxc::syntax::operator::BinaryOperator;
use url::Url;

use crate::candidates;
use crate::challenge::{expression, source};
use crate::js::ast::{self, ParsedScript, Script};
use crate::js::{JsValue, Options};
use crate::script::Source;

/// The orchestrator is served from this path prefix of the challenge page's origin.
const ORCHESTRATOR: &str = "/orchestrate/";
/// Query parameter used in the temporary page address while the orchestrator loads.
const LOADING_TOKEN: &str = "__cf_chl_rt_tk=";
/// The loader path the orchestrator builds.
const LOADER: &str = "/api.js?onload=";
/// Fixed page option holding the address to restore after the challenge. The orchestrator
/// renames page options during startup.
const ANSWERED: &str = "cUPMDTk";

/// A challenge page, as the protected site served it.
#[derive(Debug, Clone)]
pub(crate) struct ChallengePage {
    pub url: Url,
    pub html: String,
    /// The inline script that installs the options and loads the orchestrator.
    pub inline: String,
    pub orchestrator: Url,
    /// Temporary page URL, the referrer while the orchestrator loads.
    pub loading: Url,
    /// Page address restored after the challenge, which the clearance form is submitted from.
    pub answered: Option<Url>,
}

impl ChallengePage {
    /// `None` when `html` is not a challenge page.
    pub(crate) fn parse(html: &str, url: &Url) -> Result<Option<Self>> {
        let Ok(inline) = source::inline_javascript(html) else {
            return Ok(None);
        };
        let parsed = ParsedScript::parse("challenge page", &inline)?;
        let script = parsed.script();
        let literals = ast::string_literals(|literals| literals.visit_program(script.program));
        let Some(orchestrator) = candidates::at_most_one_distinct(
            literals.iter().filter(|text| {
                text.starts_with("/cdn-cgi/challenge-platform/") && text.contains(ORCHESTRATOR)
            }),
            "orchestrator path",
        )?
        else {
            return Ok(None);
        };
        let loading = candidates::at_most_one_distinct(
            literals.iter().filter(|text| text.contains(LOADING_TOKEN)),
            "loading address",
        )?
        .context("challenge page shows no loading address")?;
        let answered = source::bootstrap_options(script)
            .get(ANSWERED)
            .and_then(JsValue::as_str)
            .map(|address| url.join(address))
            .transpose()?;
        Ok(Some(Self {
            orchestrator: url.join(orchestrator)?,
            loading: url.join(loading)?,
            answered,
            url: url.clone(),
            html: html.to_owned(),
            inline,
        }))
    }

    /// Combines the inline options script and orchestrator for session extraction.
    #[must_use]
    pub(crate) fn javascript(&self, orchestrator: &str) -> String {
        format!("{}\n;\n{orchestrator}", self.inline)
    }
}

/// Recovers unset frame options from startup checks such as `top !== self` and
/// `!top.location.hostname`. Recognizes direct reads of `top` and calls to functions that read
/// it. These checks are all false on a top-level challenge page.
#[must_use]
pub(crate) fn frame_options(source: &Source, options: &Options) -> Options {
    let script = source.script();
    let readers = script.in_declared_functions(|function| {
        let mut read = TopRead(false);
        read.visit_function(function, ScopeFlags::Function);
        function
            .id
            .as_ref()
            .filter(|_| read.0)
            .map(|id| id.symbol_id())
    });
    let mut framing = Framing {
        script,
        readers: &readers,
        options,
        found: Options::new(),
    };
    framing.visit_program(script.program);
    framing.found
}

/// Whether a node reads a `top` property.
struct TopRead(bool);

impl<'a> Visit<'a> for TopRead {
    fn visit_member_expression(&mut self, member: &MemberExpression<'a>) {
        self.0 |= ast::member_str(member) == Some("top");
        walk::walk_member_expression(self, member);
    }
}

/// Assigns `false` to unset options whose value reads `top` or calls a declared function that
/// does.
struct Framing<'known, 'a> {
    script: Script<'a>,
    readers: &'known [SymbolId],
    options: &'known Options,
    found: Options,
}

impl<'a> Visit<'a> for Framing<'_, 'a> {
    fn visit_assignment_expression(&mut self, assignment: &AssignmentExpression<'a>) {
        if let Some(option) = expression::option_assignment(&assignment.left)
            && !self.options.contains_key(option)
        {
            let value = assignment.right.without_parentheses();
            let calls_reader = ast::direct_call(value).is_some_and(|(name, arguments)| {
                arguments.is_empty()
                    && self
                        .script
                        .symbol(name)
                        .is_some_and(|reader| self.readers.contains(&reader))
            });
            let mut read = TopRead(false);
            read.visit_expression(value);
            if calls_reader || read.0 {
                self.found.insert(option.to_owned(), JsValue::Bool(false));
            }
        }
        walk::walk_assignment_expression(self, assignment);
    }
}

/// Recovers the Turnstile loader URL from its host option and a path assembled from literals,
/// options, and a padded build number.
pub(crate) fn loader_url(source: &Source, options: &Options) -> Result<Url> {
    let mut found = Loader {
        options,
        builds: BTreeSet::new(),
        paths: Vec::new(),
        hosts: BTreeSet::new(),
    };
    found.visit_program(source.script().program);
    let build = candidates::exactly_one(found.builds, "loader build")?;
    let host = candidates::exactly_one(found.hosts, "loader host")?;
    let paths: BTreeSet<String> = found
        .paths
        .into_iter()
        .map(|parts| {
            parts
                .into_iter()
                .map(|part| part.unwrap_or_else(|| build.clone()))
                .collect()
        })
        .collect();
    let path = candidates::exactly_one(paths, "loader path")?;
    Url::parse(&format!("https://{host}{path}")).context("building the loader URL")
}

struct Loader<'options> {
    options: &'options Options,
    /// `("000…" + <number>.toString(16)).slice(-n)`.
    builds: BTreeSet<String>,
    /// Loader-path concatenations. `None` marks the build component.
    paths: Vec<Vec<Option<String>>>,
    /// Options a concatenation puts right after `"https://"`.
    hosts: BTreeSet<String>,
}

impl Loader<'_> {
    /// Returns the operands of a `+` chain from left to right.
    fn operands<'e, 'a>(expression: &'e Expression<'a>, out: &mut Vec<&'e Expression<'a>>) {
        match expression.without_parentheses() {
            Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
                Self::operands(&binary.left, out);
                Self::operands(&binary.right, out);
            }
            other => out.push(other),
        }
    }

    fn option(&self, operand: &Expression<'_>) -> Option<String> {
        self.options
            .get(expression::option_key(operand)?)?
            .as_str()
            .map(str::to_owned)
    }
}

impl<'a> Visit<'a> for Loader<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // `(zeros + number.toString(16)).slice(-width)`.
        if let Some(slice) = call.callee.without_parentheses().as_member_expression()
            && ast::member_str(slice) == Some("slice")
            && let Expression::BinaryExpression(sum) = slice.object().without_parentheses()
            && let Some(build) = expression::padded_build(sum)
        {
            self.builds.insert(build);
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_binary_expression(&mut self, binary: &BinaryExpression<'a>) {
        if binary.operator == BinaryOperator::Addition {
            let mut operands = Vec::new();
            Self::operands(&binary.left, &mut operands);
            Self::operands(&binary.right, &mut operands);
            if operands
                .iter()
                .any(|operand| ast::static_str(operand).is_some_and(|text| text.contains(LOADER)))
            {
                // The path references its build once through a variable.
                let parts: Option<Vec<_>> = operands
                    .iter()
                    .map(|operand| match (ast::static_str(operand), operand) {
                        (Some(text), _) => Some(Some(text.to_owned())),
                        (None, Expression::Identifier(_)) => Some(None),
                        (None, _) => self.option(operand).map(Some),
                    })
                    .collect();
                if let Some(parts) = parts
                    && parts.iter().filter(|part| part.is_none()).count() == 1
                {
                    self.paths.push(parts);
                }
                return;
            }
            if let [first, second, ..] = operands.as_slice()
                && ast::static_str(first) == Some("https://")
                && let Some(host) = self.option(second)
            {
                self.hosts.insert(host);
            }
        }
        walk::walk_binary_expression(self, binary);
    }
}

/// Reads the page language tag stored beside the message table, regardless of its option name.
#[must_use]
pub(crate) fn language(options: &Options) -> Option<&str> {
    let is_tag = |text: &&str| {
        let mut parts = text.split('-');
        parts.next().is_some_and(|primary| {
            (2..=3).contains(&primary.len())
                && primary.bytes().all(|byte| byte.is_ascii_lowercase())
        }) && parts.all(|part| {
            (2..=8).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
    };
    let tags = options
        .values()
        .filter_map(JsValue::as_object)
        .flat_map(|table| table.values().filter_map(JsValue::as_str))
        .filter(is_tag);
    candidates::at_most_one_distinct(tags, "page language").ok()?
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<html><body><script nonce="n">(function(){window._cf_chl_opt = {cH: 'token', cRay: 'ray', cUPMDTk: "/protected?__cf_chl_tk=answered"};var a = document.createElement('script');a.src = '/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=ray';if (window.history && window.history.replaceState) {history.replaceState(null, null,"/protected?__cf_chl_rt_tk=loading"+ window._cf_chl_opt.cOgUHash);}document.getElementsByTagName('head')[0].appendChild(a);}());</script></body></html>"#;

    #[test]
    fn finds_the_orchestrator_and_the_loading_address() {
        let url = Url::parse("https://example.com/protected").unwrap();
        let page = ChallengePage::parse(PAGE, &url).unwrap().unwrap();
        assert_eq!(
            page.orchestrator.as_str(),
            "https://example.com/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1?ray=ray"
        );
        assert_eq!(
            page.loading.as_str(),
            "https://example.com/protected?__cf_chl_rt_tk=loading"
        );
        assert_eq!(
            page.answered.unwrap().as_str(),
            "https://example.com/protected?__cf_chl_tk=answered"
        );
        let widget = r#"<script>window._cf_chl_opt = {}; render();</script>"#;
        for html in [widget, "<p>no script</p>"] {
            assert!(
                ChallengePage::parse(html, &url).unwrap().is_none(),
                "{html}"
            );
        }
    }
}
