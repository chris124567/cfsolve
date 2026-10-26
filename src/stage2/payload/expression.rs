//! Expressions that read session state and the context used to evaluate them.

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::js::{self, JsObject, JsValue, Options, Payload, Window, json};

/// Session map used as the root of a read.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// `window._cf_chl_opt`.
    Options,
    Window,
    /// The payload the program received.
    Input,
}

/// An expression evaluated from session state and written to the payload.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expression {
    Literal {
        value: JsValue,
    },
    /// A property path; a missing property reads as `undefined`.
    Read {
        scope: Scope,
        path: Vec<String>,
    },
    /// `left - right`, with JavaScript's numeric coercion.
    Subtract {
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// The result of calling the window function `name`.
    Call {
        name: String,
    },
    /// `value || 0`.
    OrZero {
        value: Box<Expression>,
    },
    /// `RegExp(pattern).exec(value)[group]`.
    Match {
        value: Box<Expression>,
        pattern: String,
        group: usize,
    },
}

/// Session values available to payload expressions beyond the input payload.
#[derive(Clone, Copy)]
pub struct Environment<'session> {
    pub options: &'session Options,
    /// Window globals the program reads.
    pub window: &'session Window,
    /// Results of the window functions the template calls.
    pub calls: &'session Window,
}

/// Borrowed session context for evaluating payload expressions.
#[derive(Clone, Copy)]
pub struct State<'session> {
    pub environment: Environment<'session>,
    /// The payload the program received.
    pub input: &'session Payload,
}

impl Expression {
    /// Evaluates the expression, returning `None` for `undefined` fields omitted during
    /// serialization.
    pub(in crate::stage2) fn evaluate(&self, state: &State<'_>) -> Result<Option<JsValue>> {
        Ok(match self {
            Self::Literal { value } => Some(value.clone()),
            Self::Call { name } => Some(
                state
                    .environment
                    .calls
                    .get(name)
                    .with_context(|| format!("missing result of {name}()"))?
                    .clone(),
            ),
            Self::Read { scope, path } => {
                let map: &JsObject = match scope {
                    Scope::Options => state.environment.options,
                    Scope::Window => state.environment.window,
                    Scope::Input => state.input,
                };
                let (key, tail) = path.split_first().context("payload read has empty path")?;
                let mut value = map.get(key);
                for key in tail {
                    let object = value
                        .and_then(JsValue::as_object)
                        .context("payload read crosses missing or non-object property")?;
                    value = object.get(key);
                }
                value.cloned()
            }
            Self::Subtract { left, right } => {
                let difference = js::number(left.evaluate(state)?.as_ref())
                    - js::number(right.evaluate(state)?.as_ref());
                Some(json!(difference))
            }
            Self::OrZero { value } => Some(
                value
                    .evaluate(state)?
                    .filter(js::truthy)
                    .unwrap_or(json!(0)),
            ),
            // Recovered patterns use syntax compatible with `regex`. A failed match returns
            // `null` in JavaScript, whose indexed access throws; report an error here too.
            Self::Match {
                value,
                pattern,
                group,
            } => {
                let value = value.evaluate(state)?;
                let text = value
                    .as_ref()
                    .and_then(JsValue::as_str)
                    .with_context(|| format!("matching /{pattern}/ against a non-string"))?;
                let pattern = Regex::new(pattern)
                    .with_context(|| format!("unsupported pattern /{pattern}/"))?;
                let captures = pattern
                    .captures(text)
                    .with_context(|| format!("/{pattern}/ does not match {text:?}"))?;
                // A group that took no part in the match is `undefined`.
                captures.get(*group).map(|found| json!(found.as_str()))
            }
        })
    }
}
