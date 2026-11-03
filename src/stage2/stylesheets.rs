//! Browser-measured CSSOM spelling, reused only when the source differs by session names.
//!
//! A whole-sheet comparison guards against reusing a serialization after its CSS changes.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use regex::{Captures, Regex};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::records::Probe;
use super::reference::{STYLESHEETS_HASH, STYLESHEETS_TEXT};
use super::registry::Kind;
use super::vocabulary;
use crate::js::{JsObject, json};

static NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"_[0-9a-f]{24}").expect("the session name pattern is valid"));

/// Source CSS and the browser's serialization of each of its rules.
#[derive(Debug, Deserialize, Serialize)]
pub struct Stylesheet {
    pub source: String,
    pub rules: Vec<String>,
}

/// Numbers session names by first appearance; returns the text and the names in order.
fn normalized(source: &str) -> (String, Vec<String>) {
    let mut names = Vec::new();
    let text = NAME.replace_all(source, |found: &Captures<'_>| {
        let name = &found[0];
        let index = names.iter().position(|old| old == name).unwrap_or_else(|| {
            names.push(name.to_owned());
            names.len() - 1
        });
        format!("__name_{index}__")
    });
    (text.into_owned(), names)
}

impl Stylesheet {
    /// The rules under `current`'s session names, if `current` is this sheet's CSS.
    fn translate(&self, current: &str) -> Option<Vec<String>> {
        let (old, recorded_names) = normalized(&self.source);
        let (new, current_names) = normalized(current);
        if old != new {
            return None;
        }
        let mapping: BTreeMap<String, String> =
            recorded_names.into_iter().zip(current_names).collect();
        self.rules
            .iter()
            .map(|rule| {
                let known = NAME
                    .find_iter(rule)
                    .all(|found| mapping.contains_key(found.as_str()));
                known.then(|| {
                    NAME.replace_all(rule, |found: &Captures<'_>| mapping[&found[0]].clone())
                        .into_owned()
                })
            })
            .collect()
    }
}

/// The hex-named class selector the stylesheet probe excludes from its hash, or `None` if
/// `probe` is not the stylesheet probe.
pub(crate) fn excluded_selector(probe: &Probe) -> Option<Result<&str>> {
    let operation = probe.operation.as_ref()?;
    (operation.family() == Kind::Stylesheets).then(|| {
        probe
            .features
            .iter()
            .find(|text| text.strip_prefix('.').is_some_and(vocabulary::is_hex_name))
            .map(String::as_str)
            .context("the stylesheet probe has no excluded selector")
    })
}

/// Recomputes the CSS text and its digest from this iframe's styles, rejecting unknown CSS.
pub(crate) fn patch(
    html: &str,
    templates: &[Stylesheet],
    excluded: &str,
    fields: &mut JsObject,
) -> Result<()> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("style").expect("`style` is a valid selector");
    let mut included = Vec::new();
    let mut matched = None;
    for (index, style) in document.select(&selector).enumerate() {
        let source = style.inner_html();
        let rules = templates
            .iter()
            .find_map(|template| template.translate(&source))
            .with_context(|| format!("no CSSOM measurement matches iframe stylesheet {index}"))?;
        let text = format!("{}{index}", rules.join("|"));
        if text.contains(excluded) {
            matched = Some(text);
        } else {
            included.push(text);
        }
    }
    ensure!(
        !included.is_empty(),
        "the stylesheet hash has no input sheets"
    );
    let text = matched.context("the stylesheet probe's excluded selector is absent")?;
    let hash = format!("{:x}", Sha256::digest(included.join("|").as_bytes()));
    fields.insert(STYLESHEETS_TEXT.into(), json!(text));
    fields.insert(STYLESHEETS_HASH.into(), json!(&hash[..32]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_current_names_and_excludes_the_reported_sheet() {
        let templates = vec![
            Stylesheet {
                source: "._111111111111111111111111{color:red}".into(),
                rules: vec!["._111111111111111111111111 { color: red; }".into()],
            },
            Stylesheet {
                source: "._222222222222222222222222{width:0}".into(),
                rules: vec!["._222222222222222222222222 { width: 0px; }".into()],
            },
        ];
        let html = "<style>._aaaaaaaaaaaaaaaaaaaaaaaa{color:red}</style><style>._bbbbbbbbbbbbbbbbbbbbbbbb{width:0}</style>";
        let mut fields = JsObject::new();
        patch(html, &templates, "._bbbbbbbbbbbbbbbbbbbbbbbb", &mut fields).unwrap();
        assert_eq!(
            fields[STYLESHEETS_HASH],
            json!("c04d76a7e9af7f370a08eb5d1776c682")
        );
        assert_eq!(
            fields[STYLESHEETS_TEXT],
            json!("._bbbbbbbbbbbbbbbbbbbbbbbb { width: 0px; }1")
        );
        assert!(
            patch(
                &html.replace("color:red", "color:blue"),
                &templates,
                "._bbbbbbbbbbbbbbbbbbbbbbbb",
                &mut fields
            )
            .is_err()
        );
    }

    #[test]
    fn translation_requires_identical_css_and_consistent_names() {
        let measured = Stylesheet {
            source: "._111111111111111111111111{color:red}".into(),
            rules: vec!["._111111111111111111111111 { color: red; }".into()],
        };
        assert_eq!(
            measured.translate("._aaaaaaaaaaaaaaaaaaaaaaaa{color:red}"),
            Some(vec!["._aaaaaaaaaaaaaaaaaaaaaaaa { color: red; }".into()])
        );
        assert!(
            measured
                .translate("._aaaaaaaaaaaaaaaaaaaaaaaa{color:blue}")
                .is_none()
        );
        assert_ne!(
            normalized("_111111111111111111111111 _111111111111111111111111").0,
            normalized("_aaaaaaaaaaaaaaaaaaaaaaaa _bbbbbbbbbbbbbbbbbbbbbbbb").0
        );
    }
}
