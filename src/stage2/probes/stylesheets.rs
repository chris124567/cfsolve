//! Replays captured CSSOM formatting after validating a stylesheet's structure.

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::LazyLock;

use crate::stage2::{
    records::Probe,
    reference::{STYLESHEET_DIGEST, STYLESHEET_MARKER},
    vocabulary,
};
use crate::{
    candidates,
    js::{JsObject, json},
};

static SESSION_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"_[0-9a-fA-F]{24}|[A-Za-z]{3,5}[0-9]").unwrap());

/// Source text paired with the rules the profile's browser exposed through CSSOM.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Sheet {
    pub source: String,
    pub rules: Vec<String>,
}

/// One captured stylesheet revision. Multiple revisions can share a device profile.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    pub sheets: Vec<Sheet>,
}

impl Snapshot {
    pub fn capture(html: &str, rules: Vec<Vec<String>>) -> Result<Self> {
        let sources = sources(html);
        ensure!(
            sources.len() == rules.len(),
            "CSSOM rule lists do not match the iframe's stylesheets"
        );
        Ok(Self {
            sheets: sources
                .into_iter()
                .zip(rules)
                .map(|(source, rules)| Sheet { source, rules })
                .collect(),
        })
    }

    /// Requires identical text outside randomized names and a consistent one-to-one name map.
    pub fn replay(&self, sources: &[String]) -> Result<Vec<Vec<String>>> {
        ensure!(
            sources.len() == self.sheets.len(),
            "stylesheet count changed"
        );
        let mut names = BTreeMap::new();
        let mut reverse = BTreeMap::new();
        for (sheet, current) in self.sheets.iter().zip(sources) {
            ensure!(
                SESSION_NAME
                    .split(&sheet.source)
                    .eq(SESSION_NAME.split(current)),
                "stylesheet structure changed"
            );
            for (old, new) in SESSION_NAME
                .find_iter(&sheet.source)
                .zip(SESSION_NAME.find_iter(current))
            {
                let (old, new) = (old.as_str(), new.as_str());
                ensure!(
                    names
                        .insert(old, new)
                        .is_none_or(|previous| previous == new),
                    "inconsistent stylesheet name"
                );
                ensure!(
                    reverse
                        .insert(new, old)
                        .is_none_or(|previous| previous == old),
                    "ambiguous stylesheet name"
                );
            }
        }
        Ok(self
            .sheets
            .iter()
            .map(|sheet| {
                sheet
                    .rules
                    .iter()
                    .map(|rule| {
                        SESSION_NAME
                            .replace_all(rule, |captures: &regex::Captures<'_>| {
                                names
                                    .get(&captures[0])
                                    .copied()
                                    .unwrap_or(&captures[0])
                                    .to_owned()
                            })
                            .into_owned()
                    })
                    .collect()
            })
            .collect())
    }
}

#[must_use]
pub(crate) fn sources(html: &str) -> Vec<String> {
    let document = scraper::Html::parse_document(html);
    let selector = scraper::Selector::parse("style").unwrap();
    document
        .select(&selector)
        .map(|style| style.inner_html())
        .collect()
}

/// Updates the stored fields before replay translates reference names and arranges the record.
pub(crate) fn refresh(
    snapshots: &[Snapshot],
    probe: &Probe,
    html: &str,
    fields: &mut JsObject,
) -> Result<()> {
    let markers = probe
        .features
        .iter()
        .filter(|text| text.strip_prefix('.').is_some_and(vocabulary::is_name));
    let marker = candidates::at_most_one_distinct(markers, "stylesheet marker")?
        .context("no stylesheet marker")?;
    let (digest, marker_css) = measurement(snapshots, html, marker)?;
    for (field, value) in [(STYLESHEET_DIGEST, digest), (STYLESHEET_MARKER, marker_css)] {
        *fields
            .get_mut(field)
            .with_context(|| format!("missing stylesheet field {field}"))? = json!(value);
    }
    Ok(())
}

fn measurement(snapshots: &[Snapshot], html: &str, marker: &str) -> Result<(String, String)> {
    let sources = sources(html);
    for snapshot in snapshots {
        let Ok(sheets) = snapshot.replay(&sources) else {
            continue;
        };
        let mut marker_text = None;
        let mut measured = Vec::new();
        for (index, rules) in sheets.iter().enumerate() {
            let text = rules.join("|");
            let indexed = format!("{text}{index}");
            if text.contains(marker) {
                ensure!(
                    marker_text.replace(indexed).is_none(),
                    "multiple marker stylesheets"
                );
            } else {
                measured.push(indexed);
            }
        }
        let marker_text = marker_text.context("the current marker stylesheet is absent")?;
        let digest = format!("{:x}", Sha256::digest(measured.join("|").as_bytes()));
        return Ok((digest[..32].to_owned(), marker_text));
    }
    bail!("no captured stylesheet revision matches the current iframe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_names_in_browser_serialized_rules_without_running_a_browser() {
        let snapshot = Snapshot {
            sheets: vec![Sheet {
                source: ".Abcd1{margin:0}.Abcd1 .Efgh2{color:red}".into(),
                rules: vec![
                    ".Abcd1 { margin: 0px; }".into(),
                    ".Abcd1 .Efgh2 { color: red; }".into(),
                ],
            }],
        };
        assert_eq!(
            snapshot
                .replay(&[".Ijkl3{margin:0}.Ijkl3 .Mnop4{color:red}".into()])
                .unwrap(),
            [vec![
                ".Ijkl3 { margin: 0px; }",
                ".Ijkl3 .Mnop4 { color: red; }"
            ]]
        );
        assert!(
            snapshot
                .replay(&[".Ijkl3{margin:1}.Ijkl3 .Mnop4{color:red}".into()])
                .is_err()
        );
        assert!(
            snapshot
                .replay(&[".Ijkl3{margin:0}.Mnop4 .Qrst5{color:red}".into()])
                .is_err()
        );
        assert!(
            snapshot
                .replay(&[".Ijkl3{margin:0}.Ijkl3 .Ijkl3{color:red}".into()])
                .is_err()
        );
        assert!(snapshot.replay(&[]).is_err());
    }

    #[test]
    fn measures_current_rules_and_excludes_the_marker_sheet() {
        let html = "<style>.Abcd1{color:red}</style><style>.Efgh2{margin:0}</style>";
        let snapshot = Snapshot::capture(
            html,
            vec![
                vec![".Abcd1 { color: red; }".into()],
                vec![".Efgh2 { margin: 0px; }".into()],
            ],
        )
        .unwrap();
        let fresh = "<style>.Ijkl3{color:red}</style><style>.Mnop4{margin:0}</style>";
        let (hash, marker) = measurement(std::slice::from_ref(&snapshot), fresh, ".Mnop4").unwrap();
        assert_eq!(
            hash,
            format!("{:x}", Sha256::digest(b".Ijkl3 { color: red; }0"))[..32]
        );
        assert_eq!(marker, ".Mnop4 { margin: 0px; }1");
        assert!(measurement(&[snapshot], fresh, ".Missing5").is_err());
        assert!(measurement(&[], fresh, ".Mnop4").is_err());
        assert!(Snapshot::capture(html, vec![]).is_err());
        let duplicate = Snapshot::capture(
            "<style>.Abcd1{color:red}</style><style>.Abcd1{margin:0}</style>",
            vec![
                vec![".Abcd1 { color: red; }".into()],
                vec![".Abcd1 { margin: 0px; }".into()],
            ],
        )
        .unwrap();
        assert!(
            measurement(
                &[duplicate],
                "<style>.Abcd1{color:red}</style><style>.Abcd1{margin:0}</style>",
                ".Abcd1"
            )
            .is_err()
        );
    }
}
