//! Builds the recovered DOM tree, applies configured mutations, and joins the titles of the
//! ancestors containing each queried pair.

use std::iter;

use anyhow::{Context, Result, bail};
use ego_tree::{NodeId, Tree};
use serde::{Deserialize, Serialize};

use crate::js::{JsObject, json};
use crate::listing;
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

/// Configuration decoded from the program's string table, using single-letter keys.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Node {
    #[serde(rename = "t")]
    pub tag: String,
    #[serde(rename = "e")]
    pub id: String,
    #[serde(rename = "c")]
    pub classes: Vec<String>,
    /// Parent selector for insertion; absent for the root node.
    #[serde(rename = "p")]
    pub parent: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Mutation {
    /// Mutation code: [`Mutation::RULE`], [`Mutation::TITLE`], or another code that queries its
    /// selector.
    #[serde(rename = "k")]
    pub code: u8,
    #[serde(rename = "s")]
    pub selector: Option<String>,
    #[serde(rename = "v")]
    pub value: Option<String>,
}

impl Mutation {
    /// Inserts the stylesheet rule `value`, querying no element.
    pub const RULE: u8 = 0;
    /// Sets the title of the element `selector` matches to `value`.
    pub const TITLE: u8 = 1;
}

/// A query for the nearest ancestor of `element` containing `target`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Pair {
    #[serde(rename = "a")]
    pub element: String,
    #[serde(rename = "b")]
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(rename = "n")]
    pub nodes: Vec<Node>,
    #[serde(rename = "i")]
    pub mutations: Vec<Mutation>,
    #[serde(rename = "l")]
    pub pairs: Vec<Pair>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub config: Config,
}

#[derive(Default)]
struct Element<'config> {
    id: &'config str,
    classes: &'config [String],
    title: &'config str,
}

impl Fields {
    /// Lists queried selectors in order: node parents, non-rule mutation targets, then pairs.
    #[must_use]
    pub fn selectors(&self) -> Vec<String> {
        let config = &self.config;
        let parents = config.nodes.iter().filter_map(|node| node.parent.clone());
        let targets = config
            .mutations
            .iter()
            .filter(|mutation| mutation.code != Mutation::RULE)
            .filter_map(|mutation| mutation.selector.clone());
        let pairs = config
            .pairs
            .iter()
            .flat_map(|pair| [pair.element.clone(), pair.target.clone()]);
        parents.chain(targets).chain(pairs).collect()
    }

    /// Builds the probe tree under a new root, applies title mutations, and finds each pair's
    /// nearest containing ancestor. Only probe elements match the random selectors, and the
    /// root contains all of them, so traversal stays within the tree.
    pub fn collect(&self) -> Result<JsObject> {
        let mut tree = Tree::new(Element::default());
        let find = |tree: &Tree<Element<'_>>, selector: &str| -> Result<NodeId> {
            let (name, by_id) = match selector.split_at_checked(1) {
                Some(("#", id)) => (id, true),
                Some((".", class)) => (class, false),
                _ => bail!("unsupported DOM mutation selector {selector}"),
            };
            tree.root()
                .descendants()
                .skip(1)
                .find(|node| {
                    let element = node.value();
                    if by_id {
                        element.id == name
                    } else {
                        element.classes.iter().any(|class| class == name)
                    }
                })
                .map(|node| node.id())
                .with_context(|| format!("no element matches {selector}"))
        };
        for node in &self.config.nodes {
            let parent = match node.parent.as_deref() {
                Some(selector) => find(&tree, selector)?,
                None => tree.root().id(),
            };
            // `beforeend` appends after the parent's existing children.
            let mut parent = tree.get_mut(parent).expect("a node of this tree");
            parent.append(Element {
                id: &node.id,
                classes: &node.classes,
                title: "",
            });
        }
        for mutation in &self.config.mutations {
            if mutation.code == Mutation::TITLE {
                let selector = mutation
                    .selector
                    .as_deref()
                    .context("title mutation has no selector")?;
                let element = find(&tree, selector)?;
                let mut element = tree.get_mut(element).expect("a node of this tree");
                element.value().title = mutation.value.as_deref().unwrap_or("");
            }
        }
        let mut result = String::new();
        for pair in &self.config.pairs {
            let target = find(&tree, &pair.target)?;
            let target = tree.get(target).expect("a node of this tree");
            let element = find(&tree, &pair.element)?;
            let element = tree.get(element).expect("a node of this tree");
            let ancestor = iter::once(element)
                .chain(element.ancestors())
                .find(|ancestor| {
                    *ancestor == target || target.ancestors().any(|node| node == *ancestor)
                })
                .expect("the root contains both elements");
            result.push_str(ancestor.value().title);
        }
        Ok(JsObject::from_iter([(
            reference::DOM_MUTATION_RESULT.to_owned(),
            json!(result),
        )]))
    }
}

/// Decodes the probe's configuration from the program's string table.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let strings = &probe.strings;
    if !strings.has_all(&[
        reference::DOM_MUTATION_RESULT,
        "contains",
        "parentNode",
        "insertRule",
        "appendData",
        "insertAdjacentHTML",
    ]) {
        return None;
    }
    let config = probe.index.strings().values().find_map(|text| {
        let decoded = listing::decode_string(text, probe.pool).ok()?;
        serde_json::from_str(&decoded).ok()
    })?;
    Some(Fields { config })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js;

    #[test]
    fn late_children_keep_document_order_and_existing_parent_links() {
        let fields: Fields = js::from_value(json!({
            "config":{
                "n":[
                    {"t":"div","e":"a","c":[],"p":null},
                    {"t":"div","e":"b","c":["shared"],"p":null},
                    {"t":"div","e":"c","c":["shared"],"p":"#a"},
                    {"t":"div","e":"d","c":[],"p":"#b"}
                ],
                "i":[
                    {"k":1,"s":".shared","v":"early"},
                    {"k":1,"s":"#b","v":"later"},
                    {"k":1,"s":"#a","v":"parent"}
                ],
                "l":[
                    {"a":"#c","b":"#c"}, {"a":"#d","b":"#b"},
                    {"a":"#a","b":"#c"}, {"a":"#c","b":"#d"}
                ]
            }
        }))
        .unwrap();
        assert_eq!(
            fields.collect().unwrap()[reference::DOM_MUTATION_RESULT],
            "earlylaterparent"
        );
        for (selector, expected) in [
            ("#missing", "no element matches #missing"),
            ("div", "unsupported DOM mutation selector div"),
        ] {
            let mut fields = fields.clone();
            fields.config.nodes[2].parent = Some(selector.into());
            assert_eq!(fields.collect().unwrap_err().to_string(), expected);
        }
    }

    #[test]
    fn native_tree_reproduces_a_browser_session() {
        let config: Config = serde_json::from_str(r##"{"n": [{"t": "div", "e": "mrkcd10", "c": ["KoJlT10", "KoJlT11", "KoJlT12", "KoJlT13", "KoJlT14"], "p": null}, {"t": "div", "e": "mrkcd11", "c": ["KoJlT15", "KoJlT16"], "p": ".KoJlT13"}, {"t": "span", "e": "mrkcd12", "c": ["KoJlT17", "KoJlT18"], "p": ".KoJlT16"}, {"t": "div", "e": "mrkcd13", "c": ["KoJlT19", "KoJlT110"], "p": ".KoJlT18"}], "i": [{"k": 0, "s": null, "v": ".KoJlT16{font-family:'IBAdK71'}"}, {"k": 2, "s": ".KoJlT16", "v": null}, {"k": 0, "s": null, "v": ".KoJlT19{font-family:'IBAdK75'}"}, {"k": 0, "s": null, "v": ".KoJlT16 .KoJlT16{font-family:'IBAdK70'}"}, {"k": 1, "s": ".KoJlT14", "v": "root"}, {"k": 0, "s": null, "v": ".KoJlT18{font-family:'IBAdK73'}"}, {"k": 0, "s": null, "v": ".KoJlT16 .KoJlT18{font-family:'IBAdK72'}"}, {"k": 1, "s": ".KoJlT16", "v": "mNtX20"}, {"k": 2, "s": ".KoJlT14", "v": null}, {"k": 2, "s": ".KoJlT19", "v": null}, {"k": 0, "s": null, "v": ".KoJlT18 .KoJlT19{font-family:'IBAdK74'}"}, {"k": 2, "s": ".KoJlT18", "v": null}, {"k": 1, "s": "#mrkcd12", "v": "mNtX21"}, {"k": 1, "s": ".KoJlT110", "v": "mNtX22"}], "l": [{"a": ".KoJlT13", "b": ".KoJlT15"}, {"a": ".KoJlT15", "b": ".KoJlT12"}, {"a": ".KoJlT110", "b": "#mrkcd11"}, {"a": ".KoJlT19", "b": "#mrkcd13"}, {"a": ".KoJlT18", "b": ".KoJlT17"}]}"##).unwrap();
        let fields = Fields { config };
        assert_eq!(fields.selectors().len(), 3 + 8 + 10);
        assert_eq!(
            fields.collect().unwrap()[reference::DOM_MUTATION_RESULT],
            "rootrootmNtX20mNtX22mNtX21"
        );
    }
}
