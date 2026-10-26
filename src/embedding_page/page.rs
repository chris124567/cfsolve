//! Reconstructs the page after `api.js` renders a widget. Builds the `wPr` page summary sent in
//! the `requestExtraParams` reply.

use std::collections::HashMap;
use std::iter;

use anyhow::{Context, Result};
use ego_tree::{NodeId, NodeRef};
use html5ever::{Attribute, QualName, ns};
use scraper::node::Element;
use scraper::{ElementRef, Html, Node, Selector};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::js::JsObject;

/// Implicit render collects containers with this class.
const CONTAINER_CLASS: &str = "cf-turnstile";
/// `api.js` truncates tag names to three UTF-16 code units and attribute names to two.
const TAG_PREFIX: usize = 3;
const ATTRIBUTE_PREFIX: usize = 2;
const FINGERPRINT_LIMIT: usize = 500;
/// Only the first 20 form controls, labels and links reach the fingerprint.
const SAMPLE: usize = 20;

/// Viewport and widget geometry, which HTML alone does not determine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Layout {
    pub inner_width: u32,
    pub inner_height: u32,
    pub visibility_state: String,
    pub referrer: String,
    /// `getBoundingClientRect()` of the widget wrapper.
    pub widget_top: f64,
    /// Defaults to the viewport minus the body's default 8px margin.
    pub widget_right: Option<f64>,
    /// Iframe position used for interaction; omitted from the page summary.
    pub widget_left: f64,
    /// Widget position set by a challenge page's stylesheet for this viewport. Overrides the
    /// other position settings.
    pub challenge_page: Option<Placement>,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            inner_width: 1280,
            inner_height: 720,
            visibility_state: "visible".into(),
            referrer: String::new(),
            widget_top: 8.0,
            widget_right: None,
            widget_left: 8.0,
            challenge_page: None,
        }
    }
}

/// The edges of a widget's wrapper, from `getBoundingClientRect()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Placement {
    pub top: f64,
    pub left: f64,
    pub right: f64,
}

impl Layout {
    /// Layout settings for a widget positioned by a challenge page's stylesheet.
    #[must_use]
    pub(crate) fn on_challenge_page(&self) -> Self {
        let mut layout = self.clone();
        if let Some(placement) = &self.challenge_page {
            layout.widget_top = placement.top;
            layout.widget_left = placement.left;
            layout.widget_right = Some(placement.right);
        }
        layout
    }
}

/// Site-supplied Turnstile configuration, including parameters returned by siteverify.
#[derive(Clone, Debug, Default)]
pub struct Widget {
    /// Sitekey used to select a page container or render a new widget.
    pub sitekey: String,
    /// Optional action returned by siteverify when the token is validated.
    pub action: Option<String>,
    /// Optional caller data passed as `cData` and returned by siteverify.
    pub cdata: Option<String>,
}

/// One widget's configuration once `api.js` has applied its defaults.
#[derive(Debug, Clone)]
pub(crate) struct Params {
    pub sitekey: String,
    pub action: Option<String>,
    pub cdata: Option<String>,
    pub chl_page_data: Option<String>,
    pub theme: String,
    pub size: String,
    pub language: String,
    pub retry: String,
    pub retry_interval: i64,
    pub expiry_interval: i64,
    pub refresh_expired: String,
    pub refresh_timeout: String,
    pub execution: String,
    pub appearance: String,
    pub feedback_enabled: bool,
    pub response_field: bool,
    pub response_field_name: Option<String>,
    pub offlabel_show_privacy: Option<bool>,
    pub offlabel_show_help: Option<bool>,
}

impl Params {
    /// Explicit `turnstile.render` parameters, with defaults for all others. Names correspond
    /// to lowercase `data-<name>` attributes except `chlPageData`, which is supplied only
    /// through `render`.
    pub(crate) fn from_render(parameters: &JsObject) -> Result<Self> {
        let mut attributes: HashMap<String, &str> = HashMap::new();
        for (name, value) in parameters {
            let value = value
                .as_str()
                .with_context(|| format!("render parameter {name} is not text"))?;
            attributes.insert(format!("data-{}", name.to_ascii_lowercase()), value);
        }
        let mut params = Self::from_attributes(|name| attributes.get(name).copied())?;
        params.chl_page_data = attributes.get("data-chlpagedata").map(ToString::to_string);
        Ok(params)
    }

    fn from_attributes<'a>(attribute: impl Fn(&str) -> Option<&'a str>) -> Result<Self> {
        // Preserve empty `data-action` and `data-cdata`. Other empty attributes use defaults.
        let set = |name: &str| attribute(name).filter(|value| !value.is_empty());
        let flag = |name: &str| match set(name) {
            Some("true") => Some(true),
            Some("false") => Some(false),
            _ => None,
        };
        Ok(Self {
            sitekey: attribute("data-sitekey")
                .context("`.cf-turnstile` container has no data-sitekey")?
                .to_owned(),
            action: attribute("data-action").map(str::to_owned),
            cdata: attribute("data-cdata").map(str::to_owned),
            chl_page_data: None,
            theme: set("data-theme").unwrap_or("auto").to_owned(),
            size: set("data-size").unwrap_or("normal").to_owned(),
            language: set("data-language").unwrap_or("auto").to_owned(),
            retry: set("data-retry").unwrap_or("auto").to_owned(),
            retry_interval: set("data-retry-interval")
                .and_then(|value| value.parse().ok())
                .unwrap_or(8_000),
            expiry_interval: set("data-expiry-interval")
                .and_then(|value| value.parse().ok())
                .unwrap_or(290_000),
            refresh_expired: set("data-refresh-expired").unwrap_or("auto").to_owned(),
            refresh_timeout: set("data-refresh-timeout").unwrap_or("auto").to_owned(),
            execution: set("data-execution").unwrap_or("render").to_owned(),
            appearance: set("data-appearance").unwrap_or("always").to_owned(),
            feedback_enabled: flag("data-feedback-enabled").unwrap_or(true),
            response_field: flag("data-response-field").unwrap_or(true),
            response_field_name: set("data-response-field-name").map(str::to_owned),
            offlabel_show_privacy: flag("data-offlabel-show-privacy"),
            offlabel_show_help: flag("data-offlabel-show-help"),
        })
    }
}

/// A page with one rendered Turnstile widget. Computes the summary during rendering because the
/// parsed tree cannot be sent or shared across threads.
pub(crate) struct RenderedPage {
    pub url: Url,
    pub params: Params,
    pub widget_id: String,
    /// The linked Turnstile loader, resolved as a browser resolves `src`; `api.js` reports it
    /// as `au`.
    pub loader_script: Option<Url>,
    custom_element_tags: Vec<String>,
    root_attributes: Vec<String>,
    /// Parent info (`pi`) before [`Self::signals`] adds mode and layout values.
    parent: ParentInfo,
}

/// `wPr`: what `api.js` reports about the page around the widget. Fields serialize in the
/// order `api.js` writes them, which the message keeps.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PageSignals {
    #[serde(rename = "d.cT")]
    pub custom_element_tags: Vec<String>,
    #[serde(rename = "ht.atrs")]
    pub root_attributes: Vec<String>,
    #[serde(rename = "pg.ref")]
    pub referrer: String,
    #[serde(rename = "pi")]
    pub parent: ParentInfo,
    #[serde(rename = "w.iW")]
    pub inner_width: u32,
}

/// `pi`: the widget's place in the page. The parent info probe copies these properties by
/// their `api.js` names.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ParentInfo {
    /// The enclosing form's method and controls, or `nf` if there is no form.
    #[serde(rename = "ffp")]
    pub form: String,
    #[serde(rename = "ii")]
    pub in_iframe: bool,
    #[serde(rename = "lH")]
    pub location: String,
    #[serde(rename = "mL")]
    pub meta: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad: Option<String>,
    #[serde(rename = "pfp")]
    pub fingerprint: String,
    #[serde(rename = "sL")]
    pub scripts: usize,
    #[serde(rename = "sR")]
    pub same_realm: bool,
    #[serde(rename = "ssL")]
    pub stylesheets: usize,
    /// The title's UTF-16 length and djb2 hash.
    #[serde(rename = "t")]
    pub title: String,
    #[serde(rename = "tL")]
    pub elements: usize,
    #[serde(rename = "vDa")]
    pub appearance: String,
    #[serde(rename = "vDeh")]
    pub error_handled: bool,
    #[serde(rename = "vDhp")]
    pub host: &'static str,
    /// Why the widget is hidden; `null` while it shows.
    #[serde(rename = "vDhr")]
    pub hidden_reason: Option<String>,
    /// Whether the loader rendered the widget from the page's markup.
    #[serde(rename = "vDie")]
    pub implicit: bool,
    /// The challenge mode the iframe reported.
    #[serde(rename = "vDmd")]
    pub mode: Option<String>,
    #[serde(rename = "vDmt")]
    pub mount: &'static str,
    /// Why the widget was re-rendered; empty on a first render.
    #[serde(rename = "vDrs")]
    pub reasons: Vec<String>,
    #[serde(rename = "vDuh")]
    pub user_hidden: bool,
    #[serde(rename = "vDvp")]
    pub viewport: Viewport,
    /// The wrapper's top and right edges.
    #[serde(rename = "wp")]
    pub widget_position: String,
    #[serde(rename = "xp")]
    pub xpath: String,
}

/// `vDvp`: the page's viewport.
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Viewport {
    pub height: u32,
    #[serde(rename = "visibilityState")]
    pub visibility_state: String,
    pub width: u32,
}

impl RenderedPage {
    /// Renders the container matching `widget`'s sitekey, using its action and cData. With no
    /// `widget`, uses the first container. If no container matches, renders into `<body>` as a
    /// page script calling `turnstile.render` would.
    pub(crate) fn render(
        html: &str,
        url: Url,
        widget_id: &str,
        widget: Option<&Widget>,
    ) -> Result<Self> {
        let document = Html::parse_document(html);
        let container = document
            .select(&selector(&format!(".{CONTAINER_CLASS}")))
            .find(|container| {
                widget.is_none_or(|widget| {
                    container.value().attr("data-sitekey") == Some(widget.sitekey.as_str())
                })
            });
        let Some(container) = container else {
            let widget =
                widget.with_context(|| format!("page has no .{CONTAINER_CLASS} container"))?;
            let params = Params::from_attributes(|name| match name {
                "data-sitekey" => Some(widget.sitekey.as_str()),
                "data-action" => widget.action.as_deref(),
                "data-cdata" => widget.cdata.as_deref(),
                _ => None,
            })?;
            return Self::render_explicit(html, url, widget_id, "body", params);
        };
        let mut params = Params::from_attributes(|name| container.value().attr(name))?;
        if let Some(widget) = widget {
            params.action = widget.action.clone().or(params.action);
            params.cdata = widget.cdata.clone().or(params.cdata);
        }
        let container = container.id();
        Ok(Self::insert(document, container, url, params, widget_id))
    }

    /// Parses `html` and emulates `turnstile.render(container, params)`. Creates a bare `<div>`
    /// container under the element selected by `host`.
    pub(crate) fn render_explicit(
        html: &str,
        url: Url,
        widget_id: &str,
        host: &str,
        params: Params,
    ) -> Result<Self> {
        let mut document = Html::parse_document(html);
        let selector = Selector::parse(host)
            .map_err(|error| anyhow::anyhow!("widget host selector {host}: {error:?}"))?;
        let host = document
            .select(&selector)
            .next()
            .with_context(|| format!("page has no widget host {host}"))?
            .id();
        let container = document
            .tree
            .get_mut(host)
            .expect("host just selected from this tree")
            .append(element("div", &[]))
            .id();
        Ok(Self::insert(document, container, url, params, widget_id))
    }

    /// Appends the widget to `container` and summarizes the page around it.
    fn insert(
        mut document: Html,
        container: NodeId,
        url: Url,
        params: Params,
        widget_id: &str,
    ) -> Self {
        // `api.js` appends a wrapper containing an iframe host and response field. The iframe
        // is inside a closed shadow root, so the summary sees the three added nodes but not the
        // iframe.
        let mut container = document
            .tree
            .get_mut(container)
            .expect("container just selected from this tree");
        let mut wrapper = container.append(element("div", &[]));
        let wrapper_id = wrapper.id();
        wrapper.append(element("div", &[]));
        if params.response_field {
            let name = params
                .response_field_name
                .as_deref()
                .unwrap_or("cf-turnstile-response");
            wrapper.append(element(
                "input",
                &[
                    ("type", "hidden"),
                    ("name", name),
                    ("id", &format!("cf-chl-widget-{widget_id}_response")),
                ],
            ));
        }
        let wrapper = document.tree.get(wrapper_id).expect("just appended");
        let form = ancestors(wrapper).find(|node| is_named(*node, "form"));
        let FormSignals { pac, pad } = match form {
            Some(form) => form_signals(form, &url),
            None => container_signals(wrapper, &url),
        };
        // `api.js` leaves out the form summary when the widget has `chlPageData`, as widgets
        // on challenge pages do.
        let summarized = params.chl_page_data.as_deref().is_none_or(str::is_empty);
        let count = |literal| document.select(&selector(literal)).count();
        let parent = ParentInfo {
            form: form.map_or_else(|| "nf".to_owned(), form_fields),
            in_iframe: false,
            location: url.to_string(),
            meta: count("meta"),
            pac: summarized.then_some(pac),
            pad: summarized.then_some(pad),
            fingerprint: dom_fingerprint(&document),
            scripts: count("script"),
            same_realm: true,
            // Linked sheets are assumed to have loaded.
            stylesheets: count("style, link[rel~=stylesheet][href]"),
            title: title(&document),
            elements: count("*"),
            appearance: params.appearance.clone(),
            error_handled: false,
            host: "wrapper",
            hidden_reason: None,
            implicit: params.execution == "render",
            mode: None,
            mount: "wrapper",
            reasons: Vec::new(),
            user_hidden: false,
            viewport: Viewport::default(),
            widget_position: String::new(),
            xpath: xpath(wrapper),
        };
        Self {
            loader_script: loader_script(&document, &url),
            custom_element_tags: custom_element_tags(&document),
            root_attributes: document
                .root_element()
                .value()
                .attrs()
                .map(|(name, _)| name.to_owned())
                .collect(),
            parent,
            url,
            params,
            widget_id: widget_id.to_owned(),
        }
    }

    /// Builds `wPr` for the `extraParams` message, given the challenge `mode` the iframe reported.
    #[must_use]
    pub(crate) fn signals(&self, layout: &Layout, mode: Option<&str>) -> PageSignals {
        let right = layout
            .widget_right
            .unwrap_or(f64::from(layout.inner_width) - 8.0);
        PageSignals {
            custom_element_tags: self.custom_element_tags.clone(),
            root_attributes: self.root_attributes.clone(),
            referrer: layout.referrer.clone(),
            parent: ParentInfo {
                mode: mode.map(str::to_owned),
                viewport: Viewport {
                    height: layout.inner_height,
                    visibility_state: layout.visibility_state.clone(),
                    width: layout.inner_width,
                },
                widget_position: format!("{}|{right}", layout.widget_top),
                ..self.parent.clone()
            },
            inner_width: layout.inner_width,
        }
    }
}

fn loader_script(document: &Html, url: &Url) -> Option<Url> {
    document
        .select(&selector("script[src]"))
        .filter_map(|script| url.join(script.value().attr("src")?).ok())
        .find(|url| url.path().contains("/turnstile/") && url.path().ends_with("api.js"))
}

/// `t` from `document.title`: the title text, ASCII whitespace trimmed and collapsed to single
/// spaces.
fn title(document: &Html) -> String {
    let text: String = document
        .select(&selector("title"))
        .next()
        .map(|title| title.text().collect())
        .unwrap_or_default();
    let title = text.split_ascii_whitespace().collect::<Vec<_>>().join(" ");
    format!("{}|{}", title.encode_utf16().count(), djb2(&title))
}

/// The first 50 distinct custom element names.
fn custom_element_tags(document: &Html) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for node in document.tree.root().descendants() {
        if let Some(element) = node.value().as_element()
            && element.name().contains('-')
            && !tags.iter().any(|seen| seen == element.name())
        {
            tags.push(element.name().to_owned());
        }
    }
    tags.truncate(50);
    tags
}

/// Summarizes element and text nodes within three levels of the root using truncated tag
/// and attribute names.
fn dom_fingerprint(document: &Html) -> String {
    let mut shape = String::new();
    add_shape(&mut shape, document.tree.root(), 0);
    js_prefix(&shape, FINGERPRINT_LIMIT).to_owned()
}

fn selector(literal: &str) -> Selector {
    Selector::parse(literal).expect("literal selector")
}

fn element(name: &str, attributes: &[(&str, &str)]) -> Node {
    Node::Element(Element::new(
        QualName::new(None, ns!(html), name.into()),
        attributes
            .iter()
            .map(|(name, value)| Attribute {
                name: QualName::new(None, ns!(), (*name).into()),
                value: (*value).into(),
            })
            .collect(),
    ))
}

/// Appends `node`'s part of [`dom_fingerprint`] to `shape`.
fn add_shape(shape: &mut String, node: NodeRef<'_, Node>, depth: usize) {
    if depth > 3 || shape.encode_utf16().count() >= FINGERPRINT_LIMIT {
        return;
    }
    match node.value() {
        Node::Element(element) => {
            shape.push_str(js_prefix(element.name(), TAG_PREFIX));
            for (name, _) in element.attrs() {
                shape.push('_');
                shape.push_str(js_prefix(name, ATTRIBUTE_PREFIX));
            }
            shape.push('>');
        }
        Node::Text(_) => shape.push_str("-t"),
        _ => {}
    }
    for child in node.children() {
        add_shape(shape, child, depth + 1);
    }
}

/// Builds the widget's XPath from the first element below `<body>`, cut to 500 code units.
fn xpath(node: NodeRef<'_, Node>) -> String {
    let mut path = String::new();
    let mut current = Some(node);
    while let Some(node) = current
        && let Some(element) = node.value().as_element()
        && element.name() != "body"
    {
        let index = 1 + node
            .prev_siblings()
            .filter(|sibling| is_named(*sibling, element.name()))
            .count();
        path.insert_str(
            0,
            &format!("/{}[{index}]", js_prefix(element.name(), TAG_PREFIX)),
        );
        current = node.parent();
    }
    js_prefix(&path, 500).to_owned()
}

/// Walks the `parentElement` chain up to the document.
fn ancestors(node: NodeRef<'_, Node>) -> impl Iterator<Item = NodeRef<'_, Node>> {
    iter::successors(node.parent(), NodeRef::parent).take_while(|node| node.value().is_element())
}

fn is_named(node: NodeRef<'_, Node>, name: &str) -> bool {
    node.value()
        .as_element()
        .is_some_and(|element| element.name() == name)
}

fn attribute<'a>(node: NodeRef<'a, Node>, name: &str) -> &'a str {
    node.value()
        .as_element()
        .and_then(|element| element.attr(name))
        .unwrap_or_default()
}

fn descendants_named<'a>(
    node: NodeRef<'a, Node>,
    names: &[&str],
) -> impl Iterator<Item = NodeRef<'a, Node>> {
    node.descendants()
        .skip(1)
        .filter(move |node| names.iter().any(|name| is_named(*node, name)))
}

fn controls(node: NodeRef<'_, Node>) -> Vec<NodeRef<'_, Node>> {
    descendants_named(node, &["input", "select", "textarea", "button"]).collect()
}

fn text(node: NodeRef<'_, Node>) -> String {
    ElementRef::wrap(node)
        .map(|element| element.text().collect())
        .unwrap_or_default()
}

/// Implements `value.slice(0, units)` using UTF-16 limits. If the limit splits a surrogate
/// pair, drops the entire pair because Rust strings cannot hold the lone surrogate JavaScript
/// would retain.
fn js_prefix(value: &str, units: usize) -> &str {
    let mut counted = 0;
    for (at, character) in value.char_indices() {
        counted += character.len_utf16();
        if counted > units {
            return &value[..at];
        }
    }
    value
}

/// The hash `api.js` uses for every keyword and word-pair comparison.
fn djb2(value: &str) -> u32 {
    // UTF-16 code units, which differ from Rust characters outside the basic multilingual plane.
    value.encode_utf16().fold(5381u32, |hash, unit| {
        hash.wrapping_mul(33) ^ u32::from(unit)
    })
}

/// Returns the DOM's normalized control type, which may differ from the attribute text.
fn control_type(node: NodeRef<'_, Node>) -> String {
    const INPUT_TYPES: &[&str] = &[
        "button",
        "checkbox",
        "color",
        "date",
        "datetime-local",
        "email",
        "file",
        "hidden",
        "image",
        "month",
        "number",
        "password",
        "radio",
        "range",
        "reset",
        "search",
        "submit",
        "tel",
        "text",
        "time",
        "url",
        "week",
    ];
    let value = attribute(node, "type").to_ascii_lowercase();
    let element = node.value().as_element();
    match element.map(Element::name) {
        Some("textarea") => "textarea".into(),
        Some("select") if element.and_then(|select| select.attr("multiple")).is_some() => {
            "select-multiple".into()
        }
        Some("select") => "select-one".into(),
        Some("button") if matches!(value.as_str(), "reset" | "button") => value,
        Some("button") => "submit".into(),
        _ if INPUT_TYPES.contains(&value.as_str()) => value,
        _ => "text".into(),
    }
}

/// The single-letter code in `pad`'s control list.
fn control_code(node: NodeRef<'_, Node>) -> &'static str {
    match control_type(node).as_str() {
        "select-one" | "select-multiple" => "sl",
        "textarea" => "ta",
        "button" => "b",
        "checkbox" => "c",
        "email" => "e",
        "file" => "f",
        "hidden" => "h",
        "number" => "n",
        "password" => "p",
        "radio" => "r",
        "search" => "se",
        "reset" if is_named(node, "button") => "rs",
        "submit" => "s",
        "tel" => "tel",
        "url" => "u",
        _ => "t",
    }
}

/// The shorter code in `ffp`: the `pad` code of common types, and `-` for the rest.
fn short_type(node: NodeRef<'_, Node>) -> &'static str {
    const COMMON: &[&str] = &[
        "button", "checkbox", "email", "hidden", "number", "password", "radio", "submit", "text",
        "textarea",
    ];
    if COMMON.contains(&control_type(node).as_str()) {
        control_code(node)
    } else {
        "-"
    }
}

/// `ffp`: the form's method, control count, and the first controls' types.
fn form_fields(form: NodeRef<'_, Node>) -> String {
    let controls = controls(form);
    let types: String = controls
        .iter()
        .copied()
        .take(SAMPLE)
        .map(short_type)
        .collect();
    let method = attribute(form, "method");
    format!("m:{method}|f:{}|{types}", controls.len())
}

/// Counts above 99 are reported as "99+".
fn capped(count: usize) -> String {
    if count > 99 {
        "99+".to_owned()
    } else {
        count.to_string()
    }
}

/// `pad`: a fixed set of structural counts joined with `|`.
fn describe(
    kind: &str,
    method: &str,
    action: &str,
    controls: &[NodeRef<'_, Node>],
    links: usize,
) -> String {
    let hidden = controls
        .iter()
        .filter(|node| is_named(**node, "input") && control_type(**node) == "hidden")
        .count();
    let submits = controls
        .iter()
        .filter(|node| is_named(**node, "button") || control_code(**node) == "s")
        .count();
    let types: Vec<&str> = controls
        .iter()
        .take(SAMPLE)
        .map(|node| control_code(*node))
        .collect();
    format!(
        "{kind}|{method}|{action}|{}|{}|{}|{}|{}",
        capped(controls.len()),
        capped(hidden),
        capped(submits),
        capped(links),
        types.join(","),
    )
}

/// `pac` and `pad`: the apparent purpose and the structure of the form or container around the
/// widget.
struct FormSignals {
    pac: String,
    pad: String,
}

fn form_signals(form: NodeRef<'_, Node>, base: &Url) -> FormSignals {
    let controls = controls(form);
    let links = descendants_named(form, &["a"]).count();
    let method = match normalise(attribute(form, "method")).as_str() {
        // Without a method, a form submits with `get`.
        "" | "get" => "g",
        "post" => "p",
        "dialog" => "d",
        _ => "x",
    };
    let action = match attribute(form, "action") {
        "" => "e",
        target => match base.join(target) {
            Ok(url) if url.origin() == base.origin() => "s",
            Ok(_) => "c",
            Err(_) => "b",
        },
    };
    FormSignals {
        pac: classify(&controls, &context_text(form, &controls, &[], base)),
        pad: describe("f", method, action, &controls, links),
    }
}

/// With no surrounding form, `api.js` looks up to five levels for the nearest
/// ancestor that holds form controls or links outside the widget itself.
fn container_signals(wrapper: NodeRef<'_, Node>, base: &Url) -> FormSignals {
    let none = || FormSignals {
        pac: "n".to_owned(),
        pad: "n|n|n|0|0|0|0|".to_owned(),
    };
    let ancestors: Vec<_> = ancestors(wrapper)
        .take_while(|node| !is_named(*node, "body"))
        .take(5)
        .collect();
    let Some(outermost) = ancestors.last() else {
        return none();
    };
    let outside = |node: &NodeRef<'_, Node>| !wrapper.descendants().any(|inner| inner == *node);
    let controls: Vec<_> = controls(*outermost).into_iter().filter(outside).collect();
    let links: Vec<_> = descendants_named(*outermost, &["a"])
        .filter(outside)
        .collect();
    for ancestor in &ancestors {
        let within =
            |node: &&NodeRef<'_, Node>| ancestor.descendants().any(|inner| inner == **node);
        let inner: Vec<_> = controls.iter().filter(within).copied().collect();
        let anchors: Vec<_> = links.iter().filter(within).copied().collect();
        if !inner.is_empty() || !anchors.is_empty() {
            return FormSignals {
                pac: classify(&inner, &context_text(*ancestor, &inner, &anchors, base)),
                pad: describe("c", "n", "n", &inner, anchors.len()),
            };
        }
    }
    none()
}

/// Text compared against keywords is cut to 512 code units first.
fn normalise(value: &str) -> String {
    js_prefix(value, 512).to_lowercase()
}

/// Reads attribute values and labels that suggest a control's purpose. Preserves attribute
/// order because adjacent words form search keys.
fn control_words(node: NodeRef<'_, Node>) -> Vec<String> {
    const DESCRIPTIVE: &[&str] = &[
        "autocomplete",
        "type",
        "name",
        "id",
        "aria-label",
        "placeholder",
    ];
    let Some(element) = node.value().as_element() else {
        return Vec::new();
    };
    let mut words: Vec<String> = element
        .attrs()
        .filter(|(name, _)| DESCRIPTIVE.contains(name))
        .map(|(_, value)| normalise(value))
        .collect();
    if is_named(node, "button") {
        words.push(normalise(attribute(node, "value")));
        words.push(normalise(&text(node)));
    } else if is_named(node, "input") && matches!(control_type(node).as_str(), "button" | "submit")
    {
        words.push(normalise(attribute(node, "value")));
    }
    words
}

/// Words around a form or container, in the loader's tokenization order.
fn context_text(
    node: NodeRef<'_, Node>,
    controls: &[NodeRef<'_, Node>],
    links: &[NodeRef<'_, Node>],
    base: &Url,
) -> String {
    let mut words = vec![
        normalise(attribute(node, "id")),
        normalise(attribute(node, "class")),
    ];
    if is_named(node, "form") {
        words.push(normalise(attribute(node, "name")));
        words.push(normalise(&pathname(attribute(node, "action"), base)));
    }
    for control in controls.iter().take(SAMPLE) {
        words.extend(control_words(*control));
    }
    if is_named(node, "form") {
        words.extend(
            descendants_named(node, &["label"])
                .take(SAMPLE)
                .map(|label| normalise(&text(label))),
        );
    } else {
        for link in links.iter().take(SAMPLE) {
            words.push(normalise(&text(*link)));
            words.push(normalise(&pathname(attribute(*link, "href"), base)));
        }
    }
    words.join(" ")
}

fn pathname(target: &str, base: &Url) -> String {
    if target.is_empty() {
        return String::new();
    }
    base.join(target)
        .map(|url| url.path().to_owned())
        .unwrap_or_default()
}

// Keywords that classify visible form text. `api.js` compares djb2 hashes; direct word
// comparison is equivalent for these lists and easier to read.
const CHECKOUT: &[&str] = &[
    "checkout", "payment", "card", "billing", "shipping", "postal", "zip", "order",
];
const COMMENT: &[&str] = &["comment", "reply", "review", "post"];
const CONTACT: &[&str] = &["contact", "message", "support"];
const LOGIN: &[&str] = &["login", "log in", "sign in", "signin"];
const NEWSLETTER: &[&str] = &["newsletter", "subscribe"];
const RESET: &[&str] = &["reset", "forgot", "recover"];
const SIGNUP: &[&str] = &["signup", "sign up", "register", "create account", "join"];
const UPLOAD: &[&str] = &["upload", "attach"];

/// Splits form text into words and adjacent word pairs using `api.js` rules.
fn tokens(text: &str) -> Vec<String> {
    let words: Vec<&str> = text
        .split(|character: char| !(character.is_ascii_lowercase() || character.is_ascii_digit()))
        .filter(|word| !word.is_empty())
        .collect();
    let pairs = words.windows(2).map(|pair| pair.join(" "));
    words.iter().map(ToString::to_string).chain(pairs).collect()
}

/// `pac`: what the form around the widget appears to be for.
fn classify(controls: &[NodeRef<'_, Node>], text: &str) -> String {
    let tokens = tokens(text);
    let has = |words: &[&str]| tokens.iter().any(|token| words.contains(&token.as_str()));
    let typed = |kind: &str| {
        controls
            .iter()
            .filter(|node| is_named(**node, "input") && control_type(**node) == kind)
            .count()
    };
    let email = typed("email") > 0;
    let file = typed("file") > 0;
    let passwords = typed("password");
    let password = passwords > 0;
    let textarea = controls.iter().any(|node| is_named(*node, "textarea"));
    let login = has(LOGIN);
    if has(RESET) && !login && (email || password) {
        "r"
    } else if password && passwords <= 1 && login {
        "l"
    } else if password && (passwords > 1 || has(SIGNUP)) {
        "s"
    } else if has(CHECKOUT) {
        "c"
    } else if file || has(UPLOAD) {
        "up"
    } else if textarea && has(COMMENT) {
        "cp"
    } else if has(CONTACT) {
        "ct"
    } else if email && has(NEWSLETTER) {
        "nl"
    } else {
        "u"
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding_page;
    use crate::embedding_page::tests::PAGE;
    use crate::js::{JsValue, json};

    /// Collects page signals from `html` after rendering its first widget.
    fn signals(html: &str) -> JsValue {
        let url = Url::parse("http://x/").unwrap();
        let page = RenderedPage::render(html, url, "w", None).unwrap();
        json!(page.signals(&Layout::default(), None))
    }

    #[test]
    fn reproduces_a_captured_sessions_page_signals() {
        let layout = Layout {
            inner_width: 1280,
            inner_height: 813,
            visibility_state: "hidden".into(),
            widget_top: 113.875,
            widget_right: Some(1272.0),
            ..Layout::default()
        };
        let signals = embedding_page::tests::page().signals(&layout, Some("managed"));
        // Recorded from a real browser rendering exactly this page.
        let expected = json!({
            "d.cT": [],
            "ht.atrs": [],
            "pg.ref": "",
            "pi": {
                "ffp": "nf", "ii": false, "lH": "http://127.0.0.1:8000/index.html", "mL": 1,
                "pac": "n", "pad": "n|n|n|0|0|0|0|",
                "pfp": "htm>hea>met_ch>tit>-tscr_sr_as_de>-tbod>h1>p>-tdiv_cl_da_da_da>-t",
                "sL": 1, "sR": true, "ssL": 0, "t": "19|3058264090", "tL": 12,
                "vDa": "always", "vDeh": false, "vDhp": "wrapper", "vDhr": null,
                "vDie": true, "vDmd": "managed", "vDmt": "wrapper", "vDrs": [],
                "vDuh": false,
                "vDvp": {"height": 813, "visibilityState": "hidden", "width": 1280},
                "wp": "113.875|1272", "xp": "/div[1]/div[1]"
            },
            "w.iW": 1280
        });
        // Field order is part of the message, so compare the serialized text.
        assert_eq!(json!(signals).stringify(), expected.stringify());
    }

    /// Checks `ffp`, `pac`, and `pad` for forms and nearby controls. Without a surrounding
    /// form, searches up to five ancestors. Excludes the widget's own nodes.
    #[test]
    fn summarizes_the_form_or_container_around_the_widget() {
        let login = PAGE.replace(
            "<h1>Heading</h1>",
            r#"<form method="post" action="/login"><label>Sign in</label>
               <input type="email" name="email"><input type="password" name="password">
               <button>Sign in</button></form>"#,
        );
        // The form precedes the original container, so its widget is first. The widget's own
        // hidden response field counts as a control.
        let in_login = login.replace(
            "</form>",
            r#"<div class="cf-turnstile" data-sitekey="k"></div></form>"#,
        );
        let nested = |depth| {
            format!(
                "<section><input type=email name=newsletter>{}<div class=cf-turnstile data-sitekey=k></div>{}</section>",
                "<div>".repeat(depth),
                "</div>".repeat(depth),
            )
        };
        let none = ["nf", "n", "n|n|n|0|0|0|0|"];
        let newsletter = ["nf", "nl", "c|n|n|1|0|0|0|e"];
        let link = "<section><input type=email><a href=/subscribe><div class=cf-turnstile data-sitekey=k></div></a></section>";
        let mut cases = vec![
            (login, none),
            (in_login, ["m:post|f:4|epsh", "l", "f|p|s|4|1|1|0|e,p,s,h"]),
            (link.to_owned(), ["nf", "u", "c|n|n|0|0|0|1|"]),
        ];
        for depth in 0..=6 {
            cases.push((nested(depth), if depth <= 3 { newsletter } else { none }));
        }
        for (html, expected) in cases {
            let pi = &signals(&html)["pi"];
            assert_eq!([&pi["ffp"], &pi["pac"], &pi["pad"]], expected, "{html}");
        }
    }

    /// Checks that widgets with `chlPageData` omit the form summary, as observed on challenge
    /// pages. An empty `chlPageData` value does not count as supplied.
    #[test]
    fn page_data_leaves_out_the_form_summary() {
        let url = Url::parse("http://x/").unwrap();
        let rendered = |page_data: &str| {
            let values = json!({"sitekey": "k", "chlPageData": page_data});
            let params = Params::from_render(values.as_object().unwrap()).unwrap();
            let page = RenderedPage::render_explicit(PAGE, url.clone(), "w", "body", params);
            json!(page.unwrap().signals(&Layout::default(), None))
        };
        let challenge = rendered("data");
        assert!(challenge["pi"].get("pac").is_none());
        assert!(challenge["pi"].get("pad").is_none());
        assert_eq!(rendered("")["pi"]["pac"], "n");
    }

    #[test]
    fn keywords_match_the_hashes_in_api_js() {
        for (words, hashes) in [
            (
                LOGIN,
                &[173_246_534u32, 1_422_232_710, 2_984_385_681, 2_172_846_769][..],
            ),
            (NEWSLETTER, &[517_084_052, 3_937_470_477][..]),
            (UPLOAD, &[1_759_493_702, 1_322_218_894][..]),
        ] {
            let computed: Vec<u32> = words.iter().map(|word| djb2(word)).collect();
            assert_eq!(computed, hashes, "{words:?}");
        }
    }

    #[test]
    fn explicit_parameters_preserve_empty_values_and_case_collisions() {
        let values = json!({"sitekey": "k", "theme": "dark", "THEME": "", "cData": "", "chlPageData": "", "response-field": "false"});
        let params = Params::from_render(values.as_object().unwrap()).unwrap();
        assert_eq!(params.theme, "auto");
        assert_eq!(params.cdata.as_deref(), Some(""));
        assert_eq!(params.chl_page_data.as_deref(), Some(""));
        assert!(!params.response_field);
        let not_text = json!({"sitekey": "k", "unused": false});
        assert!(Params::from_render(not_text.as_object().unwrap()).is_err());
    }

    /// Checks that a widget uses the container matching its sitekey and its configured action.
    /// Without a matching container, it renders from script outside any form.
    #[test]
    fn renders_a_named_widget_from_its_container_or_as_script_would() {
        let url = Url::parse("http://x/").unwrap();
        let html = r#"<body><div class="cf-turnstile" data-sitekey="a"></div><form>
            <div class="cf-turnstile" data-sitekey="b" data-action="old" data-cdata="kept"></div>
            </form></body>"#;
        let widget = Widget {
            sitekey: "b".into(),
            action: Some("login".into()),
            cdata: None,
        };
        let page = RenderedPage::render(html, url.clone(), "w", Some(&widget)).unwrap();
        assert_eq!(page.params.sitekey, "b");
        assert_eq!(page.params.action.as_deref(), Some("login"));
        assert_eq!(page.params.cdata.as_deref(), Some("kept"));
        assert!(page.parent.form.starts_with("m:"), "{}", page.parent.form);

        let widget = Widget {
            sitekey: "c".into(),
            ..Widget::default()
        };
        let page = RenderedPage::render(html, url, "w", Some(&widget)).unwrap();
        assert_eq!(page.params.sitekey, "c");
        assert_eq!(page.params.action, None);
        assert_eq!(page.parent.form, "nf");
    }

    #[test]
    fn limits_count_utf16_code_units_without_splitting_characters() {
        assert_eq!(js_prefix("abcdef", 3), "abc");
        assert_eq!(js_prefix("ab", 3), "ab");
        assert_eq!(js_prefix("éèê", 2), "éè");
        assert_eq!(
            js_prefix("a😀b", 2),
            "a",
            "an astral character is two code units; half of one is dropped"
        );
        assert_eq!(js_prefix("a😀b", 3), "a😀");
    }

    #[test]
    fn fingerprints_cut_multibyte_names_at_their_limit() {
        // Attribute names are truncated to two code units. Repeated two-byte names make the
        // 500-unit limit split a UTF-8 sequence.
        let attributes: String = (0..400).map(|index| format!(" é{index}=x")).collect();
        let html = format!(
            r#"<html><body><div{attributes}></div><div class="cf-turnstile" data-sitekey="k"></div></body></html>"#
        );
        let shape = signals(&html)["pi"]["pfp"].as_str().unwrap().to_owned();
        assert_eq!(shape.encode_utf16().count(), FINGERPRINT_LIMIT);
    }
}
