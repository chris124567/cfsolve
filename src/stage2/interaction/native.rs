//! Builds the click's measurements from the profile's checkbox bounds, and reads the iframe's
//! stylesheets for the UI audit, without a browser.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};

use super::click::Source;
use super::{css, ui};
use crate::embedding_page::page::Layout;
use crate::engine::Engine;
use crate::js::{JsObject, JsValue, json};

/// Settings from the fingerprint's `interaction` section: iframe size, checkbox bounds, and
/// pointer travel time. May also set the iframe's screen position, overriding the embedding
/// page.
#[derive(Clone, Copy, Deserialize)]
pub(crate) struct Viewport {
    pub width: u32,
    pub height: u32,
    /// The checkbox input's bounds in the iframe, as `getBoundingClientRect` reports them. The
    /// input covers its label, so its width depends on the device's fonts.
    pub checkbox: Rect,
    pub ready_delay_ms: u64,
    pub screen_origin_x: Option<f64>,
    pub screen_origin_y: Option<f64>,
    pub device_pixel_ratio: f64,
    /// Whether the device is tapped with a finger instead of clicked with a mouse.
    pub touch: bool,
}

/// An element's bounds, in CSS pixels.
#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Viewport {
    /// Places the iframe at the embedding widget's position unless the fingerprint gives an
    /// explicit position. Uses the window dimensions in `geometry`.
    #[must_use]
    pub(crate) fn position_in_embedding_page(
        mut self,
        page: &Layout,
        geometry: &BTreeMap<String, f64>,
    ) -> Self {
        let border = geometry.get("outerWidth").map_or(0.0, |width| {
            ((width - f64::from(page.inner_width)) / 2.0).max(0.0)
        });
        let chrome = geometry.get("outerHeight").map_or(0.0, |height| {
            (height - f64::from(page.inner_height) - border).max(0.0)
        });
        self.screen_origin_x.get_or_insert(
            geometry.get("screenX").copied().unwrap_or(0.0) + border + page.widget_left,
        );
        self.screen_origin_y.get_or_insert(
            geometry.get("screenY").copied().unwrap_or(0.0) + chrome + page.widget_top,
        );
        self
    }
}

/// Native measurements used to build the click record and UI audit.
#[derive(Deserialize, Serialize)]
pub(crate) struct Measurement {
    /// Click-record measurements indexed by source object.
    pub sources: BTreeMap<Source, JsObject>,
    pub ui: ui::Measurement,
}

impl Measurement {
    /// Where the click lands, in client coordinates.
    pub(crate) fn click_point(&self) -> Result<(f64, f64)> {
        let event = self
            .sources
            .get(&Source::Event)
            .context("missing native mouse event")?;
        let coordinate = |name: &str| {
            event
                .get(name)
                .and_then(JsValue::as_f64)
                .context("missing click coordinate")
        };
        Ok((coordinate("clientX")?, coordinate("clientY")?))
    }

    /// Sets the click timestamp to its landing time on the iframe's `performance` clock.
    pub(crate) fn stamp(&mut self, performance_ms: f64) -> Result<()> {
        self.sources
            .get_mut(&Source::Event)
            .context("missing native mouse event")?
            .insert("timeStamp".into(), JsValue::from(performance_ms));
        Ok(())
    }
}

/// Measures a click on the center of `viewport`'s checkbox at `performance_ms`, and reads the
/// stylesheets of the iframe's `html`.
pub(crate) fn measure(
    viewport: &Viewport,
    html: &str,
    performance_ms: f64,
    engine: Engine,
) -> Measurement {
    let is_primary = engine == Engine::WebKit;
    let pointer_id = if is_primary {
        // WebKit's tap reports a primary pointer with a negative 32-bit id.
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes).expect("drawing a pointer id");
        -i64::from(u32::from_le_bytes(bytes) >> 1) - 1
    } else {
        1
    };
    let Rect {
        x,
        y,
        width,
        height,
    } = viewport.checkbox;
    // PointerEvent's legacy mouse coordinates are truncated CSS pixels;
    // offset coordinates round relative to the floating point border box.
    let client_x = (x + width / 2.0).trunc();
    let client_y = (y + height / 2.0).trunc();
    let screen_x = (client_x + viewport.screen_origin_x.unwrap_or(0.0)).trunc();
    let screen_y = (client_y + viewport.screen_origin_y.unwrap_or(0.0)).trunc();
    let input = "[object HTMLInputElement]";
    let body_name = "[object HTMLBodyElement]";
    let object = |value: JsValue| match value {
        JsValue::Object(object) => object,
        _ => unreachable!("the sources are object literals"),
    };
    // Split construction to keep both parts within the macro recursion limit.
    let mut event = object(json!({
        "altKey":false, "altitudeAngle":std::f64::consts::FRAC_PI_2, "azimuthAngle":0,
        "bubbles":true, "button":0, "buttons":0, "cancelable":true,
        "clientX":client_x, "clientY":client_y, "composed":true, "ctrlKey":false,
        "defaultPrevented":false, "detail":1, "eventPhase":2, "height":1,
        "isPrimary":is_primary, "isTrusted":true, "layerX":(client_x-x).round(), "layerY":(client_y-y).round(),
    }));
    event.extend(object(json!({
        "movementX":0, "movementY":0, "metaKey":false,
        "offsetX":(client_x-x).round(), "offsetY":(client_y-y).round(),
        "pageX":client_x, "pageY":client_y, "pointerId":pointer_id, "pointerType":"mouse",
        "pressure":0, "relatedTarget":null, "screenX":screen_x, "screenY":screen_y,
        "shiftKey":false, "srcElement":input, "tangentialPressure":0, "target":input,
        "timeStamp":performance_ms, "tiltX":0, "tiltY":0, "twist":0, "type":"click",
        "width":1, "x":client_x, "y":client_y
    })));
    let sources = BTreeMap::from([
        (Source::Event, event),
        (
            Source::Derived,
            object(
                json!({"relative_x":(client_x-x).floor(), "relative_y":(client_y-y).floor(),
                "is_touch":false, "element_from_point":body_name}),
            ),
        ),
        (Source::Document, object(json!({"activeElement":body_name}))),
        (
            Source::Rect,
            object(
                json!({"x":x, "y":y, "left":x, "top":y, "right":x+width, "bottom":y+height,
                "width":width, "height":height}),
            ),
        ),
        (
            Source::Window,
            object(
                json!({"scrollX":0, "scrollY":0, "innerWidth":viewport.width,
                "innerHeight":viewport.height, "devicePixelRatio":viewport.device_pixel_ratio}),
            ),
        ),
        (
            Source::Element,
            object(json!({"isConnected":true, "clientWidth":width.round(),
                "clientHeight":height.round(), "offsetWidth":width.round(),
                "offsetHeight":height.round()})),
        ),
        // The input is a transparent overlay covering its label, as observed in captures.
        (
            Source::Style,
            object(
                json!({"display":"block", "visibility":"visible", "pointerEvents":"auto",
                "opacity":"0"}),
            ),
        ),
    ]);
    Measurement {
        sources,
        ui: ui::Measurement {
            sheets: sheets(html, engine),
        },
    }
}

/// The document's stylesheets, as the UI audit scans them: every rule, with the text of its
/// keyframes.
fn sheets(html: &str, engine: Engine) -> Vec<ui::Sheet> {
    let document = Html::parse_document(html);
    let styles = Selector::parse("style").expect("style selector");
    let scanned = |rule: css::Rule| {
        if rule.header.starts_with("@keyframes ") {
            ui::Rule::Keyframes {
                text: css::keyframes(&rule, engine),
            }
        } else {
            ui::Rule::Other
        }
    };
    document
        .select(&styles)
        .map(|style| ui::Sheet {
            rules: css::rules(&style.inner_html())
                .into_iter()
                .map(scanned)
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::Browser;
    use crate::js;

    const HTML: &str = "<html><head><style>@keyframes move{0%{transform:translateY(2px);opacity:.5}100%{transform:translateY(0);opacity:1}}.x{color:red}</style></head><body></body></html>";

    #[test]
    fn the_click_lands_on_the_center_of_the_profiles_checkbox() {
        let viewport = Viewport {
            screen_origin_x: Some(8.0),
            screen_origin_y: Some(113.875),
            ..Browser::safari().solve.viewport
        };
        let raw = json!(measure(&viewport, HTML, 123.0, Engine::Chromium));
        assert_eq!(
            raw["sources"]["rect"],
            json!({"x":9, "y":20.5, "left":9, "top":20.5, "width":168.125, "height":24,
                "right":177.125, "bottom":44.5})
        );
        let event = &raw["sources"]["event"];
        assert_eq!(event["clientX"], 93.0);
        assert_eq!(event["clientY"], 32.0);
        assert_eq!(event["screenX"], 101.0);
        assert_eq!(event["screenY"], 145.0);
        assert_eq!(event["offsetY"], 12.0);
        assert_eq!(raw["sources"]["derived"]["relative_y"], 11.0);
        assert_eq!(event["timeStamp"], 123.0);
        assert_eq!(raw["sources"]["element"]["clientWidth"], 168.0);
        assert_eq!(
            raw["ui"]["sheets"][0]["rules"][0]["text"],
            "@keyframes move { \n  0% { transform: translateY(2px); opacity: 0.5; }\n  100% { transform: translateY(0px); opacity: 1; }\n}"
        );
        assert_eq!(raw["ui"]["sheets"][0]["rules"][1]["outcome"], "other");
        // Checks that serialized measurements deserialize as inputs for result construction.
        let mut measurement: Measurement = js::from_value(raw).unwrap();
        assert_eq!(measurement.click_point().unwrap(), (93.0, 32.0));
        measurement.stamp(42.5).unwrap();
        assert_eq!(measurement.sources[&Source::Event]["timeStamp"], 42.5);
    }

    #[test]
    fn embedding_page_screen_position_includes_reported_window_decorations() {
        let window = BTreeMap::from([
            ("outerWidth".into(), 1280.0),
            ("outerHeight".into(), 800.0),
            ("screenX".into(), 0.0),
            ("screenY".into(), 0.0),
        ]);
        let viewport = Browser::safari()
            .solve
            .viewport
            .position_in_embedding_page(&Layout::default(), &window);
        assert_eq!(viewport.screen_origin_x, Some(8.0));
        assert_eq!(viewport.screen_origin_y, Some(88.0));
    }
}
