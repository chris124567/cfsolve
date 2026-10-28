//! Builds the `extraParams` reply `api.js` sends to the iframe's `requestExtraParams`: widget
//! configuration, elapsed times, loader resource timing, and the page summary.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use swc_core::ecma::ast::{CallExpr, Expr, KeyValueProp};
use swc_core::ecma::visit::{Visit, VisitWith};
use url::Url;

use crate::challenge::reduced_timing::{Entry, ResourceTiming};
use crate::embedding_page::page::{Layout, PageSignals, RenderedPage};
use crate::embedding_page::render_sample::RenderSample;
use crate::engine::Engine;
use crate::js::{JsValue, ast, json};
use crate::resource_timing::{NEXT_HOP_PROTOCOL, Phases, ResourceMeasurement};
use crate::{candidates, random_id};

/// Loader timestamps from `Date.now()`, in milliseconds since the loader started. Loaded from
/// the fingerprint's `timeline` section, based on a browser capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Timeline {
    /// When the loader script itself was fetched, relative to navigation start.
    pub script_fetch: f64,
    /// The loader began rendering the widgets declared in the page.
    pub implicit_render: i64,
    /// `render()` began building the widget.
    pub render_start: i64,
    /// The iframe element was in the document.
    pub render_end: i64,
    /// The iframe announced itself.
    pub init_start: i64,
    /// The iframe asked for these parameters.
    pub params_start: i64,
    /// The page summary started being collected.
    pub collect_start: i64,
    /// The message was posted.
    pub sent: i64,
}

/// Loader script details observed by the embedding page.
#[derive(Debug, Clone)]
pub(crate) struct ApiScript {
    /// `au`: the script's URL as the page requested it, before any redirect.
    pub url: Url,
    /// `ch`: the loader build required by the iframe. A mismatch triggers an `api.js` reload
    /// before the iframe continues.
    pub build: String,
    /// Challenge-platform route requested by this loader. It changes with the build; a stale
    /// route can fetch an iframe that rejects `build`.
    pub variant: String,
    pub start_time_ms: f64,
    pub response: LoaderResponse,
    /// The stack sample the loader takes as it renders the page's widgets.
    pub render_sample: RenderSample,
    /// The loader's source, for [`RenderSample::explicit`] once a render's caller is known.
    pub source: String,
}

/// Resource timing information for the loader response.
#[derive(Debug, Clone)]
pub(crate) struct LoaderResponse {
    /// Final response URL after redirects.
    pub body_url: Url,
    /// Time from request start to the last body byte, rounded to the page clock's resolution.
    pub duration_ms: f64,
    pub encoded_body_size: u64,
    pub decoded_body_size: u64,
    /// Whether the page can read the response's detailed timings; see [`timing_exposed`].
    pub timing_exposed: bool,
    /// Whether the page can read the response's sizes. WebKit withholds the cross-origin
    /// loader's sizes even when its timings are exposed.
    pub sizes_exposed: bool,
    /// How the browser divides the fetch's duration.
    pub phases: Phases,
}

/// Checks whether `Timing-Allow-Origin` value `allowed` permits `page` to read detailed timings
/// for `url`.
#[must_use]
pub(crate) fn timing_exposed(url: &Url, page: &Url, allowed: &str) -> bool {
    url.origin() == page.origin()
        || allowed.split(',').any(|entry| {
            let entry = entry.trim();
            entry == "*" || entry == page.origin().ascii_serialization()
        })
}

impl ApiScript {
    /// Reads the build, route, and stack sample for `engine` from loader `source` fetched at
    /// `url`, using `response` metadata.
    pub(crate) fn from_source(
        url: Url,
        source: &str,
        response: LoaderResponse,
        timeline: &Timeline,
        engine: Engine,
    ) -> Result<Self> {
        let parsed = ast::parse_javascript("the Turnstile loader", source)?;
        let mut literals = Literals::default();
        parsed.script.visit_with(&mut literals);
        let build = candidates::at_most_one_distinct(literals.builds, "build hash")?
            .context("loader script has no api.js build hash; is this really api.js?")?;
        let variant =
            candidates::at_most_one_distinct(literals.routes, "challenge-platform route")?
                .context("loader script names no challenge-platform route")?;
        let render_sample =
            RenderSample::from_parsed(&parsed, stack_url(&url, &response, engine), engine)?;
        Ok(Self {
            url,
            build,
            variant,
            start_time_ms: timeline.script_fetch,
            response,
            render_sample,
            source: source.to_owned(),
        })
    }

    /// The loader's URL as `engine` names it in stacks.
    #[must_use]
    pub(crate) fn stack_url(&self, engine: Engine) -> &Url {
        stack_url(&self.url, &self.response, engine)
    }

    /// Reports the loader fetch as a resource timing entry. Estimates phases and withholds
    /// restricted attributes unless the response permits access.
    fn measurement(&self) -> ResourceMeasurement {
        let response = &self.response;
        let end = self.start_time_ms + response.duration_ms;
        if !response.timing_exposed {
            return ResourceMeasurement::restricted(response.duration_ms, end);
        }
        let mut measured = ResourceMeasurement::estimated(
            response.duration_ms,
            response.encoded_body_size,
            response.phases,
        );
        if !response.sizes_exposed {
            measured.transfer_size = 0;
            measured.body_size = 0;
        }
        measured
    }

    /// The loader's `PerformanceResourceTiming`, which the iframe reduces as [`Self::reduced`]
    /// does. Without `Timing-Allow-Origin`, only `startTime`, `fetchStart`, `duration`, and
    /// `responseEnd` remain available.
    #[must_use]
    pub(crate) fn timing(&self) -> JsValue {
        let response = &self.response;
        let measured = self.measurement();
        let start = self.start_time_ms;
        let end = start + measured.duration;
        let exposed = response.timing_exposed;
        let connection = if exposed { start } else { 0.0 };
        // Restricted entries report zero for response start, so the response interval extends
        // from zero to response end.
        let response_start = end - measured.response;
        let request_start = response_start - measured.request;
        json!({
            "name": self.url.as_str(),
            "entryType": "resource",
            "startTime": start,
            "duration": measured.duration,
            "initiatorType": "script",
            "deliveryType": "",
            "nextHopProtocol": if exposed { NEXT_HOP_PROTOCOL } else { "" },
            "renderBlockingStatus": "non-blocking",
            "workerStart": 0.0,
            "redirectStart": 0.0,
            "redirectEnd": 0.0,
            "fetchStart": start,
            "domainLookupStart": connection,
            "domainLookupEnd": connection,
            "connectStart": connection,
            "connectEnd": connection,
            "secureConnectionStart": connection,
            "requestStart": request_start,
            "responseStart": response_start,
            "firstInterimResponseStart": 0.0,
            "finalResponseHeadersStart": response_start,
            "responseEnd": end,
            "transferSize": measured.transfer_size,
            "encodedBodySize": measured.body_size,
            "decodedBodySize": if response.sizes_exposed { response.decoded_body_size } else { 0 },
            "responseStatus": if exposed { 200 } else { 0 },
            "contentType": if exposed { "script" } else { "" },
        })
    }

    /// Reduces [`Self::timing`] to the six fields forwarded by the challenge.
    #[must_use]
    pub(crate) fn reduced(&self, timing: &ResourceTiming) -> JsValue {
        timing.reduce(&Entry {
            name: self.url.as_str(),
            start: self.start_time_ms,
            measured: self.measurement(),
        })
    }
}

/// V8 names the loader in stacks by the URL requested, JavaScriptCore by the final response URL.
fn stack_url<'u>(requested: &'u Url, response: &'u LoaderResponse, engine: Engine) -> &'u Url {
    match engine {
        Engine::Chromium => requested,
        Engine::WebKit => &response.body_url,
    }
}

/// The loader's candidates for its build hash and challenge-platform route.
#[derive(Default)]
struct Literals {
    builds: Vec<String>,
    routes: Vec<String>,
}

impl Visit for Literals {
    /// `ch: "e694063b5082"`: the twelve-digit hexadecimal build hash, which the iframe compares
    /// with its compiled-in build.
    fn visit_key_value_prop(&mut self, property: &KeyValueProp) {
        if ast::key_str(&property.key) == Some("ch")
            && let Some(value) = ast::static_str(&property.value)
            && value.len() == 12
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            self.builds.push(value.to_owned());
        }
        property.visit_children_with(self);
    }

    /// `f(..., "b", Reason.New, ...)`: the one-letter route beside the render reason when the
    /// loader builds a widget's first iframe URL.
    fn visit_call_expr(&mut self, call: &CallExpr) {
        for pair in call.args.windows(2) {
            if let Expr::Member(reason) = &*pair[1].expr
                && ast::member_str(&reason.prop) == Some("New")
                && let Some(route) = ast::static_str(&pair[0].expr)
                && route.len() == 1
                && route.bytes().all(|byte| byte.is_ascii_lowercase())
            {
                self.routes.push(route.to_owned());
            }
        }
        call.visit_children_with(self);
    }
}

/// The embedding page's reply to `requestExtraParams`. Fields serialize in the order `api.js`
/// writes them, which the merge into `_cf_chl_opt` keeps.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExtraParams<'page> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'page str>,
    pub api_js_mismatch_reload_attempts: u32,
    pub api_js_mismatch_reload_completed_count: u32,
    pub api_js_resource_timing: JsValue,
    pub appearance: &'page str,
    #[serde(rename = "au")]
    pub loader_url: &'page str,
    #[serde(rename = "cData", skip_serializing_if = "Option::is_none")]
    pub cdata: Option<&'page str>,
    #[serde(rename = "ch")]
    pub build: &'page str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chl_page_data: Option<&'page str>,
    /// Stack samples: method, elapsed milliseconds, stack, and consecutive occurrence count.
    #[serde(rename = "cs")]
    pub samples: Vec<(f64, i64, &'page str, u32)>,
    pub event: &'static str,
    pub execution: &'page str,
    #[serde(rename = "expiry-interval")]
    pub expiry_interval: i64,
    pub language: &'page str,
    /// The challenge variant. Absent on the first render.
    #[serde(rename = "rcV")]
    pub challenge_variant: &'static str,
    #[serde(rename = "refresh-expired")]
    pub refresh_expired: &'page str,
    #[serde(rename = "refresh-timeout")]
    pub refresh_timeout: &'page str,
    pub retry: &'page str,
    #[serde(rename = "retry-interval")]
    pub retry_interval: i64,
    /// Both sides check this before reading a message.
    pub source: &'static str,
    pub upgrade_attempts: u32,
    pub upgrade_completed_count: u32,
    pub url: &'page str,
    #[serde(rename = "wPr")]
    pub signals: PageSignals,
    pub widget_id: &'page str,
    #[serde(flatten)]
    pub times: ElapsedTimes,
}

/// Elapsed loader times reported at the end of [`ExtraParams`], in milliseconds.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ElapsedTimes {
    pub time_extra_params_ms: i64,
    pub time_init_ms: i64,
    pub time_load_init_ms: i64,
    pub time_params_ms: i64,
    pub time_render_ms: i64,
    pub time_tief_ms: i64,
}

impl Timeline {
    /// Returns the elapsed times reported by the loader.
    fn times(&self) -> ElapsedTimes {
        ElapsedTimes {
            time_extra_params_ms: self.sent - self.render_start,
            time_init_ms: self.init_start - self.render_end,
            // The clock starts when the loader script runs, so the mark is already an elapsed time.
            time_load_init_ms: self.sent,
            time_params_ms: self.params_start - self.init_start,
            time_render_ms: self.render_end - self.render_start,
            time_tief_ms: self.sent - self.collect_start,
        }
    }

    /// Reconstructs the timeline from reported `times` and the `implicit_render` stack sample.
    /// Reverses [`Self::times`]. The caller supplies `script_fetch` because payloads do not report
    /// when the loader was fetched.
    #[must_use]
    pub(crate) fn from_times(
        times: &ElapsedTimes,
        implicit_render: i64,
        script_fetch: f64,
    ) -> Self {
        let sent = times.time_load_init_ms;
        let render_start = sent - times.time_extra_params_ms;
        let render_end = render_start + times.time_render_ms;
        let init_start = render_end + times.time_init_ms;
        Self {
            script_fetch,
            implicit_render,
            render_start,
            render_end,
            init_start,
            params_start: init_start + times.time_params_ms,
            collect_start: sent - times.time_tief_ms,
            sent,
        }
    }
}

/// Builds the reply to `requestExtraParams`. Omits widget parameters that the page does not
/// set. The iframe treats missing and `undefined` values alike, applying `||` defaults or
/// storing them directly.
#[must_use]
pub(crate) fn collect<'page>(
    page: &'page RenderedPage,
    layout: &Layout,
    timeline: &Timeline,
    script: &'page ApiScript,
    mode: Option<&str>,
) -> ExtraParams<'page> {
    let params = &page.params;
    ExtraParams {
        action: params.action.as_deref(),
        api_js_mismatch_reload_attempts: 0,
        api_js_mismatch_reload_completed_count: 0,
        api_js_resource_timing: script.timing(),
        appearance: &params.appearance,
        loader_url: script.url.as_str(),
        cdata: params.cdata.as_deref(),
        build: &script.build,
        chl_page_data: params.chl_page_data.as_deref(),
        samples: vec![(
            script.render_sample.method,
            timeline.implicit_render,
            &script.render_sample.stack,
            1,
        )],
        event: "extraParams",
        execution: &params.execution,
        expiry_interval: params.expiry_interval,
        language: &params.language,
        challenge_variant: "",
        refresh_expired: &params.refresh_expired,
        refresh_timeout: &params.refresh_timeout,
        retry: &params.retry,
        retry_interval: params.retry_interval,
        source: "cloudflare-challenge",
        upgrade_attempts: 0,
        upgrade_completed_count: 0,
        url: page.url.as_str(),
        signals: page.signals(layout, mode),
        widget_id: &page.widget_id,
        times: timeline.times(),
    }
}

/// The widget's first iframe URL, with an empty challenge variant, which later responses may
/// supply.
pub(crate) fn iframe_url(page: &RenderedPage, script: &ApiScript) -> Result<Url> {
    let params = &page.params;
    let feedback = if params.feedback_enabled {
        "fbE"
    } else {
        "fbD"
    };
    let origin = script.url.origin().ascii_serialization();
    let route = &script.variant;
    let mut url = Url::parse(&format!(
        "{origin}/cdn-cgi/challenge-platform/h/{route}/turnstile/f/av0/rch/{}/{}/{}/{feedback}/new/{}",
        page.widget_id, params.sitekey, params.theme, params.size
    ))
    .context("building the challenge iframe URL")?;
    let mut query = url.query_pairs_mut();
    query.append_pair("lang", &params.language);
    for (key, value) in [
        ("offlabel_show_privacy", params.offlabel_show_privacy),
        ("offlabel_show_help", params.offlabel_show_help),
    ] {
        if let Some(value) = value {
            query.append_pair(key, &value.to_string());
        }
    }
    drop(query);
    Ok(url)
}

/// Generates a five-character widget ID using the `api.js` format.
#[must_use]
pub(crate) fn widget_id() -> String {
    random_id::random_id(b"abcdefghijklmnopqrstuvwxyz0123456789", 5)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::reduced_timing::Measure;

    fn page() -> RenderedPage {
        RenderedPage::render(
            r#"<html><head><title>t</title>
            <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script></head>
            <body><div class="cf-turnstile" data-sitekey="0x4AAA" data-action="login"
                data-theme="dark" data-size="compact" data-language="de"></div></body></html>"#,
            Url::parse("https://example.com/login").unwrap(),
            "j5gbk",
            None,
        )
        .unwrap()
    }

    #[test]
    fn finds_build_hashes_and_routes_only_where_the_loader_keeps_them() {
        let literals = |source: &str| {
            let mut literals = Literals::default();
            let parsed = ast::parse_javascript("t", source).unwrap();
            parsed.script.visit_with(&mut literals);
            literals
        };
        let hash = "e694063b5082";
        for (source, builds) in [
            (
                r#"me(Q,Ce({action:o.action,ch:"e694063b5082",cs:At(o)}));"#,
                &[hash][..],
            ),
            (
                "x = {'ch': `e694063b5082`}; y = { ch : 'e694063b5082' };",
                &[hash, hash],
            ),
            // A non-hash `ch` must not be mistaken for the build.
            (r#"x = {ch: "auto", bach: "e694063b5082"};"#, &[]),
        ] {
            assert_eq!(literals(source).builds, builds, "{source}");
        }
        for (source, routes) in [
            (r#"f(a, "g", e.New); f('g', e['New']);"#, &["g", "g"][..]),
            (r#"f("G", e.New); f("gg", e.New); e.New = 'new';"#, &[]),
        ] {
            assert_eq!(literals(source).routes, routes, "{source}");
        }
    }
}
