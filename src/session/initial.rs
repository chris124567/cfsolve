//! Prepares the first payload: renders the embedding page, fetches and parses the iframe, and
//! merges page parameters with iframe state.

use std::mem;

use anyhow::{Context, Result};
use url::Url;

use super::Sink;
use super::timing::Timer;
use super::widget::Embedding;
use crate::browser::Page;
use crate::challenge::program::{ExtractedProgram, PreparedSession};
use crate::challenge::state::{Intervals, ScriptState};
use crate::challenge::{payload, source};
use crate::embedding_page::extra_params::{self, ApiScript, LoaderResponse};
use crate::embedding_page::page::{Layout, PageSignals, RenderedPage, Widget};
use crate::engine::{self, Lines};
use crate::http::{self, BrowserClient, Iframe, PageDocument, ReferrerPolicy, ScriptLoad};
use crate::js::{JsValue, Options, Payload, Window, json};
use crate::resource_timing::LoadTiming;
use crate::script::Source;
use crate::stage2::call_stack::{self, CaseOpcodes, ScriptPosition};
use crate::stage2::payload::Environment;
use crate::{deep_stack, performance_clock};

/// Default loader URL for pages that load Turnstile dynamically without a script tag.
const LOADER: &str = "https://challenges.cloudflare.com/turnstile/v0/api.js";

/// Page context for the widget session.
pub(crate) struct EmbeddingPage {
    pub page: RenderedPage,
    pub script: ApiScript,
    pub layout: Layout,
    /// Referrer policy for outgoing page requests.
    pub referrer_policy: ReferrerPolicy,
    pub embedding: Embedding,
}

/// Fetched iframe and shared deobfuscated source.
pub(crate) struct Fetched {
    pub iframe: Iframe,
    /// The iframe's inline challenge script, as served.
    pub javascript: String,
    /// The deobfuscated script, parsed once.
    pub source: Source,
    /// Original VM dispatch-case positions used for stack recovery.
    pub cases: CaseOpcodes,
    /// Iframe navigation timing, which sets the origin for its performance clock.
    pub navigation: LoadTiming,
    /// Navigation referrer reported by the iframe's `document.referrer`.
    pub referrer: Option<String>,
}

impl Fetched {
    /// Where the challenge script starts in the iframe HTML, for stack frames.
    pub(crate) fn script_position(&self) -> Result<ScriptPosition> {
        let html = &self.iframe.html;
        let start = html
            .find(&self.javascript)
            .context("the challenge script is not inline in the iframe HTML")?;
        let (line, column) = engine::line_and_column(&html[..start], Lines::Document);
        Ok(ScriptPosition {
            url: self.iframe.url.to_string(),
            line,
            column,
        })
    }
}

/// The evaluated first-payload template, before sender fields, and state for later payloads.
pub(crate) struct FirstPayload {
    /// The extracted program with fully populated request options.
    pub program: ExtractedProgram,
    pub state: ScriptState,
    /// Window globals the initial program installed.
    pub window: Window,
    pub globals: Window,
    /// Evaluated payload fields.
    pub plaintext: Payload,
    /// Base time used to assign session timestamps, in epoch milliseconds.
    pub marked_ms: i64,
}

impl FirstPayload {
    /// Adds installed options and values from `complete`, assigns timestamps, saves
    /// `options_artifact`, and evaluates the payload template.
    ///
    /// `complete` returns the parameter-merge timestamp option, if any, and the clock origin:
    /// merge time or build time. Sent timestamp differences match `intervals`.
    pub(crate) fn build<'mark>(
        sink: &dyn Sink,
        mut program: ExtractedProgram,
        state: ScriptState,
        intervals: &Intervals,
        options_artifact: &str,
        complete: impl FnOnce(&mut Options) -> (Option<&'mark str>, i64),
    ) -> Result<Self> {
        let installed = mem::take(&mut program.installed);
        let fields = &program.payload_fields;
        let options = &mut program.request.options;
        options.extend(installed.options);
        if let Some(log) = &state.post_log {
            log.start(options);
        }
        let (merge_mark, marked_ms) = complete(options);
        options.extend(state.timestamps(
            &payload::differences(fields),
            merge_mark,
            marked_ms,
            intervals,
        ));
        sink.json(options_artifact, options)?;
        let window = installed.window;
        let globals = payload::infer_globals(fields, &state, options, &window);
        let plaintext = payload::build(fields, options, &globals)?;
        Ok(Self {
            program,
            state,
            window,
            globals,
            plaintext,
            marked_ms,
        })
    }
}

/// Iframe state after merging page parameters, shared by the first and later payloads.
pub(crate) struct Merged {
    /// The first payload, which the probe payload extends.
    pub first: Payload,
    pub state: ScriptState,
    /// Window globals the initial program installed.
    pub window: Window,
    pub globals: Window,
    /// The global listing the selectors the iframe sees queried.
    pub selector_log: Option<String>,
    /// The resource timing entries the first payload reports.
    pub resources: Vec<JsValue>,
    /// Start of iframe navigation in milliseconds since the Unix epoch. Resource timing uses this
    /// as its time origin.
    pub time_origin_ms: i64,
    /// What the embedding page reported about itself in `extraParams`.
    pub page_signals: PageSignals,
}

impl Merged {
    /// Window values read by later payloads, including changes from first-payload calls.
    #[must_use]
    pub(crate) fn environment<'a>(
        &'a self,
        options: &'a Options,
        window: &'a Window,
    ) -> Environment<'a> {
        Environment {
            options,
            window,
            calls: &self.globals,
        }
    }
}

impl EmbeddingPage {
    /// A rendered widget and the page layout around it.
    #[must_use]
    pub(crate) fn new(
        sink: &dyn Sink,
        page: RenderedPage,
        script: ApiScript,
        layout: Layout,
        referrer_policy: ReferrerPolicy,
        embedding: Embedding,
    ) -> Self {
        sink.progress(&format!(
            "Embedding page {} renders widget {} for sitekey {} with api.js build {} on route h/{}",
            page.url, page.widget_id, page.params.sitekey, script.build, script.variant
        ));
        Self {
            page,
            script,
            layout,
            referrer_policy,
            embedding,
        }
    }
}

/// Renders `widget`, or the page's first widget, on the embedding page.
pub(crate) async fn render_page(
    client: &BrowserClient,
    sink: &dyn Sink,
    page: &Page,
    document: PageDocument,
    widget: Option<&Widget>,
) -> Result<EmbeddingPage> {
    sink.artifact("page.html", document.html.as_bytes())?;
    let widget_id = extra_params::widget_id();
    let rendered = RenderedPage::render(&document.html, document.url.clone(), &widget_id, widget)?;
    // A page that renders its widget from script may load the loader from script too.
    let loader = rendered
        .loader_script
        .clone()
        .or_else(|| widget.map(|_| Url::parse(LOADER).expect("the loader URL is valid")))
        .context("page links no Turnstile loader script")?;
    let (script, _) = fetch_loader(
        client,
        loader,
        ScriptLoad::Classic,
        &document.url,
        document.referrer_policy,
        page,
    )
    .await?;
    Ok(EmbeddingPage::new(
        sink,
        rendered,
        script,
        page.layout.clone(),
        document.referrer_policy,
        Embedding::Site,
    ))
}

/// Fetches the loader at `url`, timing it through the last body byte and rounding the duration
/// as browser resource timing does. `facts` say how the browser reports it.
pub(crate) async fn fetch_loader(
    client: &BrowserClient,
    url: Url,
    load: ScriptLoad,
    page: &Url,
    policy: ReferrerPolicy,
    facts: &Page,
) -> Result<(ApiScript, LoadTiming)> {
    let referer = policy.referrer(page, &url);
    let timer = Timer::start();
    let response = http::fetch_script(client, &url, load, page, referer.as_deref())
        .await
        .context("fetching the Turnstile loader script")?;
    let body_url = Url::parse(&response.uri().to_string())?;
    let allowed = response
        .headers()
        .get("timing-allow-origin")
        .map(http::header_text)
        .unwrap_or_default();
    let (body, network) = http::read_encoded(response).await?;
    let source = String::from_utf8(body).context("loader script is not UTF-8")?;
    let mut timing = timer.overall(url.as_str(), network.encoded_bytes);
    timing.duration_ms = timing.duration_ms.round();
    let timing_exposed = extra_params::timing_exposed(&url, page, &allowed);
    let response = LoaderResponse {
        body_url,
        duration_ms: timing.duration_ms,
        encoded_body_size: network.encoded_bytes,
        decoded_body_size: network.decoded_bytes,
        timing_exposed,
        sizes_exposed: timing_exposed && facts.resource_timing.sizes_exposed,
        phases: facts.resource_timing.phases,
    };
    let script = ApiScript::from_source(url, &source, response, &facts.timeline, client.engine())?;
    Ok((script, timing))
}

/// Fetches the iframe at `iframe_url` with the navigation referrer `referrer`.
pub(super) async fn fetch(
    client: &BrowserClient,
    sink: &dyn Sink,
    iframe_url: Url,
    referrer: Option<String>,
) -> Result<Fetched> {
    let timer = Timer::start();
    let iframe = http::fetch_iframe(client, iframe_url, referrer.as_deref()).await?;
    let navigation = timer.overall(iframe.url.as_str(), iframe.navigation.encoded_bytes);
    sink.artifact("iframe.html", iframe.html.as_bytes())?;
    let javascript = source::inline_javascript(&iframe.html)?;
    sink.artifact("iframe.js", javascript.as_bytes())?;
    sink.artifact("iframe-url.txt", iframe.url.as_str().as_bytes())?;
    sink.json("iframe-network.json", &iframe.navigation)?;
    sink.progress(&format!(
        "Fetched {} bytes of HTML; deobfuscating {} bytes of JavaScript",
        iframe.html.len(),
        javascript.len()
    ));
    let (text, cases) = deobfuscate(sink, javascript.clone()).await?;
    sink.artifact("iframe.deobfuscated.js", text.as_bytes())?;
    let source = Source::try_new(&text).context("parsing the deobfuscated iframe")?;
    Ok(Fetched {
        iframe,
        javascript,
        source,
        cases,
        navigation,
        referrer,
    })
}

/// Deobfuscates on a blocking thread, reporting partial transformations as progress.
pub(super) async fn deobfuscate(
    sink: &dyn Sink,
    javascript: String,
) -> Result<(String, CaseOpcodes)> {
    let (deobfuscated, cases) = deep_stack::run("deobfuscation", move || {
        call_stack::deobfuscate_with_cases(javascript)
    })
    .await??;
    if let Some(unconverged) = deobfuscated.unconverged {
        sink.progress(&format!("Warning: {unconverged}"));
    }
    Ok((deobfuscated.text, cases))
}

/// Merges collected page parameters into session options and recovers iframe state, returning
/// the program and the first payload, which it saves as `payload.json`. Collection waits for the
/// iframe's mode, which the page echoes in its summary.
pub(crate) fn merge(
    sink: &dyn Sink,
    fetched: &Fetched,
    page: &Page,
    embedding_page: &EmbeddingPage,
    prepared: PreparedSession<'_>,
) -> Result<(ExtractedProgram, Merged)> {
    // Recover merge and iframe state before modifying options. Both use the shared parse; state
    // recovery also reads bootstrap options.
    let mapping = prepared.mapping()?;
    let state = prepared.state()?;
    let program = prepared.into_program();
    if let Some(expected) = source::expected_build(&fetched.source)
        && expected != embedding_page.script.build
    {
        sink.progress(&format!(
            "Warning: this challenge expects api.js build {expected} but the page loaded {}; a browser would reload api.js before answering",
            embedding_page.script.build
        ));
    }
    let message = extra_params::collect(
        &embedding_page.page,
        &embedding_page.layout,
        &page.timeline,
        &embedding_page.script,
        source::mode(&program.request.options),
    );
    sink.json("extra-params.json", &message)?;
    let page_signals = message.signals.clone();
    let message = json!(message);
    let mut unset: Vec<String> = Vec::new();
    let built = FirstPayload::build(
        sink,
        program,
        state,
        &page.intervals,
        "options.json",
        |options| {
            let merged_at = performance_clock::epoch_ms();
            unset = mapping.merge(
                options,
                &message,
                &embedding_page.page.url.origin().ascii_serialization(),
                merged_at,
            );
            (mapping.merged(), merged_at)
        },
    )?;
    sink.progress(&format!(
        "Merged {} embedding page parameters into the session options; {} option(s) remain unset: {}",
        mapping.fields().len(),
        unset.len(),
        unset.join(", ")
    ));
    let navigation = &fetched.navigation;
    let resources = built.state.timing.as_ref().map_or_else(Vec::new, |timing| {
        vec![
            timing.navigation(
                &navigation.url,
                navigation.duration_ms,
                navigation.body_bytes,
                page.resource_timing.navigation,
            ),
            embedding_page.script.reduced(timing),
        ]
    });
    let mut first = built.plaintext;
    let options = &built.program.request.options;
    let elapsed = page.intervals.send;
    payload::append_send_time(&mut first, &built.state, options, &resources, elapsed);
    sink.progress(&format!(
        "Built a {}-field payload for this session",
        first.len()
    ));
    sink.json("payload.json", &first)?;
    let merged = Merged {
        first,
        state: built.state,
        window: built.window,
        globals: built.globals,
        selector_log: payload::selector_log(&built.program.payload_fields),
        resources,
        time_origin_ms: navigation.started_ms,
        page_signals,
    };
    Ok((built.program, merged))
}
