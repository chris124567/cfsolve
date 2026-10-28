//! Runs a challenge-page orchestrator, a separate session on the page's origin, around its
//! widget. Its first response renders the widget; its second payload reports the widget's
//! completion, and the response submits a clearance form that sets `cf_clearance`.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use url::Url;

use super::Sink;
use super::channel::{Channel, Origin, Stage, Submission};
use super::initial::{self, EmbeddingPage, FirstPayload};
use super::timing::Timer;
use super::widget::{Clearance, Completion, Embedding, WidgetSession};
use crate::browser::Page;
use crate::challenge::orchestrator::{self, ChallengePage};
use crate::challenge::payload;
use crate::challenge::program::{PreparedSession, SessionEncoder};
use crate::challenge::reduced_timing::{Entry, ResourceTiming};
use crate::challenge::source::InitialRequest;
use crate::challenge::state::{Intervals, ScriptState};
use crate::embedding_page::challenge_page::WIDGET_HOST;
use crate::embedding_page::extra_params::{self, ApiScript};
use crate::embedding_page::page::{Params, RenderedPage};
use crate::embedding_page::render_sample::RenderSample;
use crate::engine::{self, Engine, Lines};
use crate::error::Refused;
use crate::http::{self, BrowserClient, ReferrerPolicy, ScriptLoad};
use crate::js::{JsValue, Payload, Window};
use crate::resource_timing::{LoadTiming, Phases, ResourceMeasurement};
use crate::script::Source;
use crate::stage2::call_stack::{self, CaseOpcodes, ScriptPosition};
use crate::stage2::challenge_page::{self, Form, Settled, WidgetProgram};
use crate::stage2::payload::{Environment, State};
use crate::{embedding_page, performance_clock};

/// `clearance-form.json`: where the clearance form posts, and its fields in order.
#[derive(Serialize)]
struct ClearanceFormJson<'form> {
    action: &'form str,
    fields: &'form [(String, String)],
}

/// The orchestrator's session, between its first payload and its second.
pub(crate) struct OrchestratorSession {
    challenge: ChallengePage,
    /// The deobfuscated orchestrator, whose VM runs every returned program.
    source: Source,
    request: InitialRequest,
    encoder: SessionEncoder,
    state: ScriptState,
    /// The first payload, which the widget program receives.
    first: Payload,
    /// Window values read by the widget program.
    window: Window,
    widget: WidgetProgram,
    /// When the widget program created its record.
    record_started_ms: i64,
    callback_ms: i64,
    /// Page navigation and subsequent orchestrator, loader, and icon requests.
    navigation: LoadTiming,
    loads: Vec<LoadTiming>,
    post: LoadTiming,
    /// Fetch phase estimates used when only total duration is measured.
    phases: Phases,
}

/// Builds the orchestrator's first payload, with frame-check results and timestamps based on
/// build time, since no `extraParams` merge happens.
pub(crate) fn first_payload(
    sink: &dyn Sink,
    source: &Source,
    page: &Url,
    intervals: &Intervals,
) -> Result<FirstPayload> {
    let prepared = PreparedSession::try_new(source, page)?;
    let state = prepared.state()?;
    FirstPayload::build(
        sink,
        prepared.into_program(),
        state,
        intervals,
        "orchestrator-options.json",
        |options| {
            let framing = orchestrator::frame_options(source, options);
            options.extend(framing);
            (None, performance_clock::epoch_ms())
        },
    )
}

/// Rebuilds the stack sampled by the loader during the orchestrator's `turnstile.render` call.
/// Includes loader frames and session-script frames from the VM call to the listener running
/// the widget program's `onload` callback.
///
/// In Chrome captures, the program calls the callback inside its own exception handler. In iOS
/// Safari captures, the loader finishes later and its timer calls the callback without a
/// registered handler.
pub(super) fn render_sample(
    api: &ApiScript,
    challenge: &ChallengePage,
    javascript: &str,
    cases: &CaseOpcodes,
    widget: &WidgetProgram,
    engine: Engine,
) -> Result<RenderSample> {
    // The session script puts the page's inline script before the orchestrator.
    let (inline_lines, _) = engine::line_and_column(&challenge.javascript(""), Lines::Script);
    let guarded = engine == Engine::Chromium;
    let geometry = call_stack::recover_method_call(javascript, cases, widget.render_call, guarded)?
        .rebased(inline_lines);
    let origin = ScriptPosition {
        url: challenge.orchestrator.to_string(),
        line: 0,
        column: 0,
    };
    let frames = geometry.placed(&origin, engine);
    RenderSample::explicit(&api.source, api.stack_url(engine), frames, engine)
}

/// Runs the orchestrator through widget creation and reconstructs the page around the widget.
pub(crate) async fn begin(
    client: &BrowserClient,
    sink: &dyn Sink,
    page: &Page,
    navigation: LoadTiming,
    challenge: ChallengePage,
    referrer_policy: ReferrerPolicy,
) -> Result<(OrchestratorSession, EmbeddingPage)> {
    sink.artifact("page.html", challenge.html.as_bytes())?;
    let pacing = &page.orchestrator_pacing;
    let timer = Timer::start();
    let script =
        http::fetch_orchestrator(client, &challenge.orchestrator, &challenge.loading).await?;
    let script_fetch = timer.overall(challenge.orchestrator.as_str(), script.len() as u64);
    sink.artifact("orchestrator.js", script.as_bytes())?;
    // The orchestrator's header shows the site's icon as it starts. Deobfuscation runs on its
    // own thread meanwhile.
    let icon_url = challenge.url.join("/favicon.ico")?;
    let icon = async {
        let timer = Timer::start();
        let icon = http::fetch_page_image(client, &challenge.url, &icon_url).await?;
        anyhow::Ok(timer.overall(icon_url.as_str(), icon.encoded_bytes))
    };
    let javascript = challenge.javascript(&script);
    sink.progress(&format!(
        "Fetched the {}-byte orchestrator; deobfuscating it with the page's options",
        script.len()
    ));
    let ((text, cases), icon) =
        tokio::try_join!(initial::deobfuscate(sink, javascript.clone()), icon)?;
    sink.artifact("orchestrator.deobfuscated.js", text.as_bytes())?;
    let source = Source::try_new(&text).context("parsing the deobfuscated orchestrator")?;

    let intervals = &pacing.intervals;
    let mut first = first_payload(sink, &source, &challenge.url, intervals)?;
    let options = &first.program.request.options;
    let send_at = first.marked_ms + intervals.handoff + 1 + intervals.send;
    payload::append_send_time_at(&mut first.plaintext, &first.state, options, send_at);
    let submission = Submission {
        plaintext: first.plaintext,
        send_at,
    };
    let encoder = first.program.session_encoder()?;
    let channel = Channel {
        client,
        sink,
        origin: Origin::Page(&challenge.url),
        request: &first.program.request,
        encoder: &encoder,
    };
    let returned = channel.submit(&submission, Stage::Orchestrator).await?;
    let listing = source.disassemble(&returned.program)?;
    let widget = WidgetProgram::recover(&listing).context("reading the widget program")?;
    let record_started_ms = returned.received_ms + i64::from(pacing.program_startup_ms);

    // The widget template reads initial-program globals, values read by the first payload, then
    // globals set by the widget program.
    let mut window = first.window;
    window.extend(first.globals);
    window.extend(widget.window.clone());
    let parameters = widget.render_parameters(options, &window)?;
    sink.json("widget-parameters.json", &parameters)?;
    let loader = orchestrator::loader_url(&source, options)?;
    // Use the server-selected language from the message table as the document's `lang`.
    let language = orchestrator::language(options)
        .context("the orchestrator's message table names no one language")?;
    let ray = first.program.request.ray()?;
    let rendered = embedding_page::challenge_page::render(&challenge, &loader, language, ray)?;
    sink.artifact("rendered-page.html", rendered.as_bytes())?;
    let rendered = RenderedPage::render_explicit(
        &rendered,
        challenge.url.clone(),
        &extra_params::widget_id(),
        WIDGET_HOST,
        Params::from_render(&parameters)?,
    )?;
    let (mut api, api_fetch) = initial::fetch_loader(
        client,
        loader,
        ScriptLoad::Anonymous,
        &challenge.url,
        referrer_policy,
        page,
    )
    .await?;
    match render_sample(
        &api,
        &challenge,
        &javascript,
        &cases,
        &widget,
        client.engine(),
    ) {
        Ok(sample) => api.render_sample = sample,
        Err(error) => sink.progress(&format!(
            "Warning: the orchestrator's render call has no recovered stack, so the loader \
             reports a markup render: {error:#}"
        )),
    }
    let embedding_page = EmbeddingPage::new(
        sink,
        rendered,
        api,
        page.layout.on_challenge_page(),
        referrer_policy,
        Embedding::ChallengePage,
    );
    let orchestrator = OrchestratorSession {
        challenge,
        source,
        request: first.program.request,
        encoder,
        state: first.state,
        first: submission.plaintext,
        window,
        widget,
        record_started_ms,
        callback_ms: pacing.callback_ms.into(),
        navigation,
        loads: vec![script_fetch, api_fetch, icon],
        post: returned.fetch,
        phases: page.resource_timing.phases,
    };
    Ok((orchestrator, embedding_page))
}

impl OrchestratorSession {
    /// Reports the completion of `widget`'s session and submits the returned clearance form for
    /// the protected page, through the same client.
    pub(crate) async fn clear(
        &self,
        widget: &WidgetSession<'_>,
        completion: Completion,
    ) -> Result<Clearance> {
        let (client, sink) = (widget.client, widget.sink);
        let settled = Settled {
            after_challenge: challenge_page::completion_extra(&completion.listing),
            token: completion.token,
            started_ms: self.record_started_ms,
            ended_ms: completion.received_ms + self.callback_ms,
        };
        let mut options = self.request.options.clone();
        if let Some(timing) = &widget.merged.state.timing {
            let entries = page_resource_timing(
                timing,
                self.phases,
                &self.navigation,
                &self.loads,
                &self.post,
                &widget.fetched.navigation,
            );
            options.insert(timing.option.clone(), JsValue::Array(entries));
        }
        let calls = Window::new();
        let state = State {
            environment: Environment {
                options: &options,
                window: &self.window,
                calls: &calls,
            },
            input: &self.first,
        };
        let mut plaintext = self.widget.payload(&state, &settled)?;
        let send_at = settled.ended_ms + 1;
        payload::append_send_time_at(&mut plaintext, &self.state, &options, send_at);
        let channel = Channel {
            client,
            sink,
            origin: Origin::Page(&self.challenge.url),
            request: &self.request,
            encoder: &self.encoder,
        };
        let submission = Submission { plaintext, send_at };
        let returned = channel.submit(&submission, Stage::Clearance).await?;
        let listing = self.source.disassemble(&returned.program)?;
        let form = Form::recover(&listing).context("reading the clearance program")?;
        let form = form.resolve(&options, &self.window, &self.challenge.url)?;
        let saved = ClearanceFormJson {
            action: form.action.as_str(),
            fields: &form.fields,
        };
        sink.json("clearance-form.json", &saved)?;
        // The form submission uses the restored page address as its referrer.
        let referer = self
            .challenge
            .answered
            .as_ref()
            .unwrap_or(&self.challenge.url);
        let cleared = http::submit_form(client, referer, &form.action, &form.fields).await?;
        sink.artifact("cleared.html", cleared.html.as_bytes())?;
        if !cleared.status.is_success()
            || ChallengePage::parse(&cleared.html, &cleared.url)?.is_some()
        {
            let message = format!(
                "the clearance form returned HTTP {} without the page",
                cleared.status
            );
            bail!(Refused::new(Stage::Clearance, message));
        }
        sink.progress(&format!(
            "Cleared the challenge: {} answered HTTP {} with the page ({} bytes)",
            cleared.url,
            cleared.status,
            cleared.html.len()
        ));
        let cookies = client.cookies(&cleared.url);
        let clearance = cookies
            .iter()
            .find(|cookie| cookie.name() == "cf_clearance")
            .context("the clearance form set no `cf_clearance` cookie")?
            .value()
            .to_owned();
        Ok(Clearance {
            clearance,
            cookies,
            page: cleared,
        })
    }
}

/// Builds two resource timing snapshots for the widget program. The first includes the
/// unfinished navigation and later loads. The second includes the finished navigation, first
/// POST, a second icon entry, and the widget iframe. Estimates unmeasured phases. Only the end
/// time is exposed for the cross-origin iframe.
#[must_use]
pub(crate) fn page_resource_timing(
    timing: &ResourceTiming,
    phases: Phases,
    navigation: &LoadTiming,
    loads: &[LoadTiming],
    post: &LoadTiming,
    iframe: &LoadTiming,
) -> Vec<JsValue> {
    // Times run from the challenge page's navigation.
    let since = |load: &LoadTiming| (load.started_ms - navigation.started_ms) as f64;
    let reduce = |load: &LoadTiming, measured: ResourceMeasurement| {
        timing.reduce(&Entry {
            name: &load.url,
            start: since(load),
            measured,
        })
    };
    let estimate = |fetch: &LoadTiming| {
        reduce(
            fetch,
            ResourceMeasurement::estimated(fetch.duration_ms, fetch.body_bytes, phases),
        )
    };
    let loading = ResourceMeasurement {
        duration: 0.0,
        ..ResourceMeasurement::estimated(navigation.duration_ms, navigation.body_bytes, phases)
    };
    let loaded_ms = loads
        .iter()
        .map(LoadTiming::ended_ms)
        .fold(navigation.ended_ms(), f64::max);
    let loaded = ResourceMeasurement {
        duration: loaded_ms - navigation.started_ms as f64,
        ..loading
    };
    let iframe_end = since(iframe) + iframe.duration_ms;
    let mut entries = vec![reduce(navigation, loading)];
    entries.extend(loads.iter().map(estimate));
    entries.push(reduce(navigation, loaded));
    entries.push(timing.entry(post, navigation.started_ms));
    entries.extend(loads.last().map(estimate));
    entries.push(reduce(
        iframe,
        ResourceMeasurement::restricted(iframe.duration_ms, iframe_end),
    ));
    entries
}
