//! Session entry points, and the widget session's shared protocol state.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use url::Url;
use wreq::cookie::Cookie;

use super::challenge_page::{self, OrchestratorSession};
use super::channel::{Channel, Origin, PostResult, Stage};
use super::initial::{self, EmbeddingPage, Fetched, Merged};
use super::timing::Timer;
use super::{Sink, interaction, probes};
use crate::browser::{Page, Solve};
use crate::challenge::orchestrator::ChallengePage;
use crate::challenge::program::{ExtractedProgram, PreparedSession, SessionEncoder};
use crate::challenge::source::InitialRequest;
use crate::embedding_page::extra_params;
use crate::embedding_page::page::Widget;
use crate::engine::Engine;
use crate::error::{Error, Refused};
use crate::http::{self, BrowserClient, PageDocument};
use crate::js::Options;
use crate::performance_clock::Resolution;
use crate::resource_timing::LoadTiming;
use crate::script::Source;
use crate::stage2::analysis::{self, Analysis, ProgramOutcome};
use crate::vm::Listing;

/// The result of a completed session.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// A widget completed on the site's page. Submit its token with the form.
    Token(String),
    /// The challenge page cleared.
    Cleared(Clearance),
}

/// A cleared challenge page. Requests that use its cookies need the browser's IP address and
/// user agent.
#[derive(Clone, Debug)]
pub struct Clearance {
    /// The `cf_clearance` cookie the browser was given.
    pub clearance: String,
    /// Every cookie the browser would send to the page, `cf_clearance` among them.
    pub cookies: Vec<Cookie<'static>>,
    /// The page the challenge protected.
    pub page: PageDocument,
}

/// What a solve expects its page to be.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Expect<'widget> {
    /// A page with a Turnstile widget. Uses the supplied widget or the page's first widget.
    Widget(Option<&'widget Widget>),
    ChallengePage,
    /// Accepts either page type. Clears a challenge page or solves the page's first widget.
    Either,
}

/// Fetches `iframe` and saves its encoder and payload field map without sending anything.
pub(crate) async fn prepare(client: &BrowserClient, sink: &dyn Sink, iframe: Url) -> Result<()> {
    // Opened on its own, the iframe has no page to name as its referrer.
    let fetched = initial::fetch(client, sink, iframe, None).await?;
    let program = PreparedSession::try_new(&fetched.source, &fetched.iframe.url)?.into_program();
    save_encoder(sink, &program)?;
    save_request(sink, &program.request, &fetched.iframe.url, None)?;
    sink.progress(
        "Prepared the session encoder and payload field map; no payload was built, so no POST was sent",
    );
    Ok(())
}

/// Navigates to `url` as if the user typed it, timing the navigation.
pub(crate) async fn navigate(
    client: &BrowserClient,
    url: &Url,
) -> Result<(PageDocument, LoadTiming)> {
    let timer = Timer::start();
    let document = http::navigate(client, url).await?;
    let navigation = timer.overall(document.url.as_str(), document.html.len() as u64);
    Ok((document, navigation))
}

/// Runs the named widget through completion, or uses the page's first widget if `expect` names
/// none. For challenge pages, also runs the orchestrator and submits the clearance form.
/// Rejects unexpected page types before sending.
pub(crate) async fn native(
    client: &BrowserClient,
    sink: &dyn Sink,
    document: PageDocument,
    navigation: LoadTiming,
    page: &Page,
    expect: Expect<'_>,
    solve: &Solve,
) -> Result<Outcome> {
    let landing = land(client, sink, document, navigation, page, expect).await?;
    let embedding_page = landing.embedding_page();
    let session = start_widget(client, sink, page, embedding_page).await?;
    let completion = session.solve(embedding_page, solve).await?;
    match landing {
        Landing::Site(_) => Ok(Outcome::Token(completion.token)),
        Landing::ChallengePage(orchestrator, _) => {
            let clearance = orchestrator.clear(&session, completion).await?;
            Ok(Outcome::Cleared(clearance))
        }
    }
}

/// Sends the first payload for the named widget, or the page's first widget if `expect` names
/// none. Returns without answering the response program. Rejects unexpected page types before
/// sending.
pub(crate) async fn send_first_payload(
    client: &BrowserClient,
    sink: &dyn Sink,
    document: PageDocument,
    navigation: LoadTiming,
    page: &Page,
    expect: Expect<'_>,
) -> Result<()> {
    let landing = land(client, sink, document, navigation, page, expect).await?;
    start_widget(client, sink, page, landing.embedding_page()).await?;
    Ok(())
}

/// The page a navigation reached, with the widget's embedding page rebuilt.
enum Landing {
    /// A site's page with a Turnstile widget.
    Site(EmbeddingPage),
    /// A challenge page, whose orchestrator has rendered its widget.
    ChallengePage(OrchestratorSession, EmbeddingPage),
}

impl Landing {
    fn embedding_page(&self) -> &EmbeddingPage {
        let (Self::Site(embedding_page) | Self::ChallengePage(_, embedding_page)) = self;
        embedding_page
    }
}

/// Checks the page against `expect` and rebuilds the embedding page of the widget it names. On
/// a challenge page, first runs the orchestrator through widget creation.
async fn land(
    client: &BrowserClient,
    sink: &dyn Sink,
    document: PageDocument,
    navigation: LoadTiming,
    page: &Page,
    expect: Expect<'_>,
) -> Result<Landing> {
    let status = document.status;
    let Some(challenge) = ChallengePage::parse(&document.html, &document.url)? else {
        if !status.is_success() {
            bail!(Error::Blocked { status });
        }
        let widget = match expect {
            Expect::Widget(widget) => widget,
            Expect::ChallengePage => bail!(Error::NotChallenged),
            Expect::Either => None,
        };
        let embedding_page = initial::render_page(client, sink, page, document, widget).await?;
        return Ok(Landing::Site(embedding_page));
    };
    if let Expect::Widget(_) = expect {
        bail!(Error::Challenged { status });
    }
    sink.progress(&format!(
        "{} answered HTTP {status} with a challenge page; running its orchestrator",
        document.url
    ));
    let (orchestrator, embedding_page) = challenge_page::begin(
        client,
        sink,
        page,
        navigation,
        challenge,
        document.referrer_policy,
    )
    .await?;
    Ok(Landing::ChallengePage(orchestrator, embedding_page))
}

/// Starts the session of the widget rendered by `embedding_page` by sending its first payload.
async fn start_widget<'caller>(
    client: &'caller BrowserClient,
    sink: &'caller dyn Sink,
    page: &Page,
    embedding_page: &EmbeddingPage,
) -> Result<WidgetSession<'caller>> {
    let iframe_url = extra_params::iframe_url(&embedding_page.page, &embedding_page.script)?;
    let referrer = embedding_page
        .referrer_policy
        .referrer(&embedding_page.page.url, &iframe_url);
    let fetched = initial::fetch(client, sink, iframe_url, referrer).await?;
    let prepared = PreparedSession::try_new(&fetched.source, &fetched.iframe.url)?;
    let (program, merged) = initial::merge(sink, &fetched, page, embedding_page, prepared)?;
    save_encoder(sink, &program)?;
    let encoder = program.session_encoder()?;
    let body = encoder.encode(&merged.first);
    save_request(sink, &program.request, &fetched.iframe.url, Some(&body))?;
    let channel = Channel {
        client,
        sink,
        origin: Origin::Iframe(&fetched.iframe),
        request: &program.request,
        encoder: &encoder,
    };
    let returned = channel.post(body, Stage::Initial).await?;
    let analysis = analyze_probes(sink, &fetched.source, &returned.program)?;
    Ok(WidgetSession {
        client,
        sink,
        fetched,
        request: program.request,
        encoder,
        embedding: embedding_page.embedding,
        merged,
        analysis,
        first_post: returned.fetch,
        arrived_ms: returned.received_ms,
    })
}

/// Analyzes the probes in the first response's `program`.
fn analyze_probes(sink: &dyn Sink, source: &Source, program: &[u8]) -> Result<Analysis> {
    let analysis =
        analysis::analyze(source, program).context("analyzing the first response's program")?;
    sink.json("stage2.json", &analysis.artifact())?;
    let probes = analysis.plan().probes();
    let implemented = probes
        .iter()
        .filter(|probe| probe.operation.is_some())
        .count();
    sink.progress(&format!(
        "Recovered {} ordered probes; {implemented} have native collection implementations",
        probes.len()
    ));
    for probe in probes {
        if probe.operation.is_none() {
            sink.progress(&format!("Probe {} matches no known collector", probe.index));
        }
    }
    Ok(analysis)
}

/// Saves the program's encoder and payload field map.
fn save_encoder(sink: &dyn Sink, program: &ExtractedProgram) -> Result<()> {
    let encoder_json = program.encoder_json();
    sink.json("encoder.json", &encoder_json)?;
    sink.json("payload-fields.json", &encoder_json.payload_fields)
}

/// Saves the first-payload request for `iframe_url`, including `body` once built.
fn save_request(
    sink: &dyn Sink,
    request: &InitialRequest,
    iframe_url: &Url,
    body: Option<&str>,
) -> Result<()> {
    let saved = RequestJson {
        url: request.url.as_str(),
        iframe_url: iframe_url.as_str(),
        headers: RequestHeaders {
            cf_chl: &request.cf_chl,
            cf_chl_ra: "0",
            content_type: "text/plain;charset=UTF-8",
        },
        options: &request.options,
        body,
    };
    sink.json("request.json", &saved)?;
    sink.progress("Saved fresh iframe and JavaScript");
    Ok(())
}

/// `request.json`: the first-payload request.
#[derive(Serialize)]
struct RequestJson<'request> {
    url: &'request str,
    iframe_url: &'request str,
    headers: RequestHeaders<'request>,
    options: &'request Options,
    /// Absent until the body is built.
    body: Option<&'request str>,
}

#[derive(Serialize)]
struct RequestHeaders<'request> {
    #[serde(rename = "cf-chl")]
    cf_chl: &'request str,
    #[serde(rename = "cf-chl-ra")]
    cf_chl_ra: &'static str,
    #[serde(rename = "content-type")]
    content_type: &'static str,
}

/// `completion.json`.
#[derive(Serialize)]
struct CompletionJson<'token> {
    token: &'token str,
}

/// The program that completed a widget, and the token it reported.
pub(crate) struct Completion {
    pub token: String,
    pub listing: Listing,
    /// When it arrived, in epoch milliseconds.
    pub received_ms: i64,
}

/// A widget session after the server answers its first payload. Later stages borrow this state.
pub(crate) struct WidgetSession<'caller> {
    pub client: &'caller BrowserClient,
    pub sink: &'caller dyn Sink,
    pub fetched: Fetched,
    /// POST destination and options reported by the first payload.
    pub request: InitialRequest,
    pub encoder: SessionEncoder,
    pub embedding: Embedding,
    pub merged: Merged,
    /// The first response's program analysis, which `stage2.json` saves.
    pub analysis: Analysis,
    pub first_post: LoadTiming,
    /// When the first response's program arrived, in epoch milliseconds.
    pub arrived_ms: i64,
}

/// Embedding context: a site page or Cloudflare challenge page. WebKit uses a finer clock on
/// challenge pages, and stored probe answers may differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Embedding {
    Site,
    ChallengePage,
}

impl WidgetSession<'_> {
    /// Clock behavior for the iframe and its workers.
    #[must_use]
    pub(crate) fn clock_resolution(&self) -> Resolution {
        match (self.client.engine(), self.embedding) {
            (Engine::Chromium, _) => Resolution::Chromium,
            (Engine::WebKit, Embedding::Site) => Resolution::WebKitMillisecond,
            (Engine::WebKit, Embedding::ChallengePage) => Resolution::WebKitFine,
        }
    }

    fn channel(&self) -> Channel<'_> {
        Channel {
            client: self.client,
            sink: self.sink,
            origin: Origin::Iframe(&self.fetched.iframe),
            request: &self.request,
            encoder: &self.encoder,
        }
    }

    /// The program's message to the embedding page, and its listing.
    fn outcome(&self, returned: &PostResult, stage: Stage) -> Result<(ProgramOutcome, Listing)> {
        let listing = self.fetched.source.disassemble(&returned.program)?;
        let outcome = ProgramOutcome::of(&listing);
        self.sink
            .progress(&format!("{}: {outcome}", stage.response()));
        Ok((outcome, listing))
    }

    fn complete(
        &self,
        token: String,
        listing: Listing,
        returned: &PostResult,
    ) -> Result<Completion> {
        self.sink
            .json("completion.json", &CompletionJson { token: &token })?;
        Ok(Completion {
            token,
            listing,
            received_ms: returned.received_ms,
        })
    }

    /// Answers probes and any requested checkbox program, through the completion token.
    async fn solve(&self, embedding_page: &EmbeddingPage, solve: &Solve) -> Result<Completion> {
        let mut submission = probes::prepare(self, solve).await?;
        let returned = self
            .channel()
            .submit(&submission.payload, Stage::Probes)
            .await?;
        // The checkbox program builds on the payload object as it stands after the send.
        let environment = self
            .merged
            .environment(&submission.options, &submission.window);
        let layout = &self.analysis.plan().payload;
        layout.after_send(&mut submission.payload.plaintext, environment)?;
        let (outcome, listing) = self.outcome(&returned, Stage::Probes)?;
        let checkbox_program = match outcome {
            ProgramOutcome::Complete { token } => return self.complete(token, listing, &returned),
            ProgramOutcome::Interaction => crate::stage2::interaction::recover(&listing)?,
            ProgramOutcome::Other(_) => bail!(Refused::new(
                Stage::Probes,
                "challenge did not complete after the second POST",
            )),
        };
        self.sink.json("interaction-plan.json", &checkbox_program)?;
        let viewport = solve
            .viewport
            .position_in_embedding_page(&embedding_page.layout, &submission.geometry);
        let result =
            interaction::collect(self, &checkbox_program, &submission, solve, &viewport).await?;
        let final_payload = interaction::payload(
            &checkbox_program,
            &self.merged,
            submission,
            result,
            &returned.fetch,
            &solve.profile.document,
        )?;
        let returned = self
            .channel()
            .submit(&final_payload, Stage::Interaction)
            .await?;
        match self.outcome(&returned, Stage::Interaction)? {
            (ProgramOutcome::Complete { token }, listing) => {
                self.complete(token, listing, &returned)
            }
            _ => bail!(Refused::new(
                Stage::Interaction,
                "challenge did not complete after the interaction POST",
            )),
        }
    }
}
