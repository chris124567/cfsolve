//! Sends session POSTs through a shared client and encoder to one challenge URL, and saves
//! responses.

use anyhow::{Context, Result, bail};
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use url::Url;

use super::Sink;
use super::timing::{self, Timer};
use crate::challenge::codec;
use crate::challenge::program::SessionEncoder;
use crate::challenge::source::InitialRequest;
use crate::error::Refused;
use crate::http::{self, BrowserClient, Iframe};
use crate::js::Payload;
use crate::performance_clock;
use crate::resource_timing::LoadTiming;

/// A response's status and headers, saved before its body is read.
#[derive(Serialize)]
struct ResponseJson<'response> {
    status: u16,
    headers: Vec<HeaderJson<'response>>,
}

#[derive(Serialize)]
struct HeaderJson<'response> {
    name: &'response str,
    value: String,
}

/// A payload and its scheduled send time.
pub(crate) struct Submission {
    pub plaintext: Payload,
    /// When to send it, in epoch milliseconds.
    pub send_at: i64,
}

/// The session POST associated with a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stage {
    /// The first payload assembled from page parameters and iframe state.
    Initial,
    /// The returned program's probe records.
    Probes,
    /// The checkbox program's record.
    Interaction,
    /// The orchestrator's first payload, whose response renders a widget.
    Orchestrator,
    /// The orchestrator's widget-completion report, whose response submits the clearance form.
    Clearance,
}

impl Stage {
    /// Artifact filename prefix, such as `second-` in `second-payload.json`.
    #[must_use]
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            Self::Initial => "",
            Self::Probes => "second-",
            Self::Interaction => "third-",
            Self::Orchestrator => "orchestrator-",
            Self::Clearance => "orchestrator-second-",
        }
    }

    /// Response label used in progress messages and errors.
    #[must_use]
    pub(crate) fn response(self) -> &'static str {
        match self {
            Self::Initial => "First response",
            Self::Probes => "Second response",
            Self::Interaction => "Third response",
            Self::Orchestrator => "Orchestrator's first response",
            Self::Clearance => "Orchestrator's second response",
        }
    }
}

/// Returned program and request metadata for a challenge POST.
pub(crate) struct PostResult {
    /// The returned VM program's bytecode.
    pub program: Vec<u8>,
    /// When the response had been read and unmasked, in epoch milliseconds.
    pub received_ms: i64,
    pub fetch: LoadTiming,
}

/// Document origin used in POST headers.
pub(super) enum Origin<'document> {
    Iframe(&'document Iframe),
    /// A challenge page, whose orchestrator posts on the page's own origin.
    Page(&'document Url),
}

pub(super) struct Channel<'session> {
    pub(super) client: &'session BrowserClient,
    pub(super) sink: &'session dyn Sink,
    pub(super) origin: Origin<'session>,
    pub(super) request: &'session InitialRequest,
    pub(super) encoder: &'session SessionEncoder,
}

impl Channel<'_> {
    /// Saves the payload, waits until its scheduled time, and sends it.
    pub(super) async fn submit(&self, submission: &Submission, stage: Stage) -> Result<PostResult> {
        let name = format!("{}payload.json", stage.prefix());
        self.sink.json(&name, &submission.plaintext)?;
        let body = self.encoder.encode(&submission.plaintext);
        timing::sleep_until(submission.send_at).await;
        self.post(body, stage).await
    }

    /// Posts encoded `body` and decodes the returned program. Saves each part of the response
    /// before checking it, so failures leave diagnostics.
    pub(super) async fn post(&self, body: String, stage: Stage) -> Result<PostResult> {
        use base64::Engine as _;

        let (client, sink, request) = (self.client, self.sink, self.request);
        let (url, cf_chl) = (&request.url, &request.cf_chl);
        let name = format!("{}response", stage.prefix());
        let timer = Timer::start();
        let response = match self.origin {
            Origin::Iframe(iframe) => {
                http::post_challenge(client, iframe, url, cf_chl, body).await?
            }
            Origin::Page(page) => http::post_orchestrator(client, page, url, cf_chl, body).await?,
        };
        let waiting_ms = timer.elapsed_ms();
        let status = response.status();
        let headers = http::text_headers(response.headers());
        let saved = ResponseJson {
            status: status.as_u16(),
            headers: headers
                .map(|(name, value)| HeaderJson { name, value })
                .collect(),
        };
        sink.json(&format!("{name}.json"), &saved)?;
        let (body, network) = http::read_encoded(response)
            .await
            .context("reading challenge POST response")?;
        sink.json(&format!("{name}-network.json"), &network)?;
        let fetch = timer.phased(url.as_str(), waiting_ms, network.encoded_bytes);
        sink.artifact(&format!("{name}.bin"), &body)?;
        sink.progress(&format!(
            "POST returned HTTP {status}; saved {} bytes",
            body.len()
        ));
        if !status.is_success() {
            bail!(Refused::new(
                stage,
                format!("POST returned HTTP {status}; response saved")
            ));
        }
        let text = codec::decode_response(&body, request.ray()?)?;
        sink.artifact(&format!("{name}.decoded.txt"), &text)?;
        let received_ms = performance_clock::epoch_ms();
        let program = STANDARD.decode(text).with_context(|| {
            format!(
                "decoding the VM program in the {}",
                stage.response().to_lowercase()
            )
        })?;
        Ok(PostResult {
            program,
            received_ms,
            fetch,
        })
    }
}
