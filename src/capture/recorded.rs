//! Reads session data from `capture.json` and request traffic from `traffic.json`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use url::Url;

use super::traffic::{Request, Traffic};
use crate::js::Payload;
use crate::script::Source;
use crate::{challenge, deobfuscate};

/// Session data from `capture.json`: the iframe page, POSTs, and decoded payloads.
/// `scripts/cdp_capture.mjs` writes the same format without `cfChl`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapturedSession {
    iframe_html: String,
    posts: Vec<CapturedPost>,
    payloads: Vec<CapturedPayload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapturedPost {
    url: String,
    cf_chl: Option<String>,
    response_body: String,
}

#[derive(Deserialize)]
struct CapturedPayload {
    payload: Payload,
}

impl CapturedSession {
    /// The iframe document as received, including its stylesheets.
    #[must_use]
    pub fn iframe_html(&self) -> &str {
        &self.iframe_html
    }

    pub fn read(path: &Path) -> Result<Self> {
        read_json(path)
    }

    /// Returns the deobfuscated inline script from the iframe.
    pub fn source(&self) -> Result<Source> {
        Source::try_new(&deobfuscate::deobfuscate(self.javascript()?)?.text)
    }

    /// Like [`Self::source`], but reads the `iframe.deobfuscated.js` that `capture_session`
    /// writes beside `capture_path` when there is one.
    pub fn source_beside(&self, capture_path: &Path) -> Result<Source> {
        let deobfuscated = capture_path.with_file_name("iframe.deobfuscated.js");
        if deobfuscated.exists() {
            Source::try_new(&fs::read_to_string(deobfuscated)?)
        } else {
            self.source()
        }
    }

    /// Returns the probe program from the first POST response, unmasked using the ray ID in the
    /// URL.
    pub fn program(&self) -> Result<Vec<u8>> {
        self.programs()?
            .into_iter()
            .next()
            .context("the capture has no POST")
    }

    /// Returns the program each POST response carries, in order, such as the probe program and
    /// then the checkbox program.
    pub fn programs(&self) -> Result<Vec<Vec<u8>>> {
        self.posts
            .iter()
            .map(|post| {
                let url = Url::parse(&post.url)?;
                let ray = challenge::ray(&url)?;
                let encoded = challenge::decode_response(post.response_body.as_bytes(), ray)?;
                Ok(STANDARD.decode(encoded)?)
            })
            .collect()
    }

    /// Returns the iframe's inline script, before deobfuscation.
    pub fn javascript(&self) -> Result<String> {
        challenge::inline_javascript(&self.iframe_html)
    }

    /// Returns the payload built before probes run.
    pub fn first_payload(&self) -> Result<&Payload> {
        let first = self.payloads.first().map(|payload| &payload.payload);
        first.context("the capture has no first payload")
    }

    /// Returns the second payload, which contains a numbered record for each probe.
    pub fn probe_payload(&self) -> Result<&Payload> {
        let mut payloads = self.payloads.iter().map(|payload| &payload.payload);
        payloads
            .find(|payload| payload.contains_key("1"))
            .context("the capture has no payload with probe records")
    }

    /// Returns the last payload, such as the checkbox interaction's.
    #[must_use]
    pub fn last_payload(&self) -> Option<&Payload> {
        self.payloads.last().map(|payload| &payload.payload)
    }
}

/// Traffic and complete sessions from one proxy run directory.
pub struct Recording {
    pub(super) dir: PathBuf,
    pub(super) traffic: Traffic,
    pub(super) sessions: BTreeMap<String, CapturedSession>,
    /// Excluded sessions and the reasons they were skipped.
    pub(super) skipped: Vec<String>,
}

/// Capture completeness status read from `session.json`.
#[derive(Deserialize)]
struct SessionLog {
    complete: bool,
    notes: Vec<String>,
}

impl Recording {
    /// Reads the proxy output directory `dir`, skipping incomplete session captures.
    pub fn read(dir: &Path) -> Result<Self> {
        let traffic: Traffic = read_json(&dir.join("traffic.json"))?;
        let sessions_dir = dir.join("sessions");
        let mut names: Vec<String> = fs::read_dir(&sessions_dir)
            .with_context(|| format!("reading {}", sessions_dir.display()))?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_>>()?;
        names.sort();
        let mut sessions = BTreeMap::new();
        let mut skipped = Vec::new();
        for name in names {
            let session_dir = sessions_dir.join(&name);
            let log: SessionLog = read_json(&session_dir.join("session.json"))?;
            if !log.complete {
                skipped.push(format!(
                    "{name}: incomplete capture: {}",
                    log.notes.join("; ")
                ));
                continue;
            }
            let capture = CapturedSession::read(&session_dir.join("capture.json"))?;
            sessions.insert(name, capture);
        }
        Ok(Self {
            dir: dir.to_owned(),
            traffic,
            sessions,
            skipped,
        })
    }

    /// Groups POSTs by the `cf-chl` header shared by all POSTs in a session.
    pub(super) fn post_times(&self, session: &CapturedSession) -> Result<PostTimes> {
        let cf_chl = session
            .posts
            .first()
            .and_then(|post| post.cf_chl.as_deref())
            .context("the capture's first POST has no cf-chl header")?;
        let posted = |request: &&Request| {
            request.method == "POST" && request.header("cf-chl") == Some(cf_chl)
        };
        let mut posts = self.traffic.requests.iter().filter(posted);
        let first = posts.next().context("traffic.json lacks the first POST")?;
        let second = posts.next().context("traffic.json lacks the second POST")?;
        Ok(PostTimes {
            first_answered_ms: first
                .answered_ms
                .context("traffic.json records no response to the first POST")?,
            second_sent_ms: second.received_ms,
        })
    }
}

/// Returns the times when the browser received the first POST response and sent the second POST, in
/// milliseconds since the Unix epoch.
pub(super) struct PostTimes {
    pub(super) first_answered_ms: i64,
    pub(super) second_sent_ms: i64,
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let text = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&text).with_context(|| format!("reading {}", path.display()))
}
