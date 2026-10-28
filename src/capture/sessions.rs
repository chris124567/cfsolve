//! Tracks iframe sessions and writes their captures.
//!
//! Each rewritten iframe GET opens a session with the real modulus and an alphabet read by a
//! fast scan. Background extraction checks that alphabet and recovers the key-transform secret
//! from the original HTML. Challenge POSTs use the session bound to their ray, or bind to the
//! latest unbound session. Shutdown waits for extraction, decrypts payloads, and writes logs.
//!
//! Each session directory holds the original and rewritten HTML, the full log `session.json`,
//! and `capture.json`, which `cargo run --example build_profile` turns into `answers.json`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use num_bigint::BigUint;
use serde::{Serialize, Serializer};
use serde_json::Value;
use swc_core::ecma::ast::Script;
use tokio::task::JoinSet;
use url::Url;

use super::rsa::{ProxyKey, Rewrapped};
use crate::challenge::codec::{Codec, KEY_LENGTH};
use crate::challenge::program::{self, PreparedSession};
use crate::deobfuscate::Encoded;
use crate::js::ast;
use crate::script::Source;
use crate::{challenge, deep_stack};

/// An iframe GET whose response was rewritten, starting a new session.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Iframe {
    #[serde(rename = "iframeUrl")]
    pub(super) url: String,
    #[serde(serialize_with = "lower_hex")]
    pub(super) real_modulus: BigUint,
    /// Alphabet from the fast scan, used until full extraction finishes.
    #[serde(skip)]
    pub(super) scanned_alphabet: String,
    #[serde(skip)]
    pub(super) original: String,
    #[serde(skip)]
    pub(super) rewritten: String,
    // Body sizes before and after rewriting, as observed by the browser.
    pub(super) upstream_encoded_bytes: u64,
    pub(super) upstream_decoded_bytes: u64,
    pub(super) observed_encoded_bytes: u64,
    pub(super) observed_decoded_bytes: u64,
}

/// A challenge POST, its decrypted values, and its response.
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Post {
    pub(super) url: String,
    pub(super) cf_chl: String,
    /// The unwrapped seed, in hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) seed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) padding: Option<u8>,
    /// The body as the browser encrypted it, under the proxy modulus.
    pub(super) encrypted_body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
    pub(super) response_body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) decoded_program: Option<String>,
    /// The frame plaintext, read once the session's secret is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) payload: Option<Value>,
}

/// `capture.json`: the iframe page and its POSTs, with the payloads that could be read.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureJson<'session> {
    iframe_html: &'session str,
    posts: Vec<CapturedPost<'session>>,
    payloads: Vec<CapturedPayload<'session>>,
}

/// A POST in `capture.json`. Unlike `session.json`, absent values are written as `null`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CapturedPost<'session> {
    url: &'session str,
    cf_chl: &'session str,
    seed: Option<&'session str>,
    padding: Option<u8>,
    error: Option<&'session str>,
    response_body: &'session str,
}

#[derive(Serialize)]
struct CapturedPayload<'session> {
    url: &'session str,
    payload: &'session Value,
}

/// One iframe session, serialized as its `session.json`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Session {
    #[serde(flatten)]
    iframe: Iframe,
    #[serde(serialize_with = "lower_hex")]
    proxy_modulus: BigUint,
    /// Alphabet and key-transform secret recovered by full extraction.
    alphabet: Option<String>,
    #[serde(serialize_with = "as_text")]
    secret: Option<[u8; KEY_LENGTH]>,
    /// Whether capture succeeded. Only complete sessions can become stored answers.
    complete: bool,
    /// The reason capture is incomplete.
    notes: Vec<String>,
    posts: Vec<Post>,
    /// The ray bound to this session's POSTs.
    #[serde(skip)]
    ray: Option<String>,
}

/// The proxy's sessions, indexed in the order they opened.
pub(super) struct Sessions {
    pub(super) proxy_key: ProxyKey,
    sessions: Mutex<Vec<Session>>,
    /// The background extractions, awaited before the logs are written.
    extractions: Mutex<JoinSet<()>>,
}

impl Sessions {
    #[must_use]
    pub(super) fn new(proxy_key: ProxyKey) -> Self {
        Self {
            proxy_key,
            sessions: Mutex::default(),
            extractions: Mutex::default(),
        }
    }

    pub(super) fn lock(&self) -> MutexGuard<'_, Vec<Session>> {
        self.sessions.lock().expect("the session table lock")
    }

    /// Opens a session for `iframe` and starts background parameter extraction.
    pub(super) fn open(self: &Arc<Self>, iframe: Iframe) -> usize {
        let original = iframe.original.clone();
        let index = {
            let mut sessions = self.lock();
            sessions.push(Session {
                iframe,
                proxy_modulus: self.proxy_key.modulus.clone(),
                alphabet: None,
                secret: None,
                complete: true,
                notes: Vec::new(),
                posts: Vec::new(),
                ray: None,
            });
            sessions.len() - 1
        };
        let sessions = Arc::clone(self);
        let mut extractions = self.extractions.lock().expect("the extraction set lock");
        extractions.spawn(async move {
            let codec = deep_stack::run("extraction", move || extract_codec(&original))
                .await
                .flatten();
            sessions.lock()[index].set_codec(codec);
        });
        index
    }

    /// Waits for all current extractions so subsequent logs include their secrets.
    pub(super) async fn finish_extractions(&self) {
        let mut extractions =
            std::mem::take(&mut *self.extractions.lock().expect("the extraction set lock"));
        while extractions.join_next().await.is_some() {}
    }

    /// Finds the session for a POST to `url`. Binds a new ray to the latest unbound session.
    /// Returns `None` when no session is available.
    #[must_use]
    pub(super) fn bind(&self, url: &Url) -> Option<usize> {
        let ray = challenge::ray(url).ok()?;
        let mut sessions = self.lock();
        let bound = |session: &Session| session.ray.as_deref() == Some(ray);
        if let Some(index) = sessions.iter().position(bound) {
            return Some(index);
        }
        let index = sessions.iter().rposition(|session| session.ray.is_none())?;
        sessions[index].ray = Some(ray.to_owned());
        Some(index)
    }

    /// Re-encrypts session `index`'s POST seed with the real modulus.
    pub(super) fn rewrap(&self, index: usize, body: &str) -> Result<Rewrapped> {
        let sessions = self.lock();
        let Session {
            iframe, alphabet, ..
        } = &sessions[index];
        let alphabet = alphabet.as_ref().unwrap_or(&iframe.scanned_alphabet);
        self.proxy_key.rewrap(body, alphabet, &iframe.real_modulus)
    }

    /// Decrypts each session's payloads and writes its log under `out_dir`.
    pub(super) fn write_all(&self, out_dir: &Path) {
        for (index, session) in self.lock().iter_mut().enumerate() {
            session.read_payloads(&self.proxy_key);
            let dir = out_dir.join(format!("sessions/session-{index:04}"));
            match session.write(&dir) {
                Ok(path) => eprintln!(
                    "session {index}: {} (complete: {})",
                    path.display(),
                    session.complete
                ),
                Err(error) => eprintln!("session {index}: writing the log failed: {error:#}"),
            }
        }
    }
}

impl Session {
    /// Marks capture as incomplete and records the reason.
    pub(super) fn poison(&mut self, note: &str) {
        self.complete = false;
        self.notes.push(note.to_owned());
    }

    /// Records a POST and marks its session incomplete if the POST has an error.
    pub(super) fn record(&mut self, post: Post) {
        if let Some(error) = &post.error {
            self.poison(&format!("POST {}: {error}", post.url));
        }
        self.posts.push(post);
    }

    /// Accepts extracted parameters after checking them against the replaced modulus and
    /// scanned alphabet.
    fn set_codec(&mut self, codec: Result<Codec>) {
        let codec = match codec {
            Ok(codec) => codec,
            Err(error) => {
                self.poison(&format!("extracting the session params: {error:#}"));
                return;
            }
        };
        if codec.modulus != self.iframe.real_modulus {
            self.poison("the pipeline modulus differs from the swapped one");
            return;
        }
        if codec.alphabet_text != self.iframe.scanned_alphabet {
            self.poison("the pipeline alphabet differs from the scanned one");
        }
        self.alphabet = Some(codec.alphabet_text);
        self.secret = Some(codec.secret);
    }

    /// Decrypts POST payloads after extraction supplies the secret. Marks capture incomplete if
    /// decryption fails.
    fn read_payloads(&mut self, proxy_key: &ProxyKey) {
        let (Some(alphabet), Some(secret)) = (&self.alphabet, &self.secret) else {
            if !self.posts.is_empty() {
                self.poison("the pipeline never supplied the secret to read payloads with");
            }
            return;
        };
        for post in &mut self.posts {
            match proxy_key.read_payload(&post.encrypted_body, alphabet, secret) {
                Ok(payload) => post.payload = Some(payload),
                Err(error) => {
                    let error = format!("{error:#}");
                    self.complete = false;
                    self.notes.push(format!("POST {}: {error}", post.url));
                    // Keep the first error so a decryption failure cannot hide the rewrapping
                    // failure that rejected the POST.
                    post.error.get_or_insert(error);
                }
            }
        }
    }

    /// Writes the session files to `dir` and returns the path to `capture.json`.
    fn write(&self, dir: &Path) -> Result<PathBuf> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        write_file(&dir.join("original.html"), &self.iframe.original)?;
        write_file(&dir.join("rewritten.html"), &self.iframe.rewritten)?;
        let log = serde_json::to_string_pretty(self)?;
        write_file(&dir.join("session.json"), log)?;
        let mut capture = CaptureJson {
            iframe_html: &self.iframe.original,
            posts: Vec::new(),
            payloads: Vec::new(),
        };
        for post in &self.posts {
            capture.posts.push(CapturedPost {
                url: &post.url,
                cf_chl: &post.cf_chl,
                seed: post.seed.as_deref(),
                padding: post.padding,
                error: post.error.as_deref(),
                response_body: &post.response_body,
            });
            if let Some(payload) = &post.payload {
                capture.payloads.push(CapturedPayload {
                    url: &post.url,
                    payload,
                });
            }
        }
        let path = dir.join("capture.json");
        write_file(&path, serde_json::to_string_pretty(&capture)?)?;
        Ok(path)
    }
}

/// Writes `contents` to `path`, naming the path in any error.
pub(super) fn write_file(path: &Path, contents: impl AsRef<[u8]>) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

fn lower_hex<S: Serializer>(number: &BigUint, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{number:x}"))
}

/// Serializes secret bytes as script characters. The `&Option` parameter is required by Serde's
/// `serialize_with` callback.
fn as_text<S: Serializer>(
    secret: &Option<[u8; KEY_LENGTH]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let text: Option<String> = secret.map(|secret| secret.map(char::from).iter().collect());
    text.serialize(serializer)
}

/// Runs the solver's extraction on the original iframe HTML.
fn extract_codec(original: &str) -> Result<Codec> {
    let javascript = challenge::inline_javascript(original)?;
    let deobfuscated = crate::deobfuscate::deobfuscate(javascript)?;
    let source = Source::try_new(&deobfuscated.text)?;
    // Extraction checks that POSTs share the iframe's origin. Any challenge host works for this
    // check.
    let base = Url::parse("https://challenges.cloudflare.com/")?;
    let session = PreparedSession::try_new(&source, &base)?;
    Ok(session.into_program().codec)
}

/// Searches literals and inline decoded `strings` for a custom base64 alphabet using the solver's
/// alphabet rule. Searches the entire raw script, including outside the immediately invoked
/// function. Background extraction validates the result before saving session answers.
pub(super) fn scan_alphabet(script: &Script, strings: &[Encoded]) -> Result<String> {
    let mut candidates = ast::string_literals(script);
    candidates.extend(strings.iter().map(|string| string.decoded.clone()));
    program::base64_alphabet(candidates)
}
