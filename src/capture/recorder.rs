//! Records challenge sessions from a browser whose traffic is intercepted, by the capture proxy
//! or by the browser itself (the DevTools protocol's `Fetch` domain, say).
//!
//! The interceptor hands the recorder each request the browser sends and the challenge traffic
//! it receives. The recorder swaps its own RSA modulus into each challenge iframe
//! ([`Recorder::rewrite_iframe`]), so it can read the payloads the browser encrypts, and rewraps
//! each challenge POST's seed under the real modulus before it goes to Cloudflare
//! ([`Recorder::challenge_post`]). [`Recorder::finish`] decrypts the payloads and returns the
//! [`Recording`], which [`super::fill_profile`] and [`crate::Answers::capture`] turn into a
//! profile.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Result;
use url::Url;

use super::recorded::Recording;
use super::rsa::{self, ProxyKey};
use super::sessions::{self, Iframe, Post, Sessions};
use super::traffic::{SentHeaders, Traffic};
use crate::challenge;
use crate::deobfuscate;
use crate::js::ast;

/// The host serving Turnstile iframes and receiving their challenge POSTs.
pub const CHALLENGE_HOST: &str = "challenges.cloudflare.com";

/// The sessions and requests of one capture.
pub struct Recorder {
    pub(super) sessions: Arc<Sessions>,
    traffic: Mutex<Traffic>,
    /// The host whose challenge POSTs need rewrapping: [`CHALLENGE_HOST`] or a test's loopback
    /// origin.
    challenge_host: String,
}

/// An iframe document whose modulus was swapped.
pub struct RewrittenIframe {
    /// The document to hand the browser instead of the original, as decoded text. Every byte
    /// offset matches the original's.
    pub html: String,
    /// The session the document opened, numbered in the order sessions open.
    pub(super) session: usize,
}

/// What to do with a challenge POST.
pub enum Posted {
    /// Send [`ChallengePost::body`] in place of the browser's body, then record the response with
    /// [`Recorder::answered_post`] (or the failure with [`Recorder::failed_post`]).
    Rewrapped(Box<ChallengePost>),
    /// No session is open for it: send it unchanged. It belongs to an iframe the recorder did not
    /// rewrite.
    Unbound,
    /// It does not open under the recorder's key, so Cloudflare would refuse it: answer the
    /// browser with an error instead. Its session is excluded from the recording.
    Rejected(String),
}

/// A challenge POST rewrapped for Cloudflare.
pub struct ChallengePost {
    /// The body to send in place of the browser's.
    pub body: String,
    session: usize,
    url: Url,
    post: Post,
}

impl Recorder {
    /// A recorder with a fresh RSA key.
    pub fn new() -> Result<Self> {
        Self::for_host(CHALLENGE_HOST)
    }

    pub(super) fn for_host(challenge_host: &str) -> Result<Self> {
        Ok(Self {
            sessions: Arc::new(Sessions::new(ProxyKey::generate()?)),
            traffic: Mutex::default(),
            challenge_host: challenge_host.to_owned(),
        })
    }

    pub(super) fn traffic(&self) -> MutexGuard<'_, Traffic> {
        self.traffic.lock().expect("the traffic log lock")
    }

    /// Logs a request the browser sent now, on the proxy's `connection` if it has one. Returns
    /// the index [`Self::answered`] takes. The challenge POSTs' times fill the profile's startup
    /// and pending delays; headers in the order sent fill its header orders and identity.
    pub fn request(
        &self,
        connection: Option<usize>,
        method: &str,
        url: &str,
        version: &str,
        headers: SentHeaders,
    ) -> usize {
        self.traffic()
            .request(connection, method, url, version, headers)
    }

    /// Logs that the response to request `index` reached the browser now.
    pub fn answered(&self, index: usize) {
        self.traffic().answered(index);
    }

    /// Swaps the recorder's modulus into an HTML document from the challenge host, opening its
    /// session. Fails, saying why, for a document that isn't a challenge iframe; the browser should
    /// get that document unchanged.
    pub fn rewrite_iframe(&self, url: &str, html: &str) -> Result<RewrittenIframe> {
        let javascript = challenge::inline_javascript(html)?;
        let parsed = ast::parse_javascript("iframe.js", &javascript)?;
        let strings = deobfuscate::inline_strings(&parsed.script);
        let alphabet = sessions::scan_alphabet(&parsed.script, &strings)?;
        let (rewritten, real_modulus) =
            rsa::swap_modulus(html, &strings, &self.sessions.proxy_key.modulus)?;
        let session = self.sessions.open(Iframe {
            url: url.to_owned(),
            real_modulus,
            scanned_alphabet: alphabet,
            original: html.to_owned(),
            rewritten: rewritten.clone(),
            upstream_encoded_bytes: None,
            upstream_decoded_bytes: html.len() as u64,
            observed_encoded_bytes: None,
            // Replacement preserves every decoded byte offset.
            observed_decoded_bytes: html.len() as u64,
        });
        Ok(RewrittenIframe {
            html: rewritten,
            session,
        })
    }

    /// Notes the iframe's encoded size from upstream and as re-encoded for the browser.
    pub(super) fn note_encoding(&self, iframe: &RewrittenIframe, upstream: u64, observed: u64) {
        self.sessions.lock()[iframe.session].note_encoding(upstream, observed);
    }

    /// Whether `method` `url` is a challenge-platform POST on the challenge host, which
    /// [`Self::challenge_post`] rewraps. Other POSTs pass through unchanged, the orchestrator's on
    /// a challenge page included: its script keeps the real modulus.
    #[must_use]
    pub fn is_challenge_post(&self, method: &str, url: &str) -> bool {
        method.eq_ignore_ascii_case("POST")
            && Url::parse(url).is_ok_and(|url| {
                url.host_str() == Some(self.challenge_host.as_str())
                    && challenge::is_post_path(url.path())
            })
    }

    /// Unwraps a challenge POST's seed and rewraps it under the real modulus. `cf_chl` is the
    /// request's `cf-chl` header.
    #[must_use]
    pub fn challenge_post(&self, url: &str, cf_chl: &str, body: &[u8]) -> Posted {
        let Ok(parsed) = Url::parse(url) else {
            return Posted::Unbound;
        };
        let Some(session) = self.sessions.bind(&parsed) else {
            return Posted::Unbound;
        };
        let Ok(encrypted) = std::str::from_utf8(body) else {
            let error = "the POST body is not UTF-8".to_owned();
            self.sessions.lock()[session].poison(&error);
            return Posted::Rejected(error);
        };
        let mut post = Post {
            url: url.to_owned(),
            cf_chl: cf_chl.to_owned(),
            encrypted_body: encrypted.to_owned(),
            ..Post::default()
        };
        match self.sessions.rewrap(session, encrypted) {
            Ok(rewrapped) => {
                post.seed = Some(hex(&rewrapped.seed));
                post.padding = Some(rewrapped.padding);
                Posted::Rewrapped(Box::new(ChallengePost {
                    body: rewrapped.body,
                    session,
                    url: parsed,
                    post,
                }))
            }
            Err(error) => {
                let error = format!("re-wrap failed: {error:#}");
                post.error = Some(error.clone());
                self.sessions.lock()[session].record(post);
                Posted::Rejected(error)
            }
        }
    }

    /// Records Cloudflare's (decoded) response to a rewrapped POST.
    pub fn answered_post(&self, post: Box<ChallengePost>, response_body: &[u8]) {
        let ChallengePost {
            session,
            url,
            mut post,
            ..
        } = *post;
        post.response_body = String::from_utf8_lossy(response_body).into_owned();
        post.decoded_program = decode_program(&url, &post.response_body);
        self.sessions.lock()[session].record(post);
    }

    /// Records that a rewrapped POST never reached Cloudflare, which excludes its session.
    pub fn failed_post(&self, post: Box<ChallengePost>, error: &str) {
        self.sessions.lock()[post.session].poison(error);
    }

    /// Waits for every session's parameter extraction, decrypts the payloads and returns the
    /// recording. Incomplete sessions are listed among its skipped ones.
    pub async fn finish(self) -> Recording {
        self.sessions.finish_extractions().await;
        let traffic = std::mem::take(&mut *self.traffic());
        let (sessions, skipped) = self.sessions.captured();
        Recording::new("the recording".into(), traffic, sessions, skipped)
    }

    pub(super) async fn finish_extractions(&self) {
        self.sessions.finish_extractions().await;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Unmasks the challenge POST response for `url`, if the result is valid base64 text.
fn decode_program(url: &Url, response_body: &str) -> Option<String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let ray = challenge::ray(url).ok()?;
    let program = challenge::decode_response(response_body.as_bytes(), ray).ok()?;
    String::from_utf8(program)
        .ok()
        .filter(|program| STANDARD.decode(program).is_ok())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::challenge::codec::{self, Codec, KEY_LENGTH, SEED_LENGTH};
    use crate::js::JsObject;

    const ALPHABET: &str = "BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/A";
    const SECRET: [u8; KEY_LENGTH] = *b"0123456789abcdef";

    /// A fake iframe with a modulus and an alphabet literal for the fast scan. It has no
    /// challenge program, so its session's parameters can't be extracted.
    fn iframe_html(modulus_hex: &str) -> String {
        format!(
            "<html><body><script>\nvar _cf_chl_opt = {{}};\nvar alphabet = \"{ALPHABET}\";\nvar n = BigInt(\"0x{modulus_hex}\");\n</script></body></html>"
        )
    }

    /// An interceptor hands the recorder the iframe and the POST; the recorder swaps in its
    /// modulus, rewraps the seed under the real one, and reports the session it couldn't read.
    #[tokio::test]
    async fn rewrites_iframes_and_rewraps_posts_for_any_interceptor() {
        let recorder = Recorder::new().unwrap();
        let real = ProxyKey::generate().unwrap();
        let iframe_url =
            format!("https://{CHALLENGE_HOST}/cdn-cgi/challenge-platform/h/g/turnstile/if/ov2");
        let html = iframe_html(&real.modulus.to_str_radix(16));
        let ours = recorder.sessions.proxy_key.modulus.clone();
        let rewritten = recorder.rewrite_iframe(&iframe_url, &html).unwrap();
        assert_eq!(rewritten.html, iframe_html(&ours.to_str_radix(16)));
        assert!(
            recorder
                .rewrite_iframe(&iframe_url, "<html></html>")
                .is_err()
        );

        let post_url = format!(
            "https://{CHALLENGE_HOST}/cdn-cgi/challenge-platform/h/g/fo/sess/RAY123/tok456"
        );
        assert!(recorder.is_challenge_post("POST", &post_url));
        assert!(!recorder.is_challenge_post("GET", &post_url));
        assert!(!recorder.is_challenge_post(
            "POST",
            "https://example.com/cdn-cgi/challenge-platform/h/g/fo/sess/RAY123/tok456"
        ));
        let mut seed = [42; SEED_LENGTH];
        seed[0] = codec::SEED_MARKER;
        let payload: JsObject =
            serde_json::from_value(json!({"1": {"a": [1, 2]}, "counter": 39})).unwrap();
        let encode = |modulus| {
            Codec::try_new(ALPHABET, modulus, SECRET)
                .unwrap()
                .encode(&payload, seed)
        };
        let Posted::Rewrapped(post) =
            recorder.challenge_post(&post_url, "tok456", encode(ours).as_bytes())
        else {
            panic!("the POST binds to the open session");
        };
        assert_eq!(post.body, encode(real.modulus.clone()));
        recorder.answered_post(post, b"masked");

        // A second ray finds no unbound session to take it.
        let other = post_url.replace("RAY123", "RAY456");
        assert!(matches!(
            recorder.challenge_post(&other, "tok", b"body"),
            Posted::Unbound
        ));

        let request = recorder.request(
            None,
            "POST",
            &post_url,
            "HTTP/2.0",
            SentHeaders::Unordered(vec![("cf-chl".into(), "tok456".into())]),
        );
        recorder.answered(request);
        let recording = recorder.finish().await;
        assert_eq!(recording.sessions().count(), 0);
        let [skipped] = recording.skipped() else {
            panic!("{:?}", recording.skipped())
        };
        assert!(
            skipped.starts_with("session-0000: incomplete capture: extracting the session params"),
            "{skipped}"
        );
    }
}
