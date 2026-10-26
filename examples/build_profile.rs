//! Store a real browser's probe answers for a device profile.
//! Usage: build_profile <capture.json> > answers.json
//!
//! The capture is what `scripts/cdp_capture.mjs` writes: the iframe's HTML,
//! its POSTs with their responses, and the plaintext payloads. Each probe's
//! record from the second payload is stored under the reference build's
//! names; see `cfsolve::stage2::replay`.

use std::{env, fs};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cfsolve::js::Payload;
use cfsolve::script::Source;
use cfsolve::stage2::replay::Answers;
use cfsolve::{JsValue, challenge};
use url::Url;

fn main() -> Result<()> {
    let path = env::args().nth(1).context("supply a capture JSON file")?;
    let capture: JsValue = serde_json::from_slice(&fs::read(&path)?)?;
    let html = capture["iframeHtml"]
        .as_str()
        .context("the capture has no iframe HTML")?;
    let javascript = challenge::inline_javascript(html)?;
    let deobfuscated = cfsolve::deobfuscate(javascript)?;
    let source = Source::try_new(&deobfuscated.text)?;

    // The first payload's response is the probe program, masked with the ray
    // its URL carries.
    let post = &capture["posts"][0];
    let url = Url::parse(post["url"].as_str().context("the capture has no POST")?)?;
    let body = post["responseBody"]
        .as_str()
        .context("the first payload has no response")?;
    let program = STANDARD.decode(challenge::decode_response(
        body.as_bytes(),
        challenge::ray(&url)?,
    )?)?;

    // The second payload is the one holding the numbered records.
    let payload = capture["payloads"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|payload| payload["payload"].as_object())
        .find(|payload| payload.contains_key("1"))
        .context("the capture has no second payload")?;
    let answers = Answers::capture(&source, &program, &Payload::from(payload.clone()))?;
    println!("{}", serde_json::to_string_pretty(&answers)?);
    Ok(())
}
