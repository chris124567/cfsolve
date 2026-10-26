//! Builds challenge-platform resource URLs for probes.

use anyhow::Result;
use url::Url;

use crate::js::{self, JsValue, Options};

/// Builds a probe URL relative to the iframe by concatenating platform path, option `platform`,
/// resource `path`, and probe `input` using JavaScript string conversion.
pub(crate) fn url(
    options: &Options,
    platform: &str,
    path: &str,
    input: &JsValue,
    base: &Url,
) -> Result<Url> {
    let path = format!(
        "/cdn-cgi/challenge-platform/h/{}{path}{}",
        js::string(options.get(platform)),
        js::string(Some(input)),
    );
    Ok(base.join(&path)?)
}
