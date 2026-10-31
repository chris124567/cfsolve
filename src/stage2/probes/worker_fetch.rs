//! Builds worker CORS fetch results, including status and the first challenge token header.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::js::{self, JsObject, Options, json};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

pub(crate) const OUTPUTS: [&str; 2] = [
    reference::WORKER_FETCH_STATUS,
    reference::WORKER_FETCH_TOKEN,
];

/// The response header whose value the probe reports as its token.
const HEADER: &str = "cf-chl-peek";
/// Explicit host and path prefix for the worker fetch. Builds may store them as one string or two.
/// The host's first label varies by region, such as `brunhild` or `hagen`.
/// [`super::platform::url`] builds URLs relative to the iframe instead.
const HOST_SUFFIX: &str = ".challenges.cloudflare.com";
const PATH: &str = "/cdn-cgi/challenge-platform/h/";

/// The fetched host and the session's options naming the request path's platform segment, ray
/// and nonce.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub host: String,
    pub platform_property: String,
    pub ray_property: String,
    pub nonce_property: String,
}

/// How the worker's fetch settled.
pub enum Measurement {
    Rejected,
    Response {
        status: u16,
        headers: Vec<(String, String)>,
    },
}

impl Fields {
    /// Returns the worker fetch URL for the hidden response header.
    pub fn url(&self, options: &Options) -> Result<Url> {
        let option = |name: &str| js::string(options.get(name));
        Ok(Url::parse(&format!(
            "https://{}{PATH}{}/i/{}/{}",
            self.host,
            option(&self.platform_property),
            option(&self.ray_property),
            option(&self.nonce_property),
        ))?)
    }

    /// Builds the fetch record with response status. For a 204 response, also reports the first
    /// challenge-token header.
    #[must_use]
    pub fn collect(&self, input: &Measurement) -> JsObject {
        let mut fields = JsObject::new();
        let status = match input {
            Measurement::Rejected => "fetch_error".into(),
            Measurement::Response { status, .. } if *status != 204 => {
                format!("http_error:{status}")
            }
            Measurement::Response { headers, .. } => {
                // Headers.forEach reports lowercase names. Compare exactly as
                // the bytecode does, and stop at the first match, even if empty.
                match headers.iter().find(|(name, _)| name == HEADER) {
                    Some((_, value)) if !value.is_empty() => {
                        fields.insert(reference::WORKER_FETCH_TOKEN.to_owned(), json!(value));
                        "ok".into()
                    }
                    _ => "no_token".into(),
                }
            }
        };
        fields.insert(reference::WORKER_FETCH_STATUS.to_owned(), json!(status));
        fields
    }
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let strings = &probe.strings;
    let markers = [
        HEADER,
        "fetch_threw",
        "fetch_error",
        "fetch_unavailable",
        "no_token",
        "cors",
        "omit",
        "no-store",
    ];
    let features = strings.features();
    let host = features.iter().find_map(|text| host(text))?;
    let path = features.iter().any(|text| text.contains(PATH));
    (strings.stores_all(&OUTPUTS) && strings.has_all(&markers) && path).then(|| Fields {
        host: host.to_owned(),
        platform_property: probe.session_name(reference::PLATFORM_OPTION),
        ray_property: probe.session_name(reference::RAY_OPTION),
        nonce_property: probe.session_name(reference::NONCE_OPTION),
    })
}

/// Finds the challenge host in `text`, which may be a full URL or a host after a length prefix.
fn host(text: &str) -> Option<&str> {
    let suffix = text.find(HOST_SUFFIX)?;
    let start = text[..suffix]
        .rfind(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
        .map_or(0, |index| index + 1);
    (start < suffix).then(|| &text[start..suffix + HOST_SUFFIX.len()])
}

#[cfg(test)]
mod tests {
    use super::host;

    #[test]
    fn finds_regional_hosts_in_urls_and_prefixed_strings() {
        for (text, expected) in [
            (
                "https://brunhild.challenges.cloudflare.com/cdn-cgi/challenge-platform/h/",
                Some("brunhild.challenges.cloudflare.com"),
            ),
            (
                "\0\u{1f}hagen.challenges.cloudflare.com\0\0",
                Some("hagen.challenges.cloudflare.com"),
            ),
            ("https://.challenges.cloudflare.com", None),
        ] {
            assert_eq!(host(text), expected, "{text:?}");
        }
    }
}
