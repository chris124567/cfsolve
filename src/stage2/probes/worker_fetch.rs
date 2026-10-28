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
/// [`super::platform::url`] builds URLs relative to the iframe instead.
const HOST: &str = "brunhild.challenges.cloudflare.com";
const PATH: &str = "/cdn-cgi/challenge-platform/h/";

/// The session's options naming the request path's platform segment, ray and nonce.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
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
            "https://{HOST}{PATH}{}/i/{}/{}",
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
    let requests = [HOST, PATH]
        .iter()
        .all(|part| strings.features().iter().any(|text| text.contains(part)));
    (strings.stores_all(&OUTPUTS) && strings.has_all(&markers) && requests).then(|| Fields {
        platform_property: probe.session_name(reference::PLATFORM_OPTION),
        ray_property: probe.session_name(reference::RAY_OPTION),
        nonce_property: probe.session_name(reference::NONCE_OPTION),
    })
}
