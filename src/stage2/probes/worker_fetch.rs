//! Builds worker CORS fetch results, including status and the first challenge token header.

use std::collections::BTreeSet;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::js::{self, JsObject, Options, json};
use crate::listing;
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

pub(crate) const OUTPUTS: [&str; 2] = [
    reference::WORKER_FETCH_STATUS,
    reference::WORKER_FETCH_TOKEN,
];

/// The response header whose value the probe reports as its token.
const HEADER: &str = "cf-chl-peek";
/// The worker endpoint's protocol path. The host comes from the current program:
/// Cloudflare rotates it independently of the iframe's host.
const PATH: &str = "/cdn-cgi/challenge-platform/h/";

/// The session's options naming the request path's platform segment, ray and nonce.
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
    if !(strings.stores_all(&OUTPUTS) && strings.has_all(&markers)) {
        return None;
    }
    Some(Fields {
        host: request_host(strings.features(), probe.pool)?,
        platform_property: probe.session_name(reference::PLATFORM_OPTION),
        ray_property: probe.session_name(reference::RAY_OPTION),
        nonce_property: probe.session_name(reference::NONCE_OPTION),
    })
}

/// Reads literal or encoded URL fragments in program order. Accepts a unique
/// Cloudflare endpoint; an unrelated URL or an ambiguous program is not a match.
fn request_host(features: &[String], pool: &str) -> Option<String> {
    let strings: Vec<String> = features
        .iter()
        .map(|text| {
            if text.starts_with('\0') || text.starts_with("ÿÿ") {
                listing::decode_string(text, pool).unwrap_or_default()
            } else {
                text.clone()
            }
        })
        .collect();
    let mut hosts = BTreeSet::new();
    for start in 0..strings.len() {
        if !strings[start].starts_with("https://") {
            continue;
        }
        let mut candidate = String::new();
        for part in strings[start..].iter().take(3) {
            candidate.push_str(part);
            let Ok(url) = Url::parse(&candidate) else {
                continue;
            };
            if url.path() == PATH
                && url.username().is_empty()
                && url.password().is_none()
                && url.port().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && let Some(host) = url.host_str()
                && host.ends_with(".challenges.cloudflare.com")
            {
                hosts.insert(host.to_owned());
            }
        }
    }
    (hosts.len() == 1).then(|| hosts.pop_first()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn reads_current_hosts_from_complete_split_and_encoded_urls() {
        for host in ["brunhild", "hagen", "future-worker"] {
            let host = format!("{host}.challenges.cloudflare.com");
            let full = format!("https://{host}{PATH}");
            let encoded = format!("\0{}{host}\0padding", char::from(host.len() as u8));
            for features in [
                strings(&[&full]),
                strings(&["https://", &host, PATH]),
                strings(&["https://", &encoded, PATH]),
                strings(&[&format!("https://{host}"), PATH]),
            ] {
                assert_eq!(request_host(&features, ""), Some(host.clone()));
            }
        }
    }

    #[test]
    fn reads_pooled_hosts_and_builds_the_current_request() {
        let host = "hagen.challenges.cloudflare.com";
        let pool = format!("\0\0{host}");
        let descriptor = format!("ÿÿ\0\0\0\0\0\0\0\0\0{}", char::from(host.len() as u8));
        let host = request_host(&strings(&["https://", &descriptor, PATH]), &pool).unwrap();
        let fields = Fields {
            host,
            platform_property: "platform".into(),
            ray_property: "ray".into(),
            nonce_property: "nonce".into(),
        };
        let options =
            serde_json::from_str(r#"{"platform":"g","ray":"fresh-ray","nonce":"fresh-nonce"}"#)
                .unwrap();
        assert_eq!(
            fields.url(&options).unwrap().as_str(),
            "https://hagen.challenges.cloudflare.com/cdn-cgi/challenge-platform/h/g/i/fresh-ray/fresh-nonce"
        );
    }

    #[test]
    fn rejects_missing_ambiguous_and_unrelated_endpoints() {
        for parts in [
            vec!["https://hagen.challenges.cloudflare.com/other/"],
            vec![
                "https://hagen.challenges.cloudflare.com.evil.example/cdn-cgi/challenge-platform/h/",
            ],
            vec!["https://user@hagen.challenges.cloudflare.com/cdn-cgi/challenge-platform/h/"],
            vec!["https://hagen.challenges.cloudflare.com:8443/cdn-cgi/challenge-platform/h/"],
            vec!["https://", "\0", PATH],
            vec![
                "https://hagen.challenges.cloudflare.com/cdn-cgi/challenge-platform/h/",
                "https://brunhild.challenges.cloudflare.com/cdn-cgi/challenge-platform/h/",
            ],
        ] {
            assert_eq!(request_host(&strings(&parts), ""), None);
        }
    }
}
