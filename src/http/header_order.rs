//! Header order for each request kind, from `transport.requests.headers`.
//!
//! A `"name: value"` entry sends a fixed value. A bare `"name"` uses a request-supplied value
//! (see [`RequestKind::supplied`]) or the browser's user agent and client hints.
//! Request-supplied headers may be omitted; browser identity headers must have a value.

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Context, Result, ensure};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use wreq::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};

/// Each kind of request the challenge flow makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RequestKind {
    /// A navigation to a typed address.
    Navigation,
    /// A navigation retried with the high-entropy client hints its response demanded.
    NavigationWithHints,
    /// The challenge iframe's navigation.
    Iframe,
    /// A classic `<script src>` from another site.
    Script,
    /// A `crossorigin="anonymous"` script from another site.
    CorsScript,
    /// A classic script request after a redirect.
    ScriptRedirect,
    /// The orchestrator a challenge page loads from its own origin.
    Orchestrator,
    /// An image a challenge page loads from its own origin.
    PageImage,
    /// The orchestrator's XHR carrying an encoded challenge body.
    OrchestratorPost,
    /// The iframe's XHR carrying an encoded challenge body.
    ChallengePost,
    /// An image the challenge iframe loads.
    Image,
    /// A worker's `fetch(url, {cache: "no-cache"})`.
    WorkerFetch,
    /// A worker's `fetch(url, {cache: "no-store", credentials: "omit"})`.
    WorkerFetchWithoutCredentials,
    Form,
    /// HTTP/1.1 WebSocket handshake from the iframe. Handshakes are not captured, so profiles
    /// specify this order manually.
    #[serde(rename = "websocket")]
    WebSocket,
}

impl RequestKind {
    /// Request kinds required in every profile. Profiles may omit hint retries if the browser
    /// has no high-entropy client hints. They may omit a redirect order if the browser
    /// preserves script headers on redirects.
    const REQUIRED: [Self; 12] = [
        Self::Navigation,
        Self::Iframe,
        Self::Script,
        Self::CorsScript,
        Self::Orchestrator,
        Self::PageImage,
        Self::OrchestratorPost,
        Self::ChallengePost,
        Self::Image,
        Self::WorkerFetch,
        Self::WorkerFetchWithoutCredentials,
        Self::Form,
    ];

    /// Lists headers this request kind can supply when the profile names a header without a
    /// fixed value.
    #[must_use]
    pub(super) fn supplied(self) -> &'static [&'static str] {
        match self {
            Self::Navigation | Self::NavigationWithHints => &[],
            Self::Iframe
            | Self::Script
            | Self::ScriptRedirect
            | Self::Orchestrator
            | Self::PageImage
            | Self::Image => &["referer"],
            Self::CorsScript => &["origin", "referer"],
            Self::OrchestratorPost | Self::ChallengePost => {
                &["content-length", "cf-chl", "origin", "referer"]
            }
            Self::WorkerFetch | Self::WorkerFetchWithoutCredentials => &["sec-fetch-site"],
            Self::Form => &["content-length", "origin", "sec-fetch-site", "referer"],
            Self::WebSocket => &["origin"],
        }
    }

    /// Converts a captured header to an order entry for [`Slot::parse`]. Uses a bare name if the
    /// request or browser identity supplies its value.
    #[must_use]
    pub(crate) fn entry(self, name: &str, value: &str) -> String {
        if self.gives_value(name) {
            name.to_owned()
        } else {
            format!("{name}: {value}")
        }
    }

    /// Checks whether the request or browser identity supplies a value for header `name`, as with
    /// the user agent and client hints.
    fn gives_value(self, name: &str) -> bool {
        name == USER_AGENT.as_str()
            || name.starts_with("sec-ch-")
            || self.supplied().contains(&name)
    }
}

/// Returns the request kind's profile name.
impl fmt::Display for RequestKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(formatter)
    }
}

/// One header in a request's order.
#[derive(Clone, Debug)]
pub(super) enum Slot {
    /// A header every request of the kind sends with this value.
    Fixed(HeaderName, HeaderValue),
    /// A header that takes its value from the request or the browser's own headers.
    Named(HeaderName),
}

impl Slot {
    /// A `"name: value"` or `"name"` entry in the header order for `kind`.
    fn parse(kind: RequestKind, entry: &str) -> Result<Self> {
        let header = |name: &str| {
            HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("{name:?} is not a header name"))
        };
        let Some((name, value)) = entry.split_once(':') else {
            let name = header(entry)?;
            ensure!(
                kind.gives_value(name.as_str()),
                "nothing gives `{name}` a value; write it as `{name}: <value>`"
            );
            return Ok(Self::Named(name));
        };
        let value = value.trim_start();
        let value = HeaderValue::from_str(value)
            .with_context(|| format!("{value:?} is not a header value"))?;
        Ok(Self::Fixed(header(name)?, value))
    }
}

/// Each kind of request's headers, in the order the browser sends them.
#[derive(Clone, Debug)]
pub struct HeaderOrder(BTreeMap<RequestKind, Vec<Slot>>);

impl HeaderOrder {
    fn try_new(entries: BTreeMap<RequestKind, Vec<String>>) -> Result<Self> {
        for kind in RequestKind::REQUIRED {
            ensure!(
                entries.contains_key(&kind),
                "no order for `{kind}` requests"
            );
        }
        let mut orders = BTreeMap::new();
        for (kind, entries) in entries {
            let slots = entries
                .iter()
                .map(|entry| Slot::parse(kind, entry))
                .collect::<Result<Vec<Slot>>>()
                .with_context(|| format!("reading the order of `{kind}` requests"))?;
            orders.insert(kind, slots);
        }
        Ok(Self(orders))
    }

    /// The order of `kind` requests, if the profile gives one.
    #[must_use]
    pub(super) fn get(&self, kind: RequestKind) -> Option<&[Slot]> {
        self.0.get(&kind).map(Vec::as_slice)
    }

    /// Checks that browser headers in `own` supply values for bare names that no request
    /// supplies.
    pub(super) fn check_own(&self, own: &HeaderMap) -> Result<()> {
        for (kind, slots) in &self.0 {
            for slot in slots {
                if let Slot::Named(name) = slot
                    && !kind.supplied().contains(&name.as_str())
                {
                    ensure!(
                        own.contains_key(name),
                        "the order of `{kind}` requests names `{name}`, which the \
                         browser's headers do not give"
                    );
                }
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for HeaderOrder {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = BTreeMap::<RequestKind, Vec<String>>::deserialize(deserializer)?;
        Self::try_new(entries).map_err(|error| de::Error::custom(format!("{error:#}")))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::*;

    /// Creates header orders for every required request kind from the same `entries`.
    fn every_kind(entries: &[&str]) -> Value {
        let orders: Map<String, Value> = RequestKind::REQUIRED
            .iter()
            .map(|kind| (kind.to_string(), json!(entries)))
            .collect();
        Value::Object(orders)
    }

    fn read(orders: Value) -> Result<HeaderOrder, String> {
        serde_json::from_value(orders).map_err(|error| error.to_string())
    }

    #[test]
    fn entries_fix_a_value_or_name_one_something_supplies() {
        let order = read(every_kind(&["user-agent", "sec-fetch-mode: navigate"])).unwrap();
        let [Slot::Named(named), Slot::Fixed(name, value)] = order.get(RequestKind::Form).unwrap()
        else {
            panic!("not one named and one fixed header");
        };
        assert_eq!(*named, USER_AGENT);
        assert_eq!(name, "sec-fetch-mode");
        assert_eq!(value, "navigate");

        let error = read(every_kind(&["sec-fetch-mode"])).unwrap_err();
        assert!(
            error.contains("nothing gives `sec-fetch-mode` a value"),
            "{error}"
        );
        let error = read(every_kind(&["referer"])).unwrap_err();
        assert!(
            error.contains("the order of `navigation` requests"),
            "a navigation supplies no referer: {error}"
        );

        // Converting a sent header to an order entry preserves how it is read back.
        let entries = [
            (RequestKind::Form, "referer", "referer"),
            (RequestKind::Image, "sec-ch-ua-model", "sec-ch-ua-model"),
            (RequestKind::Image, "user-agent", "user-agent"),
            (
                RequestKind::Navigation,
                "sec-fetch-mode",
                "sec-fetch-mode: navigate",
            ),
        ];
        for (kind, name, entry) in entries {
            assert_eq!(kind.entry(name, "navigate"), entry);
        }
    }

    #[test]
    fn the_browser_gives_what_no_request_supplies() {
        let order = read(every_kind(&["user-agent", "sec-ch-ua-model"])).unwrap();
        let mut own = HeaderMap::new();
        own.insert(USER_AGENT, HeaderValue::from_static("Mozilla/5.0"));
        let error = order.check_own(&own).unwrap_err().to_string();
        assert!(error.contains("names `sec-ch-ua-model`"), "{error}");

        own.insert("sec-ch-ua-model", HeaderValue::from_static("\"\""));
        order.check_own(&own).unwrap();
    }

    #[test]
    fn only_the_optional_kinds_may_be_left_out() {
        let mut orders = every_kind(&["user-agent"]);
        let order = read(orders.clone()).unwrap();
        assert!(order.get(RequestKind::ScriptRedirect).is_none());
        assert!(order.get(RequestKind::NavigationWithHints).is_none());

        orders
            .as_object_mut()
            .expect("every_kind builds an object")
            .remove("image");
        let error = read(orders).unwrap_err();
        assert!(error.contains("no order for `image` requests"), "{error}");
    }
}
