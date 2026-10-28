//! Derives header orders and the browser's identity headers from the requests in `traffic.json`.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::hash::Hash;

use indexmap::IndexMap;
use url::Url;

use crate::capture::CHALLENGE_HOST;
use crate::capture::traffic::Request;
use crate::http::RequestKind;

/// Client hints that can appear on any request. Other hints identify navigation retries made after
/// the server requested high-entropy hints.
const LOW_ENTROPY_HINTS: [&str; 3] = ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"];

/// Header orders and browser identity headers collected from requests.
pub(super) struct Headers {
    /// Header order for each request type. Prefer orders with the most supplied headers, then the
    /// most common order. The solver omits headers it cannot supply, such as a referrer withheld by
    /// page policy. Orders include high-entropy hints requested before the challenge. For request
    /// types shared by ordinary sites and challenge pages, such as icons, only challenge-page
    /// requests matter.
    pub(super) orders: BTreeMap<RequestKind, Vec<String>>,
    /// Most common value for each user agent or client hint header, in the order the headers first
    /// appeared.
    pub(super) identity: IndexMap<String, String>,
}

impl Headers {
    pub(super) fn observe<'r>(requests: impl IntoIterator<Item = &'r Request>) -> Self {
        let mut orders: BTreeMap<RequestKind, Tally<Vec<String>>> = BTreeMap::new();
        let mut identity: IndexMap<String, Tally<String>> = IndexMap::new();
        for request in requests {
            let Some(kind) = kind(request) else {
                continue;
            };
            let sent = request.headers.iter().filter(|(name, _)| name != "cookie");
            let order: Vec<String> = sent.map(|(name, value)| kind.entry(name, value)).collect();
            orders.entry(kind).or_default().add(order);
            for (name, value) in &request.headers {
                if name == "user-agent" || name.starts_with("sec-ch-") {
                    identity.entry(name.clone()).or_default().add(value.clone());
                }
            }
        }
        // Fixed headers use `name: value`; headers filled at request time use bare names.
        let supplied =
            |order: &Vec<String>| order.iter().filter(|entry| !entry.contains(':')).count();
        Self {
            orders: orders
                .into_iter()
                .map(|(kind, tally)| (kind, tally.best(supplied)))
                .collect(),
            identity: identity
                .into_iter()
                .map(|(name, tally)| (name, tally.best(|_| ())))
                .collect(),
        }
    }
}

/// Classifies requests the solver can send. Excludes cache revalidation requests because each solve
/// starts with an empty cache.
fn kind(request: &Request) -> Option<RequestKind> {
    if request.header("if-none-match").is_some() || request.header("if-modified-since").is_some() {
        return None;
    }
    let url = Url::parse(&request.url).ok()?;
    let challenge = url.host_str() == Some(CHALLENGE_HOST);
    let post = request.method == "POST";
    let mode = request.header("sec-fetch-mode");
    // Challenge pages load the orchestrator and post to it on their own origin.
    let platform = |route: &str| {
        let path = url.path();
        path.starts_with("/cdn-cgi/challenge-platform/") && path.contains(route)
    };
    Some(match (request.header("sec-fetch-dest")?, challenge, post) {
        ("document", _, true) => RequestKind::Form,
        // Match navigation from a typed address. Reloads and links use different headers.
        ("document", _, false) if request.header("sec-fetch-site") == Some("none") => {
            let hints = request.headers.iter().any(|(name, _)| {
                name.starts_with("sec-ch-") && !LOW_ENTROPY_HINTS.contains(&name.as_str())
            });
            if hints {
                RequestKind::NavigationWithHints
            } else {
                RequestKind::Navigation
            }
        }
        ("iframe", true, false) => RequestKind::Iframe,
        ("script", true, false) if mode == Some("cors") => RequestKind::CorsScript,
        // The loader URL redirects to a URL for a specific build.
        ("script", true, false) if url.path() == "/turnstile/v0/api.js" => RequestKind::Script,
        ("script", true, false) => RequestKind::ScriptRedirect,
        ("script", false, false) if platform("/orchestrate/") => RequestKind::Orchestrator,
        ("image", false, false) => RequestKind::PageImage,
        ("image", true, false) => RequestKind::Image,
        ("empty", false, true) if platform("/fo/") => RequestKind::OrchestratorPost,
        ("empty", true, true) => RequestKind::ChallengePost,
        // The private token probe fetches with `{cache: "no-cache"}`.
        ("empty", true, false) if url.path().contains("/pat/") => RequestKind::WorkerFetch,
        ("empty", true, false) => RequestKind::WorkerFetchWithoutCredentials,
        _ => return None,
    })
}

/// Counts occurrences of each value while preserving insertion order.
#[derive(Default)]
struct Tally<T>(IndexMap<T, usize>);

impl<T: Hash + Eq> Tally<T> {
    fn add(&mut self, value: T) {
        *self.0.entry(value).or_default() += 1;
    }

    /// Returns the highest-ranked value. Breaks ties by frequency, then by insertion order.
    fn best<R: Ord>(self, rank: impl Fn(&T) -> R) -> T {
        // For equal keys, `min_by_key` returns the first entry; `max_by_key` returns the last.
        let counts = self.0.into_iter();
        let best = counts.min_by_key(|(value, count)| Reverse((rank(value), *count)));
        best.expect("a tally holds what was added to it").0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, url: &str, headers: &[(&str, &str)]) -> Request {
        let headers = headers
            .iter()
            .map(|&(name, value)| (name.into(), value.into()));
        Request::received(method, url, headers.collect())
    }

    /// Select the most common order among those with the most supplied headers. Break ties by first
    /// occurrence. Ignore cookies and cache revalidations.
    #[test]
    fn orders_each_kind_of_request_as_most_often_sent() {
        let challenge = "https://challenges.cloudflare.com";
        let script = [
            ("sec-fetch-dest", "script"),
            ("sec-fetch-mode", "no-cors"),
            ("user-agent", "Mozilla/5.0"),
            ("referer", "https://example.com/"),
        ];
        let image = |storage: &str, referred: bool, revalidated: bool| {
            let mut headers = vec![
                ("sec-fetch-dest", "image"),
                ("cookie", "a=b"),
                ("sec-fetch-storage-access", storage),
            ];
            if referred {
                headers.push(("referer", "https://challenges.cloudflare.com/"));
            }
            if revalidated {
                headers.push(("if-none-match", "\"1\""));
            }
            request("GET", &format!("{challenge}/ci/1"), &headers)
        };
        let navigation = |hint: (&str, &str)| {
            let headers = [
                hint,
                ("sec-fetch-site", "none"),
                ("sec-fetch-dest", "document"),
            ];
            request("GET", "https://example.com/", &headers)
        };
        let requests = [
            // A site's own script should not be classified as the orchestrator.
            request(
                "GET",
                "https://example.com/app.js",
                &[("sec-fetch-dest", "script")],
            ),
            navigation(("sec-ch-ua", "\"Chromium\"")),
            navigation(("sec-ch-ua-arch", "\"x86\"")),
            request("GET", &format!("{challenge}/turnstile/v0/api.js"), &script),
            request(
                "GET",
                &format!("{challenge}/turnstile/v0/b/1/api.js"),
                &script,
            ),
            image("none", false, false),
            image("none", false, false),
            image("none", true, true),
            image("none", true, true),
            image("active", true, false),
        ];
        let headers = Headers::observe(&requests);
        let orders: Vec<(RequestKind, Vec<String>)> = headers.orders.into_iter().collect();
        let entries = |entries: &[&str]| entries.iter().map(|&entry| entry.to_owned()).collect();
        let script_order: Vec<String> = entries(&[
            "sec-fetch-dest: script",
            "sec-fetch-mode: no-cors",
            "user-agent",
            "referer",
        ]);
        assert_eq!(
            orders,
            [
                (
                    RequestKind::Navigation,
                    entries(&[
                        "sec-ch-ua",
                        "sec-fetch-site: none",
                        "sec-fetch-dest: document"
                    ])
                ),
                (
                    RequestKind::NavigationWithHints,
                    entries(&[
                        "sec-ch-ua-arch",
                        "sec-fetch-site: none",
                        "sec-fetch-dest: document"
                    ])
                ),
                (RequestKind::Script, script_order.clone()),
                (RequestKind::ScriptRedirect, script_order),
                (
                    RequestKind::Image,
                    entries(&[
                        "sec-fetch-dest: image",
                        "sec-fetch-storage-access: active",
                        "referer"
                    ])
                ),
            ]
        );
        let identity: Vec<(&str, &str)> = headers
            .identity
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            identity,
            [
                ("sec-ch-ua", "\"Chromium\""),
                ("sec-ch-ua-arch", "\"x86\""),
                ("user-agent", "Mozilla/5.0")
            ]
        );
    }
}
