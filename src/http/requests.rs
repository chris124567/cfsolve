//! Builds requests used by the challenge flow. [`super::HeaderOrder`] supplies headers and
//! ordering; each request supplies values such as its referrer.

use anyhow::{Context, Result};
use url::Url;
use url::form_urlencoded::Serializer;
use wreq::cookie::Jar;
use wreq::header::LOCATION;
use wreq::redirect::Policy;
use wreq::ws::WebSocket;
use wreq::{Response, StatusCode};

use super::client::BrowserClient;
use super::decode::{self, ResponseMetrics};
use super::header_order::RequestKind;
use super::referrer::{self, ReferrerPolicy};
use crate::engine::Engine;

/// Fetched iframe URL, HTML, and navigation measurements.
#[derive(Debug)]
pub struct Iframe {
    pub url: Url,
    pub html: String,
    pub navigation: ResponseMetrics,
}

/// Fetches the embedding API's iframe URL using the page-policy `referer`. Never caches
/// challenge options because every response creates a separate POST session.
pub async fn fetch_iframe(
    client: &BrowserClient,
    url: Url,
    referer: Option<&str>,
) -> Result<Iframe> {
    let request = decode::preserve_encoding(client.http.get(url.as_str()));
    let response = client
        .send(request, RequestKind::Iframe, &[("referer", referer)])
        .await?
        .error_for_status()?;
    let url = Url::parse(&response.uri().to_string())?;
    let (decoded, navigation) = decode::read_encoded(response).await?;
    let html = String::from_utf8(decoded).context("iframe HTML is not UTF-8")?;
    Ok(Iframe {
        url,
        html,
        navigation,
    })
}

/// A fetched document and response metadata, regardless of status. Challenge pages use 403.
#[derive(Clone, Debug)]
pub struct PageDocument {
    /// Final navigation URL, used to resolve relative links.
    pub url: Url,
    pub status: StatusCode,
    pub html: String,
    /// Referrer policy applied to the page's outgoing requests.
    pub(crate) referrer_policy: ReferrerPolicy,
}

impl PageDocument {
    /// A document served at `url` with its `Referrer-Policy` header, if any.
    #[must_use]
    pub(crate) fn new(url: Url, status: StatusCode, html: String, policy: Option<&str>) -> Self {
        Self {
            referrer_policy: ReferrerPolicy::of_document(policy, &html),
            url,
            status,
            html,
        }
    }

    async fn read(response: Response) -> Result<Self> {
        let url = Url::parse(&response.uri().to_string())?;
        let status = response.status();
        let header = response
            .headers()
            .get("referrer-policy")
            .map(decode::header_text);
        let html = response.text().await?;
        Ok(Self::new(url, status, html, header.as_deref()))
    }
}

/// Navigates as if the user typed an address. Retries once if `Critical-CH` requires
/// high-entropy client hints and the profile supports that retry.
pub async fn navigate(client: &BrowserClient, url: &Url) -> Result<PageDocument> {
    let navigation = async |kind| {
        let request = client.http.get(url.as_str());
        client
            .send(request, kind, &[])
            .await
            .context("navigating to the page")
    };
    let mut response = navigation(RequestKind::Navigation).await?;
    if response.headers().contains_key("critical-ch")
        && client.orders(RequestKind::NavigationWithHints)
    {
        response = navigation(RequestKind::NavigationWithHints).await?;
    }
    PageDocument::read(response).await
}

/// Loads a same-origin orchestrator script after the page has requested high-entropy hints.
/// `referer` is the page's temporary address during loading.
pub async fn fetch_orchestrator(
    client: &BrowserClient,
    url: &Url,
    referer: &Url,
) -> Result<String> {
    let request = client.http.get(url.as_str());
    let supplied = [("referer", Some(referer.as_str()))];
    let response = client
        .send(request, RequestKind::Orchestrator, &supplied)
        .await
        .context("loading the orchestrator")?
        .error_for_status()?;
    Ok(response.text().await?)
}

/// Loads a same-origin image as the orchestrator would. Reads and discards the body, retaining
/// response timing.
pub async fn fetch_page_image(
    client: &BrowserClient,
    page: &Url,
    url: &Url,
) -> Result<ResponseMetrics> {
    let request = decode::preserve_encoding(client.http.get(url.as_str()));
    let supplied = [("referer", Some(page.as_str()))];
    let response = client
        .send(request, RequestKind::PageImage, &supplied)
        .await
        .context("loading the page's image")?;
    let (_, metrics) = decode::read_encoded(response).await?;
    Ok(metrics)
}

/// Posts an encoded challenge body to `post_url` from `document` using `referer`. Does not
/// follow redirects, preserving the response for the caller.
async fn encoded_post(
    client: &BrowserClient,
    kind: RequestKind,
    document: &Url,
    referer: &str,
    post_url: &Url,
    cf_chl: &str,
    encoded_body: String,
) -> Result<Response, wreq::Error> {
    let length = encoded_body.len().to_string();
    let origin = document.origin().ascii_serialization();
    let request = decode::preserve_encoding(client.http.post(post_url.as_str()))
        .redirect(Policy::none())
        .body(encoded_body);
    let supplied = [
        ("content-length", Some(length.as_str())),
        ("cf-chl", Some(cf_chl)),
        ("origin", Some(origin.as_str())),
        ("referer", Some(referer)),
    ];
    client.send(request, kind, &supplied).await
}

/// The orchestrator's XHR to its challenge URL on the page's own origin.
/// Like [`post_challenge`], the response is returned intact.
pub async fn post_orchestrator(
    client: &BrowserClient,
    page: &Url,
    post_url: &Url,
    cf_chl: &str,
    encoded_body: String,
) -> Result<Response> {
    encoded_post(
        client,
        RequestKind::OrchestratorPost,
        page,
        page.as_str(),
        post_url,
        cf_chl,
        encoded_body,
    )
    .await
    .context("sending the orchestrator POST")
}

/// Submits a URL-encoded form as a navigation from `referer` to `action`.
pub async fn submit_form(
    client: &BrowserClient,
    referer: &Url,
    action: &Url,
    fields: &[(String, String)],
) -> Result<PageDocument> {
    let body = Serializer::new(String::new()).extend_pairs(fields).finish();
    let length = body.len().to_string();
    let origin = referer.origin().ascii_serialization();
    let site = if action.origin() == referer.origin() {
        "same-origin"
    } else {
        "cross-site"
    };
    let request = client.http.post(action.as_str()).body(body);
    let supplied = [
        ("content-length", Some(length.as_str())),
        ("origin", Some(origin.as_str())),
        ("sec-fetch-site", Some(site)),
        ("referer", Some(referer.as_str())),
    ];
    let response = client
        .send(request, RequestKind::Form, &supplied)
        .await
        .context("submitting the form")?;
    PageDocument::read(response).await
}

/// How a page loads a script from another site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptLoad {
    /// A classic `<script src>`.
    Classic,
    /// An anonymous cross-origin script request. Sends no cookies and reports no storage
    /// access.
    Anonymous,
}

/// Loads a cross-origin script into `page`, using the page policy's `referer` as for the widget
/// loader.
pub async fn fetch_script(
    client: &BrowserClient,
    url: &Url,
    load: ScriptLoad,
    page: &Url,
    referer: Option<&str>,
) -> Result<Response> {
    let origin = page.origin().ascii_serialization();
    let (kind, supplied): (RequestKind, &[(&str, Option<&str>)]) = match load {
        ScriptLoad::Classic => (RequestKind::Script, &[("referer", referer)]),
        ScriptLoad::Anonymous => (
            RequestKind::CorsScript,
            &[("origin", Some(origin.as_str())), ("referer", referer)],
        ),
    };
    // Follow the redirect manually when the browser uses a separate header order for redirected
    // scripts.
    let reorders_redirect = client.orders(RequestKind::ScriptRedirect);
    let mut request = decode::preserve_encoding(client.http.get(url.as_str()));
    if reorders_redirect {
        request = request.redirect(Policy::none());
    }
    let response = client.send(request, kind, supplied).await?;
    if !reorders_redirect || !response.status().is_redirection() {
        return Ok(response.error_for_status()?);
    }
    let location = response
        .headers()
        .get(LOCATION)
        .context("the loader's redirect has no location")?;
    let target = url.join(location.to_str()?)?;
    let redirected = match load {
        ScriptLoad::Classic => RequestKind::ScriptRedirect,
        // No redirected CORS load has been observed, so preserve its original order.
        ScriptLoad::Anonymous => kind,
    };
    let request = decode::preserve_encoding(client.http.get(target.as_str()));
    Ok(client
        .send(request, redirected, supplied)
        .await?
        .error_for_status()?)
}

/// The iframe's XHR of a challenge's encoded body to `post_url`. The response
/// is returned intact, so callers can read Cloudflare's error body too.
pub async fn post_challenge(
    client: &BrowserClient,
    iframe: &Iframe,
    post_url: &Url,
    cf_chl: &str,
    encoded_body: String,
) -> Result<Response> {
    let referer = iframe_referrer(client, iframe);
    encoded_post(
        client,
        RequestKind::ChallengePost,
        &iframe.url,
        &referer,
        post_url,
        cf_chl,
        encoded_body,
    )
    .await
    .context("sending the challenge POST")
}

/// Loads an image in the iframe document as an `<img>` element would.
pub async fn fetch_image(client: &BrowserClient, iframe: &Iframe, url: &Url) -> Result<Response> {
    let request = decode::preserve_encoding(client.http.get(url.as_str()));
    let referer = iframe_referrer(client, iframe);
    let supplied = [("referer", Some(referer.as_str()))];
    client
        .send(request, RequestKind::Image, &supplied)
        .await
        .context("loading a challenge image")
}

/// Returns the iframe request's referrer. WebKit exposes only the iframe URL's origin.
fn iframe_referrer(client: &BrowserClient, iframe: &Iframe) -> String {
    match client.engine {
        Engine::Chromium => iframe.url.to_string(),
        Engine::WebKit => referrer::origin_referrer(&iframe.url),
    }
}

/// Worker fetch options that affect request headers and cookies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchOptions {
    /// `{cache: "no-cache"}`: revalidate whatever the cache holds.
    NoCache,
    /// `{cache: "no-store", credentials: "omit"}`: bypasses the cache, sends no cookies, and
    /// ignores response cookies.
    NoStoreWithoutCredentials,
}

/// Fetches from an iframe worker using its `fetch` options. Worker requests send neither a
/// referrer nor client hints.
pub async fn fetch_from_worker(
    client: &BrowserClient,
    iframe: &Iframe,
    url: &Url,
    options: FetchOptions,
) -> Result<Response> {
    let site = if url.origin() == iframe.url.origin() {
        "same-origin"
    } else {
        "same-site"
    };
    let mut request = client.http.get(url.as_str());
    let kind = match options {
        FetchOptions::NoCache => RequestKind::WorkerFetch,
        FetchOptions::NoStoreWithoutCredentials => {
            request = request.cookie_provider(Jar::default());
            RequestKind::WorkerFetchWithoutCredentials
        }
    };
    let supplied = [("sec-fetch-site", Some(site))];
    client
        .send(request, kind, &supplied)
        .await
        .context("fetching from the challenge worker")
}

/// Opens the iframe's WebSocket to `url`. Omits extension offers because the client cannot
/// decompress messages.
pub async fn open_websocket(
    client: &BrowserClient,
    iframe: &Iframe,
    url: &Url,
) -> Result<WebSocket> {
    let origin = iframe.url.origin().ascii_serialization();
    client
        .websocket(url, &[("origin", Some(&origin))])
        .await
        .context("opening the iframe's WebSocket")
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use wreq::Client;
    use wreq::header::{HeaderMap, HeaderValue, USER_AGENT};

    use super::*;
    use crate::http::Requests;

    /// A request the test server received.
    struct Received {
        /// The request line and headers, each ending in CRLF.
        head: String,
        body: String,
    }

    fn read_request(stream: &mut TcpStream) -> Received {
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        while !head.ends_with("\r\n\r\n") {
            let read = reader.read_line(&mut head).unwrap();
            assert_ne!(read, 0, "the client closed the connection mid-request");
        }
        // Leave off the blank line that ends the head.
        head.truncate(head.len() - 2);
        let length: usize = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map_or(0, |(_, value)| value.trim().parse().unwrap());
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let body = String::from_utf8(body).unwrap();
        Received { head, body }
    }

    /// Serves each of `responses` on its own loopback connection. Returns the address and a
    /// thread that returns the requests it received.
    fn serve(responses: Vec<Vec<u8>>) -> (SocketAddr, JoinHandle<Vec<Received>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut received = Vec::with_capacity(responses.len());
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                // Fail the test if a request stalls instead of waiting indefinitely.
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                received.push(read_request(&mut stream));
                stream.write_all(&response).unwrap();
            }
            received
        });
        (address, server)
    }

    #[tokio::test]
    async fn iframe_fetch_preserves_compressed_sizes_and_server_timing() {
        let html = "<html><script>window._cf_chl_opt = {};</script></html>";
        let compressed = decode::encode_body(html.as_bytes(), "gzip").unwrap();
        let encoded_length = compressed.len();
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nServer-Timing: session;dur={}\r\nConnection: close\r\n\r\n", encoded_length, html.len()).into_bytes();
        response.extend_from_slice(&compressed);
        let (address, server) = serve(vec![response]);
        let client = BrowserClient::from_http(Client::builder().gzip(true).build().unwrap());
        let iframe = fetch_iframe(
            &client,
            Url::parse(&format!("http://{address}/iframe")).unwrap(),
            None,
        )
        .await
        .unwrap();
        server.join().unwrap();
        assert_eq!(iframe.html, html);
        assert_eq!(iframe.navigation.encoded_bytes, encoded_length as u64);
        assert_eq!(iframe.navigation.decoded_bytes, html.len() as u64);
        assert_eq!(
            iframe.navigation.server_timing,
            [("session".into(), html.len() as f64)]
        );
    }

    /// Runs widget requests against a loopback server. Returns its address and lowercase
    /// request headers. The WebKit case matches captured Safari traffic: the loader redirects,
    /// and the page sends its origin as referrer when no policy is specified.
    async fn flow(client: &BrowserClient) -> (SocketAddr, Vec<String>) {
        let webkit = client.engine == Engine::WebKit;
        let body = "<script>window._cf_chl_opt = {};</script>";
        let ok = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut responses = vec![ok.into_bytes(); 6];
        if webkit {
            let redirect =
                b"HTTP/1.1 302 Found\r\nLocation: /b/api.js\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            responses.insert(1, redirect.to_vec());
        }
        let (address, server) = serve(responses);
        let page = Url::parse(&format!("http://{address}/page")).unwrap();
        let origin = format!("http://{address}/");
        let referer = webkit.then_some(origin.as_str());
        navigate(client, &page).await.unwrap();
        let script = page.join("/api.js").unwrap();
        fetch_script(client, &script, ScriptLoad::Classic, &page, referer)
            .await
            .unwrap();
        let iframe = fetch_iframe(client, page.join("/iframe").unwrap(), referer)
            .await
            .unwrap();
        let url = iframe.url.join("/resource").unwrap();
        post_challenge(client, &iframe, &url, "token", "body".into())
            .await
            .unwrap();
        fetch_image(client, &iframe, &url).await.unwrap();
        fetch_from_worker(client, &iframe, &url, FetchOptions::NoCache)
            .await
            .unwrap();
        let heads: Vec<String> = server
            .join()
            .unwrap()
            .into_iter()
            .map(|request| request.head.to_ascii_lowercase())
            .collect();
        (address, heads)
    }

    /// Lists header names from `heads` in order, excluding `host` and separating names with
    /// spaces.
    fn header_names(heads: &[String]) -> Vec<String> {
        let mut sent = Vec::new();
        for head in heads {
            let names: Vec<&str> = head
                .lines()
                .skip(1)
                .map(|line| line.split(':').next().unwrap())
                .filter(|name| *name != "host")
                .collect();
            sent.push(names.join(" "));
        }
        sent
    }

    /// Expected header order from the tracked iOS Safari 26.6 profile, verified against
    /// captchatest proxy traffic. Includes Safari's separate redirected-loader order.
    #[tokio::test]
    async fn webkit_requests_send_safaris_headers_in_its_order() {
        let client = BrowserClient {
            own: HeaderMap::from_iter([(USER_AGENT, HeaderValue::from_static("Mozilla/5.0"))]),
            requests: Requests::from_profile(include_str!("../../profiles/safari-26-ios.json")),
            engine: Engine::WebKit,
            ..BrowserClient::from_http(Client::new())
        };
        let (address, heads) = flow(&client).await;
        let loaded = "sec-fetch-dest user-agent accept referer sec-fetch-site sec-fetch-mode \
                      accept-language priority accept-encoding";
        let expected = [
            "sec-fetch-dest user-agent upgrade-insecure-requests accept sec-fetch-site \
             sec-fetch-mode accept-language priority accept-encoding",
            loaded,
            "accept sec-fetch-site priority sec-fetch-mode user-agent accept-language \
             sec-fetch-dest referer accept-encoding",
            loaded,
            "accept content-type sec-fetch-site origin cf-chl content-length sec-fetch-mode \
             user-agent referer sec-fetch-dest cf-chl-ra accept-language priority \
             accept-encoding",
            loaded,
            "sec-fetch-dest user-agent accept sec-fetch-site cache-control sec-fetch-mode \
             accept-language priority accept-encoding",
        ];
        assert!(heads[2].starts_with("get /b/api.js "), "{}", heads[2]);
        for head in &heads[4..6] {
            assert!(
                head.contains(&format!("referer: http://{address}/\r\n")),
                "inside the iframe, only its origin is the referrer: {head}"
            );
        }
        assert_eq!(header_names(&heads), expected);
    }

    #[tokio::test]
    async fn worker_fetches_that_omit_credentials_neither_send_nor_keep_cookies() {
        let responses = ["session=kept", "omitted=dropped", "later=1"].map(|cookie| {
            format!("HTTP/1.1 200 OK\r\nSet-Cookie: {cookie}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
        });
        let (address, server) = serve(responses.into());
        let client =
            BrowserClient::from_http(Client::builder().cookie_store(true).build().unwrap());
        let iframe = Iframe {
            url: Url::parse(&format!("http://{address}/iframe")).unwrap(),
            html: String::new(),
            navigation: ResponseMetrics::default(),
        };
        let url = iframe.url.join("/fetch").unwrap();
        // Set a same-origin cookie to check whether worker fetches send it.
        client.http.get(iframe.url.as_str()).send().await.unwrap();
        let without_credentials = FetchOptions::NoStoreWithoutCredentials;
        for options in [without_credentials, FetchOptions::NoCache] {
            fetch_from_worker(&client, &iframe, &url, options)
                .await
                .unwrap();
        }
        let received = server.join().unwrap();
        let omitted = received[1].head.to_ascii_lowercase();
        let included = received[2].head.to_ascii_lowercase();
        assert!(!omitted.contains("cookie:"), "{omitted}");
        assert!(included.contains("cookie: session=kept"), "{included}");
        assert!(!included.contains("omitted=dropped"), "{included}");
    }

    #[tokio::test]
    async fn sends_encoded_bytes_and_session_headers_without_following_redirects() {
        let (address, server) = serve(vec![
            b"HTTP/1.1 302 Found\r\nLocation: /unexpected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        ]);
        let iframe = Iframe {
            url: Url::parse(&format!("http://{address}/iframe?lang=auto")).unwrap(),
            html: String::new(),
            navigation: ResponseMetrics::default(),
        };
        let client = BrowserClient::from_http(Client::new());
        let response = post_challenge(
            &client,
            &iframe,
            &iframe.url.join("/fo/build/ray/token").unwrap(),
            "token",
            "abc+$-123".into(),
        )
        .await
        .unwrap();
        assert_eq!(response.status().as_u16(), 302);
        let Received { head, body } = server.join().unwrap().remove(0);
        assert_eq!(body, "abc+$-123");
        let headers = head.to_ascii_lowercase();
        for expected in [
            "content-type: text/plain;charset=utf-8",
            "cf-chl: token",
            "cf-chl-ra: 0",
            "content-length: 9",
            "sec-fetch-site: same-origin",
        ] {
            assert!(headers.contains(expected), "missing {expected}: {headers}");
        }
        // WebKit sends only the iframe's origin.
        assert!(headers.contains(&format!("referer: http://{address}/\r\n")));
    }
}
