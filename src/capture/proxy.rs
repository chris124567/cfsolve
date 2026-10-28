//! CONNECT proxy that intercepts TLS for selected hosts and tunnels the rest.
//!
//! Intercepted connections use per-host certificates signed by the proxy CA, serve HTTP/1.1 or
//! HTTP/2, and forward requests through the emulated browser client; WebSocket upgrades are
//! tunneled. The proxy replaces the modulus in iframe HTML and rewraps challenge POST seeds;
//! other traffic passes through unchanged.

use std::convert::Infallible;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{self, AsHeaderName, HeaderMap};
use hyper::server::conn::{http1, http2};
use hyper::{Method, Request, Response, StatusCode, service};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use url::Url;

use super::ca::CertificateAuthority;
use super::head;
use super::rsa::{self, ProxyKey};
use super::sessions::{self, Iframe, Post, Sessions};
use super::traffic::{Connection, Traffic};
use super::upstream::{self, Stream, UpstreamProxy};
use crate::http::{self, BrowserClient, Proxied};
use crate::js::ast;
use crate::{challenge, deobfuscate};

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// The host serving Turnstile iframes and receiving their challenge POSTs.
pub const CHALLENGE_HOST: &str = "challenges.cloudflare.com";

/// Local hostname for downloading the CA certificate at [`CA_PATH`]. Supports HTTP and, after
/// the client trusts the CA, HTTPS. `GET /ssl` on the listening socket also serves the
/// certificate.
pub const CA_HOST: &str = "proxy.ca";
pub const CA_PATH: &str = "/ssl";

type ProxyResponse = Response<Full<Bytes>>;

/// Proxy serving and logging settings.
pub struct Config {
    pub listen: SocketAddr,
    /// Hostnames to intercept, lowercased, without ports.
    pub mitm_hosts: Vec<String>,
    /// The host whose challenge POSTs need rewrapping: [`CHALLENGE_HOST`] or a loopback test
    /// origin.
    pub challenge_host: String,
    /// Whether intercepted requests go upstream over TLS. Loopback tests serve plain HTTP.
    pub upstream_tls: bool,
    /// How tunnels reach the internet.
    pub upstream_proxy: UpstreamProxy,
    /// Parent directory for session captures.
    pub out_dir: PathBuf,
}

/// A running proxy with its sessions and capture logs.
pub struct CaptureProxy {
    config: Config,
    client: BrowserClient,
    acceptor: TlsAcceptor,
    ca: Arc<CertificateAuthority>,
    sessions: Arc<Sessions>,
    traffic: Mutex<Traffic>,
}

impl CaptureProxy {
    /// Creates a proxy that sends upstream requests with `client`.
    pub fn try_new(
        config: Config,
        client: BrowserClient,
        ca: CertificateAuthority,
    ) -> Result<Self> {
        let ca = Arc::new(ca);
        let mut server = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(ca.clone());
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            config,
            client,
            acceptor: TlsAcceptor::from(Arc::new(server)),
            ca,
            sessions: Arc::new(Sessions::new(ProxyKey::generate()?)),
            traffic: Mutex::default(),
        })
    }

    fn traffic(&self) -> MutexGuard<'_, Traffic> {
        self.traffic.lock().expect("the traffic log lock")
    }

    /// Listens until Ctrl-C or SIGTERM, then waits for extraction and writes session and
    /// traffic logs. A second stop request skips the wait.
    pub async fn run(self) -> Result<()> {
        let proxy = Arc::new(self);
        let listener = TcpListener::bind(proxy.config.listen)
            .await
            .with_context(|| format!("binding {}", proxy.config.listen))?;
        eprintln!("capture-proxy listening on {}", proxy.config.listen);
        let mut shutdown = pin!(shutdown_requested());
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let proxy = Arc::clone(&proxy);
                        tokio::spawn(async move {
                            if let Err(error) = proxy.serve(stream).await {
                                eprintln!("{peer}: {error:#}");
                            }
                        });
                    }
                    Err(error) => eprintln!("accepting a client: {error}"),
                },
                () = &mut shutdown => break,
            }
        }
        eprintln!("shutting down; finishing the session extractions (Ctrl-C again to skip)");
        tokio::select! {
            () = proxy.sessions.finish_extractions() => {}
            () = shutdown_requested() => eprintln!("skipped the unfinished extractions"),
        }
        eprintln!("writing the session logs");
        proxy.sessions.write_all(&proxy.config.out_dir);
        match proxy.traffic().write(&proxy.config.out_dir) {
            Ok(path) => eprintln!("traffic: {}", path.display()),
            Err(error) => eprintln!("traffic: writing the log failed: {error:#}"),
        }
        Ok(())
    }

    /// Serves one client connection. Plain HTTP serves only CA downloads so new clients can
    /// install trust. Other connections start with CONNECT.
    async fn serve(self: Arc<Self>, mut client: TcpStream) -> Result<()> {
        let head = head::read_head(&mut client).await?;
        let (method, target) = head::request_line(&head)?;
        if method != Method::CONNECT {
            let response = match ca_path(target)? {
                Some(path) => self.serve_ca(&method, &path),
                None => text_response(
                    StatusCode::BAD_REQUEST,
                    "capture-proxy: plain HTTP only serves http://proxy.ca/ssl; browse https:// sites (CONNECT) or fetch the CA there",
                ),
            };
            return write_response(&mut client, response).await;
        }
        let (host, port) = head::connect_target(target)?;
        if host == CA_HOST || self.config.mitm_hosts.contains(&host) {
            return self.serve_mitm(client, &host, port).await;
        }
        let upstream = self.config.upstream_proxy.connect(&host, port).await?;
        client.write_all(ESTABLISHED).await?;
        tunnel(client, upstream).await
    }

    /// Serves `GET /ssl` locally on the CA host over plain HTTP or TLS. Rejects other requests
    /// without contacting an upstream server.
    fn serve_ca(&self, method: &Method, path: &str) -> ProxyResponse {
        if path != CA_PATH {
            return text_response(StatusCode::NOT_FOUND, "capture-proxy: try /ssl");
        }
        if *method != Method::GET {
            return text_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "capture-proxy: only GET serves the CA download",
            );
        }
        // This content type prompts phones to offer certificate installation.
        Response::builder()
            .header(header::CONTENT_TYPE, "application/x-x509-ca-cert")
            .header(
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"capture-proxy-ca.crt\"",
            )
            .body(Full::from(self.ca.pem()))
            .expect("static headers")
    }

    /// Terminates TLS for an intercepted host, logs the connection headers, and serves
    /// requests.
    async fn serve_mitm(
        self: Arc<Self>,
        mut client: TcpStream,
        host: &str,
        port: u16,
    ) -> Result<()> {
        use tokio::io::AsyncReadExt;

        client.write_all(ESTABLISHED).await?;
        let mut read = Vec::new();
        let length = head::read_through(
            &mut client,
            &mut read,
            "the ClientHello",
            head::client_hello_length,
        )
        .await?;
        let client_hello = hex(&read[..length]);
        // Replay the ClientHello to the TLS acceptor.
        let (reader, writer) = tokio::io::split(client);
        let client = tokio::io::join(Cursor::new(read).chain(reader), writer);
        let mut tls = self
            .acceptor
            .accept(client)
            .await
            .context("TLS handshake")?;
        let mut head = head::read_head(&mut tls).await?;
        // The CA host is served here, never reached upstream.
        let scheme = if self.config.upstream_tls {
            "https"
        } else {
            "http"
        };
        let origin = (host != CA_HOST).then(|| format!("{scheme}://{host}:{port}"));
        if origin.is_some() && head::is_tunnel_request(&head) {
            let upstream = self.config.upstream_proxy.connect(host, port).await?;
            // Start a separate TLS connection upstream because the browser's connection
            // terminates here.
            let mut upstream: Box<dyn Stream> = if self.config.upstream_tls {
                Box::new(upstream::tls_connect(upstream, host).await?)
            } else {
                upstream
            };
            upstream.write_all(&head).await?;
            return tunnel(tls, upstream).await;
        }
        let (_, server_connection) = tls.get_ref();
        let alpn: Option<String> = server_connection
            .alpn_protocol()
            .map(|protocol| String::from_utf8_lossy(protocol).into_owned());
        let h2 = alpn.as_deref() == Some("h2");
        // Browsers send the first headers without waiting for server SETTINGS.
        let h2_opening = if h2 {
            let length = head::read_through(
                &mut tls,
                &mut head,
                "the HTTP/2 opening",
                head::h2_opening_length,
            )
            .await?;
            Some(hex(&head[..length]))
        } else {
            None
        };
        let connection = self.traffic().connect(Connection {
            host: host.to_owned(),
            port,
            client_hello,
            alpn,
            h2_opening,
        });
        // Replay the head and any frames read with it to hyper.
        let (reader, writer) = tokio::io::split(tls);
        let io = TokioIo::new(tokio::io::join(Cursor::new(head).chain(reader), writer));
        let service = service::service_fn(move |request| {
            let (proxy, origin) = (Arc::clone(&self), origin.clone());
            async move {
                Ok::<_, Infallible>(proxy.handle(origin.as_deref(), connection, request).await)
            }
        });
        if h2 {
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await?;
        } else {
            http1::Builder::new().serve_connection(io, service).await?;
        }
        Ok(())
    }

    /// Handles one request on `connection`, returning 502 on failure. A missing `origin`
    /// identifies a request to the local CA host.
    async fn handle(
        &self,
        origin: Option<&str>,
        connection: usize,
        request: Request<Incoming>,
    ) -> ProxyResponse {
        let Some(origin) = origin else {
            return self.serve_ca(request.method(), request.uri().path());
        };
        let path = request
            .uri()
            .path_and_query()
            .map_or("/", |path| path.as_str());
        let url = format!("{origin}{path}");
        let logged = self.traffic().request(connection, &url, &request);
        let routed = self.route(logged, &url, request).await;
        let response = routed.unwrap_or_else(|error| {
            eprintln!("{origin}: {error:#}");
            text_response(
                StatusCode::BAD_GATEWAY,
                &format!("capture-proxy: {error:#}"),
            )
        });
        self.traffic().answered(logged);
        response
    }

    /// Forwards request `logged`, rewrapping challenge POSTs and rewriting iframe GETs as
    /// needed, and keeps the bodies of challenge pages and their scripts.
    async fn route(
        &self,
        logged: usize,
        url: &str,
        request: Request<Incoming>,
    ) -> Result<ProxyResponse> {
        let (parts, body) = request.into_parts();
        let headers = end_to_end(&parts.headers);
        let body = body
            .collect()
            .await
            .context("reading the request body")?
            .to_bytes();
        if self.is_challenge_post(&parts.method, url) {
            return self.post_challenge(url, headers, body).await;
        }
        let method = parts.method;
        let mut upstream = self
            .client
            .proxy_fetch(method.clone(), url, headers, body)
            .await?;
        if let Some(kind) = kept(&method, url, &self.config.challenge_host, &upstream.headers) {
            self.traffic().keep(logged, kind, decoded_body(&upstream));
        }
        let content_type = header_value(&upstream.headers, header::CONTENT_TYPE);
        let html = content_type.to_ascii_lowercase().contains("html");
        if method == Method::GET
            && html
            && let Some(rewritten) = self.rewrite_iframe(url, &upstream)
        {
            upstream.body = Bytes::from(rewritten);
        }
        Ok(passthrough(upstream))
    }

    /// Checks for a challenge-platform `/fo/` POST on the challenge host. Requests to site
    /// paths pass through unchanged, including orchestrator POSTs: those use a script whose
    /// modulus the proxy has not replaced.
    fn is_challenge_post(&self, method: &Method, url: &str) -> bool {
        *method == Method::POST
            && Url::parse(url).is_ok_and(|url| {
                url.host_str() == Some(self.config.challenge_host.as_str())
                    && challenge::is_post_path(url.path())
            })
    }

    /// Unwraps a challenge POST's seed, rewraps it with the real modulus, and logs the payload.
    /// Passes the response through unchanged. If no session can rewrap the POST, forwards it
    /// unchanged and excludes that session from stored answers.
    async fn post_challenge(
        &self,
        url: &str,
        mut headers: HeaderMap,
        body: Bytes,
    ) -> Result<ProxyResponse> {
        let parsed = Url::parse(url).context("parsing the POST URL")?;
        let Some(session) = self.sessions.bind(&parsed) else {
            return self.forward(url, headers, body).await;
        };
        let Ok(encrypted) = std::str::from_utf8(&body) else {
            self.sessions.lock()[session].poison("the POST body is not UTF-8");
            return self.forward(url, headers, body).await;
        };
        let mut post = Post {
            url: url.to_owned(),
            cf_chl: header_value(&headers, "cf-chl"),
            encrypted_body: encrypted.to_owned(),
            ..Post::default()
        };
        let rewrapped = match self.sessions.rewrap(session, encrypted) {
            Ok(rewrapped) => rewrapped,
            Err(error) => {
                let error = format!("re-wrap failed: {error:#}");
                let response = text_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("capture-proxy: rejecting a POST that opens under no key: {error}"),
                );
                post.error = Some(error);
                self.sessions.lock()[session].record(post);
                return Ok(response);
            }
        };
        post.seed = Some(hex(&rewrapped.seed));
        post.padding = Some(rewrapped.padding);
        headers.insert(header::CONTENT_LENGTH, rewrapped.body.len().into());
        let upstream = self
            .client
            .proxy_fetch(Method::POST, url, headers, Bytes::from(rewrapped.body))
            .await
            .context("forwarding the re-wrapped POST")
            .inspect_err(|error| self.sessions.lock()[session].poison(&format!("{error:#}")))?;
        post.response_body = String::from_utf8_lossy(&decoded_body(&upstream)).into_owned();
        post.decoded_program = decode_program(&parsed, &post.response_body);
        if post.decoded_program.is_none() {
            eprintln!("{url}: the POST response did not decode; forwarding anyway");
        }
        self.sessions.lock()[session].record(post);
        Ok(passthrough(upstream))
    }

    async fn forward(&self, url: &str, headers: HeaderMap, body: Bytes) -> Result<ProxyResponse> {
        let upstream = self
            .client
            .proxy_fetch(Method::POST, url, headers, body)
            .await?;
        Ok(passthrough(upstream))
    }

    /// Replaces the modulus in an iframe response and opens its session. Returns `None` for
    /// bodies that cannot be rewritten; those pass through unchanged.
    fn rewrite_iframe(&self, url: &str, upstream: &Proxied) -> Option<Vec<u8>> {
        let encoding = header_value(&upstream.headers, header::CONTENT_ENCODING);
        let html = String::from_utf8(http::decode_body(&upstream.body, &encoding).ok()?).ok()?;
        let scanned = challenge::inline_javascript(&html).and_then(|javascript| {
            let parsed = ast::parse_javascript("iframe.js", &javascript)?;
            let strings = deobfuscate::inline_strings(&parsed.script);
            let alphabet = sessions::scan_alphabet(&parsed.script, &strings)?;
            let swapped = rsa::swap_modulus(&html, &strings, &self.sessions.proxy_key.modulus)?;
            anyhow::Ok((alphabet, swapped))
        });
        let (alphabet, (rewritten, real_modulus)) = scanned
            .inspect_err(|error| eprintln!("{url}: forwarding the original iframe: {error:#}"))
            .ok()?;
        let encoded = http::encode_body(rewritten.as_bytes(), &encoding).ok()?;
        let session = self.sessions.open(Iframe {
            url: url.to_owned(),
            real_modulus,
            scanned_alphabet: alphabet,
            upstream_encoded_bytes: upstream.body.len() as u64,
            upstream_decoded_bytes: html.len() as u64,
            observed_encoded_bytes: encoded.len() as u64,
            // Replacement preserves every decoded byte offset.
            observed_decoded_bytes: html.len() as u64,
            original: html,
            rewritten,
        });
        eprintln!("{url}: rewrote the modulus (session {session})");
        Some(encoded)
    }
}

/// Identifies response bodies needed to reconstruct a challenge page's widget without network
/// access. Orchestrator programs stay masked with the ray identifier from their URL.
fn kept(
    method: &Method,
    url: &str,
    challenge_host: &str,
    headers: &HeaderMap,
) -> Option<&'static str> {
    let url = Url::parse(url).ok()?;
    let path = url.path();
    let platform = path.starts_with("/cdn-cgi/challenge-platform/");
    let on_challenge_host = url.host_str() == Some(challenge_host);
    let challenged = header_value(headers, "cf-mitigated") == "challenge";
    match *method {
        // A form POST to a challenged site is answered with a challenge page too.
        _ if challenged => Some("challenge-page.html"),
        Method::GET if platform && path.contains("/orchestrate/") => Some("orchestrator.js"),
        Method::GET if on_challenge_host && path.ends_with("/api.js") => Some("api.js"),
        Method::POST if !on_challenge_host && challenge::is_post_path(path) => {
            Some("orchestrator-response.txt")
        }
        _ => None,
    }
}

/// Waits for Ctrl-C or SIGTERM so the proxy can write logs before exiting.
async fn shutdown_requested() {
    use tokio::signal::unix::{self, SignalKind};

    let mut terminate = unix::signal(SignalKind::terminate()).expect("watching for SIGTERM");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

/// Extracts the CA download path from a plain HTTP target. Origin-form targets address the
/// listen socket; absolute-form targets must name the CA host. Returns `None` for other hosts.
fn ca_path(target: &str) -> Result<Option<String>> {
    if target.starts_with('/') {
        let path = target.split(['?', '#']).next().unwrap_or(target);
        return Ok(Some(path.to_owned()));
    }
    let url = Url::parse(target).context("parsing the plain-HTTP target")?;
    let ca_host = url
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(CA_HOST));
    Ok(ca_host.then(|| url.path().to_owned()))
}

/// Writes `response` to a plain HTTP connection that closes afterward.
async fn write_response(client: &mut TcpStream, response: ProxyResponse) -> Result<()> {
    let (parts, body) = response.into_parts();
    let Ok(body) = body.collect().await;
    let body = body.to_bytes();
    let headers: String = parts
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {}\r\n", http::header_text(value)))
        .collect();
    let head = format!(
        "HTTP/1.1 {}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        parts.status,
        body.len()
    );
    client.write_all(head.as_bytes()).await?;
    client.write_all(&body).await?;
    Ok(())
}

async fn tunnel(
    mut client: impl AsyncRead + AsyncWrite + Unpin,
    mut upstream: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<()> {
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .context("tunneling")?;
    Ok(())
}

/// Copies headers in order, excluding `host` and hop-by-hop headers. The URL supplies the host,
/// and each connection supplies its own hop-by-hop headers. Removing entries from the original
/// map would change their order.
fn end_to_end(headers: &HeaderMap) -> HeaderMap {
    headers
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
                    | "content-length"
                    | "host"
            )
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Builds an upstream response for the browser, letting hyper set its length.
fn passthrough(upstream: Proxied) -> ProxyResponse {
    let mut response = Response::new(Full::new(upstream.body));
    *response.status_mut() = upstream.status;
    *response.headers_mut() = end_to_end(&upstream.headers);
    response
}

fn text_response(status: StatusCode, text: &str) -> ProxyResponse {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain;charset=UTF-8")
        .body(Full::from(text.to_owned()))
        .expect("static headers")
}

/// Returns the text of header `name`, or an empty string if it is absent.
fn header_value(headers: &HeaderMap, name: impl AsHeaderName) -> String {
    headers.get(name).map(http::header_text).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Undoes a response's content encoding, or returns its wire bytes if that fails.
fn decoded_body(response: &Proxied) -> Vec<u8> {
    let encoding = header_value(&response.headers, header::CONTENT_ENCODING);
    http::decode_body(&response.body, &encoding).unwrap_or_else(|_| response.body.to_vec())
}

/// Unmasks the challenge POST response for `url`, if the result is valid base64 text.
fn decode_program(url: &Url, response_body: &str) -> Option<String> {
    use base64::Engine;

    let ray = challenge::ray(url).ok()?;
    let program = challenge::decode_response(response_body.as_bytes(), ray).ok()?;
    String::from_utf8(program)
        .ok()
        .filter(|program| STANDARD.decode(program).is_ok())
}

#[cfg(test)]
mod tests;
