//! Tests the proxy over loopback with a fake origin and a TLS client that trusts the proxy CA.
//! Checks iframe rewriting, seed rewrapping, and capture logs.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use super::{CA_HOST, CA_PATH, CaptureProxy, Config};
use crate::capture::rsa::ProxyKey;
use crate::capture::{CertificateAuthority, UpstreamProxy, head};
use crate::challenge::codec::{self, Codec, KEY_LENGTH, SEED_LENGTH};
use crate::fingerprint::Transport;
use crate::http;
use crate::js::JsObject;

const ALPHABET: &str = "BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/A";
const SECRET: [u8; KEY_LENGTH] = *b"0123456789abcdef";

/// Builds a fake iframe with a modulus, an alphabet literal for the fast scan, and the marker
/// required by `inline_javascript`.
fn iframe_html(modulus_hex: &str) -> String {
    format!(
        "<html><body><script>\nvar _cf_chl_opt = {{}};\nvar alphabet = \"{ALPHABET}\";\nvar n = BigInt(\"0x{modulus_hex}\");\n</script></body></html>"
    )
}

/// A proxy serving loopback connections, and a TLS client that trusts its CA.
struct Loopback {
    proxy: Arc<CaptureProxy>,
    address: SocketAddr,
    tls: Arc<ClientConfig>,
}

impl Loopback {
    /// Starts a proxy intercepting `mitm_hosts`, with `localhost` as the challenge host and the
    /// tracked iOS Safari 26 profile's client.
    async fn start(mitm_hosts: Vec<String>) -> Self {
        let profile = Path::new("profiles/safari-26-ios.json");
        let transport = Transport::read(profile).unwrap();
        let client = transport.client(None).unwrap();
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            mitm_hosts,
            challenge_host: "localhost".to_owned(),
            upstream_tls: false,
            upstream_proxy: UpstreamProxy::Direct,
            out_dir: std::env::temp_dir().join(format!("capture-proxy-{}", std::process::id())),
        };
        let ca = CertificateAuthority::generate().unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.cert_der().to_vec()))
            .unwrap();
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let proxy = Arc::new(CaptureProxy::try_new(config, client, ca).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serving = Arc::clone(&proxy);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(Arc::clone(&serving).serve(stream));
            }
        });
        Self {
            proxy,
            address,
            tls: Arc::new(tls),
        }
    }

    /// Sends `request` over TLS through a CONNECT tunnel to `authority`.
    async fn tls(&self, authority: &str, request: &str) -> (String, Vec<u8>) {
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        let connect = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        let (head, _) = exchange(&mut stream, &connect).await;
        assert!(head.contains(" 200 "), "CONNECT refused");
        let host = authority.split(':').next().unwrap();
        let name = ServerName::try_from(host.to_owned()).unwrap();
        let mut tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, stream)
            .await
            .unwrap();
        exchange(&mut tls, request).await
    }
}

/// Reads one HTTP message. Returns the headers without the final blank line, followed by the
/// body of the length specified by `content-length`.
async fn read_message(stream: &mut (impl AsyncRead + Unpin)) -> (String, Vec<u8>) {
    let mut head = head::read_head(stream).await.unwrap();
    let end = head.windows(4).position(|window| window == b"\r\n\r\n");
    let mut body = head.split_off(end.unwrap() + 4);
    head.truncate(head.len() - 4);
    let head = String::from_utf8(head).unwrap();
    let mut length = 0;
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    assert!(body.len() <= length, "the head's read ran past the body");
    let start = body.len();
    body.resize(length, 0);
    stream.read_exact(&mut body[start..]).await.unwrap();
    (head, body)
}

async fn exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    request: &str,
) -> (String, Vec<u8>) {
    stream.write_all(request.as_bytes()).await.unwrap();
    read_message(stream).await
}

/// Builds the fake upstream's POST response: a program for ray `RAY123`, masked as the iframe
/// expects before calling the program runner.
fn masked_response() -> String {
    let mask = b"RAY123_0".iter().fold(32_u8, |a, b| a ^ b);
    let program = STANDARD.encode(b"hello-program");
    let masked: Vec<_> = program
        .bytes()
        .enumerate()
        .map(|(index, byte)| ((usize::from(byte) + usize::from(mask) + index % 65535) % 255) as u8)
        .collect();
    STANDARD.encode(masked)
}

/// Runs a fake origin. `/iframe` serves HTML, `/iframe-gzip` serves compressed HTML, and POSTs
/// are recorded and answered with a compressed masked program.
async fn run_upstream(listener: TcpListener, posts: Arc<Mutex<Vec<String>>>, html: String) {
    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (head, body) = read_message(&mut stream).await;
        let request = head.lines().next().unwrap();
        let (encoding, body) = if request.starts_with("GET /iframe-gzip") {
            ("gzip", http::encode_body(html.as_bytes(), "gzip").unwrap())
        } else if request.starts_with("GET /iframe") {
            ("identity", html.clone().into_bytes())
        } else if request.starts_with("POST ") {
            posts.lock().unwrap().push(String::from_utf8(body).unwrap());
            let masked = http::encode_body(masked_response().as_bytes(), "gzip").unwrap();
            ("gzip", masked)
        } else {
            panic!("unexpected upstream request: {request}");
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
    }
}

/// Tests iframe rewriting for plain and compressed responses, challenge POST rewrapping, and
/// the resulting capture log over loopback.
#[tokio::test]
async fn mitm_rewrites_iframes_and_rewraps_posts() {
    let real = ProxyKey::generate().unwrap();
    let html = iframe_html(&real.modulus.to_str_radix(16));
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let host = format!("localhost:{upstream_port}");
    let posts = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(run_upstream(upstream, Arc::clone(&posts), html.clone()));
    let loopback = Loopback::start(vec!["localhost".to_owned()]).await;
    let proxy = &loopback.proxy;
    let proxy_modulus = proxy.sessions.proxy_key.modulus.clone();

    // A plain iframe comes back with the proxy modulus in place of the real one.
    let get = format!("GET /iframe HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let (head, body) = loopback.tls(&host, &get).await;
    assert!(head.contains(" 200 "), "{head}");
    let rewritten = String::from_utf8(body).unwrap();
    assert_eq!(rewritten, iframe_html(&proxy_modulus.to_str_radix(16)));

    // The browser encrypts the seed with the proxy modulus. The proxy forwards the body the
    // encoder would have built under the real modulus. This POST binds the ray to the first
    // session before the next GET opens another session.
    let mut seed = [42; SEED_LENGTH];
    seed[0] = codec::SEED_MARKER;
    let payload: JsObject =
        serde_json::from_value(json!({"1": {"a": [1, 2, {"b": "x"}]}, "counter": 39})).unwrap();
    let encode = |modulus| {
        let encoder = Codec::try_new(ALPHABET, modulus, SECRET).unwrap();
        encoder.encode(&payload, seed)
    };
    let browser_body = encode(proxy_modulus);
    let post_path = "/cdn-cgi/challenge-platform/h/g/fo/sess/RAY123/tok456";
    let post_url = format!("http://{host}{post_path}");
    let post = format!(
        "POST {post_path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/plain;charset=UTF-8\r\ncf-chl: tok456\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{browser_body}",
        browser_body.len()
    );
    let (head, response) = loopback.tls(&host, &post).await;
    assert!(head.contains(" 200 "), "{head}");
    assert_eq!(*posts.lock().unwrap(), [encode(real.modulus.clone())]);
    // The encoded response goes back untouched.
    assert!(head.contains("content-encoding: gzip"), "{head}");
    let decoded = http::decode_body(&response, "gzip").unwrap();
    assert_eq!(decoded, masked_response().as_bytes());

    // A gzipped iframe decodes to the same rewrite on the way out.
    let get = format!(
        "GET /iframe-gzip HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
    );
    let (head, body) = loopback.tls(&host, &get).await;
    assert!(head.contains("content-encoding: gzip"), "{head}");
    let decoded = http::decode_body(&body, "gzip").unwrap();
    assert_eq!(decoded, rewritten.as_bytes());

    // A site's own `/fo/` path must pass through unchanged. Treating it as a challenge POST
    // would bind the unbound gzip session and fail to decrypt it.
    let plain = format!(
        "POST /site/fo/sess/RAY456/tok789 HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nplain"
    );
    let (head, _) = loopback.tls(&host, &plain).await;
    assert!(head.contains(" 200 "), "{head}");
    assert_eq!(posts.lock().unwrap()[1], "plain");

    // The session log uses the format expected by `build_profile`, including the decoded
    // response body.
    proxy.sessions.finish_extractions().await;
    let out = &proxy.config.out_dir;
    proxy.sessions.write_all(out);
    let session = out.join("sessions/session-0000");
    let read_text = |name: &str| std::fs::read_to_string(session.join(name)).unwrap();
    let read_json = |name: &str| -> Value { serde_json::from_str(&read_text(name)).unwrap() };
    let capture = read_json("capture.json");
    let logged = json!({
        "url": post_url, "cfChl": "tok456", "seed": super::hex(&seed),
        "padding": capture["posts"][0]["padding"], "error": null,
        "responseBody": masked_response(),
    });
    assert_eq!(
        capture,
        json!({"iframeHtml": html, "posts": [logged], "payloads": []})
    );
    let program = &read_json("session.json")["posts"][0]["decodedProgram"];
    assert_eq!(*program, STANDARD.encode(b"hello-program"));
    assert_eq!(read_text("original.html"), html);
    assert_eq!(read_text("rewritten.html"), rewritten);

    // The traffic log records each connection's ClientHello and each request's headers in their
    // original order.
    let path = proxy.traffic().write(out).unwrap();
    let traffic: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let connections = traffic["connections"].as_array().unwrap();
    assert_eq!(connections.len(), 4);
    for connection in connections {
        let hello = connection["clientHello"].as_str().unwrap();
        let is_client_hello = hello.starts_with("16030") && hello[10..].starts_with("01");
        assert!(is_client_hello, "{hello}");
        let expected = json!({
            "host": "localhost", "port": upstream_port, "clientHello": hello,
            "alpn": null, "h2Opening": null,
        });
        assert_eq!(*connection, expected);
    }
    assert_eq!(traffic["requests"].as_array().unwrap().len(), 4);
    let post = &traffic["requests"][1];
    assert!(post["receivedMs"].as_i64().unwrap() <= post["answeredMs"].as_i64().unwrap());
    let expected = json!({
        "connection": 1, "method": "POST", "url": post_url, "version": "HTTP/1.1",
        "headers": [
            ["host", host], ["content-type", "text/plain;charset=UTF-8"], ["cf-chl", "tok456"],
            ["content-length", browser_body.len().to_string()], ["connection", "close"],
        ],
        "receivedMs": post["receivedMs"], "answeredMs": post["answeredMs"],
    });
    assert_eq!(*post, expected);

    std::fs::remove_dir_all(out).unwrap();
}

/// Checks CA downloads over plain HTTP before the client trusts the CA, for absolute and origin
/// request targets, and over intercepted TLS after it does.
#[tokio::test]
async fn serves_the_ca_download() {
    let loopback = Loopback::start(vec![]).await;
    let cases = [
        (false, format!("GET http://{CA_HOST}{CA_PATH}"), " 200 "),
        (false, format!("GET {CA_PATH}"), " 200 "),
        (false, format!("GET http://{CA_HOST}/other"), " 404 "),
        (false, "GET http://example.com/".to_owned(), " 400 "),
        (false, format!("POST http://{CA_HOST}{CA_PATH}"), " 405 "),
        (true, format!("GET {CA_PATH}"), " 200 "),
        (true, "GET /other".to_owned(), " 404 "),
    ];
    for (tls, line, status) in cases {
        let request = format!(
            "{line} HTTP/1.1\r\nHost: {CA_HOST}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (head, body) = if tls {
            loopback.tls(&format!("{CA_HOST}:443"), &request).await
        } else {
            let mut stream = TcpStream::connect(loopback.address).await.unwrap();
            exchange(&mut stream, &request).await
        };
        assert!(head.contains(status), "{line}: {head}");
        if status == " 200 " {
            assert!(head.contains("application/x-x509-ca-cert"), "{head}");
            assert_eq!(body, loopback.proxy.ca.pem().as_bytes());
        }
    }
}

/// Checks that saved bodies include only challenge pages, orchestrator scripts and programs,
/// and the loader.
#[test]
fn keeps_what_rebuilds_a_challenge_page() {
    use hyper::Method;
    use hyper::header::HeaderMap;

    let none = HeaderMap::new();
    let mut challenged = HeaderMap::new();
    challenged.insert("cf-mitigated", "challenge".parse().unwrap());
    let page = "https://example.com/login";
    let orchestrator = "https://example.com/cdn-cgi/challenge-platform/h/b/orchestrate/v1?ray=a";
    let program = "https://example.com/cdn-cgi/challenge-platform/h/b/fo/1:2:x/a/tok";
    let iframe_post = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/fo/1:2/a/t";
    let loader = "https://challenges.cloudflare.com/turnstile/v0/b/d2d3/api.js?render=explicit";
    for (method, url, headers, expected) in [
        (Method::GET, page, &challenged, Some("challenge-page.html")),
        (Method::POST, page, &challenged, Some("challenge-page.html")),
        (Method::GET, page, &none, None),
        (Method::GET, orchestrator, &none, Some("orchestrator.js")),
        (
            Method::POST,
            program,
            &none,
            Some("orchestrator-response.txt"),
        ),
        // The challenge host's own POSTs are logged per session instead.
        (Method::POST, iframe_post, &none, None),
        (Method::GET, loader, &none, Some("api.js")),
    ] {
        let kept = super::kept(&method, url, "challenges.cloudflare.com", headers);
        assert_eq!(kept, expected, "{method} {url}");
    }
}

/// Blind tunnels carry bytes both ways.
#[tokio::test]
async fn untunneled_hosts_pass_through() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let (mut reader, mut writer) = stream.split();
        tokio::io::copy(&mut reader, &mut writer).await.unwrap();
    });
    let loopback = Loopback::start(vec![]).await;
    let mut stream = TcpStream::connect(loopback.address).await.unwrap();
    let connect = format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: x\r\n\r\n");
    let (head, _) = exchange(&mut stream, &connect).await;
    assert!(head.contains(" 200 "));
    stream.write_all(b"through the tunnel").await.unwrap();
    let mut echo = [0; 18];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"through the tunnel");
}
