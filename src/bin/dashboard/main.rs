//! Web dashboard for interactive Cloudflare challenge solving.
//!
//! Provides a browser UI for Turnstile and challenge-page solving,
//! inspects execution steps, tests custom browser profiles, and records session history.

use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use cfsolve::http::BrowserClient;
use cfsolve::{Browser, Options, Outcome, PageSource, Sink, Turnstile, Widget};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

const DASHBOARD_HTML: &str = include_str!("index.html");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolveRecord {
    pub id: String,
    pub timestamp: String,
    pub url: String,
    pub sitekey: Option<String>,
    pub success: bool,
    pub is_clearance: bool,
    pub token: Option<String>,
    pub elapsed_ms: u64,
    pub error: Option<String>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Deserialize)]
pub struct SolveRequest {
    pub page_url: String,
    pub sitekey: Option<String>,
    pub action: Option<String>,
    pub cdata: Option<String>,
    pub proxy: Option<String>,
    pub fingerprint: Option<String>,
    pub custom_fingerprint_json: Option<String>,
    pub blank_page: Option<bool>,
    pub keep_artifacts: Option<bool>,
}

struct MemorySink {
    start: Instant,
    logs: Arc<Mutex<Vec<String>>>,
    artifacts_dir: Option<PathBuf>,
}

impl Sink for MemorySink {
    fn artifact(&self, name: &str, contents: &[u8]) -> Result<()> {
        if let Some(dir) = &self.artifacts_dir {
            let path = dir.join(name);
            let _ = std::fs::write(&path, contents);
        }
        Ok(())
    }

    fn progress(&self, message: &str) {
        if let Ok(mut list) = self.logs.lock() {
            let elapsed = self.start.elapsed().as_secs_f64();
            list.push(format!("[+{elapsed:5.2}s] {message}"));
        }
    }
}

pub struct AppState {
    pub history: Arc<RwLock<Vec<SolveRecord>>>,
    pub profiles_dir: PathBuf,
    pub persistent_client: Arc<tokio::sync::Mutex<Option<BrowserClient>>>,
}

fn full_body(text: impl Into<Bytes>) -> BoxBody<Bytes, Infallible> {
    Full::new(text.into()).boxed()
}

fn json_response<T: Serialize>(status: StatusCode, data: &T) -> Response<BoxBody<Bytes, Infallible>> {
    let json_bytes = serde_json::to_vec(data).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::new(full_body(json_bytes));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn html_response(html: &'static str) -> Response<BoxBody<Bytes, Infallible>> {
    let mut resp = Response::new(full_body(html));
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    resp
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method, path.as_str()) {
        (Method::GET, "/") => Ok(html_response(DASHBOARD_HTML)),
        (Method::GET, "/api/history") => {
            let history = state.history.read().await;
            #[derive(Serialize)]
            struct HistoryResponse<'a> {
                history: &'a [SolveRecord],
            }
            Ok(json_response(StatusCode::OK, &HistoryResponse { history: &history }))
        }
        (Method::GET, "/api/status") => {
            #[derive(Serialize)]
            struct StatusResponse<'a> {
                arch: &'a str,
                os: &'a str,
                online: bool,
                version: &'a str,
            }
            Ok(json_response(
                StatusCode::OK,
                &StatusResponse {
                    arch: std::env::consts::ARCH,
                    os: std::env::consts::OS,
                    online: true,
                    version: env!("CARGO_PKG_VERSION"),
                },
            ))
        }
        (Method::GET, "/api/profiles") => {
            let mut profiles = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&state.profiles_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "json") {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            profiles.push(name.to_string());
                        }
                    }
                }
            }
            if profiles.is_empty() {
                profiles.push("safari-26-ios.json".to_string());
            }
            #[derive(Serialize)]
            struct ProfilesResponse {
                profiles: Vec<String>,
            }
            Ok(json_response(StatusCode::OK, &ProfilesResponse { profiles }))
        }
        (Method::POST, "/api/solve") => {
            let body_bytes = match req.into_body().collect().await {
                Ok(b) => b.to_bytes(),
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({ "error": format!("Failed to read request body: {e}") }),
                    ));
                }
            };

            let req_data: SolveRequest = match serde_json::from_slice(&body_bytes) {
                Ok(d) => d,
                Err(e) => {
                    return Ok(json_response(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({ "error": format!("Invalid JSON request: {e}") }),
                    ));
                }
            };

            let result = solve_challenge(req_data, state.clone()).await;
            Ok(result)
        }
        _ => {
            let mut resp = Response::new(full_body("Not Found"));
            *resp.status_mut() = StatusCode::NOT_FOUND;
            Ok(resp)
        }
    }
}

async fn solve_challenge(req: SolveRequest, state: Arc<AppState>) -> Response<BoxBody<Bytes, Infallible>> {
    let start_time = Instant::now();
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let id = format!("solve_{}", chrono::Utc::now().timestamp_millis());

    let blank_page = req.blank_page.unwrap_or(false);
    if blank_page && req.sitekey.as_deref().unwrap_or("").trim().is_empty() {
        return json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({
                "success": false,
                "error": "Blank Page Mode requires an explicit Sitekey.",
                "elapsed_ms": 0,
                "token": null
            }),
        );
    }

    // Resolve fingerprint path
    let mut temp_file = None;
    let fp_path = if let Some(custom_json) = req.custom_fingerprint_json.as_deref().filter(|s| !s.trim().is_empty()) {
        match serde_json::from_str::<serde_json::Value>(custom_json) {
            Ok(v) => {
                let temp_path = std::env::temp_dir().join(format!("custom_fp_{}.json", id));
                if let Err(e) = std::fs::write(&temp_path, serde_json::to_vec_pretty(&v).unwrap()) {
                    return json_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &serde_json::json!({ "error": format!("Failed to write temp fingerprint: {e}") }),
                    );
                }
                temp_file = Some(temp_path.clone());
                temp_path
            }
            Err(e) => {
                return json_response(
                    StatusCode::BAD_REQUEST,
                    &serde_json::json!({ "error": format!("Invalid custom fingerprint JSON: {e}") }),
                );
            }
        }
    } else {
        let profile_name = req.fingerprint.as_deref().unwrap_or("safari-26-ios.json");
        state.profiles_dir.join(profile_name)
    };

    if !fp_path.exists() {
        return json_response(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({ "error": format!("Fingerprint file not found: {}", fp_path.display()) }),
        );
    }

    let browser = match Browser::read(&fp_path) {
        Ok(b) => b,
        Err(e) => {
            if let Some(t) = temp_file {
                let _ = std::fs::remove_file(t);
            }
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": format!("Failed to load browser fingerprint: {e}") }),
            );
        }
    };

    let keep_artifacts = req.keep_artifacts.unwrap_or(false);
    let run_dir = if keep_artifacts {
        let dir = PathBuf::from("runs").join(&id);
        let _ = std::fs::create_dir_all(&dir);
        Some(dir)
    } else {
        None
    };

    let log_lines = Arc::new(Mutex::new(Vec::new()));
    let sink = MemorySink {
        start: start_time,
        logs: log_lines.clone(),
        artifacts_dir: run_dir,
    };

    let client = {
        let mut guard = state.persistent_client.lock().await;
        if req.proxy.as_deref().map(str::trim).filter(|s| !s.is_empty()).is_none() {
            if guard.is_none() {
                if let Ok(c) = browser.create_client(None) {
                    *guard = Some(c);
                }
            }
            if let Some(c) = guard.as_ref() {
                c.clear_cookies();
                Some(c.clone())
            } else {
                None
            }
        } else {
            None
        }
    };

    let options = Options {
        proxy: req.proxy.clone().filter(|s| !s.trim().is_empty()),
        sink: Some(Arc::new(sink)),
        client,
    };

    let parsed_url = match req.page_url.trim().parse::<cfsolve::Url>() {
        Ok(u) => u,
        Err(e) => {
            if let Some(t) = temp_file {
                let _ = std::fs::remove_file(t);
            }
            return json_response(
                StatusCode::BAD_REQUEST,
                &serde_json::json!({ "error": format!("Invalid target page URL: {e}") }),
            );
        }
    };

    let solve_future = async {
        if let Some(sitekey) = req.sitekey.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let widget = Widget {
                sitekey: sitekey.to_string(),
                action: req.action.filter(|s| !s.trim().is_empty()),
                cdata: req.cdata.filter(|s| !s.trim().is_empty()),
            };

            let turnstile = Turnstile {
                url: parsed_url,
                page: if blank_page {
                    PageSource::Blank
                } else {
                    PageSource::Navigate
                },
                widget: Some(widget),
            };

            let token = browser.solve_turnstile(turnstile, &options).await?;
            Ok::<Outcome, anyhow::Error>(Outcome::Token(token))
        } else {
            let outcome = browser.solve(&parsed_url, &options).await?;
            Ok(outcome)
        }
    };

    let (success, token, is_clearance, error) = match solve_future.await {
        Ok(Outcome::Token(tok)) => (true, Some(tok), false, None),
        Ok(Outcome::Cleared(cleared)) => (true, Some(format!("cf_clearance={}", cleared.clearance)), true, None),
        Err(e) => (false, None, false, Some(format!("{e:#}"))),
    };

    if let Some(t) = temp_file {
        let _ = std::fs::remove_file(t);
    }

    let elapsed_ms = start_time.elapsed().as_millis() as u64;
    let stdout_log = log_lines.lock().map(|l| l.join("\n")).unwrap_or_default();

    let record = SolveRecord {
        id,
        timestamp,
        url: req.page_url,
        sitekey: req.sitekey,
        success,
        is_clearance,
        token,
        elapsed_ms,
        error,
        stdout: stdout_log.clone(),
        stderr: String::new(),
    };

    {
        let mut hist = state.history.write().await;
        hist.insert(0, record.clone());
        if hist.len() > 100 {
            hist.pop();
        }
    }

    json_response(if success { StatusCode::OK } else { StatusCode::UNPROCESSABLE_ENTITY }, &record)
}

fn main() -> Result<()> {
    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(5000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let profiles_dir = PathBuf::from("profiles");

    let state = Arc::new(AppState {
        history: Arc::new(RwLock::new(Vec::new())),
        profiles_dir,
        persistent_client: Arc::new(tokio::sync::Mutex::new(None)),
    });

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?;

    runtime.block_on(async {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind to {addr}"))?;
        println!("======================================================");
        println!("  cfsolve native dashboard running at http://127.0.0.1:{port}");
        println!("======================================================");

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };

            let io = TokioIo::new(stream);
            let state_clone = state.clone();

            tokio::task::spawn(async move {
                let service = service_fn(move |req| {
                    let state = state_clone.clone();
                    handle_request(req, state)
                });

                if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                    eprintln!("Error serving HTTP connection: {:?}", err);
                }
            });
        }
    })
}
