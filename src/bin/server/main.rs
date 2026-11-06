use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use cfsolve::{Browser, Options, Outcome, PageSource, Sink, Turnstile, Widget};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use url::Url;

/// The solver allocates many short-lived AST and interpreter values. mimalloc handles that
/// pattern with less contention and fragmentation than the system allocator, and
/// `cfsolve::Allocator` keeps the deobfuscator's tree copies contiguous (see `arena.rs`).
#[global_allocator]
static ALLOCATOR: cfsolve::Allocator<mimalloc::MiMalloc> = cfsolve::Allocator::new(mimalloc::MiMalloc);

#[derive(Deserialize, Debug)]
struct RequestPayload {
    mode: Option<String>,
    url: Option<String>,
    domain: Option<String>,
    #[serde(alias = "siteKey")]
    sitekey: Option<String>,
    action: Option<String>,
    cdata: Option<String>,
    proxy: Option<String>,
}

#[derive(Serialize)]
struct CookieObj {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct SuccessResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clearance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookies: Option<Vec<CookieObj>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    /// Present only for cached-session responses: how many seconds until the session expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

/// Per-solve stage timings on stderr, enabled with CFSOLVE_STAGE_LOG.
struct TimedSink {
    id: u64,
    start: Instant,
}

impl Sink for TimedSink {
    fn trace_id(&self) -> Option<u64> {
        Some(self.id)
    }
    fn artifact(&self, _name: &str, _contents: &[u8]) -> Result<()> {
        Ok(())
    }
    fn progress(&self, message: &str) {
        let ms = self.start.elapsed().as_millis();
        eprintln!("[cfsolve][solve={}][+{ms:6} ms] {message}", self.id);
    }
}

fn stage_sink() -> Option<Arc<dyn Sink>> {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    std::env::var_os("CFSOLVE_STAGE_LOG").map(|_| {
        Arc::new(TimedSink {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            start: Instant::now(),
        }) as Arc<dyn Sink>
    })
}

// ══════════════════════════════════════════════════════════════════════════════
// Session cache: solved sessions keyed by domain, reusable for parallel
// requests that bypass the JS VM entirely.
// ══════════════════════════════════════════════════════════════════════════════

/// A solved session whose cookies can be reused for subsequent requests.
#[derive(Clone)]
struct CachedSession {
    /// The `cf_clearance` cookie value.
    clearance: String,
    /// All cookies the browser held after solving.
    cookies: Vec<CookieInfo>,
    /// The browser's User-Agent, needed for requests that reuse the session.
    user_agent: String,
    /// When this session was obtained. Cloudflare clearance cookies typically
    /// last 30 minutes; we default to 25 minutes to stay safe.
    created: Instant,
}

#[derive(Clone, Serialize)]
struct CookieInfo {
    name: String,
    value: String,
}

impl CachedSession {
    /// Default session lifetime: 25 minutes (Cloudflare's clearance lasts ~30m).
    const TTL: Duration = Duration::from_secs(25 * 60);

    fn is_expired(&self) -> bool {
        self.created.elapsed() > Self::TTL
    }

    fn ttl_remaining(&self) -> Duration {
        Self::TTL.saturating_sub(self.created.elapsed())
    }
}

/// Thread-safe session cache: domain → cached session.
type SessionCache = Arc<RwLock<HashMap<String, CachedSession>>>;

/// Round-robin egress proxies used when a request does not name one.
///
/// Cloudflare rate limits and risk scores are per egress IP, so a fleet behind a
/// handful of shared NAT addresses stops scaling long before CPU does.
struct ProxyPool {
    entries: Vec<String>,
    next: AtomicUsize,
}

impl ProxyPool {
    /// Reads `CFSOLVE_PROXIES` (comma/whitespace separated) and/or a proxy file.
    ///
    /// A file path passed on the command line wins over `CFSOLVE_PROXY_FILE`.
    /// Blank lines and `#` comments are ignored. Invalid entries fail startup
    /// instead of turning into per-request errors.
    fn load(command_line_file: Option<&str>) -> Result<Option<Arc<Self>>> {
        let mut entries = Vec::new();
        if let Ok(value) = std::env::var("CFSOLVE_PROXIES") {
            entries.extend(
                value
                    .split([',', ';', ' ', '\t', '\r', '\n'])
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_owned),
            );
        }
        let file = command_line_file
            .map(str::to_owned)
            .or_else(|| std::env::var("CFSOLVE_PROXY_FILE").ok());
        if let Some(path) = file {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading proxy file {path}"))?;
            entries.extend(
                text.lines()
                    .map(|line| line.split('#').next().unwrap_or_default().trim())
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned),
            );
        }
        entries.sort();
        entries.dedup();
        if entries.is_empty() {
            return Ok(None);
        }
        for entry in &entries {
            validate_proxy(entry)?;
        }
        Ok(Some(Arc::new(Self {
            entries,
            next: AtomicUsize::new(0),
        })))
    }

    fn pick(&self) -> Option<String> {
        if self.entries.is_empty() {
            return None;
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.entries.len();
        Some(self.entries[index].clone())
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn validate_proxy(proxy: &str) -> Result<()> {
    let url = Url::parse(proxy).with_context(|| format!("invalid proxy URL {proxy}"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h"),
        "unsupported proxy scheme {} in {proxy}: use http, https, socks5, or socks5h",
        url.scheme()
    );
    ensure!(url.has_host(), "proxy URL {proxy} has no host");
    Ok(())
}

/// Latency bucket boundaries in milliseconds. The last bucket is `+Inf`.
const LATENCY_BUCKETS_MS: [u64; 12] = [
    100,
    250,
    500,
    1_000,
    2_000,
    4_000,
    8_000,
    15_000,
    30_000,
    60_000,
    120_000,
    u64::MAX,
];

/// Process-wide counters exposed at `/metrics` in Prometheus text format.
#[derive(Default)]
struct Metrics {
    requests: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    rejected: AtomicU64,
    in_flight: AtomicU64,
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
    latency_buckets: [AtomicU64; LATENCY_BUCKETS_MS.len()],
    failure_build: AtomicU64,
    failure_timeout: AtomicU64,
    failure_proxy: AtomicU64,
    failure_other: AtomicU64,
}

/// Counts one solve from admission to completion and always releases `in_flight`.
struct SolveTimer<'a> {
    metrics: &'a Metrics,
    start: Instant,
    finished: bool,
}

impl<'a> SolveTimer<'a> {
    fn start(metrics: &'a Metrics) -> Self {
        metrics.requests.fetch_add(1, Ordering::Relaxed);
        metrics.in_flight.fetch_add(1, Ordering::Relaxed);
        Self {
            metrics,
            start: Instant::now(),
            finished: false,
        }
    }

    fn success(mut self) {
        self.finish();
        self.metrics.successes.fetch_add(1, Ordering::Relaxed);
    }

    fn failure(mut self, error: &str) {
        self.finish();
        self.metrics.failures.fetch_add(1, Ordering::Relaxed);
        let lower = error.to_ascii_lowercase();
        let class = if lower.contains("does not build the key transform")
            || lower.contains("initial vm program")
        {
            &self.metrics.failure_build
        } else if lower.contains("timeout")
            || lower.contains("timed out")
            || lower.contains("deadline")
        {
            &self.metrics.failure_timeout
        } else if lower.contains("proxy") || lower.contains("tunnel") || lower.contains("connect") {
            &self.metrics.failure_proxy
        } else {
            &self.metrics.failure_other
        };
        class.fetch_add(1, Ordering::Relaxed);
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let elapsed_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.metrics
            .latency_sum_ms
            .fetch_add(elapsed_ms, Ordering::Relaxed);
        self.metrics.latency_count.fetch_add(1, Ordering::Relaxed);
        let index = LATENCY_BUCKETS_MS
            .iter()
            .position(|bucket| elapsed_ms <= *bucket)
            .unwrap_or(LATENCY_BUCKETS_MS.len() - 1);
        self.metrics.latency_buckets[index].fetch_add(1, Ordering::Relaxed);
        self.metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for SolveTimer<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

impl Metrics {
    fn render(&self, concurrency: usize, proxies: usize) -> String {
        let mut out = String::new();
        out.push_str("# HELP cfsolve_requests_total Solves admitted for processing.\n");
        out.push_str("# TYPE cfsolve_requests_total counter\n");
        out.push_str(&format!(
            "cfsolve_requests_total {}\n",
            self.requests.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP cfsolve_solves_total Solves by result.\n");
        out.push_str("# TYPE cfsolve_solves_total counter\n");
        out.push_str(&format!(
            "cfsolve_solves_total{{result=\"success\"}} {}\n",
            self.successes.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "cfsolve_solves_total{{result=\"failure\"}} {}\n",
            self.failures.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "cfsolve_solves_total{{result=\"rejected\"}} {}\n",
            self.rejected.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP cfsolve_failures_total Failures by class.\n");
        out.push_str("# TYPE cfsolve_failures_total counter\n");
        for (class, counter) in [
            ("build_unsupported", &self.failure_build),
            ("timeout", &self.failure_timeout),
            ("proxy", &self.failure_proxy),
            ("other", &self.failure_other),
        ] {
            out.push_str(&format!(
                "cfsolve_failures_total{{class=\"{class}\"}} {}\n",
                counter.load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP cfsolve_in_flight Solves currently holding a worker slot.\n");
        out.push_str("# TYPE cfsolve_in_flight gauge\n");
        out.push_str(&format!(
            "cfsolve_in_flight {}\n",
            self.in_flight.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP cfsolve_worker_capacity Configured solve slots.\n");
        out.push_str("# TYPE cfsolve_worker_capacity gauge\n");
        out.push_str(&format!("cfsolve_worker_capacity {concurrency}\n"));
        out.push_str("# HELP cfsolve_proxies Configured egress proxies.\n");
        out.push_str("# TYPE cfsolve_proxies gauge\n");
        out.push_str(&format!("cfsolve_proxies {proxies}\n"));
        out.push_str("# HELP cfsolve_solve_duration_seconds End-to-end solve latency.\n");
        out.push_str("# TYPE cfsolve_solve_duration_seconds histogram\n");
        let mut cumulative = 0;
        for (boundary, bucket) in LATENCY_BUCKETS_MS.iter().zip(&self.latency_buckets) {
            cumulative += bucket.load(Ordering::Relaxed);
            let label = if *boundary == u64::MAX {
                "+Inf".to_owned()
            } else {
                format!("{:.3}", *boundary as f64 / 1000.0)
            };
            out.push_str(&format!(
                "cfsolve_solve_duration_seconds_bucket{{le=\"{label}\"}} {cumulative}\n"
            ));
        }
        out.push_str(&format!(
            "cfsolve_solve_duration_seconds_sum {:.3}\n",
            self.latency_sum_ms.load(Ordering::Relaxed) as f64 / 1000.0
        ));
        out.push_str(&format!(
            "cfsolve_solve_duration_seconds_count {}\n",
            self.latency_count.load(Ordering::Relaxed)
        ));
        out
    }
}

const MAX_SESSION_ENTRIES: usize = 4096;

struct AppState {
    browser: Arc<Browser>,
    default_proxy: Option<String>,
    proxies: Option<Arc<ProxyPool>>,
    semaphore: Arc<tokio::sync::Semaphore>,
    /// How long a request may wait for a worker slot before receiving 429.
    queue_timeout: Duration,
    max_concurrency: usize,
    metrics: Arc<Metrics>,
    /// Cache of solved sessions, keyed by domain and egress proxy.
    sessions: SessionCache,
    /// User-Agent extracted from the browser profile's transport headers.
    user_agent: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut listen_addr: SocketAddr = "127.0.0.1:8742".parse()?;
    let mut profile_path = "profiles/safari-26-ios.json".to_string();
    let mut default_proxy: Option<String> = None;
    let mut proxy_file: Option<String> = None;
    let mut max_concurrency: usize = 0;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                if let Some(val) = args.next() {
                    listen_addr = val.parse()?;
                }
            }
            "--fingerprint" | "-f" => {
                if let Some(val) = args.next() {
                    profile_path = val;
                }
            }
            "--proxy" | "-p" => {
                if let Some(val) = args.next() {
                    default_proxy = Some(val);
                }
            }
            "--proxies" => {
                if let Some(val) = args.next() {
                    proxy_file = Some(val);
                }
            }
            "--concurrency" | "-c" => {
                if let Some(val) = args.next() {
                    max_concurrency = val.parse()?;
                }
            }
            "--help" | "-h" => {
                println!(
                    "Usage: server [--listen <ip:port>] [--fingerprint <profile.json>] [--proxy <proxy_url>] [--proxies <file>] [--concurrency <num>]\n\n\
                     Environment:\n  \
                     CFSOLVE_PROXIES         comma-separated proxy URLs (round-robin)\n  \
                     CFSOLVE_PROXY_FILE      file with one proxy URL per line\n  \
                     CFSOLVE_QUEUE_TIMEOUT_SECS  max queue wait before 429 (default 15)\n  \
                     CONCURRENCY             worker slots (default: available CPUs)\n\n\
                     Concurrency is CPU-bound: use about one slot per available core. Setting it\n\
                     to 150 on a 1-vCPU dyno makes every request miss Heroku's 30s timeout."
                );
                return Ok(());
            }
            _ => {}
        }
    }

    let proxies = ProxyPool::load(proxy_file.as_deref())?;
    if max_concurrency == 0 {
        max_concurrency = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(4);
    }
    // Every slot runs a CPU-bound VM. Oversubscribing far beyond the core count
    // only increases tail latency; excess work belongs in a queue or another node.
    max_concurrency = max_concurrency.clamp(1, 512);
    let queue_timeout = std::env::var("CFSOLVE_QUEUE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(15));

    println!("Loading browser profile from: {}", profile_path);
    let browser = Arc::new(Browser::read(&profile_path)?);

    // Extract User-Agent from the browser transport for session reuse
    let user_agent = browser.user_agent().unwrap_or("Mozilla/5.0").to_string();

    let state = Arc::new(AppState {
        browser,
        default_proxy,
        proxies,
        semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrency)),
        queue_timeout,
        max_concurrency,
        metrics: Arc::new(Metrics::default()),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        user_agent,
    });

    println!(
        "Workers: {} concurrent solves, queue wait limit: {}s, proxies: {}",
        max_concurrency,
        queue_timeout.as_secs(),
        state.proxies.as_ref().map_or(0, |pool| pool.len())
    );

    // Spawn a background task to evict expired sessions every 60 seconds
    {
        let sessions = Arc::clone(&state.sessions);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut cache = sessions.write().await;
                let before = cache.len();
                cache.retain(|_, session| !session.is_expired());
                if cache.len() > MAX_SESSION_ENTRIES {
                    let excess = cache.len() - MAX_SESSION_ENTRIES;
                    let stale: Vec<String> = cache.keys().take(excess).cloned().collect();
                    for key in stale {
                        cache.remove(&key);
                    }
                }
                let evicted = before - cache.len();
                if evicted > 0 {
                    println!(
                        "Session cache: evicted {evicted} expired session(s), {} active",
                        cache.len()
                    );
                }
            }
        });
    }

    let listener = TcpListener::bind(listen_addr).await?;
    println!("cfsolve API server listening on http://{}", listen_addr);
    println!(
        "Ready to accept requests on http://{}/cloudflare",
        listen_addr
    );
    println!();
    println!("New endpoints for two-phase optimization:");
    println!("  POST /session/solve   — Phase 1: solve & cache the session");
    println!("  GET  /session/<domain> — Get cached session for a domain");
    println!("  GET  /sessions        — List all cached sessions");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let state = Arc::clone(&state);
                async move { handle_request(req, state).await }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Connection error: {:?}", err);
            }
        });
    }
}

/// Picks the proxy for one solve: request value, then round-robin pool, then default.
fn select_proxy(state: &AppState, requested: Option<String>) -> Option<String> {
    requested
        .filter(|proxy| !proxy.trim().is_empty())
        .or_else(|| state.proxies.as_ref().and_then(|pool| pool.pick()))
        .or_else(|| state.default_proxy.clone())
}

/// Clearance is scoped to an egress IP, so cached sessions include the proxy.
fn session_key(domain: &str, proxy: Option<&str>) -> String {
    match proxy {
        Some(proxy) => format!("{domain}|{proxy}"),
        None => domain.to_owned(),
    }
}

/// Finds an exact key, or the most recent cached session for `domain` on any proxy.
fn find_session<'a>(
    sessions: &'a HashMap<String, CachedSession>,
    domain: &str,
) -> Option<(&'a String, &'a CachedSession)> {
    sessions.get_key_value(domain).or_else(|| {
        sessions.iter().find(|(key, _)| {
            key.strip_prefix(domain)
                .is_some_and(|suffix| suffix.starts_with('|'))
        })
    })
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();

    // ── CORS preflight ────────────────────────────────────────────────────
    if parts.method == Method::OPTIONS {
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .header("Access-Control-Allow-Headers", "*")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    // ── Prometheus metrics ────────────────────────────────────────────────
    if parts.method == Method::GET && path == "/metrics" {
        let text = state.metrics.render(
            state.max_concurrency,
            state.proxies.as_ref().map_or(0, |pool| pool.len()),
        );
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            .body(Full::new(Bytes::from(text)))
            .unwrap());
    }

    // ── Health check ──────────────────────────────────────────────────────
    if parts.method == Method::GET && (path == "/" || path == "/health") {
        let sessions = state.sessions.read().await;
        let json = serde_json::json!({
            "status": "ok",
            "service": "cfsolve-api",
            "version": "0.3.0",
            "cached_sessions": sessions.len(),
            "workers": state.max_concurrency,
            "available_workers": state.semaphore.available_permits(),
            "in_flight": state.metrics.in_flight.load(Ordering::Relaxed),
            "queue_timeout_seconds": state.queue_timeout.as_secs(),
            "proxies": state.proxies.as_ref().map_or(0, |pool| pool.len())
        });
        return Ok(json_response(StatusCode::OK, &json));
    }

    // ── List cached sessions ──────────────────────────────────────────────
    if parts.method == Method::GET && path == "/sessions" {
        let sessions = state.sessions.read().await;
        let list: Vec<serde_json::Value> = sessions
            .iter()
            .map(|(domain, session)| {
                serde_json::json!({
                    "domain": domain,
                    "clearance": session.clearance,
                    "cookies_count": session.cookies.len(),
                    "ttl_seconds": session.ttl_remaining().as_secs(),
                    "expired": session.is_expired(),
                })
            })
            .collect();
        return Ok(json_response(
            StatusCode::OK,
            &serde_json::json!({
                "sessions": list,
                "count": list.len()
            }),
        ));
    }

    // ── Get cached session for a domain ───────────────────────────────────
    if parts.method == Method::GET && path.starts_with("/session/") && path != "/session/solve" {
        let domain = path.strip_prefix("/session/").unwrap_or("");
        let sessions = state.sessions.read().await;
        if let Some((_, session)) = find_session(&sessions, domain) {
            if session.is_expired() {
                return Ok(error_response(
                    StatusCode::GONE,
                    format!("Session for '{domain}' has expired; solve again"),
                ));
            }
            return Ok(json_response(
                StatusCode::OK,
                &SuccessResponse {
                    success: true,
                    token: None,
                    clearance: Some(session.clearance.clone()),
                    cookies: Some(
                        session
                            .cookies
                            .iter()
                            .map(|c| CookieObj {
                                name: c.name.clone(),
                                value: c.value.clone(),
                            })
                            .collect(),
                    ),
                    user_agent: Some(session.user_agent.clone()),
                    ttl_seconds: Some(session.ttl_remaining().as_secs()),
                },
            ));
        }
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            format!("No cached session for '{domain}'; POST /session/solve first"),
        ));
    }

    // ── Phase 1: Solve & cache the session ────────────────────────────────
    if parts.method == Method::POST && path == "/session/solve" {
        let whole_body = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    format!("Failed reading body: {}", e),
                ));
            }
        };

        let payload: RequestPayload = match serde_json::from_slice(&whole_body) {
            Ok(p) => p,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid JSON payload: {}", e),
                ));
            }
        };

        let target_str = payload
            .url
            .as_deref()
            .or(payload.domain.as_deref())
            .unwrap_or("");

        if target_str.is_empty() {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Missing 'url' or 'domain' field in request".to_string(),
            ));
        }

        let target_url = match Url::parse(target_str) {
            Ok(u) => u,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid URL: {}", e),
                ));
            }
        };

        let domain = target_url.host_str().unwrap_or("unknown").to_string();
        let proxy = select_proxy(&state, payload.proxy);
        let key = session_key(&domain, proxy.as_deref());

        // Check if we already have a valid cached session for this egress proxy.
        {
            let sessions = state.sessions.read().await;
            if let Some(session) = sessions.get(&key) {
                if !session.is_expired() {
                    return Ok(json_response(
                        StatusCode::OK,
                        &SuccessResponse {
                            success: true,
                            token: None,
                            clearance: Some(session.clearance.clone()),
                            cookies: Some(
                                session
                                    .cookies
                                    .iter()
                                    .map(|c| CookieObj {
                                        name: c.name.clone(),
                                        value: c.value.clone(),
                                    })
                                    .collect(),
                            ),
                            user_agent: Some(session.user_agent.clone()),
                            ttl_seconds: Some(session.ttl_remaining().as_secs()),
                        },
                    ));
                }
            }
        }

        let options = Options {
            proxy,
            sink: stage_sink(),
        };

        // Wait for a solve slot, but never past the caller's patience.
        let _permit =
            match tokio::time::timeout(state.queue_timeout, state.semaphore.acquire()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => {
                    return Ok(error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Server shutting down".to_string(),
                    ));
                }
                Err(_) => {
                    state.metrics.rejected.fetch_add(1, Ordering::Relaxed);
                    return Ok(error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        format!(
                            "Server saturated: no worker slot within {}s; retry or add a node",
                            state.queue_timeout.as_secs()
                        ),
                    ));
                }
            };

        let timer = SolveTimer::start(&state.metrics);
        let start = Instant::now();
        match state.browser.clear(&target_url, &options).await {
            Ok(cleared) => {
                let elapsed = start.elapsed();
                let cookies: Vec<CookieInfo> = cleared
                    .cookies
                    .iter()
                    .map(|c| CookieInfo {
                        name: c.name().to_string(),
                        value: c.value().to_string(),
                    })
                    .collect();

                let session = CachedSession {
                    clearance: cleared.clearance.clone(),
                    cookies: cookies.clone(),
                    user_agent: state.user_agent.clone(),
                    created: Instant::now(),
                };

                // Cache the session
                {
                    let mut sessions = state.sessions.write().await;
                    sessions.insert(key.clone(), session.clone());
                }

                println!(
                    "Session cached for '{}' (solved in {:.0?}, TTL: {}s)",
                    key,
                    elapsed,
                    CachedSession::TTL.as_secs()
                );
                timer.success();

                Ok(json_response(
                    StatusCode::OK,
                    &SuccessResponse {
                        success: true,
                        token: None,
                        clearance: Some(cleared.clearance),
                        cookies: Some(
                            cookies
                                .iter()
                                .map(|c| CookieObj {
                                    name: c.name.clone(),
                                    value: c.value.clone(),
                                })
                                .collect(),
                        ),
                        user_agent: Some(state.user_agent.clone()),
                        ttl_seconds: Some(CachedSession::TTL.as_secs()),
                    },
                ))
            }
            Err(e) => {
                timer.failure(&format!("{e:#}"));
                Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "Session solve error ({}ms): {}",
                        start.elapsed().as_millis(),
                        e
                    ),
                ))
            }
        }
    }
    // ── Original endpoints (unchanged) ────────────────────────────────────
    else if parts.method == Method::POST && (path == "/cloudflare" || path == "/solve") {
        let whole_body = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    format!("Failed reading body: {}", e),
                ));
            }
        };

        let payload: RequestPayload = match serde_json::from_slice(&whole_body) {
            Ok(p) => p,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid JSON payload: {}", e),
                ));
            }
        };

        let target_str = payload
            .url
            .as_deref()
            .or(payload.domain.as_deref())
            .unwrap_or("");

        if target_str.is_empty() {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "Missing 'url' or 'domain' field in request".to_string(),
            ));
        }

        let target_url = match Url::parse(target_str) {
            Ok(u) => u,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid URL: {}", e),
                ));
            }
        };

        let proxy = select_proxy(&state, payload.proxy);
        let options = Options {
            proxy,
            sink: stage_sink(),
        };

        // Wait for a solve slot, but never past the caller's patience.
        let _permit =
            match tokio::time::timeout(state.queue_timeout, state.semaphore.acquire()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => {
                    return Ok(error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Server shutting down".to_string(),
                    ));
                }
                Err(_) => {
                    state.metrics.rejected.fetch_add(1, Ordering::Relaxed);
                    return Ok(error_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        format!(
                            "Server saturated: no worker slot within {}s; retry or add a node",
                            state.queue_timeout.as_secs()
                        ),
                    ));
                }
            };

        let timer = SolveTimer::start(&state.metrics);
        let mode = payload.mode.as_deref().unwrap_or("auto");

        let response: Result<Response<Full<Bytes>>, Infallible> = match mode {
            "turnstile" => {
                let turnstile = Turnstile {
                    url: target_url,
                    page: if payload.sitekey.is_some() {
                        PageSource::Blank
                    } else {
                        PageSource::Navigate
                    },
                    widget: payload.sitekey.map(|key| Widget {
                        sitekey: key,
                        action: payload.action,
                        cdata: payload.cdata,
                    }),
                };

                match state.browser.solve_turnstile(turnstile, &options).await {
                    Ok(token) => {
                        timer.success();
                        Ok(json_response(
                            StatusCode::OK,
                            &SuccessResponse {
                                success: true,
                                token: Some(token),
                                clearance: None,
                                cookies: None,
                                user_agent: None,
                                ttl_seconds: None,
                            },
                        ))
                    }
                    Err(e) => {
                        let message = format!("Turnstile solve error: {:#}", e);
                        timer.failure(&message);
                        Ok(error_response(StatusCode::BAD_GATEWAY, message))
                    }
                }
            }
            "iuam" | "iaum" => match state.browser.clear(&target_url, &options).await {
                Ok(cleared) => {
                    let cookies = cleared
                        .cookies
                        .into_iter()
                        .map(|c| CookieObj {
                            name: c.name().to_string(),
                            value: c.value().to_string(),
                        })
                        .collect();
                    timer.success();
                    Ok(json_response(
                        StatusCode::OK,
                        &SuccessResponse {
                            success: true,
                            token: None,
                            clearance: Some(cleared.clearance),
                            cookies: Some(cookies),
                            user_agent: None,
                            ttl_seconds: None,
                        },
                    ))
                }
                Err(e) => {
                    let message = format!("IUAM clear error: {:#}", e);
                    timer.failure(&message);
                    Ok(error_response(StatusCode::BAD_GATEWAY, message))
                }
            },
            _ => match state.browser.solve(&target_url, &options).await {
                Ok(outcome) => match outcome {
                    Outcome::Token(token) => {
                        timer.success();
                        Ok(json_response(
                            StatusCode::OK,
                            &SuccessResponse {
                                success: true,
                                token: Some(token),
                                clearance: None,
                                cookies: None,
                                user_agent: None,
                                ttl_seconds: None,
                            },
                        ))
                    }
                    Outcome::Cleared(cleared) => {
                        let cookies = cleared
                            .cookies
                            .into_iter()
                            .map(|c| CookieObj {
                                name: c.name().to_string(),
                                value: c.value().to_string(),
                            })
                            .collect();
                        timer.success();
                        Ok(json_response(
                            StatusCode::OK,
                            &SuccessResponse {
                                success: true,
                                token: None,
                                clearance: Some(cleared.clearance),
                                cookies: Some(cookies),
                                user_agent: None,
                                ttl_seconds: None,
                            },
                        ))
                    }
                },
                Err(e) => {
                    let message = format!("Solve error: {:#}", e);
                    timer.failure(&message);
                    Ok(error_response(StatusCode::BAD_GATEWAY, message))
                }
            },
        };
        let response = response?;
        if let Some(sink) = options.sink.as_deref() {
            sink.progress(&format!(
                "server::handle_request output=HTTP {}",
                response.status()
            ));
        }
        Ok(response)
    } else {
        Ok(error_response(
            StatusCode::NOT_FOUND,
            format!("Endpoint '{}' not found", path),
        ))
    }
}

fn json_response<T: Serialize>(status: StatusCode, data: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(data).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        .header("Access-Control-Allow-Headers", "*")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn error_response(status: StatusCode, message: String) -> Response<Full<Bytes>> {
    json_response(
        status,
        &ErrorResponse {
            success: false,
            error: message,
        },
    )
}
