# cfsolve Rust execution documentary

This document follows one API request from the first Rust entry point to the final HTTP response.
It also describes the output of each major function on the solve path and how to print those
outputs as a correlated execution trace.

## 1. Start and end in one picture

```text
docker-entrypoint.sh
  -> server::main
     -> accept TCP connection
        -> server::handle_request
           -> Browser::solve_turnstile / clear / solve
              -> tokio::task::spawn_blocking
                 -> dedicated current-thread Tokio runtime
                    -> solver::open
                    -> session::native
                       -> session::land
                       -> session::start_widget
                          -> fetch + deobfuscate iframe JavaScript
                          -> prepare session + first payload
                          -> challenge POST #1
                          -> disassemble and analyze returned VM program
                       -> session::probes::prepare
                       -> challenge POST #2
                       -> ProgramOutcome::Complete
                          OR interaction/proof + challenge POST #3
                    -> Outcome::Token / Outcome::Cleared / Error
           -> JSON HTTP 200 / 4xx / 502
```

For the normal Turnstile request, execution **starts** at `src/bin/server/main.rs::main`, enters
the solve at `src/solver.rs::Browser::solve_turnstile`, and **ends** when
`src/bin/server/main.rs::handle_request` returns a JSON response.

## 2. Enable the execution log

Two independent log levels are available:

- `CFSOLVE_STAGE_LOG=1`: progress messages and network-stage results.
- `CFSOLVE_DET_LOG=1`: detailed function boundaries, function outputs, sizes, and timings.

Run the instrumented Docker server:

```bash
docker run --rm --name cfsolve-traced \
  -p 8743:8742 \
  -e LISTEN=0.0.0.0:8742 \
  -e CONCURRENCY=100 \
  -e CFSOLVE_STAGE_LOG=1 \
  -e CFSOLVE_DET_LOG=1 \
  cfsolve-server:latest
```

Follow logs:

```bash
docker logs -f cfsolve-traced
```

Every line has the form:

```text
[cfsolve][solve=17][+  3140 ms] Function output=Value(details)
```

`solve=17` is process-local and is shared by both logging layers. It is essential during a
100-request burst because lines from separate solves arrive concurrently. The trace logs token
lengths and cookie counts, not full secrets.

## 3. Server entry and routing

### `src/bin/server/main.rs::main`

Inputs:

- `--listen` address (default `127.0.0.1:8742`)
- fingerprint path
- optional default proxy
- maximum admitted solve concurrency

Work:

1. Parses CLI arguments.
2. Calls `Browser::read` once to validate and load the fingerprint.
3. Creates `AppState` and its concurrency semaphore.
4. Binds a `TcpListener`.
5. Accepts connections forever.
6. Gives each connection to Hyper HTTP/1.

Output: a running server. This function does not return during normal operation.

### `src/bin/server/main.rs::handle_request`

Important routes:

| Route | Rust operation | Output |
|---|---|---|
| `GET /health` | health check | HTTP 200 service metadata |
| `POST /cloudflare`, `/solve`, `/` | one direct solve | token, clearance, or HTTP 502 error JSON |
| `POST /session/solve` | solve and cache clearance | cached-session response |
| `GET /session/<domain>` | read cached clearance | cached session or 404 |
| `GET /sessions` | inspect cache | session list |

For a direct solve, it:

1. Reads and deserializes `RequestPayload`.
2. Parses the target `Url`.
3. Creates `Options` with proxy and trace sink.
4. Waits for one semaphore permit.
5. Dispatches by `mode`:
   - `turnstile` -> `Browser::solve_turnstile`
   - `iuam` / `iaum` -> `Browser::clear`
   - anything else -> `Browser::solve`
6. Converts the solver result into `SuccessResponse` or `ErrorResponse`.

Final trace output:

```text
server::handle_request output=HTTP 200 OK
```

or, for a solve failure:

```text
server::handle_request output=HTTP 502 Bad Gateway
```

## 4. Solver boundary and concurrency isolation

### `src/solver.rs::Browser::solve_turnstile`

Input: `Turnstile { url, page, widget }` and `Options`.

- When the caller supplied a site key, the API uses `PageSource::Blank` and renders that widget.
- Without a supplied site key, it navigates to the target page and finds the page's widget.

Output: `Result<String, Error>`, where the string is the Turnstile token.

### `src/solver.rs::Browser::solved`

This is the common solve boundary. It moves owned solve data to `tokio::task::spawn_blocking`,
builds a current-thread Tokio runtime on that worker, creates a **fresh `BrowserClient`**, and runs
the complete network/CPU pipeline there.

Why the client is fresh:

- its cookie jar must belong to only one solve;
- its connection dispatch tasks belong to the solve runtime;
- sharing a client after that runtime ends produces `dispatch task is gone` and can leak cookies.

Why the solve has a dedicated thread/runtime:

- JavaScript transformation and VM disassembly contain long synchronous CPU sections;
- running those sections on the API runtime starved unrelated HTTP/network futures under burst
  load;
- isolation keeps the API accept loop and other connections responsive.

Outputs logged:

```text
solver::solved output=Token(len=773)
solver::solved output=Clearance(cookies=4)
solver::solved output=Error(...)
```

### `src/solver.rs::open`

Input: an owned `Start`:

- `Start::Navigate(Url)` calls `session::navigate`.
- `Start::Fetched(FetchedPage)` installs supplied cookies and builds a `PageDocument` directly.

Output: `(PageDocument, LoadTiming)`.

## 5. Landing and first payload

### `src/session/widget.rs::native`

Input: browser client, sink, page document, navigation timing, fingerprint page facts, expected
page type, and solve facts.

Work:

1. `land` classifies an ordinary page versus an IUAM challenge page.
2. `start_widget` creates the widget session and sends POST #1.
3. `WidgetSession::solve` answers probes and optional interaction.
4. For IUAM, the outer orchestrator exchanges the widget completion for clearance.

Output: `Outcome::Token` or `Outcome::Cleared`.

### `src/session/widget.rs::land`

Input: `PageDocument` and `Expect`.

- Ordinary page: calls `initial::render_page`.
- Challenge page: calls `challenge_page::begin` to execute the orchestrator until it renders a
  widget.
- Unexpected page type: returns `Error::Challenged` or `Error::NotChallenged`.

Output: `Landing::Site(EmbeddingPage)` or
`Landing::ChallengePage(Orchestrator, EmbeddingPage)`.

### `src/session/initial.rs::render_page`

Work:

1. Parses the embedding HTML.
2. Selects or renders the requested widget.
3. Resolves and fetches Turnstile `api.js`.
4. Reuses the in-process loader cache when the loader build URL is unchanged.

Output: `EmbeddingPage` containing rendered page facts and parsed loader metadata.

Progress output names the URL, widget ID, site key, API build, and route.

### `src/session/widget.rs::start_widget`

This function performs the first expensive half of the solve.

#### `initial::fetch`

1. `http::fetch_iframe` downloads iframe HTML.
2. `source::inline_javascript` extracts inline JavaScript.
3. `initial::deobfuscate` runs the SWC rewrite pipeline on a deep-stack worker.
4. `Source::try_new` parses the transformed JavaScript.

Outputs logged:

```text
http::fetch_iframe output=Iframe(html_bytes=..., encoded_bytes=...)
session::initial::deobfuscate output=JavaScript(bytes=...)
script::Source::try_new output=Source
session::initial::fetch output=Fetched
```

`initial::deobfuscate` has an exact-SHA-256 process cache. A cache hit is safe only when the
entire fetched script is identical.

#### `PreparedSession::try_new`

Reads the transformed AST and recovers:

- initial request URL and headers;
- VM runner and programs;
- payload encoder;
- option mapping and templates.

Output: `PreparedSession`.

#### `initial::merge`

Merges embedding-page signals into challenge options, reconstructs initial state, and builds the
first plaintext payload.

Output: `(ExtractedProgram, Merged)`.

Trace includes `payload_fields=<count>`; normal captures currently contain about 45 fields.

#### `SessionEncoder::encode`

Input: plaintext payload map. Output: encoded request-body `String`.

#### `Channel::post(Stage::Initial)`

Sends challenge POST #1, reads the encoded response, removes the response mask, Base64-decodes
the result, and returns:

```text
PostResult {
    program: Vec<u8>,
    received_ms: i64,
    fetch: LoadTiming,
}
```

Logged sub-outputs:

```text
http::read_encoded(Initial) output=(body_bytes=..., status=200 OK)
codec::decode_response(Initial) output=Text(bytes=...)
base64::decode(Initial) output=Program(bytes=...)
Channel::post(Initial) output=PostResult(program_bytes=...)
```

## 6. VM analysis

### `src/stage2/analysis/analyze.rs::analyze`

Input: session `Source` plus POST #1 program bytes.

Ordered work and outputs:

| Function | Output |
|---|---|
| `Source::machine` | recovered `Machine` definition |
| `Machine::disassemble_from` | reachable `Listing` with instructions and failures |
| `Index::new` | indexed control flow, constants, writes, strings, and calls |
| `Index::pool` | string-pool address and text |
| `discovery::discover` | ordered raw probes |
| `Vocabulary::infer` | mapping from session names to reference names |
| `Operation::recognize` | native operation or replay operation for each probe |
| `payload::scan` | payload construction scan |
| `envelope::recover` | record-envelope fields |
| `scan.layout` | payload layout |
| `Trace::recover` | optional controller trace |

Final output: `Analysis`, holding a `ProbePlan` plus diagnostics.

Representative trace:

```text
Machine::disassemble_from output=Listing(instructions=..., failures=...)
listing::Index::new output=Index
analysis::discovery::discover output=Discovery(probes=39)
Operation::recognize output=recognized(39/39)
analysis::analyze output=Analysis(probes=39, instructions=...)
```

## 7. Probe payload and second POST

### `src/session/probes.rs::prepare`

Input: `WidgetSession` and fingerprint `Solve` facts.

Work:

1. `observe` runs native probe collectors and required network probes.
2. Applies resource timing and POST logs.
3. Builds the iframe window/options state.
4. Calculates realistic probe durations and send time.
5. Builds records in recovered VM order.
6. Calls `ProbePlan::assemble`.

Output: `ProbeSubmission { payload, options, window, geometry }`.

Logged output includes the count of probe fetches and plaintext payload fields.

### `Channel::submit(Stage::Probes)`

1. Saves/serializes the plaintext diagnostic payload through the sink.
2. Encodes it.
3. Waits until its browser-compatible scheduled send time.
4. Calls `Channel::post`.

Output: POST #2 `PostResult`.

### `WidgetSession::outcome`

Disassembles the smaller response program and calls `ProgramOutcome::of`.

Possible outputs:

- `ProgramOutcome::Complete { token }` -> solve ends successfully.
- `ProgramOutcome::Interaction` -> checkbox/proof stage follows.
- `ProgramOutcome::Other` -> solve returns a refusal error.

## 8. Optional interaction and third POST

### `src/session/interaction.rs::collect`

Only runs when POST #2 asks for interaction.

Work:

1. Recovers queried selectors and call-stack geometry.
2. Measures the native checkbox layout.
3. Generates touch/pointer/mouse input events with configured timing.
4. Waits for the proof launch time.
5. Runs proof search on a blocking worker.

Output: `InteractionResult` containing fields, timestamps, input events, and selectors.

### `src/session/interaction.rs::payload`

Adds the interaction record, refreshed timings, input counters, and selector-query log to the
existing payload.

Output: final `Submission`.

### `Channel::submit(Stage::Interaction)`

Sends POST #3. It must return `ProgramOutcome::Complete`; otherwise the solve fails.

## 9. IUAM-specific ending

For `mode=iuam`, `land` detects the challenge page and
`src/session/challenge_page.rs::begin` runs its orchestrator. After the inner widget returns a
token, the orchestrator submits completion and obtains `cf_clearance`.

Final Rust output:

```text
Outcome::Cleared(Clearance {
    clearance,
    cookies,
    page,
})
```

The server converts this to JSON containing `clearance` and all cookies.

## 10. Error path

Errors are classified in `src/error.rs` and propagated with context. The direct API maps solver
errors to HTTP 502:

```json
{
  "success": false,
  "error": "Turnstile solve error: <context chain>"
}
```

The detailed trace ends with:

```text
solver::solved output=Error(<classified error>)
server::handle_request output=HTTP 502 Bad Gateway
```

## 11. 100-thread acceptance test

The tracked harness performs a synchronized start and records both successful and failed
latencies:

```bash
python test_100.py \
  --url http://127.0.0.1:8743/cloudflare \
  --requests 100 \
  --concurrency 100 \
  --timeout 90 \
  --json-out benchmark-docker-100.json
```

It reports:

- success count and rate;
- HTTP status distribution and grouped errors;
- min, mean, p50, p90, p95, p99, and max latency;
- completed RPS, successful RPS, and successful CPM;
- every individual request result in JSON.

Interpret server failures separately from target-side rejection/rate limiting. An HTTP 502 can
be a Cloudflare response/refusal rather than an API process crash; the grouped context chain and
correlated solve log show which one occurred.

## 12. Current latency anatomy

Warm real-world measurements before deeper algorithm changes showed these dominant sections:

| Section | Windows local | Linux Docker example |
|---|---:|---:|
| iframe/loader network | ~0.3-0.4s | ~0.6s through deobfuscation start |
| deobfuscation + preparation | ~2.2-2.5s | ~0.8s |
| POST #1 | ~0.5-0.9s | ~0.9s |
| VM disassembly + analysis | ~2.0-2.2s | ~0.8s |
| probes + POST #2 | ~0.6-0.9s | ~0.4s |
| optional interaction | 0-1.4s | variable |

The thread-isolation change prevents these synchronous sections from blocking the API runtime;
it does not make the intrinsic per-solve CPU work disappear. At 100 simultaneous requests, total
CPU demand and upstream rate limits remain physical capacity constraints and must be visible in
the benchmark rather than hidden by a single-request result.
