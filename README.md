# cfsolve

cfsolve is a Rust library and command line tool that solves Cloudflare Turnstile
widgets and challenge pages without a headless browser. It returns a Turnstile
token for widgets or a `cf_clearance` cookie for challenge pages.

Turnstile widgets can be solved using the page URL, the sitekey, and optionally the
page's HTML (this should not be required in most cases).  Challenge pages require a direct
fetch or the HTML of the page.

## Browser profiles

cfsolve impersonates a specific browser, described by a profile file. One is
included: `profiles/safari-26-ios.json` (Safari on iPhone).

Each profile references recorded responses to the challenge's browser checks,
stored as JSON in a directory. Keep each profile with its directory when you
copy. Producing these files requires some manual (or AI) effort though it can
be greatly aided by solving challenges in a real web browser with the proxy
set to the address of a running `capture-proxy`, which records the decoded
payloads sent to Cloudflare.  Currently only Safari and Chrome(ium) profile
types are supported.

## Building

You need the Rust version pinned in `rust-toolchain.toml`, plus CMake, a C/C++
compiler, libclang, and Git (to patch and build BoringSSL).

```sh
cargo build --release --bin challenge
```

## Command line tool

```sh
./target/release/challenge --page 'https://example.com/login' /tmp/solve \
  --solve --fingerprint profiles/safari-26-ios.json
```

On success it prints the token (or `cf_clearance=...`) and sends progress
to stderr. The directory argument holds all requests and responses for
debugging, so it must be empty or not exist yet.

By default it solves the first Turnstile widget on the page, or clears
the challenge page. To pick one widget when the page has several, pass its
sitekey, with its action and cData when the site sets them. With `--sitekey`,
it fails on a challenge page.

```sh
./target/release/challenge --page 'https://example.com/login' /tmp/solve \
  --solve --fingerprint profiles/safari-26-ios.json \
  --sitekey 'SITEKEY' --action 'login' --cdata 'CUSTOM_DATA'
```

If you only have a sitekey, add `--blank-page` and set `--page` to the
site's real URL.

| Option | Description |
| --- | --- |
| `--fingerprint <file>` | Browser profile file to use. Required. |
| `--page <url>` | The page with the widget, or the challenge page. |
| `--solve` | Solve the widget or challenge. Without this, cfsolve stops after sending the widget's first payload. |
| `--sitekey <key>` | Select a widget by sitekey. |
| `--action <value>`, `--cdata <value>` | Override the widget's action and cData. This needs `--sitekey`. |
| `--blank-page` | Skip loading the page. Render the widget on a blank page at the page URL. This needs `--solve` and `--sitekey`. |
| `--proxy <url>` | Send every request through an `http://`, `https://`, `socks5://`, or `socks5h://` proxy. Put credentials in the URL, as in `socks5h://user:password@host:1080`. |
| `-h`, `--help` | Show help. |

## Library

Add cfsolve as a path dependency and copy its `[patch]` section, since
Cargo only reads patches from the top-level `Cargo.toml`:

```toml
[dependencies]
cfsolve = { path = "/path/to/cfsolve", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }

[patch.crates-io]
btls-sys = { path = "/path/to/cfsolve/vendor/btls-sys" }
wreq = { path = "/path/to/cfsolve/vendor/wreq" }
http2 = { path = "/path/to/cfsolve/vendor/http2" }
```

`default-features = false` turns off the internal tools so only the solver remains.
Use the Rust version in `rust-toolchain.toml` or newer.

```rust
use cfsolve::{Browser, Options, PageSource, Turnstile};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let browser = Browser::read("/path/to/cfsolve/profiles/safari-26-ios.json")?;
    let options = Options::default();

    let turnstile = Turnstile {
        url: "https://example.com/login".parse()?,
        page: PageSource::Navigate,
        widget: None,
    };
    let token = browser.solve_turnstile(turnstile, &options).await?;
    println!("{token}");

    let cleared = browser.clear(&"https://example.com/".parse()?, &options).await?;
    println!("cf_clearance={}", cleared.clearance);
    println!("{} cookies; protected page: {}", cleared.cookies.len(), cleared.page.url);
    Ok(())
}
```

Load a `Browser` once and share it. Concurrent operations each get their own
connections and cookies.

Send the `cf_clearance` cookie from the same IP address and user agent
as the profile, or Cloudflare will reject it.

### Turnstile with a sitekey or your own HTML

`PageSource::Navigate` fetches the page. With only a URL and sitekey, use
`PageSource::Blank` and specify the widget:

```rust
use cfsolve::{PageSource, Turnstile, Widget};

let turnstile = Turnstile {
    url: "https://example.com/login".parse()?,
    page: PageSource::Blank,
    widget: Some(Widget {
        sitekey: "SITEKEY".into(),
        action: Some("login".into()),
        cdata: None,
    }),
};
let token = browser.solve_turnstile(turnstile, &options).await?;
```

Set `action` and `cdata` to the values the site uses, or `None` when the site
doesn't set them. You can also pass a `Widget` with `PageSource::Navigate` to pick
one widget out of several or to supply one the site adds with JavaScript.

For a page you have already loaded, such as one behind a login, pass its URL and
HTML:

```rust
PageSource::Html {
    html: std::fs::read_to_string("account.html")?,
    referrer_policy: None, // Or the response's Referrer-Policy header.
}
```

The widget runs in a cross-site iframe, so you don't need your login cookies.
With `Html`, `widget: None` solves the first widget on the page, while `Blank`
always needs a `Widget` and renders it on a blank page at the site's URL.

### Challenge pages

`browser.clear(&url, &options)` fetches the page and clears the challenge. The
`Clearance` it returns contains the `cf_clearance` cookie, all cookies for the
page, and the protected page. It fails with `Error::NotChallenged` when there's
no challenge.

If you fetched the challenge page yourself, pass the response as a
`FetchedPage` to `browser.clear_fetched(page, &options)`. Use the same IP and user
agent as the profile.

If you don't know whether a URL shows a widget or a challenge page, use
`browser.solve`, which covers both cases:

```rust
use cfsolve::Outcome;

match browser.solve(&url, &options).await? {
    Outcome::Token(token) => println!("{token}"),
    Outcome::Cleared(cleared) => println!("cf_clearance={}", cleared.clearance),
}
```

### Options

Set a proxy per operation through `Options`, using HTTP, HTTPS, or SOCKS5:

```rust
let options = cfsolve::Options {
    proxy: Some("socks5h://127.0.0.1:1080".into()),
    ..Default::default()
};
```

Library operations are silent by default. For progress messages and debug files,
implement `Sink` and set `options.sink` to `Some(Arc::new(your_sink))`.

### Errors

| Error | Cause | Retry? |
| --- | --- | --- |
| `Error::Network` | Connection failed. | Yes |
| `Error::Rejected` | Cloudflare rejected the solution. | Yes |
| `Error::Blocked` | The site returned an error page instead of a challenge. | No |
| `Error::Challenged` | You asked for a Turnstile token but got a challenge page. | Yes, after clearing it |
| `Error::NotChallenged` | You asked for a challenge clearance but there was no challenge. | No |
| `Error::Config` | Invalid profile or options. | No |
| `Error::Unsupported` | Any other failure, such as a new challenge build or a page with no widget. | No |

## License

MIT, except for the patched dependencies in `vendor/`, which keep their own
licenses.
