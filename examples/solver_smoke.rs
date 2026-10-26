//! Throwaway live check: calls every `Browser` method against captchatest.book.bi.
//!
//! `cargo run -j2 --example solver_smoke`

use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail, ensure};
use cfsolve::fingerprint::Transport;
use cfsolve::{
    Browser, Error, FetchedPage, Options, Outcome, PageSource, Sink, Turnstile, Url, Widget,
};

const PROFILE: &str = "profiles/safari-26-ios.json";
const MANAGED: &str = "https://captchatest.book.bi/managed";
const UNDER_ATTACK: &str = "https://captchatest.book.bi/under-attack";

/// Keeps the iframe URL a session saves, for `prepare`.
#[derive(Default)]
struct IframeUrl(Mutex<Option<String>>);

impl Sink for IframeUrl {
    fn artifact(&self, name: &str, contents: &[u8]) -> Result<()> {
        if name == "iframe-url.txt" {
            *self.0.lock().unwrap() = Some(String::from_utf8_lossy(contents).trim().to_owned());
        }
        Ok(())
    }

    fn progress(&self, _: &str) {}
}

#[tokio::main]
async fn main() -> Result<()> {
    let browser = Browser::read(PROFILE)?;
    let options = Options::default();
    let managed: Url = MANAGED.parse()?;
    let under_attack: Url = UNDER_ATTACK.parse()?;

    // The managed page's HTML and sitekey, loaded as the profile's browser.
    let client = Transport::read(Path::new(PROFILE))?.client(None)?;
    let html = cfsolve::http::navigate(&client, &managed).await?.html;
    let sitekey = html
        .split("data-sitekey=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .context("the managed page names no sitekey")?
        .to_owned();
    let widget = Widget {
        sitekey,
        action: None,
        cdata: None,
    };

    let mut failures = 0;
    let mut check = |name: &str, result: Result<String>| match result {
        Ok(detail) => eprintln!("PASS {name}: {detail}"),
        Err(error) => {
            failures += 1;
            eprintln!("FAIL {name}: {error:#}");
        }
    };

    let turnstile = |page, widget| Turnstile {
        url: managed.clone(),
        page,
        widget,
    };
    let navigated = turnstile(PageSource::Navigate, None);
    check(
        "solve_turnstile(Navigate)",
        token(browser.solve_turnstile(navigated, &options).await),
    );
    let page = PageSource::Html {
        html: html.clone(),
        referrer_policy: None,
    };
    check(
        "solve_turnstile(Html)",
        token(
            browser
                .solve_turnstile(turnstile(page, None), &options)
                .await,
        ),
    );
    let blank = turnstile(PageSource::Blank, Some(widget.clone()));
    check(
        "solve_turnstile(Blank, widget)",
        token(browser.solve_turnstile(blank, &options).await),
    );
    let unknown = turnstile(PageSource::Blank, None);
    let result = browser.solve_turnstile(unknown, &options).await;
    check(
        "solve_turnstile(Blank, no widget) is Config",
        expect_error(result, |error| matches!(error, Error::Config(_))),
    );
    let challenged = Turnstile {
        url: under_attack.clone(),
        page: PageSource::Navigate,
        widget: None,
    };
    let result = browser.solve_turnstile(challenged, &options).await;
    check(
        "solve_turnstile(under-attack) is Challenged",
        expect_error(result, |error| matches!(error, Error::Challenged { .. })),
    );

    check(
        "clear(under-attack)",
        clearance(browser.clear(&under_attack, &options).await),
    );
    let result = browser.clear(&managed, &options).await;
    check(
        "clear(managed) is NotChallenged",
        expect_error(result, |error| matches!(error, Error::NotChallenged)),
    );
    check(
        "clear_fetched(under-attack)",
        async {
            let page = fetch(&under_attack).await?;
            clearance(browser.clear_fetched(page, &options).await)
        }
        .await,
    );

    check(
        "solve(managed)",
        match browser.solve(&managed, &options).await {
            Ok(Outcome::Token(token)) => Ok(format!("token of {} bytes", token.len())),
            Ok(Outcome::Cleared(_)) => Err(anyhow::anyhow!("cleared instead of a token")),
            Err(error) => Err(error.into()),
        },
    );
    check(
        "solve(under-attack)",
        match browser.solve(&under_attack, &options).await {
            Ok(Outcome::Cleared(cleared)) => Ok(format!("cf_clearance={}", cleared.clearance)),
            Ok(Outcome::Token(_)) => Err(anyhow::anyhow!("a token instead of a clearance")),
            Err(error) => Err(error.into()),
        },
    );

    let sink = Arc::new(IframeUrl::default());
    let recording = Options {
        proxy: None,
        sink: Some(sink.clone()),
    };
    check(
        "send_first_payload(managed, widget)",
        browser
            .send_first_payload(&managed, Some(&widget), &recording)
            .await
            .map(|()| "sent".to_owned())
            .map_err(Into::into),
    );
    let iframe = sink.0.lock().unwrap().take();
    check(
        "prepare(iframe)",
        async {
            let iframe: Url = iframe.context("no iframe URL was saved")?.parse()?;
            browser.prepare(iframe, &options).await?;
            Ok("prepared".to_owned())
        }
        .await,
    );

    ensure!(failures == 0, "{failures} checks failed");
    eprintln!("all checks passed");
    Ok(())
}

/// Loads `url` the way a caller of `clear_fetched` would: as the profile's browser.
async fn fetch(url: &Url) -> Result<FetchedPage> {
    let client = Transport::read(Path::new(PROFILE))?.client(None)?;
    let document = cfsolve::http::navigate(&client, url).await?;
    let set_cookies = client
        .cookies(&document.url)
        .iter()
        .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
        .collect();
    Ok(FetchedPage {
        url: document.url,
        status: document.status,
        html: document.html,
        referrer_policy: None,
        set_cookies,
    })
}

fn token(result: Result<String, Error>) -> Result<String> {
    let token = result?;
    ensure!(!token.is_empty(), "the token is empty");
    Ok(format!("token of {} bytes", token.len()))
}

fn clearance(result: Result<cfsolve::Clearance, Error>) -> Result<String> {
    let cleared = result?;
    ensure!(
        cleared
            .cookies
            .iter()
            .any(|cookie| cookie.name() == "cf_clearance"),
        "cf_clearance is not among the cookies"
    );
    Ok(format!(
        "cf_clearance={}, protected page HTTP {}",
        cleared.clearance, cleared.page.status
    ))
}

fn expect_error<T>(result: Result<T, Error>, expected: impl Fn(&Error) -> bool) -> Result<String> {
    match result {
        Ok(_) => bail!("succeeded"),
        Err(error) if expected(&error) => Ok(error.to_string()),
        Err(error) => bail!("wrong error {error:?}"),
    }
}
