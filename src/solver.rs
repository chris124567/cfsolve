//! Entry points for solving Turnstile widgets and clearing Cloudflare challenge pages with a
//! [`Browser`]. Each solve owns its client, cookie jar, connections, and proxy settings until
//! it ends. Solves can run concurrently.

use std::sync::Arc;

use url::Url;
use wreq::StatusCode;

use crate::browser::Browser;
use crate::embedding_page::page::Widget;
use crate::error::Error;
use crate::http::{BrowserClient, PageDocument};
use crate::performance_clock;
use crate::resource_timing::LoadTiming;
use crate::session::{self, Clearance, Discard, Expect, Outcome, Sink};

/// How one solve reaches the network, and where its diagnostics go.
#[derive(Clone, Default)]
pub struct Options {
    /// An `http://`, `https://`, `socks5://`, or `socks5h://` proxy for every request.
    pub proxy: Option<String>,
    /// Destination for artifacts and progress messages. Both are discarded if absent.
    pub sink: Option<Arc<dyn Sink>>,
}

/// A Turnstile widget to solve, and the page it is on.
///
/// The widget runs in a cross-site iframe, so the page's own cookies and session play no part.
/// What it reports about the page comes from the page's address and HTML.
#[derive(Clone, Debug)]
pub struct Turnstile {
    /// The address of the page the widget is on.
    pub url: Url,
    /// Where the page's HTML comes from.
    pub page: PageSource,
    /// Widget configuration. Uses the `.cf-turnstile` container matching its sitekey, or
    /// renders it with `turnstile.render` if no container matches. If omitted, solves the
    /// page's first container.
    pub widget: Option<Widget>,
}

/// Where a [`Turnstile`] solve gets its page.
#[derive(Clone, Debug)]
pub enum PageSource {
    /// Navigates to the page. A challenge page in its place fails the solve with
    /// [`Error::Challenged`].
    Navigate,
    /// The page as the caller loaded it, such as one behind a login.
    Html {
        /// The page's HTML.
        html: String,
        /// The response's `Referrer-Policy` header.
        referrer_policy: Option<String>,
    },
    /// Renders the required [`Turnstile::widget`] on a blank page at the supplied address. The
    /// widget reports this blank page rather than the site's HTML.
    Blank,
}

/// A challenge page fetched by the caller. The request must use the solve's IP address and
/// browser user agent. Clear the page before it expires.
#[derive(Clone, Debug)]
pub struct FetchedPage {
    /// The address the navigation ended at, after redirects.
    pub url: Url,
    /// The response's status. Challenge pages answer 403.
    pub status: StatusCode,
    /// The response body.
    pub html: String,
    /// The response's `Referrer-Policy` header.
    pub referrer_policy: Option<String>,
    /// The `Set-Cookie` headers of the response and any redirects before it.
    pub set_cookies: Vec<String>,
}

/// Estimated duration of a caller-supplied navigation, treated as ending when the solve starts.
const ESTIMATED_NAVIGATION_MS: u32 = 300;

/// Initial HTML for [`PageSource::Blank`], before rendering the widget.
const BLANK_PAGE: &str = "<!DOCTYPE html><html><head></head><body></body></html>";

impl Browser {
    /// Solves the specified Turnstile widget and returns its token.
    pub async fn solve_turnstile(
        &self,
        turnstile: Turnstile,
        options: &Options,
    ) -> Result<String, Error> {
        let Turnstile { url, page, widget } = turnstile;
        let html = match page {
            PageSource::Navigate => None,
            PageSource::Html {
                html,
                referrer_policy,
            } => Some((html, referrer_policy)),
            PageSource::Blank if widget.is_none() => {
                return Err(Error::Config(anyhow::anyhow!(
                    "a blank page renders no widget of its own; name one to render"
                )));
            }
            PageSource::Blank => Some((BLANK_PAGE.to_owned(), None)),
        };
        let start = match html {
            None => Start::Navigate(&url),
            Some((html, referrer_policy)) => Start::Fetched(FetchedPage {
                url,
                status: StatusCode::OK,
                html,
                referrer_policy,
                set_cookies: Vec::new(),
            }),
        };
        let expect = Expect::Widget(widget.as_ref());
        let Outcome::Token(token) = self.solved(start, expect, options).await? else {
            unreachable!("a widget's page only yields a token");
        };
        Ok(token)
    }

    /// Navigates to `page` and clears the challenge page returned by the server.
    pub async fn clear(&self, page: &Url, options: &Options) -> Result<Clearance, Error> {
        self.clear_from(Start::Navigate(page), options).await
    }

    /// Clears a challenge page already fetched by the caller.
    pub async fn clear_fetched(
        &self,
        page: FetchedPage,
        options: &Options,
    ) -> Result<Clearance, Error> {
        self.clear_from(Start::Fetched(page), options).await
    }

    /// Navigates to `page`, then clears a challenge page or solves the page's first Turnstile
    /// widget.
    pub async fn solve(&self, page: &Url, options: &Options) -> Result<Outcome, Error> {
        self.solved(Start::Navigate(page), Expect::Either, options)
            .await
    }

    /// Navigates to `page` and sends the first payload for `widget`. If no widget is specified,
    /// uses the challenge page's widget or the ordinary page's first widget.
    #[doc(hidden)]
    pub async fn send_first_payload(
        &self,
        page: &Url,
        widget: Option<&Widget>,
        options: &Options,
    ) -> Result<(), Error> {
        let expect = widget.map_or(Expect::Either, |widget| Expect::Widget(Some(widget)));
        let client = self.client(options)?;
        let sink = options.sink.as_deref().unwrap_or(&Discard);
        let (document, navigation) = open(&client, Start::Navigate(page)).await?;
        session::send_first_payload(&client, sink, document, navigation, &self.page, expect)
            .await
            .map_err(Error::classify)
    }

    /// Fetches the iframe at `iframe` and extracts its encoder and payload field map without
    /// sending anything.
    #[doc(hidden)]
    pub async fn prepare(&self, iframe: Url, options: &Options) -> Result<(), Error> {
        let client = self.client(options)?;
        let sink = options.sink.as_deref().unwrap_or(&Discard);
        session::prepare(&client, sink, iframe)
            .await
            .map_err(Error::classify)
    }

    /// Starts a fresh browser session at `start` and completes the widget specified by
    /// `expect`.
    async fn solved(
        &self,
        start: Start<'_>,
        expect: Expect<'_>,
        options: &Options,
    ) -> Result<Outcome, Error> {
        let client = self.client(options)?;
        let sink = options.sink.as_deref().unwrap_or(&Discard);
        let (document, navigation) = open(&client, start).await?;
        session::native(
            &client,
            sink,
            document,
            navigation,
            &self.page,
            expect,
            &self.solve,
        )
        .await
        .map_err(Error::classify)
    }

    async fn clear_from(&self, start: Start<'_>, options: &Options) -> Result<Clearance, Error> {
        let Outcome::Cleared(clearance) =
            self.solved(start, Expect::ChallengePage, options).await?
        else {
            unreachable!("a challenge page only yields a clearance");
        };
        Ok(clearance)
    }

    fn client(&self, options: &Options) -> Result<BrowserClient, Error> {
        self.transport
            .client(options.proxy.as_deref())
            .map_err(Error::Config)
    }
}

enum Start<'url> {
    Navigate(&'url Url),
    Fetched(FetchedPage),
}

/// Loads the starting page. Uses cookies and an estimated navigation duration when the caller
/// supplied the page.
async fn open(
    client: &BrowserClient,
    start: Start<'_>,
) -> Result<(PageDocument, LoadTiming), Error> {
    let page = match start {
        Start::Navigate(url) => {
            return session::navigate(client, url)
                .await
                .map_err(Error::classify);
        }
        Start::Fetched(page) => page,
    };
    for set_cookie in &page.set_cookies {
        client.add_cookie(set_cookie, &page.url);
    }
    let navigation = LoadTiming {
        url: page.url.to_string(),
        started_ms: performance_clock::epoch_ms() - i64::from(ESTIMATED_NAVIGATION_MS),
        duration_ms: f64::from(ESTIMATED_NAVIGATION_MS),
        waiting_ms: 0.0,
        receiving_ms: 0.0,
        body_bytes: page.html.len() as u64,
    };
    let document = PageDocument::new(
        page.url,
        page.status,
        page.html,
        page.referrer_policy.as_deref(),
    );
    Ok((document, navigation))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Callers can share a browser and spawn its solves onto a multithreaded runtime.
    #[test]
    fn solving_is_send() {
        fn send<T: Send>(_: &T) {}
        fn solves(
            browser: &Browser,
            url: &Url,
            turnstile: Turnstile,
            page: FetchedPage,
            options: &Options,
        ) {
            send(&browser.solve(url, options));
            send(&browser.solve_turnstile(turnstile, options));
            send(&browser.clear(url, options));
            send(&browser.clear_fetched(page, options));
        }
        let _ = solves;
        fn shared<T: Send + Sync>() {}
        shared::<Browser>();
    }
}
