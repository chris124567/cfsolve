//! The challenge page as it stands when its orchestrator renders the widget.

use anyhow::{Context, Result, ensure};
use url::{Position, Url};

use crate::challenge::orchestrator::ChallengePage;

/// Selector for the widget container in the rendered page.
pub(crate) const WIDGET_HOST: &str = "#challenge-widget-host";

/// Reconstructs the page at widget render time, including its language, scripts, header,
/// status text, widget container, hidden panels, and footer.
///
/// The `api.js` summary records tags, attribute names, counts, and the widget's path
/// through the tree. It omits randomized IDs and classes. Layout follows a Chromium capture
/// from 2026-10-16, template version 5.
pub(crate) fn render(
    page: &ChallengePage,
    loader: &Url,
    language: &str,
    ray: &str,
) -> Result<String> {
    let host = page.url.host_str().context("challenge page has no host")?;
    let html = &page.html;
    let opening = html
        .find("<html")
        .and_then(|start| Some(start..start + html[start..].find('>')? + 1))
        .context("challenge page has no html element")?;
    let head_end = html.find("</head>").context("challenge page has no head")?;
    let content = html
        .find("<div class=\"main-content\">")
        .map(|start| start + "<div class=\"main-content\">".len())
        .context("challenge page has no main content")?;
    let body_end = html
        .rfind("</body>")
        .context("challenge page has no body")?;
    ensure!(
        opening.end <= head_end && head_end < content && content < body_end,
        "challenge page is out of order"
    );
    let scripts = format!(
        r#"<script src="{}"></script><style></style><script src="{}" async="" defer="" crossorigin="anonymous"></script>"#,
        escape(&page.orchestrator[Position::BeforePath..]),
        escape(loader.as_str()),
    );
    let panels = format!(
        concat!(
            r#"<div class="a"><img src="/favicon.ico" class="a b" alt="Icon for {host}"><h1>{host}</h1></div>"#,
            r#"<h2 id="a" class="a b">Performing security verification</h2>"#,
            r#"<p id="b" class="a b">This website uses a security service to protect against malicious bots. This page is displayed while the website verifies you are not a bot.</p>"#,
            r#"<div id="{widget}" style="display: grid;"></div>"#,
            r#"<div id="c" style="display: none;"><h2 id="d" class="a">Verification successful. Waiting for {host} to respond</h2></div>"#,
            r#"<div id="e" class="a b" style="display: none; visibility: hidden;"><div class="a"><div></div><div></div><div></div><div></div></div></div>"#,
        ),
        host = escape(host),
        widget = &WIDGET_HOST[1..],
    );
    let footer = format!(
        concat!(
            r#"<div class="footer" role="contentinfo"><div class="footer-inner"><div class="footer-wrapper">"#,
            r#"<div><div class="ray-id">Ray ID: <code>{ray}</code></div></div>"#,
            r#"<div class="footer-link-wrapper"><span class="footer-text">Performance and Security by <a rel="noopener noreferrer" href="https://www.cloudflare.com?utm_source=challenge&amp;utm_campaign=m" target="_blank" aria-label="Cloudflare, opens in a new tab">Cloudflare</a></span>"#,
            r#"<span class="footer-divider"></span><a target="_blank" rel="noopener noreferrer" href="https://www.cloudflare.com/privacypolicy/" aria-label="Privacy, opens in a new tab" class="footer-text">Privacy</a></div>"#,
            r#"</div></div></div>"#,
        ),
        ray = escape(ray),
    );
    Ok(format!(
        r#"{}<html lang="{}" dir="ltr">{}{scripts}{}{panels}{}{footer}{}"#,
        &html[..opening.start],
        escape(language),
        &html[opening.end..head_end],
        &html[head_end..content],
        &html[content..body_end],
        &html[body_end..],
    ))
}

/// Escapes text for HTML attributes and text nodes.
#[must_use]
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
