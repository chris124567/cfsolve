//! The test page that other modules' tests render.

use url::Url;

use crate::embedding_page::page::RenderedPage;

/// A page rendering one widget.
pub(crate) const PAGE: &str = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Turnstile test page</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head><body><h1>Heading</h1><p>Text</p>
<div class="cf-turnstile" data-sitekey="0x4AAAAAAB8gDxRzm2UASWbL" data-action="login" data-cdata="test-cdata"></div>
</body></html>"#;

pub(crate) fn page() -> RenderedPage {
    let url = Url::parse("http://127.0.0.1:8000/index.html").unwrap();
    RenderedPage::render(PAGE, url, "j5gbk", None).unwrap()
}
