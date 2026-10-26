//! Applies W3C Referrer Policy to request `Referer` headers and navigated frames'
//! `document.referrer`.

use scraper::{Html, Selector};
use url::Url;

/// Controls how much of a document's address is exposed as a referrer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    SameOrigin,
    Origin,
    StrictOrigin,
    OriginWhenCrossOrigin,
    /// The policy used when a document specifies none.
    #[default]
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

impl ReferrerPolicy {
    /// Parses a policy token without case sensitivity.
    fn token(token: &str) -> Option<Self> {
        Some(match token.trim().to_ascii_lowercase().as_str() {
            "no-referrer" => Self::NoReferrer,
            "no-referrer-when-downgrade" => Self::NoReferrerWhenDowngrade,
            "same-origin" => Self::SameOrigin,
            "origin" => Self::Origin,
            "strict-origin" => Self::StrictOrigin,
            "origin-when-cross-origin" => Self::OriginWhenCrossOrigin,
            "strict-origin-when-cross-origin" => Self::StrictOriginWhenCrossOrigin,
            "unsafe-url" => Self::UnsafeUrl,
            _ => return None,
        })
    }

    /// Parses a `<meta name="referrer">` value, including legacy keywords.
    fn meta(content: &str) -> Option<Self> {
        match content.trim().to_ascii_lowercase().as_str() {
            "never" => Some(Self::NoReferrer),
            "default" => Some(Self::StrictOriginWhenCrossOrigin),
            "always" => Some(Self::UnsafeUrl),
            "origin-when-crossorigin" => Some(Self::OriginWhenCrossOrigin),
            other => Self::token(other),
        }
    }

    /// Reads the last valid `Referrer-Policy` header token, then applies `<meta
    /// name="referrer">` elements in document order.
    #[must_use]
    pub fn of_document(header: Option<&str>, html: &str) -> Self {
        let mut policy = header
            .into_iter()
            .flat_map(|header| header.split(','))
            .filter_map(Self::token)
            .next_back()
            .unwrap_or_default();
        let metas = Selector::parse(r#"meta[name="referrer" i][content]"#)
            .expect("a constant, valid selector");
        for meta in Html::parse_document(html).select(&metas) {
            if let Some(stated) = meta.attr("content").and_then(Self::meta) {
                policy = stated;
            }
        }
        policy
    }

    /// Returns the referrer for a request from `page` to `target`, if permitted.
    #[must_use]
    pub fn referrer(self, page: &Url, target: &Url) -> Option<String> {
        let mut full = page.clone();
        full.set_fragment(None);
        // Credential setters require a host, which page URLs always have.
        let _ = full.set_username("");
        let _ = full.set_password(None);
        let origin = origin_referrer(page);
        let same_origin = page.origin() == target.origin();
        let downgrade = page.scheme() == "https" && target.scheme() != "https";
        match self {
            Self::NoReferrer => None,
            Self::UnsafeUrl => Some(full.into()),
            Self::Origin => Some(origin),
            Self::NoReferrerWhenDowngrade => (!downgrade).then(|| full.into()),
            Self::SameOrigin => same_origin.then(|| full.into()),
            Self::StrictOrigin => (!downgrade).then_some(origin),
            Self::OriginWhenCrossOrigin if same_origin => Some(full.into()),
            Self::OriginWhenCrossOrigin => Some(origin),
            Self::StrictOriginWhenCrossOrigin if same_origin => Some(full.into()),
            Self::StrictOriginWhenCrossOrigin => (!downgrade).then_some(origin),
        }
    }
}

/// The referrer that names only `url`'s origin.
#[must_use]
pub(super) fn origin_referrer(url: &Url) -> String {
    format!("{}/", url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_meta_tag_overrides_the_header() {
        // Some sites state their policy in markup.
        let html = r#"<head><meta name="referrer" content="no-referrer"></head>"#;
        let legacy = r#"<meta name="Referrer" content="never">"#;
        let header = "no-referrer, bogus, same-origin, bogus";
        let cases = [
            (None, html, ReferrerPolicy::NoReferrer),
            (Some("unsafe-url"), html, ReferrerPolicy::NoReferrer),
            // The header's last valid token.
            (Some(header), "", ReferrerPolicy::SameOrigin),
            (None, legacy, ReferrerPolicy::NoReferrer),
            // The default without a valid token.
            (Some("bogus"), "<p>", ReferrerPolicy::default()),
        ];
        for (header, html, expected) in cases {
            let policy = ReferrerPolicy::of_document(header, html);
            assert_eq!(policy, expected, "{header:?} with {html}");
        }
    }

    #[test]
    fn requests_carry_what_the_policy_allows() {
        let page = Url::parse("https://user:pass@captchatest.book.bi/managed?x=1#top").unwrap();
        let other = Url::parse("https://challenges.cloudflare.com/turnstile/v0/api.js").unwrap();
        let same = page.join("/style.css").unwrap();
        let insecure = Url::parse("http://example.com/").unwrap();
        let full = Some("https://captchatest.book.bi/managed?x=1");
        let origin = Some("https://captchatest.book.bi/");
        let default = ReferrerPolicy::default();
        let cases = [
            // What the iPhone sent captchatest's widget iframe and loader.
            (default, &other, origin),
            (default, &same, full),
            (default, &insecure, None),
            (ReferrerPolicy::NoReferrer, &same, None),
            (ReferrerPolicy::SameOrigin, &other, None),
            (ReferrerPolicy::SameOrigin, &same, full),
            (ReferrerPolicy::UnsafeUrl, &insecure, full),
            (ReferrerPolicy::StrictOrigin, &insecure, None),
            (ReferrerPolicy::Origin, &insecure, origin),
        ];
        for (policy, target, expected) in cases {
            let referrer = policy.referrer(&page, target);
            assert_eq!(referrer.as_deref(), expected, "{policy:?} to {target}");
        }
    }
}
