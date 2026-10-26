//! Builds a probe record from the embedding page's signals.

use crate::embedding_page::page::PageSignals;
use crate::js::{self, JsObject, json};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference::{
    PARENT_INFO_DIRECT, PARENT_INFO_FALLBACK, PARENT_INFO_MISSING, PARENT_INFO_PAD,
    PARENT_INFO_REASONS, PARENT_INFO_REFERRER, PARENT_INFO_VISIBILITY,
};

/// Copies the page's parent information: [`PARENT_INFO_DIRECT`] properties as they are,
/// [`PARENT_INFO_FALLBACK`] properties with `""` for falsy values.
#[must_use]
pub(crate) fn collect(signals: &PageSignals) -> JsObject {
    let parent = &signals.parent;
    // The probe reads properties by their `api.js` names.
    let properties = json!(parent);
    let mut fields =
        JsObject::from_iter([(PARENT_INFO_REFERRER.to_owned(), json!(signals.referrer))]);
    for (field, property) in PARENT_INFO_DIRECT {
        if let Some(value) = properties.get(property) {
            fields.insert(field.to_owned(), value.clone());
        }
    }
    for (field, property) in PARENT_INFO_FALLBACK {
        let value = properties.get(property).filter(|value| js::truthy(value));
        fields.insert(
            field.to_owned(),
            value.cloned().unwrap_or_else(|| json!("")),
        );
    }
    fields.insert(
        PARENT_INFO_VISIBILITY.to_owned(),
        json!(parent.viewport.visibility_state),
    );
    fields.insert(
        PARENT_INFO_REASONS.to_owned(),
        json!(parent.reasons.join("~")),
    );
    fields
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<()> {
    let strings = &probe.strings;
    let outputs = [
        PARENT_INFO_REFERRER,
        PARENT_INFO_MISSING,
        PARENT_INFO_REASONS,
        PARENT_INFO_PAD,
    ];
    let markers = ["pi", "pg.ref", "vDuh", "vDrs", "visibilityState", "pad"];
    (strings.stores_all(&outputs) && strings.has_all(&markers)).then_some(())
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;
    use crate::embedding_page::page::{Layout, RenderedPage};

    #[test]
    fn copies_the_page_signals_by_their_api_js_names() {
        let page = RenderedPage::render(
            "<html><body><div class=\"cf-turnstile\" data-sitekey=\"k\"></div></body></html>",
            Url::parse("https://example.com/").unwrap(),
            "w",
            None,
        )
        .unwrap();
        let layout = Layout {
            referrer: "https://example.com/from".into(),
            ..Layout::default()
        };
        let record = collect(&page.signals(&layout, None));
        let field = |property: &str| {
            let (field, _) = PARENT_INFO_DIRECT
                .iter()
                .chain(&PARENT_INFO_FALLBACK)
                .find(|(_, read)| *read == property)
                .unwrap();
            &record[*field]
        };
        assert_eq!(record[PARENT_INFO_REFERRER], "https://example.com/from");
        assert_eq!(*field("vDuh"), false);
        assert_eq!(*field("sL"), 0);
        assert_eq!(
            *field("vDmd"),
            "",
            "a falsy fallback property reads as empty"
        );
        assert_eq!(*field("vDmt"), "wrapper");
        assert_eq!(record[PARENT_INFO_VISIBILITY], "visible");
        assert_eq!(record[PARENT_INFO_REASONS], "");
    }
}
