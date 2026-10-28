//! Recovers rectangle-probe element IDs for the selector log. Replays the measured result.

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};

use crate::stage2::analysis::recognize::ProbeView;

/// Number of strings from the opening `<style>#` to the closing button, including fragments
/// interleaved with 27 ID references.
const MARKUP_STRINGS: usize = 28;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub ids: Vec<String>,
}

impl Fields {
    /// Returns queried selectors in order. The loop counts downward and skips the first
    /// element.
    #[must_use]
    pub fn selectors(&self) -> Vec<String> {
        self.ids
            .iter()
            .rev()
            .map(|id| format!("#{id}"))
            .chain(["#undefined".to_owned()])
            .collect()
    }
}

/// Recovers the ten alphanumeric element IDs the rectangle probe splits from one string.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let strings = probe.session_features;
    let start = strings.iter().position(|text| text == "<style>#")?;
    let end = strings
        .iter()
        .position(|text| text == "><button type=button></button></div>")?;
    if strings.get(start..=end)?.len() != MARKUP_STRINGS
        || !strings
            .iter()
            .any(|text| text.starts_with("position:fixed;left:0;top:0;width:800px;"))
    {
        return None;
    }
    // Match `list.split(separator)`, including lists decoded from percent encoding first.
    (2..strings.len()).find_map(|at| {
        let separator = &strings[at - 1];
        if strings[at] != "split" || separator.is_empty() {
            return None;
        }
        let list = match &strings[at - 2] {
            decode if decode == "decodeURIComponent" => strings.get(at.checked_sub(3)?)?,
            list => list,
        };
        let list = percent_decode_str(list).decode_utf8().ok()?;
        let ids: Vec<String> = list.split(separator.as_str()).map(str::to_owned).collect();
        let valid = ids.len() == 10
            && ids
                .iter()
                .all(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        valid.then_some(Fields { ids })
    })
}
