//! Recognizes the probe that reports the length of the engine's `String.fromCodePoint(-1)` error
//! message, in [`reference::ERROR_MESSAGE_LENGTH_RESULT`].

use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<()> {
    let strings = &probe.strings;
    (strings.has("fromCodePoint")
        && strings.has("message")
        && strings.stores(reference::ERROR_MESSAGE_LENGTH_RESULT))
    .then_some(())
}
