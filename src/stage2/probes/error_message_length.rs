//! Recognizes the probe that reports the length of the engine's `String.fromCodePoint(-1)` error
//! message, in [`reference::ERROR_MESSAGE_LENGTH_RESULT`].

use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

/// Builds can read the message using a property name stored in a register. Only `fromCodePoint` is
/// guaranteed to appear in the probe strings.
pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<()> {
    let strings = &probe.strings;
    (strings.has("fromCodePoint") && strings.stores(reference::ERROR_MESSAGE_LENGTH_RESULT))
        .then_some(())
}
