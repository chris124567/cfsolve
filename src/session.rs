//! Runs a challenge session through first-payload preparation, probe analysis, and optional
//! probe and checkbox solving. Challenge pages wrap the widget in a separate orchestrator
//! session.
//!
//! All POSTs share one client and encoder, preserving cookies, transport settings, and the seed
//! generated at session startup. Writes artifacts and progress to [`Sink`] immediately so
//! diagnostics survive later failures.

mod challenge_page;
mod channel;
mod initial;
mod interaction;
mod probes;
mod sink;
mod timing;
mod widget;

pub use channel::Stage;
pub(crate) use sink::Discard;
pub use sink::Sink;
pub use widget::{Clearance, Outcome};
pub(crate) use widget::{Expect, native, navigate, prepare, send_first_payload};

#[cfg(test)]
mod tests {
    mod challenge_page;
}
