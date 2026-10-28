//! HTTP transport and response handling for challenge sessions.

mod client;
mod decode;
mod header_order;
mod referrer;
mod requests;

#[cfg(feature = "internals")]
pub(crate) use client::Proxied;
pub use client::{BrowserClient, ClientHello, Requests};
pub use decode::{ResponseMetrics, header_text, read_encoded, text_headers};
#[cfg(feature = "internals")]
pub(crate) use decode::{decode_body, encode_body};
pub use header_order::HeaderOrder;
pub(crate) use header_order::RequestKind;
pub use referrer::ReferrerPolicy;
pub use requests::{
    FetchOptions, Iframe, PageDocument, ScriptLoad, fetch_from_worker, fetch_iframe, fetch_image,
    fetch_orchestrator, fetch_page_image, fetch_script, navigate, open_websocket, post_challenge,
    post_orchestrator, submit_form,
};
