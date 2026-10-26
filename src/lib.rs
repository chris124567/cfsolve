//! Solves Cloudflare challenges natively, including Turnstile widgets and challenge pages that
//! block access to a site.
//!
//! Load a [`Browser`] profile once and reuse it for multiple solves. Each solve has its own
//! cookies and proxy. Turnstile solves can use a page's URL and supplied HTML, including HTML
//! fetched behind a login. Challenge-page solves navigate to the protected page and obtain
//! clearance:
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! use cfsolve::{Browser, Options, PageSource, Turnstile};
//!
//! let browser = Browser::read("profiles/safari-26-ios.json")?;
//! let options = Options::default();
//! let turnstile = Turnstile {
//!     url: "https://example.com/login".parse()?,
//!     page: PageSource::Navigate,
//!     widget: None,
//! };
//! let token = browser.solve_turnstile(turnstile, &options).await?;
//! println!("submit {token} with the page's form");
//! let clearance = browser.clear(&"https://example.com/".parse()?, &options).await?;
//! println!("cf_clearance={}", clearance.clearance);
//! # Ok(())
//! # }
//! ```
//!
//! The other modules deobfuscate scripts, disassemble VM programs, and extract encoding and
//! payload data. The tools in this repository use them.

#![warn(unreachable_pub)]
// Without `internals`, items that only the repository's tools use look dead.
#![cfg_attr(
    not(feature = "internals"),
    allow(dead_code, unreachable_pub, unused_imports)
)]

mod browser;
mod candidates;
mod deep_stack;
mod deobfuscate;
mod embedding_page;
mod engine;
mod error;
mod listing;
mod performance_clock;
mod random_id;
mod resource_timing;
mod session;
mod solver;

// The analysis modules are public for the tools in this repository.
#[cfg(feature = "internals")]
#[doc(hidden)]
pub mod capture;
#[doc(hidden)]
pub mod challenge;
#[doc(hidden)]
pub mod fingerprint;
#[doc(hidden)]
pub mod http;
#[doc(hidden)]
pub mod js;
#[doc(hidden)]
pub mod script;
#[doc(hidden)]
pub mod stage2;
#[doc(hidden)]
pub mod vm;

pub use browser::Browser;
#[cfg(feature = "internals")]
#[doc(hidden)]
pub use deobfuscate::{Deobfuscated, Unconverged, deobfuscate};
pub use embedding_page::page::Widget;
pub use error::Error;
pub use http::PageDocument;
pub use js::{JsObject, JsValue};
pub use session::{Clearance, Outcome, Sink, Stage};
pub use solver::{FetchedPage, Options, PageSource, Turnstile};
pub use stage2::replay::Answers;
pub use url::Url;
pub use wreq::StatusCode;
pub use wreq::cookie::Cookie;
