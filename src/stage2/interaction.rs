//! Recovers checkbox session data and proof settings for native interaction handling.

pub mod checkbox;
pub(crate) mod click;
mod css;
pub(crate) mod diagnostics;
pub(crate) mod initialization;
pub(crate) mod native;
mod plan;
pub(crate) mod ui;

pub use plan::{Plan, recover};
