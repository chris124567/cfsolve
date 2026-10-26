//! Typed [`JsObject`]s for the iframe's `_cf_chl_opt` options, window globals, and plaintext
//! payloads, kept apart so callers cannot mix them up.

use std::ops::{Deref, DerefMut};

use serde::{Deserialize, Serialize};

use crate::js::{JsObject, JsValue};

macro_rules! object {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
        #[serde(transparent)]
        pub struct $name(JsObject);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self::default()
            }
        }

        impl Deref for $name {
            type Target = JsObject;

            fn deref(&self) -> &JsObject {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut JsObject {
                &mut self.0
            }
        }

        impl From<JsObject> for $name {
            fn from(properties: JsObject) -> Self {
                Self(properties)
            }
        }

        impl From<$name> for JsValue {
            fn from(object: $name) -> Self {
                Self::Object(object.0)
            }
        }

        impl IntoIterator for $name {
            type Item = (String, JsValue);
            type IntoIter = indexmap::map::IntoIter<String, JsValue>;

            fn into_iter(self) -> Self::IntoIter {
                self.0.into_iter()
            }
        }

        impl FromIterator<(String, JsValue)> for $name {
            fn from_iter<I: IntoIterator<Item = (String, JsValue)>>(properties: I) -> Self {
                Self(properties.into_iter().collect())
            }
        }
    };
}

object! {
    /// `window._cf_chl_opt`.
    Options
}

object! {
    /// Globals on the window, or on the namespace the challenge script keeps there.
    Window
}

object! {
    /// A payload before encoding.
    Payload
}
