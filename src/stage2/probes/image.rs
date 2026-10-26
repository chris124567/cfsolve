//! Image load dimensions and the API properties sampled at completion.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use url::Url;

use super::platform;
use crate::js::{JsObject, JsValue, Options, json};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub timestamp_value: String,
    /// The session's option naming the platform segment of the request path.
    pub platform_property: String,
    pub url_path: String,
}

/// How the image's load ended, and the API properties sampled then.
pub struct Measurement {
    /// The dimensions of an image that loaded.
    pub dimensions: Option<Dimensions>,
    pub effective_type: String,
    pub online: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dimensions {
    pub width: u32,
    pub height: u32,
}

impl Measurement {
    /// Interprets an image response, reading `body` on success. Reports a load failure if the
    /// body has no recognizable dimensions.
    #[must_use]
    pub fn loaded(body: Option<&[u8]>, effective_type: &str, online: bool) -> Self {
        Self {
            dimensions: body.and_then(image_size),
            effective_type: effective_type.to_owned(),
            online,
        }
    }
}

/// The width and height a PNG, GIF or WebP header declares.
fn image_size(bytes: &[u8]) -> Option<Dimensions> {
    let big_endian = |at: usize| Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?));
    let little_endian = |at: usize, length: usize| {
        let mut word = [0; 4];
        word[..length].copy_from_slice(bytes.get(at..at + length)?);
        Some(u32::from_le_bytes(word))
    };
    let (width, height) = if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        (big_endian(16)?, big_endian(20)?)
    } else if bytes.starts_with(b"GIF8") {
        (little_endian(6, 2)?, little_endian(8, 2)?)
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP") {
        match bytes.get(12..16)? {
            b"VP8 " => (
                little_endian(26, 2)? & 0x3fff,
                little_endian(28, 2)? & 0x3fff,
            ),
            b"VP8X" => (little_endian(24, 3)? + 1, little_endian(27, 3)? + 1),
            _ => return None,
        }
    } else {
        return None;
    };
    Some(Dimensions { width, height })
}

impl Fields {
    /// Builds the probe resource URL from the platform path, family segment, and resource path.
    pub fn url(&self, options: &Options, input: &JsValue, base: &Url) -> Result<Url> {
        platform::url(
            options,
            &self.platform_property,
            &self.url_path,
            input,
            base,
        )
    }

    /// Builds the image record, with load-error markers in place of missing dimensions.
    #[must_use]
    pub fn collect(&self, input: &Measurement) -> JsObject {
        let (width, height) = match input.dimensions {
            Some(dimensions) => (dimensions.width.to_string(), dimensions.height.to_string()),
            None => (
                reference::IMAGE_LOAD_ERROR.to_owned(),
                reference::IMAGE_LOAD_ERROR.to_owned(),
            ),
        };
        let effective_type = if input.effective_type.is_empty() {
            "unknown"
        } else {
            input.effective_type.as_str()
        };
        let fields = [
            (reference::IMAGE_WIDTH, json!(width)),
            (reference::IMAGE_HEIGHT, json!(height)),
            (reference::IMAGE_TIMESTAMP, json!(self.timestamp_value)),
            (reference::IMAGE_EFFECTIVE_TYPE, json!(effective_type)),
            (reference::IMAGE_ONLINE, json!(input.online.to_string())),
            // The image has always finished loading when it is sampled.
            (reference::IMAGE_COMPLETE, json!("true")),
            (
                reference::IMAGE_NATURAL_WIDTH,
                json!(input.dimensions.map_or(0, |dimensions| dimensions.width)),
            ),
        ];
        JsObject::from_iter(fields.map(|(field, value)| (field.to_owned(), value)))
    }
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    let strings = &probe.strings;
    if !(strings.stores_all(&[
        reference::IMAGE_WIDTH,
        reference::IMAGE_HEIGHT,
        reference::IMAGE_EFFECTIVE_TYPE,
        reference::IMAGE_ONLINE,
        reference::IMAGE_COMPLETE,
        reference::IMAGE_NATURAL_WIDTH,
        reference::IMAGE_TIMESTAMP,
    ]) && strings.has_all(&[
        "naturalWidth",
        "preload",
        reference::IMAGE_LOAD_ERROR,
        reference::IMAGE_PENDING,
        reference::IMAGE_WORKER_TIMEOUT,
        reference::IMAGE_AWAITING,
    ])) {
        return None;
    }
    Some(Fields {
        timestamp_value: strings.decoded_after(reference::IMAGE_TIMESTAMP)?,
        platform_property: probe.session_name(reference::PLATFORM_OPTION),
        url_path: strings.decoded_starting("/ci/")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_image_dimensions_from_their_headers() {
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend(300u32.to_be_bytes());
        png.extend(65u32.to_be_bytes());
        let size = Some(Dimensions {
            width: 300,
            height: 65,
        });
        assert_eq!(image_size(&png), size);
        let gif = b"GIF89a\x2c\x01\x41\x00";
        assert_eq!(image_size(gif), size);
        assert_eq!(image_size(b"not an image"), None);
    }
}
