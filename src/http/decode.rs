//! Decodes responses manually to retain encoded and decoded body sizes and server timing.

use std::io::{self, Read};

use anyhow::{Context, Result, bail};
use brotli::{CompressorReader, Decompressor};
use flate2::Compression;
use flate2::read::{GzDecoder, GzEncoder, ZlibDecoder, ZlibEncoder};
use serde::Serialize;
use wreq::header::{HeaderMap, HeaderValue};
use wreq::{RequestBuilder, Response};
use zstd::stream;

/// Response measurements: encoded and decoded body sizes and server timing.
#[derive(Debug, Default, Serialize)]
pub struct ResponseMetrics {
    pub encoded_bytes: u64,
    pub decoded_bytes: u64,
    pub content_encoding: String,
    pub server_timing: Vec<(String, f64)>,
}

/// Returns each `Server-Timing` metric's name and `dur`, skipping metrics without a duration.
fn server_timing(headers: &HeaderMap) -> Vec<(String, f64)> {
    headers
        .get_all("server-timing")
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| split_unquoted(header, ','))
        .filter_map(metric_duration)
        .collect()
}

/// Parses a `Server-Timing` metric's name and finite `dur`, if present.
fn metric_duration(metric: &str) -> Option<(String, f64)> {
    let mut parts = split_unquoted(metric, ';');
    let name = parts.next()?.trim();
    for part in parts {
        if let Some((key, value)) = part.trim().split_once('=')
            && key.trim().eq_ignore_ascii_case("dur")
            && let Ok(duration) = value.trim().trim_matches('"').parse::<f64>()
        {
            return duration.is_finite().then(|| (name.to_owned(), duration));
        }
    }
    None
}

/// Splits `text` at separators outside quoted strings. Backslash escapes any character inside
/// quotes.
fn split_unquoted(text: &str, separator: char) -> impl Iterator<Item = &str> {
    let (mut quoted, mut escaped) = (false, false);
    text.split(move |character| {
        match character {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            _ => return character == separator && !quoted,
        }
        false
    })
}

/// Reverses `Content-Encoding`, decoding in the reverse of the listed order.
pub(crate) fn decode_body(body: &[u8], encoding: &str) -> Result<Vec<u8>> {
    let mut decoded = body.to_vec();
    let last_applied_first = encoding.split(',').rev();
    for coding in last_applied_first {
        decoded = match coding.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => continue,
            "gzip" | "x-gzip" => read_all(GzDecoder::new(decoded.as_slice()))?,
            "deflate" => read_all(ZlibDecoder::new(decoded.as_slice()))?,
            "br" => read_all(Decompressor::new(decoded.as_slice(), 4096))?,
            "zstd" => stream::decode_all(decoded.as_slice())?,
            other => bail!("unsupported content encoding {other}"),
        };
    }
    Ok(decoded)
}

/// Restores `Content-Encoding` after the capture proxy rewrites a body, reversing
/// [`decode_body`]. Rejects unsupported encodings so the caller can forward the original body.
pub(crate) fn encode_body(body: &[u8], encoding: &str) -> Result<Vec<u8>> {
    let level = Compression::default();
    let mut encoded = body.to_vec();
    for coding in encoding.split(',') {
        encoded = match coding.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => continue,
            "gzip" | "x-gzip" => read_all(GzEncoder::new(encoded.as_slice(), level))?,
            "deflate" => read_all(ZlibEncoder::new(encoded.as_slice(), level))?,
            // A 4 KiB buffer, quality 4, and a 4 MiB window.
            "br" => read_all(CompressorReader::new(encoded.as_slice(), 4096, 4, 22))?,
            "zstd" => stream::encode_all(encoded.as_slice(), 0)?,
            other => bail!("cannot re-encode content encoding {other}"),
        };
    }
    Ok(encoded)
}

fn read_all(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Keeps the encoded body for size measurements while accepting the browser's compression
/// formats.
pub(super) fn preserve_encoding(request: RequestBuilder) -> RequestBuilder {
    request.gzip(false).brotli(false).deflate(false).zstd(false)
}

/// A header value as text, with any invalid UTF-8 replaced.
#[must_use]
pub fn header_text(value: &HeaderValue) -> String {
    String::from_utf8_lossy(value.as_bytes()).into_owned()
}

/// Returns header names and values in order, formatting values with [`header_text`].
pub fn text_headers(headers: &HeaderMap) -> impl Iterator<Item = (&str, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), header_text(value)))
}

/// Decodes an HTTP response and retains its encoded and decoded body sizes.
pub async fn read_encoded(response: Response) -> Result<(Vec<u8>, ResponseMetrics)> {
    let content_encoding = match response.headers().get("content-encoding") {
        Some(value) => value.to_str()?.to_owned(),
        None => String::new(),
    };
    let server_timing = server_timing(response.headers());
    let uri = response.uri().to_string();
    let encoded = response.bytes().await?;
    let decoded = decode_body(&encoded, &content_encoding)
        .with_context(|| format!("decoding the body of {uri}"))?;
    let metrics = ResponseMetrics {
        encoded_bytes: encoded.len() as u64,
        decoded_bytes: decoded.len() as u64,
        content_encoding,
        server_timing,
    };
    Ok((decoded, metrics))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_round_trip_through_each_coding() {
        let body = b"iframe content that must retain its exact decoded byte count";
        for encoding in ["br", "zstd", "deflate", "gzip", "identity"] {
            let encoded = encode_body(body, encoding).unwrap();
            assert_eq!(decode_body(&encoded, encoding).unwrap(), body, "{encoding}");
        }
        assert!(decode_body(body, "unsupported").is_err());
        assert!(decode_body(body, "gzip").is_err());
        let zstd = stream::encode_all(body.as_slice(), 1).unwrap();
        let gzip = read_all(GzEncoder::new(zstd.as_slice(), Compression::default())).unwrap();
        assert_eq!(
            decode_body(&gzip, "ZSTD, GZip").unwrap(),
            body,
            "codings are case-insensitive, and undone last first"
        );
    }

    #[test]
    fn server_timing_parameters_may_quote_separators() {
        let mut headers = HeaderMap::new();
        headers.append(
            "server-timing",
            r#"cache;desc="hit, fresh;ok \" ,";dur=1.5, db;DUR=53, total"#
                .parse()
                .unwrap(),
        );
        headers.append("server-timing", "cfL4;dur=\"7\"".parse().unwrap());
        assert_eq!(
            server_timing(&headers),
            [
                ("cache".to_owned(), 1.5),
                ("db".to_owned(), 53.0),
                ("cfL4".to_owned(), 7.0)
            ]
        );
    }
}
