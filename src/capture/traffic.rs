//! Records browser connections and requests in `traffic.json`, alongside session directories.
//! These records allow reconstruction of transport settings and delays between POSTs. Saved
//! response bodies go in `bodies/`, named by request.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::sessions;
use crate::{http, performance_clock};

/// The directory beside `traffic.json` holding kept response bodies.
const BODIES: &str = "bodies";

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Traffic {
    connections: Vec<Connection>,
    /// The requests, in the order they arrived.
    pub(super) requests: Vec<Request>,
}

/// One intercepted connection, as the browser opened it.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Connection {
    pub(super) host: String,
    pub(super) port: u16,
    /// The TLS records carrying the ClientHello, in hex.
    pub(super) client_hello: String,
    /// The protocol negotiated by ALPN.
    pub(super) alpn: Option<String>,
    /// The HTTP/2 preface and frames through the first request's header block, in hex.
    pub(super) h2_opening: Option<String>,
}

/// A request on an intercepted connection. hyper preserves header order, groups repeated values
/// at the first occurrence of their name, and lowercases names as HTTP/2 does.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Request {
    /// Index of this request's connection in `connections`.
    connection: usize,
    pub(super) method: String,
    pub(super) url: String,
    version: String,
    pub(super) headers: Vec<(String, String)>,
    /// Time received, in milliseconds since the Unix epoch.
    pub(super) received_ms: i64,
    /// Time the response was handed to the browser.
    pub(super) answered_ms: Option<i64>,
    /// The file holding the decoded response body, relative to `traffic.json`, if kept.
    #[serde(skip_serializing_if = "Option::is_none")]
    body_file: Option<String>,
    #[serde(skip)]
    body: Vec<u8>,
}

impl Traffic {
    /// Records a connection and returns the index used by its requests.
    pub(super) fn connect(&mut self, connection: Connection) -> usize {
        self.connections.push(connection);
        self.connections.len() - 1
    }

    /// Records a request received now and returns the index used by [`Self::answered`].
    pub(super) fn request<B>(
        &mut self,
        connection: usize,
        url: &str,
        request: &hyper::Request<B>,
    ) -> usize {
        self.requests.push(Request {
            connection,
            method: request.method().to_string(),
            url: url.to_owned(),
            version: format!("{:?}", request.version()),
            headers: http::text_headers(request.headers())
                .map(|(name, value)| (name.to_owned(), value))
                .collect(),
            received_ms: performance_clock::epoch_ms(),
            answered_ms: None,
            body_file: None,
            body: Vec::new(),
        });
        self.requests.len() - 1
    }

    /// Records the current time as the response time for request `index`.
    pub(super) fn answered(&mut self, index: usize) {
        self.requests[index].answered_ms = Some(performance_clock::epoch_ms());
    }

    /// Saves request `index`'s decoded response body as `kind` when [`Self::write`] runs.
    pub(super) fn keep(&mut self, index: usize, kind: &str, body: Vec<u8>) {
        let request = &mut self.requests[index];
        request.body_file = Some(format!("{BODIES}/{index:04}-{kind}"));
        request.body = body;
    }

    /// Writes `traffic.json` and the kept bodies into the existing `dir`, returning the log's path.
    pub(super) fn write(&self, dir: &Path) -> Result<PathBuf> {
        for request in &self.requests {
            if let Some(file) = &request.body_file {
                let bodies = dir.join(BODIES);
                fs::create_dir_all(&bodies)
                    .with_context(|| format!("creating {}", bodies.display()))?;
                sessions::write_file(&dir.join(file), &request.body)?;
            }
        }
        let path = dir.join("traffic.json");
        sessions::write_file(&path, serde_json::to_string_pretty(self)?)?;
        Ok(path)
    }
}

impl Request {
    /// Creates a request received at the current time on connection 0.
    #[cfg(test)]
    pub(super) fn received(method: &str, url: &str, headers: Vec<(String, String)>) -> Self {
        Self {
            connection: 0,
            method: method.to_owned(),
            url: url.to_owned(),
            version: "HTTP/2.0".to_owned(),
            headers,
            received_ms: performance_clock::epoch_ms(),
            answered_ms: None,
            body_file: None,
            body: Vec::new(),
        }
    }

    /// Returns the value of header `name`. The name must be lowercase.
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        let mut headers = self.headers.iter();
        headers.find_map(|(header, value)| (header == name).then_some(value.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_bodies_are_written_beside_the_log_named_by_their_requests() {
        let dir = std::env::temp_dir().join(format!("traffic-bodies-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let mut traffic = Traffic::default();
        let request = hyper::Request::new(());
        let page = traffic.request(0, "https://example.com/", &request);
        let script = traffic.request(0, "https://example.com/v1", &request);
        traffic.keep(script, "orchestrator.js", b"script".to_vec());
        let log: serde_json::Value =
            serde_json::from_slice(&fs::read(traffic.write(&dir).unwrap()).unwrap()).unwrap();
        assert!(log["requests"][page].get("bodyFile").is_none());
        let file = log["requests"][script]["bodyFile"].as_str().unwrap();
        assert_eq!(file, "bodies/0001-orchestrator.js");
        assert_eq!(fs::read(dir.join(file)).unwrap(), b"script");
        let read: Traffic = serde_json::from_value(log).unwrap();
        assert_eq!(read.requests[script].url, "https://example.com/v1");
        fs::remove_dir_all(dir).unwrap();
    }
}
