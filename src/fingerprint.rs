//! Reads browser facts from caller-supplied fingerprint JSON. Unknown keys are ignored, and each
//! program reads only the sections it needs.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq_util::{Platform, Profile};

use crate::engine::Engine;
use crate::http::{BrowserClient, ClientHello, Requests};

/// Reads the JSON file at `path` as `T`.
pub(crate) fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("reading fingerprint JSON {}", path.display()))
}

/// The fingerprint's `transport` section.
#[derive(Deserialize)]
pub(crate) struct TransportSection {
    profile: Profile,
    platform: Platform,
    /// Headers that replace the emulated profile's headers.
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    client_hello: ClientHello,
    requests: Requests,
}

/// Transport settings from the fingerprint's `engine` and `transport` sections.
pub struct Transport {
    pub engine: Engine,
    pub profile: Profile,
    pub platform: Platform,
    /// `transport.headers`, which replace those of the emulated profile.
    pub headers: HeaderMap,
    pub client_hello: ClientHello,
    pub requests: Requests,
}

impl Transport {
    /// Reads only the transport sections of the fingerprint at `path`.
    pub fn read(path: &Path) -> Result<Self> {
        #[derive(Deserialize)]
        struct Sections {
            engine: Engine,
            transport: TransportSection,
        }
        let sections: Sections = read(path)?;
        Self::try_new(sections.engine, sections.transport)
    }

    pub(crate) fn try_new(engine: Engine, transport: TransportSection) -> Result<Self> {
        let headers: Result<HeaderMap> = transport
            .headers
            .iter()
            .map(|(name, value)| {
                Ok((
                    HeaderName::from_bytes(name.as_bytes())?,
                    HeaderValue::from_str(value)?,
                ))
            })
            .collect();
        Ok(Self {
            engine,
            profile: transport.profile,
            platform: transport.platform,
            headers: headers.context("reading fingerprint `transport.headers`")?,
            client_hello: transport.client_hello,
            requests: transport.requests,
        })
    }

    /// Creates a client with this transport, optionally using `proxy`.
    pub fn client(&self, proxy: Option<&str>) -> Result<BrowserClient> {
        BrowserClient::try_new(
            self.profile,
            self.platform,
            self.headers.clone(),
            &self.client_hello,
            self.requests.clone(),
            self.engine,
            proxy,
        )
    }
}
