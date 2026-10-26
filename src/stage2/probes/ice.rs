//! Refreshes recorded ICE connection state while preserving its format and timing.
//!
//! Reports recorded host candidates, matching a network that blocks UDP. Does not query STUN
//! servers, since they would report this machine's address instead of the proxy's.
//!
//! The probe reuses a connection opened earlier. Chrome's recorded startup connection shares
//! one mDNS name among host candidates; WebKit's uses a separate name for each. Keeps candidate
//! lines, timing offsets, shared names and foundations, and offer codec and attribute order.
//! Generates a fresh session ID, credentials, certificate fingerprint, mDNS names, foundations,
//! and ports.

use std::collections::HashMap;

use anyhow::{Context, Result};

use super::media::{self, Candidate, Measurement};
use crate::js::{JsValue, json};
use crate::{performance_clock, random_id};

/// ICE credentials draw from the ice-char set (RFC 8839).
const ICE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn tokens(line: &str) -> Vec<String> {
    line.split(' ').map(str::to_owned).collect()
}

fn is_host(tokens: &[String]) -> bool {
    tokens.get(7).is_some_and(|kind| kind == "host")
}

/// Session identity shared by candidates and SDP.
struct Identity {
    ufrag: String,
}

impl Identity {
    fn new() -> Self {
        Self {
            ufrag: random_id::random_id(ICE_CHARS, 4),
        }
    }

    /// Formats `template` with this session's foundation, address, port, and ufrag.
    fn candidate(&self, template: &[String], foundation: u32, address: &str, port: u16) -> String {
        let mut tokens = template.to_vec();
        tokens[0] = format!("candidate:{foundation}");
        tokens[4] = address.to_owned();
        tokens[5] = port.to_string();
        if let Some(position) = tokens.iter().position(|token| token == "ufrag")
            && let Some(ufrag) = tokens.get_mut(position + 1)
        {
            ufrag.clone_from(&self.ufrag);
        }
        tokens.join(" ")
    }

    /// The recorded offer with this session's ID, credentials, and certificate fingerprint.
    fn offer(&self, sdp: &str) -> String {
        let session = u64::from_le_bytes(random()) >> 1;
        let password = random_id::random_id(ICE_CHARS, 24);
        let fingerprint = random::<32>().map(|byte| format!("{byte:02X}")).join(":");
        let lines: Vec<String> = sdp
            .split("\r\n")
            .map(|line| {
                if let Some(origin) = line.strip_prefix("o=- ") {
                    let rest = origin.split_once(' ').map_or("", |(_, rest)| rest);
                    format!("o=- {session} {rest}")
                } else if line.starts_with("a=ice-ufrag:") {
                    format!("a=ice-ufrag:{}", self.ufrag)
                } else if line.starts_with("a=ice-pwd:") {
                    format!("a=ice-pwd:{password}")
                } else if line.starts_with("a=fingerprint:sha-256 ") {
                    format!("a=fingerprint:sha-256 {fingerprint}")
                } else {
                    line.to_owned()
                }
            })
            .collect();
        lines.join("\r\n")
    }
}

/// Replaces `previous`'s connection state with a fresh one, keeping its capabilities and timing.
/// Candidates that shared an mDNS name or a foundation in the recording share the fresh one.
pub(crate) fn refresh(previous: Measurement) -> Result<Measurement> {
    let Measurement::Observed {
        preparation,
        snapshot: mut recorded,
    } = previous
    else {
        // A device without a peer connection has no ICE state to refresh.
        return Ok(previous);
    };
    let recorded_started_ms = recorded.started_ms;
    let connection = &mut recorded.connection;
    let offer = connection
        .sdp
        .as_ref()
        .and_then(JsValue::as_str)
        .context("the profile's media connection has no SDP")?;
    let identity = Identity::new();
    let offer = identity.offer(offer);
    let started_ms = performance_clock::epoch_ms();
    let mut names: HashMap<String, String> = HashMap::new();
    let mut foundations: HashMap<String, u32> = HashMap::new();
    let mut candidates = Vec::new();
    for recorded_candidate in &connection.published_candidates {
        let line = recorded_candidate
            .candidate
            .as_str()
            .context("a recorded media candidate is not a line")?;
        let tokens = tokens(line);
        if !is_host(&tokens) {
            continue;
        }
        let address = names
            .entry(tokens[4].clone())
            .or_insert_with(|| format!("{}.local", uuid()));
        let foundation = *foundations
            .entry(tokens[0].clone())
            .or_insert_with(|| u32::from_le_bytes(random()));
        let candidate = identity.candidate(&tokens, foundation, address, port());
        let offset = media::delta(recorded_candidate.observed_ms, recorded_started_ms)?;
        candidates.push(Candidate {
            candidate: json!(candidate),
            observed_ms: started_ms + offset,
        });
    }
    connection.sdp = Some(json!(offer));
    connection.published_candidates = candidates;
    recorded.finished_ms = started_ms + media::delta(recorded.finished_ms, recorded_started_ms)?;
    recorded.started_ms = started_ms;
    Ok(Measurement::Observed {
        preparation,
        snapshot: recorded,
    })
}

/// An ephemeral port for a host candidate's socket.
fn port() -> u16 {
    u16::from_le_bytes(random()) | 0x8000
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).expect("drawing random bytes");
    bytes
}

/// A version 4 UUID, as Chrome names its mDNS host candidates.
fn uuid() -> String {
    let mut bytes: [u8; 16] = random();
    bytes[6] = bytes[6] & 0x0f | 0x40;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::js;
    use crate::stage2::probes::media::Snapshot;

    const HOST: &str = "candidate:3174898844 1 udp 2113937151 683b0180-f338-4571-ad28-b634f6420e8c.local 43201 typ host generation 0 ufrag 8/6Q network-cost 999";
    const OTHER_HOST: &str = "candidate:1236921985 1 udp 2113937151 624f554e-e7a7-4613-8022-f2f6d9f1a264.local 57490 typ host generation 0 ufrag 8/6Q network-cost 999";
    const REFLEXIVE: &str = "candidate:4127496462 1 udp 1677729535 192.0.2.1 52263 typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag 8/6Q network-cost 999";

    #[test]
    fn candidates_keep_the_recorded_format_with_fresh_state() {
        let first = HOST.replace("2113937151", "2113937152");
        let identity = Identity {
            ufrag: "Ab+/".to_owned(),
        };
        assert_eq!(
            identity.candidate(&tokens(&first), 7, "name.local", 4000),
            "candidate:7 1 udp 2113937152 name.local 4000 typ host generation 0 ufrag Ab+/ network-cost 999"
        );
    }

    #[test]
    fn offer_replaces_only_session_credentials_and_fingerprint() {
        let recorded = "v=0\r\no=- 3036271159841627750 2 IN IP4 127.0.0.1\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=ice-ufrag:8/6Q\r\na=ice-pwd:3RF6ZmLJJoaD2Ho+S87owtRH\r\na=fingerprint:sha-256 B4:32\r\na=rtpmap:111 opus/48000/2\r\n";
        let identity = Identity {
            ufrag: "Ab+/".to_owned(),
        };
        let offer = identity.offer(recorded);
        let lines: Vec<&str> = offer.split("\r\n").collect();
        assert_eq!(lines.len(), recorded.split("\r\n").count());
        assert!(lines[1].starts_with("o=- ") && lines[1].ends_with(" 2 IN IP4 127.0.0.1"));
        assert!(!offer.contains("3036271159841627750"));
        assert_eq!(lines[3], "a=ice-ufrag:Ab+/");
        assert_eq!(lines[4].len(), "a=ice-pwd:".len() + 24);
        assert!(!offer.contains("3RF6ZmLJJoaD2Ho+S87owtRH"));
        assert_eq!(lines[5].len(), "a=fingerprint:sha-256 ".len() + 95);
        assert_eq!(lines[6], "a=rtpmap:111 opus/48000/2");
        assert!(offer.ends_with("\r\n"));
    }

    /// A refreshed connection with candidate arrival times relative to its start.
    fn refreshed(candidates: &[(&str, i64)]) -> Measurement {
        let candidates: Vec<JsValue> = candidates
            .iter()
            .map(|&(candidate, offset)| json!({"candidate": candidate, "observed_ms": 1000 + offset}))
            .collect();
        let recorded = js::from_value(json!({
            "outcome": "observed",
            "preparation": {"receiver": {"outcome": "unavailable"}, "type_support": []},
            "snapshot": {
                "connection": {"data_channel": true, "sdp": "v=0\r\na=ice-ufrag:8/6Q\r\n",
                    "pub_candidates": candidates},
                "started_ms": 1000, "finished_ms": 1154, "ice_state": "gathering"
            }
        }))
        .unwrap();
        refresh(recorded).unwrap()
    }

    /// The fresh snapshot, and the tokens of each candidate it published.
    fn published(measurement: &Measurement) -> (&Snapshot, Vec<Vec<String>>) {
        let Measurement::Observed { snapshot, .. } = measurement else {
            panic!("an observed connection");
        };
        let candidates = snapshot.connection.published_candidates.iter();
        let lines = candidates.map(|candidate| tokens(candidate.candidate.as_str().unwrap()));
        (snapshot, lines.collect())
    }

    #[test]
    fn refreshing_keeps_only_host_candidates_and_their_timing() {
        let measured = refreshed(&[(HOST, -100), (REFLEXIVE, -84), (OTHER_HOST, -83)]);
        let (snapshot, lines) = published(&measured);
        let offsets: Vec<i64> = snapshot
            .connection
            .published_candidates
            .iter()
            .map(|candidate| candidate.observed_ms - snapshot.started_ms)
            .collect();
        assert_eq!(offsets, [-100, -83]);
        assert_eq!(snapshot.finished_ms - snapshot.started_ms, 154);
        for tokens in &lines {
            assert!(is_host(tokens) && tokens[4].ends_with(".local"));
            assert!(!HOST.contains(&tokens[4]) && !OTHER_HOST.contains(&tokens[4]));
        }
        assert_ne!(lines[0][4], lines[1][4], "WebKit names each host candidate");
        assert_ne!(lines[0][0], lines[1][0]);
    }

    #[test]
    fn candidates_that_shared_a_name_and_foundation_still_do() {
        let measured = refreshed(&[(HOST, -398), (HOST, -396), (HOST, -396)]);
        let (_, lines) = published(&measured);
        let names: HashSet<&str> = lines.iter().map(|tokens| tokens[4].as_str()).collect();
        let foundations: HashSet<&str> = lines.iter().map(|tokens| tokens[0].as_str()).collect();
        assert_eq!((lines.len(), names.len(), foundations.len()), (3, 1, 1));
        assert_ne!(lines[0][0], "candidate:3174898844");
    }

    #[test]
    fn mdns_names_are_version_4_uuids() {
        let name = uuid();
        assert_eq!(name.len(), 36);
        assert_eq!(&name[14..15], "4");
        assert!("89ab".contains(&name[19..20]));
    }
}
