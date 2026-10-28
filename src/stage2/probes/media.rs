//! Builds media probe fields from API results and the connection an earlier probe left on the
//! window, which [`super::ice`] refreshes for each session. Candidate times use wall-clock
//! observations.

use std::borrow::Cow;

use anyhow::{Context, Result, ensure};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};

use crate::js::{self, ErrorValue, JsObject, JsValue, json};
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::reference::{
    MEDIA_CANDIDATE, MEDIA_CANDIDATE_TIME, MEDIA_CANDIDATES, MEDIA_CHANNEL_ERROR, MEDIA_CODECS,
    MEDIA_DATA_CHANNEL, MEDIA_ELAPSED, MEDIA_FIRST_CANDIDATE, MEDIA_ICE_STATE, MEDIA_PRIOR_COUNT,
    MEDIA_REUSED, MEDIA_SDP, MEDIA_SEED_GATHER_ERROR, MEDIA_SEED_OFFER_ERROR, MEDIA_STATE,
    MEDIA_SUPPORT, MEDIA_UNAVAILABLE,
};

/// Length of V8's error message for `String.fromCodePoint(-1)`: "Invalid code point -1". When
/// the length matches, the probe skips decoding excluded types.
const V8_MESSAGE_LENGTH: f64 = 21.0;

/// The MIME types the probe checks support for.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub audio_types: Vec<String>,
    pub video_types: Vec<String>,
    pub excluded_types: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Access {
    Returned { value: Option<JsValue> },
    Thrown { error: ErrorValue },
}

/// `RTCRtpReceiver.getCapabilities`, called for audio, then video.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Receiver {
    Unavailable,
    Observed { calls: Vec<Access> },
}

/// One `navigator.mediaCapabilities.decodingInfo` result.
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Decode {
    /// A type excluded by the probe, so no decoding check was made.
    Skipped,
    Failed,
    Resolved {
        properties: Option<JsObject>,
    },
}

/// Media API observations before opening a connection.
#[derive(Clone, Deserialize, Serialize)]
pub struct Preparation {
    pub receiver: Receiver,
    /// Absent if preparation stopped before MediaSource checks.
    pub type_support: Option<Vec<Option<JsValue>>>,
    /// Absent until `Promise.all` settles or when `decodingInfo` is unavailable.
    pub audio_decoding: Option<Vec<Decode>>,
    pub video_decoding: Option<Vec<Decode>>,
    /// The length of the engine's message for `String.fromCodePoint(-1)`.
    pub message_length: Option<JsValue>,
}

/// An ICE candidate and when it arrived, in epoch milliseconds.
#[derive(Clone, Deserialize, Serialize)]
pub struct Candidate {
    pub candidate: JsValue,
    pub observed_ms: i64,
}

/// The connection an earlier probe left on the window, which the probe reuses.
#[derive(Clone, Deserialize, Serialize)]
pub struct Connection {
    #[serde(rename = "pub_candidates")]
    pub published_candidates: Vec<Candidate>,
    #[serde(default, deserialize_with = "js::present")]
    pub data_channel: Option<JsValue>,
    /// The offer the earlier probe saved.
    pub sdp: Option<JsValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_error: Option<JsValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_error: Option<JsValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gather_error: Option<JsValue>,
}

/// The connection once the probe stopped waiting for candidates.
#[derive(Clone, Deserialize, Serialize)]
pub struct Snapshot {
    pub connection: Connection,
    pub started_ms: i64,
    pub finished_ms: i64,
    /// A getter failure is represented by null, matching the local catch.
    #[serde(default, deserialize_with = "js::present")]
    pub ice_state: Option<JsValue>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Measurement {
    /// The browser has no `RTCPeerConnection`.
    Unavailable,
    ConstructorFailed {
        preparation: Preparation,
    },
    Observed {
        preparation: Preparation,
        snapshot: Box<Snapshot>,
    },
}

pub(super) fn delta(end: i64, start: i64) -> Result<i64> {
    end.checked_sub(start)
        .context("media clock subtraction overflow")
}

/// Formats a codec as MIME type, optional audio clock rate, then format parameters.
fn codec(value: &JsValue, audio: bool) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let mut text = js::string(value.get("mimeType"));
    if audio {
        text = format!("{text}/{}", js::string(value.get("clockRate")));
    }
    if let Some(line) = value.get("sdpFmtpLine").filter(|line| js::truthy(line)) {
        text = format!("{text};{}", js::string(Some(line)));
    }
    Some(text)
}

/// Decoding result properties in bit order.
const DECODING_PROPERTIES: [&str; 3] = ["supported", "smooth", "powerEfficient"];

/// Encodes a decoding result as one bit per property.
fn decoding_bits(properties: &JsObject) -> i32 {
    DECODING_PROPERTIES
        .iter()
        .enumerate()
        .filter(|(_, key)| properties.get(**key).is_some_and(js::truthy))
        .fold(0, |bits, (bit, _)| bits | 1 << bit)
}

/// The record values built from observations taken before connection setup.
struct Prepared {
    codecs: JsValue,
    support: JsValue,
}

impl Fields {
    /// Builds codec and support fields from observations taken before connection setup.
    fn prepare(&self, preparation: &Preparation) -> Result<Prepared> {
        let mut codecs: [Vec<String>; 2] = [Vec::new(), Vec::new()];
        let mut stopped = false;
        if let Receiver::Observed { calls } = &preparation.receiver {
            ensure!(calls.len() <= 2, "extra RTP capability calls");
            for (index, call) in calls.iter().enumerate() {
                ensure!(!stopped, "RTP capability calls continued after failure");
                let Access::Returned { value } = call else {
                    stopped = true;
                    continue;
                };
                if let Some(value) = value.as_ref().filter(|value| js::truthy(value))
                    && let Some(listed) = value.get("codecs")
                    && js::truthy(listed)
                {
                    let spelled: Option<Vec<String>> = listed.as_array().and_then(|listed| {
                        listed
                            .iter()
                            .map(|value| codec(value, index == 0))
                            .collect()
                    });
                    match spelled {
                        Some(spelled) => codecs[index] = spelled,
                        None => stopped = true,
                    }
                }
            }
            ensure!(
                stopped || calls.len() == 2,
                "incomplete RTP capability calls"
            );
        }

        let supports = if stopped {
            ensure!(
                preparation.type_support.is_none()
                    && preparation.audio_decoding.is_none()
                    && preparation.video_decoding.is_none(),
                "media preparation continued after failure"
            );
            [Vec::new(), Vec::new()]
        } else {
            let observed = preparation
                .type_support
                .as_ref()
                .context("missing MediaSource observations")?;
            ensure!(
                observed.len() == self.audio_types.len() + self.video_types.len(),
                "wrong MediaSource observation count"
            );
            let bits: Vec<i8> = observed
                .iter()
                .map(|value| {
                    value
                        .as_ref()
                        .map_or(-1, |value| i8::from(js::truthy(value)))
                })
                .collect();
            let (audio, video) = bits.split_at(self.audio_types.len());
            [audio.to_vec(), video.to_vec()]
        };

        let excluded = preparation
            .message_length
            .as_ref()
            .and_then(JsValue::as_f64)
            == Some(V8_MESSAGE_LENGTH);
        let decode = |results: Option<&[Decode]>, types: &[String]| -> Result<JsValue> {
            let Some(results) = results else {
                return Ok(JsValue::Null);
            };
            ensure!(
                results.len() == types.len(),
                "wrong media decoding observation count"
            );
            let mut bits = Vec::new();
            for (result, mime) in results.iter().zip(types) {
                let skip = excluded && self.excluded_types.contains(mime);
                ensure!(
                    skip == matches!(result, Decode::Skipped),
                    "media decoding skipped the wrong MIME type"
                );
                bits.push(match result {
                    Decode::Skipped => 0,
                    Decode::Failed | Decode::Resolved { properties: None } => -1,
                    Decode::Resolved {
                        properties: Some(properties),
                    } => decoding_bits(properties),
                });
            }
            Ok(json!(bits))
        };
        Ok(Prepared {
            codecs: json!(codecs),
            support: json!([
                supports[0],
                supports[1],
                decode(preparation.audio_decoding.as_deref(), &self.audio_types)?,
                decode(preparation.video_decoding.as_deref(), &self.video_types)?
            ]),
        })
    }

    /// Builds the record from prepared API results and the reused connection. Every outcome
    /// creates its keys in the same order, then appends error keys.
    pub fn collect(&self, measurement: &Measurement) -> Result<JsObject> {
        let mut result = JsObject::from_iter([(MEDIA_STATE.to_owned(), json!(MEDIA_UNAVAILABLE))]);
        let (preparation, snapshot) = match measurement {
            Measurement::Unavailable => return Ok(result),
            Measurement::ConstructorFailed { preparation } => (preparation, None),
            Measurement::Observed {
                preparation,
                snapshot,
            } => (preparation, Some(snapshot)),
        };
        let Prepared { codecs, support } = self.prepare(preparation)?;
        result.insert(MEDIA_CODECS.to_owned(), codecs);
        let Some(snapshot) = snapshot else {
            return Ok(result);
        };
        let connection = &snapshot.connection;
        let sdp = connection
            .sdp
            .as_ref()
            .filter(|sdp| js::truthy(sdp))
            .context("the reused media connection saved no offer")?;
        let candidates = connection
            .published_candidates
            .iter()
            .map(|candidate| {
                let time = delta(candidate.observed_ms, snapshot.started_ms)?;
                Ok(JsValue::Object(JsObject::from_iter([
                    (MEDIA_CANDIDATE.to_owned(), candidate.candidate.clone()),
                    (MEDIA_CANDIDATE_TIME.to_owned(), json!(time)),
                ])))
            })
            .collect::<Result<Vec<_>>>()?;
        let first = if candidates.is_empty() {
            JsValue::Null
        } else {
            json!(0)
        };
        let elapsed = delta(snapshot.finished_ms, snapshot.started_ms)?;
        let reported = |error: Option<&JsValue>| error.filter(|error| js::truthy(error)).cloned();
        // A ready connection is reported using the state field's own name as its value.
        let fields = [
            (MEDIA_STATE, Some(json!(MEDIA_STATE))),
            (MEDIA_CANDIDATES, Some(json!(candidates))),
            (MEDIA_DATA_CHANNEL, connection.data_channel.clone()),
            (MEDIA_SDP, Some(sdp.clone())),
            (MEDIA_SUPPORT, Some(support)),
            (MEDIA_REUSED, Some(json!(true))),
            (MEDIA_PRIOR_COUNT, Some(json!(candidates.len()))),
            (MEDIA_FIRST_CANDIDATE, Some(first)),
            (MEDIA_ELAPSED, Some(json!(elapsed))),
            (MEDIA_ICE_STATE, snapshot.ice_state.clone()),
            (
                MEDIA_CHANNEL_ERROR,
                reported(connection.channel_error.as_ref()),
            ),
            (
                MEDIA_SEED_OFFER_ERROR,
                reported(connection.offer_error.as_ref()),
            ),
            (
                MEDIA_SEED_GATHER_ERROR,
                reported(connection.gather_error.as_ref()),
            ),
        ];
        for (field, value) in fields {
            if let Some(value) = value {
                result.insert(field.to_owned(), value);
            }
        }
        Ok(result)
    }

    /// Recovers browser observations from `record` using reference field names. [`Self::collect`]
    /// can then rebuild the record exactly. The connection snapshot begins at `started_ms`, the
    /// record start mark. Codecs retain only properties present in the record. Treats decoding as
    /// skipped for the V8 message length when no excluded type reports a result.
    pub fn observed(&self, record: &JsObject, started_ms: i64) -> Result<Measurement> {
        let measurement = self.read(record, started_ms)?;
        ensure!(
            self.collect(&measurement)? == *record,
            "the media record holds values the probe would not write"
        );
        Ok(measurement)
    }

    fn read(&self, record: &JsObject, started_ms: i64) -> Result<Measurement> {
        let field = |name: &str| {
            record
                .get(name)
                .with_context(|| format!("the media record has no `{name}`"))
        };
        if *field(MEDIA_STATE)? == MEDIA_UNAVAILABLE {
            return Ok(Measurement::Unavailable);
        }
        let spelled: [Vec<String>; 2] = js::from_value(field(MEDIA_CODECS)?.clone())
            .context("the media codecs are not two lists")?;
        let calls: Vec<Access> = spelled
            .iter()
            .enumerate()
            .map(|(index, spelled)| {
                let codecs: Vec<JsValue> = spelled
                    .iter()
                    .map(|text| unspell(text, index == 0))
                    .collect::<Result<_>>()?;
                Ok(Access::Returned {
                    value: Some(json!({ "codecs": codecs })),
                })
            })
            .collect::<Result<_>>()?;
        // Read MediaSource support bits followed by decoding bits or null, for audio first and then
        // video.
        let (audio_support, video_support, audio_decoding, video_decoding): (
            Vec<i8>,
            Vec<i8>,
            Option<Vec<i32>>,
            Option<Vec<i32>>,
        ) = js::from_value(field(MEDIA_SUPPORT)?.clone())
            .context("the media support is not four entries")?;
        let reported = [
            (&self.audio_types, &audio_decoding),
            (&self.video_types, &video_decoding),
        ];
        let excluded: Vec<i32> = reported
            .iter()
            .flat_map(|(types, bits)| types.iter().zip(bits.iter().flatten()))
            .filter(|(mime, _)| self.excluded_types.contains(mime))
            .map(|(_, &bits)| bits)
            .collect();
        let skipped = !excluded.is_empty() && excluded.iter().all(|&bits| bits == 0);
        let type_support = audio_support
            .iter()
            .chain(&video_support)
            .map(|&bit| (bit >= 0).then(|| json!(bit == 1)));
        let preparation = Preparation {
            receiver: Receiver::Observed { calls },
            type_support: Some(type_support.collect()),
            audio_decoding: self.decodes(&self.audio_types, audio_decoding, skipped),
            video_decoding: self.decodes(&self.video_types, video_decoding, skipped),
            message_length: skipped.then(|| json!(V8_MESSAGE_LENGTH)),
        };

        let candidates: Vec<JsObject> = js::from_value(field(MEDIA_CANDIDATES)?.clone())
            .context("the media candidates are not objects")?;
        let published_candidates: Vec<Candidate> = candidates
            .into_iter()
            .map(|mut candidate| {
                let time = candidate
                    .get(MEDIA_CANDIDATE_TIME)
                    .and_then(JsValue::as_i64)
                    .context("a media candidate has no time")?;
                Ok(Candidate {
                    candidate: candidate.shift_remove(MEDIA_CANDIDATE).unwrap_or_default(),
                    observed_ms: started_ms + time,
                })
            })
            .collect::<Result<_>>()?;
        let elapsed = field(MEDIA_ELAPSED)?
            .as_i64()
            .context("the media probe's elapsed time is not a number")?;
        let optional = |name: &str| record.get(name).cloned();
        Ok(Measurement::Observed {
            preparation,
            snapshot: Box::new(Snapshot {
                connection: Connection {
                    published_candidates,
                    data_channel: optional(MEDIA_DATA_CHANNEL),
                    sdp: optional(MEDIA_SDP),
                    channel_error: optional(MEDIA_CHANNEL_ERROR),
                    offer_error: optional(MEDIA_SEED_OFFER_ERROR),
                    gather_error: optional(MEDIA_SEED_GATHER_ERROR),
                },
                started_ms,
                finished_ms: started_ms + elapsed,
                ice_state: optional(MEDIA_ICE_STATE),
            }),
        })
    }

    /// Reconstructs one decoding result per type from `bits`, reversing [`decoding_bits`]. Omits
    /// excluded types when `skipped` is true.
    fn decodes(
        &self,
        types: &[String],
        bits: Option<Vec<i32>>,
        skipped: bool,
    ) -> Option<Vec<Decode>> {
        let decode = |(mime, bits): (&String, i32)| match bits {
            _ if skipped && self.excluded_types.contains(mime) => Decode::Skipped,
            -1 => Decode::Failed,
            bits => {
                let keys = DECODING_PROPERTIES.iter().enumerate();
                let properties =
                    keys.map(|(bit, key)| ((*key).to_owned(), json!(bits & (1 << bit) != 0)));
                Decode::Resolved {
                    properties: Some(properties.collect()),
                }
            }
        };
        Some(types.iter().zip(bits?).map(decode).collect())
    }
}

/// Parses the output of [`codec`], preserving only the properties present in the string.
fn unspell(text: &str, audio: bool) -> Result<JsValue> {
    let (head, line) = text
        .split_once(';')
        .map_or((text, None), |(head, line)| (head, Some(line)));
    let mut codec = JsObject::new();
    if audio {
        let (mime, rate) = head
            .rsplit_once('/')
            .and_then(|(mime, rate)| Some((mime, rate.parse::<f64>().ok()?)))
            .with_context(|| format!("audio codec {text} has no clock rate"))?;
        codec.insert("mimeType".to_owned(), json!(mime));
        codec.insert("clockRate".to_owned(), json!(rate));
    } else {
        codec.insert("mimeType".to_owned(), json!(head));
    }
    if let Some(line) = line {
        codec.insert("sdpFmtpLine".to_owned(), json!(line));
    }
    Ok(JsValue::Object(codec))
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Box<Fields>> {
    let strings = &probe.strings;
    if !strings.has_all(&[
        "RTCPeerConnection",
        "RTCRtpReceiver",
        "getCapabilities",
        "decodingInfo",
        MEDIA_STATE,
        MEDIA_CODECS,
        MEDIA_SUPPORT,
        MEDIA_CANDIDATES,
        MEDIA_SDP,
        MEDIA_ICE_STATE,
    ]) {
        return None;
    }
    // Builds may percent-encode the type lists.
    let decoded: Vec<Cow<'_, str>> = strings
        .features()
        .iter()
        .filter_map(|text| percent_decode_str(text).decode_utf8().ok())
        .collect();
    let find = |prefix: &str, codec: &str| {
        decoded
            .iter()
            .find(|text| text.starts_with(prefix) && text.contains(codec))
    };
    let audio = find("audio/mp4;", "mp4a.40.2")?;
    let video = find("video/mp4;", "avc1.42E01E")?;
    let excluded = find("audio/mp4;", "theora")?;
    let types = |list: &str| -> Vec<String> { list.split('A').map(str::to_owned).collect() };
    Some(Box::new(Fields {
        audio_types: types(audio),
        video_types: types(video),
        excluded_types: types(excluded),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe checks eight audio types and ten video types in this order.
    fn fields() -> Fields {
        let named = |kind: &str, count: usize| -> Vec<String> {
            (0..count).map(|index| format!("{kind}{index}")).collect()
        };
        Fields {
            audio_types: named("audio", 8),
            video_types: named("video", 10),
            // AC-3, E-AC-3 and Theora.
            excluded_types: vec!["audio1".into(), "audio2".into(), "video9".into()],
        }
    }

    /// Recover observations from each profile's media record and rebuild the same record, including
    /// skipped decoding on V8.
    #[test]
    fn reads_back_the_observations_a_record_reports() {
        // cfsolve.test ships only the Safari profile; the Chromium profile stays out.
        let profiles = [(include_str!("../../../profiles/safari-26-ios.json"), false)];
        for (profile, v8) in profiles {
            let profile: JsValue = serde_json::from_str(profile).unwrap();
            let media = profile["second"]["facts"]["media"].clone();
            let recorded: Measurement = js::from_value(media).unwrap();
            let record = fields().collect(&recorded).unwrap();
            let Measurement::Observed { preparation, .. } = fields().observed(&record, 5).unwrap()
            else {
                panic!("the profile's connection was not read back");
            };
            let skipped = preparation.message_length == Some(json!(V8_MESSAGE_LENGTH));
            assert_eq!(skipped, v8);
        }
        let unavailable = JsObject::from_iter([(MEDIA_STATE.to_owned(), json!(MEDIA_UNAVAILABLE))]);
        let read = fields().observed(&unavailable, 5).unwrap();
        assert!(matches!(read, Measurement::Unavailable));
    }
}
