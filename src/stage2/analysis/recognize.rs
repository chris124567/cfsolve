//! Inputs to probe recognizers. Recognizers based on reference strings use names from a known
//! build; records are built with those names and renamed for the session afterward. Structural
//! recognizers read the current listing directly.

use std::collections::{BTreeSet, HashSet};

use crate::listing::{self, Index};
use crate::stage2::records::WriteOrder;
use crate::stage2::vocabulary::Vocabulary;

/// Collection strings and output names mapped to the reference build. Preserves string order
/// and duplicates; a separate set supports membership checks.
pub(crate) struct Strings<'probe> {
    features: &'probe [String],
    outputs: &'probe BTreeSet<String>,
    present: HashSet<&'probe str>,
}

impl<'probe> Strings<'probe> {
    #[must_use]
    pub(crate) fn new(features: &'probe [String], outputs: &'probe BTreeSet<String>) -> Self {
        Self {
            features,
            outputs,
            present: features.iter().map(String::as_str).collect(),
        }
    }

    /// The strings, in program order.
    #[must_use]
    pub(crate) fn features(&self) -> &'probe [String] {
        self.features
    }

    #[must_use]
    pub(crate) fn has(&self, text: &str) -> bool {
        self.present.contains(text)
    }

    #[must_use]
    pub(crate) fn has_all(&self, texts: &[&str]) -> bool {
        texts.iter().all(|text| self.has(text))
    }

    /// Checks whether the probe writes `name`. Reading another probe's result can mention the
    /// name without writing it.
    #[must_use]
    pub(crate) fn stores(&self, name: &str) -> bool {
        self.outputs.contains(name)
    }

    #[must_use]
    pub(crate) fn stores_all(&self, names: &[&str]) -> bool {
        names.iter().all(|name| self.stores(name))
    }

    /// Decodes the inline descriptor after the first occurrence of `text` that has one.
    #[must_use]
    pub(crate) fn decoded_after(&self, text: &str) -> Option<String> {
        let pair = self.features.windows(2).find(|pair| pair[0] == text)?;
        listing::decode_string(&pair[1], "").ok()
    }

    /// Returns the first inline-decoded string starting with `prefix`.
    #[must_use]
    pub(crate) fn decoded_starting(&self, prefix: &str) -> Option<String> {
        self.features
            .iter()
            .filter_map(|text| listing::decode_string(text, "").ok())
            .find(|text| text.starts_with(prefix))
    }
}

/// Recognition phase: reference matching before structural analysis.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Reference,
    Structural,
}

/// One probe, as its recognizers see it.
pub(crate) struct ProbeView<'probe> {
    /// The session's listing.
    pub index: &'probe Index<'probe>,
    /// Session-to-reference name mappings used by structural recognizers.
    pub vocabulary: &'probe Vocabulary,
    /// Where the probe sits among the program's probes, counting from zero.
    pub position: usize,
    /// The names the program's header loads.
    pub header: &'probe BTreeSet<String>,
    /// Wrapper strings shared by every probe in this program, using the session's names.
    pub wrapper: &'probe BTreeSet<String>,
    pub pool: &'probe str,
    /// Where its collection function starts.
    pub entry: u32,
    /// Its strings in the session's names.
    pub session_features: &'probe [String],
    /// Fields written by the probe, using the session's names.
    pub writes: &'probe WriteOrder,
    /// Its strings and outputs in the reference build's names.
    pub strings: Strings<'probe>,
}

impl ProbeView<'_> {
    /// The session's name for the reference build's `name`.
    #[must_use]
    pub(crate) fn session_name(&self, name: &str) -> String {
        self.vocabulary.to_session(self.position, name).to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stage2::reference::{self, REFERENCE};
    use crate::stage2::registry::{Kind, Operation};
    use crate::vm::Listing;

    /// Tests `kind` recognition using `features` and `outputs` with an empty listing.
    fn run(kind: Kind, features: &[String], outputs: &BTreeSet<String>) -> Option<Operation> {
        let listing = Listing::default();
        let index = Index::new(&listing);
        let vocabulary = Vocabulary::infer::<&[String]>(&[]);
        let header = BTreeSet::new();
        kind.recognize(&ProbeView {
            index: &index,
            vocabulary: &vocabulary,
            position: 0,
            header: &header,
            wrapper: &header,
            pool: "",
            entry: 0,
            session_features: features,
            writes: &WriteOrder::default(),
            strings: Strings::new(features, outputs),
        })
    }

    fn owned<C: FromIterator<String>>(texts: &[&str]) -> C {
        texts.iter().map(|text| (*text).to_owned()).collect()
    }

    /// Returns strings from the reference probe paired with `kind`.
    fn reference_probe(kind: Kind) -> Vec<String> {
        REFERENCE.probes[kind.references()[0] - 1].clone()
    }

    #[test]
    fn reading_another_probes_result_does_not_identify_its_operation() {
        const RESULT: &str = reference::ERROR_MESSAGE_LENGTH_RESULT;
        let features: Vec<String> = owned(&["fromCodePoint", "message", RESULT]);
        let first = |outputs: &[&str]| {
            let outputs = owned(outputs);
            Kind::in_phase(Phase::Reference).find_map(|kind| run(kind, &features, &outputs))
        };
        assert!(first(&[]).is_none());
        assert!(matches!(
            first(&[RESULT]),
            Some(Operation::ErrorMessageLength {})
        ));
    }

    /// Checks that markers alone distinguish each reference probe, even if all strings count as
    /// outputs. The environment audit also reads connection and media APIs, so broad API
    /// markers are insufficient.
    #[test]
    fn each_recognizer_recovers_only_its_own_reference_probe() {
        let probes = &REFERENCE.probes;
        assert_eq!(probes.len(), 38);
        for kind in [
            Kind::Media,
            Kind::PrivateToken,
            Kind::WorkerFetch,
            Kind::Image,
            Kind::NetworkInformation,
            Kind::WorkerNavigator,
        ] {
            let matched: Vec<usize> = probes
                .iter()
                .enumerate()
                .filter(|(_, features)| {
                    let outputs: BTreeSet<String> = features.iter().cloned().collect();
                    run(kind, features, &outputs).is_some()
                })
                .map(|(index, _)| index + 1)
                .collect();
            assert_eq!(matched, kind.references(), "{kind}");
        }
    }

    /// Checks that each recognizer accepts its reference outputs and rejects missing outputs.
    /// `tests/stage2.rs` snapshots verify the recovered operation.
    #[test]
    fn recognizers_need_every_output_stored() {
        use crate::stage2::probes::{private_token, worker_fetch};
        let cases: [(Kind, &[&str], &[&str]); 3] = [
            (
                Kind::PrivateToken,
                &private_token::OUTPUTS,
                &private_token::OUTPUTS[..4],
            ),
            (
                Kind::WorkerFetch,
                &worker_fetch::OUTPUTS,
                &worker_fetch::OUTPUTS[..1],
            ),
            (
                Kind::NetworkInformation,
                &reference::NETWORK_INFORMATION_OUTPUTS,
                &reference::NETWORK_INFORMATION_OUTPUTS[1..],
            ),
        ];
        for (kind, outputs, fewer) in cases {
            let features = reference_probe(kind);
            assert!(run(kind, &features, &owned(outputs)).is_some(), "{kind}");
            assert!(run(kind, &features, &owned(fewer)).is_none(), "{kind}");
        }
    }

    /// Checks that missing identifying lists or properties prevent recognition.
    #[test]
    fn recognizers_need_their_probes_strings() {
        let mut features = reference_probe(Kind::Media);
        assert!(run(Kind::Media, &features, &BTreeSet::new()).is_some());
        features.retain(|text| !text.starts_with("audio/mp4;"));
        assert!(run(Kind::Media, &features, &BTreeSet::new()).is_none());
        let outputs = owned(&crate::stage2::probes::worker_navigator::OUTPUTS);
        let mut features = reference_probe(Kind::WorkerNavigator);
        assert!(run(Kind::WorkerNavigator, &features, &outputs).is_some());
        features.retain(|text| !text.starts_with(":n.deviceMemory"));
        assert!(run(Kind::WorkerNavigator, &features, &outputs).is_none());
    }
}
