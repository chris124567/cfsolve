//! Maps randomized session names to reference-build names.
//!
//! Builds retain logic and browser API strings while renaming fields and states. Pair each
//! session probe with the reference probe sharing the most stable strings, align their string
//! sequences, then pair names between matching anchors.
//!
//! Probe-local mappings override the program-wide map because one build may reuse a name where
//! another uses separate names.

use std::collections::{HashMap, HashSet};
use std::mem;
use std::ops::Range;

use rustc_hash::FxHashMap;

use super::reference::{EXPANDED_REFERENCE, REFERENCE};
use crate::js::{JsObject, JsValue};

/// Session names and the reference names they stand for.
#[derive(Clone, Debug)]
pub struct Vocabulary {
    /// One-to-one name mapping for the whole program.
    global: Names,
    /// Each session probe's own pairs, by its position in the program.
    probes: Vec<Names>,
    /// Each session probe's reference probe, if it has one.
    partners: Vec<Option<usize>>,
    /// Each session probe's most similar reference probe.
    candidates: Vec<Option<Candidate>>,
}

/// A session probe's most similar reference probe, paired or not.
#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    /// The reference probe's number, counting from one as stored answers do.
    pub reference: usize,
    /// The Jaccard index of the two probes' stable strings.
    pub similarity: f64,
}

/// A one-to-one map between session and reference names.
#[derive(Clone, Debug, Default)]
struct Names {
    to_reference: HashMap<String, String>,
    to_session: HashMap<String, String>,
}

type Votes<'text> = HashMap<(&'text str, &'text str), usize>;

impl Names {
    /// Keeps name pairs with the strongest support in both directions. Both names must select
    /// each other.
    fn one_to_one(votes: &Votes<'_>) -> Self {
        let by_session = best_partners(votes, |(session, _)| session);
        let by_reference = best_partners(votes, |(_, reference)| reference);
        let mut names = Self::default();
        for &(session, reference) in by_session.intersection(&by_reference) {
            if session != reference {
                names.pair(session.to_owned(), reference.to_owned());
            }
        }
        names
    }

    /// Pairs `session` with `reference`, in place of any pair either name had.
    fn pair(&mut self, session: String, reference: String) {
        if let Some(old) = self.to_reference.remove(&session) {
            self.to_session.remove(&old);
        }
        if let Some(old) = self.to_session.remove(&reference) {
            self.to_reference.remove(&old);
        }
        self.to_reference.insert(session.clone(), reference.clone());
        self.to_session.insert(reference, session);
    }
}

impl Vocabulary {
    pub(crate) fn extend_expanded<S: AsRef<[String]>>(&mut self, session: &[S]) {
        let session = without_common_names(&expand_lists(session));
        let public: HashSet<&str> = REFERENCE
            .probes
            .iter()
            .flatten()
            .chain(EXPANDED_REFERENCE.probes.iter().flatten())
            .map(String::as_str)
            .collect();
        let clean: Vec<Vec<String>> = session
            .iter()
            .map(|strings| {
                strings
                    .iter()
                    .filter(|text| {
                        !is_log_message(text)
                            && !text.contains('\0')
                            && !text.starts_with("ÿÿ")
                            && (alignment_name(text) || public.contains(text.as_str()))
                    })
                    .cloned()
                    .collect()
            })
            .collect();
        self.align(&clean, &EXPANDED_REFERENCE.probes, true);
    }

    /// Infers name mappings from each probe's collection strings.
    #[must_use]
    pub fn infer<S: AsRef<[String]>>(session: &[S]) -> Self {
        Self::between(session, &REFERENCE.probes)
    }

    pub(crate) fn between<S: AsRef<[String]>>(session: &[S], reference: &[Vec<String>]) -> Self {
        let encoded_names = session
            .iter()
            .any(|probe| probe.as_ref().iter().any(|name| hashed_name(name)))
            || reference.iter().flatten().any(|name| hashed_name(name));
        let (partners, candidates) = pair_probes(session, reference);
        let mut vocabulary = Self {
            global: Names::default(),
            probes: vec![Names::default(); session.len()],
            partners,
            candidates,
        };
        if encoded_names {
            let session = expand_lists(session);
            let reference = expand_lists(reference);
            let (expanded, candidates) = pair_probes(&session, &reference);
            for (index, partner) in expanded.into_iter().enumerate() {
                if vocabulary.partners[index].is_none()
                    && partner.is_some()
                    && !vocabulary.partners.contains(&partner)
                {
                    vocabulary.partners[index] = partner;
                    vocabulary.candidates[index] = candidates[index];
                }
            }
            vocabulary.align(
                &without_common_names(&session),
                &without_common_names(&reference),
                true,
            );
        } else {
            vocabulary.align(session, reference, false);
        }
        vocabulary
    }

    fn align<S: AsRef<[String]>>(
        &mut self,
        session: &[S],
        reference: &[Vec<String>],
        encoded: bool,
    ) {
        let mut all = Votes::new();
        for (position, strings) in session.iter().enumerate() {
            let Some(partner) = self.partner(position) else {
                continue;
            };
            let mut votes = Votes::new();
            for pair in aligned_names(strings.as_ref(), &reference[partner - 1], encoded) {
                *votes.entry(pair).or_default() += 1;
                *all.entry(pair).or_default() += 1;
            }
            for (session, reference) in Names::one_to_one(&votes).to_reference {
                self.probes[position].pair(session, reference);
            }
        }
        for (session, reference) in Names::one_to_one(&all).to_reference {
            self.global.pair(session, reference);
        }
    }

    /// Replaces name pairs for probe `index` with mappings recovered from its code. Removes any
    /// existing pair involving either name. Used when code analysis identifies a field more
    /// reliably than string alignment.
    pub(crate) fn pin<'a>(
        &mut self,
        index: usize,
        pairs: impl IntoIterator<Item = (String, &'a str)>,
    ) {
        let Some(names) = self.probes.get_mut(index) else {
            return;
        };
        for (session, reference) in pairs {
            // Identical names are kept too, so the program-wide map cannot rename them.
            names.pair(session, reference.to_owned());
        }
    }

    pub(crate) fn refine_outputs(
        &mut self,
        position: usize,
        features: &[String],
        writes: &[String],
        internal: &[String],
        common: &HashSet<&str>,
        wanted: &[String],
    ) {
        let Some(partner) = self.partner(position) else {
            return;
        };
        if !writes.iter().any(|name| hashed_name(name)) {
            return;
        }
        let candidates: Vec<String> = writes
            .iter()
            .filter(|name| {
                let reference = self.to_reference(position, name);
                if !hashed_name(name)
                    || common.contains(name.as_str())
                    || (internal.contains(name) && !wanted.iter().any(|field| field == reference))
                {
                    return false;
                }
                reference == name.as_str() || wanted.iter().any(|field| field == reference)
            })
            .cloned()
            .collect();
        if candidates.len() == wanted.len()
            && wanted.iter().zip(&candidates).all(|(name, candidate)| {
                let mapped = self.to_session(position, name);
                mapped == name || mapped == candidate
            })
        {
            self.pin(
                position,
                candidates
                    .iter()
                    .cloned()
                    .zip(wanted.iter().map(String::as_str)),
            );
        }
        let keep = |text: &String, names: &[String]| !alignment_name(text) || names.contains(text);
        let session: Vec<String> = features
            .iter()
            .filter(|text| keep(text, &candidates))
            .cloned()
            .collect();
        let reference: Vec<String> = REFERENCE.probes[partner - 1]
            .iter()
            .filter(|text| keep(text, wanted))
            .cloned()
            .collect();
        let mut votes = Votes::new();
        for pair in aligned_names(&session, &reference, true) {
            if candidates.iter().any(|name| name == pair.0)
                && wanted.iter().any(|name| name == pair.1)
            {
                *votes.entry(pair).or_default() += 1;
            }
        }
        for (session, reference) in Names::one_to_one(&votes).to_reference {
            let mapped = self.to_session(position, &reference);
            if mapped == reference || !writes.iter().any(|name| name == mapped) {
                self.pin(position, [(session, reference.as_str())]);
            }
        }
    }

    /// The number of the reference probe the session probe at `index` was paired with.
    #[must_use]
    pub fn partner(&self, index: usize) -> Option<usize> {
        self.partners.get(index).copied().flatten()
    }

    /// The reference probe most similar to the session probe at `index`.
    #[must_use]
    pub fn candidate(&self, index: usize) -> Option<Candidate> {
        self.candidates.get(index).copied().flatten()
    }

    /// Translates `name` for probe `index` in direction `side`, preferring the probe's own pairs
    /// over the program-wide map.
    fn find(
        &self,
        index: usize,
        side: fn(&Names) -> &HashMap<String, String>,
        name: &str,
    ) -> Option<&String> {
        self.probes
            .get(index)
            .and_then(|local| side(local).get(name))
            .or_else(|| side(&self.global).get(name))
    }

    /// Returns the session name paired with reference name `name`, or `name` when no pair
    /// exists.
    #[must_use]
    pub fn to_session<'a>(&'a self, index: usize, name: &'a str) -> &'a str {
        self.find(index, |names| &names.to_session, name)
            .map_or(name, String::as_str)
    }

    /// Returns the reference name paired with session name `name`, or `name` when no pair
    /// exists.
    #[must_use]
    pub fn to_reference<'a>(&'a self, index: usize, name: &'a str) -> &'a str {
        self.find(index, |names| &names.to_reference, name)
            .map_or(name, String::as_str)
    }

    pub fn rewrite_to_reference(&self, index: usize, object: &mut JsObject) {
        rewrite_object(object, &|text| {
            rewrite_text(text, &|name| {
                self.find(index, |names| &names.to_reference, name)
            });
        });
    }

    pub fn rewrite_to_session(&self, index: usize, object: &mut JsObject) {
        rewrite_object(object, &|text| {
            rewrite_text(text, &|name| {
                self.find(index, |names| &names.to_session, name)
            });
        });
    }
}

fn expand_lists<S: AsRef<[String]>>(probes: &[S]) -> Vec<Vec<String>> {
    probes
        .iter()
        .map(|probe| {
            let decoded: HashMap<&str, String> = probe
                .as_ref()
                .windows(2)
                .filter_map(|pair| {
                    let text = if pair[1] == "decodeURIComponent" {
                        &pair[0]
                    } else if pair[0] == "decodeURIComponent" {
                        &pair[1]
                    } else {
                        return None;
                    };
                    let bytes = text.as_bytes();
                    if bytes.iter().enumerate().any(|(at, byte)| {
                        *byte == b'%'
                            && !bytes
                                .get(at + 1..at + 3)
                                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                    }) {
                        return None;
                    }
                    let decoded = percent_encoding::percent_decode_str(text)
                        .decode_utf8()
                        .ok()?;
                    (decoded != text.as_str()).then(|| (text.as_str(), decoded.into_owned()))
                })
                .collect();
            let prepared: Vec<_> = probe
                .as_ref()
                .iter()
                .map(|text| decoded.get(text.as_str()).unwrap_or(text).clone())
                .collect();
            let mut strings = prepared.as_slice();
            let mut expanded = Vec::new();
            while !strings.is_empty() {
                if let [list, separator, method, ..] = strings
                    && method == "split"
                    && separator.chars().count() == 1
                {
                    let parts: Vec<_> = list.split(separator).collect();
                    if parts.len() >= 3
                        && parts.iter().all(|part| !part.is_empty())
                        && (list.len() > 32 || parts.iter().all(|part| is_name(part)))
                    {
                        expanded.extend(parts.into_iter().map(str::to_owned));
                        strings = &strings[3..];
                        continue;
                    }
                }
                expanded.push(strings[0].clone());
                strings = &strings[1..];
            }
            expanded
        })
        .collect()
}

/// Inline decoders expose wrapper names previously held only in header registers.
/// Those names belong to the common envelope and cannot align probe-specific fields.
fn without_common_names<S: AsRef<[String]>>(probes: &[S]) -> Vec<Vec<String>> {
    let mut common: HashSet<&str> = probes
        .first()
        .into_iter()
        .flat_map(|probe| probe.as_ref())
        .map(String::as_str)
        .filter(|text| is_name(text))
        .collect();
    if probes.len() < 3 {
        common.clear();
    }
    for probe in probes.iter().skip(1) {
        common.retain(|name| probe.as_ref().iter().any(|text| text == name));
    }
    probes
        .iter()
        .map(|probe| {
            probe
                .as_ref()
                .iter()
                .filter(|text| !common.contains(text.as_str()))
                .cloned()
                .collect()
        })
        .collect()
}

/// Visits string values and object keys, preserving the recorded field order.
fn rewrite(value: &mut JsValue, rename: &impl Fn(&mut String)) {
    match value {
        JsValue::String(text) => {
            rename(text);
        }
        JsValue::Array(items) => {
            for item in items {
                rewrite(item, rename);
            }
        }
        JsValue::Object(object) => rewrite_object(object, rename),
        _ => {}
    }
}

pub(crate) fn rewrite_object(object: &mut JsObject, rename: &impl Fn(&mut String)) {
    for (mut key, mut item) in mem::take(object) {
        rewrite(&mut item, rename);
        rename(&mut key);
        object.insert(key, item);
    }
}

/// Session names also occur inside error messages, markup, property paths and digest inputs.
/// Read replacements from the original string so a replacement is never renamed twice.
fn rewrite_text<'a>(text: &mut String, rename: &impl Fn(&str) -> Option<&'a String>) {
    if let Some(name) = rename(text) {
        *text = name.clone();
        return;
    }
    let mut result = String::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let rest = &text[at..];
        let found = [25, 9, 8, 7, 6, 5, 4].into_iter().find_map(|length| {
            let name = rest.get(..length)?;
            let identifier = |c: char| c.is_alphanumeric() || matches!(c, '_' | '$');
            let before = !text[..at].chars().next_back().is_some_and(identifier);
            let after = !rest[length..].chars().next().is_some_and(identifier);
            // Fingerprint strings can concatenate a name with a digest or counter. Keep
            // those edge matches; inside a string, require a complete identifier.
            if !hashed_name(name) && at != 0 && at + length != text.len() && !(before && after) {
                return None;
            }
            is_name(name)
                .then(|| rename(name))
                .flatten()
                .map(|replacement| (length, replacement))
        });
        if let Some((length, replacement)) = found {
            result.push_str(replacement);
            at += length;
        } else {
            let character = rest.chars().next().unwrap();
            result.push(character);
            at += character.len_utf8();
        }
    }
    *text = result;
}

/// Chooses each name's pair with the most votes. Breaks ties by pair ordering so results are
/// deterministic.
fn best_partners<'a>(
    votes: &Votes<'a>,
    side: impl Fn((&'a str, &'a str)) -> &'a str,
) -> HashSet<(&'a str, &'a str)> {
    let mut best: HashMap<&str, ((&str, &str), usize)> = HashMap::new();
    for (&pair, &count) in votes {
        let (best_pair, best_count) = best.entry(side(pair)).or_insert((pair, 0));
        if count > *best_count || (count == *best_count && pair < *best_pair) {
            *best_pair = pair;
            *best_count = count;
        }
    }
    best.into_values().map(|(pair, _)| pair).collect()
}

/// The lowest similarity that pairs two probes. Below it, probes share mostly common wrapper
/// strings: unrelated probes score at most 0.2. The devtools probe scores only about 0.5 against
/// its reference, and drops to 0.49 in programs that never name `document`.
const MIN_PAIR_SIMILARITY: f64 = 0.35;

/// Pairs probes by descending Jaccard similarity of stable strings, using each reference probe
/// at most once. Also retains each session probe's closest reference match regardless of
/// pairing.
fn pair_probes<S: AsRef<[String]>>(
    session: &[S],
    reference: &[Vec<String>],
) -> (Vec<Option<usize>>, Vec<Option<Candidate>>) {
    let session_sets = distinctive(session.iter().map(AsRef::as_ref));
    let reference_sets = distinctive(reference.iter().map(Vec::as_slice));
    // Each session probe's position, with one reference probe's similarity.
    let mut pairings: Vec<(usize, Candidate)> = Vec::new();
    for (index, session_set) in session_sets.iter().enumerate() {
        for (reference_probe, reference_set) in reference_sets.iter().enumerate() {
            let shared = session_set.intersection(reference_set).count();
            let all = session_set.union(reference_set).count();
            // Probes containing only wrapper strings match each other.
            let similarity = if all == 0 {
                1.0
            } else {
                shared as f64 / all as f64
            };
            let candidate = Candidate {
                reference: reference_probe + 1,
                similarity,
            };
            pairings.push((index, candidate));
        }
    }
    pairings.sort_by(|(_, a), (_, b)| b.similarity.total_cmp(&a.similarity));
    let mut best = vec![None; session.len()];
    for &(index, candidate) in &pairings {
        best[index].get_or_insert(candidate);
    }
    let mut used = HashSet::new();
    let mut pairs = vec![None; session.len()];
    for (index, candidate) in pairings {
        if candidate.similarity < MIN_PAIR_SIMILARITY {
            break;
        }
        if pairs[index].is_none() && used.insert(candidate.reference) {
            pairs[index] = Some(candidate.reference);
        }
    }
    (pairs, best)
}

/// Returns strings that identify a probe across builds. Excludes randomized names, encrypted log
/// messages regenerated for each build, and shared wrapper strings renamed together within a
/// program.
fn distinctive<'a>(probes: impl Iterator<Item = &'a [String]>) -> Vec<HashSet<&'a str>> {
    let mut sets: Vec<HashSet<&str>> = probes
        .map(|strings| {
            strings
                .iter()
                .map(String::as_str)
                .filter(|text| !is_name(text) && !is_log_message(text))
                .collect()
        })
        .collect();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for set in &sets {
        for text in set {
            *counts.entry(text).or_default() += 1;
        }
    }
    let probe_count = sets.len();
    for set in &mut sets {
        set.retain(|text| 2 * counts[text] < probe_count);
    }
    sets
}

/// Checks for an encrypted log message in the form `<base64>$<base64>`.
fn is_log_message(text: &str) -> bool {
    let is_base64 = |part: &str| {
        !part.is_empty()
            && part
                .trim_end_matches('=')
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    };
    text.split_once('$')
        .is_some_and(|(cipher, iv)| is_base64(cipher) && is_base64(iv))
}

/// Aligns probe string sequences and pairs names between shared anchors. Requires equal counts
/// on both sides. Also compares differing strings at matching positions to recover embedded
/// names.
fn aligned_names<'a>(
    session: &'a [String],
    reference: &'a [String],
    encoded: bool,
) -> Vec<(&'a str, &'a str)> {
    // Collapse repeated API loads so duplicate reads for one call do not split runs used to
    // align neighboring output names.
    let mut session: Vec<&str> = session.iter().map(String::as_str).collect();
    let mut reference: Vec<&str> = reference.iter().map(String::as_str).collect();
    session.dedup();
    reference.dedup();
    // Shared strings remain anchors even if they resemble randomized identifiers, such as
    // `Math` or `log1p`, or have an unaligned occurrence.
    let shared: HashSet<&str> = session
        .iter()
        .copied()
        .filter(|text| reference.contains(text))
        .collect();
    let mut pairs = Vec::new();
    let (mut i, mut j) = (0, 0);
    let name = if encoded { alignment_name } else { is_name };
    for run in matching_runs(&session, &reference) {
        let (mut left_names, left_texts): (Vec<_>, Vec<_>) = session[i..run.session]
            .iter()
            .copied()
            .partition(|text| name(text));
        let (mut right_names, right_texts): (Vec<_>, Vec<_>) = reference[j..run.reference]
            .iter()
            .copied()
            .partition(|text| name(text));
        // Repeats of a name in a row count once, even across non-name text.
        left_names.dedup();
        right_names.dedup();
        if left_names.len() == right_names.len() {
            pairs.extend(left_names.into_iter().zip(right_names));
        }
        if left_texts.len() == right_texts.len() {
            for (left, right) in left_texts.into_iter().zip(right_texts) {
                pairs.extend(embedded_names(left, right));
            }
        }
        (i, j) = (run.session + run.length, run.reference + run.length);
    }
    pairs.retain(|(session, reference)| {
        session == reference || !shared.contains(session) && !shared.contains(reference)
    });
    pairs
}

/// Finds differing names in otherwise identical strings, such as markup containing
/// build-specific element IDs.
fn embedded_names<'a>(session: &'a str, reference: &'a str) -> Vec<(&'a str, &'a str)> {
    let (session, reference) = (tokens(session), tokens(reference));
    if session.len() != reference.len() {
        return Vec::new();
    }
    let mut names = Vec::new();
    for (session, reference) in session.into_iter().zip(reference) {
        if session == reference {
            continue;
        }
        if !is_name(session) || !is_name(reference) {
            return Vec::new();
        }
        names.push((session, reference));
    }
    names
}

/// Splits a string into alternating runs of ASCII letters and digits, and other characters.
fn tokens(text: &str) -> Vec<&str> {
    text.as_bytes()
        .chunk_by(|left, right| {
            (left.is_ascii_alphanumeric() || *left == b'_')
                == (right.is_ascii_alphanumeric() || *right == b'_')
        })
        // Boundaries fall only beside ASCII, never inside a UTF-8 character.
        .map(|part| std::str::from_utf8(part).expect("runs split only beside ASCII bytes"))
        .collect()
}

/// A run of strings the session and reference sequences share.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Run {
    /// Where the run starts in the session's strings.
    session: usize,
    /// Where the run starts in the reference's strings.
    reference: usize,
    length: usize,
}

/// Aligns sequences using their longest shared contiguous run, then recursively aligns the
/// parts before and after it. Appends an empty run at each end. Contiguous anchors prevent
/// distant repeated strings from distorting alignment.
fn matching_runs(session: &[&str], reference: &[&str]) -> Vec<Run> {
    let mut positions: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
    for (j, text) in reference.iter().enumerate() {
        positions.entry(text).or_default().push(j);
    }
    let mut runs = Vec::new();
    // Each pending span: its session rows and its reference columns.
    let mut pending = vec![(0..session.len(), 0..reference.len())];
    while let Some((rows, columns)) = pending.pop() {
        let run = longest_run(session, &positions, rows.clone(), columns.clone());
        if run.length > 0 {
            runs.push(run);
            pending.push((rows.start..run.session, columns.start..run.reference));
            pending.push((
                run.session + run.length..rows.end,
                run.reference + run.length..columns.end,
            ));
        }
    }
    runs.sort_unstable();
    runs.push(Run {
        session: session.len(),
        reference: reference.len(),
        length: 0,
    });
    runs
}

/// Finds the longest shared run within session `rows` and reference `columns`. `positions`
/// contains ordered reference positions for each string.
fn longest_run(
    session: &[&str],
    positions: &FxHashMap<&str, Vec<usize>>,
    rows: Range<usize>,
    columns: Range<usize>,
) -> Run {
    let mut best = Run {
        session: rows.start,
        reference: columns.start,
        length: 0,
    };
    // `run[j]` holds the previous row's match length ending at reference position `j`; `next`
    // holds the current row.
    let mut run: FxHashMap<usize, usize> = FxHashMap::default();
    let mut next = FxHashMap::default();
    for i in rows {
        next.clear();
        let occurrences = positions.get(session[i]).into_iter().flatten();
        for &j in occurrences {
            if j < columns.start {
                continue;
            }
            if j >= columns.end {
                break;
            }
            let length = j.checked_sub(1).and_then(|j| run.get(&j)).map_or(0, |n| *n) + 1;
            next.insert(j, length);
            if length > best.length {
                best = Run {
                    session: i + 1 - length,
                    reference: j + 1 - length,
                    length,
                };
            }
        }
        mem::swap(&mut run, &mut next);
    }
    best
}

/// Whether a string could be one of the program's randomized names.
fn alignment_name(text: &str) -> bool {
    if matches!(
        text,
        "Array"
            | "Boolean"
            | "Date"
            | "Error"
            | "Function"
            | "JSON"
            | "Math"
            | "Number"
            | "Object"
            | "Promise"
            | "Reflect"
            | "String"
            | "Symbol"
    ) {
        return false;
    }
    is_name(text)
}

pub(crate) fn hashed_name(text: &str) -> bool {
    text.strip_prefix('_')
        .is_some_and(|hex| hex.len() == 24 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

pub(crate) fn is_name(text: &str) -> bool {
    if hashed_name(text) {
        return true;
    }
    (4..=9).contains(&text.len())
        && text.starts_with(|c: char| c.is_ascii_alphabetic())
        && text.chars().all(|c| c.is_ascii_alphanumeric())
        && text
            .chars()
            .any(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js::json;

    #[test]
    fn rewrites_embedded_names_once_and_preserves_unicode() {
        let names = HashMap::from([
            ("_0123456789abcdef01234567".to_owned(), "Abcd1".to_owned()),
            ("Abcd1".to_owned(), "Efgh2".to_owned()),
        ]);
        let mut text = "é😀<p>_0123456789abcdef01234567</p>o.Abcd1".to_owned();
        rewrite_text(&mut text, &|name| names.get(name));
        assert_eq!(text, "é😀<p>Abcd1</p>o.Efgh2");
        for original in ["abcAbcd1xyz", "prefix_Abcd1_suffix", "$Abcd1$", "πAbcd1中"] {
            let mut opaque = original.to_owned();
            rewrite_text(&mut opaque, &|name| names.get(name));
            assert_eq!(opaque, original);
        }
        let mut fingerprint = "Abcd1611".to_owned();
        rewrite_text(&mut fingerprint, &|name| names.get(name));
        assert_eq!(fingerprint, "Efgh2611");
    }

    #[test]
    fn token_boundaries_preserve_non_ascii_markup() {
        assert_eq!(tokens("é😀Aa12-中_foo"), ["é😀", "Aa12", "-中", "_foo"]);
    }

    fn strings(text: &str) -> Vec<String> {
        text.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn packed_names_align_in_both_directions_across_identifier_formats() {
        let packed = "%41%61%61%61%31%7c%42%62%62%62%32%7c%43%63%63%63%33";
        let short = [strings(&format!(
            "Intl ListFormat style long type disjunction format {packed} decodeURIComponent {packed} | split | format Result1"
        ))];
        let hashed = [strings(
            "Intl ListFormat style long type disjunction format _111111111111111111111111 _222222222222222222222222 _333333333333333333333333 format _444444444444444444444444",
        )];
        for (session, reference, expected) in [
            (&short, &hashed, ("Aaaa1", "_111111111111111111111111")),
            (&hashed, &short, ("_111111111111111111111111", "Aaaa1")),
        ] {
            let vocabulary = Vocabulary::between(session, reference);
            assert_eq!(vocabulary.to_reference(0, expected.0), expected.1);
            assert_eq!(vocabulary.to_session(0, expected.1), expected.0);
        }
    }

    #[test]
    fn expands_only_valid_decoded_name_lists() {
        let valid = "%41%61%61%61%31%7c%42%62%62%62%32%7c%43%63%63%63%33";
        let features = strings(&format!("{valid} decodeURIComponent {valid} | split"));
        let expanded = expand_lists(&[features]);
        assert_eq!(&expanded[0][2..], ["Aaaa1", "Bbbb2", "Cccc3"]);
        let fonts = vec![
            strings("Sample Sans|Sample Serif|Sample Monospace").join(" "),
            "|".into(),
            "split".into(),
        ];
        assert_eq!(
            expand_lists(&[fonts])[0],
            ["Sample Sans", "Sample Serif", "Sample Monospace"]
        );
        for text in ["%41%", "%41%xx", "%FF", "Aaaa1|Bbbb2", "Aaaa1||Cccc3"] {
            let features = strings(&format!("{text} decodeURIComponent {text} | split"));
            assert_eq!(expand_lists(std::slice::from_ref(&features))[0], features);
        }
    }

    #[test]
    fn pairs_names_between_shared_strings() {
        let session = [strings(
            "pop length OfJgC4 OfJgC4 DgGDH1 :n.platform, Vaqi1 Zxcv3 <b_id=\"Qwer1\">",
        )];
        let reference = [strings(
            "pop length IOca9 DIEq4 :n.platform, Ijda0 <b_id=\"Asdf2\">",
        )];
        let vocabulary = Vocabulary::between(&session, &reference);
        assert_eq!(vocabulary.to_reference(0, "OfJgC4"), "IOca9");
        assert_eq!(vocabulary.to_reference(0, "DgGDH1"), "DIEq4");
        assert_eq!(vocabulary.to_reference(0, "Qwer1"), "Asdf2");
        for name in ["Vaqi1", "Zxcv3"] {
            assert_eq!(
                vocabulary.to_reference(0, name),
                name,
                "an uneven gap pairs nothing"
            );
        }
        let mut object = JsObject::from_iter([("IOca9".into(), json!(["DIEq4", "length"]))]);
        vocabulary.rewrite_to_session(0, &mut object);
        assert_eq!(
            JsValue::Object(object),
            json!({"OfJgC4": ["DgGDH1", "length"]})
        );
    }

    /// Checks that repeated API loads do not shift output-field mappings. A shared API string
    /// such as `Math` remains an anchor.
    #[test]
    fn aligned_names_pair_only_output_fields() {
        let cases = [
            (
                "String String Cmfg1 String String then Abcd2 String String then then catch catch Efgh3",
                "String Qrst1 String then Uvwx2 String then catch Yzab3",
                vec![("Cmfg1", "Qrst1"), ("Abcd2", "Uvwx2"), ("Efgh3", "Yzab3")],
            ),
            (
                "sqrt Math acosh Abcd1 toString",
                "Math sqrt log1p acosh Qrst1 toString",
                vec![("Abcd1", "Qrst1")],
            ),
        ];
        for (session, reference, expected) in cases {
            assert_eq!(
                aligned_names(&strings(session), &strings(reference), false),
                expected
            );
        }
    }

    /// A probe that shares only three of seven stable strings with its reference still pairs,
    /// as the devtools probe must when a program never names `document`.
    #[test]
    fn pairs_a_probe_below_half_similarity() {
        let session = [
            strings("debug stack console"),
            strings("fetch then"),
            strings("now floor"),
        ];
        let reference = [
            strings("debug stack console document create remove append"),
            strings("fetch then"),
            strings("now floor"),
        ];
        let (pairs, _) = pair_probes(&session, &reference);
        assert_eq!(pairs, [Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn prefers_a_probes_own_pairs_over_the_global_map() {
        // The reference reuses one name where the session has two.
        let session = [strings("a:b Abcd1 c:d"), strings("e:f Wxyz2 g:h")];
        let reference = [strings("a:b Qrst1 c:d"), strings("e:f Qrst1 g:h")];
        let vocabulary = Vocabulary::between(&session, &reference);
        assert_eq!(vocabulary.to_reference(0, "Abcd1"), "Qrst1");
        assert_eq!(vocabulary.to_reference(1, "Wxyz2"), "Qrst1");
        let mut object = JsObject::from_iter([("Qrst1".into(), json!("Qrst1"))]);
        vocabulary.rewrite_to_session(1, &mut object);
        assert_eq!(JsValue::Object(object), json!({"Wxyz2": "Wxyz2"}));
        assert_eq!(vocabulary.global.to_session.len(), 1);
    }

    #[test]
    fn pinned_names_replace_aligned_pairs_in_their_probe() {
        let session = [strings("a:b Abcd1 c:d"), strings("e:f Wxyz2 g:h")];
        let reference = [strings("a:b Qrst1 c:d"), strings("e:f Uvwx2 g:h")];
        let mut vocabulary = Vocabulary::between(&session, &reference);
        vocabulary.pin(0, [("Efgh3".into(), "Qrst1"), ("Ijkl4".into(), "Ijkl4")]);
        assert_eq!(vocabulary.to_reference(0, "Efgh3"), "Qrst1");
        assert_eq!(vocabulary.to_session(0, "Qrst1"), "Efgh3");
        assert_eq!(vocabulary.to_session(0, "Ijkl4"), "Ijkl4");
        let mut object = JsObject::from_iter([("Qrst1".into(), json!(1))]);
        vocabulary.rewrite_to_session(0, &mut object);
        assert_eq!(JsValue::Object(object), json!({"Efgh3": 1}));
        assert_eq!(vocabulary.to_session(1, "Uvwx2"), "Wxyz2");
    }
}
