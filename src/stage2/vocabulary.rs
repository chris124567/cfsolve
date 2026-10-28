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

use super::reference::REFERENCE;
use crate::js::{JsObject, JsValue};

/// Session names and the reference names they stand for.
#[derive(Debug)]
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
#[derive(Debug, Default)]
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
    /// Infers name mappings from each probe's collection strings.
    #[must_use]
    pub fn infer<S: AsRef<[String]>>(session: &[S]) -> Self {
        Self::between(session, &REFERENCE.probes)
    }

    fn between<S: AsRef<[String]>>(session: &[S], reference: &[Vec<String>]) -> Self {
        let (partners, candidates) = pair_probes(session, reference);
        let mut all = Votes::new();
        let mut probes = Vec::with_capacity(session.len());
        for (index, strings) in session.iter().enumerate() {
            let mut votes = Votes::new();
            if let Some(partner) = partners[index] {
                for pair in aligned_names(strings.as_ref(), &reference[partner - 1]) {
                    *votes.entry(pair).or_default() += 1;
                    *all.entry(pair).or_default() += 1;
                }
            }
            probes.push(Names::one_to_one(&votes));
        }
        Self {
            global: Names::one_to_one(&all),
            probes,
            partners,
            candidates,
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
        rewrite_object(object, &|name| {
            self.find(index, |names| &names.to_reference, name)
        });
    }

    pub fn rewrite_to_session(&self, index: usize, object: &mut JsObject) {
        rewrite_object(object, &|name| {
            self.find(index, |names| &names.to_session, name)
        });
    }
}

/// Renames strings and object keys using `rename`.
fn rewrite<'a>(value: &mut JsValue, rename: &impl Fn(&str) -> Option<&'a String>) {
    match value {
        JsValue::String(text) => {
            if let Some(name) = rename(text) {
                *text = name.clone();
            }
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

fn rewrite_object<'a>(object: &mut JsObject, rename: &impl Fn(&str) -> Option<&'a String>) {
    for (key, mut item) in mem::take(object) {
        rewrite(&mut item, rename);
        object.insert(rename(&key).cloned().unwrap_or(key), item);
    }
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
        // Below this threshold, probes share mostly common wrapper strings.
        if candidate.similarity < 0.5 {
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
fn aligned_names<'a>(session: &'a [String], reference: &'a [String]) -> Vec<(&'a str, &'a str)> {
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
    for run in matching_runs(&session, &reference) {
        let (mut left_names, left_texts): (Vec<_>, Vec<_>) = session[i..run.session]
            .iter()
            .copied()
            .partition(|text| is_name(text));
        let (mut right_names, right_texts): (Vec<_>, Vec<_>) = reference[j..run.reference]
            .iter()
            .copied()
            .partition(|text| is_name(text));
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
        .chunk_by(|left, right| left.is_ascii_alphanumeric() == right.is_ascii_alphanumeric())
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
fn is_name(text: &str) -> bool {
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
    fn token_boundaries_preserve_non_ascii_markup() {
        assert_eq!(tokens("é😀Aa12-中_foo"), ["é😀", "Aa12", "-中_", "foo"]);
    }

    fn strings(text: &str) -> Vec<String> {
        text.split(' ').map(str::to_owned).collect()
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
                aligned_names(&strings(session), &strings(reference)),
                expected
            );
        }
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
