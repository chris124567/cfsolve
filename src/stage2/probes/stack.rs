//! Recovers the stack probe's output field and the VM calls leading to `new Error()`. Sessions
//! pass those calls to [`crate::stage2::call_stack::recover_probe`] to rebuild the frames.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::candidates;
use crate::js::{JsObject, json};
use crate::listing::Index;
use crate::stage2::analysis::recognize::ProbeView;
use crate::stage2::call_stack::ProbeCalls;
use crate::vm::Term;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Fields {
    pub result: String,
    /// Absent when the probe's calls have another shape.
    pub calls: Option<ProbeCalls>,
}

impl Fields {
    /// The record holding the rebuilt `stack`.
    #[must_use]
    pub fn collect(&self, stack: &str) -> JsObject {
        JsObject::from_iter([(self.result.clone(), json!(stack))])
    }
}

/// Finds the closure called by the probe function at `entry` to construct `new Error()`.
fn calls(index: &Index<'_>, entry: u32) -> Option<ProbeCalls> {
    let construct = index
        .effects_in(index.function_range(entry)?)
        .find_map(|(pc, effect)| {
            let (callee, _) = effect.call()?;
            let (_, Term::Closure { pc: closure, .. }) = index.dereference(pc, callee)? else {
                return None;
            };
            construction(index, closure)
        })?;
    Some(ProbeCalls {
        construct,
        arity: index.arity(entry)?,
    })
}

/// The opcode with which the function at `entry` constructs `new Error()`.
fn construction(index: &Index<'_>, entry: u32) -> Option<u8> {
    let instructions = &index.listing().instructions;
    index
        .effects_in(index.function_range(entry)?)
        .find_map(|(pc, effect)| {
            let mut constructs = false;
            effect.visit_terms(&mut |term| {
                if let Term::New { callee, arguments } = term
                    && arguments.is_empty()
                    && index.method(pc, callee).as_deref() == Some("Error")
                {
                    constructs = true;
                }
            });
            constructs.then(|| instructions[&pc].opcode)
        })
}

/// Finds the output field hidden by base64 encoding and a two-byte XOR key. A name that decodes to
/// `stack` identifies the key. The output field is the remaining name after excluding `stack` and
/// the record counter from the header.
fn encoded_result_field(features: &[String], header: &BTreeSet<String>) -> Option<String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let decoded: Vec<Vec<u8>> = features
        .iter()
        .filter_map(|text| STANDARD.decode(text).ok())
        .filter(|bytes| (3..=12).contains(&bytes.len()))
        .collect();
    for candidate in decoded.iter().filter(|bytes| bytes.len() == "stack".len()) {
        let key = [candidate[0] ^ b's', candidate[1] ^ b't'];
        let reveal = |bytes: &Vec<u8>| {
            let revealed = bytes
                .iter()
                .zip(key.iter().cycle())
                .map(|(byte, mask)| byte ^ mask);
            String::from_utf8(revealed.collect()).ok()
        };
        if reveal(candidate).as_deref() != Some("stack") {
            continue;
        }
        // Plain strings such as `this` can also be valid base64. Restrict candidates to the
        // four-to-nine-character program names.
        let names = decoded.iter().filter_map(reveal).filter(|name| {
            (4..=9).contains(&name.len())
                && name.starts_with(|first: char| first.is_ascii_alphabetic())
                && name
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
                && name != "stack"
                && !header.contains(name)
        });
        if let Ok(result) = candidates::exactly_one(names, "stack result field") {
            return Some(result);
        }
    }
    None
}

/// Finds the output field in the string table by excluding the header's record-counter name,
/// `stack`, and checksum numbers. Supports reversed entries.
fn result_field(features: &[String], header: &BTreeSet<String>) -> Option<String> {
    for table in features {
        // The separator is the character that splits out `stack`.
        let separators: BTreeSet<char> = table.chars().collect();
        for separator in separators {
            let parts: Vec<&str> = table.split(separator).collect();
            let reversed = parts.contains(&"kcats");
            if parts.len() < 8 || !reversed && !parts.contains(&"stack") {
                continue;
            }
            let names = parts.iter().map(|part| {
                if reversed {
                    part.chars().rev().collect()
                } else {
                    part.to_string()
                }
            });
            let results = names.filter(|name| {
                name.starts_with(|first: char| first.is_ascii_alphabetic())
                    && name != "stack"
                    && !header.contains(name)
            });
            if let Ok(result) = candidates::exactly_one(results, "stack result field") {
                return Some(result);
            }
        }
    }
    None
}

pub(crate) fn recognize(probe: &ProbeView<'_>) -> Option<Fields> {
    result_field(probe.session_features, probe.header)
        .or_else(|| encoded_result_field(probe.session_features, probe.header))
        .map(|result| Fields {
            result,
            calls: calls(probe.index, probe.entry),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// String-table fixtures from `oct07` and `auto07`, with reversed entries, different
    /// separators, record counter `MpnR7`, and output `KtSk9` among checksums.
    const TABLES: [&str; 2] = [
        "jofSiE30008083BkkWNuT7448403BdopMzg44061BNGFZaZ261BkcatsB9kStKBfLtcHj96832BgaTDbY4BpXQttP25B7RnpMBmUhSIX36BDVzmUR5929603BYmhrYo9141BEaIFAp045194BjnyEXu464181BUJSbfj21",
        "9kStKdcbIlPD41905061dwyaOcj8d7RnpMdYyBnCs01dXDFpnl1dkcatsdkqJgKK4841dsslBLo4138912dnxktDj04102605dumXLnH6dNwsxWl1479dFzWAcA5127017dMcaZve4139676dAWAbss1932682",
    ];

    /// Both string orders identify the output field. Without header names, the record counter
    /// remains a competing candidate and recovery must fail.
    #[test]
    fn reads_the_one_name_besides_the_header() {
        let in_order: String = TABLES[0].chars().rev().collect();
        for table in [TABLES[0], TABLES[1], in_order.as_str()] {
            let features = ["stack".to_owned(), table.to_owned()];
            let result = result_field(&features, &BTreeSet::from(["MpnR7".to_owned()]));
            assert_eq!(result.as_deref(), Some("KtSk9"), "{table}");
        }
        assert!(result_field(&[TABLES[0].to_owned()], &BTreeSet::new()).is_none());
    }

    /// Names captured from c787ce48cf6b sessions with XOR keys 0x91 0xa2 and 0xff 0x75. The second
    /// key also decodes the plain string `this` to `ImS`, which must be excluded.
    #[test]
    fn reveals_encoded_names_with_the_key_that_spells_stack() {
        let header = BTreeSet::from(["XNWt6".to_owned()]);
        for features in [
            [
                "atob", "yezG1qc=", "0uj6w/Wb", "4tbwwfo=", "jROwcoLu", "this",
            ],
            [
                "atob", "jAGeFpQ=", "pzuoAck=", "vD+UFJtM", "KKExCrEv", "this",
            ],
        ] {
            let features = features.map(str::to_owned);
            assert_eq!(
                encoded_result_field(&features, &header).as_deref(),
                Some("CJkad9"),
                "{features:?}"
            );
            assert!(encoded_result_field(&features, &BTreeSet::new()).is_none());
        }
    }
}
