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

/// A two-byte XOR key that spells `stack` identifies the encoded string table.
fn encoded_names(features: &[String]) -> Option<Vec<String>> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let decoded: Vec<Vec<u8>> = features
        .iter()
        .filter_map(|text| {
            let decoded;
            let text = if text.starts_with('\0') {
                decoded = crate::listing::decode_string(text, "").ok()?;
                &decoded
            } else {
                text
            };
            STANDARD.decode(text).ok()
        })
        .filter(|bytes| (3..=25).contains(&bytes.len()))
        .collect();
    let keys: BTreeSet<_> = decoded
        .iter()
        .filter(|bytes| bytes.len() == 5)
        .filter_map(|candidate| {
            let key = [candidate[0] ^ b's', candidate[1] ^ b't'];
            candidate
                .iter()
                .zip(b"stack")
                .enumerate()
                .all(|(index, (cipher, plain))| cipher ^ key[index % 2] == *plain)
                .then_some(key)
        })
        .collect();
    let key = candidates::exactly_one(keys, "stack string key").ok()?;
    Some(
        decoded
            .iter()
            .filter_map(|bytes| {
                String::from_utf8(
                    bytes
                        .iter()
                        .zip(key.iter().cycle())
                        .map(|(byte, mask)| byte ^ mask)
                        .collect(),
                )
                .ok()
            })
            .collect(),
    )
}

/// Ignore ordinary base64-looking words and the record counter when identifying the output.
fn encoded_result_field(names: &[String], header: &BTreeSet<String>) -> Option<String> {
    let names = names.iter().filter(|name| {
        crate::stage2::vocabulary::is_name(name)
            && name.as_str() != "stack"
            && !header.contains(*name)
    });
    candidates::at_most_one_distinct(names, "stack result field")
        .ok()?
        .cloned()
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
    let encoded = encoded_names(probe.session_features);
    let calls = calls(probe.index, probe.entry);
    let result = result_field(probe.session_features, probe.header)
        .or_else(|| encoded_result_field(encoded.as_ref()?, probe.header))
        .or_else(|| {
            calls.as_ref()?;
            encoded.as_ref()?;
            let fields = probe.writes.fields.iter().filter(|name| {
                crate::stage2::vocabulary::is_name(name)
                    && !probe.header.contains(*name)
                    && !probe.wrapper.contains(*name)
            });
            candidates::exactly_one(fields, "plain stack result")
                .ok()
                .cloned()
        })?;
    Some(Fields { result, calls })
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
            let names = encoded_names(&features).unwrap();
            assert_eq!(
                encoded_result_field(&names, &header).as_deref(),
                Some("CJkad9"),
                "{features:?}"
            );
            assert!(encoded_result_field(&names, &BTreeSet::new()).is_none());
        }
    }

    #[test]
    fn decodes_inline_tables_and_rejects_conflicting_keys() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let encode = |text: &str, key: [u8; 2]| {
            STANDARD.encode(
                text.bytes()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % 2])
                    .collect::<Vec<_>>(),
            )
        };
        let key = [17, 44];
        let field = "_0123456789abcdef01234567";
        let features = ["stack", field].map(|text| {
            let encoded = encode(text, key);
            format!("\0{}{encoded}padding", char::from(encoded.len() as u8))
        });
        let names = encoded_names(&features).unwrap();
        assert_eq!(
            encoded_result_field(&names, &BTreeSet::new()).as_deref(),
            Some(field)
        );
        assert!(encoded_names(&[encode("stack", key), encode("stack", [18, 45])]).is_none());
    }
}
