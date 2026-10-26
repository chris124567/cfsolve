//! Reads messages sent by returned programs to the embedding page.

use std::fmt::{self, Display, Formatter};

use crate::listing::Index;
use crate::vm::Listing;

/// Challenge outcome inferred from a returned program's strings.
#[derive(Debug)]
pub enum ProgramOutcome {
    /// The challenge passed, with the token the page receives.
    Complete { token: String },
    /// The checkbox program installs click handlers and a proof worker.
    Interaction,
    /// Anything else, described by the program's short strings.
    Other(Vec<String>),
}

impl ProgramOutcome {
    /// Reads `event: "complete"` messages sent to the embedding page. Uses the `token` member.
    /// Pre-clearance widgets also send an `sToken` with the same format, but siteverify rejects
    /// that secondary token.
    #[must_use]
    pub fn of(listing: &Listing) -> Self {
        let index = Index::new(listing);
        let strings: Vec<&str> = index.strings().values().copied().collect();
        let token = index
            .stores()
            .iter()
            .rev()
            .filter(|store| store.key == "token")
            .filter_map(|store| index.text(store.pc, &store.value))
            .find(|text| text.starts_with("1."));
        match token {
            Some(token) if strings.contains(&"complete") => Self::Complete { token },
            _ if ["Worker", "click", "SHA-256"]
                .iter()
                .all(|marker| strings.contains(marker)) =>
            {
                Self::Interaction
            }
            _ => Self::Other(
                strings
                    .iter()
                    .filter(|text| text.len() <= 64)
                    .map(|text| (*text).to_owned())
                    .collect(),
            ),
        }
    }
}

impl Display for ProgramOutcome {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Complete { token } => write!(f, "complete, token {token:.48}…"),
            Self::Interaction => {
                f.write_str("interaction required; checkbox and proof worker returned")
            }
            Self::Other(strings) => write!(f, "not complete; program strings {strings:?}"),
        }
    }
}
