//! Classifies solve failures to help callers decide whether to retry. The wrapped error chain
//! retains the details.

use std::error::Error as StdError;
use std::fmt;

use wreq::StatusCode;

use crate::session::Stage;

/// A failed solve, or a profile that cannot solve.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The profile or options are invalid. Found before any network access.
    Config(anyhow::Error),
    /// A request failed or timed out. Retrying may succeed.
    Network(anyhow::Error),
    /// The page answered with an error status and no challenge.
    Blocked {
        /// HTTP status of the response that blocked navigation.
        status: StatusCode,
    },
    /// A Turnstile solve received a challenge page with `status` instead of the requested page.
    /// Use [`Browser::clear`](crate::Browser::clear) to clear it.
    Challenged {
        /// HTTP status of the challenge-page response.
        status: StatusCode,
    },
    /// The page answered without a challenge page, so there was nothing to clear.
    NotChallenged,
    /// Cloudflare refused the answers it was sent at `stage`. A new solve may succeed.
    Rejected {
        /// Payload stage whose answers were refused.
        stage: Stage,
        /// Rejection details, including request context.
        error: anyhow::Error,
    },
    /// The solver cannot handle this page or challenge, for example because it uses a new
    /// challenge build. Retrying will not help.
    Unsupported(anyhow::Error),
}

impl Error {
    /// Classifies a failure using a wrapped `Error`, if present, or the first recognized marker
    /// or network error in the chain.
    pub(crate) fn classify(error: anyhow::Error) -> Self {
        let error = match error.downcast::<Self>() {
            Ok(error) => return error,
            Err(error) => error,
        };
        for cause in error.chain() {
            if let Some(&Refused { stage, .. }) = cause.downcast_ref() {
                return Self::Rejected { stage, error };
            }
            if cause.is::<wreq::Error>() {
                return Self::Network(error);
            }
        }
        Self::Unsupported(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error)
            | Self::Network(error)
            | Self::Rejected { error, .. }
            | Self::Unsupported(error) => fmt::Display::fmt(error, formatter),
            Self::Blocked { status } => write!(formatter, "the page answered HTTP {status}"),
            Self::Challenged { status } => write!(
                formatter,
                "the page answered HTTP {status} with a challenge page; clear it before solving its widget"
            ),
            Self::NotChallenged => {
                formatter.write_str("the page answered without a challenge page")
            }
        }
    }
}

impl StdError for Error {
    /// The wrapped error's source, since `Display` already shows the wrapped error itself.
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Config(error)
            | Self::Network(error)
            | Self::Rejected { error, .. }
            | Self::Unsupported(error) => error.source(),
            Self::Blocked { .. } | Self::Challenged { .. } | Self::NotChallenged => None,
        }
    }
}

/// Marks a failure caused by Cloudflare refusing the answers sent at `stage`.
#[derive(Debug)]
pub(crate) struct Refused {
    stage: Stage,
    message: String,
}

impl Refused {
    pub(crate) fn new(stage: Stage, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl StdError for Refused {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_the_marker_beneath_any_context() {
        let refused = anyhow::Error::new(Refused::new(Stage::Probes, "refused"))
            .context("sending the probes");
        let refused = Error::classify(refused);
        assert!(matches!(refused, Error::Rejected { stage, .. } if stage == Stage::Probes));
        // `anyhow` displays the classified error's chain as it did before classification.
        let refused = anyhow::Error::new(refused);
        assert_eq!(format!("{refused:#}"), "sending the probes: refused");
        let blocked = anyhow::Error::new(Error::Blocked {
            status: StatusCode::FORBIDDEN,
        });
        let blocked = Error::classify(blocked.context("solving the widget"));
        assert!(matches!(blocked, Error::Blocked { status } if status == 403));
        assert_eq!(blocked.to_string(), "the page answered HTTP 403 Forbidden");
        let unknown = Error::classify(anyhow::anyhow!("no orchestrator path"));
        assert!(matches!(unknown, Error::Unsupported(_)));
    }
}
