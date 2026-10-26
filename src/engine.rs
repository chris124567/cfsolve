//! Browser engine behavior used by fingerprints: stack formatting, clocks, API availability,
//! and referrer handling. Header order varies by browser version and comes from the profile
//! (see [`crate::http::HeaderOrder`]).

use serde::Deserialize;

/// An engine family, named in lowercase in the fingerprint's `engine`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    /// Blink and V8, used by Chrome and related browsers.
    Chromium,
    /// WebKit and JavaScriptCore, used by Safari and iOS browser profiles.
    WebKit,
}

/// A stack frame with the engine's function name and one-based line and UTF-16 column of the
/// call in `url`.
pub(crate) struct StackFrame<'frame> {
    pub function: &'frame str,
    pub url: &'frame str,
    pub line: usize,
    pub column: usize,
}

/// The kind of text a stack position counts lines in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lines {
    /// Script source, where `\n`, `\r`, `\r\n`, U+2028 and U+2029 each end a line.
    Script,
    /// An HTML document, whose input stream turns `\r\n` and `\r` into `\n` but keeps U+2028
    /// and U+2029 as text.
    Document,
}

/// Returns the zero-based line and UTF-16 column after `prefix`, using the line-break rules
/// specified by `lines`.
#[must_use]
pub(crate) fn line_and_column(prefix: &str, lines: Lines) -> (u32, u32) {
    let (mut line, mut column, mut after_cr) = (0, 0, false);
    for character in prefix.chars() {
        match character {
            '\n' if after_cr => {}
            '\r' | '\n' => {
                line += 1;
                column = 0;
            }
            '\u{2028}' | '\u{2029}' if lines == Lines::Script => {
                line += 1;
                column = 0;
            }
            _ => column += character.len_utf16() as u32,
        }
        after_cr = character == '\r';
    }
    (line, column)
}

/// V8's default `Error.stackTraceLimit`: an `Error` stack keeps its innermost ten frames.
pub(crate) const V8_STACK_LIMIT: usize = 10;

impl Engine {
    /// Formats an `Error` stack created in the innermost frame. V8 includes the error name;
    /// JavaScriptCore lists only frames, leaving the query and fragment out of their URLs.
    #[must_use]
    pub(crate) fn error_stack<'frame>(
        self,
        frames: impl IntoIterator<Item = StackFrame<'frame>>,
    ) -> String {
        let mut lines = Vec::new();
        if self == Self::Chromium {
            lines.push("Error".to_owned());
        }
        for frame in frames {
            let StackFrame {
                function,
                url,
                line,
                column,
            } = frame;
            lines.push(match self {
                // V8 gives an anonymous function's frame its location alone.
                Self::Chromium if function.is_empty() => format!("    at {url}:{line}:{column}"),
                Self::Chromium => format!("    at {function} ({url}:{line}:{column})"),
                Self::WebKit => {
                    let url = url.find(['?', '#']).map_or(url, |end| &url[..end]);
                    format!("{function}@{url}:{line}:{column}")
                }
            });
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that both formats count `\r\n` as one line break and measure columns in UTF-16
    /// code units. Only script source treats U+2028 and U+2029 as line breaks.
    #[test]
    fn scripts_and_documents_count_lines_their_own_way() {
        let text = "a\r\nb\rc\u{2028}d\u{2029}e\n\u{1F600}é";
        assert_eq!(line_and_column(text, Lines::Script), (5, 3));
        assert_eq!(line_and_column(text, Lines::Document), (3, 3));
        assert_eq!(line_and_column("", Lines::Document), (0, 0));
    }

    /// As iOS Safari reports an iframe loaded with `?lang=auto`.
    #[test]
    fn only_v8_stack_frames_keep_the_query() {
        let url = "https://challenges.cloudflare.com/normal?lang=auto";
        let frame = || StackFrame {
            function: "f",
            url,
            line: 1,
            column: 2,
        };
        assert_eq!(
            Engine::WebKit.error_stack([frame()]),
            "f@https://challenges.cloudflare.com/normal:1:2"
        );
        assert_eq!(
            Engine::Chromium.error_stack([frame()]),
            "Error\n    at f (https://challenges.cloudflare.com/normal?lang=auto:1:2)"
        );
    }
}
