//! Command-line forms, help text, and option validation. Parsing does not read files.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail, ensure};
use cfsolve::{PageSource, Turnstile, Widget};
use url::Url;

pub const USAGE: &str = "\
Usage: challenge <iframe-url> <output-directory> --fingerprint <fingerprint.json>
       challenge --page <page-url> <output-directory> --fingerprint <fingerprint.json>
       challenge --page <page-url> <output-directory> --solve --fingerprint <fingerprint.json>
       challenge --help

The output directory must be new or empty. A solve prints the widget's token,
or `cf_clearance=<value>` once a challenge page clears.

Options:
  --fingerprint <fingerprint.json>
                     Required. The browser the session presents itself as.
  --solve            Answer the returned program and send the probe and
                     interaction POSTs. Needs --page; the fingerprint's
                     `answers` holds the device's stored probe answers.
  --sitekey <sitekey>
                     The widget to answer: the page's .cf-turnstile
                     container with this sitekey, or, if the page renders
                     it from script, one rendered as turnstile.render
                     would. Without it, the page's first container.
                     Needs --page. A challenge page in the widget's
                     page's place fails the session.
  --action <action>, --cdata <cdata>
                     The widget's action and cData, in place of its
                     container's. Need --sitekey.
  --blank-page       Render the --sitekey widget on a blank page at the
                     page's address instead of navigating to it. Needs
                     --solve.
  --proxy <url>      Send every request through an http://, https://,
                     socks5:// or socks5h:// proxy. Credentials go in the
                     URL: socks5h://user:password@host:port.";

/// Session settings from the command line.
#[derive(Debug)]
pub struct SessionArgs {
    pub entry: Entry,
    pub directory: PathBuf,
    pub fingerprint: PathBuf,
    pub proxy: Option<String>,
}

/// The page or iframe that starts a session, and how far the session goes.
#[derive(Debug)]
pub enum Entry {
    /// Sends the iframe's first payload.
    Iframe(Url),
    /// Sends the first payload of `widget`, or of the page's first widget.
    Page { url: Url, widget: Option<Widget> },
    /// Solves the page's first widget, or clears its challenge page.
    Solve(Url),
    /// Solves the widget named by `--sitekey`.
    Turnstile(Turnstile),
}

/// Parses arguments after the program name, or returns `None` for `--help`. Options may appear
/// anywhere until `--`.
pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Option<SessionArgs>> {
    let mut arguments = arguments.into_iter();
    let (mut page, mut fingerprint, mut proxy) = (None, None, None);
    let (mut sitekey, mut action, mut cdata) = (None, None, None);
    let (mut solve, mut blank) = (None, None);
    let mut positional = Vec::new();
    while let Some(argument) = arguments.next() {
        let Some(name) = argument
            .to_str()
            .filter(|text| text.starts_with('-') && *text != "-")
        else {
            positional.push(argument);
            continue;
        };
        match name {
            "--" => {
                positional.extend(arguments.by_ref());
                break;
            }
            "-h" | "--help" => return Ok(None),
            "--solve" => once(&mut solve, name, ())?,
            "--blank-page" => once(&mut blank, name, ())?,
            "--page" => once(&mut page, name, value(&mut arguments, name)?)?,
            "--fingerprint" => once(&mut fingerprint, name, value(&mut arguments, name)?)?,
            "--sitekey" => once(&mut sitekey, name, text(&mut arguments, name)?)?,
            "--action" => once(&mut action, name, text(&mut arguments, name)?)?,
            "--cdata" => once(&mut cdata, name, text(&mut arguments, name)?)?,
            "--proxy" => once(&mut proxy, name, proxy_url(&value(&mut arguments, name)?)?)?,
            _ => bail!("unknown option {name}\n\n{USAGE}"),
        }
    }
    let (solve, blank) = (solve.is_some(), blank.is_some());
    ensure!(
        sitekey.is_some() || (action.is_none() && cdata.is_none()),
        "--action and --cdata require --sitekey: they configure the widget it names"
    );
    ensure!(
        !blank || (solve && sitekey.is_some()),
        "--blank-page requires --solve and --sitekey: a solve renders the widget it names"
    );
    let widget = sitekey.map(|sitekey| Widget {
        sitekey,
        action,
        cdata,
    });
    let (entry, directory) = match (page, positional.as_slice()) {
        (Some(page), [directory]) => {
            let url = url(&page, "page")?;
            let entry = match (solve, widget) {
                (false, widget) => Entry::Page { url, widget },
                (true, None) => Entry::Solve(url),
                (true, widget @ Some(_)) => {
                    let page = if blank {
                        PageSource::Blank
                    } else {
                        PageSource::Navigate
                    };
                    Entry::Turnstile(Turnstile { url, page, widget })
                }
            };
            (entry, directory)
        }
        (None, [iframe, directory]) => {
            let iframe = url(iframe, "iframe")?;
            ensure!(
                !solve,
                "--solve requires --page: answering the returned program needs the embedding page"
            );
            ensure!(
                widget.is_none(),
                "--sitekey requires --page: the embedding page renders the widget"
            );
            (Entry::Iframe(iframe), directory)
        }
        _ => bail!("{USAGE}"),
    };
    let fingerprint = fingerprint.context(
        "a session needs --fingerprint, which describes the browser it presents, starting with its transport",
    )?;
    Ok(Some(SessionArgs {
        entry,
        directory: directory.into(),
        fingerprint: fingerprint.into(),
        proxy,
    }))
}

/// Reads the next argument as the value of `option`. Rejects another option in its place. Use
/// `./--name` for a path starting with `--`.
fn value(arguments: &mut impl Iterator<Item = OsString>, option: &str) -> Result<OsString> {
    let value = arguments
        .next()
        .with_context(|| format!("{option} needs a value\n\n{USAGE}"))?;
    ensure!(
        !value.to_str().is_some_and(|text| text.starts_with("--")),
        "{option} needs a value, not {}",
        value.to_string_lossy()
    );
    Ok(value)
}

/// Reads a text value with [`value`].
fn text(arguments: &mut impl Iterator<Item = OsString>, option: &str) -> Result<String> {
    value(arguments, option)?
        .into_string()
        .map_err(|value| anyhow!("{option} needs text, not {}", value.to_string_lossy()))
}

fn once<T>(slot: &mut Option<T>, option: &str, value: T) -> Result<()> {
    ensure!(slot.is_none(), "{option} is given more than once");
    *slot = Some(value);
    Ok(())
}

fn url(text: &OsStr, what: &str) -> Result<Url> {
    let text = text
        .to_str()
        .with_context(|| format!("invalid {what} URL {}", text.to_string_lossy()))?;
    Url::parse(text).with_context(|| format!("invalid {what} URL {text}"))
}

/// Reads `text` as a proxy URL whose scheme the client supports. Rejecting one here fails
/// before the output directory is created.
fn proxy_url(text: &OsStr) -> Result<String> {
    let proxy = url(text, "proxy")?;
    let scheme = proxy.scheme();
    ensure!(
        matches!(scheme, "http" | "https" | "socks5" | "socks5h"),
        "unsupported proxy scheme {scheme}: --proxy takes http, https, socks5, or socks5h"
    );
    ensure!(proxy.has_host(), "the proxy URL has no host");
    Ok(proxy.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses space-separated arguments.
    fn parse(arguments: &str) -> Result<Option<SessionArgs>, String> {
        let arguments = arguments.split_whitespace().map(OsString::from);
        super::parse(arguments).map_err(|error| format!("{error:#}"))
    }

    fn session(arguments: &str) -> SessionArgs {
        parse(arguments).expect(arguments).expect("not --help")
    }

    /// Options may appear anywhere until `--`.
    #[test]
    fn reads_the_command_forms() {
        let iframe = session("https://x/iframe /tmp/out --fingerprint f.json");
        assert!(matches!(iframe.entry, Entry::Iframe(url) if url.as_str() == "https://x/iframe"));
        assert_eq!(iframe.directory.to_str(), Some("/tmp/out"));
        let ended = session("--fingerprint f.json https://x/iframe -- --odd-directory");
        assert_eq!(ended.directory.to_str(), Some("--odd-directory"));

        let page = session("--page https://x/ /tmp/out --fingerprint f.json");
        assert!(matches!(page.entry, Entry::Page { widget: None, .. }));

        let named = session("--page https://x/ /tmp/out --sitekey k --action a --fingerprint f");
        let Entry::Page {
            widget: Some(widget),
            ..
        } = &named.entry
        else {
            panic!("{:?} names no widget", named.entry);
        };
        assert_eq!(widget.sitekey, "k");
        assert_eq!(widget.action.as_deref(), Some("a"));
        assert_eq!(widget.cdata, None);

        let solved = session("--solve --fingerprint f.json /tmp/out --page https://x/");
        assert!(matches!(solved.entry, Entry::Solve(_)));
        assert_eq!(solved.directory.to_str(), Some("/tmp/out"));
        assert_eq!(solved.fingerprint.to_str(), Some("f.json"));
        assert_eq!(solved.proxy, None);

        let proxied =
            session("https://x/iframe /tmp/out --proxy socks5h://u:p@h:1080 --fingerprint f");
        assert_eq!(proxied.proxy.as_deref(), Some("socks5h://u:p@h:1080"));

        let blank =
            session("--page https://x/ /tmp/out --solve --sitekey k --blank-page --fingerprint f");
        assert!(matches!(
            blank.entry,
            Entry::Turnstile(Turnstile {
                page: PageSource::Blank,
                widget: Some(_),
                ..
            })
        ));

        assert!(matches!(parse("--help"), Ok(None)));
        assert!(matches!(parse("https://x/ -h"), Ok(None)));
    }

    #[test]
    fn rejects_what_it_cannot_interpret_or_honour() {
        let cases = [
            ("", "Usage:"),
            ("one", "Usage:"),
            ("one two three", "Usage:"),
            ("--page https://x/ one two", "Usage:"),
            ("--page", "--page needs a value"),
            ("not-a-url /tmp/out", "invalid iframe URL"),
            ("https://x/ /tmp/out --slove", "unknown option --slove"),
            (
                "https://x/ /tmp/out --fingerprint a --fingerprint b",
                "--fingerprint is given more than once",
            ),
            (
                "--page https://x/ /tmp/out --solve --solve",
                "--solve is given more than once",
            ),
            (
                "https://x/ /tmp/out --fingerprint --solve",
                "--fingerprint needs a value, not --solve",
            ),
            (
                "https://x/ /tmp/out --fingerprint",
                "--fingerprint needs a value",
            ),
            ("https://x/iframe /tmp/out", "a session needs --fingerprint"),
            (
                "--page https://x/ /tmp/out --solve",
                "a session needs --fingerprint",
            ),
            (
                "https://x/iframe /tmp/out --solve",
                "--solve requires --page",
            ),
            (
                "https://x/iframe /tmp/out --sitekey k",
                "--sitekey requires --page",
            ),
            (
                "--page https://x/ /tmp/out --cdata c",
                "--action and --cdata require --sitekey",
            ),
            (
                "--page https://x/ /tmp/out --sitekey a --sitekey b",
                "--sitekey is given more than once",
            ),
            (
                "--page https://x/ /tmp/out --sitekey k --blank-page",
                "--blank-page requires --solve and --sitekey",
            ),
            (
                "https://x/ /tmp/out --proxy h:1080",
                "unsupported proxy scheme h",
            ),
            (
                "https://x/ /tmp/out --proxy socks5:h",
                "the proxy URL has no host",
            ),
            ("https://x/ /tmp/out --proxy :1080", "invalid proxy URL"),
            (
                "https://x/ /tmp/out --proxy http://a --proxy http://b",
                "--proxy is given more than once",
            ),
        ];
        for (arguments, expected) in cases {
            let error = parse(arguments).expect_err(arguments);
            assert!(
                error.starts_with(expected),
                "{arguments:?} reported {error}"
            );
        }
    }
}
