//! Command-line options, help text, and option validation. Parsing does not read files.

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail, ensure};
use cfsolve::capture::CHALLENGE_HOST;
use url::Url;

pub const USAGE: &str = "\
Usage: capture-proxy --fingerprint <fingerprint.json> [options]
       capture-proxy --help

Options:
  --fingerprint <fingerprint.json>
                     Required. The browser the upstream requests present
                     themselves as; only its `transport` is read.
  --site <url>       Intercept the host of this page, which embeds the
                     widget. May be repeated.
  --mitm-host <host> Intercept this host. May be repeated.
                     challenges.cloudflare.com is always intercepted.
  --listen <address> Where the proxy listens. Default 127.0.0.1:8888.
  --ca-dir <directory>
                     Where the proxy's CA is kept, generated on first use.
                     Default ./proxy-ca.
  --out <directory>  Where the session logs go. Default ./captures.
  --upstream-proxy <url>
                     Reach the internet through an http://, https://,
                     socks5:// or socks5h:// proxy.

Point a browser at this proxy and open http://proxy.ca/ssl to
download its CA certificate.";

const LISTEN: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8888));
const CA_DIR: &str = "./proxy-ca";
const OUT_DIR: &str = "./captures";

/// Proxy settings from the command line.
#[derive(Debug)]
pub struct ProxyArgs {
    pub fingerprint: PathBuf,
    pub listen: SocketAddr,
    /// Lowercase hostnames to intercept, with the challenge host first.
    pub mitm_hosts: Vec<String>,
    pub ca_dir: PathBuf,
    pub out_dir: PathBuf,
    /// The `--upstream-proxy` value used for tunnels and forwarded requests.
    pub upstream_proxy: Option<String>,
}

/// Parses options after the program name, or returns `None` for `--help`.
pub fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Option<ProxyArgs>> {
    let mut arguments = arguments.into_iter();
    let (mut fingerprint, mut listen, mut ca_dir, mut out_dir) = (None, None, None, None);
    let mut upstream_proxy = None;
    let mut mitm_hosts = vec![CHALLENGE_HOST.to_owned()];
    while let Some(argument) = arguments.next() {
        let Some(name) = argument.to_str().filter(|text| text.starts_with('-')) else {
            bail!(
                "unexpected argument {}\n\n{USAGE}",
                argument.to_string_lossy()
            );
        };
        match name {
            "-h" | "--help" => return Ok(None),
            "--fingerprint" => once(&mut fingerprint, name, value(&mut arguments, name)?)?,
            "--site" => {
                let site = text(&mut arguments, name)?;
                let site = Url::parse(&site).with_context(|| format!("invalid site URL {site}"))?;
                let host = site
                    .host_str()
                    .with_context(|| format!("{name} {site} has no host"))?;
                intercept(&mut mitm_hosts, host);
            }
            "--mitm-host" => intercept(&mut mitm_hosts, &text(&mut arguments, name)?),
            "--listen" => {
                let address = text(&mut arguments, name)?;
                let address: SocketAddr = address.parse().with_context(|| {
                    format!("{name} needs a socket address such as {LISTEN}, not {address}")
                })?;
                once(&mut listen, name, address)?;
            }
            "--ca-dir" => once(&mut ca_dir, name, value(&mut arguments, name)?)?,
            "--out" => once(&mut out_dir, name, value(&mut arguments, name)?)?,
            "--upstream-proxy" => once(&mut upstream_proxy, name, text(&mut arguments, name)?)?,
            _ => bail!("unknown option {name}\n\n{USAGE}"),
        }
    }
    let fingerprint = fingerprint
        .context("the proxy needs --fingerprint, whose transport its upstream requests present")?;
    Ok(Some(ProxyArgs {
        fingerprint: fingerprint.into(),
        listen: listen.unwrap_or(LISTEN),
        mitm_hosts,
        ca_dir: ca_dir.unwrap_or_else(|| CA_DIR.into()).into(),
        out_dir: out_dir.unwrap_or_else(|| OUT_DIR.into()).into(),
        upstream_proxy,
    }))
}

/// Adds `host` in lowercase to match the proxy's hostname comparisons.
fn intercept(hosts: &mut Vec<String>, host: &str) {
    let host = host.to_lowercase();
    if !hosts.contains(&host) {
        hosts.push(host);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses space-separated arguments.
    fn parse(arguments: &str) -> Result<Option<ProxyArgs>, String> {
        let arguments = arguments.split_whitespace().map(OsString::from);
        super::parse(arguments).map_err(|error| format!("{error:#}"))
    }

    fn proxy(arguments: &str) -> ProxyArgs {
        parse(arguments).expect(arguments).expect("not --help")
    }

    #[test]
    fn reads_the_options_and_their_defaults() {
        let defaults = proxy("--fingerprint f.json");
        assert_eq!(defaults.fingerprint.to_str(), Some("f.json"));
        assert_eq!(defaults.listen, LISTEN);
        assert_eq!(defaults.mitm_hosts, [CHALLENGE_HOST]);
        assert_eq!(defaults.ca_dir.to_str(), Some(CA_DIR));
        assert_eq!(defaults.out_dir.to_str(), Some(OUT_DIR));
        assert_eq!(defaults.upstream_proxy, None);

        let given = proxy(
            "--listen 0.0.0.0:9000 --ca-dir /tmp/ca --out /tmp/out \
             --upstream-proxy socks5h://127.0.0.1:1080 --fingerprint f.json \
             --site https://CaptchaTest.Book.BI/path --mitm-host CHALLENGES.cloudflare.com \
             --mitm-host captchatest.book.bi --mitm-host Cdn.CaptchaTest.Book.BI",
        );
        assert_eq!(given.listen.to_string(), "0.0.0.0:9000");
        assert_eq!(given.ca_dir.to_str(), Some("/tmp/ca"));
        assert_eq!(given.out_dir.to_str(), Some("/tmp/out"));
        let upstream_proxy = given.upstream_proxy.as_deref();
        assert_eq!(upstream_proxy, Some("socks5h://127.0.0.1:1080"));
        assert_eq!(
            given.mitm_hosts,
            [
                CHALLENGE_HOST,
                "captchatest.book.bi",
                "cdn.captchatest.book.bi"
            ]
        );

        assert!(matches!(parse("--help"), Ok(None)));
        assert!(matches!(parse("--out /tmp/out -h"), Ok(None)));
    }

    #[test]
    fn rejects_what_it_cannot_interpret() {
        let cases = [
            ("", "the proxy needs --fingerprint"),
            ("f.json", "unexpected argument f.json"),
            ("--fingerprint", "--fingerprint needs a value"),
            (
                "--fingerprint --listen",
                "--fingerprint needs a value, not --listen",
            ),
            (
                "--fingerprint a --fingerprint b",
                "--fingerprint is given more than once",
            ),
            (
                "--listen localhost",
                "--listen needs a socket address such as 127.0.0.1:8888, not localhost",
            ),
            (
                "--site captchatest.book.bi",
                "invalid site URL captchatest.book.bi",
            ),
            (
                "--site data:text/plain,",
                "--site data:text/plain, has no host",
            ),
            ("--slove", "unknown option --slove"),
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
