//! Connects tunnels directly or through an HTTP or SOCKS5 proxy.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result, bail, ensure};
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use url::Url;

use super::head;

/// How the proxy reaches the internet.
#[derive(Debug, PartialEq)]
pub enum UpstreamProxy {
    Direct,
    Http {
        host: String,
        port: u16,
        tls: bool,
        auth: Option<Credentials>,
    },
    /// A SOCKS5 proxy. With `remote_dns`, the proxy resolves hostnames, matching `socks5h`.
    Socks {
        host: String,
        port: u16,
        auth: Option<Credentials>,
        remote_dns: bool,
    },
}

#[derive(Debug, PartialEq)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}

/// A tunnel's byte stream.
pub(super) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

impl FromStr for UpstreamProxy {
    type Err = anyhow::Error;

    /// Parses an `http://`, `https://`, `socks5://`, or `socks5h://` proxy URL.
    fn from_str(url: &str) -> Result<Self> {
        let url = Url::parse(url).context("parsing the upstream proxy URL")?;
        let host = url
            .host_str()
            .context("the proxy URL has no host")?
            .to_owned();
        // `Url` keeps the userinfo percent-encoded.
        let decode = |text: &str| -> Result<String> {
            let decoded = percent_encoding::percent_decode_str(text).decode_utf8();
            Ok(decoded
                .context("the proxy credentials are not UTF-8")?
                .into_owned())
        };
        let auth = if url.username().is_empty() {
            None
        } else {
            Some(Credentials {
                user: decode(url.username())?,
                password: decode(url.password().unwrap_or_default())?,
            })
        };
        let port = url.port_or_known_default();
        Ok(match url.scheme() {
            "http" | "https" => Self::Http {
                port: port.expect("http and https have default ports"),
                host,
                tls: url.scheme() == "https",
                auth,
            },
            "socks5" | "socks5h" => Self::Socks {
                port: port.unwrap_or(1080),
                host,
                auth,
                remote_dns: url.scheme() == "socks5h",
            },
            scheme => bail!("unsupported upstream proxy scheme {scheme}"),
        })
    }
}

impl UpstreamProxy {
    pub(super) async fn connect(&self, host: &str, port: u16) -> Result<Box<dyn Stream>> {
        match self {
            Self::Direct => Ok(Box::new(tcp_connect(host, port).await?)),
            Self::Http {
                host: proxy_host,
                port: proxy_port,
                tls,
                auth,
            } => {
                let stream = tcp_connect(proxy_host, *proxy_port).await?;
                // TLS to an `https://` proxy carries the whole tunnel.
                let mut stream: Box<dyn Stream> = if *tls {
                    Box::new(tls_connect(stream, proxy_host).await?)
                } else {
                    Box::new(stream)
                };
                http_connect(&mut stream, host, port, auth.as_ref()).await?;
                Ok(stream)
            }
            Self::Socks {
                host: proxy_host,
                port: proxy_port,
                auth,
                remote_dns,
            } => {
                let mut stream = tcp_connect(proxy_host, *proxy_port).await?;
                socks_connect(&mut stream, host, port, auth.as_ref(), *remote_dns).await?;
                Ok(Box::new(stream))
            }
        }
    }
}

async fn tcp_connect(host: &str, port: u16) -> Result<TcpStream> {
    TcpStream::connect((host, port))
        .await
        .with_context(|| format!("connecting to {host}:{port}"))
}

/// Wraps `stream` in TLS for `host`. Verifies certificates against system roots, loaded on
/// first use.
pub(super) async fn tls_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    host: &str,
) -> Result<TlsStream<S>> {
    static CONNECTOR: LazyLock<Option<TlsConnector>> = LazyLock::new(|| {
        let mut roots = RootCertStore::empty();
        let (added, _) =
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (added > 0).then(|| TlsConnector::from(Arc::new(config)))
    });
    let connector = CONNECTOR
        .as_ref()
        .context("no usable system root certificates")?;
    let name = ServerName::try_from(host.to_owned()).context("the host is not a DNS name")?;
    connector
        .connect(name, stream)
        .await
        .with_context(|| format!("TLS to {host}"))
}

async fn http_connect(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    host: &str,
    port: u16,
    auth: Option<&Credentials>,
) -> Result<()> {
    use base64::Engine;

    let authorization = auth.map_or_else(String::new, |Credentials { user, password }| {
        let credentials = STANDARD.encode(format!("{user}:{password}"));
        format!("Proxy-Authorization: Basic {credentials}\r\n")
    });
    let request =
        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{authorization}\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let head = head::read_head(stream).await?;
    let status = head::first_line(&head)?;
    ensure!(
        status.split_whitespace().nth(1) == Some("200"),
        "the proxy refused CONNECT: {status}"
    );
    Ok(())
}

/// Opens a SOCKS5 CONNECT tunnel (RFC 1928) to `host:port`. With `remote_dns`, asks the proxy
/// to resolve `host`.
async fn socks_connect(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    host: &str,
    port: u16,
    auth: Option<&Credentials>,
    remote_dns: bool,
) -> Result<()> {
    // Offer the configured authentication method: username and password (RFC 1929), or no
    // authentication.
    let method = if auth.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    ensure!(
        reply == [5, method],
        "the SOCKS proxy refuses authentication method {method}"
    );
    if let Some(Credentials { user, password }) = auth {
        let mut request = vec![1];
        for field in [user, password] {
            let length =
                u8::try_from(field.len()).context("SOCKS credentials are over 255 bytes")?;
            request.push(length);
            request.extend_from_slice(field.as_bytes());
        }
        stream.write_all(&request).await?;
        stream.read_exact(&mut reply).await?;
        ensure!(reply == [1, 0], "SOCKS authentication failed");
    }

    // Send CONNECT with a domain name (3), IPv4 address (1), or IPv6 address (4).
    let mut request = vec![5, 1, 0];
    if remote_dns {
        let length = u8::try_from(host.len()).context("the target hostname is over 255 bytes")?;
        request.extend_from_slice(&[3, length]);
        request.extend_from_slice(host.as_bytes());
    } else {
        let address = tokio::net::lookup_host((host, port))
            .await?
            .next()
            .with_context(|| format!("resolving {host}"))?;
        let (kind, octets) = match address.ip() {
            IpAddr::V4(ip) => (1, ip.octets().to_vec()),
            IpAddr::V6(ip) => (4, ip.octets().to_vec()),
        };
        request.push(kind);
        request.extend_from_slice(&octets);
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    ensure!(reply[..2] == [5, 0], "SOCKS CONNECT failed ({reply:02x?})");
    // Skip the address and port the proxy bound.
    let address_length = match reply[3] {
        1 => 4,
        3 => usize::from(stream.read_u8().await?),
        4 => 16,
        kind => bail!("bad SOCKS address type {kind}"),
    };
    stream.read_exact(&mut vec![0; address_length + 2]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn upstream_proxy_urls_parse() {
        let parse = |url| UpstreamProxy::from_str(url).unwrap();
        let http = |port, tls, auth: Option<(&str, &str)>| UpstreamProxy::Http {
            host: "proxy".to_owned(),
            port,
            tls,
            auth: auth.map(|(user, password)| Credentials {
                user: user.to_owned(),
                password: password.to_owned(),
            }),
        };
        assert_eq!(parse("http://proxy:8080"), http(8080, false, None));
        let https = parse("https://user:pass@proxy");
        assert_eq!(https, http(443, true, Some(("user", "pass"))));
        let encoded = parse("http://us%40er:p%3As%25s@proxy");
        assert_eq!(encoded, http(80, false, Some(("us@er", "p:s%s"))));
        let socks = UpstreamProxy::Socks {
            host: "proxy".to_owned(),
            port: 1080,
            auth: None,
            remote_dns: true,
        };
        assert_eq!(parse("socks5h://proxy"), socks);
        assert!(UpstreamProxy::from_str("ftp://proxy").is_err());
        assert!(UpstreamProxy::from_str("://missing").is_err());
    }

    #[tokio::test]
    async fn socks5_chains_the_tunnel() {
        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_port = socks.local_addr().unwrap().port();
        let (request_sender, request_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = socks.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            request_sender.send(request).unwrap();
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        });
        let socks = UpstreamProxy::Socks {
            host: "127.0.0.1".to_owned(),
            port: socks_port,
            auth: None,
            remote_dns: false,
        };
        let mut tunnel = socks.connect("localhost", 80).await.unwrap();
        let request = request_receiver.await.unwrap();
        assert_eq!(
            request[..4],
            [5, 1, 0, 1],
            "a CONNECT to a locally resolved IPv4 target"
        );
        assert_eq!(request[8..], 80u16.to_be_bytes(), "the target's port");
        tunnel.write_all(b"socks").await.unwrap();
        let mut echo = [0; 5];
        tunnel.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"socks");
    }
}
