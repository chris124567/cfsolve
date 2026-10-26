//! Reads connection headers before forwarding streams: HTTP/1 request and response headers, TLS
//! ClientHellos, and HTTP/2 connection openings.

use anyhow::{Context, Result, bail, ensure};
use hyper::Method;
use hyper::http::uri::Authority;
use tokio::io::AsyncRead;

/// Maximum bytes to read before forwarding a stream.
const MAX_READ_AHEAD: usize = 64 * 1024;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Reads one HTTP header block, preserving bytes read past its end.
pub(super) async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    read_through(stream, &mut head, "the head", |bytes| {
        bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|end| end + 4)
    })
    .await?;
    Ok(head)
}

/// Reads into `bytes` until `end` returns the header length, keeping extra bytes for replay.
pub(super) async fn read_through(
    stream: &mut (impl AsyncRead + Unpin),
    bytes: &mut Vec<u8>,
    what: &str,
    end: impl Fn(&[u8]) -> Option<usize>,
) -> Result<usize> {
    use tokio::io::AsyncReadExt;

    let mut buffer = [0; 4096];
    loop {
        if let Some(length) = end(bytes) {
            return Ok(length);
        }
        ensure!(
            bytes.len() <= MAX_READ_AHEAD,
            "{what} is over {MAX_READ_AHEAD} bytes"
        );
        let count = stream
            .read(&mut buffer)
            .await
            .with_context(|| format!("reading {what}"))?;
        ensure!(count != 0, "unexpected EOF in {what}");
        bytes.extend_from_slice(&buffer[..count]);
    }
}

/// The length of the TLS records carrying the ClientHello, once `bytes` holds all of them.
#[must_use]
pub(super) fn client_hello_length(bytes: &[u8]) -> Option<usize> {
    // The first record holds the handshake type followed by the message length.
    let needed = 4 + u24(bytes.get(6..9)?);
    let (mut length, mut carried) = (0, 0);
    while carried < needed {
        let header = bytes.get(length..length + 5)?;
        let fragment = usize::from(u16::from_be_bytes([header[3], header[4]]));
        length += 5 + fragment;
        carried += fragment;
    }
    (length <= bytes.len()).then_some(length)
}

/// The length of the HTTP/2 preface and frames through the end of the first header block.
#[must_use]
pub(super) fn h2_opening_length(bytes: &[u8]) -> Option<usize> {
    const HEADERS: u8 = 0x1;
    const CONTINUATION: u8 = 0x9;
    const END_HEADERS: u8 = 0x4;
    let mut length = H2_PREFACE.len();
    loop {
        let header = bytes.get(length..length + 9)?;
        length += 9 + u24(&header[..3]);
        if matches!(header[3], HEADERS | CONTINUATION) && header[4] & END_HEADERS != 0 {
            return (length <= bytes.len()).then_some(length);
        }
    }
}

/// Reads the big-endian 24-bit length used in TLS handshakes and HTTP/2 frames.
fn u24(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .fold(0, |length, &byte| length << 8 | usize::from(byte))
}

/// Extracts the request or status line from an HTTP header block.
pub(super) fn first_line(head: &[u8]) -> Result<&str> {
    let line = head
        .split(|&byte| byte == b'\r' || byte == b'\n')
        .next()
        .unwrap_or_default();
    std::str::from_utf8(line).context("the head's first line is not UTF-8")
}

/// Extracts the method and target from an HTTP request line, such as `CONNECT example.com:443`
/// or `GET http://proxy.ca/ssl`.
pub(super) fn request_line(head: &[u8]) -> Result<(Method, &str)> {
    let line = first_line(head)?;
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        bail!("not an HTTP request: {line:?}");
    };
    let method = Method::from_bytes(method.as_bytes())
        .with_context(|| format!("not an HTTP method: {method:?}"))?;
    Ok((method, target))
}

/// Parses a CONNECT target into a lowercase host and a port, defaulting to 443.
pub(super) fn connect_target(target: &str) -> Result<(String, u16)> {
    let target: Authority = target.parse().context("parsing the CONNECT target")?;
    ensure!(!target.host().is_empty(), "CONNECT names an empty host");
    Ok((
        target.host().to_lowercase(),
        target.port_u16().unwrap_or(443),
    ))
}

/// Whether an intercepted request needs a tunnel: a CONNECT or an upgrade such as WebSocket.
#[must_use]
pub(super) fn is_tunnel_request(head: &[u8]) -> bool {
    let connect = request_line(head).is_ok_and(|(method, _)| method == Method::CONNECT);
    connect
        || String::from_utf8_lossy(head)
            .lines()
            .skip(1)
            .take_while(|line| !line.is_empty())
            .any(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("upgrade"))
            })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_targets_and_bad_request_lines() {
        let parse = |target| connect_target(target).unwrap();
        assert_eq!(parse("Example.com:8443"), ("example.com".to_owned(), 8443));
        assert_eq!(parse("example.com"), ("example.com".to_owned(), 443));
        assert!(connect_target("").is_err());
        assert!(request_line(b"GARBAGE\r\n\r\n").is_err());
        assert!(request_line(b"CONNECT\r\n\r\n").is_err());
    }

    /// A TLS handshake record carrying `fragment`.
    fn record(fragment: &[u8]) -> Vec<u8> {
        let length = u16::try_from(fragment.len()).unwrap().to_be_bytes();
        [&[22, 3, 1], &length[..], fragment].concat()
    }

    /// An HTTP/2 frame of `kind` with `flags` and a `length`-byte payload.
    fn frame(kind: u8, flags: u8, length: u8) -> Vec<u8> {
        [
            &[0, 0, length, kind, flags, 0, 0, 0, 1][..],
            &vec![0; length.into()],
        ]
        .concat()
    }

    #[test]
    fn client_hellos_end_with_their_last_record() {
        // The handshake type and length precede this six-byte ClientHello body.
        let message = [1, 0, 0, 6, 10, 11, 12, 13, 14, 15];
        let whole = record(&message);
        assert_eq!(client_hello_length(&whole), Some(whole.len()));
        assert_eq!(client_hello_length(&whole[..whole.len() - 1]), None);
        assert_eq!(client_hello_length(&whole[..4]), None);

        // The handshake spans two records. The browser has already sent more bytes after it.
        let split = [record(&message[..7]), record(&message[7..]), vec![20]].concat();
        assert_eq!(client_hello_length(&split), Some(split.len() - 1));
        assert_eq!(client_hello_length(&split[..14]), None);
    }

    #[test]
    fn h2_openings_end_with_the_first_header_block() {
        let settings = frame(0x4, 0, 6);
        let window_update = frame(0x8, 0, 4);
        let headers = frame(0x1, 0x4 | 0x1, 3);
        let opening = [H2_PREFACE, &settings, &window_update, &headers].concat();
        let data = frame(0x0, 0x1, 2);
        let read = [&opening[..], &data].concat();
        assert_eq!(h2_opening_length(&read), Some(opening.len()));
        assert_eq!(h2_opening_length(&opening[..opening.len() - 1]), None);

        // A header block continued in a CONTINUATION frame ends there.
        let unended = frame(0x1, 0, 3);
        let continuation = frame(0x9, 0x4, 2);
        let continued = [H2_PREFACE, &settings, &unended, &continuation].concat();
        assert_eq!(h2_opening_length(&continued), Some(continued.len()));
        assert_eq!(h2_opening_length(&continued[..continued.len() - 11]), None);
    }

    #[test]
    fn upgrades_and_connects_tunnel() {
        let websocket = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n";
        assert!(is_tunnel_request(websocket));
        assert!(is_tunnel_request(b"CONNECT x:443 HTTP/1.1\r\n\r\n"));
        assert!(!is_tunnel_request(b"GET / HTTP/1.1\r\n\r\nUpgrade: body"));
        assert!(!is_tunnel_request(H2_PREFACE));
    }
}
