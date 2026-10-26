//! Fetch a TLS echo page through the client a fingerprint's transport
//! describes, to compare its ClientHello and HTTP/2 settings with a real
//! browser's view of the same page.
//! Usage: tls_echo <fingerprint.json> [url]

use std::env;
use std::path::Path;

use anyhow::{Context, Result};
use cfsolve::fingerprint::Transport;
use cfsolve::http::navigate;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let path = args.next().context("supply a fingerprint JSON file")?;
    let url = args
        .next()
        .unwrap_or_else(|| "https://tls.peet.ws/api/all".to_owned());
    let browser = Transport::read(Path::new(&path))?.client(None)?;
    // Opened the way the solver opens an embedding page.
    let document = navigate(&browser, &Url::parse(&url)?).await?;
    print!("{}", document.html);
    Ok(())
}
