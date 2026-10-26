//! Captures decrypted browser challenge payloads with [`cfsolve::capture`].
//!
//! Configure the phone to use this HTTP proxy, download its CA certificate from
//! `http://proxy.ca/ssl` through the proxy, and trust the certificate. Then load the target
//! site in Safari.
//!
//! Each iframe session is saved in `<out>/sessions/session-NNNN/`. Its `capture.json` can be
//! converted to `answers.json` with `cargo run --example build_profile`. `<out>/traffic.json`
//! records ClientHellos, HTTP/2 connection openings, and request headers. `<out>/bodies/` keeps
//! challenge pages, their orchestrator scripts and programs, and the Turnstile loader, each
//! named by its request's index in `traffic.json`. Pass the site with `--site` so its challenge
//! pages are intercepted.
//!
//! Ctrl-C waits for session extraction to finish and writes the logs. A second Ctrl-C writes
//! the logs without waiting.

mod cli;
mod io;

use std::env;

use anyhow::Result;
use cfsolve::capture::{CHALLENGE_HOST, CaptureProxy, Config, UpstreamProxy};
use cfsolve::fingerprint::Transport;
use tokio::runtime::Builder;

fn main() -> Result<()> {
    let Some(arguments) = cli::parse(env::args_os().skip(1))? else {
        println!("{}", cli::USAGE);
        return Ok(());
    };
    let transport = Transport::read(&arguments.fingerprint)?;
    let upstream_proxy: UpstreamProxy = match &arguments.upstream_proxy {
        Some(url) => url.parse()?,
        None => UpstreamProxy::Direct,
    };
    let config = Config {
        listen: arguments.listen,
        mitm_hosts: arguments.mitm_hosts,
        challenge_host: CHALLENGE_HOST.to_owned(),
        upstream_tls: true,
        upstream_proxy,
        out_dir: arguments.out_dir,
    };
    // Check that logs can be written before starting the proxy.
    io::create_dir(&config.out_dir)?;
    let ca = io::certificate_authority(&arguments.ca_dir)?;
    io::print_trust_instructions(&ca);
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        // Use the same upstream proxy for forwarded requests and tunnels.
        let client = transport.client(arguments.upstream_proxy.as_deref())?;
        CaptureProxy::try_new(config, client, ca)?.run().await
    });
    // Exit without waiting for an extraction still in progress.
    runtime.shutdown_background();
    result
}
