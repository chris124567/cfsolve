//! Runs a [`cfsolve::Browser`] session from a page or iframe URL. Builds the first payload and,
//! with `--solve`, answers the probe and checkbox programs.

mod cli;
mod io;

use std::env;
use std::sync::Arc;

use anyhow::Result;
use cfsolve::{Browser, Options, Outcome};
use tokio::runtime::Builder;

use crate::cli::Entry;
use crate::io::Artifacts;

fn main() -> Result<()> {
    let Some(arguments) = cli::parse(env::args_os().skip(1))? else {
        println!("{}", cli::USAGE);
        return Ok(());
    };
    // Load the browser before any network access.
    let browser = Browser::read(&arguments.fingerprint)?;
    let artifacts = Artifacts::try_new(arguments.directory)?;
    let options = Options {
        proxy: arguments.proxy,
        sink: Some(Arc::new(artifacts)),
    };
    let runtime = Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        match arguments.entry {
            Entry::Iframe(iframe) => browser.prepare(iframe, &options).await,
            Entry::Page { url, widget } => {
                browser
                    .send_first_payload(&url, widget.as_ref(), &options)
                    .await
            }
            Entry::Solve(url) => {
                match browser.solve(&url, &options).await? {
                    Outcome::Token(token) => println!("{token}"),
                    Outcome::Cleared(cleared) => println!("cf_clearance={}", cleared.clearance),
                }
                Ok(())
            }
            Entry::Turnstile(turnstile) => {
                println!("{}", browser.solve_turnstile(turnstile, &options).await?);
                Ok(())
            }
        }
    })?;
    Ok(())
}
