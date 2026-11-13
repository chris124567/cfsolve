//! Read the payloads of capture-proxy sessions logged without them, as when the proxy could not
//! extract a session's parameters, and write completed copies of the sessions.
//! Usage: reread_capture <capture-dir> <output-dir>
//!
//! Reads each `sessions/session-*` under the capture directory and writes the completed session
//! under `<output-dir>/sessions/` with the same name. The capture directory is left unchanged.

use std::path::PathBuf;
use std::{env, fs};

use anyhow::{Context, Result};
use cfsolve::capture;

fn main() -> Result<()> {
    let mut arguments = env::args().skip(1);
    let directory = PathBuf::from(arguments.next().context("supply a capture directory")?);
    let output = PathBuf::from(arguments.next().context("supply an output directory")?);
    let mut sessions: Vec<PathBuf> = fs::read_dir(directory.join("sessions"))?
        .map(|entry| Ok(entry?.path()))
        .collect::<Result<_>>()?;
    sessions.sort();
    for session in sessions {
        let name = session.file_name().context("a session has no name")?;
        let out = output.join("sessions").join(name);
        match capture::reread_session(&session, &out) {
            Ok(count) => println!("{}: {count} payloads", session.display()),
            Err(error) => println!("{}: {error:#}", session.display()),
        }
    }
    Ok(())
}
