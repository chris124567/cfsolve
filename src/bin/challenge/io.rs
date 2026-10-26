//! Session artifacts in the output directory, with progress on standard error.

use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use cfsolve::Sink;

/// Saves session artifacts as they become available so diagnostics survive later failures.
pub struct Artifacts {
    directory: PathBuf,
}

impl Artifacts {
    /// Opens a new or empty output directory before network access. Reusing a nonempty
    /// directory could mix artifacts from different sessions.
    pub fn try_new(directory: PathBuf) -> Result<Self> {
        match std::fs::read_dir(&directory) {
            Ok(mut entries) => ensure!(
                entries.next().is_none(),
                "{} is not empty; use a fresh session directory",
                directory.display()
            ),
            Err(error) if error.kind() == ErrorKind::NotFound => {
                std::fs::create_dir_all(&directory)
                    .with_context(|| format!("creating {}", directory.display()))?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", directory.display()));
            }
        }
        Ok(Self { directory })
    }
}

impl Sink for Artifacts {
    fn artifact(&self, name: &str, contents: &[u8]) -> Result<()> {
        let path = self.directory.join(name);
        std::fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))
    }

    fn progress(&self, message: &str) {
        eprintln!("{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_directory_must_be_new_or_empty() {
        let directory =
            std::env::temp_dir().join(format!("challenge-artifacts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        let fresh = directory.join("session");
        let artifacts = Artifacts::try_new(fresh.clone()).unwrap();
        assert!(fresh.is_dir());
        Artifacts::try_new(fresh.clone()).expect("an empty directory is still fresh");
        artifacts.artifact("payload.json", b"{}").unwrap();
        let error = format!("{:#}", Artifacts::try_new(fresh.clone()).err().unwrap());
        assert!(
            error.ends_with("is not empty; use a fresh session directory"),
            "{error}"
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
