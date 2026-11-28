//! Dot files and dot folders. The source rules do not walk them; a credential in one that Git
//! does not ignore (or already tracks) is still published, so the credential rules judge them.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::Violation;

pub const PLAINTEXT_ID: &str = "SEC-PLAINTEXT-SECRET";

/// True when a name below `root` starts with a dot (the file itself when `root` is that file).
pub fn is_hidden(root: &Path, path: &Path) -> bool {
    let below = match path.strip_prefix(root) {
        Ok(rest) if !rest.as_os_str().is_empty() => rest,
        _ => match path.file_name() {
            Some(name) => Path::new(name),
            None => return false,
        },
    };
    below
        .components()
        .any(|c| c.as_os_str().to_string_lossy().starts_with('.') && c.as_os_str() != ".")
}

/// Every dot file under `root` that Git does not ignore, plus every tracked one. `skip` drops
/// generated trees. A Git failure inside a work tree is an error.
pub fn files(root: &Path, skip: impl Fn(&Path) -> bool) -> Result<Vec<PathBuf>, String> {
    let mut found = BTreeSet::new();
    let mut walker = crate::baseline::create_standard_walker(root);
    walker.hidden(false).filter_entry(|e| {
        // Synced old versions are copies of files that are judged where they live.
        !matches!(e.file_name().to_str(), Some(".git" | ".stversions"))
    });
    for entry in walker.build() {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().is_some_and(|t| t.is_file()) {
            found.insert(entry.into_path());
        }
    }
    if root.is_dir() {
        found.extend(crate::gitfiles::tracked(root)?);
    }
    Ok(found
        .into_iter()
        .filter(|p| is_hidden(root, p) && !skip(p))
        .collect())
}

/// Text of a dot file; `None` for a binary one.
pub fn read_text(path: &Path) -> std::io::Result<Option<String>> {
    let bytes = fs::read(path)?;
    Ok((!bytes.contains(&0)).then(|| String::from_utf8_lossy(&bytes).into_owned()))
}

/// The key-name heuristic for the dotenv files among them (`*_PASSWORD=literal`).
pub fn dotenv_findings(path: &Path, content: &str) -> Vec<Violation> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let text = path.to_string_lossy();
    let example = [".template", ".example", ".sample", "templates/"]
        .iter()
        .any(|m| text.contains(m));
    if example
        || !crate::guardian::is_env_like_name(name)
        || content.contains("-----BEGIN AGE ENCRYPTED FILE-----")
    {
        return Vec::new();
    }
    crate::infra::plaintext_secret_violations(&text, content, false)
}
