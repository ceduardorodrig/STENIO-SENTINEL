//! One walk of the scanned tree, shared by the environment rules, plus compose interpolation parsing.

use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".venv",
    ".stversions",
    "dist",
    "dependencies",
    "vendor",
    "archive",
    "cold-storage",
    ".agents-work",
];

/// Every file under `root` that git would see (dotfiles included).
pub fn files(root: &Path) -> Vec<PathBuf> {
    let mut walker = WalkBuilder::new(root);
    walker.hidden(false).git_ignore(true).filter_entry(|e| {
        e.depth() == 0 || !SKIP_DIRS.iter().any(|d| e.file_name().to_str() == Some(*d))
    });
    walker
        .build()
        .flatten()
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(|e| e.into_path())
        .collect()
}

pub fn name_of(p: &Path) -> &str {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("")
}

pub fn is_compose(p: &Path) -> bool {
    let n = name_of(p);
    (n.starts_with("compose.") || n.starts_with("docker-compose."))
        && (n.ends_with(".yml") || n.ends_with(".yaml"))
}

/// A swarm stack file: YAML directly inside a `stacks` directory.
pub fn is_stack(p: &Path) -> bool {
    let n = name_of(p);
    (n.ends_with(".yml") || n.ends_with(".yaml")) && p.parent().map(name_of) == Some("stacks")
}

#[derive(Debug)]
pub struct Interpolation {
    pub name: String,
    pub line: usize,
    pub has_default: bool,
    pub required: bool,
}

/// The line without its YAML comment.
pub fn code_part(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        return "";
    }
    line.split_once(" #").map_or(line, |(code, _)| code)
}

/// `$NAME` and `${NAME...}` occurrences; `$$` is the compose escape.
pub fn interpolations(content: &str) -> Vec<Interpolation> {
    let mut out = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line = code_part(raw).replace("$$", "  ");
        for (pos, _) in line.match_indices('$') {
            let rest = &line[pos + 1..];
            let (braced, rest) = match rest.strip_prefix('{') {
                Some(r) => (true, r),
                None => (false, rest),
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.starts_with(|c: char| c.is_ascii_uppercase()) {
                continue;
            }
            let tail = &rest[name.len()..];
            out.push(Interpolation {
                line: i + 1,
                has_default: braced && (tail.starts_with(":-") || tail.starts_with('-')),
                required: braced && (tail.starts_with(":?") || tail.starts_with('?')),
                name,
            });
        }
    }
    out
}

/// Names declared by an env example, commented declarations included.
pub fn declared_in_example(content: &str) -> std::collections::BTreeSet<String> {
    content
        .lines()
        .filter_map(|l| {
            let l = l.trim_start().trim_start_matches('#').trim_start();
            super::store::assignment(l).map(|(k, _)| k.to_string())
        })
        .collect()
}
