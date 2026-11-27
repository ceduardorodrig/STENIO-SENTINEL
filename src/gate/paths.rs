//! Path patterns: `**` spans directories, `*` stays inside one name, `~` is the home directory.

use std::path::{Component, Path, PathBuf};

fn name_matches(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else {
        return name.is_empty();
    };
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let mut parts: Vec<&str> = parts.collect();
    let Some(last) = parts.pop() else {
        return rest.is_empty();
    };
    for part in parts {
        let Some(found) = rest.find(part) else {
            return false;
        };
        rest = &rest[found + part.len()..];
    }
    rest.ends_with(last)
}

fn parts_match(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (0..=path.len()).any(|skip| parts_match(rest, &path[skip..])),
        Some((head, rest)) => path
            .split_first()
            .is_some_and(|(first, tail)| name_matches(head, first) && parts_match(rest, tail)),
    }
}

fn names(path: &str) -> Vec<&str> {
    path.split('/').filter(|p| !p.is_empty()).collect()
}

/// `~` and `~/x` under `home`; other text unchanged.
pub fn tilde(text: &str, home: &str) -> String {
    match text.strip_prefix('~') {
        Some("") => home.to_string(),
        Some(rest) if rest.starts_with('/') => format!("{home}{rest}"),
        _ => text.to_string(),
    }
}

pub fn matches(pattern: &str, path: &Path, home: &str) -> bool {
    let pattern = tilde(pattern, home);
    let path = path.to_string_lossy();
    parts_match(&names(&pattern), &names(&path))
}

pub fn any(patterns: &[String], path: &Path, home: &str) -> bool {
    patterns.iter().any(|p| matches(p, path, home))
}

/// The path or one of its parents matches: the path lies inside a matched directory.
pub fn within(patterns: &[String], path: &Path, home: &str) -> bool {
    path.ancestors().any(|a| any(patterns, a, home))
}

/// An absolute path without `.` and `..`, resolved against `cwd`.
pub fn absolute(text: &str, cwd: &Path) -> PathBuf {
    let raw = Path::new(text);
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };
    let mut out = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// The path as written and, when a symbolic link leads elsewhere, the place it leads to.
pub fn spellings(path: PathBuf) -> Vec<PathBuf> {
    let real = path.canonicalize().ok().or_else(|| {
        let name = path.file_name()?;
        Some(path.parent()?.canonicalize().ok()?.join(name))
    });
    match real {
        Some(real) if real != path => vec![path, real],
        _ => vec![path],
    }
}
