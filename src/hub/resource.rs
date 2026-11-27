//! Resource names: `kind:value`, normalised so that two spellings cannot both be claimed.

use std::path::{Component, Path, PathBuf};

use super::{HubError, HubResult};
use crate::backlog::queue_index::declared_prefixes;

pub const KINDS: [&str; 9] = [
    "row", "tree", "repo", "branch", "host", "release", "deploy", "backlog", "fleet",
];
/// The fleet resource without a number: the ledger assigns the first free slot.
pub const ANY_SLOT: &str = "fleet:slot";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub kind: &'static str,
    pub name: String,
}

fn bad(raw: &str, why: &str) -> HubError {
    HubError::Usage(format!("invalid resource '{raw}': {why}"))
}

/// `GB-7`-shaped id of a declared queue, upper-cased.
pub fn row_id(raw: &str) -> HubResult<String> {
    let id = raw.trim().to_uppercase();
    let known = id.split_once('-').is_some_and(|(prefix, number)| {
        !number.is_empty()
            && number.bytes().all(|b| b.is_ascii_digit())
            && declared_prefixes().iter().any(|p| p == prefix)
    });
    if known {
        Ok(id)
    } else {
        Err(bad(
            raw,
            &format!(
                "a row id is <PREFIX>-<number> with a declared prefix ({})",
                declared_prefixes().join(", ")
            ),
        ))
    }
}

/// An absolute path without `.`/`..`; symlinks are resolved when the path exists.
fn tree_path(raw: &str, value: &str) -> HubResult<String> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(bad(raw, "a tree is an absolute path"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(bad(raw, "'..' is not allowed"));
    }
    let clean: PathBuf = path.components().collect();
    let resolved = clean.canonicalize().unwrap_or(clean);
    resolved
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| bad(raw, "the path is not UTF-8"))
}

impl Resource {
    pub fn parse(raw: &str) -> HubResult<Self> {
        let raw = raw.trim();
        let Some((kind, value)) = raw.split_once(':') else {
            return Err(bad(raw, "expected kind:value"));
        };
        let Some(kind) = KINDS.into_iter().find(|k| *k == kind) else {
            return Err(bad(raw, &format!("unknown kind; use {}", KINDS.join(", "))));
        };
        if value.is_empty() || value.chars().any(|c| c.is_control() || c == ',') {
            return Err(bad(raw, "empty value or forbidden character"));
        }
        if kind != "tree" && value.chars().any(char::is_whitespace) {
            return Err(bad(raw, "spaces are only allowed in tree paths"));
        }
        let value = match kind {
            "row" => row_id(value)?,
            "tree" => tree_path(raw, value)?,
            "repo" => value.to_lowercase(),
            "backlog" => {
                let prefix = value
                    .strip_suffix(":write")
                    .map(|p| p.trim_end_matches('-').to_uppercase())
                    .filter(|p| declared_prefixes().contains(p))
                    .ok_or_else(|| bad(raw, "expected backlog:<declared prefix>:write"))?;
                format!("{prefix}:write")
            }
            "fleet" => {
                let ok = value == "slot"
                    || value
                        .strip_prefix("slot/")
                        .and_then(|n| n.parse::<u32>().ok())
                        .is_some_and(|n| n > 0 && value == format!("slot/{n}"));
                if !ok {
                    return Err(bad(raw, "expected fleet:slot or fleet:slot/<n>"));
                }
                value.to_string()
            }
            _ => value.to_string(),
        };
        Ok(Resource {
            kind,
            name: format!("{kind}:{value}"),
        })
    }

    /// Claiming it starts new work, so the quota gate applies.
    pub fn starts_work(&self) -> bool {
        matches!(self.kind, "row" | "fleet")
    }

    pub fn value(&self) -> &str {
        self.name.split_once(':').map_or("", |(_, v)| v)
    }
}

/// Parses a list given as separate items or comma-separated, without duplicates.
pub fn parse_list(raw: &[String]) -> HubResult<Vec<Resource>> {
    let mut out: Vec<Resource> = Vec::new();
    for part in raw.iter().flat_map(|r| r.split(',')) {
        if part.trim().is_empty() {
            continue;
        }
        let resource = Resource::parse(part)?;
        if resource.name != ANY_SLOT && out.contains(&resource) {
            return Err(bad(part, "listed twice"));
        }
        out.push(resource);
    }
    if out.is_empty() {
        return Err(HubError::Usage("no resource to claim".to_string()));
    }
    Ok(out)
}

/// True when one tree contains the other (exact equality is left to the unique constraint).
pub fn nested(a: &str, b: &str) -> bool {
    let (a, b) = (Path::new(a), Path::new(b));
    a != b && (a.starts_with(b) || b.starts_with(a))
}
