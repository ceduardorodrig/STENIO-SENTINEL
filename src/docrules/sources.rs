//! Resolution of the `file:line` citations documents make, shared by the citation rules.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use regex::Regex;

use super::Ctx;

/// Files by name under the trees a citation may point into.
pub struct Sources<'a> {
    ctx: &'a Ctx,
    indexed: HashMap<PathBuf, HashMap<String, Vec<PathBuf>>>,
}

impl<'a> Sources<'a> {
    pub fn new(ctx: &'a Ctx) -> Self {
        Sources {
            ctx,
            indexed: HashMap::new(),
        }
    }

    fn index(&mut self, base: &Path) -> &HashMap<String, Vec<PathBuf>> {
        self.indexed.entry(base.to_path_buf()).or_insert_with(|| {
            let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
            let mut walker = WalkBuilder::new(base);
            walker.hidden(true).git_ignore(true).parents(false);
            for entry in walker.build().flatten() {
                let path = entry.into_path();
                let noise = path.components().any(|c| {
                    matches!(
                        c.as_os_str().to_str(),
                        Some("node_modules" | "target" | ".stversions" | ".agents-work")
                    )
                });
                if noise || !path.is_file() {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    map.entry(name.to_string()).or_default().push(path.clone());
                }
            }
            map
        })
    }

    /// Directories the document names as the home of its sources (backticked absolute paths).
    pub fn declared_bases(content: &str) -> Vec<PathBuf> {
        let Ok(re) = Regex::new(r"`(/[\w.@/-]+)`") else {
            return Vec::new();
        };
        re.captures_iter(content)
            .map(|c| PathBuf::from(&c[1]))
            .filter(|p| p.is_dir() && p.components().count() > 3)
            .collect()
    }

    /// Every file `cited` can mean, from the nearest base outwards: the path relative to the
    /// citing file and its ancestors, then a path suffix inside the declared bases and the vault.
    pub fn resolve(&mut self, doc: &Path, bases: &[PathBuf], cited: &str) -> Vec<PathBuf> {
        let path = Path::new(cited);
        if path.is_absolute() {
            return Some(path.to_path_buf())
                .filter(|p| p.is_file())
                .into_iter()
                .collect();
        }
        let vault = self.ctx.vault.clone();
        let stop = vault.as_deref().unwrap_or(self.ctx.root()).to_path_buf();
        for dir in doc.ancestors().skip(1) {
            let candidate = dir.join(cited);
            if candidate.is_file() {
                return vec![candidate];
            }
            if dir == stop {
                break;
            }
        }
        let direct: Vec<PathBuf> = bases
            .iter()
            .map(|b| b.join(cited))
            .filter(|p| p.is_file())
            .collect();
        if !direct.is_empty() {
            return direct;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for base in bases.iter().cloned().chain([stop]) {
            if let Some(hits) = self.index(&base).get(name) {
                found.extend(hits.iter().filter(|h| h.ends_with(cited)).cloned());
            }
            if !found.is_empty() {
                break;
            }
        }
        found
    }

    pub fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .map(|t| t.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }
}
