//! What the application declares about its panels, shared by the panel rules.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use serde_json::Value;

/// Every JSON file of the application checkout.
fn json_files(app: &Path) -> Vec<PathBuf> {
    let mut walker = WalkBuilder::new(app);
    walker.hidden(true).git_ignore(true).parents(false);
    walker
        .build()
        .flatten()
        .map(ignore::DirEntry::into_path)
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect()
}

fn load(path: &Path) -> Option<Value> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

fn strings(value: &Value, keys: &[&str], out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                match v.as_str() {
                    Some(s) if keys.contains(&k.as_str()) => out.push(s.to_string()),
                    _ => strings(v, keys, out),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|v| strings(v, keys, out)),
        _ => {}
    }
}

/// Labels of the sidebar, the workspace and the dashboards, in their stored (English) form.
pub fn labels(app: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for path in json_files(app) {
        let text = path.to_string_lossy();
        let is_desk = ["desk/workspace.json", "desk/dashboard.json"]
            .iter()
            .any(|f| text.ends_with(f));
        let is_sidebar = path.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("sidebar" | "workspace_sidebar")
            )
        });
        if (is_desk || is_sidebar)
            && let Some(v) = load(&path)
        {
            strings(&v, &["label", "title", "dashboard_name"], &mut out);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Link labels of the sidebar only, the menu a manual lists.
pub fn menu(app: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for path in json_files(app) {
        let in_sidebar = path.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("sidebar" | "workspace_sidebar")
            )
        });
        let Some(v) = load(&path).filter(|_| in_sidebar) else {
            continue;
        };
        for item in v
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if item.get("type").and_then(Value::as_str) == Some("Link")
                && let Some(label) = item.get("label").and_then(Value::as_str)
            {
                out.push(label.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `msgid -> msgstr` of the Portuguese catalogue (single-line entries, which labels are).
pub fn catalogue(app: &Path) -> HashMap<String, String> {
    let text = fs::read_to_string(app.join("locale/pt_BR.po")).unwrap_or_default();
    let mut out = HashMap::new();
    let mut id = None;
    let quoted = |rest: &str| {
        rest.trim()
            .strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .map(|r| r.replace("\\\"", "\""))
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("msgid ") {
            id = quoted(rest).filter(|s| !s.is_empty());
        } else if let Some(rest) = line.strip_prefix("msgstr ")
            && let (Some(key), Some(value)) = (id.take(), quoted(rest))
        {
            out.insert(key, value);
        }
    }
    out
}

/// The `permissions` of a DocType found by name, as `role -> [read, write, create, delete]`.
pub fn permissions(app: &Path) -> HashMap<String, (PathBuf, HashMap<String, [bool; 4]>)> {
    let mut out = HashMap::new();
    for path in json_files(app) {
        let in_doctype = path.components().any(|c| c.as_os_str() == "doctype");
        let Some(v) = load(&path).filter(|_| in_doctype) else {
            continue;
        };
        if v.get("doctype").and_then(Value::as_str) != Some("DocType") {
            continue;
        }
        let Some(name) = v.get("name").and_then(Value::as_str) else {
            continue;
        };
        let mut roles: HashMap<String, [bool; 4]> = HashMap::new();
        for row in v
            .get("permissions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let level = row.get("permlevel").and_then(Value::as_u64).unwrap_or(0);
            let Some(role) = row
                .get("role")
                .and_then(Value::as_str)
                .filter(|_| level == 0)
            else {
                continue;
            };
            let granted = roles.entry(role.to_string()).or_default();
            for (slot, key) in ["read", "write", "create", "delete"].iter().enumerate() {
                granted[slot] |= row.get(*key).and_then(Value::as_u64) == Some(1);
            }
        }
        out.insert(name.to_string(), (path, roles));
    }
    out
}
