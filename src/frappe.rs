//! Scope `frappe`: deterministic static rules over a Frappe app tree (GB-007, 2026-11-04).
//!
//! WHY IT EXISTS: releases rc68 to rc73 of the Miracena platform lost hours to bugs a program
//! finds offline in seconds (child DocTypes without a controller module, Link fields whose
//! target has no title field, tests or patches not registered, hook paths that do not exist,
//! roles nobody defines). Every rule here is static (no site, no bench) and has no
//! suppression directive. The app is described by the `[frappe]` table of `steniocheck.toml`
//! (`crate::config::FrappeConfig`); no project name lives in the engine.
//!
//! References: Frappe docs, "DocType" (controller `<name>.py` next to `<name>.json`), "Hooks"
//! (dotted paths), "Patches" (`patches.txt`), "Sidebar" and gettext "PO Files".

use ignore::WalkBuilder;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::FrappeConfig;
use crate::engine::Violation;
use crate::i18n;
use crate::rule::Severity;

pub const RULES: &[(&str, &str, Severity)] = &[
    (
        "FRAPPE-DOCTYPE-CONTROLLER",
        "DocType Controller Missing",
        Severity::Error,
    ),
    (
        "FRAPPE-LINK-TITLE",
        "Link Target Without Title Field",
        Severity::Error,
    ),
    (
        "FRAPPE-PATCH-REGISTERED",
        "Patch Not Registered",
        Severity::Error,
    ),
    (
        "FRAPPE-HOOK-TARGETS",
        "Hook Path Does Not Resolve",
        Severity::Error,
    ),
    (
        "FRAPPE-TEST-REGISTERED",
        "Test Not Registered",
        Severity::Error,
    ),
    (
        "FRAPPE-SIDEBAR-COVERAGE",
        "Sidebar Does Not Cover DocType",
        Severity::Error,
    ),
    ("FRAPPE-ROLE-DEFINED", "Role Not Defined", Severity::Error),
    (
        "FRAPPE-SELECT-CASE",
        "Select Option Case Mismatch",
        Severity::Error,
    ),
    (
        "FRAPPE-DOCTYPE-LABEL-TRANSLATED",
        "JSON Label Without Translation",
        Severity::Error,
    ),
    (
        "FRAPPE-WHITELIST-PERMISSION",
        "Whitelisted Function Without Permission Check",
        Severity::Warning,
    ),
];

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".stversions",
    "dist",
    "build",
    "site-packages",
];

/// Frappe core targets and roles that exist without any app fixture.
const CORE_LINK_TARGETS: &[&str] = &[
    "User",
    "Role",
    "Company",
    "Employee",
    "Project",
    "Task",
    "Customer",
    "Supplier",
    "Item",
    "Currency",
    "Country",
    "File",
    "Contact",
    "Address",
    "Department",
    "Designation",
    "Print Format",
    "Email Template",
    "Workspace",
    "DocType",
    "Module Def",
    "Language",
    "Letter Head",
    "Cost Center",
    "Account",
    "Sales Invoice",
    "Purchase Invoice",
    "Payment Entry",
    "Bank",
    "Bank Account",
];
const CORE_ROLES: &[&str] = &[
    "System Manager",
    "Administrator",
    "All",
    "Guest",
    "Desk User",
    "Report Manager",
    "Workspace Manager",
    "Website Manager",
    "Blogger",
    "Newsletter Manager",
    "Script Manager",
    "Dashboard Manager",
    "Accounts Manager",
    "Accounts User",
    "HR Manager",
    "HR User",
    "Projects Manager",
    "Projects User",
    "Employee",
    "Employee Self Service",
    "Sales Manager",
    "Sales User",
    "Purchase Manager",
    "Purchase User",
    "Stock Manager",
    "Stock User",
    "Support Team",
    "Customer",
    "Supplier",
];
const PERMISSION_MARKERS: &[&str] = &[
    "only_for",
    "has_permission",
    "check_permission",
    "PermissionError",
    "get_roles",
    "validate_permission",
    "_require",
    "require_",
    "ensure_",
    "_ensure",
];

const PT_SMALL: &[&str] = &[
    "de", "da", "do", "das", "dos", "e", "em", "a", "o", "as", "os", "para", "por", "com", "no",
    "na", "nos", "nas", "ao", "à", "ou", "um", "uma", "que", "se", "sem", "sob", "entre", "até",
    "pelo", "pela", "num", "numa",
];
const EN_SMALL: &[&str] = &[
    "with", "from", "into", "that", "this", "your", "have", "been", "only", "each", "than", "then",
    "when", "will",
];
const EN_STOP: &[&str] = &[
    "and", "the", "for", "per", "via", "not", "off", "out", "are", "was", "its", "but", "all",
    "any", "new",
];

fn viol(id: &str, path: &str, line: usize, snip: &str, msg: String, hint: &str) -> Violation {
    let (name, sev) = RULES
        .iter()
        .find(|r| r.0 == id)
        .map(|r| (r.1, r.2))
        .unwrap_or(("Frappe", Severity::Error));
    Violation {
        rule_id: id.to_string(),
        rule_name: name.to_string(),
        severity: sev,
        file_path: path.to_string(),
        line_number: line.max(1),
        snippet: snip.chars().take(120).collect(),
        message: msg,
        suggestion: Some(hint.to_string()),
    }
}

struct Field {
    fieldname: String,
    fieldtype: String,
    options: String,
}

struct DocType {
    name: String,
    rel: String,
    text: String,
    is_child: bool,
    title_ok: bool,
    fields: Vec<Field>,
    roles: Vec<String>,
}

struct Ctx {
    root: PathBuf,
    pkg: PathBuf,
    app: String,
    cfg: FrappeConfig,
    files: Vec<PathBuf>,
    doctypes: Vec<DocType>,
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .to_string()
}

fn line_of(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|l| l.contains(needle))
        .map(|i| i + 1)
        .unwrap_or(1)
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    WalkBuilder::new(dir)
        .hidden(false)
        .filter_entry(|e| {
            e.file_name()
                .to_str()
                .map(|n| !SKIP_DIRS.contains(&n))
                .unwrap_or(true)
        })
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.into_path())
        .collect()
}

pub(crate) fn infer_app(root: &Path) -> Option<String> {
    let mut found: Vec<String> = fs::read_dir(root)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("hooks.py").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    found.sort();
    found.into_iter().next()
}

fn str_of(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn flag(v: &Value, key: &str) -> bool {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
        Some(Value::Bool(b)) => *b,
        _ => false,
    }
}

fn load_doctype(root: &Path, path: &Path) -> Option<DocType> {
    let text = read(path);
    let v: Value = serde_json::from_str(&text).ok()?;
    if str_of(&v, "doctype") != "DocType" {
        return None;
    }
    let fields = v
        .get("fields")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .map(|f| Field {
                    fieldname: str_of(f, "fieldname"),
                    fieldtype: str_of(f, "fieldtype"),
                    options: str_of(f, "options"),
                })
                .collect()
        })
        .unwrap_or_default();
    let roles = v
        .get("permissions")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .map(|p| str_of(p, "role"))
                .filter(|r| !r.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let title_ok = (!str_of(&v, "title_field").is_empty() && flag(&v, "show_title_field_in_link"))
        || !str_of(&v, "search_fields").trim().is_empty();
    Some(DocType {
        name: str_of(&v, "name"),
        rel: rel(root, path),
        is_child: flag(&v, "istable"),
        title_ok,
        fields,
        roles,
        text,
    })
}

fn build_ctx(root: &Path, cfg: &FrappeConfig) -> Result<Ctx, String> {
    let app = match cfg.app.clone().or_else(|| infer_app(root)) {
        Some(a) => a,
        None => {
            return Err("no Frappe app found: set `app` in [frappe] of steniocheck.toml".into());
        }
    };
    let pkg = root.join(&app);
    if !pkg.is_dir() {
        return Err(format!(
            "app package directory {} does not exist",
            pkg.display()
        ));
    }
    let files = walk(&pkg);
    let doctypes = files
        .iter()
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
        .filter(|p| {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            p.parent()
                .and_then(|d| d.file_name())
                .and_then(|n| n.to_str())
                == Some(stem)
                && p.parent()
                    .and_then(|d| d.parent())
                    .and_then(|d| d.file_name())
                    .and_then(|n| n.to_str())
                    == Some("doctype")
        })
        .filter_map(|p| load_doctype(root, p))
        .collect();
    Ok(Ctx {
        root: root.to_path_buf(),
        pkg,
        app,
        cfg: cfg.clone(),
        files,
        doctypes,
    })
}

fn title_source(msgid: &str) -> bool {
    let Ok(word) = Regex::new(r"[A-Za-z][A-Za-z'\-]*") else {
        return false;
    };
    let words: Vec<&str> = word.find_iter(msgid).map(|m| m.as_str()).collect();
    if words.len() < 2
        || words.len() > 6
        || msgid.contains(['{', '%', '<', '.', ':', ';', '?', '!'])
    {
        return false;
    }
    let low = |w: &str| w.to_lowercase();
    let big = words
        .iter()
        .any(|w| w.len() >= 4 && !EN_SMALL.contains(&low(w).as_str()));
    let content = words.iter().filter(|w| {
        w.len() >= 3 && !EN_SMALL.contains(&low(w).as_str()) && !EN_STOP.contains(&low(w).as_str())
    });
    big && content
        .into_iter()
        .all(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
}

/// Capitalisation problems of a translation (first letter, Title Case labels); shared with `pre-release`.
pub fn case_problems(msgid: &str, msgstr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let first = msgstr.chars().find(|c| c.is_alphabetic());
    let id0 = msgid.chars().next();
    if id0
        .map(|c| c.is_alphabetic() && c.is_uppercase())
        .unwrap_or(false)
        && first.map(|c| c.is_lowercase()).unwrap_or(false)
    {
        out.push("first letter should be uppercase".to_string());
    }
    if title_source(msgid) && !msgstr.contains(['{', '%', '<']) {
        let bad: Vec<&str> = msgstr
            .split_whitespace()
            .enumerate()
            .filter_map(|(i, t)| {
                let w = trim_word(t);
                let c0 = w.chars().next()?;
                let ok = c0.is_alphabetic()
                    && c0.is_lowercase()
                    && !is_upper(w)
                    && !w.chars().any(|c| c.is_ascii_digit() || c == '_')
                    && (i == 0 || !PT_SMALL.contains(&w.to_lowercase().as_str()));
                ok.then_some(w)
            })
            .collect();
        if !bad.is_empty() {
            out.push(format!(
                "Title Case label, lowercase word(s): {}",
                bad.join(", ")
            ));
        }
    }
    out
}

// ── FRAPPE-DOCTYPE-CONTROLLER ──────────────────────────────────────────────
fn rule_controller(c: &Ctx) -> Vec<Violation> {
    let class_re = Regex::new(r"(?m)^class\s+\w+").ok();
    let mut out = Vec::new();
    for json in c.files.iter().filter(|p| {
        p.extension().map(|e| e == "json").unwrap_or(false)
            && p.parent()
                .and_then(|d| d.parent())
                .and_then(|d| d.file_name())
                .and_then(|n| n.to_str())
                == Some("doctype")
            && p.file_stem() == p.parent().and_then(|d| d.file_name())
    }) {
        let dir = match json.parent() {
            Some(d) => d,
            None => continue,
        };
        let stem = json.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let r = rel(&c.root, json);
        if !dir.join("__init__.py").is_file() {
            out.push(viol("FRAPPE-DOCTYPE-CONTROLLER", &r, 1, stem,
                format!("DocType folder `{stem}` has no __init__.py: migrate cannot import the controller."),
                "Create an empty __init__.py in the DocType folder."));
        }
        let py = dir.join(format!("{stem}.py"));
        let ok = class_re
            .as_ref()
            .map(|re| re.is_match(&read(&py)))
            .unwrap_or(false);
        if !ok {
            out.push(viol("FRAPPE-DOCTYPE-CONTROLLER", &r, 1, stem,
                format!("DocType `{stem}` has no `{stem}.py` defining a class: migrate fails on it (child DocTypes too)."),
                "Add `<name>.py` with `class <Name>(Document): pass` next to the JSON."));
        }
    }
    out
}

// ── FRAPPE-LINK-TITLE ──────────────────────────────────────────────────────
fn rule_link_title(c: &Ctx) -> Vec<Violation> {
    let skip: BTreeSet<&str> = CORE_LINK_TARGETS
        .iter()
        .copied()
        .chain(c.cfg.link_allowlist.iter().flatten().map(|s| s.as_str()))
        .collect();
    let by_name: HashMap<&str, &DocType> =
        c.doctypes.iter().map(|d| (d.name.as_str(), d)).collect();
    let mut out = Vec::new();
    for d in &c.doctypes {
        for f in d.fields.iter().filter(|f| f.fieldtype == "Link") {
            if skip.contains(f.options.as_str()) {
                continue;
            }
            if let Some(t) = by_name.get(f.options.as_str()).filter(|t| !t.title_ok) {
                {
                    out.push(viol("FRAPPE-LINK-TITLE", &d.rel, line_of(&d.text, &format!("\"{}\"", f.fieldname)),
                        &f.fieldname,
                        format!("Link `{}.{}` targets `{}`, which has neither title_field with show_title_field_in_link nor search_fields.", d.name, f.fieldname, t.name),
                        "Set title_field and show_title_field_in_link=1 (or search_fields) on the target DocType."));
                }
            }
        }
    }
    out
}

// ── dotted path resolution (hooks, patches) ────────────────────────────────
enum Resolved {
    Ok,
    External,
    Missing(String),
}

fn resolve_dotted(c: &Ctx, dotted: &str) -> Resolved {
    let parts: Vec<&str> = dotted.split('.').collect();
    if parts.first().copied() != Some(c.app.as_str()) {
        return Resolved::External;
    }
    for i in (1..=parts.len()).rev() {
        let base = parts[..i].iter().fold(c.root.clone(), |p, s| p.join(s));
        let file = if base.with_extension("py").is_file() {
            base.with_extension("py")
        } else if base.join("__init__.py").is_file() {
            base.join("__init__.py")
        } else {
            continue;
        };
        let rest = &parts[i..];
        if rest.is_empty() {
            return Resolved::Ok;
        }
        let name = regex::escape(rest[0]);
        let pat = format!(
            r"(?m)^(?:async\s+)?(?:def|class)\s+{name}\b|^{name}\s*(?::[^=\n]+)?=|^from\s+\S+\s+import\s+.*\b{name}\b"
        );
        let found = Regex::new(&pat)
            .map(|re| re.is_match(&read(&file)))
            .unwrap_or(false);
        return if found {
            Resolved::Ok
        } else {
            Resolved::Missing(format!(
                "module `{}` exists but defines no `{}`",
                parts[..i].join("."),
                rest[0]
            ))
        };
    }
    Resolved::Missing(format!("no module for `{dotted}`"))
}

// ── FRAPPE-PATCH-REGISTERED ────────────────────────────────────────────────
fn rule_patches(c: &Ctx) -> Vec<Violation> {
    let list = c.pkg.join("patches.txt");
    let text = read(&list);
    let lr = rel(&c.root, &list);
    let mut listed: BTreeMap<String, usize> = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let l = raw.split('#').next().unwrap_or("").trim();
        if l.is_empty() || l.starts_with('[') || l.starts_with("execute:") {
            continue;
        }
        listed.insert(l.split_whitespace().next().unwrap_or("").to_string(), i + 1);
    }
    let mut out = Vec::new();
    let prefix = format!("{}.patches.", c.app);
    for p in c.files.iter().filter(|p| {
        p.extension().map(|e| e == "py").unwrap_or(false)
            && p.parent() == Some(c.pkg.join("patches").as_path())
            && p.file_stem().and_then(|s| s.to_str()) != Some("__init__")
    }) {
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if !listed.contains_key(&format!("{prefix}{stem}")) {
            out.push(viol(
                "FRAPPE-PATCH-REGISTERED",
                &rel(&c.root, p),
                1,
                stem,
                format!(
                    "Patch `{stem}.py` is not listed in patches.txt: it never runs on migrate."
                ),
                "Add `<app>.patches.<name>` to the right section of patches.txt.",
            ));
        }
    }
    for (name, line) in &listed {
        if let Resolved::Missing(why) = resolve_dotted(c, name) {
            out.push(viol(
                "FRAPPE-PATCH-REGISTERED",
                &lr,
                *line,
                name,
                format!("patches.txt lists `{name}` but it does not resolve: {why}."),
                "Create the patch module or remove the line.",
            ));
        }
    }
    out
}

// ── FRAPPE-HOOK-TARGETS ────────────────────────────────────────────────────
fn strip_comment(line: &str) -> String {
    let mut quote: Option<char> = None;
    let mut out = String::new();
    for ch in line.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch == '#' => break,
            None => {}
        }
        out.push(ch);
    }
    out
}

fn rule_hooks(c: &Ctx) -> Vec<Violation> {
    let hooks = c.pkg.join("hooks.py");
    let text = read(&hooks);
    let hr = rel(&c.root, &hooks);
    let re = match Regex::new(r#"["']([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)["']"#) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = strip_comment(raw);
        for m in re.captures_iter(&line) {
            let path = &m[1];
            if let Resolved::Missing(why) = resolve_dotted(c, path) {
                out.push(viol(
                    "FRAPPE-HOOK-TARGETS",
                    &hr,
                    i + 1,
                    raw.trim(),
                    format!("Hook path `{path}` does not resolve: {why}."),
                    "Fix the dotted path or define the function in that module.",
                ));
            }
        }
    }
    out
}

// ── FRAPPE-TEST-REGISTERED ─────────────────────────────────────────────────
fn section(text: &str, anchor: &str) -> Option<String> {
    let mut lines = text.lines();
    let mut found = false;
    let mut body = String::new();
    for l in lines.by_ref() {
        if l.trim_start().starts_with(anchor) {
            found = true;
            body.push_str(l);
            body.push('\n');
            break;
        }
    }
    if !found {
        return None;
    }
    for l in lines {
        if l.starts_with("## ") {
            break;
        }
        body.push_str(l);
        body.push('\n');
    }
    Some(body)
}

fn rule_tests(c: &Ctx) -> Vec<Violation> {
    let (file, anchor) = match (&c.cfg.test_list_file, &c.cfg.test_list_anchor) {
        (Some(f), Some(a)) => (f, a),
        _ => return Vec::new(), // not configured: nothing to compare against
    };
    let path = if Path::new(file).is_absolute() {
        PathBuf::from(file)
    } else {
        c.root.join(file)
    };
    let tr = rel(&c.root, &path);
    let sec = match fs::read_to_string(&path)
        .ok()
        .and_then(|t| section(&t, anchor))
    {
        Some(s) => s,
        None => {
            return vec![viol(
                "FRAPPE-TEST-REGISTERED",
                &tr,
                1,
                anchor,
                format!("Configured test list section `{anchor}` not found in {tr}."),
                "Fix test_list_file / test_list_anchor in [frappe] or restore the section.",
            )];
        }
    };
    let run_re = Regex::new(r"(?m)^def run\b").ok();
    let mut out = Vec::new();
    for p in c.files.iter().filter(|p| {
        p.extension().map(|e| e == "py").unwrap_or(false)
            && p.parent() == Some(c.pkg.join("tests").as_path())
    }) {
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if stem == "__init__"
            || !run_re
                .as_ref()
                .map(|r| r.is_match(&read(p)))
                .unwrap_or(false)
        {
            continue;
        }
        let listed = Regex::new(&format!(r"\b{}\b", regex::escape(stem)))
            .map(|r| r.is_match(&sec))
            .unwrap_or(false);
        if !listed {
            out.push(viol("FRAPPE-TEST-REGISTERED", &rel(&c.root, p), 1, stem,
                format!("Test `{stem}` defines run() but is not in the test list of {tr} (section `{anchor}`): the release battery never runs it."),
                "Add the module to the test list of the repository AGENTS.md (and to the rehearsal script)."));
        }
    }
    out
}

// ── .po helpers, FRAPPE-SIDEBAR-COVERAGE, FRAPPE-SELECT-CASE ───────────────
fn catalogue(c: &Ctx) -> Option<(String, BTreeMap<String, String>)> {
    let rel_loc = c
        .cfg
        .locale_file
        .clone()
        .unwrap_or_else(|| "locale/pt_BR.po".into());
    let path = c.pkg.join(&rel_loc);
    let text = fs::read_to_string(&path).ok()?;
    let map = i18n::parse_po(&text)
        .into_iter()
        .filter(|e| !e.obsolete && !e.msgid.is_empty())
        .map(|e| (e.msgid, e.strs.first().cloned().unwrap_or_default()))
        .collect();
    Some((rel(&c.root, &path), map))
}

fn rule_sidebar(c: &Ctx) -> Vec<Violation> {
    let sidebars: Vec<&PathBuf> = c
        .files
        .iter()
        .filter(|p| {
            p.extension().map(|e| e == "json").unwrap_or(false)
                && p.parent()
                    .and_then(|d| d.parent())
                    .and_then(|d| d.file_name())
                    .and_then(|n| n.to_str())
                    == Some("sidebar")
        })
        .collect();
    if sidebars.is_empty() {
        return Vec::new();
    }
    let po = catalogue(c);
    let mut linked: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for s in sidebars {
        let text = read(s);
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for item in v
            .get("items")
            .and_then(|i| i.as_array())
            .into_iter()
            .flatten()
        {
            if str_of(item, "link_type") == "DocType" {
                linked.insert(str_of(item, "link_to"));
            }
            let label = str_of(item, "label");
            if let Some((pr, map)) = po.as_ref() {
                let literal = label
                    .chars()
                    .next()
                    .map(|ch| ch.is_alphabetic())
                    .unwrap_or(false)
                    && !label.contains('{');
                if literal && !map.contains_key(&label) {
                    out.push(viol(
                        "FRAPPE-SIDEBAR-COVERAGE",
                        &rel(&c.root, s),
                        line_of(&text, &format!("\"{label}\"")),
                        &label,
                        format!(
                            "Sidebar label `{label}` has no msgid in {pr}: it shows in English."
                        ),
                        "Add the msgid and its translation to the catalogue.",
                    ));
                }
            }
        }
    }
    let mut allowed: BTreeSet<String> = BTreeSet::new();
    let mut allow_path = String::new();
    if let Some(f) = &c.cfg.sidebar_allowlist {
        let p = if Path::new(f).is_absolute() {
            PathBuf::from(f)
        } else {
            c.root.join(f)
        };
        allow_path = rel(&c.root, &p);
        for (i, raw) in read(&p).lines().enumerate() {
            let l = raw.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let (name, reason) = l
                .split_once('|')
                .or_else(|| l.split_once(':'))
                .unwrap_or((l, ""));
            if reason.trim().is_empty() {
                out.push(viol(
                    "FRAPPE-SIDEBAR-COVERAGE",
                    &allow_path,
                    i + 1,
                    l,
                    format!("Allowlist entry `{}` has no reason.", name.trim()),
                    "Write `DocType | reason`.",
                ));
            }
            allowed.insert(name.trim().to_string());
        }
    }
    for d in c.doctypes.iter().filter(|d| !d.is_child) {
        if !linked.contains(&d.name) && !allowed.contains(&d.name) {
            out.push(viol(
                "FRAPPE-SIDEBAR-COVERAGE",
                &d.rel,
                1,
                &d.name,
                format!(
                    "DocType `{}` is not in the sidebar{}.",
                    d.name,
                    if allow_path.is_empty() {
                        String::new()
                    } else {
                        format!(" or in {allow_path}")
                    }
                ),
                "Add a sidebar link, or list it in the allowlist file with a reason.",
            ));
        }
    }
    out
}

fn is_upper(w: &str) -> bool {
    w.chars().any(|c| c.is_alphabetic()) && !w.chars().any(|c| c.is_lowercase())
}

fn trim_word(t: &str) -> &str {
    t.trim_matches(|c: char| !(c.is_alphanumeric() || c == '_'))
}

/// "title" when every content word after the first is capitalised, "sentence" when none, "mixed", or None.
pub fn case_pattern(text: &str, small: &[&[&str]]) -> Option<&'static str> {
    let words: Vec<&str> = text
        .split_whitespace()
        .map(trim_word)
        .filter(|w| {
            w.chars().next().map(|c| c.is_alphabetic()).unwrap_or(false)
                && !is_upper(w)
                && !w.chars().any(|c| c.is_ascii_digit() || c == '_')
        })
        .collect();
    let rest: Vec<&&str> = words
        .iter()
        .skip(1)
        .filter(|w| {
            w.chars().count() >= 3 && !small.iter().any(|s| s.contains(&w.to_lowercase().as_str()))
        })
        .collect();
    if words.len() < 2 || rest.is_empty() || text.contains(['{', '%', '<']) {
        return None;
    }
    let upper = rest
        .iter()
        .filter(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
        .count();
    Some(if upper == rest.len() {
        "title"
    } else if upper == 0 {
        "sentence"
    } else {
        "mixed"
    })
}

pub fn select_case_problem(option: &str, translated: &str) -> Option<String> {
    let sp = case_pattern(option, &[EN_SMALL, EN_STOP])?;
    let tp = case_pattern(translated, &[PT_SMALL])?;
    (sp != tp)
        .then(|| format!("`{option}` is {sp} case but its translation `{translated}` is {tp} case"))
}

fn rule_select_case(c: &Ctx) -> Vec<Violation> {
    let Some((pr, map)) = catalogue(c) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for d in &c.doctypes {
        for f in d.fields.iter().filter(|f| f.fieldtype == "Select") {
            for opt in f
                .options
                .split('\n')
                .map(str::trim)
                .filter(|o| !o.is_empty())
            {
                let tr = map.get(opt).map(String::as_str).unwrap_or("");
                if tr.is_empty() {
                    continue;
                }
                if let Some(p) = select_case_problem(opt, tr) {
                    out.push(viol("FRAPPE-SELECT-CASE", &d.rel, line_of(&d.text, &format!("\"{}\"", f.fieldname)), opt,
                        format!("{}.{}: {p} ({pr}).", d.name, f.fieldname),
                        "A sentence-case source keeps a sentence-case translation, and Title Case keeps Title Case."));
                }
            }
        }
    }
    out
}

// ── FRAPPE-DOCTYPE-LABEL-TRANSLATED ────────────────────────────────────────
fn collect_translatable(v: &Value, doctype_file: bool, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            let select_options = (m.get("fieldtype").and_then(|x| x.as_str()) == Some("Select"))
                .then(|| m.get("options").and_then(|x| x.as_str()))
                .flatten();
            if let Some(o) = select_options {
                out.extend(o.split('\n').map(|x| x.trim().to_string()));
            }
            for (k, val) in m {
                match (k.as_str(), val) {
                    ("label" | "chart_name", Value::String(t)) => out.push(t.trim().to_string()),
                    ("description", Value::String(t)) if doctype_file => {
                        out.push(t.trim().to_string())
                    }
                    _ => collect_translatable(val, doctype_file, out),
                }
            }
        }
        Value::Array(a) => a
            .iter()
            .for_each(|x| collect_translatable(x, doctype_file, out)),
        _ => {}
    }
}

fn technical(s: &str, allow: &[String]) -> bool {
    !s.chars().any(|c| c.is_alphabetic())
        || s.contains("{{")
        || (s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-/".contains(c)))
        || allow.iter().any(|a| a == s)
}

fn rule_labels(c: &Ctx) -> Vec<Violation> {
    let Some((pr, map)) = catalogue(c) else {
        return Vec::new();
    };
    let allow = c.cfg.label_allowlist.clone().unwrap_or_default();
    let kinds = [
        "doctype",
        "workspace",
        "number_card",
        "dashboard_chart",
        "sidebar",
    ];
    let mut out = Vec::new();
    for p in c
        .files
        .iter()
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
    {
        let dirs: Vec<String> = rel(&c.pkg, p).split('/').map(str::to_string).collect();
        let stem = p.file_stem().and_then(|x| x.to_str()).unwrap_or("");
        let is_fixture =
            dirs.first().map(|d| d == "fixtures").unwrap_or(false) && kinds.contains(&stem);
        let in_kind = dirs
            .iter()
            .rev()
            .skip(2)
            .take(1)
            .any(|d| kinds.contains(&d.as_str()));
        if !(is_fixture || in_kind) {
            continue;
        }
        let text = read(p);
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let mut strings = Vec::new();
        collect_translatable(&v, dirs.iter().any(|d| d == "doctype"), &mut strings);
        let sidebar = dirs.iter().any(|d| d == "sidebar");
        let mut seen = BTreeSet::new();
        for t in strings
            .into_iter()
            .filter(|t| !t.is_empty() && !technical(t, &allow))
        {
            if !seen.insert(t.clone()) {
                continue;
            }
            let why = match map.get(&t) {
                None if sidebar => continue, // reported by FRAPPE-SIDEBAR-COVERAGE
                None => "has no msgid",
                Some(m) if m.trim().is_empty() => "has an empty translation",
                Some(_) => continue,
            };
            out.push(viol("FRAPPE-DOCTYPE-LABEL-TRANSLATED", &rel(&c.root, p), line_of(&text, &format!("\"{}\"", t.split('\n').next().unwrap_or(""))), &t,
                format!("`{t}` {why} in {pr}: the desk shows it in English."),
                "Add the msgid with its translation (copy it only for symbols), or list a technical option in label_allowlist."));
        }
    }
    out
}

// ── FRAPPE-ROLE-DEFINED ────────────────────────────────────────────────────
fn rule_roles(c: &Ctx) -> Vec<Violation> {
    let mut defined: BTreeSet<String> = CORE_ROLES
        .iter()
        .map(|s| s.to_string())
        .chain(c.cfg.role_allowlist.iter().flatten().cloned())
        .collect();
    for p in c.files.iter().filter(|p| {
        p.extension().map(|e| e == "json").unwrap_or(false)
            && p.parent()
                .and_then(|d| d.file_name())
                .and_then(|n| n.to_str())
                == Some("fixtures")
    }) {
        if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&read(p)) {
            for it in items.iter().filter(|i| str_of(i, "doctype") == "Role") {
                defined.insert(str_of(it, "role_name"));
                defined.insert(str_of(it, "name"));
            }
        }
    }
    let patch_text: String = c
        .files
        .iter()
        .filter(|p| {
            p.extension().map(|e| e == "py").unwrap_or(false)
                && p.parent() == Some(c.pkg.join("patches").as_path())
        })
        .map(|p| read(p))
        .filter(|t| t.contains("Role"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut out = Vec::new();
    for d in &c.doctypes {
        for r in &d.roles {
            let in_patch =
                patch_text.contains(&format!("\"{r}\"")) || patch_text.contains(&format!("'{r}'"));
            if !defined.contains(r) && !in_patch {
                out.push(viol("FRAPPE-ROLE-DEFINED", &d.rel, line_of(&d.text, &format!("\"{r}\"")), r,
                    format!("DocType `{}` grants permissions to role `{r}`, which no fixture, patch or core allowlist defines.", d.name),
                    "Add the role to fixtures/role.json (or a patch that creates it), or to role_allowlist."));
            }
        }
    }
    out
}

// ── FRAPPE-WHITELIST-PERMISSION ────────────────────────────────────────────
fn rule_whitelist(c: &Ctx) -> Vec<Violation> {
    let markers: Vec<&str> = PERMISSION_MARKERS
        .iter()
        .copied()
        .chain(
            c.cfg
                .permission_markers
                .iter()
                .flatten()
                .map(|s| s.as_str()),
        )
        .collect();
    let indent = |l: &str| l.len() - l.trim_start().len();
    let mut out = Vec::new();
    for p in c.files.iter().filter(|p| {
        p.extension().map(|e| e == "py").unwrap_or(false)
            && !rel(&c.pkg, p)
                .split('/')
                .any(|s| s == "tests" || s == "patches")
    }) {
        let text = read(p);
        let lines: Vec<&str> = text.lines().collect();
        let mut i = 0;
        while i < lines.len() {
            if !lines[i].trim_start().starts_with("@frappe.whitelist") {
                i += 1;
                continue;
            }
            let mut j = i + 1;
            while j < lines.len()
                && !lines[j].trim_start().starts_with("def ")
                && !lines[j].trim_start().starts_with("async def ")
            {
                j += 1;
            }
            if j >= lines.len() {
                break;
            }
            let base = indent(lines[j]);
            let mut k = j + 1;
            while k < lines.len() && (lines[k].trim().is_empty() || indent(lines[k]) > base) {
                k += 1;
            }
            let body = lines[j..k].join("\n");
            if !markers.iter().any(|m| body.contains(m)) {
                let name = lines[j]
                    .trim()
                    .trim_start_matches("async ")
                    .trim_start_matches("def ");
                let name = name.split('(').next().unwrap_or("");
                out.push(viol("FRAPPE-WHITELIST-PERMISSION", &rel(&c.root, p), j + 1, lines[j].trim(),
                    format!("Whitelisted function `{name}` has no permission check (frappe.only_for, has_permission, PermissionError or get_roles)."),
                    "Check the caller's permission inside the function; whitelisted means callable by any logged-in user."));
            }
            i = k.max(i + 1);
        }
    }
    out
}

/// Runs every rule and returns the violations (sorted by file and line).
pub fn audit(root: &Path, cfg: &FrappeConfig) -> Result<Vec<Violation>, String> {
    let c = build_ctx(root, cfg)?;
    let mut all: Vec<Violation> = Vec::new();
    for f in [
        rule_controller,
        rule_link_title,
        rule_patches,
        rule_hooks,
        rule_tests,
        rule_sidebar,
        rule_roles,
        rule_select_case,
        rule_labels,
        rule_whitelist,
    ] {
        all.extend(f(&c));
    }
    all.sort_by(|a, b| {
        (&a.rule_id, &a.file_path, a.line_number).cmp(&(&b.rule_id, &b.file_path, b.line_number))
    });
    Ok(all)
}

// ── self-test fixtures ─────────────────────────────────────────────────────
const THING_JSON: &str = r#"{"doctype":"DocType","name":"Thing","fields":[{"fieldname":"part","fieldtype":"Link","options":"Part","label":"LBL"},{"fieldname":"state","fieldtype":"Select","options":"Open day\nClosed day"}],"permissions":[{"role":"ROLE"}]}"#;
const PART_JSON_GOOD: &str = r#"{"doctype":"DocType","name":"Part","title_field":"label","show_title_field_in_link":1,"fields":[]}"#;
const PART_JSON_BAD: &str = r#"{"doctype":"DocType","name":"Part","fields":[]}"#;
const PO_GOOD: &str = "msgid \"\"\nmsgstr \"\"\n\nmsgid \"Things\"\nmsgstr \"Coisas\"\n\nmsgid \"Parts\"\nmsgstr \"Pecas\"\n\nmsgid \"Part\"\nmsgstr \"Peca\"\n\nmsgid \"Open day\"\nmsgstr \"Dia aberto\"\n\nmsgid \"Closed day\"\nmsgstr \"Dia fechado\"\n";

/// The files of a tiny demo app; `bad` plants one violation of every rule.
pub fn fixture_files(bad: bool) -> Vec<(String, String)> {
    let f = |p: &str, t: &str| (p.to_string(), t.to_string());
    let mut v = vec![
        f("demoapp/__init__.py", "__version__ = \"0.1.0\"\n"),
        f("demoapp/modules.txt", "Demo\n"),
        f(
            "demoapp/hooks.py",
            &format!(
                "app_name = \"demoapp\"\ndoc_events = {{\"ToDo\": {{\"on_update\": \"demoapp.api.{}\"}}}}  # \"demoapp.api.commented\"\n",
                if bad { "missing_fn" } else { "on_todo" }
            ),
        ),
        f(
            "demoapp/api.py",
            &format!(
                "import frappe\n\n\ndef on_todo(doc, method=None):\n    pass\n\n\n@frappe.whitelist()\ndef ping():\n    {}\n    return 1\n",
                if bad {
                    "pass"
                } else {
                    "frappe.only_for(\"System Manager\")"
                }
            ),
        ),
        f(
            "demoapp/patches.txt",
            &format!(
                "[post_model_sync]\ndemoapp.patches.first\n{}",
                if bad { "demoapp.patches.ghost\n" } else { "" }
            ),
        ),
        f("demoapp/patches/__init__.py", ""),
        f("demoapp/patches/first.py", "def execute():\n    pass\n"),
        f("demoapp/demo/doctype/part/__init__.py", ""),
        f(
            "demoapp/demo/doctype/part/part.py",
            "class Part:\n    pass\n",
        ),
        f(
            "demoapp/demo/doctype/part/part.json",
            if bad { PART_JSON_BAD } else { PART_JSON_GOOD },
        ),
        f("demoapp/demo/doctype/thing/__init__.py", ""),
        f(
            "demoapp/demo/doctype/thing/thing.json",
            &THING_JSON
                .replace("ROLE", if bad { "Ghost Role" } else { "Demo Role" })
                .replace("LBL", if bad { "Mystery label" } else { "Part" }),
        ),
        f(
            "demoapp/fixtures/role.json",
            "[{\"doctype\":\"Role\",\"role_name\":\"Demo Role\"}]",
        ),
        f(
            "demoapp/locale/pt_BR.po",
            &if bad {
                PO_GOOD.replace("\"Dia aberto\"", "\"Dia Aberto\"")
            } else {
                PO_GOOD.to_string()
            },
        ),
        f(
            "demoapp/demo/sidebar/demo/demo.json",
            &format!(
                "{{\"doctype\":\"Sidebar\",\"items\":[{{\"label\":\"Things\",\"link_type\":\"DocType\",\"link_to\":\"Thing\"}}{}]}}",
                if bad {
                    ",{\"label\":\"Widgets\",\"link_type\":\"Page\",\"link_to\":\"w\"}"
                } else {
                    ",{\"label\":\"Parts\",\"link_type\":\"DocType\",\"link_to\":\"Part\"}"
                }
            ),
        ),
        f("demoapp/tests/alpha.py", "def run():\n    pass\n"),
        f("AGENTS.md", "## 2. Tests\n`alpha`\n## 3. Other\nbeta\n"),
    ];
    if !bad {
        v.push(f(
            "demoapp/demo/doctype/thing/thing.py",
            "class Thing:\n    pass\n",
        ));
    } else {
        v.push(f("demoapp/patches/second.py", "def execute():\n    pass\n"));
        v.push(f("demoapp/tests/beta.py", "def run():\n    pass\n"));
    }
    v
}

pub fn fixture_config() -> FrappeConfig {
    FrappeConfig {
        app: Some("demoapp".into()),
        test_list_file: Some("AGENTS.md".into()),
        test_list_anchor: Some("## 2. Tests".into()),
        ..FrappeConfig::default()
    }
}

/// Writes a fixture under a fresh temp directory; the caller removes it.
pub fn write_fixture(tag: &str, files: &[(String, String)]) -> Option<PathBuf> {
    let root = std::env::temp_dir().join(format!("stenio-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for (p, t) in files {
        let path = root.join(p);
        fs::create_dir_all(path.parent()?).ok()?;
        fs::write(path, t).ok()?;
    }
    Some(root)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let cfg = fixture_config();
    let good = write_fixture("frappe-good", &fixture_files(false));
    let bad = write_fixture("frappe-bad", &fixture_files(true));
    let run =
        |root: &Option<PathBuf>| -> Option<Vec<Violation>> { audit(root.as_deref()?, &cfg).ok() };
    let (g, b) = (run(&good), run(&bad));
    for r in [&good, &bad].into_iter().flatten() {
        let _ = fs::remove_dir_all(r);
    }
    RULES
        .iter()
        .map(|(id, _, _)| {
            let silent = g
                .as_ref()
                .map(|v| v.iter().all(|x| x.rule_id != *id))
                .unwrap_or(false);
            let fires = b
                .as_ref()
                .map(|v| v.iter().any(|x| x.rule_id == *id))
                .unwrap_or(false);
            (id.to_string(), silent && fires)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_fires_and_is_silent() {
        assert!(
            self_test_cases().iter().all(|(_, ok)| *ok),
            "{:?}",
            self_test_cases()
        );
    }

    #[test]
    fn case_rule_reference_cases() {
        assert!(select_case_problem("Open day", "Dia Aberto").is_some());
        assert!(select_case_problem("Open Day", "Dia Aberto").is_none());
        assert!(select_case_problem("Open day", "Dia aberto").is_none());
    }
}
