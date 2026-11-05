//! Scope `frappe`: deterministic static rules over a Frappe app tree (GB-007, 2026-11-04).
//!
//! WHY IT EXISTS: releases rc68 to rc73 of the Miracena platform lost hours to bugs a program
//! finds offline in seconds (child DocTypes without a controller module, Link fields whose
//! target has no title field, tests or patches not registered, hook paths that do not exist,
//! roles nobody defines). Every rule here is static (no site, no bench) and has
//! no suppression directive. The app is described by the `[frappe]` table of `steniocheck.toml`
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
    (
        "FRAPPE-DOCTYPE-HEADER-KEYS",
        "DocType JSON Missing Header Key",
        Severity::Error,
    ),
    (
        "FRAPPE-AUTONAME-COLLISION",
        "Duplicate Guard Defeated By Autoname",
        Severity::Error,
    ),
    (
        "FRAPPE-RULES-COVERAGE",
        "DocType Outside The Validation Gate",
        Severity::Error,
    ),
    (
        "FRAPPE-ROLE-FIXTURE-PARITY",
        "Role Fixture Filter Drops A Role",
        Severity::Error,
    ),
    (
        "FRAPPE-SILENT-EXCEPT",
        "Exception Swallowed Without A Record",
        Severity::Error,
    ),
    (
        "FRAPPE-PY-MIN-SYNTAX",
        "Syntax Newer Than The Bench Python",
        Severity::Error,
    ),
    (
        "FRAPPE-PRIVILEGED-READ-IN-SAVE",
        "Permission-Sensitive Read Inside A Write Hook",
        Severity::Error,
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
    /// A read-only field is filled by the server (prepare function or patch), never by the
    /// user, so the validation gate cannot normalise it.
    read_only: bool,
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
                    read_only: flag(f, "read_only"),
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

// ── FRAPPE-DOCTYPE-HEADER-KEYS / FRAPPE-AUTONAME-COLLISION ────────────────
fn doctype_json(p: &Path) -> bool {
    p.extension().map(|e| e == "json").unwrap_or(false)
        && p.parent()
            .and_then(|d| d.parent())
            .and_then(|d| d.file_name())
            .and_then(|n| n.to_str())
            == Some("doctype")
        && p.file_stem() == p.parent().and_then(|d| d.file_name())
}

/// The keys Frappe needs to import a DocType. A JSON without `doctype` is dropped by
/// `load_doctype` and becomes invisible to every other rule, so it must fail loudly here.
fn rule_doctype_headers(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for json in c.files.iter().filter(|p| doctype_json(p)) {
        let r = rel(&c.root, json);
        let stem = json.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let text = read(json);
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                out.push(viol(
                    "FRAPPE-DOCTYPE-HEADER-KEYS",
                    &r,
                    1,
                    stem,
                    format!("DocType JSON does not parse ({e}): migrate cannot read it."),
                    "Fix the JSON syntax.",
                ));
                continue;
            }
        };
        if str_of(&v, "doctype") != "DocType" {
            let got = str_of(&v, "doctype");
            out.push(viol("FRAPPE-DOCTYPE-HEADER-KEYS", &r, 1, "\"doctype\"",
                if got.is_empty() {
                    format!("DocType JSON `{stem}` has no `doctype` key: Frappe discards it on import and the engine sees no DocType at all.")
                } else {
                    format!("DocType JSON `{stem}` has `doctype: {got}`: Frappe only imports `doctype: DocType`.")
                },
                "Add \"doctype\": \"DocType\" as the first key."));
        }
        for key in ["name", "fields"] {
            if v.get(key).is_none() {
                out.push(viol(
                    "FRAPPE-DOCTYPE-HEADER-KEYS",
                    &r,
                    1,
                    key,
                    format!("DocType JSON `{stem}` has no `{key}` key: migrate fails on import."),
                    "Export the DocType from a working site instead of writing the JSON by hand.",
                ));
            }
        }
        let name = str_of(&v, "name");
        let want = name.to_lowercase().replace([' ', '-'], "_");
        if !name.is_empty() && !stem.is_empty() && want != stem {
            out.push(viol("FRAPPE-DOCTYPE-HEADER-KEYS", &r, 1, stem,
                format!("DocType `{name}` lives in the folder `{stem}`: the folder must be the name in snake_case."),
                "Rename the folder (and its .py/__init__.py) to match the DocType name."));
        }
    }
    out
}

/// A deterministic autoname (`format:`, `field:`, `prompt:`) fills `doc.name` **before**
/// `validate`, so a duplicate guard that compares the found name with `doc.name` is always
/// false and the insert reaches the primary key. rc80 and rc81 of the Miracena app burned
/// exactly this way.
fn rule_autoname_collision(c: &Ctx) -> Vec<Violation> {
    let cmp = match Regex::new(r"!=\s*(?:doc|self)\.name\b") {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let safe = Regex::new(r"\b(?:is_new\(\)|__islocal|get_doc_before_save\()").ok();
    let mut out = Vec::new();
    let mut reported: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for json in c.files.iter().filter(|p| doctype_json(p)) {
        let v: Value = match serde_json::from_str(&read(json)) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let autoname = str_of(&v, "autoname");
        let deterministic = ["format:", "field:", "prompt:"]
            .iter()
            .any(|p| autoname.starts_with(p));
        if !deterministic {
            continue;
        }
        let stem = json.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let name = str_of(&v, "name");
        // The guard is not always in the controller: it may live in a module the controller
        // imports (Miracena keeps it in `salary.py`), so the search covers every module of the
        // package that names this DocType.
        for py in c
            .files
            .iter()
            .filter(|p| p.extension().map(|e| e == "py").unwrap_or(false) && p.starts_with(&c.pkg))
        {
            let text = read(py);
            let names_it = (!name.is_empty() && text.contains(&name)) || text.contains(stem);
            if !names_it || !text.contains("db.exists") || !cmp.is_match(&text) {
                continue;
            }
            let exempt = safe.as_ref().map(|re| re.is_match(&text)).unwrap_or(false);
            if exempt {
                continue;
            }
            let key = rel(&c.root, py);
            if !reported.insert(key.clone()) {
                break;
            }
            let line = line_of(&text, ".name");
            out.push(viol("FRAPPE-AUTONAME-COLLISION", &key, line, "!= doc.name",
                format!("`{stem}` uses autoname `{autoname}`, so doc.name is already set at validate: comparing the existing row with doc.name never matches and the duplicate reaches the primary key."),
                "Use `doc.is_new() or clash != doc.name`, or `get_doc_before_save()`."));
            break;
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
    for (name, _, _) in fixture_roles(c) {
        defined.insert(name);
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

// ── Python declaration reading (textual, ARCH-NO-PYTHON) ───────────────────
// The gate's declarations are Python data, so they are read as text: the engine never imports
// or executes the app. Only the shape it needs is extracted (the `RULES` dict and the calls
// that add entries to it), and anything it cannot read leaves the rule silent instead of
// guessing.

/// Byte range `[start, end)` of the `open`/`close` pair opening at `start`.
fn balanced_at(text: &str, start: usize, open: u8, close: u8) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    if bytes.get(start).copied() != Some(open) {
        return None;
    }
    let mut depth = 0i32;
    for (i, &c) in bytes.iter().enumerate().skip(start) {
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return Some((start, i + 1));
            }
        }
    }
    None
}

/// Splits at top-level commas, ignoring separators inside brackets or quoted strings.
fn split_top(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut quote, mut start) = (0i32, 0u8, 0usize);
    for (i, &c) in s.as_bytes().iter().enumerate() {
        match quote {
            0 if c == b'"' || c == b'\'' => quote = c,
            q if c == q => quote = 0,
            0 => match c {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b',' if depth == 0 => {
                    out.push(&s[start..i]);
                    start = i + 1;
                }
                _ => {}
            },
            _ => {}
        }
    }
    out.push(&s[start..]);
    out.retain(|p| !p.trim().is_empty());
    out
}

/// One DocType declaration of the validation gate (`_rule(...)` / `make(...)`).
struct GateEntry {
    /// `normalise` fieldname -> expression applied to it.
    normalise: Vec<(String, String)>,
    /// `raw` fieldnames: left out of the automatic `clean_text` pass.
    raw: Vec<String>,
    /// Module that declares the entry, relative to the app root.
    path: String,
    line: usize,
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches(|c| c == '"' || c == '\'')
}

/// Reads one `_rule(...)` call into its declared normalisers and raw fields.
fn gate_entry(text: &str, call_at: usize, path: &str, line: usize) -> Option<GateEntry> {
    let (start, end) = balanced_at(text, call_at, b'(', b')')?;
    let mut entry = GateEntry {
        normalise: Vec::new(),
        raw: Vec::new(),
        path: path.to_string(),
        line,
    };
    for arg in split_top(&text[start + 1..end - 1]) {
        let Some((key, value)) = arg.split_once('=') else {
            continue; // positional argument (`*args`, `**parts`): no declaration to read
        };
        let value = value.trim();
        let brackets = match value.as_bytes().first() {
            Some(b'(') => (b'(', b')'),
            Some(b'{') => (b'{', b'}'),
            _ => continue, // a bare name or literal: no declaration to read
        };
        let Some((bs, be)) = balanced_at(value, 0, brackets.0, brackets.1) else {
            continue;
        };
        let body = &value[bs + 1..be - 1];
        match key.trim() {
            "normalise" if brackets.0 == b'{' => {
                for item in split_top(body) {
                    if let Some((field, expr)) = item.split_once(':') {
                        entry
                            .normalise
                            .push((unquote(field).to_string(), expr.trim().to_string()));
                    }
                }
            }
            "raw" if brackets.0 == b'(' => {
                for item in split_top(body) {
                    let name = unquote(item);
                    if !name.is_empty() {
                        entry.raw.push(name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    Some(entry)
}

/// Every DocType the app's validation gate declares: the entries of its `RULES` dict plus the
/// entries other modules add to it (`rules["Name"] = make(...)`, which is how a second
/// declaration file joins the same gate).
fn gate_entries(c: &Ctx) -> BTreeMap<String, GateEntry> {
    let dict = match Regex::new(r#"(?m)^RULES\s*(?::[^=\n]+)?=\s*\{"#) {
        Ok(r) => r,
        Err(_) => return BTreeMap::new(),
    };
    let member = Regex::new(r#"(?m)^[ \t]*["']([^"']+)["']\s*:\s*(?:_rule|make)\s*\("#);
    let assign = Regex::new(r#"(?m)rules\[["']([^"']+)["']\]\s*=\s*(?:_rule|make)\s*\("#);
    let (Ok(member), Ok(assign)) = (member, assign) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for p in c
        .files
        .iter()
        .filter(|p| p.extension().map(|e| e == "py").unwrap_or(false))
    {
        let text = read(p);
        let path = rel(&c.root, p);
        // `RULES = { ... }`: only the entries inside the dict belong to the gate.
        if let Some(m) = dict.find(&text) {
            let body = balanced_at(&text, m.end() - 1, b'{', b'}').unwrap_or((m.end(), text.len()));
            let block = &text[body.0..body.1];
            for m in member.captures_iter(block) {
                let Some(whole) = m.get(0) else { continue };
                let line = text[..body.0 + whole.start()].lines().count();
                let call = text[..body.0 + whole.end()].rfind('(').unwrap_or(0);
                if let Some(entry) = gate_entry(&text, call, &path, line) {
                    out.insert(m[1].to_string(), entry);
                }
            }
        }
        // Entries another module of the package adds to the same dict.
        for m in assign.captures_iter(&text) {
            let Some(whole) = m.get(0) else { continue };
            let line = text[..whole.start()].lines().count();
            if let Some(entry) = gate_entry(&text, whole.end() - 1, &path, line) {
                out.insert(m[1].to_string(), entry);
            }
        }
    }
    out
}

/// A violation whose severity is not the one pinned in `RULES` (a sub-case of the same rule).
fn viol_as(
    id: &str,
    sev: Severity,
    path: &str,
    line: usize,
    snip: &str,
    msg: String,
    hint: &str,
) -> Violation {
    let mut v = viol(id, path, line, snip, msg, hint);
    v.severity = sev;
    v
}

/// True when the expression applies the money normaliser (`money`, not a look-alike name).
fn is_money(expr: &str) -> bool {
    expr.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == "money")
}

// ── FRAPPE-RULES-COVERAGE ──────────────────────────────────────────────────
/// The gate is `doc_events["*"]["validate"]` calling one `validate(doc)` that returns at once
/// for a DocType without an entry in `RULES`. A DocType outside it never passes through
/// `clean_text` or a normaliser, and nothing says so: thirteen parent DocTypes of the Miracena
/// app sat outside the gate and only a test against a real site noticed.
fn rule_rules_coverage(c: &Ctx) -> Vec<Violation> {
    let entries = gate_entries(c);
    if entries.is_empty() {
        return Vec::new(); // no gate to compare against (another app layout): stay silent
    }
    let mut out = Vec::new();
    for d in c.doctypes.iter().filter(|d| !d.is_child) {
        let Some(entry) = entries.get(&d.name) else {
            out.push(viol(
                "FRAPPE-RULES-COVERAGE",
                &d.rel,
                1,
                &d.name,
                format!(
                    "DocType `{}` has no entry in the validation gate: `validate()` returns early for it, so no field goes through clean_text or a normaliser.",
                    d.name
                ),
                "Declare it in RULES (validators.py or the module that extends it): normalise/prepare/checks, even empty.",
            ));
            continue;
        };
        let money: Vec<&str> = entry
            .normalise
            .iter()
            .filter(|(_, expr)| is_money(expr))
            .map(|(k, _)| k.as_str())
            .collect();
        for f in d
            .fields
            .iter()
            .filter(|f| f.fieldtype == "Currency" && !f.read_only)
        {
            if !money.contains(&f.fieldname.as_str()) {
                out.push(viol(
                    "FRAPPE-RULES-COVERAGE",
                    &d.rel,
                    line_of(&d.text, &format!("\"{}\"", f.fieldname)),
                    &f.fieldname,
                    format!(
                        "`{}.{}` is a Currency field but the entry of `{}` in {} declares no money normaliser for it: the raw value reaches storage.",
                        d.name, f.fieldname, d.name, entry.path
                    ),
                    "Add `\"<field>\": money` to the normalise of that entry, or mark the field read-only if the server fills it.",
                ));
            }
        }
        let fields: BTreeSet<&str> = d.fields.iter().map(|f| f.fieldname.as_str()).collect();
        for (name, _) in &entry.normalise {
            if !fields.contains(name.as_str()) {
                out.push(viol_as(
                    "FRAPPE-RULES-COVERAGE",
                    Severity::Warning,
                    &entry.path,
                    entry.line,
                    name,
                    format!(
                        "{} declares a normaliser for `{}`, which is not a field of the `{}` DocType JSON: the declaration does nothing.",
                        entry.path, name, d.name
                    ),
                    "Rename it to the real fieldname or remove it.",
                ));
            }
        }
        for name in &entry.raw {
            if !fields.contains(name.as_str()) {
                out.push(viol_as(
                    "FRAPPE-RULES-COVERAGE",
                    Severity::Warning,
                    &entry.path,
                    entry.line,
                    name,
                    format!(
                        "{} lists `{}` as raw, but it is not a field of the `{}` DocType JSON: the exemption protects nothing.",
                        entry.path, name, d.name
                    ),
                    "Rename it to the real fieldname or remove it.",
                ));
            }
        }
    }
    out
}

// ── FRAPPE-ROLE-FIXTURE-PARITY ─────────────────────────────────────────────
/// Every Role a fixture of the app defines: (role name, fixture path, line).
fn fixture_roles(c: &Ctx) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    for p in c.files.iter().filter(|p| {
        p.extension().map(|e| e == "json").unwrap_or(false)
            && p.parent()
                .and_then(|d| d.file_name())
                .and_then(|n| n.to_str())
                == Some("fixtures")
    }) {
        let text = read(p);
        let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let path = rel(&c.root, p);
        for it in items.iter().filter(|i| str_of(i, "doctype") == "Role") {
            let name = match str_of(it, "role_name") {
                n if !n.is_empty() => n,
                _ => str_of(it, "name"),
            };
            if name.is_empty() {
                continue;
            }
            let line = line_of(&text, &format!("\"{name}\""));
            out.push((name, path.clone(), line));
        }
    }
    out
}

/// The names the Role fixture filter of `hooks.py` selects, and the line of the `in` clause.
/// `None` when hooks.py has no Role fixture with a readable `["name", "in", [...]]` filter:
/// a filter the engine cannot read must not be guessed at.
fn role_fixture_filter(text: &str) -> Option<(Vec<String>, usize)> {
    let head = Regex::new(r"(?m)^fixtures\s*=\s*\[").ok()?;
    let at = head.find(text)?;
    let (bs, be) = balanced_at(text, at.end() - 1, b'[', b']')?;
    let block = text.get(bs + 1..be - 1)?;
    let dt = Regex::new(r#"["'](?:dt|doctype)["']\s*:\s*["']Role["']"#).ok()?;
    let role = dt.find(block)?;
    let rest = block.get(role.end()..)?;
    let (fs, fe) = balanced_at(rest, rest.find('[')?, b'[', b']')?;
    let filters = rest.get(fs + 1..fe - 1)?;
    let op = Regex::new(r#"["']in["']"#).ok()?;
    let in_at = op.find(filters)?;
    let after = filters.get(in_at.end()..)?;
    let (ls, le) = balanced_at(after, after.find('[')?, b'[', b']')?;
    let names: Vec<String> = split_top(after.get(ls + 1..le - 1)?)
        .iter()
        .map(|s| unquote(s).to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if names.is_empty() {
        return None;
    }
    let line = text[..bs + 1 + role.end() + fs + 1 + in_at.start()]
        .lines()
        .count();
    Some((names, line))
}

/// `bench migrate` creates a Role only when the Role fixture filter of `hooks.py` selects it.
/// A role present in `fixtures/role.json` but missing from that filter never exists on the
/// site, and every permission naming it points at nothing — the role is deployed and inert,
/// which already cost a release tag.
fn rule_role_fixture_parity(c: &Ctx) -> Vec<Violation> {
    let hooks = c.pkg.join("hooks.py");
    let text = read(&hooks);
    let Some((filter, line)) = role_fixture_filter(&text) else {
        return Vec::new();
    };
    let hr = rel(&c.root, &hooks);
    let roles = fixture_roles(c);
    if roles.is_empty() {
        return Vec::new(); // no Role fixture: nothing to keep in parity
    }
    let listed: BTreeSet<&str> = filter.iter().map(String::as_str).collect();
    let present: BTreeSet<&str> = roles.iter().map(|(n, _, _)| n.as_str()).collect();
    let mut out = Vec::new();
    for (name, path, at) in &roles {
        if !listed.contains(name.as_str()) {
            out.push(viol(
                "FRAPPE-ROLE-FIXTURE-PARITY",
                path,
                *at,
                name,
                format!(
                    "Role `{name}` is in {path} but the Role fixture filter in {hr} does not select it: bench migrate never creates it, so every permission naming `{name}` hangs on a role that does not exist."
                ),
                "Add the role to the `[\"name\", \"in\", [...]]` list of the Role filter in hooks.py, or drop it from the fixture.",
            ));
        }
    }
    for name in &filter {
        if !present.contains(name.as_str()) {
            out.push(viol_as(
                "FRAPPE-ROLE-FIXTURE-PARITY",
                Severity::Warning,
                &hr,
                line,
                name,
                format!(
                    "The Role fixture filter in {hr} selects `{name}`, but no Role fixture of the app defines it: migrate creates nothing."
                ),
                "Add the role to fixtures/role.json or remove it from the filter.",
            ));
        }
    }
    out
}

// ── FRAPPE-SILENT-EXCEPT ───────────────────────────────────────────────────
/// Handlers whose silence is an expected-exception probe, not a swallowed failure: the handler
/// exists to answer a question (does the doc exist? is the optional package installed?) and the
/// body carries the answer. Their trivial body is deliberate, so the rule stays silent.
const TOLERATED_EXCEPTS: &[&str] = &[
    "DoesNotExistError",
    "ImportError",
    "ModuleNotFoundError",
    "AttributeError",
];

/// A statement that leaves no decision behind: the handler neither records nor answers.
/// `return <value>` is a decision (`except X: return False` in an idempotency guard), so only the
/// bare forms count here.
fn py_swallow_stmt(s: &str) -> bool {
    matches!(
        s,
        "pass" | "continue" | "break" | "..." | "return" | "return None"
    )
}

/// Visual indentation of a source line (tabs count as one, as everywhere else in this module).
fn py_indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

/// False for a line inside a triple-quoted string: a docstring quoting `except: pass` is prose,
/// not a handler. Line numbering is preserved by keeping one entry per source line.
fn py_code_line(line: &str, state: &mut Option<&'static str>) -> bool {
    match *state {
        Some(q) => {
            if line.contains(q) {
                *state = None;
            }
            false
        }
        None => {
            if line.matches("\"\"\"").count() % 2 == 1 {
                *state = Some("\"\"\"");
            } else if line.matches("'''").count() % 2 == 1 {
                *state = Some("'''");
            }
            true
        }
    }
}

/// `line` without its trailing comment (quotes respected, so a `#` in a message survives).
fn py_strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, ch) in line.char_indices() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => {}
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '#' => return &line[..i],
                _ => {}
            },
        }
    }
    line
}

/// Byte index of the clause colon: the first `:` outside brackets and strings. A one-line body
/// (`except Exception: pass`) ends the header on its own line instead of eating the next statement
/// as if it were a continuation.
fn py_clause_colon(l: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for (i, ch) in l.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ':' if depth <= 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// The `except` clause opening at `start`: its exception expression (empty for a bare `except`),
/// the index of its last header line and any body written on the same line.
fn py_except_header(lines: &[&str], start: usize) -> Option<(String, usize, String)> {
    let mut header = String::new();
    let mut j = start;
    loop {
        let line = py_strip_comment(lines[j]);
        let closed = py_clause_colon(line).is_some();
        header.push_str(line.trim());
        header.push(' ');
        if closed {
            break;
        }
        j += 1;
        if j >= lines.len() {
            return None;
        }
    }
    let h = header.trim();
    let colon = py_clause_colon(h)?;
    let inline = h[colon + 1..].trim().to_string();
    let head = h[..colon].trim();
    let typ = head.strip_prefix("except").unwrap_or(head).trim();
    let typ = typ
        .trim_start_matches('*')
        .split(" as ")
        .next()
        .unwrap_or(typ)
        .trim()
        .to_string();
    Some((typ, j, inline))
}

/// True when the statement records the failure: a log, a re-raise or a thrown message. `print`
/// is volatile output, not a record, so it does not count.
fn py_registers(stmt: &str, log_re: &Regex) -> bool {
    let s = stmt.trim_start();
    if s == "raise" || s.starts_with("raise ") || s.starts_with("raise(") {
        return true;
    }
    log_re.is_match(s)
}

/// A `try` whose `except` neither records the failure nor re-raises: the automation dies and the
/// caller sees a healthy result. Static over the app's `.py` files, no site, no bench.
fn rule_silent_except(c: &Ctx) -> Vec<Violation> {
    let Ok(log_re) = Regex::new(
        r"\b(?:frappe\.(?:log_error|logger|throw)|log_error|logger\.|logging\.|log\.|traceback)",
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in c.files.iter().filter(|p| {
        p.extension().map(|e| e == "py").unwrap_or(false)
            && !rel(&c.pkg, p).split('/').any(|s| s == "tests")
            && !p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("test_") || n.ends_with("_test.py"))
                .unwrap_or(true)
    }) {
        let text = read(p);
        let lines: Vec<&str> = text.lines().collect();
        let mut state: Option<&'static str> = None;
        let code: Vec<bool> = lines.iter().map(|l| py_code_line(l, &mut state)).collect();
        let mut i = 0;
        while i < lines.len() {
            let t = py_strip_comment(lines[i]).trim();
            let is_except = code[i]
                && (t == "except"
                    || t.starts_with("except ")
                    || t.starts_with("except:")
                    || t.starts_with("except(")
                    || t.starts_with("except*"));
            if !is_except {
                i += 1;
                continue;
            }
            let start = i;
            let Some((typ, last, inline)) = py_except_header(&lines, i) else {
                i += 1;
                continue;
            };
            let base = py_indent(lines[i]);
            let mut end = last + 1;
            while end < lines.len()
                && (lines[end].trim().is_empty() || py_indent(lines[end]) > base)
            {
                end += 1;
            }
            let mut stmts: Vec<String> = Vec::new();
            if !inline.is_empty() {
                stmts.push(inline);
            }
            for l in &lines[last + 1..end] {
                let s = py_strip_comment(l).trim();
                if !s.is_empty() {
                    stmts.push(s.to_string());
                }
            }
            // Resume inside the body (not after it), so a `try` nested in the handler is scanned
            // too: an outer handler that logs can still hide a silent inner one.
            i = last + 1;
            if stmts.iter().any(|s| py_registers(s, &log_re)) {
                continue;
            }
            let swallow = stmts.is_empty() || stmts.iter().all(|s| py_swallow_stmt(s));
            let broad = typ.is_empty()
                || typ
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .any(|w| matches!(w, "Exception" | "BaseException" | "StandardError"));
            let tolerated = TOLERATED_EXCEPTS.iter().any(|t| typ.contains(t));
            let shown = if typ.is_empty() {
                "except:".to_string()
            } else {
                format!("except {typ}:")
            };
            let line = start + 1;
            if broad {
                out.push(viol_as(
                    "FRAPPE-SILENT-EXCEPT",
                    Severity::Error,
                    &rel(&c.root, p),
                    line,
                    lines[start].trim(),
                    format!(
                        "`{shown}` records nothing and does not re-raise: a failing automation looks like a healthy one (a broad handler also hides the real exception type)."
                    ),
                    "Record the failure with frappe.log_error(title=..., message=f\"{type(exc).__name__}: {exc}\") or re-raise; `print` is not a record.",
                ));
            } else if !tolerated && swallow {
                out.push(viol_as(
                    "FRAPPE-SILENT-EXCEPT",
                    Severity::Warning,
                    &rel(&c.root, p),
                    line,
                    lines[line - 1].trim(),
                    format!(
                        "`{shown}` has an empty `pass`/`return` body: the narrow type suggests an expected exception, but nothing in the handler says why it is ignored."
                    ),
                    "Return the decision explicitly (a value, not a bare `return`) or record it with frappe.log_error; keep the narrow type.",
                ));
            }
        }
    }
    out
}

// ── FRAPPE-PY-MIN-SYNTAX ───────────────────────────────────────────────────
// Why it exists: `miracena/ritual_dates.py:88` wrote `except TypeError, ValueError:` — PEP 758
// syntax that only Python 3.14 accepts. Production runs 3.14.10, so nobody noticed; a standard
// Frappe 15 bench on Python 3.12 raises SyntaxError at import and the module never loads.
//
// The engine has no embedded CPython (ARCH-NO-PYTHON), so the check is textual and deliberately
// narrow: it covers the constructs Python 3.14 introduced and earlier versions reject, NOT the
// whole grammar. A false negative is the accepted cost, and the shape must be unambiguous before
// a line is flagged; both scans run over a masked copy of the line, so prose never matches.

/// `line` with the content of its string literals and its trailing comment blanked. Quote
/// characters are kept (a scan can still see where a literal starts); only content is lost, which
/// can hide a finding but cannot invent one.
fn py_mask_code(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut comment = false;
    for ch in line.chars() {
        if comment {
            out.push(' ');
            continue;
        }
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                    out.push(' ');
                } else if ch == '\\' {
                    escaped = true;
                    out.push(' ');
                } else if ch == q {
                    quote = None;
                    out.push(ch);
                } else {
                    out.push(' ');
                }
            }
            None => match ch {
                '#' => {
                    comment = true;
                    out.push(' ');
                }
                '"' | '\'' => {
                    quote = Some(ch);
                    out.push(ch);
                }
                _ => out.push(ch),
            },
        }
    }
    out
}

/// The exception expression of the `except` header starting at `start`, masking only the header
/// lines (comments, strings and docstrings blanked), plus the index of its last header line.
/// `None` when the header never closes.
fn py_except_expr(raw: &[&str], start: usize) -> Option<(String, usize)> {
    let mut header = String::new();
    let mut j = start;
    loop {
        header.push_str(py_mask_code(raw.get(j)?).trim());
        header.push(' ');
        if py_clause_colon(&header).is_some() {
            break;
        }
        j += 1;
    }
    let colon = py_clause_colon(&header)?;
    let head = header[..colon].trim();
    let expr = head
        .strip_prefix("except")
        .unwrap_or(head)
        .trim_start_matches('*')
        .trim()
        .to_string();
    Some((expr, j))
}

/// True when `line` opens an `except` clause (bare, `except X:`, `except*` or `except(`).
fn py_starts_except(line: &str) -> bool {
    match line.trim_start().strip_prefix("except") {
        Some(rest) => {
            rest.is_empty()
                || rest.starts_with(|ch: char| matches!(ch, ' ' | '\t' | ':' | '(' | '*'))
        }
        None => false,
    }
}

/// Cheap pre-filter for a t-string prefix before the line is masked: a `t`/`r` immediately followed
/// by a quote character. Most lines fail this and are never copied.
fn py_maybe_tstring(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes
        .windows(2)
        .any(|w| matches!(w[0], b't' | b'r') && matches!(w[1], b'"' | b'\''))
}

/// True when the exception expression lists types with a bare comma (`except A, B:`, `except*`
/// included): legal in Python 3.14 by PEP 758, a SyntaxError in every earlier version, which is
/// what a Frappe 15 bench ships.
fn py_bare_tuple(expr: &str) -> bool {
    if expr.is_empty() || expr.starts_with('(') {
        return false;
    }
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for ch in expr.chars() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

/// Column of a t-string prefix (`t"`, `rt'`, `tr"`) in masked code — PEP 750, Python 3.14 only.
/// The prefix has to sit on an expression boundary (`t"` after an identifier is not this shape),
/// and the literal body is already blanked, so `"t"` and `'...t"x"...'` never match.
fn py_tstring_at(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'"' && b != b'\'' {
            continue;
        }
        let mut start = i;
        while start > 0 && matches!(bytes[start - 1], b't' | b'r') {
            start -= 1;
        }
        if start == i {
            continue;
        }
        let prefix = line.get(start..i).unwrap_or("");
        if !matches!(prefix, "t" | "rt" | "tr") {
            continue;
        }
        let boundary = start == 0 || {
            let before = bytes[start - 1];
            !(before.is_ascii_alphanumeric() || before == b'_')
        };
        if boundary {
            return Some(start);
        }
    }
    None
}

fn rule_min_syntax(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for p in c
        .files
        .iter()
        .filter(|p| p.extension().map(|e| e == "py").unwrap_or(false))
    {
        let text = read(p);
        if !text.contains("except") && !py_maybe_tstring(&text) {
            continue; // neither covered shape can be in this module
        }
        let path = rel(&c.root, p);
        let lines: Vec<&str> = text.lines().collect();
        let mut state: Option<&'static str> = None;
        for (i, line) in lines.iter().enumerate() {
            if !py_code_line(line, &mut state) {
                continue; // inside a triple-quoted string: prose, not code
            }
            if py_starts_except(line) {
                if let Some((expr, _)) = py_except_expr(&lines, i) {
                    if py_bare_tuple(&expr) {
                        out.push(viol(
                            "FRAPPE-PY-MIN-SYNTAX",
                            &path,
                            i + 1,
                            line.trim(),
                            format!(
                                "`{path}:{}` writes `except {expr}:` — PEP 758 syntax, Python 3.14 only. A Frappe 15 bench on Python 3.12 raises SyntaxError at import, so the whole module never loads (production on 3.14 hides it).",
                                i + 1
                            ),
                            "Wrap the types in parentheses: `except (A, B):` — the form every Python 3 release accepts.",
                        ));
                    }
                }
            }
            if py_maybe_tstring(line) && py_tstring_at(&py_mask_code(line)).is_some() {
                out.push(viol(
                    "FRAPPE-PY-MIN-SYNTAX",
                    &path,
                    i + 1,
                    line.trim(),
                    format!(
                        "`{path}:{}` uses a t-string (PEP 750), Python 3.14 only: a bench on Python 3.12 raises SyntaxError at import.",
                        i + 1
                    ),
                    "Use an f-string plus a tag function, or a plain string, so the module imports on the bench Python.",
                ));
            }
        }
    }
    out
}

// ── FRAPPE-PRIVILEGED-READ-IN-SAVE ────────────────────────────────────────
// Why it exists: `miracena/functions.py:62` read `frappe.get_doc("User", user)` inside
// `sync_function_roles`, which hooks.py binds to the save of a Cabal. The handler runs in the
// session of whoever saved, so a Structure Steward (no `write` on User) died with PermissionError
// on an edit the steward is allowed to make. The rule reads the hook binding and the function
// body as text (the engine never imports the app) and stays silent on any shape it cannot read:
// a computed DocType, a path outside the app, a hook written as a list.

/// Doc events that run inside a write, so the handler inherits the permissions of whoever saved.
/// `before_validate` is included because it runs in the same save phase as `validate`.
const WRITE_HOOKS: &[&str] = &[
    "validate",
    "before_validate",
    "before_save",
    "after_save",
    "on_update",
];

/// One token of the `doc_events` dict literal: only the shapes the reader needs.
enum DictTok {
    Str(String),
    Open,
    Close,
    Colon,
}

/// Strings, braces and colons of a dict literal, comments skipped (a commented entry is not a
/// binding).
fn dict_tokens(s: &str) -> Vec<DictTok> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '#' => {
                while chars.peek().map(|c| *c != '\n').unwrap_or(false) {
                    chars.next();
                }
            }
            '{' => out.push(DictTok::Open),
            '}' => out.push(DictTok::Close),
            ':' => out.push(DictTok::Colon),
            '"' | '\'' => {
                let mut buf = String::new();
                let quote = ch;
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        if let Some(n) = chars.next() {
                            buf.push(n);
                        }
                        continue;
                    }
                    if c == quote {
                        break;
                    }
                    buf.push(c);
                }
                out.push(DictTok::Str(buf));
            }
            _ => {}
        }
    }
    out
}

/// `(DocType, event, dotted path)` of every `doc_events` entry bound to a write hook. Only the
/// dict form with a literal string path is read; a list of paths or a computed value stays
/// unread (silent), which is the conservative direction.
fn write_hook_targets(c: &Ctx) -> Vec<(String, String, String)> {
    let text = read(&c.pkg.join("hooks.py"));
    let Ok(head) = Regex::new(r"(?m)^doc_events\s*=\s*\{") else {
        return Vec::new();
    };
    let Some(m) = head.find(&text) else {
        return Vec::new();
    };
    let Some((start, end)) = balanced_at(&text, m.end() - 1, b'{', b'}') else {
        return Vec::new();
    };
    let toks = dict_tokens(&text[start..end]);
    let mut out = Vec::new();
    let mut doc_type = String::new();
    let mut depth = 0usize;
    let mut i = 0;
    while i < toks.len() {
        match toks.get(i) {
            Some(DictTok::Open) => depth += 1,
            Some(DictTok::Close) => {
                depth = depth.saturating_sub(1);
                if depth <= 1 {
                    doc_type.clear();
                }
            }
            Some(DictTok::Str(key)) if depth == 1 => {
                let colon = matches!(toks.get(i + 1), Some(DictTok::Colon));
                let open = matches!(toks.get(i + 2), Some(DictTok::Open));
                if colon && open {
                    doc_type = key.clone();
                }
            }
            Some(DictTok::Str(key)) if depth == 2 => {
                let value = match (toks.get(i + 1), toks.get(i + 2)) {
                    (Some(DictTok::Colon), Some(DictTok::Str(path))) => Some(path),
                    _ => None,
                };
                if let Some(path) = value {
                    if WRITE_HOOKS.contains(&key.as_str()) && !doc_type.is_empty() {
                        out.push((doc_type.clone(), key.clone(), path.clone()));
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// The module file and function name of an app-local dotted hook path (`miracena.api.on_todo`).
fn dotted_target(c: &Ctx, dotted: &str) -> Option<(PathBuf, String)> {
    let parts: Vec<&str> = dotted.split('.').collect();
    if parts.first().copied() != Some(c.app.as_str()) || parts.len() < 2 {
        return None;
    }
    for i in (1..parts.len()).rev() {
        let base = parts[..i].iter().fold(c.root.clone(), |p, s| p.join(s));
        let file = if base.with_extension("py").is_file() {
            base.with_extension("py")
        } else if base.join("__init__.py").is_file() {
            base.join("__init__.py")
        } else {
            continue;
        };
        return Some((file, parts[i].to_string()));
    }
    None
}

/// True when `line` is the `def` of `name` (`def name(` or `async def name(`), without a regex
/// compile on every hook target — the audit runs this per binding.
fn py_def_line(line: &str, name: &str) -> bool {
    let t = line.trim_start();
    let rest = t.strip_prefix("async ").unwrap_or(t);
    let Some(rest) = rest.strip_prefix("def ") else {
        return false;
    };
    let Some(after) = rest.strip_prefix(name) else {
        return false;
    };
    after.starts_with('(') || after.starts_with([' ', '\t'])
}

/// Name of the `def` a line declares, if any.
fn py_def_name(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let rest = t.strip_prefix("async ").unwrap_or(t);
    let rest = rest.strip_prefix("def ")?;
    let end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    (end > 0 && rest[end..].trim_start().starts_with('(')).then(|| &rest[..end])
}

/// `(index of the def line, body text)` of the first `def name(...)` of a module.
fn py_function(lines: &[&str], name: &str) -> Option<(usize, String)> {
    let idx = lines.iter().position(|l| py_def_line(l, name))?;
    let base = py_indent(lines[idx]);
    let mut end = idx + 1;
    while end < lines.len() && (lines[end].trim().is_empty() || py_indent(lines[end]) > base) {
        end += 1;
    }
    Some((idx, lines[idx + 1..end.min(lines.len())].join("\n")))
}

/// Names a body opens a `with <name>(...)` on (context managers, one level deep).
fn py_with_contexts(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let code = py_strip_comment(line);
        let t = code.trim_start();
        let Some(rest) = t.strip_prefix("with ") else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        if rest[name.len()..].trim_start().starts_with('(') {
            out.push(name);
        }
    }
    out
}

/// True when the function body establishes a system context: `ignore_permissions` (on the call
/// or on the flags), `frappe.set_user("Administrator")`, or a `with <helper>(...)` whose body does
/// one of those. One hop into the helper, defined in the same module.
fn py_system_context(lines: &[&str], body: &str, depth: u8) -> bool {
    if body.contains("ignore_permissions") {
        return true;
    }
    for line in body.lines() {
        let code = py_strip_comment(line);
        if let Some(at) = code.find("set_user(") {
            if code[at..].contains("Administrator") {
                return true;
            }
        }
    }
    if depth >= 1 {
        return false;
    }
    for name in py_with_contexts(body) {
        let Some((_, helper)) = py_function(lines, &name) else {
            continue;
        };
        if py_system_context(lines, &helper, depth + 1) {
            return true;
        }
    }
    false
}

/// Every `frappe.get_doc("Literal", ...)` of a body that does not pass `ignore_permissions`:
/// `(offset, DocType)`. A computed first argument (a dict literal, a variable) is not read.
fn py_get_doc_reads(body: &str) -> Vec<(usize, String)> {
    let Ok(re) = Regex::new(r#"frappe\.get_doc\(\s*["']([^"']+)["']"#) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for cap in re.captures_iter(body) {
        let (Some(whole), Some(dt)) = (cap.get(0), cap.get(1)) else {
            continue;
        };
        let Some(open) = body[..whole.end()].rfind('(') else {
            continue;
        };
        let Some((_, end)) = balanced_at(body, open, b'(', b')') else {
            continue;
        };
        if body[open..end].contains("ignore_permissions") {
            continue;
        }
        out.push((whole.start(), dt.as_str().to_string()));
    }
    out
}

/// The module file of a `from ... import`: app-absolute (`miracena.x`) or one leading dot (same
/// package as `current`). Anything else is outside the app and not followed.
fn app_module(c: &Ctx, current: &Path, module: &str) -> Option<PathBuf> {
    let base = if let Some(rest) = module.strip_prefix('.') {
        if rest.is_empty() || rest.starts_with('.') {
            return None;
        }
        current.parent()?.join(rest.replace('.', "/"))
    } else if module.split('.').next() == Some(c.app.as_str()) {
        module.split('.').fold(c.root.clone(), |p, s| p.join(s))
    } else {
        return None;
    };
    if base.with_extension("py").is_file() {
        Some(base.with_extension("py"))
    } else if base.join("__init__.py").is_file() {
        Some(base.join("__init__.py"))
    } else {
        None
    }
}

/// Walks the functions a write hook reaches (the handler itself plus one import/same-module hop)
/// and reports each permission-sensitive `frappe.get_doc("<DocType>", ...)`.
struct ReadScan<'a> {
    c: &'a Ctx,
    out: Vec<Violation>,
    seen: BTreeSet<(String, usize)>,
}

impl ReadScan<'_> {
    fn run(&mut self, path: &Path, name: &str, hook: &str, hop: bool, inherited: bool) {
        let text = read(path);
        let lines: Vec<&str> = text.lines().collect();
        let Some((def, body)) = py_function(&lines, name) else {
            return;
        };
        // A callee runs inside the `with` block of its caller, so an open system context is
        // inherited: a false negative here is cheaper than flagging `desired_roles` because
        // `sync_function_roles` opened the context one frame up.
        let system = inherited || py_system_context(&lines, &body, 0);
        let rel_path = rel(&self.c.root, path);
        for (offset, target) in py_get_doc_reads(&body) {
            let line = def + 2 + body[..offset].matches('\n').count();
            if system || !self.seen.insert((rel_path.clone(), line)) {
                continue;
            }
            let snippet = lines.get(line - 1).map(|l| l.trim()).unwrap_or("");
            self.out.push(viol(
                "FRAPPE-PRIVILEGED-READ-IN-SAVE",
                &rel_path,
                line,
                snippet,
                format!(
                    "`frappe.get_doc(\"{target}\", ...)` in `{name}` runs from the write hook `{hook}`, so the read and any save of that document carry the permissions of whoever saved: a user without `write` on {target} gets PermissionError on an edit they are allowed to make (GB-074)."
                ),
                &format!(
                    "Read only the value you need with `frappe.db.get_value(\"{target}\", name, field)` (no permission check, no save), or open an explicit system context (`frappe.set_user(\"Administrator\")` wrapped in try/finally) before the read."
                ),
            ));
        }
        if !hop {
            return;
        }
        for (callee_path, callee) in self.callees(path, &text, &body, name) {
            self.run(&callee_path, &callee, hook, false, system);
        }
    }

    /// Functions the body calls that the app defines: top-level defs of the same module and names
    /// the module imports from another module of the app. One hop only.
    fn callees(
        &self,
        path: &Path,
        text: &str,
        body: &str,
        self_name: &str,
    ) -> Vec<(PathBuf, String)> {
        let mut out = Vec::new();
        for line in text.lines() {
            let code = py_strip_comment(line);
            if let Some(name) = py_def_name(code) {
                if name != self_name && body.contains(&format!("{name}(")) {
                    out.push((path.to_path_buf(), name.to_string()));
                }
                continue;
            }
            let t = code.trim_start();
            let Some(rest) = t.strip_prefix("from ") else {
                continue;
            };
            let Some((module, names)) = rest.split_once(" import ") else {
                continue;
            };
            let Some(file) = app_module(self.c, path, module.trim()) else {
                continue;
            };
            for part in names.split(',') {
                let name = part.trim().split(" as ").next().unwrap_or("").trim();
                if !name.is_empty() && body.contains(&format!("{name}(")) {
                    out.push((file.clone(), name.to_string()));
                }
            }
        }
        out
    }
}

fn rule_privileged_read(c: &Ctx) -> Vec<Violation> {
    let mut scan = ReadScan {
        c,
        out: Vec::new(),
        seen: BTreeSet::new(),
    };
    for (doc_type, event, dotted) in write_hook_targets(c) {
        let Some((file, name)) = dotted_target(c, &dotted) else {
            continue;
        };
        scan.run(&file, &name, &format!("{doc_type}.{event}"), true, false);
    }
    scan.out
}

/// Runs every rule and returns the violations (sorted by file and line).
pub fn audit(root: &Path, cfg: &FrappeConfig) -> Result<Vec<Violation>, String> {
    let c = build_ctx(root, cfg)?;
    let mut all: Vec<Violation> = Vec::new();
    for f in [
        rule_doctype_headers,
        rule_controller,
        rule_autoname_collision,
        rule_link_title,
        rule_patches,
        rule_hooks,
        rule_tests,
        rule_sidebar,
        rule_roles,
        rule_select_case,
        rule_labels,
        rule_whitelist,
        rule_rules_coverage,
        rule_role_fixture_parity,
        rule_silent_except,
        rule_min_syntax,
        rule_privileged_read,
    ] {
        all.extend(f(&c));
    }
    all.sort_by(|a, b| {
        (&a.rule_id, &a.file_path, a.line_number).cmp(&(&b.rule_id, &b.file_path, b.line_number))
    });
    Ok(all)
}

// ── self-test fixtures ─────────────────────────────────────────────────────
const THING_JSON: &str = r#"{"doctype":"DocType","name":"Thing","fields":[{"fieldname":"part","fieldtype":"Link","options":"Part","label":"LBL"},{"fieldname":"state","fieldtype":"Select","options":"Open day\nClosed day"},{"fieldname":"code","fieldtype":"Data"},{"fieldname":"price","fieldtype":"Currency"}],"permissions":[{"role":"ROLE"}]}"#;
const PART_JSON_GOOD: &str = r#"{"doctype":"DocType","name":"Part","title_field":"label","show_title_field_in_link":1,"fields":[]}"#;
const PART_JSON_BAD: &str = r#"{"doctype":"DocType","name":"Part","fields":[]}"#;
const WIDGET_JSON: &str =
    r#"{"doctype":"DocType","name":"Widget","fields":[],"permissions":[{"role":"Demo Role"}]}"#;
/// The validation gate: `Thing` stores `price` as Currency, so the entry must normalise it.
const VALIDATORS_GOOD: &str = "import frappe\n\n\ndef money(value):\n\treturn value\n\n\ndef _rule(**parts):\n\treturn {\"normalise\": {}, \"prepare\": (), \"checks\": (), \"raw\": ()} | parts\n\n\nRULES = {\n\t\"Part\": _rule(),\n\t\"Thing\": _rule(normalise={\"price\": money}, raw=(\"code\",)),\n}\n";
const VALIDATORS_BAD: &str = "import frappe\n\n\ndef money(value):\n\treturn value\n\n\ndef _rule(**parts):\n\treturn {\"normalise\": {}, \"prepare\": (), \"checks\": (), \"raw\": ()} | parts\n\n\nRULES = {\n\t\"Part\": _rule(),\n\t\"Thing\": _rule(normalise={\"ghost_field\": money}, raw=(\"code\",)),\n}\n";
/// A second declaration file joining the same gate (`rules["Widget"] = make()`).
const MORE_RULES_GOOD: &str = "def extend(rules, make):\n\trules[\"Widget\"] = make()\n";
const MORE_RULES_BAD: &str = "def extend(rules, make):\n\tpass\n";
/// FRAPPE-SILENT-EXCEPT: the good file records, re-raises, or answers with a decision; the bad
/// file swallows a broad exception with `pass` and with a counter, the shape that hid four broken
/// automations.
const SAFETY_GOOD: &str = "import frappe\n\n\ndef sync(doc):\n\ttry:\n\t\tdoc.insert()\n\texcept Exception as exc:\n\t\tfrappe.log_error(title=\"demo sync\", message=f\"{type(exc).__name__}: {exc}\")\n\t\traise\n\n\ndef optional():\n\ttry:\n\t\timport phonenumbers\n\texcept ImportError:\n\t\tphonenumbers = None\n\treturn phonenumbers\n\n\ndef number(value):\n\ttry:\n\t\treturn int(value)\n\texcept ValueError:\n\t\treturn 0\n";
const SAFETY_BAD: &str = "import frappe\n\n\ndef sync(doc):\n\tskipped = 0\n\ttry:\n\t\tdoc.insert()\n\texcept Exception:\n\t\tpass\n\treturn skipped\n\n\ndef number(value):\n\tskipped = 0\n\ttry:\n\t\treturn int(value)\n\texcept Exception:\n\t\tskipped += 1\n\t\treturn None\n";
/// FRAPPE-PY-MIN-SYNTAX (PEP 758) and FRAPPE-PRIVILEGED-READ-IN-SAVE, in one module bound to the
/// `validate` write hook of hooks.py. The good file keeps the parenthesised tuple and opens an
/// explicit system context before reading the User; the bad file writes the 3.14-only clause and
/// reads the User in the session of whoever saved.
const SESSION_GOOD: &str = "import frappe\n\n\ndef sync_members(doc=None, method=None):\n\tprevious = frappe.session.user\n\tfrappe.set_user(\"Administrator\")\n\ttry:\n\t\tuser = frappe.get_doc(\"User\", \"Administrator\")\n\t\tuser.add_roles(\"Demo Role\")\n\tfinally:\n\t\tfrappe.set_user(previous)\n\n\ndef parse(text):\n\ttry:\n\t\treturn int(text)\n\texcept (TypeError, ValueError):\n\t\treturn 0\n";
const SESSION_BAD: &str = "import frappe\n\n\ndef sync_members(doc=None, method=None):\n\tuser = frappe.get_doc(\"User\", doc.user)\n\tuser.add_roles(\"Demo Role\")\n\n\ndef parse(text):\n\ttry:\n\t\treturn int(text)\n\texcept TypeError, ValueError:\n\t\treturn 0\n";
const PO_GOOD: &str = "msgid \"\"\nmsgstr \"\"\n\nmsgid \"Things\"\nmsgstr \"Coisas\"\n\nmsgid \"Parts\"\nmsgstr \"Pecas\"\n\nmsgid \"Part\"\nmsgstr \"Peca\"\n\nmsgid \"Open day\"\nmsgstr \"Dia aberto\"\n\nmsgid \"Closed day\"\nmsgstr \"Dia fechado\"\n\nmsgid \"Widget\"\nmsgstr \"Widget\"\n";

/// The files of a tiny demo app; `bad` plants one violation of every rule.
pub fn fixture_files(bad: bool) -> Vec<(String, String)> {
    let f = |p: &str, t: &str| (p.to_string(), t.to_string());
    let mut v = vec![
        f("demoapp/__init__.py", "__version__ = \"0.1.0\"\n"),
        f("demoapp/modules.txt", "Demo\n"),
        f(
            "demoapp/hooks.py",
            &format!(
                "app_name = \"demoapp\"\ndoc_events = {{\"ToDo\": {{\"on_update\": \"demoapp.api.{}\", \"validate\": \"demoapp.session.sync_members\"}}}}  # \"demoapp.api.commented\"\nfixtures = [\n\t{{\"dt\": \"Role\", \"filters\": [[\"name\", \"in\", {}]]}},\n]\n",
                if bad { "missing_fn" } else { "on_todo" },
                if bad {
                    "[\"Demo Role\", \"Phantom Role\"]"
                } else {
                    "[\"Demo Role\"]"
                }
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
            if bad {
                "[{\"doctype\":\"Role\",\"role_name\":\"Demo Role\"},{\"doctype\":\"Role\",\"role_name\":\"Extra Role\"}]"
            } else {
                "[{\"doctype\":\"Role\",\"role_name\":\"Demo Role\"}]"
            },
        ),
        f(
            "demoapp/validators.py",
            if bad { VALIDATORS_BAD } else { VALIDATORS_GOOD },
        ),
        f(
            "demoapp/more_rules.py",
            if bad { MORE_RULES_BAD } else { MORE_RULES_GOOD },
        ),
        f(
            "demoapp/safety.py",
            if bad { SAFETY_BAD } else { SAFETY_GOOD },
        ),
        f(
            "demoapp/session.py",
            if bad { SESSION_BAD } else { SESSION_GOOD },
        ),
        f("demoapp/demo/doctype/widget/__init__.py", ""),
        f("demoapp/demo/doctype/widget/widget.json", WIDGET_JSON),
        f(
            "demoapp/demo/doctype/widget/widget.py",
            "class Widget:\n    pass\n",
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
                "{{\"doctype\":\"Sidebar\",\"items\":[{{\"label\":\"Things\",\"link_type\":\"DocType\",\"link_to\":\"Thing\"}}{},{{\"label\":\"Widget\",\"link_type\":\"DocType\",\"link_to\":\"Widget\"}}]}}",
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
        // FRAPPE-AUTONAME-COLLISION: deterministic autoname plus a guard that compares the
        // found row with doc.name, which is already filled at validate.
        v.push(f("demoapp/demo/doctype/slot/__init__.py", ""));
        v.push(f(
            "demoapp/demo/doctype/slot/slot.json",
            "{\"doctype\":\"DocType\",\"name\":\"Slot\",\"autoname\":\"format:SLOT-{code}\",\"fields\":[{\"fieldname\":\"code\",\"fieldtype\":\"Data\"}],\"permissions\":[{\"role\":\"Demo Role\"}]}",
        ));
        v.push(f(
            "demoapp/demo/doctype/slot/slot.py",
            "import frappe\n\n\nclass Slot:\n    def validate(self):\n        clash = frappe.db.exists(\"Slot\", {\"code\": self.code})\n        if clash and clash != self.name:\n            frappe.throw(\"duplicate\")\n",
        ));
        // FRAPPE-DOCTYPE-HEADER-KEYS: no `doctype` key, invisible to every other rule.
        v.push(f("demoapp/demo/doctype/nohead/__init__.py", ""));
        v.push(f(
            "demoapp/demo/doctype/nohead/nohead.json",
            "{\"name\":\"Nohead\",\"fields\":[],\"permissions\":[]}",
        ));
        v.push(f(
            "demoapp/demo/doctype/nohead/nohead.py",
            "class Nohead:\n    pass\n",
        ));
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
