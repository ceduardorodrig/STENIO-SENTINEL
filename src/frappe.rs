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

use crate::config::{FetchParity, FrappeConfig};
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
        "FRAPPE-FETCH-PARITY",
        "Child Field Without Its Declared fetch_from",
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
    (
        "FRAPPE-I18N-SOURCE-LITERALS",
        "Translatable Source Literal Missing From Catalogue",
        Severity::Error,
    ),
    (
        "FRAPPE-OTHER-OPTION-NEEDS-TEXT",
        "Select Other Without A Companion Field",
        Severity::Error,
    ),
    (
        "VIZ-PANEL-SCHEMA",
        "Dashboard Panel Type Against The Field It Measures",
        Severity::Error,
    ),
    (
        "NO-KANBAN-BOARD-FIXTURE",
        "Desk-Owned Document Declared As A Fixture",
        Severity::Error,
    ),
    (
        "DOCTYPE-CALENDAR-GANTT-NEEDS-DATES",
        "Calendar/Gantt View Without Its Dates",
        Severity::Error,
    ),
    (
        "FRAPPE-KANBAN-BOARD-DERIVED",
        "Kanban Board Not Derived From The App",
        Severity::Error,
    ),
    (
        "FRAPPE-TEST-PARITY",
        "Declared Pure Test Missing From The Release Battery",
        Severity::Error,
    ),
    (
        "FRAPPE-CURRENCY-THRESHOLD-UNSET",
        "Currency Threshold Decided Without An Empty Branch",
        Severity::Error,
    ),
    (
        "FRAPPE-PERMISSION-SCOPE",
        "Broad Role On A Person-Scoped DocType Without A Scope",
        Severity::Error,
    ),
    (
        "FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE",
        "Published Content Left Behind In The Patch Ledger",
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
    /// Visible names: a companion field can point at a Select through either of them.
    label: String,
    description: String,
    /// `depends_on` expression: the only structural link between two fields.
    depends_on: String,
    /// `fetch_from` as written in the JSON (`link_field.source_field`), empty when absent.
    fetch_from: String,
    fetch_if_empty: bool,
}

struct DocType {
    name: String,
    rel: String,
    text: String,
    is_child: bool,
    /// A Single holds one configuration record, not rows about people: it has no table to scope.
    is_single: bool,
    title_ok: bool,
    fields: Vec<Field>,
    roles: Vec<String>,
    /// The same rows as `roles`, kept whole: `FRAPPE-PERMISSION-SCOPE` needs which operations a
    /// role was granted, not only that it appears.
    perms: Vec<Perm>,
}

/// One row of a DocType's `permissions` array.
struct Perm {
    role: String,
    read: bool,
    write: bool,
    /// Set on the row itself: it narrows the rows that role may touch to the ones it owns.
    if_owner: bool,
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
                    label: str_of(f, "label"),
                    description: str_of(f, "description"),
                    depends_on: str_of(f, "depends_on"),
                    fetch_from: str_of(f, "fetch_from"),
                    fetch_if_empty: flag(f, "fetch_if_empty"),
                })
                .collect()
        })
        .unwrap_or_default();
    let perms: Vec<Perm> = v
        .get("permissions")
        .and_then(|f| f.as_array())
        .map(|a| {
            a.iter()
                .map(|p| Perm {
                    role: str_of(p, "role"),
                    read: flag(p, "read"),
                    write: flag(p, "write"),
                    if_owner: flag(p, "if_owner"),
                })
                .filter(|p| !p.role.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let roles = perms.iter().map(|p| p.role.clone()).collect();
    let title_ok = (!str_of(&v, "title_field").is_empty() && flag(&v, "show_title_field_in_link"))
        || !str_of(&v, "search_fields").trim().is_empty();
    Some(DocType {
        name: str_of(&v, "name"),
        rel: rel(root, path),
        is_child: flag(&v, "istable"),
        is_single: flag(&v, "issingle"),
        title_ok,
        fields,
        roles,
        perms,
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

// ── FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE (GB-142) ────────────────────
// A patch that publishes a file shipped in the image into a record is the one shape Frappe's
// patch ledger gets wrong: `patches.txt` records what already ran, so the release that carries a
// new `docs/manual.html` never writes it again — the site keeps serving the previous edition.
const PUBLISHED_FIELDS: &[&str] = &[
    "content",
    "body",
    "html",
    "markup",
    "page_content",
    "page_html",
    "rich_text",
    "long_description",
];

/// The verbs a patch uses to write a record. A patch that reads a file and writes rows through
/// one of these is a publisher; one that only compares or logs is not.
const WRITE_VERBS: &[&str] = &[
    ".insert(",
    ".save(",
    ".set_value(",
    ".set_single_value(",
    ".db_set(",
    ".db_insert(",
];

/// The ways a module reads a file that ships inside the app package.
const FILE_READS: &[&str] = &[
    "read_text(",
    "read_bytes(",
    "pkgutil.get_data",
    "importlib.resources",
    "open(",
];

/// A byte slice of `text` around `at`, widened to char boundaries so UTF-8 can be cut safely.
fn window(text: &str, at: usize, back: usize, fwd: usize) -> &str {
    let mut lo = at.saturating_sub(back);
    while lo > 0 && !text.is_char_boundary(lo) {
        lo -= 1;
    }
    let mut hi = (at + fwd).min(text.len());
    while hi < text.len() && !text.is_char_boundary(hi) {
        hi += 1;
    }
    &text[lo..hi]
}

/// Every write into a record that names a long-text field nearby: `(offset of the verb, field)`.
/// `set_single_value("Handbook", "content", body)` and the dict-shaped
/// `get_doc({"doctype": ..., "content": body}).insert()` are both read from the same window.
fn published_writes(text: &str) -> Vec<(usize, String)> {
    let Ok(field_re) = Regex::new(r#"["']([a-z_]+)["']"#) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for verb in WRITE_VERBS {
        for (at, _) in text.match_indices(verb) {
            let near = window(text, at, 200, 320);
            if let Some(m) = field_re
                .captures_iter(near)
                .find(|m| PUBLISHED_FIELDS.contains(&m[1].to_string().as_str()))
            {
                out.push((at, m[1].to_string()));
            }
        }
    }
    out.sort_by_key(|(at, _)| *at);
    out
}

/// The first file the module names with a document extension, for the finding.
fn published_file(text: &str) -> Option<String> {
    let re = Regex::new(r#"["']([\w./-]+\.(?:html|htm|md|markdown|txt|rst))["']"#).ok()?;
    re.captures(text).map(|m| m[1].to_string())
}

/// The DocTypes a module writes by name — the dict literal and the direct call forms.
fn written_doctypes(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for pat in [
        r#""doctype"\s*:\s*"([^"]+)""#,
        r#"(?:get_doc|new_doc|set_single_value|set_value|db\.set_value)\(\s*["']([A-Z][^"']*)["']"#,
    ] {
        let Ok(re) = Regex::new(pat) else { continue };
        for m in re.captures_iter(text) {
            let name = m[1].to_string();
            if name != "DocType" && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out.truncate(4);
    out
}

/// The dotted paths `hooks.py` registers under `after_migrate`, in any layout: one line, a
/// bracketed list over several lines, or an augmented assignment. A commented block registers
/// nothing, exactly as Frappe sees it.
fn after_migrate_paths(hooks: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r#"["']([A-Za-z_][A-Za-z0-9_.]*)["']"#) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut collecting = false;
    for raw in hooks.lines() {
        let code = strip_comment(raw);
        if !collecting {
            let Some(rest) = code.trim_start().strip_prefix("after_migrate") else {
                continue;
            };
            let rest = rest.trim_start();
            if !(rest.starts_with('=') || rest.starts_with("+=")) {
                continue;
            }
            collecting = true;
        }
        out.extend(re.captures_iter(&code).map(|m| m[1].to_string()));
        depth += code.matches(['[', '(']).count() as i32 - code.matches([']', ')']).count() as i32;
        if depth <= 0 {
            break;
        }
    }
    out
}

fn rule_published_content(c: &Ctx) -> Vec<Violation> {
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
    if listed.is_empty() {
        return Vec::new();
    }
    let registered = after_migrate_paths(&read(&c.pkg.join("hooks.py")));
    let prefix = format!("{}.patches.", c.app);
    let mut out = Vec::new();
    for (name, list_line) in &listed {
        // Only the module a patch line names, never a dotted function inside it.
        let Some(stem) = name.strip_prefix(&prefix).filter(|s| !s.contains('.')) else {
            continue;
        };
        let path = c.pkg.join("patches").join(format!("{stem}.py"));
        if !path.is_file() {
            continue;
        }
        let src = read(&path);
        if !FILE_READS.iter().any(|m| src.contains(m)) {
            continue; // reads no file of the image: nothing to republish
        }
        let Some((at, field)) = published_writes(&src).into_iter().next() else {
            continue; // writes no long-text record: a data patch, not a publisher
        };
        let owner = format!("{prefix}{stem}");
        if registered
            .iter()
            .any(|r| r == &owner || r.starts_with(&format!("{owner}.")))
        {
            continue; // republished by every migrate: the image is the source of truth
        }
        let doctypes = written_doctypes(&src);
        let target = if doctypes.is_empty() {
            format!("the long-text field `{field}` of a record it writes")
        } else {
            format!(
                "`{field}` on {}",
                doctypes
                    .iter()
                    .map(|d| format!("`{d}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let file = published_file(&src).unwrap_or_else(|| "a file shipped in the image".into());
        let at_line = src[..at].matches('\n').count() + 1;
        out.push(viol(
            "FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE",
            &rel(&c.root, &path),
            at_line,
            &format!("{stem}: {target}"),
            format!(
                "Patch `{stem}` publishes `{file}` into {target} but is registered only in `{lr}`:{list_line}: Frappe runs a patch once, so the second edition of the document never reaches the site."
            ),
            &format!(
                "Register `{owner}` (or `{owner}.execute`) in `after_migrate` of hooks.py, behind the content hash guard, so every image republishes its documents."
            ),
        ));
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
/// Parse one catalogue into `msgid -> msgstr`; obsolete and header entries are dropped.
fn load_catalogue(path: &Path) -> Option<BTreeMap<String, String>> {
    let text = fs::read_to_string(path).ok()?;
    Some(
        i18n::parse_po(&text)
            .into_iter()
            .filter(|e| !e.obsolete && !e.msgid.is_empty())
            .map(|e| (e.msgid, e.strs.first().cloned().unwrap_or_default()))
            .collect(),
    )
}

fn catalogue(c: &Ctx) -> Option<(String, BTreeMap<String, String>)> {
    let rel_loc = c
        .cfg
        .locale_file
        .clone()
        .unwrap_or_else(|| "locale/pt_BR.po".into());
    let path = c.pkg.join(&rel_loc);
    Some((rel(&c.root, &path), load_catalogue(&path)?))
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
/// Append the translatable strings of a JSON document to `out`. The accumulator is any
/// `Extend<String>` so the signature takes no `&mut Vec` (RUST-IDIOMATIC-SLICES): a slice cannot
/// grow, and an append-only out-parameter has no slice form.
fn collect_translatable(v: &Value, doctype_file: bool, out: &mut impl Extend<String>) {
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
                    ("label" | "chart_name", Value::String(t)) => {
                        out.extend(std::iter::once(t.trim().to_string()))
                    }
                    ("description", Value::String(t)) if doctype_file => {
                        out.extend(std::iter::once(t.trim().to_string()))
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

// ── FRAPPE-FETCH-PARITY ────────────────────────────────────────────────────
/// GB-241 (bug F-01): a child row that names a person must copy the person's role itself.
/// `[[frappe.fetch_parity]]` says which child DocTypes (`doctype_pattern`, `*` wildcard over the
/// snake_case name) must declare `field` with the expected `fetch_from` and `fetch_if_empty: 1`.
/// Without a table the rule is silent: the engine hardcodes no app.
fn rule_fetch_parity(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    let Some(entries) = c.cfg.fetch_parity.as_ref() else {
        return out;
    };
    for e in entries {
        let need_empty = e.fetch_if_empty.unwrap_or(true);
        for d in c.doctypes.iter().filter(|d| d.is_child) {
            let snake = d.name.to_lowercase().replace(' ', "_");
            if !crate::reconcile::glob_match(&e.doctype_pattern, &snake) {
                continue;
            }
            let problem = match d.fields.iter().find(|f| f.fieldname == e.field) {
                None => Some(format!("declares no `{}` field", e.field)),
                Some(f) if f.fetch_from != e.fetch_from => Some(format!(
                    "`{}` has fetch_from `{}`, expected `{}`",
                    e.field, f.fetch_from, e.fetch_from
                )),
                Some(f) if need_empty && !f.fetch_if_empty => Some(format!(
                    "`{}` has fetch_from but not `fetch_if_empty: 1`: a value typed or imported first is overwritten, an empty one never filled",
                    e.field
                )),
                Some(_) => None,
            };
            if let Some(p) = problem {
                out.push(viol(
                    "FRAPPE-FETCH-PARITY",
                    &d.rel,
                    line_of(&d.text, &format!("\"{}\"", e.field)),
                    &e.field,
                    format!(
                        "Child DocType `{}` {}: [frappe] fetch_parity requires `{}` fetched from `{}`.",
                        d.name, p, e.field, e.fetch_from
                    ),
                    "Add `\"fetch_from\": \"<link>.<field>\"` and `\"fetch_if_empty\": 1` to the field, or correct the [[frappe.fetch_parity]] entry.",
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

// ── FRAPPE-I18N-SOURCE-LITERALS (GB-082) ───────────────────────────────────
/// Undo the escapes of a Python string literal so it compares with the unescaped `msgid`.
fn py_unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// A literal `_()` can translate: it carries words and is not a template fragment.
fn translatable_literal(s: &str) -> bool {
    s.chars().any(|c| c.is_alphabetic()) && !s.contains("{{")
}

/// Every string literal passed to `_(` in one Python file, as (1-based line, literal).
///
/// The read is textual — the engine never imports the app (ARCH-NO-PYTHON) — so it follows the
/// one shape a gettext call has: `_` at a word boundary in *code* (never inside a string, a
/// docstring or a comment), `(`, then a string literal, possibly on the next line because the
/// call is wrapped. Escapes are undone the way the catalogue undoes its `msgid`; a triple-quoted
/// literal is read whole; an implicit concatenation (`_("a" "b")`) is skipped because the joined
/// string, not the piece, is the key. A wrapped call whose first argument is a variable is not a
/// literal and is skipped, not guessed.
fn translation_literals(text: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = text.chars().collect();
    let mut line_at: Vec<usize> = Vec::with_capacity(chars.len());
    let mut ln = 1usize;
    for ch in &chars {
        line_at.push(ln);
        if *ch == '\n' {
            ln += 1;
        }
    }
    let line_of_index = |k: usize| line_at[k.min(line_at.len().saturating_sub(1))];
    let mut out = Vec::new();
    let mut i = 0usize;
    // `Some((quote, triple))` while inside any string literal, so `_` in prose never matches.
    let mut inside: Option<(char, bool)> = None;
    while i < chars.len() {
        let ch = chars[i];
        if let Some((q, triple)) = inside {
            if ch == '\\' {
                i += 2;
                continue;
            }
            let closes = ch == q
                && (!triple || (chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q)));
            if closes {
                i += if triple { 3 } else { 1 };
                inside = None;
                continue;
            }
            i += 1;
            continue;
        }
        match ch {
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            '"' | '\'' => {
                let triple = chars.get(i + 1) == Some(&ch) && chars.get(i + 2) == Some(&ch);
                i += if triple { 3 } else { 1 };
                inside = Some((ch, triple));
                continue;
            }
            '_' if (i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_'))
                && chars.get(i + 1) == Some(&'(') =>
            {
                i += 2;
            }
            _ => {
                i += 1;
                continue;
            }
        }
        // `_` followed by `(`: the argument must be a literal, or there is nothing to compare.
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        let Some(&q) = chars.get(i) else { break };
        if q != '"' && q != '\'' {
            continue;
        }
        let triple = chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q);
        i += if triple { 3 } else { 1 };
        let start = i;
        let mut raw = String::new();
        let mut closed = false;
        while i < chars.len() {
            let ch = chars[i];
            if ch == '\\' {
                match chars.get(i + 1) {
                    Some(&next) => {
                        raw.push(ch);
                        raw.push(next);
                        i += 2;
                    }
                    None => break,
                }
                continue;
            }
            if !triple && ch == '\n' {
                break; // an unterminated single-quoted literal: not a call we can read
            }
            if ch == q {
                let closes =
                    !triple || (chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q));
                if closes {
                    i += if triple { 3 } else { 1 };
                    closed = true;
                    break;
                }
            }
            raw.push(ch);
            i += 1;
        }
        if !closed {
            continue;
        }
        let after = i;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i > after && (chars.get(i) == Some(&'"') || chars.get(i) == Some(&'\'')) {
            continue; // implicit concatenation: the msgid is the joined string
        }
        // The literal is the first argument: `)`, `,` (format args), `.format(...)` or `%`.
        match chars.get(i) {
            Some(')') | Some(',') | Some('.') | Some('%') => {}
            _ => continue,
        }
        out.push((line_of_index(start), py_unescape(&raw)));
    }
    out
}

/// The catalogue the app actually ships, unlike `catalogue()` which only looks inside the package:
/// `locale_file` of `[frappe]` when set, else `<package>/locale/*.po`, else the bench layout
/// `<app>/locale/*.po` one level up. `pt_BR.po` wins, then alphabetical. No `.po`, no findings.
fn po_catalogue(c: &Ctx) -> Option<(String, BTreeMap<String, String>)> {
    let mut found: Vec<PathBuf> = Vec::new();
    if let Some(f) = &c.cfg.locale_file {
        let p = Path::new(f);
        let inside = if p.is_absolute() {
            p.to_path_buf()
        } else {
            c.pkg.join(p)
        };
        found.push(inside);
        found.push(c.root.join(f));
    }
    let mut dirs: Vec<PathBuf> = vec![c.pkg.join("locale")];
    if let Some(parent) = c.pkg.parent() {
        dirs.push(parent.join("locale"));
    }
    for d in &dirs {
        let mut here: Vec<PathBuf> = fs::read_dir(d)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.extension().map(|x| x == "po").unwrap_or(false))
                    .collect()
            })
            .unwrap_or_default();
        here.sort();
        here.sort_by_key(|p| p.file_name().and_then(|n| n.to_str()) != Some("pt_BR.po"));
        found.append(&mut here);
    }
    let path = found.into_iter().find(|p| p.is_file())?;
    Some((rel(&c.root, &path), load_catalogue(&path)?))
}

fn rule_i18n_literals(c: &Ctx) -> Vec<Violation> {
    let Some((pr, map)) = po_catalogue(c) else {
        return Vec::new(); // no catalogue: nothing to compare against, stay silent
    };
    let mut out = Vec::new();
    for p in c
        .files
        .iter()
        .filter(|p| p.extension().map(|e| e == "py").unwrap_or(false))
    {
        let text = read(p);
        // one entry per literal, at its first line, with the number of calls
        let mut missing: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for (line, lit) in translation_literals(&text) {
            if !translatable_literal(&lit) || map.contains_key(&lit) {
                continue;
            }
            let e = missing.entry(lit).or_insert((line, 0));
            e.1 += 1;
        }
        for (lit, (line, n)) in missing {
            out.push(viol(
                "FRAPPE-I18N-SOURCE-LITERALS",
                &rel(&c.root, p),
                line,
                &lit,
                format!(
                    "`_(\"{lit}\")`{} has no msgid in {pr}: gettext returns the source string, so it reaches the screen in English on a translated page (GB-082).",
                    if n > 1 { format!(" ({n} calls)") } else { String::new() }
                ),
                "Add the msgid and its translation to the catalogue, or stop passing the technical string through `_()`.",
            ));
        }
    }
    out
}

// ── FRAPPE-OTHER-OPTION-NEEDS-TEXT (GB-081) ────────────────────────────────
/// Options that promise free text the Select cannot hold.
const OTHER_OPTIONS: &[&str] = &["other", "outro"];
/// Fieldtypes that can carry the text the `Other` option stands for.
const OTHER_TEXT_TYPES: &[&str] = &["Data", "Text", "Long Text", "Small Text"];
/// Closed lists where `Other` is a final category and asking for a sentence afterwards is wrong
/// design: a relationship reads "Other", not a description of the kinship. Reference case from
/// GB-081 triage: `Emergency Contact.relationship`. Keep this list short and fieldname-exact.
const CLOSED_LIST_FIELDS: &[&str] = &[
    "relationship",
    "gender",
    "salutation",
    "employment_type",
    "industry",
    "sector",
];

/// True when the field points at `select` in `depends_on`, or its label/description names it.
fn cites_field(g: &Field, select: &Field) -> bool {
    let named = |hay: &str| {
        hay.split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .any(|w| w == select.fieldname)
    };
    named(&g.depends_on)
        || (!select.label.is_empty()
            && (g
                .label
                .to_lowercase()
                .contains(&select.label.to_lowercase())
                || g.description
                    .to_lowercase()
                    .contains(&select.label.to_lowercase())))
}

fn rule_other_option(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for d in &c.doctypes {
        for f in d.fields.iter().filter(|f| f.fieldtype == "Select") {
            let opts: Vec<&str> = f
                .options
                .split('\n')
                .map(str::trim)
                .filter(|o| !o.is_empty())
                .collect();
            let Some(opt) = opts
                .iter()
                .find(|o| OTHER_OPTIONS.contains(&o.to_lowercase().as_str()))
            else {
                continue;
            };
            if CLOSED_LIST_FIELDS.contains(&f.fieldname.as_str()) {
                continue; // documented exception: `Other` is the answer, not a placeholder
            }
            let companions: Vec<&str> = d
                .fields
                .iter()
                .filter(|g| {
                    g.fieldname != f.fieldname && OTHER_TEXT_TYPES.contains(&g.fieldtype.as_str())
                })
                .filter(|g| cites_field(g, f))
                .map(|g| g.fieldname.as_str())
                .collect();
            if !companions.is_empty() {
                continue;
            }
            // A short list is as likely to be a closed list as a broken promise: advisory.
            let sev = if opts.len() <= 6 {
                Severity::Warning
            } else {
                Severity::Error
            };
            let text_fields: Vec<&str> = d
                .fields
                .iter()
                .filter(|g| OTHER_TEXT_TYPES.contains(&g.fieldtype.as_str()))
                .map(|g| g.fieldname.as_str())
                .collect();
            out.push(viol_as(
                "FRAPPE-OTHER-OPTION-NEEDS-TEXT",
                sev,
                &d.rel,
                line_of(&d.text, &format!("\"{}\"", f.fieldname)),
                &f.fieldname,
                format!(
                    "`{}.{}` offers `{opt}` among {} options and no text field is tied to it: whoever picks `{opt}` stores a value with no place to say what it is (GB-081). Text fields in the DocType: {}.",
                    d.name,
                    f.fieldname,
                    opts.len(),
                    if text_fields.is_empty() {
                        "none".to_string()
                    } else {
                        text_fields.join(", ")
                    }
                ),
                &format!(
                    "Add a Data/Text field whose `depends_on` is `eval:doc.{}=='{opt}'` (mandatory in that branch), or drop `{opt}` from the options.",
                    f.fieldname
                ),
            ));
        }
    }
    out
}

// ── VIZ-PANEL-SCHEMA (GB-086) ───────────────────────────────────────────────
/// Selects whose option ORDER is the process itself. Listed by name instead of inferred: the
/// engine cannot tell a funnel from a list of flavours without reading meaning into the option
/// text, and a guess would fire on `Gender` while missing a renamed stage. Each entry carries the
/// reason it belongs here, so a new ordinal can be added with one line of justification and not by
/// widening a heuristic.
const ORDINAL_SELECTS: &[(&str, &str, &str)] = &[
    (
        "Deal",
        "stage",
        "Lead -> Proposal -> Negotiation -> Won/Lost: a deal only moves down the list, so the option index is the funnel",
    ),
    (
        "Invoice",
        "status",
        "Pending -> Paid -> Overdue -> Cancelled: the list is the invoice lifecycle, and the position says what still needs chasing",
    ),
    (
        "OKR",
        "status",
        "On Track -> At Risk -> Behind -> Done: the list is the confidence ladder a steward reads at a glance",
    ),
];

/// Line of the JSON object key that carries `value`. The documents here are written one key per
/// line (the Desk export shape), so the line of the key is the line to point a reader at.
fn key_line(text: &str, keys: &[&str], value: &str) -> usize {
    let quoted = format!("\"{value}\"");
    text.lines()
        .position(|l| keys.iter().any(|k| l.contains(&format!("\"{k}\""))) && l.contains(&quoted))
        .map(|i| i + 1)
        .unwrap_or(1)
}

fn app_doctype<'a>(c: &'a Ctx, name: &str) -> Option<&'a DocType> {
    c.doctypes.iter().find(|d| d.name == name)
}

fn app_field<'a>(c: &'a Ctx, doctype: &str, field: &str) -> Option<&'a Field> {
    app_doctype(c, doctype)?
        .fields
        .iter()
        .find(|f| f.fieldname == field)
}

/// Every document of `doctype` the app ships as a JSON array, with the file it came from. Frappe
/// exports these files as an array of documents (the Desk export), which is the shape read here.
fn desk_documents(c: &Ctx, doctype: &str) -> Vec<(String, String, Value)> {
    let mut out = Vec::new();
    for p in c
        .files
        .iter()
        .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
    {
        let text = read(p);
        let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let path = rel(&c.root, p);
        for it in items.iter().filter(|i| str_of(i, "doctype") == doctype) {
            out.push((path.clone(), text.clone(), it.clone()));
        }
    }
    out
}

/// GB-086: a dashboard panel has to match what it measures. A Donut/Pie claims part-to-whole, so
/// it is the wrong panel for a Select whose option order is the process (a circle has no first
/// slice — the reader cannot see where a row stands) and for a money measure without a total.
/// Frappe stores the renderer in `type` and the data source in `chart_type`; the field named in
/// the report ("chart_type Donut/Pie") is the renderer, so `type` is read first and `chart_type`
/// is only a fallback for a malformed export.
fn rule_viz_panel(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for (path, text, chart) in desk_documents(c, "Dashboard Chart") {
        let render = match str_of(&chart, "type") {
            t if !t.is_empty() => t,
            _ => str_of(&chart, "chart_type"),
        };
        if !matches!(render.as_str(), "Donut" | "Pie") {
            continue;
        }
        let doc = str_of(&chart, "document_type");
        if doc.is_empty() {
            continue; // Element/Report charts measure nothing this rule can resolve
        }
        let name = match str_of(&chart, "chart_name") {
            n if !n.is_empty() => n,
            _ => str_of(&chart, "name"),
        };
        let grouped = match str_of(&chart, "group_by_based_on") {
            g if !g.is_empty() => g,
            _ => str_of(&chart, "based_on"),
        };
        let measure = str_of(&chart, "value_based_on");
        let line = key_line(&text, &["chart_name", "name"], &name);
        let snippet = text
            .lines()
            .nth(line.saturating_sub(1))
            .unwrap_or("")
            .trim();

        if let Some((_, _, why)) = ORDINAL_SELECTS
            .iter()
            .find(|(d, f, _)| *d == doc && *f == grouped)
        {
            if let Some(field) = app_field(c, &doc, &grouped).filter(|f| f.fieldtype == "Select") {
                let opts: Vec<&str> = field
                    .options
                    .split('\n')
                    .map(str::trim)
                    .filter(|o| !o.is_empty())
                    .collect();
                out.push(viol(
                    "VIZ-PANEL-SCHEMA",
                    &path,
                    line,
                    snippet,
                    format!(
                        "chart `{name}` draws `{doc}.{grouped}` as a {render}, but that Select's option order is the process itself ({}). {why}. A {render} has no first and no last slice, so the reader cannot see where a row stands in the process (GB-086).",
                        opts.join(" -> ")
                    ),
                    &format!(
                        "Draw it as a Bar ordered by the Select order of `{doc}.{grouped}`, or split the process into a board/report instead of a circle."
                    ),
                ));
                continue;
            }
        }

        let money = app_field(c, &doc, &measure)
            .map(|f| f.fieldtype == "Currency")
            .unwrap_or(false);
        if money {
            out.push(viol(
                "VIZ-PANEL-SCHEMA",
                &path,
                line,
                snippet,
                format!(
                    "chart `{name}` is a {render} whose measure is `{doc}.{measure}` (Currency): a part-to-whole circle of money needs a total the data does not carry, so two invoices of opposite meaning become two comparable slices (GB-086)."
                ),
                &format!(
                    "Draw it as a Bar with SUM over `{doc}.{measure}`; keep `{}` for a count of rows, where the slices really do add up to the whole.",
                    if grouped.is_empty() { "the grouped field" } else { grouped.as_str() }
                ),
            ));
        }
    }
    out
}

// ── NO-KANBAN-BOARD-FIXTURE (GB-087) ────────────────────────────────────────
/// Documents people arrange in the Desk. A fixture of one of these is a delete+insert of the live
/// row on every `bench migrate`, which is the opposite of what the Desk is for.
const DESK_OWNED_FIXTURES: &[&str] = &[
    "Kanban Board",
    "Dashboard",
    "Dashboard Chart",
    "Number Card",
    "Workspace",
];

/// Byte ranges of every `fixtures = [...]` / `fixtures += [...]` block of hooks.py, brackets
/// included: an app may extend the list in a second assignment.
fn fixtures_blocks(text: &str) -> Vec<(usize, usize)> {
    let Ok(head) = Regex::new(r"(?m)^fixtures\s*\+?=\s*\[") else {
        return Vec::new();
    };
    head.find_iter(text)
        .filter_map(|m| balanced_at(text, m.end() - 1, b'[', b']'))
        .collect()
}

/// GB-087: a fixture is imported with `force=True`, which deletes and reinserts the live document
/// (`frappe/modules/import_file.py`, `delete_old_doc`), bypassing the Kanban Board guard. Whatever
/// a steward arranged — columns, order, cards in a column — is gone after migrate, silently.
/// `desk_sync` exists in the app for exactly this reason: it inserts what is missing and keeps
/// what is there.
fn rule_kanban_fixture(c: &Ctx) -> Vec<Violation> {
    let hooks = c.pkg.join("hooks.py");
    let text = read(&hooks);
    let blocks = fixtures_blocks(&text);
    if blocks.is_empty() {
        return Vec::new();
    }
    let Ok(dt_re) = Regex::new(r#"(?m)["']dt["']\s*:\s*["']([^"']+)["']"#) else {
        return Vec::new();
    };
    let hr = rel(&c.root, &hooks);
    let mut out = Vec::new();
    for (bs, be) in blocks {
        let block = text.get(bs..be).unwrap_or("");
        for m in dt_re.captures_iter(block) {
            let Some(dt) = m.get(1) else { continue };
            let dt_name = dt.as_str();
            if !DESK_OWNED_FIXTURES.contains(&dt_name) {
                continue;
            }
            let at = bs + dt.start();
            let line = text
                .get(..at)
                .map(|p| p.matches('\n').count() + 1)
                .unwrap_or(1);
            out.push(viol(
                "NO-KANBAN-BOARD-FIXTURE",
                &hr,
                line,
                text.lines().nth(line.saturating_sub(1)).unwrap_or("").trim(),
                format!(
                    "`fixtures` imports `{dt_name}` at {hr}:{line}; Frappe's fixture importer runs with force=True and delete+inserts the live document, so the arrangement a steward made in the Desk is replaced by the file after every `bench migrate` (GB-087)."
                ),
                &format!(
                    "Ship `{dt_name}` from the app's `desk/` directory and install it create-only (insert when missing, keep what the site has), or as a standard module document with is_standard=Yes (force=0). Keep `fixtures` for reference data such as Role."
                ),
            ));
        }
    }
    out
}

// ── DOCTYPE-CALENDAR-GANTT-NEEDS-DATES (GB-088) ─────────────────────────────
/// Date fields whose name says which end of the span they hold. The names are the vocabulary the
/// apps actually use; a DocType that names its span something else is a false negative, which is
/// cheaper than refusing a file that works.
const START_DATES: &[&str] = &[
    "start_date",
    "from_date",
    "start",
    "start_on",
    "begins_on",
    "planned_start_date",
    "expected_start_date",
];
const END_DATES: &[&str] = &[
    "end_date",
    "to_date",
    "end",
    "end_on",
    "due_date",
    "finish_date",
    "completion_date",
    "planned_end_date",
    "expected_end_date",
];

fn date_role(fieldname: &str) -> Option<&'static str> {
    let starts = START_DATES.contains(&fieldname)
        || fieldname.starts_with("start_")
        || fieldname.ends_with("_start")
        || fieldname.ends_with("_from");
    if starts {
        return Some("start");
    }
    let ends = END_DATES.contains(&fieldname)
        || fieldname.starts_with("end_")
        || fieldname.ends_with("_end")
        || fieldname.ends_with("_to");
    ends.then_some("end")
}

/// The calendar controller the app ships for a DocType: `<stem>_calendar.js` in `public/js/`, or a
/// shared `*_calendar.js` that names the DocType.
fn calendar_js(c: &Ctx, stem: &str, doctype: &str) -> bool {
    let dir = c.pkg.join("public").join("js");
    if dir.join(format!("{stem}_calendar.js")).is_file() {
        return true;
    }
    let Ok(entries) = fs::read_dir(&dir) else {
        return false;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with("_calendar.js"))
        .any(|e| read(&e.path()).contains(doctype))
}

/// GB-088: `is_calendar_and_gantt` is a checkbox that ships a view. Without a start or an end
/// date, Gantt draws a zero-duration bar and Calendar raises when the view opens — and neither
/// shows up at migrate, so the defect waits for the user who clicks the tab (Frappe
/// `gantt_view.js`, `calendar.py`). The controller half is the app's convention: every
/// calendar-enabled DocType carries its `*_calendar.js`, so the view exists next to the code that
/// keeps it readable.
fn rule_calendar_gantt(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for d in &c.doctypes {
        let Ok(v) = serde_json::from_str::<Value>(&d.text) else {
            continue;
        };
        if !flag(&v, "is_calendar_and_gantt") {
            continue;
        }
        let roles: Vec<&str> = d
            .fields
            .iter()
            .filter(|f| matches!(f.fieldtype.as_str(), "Date" | "Datetime"))
            .filter_map(|f| date_role(&f.fieldname))
            .collect();
        let mut missing = Vec::new();
        if !roles.contains(&"start") {
            missing.push(
                "no start date field (a Date/Datetime named start_date, start_*, *_start or from_date)"
                    .to_string(),
            );
        }
        if !roles.contains(&"end") {
            missing.push(
                "no end date field (a Date/Datetime named end_date, due_date, *_end or *_to)"
                    .to_string(),
            );
        }
        let stem = Path::new(&d.rel)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if !calendar_js(c, stem, &d.name) {
            missing.push(format!("no `public/js/{stem}_calendar.js` controller"));
        }
        if missing.is_empty() {
            continue;
        }
        out.push(viol(
            "DOCTYPE-CALENDAR-GANTT-NEEDS-DATES",
            &d.rel,
            line_of(&d.text, "is_calendar_and_gantt"),
            "is_calendar_and_gantt",
            format!(
                "DocType `{}` enables Calendar and Gantt but {}: Gantt degrades to a zero-duration bar with no start/end, Calendar raises when the view opens, and neither failure appears at migrate — only the user who clicks the view finds it (GB-088).",
                d.name,
                missing.join("; ")
            ),
            "Add the missing Date/Datetime fields (or drop the flag), and ship the calendar controller next to the other public/js files.",
        ));
    }
    out
}

// ── FRAPPE-KANBAN-BOARD-DERIVED ─────────────────────────────────────────────
/// True when a module of the app (never a test) names the shipped file: that is what makes the
/// document reach a site — a create-only sync reads it, a hook imports it, a patch loads it.
fn installed_by_app(c: &Ctx, file: &str) -> bool {
    let name = Path::new(file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if name.is_empty() {
        return false;
    }
    let tests = c.pkg.join("tests");
    c.files
        .iter()
        .filter(|p| p.extension().map(|e| e == "py").unwrap_or(false))
        .filter(|p| p.parent() != Some(tests.as_path()))
        .any(|p| read(p).contains(name))
}

/// A board is derived when the app's own code produces it and proves it: the reference field
/// resolves, something installs the file, and — when the app carries a generator — a test
/// exercises it. The engine is static (no site, no bench), so "every Formed Squad and every Guild
/// has a board" cannot be read from the tree; what CAN be read is whether the thing that produces
/// those boards exists, is wired, and is proven. A tree with no generator and no board keeps the
/// rule silent: there is nothing to derive.
fn rule_kanban_derived(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for (path, text, board) in desk_documents(c, "Kanban Board") {
        if rel_to_fixtures(&path) {
            continue; // a fixtured board is GB-087's finding, not a second one here
        }
        let name = match str_of(&board, "kanban_board_name") {
            n if !n.is_empty() => n,
            _ => str_of(&board, "name"),
        };
        let reference = str_of(&board, "reference_doctype");
        let field = str_of(&board, "field_name");
        let line = key_line(&text, &["kanban_board_name", "name"], &name);
        let snippet = text
            .lines()
            .nth(line.saturating_sub(1))
            .unwrap_or("")
            .trim();
        let mut broken = Vec::new();
        if reference.is_empty() || field.is_empty() {
            broken.push("declares no reference_doctype or no field_name".to_string());
        } else if let Some(d) = app_doctype(c, &reference) {
            match d.fields.iter().find(|f| f.fieldname == field) {
                None => broken.push(format!(
                    "columns are grouped by `{field}`, which the app's `{reference}` DocType does not have"
                )),
                Some(f) if f.fieldtype != "Select" => broken.push(format!(
                    "columns are grouped by `{reference}.{field}`, a {} field: a board needs a Select",
                    f.fieldtype
                )),
                _ => {}
            }
        }
        if broken.is_empty() && !installed_by_app(c, &path) {
            broken.push(format!(
                "no module of the app names `{path}`, so nothing installs the board: it exists in git and never reaches a site"
            ));
        }
        if !broken.is_empty() {
            out.push(viol(
                "FRAPPE-KANBAN-BOARD-DERIVED",
                &path,
                line,
                snippet,
                format!(
                    "board `{name}` is not derived from the app: {}. A board that the code does not produce and install is a board nobody can rely on.",
                    broken.join("; ")
                ),
                "Fix the reference doctype/field, and install the file from the create-only sync (desk_sync) instead of shipping it by hand.",
            ));
        }
    }

    let generator = c.pkg.join("boards.py");
    if generator.is_file() {
        // The proof has to be a call, not a mention: `dashboards` and `offboards` are words in
        // other tests, and a docstring that says "boards" exercises nothing. The generator's own
        // top-level functions are what a test calls, so they are read from its source.
        let symbols = generator_symbols(&read(&generator));
        let tests = c.pkg.join("tests");
        let proven = symbols.iter().any(|sym| {
            let Ok(call) = Regex::new(&format!(r"\b{}\s*\(", regex::escape(sym))) else {
                return false;
            };
            c.files
                .iter()
                .filter(|p| p.extension().map(|e| e == "py").unwrap_or(false))
                .filter(|p| p.parent() == Some(tests.as_path()))
                .any(|p| call.is_match(&read(p)))
        });
        if !symbols.is_empty() && !proven {
            out.push(viol(
                "FRAPPE-KANBAN-BOARD-DERIVED",
                &rel(&c.root, &generator),
                1,
                "boards.py",
                "`boards.py` derives boards for the app (a board per Formed Squad and per Guild), but no test of the app exercises it: the derivation is code nobody checks, and the first missing board is found by a steward opening the Desk.".to_string(),
                "Add a test under the app's tests/ that builds a Squad (status Formed) and a Guild and asserts each gets its board, and register it in the test list.",
            ));
        }
    }
    out
}

// ── FRAPPE-TEST-PARITY ─────────────────────────────────────────────────────
// Why it exists: the pure-test battery exists twice — the section of the repository AGENTS.md
// that declares which modules run "without a site", and the `names`/`cmds` arrays of the release
// script. They drifted, and a release tagged a tree whose declared tests were not the ones that
// ran (rc107, tag burned). `names` and `cmds` are PARALLEL arrays: a shifted slot changes which
// command a log label refers to and the gate lies without failing. Both directions are compared
// by machine (agent-global-rules.md §12.4); a missing side leaves the rule inert and says so.

/// One quoted command of a bash array, with the source line it occupies.
struct QuotedCmd {
    text: String,
    line: usize,
}

/// Words of a bash word array (`names=(a b c)`), which may wrap over several lines; a `#` opens
/// a comment. Returns the words and the line the array opens on.
fn shell_words(text: &str, key: &str) -> Option<(Vec<String>, usize)> {
    let head = format!("{key}=(");
    let mut words: Vec<String> = Vec::new();
    let mut open: Option<usize> = None;
    for (i, line) in text.lines().enumerate() {
        let code = line.split('#').next().unwrap_or("");
        let start = match open {
            None => match code.find(&head) {
                Some(p) => {
                    open = Some(i + 1);
                    p + head.len()
                }
                None => continue,
            },
            Some(_) => 0,
        };
        let body = &code[start..];
        let end = body.find(')').unwrap_or(body.len());
        words.extend(body[..end].split_whitespace().map(str::to_string));
        if body.contains(')') {
            return Some((words, open?));
        }
    }
    None
}

/// Entries of a bash array written one quoted command per line (`cmds=( "..." ... )`), with the
/// line each entry occupies. Comments, blank lines and the closing parenthesis are skipped.
fn shell_quoted(text: &str, key: &str) -> Option<(Vec<QuotedCmd>, usize)> {
    let head = format!("{key}=(");
    let mut out: Vec<QuotedCmd> = Vec::new();
    let mut open: Option<usize> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if open.is_none() {
            if t.starts_with(&head) {
                open = Some(i + 1);
            }
            continue;
        }
        if t.starts_with(')') {
            break;
        }
        let Some(quote) = t.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            continue;
        };
        let inner = &t[1..];
        let end = inner.rfind(quote).unwrap_or(inner.len());
        out.push(QuotedCmd {
            text: inner[..end].to_string(),
            line: i + 1,
        });
    }
    open.map(|l| (out, l))
}

/// The release battery as the two parallel arrays it is written with.
struct Battery {
    rel: String,
    names: Vec<String>,
    names_line: usize,
    cmds: Vec<QuotedCmd>,
}

fn read_battery(root: &Path, path: &Path) -> Option<Battery> {
    let text = read(path);
    let (names, names_line) = shell_words(&text, "names")?;
    let (cmds, _) = shell_quoted(&text, "cmds")?;
    Some(Battery {
        rel: rel(root, path),
        names,
        names_line,
        cmds,
    })
}

/// The app root and up to `n` ancestors, nearest first. The filesystem root is never included:
/// it is not a repository neighbourhood, and walking it would be both slow and meaningless.
fn ancestors(root: &Path, n: usize) -> Vec<PathBuf> {
    // GB-230: `.` and `../x` have no usable `parent()` (`Path::new(".").parent()` is `""`, which
    // has no file name), so a relative `--repo` never reached the sibling repository an absolute
    // one did and the verdict depended on the spelling. Resolve to the real path first.
    let real = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let root = real.as_path();
    let mut out = vec![root.to_path_buf()];
    let mut cur = root;
    for _ in 0..n {
        match cur.parent() {
            Some(p) => {
                if p.file_name().is_none() {
                    break;
                }
                out.push(p.to_path_buf());
                cur = p;
            }
            None => break,
        }
    }
    out
}

/// Bounded search for a file named `name` under `base`, at most `depth` directory levels down,
/// whose content satisfies `accept`. Hidden and heavy directories are skipped (the same list the
/// package walk uses) and the visit count is capped, so an unknown layout costs "not found"
/// instead of a stalled audit.
fn find_in(
    base: &Path,
    name: &str,
    depth: usize,
    accept: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    const MAX_DIRS: usize = 4000;
    let mut queue: Vec<(PathBuf, usize)> = vec![(base.to_path_buf(), 0)];
    let mut seen = 0usize;
    while let Some((dir, level)) = queue.pop() {
        seen += 1;
        if seen > MAX_DIRS {
            return None;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            let name_owned = entry.file_name();
            let Some(file_name) = name_owned.to_str() else {
                continue;
            };
            if kind.is_dir() {
                if level < depth && !file_name.starts_with('.') && !SKIP_DIRS.contains(&file_name) {
                    queue.push((path, level + 1));
                }
            } else if kind.is_file() && file_name == name && accept(&path) {
                return Some(path);
            }
        }
    }
    None
}

/// The battery script: `STENIO_FRAPPE_BATTERY`, `[frappe] battery_file`, the two documented repo
/// positions, then a bounded search from the app root and its ancestors.
fn parity_battery(c: &Ctx) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let configured = std::env::var("STENIO_FRAPPE_BATTERY")
        .ok()
        .into_iter()
        .chain(c.cfg.battery_file.clone());
    for f in configured {
        let p = Path::new(&f);
        candidates.push(if p.is_absolute() {
            p.to_path_buf()
        } else {
            c.root.join(p)
        });
    }
    candidates.push(c.root.join("scripts/release-checks.sh"));
    candidates.push(c.root.join("compose/frappe/scripts/release-checks.sh"));
    if let Some(p) = candidates.into_iter().find(|p| p.is_file()) {
        return Some(p);
    }
    let accept = |p: &Path| read(p).contains("names=(");
    ancestors(&c.root, 1)
        .into_iter()
        .find_map(|a| find_in(&a, "release-checks.sh", 4, &accept))
}

/// The document that declares the tests: `STENIO_FRAPPE_TEST_LIST`, `[frappe] test_list_file`,
/// `<root>/AGENTS.md`, then a bounded search for the nearest AGENTS.md whose text says which
/// tests run "without a site".
fn parity_doc(c: &Ctx) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let configured = std::env::var("STENIO_FRAPPE_TEST_LIST")
        .ok()
        .into_iter()
        .chain(c.cfg.test_list_file.clone());
    for f in configured {
        let p = Path::new(&f);
        candidates.push(if p.is_absolute() {
            p.to_path_buf()
        } else {
            c.root.join(p)
        });
    }
    candidates.push(c.root.join("AGENTS.md"));
    if let Some(p) = candidates.into_iter().find(|p| p.is_file()) {
        return Some(p);
    }
    let accept = |p: &Path| {
        let text = read(p).to_lowercase();
        text.contains("without a site") && text.contains('`')
    };
    ancestors(&c.root, 1)
        .into_iter()
        .find_map(|a| find_in(&a, "AGENTS.md", 4, &accept))
}

/// A bare lowercase identifier with at least one underscore — the shape a test module has
/// (`w1_structure`, `charts_pure`, `i18n_coverage`). Prose, paths and flags never match.
fn module_shaped(token: &str) -> bool {
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    let mut underscore = false;
    for ch in chars {
        if ch == '_' {
            underscore = true;
            continue;
        }
        if !(ch.is_ascii_lowercase() || ch.is_ascii_digit()) {
            return false;
        }
    }
    underscore
}

/// The modules the section of `text` opened by `anchor` declares as running "without a site",
/// with the line each is declared on. A backticked token counts when it is module-shaped or when
/// `tests/<token>.py` exists, so prose (`migrate`, `docker`) is never read as a test. `None` when
/// the section or the declaration sentence is missing: the rule then refuses to compare instead
/// of passing over an unreadable list.
fn pure_declaration(text: &str, anchor: &str, tests: &Path) -> Option<Vec<(String, usize)>> {
    let body = section(text, anchor)?;
    let top = line_of(text, anchor);
    let backtick = Regex::new(r"`([^`]+)`").ok()?;
    let mut out: Vec<(String, usize)> = Vec::new();
    let mut clause = false;
    for (i, line) in body.lines().enumerate() {
        for part in line.split(';') {
            if !part.to_lowercase().contains("without a site") {
                continue;
            }
            clause = true;
            for cap in backtick.captures_iter(part) {
                let Some(token) = cap.get(1).map(|m| m.as_str()) else {
                    continue;
                };
                if module_shaped(token) || tests.join(format!("{token}.py")).is_file() {
                    out.push((token.to_string(), top + i));
                }
            }
        }
    }
    if !clause {
        return None;
    }
    out.sort();
    out.dedup();
    Some(out)
}

fn rule_test_parity(c: &Ctx) -> Vec<Violation> {
    let root_label = c.root.display().to_string();
    let hint_cfg = "Declare `[frappe] test_list_file`/`test_list_anchor` and `battery_file` (or STENIO_FRAPPE_TEST_LIST / STENIO_FRAPPE_BATTERY).";
    let Some(doc) = parity_doc(c) else {
        return vec![viol_as(
            "FRAPPE-TEST-PARITY",
            Severity::Warning,
            "AGENTS.md",
            1,
            "AGENTS.md",
            format!(
                "No test-list document was found from {root_label}: the parity between the declared pure tests and the release battery is unverified for this tree (isolated repo or partial checkout)."
            ),
            hint_cfg,
        )];
    };
    let doc_rel = rel(&c.root, &doc);
    let anchor = c
        .cfg
        .test_list_anchor
        .clone()
        .unwrap_or_else(|| "## 2.".to_string());
    let Some(declared) = pure_declaration(&read(&doc), &anchor, &c.pkg.join("tests")) else {
        return vec![viol(
            "FRAPPE-TEST-PARITY",
            &doc_rel,
            1,
            &anchor,
            format!(
                "`{doc_rel}` has no section `{anchor}`, or that section no longer declares which tests run `without a site`: the list the battery is compared against cannot be read, so the parity would pass on nothing."
            ),
            "Keep the release section and the sentence that names the pure tests (or point `test_list_anchor` at the heading that holds them).",
        )];
    };
    let Some(battery) = parity_battery(c).and_then(|p| read_battery(&c.root, &p)) else {
        return vec![viol_as(
            "FRAPPE-TEST-PARITY",
            Severity::Warning,
            "release-checks.sh",
            1,
            "release-checks.sh",
            format!(
                "No release battery with `names=(`/`cmds=(` was found from {root_label} (app root, its two documented positions and a bounded search of its ancestors): the declared pure tests are unverified for this tree (isolated repo or partial checkout)."
            ),
            hint_cfg,
        )];
    };
    let mut out = Vec::new();
    if battery.names.len() != battery.cmds.len() {
        out.push(viol(
            "FRAPPE-TEST-PARITY",
            &battery.rel,
            battery.names_line,
            "names=(",
            format!(
                "`{}` declares {} label(s) in `names` and {} command(s) in `cmds`: the arrays are parallel, so a slot no longer names its own command and every log line of the battery reports the wrong test.",
                battery.rel,
                battery.names.len(),
                battery.cmds.len()
            ),
            "Restore the one-to-one order: each label needs its command at the same index.",
        ));
    }
    let Ok(module_re) = Regex::new(r"tests/([A-Za-z0-9_]+)\.py") else {
        return out;
    };
    let tests = c.pkg.join("tests");
    let mut ran: BTreeMap<String, usize> = BTreeMap::new();
    for (i, label) in battery.names.iter().enumerate() {
        let Some(cmd) = battery.cmds.get(i) else {
            continue;
        };
        let Some(module) = module_re
            .captures(&cmd.text)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
        else {
            continue; // a lint or a secret scan is not a test module: nothing to pair
        };
        if !module.starts_with(label.as_str()) {
            out.push(viol(
                "FRAPPE-TEST-PARITY",
                &battery.rel,
                cmd.line,
                label,
                format!(
                    "Slot {i} of `{}` is labelled `{label}` but its command runs `{module}`: `names` and `cmds` have drifted out of alignment.",
                    battery.rel
                ),
                &format!("Put the label and the command of `{module}` in the same slot."),
            ));
        }
        if !tests.join(format!("{module}.py")).is_file() {
            out.push(viol(
                "FRAPPE-TEST-PARITY",
                &battery.rel,
                cmd.line,
                &module,
                format!(
                    "The release battery `{}` runs `{module}` but `tests/{module}.py` is not in the app: that slot fails at release time (or is skipped by a guard), so the module named after it never runs.",
                    battery.rel
                ),
                &format!(
                    "Add `tests/{module}.py` or remove the stale slot from both arrays of `{}`.",
                    battery.rel
                ),
            ));
        }
        ran.entry(module).or_insert(cmd.line);
    }
    let mut listed: BTreeMap<String, usize> = BTreeMap::new();
    for (module, line) in declared {
        listed.entry(module).or_insert(line);
    }
    for (module, line) in &listed {
        if !ran.contains_key(module) {
            out.push(viol(
                "FRAPPE-TEST-PARITY",
                &doc_rel,
                *line,
                module,
                format!(
                    "`{module}` is declared as a pure test in `{doc_rel}`:{line} (section `{anchor}`) but the release battery `{}` never runs it: the declaration promises coverage the gate does not deliver.",
                    battery.rel
                ),
                &format!(
                    "Add `{module}` to both arrays of `{}` (same slot), or stop declaring it as a pure test.",
                    battery.rel
                ),
            ));
        }
    }
    for (module, line) in &ran {
        if !listed.contains_key(module) {
            out.push(viol(
                "FRAPPE-TEST-PARITY",
                &battery.rel,
                *line,
                module,
                format!(
                    "The release battery `{}`:{line} runs `{module}` but no pure-test declaration in `{doc_rel}` (section `{anchor}`) names it: the document and the gate describe different sets, so one of them is stale.",
                    battery.rel
                ),
                &format!("Declare `{module}` in the pure list of `{doc_rel}`, or drop it from the battery."),
            ));
        }
    }
    out
}

// ── FRAPPE-CURRENCY-THRESHOLD-UNSET ────────────────────────────────────────
// Why it exists (GB-123, GB-133): a Decision without an amount was approved with zero votes.
// Frappe stores an unfilled Currency as 0.0, so `(amount or 0) >= STRATEGIC_AMOUNT` answers
// "not strategic" for a value nobody filled — three of three Decisions carried amount 0 and the
// two-vote quorum of a Strategic decision never ran. The rule resolves the name against the
// Currency fields of the app's DocType JSONs, so a threshold over an Int or a local parameter
// (`value` in a rating function) is never accused.

/// A monetary operand of a comparison: the field, whether the code coerced emptiness away
/// (`or 0`, `flt()`, `float()`) and whether it was read as an attribute (`doc.amount`).
struct MoneyOperand {
    field: String,
    coerced: bool,
    attribute: bool,
}

/// The operand grammar shared by both sides of a threshold comparison.
const MONEY_OPERAND: &str = r"(?:(?:flt|float)\(\s*[^()]*\)|\(\s*[A-Za-z_][\w.]*\s+or\s+0(?:\.0)?\s*\)|[A-Za-z_][\w.]*\s+or\s+0(?:\.0)?|[A-Za-z_][\w.]*)";

/// Reads one comparison side as a Currency field: `X`, `(X or 0)`, `flt(X)`, `flt(X or 0)`,
/// `doc.X`, `self.X`.
fn money_operand(expr: &str, currency: &BTreeSet<String>) -> Option<MoneyOperand> {
    let mut e = expr.trim();
    let mut coerced = false;
    for wrapper in ["flt", "float"] {
        if let Some(rest) = e.strip_prefix(wrapper) {
            let rest = rest.trim_start();
            if let Some(inner) = rest.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
                e = inner.trim();
                coerced = true;
                break;
            }
        }
    }
    if e.starts_with('(')
        && e.ends_with(')')
        && balanced_at(e, 0, b'(', b')')
            .map(|(open, close)| open == 0 && close == e.len())
            .unwrap_or(false)
    {
        e = e[1..e.len() - 1].trim();
    }
    let low = e.to_lowercase();
    if let Some(at) = low.rfind(" or ") {
        let tail = low[at + 4..].trim();
        if tail == "0" || tail == "0.0" {
            e = e[..at].trim();
            coerced = true;
        }
    }
    let attribute = e.contains('.');
    let field = e.rsplit('.').next().unwrap_or(e).to_string();
    let mut chars = field.chars();
    let first_ok = chars
        .next()
        .map(|c| c.is_ascii_alphabetic() || c == '_')
        .unwrap_or(false);
    if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let known = currency.contains(&field);
    known.then_some(MoneyOperand {
        field,
        coerced,
        attribute,
    })
}

/// True when the function around `upto` already answered the empty case of `field` (a `None` /
/// empty test or a bare falsiness test). A per-line heuristic: a guard inside a sibling branch is
/// not proven, which costs a false negative, never a false accusation.
fn py_guards_field(lines: &[&str], upto: usize, field: &str) -> bool {
    let pattern = format!(
        r"(?:\b{0}\s+is\s+(?:not\s+)?None\b|\bnot\s+{0}\b|\b{0}\s+in\s+\([^)]*None|\b{0}\s*(?:==|!=)\s*None)",
        regex::escape(field)
    );
    let Ok(guard) = Regex::new(&pattern) else {
        return false;
    };
    let mut i = upto as isize;
    let mut seen = 0usize;
    while i >= 0 && seen < 40 {
        let line = lines[i as usize];
        if guard.is_match(line) {
            return true;
        }
        if line.starts_with("def ") || line.starts_with("class ") {
            break;
        }
        i -= 1;
        seen += 1;
    }
    false
}

fn rule_currency_threshold(c: &Ctx) -> Vec<Violation> {
    let currency: BTreeSet<String> = c
        .doctypes
        .iter()
        .flat_map(|d| d.fields.iter())
        .filter(|f| f.fieldtype == "Currency")
        .map(|f| f.fieldname.clone())
        .filter(|n| !n.is_empty())
        .collect();
    if currency.is_empty() {
        return Vec::new();
    }
    let pattern = format!(
        r"(?P<lhs>{MONEY_OPERAND})\s*(?P<op>>=|<=|>|<)\s*(?P<rhs>{MONEY_OPERAND}|\d[\d_]*(?:\.\d+)?)"
    );
    let Ok(compare) = Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in c
        .files
        .iter()
        .filter(|p| p.extension().map(|e| e == "py").unwrap_or(false))
    {
        let text = read(p);
        if !text.contains(['<', '>']) {
            continue;
        }
        let path = rel(&c.root, p);
        let lines: Vec<&str> = text.lines().collect();
        let mut state: Option<&'static str> = None;
        for (i, raw) in lines.iter().enumerate() {
            if !py_code_line(raw, &mut state) {
                continue; // inside a docstring: prose, not a decision
            }
            let line = py_strip_comment(raw);
            if !line.contains(['<', '>']) {
                continue;
            }
            for cap in compare.captures_iter(line) {
                let (Some(lhs), Some(op), Some(rhs)) =
                    (cap.name("lhs"), cap.name("op"), cap.name("rhs"))
                else {
                    continue;
                };
                let money = match (
                    money_operand(lhs.as_str(), &currency),
                    money_operand(rhs.as_str(), &currency),
                ) {
                    (Some(left), _) => left,
                    (None, Some(right)) => right,
                    (None, None) => continue,
                };
                // A bare name can be a local parameter (`value` in a rating check); only the
                // coerced shapes and the attribute reads prove a document field is compared.
                if !money.coerced && !money.attribute {
                    continue;
                }
                if py_guards_field(&lines, i, &money.field) {
                    continue;
                }
                let (expr, limit) = if money.field == field_of(lhs.as_str()) {
                    (lhs.as_str(), rhs.as_str())
                } else {
                    (rhs.as_str(), lhs.as_str())
                };
                // `x > 0` / `x <= 0` is an emptiness test, not a threshold: zero is exactly what
                // Frappe returns for an unfilled Currency, so that comparison is the branch.
                if limit
                    .trim()
                    .parse::<f64>()
                    .map(|v| v == 0.0)
                    .unwrap_or(false)
                {
                    continue;
                }
                out.push(viol(
                    "FRAPPE-CURRENCY-THRESHOLD-UNSET",
                    &path,
                    i + 1,
                    line.trim(),
                    format!(
                        "`{path}:{}` decides on Currency field `{}` with `{expr} {} {limit}`: Frappe stores an unfilled Currency as 0.0, so an empty value reads as zero and the threshold decides on it silently (GB-123/GB-133). An empty value needs its own branch before the comparison.",
                        i + 1,
                        money.field,
                        op.as_str()
                    ),
                    "Answer the empty case explicitly (`if doc.<field> is None: frappe.throw(...)`, or return/reject) before comparing, so \"no amount\" is never read as \"amount zero\".",
                ));
            }
        }
    }
    out
}

/// The last dotted segment of an expression, for matching an operand back to its side.
fn field_of(expr: &str) -> &str {
    let trimmed = expr.trim().trim_matches(['(', ')']).trim();
    trimmed.rsplit('.').next().unwrap_or(trimmed)
}

/// Top-level functions a generator module defines — the entry points a test has to call to prove
/// the boards exist.
fn generator_symbols(text: &str) -> Vec<String> {
    let Ok(re) = Regex::new(r"(?m)^def\s+([A-Za-z_]\w*)\s*\(") else {
        return Vec::new();
    };
    let mut out: Vec<String> = re
        .captures_iter(text)
        .filter_map(|m| m.get(1).map(|s| s.as_str().to_string()))
        .filter(|s| !s.starts_with('_'))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn rel_to_fixtures(path: &str) -> bool {
    path.split('/').any(|seg| seg == "fixtures")
}

// ── FRAPPE-PERMISSION-SCOPE ────────────────────────────────────────────────
// HOUSE POLICY, not a deduction from the app: roles that carry no identity of their own. A DocType
// that stores rows about a PERSON and lets one of these roles `read` or `write` needs a row-level
// scope in `hooks.py`. Adding a role here is a policy edit, deliberate and reviewed in the
// repository — the same way `mnemocine/network/gpu-consumers.txt` registers a GPU consumer.
const BROAD_ROLES: &[&str] = &[
    "Miracena Member",
    "Miracena Freelancer",
    "Desk User",
    "All",
    "Guest",
];

// Fieldnames that name a person even when the field is not a Link (a `Data` field holding a
// username, a Select of reviewers). A Link is resolved by its `options` INSTEAD: the target
// DocType is the fact and the fieldname is only a hint — a Link called `member` that points at
// `Member Squad` is not a person, while `assigned_to` pointing at `Member` is.
const PERSON_FIELDNAMES: &[&str] = &[
    "member",
    "user",
    "employee",
    "assigned_to",
    "voter",
    "reviewer",
    "reviewee",
    "candidate",
    "custodian",
];

/// DocTypes that are public BY DECLARATION live in this data file (one name per line, reason after
/// `#`). It is read from the app root — the package that carries `hooks.py`, which is what Frappe
/// calls an app — and, as an accepted alternative, from `--path` itself, so a repository that keeps
/// the file beside its `steniocheck.toml` is not forced to move it. A missing file is an EMPTY
/// allowlist on purpose: every DocType stays protected until somebody states, in the repository,
/// that a catalogue is meant to be readable by everyone. Registering a public DocType is therefore a
/// data edit, never an engine change.
const PUBLIC_PERMISSIONS_FILE: &str = "permissions-public.txt";

/// `Some(description)` when the field identifies a person, e.g. `` `assigned_to` (Link to Member)``.
fn person_field(f: &Field) -> Option<String> {
    let target = f.options.trim();
    if f.fieldtype.eq_ignore_ascii_case("Link") {
        return match target {
            "Member" | "User" => Some(format!("`{}` (Link to {target})", f.fieldname)),
            _ => None,
        };
    }
    let name = f.fieldname.to_ascii_lowercase();
    PERSON_FIELDNAMES
        .contains(&name.as_str())
        .then(|| format!("`{}` ({})", f.fieldname, f.fieldtype))
}

/// DocTypes named as a key of `permission_query_conditions` or `has_permission` in `hooks.py`.
///
/// Only the KEYS are read: the body of the function is never inspected, because whether a
/// condition is correct is not decidable statically — registration is the decision this rule can
/// verify. Two shapes are accepted, the ones the fleet writes: a literal key
/// (`"PDI": "miracena.pdi.pdi_conditions"`) and the spread comprehension
/// (`**{dt: "miracena.access.query_conditions" for dt in ("Invoice", "Deal", "Project")}`), because
/// both leave the DocType name as a quoted literal without a dot inside the block. A dotted literal
/// is a function path. Comments are dropped first, so the commented template that Frappe ships in
/// every `hooks.py` (`# permission_query_conditions = {`) registers nothing.
fn scoped_doctypes(c: &Ctx) -> BTreeSet<String> {
    let mut clean = String::new();
    for raw in read(&c.pkg.join("hooks.py")).lines() {
        clean.push_str(&strip_comment(raw));
        clean.push('\n');
    }
    let Ok(head) = Regex::new(r"(?m)^[ \t]*(?:permission_query_conditions|has_permission)\s*=")
    else {
        return BTreeSet::new();
    };
    let Ok(quoted) = Regex::new(r#""([^"\n]*)"|'([^'\n]*)'"#) else {
        return BTreeSet::new();
    };
    let mut out = BTreeSet::new();
    for m in head.find_iter(&clean) {
        let rest = &clean[m.end()..];
        let Some(brace) = rest.find('{') else {
            continue;
        };
        // The value must be a dict literal, not a name bound elsewhere: anything before the brace
        // that is not whitespace or a `**` spread means the dict is built somewhere we do not read.
        if !rest[..brace]
            .trim_start_matches(|c: char| c == '*' || c.is_whitespace())
            .is_empty()
        {
            continue;
        }
        let Some((_, end)) = balanced_at(rest, brace, b'{', b'}') else {
            continue;
        };
        let Some(block) = rest.get(brace..end) else {
            continue;
        };
        for q in quoted.captures_iter(block) {
            let Some(lit) = q.get(1).or_else(|| q.get(2)) else {
                continue;
            };
            let name = lit.as_str().trim();
            // A dotted literal is the function path, not the DocType key.
            if !name.is_empty() && !name.contains('.') {
                out.insert(name.to_string());
            }
        }
    }
    out
}

/// DocTypes declared public in `permissions-public.txt` (app root, or `--path` when the app keeps it
/// beside `steniocheck.toml`). The name is everything before the `#` — DocType names carry spaces
/// (`Studio Space`), so the line is not split on whitespace.
fn public_doctypes(c: &Ctx) -> BTreeSet<String> {
    [
        c.pkg.join(PUBLIC_PERMISSIONS_FILE),
        c.root.join(PUBLIC_PERMISSIONS_FILE),
    ]
    .iter()
    .flat_map(|p| {
        read(p)
            .lines()
            .filter_map(|raw| {
                let line = raw.split('#').next().unwrap_or("").trim();
                (!line.is_empty()).then(|| line.to_string())
            })
            .collect::<Vec<String>>()
    })
    .collect()
}

/// Line of the `nth` (1-based) permission row naming `role`. A DocType may grant the same role
/// twice — one row plain and one with `if_owner`, exactly the shape that reopens a table — so each
/// finding has to point at its own row instead of the first mention of the name.
fn perm_line(text: &str, role: &str, nth: usize) -> usize {
    let needle = format!("\"{role}\"");
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.contains(&needle))
        .map(|(i, _)| i + 1)
        .nth(nth.saturating_sub(1))
        .unwrap_or(1)
}

fn rule_permission_scope(c: &Ctx) -> Vec<Violation> {
    let scoped = scoped_doctypes(c);
    let public = public_doctypes(c);
    let mut out = Vec::new();
    for d in c.doctypes.iter().filter(|d| !d.is_child && !d.is_single) {
        // A registered scope and a declared-public DocType are both an answer: the rule is silent.
        if scoped.contains(&d.name) || public.contains(&d.name) {
            continue;
        }
        let Some(field) = d.fields.iter().find_map(person_field) else {
            continue; // a catalogue, not a table about people
        };
        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for p in &d.perms {
            let nth = seen.entry(p.role.as_str()).or_insert(0);
            *nth += 1;
            let nth = *nth;
            if !BROAD_ROLES.iter().any(|r| r.eq_ignore_ascii_case(&p.role)) {
                continue;
            }
            let mut ops: Vec<&str> = Vec::new();
            if p.read {
                ops.push("read");
            }
            if p.write {
                ops.push("write");
            }
            if ops.is_empty() {
                continue; // report/export alone cannot change or page through a row's content
            }
            // `if_owner` narrows the row that declares it and nothing else: another broad role on
            // the same DocType reopens the whole table, and a role added later does so with no
            // record of the decision. A permission row is not a scope; hooks.py is where the
            // scope of a DocType is written down, so the finding stands.
            let owner = if p.if_owner {
                " `if_owner` on this row narrows only the role that declares it: another broad row, or a role added later, reopens every record with no line in hooks.py saying so."
            } else {
                ""
            };
            out.push(viol(
                "FRAPPE-PERMISSION-SCOPE",
                &d.rel,
                perm_line(&d.text, &p.role, nth),
                &format!("{field} -> {}", p.role),
                format!(
                    "DocType `{}` stores rows about a person — {field} — and grants the broad role `{}` {}: neither `permission_query_conditions` nor `has_permission` names this DocType in hooks.py, so the grant is the whole table: every holder of `{}` reaches every record.{owner} Register `{}` in hooks.py (`permission_query_conditions`/`has_permission`) or declare the DocType public in {PUBLIC_PERMISSIONS_FILE}.",
                    d.name,
                    p.role,
                    ops.join(" and "),
                    p.role,
                    d.name
                ),
                &format!(
                    "Register `{}` in hooks.py — `permission_query_conditions[\"{}\"]` and `has_permission[\"{}\"]` — or declare it public in {PUBLIC_PERMISSIONS_FILE} (one DocType per line, reason after `#`).",
                    d.name, d.name, d.name
                ),
            ));
        }
    }
    out
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
        rule_published_content,
        rule_tests,
        rule_test_parity,
        rule_sidebar,
        rule_roles,
        rule_select_case,
        rule_labels,
        rule_whitelist,
        rule_rules_coverage,
        rule_role_fixture_parity,
        rule_fetch_parity,
        rule_currency_threshold,
        rule_permission_scope,
        rule_silent_except,
        rule_min_syntax,
        rule_privileged_read,
        rule_i18n_literals,
        rule_other_option,
        rule_viz_panel,
        rule_kanban_fixture,
        rule_calendar_gantt,
        rule_kanban_derived,
    ] {
        all.extend(f(&c));
    }
    all.sort_by(|a, b| {
        (&a.rule_id, &a.file_path, a.line_number).cmp(&(&b.rule_id, &b.file_path, b.line_number))
    });
    Ok(all)
}

// ── self-test fixtures ─────────────────────────────────────────────────────
const THING_JSON: &str = r#"{"doctype":"DocType","name":"Thing","fields":[{"fieldname":"part","fieldtype":"Link","options":"Part","label":"LBL"},{"fieldname":"state","fieldtype":"Select","options":"Open day\nClosed day"},{"fieldname":"kind","fieldtype":"Select","options":"KINDS"},{"fieldname":"code","fieldtype":"Data"},{"fieldname":"price","fieldtype":"Currency"}EXTRA],"permissions":[{"role":"ROLE"}]}"#;
const PART_JSON_GOOD: &str = r#"{"doctype":"DocType","name":"Part","title_field":"label","show_title_field_in_link":1,"fields":[]}"#;
const TEAM_MEMBER_GOOD: &str = r#"{"doctype":"DocType","name":"Team Member","istable":1,"fields":[{"fieldname":"member","fieldtype":"Link","options":"Part"},{"fieldname":"role","fieldtype":"Data","fetch_from":"member.role","fetch_if_empty":1}],"permissions":[]}"#;
const TEAM_MEMBER_BAD: &str = r#"{"doctype":"DocType","name":"Team Member","istable":1,"fields":[{"fieldname":"member","fieldtype":"Link","options":"Part"},{"fieldname":"role","fieldtype":"Data"}],"permissions":[]}"#;
const PART_JSON_BAD: &str = r#"{"doctype":"DocType","name":"Part","fields":[]}"#;
/// `Widget` carries a Link to `User` — a record about a person. `PERM` is where the bad tree adds
/// the broad role `FRAPPE-PERMISSION-SCOPE` refuses while `hooks.py` neither scopes nor the
/// allowlist declares the DocType.
const WIDGET_JSON: &str = r#"{"doctype":"DocType","name":"Widget","fields":[{"fieldname":"member","fieldtype":"Link","options":"User","label":"Member"}],"permissions":[{"role":"Demo Role"}PERM]}"#;
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
const PO_GOOD: &str = "msgid \"\"\nmsgstr \"\"\n\nmsgid \"Things\"\nmsgstr \"Coisas\"\n\nmsgid \"Member\"\nmsgstr \"Membro\"\n\nmsgid \"Parts\"\nmsgstr \"Pecas\"\n\nmsgid \"Part\"\nmsgstr \"Peca\"\n\nmsgid \"Open day\"\nmsgstr \"Dia aberto\"\n\nmsgid \"Closed day\"\nmsgstr \"Dia fechado\"\n\nmsgid \"Kind note\"\nmsgstr \"Nota do tipo\"\n\nmsgid \"Widget\"\nmsgstr \"Widget\"\n";
/// FRAPPE-I18N-SOURCE-LITERALS: one `_()` call inline and one wrapped over three lines. The good
/// file only uses msgids the catalogue carries; the bad file adds a literal nobody translated.
const LABELS_GOOD: &str = "from frappe import _\n\n\ndef parts_label():\n\treturn _(\"Parts\")\n\n\ndef wrapped():\n\treturn _(\n\t\t\"Parts\"\n\t)\n";
const LABELS_BAD: &str = "from frappe import _\n\n\ndef parts_label():\n\treturn _(\"Parts\")\n\n\ndef wrapped():\n\treturn _(\n\t\t\"Uncatalogued label\"\n\t)\n";
/// VIZ-PANEL-SCHEMA needs a DocType with an ordinal Select and a money field to measure.
const DEAL_JSON: &str = r#"{"doctype":"DocType","name":"Deal","fields":[{"fieldname":"stage","fieldtype":"Select","label":"Stage","options":"Lead\nProposal\nNegotiation\nWon\nLost"},{"fieldname":"value","fieldtype":"Currency","label":"Value"}],"permissions":[{"role":"Demo Role"}]}"#;
/// Two panels, one per half of the rule: a Donut over the funnel, a Pie over the money.
const CHART_BAD: &str = r#"[
 {
  "doctype": "Dashboard Chart",
  "name": "Deals by Stage",
  "chart_name": "Deals by Stage",
  "chart_type": "Group By",
  "document_type": "Deal",
  "group_by_type": "Count",
  "group_by_based_on": "stage",
  "type": "Donut"
 },
 {
  "doctype": "Dashboard Chart",
  "name": "Money by Stage",
  "chart_name": "Money by Stage",
  "chart_type": "Sum",
  "document_type": "Deal",
  "based_on": "stage",
  "value_based_on": "value",
  "type": "Pie"
 }
]"#;
/// DOCTYPE-CALENDAR-GANTT-NEEDS-DATES: the flag on, a start date, no end date, no controller.
const ROADMAP_JSON: &str = r#"{
 "doctype": "DocType",
 "name": "Roadmap",
 "is_calendar_and_gantt": 1,
 "fields": [
  {"fieldname": "start_date", "fieldtype": "Date"},
  {"fieldname": "summary", "fieldtype": "Data"}
 ],
 "permissions": [{"role": "Demo Role"}]
}"#;
/// FRAPPE-KANBAN-BOARD-DERIVED: a generator no test of the app exercises.
const BOARDS_PY: &str = "import json\n\n\ndef boards():\n\treturn json.dumps([\"Tasks\"])\n";
/// FRAPPE-CURRENCY-THRESHOLD-UNSET: `Thing.price` is the only Currency of the fixture app. The
/// good module answers the empty case before comparing; the bad one coerces it to zero, which is
/// the shape that approved a Decision with no amount. `amount` and `code` are NOT Currency here,
/// so naming them proves the fieldname is resolved against the DocType JSONs.
const PRICING_GOOD: &str = "import frappe\nfrom frappe.utils import flt\n\nLIMIT = 250000\n\n\ndef is_large(price):\n\t\"\"\"A missing price is a decision of its own: never read as zero.\"\"\"\n\tif price is None:\n\t\tfrappe.throw(\"Price is required.\")\n\treturn flt(price) >= LIMIT\n";
const PRICING_BAD: &str = "from frappe.utils import flt\n\nLIMIT = 250000\n\n\ndef is_large(amount):\n\treturn (amount or 0) >= LIMIT\n\n\ndef is_huge(doc):\n\treturn flt(doc.price) >= LIMIT\n\n\ndef is_guarded(doc):\n\tif doc.price is not None and flt(doc.price) > LIMIT:\n\t\treturn True\n\treturn False\n\n\ndef is_code(doc):\n\treturn (doc.code or 0) >= 1\n";

/// FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE: the shape a publisher has — a file of the package
/// read at import of `execute()` and written into a Single's long-text field, with the hash guard
/// the real fix carries.
const PUBLISHER_PY: &str = "import hashlib\nfrom pathlib import Path\n\nDOCS = Path(__file__).resolve().parents[1] / \"docs\"\n\n\ndef same_content(stored, desired):\n\treturn hashlib.sha256(stored.encode()).hexdigest() == hashlib.sha256(desired.encode()).hexdigest()\n\n\ndef execute():\n\timport frappe\n\n\tbody = (DOCS / \"manual.html\").read_text(encoding=\"utf-8\")\n\tstored = frappe.db.get_single_value(\"Handbook\", \"content\")\n\tif same_content(stored or \"\", body):\n\t\treturn\n\tif frappe.db.exists(\"Handbook\", \"Handbook\"):\n\t\tfrappe.db.set_single_value(\"Handbook\", \"content\", body)\n\telse:\n\t\tfrappe.get_doc({\"doctype\": \"Handbook\", \"title\": \"Manual\", \"content\": body}).insert(ignore_permissions=True)\n";

/// The files of a tiny demo app; `bad` plants one violation of every rule.
pub fn fixture_files(bad: bool) -> Vec<(String, String)> {
    let f = |p: &str, t: &str| (p.to_string(), t.to_string());
    let mut v = vec![
        f("demoapp/__init__.py", "__version__ = \"0.1.0\"\n"),
        f("demoapp/modules.txt", "Demo\n"),
        f(
            "demoapp/hooks.py",
            &format!(
                "app_name = \"demoapp\"\ndoc_events = {{\"ToDo\": {{\"on_update\": \"demoapp.api.{}\", \"validate\": \"demoapp.session.sync_members\"}}}}  # \"demoapp.api.commented\"\nfixtures = [\n\t{{\"dt\": \"Role\", \"filters\": [[\"name\", \"in\", {}]]}},\n{}]\n{}",
                if bad { "missing_fn" } else { "on_todo" },
                if bad {
                    "[\"Demo Role\", \"Phantom Role\"]"
                } else {
                    "[\"Demo Role\"]"
                },
                // NO-KANBAN-BOARD-FIXTURE: the good tree fixtures reference data only; the bad
                // tree also fixtures the board a steward arranges in the Desk.
                if bad {
                    "\t{\"dt\": \"Kanban Board\", \"filters\": [[\"name\", \"in\", [\"Tasks\"]]]},\n"
                } else {
                    ""
                },
                // FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE: `patches/first.py` publishes
                // `docs/manual.html` into a Single, so the good tree republishes it on every
                // migrate; the bad tree leaves it in the one-shot ledger.
                if bad {
                    ""
                } else {
                    "after_migrate = [\"demoapp.patches.first.execute\"]\n"
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
        f("demoapp/patches/first.py", PUBLISHER_PY),
        f("demoapp/docs/manual.html", "<p>Manual, first edition</p>\n"),
        f("demoapp/demo/doctype/part/__init__.py", ""),
        f(
            "demoapp/demo/doctype/part/part.py",
            "class Part:\n    pass\n",
        ),
        f(
            "demoapp/demo/doctype/part/part.json",
            if bad { PART_JSON_BAD } else { PART_JSON_GOOD },
        ),
        f("demoapp/demo/doctype/team_member/__init__.py", ""),
        f(
            "demoapp/demo/doctype/team_member/team_member.py",
            "class TeamMember:\n    pass\n",
        ),
        // FRAPPE-FETCH-PARITY: the bad tree drops `fetch_from` from the child row's `role`.
        f(
            "demoapp/demo/doctype/team_member/team_member.json",
            if bad { TEAM_MEMBER_BAD } else { TEAM_MEMBER_GOOD },
        ),
        f("demoapp/demo/doctype/thing/__init__.py", ""),
        f(
            "demoapp/demo/doctype/thing/thing.json",
            &THING_JSON
                .replace("ROLE", if bad { "Ghost Role" } else { "Demo Role" })
                .replace("LBL", if bad { "Mystery label" } else { "Part" })
                // FRAPPE-OTHER-OPTION-NEEDS-TEXT: seven options ending in `Other` with no
                // companion field; the good tree keeps a closed list of two.
                .replace(
                    "KINDS",
                    if bad {
                        "Alpha\\nBravo\\nCharlie\\nDelta\\nEcho\\nFoxtrot\\nOther"
                    } else {
                        "Open day\\nClosed day"
                    }
                )
                .replace(
                    "EXTRA",
                    if bad {
                        ""
                    } else {
                        ",{\"fieldname\":\"kind_note\",\"fieldtype\":\"Data\",\"label\":\"Kind note\",\"depends_on\":\"eval:doc.kind=='Other'\"}"
                    },
                ),
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
        f(
            "demoapp/labels.py",
            if bad { LABELS_BAD } else { LABELS_GOOD },
        ),
        f("demoapp/demo/doctype/widget/__init__.py", ""),
        f(
            "demoapp/demo/doctype/widget/widget.json",
            &WIDGET_JSON.replace(
                "PERM",
                if bad {
                    // FRAPPE-PERMISSION-SCOPE: a broad role with read+write on a record about a
                    // person, with no scope registered in hooks.py.
                    r#",{"role":"Desk User","read":1,"write":1}"#
                } else {
                    ""
                },
            ),
        ),
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
        // FRAPPE-TEST-PARITY: the document declares which pure modules run without a site, the
        // battery below is the second copy of the same set. The bad tree adds `gamma` to the
        // battery and never declares it.
        f(
            "AGENTS.md",
            "## 2. Tests\n`alpha`\nThe pure ones (`alpha`) also run without a site.\n## 3. Other\nbeta\n",
        ),
        f(
            "scripts/release-checks.sh",
            if bad {
                "#!/usr/bin/env bash\n# release gates that need no site\nnames=(alpha gamma)\ncmds=(\n  \"python3 -I demoapp/tests/alpha.py\"\n  \"python3 -I demoapp/tests/gamma.py\"\n)\n"
            } else {
                "#!/usr/bin/env bash\n# release gates that need no site\nnames=(alpha)\ncmds=(\n  \"python3 -I demoapp/tests/alpha.py\"\n)\n"
            },
        ),
        f(
            "demoapp/pricing.py",
            if bad { PRICING_BAD } else { PRICING_GOOD },
        ),
    ];
    if !bad {
        v.push(f(
            "demoapp/demo/doctype/thing/thing.py",
            "class Thing:\n    pass\n",
        ));
    } else {
        v.push(f("demoapp/patches/second.py", "def execute():\n    pass\n"));
        v.push(f("demoapp/tests/beta.py", "def run():\n    pass\n"));
        v.push(f("demoapp/tests/gamma.py", "def run():\n    pass\n"));
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
        // VIZ-PANEL-SCHEMA: a Donut over the ordinal `Deal.stage` and a Pie over `Deal.value`.
        v.push(f("demoapp/desk/dashboard_chart.json", CHART_BAD));
        v.push(f("demoapp/demo/doctype/deal/__init__.py", ""));
        v.push(f("demoapp/demo/doctype/deal/deal.json", DEAL_JSON));
        v.push(f(
            "demoapp/demo/doctype/deal/deal.py",
            "class Deal:\n    pass\n",
        ));
        // DOCTYPE-CALENDAR-GANTT-NEEDS-DATES: the flag with a start date, no end, no controller.
        v.push(f("demoapp/demo/doctype/roadmap/__init__.py", ""));
        v.push(f("demoapp/demo/doctype/roadmap/roadmap.json", ROADMAP_JSON));
        v.push(f(
            "demoapp/demo/doctype/roadmap/roadmap.py",
            "class Roadmap:\n    pass\n",
        ));
        // FRAPPE-KANBAN-BOARD-DERIVED: a generator the app's tests never exercise.
        v.push(f("demoapp/boards.py", BOARDS_PY));
    }
    v
}

pub fn fixture_config() -> FrappeConfig {
    FrappeConfig {
        app: Some("demoapp".into()),
        test_list_file: Some("AGENTS.md".into()),
        test_list_anchor: Some("## 2. Tests".into()),
        fetch_parity: Some(vec![FetchParity {
            doctype_pattern: "*_member".into(),
            field: "role".into(),
            fetch_from: "member.role".into(),
            fetch_if_empty: None,
        }]),
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
    let mut cases: Vec<(String, bool)> = RULES
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
        .collect();
    cases.push((
        "FRAPPE-TEST-PARITY-SPELLING".to_string(),
        parity_spelling_agrees(),
    ));
    cases
}

/// GB-230: the same tree audited through an absolute and a relative spelling of its root (the
/// battery lives in a sibling repository) must give the same findings, and the sibling battery
/// must really have been seen (an error, not the inert warning). The relative spelling is built
/// from the current directory with `..` hops, so no process-wide `chdir` is needed.
pub(crate) fn parity_spelling_agrees() -> bool {
    let files: Vec<(String, String)> = vec![
        (
            "app-repo/AGENTS.md".into(),
            "## 2. Tests\nThe pure ones (`alpha`, `beta`) also run without a site.\n".into(),
        ),
        ("app-repo/app/__init__.py".into(), "__version__ = \"0.1.0\"\n".into()),
        ("app-repo/app/hooks.py".into(), "app_name = \"app\"\n".into()),
        ("app-repo/app/tests/alpha.py".into(), "def run():\n    pass\n".into()),
        ("app-repo/app/tests/beta.py".into(), "def run():\n    pass\n".into()),
        (
            "infra/compose/frappe/scripts/release-checks.sh".into(),
            "names=(alpha)\ncmds=(\n  \"python3 -I app/tests/alpha.py\"\n)\n".into(),
        ),
    ];
    let Some(base) = write_fixture("parity-spelling/x", &files) else {
        return false;
    };
    let cfg = FrappeConfig {
        app: Some("app".into()),
        ..FrappeConfig::default()
    };
    let abs = base.join("app-repo");
    let hops = std::env::current_dir()
        .map(|d| d.components().count().saturating_sub(1))
        .unwrap_or(0);
    let mut rel = PathBuf::new();
    for _ in 0..hops {
        rel.push("..");
    }
    rel.push(abs.strip_prefix("/").unwrap_or(&abs));
    let key = |r: Result<Vec<Violation>, String>| -> Vec<String> {
        r.unwrap_or_default()
            .into_iter()
            .filter(|v| v.rule_id == "FRAPPE-TEST-PARITY")
            .map(|v| format!("{:?}|{}|{}|{}", v.severity, v.file_path, v.line_number, v.message))
            .collect()
    };
    let (a, r) = (key(audit(&abs, &cfg)), key(audit(&rel, &cfg)));
    let _ = fs::remove_dir_all(&base);
    !a.is_empty() && a.iter().any(|m| m.starts_with("Error")) && a == r
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

    /// GB-230: absolute and relative spellings of the same repository root give one verdict.
    #[test]
    fn test_parity_verdict_is_independent_of_the_root_spelling() {
        assert!(parity_spelling_agrees());
    }

    #[test]
    fn case_rule_reference_cases() {
        assert!(select_case_problem("Open day", "Dia Aberto").is_some());
        assert!(select_case_problem("Open Day", "Dia Aberto").is_none());
        assert!(select_case_problem("Open day", "Dia aberto").is_none());
    }

    /// The scanner reads the shapes the real app writes: a wrapped call, an escaped quote, a
    /// single-quoted literal — and ignores what only looks like a call (docstring, comment,
    /// string constant, concatenation, a variable argument).
    #[test]
    fn translation_literals_reads_code_not_prose() {
        let src = "from frappe import _\n\nDOC = \"_('not a call')\"\n\n\ndef one():\n\treturn _(\n\t\t\"Wrapped over lines\"\n\t)\n\n\ndef two():\n\treturn _(\"He said \\\"hi\\\"\")\n\n\ndef three():\n\treturn _('Single quoted')\n\n\ndef four():\n\treturn _(name)\n\n\ndef five():\n\treturn _(\"joined \" \"piece\")\n\n\ndef six():\n\t# _(\"commented out\")\n\treturn _(\"Real one\").format(x=1)\n\n\"\"\"A docstring quoting _(\"prose\") is not a call.\"\"\"\n";
        let got: Vec<(usize, String)> = translation_literals(src);
        let texts: Vec<&str> = got.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            texts,
            vec![
                "Wrapped over lines",
                "He said \"hi\"",
                "Single quoted",
                "Real one"
            ]
        );
        assert_eq!(got[0].0, 8, "the line of the literal, not of the call");
    }

    /// GB-081 reference pair: `gender_other` with a `depends_on` that names the Select satisfies
    /// the rule; the same Select without it does not.
    #[test]
    fn companion_field_detection() {
        let select = Field {
            fieldname: "gender".into(),
            fieldtype: "Select".into(),
            options: "Woman\nMan\nOther".into(),
            read_only: false,
            label: "Gender".into(),
            description: String::new(),
            depends_on: String::new(),
            fetch_from: String::new(),
            fetch_if_empty: false,
        };
        let companion = Field {
            fieldname: "gender_other".into(),
            fieldtype: "Data".into(),
            options: String::new(),
            read_only: false,
            label: "How do you describe your gender?".into(),
            description: String::new(),
            depends_on: "eval:doc.gender=='Other'".into(),
            fetch_from: String::new(),
            fetch_if_empty: false,
        };
        assert!(cites_field(&companion, &select));
        let unrelated = Field {
            fieldname: "notes".into(),
            fieldtype: "Small Text".into(),
            options: String::new(),
            read_only: false,
            label: "Notes".into(),
            description: String::new(),
            depends_on: String::new(),
            fetch_from: String::new(),
            fetch_if_empty: false,
        };
        assert!(!cites_field(&unrelated, &select));
    }

    // ── mutation proofs for the four Desk/view rules ───────────────────────
    // Each test builds a temporary app, audits it, and then changes ONE thing. The run is the
    // proof the rule discriminates: the injected line turns it red, the line it replaced leaves
    // it green. Nothing here touches the real tree.

    const DEAL_JSON_T: &str = r#"{"doctype":"DocType","name":"Deal","fields":[{"fieldname":"stage","fieldtype":"Select","label":"Stage","options":"Lead\nProposal\nNegotiation\nWon\nLost"},{"fieldname":"value","fieldtype":"Currency","label":"Value"},{"fieldname":"owner","fieldtype":"Link","options":"User","label":"Owner"}],"permissions":[{"role":"System Manager"}]}"#;

    /// A minimal app: a package with hooks.py and nothing a rule other than the one under test
    /// would complain about.
    fn app_tree(extra: Vec<(&str, String)>) -> Vec<(String, String)> {
        let mut v = vec![
            (
                "app/__init__.py".to_string(),
                "__version__ = \"0.1.0\"\n".to_string(),
            ),
            (
                "app/hooks.py".to_string(),
                "app_name = \"app\"\n".to_string(),
            ),
        ];
        v.extend(extra.into_iter().map(|(p, t)| (p.to_string(), t)));
        v
    }

    /// Audit one temporary tree and return only the violations of `rule`; the tree is removed.
    fn audit_rule(tag: &str, files: &[(String, String)], rule: &str) -> Vec<Violation> {
        let cfg = FrappeConfig {
            app: Some("app".into()),
            ..FrappeConfig::default()
        };
        audit_rule_with(tag, files, rule, &cfg)
    }

    /// The same audit with an explicit `[frappe]` table (paths, anchor, battery).
    fn audit_rule_with(
        tag: &str,
        files: &[(String, String)],
        rule: &str,
        cfg: &FrappeConfig,
    ) -> Vec<Violation> {
        let Some(root) = write_fixture(tag, files) else {
            return Vec::new();
        };
        let got = audit(&root, cfg).unwrap_or_default();
        let _ = fs::remove_dir_all(&root);
        got.into_iter().filter(|v| v.rule_id == rule).collect()
    }

    /// An app with `Deal` and one dashboard panel over it: `render` is `type`, `grouped` is
    /// `group_by_based_on`, `measure` is `value_based_on` (empty means the panel counts rows).
    fn deal_app(render: &str, grouped: &str, measure: &str) -> Vec<(String, String)> {
        let chart_type = if measure.is_empty() {
            "Group By"
        } else {
            "Sum"
        };
        let chart = format!(
            "[\n {{\n  \"doctype\": \"Dashboard Chart\",\n  \"name\": \"Deals by Stage\",\n  \"chart_name\": \"Deals by Stage\",\n  \"chart_type\": \"{chart_type}\",\n  \"document_type\": \"Deal\",\n  \"group_by_based_on\": \"{grouped}\",\n  \"value_based_on\": \"{measure}\",\n  \"type\": \"{render}\"\n }}\n]"
        );
        app_tree(vec![
            ("app/demo/doctype/deal/deal.json", DEAL_JSON_T.to_string()),
            (
                "app/demo/doctype/deal/deal.py",
                "class Deal:\n\tpass\n".to_string(),
            ),
            ("app/desk/dashboard_chart.json", chart),
        ])
    }

    /// MUTATION: line 10 of the chart (`"type": "Donut"`) becomes `"Bar"`. Red names the chart,
    /// the field and the reason; green is the same tree with the panel the rule asks for.
    #[test]
    fn viz_panel_schema_turns_red_on_the_donut_and_green_on_the_bar() {
        let red = audit_rule(
            "viz-donut",
            &deal_app("Donut", "stage", ""),
            "VIZ-PANEL-SCHEMA",
        );
        assert_eq!(red.len(), 1, "{red:?}");
        assert_eq!(red[0].file_path, "app/desk/dashboard_chart.json");
        assert_eq!(red[0].line_number, 4);
        assert_eq!(red[0].severity, Severity::Error);
        assert!(
            red[0].message.contains("Deals by Stage"),
            "{}",
            red[0].message
        );
        assert!(red[0].message.contains("Deal.stage"), "{}", red[0].message);
        assert!(red[0].message.contains("GB-086"));

        assert!(
            audit_rule("viz-bar", &deal_app("Bar", "stage", ""), "VIZ-PANEL-SCHEMA").is_empty()
        );
    }

    /// The other half of GB-086: the measure is money. A Pie over `Deal.value` grouped by a field
    /// that is not an ordinal (`Deal.owner`) is red; the same measure as a Bar is green.
    #[test]
    fn viz_panel_schema_reads_the_money_measure() {
        let red = audit_rule(
            "viz-money",
            &deal_app("Pie", "owner", "value"),
            "VIZ-PANEL-SCHEMA",
        );
        assert_eq!(red.len(), 1, "{red:?}");
        assert!(red[0].message.contains("Deal.value"), "{}", red[0].message);

        assert!(
            audit_rule(
                "viz-sum-bar",
                &deal_app("Bar", "owner", "value"),
                "VIZ-PANEL-SCHEMA"
            )
            .is_empty()
        );
    }

    const HOOKS_GREEN: &str = "app_name = \"app\"\nfixtures = [\n\t{\"dt\": \"Role\", \"filters\": [[\"name\", \"in\", [\"System Manager\"]]]},\n]\n";
    const HOOKS_RED: &str = "app_name = \"app\"\nfixtures = [\n\t{\"dt\": \"Role\"},\n\t{\"dt\": \"Kanban Board\", \"filters\": [[\"name\", \"in\", [\"Tasks\"]]]},\n]\n";

    /// MUTATION: one line added to hooks.py (line 4) declares the board as a fixture. The run is
    /// red at that exact line; the file without it is green.
    #[test]
    fn board_fixture_is_refused_at_its_line() {
        let green = app_tree(vec![("app/hooks.py", HOOKS_GREEN.to_string())]);
        assert!(audit_rule("fx-green", &green, "NO-KANBAN-BOARD-FIXTURE").is_empty());

        let red = app_tree(vec![("app/hooks.py", HOOKS_RED.to_string())]);
        let got = audit_rule("fx-red", &red, "NO-KANBAN-BOARD-FIXTURE");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].file_path, "app/hooks.py");
        assert_eq!(got[0].line_number, 4);
        assert!(
            got[0].message.contains("Kanban Board"),
            "{}",
            got[0].message
        );
    }

    const ROADMAP_T: &str = "{\n \"doctype\": \"DocType\",\n \"name\": \"Roadmap\",\n \"is_calendar_and_gantt\": 1,\n \"fields\": [\n  {\"fieldname\": \"start_date\", \"fieldtype\": \"Date\"},\n  {\"fieldname\": \"end_date\", \"fieldtype\": \"Date\"}\n ],\n \"permissions\": [{\"role\": \"System Manager\"}]\n}";

    fn roadmap_app(json: &str, controller: bool) -> Vec<(String, String)> {
        let mut v = app_tree(vec![
            ("app/demo/doctype/roadmap/roadmap.json", json.to_string()),
            (
                "app/demo/doctype/roadmap/roadmap.py",
                "class Roadmap:\n\tpass\n".to_string(),
            ),
        ]);
        if controller {
            v.push((
                "app/public/js/roadmap_calendar.js".to_string(),
                "frappe.ui.form.on(\"Roadmap\", {});\n".to_string(),
            ));
        }
        v
    }

    /// MUTATION 1: `end_date` renamed to `closed_date`, a Date whose name does not say it is the
    /// end — the flag now has a span with one side. MUTATION 2: the `_calendar.js` removed.
    #[test]
    fn calendar_and_gantt_needs_both_dates_and_its_controller() {
        assert!(
            audit_rule(
                "cal-green",
                &roadmap_app(ROADMAP_T, true),
                "DOCTYPE-CALENDAR-GANTT-NEEDS-DATES"
            )
            .is_empty()
        );

        let renamed = ROADMAP_T.replace("end_date", "closed_date");
        let got = audit_rule(
            "cal-nodate",
            &roadmap_app(&renamed, true),
            "DOCTYPE-CALENDAR-GANTT-NEEDS-DATES",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].line_number, 4);
        assert!(got[0].message.contains("Roadmap"), "{}", got[0].message);
        assert!(
            got[0].message.contains("no end date field"),
            "{}",
            got[0].message
        );

        let got = audit_rule(
            "cal-nojs",
            &roadmap_app(ROADMAP_T, false),
            "DOCTYPE-CALENDAR-GANTT-NEEDS-DATES",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(
            got[0].message.contains("roadmap_calendar.js"),
            "{}",
            got[0].message
        );
    }

    const BOARD_T: &str = "[\n {\n  \"doctype\": \"Kanban Board\",\n  \"name\": \"Tasks\",\n  \"kanban_board_name\": \"Tasks\",\n  \"reference_doctype\": \"Task\",\n  \"field_name\": \"status\"\n }\n]";
    const SYNC_T: &str = "import json\n\nFILES = (\"number_card.json\", \"kanban_board.json\")\n\n\ndef documents(path):\n\treturn json.loads(path.read_text())\n";

    /// MUTATION: `kanban_board.json` dropped from the sync tuple. The file stays in git and
    /// nothing installs it — the board exists in the repository and never on a site.
    #[test]
    fn board_must_be_installed_by_the_app() {
        let green = app_tree(vec![
            ("app/desk/kanban_board.json", BOARD_T.to_string()),
            ("app/desk_sync.py", SYNC_T.to_string()),
        ]);
        assert!(audit_rule("board-green", &green, "FRAPPE-KANBAN-BOARD-DERIVED").is_empty());

        let dropped = app_tree(vec![
            ("app/desk/kanban_board.json", BOARD_T.to_string()),
            (
                "app/desk_sync.py",
                SYNC_T.replace("\"kanban_board.json\"", "\"dashboard.json\""),
            ),
        ]);
        let got = audit_rule("board-git-only", &dropped, "FRAPPE-KANBAN-BOARD-DERIVED");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].file_path, "app/desk/kanban_board.json");
        assert!(
            got[0].message.contains("nothing installs the board"),
            "{}",
            got[0].message
        );
    }

    /// MUTATION: the test that exercises `boards.py` deleted, and then replaced by a test that
    /// only MENTIONS boards (`dashboards` is not a call). A generator nobody calls is a rule
    /// nobody proves; with the call in place the same tree is green.
    #[test]
    fn board_generator_without_a_test_is_refused() {
        let module = "import json\n\n\ndef boards():\n\treturn {\"name\": \"Tasks\"}\n";
        let green = app_tree(vec![
            ("app/boards.py", module.to_string()),
            (
                "app/tests/kanban_boards.py",
                "from app import boards\n\n\ndef run():\n\tdoc = boards.boards()\n\tassert doc[\"name\"] == \"Tasks\"\n".to_string(),
            ),
        ]);
        assert!(audit_rule("gen-green", &green, "FRAPPE-KANBAN-BOARD-DERIVED").is_empty());

        let red = app_tree(vec![("app/boards.py", module.to_string())]);
        let got = audit_rule("gen-red", &red, "FRAPPE-KANBAN-BOARD-DERIVED");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].file_path, "app/boards.py");
        assert!(
            got[0].message.contains("no test of the app"),
            "{}",
            got[0].message
        );

        // The real app taught this one: two of its tests said "boards" only inside "dashboards"
        // and "offboards", which proves nothing. A mention is not a call.
        let mention = app_tree(vec![
            ("app/boards.py", module.to_string()),
            (
                "app/tests/desk.py",
                "def run():\n\t# dashboards and offboards, no board call\n\tpass\n".to_string(),
            ),
        ]);
        let got = audit_rule("gen-mention", &mention, "FRAPPE-KANBAN-BOARD-DERIVED");
        assert_eq!(got.len(), 1, "a mention is not a call: {got:?}");
    }

    // ── FRAPPE-TEST-PARITY ─────────────────────────────────────────────────
    // The battery exists twice: a document declares the pure modules, the release script runs
    // them. Every test below changes ONE thing in a healthy pair, in both directions — a set
    // compared on one side only still lets the other drift.

    const PARITY_DOC: &str = "## 2. Release rules\n\n1. Tag once.\n   The pure ones (`alpha_pure`, `beta_pure`, `gamma_pure`) also run without a site.\n2. Other rule.\n";

    /// A battery in the shape the release script writes: labels in `names`, one quoted command
    /// per line in `cmds`, both parallel.
    fn battery(labels: &[&str], modules: &[&str]) -> String {
        let cmds: Vec<String> = modules
            .iter()
            .map(|m| format!("  \"python3 -I app/tests/{m}.py\""))
            .collect();
        format!(
            "names=({})\ncmds=(\n{}\n)\n",
            labels.join(" "),
            cmds.join("\n")
        )
    }

    fn parity_cfg() -> FrappeConfig {
        FrappeConfig {
            app: Some("app".into()),
            test_list_file: Some("docs/AGENTS.md".into()),
            test_list_anchor: Some("## 2. Release rules".into()),
            battery_file: Some("scripts/release-checks.sh".into()),
            ..FrappeConfig::default()
        }
    }

    fn parity_tree(doc: &str, script: &str, extra_tests: &[&str]) -> Vec<(String, String)> {
        let mut files = vec![
            ("docs/AGENTS.md".to_string(), doc.to_string()),
            ("scripts/release-checks.sh".to_string(), script.to_string()),
            (
                "app/tests/alpha_pure.py".to_string(),
                "def run():\n\tpass\n".to_string(),
            ),
            (
                "app/tests/beta_pure.py".to_string(),
                "def run():\n\tpass\n".to_string(),
            ),
            (
                "app/tests/gamma_pure.py".to_string(),
                "def run():\n\tpass\n".to_string(),
            ),
        ];
        for m in extra_tests {
            files.push((
                format!("app/tests/{m}.py"),
                "def run():\n\tpass\n".to_string(),
            ));
        }
        app_tree(files.iter().map(|(p, t)| (p.as_str(), t.clone())).collect())
    }

    /// The healthy pair is silent: the document and the battery describe one set.
    #[test]
    fn test_parity_is_silent_when_doc_and_battery_agree() {
        let script = battery(
            &["alpha_pure", "beta_pure", "gamma_pure"],
            &["alpha_pure", "beta_pure", "gamma_pure"],
        );
        let got = audit_rule_with(
            "parity-green",
            &parity_tree(PARITY_DOC, &script, &[]),
            "FRAPPE-TEST-PARITY",
            &parity_cfg(),
        );
        assert!(got.is_empty(), "{got:?}");
    }

    /// MUTATION of the healthy pair, direction 1: `beta_pure` leaves the battery and stays
    /// declared. The finding names the module, the declaration line and the script that skips it.
    #[test]
    fn test_parity_refuses_a_declared_module_the_battery_skips() {
        let script = battery(&["alpha_pure", "gamma_pure"], &["alpha_pure", "gamma_pure"]);
        let got = audit_rule_with(
            "parity-skip",
            &parity_tree(PARITY_DOC, &script, &[]),
            "FRAPPE-TEST-PARITY",
            &parity_cfg(),
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].file_path, "docs/AGENTS.md");
        assert_eq!(got[0].line_number, 4);
        assert_eq!(got[0].severity, Severity::Error);
        assert!(got[0].message.contains("beta_pure"), "{}", got[0].message);
        assert!(
            got[0].message.contains("never runs it"),
            "{}",
            got[0].message
        );
        assert!(
            got[0].message.contains("scripts/release-checks.sh"),
            "{}",
            got[0].message
        );
    }

    /// MUTATION, direction 2: `delta_pure` runs in the battery and nobody declared it.
    #[test]
    fn test_parity_refuses_a_battery_module_nobody_declared() {
        let script = battery(
            &["alpha_pure", "beta_pure", "gamma_pure", "delta_pure"],
            &["alpha_pure", "beta_pure", "gamma_pure", "delta_pure"],
        );
        let got = audit_rule_with(
            "parity-extra",
            &parity_tree(PARITY_DOC, &script, &["delta_pure"]),
            "FRAPPE-TEST-PARITY",
            &parity_cfg(),
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].file_path, "scripts/release-checks.sh");
        assert!(got[0].message.contains("delta_pure"), "{}", got[0].message);
        assert!(
            got[0].message.contains("no pure-test declaration"),
            "{}",
            got[0].message
        );
    }

    /// MUTATION, the incident itself: one command removed from a three-label battery. The arrays
    /// are parallel, so slot 2 would log `gamma_pure` for the command of `beta_pure`.
    #[test]
    fn test_parity_refuses_drifted_parallel_arrays_and_a_mislabelled_slot() {
        let short = battery(
            &["alpha_pure", "beta_pure", "gamma_pure"],
            &["alpha_pure", "beta_pure"],
        );
        let got = audit_rule_with(
            "parity-short",
            &parity_tree(PARITY_DOC, &short, &[]),
            "FRAPPE-TEST-PARITY",
            &parity_cfg(),
        );
        assert!(
            got.iter().any(|v| v.message.contains("are parallel")),
            "{got:?}"
        );

        let swapped = battery(
            &["alpha_pure", "beta_pure", "gamma_pure"],
            &["alpha_pure", "gamma_pure", "beta_pure"],
        );
        let got = audit_rule_with(
            "parity-swap",
            &parity_tree(PARITY_DOC, &swapped, &[]),
            "FRAPPE-TEST-PARITY",
            &parity_cfg(),
        );
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(
            got.iter()
                .all(|v| v.message.contains("drifted out of alignment")),
            "{got:?}"
        );
        assert!(
            got.iter().any(|v| v.message.contains("`beta_pure`")),
            "{got:?}"
        );
    }

    /// A battery slot naming a module the app does not carry fails at release time (or is
    /// skipped by a guard): the label promises a test that is not there.
    #[test]
    fn test_parity_refuses_a_battery_slot_without_its_file() {
        let script = battery(
            &["alpha_pure", "beta_pure", "gamma_pure", "ghost_pure"],
            &["alpha_pure", "beta_pure", "gamma_pure", "ghost_pure"],
        );
        let got = audit_rule_with(
            "parity-ghost",
            &parity_tree(PARITY_DOC, &script, &[]),
            "FRAPPE-TEST-PARITY",
            &parity_cfg(),
        );
        assert!(
            got.iter().any(|v| v.message.contains("is not in the app")),
            "{got:?}"
        );
    }

    /// Neither side present (isolated repo, partial checkout): the rule is inert and SAYS why,
    /// as a Warning — it never fails a tree for the other repository being absent. The tag
    /// carries a `/` so the fixture root sits one level below its own directory and the bounded
    /// discovery cannot see the trees of the tests running in parallel.
    #[test]
    fn test_parity_is_inert_without_the_other_side() {
        let got = audit_rule_with(
            "parity/inert",
            &app_tree(vec![]),
            "FRAPPE-TEST-PARITY",
            &FrappeConfig {
                app: Some("app".into()),
                ..FrappeConfig::default()
            },
        );
        assert!(!got.is_empty(), "an inert rule still says why: {got:?}");
        assert!(
            got.iter().all(|v| v.severity == Severity::Warning),
            "{got:?}"
        );
        assert!(
            got.iter().any(|v| v.message.contains("unverified")),
            "{got:?}"
        );
    }

    // ── FRAPPE-CURRENCY-THRESHOLD-UNSET ────────────────────────────────────
    // `Thing.price` is the only Currency of the tree; `code` is Data and `value` is a local
    // parameter, so the rule has to resolve the name against the DocType JSON to stay quiet.

    const PRICE_JSON: &str = r#"{"doctype":"DocType","name":"Thing","fields":[{"fieldname":"price","fieldtype":"Currency"},{"fieldname":"code","fieldtype":"Data"}],"permissions":[{"role":"System Manager"}]}"#;

    fn price_app(module: &str) -> Vec<(String, String)> {
        app_tree(vec![
            ("app/demo/doctype/thing/thing.json", PRICE_JSON.to_string()),
            (
                "app/demo/doctype/thing/thing.py",
                "class Thing:\n\tpass\n".to_string(),
            ),
            ("app/pricing.py", module.to_string()),
        ])
    }

    /// MUTATION: `flt(doc.price) >= LIMIT` with no branch for an empty amount. The finding names
    /// file:line, the field, the threshold and the missing branch; the same module with the
    /// guard (and the local `amount`, the Data field and the docstring) is silent.
    #[test]
    fn currency_threshold_fires_on_unset_currency_and_names_it() {
        let red = audit_rule(
            "money-red",
            &price_app(PRICING_BAD),
            "FRAPPE-CURRENCY-THRESHOLD-UNSET",
        );
        assert_eq!(red.len(), 1, "{red:?}");
        assert_eq!(red[0].file_path, "app/pricing.py");
        assert_eq!(red[0].line_number, 11);
        assert_eq!(red[0].severity, Severity::Error);
        for needle in [
            "app/pricing.py:11",
            "`price`",
            "LIMIT",
            "empty value needs its own branch",
            "0.0",
        ] {
            assert!(red[0].message.contains(needle), "{}", red[0].message);
        }

        let green = audit_rule(
            "money-green",
            &price_app(PRICING_GOOD),
            "FRAPPE-CURRENCY-THRESHOLD-UNSET",
        );
        assert!(green.is_empty(), "{green:?}");
    }

    /// A bare local parameter, a Data field, a docstring that quotes the comparison and a
    /// zero-test (`x <= 0`, the emptiness branch Frappe's 0.0 makes readable) are not Currency
    /// thresholds: the rule resolves the fieldname against the DocType JSONs.
    #[test]
    fn currency_threshold_ignores_names_that_are_not_currency() {
        let module = "import frappe\nfrom frappe.utils import flt\n\n\ndef rating(value):\n\tif not 1 <= value <= 5:\n\t\tfrappe.throw(\"Rating out of range.\")\n\treturn value\n\n\ndef code_of(doc):\n\treturn (doc.code or 0) >= 1\n\n\ndef positive(doc):\n\treturn flt(doc.price) > 0\n\n\ndef note():\n\t\"\"\"A Decision is strategic when amount >= 250000.\"\"\"\n\treturn None\n";
        let got = audit_rule(
            "money-types",
            &price_app(module),
            "FRAPPE-CURRENCY-THRESHOLD-UNSET",
        );
        assert!(got.is_empty(), "{got:?}");
    }

    /// The mirrored form decides the same way and is accused the same way.
    #[test]
    fn currency_threshold_reads_the_mirrored_comparison() {
        let module = "LIMIT = 250000\n\n\ndef is_large(doc):\n\tif LIMIT <= (doc.price or 0):\n\t\treturn True\n\treturn False\n";
        let got = audit_rule(
            "money-mirror",
            &price_app(module),
            "FRAPPE-CURRENCY-THRESHOLD-UNSET",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].message.contains("`price`"), "{}", got[0].message);
        assert_eq!(got[0].line_number, 5);
    }

    // ── FRAPPE-PERMISSION-SCOPE ────────────────────────────────────────────
    // `Note` is one person's onboarding record: `owner_member` is a Link to `Member` (the field
    // name says nothing, the resolved `options` does) and `Miracena Member` reads AND writes it.
    // The two answers are a registration in hooks.py and a line in permissions-public.txt.
    const NOTE_JSON: &str = "{\n \"doctype\": \"DocType\",\n \"name\": \"Note\",\n \"fields\": [\n  {\"fieldname\": \"title\", \"fieldtype\": \"Data\"},\n  {\"fieldname\": \"owner_member\", \"fieldtype\": \"Link\", \"options\": \"Member\"}\n ],\n \"permissions\": [\n  {\"role\": \"System Manager\", \"read\": 1, \"write\": 1},\n  {\"role\": \"Miracena Member\", \"read\": 1, \"write\": 1}\n ]\n}";
    /// The same DocType, `if_owner` on the broad row: Frappe narrows that row only.
    const NOTE_OWNER_JSON: &str = "{\n \"doctype\": \"DocType\",\n \"name\": \"Note\",\n \"fields\": [\n  {\"fieldname\": \"owner_member\", \"fieldtype\": \"Link\", \"options\": \"Member\"}\n ],\n \"permissions\": [\n  {\"role\": \"Miracena Member\", \"read\": 1, \"write\": 1, \"if_owner\": 1}\n ]\n}";
    /// A catalogue: the broad role is fine because no row belongs to a person.
    const CATALOGUE_JSON: &str = "{\"doctype\":\"DocType\",\"name\":\"Tag\",\"fields\":[{\"fieldname\":\"label\",\"fieldtype\":\"Data\"}],\"permissions\":[{\"role\":\"Miracena Member\",\"read\":1,\"write\":1}]}";
    /// A child table: the permission that decides is the parent's, so the rows are not accused.
    const CHILD_JSON: &str = "{\"doctype\":\"DocType\",\"name\":\"Note Line\",\"istable\":1,\"fields\":[{\"fieldname\":\"assigned_to\",\"fieldtype\":\"Link\",\"options\":\"Member\"}],\"permissions\":[{\"role\":\"Miracena Member\",\"read\":1,\"write\":1}]}";
    /// A Single is one configuration record, not a table of people.
    const SINGLE_JSON: &str = "{\"doctype\":\"DocType\",\"name\":\"Scope Settings\",\"issingle\":1,\"fields\":[{\"fieldname\":\"reviewer\",\"fieldtype\":\"Link\",\"options\":\"User\"}],\"permissions\":[{\"role\":\"Miracena Member\",\"read\":1,\"write\":1}]}";

    const HOOKS_BARE: &str = "app_name = \"app\"\n";
    const HOOKS_QCC: &str = "app_name = \"app\"\npermission_query_conditions = {\n\t\"Note\": \"app.access.note_conditions\",\n}\n";
    const HOOKS_HP: &str = "app_name = \"app\"\nhas_permission = {\n\t**{dt: \"app.access.has_permission\" for dt in (\"Note\", \"Deal\")},\n}\n";
    /// The template Frappe ships in every hooks.py, commented: it registers nothing.
    const HOOKS_COMMENTED: &str = "app_name = \"app\"\n# permission_query_conditions = {\n# \t\"Note\": \"app.access.note_conditions\",\n# }\nhas_permission = {\n\t\"Deal\": \"app.access.has_permission\",\n}\n";

    /// A one-DocType app; `extra` adds the hooks block, the allowlist or a sibling DocType.
    fn scope_app(json: &str, hooks: &str, extra: Vec<(String, String)>) -> Vec<(String, String)> {
        let mut v = vec![
            (
                "app/demo/doctype/note/note.json".to_string(),
                json.to_string(),
            ),
            (
                "app/demo/doctype/note/note.py".to_string(),
                "class Note:\n\tpass\n".to_string(),
            ),
            ("app/hooks.py".to_string(), hooks.to_string()),
        ];
        v.extend(extra);
        v
    }

    /// (a) The leak: 1 ERROR naming the DocType, the person field, the broad role, the operations
    /// and the way out. The `snippet` carries the two facts that make it a finding.
    #[test]
    fn permission_scope_flags_a_person_doctype_with_a_broad_role() {
        let got = audit_rule(
            "scope-leak",
            &scope_app(NOTE_JSON, HOOKS_BARE, vec![]),
            "FRAPPE-PERMISSION-SCOPE",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].file_path, "app/demo/doctype/note/note.json");
        assert_eq!(
            got[0].line_number, 10,
            "the permission row of the broad role"
        );
        assert_eq!(got[0].severity, Severity::Error);
        for needle in [
            "`Note`",
            "`owner_member`",
            "Link to Member",
            "`Miracena Member`",
            "read and write",
            "permission_query_conditions",
            "permissions-public.txt",
        ] {
            assert!(got[0].message.contains(needle), "{}", got[0].message);
        }
        assert!(
            got[0]
                .suggestion
                .as_deref()
                .unwrap_or("")
                .contains("has_permission[\"Note\"]"),
            "{:?}",
            got[0].suggestion
        );
    }

    /// (b) A registered scope silences the rule in either shape — a literal key and the spread
    /// comprehension — and a registration for ANOTHER DocType does not. A commented template and
    /// `if_owner` (f) do not either.
    #[test]
    fn permission_scope_goes_quiet_on_a_registration_and_only_on_that_doctype() {
        assert!(
            audit_rule(
                "scope-qcc",
                &scope_app(NOTE_JSON, HOOKS_QCC, vec![]),
                "FRAPPE-PERMISSION-SCOPE"
            )
            .is_empty()
        );
        assert!(
            audit_rule(
                "scope-hp",
                &scope_app(NOTE_JSON, HOOKS_HP, vec![]),
                "FRAPPE-PERMISSION-SCOPE"
            )
            .is_empty()
        );
        let commented = audit_rule(
            "scope-commented",
            &scope_app(NOTE_JSON, HOOKS_COMMENTED, vec![]),
            "FRAPPE-PERMISSION-SCOPE",
        );
        assert_eq!(
            commented.len(),
            1,
            "a commented dict registers nothing: {commented:?}"
        );
    }

    /// (c) The allowlist is data: a tolerant line (`Note   # reason`, blank lines, comments)
    /// silence it, and the presence of the FILE alone does not — another DocType's line leaves
    /// this one accused.
    #[test]
    fn permission_scope_reads_the_allowlist_as_data() {
        let allowed = vec![(
            "permissions-public.txt".to_string(),
            "# catalogues the whole team reads\n\n  Note   # the onboarding checklist is public by design\n\n".to_string(),
        )];
        assert!(
            audit_rule(
                "scope-public",
                &scope_app(NOTE_JSON, HOOKS_BARE, allowed),
                "FRAPPE-PERMISSION-SCOPE"
            )
            .is_empty()
        );

        let other = vec![(
            "permissions-public.txt".to_string(),
            "Tag # only the catalogue\n".to_string(),
        )];
        let got = audit_rule(
            "scope-other",
            &scope_app(NOTE_JSON, HOOKS_BARE, other),
            "FRAPPE-PERMISSION-SCOPE",
        );
        assert_eq!(got.len(), 1, "{got:?}");

        // A DocType name carries spaces (`Studio Space`): the line is the name up to the `#`, not
        // its first word, so this entry silences `Note Space` and leaves `Note` accused.
        let spaced = vec![
            (
                "app/demo/doctype/note_space/note_space.json".to_string(),
                NOTE_JSON.replace("\"name\": \"Note\"", "\"name\": \"Note Space\""),
            ),
            (
                "app/demo/doctype/note_space/note_space.py".to_string(),
                "class NoteSpace:\n\tpass\n".to_string(),
            ),
            (
                "permissions-public.txt".to_string(),
                "Note Space   # a catalogue of rooms the whole team books\n".to_string(),
            ),
        ];
        let got = audit_rule(
            "scope-spaced",
            &scope_app(NOTE_JSON, HOOKS_BARE, spaced),
            "FRAPPE-PERMISSION-SCOPE",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].message.contains("`Note`"), "{}", got[0].message);
    }

    /// (d) A catalogue with no person field and (e) a child table and a Single are never accused.
    #[test]
    fn permission_scope_ignores_catalogues_children_and_singles() {
        let catalogue = vec![
            (
                "app/demo/doctype/tag/tag.json".to_string(),
                CATALOGUE_JSON.to_string(),
            ),
            (
                "app/demo/doctype/tag/tag.py".to_string(),
                "class Tag:\n\tpass\n".to_string(),
            ),
            (
                "app/demo/doctype/note_line/note_line.json".to_string(),
                CHILD_JSON.to_string(),
            ),
            (
                "app/demo/doctype/note_line/note_line.py".to_string(),
                "class NoteLine:\n\tpass\n".to_string(),
            ),
            (
                "app/demo/doctype/scope_settings/scope_settings.json".to_string(),
                SINGLE_JSON.to_string(),
            ),
            (
                "app/demo/doctype/scope_settings/scope_settings.py".to_string(),
                "class ScopeSettings:\n\tpass\n".to_string(),
            ),
        ];
        let got = audit_rule(
            "scope-shapes",
            &scope_app(NOTE_JSON, HOOKS_BARE, catalogue),
            "FRAPPE-PERMISSION-SCOPE",
        );
        assert_eq!(
            got.len(),
            1,
            "only `Note` is a parent table about people: {got:?}"
        );
        assert!(got[0].message.contains("`Note`"), "{}", got[0].message);
    }

    /// (f) `if_owner` does not silence the rule: it narrows the row that declares it, and the
    /// finding says so. Two rows of the same role are also two findings, each on its own line.
    #[test]
    fn permission_scope_does_not_accept_if_owner_as_a_scope() {
        let got = audit_rule(
            "scope-if-owner",
            &scope_app(NOTE_OWNER_JSON, HOOKS_BARE, vec![]),
            "FRAPPE-PERMISSION-SCOPE",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].line_number, 8, "the role row, not the field");
        assert!(got[0].message.contains("`if_owner`"), "{}", got[0].message);
        assert!(
            got[0].message.contains("another broad row"),
            "{}",
            got[0].message
        );

        let two_rows = "{\n \"doctype\": \"DocType\",\n \"name\": \"Note\",\n \"fields\": [\n  {\"fieldname\": \"member\", \"fieldtype\": \"Link\", \"options\": \"Member\"}\n ],\n \"permissions\": [\n  {\"role\": \"Miracena Member\", \"read\": 1, \"write\": 1},\n  {\"role\": \"Miracena Member\", \"read\": 1, \"if_owner\": 1}\n ]\n}";
        let got = audit_rule(
            "scope-two-rows",
            &scope_app(two_rows, HOOKS_BARE, vec![]),
            "FRAPPE-PERMISSION-SCOPE",
        );
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(
            got.iter().map(|v| v.line_number).collect::<Vec<usize>>(),
            vec![8, 9],
            "each finding points at its own row"
        );
    }

    // ── FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE (GB-142) ────────────────
    // The publisher in the shape the app has it: a file of the package, read inside `execute()`,
    // written into a Single's long-text field. Line 9 is the write the finding points at.
    const PUBLISHER_T: &str = "import frappe\nfrom pathlib import Path\n\nDOCS = Path(__file__).resolve().parents[1] / \"docs\"\n\n\ndef execute():\n\tbody = (DOCS / \"manual.html\").read_text(encoding=\"utf-8\")\n\tfrappe.db.set_single_value(\"Handbook\", \"content\", body)\n";
    /// The same field, migrated once and never from a file: a data patch, not a publisher.
    const MIGRATOR_T: &str = "import frappe\n\n\ndef execute():\n\tfrappe.db.set_value(\"Handbook\", \"Handbook\", \"content\", \"cleaned\")\n";
    /// Reads a file and writes a record, but no long-text field: a chart/board installer.
    const INSTALLER_T: &str = "import json\nfrom pathlib import Path\n\nDESK = Path(__file__).resolve().parent / \"desk\"\n\n\ndef execute():\n\tfrappe.db.set_value(\"Dashboard Chart\", \"Deals by Stage\", \"chart_type\", json.loads((DESK / \"chart.json\").read_text())[\"chart_type\"])\n";
    const HOOKS_ONE_SHOT: &str = "app_name = \"app\"\n";
    /// The same registration over three lines: the layout Frappe itself ships.
    const HOOKS_REPUBLISHED: &str =
        "app_name = \"app\"\nafter_migrate = [\n\t\"app.patches.publisher.execute\",\n]\n";

    /// A one-patch app: the module, the file it publishes and the hooks. `listed` decides whether
    /// the patch is also in `patches.txt` (the one-shot ledger the rule is about).
    fn publish_app(module: &str, hooks: &str, listed: bool) -> Vec<(String, String)> {
        let mut v = vec![
            (
                "app/__init__.py".to_string(),
                "__version__ = \"0.1.0\"\n".to_string(),
            ),
            ("app/hooks.py".to_string(), hooks.to_string()),
            ("app/patches/__init__.py".to_string(), String::new()),
            ("app/patches/publisher.py".to_string(), module.to_string()),
            (
                "app/docs/manual.html".to_string(),
                "<p>edition one</p>\n".to_string(),
            ),
        ];
        if listed {
            v.push((
                "app/patches.txt".to_string(),
                "[post_model_sync]\napp.patches.publisher\n".to_string(),
            ));
        }
        v
    }

    /// (a) The incident, statically: the publisher is in `patches.txt` and nowhere else. One ERROR
    /// naming the patch, the file, the DocType, the field and the consequence the release met.
    #[test]
    fn published_content_is_refused_when_the_patch_is_the_only_registration() {
        let got = audit_rule(
            "publish-a",
            &publish_app(PUBLISHER_T, HOOKS_ONE_SHOT, true),
            "FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].file_path, "app/patches/publisher.py");
        assert_eq!(got[0].line_number, 9, "the write, not the import");
        assert_eq!(got[0].severity, Severity::Error);
        for needle in [
            "`publisher`",
            "`manual.html`",
            "`Handbook`",
            "`content`",
            "`app/patches.txt`:2",
            "runs a patch once",
            "second edition of the document never reaches the site",
        ] {
            assert!(got[0].message.contains(needle), "{}", got[0].message);
        }
        assert!(
            got[0]
                .suggestion
                .as_deref()
                .unwrap_or("")
                .contains("after_migrate"),
            "{:?}",
            got[0].suggestion
        );
    }

    /// (b) The fix: the same module registered in `after_migrate` is republished by every migrate,
    /// so the rule is silent — over one line or three.
    #[test]
    fn published_content_is_silent_when_the_module_runs_on_every_migrate() {
        assert!(
            audit_rule(
                "publish-b",
                &publish_app(PUBLISHER_T, HOOKS_REPUBLISHED, true),
                "FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE"
            )
            .is_empty()
        );
        let one_line = "app_name = \"app\"\nafter_migrate = [\"app.patches.publisher\"]\n";
        assert!(
            audit_rule(
                "publish-b-flat",
                &publish_app(PUBLISHER_T, one_line, true),
                "FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE"
            )
            .is_empty()
        );
    }

    /// (c) A patch that migrates a field and reads no file of the image is not a publisher; (d) a
    /// module registered in `after_migrate` but absent from `patches.txt` has nothing to compare
    /// against; and a file-reading installer that writes no long-text field is left alone — the
    /// rule would rather miss than accuse a tree that is fine.
    #[test]
    fn published_content_ignores_data_patches_installers_and_a_registration_alone() {
        for (tag, module, listed, hooks) in [
            ("publish-c", MIGRATOR_T, true, HOOKS_ONE_SHOT),
            ("publish-c-installer", INSTALLER_T, true, HOOKS_ONE_SHOT),
            ("publish-d", PUBLISHER_T, false, HOOKS_REPUBLISHED),
        ] {
            let got = audit_rule(
                tag,
                &publish_app(module, hooks, listed),
                "FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE",
            );
            assert!(got.is_empty(), "{tag}: {got:?}");
        }
    }

    /// A commented `after_migrate` template registers nothing, exactly as Frappe reads it, and the
    /// publisher stays accused.
    #[test]
    fn published_content_reads_no_registration_out_of_a_comment() {
        let commented =
            "app_name = \"app\"\n# after_migrate = [\"app.patches.publisher.execute\"]\n";
        let got = audit_rule(
            "publish-comment",
            &publish_app(PUBLISHER_T, commented, true),
            "FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE",
        );
        assert_eq!(got.len(), 1, "{got:?}");
    }

    #[test]
    fn after_migrate_paths_reads_the_layouts_hooks_use() {
        assert_eq!(
            after_migrate_paths("app_name = \"app\"\nafter_migrate = [\"a.b.c\"]\n"),
            vec!["a.b.c".to_string()]
        );
        assert_eq!(
            after_migrate_paths("after_migrate = [\n\t\"a.b\",\n\t\"a.c\",\n]\n"),
            vec!["a.b".to_string(), "a.c".to_string()]
        );
        assert_eq!(
            after_migrate_paths("after_migrate += (\"a.b\",)\n"),
            vec!["a.b".to_string()]
        );
        assert!(after_migrate_paths("app_name = \"app\"\n").is_empty());
        assert!(
            after_migrate_paths("after_migrate_backup = [\"a.b\"]\n").is_empty(),
            "a different hook name is not the hook"
        );
    }

    // ── FRAPPE-FETCH-PARITY (GB-241) ───────────────────────────────────────
    fn member_json(role: &str) -> String {
        format!(
            "{{\"doctype\":\"DocType\",\"name\":\"Squad Member\",\"istable\":1,\"fields\":[{{\"fieldname\":\"member\",\"fieldtype\":\"Link\",\"options\":\"Member\"}},{role}],\"permissions\":[]}}"
        )
    }

    fn fetch_audit(tag: &str, json: &str, entry: FetchParity) -> Vec<Violation> {
        let files = app_tree(vec![(
            "app/m/doctype/squad_member/squad_member.json",
            json.to_string(),
        )]);
        let cfg = FrappeConfig {
            app: Some("app".into()),
            fetch_parity: Some(vec![entry]),
            ..FrappeConfig::default()
        };
        audit_rule_with(tag, &files, "FRAPPE-FETCH-PARITY", &cfg)
    }

    fn role_entry() -> FetchParity {
        FetchParity {
            doctype_pattern: "*_member".into(),
            field: "role".into(),
            fetch_from: "member.role".into(),
            fetch_if_empty: None,
        }
    }

    #[test]
    fn fetch_parity_green_and_red() {
        let ok = "{\"fieldname\":\"role\",\"fieldtype\":\"Data\",\"fetch_from\":\"member.role\",\"fetch_if_empty\":1}";
        assert!(fetch_audit("fp-ok", &member_json(ok), role_entry()).is_empty());
        let no_fetch = "{\"fieldname\":\"role\",\"fieldtype\":\"Data\",\"fetch_if_empty\":1}";
        assert_eq!(
            fetch_audit("fp-nf", &member_json(no_fetch), role_entry()).len(),
            1
        );
        let no_empty =
            "{\"fieldname\":\"role\",\"fieldtype\":\"Data\",\"fetch_from\":\"member.role\"}";
        assert_eq!(
            fetch_audit("fp-ne", &member_json(no_empty), role_entry()).len(),
            1
        );
        let wrong = "{\"fieldname\":\"role\",\"fieldtype\":\"Data\",\"fetch_from\":\"member.title\",\"fetch_if_empty\":1}";
        assert_eq!(
            fetch_audit("fp-w", &member_json(wrong), role_entry()).len(),
            1
        );
        let missing = "{\"fieldname\":\"note\",\"fieldtype\":\"Data\"}";
        assert_eq!(
            fetch_audit("fp-m", &member_json(missing), role_entry()).len(),
            1
        );
    }

    #[test]
    fn fetch_parity_is_config_driven() {
        let no_empty =
            "{\"fieldname\":\"role\",\"fieldtype\":\"Data\",\"fetch_from\":\"member.role\"}";
        // fetch_if_empty = false in the entry relaxes only that requirement
        let relaxed = FetchParity {
            fetch_if_empty: Some(false),
            ..role_entry()
        };
        assert!(fetch_audit("fp-r", &member_json(no_empty), relaxed).is_empty());
        // a pattern that does not match the DocType leaves it alone
        let other = FetchParity {
            doctype_pattern: "*_seat".into(),
            ..role_entry()
        };
        assert!(
            fetch_audit(
                "fp-o",
                &member_json("{\"fieldname\":\"x\",\"fieldtype\":\"Data\"}"),
                other
            )
            .is_empty()
        );
        // no [[frappe.fetch_parity]] table at all: silent
        let files = app_tree(vec![(
            "app/m/doctype/squad_member/squad_member.json",
            member_json("{\"fieldname\":\"x\",\"fieldtype\":\"Data\"}"),
        )]);
        assert!(audit_rule("fp-none", &files, "FRAPPE-FETCH-PARITY").is_empty());
    }
}
