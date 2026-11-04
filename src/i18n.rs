//! `I18N-PO-INCOMPLETE`: deterministic completeness audit of gettext catalogues.
//!
//! WHY IT EXISTS (2026-11-03): a Frappe/ERPNext application ships its own
//! `locale/*.po` files, and the UI text that is missing from them (or present with an
//! empty `msgstr`) silently appears in English. Fixing such strings one by one, as
//! the users find them, is not a quality gate. This module makes the check
//! deterministic and fails the build/gate on:
//!
//! 1. a non-header, non-obsolete entry with an empty `msgstr` (plural forms
//!    included) or marked `fuzzy` (a fuzzy entry is not used at run time);
//! 2. a static literal passed to `_()`, `__()`, `_lt()` or a Jinja `{% trans %}`
//!    block, in the project sources, that is not a `msgid` of any catalogue of the
//!    project (the context of `context=` / the third JS argument is part of the key);
//! 3. printf/brace placeholders (`{0}`, `%s`, `%(name)s`) that differ between
//!    `msgid` and `msgstr`.
//!
//! There is deliberately no suppression directive for this rule: the violations
//! are produced here and never go through the whitelist.
//!
//! References: GNU gettext manual, "The Format of PO Files" (entries, `msgctxt`,
//! `msgid_plural`, `msgstr[N]`, `#, fuzzy`, `#~` obsolete entries, the header entry
//! with an empty `msgid`).

use ignore::WalkBuilder;
use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::Violation;
use crate::rule::Severity;

pub const RULE_ID: &str = "I18N-PO-INCOMPLETE";
pub const CASE_RULE_ID: &str = "I18N-CASE";
const RULE_NAME: &str = "Gettext Catalogue Incomplete";
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Directories never walked (vendored code, build output, caches, sync history).
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
    ".tox",
    "site-packages",
];

/// Source extensions that may contain translatable literals.
const SOURCE_EXTENSIONS: &[&str] = &["py", "js", "ts", "vue", "html", "jinja", "jinja2"];

/// `(context, msgid)`; the context is empty when the entry has no `msgctxt`.
pub type CatalogueKey = (String, String);

#[derive(Debug, Default)]
pub struct I18nReport {
    pub violations: Vec<Violation>,
    pub catalogues: usize,
    pub entries_checked: usize,
    pub literals_checked: usize,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PoEntry {
    pub(crate) ctx: Option<String>,
    pub(crate) msgid: String,
    pub(crate) plural: Option<String>,
    pub(crate) strs: Vec<String>,
    pub(crate) fuzzy: bool,
    pub(crate) obsolete: bool,
    pub(crate) line: usize,
    pub(crate) has_id: bool,
}

#[derive(Clone, Copy)]
enum Field {
    Ctx,
    Id,
    Plural,
    Str(usize),
    None,
}

fn unquote(raw: &str) -> String {
    let t = raw.trim();
    let inner = t
        .strip_prefix('"')
        .map(|s| s.strip_suffix('"').unwrap_or(s))
        .unwrap_or(t);
    unescape(inner)
}

fn unescape(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
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

fn append(entry: &mut PoEntry, field: Field, text: &str) {
    match field {
        Field::Ctx => entry.ctx.get_or_insert_with(String::new).push_str(text),
        Field::Id => entry.msgid.push_str(text),
        Field::Plural => entry.plural.get_or_insert_with(String::new).push_str(text),
        Field::Str(n) => {
            if entry.strs.len() <= n {
                entry.strs.resize(n + 1, String::new());
            }
            entry.strs[n].push_str(text);
        }
        Field::None => {}
    }
}

pub(crate) fn parse_po(text: &str) -> Vec<PoEntry> {
    let mut entries = Vec::new();
    let mut cur = PoEntry::default();
    let mut field = Field::None;
    let finish = |cur: &mut PoEntry, entries: &mut Vec<PoEntry>| {
        let done = std::mem::take(cur);
        if done.has_id {
            entries.push(done);
        }
    };

    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            finish(&mut cur, &mut entries);
            field = Field::None;
        } else if line.starts_with("#~") {
            cur.obsolete = true;
        } else if let Some(flags) = line.strip_prefix("#,") {
            if flags.contains("fuzzy") {
                cur.fuzzy = true;
            }
        } else if line.starts_with('#') {
            // translator/extracted/reference comments carry nothing to check
        } else if let Some(rest) = line.strip_prefix("msgctxt ") {
            if cur.has_id || cur.ctx.is_some() {
                finish(&mut cur, &mut entries);
            }
            field = Field::Ctx;
            append(&mut cur, field, &unquote(rest));
        } else if let Some(rest) = line.strip_prefix("msgid_plural ") {
            field = Field::Plural;
            append(&mut cur, field, &unquote(rest));
        } else if let Some(rest) = line.strip_prefix("msgid ") {
            if cur.has_id {
                finish(&mut cur, &mut entries);
            }
            cur.has_id = true;
            cur.line = idx + 1;
            field = Field::Id;
            append(&mut cur, field, &unquote(rest));
        } else if let Some(rest) = line.strip_prefix("msgstr[") {
            let (num, tail) = rest.split_once(']').unwrap_or((rest, ""));
            let n = num.trim().parse::<usize>().unwrap_or(0);
            field = Field::Str(n);
            append(&mut cur, field, &unquote(tail));
        } else if let Some(rest) = line.strip_prefix("msgstr ") {
            field = Field::Str(0);
            append(&mut cur, field, &unquote(rest));
        } else if line.starts_with('"') {
            append(&mut cur, field, &unquote(line));
        }
    }
    finish(&mut cur, &mut entries);
    entries
}

/// Sorted placeholders of a string. `%%` is a literal percent sign.
fn placeholders(re: &Regex, s: &str) -> Vec<String> {
    let cleaned = s.replace("%%", "");
    let mut found: Vec<String> = re
        .find_iter(&cleaned)
        .map(|m| m.as_str().to_string())
        .collect();
    found.sort();
    found
}

fn placeholder_regex() -> Option<Regex> {
    Regex::new(r"%\([A-Za-z_][A-Za-z0-9_]*\)[sdifrx]|%[sdif]|\{[A-Za-z0-9_.]*\}").ok()
}

fn snippet(s: &str) -> String {
    let flat: String = s.chars().take(100).collect();
    flat.replace('\n', "\\n")
}

fn violation(path: &str, line: usize, snip: &str, message: String, hint: &str) -> Violation {
    Violation {
        rule_id: RULE_ID.to_string(),
        rule_name: RULE_NAME.to_string(),
        severity: Severity::Error,
        file_path: path.to_string(),
        line_number: line,
        snippet: snippet(snip),
        message,
        suggestion: Some(hint.to_string()),
    }
}

/// Checks one catalogue (rules 1 and 3) and returns its message keys (for rule 2).
pub fn audit_catalogue(display_path: &str, text: &str) -> (Vec<Violation>, HashSet<CatalogueKey>) {
    let mut violations = Vec::new();
    let mut keys = HashSet::new();
    let ph = placeholder_regex();
    for e in parse_po(text) {
        if e.obsolete || (e.msgid.is_empty() && e.ctx.is_none()) {
            continue; // obsolete (#~) entries and the header entry are not messages
        }
        keys.insert((e.ctx.clone().unwrap_or_default(), e.msgid.clone()));
        if e.msgid.trim().is_empty() {
            continue;
        }
        if e.fuzzy {
            violations.push(violation(
                display_path,
                e.line,
                &e.msgid,
                "Fuzzy entry: gettext does not use it at run time, so the text shows in English."
                    .to_string(),
                "Review the translation and remove the `#, fuzzy` flag.",
            ));
            continue;
        }
        let forms = e.strs.len().max(1);
        let empty: Vec<usize> = (0..forms)
            .filter(|i| e.strs.get(*i).map(|s| s.trim().is_empty()).unwrap_or(true))
            .collect();
        if !empty.is_empty() {
            violations.push(violation(
                display_path,
                e.line,
                &e.msgid,
                format!(
                    "Empty msgstr{} for this message: the text shows in English.",
                    if e.plural.is_some() {
                        format!(" in plural form(s) {:?}", empty)
                    } else {
                        String::new()
                    }
                ),
                "Translate it (copy the msgid only when it is a symbol, code or URL).",
            ));
            continue;
        }
        if e.plural.is_none() {
            for problem in crate::frappe::case_problems(
                &e.msgid,
                e.strs.first().map(String::as_str).unwrap_or(""),
            ) {
                let mut v = violation(
                    display_path,
                    e.line,
                    &e.msgid,
                    format!("Capitalisation: {problem}."),
                    "Match the source: an uppercase first letter stays uppercase, and a Title Case label (2 to 6 words) keeps Title Case except small words.",
                );
                v.rule_id = CASE_RULE_ID.to_string();
                v.rule_name = "Translation Capitalisation".to_string();
                violations.push(v);
            }
        }
        if let Some(re) = ph.as_ref() {
            let source = placeholders(re, &e.msgid);
            let plural_source = e.plural.as_deref().map(|p| placeholders(re, p));
            for (i, translated) in e.strs.iter().enumerate() {
                let got = placeholders(re, translated);
                let bad = match (&plural_source, i) {
                    (Some(_), 0) => false, // singular form may drop the number
                    (Some(p), _) => !same_set(p, &got),
                    (None, _) => source != got,
                };
                if bad {
                    violations.push(violation(
                        display_path,
                        e.line,
                        &e.msgid,
                        format!(
                            "Placeholders differ between msgid {:?} and msgstr {:?}.",
                            source, got
                        ),
                        "Keep every {0}, %s and %(name)s exactly as in the msgid.",
                    ));
                    break;
                }
            }
        }
    }
    (violations, keys)
}

fn same_set(a: &[String], b: &[String]) -> bool {
    let sa: HashSet<&String> = a.iter().collect();
    let sb: HashSet<&String> = b.iter().collect();
    sa == sb
}

/// A static literal found in a source file.
#[derive(Debug, PartialEq, Eq)]
struct Literal {
    line: usize,
    key: CatalogueKey,
}

fn extract_literals(text: &str) -> Vec<Literal> {
    let mut out = Vec::new();
    let Ok(call) = Regex::new(
        r#"(?:^|[^\w$])(?:__|_lt|_)\(\s*(?:"((?:\\.|[^"\\\n])*)"|'((?:\\.|[^'\\\n])*)')"#,
    ) else {
        return out;
    };
    let ctx_py = Regex::new(r#"^\s*,[^)]*?\bcontext\s*=\s*(?:"([^"]*)"|'([^']*)')"#).ok();
    let ctx_js = Regex::new(
        r#"^\s*,\s*(?:null|undefined|\[[^\]]*\]|\{[^}]*\}|[\w.]+)\s*,\s*(?:"([^"]*)"|'([^']*)')"#,
    )
    .ok();
    for caps in call.captures_iter(text) {
        let (Some(whole), lit) = (caps.get(0), caps.get(1).or_else(|| caps.get(2))) else {
            continue;
        };
        let Some(lit) = lit else { continue };
        let tail = &text[whole.end()..];
        let after: String = tail.chars().take(160).collect();
        let next = after.trim_start().chars().next();
        if !matches!(next, Some(',') | Some(')')) {
            continue; // concatenation, % formatting or another expression: not a static literal
        }
        let msgid = unescape(lit.as_str());
        if !msgid.chars().any(|c| c.is_alphabetic()) {
            continue; // symbols, numbers and bare placeholders need no translation
        }
        let pick = |re: &Option<Regex>| -> Option<String> {
            let m = re.as_ref()?.captures(&after)?;
            m.get(1)
                .or_else(|| m.get(2))
                .map(|g| g.as_str().to_string())
        };
        let ctx = pick(&ctx_py).or_else(|| pick(&ctx_js)).unwrap_or_default();
        let line = text[..lit.start()].matches('\n').count() + 1;
        out.push(Literal {
            line,
            key: (ctx, msgid),
        });
    }
    if let Ok(trans) = Regex::new(r"(?s)\{%-?\s*trans\s*-?%\}(.*?)\{%-?\s*endtrans\s*-?%\}") {
        for caps in trans.captures_iter(text) {
            let (Some(whole), Some(body)) = (caps.get(0), caps.get(1)) else {
                continue;
            };
            let msgid = body.as_str().trim();
            if msgid.contains("{{") || msgid.contains("{%") {
                continue;
            }
            if msgid.chars().any(|c| c.is_alphabetic()) {
                out.push(Literal {
                    line: text[..whole.start()].matches('\n').count() + 1,
                    key: (String::new(), msgid.to_string()),
                });
            }
        }
    }
    out
}

/// Checks one source file against the catalogue keys of its project (rule 2).
pub fn audit_source_text(
    display_path: &str,
    text: &str,
    catalogue: &HashSet<CatalogueKey>,
) -> Vec<Violation> {
    extract_literals(text)
        .into_iter()
        .filter(|l| !catalogue.contains(&l.key))
        .map(|l| {
            let with_ctx = if l.key.0.is_empty() {
                String::new()
            } else {
                format!(" (context {:?})", l.key.0)
            };
            violation(
                display_path,
                l.line,
                &l.key.1,
                format!(
                    "Translatable string{} is not in any .po catalogue of the project.",
                    with_ctx
                ),
                "Add the msgid (with its msgctxt, if any) to locale/<lang>.po and translate it.",
            )
        })
        .collect()
}

fn is_test_path(rel: &Path) -> bool {
    let in_test_dir = rel.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("tests") | Some("test") | Some("__tests__")
        )
    });
    let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");
    in_test_dir
        || name.starts_with("test_")
        || name.ends_with("_test.py")
        || name.ends_with(".test.js")
        || name.ends_with(".spec.js")
        || name.ends_with(".min.js")
}

/// The project root of a catalogue is the parent of its nearest `locale` directory.
fn project_root(po: &Path) -> Option<PathBuf> {
    po.ancestors()
        .skip(1)
        .find(|a| a.file_name().and_then(|n| n.to_str()) == Some("locale"))
        .and_then(|locale| locale.parent())
        .map(Path::to_path_buf)
}

fn read_small(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > MAX_FILE_BYTES {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

/// Audits every gettext project under `root` (a project is a `locale/` directory
/// holding `.po` files plus the sources next to it).
pub fn audit_gettext(root: &Path) -> I18nReport {
    let mut report = I18nReport::default();
    let mut po_files: Vec<PathBuf> = Vec::new();
    let mut sources: Vec<PathBuf> = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .require_git(false)
        .filter_entry(|e| {
            e.file_name()
                .to_str()
                .map(|n| !SKIP_DIRS.contains(&n))
                .unwrap_or(true)
        })
        .build();
    for entry in walker.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "po" && project_root(path).is_some() {
            po_files.push(path.to_path_buf());
        } else if SOURCE_EXTENSIONS.contains(&ext) {
            sources.push(path.to_path_buf());
        }
    }
    if po_files.is_empty() {
        return report;
    }

    let mut projects: BTreeMap<PathBuf, HashSet<CatalogueKey>> = BTreeMap::new();
    for po in &po_files {
        let (Some(proj), Some(text)) = (project_root(po), read_small(po)) else {
            continue;
        };
        report.catalogues += 1;
        let (found, keys) = audit_catalogue(&relative(root, po), &text);
        report.entries_checked += keys.len();
        report.violations.extend(found);
        projects.entry(proj).or_default().extend(keys);
    }

    for src in sources {
        // the deepest project that contains the file owns it
        let owner = projects
            .keys()
            .filter(|p| src.starts_with(p))
            .max_by_key(|p| p.components().count());
        let Some(owner) = owner else { continue };
        let rel_to_project = src.strip_prefix(owner).unwrap_or(&src);
        if is_test_path(rel_to_project)
            || rel_to_project
                .components()
                .any(|c| c.as_os_str().to_str() == Some("locale"))
        {
            continue;
        }
        let (Some(catalogue), Some(text)) = (projects.get(owner), read_small(&src)) else {
            continue;
        };
        let found = audit_source_text(&relative(root, &src), &text, catalogue);
        report.literals_checked += extract_literals(&text).len();
        report.violations.extend(found);
    }
    report
}

/// Synthetic cases for `stenio --self-test`: `(name, passed)`.
pub fn self_test_cases() -> Vec<(&'static str, bool)> {
    let bad_po = "msgid \"\"\nmsgstr \"\"\n\"Plural-Forms: nplurals=2; plural=(n != 1);\\n\"\n\n\
        msgid \"Save\"\nmsgstr \"\"\n\n\
        #, fuzzy\nmsgid \"Cancel\"\nmsgstr \"Cancelar\"\n\n\
        msgid \"Hello {0}\"\nmsgstr \"Olá\"\n\n\
        msgid \"One day\"\nmsgid_plural \"{0} days\"\nmsgstr[0] \"Um dia\"\nmsgstr[1] \"\"\n";
    let good_po = "msgid \"\"\nmsgstr \"\"\n\"Plural-Forms: nplurals=2; plural=(n != 1);\\n\"\n\n\
        msgid \"Save\"\nmsgstr \"Salvar\"\n\n\
        msgctxt \"email\"\nmsgid \"Open\"\nmsgstr \"Abrir\"\n\n\
        msgid \"Hello {0}\"\nmsgstr \"Olá, {0}\"\n\n\
        msgid \"One day\"\nmsgid_plural \"{0} days\"\nmsgstr[0] \"Um dia\"\nmsgstr[1] \"{0} dias\"\n\n\
        #~ msgid \"Old\"\n#~ msgstr \"\"\n";
    let source = "a = _(\"Save\")\nb = _(\"Open\", context=\"email\")\nc = _(\"Brand new\")\n\
        d = _(f\"x {y}\")\ne = _(name)\nf = _(\"Hello {0}\").format(n)\ng = _(\"Open\")\n";

    let case_bad_po = "msgid \"Save\"\nmsgstr \"salvar\"\n\nmsgid \"Open Door Sign\"\nmsgstr \"Placa de porta aberta\"\n";
    let case_good_po = "msgid \"Save\"\nmsgstr \"Salvar\"\n\nmsgid \"Open Door Sign\"\nmsgstr \"Placa de Porta Aberta\"\n\nmsgid \"Open the door\"\nmsgstr \"Abrir a porta\"\n";
    let (case_bad, _) = audit_catalogue("fixture/case-bad.po", case_bad_po);
    let (case_good, _) = audit_catalogue("fixture/case-good.po", case_good_po);
    let (bad, _) = audit_catalogue("fixture/bad.po", bad_po);
    let (good, keys) = audit_catalogue("fixture/good.po", good_po);
    let missing: Vec<String> = audit_source_text("fixture/app.py", source, &keys)
        .into_iter()
        .map(|v| format!("{}:{}", v.line_number, v.snippet))
        .collect();
    vec![
        (
            "Empty/fuzzy/placeholder",
            bad.len() == 4 && bad.iter().all(|v| v.rule_id == RULE_ID),
        ),
        ("Complete catalogue", good.is_empty()),
        (
            "Case: first letter and Title Case",
            case_bad.len() == 2 && case_bad.iter().all(|v| v.rule_id == CASE_RULE_ID),
        ),
        ("Case: sentence case is not forced", case_good.is_empty()),
        (
            "Missing source msgid",
            missing == vec!["3:Brand new".to_string(), "7:Open".to_string()],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_cases_pass() {
        assert!(self_test_cases().iter().all(|(_, ok)| *ok));
    }

    #[test]
    fn jinja_trans_block_is_checked() {
        let keys: HashSet<CatalogueKey> = HashSet::new();
        let v = audit_source_text("t.html", "{% trans %}Welcome{% endtrans %}", &keys);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn js_context_argument_is_part_of_the_key() {
        let lits = extract_literals("__(\"Open\", null, \"email\")");
        assert_eq!(lits.len(), 1);
        assert_eq!(lits[0].key, ("email".to_string(), "Open".to_string()));
    }

    #[test]
    fn multi_line_msgid_is_joined() {
        let po = "msgid \"\"\n\"First \"\n\"second\"\nmsgstr \"\"\n\"Primeiro \"\n\"segundo\"\n";
        let (v, keys) = audit_catalogue("m.po", po);
        assert!(v.is_empty());
        assert!(keys.contains(&(String::new(), "First second".to_string())));
    }
}
