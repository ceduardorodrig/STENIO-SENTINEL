//! One reader of `@frappe.whitelist(...)` functions for three rules (GB-052, GB-056, GB-054).
//!
//! Pure text, no import of the app (ARCH-NO-PYTHON): for every decorated function the extractor
//! returns the decorator line, the verbs it declares (`methods=[...]`), the state-changing calls
//! of its body (`.save()`, `.insert()`, `.delete()`, `.db_set()`, `frappe.delete_doc()`,
//! `frappe.db.set_value()`, `frappe.db.delete()`) and the dotted path a client calls it by.
//! The rules built on it live in `frappe.rs`:
//!   * `FRAPPE-WHITELIST-METHODS`    writer with no `methods=` at all (default GET/POST/PUT/DELETE);
//!   * `FRAPPE-WHITELIST-WRITE-POST` writer whose declared `methods` is not exactly `["POST"]`;
//!   * `FRAPPE-WHITELIST-NO-CALLER`  endpoint whose dotted path no screen, report or card names.
//!
//! Known limit, stated on purpose: a writer reached through a helper (`_apply(doc)` that saves)
//! is not seen, because the extractor reads one function body, not the call graph.

use regex::Regex;

/// Verbs of a decorator: absent, a readable list, or an expression the reader leaves alone.
#[derive(Debug, Clone, PartialEq)]
pub enum Methods {
    Absent,
    List(Vec<String>),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub name: String,
    /// 1-based line of the `def`.
    pub decorator_line: usize,
    pub methods: Methods,
    /// (1-based line, call text) of each state-changing call in the body.
    pub writes: Vec<(usize, String)>,
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

/// Decorator name end: `@frappe.whitelist` or the `@whitelist` alias, as a whole word.
fn decorator_rest(line: &str) -> Option<&str> {
    let t = line.trim_start();
    let rest = t
        .strip_prefix("@frappe.whitelist")
        .or_else(|| t.strip_prefix("@whitelist"))?;
    match rest.chars().next() {
        None | Some('(') | Some(' ') | Some('#') => Some(rest),
        _ => None,
    }
}

/// Text between the parentheses of the decorator call that opens at the start of `lines[i]`'s
/// argument list, joined over the lines it spans.
fn decorator_args(lines: &[&str], i: usize, rest: &str) -> String {
    if !rest.trim_start().starts_with('(') {
        return String::new();
    }
    let mut joined = rest.trim_start().to_string();
    let mut k = i;
    let balanced = |s: &str| s.matches('(').count() <= s.matches(')').count();
    while !balanced(&joined) && k + 1 < lines.len() {
        k += 1;
        joined.push(' ');
        joined.push_str(lines[k].trim());
    }
    let inner = joined.trim_start().trim_start_matches('(');
    match inner.rfind(')') {
        Some(e) => inner[..e].to_string(),
        None => inner.to_string(),
    }
}

fn parse_methods(args: &str) -> Methods {
    let mut depth = 0i32;
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote = '\0';
    for ch in args.chars() {
        if quote != '\0' {
            cur.push(ch);
            if ch == quote {
                quote = '\0';
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                quote = ch;
                cur.push(ch);
            }
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    parts.push(cur);
    for p in parts {
        let p = p.trim();
        let Some(v) = p.strip_prefix("methods") else {
            continue;
        };
        let Some(v) = v.trim_start().strip_prefix('=') else {
            continue;
        };
        let mut verbs = Vec::new();
        let mut word = String::new();
        let mut q = '\0';
        for ch in v.chars() {
            if q != '\0' {
                if ch == q {
                    verbs.push(word.to_uppercase());
                    word.clear();
                    q = '\0';
                } else {
                    word.push(ch);
                }
            } else if ch == '"' || ch == '\'' {
                q = ch;
            }
        }
        // a name, a call or a `*` expansion has no quoted verb: leave it alone
        return if verbs.is_empty() {
            Methods::Unknown
        } else {
            Methods::List(verbs)
        };
    }
    Methods::Absent
}

/// Every `@frappe.whitelist` function of a Python source text.
pub fn extract(text: &str) -> Vec<Endpoint> {
    let Ok(write_re) = Regex::new(
        r"(\.(save|insert|delete)\(\s*(\)|[A-Za-z_]+\s*=)|\.db_set\(|\bfrappe\.delete_doc\(|\bfrappe\.db\.(set_value|delete)\()",
    ) else {
        return Vec::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some(rest) = decorator_rest(lines[i]) else {
            i += 1;
            continue;
        };
        let methods = parse_methods(&decorator_args(&lines, i, rest));
        let mut j = i + 1;
        while j < lines.len() {
            let t = lines[j].trim_start();
            if t.starts_with("def ") || t.starts_with("async def ") {
                break;
            }
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
        let name = lines[j]
            .trim()
            .trim_start_matches("async ")
            .trim_start_matches("def ")
            .split('(')
            .next()
            .unwrap_or("")
            .to_string();
        let writes = (j..k)
            .filter(|&n| !lines[n].trim_start().starts_with('#'))
            .filter_map(|n| {
                write_re.find(lines[n]).map(|m| {
                    (
                        n + 1,
                        m.as_str().split('(').next().unwrap_or_default().to_string(),
                    )
                })
            })
            .collect();
        out.push(Endpoint {
            name,
            decorator_line: i + 1,
            methods,
            writes,
        });
        i = k.max(i + 1);
    }
    out
}

/// `app.pkg.module` of a package-relative path such as `ranking.py` (`__init__` collapses).
pub fn module_path(app: &str, rel_in_pkg: &str) -> String {
    let stem = rel_in_pkg.strip_suffix(".py").unwrap_or(rel_in_pkg);
    let stem = stem.strip_suffix("/__init__").unwrap_or(stem);
    let tail = stem.replace('/', ".");
    if tail.is_empty() || tail == "__init__" {
        app.to_string()
    } else {
        format!("{app}.{tail}")
    }
}

/// True when `needle` appears in `hay` as a whole dotted name (not a prefix of a longer identifier).
pub fn names_path(hay: &str, needle: &str) -> bool {
    let mut from = 0;
    while let Some(p) = hay[from..].find(needle) {
        let s = from + p;
        let e = s + needle.len();
        let before = hay[..s].chars().next_back();
        let after = hay[e..].chars().next();
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !ident(before) && !ident(after) {
            return true;
        }
        from = e;
    }
    false
}

/// A text calls `module.name` when it spells the full dotted path, or names the module and the
/// function separately: a JS helper `frappe.call({method: `app.mod.${method}`})` fed
/// `"fn"`, or Python `from app.mod import fn`.
pub fn is_caller(text: &str, module: &str, name: &str) -> bool {
    names_path(text, &format!("{module}.{name}"))
        || (names_path(text, module) && names_path(text, name))
}

/// The text without whole-line comments (`//`, `#`, `/*`, `*`): a comment that names an endpoint
/// is documentation, not a call, and must not hide an orphan.
pub fn without_comment_lines(text: &str) -> String {
    text.lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//")
                || t.starts_with('#')
                || t.starts_with("/*")
                || t.starts_with('*'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let writer_get =
        "@frappe.whitelist()\ndef off(m):\n    doc = frappe.get_doc('X', m)\n    doc.save()\n";
    let writer_post = "@frappe.whitelist(methods=[\"POST\"])\ndef off(m):\n    doc.save()\n";
    let reader =
        "@frappe.whitelist()\ndef rd():\n    items.insert(0, 1)\n    return frappe.get_all('X')\n";
    let mixed = "@frappe.whitelist(methods=[\"GET\", \"POST\"])\ndef off(m):\n    doc.delete()\n";
    let e1 = extract(writer_get);
    let e2 = extract(writer_post);
    let e3 = extract(reader);
    let e4 = extract(mixed);
    vec![
        (
            "whitelist: writer without methods is read as Absent with one write".into(),
            e1.len() == 1 && e1[0].methods == Methods::Absent && e1[0].writes.len() == 1,
        ),
        (
            "whitelist: methods=[POST] is read as the exact verb list".into(),
            e2.len() == 1 && e2[0].methods == Methods::List(vec!["POST".into()]),
        ),
        (
            "whitelist: list.insert(0, x) in a reader is not a write".into(),
            e3.len() == 1 && e3[0].writes.is_empty(),
        ),
        (
            "whitelist: GET+POST list on a writer keeps both verbs".into(),
            e4.len() == 1 && matches!(&e4[0].methods, Methods::List(v) if v.len() == 2),
        ),
        (
            "whitelist: dotted path collapses __init__ and nests folders".into(),
            module_path("app", "a/b.py") == "app.a.b"
                && module_path("app", "a/__init__.py") == "app.a",
        ),
        (
            "whitelist: module and function named apart still count as a caller".into(),
            is_caller("method: `app.m.${x}` call('close')", "app.m", "close")
                && !is_caller("app.other.close()", "app.m", "close"),
        ),
        (
            "whitelist: a comment that names the endpoint is not a caller".into(),
            !is_caller(
                &without_comment_lines("// calls app.m close_it\n# app.m.close_it"),
                "app.m",
                "close_it",
            ),
        ),
        (
            "whitelist: a longer identifier is not a caller".into(),
            names_path("method: 'app.m.close'", "app.m.close")
                && !names_path("app.m.close_all", "app.m.close"),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_cases_all_pass() {
        for (name, ok) in self_test_cases() {
            assert!(ok, "{name}");
        }
    }

    #[test]
    fn multiline_decorator_and_alias_are_read() {
        let t = "@whitelist(\n    allow_guest=False,\n    methods=['post'],\n)\ndef f():\n    frappe.db.set_value('A', 'b', 'c', 1)\n";
        let e = extract(t);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].methods, Methods::List(vec!["POST".into()]));
        assert_eq!(e[0].writes.len(), 1);
        assert_eq!(e[0].decorator_line, 1);
    }

    #[test]
    fn variable_methods_are_left_alone() {
        let e = extract("@frappe.whitelist(methods=VERBS)\ndef f():\n    doc.save()\n");
        assert_eq!(e[0].methods, Methods::Unknown);
    }

    #[test]
    fn commented_write_is_not_a_write_and_next_function_is_separate() {
        let t = "@frappe.whitelist()\ndef a():\n    # doc.save()\n    return 1\n\n@frappe.whitelist()\ndef b():\n    doc.insert(ignore_permissions=True)\n";
        let e = extract(t);
        assert_eq!(e.len(), 2);
        assert!(e[0].writes.is_empty());
        assert_eq!(e[1].writes.len(), 1);
    }
}
