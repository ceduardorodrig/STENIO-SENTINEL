//! I18N-NO-UNTRANSLATED-INTERPOLATION (GB-083).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "I18N-NO-UNTRANSLATED-INTERPOLATION",
    name: "User Message That Skips Translation",
    severity: "ERROR",
    tag: "frappe",
    summary: "`frappe.throw` / `frappe.msgprint` whose message starts with a literal or an f-string (not `_(...)`), or a `get_label(...)` passed raw into `.format(...)` or a `label=` argument. Tests and patches are skipped; a variable message is not judged.",
    rationale: "GB-083 (i18n audit): `validators.py` passed a raw `doc.meta.get_label()` into a translated sentence and `integrations_setup.py` threw English literals and f-strings; the coverage gates only read literals inside `_()`.",
    bad_example: "frappe.throw(f\"{email} already exists\")",
    good_example: "frappe.throw(_(\"{0} already exists\").format(email))",
    remediation: "Wrap the sentence in _() with placeholders, and each label in _().",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let (Ok(call), Ok(label), Ok(wrapped)) = (
        Regex::new(
            r#"frappe\.(throw|msgprint)\(\s*(?:msg\s*=\s*)?[rRfFbB]{0,2}("[^"\n]*[A-Za-z]{2}[^"\n]*"|'[^'\n]*[A-Za-z]{2}[^'\n]*')"#,
        ),
        Regex::new(r"(?:[\w\]\)]+\.)*get_label\("),
        Regex::new(r"(?:\b_|\bfrappe\._)\(\s*$"),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in sources(c, &["py"]) {
        if rel(&c.pkg, p).starts_with("patches/") {
            continue;
        }
        let mut state: Option<&'static str> = None;
        // Docstrings are prose: blank them, keeping the line count.
        let code: String = read(p)
            .lines()
            .map(|l| {
                let t = l.trim_start();
                let docstring = t.starts_with("\"\"\"") || t.starts_with("'''");
                if py_code_line(l, &mut state) && !docstring {
                    py_strip_comment(l)
                } else {
                    ""
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let path = rel(&c.root, p);
        for m in call.captures_iter(&code) {
            let at = m.get(0).map(|x| x.start()).unwrap_or(0);
            out.push(finding(
                &EXPLAIN,
                &path,
                line_at(&code, at),
                &m[2],
                format!(
                    "frappe.{} shows {} without _(): it is never translated.",
                    &m[1], &m[2]
                ),
            ));
        }
        for m in label.find_iter(&code) {
            let before = &code[..m.start()];
            let line = before.rsplit('\n').next().unwrap_or("");
            let raw = line.contains(".format(") || line.contains("label=");
            if raw && !wrapped.is_match(line) {
                out.push(finding(
                    &EXPLAIN,
                    &path,
                    line_at(&code, m.start()),
                    m.as_str(),
                    "`get_label(...)` goes into a message without _(): the label stays in English."
                        .to_string(),
                ));
            }
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let good = "import frappe\nfrom frappe import _\n\n\ndef a(doc, msg):\n\t\"\"\"frappe.throw(\"prose\")\"\"\"\n\tfrappe.throw(_(\"{0} is late\").format(_(doc.meta.get_label(\"x\"))))\n\tfrappe.throw(msg)\n\tfrappe.msgprint(_(\"Done\"))\n\t# frappe.throw(\"old\")\n";
    let literal = "def a():\n\tfrappe.throw(\"Set the password\")\n";
    let fstring = "def a(e):\n\tfrappe.throw(\n\t\tf\"{e} already exists\"\n\t)\n";
    let raw = "def a(doc, f):\n\tf(doc, label=doc.meta.get_label(\"x\"))\n";
    let path = "app/api.py";
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[(path, good)])
            && fires(run, &[(path, literal)], 1, &["Set the password"])
            && fires(run, &[(path, fstring)], 1, &["already exists"])
            && fires(run, &[(path, raw)], 1, &["get_label"])
            && silent(run, &[("app/tests/t.py", literal)]),
    )]
}
