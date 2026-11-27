//! FRAPPE-TEMPLATE-LITERALS-TRANSLATED (GB-204).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-TEMPLATE-LITERALS-TRANSLATED",
    name: "Template Or Script Literal Missing From Catalogue",
    severity: "ERROR",
    tag: "frappe",
    summary: "A literal passed to `_()` or `__()` in an `.html` of www/ or templates/, or in a `.js` of public/js/, has no msgid in the app catalogue. Computed arguments and concatenations are skipped; an app with no catalogue is silent (FRAPPE-PO-CATALOGUE-RESOLVES reports that).",
    rationale: "GB-204: the assistant page shipped with sentences checked only by a hand regex; the app's own coverage test reads `*.py`, and the one covering html/js needs a site.",
    bad_example: "{{ _(\"Ask the assistant\") }}   <!-- no msgid -->",
    good_example: "{{ _(\"Ask the assistant\") }}   <!-- msgid + msgstr in the .po -->",
    remediation: "Add the msgid and its translation to the catalogue.",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let Some((pr, map)) = po_catalogue(c) else {
        return Vec::new();
    };
    let Ok(call) = Regex::new(
        r#"(?:^|[^\w$])_{1,2}\(\s*(?:"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)')\s*[,)]"#,
    ) else {
        return Vec::new();
    };
    let dirs = ["www/", "templates/", "public/js/"];
    let mut out = Vec::new();
    for p in sources(c, &["html", "js"]) {
        let inner = rel(&c.pkg, p);
        let html = inner.ends_with(".html");
        let wanted = dirs
            .iter()
            .any(|d| inner.starts_with(d) && (d.starts_with("public") != html));
        if !wanted {
            continue;
        }
        let text = if html {
            read(p)
        } else {
            blank_js_comments(&read(p))
        };
        let mut seen = BTreeSet::new();
        for m in call.captures_iter(&text) {
            let Some(raw) = m.get(1).or_else(|| m.get(2)) else {
                continue;
            };
            let lit = py_unescape(raw.as_str());
            if !translatable_literal(&lit) || map.contains_key(&lit) || !seen.insert(lit.clone()) {
                continue;
            }
            out.push(finding(
                &EXPLAIN,
                &rel(&c.root, p),
                line_at(&text, raw.start()),
                &lit,
                format!("`{lit}` has no msgid in {pr}: the page shows it in English."),
            ));
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let po = (
        "app/locale/pt_BR.po",
        "msgid \"Ask\"\nmsgstr \"Perguntar\"\n",
    );
    let html = ("app/www/p.html", "<h1>{{ _(\"Ask\") }}</h1>\n");
    let js = (
        "app/public/js/a.js",
        "// __(\"commented\")\nfrappe.msgprint(__('Ask'));\nfoo_(\"x y\"); __(name);\n",
    );
    let bad_html = ("app/www/p.html", "<p>\n{{ _(\"Send now\") }}</p>\n");
    let bad_js = ("app/public/js/a.js", "alert(__(\"Not sent\", [n]));\n");
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[po, html, js])
            && probe(run, &[po, bad_html]).is_some_and(|v| v.len() == 1 && v[0].1 == 2)
            && fires(run, &[po, bad_js], 1, &["Not sent"]),
    )]
}
