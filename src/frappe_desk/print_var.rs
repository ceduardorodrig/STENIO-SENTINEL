//! FRAPPE-PRINT-NO-CSS-VAR (GB-192).

use super::super::*;
use super::print_css::printable;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-PRINT-NO-CSS-VAR",
    name: "CSS Variable In A Printed Shorthand",
    severity: "ERROR",
    tag: "frappe",
    summary: "A page declaring `@page` uses `var()` inside a `border*` or `background` shorthand that reaches paper. Screen-only rules and a background on html/body alone (paper is white without it) are not reported.",
    rationale: "GB-192 (2026-11-06): wkhtmltopdf 0.12.6.1 has no CSS custom properties; `border: 2mm dashed var(--x)` renders no border at all, so a token rewrite would have deleted the cut guides of the label sheet. The design-token colour rules push exactly that way.",
    bad_example: "td.label { border: .2mm dashed var(--sheet-rule) }",
    good_example: "td.label { border: .2mm dashed }   /* currentColor */",
    remediation: "Leave the colour out (currentColor) or write it literally on printed rules.",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for (p, decls) in printable(c, false) {
        for d in decls {
            let shorthand = d.property == "background" || d.property.starts_with("border");
            let page = d.property == "background"
                && d.selector
                    .split(',')
                    .all(|s| matches!(s.trim(), "html" | "body"));
            if shorthand && !page && d.value.contains("var(") {
                out.push(finding(
                    &EXPLAIN,
                    &rel(&c.root, &p),
                    d.line,
                    &format!("{}: {}", d.property, d.value),
                    format!(
                        "`{}: {}` on printed selector `{}`: the print engine drops the whole declaration.",
                        d.property, d.value, d.selector
                    ),
                ));
            }
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let good = "<style>\n@page { size: A4 }\nhtml, body { background: var(--w); color: var(--i) }\n.bar a { border: 1px solid var(--r) }\ntd.label { border: .2mm dashed }\n@media print { .bar { display: none !important } }\n</style>\n";
    let bad =
        "<style>\n@page { size: A4 }\ntd.label { border: .2mm dashed var(--mc-x) }\n</style>\n";
    let no_page = "<style>\ntd.label { border: .2mm dashed var(--mc-x) }\n</style>\n";
    let path = "app/www/p.html";
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[(path, good)])
            && silent(run, &[(path, no_page)])
            && probe(run, &[(path, bad)]).is_some_and(|v| v.len() == 1 && v[0].1 == 3),
    )]
}
