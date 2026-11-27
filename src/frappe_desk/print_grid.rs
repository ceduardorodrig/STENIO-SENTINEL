//! ARCH-PRINT-QTWEBKIT (GB-174).

use super::super::*;
use super::print_css::printable;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "ARCH-PRINT-QTWEBKIT",
    name: "CSS Grid On A Printable Page",
    severity: "ERROR",
    tag: "frappe",
    summary: "A page of the app declaring `@page` or `@media print` lays paper content out with `display: grid` / `grid-template*`. Screen-only rules (`@media screen`, or under a class that print hides) are not reported; flexbox is not reported.",
    rationale: "GB-174: wkhtmltopdf 0.12.6.1 (QtWebKit), the platform's PDF engine, does not implement CSS Grid and laid 48 labels over 6 pages instead of 1 (measured on www/etiquetas.html).",
    bad_example: "@page { size: A4 }\n.sheet { display: grid; grid-template-columns: repeat(4, 1fr) }",
    good_example: "@page { size: A4 }\ntable.sheet { table-layout: fixed }",
    remediation: "Lay the printed content out with tables, floats or inline-block.",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for (p, decls) in printable(c, true) {
        for d in decls {
            let grid = (d.property == "display" && d.value.contains("grid"))
                || d.property.starts_with("grid-template");
            if grid {
                out.push(finding(
                    &EXPLAIN,
                    &rel(&c.root, &p),
                    d.line,
                    &format!("{}: {}", d.property, d.value),
                    format!(
                        "`{}: {}` on printable selector `{}`: QtWebKit has no CSS Grid.",
                        d.property, d.value, d.selector
                    ),
                ));
            }
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let good = "<style>\n@page { size: A4; margin: {{ m }}mm; }\n.bar { display: grid }\n@media screen { .s { display: grid } }\ntable { table-layout: fixed }\n@media print { .bar { display: none !important } }\n</style>\n";
    let bad = "<style>\n@page { size: A4 }\n.sheet {\n  display: grid;\n}\n</style>\n";
    let media = "<style>\n@media print { .sheet { grid-template-columns: 1fr 1fr } }\n</style>\n";
    let screen = "<style>\n.sheet { display: grid }\n</style>\n";
    let path = "app/www/p.html";
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[(path, good)])
            && silent(run, &[(path, screen)])
            && probe(run, &[(path, bad)]).is_some_and(|v| v.len() == 1 && v[0].1 == 4)
            && fires(run, &[(path, media)], 1, &["grid-template-columns"]),
    )]
}
