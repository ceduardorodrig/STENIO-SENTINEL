//! FRAPPE-TABLE-NEEDS-SECTION (GB-168).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

const ALLOWLIST: &str = "table-section-allowlist.txt";

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-TABLE-NEEDS-SECTION",
    name: "Child Table Without A Section Header",
    severity: "ERROR",
    tag: "frappe",
    summary: "A Table / Table MultiSelect field whose preceding field (in `field_order`) is neither a Section Break nor a Tab Break. Documented exceptions go in `table-section-allowlist.txt` at the app root, one `DocType.fieldname  # reason` per line.",
    rationale: "GB-168 (2026-11-06): 13 tables in 10 Miracena DocTypes reached the Desk with no header, directly under an unrelated field; nothing read the field order.",
    bad_example: "[{\"fieldtype\": \"Data\"}, {\"fieldtype\": \"Table\"}]",
    good_example: "[{\"fieldtype\": \"Data\"}, {\"fieldtype\": \"Section Break\"}, {\"fieldtype\": \"Table\"}]",
    remediation: "Insert a Section Break (with a label) before the table, or list it in table-section-allowlist.txt with the reason.",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let allow: BTreeSet<String> = read(&c.root.join(ALLOWLIST))
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let mut out = Vec::new();
    for d in &c.doctypes {
        let Ok(v) = serde_json::from_str::<Value>(&d.text) else {
            continue;
        };
        // The form follows `field_order`; without it, the order of `fields`.
        let order: Vec<&str> = v
            .get("field_order")
            .and_then(|o| o.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .filter(|a: &Vec<&str>| !a.is_empty())
            .unwrap_or_else(|| d.fields.iter().map(|f| f.fieldname.as_str()).collect());
        let mut before: Option<&str> = None;
        for name in order {
            let Some(f) = d.fields.iter().find(|f| f.fieldname == name) else {
                continue;
            };
            let table = matches!(f.fieldtype.as_str(), "Table" | "Table MultiSelect");
            let headed = matches!(before, Some("Section Break" | "Tab Break"));
            if table && !headed && !allow.contains(&format!("{}.{name}", d.name)) {
                out.push(finding(
                    &EXPLAIN,
                    &d.rel,
                    line_of(&d.text, &format!("\"fieldname\": \"{name}\"")),
                    name,
                    format!(
                        "Table `{}.{name}` follows {} instead of a Section Break: it has no header on the form.",
                        d.name,
                        before.map(|t| format!("a {t} field")).unwrap_or_else(|| "nothing".into())
                    ),
                ));
            }
            before = Some(f.fieldtype.as_str());
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let doc = |order: &str| {
        format!(
            "{{\"doctype\":\"DocType\",\"name\":\"Thing\",\"field_order\":[{order}],\"fields\":[{{\"fieldname\":\"a\",\"fieldtype\":\"Data\"}},{{\"fieldname\":\"s\",\"fieldtype\":\"Section Break\"}},{{\"fieldname\":\"rows\",\"fieldtype\":\"Table\"}}]}}"
        )
    };
    let path = "app/m/doctype/thing/thing.json";
    let good = doc("\"a\",\"s\",\"rows\"");
    let bad = doc("\"s\",\"a\",\"rows\"");
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[(path, &good)])
            && fires(run, &[(path, &bad)], 1, &["Thing.rows", "Data"])
            && silent(
                run,
                &[(path, &bad), (ALLOWLIST, "Thing.rows  # documented\n")],
            ),
    )]
}
