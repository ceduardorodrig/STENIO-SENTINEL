//! FRAPPE-FIELDNAME-COLLIDES-WITH-PROPERTY (GB-089).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-FIELDNAME-COLLIDES-WITH-PROPERTY",
    name: "Fieldname Shadows A Frappe Property",
    severity: "ERROR",
    tag: "frappe",
    summary: "A DocType fieldname equals a reserved Document keyword, a restricted column, or `fieldtype`/`fieldname` (ERROR); `depends_on`, `mandatory_depends_on`, `read_only_depends_on`, `fetch_from` and `permlevel` shadow a DocField property and are a WARNING. `description`, `label` and `options` are ordinary field names and are not reported.",
    rationale: "GB-089. Frappe checks `RESERVED_KEYWORDS` (model/document.py) and its restricted list (core/doctype/doctype/doctype.py, v16.55.1) in the Desk form editor path, so a hand-written JSON can ship the name and shadow the attribute. `Task.depends_on` shipped on purpose, hence the warning tier for the DocField properties.",
    bad_example: "{\"fieldname\": \"fieldtype\", \"fieldtype\": \"Data\"}",
    good_example: "{\"fieldname\": \"asset_kind\", \"fieldtype\": \"Data\"}",
    remediation: "Rename the field (and ship a patch that renames the column) so it no longer shadows the property.",
};

const RESERVED: &[&str] = &[
    "doctype",
    "flags",
    "_parent_doc",
    "_doc_before_save",
    "_action",
    "dont_update_if_missing",
    "meta",
    "permitted_fieldnames",
    "_weakref",
    "_table_fieldnames",
    "_non_computed_table_fieldnames",
];
const RESTRICTED: &[&str] = &[
    "name",
    "parent",
    "creation",
    "owner",
    "modified",
    "modified_by",
    "parentfield",
    "parenttype",
    "file_list",
    "docstatus",
];
const DOCFIELD_CORE: &[&str] = &["fieldtype", "fieldname"];
const DOCFIELD_SOFT: &[&str] = &[
    "depends_on",
    "mandatory_depends_on",
    "read_only_depends_on",
    "fetch_from",
    "permlevel",
];
/// Core DocTypes that describe fields themselves.
const META_DOCTYPES: &[&str] = &[
    "DocType",
    "DocField",
    "Custom Field",
    "Customize Form Field",
];

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let mut out = Vec::new();
    for d in &c.doctypes {
        if META_DOCTYPES.contains(&d.name.as_str()) {
            continue;
        }
        for f in &d.fields {
            let n = f.fieldname.as_str();
            let (what, hard) = if RESERVED.contains(&n) {
                ("a reserved Document keyword", true)
            } else if RESTRICTED.contains(&n) {
                ("a restricted standard column", true)
            } else if DOCFIELD_CORE.contains(&n) {
                ("the DocField property", true)
            } else if DOCFIELD_SOFT.contains(&n) {
                ("the DocField property", false)
            } else {
                continue;
            };
            let mut v = finding(
                &EXPLAIN,
                &d.rel,
                line_of(&d.text, &format!("\"{n}\"")),
                n,
                format!("`{}.{n}` shadows {what} `{n}`.", d.name),
            );
            if !hard {
                v.severity = Severity::Warning;
            }
            out.push(v);
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let doc = |name: &str| {
        format!(
            "{{\"doctype\":\"DocType\",\"name\":\"Thing\",\"fields\":[{{\"fieldname\":\"{name}\",\"fieldtype\":\"Data\"}}]}}"
        )
    };
    let path = "app/m/doctype/thing/thing.json";
    let hit = |name: &str, what: &str| fires(run, &[(path, &doc(name))], 1, &[name, what]);
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[(path, &doc("description"))])
            && silent(run, &[(path, &doc("asset_kind"))])
            && hit("fieldtype", "DocField property")
            && hit("depends_on", "DocField property")
            && hit("flags", "reserved Document keyword")
            && hit("docstatus", "restricted standard column"),
    )]
}
