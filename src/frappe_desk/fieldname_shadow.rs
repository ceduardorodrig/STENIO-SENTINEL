//! FRAPPE-FIELDNAME-COLLIDES-WITH-PROPERTY (GB-089).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

/// Documented exceptions for the DocField-property tier, `DocType.fieldname | reason`.
const ALLOWLIST: &str = "fieldname-shadow-allowlist.txt";

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-FIELDNAME-COLLIDES-WITH-PROPERTY",
    name: "Fieldname Shadows A Frappe Property",
    severity: "ERROR",
    tag: "frappe",
    summary: "A DocType fieldname equals a reserved Document keyword, a restricted column, or `fieldtype`/`fieldname`, `depends_on`, `mandatory_depends_on`, `read_only_depends_on`, `fetch_from` or `permlevel`. Only the last five can be a documented exception, one `DocType.fieldname | reason` per line in `fieldname-shadow-allowlist.txt` at the app root; an entry without a reason or matching no field is an ERROR. `description`, `label` and `options` are ordinary field names and are not reported.",
    rationale: "GB-089. Frappe checks `RESERVED_KEYWORDS` (model/document.py) and its restricted list (core/doctype/doctype/doctype.py, v16.55.1) in the Desk form editor path, so a hand-written JSON can ship the name and shadow the attribute. `Task.depends_on` shipped on purpose (a Link to the blocking task), hence the reasoned exception for the DocField properties.",
    bad_example: "{\"fieldname\": \"fieldtype\", \"fieldtype\": \"Data\"}",
    good_example: "{\"fieldname\": \"asset_kind\", \"fieldtype\": \"Data\"}",
    remediation: "Rename the field (and ship a patch that renames the column), or for a DocField property record `DocType.fieldname | reason` in fieldname-shadow-allowlist.txt.",
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
    let text = read(&c.root.join(ALLOWLIST));
    // (line, `DocType.fieldname`, reason) of every entry.
    let allow: Vec<(usize, &str, &str)> = text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
        .map(|(i, l)| {
            let (key, reason) = l.split_once('|').unwrap_or((l, ""));
            (i, key.trim(), reason.trim())
        })
        .collect();
    let mut used = BTreeSet::new();
    for d in &c.doctypes {
        if META_DOCTYPES.contains(&d.name.as_str()) {
            continue;
        }
        for f in &d.fields {
            let n = f.fieldname.as_str();
            let (what, excusable) = if RESERVED.contains(&n) {
                ("a reserved Document keyword", false)
            } else if RESTRICTED.contains(&n) {
                ("a restricted standard column", false)
            } else if DOCFIELD_CORE.contains(&n) {
                ("the DocField property", false)
            } else if DOCFIELD_SOFT.contains(&n) {
                ("the DocField property", true)
            } else {
                continue;
            };
            let key = format!("{}.{n}", d.name);
            if excusable
                && let Some((line, ..)) = allow
                    .iter()
                    .find(|(_, k, reason)| *k == key && !reason.is_empty())
            {
                used.insert(*line);
                continue;
            }
            out.push(finding(
                &EXPLAIN,
                &d.rel,
                line_of(&d.text, &format!("\"{n}\"")),
                n,
                format!("`{key}` shadows {what} `{n}`."),
            ));
        }
    }
    for (line, key, _) in allow.iter().filter(|(i, ..)| !used.contains(i)) {
        out.push(finding(
            &EXPLAIN,
            ALLOWLIST,
            *line,
            key,
            format!(
                "Allowlist entry `{key}` excuses nothing: it needs `| reason` and must name an existing DocField-property field."
            ),
        ));
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
            && hit("docstatus", "restricted standard column")
            && silent(
                run,
                &[
                    (path, &doc("depends_on")),
                    (ALLOWLIST, "# why\nThing.depends_on | blocking task link\n"),
                ],
            )
            && fires(
                run,
                &[
                    (path, &doc("depends_on")),
                    (ALLOWLIST, "Thing.depends_on\n"),
                ],
                2,
                &["excuses nothing"],
            )
            && fires(
                run,
                &[(path, &doc("flags")), (ALLOWLIST, "Thing.flags | no\n")],
                2,
                &["reserved Document keyword"],
            )
            && fires(
                run,
                &[
                    (path, &doc("asset_kind")),
                    (ALLOWLIST, "Thing.gone | old\n"),
                ],
                1,
                &["excuses nothing"],
            ),
    )]
}
