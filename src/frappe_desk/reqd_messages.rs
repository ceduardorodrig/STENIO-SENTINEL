//! FRAPPE-REQD-MESSAGES (GB-011).

use super::super::*;
use super::support::*;
use crate::explain::RuleExplanation;

pub(super) const EXPLAIN: RuleExplanation = RuleExplanation {
    id: "FRAPPE-REQD-MESSAGES",
    name: "Mandatory Field Without A Translated Message",
    severity: "ERROR",
    tag: "frappe",
    summary: "A visible field with `reqd` or `mandatory_depends_on` has no `label`, or its label has no msgid / an empty translation in the app catalogue: Frappe builds the mandatory message from the label.",
    rationale: "GB-011 (2026-11-04). `Value missing for {0}: {1}` is composed from the translated label; without it the person is told, in English or with a bare fieldname, to fill a field they cannot find.",
    bad_example: "{\"fieldname\": \"due_date\", \"fieldtype\": \"Date\", \"reqd\": 1}",
    good_example: "{\"fieldname\": \"due_date\", \"fieldtype\": \"Date\", \"label\": \"Due Date\", \"reqd\": 1}  # msgid + msgstr in the .po",
    remediation: "Give the field a label and add its msgid with a non-empty translation to the catalogue.",
};

pub(super) fn run(c: &Ctx) -> Vec<Violation> {
    let po = catalogue(c);
    let allow = c.cfg.label_allowlist.clone().unwrap_or_default();
    let mut out = Vec::new();
    for d in &c.doctypes {
        let Ok(v) = serde_json::from_str::<Value>(&d.text) else {
            continue;
        };
        for f in v
            .get("fields")
            .and_then(|f| f.as_array())
            .into_iter()
            .flatten()
        {
            let mandatory = flag(f, "reqd") || !str_of(f, "mandatory_depends_on").is_empty();
            if !mandatory || flag(f, "hidden") {
                continue;
            }
            let field = str_of(f, "fieldname");
            let label = str_of(f, "label").trim().to_string();
            let why = if label.is_empty() {
                "has no label".to_string()
            } else {
                match &po {
                    Some((pr, map)) if !technical(&label, &allow) => match map.get(&label) {
                        None => format!("has label `{label}` with no msgid in {pr}"),
                        Some(m) if m.trim().is_empty() => {
                            format!("has label `{label}` with an empty translation in {pr}")
                        }
                        Some(_) => continue,
                    },
                    _ => continue,
                }
            };
            out.push(finding(
                &EXPLAIN,
                &d.rel,
                line_of(&d.text, &format!("\"{field}\"")),
                &field,
                format!(
                    "Mandatory field `{}.{field}` {why}: the \"value missing\" message cannot name it in the user's language.",
                    d.name
                ),
            ));
        }
    }
    out
}

pub(super) fn cases() -> Vec<(String, bool)> {
    let doc = |field: &str| {
        format!(
            "{{\"doctype\":\"DocType\",\"name\":\"Thing\",\"fields\":[{{\"fieldname\":\"due\",\"fieldtype\":\"Date\"{field}}}]}}"
        )
    };
    let good = doc(",\"label\":\"Due Date\",\"reqd\":1");
    let bare = doc(",\"reqd\":1");
    let other = doc(",\"label\":\"Deadline\",\"mandatory_depends_on\":\"eval:1\"");
    let optional = doc("");
    let po = (
        "app/locale/pt_BR.po",
        "msgid \"Due Date\"\nmsgstr \"Prazo\"\n",
    );
    let path = "app/m/doctype/thing/thing.json";
    vec![(
        EXPLAIN.id.to_string(),
        silent(run, &[po, (path, &good)])
            && silent(run, &[po, (path, &optional)])
            && fires(run, &[po, (path, &bare)], 1, &["Thing.due", "no label"])
            && fires(run, &[po, (path, &other)], 1, &["Deadline", "no msgid"]),
    )]
}
