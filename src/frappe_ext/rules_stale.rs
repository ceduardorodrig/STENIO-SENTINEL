//! MIRACENA-DOCTYPE-NO-RULES (GB-160), the stale half: FRAPPE-RULES-COVERAGE already fails a
//! DocType without an entry.

use super::*;

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "MIRACENA-DOCTYPE-NO-RULES",
        name: "Validation Gate Entry For A DocType That Does Not Exist",
        severity: "ERROR",
        tag: "frappe",
        summary: "A key of `RULES` (including `rules[...] =` extensions) names no DocType JSON of the app and no Frappe core DocType. The opposite direction, a DocType without an entry, is FRAPPE-RULES-COVERAGE.",
        rationale: "GB-160: the two sets (DocType JSONs and RULES) were compared by hand. A renamed DocType keeps its old key, and the validation written for it silently stops running.",
        bad_example: "RULES = {\"Old Name\": _rule()}  # the DocType is now `New Name`",
        good_example: "RULES = {\"New Name\": _rule()}",
        remediation: "Rename the key to the DocType that exists, or delete the entry.",
    },
};

fn rule(c: &Ctx) -> Vec<Violation> {
    if c.doctypes.is_empty() {
        return Vec::new();
    }
    super::super::gate_entries(c)
        .iter()
        .filter(|(name, _)| {
            !c.doctypes.iter().any(|d| &d.name == *name)
                && !super::privacy_lists::CORE_DOCTYPES.contains(&name.as_str())
        })
        .map(|(name, e)| {
            hit(&ITEM, &e.path, e.line, name, format!(
                "RULES has an entry for `{name}`, which is not a DocType of the app: its validation never runs."
            ))
        })
        .collect()
}

fn self_test() -> bool {
    let a = doctype("Part", "");
    let run = |rules: &str| {
        count(
            &ITEM,
            &[
                ("app/m/doctype/part/part.json", &a),
                ("app/validators.py", rules),
            ],
        )
    };
    run("RULES = {\n\t\"Part\": _rule(),\n\t\"Ghost\": _rule(),\n}\n") == Some(1)
        && run("RULES = {\n\t\"Part\": _rule(),\n\t\"User\": _rule(),\n}\n") == Some(0)
}
