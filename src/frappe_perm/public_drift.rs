//! `FRAPPE-PUBLIC-FIELD-DRIFT` (GB-178): personal data left at permlevel 0 on a DocType that is
//! declared public.

use super::{Case, PUBLIC_FILE, Rule, Tree, declarations, doctype_file, int_of, str_of, viol};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

/// Fieldnames (whole, or as a `_` suffix) that hold personal contact or identity data.
const PERSONAL: &[&str] = &[
    "email",
    "e_mail",
    "cpf",
    "rg",
    "phone",
    "mobile",
    "mobile_no",
    "whatsapp",
];

pub static RULE: Rule = Rule {
    id: "FRAPPE-PUBLIC-FIELD-DRIFT",
    name: "Personal Field Readable Through A Public DocType",
    severity: Severity::Error,
    run,
    cases,
    explain: RuleExplanation {
        id: "FRAPPE-PUBLIC-FIELD-DRIFT",
        name: "Personal Field Readable Through A Public DocType",
        severity: "ERROR",
        tag: "frappe",
        summary: "A DocType named in permissions-public.txt keeps an e-mail, CPF, RG or phone field (by fieldname, Email/Phone type, or a Link to User) at permlevel 0, and the field has no `DocType.fieldname  # reason` line of its own.",
        rationale: "GB-178 (2026-11-06): the directory was declared public as name, role and skills, while Member.email and Member.user stayed at permlevel 0 and every member read every colleague's address.",
        bad_example: "# permissions-public.txt: Member  # the directory\n{\"fieldname\": \"email\", \"fieldtype\": \"Data\"}",
        good_example: "{\"fieldname\": \"email\", \"fieldtype\": \"Data\", \"permlevel\": 1}",
        remediation: "Raise the field's permlevel (with read and write rows), or declare `DocType.fieldname  # reason` in permissions-public.txt.",
    },
};

fn personal(f: &serde_json::Value) -> bool {
    let name = str_of(f, "fieldname").to_ascii_lowercase();
    let kind = str_of(f, "fieldtype");
    let options = str_of(f, "options");
    let named = PERSONAL
        .iter()
        .any(|p| name == *p || name.ends_with(&format!("_{p}")));
    match kind {
        "Phone" => true,
        "Link" => options == "User",
        "Data" => named || matches!(options, "Email" | "Phone") || name == "user",
        "Int" | "Small Text" => named,
        _ => false,
    }
}

fn run(t: &Tree) -> Vec<Violation> {
    let public = declarations(t, PUBLIC_FILE);
    let declared = |name: &str| public.iter().any(|d| d.entry == name);
    let mut out = Vec::new();
    for d in t.docs.iter().filter(|d| declared(&d.name)) {
        for f in d.fields() {
            let name = str_of(f, "fieldname");
            if int_of(f, "permlevel") != 0
                || !personal(f)
                || declared(&format!("{}.{name}", d.name))
            {
                continue;
            }
            out.push(viol(
                &RULE,
                &d.rel,
                d.field_line(name),
                &format!("{name} permlevel 0"),
                format!("`{}` is declared public in {PUBLIC_FILE} and `{name}` (personal data) is at permlevel 0: every reader of the DocType reads it.", d.name),
                "Raise the permlevel, or declare `DocType.fieldname  # reason` in permissions-public.txt.",
            ));
        }
    }
    out
}

fn cases() -> Vec<Case> {
    let case = |label, level: u8, public: &str, expect| Case {
        label,
        files: vec![
            doctype_file(
                "Member",
                "",
                &format!(
                    r#"{{"fieldname":"email","fieldtype":"Data","permlevel":{level}}},{{"fieldname":"user","fieldtype":"Link","options":"User","permlevel":{level}}},{{"fieldname":"bio","fieldtype":"Small Text"}}"#
                ),
                "",
            ),
            ("demoapp/permissions-public.txt".into(), public.into()),
        ],
        validated: &[],
        expect,
    };
    vec![
        case(
            "restricted contact fields are accepted",
            1,
            "Member # directory\n",
            0,
        ),
        case(
            "fields declared public one by one are accepted",
            0,
            "Member # directory\nMember.email # work address\nMember.user # work login\n",
            0,
        ),
        case(
            "a DocType that is not declared public is not judged",
            0,
            "Tag # x\n",
            0,
        ),
        case(
            "e-mail and User link at level 0 fire",
            0,
            "Member # directory\n",
            2,
        ),
    ]
}
