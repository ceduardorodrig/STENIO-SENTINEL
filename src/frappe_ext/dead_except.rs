//! FRAPPE-DEAD-EXCEPT (GB-063).

use super::*;

/// `(exception class, first Frappe major where the framework stopped raising it, source)`.
/// Add a row only after reading the vendor source of that version.
const DEAD: &[(&str, u64, &str)] = &[(
    "DuplicateToDoError",
    15,
    "frappe/desk/form/assign_to.py (version-15 and version-16): the class is declared, `add()` only calls msgprint for a duplicate",
)];

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "FRAPPE-DEAD-EXCEPT",
        name: "Except Clause For An Exception The Framework No Longer Raises",
        severity: "ERROR",
        tag: "frappe",
        summary: "An `except` clause names a Frappe exception that the pinned Frappe major (Dockerfile `BASE_IMAGE`; every version when unpinned) no longer raises. Versioned table: `assign_to.DuplicateToDoError`, dead since Frappe 15.",
        rationale: "GB-063: miracena/peer_cycle.py counted one ToDo per person per run because the `except assign_to.DuplicateToDoError` branch never ran: since Frappe 15 `add()` only prints the duplicate. https://github.com/frappe/frappe/blob/version-15/frappe/desk/form/assign_to.py and .../version-16/... (class declared, never raised; read 2026-11-26).",
        bad_example: "try:\n\tassign_to.add(args)\nexcept assign_to.DuplicateToDoError:\n\tskipped += 1",
        good_example: "if frappe.db.exists(\"ToDo\", {\"reference_name\": name, \"allocated_to\": user, \"status\": \"Open\"}):\n\tskipped += 1\nelse:\n\tassign_to.add(args)",
        remediation: "Test for the condition before the call and delete the dead branch.",
    },
};

fn rule(c: &Ctx) -> Vec<Violation> {
    let major = frappe_major(c);
    let mut out = Vec::new();
    for (path, _, text) in python_under(c, &c.pkg) {
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let head = line.trim_start();
            if !(head.starts_with("except ") || head.starts_with("except(")) {
                continue;
            }
            // The clause may wrap: join up to the closing colon.
            let mut clause = String::new();
            for l in lines.iter().skip(i).take(8) {
                let code = l.split('#').next().unwrap_or("").trim_end();
                clause.push_str(code);
                if code.ends_with(':') {
                    break;
                }
            }
            for (class, since, source) in DEAD {
                let named = clause
                    .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .any(|w| w == *class);
                if named && major.is_none_or(|m| m >= *since) {
                    out.push(hit(
                        &ITEM,
                        &path,
                        i + 1,
                        line,
                        format!(
                            "`except {class}` never runs on Frappe {since} or later ({source})."
                        ),
                    ));
                }
            }
        }
    }
    out
}

fn self_test() -> bool {
    const BAD: &str =
        "def f():\n\ttry:\n\t\tadd()\n\texcept assign_to.DuplicateToDoError:\n\t\tpass\n";
    const WRAPPED: &str = "def f():\n\ttry:\n\t\tadd()\n\texcept (\n\t\tValueError,\n\t\tassign_to.DuplicateToDoError,\n\t):\n\t\tpass\n";
    const GOOD: &str = "def f():\n\t# except assign_to.DuplicateToDoError:\n\ttry:\n\t\tadd()\n\texcept frappe.DuplicateEntryError:\n\t\tpass\n";
    let run = |body: &str, pin: &str| count(&ITEM, &[("app/peer.py", body), ("Dockerfile", pin)]);
    let v16 = "ARG BASE_IMAGE=frappe/erpnext:v16.53.0\n";
    run(BAD, v16) == Some(1)
        && run(WRAPPED, v16) == Some(1)
        && run(BAD, "") == Some(1)
        && run(BAD, "ARG BASE_IMAGE=frappe/erpnext:v14.1.0\n") == Some(0)
        && run(GOOD, v16) == Some(0)
}
