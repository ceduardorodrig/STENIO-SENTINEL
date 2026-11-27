//! TEST-NO-MASKED-LITERAL (GB-061).

use super::*;
use regex::Regex;

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "TEST-NO-MASKED-LITERAL",
        name: "Masked Literal Used As Test Data",
        severity: "ERROR",
        tag: "frappe",
        summary: "A quoted string in a Python module under `<app>/tests` carries a redaction mask: four or more asterisks, three or more asterisks glued to a digit, letter, `+` or `@`, or an upper-case `[REDACTED]`.",
        rationale: "GB-061: tests/validation.py passed the masked phone `+556****3546` as input. The module then reported 'contact normalised: Commercial Contact was refused', a defect of the test data, found only by the rehearsal. A literal copied from a masked log is never real input.",
        bad_example: "phone = \"+556****3546\"",
        good_example: "phone = \"+5561999993546\"  # a synthetic number, not a masked one",
        remediation: "Replace the masked literal with a synthetic but well-formed value.",
    },
};

fn rule(c: &Ctx) -> Vec<Violation> {
    let (Ok(literal), Ok(mask)) = (
        Regex::new(r#""([^"\\]|\\.)*"|'([^'\\]|\\.)*'"#),
        Regex::new(r"\*{4,}|[A-Za-z0-9+@_-]\*{3,}|\*{3,}[A-Za-z0-9@]|\[REDACTED\]"),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (path, _, text) in test_modules(c) {
        for (i, line) in text.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            if let Some(m) = literal.find_iter(line).find(|m| mask.is_match(m.as_str())) {
                out.push(hit(
                    &ITEM,
                    &path,
                    i + 1,
                    m.as_str(),
                    "a test literal carries a redaction mask: the code under test receives data that never existed.".into(),
                ));
            }
        }
    }
    out
}

fn self_test() -> bool {
    let run = |body: &str| count(&ITEM, &[("app/tests/validation.py", body)]);
    run("phone = \"+556****3546\"\n") == Some(1)
        && run("key = 'sk-***'\n") == Some(1)
        && run("pad = \"****\"\n") == Some(1)
        && run(
            "phone = \"+5561999993546\"\nnote = \"** bold **\"\n# \"+556****3546\"\nr = r\"\\*{4}\"\n",
        ) == Some(0)
}
