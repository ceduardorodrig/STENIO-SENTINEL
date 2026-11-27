//! FRAPPE-SIDEBAR-ALLOWLIST-PARITY (GB-027).

use super::*;

pub(super) static ITEM: Item = Item {
    severity: Severity::Warning,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "FRAPPE-SIDEBAR-ALLOWLIST-PARITY",
        name: "Second No-Sidebar List Diverges From The Allowlist File",
        severity: "WARNING",
        tag: "frappe",
        summary: "A `NO_SIDEBAR` collection in a test module names a DocType that the `[frappe] sidebar_allowlist` file lacks.",
        rationale: "GB-027: rc76 burned on two copies of the no-sidebar allowlist (the rule's file and tests/release_baseline.py): each was right for its own reader.",
        bad_example: "# stenio-sidebar-allowlist.txt: Climate Receipt | reason\nNO_SIDEBAR = {\"Climate Receipt\": \"...\", \"Climate Response\": \"...\"}",
        good_example: "NO_SIDEBAR = dict(line.split(\"|\", 1) for line in ALLOWLIST.read_text().splitlines() if \"|\" in line)",
        remediation: "Make the test read the allowlist file, or add the missing line (with its reason) to it.",
    },
};

fn rule(c: &Ctx) -> Vec<Violation> {
    let Some(file) = &c.cfg.sidebar_allowlist else {
        return Vec::new();
    };
    let allow: Vec<String> = super::super::read(&c.root.join(file))
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(['|', '#']).next().unwrap_or("").trim().to_string())
        .collect();
    let mut out = Vec::new();
    for (path, _, text) in test_modules(c) {
        for (line, name) in no_sidebar_names(&text) {
            if !allow.contains(&name) {
                out.push(hit(
                    &ITEM,
                    &path,
                    line,
                    &name,
                    format!("NO_SIDEBAR exempts `{name}` but `{file}` does not list it: the two allowlists diverge."),
                ));
            }
        }
    }
    out
}

/// `(line, name)` of the entries of a module-level `NO_SIDEBAR` literal.
pub(super) fn no_sidebar_names(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let Some(start) = text
        .match_indices("NO_SIDEBAR")
        .find(|(i, _)| {
            (*i == 0 || text[..*i].ends_with('\n'))
                && text[*i..]
                    .lines()
                    .next()
                    .is_some_and(|l| l.contains('=') && l.contains(['{', '[', '(']))
        })
        .map(|(i, _)| i)
    else {
        return out;
    };
    for (offset, name) in super::privacy_lists::literal_names(&text[start..]) {
        let line = text[..start + offset].matches('\n').count() + 1;
        out.push((line, name));
    }
    out
}

fn self_test() -> bool {
    let cfg = FrappeConfig {
        sidebar_allowlist: Some("allow.txt".into()),
        ..FrappeConfig::default()
    };
    let run = |test: &str| {
        probe(
            &ITEM,
            &cfg,
            &[
                ("allow.txt", "# list\nClimate Receipt | anonymous\n"),
                ("app/tests/baseline.py", test),
            ],
        )
        .map(|v| v.len())
    };
    run(
        "NO_SIDEBAR = {\n\t\"Climate Receipt\": \"proof, never listed\",\n\t\"Climate Response\": \"anonymous\",\n}\n",
    ) == Some(1)
        && run("NO_SIDEBAR = {\"Climate Receipt\": \"proof\"}\n") == Some(0)
        && run("x = 1\n") == Some(0)
}
