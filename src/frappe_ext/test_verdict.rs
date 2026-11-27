//! FRAPPE-TEST-VERDICT (GB-057).

use super::*;

pub(super) static ITEM: Item = Item {
    severity: Severity::Error,
    rule,
    self_test,
    explain: RuleExplanation {
        id: "FRAPPE-TEST-VERDICT",
        name: "Site Test Without A Verdict Line And A Failing Exit",
        severity: "ERROR",
        tag: "frappe",
        summary: "Every module of the rehearsal list (or, without a reachable rehearsal script, every `tests/*.py` with `run()` that has half of the contract) must, inside `run()`, print `<module> OK` or `<module> N FAILED` and raise `SystemExit(1)` (or `sys.exit(1 ...)`) on failure.",
        rationale: "GB-057: rehearse.sh accepted a module whose log had no Traceback/FAIL; 12 of 18 modules printed 'expected X, got Y' and exited 0, so '18 module(s) green' proved nothing. FRAPPE-REHEARSAL-VERDICT holds the script side; this holds the module side.",
        bad_example: "def run():\n\tprint(\"\\n\".join(failures) or \"all good\")",
        good_example: "def run():\n\tprint(\"w4 \" + (\"OK\" if not failures else f\"{len(failures)} FAILED\"))\n\tif failures:\n\t\traise SystemExit(1)",
        remediation: "End `run()` with the `<module> OK` / `<module> N FAILED` print and `raise SystemExit(1)` on failure.",
    },
};

/// `(0-based line, text)` of the top-level `def run(` block.
fn run_body(text: &str) -> Option<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let (s, e) = functions(&lines)
        .into_iter()
        .find(|(s, _)| lines[*s].starts_with("def run("))?;
    let code: Vec<&str> = lines[s..e]
        .iter()
        .copied()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect();
    Some((s, code.join("\n")))
}

fn rule(c: &Ctx) -> Vec<Violation> {
    let listed: Option<Vec<String>> = super::super::rehearsal_script(c)
        .and_then(|p| super::super::rehearsal_modules(&super::super::read(&p)))
        .map(|m| m.into_iter().map(|(name, _)| name).collect());
    let mut out = Vec::new();
    for (path, file, text) in test_modules(c) {
        let Some(module) = file.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some((at, body)) = run_body(&text) else {
            continue;
        };
        let verdict = body.contains("print(")
            && (body.contains(&format!("\"{module} ")) || body.contains(&format!("{module} OK")))
            && body.contains("OK")
            && body.contains("FAILED");
        let exits = body.contains("SystemExit(1") || body.contains("sys.exit(1");
        let in_scope = match &listed {
            Some(l) => l.iter().any(|m| m == module),
            None => verdict || exits,
        };
        if !in_scope || (verdict && exits) {
            continue;
        }
        let missing = match (verdict, exits) {
            (false, false) => "neither the `<module> OK / N FAILED` print nor `SystemExit(1)`",
            (false, true) => "no `<module> OK / N FAILED` print",
            _ => "no `raise SystemExit(1)` on failure",
        };
        out.push(hit(
            &ITEM,
            &path,
            at + 1,
            "def run(",
            format!(
                "`{module}.run()` has {missing}: the rehearsal cannot tell a failure from a pass."
            ),
        ));
    }
    out
}

fn self_test() -> bool {
    const SCRIPT: &str = "TESTS=(w4)\nfor t in \"${TESTS[@]}\"; do\n  :\ndone\n";
    const GOOD: &str = "def run():\n\tprint(\"w4 \" + (\"OK\" if not f else f\"{len(f)} FAILED\"))\n\tif f:\n\t\traise SystemExit(1)\n";
    const NO_PRINT: &str = "def run():\n\tif f:\n\t\traise SystemExit(1)\n";
    const NO_EXIT: &str =
        "def run():\n\tprint(\"w4 \" + (\"OK\" if not f else f\"{len(f)} FAILED\"))\n";
    const NEITHER: &str = "def run():\n\tprint(\"done\")\n";
    let run = |body: &str, script: &str| {
        count(
            &ITEM,
            &[("app/tests/w4.py", body), ("scripts/rehearse.sh", script)],
        )
    };
    let unlisted = "TESTS=(other)\nfor t in \"${TESTS[@]}\"; do\n  :\ndone\n";
    run(GOOD, SCRIPT) == Some(0)
        && run(NO_PRINT, SCRIPT) == Some(1)
        && run(NO_EXIT, SCRIPT) == Some(1)
        && run(NEITHER, SCRIPT) == Some(1)
        && run(NEITHER, unlisted) == Some(0)
        && count(&ITEM, &[("app/tests/w4.py", NO_PRINT)]) == Some(1)
}
