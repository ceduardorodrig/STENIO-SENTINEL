//! `stenio --path <release.sh>`: the order of one release orchestrator, judged on the file alone
//! (GB-165, GB-196). The parsing is `release_order::analyze`; this adds the two rule ids, the exit
//! code and the `--skip-rehearsal` guard, so a copy of the script can be judged without an app tree.

use crate::explain::RuleExplanation;
use std::path::Path;

const BATTERY: &str = "RELEASE-BATTERY-BEFORE-TAG";
const PUBLISH: &str = "RELEASE-TAG-PUBLISHED-AFTER-REHEARSAL";

pub(crate) static EXPLANATIONS: &[RuleExplanation] = &[
    RuleExplanation {
        id: BATTERY,
        name: "Release Number Spent Before The Static Battery (one script)",
        severity: "ERROR",
        tag: "frappe",
        summary: "`stenio --path <dir>/release.sh`: a tag push, image build, version bump or tag creation above the `release-checks.sh` call, or no such call, exits 1 naming the lines.",
        rationale: "GB-165: rc117 and rc119 spent their numbers on a 17 s offline battery that ran after the tag push.",
        bad_example: "git push origin \"refs/tags/\"\nrelease-checks.sh --no-pre \"\"",
        good_example: "release-checks.sh --no-pre \"\" || fail checks x\ngit push origin \"refs/tags/\"",
        remediation: "Move the battery call above every step that spends the number.",
    },
    RuleExplanation {
        id: PUBLISH,
        name: "Release Tag Published Before The Rehearsal (one script)",
        severity: "ERROR",
        tag: "frappe",
        summary: "`stenio --path <dir>/release.sh`: a `git push ... refs/tags` above the `rehearse.sh` run (both lines named), no rehearsal run at all, or a rehearsal skip that no `TEXT-ONLY || fail` line restricts, exits 1.",
        rationale: "GB-196: a red rehearsal after the push spends a public release number.",
        bad_example: "git push origin \"refs/tags/\"\nbash rehearse.sh \"\"",
        good_example: "bash rehearse.sh \"\"\ngit push origin \"refs/tags/\"",
        remediation: "Build from a candidate branch, rehearse, then publish the tag.",
    },
];

/// `(rule id, line, message)` of every problem, plus the notes a passing run prints.
fn judge(text: &str) -> (Vec<(&'static str, usize, String)>, Vec<String>) {
    let order = crate::release_order::analyze(text);
    let mut errors: Vec<(&str, usize, String)> = Vec::new();
    let mut notes = Vec::new();
    errors.extend(
        order
            .errors
            .into_iter()
            .map(|f| (BATTERY, f.line, f.message)),
    );
    errors.extend(
        order
            .rehearsal
            .into_iter()
            .map(|f| (PUBLISH, f.line, f.message)),
    );
    // A pattern the parser cannot find leaves the order unproven: this gate fails closed.
    errors.extend(order.inert.into_iter().map(|f| {
        let id = if f.message.contains("rehearse.sh") {
            PUBLISH
        } else {
            BATTERY
        };
        (id, f.line, f.message)
    }));
    let code: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim_start()))
        .filter(|(_, l)| !l.starts_with('#'))
        .collect();
    if let Some((line, _)) = code
        .iter()
        .find(|(_, l)| l.contains("((SKIP_REHEARSAL))") || l.contains("$SKIP_REHEARSAL"))
    {
        if code
            .iter()
            .any(|(n, l)| n >= line && l.contains("== TEXT-ONLY") && l.contains("|| fail"))
        {
            notes.push(format!(
                "line {line}: --skip-rehearsal is refused unless the scope is TEXT-ONLY (the run reports the rehearsal as skipped)"
            ));
        } else {
            errors.push((
                PUBLISH,
                *line,
                format!("line {line} can skip the rehearsal and no later line refuses a scope other than TEXT-ONLY (`[[ $SCOPE == TEXT-ONLY ]] || fail ...`)."),
            ));
        }
    }
    (errors, notes)
}

/// Judges `path` when it is a file named `release.sh`; None for anything else.
pub fn run_path(path: &Path) -> Option<i32> {
    if !path.is_file() || path.file_name()? != "release.sh" {
        return None;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ERROR {}: {e}", path.display());
            return Some(2);
        }
    };
    if !text.contains("release-checks.sh") && !text.contains("refs/tags") {
        return None;
    }
    let (errors, notes) = judge(&text);
    for (id, line, message) in &errors {
        println!("ERROR [{id}] {}:{line} {message}", path.display());
    }
    for n in notes {
        println!("NOTE {n}");
    }
    println!("release order: {} error(s)", errors.len());
    Some(i32::from(!errors.is_empty()))
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    const GOOD: &str = "release-checks.sh --no-pre v\nif ((SKIP_REHEARSAL)); then\n  [[ $SCOPE == TEXT-ONLY ]] || fail rehearse x\nelse\n  ssh host \"bash /tmp/rehearse.sh v\"\nfi\ngit push origin \"refs/tags/v\"\n";
    let ids = |t: &str| -> Vec<&str> { judge(t).0.into_iter().map(|e| e.0).collect() };
    let early_tag = format!("git push origin \"refs/tags/v\"\n{GOOD}");
    let before_rehearsal =
        "release-checks.sh --no-pre v\ngit push origin \"refs/tags/v\"\nbash rehearse.sh v\n";
    let unguarded = GOOD.replace("  [[ $SCOPE == TEXT-ONLY ]] || fail rehearse x\n", "  :\n");
    let both_lines = judge(before_rehearsal)
        .0
        .iter()
        .any(|(_, _, m)| m.contains("line 2") && m.contains("line 3"));
    vec![
        (
            "release-file: the correct order passes and reports the TEXT-ONLY skip".into(),
            ids(GOOD).is_empty() && judge(GOOD).1.len() == 1,
        ),
        (
            "release-file: mutation, a tag pushed before the battery fails".into(),
            ids(&early_tag).contains(&BATTERY),
        ),
        (
            "release-file: mutation, a tag pushed before the rehearsal fails naming both lines"
                .into(),
            ids(before_rehearsal) == vec![PUBLISH] && both_lines,
        ),
        (
            "release-file: mutation, an unguarded rehearsal skip fails".into(),
            ids(&unguarded) == vec![PUBLISH],
        ),
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_release_file_gate_proves_itself() {
        for (name, ok) in super::self_test_cases() {
            assert!(ok, "{name}");
        }
    }
}
