//! Release orchestrator step order (GB-165, GB-214, detector half of GB-196).
//!
//! Pure text parsing of the release script, with line numbers and no network: the order of the
//! calls decides whether a release number is spent on a check that needed no network.
//!   1. the offline static battery (`release-checks.sh`) runs before any `git push ... refs/tags`
//!      and before the image build (GB-165 / GB-157);
//!   2. the version bump and the tag creation come only after the battery (GB-214);
//!   3. the tag push comes after the rehearsal (GB-196). That one is a WARNING: the real fix is a
//!      release.sh + Dockerfile change, so the detector reports it without blocking.
//! Echo lines (`say`, `note`, `pass`, `fail`, `echo`, `printf`) and comments are not calls.

use regex::Regex;

/// One ordering problem: the line it is reported on and a message.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub line: usize,
    pub message: String,
}

/// Findings split by severity: `errors` (battery/bump/tag order), `rehearsal` (GB-196, a
/// warning), `inert` (a pattern was not found, so the order cannot be judged).
#[derive(Debug, Default)]
pub struct Order {
    pub errors: Vec<Finding>,
    pub rehearsal: Vec<Finding>,
    pub inert: Vec<Finding>,
}

fn is_call(line: &str) -> bool {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return false;
    }
    let word = t.split_whitespace().next().unwrap_or("");
    !matches!(word, "say" | "note" | "pass" | "fail" | "echo" | "printf")
}

/// Judges the order of the calls of a release script.
pub fn analyze(text: &str) -> Order {
    let mut out = Order::default();
    let (Ok(battery), Ok(push), Ok(create), Ok(bump), Ok(build), Ok(rehearse)) = (
        Regex::new(r"release-checks\.sh"),
        Regex::new(r"\bgit\s+(?:-C\s+\S+\s+)?push\b.*(?:refs/tags|--tags)"),
        Regex::new(r"\bgit\s+(?:-C\s+\S+\s+)?tag\s+(?:-[asfm]\b|[^-\s])"),
        Regex::new(r"\b(?:sd|sed)\b.*__version__"),
        Regex::new(r"\bdocker\s+(?:buildx\s+)?build\b"),
        Regex::new(r"rehearse\.sh"),
    ) else {
        return out;
    };
    let calls: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| is_call(l))
        .map(|(i, l)| (i + 1, l))
        .collect();
    let first = |re: &Regex| calls.iter().find(|(_, l)| re.is_match(l)).map(|c| c.0);
    let all = |re: &Regex| -> Vec<usize> {
        calls
            .iter()
            .filter(|(_, l)| re.is_match(l))
            .map(|c| c.0)
            .collect()
    };
    let Some(bat) = first(&battery) else {
        out.inert.push(Finding {
            line: 1,
            message: "no call to release-checks.sh was found in the release script: whether the offline static battery runs before the tag is published is unverified.".into(),
        });
        return out;
    };
    for (what, lines) in [
        ("the tag push (`git push ... refs/tags`)", all(&push)),
        ("the image build (`docker build`)", all(&build)),
    ] {
        if let Some(l) = lines.into_iter().find(|l| *l < bat) {
            out.errors.push(Finding {
                line: l,
                message: format!("{what} at line {l} runs before the static battery (release-checks.sh, line {bat}): a red offline check would still spend the release number (GB-165/GB-157)."),
            });
        }
    }
    for (what, lines) in [
        ("the `__version__` bump", all(&bump)),
        ("the tag creation (`git tag`)", all(&create)),
    ] {
        if let Some(l) = lines.into_iter().find(|l| *l < bat) {
            out.errors.push(Finding {
                line: l,
                message: format!("{what} at line {l} comes before the static battery (line {bat}): the number must be written only after a green battery (RELEASE-NUMBER-ONLY-AFTER-GREEN, GB-214)."),
            });
        }
    }
    match (all(&push).first().copied(), first(&rehearse)) {
        (Some(p), Some(r)) if p < r => out.rehearsal.push(Finding {
            line: p,
            message: format!("the tag is pushed at line {p} before the rehearsal call at line {r}: a red rehearsal still spends the published number (GB-196, WARNING: the fix is a release.sh + Dockerfile change, not yet done)."),
        }),
        (_, None) => out.inert.push(Finding {
            line: 1,
            message: "no call to rehearse.sh was found: the tag-before-rehearsal order (GB-196) is unverified.".into(),
        }),
        _ => {}
    }
    out
}

const GOOD: &str = "#!/usr/bin/env bash\nsay \"+ release-checks.sh dry\"\nrelease-checks.sh --no-pre \"$VTAG\" || fail checks x\nsd '^__version__' '__version__ = \"1\"' v.py\ngit tag -a \"$VTAG\" -m m\nbash /tmp/rehearse.sh \"$IMG\"\ngit push origin \"refs/tags/$VTAG\"\n";

fn mutate(from: &str, to: &str) -> String {
    GOOD.replace(from, to)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let tag_first = "git push origin \"refs/tags/$VTAG\"\nrelease-checks.sh --no-pre \"$VTAG\" || fail checks x\n";
    let battery_after_push = mutate(
        "release-checks.sh --no-pre \"$VTAG\" || fail checks x\n",
        "",
    )
    .replace("git push origin \"refs/tags/$VTAG\"\n", tag_first);
    let bump_first = format!(
        "#!/usr/bin/env bash\nsd '^__version__' '__version__ = \"1\"' v.py\n{}",
        GOOD.replace("sd '^__version__' '__version__ = \"1\"' v.py\n", "")
            .trim_start_matches("#!/usr/bin/env bash\n")
    );
    let push_before_rehearse = GOOD
        .replace("git push origin \"refs/tags/$VTAG\"\n", "")
        .replace(
            "bash /tmp/rehearse.sh \"$IMG\"\n",
            "git push origin \"refs/tags/$VTAG\"\nbash /tmp/rehearse.sh \"$IMG\"\n",
        );
    let g = analyze(GOOD);
    let a = analyze(&battery_after_push);
    let b = analyze(&bump_first);
    let r = analyze(&push_before_rehearse);
    vec![
        (
            "release-order: good order is silent".into(),
            g.errors.is_empty() && g.rehearsal.is_empty() && g.inert.is_empty(),
        ),
        (
            "release-order: battery after tag push is an error".into(),
            !a.errors.is_empty(),
        ),
        (
            "release-order: bump before battery is an error".into(),
            b.errors.iter().any(|f| f.message.contains("bump")),
        ),
        (
            "release-order: tag before rehearsal is only a warning".into(),
            r.errors.is_empty() && !r.rehearsal.is_empty(),
        ),
        (
            "release-order: no battery call is inert".into(),
            analyze("echo hi\n").inert.len() == 1,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_cases_all_pass() {
        for (name, ok) in self_test_cases() {
            assert!(ok, "{name}");
        }
    }

    #[test]
    fn echo_lines_and_comments_are_not_calls() {
        let t = "# git push origin refs/tags/x\nsay \"+ git push origin refs/tags/x\"\nrelease-checks.sh\nbash rehearse.sh\ngit push origin refs/tags/x\n";
        let o = analyze(t);
        assert!(o.errors.is_empty() && o.rehearsal.is_empty(), "{o:?}");
    }

    #[test]
    fn tag_listing_and_rev_parse_are_not_creation() {
        let t = "git -C r tag --sort=-v:refname\ngit tag -l\nrelease-checks.sh\n";
        assert!(analyze(t).errors.is_empty());
        let t2 = "git -C r tag -a \"$V\" -m m\nrelease-checks.sh\n";
        assert_eq!(analyze(t2).errors.len(), 1);
    }

    #[test]
    fn a_message_that_says_tag_is_not_a_tag_creation() {
        let t = "git -C r rev-parse --verify -q \"$P\" || fail pre \"previous tag $P does not exist\"\nrelease-checks.sh\n";
        assert!(analyze(t).errors.is_empty());
    }

    #[test]
    fn build_before_battery_is_an_error_with_both_lines() {
        let o = analyze("docker build -t x .\nrelease-checks.sh\n");
        assert_eq!(o.errors.len(), 1);
        assert_eq!(o.errors[0].line, 1);
        assert!(o.errors[0].message.contains("line 2"));
    }
}
