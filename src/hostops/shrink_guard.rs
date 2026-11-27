//! `SESSION-SAVE-SHRINK-GUARD` (GB-236): a session saver must not replace a large snapshot with a
//! much smaller one taken from a degraded live state.

use regex::Regex;

use super::{SourceFile, case, file_name, fixture, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "SESSION-SAVE-SHRINK-GUARD";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Session Snapshot Overwritten Without A Shrink Guard",
    severity: "WARNING",
    tag: "gaming",
    summary: "A script that reads live window state (hyprctl clients) and writes a session JSON has neither a size comparison against the previous snapshot nor an explicit accept-shrink flag.",
    rationale: "GB-236: on 2026-11-08 hypr-session-save, driven by a 2-minute timer, replaced a 6-entry saved-session.json with a 1-entry list; the good copy survived only in the 05:00 mirror.",
    bad_example: "hyprctl clients -j | jq ... > \"$tmp\"; mv \"$tmp\" \"$HOME/.config/hypr/saved-session.json\"",
    good_example: "new=$(jq length \"$tmp\"); old=$(jq length \"$SESSION\")\n(( new * 2 < old )) && [ -z \"$ACCEPT_SHRINK\" ] && exit 0\nmv \"$tmp\" \"$SESSION\"",
    remediation: "Refuse to replace N entries with fewer than N/2 unless an accept-shrink flag is given.",
};

fn code_lines(content: &str) -> impl Iterator<Item = (usize, &str)> {
    content
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.starts_with('#'))
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let (Ok(session_var), Ok(guard)) = (
        Regex::new(r#"^(?:local\s+)?(\w+)=.*session[\w.-]*\.json"#),
        Regex::new(
            r"(?i)accept.?shrink|allow.?shrink|(?:old|prev|previous|saved)\w*\b[^\n]*(?:-lt|-le|-gt|-ge|[<>])[^\n]*\d|(?:new|count)\w*\b[^\n]*(?:-lt|-le|<)\s*[^\n]*(?:old|prev|saved)",
        ),
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in files.iter().filter(|f| f.content.starts_with("#!")) {
        let live =
            code_lines(&f.content).any(|(_, l)| l.contains("hyprctl") && l.contains("clients"));
        if !live || code_lines(&f.content).any(|(_, l)| guard.is_match(l)) {
            continue;
        }
        let mut targets: Vec<String> = Vec::new();
        for (_, l) in code_lines(&f.content) {
            if let Some(c) = session_var.captures(l) {
                targets.push(format!("${}", &c[1]));
                targets.push(format!("${{{}}}", &c[1]));
            }
        }
        let write = code_lines(&f.content).find(|(_, l)| {
            let sink = l.starts_with("mv ") || l.starts_with("cp ") || l.contains('>');
            let named = l.contains("session") && l.contains(".json");
            sink && !session_var.is_match(l)
                && (named
                    || targets.iter().any(|t| {
                        l.contains(&format!("> {t}"))
                            || l.contains(&format!("> \"{t}\""))
                            || ((l.starts_with("mv ") || l.starts_with("cp "))
                                && l.trim_end_matches('"').ends_with(t.as_str()))
                    }))
        });
        if let Some((line, text)) = write {
            out.push(violation(
                RULE_ID,
                Severity::Warning,
                &f.path,
                line,
                text,
                format!(
                    "{} overwrites the session snapshot from live state with no shrink guard",
                    file_name(&f.path)
                ),
                "Refuse to replace N entries with fewer than N/2 unless an accept-shrink flag is set.",
            ));
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let bad = "#!/bin/sh\nFILE=\"$HOME/.config/hypr/saved-session.json\"\nhyprctl clients -j > \"$tmp\"\n[ -s \"$tmp\" ] && mv \"$tmp\" \"$FILE\"\nmv \"$tmp\" \"$FILE\"\n";
    let good = "#!/bin/sh\nFILE=\"$HOME/saved-session.json\"\nhyprctl clients -j > \"$tmp\"\nnew=$(jq length \"$tmp\"); old=$(jq length \"$FILE\")\n[ $((new * 2)) -lt \"$old\" ] && exit 0\nmv \"$tmp\" \"$FILE\"\n";
    let n = |s: &str| lint(&fixture(&[("bin/hypr-session-save", s)])).len();
    vec![
        case("shrink-guard: unguarded saver fires", n(bad) == 1),
        case("shrink-guard: guarded saver is clean", n(good) == 0),
        case(
            "shrink-guard: removing the guard line fires again",
            n(&good.replace("[ $((new * 2)) -lt \"$old\" ] && exit 0\n", "")) == 1,
        ),
        case(
            "shrink-guard: a restore script that only reads is clean",
            n("#!/bin/sh\nhyprctl clients -j\njq . \"$HOME/saved-session.json\"\n") == 0,
        ),
    ]
}
