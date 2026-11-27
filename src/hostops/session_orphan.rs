//! `SESSION-TARGET-ORPHAN` (GB-235): a unit wanted by `graphical-session.target` never starts
//! when nothing in the tree activates that target.

use super::{SourceFile, case, file_name, fixture, unit_entries, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "SESSION-TARGET-ORPHAN";
const TARGET: &str = "graphical-session.target";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Unit Wanted By A Session Target Nobody Activates",
    severity: "WARNING",
    tag: "homelab",
    summary: "A unit declares WantedBy=graphical-session.target and the tree holds no activator: no `uwsm start`/`uwsm app` reference and no unit with BindsTo= or Wants= on the target.",
    rationale: "GB-235: hypr-session-save.service depends on graphical-session.target, which on psicopompo is activated only by the uwsm wayland-session@ unit; without a session manager the unit is silently never started.",
    bad_example: "[Install]\nWantedBy=graphical-session.target   # compositor started by hand",
    good_example: "# session started with `uwsm start hyprland.desktop`\n[Install]\nWantedBy=graphical-session.target",
    remediation: "Start the session through uwsm (or bind the target from the compositor unit), or use another target.",
};

fn activates(f: &SourceFile) -> bool {
    if f.path.ends_with(".md") {
        return false;
    }
    let by_unit = f.path.ends_with(".service")
        && unit_entries(&f.content)
            .iter()
            .any(|e| e.1 == "BindsTo" && e.2.split_whitespace().any(|w| w == TARGET));
    by_unit
        || f.content.lines().any(|l| {
            let l = l.trim();
            !(l.starts_with('#') || l.starts_with("--"))
                && (l.contains("uwsm start") || l.contains("uwsm app"))
        })
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    if files.iter().any(activates) {
        return Vec::new();
    }
    files
        .iter()
        .filter(|f| f.path.ends_with(".service"))
        .filter_map(|f| {
            let e = unit_entries(&f.content)
                .into_iter()
                .find(|e| e.1 == "WantedBy" && e.2.split_whitespace().any(|w| w == TARGET))?;
            Some(violation(
                RULE_ID,
                Severity::Warning,
                &f.path,
                e.3,
                &format!("WantedBy={}", e.2),
                format!(
                    "{} is wanted by {TARGET}, and nothing in this tree (uwsm or BindsTo=) activates that target",
                    file_name(&f.path)
                ),
                "Start the session through uwsm or bind the target from the compositor unit.",
            ))
        })
        .collect()
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let unit = "[Install]\nWantedBy=graphical-session.target\n";
    vec![
        case(
            "session-orphan: no activator fires",
            lint(&fixture(&[("s.service", unit)])).len() == 1,
        ),
        case(
            "session-orphan: uwsm activator is clean",
            lint(&fixture(&[
                ("s.service", unit),
                ("autostart.lua", "hl.exec_cmd(\"uwsm app -- noctalia\")\n"),
            ]))
            .is_empty(),
        ),
        case(
            "session-orphan: a commented activator still fires",
            lint(&fixture(&[
                ("s.service", unit),
                ("run.sh", "# uwsm start hyprland\n"),
            ]))
            .len()
                == 1,
        ),
    ]
}
