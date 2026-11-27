//! `SYSTEMD-NO-ONFAILURE` (GB-016): a long-running or timer-driven managed unit says who is told
//! when it fails.

use std::collections::BTreeMap;

use super::{case, host_arg, host_run, opt, unreadable, verdict};
use crate::explain::RuleExplanation;

pub const RULE_ID: &str = "SYSTEMD-NO-ONFAILURE";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Managed Unit Without OnFailure=",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops onfailure --host H [--prefix hl-]` reads `systemctl show` for the managed services of H and reports each long-running (Type other than oneshot, active or enabled) or timer-driven unit with an empty OnFailure=. Drop-ins count, template notifiers are excluded.",
    rationale: "GB-016: the 10-hour outage of 2026-11-04 went unnoticed because the failing unit told nobody.",
    bad_example: "[Unit]\nDescription=backup   # no OnFailure=",
    good_example: "[Unit]\nOnFailure=notify-backup-failure@%n.service",
    remediation: "Add OnFailure= to the unit or a drop-in.",
};

/// Findings and the number of units in scope, from blank-line separated `systemctl show` blocks.
pub fn check(show: &str) -> (Vec<String>, usize) {
    let (mut out, mut checked) = (Vec::new(), 0);
    for block in show.split("\n\n") {
        let p: BTreeMap<&str, &str> = block.lines().filter_map(|l| l.split_once('=')).collect();
        let get = |k: &str| p.get(k).copied().unwrap_or("");
        let id = get("Id");
        if id.is_empty() || id.contains('@') || get("LoadState") != "loaded" {
            continue;
        }
        let timer = get("TriggeredBy").split(' ').any(|t| t.ends_with(".timer"));
        let long = get("Type") != "oneshot"
            && (get("ActiveState") == "active" || get("UnitFileState") == "enabled");
        if !(timer || long) {
            continue;
        }
        checked += 1;
        if get("OnFailure").is_empty() {
            let why = if timer {
                "timer-driven"
            } else {
                "long-running"
            };
            out.push(format!("{id} is {why} and has no OnFailure="));
        }
    }
    (out, checked)
}

pub fn run_cli(args: &[String]) -> i32 {
    let Some(host) = host_arg(args) else {
        return unreadable(RULE_ID, "--host is required");
    };
    let prefix = opt(args, "--prefix").unwrap_or_else(|| "hl-".to_string());
    if !crate::verify_release::safe(&prefix, "") {
        return unreadable(RULE_ID, "unsafe --prefix");
    }
    let command = format!(
        "systemctl list-unit-files '{prefix}*.service' --no-legend --plain | awk '{{print $1}}' | grep -v '@' | xargs -r systemctl show -p Id -p LoadState -p Type -p ActiveState -p UnitFileState -p TriggeredBy -p OnFailure"
    );
    match host_run(&host, &command) {
        Ok(show) => {
            let (found, checked) = check(&show);
            if checked == 0 {
                return unreadable(RULE_ID, format!("no {prefix}* unit in scope on {host}"));
            }
            verdict(RULE_ID, &host, checked, &found)
        }
        Err(e) => unreadable(RULE_ID, e),
    }
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let unit = |kind: &str, trig: &str, onf: &str| {
        format!(
            "Id=hl-x.service\nLoadState=loaded\nType={kind}\nActiveState=inactive\nUnitFileState=enabled\nTriggeredBy={trig}\nOnFailure={onf}\n"
        )
    };
    vec![
        case(
            "onfailure: timer-driven oneshot without it fails",
            check(&unit("oneshot", "hl-x.timer", "")).0.len() == 1,
        ),
        case(
            "onfailure: long-running without it fails",
            check(&unit("simple", "", "")).0.len() == 1,
        ),
        case(
            "onfailure: managed unit passes",
            check(&unit("simple", "", "notify@x.service")) == (Vec::new(), 1),
        ),
        case(
            "onfailure: manual oneshot is out of scope",
            check(&unit("oneshot", "", "")).1 == 0,
        ),
    ]
}
