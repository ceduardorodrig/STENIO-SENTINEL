//! `BOOT-ABRUPT-END-AUDIT` (GB-155): boots that ended without a clean shutdown record.

use chrono::{DateTime, FixedOffset};

use super::{case, host_arg, host_run, opt, unreadable, verdict};
use crate::explain::RuleExplanation;

pub const RULE_ID: &str = "BOOT-ABRUPT-END-AUDIT";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Boot Ended Without A Clean Shutdown",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops boots --host H [--since YYYY-MM-DD]` pairs the `reboot` and `shutdown` records of `last -x --time-format iso`: a boot with no shutdown record before the next boot ended abruptly. Prints boot time, next boot, uptime bound and the last journal line when the journal still holds that boot. Exit 0 when every boot ended cleanly.",
    rationale: "GB-155: telling a power cut from a hang on kuaray needed 34 wtmp boots paired by hand; 6 of the last 7 since 2026-10-04 were abrupt.",
    bad_example: "reboot 10-05 ... (no shutdown record) reboot 10-06",
    good_example: "reboot 10-05 ... shutdown 10-06 02:00 ... reboot 10-06 02:01",
    remediation: "Read the last journal lines of the listed boot; check power and hardware.",
};

type When = DateTime<FixedOffset>;

/// (boot start, next boot start) of every boot that ended without a shutdown record.
pub fn abrupt(last: &str) -> (Vec<(When, When)>, usize) {
    let mut boots = Vec::new();
    let mut downs = Vec::new();
    for line in last.lines() {
        let kind = line.split_whitespace().next().unwrap_or("");
        let time = line
            .split_whitespace()
            .find_map(|w| DateTime::parse_from_rfc3339(w).ok());
        match (kind, time) {
            ("reboot", Some(t)) => boots.push(t),
            ("shutdown", Some(t)) => downs.push(t),
            _ => {}
        }
    }
    boots.sort();
    let found = boots
        .windows(2)
        .filter(|w| !downs.iter().any(|d| *d >= w[0] && *d <= w[1]))
        .map(|w| (w[0], w[1]))
        .collect();
    (found, boots.len())
}

pub fn run_cli(args: &[String]) -> i32 {
    let Some(host) = host_arg(args) else {
        return unreadable(RULE_ID, "--host is required");
    };
    let since = opt(args, "--since").unwrap_or_default();
    let last = match host_run(&host, "last -x --time-format iso reboot shutdown") {
        Ok(s) => s,
        Err(e) => return unreadable(RULE_ID, e),
    };
    let (found, total) = abrupt(&last);
    if total == 0 {
        return unreadable(RULE_ID, "no reboot record in wtmp");
    }
    let mut lines = Vec::new();
    for (start, next) in found {
        if start.format("%Y-%m-%d").to_string() < since {
            continue;
        }
        // The journal entry just before the next boot belongs to the boot that ended.
        let journal = format!(
            "journalctl --since @{} --until @{} -n 1 -o short-iso --no-pager -q",
            start.timestamp(),
            next.timestamp() - 1
        );
        let tail = host_run(&host, &journal)
            .ok()
            .and_then(|s| {
                s.lines()
                    .last()
                    .map(|l| l.chars().take(180).collect::<String>())
            })
            .unwrap_or_else(|| "no journal entry kept for this boot".to_string());
        let hours = (next - start).num_minutes() as f64 / 60.0;
        lines.push(format!(
            "{host} boot {} ended abruptly; next boot {} ({hours:.1} h later); last log: {tail}",
            start.to_rfc3339(),
            next.to_rfc3339()
        ));
    }
    verdict(RULE_ID, &host, total, &lines)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let rec =
        |k: &str, t: &str| format!("{k:8} system x 7.0 2026-10-{t}:00-03:00   still running\n");
    let cut = [rec("reboot", "05T18:00"), rec("reboot", "04T14:00")].concat();
    let clean = [
        rec("reboot", "05T18:00"),
        rec("shutdown", "05T17:59"),
        rec("reboot", "04T14:00"),
    ]
    .concat();
    vec![
        case(
            "boots: missing shutdown record is abrupt",
            abrupt(&cut).0.len() == 1 && abrupt(&cut).1 == 2,
        ),
        case("boots: clean shutdown passes", abrupt(&clean).0.is_empty()),
        case(
            "boots: unreadable input has no boot",
            abrupt("wtmp begins\n").1 == 0,
        ),
    ]
}
