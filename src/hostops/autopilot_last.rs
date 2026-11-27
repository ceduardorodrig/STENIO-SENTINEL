//! `AUTOPILOT-LAST-PUBLISH` (GB-175): when did the pipeline last publish, from its run journals.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use super::{case, opt, unreadable};
use crate::explain::RuleExplanation;

pub const RULE_ID: &str = "AUTOPILOT-LAST-PUBLISH";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Pipeline Silent Or Failing Since Its Last Publication",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops autopilot-last --dir var/runs [--max-age-h 36]` reads the JSONL run journals ({at_unix, persona, stage, status}). Exit 0 and no output when the newest `published` record is fresh and no active persona has an error newer than its last publication; 2 when stale or failing; 1 when unreadable (the exit codes the item asked for). Time comes from at_unix, never from file mtime.",
    rationale: "GB-175: deciding whether the social-media pipeline was silent took a hand-written search over 418 journals, and mtime disagreed with at_unix.",
    bad_example: "newest published record 50 h old",
    good_example: "published 3 h ago, no later error",
    remediation: "Read the journal of the named persona and stage.",
};

#[derive(Deserialize)]
struct Record {
    at_unix: u64,
    #[serde(default)]
    persona: String,
    #[serde(default)]
    stage: String,
    #[serde(default)]
    status: String,
}

fn iso(at: u64) -> String {
    chrono::DateTime::from_timestamp(at as i64, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| at.to_string())
}

/// (exit code, lines) over the text of all journals.
pub fn evaluate(journals: &[String], now: u64, max_age_h: u64) -> (i32, Vec<String>) {
    let records: Vec<Record> = journals
        .iter()
        .flat_map(|j| j.lines())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if records.is_empty() {
        return (2, vec!["no journal record found".to_string()]);
    }
    let window = max_age_h.saturating_mul(3600);
    let mut published: BTreeMap<&str, u64> = BTreeMap::new();
    for r in records.iter().filter(|r| r.status == "published") {
        let at = published.entry(&r.persona).or_default();
        *at = (*at).max(r.at_unix);
    }
    let mut out = Vec::new();
    match published.iter().max_by_key(|p| p.1) {
        None => out.push("no published record in any journal".to_string()),
        Some((persona, &at)) if now.saturating_sub(at) > window => out.push(format!(
            "stale: newest publication at_unix={at} ({}) persona={persona}, {} h old",
            iso(at),
            now.saturating_sub(at) / 3600
        )),
        Some(_) => {}
    }
    let mut errors: BTreeMap<&str, &Record> = BTreeMap::new();
    for r in records.iter().filter(|r| {
        r.status == "error"
            && now.saturating_sub(r.at_unix) <= window
            && published
                .get(r.persona.as_str())
                .is_none_or(|p| r.at_unix > *p)
    }) {
        let newest = errors.entry(&r.persona).or_insert(r);
        if r.at_unix >= newest.at_unix {
            *newest = r;
        }
    }
    out.extend(errors.values().map(|r| {
        format!(
            "error after the last publication: persona={} stage={} at_unix={} ({})",
            r.persona,
            r.stage,
            r.at_unix,
            iso(r.at_unix)
        )
    }));
    (if out.is_empty() { 0 } else { 2 }, out)
}

pub fn run_cli(args: &[String]) -> i32 {
    let max_age = opt(args, "--max-age-h")
        .and_then(|v| v.parse().ok())
        .unwrap_or(36);
    let Some(dir) = opt(args, "--dir") else {
        unreadable(RULE_ID, "--dir <runs directory> is required");
        return 1;
    };
    let Ok(entries) = std::fs::read_dir(Path::new(&dir)) else {
        unreadable(RULE_ID, format!("cannot read {dir}"));
        return 1;
    };
    let mut journals = Vec::new();
    for e in entries.flatten() {
        if e.path().extension().is_some_and(|x| x == "jsonl") {
            match std::fs::read_to_string(e.path()) {
                Ok(t) => journals.push(t),
                Err(err) => {
                    unreadable(RULE_ID, format!("{}: {err}", e.path().display()));
                    return 1;
                }
            }
        }
    }
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let (code, lines) = evaluate(&journals, now, max_age);
    for l in lines {
        println!("FAIL {RULE_ID} {l}");
    }
    code
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let now = 1_000_000_000u64;
    let rec = |ago_h: u64, status: &str| {
        format!(
            "{{\"at_unix\":{},\"persona\":\"p\",\"stage\":\"publish\",\"status\":\"{status}\"}}\n",
            now - ago_h * 3600
        )
    };
    let run = |s: String| evaluate(&[s], now, 36);
    let stale = run(rec(50, "published"));
    let failing = run(format!("{}{}", rec(5, "published"), rec(1, "error")));
    vec![
        case(
            "autopilot-last: fresh publication exits 0 and prints nothing",
            run(rec(5, "published")) == (0, Vec::new()),
        ),
        case(
            "autopilot-last: stale names the at_unix",
            stale.0 == 2 && stale.1[0].contains(&format!("at_unix={}", now - 180_000)),
        ),
        case(
            "autopilot-last: later error names persona and stage",
            failing.0 == 2 && failing.1[0].contains("persona=p stage=publish"),
        ),
        case(
            "autopilot-last: an error superseded by a publication is clean",
            run(format!("{}{}", rec(6, "error"), rec(5, "published"))).0 == 0,
        ),
        case(
            "autopilot-last: no journal is not age zero",
            evaluate(&[], now, 36).0 == 2,
        ),
    ]
}
