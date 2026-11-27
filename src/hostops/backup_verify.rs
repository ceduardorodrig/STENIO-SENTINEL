//! `BACKUP-ARTIFACT-VERIFY` (GB-051): a health stamp means "verified artifact", not "script ran".

use regex::Regex;

use super::{SourceFile, case, file_name, fixture, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "BACKUP-ARTIFACT-VERIFY";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Backup Health Stamp Without Artifact Verification",
    severity: "ERROR",
    tag: "homelab",
    summary: "A script that produces a compressed or database dump touches a *-last-ok health stamp without both an integrity test (gzip -t, zstd -t, tar -t, PRAGMA integrity_check, restic check) and a minimum size test before the touch.",
    rationale: "GB-051: miracena-backup touches /srv/health/miracena-backup-last-ok right after `pg_dump | gzip`; on 2026-11-04 it failed and the stale stamp was the only signal. A truncated dump with a fresh stamp is worse: the alert stays quiet.",
    bad_example: "pg_dump db | gzip > \"$OUT\"\ntouch \"$HEALTH\"",
    good_example: "pg_dump db | gzip > \"$OUT\"\ngzip -t \"$OUT\"\n[ \"$(stat -c %s \"$OUT\")\" -ge 1024 ]\ntouch \"$HEALTH\"",
    remediation: "Test integrity and minimum size of every artifact before writing the stamp.",
};

struct Patterns {
    dump: Regex,
    integrity: Regex,
    size: Regex,
    stamp_var: Regex,
}

fn patterns() -> Option<Patterns> {
    Some(Patterns {
        dump: Regex::new(r"\b(pg_dumpall|pg_dump|mariadb-dump|mysqldump)\b|\|\s*(gzip|zstd|xz)\b|\btar\s+-?\w*c\w*f|\.backup\s+'|ouch\s+(c|compress)\b|bench\b.*\bbackup\b").ok()?,
        integrity: Regex::new(r"\b(gzip|zstd|xz)\s+(-\w*t\b|--test)|\bgunzip\s+-t|\btar\s+(-\w*t|t\w*f|--list)|PRAGMA\s+(integrity|quick)_check|\brestic\b.*\bcheck\b|ouch\s+(l|list)\b").ok()?,
        size: Regex::new(r"stat\s+(-c\s*%s|--format[= ]%s|--printf[= ]%s)|\bwc\s+-c\b|-size\s+[+-]|\[\[?\s+(!\s+)?-s\s|\btest\s+(!\s+)?-s\s").ok()?,
        stamp_var: Regex::new(r#"^(?:export\s+|local\s+)?(\w+)=.*last-ok"#).ok()?,
    })
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let Some(p) = patterns() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in files.iter().filter(|f| f.content.starts_with("#!")) {
        let lines: Vec<(usize, &str)> = f
            .content
            .lines()
            .enumerate()
            .map(|(i, l)| (i + 1, l.trim()))
            .filter(|(_, l)| !l.starts_with('#'))
            .collect();
        if !lines.iter().any(|(_, l)| p.dump.is_match(l)) {
            continue;
        }
        let vars: Vec<String> = lines
            .iter()
            .filter_map(|(_, l)| p.stamp_var.captures(l).map(|c| c[1].to_string()))
            .collect();
        let stamp = lines.iter().position(|(_, l)| {
            l.contains("touch ")
                && (l.contains("last-ok")
                    || vars
                        .iter()
                        .any(|v| l.contains(&format!("${v}")) || l.contains(&format!("${{{v}}}"))))
        });
        let Some(at) = stamp else { continue };
        let before = &lines[..at];
        let mut missing = Vec::new();
        if !before.iter().any(|(_, l)| p.integrity.is_match(l)) {
            missing.push("an integrity test");
        }
        if !before.iter().any(|(_, l)| p.size.is_match(l)) {
            missing.push("a minimum size test");
        }
        if !missing.is_empty() {
            out.push(violation(
                RULE_ID,
                Severity::Error,
                &f.path,
                lines[at].0,
                lines[at].1,
                format!(
                    "{} writes the health stamp without {} before it",
                    file_name(&f.path),
                    missing.join(" and ")
                ),
                "Verify every artifact (gzip -t, minimum bytes) before touching the stamp.",
            ));
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let script = |checks: &str| {
        format!(
            "#!/bin/bash\nHEALTH=\"/srv/health/x-last-ok\"\npg_dump x | gzip > \"$O\"\n{checks}touch \"$HEALTH\"\n"
        )
    };
    let n = |s: &str| lint(&fixture(&[("bin/x-backup", s)])).len();
    let both = "gzip -t \"$O\"\n[ \"$(stat -c %s \"$O\")\" -ge 1024 ]\n";
    vec![
        case(
            "backup-verify: stamp without checks fires",
            n(&script("")) == 1,
        ),
        case(
            "backup-verify: integrity and size are clean",
            n(&script(both)) == 0,
        ),
        case(
            "backup-verify: integrity alone fires",
            n(&script("gzip -t \"$O\"\n")) == 1,
        ),
        case(
            "backup-verify: checks after the stamp fire",
            n(&format!("{}{both}", script(""))) == 1,
        ),
        case(
            "backup-verify: a stamp without a dump is out of scope",
            n("#!/bin/sh\nrsync -a a b\ntouch /srv/health/y-last-ok\n") == 0,
        ),
    ]
}
