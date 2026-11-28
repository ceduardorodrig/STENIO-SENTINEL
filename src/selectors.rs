//! `--only`, `--tag` and `--scope`: an unknown value is a usage error, and the filters apply to
//! every finding, whatever subsystem produced it.

use crate::engine::Violation;
use crate::rule::Rule;

pub const SCOPES: &[&str] = &[
    "all",
    "hub",
    "homelab",
    "mnemocine",
    "vault",
    "docs",
    "cv",
    "fork",
    "derived",
    "mirror",
    "snapshot",
    "generated",
    "frappe",
    "project",
    "rust",
];

/// Tags the subsystems answer besides the tags the rules declare.
const SUBSYSTEM_TAGS: &[(&str, &[&str])] = &[
    (
        "sec",
        &[
            "SEC-",
            "SECRET",
            "PROVIDER-",
            "STACK-",
            "ENV-",
            "COMPOSE-ENV-",
        ],
    ),
    ("arch", &["ARCH-"]),
    ("infra", &["INFRA-"]),
    ("homelab", &["HOMELAB-"]),
    ("vault", &["VAULT-", "PROJECT-"]),
    ("doc", &["DOC-", "BACKLOG-", "HOMELAB-BACKLOG-"]),
    ("gov", &["GOV-"]),
    ("gpu", &["GPU-"]),
    ("db", &["DB-"]),
    ("migrations", &["DB-"]),
    ("cv", &["CV-"]),
    ("frontend", &["FRONT-", "PERF-"]),
    ("seo", &["SEO-"]),
    ("agent", &["AGENT-", "HOOK-EVENT-"]),
    (
        "shell",
        &[
            "HOOK-STDIN-",
            "INFRA-BASH-PIPEFAIL-",
            "SH-",
            "DEPLOY-",
            "LOCK-",
        ],
    ),
    ("ci", &["CI-", "GOV-LOG-EN-"]),
    ("deps", &["DEPENDABOT-"]),
    ("i18n", &["I18N-"]),
    ("hostops", &[]),
];

/// Ids that only another command produces: asking a scan for one would pass without looking.
const ELSEWHERE: &[(&str, &str)] = &[
    ("FRAPPE-", "stenio --scope frappe"),
    ("GATE-", "stenio gate"),
    ("REALITY-", "stenio --reconcile"),
    ("DECLARATION-", "stenio --reconcile"),
    ("PURPOSE-", "stenio --reconcile"),
    ("POLICY-", "stenio --reconcile"),
    ("ARCH-DRY-", "stenio --dry"),
];

fn near<'a>(wanted: &str, known: impl Iterator<Item = &'a str>) -> String {
    let wanted = wanted.to_ascii_uppercase();
    let mut scored: Vec<(usize, &str)> = known
        .map(|k| {
            let upper = k.to_ascii_uppercase();
            let shared = wanted
                .chars()
                .zip(upper.chars())
                .take_while(|(a, b)| a == b)
                .count();
            (shared, k)
        })
        .filter(|(shared, _)| *shared >= 2)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    scored.dedup_by(|a, b| a.1 == b.1);
    let names: Vec<&str> = scored.into_iter().take(3).map(|(_, k)| k).collect();
    if names.is_empty() {
        String::new()
    } else {
        format!(" (close: {})", names.join(", "))
    }
}

fn tags(rules: &[Rule]) -> impl Iterator<Item = &str> {
    rules
        .iter()
        .map(|r| r.tag.as_str())
        .chain(SUBSYSTEM_TAGS.iter().map(|(t, _)| *t))
}

pub fn check_scope(scope: &str) -> Result<(), String> {
    if SCOPES.iter().any(|s| s.eq_ignore_ascii_case(scope)) {
        return Ok(());
    }
    Err(format!(
        "unknown --scope '{scope}'{}; known: {}",
        near(scope, SCOPES.iter().copied()),
        SCOPES.join(", ")
    ))
}

pub fn check_tag(tag: &str, rules: &[Rule]) -> Result<(), String> {
    if tags(rules).any(|t| t.eq_ignore_ascii_case(tag)) {
        return Ok(());
    }
    let mut known: Vec<&str> = tags(rules).collect();
    known.sort_unstable();
    known.dedup();
    Err(format!(
        "unknown --tag '{tag}'{}; known: {}",
        near(tag, known.iter().copied()),
        known.join(", ")
    ))
}

/// `only` must name a rule, and one that the chosen scope can run.
pub fn check_only(only: &str, scope: &str, rules: &[Rule]) -> Result<(), String> {
    let known = || {
        rules
            .iter()
            .map(|r| r.id.as_str())
            .chain(crate::registry::IDS.iter().copied())
    };
    if !known().any(|id| id.eq_ignore_ascii_case(only)) {
        return Err(format!(
            "unknown --only '{only}'{}; see stenio --list",
            near(only, known())
        ));
    }
    let upper = only.to_ascii_uppercase();
    let frappe = scope.eq_ignore_ascii_case("frappe");
    if frappe && !upper.starts_with("FRAPPE-") && !upper.starts_with("LANG-") {
        return Err(format!("--only {only} is not a rule of --scope frappe"));
    }
    if let Some((_, command)) = ELSEWHERE.iter().find(|(p, _)| upper.starts_with(p)) {
        if !(frappe && upper.starts_with("FRAPPE-")) {
            return Err(format!(
                "--only {only} is not run by this scan, so it would pass unread; use `{command}`"
            ));
        }
    }
    Ok(())
}

/// Whether a finding belongs to the requested tag: the rule's own tag when the rule is one of
/// the loaded rules, else the tag its subsystem answers.
fn tagged(violation: &Violation, tag: &str, rules: &[Rule]) -> bool {
    let id = violation.rule_id.to_ascii_uppercase();
    let declared = rules
        .iter()
        .any(|r| r.id.eq_ignore_ascii_case(&id) && r.tag.eq_ignore_ascii_case(tag));
    declared
        || SUBSYSTEM_TAGS.iter().any(|(t, prefixes)| {
            t.eq_ignore_ascii_case(tag) && prefixes.iter().any(|p| id.starts_with(p))
        })
}

/// `--only`, applied to every finding. Findings of the engine itself survive it: they say the
/// run did not look.
pub fn wanted(violation: &Violation, only: Option<&str>) -> bool {
    violation.rule_id.starts_with("SCAN-")
        || only.is_none_or(|o| violation.rule_id.eq_ignore_ascii_case(o))
}

/// `--tag`, applied to the subsystems that do not select by tag themselves.
pub fn retain_tag(findings: &mut Vec<Violation>, tag: Option<&str>, rules: &[Rule]) {
    if let Some(tag) = tag {
        findings.retain(|v| tagged(v, tag, rules));
    }
}
