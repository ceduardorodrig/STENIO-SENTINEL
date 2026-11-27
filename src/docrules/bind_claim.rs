//! `DOC-BIND-CLAIM` (GB-018): the address a service document says the service binds to is the
//! one its mirrored compose file publishes.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use regex::Regex;

use super::{Ctx, DocRule, finding, prose_lines, red_green};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub static RULE: DocRule = DocRule {
    id: "DOC-BIND-CLAIM",
    check,
    self_test,
    explain: RuleExplanation {
        id: "DOC-BIND-CLAIM",
        name: "Bind Address Claim Contradicts the Compose File",
        severity: "WARN",
        tag: "doc",
        summary: "In mnemocine/services/<name>.md, a line saying the service is bound to or listens on an address is compared with the `ports:` of <mirror>/<host>/{homelab,data}/<name>/ compose files. Services with `network_mode: host` or no published port are not judged.",
        rationale: "GB-018: ntfy.md said the service was bound to 0.0.0.0 while the live compose publishes it on one tailnet address only (HB-047); readers took the exposure from the prose.",
        bad_example: "ntfy is bound to `0.0.0.0`   # compose: \"100.115.253.109:8083:80\"",
        good_example: "ntfy is bound to `100.115.253.109:8083`",
        remediation: "Correct the sentence from the compose file (or the compose file, if the document states the intent), with the date it was read.",
    },
};

/// Host addresses published by the `ports:` entries of one compose file.
fn published(compose: &Path) -> Option<BTreeSet<String>> {
    let doc: serde_yaml::Value = serde_yaml::from_str(&fs::read_to_string(compose).ok()?).ok()?;
    let mut out = BTreeSet::new();
    for (_, service) in doc.get("services")?.as_mapping()? {
        if service.get("network_mode").and_then(|v| v.as_str()) == Some("host") {
            return None;
        }
        let Some(ports) = service.get("ports").and_then(|p| p.as_sequence()) else {
            continue;
        };
        for port in ports {
            if let Some(text) = port.as_str() {
                let parts: Vec<&str> = text.rsplitn(3, ':').collect();
                let ip = parts.get(2).copied().unwrap_or("0.0.0.0");
                // `${VAR}` addresses cannot be resolved statically.
                if ip.contains('$') {
                    return None;
                }
                out.insert(ip.to_string());
            } else if let Some(map) = port.as_mapping() {
                let ip = map
                    .get("host_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0.0.0.0");
                out.insert(ip.to_string());
            }
        }
    }
    Some(out).filter(|s| !s.is_empty())
}

fn addresses_of(mirror: &Path, service: &str) -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    let Ok(hosts) = fs::read_dir(mirror) else {
        return all;
    };
    for host in hosts.flatten() {
        for base in ["homelab", "data"] {
            for file in ["compose.yml", "compose.yaml", "docker-compose.yml"] {
                let path = host.path().join(base).join(service).join(file);
                if let Some(found) = published(&path) {
                    all.extend(found);
                }
            }
        }
    }
    all
}

fn check(ctx: &Ctx, out: &mut Vec<Violation>) {
    let Some(mirror) = ctx.mirror.as_deref() else {
        return;
    };
    let (Ok(verb), Ok(address), Ok(past)) = (
        Regex::new(
            r"(?i)\b(?:bound\s+(?:only\s+)?to|binds?\s+(?:only\s+)?(?:to|on)|listens?\s+(?:only\s+)?on|publish(?:es|ed)\s+(?:only\s+)?on|escuta(?:ndo)?\s+(?:só\s+)?em|vinculad[oa]\s+a)\s+[`*]{0,3}(\d{1,3}(?:\.\d{1,3}){3})",
        ),
        Regex::new(r"^services/([a-z0-9._-]+)\.md$"),
        Regex::new(r"(?i)\b(?:no longer|previously|formerly|was|used to|antes)\b"),
    ) else {
        return;
    };
    for (path, content) in ctx.docs() {
        let text = path.to_string_lossy().to_string();
        let Some(service) = text
            .split_once("mnemocine/")
            .and_then(|(_, rel)| address.captures(rel))
            .map(|c| c[1].to_string())
        else {
            continue;
        };
        let live = addresses_of(mirror, &service);
        if live.is_empty() {
            continue;
        }
        for (idx, line) in prose_lines(&content) {
            if past.is_match(line) {
                continue;
            }
            for claim in verb.captures_iter(line) {
                let ip = &claim[1];
                // Inside the container the process listens on its own loopback or wildcard.
                if !live.contains(ip) && !line.to_lowercase().contains("container") {
                    out.push(finding(
                        &RULE.explain,
                        Severity::Warning,
                        ctx.display(&path),
                        idx + 1,
                        line,
                        format!(
                            "says '{service}' binds {ip}, but its compose publishes only on {}",
                            live.iter().cloned().collect::<Vec<_>>().join(", ")
                        ),
                    ));
                }
            }
        }
    }
}

fn self_test() -> Vec<(String, bool)> {
    const DOC: &str = "mnemocine/services/ntfy.md";
    let compose = (
        "mirror/h/homelab/ntfy/compose.yml",
        "services:\n  ntfy:\n    ports:\n      - \"100.1.2.3:8083:80\"\n",
    );
    vec![red_green(
        &RULE,
        "contradiction",
        &[compose, (DOC, "ntfy is bound to `100.1.2.3` only.\n")],
        &[compose, (DOC, "ntfy is bound to `0.0.0.0`.\n")],
        1,
    )]
}
