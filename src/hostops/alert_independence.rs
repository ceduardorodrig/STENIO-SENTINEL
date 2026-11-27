//! `OPS-ALERT-INDEPENDENCE` (GB-213): the host that delivers alerts must not be a watched target.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use super::{SourceFile, case, file_name, fixture, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "OPS-ALERT-INDEPENDENCE";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Alert Delivery Lives On A Watched Host",
    severity: "ERROR",
    tag: "homelab",
    summary: "The notifier of the monitoring configs (alertmanager receiver url, alertmanager-ntfy baseurl, NTFY_URL) resolves to a host that is also a Prometheus scrape target. ERROR with --only or `hostops lint`; reported as a warning inside the aggregate homelab scope.",
    rationale: "GB-213 / HB-117: ybytu hosted ntfy and was a target itself; it thrashed for 15 h, NodeDown was routed into the host that could not answer and nothing recorded the drop.",
    bad_example: "# alertmanager-ntfy/config.yml\nntfy:\n  baseurl: http://ybytu:8083\n# prometheus.yml\n- targets: ['ybytu:9100']",
    good_example: "# notifier on a host that no scrape job watches (or a hosted relay)\nntfy:\n  baseurl: https://ntfy.sh",
    remediation: "Move the notifier (or add a second delivery path) to a host outside the target list.",
};

/// First DNS label of a name; IP addresses are kept whole.
fn short_host(h: &str) -> String {
    if h.chars().all(|c| c.is_ascii_digit() || c == '.') {
        h.to_string()
    } else {
        h.split('.').next().unwrap_or(h).to_ascii_lowercase()
    }
}

struct Targets {
    hosts: BTreeSet<String>,
}

/// Scrape targets of every prometheus config, with IPs resolved to the names the file gives
/// them (`'IP:port'  # name` comments).
fn targets(files: &[SourceFile]) -> Targets {
    let mut hosts = BTreeSet::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let (Ok(quoted), Ok(named)) = (
        Regex::new(r#"['"]([A-Za-z0-9._-]+):\d+['"]"#),
        Regex::new(r#"['"]([0-9.]+):\d+['"][^#\n]*#\s*([A-Za-z][A-Za-z0-9-]*)"#),
    ) else {
        return Targets { hosts };
    };
    for f in files
        .iter()
        .filter(|f| file_name(&f.path).starts_with("prometheus") && f.path.ends_with("ml"))
    {
        for c in named.captures_iter(&f.content) {
            names.insert(c[1].to_string(), c[2].to_ascii_lowercase());
        }
        let mut in_targets = false;
        for line in f.content.lines() {
            let t = line.split(" #").next().unwrap_or("").trim();
            if t.starts_with("- targets:") || t.starts_with("targets:") {
                in_targets = true;
            } else if in_targets && !(t.starts_with("- '") || t.starts_with("- \"") || t.is_empty())
            {
                in_targets = false;
            }
            if in_targets {
                hosts.extend(quoted.captures_iter(t).map(|c| short_host(&c[1])));
            }
        }
    }
    let resolved: Vec<String> = hosts.iter().filter_map(|h| names.get(h).cloned()).collect();
    hosts.extend(resolved);
    Targets { hosts }
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let watched = targets(files).hosts;
    let Ok(url) = Regex::new(
        r#"(?:^\s*(?:-\s*)?(?:url|baseurl):|NTFY_URL\s*[:=])\s*["']?https?://([A-Za-z0-9._-]+)"#,
    ) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for f in files.iter().filter(|f| {
        let yaml = f.path.ends_with(".yml") || f.path.ends_with(".yaml");
        yaml && f.path.contains("alertmanager")
            || (yaml
                && file_name(&f.path).starts_with("compose")
                && f.content.contains("alertmanager"))
    }) {
        for (i, line) in f.content.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            let Some(c) = url.captures(line) else {
                continue;
            };
            let host = short_host(&c[1]);
            if watched.contains(&host) {
                out.push(violation(
                    RULE_ID,
                    Severity::Error,
                    &f.path,
                    i + 1,
                    line,
                    format!(
                        "alerts are delivered through '{host}', which is also a scrape target: when it fails, its own alarm is lost"
                    ),
                    "Deliver through a host outside the target list, or add an independent path.",
                ));
            }
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let prom = "scrape_configs:\n  - job_name: node\n    static_configs:\n      - targets:\n          - '100.0.0.9:9100'    # ybytu\n          - 'kavure:9100'\n";
    let n = |url: &str| {
        let cfg = format!("ntfy:\n  baseurl: {url}\n");
        lint(&fixture(&[
            ("m/prometheus/prometheus.yml", prom),
            ("m/alertmanager-ntfy/config.yml", &cfg),
        ]))
        .len()
    };
    vec![
        case(
            "alert-independence: notifier on a watched name fires",
            n("http://ybytu.example.ts.net:8083") == 1,
        ),
        case(
            "alert-independence: notifier on a watched IP fires",
            n("http://100.0.0.9:8083") == 1,
        ),
        case(
            "alert-independence: notifier outside the targets is clean",
            n("https://ntfy.sh") == 0,
        ),
    ]
}
