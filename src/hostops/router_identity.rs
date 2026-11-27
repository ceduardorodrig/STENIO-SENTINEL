//! `ROUTER-IDENTITY-DRIFT` (GB-256): the documents agree on what the gateway and each NIC are.

use std::collections::BTreeMap;

use regex::Regex;

use super::{SourceFile, case, file_name, fixture, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "ROUTER-IDENTITY-DRIFT";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Documents Disagree On Gateway Or Link Identity",
    severity: "WARNING",
    tag: "homelab",
    summary: "Two documents name different router vendors on lines about the same LAN gateway address (x.y.z.1), or give different link speeds for the same host and NIC. Backlogs are excluded; a line naming two vendors, two NICs or two speeds is a comparison or a history note and is skipped.",
    rationale: "GB-256: 192.168.3.1 was a Huawei WS7001-40 in network/topology.md and a ZTE CPE in services/autopilot.md.",
    bad_example: "a.md: router 192.168.3.1 (Huawei)\nb.md: the ZTE CPE at 192.168.3.1",
    good_example: "a.md: router 192.168.3.1 (Huawei)\nb.md: the Huawei gateway 192.168.3.1",
    remediation: "Verify on the device and correct the wrong document.",
};

const VENDORS: &[&str] = &[
    "huawei",
    "zte",
    "tp-link",
    "mikrotik",
    "mitrastar",
    "intelbras",
    "nokia",
    "arris",
    "sagemcom",
    "asus",
    "d-link",
    "ubiquiti",
];
const HOSTS: &[&str] = &["psicopompo", "kavure", "kuaray", "ybytu", "ybyra", "kururu"];

/// Claims grouped by subject: value -> first place (file, line, text).
type Claims = BTreeMap<String, BTreeMap<String, (String, usize, String)>>;

fn only<'a>(mut it: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let first = it.next()?;
    it.all(|o| o == first).then_some(first)
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let (Ok(gateway), Ok(nic), Ok(speed)) = (
        Regex::new(r"\b(?:192\.168|10\.\d{1,3})\.\d{1,3}\.1\b"),
        Regex::new(r"\b(enp\d+s\d+\w*|eno\d+|eth\d+)\b"),
        Regex::new(r"(?i)\b(\d+(?:[.,]\d+)?)\s*(mb/s|mbps|mbit|gb/s|gbps|gbit|gbe)"),
    ) else {
        return Vec::new();
    };
    let mut claims: Claims = BTreeMap::new();
    for f in files
        .iter()
        .filter(|f| f.path.ends_with(".md") && !file_name(&f.path).starts_with("backlog"))
    {
        for (i, line) in f.content.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let mut claim = |subject: String, value: String| {
                claims.entry(subject).or_default().entry(value).or_insert((
                    f.path.clone(),
                    i + 1,
                    line.to_string(),
                ));
            };
            let vendors: Vec<&str> = VENDORS
                .iter()
                .copied()
                .filter(|v| {
                    lower
                        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                        .any(|w| w == *v)
                })
                .collect();
            if let (Some(ip), [vendor]) = (
                only(gateway.find_iter(line).map(|m| m.as_str())),
                &vendors[..],
            ) {
                claim(format!("gateway {ip}"), (*vendor).to_string());
            }
            let Some(name) = only(nic.find_iter(line).map(|m| m.as_str())) else {
                continue;
            };
            let speeds: Vec<u64> = speed
                .captures_iter(line)
                .filter_map(|c| {
                    let n: f64 = c[1].replace(',', ".").parse().ok()?;
                    let giga = c[2].to_ascii_lowercase().starts_with('g');
                    Some((n * if giga { 1000.0 } else { 1.0 }) as u64)
                })
                .collect();
            let host = HOSTS
                .iter()
                .copied()
                .filter(|h| lower.contains(h))
                .collect::<Vec<_>>();
            if let ([s], [h]) = (&speeds[..], &host[..]) {
                claim(format!("link {h} {name}"), format!("{s} Mb/s"));
            }
        }
    }
    let mut out = Vec::new();
    for (subject, values) in claims.iter().filter(|(_, v)| v.len() > 1) {
        let places: Vec<String> = values
            .iter()
            .map(|(v, (file, line, _))| format!("'{v}' at {file}:{line}"))
            .collect();
        if let Some((_, (file, line, text))) = values.iter().next_back() {
            out.push(violation(
                RULE_ID,
                Severity::Warning,
                file,
                *line,
                text,
                format!(
                    "{subject} is described differently: {}",
                    places.join(" and ")
                ),
                "Verify on the device and correct the wrong document.",
            ));
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let n = |a: &str, b: &str| lint(&fixture(&[("a.md", a), ("b.md", b)]));
    vec![
        case(
            "router-identity: two vendors fire and name both files",
            n("router 192.168.3.1 Huawei", "ZTE CPE 192.168.3.1")
                .iter()
                .any(|v| v.message.contains("a.md:1") && v.message.contains("b.md:1")),
        ),
        case(
            "router-identity: same vendor is clean",
            n("192.168.3.1 Huawei WS7001", "Huawei (192.168.3.1)").is_empty(),
        ),
        case(
            "router-identity: conflicting link speed fires",
            n("kuaray enp7s0 100 Mb/s", "kuaray enp7s0 at 1 Gb/s").len() == 1,
        ),
        case(
            "router-identity: another host with the same NIC is clean",
            n("kuaray enp7s0 100 Mb/s", "kavure enp7s0 1000 Mb/s").is_empty(),
        ),
    ]
}
