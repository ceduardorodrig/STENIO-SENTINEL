//! `DOC-PORTS-VS-SS` (GB-013): the declared TCP ports of a host against its listening sockets.

use std::collections::BTreeSet;
use std::path::Path;

use super::{case, host_arg, host_run, opt, unreadable, verdict};
use crate::explain::RuleExplanation;
use crate::ports::{PortEntry, is_wildcard_bind, load_port_catalog, parse_ss_output};

pub const RULE_ID: &str = "DOC-PORTS-VS-SS";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Port Catalog Differs From The Listening Sockets",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops ports --host H [--vault DIR]` compares the TCP rows of H in mnemocine/network/ports.md with `ss -Htlpn` on H: a non-loopback listener without a row is `undeclared`, a row without a listener is `missing`. Ephemeral ports (>= 32768) without a row are listed as skipped.",
    rationale: "GB-013 (split of GB-009): the port matrix and the hosts drift and nobody compared them with an exit code.",
    bad_example: "| `8080/tcp` | ... |   # nothing listens, and :9999 listens without a row",
    good_example: "every non-loopback listener has a row and every row has a listener",
    remediation: "Add or retire the row in ports.md, or stop the undeclared listener.",
};

fn loopback(ip: &str) -> bool {
    ip.starts_with("127.") || ip == "::1" || ip.starts_with("::ffff:127.")
}

/// (findings, number of ephemeral listeners left out)
pub fn compare(host: &str, catalog: &[PortEntry], ss: &str) -> (Vec<String>, usize) {
    let sockets = parse_ss_output(ss);
    let rows: Vec<&PortEntry> = catalog
        .iter()
        .filter(|e| e.host == host && e.proto.contains("tcp"))
        .collect();
    let declared: BTreeSet<u16> = rows.iter().map(|e| e.port).collect();
    let listening: BTreeSet<u16> = sockets.iter().map(|s| s.port).collect();
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();
    let mut ephemeral = 0;
    for s in &sockets {
        let local = loopback(s.ip.split('%').next().unwrap_or(&s.ip));
        if local || declared.contains(&s.port) || !seen.insert(s.port) {
            continue;
        }
        if s.port >= 32768 {
            ephemeral += 1;
            continue;
        }
        let bind = if is_wildcard_bind(&s.ip) {
            "all interfaces".to_string()
        } else {
            s.ip.clone()
        };
        findings.push(format!(
            "undeclared: {host} listens on {}/tcp ({bind}, {}) with no row in ports.md",
            s.port,
            s.process.as_deref().unwrap_or("process unknown")
        ));
    }
    let mut missing = BTreeSet::new();
    for r in rows {
        if !listening.contains(&r.port) && missing.insert(r.port) {
            findings.push(format!(
                "missing: ports.md declares {}/tcp ({}) on {host} and nothing listens",
                r.port, r.service
            ));
        }
    }
    (findings, ephemeral)
}

pub fn run_cli(args: &[String]) -> i32 {
    let Some(host) = host_arg(args) else {
        return unreadable(RULE_ID, "--host is required");
    };
    let vault = opt(args, "--vault").unwrap_or_else(|| ".".to_string());
    let name = opt(args, "--catalog-host").unwrap_or_else(|| host.clone());
    if !Path::new(&vault)
        .join("mnemocine/network/ports.md")
        .is_file()
    {
        return unreadable(RULE_ID, "no mnemocine/network/ports.md under --vault");
    }
    let catalog = load_port_catalog(Path::new(&vault));
    if !catalog.iter().any(|e| e.host == name) {
        return unreadable(RULE_ID, format!("ports.md has no section for {name}"));
    }
    let ss = match host_run(&host, "ss -Htlpn") {
        Ok(s) if !s.trim().is_empty() => s,
        Ok(_) => return unreadable(RULE_ID, "ss printed nothing"),
        Err(e) => return unreadable(RULE_ID, e),
    };
    let (findings, ephemeral) = compare(&name, &catalog, &ss);
    println!("skipped {ephemeral} undeclared ephemeral listener(s) (port >= 32768)");
    verdict(RULE_ID, &name, parse_ss_output(&ss).len(), &findings)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let row = |port| PortEntry {
        host: "h".into(),
        port,
        proto: "tcp".into(),
        bind: String::new(),
        service: "svc".into(),
        justification: String::new(),
        doc_link: String::new(),
        defect: false,
    };
    let ss = "LISTEN 0 1 100.0.0.1:80 0.0.0.0:*\nLISTEN 0 1 0.0.0.0:999 0.0.0.0:*\nLISTEN 0 1 127.0.0.1:555 0.0.0.0:*\n";
    let (bad, _) = compare("h", &[row(80), row(443)], ss);
    let (good, _) = compare("h", &[row(80), row(999)], ss);
    vec![
        case(
            "ports-vs-ss: one extra and one missing port yield two findings",
            bad.len() == 2 && bad[0].contains("999/tcp") && bad[1].contains("443/tcp"),
        ),
        case("ports-vs-ss: matching catalog is clean", good.is_empty()),
    ]
}
