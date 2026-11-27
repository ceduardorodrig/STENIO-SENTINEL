//! `FUNDAMENTAL-NO-OFFHOST-PROBE` (GB-232): a fundamental service declares an off-host probe and
//! an alert path that does not depend on its own host.

use serde::Deserialize;

use super::{SourceFile, case, file_name, fixture, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "FUNDAMENTAL-NO-OFFHOST-PROBE";
const FENCE: &str = "```toml stenio-fundamental";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Fundamental Service Without An Off-Host Probe",
    severity: "ERROR",
    tag: "homelab",
    summary: "monitoring.md declares fundamental services in a ```toml stenio-fundamental block: fundamental = [names] and one [[probe]] per name with service, service_host, probe_host, port, query, expect and alert_host. Errors: no probe, probe_host or alert_host equal to the service host, or no block at all in monitoring.md.",
    rationale: "GB-232: AdGuard Home on ybytu was dark for 32 h 46 m while Docker reported Running=true; three detectors fired but the alert bridge lost 91% of its webhooks because ntfy ran on the same host.",
    bad_example: "fundamental = [\"adguardhome\"]\n# no [[probe]] for it",
    good_example: "fundamental = [\"adguardhome\"]\n[[probe]]\nservice = \"adguardhome\"\nservice_host = \"ybytu\"\nprobe_host = \"kavure\"\nport = 53\nquery = \"doubleclick.net\"\nexpect = \"0.0.0.0\"\nalert_host = \"ntfy.sh\"",
    remediation: "Declare a probe that runs on another host and delivers its alert through a third path.",
};

#[derive(Deserialize, Default)]
struct Block {
    #[serde(default)]
    fundamental: Vec<String>,
    #[serde(default)]
    probe: Vec<Probe>,
}

#[derive(Deserialize)]
struct Probe {
    service: String,
    service_host: String,
    probe_host: String,
    port: u16,
    query: String,
    expect: String,
    alert_host: String,
}

fn errors(block: &Block) -> Vec<String> {
    let mut out = Vec::new();
    for name in &block.fundamental {
        let probes: Vec<&Probe> = block.probe.iter().filter(|p| &p.service == name).collect();
        if probes.is_empty() {
            out.push(format!("{name}: no off-host probe declared"));
        }
        for p in probes {
            if p.port == 0 || p.query.is_empty() || p.expect.is_empty() {
                out.push(format!(
                    "{name}: the probe needs a port, a query and an expected answer"
                ));
            }
            if p.probe_host == p.service_host {
                out.push(format!(
                    "{name}: probe host {} is the service host",
                    p.probe_host
                ));
            }
            if p.alert_host == p.service_host {
                out.push(format!(
                    "{name}: the alert path goes through {}, the host of the service",
                    p.alert_host
                ));
            }
        }
    }
    if block.fundamental.is_empty() {
        out.push("the block declares no fundamental service".to_string());
    }
    out
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let mut out = Vec::new();
    for f in files
        .iter()
        .filter(|f| f.path.ends_with(".md") && file_name(&f.path) == "monitoring.md")
    {
        let mut report = |line: usize, message: String| {
            out.push(violation(
                RULE_ID,
                Severity::Error,
                &f.path,
                line,
                FENCE,
                message,
                "Declare the probe in the stenio-fundamental block (stenio --explain).",
            ));
        };
        let Some(at) = f.content.find(FENCE) else {
            report(
                1,
                "monitoring.md has no stenio-fundamental block".to_string(),
            );
            continue;
        };
        let line = f.content[..at].lines().count() + 1;
        let body = &f.content[at + FENCE.len()..];
        let body = &body[..body.find("\n```").unwrap_or(body.len())];
        match toml::from_str::<Block>(body) {
            Ok(b) => errors(&b).into_iter().for_each(|e| report(line, e)),
            Err(e) => report(line, format!("unparsable block: {}", e.message())),
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let probe = "[[probe]]\nservice = \"adguardhome\"\nservice_host = \"ybytu\"\nprobe_host = \"kavure\"\nport = 53\nquery = \"doubleclick.net\"\nexpect = \"0.0.0.0\"\nalert_host = \"ntfy.sh\"\n";
    let doc = |p: &str| format!("# m\n{FENCE}\nfundamental = [\"adguardhome\"]\n{p}```\n");
    let run = |d: &str| lint(&fixture(&[("mnemocine/services/monitoring.md", d)]));
    vec![
        case(
            "fundamental-probe: off-host probe is clean",
            run(&doc(probe)).is_empty(),
        ),
        case(
            "fundamental-probe: removing the probe names the service",
            run(&doc(""))
                .iter()
                .any(|v| v.message.contains("adguardhome")),
        ),
        case(
            "fundamental-probe: probe on the service host fires",
            run(&doc(&probe.replace("\"kavure\"", "\"ybytu\""))).len() == 1,
        ),
        case(
            "fundamental-probe: alert path on the service host fires",
            run(&doc(&probe.replace("\"ntfy.sh\"", "\"ybytu\""))).len() == 1,
        ),
        case(
            "fundamental-probe: deleting the whole block fires",
            run("# monitoring\n").len() == 1,
        ),
    ]
}
