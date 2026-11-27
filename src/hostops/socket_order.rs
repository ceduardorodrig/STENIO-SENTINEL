//! `SOCKET-NO-AFTER-NETWORK` (GB-171): a socket pulled in by `sockets.target` must not be
//! ordered after anything that is itself ordered after `basic.target`.

use super::{SourceFile, case, file_name, fixture, unit_entries, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "SOCKET-NO-AFTER-NETWORK";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Early-Boot Socket Ordered After A Late Unit",
    severity: "ERROR",
    tag: "homelab",
    summary: "A *.socket wanted by sockets.target (default dependencies on) with After= on network-online.target, network.target or a regular service closes an ordering cycle through basic.target; systemd breaks it by deleting a start job, so the socket stays dead after boot.",
    rationale: "GB-171: ollama-tailnet.socket was enabled but dead from the 2026-11-03 boot: sockets.target -> ollama-tailnet.socket -> After=network-online.target -> network.target -> NetworkManager.service -> basic.target -> sockets.target.",
    bad_example: "[Unit]\nAfter=network-online.target\n[Socket]\nListenStream=100.64.0.1:11434\n[Install]\nWantedBy=sockets.target",
    good_example: "[Socket]\nListenStream=100.64.0.1:11434\nFreeBind=yes\n[Install]\nWantedBy=sockets.target",
    remediation: "Drop the After= edge and set FreeBind=yes so the bind succeeds before the address exists.",
};

/// True when ordering after `unit` places a socket behind `basic.target`.
fn is_late(unit: &str) -> bool {
    matches!(
        unit,
        "network-online.target" | "network.target" | "multi-user.target" | "basic.target"
    ) || (unit.ends_with(".service") && !unit.starts_with("systemd-"))
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let mut out = Vec::new();
    for f in files.iter().filter(|f| f.path.ends_with(".socket")) {
        let entries = unit_entries(&f.content);
        let early = entries
            .iter()
            .any(|e| e.1 == "WantedBy" && e.2.split_whitespace().any(|w| w == "sockets.target"));
        let no_defaults = entries
            .iter()
            .any(|e| e.1 == "DefaultDependencies" && matches!(e.2.as_str(), "no" | "false"));
        if !early || no_defaults {
            continue;
        }
        for (_, _, value, line) in entries.iter().filter(|e| e.0 == "Unit" && e.1 == "After") {
            for dep in value.split_whitespace().filter(|d| is_late(d)) {
                let name = file_name(&f.path);
                out.push(violation(
                    RULE_ID,
                    Severity::Error,
                    &f.path,
                    *line,
                    &format!("After={value}"),
                    format!(
                        "ordering cycle: sockets.target -> {name} -> After={dep} -> basic.target -> sockets.target; systemd deletes a start job and the socket stays dead"
                    ),
                    "Remove the After= edge and use FreeBind=yes.",
                ));
            }
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let head = "[Socket]\nListenStream=1.2.3.4:1\n[Install]\nWantedBy=sockets.target\n";
    let n = |unit: &str| {
        let text = format!("{unit}{head}");
        lint(&fixture(&[("x.socket", &text)])).len()
    };
    vec![
        case(
            "socket-order: After=network-online.target fires",
            n("[Unit]\nAfter=network-online.target\n") == 1,
        ),
        case(
            "socket-order: After=regular service fires",
            n("[Unit]\nAfter=tailscaled.service\n") == 1,
        ),
        case(
            "socket-order: Wants without After is clean",
            n("[Unit]\nWants=tailscaled.service\n") == 0,
        ),
        case(
            "socket-order: DefaultDependencies=no is clean",
            n("[Unit]\nDefaultDependencies=no\nAfter=network.target\n") == 0,
        ),
    ]
}
