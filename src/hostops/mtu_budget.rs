//! `MTU-BUDGET-PRECHECK` (GB-254): a required UDP datagram size against the live interface MTUs.

use super::{case, host_arg, host_run, opt, opts, unreadable, verdict};
use crate::explain::RuleExplanation;

pub const RULE_ID: &str = "MTU-BUDGET-PRECHECK";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Required UDP Datagram Exceeds The Path MTU",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops mtu --need BYTES --iface IF [--iface IF2] [--host H] [--ipv6]` reads the live MTU of each interface and computes the largest UDP payload (MTU - 28, or - 48 on IPv6). A requirement above the smallest ceiling is unsatisfiable. Pass the overlay interface (tailscale0) when the path goes through it.",
    rationale: "GB-254: Punktfunk asked for 1472-byte datagrams while eno1 was pinned to 1492 (ceiling 1464); the failure showed as a black screen with zero reported loss.",
    bad_example: "--need 1472 --iface eno1   # MTU 1492, ceiling 1464",
    good_example: "--need 1464 --iface eno1",
    remediation: "Lower the datagram size to the ceiling or raise the MTU of every link of the path.",
};

/// `(interface, mtu)` pairs against the requirement.
pub fn check(need: u32, links: &[(String, u32)], ipv6: bool) -> Vec<String> {
    let headers = if ipv6 { 48 } else { 28 };
    links
        .iter()
        .min_by_key(|l| l.1)
        .map(|(name, mtu)| (name, *mtu, mtu.saturating_sub(headers)))
        .filter(|(_, _, ceiling)| need > *ceiling)
        .map(|(name, mtu, ceiling)| {
            vec![format!(
                "needed UDP payload {need} is unsatisfiable: ceiling {ceiling} (interface {name}, MTU {mtu}, {headers} bytes of headers)"
            )]
        })
        .unwrap_or_default()
}

pub fn run_cli(args: &[String]) -> i32 {
    let Some(need) = opt(args, "--need").and_then(|v| v.parse::<u32>().ok()) else {
        return unreadable(RULE_ID, "--need <bytes> is required");
    };
    let ifaces = opts(args, "--iface");
    if ifaces.is_empty() {
        return unreadable(RULE_ID, "--iface <name> is required");
    }
    let host = host_arg(args).unwrap_or_else(|| "local".to_string());
    let mut links = Vec::new();
    for i in ifaces {
        if !crate::verify_release::safe(&i, "") || i.contains("..") {
            return unreadable(RULE_ID, "unsafe interface name");
        }
        match host_run(&host, &format!("head -n1 /sys/class/net/{i}/mtu")) {
            Ok(s) => match s.trim().parse() {
                Ok(m) => links.push((i, m)),
                Err(_) => return unreadable(RULE_ID, format!("no MTU for {i}")),
            },
            Err(e) => return unreadable(RULE_ID, e),
        }
    }
    let found = check(need, &links, args.iter().any(|a| a == "--ipv6"));
    verdict(RULE_ID, &host, links.len(), &found)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let at = |m| vec![("eno1".to_string(), m)];
    vec![
        case(
            "mtu: 1472 on a 1492 link names both numbers",
            check(1472, &at(1492), false)
                .first()
                .is_some_and(|f| f.contains("1472") && f.contains("1464")),
        ),
        case(
            "mtu: 1472 on a 1500 link passes",
            check(1472, &at(1500), false).is_empty(),
        ),
        case(
            "mtu: the smallest link of the path decides",
            check(
                1300,
                &[("eno1".into(), 1500), ("tailscale0".into(), 1280)],
                false,
            )
            .len()
                == 1,
        ),
    ]
}
