//! `MONITOR-TARGET-LOOPBACK` (GB-014) and `MONITOR-NO-NOTIFICATION` (GB-015) over an Uptime Kuma
//! database snapshot, opened read-only. Only non-secret columns are selected.

use std::process::Command;

use serde::Deserialize;

use super::{case, host_run, opt, opts, unreadable};
use crate::explain::RuleExplanation;
use crate::ports::{ActiveSocket, is_wildcard_bind, parse_ss_output};

pub const LOOPBACK_ID: &str = "MONITOR-TARGET-LOOPBACK";
pub const NOTIFY_ID: &str = "MONITOR-NO-NOTIFICATION";

pub const EXPLAIN_LOOPBACK: RuleExplanation = RuleExplanation {
    id: LOOPBACK_ID,
    name: "Monitor Address Differs From The Listening Address",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops kuma --db kuma.snapshot --kuma-node H=IP [--node H=IP]...` reads `ss` of every node: a monitor aimed at loopback needs a loopback or wildcard listener on the Kuma host; a monitor aimed at a node address needs a listener on that address or a wildcard.",
    rationale: "GB-014: a service bound to one address and watched on another reports down (or watches a different process).",
    bad_example: "monitor http://127.0.0.1:3002, service listening on 100.64.0.1:3002 only",
    good_example: "monitor and listener use the same address",
    remediation: "Point the monitor at the address the service listens on.",
};

pub const EXPLAIN_NOTIFY: RuleExplanation = RuleExplanation {
    id: NOTIFY_ID,
    name: "Monitor Without A Notification Channel",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops kuma --db kuma.snapshot [--exempt NAME]...` reports every active monitor (groups excluded) with no active notification attached.",
    rationale: "GB-015: a monitor that notifies nobody is a dashboard, not an alarm.",
    bad_example: "monitor #7 with no row in monitor_notification",
    good_example: "every active monitor has at least one active notification",
    remediation: "Attach a notification in Uptime Kuma, or name the deliberate exception with --exempt.",
};

#[derive(Deserialize, Clone)]
pub struct Monitor {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub url: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub notifications: u64,
}

const QUERY: &str = "select m.name as name, m.type as type, m.url as url, m.hostname as hostname, m.port as port, (select count(*) from monitor_notification n join notification c on c.id = n.notification_id where n.monitor_id = m.id and c.active = 1) as notifications from monitor m where m.active = 1";

pub fn no_notification(monitors: &[Monitor], exempt: &[String]) -> Vec<String> {
    monitors
        .iter()
        .filter(|m| m.kind != "group" && m.notifications == 0 && !exempt.contains(&m.name))
        .map(|m| {
            format!(
                "monitor '{}' ({}) has no active notification",
                m.name, m.kind
            )
        })
        .collect()
}

/// (host, port) a TCP-based monitor connects to.
fn target(m: &Monitor) -> Option<(String, u16)> {
    match m.kind.as_str() {
        "http" | "keyword" | "json-query" => {
            let url = m.url.as_deref()?;
            let (scheme, rest) = url.split_once("://")?;
            let authority = rest.split(['/', '?']).next()?.rsplit('@').next()?;
            let default = if scheme == "https" { 443 } else { 80 };
            match authority.rsplit_once(':') {
                Some((h, p)) if !p.ends_with(']') => Some((h.to_string(), p.parse().ok()?)),
                _ => Some((authority.to_string(), default)),
            }
        }
        "port" => Some((m.hostname.clone()?, m.port?)),
        _ => None,
    }
}

/// Address of an `ss` local column without brackets or the `%interface` zone.
fn bare(ip: &str) -> &str {
    ip.split('%').next().unwrap_or(ip).trim_matches(['[', ']'])
}

pub struct Node {
    pub name: String,
    pub ip: String,
    pub sockets: Vec<ActiveSocket>,
}

/// Findings and the number of monitors that could be compared.
pub fn mismatches(monitors: &[Monitor], kuma: &str, nodes: &[Node]) -> (Vec<String>, usize) {
    let (mut out, mut checked) = (Vec::new(), 0);
    for m in monitors {
        let Some((host, port)) = target(m) else {
            continue;
        };
        let host = host.trim_matches(['[', ']']).to_string();
        let local = host == "localhost" || host == "::1" || host.starts_with("127.");
        let node = nodes
            .iter()
            .find(|n| if local { n.name == kuma } else { n.ip == host });
        let Some(node) = node else { continue };
        checked += 1;
        let on_port: Vec<&ActiveSocket> = node.sockets.iter().filter(|s| s.port == port).collect();
        let reachable = on_port.iter().any(|s| {
            is_wildcard_bind(bare(&s.ip))
                || if local {
                    bare(&s.ip).starts_with("127.") || bare(&s.ip) == "::1"
                } else {
                    bare(&s.ip) == host
                }
        });
        if !reachable {
            let bound: Vec<&str> = on_port.iter().map(|s| s.ip.as_str()).collect();
            out.push(format!(
                "monitor '{}' targets {host}:{port} but {} listens on {}",
                m.name,
                node.name,
                if bound.is_empty() {
                    "nothing on that port".to_string()
                } else {
                    format!("{} only", bound.join(", "))
                }
            ));
        }
    }
    (out, checked)
}

fn read_monitors(db: &str) -> Result<Vec<Monitor>, String> {
    let mut c = Command::new("sqlite3");
    c.args(["-readonly", "-json", db, QUERY]);
    let out = crate::verify_release::spawn_with_timeout(c, std::time::Duration::from_secs(60))?;
    if out.code != 0 {
        return Err(format!("sqlite3 exited {}", out.code));
    }
    serde_json::from_str(&out.stdout).map_err(|e| format!("unexpected sqlite3 output: {e}"))
}

pub fn run_cli(args: &[String]) -> i32 {
    let Some(db) = opt(args, "--db").filter(|p| std::path::Path::new(p).is_file()) else {
        return unreadable(NOTIFY_ID, "--db <kuma.db snapshot> is required");
    };
    let monitors = match read_monitors(&db) {
        Ok(m) if !m.is_empty() => m,
        Ok(_) => return unreadable(NOTIFY_ID, "no active monitor in the database"),
        Err(e) => return unreadable(NOTIFY_ID, e),
    };
    let mut code = super::verdict(
        NOTIFY_ID,
        "kuma",
        monitors.len(),
        &no_notification(&monitors, &opts(args, "--exempt")),
    );
    let Some(kuma_spec) = opt(args, "--kuma-node") else {
        println!("SKIP {LOOPBACK_ID}: pass --kuma-node host=ip to compare listening addresses");
        return code;
    };
    let mut nodes = Vec::new();
    for spec in std::iter::once(kuma_spec.clone()).chain(opts(args, "--node")) {
        let Some((name, ip)) = spec.split_once('=') else {
            return unreadable(LOOPBACK_ID, "node spec is host=ip");
        };
        if name.starts_with('-') || !crate::verify_release::safe(name, "") {
            return unreadable(LOOPBACK_ID, "unsafe node name");
        }
        match host_run(name, "ss -Htln") {
            Ok(s) => nodes.push(Node {
                name: name.to_string(),
                ip: ip.to_string(),
                sockets: parse_ss_output(&s),
            }),
            Err(e) => return unreadable(LOOPBACK_ID, e),
        }
    }
    let kuma = kuma_spec.split('=').next().unwrap_or_default();
    let (found, checked) = mismatches(&monitors, kuma, &nodes);
    code = code.max(super::verdict(LOOPBACK_ID, "kuma", checked, &found));
    code
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let m = |url: &str, notifications| Monitor {
        name: "svc".into(),
        kind: "http".into(),
        url: Some(url.into()),
        hostname: None,
        port: None,
        notifications,
    };
    let node = |ss: &str| {
        vec![Node {
            name: "k".into(),
            ip: "100.0.0.1".into(),
            sockets: parse_ss_output(ss),
        }]
    };
    let tail = "LISTEN 0 1 100.0.0.1:3002 0.0.0.0:*\n";
    let wild = "LISTEN 0 1 0.0.0.0:3002 0.0.0.0:*\n";
    let zoned = "LISTEN 0 1 100.0.0.1%tailscale0:3002 0.0.0.0:*\n";
    let local = [m("http://127.0.0.1:3002/x", 1)];
    let remote = [m("http://100.0.0.1:3002", 1)];
    vec![
        case(
            "kuma: loopback monitor on a tailnet-only listener fires",
            mismatches(&local, "k", &node(tail)).0.len() == 1,
        ),
        case(
            "kuma: wildcard listener satisfies both addresses",
            mismatches(&local, "k", &node(wild)).0.is_empty()
                && mismatches(&remote, "k", &node(wild)).0.is_empty(),
        ),
        case(
            "kuma: tailnet monitor on a loopback-only listener fires",
            mismatches(&remote, "k", &node("LISTEN 0 1 127.0.0.1:3002 0.0.0.0:*\n"))
                .0
                .len()
                == 1,
        ),
        case(
            "kuma: an interface zone on the bind address is not a mismatch",
            mismatches(&remote, "k", &node(zoned)).0.is_empty(),
        ),
        case(
            "kuma: monitor without notification fails, exemption passes",
            no_notification(&[m("http://a", 0)], &[]).len() == 1
                && no_notification(&[m("http://a", 0)], &["svc".to_string()]).is_empty()
                && no_notification(&[m("http://a", 1)], &[]).is_empty(),
        ),
    ]
}
