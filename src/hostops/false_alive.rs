//! `DOCKER-FALSE-ALIVE` (GB-231): Docker says Running while the container process is gone.

use super::{case, host_arg, host_run, unreadable, verdict};
use crate::explain::RuleExplanation;

pub const RULE_ID: &str = "DOCKER-FALSE-ALIVE";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Running Container Without A Process",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops false-alive --host H` checks that the .State.Pid of every container with .State.Running=true exists under /proc on H, and names the published ports that only docker-proxy still holds.",
    rationale: "GB-231: adguardhome on ybytu reported Running=true with Pid 852692 absent from /proc; docker-proxy held :53 and :3000 and every query was refused for about 32 h.",
    bad_example: "docker ps: Up 4 days (unhealthy), /proc/<pid> missing",
    good_example: "every running container has a live pid",
    remediation: "Recreate the container (docker compose up -d --force-recreate) after reading the kernel log.",
};

const COMMAND: &str = "docker ps -q | xargs -r docker inspect -f '{{.Name}}|{{.State.Running}}|{{.State.Pid}}|{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}' | while IFS='|' read -r n r p ports; do if [ -d \"/proc/$p\" ]; then a=present; else a=absent; fi; echo \"$n|$r|$p|$a|$ports\"; done";

/// Findings and number of running containers from `name|running|pid|present|ports` lines.
pub fn check(out: &str) -> (Vec<String>, usize) {
    let (mut found, mut running) = (Vec::new(), 0);
    for l in out.lines() {
        let f: Vec<&str> = l.split('|').collect();
        if f.len() < 5 || f[1] != "true" {
            continue;
        }
        running += 1;
        if f[2] == "0" || f[3] != "present" {
            let ports = f[4].trim();
            found.push(format!(
                "zombie container {} pid {}: Running=true but the process is gone{}",
                f[0].trim_start_matches('/'),
                f[2],
                if ports.is_empty() {
                    String::new()
                } else {
                    format!("; published ports {ports} have no live backend")
                }
            ));
        }
    }
    (found, running)
}

pub fn run_cli(args: &[String]) -> i32 {
    let Some(host) = host_arg(args) else {
        return unreadable(RULE_ID, "--host is required");
    };
    match host_run(&host, COMMAND) {
        Ok(out) => {
            let (found, running) = check(&out);
            if running == 0 {
                return unreadable(RULE_ID, format!("no running container listed on {host}"));
            }
            verdict(RULE_ID, &host, running, &found)
        }
        Err(e) => unreadable(RULE_ID, e),
    }
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let (bad, n) = check("/adguardhome|true|852692|absent|53/tcp \n/ok|true|10|present|\n");
    vec![
        case(
            "false-alive: absent pid is named with its ports",
            n == 2
                && bad.len() == 1
                && bad[0].contains("adguardhome pid 852692")
                && bad[0].contains("53/tcp"),
        ),
        case(
            "false-alive: live containers pass",
            check("/ok|true|10|present|80/tcp \n").0.is_empty(),
        ),
    ]
}
