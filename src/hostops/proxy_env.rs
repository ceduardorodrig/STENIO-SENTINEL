//! `UNIT-PROXY-ENV-MUST-REACH-SOCKET-OWNER` (GB-200): a proxy exported by a unit is inert when
//! the process that dials upstream is a shared daemon, not a child of the unit.

use super::{SourceFile, case, file_name, fixture, unit_entries, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "UNIT-PROXY-ENV-MUST-REACH-SOCKET-OWNER";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Unit Proxy Environment Does Not Reach The Process That Dials",
    severity: "ERROR",
    tag: "homelab",
    summary: "A unit exports HTTP_PROXY/HTTPS_PROXY/NO_PROXY while ExecStart (directly, through a known wrapper or through a script of the tree) runs a client that hands the HTTP request to a daemon: opencode without --standalone, docker, tailscale, ollama.",
    rationale: "GB-200: hl-autopilot.service -> opencode CLI -> shared `opencode serve --service` daemon (PPID 1). With HTTPS_PROXY=http://127.0.0.1:9 the run still succeeded; only `--standalone` made the environment reach the socket owner. The wrapper table encodes that chain.",
    bad_example: "[Service]\nEnvironment=HTTPS_PROXY=http://127.0.0.1:3128\nExecStart=/usr/bin/opencode run --format json",
    good_example: "[Service]\nEnvironment=HTTPS_PROXY=http://127.0.0.1:3128\nExecStart=/usr/bin/opencode run --standalone --format json",
    remediation: "Set the proxy on the unit of the daemon that opens the upstream socket, or run the client standalone.",
};

/// (client, process that opens the upstream socket, flag that keeps the request in-process)
const DELEGATORS: &[(&str, &str, Option<&str>)] = &[
    (
        "opencode",
        "the shared `opencode serve --service` daemon",
        Some("--standalone"),
    ),
    ("docker", "dockerd (docker.service)", None),
    ("tailscale", "tailscaled (tailscaled.service)", None),
    ("ollama", "the `ollama serve` daemon", None),
];
/// Binaries that shell out to a delegating client.
const WRAPPERS: &[(&str, &str)] = &[("hl-autopilot", "opencode")];

/// The delegating client a command line reaches, if any.
fn delegated(command: &str, files: &[SourceFile]) -> Option<(&'static str, &'static str)> {
    let words: Vec<&str> = command
        .split_whitespace()
        .map(|w| file_name(w.trim_start_matches(['-', '@', '+', '!', ':'])))
        .collect();
    let program = *words.first()?;
    let script = files
        .iter()
        .find(|f| f.content.starts_with("#!") && file_name(&f.path) == program);
    DELEGATORS.iter().find_map(|&(client, owner, flag)| {
        let direct = program == client;
        let wrapped = WRAPPERS.contains(&(program, client));
        let scripted = script.is_some_and(|s| {
            s.content.lines().any(|l| {
                let l = l.trim();
                !l.starts_with('#')
                    && l.split_whitespace().any(|w| file_name(w) == client)
                    && !flag.is_some_and(|f| l.contains(f))
            })
        });
        let opted_out = direct && flag.is_some_and(|f| command.contains(f));
        (((direct || wrapped) && !opted_out) || scripted).then_some((client, owner))
    })
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let mut out = Vec::new();
    for f in files.iter().filter(|f| f.path.ends_with(".service")) {
        let entries = unit_entries(&f.content);
        let proxy = entries.iter().find(|e| {
            e.1 == "Environment" && {
                let v = e.2.to_ascii_uppercase();
                ["HTTP_PROXY=", "HTTPS_PROXY=", "NO_PROXY="]
                    .iter()
                    .any(|k| v.contains(k))
            }
        });
        let Some(proxy) = proxy else { continue };
        let hit = entries
            .iter()
            .filter(|e| e.1.starts_with("ExecStart"))
            .find_map(|e| delegated(&e.2, files));
        if let Some((client, owner)) = hit {
            // The value may embed proxy credentials: only the variable name is shown.
            out.push(violation(
                RULE_ID,
                Severity::Error,
                &f.path,
                proxy.3,
                "Environment=<proxy variable>",
                format!(
                    "the proxy environment of {} is inert: `{client}` delegates its HTTP to {owner}, which does not inherit it",
                    file_name(&f.path)
                ),
                "Configure the proxy on the process that opens the upstream socket, or run the client standalone.",
            ));
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let unit = |exec: &str, env: &str| format!("[Service]\n{env}\nExecStart={exec}\n");
    let env = "Environment=HOME=/x HTTPS_PROXY=http://127.0.0.1:9";
    let n = |text: &str| lint(&fixture(&[("a.service", text)])).len();
    let script = unit("/usr/local/bin/job", env);
    vec![
        case(
            "proxy-env: hl-autopilot replay fires",
            n(&unit("/usr/local/bin/hl-autopilot", env)) == 1,
        ),
        case(
            "proxy-env: opencode run fires, --standalone is clean",
            n(&unit("/usr/bin/opencode run", env)) == 1
                && n(&unit("/usr/bin/opencode run --standalone", env)) == 0,
        ),
        case(
            "proxy-env: process that dials itself is clean",
            n(&unit("/usr/bin/curl https://example.com", env)) == 0,
        ),
        case(
            "proxy-env: no proxy variable is clean",
            n(&unit("/usr/bin/opencode run", "Environment=HOME=/x")) == 0,
        ),
        case(
            "proxy-env: script that shells out fires",
            lint(&fixture(&[
                ("a.service", &script),
                ("bin/job", "#!/bin/sh\nopencode run x\n"),
            ]))
            .len()
                == 1,
        ),
    ]
}
