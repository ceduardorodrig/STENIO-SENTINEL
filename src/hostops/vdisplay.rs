//! `PUNKTFUNK-VDISPLAY-EMPTY-WORKSPACE` (GB-253): the streamed virtual head shows an empty
//! workspace while the windows are on another monitor.

use serde_json::Value;

use super::{case, host_arg, host_run, opt, unreadable, verdict};
use crate::explain::RuleExplanation;

pub const RULE_ID: &str = "PUNKTFUNK-VDISPLAY-EMPTY-WORKSPACE";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Streamed Virtual Display Shows An Empty Workspace",
    severity: "WARNING",
    tag: "gaming",
    summary: "`stenio hostops vdisplay --host local [--prefix PF]` reads `hyprctl -j monitors` and `clients`: a virtual head whose active workspace has no window while other monitors have windows would stream a black screen.",
    rationale: "GB-253: PF-1 came up on workspace 4 with 0 windows while all 6 clients sat on HDMI-A-4; NVENC kept encoding 27 fps of black.",
    bad_example: "PF-1 active workspace 4: 0 windows; HDMI-A-4: 6 windows",
    good_example: "PF-1 mirrors the populated desk or its workspace has windows",
    remediation: "Move a window or the workspace to the virtual head, or mirror the populated monitor.",
};

pub fn check(prefix: &str, monitors: &Value, clients: &Value) -> (Vec<String>, usize) {
    let none = Vec::new();
    let monitors = monitors.as_array().unwrap_or(&none);
    let clients = clients.as_array().unwrap_or(&none);
    let windows = |ws: i64| {
        clients
            .iter()
            .filter(|c| c["workspace"]["id"].as_i64() == Some(ws))
            .count()
    };
    let (mut found, mut heads) = (Vec::new(), 0);
    for m in monitors {
        let name = m["name"].as_str().unwrap_or("");
        let Some(ws) = m["activeWorkspace"]["id"].as_i64() else {
            continue;
        };
        if !name.starts_with(prefix) {
            continue;
        }
        heads += 1;
        if windows(ws) == 0 && !clients.is_empty() {
            found.push(format!(
                "{name} shows workspace {ws} with 0 windows while {} window(s) are elsewhere: the stream would be black",
                clients.len()
            ));
        }
    }
    (found, heads)
}

pub fn run_cli(args: &[String]) -> i32 {
    let host = host_arg(args).unwrap_or_else(|| "local".to_string());
    let prefix = opt(args, "--prefix").unwrap_or_else(|| "PF".to_string());
    let read = |what: &str| -> Result<Value, String> {
        let out = host_run(&host, &format!("hyprctl -j {what}"))?;
        serde_json::from_str(&out).map_err(|e| format!("hyprctl {what}: {e}"))
    };
    match (read("monitors"), read("clients")) {
        (Ok(m), Ok(c)) => {
            let (found, heads) = check(&prefix, &m, &c);
            if heads == 0 {
                println!("SKIP {RULE_ID} {host}: no virtual head matching '{prefix}' is present");
                return 0;
            }
            verdict(RULE_ID, &host, heads, &found)
        }
        (Err(e), _) | (_, Err(e)) => unreadable(RULE_ID, e),
    }
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let monitors = serde_json::json!([
        {"name": "HDMI-A-4", "activeWorkspace": {"id": 1}},
        {"name": "PF-1", "activeWorkspace": {"id": 4}}
    ]);
    let away = serde_json::json!([{"workspace": {"id": 1}}]);
    let there = serde_json::json!([{"workspace": {"id": 4}}]);
    vec![
        case(
            "vdisplay: empty head with windows elsewhere fires",
            check("PF", &monitors, &away).0.len() == 1,
        ),
        case(
            "vdisplay: populated head passes",
            check("PF", &monitors, &there) == (Vec::new(), 1),
        ),
        case(
            "vdisplay: an empty desk is not a finding",
            check("PF", &monitors, &serde_json::json!([])).0.is_empty(),
        ),
    ]
}
