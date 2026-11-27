//! `HL-LUA-NO-HYPRCTL-IN-SHUTDOWN` (GB-239): blocking IPC inside Hyprland teardown handlers.

use super::lua_load_api::lua_calls;
use super::{SourceFile, case, fixture, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "HL-LUA-NO-HYPRCTL-IN-SHUTDOWN";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Blocking Shell-Out In A Hyprland Shutdown Handler",
    severity: "ERROR",
    tag: "gaming",
    summary: "os.execute or io.popen (or an exec of hyprctl / a session saver) inside hl.on(\"hyprland.shutdown\") or hl.on(\"config.unload\").",
    rationale: "GB-239: autostart.lua saved the session from hyprland.shutdown. In Hyprland 0.57.1 that event is emitted only by the exit dispatcher (ConfigActions.cpp:1249), so reboot, poweroff and `uwsm stop` (SIGTERM) never run it; and the hyprctl socket shares the compositor event loop under a 50 ms Lua watchdog, so the call cannot be answered.",
    bad_example: "hl.on(\"hyprland.shutdown\", function() os.execute(\"hypr-session-save\") end)",
    good_example: "# event-sourced saver daemon, or ExecStopPre= of a systemd user unit",
    remediation: "Save from a daemon that follows compositor events, or from a systemd unit; never depend on this event.",
};

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let mut out = Vec::new();
    for f in files.iter().filter(|f| f.path.ends_with(".lua")) {
        for call in lua_calls(&f.content) {
            let Some(event @ ("hyprland.shutdown" | "config.unload")) = call.event.as_deref()
            else {
                continue;
            };
            let blocking = matches!(call.name.as_str(), "os.execute" | "io.popen");
            let ipc = call.name.starts_with("hl.exec")
                && (call.text.contains("hyprctl") || call.text.contains("session"));
            if blocking || ipc {
                out.push(violation(
                    RULE_ID,
                    Severity::Error,
                    &f.path,
                    call.line,
                    &call.text,
                    format!(
                        "{} inside the {event} handler: hyprland.shutdown does not fire on SIGTERM/reboot, and an IPC call from the handler cannot be answered by the blocked compositor",
                        call.name
                    ),
                    "Save from an event-sourced daemon or a systemd unit instead.",
                ));
            }
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let n = |src: &str| lint(&fixture(&[("autostart.lua", src)])).len();
    vec![
        case(
            "lua-shutdown: os.execute saver in shutdown fires",
            n(
                "hl.on(\"hyprland.shutdown\", function()\n  os.execute(os.getenv(\"HOME\") .. \"/.local/bin/hypr-session-save\")\nend)\n",
            ) == 1,
        ),
        case(
            "lua-shutdown: hyprctl exec in config.unload fires",
            n("hl.on('config.unload', function() hl.exec_cmd('hyprctl clients') end)\n") == 1,
        ),
        case(
            "lua-shutdown: the same call at start is clean",
            n("hl.on(\"hyprland.start\", function() os.execute(\"hypr-session-save\") end)\n") == 0,
        ),
    ]
}
