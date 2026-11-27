//! `HL-LUA-RUNTIME-API-AT-LOAD` (GB-234): Hyprland runtime-only Lua calls while the config loads.

use super::{SourceFile, case, fixture, violation};
use crate::engine::Violation;
use crate::explain::RuleExplanation;
use crate::rule::Severity;

pub const RULE_ID: &str = "HL-LUA-RUNTIME-API-AT-LOAD";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Hyprland Runtime-Only API Called While The Config Loads",
    severity: "ERROR",
    tag: "gaming",
    summary: "hl.exec_scheduled_prop_refresh_immediately, hl.dispatch, hl.get_windows or hl.get_monitor(s) called at the top level of a Hyprland Lua config or inside a config.reloaded handler.",
    rationale: "GB-234: workspaces.lua:54 called the immediate prop refresh at load; CPropRefresher::refreshProp ran before g_pInputManager existed (Hyprland 0.57.1) and the compositor died with SIGABRT, reproduced headless with four lines of Lua. Calls inside other functions run later and are not reported.",
    bad_example: "hl.exec_scheduled_prop_refresh_immediately()",
    good_example: "hl.on(\"hyprland.start\", function() hl.exec_scheduled_prop_refresh_immediately() end)",
    remediation: "Move the call into a runtime event handler such as hyprland.start.",
};

const RUNTIME_API: &[&str] = &[
    "hl.exec_scheduled_prop_refresh_immediately",
    "hl.dispatch",
    "hl.get_windows",
    "hl.get_monitor",
    "hl.get_monitors",
];

/// A call found in a Lua source, with the event of the nearest enclosing `hl.on` handler.
pub(super) struct LuaCall {
    pub name: String,
    pub line: usize,
    /// True when no `function` encloses the call.
    pub top_level: bool,
    pub event: Option<String>,
    /// String literals between the call name and the end of its line.
    pub text: String,
}

/// Minimal Lua walk: skips comments and strings and tracks which blocks are functions.
pub(super) fn lua_calls(src: &str) -> Vec<LuaCall> {
    let chars: Vec<char> = src.chars().collect();
    let lines: Vec<&str> = src.lines().collect();
    // One entry per open block: Some(event) for a function, None for if/do/repeat.
    let mut stack: Vec<(bool, Option<String>)> = Vec::new();
    let mut pending_on = false;
    let mut pending_event: Option<String> = None;
    let mut out = Vec::new();
    let (mut i, mut line) = (0usize, 1usize);
    let long_close = |from: usize| -> usize {
        let mut j = from;
        while j + 1 < chars.len() && !(chars[j] == ']' && chars[j + 1] == ']') {
            j += 1;
        }
        (j + 2).min(chars.len())
    };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied().unwrap_or(' ');
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c == '-' && next == '-' {
            if chars.get(i + 2) == Some(&'[') && chars.get(i + 3) == Some(&'[') {
                let end = long_close(i + 4);
                line += chars[i..end].iter().filter(|c| **c == '\n').count();
                i = end;
            } else {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
        } else if c == '[' && next == '[' {
            let end = long_close(i + 2);
            line += chars[i..end].iter().filter(|c| **c == '\n').count();
            i = end;
        } else if c == '"' || c == '\'' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] != c && chars[j] != '\n' {
                j += if chars[j] == '\\' { 2 } else { 1 };
            }
            if pending_on {
                pending_event = Some(chars[i + 1..j.min(chars.len())].iter().collect());
                pending_on = false;
            }
            i = (j + 1).min(chars.len());
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || "_.".contains(chars[i])) {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            match word.as_str() {
                "function" => stack.push((true, pending_event.take())),
                "if" | "do" | "repeat" => stack.push((false, None)),
                "end" | "until" => {
                    stack.pop();
                }
                _ => {
                    let called = chars[i..]
                        .iter()
                        .find(|c| !c.is_whitespace())
                        .is_some_and(|c| matches!(c, '(' | '"' | '\'' | '{'));
                    if word == "hl.on" {
                        pending_on = true;
                    } else if called && word.contains('.') {
                        out.push(LuaCall {
                            name: word,
                            line,
                            top_level: !stack.iter().any(|b| b.0),
                            event: stack.iter().rev().find_map(|b| b.1.clone()),
                            text: lines.get(line - 1).unwrap_or(&"").trim().to_string(),
                        });
                    }
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

pub fn lint(files: &[SourceFile]) -> Vec<Violation> {
    let mut out = Vec::new();
    for f in files.iter().filter(|f| f.path.ends_with(".lua")) {
        for call in lua_calls(&f.content) {
            let reload = call.event.as_deref() == Some("config.reloaded");
            if !RUNTIME_API.contains(&call.name.as_str()) || !(call.top_level || reload) {
                continue;
            }
            let place = if reload {
                "inside a config.reloaded handler"
            } else {
                "at the top level (config load)"
            };
            out.push(violation(
                RULE_ID,
                Severity::Error,
                &f.path,
                call.line,
                &call.text,
                format!(
                    "runtime-only call {} {place}: the compositor subsystems it touches may not exist yet",
                    call.name
                ),
                "Move the call into a runtime event handler such as hyprland.start.",
            ));
        }
    }
    out
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let n = |src: &str| lint(&fixture(&[("c.lua", src)])).len();
    vec![
        case(
            "lua-load: top-level refresh fires",
            n("local x = 1\nhl.exec_scheduled_prop_refresh_immediately()\n") == 1,
        ),
        case(
            "lua-load: top-level if block still fires",
            n("if true then\n  hl.dispatch(\"x\")\nend\n") == 1,
        ),
        case(
            "lua-load: config.reloaded handler fires",
            n("hl.on(\"config.reloaded\", function() hl.get_windows() end)\n") == 1,
        ),
        case(
            "lua-load: other handlers and functions are clean",
            n(
                "local function f() for _ in pairs(hl.get_monitors()) do end end\nhl.on(\"hyprland.start\", function()\n  if a then hl.dispatch(\"x\") end\nend)\n",
            ) == 0,
        ),
        case(
            "lua-load: comments and strings are clean",
            n("-- hl.dispatch(x)\n--[[ hl.get_windows() ]]\nlocal s = \"hl.dispatch()\"\n") == 0,
        ),
    ]
}
