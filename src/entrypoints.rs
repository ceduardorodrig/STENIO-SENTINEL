//! `AGENT-ENTRYPOINT-RULES` (GB-033): every agent harness must point at the shared rules.
//!
//! The vault file `governance/agent-entrypoints.toml` lists each harness entry file (absolute
//! or `~/` paths) and the strings it must contain (the path of `agent-global-rules.md`, the
//! name of the shared reminder script). A required file that is missing or lacks a reference is
//! an ERROR; an optional one is a WARN. `host_only` names the host that owns the file: on any
//! other host a missing file is an INFO line, not a finding.
//!
//! `required = false` silences only an ABSENT file (the harness is not installed); a file that
//! exists and lost a reference is always an ERROR (GB-237).
//!
//! `AGENT-FANOUT-WIRED` (GB-046) and `HOOK-EVENT-COVERAGE` (GB-163) go one step further than a
//! substring: each `[[fanout]]` / `[[hook]]` line says which script a harness must run on which
//! event, the hook file is parsed (JSON, JSONC or YAML) and the script must sit under that event.
//! `canonical` is the vault script behind it (relative to the vault root): it must exist, and carry
//! `marker` when one is given. Every name in `fanout_harnesses` needs at least one `[[fanout]]`.

use serde_yaml::Value;
use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::Violation;
use crate::rule::Severity;

pub const RULE_ID: &str = "AGENT-ENTRYPOINT-RULES";
pub const FANOUT_ID: &str = "AGENT-FANOUT-WIRED";
pub const HOOK_ID: &str = "HOOK-EVENT-COVERAGE";
const CONFIG_REL: &str = "governance/agent-entrypoints.toml";

#[derive(Debug, serde::Deserialize)]
struct Config {
    #[serde(default)]
    entry: Vec<Entry>,
    #[serde(default)]
    fanout_harnesses: Vec<String>,
    #[serde(default)]
    fanout: Vec<Wire>,
    #[serde(default)]
    hook: Vec<Wire>,
}

/// One "this harness runs this script on this event" line.
#[derive(Debug, Default, serde::Deserialize)]
struct Wire {
    harness: String,
    file: String,
    event: String,
    script: String,
    #[serde(default)]
    canonical: Option<String>,
    #[serde(default)]
    marker: Option<String>,
    #[serde(default)]
    host_only: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct Entry {
    harness: String,
    file: String,
    #[serde(default)]
    must_reference: Vec<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    host_only: Option<String>,
}

/// Outcome of one entry: a PASS/INFO message or a finding.
#[derive(Debug, PartialEq)]
enum Verdict {
    Pass,
    Info(String),
    Finding(Severity, String),
}

pub struct EntrypointReport {
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

fn expand(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => Path::new(&home).join(rest),
        _ => PathBuf::from(path),
    }
}

fn current_host() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
}

fn foreign_host(host_only: Option<&str>, host: &str) -> bool {
    host_only.is_some_and(|h| !h.eq_ignore_ascii_case(host))
}

fn evaluate(entry: &Entry, content: Option<&str>, host: &str) -> Verdict {
    let Some(text) = content else {
        if foreign_host(entry.host_only.as_deref(), host) {
            return Verdict::Info(format!("{} not on this host, skipped", entry.file));
        }
        if !entry.required {
            return Verdict::Info(format!("optional {} absent, skipped", entry.file));
        }
        return Verdict::Finding(
            Severity::Error,
            format!("{} entry file {} is missing", entry.harness, entry.file),
        );
    };
    let absent: Vec<&str> = entry
        .must_reference
        .iter()
        .map(String::as_str)
        .filter(|needle| !text.contains(needle))
        .collect();
    if absent.is_empty() {
        return Verdict::Pass;
    }
    Verdict::Finding(
        Severity::Error,
        format!(
            "{} entry file {} does not reference: {}",
            entry.harness,
            entry.file,
            absent.join(", ")
        ),
    )
}

/// Parses a harness hook file: JSON and YAML directly, JSONC after dropping whole-line comments.
fn parse_hook_file(text: &str) -> Option<Value> {
    serde_yaml::from_str(text).ok().or_else(|| {
        let code: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        serde_yaml::from_str(&code.join("\n")).ok()
    })
}

fn mentions(v: &Value, needle: &str) -> bool {
    match v {
        Value::String(s) => s.contains(needle),
        Value::Sequence(s) => s.iter().any(|x| mentions(x, needle)),
        Value::Mapping(m) => m.values().any(|x| mentions(x, needle)),
        _ => false,
    }
}

/// True when some `event:` key, outside any block marked `enabled: false`, mentions `script`.
fn event_runs(v: &Value, event: &str, script: &str) -> bool {
    match v {
        Value::Sequence(s) => s.iter().any(|x| event_runs(x, event, script)),
        Value::Mapping(m) => {
            let enabled = Value::String("enabled".to_string());
            if m.get(&enabled).and_then(Value::as_bool) == Some(false) {
                return false;
            }
            m.iter().any(|(k, x)| {
                (k.as_str() == Some(event) && mentions(x, script)) || event_runs(x, event, script)
            })
        }
        _ => false,
    }
}

/// `content` is the hook file, `canonical` the text of the vault script (`None` = not readable).
fn evaluate_wire(w: &Wire, content: Option<&str>, canonical: Option<&str>, host: &str) -> Verdict {
    let fail = |m: String| Verdict::Finding(Severity::Error, format!("{}: {m}", w.harness));
    let Some(text) = content else {
        if foreign_host(w.host_only.as_deref(), host) {
            return Verdict::Info(format!("{} not on this host, skipped", w.file));
        }
        return fail(format!("hook file {} is missing", w.file));
    };
    if let Some(rel) = &w.canonical {
        let Some(body) = canonical else {
            return fail(format!("hook script {rel} is missing"));
        };
        if let Some(marker) = &w.marker
            && !body.contains(marker.as_str())
        {
            return fail(format!("hook script {rel} lacks the marker {marker:?}"));
        }
    }
    let Some(doc) = parse_hook_file(text) else {
        return fail(format!("hook file {} cannot be parsed", w.file));
    };
    if event_runs(&doc, &w.event, &w.script) {
        Verdict::Pass
    } else {
        fail(format!(
            "{} does not run {} on event {}",
            w.file, w.script, w.event
        ))
    }
}

/// Listed harnesses that declare no `[[fanout]]` line.
fn unwired_harnesses<'a>(listed: &'a [String], wires: &[Wire]) -> Vec<&'a str> {
    listed
        .iter()
        .filter(|h| !wires.iter().any(|w| w.harness == **h))
        .map(String::as_str)
        .collect()
}

/// Rule ids this module answers to (for `--only`).
pub fn owns(rule: &str) -> bool {
    [RULE_ID, FANOUT_ID, HOOK_ID]
        .iter()
        .any(|id| id.eq_ignore_ascii_case(rule))
}

/// Finds `governance/agent-entrypoints.toml` at `start` or in one of its ancestors.
fn find_config(start: &Path) -> Option<PathBuf> {
    let base = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
    base.ancestors()
        .map(|a| a.join(CONFIG_REL))
        .find(|p| p.is_file())
}

pub fn audit(start: &Path) -> EntrypointReport {
    let mut report = EntrypointReport {
        messages: Vec::new(),
        violations: Vec::new(),
    };
    let Some(cfg_path) = find_config(start) else {
        return report;
    };
    let cfg: Config = match fs::read_to_string(&cfg_path).map(|t| toml::from_str(&t)) {
        Ok(Ok(c)) => c,
        _ => {
            report.violations.push(finding(
                RULE_ID,
                &cfg_path.to_string_lossy(),
                "config",
                Severity::Error,
                "agent-entrypoints.toml cannot be parsed".to_string(),
            ));
            return report;
        }
    };
    let host = current_host();
    for entry in &cfg.entry {
        let path = expand(&entry.file);
        let content = fs::read_to_string(&path).ok();
        match evaluate(entry, content.as_deref(), &host) {
            Verdict::Pass => report
                .messages
                .push(format!("PASS {RULE_ID} {}: {}", entry.harness, entry.file)),
            Verdict::Info(m) => report
                .messages
                .push(format!("INFO {RULE_ID} {}: {m}", entry.harness)),
            Verdict::Finding(sev, m) => {
                report
                    .violations
                    .push(finding(RULE_ID, &entry.file, &entry.harness, sev, m))
            }
        }
    }
    let root = cfg_path.parent().and_then(Path::parent).unwrap_or(start);
    for (rule, wires) in [(FANOUT_ID, &cfg.fanout), (HOOK_ID, &cfg.hook)] {
        for w in wires {
            let content = fs::read_to_string(expand(&w.file)).ok();
            let canonical = w
                .canonical
                .as_ref()
                .and_then(|rel| fs::read_to_string(root.join(rel)).ok());
            match evaluate_wire(w, content.as_deref(), canonical.as_deref(), &host) {
                Verdict::Pass => report.messages.push(format!(
                    "PASS {rule} {}: {} on {}",
                    w.harness, w.script, w.event
                )),
                Verdict::Info(m) => report
                    .messages
                    .push(format!("INFO {rule} {}: {m}", w.harness)),
                Verdict::Finding(sev, m) => report
                    .violations
                    .push(finding(rule, &w.file, &w.harness, sev, m)),
            }
        }
    }
    for h in unwired_harnesses(&cfg.fanout_harnesses, &cfg.fanout) {
        report.violations.push(finding(
            FANOUT_ID,
            &cfg_path.to_string_lossy(),
            h,
            Severity::Error,
            format!("harness {h} is listed in fanout_harnesses and has no [[fanout]] line"),
        ));
    }
    report
}

fn finding(
    rule: &str,
    file: &str,
    harness: &str,
    severity: Severity,
    message: String,
) -> Violation {
    Violation {
        rule_id: rule.to_string(),
        rule_name: match rule {
            FANOUT_ID => "Harness Must Run The Fan-Out Reminder And Gate",
            HOOK_ID => "Harness Hook Event Must Run Its Script",
            _ => "Agent Entry Point Must Reference Shared Rules",
        }
        .to_string(),
        severity,
        file_path: file.to_string(),
        line_number: 1,
        snippet: harness.to_string(),
        message,
        suggestion: Some(
            "Add the missing reference to the entry file (surgical edit), or fix governance/agent-entrypoints.toml.".to_string(),
        ),
    }
}

/// GB-046 / GB-163: the wiring check passes on a good file and fires on every drift.
fn wire_cases() -> Vec<(String, bool)> {
    let wire = Wire {
        harness: "h".into(),
        file: "/x/hooks.json".into(),
        event: "PreInvocation".into(),
        script: "rituals-reminder.sh".into(),
        canonical: Some("scripts/agent-hooks/rituals-reminder.sh".into()),
        marker: Some("[R6 FAN-OUT".into()),
        host_only: None,
    };
    let good = r#"{"g":{"enabled":true,"PreInvocation":[{"command":"/s/rituals-reminder.sh"}]}}"#;
    let wrong_event = good.replace("PreInvocation", "SessionStart");
    let disabled = good.replace("true", "false");
    let script = "echo '[R6 FAN-OUT'";
    let red = |c: Option<&str>, s: Option<&str>| {
        matches!(
            evaluate_wire(&wire, c, s, "a"),
            Verdict::Finding(Severity::Error, _)
        )
    };
    let yaml = "hooks:\n  PreInvocation:\n    - command: /s/rituals-reminder.sh\n";
    vec![
        (
            "wire passes on JSON and YAML".to_string(),
            evaluate_wire(&wire, Some(good), Some(script), "a") == Verdict::Pass
                && evaluate_wire(&wire, Some(yaml), Some(script), "a") == Verdict::Pass,
        ),
        (
            "wire fails: wrong event, disabled block".to_string(),
            red(Some(&wrong_event), Some(script)) && red(Some(&disabled), Some(script)),
        ),
        (
            "wire fails: script absent, marker gone, file missing".to_string(),
            red(Some(good), None) && red(Some(good), Some("echo")) && red(None, Some(script)),
        ),
        (
            "listed harness without a fanout line".to_string(),
            unwired_harnesses(&["h".into(), "k".into()], std::slice::from_ref(&wire)) == ["k"],
        ),
    ]
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let entry = |required: bool, host: Option<&str>| Entry {
        harness: "h".into(),
        file: "/x/CLAUDE.md".into(),
        must_reference: vec!["agent-global-rules.md".into()],
        required,
        host_only: host.map(str::to_string),
    };
    let good = "see governance/agent-global-rules.md";
    vec![
        (
            "entrypoint passes with reference".to_string(),
            evaluate(&entry(true, None), Some(good), "a") == Verdict::Pass,
        ),
        (
            "entrypoint fails without reference".to_string(),
            matches!(
                evaluate(&entry(true, None), Some("nothing"), "a"),
                Verdict::Finding(Severity::Error, _)
            ) && matches!(
                evaluate(&entry(false, None), Some("nothing"), "a"),
                Verdict::Finding(Severity::Error, _)
            ),
        ),
        (
            "entrypoint missing file and host_only".to_string(),
            matches!(
                evaluate(&entry(true, None), None, "a"),
                Verdict::Finding(Severity::Error, _)
            ) && matches!(
                evaluate(&entry(true, Some("b")), None, "a"),
                Verdict::Info(_)
            ) && matches!(
                evaluate(&entry(true, Some("a")), None, "a"),
                Verdict::Finding(Severity::Error, _)
            ) && matches!(evaluate(&entry(false, None), None, "a"), Verdict::Info(_)),
        ),
    ]
    .into_iter()
    .chain(wire_cases())
    .collect()
}
