//! `stenio gate hook` as a harness runs it: payload on stdin, decision by exit code or JSON.
//! Every command here is only text in a payload; nothing is executed.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Home(PathBuf);

impl Home {
    fn new(label: &str) -> Home {
        let dir = std::env::temp_dir().join(format!("stenio-gt-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temporary home");
        Home(dir)
    }

    fn stenio(&self, args: &[&str], stdin: &str, ledger: &Path) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_stenio"))
            .args(args)
            .env_clear()
            .env("HOME", &self.0)
            .env("STENIO_HUB_DB", ledger)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn stenio");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(stdin.as_bytes())
            .expect("write payload");
        child.wait_with_output().expect("wait")
    }

    fn hook(&self, payload: &str) -> Output {
        self.stenio(&["gate", "hook"], payload, &self.0.join("hub.db"))
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const FORCE: &str =
    r#"{"tool_name":"terminal","tool_input":{"command":"git push --force"},"session_id":"s1"}"#;
const PLAIN: &str =
    r#"{"tool_name":"Bash","tool_input":{"command":"git status"},"session_id":"s1"}"#;
const DEPLOY: &str = r#"{"tool_name":"shell","tool_input":{"command":"docker stack deploy -c s.yml a"},"session_id":"s1"}"#;

#[test]
fn deny_exits_two_and_ordinary_work_is_silent() {
    let home = Home::new("deny");
    let denied = home.hook(FORCE);
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("GATE-HISTORY"));
    let allowed = home.hook(PLAIN);
    assert_eq!(allowed.status.code(), Some(0));
    assert!(allowed.stdout.is_empty() && allowed.stderr.is_empty());
}

#[test]
fn antigravity_gets_deny_or_ask_never_allow() {
    let home = Home::new("agy");
    let call = |command: &str| {
        let payload = format!(
            r#"{{"toolCall":{{"name":"run_command","args":{{"CommandLine":"{command}"}}}},"conversationId":"c"}}"#
        );
        let out = home.hook(&payload);
        assert_eq!(out.status.code(), Some(0));
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    assert!(call("reboot").contains(r#""decision":"deny""#));
    assert_eq!(call("ls").trim(), r#"{"decision":"ask"}"#);
}

#[test]
fn an_unusable_ledger_keeps_the_list_and_never_locks_out_work() {
    let home = Home::new("broken");
    let ledger = home.0.join("not-a-database");
    std::fs::write(&ledger, "garbage, not sqlite").expect("write");
    let run = |p: &str| home.stenio(&["gate", "hook"], p, &ledger).status.code();
    assert_eq!(run(FORCE), Some(2));
    assert_eq!(run(DEPLOY), Some(2));
    assert_eq!(run(PLAIN), Some(0));
    assert_eq!(run("not json"), Some(0));
}

#[test]
fn a_held_lease_allows_publishing_only_to_its_holder() {
    let home = Home::new("lease");
    let ledger = home.0.join("hub.db");
    let hub = |args: &[&str]| home.stenio(args, "", &ledger);
    let joined = hub(&[
        "hub",
        "join",
        "--harness",
        "hermes",
        "--account",
        "t",
        "--session",
        "s1",
        "--json",
    ]);
    let text = String::from_utf8_lossy(&joined.stdout).to_string();
    let reply: serde_json::Value = serde_json::from_str(&text).expect("join answers JSON");
    let worker = reply["worker"].as_str().expect("worker id");
    assert_eq!(home.hook(DEPLOY).status.code(), Some(2));
    let claimed = hub(&["hub", "claim", "--worker", worker, "deploy:app"]);
    assert_eq!(claimed.status.code(), Some(0));
    assert_eq!(home.hook(DEPLOY).status.code(), Some(0));
    let other = DEPLOY.replace("s1", "s2");
    assert_eq!(home.hook(&other).status.code(), Some(2));
    assert_eq!(home.hook(FORCE).status.code(), Some(2));
}

#[test]
fn every_judged_call_is_recorded_and_redacted() {
    let home = Home::new("audit");
    home.hook(PLAIN);
    home.hook(r#"{"tool_name":"Bash","tool_input":{"command":"API_TOKEN=hunter2value reboot"}}"#);
    let ledger = home.0.join("hub.db");
    let report = home.stenio(&["gate", "report"], "", &ledger);
    let text = String::from_utf8_lossy(&report.stdout).to_string();
    assert_eq!(report.status.code(), Some(0), "{text}");
    assert!(
        text.contains("entries=2") && text.contains("chain ok"),
        "{text}"
    );
    assert!(!text.contains("hunter2value"), "{text}");
}

#[test]
fn an_override_needs_the_owner_at_a_terminal() {
    let home = Home::new("owner");
    let ledger = home.0.join("hub.db");
    let out = home.stenio(
        &[
            "gate",
            "override",
            "--rule",
            "GATE-POWER",
            "--for",
            "1h",
            "--reason",
            "x",
        ],
        "GATE-POWER\n",
        &ledger,
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(home.hook(FORCE).status.code(), Some(2));
}
