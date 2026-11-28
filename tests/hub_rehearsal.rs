//! The engine defects of the acceptance rehearsal of 2026-11-28 (GB-422, GB-416, GB-417,
//! GB-420), through the built binary and its own temporary ledger.

use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

type Fallible = Result<(), Box<dyn std::error::Error>>;
type Made<T> = Result<T, Box<dyn std::error::Error>>;

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl Fixture {
    fn new(label: &str) -> Made<Self> {
        let root =
            std::env::temp_dir().join(format!("stenio-rehearsal-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let gov = root.join("vault/governance");
        fs::create_dir_all(&gov)?;
        fs::create_dir_all(root.join("home"))?;
        let rows: String = (1..=3)
            .map(|n| format!("| **GB-00{n}** | item | [`a.md`](a.md) | low | open | a | - |\n"))
            .collect();
        fs::write(
            gov.join("backlog.md"),
            format!(
                "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n|---|---|---|---|---|---|---|\n{rows}"
            ),
        )?;
        let text = include_str!("../src/hub/defaults.toml");
        let head = text.split("\n[[quota.source]]").next().unwrap_or(text);
        fs::write(root.join("hub.toml"), format!("{head}\n"))?;
        Ok(Fixture(root))
    }

    fn command(&self, session: Option<&str>) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_stenio"));
        c.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.0.join("home"))
            .env("STENIO_HUB_DB", self.0.join("state/hub.db"))
            .env("STENIO_HUB_CONFIG", self.0.join("hub.toml"))
            .current_dir(self.0.join("vault"));
        if let Some(s) = session {
            c.env("CLAUDE_CODE_SESSION_ID", s);
        }
        c
    }

    fn hub_in(&self, session: Option<&str>, args: &[&str]) -> Made<(i32, Value)> {
        let out = self
            .command(session)
            .arg("hub")
            .args(args)
            .arg("--json")
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let value = serde_json::from_str(text.trim()).unwrap_or_else(|_| json!(text.trim()));
        Ok((out.status.code().unwrap_or(-1), value))
    }

    fn ok(&self, args: &[&str]) -> Made<Value> {
        let (code, value) = self.hub_in(None, args)?;
        assert_eq!(code, 0, "{args:?} -> {value}");
        Ok(value)
    }

    fn join(&self, extra: &[&str]) -> Made<String> {
        let mut args = vec!["join", "--harness", "claude-code"];
        args.extend_from_slice(extra);
        Ok(self.ok(&args)?["worker"]
            .as_str()
            .ok_or("no worker")?
            .to_string())
    }

    fn events(&self, run: &str) -> Made<Vec<Value>> {
        let out = self
            .command(None)
            .args(["hub", "export", "--run", run])
            .output()?;
        String::from_utf8(out.stdout)?
            .lines()
            .map(|l| Ok(serde_json::from_str(l)?))
            .collect()
    }
}

#[test]
fn gb422_a_claim_without_a_row_joins_a_run_only_through_its_coordinator() -> Fallible {
    let f = Fixture::new("adopt")?;
    let lead = f.join(&[])?;
    let run = f.ok(&[
        "run", "start", "--path", ".", "--rows", "GB-001", "--slots", "2",
    ])?;
    let run = run["run"].as_str().ok_or("no run")?.to_string();
    let stranger = f.join(&[])?;
    let other = f.ok(&["claim", "--worker", &stranger, "release:app"])?;
    assert_eq!(other["run"], Value::Null, "{other}");
    f.ok(&["claim", "--worker", &lead, "row:GB-001"])?;
    let child = f.join(&["--parent", &lead])?;
    let theirs = f.ok(&["claim", "--worker", &child, "host:node-a"])?;
    assert_eq!(theirs["run"], json!(run), "{theirs}");
    assert!(
        f.events(&run)?
            .iter()
            .all(|e| e["worker"] != json!(stranger)),
        "a foreign claim is in the run"
    );
    Ok(())
}

#[test]
fn gb416_the_run_export_holds_each_member_join_and_refusal() -> Fallible {
    let f = Fixture::new("audit")?;
    let first = f.join(&["--session", "s-one"])?;
    let second = f.join(&["--session", "s-two"])?;
    let run = f.ok(&[
        "run", "start", "--path", ".", "--rows", "GB-001", "--slots", "2",
    ])?;
    let run = run["run"].as_str().ok_or("no run")?.to_string();
    f.ok(&["claim", "--worker", &first, "row:GB-001"])?;
    let (code, no) = f.hub_in(None, &["claim", "--worker", &second, "row:GB-001"])?;
    assert_eq!((code, no["code"].as_str()), (1, Some("held")), "{no}");
    let events = f.events(&run)?;
    let join = events
        .iter()
        .find(|e| e["type"] == "join" && e["worker"] == json!(first))
        .ok_or("no join")?;
    assert_eq!(join["payload"]["session"], "s-one", "{join}");
    assert!(
        events.iter().any(|e| e["type"] == "refused"
            && e["worker"] == json!(second)
            && e["payload"]["code"] == "held"),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["type"] == "join" && e["worker"] == json!(second)),
        "the refused member's join"
    );
    f.ok(&["audit"])?;
    Ok(())
}

#[test]
fn gb417_a_second_takeover_still_receives_the_checkpoint() -> Fallible {
    let f = Fixture::new("takeover")?;
    let (a, b, c) = (f.join(&[])?, f.join(&[])?, f.join(&[])?);
    let fence = f.ok(&["claim", "--worker", &a, "row:GB-001", "--ttl", "1"])?["fence"]
        .as_i64()
        .ok_or("no fence")?
        .to_string();
    f.ok(&[
        "event",
        "--worker",
        &a,
        "--type",
        "checkpoint",
        "--fence",
        &fence,
        "--next-step",
        "resume here",
    ])?;
    let wait = || std::thread::park_timeout(std::time::Duration::from_millis(1300));
    wait();
    f.ok(&["claim", "--worker", &b, "row:GB-001", "--ttl", "1"])?;
    wait();
    let third = f.ok(&["claim", "--worker", &c, "row:GB-001"])?;
    let told = &third["takeover"][0];
    assert_eq!(told["checkpoint"]["next_step"], "resume here", "{third}");
    assert_eq!(told["checkpoint_by"], json!(a), "{third}");
    assert!(told["checkpoint_host"].is_string(), "{third}");
    Ok(())
}

#[test]
fn gb420_a_bound_session_needs_no_worker_argument() -> Fallible {
    let f = Fixture::new("infer")?;
    let (code, no) = f.hub_in(Some("sess-9"), &["claim", "row:GB-001"])?;
    assert_eq!(code, 2, "{no}");
    assert!(no.to_string().contains("hub join"), "{no}");
    f.ok(&["join", "--harness", "claude-code", "--session", "sess-9"])?;
    let (code, taken) = f.hub_in(Some("sess-9"), &["claim", "row:GB-001"])?;
    assert_eq!(code, 0, "{taken}");
    f.ok(&["join", "--harness", "claude-code", "--session", "sess-9"])?;
    let (code, two) = f.hub_in(Some("sess-9"), &["claim", "row:GB-002"])?;
    assert_eq!(code, 2, "{two}");
    assert!(two.to_string().contains("several workers"), "{two}");
    Ok(())
}
