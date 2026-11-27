//! Heartbeat hook, queue edit guard, release lease and ledger backup, through the built binary.
//! Each test fails when its check is removed.

use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

type Fallible = Result<(), Box<dyn std::error::Error>>;

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

impl Fixture {
    fn new(label: &str) -> std::io::Result<Self> {
        let root =
            std::env::temp_dir().join(format!("stenio-hooks-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let gov = root.join("vault/governance");
        fs::create_dir_all(&gov)?;
        let row = "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n\
                   |---|---|---|---|---|---|---|\n\
                   | **GB-001** | fixture | [`a.md`](a.md) | 🟡 | open | a | — |\n";
        fs::write(gov.join("backlog.md"), row)?;
        fs::write(gov.join("backlog-archive.md"), "| ID |\n|---|\n")?;
        // No quota source: tests must not read a real account.
        let text = include_str!("../src/hub/defaults.toml");
        let head = text.split("[[quota.source]]").next().unwrap_or(text);
        fs::write(root.join("hub.toml"), head)?;
        Ok(Fixture(root))
    }

    fn db(&self) -> PathBuf {
        self.0.join("hub.db")
    }

    fn run(&self, args: &[&str], stdin: &str) -> std::io::Result<Run> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_stenio"))
            .args(args)
            .current_dir(&self.0)
            .env("STENIO_HUB_DB", self.db())
            .env("STENIO_HUB_CONFIG", self.0.join("hub.toml"))
            .env("HOME", &self.0)
            .env_remove("STENIO_HUB_WORKER")
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut pipe) = child.stdin.take() {
            // A command that never reads stdin may close it first.
            if let Err(e) = pipe.write_all(stdin.as_bytes())
                && e.kind() != std::io::ErrorKind::BrokenPipe
            {
                return Err(e);
            }
        }
        let out = child.wait_with_output()?;
        Ok(Run {
            code: out.status.code().unwrap_or(-1),
            out: String::from_utf8_lossy(&out.stdout).into_owned(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn join(&self, session: &str) -> Result<String, Box<dyn std::error::Error>> {
        let run = self.run(
            &[
                "hub",
                "join",
                "--harness",
                "t",
                "--session",
                session,
                "--json",
            ],
            "",
        )?;
        let value: Value = serde_json::from_str(run.out.trim())?;
        Ok(value["worker"].as_str().ok_or("no worker")?.to_string())
    }

    fn claim(&self, worker: &str, resource: &str, ttl: &str) -> std::io::Result<Run> {
        self.run(
            &["hub", "claim", "--worker", worker, resource, "--ttl", ttl],
            "",
        )
    }

    fn backlog(&self) -> PathBuf {
        self.0.join("vault/governance/backlog.md")
    }
}

fn edit(file: &Path, session: &str) -> String {
    json!({"session_id": session, "tool_name": "Edit",
        "tool_input": {"file_path": file.display().to_string()}})
    .to_string()
}

#[test]
fn guard_refuses_only_a_non_holder() -> Fallible {
    let f = Fixture::new("guard")?;
    let holder = f.join("s-holder")?;
    f.join("s-other")?;
    assert_eq!(f.claim(&holder, "backlog:GB:write", "5m")?.code, 0);
    let refused = f.run(&["hub", "guard"], &edit(&f.backlog(), "s-other"))?;
    assert_eq!(refused.code, 2, "{}", refused.err);
    assert!(refused.err.contains(&holder), "{}", refused.err);
    let own = f.run(&["hub", "guard"], &edit(&f.backlog(), "s-holder"))?;
    assert_eq!(own.code, 0, "{}", own.err);
    let area = f.0.join("vault/governance/a.md");
    assert_eq!(f.run(&["hub", "guard"], &edit(&area, "s-other"))?.code, 0);
    let read = edit(&f.backlog(), "s-other").replace("\"Edit\"", "\"Read\"");
    assert_eq!(f.run(&["hub", "guard"], &read)?.code, 0);
    let agy = json!({"conversationId": "s-other", "toolCall": {"name": "replace_file_content",
        "args": {"TargetFile": f.backlog().display().to_string()}}});
    let denied = f.run(&["hub", "guard"], &agy.to_string())?;
    assert!(denied.out.contains("\"deny\""), "{}", denied.out);
    // The guard never grants: an edit it does not block keeps the normal permission prompt.
    for payload in [
        agy.to_string().replace("s-other", "s-holder"),
        "{\"toolCall\": {\"name\": \"view_file\"}}".to_string(),
    ] {
        let passed = f.run(&["hub", "guard"], &payload)?;
        assert!(passed.out.contains("\"ask\""), "{}", passed.out);
        assert!(!passed.out.contains("allow"), "{}", passed.out);
    }
    Ok(())
}

#[test]
fn hooks_fail_open_without_a_usable_ledger() -> Fallible {
    let f = Fixture::new("open")?;
    let payload = edit(&f.backlog(), "s");
    assert_eq!(f.run(&["hub", "guard"], &payload)?.code, 0);
    assert!(!f.db().exists(), "a hook must not create the ledger");
    fs::write(f.db(), "not a database")?;
    assert_eq!(f.run(&["hub", "guard"], &payload)?.code, 0);
    assert_eq!(f.run(&["hub", "guard"], "not json")?.code, 0);
    let beat = f.run(&["hub", "beat", "--from-hook"], &payload)?;
    assert_eq!((beat.code, beat.out.as_str()), (0, ""));
    Ok(())
}

#[test]
fn hook_heartbeat_keeps_the_lease_and_its_absence_loses_it() -> Fallible {
    let f = Fixture::new("beat")?;
    let kept = f.join("s-kept")?;
    let lost = f.join("s-lost")?;
    assert_eq!(f.claim(&kept, "branch:kept", "3s")?.code, 0);
    assert_eq!(f.claim(&lost, "branch:lost", "3s")?.code, 0);
    for _ in 0..4 {
        std::thread::sleep(Duration::from_millis(1100));
        let beat = f.run(
            &["hub", "beat", "--from-hook"],
            &json!({"session_id": "s-kept"}).to_string(),
        )?;
        assert_eq!((beat.code, beat.out.as_str()), (0, ""), "{}", beat.err);
    }
    let other = f.join("s-new")?;
    assert_eq!(f.claim(&other, "branch:kept", "1m")?.code, 1);
    assert_eq!(f.claim(&other, "branch:lost", "1m")?.code, 0);
    Ok(())
}

#[test]
fn a_dead_sub_agent_expires_while_its_session_works() -> Fallible {
    let f = Fixture::new("agents")?;
    let main = f.join("s")?;
    let child = f.join("s")?;
    let seen = |worker: &str, agent: Option<&str>| {
        let mut payload = json!({"session_id": "s", "tool_name": "Bash",
            "tool_input": {"command": "stenio hub join --harness t"},
            "tool_response": {"stdout": format!("worker: {worker}")}});
        if let Some(agent) = agent {
            payload["agent_id"] = json!(agent);
        }
        f.run(&["hub", "beat", "--from-hook"], &payload.to_string())
    };
    assert_eq!(seen(&main, None)?.code, 0);
    assert_eq!(seen(&child, Some("a1"))?.code, 0);
    assert_eq!(f.claim(&main, "branch:main", "3s")?.code, 0);
    assert_eq!(f.claim(&child, "branch:child", "3s")?.code, 0);
    // The sub-agent is gone: only the main thread and a sibling keep calling tools.
    for round in 0..4 {
        std::thread::sleep(Duration::from_millis(1100));
        let mut payload = json!({"session_id": "s"});
        if round % 2 == 1 {
            payload["agent_id"] = json!("a2");
            f.run(&["hub", "beat", "--from-hook"], &payload.to_string())?;
            payload = json!({"session_id": "s"});
        }
        f.run(&["hub", "beat", "--from-hook"], &payload.to_string())?;
    }
    let other = f.join("s-new")?;
    assert_eq!(f.claim(&other, "branch:main", "1m")?.code, 1);
    assert_eq!(f.claim(&other, "branch:child", "1m")?.code, 0);
    Ok(())
}

#[test]
fn release_engine_needs_the_release_claim() -> Fallible {
    let f = Fixture::new("release")?;
    let holder = f.join("s-holder")?;
    let other = f.join("s-other")?;
    let repo = f.0.display().to_string();
    let release = |worker: &str, extra: &[&str]| {
        let mut args = vec![
            "release-engine",
            "--tag",
            "v0.0.0",
            "--repo",
            &repo,
            "--skip-ci",
            "--worker",
            worker,
        ];
        args.extend_from_slice(extra);
        f.run(&args, "")
    };
    let nobody = release(&holder, &[])?;
    assert_eq!(nobody.code, 1);
    assert!(
        nobody.out.contains("nobody holds release:stenio"),
        "{}",
        nobody.out
    );
    assert!(!nobody.out.contains("tag-local"), "{}", nobody.out);
    assert_eq!(f.claim(&holder, "release:stenio", "5m")?.code, 0);
    let foreign = release(&other, &[])?;
    assert!(foreign.out.contains("is held by"), "{}", foreign.out);
    assert!(!foreign.out.contains("tag-local"), "{}", foreign.out);
    let bypass = release(&other, &["--without-lease"])?;
    assert!(
        bypass.out.contains("interactive terminal"),
        "{}",
        bypass.out
    );
    // The holder passes the gate and fails later, on the tag that does not exist.
    let mine = release(&holder, &[])?;
    assert!(mine.out.contains("PASS lease"), "{}", mine.out);
    assert!(mine.out.contains("tag-local"), "{}", mine.out);
    Ok(())
}

#[test]
fn backup_restores_and_reports_staleness() -> Fallible {
    let f = Fixture::new("backup")?;
    let worker = f.join("s")?;
    assert_eq!(f.claim(&worker, "branch:x", "5m")?.code, 0);
    // The real backup tree is a synchronised folder, where a ledger is never opened.
    fs::create_dir_all(f.0.join("synced/.stfolder"))?;
    let out = f.0.join("synced/backups");
    let dir = out.display().to_string();
    let done = f.run(&["hub", "backup", "--out", &dir], "")?;
    assert_eq!(done.code, 0, "{}", done.err);
    assert_eq!(f.run(&["hub", "backup", "--check", &dir], "")?.code, 0);
    let files = || -> std::io::Result<Vec<PathBuf>> {
        fs::read_dir(&out)?.map(|e| e.map(|e| e.path())).collect()
    };
    assert_eq!(
        files()?.len(),
        2,
        "snapshot and export only: {:?}",
        files()?
    );
    let snapshot = files()?
        .into_iter()
        .find(|p| p.extension().is_some_and(|x| x == "db"))
        .ok_or("no snapshot")?;
    // The restored copy passes the same audit the live ledger does.
    let restored = f.0.join("restored.db");
    fs::copy(&snapshot, &restored)?;
    let audit = Command::new(env!("CARGO_BIN_EXE_stenio"))
        .args(["hub", "audit"])
        .env("STENIO_HUB_DB", &restored)
        .env("STENIO_HUB_CONFIG", f.0.join("hub.toml"))
        .output()?;
    assert!(audit.status.success());
    // 27 hours old by its recorded instant.
    let old = chrono::Utc::now() - chrono::Duration::hours(27);
    let aged = out.join(format!("hub-{}.db", old.format("%Y%m%dT%H%M%S%3fZ")));
    fs::rename(&snapshot, &aged)?;
    let stale = f.run(&["hub", "backup", "--check", &dir], "")?;
    assert_eq!(stale.code, 1);
    assert!(stale.err.contains("backup_stale"), "{}", stale.err);
    fs::write(&aged, "damaged")?;
    assert_ne!(
        f.run(&["hub", "backup", "--check", &dir, "--max-age", "48h"], "")?
            .code,
        0
    );
    Ok(())
}
