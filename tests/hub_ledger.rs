//! Acceptance tests of the shared work ledger (design document, tests A1 to A18), driven through
//! the built binary: its command line and its stdio MCP server. A19 belongs to the HTTP server.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

type Fallible = Result<(), Box<dyn std::error::Error>>;

const ROWS: &str = "GB-001,GB-002,GB-003,GB-004,GB-005,GB-006";

struct Fixture {
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.db(), fs::Permissions::from_mode(0o600));
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The embedded declaration without its quota sources.
/// The gate tests declare their own limits, so a change of the shipped policy leaves them.
fn config_head() -> String {
    shipped_head()
        .replace("stop_percent = 100.0", "stop_percent = 80.0")
        .replace("throttle_percent = 100.0", "throttle_percent = 60.0")
        .replace("throttle_workers = 5", "throttle_workers = 2")
        .replace("unknown_workers = 5", "unknown_workers = 1")
}

/// The shipped declaration without its quota sources.
fn shipped_head() -> String {
    let text = include_str!("../src/hub/defaults.toml");
    // The comment about `[[quota.limit]]` stays; the sources start at the first table.
    let head = text.split("\n[[quota.source]]").next().unwrap_or(text);
    format!("{head}\n")
}

fn row(n: usize) -> String {
    format!("| **GB-00{n}** | fixture item {n} | [`area.md`](area.md) | 🟡 | open | a | — |\n")
}

impl Fixture {
    /// A temporary vault with the queue rows GB-001 to GB-006 and its own ledger.
    fn new(label: &str) -> std::io::Result<Self> {
        let root = std::env::temp_dir().join(format!("stenio-hub-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let gov = root.join("vault/governance");
        fs::create_dir_all(&gov)?;
        fs::create_dir_all(root.join("home"))?;
        let rows: String = (1..=6).map(row).collect();
        fs::write(
            gov.join("backlog.md"),
            format!(
                "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n\
                 |---|---|---|---|---|---|---|\n{rows}"
            ),
        )?;
        fs::write(
            gov.join("backlog-archive.md"),
            "| ID | Item | Ref | Sev | State | Closed | Recurred-by |\n\
             |---|---|---|---|---|---|---|\n",
        )?;
        fs::write(
            gov.join("area.md"),
            "---\ntags: [gov]\npending: [GB-001, GB-002, GB-003, GB-004, GB-005, GB-006]\n---\n# Area\n",
        )?;
        // No quota source: a test never runs a command of the host.
        fs::write(root.join("hub.toml"), config_head())?;
        Ok(Fixture { root })
    }

    fn vault(&self) -> PathBuf {
        self.root.join("vault")
    }

    fn db(&self) -> PathBuf {
        self.root.join("state/hub.db")
    }

    /// The binary with an environment that cannot reach the host's ledger or configuration.
    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_stenio"));
        c.env("STENIO_HUB_DB", self.db())
            .env("HOME", self.root.join("home"))
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_STATE_HOME")
            .env("STENIO_HUB_CONFIG", self.root.join("hub.toml"))
            .env_remove("STENIO_HUB_WORKER")
            .current_dir(self.vault());
        c
    }

    fn spawn(&self, args: &[&str]) -> std::io::Result<Child> {
        self.command()
            .arg("hub")
            .args(args)
            .arg("--json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    /// `stenio hub <args> --json`: exit code and the JSON document.
    fn hub(&self, args: &[&str]) -> Result<(i32, Value), Box<dyn std::error::Error>> {
        finish(self.spawn(args)?)
    }

    /// A call that must succeed.
    fn ok(&self, args: &[&str]) -> Result<Value, Box<dyn std::error::Error>> {
        let (code, value) = self.hub(args)?;
        assert_eq!(code, 0, "{args:?} -> {value}");
        Ok(value)
    }

    /// A call that must be refused with exit 1 and this code.
    fn refused(&self, args: &[&str], why: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let (code, value) = self.hub(args)?;
        assert_eq!(
            (code, value["code"].as_str()),
            (1, Some(why)),
            "{args:?} -> {value}"
        );
        assert!(value["next"].is_string(), "no next action: {value}");
        Ok(value)
    }

    fn join(&self, harness: &str) -> Result<String, Box<dyn std::error::Error>> {
        let out = self.ok(&["join", "--harness", harness])?;
        Ok(out["worker"].as_str().ok_or("no worker id")?.to_string())
    }

    fn claim(&self, worker: &str, resources: &str) -> Result<i64, Box<dyn std::error::Error>> {
        let out = self.ok(&["claim", "--worker", worker, resources])?;
        Ok(out["fence"].as_i64().ok_or("no fence")?)
    }

    fn export(&self) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        let out = self.command().args(["hub", "export"]).output()?;
        assert!(out.status.success(), "export failed");
        String::from_utf8(out.stdout)?
            .lines()
            .map(|l| Ok(serde_json::from_str(l)?))
            .collect()
    }

    fn sql(&self, statement: &str) -> Fallible {
        rusqlite::Connection::open(self.db())?.execute_batch(statement)?;
        Ok(())
    }
}

fn finish(child: Child) -> Result<(i32, Value), Box<dyn std::error::Error>> {
    let out = child.wait_with_output()?;
    let code = out.status.code().ok_or("killed by a signal")?;
    let text = String::from_utf8(out.stdout)?;
    let value = serde_json::from_str(text.trim()).map_err(|e| {
        format!(
            "exit {code}, not JSON ({e}): {text}{}",
            String::from_utf8_lossy(&out.stderr)
        )
    })?;
    Ok((code, value))
}

fn pause(ms: u64) {
    let (start, wanted) = (std::time::Instant::now(), Duration::from_millis(ms));
    // `park_timeout` may wake early, so wait for what is left.
    while let Some(left) = wanted.checked_sub(start.elapsed()) {
        std::thread::park_timeout(left);
    }
}

/// Waits until a one-second lease is certainly over.
fn expire() {
    pause(1_200);
}

#[test]
fn a1_a2_a4_claims_are_exclusive_and_all_or_nothing() -> Fallible {
    let f = Fixture::new("claims")?;
    let (w1, w2) = (f.join("claude")?, f.join("hermes")?);
    assert!(f.claim(&w1, "row:GB-001")? > 0);
    let no = f.refused(&["claim", "--worker", &w2, "row:GB-001"], "held")?;
    assert_eq!(no["holder"], w1.as_str());
    assert!(no["expires"].is_string());

    f.claim(&w1, "row:GB-003,tree:/x")?;
    f.refused(&["claim", "--worker", &w2, "row:GB-004,tree:/x"], "held")?;
    // A tree inside a held tree is the same collision.
    f.refused(
        &["claim", "--worker", &w2, "row:GB-004,tree:/x/sub"],
        "held",
    )?;
    let status = f.ok(&["status"])?;
    assert!(!status.to_string().contains("row:GB-004"), "{status}");
    f.claim(&w2, "row:GB-004")?;

    // Another spelling of a held resource is the same resource.
    f.refused(&["claim", "--worker", &w2, "row:gb-1"], "held")?;
    f.claim(&w1, "host:Node-A")?;
    f.refused(&["claim", "--worker", &w2, "host:node-a"], "held")?;
    std::os::unix::fs::symlink(f.vault(), f.root.join("alias"))?;
    f.claim(&w1, &format!("tree:{}/new-dir", f.vault().display()))?;
    let aliased = format!("tree:{}/alias/new-dir", f.root.display());
    f.refused(&["claim", "--worker", &w2, &aliased], "held")?;
    // Misuse is distinct from refusal.
    assert_eq!(f.hub(&["claim", "--worker", &w1, "row:XX-1"])?.0, 2);
    f.refused(
        &["claim", "--worker", "nobody", "row:GB-006"],
        "unknown_worker",
    )?;
    Ok(())
}

#[test]
fn a3_twenty_processes_claiming_one_row_give_exactly_one_winner() -> Fallible {
    let f = Fixture::new("race")?;
    // One account with a fresh low reading, so the quota gate cannot hide a race.
    f.ok(&[
        "quota",
        "put",
        "--account",
        "bulk",
        "--window",
        "w",
        "--used",
        "1",
    ])?;
    let mut workers = Vec::new();
    for _ in 0..20 {
        let out = f.ok(&["join", "--harness", "claude", "--account", "bulk"])?;
        workers.push(out["worker"].as_str().ok_or("no id")?.to_string());
    }
    for round in 0..100 {
        if round % 20 == 0 {
            f.ok(&[
                "quota",
                "put",
                "--account",
                "bulk",
                "--window",
                "w",
                "--used",
                "1",
            ])?;
        }
        let running = workers
            .iter()
            .map(|w| f.spawn(&["claim", "--worker", w, "row:GB-002"]))
            .collect::<Result<Vec<_>, _>>()?;
        let mut won = Vec::new();
        for (worker, child) in workers.iter().zip(running) {
            let (code, value) = finish(child)?;
            match code {
                0 => won.push((worker.clone(), value["fence"].as_i64().ok_or("fence")?)),
                1 => assert_eq!(value["code"], "held", "round {round}: {value}"),
                other => return Err(format!("round {round}: exit {other}: {value}").into()),
            }
        }
        assert_eq!(won.len(), 1, "round {round}: {won:?}");
        let (worker, fence) = &won[0];
        f.ok(&["release", "--worker", worker, "--fence", &fence.to_string()])?;
    }
    f.ok(&["audit"])?;
    Ok(())
}

#[test]
fn a5_a6_a7_expiry_takeover_and_stale_fences() -> Fallible {
    let f = Fixture::new("fence")?;
    let (w1, w2) = (f.join("claude")?, f.join("hermes")?);
    let held = f.ok(&["claim", "--worker", &w1, "--ttl", "30s", "row:GB-001"])?;
    let old = held["fence"].as_i64().ok_or("fence")?.to_string();

    // A7: a heartbeat moves the expiry forward.
    pause(1_100);
    expire();
    let beat = f.ok(&["beat", "--worker", &w1])?;
    let moved = beat["extended"][0]["expires"].as_str().ok_or("expires")?;
    assert!(moved > held["expires"].as_str().ok_or("expires")?, "{beat}");

    // A5: a short lease, a checkpoint, then another worker takes over.
    f.ok(&["release", "--worker", &w1, "--fence", &old])?;
    let short = f.ok(&["claim", "--worker", &w1, "--ttl", "2s", "row:GB-001"])?;
    let old = short["fence"].as_i64().ok_or("fence")?;
    let old_text = old.to_string();
    f.ok(&[
        "event",
        "--worker",
        &w1,
        "--type",
        "checkpoint",
        "--fence",
        &old_text,
        "--clone",
        "/work/w1",
        "--next-step",
        "run the tests",
    ])?;
    expire();
    expire();
    let taken = f.ok(&["claim", "--worker", &w2, "row:GB-001"])?;
    assert!(taken["fence"].as_i64().ok_or("fence")? > old);
    assert_eq!(
        taken["takeover"][0]["checkpoint"]["next_step"], "run the tests",
        "{taken}"
    );
    let events = f.export()?;
    let expired = events
        .iter()
        .find(|e| e["type"] == "lease_expired" && e["payload"]["fence"] == old)
        .ok_or("no lease_expired event")?;
    assert_eq!(expired["payload"]["checkpoint"]["clone"], "/work/w1");

    // A6: the old fence cannot hand back, and nothing is stored.
    f.refused(
        &[
            "handback",
            "--worker",
            &w1,
            "--row",
            "GB-001",
            "--fence",
            &old_text,
            "--verdict",
            "done",
            "--proof",
            "p",
        ],
        "stale_fence",
    )?;
    assert!(!f.export()?.iter().any(|e| e["type"] == "handback"));

    // A7: a heartbeat after the takeover is refused.
    f.refused(&["beat", "--worker", &w1], "lease_lost")?;
    // Told once; afterwards the worker simply holds nothing.
    f.refused(&["beat", "--worker", &w1], "no_claims")?;
    f.refused(
        &["beat", "--worker", &w1, "--fence", &old_text],
        "stale_fence",
    )?;
    f.ok(&["audit"])?;
    Ok(())
}

#[test]
fn a_late_hand_back_is_accepted_only_when_nobody_took_the_row() -> Fallible {
    let f = Fixture::new("late")?;
    let w1 = f.join("claude")?;
    let out = f.ok(&["claim", "--worker", &w1, "--ttl", "1s", "row:GB-001"])?;
    let fence = out["fence"].as_i64().ok_or("fence")?.to_string();
    expire();
    let back = f.ok(&[
        "handback",
        "--worker",
        &w1,
        "--row",
        "GB-001",
        "--fence",
        &fence,
        "--verdict",
        "done",
        "--proof",
        "test output",
    ])?;
    assert_eq!(back["late"], true, "{back}");
    // A done row is final: it cannot be claimed or handed back again.
    f.refused(&["claim", "--worker", &w1, "row:GB-001"], "row_final")?;
    f.refused(
        &[
            "handback",
            "--worker",
            &w1,
            "--row",
            "GB-001",
            "--fence",
            &fence,
            "--verdict",
            "done",
            "--proof",
            "again",
        ],
        "handed_back",
    )?;
    Ok(())
}

#[test]
fn a8_the_fleet_ceiling_holds() -> Fallible {
    let f = Fixture::new("fleet")?;
    f.ok(&["run", "start", "--rows", ROWS, "--slots", "2"])?;
    let w1 = f.join("claude")?;
    f.ok(&["claim", "--worker", &w1, "--run", "run-1", "fleet:slot"])?;
    // A slot claimed outside the run still counts against its ceiling.
    f.claim(&w1, "fleet:slot")?;
    f.refused(&["claim", "--worker", &w1, "fleet:slot"], "fleet_full")?;
    f.refused(&["claim", "--worker", &w1, "fleet:slot/1"], "fleet_full")?;
    f.refused(&["run", "close", "--run", "run-1"], "claims_open")?;
    Ok(())
}

#[test]
fn a9_quota_gates_new_claims() -> Fallible {
    let f = Fixture::new("quota")?;
    let w1 = f.join("claude")?;
    let resets = chrono::Utc::now().timestamp() + 3_600;
    let reset_text = resets.to_string();
    let put = |used: &str| {
        f.ok(&[
            "quota",
            "put",
            "--account",
            "claude",
            "--window",
            "five_hour",
            "--used",
            used,
            "--resets-at",
            &reset_text,
        ])
    };
    put("91")?;
    let no = f.refused(&["claim", "--worker", &w1, "row:GB-001"], "quota")?;
    let resume =
        chrono::DateTime::parse_from_rfc3339(no["resume_after"].as_str().ok_or("resume")?)?;
    assert_eq!(resume.timestamp(), resets + 120);
    // A lock claim is finishing work, not new work.
    f.claim(&w1, "backlog:GB:write")?;
    put("50")?;
    f.claim(&w1, "row:GB-001")?;

    // No sample: one working worker per account.
    let a = f.join("opencode")?;
    let b = f.join("opencode")?;
    f.claim(&a, "row:GB-002")?;
    f.refused(&["claim", "--worker", &b, "row:GB-003"], "quota")?;
    f.claim(&a, "row:GB-004")?;

    // The Claude status line is a source; an absent record stays unknown.
    let input = format!(
        r#"{{"rate_limits":{{"seven_day":{{"used_percentage":85,"resets_at":{resets}}}}}}}"#
    );
    let mut child = f
        .command()
        .args([
            "hub",
            "quota",
            "put",
            "--account",
            "claude",
            "--from",
            "claude-statusline",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("stdin")?
        .write_all(input.as_bytes())?;
    assert!(child.wait()?.success());
    f.refused(&["claim", "--worker", &w1, "row:GB-005"], "quota")?;
    Ok(())
}

#[test]
fn a10_a_failing_source_is_unknown_never_zero() -> Fallible {
    let f = Fixture::new("unknown")?;
    let config = f.root.join("hub.toml");
    let head = config_head();
    fs::write(
        &config,
        format!(
            "{head}[[quota.source]]\naccount = \"missing\"\ncommand = [\"/nonexistent/usage\"]\n\
             [[quota.source]]\naccount = \"failing\"\ncommand = [\"false\"]\n\
             [[quota.source]]\naccount = \"reading\"\ncommand = [\"echo\", \
             '{{\"windows\":[{{\"label\":\"week\",\"used_percent\":12.5,\"resets_at\":null}}]}}']\n"
        ),
    )?;
    let run = |args: &[&str]| -> Result<Value, Box<dyn std::error::Error>> {
        let child = f
            .command()
            .env("STENIO_HUB_CONFIG", &config)
            .arg("hub")
            .args(args)
            .arg("--json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (code, value) = finish(child)?;
        assert_eq!(code, 0, "{value}");
        Ok(value)
    };
    run(&["quota", "refresh"])?;
    let shown = run(&["quota", "show"])?;
    let items = shown["items"].as_array().ok_or("items")?;
    for account in ["missing", "failing"] {
        let item = items
            .iter()
            .find(|i| i["account"] == account)
            .ok_or("account not listed")?;
        assert_eq!(item["confidence"], "unknown", "{item}");
        assert!(item["used_pct"].is_null(), "{item}");
        assert!(item["reason"].as_str().is_some_and(|r| !r.is_empty()));
    }
    let read = items
        .iter()
        .find(|i| i["account"] == "reading")
        .ok_or("reading not listed")?;
    assert_eq!(
        (read["confidence"].as_str(), read["used_pct"].as_f64()),
        (Some("measured"), Some(12.5))
    );
    Ok(())
}

#[test]
fn a11_killed_writers_leave_a_sound_ledger() -> Fallible {
    let f = Fixture::new("kill")?;
    let w1 = f.join("claude")?;
    for round in 0..50_u64 {
        let resources: Vec<String> = (0..120).map(|n| format!("host:h{round}-{n}")).collect();
        let list = resources.join(",");
        let mut child = f.spawn(&["claim", "--worker", &w1, &list])?;
        pause(round % 25);
        child.kill()?;
        child.wait()?;
    }
    let audit = f.ok(&["audit"])?;
    assert_eq!(audit["problem_count"], 0, "{audit}");
    // All or nothing: every claim group is complete.
    let events = f.export()?;
    let claims = events.iter().filter(|e| e["type"] == "claim").count();
    assert_eq!(claims % 120, 0, "{claims} claim events");
    let conn = rusqlite::Connection::open(f.db())?;
    let sound: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    assert_eq!(sound, "ok");
    Ok(())
}

#[test]
fn a12_edits_are_detected() -> Fallible {
    let f = Fixture::new("tamper")?;
    let w1 = f.join("claude")?;
    f.claim(&w1, "row:GB-001")?;
    f.ok(&["audit"])?;
    // A state table edited behind the engine's back.
    f.sql("UPDATE claims SET holder = 'someone-else'")?;
    let (code, state) = f.hub(&["audit"])?;
    assert_eq!(code, 1, "{state}");
    assert_eq!(state["chain"], true);
    assert!(state["problem_count"].as_i64() > Some(0));
    f.sql(&format!("UPDATE claims SET holder = '{w1}'"))?;
    f.ok(&["audit"])?;
    // A truncated chain.
    f.sql(
        "CREATE TABLE kept AS SELECT * FROM events WHERE seq = 2; DELETE FROM events WHERE seq = 2",
    )?;
    assert_eq!(f.hub(&["audit"])?.0, 1);
    f.sql("INSERT INTO events SELECT * FROM kept")?;
    // An altered event names its sequence number.
    f.sql("UPDATE events SET worker = 'forged' WHERE seq = 2")?;
    let (code, chain) = f.hub(&["audit"])?;
    assert_eq!(
        (code, chain["first_bad_seq"].as_i64()),
        (1, Some(2)),
        "{chain}"
    );
    Ok(())
}

#[test]
fn a13_an_unusable_ledger_refuses_with_exit_3() -> Fallible {
    let f = Fixture::new("unusable")?;
    let w1 = f.join("claude")?;
    fs::set_permissions(f.db(), fs::Permissions::from_mode(0o400))?;
    let (code, value) = f.hub(&["claim", "--worker", &w1, "row:GB-001"])?;
    assert_eq!(
        (code, value["code"].as_str()),
        (3, Some("store_unavailable")),
        "{value}"
    );
    fs::set_permissions(f.db(), fs::Permissions::from_mode(0o600))?;
    assert!(!f.export()?.iter().any(|e| e["type"] == "claim"));
    fs::write(
        f.db(),
        "this is not a database, only text that is long enough".repeat(200),
    )?;
    for side in ["hub.db-wal", "hub.db-shm"] {
        let _ = fs::remove_file(f.root.join("state").join(side));
    }
    assert_eq!(f.hub(&["claim", "--worker", &w1, "row:GB-001"])?.0, 3);
    // A synchronised folder cannot hold the ledger.
    fs::create_dir_all(f.root.join("synced/.stfolder"))?;
    let out = f
        .command()
        .env("STENIO_HUB_DB", f.root.join("synced/state/hub.db"))
        .args(["hub", "status"])
        .output()?;
    assert_eq!(out.status.code(), Some(3));
    Ok(())
}

fn opportunity(f: &Fixture, title: &str) -> std::io::Result<Child> {
    f.command()
        .args([
            "opportunity",
            "add",
            "--title",
            title,
            "--evidence",
            "seen",
            "--desired",
            "do it",
            "--acceptance",
            "test",
            "--origin",
            "t",
            "--ref",
            "governance/area.md",
            "--path",
        ])
        .arg(f.vault())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

#[test]
fn a14_twenty_parallel_adds_give_twenty_rows_with_unique_ids() -> Fallible {
    let f = Fixture::new("parallel")?;
    // The ledger exists, so every writer also goes through its lock.
    f.join("claude")?;
    let titles = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliett", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo",
        "sierra", "tango",
    ];
    let running = titles
        .iter()
        .map(|t| opportunity(&f, t))
        .collect::<Result<Vec<_>, _>>()?;
    for child in running {
        let out = child.wait_with_output()?;
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = fs::read_to_string(f.vault().join("governance/backlog.md"))?;
    let ids: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("| **"))
        .filter_map(|l| l.split("**").next())
        .collect();
    assert_eq!(ids.len(), 26, "{text}");
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), 26);
    for title in titles {
        assert!(text.contains(&format!("Stenio: {title}.")), "lost {title}");
    }
    for line in text.lines().filter(|l| l.starts_with('|')) {
        assert_eq!(line.matches('|').count(), 8, "broken row: {line}");
    }
    let area = fs::read_to_string(f.vault().join("governance/area.md"))?;
    for id in &ids {
        assert!(area.contains(id), "{id} not linked");
    }
    let leftovers = fs::read_dir(f.vault().join("governance"))?
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .count();
    assert_eq!(leftovers, 0);
    Ok(())
}

#[test]
fn a15_the_backlog_claim_blocks_every_other_writer() -> Fallible {
    let f = Fixture::new("lock")?;
    let w1 = f.join("claude")?;
    f.claim(&w1, "backlog:GB:write")?;
    let backlog = f.vault().join("governance/backlog.md");
    let before = fs::read(&backlog)?;
    let close = |worker: Option<&str>| {
        let mut c = f.command();
        c.args([
            "backlog",
            "close",
            "GB-001",
            "--note",
            "done in test",
            "--path",
        ])
        .arg(f.vault());
        if let Some(w) = worker {
            c.args(["--worker", w]);
        }
        c.output()
    };
    let refused = close(None)?;
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains(&w1));
    assert_eq!(close(Some("intruder"))?.status.code(), Some(1));
    let add = opportunity(&f, "blocked")?.wait_with_output()?;
    assert_eq!(add.status.code(), Some(1));
    assert_eq!(
        fs::read(&backlog)?,
        before,
        "a refused writer changed the file"
    );
    let allowed = close(Some(&w1))?;
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_ne!(fs::read(&backlog)?, before);
    // A ledger that exists but cannot be used refuses the write.
    fs::write(f.db(), "broken".repeat(900))?;
    for side in ["hub.db-wal", "hub.db-shm"] {
        let _ = fs::remove_file(f.root.join("state").join(side));
    }
    let blind = opportunity(&f, "blind")?.wait_with_output()?;
    assert_eq!(blind.status.code(), Some(3));
    Ok(())
}

/// One stdio MCP server process.
struct Mcp {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    id: i64,
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Mcp {
    fn start(f: &Fixture) -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = f
            .command()
            .arg("--mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().ok_or("stdin")?;
        let output = BufReader::new(child.stdout.take().ok_or("stdout")?);
        Ok(Mcp {
            child,
            input,
            output,
            id: 0,
        })
    }

    /// The response line and its `result`.
    fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<(usize, Value), Box<dyn std::error::Error>> {
        self.id += 1;
        let request = json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params});
        writeln!(self.input, "{request}")?;
        self.input.flush()?;
        let mut line = String::new();
        self.output.read_line(&mut line)?;
        let reply: Value = serde_json::from_str(&line)?;
        assert_eq!(reply["id"], self.id);
        Ok((line.len(), reply["result"].clone()))
    }

    fn call(&mut self, tool: &str, args: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let (size, result) =
            self.request("tools/call", json!({"name": tool, "arguments": args}))?;
        if tool.starts_with("hub_") || tool == "stenio_quota" || tool == "stenio_backlog" {
            assert!(size <= 16 * 1024, "{tool}: {size} bytes");
        }
        Ok(result)
    }

    fn ok(&mut self, tool: &str, args: Value) -> Result<Value, Box<dyn std::error::Error>> {
        let result = self.call(tool, args)?;
        assert_eq!(result["isError"], false, "{tool}: {result}");
        Ok(result["structuredContent"].clone())
    }
}

#[test]
fn a16_mcp_tools_report_errors_and_stay_small() -> Fallible {
    let f = Fixture::new("mcp")?;
    let mut mcp = Mcp::start(&f)?;
    let (_, init) = mcp.request("initialize", json!({}))?;
    assert!(
        init["instructions"]
            .as_str()
            .is_some_and(|i| i.contains("hub_join"))
    );
    let (_, list) = mcp.request("tools/list", json!({}))?;
    let names: BTreeSet<&str> = list["tools"]
        .as_array()
        .ok_or("tools")?
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    for name in [
        "hub_join",
        "hub_status",
        "hub_claim",
        "hub_beat",
        "hub_release",
        "hub_event",
        "hub_handback",
        "hub_ask",
        "stenio_quota",
        "stenio_backlog",
        "stenio_gate",
    ] {
        assert!(names.contains(name), "missing {name}");
    }
    assert!(
        !names
            .iter()
            .any(|n| n.contains("answer") || n.contains("grant"))
    );

    let w1 = mcp.ok("hub_join", json!({"harness": "claude"}))?["worker"].clone();
    let w2 = mcp.ok("hub_join", json!({"harness": "hermes"}))?["worker"].clone();
    mcp.ok(
        "hub_claim",
        json!({"worker": w1, "resources": ["row:GB-001"]}),
    )?;
    let (size, held) = mcp.request(
        "tools/call",
        json!({"name": "hub_claim", "arguments": {"worker": w2, "resources": ["row:GB-001"]}}),
    )?;
    assert!(size < 8 * 1024, "{size} bytes");
    assert_eq!(held["isError"], true, "{held}");
    assert_eq!(held["structuredContent"]["code"], "held");
    assert_eq!(held["structuredContent"]["holder"], w1);

    // A long list is paged.
    for n in 0..60 {
        mcp.ok(
            "hub_claim",
            json!({"worker": w1, "resources": [format!("host:node-{n}")]}),
        )?;
    }
    let (size, page) = mcp.request("tools/call", json!({"name": "hub_status", "arguments": {}}))?;
    assert!(size <= 16 * 1024, "{size} bytes");
    assert!(
        page["structuredContent"].to_string().len() < 8 * 1024,
        "{size}"
    );
    assert!(
        page["structuredContent"]["next_cursor"].is_number(),
        "{page}"
    );

    let read = mcp.ok("stenio_backlog", json!({"id": "GB-002"}))?;
    assert!(
        read["row"]
            .as_str()
            .is_some_and(|r| r.contains("fixture item 2"))
    );

    // Missing arguments and the older tools also set isError.
    assert_eq!(mcp.call("hub_claim", json!({}))?["isError"], true);
    assert_eq!(
        mcp.call("stenio_gate", json!({"path": "no/such/path"}))?["isError"],
        true
    );
    assert_eq!(
        mcp.call("stenio_scan", json!({"path": "no/such/path"}))?["isError"],
        true
    );
    assert_eq!(mcp.call("no_such_tool", json!({}))?["isError"], true);
    assert_eq!(
        mcp.call("stenio_explain", json!({"rule_id": "ARCH-NO-PYTHON"}))?["isError"],
        false
    );
    fs::create_dir_all(f.vault().join("code"))?;
    fs::write(
        f.vault().join("code/bad.rs"),
        concat!("fn main() { std::env::var(\"X\").unw", "rap(); }\n"),
    )?;
    let gate = mcp.call("stenio_gate", json!({"path": "code"}))?;
    assert_eq!(gate["isError"], true, "{gate}");
    Ok(())
}

#[test]
fn a17_north_star_two_harnesses_one_dies_the_other_finishes() -> Fallible {
    let f = Fixture::new("north")?;
    let run = f.ok(&["run", "start", "--rows", ROWS, "--slots", "2"])?["run"]
        .as_str()
        .ok_or("run")?
        .to_string();
    let mut claude = Mcp::start(&f)?;
    let mut hermes = Mcp::start(&f)?;
    let w1 = claude.ok("hub_join", json!({"harness": "claude"}))?["worker"].clone();
    let w2 = hermes.ok("hub_join", json!({"harness": "hermes"}))?["worker"].clone();
    for r in ["row:GB-001", "row:GB-002"] {
        claude.ok(
            "hub_claim",
            json!({"worker": w1, "resources": [r], "ttl_secs": 2}),
        )?;
    }
    let status = hermes.ok("hub_status", json!({}))?;
    assert_eq!(status["counts"]["rows_claimed"], 2, "{status}");
    let mut held = Vec::new();
    for r in ["row:GB-003", "row:GB-004"] {
        held.push((
            r,
            hermes.ok("hub_claim", json!({"worker": w2, "resources": [r]}))?["fence"].clone(),
        ));
    }
    let taken = hermes.call(
        "hub_claim",
        json!({"worker": w2, "resources": ["row:GB-001"]}),
    )?;
    assert_eq!(taken["structuredContent"]["code"], "held", "{taken}");
    drop(claude);
    expire();
    expire();
    for r in ["row:GB-001", "row:GB-002", "row:GB-005", "row:GB-006"] {
        held.push((
            r,
            hermes.ok("hub_claim", json!({"worker": w2, "resources": [r]}))?["fence"].clone(),
        ));
    }
    let unfinished = f.refused_audit(&run)?;
    assert_eq!(unfinished["rows_without_final_state"], 6);
    hermes.ok(
        "hub_ask",
        json!({"worker": w2, "row": "GB-006", "text": "Which option?", "options": ["a", "b"]}),
    )?;
    for (r, fence) in &held {
        let verdict = if *r == "row:GB-006" {
            "needs-owner"
        } else {
            "done"
        };
        hermes.ok(
            "hub_handback",
            json!({"worker": w2, "row": r, "fence": fence, "verdict": verdict, "proof": "p"}),
        )?;
    }
    let audit = f.ok(&["audit", "--run", &run, "--require-final"])?;
    assert_eq!(audit["complete"], true, "{audit}");
    assert_eq!(audit["rows"].as_array().map(Vec::len), Some(6));
    assert_eq!(audit["problem_count"], 0);

    // The export alone rebuilds who did what, in order.
    let events = f.export()?;
    let seqs: Vec<i64> = events.iter().filter_map(|e| e["seq"].as_i64()).collect();
    assert_eq!(seqs, (1..=events.len() as i64).collect::<Vec<_>>());
    let finals: BTreeSet<&str> = events
        .iter()
        .filter(|e| e["type"] == "handback")
        .filter_map(|e| e["resource"].as_str())
        .collect();
    assert_eq!(finals.len(), 6);
    assert_eq!(events.iter().filter(|e| e["type"] == "handback").count(), 6);
    let position = |kind: &str, resource: &str, worker: &Value| {
        events
            .iter()
            .position(|e| e["type"] == kind && e["resource"] == resource && &e["worker"] == worker)
            .ok_or(format!("no {kind} of {resource}"))
    };
    assert!(position("claim", "row:GB-001", &w1)? < position("lease_expired", "row:GB-001", &w1)?);
    assert!(position("lease_expired", "row:GB-001", &w1)? < position("claim", "row:GB-001", &w2)?);
    assert!(position("claim", "row:GB-001", &w2)? < position("handback", "row:GB-001", &w2)?);

    f.ok(&["answer", "--id", "1", "--text", "a"])?;
    f.refused(&["answer", "--id", "1", "--text", "b"], "answered")?;
    f.ok(&["run", "close", "--run", &run])?;
    f.ok(&["audit", "--run", &run, "--require-final"])?;
    Ok(())
}

impl Fixture {
    fn refused_audit(&self, run: &str) -> Result<Value, Box<dyn std::error::Error>> {
        let (code, value) = self.hub(&["audit", "--run", run, "--require-final"])?;
        assert_eq!(code, 1, "{value}");
        Ok(value)
    }
}

#[test]
fn a18_the_self_test_turns_red_without_each_guarantee() -> Fallible {
    let f = Fixture::new("selftest")?;
    let out = f
        .command()
        .arg("--self-test")
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for case in [
        "hub: a held row refuses a second claim",
        "hub: mutation, no unique claim index is red",
        "hub: a stale fence cannot hand back",
        "hub: mutation, no fence check is red",
        "hub: an edited event fails the audit",
    ] {
        assert!(
            text.lines().any(|l| l.contains(case) && l.contains("OK")),
            "self-test case not OK: {case}"
        );
    }
    Ok(())
}

/// Adds a homelab queue with the row HB-001 to the fixture vault.
fn homelab(f: &Fixture) -> std::io::Result<PathBuf> {
    let dir = f.vault().join("mnemocine");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join("backlog.md"),
        "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n\
         |---|---|---|---|---|---|---|\n\
         | **HB-001** | **Old chore.** x | [`area.md`](area.md) | 🟡 | open | a | — |\n",
    )?;
    fs::write(
        dir.join("area.md"),
        "---\ntags: [gov]\npending: [HB-001]\n---\n# Area\n",
    )?;
    Ok(dir)
}

/// `stenio opportunity add --json` under `root`.
fn add_json(
    f: &Fixture,
    root: &Path,
    extra: &[&str],
) -> Result<(i32, Value), Box<dyn std::error::Error>> {
    let child = f
        .command()
        .args([
            "opportunity",
            "add",
            "--json",
            "--evidence",
            "seen",
            "--desired",
            "do it",
            "--acceptance",
            "test",
            "--origin",
            "t",
            "--path",
        ])
        .arg(root)
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    finish(child)
}

#[test]
fn f1_f2_f3_f4_other_queues_are_written_under_their_claim() -> Fallible {
    let f = Fixture::new("queues")?;
    let dir = homelab(&f)?;
    let (holder, other) = (f.join("claude")?, f.join("hermes")?);
    f.claim(&holder, "backlog:HB:write")?;
    let base = [
        "--queue",
        "HB",
        "--title",
        "Rotate logs",
        "--ref",
        "mnemocine/area.md",
    ];
    let before = fs::read(dir.join("backlog.md"))?;
    // A dry run reports the refusal of the real run.
    for dry in [&["--dry-run"][..], &[]] {
        let mut args = base.to_vec();
        args.extend(["--worker", other.as_str()]);
        args.extend(dry);
        let (code, no) = add_json(&f, &f.vault(), &args)?;
        assert_eq!((code, no["code"].as_str()), (1, Some("held")), "{no}");
        assert_eq!(no["holder"], holder.as_str());
    }
    assert_eq!(fs::read(dir.join("backlog.md"))?, before);
    let mut args = base.to_vec();
    args.extend(["--worker", holder.as_str()]);
    let (code, done) = add_json(&f, &f.vault(), &args)?;
    assert_eq!((code, done["id"].as_str()), (0, Some("HB-002")), "{done}");
    assert_eq!(done["pending"], "added");
    let text = fs::read_to_string(dir.join("backlog.md"))?;
    assert!(
        text.contains("| **HB-002** | **Rotate logs.** Evidence: seen"),
        "{text}"
    );
    assert!(text.contains("[`area.md`](area.md)"));
    assert!(fs::read_to_string(dir.join("area.md"))?.contains("HB-001, HB-002"));
    let write = f
        .export()?
        .into_iter()
        .find(|e| e["type"] == "backlog_write")
        .ok_or("no write event")?;
    let payload: Value = match &write["payload"] {
        Value::String(s) => serde_json::from_str(s)?,
        other => other.clone(),
    };
    assert_eq!(payload["rows"], json!(["HB-002"]), "{write}");
    assert_eq!(
        payload["files"][0]["sha256"].as_str().map(str::len),
        Some(64),
        "{write}"
    );
    // A queue without a default document needs --ref.
    let (code, no) = add_json(&f, &f.vault(), &["--queue", "HB", "--title", "No ref"])?;
    assert_eq!((code, no["code"].as_str()), (2, Some("usage")), "{no}");
    Ok(())
}

#[test]
fn f5_a_claim_without_a_row_is_handed_back_by_its_fence() -> Fallible {
    let f = Fixture::new("claimback")?;
    let (w1, w2) = (f.join("claude")?, f.join("hermes")?);
    let fence = f.claim(&w1, "backlog:GB:write")?.to_string();
    let args = |w: &'static str| {
        [
            "handback",
            "--worker",
            w,
            "--fence",
            fence.as_str(),
            "--verdict",
            "done",
            "--proof",
            "filed",
        ]
        .map(str::to_string)
    };
    let call = |worker: &str| {
        let mut list = args("-").to_vec();
        list[2] = worker.to_string();
        f.hub(&list.iter().map(String::as_str).collect::<Vec<_>>())
    };
    assert_eq!(call(&w2)?.1["code"], "stale_fence");
    let (code, done) = call(&w1)?;
    assert_eq!(code, 0, "{done}");
    assert_eq!(done["resources"], json!(["backlog:GB:write"]));
    assert_eq!(call(&w1)?.1["code"], "stale_fence");
    f.claim(&w2, "backlog:GB:write")?;
    // A fence that holds a row still names it.
    let with_row = f.claim(&w1, "row:GB-001")?.to_string();
    let (code, _) = f.hub(&[
        "handback",
        "--worker",
        &w1,
        "--fence",
        &with_row,
        "--verdict",
        "done",
        "--proof",
        "x",
    ])?;
    assert_eq!(code, 2);
    assert_eq!(f.ok(&["audit"])?["ok"], true);
    Ok(())
}

#[test]
fn f6_a_claim_bound_to_a_queue_leaves_a_scratch_copy_writable() -> Fallible {
    let f = Fixture::new("bound")?;
    let w1 = f.join("claude")?;
    let vault = f.vault().display().to_string();
    f.ok(&[
        "claim",
        "--worker",
        &w1,
        "--path",
        &vault,
        "backlog:GB:write",
    ])?;
    let scratch = f.root.join("scratch");
    fs::create_dir_all(scratch.join("governance"))?;
    for name in ["backlog.md", "backlog-archive.md", "area.md"] {
        fs::copy(
            f.vault().join("governance").join(name),
            scratch.join("governance").join(name),
        )?;
    }
    let (code, done) = add_json(&f, &scratch, &["--title", "Scratch rule"])?;
    assert_eq!(code, 0, "{done}");
    let (code, no) = add_json(&f, &f.vault(), &["--title", "Real rule"])?;
    assert_eq!((code, no["code"].as_str()), (1, Some("held")), "{no}");
    let (code, _) = f.hub(&["claim", "--worker", &w1, "--path", &vault, "row:GB-001"])?;
    assert_eq!(code, 2);
    Ok(())
}

#[test]
fn f7_a_voluntary_release_has_no_expired_at() -> Fallible {
    let f = Fixture::new("release")?;
    let w1 = f.join("claude")?;
    let fence = f.claim(&w1, "backlog:GB:write")?.to_string();
    f.ok(&["release", "--worker", &w1, "--fence", &fence])?;
    let events = f.export()?;
    let released = events
        .iter()
        .find(|e| e["type"] == "release")
        .ok_or("no release")?;
    let text = released["payload"].to_string();
    assert!(
        text.contains("lease_until") && !text.contains("expired_at"),
        "{text}"
    );
    Ok(())
}

#[test]
fn a_claim_reads_the_declared_source_of_the_account_itself() -> Fallible {
    let f = Fixture::new("autoquota")?;
    let source = |command: &str| {
        fs::write(
            f.root.join("hub.toml"),
            format!(
                "{}[[quota.source]]\naccount = \"anthropic\"\ncommand = {command}\n",
                config_head()
            ),
        )
    };
    source(
        "[\"echo\", '{\"windows\":[{\"label\":\"week\",\"used_percent\":91,\"resets_at\":null}]}']",
    )?;
    // No --account and no refresh: the harness is declared to use the account.
    let w1 = f.join("claude-code")?;
    let no = f.refused(&["claim", "--worker", &w1, "row:GB-001"], "quota")?;
    assert!(
        no["message"].as_str().is_some_and(|m| m.contains("91%")),
        "{no}"
    );
    let g = Fixture::new("autoquota-unreadable")?;
    fs::write(
        g.root.join("hub.toml"),
        format!(
            "{}[[quota.source]]\naccount = \"anthropic\"\ncommand = [\"false\"]\n",
            config_head()
        ),
    )?;
    let w2 = g.join("claude-code")?;
    g.claim(&w2, "row:GB-001")?;
    let shown = g.ok(&["quota", "show"])?;
    let item = shown["items"]
        .as_array()
        .and_then(|i| i.iter().find(|i| i["account"] == "anthropic"))
        .ok_or("not listed")?;
    assert_eq!(item["confidence"], "unknown", "{item}");
    assert!(item["used_pct"].is_null(), "{item}");
    Ok(())
}

#[test]
fn gb414_the_shipped_policy_refuses_only_an_exhausted_window() -> Fallible {
    let f = Fixture::new("shipped-quota")?;
    fs::write(f.root.join("hub.toml"), shipped_head())?;
    let w = f.join("claude")?;
    let sample = |used: &str, window: &str| {
        f.ok(&[
            "quota",
            "put",
            "--account",
            "claude",
            "--window",
            window,
            "--used",
            used,
        ])
    };
    sample("85", "week")?;
    let taken = f.ok(&["claim", "--worker", &w, "row:GB-001"])?;
    assert!(
        taken["warning"]
            .as_str()
            .is_some_and(|t| t.contains("85%") && t.contains("do not start a release")),
        "{taken}"
    );
    sample("99", "week")?;
    let other = f.join("claude")?;
    f.ok(&["claim", "--worker", &other, "row:GB-002"])?;
    sample("100", "week")?;
    let no = f.refused(&["claim", "--worker", &w, "row:GB-003"], "quota")?;
    assert!(
        no["message"].as_str().is_some_and(|m| m.contains("week")),
        "{no}"
    );
    let shown = f.ok(&["status"])?.to_string();
    assert!(shown.contains("\"level\":\"exhausted\""), "{shown}");
    assert!(shown.contains("\"stop_percent\":100.0"), "{shown}");
    // One window may be held to a lower limit.
    fs::write(
        f.root.join("hub.toml"),
        format!(
            "{}\n[[quota.limit]]\naccount = \"claude\"\nwindow = \"session\"\nstop_percent = 50.0\n",
            shipped_head()
        ),
    )?;
    sample("10", "week")?;
    sample("55", "session")?;
    f.refused(&["claim", "--worker", &w, "row:GB-003"], "quota")?;
    let out = f.command().args(["config", "show"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("hub.quota.stop_percent = 100  [applied;")
            && text.contains("hub.quota.limit.0 = account claude window session"),
        "{text}"
    );
    Ok(())
}
