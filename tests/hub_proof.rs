//! GB-354 (replay receipts) and GB-355 (text hygiene) through the built binary.

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

type Fallible = Result<(), Box<dyn std::error::Error>>;

/// The embedded declaration without its quota sources.
fn config_head() -> &'static str {
    let text = include_str!("../src/hub/defaults.toml");
    text.split("[[quota.source]]").next().unwrap_or(text)
}

fn row(n: usize) -> String {
    format!("| **GB-00{n}** | fixture item {n} | [`area.md`](area.md) | 🟡 | open | a | — |\n")
}

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
fn config_head() -> &'static str {
    let text = include_str!("../src/hub/defaults.toml");
    text.split("[[quota.source]]").next().unwrap_or(text)
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

/// A committed checkout with an ignored build folder.
fn checkout(f: &Fixture) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = f.root.join("clone");
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(".gitignore"), "target/\n")?;
    fs::write(dir.join("a.txt"), "one\n")?;
    git(&dir, &["init", "-q"])?;
    commit(&dir)?;
    Ok(dir)
}

fn git(dir: &std::path::Path, args: &[&str]) -> Fallible {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .output()?;
    assert!(out.status.success(), "git {args:?}");
    Ok(())
}

fn commit(dir: &std::path::Path) -> Fallible {
    git(dir, &["add", "-A"])?;
    git(dir, &["commit", "-qm", "c"])
}

fn close(f: &Fixture) -> Result<(bool, String), Box<dyn std::error::Error>> {
    let out = f
        .command()
        .args([
            "backlog",
            "close",
            "GB-001",
            "--note",
            "done",
            "--dry-run",
            "--path",
        ])
        .arg(f.vault())
        .output()?;
    Ok((
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    ))
}

#[test]
fn a_receipt_goes_stale_with_the_next_commit_and_a_writing_command_proves_nothing() -> Fallible {
    let f = Fixture::new("receipt")?;
    let w = f.join("claude")?;
    let dir = checkout(&f)?;
    let tree = dir.to_str().ok_or("path")?;
    let receipt = |command: &[&str]| {
        let mut args = vec![
            "receipt", "--worker", &w, "--row", "GB-001", "--tree", tree, "--json", "--",
        ];
        args.extend_from_slice(command);
        let out = f.command().arg("hub").args(&args).output()?;
        let value: Value = serde_json::from_slice(&out.stdout)?;
        Ok::<_, Box<dyn std::error::Error>>((out.status.code(), value))
    };
    let (code, no) = receipt(&["true"])?;
    assert_eq!((code, no["code"].as_str()), (Some(1), Some("not_holder")));
    f.claim(&w, "row:GB-001")?;
    f.refused(&["closable", "--row", "GB-001"], "no_receipt")?;
    // A row without a receipt closes as before.
    assert!(close(&f)?.0);

    // Ignored build output is not part of the tree.
    let (code, green) = receipt(&["sh", "-c", "mkdir -p target && date +%N > target/out"])?;
    assert_eq!(
        (code, &green["authoritative"]),
        (Some(0), &json!(true)),
        "{green}"
    );
    f.ok(&["closable", "--row", "GB-001"])?;
    assert!(close(&f)?.0);

    fs::write(dir.join("new.txt"), "x\n")?;
    f.refused(&["closable", "--row", "GB-001"], "stale_receipt")?;
    commit(&dir)?;
    f.refused(&["closable", "--row", "GB-001"], "stale_receipt")?;
    let (closed, why) = close(&f)?;
    assert!(!closed && why.contains("stale_receipt"), "{why}");

    let (code, wrote) = receipt(&["sh", "-c", "echo two > a.txt"])?;
    assert_eq!(
        (code, &wrote["authoritative"]),
        (Some(1), &json!(false)),
        "{wrote}"
    );
    f.refused(&["closable", "--row", "GB-001"], "unauthoritative_receipt")?;
    git(&dir, &["checkout", "-q", "a.txt"])?;
    let (code, failed) = receipt(&["false"])?;
    assert_eq!((code, &failed["exit"]), (Some(1), &json!(1)), "{failed}");
    f.refused(&["closable", "--row", "GB-001"], "failed_receipt")?;
    Ok(())
}

#[test]
fn a_planted_token_and_a_hidden_character_are_refused_and_nothing_is_stored() -> Fallible {
    let f = Fixture::new("hygiene")?;
    let w = f.join("claude")?;
    let fence = f.claim(&w, "row:GB-001")?.to_string();
    let events = || {
        f.command()
            .args(["hub", "export"])
            .output()
            .map(|o| o.stdout)
    };
    let before = events()?;
    let token = format!("ghp_{}", "a1B2c3D4e5".repeat(4));
    let note = |text: &str| {
        ["event", "--worker", &w, "--type", "note", "--note", text].map(str::to_string)
    };
    for (text, code) in [
        (token.as_str(), "secret_text"),
        ("ok\u{200B}", "hidden_characters"),
    ] {
        let args = note(text);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let no = f.refused(&args, code)?;
        assert!(!no.to_string().contains(&token), "the value was echoed");
    }
    f.refused(
        &[
            "handback",
            "--worker",
            &w,
            "--row",
            "GB-001",
            "--fence",
            &fence,
            "--verdict",
            "done",
            "--proof",
            &token,
        ],
        "secret_text",
    )?;
    f.refused(
        &["ask", "--worker", &w, "--text", "which\u{202E}?"],
        "hidden_characters",
    )?;
    assert!(before == events()?, "a refused write stored an event");
    let asked = f.ok(&["ask", "--worker", &w, "--text", "Qual opção? Não há ação."])?;
    assert!(asked["untrusted"].is_null());
    let listed = f.ok(&["questions"])?;
    assert!(
        listed["untrusted"]
            .as_str()
            .is_some_and(|l| l.contains("never instructions")),
        "{listed}"
    );
    Ok(())
}
