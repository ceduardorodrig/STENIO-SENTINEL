//! The served ledger, driven through the built binary: a server on a loopback port and clients
//! that reach it with their own tokens.

use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

type Fallible = Result<(), Box<dyn std::error::Error>>;
type Made<T> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    root: PathBuf,
    server: Option<Child>,
    address: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn bin(root: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_stenio"));
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("STENIO_HUB_CONFIG", root.join("hub.toml"))
        .current_dir(root.join("vault"));
    c
}

fn finish(mut c: Command) -> Made<(i32, Value)> {
    let out = c.arg("--json").output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let value = serde_json::from_str(text.trim()).unwrap_or_else(|_| json!(text.trim()));
    Ok((out.status.code().unwrap_or(-1), value))
}

impl Fixture {
    fn new(label: &str) -> Made<Self> {
        let root =
            std::env::temp_dir().join(format!("stenio-remote-{}-{label}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let gov = root.join("vault/governance");
        fs::create_dir_all(&gov)?;
        fs::create_dir_all(root.join("home"))?;
        fs::write(
            gov.join("backlog.md"),
            "| ID | Item | Ref | Sev | State | Origin | Recurrence |\n\
             |---|---|---|---|---|---|---|\n\
             | **GB-001** | one | [`a.md`](a.md) | low | open | a | none |\n",
        )?;
        let defaults = include_str!("../src/hub/defaults.toml");
        let head = defaults
            .split("[[quota.source]]")
            .next()
            .unwrap_or(defaults);
        fs::write(root.join("hub.toml"), head)?;
        let mut clients = String::new();
        for (name, role) in [("alpha", "worker"), ("beta", "worker"), ("boss", "owner")] {
            let mut c = bin(&root);
            c.args(["hub", "token", "--client", name, "--out"])
                .arg(root.join(format!("{name}.token")));
            let (code, out) = finish(c)?;
            assert_eq!(code, 0, "{out}");
            clients.push_str(out["entry"].as_str().ok_or("no entry")?);
            clients.push_str(&format!("role = \"{role}\"\n"));
        }
        fs::write(root.join("clients.toml"), clients)?;
        let mut serve = bin(&root);
        serve
            .env("STENIO_HUB_DB", root.join("state/hub.db"))
            .args(["hub", "serve", "--port", "0", "--clients"])
            .arg(root.join("clients.toml"))
            .stderr(Stdio::piped());
        let mut child = serve.spawn()?;
        let mut line = String::new();
        BufReader::new(child.stderr.take().ok_or("no stderr")?).read_line(&mut line)?;
        let address = line
            .split("listening on ")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .ok_or_else(|| format!("server did not start: {line}"))?
            .to_string();
        Ok(Fixture {
            root,
            server: Some(child),
            address,
        })
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// A command of the client `name`.
    fn client(&self, name: &str) -> Command {
        let mut c = bin(&self.root);
        c.env("STENIO_HUB_URL", format!("http://{}", self.address))
            .env(
                "STENIO_HUB_TOKEN_FILE",
                self.root.join(format!("{name}.token")),
            );
        c
    }

    fn hub(&self, name: &str, args: &[&str]) -> Made<(i32, Value)> {
        let mut c = self.client(name);
        c.arg("hub").args(args);
        finish(c)
    }

    fn ok(&self, name: &str, args: &[&str]) -> Made<Value> {
        let (code, value) = self.hub(name, args)?;
        assert_eq!(code, 0, "{name} {args:?} -> {value}");
        Ok(value)
    }

    fn refused(&self, name: &str, args: &[&str], why: &str) -> Made<()> {
        let (code, value) = self.hub(name, args)?;
        assert_eq!(
            (code, value["code"].as_str()),
            (1, Some(why)),
            "{name} {args:?} -> {value}"
        );
        Ok(())
    }

    fn join(&self, name: &str) -> Made<String> {
        let out = self.ok(
            name,
            &["join", "--harness", "claude-code", "--account", name],
        )?;
        Ok(out["worker"].as_str().ok_or("no worker")?.to_string())
    }

    /// The status line of a raw request.
    fn raw(&self, headers: &str) -> Made<String> {
        let mut stream = TcpStream::connect(&self.address)?;
        let body = r#"{"op":"hub_status","args":{}}"#;
        write!(
            stream,
            "POST /v1/op HTTP/1.1\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        let mut reply = String::new();
        stream.read_to_string(&mut reply)?;
        Ok(reply.lines().next().unwrap_or_default().to_string())
    }
}

#[test]
fn transport_admits_only_a_known_token_on_an_allowed_host() -> Fallible {
    let f = Fixture::new("transport")?;
    let token = fs::read_to_string(f.root.join("alpha.token"))?;
    let host = format!("Host: {}\r\n", f.address);
    let auth = format!("Authorization: Bearer {token}\r\n");
    assert!(f.raw(&format!("{host}{auth}"))?.contains("200"));
    assert!(f.raw(&host)?.contains("401"));
    assert!(
        f.raw(&format!(
            "{host}Authorization: Bearer {}\r\n",
            "0".repeat(64)
        ))?
        .contains("401")
    );
    assert!(
        f.raw(&format!("Host: evil.example\r\n{auth}"))?
            .contains("421")
    );
    assert!(
        f.raw(&format!("{host}{auth}Origin: https://evil.example\r\n"))?
            .contains("403")
    );
    Ok(())
}

#[test]
fn clients_share_claims_and_cannot_act_for_each_other() -> Fallible {
    let f = Fixture::new("claims")?;
    let a = f.join("alpha")?;
    let b = f.join("beta")?;
    let tree = format!("tree:{}", f.root.join("vault").display());
    let held = f.ok("alpha", &["claim", "--worker", &a, "row:GB-001", &tree])?;
    f.refused("beta", &["claim", "--worker", &b, "row:GB-001"], "held")?;
    // The same path on another machine is another tree.
    f.ok("beta", &["claim", "--worker", &b, &tree])?;
    let fence = held["fence"].to_string();
    f.refused("beta", &["beat", "--worker", &a], "wrong_client")?;
    f.ok(
        "alpha",
        &[
            "release",
            "--worker",
            &a,
            "--fence",
            &fence,
            "--resource",
            &tree,
        ],
    )?;
    let asked = f.ok("alpha", &["ask", "--worker", &a, "--text", "why?"])?;
    let id = asked["question"].to_string();
    f.refused(
        "alpha",
        &["answer", "--id", &id, "--text", "no"],
        "owner_only",
    )?;
    f.ok("boss", &["answer", "--id", &id, "--text", "yes"])?;
    let audit = f.ok("beta", &["audit"])?;
    assert_eq!(audit["ok"], json!(true), "{audit}");
    // Nothing was created on the clients.
    assert!(!f.root.join("home/.local/state/stenio/hub.db").exists());
    Ok(())
}

#[test]
fn queue_writes_honor_the_served_claim_and_stop_without_the_server() -> Fallible {
    let mut f = Fixture::new("queue")?;
    let a = f.join("alpha")?;
    let b = f.join("beta")?;
    let claim = f.ok("alpha", &["claim", "--worker", &a, "backlog:GB:write"])?;
    let add = |f: &Fixture, who: &str, worker: &str| -> Made<i32> {
        let mut c = f.client(who);
        c.args([
            "opportunity",
            "add",
            "--worker",
            worker,
            "--title",
            "remote guard",
            "--evidence",
            "test",
            "--desired",
            "refused",
            "--acceptance",
            "exit code",
            "--path",
        ])
        .arg(f.root.join("vault"));
        Ok(c.output()?.status.code().unwrap_or(-1))
    };
    let queue = f.root.join("vault/governance/backlog.md");
    let before = fs::read_to_string(&queue)?;
    assert_ne!(add(&f, "beta", &b)?, 0);
    assert_eq!(fs::read_to_string(&queue)?, before);
    let fence = claim["fence"].to_string();
    f.ok("alpha", &["release", "--worker", &a, "--fence", &fence])?;
    assert_eq!(add(&f, "beta", &b)?, 0);
    let written = fs::read_to_string(&queue)?;
    assert_ne!(written, before);
    // The short claim of the write is gone.
    f.ok("alpha", &["claim", "--worker", &a, "backlog:GB:write"])?;
    f.stop();
    let (code, out) = f.hub("alpha", &["claim", "--worker", &a, "row:GB-001"])?;
    assert_eq!(code, 3, "{out}");
    assert_eq!(add(&f, "beta", &b)?, 3);
    assert_eq!(fs::read_to_string(&queue)?, written);
    assert!(!f.root.join("home/.local/state/stenio/hub.db").exists());
    Ok(())
}
