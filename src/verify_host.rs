//! `stenio verify-host`: managed-file parity and container restart policies of one host.
//!
//! Parity compares the sha256 of a file on the host (fixed read-only command `sha256sum <path>`)
//! with the file in the repository that is meant to manage it, so a change made only on the host
//! is reported as DRIFT with both hashes instead of being overwritten blindly. Restart policies
//! come from `docker inspect` (fixed command) and follow `INFRA-COMPOSE-RESTART-POLICY`.

use clap::Parser;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::{ParityFile, SteniocheckConfig};
use crate::verify_release::{Cmd, Ctx, Fake, SshTransport, Transport, safe};

#[derive(Parser, Debug)]
#[command(
    name = "stenio verify-host",
    about = "Managed-file parity and restart policies of a host (read-only)"
)]
struct HostArgs {
    #[arg(long)]
    host: String,
    #[arg(long, help = "steniocheck.toml with a [parity] table")]
    config: PathBuf,
    #[arg(
        long,
        default_value = ".",
        help = "Directory the `repo` paths of [parity] are relative to"
    )]
    repo_root: PathBuf,
    #[arg(long, default_value_t = 40)]
    timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Drift,
}

pub struct Line {
    pub verdict: Verdict,
    pub name: String,
    pub detail: String,
}

fn line(verdict: Verdict, name: &str, detail: impl Into<String>) -> Line {
    Line {
        verdict,
        name: name.to_string(),
        detail: detail.into(),
    }
}

fn short(h: &str) -> &str {
    &h[..h.len().min(16)]
}

pub fn check_parity(t: &dyn Transport, f: &ParityFile, local: Option<String>) -> Line {
    let name = format!("parity {}", f.path);
    let ctx = Ctx {
        dir: "/".into(),
        site: String::new(),
    };
    let Some(local) = local else {
        return line(
            Verdict::Fail,
            &name,
            format!("repository file {} unreadable", f.repo),
        );
    };
    match t.run(&Cmd::Sha256(f.path.clone()), &ctx) {
        Ok(o) if o.code == 0 => {
            let remote = o.stdout.split_whitespace().next().unwrap_or("").to_string();
            if remote == local {
                line(
                    Verdict::Pass,
                    &name,
                    format!("sha256 {} identical", short(&local)),
                )
            } else {
                line(
                    Verdict::Drift,
                    &name,
                    format!(
                        "host {} != repo {}: review before deploying, do not overwrite blindly",
                        short(&remote),
                        short(&local)
                    ),
                )
            }
        }
        Ok(_) => line(
            Verdict::Fail,
            &name,
            "file missing or unreadable on the host",
        ),
        Err(e) => line(Verdict::Fail, &name, e),
    }
}

pub fn check_policies(t: &dyn Transport) -> Line {
    let ctx = Ctx {
        dir: "/".into(),
        site: String::new(),
    };
    let out = match t.run(&Cmd::ContainerPolicies, &ctx) {
        Ok(o) if o.code == 0 => o,
        Ok(_) => return line(Verdict::Fail, "restart-policies", "docker inspect failed"),
        Err(e) => return line(Verdict::Fail, "restart-policies", e),
    };
    let (mut total, mut bad) = (0, Vec::new());
    for l in out.stdout.lines().filter(|l| !l.trim().is_empty()) {
        let p: Vec<&str> = l.split('|').collect();
        if p.len() < 4 {
            continue;
        }
        total += 1;
        let (name, policy, state, exit) = (p[0].trim_start_matches('/'), p[1], p[2], p[3]);
        let exempt = p
            .get(4)
            .is_some_and(|x| !x.trim().is_empty() && *x != "<no value>");
        let one_shot = policy == "no" && state == "exited" && exit == "0";
        if !(policy == "unless-stopped" || policy == "always" || one_shot || exempt) {
            bad.push(format!(
                "{name}={}",
                if policy.is_empty() { "none" } else { policy }
            ));
        }
    }
    if bad.is_empty() {
        line(
            Verdict::Pass,
            "restart-policies",
            format!("{total} container(s): long-running ones are unless-stopped or always"),
        )
    } else {
        line(
            Verdict::Fail,
            "restart-policies",
            format!("{} of {total}: {}", bad.len(), bad.join(", ")),
        )
    }
}

fn local_hash(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

pub fn run_cli(argv: &[String]) -> i32 {
    let a = match HostArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let cfg = SteniocheckConfig::load_from_file(&a.config);
    let files: Vec<ParityFile> = cfg
        .parity
        .unwrap_or_default()
        .files
        .into_iter()
        .filter(|f| f.host == a.host)
        .collect();
    if !safe(&a.host, "")
        || files
            .iter()
            .any(|f| !safe(&f.path, "/") || !f.path.starts_with('/'))
    {
        eprintln!("unsafe host or path in [parity]: refusing to run");
        return 2;
    }
    let t = SshTransport {
        host: a.host.clone(),
        repo: a.repo_root.clone(),
        timeout: Duration::from_secs(a.timeout_secs),
    };
    println!(
        "stenio verify-host host={} ({} managed file(s))",
        a.host,
        files.len()
    );
    let mut lines: Vec<Line> = files
        .iter()
        .map(|f| check_parity(&t, f, local_hash(&a.repo_root.join(&f.repo))))
        .collect();
    lines.push(check_policies(&t));
    for l in &lines {
        let tag = match l.verdict {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Drift => "DRIFT",
        };
        println!("{tag} {:<44} {}", l.name, l.detail);
    }
    let bad = lines.iter().filter(|l| l.verdict != Verdict::Pass).count();
    println!("{} check(s): {} not PASS", lines.len(), bad);
    i32::from(bad > 0)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let file = ParityFile {
        host: "h".into(),
        path: "/usr/local/bin/x".into(),
        repo: "x".into(),
    };
    let sha_cmd = Cmd::Sha256(file.path.clone());
    let fake = |hash: &str, policies: &str| {
        let mut m = BTreeMap::new();
        m.insert(sha_cmd.clone(), (0, format!("{hash}  /usr/local/bin/x\n")));
        m.insert(Cmd::ContainerPolicies, (0, policies.to_string()));
        Fake(m)
    };
    let good = fake(
        "aaaa",
        "/web|unless-stopped|running|0|\n/init|no|exited|0|\n/vm|no|running|0|manual start\n",
    );
    let bad = fake("bbbb", "/web|on-failure|running|0|\n");
    vec![
        (
            "verify-host parity pass".to_string(),
            check_parity(&good, &file, Some("aaaa".into())).verdict == Verdict::Pass,
        ),
        (
            "verify-host parity drift".to_string(),
            check_parity(&bad, &file, Some("aaaa".into())).verdict == Verdict::Drift,
        ),
        (
            "verify-host policies pass".to_string(),
            check_policies(&good).verdict == Verdict::Pass,
        ),
        (
            "verify-host policies fail".to_string(),
            check_policies(&bad).verdict == Verdict::Fail,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures() {
        assert!(self_test_cases().iter().all(|(_, ok)| *ok));
    }
}
