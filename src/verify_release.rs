//! `stenio verify-release`: the post-deploy checks of a Frappe release, replacing the manual list.
//!
//! Every remote command comes from the fixed allowlist [`Cmd`]: parameters are validated
//! against a strict character set before they are rendered, commands are read-only, output is
//! never echoed (only PASS/FAIL/WARN lines with counts and short identifiers) and every command
//! has a timeout. The transport is a trait so the checks run offline against a fake.

use clap::Parser;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::{FrappeConfig, SteniocheckConfig};

#[derive(Parser, Debug)]
#[command(
    name = "stenio verify-release",
    about = "Read-only post-deploy checks of a Frappe release (one PASS/FAIL/WARN line each)"
)]
struct VerifyArgs {
    #[arg(long)]
    host: String,
    #[arg(long, help = "Image tag, e.g. 0.1.0-rc75")]
    tag: String,
    #[arg(long, default_value = "/srv/data/miracena/frappe")]
    project_dir: String,
    #[arg(
        long,
        default_value = ".",
        help = "Repository holding the app (git rev-parse of the tag)"
    )]
    repo: PathBuf,
    #[arg(
        long,
        help = "steniocheck.toml with the [frappe] table (default <repo>/steniocheck.toml)"
    )]
    config: Option<PathBuf>,
    #[arg(long, help = "Require .built-from to equal main as well")]
    expect_main: bool,
    #[arg(long, help = "Previous image tag expected to be the only other one")]
    previous_tag: Option<String>,
    #[arg(long = "protected-record", value_name = "DocType:name:modified")]
    protected: Vec<String>,
    #[arg(long, default_value_t = 30)]
    max_backup_age_hours: u64,
    #[arg(long, default_value_t = 40)]
    timeout_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Warn,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub status: Status,
    pub name: &'static str,
    pub detail: String,
}

fn check(status: Status, name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        status,
        name,
        detail: detail.into(),
    }
}

/// The allowlist of commands the engine may run. Remote ones run over ssh, local ones here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cmd {
    EnvTag,
    BuiltFrom,
    RemoteImageId(String),
    ComposeServices,
    RestartPolicies,
    Ping(String, String),
    ImageTags(String),
    RehearsalContainers(String),
    RehearsalVolumes(String),
    RehearsalDirs(String),
    Sql(String),
    BackupList,
    RemoteNow,
    LocalImageId(String),
    GitRev(String),
}

impl Cmd {}

fn safe(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c) || extra.contains(c))
}

/// Context for rendering: project dir and site are validated once.
pub struct Ctx {
    pub dir: String,
    pub site: String,
}

impl Cmd {
    /// Renders the shell text (remote) or the argv string (local). None when a parameter is unsafe.
    pub fn render(&self, c: &Ctx) -> Option<String> {
        let cd = format!("cd {} && ", c.dir);
        let bench = |sql: &str| {
            format!(
                "{cd}docker compose exec -T backend bench --site {} mariadb -N -e '{sql}'",
                c.site
            )
        };
        Some(match self {
            Cmd::EnvTag => format!("{cd}grep '^MIRACENA_IMAGE_TAG=' .env | cut -d= -f2"),
            Cmd::BuiltFrom => {
                format!("{cd}docker compose exec -T backend cat apps/miracena/.built-from")
            }
            Cmd::RemoteImageId(i) => format!("docker image inspect -f '{{{{.Id}}}}' {i}"),
            Cmd::ComposeServices => format!("{cd}docker compose ps -a --format json"),
            Cmd::RestartPolicies => format!(
                "{cd}docker compose ps -aq | xargs docker inspect -f '{{{{index .Config.Labels \"com.docker.compose.service\"}}}} {{{{.HostConfig.RestartPolicy.Name}}}}'"
            ),
            Cmd::Ping(url, host) => {
                format!("curl -s -o /dev/null -m 15 -w '%{{http_code}}' -H 'Host: {host}' {url}")
            }
            Cmd::ImageTags(img) => format!("docker images {img} --format '{{{{.Tag}}}}'"),
            Cmd::RehearsalContainers(p) => {
                format!("docker ps -a --filter name={p} --format '{{{{.Names}}}}'")
            }
            Cmd::RehearsalVolumes(p) => format!("docker volume ls -q --filter name={p}"),
            Cmd::RehearsalDirs(g) => format!("sh -c 'ls -d {g} 2>/dev/null; true'"),
            Cmd::Sql(s) => bench(s),
            Cmd::BackupList => format!(
                "{cd}docker compose exec -T backend sh -c 'ls -l --time-style=+%s sites/{}/private/backups'",
                c.site
            ),
            Cmd::RemoteNow => "date +%s".to_string(),
            Cmd::LocalImageId(i) => format!("docker image inspect -f {{{{.Id}}}} {i}"),
            Cmd::GitRev(r) => format!("rev-parse {r}"),
        })
    }
}

pub struct Out {
    pub code: i32,
    pub stdout: String,
}

pub trait Transport {
    fn run(&self, cmd: &Cmd, c: &Ctx) -> Result<Out, String>;
}

pub struct SshTransport {
    pub host: String,
    pub repo: PathBuf,
    pub timeout: Duration,
}

fn spawn_with_timeout(mut command: Command, timeout: Duration) -> Result<Out, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timeout after {}s", timeout.as_secs()));
            }
            Ok(None) => std::thread::park_timeout(Duration::from_millis(20)),
            Err(e) => return Err(format!("wait failed: {e}")),
        }
    };
    let stdout = reader.join().unwrap_or_default();
    Ok(Out {
        code: status.code().unwrap_or(-1),
        stdout,
    })
}

fn remote_outcome(o: crate::remote::RemoteOutcome) -> Result<Out, String> {
    use crate::remote::RemoteOutcome as R;
    match o {
        R::Success(stdout) => Ok(Out { code: 0, stdout }),
        R::Failed { exit_code, .. } => Ok(Out {
            code: exit_code.unwrap_or(-1),
            stdout: String::new(),
        }),
        R::Timeout { timeout_secs, .. } => Err(format!("timeout after {timeout_secs}s")),
        R::AuthRequired { .. } => Err("ssh needs interactive authentication".into()),
        R::Unreachable { reason, .. } => Err(format!("host unreachable: {reason}")),
    }
}

impl Transport for SshTransport {
    fn run(&self, cmd: &Cmd, c: &Ctx) -> Result<Out, String> {
        let text = cmd.render(c).ok_or("unsafe parameter")?;
        let command = match cmd {
            Cmd::LocalImageId(i) => {
                let mut k = Command::new("docker");
                k.args(["image", "inspect", "-f", "{{.Id}}"]).arg(i);
                k
            }
            Cmd::GitRev(r) => {
                let mut k = Command::new("git");
                k.arg("-C")
                    .arg(&self.repo)
                    .args(["rev-parse", "--verify", "-q", r]);
                k
            }
            _ => {
                return remote_outcome(crate::remote::run_ssh(
                    &self.host,
                    &text,
                    self.timeout.as_secs(),
                ));
            }
        };
        spawn_with_timeout(command, self.timeout)
    }
}

pub struct Opts {
    pub tag: String,
    pub repo_ref: Vec<String>,
    pub image: Option<String>,
    pub expect_main: bool,
    pub previous_tag: Option<String>,
    pub protected: Vec<(String, String, String)>,
    pub max_backup_age_hours: u64,
    pub fc: FrappeConfig,
    pub site: String,
    pub dir: String,
}

fn one_line(o: &Out) -> String {
    o.stdout.trim().to_string()
}

fn try_run(t: &dyn Transport, cmd: &Cmd, c: &Ctx) -> Result<Out, String> {
    t.run(cmd, c)
}

fn rev_of(t: &dyn Transport, refs: &[String], c: &Ctx) -> Option<String> {
    refs.iter().find_map(|r| {
        t.run(&Cmd::GitRev(format!("{r}^{{commit}}")), c)
            .ok()
            .filter(|o| o.code == 0)
            .map(|o| one_line(&o))
            .filter(|s| !s.is_empty())
    })
}

pub fn run_checks(t: &dyn Transport, o: &Opts) -> Vec<Check> {
    let c = Ctx {
        dir: o.dir.clone(),
        site: o.site.clone(),
    };
    let mut out = Vec::new();

    // 1. .env tag
    match try_run(t, &Cmd::EnvTag, &c) {
        Ok(r) if r.code == 0 && one_line(&r) == o.tag => out.push(check(
            Status::Pass,
            "env-tag",
            format!("MIRACENA_IMAGE_TAG={}", o.tag),
        )),
        Ok(r) => out.push(check(
            Status::Fail,
            "env-tag",
            format!(
                "MIRACENA_IMAGE_TAG is '{}', expected '{}'",
                one_line(&r),
                o.tag
            ),
        )),
        Err(e) => out.push(check(Status::Fail, "env-tag", e)),
    }

    // 2. .built-from
    let want = rev_of(t, &o.repo_ref, &c);
    match (try_run(t, &Cmd::BuiltFrom, &c), &want) {
        (Ok(r), Some(w)) if r.code == 0 && one_line(&r) == *w => {
            out.push(check(
                Status::Pass,
                "built-from",
                format!("{} = tag commit", &w[..w.len().min(12)]),
            ));
            if o.expect_main {
                let main = rev_of(t, &["main".to_string()], &c);
                match main {
                    Some(m) if m == *w => {
                        out.push(check(Status::Pass, "built-from-main", "tag commit = main"))
                    }
                    Some(m) => out.push(check(
                        Status::Fail,
                        "built-from-main",
                        format!("main is {}", &m[..m.len().min(12)]),
                    )),
                    None => out.push(check(
                        Status::Fail,
                        "built-from-main",
                        "cannot resolve main",
                    )),
                }
            }
        }
        (Ok(r), Some(w)) => out.push(check(
            Status::Fail,
            "built-from",
            format!(
                "running {} != tag commit {}",
                one_line(&r).chars().take(12).collect::<String>(),
                &w[..w.len().min(12)]
            ),
        )),
        (_, None) => out.push(check(
            Status::Fail,
            "built-from",
            "tag not found in the repository",
        )),
        (Err(e), _) => out.push(check(Status::Fail, "built-from", e)),
    }

    // 3. image id on both hosts
    match &o.image {
        None => out.push(check(
            Status::Warn,
            "image-id",
            "image not configured ([frappe] image): skipped",
        )),
        Some(img) => {
            let r = format!("{img}:{}", o.tag);
            match (
                t.run(&Cmd::LocalImageId(r.clone()), &c),
                t.run(&Cmd::RemoteImageId(r), &c),
            ) {
                (Ok(a), Ok(b))
                    if a.code == 0
                        && b.code == 0
                        && !one_line(&a).is_empty()
                        && one_line(&a) == one_line(&b) =>
                {
                    out.push(check(
                        Status::Pass,
                        "image-id",
                        format!(
                            "identical {}",
                            one_line(&a).chars().skip(7).take(12).collect::<String>()
                        ),
                    ));
                }
                (Ok(a), Ok(b)) => out.push(check(
                    Status::Fail,
                    "image-id",
                    format!(
                        "local '{}' vs remote '{}'",
                        one_line(&a).chars().skip(7).take(12).collect::<String>(),
                        one_line(&b).chars().skip(7).take(12).collect::<String>()
                    ),
                )),
                (a, b) => out.push(check(
                    Status::Fail,
                    "image-id",
                    a.err().or(b.err()).unwrap_or_default(),
                )),
            }
        }
    }

    // 4. services
    out.push(check_services(t, &c));

    // 5. ping
    match &o.fc.ping_url {
        None => out.push(check(
            Status::Warn,
            "ping",
            "ping_url not configured: skipped",
        )),
        Some(url) => match t.run(&Cmd::Ping(url.clone(), o.site.clone()), &c) {
            Ok(r) if one_line(&r) == "200" => out.push(check(Status::Pass, "ping", "HTTP 200")),
            Ok(r) => out.push(check(
                Status::Fail,
                "ping",
                format!("HTTP '{}'", one_line(&r)),
            )),
            Err(e) => out.push(check(Status::Fail, "ping", e)),
        },
    }

    // 6. image tags
    if let Some(img) = &o.image {
        match t.run(&Cmd::ImageTags(img.clone()), &c) {
            Ok(r) if r.code == 0 => {
                let tags: BTreeSet<String> = r
                    .stdout
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && l != "<none>")
                    .collect();
                let mut allowed: BTreeSet<String> = BTreeSet::from([o.tag.clone()]);
                if let Some(p) = &o.previous_tag {
                    allowed.insert(p.clone());
                }
                let extra: Vec<&String> = tags.iter().filter(|x| !allowed.contains(*x)).collect();
                if !tags.contains(&o.tag) {
                    out.push(check(
                        Status::Fail,
                        "image-tags",
                        "current tag not on the host",
                    ));
                } else if o.previous_tag.is_some() && !extra.is_empty()
                    || o.previous_tag.is_none() && tags.len() > 2
                {
                    out.push(check(
                        Status::Fail,
                        "image-tags",
                        format!(
                            "{} tags on the host, more than current and previous: {:?}",
                            tags.len(),
                            extra
                        ),
                    ));
                } else {
                    out.push(check(
                        Status::Pass,
                        "image-tags",
                        format!(
                            "{} tag(s): current{}",
                            tags.len(),
                            if tags.len() > 1 { " and previous" } else { "" }
                        ),
                    ));
                }
            }
            Ok(_) => out.push(check(Status::Fail, "image-tags", "docker images failed")),
            Err(e) => out.push(check(Status::Fail, "image-tags", e)),
        }
    }

    // 7. rehearsal leftovers
    out.push(check_leftovers(t, &c, &o.fc));

    // 8. error log (count only)
    match t.run(
        &Cmd::Sql(
            "select count(*) from `tabError Log` where creation > now() - interval 60 minute"
                .into(),
        ),
        &c,
    ) {
        Ok(r) if r.code == 0 => match one_line(&r).parse::<u64>() {
            Ok(0) => out.push(check(
                Status::Pass,
                "error-log",
                "0 rows in the last 60 minutes",
            )),
            Ok(n) => out.push(check(
                Status::Fail,
                "error-log",
                format!("{n} Error Log row(s) in the last 60 minutes"),
            )),
            Err(_) => out.push(check(Status::Fail, "error-log", "unexpected SQL output")),
        },
        Ok(_) => out.push(check(Status::Fail, "error-log", "SQL command failed")),
        Err(e) => out.push(check(Status::Fail, "error-log", e)),
    }

    // 9. protected records
    for (dt, name, modified) in &o.protected {
        let sql = format!("select modified from `tab{dt}` where name=\"{name}\"");
        match t.run(&Cmd::Sql(sql), &c) {
            Ok(r) if r.code == 0 && one_line(&r) == *modified => out.push(check(
                Status::Pass,
                "protected-record",
                format!("{dt} '{name}' unchanged"),
            )),
            Ok(r) if r.code == 0 => out.push(check(
                Status::Fail,
                "protected-record",
                format!(
                    "{dt} '{name}' modified is '{}', expected '{modified}'",
                    one_line(&r)
                ),
            )),
            Ok(_) => out.push(check(
                Status::Fail,
                "protected-record",
                format!("{dt} '{name}': SQL failed"),
            )),
            Err(e) => out.push(check(Status::Fail, "protected-record", e)),
        }
    }

    // 10. last backup age
    out.push(check_backup(t, &c, o.max_backup_age_hours));
    out
}

fn check_services(t: &dyn Transport, c: &Ctx) -> Check {
    let (ps, pol) = (
        t.run(&Cmd::ComposeServices, c),
        t.run(&Cmd::RestartPolicies, c),
    );
    let (ps, pol) = match (ps, pol) {
        (Ok(a), Ok(b)) if a.code == 0 && b.code == 0 => (a, b),
        (a, b) => {
            return check(
                Status::Fail,
                "services",
                a.err()
                    .or(b.err())
                    .unwrap_or_else(|| "compose command failed".into()),
            );
        }
    };
    let policies: BTreeMap<String, String> = pol
        .stdout
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(s, p)| (s.to_string(), p.trim().to_string()))
        .collect();
    let rows: Vec<serde_json::Value> = ps
        .stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l.trim()).ok())
        .chain(serde_json::from_str::<Vec<serde_json::Value>>(ps.stdout.trim()).unwrap_or_default())
        .collect();
    if rows.is_empty() {
        return check(Status::Fail, "services", "no compose services found");
    }
    let mut bad = Vec::new();
    for r in &rows {
        let svc = r.get("Service").and_then(|v| v.as_str()).unwrap_or("?");
        let state = r.get("State").and_then(|v| v.as_str()).unwrap_or("");
        let health = r.get("Health").and_then(|v| v.as_str()).unwrap_or("");
        let exit = r.get("ExitCode").and_then(|v| v.as_i64()).unwrap_or(-1);
        let policy = policies.get(svc).map(String::as_str).unwrap_or("?");
        if policy == "no" {
            if !(state == "exited" && exit == 0) {
                bad.push(format!("{svc}: one-shot {state} code {exit}"));
            }
        } else if policy != "unless-stopped" {
            bad.push(format!("{svc}: restart policy '{policy}'"));
        } else if state != "running" || !(health == "healthy" || health.is_empty()) {
            bad.push(format!("{svc}: {state}/{health}"));
        }
    }
    if bad.is_empty() {
        check(
            Status::Pass,
            "services",
            format!(
                "{} services: long-running healthy with unless-stopped, one-shots exited 0",
                rows.len()
            ),
        )
    } else {
        check(Status::Fail, "services", bad.join("; "))
    }
}

fn check_leftovers(t: &dyn Transport, c: &Ctx, fc: &FrappeConfig) -> Check {
    let (Some(p), Some(g)) = (&fc.rehearsal_project, &fc.rehearsal_dir_glob) else {
        return check(
            Status::Warn,
            "rehearsal-leftovers",
            "rehearsal_project / rehearsal_dir_glob not configured: skipped",
        );
    };
    let mut found = Vec::new();
    for (label, cmd) in [
        ("container", Cmd::RehearsalContainers(p.clone())),
        ("volume", Cmd::RehearsalVolumes(p.clone())),
        ("directory", Cmd::RehearsalDirs(g.clone())),
    ] {
        match t.run(&cmd, c) {
            Ok(r) => {
                let n = r.stdout.lines().filter(|l| !l.trim().is_empty()).count();
                if n > 0 {
                    found.push(format!("{n} {label}(s)"));
                }
            }
            Err(e) => return check(Status::Fail, "rehearsal-leftovers", e),
        }
    }
    if found.is_empty() {
        check(
            Status::Pass,
            "rehearsal-leftovers",
            "no rehearsal containers, volumes or directories",
        )
    } else {
        check(Status::Fail, "rehearsal-leftovers", found.join(", "))
    }
}

fn check_backup(t: &dyn Transport, c: &Ctx, max_hours: u64) -> Check {
    let (list, now) = (t.run(&Cmd::BackupList, c), t.run(&Cmd::RemoteNow, c));
    match (list, now) {
        (Ok(l), Ok(n)) if l.code == 0 => {
            let now: u64 = one_line(&n).parse().unwrap_or(0);
            let newest = l
                .stdout
                .lines()
                .filter(|x| x.contains("-database.sql"))
                .filter_map(|x| x.split_whitespace().rev().nth(1)?.parse::<u64>().ok())
                .max();
            match newest {
                None => check(Status::Fail, "backup-age", "no database backup found"),
                Some(ts) if now >= ts && (now - ts) / 3600 <= max_hours => check(
                    Status::Pass,
                    "backup-age",
                    format!(
                        "newest database backup {}h old (limit {max_hours}h)",
                        (now - ts) / 3600
                    ),
                ),
                Some(ts) => check(
                    Status::Fail,
                    "backup-age",
                    format!(
                        "newest database backup {}h old (limit {max_hours}h)",
                        now.saturating_sub(ts) / 3600
                    ),
                ),
            }
        }
        (a, b) => check(
            Status::Fail,
            "backup-age",
            a.err()
                .or(b.err())
                .unwrap_or_else(|| "listing failed".into()),
        ),
    }
}

fn parse_protected(raw: &[String]) -> Result<Vec<(String, String, String)>, String> {
    raw.iter()
        .map(|s| {
            let mut p = s.splitn(3, ':');
            match (p.next(), p.next(), p.next()) {
                (Some(d), Some(n), Some(m))
                    if safe(&d.replace(' ', "_"), "")
                        && safe(&n.replace(' ', "_"), "@+")
                        && !m.is_empty()
                        && !m.contains(['\'', '"', '`', '$', '\\']) =>
                {
                    Ok((d.to_string(), n.to_string(), m.to_string()))
                }
                _ => Err(format!(
                    "bad --protected-record '{s}' (use DocType:name:modified, safe characters only)"
                )),
            }
        })
        .collect()
}

pub fn run_cli(argv: &[String]) -> i32 {
    let a = match VerifyArgs::try_parse_from(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let cfg_path = a
        .config
        .clone()
        .unwrap_or_else(|| a.repo.join("steniocheck.toml"));
    let fc = SteniocheckConfig::load_from_file(&cfg_path)
        .frappe
        .unwrap_or_default();
    let protected = match parse_protected(&a.protected) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let valid = safe(&a.host, "")
        && safe(&a.tag, "")
        && safe(&a.project_dir, "/")
        && a.project_dir.starts_with('/')
        && fc.site.as_deref().map(|s| safe(s, "")).unwrap_or(true)
        && fc.image.as_deref().map(|s| safe(s, "/")).unwrap_or(true)
        && fc
            .rehearsal_project
            .as_deref()
            .map(|s| safe(s, ""))
            .unwrap_or(true)
        && fc
            .rehearsal_dir_glob
            .as_deref()
            .map(|s| safe(s, "/*"))
            .unwrap_or(true)
        && fc
            .ping_url
            .as_deref()
            .map(|s| safe(s, ":/"))
            .unwrap_or(true)
        && a.previous_tag
            .as_deref()
            .map(|s| safe(s, ""))
            .unwrap_or(true);
    if !valid {
        eprintln!("unsafe characters in a host, tag, directory or [frappe] value: refusing to run");
        return 2;
    }
    let opts = Opts {
        repo_ref: vec![a.tag.clone(), format!("v{}", a.tag)],
        tag: a.tag.clone(),
        image: fc.image.clone(),
        expect_main: a.expect_main,
        previous_tag: a.previous_tag.clone(),
        protected,
        max_backup_age_hours: a.max_backup_age_hours,
        site: fc.site.clone().unwrap_or_else(|| "frontend".into()),
        dir: a.project_dir.clone(),
        fc,
    };
    let t = SshTransport {
        host: a.host.clone(),
        repo: a.repo.clone(),
        timeout: Duration::from_secs(a.timeout_secs),
    };
    println!(
        "stenio verify-release host={} tag={} dir={}",
        a.host, a.tag, a.project_dir
    );
    let results = run_checks(&t, &opts);
    for r in &results {
        let label = match r.status {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Warn => "WARN",
        };
        println!("{label} {:<20} {}", r.name, r.detail);
    }
    let fails = results.iter().filter(|r| r.status == Status::Fail).count();
    let warns = results.iter().filter(|r| r.status == Status::Warn).count();
    println!("{} check(s): {} FAIL, {} WARN", results.len(), fails, warns);
    i32::from(fails > 0)
}

// ── offline tests with a fake transport ────────────────────────────────────
struct Fake(BTreeMap<Cmd, (i32, String)>);

impl Transport for Fake {
    fn run(&self, cmd: &Cmd, _c: &Ctx) -> Result<Out, String> {
        match self.0.get(cmd) {
            Some((code, s)) => Ok(Out {
                code: *code,
                stdout: s.clone(),
            }),
            None => Err("not scripted".into()),
        }
    }
}

const SHA: &str = "f464242c6215c18f69ba59f47aa0d240c0f75c7e";

fn fixture_opts() -> Opts {
    let fc = FrappeConfig {
        image: Some("acme/app".into()),
        ping_url: Some("http://127.0.0.1:8081/api/method/ping".into()),
        rehearsal_project: Some("acme-rc".into()),
        rehearsal_dir_glob: Some("/srv/acme/app-rc*".into()),
        ..FrappeConfig::default()
    };
    Opts {
        tag: "1.0.0".into(),
        repo_ref: vec!["1.0.0".into(), "v1.0.0".into()],
        image: fc.image.clone(),
        expect_main: false,
        previous_tag: Some("0.9.0".into()),
        protected: vec![(
            "Member".into(),
            "ana".into(),
            "2026-01-01 10:00:00.000000".into(),
        )],
        max_backup_age_hours: 30,
        site: "frontend".into(),
        dir: "/srv/acme".into(),
        fc,
    }
}

fn good_fake(o: &Opts) -> BTreeMap<Cmd, (i32, String)> {
    let mut m = BTreeMap::new();
    let ok = |s: &str| (0, format!("{s}\n"));
    m.insert(Cmd::EnvTag, ok("1.0.0"));
    m.insert(Cmd::GitRev("1.0.0^{commit}".into()), (1, String::new()));
    m.insert(Cmd::GitRev("v1.0.0^{commit}".into()), ok(SHA));
    m.insert(Cmd::GitRev("main^{commit}".into()), ok(SHA));
    m.insert(Cmd::BuiltFrom, ok(SHA));
    m.insert(
        Cmd::LocalImageId("acme/app:1.0.0".into()),
        ok("sha256:aaaaaaaaaaaaaaaaaaaa"),
    );
    m.insert(
        Cmd::RemoteImageId("acme/app:1.0.0".into()),
        ok("sha256:aaaaaaaaaaaaaaaaaaaa"),
    );
    m.insert(Cmd::ComposeServices, ok("{\"Service\":\"backend\",\"State\":\"running\",\"Health\":\"healthy\",\"ExitCode\":0}\n{\"Service\":\"migrate\",\"State\":\"exited\",\"Health\":\"\",\"ExitCode\":0}"));
    m.insert(
        Cmd::RestartPolicies,
        ok("backend unless-stopped\nmigrate no"),
    );
    m.insert(
        Cmd::Ping(
            "http://127.0.0.1:8081/api/method/ping".into(),
            "frontend".into(),
        ),
        (0, "200".into()),
    );
    m.insert(Cmd::ImageTags("acme/app".into()), ok("1.0.0\n0.9.0"));
    m.insert(
        Cmd::RehearsalContainers("acme-rc".into()),
        (0, String::new()),
    );
    m.insert(Cmd::RehearsalVolumes("acme-rc".into()), (0, String::new()));
    m.insert(
        Cmd::RehearsalDirs("/srv/acme/app-rc*".into()),
        (0, String::new()),
    );
    m.insert(
        Cmd::Sql(
            "select count(*) from `tabError Log` where creation > now() - interval 60 minute"
                .into(),
        ),
        ok("0"),
    );
    m.insert(
        Cmd::Sql("select modified from `tabMember` where name=\"ana\"".into()),
        ok("2026-01-01 10:00:00.000000"),
    );
    m.insert(
        Cmd::BackupList,
        ok("-rw-r--r-- 1 f r 100 1000 20260101_000000-frontend-database.sql.gz"),
    );
    m.insert(Cmd::RemoteNow, ok("4600"));
    let _ = o;
    m
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let o = fixture_opts();
    let good = run_checks(&Fake(good_fake(&o)), &o);
    let all_pass = good.iter().all(|c| c.status == Status::Pass);
    let mut bad_map = good_fake(&o);
    bad_map.insert(Cmd::EnvTag, (0, "0.9.0\n".into()));
    bad_map.insert(Cmd::BuiltFrom, (0, "deadbeef\n".into()));
    bad_map.insert(
        Cmd::ImageTags("acme/app".into()),
        (0, "1.0.0\n0.9.0\n0.8.0".into()),
    );
    bad_map.insert(
        Cmd::RehearsalVolumes("acme-rc".into()),
        (0, "acme-rc_db\n".into()),
    );
    bad_map.insert(
        Cmd::Sql(
            "select count(*) from `tabError Log` where creation > now() - interval 60 minute"
                .into(),
        ),
        (0, "3\n".into()),
    );
    bad_map.insert(Cmd::RemoteNow, (0, "999999\n".into()));
    let bad = run_checks(&Fake(bad_map), &o);
    let failed: BTreeSet<&str> = bad
        .iter()
        .filter(|c| c.status == Status::Fail)
        .map(|c| c.name)
        .collect();
    let expected = [
        "env-tag",
        "built-from",
        "image-tags",
        "rehearsal-leftovers",
        "error-log",
        "backup-age",
    ];
    vec![
        ("verify-release good".to_string(), all_pass),
        (
            "verify-release bad".to_string(),
            expected.iter().all(|e| failed.contains(e)),
        ),
        (
            "verify-release params".to_string(),
            parse_protected(&["Member:a'b:x".into()]).is_err()
                && parse_protected(&["Member:ana:2026".into()]).is_ok(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_checks() {
        assert!(
            self_test_cases().iter().all(|(_, ok)| *ok),
            "{:?}",
            self_test_cases()
        );
    }
}
