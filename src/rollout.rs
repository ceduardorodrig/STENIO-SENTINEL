//! The binary targets a release updates besides its own host and the container: declared in one
//! file, never in code. Each target is staged, checked, swapped with a rollback copy, restarted
//! and probed; a failure restores the previous binary and leaves the later targets alone.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

use crate::release_engine::Runner;
use crate::verify_release::{Out, safe};

/// The declaration, relative to the engine repository.
pub const DECLARATION: &str = "deploy/rollout.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// SSH destination.
    pub host: String,
    /// The binary to replace: absolute, or `~/...`.
    pub path: String,
    #[serde(default)]
    pub sudo: bool,
    /// Started before the swap (a snapshot of the data the service owns).
    pub backup_unit: Option<String>,
    /// Restarted after the swap and after a restore.
    pub restart: Option<String>,
    /// Fetched on the target after the restart; it must answer.
    pub health: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    target: Vec<Target>,
}

/// What is being rolled out.
pub struct Release<'a> {
    pub binary: &'a Path,
    pub version: &'a str,
    pub sha256: &'a str,
}

fn plain(value: &str, extra: &str) -> bool {
    safe(value, extra) && !value.starts_with('-')
}

fn valid(t: &Target) -> bool {
    let unit = |u: &Option<String>| u.as_deref().is_none_or(|u| plain(u, "._-@"));
    plain(&t.host, "._-@")
        && plain(&t.path, "/._-~")
        && (t.path.starts_with('/') || t.path.starts_with("~/"))
        && unit(&t.backup_unit)
        && unit(&t.restart)
        && t.health.as_deref().is_none_or(|h| plain(h, "/._-:"))
}

pub fn load(file: &Path) -> Result<Vec<Target>, String> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let declared: Declaration =
        toml::from_str(&text).map_err(|e| format!("invalid {}: {e}", file.display()))?;
    if declared.target.is_empty() {
        return Err(format!("{} declares no target", file.display()));
    }
    if let Some(bad) = declared.target.iter().find(|t| !valid(t)) {
        return Err(format!(
            "unsafe characters in the target {}:{}",
            bad.host, bad.path
        ));
    }
    Ok(declared.target)
}

pub fn digest(binary: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(binary).map_err(|e| format!("cannot read {}: {e}", binary.display()))?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn label(t: &Target) -> String {
    format!("{}:{}", t.host, t.path)
}

fn ssh(t: &Target, script: String) -> Vec<String> {
    ["ssh", "-o", "BatchMode=yes", &t.host, &script]
        .map(String::from)
        .to_vec()
}

/// Relative to the login directory, for both `scp` and the remote shell.
fn staged(release: &Release) -> String {
    format!(".stenio-rollout-{}", release.version)
}

fn probe_argv(t: &Target) -> Vec<String> {
    ssh(t, format!("{0} --version && sha256sum {0}", t.path))
}

pub fn parity_argv(t: &Target) -> Vec<String> {
    ssh(t, format!("sha256sum {0} && {0} --version", t.path))
}

fn copy_argv(t: &Target, release: &Release) -> Vec<String> {
    let from = release.binary.display().to_string();
    let to = format!("{}:{}", t.host, staged(release));
    ["scp", "-q", "-o", "BatchMode=yes", &from, &to]
        .map(String::from)
        .to_vec()
}

/// The staged binary must run on the target before anything is replaced.
fn check_argv(t: &Target, release: &Release) -> Vec<String> {
    let file = staged(release);
    ssh(t, format!("chmod 755 {file} && ./{file} --version"))
}

fn sudo(t: &Target) -> &'static str {
    if t.sudo { "sudo -n " } else { "" }
}

fn swap_argv(t: &Target, release: &Release, old: &str) -> Vec<String> {
    let (s, path, file) = (sudo(t), &t.path, staged(release));
    let backup = t
        .backup_unit
        .as_ref()
        .map(|u| format!("sudo -n systemctl start {u} && "))
        .unwrap_or_default();
    // An existing rollback copy of that version is the older one: it is kept.
    ssh(
        t,
        format!(
            "{backup}{{ test -e {path}.prev-{old} || {s}cp -p {path} {path}.prev-{old}; }} && \
             {s}install -m 755 {file} {path}.new && {s}mv -f {path}.new {path} && rm -f {file}"
        ),
    )
}

fn restart_steps(t: &Target) -> Option<String> {
    let unit = t.restart.as_ref()?;
    let health = t.health.as_ref().map_or(String::new(), |url| {
        format!(" && curl -fsS -m 5 --retry 15 --retry-delay 1 --retry-connrefused {url}")
    });
    Some(format!(
        "sudo -n systemctl restart {unit}{health} && systemctl is-active {unit}"
    ))
}

/// Restart and probe the service, then ask the installed binary for its version (printed last).
pub fn activate_argv(t: &Target, release: &Release) -> Vec<String> {
    let restart = restart_steps(t)
        .map(|r| format!("{{ {r}; }} >/dev/null && "))
        .unwrap_or_default();
    // The version is in the script so that one release cannot answer for another.
    ssh(
        t,
        format!(
            "{restart}test \"$({0} --version)\" = \"stenio {1}\"",
            t.path, release.version
        ),
    )
}

fn restore_argv(t: &Target, old: &str) -> Vec<String> {
    let (s, path) = (sudo(t), &t.path);
    let restart = restart_steps(t)
        .map(|r| format!(" && {{ {r}; }} >/dev/null"))
        .unwrap_or_default();
    ssh(
        t,
        format!("{s}cp -p {path}.prev-{old} {path}.new && {s}mv -f {path}.new {path}{restart}"),
    )
}

/// `(version, sha256)` read from the two lines of a probe, in either order.
fn read_state(out: &str) -> (String, String) {
    let mut found = (String::new(), String::new());
    for line in out.lines() {
        match line.strip_prefix("stenio ") {
            Some(version) => found.0 = version.trim().to_string(),
            None => {
                if let Some(sha) = line.split_whitespace().next() {
                    found.1 = sha.to_string();
                }
            }
        }
    }
    found
}

fn run(r: &dyn Runner, argv: &[String], secs: u64) -> Result<Out, String> {
    let out = r.run(None, argv, Duration::from_secs(secs))?;
    if out.code == 0 {
        Ok(out)
    } else {
        Err(format!("exit {}", out.code))
    }
}

fn update(r: &dyn Runner, t: &Target, release: &Release) -> Result<String, String> {
    let probe = run(r, &probe_argv(t), 60).map_err(|e| format!("cannot probe ({e})"))?;
    let (old, sha) = read_state(&probe.stdout);
    if old == release.version && sha == release.sha256 {
        return Ok(format!("{} already {old}", label(t)));
    }
    if !old.starts_with(|c: char| c.is_ascii_digit()) || !plain(&old, ".-+") {
        return Err("no readable version: no rollback copy can be named".to_string());
    }
    run(r, &copy_argv(t, release), 300).map_err(|e| format!("copy failed ({e})"))?;
    let staged = run(r, &check_argv(t, release), 60)
        .map_err(|e| format!("the staged binary does not run there ({e}); nothing replaced"))?;
    if read_state(&staged.stdout).0 != release.version {
        return Err("the staged binary declares another version; nothing replaced".to_string());
    }
    let swapped = run(r, &swap_argv(t, release, &old), 180)
        .map_err(|e| format!("swap failed ({e})"))
        .and_then(|_| {
            run(r, &activate_argv(t, release), 120)
                .map_err(|e| format!("not healthy after the swap ({e})"))
        });
    match swapped {
        Ok(_) => Ok(format!("{} {old} -> {}", label(t), release.version)),
        Err(why) => match run(r, &restore_argv(t, &old), 180) {
            Ok(_) => Err(format!("{why}; restored {old}")),
            Err(e) => Err(format!(
                "{why}; RESTORE FAILED ({e}): copy {}.prev-{old} back by hand",
                t.path
            )),
        },
    }
}

/// Updates the targets in their declared order and stops at the first failure.
pub fn apply(r: &dyn Runner, targets: &[Target], release: &Release) -> Result<String, String> {
    let mut done = Vec::new();
    for (index, t) in targets.iter().enumerate() {
        match update(r, t, release) {
            Ok(detail) => done.push(detail),
            Err(why) => {
                return Err(format!(
                    "{}: {why}; {} target(s) not updated; updated before: {}",
                    label(t),
                    targets.len() - index - 1,
                    if done.is_empty() {
                        "none".to_string()
                    } else {
                        done.join(", ")
                    }
                ));
            }
        }
    }
    Ok(format!(
        "{n}/{n} target(s): {}",
        done.join(", "),
        n = targets.len()
    ))
}

/// Every declared target runs exactly the released bytes.
pub fn parity(r: &dyn Runner, targets: &[Target], release: &Release) -> Result<String, String> {
    let differs: Vec<String> = targets
        .iter()
        .filter_map(|t| match run(r, &parity_argv(t), 60) {
            Ok(out) => {
                let (version, sha) = read_state(&out.stdout);
                (version != release.version || sha != release.sha256).then(|| {
                    format!(
                        "{} has {version} {}",
                        label(t),
                        sha.get(..12).unwrap_or(&sha)
                    )
                })
            }
            Err(e) => Some(format!("{} unreadable ({e})", label(t))),
        })
        .collect();
    let n = targets.len();
    if differs.is_empty() {
        Ok(format!("{n}/{n} target(s) run {}", release.version))
    } else {
        Err(format!(
            "{}/{n} target(s) run the release; {}",
            n - differs.len(),
            differs.join(", ")
        ))
    }
}

/// The commands of a successful update of one target, with their answers, for the offline cases.
pub fn scripted(t: &Target, release: &Release, old: &str) -> Vec<(Vec<String>, String)> {
    let (new, sha) = (release.version, release.sha256);
    vec![
        (probe_argv(t), format!("stenio {old}\nffff  {}\n", t.path)),
        (copy_argv(t, release), String::new()),
        (check_argv(t, release), format!("stenio {new}\n")),
        (swap_argv(t, release, old), String::new()),
        (activate_argv(t, release), String::new()),
        (restore_argv(t, old), String::new()),
        (parity_argv(t), format!("{sha}  {}\nstenio {new}\n", t.path)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_declaration_is_valid_and_puts_the_server_first()
    -> Result<(), Box<dyn std::error::Error>> {
        let file = Path::new(env!("CARGO_MANIFEST_DIR")).join(DECLARATION);
        let targets = load(&file)?;
        assert!(targets.first().is_some_and(|t| t.restart.is_some()));
        Ok(())
    }
}
