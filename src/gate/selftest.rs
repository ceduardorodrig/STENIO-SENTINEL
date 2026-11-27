//! Red and green fixtures of the gate. Every command here is only text: nothing is executed.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};

use super::judge::{BACKUP, DB, DESTROY, HISTORY, POWER, PUBLISH, SECRET, SELF, STORAGE};
use super::{Action, action_of, audit, decide, grant, judge_action, policy};

const HOME: &str = "/home/agent";
const CWD: &str = "/mnt/disk/projects/app";

/// Commands the list must stop, with the rule expected among the findings.
const RED: &[(&str, &str)] = &[
    // destroying data
    ("rm -rf /", DESTROY),
    ("rm -rf ~", DESTROY),
    ("rm -rf $HOME/projects", DESTROY),
    ("rm -fr /mnt/disk", DESTROY),
    ("rm -r -f /mnt/disk/projects", DESTROY),
    ("rm --recursive /mnt/disk/projects/", DESTROY),
    ("cd /mnt/disk && rm -rf projects", DESTROY),
    ("cd /mnt/disk/projects && rm -rf ./*", DESTROY),
    ("D=/mnt/disk/projects; rm -rf \"$D\"", DESTROY),
    ("rm -rf \"$UNSET\"/*", DESTROY),
    ("rm -f /mnt/BACKUP/configs/x.tar", DESTROY),
    ("rm /mnt/storage/photos/a.jpg", DESTROY),
    ("rm -rf .git", DESTROY),
    ("rip -r ~/documents", DESTROY),
    ("mv ~/documents /tmp/x", DESTROY),
    ("find /mnt/BACKUP -name '*.old' -delete", DESTROY),
    ("find /mnt/disk -delete", DESTROY),
    ("fd . /mnt/BACKUP -x rm", DESTROY),
    ("fd . /mnt/disk/projects -X rm -rf", DESTROY),
    ("find /mnt/storage -type f -exec rm {} \\;", DESTROY),
    ("truncate -s 0 /mnt/BACKUP/dump.sql && true", DESTROY),
    ("rsync -a --delete ./empty/ /mnt/disk/projects", DESTROY),
    ("chmod -R 777 /etc", DESTROY),
    // storage
    ("shred -u secret.bin", STORAGE),
    ("sudo wipefs -a /dev/sda", STORAGE),
    ("mkfs.ext4 /dev/sdb1", STORAGE),
    ("dd if=/dev/zero of=/dev/nvme0n1 bs=1M", STORAGE),
    ("parted /dev/sda mklabel gpt", STORAGE),
    ("echo '' > /dev/sda", STORAGE),
    ("cryptsetup luksFormat /dev/sda2", STORAGE),
    // backups and volumes
    ("restic -r /repo forget --prune", BACKUP),
    ("sudo btrfs subvolume delete /snapshots/1", BACKUP),
    ("snapper -c root delete 3", BACKUP),
    ("docker volume rm db_data", BACKUP),
    ("docker volume prune -f", BACKUP),
    ("docker compose -f s.yml down -v", BACKUP),
    ("docker system prune -af --volumes", BACKUP),
    ("rclone purge drive:backup", BACKUP),
    ("gh api -X DELETE repos/o/r", BACKUP),
    // history
    ("git push --force", HISTORY),
    ("git push -f origin main", HISTORY),
    ("git -C /repo push --force-with-lease origin main", HISTORY),
    ("git push origin +main", HISTORY),
    ("git push origin :old-branch", HISTORY),
    ("git push origin --delete \"$B\"", HISTORY),
    ("git push -d origin old", HISTORY),
    ("git push --mirror backup", HISTORY),
    ("git -c core.x=y push -uf origin x", HISTORY),
    ("git filter-repo --path x --invert-paths", HISTORY),
    ("git reflog expire --expire=now --all", HISTORY),
    // secrets
    ("sops -d secrets.enc.env", SECRET),
    ("sops --decrypt s.yml | rg TOKEN", SECRET),
    ("sops -d s.env > plain.env", SECRET),
    ("gh auth token > t", SECRET),
    ("docker compose down -v", BACKUP),
    ("cd /srv/app && docker compose down -v", BACKUP),
    ("echo \"$(sops -d s.env)\"", SECRET),
    ("age -d -i key.txt s.age", SECRET),
    ("printenv", SECRET),
    ("printenv GITHUB_TOKEN", SECRET),
    ("env | sort", SECRET),
    ("echo $API_KEY", SECRET),
    ("echo \"token=${MY_TOKEN}\"", SECRET),
    ("bat .env", SECRET),
    ("rg KEY ~/.config/app/.env", SECRET),
    ("rg -n KEY .env", SECRET),
    ("head -n 3 .env", SECRET),
    ("shred -u \"$F\"", STORAGE),
    ("cat ~/.ssh/id_ed25519", SECRET),
    ("gh auth token", SECRET),
    ("sops exec-env s.env 'printenv'", SECRET),
    // power
    ("reboot", POWER),
    ("sudo shutdown -h now", POWER),
    ("systemctl poweroff", POWER),
    ("sudo systemctl --force reboot", POWER),
    ("ssh kuaray 'sudo reboot'", POWER),
    ("xh POST http://relay/power/shutdown", POWER),
    // database
    ("psql -c 'DROP DATABASE prod'", DB),
    ("echo 'drop table users;' | mysql app", DB),
    ("mariadb app <<EOF\nTRUNCATE TABLE tabUser;\nEOF", DB),
    ("sqlite3 x.db 'DELETE FROM events;'", DB),
    ("dropdb prod", DB),
    ("bench --site a.local drop-site", DB),
    (
        "docker exec db psql -U x -c 'drop schema public cascade'",
        DB,
    ),
    ("redis-cli FLUSHALL", DB),
    // publishing without a lease
    ("cargo publish", PUBLISH),
    ("docker push ghcr.io/o/i:1", PUBLISH),
    ("docker stack deploy -c s.yml app", PUBLISH),
    ("gh release create v1.0.0", PUBLISH),
    ("git push origin v1.2.3", PUBLISH),
    ("git push --tags", PUBLISH),
    ("./scripts/release.sh v2", PUBLISH),
    ("bash release.sh", PUBLISH),
    ("terraform destroy", PUBLISH),
    // the guard itself
    (
        "stenio gate override --rule GATE-POWER --for 1h --reason x",
        SELF,
    ),
    (
        "stenio hub quota override --account a --for 1h --reason x",
        SELF,
    ),
    ("echo '{}' > ~/.claude/settings.json", SELF),
    ("sd always never ~/.hermes/config.yaml", SELF),
    ("cp /tmp/x ~/.config/opencode/opencode.jsonc", SELF),
    ("rm ~/.config/opencode/plugins/stenio-hub.ts", SELF),
    ("echo x | tee -a ~/.gemini/config/hooks.json", SELF),
    ("chmod -x /mnt/vault/scripts/agent-hooks/guard.sh", SELF),
    ("sed -i s/a/b/ .claude/settings.local.json", SELF),
    ("rm ~/.local/state/stenio/gate/audit/h.jsonl", SELF),
    ("cp evil ~/.cargo/bin/stenio", SELF),
    // evasion
    ("bash -c 'git push --force'", HISTORY),
    ("sh -c \"rm -rf /\"", DESTROY),
    ("zsh -lc 'reboot'", POWER),
    ("env reboot", POWER),
    ("env A=1 B=2 git push -f", HISTORY),
    ("command reboot", POWER),
    ("\\reboot", POWER),
    ("/usr/sbin/reboot", POWER),
    ("r\"\"eboot", POWER),
    ("nohup setsid timeout 5 nice -n 5 reboot", POWER),
    ("sudo -u root -E reboot", POWER),
    ("eval 'git push --force'", HISTORY),
    ("echo ok && (cd /x; reboot)", POWER),
    ("true; if true; then reboot; fi", POWER),
    ("for h in a b; do ssh $h poweroff; done", POWER),
    ("x=$(reboot)", POWER),
    ("echo `reboot`", POWER),
    ("diff <(sops -d a) <(echo reboot; reboot)", POWER),
    ("echo 'reboot' | sh", POWER),
    ("bash <<'EOF'\nreboot\nEOF", POWER),
    ("ssh host bash -c 'wipefs -a /dev/sda'", STORAGE),
    ("docker exec -it c sh -c 'dropdb prod'", DB),
    (
        "fd -e x . | xargs rm -rf; find /mnt/disk/projects | xargs rm -rf",
        DESTROY,
    ),
    ("echo a | xargs -I{} git push --force", HISTORY),
    (
        "script -qc 'stenio gate override --rule GATE-DB --for 1h --reason x' /dev/null",
        SELF,
    ),
    (
        "python3 -c \"import os; os.system('git push --force')\"",
        HISTORY,
    ),
    (
        "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'push', '--force'])\nEOF",
        HISTORY,
    ),
    (
        "python3 -c \"import shutil; shutil.rmtree('/mnt/disk/projects')\"",
        DESTROY,
    ),
    ("git status\nreboot", POWER),
    ("git \\\n push \\\n --force", HISTORY),
];

/// Ordinary work, which must proceed.
const GREEN: &[&str] = &[
    "git status && git diff --stat",
    "git push -u origin wave/x",
    "git push origin HEAD:main",
    "git push --dry-run --force",
    "git commit -m 'docs: never run git push --force or reboot'",
    "git rebase origin/main",
    "rg -n 'rm -rf /|reboot' src",
    "echo 'rm -rf /' > notes.txt",
    "printf '%s\\n' 'sops -d s.env'",
    "cat > doc.md <<'EOF'\nreboot\ngit push --force\nEOF",
    "ls # then reboot",
    "rm -f build.log",
    "shred -u /tmp/otp.png",
    "rm -rf target node_modules",
    "rm -rf /tmp/scratch-123",
    "rm -rf \"$tmp\"",
    "rm -rf \"${work:?}\"/*",
    "rm -rf /mnt/disk/projects/app/dist",
    "cd /tmp/x && rm -rf ./*",
    "find . -name '*.pyc' -delete",
    "fd -e orig . -x rm",
    "mv a.txt b.txt",
    "cp ~/.claude/settings.json ~/settings.json.prev",
    "bat ~/.claude/settings.json",
    "cp x /mnt/BACKUP/new-copy-does-not-exist",
    "sops -d s.env | docker login ghcr.io -u x --password-stdin",
    "TOKEN=$(sops -d --extract '[\"T\"]' s.yml)",
    "printf '%s' \"$API_KEY\" | gh secret set API_KEY",
    "sops -d s.env | rg -c TOKEN",
    "echo \"${API_KEY:+set}\" ${#API_KEY}",
    "echo $HOME $TOKEN_FILE",
    "printenv PATH",
    "env FOO=1 cargo test",
    "bat .env.example",
    "rg -l TOKEN .env",
    "sops -e -i secrets.yml",
    "docker compose down",
    "TOKEN=$(gh auth token)",
    "cd /tmp/rehearsal && docker compose down -v",
    "docker volume ls",
    "docker system prune -f",
    "systemctl status x && systemctl restart hl-x.service",
    "shutdown -c",
    "psql -c 'select * from t'",
    "sqlite3 x.db 'delete from t where id = 1'",
    "echo 'drop table x' > migration.sql",
    "cargo publish --dry-run",
    "docker build -t x .",
    "gh pr create --title x --body 'git push --force is not allowed'",
    "gh release view v1",
    "stenio gate check --command reboot",
    "stenio hub claim --worker w release:app",
    "snapper -c root create -d before",
    "snapper list",
    "restic backup /data",
    "fdisk -l",
    "xargs -n1 echo reboot",
    "python3 -c \"print('reboot')\"",
    "command -v reboot",
    "man shutdown",
    "echo done 2>&1 >/dev/null",
];

const WRITES_RED: &[(&str, &str)] = &[
    ("~/.claude/settings.json", SELF),
    ("/home/agent/.hermes/config.yaml", SELF),
    ("/mnt/disk/projects/app/.claude/settings.json", SELF),
    ("/mnt/disk/projects/app/opencode.json", SELF),
    ("/mnt/vault/.agents/hooks.json", SELF),
];

const WRITES_GREEN: &[&str] = &[
    "src/main.rs",
    "/tmp/x/.claude/settings.json",
    "/mnt/disk/.agents-work/a/opencode.json",
    "/home/agent/.hermes/config.yaml.prev",
];

fn embedded() -> Option<policy::Policy> {
    policy::Policy::embedded().ok()
}

fn rules_of(policy: &policy::Policy, action: &Action) -> Vec<&'static str> {
    judge_action(policy, HOME, action)
        .into_iter()
        .map(|f| f.rule)
        .collect()
}

fn command(text: &str) -> Action {
    Action {
        cwd: PathBuf::from(CWD),
        command: Some(text.to_string()),
        ..Action::default()
    }
}

fn payload_rules(policy: &policy::Policy, payload: &Value) -> Vec<&'static str> {
    rules_of(policy, &action_of(payload))
}

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stenio-gate-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn script_is_judged(policy: &policy::Policy, dir: &Path) -> bool {
    let script = dir.join("job.sh");
    if std::fs::write(&script, "#!/usr/bin/env bash\nset -e\ngit push --force\n").is_err() {
        return false;
    }
    let path = script.display();
    [
        format!("bash {path}"),
        format!("{path}"),
        format!("source {path}"),
        format!("sudo sh -x {path}"),
    ]
    .iter()
    .all(|c| rules_of(policy, &command(c)).contains(&HISTORY))
}

fn payload_cases(policy: &policy::Policy) -> Vec<(String, bool)> {
    let denied = [
        (
            "claude Bash",
            json!({"tool_name": "Bash", "tool_input": {"command": "reboot"}, "cwd": CWD}),
        ),
        (
            "hermes terminal",
            json!({"tool_name": "terminal", "tool_input": {"command": "reboot"}}),
        ),
        (
            "hermes execute_code",
            json!({"tool_name": "execute_code",
                "tool_input": {"code": "terminal(\"reboot\")"}}),
        ),
        (
            "hermes read_file secret",
            json!({"tool_name": "read_file", "tool_input": {"path": "/srv/app/.env"}}),
        ),
        (
            "hermes write_file guard",
            json!({"tool_name": "write_file",
                "tool_input": {"path": "/home/agent/.hermes/config.yaml", "content": "x"}}),
        ),
        (
            "opencode shell",
            json!({"tool_name": "shell", "tool_input": {"command": "reboot"}}),
        ),
        (
            "opencode patch guard",
            json!({"tool_name": "patch", "tool_input": {"patchText":
                "*** Begin Patch\n*** Update File: /home/agent/.claude/settings.json\n"}}),
        ),
        (
            "patch delete in a backup tree",
            json!({"tool_name": "apply_patch", "tool_input": {"patch":
                "*** Begin Patch\n*** Delete File: /mnt/BACKUP/a\n*** End Patch"}}),
        ),
        (
            "agy run_command",
            json!({"toolCall": {"name": "run_command",
                "args": {"CommandLine": "reboot", "Cwd": CWD}}}),
        ),
        (
            "agy write_to_file guard",
            json!({"toolCall": {"name": "write_to_file",
                "args": {"TargetFile": "/home/agent/.agents/hooks.json"}}}),
        ),
        (
            "agy view_file secret",
            json!({"toolCall": {"name": "view_file",
                "args": {"AbsolutePath": "/home/agent/.ssh/id_ed25519"}}}),
        ),
    ];
    let allowed = [
        (
            "write of a note that quotes a command",
            json!({"tool_name": "Write",
                "tool_input": {"file_path": "/tmp/n.md", "content": "reboot"}}),
        ),
        (
            "read of a settings file",
            json!({"tool_name": "read_file",
                "tool_input": {"path": "/home/agent/.hermes/config.yaml"}}),
        ),
        (
            "unrelated tool",
            json!({"tool_name": "web_search", "tool_input": {"query": "reboot"}}),
        ),
    ];
    denied
        .iter()
        .map(|(name, p)| {
            (
                format!("gate: payload {name} denied"),
                !payload_rules(policy, p).is_empty(),
            )
        })
        .chain(allowed.iter().map(|(name, p)| {
            (
                format!("gate: payload {name} proceeds"),
                payload_rules(policy, p).is_empty(),
            )
        }))
        .collect()
}

fn decision_cases(policy: &policy::Policy, dir: &Path) -> Vec<(String, bool)> {
    let publish = || judge_action(policy, HOME, &command("docker push x"));
    let power = || judge_action(policy, HOME, &command("reboot"));
    let run =
        |found, lease: Result<bool, String>| decide(policy, found, "reboot", dir, || lease).verdict;
    let now = crate::hub::now_ms();
    let record = |until: i64, at: i64| grant::Grant {
        rule: POWER.to_string(),
        until,
        reason: "t".to_string(),
        matching: None,
        at,
    };
    let without = run(power(), Ok(true));
    let stored = grant::store(dir, &record(now + 60_000, now)).is_ok();
    let lifted = run(power(), Ok(false));
    let other = run(publish(), Ok(false));
    let expired =
        grant::store(dir, &record(now - 1, now - 2)).is_ok() && run(power(), Ok(false)) == "deny";
    let long = grant::store(dir, &record(now + 90 * 86_400_000, now)).is_ok()
        && run(power(), Ok(false)) == "deny";
    vec![
        (
            "gate: publish proceeds under a lease".to_string(),
            run(publish(), Ok(true)) == "lease",
        ),
        (
            "gate: publish is denied without a lease".to_string(),
            run(publish(), Ok(false)) == "deny",
        ),
        (
            "gate: publish is denied when the ledger cannot answer".to_string(),
            run(publish(), Err("down".to_string())) == "deny",
        ),
        (
            "gate: a lease does not allow a reboot".to_string(),
            without == "deny",
        ),
        (
            "gate: an owner override lifts one rule only".to_string(),
            stored && lifted == "override" && other == "deny",
        ),
        ("gate: an expired override is ignored".to_string(), expired),
        (
            "gate: an override longer than a day is ignored".to_string(),
            long,
        ),
    ]
}

fn audit_cases(dir: &Path) -> Vec<(String, bool)> {
    let folder = dir.join("audit");
    let secret = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz0123");
    let shown = audit::redact(&format!(
        "curl -H 'Authorization: Bearer abcdefgh12345678' https://u:hunter2@h; API_KEY=plainvalue gh {secret}"
    ));
    let clean = ["abcdefgh12345678", "hunter2", "plainvalue", secret]
        .iter()
        .all(|s| !shown.contains(s));
    let entry = |v: &str| {
        let mut m = serde_json::Map::new();
        m.insert("verdict".to_string(), json!(v));
        m
    };
    let first = audit::append(&folder, entry("allow"));
    let second = audit::append(&folder, entry("deny"));
    let whole = audit::report(&folder, "").is_ok_and(|r| r.broken.is_empty() && r.entries == 2);
    let edited = match (&first, second) {
        (Ok(file), Ok(_)) => std::fs::read_to_string(file)
            .and_then(|t| std::fs::write(file, t.replacen("allow", "ALLOW", 1)))
            .is_ok(),
        _ => false,
    };
    let caught = audit::report(&folder, "").is_ok_and(|r| !r.broken.is_empty());
    vec![
        ("gate: the audit redacts secrets".to_string(), clean),
        ("gate: the audit chain verifies".to_string(), whole),
        (
            "gate: an edited audit entry breaks the chain".to_string(),
            edited && caught,
        ),
    ]
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let Some(policy) = embedded() else {
        return vec![("gate: the embedded list parses".to_string(), false)];
    };
    let mut out = Vec::new();
    for (text, rule) in RED {
        let got = rules_of(&policy, &command(text));
        out.push((format!("gate: deny {rule} `{text}`"), got.contains(rule)));
    }
    for text in GREEN {
        let got = rules_of(&policy, &command(text));
        out.push((format!("gate: allow `{text}` {got:?}"), got.is_empty()));
    }
    for (file, rule) in WRITES_RED {
        let action = Action {
            cwd: PathBuf::from(CWD),
            writes: vec![file.to_string()],
            ..Action::default()
        };
        out.push((
            format!("gate: deny write {file}"),
            rules_of(&policy, &action).contains(rule),
        ));
    }
    for file in WRITES_GREEN {
        let action = Action {
            cwd: PathBuf::from(CWD),
            writes: vec![file.to_string()],
            ..Action::default()
        };
        out.push((
            format!("gate: allow write {file}"),
            rules_of(&policy, &action).is_empty(),
        ));
    }
    // Mutation: without its declared entries the list stops denying, so the fixtures see it.
    let mut emptied = policy.clone();
    emptied.rules.iter_mut().for_each(|r| r.commands.clear());
    emptied.paths = policy::Paths::default();
    out.push((
        "gate: mutation, an emptied list is red".to_string(),
        rules_of(&emptied, &command("reboot")).is_empty()
            && rules_of(&emptied, &command("echo x > ~/.claude/settings.json")).is_empty()
            && !rules_of(&policy, &command("reboot")).is_empty(),
    ));
    let dir = scratch("cases");
    out.push((
        "gate: a script file is judged by its lines".to_string(),
        script_is_judged(&policy, &dir),
    ));
    out.extend(payload_cases(&policy));
    out.extend(decision_cases(&policy, &dir));
    out.extend(audit_cases(&dir));
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        eprintln!("gate self-test: cannot remove {}: {e}", dir.display());
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixtures_hold() {
        let red: Vec<String> = super::self_test_cases()
            .into_iter()
            .filter(|(_, ok)| !ok)
            .map(|(name, _)| name)
            .collect();
        assert!(red.is_empty(), "{red:#?}");
    }
}
