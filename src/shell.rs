//! Shell script rules: hooks that hang, pipelines that lie, deploys that claim what they never saw.
//!
//! * `HOOK-STDIN-UNBOUNDED` (GB-224): a harness hook reading `$(cat)` at top level waits for an
//!   EOF an inherited stdin never sends (killed at 15 s, 2026-11-06).
//! * `INFRA-BASH-PIPEFAIL-QUIET-MATCH` (GB-249): under `pipefail`, `cmd | rg -q X` as a condition
//!   fails when `X` is found early, because `cmd` dies of SIGPIPE (release.sh 1c, 2026-11-09).
//! * `SH-SERIAL-CHAIN-NO-STOP` (GB-248): `build; git push` without `set -e` publishes after a red
//!   build; `pkill -f` inside `ssh`/`sh -c` matches its own command line.
//! * `SH-DEPLOY-CONVERGENCE` (GB-212, GB-221): `docker stack deploy` returns before the services
//!   converge (`--detach` defaults to true), so the script must pass `--detach=false` or read
//!   RUNNING/DESIRED or `UpdateStatus` afterwards.
//! * `DEPLOY-SUCCESS-AFTER-WARN` (GB-222, GB-212): a deploy script that can reach a success marker
//!   after a failure it only printed.
//!
//! All are static line heuristics over `*.sh`, `*.bash` and extensionless files with a shell
//! shebang. Comments and heredoc bodies are skipped, backslash continuations are joined.

use ignore::WalkBuilder;
use regex::Regex;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::engine::Violation;
use crate::rule::Severity;

pub const STDIN_ID: &str = "HOOK-STDIN-UNBOUNDED";
pub const PIPE_ID: &str = "INFRA-BASH-PIPEFAIL-QUIET-MATCH";
pub const CHAIN_ID: &str = "SH-SERIAL-CHAIN-NO-STOP";
pub const CONVERGE_ID: &str = "SH-DEPLOY-CONVERGENCE";
pub const BANNER_ID: &str = "DEPLOY-SUCCESS-AFTER-WARN";
pub const IDS: [&str; 5] = [STDIN_ID, PIPE_ID, CHAIN_ID, CONVERGE_ID, BANNER_ID];

/// Files under `root` (or `root` itself), without VCS, build and vendored trees.
pub fn walk(root: &Path) -> impl Iterator<Item = PathBuf> {
    WalkBuilder::new(root)
        .hidden(false)
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !(e.depth() > 0
                && matches!(
                    name.as_ref(),
                    ".git"
                        | "target"
                        | "node_modules"
                        | "vendor"
                        | ".venv"
                        | ".stversions"
                        | "archive"
                ))
        })
        .build()
        .flatten()
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(ignore::DirEntry::into_path)
}

/// Paths (repository-relative) that differ from `base`, for the rules that walk the tree.
pub fn changed_files(repo: &Path, base: &str) -> Vec<String> {
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    };
    let mut out = run(&["diff", "--name-only", "--relative", base, "--"]);
    out.push_str(&run(&["ls-files", "--others", "--exclude-standard"]));
    out.lines().map(str::to_string).collect()
}

fn is_shell(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("sh" | "bash") => true,
        Some(_) => false,
        None => {
            let mut head = [0u8; 40];
            let n = fs::File::open(path)
                .and_then(|mut f| f.read(&mut head))
                .unwrap_or(0);
            let first = String::from_utf8_lossy(&head[..n]);
            let first = first.lines().next().unwrap_or("");
            first.starts_with("#!") && (first.contains("bash") || first.ends_with("/sh"))
        }
    }
}

/// A compiled pattern, built once; `None` only for a broken literal (the self-test would be red).
macro_rules! re {
    ($pat:expr) => {{
        static RE: OnceLock<Option<Regex>> = OnceLock::new();
        RE.get_or_init(|| Regex::new($pat).ok()).as_ref()
    }};
}

fn hit(re: Option<&Regex>, text: &str) -> bool {
    re.is_some_and(|r| r.is_match(text))
}

/// One logical line: continuations joined, comments and heredoc bodies dropped.
struct Line {
    no: usize,
    indent: usize,
    text: String,
}

fn logical_lines(content: &str) -> Vec<Line> {
    let heredoc = re!(r#"(?:^|[^<])<<-?\s*["']?([A-Za-z_]\w*)"#);
    let mut out: Vec<Line> = Vec::new();
    let mut until: Option<String> = None;
    let mut open = false;
    for (i, raw) in content.lines().enumerate() {
        if let Some(word) = &until {
            if raw.trim() == word {
                until = None;
            }
            continue;
        }
        let trimmed = raw.trim();
        if !open && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        let continues = trimmed.ends_with('\\');
        let body = trimmed.trim_end_matches('\\').trim_end();
        match out.last_mut() {
            Some(last) if open => {
                last.text.push(' ');
                last.text.push_str(body);
            }
            _ => out.push(Line {
                no: i + 1,
                indent: raw.len() - raw.trim_start().len(),
                text: body.to_string(),
            }),
        }
        open = continues;
        until = heredoc
            .and_then(|r| r.captures(trimmed))
            .map(|c| c[1].to_string());
    }
    out
}

/// The line without quoted text, so a command named inside a message is not a command.
fn unquoted(line: &str) -> String {
    re!(r#""(?:[^"\\]|\\.)*"|'[^']*'"#).map_or_else(
        || line.to_string(),
        |r| r.replace_all(line, " ").to_string(),
    )
}

fn is_message(line: &str) -> bool {
    hit(re!(r"^(?:\{\s*)?(?:echo|printf|log|info|say)\b"), line)
}

fn violation(
    id: &str,
    name: &str,
    severity: Severity,
    file: &str,
    l: &Line,
    message: &str,
    fix: &str,
) -> Violation {
    Violation {
        rule_id: id.to_string(),
        rule_name: name.to_string(),
        severity,
        file_path: file.to_string(),
        line_number: l.no,
        snippet: l.text.chars().take(160).collect(),
        message: message.to_string(),
        suggestion: Some(fix.to_string()),
    }
}

fn stdin_findings(file: &str, lines: &[Line]) -> Vec<Violation> {
    if !Path::new(file).parent().is_some_and(|d| {
        d.components()
            .any(|c| c.as_os_str().to_string_lossy().contains("hooks"))
    }) {
        return Vec::new();
    }
    let read = re!(r#"^(?:export\s+)?\w+=["']?\$\(\s*(?:cat(?:\s+-)?|<\s*/dev/stdin)\s*\)"#);
    lines
        .iter()
        .filter(|l| l.indent == 0 && hit(read, &l.text))
        .map(|l| violation(STDIN_ID, "Hook Reads Stdin Without A Bound", Severity::Error, file, l,
            "the hook waits for an EOF that an inherited harness stdin never sends",
            "Resolve the mode from argv first, then read with a bound: payload=\"$(timeout 1 cat || true)\"."))
        .collect()
}

fn pipe_findings(file: &str, content: &str, lines: &[Line]) -> Vec<Violation> {
    if !hit(re!(r"(?m)^\s*set\s+(?:-\w+\s+)*-\w*o\s+pipefail"), content) {
        return Vec::new();
    }
    let substitution = re!(r"\$\([^()]*\)");
    let quiet = re!(
        r"(?:^|[^|])\|\s*(?:(?:rg|grep|egrep|fgrep)(?:\s+-[\w-]+)*?\s+(?:-[A-Za-z]*q[A-Za-z]*|--quiet|--silent)\b|head\b)"
    );
    let keyword = re!(r"^(?:if|elif|while|until)\b");
    let chained = re!(r"&&|\|\|\s*(?:[^t:\s]|t[^r])");
    let builtin = re!(r"^(?:(?:if|elif|while|until|then|!)\s+)*(?:echo|printf|head\s+-n\s*1)\b");
    let mut out = Vec::new();
    for l in lines {
        let mut code = unquoted(&l.text);
        while let Some(r) = substitution {
            let next = r.replace_all(&code, " ").to_string();
            if next == code {
                break;
            }
            code = next;
        }
        let Some(m) = quiet.and_then(|r| r.find(&code)) else {
            continue;
        };
        let after = &code[m.end()..];
        if !(hit(keyword, &code) || hit(chained, after)) {
            continue;
        }
        let before = &code[..m.start() + 1];
        let last = before.rsplit([';', '&']).next().unwrap_or("");
        let producer = last.rsplit("||").next().unwrap_or("").trim();
        if hit(builtin, producer) {
            continue;
        }
        out.push(violation(PIPE_ID, "Quiet Match Closes The Pipe Under pipefail", Severity::Warning, file, l,
            "`rg -q`/`grep -q`/`head` closes the pipe early, the producer dies of SIGPIPE and pipefail reports the condition as false",
            "Capture, then match: out=$(cmd); rg -q PATTERN <<<\"$out\"."));
    }
    out
}

fn chain_findings(file: &str, content: &str, lines: &[Line]) -> Vec<Violation> {
    let errexit = hit(
        re!(r"(?m)^\s*set\s+(?:-\w*e\w*\b|(?:-\w+\s+)*-o\s+errexit)"),
        content,
    );
    let build = re!(
        r"\b(?:cargo\s+(?:build|test|clippy)|npm\s+(?:run\s+build|test)|pytest|docker\s+build)\b"
    );
    let publish = re!(r"\bgit\s+(?:-C\s+\S*\s*)?(?:commit|tag|push)\b");
    let pkill =
        re!(r#"(?:\bssh\b[^"']*|\b(?:ba|z)?sh\s+-c\s*)["'].*\bpkill\s+(?:-\w+\s+)*-\w*f\b"#);
    let mut out = Vec::new();
    for l in lines {
        let code = unquoted(&l.text);
        let parts: Vec<&str> = code.split(';').collect();
        let built = parts
            .iter()
            .position(|p| hit(build, p) && !p.contains("||"));
        if !errexit && built.is_some_and(|i| parts[i + 1..].iter().any(|p| hit(publish, p))) {
            out.push(violation(
                CHAIN_ID,
                "Publish Runs After A Failed Build",
                Severity::Warning,
                file,
                l,
                "`;` runs the git publish step even when the build before it failed",
                "Chain with && or add set -euo pipefail.",
            ));
        }
        if hit(pkill, &l.text) && !hit(re!(r"pkill\s.*\[\w\]"), &l.text) {
            out.push(violation(CHAIN_ID, "pkill -f Matches Its Own Command Line", Severity::Warning, file, l,
                "the remote or child shell carries the pattern in its own arguments, so pkill -f kills it",
                "Write the pattern as '[n]ame', or use pkill -x / a PID file."));
        }
    }
    out
}

fn deploys(l: &Line) -> bool {
    let code = if hit(re!(r"\bssh\b|\bsh\s+-c\b"), &l.text) {
        l.text.clone()
    } else {
        unquoted(&l.text)
    };
    !is_message(&l.text)
        && hit(
            re!(r"(?:\bdocker\b|\$\{?DOCKER|\bdocker_cmd\b)[^;|&]*\bstack\s+deploy\b"),
            &code,
        )
}

fn asserts_convergence(l: &Line) -> bool {
    !is_message(&l.text)
        && (l.text.contains("UpdateStatus")
            || (hit(re!(r"\b(?:stack\s+services|service\s+ls)\b"), &l.text)
                && l.text.contains("Replicas")
                && !l.text.contains("table ")
                && (l.text.contains("$(") || l.text.contains('|') || l.text.starts_with("while"))))
}

/// `(name, first line index, last line index)` of every `name() {` block closed at column 0.
fn functions(lines: &[Line]) -> Vec<(String, usize, usize)> {
    let head = re!(r"^(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{?$");
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let Some(c) = head.and_then(|r| r.captures(&l.text)) else {
            continue;
        };
        if let Some(n) = lines[i..]
            .iter()
            .position(|x| x.indent == l.indent && x.text == "}")
        {
            out.push((c[1].to_string(), i, i + n));
        }
    }
    out
}

fn converge_findings(file: &str, lines: &[Line]) -> Vec<Violation> {
    let funcs = functions(lines);
    let checked_after = |at: usize| {
        lines.iter().enumerate().skip(at + 1).any(|(i, l)| {
            // an assertion in the flow, or a call of a function that holds one
            (asserts_convergence(l) && !funcs.iter().any(|(_, a, b)| *a < i && i < *b))
                || funcs.iter().any(|(name, a, b)| {
                    l.text.split_whitespace().next() == Some(name.as_str())
                        && lines[*a..*b].iter().any(asserts_convergence)
                })
        }) || funcs.iter().any(|(_, a, b)| {
            *a < at && at < *b && lines[at + 1..*b].iter().any(asserts_convergence)
        })
    };
    let detach = re!(r"(?:--detach|\s-d)(?:=|\s+)false");
    lines
        .iter()
        .enumerate()
        .filter(|(i, l)| deploys(l) && !hit(detach, &l.text) && !checked_after(*i))
        .map(|(_, l)| violation(CONVERGE_ID, "Stack Deploy Without A Convergence Check", Severity::Error, file, l,
            "`docker stack deploy` returns before the services converge and nothing after it reads RUNNING/DESIRED or UpdateStatus",
            "Pass --detach=false, or poll `docker stack services <stack> --format '{{.Name}} {{.Replicas}}'` with a timeout."))
        .collect()
}

fn success_banner(l: &Line) -> bool {
    // a variable name such as $deployed_json is not a claim
    let said = re!(r"\$\([^()]*\)|\$\{?\w+\}?").map_or_else(
        || l.text.clone(),
        |r| r.replace_all(&l.text, " ").to_string(),
    );
    is_message(&l.text)
        && hit(
            re!(r"(?i)conclu[ií]|complet|succe|deployed|\bstarted\b|finaliz"),
            &said,
        )
        && !hit(
            re!(
                r"(?i)\bnot\b|n[ãÃ]o\b|nenhum|\bfail(?:ed|ure|s)?\b|falh|⚠|❌|\[warn\]|\[!\]|incomplet"
            ),
            &l.text,
        )
}

fn warns(text: &str) -> bool {
    hit(
        re!(r"(?i)⚠|❌|\[warn(?:ing)?\]|\[fail\]|\bwarn(?:ing)?:"),
        text,
    )
}

/// A branch that stops, returns a failure or records one for later is not "warning only".
fn handles(text: &str) -> bool {
    !is_message(text)
        && hit(
            re!(
                r#"\bexit\s+(?:[1-9]|"?\$)|\breturn\s+(?:[1-9]|"?\$)|\b(?:die|fail|abort)\b|\bfalse\b|(?:^|;\s*|\{\s*)[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=|\(\(.*(?:\+\+|=)|\bcontinue\b"#
            ),
            &unquoted(text),
        )
        || hit(re!(r#"["'};]\s*;\s*(?:exit|return)\s+[1-9]"#), text)
}

/// The outermost chain of failure blocks that holds line `at`: an inner `else` is handled when an
/// enclosing failure block exits after it.
fn outer_failure_block(lines: &[Line], at: usize) -> Option<(usize, usize)> {
    let mut block = failure_block(lines, at)?;
    while let Some(outer) = failure_block(lines, block.0 - 1) {
        block = outer;
    }
    Some(block)
}

/// The `else` / `|| {` block that holds line `at`, as a line range; `None` outside such a block.
fn failure_block(lines: &[Line], at: usize) -> Option<(usize, usize)> {
    let me = lines[at].indent;
    let start = (0..at).rev().find(|&i| lines[i].indent < me)?;
    let opener = &lines[start].text;
    if !(opener == "else" || opener.ends_with("|| {")) {
        return None;
    }
    let end = (at + 1..lines.len())
        .find(|&i| lines[i].indent < me)
        .unwrap_or(lines.len());
    Some((start + 1, end))
}

fn banner_findings(file: &str, lines: &[Line]) -> Vec<Violation> {
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let deploy_script = hit(re!(r"deploy|failover|release|swarm|-ctl$"), &name)
        || lines.iter().any(|l| {
            deploys(l) || hit(re!(r"\bdocker\b.*\bservice\s+(?:scale|update)\b"), &l.text)
        });
    if !deploy_script {
        return Vec::new();
    }
    let banner = lines.iter().any(success_banner);
    let action = re!(
        r"\bstack\s+deploy\b|\bcompose\b.*\bup\b|\brsync\b|\bscp\b|\bssh\b|\bkubectl\b|\bdocker\b.*\b(?:push|service\s+(?:update|scale))\b|deploy[-_]\w+(?:\.sh)?\b|\bansible"
    );
    let acts = lines
        .iter()
        .any(|l| !is_message(&l.text) && hit(action, &l.text));
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    let mut add = |l: &Line, message: &str| {
        if seen.insert(l.no) {
            out.push(violation(BANNER_ID, "Success Marker Reachable After A Failure", Severity::Error, file, l, message,
                "Exit non-zero on the failed step, or record it and print a different, non-success marker."));
        }
    };
    for (i, l) in lines.iter().enumerate() {
        if success_banner(l) && !acts && hit(re!(r"(?i)deploy"), &l.text) {
            add(
                l,
                "the banner claims a deploy and the script never performs one",
            );
        }
        let next = lines.get(i + 1);
        if banner && is_message(&l.text) && warns(&l.text) {
            if next.is_some_and(|n| n.text == "exit 0") {
                add(
                    l,
                    "a failure is printed and the block exits 0, so the caller goes on to report success",
                );
            } else if let Some((a, b)) = outer_failure_block(lines, i)
                && !lines[a..b].iter().any(|x| handles(&x.text))
            {
                add(
                    l,
                    "this failure branch only prints: the script still reaches its success marker and exits 0",
                );
            }
        }
        if banner
            && hit(re!(r"\|\|\s*(?:echo|printf)\b"), &l.text)
            && warns(&l.text)
            && !handles(&l.text)
        {
            add(
                l,
                "the failed command is turned into a message and the script goes on to its success marker",
            );
        }
        if hit(
            re!(r"^(?:timeout\s+\d+\s+)?(?:rsync|ssh|scp|docker)\b.*\|\|\s*true$"),
            &l.text,
        ) && next.is_some_and(|n| is_message(&n.text) && hit(re!(r"✅|✔|\[OK\]"), &n.text))
        {
            add(
                l,
                "the failure is swallowed with `|| true` and the next line reports it as done",
            );
        }
        if let Some(c) = re!(r#"^(\w+)=.*\$\(.*\b(?:config|service|stack|secret)\s+(?:inspect|ls)\b.*\|\|\s*true\s*\)"#)
            .and_then(|r| r.captures(&l.text))
        {
            let empty = format!("-z \"${}\"", &c[1]);
            let window = &lines[i + 1..(i + 5).min(lines.len())];
            if window.iter().any(|x| x.text.contains(&empty))
                && window.iter().any(|x| hit(re!(r"✅|✔|\[OK\]"), &x.text))
            {
                add(l, "an unreadable value (`|| true`) is reported as a legitimate negative answer");
            }
        }
    }
    out
}

/// All shell rules over one script.
pub fn check(file: &str, content: &str) -> Vec<Violation> {
    let lines = logical_lines(content);
    let mut out = stdin_findings(file, &lines);
    out.extend(pipe_findings(file, content, &lines));
    out.extend(chain_findings(file, content, &lines));
    out.extend(converge_findings(file, &lines));
    out.extend(banner_findings(file, &lines));
    out
}

/// Every shell script under `root`.
pub fn audit(root: &Path) -> Vec<Violation> {
    walk(root)
        .filter(|p| is_shell(p))
        .filter_map(|p| Some(check(&p.to_string_lossy(), &fs::read_to_string(&p).ok()?)))
        .flatten()
        .collect()
}

/// `(case, file name, script, rule that must fire or stay silent, expected to fire)`.
const CASES: &[(&str, &str, &str, &str, bool)] = &[
    (
        "unbounded read",
        "x/agent-hooks/g.sh",
        "set -u\npayload=\"$(cat)\"\n",
        STDIN_ID,
        true,
    ),
    (
        "bounded read",
        "x/agent-hooks/g.sh",
        "payload=\"$(timeout 1 cat || true)\"\nf() {\n  payload=\"$(cat)\"\n}\n",
        STDIN_ID,
        false,
    ),
    (
        "cat outside hooks",
        "x/bin/g.sh",
        "payload=\"$(cat)\"\n",
        STDIN_ID,
        false,
    ),
    (
        "pipe into rg -q",
        "r.sh",
        "set -euo pipefail\nif stenio pre-release --help | rg -q X; then :; fi\n",
        PIPE_ID,
        true,
    ),
    (
        "pipe into grep -q &&",
        "r.sh",
        "set -o pipefail\nstenio --help 2>&1 | grep -qE X && echo y\n",
        PIPE_ID,
        true,
    ),
    (
        "capture then match",
        "r.sh",
        "set -euo pipefail\nh=$(stenio --help)\nif rg -q X <<<\"$h\"; then :; fi\nif echo \"$h\" | grep -q X; then :; fi\nv=$(ls | head -1)\nls | rg -q X || true\ntest -f a || grep -q X a\n",
        PIPE_ID,
        false,
    ),
    (
        "no pipefail",
        "r.sh",
        "set -e\nif a | grep -q X; then :; fi\n",
        PIPE_ID,
        false,
    ),
    (
        "build ; push",
        "r.sh",
        "cargo build --release; git commit -am x; git push\n",
        CHAIN_ID,
        true,
    ),
    (
        "build && push",
        "r.sh",
        "cargo build --release && git push\n",
        CHAIN_ID,
        false,
    ),
    (
        "set -e chain",
        "r.sh",
        "set -euo pipefail\ncargo build; git push\n",
        CHAIN_ID,
        false,
    ),
    (
        "pkill self match",
        "r.sh",
        "ssh h \"pkill -f worker.bin\"\n",
        CHAIN_ID,
        true,
    ),
    (
        "pkill bracket",
        "r.sh",
        "ssh h \"pkill -f '[w]orker.bin'\"\npkill -f worker\n",
        CHAIN_ID,
        false,
    ),
    (
        "bare stack deploy",
        "d.sh",
        "docker -H \"$R\" stack deploy -c a.yml s\necho \"check: docker stack services s {{.Replicas}} | x\"\necho \"Deploy done\"\n",
        CONVERGE_ID,
        true,
    ),
    (
        "table print is no check",
        "d.sh",
        "docker stack deploy -c a.yml s\ndocker stack services s --format \"table {{.Name}}\\t{{.Replicas}}\"\n",
        CONVERGE_ID,
        true,
    ),
    (
        "detach false",
        "d.sh",
        "docker stack deploy --detach=false -c a.yml s\n",
        CONVERGE_ID,
        false,
    ),
    (
        "poll after",
        "d.sh",
        "docker stack deploy -c a.yml s\nr=$(docker stack services s \\\n  --format '{{.Name}} {{.Replicas}}')\n",
        CONVERGE_ID,
        false,
    ),
    (
        "poll in a called function",
        "d.sh",
        "wait_up() {\n  r=$(docker stack services s --format '{{.Replicas}}')\n}\ndocker stack deploy -c a.yml s\nwait_up s\n",
        CONVERGE_ID,
        false,
    ),
    (
        "function never called",
        "d.sh",
        "wait_up() {\n  r=$(docker stack services s --format '{{.Replicas}}')\n}\ndocker stack deploy -c a.yml s\n",
        CONVERGE_ID,
        true,
    ),
    (
        "warn-only else",
        "deploy.sh",
        "ssh h up\nif ok; then\n  echo ok\nelse\n  echo \"  ⚠️ api down\"\nfi\necho \"Deploy complete\"\n",
        BANNER_ID,
        true,
    ),
    (
        "else that exits",
        "deploy.sh",
        "ssh h up\nif ok; then\n  echo ok\nelse\n  echo \"  ⚠️ api down\"\n  exit 1\nfi\necho \"Deploy complete\"\n",
        BANNER_ID,
        false,
    ),
    (
        "else that records",
        "deploy.sh",
        "ssh h up\nif ok; then\n  echo ok\nelse\n  echo \"  ⚠️ unread\"\n  DEGRADED=1\nfi\necho \"Deploy complete\"\n",
        BANNER_ID,
        false,
    ),
    (
        "warn then exit 0",
        "deploy.sh",
        "ssh h '\n  echo \"[WARN] reload failed\"\n  exit 0\n'\necho \"Deploy complete\"\n",
        BANNER_ID,
        true,
    ),
    (
        "swallowed ssh",
        "x-ctl",
        "ssh h up || echo \"  ⚠️ no ssh\"\necho \"cluster started\"\n",
        BANNER_ID,
        true,
    ),
    (
        "or true then ok",
        "deploy.sh",
        "rsync a h:b || true\necho \"✅ synced\"\n",
        BANNER_ID,
        true,
    ),
    (
        "unreadable is new",
        "deploy.sh",
        "d=\"$(docker config inspect x 2>/dev/null || true)\"\nif [ -z \"$d\" ]; then\n  echo \"✅ new\"\nfi\n",
        BANNER_ID,
        true,
    ),
    (
        "outer else exits",
        "deploy.sh",
        "ssh h up\nif a; then\n  :\nelse\n  if b; then\n    echo x\n  else\n    echo \"[FAIL] cfg\"\n  fi\n  exit 1\nfi\necho \"Deploy complete\"\n",
        BANNER_ID,
        false,
    ),
    (
        "failover banner",
        "failover.sh",
        "ssh h up\nif ok; then\n  echo \"✅ failover concluído!\"\nelse\n  echo \"  ❌ standby down\"\nfi\n",
        BANNER_ID,
        true,
    ),
    (
        "banner without deploy",
        "deploy_final.sh",
        "npm run build\necho \"✅ Deploy concluído!\"\n",
        BANNER_ID,
        true,
    ),
    (
        "variable is no banner",
        "deploy_check.sh",
        "echo \"said: $deployed_json\"\n",
        BANNER_ID,
        false,
    ),
    (
        "local gate banner",
        "deploy_final.sh",
        "npm run build\necho \"✅ Gate local concluído\"\n",
        BANNER_ID,
        false,
    ),
];

pub fn self_test_cases() -> Vec<(String, bool)> {
    CASES
        .iter()
        .map(|(case, file, script, rule, fires)| {
            let found = check(file, script).iter().any(|v| v.rule_id == *rule);
            (format!("shell: {case}"), found == *fires)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn shell_and_lock_cases() {
        let failed: Vec<String> = super::self_test_cases()
            .into_iter()
            .chain(crate::lockparity::self_test_cases())
            .filter(|(_, ok)| !ok)
            .map(|(n, _)| n)
            .collect();
        assert!(failed.is_empty(), "{failed:?}");
    }
}
