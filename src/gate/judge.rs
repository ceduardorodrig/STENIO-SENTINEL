//! The judgement of one command text or file action against the declared list. Pure: it reads
//! only the scripts and SQL files the command names. It never runs anything.

use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::parse::{self, LITERAL_DOLLAR, SUBST, Simple};
use super::paths;
use super::policy::Policy;

pub const DESTROY: &str = "GATE-DESTROY";
pub const STORAGE: &str = "GATE-STORAGE";
pub const BACKUP: &str = "GATE-BACKUP";
pub const HISTORY: &str = "GATE-HISTORY";
pub const SECRET: &str = "GATE-SECRET";
pub const POWER: &str = "GATE-POWER";
pub const DB: &str = "GATE-DB";
pub const PUBLISH: &str = "GATE-PUBLISH";
pub const SELF: &str = "GATE-SELF";

const MAX_DEPTH: u8 = 6;
const SCRIPT_LIMIT: u64 = 512 * 1024;
const SHELLS: [&str; 7] = ["bash", "sh", "zsh", "dash", "ksh", "fish", "ash"];
const PRINTERS: [&str; 24] = [
    "bat", "cat", "rg", "grep", "head", "tail", "less", "more", "cut", "awk", "sed", "sd", "tee",
    "jq", "yq", "tr", "sort", "uniq", "nl", "xxd", "hexyl", "base64", "column", "fold",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub detail: String,
}

/// Where the output of a command ends up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Output {
    /// The agent reads it.
    Shown,
    /// A substitution or a following program consumes it.
    Consumed,
    /// A file keeps it.
    Stored,
}

pub struct Judge<'a> {
    policy: &'a Policy,
    home: String,
    cwd: PathBuf,
    vars: HashMap<String, String>,
    depth: u8,
    in_script: bool,
    pub found: Vec<Finding>,
}

macro_rules! re {
    ($pat:expr) => {{
        static RE: OnceLock<Option<Regex>> = OnceLock::new();
        RE.get_or_init(|| Regex::new($pat).ok()).as_ref()
    }};
}

fn hit(re: Option<&Regex>, text: &str) -> bool {
    re.is_some_and(|r| r.is_match(text))
}

fn base(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn assignment(word: &str) -> Option<(&str, &str)> {
    let (name, value) = word.split_once('=')?;
    let name = name.strip_suffix('+').unwrap_or(name);
    let ok = !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    ok.then_some((name, value))
}

fn is_flag(word: &str) -> bool {
    word.len() > 1 && word.starts_with('-')
}

/// A flag given alone, with `=value`, or inside a cluster of short flags.
fn has_flag(args: &[String], flag: &str) -> bool {
    let short = flag
        .strip_prefix('-')
        .filter(|f| f.len() == 1)
        .and_then(|f| f.chars().next());
    args.iter().take_while(|a| *a != "--").any(|a| {
        a == flag
            || a.strip_prefix(flag).is_some_and(|r| r.starts_with('='))
            || short.is_some_and(|c| a.starts_with('-') && !a.starts_with("--") && a.contains(c))
    })
}

/// The arguments that are not flags, skipping the value of each flag named in `valued`.
fn operands<'v>(args: &'v [String], valued: &[&str]) -> Vec<&'v String> {
    let mut out = Vec::new();
    let mut skip = false;
    let mut plain = false;
    for arg in args {
        if skip {
            skip = false;
        } else if !plain && arg == "--" {
            plain = true;
        } else if !plain && is_flag(arg) {
            skip = valued.contains(&arg.as_str());
        } else {
            out.push(arg);
        }
    }
    out
}

/// What follows the wrapper options: the wrapped command.
fn after_options<'v>(args: &'v [String], valued: &[&str]) -> &'v [String] {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        if arg == "--" {
            at += 1;
            break;
        }
        if is_flag(arg) {
            at += if valued.contains(&arg.as_str()) {
                2
            } else {
                1
            };
        } else if assignment(arg).is_some() {
            at += 1;
        } else {
            break;
        }
    }
    args.get(at..).unwrap_or_default()
}

/// A declared pattern against a program and its arguments.
fn pattern_matches(pattern: &str, program: &str, args: &[String]) -> bool {
    let mut tokens = pattern.split_whitespace();
    let Some(head) = tokens.next() else {
        return false;
    };
    let named = match head.strip_suffix('*') {
        Some(prefix) => program.starts_with(prefix),
        None => program == head,
    };
    if !named {
        return false;
    }
    let words: Vec<&String> = args.iter().filter(|a| !is_flag(a)).collect();
    let mut from = 0;
    for token in tokens {
        if let Some(flags) = token.strip_prefix('!') {
            if flags.split('|').any(|f| has_flag(args, f)) {
                return false;
            }
        } else if token.starts_with('-') {
            if !token.split('|').any(|f| has_flag(args, f)) {
                return false;
            }
        } else {
            let found = words
                .iter()
                .enumerate()
                .skip(from)
                .take(5)
                .find(|(_, w)| token.split('|').any(|t| t == w.as_str()));
            match found {
                Some((index, _)) => from = index + 1,
                None => return false,
            }
        }
    }
    true
}

fn secret_name(name: &str) -> bool {
    hit(
        re!(r"(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_?KEY|_KEY|CREDENTIALS?)(_B64)?$"),
        name,
    )
}

/// A word that expands to the value of a secret-named variable.
fn expands_secret(word: &str) -> bool {
    let Some(re) = re!(r"\$(\{[!]?)?([A-Za-z_]\w*)(:?\+)?") else {
        return false;
    };
    re.captures_iter(word)
        .any(|c| c.get(3).is_none() && c.get(2).is_some_and(|n| secret_name(n.as_str())))
}

fn destructive_sql(text: &str) -> bool {
    hit(
        re!(
            r"(?i)\bdrop\s+(database|schema|table)\b|\btruncate\s+(table\s+)?[`\x22]?\w+|\bdropDatabase\s*\(|\.drop\s*\(\s*\)|\bflush(all|db)\b"
        ),
        text,
    ) || re!(r"(?i)\bdelete\s+from\s+[\w.`\x22]+\s*([;\x22']|$)").is_some_and(|r| r.is_match(text))
}

impl<'a> Judge<'a> {
    pub fn new(policy: &'a Policy, home: &str, cwd: &Path) -> Self {
        Judge {
            policy,
            home: home.to_string(),
            cwd: cwd.to_path_buf(),
            vars: HashMap::new(),
            depth: 0,
            in_script: false,
            found: Vec::new(),
        }
    }

    fn deny(&mut self, rule: &'static str, detail: impl Into<String>) {
        let finding = Finding {
            rule,
            detail: detail.into(),
        };
        if !self.found.contains(&finding) {
            self.found.push(finding);
        }
    }

    /// Replaces the variables whose value is known; the others stay as written.
    fn expand(&self, word: &str) -> String {
        let Some(re) = re!(r"\$(?:\{([A-Za-z_]\w*)(?::?[-?=][^}]*)?\}|([A-Za-z_]\w*))") else {
            return word.to_string();
        };
        let expanded = re.replace_all(word, |c: &regex::Captures<'_>| {
            let name = c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str());
            match name {
                "HOME" => self.home.clone(),
                "PWD" => self.cwd.display().to_string(),
                _ => self
                    .vars
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| c[0].to_string()),
            }
        });
        paths::tilde(&expanded, &self.home)
    }

    fn resolve(&self, word: &str) -> Vec<PathBuf> {
        paths::spellings(paths::absolute(&self.expand(word), &self.cwd))
    }

    fn guard_file(&self, path: &Path) -> bool {
        let p = &self.policy.paths;
        paths::any(&p.guard_files, path, &self.home)
            && !paths::any(&p.scratch, path, &self.home)
    }

    fn backed_up(&self, path: &Path) -> bool {
        paths::within(&self.policy.paths.protected_trees, path, &self.home)
    }

    fn root_dir(&self, path: &Path) -> bool {
        paths::any(&self.policy.paths.protected_roots, path, &self.home)
    }

    /// A file that is written, appended to or created.
    fn write_to(&mut self, word: &str, overwrite: bool) {
        if word.contains(SUBST) {
            return;
        }
        for path in self.resolve(word) {
            let text = path.display().to_string();
            if self.guard_file(&path) {
                self.deny(SELF, format!("write to {text}"));
            }
            if overwrite && self.backed_up(&path) && path.is_file() {
                self.deny(DESTROY, format!("overwrite of {text}"));
            }
            if text.starts_with("/dev/")
                && hit(re!(r"^/dev/(sd|nvme|vd|mmcblk|md|dm-|mapper/)"), &text)
            {
                self.deny(STORAGE, format!("write to the device {text}"));
            }
        }
    }

    /// A file or directory that disappears, or loses its place.
    fn remove(&mut self, word: &str, recursive: bool) {
        if word.contains(SUBST) {
            return;
        }
        let expanded = self.expand(word);
        if expanded.starts_with('$') {
            let rest = expanded.trim_start_matches(|c: char| c != '/');
            let guarded = word.contains(":?");
            if recursive && !self.in_script && !guarded && matches!(rest, "/" | "/*" | "/.*") {
                self.deny(
                    DESTROY,
                    format!("recursive delete of {word}: an empty variable names the root"),
                );
            }
            return;
        }
        for path in paths::spellings(paths::absolute(&expanded, &self.cwd)) {
            let text = path.display().to_string();
            if self.guard_file(&path) {
                self.deny(SELF, format!("removal of {text}"));
            }
            if self.backed_up(&path) {
                self.deny(DESTROY, format!("removal of {text} (backup or version tree)"));
            }
            if !recursive {
                continue;
            }
            let glob = path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().contains(['*', '?', '[']));
            let dir = match path.parent() {
                Some(parent) if glob => parent,
                _ => path.as_path(),
            };
            if self.root_dir(dir) {
                self.deny(DESTROY, format!("recursive delete or move of {text}"));
            }
            let git = format!("{text}/");
            if git.ends_with("/.git/")
                || git.contains("/.git/objects")
                || git.contains("/.git/refs")
            {
                self.deny(DESTROY, format!("removal of git history at {text}"));
            }
        }
    }

    pub fn file_write(&mut self, path: &str) {
        self.write_to(path, true);
    }

    pub fn file_delete(&mut self, path: &str) {
        self.remove(path, false);
    }

    pub fn file_read(&mut self, path: &str) {
        if self.secret_file(path) {
            self.deny(SECRET, format!("read of the secret file {path}"));
        }
    }

    fn secret_file(&self, word: &str) -> bool {
        let p = &self.policy.paths;
        self.resolve(word).iter().any(|path| {
            paths::any(&p.secret_files, path, &self.home)
                && !paths::any(&p.secret_exempt, path, &self.home)
        })
    }

    /// A command line as a shell would receive it.
    pub fn command(&mut self, text: &str) {
        self.text(text, Output::Shown);
    }

    fn text(&mut self, text: &str, out: Output) {
        if self.depth >= MAX_DEPTH {
            return;
        }
        self.depth += 1;
        let commands = parse::parse(text);
        let mut first = 0;
        for at in 0..commands.len() {
            if commands[at].piped && at + 1 < commands.len() {
                continue;
            }
            let pipeline = &commands[first..=at];
            for index in 0..pipeline.len() {
                self.stage(pipeline, index, out);
            }
            first = at + 1;
        }
        self.depth -= 1;
    }

    fn stage(&mut self, pipeline: &[Simple], index: usize, out: Output) {
        let command = &pipeline[index];
        let stored = command.redirects.iter().any(|(op, target)| {
            op.starts_with('>')
                && !target.chars().all(|c| c.is_ascii_digit() || c == '-')
                && target != "/dev/null"
                && !target.starts_with("/dev/std")
                && !op.ends_with('&')
        });
        let output = match pipeline.last() {
            _ if stored => Output::Stored,
            Some(sink) if index + 1 < pipeline.len() => {
                let (argv, _) = self.unwrapped(&sink.words);
                let program = argv.first().map(|w| base(w)).unwrap_or_default();
                let quiet = ["-q", "-c", "-l", "--quiet", "--count"]
                    .iter()
                    .any(|f| has_flag(&argv, f));
                let kept = sink.redirects.iter().any(|(op, _)| op.starts_with('>'));
                if PRINTERS.contains(&program) && !quiet && !kept {
                    out
                } else {
                    Output::Consumed
                }
            }
            _ => out,
        };
        let shows = command
            .words
            .first()
            .is_some_and(|w| matches!(base(w), "echo" | "printf"));
        for inner in &command.substitutions {
            let kind = if shows { output } else { Output::Consumed };
            self.text(inner, kind);
        }
        for (op, target) in &command.redirects {
            if op.starts_with('>') && !target.chars().all(|c| c.is_ascii_digit() || c == '-') {
                self.write_to(target, !op.starts_with(">>"));
            }
            if op == "<" && output != Output::Consumed && self.secret_file(target) {
                let reader = command.words.first().map(|w| base(w)).unwrap_or_default();
                if PRINTERS.contains(&reader) {
                    self.deny(SECRET, format!("print of the secret file {target}"));
                }
            }
        }
        let (argv, env_dump) = self.unwrapped(&command.words);
        if env_dump && output != Output::Consumed {
            self.deny(SECRET, "dump of the environment");
        }
        if !argv.is_empty() {
            self.program(&argv, command, &pipeline[..index], output);
        }
    }

    /// Drops reserved words, assignments and wrappers. The flag says that nothing was left
    /// after `env`, which then prints every variable.
    fn unwrapped(&mut self, words: &[String]) -> (Vec<String>, bool) {
        let mut argv: &[String] = words;
        loop {
            let Some(first) = argv.first() else {
                return (Vec::new(), false);
            };
            if let Some((name, value)) = assignment(first) {
                if argv.len() == 1 || argv[1..].iter().all(|w| assignment(w).is_some()) {
                    let value = self.expand(value);
                    if !value.contains(SUBST) {
                        self.vars.insert(name.to_string(), value);
                    }
                }
                argv = &argv[1..];
                continue;
            }
            let rest = &argv[1..];
            argv = match base(first) {
                "if" | "then" | "else" | "elif" | "fi" | "do" | "done" | "while" | "until" | "!"
                | "{" | "}" | "builtin" | "nohup" | "chronic" | "coproc" => rest,
                "export" | "local" | "declare" | "readonly" | "typeset"
                    if rest.iter().any(|w| assignment(w).is_some()) =>
                {
                    rest
                }
                "command" if !has_flag(rest, "-v") && !has_flag(rest, "-V") => {
                    after_options(rest, &[])
                }
                "exec" => after_options(rest, &["-a"]),
                "time" => after_options(rest, &["-o", "-f"]),
                "setsid" => after_options(rest, &[]),
                "sudo" | "doas" | "run0" => after_options(
                    rest,
                    &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "--user"],
                ),
                "pkexec" => after_options(rest, &["--user"]),
                "env" => {
                    let inner = after_options(rest, &["-u", "--unset", "-C", "--chdir"]);
                    if inner.is_empty() {
                        return (Vec::new(), true);
                    }
                    inner
                }
                "nice" => after_options(rest, &["-n", "--adjustment"]),
                "ionice" => after_options(rest, &["-c", "-n", "-p"]),
                "stdbuf" => after_options(rest, &["-i", "-o", "-e"]),
                "timeout" => {
                    let inner = after_options(rest, &["-s", "--signal", "-k", "--kill-after"]);
                    inner.get(1..).unwrap_or_default()
                }
                "systemd-run" => after_options(
                    rest,
                    &["-u", "--unit", "-p", "--property", "-E", "--setenv", "--on-active"],
                ),
                "flock" if !has_flag(rest, "-c") => {
                    let inner = after_options(rest, &["-w", "--timeout", "-E"]);
                    inner.get(1..).unwrap_or_default()
                }
                "watchexec" => after_options(rest, &["-w", "--watch", "-e", "--exts", "-f"]),
                _ => return (argv.to_vec(), false),
            };
        }
    }

    fn declared(&mut self, program: &str, args: &[String]) {
        let policy = self.policy;
        for rule in &policy.rules {
            if let Some(pattern) = rule
                .commands
                .iter()
                .find(|p| pattern_matches(p, program, args))
            {
                // The identifiers of the embedded list are the constants above.
                let id = [
                    DESTROY, STORAGE, BACKUP, HISTORY, SECRET, POWER, DB, PUBLISH, SELF,
                ]
                .into_iter()
                .find(|id| *id == rule.id);
                if let Some(id) = id {
                    self.deny(id, format!("`{pattern}`"));
                }
            }
        }
    }

    fn inner(&mut self, argv: &[String], command: &Simple, output: Output) {
        if self.depth >= MAX_DEPTH {
            return;
        }
        self.depth += 1;
        let (argv, env_dump) = self.unwrapped(argv);
        if env_dump && output != Output::Consumed {
            self.deny(SECRET, "dump of the environment");
        }
        if !argv.is_empty() {
            self.program(&argv, command, &[], output);
        }
        self.depth -= 1;
    }

    fn script(&mut self, word: &str, args: &[String], must_be_shell: bool) {
        // The script's own name is also judged, as in `release.sh`.
        self.declared(base(word), args);
        for path in self.resolve(word) {
            let small = path
                .metadata()
                .is_ok_and(|m| m.is_file() && m.len() <= SCRIPT_LIMIT);
            if !small {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let head = text.lines().next().unwrap_or_default();
            let shell = head.starts_with("#!")
                && ["bash", "/sh", "zsh", "env sh", "fish", "dash"]
                    .iter()
                    .any(|s| head.contains(s));
            if must_be_shell && !shell {
                continue;
            }
            let (was, vars, cwd) = (self.in_script, self.vars.clone(), self.cwd.clone());
            self.in_script = true;
            self.text(&text, Output::Shown);
            (self.in_script, self.vars, self.cwd) = (was, vars, cwd);
            return;
        }
    }

    /// Code given to another interpreter: only the shell commands and deletions it spells out.
    fn foreign_code(&mut self, code: &str) {
        let call = re!(
            r"(?:\bsystem|\bpopen|\brun|\bcall|\bcheck_call|\bcheck_output|\bPopen|\bterminal|\bexecSync|\bspawnSync)\s*\(\s*(?:command\s*=\s*)?\[?((?:\s*[rfb]?(?:\x22(?:[^\x22\\]|\\.)*\x22|'(?:[^'\\]|\\.)*')\s*,?)+)"
        );
        let literal = re!(r"\x22((?:[^\x22\\]|\\.)*)\x22|'((?:[^'\\]|\\.)*)'");
        if let (Some(call), Some(literal)) = (call, literal) {
            for found in call.captures_iter(code) {
                let words: Vec<&str> = literal
                    .captures_iter(&found[1])
                    .filter_map(|c| c.get(1).or_else(|| c.get(2)).map(|m| m.as_str()))
                    .collect();
                self.text(&words.join(" "), Output::Shown);
            }
        }
        if let Some(tree) = re!(r"\brmtree\s*\(\s*[rfb]?[\x22']([^\x22']+)") {
            for found in tree.captures_iter(code) {
                self.remove(&found[1], true);
            }
        }
    }

    fn program(&mut self, argv: &[String], command: &Simple, upstream: &[Simple], output: Output) {
        let word = argv[0].clone();
        let program = base(&word).to_string();
        let args: Vec<String> = argv[1..].to_vec();
        if program == "git" {
            return self.git(&args);
        }
        self.declared(&program, &args);
        match program.as_str() {
            "cd" | "pushd" => {
                if let Some(dir) = operands(&args, &[]).first() {
                    let dir = self.expand(dir);
                    if !dir.contains('$') {
                        self.cwd = paths::absolute(&dir, &self.cwd);
                    }
                }
            }
            "rm" | "rip" | "rmdir" | "unlink" => {
                let recursive = ["-r", "-R", "--recursive"]
                    .iter()
                    .any(|f| has_flag(&args, f));
                for target in operands(&args, &[]) {
                    self.remove(target, recursive);
                }
            }
            "mv" => {
                let files = operands(&args, &["-t", "--target-directory", "-S", "--suffix"]);
                if let Some((destination, sources)) = files.split_last() {
                    for source in sources {
                        self.remove(source, true);
                    }
                    self.write_to(destination, true);
                }
            }
            "cp" | "install" | "ln" | "rsync" => {
                let files = operands(
                    &args,
                    &["-t", "--target-directory", "-m", "-o", "-g", "-e", "--exclude"],
                );
                if let Some(destination) = files.last().filter(|_| files.len() > 1) {
                    self.write_to(destination, true);
                    if program == "rsync" && args.iter().any(|a| a.starts_with("--delete")) {
                        self.remove(destination, true);
                    }
                }
            }
            "tee" => {
                let append = has_flag(&args, "-a");
                for file in operands(&args, &[]) {
                    self.write_to(file, !append);
                }
            }
            "truncate" => {
                for file in operands(&args, &["-s", "--size", "-r", "--reference"]) {
                    self.remove(file, false);
                }
            }
            "dd" => {
                if let Some(of) = args.iter().find_map(|a| a.strip_prefix("of=")) {
                    self.write_to(of, true);
                }
            }
            "sd" => {
                if !has_flag(&args, "-p") && !has_flag(&args, "--preview") {
                    for file in operands(&args, &["-n", "-f", "--flags", "--max-replacements"])
                        .into_iter()
                        .skip(2)
                    {
                        self.write_to(file, true);
                    }
                }
            }
            "sed" | "perl" | "yq"
                if args
                    .iter()
                    .any(|a| a.starts_with("-i") || a == "--in-place" || a == "-pi") =>
            {
                for file in operands(&args, &["-e", "-f"]) {
                    self.write_to(file, true);
                }
            }
            "chmod" | "chown" | "chgrp" | "chattr" => {
                let recursive = has_flag(&args, "-R") || has_flag(&args, "--recursive");
                for file in operands(&args, &["--reference"]).into_iter().skip(1) {
                    for path in self.resolve(file) {
                        if self.guard_file(&path) {
                            self.deny(SELF, format!("permission change of {}", path.display()));
                        }
                        if recursive && (self.root_dir(&path) || self.backed_up(&path)) {
                            self.deny(
                                DESTROY,
                                format!("recursive permission change of {}", path.display()),
                            );
                        }
                    }
                }
            }
            "find" => self.find(&args, command, output),
            "fd" | "fdfind" => self.fd(&args, command, output),
            "xargs" | "parallel" => {
                let inner = after_options(
                    &args,
                    &["-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "-j"],
                )
                .to_vec();
                if inner.is_empty() {
                    return;
                }
                // The targets arrive on standard input: the names upstream mentions are them.
                let (run, _) = self.unwrapped(&inner);
                let deletes = run.first().is_some_and(|w| base(w) == "rm");
                if deletes {
                    let recursive = has_flag(&run, "-r") || has_flag(&run, "-R");
                    for stage in upstream {
                        for name in stage.words.iter().skip(1).filter(|w| w.contains('/')) {
                            self.remove(name, recursive);
                        }
                    }
                }
                self.inner(&inner, command, output);
            }
            s if SHELLS.contains(&s) => {
                if let Some(at) = args.iter().position(|a| {
                    a.starts_with('-') && !a.starts_with("--") && a.ends_with('c')
                }) {
                    if let Some(code) = args.get(at + 1) {
                        self.text(&code.replace(LITERAL_DOLLAR, "$"), output);
                    }
                } else if let Some(script) = operands(&args, &["-o", "-O"]).first() {
                    let rest = args
                        .iter()
                        .skip_while(|a| a != script)
                        .skip(1)
                        .cloned()
                        .collect::<Vec<_>>();
                    self.script(script, &rest, false);
                } else {
                    self.text(&command.input, output);
                    for stage in upstream {
                        let said = stage.words.get(1..).unwrap_or_default().join(" ");
                        self.text(&said, output);
                        self.text(&stage.input, output);
                    }
                }
            }
            "source" | "." => {
                if let Some(script) = args.first() {
                    self.script(script, &args[1..], false);
                }
            }
            "eval" => self.text(&args.join(" ").replace(LITERAL_DOLLAR, "$"), output),
            "su" | "script" | "flock" => {
                if let Some(at) = args.iter().position(|a| a == "-c" || a == "--command")
                    && let Some(code) = args.get(at + 1)
                {
                    self.text(&code.replace(LITERAL_DOLLAR, "$"), output);
                }
            }
            "ssh" => {
                let rest = after_options(
                    &args,
                    &[
                        "-i", "-p", "-o", "-l", "-J", "-F", "-L", "-R", "-D", "-b", "-c", "-m",
                        "-S", "-W", "-E", "-e", "-Q", "-w", "-B", "-I", "-O",
                    ],
                );
                let remote = rest.get(1..).unwrap_or_default().join(" ");
                let remote = if remote.is_empty() {
                    command.input.clone()
                } else {
                    remote.replace(LITERAL_DOLLAR, "$")
                };
                let cwd = std::mem::replace(&mut self.cwd, PathBuf::from(&self.home));
                self.text(&remote, output);
                self.cwd = cwd;
            }
            "docker" | "podman" | "kubectl" => {
                let Some(at) = args.iter().position(|a| a == "exec") else {
                    return;
                };
                let rest = &args[at + 1..];
                let run = if program == "kubectl" {
                    rest.iter()
                        .position(|a| a == "--")
                        .and_then(|i| rest.get(i + 1..))
                        .unwrap_or_default()
                } else {
                    let after = after_options(
                        rest,
                        &["-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file"],
                    );
                    after.get(1..).unwrap_or_default()
                };
                let run = run.to_vec();
                if !run.is_empty() {
                    self.inner(&run, command, output);
                }
            }
            "psql" | "mysql" | "mariadb" | "sqlite3" | "mongosh" | "mongo" | "duckdb"
            | "clickhouse-client" | "clickhouse" | "redis-cli" | "bench" => {
                self.database(&program, &args, command, upstream);
            }
            "sops" | "age" | "rage" | "gpg" => self.decrypt(&program, &args, output),
            "printenv" => {
                let names = operands(&args, &[]);
                if output != Output::Consumed
                    && (names.is_empty() || names.iter().any(|n| secret_name(n)))
                {
                    self.deny(SECRET, "print of secret environment variables");
                }
            }
            "set" | "export" | "declare" | "typeset" => {
                let dumps = args.is_empty() || args == ["-p"] || args == ["-x"];
                if dumps && output != Output::Consumed && !self.in_script {
                    self.deny(SECRET, "dump of the shell variables");
                }
            }
            "echo" | "printf" => {
                let into_variable = program == "printf" && has_flag(&args, "-v");
                if output != Output::Consumed
                    && !into_variable
                    && args.iter().any(|a| expands_secret(a))
                {
                    self.deny(SECRET, "print of a secret variable");
                }
            }
            "gh" => {
                let deletes = args.windows(2).any(|w| {
                    (w[0] == "-X" || w[0] == "--method") && w[1].eq_ignore_ascii_case("delete")
                }) || args.iter().any(|a| a.eq_ignore_ascii_case("-XDELETE"));
                if args.first().is_some_and(|a| a == "api") && deletes {
                    self.deny(BACKUP, "`gh api` DELETE");
                }
            }
            "curl" | "xh" | "wget" | "http" => {
                if args.iter().any(|a| a.contains("/power/shutdown")) {
                    self.deny(POWER, "power relay shutdown");
                }
            }
            "python" | "python3" | "perl" | "ruby" | "node" | "bun" | "deno" | "uv" => {
                if let Some(at) = args.iter().position(|a| a == "-c" || a == "-e")
                    && let Some(code) = args.get(at + 1)
                {
                    self.foreign_code(code);
                }
                self.foreign_code(&command.input);
            }
            _ if word.contains('/') => self.script(&word, &args, true),
            _ => {}
        }
        const READERS: [&str; 21] = [
            "bat", "cat", "head", "tail", "less", "more", "rg", "grep", "awk", "sed", "sd", "cut",
            "jq", "yq", "xxd", "hexyl", "strings", "base64", "nl", "tac", "delta",
        ];
        if READERS.contains(&program.as_str()) && output != Output::Consumed {
            let quiet = matches!(program.as_str(), "rg" | "grep")
                && ["-q", "-c", "-l", "--quiet", "--count", "--files-with-matches", "--files"]
                    .iter()
                    .any(|f| has_flag(&args, f));
            // The first operands of these are a pattern or a program, not a file.
            let skip = match program.as_str() {
                "rg" | "grep" | "awk" | "sed" | "jq" | "yq" => 1,
                "sd" => 2,
                _ => 0,
            };
            if !quiet {
                for file in operands(&args, &["-e", "-g", "-r", "-n"])
                    .into_iter()
                    .skip(skip)
                {
                    self.file_read(file);
                }
            }
        }
    }

    fn git(&mut self, args: &[String]) {
        let mut rest = args;
        loop {
            match rest.first().map(String::as_str) {
                Some("-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace") => {
                    rest = rest.get(2..).unwrap_or_default();
                }
                Some(f) if f.starts_with('-') => rest = &rest[1..],
                _ => break,
            }
        }
        self.declared("git", rest);
        if rest.first().is_none_or(|s| s != "push") {
            return;
        }
        let push = &rest[1..];
        if has_flag(push, "-n") || has_flag(push, "--dry-run") {
            return;
        }
        let forced = [
            "-f",
            "--force",
            "--force-with-lease",
            "--force-if-includes",
            "--mirror",
            "--delete",
            "-d",
            "--prune",
        ]
        .iter()
        .any(|f| has_flag(push, f));
        let refs = operands(push, &["-o", "--push-option", "--repo", "--receive-pack"]);
        if forced
            || refs
                .iter()
                .any(|r| r.starts_with('+') || r.starts_with(':'))
        {
            self.deny(HISTORY, "force push or deletion of a remote ref");
        }
        let tags = has_flag(push, "--tags")
            || has_flag(push, "--follow-tags")
            || refs.iter().skip(1).any(|r| {
                r.starts_with("refs/tags/") || hit(re!(r"^v?\d+\.\d+(\.\d+)?([-.][\w.]+)?$"), r)
            });
        if tags {
            self.deny(PUBLISH, "push of a release tag");
        }
    }

    fn find(&mut self, args: &[String], command: &Simple, output: Output) {
        let starts: Vec<&String> = args
            .iter()
            .take_while(|a| !a.starts_with('-') && *a != "(" && *a != "!")
            .collect();
        let filtered = args.iter().any(|a| {
            matches!(
                a.as_str(),
                "-name" | "-iname" | "-path" | "-regex" | "-newer" | "-mtime" | "-mmin"
            )
        });
        let dot = ".".to_string();
        let starts = if starts.is_empty() {
            vec![&dot]
        } else {
            starts
        };
        let mut deletes = args.iter().any(|a| a == "-delete");
        for (at, arg) in args.iter().enumerate() {
            if !matches!(arg.as_str(), "-exec" | "-execdir" | "-ok") {
                continue;
            }
            let run: Vec<String> = args[at + 1..]
                .iter()
                .take_while(|a| *a != ";" && *a != "+")
                .filter(|a| *a != "{}")
                .cloned()
                .collect();
            deletes |= run.first().is_some_and(|w| base(w) == "rm");
            self.inner(&run, command, output);
        }
        if deletes {
            for start in starts {
                self.remove(start, !filtered);
            }
        }
    }

    fn fd(&mut self, args: &[String], command: &Simple, output: Output) {
        let Some(at) = args
            .iter()
            .position(|a| matches!(a.as_str(), "-x" | "-X" | "--exec" | "--exec-batch"))
        else {
            return;
        };
        let run: Vec<String> = args[at + 1..]
            .iter()
            .take_while(|a| *a != ";")
            .filter(|a| !a.starts_with('{'))
            .cloned()
            .collect();
        if run.first().is_some_and(|w| base(w) == "rm") {
            let head = &args[..at];
            let found = operands(
                head,
                &["-e", "-t", "-d", "-E", "--max-depth", "--base-directory"],
            );
            let pattern = found
                .first()
                .is_some_and(|p| !matches!(p.as_str(), "." | "" | ".*"));
            let filtered = pattern || has_flag(head, "-e");
            let dot = ".".to_string();
            let mut roots: Vec<&String> = found.into_iter().skip(1).collect();
            if roots.is_empty() {
                roots.push(&dot);
            }
            for root in roots {
                self.remove(root, !filtered);
            }
        }
        self.inner(&run, command, output);
    }

    fn database(&mut self, program: &str, args: &[String], command: &Simple, upstream: &[Simple]) {
        let mut text = format!("{}\n{}", args.join(" "), command.input);
        for stage in upstream {
            text.push('\n');
            text.push_str(&stage.words.join(" "));
            text.push('\n');
            text.push_str(&stage.input);
        }
        let mut files: Vec<&String> = command
            .redirects
            .iter()
            .filter(|(op, _)| op == "<")
            .map(|(_, f)| f)
            .collect();
        for pair in args.windows(2) {
            if pair[0] == "-f" || pair[0] == "--file" {
                files.push(&pair[1]);
            }
        }
        for file in files {
            for path in self.resolve(file) {
                let small = path.metadata().is_ok_and(|m| m.len() <= SCRIPT_LIMIT);
                if small && let Ok(sql) = std::fs::read_to_string(&path) {
                    text.push_str(&sql);
                }
            }
        }
        if destructive_sql(&text) {
            self.deny(DB, format!("destructive statement sent to {program}"));
        }
    }

    fn decrypt(&mut self, program: &str, args: &[String], output: Output) {
        if program == "sops"
            && let Some(at) = args
                .iter()
                .position(|a| a == "exec-env" || a == "exec-file")
        {
            let rest = operands(&args[at + 1..], &[]);
            if let Some(run) = rest.get(1..).filter(|r| !r.is_empty()) {
                let run: Vec<&str> = run.iter().map(|s| s.as_str()).collect();
                self.text(&run.join(" ").replace(LITERAL_DOLLAR, "$"), output);
            }
            return;
        }
        let decrypts = has_flag(args, "-d")
            || has_flag(args, "--decrypt")
            || (program == "sops" && args.iter().any(|a| a == "decrypt"));
        if !decrypts {
            return;
        }
        let to_file = ["-o", "--output"].iter().any(|f| has_flag(args, f))
            || (program == "sops" && (has_flag(args, "-i") || has_flag(args, "--in-place")));
        if output != Output::Consumed || to_file {
            self.deny(
                SECRET,
                format!("{program} decrypts to the terminal or to a clear-text file"),
            );
        }
    }

    pub fn code(&mut self, code: &str) {
        self.foreign_code(code);
    }
}
